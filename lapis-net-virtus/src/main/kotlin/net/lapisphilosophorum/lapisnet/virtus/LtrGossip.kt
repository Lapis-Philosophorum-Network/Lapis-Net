package net.lapisphilosophorum.lapisnet.virtus

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.PubsubSubscription
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.storage.NabuStorageException

private val logger = KotlinLogging.logger {}

/**
 * Virtus-specific wiring on top of the domain-agnostic [GossipPubSub]: propagates [LtrRecord]s
 * over a dedicated topic, persists every accepted record into [NabuStorage], and exposes both the
 * raw per-pair record set ([currentRecords]) and the decayed/accumulated sort-weight
 * ([currentWeight]) a view needs to rank content by. Mirrors
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip]'s structure and persistence-lifecycle
 * ordering precisely - see that class's doc comment for the full reasoning; only the
 * pair-resolution semantics differ (see [LtrRecordIndex]'s doc comment: every record for a pair
 * is kept and summed, never resolved to one winner).
 *
 * **Publishes full record bytes, not a [Cid] pointer** - same reasoning as
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip]'s own doc comment (an
 * [LtrRecordCodec.MAX_BODY_SIZE]-bounded record plus a 64-byte signature is tiny relative to any
 * reasonable gossip message-size ceiling, and `NabuStorage.findProviders()` does not reliably work
 * cross-node as of this project's current state).
 *
 * **Persistence lifecycle order is load-bearing, not stylistic** - identical to
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip]:
 *  - Local creation ([announce]): `put()` -> `index.add()` -> `publish()`, publish always last.
 *  - Gossip receipt ([onGossipMessage]): [LtrRecordIndex.canAccept] (cheap, dedup-only) gates
 *    everything; [LtrRecordIndex.tryReservePersistence] (a separate, non-evicting cap)
 *    independently gates `put()`; reaching the persistence cap must NOT decline or invalidate the
 *    gossip message - this node's disk budget has no bearing on whether the record is valid or
 *    should keep propagating to the rest of the mesh.
 */
class LtrGossip private constructor(
    private val pubsub: GossipPubSub,
    private val storage: NabuStorage,
    private val index: LtrRecordIndex,
    private val subscription: PubsubSubscription,
) {
    /**
     * Persists, indexes, then publishes an already-locally-verified (self-signed) [record]. Order
     * matters (see class doc comment): `publish()` is the only externally-visible step and always
     * happens last.
     *
     * If [index.add] declines to track this node's own record (an exact content-id duplicate -
     * see [LtrRecordIndex.add]; the index evicts rather than rejects for "full", so that is not a
     * possible cause here), that is logged at `warn` - the record is still durably persisted and
     * still gets published either way, mirroring
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip.announce]'s exact contract.
     *
     * **No delivery guarantee** - see [GossipPubSub.publish]'s doc comment, which this defers to.
     */
    fun announce(record: LtrRecord) {
        val bytes = LtrRecordCodec.encode(record)
        storage.put(bytes)
        if (!index.add(record)) {
            logger.warn {
                "own announced record (content id ${record.contentId().fingerprintHex()}) was not tracked " +
                    "locally - already durably persisted and will still be published"
            }
        }
        pubsub.publish(LTR_RECORD_GOSSIP_TOPIC, bytes)
    }

    /** Every tracked [LtrRecord] for the `(cid, viewId)` pair, in insertion order - see
     * [LtrRecordIndex.recordsFor]'s doc comment on why this is never resolved to one winner. */
    fun currentRecords(
        cid: Cid,
        viewId: Secp256k1PublicKey,
    ): List<LtrRecord> = index.recordsFor(cid, viewId)

    /** The decayed, accumulated sort-weight for the `(cid, viewId)` pair as of [atEpochSeconds] -
     * see [LtrWeightCalculator.accumulatedWeightMsat] for the underlying math. */
    fun currentWeight(
        cid: Cid,
        viewId: Secp256k1PublicKey,
        atEpochSeconds: Long = System.currentTimeMillis() / 1000,
    ): Double = LtrWeightCalculator.accumulatedWeightMsat(currentRecords(cid, viewId), atEpochSeconds)

    /** Unsubscribes from the gossip topic. No other sub-resources to release - mirrors
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip.stop] exactly. */
    fun stop() {
        subscription.unsubscribe()
    }

    companion object {
        /** Dedicated GossipSub topic for Virtus/LTR record propagation - deliberately a separate
         * string from [VIRTUS_LTR_RECORD_DOMAIN_TAG]-style signing domain-separation tags, same
         * reasoning as
         * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip.VERITAS_GRANT_GOSSIP_TOPIC]'s doc
         * comment. */
        const val LTR_RECORD_GOSSIP_TOPIC = "LapisNet:virtus-ltr-record-gossip:v1"

        /**
         * Attaches Virtus-specific GossipSub wiring on top of an already-[GossipPubSub.attach]-ed
         * [pubsub] and an already-[NabuStorage.attach]-ed [storage]. Subscribes to
         * [LTR_RECORD_GOSSIP_TOPIC] immediately - see [onGossipMessage] for the validator.
         */
        fun attach(
            pubsub: GossipPubSub,
            storage: NabuStorage,
        ): LtrGossip {
            val index = LtrRecordIndex()
            val subscription =
                pubsub.subscribe(LTR_RECORD_GOSSIP_TOPIC) { bytes, from ->
                    onGossipMessage(bytes, from, storage, index)
                }
            return LtrGossip(pubsub, storage, index, subscription)
        }

        /**
         * The GossipSub validator: structural decode AND signature verification happen here in
         * one step, gating both this node's acceptance and mesh-wide re-propagation. Mirrors
         * [net.lapisphilosophorum.lapisnet.trust.VeritasGossip.onGossipMessage]'s three-way
         * structure exactly:
         *  1. [LtrRecordIndex.canAccept] - cheap, in-memory, dedup-only - declines an exact
         *     content-id duplicate immediately, with no persist attempt, no indexing, and no
         *     re-propagation.
         *  2. For anything that clears step 1, [LtrRecordIndex.tryReservePersistence] - a
         *     separate, non-evicting cap - decides whether [storage].`put()` is even attempted.
         *  3. [LtrRecordIndex.add] always runs for a record that cleared step 1, and this function
         *     always returns `Valid` for it - regardless of whether step 2 actually persisted it.
         *     Only a genuine decode failure, signature failure, or `put()` throwing
         *     [NabuStorageException] returns `Invalid`.
         *
         * Visibility is `internal`, not `private`, purely as a test seam - mirrors
         * `VeritasGossip.onGossipMessage`'s own documented reasoning.
         */
        internal fun onGossipMessage(
            bytes: ByteArray,
            from: PeerId,
            storage: NabuStorage,
            index: LtrRecordIndex,
        ): ValidationResult {
            val record =
                try {
                    LtrRecordCodec.decode(bytes)
                } catch (e: MalformedLtrRecordException) {
                    logger.debug(e) {
                        "rejected structurally malformed record from $from on $LTR_RECORD_GOSSIP_TOPIC"
                    }
                    return ValidationResult.Invalid
                }
            if (!LtrRecord.verify(record)) {
                logger.debug { "rejected signature-invalid record from $from on $LTR_RECORD_GOSSIP_TOPIC" }
                return ValidationResult.Invalid
            }
            if (!index.canAccept(record)) {
                logger.debug {
                    "declining duplicate (already-tracked) record from $from on $LTR_RECORD_GOSSIP_TOPIC - " +
                        "not persisting or re-propagating"
                }
                return ValidationResult.Invalid
            }
            if (index.tryReservePersistence(record)) {
                try {
                    storage.put(bytes)
                } catch (e: NabuStorageException) {
                    // Couldn't durably persist - don't vouch for it either (never index/re-propagate
                    // something we failed to store). The reserved persistence slot is not rolled
                    // back here - see LtrRecordIndex.tryReservePersistence's doc comment.
                    logger.warn(e) { "failed to persist gossip-received record from $from - declining to accept it" }
                    return ValidationResult.Invalid
                }
            } else {
                // Persistence cap reached - NOT a reason to decline the message. This node's live
                // view and mesh-wide propagation don't depend on this node's own disk budget - see
                // this function's doc comment.
                logger.debug {
                    "persistence cap reached - not durably storing record from $from on $LTR_RECORD_GOSSIP_TOPIC " +
                        "(still tracking and propagating it)"
                }
            }
            if (!index.add(record)) {
                // Narrow race: canAccept() and add() are two separate @Synchronized lock
                // acquisitions - a concurrent gossip delivery of the identical content id could win
                // the index slot between the two calls above. Still propagates - see
                // VeritasGossip.onGossipMessage's identical reasoning.
                logger.debug {
                    "record from $from on $LTR_RECORD_GOSSIP_TOPIC was persisted but lost a narrow index race - " +
                        "propagating anyway"
                }
            }
            return ValidationResult.Valid
        }
    }
}
