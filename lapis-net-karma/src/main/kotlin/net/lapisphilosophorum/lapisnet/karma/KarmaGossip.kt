package net.lapisphilosophorum.lapisnet.karma

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
 * Karma-specific wiring on top of the domain-agnostic [GossipPubSub]: propagates [KarmaVote]s over
 * a dedicated topic, persists every accepted vote into [NabuStorage], and exposes the tracked vote
 * sets ([currentVotesForTarget]/[currentVotesByVoter]) a viewer needs to compute personalized Karma
 * scores (see `net.lapisphilosophorum.lapisnet.browser.KarmaScoring`, one layer up). Mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip]'s structure and persistence-lifecycle ordering
 * precisely - see that class's doc comment for the general pattern this follows.
 *
 * **No chain verification anywhere in this file - the central design decision for this whole
 * module, stated here because [onGossipMessage] is where it is load-bearing.** [onGossipMessage]
 * validates ONLY structure ([KarmaVoteCodec.decode]) and the [KarmaVote] signature
 * ([KarmaVote.verify]) - it never calls Electrum, never resolves a [ChainAnchorClaim] against a
 * real chain, and never makes any network call of any kind. This mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.OnChainProof]'s already-accepted V0.2.1 "structural-only"
 * precedent and is deliberate for three reasons:
 *  1. Gating message acceptance on a blocking third-party network call (an Electrum round-trip)
 *     would make this node's mesh behavior depend on a third party's uptime - a single slow or
 *     down Electrum server could stall or block gossip validation entirely.
 *  2. Different nodes might reach different Electrum servers (or none at all, per
 *     [ElectrumServers.PLACEHOLDER]'s doc comment) and could therefore resolve the identical
 *     [ChainAnchorClaim] to different real-world truth values, or fail differently - breaking this
 *     codebase's established invariant that the SAME structural+signature rules applied to the SAME
 *     bytes always yield the SAME accept/reject decision on every honest node. A GossipSub
 *     validator that can disagree between honest nodes undermines the mesh's re-propagation
 *     guarantees.
 *  3. It would hand a malicious peer a trivial amplification DoS: flood a topic with structurally
 *     valid, validly-signed [KarmaVote]s carrying fabricated [ChainAnchorClaim]s, and force every
 *     relaying node in the mesh to independently perform an outbound Electrum lookup per message.
 *
 * The REAL chain lookup - resolving a voter's OWN [TimeAnchorClaim] before casting a vote - only
 * ever runs client-side, in [KarmaAnchorCache] (one layer up, in `lapis-net-browser`), never here.
 * A [ChainAnchorClaim] gossiped by a peer is trusted exactly as far as its structural validity and
 * the voter's own signature go - no further. This is the same trust model
 * [net.lapisphilosophorum.lapisnet.virtus.OnChainProof]'s doc comment documents for LTR records: a
 * malicious voter can costlessly fabricate an arbitrarily favorable [ChainAnchorClaim] today, and
 * that is a known, accepted limitation of this wave, not a silent gap.
 *
 * **Publishes full vote bytes, not a [Cid] pointer** - same reasoning as
 * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip]'s own doc comment (a
 * [KarmaVoteCodec.MAX_BODY_SIZE]-bounded vote plus a 64-byte signature is tiny relative to any
 * reasonable gossip message-size ceiling).
 *
 * **Persistence lifecycle order is load-bearing, not stylistic** - identical to
 * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip]:
 *  - Local creation ([announce]): `put()` -> `index.add()` -> `publish()`, publish always last.
 *  - Gossip receipt ([onGossipMessage]): [KarmaVoteIndex.canAccept] (cheap, dedup-only) gates
 *    everything; [KarmaVoteIndex.tryReservePersistence] (a separate, non-evicting cap)
 *    independently gates `put()`; reaching the persistence cap must NOT decline or invalidate the
 *    gossip message - this node's disk budget has no bearing on whether the message is valid or
 *    should keep propagating to the rest of the mesh.
 */
class KarmaGossip private constructor(
    private val pubsub: GossipPubSub,
    private val storage: NabuStorage,
    private val index: KarmaVoteIndex,
    private val subscription: PubsubSubscription,
) {
    /**
     * Persists, indexes, then publishes an already-locally-verified (self-signed) [vote]. Order
     * matters (see class doc comment): `publish()` is the only externally-visible step and always
     * happens last.
     *
     * If [index.add] declines to track this node's own vote (an exact content-id duplicate - see
     * [KarmaVoteIndex.add]; the index evicts rather than rejects for "full", so that is not a
     * possible cause here), that is logged at `warn` - the vote is still durably persisted and
     * still gets published either way, mirroring
     * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip.announce]'s exact contract.
     *
     * **No delivery guarantee** - see [GossipPubSub.publish]'s doc comment, which this defers to.
     */
    fun announce(vote: KarmaVote) {
        val bytes = KarmaVoteCodec.encode(vote)
        storage.put(bytes)
        if (!index.add(vote)) {
            logger.warn {
                "own announced vote (content id ${vote.contentId().fingerprintHex()}) was not tracked " +
                    "locally - already durably persisted and will still be published"
            }
        }
        pubsub.publish(KARMA_VOTE_GOSSIP_TOPIC, bytes)
    }

    /** Every tracked [KarmaVote] for [cid], in insertion order - see
     * [KarmaVoteIndex.votesForTarget]'s doc comment on why this is never resolved to one winner. */
    fun currentVotesForTarget(cid: Cid): List<KarmaVote> = index.votesForTarget(cid)

    /** Every tracked [KarmaVote] cast by [voter], in insertion order - the raw input
     * [net.lapisphilosophorum.lapisnet.browser.KarmaScoring] (and, beneath it,
     * [KarmaWeightCalculator]) needs to compute a voter's own `n`. */
    fun currentVotesByVoter(voter: Secp256k1PublicKey): List<KarmaVote> = index.votesByVoter(voter)

    /** Unsubscribes from the gossip topic. No other sub-resources to release - mirrors
     * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip.stop] exactly. */
    fun stop() {
        subscription.unsubscribe()
    }

    companion object {
        /** Dedicated GossipSub topic for Karma vote propagation - deliberately a separate string
         * from [KarmaVote]'s own signing domain-separation tag, same reasoning as
         * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip.LTR_RECORD_GOSSIP_TOPIC]'s doc comment. */
        const val KARMA_VOTE_GOSSIP_TOPIC = "LapisNet:karma-vote-gossip:v1"

        /**
         * Attaches Karma-specific GossipSub wiring on top of an already-[GossipPubSub.attach]-ed
         * [pubsub] and an already-[NabuStorage.attach]-ed [storage]. Subscribes to
         * [KARMA_VOTE_GOSSIP_TOPIC] immediately - see [onGossipMessage] for the validator.
         */
        fun attach(
            pubsub: GossipPubSub,
            storage: NabuStorage,
        ): KarmaGossip {
            val index = KarmaVoteIndex()
            val subscription =
                pubsub.subscribe(KARMA_VOTE_GOSSIP_TOPIC) { bytes, from ->
                    onGossipMessage(bytes, from, storage, index)
                }
            return KarmaGossip(pubsub, storage, index, subscription)
        }

        /**
         * The GossipSub validator: structural decode AND signature verification happen here in one
         * step, gating both this node's acceptance and mesh-wide re-propagation. **No network or
         * chain call of any kind happens in this function** - see this class's doc comment for the
         * full reasoning. Mirrors
         * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip.onGossipMessage]'s three-way structure
         * exactly:
         *  1. [KarmaVoteIndex.canAccept] - cheap, in-memory, dedup-only - declines an exact
         *     content-id duplicate immediately, with no persist attempt, no indexing, and no
         *     re-propagation.
         *  2. For anything that clears step 1, [KarmaVoteIndex.tryReservePersistence] - a separate,
         *     non-evicting cap - decides whether [storage].`put()` is even attempted.
         *  3. [KarmaVoteIndex.add] always runs for a vote that cleared step 1, and this function
         *     always returns `Valid` for it - regardless of whether step 2 actually persisted it.
         *     Only a genuine decode failure, signature failure, or `put()` throwing
         *     [NabuStorageException] returns `Invalid`.
         *
         * Visibility is `internal`, not `private`, purely as a test seam - mirrors
         * `LtrGossip.onGossipMessage`'s own documented reasoning.
         */
        internal fun onGossipMessage(
            bytes: ByteArray,
            from: PeerId,
            storage: NabuStorage,
            index: KarmaVoteIndex,
        ): ValidationResult {
            val vote =
                try {
                    KarmaVoteCodec.decode(bytes)
                } catch (e: MalformedKarmaVoteException) {
                    logger.debug(e) {
                        "rejected structurally malformed vote from $from on $KARMA_VOTE_GOSSIP_TOPIC"
                    }
                    return ValidationResult.Invalid
                }
            if (!KarmaVote.verify(vote)) {
                logger.debug { "rejected signature-invalid vote from $from on $KARMA_VOTE_GOSSIP_TOPIC" }
                return ValidationResult.Invalid
            }
            if (!index.canAccept(vote)) {
                logger.debug {
                    "declining duplicate (already-tracked) vote from $from on $KARMA_VOTE_GOSSIP_TOPIC - " +
                        "not persisting or re-propagating"
                }
                return ValidationResult.Invalid
            }
            if (index.tryReservePersistence(vote)) {
                try {
                    storage.put(bytes)
                } catch (e: NabuStorageException) {
                    // Couldn't durably persist - don't vouch for it either (never index/re-propagate
                    // something we failed to store). The reserved persistence slot is not rolled
                    // back here - see KarmaVoteIndex.tryReservePersistence's doc comment.
                    logger.warn(e) { "failed to persist gossip-received vote from $from - declining to accept it" }
                    return ValidationResult.Invalid
                }
            } else {
                // Persistence cap reached - NOT a reason to decline the message. This node's live
                // view and mesh-wide propagation don't depend on this node's own disk budget - see
                // this function's doc comment.
                logger.debug {
                    "persistence cap reached - not durably storing vote from $from on " +
                        "$KARMA_VOTE_GOSSIP_TOPIC (still tracking and propagating it)"
                }
            }
            if (!index.add(vote)) {
                // Narrow race: canAccept() and add() are two separate @Synchronized lock
                // acquisitions - a concurrent gossip delivery of the identical content id could win
                // the index slot between the two calls above. Still propagates - see
                // LtrGossip.onGossipMessage's identical reasoning.
                logger.debug {
                    "vote from $from on $KARMA_VOTE_GOSSIP_TOPIC was persisted but lost a narrow index " +
                        "race - propagating anyway"
                }
            }
            return ValidationResult.Valid
        }
    }
}
