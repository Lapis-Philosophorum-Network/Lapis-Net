package net.lapisphilosophorum.lapisnet.virtus

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Wraps an [LtrRecord.contentId] byte array with value equality, so it can be used as a
 * `HashMap`/`HashSet` key - a plain `ByteArray` uses reference equality. Mirrors
 * [net.lapisphilosophorum.lapisnet.trust.GrantContentId] exactly, duplicated locally rather than
 * reused: `lapis-net-virtus` has no dependency edge to `lapis-net-trust` (see this module's
 * `build.gradle.kts` comment - Virtus is a sibling scoring dimension, not built on Veritas).
 * Internal: only [LtrRecordIndex] (same package) needs this.
 */
internal data class LtrContentId(
    private val bytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is LtrContentId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * Bounded, in-memory index of [LtrRecord]s received (locally created or via gossip), keyed by
 * content id and by `(cid, viewId)` pair. Mirrors
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex]'s two-cap eviction/persistence
 * pattern precisely - see that class's doc comment for the full round-2/round-3 reasoning this
 * structure is copied from (evicting in-memory tracking cap vs. a separate, non-evicting,
 * hard-capped persistence cap, and why those need to be two independent resources).
 *
 * **One deliberate behavioral difference from [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex]:**
 * nothing here ever resolves multiple records for the same `(cid, viewId)` pair down to one
 * winner. [recordsFor] returns EVERY tracked record for that pair, because per the Virtus spec
 * note's "Akkumulationslogik" section, every boost accumulates independently - there is no
 * backward-hash chain and no "latest wins" resolution (see [LtrRecord]'s own doc comment). The
 * reverse index is therefore keyed off a plain `(Cid, Secp256k1PublicKey)` pair (not a
 * `(Secp256k1PublicKey, Secp256k1PublicKey)` truster/target pair like `VeritasGrantIndex`), still
 * mapping to a `MutableList<LtrRecord>`, kept in sync on eviction via `removeEldestEntry` exactly
 * like `VeritasGrantIndex`'s own reverse index.
 */
class LtrRecordIndex internal constructor(
    private val maxTracked: Int = MAX_TRACKED_RECORDS,
    private val maxPersisted: Int = MAX_PERSISTED_RECORDS,
) {
    /** Public entry point - always uses [MAX_TRACKED_RECORDS]/[MAX_PERSISTED_RECORDS]. The
     * internal constructor above exists purely as a test seam, mirroring
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex]'s own constructor pattern. */
    constructor() : this(MAX_TRACKED_RECORDS, MAX_PERSISTED_RECORDS)

    private val recordsByPair = HashMap<Pair<Cid, Secp256k1PublicKey>, MutableList<LtrRecord>>()

    /** Backed by a [LinkedHashMap] constructed with access-order tracking enabled, exactly
     * mirroring [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.grantsByContentId] -
     * see that field's doc comment for why this is FIFO-equivalent in practice, not true LRU. */
    private val recordsByContentId =
        object : LinkedHashMap<LtrContentId, LtrRecord>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<LtrContentId, LtrRecord>): Boolean {
                if (size <= maxTracked) return false
                val evicted = eldest.value
                val pairKey = evicted.cid to evicted.viewId
                val bucket = recordsByPair[pairKey]
                bucket?.remove(evicted)
                if (bucket != null && bucket.isEmpty()) recordsByPair.remove(pairKey)
                return true
            }
        }

    /** Backing set for [tryReservePersistence] - a plain, never-evicting [HashSet], mirroring
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.persistedContentIds] exactly. */
    private val persistedContentIds = HashSet<LtrContentId>()

    /**
     * Adds [record] to the index. Returns `true` iff it was newly added; `false` for a duplicate
     * (by content id), a signature-invalid record, or - for a [LightningProof]-backed record - one
     * whose [LightningProof.paymentHash] already backs another tracked record for the same
     * `(cid, viewId)` pair - **never throws**, mirroring
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.add]'s "last line of defense
     * before untrusted gossip data reaches this node's in-memory state" contract exactly,
     * including the defensive re-verification of [record]'s signature.
     *
     * **Round-2 atomicity fix - THIS METHOD is now the single authoritative, atomic gate for BOTH
     * invariants (content-id dedup AND payment-hash dedup).** Two independent round-2 reviewers
     * converged on the same finding: the payment-hash check-then-act used to be split across two
     * separate `@Synchronized` lock acquisitions - a read-only pre-check
     * ([hasLightningPaymentBeenUsed], consulted by [canAccept]/[LtrGossip.announce]) and this
     * method's mutation, acquired separately. Because a JVM intrinsic lock is released between two
     * separate `@Synchronized` calls, N concurrent callers could all pass the pre-check (none of
     * them had committed yet), then all successfully call this method - each with a *different*
     * content id (a fresh nonce/payer key per [LtrRecord.create] call, exactly what
     * `POST /api/ltr/lightning` produces per request), so the content-id dedup below never caught
     * them either. One real payment could thereby mint N times its weight within one race window.
     *
     * The fix: the payment-hash nullifier check now runs INSIDE this method's own `@Synchronized`
     * critical section, immediately before the mutation, exactly mirroring how the content-id dedup
     * immediately below it already was atomic. [hasLightningPaymentBeenUsed] is itself
     * `@Synchronized` on this same instance - calling it from here is safely reentrant (a JVM
     * intrinsic lock may be re-acquired by the thread that already holds it) and does NOT release
     * the lock in between, so no other thread's [add] can interleave between the check and the
     * commit. Whichever caller's thread wins this method's lock first only ever mutates the
     * `(cid, viewId)` pair; every other concurrent caller racing on the same payment hash sees the
     * winner's record already present and is atomically rejected - "exactly one winner" is now a
     * true invariant of this method alone, not an accident of scheduling.
     *
     * [canAccept] (gossip path) and the inline pre-check in [LtrGossip.announce] (local
     * self-announce path) remain in place as cheap, non-mutating early-outs - they save an
     * unnecessary `storage.put()` for a record that is obviously going to be rejected - but they
     * are no longer the only enforcement, and this method's return value is trustworthy on its own
     * even if a caller skips them entirely or loses its own race against them.
     */
    @Synchronized
    fun add(record: LtrRecord): Boolean =
        runCatching {
            if (!LtrRecord.verify(record)) return@runCatching false
            val id = LtrContentId(record.contentId())
            if (recordsByContentId.containsKey(id)) return@runCatching false
            val proof = record.proof
            if (proof is LightningProof && hasLightningPaymentBeenUsed(record.cid, record.viewId, proof.paymentHash)) {
                return@runCatching false
            }
            recordsByContentId[id] = record
            recordsByPair.getOrPut(record.cid to record.viewId) { mutableListOf() }.add(record)
            true
        }.getOrDefault(false)

    /**
     * Cheap, non-mutating, no-I/O admission pre-check: `true` iff [record] is not already tracked
     * by content id, AND - for a [LightningProof]-backed record - its [LightningProof.paymentHash]
     * has not already backed another tracked record for the same `(cid, viewId)` pair (see
     * [hasLightningPaymentBeenUsed]'s doc comment for the full "spent payment-hash" reasoning).
     * Mirrors [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.canAccept]'s contract for
     * the content-id half exactly - see that method's doc comment for why this alone does not
     * bound durable persistence.
     *
     * **Round-2: this is a cheap early-out, NOT the atomic gate.** [add] is the sole authoritative,
     * atomic enforcement of both invariants (see [add]'s doc comment) - this method's read-only
     * pre-check and [add]'s later mutation are still two separate `@Synchronized` acquisitions, so
     * a concurrent caller can race between them exactly as before. That race is now harmless: it
     * only wastes a [tryReservePersistence]/`storage.put()` call for a record [add] is going to
     * reject anyway, because [add] re-checks and rejects atomically regardless of what this method
     * returned. Callers must not treat a `true` result here as a guarantee that [add] will also
     * accept the same record.
     *
     * Consulted by [LtrGossip.onGossipMessage] as its step-1 gate for gossip-received records -
     * both halves (content-id AND payment-hash dedup) are exactly what a gossip delivery needs:
     * an exact-content-id redelivery must never re-propagate, and neither must a genuinely new
     * record that reuses an already-spent payment hash.
     *
     * **NOT used directly by [LtrGossip.announce]** - the local self-announce path re-announces
     * the SAME already-tracked [LtrRecord] object on retry (to work around gossip-mesh warm-up
     * delivery flakiness - see [net.lapisphilosophorum.lapisnet.virtus.TwoNodeLtrGossipIntegrationTest]),
     * and that harmless, idempotent re-send must still re-publish even though the content id is
     * already tracked - behavior this method's content-id half would incorrectly veto. [announce]
     * therefore consults [isTrackedByContentId] and [hasLightningPaymentBeenUsed] directly, with
     * the extra "only reject a genuinely NEW record" precondition this method doesn't need. The
     * underlying dedup logic (payment-hash reuse) still lives in exactly one place -
     * [hasLightningPaymentBeenUsed] - both call sites just apply it with the preconditions their
     * own caller's retry semantics require.
     */
    @Synchronized
    fun canAccept(record: LtrRecord): Boolean {
        if (isTrackedByContentId(record)) return false
        val proof = record.proof
        if (proof is LightningProof && hasLightningPaymentBeenUsed(record.cid, record.viewId, proof.paymentHash)) {
            return false
        }
        return true
    }

    /** `true` iff [record]'s content id is already tracked - the content-id-only half of
     * [canAccept], exposed separately so [LtrGossip.announce] can distinguish "this exact record
     * was already accepted, a harmless re-send" from "this is a genuinely new record" (see
     * [canAccept]'s doc comment for why [announce] cannot use [canAccept] directly). */
    @Synchronized
    internal fun isTrackedByContentId(record: LtrRecord): Boolean =
        recordsByContentId.containsKey(LtrContentId(record.contentId()))

    /**
     * `true` iff `(cid, viewId)` already has a tracked record whose [LtrRecord.proof] is a
     * [LightningProof] carrying this exact [paymentHash] - the "spent payment-hash" nullifier
     * that stops the SAME already-bound `(cid, viewId, paymentHash)` triple from backing more than
     * one accepted [LtrRecord] (see the Virtus spec note and
     * [LightningProofVerifier.canonicalMemo]'s doc comment: the invoice's own signed memo already
     * binds one payment to exactly one `(cid, viewId)` pair - this check additionally ensures that
     * binding can only be spent once, mirroring a Lightning-style anti-double-spend nullifier).
     * Consulted by [canAccept] and the inline pre-check in [LtrGossip.announce] as a cheap early-out
     * for every [LightningProof] record, and consulted AGAIN by [add] itself - under [add]'s own
     * lock acquisition, immediately before the mutation - as the actual atomic gate (see [add]'s
     * doc comment for the round-2 fix this enables). The underlying dedup logic lives in exactly
     * this one place; every call site applies it, but only [add]'s own invocation is
     * security-load-bearing.
     *
     * **Deliberately scoped to `(cid, viewId, paymentHash)`, NOT global.** The same payment
     * funding two DIFFERENT `(cid, viewId)` pairs is a separate, out-of-scope concern here -
     * [LightningProofVerifier.canonicalMemo] already binds one payment to exactly one
     * `(cid, viewId)` pair inside the invoice's own BOLT-11-signed memo, so a payer cannot spoof a
     * *different* `(cid, viewId)` with the same payment without a fresh, differently-memo'd
     * invoice (which [LightningProofVerifier.verify] would reject as a memo mismatch). This check
     * only stops the SAME already-bound triple from being resubmitted to mint additional weight.
     *
     * **Known gap - bounded by [MAX_TRACKED_RECORDS] eviction, not a silent oversight.** This
     * method only sees records still present in [recordsByContentId]'s evicting, access-order LRU
     * cap (see [recordsFor], which this delegates to). If the original record backed by
     * [paymentHash] is evicted - the index is at [MAX_TRACKED_RECORDS] capacity and this pair's
     * record happens to be the least recently touched - a resubmission of the same payment after
     * that eviction is no longer caught here and would be accepted as though it were a fresh
     * payment. This is a bounded, acknowledged gap, deliberately documented rather than hidden -
     * mirrors this codebase's established precedent for eviction-vs-invariant tradeoffs (see
     * [OnChainProof]'s "Known gap" doc comment and
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex]'s own round-2/round-3 eviction-cap
     * doc comments).
     */
    @Synchronized
    internal fun hasLightningPaymentBeenUsed(
        cid: Cid,
        viewId: Secp256k1PublicKey,
        paymentHash: ByteArray,
    ): Boolean =
        recordsFor(cid, viewId).any { existing ->
            val existingProof = existing.proof
            existingProof is LightningProof && existingProof.paymentHash.contentEquals(paymentHash)
        }

    /**
     * Admission gate purely for **durable persistence** - a bounded, non-evicting,
     * hard-reject-once-[maxPersisted] cap, entirely separate from [recordsByContentId]'s evicting
     * cap. Mirrors
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.tryReservePersistence]'s contract
     * exactly, including atomic reserve-before-put semantics and idempotency per content id.
     */
    @Synchronized
    fun tryReservePersistence(record: LtrRecord): Boolean {
        val id = LtrContentId(record.contentId())
        if (persistedContentIds.contains(id)) return true
        if (persistedContentIds.size >= maxPersisted) return false
        persistedContentIds.add(id)
        return true
    }

    /** Every tracked record for the `(cid, viewId)` pair, in insertion order - unlike
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.grantsFor], this is never resolved
     * down to a single winner (see this class's doc comment). */
    @Synchronized
    internal fun recordsFor(
        cid: Cid,
        viewId: Secp256k1PublicKey,
    ): List<LtrRecord> = recordsByPair[cid to viewId]?.toList() ?: emptyList()

    /** Every distinct `(cid, viewId)` pair with at least one tracked record. */
    @Synchronized
    internal fun allPairs(): Set<Pair<Cid, Secp256k1PublicKey>> = recordsByPair.keys.toSet()

    companion object {
        /**
         * Upper bound on distinct records tracked from gossip. Borrowed in *magnitude* from
         * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.MAX_TRACKED_GRANTS] but NOT its
         * social-graph-size (Dunbar's-number) justification - LTR records scale with content and
         * engagement volume, a fundamentally different growth driver than a personal trust graph's
         * edge count. This number is provisional, chosen for parity with the existing precedent
         * rather than derived from real pilot usage data; revisit once actual Virtus traffic
         * volumes are observed.
         */
        const val MAX_TRACKED_RECORDS = 64_000

        /**
         * Upper bound on distinct records this node will durably persist via `NabuStorage.put()`
         * from gossip - see [tryReservePersistence] and
         * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.MAX_PERSISTED_GRANTS]'s doc
         * comment for the full reasoning this mirrors. Same provisional-magnitude caveat as
         * [MAX_TRACKED_RECORDS] applies.
         */
        const val MAX_PERSISTED_RECORDS = 64_000
    }
}
