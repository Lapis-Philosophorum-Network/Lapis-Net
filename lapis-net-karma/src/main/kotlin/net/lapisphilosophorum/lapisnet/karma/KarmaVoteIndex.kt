package net.lapisphilosophorum.lapisnet.karma

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Wraps a [KarmaVote.contentId] byte array with value equality, so it can be used as a
 * `HashMap`/`HashSet` key - a plain `ByteArray` uses reference equality. Mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrContentId] exactly, duplicated locally rather than
 * reused for the same module-boundary reason that class documents. Internal: only
 * [KarmaVoteIndex] (same package) needs this.
 */
internal data class KarmaContentId(
    private val bytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is KarmaContentId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * Bounded, in-memory index of [KarmaVote]s received (locally created or via gossip), keyed by
 * content id, by target [Cid], and by voter. Mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex]'s two-cap eviction/persistence pattern
 * precisely (an evicting in-memory tracking cap vs. a separate, non-evicting, hard-capped
 * persistence cap) - see that class's doc comment for the full round-2/round-3 reasoning this
 * structure is copied from. Like [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex], nothing
 * here ever resolves multiple votes for DIFFERENT voters targeting the same content down to one
 * winner - [votesForTarget] returns EVERY DISTINCT VOTER's tracked vote for that [Cid], because
 * [KarmaWeightCalculator] needs the full set to fold Karma across supporters, and [votesByVoter]
 * needs the full set to compute each vote's `n` (see that object's doc comment on why `n` must be
 * observer-derived, never self-declared).
 *
 * **The one genuine structural deviation from [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex]:
 * TWO secondary (reverse) indices, not one.** [votesByTarget] answers "which votes does this piece
 * of content have" (mirrors `LtrRecordIndex.recordsByPair`'s role); [votesByVoter] answers "which
 * votes has this voter cast" (a wholly new axis Virtus's single `(cid, viewId)` pair-index has no
 * equivalent of - Karma's `n` calculation in [KarmaWeightCalculator] is fundamentally per-voter,
 * not per-target). **Both maps MUST be cleaned in the exact same [removeEldestEntry] override** -
 * an eviction that only cleans one of the two would leave the other holding a stale reference to a
 * vote no longer reachable via [votesByContentId]/[canAccept]'s dedup check, silently corrupting
 * both [votesForTarget]'s accumulation and [votesByVoter]'s `n`-calculation input for as long as
 * this process runs. See `KarmaVoteIndexTest`'s dedicated "eviction removes from BOTH buckets" test
 * for the regression guard this specific risk warrants.
 *
 * **At most ONE tracked vote per `(voter, targetCid)` pair - security-critical, not merely tidy.**
 * [KarmaVote.nonce] makes every vote content-id-distinct (see that field's doc comment), so
 * [votesByContentId]'s dedup-by-content-id alone does NOT stop a single identity from signing and
 * gossiping unlimited free votes toward the same target - unlike
 * [net.lapisphilosophorum.lapisnet.virtus.LtrRecord], a [KarmaVote] carries no PoW/stake admission
 * cost. Left unchecked, that has two consequences: (1) a flood of same-target votes from one voter
 * evicts unrelated voters'/targets' votes out of the shared [MAX_TRACKED_VOTES] LRU cap, and (2)
 * [KarmaWeightCalculator]'s `t/(n+1)` marginal-diminishing-return math only shrinks each individual
 * repeat vote's OWN value - the TOTAL contribution of `M` repeat votes from one voter toward one
 * target still grows without bound as `t * H_M` (the `M`th harmonic number), letting one identity
 * inflate a single target's Karma arbitrarily by voting for it over and over. [add] closes both
 * vectors by enforcing "one tracked vote per (voter, targetCid)" directly: when a new vote arrives
 * from a voter who already has a tracked vote for that same target, the new vote REPLACES the old
 * one (most-recent-arrival wins) rather than being added alongside it - see [add]'s doc comment.
 * This also happens to match the "one-click like" semantics [KarmaVote]'s own doc comment describes
 * - a like is naturally a toggle/refresh per (voter, target), not an accumulating pile of clicks.
 */
class KarmaVoteIndex internal constructor(
    private val maxTracked: Int = MAX_TRACKED_VOTES,
    private val maxPersisted: Int = MAX_PERSISTED_VOTES,
) {
    /** Public entry point - always uses [MAX_TRACKED_VOTES]/[MAX_PERSISTED_VOTES]. The internal
     * constructor above exists purely as a test seam, mirroring
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex]'s own constructor pattern. */
    constructor() : this(MAX_TRACKED_VOTES, MAX_PERSISTED_VOTES)

    private val votesByTarget = HashMap<Cid, MutableList<KarmaVote>>()
    private val votesByVoterMap = HashMap<Secp256k1PublicKey, MutableList<KarmaVote>>()

    /** Key for [currentVoteByVoterTarget] - see this class's doc comment on the "one tracked vote
     * per (voter, targetCid)" invariant [add] enforces. Deliberately a separate small key type
     * rather than `Pair<Secp256k1PublicKey, Cid>`, purely for readability at call sites. */
    private data class VoterTargetKey(
        val voter: Secp256k1PublicKey,
        val targetCid: Cid,
    )

    /** The single currently-tracked vote for each `(voter, targetCid)` pair - see this class's doc
     * comment on why this invariant exists. Kept as its own map (rather than re-derived by
     * scanning [votesByVoterMap] on every [add]) so replacement is O(1). Cleaned in lockstep with
     * [votesByContentId]/[votesByTarget]/[votesByVoterMap] on both eviction ([removeEldestEntry])
     * and replacement ([add]) - the same "every index MUST be kept in sync" discipline this class's
     * doc comment already establishes for the other two secondary indices. */
    private val currentVoteByVoterTarget = HashMap<VoterTargetKey, KarmaVote>()

    /** Backed by a [LinkedHashMap] constructed with access-order tracking enabled, exactly
     * mirroring [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.recordsByContentId] - see
     * that field's doc comment for why this is FIFO-equivalent in practice, not true LRU.
     *
     * [removeEldestEntry] cleans [votesByTarget], [votesByVoterMap], AND
     * [currentVoteByVoterTarget] off the evicted entry's value - see this class's doc comment for
     * why keeping every secondary index in sync here, in one place, is this class's single
     * highest-risk correctness property. */
    private val votesByContentId =
        object : LinkedHashMap<KarmaContentId, KarmaVote>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<KarmaContentId, KarmaVote>): Boolean {
                if (size <= maxTracked) return false
                removeFromSecondaryIndices(eldest.value)
                return true
            }
        }

    /** Removes [evicted] from every secondary index that isn't [votesByContentId] itself - shared
     * by [removeEldestEntry] (global LRU eviction) and [add] (per-(voter,target) replacement), the
     * two places a vote already tracked in [votesByContentId] can stop being tracked. Idempotent
     * no-ops safely if [evicted] is already absent from a given bucket - callers rely on that (see
     * [add]'s replacement path, which may run against a vote that a prior LRU eviction already
     * partially cleaned up). [currentVoteByVoterTarget] is only cleared if it still points at
     * EXACTLY [evicted] - a newer vote for the same (voter, targetCid) may already have overwritten
     * that slot via [add]'s replacement path, and this must never clobber that newer entry. */
    private fun removeFromSecondaryIndices(evicted: KarmaVote) {
        val targetBucket = votesByTarget[evicted.targetCid]
        targetBucket?.remove(evicted)
        if (targetBucket != null && targetBucket.isEmpty()) votesByTarget.remove(evicted.targetCid)

        val voterBucket = votesByVoterMap[evicted.voter]
        voterBucket?.remove(evicted)
        if (voterBucket != null && voterBucket.isEmpty()) votesByVoterMap.remove(evicted.voter)

        val key = VoterTargetKey(evicted.voter, evicted.targetCid)
        if (currentVoteByVoterTarget[key] == evicted) currentVoteByVoterTarget.remove(key)
    }

    /** Backing set for [tryReservePersistence] - a plain, never-evicting [HashSet], mirroring
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.persistedContentIds] exactly. */
    private val persistedContentIds = HashSet<KarmaContentId>()

    /**
     * Adds [vote] to the index. Returns `true` iff it was newly added; `false` for an exact
     * duplicate (by content id) or a signature-invalid vote - **never throws**, mirroring
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.add]'s "last line of defense before
     * untrusted gossip data reaches this node's in-memory state" contract exactly, including the
     * defensive re-verification of [vote]'s signature.
     *
     * **Enforces "at most one tracked vote per `(voter, targetCid)`"** - see this class's doc
     * comment for why. If [vote]'s voter already has a DIFFERENT tracked vote for the same
     * [KarmaVote.targetCid] (necessarily a different content id, since [vote] just cleared the
     * exact-duplicate check above), that older vote is fully removed from every index
     * ([removeFromSecondaryIndices] plus its own [votesByContentId] entry) before [vote] is added -
     * "most-recent-arrival wins", not a timestamp comparison. Still returns `true` in this
     * replacement case: [vote] itself IS newly added, even though it displaced another entry.
     */
    @Synchronized
    fun add(vote: KarmaVote): Boolean =
        runCatching {
            if (!KarmaVote.verify(vote)) return@runCatching false
            val id = KarmaContentId(vote.contentId())
            if (votesByContentId.containsKey(id)) return@runCatching false

            val key = VoterTargetKey(vote.voter, vote.targetCid)
            currentVoteByVoterTarget[key]?.let { previous ->
                votesByContentId.remove(KarmaContentId(previous.contentId()))
                removeFromSecondaryIndices(previous)
            }

            votesByContentId[id] = vote
            votesByTarget.getOrPut(vote.targetCid) { mutableListOf() }.add(vote)
            votesByVoterMap.getOrPut(vote.voter) { mutableListOf() }.add(vote)
            currentVoteByVoterTarget[key] = vote
            true
        }.getOrDefault(false)

    /**
     * Cheap, non-mutating, no-I/O admission pre-check: `true` iff [vote] is not already tracked by
     * content id. Mirrors
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.canAccept]'s contract exactly.
     */
    @Synchronized
    fun canAccept(vote: KarmaVote): Boolean = !votesByContentId.containsKey(KarmaContentId(vote.contentId()))

    /**
     * Admission gate purely for **durable persistence** - a bounded, non-evicting,
     * hard-reject-once-[maxPersisted] cap, entirely separate from [votesByContentId]'s evicting
     * cap. Mirrors
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.tryReservePersistence]'s contract
     * exactly, including atomic reserve-before-put semantics and idempotency per content id.
     */
    @Synchronized
    fun tryReservePersistence(vote: KarmaVote): Boolean {
        val id = KarmaContentId(vote.contentId())
        if (persistedContentIds.contains(id)) return true
        if (persistedContentIds.size >= maxPersisted) return false
        persistedContentIds.add(id)
        return true
    }

    /** Every tracked [KarmaVote] for [cid], in insertion order. */
    @Synchronized
    internal fun votesForTarget(cid: Cid): List<KarmaVote> = votesByTarget[cid]?.toList() ?: emptyList()

    /** Every tracked [KarmaVote] cast by [voter], in insertion order - the input
     * [KarmaWeightCalculator.karmaValue]'s `n` calculation folds over. */
    @Synchronized
    internal fun votesByVoter(voter: Secp256k1PublicKey): List<KarmaVote> =
        votesByVoterMap[voter]?.toList() ?: emptyList()

    /** Every distinct target [Cid] with at least one tracked vote. */
    @Synchronized
    internal fun allTargets(): Set<Cid> = votesByTarget.keys.toSet()

    companion object {
        /**
         * Upper bound on distinct votes tracked from gossip. Same provisional-magnitude caveat as
         * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.MAX_TRACKED_RECORDS] applies:
         * chosen for parity with that existing precedent rather than derived from real pilot usage
         * data - Karma votes are a "like" mechanic and may see substantially higher volume than LTR
         * boosts in practice; revisit once real traffic is observed.
         */
        const val MAX_TRACKED_VOTES = 64_000

        /**
         * Upper bound on distinct votes this node will durably persist via `NabuStorage.put()` from
         * gossip - see [tryReservePersistence] and
         * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex.MAX_PERSISTED_RECORDS]'s doc
         * comment for the full reasoning this mirrors. Same provisional-magnitude caveat as
         * [MAX_TRACKED_VOTES] applies.
         */
        const val MAX_PERSISTED_VOTES = 64_000
    }
}
