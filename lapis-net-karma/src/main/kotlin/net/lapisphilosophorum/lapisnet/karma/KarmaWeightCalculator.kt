package net.lapisphilosophorum.lapisnet.karma

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Pure Karma-value math: `Karma = t / (n+1)`, per the fach-spec's Sybil-resistance design combining
 * a Bitcoin-chain-derived time anchor (`t`) with a scarcity mechanic (`n`, the voter's own prior
 * eligible-vote count - more a voter has voted, less their next vote is worth). No I/O, no side
 * effects, no dependency on `lapis-net-trust` - Veritas-weighting of a vote's contribution to a
 * viewer's personalized score is a separate concern, one layer up (see
 * `net.lapisphilosophorum.lapisnet.browser.KarmaScoring`), never folded into this object.
 *
 * **Why [Double], mirroring [net.lapisphilosophorum.lapisnet.virtus.LtrWeightCalculator]'s exact
 * reasoning, not [net.lapisphilosophorum.lapisnet.trust.VeritasGrant.trustMicros]'s fixed-point
 * convention.** A Karma value is never signed, never part of any [KarmaVoteCodec]-encoded byte
 * sequence, and never compared for cross-node consensus - it is purely a local, per-observer
 * ranking heuristic each node computes independently. `Double` is the natural, simplest type for
 * that purely-local computation.
 *
 * **`n` is NEVER self-declared/signed by the voter - it is always derived by the observer from
 * actually-indexed votes.** This is the security-critical property this whole object exists to
 * protect: if a [KarmaVote] carried its own claimed `n` field, a malicious voter could always claim
 * `n=0` on every vote, permanently defeating the scarcity mechanic (every vote would be worth its
 * full, undiminished `t`). Instead, [karmaValue] takes [allVotesByThisVoter] - the observer's own
 * locally-indexed view of every OTHER vote the same voter has cast (see
 * [KarmaGossip.currentVotesByVoter] / [net.lapisphilosophorum.lapisnet.browser.KarmaScoring]) - and
 * counts `n` from that. Two different observers with two different partial views of the gossip mesh
 * may therefore compute two different `n` (and therefore `karmaValue`) for the identical vote - that
 * is an accepted consequence of this being a local heuristic, not a protocol-consensus value (see
 * this object's class doc comment on why [Double] is safe here for the same reason).
 */
object KarmaWeightCalculator {
    /**
     * A single [vote]'s Karma value as of the observer's own indexed vote history for that voter
     * ([allVotesByThisVoter]):
     *  - [NoAnchorClaim] always yields `0.0` directly - `t` is not even computed for it (an
     *    identity with no recognized chain anchor has no time basis for Karma at all, per the
     *    fach-spec's `t < 0 ⇒ Karma = 0` rule, of which "no anchor" is the degenerate case).
     *  - For a [ChainAnchorClaim], `t = tipHeightAtVote - genesisBlockHeight` (see
     *    [ChainAnchorClaim.t] - structurally guaranteed `>= 0` by that class's own `init` block, so
     *    no additional clamp is needed here, unlike
     *    [net.lapisphilosophorum.lapisnet.virtus.LtrWeightCalculator.decayedWeightMsat]'s
     *    `coerceAtLeast(0.0)` clamp on a value that ISN'T structurally guaranteed).
     *  - `n` = the count of this SAME voter's OTHER votes that also carry a [ChainAnchorClaim],
     *    strictly before [vote] in a deterministic order: sorted by `(timestampSeconds, contentId
     *    bytes)` ascending. This is receipt-order-independent - two observers with the same vote
     *    set (however they arrived over gossip) always compute the identical `n` for the identical
     *    vote, mirroring
     *    [net.lapisphilosophorum.lapisnet.trust.VeritasGrantResolver]'s established discipline of
     *    never letting gossip arrival order leak into a computed value. Votes cast during the
     *    voter's own [NoAnchorClaim] era never count toward `n` for a later eligible vote - only
     *    [ChainAnchorClaim]-carrying votes are "eligible" for the scarcity count at all.
     *
     * `Karma = t / (n + 1)`.
     */
    fun karmaValue(
        vote: KarmaVote,
        allVotesByThisVoter: Collection<KarmaVote>,
    ): Double {
        val anchor = vote.timeAnchor
        if (anchor !is ChainAnchorClaim) return 0.0

        val eligibleOrdered =
            allVotesByThisVoter
                .filter { it.timeAnchor is ChainAnchorClaim }
                .sortedWith(
                    compareBy<KarmaVote> { it.timestampSeconds }
                        .thenBy(ByteArrayComparator) { it.contentId() },
                )
        val voteContentId = vote.contentId()
        val n =
            eligibleOrdered.count { candidate ->
                candidate.timestampSeconds < vote.timestampSeconds ||
                    (
                        candidate.timestampSeconds == vote.timestampSeconds &&
                            ByteArrayComparator.compare(candidate.contentId(), voteContentId) < 0
                    )
            }

        val t = anchor.t.toDouble()
        return t / (n + 1).toDouble()
    }

    /**
     * Sum of [karmaValue] across [votesForTarget] as of the observer's own [votesByVoter]-derived
     * view - the raw (not yet Veritas-weighted) Karma total for a piece of content. Does not mutate
     * [votesForTarget] or any element in it - purely a read-only fold, mirroring
     * [net.lapisphilosophorum.lapisnet.virtus.LtrWeightCalculator.accumulatedWeightMsat]'s shape.
     * Veritas-weighting each vote's contribution before summing is a separate concern, one layer up
     * - see `net.lapisphilosophorum.lapisnet.browser.KarmaScoring.personalizedKarmaForTarget`,
     * which folds [karmaValue] together with a per-voter trust weight instead of calling this
     * function.
     */
    fun totalRawKarmaForTarget(
        votesForTarget: List<KarmaVote>,
        votesByVoter: (Secp256k1PublicKey) -> List<KarmaVote>,
    ): Double = votesForTarget.sumOf { vote -> karmaValue(vote, votesByVoter(vote.voter)) }
}

/** Unsigned lexicographic byte-order comparator - a local, deterministic tiebreak for
 * [KarmaWeightCalculator.karmaValue]'s ordering, mirroring
 * [net.lapisphilosophorum.lapisnet.trust.Secp256k1PublicKeyBytesComparator]'s identical unsigned
 * byte-by-byte comparison shape (duplicated locally rather than reused - this module has no
 * dependency on `lapis-net-trust`, see this module's `build.gradle.kts` comment). */
private object ByteArrayComparator : Comparator<ByteArray> {
    override fun compare(
        a: ByteArray,
        b: ByteArray,
    ): Int {
        val length = minOf(a.size, b.size)
        for (i in 0 until length) {
            val diff = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (diff != 0) return diff
        }
        return a.size - b.size
    }
}
