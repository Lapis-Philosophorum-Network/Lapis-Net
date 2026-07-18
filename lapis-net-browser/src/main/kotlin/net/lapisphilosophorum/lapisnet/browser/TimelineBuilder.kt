package net.lapisphilosophorum.lapisnet.browser

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.KarmaVote
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.virtus.LtrRecord
import net.lapisphilosophorum.lapisnet.virtus.LtrWeightCalculator

/**
 * Combines Veritas trust-graph credibility ([CredibilityCalculator]) and Virtus/LTR sort-weight
 * ([LtrWeightCalculator]) into a sorted, filterable browser timeline. Also attaches a personalized
 * Karma score ([KarmaScoring]) to each entry - see [build]'s doc comment for why that attachment is
 * deliberately display-only and never affects sort order or filtering.
 */
object TimelineBuilder {
    /** UI-POLICY default, deliberately NOT a protocol constant: 25% - below this resolved
     * credibility score, a post is filtered out of the default view by [visible]. A pilot-stage
     * choice for the Minimal-Browser MVP, not derived from the Veritas spec. */
    const val DEFAULT_CREDIBILITY_FILTER_THRESHOLD_MICROS = 250_000

    data class TimelineOptions(
        val credibilityFilterThresholdMicros: Int = DEFAULT_CREDIBILITY_FILTER_THRESHOLD_MICROS,
        val atEpochSeconds: Long = System.currentTimeMillis() / 1000,
    )

    /**
     * Scores and sorts [candidates] into [TimelineEntry] objects. For each candidate: resolves
     * [Credibility] via [CredibilityCalculator.credibility]; looks up its [LtrRecord]s in
     * [ltrRecordsByCid] (missing entries treated as no records, never an error); computes the
     * decayed, overflow-safe [LtrWeightCalculator.accumulatedWeightMsat] as of
     * [TimelineOptions.atEpochSeconds] - reused as-is, pure `Double` math already hardened in
     * V0.2.1, not reimplemented here.
     *
     * **Deliberately never calls [LtrWeightCalculator.totalInvestedMsat] anywhere in this
     * function.** That function throws [ArithmeticException] on overflow (a realistic, cheap
     * attack per V0.2.1's own findings - see its doc comment) and nothing here needs an exact
     * "total sats invested" figure, only the overflow-safe decayed weight [accumulatedWeightMsat]
     * already provides.
     *
     * Sorted by [TimelineEntry.ltrWeightMsat] descending, then by
     * [TimelineEntry.publishedAtEpochSeconds] descending (most recent first) as a tie-break for
     * zero-weight (or equal-weight) posts.
     *
     * **[karmaVotesByCid]/[karmaVotesByVoter] feed [TimelineEntry.karmaScore]/[TimelineEntry.karmaVoteCount] -
     * deliberately additive/display-only, NEVER folded into [filteredOut] or the sort order above.**
     * The fach-spec's original vision for Karma is as a trust-network "bridge" - letting Karma
     * surface content from beyond a viewer's direct/transitive trust graph. Implementing that for
     * real would require a default-private-timeline mode this [TimelineBuilder] does not have yet:
     * today every candidate is shown regardless of any trust relationship to its author (see
     * [CredibilityLevel]'s doc comment on the bootstrap design this rests on) - only a `RESOLVED`
     * score below [TimelineOptions.credibilityFilterThresholdMicros] gets filtered, and Karma has
     * no role in that decision at all. Building real Karma-driven bridging would mean redesigning
     * an already-shipped, twice-reviewed component's core filtering/sorting contract - deliberately
     * out of scope for this wave. This is a NAMED, deliberate scope narrowing, not an oversight -
     * a future wave that wants real Karma-driven bridging must design that filtering/sorting change
     * explicitly, not assume [karmaScore] already secretly influences anything here.
     */
    fun build(
        graph: TrustGraph,
        localIdentity: Secp256k1PublicKey,
        candidates: List<TimelineCandidate>,
        ltrRecordsByCid: Map<Cid, List<LtrRecord>>,
        options: TimelineOptions = TimelineOptions(),
        karmaVotesByCid: Map<Cid, List<KarmaVote>> = emptyMap(),
        karmaVotesByVoter: (Secp256k1PublicKey) -> List<KarmaVote> = { emptyList() },
    ): List<TimelineEntry> {
        val entries =
            candidates.map { candidate ->
                val credibility =
                    CredibilityCalculator.credibility(
                        graph = graph,
                        localIdentity = localIdentity,
                        author = candidate.author,
                        confirmers = candidate.confirmers,
                    )
                val records = ltrRecordsByCid[candidate.cid] ?: emptyList()
                val ltrWeightMsat = LtrWeightCalculator.accumulatedWeightMsat(records, options.atEpochSeconds)

                val karmaVotes = karmaVotesByCid[candidate.cid] ?: emptyList()
                val karmaScore =
                    KarmaScoring.personalizedKarmaForTarget(
                        votesForTarget = karmaVotes,
                        votesByVoter = karmaVotesByVoter,
                        graph = graph,
                        localIdentity = localIdentity,
                    )

                // A NO_PATH candidate is NEVER filtered by the credibility threshold below - only a
                // RESOLVED score that's genuinely too low is. This branch is written out explicitly
                // (rather than folded into a single boolean expression) because it is easy to get
                // backwards - see CredibilityLevel's doc comment for the full reasoning why
                // collapsing "unknown" and "resolved-low" would be a serious correctness bug here.
                val filteredOut =
                    if (credibility.level == CredibilityLevel.RESOLVED) {
                        credibility.scoreMicros < options.credibilityFilterThresholdMicros
                    } else {
                        false
                    }

                TimelineEntry(
                    cid = candidate.cid,
                    author = candidate.author,
                    publishedAtEpochSeconds = candidate.publishedAtEpochSeconds,
                    credibility = credibility,
                    ltrWeightMsat = ltrWeightMsat,
                    ltrRecordCount = records.size,
                    karmaScore = karmaScore,
                    karmaVoteCount = karmaVotes.size,
                    filteredOut = filteredOut,
                )
            }
        return entries.sortedWith(
            compareByDescending<TimelineEntry> { it.ltrWeightMsat }
                .thenByDescending { it.publishedAtEpochSeconds },
        )
    }

    /** [entries] as-is if [includeFilteredContent], otherwise with every [TimelineEntry.filteredOut]
     * entry dropped. */
    fun visible(
        entries: List<TimelineEntry>,
        includeFilteredContent: Boolean,
    ): List<TimelineEntry> = if (includeFilteredContent) entries else entries.filterNot { it.filteredOut }
}
