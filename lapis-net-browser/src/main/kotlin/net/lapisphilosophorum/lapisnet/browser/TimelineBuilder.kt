package net.lapisphilosophorum.lapisnet.browser

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.virtus.LtrRecord
import net.lapisphilosophorum.lapisnet.virtus.LtrWeightCalculator

/**
 * Combines Veritas trust-graph credibility ([CredibilityCalculator]) and Virtus/LTR sort-weight
 * ([LtrWeightCalculator]) into a sorted, filterable browser timeline.
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
     */
    fun build(
        graph: TrustGraph,
        localIdentity: Secp256k1PublicKey,
        candidates: List<TimelineCandidate>,
        ltrRecordsByCid: Map<Cid, List<LtrRecord>>,
        options: TimelineOptions = TimelineOptions(),
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
