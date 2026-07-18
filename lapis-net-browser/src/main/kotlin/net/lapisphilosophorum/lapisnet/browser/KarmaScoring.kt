package net.lapisphilosophorum.lapisnet.browser

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.KarmaVote
import net.lapisphilosophorum.lapisnet.karma.KarmaWeightCalculator
import net.lapisphilosophorum.lapisnet.trust.MAX_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.TrustPathFinder

/**
 * Folds Veritas trust-graph weighting into raw [KarmaWeightCalculator] values, turning each
 * [KarmaVote]'s Sybil-resistant `Karma = t / (n+1)` value into a viewer-personalized number: a
 * stranger's vote contributes exactly `0` to a viewer with no trust path to them, a fully-trusted
 * voter's vote contributes its full raw value, and everything in between scales proportionally.
 * This is where Karma's SECOND Sybil-resistance mechanism (see this module's/`lapis-net-karma`'s
 * class doc comments - the fach-spec's two combined mechanisms are the chain-derived time anchor
 * AND Veritas-weighting) actually happens - `lapis-net-karma` itself has no dependency on
 * `lapis-net-trust` at all (see that module's `build.gradle.kts` comment: Karma is a sibling scoring
 * dimension, Veritas-weighting is layered on top, one level up, exactly here).
 *
 * **Deliberately uses [TrustPathFinder.trustMicros] - the `NO_PATH`-collapses-to-`0` convenience
 * wrapper - NOT [CredibilityCalculator]'s `NO_PATH`-preserving split.** This is intentional, not an
 * inconsistency with [Credibility]'s own hard-won discipline (see [CredibilityLevel]'s doc comment):
 * [Credibility] LABELS a post for a human reader - "unknown" must never visually or semantically
 * look like "distrusted", because Veritas's bootstrap design requires a brand-new user's unfiltered
 * timeline to not look like everyone in it is maximally distrusted. Karma-weighting does something
 * categorically different: it folds a voter's opinion into a personalized NUMBER a viewer's own
 * trust graph produces. A stranger's vote correctly contributing exactly `0` to that number IS the
 * intended anti-Sybil mechanism working as designed, not a mislabeling of "unknown" as
 * "distrusted" - there is no separate "unrated" bucket a numeric contribution could even render as.
 * A future reader must not "fix" this to match [CredibilityCalculator]'s split by mistake; this
 * contrast is deliberate and is the reason this doc comment spells it out explicitly.
 */
object KarmaScoring {
    /**
     * [rawKarmaValue] (already computed by [KarmaWeightCalculator.karmaValue] for a specific
     * [KarmaVote] cast by [voter]) scaled by [localIdentity]'s trust in [voter], per
     * [TrustPathFinder.trustMicros] (`0` for no path, mirroring self-trust's own axiomatic `1.0`
     * for `voter == localIdentity` - see [TrustPathFinder.findPath]'s doc comment on the self-trust
     * short-circuit).
     */
    fun weightedContribution(
        rawKarmaValue: Double,
        graph: TrustGraph,
        localIdentity: Secp256k1PublicKey,
        voter: Secp256k1PublicKey,
    ): Double {
        val trustMicros = TrustPathFinder.trustMicros(graph, localIdentity, voter)
        return rawKarmaValue * (trustMicros.toDouble() / MAX_TRUST_MICROS.toDouble())
    }

    /**
     * The full personalized Karma score for a target: sums [weightedContribution] across every
     * vote in [votesForTarget], each vote's raw value computed via
     * [KarmaWeightCalculator.karmaValue] fed by [votesByVoter] (the observer's own indexed view of
     * each voter's OTHER votes - see that function's doc comment on why `n` must always be
     * observer-derived, never trusted from the vote itself). Does not mutate [votesForTarget] or
     * any element in it - purely a read-only fold, mirroring
     * [net.lapisphilosophorum.lapisnet.virtus.LtrWeightCalculator.accumulatedWeightMsat]'s shape.
     */
    fun personalizedKarmaForTarget(
        votesForTarget: List<KarmaVote>,
        votesByVoter: (Secp256k1PublicKey) -> List<KarmaVote>,
        graph: TrustGraph,
        localIdentity: Secp256k1PublicKey,
    ): Double =
        votesForTarget.sumOf { vote ->
            val rawValue = KarmaWeightCalculator.karmaValue(vote, votesByVoter(vote.voter))
            weightedContribution(rawValue, graph, localIdentity, vote.voter)
        }
}
