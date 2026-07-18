package net.lapisphilosophorum.lapisnet.browser

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.trust.MIN_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.TrustPathFinder

/**
 * Whether a [Credibility] score reflects a resolved trust path, or the genuine absence of one.
 *
 * **This distinction is the single most important correctness property in this whole module.**
 * [NO_PATH] means "no trust path exists at all between the local identity and this author/
 * confirmer set - genuinely unrated". The UI MUST read this as "unknown", NEVER as "distrusted".
 * [RESOLVED] means "a path exists and resolved to a real score, which may legitimately BE 0" -
 * [net.lapisphilosophorum.lapisnet.trust.MIN_TRUST_MICROS] (0) is Veritas's own documented default/
 * revocation value, i.e. ACTIVE distrust along a real, resolved path - a completely different
 * thing from "no data at all".
 *
 * Collapsing this distinction - treating [TrustPathFinder.findPath] returning `null` the same as
 * it resolving to a path whose [net.lapisphilosophorum.lapisnet.trust.TrustPath.scoreMicros] is 0 -
 * would make a brand-new pilot user's entire unfiltered timeline look identically "maximally
 * distrusted" (since a fresh identity has no outgoing trust edges to anyone yet, every author would
 * resolve to the same collapsed "0" bucket). That directly contradicts Veritas's own documented
 * bootstrap design: a newcomer with no trust graph yet should see the unfiltered stream, not
 * something that LOOKS like everyone in it is distrusted. [TimelineBuilder.build]'s filtering logic
 * depends on this enum being read correctly - see its doc comment for the concrete filtering rule.
 */
enum class CredibilityLevel {
    NO_PATH,
    RESOLVED,
}

/**
 * The resolved (or explicitly absent) trust credibility of a piece of content's author (and,
 * forward-looking, its confirmers - see [CredibilityCalculator.credibility]'s `confirmers`
 * parameter). [scoreMicros] mirrors
 * [net.lapisphilosophorum.lapisnet.trust.TrustPath.scoreMicros]'s fixed-point millionths
 * convention (0..1_000_000) when [level] is [CredibilityLevel.RESOLVED]; when [level] is
 * [CredibilityLevel.NO_PATH], [scoreMicros] is [net.lapisphilosophorum.lapisnet.trust.MIN_TRUST_MICROS]
 * (0) as a placeholder ONLY - see [CredibilityLevel]'s doc comment for why that placeholder value
 * must never be compared/thresholded against as if it were a real resolved score.
 */
data class Credibility(
    val level: CredibilityLevel,
    val scoreMicros: Int,
)

/**
 * Computes a piece of content's [Credibility] relative to the local identity's trust graph.
 */
object CredibilityCalculator {
    /**
     * Resolves the best (highest-scoring) [net.lapisphilosophorum.lapisnet.trust.TrustPathFinder.findPath]
     * result across [author] and every entry in [confirmers], using the RAW path-finding function
     * (never a convenience wrapper that collapses "no path" to a numeric zero, such as
     * [net.lapisphilosophorum.lapisnet.trust.TrustPathFinder.trustMicros]) specifically so this
     * function can branch on nullability itself - see [CredibilityLevel]'s doc comment for why
     * that distinction must be preserved all the way through to the caller.
     *
     * [confirmers] is always `emptyList()` from every call site in this wave - no confirm
     * mechanism exists yet in the Minimal-Browser MVP. The parameter exists purely for forward
     * compatibility with a future wave that lets other identities co-sign/confirm a piece of
     * content, at which point their trust paths should also be able to boost its credibility.
     */
    fun credibility(
        graph: TrustGraph,
        localIdentity: Secp256k1PublicKey,
        author: Secp256k1PublicKey,
        confirmers: List<Secp256k1PublicKey> = emptyList(),
    ): Credibility {
        val best =
            (listOf(author) + confirmers)
                .mapNotNull { candidate -> TrustPathFinder.findPath(graph, localIdentity, candidate) }
                .maxByOrNull { it.scoreMicros }
        return if (best != null) {
            Credibility(CredibilityLevel.RESOLVED, best.scoreMicros)
        } else {
            Credibility(CredibilityLevel.NO_PATH, MIN_TRUST_MICROS)
        }
    }
}
