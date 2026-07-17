package net.lapisphilosophorum.lapisnet.trust

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * The winning trust path selected by [TrustPathFinder]: the shortest-hop path, and among those the
 * lexicographically-greatest hop-weight sequence from the source. Absence of any path is expressed
 * as `null` by the finder (default distrust, score 0), so a non-null [TrustPath] always means "a
 * path exists".
 *
 * [nodes] is source..target inclusive (size = hops + 1; size 1 for the trivial self-trust case).
 * [scoreMicros] is the transitive trust as fixed-point millionths (0..1_000_000) - the product of
 * the edge weights in the micros domain, consistent with [VeritasGrant.trustMicros]. [scoreFraction]
 * is a display-only `Double`, mirroring [VeritasGrant.trustFraction]; never compare/threshold on it.
 */
data class TrustPath(
    val nodes: List<Secp256k1PublicKey>,
    val scoreMicros: Int,
) {
    val scoreFraction: Double get() = scoreMicros.toDouble() / MAX_TRUST_MICROS
    val hops: Int get() = nodes.size - 1
}
