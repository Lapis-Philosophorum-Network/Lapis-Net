package net.lapisphilosophorum.lapisnet.madli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.trust.TrustGraph

private fun testPeerId(seed: Byte): PeerId = PeerId(ByteArray(34) { seed })

private fun trustGraphOf(edges: List<Triple<Secp256k1PublicKey, Secp256k1PublicKey, Int>>): TrustGraph =
    TrustGraph.fromEdges(edges)

private fun metricsWithReachability(reachabilityMicros: Int): MadliMetrics {
    val isMax = reachabilityMicros >= 1_000_000
    return MadliMetrics(
        reachabilityMicros = reachabilityMicros,
        medianBandwidthBytesPerSec = if (isMax) MadliMetrics.MAX_BANDWIDTH_BYTES_PER_SEC else 5_000_000L,
        medianLatencyMillis = if (isMax) 0 else 100,
        deliveryIntegrityMicros = reachabilityMicros,
        routingHelpfulnessMicros = reachabilityMicros,
        observationCount = 1,
    )
}

private fun honestVector(
    observer: Secp256k1KeyPair,
    peer: PeerId,
    day: Long,
    reachability: Int = 500_000,
): MadliDailyVector = MadliDailyVector.create(observer, peer, day, metricsWithReachability(reachability))

private fun maxVector(
    observer: Secp256k1KeyPair,
    peer: PeerId,
    day: Long,
): MadliDailyVector = MadliDailyVector.create(observer, peer, day, metricsWithReachability(1_000_000))

/**
 * The wave's flagged open research question, made concrete: a Sybil-load + real-lie-load
 * manipulation-resistance harness, mirroring how V0.1.6's `TrustPathFinder` got dedicated
 * adversarial path-manipulation tests. Every scenario below runs [MadliDailyVector]s through the
 * REAL [MadliAggregator.aggregate] + REAL [MadliAggregator.veritasObserverWeight] + REAL
 * [TrustGraph]/[net.lapisphilosophorum.lapisnet.trust.TrustPathFinder] - not a mock of aggregation
 * - so a passing test here is evidence the conceptual manipulation-resistance table in the vault
 * note actually holds against this module's real implementation, not merely against an idealized
 * description of it.
 */
class MadliSybilResistanceSimulationTest :
    FunSpec({
        // --- Scenario 1: Sybil cluster self-vouches - proves Veritas-weighting -----------------

        test(
            "Scenario 1: a 20-node Sybil cluster that mutually vouches at max trust, but has NO path from " +
                "the consumer, has near-zero effect on the consumer's aggregated view",
        ) {
            val consumer = Secp256k1KeyPair.generate()
            val honestObservers = (1..5).map { Secp256k1KeyPair.generate() }
            val sybilObservers = (1..20).map { Secp256k1KeyPair.generate() }
            val observedPeer = testPeerId(1)

            // Consumer trusts each honest observer directly and highly.
            val honestEdges =
                honestObservers.map { h -> Triple(consumer.publicKey, h.publicKey, 900_000) }
            // Sybils mutually vouch at maximum trust among themselves - but NONE of them has any
            // edge reachable from the consumer's own identity.
            val sybilEdges =
                sybilObservers.flatMapIndexed { i, si ->
                    sybilObservers
                        .filterIndexed {
                            j,
                            _,
                            ->
                            i != j
                        }.map { sj -> Triple(si.publicKey, sj.publicKey, 1_000_000) }
                }
            val graph = trustGraphOf(honestEdges + sybilEdges)

            // Honest observers report the TRUTH (moderate reachability); the Sybil cluster
            // fabricates MAXIMAL vectors to try to drag the aggregate upward.
            val honestVectors =
                honestObservers.map { h ->
                    honestVector(h, observedPeer, day = 0L, reachability = 500_000)
                }
            val sybilVectors = sybilObservers.map { s -> maxVector(s, observedPeer, day = 0L) }

            val weight = MadliAggregator.veritasObserverWeight(graph, consumer.publicKey)
            val result =
                MadliAggregator.aggregate(honestVectors + sybilVectors, observerWeight = weight, atEpochDay = 0L)

            // Every Sybil has observerWeight 0.0 from the consumer's perspective (no path) - they
            // are dropped entirely, and the aggregate reflects exactly the honest observers' report.
            result!!.reachabilityMicros shouldBe 500_000
        }

        // --- Scenario 2: selective service - proves weighted-MEDIAN, not mean -----------------

        test(
            "Scenario 2: a peer that selectively serves 1-of-10 trusted observers well and the other 9 " +
                "badly is scored by the 9-observer BADLY-served majority, not pulled up by the outlier",
        ) {
            val consumer = Secp256k1KeyPair.generate()
            val observers = (1..10).map { Secp256k1KeyPair.generate() }
            val observedPeer = testPeerId(1)

            val edges = observers.map { o -> Triple(consumer.publicKey, o.publicKey, 900_000) }
            val graph = trustGraphOf(edges)

            // observers[0] is served well; observers[1..9] are served badly.
            val vectors =
                observers.mapIndexed { index, o ->
                    if (index == 0) {
                        honestVector(o, observedPeer, day = 0L, reachability = 1_000_000)
                    } else {
                        honestVector(o, observedPeer, day = 0L, reachability = 100_000)
                    }
                }

            val weight = MadliAggregator.veritasObserverWeight(graph, consumer.publicKey)
            val result = MadliAggregator.aggregate(vectors, observerWeight = weight, atEpochDay = 0L)

            // A MEAN would be pulled noticeably upward by the single 1_000_000 outlier
            // (mean = (9*100_000 + 1_000_000)/10 = 190_000); the weighted MEDIAN follows the
            // 9-observer badly-served majority instead.
            result!!.reachabilityMicros shouldBe 100_000
        }

        // --- Scenario 3: trusted minority liar vs. trusted majority liar - documents the boundary ---

        test("Scenario 3a: a single trusted observer lying (max vector) is defeated by a trusted honest majority") {
            val consumer = Secp256k1KeyPair.generate()
            val honestObservers = (1..9).map { Secp256k1KeyPair.generate() }
            val liar = Secp256k1KeyPair.generate()
            val observedPeer = testPeerId(1)

            val edges =
                (honestObservers + liar).map { o -> Triple(consumer.publicKey, o.publicKey, 900_000) }
            val graph = trustGraphOf(edges)

            val vectors =
                honestObservers.map { h -> honestVector(h, observedPeer, day = 0L, reachability = 500_000) } +
                    maxVector(liar, observedPeer, day = 0L)

            val weight = MadliAggregator.veritasObserverWeight(graph, consumer.publicKey)
            val result = MadliAggregator.aggregate(vectors, observerWeight = weight, atEpochDay = 0L)

            result!!.reachabilityMicros shouldBe 500_000
        }

        test(
            "Scenario 3b: DOCUMENTED RESIDUAL - a trusted MAJORITY that lies still wins the median. " +
                "This is the vault note's acknowledged theoretical residual (generic reputation-burning is " +
                "the only real defense, not this module's aggregation math) - asserted explicitly so the " +
                "boundary is a tested, documented property, not a silent gap.",
        ) {
            val consumer = Secp256k1KeyPair.generate()
            val lyingMajority = (1..9).map { Secp256k1KeyPair.generate() }
            val honestMinority = Secp256k1KeyPair.generate()
            val observedPeer = testPeerId(1)

            val edges =
                (lyingMajority + honestMinority).map { o -> Triple(consumer.publicKey, o.publicKey, 900_000) }
            val graph = trustGraphOf(edges)

            val vectors =
                lyingMajority.map { liar -> maxVector(liar, observedPeer, day = 0L) } +
                    honestVector(honestMinority, observedPeer, day = 0L, reachability = 100_000)

            val weight = MadliAggregator.veritasObserverWeight(graph, consumer.publicKey)
            val result = MadliAggregator.aggregate(vectors, observerWeight = weight, atEpochDay = 0L)

            // The consumer's view follows the lying majority - a real, accepted, and now
            // explicitly tested boundary of this module's manipulation resistance.
            result!!.reachabilityMicros shouldBe 1_000_000
        }

        test("sanity: the Sybil cluster's edges really are unreachable from the consumer (graph construction check)") {
            val consumer = Secp256k1KeyPair.generate()
            val sybilObservers = (1..3).map { Secp256k1KeyPair.generate() }
            val sybilEdges =
                sybilObservers.flatMapIndexed { i, si ->
                    sybilObservers
                        .filterIndexed {
                            j,
                            _,
                            ->
                            i != j
                        }.map { sj -> Triple(si.publicKey, sj.publicKey, 1_000_000) }
                }
            val graph = trustGraphOf(sybilEdges)

            val weight = MadliAggregator.veritasObserverWeight(graph, consumer.publicKey)
            sybilObservers.count { weight(it.publicKey) > 0.0 } shouldBe 0
            sybilEdges.size shouldBeGreaterThan 0
        }
    })
