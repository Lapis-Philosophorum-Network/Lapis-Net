package net.lapisphilosophorum.lapisnet.madli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId

private fun testPeerId(seed: Byte): PeerId = PeerId(ByteArray(34) { seed })

private fun baselineMadli(): AggregatedMadli =
    AggregatedMadli(
        reachabilityMicros = 500_000,
        medianBandwidthBytesPerSec = 10_000_000L,
        medianLatencyMillis = 100,
        deliveryIntegrityMicros = 500_000,
        routingHelpfulnessMicros = 500_000,
    )

class MadliRoutingPolicyTest :
    FunSpec({
        test("routingScore increases with higher reachability, all else equal") {
            val low = baselineMadli().copy(reachabilityMicros = 100_000)
            val high = baselineMadli().copy(reachabilityMicros = 900_000)

            (MadliRoutingPolicy.routingScore(high) > MadliRoutingPolicy.routingScore(low)) shouldBe true
        }

        test("routingScore increases with higher delivery integrity, all else equal") {
            val low = baselineMadli().copy(deliveryIntegrityMicros = 100_000)
            val high = baselineMadli().copy(deliveryIntegrityMicros = 900_000)

            (MadliRoutingPolicy.routingScore(high) > MadliRoutingPolicy.routingScore(low)) shouldBe true
        }

        test("routingScore increases with higher bandwidth, all else equal") {
            val low = baselineMadli().copy(medianBandwidthBytesPerSec = 100_000L)
            val high = baselineMadli().copy(medianBandwidthBytesPerSec = 100_000_000L)

            (MadliRoutingPolicy.routingScore(high) > MadliRoutingPolicy.routingScore(low)) shouldBe true
        }

        test("routingScore DECREASES with higher latency, all else equal - latency is inverted") {
            val fast = baselineMadli().copy(medianLatencyMillis = 10)
            val slow = baselineMadli().copy(medianLatencyMillis = 5_000)

            (MadliRoutingPolicy.routingScore(fast) > MadliRoutingPolicy.routingScore(slow)) shouldBe true
        }

        test("routingScore is always finite and non-negative for in-range metrics") {
            val best =
                AggregatedMadli(
                    reachabilityMicros = 1_000_000,
                    medianBandwidthBytesPerSec = MadliMetrics.MAX_BANDWIDTH_BYTES_PER_SEC,
                    medianLatencyMillis = 0,
                    deliveryIntegrityMicros = 1_000_000,
                    routingHelpfulnessMicros = 1_000_000,
                )
            val worst =
                AggregatedMadli(
                    reachabilityMicros = 0,
                    medianBandwidthBytesPerSec = 0L,
                    medianLatencyMillis = MadliMetrics.MAX_LATENCY_MILLIS,
                    deliveryIntegrityMicros = 0,
                    routingHelpfulnessMicros = 0,
                )

            MadliRoutingPolicy.routingScore(best).isFinite() shouldBe true
            MadliRoutingPolicy.routingScore(worst).isFinite() shouldBe true
            (MadliRoutingPolicy.routingScore(best) > MadliRoutingPolicy.routingScore(worst)) shouldBe true
        }

        test("orderPeers puts the best-scoring peer first") {
            val goodPeer = testPeerId(1)
            val badPeer = testPeerId(2)
            val madliOf: (PeerId) -> AggregatedMadli? = { peer ->
                when (peer) {
                    goodPeer -> baselineMadli().copy(reachabilityMicros = 900_000)
                    badPeer -> baselineMadli().copy(reachabilityMicros = 100_000)
                    else -> null
                }
            }

            val ordered = MadliRoutingPolicy.orderPeers(listOf(badPeer, goodPeer), madliOf)

            ordered shouldBe listOf(goodPeer, badPeer)
        }

        test("a peer with no Madli history (madliOf returns null) sorts LAST - bootstrap deprioritization") {
            val knownPeer = testPeerId(1)
            val unknownPeer = testPeerId(2)
            val madliOf: (PeerId) -> AggregatedMadli? = { peer -> if (peer == knownPeer) baselineMadli() else null }

            val ordered = MadliRoutingPolicy.orderPeers(listOf(unknownPeer, knownPeer), madliOf)

            ordered shouldBe listOf(knownPeer, unknownPeer)
        }

        test("ties (including all-null) are broken deterministically by ascending peerId bytes") {
            val peerLow = PeerId(ByteArray(34) { 1 })
            val peerHigh = PeerId(ByteArray(34) { 2 })
            val noHistory: (PeerId) -> AggregatedMadli? = { null }

            val orderedOnce = MadliRoutingPolicy.orderPeers(listOf(peerHigh, peerLow), noHistory)
            val orderedAgain = MadliRoutingPolicy.orderPeers(listOf(peerLow, peerHigh), noHistory)

            orderedOnce shouldBe listOf(peerLow, peerHigh)
            orderedAgain shouldBe listOf(peerLow, peerHigh)
        }

        test(
            "profile presets change ordering - DHT_HOP's latency-dominant weighting flips a bandwidth-vs-latency tradeoff",
        ) {
            val fastLowBandwidth = testPeerId(1)
            val slowHighBandwidth = testPeerId(2)
            val madliOf: (PeerId) -> AggregatedMadli? = { peer ->
                when (peer) {
                    fastLowBandwidth ->
                        baselineMadli().copy(medianLatencyMillis = 200, medianBandwidthBytesPerSec = 1_000_000L)
                    slowHighBandwidth ->
                        baselineMadli().copy(medianLatencyMillis = 800, medianBandwidthBytesPerSec = 500_000_000L)
                    else -> null
                }
            }

            val orderedByProviderDefault =
                MadliRoutingPolicy.orderPeers(
                    listOf(fastLowBandwidth, slowHighBandwidth),
                    madliOf,
                    MadliRoutingProfile.PROVIDER_ORDERING,
                )
            val orderedByDhtHop =
                MadliRoutingPolicy.orderPeers(
                    listOf(fastLowBandwidth, slowHighBandwidth),
                    madliOf,
                    MadliRoutingProfile.DHT_HOP,
                )

            // Under the default equal-weight profile, the huge bandwidth advantage wins.
            orderedByProviderDefault shouldBe listOf(slowHighBandwidth, fastLowBandwidth)
            // Under DHT_HOP's latency-dominant weighting, the fast-but-low-bandwidth peer wins instead.
            orderedByDhtHop shouldBe listOf(fastLowBandwidth, slowHighBandwidth)
        }
    })
