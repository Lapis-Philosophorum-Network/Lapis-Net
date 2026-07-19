package net.lapisphilosophorum.lapisnet.madli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.doubles.plusOrMinus
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.trust.TrustGraph

private fun testPeerId(seed: Byte): PeerId = PeerId(ByteArray(34) { seed })

private fun metricsWithReachability(reachabilityMicros: Int): MadliMetrics =
    MadliMetrics(
        reachabilityMicros = reachabilityMicros,
        medianBandwidthBytesPerSec = 10_000_000L,
        medianLatencyMillis = 50,
        deliveryIntegrityMicros = 900_000,
        routingHelpfulnessMicros = 700_000,
        observationCount = 10,
    )

private fun vectorAt(
    observer: Secp256k1KeyPair,
    peer: PeerId,
    epochDay: Long,
    reachabilityMicros: Int = 500_000,
): MadliDailyVector = MadliDailyVector.create(observer, peer, epochDay, metricsWithReachability(reachabilityMicros))

class MadliAggregatorTest :
    FunSpec({
        test("a single honest observer at weight 1.0 aggregates to exactly that vector's own metrics") {
            val observer = Secp256k1KeyPair.generate()
            val peer = testPeerId(1)
            val metrics = metricsWithReachability(500_000)
            val vector = MadliDailyVector.create(observer, peer, epochDay = 10L, metrics = metrics)

            val result =
                MadliAggregator.aggregate(
                    vectors = listOf(vector),
                    observerWeight = { 1.0 },
                    atEpochDay = 10L, // age 0 -> decay factor 1.0 for every metric
                )

            result shouldBe
                AggregatedMadli(
                    reachabilityMicros = metrics.reachabilityMicros,
                    medianBandwidthBytesPerSec = metrics.medianBandwidthBytesPerSec,
                    medianLatencyMillis = metrics.medianLatencyMillis,
                    deliveryIntegrityMicros = metrics.deliveryIntegrityMicros,
                    routingHelpfulnessMicros = metrics.routingHelpfulnessMicros,
                )
        }

        test("weighted median picks the correct value for an ODD-sized equally-weighted set") {
            val peer = testPeerId(1)
            val vectors =
                listOf(100_000, 500_000, 900_000).map { r ->
                    vectorAt(Secp256k1KeyPair.generate(), peer, epochDay = 10L, reachabilityMicros = r)
                }

            val result = MadliAggregator.aggregate(vectors, observerWeight = { 1.0 }, atEpochDay = 10L)

            result?.reachabilityMicros shouldBe 500_000
        }

        test("weighted median follows the majority WEIGHT when two equal-weight observers outnumber one") {
            val peer = testPeerId(1)
            val lowObserver = Secp256k1KeyPair.generate()
            val highA = Secp256k1KeyPair.generate()
            val highB = Secp256k1KeyPair.generate()
            val vLow = vectorAt(lowObserver, peer, epochDay = 10L, reachabilityMicros = 100_000)
            val vHighA = vectorAt(highA, peer, epochDay = 10L, reachabilityMicros = 900_000)
            val vHighB = vectorAt(highB, peer, epochDay = 10L, reachabilityMicros = 900_000)

            // Two "high" observers (each weight 1.0) outweigh a single "low" observer (weight 1.0)
            // 2-to-1 - the weighted median must follow the 2-observer majority.
            val result =
                MadliAggregator.aggregate(listOf(vLow, vHighA, vHighB), observerWeight = { 1.0 }, atEpochDay = 10L)

            result?.reachabilityMicros shouldBe 900_000
        }

        test(
            "decay is applied per-metric - a two-observer old 'majority' can still outvote a single fresh " +
                "observer on slow-decaying Delivery-Integrity, but not on fast-decaying Reachability",
        ) {
            val peer = testPeerId(1)
            val freshObserver = Secp256k1KeyPair.generate()
            val oldObserver1 = Secp256k1KeyPair.generate()
            val oldObserver2 = Secp256k1KeyPair.generate()

            fun metricsAt(value: Int): MadliMetrics =
                MadliMetrics(
                    reachabilityMicros = value,
                    medianBandwidthBytesPerSec = 1_000_000L,
                    medianLatencyMillis = 50,
                    deliveryIntegrityMicros = value,
                    routingHelpfulnessMicros = value,
                    observationCount = 1,
                )

            // One fresh (age 0) observer reports LOW; two 60-day-old observers report HIGH.
            val freshVector = MadliDailyVector.create(freshObserver, peer, epochDay = 60L, metrics = metricsAt(100_000))
            val oldVector1 = MadliDailyVector.create(oldObserver1, peer, epochDay = 0L, metrics = metricsAt(900_000))
            val oldVector2 = MadliDailyVector.create(oldObserver2, peer, epochDay = 0L, metrics = metricsAt(900_000))

            val result =
                MadliAggregator.aggregate(
                    listOf(freshVector, oldVector1, oldVector2),
                    observerWeight = { 1.0 },
                    atEpochDay = 60L,
                )

            // Reachability (7-day half-life): at 60 days old, decayFactor(7, 60) = 0.5^(60/7) ~=
            // 0.0026 per old observer - their COMBINED weight (~0.0053) is still far below the
            // fresh observer's weight (1.0), so the fresh (LOW) value wins the median.
            result!!.reachabilityMicros shouldBe 100_000
            // Delivery-Integrity (90-day half-life): at 60 days old, decayFactor(90, 60) =
            // 0.5^(60/90) ~= 0.63 per old observer - their COMBINED weight (~1.26) now exceeds the
            // fresh observer's weight (1.0), so the two-observer old majority's (HIGH) value wins.
            result.deliveryIntegrityMicros shouldBe 900_000
        }

        test("an observer with weight 0 is dropped entirely - contributes to no metric") {
            val peer = testPeerId(1)
            val honestObserver = Secp256k1KeyPair.generate()
            val sybilObserver = Secp256k1KeyPair.generate()
            val honestVector = vectorAt(honestObserver, peer, epochDay = 10L, reachabilityMicros = 500_000)
            val sybilVector = vectorAt(sybilObserver, peer, epochDay = 10L, reachabilityMicros = 1_000_000)

            val result =
                MadliAggregator.aggregate(
                    listOf(honestVector, sybilVector),
                    observerWeight = { observer -> if (observer == honestObserver.publicKey) 1.0 else 0.0 },
                    atEpochDay = 10L,
                )

            result?.reachabilityMicros shouldBe 500_000
        }

        test("aggregate returns null when every observer has weight 0") {
            val peer = testPeerId(1)
            val vector = vectorAt(Secp256k1KeyPair.generate(), peer, epochDay = 10L)

            val result = MadliAggregator.aggregate(listOf(vector), observerWeight = { 0.0 }, atEpochDay = 10L)

            result.shouldBeNull()
        }

        test("aggregate returns null for an empty vector collection") {
            MadliAggregator.aggregate(emptyList(), observerWeight = { 1.0 }, atEpochDay = 10L).shouldBeNull()
        }

        test("aggregate does not mutate its input vectors") {
            val peer = testPeerId(1)
            val vector = vectorAt(Secp256k1KeyPair.generate(), peer, epochDay = 10L, reachabilityMicros = 321_000)
            val before = vector.metrics

            MadliAggregator.aggregate(listOf(vector), observerWeight = { 1.0 }, atEpochDay = 10L)

            vector.metrics shouldBe before
        }

        // --- CRITICAL fix regression: one representative vector per observer per metric ------

        test(
            "a single observer publishing vectors for 3 different days contributes only their single " +
                "freshest (highest-weight) vector for a metric, not a sum or average of all 3",
        ) {
            val peer = testPeerId(1)
            val observer = Secp256k1KeyPair.generate()
            val vOld = vectorAt(observer, peer, epochDay = 0L, reachabilityMicros = 100_000)
            val vMid = vectorAt(observer, peer, epochDay = 5L, reachabilityMicros = 500_000)
            val vFresh = vectorAt(observer, peer, epochDay = 10L, reachabilityMicros = 900_000)

            val result =
                MadliAggregator.aggregate(
                    vectors = listOf(vOld, vMid, vFresh),
                    observerWeight = { 1.0 },
                    atEpochDay = 10L,
                )

            // If the three vectors were folded in as independent samples, the median of
            // [100_000, 500_000, 900_000] would be 500_000 (the SAME value the "ODD-sized" test
            // above asserts for three genuinely DIFFERENT observers) - a sum would be even further
            // off. Only the freshest (epochDay 10, age 0) vector must count.
            result?.reachabilityMicros shouldBe 900_000
        }

        test(
            "backdated-vector-flooding: a Veritas-trusted attacker publishing 128 backdated, maximally-" +
                "fabricated vectors about a peer is bounded to ONE vote, not 128 - the aggregate follows " +
                "the 9 honest observers' truthful majority",
        ) {
            val peer = testPeerId(1)
            val atEpochDay = 200L
            val perObserverWeight = 1.0

            fun deliveryIntegrityVector(
                observer: Secp256k1KeyPair,
                epochDay: Long,
                deliveryIntegrityMicros: Int,
            ): MadliDailyVector =
                MadliDailyVector.create(
                    observer,
                    peer,
                    epochDay,
                    MadliMetrics(
                        reachabilityMicros = 500_000,
                        medianBandwidthBytesPerSec = 10_000_000L,
                        medianLatencyMillis = 50,
                        deliveryIntegrityMicros = deliveryIntegrityMicros,
                        routingHelpfulnessMicros = 500_000,
                        observationCount = 1,
                    ),
                )

            // Attacker: ONE Veritas-trusted observer, but publishes the maximum
            // MadliVectorIndex.MAX_TRACKED_DAYS_PER_OBSERVER_PEER (128) distinct-day vectors, all
            // backdated into the past ending at atEpochDay, every one fabricated to the max
            // deliveryIntegrityMicros (1_000_000).
            val attacker = Secp256k1KeyPair.generate()
            val attackerVectors =
                (0 until MadliVectorIndex.MAX_TRACKED_DAYS_PER_OBSERVER_PEER).map { daysAgo ->
                    deliveryIntegrityVector(attacker, atEpochDay - daysAgo, deliveryIntegrityMicros = 1_000_000)
                }

            // 9 honest observers, each publishing exactly ONE truthful, low vector for today.
            val honestObservers = (1..9).map { Secp256k1KeyPair.generate() }
            val honestVectors =
                honestObservers.map { h -> deliveryIntegrityVector(h, atEpochDay, deliveryIntegrityMicros = 100_000) }

            val observerWeight: (Secp256k1PublicKey) -> Double = { _ -> perObserverWeight }

            val result =
                MadliAggregator.aggregate(
                    vectors = attackerVectors + honestVectors,
                    observerWeight = observerWeight,
                    atEpochDay = atEpochDay,
                )

            // Pre-fix, folding all 128 backdated vectors as independent samples would multiply the
            // attacker's effective weight by ~81.7x (90-day half-life) - far outweighing the 9
            // honest observers' combined weight of 9.0, so the result would follow the attacker's
            // fabricated 1_000_000. Post-fix, the attacker contributes at most ONE representative
            // vector (their freshest, age 0, weight 1.0) - so the aggregate reflects the 9-observer
            // honest majority instead.
            result!!.deliveryIntegrityMicros shouldBe 100_000
        }

        // --- MINOR fix regression: symmetric weighted-median tie-break at an exact 50/50 split -

        test(
            "weighted median at an exact 50/50 weight split between two distinct values resolves to " +
                "their MIDPOINT, not the lower value - an attacker holding exactly half the weight " +
                "cannot force the aggregate toward their own low fabricated report",
        ) {
            val peer = testPeerId(1)
            val lowObserver = Secp256k1KeyPair.generate()
            val highObserver = Secp256k1KeyPair.generate()
            val vLow = vectorAt(lowObserver, peer, epochDay = 10L, reachabilityMicros = 100_000)
            val vHigh = vectorAt(highObserver, peer, epochDay = 10L, reachabilityMicros = 300_000)

            val result =
                MadliAggregator.aggregate(
                    vectors = listOf(vLow, vHigh),
                    observerWeight = { 1.0 },
                    atEpochDay = 10L,
                )

            // Exact 50/50 weight split (1.0 vs 1.0) between 100_000 and 300_000 - midpoint 200_000.
            result?.reachabilityMicros shouldBe 200_000
        }

        // --- code review follow-up: totalWeight <= 0.0 fallback path in weightedMedianLong -----

        test(
            "when every vector's decayed weight underflows to exactly 0.0 (atEpochDay far enough past " +
                "every epochDay for even the longest 90-day half-life), aggregate() does NOT return null " +
                "- it falls back to the plain (unweighted) median, since the raw observerWeight was " +
                "positive and only the read-time DECAY, not the Veritas weight, vanished",
        ) {
            val peer = testPeerId(1)
            val observers = (1..3).map { Secp256k1KeyPair.generate() }
            val values = listOf(100_000, 500_000, 900_000)
            val vectors =
                observers.zip(values).map { (o, v) -> vectorAt(o, peer, epochDay = 0L, reachabilityMicros = v) }

            // 200_000 days (~547 years) past epochDay 0 - astronomically far past every half-life
            // (longest is 90 days), so 0.5^(200_000 / halfLife) underflows to a true IEEE-754 0.0
            // for all five metrics, not merely a very small positive number.
            val farFutureEpochDay = 200_000L

            val result =
                MadliAggregator.aggregate(
                    vectors = vectors,
                    observerWeight = { 1.0 }, // raw observer weight is positive - only decay vanishes
                    atEpochDay = farFutureEpochDay,
                )

            // aggregate()'s null contract is scoped to raw observerWeight <= 0 (see its KDoc) - it
            // is NOT re-checked against decayed weight, so this is genuinely reachable, non-dead
            // code: the plain-median fallback (sorted middle element) kicks in instead of null.
            result shouldNotBe null
            result!!.reachabilityMicros shouldBe 500_000
        }

        // --- veritasObserverWeight -----------------------------------------------------------

        test("veritasObserverWeight: an observer with no Veritas path from the consumer gets weight 0.0") {
            val consumer = Secp256k1KeyPair.generate()
            val unrelatedObserver = Secp256k1KeyPair.generate()
            val graph = TrustGraph.fromEdges(emptyList())

            val weight = MadliAggregator.veritasObserverWeight(graph, consumer.publicKey)

            weight(unrelatedObserver.publicKey) shouldBe (0.0 plusOrMinus 1e-9)
        }

        test("veritasObserverWeight: self (observer == localIdentity) gets weight 1.0 via the self-trust axiom") {
            val consumer = Secp256k1KeyPair.generate()
            val graph = TrustGraph.fromEdges(emptyList())

            val weight = MadliAggregator.veritasObserverWeight(graph, consumer.publicKey)

            weight(consumer.publicKey) shouldBe (1.0 plusOrMinus 1e-9)
        }

        test("veritasObserverWeight: a mid-trust path yields a proportional weight in 0.0..1.0") {
            val consumer = Secp256k1KeyPair.generate()
            val observer = Secp256k1KeyPair.generate()
            val edgeTrustMicros = 500_000 // 50% trust, one hop
            val graph: TrustGraph =
                TrustGraph.fromEdges(
                    listOf(Triple(consumer.publicKey, observer.publicKey, edgeTrustMicros)),
                )

            val weight = MadliAggregator.veritasObserverWeight(graph, consumer.publicKey)

            weight(observer.publicKey) shouldBe (0.5 plusOrMinus 1e-9)
        }
    })
