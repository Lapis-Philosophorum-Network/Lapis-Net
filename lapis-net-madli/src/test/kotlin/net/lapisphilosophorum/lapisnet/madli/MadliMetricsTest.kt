package net.lapisphilosophorum.lapisnet.madli

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private fun validMetrics(
    reachabilityMicros: Int = 500_000,
    medianBandwidthBytesPerSec: Long = 10_000_000L,
    medianLatencyMillis: Int = 50,
    deliveryIntegrityMicros: Int = 900_000,
    routingHelpfulnessMicros: Int = 700_000,
    observationCount: Int = 10,
): MadliMetrics =
    MadliMetrics(
        reachabilityMicros = reachabilityMicros,
        medianBandwidthBytesPerSec = medianBandwidthBytesPerSec,
        medianLatencyMillis = medianLatencyMillis,
        deliveryIntegrityMicros = deliveryIntegrityMicros,
        routingHelpfulnessMicros = routingHelpfulnessMicros,
        observationCount = observationCount,
    )

class MadliMetricsTest :
    FunSpec({
        test("a valid metrics value constructs without throwing") {
            validMetrics()
        }

        test("boundary values (0 and MAX) are accepted for every micros field") {
            validMetrics(reachabilityMicros = 0, deliveryIntegrityMicros = 0, routingHelpfulnessMicros = 0)
            validMetrics(
                reachabilityMicros = MadliMetrics.MAX_METRIC_MICROS,
                deliveryIntegrityMicros = MadliMetrics.MAX_METRIC_MICROS,
                routingHelpfulnessMicros = MadliMetrics.MAX_METRIC_MICROS,
            )
        }

        test("boundary values (0 and MAX) are accepted for bandwidth/latency") {
            validMetrics(medianBandwidthBytesPerSec = 0, medianLatencyMillis = 0)
            validMetrics(
                medianBandwidthBytesPerSec = MadliMetrics.MAX_BANDWIDTH_BYTES_PER_SEC,
                medianLatencyMillis = MadliMetrics.MAX_LATENCY_MILLIS,
            )
        }

        test("boundary value 0 is accepted for observationCount") {
            validMetrics(observationCount = 0)
        }

        test("negative reachabilityMicros is rejected") {
            shouldThrow<IllegalArgumentException> { validMetrics(reachabilityMicros = -1) }
        }

        test("reachabilityMicros above MAX is rejected") {
            shouldThrow<IllegalArgumentException> {
                validMetrics(
                    reachabilityMicros = MadliMetrics.MAX_METRIC_MICROS + 1,
                )
            }
        }

        test("negative deliveryIntegrityMicros is rejected") {
            shouldThrow<IllegalArgumentException> { validMetrics(deliveryIntegrityMicros = -1) }
        }

        test("deliveryIntegrityMicros above MAX is rejected") {
            shouldThrow<IllegalArgumentException> {
                validMetrics(deliveryIntegrityMicros = MadliMetrics.MAX_METRIC_MICROS + 1)
            }
        }

        test("negative routingHelpfulnessMicros is rejected") {
            shouldThrow<IllegalArgumentException> { validMetrics(routingHelpfulnessMicros = -1) }
        }

        test("routingHelpfulnessMicros above MAX is rejected") {
            shouldThrow<IllegalArgumentException> {
                validMetrics(routingHelpfulnessMicros = MadliMetrics.MAX_METRIC_MICROS + 1)
            }
        }

        test("negative medianBandwidthBytesPerSec is rejected") {
            shouldThrow<IllegalArgumentException> { validMetrics(medianBandwidthBytesPerSec = -1L) }
        }

        test("medianBandwidthBytesPerSec above the sanity cap is rejected") {
            shouldThrow<IllegalArgumentException> {
                validMetrics(medianBandwidthBytesPerSec = MadliMetrics.MAX_BANDWIDTH_BYTES_PER_SEC + 1)
            }
        }

        test("negative medianLatencyMillis is rejected") {
            shouldThrow<IllegalArgumentException> { validMetrics(medianLatencyMillis = -1) }
        }

        test("medianLatencyMillis above the sanity cap is rejected") {
            shouldThrow<IllegalArgumentException> {
                validMetrics(
                    medianLatencyMillis =
                        MadliMetrics.MAX_LATENCY_MILLIS + 1,
                )
            }
        }

        test("negative observationCount is rejected") {
            shouldThrow<IllegalArgumentException> { validMetrics(observationCount = -1) }
        }

        test("equals/hashCode are structural") {
            val a = validMetrics()
            val b = validMetrics()

            a shouldBe b
            a.hashCode() shouldBe b.hashCode()
        }

        test("equals is false when any single field differs") {
            val base = validMetrics()

            base shouldBe validMetrics()
            (base == validMetrics(reachabilityMicros = 1)) shouldBe false
            (base == validMetrics(medianBandwidthBytesPerSec = 1L)) shouldBe false
            (base == validMetrics(medianLatencyMillis = 1)) shouldBe false
            (base == validMetrics(deliveryIntegrityMicros = 1)) shouldBe false
            (base == validMetrics(routingHelpfulnessMicros = 1)) shouldBe false
            (base == validMetrics(observationCount = 1)) shouldBe false
        }
    })
