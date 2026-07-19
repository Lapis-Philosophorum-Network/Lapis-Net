package net.lapisphilosophorum.lapisnet.madli

/**
 * The five bilaterally-observed Madli metrics for one (observer, observed-peer, day) tuple. All
 * fixed-point integers (never `Double`): this value is embedded in a signed, cross-node-compared
 * structure ([MadliDailyVector]), so it must not depend on floating-point being bit-identical
 * across JVMs - the same reasoning `VeritasGrant.trustMicros` documents. `Double` is used only
 * later, in the local read-time [MadliDecayCalculator]/[MadliAggregator] heuristics (mirroring
 * `LtrWeightCalculator`).
 *
 * Reachability / Delivery-Integrity / Routing-Helpfulness are micros fractions in
 * `0..1_000_000`. Bandwidth (raw median bytes/sec) and Latency (raw median RTT millis) are raw
 * physical integers; normalizing them into a routing score is deferred to the local, read-time
 * routing policy ([MadliRoutingPolicy]), never baked into the signed value - consistent with the
 * vault note's "selection function is local policy per node/browser vendor".
 *
 * [observationCount] is ADVISORY and self-declared (the count of underlying interactions this
 * vector summarizes). It is NOT part of any anti-Sybil guarantee - like a `KarmaVote`'s
 * `timeAnchor`, it is trusted only structurally; the Veritas-weighting ([MadliAggregator]) is the
 * actual guarantee. A local aggregation policy MAY use it to floor/weight by sample size, but must
 * never rely on it for manipulation resistance.
 */
data class MadliMetrics(
    val reachabilityMicros: Int,
    val medianBandwidthBytesPerSec: Long,
    val medianLatencyMillis: Int,
    val deliveryIntegrityMicros: Int,
    val routingHelpfulnessMicros: Int,
    val observationCount: Int,
) {
    init {
        require(reachabilityMicros in 0..MAX_METRIC_MICROS) {
            "reachabilityMicros out of range: $reachabilityMicros"
        }
        require(deliveryIntegrityMicros in 0..MAX_METRIC_MICROS) {
            "deliveryIntegrityMicros out of range: $deliveryIntegrityMicros"
        }
        require(routingHelpfulnessMicros in 0..MAX_METRIC_MICROS) {
            "routingHelpfulnessMicros out of range: $routingHelpfulnessMicros"
        }
        require(medianBandwidthBytesPerSec in 0..MAX_BANDWIDTH_BYTES_PER_SEC) {
            "medianBandwidthBytesPerSec out of range: $medianBandwidthBytesPerSec"
        }
        require(medianLatencyMillis in 0..MAX_LATENCY_MILLIS) {
            "medianLatencyMillis out of range: $medianLatencyMillis"
        }
        require(observationCount >= 0) { "observationCount must be >= 0: $observationCount" }
    }

    companion object {
        const val MAX_METRIC_MICROS = 1_000_000
        const val MAX_BANDWIDTH_BYTES_PER_SEC = 1_000_000_000_000L // 1 TB/s sanity cap
        const val MAX_LATENCY_MILLIS = 600_000 // 10 min sanity cap
    }
}
