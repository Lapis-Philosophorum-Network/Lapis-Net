package net.lapisphilosophorum.lapisnet.virtus

/**
 * Pure time-decay/accumulation math for Virtus/LTR sort-weight, per the Virtus spec note's
 * "Verfallskurve" and "Akkumulationslogik" sections. No I/O, no side effects - every function here
 * is a deterministic function of its inputs plus a caller-supplied "now" timestamp, so tests never
 * need to depend on wall-clock time.
 *
 * **Why [Double], unlike [net.lapisphilosophorum.lapisnet.trust.VeritasGrant.trustMicros]'s
 * fixed-point convention.** A Veritas grant's `trustMicros` is part of a cryptographically signed,
 * cross-platform-verified structure, where floating point's hashing-determinism footguns (`-0.0`
 * vs `0.0`, NaN encodings, subtle cross-JVM differences) are a real correctness risk. A decayed or
 * accumulated LTR weight is none of those things: it is never signed, never part of any
 * [LtrRecordCodec]-encoded byte sequence, and never compared for cross-node consensus - it is
 * purely a local, per-view ranking heuristic each node/view computes independently for its own
 * sort order. `Double` is the natural, simplest type for that purely-local computation; the
 * determinism concerns that motivate `VeritasGrant.trustMicros`'s fixed-point choice do not apply
 * here.
 */
object LtrWeightCalculator {
    /** Fraction of value retained per 24h - see the Virtus spec note's "Verfallskurve" table
     * (10 % daily decay, i.e. 90 % retained per day). */
    private const val DECAY_PER_DAY = 0.9
    private const val HOURS_PER_DAY = 24.0

    /**
     * The decayed msat weight of a single [record] as of [atEpochSeconds]:
     * `initialValueMsat * 0.9 ^ (hoursElapsed / 24)`, per the Virtus spec note's worked decay
     * table (t=0h -> 100 %, t=24h -> ~90 %, t=7d -> ~48 %, t=30d -> ~4 %, t=60d -> ~0.2 %).
     *
     * **The `coerceAtLeast(0.0)` clamp on `hoursElapsed` is load-bearing, not defensive
     * boilerplate.** A record whose [LtrRecord.timestampSeconds] is in the future relative to
     * [atEpochSeconds] (clock skew between peers, or a record not yet valid) would otherwise
     * produce a *negative* exponent in `0.9 ^ (hoursElapsed / 24)` - and since `0.9 < 1`, a
     * negative exponent makes the decay factor *greater than 1*, i.e. the record would appear to
     * be worth MORE than its own signed face value. That must never happen: a record can only
     * ever decay towards zero, never inflate above what was actually paid for it. Clamping
     * `hoursElapsed` to a minimum of `0.0` forces the decay factor to a maximum of exactly `1.0`
     * (full face value) for any future-timestamped record, never more.
     */
    fun decayedWeightMsat(
        record: LtrRecord,
        atEpochSeconds: Long = System.currentTimeMillis() / 1000,
    ): Double {
        val hoursElapsed = ((atEpochSeconds - record.timestampSeconds) / 3600.0).coerceAtLeast(0.0)
        val decayFactor = Math.pow(DECAY_PER_DAY, hoursElapsed / HOURS_PER_DAY)
        return record.initialValueMsat.toDouble() * decayFactor
    }

    /** Sum of [decayedWeightMsat] across [records] as of [atEpochSeconds] - the sort-weight for a
     * `(cid, viewId)` pair, per the Virtus spec note's "Akkumulationslogik" section: every
     * independent record for the pair contributes its own decayed value, none are merged or
     * resolved to a single winner (see [LtrRecordIndex]'s doc comment). Does not mutate
     * [records] or any element in it - purely a read-only fold. */
    fun accumulatedWeightMsat(
        records: Collection<LtrRecord>,
        atEpochSeconds: Long = System.currentTimeMillis() / 1000,
    ): Double = records.sumOf { decayedWeightMsat(it, atEpochSeconds) }

    /**
     * The exact, undecayed sum of [LtrRecord.initialValueMsat] across [records] - a real
     * accounting figure ("how many msat were actually paid in, total"), NOT a ranking heuristic,
     * which is why this is [Long] (exact, overflow-guarded via [Math.addExact]) rather than the
     * [Double] used everywhere else in this object. Unlike [accumulatedWeightMsat], this number
     * has real-world financial meaning and must never silently lose precision or wrap around -
     * [Math.addExact] fails loudly on overflow rather than silently corrupting the total, and that
     * behavior is deliberate and must not be changed to a saturating or wrapping sum.
     *
     * **Caller contract - MUST catch [ArithmeticException].** See [MAX_INITIAL_VALUE_MSAT]'s doc
     * comment: as few as 5 maximum-value records already overflow a running [Long] sum, and this
     * wave's [OnChainProof] has no live chain verification, so a handful of self-signed
     * maximum-value records is a trivial, cheap way for an adversary to trigger this. Any caller
     * that feeds this function a network-derived/untrusted record set - e.g. records obtained from
     * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip.currentRecords] - MUST catch
     * [ArithmeticException]. This is not a defensive nicety for a remote edge case; it is a
     * realistic input a single hostile peer can produce today.
     *
     * @throws ArithmeticException if the sum would overflow [Long.MAX_VALUE].
     */
    fun totalInvestedMsat(records: Collection<LtrRecord>): Long =
        records.fold(0L) { acc, r -> Math.addExact(acc, r.initialValueMsat) }
}
