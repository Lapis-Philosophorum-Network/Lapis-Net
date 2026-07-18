package net.lapisphilosophorum.lapisnet.virtus

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.doubles.plusOrMinus
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import java.security.SecureRandom

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testProof(seed: Byte = 1): OnChainProof = OnChainProof(ByteArray(32) { seed }, outputIndex = 0)

private const val BASE_TIME = 1_700_000_000L

private fun recordAt(
    timestampSeconds: Long,
    initialValueMsat: Long = 1_000_000L,
): LtrRecord {
    val payer = Secp256k1KeyPair.generate()
    val viewId = Secp256k1KeyPair.generate().publicKey
    return LtrRecord.create(
        payer,
        testCid(1),
        viewId,
        initialValueMsat = initialValueMsat,
        proof = testProof(),
        timestampSeconds = timestampSeconds,
        random = SecureRandom(),
    )
}

class LtrWeightCalculatorTest :
    FunSpec({
        test("t=0h: full face value") {
            val record = recordAt(BASE_TIME, initialValueMsat = 1_000_000L)

            LtrWeightCalculator.decayedWeightMsat(record, BASE_TIME) shouldBe 1_000_000.0
        }

        test("t=24h: exactly 0.9x") {
            val record = recordAt(BASE_TIME, initialValueMsat = 1_000_000L)

            val weight = LtrWeightCalculator.decayedWeightMsat(record, BASE_TIME + 24 * 3600)

            weight shouldBe (900_000.0 plusOrMinus 0.001)
        }

        test("t=7 days: ~48% of face value, per the spec note's worked decay table") {
            val record = recordAt(BASE_TIME, initialValueMsat = 1_000_000L)

            val weight = LtrWeightCalculator.decayedWeightMsat(record, BASE_TIME + 7 * 24 * 3600)

            weight shouldBe (478_296.9 plusOrMinus 1.0) // ~48%
        }

        test("t=30 days: ~4% of face value, per the spec note's worked decay table") {
            val record = recordAt(BASE_TIME, initialValueMsat = 1_000_000L)

            val weight = LtrWeightCalculator.decayedWeightMsat(record, BASE_TIME + 30 * 24 * 3600)

            weight shouldBe (42_391.16 plusOrMinus 10.0) // ~4%
        }

        test("t=60 days: ~0.2% of face value, per the spec note's worked decay table") {
            val record = recordAt(BASE_TIME, initialValueMsat = 1_000_000L)

            val weight = LtrWeightCalculator.decayedWeightMsat(record, BASE_TIME + 60 * 24 * 3600)

            weight shouldBe (1_797.0 plusOrMinus 5.0) // ~0.18%, "~0.2%" in the spec table
        }

        test("a future-timestamped record never decays above its own face value") {
            val record = recordAt(BASE_TIME, initialValueMsat = 1_000_000L)

            // atEpochSeconds is BEFORE the record's own timestamp - without the coerceAtLeast(0.0)
            // clamp, this would produce a negative exponent and inflate the weight above face value.
            val weight = LtrWeightCalculator.decayedWeightMsat(record, BASE_TIME - 100_000)

            weight shouldBe 1_000_000.0
        }

        test("accumulatedWeightMsat sums independently-decayed weights across multiple records") {
            val recordFresh = recordAt(BASE_TIME, initialValueMsat = 1_000_000L)
            val recordOneDayOld = recordAt(BASE_TIME - 24 * 3600, initialValueMsat = 1_000_000L)

            val total = LtrWeightCalculator.accumulatedWeightMsat(listOf(recordFresh, recordOneDayOld), BASE_TIME)

            // 1_000_000 (fresh, t=0h) + 900_000 (one day old, t=24h decay)
            total shouldBe (1_900_000.0 plusOrMinus 0.01)
        }

        test("accumulatedWeightMsat does not mutate its input records") {
            val records = listOf(recordAt(BASE_TIME, 1_000_000L), recordAt(BASE_TIME - 3600, 500_000L))
            val snapshotBefore = records.map { it.contentId().toList() to it.initialValueMsat }

            LtrWeightCalculator.accumulatedWeightMsat(records, BASE_TIME)

            val snapshotAfter = records.map { it.contentId().toList() to it.initialValueMsat }
            snapshotAfter shouldBe snapshotBefore
        }

        test("totalInvestedMsat is the exact, undecayed sum") {
            val records = listOf(recordAt(BASE_TIME, 1_000_000L), recordAt(BASE_TIME - 999_999, 2_500_000L))

            LtrWeightCalculator.totalInvestedMsat(records) shouldBe 3_500_000L
        }

        test("totalInvestedMsat throws ArithmeticException on overflow") {
            // Each individual LtrRecord is capped at MAX_INITIAL_VALUE_MSAT (~2.1 * 10^18), so no
            // single record can overflow a Long by itself - but summing enough of them can, and it
            // doesn't take many: Long.MAX_VALUE / MAX_INITIAL_VALUE_MSAT is ~4.39, so the real
            // minimum-overflow record count is just 5 (4 copies sum to 8.4 * 10^18, still under
            // Long.MAX_VALUE; a 5th pushes the running sum past it) - not thousands. This test uses
            // 4393 copies of the same maximum-value record (reusing one already-signed record
            // instance - no need to sign 4393 distinct ones) purely as a generous, obviously-past-
            // the-threshold margin, not because that many are actually needed.
            val maxValueRecord = recordAt(BASE_TIME, MAX_INITIAL_VALUE_MSAT)
            val records = List(4393) { maxValueRecord }

            io.kotest.assertions.throwables.shouldThrow<ArithmeticException> {
                LtrWeightCalculator.totalInvestedMsat(records)
            }
        }
    })
