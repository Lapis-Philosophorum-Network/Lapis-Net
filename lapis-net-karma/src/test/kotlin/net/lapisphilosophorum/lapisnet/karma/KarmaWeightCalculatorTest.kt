package net.lapisphilosophorum.lapisnet.karma

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.doubles.shouldNotBeNaN
import io.kotest.matchers.doubles.shouldNotBePositiveInfinity
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun anchor(
    genesisHeight: Int,
    tipHeight: Int,
    seed: Byte = 1,
): ChainAnchorClaim = ChainAnchorClaim(genesisHeight, ByteArray(32) { seed }, tipHeight)

class KarmaWeightCalculatorTest :
    FunSpec({
        test("t=0 (genesisBlockHeight == tipHeightAtVote) yields Karma=0") {
            val voter = Secp256k1KeyPair.generate()
            val vote = KarmaVote.create(voter, testCid(1), anchor(500, 500))

            KarmaWeightCalculator.karmaValue(vote, listOf(vote)) shouldBe 0.0
        }

        test("the voter's first (and only) eligible vote has n=0, so Karma = t") {
            val voter = Secp256k1KeyPair.generate()
            val vote = KarmaVote.create(voter, testCid(1), anchor(100, 250))

            KarmaWeightCalculator.karmaValue(vote, listOf(vote)) shouldBe 150.0
        }

        test("NoAnchorClaim always yields Karma=0, regardless of other votes by the same voter") {
            val voter = Secp256k1KeyPair.generate()
            val eligible = KarmaVote.create(voter, testCid(1), anchor(0, 1000), timestampSeconds = 1_000)
            val noAnchorVote = KarmaVote.create(voter, testCid(2), NoAnchorClaim, timestampSeconds = 2_000)

            KarmaWeightCalculator.karmaValue(noAnchorVote, listOf(eligible, noAnchorVote)) shouldBe 0.0
        }

        test("votes cast during the voter's NoAnchorClaim era never count toward n for a later eligible vote") {
            val voter = Secp256k1KeyPair.generate()
            val noAnchorVote = KarmaVote.create(voter, testCid(1), NoAnchorClaim, timestampSeconds = 1_000)
            val laterEligible = KarmaVote.create(voter, testCid(2), anchor(0, 500), timestampSeconds = 2_000)

            // Only laterEligible carries a ChainAnchorClaim - the earlier NoAnchorClaim vote must
            // not be counted as a prior eligible vote, so n stays 0.
            val karma = KarmaWeightCalculator.karmaValue(laterEligible, listOf(noAnchorVote, laterEligible))

            karma shouldBe 500.0 // t=500, n=0 -> 500/1
        }

        test("a second eligible vote by the same voter has n=1, halving the raw t") {
            val voter = Secp256k1KeyPair.generate()
            val first = KarmaVote.create(voter, testCid(1), anchor(0, 100), timestampSeconds = 1_000)
            val second = KarmaVote.create(voter, testCid(2), anchor(0, 100), timestampSeconds = 2_000)

            KarmaWeightCalculator.karmaValue(first, listOf(first, second)) shouldBe 100.0 // n=0
            KarmaWeightCalculator.karmaValue(second, listOf(first, second)) shouldBe 50.0 // n=1, t=100/(1+1)
        }

        test("receipt-order independence: the same vote set in a different insertion order yields identical n") {
            val voter = Secp256k1KeyPair.generate()
            val v1 = KarmaVote.create(voter, testCid(1), anchor(0, 100), timestampSeconds = 1_000)
            val v2 = KarmaVote.create(voter, testCid(2), anchor(0, 200), timestampSeconds = 2_000)
            val v3 = KarmaVote.create(voter, testCid(3), anchor(0, 300), timestampSeconds = 3_000)

            val orderA = listOf(v1, v2, v3)
            val orderB = listOf(v3, v1, v2)
            val orderC = listOf(v2, v3, v1)

            for (target in listOf(v1, v2, v3)) {
                val a = KarmaWeightCalculator.karmaValue(target, orderA)
                val b = KarmaWeightCalculator.karmaValue(target, orderB)
                val c = KarmaWeightCalculator.karmaValue(target, orderC)
                a shouldBe b
                b shouldBe c
            }
        }

        test("large-but-capped heights produce a finite, non-NaN, non-Infinity Karma value") {
            val voter = Secp256k1KeyPair.generate()
            val vote =
                KarmaVote.create(
                    voter,
                    testCid(1),
                    anchor(genesisHeight = 0, tipHeight = MAX_STRUCTURAL_BLOCK_HEIGHT),
                )

            val karma = KarmaWeightCalculator.karmaValue(vote, listOf(vote))

            karma.shouldNotBeNaN()
            karma.shouldNotBePositiveInfinity()
            karma shouldBe MAX_STRUCTURAL_BLOCK_HEIGHT.toDouble()
        }

        test("totalRawKarmaForTarget sums karmaValue across every vote for a target") {
            val voterA = Secp256k1KeyPair.generate()
            val voterB = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val voteA = KarmaVote.create(voterA, cid, anchor(0, 100), timestampSeconds = 1_000)
            val voteB = KarmaVote.create(voterB, cid, anchor(0, 300), timestampSeconds = 1_000)
            val votesByVoter: (net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey) -> List<KarmaVote> = {
                when (it) {
                    voterA.publicKey -> listOf(voteA)
                    voterB.publicKey -> listOf(voteB)
                    else -> emptyList()
                }
            }

            val total = KarmaWeightCalculator.totalRawKarmaForTarget(listOf(voteA, voteB), votesByVoter)

            total shouldBe 400.0 // 100 (n=0) + 300 (n=0, different voter)
        }
    })
