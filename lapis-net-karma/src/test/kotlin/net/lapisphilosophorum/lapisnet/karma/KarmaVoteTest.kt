package net.lapisphilosophorum.lapisnet.karma

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testAnchor(seed: Byte = 1): ChainAnchorClaim = ChainAnchorClaim(100, ByteArray(32) { seed }, 200)

class KarmaVoteTest :
    FunSpec({
        test("create then verify round-trips for a valid vote with a ChainAnchorClaim") {
            val voter = Secp256k1KeyPair.generate()
            val vote = KarmaVote.create(voter, testCid(1), testAnchor())

            KarmaVote.verify(vote) shouldBe true
            vote.voter shouldBe voter.publicKey
        }

        test("create then verify round-trips for a valid vote with NoAnchorClaim") {
            val voter = Secp256k1KeyPair.generate()
            val vote = KarmaVote.create(voter, testCid(1), NoAnchorClaim)

            KarmaVote.verify(vote) shouldBe true
            vote.timeAnchor shouldBe NoAnchorClaim
        }

        test("verify(expectedVoter, vote) is true for the real voter and false for a different one") {
            val voter = Secp256k1KeyPair.generate()
            val other = Secp256k1KeyPair.generate()
            val vote = KarmaVote.create(voter, testCid(1), testAnchor())

            KarmaVote.verify(voter.publicKey, vote) shouldBe true
            KarmaVote.verify(other.publicKey, vote) shouldBe false
        }

        test("fromDecoded rejects a nonce that is not exactly 8 bytes") {
            val voter = Secp256k1KeyPair.generate().publicKey

            shouldThrow<IllegalArgumentException> {
                KarmaVote.fromDecoded(
                    voter = voter,
                    targetCid = testCid(1),
                    timestampSeconds = 0,
                    timeAnchor = NoAnchorClaim,
                    nonce = ByteArray(7),
                    signature = ByteArray(64),
                )
            }
        }

        test("fromDecoded rejects a signature that is not exactly 64 bytes") {
            val voter = Secp256k1KeyPair.generate().publicKey

            shouldThrow<IllegalArgumentException> {
                KarmaVote.fromDecoded(
                    voter = voter,
                    targetCid = testCid(1),
                    timestampSeconds = 0,
                    timeAnchor = NoAnchorClaim,
                    nonce = ByteArray(8),
                    signature = ByteArray(63),
                )
            }
        }

        test("two independent create() calls with otherwise-identical inputs get distinct nonces and content ids") {
            val voter = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val anchor = testAnchor()
            val timestamp = 1_700_000_000L

            val a = KarmaVote.create(voter, cid, anchor, timestampSeconds = timestamp)
            val b = KarmaVote.create(voter, cid, anchor, timestampSeconds = timestamp)

            a.nonce.contentEquals(b.nonce) shouldBe false
            a.contentId().contentEquals(b.contentId()) shouldBe false
            (a == b) shouldBe false
        }

        test("equals/hashCode are consistent for votes built from identical fromDecoded inputs") {
            val voter = Secp256k1KeyPair.generate().publicKey
            val nonce = ByteArray(8) { it.toByte() }
            val signature = ByteArray(64) { it.toByte() }
            val anchor = testAnchor()

            val a = KarmaVote.fromDecoded(voter, testCid(1), 1_700_000_000L, anchor, nonce, signature)
            val b = KarmaVote.fromDecoded(voter, testCid(1), 1_700_000_000L, anchor, nonce, signature)

            a shouldBe b
            a.hashCode() shouldBe b.hashCode()
        }

        test("toString never includes the raw signature bytes") {
            val voter = Secp256k1KeyPair.generate()
            val vote = KarmaVote.create(voter, testCid(1), testAnchor())

            val signatureHex = vote.signature.joinToString("") { "%02x".format(it) }
            vote.toString().contains(signatureHex) shouldBe false
        }

        test("contentId is deterministic and 32 bytes long") {
            val voter = Secp256k1KeyPair.generate()
            val vote = KarmaVote.create(voter, testCid(1), testAnchor())

            val idA = vote.contentId()
            val idB = vote.contentId()

            idA.size shouldBe 32
            idA.contentEquals(idB) shouldBe true
        }

        test("votes differing only in targetCid or timeAnchor have distinct contentIds") {
            val voter = Secp256k1KeyPair.generate()
            val timestamp = 1_700_000_000L

            val base = KarmaVote.create(voter, testCid(1), testAnchor(1), timestampSeconds = timestamp)
            val differentCid = KarmaVote.create(voter, testCid(2), testAnchor(1), timestampSeconds = timestamp)
            val differentAnchor = KarmaVote.create(voter, testCid(1), testAnchor(2), timestampSeconds = timestamp)
            val noAnchor = KarmaVote.create(voter, testCid(1), NoAnchorClaim, timestampSeconds = timestamp)

            val ids = listOf(base, differentCid, differentAnchor, noAnchor).map { it.contentId().toList() }
            ids.toSet().size shouldBe 4
        }

        test("returned mutable byte arrays are copies, not live references to internal state") {
            val voter = Secp256k1KeyPair.generate()
            val vote = KarmaVote.create(voter, testCid(1), testAnchor())

            val originalSignature = vote.signature.copyOf()
            vote.signature.also { it[0] = (it[0] + 1).toByte() }
            vote.signature.contentEquals(originalSignature) shouldBe true
            KarmaVote.verify(vote) shouldBe true

            val originalNonce = vote.nonce.copyOf()
            vote.nonce.also { it[0] = (it[0] + 1).toByte() }
            vote.nonce.contentEquals(originalNonce) shouldBe true
        }
    })
