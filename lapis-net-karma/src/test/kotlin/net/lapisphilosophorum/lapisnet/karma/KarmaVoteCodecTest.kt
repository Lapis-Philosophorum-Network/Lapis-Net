package net.lapisphilosophorum.lapisnet.karma

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testAnchor(seed: Byte = 1): ChainAnchorClaim = ChainAnchorClaim(100, ByteArray(32) { seed }, 200)

class KarmaVoteCodecTest :
    FunSpec({
        test("decode(encode(vote)) round-trips to an equal vote - ChainAnchorClaim") {
            val voter = Secp256k1KeyPair.generate()
            val vote = KarmaVote.create(voter, testCid(1), testAnchor())

            val roundTripped = KarmaVoteCodec.decode(KarmaVoteCodec.encode(vote))

            roundTripped shouldBe vote
        }

        test("decode(encode(vote)) round-trips to an equal vote - NoAnchorClaim") {
            val voter = Secp256k1KeyPair.generate()
            val vote = KarmaVote.create(voter, testCid(1), NoAnchorClaim)

            val roundTripped = KarmaVoteCodec.decode(KarmaVoteCodec.encode(vote))

            roundTripped shouldBe vote
            roundTripped.timeAnchor shouldBe NoAnchorClaim
        }

        test("contentId is deterministic and 32 bytes long") {
            val voter = Secp256k1KeyPair.generate()
            val vote = KarmaVote.create(voter, testCid(1), testAnchor())

            val idA = KarmaVoteCodec.contentId(vote)
            val idB = KarmaVoteCodec.contentId(vote)

            idA.size shouldBe 32
            idA.contentEquals(idB) shouldBe true
        }

        test("decode does not verify signatures - a signature-tampered vote still decodes successfully") {
            val voter = Secp256k1KeyPair.generate()
            val vote = KarmaVote.create(voter, testCid(1), testAnchor())
            val bytes = KarmaVoteCodec.encode(vote)
            bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte()

            val decoded = KarmaVoteCodec.decode(bytes)

            KarmaVote.verify(decoded) shouldBe false
        }

        test("decode rejects bad magic") {
            val voter = Secp256k1KeyPair.generate()
            val bytes = KarmaVoteCodec.encode(KarmaVote.create(voter, testCid(1), testAnchor()))
            bytes[0] = 'X'.code.toByte()

            shouldThrow<MalformedKarmaVoteException> { KarmaVoteCodec.decode(bytes) }
        }

        test("decode rejects an unsupported version") {
            val voter = Secp256k1KeyPair.generate()
            val bytes = KarmaVoteCodec.encode(KarmaVote.create(voter, testCid(1), testAnchor()))
            bytes[4] = 99 // version byte, right after the 4-byte magic

            shouldThrow<MalformedKarmaVoteException> { KarmaVoteCodec.decode(bytes) }
        }

        test("decode rejects a truncated buffer") {
            val voter = Secp256k1KeyPair.generate()
            val bytes = KarmaVoteCodec.encode(KarmaVote.create(voter, testCid(1), testAnchor()))

            shouldThrow<MalformedKarmaVoteException> { KarmaVoteCodec.decode(bytes.copyOf(bytes.size / 2)) }
        }

        test("decode rejects trailing garbage after the signature") {
            val voter = Secp256k1KeyPair.generate()
            val bytes = KarmaVoteCodec.encode(KarmaVote.create(voter, testCid(1), testAnchor()))
            val withTrailingGarbage = bytes + byteArrayOf(1, 2, 3)

            shouldThrow<MalformedKarmaVoteException> { KarmaVoteCodec.decode(withTrailingGarbage) }
        }

        test("decode rejects an unknown anchorType") {
            val voter = Secp256k1KeyPair.generate()
            val bytes = KarmaVoteCodec.encode(KarmaVote.create(voter, testCid(1), testAnchor()))

            // anchorType is the single byte right after magic(4)+version(1)+voter(33)+cidLen(2)+
            // cid+timestampSeconds(8).
            val cidBytes = testCid(1).toBytes()
            val anchorTypeOffset = 4 + 1 + 33 + 2 + cidBytes.size + 8

            val neverDefined = bytes.copyOf()
            neverDefined[anchorTypeOffset] = 99
            shouldThrow<MalformedKarmaVoteException> { KarmaVoteCodec.decode(neverDefined) }
        }

        test("decode rejects a wrong-length ChainAnchorClaim payload") {
            val voter = Secp256k1KeyPair.generate()
            val bytes = KarmaVoteCodec.encode(KarmaVote.create(voter, testCid(1), testAnchor()))

            // anchorLen(2) sits right after magic(4)+version(1)+voter(33)+cidLen(2)+cid+
            // timestampSeconds(8)+anchorType(1) - declaring one byte fewer than the true 40-byte
            // ChainAnchorClaim payload must be rejected outright, not silently truncated.
            val cidBytes = testCid(1).toBytes()
            val anchorLenOffset = 4 + 1 + 33 + 2 + cidBytes.size + 8 + 1
            val wrongLen = 39
            bytes[anchorLenOffset] = (wrongLen ushr 8).toByte()
            bytes[anchorLenOffset + 1] = wrongLen.toByte()

            shouldThrow<MalformedKarmaVoteException> { KarmaVoteCodec.decode(bytes) }
        }

        test("decode rejects a non-zero-length NoAnchorClaim payload") {
            val voter = Secp256k1KeyPair.generate()
            val bytes = KarmaVoteCodec.encode(KarmaVote.create(voter, testCid(1), NoAnchorClaim))

            // anchorLen(2) sits right after magic(4)+version(1)+voter(33)+cidLen(2)+cid+
            // timestampSeconds(8)+anchorType(1) - anchorType is 0 (NoAnchorClaim), declared
            // anchorLen must be 0; forcing it non-zero (without adding matching payload bytes)
            // makes the buffer internally inconsistent and must be rejected.
            val cidBytes = testCid(1).toBytes()
            val anchorLenOffset = 4 + 1 + 33 + 2 + cidBytes.size + 8 + 1
            bytes[anchorLenOffset] = 0
            bytes[anchorLenOffset + 1] = 1

            shouldThrow<MalformedKarmaVoteException> { KarmaVoteCodec.decode(bytes) }
        }

        test("decode rejects out-of-range heights for a type-1 ChainAnchorClaim") {
            val voter = Secp256k1KeyPair.generate()
            val bytes = KarmaVoteCodec.encode(KarmaVote.create(voter, testCid(1), testAnchor()))

            // ChainAnchorClaim payload is genesisTxid(32)|genesisBlockHeight(4)|tipHeightAtVote(4),
            // sitting right after magic(4)+version(1)+voter(33)+cidLen(2)+cid+timestampSeconds(8)+
            // anchorType(1)+anchorLen(2).
            val cidBytes = testCid(1).toBytes()
            val anchorBytesOffset = 4 + 1 + 33 + 2 + cidBytes.size + 8 + 1 + 2
            val genesisHeightOffset = anchorBytesOffset + 32
            val tooLarge = MAX_STRUCTURAL_BLOCK_HEIGHT + 1
            bytes[genesisHeightOffset] = (tooLarge ushr 24).toByte()
            bytes[genesisHeightOffset + 1] = (tooLarge ushr 16).toByte()
            bytes[genesisHeightOffset + 2] = (tooLarge ushr 8).toByte()
            bytes[genesisHeightOffset + 3] = tooLarge.toByte()

            shouldThrow<MalformedKarmaVoteException> { KarmaVoteCodec.decode(bytes) }
        }

        test("decode rejects tipHeightAtVote < genesisBlockHeight for a type-1 ChainAnchorClaim") {
            val voter = Secp256k1KeyPair.generate()
            val bytes = KarmaVoteCodec.encode(KarmaVote.create(voter, testCid(1), testAnchor(seed = 1)))

            val cidBytes = testCid(1).toBytes()
            val anchorBytesOffset = 4 + 1 + 33 + 2 + cidBytes.size + 8 + 1 + 2
            val tipHeightOffset = anchorBytesOffset + 32 + 4
            // Force tipHeightAtVote to 0 - below the encoded genesisBlockHeight (100).
            bytes[tipHeightOffset] = 0
            bytes[tipHeightOffset + 1] = 0
            bytes[tipHeightOffset + 2] = 0
            bytes[tipHeightOffset + 3] = 0

            shouldThrow<MalformedKarmaVoteException> { KarmaVoteCodec.decode(bytes) }
        }

        test("decode rejects a cid whose declared length exceeds MAX_CID_BYTES") {
            val voter = Secp256k1KeyPair.generate()
            val bytes = KarmaVoteCodec.encode(KarmaVote.create(voter, testCid(1), testAnchor()))

            // cidLen(2) starts right after magic(4)+version(1)+voter(33)
            val cidLenOffset = 4 + 1 + 33
            val tooLong = KarmaVoteCodec.MAX_CID_BYTES + 1
            bytes[cidLenOffset] = (tooLong ushr 8).toByte()
            bytes[cidLenOffset + 1] = tooLong.toByte()

            shouldThrow<MalformedKarmaVoteException> { KarmaVoteCodec.decode(bytes) }
        }
    })
