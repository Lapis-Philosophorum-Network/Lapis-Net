package net.lapisphilosophorum.lapisnet.trust

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

class VeritasGrantCodecTest :
    FunSpec({
        test("decode(encode(grant)) round-trips to an equal genesis grant") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000, comment = "hello")

            val roundTripped = VeritasGrantCodec.decode(VeritasGrantCodec.encode(grant))

            roundTripped shouldBe grant
        }

        test("decode(encode(grant)) round-trips for a grant with a predecessor") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val first = VeritasGrant.create(truster, target, trustMicros = 300_000)
            val second = VeritasGrant.create(truster, target, trustMicros = 700_000, previous = first)

            val roundTripped = VeritasGrantCodec.decode(VeritasGrantCodec.encode(second))

            roundTripped shouldBe second
            roundTripped.linksTo(first) shouldBe true
        }

        test("decode(encode(grant)) round-trips for empty comment and no occasion references") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = MIN_TRUST_MICROS)

            VeritasGrantCodec.decode(VeritasGrantCodec.encode(grant)) shouldBe grant
        }

        test("decode(encode(grant)) round-trips for multiple occasion references") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val refs = listOf(testCid(1), testCid(2), testCid(3))
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000, occasionReferences = refs)

            val roundTripped = VeritasGrantCodec.decode(VeritasGrantCodec.encode(grant))

            roundTripped shouldBe grant
            roundTripped.occasionReferences shouldBe refs
        }

        test("contentId is deterministic and 32 bytes long") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)

            val idA = grant.contentId()
            val idB = grant.contentId()

            idA.size shouldBe 32
            idA.contentEquals(idB) shouldBe true
        }

        test("grants differing only in trustMicros, target, or previousGrantId have distinct contentIds") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val otherTarget = Secp256k1KeyPair.generate().publicKey
            val base = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val differentTrust = VeritasGrant.create(truster, target, trustMicros = 500_001)
            val differentTarget = VeritasGrant.create(truster, otherTarget, trustMicros = 500_000)
            val withPredecessor = VeritasGrant.create(truster, target, trustMicros = 500_000, previous = base)

            val ids = listOf(base, differentTrust, differentTarget, withPredecessor).map { it.contentId().toList() }
            ids.toSet().size shouldBe 4
        }

        test("decode rejects bad magic") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val bytes = VeritasGrantCodec.encode(VeritasGrant.create(truster, target, trustMicros = 500_000))
            bytes[0] = 'X'.code.toByte()

            shouldThrow<MalformedVeritasGrantException> { VeritasGrantCodec.decode(bytes) }
        }

        test("decode rejects an unsupported version") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val bytes = VeritasGrantCodec.encode(VeritasGrant.create(truster, target, trustMicros = 500_000))
            bytes[4] = 99 // version byte, right after the 4-byte magic

            shouldThrow<MalformedVeritasGrantException> { VeritasGrantCodec.decode(bytes) }
        }

        test("decode rejects a truncated buffer") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val bytes = VeritasGrantCodec.encode(VeritasGrant.create(truster, target, trustMicros = 500_000))

            shouldThrow<MalformedVeritasGrantException> { VeritasGrantCodec.decode(bytes.copyOf(bytes.size / 2)) }
        }

        test("decode rejects trailing garbage after the signature") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val bytes = VeritasGrantCodec.encode(VeritasGrant.create(truster, target, trustMicros = 500_000))
            val withTrailingGarbage = bytes + byteArrayOf(1, 2, 3)

            shouldThrow<MalformedVeritasGrantException> { VeritasGrantCodec.decode(withTrailingGarbage) }
        }

        test("decode rejects non-zero reserved flag bits") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val bytes = VeritasGrantCodec.encode(VeritasGrant.create(truster, target, trustMicros = 500_000))
            bytes[5] = (bytes[5].toInt() or 0x02).toByte() // flags byte, right after magic(4) + version(1)

            shouldThrow<MalformedVeritasGrantException> { VeritasGrantCodec.decode(bytes) }
        }

        test("decode rejects a truster public key that is not a valid point on the curve") {
            // A structurally-plausible (right length, right prefix byte) but curve-invalid
            // truster key must fail cleanly as MalformedVeritasGrantException, not propagate an
            // uncaught native exception from the secp256k1 library - this is the regression test
            // for the DoS finding fixed in Secp256k1PublicKey's constructor (lapis-net-identity).
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val bytes = VeritasGrantCodec.encode(VeritasGrant.create(truster, target, trustMicros = 500_000))
            val invalidCurvePoint = byteArrayOf(0x02) + ByteArray(32)
            // truster starts right after magic(4) + version(1) + flags(1)
            invalidCurvePoint.copyInto(bytes, destinationOffset = 6)

            shouldThrow<MalformedVeritasGrantException> { VeritasGrantCodec.decode(bytes) }
        }

        test("a grant at the comment and occasion-reference caps still encodes and signs") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val maxComment = "a".repeat(VeritasGrantCodec.MAX_COMMENT_BYTES)
            val maxRefs = (1..VeritasGrantCodec.MAX_OCCASION_REFERENCES).map { testCid(it.toByte()) }

            val grant =
                VeritasGrant.create(
                    truster,
                    target,
                    trustMicros = 500_000,
                    comment = maxComment,
                    occasionReferences = maxRefs,
                )

            VeritasGrant.verify(grant) shouldBe true
            VeritasGrantCodec.decode(VeritasGrantCodec.encode(grant)) shouldBe grant
        }

        test("exceeding the comment cap is rejected at construction") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val tooLongComment = "a".repeat(VeritasGrantCodec.MAX_COMMENT_BYTES + 1)

            shouldThrow<IllegalArgumentException> {
                VeritasGrant.create(truster, target, trustMicros = 500_000, comment = tooLongComment)
            }
        }

        test("exceeding the occasion reference count cap is rejected at construction") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val tooManyRefs = (1..VeritasGrantCodec.MAX_OCCASION_REFERENCES + 1).map { testCid(it.toByte()) }

            shouldThrow<IllegalArgumentException> {
                VeritasGrant.create(truster, target, trustMicros = 500_000, occasionReferences = tooManyRefs)
            }
        }

        test("an occasion CID round-trips byte-identically through encode/decode") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val cid = testCid(42)
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000, occasionReferences = listOf(cid))

            val roundTripped = VeritasGrantCodec.decode(VeritasGrantCodec.encode(grant))

            roundTripped.occasionReferences
                .single()
                .toBytes()
                .contentEquals(cid.toBytes()) shouldBe true
        }
    })
