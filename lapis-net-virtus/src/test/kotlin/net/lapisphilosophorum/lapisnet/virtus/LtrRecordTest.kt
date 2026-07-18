package net.lapisphilosophorum.lapisnet.virtus

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testProof(seed: Byte = 1): OnChainProof = OnChainProof(ByteArray(32) { seed }, outputIndex = 0)

class LtrRecordTest :
    FunSpec({
        test("create then verify round-trips for a valid record") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 1000, proof = testProof())

            LtrRecord.verify(record) shouldBe true
            record.payer shouldBe payer.publicKey
        }

        test("verify(expectedPayer, record) is true for the real payer and false for a different one") {
            val payer = Secp256k1KeyPair.generate()
            val other = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 1000, proof = testProof())

            LtrRecord.verify(payer.publicKey, record) shouldBe true
            LtrRecord.verify(other.publicKey, record) shouldBe false
        }

        test("boundary initialValueMsat values MIN and MAX both create and verify") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey

            val min =
                LtrRecord.create(
                    payer,
                    testCid(1),
                    viewId,
                    initialValueMsat = MIN_INITIAL_VALUE_MSAT,
                    proof = testProof(),
                )
            val max =
                LtrRecord.create(
                    payer,
                    testCid(2),
                    viewId,
                    initialValueMsat = MAX_INITIAL_VALUE_MSAT,
                    proof = testProof(),
                )

            LtrRecord.verify(min) shouldBe true
            LtrRecord.verify(max) shouldBe true
            min.initialValueMsat shouldBe MIN_INITIAL_VALUE_MSAT
            max.initialValueMsat shouldBe MAX_INITIAL_VALUE_MSAT
        }

        test("initialValueMsat below the floor is rejected") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey

            shouldThrow<IllegalArgumentException> {
                LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 0, proof = testProof())
            }
            shouldThrow<IllegalArgumentException> {
                LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = -1, proof = testProof())
            }
        }

        test("initialValueMsat above the ceiling is rejected") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey

            shouldThrow<IllegalArgumentException> {
                LtrRecord.create(
                    payer,
                    testCid(1),
                    viewId,
                    initialValueMsat = MAX_INITIAL_VALUE_MSAT + 1,
                    proof = testProof(),
                )
            }
        }

        test("fromDecoded rejects a nonce that is not exactly 8 bytes") {
            val payer = Secp256k1KeyPair.generate().publicKey
            val viewId = Secp256k1KeyPair.generate().publicKey

            shouldThrow<IllegalArgumentException> {
                LtrRecord.fromDecoded(
                    cid = testCid(1),
                    viewId = viewId,
                    payer = payer,
                    initialValueMsat = 1000,
                    timestampSeconds = 0,
                    nonce = ByteArray(7),
                    proof = testProof(),
                    signature = ByteArray(64),
                )
            }
        }

        test("fromDecoded rejects a signature that is not exactly 64 bytes") {
            val payer = Secp256k1KeyPair.generate().publicKey
            val viewId = Secp256k1KeyPair.generate().publicKey

            shouldThrow<IllegalArgumentException> {
                LtrRecord.fromDecoded(
                    cid = testCid(1),
                    viewId = viewId,
                    payer = payer,
                    initialValueMsat = 1000,
                    timestampSeconds = 0,
                    nonce = ByteArray(8),
                    proof = testProof(),
                    signature = ByteArray(63),
                )
            }
        }

        test("initialValueSats is a display-only derivation - 1000 msat is 1.0 sats") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 1000, proof = testProof())

            record.initialValueSats shouldBe 1.0
        }

        test("two independent create() calls with otherwise-identical inputs get distinct nonces and content ids") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val cid = testCid(1)
            val proof = testProof()
            val timestamp = 1_700_000_000L

            val a =
                LtrRecord.create(
                    payer,
                    cid,
                    viewId,
                    initialValueMsat = 1000,
                    proof = proof,
                    timestampSeconds = timestamp,
                )
            val b =
                LtrRecord.create(
                    payer,
                    cid,
                    viewId,
                    initialValueMsat = 1000,
                    proof = proof,
                    timestampSeconds = timestamp,
                )

            a.nonce.contentEquals(b.nonce) shouldBe false
            a.contentId().contentEquals(b.contentId()) shouldBe false
            a shouldNotBeEqualTo b
        }

        test("equals/hashCode are consistent for records built from identical fromDecoded inputs") {
            val payer = Secp256k1KeyPair.generate().publicKey
            val viewId = Secp256k1KeyPair.generate().publicKey
            val nonce = ByteArray(8) { it.toByte() }
            val signature = ByteArray(64) { it.toByte() }
            val proof = testProof()

            val a =
                LtrRecord.fromDecoded(testCid(1), viewId, payer, 1000, 1_700_000_000L, nonce, proof, signature)
            val b =
                LtrRecord.fromDecoded(testCid(1), viewId, payer, 1000, 1_700_000_000L, nonce, proof, signature)

            a shouldBe b
            a.hashCode() shouldBe b.hashCode()
        }

        test("toString never includes the raw signature bytes") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 1000, proof = testProof())

            val signatureHex = record.signature.joinToString("") { "%02x".format(it) }
            record.toString().contains(signatureHex) shouldBe false
        }

        test("contentId is deterministic and 32 bytes long") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 1000, proof = testProof())

            val idA = record.contentId()
            val idB = record.contentId()

            idA.size shouldBe 32
            idA.contentEquals(idB) shouldBe true
        }

        test("records differing only in initialValueMsat, cid, or viewId have distinct contentIds") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val otherViewId = Secp256k1KeyPair.generate().publicKey
            val timestamp = 1_700_000_000L
            val proof = testProof()

            val base = LtrRecord.create(payer, testCid(1), viewId, 1000, proof, timestamp)
            val differentValue = LtrRecord.create(payer, testCid(1), viewId, 2000, proof, timestamp)
            val differentCid = LtrRecord.create(payer, testCid(2), viewId, 1000, proof, timestamp)
            val differentView = LtrRecord.create(payer, testCid(1), otherViewId, 1000, proof, timestamp)

            val ids = listOf(base, differentValue, differentCid, differentView).map { it.contentId().toList() }
            ids.toSet().size shouldBe 4
        }

        test("returned mutable byte arrays are copies, not live references to internal state") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 1000, proof = testProof())

            val originalSignature = record.signature.copyOf()
            record.signature.also { it[0] = (it[0] + 1).toByte() }
            record.signature.contentEquals(originalSignature) shouldBe true
            LtrRecord.verify(record) shouldBe true

            val originalNonce = record.nonce.copyOf()
            record.nonce.also { it[0] = (it[0] + 1).toByte() }
            record.nonce.contentEquals(originalNonce) shouldBe true
        }
    })

private infix fun LtrRecord.shouldNotBeEqualTo(other: LtrRecord) {
    (this == other) shouldBe false
}
