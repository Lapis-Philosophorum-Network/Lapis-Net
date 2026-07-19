package net.lapisphilosophorum.lapisnet.virtus

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testProof(seed: Byte = 1): OnChainProof = OnChainProof(ByteArray(32) { seed }, outputIndex = 3)

private fun testLightningProof(seed: Byte = 1): LightningProof =
    LightningProof(ByteArray(32) { seed }, ByteArray(32) { (seed + 1).toByte() }, "lnbc1testinvoiceabc")

class LtrRecordCodecTest :
    FunSpec({
        test("decode(encode(record)) round-trips to an equal record") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 5000, proof = testProof())

            val roundTripped = LtrRecordCodec.decode(LtrRecordCodec.encode(record))

            roundTripped shouldBe record
        }

        test("decode(encode(record)) round-trips at the MIN and MAX initialValueMsat boundaries") {
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

            LtrRecordCodec.decode(LtrRecordCodec.encode(min)) shouldBe min
            LtrRecordCodec.decode(LtrRecordCodec.encode(max)) shouldBe max
        }

        test("contentId is deterministic and 32 bytes long") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 1000, proof = testProof())

            val idA = LtrRecordCodec.contentId(record)
            val idB = LtrRecordCodec.contentId(record)

            idA.size shouldBe 32
            idA.contentEquals(idB) shouldBe true
        }

        test("decode does not verify signatures - a signature-tampered record still decodes successfully") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 1000, proof = testProof())
            val bytes = LtrRecordCodec.encode(record)
            bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte()

            val decoded = LtrRecordCodec.decode(bytes)

            LtrRecord.verify(decoded) shouldBe false
        }

        test("decode rejects bad magic") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val bytes = LtrRecordCodec.encode(LtrRecord.create(payer, testCid(1), viewId, 1000, testProof()))
            bytes[0] = 'X'.code.toByte()

            shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(bytes) }
        }

        test("decode rejects an unsupported version") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val bytes = LtrRecordCodec.encode(LtrRecord.create(payer, testCid(1), viewId, 1000, testProof()))
            bytes[4] = 99 // version byte, right after the 4-byte magic

            shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(bytes) }
        }

        test("decode rejects a truncated buffer") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val bytes = LtrRecordCodec.encode(LtrRecord.create(payer, testCid(1), viewId, 1000, testProof()))

            shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(bytes.copyOf(bytes.size / 2)) }
        }

        test("decode rejects trailing garbage after the signature") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val bytes = LtrRecordCodec.encode(LtrRecord.create(payer, testCid(1), viewId, 1000, testProof()))
            val withTrailingGarbage = bytes + byteArrayOf(1, 2, 3)

            shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(withTrailingGarbage) }
        }

        test("decode rejects an out-of-range initialValueMsat") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val bytes = LtrRecordCodec.encode(LtrRecord.create(payer, testCid(1), viewId, 1000, testProof()))

            // initialValueMsat(8 bytes, Long) starts right after magic(4)+version(1)+payer(33)+viewId(33)+cidLen(2)+cid
            val cidBytes = testCid(1).toBytes()
            val offset = 4 + 1 + 33 + 33 + 2 + cidBytes.size
            // Overwrite with a value below the 1 msat floor (0L) by zeroing all 8 bytes.
            for (i in offset until offset + 8) bytes[i] = 0

            shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(bytes) }
        }

        test("decode still rejects a genuinely unknown proofType (99)") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val bytes = LtrRecordCodec.encode(LtrRecord.create(payer, testCid(1), viewId, 1000, testProof()))

            // proofType is the single byte right after magic(4)+version(1)+payer(33)+viewId(33)+
            // cidLen(2)+cid+initialValueMsat(8)+timestampSeconds(8)+nonce(8)
            val cidBytes = testCid(1).toBytes()
            val proofTypeOffset = 4 + 1 + 33 + 33 + 2 + cidBytes.size + 8 + 8 + 8

            val neverDefined = bytes.copyOf()
            neverDefined[proofTypeOffset] = 99
            shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(neverDefined) }
        }

        test("decode accepts a well-formed type-2 (Lightning) payload - no longer rejected as unknown") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record =
                LtrRecord.create(
                    payer,
                    testCid(1),
                    viewId,
                    initialValueMsat = 1000,
                    proof = testLightningProof(),
                )

            val decoded = LtrRecordCodec.decode(LtrRecordCodec.encode(record))

            decoded shouldBe record
        }

        test("decode(encode(record)) round-trips a LightningProof record to an equal record") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record =
                LtrRecord.create(payer, testCid(2), viewId, initialValueMsat = 12345, proof = testLightningProof(7))

            val roundTripped = LtrRecordCodec.decode(LtrRecordCodec.encode(record))

            roundTripped shouldBe record
        }

        test("decode rejects an oversized declared invoiceLen for a type-2 proof BEFORE allocation") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record =
                LtrRecord.create(
                    payer,
                    testCid(1),
                    viewId,
                    initialValueMsat = 1000,
                    proof = testLightningProof(),
                )
            val bytes = LtrRecordCodec.encode(record)

            // invoiceLen(2) sits right after proofType(1)+proofLen(2)+preimage(32)+paymentHash(32) -
            // i.e. right after the fixed 66-byte proof-header prefix starting at proofBytesOffset.
            val cidBytes = testCid(1).toBytes()
            val proofBytesOffset = 4 + 1 + 33 + 33 + 2 + cidBytes.size + 8 + 8 + 8 + 1 + 2
            val invoiceLenOffset = proofBytesOffset + 32 + 32
            val oversized = LightningProof.MAX_SIGNED_INVOICE_BYTES + 1
            bytes[invoiceLenOffset] = (oversized ushr 8).toByte()
            bytes[invoiceLenOffset + 1] = oversized.toByte()

            shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(bytes) }
        }

        test("decode rejects a declared invoiceLen exceeding the actual available proof bytes") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val record =
                LtrRecord.create(
                    payer,
                    testCid(1),
                    viewId,
                    initialValueMsat = 1000,
                    proof = testLightningProof(),
                )
            val bytes = LtrRecordCodec.encode(record)

            val cidBytes = testCid(1).toBytes()
            val proofBytesOffset = 4 + 1 + 33 + 33 + 2 + cidBytes.size + 8 + 8 + 8 + 1 + 2
            val invoiceLenOffset = proofBytesOffset + 32 + 32
            // Declares one byte more than is actually present in proofBytes - still within
            // MAX_SIGNED_INVOICE_BYTES, so this exercises the "declared length vs. actual proofLen"
            // check specifically, not the DoS-guard range check above.
            val trueInvoiceLen = "lnbc1testinvoiceabc".toByteArray(Charsets.US_ASCII).size
            val declaredTooLong = trueInvoiceLen + 1
            bytes[invoiceLenOffset] = (declaredTooLong ushr 8).toByte()
            bytes[invoiceLenOffset + 1] = declaredTooLong.toByte()

            shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(bytes) }
        }

        test("decode rejects a type-2 proof payload shorter than the fixed 66-byte prefix") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            // Reuse a valid type-1 (OnChainProof) record, whose proofBytes is only 36 bytes, then
            // relabel it as type 2 (Lightning) without changing proofLen - well under the 66-byte
            // fixed prefix a type-2 payload must have before an invoiceLen field can even exist.
            val bytes = LtrRecordCodec.encode(LtrRecord.create(payer, testCid(1), viewId, 1000, testProof()))

            val cidBytes = testCid(1).toBytes()
            val proofTypeOffset = 4 + 1 + 33 + 33 + 2 + cidBytes.size + 8 + 8 + 8
            bytes[proofTypeOffset] = 2

            shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(bytes) }
        }

        test("decode rejects a wrong-length OnChainProof payload") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val bytes = LtrRecordCodec.encode(LtrRecord.create(payer, testCid(1), viewId, 1000, testProof()))

            // proofLen(2) sits right after magic(4)+version(1)+payer(33)+viewId(33)+cidLen(2)+cid+
            // initialValueMsat(8)+timestampSeconds(8)+nonce(8)+proofType(1) - declaring one byte
            // fewer than the true 36-byte OnChainProof payload must be rejected outright, not
            // silently truncated or reinterpreted.
            val cidBytes = testCid(1).toBytes()
            val proofLenOffset = 4 + 1 + 33 + 33 + 2 + cidBytes.size + 8 + 8 + 8 + 1
            val wrongLen = 35
            bytes[proofLenOffset] = (wrongLen ushr 8).toByte()
            bytes[proofLenOffset + 1] = wrongLen.toByte()

            shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(bytes) }
        }

        test("decode rejects an out-of-range outputIndex for a type-1 OnChainProof") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val validProof = testProof()
            val bytes = LtrRecordCodec.encode(LtrRecord.create(payer, testCid(1), viewId, 1000, validProof))

            // outputIndex(4, Int) is the last 4 bytes of proofBytes(36), which sit right before the
            // trailing 64-byte signature.
            val outputIndexOffset = bytes.size - 64 - 4
            val tooLarge = OnChainProof.MAX_OUTPUT_INDEX + 1
            bytes[outputIndexOffset] = (tooLarge ushr 24).toByte()
            bytes[outputIndexOffset + 1] = (tooLarge ushr 16).toByte()
            bytes[outputIndexOffset + 2] = (tooLarge ushr 8).toByte()
            bytes[outputIndexOffset + 3] = tooLarge.toByte()

            shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(bytes) }
        }

        test("decode rejects a cid whose declared length exceeds MAX_CID_BYTES") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate().publicKey
            val bytes = LtrRecordCodec.encode(LtrRecord.create(payer, testCid(1), viewId, 1000, testProof()))

            // cidLen(2) starts right after magic(4)+version(1)+payer(33)+viewId(33)
            val cidLenOffset = 4 + 1 + 33 + 33
            val tooLong = LtrRecordCodec.MAX_CID_BYTES + 1
            bytes[cidLenOffset] = (tooLong ushr 8).toByte()
            bytes[cidLenOffset + 1] = tooLong.toByte()

            shouldThrow<MalformedLtrRecordException> { LtrRecordCodec.decode(bytes) }
        }
    })
