package net.lapisphilosophorum.lapisnet.virtus

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Chain
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.Feature
import fr.acinq.lightning.FeatureSupport
import fr.acinq.lightning.Features
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.payment.Bolt11Invoice
import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import java.security.MessageDigest
import java.security.SecureRandom

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

/** File-local hex decode - see [LightningProofVerifier]'s own `toLightningHex()` doc comment on
 * why this codebase keeps a separate, non-shared hex helper per file rather than a shared one. */
private fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "hex string must have an even length" }
    return ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
}

/** Minimal BOLT-11 feature set every real invoice needs (see [Bolt11Invoice]'s own `init` block -
 * both are required or the invoice fails to even construct). */
private val INVOICE_FEATURES =
    Features(
        mapOf(
            Feature.VariableLengthOnion to FeatureSupport.Mandatory,
            Feature.PaymentSecret to FeatureSupport.Mandatory,
        ),
    )

private fun signedInvoice(
    signerPrivateKeyBytes: ByteArray,
    paymentHash: ByteArray,
    amountMsat: Long?,
    description: Either<String, ByteVector32>,
    expirySeconds: Long? = null,
    timestampSeconds: Long = System.currentTimeMillis() / 1000,
): String =
    Bolt11Invoice
        .create(
            chain = Chain.Mainnet,
            amount = amountMsat?.let { MilliSatoshi(it) },
            paymentHash = ByteVector32(paymentHash),
            privateKey = PrivateKey(signerPrivateKeyBytes),
            description = description,
            minFinalCltvExpiryDelta = Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA,
            features = INVOICE_FEATURES,
            expirySeconds = expirySeconds,
            timestampSeconds = timestampSeconds,
        ).write()

/**
 * A complete, real, in-process-generated valid Lightning proof tuple - every field's actual
 * cryptography (sha256 preimage->hash, a real signed BOLT-11 invoice via `lightning-kmp`) is real;
 * nothing here is mocked or faked. The SAME 32-byte secp256k1 scalar is deliberately used as both
 * the Lapis [viewId] keypair and the ACINQ Lightning node private key that signs [invoice] - this
 * is what makes [LightningProofVerifier]'s mandatory recipient-binding check
 * (`invoice.nodeId == viewId`) hold for this fixture.
 */
private class ValidTuple {
    val payer: Secp256k1KeyPair = Secp256k1KeyPair.generate()
    val viewId: Secp256k1KeyPair = Secp256k1KeyPair.generate()
    val cid: Cid = testCid(1)
    val amountMsat: Long = 5_000_000L
    val preimage: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
    val paymentHash: ByteArray = sha256(preimage)
    val memo: String = LightningProofVerifier.canonicalMemo(cid, viewId.publicKey)

    val invoice: String =
        signedInvoice(
            signerPrivateKeyBytes = viewId.privateKey.bytes,
            paymentHash = paymentHash,
            amountMsat = amountMsat,
            description = Either.Left(memo),
        )

    val proof: LightningProof = LightningProof(preimage, paymentHash, invoice)

    val record: LtrRecord = LtrRecord.create(payer, cid, viewId.publicKey, initialValueMsat = amountMsat, proof = proof)
}

class LightningProofVerifierTest :
    FunSpec({
        test("a fully valid tuple verifies true") {
            val tuple = ValidTuple()

            LightningProofVerifier.verify(tuple.record, tuple.proof) shouldBe true
        }

        test("a corrupted preimage (sha256 mismatch) is rejected") {
            val tuple = ValidTuple()
            val corruptPreimage = tuple.preimage.copyOf().also { it[0] = (it[0] + 1).toByte() }
            val corruptProof = LightningProof(corruptPreimage, tuple.paymentHash, tuple.invoice)

            LightningProofVerifier.verify(tuple.record, corruptProof) shouldBe false
        }

        test("a corrupted stored payment hash is rejected") {
            val tuple = ValidTuple()
            val corruptHash = tuple.paymentHash.copyOf().also { it[0] = (it[0] + 1).toByte() }
            val corruptProof = LightningProof(tuple.preimage, corruptHash, tuple.invoice)

            LightningProofVerifier.verify(tuple.record, corruptProof) shouldBe false
        }

        test("an invoice signed by a different key than viewId is rejected (recipient binding)") {
            val tuple = ValidTuple()
            val otherKey = Secp256k1KeyPair.generate()
            val wrongSignerInvoice =
                signedInvoice(
                    signerPrivateKeyBytes = otherKey.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = tuple.amountMsat,
                    description = Either.Left(tuple.memo),
                )
            val proof = LightningProof(tuple.preimage, tuple.paymentHash, wrongSignerInvoice)

            LightningProofVerifier.verify(tuple.record, proof) shouldBe false
        }

        test("an invoice amount different from record.initialValueMsat is rejected") {
            val tuple = ValidTuple()
            val differentAmountInvoice =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.viewId.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = tuple.amountMsat + 1,
                    description = Either.Left(tuple.memo),
                )
            val proof = LightningProof(tuple.preimage, tuple.paymentHash, differentAmountInvoice)

            LightningProofVerifier.verify(tuple.record, proof) shouldBe false
        }

        test("an amountless invoice is rejected") {
            val tuple = ValidTuple()
            val amountlessInvoice =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.viewId.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = null,
                    description = Either.Left(tuple.memo),
                )
            val proof = LightningProof(tuple.preimage, tuple.paymentHash, amountlessInvoice)

            LightningProofVerifier.verify(tuple.record, proof) shouldBe false
        }

        test("an invoice whose own embedded payment hash differs from proof.paymentHash is rejected") {
            val tuple = ValidTuple()
            val otherPaymentHash = sha256(ByteArray(32) { (it + 9).toByte() })
            val invoiceWithDifferentHash =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.viewId.privateKey.bytes,
                    paymentHash = otherPaymentHash,
                    amountMsat = tuple.amountMsat,
                    description = Either.Left(tuple.memo),
                )
            // proof still claims tuple.preimage/tuple.paymentHash - the invoice's OWN embedded
            // payment hash (otherPaymentHash) is what must mismatch here.
            val proof = LightningProof(tuple.preimage, tuple.paymentHash, invoiceWithDifferentHash)

            LightningProofVerifier.verify(tuple.record, proof) shouldBe false
        }

        test("a memo not matching canonicalMemo(cid, viewId) is rejected - cross-cid replay") {
            val tuple = ValidTuple()
            val otherCidMemo = LightningProofVerifier.canonicalMemo(testCid(2), tuple.viewId.publicKey)
            val replayInvoice =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.viewId.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = tuple.amountMsat,
                    description = Either.Left(otherCidMemo),
                )
            val proof = LightningProof(tuple.preimage, tuple.paymentHash, replayInvoice)

            LightningProofVerifier.verify(tuple.record, proof) shouldBe false
        }

        test("a garbage signedInvoice string is rejected, not thrown") {
            val tuple = ValidTuple()
            val proof = LightningProof(tuple.preimage, tuple.paymentHash, "not-an-invoice")

            LightningProofVerifier.verify(tuple.record, proof) shouldBe false
        }

        test("an invoice using descriptionHash instead of description is rejected") {
            val tuple = ValidTuple()
            val descriptionHashInvoice =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.viewId.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = tuple.amountMsat,
                    description = Either.Right(ByteVector32(sha256(tuple.memo.toByteArray(Charsets.UTF_8)))),
                )
            val proof = LightningProof(tuple.preimage, tuple.paymentHash, descriptionHashInvoice)

            LightningProofVerifier.verify(tuple.record, proof) shouldBe false
        }

        // Deliberate: expiry is NEVER checked (see LightningProofVerifier.verify's doc comment) -
        // a settled payment's invoice may legitimately be past its own BOLT-11 expiry by the time
        // the record propagates through gossip; the payment already happened by then.
        test("an already-expired invoice still verifies true") {
            val tuple = ValidTuple()
            val expiredInvoice =
                signedInvoice(
                    signerPrivateKeyBytes = tuple.viewId.privateKey.bytes,
                    paymentHash = tuple.paymentHash,
                    amountMsat = tuple.amountMsat,
                    description = Either.Left(tuple.memo),
                    expirySeconds = 1L,
                    timestampSeconds = 1L,
                )
            val proof = LightningProof(tuple.preimage, tuple.paymentHash, expiredInvoice)

            LightningProofVerifier.verify(tuple.record, proof) shouldBe true
        }

        // --- Security-audit finding: external BOLT-11 interop ------------------------------------
        // Every test above (and in LightningProofTest.kt) generates AND parses invoices using this
        // project's own in-process lightning-kmp/bitcoin-kmp combination - self-consistent by
        // construction, but proving nothing about whether the version-bumped bitcoin-kmp (0.31.0,
        // force-pinned over lightning-kmp 1.8.4's own transitive pin of 0.20.0 - see
        // gradle/libs.versions.toml's comment) still correctly parses and verifies the ECDSA
        // signature of an invoice signed by a genuinely INDEPENDENT implementation. This test
        // hardcodes a real BOLT-11 spec test vector - published in the spec itself
        // (https://github.com/lightning/bolts/blob/master/11-payment-encoding.md#examples), signed
        // with a fixed, publicly-known test private key, NOT generated by this project's own code -
        // and asserts it parses successfully with the expected payment hash, amount, node id, and
        // description. This is real evidence of interop, independent of this project's own signing
        // path (deliberately calls Bolt11Invoice.read directly, not LightningProofVerifier.verify,
        // since verify also checks this record's own canonicalMemo binding, which an externally-
        // authored spec vector was never signed against).
        test("a real, externally-signed BOLT-11 spec test vector parses with the expected fields") {
            // "Please send $3 for a cup of coffee to the same peer, within one minute" - the BOLT-11
            // spec's own worked example. Every example invoice in that section of the spec is signed
            // with the same fixed key, priv_key=e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734,
            // whose corresponding node id is 03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad
            // (stated explicitly in the spec's first example's own title) - this invoice carries no
            // explicit `n` field, so a correct parse also exercises real ECDSA public-key recovery
            // from the signature, not just a plain signature-verify.
            val specInvoice =
                "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqc" +
                    "yq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla20" +
                    "87ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh"
            val expectedNodeId = hexToBytes("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad")
            val expectedPaymentHash = hexToBytes("0001020304050607080900010203040506070809000102030405060708090102")
            // 2500 micro-BTC = 0.0025 BTC = 250,000 sat = 250,000,000 msat.
            val expectedAmountMsat = 250_000_000L

            val parsed = Bolt11Invoice.read(specInvoice)

            parsed.isSuccess shouldBe true
            val invoice = parsed.get()
            invoice.amount shouldBe MilliSatoshi(expectedAmountMsat)
            invoice.paymentHash.toByteArray().contentEquals(expectedPaymentHash) shouldBe true
            invoice.nodeId.value
                .toByteArray()
                .contentEquals(expectedNodeId) shouldBe true
            invoice.description shouldBe "1 cup coffee"
        }
    })
