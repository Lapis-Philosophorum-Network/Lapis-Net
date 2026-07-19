package net.lapisphilosophorum.lapisnet.virtus

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

private fun testInvoice(length: Int): String = "a".repeat(length)

class LightningProofTest :
    FunSpec({
        test("a well-formed 32-byte preimage, 32-byte paymentHash, and non-empty invoice construct successfully") {
            val proof =
                LightningProof(ByteArray(32) { it.toByte() }, ByteArray(32) { (it + 1).toByte() }, "lnbc1invoice")

            proof.preimage.size shouldBe 32
            proof.paymentHash.size shouldBe 32
            proof.signedInvoice shouldBe "lnbc1invoice"
        }

        test("preimage shorter than 32 bytes is rejected") {
            shouldThrow<IllegalArgumentException> { LightningProof(ByteArray(31), ByteArray(32), "lnbc1x") }
        }

        test("preimage longer than 32 bytes is rejected") {
            shouldThrow<IllegalArgumentException> { LightningProof(ByteArray(33), ByteArray(32), "lnbc1x") }
        }

        test("paymentHash shorter than 32 bytes is rejected") {
            shouldThrow<IllegalArgumentException> { LightningProof(ByteArray(32), ByteArray(31), "lnbc1x") }
        }

        test("paymentHash longer than 32 bytes is rejected") {
            shouldThrow<IllegalArgumentException> { LightningProof(ByteArray(32), ByteArray(33), "lnbc1x") }
        }

        test("an empty signedInvoice is rejected") {
            shouldThrow<IllegalArgumentException> { LightningProof(ByteArray(32), ByteArray(32), "") }
        }

        test("a signedInvoice longer than MAX_SIGNED_INVOICE_BYTES is rejected") {
            shouldThrow<IllegalArgumentException> {
                LightningProof(ByteArray(32), ByteArray(32), testInvoice(LightningProof.MAX_SIGNED_INVOICE_BYTES + 1))
            }
        }

        test("a signedInvoice at exactly MAX_SIGNED_INVOICE_BYTES is accepted") {
            val proof =
                LightningProof(ByteArray(32), ByteArray(32), testInvoice(LightningProof.MAX_SIGNED_INVOICE_BYTES))

            proof.signedInvoice.length shouldBe LightningProof.MAX_SIGNED_INVOICE_BYTES
        }

        test("preimage returns a defensive copy - mutating the returned array does not affect the proof") {
            val preimage = ByteArray(32) { it.toByte() }
            val proof = LightningProof(preimage, ByteArray(32), "lnbc1x")

            val returned = proof.preimage
            returned[0] = (returned[0] + 1).toByte()

            proof.preimage[0] shouldBe preimage[0]
        }

        test("paymentHash returns a defensive copy - mutating the returned array does not affect the proof") {
            val paymentHash = ByteArray(32) { it.toByte() }
            val proof = LightningProof(ByteArray(32), paymentHash, "lnbc1x")

            val returned = proof.paymentHash
            returned[0] = (returned[0] + 1).toByte()

            proof.paymentHash[0] shouldBe paymentHash[0]
        }

        test("equals/hashCode compare by content, not by reference") {
            val preimage = ByteArray(32) { (it * 3).toByte() }
            val paymentHash = ByteArray(32) { (it * 5).toByte() }
            val a = LightningProof(preimage, paymentHash, "lnbc1same")
            val b = LightningProof(preimage.copyOf(), paymentHash.copyOf(), "lnbc1same")

            (a === b) shouldBe false
            a shouldBe b
            a.hashCode() shouldBe b.hashCode()
        }

        test("proofs differing in preimage, paymentHash, or signedInvoice are not equal") {
            val preimage = ByteArray(32) { it.toByte() }
            val paymentHash = ByteArray(32) { (it + 1).toByte() }
            val base = LightningProof(preimage, paymentHash, "lnbc1base")
            val differentPreimage = LightningProof(ByteArray(32) { (it + 2).toByte() }, paymentHash, "lnbc1base")
            val differentPaymentHash = LightningProof(preimage, ByteArray(32) { (it + 3).toByte() }, "lnbc1base")
            val differentInvoice = LightningProof(preimage, paymentHash, "lnbc1different")

            base shouldNotBe differentPreimage
            base shouldNotBe differentPaymentHash
            base shouldNotBe differentInvoice
        }
    })
