package net.lapisphilosophorum.lapisnet.virtus

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class OnChainProofTest :
    FunSpec({
        test("a well-formed 32-byte txid and in-range outputIndex construct successfully") {
            val proof = OnChainProof(ByteArray(32) { it.toByte() }, outputIndex = 0)

            proof.btcTxid.size shouldBe 32
            proof.outputIndex shouldBe 0
        }

        test("btcTxid shorter than 32 bytes is rejected") {
            shouldThrow<IllegalArgumentException> { OnChainProof(ByteArray(31), outputIndex = 0) }
        }

        test("btcTxid longer than 32 bytes is rejected") {
            shouldThrow<IllegalArgumentException> { OnChainProof(ByteArray(33), outputIndex = 0) }
        }

        test("outputIndex boundary values 0 and MAX_OUTPUT_INDEX both construct successfully") {
            OnChainProof(ByteArray(32), outputIndex = 0).outputIndex shouldBe 0
            OnChainProof(ByteArray(32), outputIndex = OnChainProof.MAX_OUTPUT_INDEX).outputIndex shouldBe
                OnChainProof.MAX_OUTPUT_INDEX
        }

        test("a negative outputIndex is rejected") {
            shouldThrow<IllegalArgumentException> { OnChainProof(ByteArray(32), outputIndex = -1) }
        }

        test("an outputIndex beyond MAX_OUTPUT_INDEX is rejected") {
            shouldThrow<IllegalArgumentException> {
                OnChainProof(ByteArray(32), outputIndex = OnChainProof.MAX_OUTPUT_INDEX + 1)
            }
        }

        test("equals/hashCode compare by content, not by reference") {
            val txid = ByteArray(32) { (it * 3).toByte() }
            val a = OnChainProof(txid, outputIndex = 5)
            val b = OnChainProof(txid.copyOf(), outputIndex = 5)

            (a === b) shouldBe false
            a shouldBe b
            a.hashCode() shouldBe b.hashCode()
        }

        test("proofs differing in txid or outputIndex are not equal") {
            val txid = ByteArray(32) { it.toByte() }
            val base = OnChainProof(txid, outputIndex = 0)
            val differentIndex = OnChainProof(txid, outputIndex = 1)
            val differentTxid = OnChainProof(ByteArray(32) { (it + 1).toByte() }, outputIndex = 0)

            base shouldNotBe differentIndex
            base shouldNotBe differentTxid
        }

        test("btcTxid returns a defensive copy - mutating the returned array does not affect the proof") {
            val txid = ByteArray(32) { it.toByte() }
            val proof = OnChainProof(txid, outputIndex = 0)

            val returned = proof.btcTxid
            returned[0] = (returned[0] + 1).toByte()

            proof.btcTxid[0] shouldBe txid[0]
        }
    })
