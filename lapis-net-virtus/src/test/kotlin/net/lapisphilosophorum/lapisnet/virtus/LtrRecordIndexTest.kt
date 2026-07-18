package net.lapisphilosophorum.lapisnet.virtus

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testProof(seed: Byte = 1): OnChainProof = OnChainProof(ByteArray(32) { seed }, outputIndex = 0)

private fun record(
    cid: Cid,
    viewId: net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey,
    initialValueMsat: Long = 1000,
): LtrRecord {
    val payer = Secp256k1KeyPair.generate()
    return LtrRecord.create(payer, cid, viewId, initialValueMsat, testProof())
}

class LtrRecordIndexTest :
    FunSpec({
        test("add returns true for a new record, false for the same record added again") {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val cid = testCid(1)
            val r = record(cid, viewId)
            val index = LtrRecordIndex()

            index.add(r) shouldBe true
            index.add(r) shouldBe false
            index.recordsFor(cid, viewId) shouldBe listOf(r)
        }

        test("add rejects a signature-tampered record and never throws") {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val cid = testCid(1)
            val r = record(cid, viewId)
            val bytes = LtrRecordCodec.encode(r)
            bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the signature
            val tampered = LtrRecordCodec.decode(bytes)
            val index = LtrRecordIndex()

            index.add(tampered) shouldBe false
            index.allPairs() shouldBe emptySet()
        }

        test("two records for different (cid, viewId) pairs are both tracked independently") {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val cidA = testCid(1)
            val cidB = testCid(2)
            val rA = record(cidA, viewId)
            val rB = record(cidB, viewId)
            val index = LtrRecordIndex()

            index.add(rA) shouldBe true
            index.add(rB) shouldBe true
            index.recordsFor(cidA, viewId) shouldBe listOf(rA)
            index.recordsFor(cidB, viewId) shouldBe listOf(rB)
            index.allPairs() shouldBe setOf(cidA to viewId, cidB to viewId)
        }

        test(
            "multiple independent records for the SAME (cid, viewId) pair are ALL tracked - " +
                "never resolved down to one winner, unlike VeritasGrantIndex",
        ) {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val cid = testCid(1)
            val r1 = record(cid, viewId, initialValueMsat = 100)
            val r2 = record(cid, viewId, initialValueMsat = 200)
            val r3 = record(cid, viewId, initialValueMsat = 300)
            val index = LtrRecordIndex()

            index.add(r1) shouldBe true
            index.add(r2) shouldBe true
            index.add(r3) shouldBe true

            index.recordsFor(cid, viewId) shouldBe listOf(r1, r2, r3)
        }

        test("recordsFor an unknown pair returns an empty list") {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val cid = testCid(1)
            val index = LtrRecordIndex()

            index.recordsFor(cid, viewId) shouldBe emptyList()
        }

        // --- Eviction once MAX_TRACKED_RECORDS is exceeded ------------------------------------

        test("MAX_TRACKED_RECORDS cap does not reject - it evicts the oldest tracked entry") {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val cids = (1..3).map { testCid(it.toByte()) }
            val index = LtrRecordIndex(maxTracked = 2, maxPersisted = 10)

            val r0 = record(cids[0], viewId, 100)
            val r1 = record(cids[1], viewId, 200)
            val r2 = record(cids[2], viewId, 300)

            index.add(r0) shouldBe true
            index.add(r1) shouldBe true
            index.add(r2) shouldBe true
            index.allPairs().size shouldBe 2

            index.recordsFor(cids[0], viewId) shouldBe emptyList()
            index.allPairs() shouldBe setOf(cids[1] to viewId, cids[2] to viewId)
            index.recordsFor(cids[1], viewId) shouldBe listOf(r1)
            index.recordsFor(cids[2], viewId) shouldBe listOf(r2)
        }

        // --- canAccept: cheap, non-mutating admission pre-check --------------------------------

        test("canAccept returns true for a not-yet-tracked record, under cap") {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val r = record(testCid(1), viewId)
            val index = LtrRecordIndex()

            index.canAccept(r) shouldBe true
        }

        test("canAccept returns false for a record already tracked by content id") {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val r = record(testCid(1), viewId)
            val index = LtrRecordIndex()
            index.add(r) shouldBe true

            index.canAccept(r) shouldBe false
        }

        test("canAccept returns true even when the index is at capacity - a full index evicts, it never rejects") {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val cids = (1..2).map { testCid(it.toByte()) }
            val index = LtrRecordIndex(maxTracked = 2, maxPersisted = 10)
            index.add(record(cids[0], viewId, 100)) shouldBe true
            index.add(record(cids[1], viewId, 200)) shouldBe true

            val newRecord = record(testCid(3), viewId, 300)

            index.canAccept(newRecord) shouldBe true
        }

        // --- tryReservePersistence: separate, non-evicting cap ----------------------------------

        test("tryReservePersistence succeeds for a new content id under the persistence cap") {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val r = record(testCid(1), viewId)
            val index = LtrRecordIndex(maxTracked = 10, maxPersisted = 2)

            index.tryReservePersistence(r) shouldBe true
        }

        test("tryReservePersistence fails once the persistence cap is reached, and stays failing - it does not evict") {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val cids = (1..3).map { testCid(it.toByte()) }
            val index = LtrRecordIndex(maxTracked = 10, maxPersisted = 2)

            val r0 = record(cids[0], viewId, 100)
            val r1 = record(cids[1], viewId, 200)
            val r2 = record(cids[2], viewId, 300)

            index.tryReservePersistence(r0) shouldBe true
            index.tryReservePersistence(r1) shouldBe true
            index.tryReservePersistence(r2) shouldBe false

            val r3 = record(testCid(4), viewId, 400)
            index.tryReservePersistence(r3) shouldBe false
        }

        test(
            "tryReservePersistence is idempotent - calling it again for an already-reserved content id " +
                "succeeds without consuming a second slot",
        ) {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val r0 = record(testCid(1), viewId, 100)
            val index = LtrRecordIndex(maxTracked = 10, maxPersisted = 1)

            index.tryReservePersistence(r0) shouldBe true
            repeat(5) { index.tryReservePersistence(r0) shouldBe true }

            val r1 = record(testCid(2), viewId, 200)
            index.tryReservePersistence(r1) shouldBe false
        }

        test(
            "tryReservePersistence and the in-memory tracking cap are independent - " +
                "a low persistence cap does not stop the index from tracking more records",
        ) {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val cids = (1..3).map { testCid(it.toByte()) }
            val index = LtrRecordIndex(maxTracked = 10, maxPersisted = 1)

            val r0 = record(cids[0], viewId, 100)
            val r1 = record(cids[1], viewId, 200)
            val r2 = record(cids[2], viewId, 300)

            index.tryReservePersistence(r0) shouldBe true
            index.tryReservePersistence(r1) shouldBe false
            index.tryReservePersistence(r2) shouldBe false

            index.add(r0) shouldBe true
            index.add(r1) shouldBe true
            index.add(r2) shouldBe true
            index.allPairs().size shouldBe 3
        }
    })
