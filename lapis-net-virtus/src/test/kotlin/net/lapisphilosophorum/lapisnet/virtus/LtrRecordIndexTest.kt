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
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

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

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

private val INVOICE_FEATURES =
    Features(
        mapOf(
            Feature.VariableLengthOnion to FeatureSupport.Mandatory,
            Feature.PaymentSecret to FeatureSupport.Mandatory,
        ),
    )

/** A real, cryptographically valid [LightningProof] for `(cid, viewId)` - file-local, mirrors
 * [LtrGossipOnGossipMessageTest]'s identically-purposed private helper (no shared test-fixture
 * helper exists in this codebase for this - see that file's own doc comment convention). */
private fun lightningProof(
    cid: Cid,
    viewId: Secp256k1KeyPair,
    amountMsat: Long,
): LightningProof {
    val preimage = ByteArray(32).also { SecureRandom().nextBytes(it) }
    val paymentHash = sha256(preimage)
    val memo = LightningProofVerifier.canonicalMemo(cid, viewId.publicKey)
    val invoice =
        Bolt11Invoice
            .create(
                chain = Chain.Mainnet,
                amount = MilliSatoshi(amountMsat),
                paymentHash = ByteVector32(paymentHash),
                privateKey = PrivateKey(viewId.privateKey.bytes),
                description = Either.Left(memo),
                minFinalCltvExpiryDelta = Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA,
                features = INVOICE_FEATURES,
            ).write()
    return LightningProof(preimage, paymentHash, invoice)
}

private fun lightningRecord(
    payer: Secp256k1KeyPair,
    cid: Cid,
    viewId: Secp256k1KeyPair,
    proof: LightningProof,
    initialValueMsat: Long,
): LtrRecord = LtrRecord.create(payer, cid, viewId.publicKey, initialValueMsat, proof)

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

        // --- C1 fix: hasLightningPaymentBeenUsed / canAccept's Lightning payment-hash dedup ----

        test("hasLightningPaymentBeenUsed returns false when no record for the pair is tracked yet") {
            val viewId = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val index = LtrRecordIndex()

            index.hasLightningPaymentBeenUsed(cid, viewId.publicKey, ByteArray(32) { 1 }) shouldBe false
        }

        test(
            "hasLightningPaymentBeenUsed returns true once a tracked record for the pair carries that exact " +
                "payment hash",
        ) {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val proof = lightningProof(cid, viewId, amountMsat = 1000)
            val r = lightningRecord(payer, cid, viewId, proof, initialValueMsat = 1000)
            val index = LtrRecordIndex()
            index.add(r) shouldBe true

            index.hasLightningPaymentBeenUsed(cid, viewId.publicKey, proof.paymentHash) shouldBe true
        }

        test("hasLightningPaymentBeenUsed returns false for a different payment hash on the same pair") {
            val payer = Secp256k1KeyPair.generate()
            val viewId = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val proof = lightningProof(cid, viewId, amountMsat = 1000)
            val r = lightningRecord(payer, cid, viewId, proof, initialValueMsat = 1000)
            val index = LtrRecordIndex()
            index.add(r) shouldBe true

            index.hasLightningPaymentBeenUsed(cid, viewId.publicKey, ByteArray(32) { 9 }) shouldBe false
        }

        test("hasLightningPaymentBeenUsed ignores an OnChainProof record even with a matching byte pattern") {
            // OnChainProof has no paymentHash concept at all - a tracked OnChainProof record must
            // never be mistaken for a Lightning-proof record when checking payment-hash reuse.
            val viewId = Secp256k1KeyPair.generate().publicKey
            val cid = testCid(1)
            val r = record(cid, viewId)
            val index = LtrRecordIndex()
            index.add(r) shouldBe true

            index.hasLightningPaymentBeenUsed(cid, viewId, ByteArray(32) { 1 }) shouldBe false
        }

        test(
            "canAccept returns false for a NEW record (different content id) whose LightningProof reuses an " +
                "already-tracked payment hash for the same (cid, viewId) - the C1 double-counting fix",
        ) {
            val viewId = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val proof = lightningProof(cid, viewId, amountMsat = 2000)
            val index = LtrRecordIndex()
            val first = lightningRecord(Secp256k1KeyPair.generate(), cid, viewId, proof, initialValueMsat = 2000)
            index.add(first) shouldBe true

            // A second, independently-signed record (different payer, fresh nonce - so a different
            // content id) built around the SAME proof - exactly the exploit shape.
            val second = lightningRecord(Secp256k1KeyPair.generate(), cid, viewId, proof, initialValueMsat = 2000)
            first.contentId().contentEquals(second.contentId()) shouldBe false

            index.canAccept(second) shouldBe false
        }

        test("canAccept returns true for a NEW record whose LightningProof has a fresh, unused payment hash") {
            val viewId = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val index = LtrRecordIndex()
            val first =
                lightningRecord(
                    Secp256k1KeyPair.generate(),
                    cid,
                    viewId,
                    lightningProof(cid, viewId, amountMsat = 2000),
                    initialValueMsat = 2000,
                )
            index.add(first) shouldBe true

            val second =
                lightningRecord(
                    Secp256k1KeyPair.generate(),
                    cid,
                    viewId,
                    lightningProof(cid, viewId, amountMsat = 2000),
                    initialValueMsat = 2000,
                )

            index.canAccept(second) shouldBe true
        }

        // --- isTrackedByContentId: the content-id-only half canAccept relies on, exposed separately
        // so LtrGossip.announce can distinguish "already-accepted, harmless re-send" from "new" ---

        test("isTrackedByContentId returns false for a not-yet-tracked record, true once added") {
            val viewId = Secp256k1KeyPair.generate().publicKey
            val r = record(testCid(1), viewId)
            val index = LtrRecordIndex()

            index.isTrackedByContentId(r) shouldBe false
            index.add(r) shouldBe true
            index.isTrackedByContentId(r) shouldBe true
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

        // --- Round-2 atomicity fix: add() is the sole authoritative gate for the payment-hash
        // nullifier, not just canAccept()/hasLightningPaymentBeenUsed() -------------------------

        test(
            "add rejects a NEW record (different content id) whose LightningProof reuses an already-tracked " +
                "payment hash for the same (cid, viewId) - add() itself is now the atomic gate, not just canAccept",
        ) {
            val viewId = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val proof = lightningProof(cid, viewId, amountMsat = 2000)
            val index = LtrRecordIndex()
            val first = lightningRecord(Secp256k1KeyPair.generate(), cid, viewId, proof, initialValueMsat = 2000)
            index.add(first) shouldBe true

            val second = lightningRecord(Secp256k1KeyPair.generate(), cid, viewId, proof, initialValueMsat = 2000)
            first.contentId().contentEquals(second.contentId()) shouldBe false

            // Rejected by add() directly - no canAccept()/hasLightningPaymentBeenUsed() pre-check
            // consulted here at all, proving add() enforces the invariant on its own.
            index.add(second) shouldBe false
            index.recordsFor(cid, viewId.publicKey) shouldBe listOf(first)
        }

        test(
            "CONCURRENCY: N threads racing index.add() with distinct content ids sharing one Lightning payment " +
                "hash - exactly one must succeed, never zero, never more than one",
        ) {
            // Adversarial concurrency test for the round-2 CRITICAL finding: the payment-hash
            // check-then-act used to be split across two separate @Synchronized lock acquisitions
            // (a read-only pre-check, then a separate add() mutation), so N concurrent callers could
            // all pass the pre-check before any of them committed, then all successfully add() a
            // distinct-content-id record backed by the SAME real payment - unbounded weight from one
            // payment. This test proves add() alone is now atomic: every thread calls ONLY
            // index.add(record) directly (no pre-check at all), released simultaneously via a
            // CyclicBarrier (not a loop that might accidentally serialize on scheduling), and across
            // a high thread count exactly one must win.
            repeat(10) { run ->
                val payer = Secp256k1KeyPair.generate()
                val viewId = Secp256k1KeyPair.generate()
                val cid = testCid((run + 1).toByte())
                val amountMsat = 5_000_000L
                val sharedProof = lightningProof(cid, viewId, amountMsat)
                val threadCount = 32

                // Distinct content ids: LtrRecord.create draws a fresh nonce every call even with an
                // identical payer/cid/viewId/proof, exactly mirroring what a real fresh-nonce replay
                // of POST /api/ltr/lightning would produce.
                val records =
                    (1..threadCount).map {
                        lightningRecord(payer, cid, viewId, sharedProof, initialValueMsat = amountMsat)
                    }
                records.map { it.contentId().toList() }.toSet().size shouldBe threadCount

                val index = LtrRecordIndex()
                val barrier = CyclicBarrier(threadCount)
                val executor = Executors.newFixedThreadPool(threadCount)
                try {
                    val futures =
                        records.map { record ->
                            executor.submit<Boolean> {
                                barrier.await() // force every thread to be ready, then release together
                                index.add(record)
                            }
                        }
                    val results = futures.map { it.get(30, TimeUnit.SECONDS) }

                    results.count { it } shouldBe 1
                    index.recordsFor(cid, viewId.publicKey).size shouldBe 1
                } finally {
                    executor.shutdown()
                    executor.awaitTermination(10, TimeUnit.SECONDS)
                }
            }
        }
    })
