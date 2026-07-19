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
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

private val INVOICE_FEATURES =
    Features(
        mapOf(
            Feature.VariableLengthOnion to FeatureSupport.Mandatory,
            Feature.PaymentSecret to FeatureSupport.Mandatory,
        ),
    )

/** A real, cryptographically valid [LightningProof] for `(cid, viewId)` - mirrors
 * [LtrGossipOnGossipMessageTest]'s identically-named private helper (file-local, not shared - see
 * this codebase's established no-shared-test-helper convention for small fixtures like this). */
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

/**
 * Regression coverage for the C1 security fix on the LOCAL self-announce path
 * ([LtrGossip.announce]) - mirrors the exploit `POST /api/ltr/lightning` would otherwise allow: a
 * single real Lightning payment resubmitted as a fresh [LtrRecord] (a new nonce every
 * [LtrRecord.create] call, exactly what that route does per request) must not accumulate more than
 * one accepted record's worth of weight. See [LtrGossipOnGossipMessageTest] for the equivalent
 * gossip-receipt-path regression coverage.
 */
class LtrGossipAnnounceTest :
    FunSpec({
        test(
            "announcing the same Lightning payment twice (fresh nonce/content id each time) is declined the " +
                "second time - weight reflects only the first accepted record",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-announce-dup"))
                val pubsub = GossipPubSub.attach(node)
                val ltr = LtrGossip.attach(pubsub, storage)
                try {
                    val payer = identity.secp256k1KeyPair
                    val viewId = Secp256k1KeyPair.generate()
                    val cid = testCid(1)
                    val amountMsat = 3_000_000L
                    val proof = lightningProof(cid, viewId, amountMsat)

                    // Two INDEPENDENT LtrRecords built from the SAME (preimage, signedInvoice) pair -
                    // exactly what two calls to POST /api/ltr/lightning with an identical request
                    // body produce: LtrRecord.create draws a fresh nonce every call, so these have
                    // different content ids despite sharing the identical LightningProof.
                    val first =
                        LtrRecord.create(payer, cid, viewId.publicKey, initialValueMsat = amountMsat, proof = proof)
                    val second =
                        LtrRecord.create(payer, cid, viewId.publicKey, initialValueMsat = amountMsat, proof = proof)
                    first.contentId().contentEquals(second.contentId()) shouldBe false

                    val firstAccepted = ltr.announce(first)
                    val secondAccepted = ltr.announce(second)

                    firstAccepted shouldBe true
                    secondAccepted shouldBe false
                    ltr.currentRecords(cid, viewId.publicKey) shouldBe listOf(first)
                    ltr.currentWeight(cid, viewId.publicKey, atEpochSeconds = first.timestampSeconds) shouldBe
                        LtrWeightCalculator.decayedWeightMsat(first, first.timestampSeconds)
                } finally {
                    ltr.stop()
                    pubsub.stop()
                }
            } finally {
                runCatching { node.stop() }
            }
        }

        test(
            "re-announcing the exact SAME already-accepted record (identical content id) still succeeds - " +
                "retry-for-delivery-reliability semantics are preserved, not broken by the C1 fix",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-announce-retry"))
                val pubsub = GossipPubSub.attach(node)
                val ltr = LtrGossip.attach(pubsub, storage)
                try {
                    val payer = identity.secp256k1KeyPair
                    val viewId = Secp256k1KeyPair.generate()
                    val cid = testCid(1)
                    val amountMsat = 3_000_000L
                    val proof = lightningProof(cid, viewId, amountMsat)
                    val record =
                        LtrRecord.create(payer, cid, viewId.publicKey, initialValueMsat = amountMsat, proof = proof)

                    // The identical record object/bytes, announced three times in a row - the
                    // real-world pattern TwoNodeLtrGossipIntegrationTest/LtrAccumulationIntegrationTest
                    // rely on to work around gossip-mesh warm-up delivery flakiness.
                    val results = (1..3).map { ltr.announce(record) }

                    results shouldBe listOf(true, true, true)
                    // Still only ONE tracked record and ONE unit of weight - re-announcing the same
                    // record never doubles it.
                    ltr.currentRecords(cid, viewId.publicKey) shouldBe listOf(record)
                    ltr.currentWeight(cid, viewId.publicKey, atEpochSeconds = record.timestampSeconds) shouldBe
                        LtrWeightCalculator.decayedWeightMsat(record, record.timestampSeconds)
                } finally {
                    ltr.stop()
                    pubsub.stop()
                }
            } finally {
                runCatching { node.stop() }
            }
        }

        test(
            "two DIFFERENT genuine Lightning payments for the same (cid, viewId) both get accepted and their " +
                "weights sum normally",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-announce-two-real"))
                val pubsub = GossipPubSub.attach(node)
                val ltr = LtrGossip.attach(pubsub, storage)
                try {
                    val payer = identity.secp256k1KeyPair
                    val viewId = Secp256k1KeyPair.generate()
                    val cid = testCid(1)
                    val amountMsat = 1_000_000L
                    val firstProof = lightningProof(cid, viewId, amountMsat)
                    val secondProof = lightningProof(cid, viewId, amountMsat)
                    firstProof.paymentHash.contentEquals(secondProof.paymentHash) shouldBe false

                    val firstRecord =
                        LtrRecord.create(
                            payer,
                            cid,
                            viewId.publicKey,
                            initialValueMsat = amountMsat,
                            proof = firstProof,
                        )
                    val secondRecord =
                        LtrRecord.create(
                            payer,
                            cid,
                            viewId.publicKey,
                            initialValueMsat = amountMsat,
                            proof = secondProof,
                        )

                    ltr.announce(firstRecord) shouldBe true
                    ltr.announce(secondRecord) shouldBe true

                    ltr.currentRecords(cid, viewId.publicKey) shouldBe listOf(firstRecord, secondRecord)
                    ltr.currentWeight(cid, viewId.publicKey, atEpochSeconds = firstRecord.timestampSeconds) shouldBe
                        LtrWeightCalculator.decayedWeightMsat(firstRecord, firstRecord.timestampSeconds) +
                        LtrWeightCalculator.decayedWeightMsat(secondRecord, secondRecord.timestampSeconds)
                } finally {
                    ltr.stop()
                    pubsub.stop()
                }
            } finally {
                runCatching { node.stop() }
            }
        }

        test(
            "CONCURRENCY: N threads calling ltr.announce() with fresh-nonce records sharing one Lightning payment " +
                "hash (the POST /api/ltr/lightning exploit shape) - exactly one must be accepted",
        ) {
            // Adversarial concurrency test for the round-2 CRITICAL finding at the actual call site
            // the exploit targets: firing N concurrent identical POST /api/ltr/lightning requests.
            // Each request would call LtrRecord.create (fresh nonce -> distinct content id) then
            // LtrGossip.announce(record). Before the round-2 fix, announce()'s pre-check
            // (index.hasLightningPaymentBeenUsed) and index.add()'s mutation were separate
            // @Synchronized acquisitions, so all N threads could pass the pre-check before any of
            // them committed. All threads are released simultaneously via a CyclicBarrier - not a
            // loop that could accidentally serialize on scheduling - to make the race genuinely
            // adversarial rather than incidentally safe.
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-announce-concurrent"))
                val pubsub = GossipPubSub.attach(node)
                val ltr = LtrGossip.attach(pubsub, storage)
                try {
                    val payer = identity.secp256k1KeyPair
                    val viewId = Secp256k1KeyPair.generate()
                    val cid = testCid(1)
                    val amountMsat = 3_000_000L
                    val sharedProof = lightningProof(cid, viewId, amountMsat)
                    val threadCount = 24

                    val records =
                        (1..threadCount).map {
                            LtrRecord.create(
                                payer,
                                cid,
                                viewId.publicKey,
                                initialValueMsat = amountMsat,
                                proof = sharedProof,
                            )
                        }
                    records.map { it.contentId().toList() }.toSet().size shouldBe threadCount

                    val barrier = CyclicBarrier(threadCount)
                    val executor = Executors.newFixedThreadPool(threadCount)
                    val results =
                        try {
                            val futures =
                                records.map { record ->
                                    executor.submit<Boolean> {
                                        barrier.await()
                                        ltr.announce(record)
                                    }
                                }
                            futures.map { it.get(30, TimeUnit.SECONDS) }
                        } finally {
                            executor.shutdown()
                            executor.awaitTermination(10, TimeUnit.SECONDS)
                        }

                    results.count { it } shouldBe 1
                    ltr.currentRecords(cid, viewId.publicKey).size shouldBe 1
                } finally {
                    ltr.stop()
                    pubsub.stop()
                }
            } finally {
                runCatching { node.stop() }
            }
        }
    })
