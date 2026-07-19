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
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testProof(seed: Byte = 1): OnChainProof = OnChainProof(ByteArray(32) { seed }, outputIndex = 0)

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

private val INVOICE_FEATURES =
    Features(
        mapOf(
            Feature.VariableLengthOnion to FeatureSupport.Mandatory,
            Feature.PaymentSecret to FeatureSupport.Mandatory,
        ),
    )

/** A real, cryptographically valid [LightningProof] whose invoice is signed by [viewId] itself -
 * see [LightningProofVerifierTest]'s `ValidTuple` for the identical "same scalar for both the
 * Lapis viewId and the ACINQ Lightning node key" construction this mirrors. */
private fun validLightningProof(
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
 * Unit-level tests of [LtrGossip.onGossipMessage] itself, called directly rather than through a
 * full two-node gossip mesh - mirrors
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGossipOnGossipMessageTest]'s exact test seam
 * reasoning (a single, never-connected [LapisNode] + [NabuStorage] is enough, since the function
 * takes both as plain parameters).
 */
class LtrGossipOnGossipMessageTest :
    FunSpec({
        test("a fresh, valid, non-duplicate record is persisted, indexed, and accepted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-ongossip-a"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val payer = identity.secp256k1KeyPair
                val viewId = Secp256k1KeyPair.generate().publicKey
                val cid = testCid(1)
                val record = LtrRecord.create(payer, cid, viewId, initialValueMsat = 1000, proof = testProof())
                val bytes = LtrRecordCodec.encode(record)
                val index = LtrRecordIndex()

                val result = LtrGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Valid
                index.recordsFor(cid, viewId) shouldBe listOf(record)
                storage.get(storage.put(bytes)) shouldBe bytes
            } finally {
                node.stop()
            }
        }

        test("a signature-corrupted record is rejected as Invalid and never persisted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-ongossip-sig"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val payer = identity.secp256k1KeyPair
                val viewId = Secp256k1KeyPair.generate().publicKey
                val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 1000, proof = testProof())
                val bytes = LtrRecordCodec.encode(record)
                bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the signature
                val index = LtrRecordIndex()

                val result = LtrGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allPairs() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("initialValueMsat altered after signing is rejected as Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-ongossip-value"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val payer = identity.secp256k1KeyPair
                val viewId = Secp256k1KeyPair.generate().publicKey
                val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 1000, proof = testProof())
                val bytes = LtrRecordCodec.encode(record)

                // initialValueMsat(8, Long) starts right after magic(4)+version(1)+payer(33)+
                // viewId(33)+cidLen(2)+cid.
                val cidBytes = testCid(1).toBytes()
                val offset = 4 + 1 + 33 + 33 + 2 + cidBytes.size
                bytes[offset + 7] = (bytes[offset + 7] + 1).toByte() // low-order byte of the Long

                val index = LtrRecordIndex()

                val result = LtrGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allPairs() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("OnChainProof.btcTxid altered after signing is rejected as Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-ongossip-proof"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val payer = identity.secp256k1KeyPair
                val viewId = Secp256k1KeyPair.generate().publicKey
                val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 1000, proof = testProof())
                val bytes = LtrRecordCodec.encode(record)

                // proofBytes(36 = btcTxid(32)+outputIndex(4)) sit right before the trailing 64-byte
                // signature - flip a byte inside the txid portion.
                val txidOffset = bytes.size - 64 - 36
                bytes[txidOffset] = (bytes[txidOffset] + 1).toByte()

                val index = LtrRecordIndex()

                val result = LtrGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allPairs() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("a replayed (identical bytes) delivery is declined by canAccept - not re-persisted or re-indexed") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-ongossip-replay"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val payer = identity.secp256k1KeyPair
                val viewId = Secp256k1KeyPair.generate().publicKey
                val cid = testCid(1)
                val record = LtrRecord.create(payer, cid, viewId, initialValueMsat = 1000, proof = testProof())
                val bytes = LtrRecordCodec.encode(record)
                val index = LtrRecordIndex()

                val first = LtrGossip.onGossipMessage(bytes, from, storage, index)
                val second = LtrGossip.onGossipMessage(bytes, from, storage, index)

                first shouldBe ValidationResult.Valid
                second shouldBe ValidationResult.Invalid
                // Only ever tracked once, even though onGossipMessage was called twice.
                index.recordsFor(cid, viewId) shouldHaveSize 1
            } finally {
                node.stop()
            }
        }

        test(
            "distinct records beyond the persistence cap are all still Valid and indexed, but only up to the " +
                "cap are actually persisted to disk",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-ongossip-persist-cap"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val persistCap = 2
                val totalRecords = 6
                val index = LtrRecordIndex(maxTracked = 100, maxPersisted = persistCap)

                val sent =
                    (1..totalRecords).map { i ->
                        val payer = Secp256k1KeyPair.generate()
                        val viewId = Secp256k1KeyPair.generate().publicKey
                        val record =
                            LtrRecord.create(
                                payer,
                                testCid(i.toByte()),
                                viewId,
                                initialValueMsat = 1000,
                                proof = testProof(),
                            )
                        LtrRecordCodec.encode(record)
                    }

                val results = sent.map { LtrGossip.onGossipMessage(it, from, storage, index) }

                results shouldBe List(totalRecords) { ValidationResult.Valid }
                index.allPairs().size shouldBe totalRecords

                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                val persistedCount =
                    try {
                        val mintingStorage =
                            NabuStorage.attach(mintingNode, Files.createTempDirectory("ltr-ongossip-persist-mint"))
                        sent.count { storage.get(mintingStorage.put(it)) != null }
                    } finally {
                        mintingNode.stop()
                    }
                persistedCount shouldBe persistCap
            } finally {
                node.stop()
            }
        }

        test("a duplicate delivery is never persisted, verified against the real blockstore") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-ongossip-dup-persist"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val payer = identity.secp256k1KeyPair
                val viewId = Secp256k1KeyPair.generate().publicKey
                val record = LtrRecord.create(payer, testCid(1), viewId, initialValueMsat = 1000, proof = testProof())
                val bytes = LtrRecordCodec.encode(record)

                val index = LtrRecordIndex()
                index.add(record) shouldBe true

                val result = LtrGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid

                val otherNode = LapisNode.create(DualKeyIdentity.generate())
                otherNode.start(bootstrapPeers = emptyList())
                val mintedCid =
                    try {
                        NabuStorage.attach(otherNode, Files.createTempDirectory("ltr-ongossip-dup-mint")).put(bytes)
                    } finally {
                        otherNode.stop()
                    }
                storage.get(mintedCid).shouldBeNull()
            } finally {
                node.stop()
            }
        }

        test("a valid Lightning-proof record is persisted, indexed, and accepted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-ongossip-lightning-valid"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val payer = identity.secp256k1KeyPair
                val viewId = Secp256k1KeyPair.generate()
                val cid = testCid(1)
                val amountMsat = 2_500_000L
                val proof = validLightningProof(cid, viewId, amountMsat)
                val record =
                    LtrRecord.create(
                        payer,
                        cid,
                        viewId.publicKey,
                        initialValueMsat = amountMsat,
                        proof = proof,
                    )
                val bytes = LtrRecordCodec.encode(record)
                val index = LtrRecordIndex()

                val result = LtrGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Valid
                index.recordsFor(cid, viewId.publicKey) shouldBe listOf(record)
            } finally {
                node.stop()
            }
        }

        test("a crypto-invalid Lightning-proof record (corrupt preimage) is rejected as Invalid and never indexed") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-ongossip-lightning-invalid"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val payer = identity.secp256k1KeyPair
                val viewId = Secp256k1KeyPair.generate()
                val cid = testCid(1)
                val amountMsat = 2_500_000L
                val validProof = validLightningProof(cid, viewId, amountMsat)
                // Corrupt the preimage so sha256(preimage) != paymentHash - the record's own LtrRecord
                // signature stays valid (it signs over the whole proof, corrupt or not), only the
                // Lightning-specific crypto check inside LightningProofVerifier must catch this.
                val corruptPreimage = validProof.preimage.also { it[0] = (it[0] + 1).toByte() }
                val corruptProof = LightningProof(corruptPreimage, validProof.paymentHash, validProof.signedInvoice)
                val record =
                    LtrRecord.create(payer, cid, viewId.publicKey, initialValueMsat = amountMsat, proof = corruptProof)
                val bytes = LtrRecordCodec.encode(record)
                val index = LtrRecordIndex()

                val result = LtrGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allPairs() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        // --- C1 regression: one real Lightning payment must not mint unbounded LTR weight -------

        test(
            "a resubmitted Lightning payment - harvested preimage, different payer key, fresh nonce - is " +
                "rejected as Invalid and does not double the tracked weight",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-ongossip-lightning-replay"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = LtrRecordIndex()

                val viewId = Secp256k1KeyPair.generate()
                val cid = testCid(1)
                val amountMsat = 2_500_000L
                // ONE real Lightning proof - the preimage is public once gossiped (see
                // LightningProof's own doc comment), so an attacker who merely observed the first
                // gossiped record can lift (preimage, signedInvoice) straight off the wire and
                // reuse it verbatim - they never need to forge anything cryptographic.
                val sharedProof = validLightningProof(cid, viewId, amountMsat)

                val genuinePayer = identity.secp256k1KeyPair
                val genuineRecord =
                    LtrRecord.create(
                        genuinePayer,
                        cid,
                        viewId.publicKey,
                        initialValueMsat = amountMsat,
                        proof = sharedProof,
                    )

                // The attacker signs their OWN LtrRecord (a different payer key, and LtrRecord.create
                // draws a fresh nonce every call) around the exact same harvested proof - a
                // structurally and cryptographically valid record in every respect the codec/
                // signature/LightningProofVerifier checks look at; only content id differs.
                val attackerPayer = Secp256k1KeyPair.generate()
                val replayedRecord =
                    LtrRecord.create(
                        attackerPayer,
                        cid,
                        viewId.publicKey,
                        initialValueMsat = amountMsat,
                        proof = sharedProof,
                    )
                replayedRecord.contentId().contentEquals(genuineRecord.contentId()) shouldBe false

                val genuineResult =
                    LtrGossip.onGossipMessage(LtrRecordCodec.encode(genuineRecord), from, storage, index)
                val replayResult =
                    LtrGossip.onGossipMessage(LtrRecordCodec.encode(replayedRecord), from, storage, index)

                genuineResult shouldBe ValidationResult.Valid
                replayResult shouldBe ValidationResult.Invalid
                // Only the genuine record is tracked - the replay contributed zero extra weight.
                index.recordsFor(cid, viewId.publicKey) shouldBe listOf(genuineRecord)
                LtrWeightCalculator.accumulatedWeightMsat(
                    index.recordsFor(cid, viewId.publicKey),
                    atEpochSeconds = genuineRecord.timestampSeconds,
                ) shouldBe LtrWeightCalculator.decayedWeightMsat(genuineRecord, genuineRecord.timestampSeconds)
            } finally {
                node.stop()
            }
        }

        test(
            "two DIFFERENT genuine Lightning payments for the same (cid, viewId) are both accepted and their " +
                "weights sum normally - the C1 fix must not block legitimate independent boosts",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-ongossip-lightning-two-real"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = LtrRecordIndex()

                val payer = identity.secp256k1KeyPair
                val viewId = Secp256k1KeyPair.generate()
                val cid = testCid(1)
                val amountMsat = 1_000_000L
                // Two INDEPENDENT payments - distinct preimages, therefore distinct payment hashes -
                // must never be conflated by the paymentHash dedup check.
                val firstProof = validLightningProof(cid, viewId, amountMsat)
                val secondProof = validLightningProof(cid, viewId, amountMsat)
                firstProof.paymentHash.contentEquals(secondProof.paymentHash) shouldBe false

                val firstRecord =
                    LtrRecord.create(payer, cid, viewId.publicKey, initialValueMsat = amountMsat, proof = firstProof)
                val secondRecord =
                    LtrRecord.create(payer, cid, viewId.publicKey, initialValueMsat = amountMsat, proof = secondProof)

                val firstResult = LtrGossip.onGossipMessage(LtrRecordCodec.encode(firstRecord), from, storage, index)
                val secondResult = LtrGossip.onGossipMessage(LtrRecordCodec.encode(secondRecord), from, storage, index)

                firstResult shouldBe ValidationResult.Valid
                secondResult shouldBe ValidationResult.Valid
                index.recordsFor(cid, viewId.publicKey) shouldBe listOf(firstRecord, secondRecord)
                LtrWeightCalculator.accumulatedWeightMsat(
                    index.recordsFor(cid, viewId.publicKey),
                    atEpochSeconds = firstRecord.timestampSeconds,
                ) shouldBe
                    LtrWeightCalculator.decayedWeightMsat(firstRecord, firstRecord.timestampSeconds) +
                    LtrWeightCalculator.decayedWeightMsat(secondRecord, secondRecord.timestampSeconds)
            } finally {
                node.stop()
            }
        }

        test(
            "CONCURRENCY: N concurrent onGossipMessage() deliveries with fresh-nonce records sharing one " +
                "Lightning payment hash - exactly one record is ever tracked/credited, no matter how many " +
                "deliveries this function reports as Valid",
        ) {
            // Adversarial concurrency test for the round-2 CRITICAL finding on the gossip-receipt
            // path: simulates concurrent gossip deliveries of records that all harvested the same
            // public preimage (see LightningProof's own doc comment on preimages being public once
            // gossiped) but each carries a different payer key/fresh nonce - the identical exploit
            // shape as the local self-announce path, just arriving via the gossip validator instead
            // of the HTTP endpoint. canAccept()'s pre-check and index.add()'s mutation are separate
            // @Synchronized acquisitions, so without the round-2 fix inside add() itself, all threads
            // could pass canAccept() before any of them committed. Released simultaneously via a
            // CyclicBarrier to force a genuine race rather than one that might accidentally serialize.
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("ltr-ongossip-concurrent"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = LtrRecordIndex()

                val viewId = Secp256k1KeyPair.generate()
                val cid = testCid(1)
                val amountMsat = 2_500_000L
                val sharedProof = validLightningProof(cid, viewId, amountMsat)
                val threadCount = 24

                val payloads =
                    (1..threadCount).map {
                        val payer = Secp256k1KeyPair.generate()
                        val record =
                            LtrRecord.create(
                                payer,
                                cid,
                                viewId.publicKey,
                                initialValueMsat = amountMsat,
                                proof = sharedProof,
                            )
                        LtrRecordCodec.encode(record)
                    }
                payloads.map { LtrRecordCodec.decode(it).contentId().toList() }.toSet().size shouldBe threadCount

                val barrier = CyclicBarrier(threadCount)
                val executor = Executors.newFixedThreadPool(threadCount)
                val results =
                    try {
                        val futures =
                            payloads.map { bytes ->
                                executor.submit<ValidationResult> {
                                    barrier.await()
                                    LtrGossip.onGossipMessage(bytes, from, storage, index)
                                }
                            }
                        futures.map { it.get(30, TimeUnit.SECONDS) }
                    } finally {
                        executor.shutdown()
                        executor.awaitTermination(10, TimeUnit.SECONDS)
                    }

                // Every delivery is structurally/cryptographically valid on its own, so a losing
                // delivery can come back Invalid two different ways, both safe: rejected early by
                // canAccept()'s cheap pre-check (if, by the time this thread's canAccept() ran, the
                // atomic winner had already committed via add()), or - the genuinely adversarial case
                // this CyclicBarrier is built to provoke - waved through by canAccept() alongside
                // other racers and only THEN rejected atomically inside add() itself, in which case
                // onGossipMessage still returns Valid for it (see that function's own doc comment on
                // why a narrow index-race loser still propagates). Either way, whichever thread wins
                // index.add() first always returns Valid (onGossipMessage only ever returns Invalid
                // before reaching add()), so at least one Valid is guaranteed. The actual load-bearing
                // assertion is the index itself: only ONE record - the atomic winner of index.add() -
                // is ever actually tracked/credited, no matter how many threads raced to get there or
                // how many of them this function happened to tell "Valid".
                val validCount = results.count { it == ValidationResult.Valid }
                val invalidCount = results.count { it == ValidationResult.Invalid }
                (validCount + invalidCount) shouldBe threadCount
                (validCount >= 1) shouldBe true
                index.recordsFor(cid, viewId.publicKey).size shouldBe 1
            } finally {
                node.stop()
            }
        }
    })
