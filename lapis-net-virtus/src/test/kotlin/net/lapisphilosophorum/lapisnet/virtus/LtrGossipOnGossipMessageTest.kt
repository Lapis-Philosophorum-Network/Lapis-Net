package net.lapisphilosophorum.lapisnet.virtus

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

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testProof(seed: Byte = 1): OnChainProof = OnChainProof(ByteArray(32) { seed }, outputIndex = 0)

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
    })
