package net.lapisphilosophorum.lapisnet.madli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files

private fun testPeerId(seed: Byte): PeerId = PeerId(ByteArray(34) { seed })

private fun testMetrics(): MadliMetrics =
    MadliMetrics(
        reachabilityMicros = 500_000,
        medianBandwidthBytesPerSec = 10_000_000L,
        medianLatencyMillis = 50,
        deliveryIntegrityMicros = 900_000,
        routingHelpfulnessMicros = 700_000,
        observationCount = 10,
    )

/**
 * Unit-level tests of [MadliGossip.onGossipMessage] itself, called directly rather than through a
 * full two-node gossip mesh - mirrors `KarmaGossipOnGossipMessageTest`/`LtrGossipOnGossipMessageTest`'s
 * exact test seam reasoning (a single, never-connected [LapisNode] + [NabuStorage] is enough, since
 * the function takes both as plain parameters).
 */
class MadliGossipOnGossipMessageTest :
    FunSpec({
        test("a fresh, valid, non-duplicate vector is persisted, indexed, and accepted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-ongossip-a"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val observer = identity.secp256k1KeyPair
                val peer = testPeerId(1)
                val vector = MadliDailyVector.create(observer, peer, epochDay = 100L, metrics = testMetrics())
                val bytes = MadliDailyVectorCodec.encode(vector)
                val index = MadliVectorIndex()

                val result = MadliGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Valid
                index.vectorsForObservedPeer(peer) shouldBe listOf(vector)
                storage.get(storage.put(bytes)) shouldBe bytes
            } finally {
                node.stop()
            }
        }

        test("a signature-corrupted vector is rejected as Invalid and never persisted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-ongossip-sig"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val observer = identity.secp256k1KeyPair
                val vector = MadliDailyVector.create(observer, testPeerId(1), epochDay = 100L, metrics = testMetrics())
                val bytes = MadliDailyVectorCodec.encode(vector)
                bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the signature
                val index = MadliVectorIndex()

                val result = MadliGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allObservedPeers() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("epochDay altered after signing is rejected as Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-ongossip-epochday"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val observer = identity.secp256k1KeyPair
                val peer = testPeerId(1)
                val vector = MadliDailyVector.create(observer, peer, epochDay = 100L, metrics = testMetrics())
                val bytes = MadliDailyVectorCodec.encode(vector)

                // epochDay(8) sits right after magic(4)+version(1)+observer(33)+peerIdLen(2)+peerId(34).
                val offset = 4 + 1 + 33 + 2 + peer.bytes.size
                bytes[offset + 7] = (bytes[offset + 7] + 1).toByte() // low-order byte of the Long

                val index = MadliVectorIndex()

                val result = MadliGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allObservedPeers() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("a malformed (structurally invalid) message is rejected as Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-ongossip-malformed"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = MadliVectorIndex()

                val result = MadliGossip.onGossipMessage(byteArrayOf(1, 2, 3), from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allObservedPeers() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("a replayed (identical bytes) delivery is declined by canAccept - not re-persisted or re-indexed") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-ongossip-replay"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val observer = identity.secp256k1KeyPair
                val peer = testPeerId(1)
                val vector = MadliDailyVector.create(observer, peer, epochDay = 100L, metrics = testMetrics())
                val bytes = MadliDailyVectorCodec.encode(vector)
                val index = MadliVectorIndex()

                val first = MadliGossip.onGossipMessage(bytes, from, storage, index)
                val second = MadliGossip.onGossipMessage(bytes, from, storage, index)

                first shouldBe ValidationResult.Valid
                second shouldBe ValidationResult.Invalid
                index.vectorsForObservedPeer(peer) shouldHaveSize 1
            } finally {
                node.stop()
            }
        }

        test(
            "distinct vectors beyond the persistence cap are all still Valid and indexed, but only up to the " +
                "cap are actually persisted to disk",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-ongossip-persist-cap"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val persistCap = 2
                val totalVectors = 6
                val index = MadliVectorIndex(maxTracked = 100, maxPersisted = persistCap, maxDaysPerObserverPeer = 128)

                val sent =
                    (1..totalVectors).map { i ->
                        val observer = Secp256k1KeyPair.generate()
                        val vector =
                            MadliDailyVector.create(
                                observer,
                                testPeerId(i.toByte()),
                                epochDay = 100L,
                                metrics = testMetrics(),
                            )
                        MadliDailyVectorCodec.encode(vector)
                    }

                val results = sent.map { MadliGossip.onGossipMessage(it, from, storage, index) }

                results shouldBe List(totalVectors) { ValidationResult.Valid }
                index.allObservedPeers().size shouldBe totalVectors

                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                val persistedCount =
                    try {
                        val mintingStorage =
                            NabuStorage.attach(mintingNode, Files.createTempDirectory("madli-ongossip-persist-mint"))
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
                val storage = NabuStorage.attach(node, Files.createTempDirectory("madli-ongossip-dup-persist"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val observer = identity.secp256k1KeyPair
                val vector = MadliDailyVector.create(observer, testPeerId(1), epochDay = 100L, metrics = testMetrics())
                val bytes = MadliDailyVectorCodec.encode(vector)

                val index = MadliVectorIndex()
                index.add(vector) shouldBe true

                val result = MadliGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid

                val otherNode = LapisNode.create(DualKeyIdentity.generate())
                otherNode.start(bootstrapPeers = emptyList())
                val mintedCid =
                    try {
                        NabuStorage.attach(otherNode, Files.createTempDirectory("madli-ongossip-dup-mint")).put(bytes)
                    } finally {
                        otherNode.stop()
                    }
                storage.get(mintedCid).shouldBeNull()
            } finally {
                node.stop()
            }
        }
    })
