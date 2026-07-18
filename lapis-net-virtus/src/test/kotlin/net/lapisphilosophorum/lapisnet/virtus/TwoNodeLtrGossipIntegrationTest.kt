package net.lapisphilosophorum.lapisnet.virtus

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

/**
 * Two REAL nodes (no mocking), direct-dialed on loopback TCP - mirrors
 * [net.lapisphilosophorum.lapisnet.trust.TwoNodeVeritasGossipIntegrationTest]'s connectivity
 * pattern exactly, adapted to [LtrGossip]/[LtrRecord].
 */
class TwoNodeLtrGossipIntegrationTest :
    FunSpec({
        test("a record announced on node A propagates to node B, resolves identically, and persists durably") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("ltr-gossip-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("ltr-gossip-b"))

                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val ltrA = LtrGossip.attach(pubsubA, storageA)
                val ltrB = LtrGossip.attach(pubsubB, storageB)

                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val payer = identityA.secp256k1KeyPair
                val viewId = Secp256k1KeyPair.generate().publicKey
                val cid = testCid(1)
                val proof = OnChainProof(ByteArray(32) { it.toByte() }, outputIndex = 0)
                val record = LtrRecord.create(payer, cid, viewId, initialValueMsat = 50_000, proof = proof)

                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var recordsOnB = ltrB.currentRecords(cid, viewId)
                while (recordsOnB.isEmpty() && Instant.now().isBefore(deadline)) {
                    ltrA.announce(record)
                    Thread.sleep(500)
                    recordsOnB = ltrB.currentRecords(cid, viewId)
                }

                recordsOnB shouldBe listOf(record)
                ltrB.currentWeight(cid, viewId, atEpochSeconds = record.timestampSeconds) shouldBe
                    LtrWeightCalculator.decayedWeightMsat(record, record.timestampSeconds)

                // Durable persistence: node B's local blockstore must hold the exact same bytes A
                // announced, addressable by the same content-addressed CID.
                val recordBytes = LtrRecordCodec.encode(record)
                val cidOfBytes = storageA.put(recordBytes)
                storageB.get(cidOfBytes) shouldBe recordBytes

                ltrA.stop()
                ltrB.stop()
                pubsubA.stop()
                pubsubB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
