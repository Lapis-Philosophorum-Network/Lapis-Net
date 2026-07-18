package net.lapisphilosophorum.lapisnet.virtus

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
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
 * Real two-node setup (no mocking) - mirrors
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGossipNegativePathIntegrationTest]'s "malformed/
 * malicious gossip message must never kill the subscription, and must never reach the receiver's
 * index/storage" regression test, adapted to [LtrGossip]. A signature-invalid record (well-formed
 * bytes, tampered trailing signature) is published directly over real GossipSub, bypassing
 * [LtrGossip.announce]/[LtrRecordCodec.encode] entirely to simulate a malicious or buggy peer.
 */
class LtrGossipNegativePathIntegrationTest :
    FunSpec({
        test("a signature-invalid record sent over real gossip never reaches the receiver's index or storage") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("ltr-negative-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("ltr-negative-b"))

                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val ltrB = LtrGossip.attach(pubsubB, storageB)

                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val payer = identityA.secp256k1KeyPair
                val viewId = Secp256k1KeyPair.generate().publicKey
                val cid = testCid(1)
                val proof = OnChainProof(ByteArray(32) { it.toByte() }, outputIndex = 0)
                val validRecord = LtrRecord.create(payer, cid, viewId, initialValueMsat = 25_000, proof = proof)
                val tamperedBytes = LtrRecordCodec.encode(validRecord)
                tamperedBytes[tamperedBytes.size - 1] = (tamperedBytes[tamperedBytes.size - 1] + 1).toByte()

                val settleDeadline = Instant.now().plus(Duration.ofSeconds(15))
                while (Instant.now().isBefore(settleDeadline)) {
                    pubsubA.publish(LtrGossip.LTR_RECORD_GOSSIP_TOPIC, tamperedBytes)
                    Thread.sleep(500)
                    if (ltrB.currentRecords(cid, viewId).isNotEmpty()) break
                }

                ltrB.currentRecords(cid, viewId).shouldBeEmpty()

                // The subscription must still be functional: a real valid record sent next on the
                // same connection must be accepted normally.
                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var recordsOnB = ltrB.currentRecords(cid, viewId)
                while (recordsOnB.isEmpty() && Instant.now().isBefore(deadline)) {
                    pubsubA.publish(LtrGossip.LTR_RECORD_GOSSIP_TOPIC, LtrRecordCodec.encode(validRecord))
                    Thread.sleep(500)
                    recordsOnB = ltrB.currentRecords(cid, viewId)
                }

                recordsOnB shouldBe listOf(validRecord)

                // Also confirm the tampered bytes never landed durably on B, using storageA purely
                // as a way to mint the content-addressed CID for those exact bytes.
                val tamperedCid = storageA.put(tamperedBytes)
                storageB.get(tamperedCid) shouldBe null

                ltrB.stop()
                pubsubA.stop()
                pubsubB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
