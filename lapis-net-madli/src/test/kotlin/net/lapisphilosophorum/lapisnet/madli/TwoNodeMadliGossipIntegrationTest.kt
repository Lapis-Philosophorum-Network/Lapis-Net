package net.lapisphilosophorum.lapisnet.madli

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

private fun testPeerId(seed: Byte): PeerId = PeerId(ByteArray(34) { seed })

/**
 * Two REAL nodes (no mocking), direct-dialed on loopback TCP - mirrors
 * `TwoNodeKarmaGossipIntegrationTest`/`TwoNodeLtrGossipIntegrationTest`'s connectivity pattern
 * exactly, adapted to [MadliGossip]/[MadliDailyVector].
 */
class TwoNodeMadliGossipIntegrationTest :
    FunSpec({
        test("a vector announced on node A propagates to node B, resolves identically, and persists durably") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("madli-gossip-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("madli-gossip-b"))

                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val madliA = MadliGossip.attach(pubsubA, storageA)
                val madliB = MadliGossip.attach(pubsubB, storageB)

                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val observer = identityA.secp256k1KeyPair
                val observedPeer = testPeerId(1)
                val metrics =
                    MadliMetrics(
                        reachabilityMicros = 500_000,
                        medianBandwidthBytesPerSec = 10_000_000L,
                        medianLatencyMillis = 50,
                        deliveryIntegrityMicros = 900_000,
                        routingHelpfulnessMicros = 700_000,
                        observationCount = 10,
                    )
                val vector = MadliDailyVector.create(observer, observedPeer, epochDay = 100L, metrics = metrics)

                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var vectorsOnB = madliB.currentVectorsForObservedPeer(observedPeer)
                while (vectorsOnB.isEmpty() && Instant.now().isBefore(deadline)) {
                    madliA.announce(vector)
                    Thread.sleep(500)
                    vectorsOnB = madliB.currentVectorsForObservedPeer(observedPeer)
                }

                vectorsOnB shouldBe listOf(vector)

                // Durable persistence: node B's local blockstore must hold the exact same bytes A
                // announced, addressable by the same content-addressed CID.
                val vectorBytes = MadliDailyVectorCodec.encode(vector)
                val cidOfBytes = storageA.put(vectorBytes)
                storageB.get(cidOfBytes) shouldBe vectorBytes

                madliA.stop()
                madliB.stop()
                pubsubA.stop()
                pubsubB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
