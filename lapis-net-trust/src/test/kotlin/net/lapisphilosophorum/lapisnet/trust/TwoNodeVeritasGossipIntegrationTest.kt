package net.lapisphilosophorum.lapisnet.trust

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

/**
 * Two REAL nodes (no mocking), direct-dialed on loopback TCP - `LapisNode` + `NabuStorage` +
 * [GossipPubSub] + [VeritasGossip] fully attached on both, mirroring
 * [net.lapisphilosophorum.lapisnet.storage.TwoNodeBitswapDirectFetchTest]'s connectivity pattern.
 * Node A announces a genesis grant trusting a throwaway keypair C (not itself a running node);
 * node B's resolved view is polled with a bounded timeout until it converges with A's.
 */
class TwoNodeVeritasGossipIntegrationTest :
    FunSpec({
        test("a grant announced on node A propagates to node B, resolves identically, and persists durably") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("veritas-gossip-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("veritas-gossip-b"))

                // GossipPubSub (and therefore VeritasGossip, which subscribes through it) must be
                // attached BEFORE the nodes connect - Gossip is a ConnectionHandler and only sees
                // connection-established events for connections made after it registers.
                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val veritasA = VeritasGossip.attach(pubsubA, storageA)
                val veritasB = VeritasGossip.attach(pubsubB, storageB)

                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val truster = identityA.secp256k1KeyPair
                val targetC = Secp256k1KeyPair.generate().publicKey // throwaway, not a running node
                val grant = VeritasGrant.create(truster, targetC, trustMicros = 700_000, comment = "trusted colleague")

                // GossipSub mesh formation (GRAFT) is asynchronous, so retry announce(), not just
                // the assertion below - a publish issued before the mesh has formed has no
                // delivery guarantee at all (GossipPubSub.publish's doc comment). Retrying the
                // whole announce() call is safe: storage.put is idempotent/deterministic for
                // identical content and index.add is a harmless no-op on a duplicate.
                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var grantsOnB = veritasB.currentGrants()
                while (grantsOnB.isEmpty() && Instant.now().isBefore(deadline)) {
                    veritasA.announce(grant)
                    Thread.sleep(500)
                    grantsOnB = veritasB.currentGrants()
                }

                grantsOnB shouldBe listOf(grant)

                val graphA = TrustGraph.fromGrants(veritasA.currentGrants())
                val graphB = TrustGraph.fromGrants(grantsOnB)
                val pathA = TrustPathFinder.findPath(graphA, truster.publicKey, targetC)
                val pathB = TrustPathFinder.findPath(graphB, truster.publicKey, targetC)

                pathA shouldBe pathB
                pathA?.scoreMicros shouldBe 700_000

                // Durable persistence, not just the in-memory index: node B's NabuStorage local
                // blockstore must hold the exact same bytes A announced, addressable by the same
                // content-addressed CID (NabuStorage.put is idempotent/deterministic for
                // identical content, so calling it again on A's already-stored bytes is safe and
                // yields the same Cid without double-storing anything new).
                val grantBytes = VeritasGrantCodec.encode(grant)
                val cid = storageA.put(grantBytes)
                storageB.get(cid) shouldBe grantBytes

                veritasA.stop()
                veritasB.stop()
                pubsubA.stop()
                pubsubB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
