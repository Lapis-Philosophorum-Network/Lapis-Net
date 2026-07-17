package net.lapisphilosophorum.lapisnet.trust

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.Collections

private const val WARMUP_TOPIC = "lapis-net-test:three-node-relay-warmup:v1"

/**
 * Three REAL nodes (no mocking) in a chain: A<->B and B<->C are each direct-dialed, but A and C
 * are NEVER connected to each other - mirrors
 * [net.lapisphilosophorum.lapisnet.storage.MultiNodeDhtProviderDiscoveryTest]'s 3-node
 * loopback-chain topology from V0.1.4. Proves actual multi-hop GossipSub mesh relay (not just
 * direct-peer delivery, already covered by [TwoNodeVeritasGossipIntegrationTest]) carries a grant
 * from A to C via B.
 *
 * **Warm-up phase (round-2 addition).** [VeritasGrantIndex.canAccept] (round-2's C2 fix) means
 * [VeritasGossip.onGossipMessage] now correctly declines to re-persist-or-relay an exact
 * content-id duplicate. That is the intended, correct anti-spam behavior - but it also means a
 * grant's *first* successful A->B delivery is its *only* chance to reach C: if B's own mesh link
 * to C has not finished forming yet at that exact moment, B will not relay it, and every later
 * retry of the *identical* grant bytes is now (correctly) deduped by B before it ever reaches
 * GossipSub's re-propagation step. Before round-2, [VeritasGossip.onGossipMessage] ignored
 * `index.add`'s return value and returned `Valid` unconditionally after a successful persist -
 * meaning every retried duplicate got re-relayed too, which incidentally (and insecurely) papered
 * over exactly this mesh-formation race. Retrying `announce()` alone can therefore no longer be
 * relied on to eventually "get lucky" past a not-yet-formed B<->C mesh link.
 *
 * The fix is to warm the *entire* A->B->C GossipSub path up front, on a disposable topic
 * completely separate from [VeritasGossip.VERITAS_GRANT_GOSSIP_TOPIC] - unlike the real Veritas
 * topic, delivery on this topic always validates `Valid`, so distinct warm-up payloads (a fresh
 * random suffix per publish, not `VeritasGossip`'s domain-level content-addressed dedup) keep
 * getting relayed by B on every retry regardless of duplicate content, exactly like
 * [TwoNodeGossipPubSubTest]. Once C has observed one, the whole chain's mesh is known-hot, and the
 * one real [VeritasGossip.announce] call that follows is no longer racing mesh formation - the
 * existing bounded retry loop then remains as a harmless safety net, not the primary delivery
 * mechanism.
 */
class ThreeNodeVeritasGossipRelayTest :
    FunSpec({
        test("a grant announced on node A reaches node C via node B's relay, with no direct A-C connection") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val identityC = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            val nodeC = LapisNode.create(identityC)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeC.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("veritas-relay-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("veritas-relay-b"))
                val storageC = NabuStorage.attach(nodeC, Files.createTempDirectory("veritas-relay-c"))

                // Attach GossipPubSub (ConnectionHandler) on all three BEFORE connecting - see
                // TwoNodeVeritasGossipIntegrationTest's note on why ordering matters here.
                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val pubsubC = GossipPubSub.attach(nodeC)
                val veritasA = VeritasGossip.attach(pubsubA, storageA)
                val veritasB = VeritasGossip.attach(pubsubB, storageB)
                val veritasC = VeritasGossip.attach(pubsubC, storageC)

                // Chain topology: A<->B, B<->C - A and C are never directly dialed.
                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))
                nodeC.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                // Warm-up phase - see the class doc comment. A disposable topic where every
                // message always validates Valid, so distinct retried payloads keep getting
                // relayed by B regardless of duplicate content (unlike the real Veritas topic's
                // content-addressed dedup). Once C observes one, the full A->B->C mesh is known to
                // be hot, so the real announce() below is no longer racing mesh formation.
                val warmupReceivedOnC = Collections.synchronizedList(mutableListOf<ByteArray>())
                pubsubB.subscribe(WARMUP_TOPIC) { _, _ -> ValidationResult.Valid }
                pubsubC.subscribe(WARMUP_TOPIC) { bytes, _ ->
                    warmupReceivedOnC.add(bytes)
                    ValidationResult.Valid
                }
                val warmupDeadline = Instant.now().plus(Duration.ofSeconds(30))
                var warmupSeq = 0
                while (warmupReceivedOnC.isEmpty() && Instant.now().isBefore(warmupDeadline)) {
                    warmupSeq++
                    runCatching { pubsubA.publish(WARMUP_TOPIC, "warmup-$warmupSeq".toByteArray()) }
                    Thread.sleep(200)
                }
                warmupReceivedOnC.shouldNotBeEmpty()

                val truster = identityA.secp256k1KeyPair
                val target = Secp256k1KeyPair.generate().publicKey
                val grant = VeritasGrant.create(truster, target, trustMicros = 850_000, comment = "relayed via B")

                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                var grantsOnC = veritasC.currentGrants()
                while (grantsOnC.isEmpty() && Instant.now().isBefore(deadline)) {
                    veritasA.announce(grant)
                    Thread.sleep(500)
                    grantsOnC = veritasC.currentGrants()
                }

                grantsOnC shouldBe listOf(grant)

                veritasA.stop()
                veritasB.stop()
                veritasC.stop()
                pubsubA.stop()
                pubsubB.stop()
                pubsubC.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { nodeC.stop() }
            }
        }
    })
