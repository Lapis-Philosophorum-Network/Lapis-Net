package net.lapisphilosophorum.lapisnet.networking

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.time.Duration
import java.time.Instant
import java.util.Collections

private const val TEST_TOPIC = "lapis-net-test:gossip-pub-sub:v1"

/**
 * Two local nodes, direct-dialed on loopback TCP (mirrors [TwoNodeDirectDialTest]'s connection
 * pattern) - both attach [GossipPubSub] and subscribe to a throwaway test topic, node A publishes
 * bytes, node B's received-messages collection is polled with a bounded timeout (gossip mesh
 * formation is asynchronous and non-instant - never a fixed sleep, never an unconditional
 * immediate assert after publish).
 *
 * This does NOT test GossipSub's own mesh-level re-propagation suppression on `Invalid` - that is
 * upstream jvm-libp2p's own tested responsibility, not this project's.
 */
class TwoNodeGossipPubSubTest :
    FunSpec({
        test("node B receives bytes node A publishes, with the correct sender peer id") {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                // GossipPubSub.attach() registers a ConnectionHandler - it must run BEFORE the
                // nodes connect, or Gossip never sees the connection-established event for this
                // pair and can't open its own mesh stream on it (unlike Bitswap, which dials
                // fresh streams on demand and so tolerates attaching after connect()).
                val gossipA = GossipPubSub.attach(nodeA)
                val gossipB = GossipPubSub.attach(nodeB)

                val received = Collections.synchronizedList(mutableListOf<Pair<ByteArray, PeerId>>())
                val subscriptionA = gossipA.subscribe(TEST_TOPIC) { _, _ -> ValidationResult.Valid }
                val subscriptionB =
                    gossipB.subscribe(TEST_TOPIC) { bytes, from ->
                        received.add(bytes to from)
                        ValidationResult.Valid
                    }

                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val payload = "hello over the real gossipsub wire protocol".toByteArray()

                // GossipSub mesh formation (GRAFT/subscription propagation) is asynchronous, so
                // retry publish, not just the assertion below - a publish issued before the mesh
                // has formed either has no delivery guarantee at all, or (observed in practice)
                // fails outright with NoPeersForOutboundMessageException wrapped as
                // GossipPubSubException, since the router has no known subscriber yet. Both cases
                // just mean "not ready yet, retry" here.
                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var delivered = received.toList()
                while (delivered.isEmpty() && Instant.now().isBefore(deadline)) {
                    runCatching { gossipA.publish(TEST_TOPIC, payload) }
                    Thread.sleep(500)
                    delivered = received.toList()
                }

                delivered.shouldNotBeEmpty()
                delivered.first().first shouldBe payload
                delivered.first().second shouldBe nodeA.peerId

                subscriptionA.unsubscribe()
                subscriptionB.unsubscribe()
                gossipA.stop()
                gossipB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
