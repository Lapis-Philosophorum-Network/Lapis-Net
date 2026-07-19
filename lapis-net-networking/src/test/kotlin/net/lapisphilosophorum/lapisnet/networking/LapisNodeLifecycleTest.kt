package net.lapisphilosophorum.lapisnet.networking

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.Protocol
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity

/** Unreachable-but-syntactically-valid bootstrap addresses for [LapisNodeLifecycleTest]'s
 * "unreachable bootstrap peers must never block startup" case - RFC 5737 documentation-range IPs
 * (`203.0.113.0/24`) paired with a freshly-generated random [PeerId], mirroring the retired
 * `BootstrapPeers.PLACEHOLDER`'s exact construction (see V0.4's BootstrapConfig, which replaced
 * that hardcoded production constant with real operator configuration - this test still needs
 * *some* guaranteed-unreachable multiaddr, which is a purely local test concern, not a production
 * default). */
private fun unreachableBootstrapMultiaddrs(): List<Multiaddr> =
    listOf("203.0.113.10", "203.0.113.11").map { ip ->
        Multiaddr("/ip4/$ip/tcp/4001").withP2P(PeerId.random())
    }

class LapisNodeLifecycleTest :
    FunSpec({
        val nodes = mutableListOf<LapisNode>()

        fun newNode(): LapisNode = LapisNode.create(DualKeyIdentity.generate()).also { nodes += it }

        afterEach {
            nodes.forEach { runCatching { it.stop() } }
            nodes.clear()
        }

        test("a node starts and stops cleanly") {
            val node = newNode()
            shouldNotThrowAny {
                node.start(bootstrapPeers = emptyList())
            }
            node.listenAddresses().shouldNotBeEmpty()
            // an ephemeral tcp/0 listen address must be resolved to a real, non-zero bound port
            val boundPort =
                node
                    .listenAddresses()
                    .first()
                    .getFirstComponent(Protocol.TCP)
                    ?.stringValue
            boundPort shouldNotBe "0"
            shouldNotThrowAny { node.stop() }
        }

        test("a node's discoveredPeers list starts empty") {
            val node = newNode()
            node.start(bootstrapPeers = emptyList())
            node.discoveredPeers().shouldBeEmpty()
        }

        test("a node with only unreachable bootstrap peers still starts within the timeout") {
            val node = newNode()
            shouldNotThrowAny {
                node.start(bootstrapPeers = unreachableBootstrapMultiaddrs())
            }
        }

        test("stop is idempotent - a second call is a safe no-op") {
            val node = newNode()
            node.start(bootstrapPeers = emptyList())
            node.stop()
            // guarded by an AtomicBoolean, so this exercises the no-op short-circuit path, not
            // the independent-sub-shutdown logic itself (that's verified by direct code review:
            // LapisNode.stop() unconditionally attempts both mdns.stop() and host.stop() via
            // separate runCatching blocks before either is allowed to short-circuit the other -
            // Host/MDnsDiscovery aren't easily mockable to inject a genuine partial failure here)
            shouldNotThrowAny { node.stop() }
        }
    })
