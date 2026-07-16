package net.lapisphilosophorum.lapisnet.networking

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.multiformats.Protocol
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity

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

        test("a node with only placeholder bootstrap peers still starts within the timeout") {
            val node = newNode()
            shouldNotThrowAny {
                node.start(bootstrapPeers = BootstrapPeers.PLACEHOLDER)
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
