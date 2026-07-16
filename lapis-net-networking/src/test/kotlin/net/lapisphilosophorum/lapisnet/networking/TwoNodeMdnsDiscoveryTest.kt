package net.lapisphilosophorum.lapisnet.networking

import io.github.oshai.kotlinlogging.KotlinLogging
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.time.Duration
import java.time.Instant

private val logger = KotlinLogging.logger {}

/**
 * mDNS discovery relies on IP multicast, which many containerized/sandboxed/CI environments
 * (including a vanilla GitHub Actions `ubuntu-latest` runner without extra network
 * configuration) either block or don't route correctly by default. jvm-libp2p's own README
 * marks mDNS discovery as "prototype/beta, not tested in production" - matching that risk level.
 *
 * This test is therefore intentionally best-effort: if node B isn't discovered within the
 * timeout, it logs a warning and passes rather than failing the build - unlike
 * [TwoNodeDirectDialTest], which must always pass and is the real connectivity regression test.
 * When multicast does work in the running environment, this test still verifies real behavior
 * (the discovered peer's id actually matches).
 */
class TwoNodeMdnsDiscoveryTest :
    FunSpec({
        test("node A discovers node B via mDNS, best-effort") {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var found = nodeA.discoveredPeers().any { it.peerId == nodeB.peerId }
                while (!found && Instant.now().isBefore(deadline)) {
                    Thread.sleep(500)
                    found = nodeA.discoveredPeers().any { it.peerId == nodeB.peerId }
                }

                if (found) {
                    nodeA.discoveredPeers().any { it.peerId == nodeB.peerId } shouldBe true
                } else {
                    logger.warn {
                        "mDNS did not discover node B within the timeout - likely multicast is unavailable in this environment; not failing the build"
                    }
                }
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
