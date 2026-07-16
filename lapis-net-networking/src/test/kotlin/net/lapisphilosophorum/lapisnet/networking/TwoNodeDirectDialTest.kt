package net.lapisphilosophorum.lapisnet.networking

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity

/**
 * Two local nodes connecting via a direct dial on loopback TCP - no multicast, no bootstrap, no
 * real network egress. This is the connectivity test that must always pass in any sandbox/CI;
 * see [TwoNodeMdnsDiscoveryTest] for the environment-dependent mDNS alternative.
 */
class TwoNodeDirectDialTest :
    FunSpec({
        test("node A can directly dial and connect to node B on loopback") {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val connection = nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                // The dialed addresses (nodeB.listenAddresses()) don't carry a /p2p component, so
                // remoteAddress() alone can't identify the peer - the Noise handshake's negotiated
                // secure session is the actual source of truth for who we ended up connected to.
                connection.secureSession().remoteId shouldBe nodeB.peerId
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
