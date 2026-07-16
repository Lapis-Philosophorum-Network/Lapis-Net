package net.lapisphilosophorum.lapisnet.storage

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.nio.file.Files

/**
 * Two local nodes, explicitly connected via [LapisNode.connect] on loopback TCP - no mDNS, no
 * DHT, no real bootstrap infra (mirrors [net.lapisphilosophorum.lapisnet.networking.TwoNodeDirectDialTest]
 * from V0.1.3). A block is `put` on node A only, then fetched from node B via the real Bitswap
 * wire protocol by passing node A as an explicit peer - this bypasses DHT provider discovery
 * entirely, so it's deterministic and must always pass regardless of sandbox networking
 * restrictions.
 */
class TwoNodeBitswapDirectFetchTest :
    FunSpec({
        test("node B fetches a block put on node A via Bitswap, given node A as an explicit peer") {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("nabu-storage-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("nabu-storage-b"))
                // Bitswap dials peers via the AddressBook, not via the raw Connection above -
                // register node A's address so node B can actually reach it.
                storageB.registerPeerAddress(nodeA.listenAddresses().first().withP2P(nodeA.peerId))

                val payload = "block fetched over the real bitswap wire protocol".toByteArray()
                val cid = storageA.put(payload)

                val fetched = storageB.get(cid, peers = setOf(nodeA.peerId))

                fetched shouldBe payload
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }

        test("registerPeerAddress rejects an address with no /p2p/ peer component") {
            val node = LapisNode.create(DualKeyIdentity.generate())
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("nabu-storage-reject"))
                shouldThrow<NabuStorageException> {
                    storage.registerPeerAddress(Multiaddr("/ip4/127.0.0.1/tcp/4001"))
                }
            } finally {
                node.stop()
            }
        }
    })
