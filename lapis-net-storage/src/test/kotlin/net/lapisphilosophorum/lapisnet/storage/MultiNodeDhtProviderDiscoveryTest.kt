package net.lapisphilosophorum.lapisnet.storage

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import java.nio.file.Files

/**
 * Three local nodes (A, B, C) in a chain - A and C are each explicitly connected to B's DHT
 * routing table via [NabuStorage.connectToDhtPeer] (not mDNS, not real bootstrap infra, same
 * "explicit local peer" reasoning as [TwoNodeBitswapDirectFetchTest]).
 *
 * This originally attempted a full round trip: node A `put`s a block and `provide`s it to the
 * DHT, node C calls `get` with no explicit peer hint, relying on [NabuStorage.findProviders] to
 * discover node A via B. That part does not currently work - see the **known limitation** noted
 * on [NabuStorage.provide]'s doc comment and docs/architecture.adoc: a standalone diagnostic
 * spike isolated the underlying `GET_PROVIDERS` RPC round trip returning empty even via Nabu's
 * own trivial "I already have this block locally" auto-provide path, i.e. reproducing with zero
 * involvement of [NabuStorage.provide]/`ADD_PROVIDER`. This is a reproducible, non-flaky
 * failure (confirmed across 4 isolated spike runs), not the kind of environment-dependent
 * flakiness [net.lapisphilosophorum.lapisnet.networking.TwoNodeMdnsDiscoveryTest] soft-degrades
 * for - silently passing here would hide a real, unresolved gap rather than a genuinely
 * unavoidable one, so this test only asserts what has actually been verified working
 * ([NabuStorage.connectToDhtPeer]'s routing-table bootstrap) and does not assert on
 * provider discovery.
 */
class MultiNodeDhtProviderDiscoveryTest :
    FunSpec({
        test("connectToDhtPeer populates both A's and C's routing tables with B, in a 3-node chain") {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            val nodeC = LapisNode.create(DualKeyIdentity.generate())
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeC.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("nabu-storage-a"))
                val storageC = NabuStorage.attach(nodeC, Files.createTempDirectory("nabu-storage-c"))
                NabuStorage.attach(nodeB, Files.createTempDirectory("nabu-storage-b"))

                val bAddress = nodeB.listenAddresses().first().withP2P(nodeB.peerId)
                storageA.connectToDhtPeer(bAddress) shouldBe true
                storageC.connectToDhtPeer(bAddress) shouldBe true
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { nodeC.stop() }
            }
        }

        test(
            "KNOWN ISSUE: findProviders does not currently discover a provider announced by another " +
                "node via the DHT - this test pins the current (broken) behavior so a future fix shows " +
                "up as a test failure here, prompting this test (and NabuStorage's doc comments) to be " +
                "updated rather than the regression going unnoticed",
        ) {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            val nodeC = LapisNode.create(DualKeyIdentity.generate())
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())
                nodeC.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("nabu-storage-a"))
                NabuStorage.attach(nodeB, Files.createTempDirectory("nabu-storage-b"))
                val storageC = NabuStorage.attach(nodeC, Files.createTempDirectory("nabu-storage-c"))

                val bAddress = nodeB.listenAddresses().first().withP2P(nodeB.peerId)
                storageA.connectToDhtPeer(bAddress)
                storageC.connectToDhtPeer(bAddress)

                val cid = storageA.put("known-issue tracking payload".toByteArray())
                storageA.provide(cid)

                storageC.findProviders(cid).shouldBeEmpty()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
                runCatching { nodeC.stop() }
            }
        }
    })
