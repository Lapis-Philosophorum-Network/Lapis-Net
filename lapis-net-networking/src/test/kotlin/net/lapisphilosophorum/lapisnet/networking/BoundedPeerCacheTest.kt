package net.lapisphilosophorum.lapisnet.networking

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo

private fun randomPeerInfo(): PeerInfo = PeerInfo(PeerId.random(), emptyList())

/**
 * Deterministic, non-network coverage of the discovered-peer bookkeeping logic - the part of
 * [LapisNode]'s mDNS wiring that can't otherwise be exercised reliably, since real mDNS depends
 * on multicast that isn't available in every sandbox/CI environment (see
 * [TwoNodeMdnsDiscoveryTest]).
 */
class BoundedPeerCacheTest :
    FunSpec({
        test("record stores a new peer and it appears in values") {
            val cache = BoundedPeerCache(maxSize = 10)
            val peer = randomPeerInfo()
            cache.record(peer) shouldBe true
            cache.values() shouldContainExactlyInAnyOrder listOf(peer)
        }

        test("recording the same peerId twice deduplicates rather than accumulating") {
            val cache = BoundedPeerCache(maxSize = 10)
            val peer = randomPeerInfo()
            cache.record(peer)
            cache.record(peer)
            cache.values() shouldHaveSize 1
        }

        test("recording the same peerId with updated addresses overwrites the stored entry") {
            val cache = BoundedPeerCache(maxSize = 10)
            val peerId = PeerId.random()
            val first = PeerInfo(peerId, emptyList())
            val updated =
                PeerInfo(
                    peerId,
                    listOf(
                        io.libp2p.core.multiformats
                            .Multiaddr("/ip4/127.0.0.1/tcp/4001"),
                    ),
                )

            cache.record(first)
            cache.record(updated)

            cache.values() shouldHaveSize 1
            cache.values().first().addresses shouldBe updated.addresses
        }

        test("drops new peers once the cache is full") {
            val cache = BoundedPeerCache(maxSize = 2)
            val a = randomPeerInfo()
            val b = randomPeerInfo()
            val c = randomPeerInfo()

            cache.record(a) shouldBe true
            cache.record(b) shouldBe true
            cache.record(c) shouldBe false

            cache.values() shouldHaveSize 2
            cache.values().map { it.peerId } shouldContainExactlyInAnyOrder listOf(a.peerId, b.peerId)
        }

        test("a full cache still accepts refreshes of peers it already knows") {
            val cache = BoundedPeerCache(maxSize = 1)
            val a = randomPeerInfo()
            cache.record(a) shouldBe true

            val refreshed =
                PeerInfo(
                    a.peerId,
                    listOf(
                        io.libp2p.core.multiformats
                            .Multiaddr("/ip4/127.0.0.1/tcp/4001"),
                    ),
                )
            cache.record(refreshed) shouldBe true

            cache.values() shouldHaveSize 1
            cache.values().first().addresses shouldBe refreshed.addresses
        }
    })
