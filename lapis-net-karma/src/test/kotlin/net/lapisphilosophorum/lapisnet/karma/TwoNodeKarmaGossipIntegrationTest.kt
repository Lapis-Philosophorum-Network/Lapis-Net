package net.lapisphilosophorum.lapisnet.karma

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

/**
 * Two REAL nodes (no mocking), direct-dialed on loopback TCP - mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.TwoNodeLtrGossipIntegrationTest]'s connectivity pattern
 * exactly, adapted to [KarmaGossip]/[KarmaVote].
 */
class TwoNodeKarmaGossipIntegrationTest :
    FunSpec({
        test("a vote announced on node A propagates to node B, resolves identically, and persists durably") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("karma-gossip-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("karma-gossip-b"))

                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val karmaA = KarmaGossip.attach(pubsubA, storageA)
                val karmaB = KarmaGossip.attach(pubsubB, storageB)

                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val voter = identityA.secp256k1KeyPair
                val cid = testCid(1)
                val anchor = ChainAnchorClaim(100, ByteArray(32) { it.toByte() }, 200)
                val vote = KarmaVote.create(voter, cid, anchor)

                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var votesOnB = karmaB.currentVotesForTarget(cid)
                while (votesOnB.isEmpty() && Instant.now().isBefore(deadline)) {
                    karmaA.announce(vote)
                    Thread.sleep(500)
                    votesOnB = karmaB.currentVotesForTarget(cid)
                }

                votesOnB shouldBe listOf(vote)
                karmaB.currentVotesByVoter(voter.publicKey) shouldBe listOf(vote)
                KarmaWeightCalculator.karmaValue(vote, karmaB.currentVotesByVoter(voter.publicKey)) shouldBe 100.0

                // Durable persistence: node B's local blockstore must hold the exact same bytes A
                // announced, addressable by the same content-addressed CID.
                val voteBytes = KarmaVoteCodec.encode(vote)
                val cidOfBytes = storageA.put(voteBytes)
                storageB.get(cidOfBytes) shouldBe voteBytes

                karmaA.stop()
                karmaB.stop()
                pubsubA.stop()
                pubsubB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
