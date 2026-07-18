package net.lapisphilosophorum.lapisnet.virtus

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.doubles.plusOrMinus
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testProof(seed: Byte): OnChainProof = OnChainProof(ByteArray(32) { seed }, outputIndex = 0)

/**
 * Real two-node GossipSub setup proving the Virtus spec note's "Akkumulationslogik" over the
 * wire, not just in-memory: multiple independent [LtrRecord]s for the SAME `(cid, viewId)` pair -
 * from different payers (a like-boost from a stranger) AND from the same payer boosting twice
 * (an author topping up their own post) - must all arrive as distinct entries on the receiving
 * node, never merged or resolved to a single winner (unlike
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGrant]'s backward-hash-chain "latest wins"
 * semantics). [LtrGossip.currentWeight] on the receiver must equal the sum of each record's own
 * independently-decayed weight.
 */
class LtrAccumulationIntegrationTest :
    FunSpec({
        test("independent boosts for the same (cid, viewId) pair accumulate as distinct records over real gossip") {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("ltr-accum-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("ltr-accum-b"))

                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val ltrA = LtrGossip.attach(pubsubA, storageA)
                val ltrB = LtrGossip.attach(pubsubB, storageB)

                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val viewId = Secp256k1KeyPair.generate().publicKey
                val cid = testCid(1)

                // The author (node A's own identity) makes the initial payment...
                val author = identityA.secp256k1KeyPair
                // ...then boosts their own post again later...
                val authorBoostAgain = author
                // ...and a completely different payer (a stranger liking the post) also boosts it.
                val stranger = Secp256k1KeyPair.generate()

                val now = System.currentTimeMillis() / 1000
                val initial = LtrRecord.create(author, cid, viewId, 10_000, testProof(1), timestampSeconds = now)
                val authorTopUp =
                    LtrRecord.create(authorBoostAgain, cid, viewId, 5_000, testProof(2), timestampSeconds = now)
                val strangerLike =
                    LtrRecord.create(stranger, cid, viewId, 1_000, testProof(3), timestampSeconds = now)
                val allRecords = listOf(initial, authorTopUp, strangerLike)

                val deadline = Instant.now().plus(Duration.ofSeconds(30))
                var recordsOnB = ltrB.currentRecords(cid, viewId)
                while (recordsOnB.size < allRecords.size && Instant.now().isBefore(deadline)) {
                    allRecords.forEach { ltrA.announce(it) }
                    Thread.sleep(500)
                    recordsOnB = ltrB.currentRecords(cid, viewId)
                }

                recordsOnB shouldHaveSize 3
                recordsOnB.toSet() shouldBe allRecords.toSet()

                val expectedWeight = LtrWeightCalculator.accumulatedWeightMsat(allRecords, atEpochSeconds = now)
                ltrB.currentWeight(cid, viewId, atEpochSeconds = now) shouldBe (expectedWeight plusOrMinus 0.01)

                ltrA.stop()
                ltrB.stop()
                pubsubA.stop()
                pubsubB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
