package net.lapisphilosophorum.lapisnet.karma

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.pubsub.ValidationResult
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testAnchor(seed: Byte = 1): ChainAnchorClaim = ChainAnchorClaim(100, ByteArray(32) { seed }, 200)

/**
 * Unit-level tests of [KarmaGossip.onGossipMessage] itself, called directly rather than through a
 * full two-node gossip mesh - mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrGossipOnGossipMessageTest]'s exact test seam
 * reasoning (a single, never-connected [LapisNode] + [NabuStorage] is enough, since the function
 * takes both as plain parameters).
 */
class KarmaGossipOnGossipMessageTest :
    FunSpec({
        test("a fresh, valid, non-duplicate vote is persisted, indexed, and accepted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("karma-ongossip-a"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val voter = identity.secp256k1KeyPair
                val cid = testCid(1)
                val vote = KarmaVote.create(voter, cid, testAnchor())
                val bytes = KarmaVoteCodec.encode(vote)
                val index = KarmaVoteIndex()

                val result = KarmaGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Valid
                index.votesForTarget(cid) shouldBe listOf(vote)
                storage.get(storage.put(bytes)) shouldBe bytes
            } finally {
                node.stop()
            }
        }

        test("a signature-corrupted vote is rejected as Invalid and never persisted") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("karma-ongossip-sig"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val voter = identity.secp256k1KeyPair
                val vote = KarmaVote.create(voter, testCid(1), testAnchor())
                val bytes = KarmaVoteCodec.encode(vote)
                bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the signature
                val index = KarmaVoteIndex()

                val result = KarmaGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allTargets() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("timestampSeconds altered after signing is rejected as Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("karma-ongossip-timestamp"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val voter = identity.secp256k1KeyPair
                val vote = KarmaVote.create(voter, testCid(1), testAnchor())
                val bytes = KarmaVoteCodec.encode(vote)

                // timestampSeconds(8, Long) starts right after magic(4)+version(1)+voter(33)+
                // cidLen(2)+cid.
                val cidBytes = testCid(1).toBytes()
                val offset = 4 + 1 + 33 + 2 + cidBytes.size
                bytes[offset + 7] = (bytes[offset + 7] + 1).toByte() // low-order byte of the Long

                val index = KarmaVoteIndex()

                val result = KarmaGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allTargets() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("ChainAnchorClaim.genesisTxid altered after signing is rejected as Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("karma-ongossip-anchor"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val voter = identity.secp256k1KeyPair
                val vote = KarmaVote.create(voter, testCid(1), testAnchor())
                val bytes = KarmaVoteCodec.encode(vote)

                // anchorBytes(40 = genesisTxid(32)+heights(8)) sit right before nonce(8)+signature(64).
                val txidOffset = bytes.size - 64 - 8 - 40
                bytes[txidOffset] = (bytes[txidOffset] + 1).toByte()

                val index = KarmaVoteIndex()

                val result = KarmaGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allTargets() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("a malformed (structurally invalid) message is rejected as Invalid") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("karma-ongossip-malformed"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()
                val index = KarmaVoteIndex()

                val result = KarmaGossip.onGossipMessage(byteArrayOf(1, 2, 3), from, storage, index)

                result shouldBe ValidationResult.Invalid
                index.allTargets() shouldBe emptySet()
            } finally {
                node.stop()
            }
        }

        test("a replayed (identical bytes) delivery is declined by canAccept - not re-persisted or re-indexed") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("karma-ongossip-replay"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val voter = identity.secp256k1KeyPair
                val cid = testCid(1)
                val vote = KarmaVote.create(voter, cid, testAnchor())
                val bytes = KarmaVoteCodec.encode(vote)
                val index = KarmaVoteIndex()

                val first = KarmaGossip.onGossipMessage(bytes, from, storage, index)
                val second = KarmaGossip.onGossipMessage(bytes, from, storage, index)

                first shouldBe ValidationResult.Valid
                second shouldBe ValidationResult.Invalid
                // Only ever tracked once, even though onGossipMessage was called twice.
                index.votesForTarget(cid) shouldHaveSize 1
            } finally {
                node.stop()
            }
        }

        test(
            "distinct votes beyond the persistence cap are all still Valid and indexed, but only up to the " +
                "cap are actually persisted to disk",
        ) {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("karma-ongossip-persist-cap"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val persistCap = 2
                val totalVotes = 6
                val index = KarmaVoteIndex(maxTracked = 100, maxPersisted = persistCap)

                val sent =
                    (1..totalVotes).map { i ->
                        val voter = Secp256k1KeyPair.generate()
                        val vote = KarmaVote.create(voter, testCid(i.toByte()), testAnchor())
                        KarmaVoteCodec.encode(vote)
                    }

                val results = sent.map { KarmaGossip.onGossipMessage(it, from, storage, index) }

                results shouldBe List(totalVotes) { ValidationResult.Valid }
                index.allTargets().size shouldBe totalVotes

                val mintingNode = LapisNode.create(DualKeyIdentity.generate())
                mintingNode.start(bootstrapPeers = emptyList())
                val persistedCount =
                    try {
                        val mintingStorage =
                            NabuStorage.attach(mintingNode, Files.createTempDirectory("karma-ongossip-persist-mint"))
                        sent.count { storage.get(mintingStorage.put(it)) != null }
                    } finally {
                        mintingNode.stop()
                    }
                persistedCount shouldBe persistCap
            } finally {
                node.stop()
            }
        }

        test("a duplicate delivery is never persisted, verified against the real blockstore") {
            val identity = DualKeyIdentity.generate()
            val node = LapisNode.create(identity)
            node.start(bootstrapPeers = emptyList())
            try {
                val storage = NabuStorage.attach(node, Files.createTempDirectory("karma-ongossip-dup-persist"))
                val from = DualKeyIdentity.generate().deriveLibp2pPeerId()

                val voter = identity.secp256k1KeyPair
                val vote = KarmaVote.create(voter, testCid(1), testAnchor())
                val bytes = KarmaVoteCodec.encode(vote)

                val index = KarmaVoteIndex()
                index.add(vote) shouldBe true

                val result = KarmaGossip.onGossipMessage(bytes, from, storage, index)

                result shouldBe ValidationResult.Invalid

                val otherNode = LapisNode.create(DualKeyIdentity.generate())
                otherNode.start(bootstrapPeers = emptyList())
                val mintedCid =
                    try {
                        NabuStorage.attach(otherNode, Files.createTempDirectory("karma-ongossip-dup-mint")).put(bytes)
                    } finally {
                        otherNode.stop()
                    }
                storage.get(mintedCid).shouldBeNull()
            } finally {
                node.stop()
            }
        }
    })
