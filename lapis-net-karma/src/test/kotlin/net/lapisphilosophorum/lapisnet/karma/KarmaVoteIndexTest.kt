package net.lapisphilosophorum.lapisnet.karma

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testAnchor(seed: Byte = 1): ChainAnchorClaim = ChainAnchorClaim(100, ByteArray(32) { seed }, 200)

private fun vote(
    voter: Secp256k1KeyPair,
    cid: Cid,
    timestampSeconds: Long = 1_700_000_000L,
): KarmaVote = KarmaVote.create(voter, cid, testAnchor(), timestampSeconds = timestampSeconds)

class KarmaVoteIndexTest :
    FunSpec({
        test("add returns true for a new vote, false for the same vote added again") {
            val voter = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val v = vote(voter, cid)
            val index = KarmaVoteIndex()

            index.add(v) shouldBe true
            index.add(v) shouldBe false
            index.votesForTarget(cid) shouldBe listOf(v)
            index.votesByVoter(voter.publicKey) shouldBe listOf(v)
        }

        test("add rejects a signature-tampered vote and never throws") {
            val voter = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val v = vote(voter, cid)
            val bytes = KarmaVoteCodec.encode(v)
            bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the signature
            val tampered = KarmaVoteCodec.decode(bytes)
            val index = KarmaVoteIndex()

            index.add(tampered) shouldBe false
            index.allTargets() shouldBe emptySet()
        }

        test("two votes for different targets by different voters are both tracked independently") {
            val voterA = Secp256k1KeyPair.generate()
            val voterB = Secp256k1KeyPair.generate()
            val cidA = testCid(1)
            val cidB = testCid(2)
            val vA = vote(voterA, cidA)
            val vB = vote(voterB, cidB)
            val index = KarmaVoteIndex()

            index.add(vA) shouldBe true
            index.add(vB) shouldBe true
            index.votesForTarget(cidA) shouldBe listOf(vA)
            index.votesForTarget(cidB) shouldBe listOf(vB)
            index.votesByVoter(voterA.publicKey) shouldBe listOf(vA)
            index.votesByVoter(voterB.publicKey) shouldBe listOf(vB)
            index.allTargets() shouldBe setOf(cidA, cidB)
        }

        test("multiple votes for the SAME target are ALL tracked - never resolved to one winner") {
            val cid = testCid(1)
            val v1 = vote(Secp256k1KeyPair.generate(), cid)
            val v2 = vote(Secp256k1KeyPair.generate(), cid)
            val v3 = vote(Secp256k1KeyPair.generate(), cid)
            val index = KarmaVoteIndex()

            index.add(v1) shouldBe true
            index.add(v2) shouldBe true
            index.add(v3) shouldBe true

            index.votesForTarget(cid) shouldBe listOf(v1, v2, v3)
        }

        test("multiple votes by the SAME voter (for different targets) are ALL tracked under votesByVoter") {
            val voter = Secp256k1KeyPair.generate()
            val cidA = testCid(1)
            val cidB = testCid(2)
            val vA = vote(voter, cidA)
            val vB = vote(voter, cidB)
            val index = KarmaVoteIndex()

            index.add(vA) shouldBe true
            index.add(vB) shouldBe true

            index.votesByVoter(voter.publicKey) shouldBe listOf(vA, vB)
        }

        test("votesForTarget/votesByVoter for unknown keys return an empty list") {
            val index = KarmaVoteIndex()

            index.votesForTarget(testCid(1)) shouldBe emptyList()
            index.votesByVoter(Secp256k1KeyPair.generate().publicKey) shouldBe emptyList()
        }

        // --- The highest-value test in this module: eviction must clean BOTH secondary indices ---

        test(
            "MAX_TRACKED_VOTES cap evicts the oldest tracked vote from BOTH votesByTarget AND " +
                "votesByVoter - not just one of the two",
        ) {
            val voterA = Secp256k1KeyPair.generate()
            val voterB = Secp256k1KeyPair.generate()
            val voterC = Secp256k1KeyPair.generate()
            val cids = (1..3).map { testCid(it.toByte()) }
            val index = KarmaVoteIndex(maxTracked = 2, maxPersisted = 10)

            // Three distinct voters, three distinct targets - so a bug that only cleans ONE of the
            // two reverse indices is unambiguously observable: the evicted vote would still show up
            // under either votesForTarget(cids[0]) or votesByVoter(voterA) if the sync is broken.
            val v0 = vote(voterA, cids[0])
            val v1 = vote(voterB, cids[1])
            val v2 = vote(voterC, cids[2])

            index.add(v0) shouldBe true
            index.add(v1) shouldBe true
            index.add(v2) shouldBe true // evicts v0 (oldest, access-order LinkedHashMap)

            index.allTargets().size shouldBe 2

            // BOTH reverse indices must have forgotten v0 entirely.
            index.votesForTarget(cids[0]) shouldBe emptyList()
            index.votesByVoter(voterA.publicKey) shouldBe emptyList()

            // The two surviving votes remain correct in both indices.
            index.votesForTarget(cids[1]) shouldBe listOf(v1)
            index.votesForTarget(cids[2]) shouldBe listOf(v2)
            index.votesByVoter(voterB.publicKey) shouldBe listOf(v1)
            index.votesByVoter(voterC.publicKey) shouldBe listOf(v2)
            index.allTargets() shouldBe setOf(cids[1], cids[2])
        }

        test(
            "eviction cleans votesByVoter correctly even when the SAME voter has multiple tracked " +
                "votes and only one is evicted",
        ) {
            val voter = Secp256k1KeyPair.generate()
            val otherVoter = Secp256k1KeyPair.generate()
            val cids = (1..3).map { testCid(it.toByte()) }
            val index = KarmaVoteIndex(maxTracked = 2, maxPersisted = 10)

            val v0 = vote(voter, cids[0])
            val v1 = vote(voter, cids[1])
            val v2 = vote(otherVoter, cids[2])

            index.add(v0) shouldBe true
            index.add(v1) shouldBe true
            index.add(v2) shouldBe true // evicts v0 - v1 (same voter) must remain intact

            index.votesByVoter(voter.publicKey) shouldBe listOf(v1)
            index.votesForTarget(cids[0]) shouldBe emptyList()
            index.votesForTarget(cids[1]) shouldBe listOf(v1)
        }

        // --- One tracked vote per (voter, targetCid) - security-critical invariant -------------

        test(
            "a second vote from the SAME voter for the SAME target REPLACES the first, rather than " +
                "adding a second entry alongside it",
        ) {
            val voter = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val first = vote(voter, cid, timestampSeconds = 1_700_000_000L)
            val second = vote(voter, cid, timestampSeconds = 1_700_000_100L)
            val index = KarmaVoteIndex()

            index.add(first) shouldBe true
            index.add(second) shouldBe true

            // Only the second (most-recently-added) vote survives, in BOTH secondary indices.
            index.votesForTarget(cid) shouldBe listOf(second)
            index.votesByVoter(voter.publicKey) shouldBe listOf(second)
        }

        test(
            "replacing a voter's vote for a target does not disturb that same voter's votes for OTHER targets",
        ) {
            val voter = Secp256k1KeyPair.generate()
            val cidA = testCid(1)
            val cidB = testCid(2)
            val firstForA = vote(voter, cidA, timestampSeconds = 1_700_000_000L)
            val secondForA = vote(voter, cidA, timestampSeconds = 1_700_000_100L)
            val forB = vote(voter, cidB, timestampSeconds = 1_700_000_050L)
            val index = KarmaVoteIndex()

            index.add(firstForA) shouldBe true
            index.add(forB) shouldBe true
            index.add(secondForA) shouldBe true

            index.votesForTarget(cidA) shouldBe listOf(secondForA)
            index.votesForTarget(cidB) shouldBe listOf(forB)
            index.votesByVoter(voter.publicKey) shouldBe listOf(forB, secondForA)
        }

        test(
            "replacing a voter's vote for a target does not disturb OTHER voters' votes for the same target",
        ) {
            val voterA = Secp256k1KeyPair.generate()
            val voterB = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val aFirst = vote(voterA, cid, timestampSeconds = 1_700_000_000L)
            val bVote = vote(voterB, cid, timestampSeconds = 1_700_000_050L)
            val aSecond = vote(voterA, cid, timestampSeconds = 1_700_000_100L)
            val index = KarmaVoteIndex()

            index.add(aFirst) shouldBe true
            index.add(bVote) shouldBe true
            index.add(aSecond) shouldBe true

            index.votesForTarget(cid) shouldBe listOf(bVote, aSecond)
            index.votesByVoter(voterA.publicKey) shouldBe listOf(aSecond)
            index.votesByVoter(voterB.publicKey) shouldBe listOf(bVote)
        }

        test(
            "harmonic-inflation is now bounded per target from one voter - repeat-voting the same " +
                "target many times contributes only ONE vote's worth of Karma, not a harmonic sum",
        ) {
            val voter = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val index = KarmaVoteIndex()

            // The same voter "likes" the same target 50 times in a row - each with a fresh nonce,
            // so each is content-id-distinct and would previously have all been tracked.
            val votes = (1..50).map { i -> vote(voter, cid, timestampSeconds = 1_700_000_000L + i) }
            votes.forEach { index.add(it) shouldBe true }

            // Only the LAST vote is tracked - votesForTarget/votesByVoter both reflect exactly one
            // entry for this voter, so KarmaWeightCalculator.totalRawKarmaForTarget can only ever
            // sum ONE karmaValue() contribution from this voter for this target, never a harmonic
            // sum across all 50 attempts.
            index.votesForTarget(cid) shouldBe listOf(votes.last())
            index.votesByVoter(voter.publicKey) shouldBe listOf(votes.last())

            val total =
                KarmaWeightCalculator.totalRawKarmaForTarget(index.votesForTarget(cid)) { v ->
                    index.votesByVoter(v)
                }
            val singleVoteValue = KarmaWeightCalculator.karmaValue(votes.last(), index.votesByVoter(voter.publicKey))
            total shouldBe singleVoteValue
        }

        // --- canAccept: cheap, non-mutating admission pre-check --------------------------------

        test("canAccept returns true for a not-yet-tracked vote, under cap") {
            val v = vote(Secp256k1KeyPair.generate(), testCid(1))
            val index = KarmaVoteIndex()

            index.canAccept(v) shouldBe true
        }

        test("canAccept returns false for a vote already tracked by content id") {
            val v = vote(Secp256k1KeyPair.generate(), testCid(1))
            val index = KarmaVoteIndex()
            index.add(v) shouldBe true

            index.canAccept(v) shouldBe false
        }

        test("canAccept returns true even when the index is at capacity - a full index evicts, it never rejects") {
            val index = KarmaVoteIndex(maxTracked = 2, maxPersisted = 10)
            index.add(vote(Secp256k1KeyPair.generate(), testCid(1))) shouldBe true
            index.add(vote(Secp256k1KeyPair.generate(), testCid(2))) shouldBe true

            val newVote = vote(Secp256k1KeyPair.generate(), testCid(3))

            index.canAccept(newVote) shouldBe true
        }

        // --- tryReservePersistence: separate, non-evicting cap ----------------------------------

        test("tryReservePersistence succeeds for a new content id under the persistence cap") {
            val v = vote(Secp256k1KeyPair.generate(), testCid(1))
            val index = KarmaVoteIndex(maxTracked = 10, maxPersisted = 2)

            index.tryReservePersistence(v) shouldBe true
        }

        test("tryReservePersistence fails once the persistence cap is reached, and stays failing - it does not evict") {
            val index = KarmaVoteIndex(maxTracked = 10, maxPersisted = 2)

            val v0 = vote(Secp256k1KeyPair.generate(), testCid(1))
            val v1 = vote(Secp256k1KeyPair.generate(), testCid(2))
            val v2 = vote(Secp256k1KeyPair.generate(), testCid(3))

            index.tryReservePersistence(v0) shouldBe true
            index.tryReservePersistence(v1) shouldBe true
            index.tryReservePersistence(v2) shouldBe false

            val v3 = vote(Secp256k1KeyPair.generate(), testCid(4))
            index.tryReservePersistence(v3) shouldBe false
        }

        test(
            "tryReservePersistence is idempotent - calling it again for an already-reserved content id " +
                "succeeds without consuming a second slot",
        ) {
            val v0 = vote(Secp256k1KeyPair.generate(), testCid(1))
            val index = KarmaVoteIndex(maxTracked = 10, maxPersisted = 1)

            index.tryReservePersistence(v0) shouldBe true
            repeat(5) { index.tryReservePersistence(v0) shouldBe true }

            val v1 = vote(Secp256k1KeyPair.generate(), testCid(2))
            index.tryReservePersistence(v1) shouldBe false
        }

        test(
            "tryReservePersistence and the in-memory tracking cap are independent - " +
                "a low persistence cap does not stop the index from tracking more votes",
        ) {
            val index = KarmaVoteIndex(maxTracked = 10, maxPersisted = 1)

            val v0 = vote(Secp256k1KeyPair.generate(), testCid(1))
            val v1 = vote(Secp256k1KeyPair.generate(), testCid(2))
            val v2 = vote(Secp256k1KeyPair.generate(), testCid(3))

            index.tryReservePersistence(v0) shouldBe true
            index.tryReservePersistence(v1) shouldBe false
            index.tryReservePersistence(v2) shouldBe false

            index.add(v0) shouldBe true
            index.add(v1) shouldBe true
            index.add(v2) shouldBe true
            index.allTargets().size shouldBe 3
        }
    })
