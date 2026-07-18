package net.lapisphilosophorum.lapisnet.browser

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.karma.ChainAnchorClaim
import net.lapisphilosophorum.lapisnet.karma.KarmaVote
import net.lapisphilosophorum.lapisnet.karma.MAX_STRUCTURAL_BLOCK_HEIGHT
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant
import net.lapisphilosophorum.lapisnet.virtus.LtrRecord
import net.lapisphilosophorum.lapisnet.virtus.OnChainProof

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testProof(seed: Byte = 1): OnChainProof = OnChainProof(ByteArray(32) { seed }, outputIndex = 0)

private fun testAnchor(
    genesisHeight: Int,
    tipHeight: Int,
    seed: Byte = 1,
): ChainAnchorClaim = ChainAnchorClaim(genesisHeight, ByteArray(32) { seed }, tipHeight)

class TimelineBuilderTest :
    FunSpec({
        test("empty candidates produce an empty timeline") {
            val local = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(emptyList())

            val entries = TimelineBuilder.build(graph, local, emptyList(), emptyMap())

            entries.shouldBeEmpty()
        }

        test("a NO_PATH candidate is never filtered out, regardless of the threshold") {
            val local = Secp256k1KeyPair.generate()
            val author = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(emptyList()) // no trust edges at all - author is NO_PATH
            val candidate = TimelineCandidate(testCid(1), author, publishedAtEpochSeconds = 1000)

            val entries =
                TimelineBuilder.build(
                    graph,
                    local.publicKey,
                    listOf(candidate),
                    emptyMap(),
                    // A threshold of the maximum possible score would filter out virtually any
                    // RESOLVED candidate - but NO_PATH must still never be filtered.
                    TimelineBuilder.TimelineOptions(credibilityFilterThresholdMicros = 1_000_000),
                )

            entries.single().credibility.level shouldBe CredibilityLevel.NO_PATH
            entries.single().filteredOut shouldBe false
        }

        test("a RESOLVED candidate below the threshold is filteredOut and excluded/included by visible()") {
            val local = Secp256k1KeyPair.generate()
            val author = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(local, author, trustMicros = 100_000)
            val graph = TrustGraph.fromGrants(listOf(grant))
            val candidate = TimelineCandidate(testCid(1), author, publishedAtEpochSeconds = 1000)

            val entries =
                TimelineBuilder.build(
                    graph,
                    local.publicKey,
                    listOf(candidate),
                    emptyMap(),
                    TimelineBuilder.TimelineOptions(credibilityFilterThresholdMicros = 250_000),
                )

            entries.single().credibility.level shouldBe CredibilityLevel.RESOLVED
            entries.single().filteredOut shouldBe true
            TimelineBuilder.visible(entries, includeFilteredContent = false).shouldBeEmpty()
            TimelineBuilder.visible(entries, includeFilteredContent = true) shouldBe entries
        }

        test("entries with differing LTR weights sort descending by weight") {
            val local = Secp256k1KeyPair.generate()
            val authorLow = Secp256k1KeyPair.generate()
            val authorHigh = Secp256k1KeyPair.generate()
            val cidLow = testCid(1)
            val cidHigh = testCid(2)
            val now = 1_700_000_000L

            val recordLow =
                LtrRecord.create(
                    authorLow,
                    cidLow,
                    PLACEHOLDER_VIEW_ID,
                    initialValueMsat = 1_000,
                    proof = testProof(1),
                    timestampSeconds = now,
                )
            val recordHigh =
                LtrRecord.create(
                    authorHigh,
                    cidHigh,
                    PLACEHOLDER_VIEW_ID,
                    initialValueMsat = 100_000,
                    proof = testProof(2),
                    timestampSeconds = now,
                )

            val candidates =
                listOf(
                    TimelineCandidate(cidLow, authorLow.publicKey, publishedAtEpochSeconds = now),
                    TimelineCandidate(cidHigh, authorHigh.publicKey, publishedAtEpochSeconds = now),
                )
            val ltrRecordsByCid = mapOf(cidLow to listOf(recordLow), cidHigh to listOf(recordHigh))
            val graph = TrustGraph.fromEdges(emptyList())

            val entries =
                TimelineBuilder.build(
                    graph,
                    local.publicKey,
                    candidates,
                    ltrRecordsByCid,
                    TimelineBuilder.TimelineOptions(atEpochSeconds = now),
                )

            entries.map { it.cid } shouldBe listOf(cidHigh, cidLow)
        }

        test("zero-weight entries break ties by recency descending") {
            val local = Secp256k1KeyPair.generate()
            val olderAuthor = Secp256k1KeyPair.generate().publicKey
            val newerAuthor = Secp256k1KeyPair.generate().publicKey
            val older = TimelineCandidate(testCid(1), olderAuthor, publishedAtEpochSeconds = 1_000)
            val newer = TimelineCandidate(testCid(2), newerAuthor, publishedAtEpochSeconds = 2_000)
            val graph = TrustGraph.fromEdges(emptyList())

            val entries = TimelineBuilder.build(graph, local.publicKey, listOf(older, newer), emptyMap())

            entries.map { it.cid } shouldBe listOf(newer.cid, older.cid)
        }

        test("a self-authored post is never filtered out - self-trust always resolves at full score") {
            val local = Secp256k1KeyPair.generate()
            val candidate = TimelineCandidate(testCid(1), local.publicKey, publishedAtEpochSeconds = 1_000)
            val graph = TrustGraph.fromEdges(emptyList())

            val entries =
                TimelineBuilder.build(
                    graph,
                    local.publicKey,
                    listOf(candidate),
                    emptyMap(),
                    TimelineBuilder.TimelineOptions(credibilityFilterThresholdMicros = 1_000_000),
                )

            entries.single().filteredOut shouldBe false
        }

        test("a missing entry in ltrRecordsByCid is treated as zero records, not an error") {
            val local = Secp256k1KeyPair.generate()
            val author = Secp256k1KeyPair.generate().publicKey
            val candidate = TimelineCandidate(testCid(1), author, publishedAtEpochSeconds = 1_000)
            val graph = TrustGraph.fromEdges(emptyList())

            val entries = TimelineBuilder.build(graph, local.publicKey, listOf(candidate), emptyMap())

            entries.single().ltrRecordCount shouldBe 0
            entries.single().ltrWeightMsat shouldBe 0.0
        }

        test("karmaScore/karmaVoteCount are populated from a self-cast (full-trust) karma vote") {
            val local = Secp256k1KeyPair.generate()
            val author = Secp256k1KeyPair.generate().publicKey
            val cid = testCid(1)
            val candidate = TimelineCandidate(cid, author, publishedAtEpochSeconds = 1_000)
            val graph = TrustGraph.fromEdges(emptyList())

            // local votes on their own candidate - self-trust is axiomatic (full weight)
            // regardless of the (empty) graph, per TrustPathFinder.findPath's doc comment.
            val vote =
                KarmaVote.create(local, cid, testAnchor(genesisHeight = 100, tipHeight = 200), timestampSeconds = 1_000)

            val entries =
                TimelineBuilder.build(
                    graph,
                    local.publicKey,
                    listOf(candidate),
                    emptyMap(),
                    karmaVotesByCid = mapOf(cid to listOf(vote)),
                    karmaVotesByVoter = { emptyList() },
                )

            entries.single().karmaVoteCount shouldBe 1
            // t = 200 - 100 = 100, n = 0 (no other votes by this voter) -> rawKarma = 100.0;
            // self-trust is full (1_000_000 micros / 1_000_000) -> weighted contribution = 100.0.
            entries.single().karmaScore shouldBe 100.0
        }

        test("a stranger's karma vote (no trust path) contributes exactly 0 to karmaScore") {
            val local = Secp256k1KeyPair.generate()
            val author = Secp256k1KeyPair.generate().publicKey
            val stranger = Secp256k1KeyPair.generate()
            val cid = testCid(1)
            val candidate = TimelineCandidate(cid, author, publishedAtEpochSeconds = 1_000)
            val graph = TrustGraph.fromEdges(emptyList()) // no trust edge to stranger at all

            val vote =
                KarmaVote.create(
                    stranger,
                    cid,
                    testAnchor(genesisHeight = 0, tipHeight = 1_000_000),
                    timestampSeconds = 1_000,
                )

            val entries =
                TimelineBuilder.build(
                    graph,
                    local.publicKey,
                    listOf(candidate),
                    emptyMap(),
                    karmaVotesByCid = mapOf(cid to listOf(vote)),
                    karmaVotesByVoter = { emptyList() },
                )

            entries.single().karmaVoteCount shouldBe 1
            entries.single().karmaScore shouldBe 0.0
        }

        test("karma never affects filteredOut, even with a huge karma score on a low-credibility candidate") {
            val local = Secp256k1KeyPair.generate()
            val author = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(local, author, trustMicros = 100_000) // below default threshold
            val graph = TrustGraph.fromGrants(listOf(grant))
            val cid = testCid(1)
            val candidate = TimelineCandidate(cid, author, publishedAtEpochSeconds = 1_000)

            // local casts a maximal-t self vote - if karma ever leaked into filtering, this would
            // flip filteredOut to false. It must not.
            val vote =
                KarmaVote.create(
                    local,
                    cid,
                    testAnchor(genesisHeight = 0, tipHeight = MAX_STRUCTURAL_BLOCK_HEIGHT),
                    timestampSeconds = 1_000,
                )

            val entries =
                TimelineBuilder.build(
                    graph,
                    local.publicKey,
                    listOf(candidate),
                    emptyMap(),
                    TimelineBuilder.TimelineOptions(credibilityFilterThresholdMicros = 250_000),
                    karmaVotesByCid = mapOf(cid to listOf(vote)),
                    karmaVotesByVoter = { emptyList() },
                )

            (entries.single().karmaScore > 0.0) shouldBe true
            entries.single().filteredOut shouldBe true
        }

        test("karma never affects sort order - ltrWeightMsat/recency ordering is unchanged by a huge karma score") {
            val local = Secp256k1KeyPair.generate()
            val lowKarmaAuthor = Secp256k1KeyPair.generate().publicKey
            val highKarmaAuthor = Secp256k1KeyPair.generate().publicKey
            val cidOlderHighKarma = testCid(1)
            val cidNewerNoKarma = testCid(2)
            val older = TimelineCandidate(cidOlderHighKarma, lowKarmaAuthor, publishedAtEpochSeconds = 1_000)
            val newer = TimelineCandidate(cidNewerNoKarma, highKarmaAuthor, publishedAtEpochSeconds = 2_000)
            val graph = TrustGraph.fromEdges(emptyList())

            // The OLDER candidate gets a huge self-cast karma score; the NEWER one gets none. Both
            // have zero LTR weight, so recency must still decide the order (newer first) - karma
            // must not override that tie-break.
            val vote =
                KarmaVote.create(
                    local,
                    cidOlderHighKarma,
                    testAnchor(genesisHeight = 0, tipHeight = MAX_STRUCTURAL_BLOCK_HEIGHT),
                    timestampSeconds = 1_000,
                )

            val entries =
                TimelineBuilder.build(
                    graph,
                    local.publicKey,
                    listOf(older, newer),
                    emptyMap(),
                    karmaVotesByCid = mapOf(cidOlderHighKarma to listOf(vote)),
                    karmaVotesByVoter = { emptyList() },
                )

            entries.map { it.cid } shouldBe listOf(newer.cid, older.cid)
        }
    })
