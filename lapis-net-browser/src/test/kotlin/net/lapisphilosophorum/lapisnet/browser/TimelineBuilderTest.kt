package net.lapisphilosophorum.lapisnet.browser

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant
import net.lapisphilosophorum.lapisnet.virtus.LtrRecord
import net.lapisphilosophorum.lapisnet.virtus.OnChainProof

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testProof(seed: Byte = 1): OnChainProof = OnChainProof(ByteArray(32) { seed }, outputIndex = 0)

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
    })
