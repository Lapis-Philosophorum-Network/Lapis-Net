package net.lapisphilosophorum.lapisnet.browser

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.karma.ChainAnchorClaim
import net.lapisphilosophorum.lapisnet.karma.KarmaVote
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun testAnchor(
    genesisHeight: Int,
    tipHeight: Int,
    seed: Byte = 1,
): ChainAnchorClaim = ChainAnchorClaim(genesisHeight, ByteArray(32) { seed }, tipHeight)

class KarmaScoringTest :
    FunSpec({
        test("weightedContribution is exactly 0.0 for a voter with NO_PATH (no trust edge at all)") {
            val local = Secp256k1KeyPair.generate().publicKey
            val voter = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(emptyList())

            KarmaScoring.weightedContribution(rawKarmaValue = 500.0, graph, local, voter) shouldBe 0.0
        }

        test("weightedContribution is the full raw value for full self-trust (voter == localIdentity)") {
            val local = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(emptyList())

            KarmaScoring.weightedContribution(rawKarmaValue = 250.0, graph, local, voter = local) shouldBe 250.0
        }

        test("weightedContribution is the full raw value for a fully (1_000_000 micros) trusted voter") {
            val local = Secp256k1KeyPair.generate()
            val voter = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(local, voter, trustMicros = 1_000_000)
            val graph = TrustGraph.fromGrants(listOf(grant))

            KarmaScoring.weightedContribution(rawKarmaValue = 400.0, graph, local.publicKey, voter) shouldBe 400.0
        }

        test("weightedContribution scales proportionally for a partially-trusted voter") {
            val local = Secp256k1KeyPair.generate()
            val voter = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(local, voter, trustMicros = 250_000) // 25%
            val graph = TrustGraph.fromGrants(listOf(grant))

            KarmaScoring.weightedContribution(rawKarmaValue = 400.0, graph, local.publicKey, voter) shouldBe 100.0
        }

        test("weightedContribution of 0.0 raw value is 0.0 regardless of trust") {
            val local = Secp256k1KeyPair.generate()
            val voter = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(local, voter, trustMicros = 1_000_000)
            val graph = TrustGraph.fromGrants(listOf(grant))

            KarmaScoring.weightedContribution(rawKarmaValue = 0.0, graph, local.publicKey, voter) shouldBe 0.0
        }

        test("personalizedKarmaForTarget sums weighted contributions across multiple voters") {
            val local = Secp256k1KeyPair.generate()
            val trustedVoter = Secp256k1KeyPair.generate()
            val strangerVoter = Secp256k1KeyPair.generate()
            val cid = testCid(1)

            val grant = VeritasGrant.create(local, trustedVoter.publicKey, trustMicros = 1_000_000)
            val graph = TrustGraph.fromGrants(listOf(grant))

            val trustedVote =
                KarmaVote.create(trustedVoter, cid, testAnchor(0, 100), timestampSeconds = 1_000)
            val strangerVote =
                KarmaVote.create(strangerVoter, cid, testAnchor(0, 999_999), timestampSeconds = 1_000)

            val votesByVoter: (net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey) -> List<KarmaVote> = {
                when (it) {
                    trustedVoter.publicKey -> listOf(trustedVote)
                    strangerVoter.publicKey -> listOf(strangerVote)
                    else -> emptyList()
                }
            }

            val total =
                KarmaScoring.personalizedKarmaForTarget(
                    votesForTarget = listOf(trustedVote, strangerVote),
                    votesByVoter = votesByVoter,
                    graph = graph,
                    localIdentity = local.publicKey,
                )

            // trustedVote: t=100, n=0 -> raw 100.0, full trust -> 100.0 contribution.
            // strangerVote: raw is large but NO_PATH -> 0.0 contribution.
            total shouldBe 100.0
        }

        test("personalizedKarmaForTarget with no votes is 0.0") {
            val local = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(emptyList())

            KarmaScoring.personalizedKarmaForTarget(emptyList(), { emptyList() }, graph, local) shouldBe 0.0
        }
    })
