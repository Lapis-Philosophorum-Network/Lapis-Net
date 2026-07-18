package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.trust.MAX_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant

class CredibilityCalculatorTest :
    FunSpec({
        test("an empty graph and an unrelated author resolve to NO_PATH") {
            val local = Secp256k1KeyPair.generate().publicKey
            val author = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(emptyList())

            val credibility = CredibilityCalculator.credibility(graph, local, author)

            credibility.level shouldBe CredibilityLevel.NO_PATH
        }

        test("a self-authored post (author == localIdentity) resolves to RESOLVED at full self-trust") {
            val local = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(emptyList())

            val credibility = CredibilityCalculator.credibility(graph, local, author = local)

            // TrustPathFinder.findPath's self-trust axiom short-circuits before any graph lookup,
            // even for an isolated/unknown source - see that function's doc comment. Verified here
            // rather than assumed: this is exactly the kind of real API behavior the plan asked to
            // check instead of guessing.
            credibility.level shouldBe CredibilityLevel.RESOLVED
            credibility.scoreMicros shouldBe MAX_TRUST_MICROS
        }

        test("a real resolved path with a positive score resolves to RESOLVED with that exact score") {
            val local = Secp256k1KeyPair.generate()
            val author = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster = local, target = author, trustMicros = 700_000)
            val graph = TrustGraph.fromGrants(listOf(grant))

            val credibility = CredibilityCalculator.credibility(graph, local.publicKey, author)

            credibility.level shouldBe CredibilityLevel.RESOLVED
            credibility.scoreMicros shouldBe 700_000
        }

        test(
            "a resolved path whose winning score is exactly 0 produces RESOLVED(0), NOT NO_PATH - " +
                "the single most important test in this file",
        ) {
            val local = Secp256k1KeyPair.generate()
            val author = Secp256k1KeyPair.generate().publicKey
            // A REAL VeritasGrant with trustMicros = 0 (Veritas's own documented default/active-
            // distrust value, MIN_TRUST_MICROS) - genuinely constructed, not faked - so the trust
            // graph actually contains a resolvable edge whose score happens to be zero.
            val grant = VeritasGrant.create(truster = local, target = author, trustMicros = 0)
            val graph = TrustGraph.fromGrants(listOf(grant))

            val credibility = CredibilityCalculator.credibility(graph, local.publicKey, author)

            credibility.level shouldBe CredibilityLevel.RESOLVED
            credibility.scoreMicros shouldBe 0
        }

        test("a confirmers list with a higher-scoring path than the direct author picks the max") {
            val local = Secp256k1KeyPair.generate()
            val author = Secp256k1KeyPair.generate().publicKey
            val confirmer = Secp256k1KeyPair.generate().publicKey
            val grantToAuthor = VeritasGrant.create(truster = local, target = author, trustMicros = 100_000)
            val grantToConfirmer = VeritasGrant.create(truster = local, target = confirmer, trustMicros = 900_000)
            val graph = TrustGraph.fromGrants(listOf(grantToAuthor, grantToConfirmer))

            val credibility = CredibilityCalculator.credibility(graph, local.publicKey, author, listOf(confirmer))

            credibility.level shouldBe CredibilityLevel.RESOLVED
            credibility.scoreMicros shouldBe 900_000
        }

        test("an author with no path but a confirmer with a resolved path still resolves via the confirmer") {
            val local = Secp256k1KeyPair.generate()
            val author = Secp256k1KeyPair.generate().publicKey
            val confirmer = Secp256k1KeyPair.generate().publicKey
            val grantToConfirmer = VeritasGrant.create(truster = local, target = confirmer, trustMicros = 500_000)
            val graph = TrustGraph.fromGrants(listOf(grantToConfirmer))

            val credibility = CredibilityCalculator.credibility(graph, local.publicKey, author, listOf(confirmer))

            credibility.level shouldBe CredibilityLevel.RESOLVED
            credibility.scoreMicros shouldBe 500_000
        }
    })
