package net.lapisphilosophorum.lapisnet.trust

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

class TrustGraphTest :
    FunSpec({
        test("fromGrants builds correct nodes/edges from real signed grants") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()
            val c = Secp256k1KeyPair.generate()
            val grantAb = VeritasGrant.create(a, b.publicKey, trustMicros = 700_000)
            val grantBc = VeritasGrant.create(b, c.publicKey, trustMicros = 400_000)

            val graph = TrustGraph.fromGrants(listOf(grantAb, grantBc))

            graph.nodes shouldBe setOf(a.publicKey, b.publicKey, c.publicKey)
            graph.edgesFrom(a.publicKey) shouldContainExactly listOf(TrustGraph.Edge(b.publicKey, 700_000))
            graph.edgesFrom(b.publicKey) shouldContainExactly listOf(TrustGraph.Edge(c.publicKey, 400_000))
        }

        test("fromGrants throws IllegalArgumentException on duplicate (truster, target)") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val first = VeritasGrant.create(truster, target, trustMicros = 300_000)
            val second = VeritasGrant.create(truster, target, trustMicros = 900_000, previous = first)

            shouldThrow<IllegalArgumentException> {
                TrustGraph.fromGrants(listOf(first, second))
            }
        }

        test("fromEdges throws IllegalArgumentException on duplicate (truster, target)") {
            val truster = Secp256k1KeyPair.generate().publicKey
            val target = Secp256k1KeyPair.generate().publicKey

            shouldThrow<IllegalArgumentException> {
                TrustGraph.fromEdges(
                    listOf(
                        Triple(truster, target, 300_000),
                        Triple(truster, target, 900_000),
                    ),
                )
            }
        }

        test("fromEdges drops a self-grant edge, but keeps the node if it appears elsewhere") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey

            val graph = TrustGraph.fromEdges(listOf(Triple(a, a, 500_000), Triple(a, b, 600_000)))

            graph.edgesFrom(a) shouldContainExactly listOf(TrustGraph.Edge(b, 600_000))
            graph.nodes shouldBe setOf(a, b)
        }

        test("fromEdges drops a self-grant edge entirely when the node appears nowhere else") {
            val a = Secp256k1KeyPair.generate().publicKey

            val graph = TrustGraph.fromEdges(listOf(Triple(a, a, 500_000)))

            graph.nodes.shouldBeEmpty()
            graph.edgesFrom(a).shouldBeEmpty()
            (a in graph) shouldBe false
        }

        test("fromGrants drops a self-grant edge (truster == target)") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()
            val selfGrant = VeritasGrant.create(a, a.publicKey, trustMicros = 500_000)
            val realGrant = VeritasGrant.create(a, b.publicKey, trustMicros = 600_000)

            val graph = TrustGraph.fromGrants(listOf(selfGrant, realGrant))

            graph.edgesFrom(a.publicKey) shouldContainExactly listOf(TrustGraph.Edge(b.publicKey, 600_000))
        }

        test("fromEdges throws on out-of-range trustMicros") {
            val truster = Secp256k1KeyPair.generate().publicKey
            val target = Secp256k1KeyPair.generate().publicKey

            shouldThrow<IllegalArgumentException> {
                TrustGraph.fromEdges(listOf(Triple(truster, target, -1)))
            }
            shouldThrow<IllegalArgumentException> {
                TrustGraph.fromEdges(listOf(Triple(truster, target, MAX_TRUST_MICROS + 1)))
            }
        }

        test("contains is true for known nodes and false for unknown ones") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val unknown = Secp256k1KeyPair.generate().publicKey

            val graph = TrustGraph.fromEdges(listOf(Triple(a, b, 500_000)))

            (a in graph) shouldBe true
            (b in graph) shouldBe true
            (unknown in graph) shouldBe false
        }

        test("edgesFrom an unknown node returns an empty list") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val unknown = Secp256k1KeyPair.generate().publicKey

            val graph = TrustGraph.fromEdges(listOf(Triple(a, b, 500_000)))

            graph.edgesFrom(unknown).shouldBeEmpty()
        }

        // --- Defense-in-depth caps (MAX_NODES / MAX_EDGES) ---------------------------------------
        // The real TrustGraph.MAX_NODES/MAX_EDGES are deliberately generous (tens of thousands), so
        // hitting them literally would mean generating tens of thousands of real secp256k1 keys per
        // test - slow and pointless just to prove the `require()` fires. TrustGraph.build's internal
        // (test-only) maxNodes/maxEdges overload lets us exercise the exact same cap-enforcement
        // logic with a tiny, fast threshold instead.

        test("build throws IllegalArgumentException when the node count exceeds maxNodes") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val c = Secp256k1KeyPair.generate().publicKey
            // 2 nodes is fine under a cap of 2; adding a third distinct node must trip the cap.
            TrustGraph.build(listOf(Triple(a, b, 500_000)), maxNodes = 2)

            shouldThrow<IllegalArgumentException> {
                TrustGraph.build(listOf(Triple(a, b, 500_000), Triple(b, c, 500_000)), maxNodes = 2)
            }
        }

        test("build throws IllegalArgumentException when the edge count exceeds maxEdges") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val c = Secp256k1KeyPair.generate().publicKey
            // 1 edge is fine under a cap of 1; a second distinct edge must trip the cap.
            TrustGraph.build(listOf(Triple(a, b, 500_000)), maxEdges = 1)

            shouldThrow<IllegalArgumentException> {
                TrustGraph.build(listOf(Triple(a, b, 500_000), Triple(a, c, 500_000)), maxEdges = 1)
            }
        }

        test("fromGrants and fromEdges use the real MAX_NODES/MAX_EDGES defaults") {
            // Sanity-check the public factories actually wire the production constants through
            // build's default parameters, without needing to construct that many real keys.
            // Values tightened in the round-2 DoS-constant-factor fix (see TrustGraph.MAX_EDGES's
            // doc comment) - was 50_000 / 200_000 before that fix.
            TrustGraph.MAX_NODES shouldBe 8_000
            TrustGraph.MAX_EDGES shouldBe 32_000

            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            TrustGraph.fromEdges(listOf(Triple(a, b, 500_000))).nodes shouldBe setOf(a, b)
        }
    })
