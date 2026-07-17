package net.lapisphilosophorum.lapisnet.trust

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

class TrustPathFinderTest :
    FunSpec({
        test("canonical fixture: shortest-first + lexicographic tiebreak beats a higher-product longer path") {
            // The project's spec example: odin trusts frigg, thor, and nanna directly (all 2-hop
            // paths to freya). Nanna's path has the highest PRODUCT (0.6 * 0.9 = 0.54), but this
            // is deliberately NOT max-product selection - shortest-hop-first + lexicographic
            // first-hop dominance picks frigg's path instead (tied shortest at 2 hops, and frigg's
            // first hop 0.8 beats nanna's first hop 0.6).
            val odin = Secp256k1KeyPair.generate().publicKey
            val frigg = Secp256k1KeyPair.generate().publicKey
            val thor = Secp256k1KeyPair.generate().publicKey
            val nanna = Secp256k1KeyPair.generate().publicKey
            val freya = Secp256k1KeyPair.generate().publicKey

            val graph =
                TrustGraph.fromEdges(
                    listOf(
                        Triple(odin, frigg, 800_000),
                        Triple(frigg, freya, 500_000),
                        Triple(odin, thor, 800_000),
                        Triple(thor, freya, 200_000),
                        Triple(odin, nanna, 600_000),
                        Triple(nanna, freya, 900_000),
                    ),
                )

            val path = TrustPathFinder.findPath(graph, odin, freya)

            path.shouldNotBeNull()
            path.nodes shouldBe listOf(odin, frigg, freya)
            path.scoreMicros shouldBe 400_000 // 0.8 * 0.5, NOT nanna's higher-product 0.6 * 0.9 = 0.54
        }

        test("happy path: single hop") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(a, b, 700_000)))

            val path = TrustPathFinder.findPath(graph, a, b)

            path.shouldNotBeNull()
            path.nodes shouldBe listOf(a, b)
            path.scoreMicros shouldBe 700_000
        }

        test("multi-hop chain of three equal-weight edges truncates at each step") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val c = Secp256k1KeyPair.generate().publicKey
            val d = Secp256k1KeyPair.generate().publicKey
            val graph =
                TrustGraph.fromEdges(
                    listOf(
                        Triple(a, b, 500_000),
                        Triple(b, c, 500_000),
                        Triple(c, d, 500_000),
                    ),
                )

            val path = TrustPathFinder.findPath(graph, a, d)

            path.shouldNotBeNull()
            path.nodes shouldBe listOf(a, b, c, d)
            // 1_000_000 -> *500_000/1_000_000 = 500_000 -> *500_000/1_000_000 = 250_000
            // -> *500_000/1_000_000 = 125_000
            path.scoreMicros shouldBe 125_000
        }

        test("shortest-first: a 2-hop lower-product path shadows a 3-hop higher-product path") {
            val a = Secp256k1KeyPair.generate().publicKey
            val x = Secp256k1KeyPair.generate().publicKey
            val z = Secp256k1KeyPair.generate().publicKey
            val p = Secp256k1KeyPair.generate().publicKey
            val q = Secp256k1KeyPair.generate().publicKey
            val graph =
                TrustGraph.fromEdges(
                    listOf(
                        Triple(a, x, 300_000),
                        Triple(x, z, 300_000),
                        // 3-hop alternative with a much higher product (0.9 * 0.9 * 0.9 = 0.729)
                        Triple(a, p, 900_000),
                        Triple(p, q, 900_000),
                        Triple(q, z, 900_000),
                    ),
                )

            val path = TrustPathFinder.findPath(graph, a, z)

            path.shouldNotBeNull()
            path.nodes shouldBe listOf(a, x, z)
            path.scoreMicros shouldBe 90_000 // 0.3 * 0.3, despite the 3-hop path's higher 0.729 product
        }

        test("lexicographic first-hop dominance: higher first hop wins regardless of second hop") {
            val a = Secp256k1KeyPair.generate().publicKey
            val x = Secp256k1KeyPair.generate().publicKey
            val y = Secp256k1KeyPair.generate().publicKey
            val z = Secp256k1KeyPair.generate().publicKey
            val graph =
                TrustGraph.fromEdges(
                    listOf(
                        Triple(a, x, 900_000),
                        Triple(x, z, 100_000),
                        Triple(a, y, 800_000),
                        Triple(y, z, 999_000),
                    ),
                )

            val path = TrustPathFinder.findPath(graph, a, z)

            path.shouldNotBeNull()
            path.nodes shouldBe listOf(a, x, z) // x's first hop (0.9) beats y's (0.8) - product be damned
            path.scoreMicros shouldBe 90_000
        }

        test("lexicographic second-hop tiebreak: equal first hop, higher second hop wins") {
            val a = Secp256k1KeyPair.generate().publicKey
            val x = Secp256k1KeyPair.generate().publicKey
            val y = Secp256k1KeyPair.generate().publicKey
            val z = Secp256k1KeyPair.generate().publicKey
            val graph =
                TrustGraph.fromEdges(
                    listOf(
                        Triple(a, x, 700_000),
                        Triple(x, z, 300_000),
                        Triple(a, y, 700_000),
                        Triple(y, z, 600_000),
                    ),
                )

            val path = TrustPathFinder.findPath(graph, a, z)

            path.shouldNotBeNull()
            path.nodes shouldBe listOf(a, y, z)
            path.scoreMicros shouldBe 420_000
        }

        test("no path exists: target present in graph but unreachable from source") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val c = Secp256k1KeyPair.generate().publicKey
            val d = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(a, b, 500_000), Triple(c, d, 500_000)))

            TrustPathFinder.findPath(graph, a, d).shouldBeNull()
        }

        test("target completely unknown to the graph") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val unknown = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(a, b, 500_000)))

            TrustPathFinder.findPath(graph, a, unknown).shouldBeNull()
        }

        test("self-trust is axiomatic even when the source is isolated / absent from the graph") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(a, b, 500_000)))
            val stranger = Secp256k1KeyPair.generate().publicKey

            val selfPathKnown = TrustPathFinder.findPath(graph, a, a)
            val selfPathUnknown = TrustPathFinder.findPath(graph, stranger, stranger)

            selfPathKnown shouldBe TrustPath(listOf(a), MAX_TRUST_MICROS)
            selfPathKnown!!.scoreFraction shouldBe 1.0
            selfPathUnknown shouldBe TrustPath(listOf(stranger), MAX_TRUST_MICROS)
            selfPathUnknown!!.scoreFraction shouldBe 1.0
        }

        test("disconnected graph: no path between separate components") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val c = Secp256k1KeyPair.generate().publicKey
            val d = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(a, b, 500_000), Triple(c, d, 500_000)))

            TrustPathFinder.findPath(graph, a, c).shouldBeNull()
        }

        test("a zero-trust edge is a real hop: full path returned with scoreMicros 0") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val z = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(a, b, 0), Triple(b, z, 900_000)))

            val path = TrustPathFinder.findPath(graph, a, z)

            path.shouldNotBeNull()
            path.nodes shouldBe listOf(a, b, z)
            path.scoreMicros shouldBe 0
        }

        test("a shorter zero-trust path shadows a longer positive-score path (intended V0.1 semantics)") {
            // Shortest-first + single-winner + no-fallback means a 2-hop path with score 0 beats a
            // 3-hop path with a positive score, even though the 3-hop path is "more useful" in a
            // naive sense. This is intentional per the spec, not a bug: TrustPathFinder never
            // filters/skips zero-trust edges to hunt for a "better" alternative.
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val z = Secp256k1KeyPair.generate().publicKey
            val c = Secp256k1KeyPair.generate().publicKey
            val d = Secp256k1KeyPair.generate().publicKey
            val graph =
                TrustGraph.fromEdges(
                    listOf(
                        Triple(a, b, 0),
                        Triple(b, z, 900_000),
                        Triple(a, c, 700_000),
                        Triple(c, d, 800_000),
                        Triple(d, z, 600_000),
                    ),
                )

            val path = TrustPathFinder.findPath(graph, a, z)

            path.shouldNotBeNull()
            path.nodes shouldBe listOf(a, b, z)
            path.scoreMicros shouldBe 0
        }

        test("cycles are handled safely and terminate with the correct shortest path") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val c = Secp256k1KeyPair.generate().publicKey
            val graph =
                TrustGraph.fromEdges(
                    listOf(
                        Triple(a, b, 600_000),
                        Triple(b, a, 700_000), // cycle back to a
                        Triple(b, c, 500_000),
                    ),
                )

            val path = TrustPathFinder.findPath(graph, a, c)

            path.shouldNotBeNull()
            path.nodes shouldBe listOf(a, b, c)
            path.scoreMicros shouldBe 300_000 // 0.6 * 0.5
        }

        test("weight-sequence tie breaks on lexicographically-smaller node key bytes") {
            val a = Secp256k1KeyPair.generate().publicKey
            val x = Secp256k1KeyPair.generate().publicKey
            val y = Secp256k1KeyPair.generate().publicKey
            val z = Secp256k1KeyPair.generate().publicKey
            val graph =
                TrustGraph.fromEdges(
                    listOf(
                        Triple(a, x, 800_000),
                        Triple(x, z, 500_000),
                        Triple(a, y, 800_000),
                        Triple(y, z, 500_000),
                    ),
                )

            val expectedWinner =
                if (Secp256k1PublicKeyBytesComparator.compare(x, y) < 0) x else y

            val path = TrustPathFinder.findPath(graph, a, z)

            path.shouldNotBeNull()
            path.nodes shouldBe listOf(a, expectedWinner, z)
            path.scoreMicros shouldBe 400_000
        }

        test("determinism: identical result regardless of input edge order") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val c = Secp256k1KeyPair.generate().publicKey
            val d = Secp256k1KeyPair.generate().publicKey
            val edges =
                listOf(
                    Triple(a, b, 800_000),
                    Triple(b, d, 500_000),
                    Triple(a, c, 800_000),
                    Triple(c, d, 500_000),
                )

            val graph1 = TrustGraph.fromEdges(edges)
            val graph2 = TrustGraph.fromEdges(edges.shuffled(java.util.Random(42)))

            val path1 = TrustPathFinder.findPath(graph1, a, d)
            val path2 = TrustPathFinder.findPath(graph2, a, d)

            path1.shouldNotBeNull()
            path2.shouldNotBeNull()
            path1.nodes shouldBe path2.nodes
            path1.scoreMicros shouldBe path2.scoreMicros
        }

        test("trustMicros convenience returns 0 when unreachable, and the correct score otherwise") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val unreachable = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(a, b, 650_000)))

            TrustPathFinder.trustMicros(graph, a, b) shouldBe 650_000
            TrustPathFinder.trustMicros(graph, a, unreachable) shouldBe 0
        }

        test("truncation direction / Long-overflow trap") {
            val a = Secp256k1KeyPair.generate().publicKey
            val b = Secp256k1KeyPair.generate().publicKey
            val z = Secp256k1KeyPair.generate().publicKey
            val graph = TrustGraph.fromEdges(listOf(Triple(a, b, 333_333), Triple(b, z, 500_000)))

            // acc = 1_000_000L; acc = 1_000_000 * 333_333 / 1_000_000 = 333_333;
            // acc = 333_333 * 500_000 / 1_000_000 = 166_666 (truncated down from 166_666.5).
            // Note the intermediate product 333_333 * 500_000 = 166_666_500_000 exceeds
            // Int.MAX_VALUE (~2.1 * 10^9) - this is exactly the Long-overflow trap productMicros
            // must avoid by using a Long accumulator.
            val path = TrustPathFinder.findPath(graph, a, z)

            path.shouldNotBeNull()
            path.scoreMicros shouldBe 166_666
        }

        // --- MAX_HOP_DEPTH cap ---------------------------------------------------------------

        test("MAX_HOP_DEPTH boundary: a path of exactly MAX_HOP_DEPTH hops is found") {
            val weight = 900_000
            val chain = buildLinearChain(TrustPathFinder.MAX_HOP_DEPTH, weight)

            val path = TrustPathFinder.findPath(chain.graph, chain.nodes.first(), chain.nodes.last())

            path.shouldNotBeNull()
            path.nodes shouldBe chain.nodes
            path.hops shouldBe TrustPathFinder.MAX_HOP_DEPTH
            path.scoreMicros shouldBe expectedChainScoreMicros(weight, TrustPathFinder.MAX_HOP_DEPTH)
        }

        test("MAX_HOP_DEPTH boundary: a path requiring more than MAX_HOP_DEPTH hops returns null") {
            val weight = 900_000
            // One hop longer than the previous test's exactly-at-the-cap chain.
            val chain = buildLinearChain(TrustPathFinder.MAX_HOP_DEPTH + 1, weight)

            // The true shortest path to the last node exists in principle (MAX_HOP_DEPTH + 1 hops)
            // but exceeds the bound, so it must be treated as "no path found", not discovered anyway.
            TrustPathFinder.findPath(chain.graph, chain.nodes.first(), chain.nodes.last()).shouldBeNull()

            // The node exactly at the cap boundary, in that SAME larger graph, must still be found -
            // proves the cap stops the search rather than the graph itself being unreachable/broken.
            val atCapTarget = chain.nodes[TrustPathFinder.MAX_HOP_DEPTH]
            val atCap = TrustPathFinder.findPath(chain.graph, chain.nodes.first(), atCapTarget)
            atCap.shouldNotBeNull()
            atCap.hops shouldBe TrustPathFinder.MAX_HOP_DEPTH
        }

        // --- Quadratic-blowup regression (predecessor-pointer refactor) ----------------------

        test("quadratic-blowup fix: a few-thousand-node chain still yields the correct in-bound path") {
            // Before the refactor, TrustPathFinder.findPath carried a full copy of the path-so-far
            // (node list + weight list) at every node reached during BFS - for a plain linear chain,
            // total live memory across a single query was O(1+2+...+L) = O(L^2) in the query's hop
            // distance L, and building each successive candidate was itself an O(L) list
            // concatenation, repeated per edge examined. The fix replaces that with an O(1)-per-node
            // predecessor pointer (see NodeState in TrustPathFinder.kt), reconstructing the full
            // path exactly once at the end - so per-query memory is now O(nodes reached), not
            // O(nodes reached * hop distance). This test is a functional correctness check at scale
            // (thousands of graph nodes, MAX_HOP_DEPTH-deep query), not a timing benchmark - per the
            // wave's own guidance, the complexity argument above is the actual evidence for the fix;
            // a wall-clock assertion here would only be flaky.
            val weight = 750_000
            val nodeCount = 3_000 // comfortably under TrustGraph.MAX_NODES (8_000)
            val chain = buildLinearChain(nodeCount - 1, weight)

            // Query a target well within MAX_HOP_DEPTH, even though the underlying graph the BFS
            // must be built over/reachable-from has thousands of nodes beyond it.
            val nearTarget = chain.nodes[TrustPathFinder.MAX_HOP_DEPTH]
            val path = TrustPathFinder.findPath(chain.graph, chain.nodes.first(), nearTarget)

            path.shouldNotBeNull()
            path.nodes shouldBe chain.nodes.subList(0, TrustPathFinder.MAX_HOP_DEPTH + 1)
            path.hops shouldBe TrustPathFinder.MAX_HOP_DEPTH
            path.scoreMicros shouldBe expectedChainScoreMicros(weight, TrustPathFinder.MAX_HOP_DEPTH)

            // The far end of the same (large) graph is beyond MAX_HOP_DEPTH from the source, so it
            // must correctly come back null rather than hang, crash, or exhaust memory.
            TrustPathFinder.findPath(chain.graph, chain.nodes.first(), chain.nodes.last()).shouldBeNull()
        }

        // --- 3+-hop branching tiebreak (round-2 review coverage gap) --------------------------

        test("3-hop tiebreak: first-hop weight wins over a much higher later-hop product") {
            // All existing tiebreak tests before this one were 2-hop, which only ever exercises
            // ONE level of betterOf's "earlierHops != 0 -> short-circuit, else fall through to this
            // level's own weight" recursion (compareWeightChains/compareNodeChains bottom out at
            // the source in a single recursive call for a 2-hop path). A comparator bug that
            // "only compares one level" instead of correctly recursing the FULL predecessor chain
            // could still pass every 2-hop test by coincidence. This test uses two DISTINCT 3-hop
            // paths (source -> x1 -> x2 -> target, source -> y1 -> y2 -> target) whose first hops
            // differ (0.9 vs 0.8) but whose LATER hops go the opposite direction - x's path has a
            // vastly lower product (0.9 * 0.1 * 0.1 = 0.009) than y's (0.8 * 0.999 * 0.999 =~
            // 0.798) - so only a comparator that correctly recurses all the way back to the source
            // before ever looking at a later hop picks x's path, exactly as the spec requires
            // (shortest-first, then lexicographic-from-source, deliberately NOT max-product).
            val source = Secp256k1KeyPair.generate().publicKey
            val x1 = Secp256k1KeyPair.generate().publicKey
            val x2 = Secp256k1KeyPair.generate().publicKey
            val y1 = Secp256k1KeyPair.generate().publicKey
            val y2 = Secp256k1KeyPair.generate().publicKey
            val target = Secp256k1KeyPair.generate().publicKey
            val graph =
                TrustGraph.fromEdges(
                    listOf(
                        Triple(source, x1, 900_000),
                        Triple(x1, x2, 100_000),
                        Triple(x2, target, 100_000),
                        Triple(source, y1, 800_000),
                        Triple(y1, y2, 999_000),
                        Triple(y2, target, 999_000),
                    ),
                )

            val path = TrustPathFinder.findPath(graph, source, target)

            path.shouldNotBeNull()
            path.nodes shouldBe listOf(source, x1, x2, target) // x's 0.9 first hop wins, product be damned
            path.hops shouldBe 3
            // 1_000_000 -> *900_000/1_000_000 = 900_000 -> *100_000/1_000_000 = 90_000
            // -> *100_000/1_000_000 = 9_000
            path.scoreMicros shouldBe 9_000
        }

        // --- Bipartite tie-layer regression (round-2 DoS constant-factor finding) -------------

        test("bipartite tie-layer: all-tied weights still resolve to the correct node-byte-tiebreak winner") {
            // Scaled-down permanent regression for the round-2 security auditor's adversarial
            // construction (source -> full P layer -> full T layer, every edge the SAME weight, so
            // every betterOf comparison ties on weight and must fall through to the node-byte
            // tiebreak). The auditor's full-scale version (P=T=446, ~199,362 edges, just under the
            // OLD 200,000-edge cap) cost several hundred ms per query; this is a few-hundred-node
            // version that stays well within real production caps (see TrustGraph.MAX_EDGES) and
            // asserts CORRECTNESS, not just "doesn't crash/hang": with every weight tied, the
            // winning path must be the one through the P-layer node with the lexicographically
            // smallest key bytes (per Secp256k1PublicKeyBytesComparator, the same tiebreak
            // production code uses) - computed independently here at runtime, not hardcoded, per
            // this file's no-mocking/no-hardcoded-winner style throughout.
            val pLayerSize = 150
            val tLayerSize = 150
            val source = Secp256k1KeyPair.generate().publicKey
            val pLayer = List(pLayerSize) { Secp256k1KeyPair.generate().publicKey }
            val tLayer = List(tLayerSize) { Secp256k1KeyPair.generate().publicKey }
            val edges = mutableListOf<Triple<Secp256k1PublicKey, Secp256k1PublicKey, Int>>()
            for (p in pLayer) edges += Triple(source, p, 500_000)
            for (p in pLayer) for (t in tLayer) edges += Triple(p, t, 500_000)
            val graph = TrustGraph.fromEdges(edges)
            val target = tLayer.first()

            val expectedWinner = pLayer.minWith(Secp256k1PublicKeyBytesComparator)

            // Generous smoke-level wall-clock guard, not a tight performance assertion: this
            // project prefers non-flaky tests, so 2 seconds is chosen to be comfortably above any
            // plausible steady-state cost on slow/loaded CI hardware while still catching a genuine
            // regression back toward the round-2 finding's several-hundred-ms-per-query cost (let
            // alone the pre-refactor O(N^2) quadratic blowup this whole wave started from).
            val start = System.nanoTime()
            val path = TrustPathFinder.findPath(graph, source, target)
            val elapsedMs = (System.nanoTime() - start) / 1_000_000

            path.shouldNotBeNull()
            path.nodes shouldBe listOf(source, expectedWinner, target)
            path.scoreMicros shouldBe 250_000 // 0.5 * 0.5, all weights tied
            (elapsedMs < 2_000) shouldBe true
        }

        test("integration: fromGrants and fromEdges agree on the same 2-hop path") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()
            val z = Secp256k1KeyPair.generate()
            val grantAb = VeritasGrant.create(a, b.publicKey, trustMicros = 750_000)
            val grantBz = VeritasGrant.create(b, z.publicKey, trustMicros = 400_000)

            val grantGraph = TrustGraph.fromGrants(listOf(grantAb, grantBz))
            val edgeGraph =
                TrustGraph.fromEdges(
                    listOf(
                        Triple(a.publicKey, b.publicKey, 750_000),
                        Triple(b.publicKey, z.publicKey, 400_000),
                    ),
                )

            val fromGrantsPath = TrustPathFinder.findPath(grantGraph, a.publicKey, z.publicKey)
            val fromEdgesPath = TrustPathFinder.findPath(edgeGraph, a.publicKey, z.publicKey)

            fromGrantsPath.shouldNotBeNull()
            fromGrantsPath shouldBe fromEdgesPath
        }
    })

/** A linear chain graph `nodes[0] -> nodes[1] -> ... -> nodes[hopCount]`, every edge weighted
 * [LinearChain] uniformly, built once and reused by the [MAX_HOP_DEPTH][TrustPathFinder.MAX_HOP_DEPTH]
 * and quadratic-blowup-regression tests below. */
private class LinearChain(
    val graph: TrustGraph,
    val nodes: List<Secp256k1PublicKey>,
)

/** Builds a real [hopCount]-edge (so `hopCount + 1`-node) linear chain with [weightMicros] on every
 * edge, using real generated keys (matching this file's no-mocking style throughout). */
private fun buildLinearChain(
    hopCount: Int,
    weightMicros: Int,
): LinearChain {
    val nodes = (0..hopCount).map { Secp256k1KeyPair.generate().publicKey }
    val edges = (0 until hopCount).map { i -> Triple(nodes[i], nodes[i + 1], weightMicros) }
    return LinearChain(TrustGraph.fromEdges(edges), nodes)
}

/** Independently computes the truncating-product score [TrustPathFinder.productMicros] would
 * produce for [hopCount] hops all weighted [weightMicros] - mirrors its truncate-per-step Long
 * arithmetic so the new-algorithm tests assert an actually-verified score, not a guessed constant. */
private fun expectedChainScoreMicros(
    weightMicros: Int,
    hopCount: Int,
): Int {
    var acc = MAX_TRUST_MICROS.toLong()
    repeat(hopCount) { acc = acc * weightMicros / MAX_TRUST_MICROS }
    return acc.toInt()
}
