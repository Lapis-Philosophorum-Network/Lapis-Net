package net.lapisphilosophorum.lapisnet.trust

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Computes the transitive Veritas trust score + winning path from a source to a target over a
 * [TrustGraph], per the path-selection spec:
 *   1. Transitivity is multiplicative (path score = product of edge weights).
 *   2. Selection: (a) only shortest (fewest-hop) paths, (b) among those the lexicographically-
 *      greatest hop-weight sequence FROM THE SOURCE (highest first hop; ties -> second hop; ...).
 *      Deliberately NOT max-product - a strong near edge beats a clever far construct.
 * Single winner only: no aggregation, no alternative-path fallback (V0.1 decision).
 *
 * Level-synchronous BFS (shortest = fewest hops => BFS, not Dijkstra), carrying a PREDECESSOR
 * POINTER per node - the winning predecessor node plus the single edge weight into that node -
 * rather than a full copy of the path-so-far. That is O(1) bookkeeping per node, not O(hop
 * distance): grants cost nothing to issue and can target arbitrarily many identities (see
 * [VeritasGrant]'s doc comment), so a self-signed linear chain of N grants that becomes reachable
 * from a query's source would, under a "copy the whole path-so-far at every node" approach, cost
 * O(N^2) time and memory for a single query touching it. The winning node/weight sequence is
 * reconstructed exactly ONCE - by walking predecessor pointers back from the target to the source
 * after BFS finds it - never eagerly per edge examined. Cycles are safe: each node finalized once,
 * at its shortest distance. [MAX_HOP_DEPTH] additionally hard-bounds worst-case cost outright
 * regardless of graph shape - see its doc comment - and [TrustGraph.MAX_NODES]/[TrustGraph.MAX_EDGES]
 * bound the graph itself.
 *
 * **Constant-factor note (round-2 security re-audit).** The predecessor-pointer design above is
 * asymptotically `O(edges * MAX_HOP_DEPTH)` - confirmed correct by an independent hand-trace - but
 * an adversarial ALL-TIED graph (every edge the same weight, so [betterOf] never short-circuits on
 * a weight difference and must recurse [compareWeightChains]/[compareNodeChains] all the way back
 * to the source on every comparison) drives the constant factor toward that full bound rather than
 * the typical case. Two changes address this without touching the recursive comparator design
 * itself (which stays as hand-verified): (1) [Secp256k1PublicKey.hashCode] is cached rather than
 * recomputed on every `best.getValue(...)` lookup in the hot recursive path, and (2)
 * [TrustGraph.MAX_NODES]/[TrustGraph.MAX_EDGES] were tightened specifically so that even a
 * worst-case all-tied construction sized right up to the caps stays comfortably bounded in wall-
 * clock terms - see those constants' doc comments for the re-measured numbers.
 */
object TrustPathFinder {
    /**
     * Hard cap on the number of hops a returned path may have. Trust decays multiplicatively per
     * hop (see this object's doc comment), so a path beyond a modest hop count is already so close
     * to zero as to be practically meaningless even under generous assumptions: a chain of edges
     * every one of which is trusted at a generous 0.9 already decays to 0.9^20 =~ 0.12 by hop 20,
     * and real-world trust chains will rarely stay that strong for that long. This is a legitimate
     * modeling bound, not just a defensive hack - but as a side effect it also hard-bounds the BFS's
     * worst-case work regardless of how large or deep the underlying reachable graph is, complementing
     * [TrustGraph.MAX_NODES]/[TrustGraph.MAX_EDGES]'s bound on the graph itself.
     */
    const val MAX_HOP_DEPTH = 20

    fun findPath(
        graph: TrustGraph,
        source: Secp256k1PublicKey,
        target: Secp256k1PublicKey,
    ): TrustPath? {
        // Self-trust axiom short-circuits before any graph lookup - works even for an
        // isolated/unknown source, since there is no edge to traverse at all.
        if (source == target) return TrustPath(listOf(source), MAX_TRUST_MICROS)
        if (source !in graph) return null

        val best = mutableMapOf(source to NodeState(predecessor = null, weight = MIN_TRUST_MICROS))
        val visited = mutableSetOf(source)
        var frontier = listOf(source)
        var depth = 0

        while (frontier.isNotEmpty()) {
            // One more level would exceed the hop cap - stop; treated the same as "exhausted the
            // reachable graph" below, i.e. no path found within the bound.
            if (depth >= MAX_HOP_DEPTH) break

            // Phase A - discover the next level, accumulating ALL current-frontier predecessors of
            // each candidate node before finalizing anything. This is what makes the tiebreak
            // correct: if we committed a node's winner as soon as the first predecessor reached it,
            // a later (possibly lexicographically better) predecessor in the same frontier would be
            // skipped and the true winner silently dropped.
            val candidates = HashMap<Secp256k1PublicKey, NodeState>()
            for (u in frontier) {
                for (edge in graph.edgesFrom(u)) {
                    if (edge.target in visited) continue
                    val candidate = NodeState(predecessor = u, weight = edge.trustMicros)
                    candidates[edge.target] =
                        candidates[edge.target]?.let { betterOf(best, it, candidate) } ?: candidate
                }
            }
            if (candidates.isEmpty()) break // exhausted the reachable graph - unreachable

            // Phase B - finalize this level. `visited` is updated HERE, never in Phase A - see above.
            for ((node, state) in candidates) {
                best[node] = state
                visited += node
            }
            depth++

            if (target in candidates) {
                val (nodes, weights) = reconstructPath(best, target)
                return TrustPath(nodes, productMicros(weights))
            }
            frontier = candidates.keys.toList() // iteration order irrelevant: betterOf is a total order
        }
        return null
    }

    /** Convenience: winning score, or [MIN_TRUST_MICROS] (0) when no path exists. */
    fun trustMicros(
        graph: TrustGraph,
        source: Secp256k1PublicKey,
        target: Secp256k1PublicKey,
    ): Int = findPath(graph, source, target)?.scoreMicros ?: MIN_TRUST_MICROS

    /**
     * A node's winning predecessor pointer during BFS: [predecessor] is the previous node on the
     * winning path (`null` ONLY for the source's own entry in `best`), and [weight] is the single
     * edge weight from [predecessor] into this node (meaningless/unused when [predecessor] is
     * `null`, since the source has no incoming edge). O(1) size regardless of a node's distance from
     * the source - this is what replaces the old approach's eager `nodes: List<...>` /
     * `weights: List<Int>` copies, which were duplicated in full at every node reached.
     */
    private data class NodeState(
        val predecessor: Secp256k1PublicKey?,
        val weight: Int,
    )

    /**
     * Returns the winning [NodeState] of two same-depth candidates [a]/[b] competing for the same
     * node (total order): weights lexicographically DESCENDING (source-first significance), then -
     * on a full weight tie - node-key bytes ASCENDING (source-first significance). Resolves the
     * comparison by walking the predecessor-pointer chains of already-finalized entries in [best] -
     * see [compareWeightChains]/[compareNodeChains] - rather than by comparing pre-materialized
     * arrays.
     */
    private fun betterOf(
        best: Map<Secp256k1PublicKey, NodeState>,
        a: NodeState,
        b: NodeState,
    ): NodeState {
        val weightComparison = compareWeightChains(best, a, b)
        if (weightComparison != 0) return if (weightComparison > 0) a else b
        // All weights equal all the way back to source - distinct shortest paths differ in at least
        // one node, so this always resolves before falling through.
        val nodeComparison = compareNodeChains(best, a, b)
        return when {
            nodeComparison < 0 -> a
            nodeComparison > 0 -> b
            else ->
                // Genuinely unreachable given TrustGraph.build's current invariants: it dedups
                // edges per (truster, target) pair (`seen.add(truster to target)`), so two distinct
                // predecessors can never both reach the same target via a node-chain that compares
                // equal all the way back to source - that would require two identical paths, which
                // can't both be distinct candidates for the same node. If a future change to
                // TrustGraph's dedup/construction logic ever weakens that guarantee, silently
                // returning `a` here would pick an arbitrary winner instead of surfacing the broken
                // invariant - fail loudly instead.
                error(
                    "betterOf: two distinct same-depth candidates tied on every weight AND every " +
                        "node-key byte all the way back to source - this should be impossible under " +
                        "TrustGraph.build's per-(truster, target) edge dedup invariant; that " +
                        "invariant appears to have been violated",
                )
        }
    }

    /**
     * Compares the FULL hop-weight sequences (from the source, most-significant/earliest hop first)
     * of the paths ending at [a] and [b] - both same-depth [NodeState]s, either finalized [best]
     * entries or provisional (not-yet-finalized) candidates whose predecessor chain is already
     * finalized. Recurses toward the source first, so the earliest hop is compared first with early
     * exit as soon as a difference is found on the way back up, and only compares this level's own
     * (least significant, last) edge weight once every earlier hop has tied. Positive => [a] wins,
     * negative => [b] wins, 0 => every hop weight matches all the way back to source.
     */
    private fun compareWeightChains(
        best: Map<Secp256k1PublicKey, NodeState>,
        a: NodeState,
        b: NodeState,
    ): Int {
        val aPredecessor = a.predecessor ?: return 0 // source has no incoming edge to compare
        val bPredecessor = requireNotNull(b.predecessor) { "same-depth candidates must both reach the source together" }
        val earlierHops = compareWeightChains(best, best.getValue(aPredecessor), best.getValue(bPredecessor))
        return if (earlierHops != 0) earlierHops else a.weight - b.weight
    }

    /**
     * As [compareWeightChains], but compares node-key-bytes sequences (ascending, source-first
     * significance) instead of weights - the tiebreak fallback used only once every hop weight has
     * already tied.
     */
    private fun compareNodeChains(
        best: Map<Secp256k1PublicKey, NodeState>,
        a: NodeState,
        b: NodeState,
    ): Int {
        val aPredecessor = a.predecessor ?: return 0
        val bPredecessor = requireNotNull(b.predecessor) { "same-depth candidates must both reach the source together" }
        val earlierHops = compareNodeChains(best, best.getValue(aPredecessor), best.getValue(bPredecessor))
        return if (earlierHops != 0) {
            earlierHops
        } else {
            Secp256k1PublicKeyBytesComparator.compare(aPredecessor, bPredecessor)
        }
    }

    /**
     * Reconstructs the winning node/weight sequence exactly ONCE, by walking predecessor pointers
     * backward from [target] to the source and reversing - the only place in [findPath] a full path
     * list is ever materialized, and only for the single winning path. `nodes` is source..target
     * inclusive; `weights` has one fewer entry (the per-hop edge weights, in source-to-target order).
     */
    private fun reconstructPath(
        best: Map<Secp256k1PublicKey, NodeState>,
        target: Secp256k1PublicKey,
    ): Pair<List<Secp256k1PublicKey>, List<Int>> {
        val nodes = mutableListOf<Secp256k1PublicKey>()
        val weights = mutableListOf<Int>()
        var current = target
        while (true) {
            nodes += current
            val state = best.getValue(current)
            val predecessor = state.predecessor ?: break
            weights += state.weight
            current = predecessor
        }
        nodes.reverse()
        weights.reverse()
        return nodes to weights
    }

    /** Product of [weights] in the micros domain, truncating each step. Empty -> [MAX_TRUST_MICROS]. */
    private fun productMicros(weights: List<Int>): Int {
        // Two values up to MAX_TRUST_MICROS (1_000_000) multiply to up to 10^12, far past
        // Int.MAX_VALUE (~2.1*10^9) - the intermediate accumulator MUST be Long.
        var acc = MAX_TRUST_MICROS.toLong()
        for (weight in weights) {
            acc = acc * weight / MAX_TRUST_MICROS
        }
        return acc.toInt()
    }
}
