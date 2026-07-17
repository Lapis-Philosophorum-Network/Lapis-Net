package net.lapisphilosophorum.lapisnet.trust

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Immutable in-memory directed trust graph. Nodes are identities (secp256k1 public keys); a
 * directed edge truster -> target with weight trustMicros means "truster trusts target to
 * trustMicros millionths". Built from an ALREADY-RESOLVED edge set: exactly one latest grant per
 * (truster, target) pair. Resolving each version chain to its latest grant, and fetching grants
 * from storage, is V0.1.7's job - not this graph's. Pure data; pathfinding lives in
 * [TrustPathFinder].
 */
class TrustGraph private constructor(
    private val adjacency: Map<Secp256k1PublicKey, List<Edge>>,
    val nodes: Set<Secp256k1PublicKey>,
) {
    /** A single outgoing trust edge to [target] with fixed-point weight [trustMicros] (0..1_000_000). */
    internal data class Edge(
        val target: Secp256k1PublicKey,
        val trustMicros: Int,
    )

    /** Outgoing edges from [node] in a deterministic (target-key-sorted) order; empty if unknown. */
    internal fun edgesFrom(node: Secp256k1PublicKey): List<Edge> = adjacency[node] ?: emptyList()

    /** True iff [node] appears (as truster or target) anywhere in the graph. */
    operator fun contains(node: Secp256k1PublicKey): Boolean = node in nodes

    companion object {
        /**
         * Upper bound on distinct identities (nodes) a single [TrustGraph] may contain. Veritas
         * grants cost nothing to issue and can be issued to arbitrarily many targets arbitrarily
         * often (see [VeritasGrant]'s doc comment), and [fromGrants]/[fromEdges] otherwise accept a
         * [Collection] of unbounded size - so an attacker who wants to grow a victim's local graph
         * needs only one gossiped edge into it (a later wave's concern, not this one). This cap is
         * what stops that from growing this node's heap, and the [TrustPathFinder] BFS's work,
         * without bound. 8,000 is deliberately generous for this project's stated scale target - a
         * *personal/local* web-of-trust (see [TrustPathFinder]'s doc comment): Dunbar's number tops
         * out around 150, and even a very well-connected super-node's multi-hop social graph is
         * unlikely to reach four figures, let alone 8,000. 8,000 leaves ample headroom above any
         * real personal-scale usage while still keeping worst-case construction (`O(nodes + edges)`)
         * and the BFS's per-query memory (`O(nodes)`, see [TrustPathFinder]) bounded to a few tens
         * of KB, not unbounded attacker-controlled growth.
         *
         * Originally 50,000 (V0.1.6 initial implementation). Tightened here specifically because of
         * [MAX_EDGES]'s constant-factor finding below - lowering [MAX_NODES] in step keeps the two
         * caps' documented 4x ratio intact rather than leaving [MAX_NODES] stranded far above what
         * [MAX_EDGES] alone would ever allow to be reached (at most `2 * MAX_EDGES` distinct nodes
         * can appear in [MAX_EDGES] edges).
         */
        const val MAX_NODES = 8_000

        /**
         * Upper bound on directed edges (resolved grants) a single [TrustGraph] may contain - see
         * [MAX_NODES] for the full reasoning. Set to a 4x multiple of [MAX_NODES] because a personal
         * web-of-trust is not a simple chain - a node may have many outgoing/incoming trust edges -
         * but 32,000 is still comfortably generous for real personal-scale usage while keeping
         * construction and query cost bounded well below the territory where cost becomes a
         * real concern.
         *
         * Originally 200,000 (V0.1.6 initial implementation, alongside `MAX_NODES = 50,000`). A
         * round-2 security re-audit of the predecessor-pointer BFS refactor (see
         * [TrustPathFinder]'s doc comment) found that, although the refactor is asymptotically
         * correct (`O(edges * MAX_HOP_DEPTH)`, confirmed by an independent hand-trace), the constant
         * factor at the *old* 200,000/20 caps was not negligible: an adversarial "tie layer" graph -
         * every edge the same weight, so every [TrustPathFinder] comparison ties and must recurse
         * through the full predecessor chain instead of short-circuiting on the first differing
         * weight - cost several hundred ms per query at the old caps (worse for a construction that
         * spreads the same edge budget across many tied hops instead of concentrating it into a
         * single 2-hop layer, which drives the cost toward its full `edges * MAX_HOP_DEPTH` bound
         * rather than just `edges`). [Secp256k1PublicKey.hashCode] is now cached (see its doc
         * comment), which alone cut a meaningful fraction of that cost, but a real residual
         * remained at the old caps. Lowering [MAX_EDGES] to 32,000 directly and proportionally
         * shrinks that residual: re-measured against the SAME adversarial tie-layer construction
         * (both the single-layer and the worse full-`MAX_HOP_DEPTH`-deep chained-layer variant) at
         * these new caps, worst-case cost is comfortably under 100ms on ordinary hardware - see the
         * wave's test/benchmark notes for the actual numbers. 32,000 is still far above anything a
         * real personal-scale web-of-trust needs (see [MAX_NODES]'s Dunbar's-number reasoning).
         */
        const val MAX_EDGES = 32_000

        /**
         * Builds a graph from real, already-verified Veritas grants - one per (truster, target)
         * pair. Signatures are NOT verified here; that is [VeritasGrant.verify]'s job, and callers
         * must have already done it before a grant reaches this factory.
         *
         * Uses `asSequence()` rather than eagerly `.map`-ing [grants] into a `List<Triple<...>>`
         * before calling [build]: a fully materialized mapped list would defeat [build]'s
         * incremental per-triple cap checks (`seen.size <= maxEdges`, `nodeSet.size <= maxNodes`)
         * by doing `O(grants.size)` work up front regardless of where those caps would abort - the
         * same unbounded-construction-cost problem [MAX_NODES]/[MAX_EDGES] exist to prevent in the
         * first place. A lazy sequence lets [build]'s for-loop pull one triple at a time, so an
         * over-cap [grants] collection still aborts as soon as the relevant `require()` trips,
         * exactly like [fromEdges] (which never materializes an intermediate list at all).
         */
        fun fromGrants(grants: Collection<VeritasGrant>): TrustGraph =
            build(grants.asSequence().map { Triple(it.truster, it.target, it.trustMicros) }.asIterable())

        /** As [fromGrants], but for tests/callers that already have raw (truster, target, weight)
         * triples rather than signed grant objects. */
        fun fromEdges(edges: Collection<Triple<Secp256k1PublicKey, Secp256k1PublicKey, Int>>): TrustGraph = build(edges)

        /**
         * Shared graph-construction logic for [fromGrants]/[fromEdges]. [maxNodes]/[maxEdges] default
         * to [MAX_NODES]/[MAX_EDGES]; the parameters exist (internal-only, not part of the public
         * factory surface) so tests can exercise the cap-enforcement logic itself without
         * constructing tens of thousands of real keys.
         *
         * [raw] is deliberately typed as [Iterable], not [Collection]: the for-loop below only ever
         * iterates it once and never touches a size/count, so accepting the weaker [Iterable]
         * lets [fromGrants] pass a lazy `Sequence`-backed iterable through unmaterialized - see its
         * doc comment - while [fromEdges] keeps passing its [Collection] straight through unchanged
         * (every [Collection] is already an [Iterable]).
         */
        internal fun build(
            raw: Iterable<Triple<Secp256k1PublicKey, Secp256k1PublicKey, Int>>,
            maxNodes: Int = MAX_NODES,
            maxEdges: Int = MAX_EDGES,
        ): TrustGraph {
            val seen = HashSet<Pair<Secp256k1PublicKey, Secp256k1PublicKey>>()
            val adj = HashMap<Secp256k1PublicKey, MutableList<Edge>>()
            val nodeSet = LinkedHashSet<Secp256k1PublicKey>()

            for ((truster, target, trustMicros) in raw) {
                require(trustMicros in MIN_TRUST_MICROS..MAX_TRUST_MICROS) {
                    "trustMicros must be in $MIN_TRUST_MICROS..$MAX_TRUST_MICROS, was $trustMicros"
                }
                // Self-trust is axiomatic (1.0), never read from a grant - drop self-edges before
                // the duplicate check below, so a stray self-grant can never collide with a real edge.
                if (truster == target) continue
                require(seen.add(truster to target)) {
                    "duplicate grant for (truster=${truster.fingerprint()}, target=${target.fingerprint()}); " +
                        "caller must pass exactly one latest grant per (truster, target) pair"
                }
                require(seen.size <= maxEdges) {
                    "trust graph exceeds the maximum of $maxEdges edges - hard cap for personal/local " +
                        "web-of-trust scale, see TrustGraph.MAX_EDGES"
                }
                adj.getOrPut(truster) { mutableListOf() }.add(Edge(target, trustMicros))
                nodeSet += truster
                nodeSet += target
                require(nodeSet.size <= maxNodes) {
                    "trust graph exceeds the maximum of $maxNodes nodes - hard cap for personal/local " +
                        "web-of-trust scale, see TrustGraph.MAX_NODES"
                }
            }

            val sortedAdj =
                adj.mapValues { (_, edges) ->
                    edges.sortedWith(compareBy(Secp256k1PublicKeyBytesComparator) { it.target })
                }
            return TrustGraph(sortedAdj, nodeSet)
        }
    }
}

/** Unsigned lexicographic byte-order comparator over compressed public keys - shared by
 * [TrustGraph]'s deterministic edge ordering and [TrustPathFinder]'s tiebreak. */
internal object Secp256k1PublicKeyBytesComparator : Comparator<Secp256k1PublicKey> {
    override fun compare(
        a: Secp256k1PublicKey,
        b: Secp256k1PublicKey,
    ): Int {
        val ba = a.bytes
        val bb = b.bytes
        for (i in ba.indices) {
            val diff = (ba[i].toInt() and 0xFF) - (bb[i].toInt() and 0xFF)
            if (diff != 0) return diff
        }
        return 0
    }
}
