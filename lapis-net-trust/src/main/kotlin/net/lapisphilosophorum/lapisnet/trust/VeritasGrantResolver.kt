package net.lapisphilosophorum.lapisnet.trust

/**
 * Resolves the single "latest" [VeritasGrant] out of a set of candidates that all share one
 * (truster, target) pair - i.e. collapses a (possibly forked, possibly byzantine) version-chain
 * fragment down to the one edge [TrustGraph.fromGrants] should see for that pair. This is what
 * turns [VeritasGrantIndex]'s raw per-pair candidate lists into the "exactly one latest grant per
 * (truster, target) pair" input [TrustGraph.fromGrants] requires.
 *
 * **Algorithm.**
 *  1. Keep only individually signature-valid candidates ([VeritasGrant.verify]). An invalid grant
 *     is excluded entirely - this makes invalid-signature grants and dangling references (nothing
 *     legitimately points to them) collapse into the same "not a linkable node" case, no
 *     special-casing needed.
 *  2. Index the valid set by content id and build reverse adjacency (a valid grant's
 *     [VeritasGrant.previousGrantId] content id -> its successors) over the valid set only.
 *  3. Every valid genesis grant ([VeritasGrant.isGenesis]) is a root. Multiple roots (a byzantine
 *     truster issuing two unrelated genesis grants for the same pair) are handled uniformly by
 *     step 5, not specially.
 *  4. Walk forward from every root along the reverse-adjacency edges (a TREE walk, not a
 *     linked-list walk - a fork produces two branches, both explored), tracking a `visited` set
 *     and the current depth; a branch aborts (and its current node becomes a forced tip) if depth
 *     would exceed [MAX_CHAIN_DEPTH], or is dropped outright if a node is revisited (cycle guard -
 *     see the note below on why a genuine cycle can't actually occur). Every leaf (no successor
 *     edge, or the depth cap was hit) is a tip candidate, tagged with its depth.
 *  5. The winner is picked among ALL tip candidates across the whole forest: greatest depth wins;
 *     ties are broken by lexicographically-greatest content-id bytes (unsigned byte comparison).
 *     This rule is receipt-order-independent by construction - it depends only on the resolved
 *     candidate *set*, never on the order candidates were passed in - so two nodes that eventually
 *     see the identical candidate set, even via differently-ordered gossip deliveries, converge on
 *     the identical answer.
 *
 * A genuine hash-chain cycle is not defended against by any special-case beyond the depth cap and
 * cycle guard above, and is not exercised by this object's tests, because it is cryptographically
 * infeasible to construct through the real API: a successor's [VeritasGrant.previousGrantId] is
 * fixed to a predecessor's already-computed [VeritasGrant.contentId] at creation time, so two
 * grants can never legitimately reference each other.
 */
object VeritasGrantResolver {
    /** Hard bound on a single (truster, target) pair's version-chain walk depth - defense in
     * depth against a pathologically long forked chain reaching this index via gossip, on top of
     * [VeritasGrantIndex.MAX_TRACKED_GRANTS]'s bound on the number of distinct tracked grants. */
    const val MAX_CHAIN_DEPTH = 4_096

    /** All [candidates] must share one (truster, target) pair. Returns the resolved tip, or
     * `null` if [candidates] is empty or contains no valid genesis-rooted chain. See this object's
     * doc comment for the full algorithm. */
    fun resolveLatest(candidates: List<VeritasGrant>): VeritasGrant? = resolveLatest(candidates, MAX_CHAIN_DEPTH)

    /** As [resolveLatest], but with an explicit [maxDepth] - a test seam so
     * [MAX_CHAIN_DEPTH]'s cap-enforcement can be exercised without constructing thousands of real
     * signed grants for every other test.
     *
     * **Precondition**: [candidates] is indexed by content id ([byContentId] below) without any
     * dedup step of its own - if [candidates] contains multiple entries sharing the same content
     * id, the last one encountered in iteration order silently wins (later entries overwrite
     * earlier ones in the `HashMap` build-up). This is never reachable via the real
     * [VeritasGrantIndex.grantsFor] -> [VeritasGossip.currentGrants] path (dedup by content id
     * already happened upstream, in [VeritasGrantIndex.add]/[VeritasGrantIndex.canAccept]), but a
     * test or future caller invoking this internal overload directly with unfiltered data must
     * pre-dedup [candidates] itself if it cares which duplicate wins. */
    internal fun resolveLatest(
        candidates: List<VeritasGrant>,
        maxDepth: Int,
    ): VeritasGrant? {
        if (candidates.isEmpty()) return null

        val valid = candidates.filter { runCatching { VeritasGrant.verify(it) }.getOrDefault(false) }
        if (valid.isEmpty()) return null

        val byContentId = HashMap<GrantContentId, VeritasGrant>(valid.size)
        valid.forEach { byContentId[GrantContentId(it.contentId())] = it }

        val successorsOf = HashMap<GrantContentId, MutableList<VeritasGrant>>()
        valid.forEach { grant ->
            val previousId = grant.previousGrantId ?: return@forEach
            val previousContentId = GrantContentId(previousId)
            // Dangling reference (predecessor not among the valid candidates) - simply not linked
            // into the walk below, per step 1/2's "not a linkable node" rule.
            if (byContentId.containsKey(previousContentId)) {
                successorsOf.getOrPut(previousContentId) { mutableListOf() }.add(grant)
            }
        }

        val roots = valid.filter { it.isGenesis }
        if (roots.isEmpty()) return null

        // Iterative DFS (explicit stack, not recursion) so MAX_CHAIN_DEPTH's default (4,096)
        // can never risk a StackOverflowError regardless of the calling thread's stack size.
        val tips = mutableListOf<Tip>()
        val visited = HashSet<GrantContentId>()
        val stack = ArrayDeque<Tip>()
        roots.forEach { root -> stack.addLast(Tip(root, 0, GrantContentId(root.contentId()))) }

        while (stack.isNotEmpty()) {
            val frame = stack.removeLast()
            if (!visited.add(frame.id)) continue // cycle guard - see the class doc comment

            val successors = successorsOf[frame.id].orEmpty()
            if (successors.isEmpty() || frame.depth >= maxDepth) {
                tips += frame
                continue
            }
            for (successor in successors) {
                check(successor.linksTo(frame.grant)) {
                    "successor grant does not link to its predecessor - reverse-adjacency invariant violated"
                }
                stack.addLast(Tip(successor, frame.depth + 1, GrantContentId(successor.contentId())))
            }
        }

        if (tips.isEmpty()) return null

        return tips
            .maxWithOrNull(
                compareBy<Tip> { it.depth }
                    .thenComparator { a, b -> GrantContentIdBytesComparator.compare(a.id, b.id) },
            )?.grant
    }

    private data class Tip(
        val grant: VeritasGrant,
        val depth: Int,
        val id: GrantContentId,
    )
}

/** Unsigned lexicographic byte-order comparator over [GrantContentId]s - the tiebreak
 * [VeritasGrantResolver] uses when multiple tip candidates share the same (winning) depth. Mirrors
 * [Secp256k1PublicKeyBytesComparator]'s comparison style, applied to content-id bytes instead of
 * public-key bytes. */
private object GrantContentIdBytesComparator : Comparator<GrantContentId> {
    override fun compare(
        a: GrantContentId,
        b: GrantContentId,
    ): Int {
        val ba = a.bytesForComparison()
        val bb = b.bytesForComparison()
        for (i in ba.indices) {
            val diff = (ba[i].toInt() and 0xFF) - (bb[i].toInt() and 0xFF)
            if (diff != 0) return diff
        }
        return ba.size - bb.size
    }
}
