package net.lapisphilosophorum.lapisnet.trust

/**
 * Validates an in-memory, genesis-first list of [VeritasGrant]s as a single (truster, target)
 * version chain. This walks a list already held in memory only - it never fetches predecessors
 * from anywhere. Fetching a chain's grants by content id from the DFS is a later wave's concern
 * (V0.1.7+), and is currently blocked by V0.1.4's documented cross-node DHT provider-discovery
 * limitation (see `NabuStorage`'s doc comments) - this object provides the fully local, fully
 * testable validation logic that a future fetching layer can build on.
 */
object VeritasGrantChain {
    /**
     * Returns `true` iff [orderedGrants] is a valid, complete version chain: non-empty; every
     * grant shares the same [VeritasGrant.truster] and [VeritasGrant.target]; every grant
     * individually passes [VeritasGrant.verify]; the first grant is genesis
     * ([VeritasGrant.isGenesis]); and every subsequent grant [VeritasGrant.linksTo] its immediate
     * predecessor in the list. The last element, if valid, is the chain's authoritative (newest)
     * grant.
     */
    fun validate(orderedGrants: List<VeritasGrant>): Boolean {
        if (orderedGrants.isEmpty()) return false

        val truster = orderedGrants.first().truster
        val target = orderedGrants.first().target
        if (orderedGrants.any { it.truster != truster || it.target != target }) return false

        if (orderedGrants.any { !VeritasGrant.verify(it) }) return false

        if (!orderedGrants.first().isGenesis) return false

        for (i in 1 until orderedGrants.size) {
            if (!orderedGrants[i].linksTo(orderedGrants[i - 1])) return false
        }

        return true
    }
}
