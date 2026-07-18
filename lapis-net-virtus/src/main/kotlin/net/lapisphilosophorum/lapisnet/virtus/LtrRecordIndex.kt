package net.lapisphilosophorum.lapisnet.virtus

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * Wraps an [LtrRecord.contentId] byte array with value equality, so it can be used as a
 * `HashMap`/`HashSet` key - a plain `ByteArray` uses reference equality. Mirrors
 * [net.lapisphilosophorum.lapisnet.trust.GrantContentId] exactly, duplicated locally rather than
 * reused: `lapis-net-virtus` has no dependency edge to `lapis-net-trust` (see this module's
 * `build.gradle.kts` comment - Virtus is a sibling scoring dimension, not built on Veritas).
 * Internal: only [LtrRecordIndex] (same package) needs this.
 */
internal data class LtrContentId(
    private val bytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is LtrContentId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * Bounded, in-memory index of [LtrRecord]s received (locally created or via gossip), keyed by
 * content id and by `(cid, viewId)` pair. Mirrors
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex]'s two-cap eviction/persistence
 * pattern precisely - see that class's doc comment for the full round-2/round-3 reasoning this
 * structure is copied from (evicting in-memory tracking cap vs. a separate, non-evicting,
 * hard-capped persistence cap, and why those need to be two independent resources).
 *
 * **One deliberate behavioral difference from [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex]:**
 * nothing here ever resolves multiple records for the same `(cid, viewId)` pair down to one
 * winner. [recordsFor] returns EVERY tracked record for that pair, because per the Virtus spec
 * note's "Akkumulationslogik" section, every boost accumulates independently - there is no
 * backward-hash chain and no "latest wins" resolution (see [LtrRecord]'s own doc comment). The
 * reverse index is therefore keyed off a plain `(Cid, Secp256k1PublicKey)` pair (not a
 * `(Secp256k1PublicKey, Secp256k1PublicKey)` truster/target pair like `VeritasGrantIndex`), still
 * mapping to a `MutableList<LtrRecord>`, kept in sync on eviction via `removeEldestEntry` exactly
 * like `VeritasGrantIndex`'s own reverse index.
 */
class LtrRecordIndex internal constructor(
    private val maxTracked: Int = MAX_TRACKED_RECORDS,
    private val maxPersisted: Int = MAX_PERSISTED_RECORDS,
) {
    /** Public entry point - always uses [MAX_TRACKED_RECORDS]/[MAX_PERSISTED_RECORDS]. The
     * internal constructor above exists purely as a test seam, mirroring
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex]'s own constructor pattern. */
    constructor() : this(MAX_TRACKED_RECORDS, MAX_PERSISTED_RECORDS)

    private val recordsByPair = HashMap<Pair<Cid, Secp256k1PublicKey>, MutableList<LtrRecord>>()

    /** Backed by a [LinkedHashMap] constructed with access-order tracking enabled, exactly
     * mirroring [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.grantsByContentId] -
     * see that field's doc comment for why this is FIFO-equivalent in practice, not true LRU. */
    private val recordsByContentId =
        object : LinkedHashMap<LtrContentId, LtrRecord>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<LtrContentId, LtrRecord>): Boolean {
                if (size <= maxTracked) return false
                val evicted = eldest.value
                val pairKey = evicted.cid to evicted.viewId
                val bucket = recordsByPair[pairKey]
                bucket?.remove(evicted)
                if (bucket != null && bucket.isEmpty()) recordsByPair.remove(pairKey)
                return true
            }
        }

    /** Backing set for [tryReservePersistence] - a plain, never-evicting [HashSet], mirroring
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.persistedContentIds] exactly. */
    private val persistedContentIds = HashSet<LtrContentId>()

    /**
     * Adds [record] to the index. Returns `true` iff it was newly added; `false` for a duplicate
     * (by content id) or a signature-invalid record - **never throws**, mirroring
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.add]'s "last line of defense
     * before untrusted gossip data reaches this node's in-memory state" contract exactly,
     * including the defensive re-verification of [record]'s signature.
     */
    @Synchronized
    fun add(record: LtrRecord): Boolean =
        runCatching {
            if (!LtrRecord.verify(record)) return@runCatching false
            val id = LtrContentId(record.contentId())
            if (recordsByContentId.containsKey(id)) return@runCatching false
            recordsByContentId[id] = record
            recordsByPair.getOrPut(record.cid to record.viewId) { mutableListOf() }.add(record)
            true
        }.getOrDefault(false)

    /**
     * Cheap, non-mutating, no-I/O admission pre-check: `true` iff [record] is not already tracked
     * by content id. Mirrors
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.canAccept]'s contract exactly -
     * see that method's doc comment for why this alone does not bound durable persistence.
     */
    @Synchronized
    fun canAccept(record: LtrRecord): Boolean = !recordsByContentId.containsKey(LtrContentId(record.contentId()))

    /**
     * Admission gate purely for **durable persistence** - a bounded, non-evicting,
     * hard-reject-once-[maxPersisted] cap, entirely separate from [recordsByContentId]'s evicting
     * cap. Mirrors
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.tryReservePersistence]'s contract
     * exactly, including atomic reserve-before-put semantics and idempotency per content id.
     */
    @Synchronized
    fun tryReservePersistence(record: LtrRecord): Boolean {
        val id = LtrContentId(record.contentId())
        if (persistedContentIds.contains(id)) return true
        if (persistedContentIds.size >= maxPersisted) return false
        persistedContentIds.add(id)
        return true
    }

    /** Every tracked record for the `(cid, viewId)` pair, in insertion order - unlike
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.grantsFor], this is never resolved
     * down to a single winner (see this class's doc comment). */
    @Synchronized
    internal fun recordsFor(
        cid: Cid,
        viewId: Secp256k1PublicKey,
    ): List<LtrRecord> = recordsByPair[cid to viewId]?.toList() ?: emptyList()

    /** Every distinct `(cid, viewId)` pair with at least one tracked record. */
    @Synchronized
    internal fun allPairs(): Set<Pair<Cid, Secp256k1PublicKey>> = recordsByPair.keys.toSet()

    companion object {
        /**
         * Upper bound on distinct records tracked from gossip. Borrowed in *magnitude* from
         * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.MAX_TRACKED_GRANTS] but NOT its
         * social-graph-size (Dunbar's-number) justification - LTR records scale with content and
         * engagement volume, a fundamentally different growth driver than a personal trust graph's
         * edge count. This number is provisional, chosen for parity with the existing precedent
         * rather than derived from real pilot usage data; revisit once actual Virtus traffic
         * volumes are observed.
         */
        const val MAX_TRACKED_RECORDS = 64_000

        /**
         * Upper bound on distinct records this node will durably persist via `NabuStorage.put()`
         * from gossip - see [tryReservePersistence] and
         * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantIndex.MAX_PERSISTED_GRANTS]'s doc
         * comment for the full reasoning this mirrors. Same provisional-magnitude caveat as
         * [MAX_TRACKED_RECORDS] applies.
         */
        const val MAX_PERSISTED_RECORDS = 64_000
    }
}
