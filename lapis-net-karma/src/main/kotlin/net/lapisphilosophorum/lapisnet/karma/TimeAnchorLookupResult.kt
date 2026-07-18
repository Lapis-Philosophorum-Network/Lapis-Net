package net.lapisphilosophorum.lapisnet.karma

/**
 * The outcome of a REAL, client-side [BitcoinTimeAnchorSource.findFirstOutgoingTransaction] lookup
 * - never used in [KarmaGossip]'s validation path, which performs no chain lookups at all (see that
 * class's doc comment).
 *
 * **[LookupFailed] must NEVER be silently coerced to [NotFound] (and therefore, by
 * [KarmaAnchorCache], to [NoAnchorClaim]) anywhere in this codebase.** [NotFound] means "we
 * successfully asked a real Electrum server and it confirmed this identity has no recognized
 * outgoing transaction" - a genuine, trustworthy zero. [LookupFailed] means "we could not get a
 * trustworthy answer at all" (a network error, a malformed server response, a connection timeout,
 * an empty [ElectrumServers] configuration) - collapsing that into [NotFound] would wrongly zero out
 * a real voter's Karma anchor merely because of a transient infrastructure problem, silently
 * punishing them for something outside their control. See [KarmaAnchorCache.currentClaimFor]'s doc
 * comment for the concrete caller contract this drives: a [LookupFailed] outcome propagates as a
 * thrown exception, not a quietly-substituted [NoAnchorClaim].
 */
sealed interface TimeAnchorLookupResult {
    /** [genesisTxid] is in internal/wire byte order - see [ChainAnchorClaim.genesisTxid]'s doc
     * comment for the same convention and its caveats. */
    data class Found(
        val genesisBlockHeight: Int,
        val genesisTxid: ByteArray,
    ) : TimeAnchorLookupResult {
        override fun equals(other: Any?): Boolean =
            other is Found &&
                genesisBlockHeight == other.genesisBlockHeight &&
                genesisTxid.contentEquals(other.genesisTxid)

        override fun hashCode(): Int = 31 * genesisBlockHeight + genesisTxid.contentHashCode()
    }

    /** A real lookup ran and confirmed: no recognized outgoing transaction exists for this
     * identity's P2WPKH address (see [BitcoinAddressDerivation]'s scope-limitation doc comment for
     * what "recognized" means here). */
    object NotFound : TimeAnchorLookupResult

    /** The lookup could not produce a trustworthy answer at all - see this interface's doc comment
     * for why this must never be treated as equivalent to [NotFound]. */
    data class LookupFailed(
        val reason: String,
    ) : TimeAnchorLookupResult
}
