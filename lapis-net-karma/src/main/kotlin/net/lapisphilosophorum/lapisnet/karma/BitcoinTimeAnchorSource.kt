package net.lapisphilosophorum.lapisnet.karma

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * A source of REAL Bitcoin chain data for resolving a [ChainAnchorClaim], used only client-side
 * (see [KarmaAnchorCache]) - never in [KarmaGossip]'s validation path. Kept as an interface, not a
 * concrete class, purely so tests (and [KarmaAnchorCache]'s own tests) can substitute a fake without
 * any real network I/O - the one real implementation is [ElectrumTimeAnchorSource].
 */
interface BitcoinTimeAnchorSource {
    /** Resolves [pubkey]'s first outgoing Bitcoin transaction, scoped to the single P2WPKH address
     * type this wave recognizes - see [BitcoinAddressDerivation]'s doc comment for that scope
     * limitation. Never throws for an ordinary "no history"/network outcome - see
     * [TimeAnchorLookupResult]'s doc comment for the three possible outcomes and why
     * [TimeAnchorLookupResult.LookupFailed] must never be conflated with
     * [TimeAnchorLookupResult.NotFound]. */
    fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult

    /** The current Bitcoin chain tip height. Unlike [findFirstOutgoingTransaction], this DOES throw
     * on failure - there is no meaningful "not found" outcome for a chain tip query the way there is
     * for a transaction-history query, so a real network/protocol failure has no safe non-throwing
     * value to return. */
    fun currentChainTipHeight(): Int
}
