package net.lapisphilosophorum.lapisnet.karma

private const val BTC_TXID_SIZE = 32

/**
 * Defense-in-depth sanity cap on a block height ([ChainAnchorClaim.genesisBlockHeight] /
 * [ChainAnchorClaim.tipHeightAtVote]) - NOT a real Bitcoin consensus rule. Bitcoin's real chain
 * height will not reach this value for centuries at the current ~10-minute block interval (10M
 * blocks is roughly 190 years' worth of blocks from genesis). This cap exists purely to keep a
 * decoded [ChainAnchorClaim] a small, bounded value, mirroring
 * [net.lapisphilosophorum.lapisnet.virtus.OnChainProof]'s identical "structural sanity cap, not a
 * consensus rule" reasoning for its own `MAX_STRUCTURAL_OUTPUT_INDEX`.
 */
const val MAX_STRUCTURAL_BLOCK_HEIGHT = 10_000_000

/**
 * A voter's claimed anchor into Bitcoin chain time, carried inside a [KarmaVote] to let an
 * observer compute `t` (see [KarmaWeightCalculator]) without itself performing any chain lookup -
 * see this file's second doc comment (on [ChainAnchorClaim]) for why gossip acceptance NEVER
 * verifies this claim against a real chain.
 *
 * Sealed so every case is enumerable at compile time, mirroring
 * [net.lapisphilosophorum.lapisnet.virtus.LtrProof]'s established pattern. Unlike [LtrProof]
 * (where only [net.lapisphilosophorum.lapisnet.virtus.OnChainProof] is implemented and a second,
 * Lightning-based case is merely planned for later), **both cases here are real, everyday,
 * expected outcomes today**: [NoAnchorClaim] is the genuine, common state for any identity that
 * has never sent an outgoing Bitcoin transaction from the single, narrow address type this wave's
 * [BitcoinAddressDerivation] can recognize (see that object's doc comment for the recognized-
 * address-type scope limitation) - not a placeholder for a future case, not an error state.
 */
sealed interface TimeAnchorClaim

/**
 * A structural claim that [genesisTxid] - a transaction at height [genesisBlockHeight] - was the
 * voter's own first outgoing Bitcoin transaction, and that the chain tip was at
 * [tipHeightAtVote] when the enclosing [KarmaVote] was cast. `t` (see [KarmaWeightCalculator]) is
 * `tipHeightAtVote - genesisBlockHeight`, structurally guaranteed non-negative by this class's own
 * [init] block (see below) - never computed from an untrusted difference a decoder would have to
 * re-validate itself.
 *
 * **This class validates SHAPE ONLY - it never verifies chain existence, exactly mirroring
 * [net.lapisphilosophorum.lapisnet.virtus.OnChainProof]'s established "structural-only" contract.**
 * Constructing a [ChainAnchorClaim] with a well-formed 32-byte [genesisTxid] and heights within
 * [MAX_STRUCTURAL_BLOCK_HEIGHT] proves nothing about whether [genesisTxid] actually exists on any
 * Bitcoin chain, was actually mined at [genesisBlockHeight], or actually spends from the claiming
 * voter's own key. [KarmaGossip.onGossipMessage] validates ONLY structure and the [KarmaVote]
 * signature - it never calls out to Electrum or any other network service to check this claim
 * against a real chain. This is deliberate, not an oversight, for three reasons - see
 * [KarmaGossip]'s class doc comment for the full reasoning this mirrors from
 * [net.lapisphilosophorum.lapisnet.virtus.OnChainProof]'s already-accepted V0.2.1 precedent:
 *  (a) gating message acceptance on a blocking third-party network call makes mesh behavior
 *      depend on a third party's uptime;
 *  (b) different nodes might reach different (or no) Electrum servers, so two honest nodes could
 *      reach different accept/reject decisions for the identical message - breaking this
 *      codebase's established "same structural rules -> same decision" invariant;
 *  (c) it would let a malicious peer's gossip flood force every relaying node into outbound
 *      network calls - an amplification DoS vector.
 *
 * The REAL chain lookup only ever runs client-side, when a user's own node casts a Karma vote -
 * see [BitcoinTimeAnchorSource]/[ElectrumTimeAnchorSource]/[KarmaAnchorCache].
 *
 * **Byte-order assumption for [genesisTxid], unverified pending live chain confirmation - same
 * caveat style as [net.lapisphilosophorum.lapisnet.virtus.OnChainProof.btcTxid].** Treated purely
 * as an opaque 32-byte identifier, assumed to be in internal/wire byte order (matching
 * `Transaction.hash` in a real Bitcoin library, NOT the reversed "display hex" order block
 * explorers show and the Electrum protocol's own `tx_hash` wire field uses) - see
 * [ElectrumTimeAnchorSource]'s doc comment for exactly where that reversal happens when this wave
 * DOES cross-reference a real Bitcoin library (`bitcoin-kmp`) client-side.
 */
class ChainAnchorClaim(
    val genesisBlockHeight: Int,
    genesisTxid: ByteArray,
    val tipHeightAtVote: Int,
) : TimeAnchorClaim {
    private val storedGenesisTxid: ByteArray = genesisTxid.copyOf()

    /** The claimed genesis transaction id, in internal/wire byte order (see this class's doc
     * comment) - NOT verified against any real chain. Returns a fresh copy on every access. */
    val genesisTxid: ByteArray get() = storedGenesisTxid.copyOf()

    init {
        require(storedGenesisTxid.size == BTC_TXID_SIZE) { "genesisTxid must be exactly $BTC_TXID_SIZE bytes" }
        require(genesisBlockHeight in 0..MAX_STRUCTURAL_BLOCK_HEIGHT) {
            "genesisBlockHeight must be in 0..$MAX_STRUCTURAL_BLOCK_HEIGHT, was $genesisBlockHeight"
        }
        require(tipHeightAtVote in genesisBlockHeight..MAX_STRUCTURAL_BLOCK_HEIGHT) {
            "tipHeightAtVote must be in genesisBlockHeight ($genesisBlockHeight)..$MAX_STRUCTURAL_BLOCK_HEIGHT " +
                "(structurally guarantees t = tipHeightAtVote - genesisBlockHeight >= 0), was $tipHeightAtVote"
        }
    }

    /** `t` per [KarmaWeightCalculator]'s formula - structurally guaranteed `>= 0` by [init] above. */
    val t: Int get() = tipHeightAtVote - genesisBlockHeight

    override fun equals(other: Any?): Boolean =
        other is ChainAnchorClaim &&
            genesisBlockHeight == other.genesisBlockHeight &&
            storedGenesisTxid.contentEquals(other.storedGenesisTxid) &&
            tipHeightAtVote == other.tipHeightAtVote

    override fun hashCode(): Int {
        var result = genesisBlockHeight
        result = 31 * result + storedGenesisTxid.contentHashCode()
        result = 31 * result + tipHeightAtVote
        return result
    }

    override fun toString(): String =
        "ChainAnchorClaim(genesisBlockHeight=$genesisBlockHeight, " +
            "genesisTxid=${storedGenesisTxid.toHexPreview()}, tipHeightAtVote=$tipHeightAtVote)"
}

/**
 * The genuine, common "no anchor" state: the voter's identity has no recognized first outgoing
 * Bitcoin transaction (either because none exists, or because it exists but was made via an
 * address type/path [BitcoinAddressDerivation] does not recognize - see that object's doc
 * comment). Per [KarmaWeightCalculator], any [KarmaVote] carrying [NoAnchorClaim] always resolves
 * to `Karma = 0` - never a lookup error, never silently coerced from a real
 * [TimeAnchorLookupResult.LookupFailed] (see that sealed interface's doc comment on why that
 * distinction must be preserved by callers).
 */
object NoAnchorClaim : TimeAnchorClaim {
    override fun toString(): String = "NoAnchorClaim"
}

/** Short, non-sensitive hex preview - a txid is public on-chain data once broadcast, so unlike
 * [KarmaVote.signature] there is no "never log this" concern here; truncated purely to keep
 * toString() output compact, mirroring [net.lapisphilosophorum.lapisnet.virtus.OnChainProof]'s
 * identical helper. */
private fun ByteArray.toHexPreview(): String = take(8).joinToString("") { "%02x".format(it) } + "…"
