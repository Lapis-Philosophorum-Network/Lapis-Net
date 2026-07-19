package net.lapisphilosophorum.lapisnet.virtus

/** Number of bytes in a Bitcoin transaction id. */
private const val BTC_TXID_SIZE = 32

/** Defense-in-depth sanity cap on [OnChainProof.outputIndex] - NOT a real Bitcoin consensus rule.
 * A real Bitcoin transaction can, in principle, have far more outputs than this, but nothing in
 * this project's own OP_RETURN payment convention (see the Virtus spec note) ever legitimately
 * needs anywhere near this many - the cap exists purely to keep a decoded [OnChainProof] a small,
 * bounded value even before any real chain lookup happens. See [OnChainProof]'s class doc comment. */
private const val MAX_STRUCTURAL_OUTPUT_INDEX = 100_000

/**
 * A cryptographic proof binding an [net.lapisphilosophorum.lapisnet.virtus.LtrRecord] to a real
 * Bitcoin payment. Sealed so every implementation is enumerable at compile time - see
 * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordCodec]'s `proofType` byte, which switches on
 * the concrete type. Two implementations exist, per the Virtus spec note's "Zwei Zahlungswege"
 * section: [OnChainProof] (`proofType = 1`, structural-only, no live chain verification - see its
 * own doc comment) and [net.lapisphilosophorum.lapisnet.virtus.LightningProof] (`proofType = 2`,
 * V0.6 - fully cryptographically verified, including in the gossip hot path, see that class's and
 * [net.lapisphilosophorum.lapisnet.virtus.LightningProofVerifier]'s doc comments). Adding either
 * meant adding a new `proofType` case to the codec, not changing this interface's shape.
 */
sealed interface LtrProof

/**
 * A structural claim that an on-chain Bitcoin transaction output at ([btcTxid], [outputIndex])
 * paid a Virtus/LTR boost into existence, per the "B. On-Chain Bitcoin mit OP_RETURN" payment path
 * described in the Virtus spec note.
 *
 * **This class validates SHAPE ONLY - it never verifies chain existence.** Constructing an
 * [OnChainProof] with a well-formed 32-byte [btcTxid] and an [outputIndex] within
 * [MAX_STRUCTURAL_OUTPUT_INDEX] proves nothing about whether that transaction actually exists on
 * any Bitcoin chain, whether it actually pays the claimed amount, or whether its OP_RETURN output
 * actually binds the claimed `(cid, viewId)` pair. V0.2.1 deliberately does not construct, sign,
 * broadcast, or verify real Bitcoin transaction bytes - no Bitcoin transaction library dependency
 * is added in this wave (see this module's `build.gradle.kts` comment). Live chain verification
 * of a claimed `(txid, vout)` pair - actually checking amount, recipient address, and OP_RETURN
 * payload against a real block explorer or full node, as the spec note's "Jeder Node kann ...
 * prüfen" section describes - is out of scope for this wave and deferred to a later one.
 *
 * **Known gap - concrete economic consequence, not just a missing feature.** Because nothing in
 * this wave checks that the claimed transaction, output, amount, or OP_RETURN payload actually
 * exist on any chain, a malicious node can today fabricate
 * [net.lapisphilosophorum.lapisnet.virtus.LtrRecord]s claiming arbitrary msat amounts were paid,
 * at zero cost - only structural shape and the payer's own signature are checked, and a payer can
 * trivially sign a claim about their own alleged payment. Any view that honors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip.currentWeight] or
 * [net.lapisphilosophorum.lapisnet.virtus.LtrWeightCalculator.totalInvestedMsat] today, before a
 * later wave adds real chain verification, is trivially manipulable by anyone willing to run this
 * code - sort-weight boosting is currently free, not merely under-verified.
 *
 * **Byte-order assumption for [btcTxid], unverified pending a real Bitcoin library.** Bitcoin
 * transaction ids are conventionally displayed to humans in reversed byte order (the "reversed
 * display-hex" convention seen in block explorers), but are stored and transmitted internally
 * (e.g. in `OutPoint` structures within transaction bytes) in a different, non-reversed order.
 * This class makes no attempt to detect or normalize which order [btcTxid] is in - it is treated
 * purely as an opaque 32-byte identifier, assumed to already be in internal/wire order (not
 * reversed display-hex order), matching how a real Bitcoin library's txid type would store it.
 * This assumption is unverified in this wave, since no Bitcoin library is present to cross-check
 * against - a future wave that adds real chain verification must confirm (or correct) it before
 * comparing a stored [btcTxid] against bytes read from an actual block.
 */
class OnChainProof(
    btcTxid: ByteArray,
    val outputIndex: Int,
) : LtrProof {
    private val storedTxid: ByteArray = btcTxid.copyOf()

    /** The claimed Bitcoin transaction id, in internal/wire byte order (see this class's doc
     * comment) - NOT verified against any real chain. Returns a fresh copy on every access. */
    val btcTxid: ByteArray get() = storedTxid.copyOf()

    init {
        require(storedTxid.size == BTC_TXID_SIZE) { "btcTxid must be exactly $BTC_TXID_SIZE bytes" }
        require(outputIndex in 0..MAX_STRUCTURAL_OUTPUT_INDEX) {
            "outputIndex must be in 0..$MAX_STRUCTURAL_OUTPUT_INDEX (structural sanity cap, not a Bitcoin consensus " +
                "rule), was $outputIndex"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is OnChainProof && storedTxid.contentEquals(other.storedTxid) && outputIndex == other.outputIndex

    override fun hashCode(): Int {
        var result = storedTxid.contentHashCode()
        result = 31 * result + outputIndex
        return result
    }

    override fun toString(): String = "OnChainProof(btcTxid=${storedTxid.toHexPreview()}, outputIndex=$outputIndex)"

    companion object {
        /** See this class's doc comment on why this is a sanity cap, not a consensus rule. */
        const val MAX_OUTPUT_INDEX = MAX_STRUCTURAL_OUTPUT_INDEX
    }
}

/** Short, non-sensitive hex preview for [OnChainProof.toString] - a txid is public on-chain data
 * once broadcast, unlike a private key or signature, so unlike [LtrRecord.signature] there is no
 * "never log this" concern here; this is still truncated purely to keep toString() output compact. */
private fun ByteArray.toHexPreview(): String = take(8).joinToString("") { "%02x".format(it) } + "…"
