package net.lapisphilosophorum.lapisnet.virtus

/** Number of bytes in a BOLT-11 payment preimage / payment hash. */
private const val LIGHTNING_PREIMAGE_SIZE = 32
private const val LIGHTNING_PAYMENT_HASH_SIZE = 32

/**
 * A structural claim that a real Lightning Network payment - proven by [LightningProof.preimage],
 * whose `sha256(preimage)` equals [LightningProof.paymentHash] - was made against
 * [LightningProof.signedInvoice], a real, signed BOLT-11 invoice string binding that payment to a
 * `(cid, viewId)` pair. This is the second [LtrProof] implementation, alongside [OnChainProof] -
 * see the "B. Lightning" payment path described in the Virtus spec note's "Zwei Zahlungswege"
 * section.
 *
 * **This class validates SHAPE ONLY - it never verifies the cryptography.** Constructing a
 * [LightningProof] with three well-formed fields proves nothing about whether `sha256(preimage)`
 * actually equals [LightningProof.paymentHash], whether [LightningProof.signedInvoice] is even a
 * parseable BOLT-11 string, or whether its embedded signature is valid. All of that - the actual
 * cryptographic verification chain - is [LightningProofVerifier]'s job, not this constructor's.
 * This mirrors [OnChainProof]'s own "structural/trusting, not verified" precedent exactly:
 * [LtrRecordCodec.decode] must stay purely structural (a signature-tampered [LtrRecord] must still
 * decode, see that codec's doc comment), so no crypto check belongs in this `init` block.
 *
 * **Unlike [OnChainProof], this proof CAN be - and is - cryptographically verified in the gossip
 * hot path.** See [LtrGossip]'s doc comment on why: Lightning-proof verification is a pure,
 * bounded, local computation (hash a preimage, parse+verify a BOLT-11 signature, compare a few
 * fields) with no liveness dependency on any third party, unlike [OnChainProof]'s live chain
 * lookup - which correctly stays out of the hot path. [LightningProofVerifier.verify] is the one
 * place that check happens.
 */
class LightningProof(
    preimage: ByteArray,
    paymentHash: ByteArray,
    signedInvoice: String,
) : LtrProof {
    private val storedPreimage: ByteArray = preimage.copyOf()

    /** 32-byte payment preimage - public data once gossiped (unlike [LtrRecord.signature], no
     * "never log" rule applies to it). Returns a fresh copy on every access. NOT checked against
     * [paymentHash] here - see [LightningProofVerifier.verify]. */
    val preimage: ByteArray get() = storedPreimage.copyOf()

    private val storedPaymentHash: ByteArray = paymentHash.copyOf()

    /** 32-byte payment hash, also present (redundantly) inside [signedInvoice] itself - see
     * [LightningProofVerifier.verify]'s consistency check between the two. Returns a fresh copy on
     * every access. */
    val paymentHash: ByteArray get() = storedPaymentHash.copyOf()

    /** A BOLT-11 bech32 invoice string (`"lnbc…"`/`"lntb…"`/`"lnbcrt…"`) - the source of truth for
     * the claimed payment amount and recipient once verified, never re-derived or normalized here. */
    val signedInvoice: String = signedInvoice

    init {
        require(storedPreimage.size == LIGHTNING_PREIMAGE_SIZE) {
            "preimage must be exactly $LIGHTNING_PREIMAGE_SIZE bytes"
        }
        require(storedPaymentHash.size == LIGHTNING_PAYMENT_HASH_SIZE) {
            "paymentHash must be exactly $LIGHTNING_PAYMENT_HASH_SIZE bytes"
        }
        val invoiceBytes = signedInvoice.toByteArray(Charsets.US_ASCII).size
        require(invoiceBytes in 1..MAX_SIGNED_INVOICE_BYTES) {
            "signedInvoice must be 1..$MAX_SIGNED_INVOICE_BYTES US-ASCII bytes, was $invoiceBytes"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is LightningProof &&
            storedPreimage.contentEquals(other.storedPreimage) &&
            storedPaymentHash.contentEquals(other.storedPaymentHash) &&
            signedInvoice == other.signedInvoice

    override fun hashCode(): Int {
        var result = storedPreimage.contentHashCode()
        result = 31 * result + storedPaymentHash.contentHashCode()
        result = 31 * result + signedInvoice.hashCode()
        return result
    }

    override fun toString(): String =
        "LightningProof(preimage=${storedPreimage.toLightningHexPreview()}, " +
            "paymentHash=${storedPaymentHash.toLightningHexPreview()}, signedInvoice.length=${signedInvoice.length})"

    companion object {
        /** See [LIGHTNING_PREIMAGE_SIZE]. Exposed publicly so callers (e.g. tests, the browser
         * authoring endpoint) don't need to hardcode `32` independently. */
        const val PREIMAGE_SIZE = LIGHTNING_PREIMAGE_SIZE

        /** See [LIGHTNING_PAYMENT_HASH_SIZE]. */
        const val PAYMENT_HASH_SIZE = LIGHTNING_PAYMENT_HASH_SIZE

        /** Generous cap on a BOLT-11 invoice string. Typical invoices are 200-700 chars; heavily
         * route-hinted ones can reach ~1.5-2 KB. 2048 covers pathological real invoices while
         * bounding the length-prefixed field before allocation (DoS guard) - see
         * [LtrRecordCodec]'s `proofType = 2` decode branch, which validates the declared length
         * against this cap BEFORE allocating the buffer. */
        const val MAX_SIGNED_INVOICE_BYTES = 2048
    }
}

/** Short, non-sensitive hex preview for [LightningProof.toString] - mirrors
 * [OnChainProof]'s file-local `toHexPreview()` (a private extension is not visible across files
 * in the same package, hence the separate, distinctly-named copy here). A preimage/payment hash
 * is public data once gossiped, unlike a private key or signature - see [LightningProof.preimage]'s
 * doc comment - so this is truncated purely to keep toString() output compact, not for secrecy. */
private fun ByteArray.toLightningHexPreview(): String = take(8).joinToString("") { "%02x".format(it) } + "…"
