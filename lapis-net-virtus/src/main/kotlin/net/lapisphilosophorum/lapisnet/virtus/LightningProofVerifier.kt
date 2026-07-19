package net.lapisphilosophorum.lapisnet.virtus

import fr.acinq.lightning.payment.Bolt11Invoice
import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.security.MessageDigest

/** Domain-separation prefix for [LightningProofVerifier.canonicalMemo] - deliberately distinct
 * from every other signing-domain tag in this codebase (see [LtrRecord]'s
 * `VIRTUS_LTR_RECORD_DOMAIN_TAG` for the established `"LapisNet:<purpose>:v<n>"` convention this
 * loosely mirrors), even though this is a BOLT-11 invoice *description* string, not a secp256k1
 * signing digest - it exists purely to make a Lightning-proof memo unambiguous and
 * cross-application-collision-resistant, the same reasoning as every other domain tag here. */
private const val LIGHTNING_MEMO_PREFIX = "lapisnet-ltr:v1:"

/**
 * The sole consumer of `lightning-kmp`/`fr.acinq.*` types in this module - every one of them stays
 * confined to this file (see this module's `build.gradle.kts` header comment). Performs the
 * complete cryptographic verification chain for a [LightningProof]: preimage-to-hash, real BOLT-11
 * parsing + signature verification (via [Bolt11Invoice.read]), and the anti-spoofing/anti-replay
 * cross-checks against the [LtrRecord] the proof is attached to.
 *
 * **Called from [LtrGossip]'s gossip hot path - a deliberate divergence from [OnChainProof].** See
 * [LtrGossip]'s doc comment for the full reasoning: unlike [OnChainProof]'s live chain lookup
 * (which has a liveness dependency on a third party and stays out of the validation path),
 * [verify] is a pure, bounded, local computation with no network I/O - safe to run on every
 * gossip-received [LightningProof] record.
 */
object LightningProofVerifier {
    /**
     * The canonical BOLT-11 `description` a [LightningProof]'s [signedInvoice][LightningProof.signedInvoice]
     * must carry for [cid]/[viewId] - the anti-replay binding that stops a genuine, validly-signed
     * `(preimage, invoice)` pair paid for one `(cid, viewId)` pair from being replayed as if it
     * proved a payment for a different one. Bound into the invoice itself (not just the
     * [LtrRecord]'s own signed body) because the invoice's own BOLT-11 signature is what actually
     * proves a real Lightning node committed to it - the [LtrRecord]'s signature alone only proves
     * the payer *submitted* the claim, not that the claimed invoice was ever real.
     */
    fun canonicalMemo(
        cid: Cid,
        viewId: Secp256k1PublicKey,
    ): String = LIGHTNING_MEMO_PREFIX + cid.toString() + ":" + viewId.bytes.toLightningHex()

    /**
     * The full verification chain for [proof] against [record]. Returns `false` - never throws -
     * for any failure: a hash mismatch, an unparseable/unsigned-correctly invoice, a
     * recipient/amount/content mismatch, or any unexpected exception from the underlying
     * `lightning-kmp`/`bitcoin-kmp` call chain (defense-in-depth against a remote DoS via
     * adversarial invoice bytes - see this object's class doc comment).
     *
     * Steps, all AND-ed:
     *  1. `sha256(proof.preimage) == proof.paymentHash`.
     *  2. [proof]'s [LightningProof.signedInvoice] parses as a real BOLT-11 invoice with a valid
     *     signature ([Bolt11Invoice.read] verifies the signature internally as part of parsing).
     *  3. The invoice's own parsed payment hash equals [proof]'s [LightningProof.paymentHash].
     *  4. The invoice declares a non-null amount, and that amount (in msat) equals
     *     [record]'s `initialValueMsat` exactly - the invoice is the source of truth for the
     *     amount, an amountless invoice cannot prove any specific payment size, and this is the
     *     anti-amount-spoofing check.
     *  5. The invoice's signer (`nodeId`) equals [record]'s `viewId` bytes - **mandatory, not
     *     optional**: a manufacturer's Lightning node key IS its Lapis viewId, by protocol
     *     commitment. This is the anti-recipient-spoofing check; without it, anyone could pay
     *     their own Lightning node and claim the resulting proof boosts a completely different
     *     view.
     *  6. The invoice's `description` equals [canonicalMemo] for `(record.cid, record.viewId)`
     *     exactly - the anti-replay check (see [canonicalMemo]'s doc comment). An invoice using
     *     `descriptionHash` instead of a plain `description` is rejected outright: there is no way
     *     to confirm a hash-only description actually matches the canonical memo without the
     *     preimage of that hash, which this verifier never has.
     *
     * **Deliberately NOT checked: invoice expiry.** A settled payment's invoice may legitimately
     * be past its own BOLT-11 expiry by the time the resulting [LtrRecord] propagates through
     * gossip - the payment already happened, and expiry only ever governs whether a *new* payment
     * attempt against that invoice should still be accepted, which is irrelevant once a preimage
     * already proves settlement.
     */
    fun verify(
        record: LtrRecord,
        proof: LightningProof,
    ): Boolean =
        runCatching {
            val computedHash = sha256(proof.preimage)
            if (!computedHash.contentEquals(proof.paymentHash)) return@runCatching false

            val parsed = Bolt11Invoice.read(proof.signedInvoice)
            if (parsed.isFailure) return@runCatching false
            val invoice = parsed.get()

            if (!invoice.paymentHash.toByteArray().contentEquals(proof.paymentHash)) return@runCatching false

            val invoiceAmountMsat = invoice.amount ?: return@runCatching false
            if (invoiceAmountMsat.toLong() != record.initialValueMsat) return@runCatching false

            if (!invoice.nodeId.value
                    .toByteArray()
                    .contentEquals(record.viewId.bytes)
            ) {
                return@runCatching false
            }

            val description = invoice.description ?: return@runCatching false
            if (description != canonicalMemo(record.cid, record.viewId)) return@runCatching false

            true
        }.getOrDefault(false)

    /**
     * The parsed invoice's amount in msat, or `null` if [signedInvoice] is unparseable or
     * amountless - used by `lapis-net-browser`'s `POST /api/ltr/lightning` route to derive
     * `initialValueMsat` server-side from the invoice itself, never trusting a client-supplied
     * amount (see that route's doc comment). Kept here, rather than in `lapis-net-browser`, so
     * that module never needs its own `lightning-kmp` dependency - see this module's
     * `build.gradle.kts` header comment. Never throws - defensive [runCatching] mirrors [verify].
     */
    fun invoiceAmountMsatOrNull(signedInvoice: String): Long? =
        runCatching {
            val parsed = Bolt11Invoice.read(signedInvoice)
            if (parsed.isFailure) return@runCatching null
            parsed.get().amount?.toLong()
        }.getOrNull()

    /** A fresh [MessageDigest] instance per call - [MessageDigest] is not thread-safe (mirrors
     * [LtrRecordCodec]'s own `sha256` helper and every other hashing call site in this codebase). */
    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}

/** Full (not truncated/fingerprint) lower-case hex encoding - deliberately distinct from
 * [net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex] (which hashes-then-truncates for
 * display) since [LightningProofVerifier.canonicalMemo] needs every byte of [viewId]'s bytes to
 * unambiguously identify it, not a lossy fingerprint. Mirrors the same file-local, non-shared
 * `toHex()` convention already used in `lapis-net-karma` (`ElectrumTimeAnchorSource.kt`) and
 * `lapis-net-browser` (`BrowserApi.kt`'s `toHexString()`) - there is no shared hex-encoding helper
 * in this codebase to reuse instead. */
private fun ByteArray.toLightningHex(): String = joinToString("") { "%02x".format(it) }
