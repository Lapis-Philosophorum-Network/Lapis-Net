package net.lapisphilosophorum.lapisnet.virtus

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify
import java.security.SecureRandom

/** Domain-separation tag for Virtus/LTR record signatures - see
 * [net.lapisphilosophorum.lapisnet.identity.IdentityBinding]'s own tag for the established
 * `"LapisNet:<purpose>:v<n>"` convention this follows. Deliberately distinct from
 * `"LapisNet:veritas-trust-edge:v1"` ([net.lapisphilosophorum.lapisnet.trust.VeritasGrant]) even
 * though both are secp256k1-signed structures - a signature produced for a trust edge must never
 * be reinterpretable as a signature for an LTR record over the same bytes. */
private const val VIRTUS_LTR_RECORD_DOMAIN_TAG = "LapisNet:virtus-ltr-record:v1"

private const val SIGNATURE_SIZE = 64
private const val NONCE_SIZE = 8

/** Technical floor: 1 msat is the smallest unit a Lightning payment can express - see the Virtus
 * spec note's "Mindestbetrag" section. Below this, no valid payment - and therefore no valid
 * [proof] - can exist at all. */
const val MIN_INITIAL_VALUE_MSAT = 1L

/** 21,000,000 BTC expressed in msat (`21_000_000 * 100_000_000 * 1000` = 2.1 * 10^18) - the
 * absolute maximum that could ever exist under Bitcoin's own supply cap. Chosen for that domain
 * reason alone - **NOT** an engineering safety margin against [Long] summation overflow in
 * [net.lapisphilosophorum.lapisnet.virtus.LtrWeightCalculator.totalInvestedMsat]. The margin is
 * thin: [Long.MAX_VALUE] (about 9.2 * 10^18) divided by this constant is only about 4.4, so as
 * few as **5** records at this maximum value already overflow a running [Long] sum - not "a very
 * large number of records" (4 such records sum to 8.4 * 10^18, still under [Long.MAX_VALUE]; a
 * 5th pushes the running total past it). Because this wave's [OnChainProof] performs no live
 * chain verification (see its class doc comment), an attacker can costlessly self-sign 5 records
 * at this maximum value for a single `(cid, viewId)` pair - comfortably within
 * [LtrRecordIndex.MAX_TRACKED_RECORDS] - and get them gossiped/indexed via ordinary
 * structural+signature validation alone. See [LtrWeightCalculator.totalInvestedMsat]'s doc
 * comment for the resulting caller contract. */
const val MAX_INITIAL_VALUE_MSAT = 21_000_000L * 100_000_000L * 1000L

/**
 * A Virtus/LTR record: a signed, immutable claim by [payer] that they paid [initialValueMsat]
 * msat (real Bitcoin, per [proof]) to boost the sort-weight of content identified by [cid] within
 * the view identified by [viewId]. See the Virtus spec note (`Virtus - Libertaler.md`) for the
 * full economic/protocol semantics; this class only carries the signed data model.
 *
 * **No backward-hash version chain, unlike [net.lapisphilosophorum.lapisnet.trust.VeritasGrant].**
 * A Veritas grant supersedes its predecessor - only the latest grant in a (truster, target) chain
 * matters. An LtrRecord is the opposite: every record for the same `(cid, viewId)` pair is kept
 * and its decayed value summed independently, forever - see the spec note's "Akkumulationslogik"
 * section (`aktuelles_Gewicht = Σ record.initial_value × 0.9 ^ (stunden / 24)` over ALL records
 * for the pair, not just the latest one). There is no "latest winner" to resolve to, so there is
 * no predecessor link to embed.
 *
 * **Why [initialValueMsat] and not sats.** The spec note's protocol-level floor is 1 msat, not
 * 1 sat (`initial_value ≥ 1 msat`, see "Mindestbetrag") - a view is free to treat sub-sat records
 * as zero-weight (the reference browser's own convention), but the protocol itself must not
 * silently round away sub-sat precision, because a planned second [LtrProof] implementation
 * (Lightning, per the spec note's "A. Lightning via BOLT-12 Offer" path, not built in this wave)
 * needs exactly that sub-sat precision for its own future payment amounts. [initialValueSats] is
 * a convenience display-only derivation, never part of the signed bytes.
 *
 * **Why [nonce] exists - NOT part of the literal spec schema, an engineering necessity.** The
 * spec note's `LtrRecord` schema (`Virtus - Libertaler.md`) has no nonce field. Without one,
 * two genuinely independent boosts - e.g. the same [payer] buying two separate LTR boosts for the
 * same `(cid, viewId)` within the same wall-clock second, for the exact same [initialValueMsat]
 * (entirely plausible for a "like" boost with a conventional round amount) - would encode to
 * byte-identical [LtrRecordCodec.encode] output. [net.lapisphilosophorum.lapisnet.virtus.LtrGossip]
 * (mirroring [net.lapisphilosophorum.lapisnet.trust.VeritasGossip]'s content-id-keyed gossip
 * dedup) would then treat the second, real, independently-paid boost as an exact-content-id replay
 * of the first and silently drop it - permanently losing real economic weight the payer actually
 * paid for. [nonce] (8 random bytes, freshly generated per [create] call, folded into the signed
 * body) makes two otherwise-identical records cryptographically distinct with overwhelming
 * probability, so this collision cannot happen in practice.
 *
 * **[signature] - never log this at any log level.** Matches
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGrant.signature]'s established convention.
 */
class LtrRecord private constructor(
    val cid: Cid,
    val viewId: Secp256k1PublicKey,
    val payer: Secp256k1PublicKey,
    val initialValueMsat: Long,
    val timestampSeconds: Long,
    nonce: ByteArray,
    val proof: LtrProof,
    signature: ByteArray,
) {
    private val storedNonce: ByteArray = nonce.copyOf()

    /** 8 random bytes, freshly generated per [create] call - see this class's doc comment on why
     * this exists. Returns a fresh copy on every access. */
    val nonce: ByteArray get() = storedNonce.copyOf()

    private val storedSignature: ByteArray = signature.copyOf()

    /** Compact 64-byte ECDSA signature by [payer] over this record's canonical bytes. Returns a
     * fresh copy on every access. Never log this at any log level. */
    val signature: ByteArray get() = storedSignature.copyOf()

    /** Display-only convenience - `initialValueMsat / 1000.0`. Never part of the signed bytes. */
    val initialValueSats: Double get() = initialValueMsat / 1000.0

    init {
        require(initialValueMsat in MIN_INITIAL_VALUE_MSAT..MAX_INITIAL_VALUE_MSAT) {
            "initialValueMsat must be in $MIN_INITIAL_VALUE_MSAT..$MAX_INITIAL_VALUE_MSAT, was $initialValueMsat"
        }
        require(storedNonce.size == NONCE_SIZE) { "nonce must be exactly $NONCE_SIZE bytes" }
        require(storedSignature.size == SIGNATURE_SIZE) {
            "record signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature"
        }
    }

    /**
     * SHA-256 over this record's full canonical bytes (signed body + signature, see
     * [LtrRecordCodec.encode]) - the content id [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex]
     * dedups gossip delivery by, mirroring
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrant.contentId]'s role exactly.
     */
    fun contentId(): ByteArray = LtrRecordCodec.contentId(this)

    override fun equals(other: Any?): Boolean {
        if (other !is LtrRecord) return false
        return cid == other.cid &&
            viewId == other.viewId &&
            payer == other.payer &&
            initialValueMsat == other.initialValueMsat &&
            timestampSeconds == other.timestampSeconds &&
            storedNonce.contentEquals(other.storedNonce) &&
            proof == other.proof &&
            storedSignature.contentEquals(other.storedSignature)
    }

    override fun hashCode(): Int {
        var result = cid.hashCode()
        result = 31 * result + viewId.hashCode()
        result = 31 * result + payer.hashCode()
        result = 31 * result + initialValueMsat.hashCode()
        result = 31 * result + timestampSeconds.hashCode()
        result = 31 * result + storedNonce.contentHashCode()
        result = 31 * result + proof.hashCode()
        result = 31 * result + storedSignature.contentHashCode()
        return result
    }

    /** Deliberately excludes [signature] - see this class's doc comment on never logging it. */
    override fun toString(): String =
        "LtrRecord(cid=$cid, viewId=${viewId.fingerprint()}, payer=${payer.fingerprint()}, " +
            "initialValueMsat=$initialValueMsat, timestampSeconds=$timestampSeconds, proof=$proof)"

    companion object {
        private fun signingDigest(body: ByteArray): ByteArray =
            domainSeparatedDigest(VIRTUS_LTR_RECORD_DOMAIN_TAG, body)

        /**
         * Creates and signs a new LTR record. [payer] is whoever's Bitcoin funded this boost - the
         * content's original author for an initial payment or an author self-boost, or a different
         * user entirely for a like-boost (see the Virtus spec note's "Nachträgliches Aufstocken"
         * section) - never necessarily the content's author. A fresh [nonce] is drawn from [random]
         * on every call - see this class's doc comment for why that matters.
         */
        fun create(
            payer: Secp256k1KeyPair,
            cid: Cid,
            viewId: Secp256k1PublicKey,
            initialValueMsat: Long,
            proof: LtrProof,
            timestampSeconds: Long = System.currentTimeMillis() / 1000,
            random: SecureRandom = SecureRandom(),
        ): LtrRecord {
            val nonce = ByteArray(NONCE_SIZE).also(random::nextBytes)
            val body =
                LtrRecordCodec.encodeSignedBody(
                    cid = cid,
                    viewId = viewId,
                    payer = payer.publicKey,
                    initialValueMsat = initialValueMsat,
                    timestampSeconds = timestampSeconds,
                    nonce = nonce,
                    proof = proof,
                )
            val signature = payer.sign(signingDigest(body))
            return LtrRecord(cid, viewId, payer.publicKey, initialValueMsat, timestampSeconds, nonce, proof, signature)
        }

        /** Self-contained cryptographic verification: checks [record]'s signature against the
         * payer public key embedded in the record itself. */
        fun verify(record: LtrRecord): Boolean {
            val body = LtrRecordCodec.encodeSignedBody(record)
            return record.payer.verify(signingDigest(body), record.signature)
        }

        /** As [verify], but additionally asserts [record] was signed by [expectedPayer] rather
         * than trusting whichever payer key happens to be embedded in the record. */
        fun verify(
            expectedPayer: Secp256k1PublicKey,
            record: LtrRecord,
        ): Boolean = record.payer == expectedPayer && verify(record)

        /** Reconstructs a record from already-decoded, unverified fields. Used only by
         * [LtrRecordCodec.decode] - callers must call [verify] before trusting the result. */
        internal fun fromDecoded(
            cid: Cid,
            viewId: Secp256k1PublicKey,
            payer: Secp256k1PublicKey,
            initialValueMsat: Long,
            timestampSeconds: Long,
            nonce: ByteArray,
            proof: LtrProof,
            signature: ByteArray,
        ): LtrRecord = LtrRecord(cid, viewId, payer, initialValueMsat, timestampSeconds, nonce, proof, signature)
    }
}
