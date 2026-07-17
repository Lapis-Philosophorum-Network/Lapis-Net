package net.lapisphilosophorum.lapisnet.trust

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify

/** First domain-separation tag reserved for Veritas trust-edge grants - see
 * [net.lapisphilosophorum.lapisnet.identity.IdentityBinding]'s own tag for the established
 * `"LapisNet:<purpose>:v<n>"` convention this follows. */
private const val VERITAS_TRUST_EDGE_DOMAIN_TAG = "LapisNet:veritas-trust-edge:v1"

private const val SIGNATURE_SIZE = 64
private const val CONTENT_ID_SIZE = 32

/** Full self-trust - `1.0` in the spec's `[0.0, 1.0]` value range. */
const val MAX_TRUST_MICROS = 1_000_000

/** Default / active distrust - `0.0` in the spec's value range. Also the value used to revoke a
 * prior grant (revocation is not a special case, just a new grant with this value). */
const val MIN_TRUST_MICROS = 0

/**
 * A Veritas web-of-trust edge: a signed, immutable statement that [truster] trusts [target] to
 * degree [trustMicros]. Not a point-spend - costs nothing, can be issued to arbitrarily many
 * targets arbitrarily often. Forms a Git-like backward-hash version chain per (truster, target)
 * pair via [previousGrantId]/[linksTo]: each new grant supersedes the previous one for that pair,
 * and the chain is fully auditable. See [net.lapisphilosophorum.lapisnet.trust] package docs / the
 * project's Veritas specification for the full social/protocol semantics.
 *
 * Trust is represented as [trustMicros], a fixed-point integer in [MIN_TRUST_MICROS]..
 * [MAX_TRUST_MICROS] (millionths), deliberately not a `Double` - this value is part of a
 * cryptographically signed, cross-platform-verified structure, and floating point has real
 * hashing-determinism footguns (`-0.0` vs `0.0`, NaN encodings, subtle cross-JVM differences).
 * [trustFraction] is a display-only convenience derived from it, never part of the signed bytes.
 *
 * A single grant names exactly one target. The spec allows "one or more" targets per grant
 * conceptually, but the backward-hash chain is intrinsically per-(truster, target) pair - a
 * multi-target grant would need one backward-hash per target, breaking the clean "one chain, one
 * predecessor hash" model. Multiple targets are expressed as multiple single-target grants.
 */
class VeritasGrant private constructor(
    val truster: Secp256k1PublicKey,
    val target: Secp256k1PublicKey,
    val trustMicros: Int,
    previousGrantId: ByteArray?,
    val comment: String,
    occasionReferences: List<Cid>,
    signature: ByteArray,
) {
    private val storedPreviousGrantId: ByteArray? = previousGrantId?.copyOf()

    /** Content id (see [contentId]) of the grant this one supersedes for the same (truster,
     * target) pair, or `null` if this is the first grant in that chain. Returns a fresh copy. */
    val previousGrantId: ByteArray? get() = storedPreviousGrantId?.copyOf()

    /** Immutable snapshot - safe from later mutation of any list the caller passed in. */
    val occasionReferences: List<Cid> = occasionReferences.toList()

    private val storedSignature: ByteArray = signature.copyOf()

    /** Compact 64-byte ECDSA signature by [truster] over this grant's canonical bytes. Returns a
     * fresh copy on every access. Never log this at any log level. */
    val signature: ByteArray get() = storedSignature.copyOf()

    /** `true` iff this is the first grant in its (truster, target) chain (no predecessor). */
    val isGenesis: Boolean get() = storedPreviousGrantId == null

    /** Display-only convenience - `trustMicros / 1_000_000.0`. Never part of the signed bytes. */
    val trustFraction: Double get() = trustMicros.toDouble() / MAX_TRUST_MICROS

    init {
        require(trustMicros in MIN_TRUST_MICROS..MAX_TRUST_MICROS) {
            "trustMicros must be in $MIN_TRUST_MICROS..$MAX_TRUST_MICROS, was $trustMicros"
        }
        require(storedSignature.size == SIGNATURE_SIZE) {
            "grant signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature"
        }
        require(storedPreviousGrantId == null || storedPreviousGrantId.size == CONTENT_ID_SIZE) {
            "previousGrantId must be a $CONTENT_ID_SIZE-byte content id or null"
        }
        val commentBytes = comment.toByteArray(Charsets.UTF_8)
        require(commentBytes.size <= VeritasGrantCodec.MAX_COMMENT_BYTES) {
            "comment must be at most ${VeritasGrantCodec.MAX_COMMENT_BYTES} UTF-8 bytes"
        }
        require(this.occasionReferences.size <= VeritasGrantCodec.MAX_OCCASION_REFERENCES) {
            "at most ${VeritasGrantCodec.MAX_OCCASION_REFERENCES} occasion references allowed"
        }
    }

    /**
     * SHA-256 over this grant's full canonical bytes (signed body + signature, see
     * [VeritasGrantCodec.encode]). A successor grant in the same (truster, target) chain embeds
     * this as its [previousGrantId] - this is the "backward hash" the wave is named for.
     */
    fun contentId(): ByteArray = VeritasGrantCodec.contentId(this)

    /** `true` iff this grant has a predecessor and that predecessor's [contentId] matches it -
     * i.e. this grant is the direct, authenticated successor of [predecessor]. */
    fun linksTo(predecessor: VeritasGrant): Boolean =
        storedPreviousGrantId != null && storedPreviousGrantId.contentEquals(predecessor.contentId())

    override fun equals(other: Any?): Boolean {
        if (other !is VeritasGrant) return false
        val previousMatches =
            when {
                storedPreviousGrantId == null && other.storedPreviousGrantId == null -> true
                storedPreviousGrantId == null || other.storedPreviousGrantId == null -> false
                else -> storedPreviousGrantId.contentEquals(other.storedPreviousGrantId)
            }
        return truster == other.truster &&
            target == other.target &&
            trustMicros == other.trustMicros &&
            previousMatches &&
            comment == other.comment &&
            occasionReferences == other.occasionReferences &&
            storedSignature.contentEquals(other.storedSignature)
    }

    override fun hashCode(): Int {
        var result = truster.hashCode()
        result = 31 * result + target.hashCode()
        result = 31 * result + trustMicros
        result = 31 * result + (storedPreviousGrantId?.contentHashCode() ?: 0)
        result = 31 * result + comment.hashCode()
        result = 31 * result + occasionReferences.hashCode()
        result = 31 * result + storedSignature.contentHashCode()
        return result
    }

    override fun toString(): String =
        "VeritasGrant(truster=${truster.fingerprint()}, target=${target.fingerprint()}, " +
            "trustMicros=$trustMicros, genesis=$isGenesis, refs=${occasionReferences.size})"

    companion object {
        private fun signingDigest(body: ByteArray): ByteArray =
            domainSeparatedDigest(VERITAS_TRUST_EDGE_DOMAIN_TAG, body)

        /**
         * Creates and signs a new grant from [truster] to [target]. Pass [previous] (the actual
         * predecessor grant in this (truster, target) chain) to link it into the version chain -
         * its [contentId] is derived here, so the caller cannot embed a wrong/stale link. Omit
         * (or pass `null`) for the first grant in a chain.
         */
        fun create(
            truster: Secp256k1KeyPair,
            target: Secp256k1PublicKey,
            trustMicros: Int,
            comment: String = "",
            occasionReferences: List<Cid> = emptyList(),
            previous: VeritasGrant? = null,
        ): VeritasGrant =
            createFromPreviousId(
                truster = truster,
                target = target,
                trustMicros = trustMicros,
                comment = comment,
                occasionReferences = occasionReferences,
                previousGrantId = previous?.contentId(),
            )

        /**
         * As [create], but for callers holding only the predecessor's [contentId] bytes rather
         * than the predecessor [VeritasGrant] object itself (e.g. a chain-walking caller that
         * only fetched the content id, not the full grant).
         */
        fun createFromPreviousId(
            truster: Secp256k1KeyPair,
            target: Secp256k1PublicKey,
            trustMicros: Int,
            comment: String = "",
            occasionReferences: List<Cid> = emptyList(),
            previousGrantId: ByteArray?,
        ): VeritasGrant {
            val body =
                VeritasGrantCodec.encodeSignedBody(
                    truster = truster.publicKey,
                    target = target,
                    trustMicros = trustMicros,
                    previousGrantId = previousGrantId,
                    comment = comment,
                    occasionReferences = occasionReferences,
                )
            val signature = truster.sign(signingDigest(body))
            return VeritasGrant(
                truster.publicKey,
                target,
                trustMicros,
                previousGrantId,
                comment,
                occasionReferences,
                signature,
            )
        }

        /** Self-contained cryptographic verification: checks [grant]'s signature against the
         * truster public key embedded in the grant itself. */
        fun verify(grant: VeritasGrant): Boolean {
            val body = VeritasGrantCodec.encodeSignedBody(grant)
            return grant.truster.verify(signingDigest(body), grant.signature)
        }

        /** As [verify], but additionally asserts [grant] was signed by [expectedTruster] rather
         * than trusting whichever truster key happens to be embedded in the grant. */
        fun verify(
            expectedTruster: Secp256k1PublicKey,
            grant: VeritasGrant,
        ): Boolean = grant.truster == expectedTruster && verify(grant)

        /** Reconstructs a grant from already-decoded, unverified fields. Used only by
         * [VeritasGrantCodec.decode] - callers must call [verify] before trusting the result. */
        internal fun fromDecoded(
            truster: Secp256k1PublicKey,
            target: Secp256k1PublicKey,
            trustMicros: Int,
            previousGrantId: ByteArray?,
            comment: String,
            occasionReferences: List<Cid>,
            signature: ByteArray,
        ): VeritasGrant =
            VeritasGrant(truster, target, trustMicros, previousGrantId, comment, occasionReferences, signature)
    }
}
