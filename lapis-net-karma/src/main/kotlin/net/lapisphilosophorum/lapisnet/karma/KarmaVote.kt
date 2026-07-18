package net.lapisphilosophorum.lapisnet.karma

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify
import java.security.SecureRandom

/** Domain-separation tag for Karma vote signatures - see
 * [net.lapisphilosophorum.lapisnet.identity.IdentityBinding]'s own tag for the established
 * `"LapisNet:<purpose>:v<n>"` convention this follows. Deliberately distinct from every other
 * signing purpose in this project (`"LapisNet:veritas-trust-edge:v1"`,
 * `"LapisNet:virtus-ltr-record:v1"`, `"LapisNet:browser-post-announcement:v1"`,
 * `"LapisNet:identity-binding:v1"`) - a signature produced for one of those purposes must never be
 * reinterpretable as a signature for a Karma vote over the same bytes. */
private const val KARMA_VOTE_DOMAIN_TAG = "LapisNet:karma-vote:v1"

private const val SIGNATURE_SIZE = 64
private const val NONCE_SIZE = 8

/**
 * A cheap, one-click "like": a signed claim by [voter] that they like the content identified by
 * [targetCid], carrying their own [timeAnchor] claim (see that sealed interface's doc comment) so
 * an observer can compute this vote's Karma value (see [KarmaWeightCalculator]) without any chain
 * lookup of its own. Mirrors [net.lapisphilosophorum.lapisnet.virtus.LtrRecord]'s private-
 * constructor + companion-factory shape exactly - Karma's accumulating-not-resolved model (every
 * vote for a target is kept, never resolved to one winner - see [KarmaVoteIndex]'s doc comment) is
 * closer to Virtus's [net.lapisphilosophorum.lapisnet.virtus.LtrRecord] than to Veritas's
 * latest-wins [net.lapisphilosophorum.lapisnet.trust.VeritasGrant] chain.
 *
 * **Why [nonce] exists - not part of any hypothetical "spec schema", an engineering necessity,
 * same reasoning as [net.lapisphilosophorum.lapisnet.virtus.LtrRecord.nonce].** Two genuinely
 * independent likes of the same content by the same [voter] within the same wall-clock second
 * (entirely plausible - e.g. a user double-tapping "like" on two different sessions, or simply two
 * votes with identical fields by coincidence) would otherwise encode to byte-identical
 * [KarmaVoteCodec.encode] output. [KarmaGossip] (content-id-keyed gossip dedup, mirroring
 * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip]) would then treat the second, real,
 * independently-cast vote as an exact-content-id replay of the first and silently drop it.
 * [nonce] (8 random bytes, freshly generated per [create] call, folded into the signed body) makes
 * two otherwise-identical votes cryptographically distinct with overwhelming probability, so this
 * collision cannot happen in practice.
 *
 * **[signature] - never log this at any log level.** Matches
 * [net.lapisphilosophorum.lapisnet.virtus.LtrRecord.signature]'s established convention.
 */
class KarmaVote private constructor(
    val voter: Secp256k1PublicKey,
    val targetCid: Cid,
    val timestampSeconds: Long,
    val timeAnchor: TimeAnchorClaim,
    nonce: ByteArray,
    signature: ByteArray,
) {
    private val storedNonce: ByteArray = nonce.copyOf()

    /** 8 random bytes, freshly generated per [create] call - see this class's doc comment on why
     * this exists. Returns a fresh copy on every access. */
    val nonce: ByteArray get() = storedNonce.copyOf()

    private val storedSignature: ByteArray = signature.copyOf()

    /** Compact 64-byte ECDSA signature by [voter] over this vote's canonical bytes. Returns a
     * fresh copy on every access. Never log this at any log level. */
    val signature: ByteArray get() = storedSignature.copyOf()

    init {
        require(storedNonce.size == NONCE_SIZE) { "nonce must be exactly $NONCE_SIZE bytes" }
        require(storedSignature.size == SIGNATURE_SIZE) {
            "vote signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature"
        }
    }

    /**
     * SHA-256 over this vote's full canonical bytes (signed body + signature, see
     * [KarmaVoteCodec.encode]) - the content id [KarmaVoteIndex] dedups gossip delivery by,
     * mirroring [net.lapisphilosophorum.lapisnet.virtus.LtrRecord.contentId]'s role exactly.
     */
    fun contentId(): ByteArray = KarmaVoteCodec.contentId(this)

    override fun equals(other: Any?): Boolean {
        if (other !is KarmaVote) return false
        return voter == other.voter &&
            targetCid == other.targetCid &&
            timestampSeconds == other.timestampSeconds &&
            timeAnchor == other.timeAnchor &&
            storedNonce.contentEquals(other.storedNonce) &&
            storedSignature.contentEquals(other.storedSignature)
    }

    override fun hashCode(): Int {
        var result = voter.hashCode()
        result = 31 * result + targetCid.hashCode()
        result = 31 * result + timestampSeconds.hashCode()
        result = 31 * result + timeAnchor.hashCode()
        result = 31 * result + storedNonce.contentHashCode()
        result = 31 * result + storedSignature.contentHashCode()
        return result
    }

    /** Deliberately excludes [signature] - see this class's doc comment on never logging it. */
    override fun toString(): String =
        "KarmaVote(voter=${voter.fingerprint()}, targetCid=$targetCid, " +
            "timestampSeconds=$timestampSeconds, timeAnchor=$timeAnchor)"

    companion object {
        private fun signingDigest(body: ByteArray): ByteArray = domainSeparatedDigest(KARMA_VOTE_DOMAIN_TAG, body)

        /**
         * Creates and signs a new Karma vote. [timeAnchor] should be [voter]'s real, freshly (or
         * cache-)resolved anchor claim - see [KarmaAnchorCache.currentClaimFor] - never a
         * self-serving fabrication, though nothing in this structural layer can prevent that (see
         * [ChainAnchorClaim]'s doc comment: gossip acceptance never verifies this claim against a
         * real chain). A fresh [nonce] is drawn from [random] on every call - see this class's doc
         * comment for why that matters.
         */
        fun create(
            voter: Secp256k1KeyPair,
            targetCid: Cid,
            timeAnchor: TimeAnchorClaim,
            timestampSeconds: Long = System.currentTimeMillis() / 1000,
            random: SecureRandom = SecureRandom(),
        ): KarmaVote {
            val nonce = ByteArray(NONCE_SIZE).also(random::nextBytes)
            val body =
                KarmaVoteCodec.encodeSignedBody(
                    voter = voter.publicKey,
                    targetCid = targetCid,
                    timestampSeconds = timestampSeconds,
                    timeAnchor = timeAnchor,
                    nonce = nonce,
                )
            val signature = voter.sign(signingDigest(body))
            return KarmaVote(voter.publicKey, targetCid, timestampSeconds, timeAnchor, nonce, signature)
        }

        /** Self-contained cryptographic verification: checks [vote]'s signature against the voter
         * public key embedded in the vote itself. */
        fun verify(vote: KarmaVote): Boolean {
            val body = KarmaVoteCodec.encodeSignedBody(vote)
            return vote.voter.verify(signingDigest(body), vote.signature)
        }

        /** As [verify], but additionally asserts [vote] was signed by [expectedVoter] rather than
         * trusting whichever voter key happens to be embedded in the vote. */
        fun verify(
            expectedVoter: Secp256k1PublicKey,
            vote: KarmaVote,
        ): Boolean = vote.voter == expectedVoter && verify(vote)

        /** Reconstructs a vote from already-decoded, unverified fields. Used only by
         * [KarmaVoteCodec.decode] - callers must call [verify] before trusting the result. */
        internal fun fromDecoded(
            voter: Secp256k1PublicKey,
            targetCid: Cid,
            timestampSeconds: Long,
            timeAnchor: TimeAnchorClaim,
            nonce: ByteArray,
            signature: ByteArray,
        ): KarmaVote = KarmaVote(voter, targetCid, timestampSeconds, timeAnchor, nonce, signature)
    }
}
