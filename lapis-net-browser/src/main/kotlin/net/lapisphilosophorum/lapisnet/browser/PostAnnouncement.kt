package net.lapisphilosophorum.lapisnet.browser

import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.identity.verify
import java.security.SecureRandom

/** Domain-separation tag for browser post-announcement signatures - see
 * [net.lapisphilosophorum.lapisnet.identity.IdentityBinding]'s own tag for the established
 * `"LapisNet:<purpose>:v<n>"` convention this follows. Deliberately distinct from both
 * `"LapisNet:veritas-trust-edge:v1"` ([net.lapisphilosophorum.lapisnet.trust.VeritasGrant]) and
 * `"LapisNet:virtus-ltr-record:v1"` ([net.lapisphilosophorum.lapisnet.virtus.LtrRecord]) - a
 * signature produced for one of those purposes must never be reinterpretable as a signature for a
 * post announcement over the same bytes. */
private const val BROWSER_POST_ANNOUNCEMENT_DOMAIN_TAG = "LapisNet:browser-post-announcement:v1"

private const val SIGNATURE_SIZE = 64
private const val NONCE_SIZE = 8

/** Upper bound on a post's UTF-8 body length - a pilot-stage sanity limit for the Minimal-Browser
 * MVP, not a protocol-wide constant. Kept small and deliberately generous only for short-form
 * posts; a future wave that wants longer-form content should introduce its own signed content
 * type rather than raising this. */
const val MAX_POST_BODY_BYTES = 2_048

/**
 * A browser-MVP signed post: an immutable claim by [author] that they authored the UTF-8 text
 * carried in [bodyBytes] at [timestampSeconds]. Mirrors [net.lapisphilosophorum.lapisnet.virtus.LtrRecord]'s
 * private-constructor + companion-factory shape exactly - see that class's doc comment for the
 * general pattern this follows.
 *
 * **Why [nonce] exists - not part of any hypothetical "spec schema", an engineering necessity,
 * same reasoning as [net.lapisphilosophorum.lapisnet.virtus.LtrRecord.nonce].** Two genuinely
 * independent posts by the same [author] with byte-identical text within the same wall-clock
 * second (entirely plausible - e.g. a repeated short reply like "yes" or "lol") would otherwise
 * encode to byte-identical [PostAnnouncementCodec.encode] output. [PostAnnouncementGossip]
 * (content-id-keyed gossip dedup, mirroring [net.lapisphilosophorum.lapisnet.virtus.LtrGossip])
 * would then treat the second, real, independently-authored post as an exact-content-id replay of
 * the first and silently drop it. [nonce] (8 random bytes, freshly generated per [create] call,
 * folded into the signed body) makes two otherwise-identical posts cryptographically distinct
 * with overwhelming probability, so this collision cannot happen in practice.
 *
 * **[signature] - never log this at any log level.** Matches
 * [net.lapisphilosophorum.lapisnet.virtus.LtrRecord.signature]'s established convention.
 */
class PostAnnouncement private constructor(
    val author: Secp256k1PublicKey,
    bodyBytes: ByteArray,
    val timestampSeconds: Long,
    nonce: ByteArray,
    signature: ByteArray,
) {
    private val storedBodyBytes: ByteArray = bodyBytes.copyOf()

    /** Raw UTF-8 text bytes - part of the signed body. Returns a fresh copy on every access. */
    val bodyBytes: ByteArray get() = storedBodyBytes.copyOf()

    private val storedNonce: ByteArray = nonce.copyOf()

    /** 8 random bytes, freshly generated per [create] call - see this class's doc comment on why
     * this exists. Returns a fresh copy on every access. */
    val nonce: ByteArray get() = storedNonce.copyOf()

    private val storedSignature: ByteArray = signature.copyOf()

    /** Compact 64-byte ECDSA signature by [author] over this announcement's canonical bytes.
     * Returns a fresh copy on every access. Never log this at any log level. */
    val signature: ByteArray get() = storedSignature.copyOf()

    init {
        require(storedBodyBytes.size in 1..MAX_POST_BODY_BYTES) {
            "bodyBytes must be 1..$MAX_POST_BODY_BYTES bytes, was ${storedBodyBytes.size}"
        }
        require(storedNonce.size == NONCE_SIZE) { "nonce must be exactly $NONCE_SIZE bytes" }
        require(storedSignature.size == SIGNATURE_SIZE) {
            "announcement signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature"
        }
    }

    /** The post's text, decoded from [bodyBytes] as UTF-8. */
    fun text(): String = storedBodyBytes.toString(Charsets.UTF_8)

    /**
     * SHA-256 over this announcement's full canonical bytes (signed body + signature, see
     * [PostAnnouncementCodec.encode]) - the content id [PostAnnouncementGossip] dedups gossip
     * delivery by, mirroring [net.lapisphilosophorum.lapisnet.virtus.LtrRecord.contentId]'s role
     * exactly. **Not** the content-addressed [io.ipfs.cid.Cid] of [bodyBytes] alone - see
     * [PostAnnouncementGossip]'s doc comment for why the post body is separately content-addressed
     * by [net.lapisphilosophorum.lapisnet.storage.NabuStorage].
     */
    fun contentId(): ByteArray = PostAnnouncementCodec.contentId(this)

    override fun equals(other: Any?): Boolean {
        if (other !is PostAnnouncement) return false
        return author == other.author &&
            storedBodyBytes.contentEquals(other.storedBodyBytes) &&
            timestampSeconds == other.timestampSeconds &&
            storedNonce.contentEquals(other.storedNonce) &&
            storedSignature.contentEquals(other.storedSignature)
    }

    override fun hashCode(): Int {
        var result = author.hashCode()
        result = 31 * result + storedBodyBytes.contentHashCode()
        result = 31 * result + timestampSeconds.hashCode()
        result = 31 * result + storedNonce.contentHashCode()
        result = 31 * result + storedSignature.contentHashCode()
        return result
    }

    /** Deliberately excludes [signature] - see this class's doc comment on never logging it. Also
     * excludes [bodyBytes]/[text] to avoid dumping arbitrary user-authored content into logs. */
    override fun toString(): String =
        "PostAnnouncement(author=${author.fingerprint()}, timestampSeconds=$timestampSeconds, " +
            "bodyLength=${storedBodyBytes.size})"

    companion object {
        private fun signingDigest(body: ByteArray): ByteArray =
            domainSeparatedDigest(BROWSER_POST_ANNOUNCEMENT_DOMAIN_TAG, body)

        /**
         * Creates and signs a new post announcement. A fresh [nonce] is drawn from [random] on
         * every call - see this class's doc comment for why that matters.
         */
        fun create(
            author: Secp256k1KeyPair,
            bodyBytes: ByteArray,
            timestampSeconds: Long = System.currentTimeMillis() / 1000,
            random: SecureRandom = SecureRandom(),
        ): PostAnnouncement {
            val nonce = ByteArray(NONCE_SIZE).also(random::nextBytes)
            val body =
                PostAnnouncementCodec.encodeSignedBody(
                    author = author.publicKey,
                    bodyBytes = bodyBytes,
                    timestampSeconds = timestampSeconds,
                    nonce = nonce,
                )
            val signature = author.sign(signingDigest(body))
            return PostAnnouncement(author.publicKey, bodyBytes, timestampSeconds, nonce, signature)
        }

        /** Self-contained cryptographic verification: checks [announcement]'s signature against
         * the author public key embedded in the announcement itself. */
        fun verify(announcement: PostAnnouncement): Boolean {
            val body = PostAnnouncementCodec.encodeSignedBody(announcement)
            return announcement.author.verify(signingDigest(body), announcement.signature)
        }

        /** As [verify], but additionally asserts [announcement] was signed by [expectedAuthor]
         * rather than trusting whichever author key happens to be embedded in the announcement. */
        fun verify(
            expectedAuthor: Secp256k1PublicKey,
            announcement: PostAnnouncement,
        ): Boolean = announcement.author == expectedAuthor && verify(announcement)

        /** Reconstructs an announcement from already-decoded, unverified fields. Used only by
         * [PostAnnouncementCodec.decode] - callers must call [verify] before trusting the result. */
        internal fun fromDecoded(
            author: Secp256k1PublicKey,
            bodyBytes: ByteArray,
            timestampSeconds: Long,
            nonce: ByteArray,
            signature: ByteArray,
        ): PostAnnouncement = PostAnnouncement(author, bodyBytes, timestampSeconds, nonce, signature)
    }
}
