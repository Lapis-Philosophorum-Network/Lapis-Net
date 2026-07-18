package net.lapisphilosophorum.lapisnet.browser

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.security.MessageDigest

/**
 * Thrown when decoding a [PostAnnouncement]'s canonical byte encoding fails structurally (bad
 * magic, unsupported version, truncated/overrun buffer, out-of-range field). Never thrown for
 * signature verification failures - [PostAnnouncementCodec.decode] does not verify signatures,
 * see its doc comment. Mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.MalformedLtrRecordException]'s established
 * same-file-as-its-codec organization.
 */
class MalformedPostAnnouncementException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [PostAnnouncement] - used both to build the digest
 * that gets signed and to compute an announcement's content id (the gossip dedup key, see
 * [PostAnnouncementIndex]). Mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordCodec]'s sequential length-prefixed layout and
 * big-endian integer convention exactly.
 *
 * Layout of [encodeSignedBody]'s output: `magic(4="LNPA") | version(1) | author(33) | bodyLen(2) |
 * bodyBytes(bodyLen) | timestampSeconds(8) | nonce(8)`. [encode] appends the 64-byte signature
 * after that.
 */
object PostAnnouncementCodec {
    private val MAGIC = "LNPA".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private const val PUBLIC_KEY_SIZE = 33
    private const val SIGNATURE_SIZE = 64
    private const val NONCE_SIZE = 8

    /** [domainSeparatedDigest][net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest]
     * treats the whole signed body as a single part, capped at this size - mirrors
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordCodec.MAX_BODY_SIZE]'s reasoning. Worst
     * case here is tiny by comparison (magic+version+author+bodyLen+[MAX_POST_BODY_BYTES]+
     * timestamp+nonce ≈ 2.1 KB), well under the limit. */
    const val MAX_BODY_SIZE = 0xFFFF

    /** Builds the exact bytes that get domain-separated-digested and signed - see
     * [PostAnnouncement.Companion.create]. */
    fun encodeSignedBody(
        author: Secp256k1PublicKey,
        bodyBytes: ByteArray,
        timestampSeconds: Long,
        nonce: ByteArray,
    ): ByteArray {
        require(bodyBytes.size in 1..MAX_POST_BODY_BYTES) {
            "bodyBytes must be 1..$MAX_POST_BODY_BYTES bytes, was ${bodyBytes.size}"
        }
        require(nonce.size == NONCE_SIZE) { "nonce must be exactly $NONCE_SIZE bytes" }

        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            write(author.bytes)
            writeShort(bodyBytes.size)
            write(bodyBytes)
            writeLong(timestampSeconds)
            write(nonce)
        }
        val body = out.toByteArray()
        require(body.size <= MAX_BODY_SIZE) { "encoded announcement body exceeds $MAX_BODY_SIZE bytes: ${body.size}" }
        return body
    }

    /** As the other [encodeSignedBody] overload, pulling fields off an existing [announcement]. */
    fun encodeSignedBody(announcement: PostAnnouncement): ByteArray =
        encodeSignedBody(
            author = announcement.author,
            bodyBytes = announcement.bodyBytes,
            timestampSeconds = announcement.timestampSeconds,
            nonce = announcement.nonce,
        )

    /** The full canonical artifact: signed body followed by the 64-byte signature. This is what
     * [PostAnnouncementGossip] hands to `NabuStorage.put()` for the announcement wrapper's own
     * durable bytes, and the preimage of [contentId]. */
    fun encode(announcement: PostAnnouncement): ByteArray = encodeSignedBody(announcement) + announcement.signature

    /** Plain (not domain-separated) SHA-256 of [encode] - the gossip dedup / index lookup key,
     * not itself a signed value. */
    fun contentId(announcement: PostAnnouncement): ByteArray = sha256(encode(announcement))

    /**
     * Structural decode only - does **not** verify the signature, matching
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordCodec.decode]'s exact contract. An
     * announcement typically arrives from an untrusted peer over gossip; callers must explicitly
     * call [PostAnnouncement.Companion.verify] before trusting it.
     *
     * @throws MalformedPostAnnouncementException if the bytes are structurally invalid, including
     * an out-of-range field or trailing bytes after the signature. `bodyLen` is validated BEFORE
     * the corresponding buffer is allocated, mirroring
     * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordCodec.decode]'s `cidLen`/`proofLen` checks -
     * an attacker cannot force an oversized allocation by sending a malicious length prefix.
     */
    fun decode(bytes: ByteArray): PostAnnouncement {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedPostAnnouncementException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedPostAnnouncementException("unsupported version $version")

            val authorBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }

            val bodyLen = input.readUnsignedShort()
            if (bodyLen !in 1..MAX_POST_BODY_BYTES) {
                throw MalformedPostAnnouncementException("invalid body length: $bodyLen")
            }
            val bodyBytes = ByteArray(bodyLen).also { input.readFully(it) }

            val timestampSeconds = input.readLong()
            val nonce = ByteArray(NONCE_SIZE).also { input.readFully(it) }

            val signature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedPostAnnouncementException("trailing bytes after signature")

            return PostAnnouncement.fromDecoded(
                author = Secp256k1PublicKey(authorBytes),
                bodyBytes = bodyBytes,
                timestampSeconds = timestampSeconds,
                nonce = nonce,
                signature = signature,
            )
        } catch (e: EOFException) {
            throw MalformedPostAnnouncementException("truncated announcement bytes", e)
        } catch (e: IOException) {
            throw MalformedPostAnnouncementException("failed to decode announcement", e)
        } catch (e: MalformedPostAnnouncementException) {
            throw e
        } catch (e: RuntimeException) {
            // Covers IllegalArgumentException from PostAnnouncement's/Secp256k1PublicKey's own
            // constructor validation - decode() must never leak an arbitrary third-party
            // exception type to callers.
            throw MalformedPostAnnouncementException("invalid announcement field", e)
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
