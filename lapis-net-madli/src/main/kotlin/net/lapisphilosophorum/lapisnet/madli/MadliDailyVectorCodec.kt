package net.lapisphilosophorum.lapisnet.madli

import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.security.MessageDigest

/**
 * Thrown when decoding a [MadliDailyVector]'s canonical byte encoding fails structurally (bad
 * magic, unsupported version, truncated/overrun buffer, out-of-range field, malformed `PeerId`
 * bytes). Never thrown for signature verification failures - [MadliDailyVectorCodec.decode] does
 * not verify signatures, see its doc comment. Mirrors `MalformedKarmaVoteException`'s established
 * same-file-as-its-codec organization.
 */
class MalformedMadliDailyVectorException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Canonical, deterministic byte encoding for [MadliDailyVector] - used both to build the digest
 * that gets signed and to compute a vector's content id (the gossip dedup key, see
 * [MadliVectorIndex]). Mirrors `KarmaVoteCodec`'s sequential length-prefixed layout and
 * big-endian integer convention exactly.
 *
 * Layout of [encodeSignedBody]'s output: `magic(4="LNMV") | version(1) | observer(33) |
 * peerIdLen(2) | peerId(peerIdLen) | epochDay(8) | reachabilityMicros(4) |
 * medianBandwidthBytesPerSec(8) | medianLatencyMillis(4) | deliveryIntegrityMicros(4) |
 * routingHelpfulnessMicros(4) | observationCount(4)`. [encode] appends the 64-byte signature
 * after that.
 *
 * **`epochDay` is NOT range-checked against wall-clock time here - deliberate.** This codec is
 * used by [MadliGossip]'s validator, which must be clock-independent and deterministic (see that
 * class's doc comment). A negative or absurd `epochDay` is structurally accepted at decode time; it
 * is defused at read time by [MadliDecayCalculator]/[MadliAggregator] (future-dated vectors clamp
 * to a decay factor of exactly 1.0, never more) and bounded by [MadliVectorIndex]'s per-pair
 * distinct-day cap (invariant B).
 */
object MadliDailyVectorCodec {
    private val MAGIC = "LNMV".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private const val PUBLIC_KEY_SIZE = 33
    private const val SIGNATURE_SIZE = 64

    /** Cap on an encoded libp2p `PeerId`'s byte length. A real Ed25519/identity-multihash libp2p
     * `PeerId` is ~34-38 bytes (and the `PeerId` constructor itself hard-rejects anything outside
     * 32..50 bytes) - 128 is generous headroom above that, mirroring
     * `KarmaVoteCodec.MAX_CID_BYTES`'s "generous headroom, not derived from a specific future
     * need" reasoning. */
    const val MAX_PEER_ID_BYTES = 128

    /** [domainSeparatedDigest][net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest]
     * treats the whole signed body as a single part, capped at this size - mirrors
     * `KarmaVoteCodec.MAX_BODY_SIZE`'s reasoning. This body's worst case (magic+version+observer+
     * peerIdLen+MAX_PEER_ID_BYTES+epochDay+five metric fields) is well under 1 KB, far under the
     * limit. */
    const val MAX_BODY_SIZE = 0xFFFF

    /** Builds the exact bytes that get domain-separated-digested and signed - see
     * [MadliDailyVector.Companion.create]. */
    fun encodeSignedBody(
        observer: Secp256k1PublicKey,
        observedPeer: PeerId,
        epochDay: Long,
        metrics: MadliMetrics,
    ): ByteArray {
        val peerIdBytes = observedPeer.bytes
        require(peerIdBytes.size in 1..MAX_PEER_ID_BYTES) {
            "peer id must be 1..$MAX_PEER_ID_BYTES bytes, was ${peerIdBytes.size}"
        }

        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            write(observer.bytes)
            writeShort(peerIdBytes.size)
            write(peerIdBytes)
            writeLong(epochDay)
            writeInt(metrics.reachabilityMicros)
            writeLong(metrics.medianBandwidthBytesPerSec)
            writeInt(metrics.medianLatencyMillis)
            writeInt(metrics.deliveryIntegrityMicros)
            writeInt(metrics.routingHelpfulnessMicros)
            writeInt(metrics.observationCount)
        }
        val body = out.toByteArray()
        require(body.size <= MAX_BODY_SIZE) { "encoded vector body exceeds $MAX_BODY_SIZE bytes: ${body.size}" }
        return body
    }

    /** As the other [encodeSignedBody] overload, pulling fields off an existing [vector]. */
    fun encodeSignedBody(vector: MadliDailyVector): ByteArray =
        encodeSignedBody(
            observer = vector.observer,
            observedPeer = vector.observedPeer,
            epochDay = vector.epochDay,
            metrics = vector.metrics,
        )

    /** The full canonical artifact: signed body followed by the 64-byte signature. This is what
     * [MadliGossip] hands to `NabuStorage.put()` and publishes over GossipSub, and the preimage of
     * [contentId]. */
    fun encode(vector: MadliDailyVector): ByteArray = encodeSignedBody(vector) + vector.signature

    /** Plain (not domain-separated) SHA-256 of [encode] - the gossip dedup / index lookup key,
     * not itself a signed value. A fresh [MessageDigest] instance is created per call -
     * [MessageDigest] is not thread-safe. */
    fun contentId(vector: MadliDailyVector): ByteArray = sha256(encode(vector))

    /**
     * Structural decode only - does **not** verify the signature, matching
     * `KarmaVoteCodec.decode`'s exact contract. A vector typically arrives from an untrusted peer
     * over gossip; callers must explicitly call [MadliDailyVector.Companion.verify] before
     * trusting it.
     *
     * @throws MalformedMadliDailyVectorException if the bytes are structurally invalid, including
     * an out-of-range field, trailing bytes after the signature, or a malformed `PeerId`.
     */
    fun decode(bytes: ByteArray): MadliDailyVector {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedMadliDailyVectorException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedMadliDailyVectorException("unsupported version $version")

            val observerBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }

            val peerIdLen = input.readUnsignedShort()
            if (peerIdLen !in 1..MAX_PEER_ID_BYTES) {
                throw MalformedMadliDailyVectorException("invalid peer id length: $peerIdLen")
            }
            val peerIdBytes = ByteArray(peerIdLen).also { input.readFully(it) }

            val epochDay = input.readLong()
            val reachabilityMicros = input.readInt()
            val medianBandwidthBytesPerSec = input.readLong()
            val medianLatencyMillis = input.readInt()
            val deliveryIntegrityMicros = input.readInt()
            val routingHelpfulnessMicros = input.readInt()
            val observationCount = input.readInt()

            val signature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedMadliDailyVectorException("trailing bytes after signature")

            return MadliDailyVector.fromDecoded(
                observer = Secp256k1PublicKey(observerBytes),
                observedPeer = PeerId(peerIdBytes),
                epochDay = epochDay,
                metrics =
                    MadliMetrics(
                        reachabilityMicros = reachabilityMicros,
                        medianBandwidthBytesPerSec = medianBandwidthBytesPerSec,
                        medianLatencyMillis = medianLatencyMillis,
                        deliveryIntegrityMicros = deliveryIntegrityMicros,
                        routingHelpfulnessMicros = routingHelpfulnessMicros,
                        observationCount = observationCount,
                    ),
                signature = signature,
            )
        } catch (e: EOFException) {
            throw MalformedMadliDailyVectorException("truncated vector bytes", e)
        } catch (e: IOException) {
            throw MalformedMadliDailyVectorException("failed to decode vector", e)
        } catch (e: MalformedMadliDailyVectorException) {
            throw e
        } catch (e: RuntimeException) {
            // Covers IllegalArgumentException from MadliMetrics's/Secp256k1PublicKey's own
            // constructor validation and IllegalArgumentException from PeerId's constructor (its
            // 32..50-byte length check) - decode() must never leak an arbitrary third-party
            // exception type to callers.
            throw MalformedMadliDailyVectorException("invalid vector field", e)
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
