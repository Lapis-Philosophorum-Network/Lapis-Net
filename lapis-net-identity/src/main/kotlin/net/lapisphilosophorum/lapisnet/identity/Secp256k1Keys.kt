package net.lapisphilosophorum.lapisnet.identity

import fr.acinq.secp256k1.Secp256k1
import net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex
import java.security.SecureRandom

private const val PRIVATE_KEY_SIZE = 32
private const val COMPRESSED_PUBLIC_KEY_SIZE = 33
private const val SIGNATURE_SIZE = 64
private const val DIGEST_SIZE = 32
private const val KEY_GENERATION_ATTEMPTS = 10

/**
 * A secp256k1 private key - the raw 32-byte scalar. This is the canonical Lapis Net identity key
 * (Bitcoin-compatible). There is no recovery mechanism: losing this key means losing the
 * identity permanently, by design.
 */
class Secp256k1PrivateKey(
    bytes: ByteArray,
) {
    private val storedBytes: ByteArray = bytes.copyOf()

    /** Returns a fresh copy on every access - the caller cannot mutate the stored key through it. */
    val bytes: ByteArray get() = storedBytes.copyOf()

    init {
        require(storedBytes.size == PRIVATE_KEY_SIZE) { "secp256k1 private key must be $PRIVATE_KEY_SIZE bytes" }
        require(Secp256k1.secKeyVerify(storedBytes)) {
            "invalid secp256k1 private key (zero, out of curve order, or otherwise degenerate)"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is Secp256k1PrivateKey && storedBytes.contentEquals(other.storedBytes)

    override fun hashCode(): Int = storedBytes.contentHashCode()

    override fun toString(): String = "Secp256k1PrivateKey(REDACTED)"
}

/** A secp256k1 public key in its canonical compressed (33-byte) form. */
class Secp256k1PublicKey(
    bytes: ByteArray,
) {
    private val storedBytes: ByteArray = bytes.copyOf()

    /** Returns a fresh copy on every access. */
    val bytes: ByteArray get() = storedBytes.copyOf()

    init {
        require(storedBytes.size == COMPRESSED_PUBLIC_KEY_SIZE) {
            "secp256k1 public key must be compressed ($COMPRESSED_PUBLIC_KEY_SIZE bytes)"
        }
        // Bytes of the right length are not necessarily a valid point on the curve. Without this
        // check, constructing a Secp256k1PublicKey from untrusted/decoded bytes (e.g. a Veritas
        // grant read off the DFS) would silently succeed, and a *later* call to verify() would
        // throw an uncaught native Secp256k1Exception instead of returning false - turning any
        // caller that verifies a batch/stream of untrusted grants into a trivial remote DoS.
        require(runCatching { Secp256k1.pubkeyParse(storedBytes) }.isSuccess) {
            "secp256k1 public key bytes do not represent a valid point on the curve"
        }
    }

    // Cached at construction, not recomputed per call: storedBytes never changes after the init
    // block above runs (bytes returns a defensive copy; the array it copies from is fixed for the
    // object's lifetime), so contentHashCode() always produces the same result for this instance -
    // safe to compute once, same pattern as java.lang.String's cached hashCode. This matters
    // because Secp256k1PublicKey is used as a HashMap/HashSet key throughout lapis-net-trust's
    // hot BFS path (TrustPathFinder's `best`/`visited`/`candidates` maps), where hashCode() is
    // called far more often than the key is constructed.
    private val cachedHashCode: Int = storedBytes.contentHashCode()

    /** Short hex fingerprint safe to log or display - never applies to private key material. */
    fun fingerprint(): String = storedBytes.fingerprintHex()

    override fun equals(other: Any?): Boolean =
        other is Secp256k1PublicKey && storedBytes.contentEquals(other.storedBytes)

    override fun hashCode(): Int = cachedHashCode

    override fun toString(): String = "Secp256k1PublicKey(${fingerprint()})"
}

class Secp256k1KeyPair internal constructor(
    val privateKey: Secp256k1PrivateKey,
    val publicKey: Secp256k1PublicKey,
) {
    companion object {
        fun generate(random: SecureRandom = SecureRandom()): Secp256k1KeyPair {
            repeat(KEY_GENERATION_ATTEMPTS) {
                val candidate = ByteArray(PRIVATE_KEY_SIZE).also(random::nextBytes)
                if (Secp256k1.secKeyVerify(candidate)) {
                    return fromPrivateKeyBytes(candidate)
                }
            }
            error("failed to generate a valid secp256k1 private key after $KEY_GENERATION_ATTEMPTS attempts")
        }

        fun fromPrivateKeyBytes(privateKeyBytes: ByteArray): Secp256k1KeyPair {
            val privateKey = Secp256k1PrivateKey(privateKeyBytes)
            val uncompressedPublicKey = Secp256k1.pubkeyCreate(privateKey.bytes)
            val compressedPublicKey = Secp256k1.pubKeyCompress(uncompressedPublicKey)
            return Secp256k1KeyPair(privateKey, Secp256k1PublicKey(compressedPublicKey))
        }
    }

    /**
     * Signs a 32-byte digest with a normalized (low-S) compact ECDSA signature. Callers must pass
     * an already-hashed 32-byte digest - secp256k1 does not hash its input internally. Never log
     * the returned signature bytes at any log level.
     */
    fun sign(digest: ByteArray): ByteArray {
        require(digest.size == DIGEST_SIZE) { "digest to sign must be exactly $DIGEST_SIZE bytes" }
        val signature = Secp256k1.sign(digest, privateKey.bytes)
        check(signature.size == SIGNATURE_SIZE) { "Secp256k1.sign produced an unexpected signature length" }
        return signature
    }
}

/** Verifies a compact 64-byte ECDSA signature over a 32-byte digest. */
fun Secp256k1PublicKey.verify(
    digest: ByteArray,
    signature: ByteArray,
): Boolean {
    require(digest.size == DIGEST_SIZE) { "digest to verify must be exactly $DIGEST_SIZE bytes" }
    require(signature.size == SIGNATURE_SIZE) { "signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature" }
    return Secp256k1.verify(signature, digest, bytes)
}
