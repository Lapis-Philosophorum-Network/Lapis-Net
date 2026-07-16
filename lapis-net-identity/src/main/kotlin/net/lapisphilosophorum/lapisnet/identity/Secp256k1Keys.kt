package net.lapisphilosophorum.lapisnet.identity

import fr.acinq.secp256k1.Secp256k1
import net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex
import java.security.SecureRandom

private const val PRIVATE_KEY_SIZE = 32
private const val COMPRESSED_PUBLIC_KEY_SIZE = 33
private const val KEY_GENERATION_ATTEMPTS = 10

/**
 * A secp256k1 private key - the raw 32-byte scalar. This is the canonical Lapis Net identity key
 * (Bitcoin-compatible). There is no recovery mechanism: losing this key means losing the
 * identity permanently, by design.
 */
class Secp256k1PrivateKey(
    bytes: ByteArray,
) {
    val bytes: ByteArray = bytes.copyOf()

    init {
        require(bytes.size == PRIVATE_KEY_SIZE) { "secp256k1 private key must be $PRIVATE_KEY_SIZE bytes" }
        require(Secp256k1.secKeyVerify(bytes)) {
            "invalid secp256k1 private key (zero, out of curve order, or otherwise degenerate)"
        }
    }

    override fun equals(other: Any?): Boolean = other is Secp256k1PrivateKey && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = "Secp256k1PrivateKey(REDACTED)"
}

/** A secp256k1 public key in its canonical compressed (33-byte) form. */
class Secp256k1PublicKey(
    bytes: ByteArray,
) {
    val bytes: ByteArray = bytes.copyOf()

    init {
        require(bytes.size == COMPRESSED_PUBLIC_KEY_SIZE) {
            "secp256k1 public key must be compressed ($COMPRESSED_PUBLIC_KEY_SIZE bytes)"
        }
    }

    /** Short hex fingerprint safe to log or display - never applies to private key material. */
    fun fingerprint(): String = bytes.fingerprintHex()

    override fun equals(other: Any?): Boolean = other is Secp256k1PublicKey && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

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
        require(digest.size == 32) { "digest to sign must be exactly 32 bytes" }
        return Secp256k1.sign(digest, privateKey.bytes)
    }
}

/** Verifies a compact 64-byte ECDSA signature over a 32-byte digest. */
fun Secp256k1PublicKey.verify(
    digest: ByteArray,
    signature: ByteArray,
): Boolean {
    require(digest.size == 32) { "digest to verify must be exactly 32 bytes" }
    require(signature.size == 64) { "signature must be a compact 64-byte ECDSA signature" }
    return Secp256k1.verify(signature, digest, bytes)
}
