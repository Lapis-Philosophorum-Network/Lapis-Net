package net.lapisphilosophorum.lapisnet.identity

import net.lapisphilosophorum.lapisnet.core.crypto.fingerprintHex
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom

private const val ED25519_KEY_SIZE = 32

/**
 * An Ed25519 private key seed - the raw 32-byte representation jvm-libp2p expects
 * (`Ed25519PrivateKeyParameters(seed, 0)`). Used only for this identity's libp2p peer ID, never
 * as the canonical Lapis Net identity (that role belongs to the secp256k1 key).
 */
class Ed25519PrivateKey(
    seed: ByteArray,
) {
    val seed: ByteArray = seed.copyOf()

    init {
        require(seed.size == ED25519_KEY_SIZE) { "Ed25519 seed must be $ED25519_KEY_SIZE bytes" }
        // Not a cryptographic requirement of Ed25519 itself - an all-zero/all-ones seed is the
        // classic symptom of a broken or mocked SecureRandom, so it is rejected as a sanity guard.
        require(!seed.all { it == 0.toByte() }) { "Ed25519 seed must not be all-zero (likely broken RNG)" }
        require(!seed.all { it == 0xFF.toByte() }) { "Ed25519 seed must not be all-ones (likely broken RNG)" }
    }

    override fun equals(other: Any?): Boolean = other is Ed25519PrivateKey && seed.contentEquals(other.seed)

    override fun hashCode(): Int = seed.contentHashCode()

    override fun toString(): String = "Ed25519PrivateKey(REDACTED)"
}

/** An Ed25519 public key in its raw 32-byte representation. */
class Ed25519PublicKey(
    bytes: ByteArray,
) {
    val bytes: ByteArray = bytes.copyOf()

    init {
        require(bytes.size == ED25519_KEY_SIZE) { "Ed25519 public key must be $ED25519_KEY_SIZE bytes" }
    }

    /** Short hex fingerprint safe to log or display - never applies to private key material. */
    fun fingerprint(): String = bytes.fingerprintHex()

    override fun equals(other: Any?): Boolean = other is Ed25519PublicKey && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = "Ed25519PublicKey(${fingerprint()})"
}

class Ed25519KeyPair internal constructor(
    val privateKey: Ed25519PrivateKey,
    val publicKey: Ed25519PublicKey,
) {
    companion object {
        fun generate(random: SecureRandom = SecureRandom()): Ed25519KeyPair {
            val generator =
                Ed25519KeyPairGenerator().apply {
                    init(Ed25519KeyGenerationParameters(random))
                }
            val keyPair = generator.generateKeyPair()
            val privateKeyParams = keyPair.private as Ed25519PrivateKeyParameters
            val publicKeyParams = keyPair.public as Ed25519PublicKeyParameters
            return Ed25519KeyPair(
                Ed25519PrivateKey(privateKeyParams.encoded),
                Ed25519PublicKey(publicKeyParams.encoded),
            )
        }
    }

    /** Signs a message with a fresh [Ed25519Signer] instance - the signer is not thread-safe. */
    fun sign(message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(privateKey.seed, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }
}

/** Verifies an Ed25519 signature with a fresh [Ed25519Signer] instance per call. */
fun Ed25519PublicKey.verify(
    message: ByteArray,
    signature: ByteArray,
): Boolean {
    val signer = Ed25519Signer()
    signer.init(false, Ed25519PublicKeyParameters(bytes, 0))
    signer.update(message, 0, message.size)
    return signer.verifySignature(signature)
}
