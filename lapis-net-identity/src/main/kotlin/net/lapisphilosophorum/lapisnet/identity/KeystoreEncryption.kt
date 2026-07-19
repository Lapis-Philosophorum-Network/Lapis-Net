package net.lapisphilosophorum.lapisnet.identity

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Thrown when a keystore fails to decrypt: either the passphrase was wrong, or the
 * ciphertext/header was corrupted or tampered with. AES-GCM's authenticated decryption cannot
 * distinguish the two cases - a failed auth tag check means "not what was encrypted with this key
 * and this AAD", nothing more specific. Deliberately a distinct type from
 * [CorruptedIdentityFileException] (which covers structural/format problems detected BEFORE
 * decryption is even attempted, e.g. wrong length or bad magic). */
class KeystoreDecryptionException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Pure crypto for keystore encryption at rest (V0.4): Argon2id key derivation + AES-256-GCM
 * authenticated encryption. No filesystem I/O here - see [KeystoreFileFormat] for the on-disk v2
 * layout and [FileIdentityRepository] for how a passphrase is actually sourced.
 *
 * [encrypt]/[decrypt] take [Params], [nonce], and [aadHeader] as EXPLICIT inputs rather than
 * generating them internally - this resolves what would otherwise be a circular dependency: the
 * AAD must be the fully-assembled on-disk header (magic + version + KDF params + salt + nonce),
 * but salt and nonce are naturally generated as part of "encrypting". The caller
 * ([KeystoreFileFormat.encodeEncrypted]) owns salt/nonce generation and header assembly, so the
 * AAD binding is unambiguous by construction: it is impossible to call [encrypt] without first
 * having decided exactly what header bytes it authenticates.
 */
object KeystoreEncryption {
    const val KDF_ID_ARGON2ID: Byte = 1

    const val SALT_SIZE = 16
    const val NONCE_SIZE = 12
    const val GCM_TAG_BITS = 128
    const val DERIVED_KEY_SIZE = 32

    const val DEFAULT_MEMORY_KIB = 65536
    const val DEFAULT_ITERATIONS = 3
    const val DEFAULT_PARALLELISM = 1

    /** Argon2id cost parameters plus salt. Stored in the v2 file header (see
     * [KeystoreFileFormat]) so future hardening can raise the cost without breaking old files - a
     * plain class (no `data class`) since it carries a [ByteArray] field and is never compared for
     * equality in production code, only field-accessed in tests. */
    class Params(
        val memoryKiB: Int,
        val iterations: Int,
        val parallelism: Int,
        salt: ByteArray,
    ) {
        private val storedSalt: ByteArray = salt.copyOf()

        /** Returns a fresh copy on every access. */
        val salt: ByteArray get() = storedSalt.copyOf()

        init {
            require(storedSalt.size == SALT_SIZE) { "salt must be $SALT_SIZE bytes" }
            require(memoryKiB > 0) { "memoryKiB must be positive" }
            require(iterations > 0) { "iterations must be positive" }
            require(parallelism in 1..255) { "parallelism must be in 1..255" }
        }
    }

    /**
     * Derives a 32-byte AES-256 key from [passphrase] via Argon2id ([params]). The passphrase is
     * encoded to UTF-8 bytes without ever materializing an immutable [String] copy of it (an
     * intermediate `String` cannot be zeroed and would linger in the JVM's memory for an
     * indeterminate time), and the encoded bytes are zeroed in a `finally` block regardless of
     * outcome.
     */
    fun deriveKey(
        passphrase: CharArray,
        params: Params,
    ): ByteArray {
        val passphraseBytes = encodeUtf8(passphrase)
        try {
            val argon2Params =
                Argon2Parameters
                    .Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withMemoryAsKB(params.memoryKiB)
                    .withIterations(params.iterations)
                    .withParallelism(params.parallelism)
                    .withSalt(params.salt)
                    .build()
            val generator = Argon2BytesGenerator()
            generator.init(argon2Params)
            val derived = ByteArray(DERIVED_KEY_SIZE)
            generator.generateBytes(passphraseBytes, derived)
            return derived
        } finally {
            passphraseBytes.fill(0)
        }
    }

    /** Encrypts [plaintext] with AES-256-GCM under a key derived from [passphrase]/[params],
     * using [nonce] and authenticating [aadHeader] (the full on-disk header these bytes will be
     * stored alongside - see this object's doc comment for why the header must be assembled by
     * the caller before this is called). Returns ciphertext with the 16-byte GCM tag appended. */
    fun encrypt(
        plaintext: ByteArray,
        passphrase: CharArray,
        params: Params,
        nonce: ByteArray,
        aadHeader: ByteArray,
    ): ByteArray {
        require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes" }
        val key = deriveKey(passphrase, params)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
            cipher.updateAAD(aadHeader)
            return cipher.doFinal(plaintext)
        } finally {
            key.fill(0)
        }
    }

    /** Decrypts+authenticates [ciphertext] (with its trailing GCM tag) under a key derived from
     * [passphrase]/[params], using [nonce] and [aadHeader]. Throws [KeystoreDecryptionException]
     * for a wrong passphrase OR any tampered/corrupted byte in ciphertext/AAD - AES-GCM cannot
     * distinguish the two, see this object's doc comment. */
    fun decrypt(
        ciphertext: ByteArray,
        passphrase: CharArray,
        params: Params,
        nonce: ByteArray,
        aadHeader: ByteArray,
    ): ByteArray {
        require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes" }
        val key = deriveKey(passphrase, params)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
            cipher.updateAAD(aadHeader)
            return cipher.doFinal(ciphertext)
        } catch (e: AEADBadTagException) {
            throw KeystoreDecryptionException(
                "keystore decryption failed: wrong passphrase or corrupted/tampered file",
                e,
            )
        } catch (e: GeneralSecurityException) {
            throw KeystoreDecryptionException("keystore decryption failed: ${e.message}", e)
        } finally {
            key.fill(0)
        }
    }

    private fun encodeUtf8(chars: CharArray): ByteArray {
        val buffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars))
        val bytes = ByteArray(buffer.remaining())
        buffer.get(bytes)
        // CharsetEncoder.encode() may return a ByteBuffer backed by an over-allocated array (its
        // capacity can exceed `remaining()` at the point copied above) - zero the buffer's own
        // backing array too so no stray copy of the encoded passphrase bytes lingers past this
        // point, not just the right-sized array returned to the caller.
        if (buffer.hasArray()) buffer.array().fill(0)
        return bytes
    }
}
