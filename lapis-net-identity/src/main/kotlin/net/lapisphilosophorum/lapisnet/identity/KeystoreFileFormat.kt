package net.lapisphilosophorum.lapisnet.identity

import io.github.oshai.kotlinlogging.KotlinLogging
import java.nio.ByteBuffer
import java.security.SecureRandom

private val logger = KotlinLogging.logger {}

private val MAGIC = byteArrayOf('L'.code.toByte(), 'N'.code.toByte(), 'K'.code.toByte(), 'S'.code.toByte())
private const val VERSION: Byte = 1

private const val MAGIC_SIZE = 4
private const val VERSION_SIZE = 1
private const val SECP256K1_PRIVATE_KEY_SIZE = 32
private const val SECP256K1_PUBLIC_KEY_SIZE = 33
private const val ED25519_KEY_SIZE = 32
private const val SIGNATURE_SIZE = 64

private const val MAGIC_OFFSET = 0
private const val VERSION_OFFSET = MAGIC_OFFSET + MAGIC_SIZE
private const val SECP256K1_PRIVATE_KEY_OFFSET = VERSION_OFFSET + VERSION_SIZE
private const val SECP256K1_PUBLIC_KEY_OFFSET = SECP256K1_PRIVATE_KEY_OFFSET + SECP256K1_PRIVATE_KEY_SIZE
private const val ED25519_PRIVATE_KEY_OFFSET = SECP256K1_PUBLIC_KEY_OFFSET + SECP256K1_PUBLIC_KEY_SIZE
private const val ED25519_PUBLIC_KEY_OFFSET = ED25519_PRIVATE_KEY_OFFSET + ED25519_KEY_SIZE
private const val SIGNATURE_OFFSET = ED25519_PUBLIC_KEY_OFFSET + ED25519_KEY_SIZE

// --- v2 (encrypted-at-rest, V0.4) header layout ---
// offset  len  field
// 0       4    magic "LNKS" (same magic as v1)
// 4       1    version = 2
// 5       1    kdfId = 1 (Argon2id)
// 6       4    argon2 memoryKiB      (big-endian Int)
// 10      4    argon2 iterations     (big-endian Int)
// 14      1    argon2 parallelism    (1..255)
// 15      16   salt
// 31      12   GCM nonce
// --- header ends at offset 43 (this whole 43-byte prefix is the GCM AAD) ---
// 43      ...  ciphertext = AES-256-GCM(plaintext = v1 FILE_SIZE-byte encoding) + 16-byte GCM tag
private const val VERSION_2: Byte = 2
private const val KDF_ID_OFFSET = 5
private const val MEMORY_OFFSET = 6
private const val ITERATIONS_OFFSET = 10
private const val PARALLELISM_OFFSET = 14
private const val SALT_OFFSET = 15
private const val NONCE_OFFSET = 31
private const val CIPHERTEXT_OFFSET = 43
private const val V2_HEADER_SIZE = CIPHERTEXT_OFFSET
private const val GCM_TAG_SIZE = 16

/**
 * Fixed-layout binary codec for a [DualKeyIdentity]:
 *
 * ```
 * offset  length  field
 * 0       4       magic "LNKS"
 * 4       1       format version (1)
 * 5       32      secp256k1 private key
 * 37      33      secp256k1 public key (compressed) - recomputed and cross-checked on decode
 * 70      32      Ed25519 private key (seed)
 * 102     32      Ed25519 public key
 * 134     64      identity binding signature
 * ```
 *
 * Pure byte<->object codec, no filesystem I/O.
 *
 * **V0.4 adds a v2, encrypted-at-rest variant** ([encodeEncrypted]/[decodeEncrypted]/
 * [decodeAuto]) that wraps this exact same v1 encoding as its plaintext, under Argon2id-derived
 * AES-256-GCM - see [KeystoreEncryption] for the crypto and the header layout comment above this
 * class for the v2 on-disk format. v1 stays supported unchanged (both for encoding and decoding)
 * since this project has no real users/keystores yet needing hard migration, but a smooth
 * legacy-read path is kept via [decodeAuto].
 */
object KeystoreFileFormat {
    const val FILE_SIZE = SIGNATURE_OFFSET + SIGNATURE_SIZE
    const val V2_FILE_SIZE = V2_HEADER_SIZE + FILE_SIZE + GCM_TAG_SIZE

    /** Public aliases for the private version-byte constants above, so callers outside this file
     * (e.g. [FileIdentityRepository]'s v1-to-v2 migration check) can compare against them without
     * this file needing to make the raw constants themselves public. */
    const val FORMAT_VERSION_1: Byte = VERSION
    const val FORMAT_VERSION_2: Byte = VERSION_2

    /** The on-disk format version encoded in [bytes]' header (offset 4) - [FORMAT_VERSION_1] for
     * legacy plaintext, [FORMAT_VERSION_2] for encrypted. Does not otherwise validate [bytes]. */
    fun formatVersionOf(bytes: ByteArray): Byte {
        require(bytes.size >= MAGIC_SIZE + VERSION_SIZE) { "keystore file too short to contain a version header" }
        return bytes[VERSION_OFFSET]
    }

    fun encode(identity: DualKeyIdentity): ByteArray {
        val out = ByteArray(FILE_SIZE)
        MAGIC.copyInto(out, MAGIC_OFFSET)
        out[VERSION_OFFSET] = VERSION
        identity.secp256k1KeyPair.privateKey.bytes
            .copyInto(out, SECP256K1_PRIVATE_KEY_OFFSET)
        identity.secp256k1KeyPair.publicKey.bytes
            .copyInto(out, SECP256K1_PUBLIC_KEY_OFFSET)
        identity.ed25519KeyPair.privateKey.seed
            .copyInto(out, ED25519_PRIVATE_KEY_OFFSET)
        identity.ed25519KeyPair.publicKey.bytes
            .copyInto(out, ED25519_PUBLIC_KEY_OFFSET)
        identity.binding.signature.copyInto(out, SIGNATURE_OFFSET)
        return out
    }

    fun decode(bytes: ByteArray): DualKeyIdentity {
        if (bytes.size != FILE_SIZE) {
            throw CorruptedIdentityFileException("expected $FILE_SIZE bytes, got ${bytes.size}")
        }
        if (!bytes.copyOfRange(MAGIC_OFFSET, VERSION_OFFSET).contentEquals(MAGIC)) {
            throw CorruptedIdentityFileException("bad magic header")
        }
        if (bytes[VERSION_OFFSET] != VERSION) {
            throw CorruptedIdentityFileException("unsupported keystore format version ${bytes[VERSION_OFFSET]}")
        }

        val secp256k1PrivateKey =
            runCatchingCorruption {
                Secp256k1PrivateKey(bytes.copyOfRange(SECP256K1_PRIVATE_KEY_OFFSET, SECP256K1_PUBLIC_KEY_OFFSET))
            }
        val storedSecp256k1PublicKey =
            runCatchingCorruption {
                Secp256k1PublicKey(
                    bytes.copyOfRange(SECP256K1_PUBLIC_KEY_OFFSET, ED25519_PRIVATE_KEY_OFFSET),
                )
            }

        val derivedKeyPair = Secp256k1KeyPair.fromPrivateKeyBytes(secp256k1PrivateKey.bytes)
        if (derivedKeyPair.publicKey != storedSecp256k1PublicKey) {
            throw CorruptedIdentityFileException(
                "stored secp256k1 public key does not match the key derived from the private key - file corrupted or tampered",
            )
        }

        val ed25519PrivateKeySeed =
            runCatchingCorruption {
                bytes.copyOfRange(ED25519_PRIVATE_KEY_OFFSET, ED25519_PUBLIC_KEY_OFFSET).also { Ed25519PrivateKey(it) }
            }
        val storedEd25519PublicKey =
            runCatchingCorruption { Ed25519PublicKey(bytes.copyOfRange(ED25519_PUBLIC_KEY_OFFSET, SIGNATURE_OFFSET)) }
        val signature = bytes.copyOfRange(SIGNATURE_OFFSET, FILE_SIZE)

        val derivedEd25519KeyPair = Ed25519KeyPair.fromPrivateKeySeed(ed25519PrivateKeySeed)
        if (derivedEd25519KeyPair.publicKey != storedEd25519PublicKey) {
            throw CorruptedIdentityFileException(
                "stored Ed25519 public key does not match the key derived from the private key - file corrupted or tampered",
            )
        }

        val identity =
            DualKeyIdentity(
                derivedKeyPair,
                derivedEd25519KeyPair,
                IdentityBinding(storedEd25519PublicKey, signature),
            )
        if (!identity.verifyBinding()) {
            throw CorruptedIdentityFileException("stored identity binding signature does not verify")
        }
        return identity
    }

    /**
     * Encrypts [identity] into a v2 keystore file under [passphrase] - see the v2 header layout
     * comment above this class. Generates a fresh random salt + nonce via [random] on every call
     * (so encrypting the same identity twice never produces the same bytes), assembles the
     * [V2_HEADER_SIZE]-byte header FIRST, then encrypts with that exact header as the GCM AAD -
     * this ordering is what makes the AAD binding in [KeystoreEncryption] unambiguous.
     */
    fun encodeEncrypted(
        identity: DualKeyIdentity,
        passphrase: CharArray,
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        val plaintext = encode(identity)
        val salt = ByteArray(KeystoreEncryption.SALT_SIZE).also(random::nextBytes)
        val nonce = ByteArray(KeystoreEncryption.NONCE_SIZE).also(random::nextBytes)

        val header = ByteBuffer.allocate(V2_HEADER_SIZE)
        header.put(MAGIC)
        header.put(VERSION_2)
        header.put(KeystoreEncryption.KDF_ID_ARGON2ID)
        header.putInt(KeystoreEncryption.DEFAULT_MEMORY_KIB)
        header.putInt(KeystoreEncryption.DEFAULT_ITERATIONS)
        header.put(KeystoreEncryption.DEFAULT_PARALLELISM.toByte())
        header.put(salt)
        header.put(nonce)
        val headerBytes = header.array()
        check(headerBytes.size == V2_HEADER_SIZE) { "v2 header assembly produced an unexpected size" }

        val params =
            KeystoreEncryption.Params(
                memoryKiB = KeystoreEncryption.DEFAULT_MEMORY_KIB,
                iterations = KeystoreEncryption.DEFAULT_ITERATIONS,
                parallelism = KeystoreEncryption.DEFAULT_PARALLELISM,
                salt = salt,
            )
        val ciphertext = KeystoreEncryption.encrypt(plaintext, passphrase, params, nonce, headerBytes)

        val out = ByteArray(V2_HEADER_SIZE + ciphertext.size)
        headerBytes.copyInto(out, 0)
        ciphertext.copyInto(out, V2_HEADER_SIZE)
        return out
    }

    /**
     * Decrypts a v2 keystore file produced by [encodeEncrypted] under [passphrase]. Validates
     * length, magic, version, and kdfId BEFORE ever attempting decryption (a structural problem
     * throws [CorruptedIdentityFileException], matching this file's existing v1 conventions); a
     * decryption failure (wrong passphrase, or any tampered byte anywhere in the 43-byte header or
     * ciphertext, since the whole header is the GCM AAD) throws [KeystoreDecryptionException],
     * propagated as-is from [KeystoreEncryption.decrypt]. Once decrypted, the plaintext runs
     * through the exact same structural/signature cross-checks as [decode] (derived-pubkey match,
     * binding-signature verify) - encryption never bypasses those.
     */
    fun decodeEncrypted(
        bytes: ByteArray,
        passphrase: CharArray,
    ): DualKeyIdentity {
        if (bytes.size != V2_FILE_SIZE) {
            throw CorruptedIdentityFileException("expected $V2_FILE_SIZE bytes for a v2 keystore, got ${bytes.size}")
        }
        if (!bytes.copyOfRange(MAGIC_OFFSET, VERSION_OFFSET).contentEquals(MAGIC)) {
            throw CorruptedIdentityFileException("bad magic header")
        }
        if (bytes[VERSION_OFFSET] != VERSION_2) {
            throw CorruptedIdentityFileException("unsupported keystore format version ${bytes[VERSION_OFFSET]}")
        }
        if (bytes[KDF_ID_OFFSET] != KeystoreEncryption.KDF_ID_ARGON2ID) {
            throw CorruptedIdentityFileException("unsupported KDF id ${bytes[KDF_ID_OFFSET]}")
        }

        val header = ByteBuffer.wrap(bytes, 0, V2_HEADER_SIZE)
        val memoryKiB = header.getInt(MEMORY_OFFSET)
        val iterations = header.getInt(ITERATIONS_OFFSET)
        val parallelism = bytes[PARALLELISM_OFFSET].toInt() and 0xFF
        // Sanity-cap the KDF cost parameters read off disk BEFORE ever handing them to Argon2 -
        // a corrupted or maliciously crafted v2 file could otherwise claim an absurd memoryKiB/
        // iterations value (e.g. Int.MAX_VALUE KiB) and turn a single load attempt into an
        // unbounded-memory/CPU hang, long before the GCM auth tag is even checked. These caps are
        // generous (16x this file's own DEFAULT_* constants) so legitimate future hardening of the
        // defaults never trips them, while still ruling out obviously-hostile values.
        if (memoryKiB <= 0 || memoryKiB > KeystoreEncryption.DEFAULT_MEMORY_KIB * 16) {
            throw CorruptedIdentityFileException("implausible Argon2 memoryKiB $memoryKiB in keystore header")
        }
        if (iterations <= 0 || iterations > KeystoreEncryption.DEFAULT_ITERATIONS * 16) {
            throw CorruptedIdentityFileException("implausible Argon2 iterations $iterations in keystore header")
        }
        if (parallelism <= 0 || parallelism > KeystoreEncryption.DEFAULT_PARALLELISM * 16) {
            throw CorruptedIdentityFileException("implausible Argon2 parallelism $parallelism in keystore header")
        }
        val salt = bytes.copyOfRange(SALT_OFFSET, NONCE_OFFSET)
        val nonce = bytes.copyOfRange(NONCE_OFFSET, CIPHERTEXT_OFFSET)
        val aadHeader = bytes.copyOfRange(0, V2_HEADER_SIZE)
        val ciphertext = bytes.copyOfRange(CIPHERTEXT_OFFSET, bytes.size)

        val params =
            runCatchingCorruption {
                KeystoreEncryption.Params(memoryKiB, iterations, parallelism, salt)
            }
        val plaintext = KeystoreEncryption.decrypt(ciphertext, passphrase, params, nonce, aadHeader)
        return decode(plaintext)
    }

    /**
     * Auto-detects the on-disk keystore version from [bytes] and decodes accordingly - the read
     * path a caller uses when it does not itself know in advance whether a given file is legacy
     * plaintext (v1) or encrypted (v2). A v1 file decodes regardless of [passphrase] (ignored, with
     * a warning - v1 was never encrypted, so there is nothing to decrypt); a v2 file requires a
     * non-null [passphrase], else throws [KeystoreDecryptionException] rather than silently
     * treating "no passphrase" as "wrong passphrase" (a clearer error for the caller to act on).
     */
    fun decodeAuto(
        bytes: ByteArray,
        passphrase: CharArray?,
    ): DualKeyIdentity {
        if (bytes.size < MAGIC_SIZE + VERSION_SIZE) {
            throw CorruptedIdentityFileException("keystore file too short to contain a version header")
        }
        return when (bytes[VERSION_OFFSET]) {
            VERSION -> {
                logger.warn {
                    "loading a legacy unencrypted (v1) keystore - consider setting a passphrase to encrypt it at rest"
                }
                decode(bytes)
            }
            VERSION_2 -> {
                if (passphrase == null) {
                    throw KeystoreDecryptionException("passphrase required for encrypted keystore")
                }
                decodeEncrypted(bytes, passphrase)
            }
            else -> throw CorruptedIdentityFileException("unsupported keystore format version ${bytes[VERSION_OFFSET]}")
        }
    }

    private inline fun <T> runCatchingCorruption(block: () -> T): T =
        try {
            block()
        } catch (e: IllegalArgumentException) {
            throw CorruptedIdentityFileException("malformed key material in keystore file: ${e.message}")
        }
}
