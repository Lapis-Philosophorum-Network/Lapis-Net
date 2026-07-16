package net.lapisphilosophorum.lapisnet.identity

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
 */
object KeystoreFileFormat {
    const val FILE_SIZE = SIGNATURE_OFFSET + SIGNATURE_SIZE

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

        val ed25519PrivateKey =
            runCatchingCorruption {
                Ed25519PrivateKey(
                    bytes.copyOfRange(ED25519_PRIVATE_KEY_OFFSET, ED25519_PUBLIC_KEY_OFFSET),
                )
            }
        val ed25519PublicKey =
            runCatchingCorruption { Ed25519PublicKey(bytes.copyOfRange(ED25519_PUBLIC_KEY_OFFSET, SIGNATURE_OFFSET)) }
        val signature = bytes.copyOfRange(SIGNATURE_OFFSET, FILE_SIZE)

        val identity =
            DualKeyIdentity(
                derivedKeyPair,
                Ed25519KeyPair(ed25519PrivateKey, ed25519PublicKey),
                IdentityBinding(ed25519PublicKey, signature),
            )
        if (!identity.verifyBinding()) {
            throw CorruptedIdentityFileException("stored identity binding signature does not verify")
        }
        return identity
    }

    private inline fun <T> runCatchingCorruption(block: () -> T): T =
        try {
            block()
        } catch (e: IllegalArgumentException) {
            throw CorruptedIdentityFileException("malformed key material in keystore file: ${e.message}")
        }
}
