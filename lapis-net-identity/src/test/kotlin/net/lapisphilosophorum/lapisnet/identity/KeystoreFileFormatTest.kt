package net.lapisphilosophorum.lapisnet.identity

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.nio.ByteBuffer

class KeystoreFileFormatTest :
    FunSpec({
        test("decode(encode(identity)) round-trips to an identical identity") {
            val identity = DualKeyIdentity.generate()
            val decoded = KeystoreFileFormat.decode(KeystoreFileFormat.encode(identity))

            decoded.secp256k1KeyPair.privateKey shouldBe identity.secp256k1KeyPair.privateKey
            decoded.secp256k1KeyPair.publicKey shouldBe identity.secp256k1KeyPair.publicKey
            decoded.ed25519KeyPair.privateKey shouldBe identity.ed25519KeyPair.privateKey
            decoded.ed25519KeyPair.publicKey shouldBe identity.ed25519KeyPair.publicKey
            decoded.binding.signature.contentEquals(identity.binding.signature) shouldBe true
            decoded.verifyBinding() shouldBe true
        }

        test("rejects a buffer of the wrong length") {
            shouldThrow<CorruptedIdentityFileException> {
                KeystoreFileFormat.decode(ByteArray(10))
            }
        }

        test("rejects a buffer with a bad magic header") {
            val bytes = KeystoreFileFormat.encode(DualKeyIdentity.generate())
            bytes[0] = 'X'.code.toByte()
            shouldThrow<CorruptedIdentityFileException> {
                KeystoreFileFormat.decode(bytes)
            }
        }

        test("rejects a buffer with an unsupported format version") {
            val bytes = KeystoreFileFormat.encode(DualKeyIdentity.generate())
            bytes[4] = 99
            shouldThrow<CorruptedIdentityFileException> {
                KeystoreFileFormat.decode(bytes)
            }
        }

        test("rejects a buffer where the stored secp256k1 public key does not match the private key") {
            val bytes = KeystoreFileFormat.encode(DualKeyIdentity.generate())
            // flip a byte inside the stored secp256k1 public key (offset 37..69)
            bytes[40] = (bytes[40] + 1).toByte()
            shouldThrow<CorruptedIdentityFileException> {
                KeystoreFileFormat.decode(bytes)
            }
        }

        test("rejects a buffer where the stored Ed25519 public key does not match the private key") {
            val bytes = KeystoreFileFormat.encode(DualKeyIdentity.generate())
            // flip a byte inside the stored Ed25519 public key (offset 102..133)
            bytes[105] = (bytes[105] + 1).toByte()
            shouldThrow<CorruptedIdentityFileException> {
                KeystoreFileFormat.decode(bytes)
            }
        }

        test("rejects a buffer where the binding signature no longer verifies") {
            val bytes = KeystoreFileFormat.encode(DualKeyIdentity.generate())
            // flip a byte inside the signature (offset 134..197)
            bytes[134] = (bytes[134] + 1).toByte()
            shouldThrow<CorruptedIdentityFileException> {
                KeystoreFileFormat.decode(bytes)
            }
        }

        test("decodeEncrypted(encodeEncrypted(identity, passphrase)) round-trips to an identical identity") {
            val identity = DualKeyIdentity.generate()
            val passphrase = "correct horse battery staple".toCharArray()
            val encrypted = KeystoreFileFormat.encodeEncrypted(identity, passphrase)
            val decoded = KeystoreFileFormat.decodeEncrypted(encrypted, passphrase)

            decoded.secp256k1KeyPair.privateKey shouldBe identity.secp256k1KeyPair.privateKey
            decoded.secp256k1KeyPair.publicKey shouldBe identity.secp256k1KeyPair.publicKey
            decoded.ed25519KeyPair.privateKey shouldBe identity.ed25519KeyPair.privateKey
            decoded.ed25519KeyPair.publicKey shouldBe identity.ed25519KeyPair.publicKey
            decoded.verifyBinding() shouldBe true
        }

        test("encodeEncrypted output is exactly V2_FILE_SIZE bytes with version byte 2") {
            val identity = DualKeyIdentity.generate()
            val encrypted = KeystoreFileFormat.encodeEncrypted(identity, "a passphrase".toCharArray())

            encrypted.size shouldBe KeystoreFileFormat.V2_FILE_SIZE
            encrypted[4] shouldBe KeystoreFileFormat.FORMAT_VERSION_2
        }

        test("decodeEncrypted with the wrong passphrase throws KeystoreDecryptionException") {
            val identity = DualKeyIdentity.generate()
            val encrypted = KeystoreFileFormat.encodeEncrypted(identity, "correct-passphrase".toCharArray())

            shouldThrow<KeystoreDecryptionException> {
                KeystoreFileFormat.decodeEncrypted(encrypted, "wrong-passphrase".toCharArray())
            }
        }

        test("decodeEncrypted rejects a truncated v2 file") {
            val identity = DualKeyIdentity.generate()
            val encrypted = KeystoreFileFormat.encodeEncrypted(identity, "a passphrase".toCharArray())

            shouldThrow<CorruptedIdentityFileException> {
                KeystoreFileFormat.decodeEncrypted(
                    encrypted.copyOfRange(0, encrypted.size - 10),
                    "a passphrase".toCharArray(),
                )
            }
        }

        test("decodeEncrypted rejects a v2 file with a flipped ciphertext byte") {
            val identity = DualKeyIdentity.generate()
            val passphrase = "a passphrase".toCharArray()
            val encrypted = KeystoreFileFormat.encodeEncrypted(identity, passphrase)
            // Flip a byte well past the 43-byte header, inside the ciphertext.
            encrypted[50] = (encrypted[50] + 1).toByte()

            shouldThrow<KeystoreDecryptionException> {
                KeystoreFileFormat.decodeEncrypted(encrypted, passphrase)
            }
        }

        test("decodeEncrypted rejects a v2 file with a flipped salt byte inside the 43-byte header (AAD binding)") {
            val identity = DualKeyIdentity.generate()
            val passphrase = "a passphrase".toCharArray()
            val encrypted = KeystoreFileFormat.encodeEncrypted(identity, passphrase)
            // Offset 15 is inside the salt field (salt occupies offsets 15..30 of the 43-byte
            // header) - flipping it must fail authentication, proving the AAD genuinely covers the
            // full on-disk header (not just the ciphertext) end-to-end through the real
            // encodeEncrypted/decodeEncrypted file-format path, not just KeystoreEncryption's own
            // lower-level unit tests.
            encrypted[15] = (encrypted[15] + 1).toByte()

            shouldThrow<KeystoreDecryptionException> {
                KeystoreFileFormat.decodeEncrypted(encrypted, passphrase)
            }
        }

        test("decodeEncrypted rejects an implausible memoryKiB header value before ever calling Argon2") {
            val identity = DualKeyIdentity.generate()
            val passphrase = "a passphrase".toCharArray()
            val encrypted = KeystoreFileFormat.encodeEncrypted(identity, passphrase)
            // Offset 6 is the 4-byte big-endian memoryKiB field (header layout: magic[0..4) version[4]
            // kdfId[5] memoryKiB[6..10) iterations[10..14) parallelism[14] salt[15..31) nonce[31..43)).
            // A corrupted/malicious file claiming an absurd memoryKiB must be rejected structurally,
            // BEFORE the expensive Argon2 KDF call is ever reached - not just eventually fail the GCM
            // tag after already having spent the memory/CPU. CorruptedIdentityFileException (not
            // KeystoreDecryptionException) proves this is caught at the cheap validation step.
            ByteBuffer.wrap(encrypted).putInt(6, Int.MAX_VALUE)

            shouldThrow<CorruptedIdentityFileException> {
                KeystoreFileFormat.decodeEncrypted(encrypted, passphrase)
            }
        }

        test("decodeEncrypted rejects an implausible parallelism header value before ever calling Argon2") {
            val identity = DualKeyIdentity.generate()
            val passphrase = "a passphrase".toCharArray()
            val encrypted = KeystoreFileFormat.encodeEncrypted(identity, passphrase)
            // Offset 14 is the single parallelism byte - see the memoryKiB test above for the full
            // header layout. Pins the same cap for parallelism as already exists for memoryKiB/
            // iterations (a byte value of 255 is otherwise structurally valid per Params' own 1..255
            // range check, so only this cap in decodeEncrypted rules it out).
            encrypted[14] = 255.toByte()

            shouldThrow<CorruptedIdentityFileException> {
                KeystoreFileFormat.decodeEncrypted(encrypted, passphrase)
            }
        }

        test("decodeAuto reads a legacy v1 plaintext file correctly") {
            val identity = DualKeyIdentity.generate()
            val plaintext = KeystoreFileFormat.encode(identity)

            val decoded = KeystoreFileFormat.decodeAuto(plaintext, passphrase = null)

            decoded.secp256k1KeyPair.publicKey shouldBe identity.secp256k1KeyPair.publicKey
        }

        test("decodeAuto with a v2 file and a null passphrase throws KeystoreDecryptionException") {
            val identity = DualKeyIdentity.generate()
            val encrypted = KeystoreFileFormat.encodeEncrypted(identity, "a passphrase".toCharArray())

            shouldThrow<KeystoreDecryptionException> {
                KeystoreFileFormat.decodeAuto(encrypted, passphrase = null)
            }
        }
    })
