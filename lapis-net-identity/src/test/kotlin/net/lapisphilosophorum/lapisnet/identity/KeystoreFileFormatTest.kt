package net.lapisphilosophorum.lapisnet.identity

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

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

        test("rejects a buffer where the stored public key does not match the private key") {
            val bytes = KeystoreFileFormat.encode(DualKeyIdentity.generate())
            // flip a byte inside the stored secp256k1 public key (offset 37..69)
            bytes[40] = (bytes[40] + 1).toByte()
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
    })
