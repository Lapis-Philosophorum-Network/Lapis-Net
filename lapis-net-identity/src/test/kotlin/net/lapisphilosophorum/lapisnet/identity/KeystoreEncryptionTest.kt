package net.lapisphilosophorum.lapisnet.identity

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.security.SecureRandom

private fun testParams(random: SecureRandom = SecureRandom()): KeystoreEncryption.Params =
    KeystoreEncryption.Params(
        memoryKiB = KeystoreEncryption.DEFAULT_MEMORY_KIB,
        iterations = KeystoreEncryption.DEFAULT_ITERATIONS,
        parallelism = KeystoreEncryption.DEFAULT_PARALLELISM,
        salt = ByteArray(KeystoreEncryption.SALT_SIZE).also(random::nextBytes),
    )

private fun testNonce(random: SecureRandom = SecureRandom()): ByteArray =
    ByteArray(KeystoreEncryption.NONCE_SIZE).also(random::nextBytes)

private fun testHeader(): ByteArray = "test-aad-header".toByteArray()

class KeystoreEncryptionTest :
    FunSpec({
        test("encrypt-then-decrypt round-trips the exact plaintext") {
            val plaintext = "hello lapis net keystore".toByteArray()
            val passphrase = "correct horse battery staple".toCharArray()
            val params = testParams()
            val nonce = testNonce()
            val header = testHeader()

            val ciphertext = KeystoreEncryption.encrypt(plaintext, passphrase, params, nonce, header)
            val decrypted = KeystoreEncryption.decrypt(ciphertext, passphrase, params, nonce, header)

            decrypted.contentEquals(plaintext) shouldBe true
        }

        test("wrong passphrase throws KeystoreDecryptionException") {
            val plaintext = "secret material".toByteArray()
            val params = testParams()
            val nonce = testNonce()
            val header = testHeader()
            val ciphertext =
                KeystoreEncryption.encrypt(
                    plaintext,
                    "correct-passphrase".toCharArray(),
                    params,
                    nonce,
                    header,
                )

            shouldThrow<KeystoreDecryptionException> {
                KeystoreEncryption.decrypt(ciphertext, "wrong-passphrase".toCharArray(), params, nonce, header)
            }
        }

        test("a tampered ciphertext byte throws KeystoreDecryptionException") {
            val plaintext = "secret material".toByteArray()
            val passphrase = "a passphrase".toCharArray()
            val params = testParams()
            val nonce = testNonce()
            val header = testHeader()
            val ciphertext = KeystoreEncryption.encrypt(plaintext, passphrase, params, nonce, header)
            ciphertext[0] = (ciphertext[0] + 1).toByte()

            shouldThrow<KeystoreDecryptionException> {
                KeystoreEncryption.decrypt(ciphertext, passphrase, params, nonce, header)
            }
        }

        test(
            "a tampered AAD header byte throws KeystoreDecryptionException - proves params/salt/nonce are authenticated",
        ) {
            val plaintext = "secret material".toByteArray()
            val passphrase = "a passphrase".toCharArray()
            val params = testParams()
            val nonce = testNonce()
            val header = testHeader()
            val ciphertext = KeystoreEncryption.encrypt(plaintext, passphrase, params, nonce, header)

            val tamperedHeader = header.copyOf()
            tamperedHeader[0] = (tamperedHeader[0] + 1).toByte()

            shouldThrow<KeystoreDecryptionException> {
                KeystoreEncryption.decrypt(ciphertext, passphrase, params, nonce, tamperedHeader)
            }
        }

        test("deriveKey is deterministic for identical params and passphrase") {
            val passphrase = "same passphrase".toCharArray()
            val params = testParams()

            val key1 = KeystoreEncryption.deriveKey(passphrase, params)
            val key2 = KeystoreEncryption.deriveKey(passphrase, params)

            key1.contentEquals(key2) shouldBe true
        }

        test("deriveKey differs for a different salt") {
            val passphrase = "same passphrase".toCharArray()
            val random = SecureRandom()
            val paramsA = testParams(random)
            val paramsB = testParams(random)

            val keyA = KeystoreEncryption.deriveKey(passphrase, paramsA)
            val keyB = KeystoreEncryption.deriveKey(passphrase, paramsB)

            keyA.contentEquals(keyB) shouldBe false
        }
    })
