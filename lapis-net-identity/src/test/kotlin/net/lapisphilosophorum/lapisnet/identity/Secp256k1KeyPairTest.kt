package net.lapisphilosophorum.lapisnet.identity

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class Secp256k1KeyPairTest :
    FunSpec({
        val digest = ByteArray(32) { it.toByte() }

        test("generate produces different private keys across calls") {
            val a = Secp256k1KeyPair.generate()
            val b = Secp256k1KeyPair.generate()
            a.privateKey shouldNotBe b.privateKey
        }

        test("sign is deterministic for the same digest and key") {
            val keyPair = Secp256k1KeyPair.generate()
            keyPair.sign(digest) shouldBe keyPair.sign(digest)
        }

        test("verify succeeds for a matching signature, digest, and public key") {
            val keyPair = Secp256k1KeyPair.generate()
            val signature = keyPair.sign(digest)
            keyPair.publicKey.verify(digest, signature) shouldBe true
        }

        test("verify fails when the digest is tampered") {
            val keyPair = Secp256k1KeyPair.generate()
            val signature = keyPair.sign(digest)
            val tamperedDigest = digest.copyOf().also { it[0] = (it[0] + 1).toByte() }
            keyPair.publicKey.verify(tamperedDigest, signature) shouldBe false
        }

        test("verify fails when the signature is tampered") {
            val keyPair = Secp256k1KeyPair.generate()
            val signature = keyPair.sign(digest)
            val tamperedSignature = signature.copyOf().also { it[0] = (it[0] + 1).toByte() }
            keyPair.publicKey.verify(digest, tamperedSignature) shouldBe false
        }

        test("verify fails against a different public key") {
            val keyPair = Secp256k1KeyPair.generate()
            val otherKeyPair = Secp256k1KeyPair.generate()
            val signature = keyPair.sign(digest)
            otherKeyPair.publicKey.verify(digest, signature) shouldBe false
        }

        test("rejects an all-zero private key") {
            shouldThrow<IllegalArgumentException> {
                Secp256k1PrivateKey(ByteArray(32))
            }
        }

        test("rejects a private key that is out of curve order (all-0xFF)") {
            shouldThrow<IllegalArgumentException> {
                Secp256k1PrivateKey(ByteArray(32) { 0xFF.toByte() })
            }
        }

        test("rejects a private key of the wrong length") {
            shouldThrow<IllegalArgumentException> {
                Secp256k1PrivateKey(ByteArray(31))
            }
            shouldThrow<IllegalArgumentException> {
                Secp256k1PrivateKey(ByteArray(33))
            }
        }

        test("rejects a public key of the wrong length") {
            shouldThrow<IllegalArgumentException> {
                Secp256k1PublicKey(ByteArray(32))
            }
        }

        test("rejects a public key of the correct length that is not a valid point on the curve") {
            // Correct-length (33) bytes with a plausible compressed-key prefix, but the X
            // coordinate has no corresponding point on the curve. Without this check, a caller
            // constructing a Secp256k1PublicKey from untrusted/decoded bytes (e.g. a Veritas
            // grant read off the DFS) would silently succeed, and a *later* call to verify()
            // would throw an uncaught native exception instead of returning false.
            shouldThrow<IllegalArgumentException> {
                Secp256k1PublicKey(byteArrayOf(0x02) + ByteArray(32))
            }
        }

        test("rejects signing a digest of the wrong length") {
            val keyPair = Secp256k1KeyPair.generate()
            shouldThrow<IllegalArgumentException> {
                keyPair.sign(ByteArray(31))
            }
        }

        // --- hashCode caching (round-2 DoS constant-factor fix) --------------------------------

        test("hashCode is cached but stays consistent with equals across independent instances") {
            // Secp256k1PublicKey.hashCode() is cached at construction (see its doc comment) since
            // the object is immutable - this must not weaken the hashCode/equals contract that
            // lapis-net-trust's HashMap/HashSet-keyed BFS (TrustPathFinder) relies on: two
            // DIFFERENT Secp256k1PublicKey instances built from the same underlying bytes must
            // still report equal hashCodes (and be equal), and calling hashCode() repeatedly on the
            // same instance must keep returning the identical value.
            val bytes = Secp256k1KeyPair.generate().publicKey.bytes
            val a = Secp256k1PublicKey(bytes)
            val b = Secp256k1PublicKey(bytes.copyOf())

            (a == b) shouldBe true
            a.hashCode() shouldBe b.hashCode()
            a.hashCode() shouldBe a.hashCode() // repeated calls on the same instance are stable

            val other = Secp256k1KeyPair.generate().publicKey
            (a == other) shouldBe false
        }

        // --- degenerate-signature verify() hardening (round-2 C1 fix) ---------------------------

        test("verify returns false, not throws, for a right-length all-0xFF degenerate signature") {
            // Right-length (64 bytes) but not a well-formed (r, s) pair at all - this is the exact
            // shape a malicious gossip peer can cheaply produce (see VeritasGossipNegativePathIntegrationTest).
            // Before the fix, the native secp256k1-kmp-jvm call threw Secp256k1Exception here
            // instead of returning false.
            val keyPair = Secp256k1KeyPair.generate()
            val degenerateSignature = ByteArray(64) { 0xFF.toByte() }
            keyPair.publicKey.verify(digest, degenerateSignature) shouldBe false
        }

        test("verify returns false, not throws, for a signature whose r component is >= the curve order") {
            // secp256k1 curve order n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B
            // BFD25E8C D0364141. Using r == n (out of range) with a plausible low s.
            val curveOrderR =
                byteArrayOf(
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFF.toByte(),
                    0xFE.toByte(),
                    0xBA.toByte(),
                    0xAE.toByte(),
                    0xDC.toByte(),
                    0xE6.toByte(),
                    0xAF.toByte(),
                    0x48.toByte(),
                    0xA0.toByte(),
                    0x3B.toByte(),
                    0xBF.toByte(),
                    0xD2.toByte(),
                    0x5E.toByte(),
                    0x8C.toByte(),
                    0xD0.toByte(),
                    0x36.toByte(),
                    0x41.toByte(),
                    0x41.toByte(),
                )
            val plausibleS = ByteArray(32).also { it[31] = 1 }
            val degenerateSignature = curveOrderR + plausibleS
            val keyPair = Secp256k1KeyPair.generate()
            keyPair.publicKey.verify(digest, degenerateSignature) shouldBe false
        }
    })
