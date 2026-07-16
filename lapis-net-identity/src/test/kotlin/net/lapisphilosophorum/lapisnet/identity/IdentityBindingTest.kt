package net.lapisphilosophorum.lapisnet.identity

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import java.security.MessageDigest

class IdentityBindingTest :
    FunSpec({
        test("create then verify round-trips successfully") {
            val secp256k1KeyPair = Secp256k1KeyPair.generate()
            val ed25519PublicKey = Ed25519KeyPair.generate().publicKey
            val binding = IdentityBinding.create(secp256k1KeyPair, ed25519PublicKey)
            IdentityBinding.verify(secp256k1KeyPair.publicKey, binding) shouldBe true
        }

        test("verify fails when the bound Ed25519 public key is tampered") {
            val secp256k1KeyPair = Secp256k1KeyPair.generate()
            val ed25519PublicKey = Ed25519KeyPair.generate().publicKey
            val binding = IdentityBinding.create(secp256k1KeyPair, ed25519PublicKey)

            val tamperedBytes = ed25519PublicKey.bytes.copyOf().also { it[0] = (it[0] + 1).toByte() }
            val tamperedBinding = IdentityBinding(Ed25519PublicKey(tamperedBytes), binding.signature)

            IdentityBinding.verify(secp256k1KeyPair.publicKey, tamperedBinding) shouldBe false
        }

        test("verify fails against a different secp256k1 identity") {
            val secp256k1KeyPair = Secp256k1KeyPair.generate()
            val otherSecp256k1KeyPair = Secp256k1KeyPair.generate()
            val ed25519PublicKey = Ed25519KeyPair.generate().publicKey
            val binding = IdentityBinding.create(secp256k1KeyPair, ed25519PublicKey)

            IdentityBinding.verify(otherSecp256k1KeyPair.publicKey, binding) shouldBe false
        }

        test("a signature over a plain, non-domain-tagged digest of the same bytes is not the binding signature") {
            val secp256k1KeyPair = Secp256k1KeyPair.generate()
            val ed25519PublicKey = Ed25519KeyPair.generate().publicKey
            val binding = IdentityBinding.create(secp256k1KeyPair, ed25519PublicKey)

            val plainDigest = MessageDigest.getInstance("SHA-256").digest(ed25519PublicKey.bytes)
            val plainSignature = secp256k1KeyPair.sign(plainDigest)

            plainDigest.contentEquals(
                domainSeparatedDigest("LapisNet:identity-binding:v1", ed25519PublicKey.bytes),
            ) shouldBe
                false
            plainSignature.contentEquals(binding.signature) shouldBe false
        }
    })
