package net.lapisphilosophorum.lapisnet.identity

import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest

private const val SIGNATURE_SIZE = 64

/** First domain-separation tag in the project. Every future secp256k1 signing purpose - e.g. a
 * Veritas trust-edge grant in V0.1.5 - must reserve its own distinct, versioned tag. */
private const val BINDING_DOMAIN_TAG = "LapisNet:identity-binding:v1"

/**
 * Cryptographic proof that a secp256k1 identity (the canonical Lapis Net identity) vouches for a
 * given Ed25519 key (used only for that identity's libp2p peer ID). The secp256k1 key signs a
 * domain-separated digest of the Ed25519 public key, so this signature cannot be confused with a
 * signature produced for another purpose - e.g. a Bitcoin sighash or a Veritas trust-edge grant -
 * even though all of those are also 32-byte digests signed with the same secp256k1 key.
 */
class IdentityBinding(
    val ed25519PublicKey: Ed25519PublicKey,
    val signature: ByteArray,
) {
    init {
        require(
            signature.size == SIGNATURE_SIZE,
        ) { "binding signature must be a compact $SIGNATURE_SIZE-byte ECDSA signature" }
    }

    companion object {
        private fun bindingDigest(ed25519PublicKey: Ed25519PublicKey): ByteArray =
            domainSeparatedDigest(BINDING_DOMAIN_TAG, ed25519PublicKey.bytes)

        fun create(
            secp256k1KeyPair: Secp256k1KeyPair,
            ed25519PublicKey: Ed25519PublicKey,
        ): IdentityBinding {
            val digest = bindingDigest(ed25519PublicKey)
            val signature = secp256k1KeyPair.sign(digest)
            return IdentityBinding(ed25519PublicKey, signature)
        }

        fun verify(
            secp256k1PublicKey: Secp256k1PublicKey,
            binding: IdentityBinding,
        ): Boolean {
            val digest = bindingDigest(binding.ed25519PublicKey)
            return secp256k1PublicKey.verify(digest, binding.signature)
        }
    }
}
