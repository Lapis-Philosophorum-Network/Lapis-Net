package net.lapisphilosophorum.lapisnet.identity

import java.security.SecureRandom

/**
 * A full Lapis Net identity: the canonical secp256k1 keypair plus an Ed25519 keypair bound to it
 * for libp2p's peer ID (from V0.1.3 onward). A user may hold several [DualKeyIdentity] instances
 * as separate pseudonyms - this type intentionally has no notion of "the one identity", that is
 * left to [IdentityRepository].
 */
class DualKeyIdentity(
    val secp256k1KeyPair: Secp256k1KeyPair,
    val ed25519KeyPair: Ed25519KeyPair,
    val binding: IdentityBinding,
) {
    companion object {
        fun generate(random: SecureRandom = SecureRandom()): DualKeyIdentity {
            val secp256k1KeyPair = Secp256k1KeyPair.generate(random)
            val ed25519KeyPair = Ed25519KeyPair.generate(random)
            val binding = IdentityBinding.create(secp256k1KeyPair, ed25519KeyPair.publicKey)
            return DualKeyIdentity(secp256k1KeyPair, ed25519KeyPair, binding)
        }
    }

    fun verifyBinding(): Boolean = IdentityBinding.verify(secp256k1KeyPair.publicKey, binding)
}
