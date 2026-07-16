package net.lapisphilosophorum.lapisnet.identity

import java.security.SecureRandom

/** Metadata about a stored identity that never carries private key material - safe to log or list. */
data class IdentityHandle(
    val label: String,
    val secp256k1Fingerprint: String,
)

/** Thrown when a stored identity file fails to load: wrong size, bad header, or a cryptographic
 * inconsistency (derived public key mismatch, invalid binding signature). */
class CorruptedIdentityFileException(
    message: String,
) : RuntimeException(message)

/**
 * Persists and retrieves [DualKeyIdentity] instances by label, so a user can hold multiple
 * pseudonyms (see the project's device-sync / self-trust design, implemented in a later wave).
 */
interface IdentityRepository {
    fun list(): List<IdentityHandle>

    fun load(label: String): DualKeyIdentity?

    fun loadDefault(): DualKeyIdentity? = load(DEFAULT_LABEL)

    fun save(
        identity: DualKeyIdentity,
        label: String = DEFAULT_LABEL,
    ): IdentityHandle

    fun generateAndSave(
        label: String = DEFAULT_LABEL,
        random: SecureRandom = SecureRandom(),
    ): DualKeyIdentity = DualKeyIdentity.generate(random).also { save(it, label) }

    companion object {
        const val DEFAULT_LABEL = "default"
    }
}
