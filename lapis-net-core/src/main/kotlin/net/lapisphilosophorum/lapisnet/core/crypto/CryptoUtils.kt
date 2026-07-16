package net.lapisphilosophorum.lapisnet.core.crypto

import java.security.MessageDigest

private const val MAX_DIGEST_PART_SIZE = 0xFFFF

/**
 * Domain-separated SHA-256: hashes a length-prefixed ASCII domain tag followed by each given
 * byte-string part, itself length-prefixed. Prevents a signature produced for one purpose (e.g.
 * an identity binding) from being replayed or confused as a signature for a different purpose
 * (e.g. a Bitcoin sighash or a Veritas trust-edge signature) using the same secp256k1 key. Every
 * signing purpose in this project must use its own, distinct domain tag.
 *
 * Every part is prefixed with its own length, not just the domain tag - otherwise
 * `digest(tag, "AB", "CD")` and `digest(tag, "A", "BCD")` would hash to the same bytes, silently
 * breaking domain separation for any future caller that signs more than one field at once.
 *
 * A fresh [MessageDigest] instance is created per call - [MessageDigest] is not thread-safe.
 */
fun domainSeparatedDigest(
    domainTag: String,
    vararg parts: ByteArray,
): ByteArray {
    require(domainTag.length in 1..255) { "domain tag must be 1..255 chars" }
    val tagBytes = domainTag.toByteArray(Charsets.US_ASCII)
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(tagBytes.size.toByte())
    digest.update(tagBytes)
    parts.forEach { part ->
        require(part.size <= MAX_DIGEST_PART_SIZE) { "digest part must be at most $MAX_DIGEST_PART_SIZE bytes" }
        digest.update((part.size ushr 8).toByte())
        digest.update(part.size.toByte())
        digest.update(part)
    }
    return digest.digest()
}

/**
 * Short hex fingerprint (first 8 bytes of SHA-256) safe to log or display. Never call this on
 * private key material - it is intended for public keys and other non-secret identifiers only.
 */
fun ByteArray.fingerprintHex(): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(this)
    return digest.copyOfRange(0, 8).joinToString("") { "%02x".format(it) }
}
