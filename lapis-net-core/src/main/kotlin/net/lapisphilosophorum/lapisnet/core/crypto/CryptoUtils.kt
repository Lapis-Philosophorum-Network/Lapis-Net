package net.lapisphilosophorum.lapisnet.core.crypto

import java.security.MessageDigest

/**
 * Domain-separated SHA-256: hashes a length-prefixed ASCII domain tag followed by the given
 * byte-string parts. Prevents a signature produced for one purpose (e.g. an identity binding)
 * from being replayed or confused as a signature for a different purpose (e.g. a Bitcoin sighash
 * or a Veritas trust-edge signature) using the same secp256k1 key. Every signing purpose in this
 * project must use its own, distinct domain tag.
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
    parts.forEach { digest.update(it) }
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
