package net.lapisphilosophorum.lapisnet.browser

import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * The `lapisnet://connect?maddr=...&pk=...` deep-link/QR payload two real users exchange to connect
 * their nodes and (optionally) rate/self-link each other's identities without hand-copying hex.
 * Purely a transport/UX convenience - carries only public data (a dialable multiaddr and a public
 * key), never any secret, and is not itself signed or authenticated. Any trust decision made after
 * scanning is still an explicit, separately-signed [net.lapisphilosophorum.lapisnet.trust.VeritasGrant]
 * (`POST /api/trust` or `POST /api/self-link`).
 */
class ConnectUri private constructor(
    val multiaddr: Multiaddr,
    val publicKey: Secp256k1PublicKey,
) {
    fun toUriString(): String {
        val maddr = URLEncoder.encode(multiaddr.toString(), StandardCharsets.UTF_8)
        val pk = publicKey.bytes.joinToString("") { "%02x".format(it) }
        return "$SCHEME://$HOST?maddr=$maddr&pk=$pk"
    }

    companion object {
        const val SCHEME = "lapisnet"
        const val HOST = "connect"
        private const val PUBLIC_KEY_HEX_LEN = 66
        const val MAX_URI_LENGTH = 512

        fun of(
            multiaddr: Multiaddr,
            publicKey: Secp256k1PublicKey,
        ): ConnectUri {
            requireNotNull(multiaddr.getPeerId()) { "multiaddr must include a /p2p/<peerId> component" }
            return ConnectUri(multiaddr, publicKey)
        }

        /** Parses [raw], or `null` for ANY malformed input - never throws, so a route handler turns
         * `null` straight into a 400. */
        fun parseOrNull(raw: String): ConnectUri? {
            if (raw.length > MAX_URI_LENGTH) return null
            val prefix = "$SCHEME://$HOST?"
            if (!raw.startsWith(prefix)) return null
            val query = raw.substring(prefix.length)
            val params =
                query
                    .split('&')
                    .mapNotNull { part ->
                        val i = part.indexOf('=')
                        if (i <= 0) null else part.substring(0, i) to part.substring(i + 1)
                    }.toMap()
            val maddrRaw =
                params["maddr"]?.let {
                    runCatching { URLDecoder.decode(it, StandardCharsets.UTF_8) }.getOrNull()
                } ?: return null
            val pkHex = params["pk"] ?: return null
            if (pkHex.length != PUBLIC_KEY_HEX_LEN || pkHex.any { it !in "0123456789abcdefABCDEF" }) return null
            val multiaddr = runCatching { Multiaddr(maddrRaw) }.getOrNull() ?: return null
            if (multiaddr.getPeerId() == null) return null
            val pkBytes = ByteArray(33) { i -> pkHex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
            val publicKey = runCatching { Secp256k1PublicKey(pkBytes) }.getOrNull() ?: return null
            return ConnectUri(multiaddr, publicKey)
        }
    }
}
