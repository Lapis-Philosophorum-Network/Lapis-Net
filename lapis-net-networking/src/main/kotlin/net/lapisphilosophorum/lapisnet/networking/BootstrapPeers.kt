package net.lapisphilosophorum.lapisnet.networking

import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr

/**
 * Hardcoded bootstrap peers a node dials on startup (Bitcoin-client-style), per the project's
 * decided bootstrap model. No real bootstrap infrastructure exists yet as of V0.1.3.
 *
 * [PLACEHOLDER] uses RFC 5737 documentation-range IPs (`203.0.113.0/24`) precisely so nobody
 * mistakes them for real, reachable addresses, paired with a freshly-generated random [PeerId]
 * per entry (never network-reachable, but syntactically valid so the resulting [Multiaddr]
 * parses like a real one). Kept as a code constant, not a resource file: this repository has no
 * resource-file precedent yet, and this list is expected to become externally configurable once
 * real infrastructure exists.
 *
 * TODO(post-V0.1.3, before any real deployment): replace with real, operator-controlled
 * bootstrap addresses, and make the list externally configurable (env var / config file), not
 * just a compiled-in constant.
 */
object BootstrapPeers {
    private val DOCUMENTATION_RANGE_IPS = listOf("203.0.113.10", "203.0.113.11")
    private const val PLACEHOLDER_PORT = 4001

    val PLACEHOLDER: List<Multiaddr> =
        DOCUMENTATION_RANGE_IPS.map { ip ->
            Multiaddr("/ip4/$ip/tcp/$PLACEHOLDER_PORT").withP2P(PeerId.random())
        }
}
