package net.lapisphilosophorum.lapisnet.networking

import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import java.util.concurrent.ConcurrentHashMap

/**
 * A peer-id-keyed, size-capped cache of [PeerInfo] discoveries.
 *
 * Keying by [PeerId] deduplicates repeated re-announcements of the same peer (normal mDNS
 * behavior). The cap bounds memory growth against a noisy or spoofing LAN - mDNS is trivially
 * spoofable, since any device can announce arbitrary, freshly-generated [PeerId]s. Once full,
 * new peers are dropped (existing entries can still be refreshed/overwritten) rather than
 * evicting older entries, so an attacker flooding announcements can't push out peers a caller
 * has already seen and may be relying on.
 *
 * Deliberately independent of jvm-libp2p's [io.libp2p.discovery.MDnsDiscovery] (which needs a
 * real, started [io.libp2p.core.Host] and - per its own README - relies on IP multicast that
 * isn't reliably available in every sandbox/CI environment) so the accumulate/dedup/cap logic
 * itself has deterministic, non-network test coverage.
 */
internal class BoundedPeerCache(
    private val maxSize: Int,
) {
    private val peers = ConcurrentHashMap<PeerId, PeerInfo>()

    /** Records a discovery. Returns `true` if it was stored (new peer, refreshed peer, or cache
     * not yet full), `false` if it was dropped because the cache is full and this is a new peer. */
    fun record(peerInfo: PeerInfo): Boolean {
        if (peers.size >= maxSize && !peers.containsKey(peerInfo.peerId)) {
            return false
        }
        peers[peerInfo.peerId] = peerInfo
        return true
    }

    fun values(): List<PeerInfo> = peers.values.toList()
}
