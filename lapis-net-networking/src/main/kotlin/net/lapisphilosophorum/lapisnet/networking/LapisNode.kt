package net.lapisphilosophorum.lapisnet.networking

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.Connection
import io.libp2p.core.Host
import io.libp2p.core.PeerId
import io.libp2p.core.PeerInfo
import io.libp2p.core.dsl.host
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.mux.StreamMuxerProtocol
import io.libp2p.discovery.MDnsDiscovery
import io.libp2p.security.noise.NoiseXXSecureChannel
import io.libp2p.transport.tcp.TcpTransport
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

private val logger = KotlinLogging.logger {}

private val DEFAULT_TIMEOUT: Duration = Duration.ofSeconds(10)
private val DEFAULT_LISTEN_ADDRESS = Multiaddr("/ip4/127.0.0.1/tcp/0")

/** Caps [LapisNode.discovered] so a noisy or malicious LAN (mDNS is trivially spoofable - any
 * device can announce arbitrary, freshly-generated PeerIds) can't grow it without bound. */
private const val MAX_DISCOVERED_PEERS = 256

/** Thrown when a node lifecycle or connection operation fails or times out. */
class LapisNodeException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * A Lapis Net P2P node: wraps a jvm-libp2p [Host] whose identity is derived from a
 * [DualKeyIdentity] (see [deriveLibp2pPeerId]), plus mDNS discovery of LAN peers.
 *
 * mDNS-discovered peers are only logged and added to [discoveredPeers] - never auto-dialed. This
 * mirrors jvm-libp2p's own [io.libp2p.core.Discoverer] design (discovery and connection are
 * separate concerns there too), and keeps discovery and connectivity independently testable.
 * Bootstrap peers are the opposite case: dialing them is the whole point of [start], so it does,
 * but non-blockingly and non-fatally - an unreachable placeholder bootstrap peer must never
 * block or fail node startup.
 *
 * [host] is exposed (read-only) so other modules that need to attach additional libp2p protocol
 * handlers to this same swarm - e.g. `lapis-net-storage`'s `NabuStorage.attach` - can do so
 * without this class growing a dependency on every protocol layered on top of it. Callers must
 * still go through [start]/[stop] for lifecycle, never call [Host.start]/[Host.stop] directly.
 */
class LapisNode private constructor(
    val host: Host,
    private val mdns: MDnsDiscovery,
) {
    private val discovered = BoundedPeerCache(MAX_DISCOVERED_PEERS)
    private val stopped = AtomicBoolean(false)

    /**
     * Set by `GossipPubSub.attach()` once GossipSub has been wired up on this node - a same-module
     * signal purely between [connect] and `GossipPubSub.attach()`, not part of this class's public
     * lifecycle API (round-2 N1 defensive check; see `GossipPubSub.attach`'s doc comment for the
     * full precondition this supports and the doc comment on [connectsBeforeGossipAttach] for how
     * the two are used together).
     */
    internal var gossipAttached: Boolean = false

    /**
     * Count of [connect] calls made while [gossipAttached] was still `false` - i.e. connections
     * GossipSub can never see, regardless of whether `GossipPubSub.attach()` is called later
     * (`Gossip` only observes connection-established events for connections made *after* it
     * registers as a [io.libp2p.core.ConnectionHandler]). `GossipPubSub.attach()` reads this once,
     * right after wiring up, to decide whether its documented "must be called before connect()"
     * precondition was actually violated - see its doc comment for why the check lives there
     * rather than here: at the moment [connect] runs, there is no way to know whether
     * `GossipPubSub.attach()` will ever be called at all, and a node that legitimately never wants
     * GossipSub must be free to call [connect] without triggering a warning.
     */
    internal val connectsBeforeGossipAttach = AtomicInteger(0)

    val peerId: PeerId get() = host.peerId

    fun listenAddresses(): List<Multiaddr> = host.listenAddresses()

    /** Peers discovered via mDNS so far. Never auto-dialed - see the class doc. */
    fun discoveredPeers(): List<PeerInfo> = discovered.values()

    /** Explicitly dial a peer (bootstrap or mDNS-discovered). */
    fun connect(
        peer: PeerInfo,
        timeout: Duration = DEFAULT_TIMEOUT,
    ): Connection {
        if (!gossipAttached) connectsBeforeGossipAttach.incrementAndGet()
        return awaitOrWrap("connect to ${peer.peerId}", timeout) {
            host.network.connect(peer.peerId, *peer.addresses.toTypedArray())
        }
    }

    fun start(
        bootstrapPeers: List<Multiaddr> = emptyList(),
        timeout: Duration = DEFAULT_TIMEOUT,
    ) {
        awaitOrWrap("start host", timeout) { host.start() }
        awaitOrWrap("start mDNS discovery", timeout) { mdns.start() }
        bootstrapPeers.forEach { address ->
            host.network
                .connect(address)
                .orTimeout(timeout.toMillis(), TimeUnit.MILLISECONDS)
                .whenComplete { _, error ->
                    if (error != null) {
                        logger.warn { "bootstrap dial to $address failed: ${error.message}" }
                    } else {
                        logger.info { "connected to bootstrap peer $address" }
                    }
                }
        }
    }

    /**
     * Stops mDNS discovery and the host independently - a failure stopping one (e.g. mDNS was
     * never successfully started) must never prevent the other's shutdown from being attempted,
     * or the Netty-backed host (bound socket, event-loop threads) could leak. Idempotent: a
     * second or later call is a no-op, so callers (e.g. a `try { start() } finally { stop() }`
     * block after `start()` itself already failed) never have to guard against a confusing
     * "already stopped" exception. If both sub-shutdowns fail on the one call that actually
     * performs them, the host's failure is thrown (mDNS's is logged) since a leaked listening
     * socket is the more severe outcome; if only one fails, that failure is thrown.
     */
    fun stop(timeout: Duration = DEFAULT_TIMEOUT) {
        if (!stopped.compareAndSet(false, true)) return
        val mdnsFailure = runCatching { awaitOrWrap("stop mDNS discovery", timeout) { mdns.stop() } }.exceptionOrNull()
        if (mdnsFailure != null) {
            logger.warn(mdnsFailure) { "failed to stop mDNS discovery cleanly, stopping host anyway" }
        }
        val hostFailure = runCatching { awaitOrWrap("stop host", timeout) { host.stop() } }.exceptionOrNull()
        if (hostFailure != null) throw hostFailure
        if (mdnsFailure != null) throw mdnsFailure
    }

    private fun <T> awaitOrWrap(
        action: String,
        timeout: Duration,
        block: () -> CompletableFuture<T>,
    ): T =
        try {
            block().get(timeout.toMillis(), TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            throw LapisNodeException("timed out waiting to $action", e)
        } catch (e: ExecutionException) {
            throw LapisNodeException("failed to $action", e.cause ?: e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw LapisNodeException("interrupted while waiting to $action", e)
        }

    companion object {
        fun create(
            identity: DualKeyIdentity,
            listenAddress: Multiaddr = DEFAULT_LISTEN_ADDRESS,
        ): LapisNode {
            val privKey = identity.deriveLibp2pPrivKey()
            val builtHost =
                host {
                    identity {
                        factory = { privKey }
                    }
                    transports {
                        add(::TcpTransport)
                    }
                    secureChannels {
                        add(::NoiseXXSecureChannel)
                    }
                    muxers {
                        add(StreamMuxerProtocol.Mplex)
                    }
                    network {
                        listen(listenAddress.toString())
                    }
                }
            val mdns = MDnsDiscovery(builtHost)
            val node = LapisNode(builtHost, mdns)
            mdns.addHandler { peerInfo ->
                if (node.discovered.record(peerInfo)) {
                    logger.info { "mDNS discovered peer ${peerInfo.peerId}" }
                } else {
                    logger.warn { "discovered-peer cache full ($MAX_DISCOVERED_PEERS) - dropping ${peerInfo.peerId}" }
                }
            }
            return node
        }
    }
}
