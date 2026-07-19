package net.lapisphilosophorum.lapisnet.networking

import io.github.oshai.kotlinlogging.KotlinLogging
import io.libp2p.core.multiformats.Multiaddr
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists

private val logger = KotlinLogging.logger {}

private val DEFAULT_LISTEN_ADDRESS = Multiaddr("/ip4/127.0.0.1/tcp/0")

/**
 * Resolves the real bootstrap-peer list a [LapisNode] dials on [LapisNode.start], from operator
 * configuration rather than a compiled-in constant. Lapis Net is fully decentralized: a bootstrap
 * peer is only a *technical first anchor* for mesh entry (Bitcoin-client style), never a protocol
 * authority - the "genesis node" (the project's first operator) is a social/technical convention,
 * not infrastructure the protocol depends on. See docs/architecture.adoc "Genesis bootstrap".
 *
 * Two sources, merged (both optional, order deterministic - env first, then file):
 *  1. Env var LAPISNET_BOOTSTRAP_PEERS: comma-separated multiaddrs, each including a /p2p/<peerId>.
 *  2. File $LAPISNET_HOME/bootstrap.peers (or ~/.lapisnet/bootstrap.peers): one multiaddr per line;
 *     blank lines and lines beginning with '#' are ignored.
 *
 * An empty result (nothing configured) is the correct default - a fresh install with no operator
 * config dials nobody and relies on mDNS/manual POST /api/peers/connect until an operator supplies
 * a real anchor. Malformed entries are logged and skipped, never fatal (a single bad line must not
 * stop a node from starting).
 */
object BootstrapConfig {
    const val ENV_VAR = "LAPISNET_BOOTSTRAP_PEERS"
    const val FILE_NAME = "bootstrap.peers"
    const val LISTEN_ENV_VAR = "LAPISNET_LISTEN_ADDR"

    /** Hard cap on how many bootstrap entries we will parse/dial, so a hostile or accidentally
     * huge config file can't create an unbounded dial fan-out on startup. */
    const val MAX_BOOTSTRAP_PEERS = 64

    fun resolve(
        env: Map<String, String> = System.getenv(),
        lapisnetHome: Path = defaultLapisnetHome(env),
    ): List<Multiaddr> {
        val fromEnv = env[ENV_VAR]?.split(',').orEmpty()
        val fromFile = readFileLines(lapisnetHome.resolve(FILE_NAME))
        return (fromEnv + fromFile)
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .take(MAX_BOOTSTRAP_PEERS)
            .mapNotNull { raw -> parseOrWarn(raw) }
            .distinct()
    }

    /** Resolves the libp2p listen address a real (non-test) node binds - defaults to loopback with
     * an OS-assigned port, matching [LapisNode.create]'s own default exactly, so a headless/CI
     * process with no [LISTEN_ENV_VAR] set behaves identically to today. An operator running a
     * real, externally-reachable node sets e.g. `LAPISNET_LISTEN_ADDR=/ip4/0.0.0.0/tcp/4001`. */
    fun resolveListenAddress(env: Map<String, String> = System.getenv()): Multiaddr =
        env[LISTEN_ENV_VAR]?.let { raw ->
            runCatching { Multiaddr(raw) }
                .onFailure { logger.warn { "ignoring malformed $LISTEN_ENV_VAR value '$raw': ${it.message}" } }
                .getOrNull()
        } ?: DEFAULT_LISTEN_ADDRESS

    private fun parseOrWarn(raw: String): Multiaddr? {
        val maddr = runCatching { Multiaddr(raw) }.getOrNull()
        if (maddr == null) {
            logger.warn { "ignoring malformed bootstrap multiaddr '$raw'" }
            return null
        }
        if (maddr.getPeerId() == null) {
            logger.warn { "ignoring bootstrap multiaddr without a /p2p/<peerId> component: '$raw'" }
            return null
        }
        return maddr
    }

    private fun readFileLines(path: Path): List<String> =
        if (path.exists()) {
            runCatching { Files.readAllLines(path) }
                .onFailure { logger.warn { "could not read bootstrap file $path: ${it.message}" } }
                .getOrDefault(emptyList())
        } else {
            emptyList()
        }
}

/** Resolves $LAPISNET_HOME or ~/.lapisnet, matching defaultIdentityDirectory()'s convention in
 * lapis-net-identity. Kept here (not imported) to avoid a networking->identity coupling just for a
 * path string; the two definitions must stay in sync (both read LAPISNET_HOME then user.home). */
internal fun defaultLapisnetHome(env: Map<String, String> = System.getenv()): Path =
    Path.of(env["LAPISNET_HOME"] ?: (System.getProperty("user.home") + "/.lapisnet"))
