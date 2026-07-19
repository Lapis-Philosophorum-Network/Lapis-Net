package net.lapisphilosophorum.lapisnet.karma

/** `host`/`port` for a single Electrum server. **Plaintext TCP only, deliberately - not a design
 * choice, a real constraint of the `net.osslabz:electrum-client:0.3.0` library this wave depends
 * on.** Its underlying `net.osslabz.jsonrpc.JsonRpcTcpClient` transport connects over a raw JDK
 * `java.nio.channels.SocketChannel` with no TLS support at all (verified by inspecting the
 * decompiled class - there is no `SSLSocketChannel`/`SSLContext` anywhere in it), so [port] must be
 * a plaintext Electrum port (conventionally `50001`) even though many public Electrum servers also
 * offer a TLS port (conventionally `50002`) that this library cannot use. This is an additional
 * "trusting, not trustless" caveat on top of [ElectrumTimeAnchorSource]'s own documented
 * no-merkle-proof-verification scope: queries sent to a configured server are visible in plaintext
 * to any network observer between this node and that server, in addition to the server itself being
 * trusted for the response content. */
data class ElectrumServerConfig(
    val host: String,
    val port: Int,
)

/**
 * Operator-configured Electrum server list for [ElectrumTimeAnchorSource]. [PLACEHOLDER] is
 * deliberately an EMPTY list - a "clearly-marked stand-in, not a real value", the same convention
 * [net.lapisphilosophorum.lapisnet.browser.PLACEHOLDER_VIEW_ID] follows, and the same convention
 * the retired `BootstrapPeers.PLACEHOLDER` followed before V0.4 replaced it with real,
 * externally-configurable operator config (see
 * [net.lapisphilosophorum.lapisnet.networking.BootstrapConfig]).
 *
 * **Why empty, not a hardcoded list of real public Electrum servers.** During this wave's
 * implementation, this codebase's sandboxed build/dev environment was confirmed to allow only
 * HTTPS egress through a pre-configured proxy - raw TCP connections (which is all
 * `net.osslabz:electrum-client`'s transport supports, see [ElectrumServerConfig]'s doc comment on
 * why TLS isn't an option either) to well-known public Electrum servers (e.g.
 * `electrum.blockstream.info:50001`, `fortress.qtornado.com:50001`) were attempted and confirmed
 * BLOCKED, not merely slow - `bash`'s `/dev/tcp` pseudo-device connect attempts timed out with no
 * TCP handshake completing at all. There was therefore no way to verify from this environment that
 * any specific hardcoded hostname is currently a real, reachable, reputable public Electrum server
 * - public server lists are known to churn (servers go offline, change ports, or stop serving
 * public traffic) - and shipping unverified hostnames would be worse than shipping none: a node
 * operator would silently get [TimeAnchorLookupResult.LookupFailed] against a dead server and might
 * reasonably assume the code is broken rather than the configured server being stale.
 *
 * A real deployment MUST explicitly configure a real, currently-reachable server list -
 * [ElectrumTimeAnchorSource] with an empty [servers] list (the default) will surface a clear
 * [TimeAnchorLookupResult.LookupFailed] on the first real lookup attempt, never a silent
 * [TimeAnchorLookupResult.NotFound] (see that sealed interface's doc comment for why that
 * distinction is load-bearing).
 */
object ElectrumServers {
    val PLACEHOLDER: List<ElectrumServerConfig> = emptyList()
}
