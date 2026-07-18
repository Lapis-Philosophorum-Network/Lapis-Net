package net.lapisphilosophorum.lapisnet.karma

import com.fasterxml.jackson.databind.JsonNode
import fr.acinq.bitcoin.Transaction
import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.osslabz.jsonrpc.JsonRpcTcpClient
import java.time.Duration

private val logger = KotlinLogging.logger {}

/** Shared default connect timeout for [ElectrumTimeAnchorSource] and [RealElectrumRpc] - kept as
 * one constant, not two independently-defaulted parameters, so the two classes' defaults cannot
 * silently drift apart (see [ElectrumTimeAnchorSource]'s constructor doc comment for why they are
 * two separate parameters in the first place). */
internal val DEFAULT_ELECTRUM_CONNECT_TIMEOUT: Duration = Duration.ofSeconds(10)

/** One entry from `blockchain.scripthash.get_history`. [txHash] is in Electrum-protocol DISPLAY
 * byte order (reversed relative to [ChainAnchorClaim.genesisTxid]'s internal/wire-order convention)
 * - exactly the same order the real protocol both returns it in and expects it back in for
 * `blockchain.transaction.get`. [height] follows the Electrum protocol convention: a positive value
 * is a real confirmed block height; `0` or negative means unconfirmed (mempool, possibly with an
 * unconfirmed parent) - see [ElectrumTimeAnchorSource.findFirstOutgoingTransaction]'s doc comment
 * for why unconfirmed entries are filtered out before this wave ever calls them a "genesis" height. */
internal class HistoryEntry(
    txHash: ByteArray,
    val height: Int,
) {
    private val storedTxHash: ByteArray = txHash.copyOf()
    val txHash: ByteArray get() = storedTxHash.copyOf()

    override fun equals(other: Any?): Boolean =
        other is HistoryEntry && height == other.height && storedTxHash.contentEquals(other.storedTxHash)

    override fun hashCode(): Int = 31 * height + storedTxHash.contentHashCode()

    override fun toString(): String = "HistoryEntry(txHash=${storedTxHash.toHex()}, height=$height)"
}

/** Thrown by [ElectrumRpc] implementations on any RPC/connection failure - always caught and
 * translated into [TimeAnchorLookupResult.LookupFailed] by [ElectrumTimeAnchorSource], never
 * allowed to escape to a caller uncaught. */
internal class ElectrumRpcException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Test seam between [ElectrumTimeAnchorSource] and the real network: [RealElectrumRpc] is the one
 * production implementation, a `FakeElectrumRpc` (test-only, in `ElectrumTimeAnchorSourceTest`)
 * returns canned responses with zero real network I/O. All byte-array parameters/returns use
 * whichever byte order is documented on each method - never a `bitcoin-kmp`/Jackson type, keeping
 * this interface (and therefore every implementation's public shape) free of this module's
 * `implementation`-only dependencies leaking out.
 */
internal interface ElectrumRpc {
    /** [scriptHash] is [BitcoinAddressDerivation.electrumScriptHash]'s already-reversed output.
     * Returned entries are in NO particular guaranteed order - callers sort by height themselves
     * (mirrors the real Electrum protocol, which does not guarantee history ordering). */
    fun scriptHashHistory(scriptHash: ByteArray): List<HistoryEntry>

    /** [txHash] must be in the same DISPLAY-order convention as [HistoryEntry.txHash]. Returns the
     * raw serialized transaction bytes. */
    fun rawTransaction(txHash: ByteArray): ByteArray

    /** The current chain tip height. */
    fun tipHeight(): Int
}

/**
 * The one real [ElectrumRpc] implementation, talking Electrum's JSON-RPC-over-TCP protocol.
 *
 * **Deliberately bypasses `net.osslabz.electrum.ElectrumClient`'s high-level façade class, talking
 * directly to `net.osslabz.jsonrpc.JsonRpcTcpClient` instead - a real API finding from this wave's
 * implementation, not the plan's original assumption.** `ElectrumClient` exposes only
 * `addressGetHistory`/`scriptHashGetHistory` and `getServerVersion` - there is no method for
 * `blockchain.transaction.get` (fetching a raw transaction, needed to scan its witnesses) or any
 * "current chain tip" RPC (`blockchain.headers.subscribe`) anywhere on it, and its own internal
 * `JsonRpcTcpClient` instance is a private field with no accessor, so it cannot be reused for the
 * two missing calls either. `net.osslabz.jsonrpc.JsonRpcTcpClient` (the transport class
 * `ElectrumClient` itself wraps internally) is a public class with a public
 * `call(method: String, params: Any): JsonNode` generic JSON-RPC method - this class uses that
 * directly for all three needed RPCs (`blockchain.scripthash.get_history`,
 * `blockchain.transaction.get`, `blockchain.headers.subscribe`) over a single connection, rather
 * than splitting across a half-used `ElectrumClient` plus a second, separately-connected
 * `JsonRpcTcpClient`.
 *
 * **Lazy connection, not eager.** `JsonRpcTcpClient`'s own constructor (confirmed by inspecting its
 * decompiled bytecode) synchronously attempts the initial TCP connection and THROWS
 * `JsonRpcException` if it fails, in addition to unconditionally starting a background daemon
 * selector thread. Connecting eagerly inside THIS class's constructor would make merely
 * constructing an [ElectrumTimeAnchorSource] with its default parameters (see that class - the
 * default [ElectrumTimeAnchorSource.rpc] parameter constructs a [RealElectrumRpc]) either throw
 * immediately (with the empty [ElectrumServers.PLACEHOLDER] default) or spawn a live network
 * connection as a side effect of object construction, neither of which is acceptable. [connection]
 * is therefore a `by lazy` property: the real connection attempt (trying each of [servers] in
 * order, per this class's own [connectToFirstReachable]) happens on the FIRST real RPC call, not at
 * construction time.
 *
 * **Known resource-lifecycle gap, accepted for this wave.** Once [connection] is realized, it holds
 * a live socket and a background thread for the remaining lifetime of this [RealElectrumRpc]
 * instance - there is no `close()`/`stop()` wired into [ElectrumTimeAnchorSource] or
 * [KarmaAnchorCache], and neither is wired into `BrowserServer.stop()`, matching the plan's scope
 * for this wave (which specifies no such lifecycle method). In practice this is a single, bounded
 * connection per long-lived [KarmaAnchorCache] instance, not an unbounded leak, but it is a real,
 * named gap a future wave should close - flagged explicitly here rather than left silent.
 */
internal class RealElectrumRpc(
    private val servers: List<ElectrumServerConfig>,
    private val connectTimeout: Duration = DEFAULT_ELECTRUM_CONNECT_TIMEOUT,
) : ElectrumRpc {
    private val connection: JsonRpcTcpClient by lazy { connectToFirstReachable() }

    private fun connectToFirstReachable(): JsonRpcTcpClient {
        if (servers.isEmpty()) {
            throw ElectrumRpcException(
                "no Electrum servers configured - see ElectrumServers.PLACEHOLDER's doc comment; " +
                    "a real deployment must supply its own server list",
            )
        }
        var lastError: Throwable? = null
        for (server in servers) {
            try {
                return JsonRpcTcpClient(server.host, server.port, connectTimeout)
            } catch (e: RuntimeException) {
                logger.debug(e) { "failed to connect to Electrum server ${server.host}:${server.port}, trying next" }
                lastError = e
            }
        }
        throw ElectrumRpcException(
            "failed to connect to any of ${servers.size} configured Electrum server(s)",
            lastError,
        )
    }

    private fun call(
        method: String,
        params: Any,
    ): JsonNode =
        try {
            connection.call(method, params)
        } catch (e: RuntimeException) {
            throw ElectrumRpcException("Electrum RPC call '$method' failed", e)
        }

    override fun scriptHashHistory(scriptHash: ByteArray): List<HistoryEntry> {
        val response = call("blockchain.scripthash.get_history", listOf(scriptHash.toHex()))
        if (!response.isArray) {
            throw ElectrumRpcException("unexpected blockchain.scripthash.get_history response shape: $response")
        }
        return response.map { entry ->
            val txHashHex =
                entry.get("tx_hash")?.asText()
                    ?: throw ElectrumRpcException("history entry missing tx_hash: $entry")
            val height =
                entry.get("height")?.asInt()
                    ?: throw ElectrumRpcException("history entry missing height: $entry")
            HistoryEntry(txHashHex.hexToByteArray(), height)
        }
    }

    override fun rawTransaction(txHash: ByteArray): ByteArray {
        val response = call("blockchain.transaction.get", listOf(txHash.toHex()))
        if (!response.isTextual) {
            throw ElectrumRpcException("unexpected blockchain.transaction.get response shape: $response")
        }
        return response.asText().hexToByteArray()
    }

    override fun tipHeight(): Int {
        val response = call("blockchain.headers.subscribe", emptyList<Any>())
        return response.get("height")?.asInt()
            ?: throw ElectrumRpcException("blockchain.headers.subscribe response missing height: $response")
    }
}

/**
 * The real, client-side-only [BitcoinTimeAnchorSource] implementation - a "trusting light client",
 * NOT a trustless SPV client. No genuine SPV client library exists on Maven Central for Kotlin/JVM
 * (confirmed during this wave's planning); building real header-chain-verified SPV from scratch is
 * out of scope for this wave. Every response from [rpc] - history entries, raw transaction bytes,
 * chain tip height - is trusted at face value, with NO merkle-proof verification against a block
 * header chain and NO independent cross-check against a second server. A malicious or compromised
 * Electrum server can lie to this class about ANY of those facts, and this class has no way to
 * detect it. This is an accepted, explicitly-named scope limitation for this wave, exactly mirroring
 * [net.lapisphilosophorum.lapisnet.virtus.OnChainProof]'s own "structural/trusting, not verified"
 * precedent - and it only matters for THIS node's own outgoing vote (see [KarmaAnchorCache]), since
 * [KarmaGossip] never calls this class at all (see that class's doc comment on why chain
 * verification never happens in the gossip path).
 */
class ElectrumTimeAnchorSource internal constructor(
    private val servers: List<ElectrumServerConfig>,
    private val rpc: ElectrumRpc,
    private val connectTimeout: Duration,
    /** Defense-in-depth cap on how many of a scripthash's history entries this class will fetch a
     * raw transaction for. A real address could in principle have an enormous transaction history;
     * without a cap, a single lookup could trigger unboundedly many `blockchain.transaction.get`
     * round-trips against a possibly-malicious or possibly-slow server. Only the EARLIEST (lowest
     * height) entries are ever needed for "first outgoing transaction", so entries are sorted
     * ascending by height before this cap is applied - the cap only bites for an address with an
     * implausibly long history, not for the common case. */
    private val maxHistoryEntriesScanned: Int,
) : BitcoinTimeAnchorSource {
    /** Public entry point - always builds a real [RealElectrumRpc] over [servers]. The internal
     * primary constructor above exists purely as a test seam (letting tests substitute a fake
     * [ElectrumRpc] with zero real network I/O - see `ElectrumTimeAnchorSourceTest`'s
     * `FakeElectrumRpc`), mirroring [KarmaVoteIndex]'s/[net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex]'s
     * established internal-constructor-as-test-seam pattern, inverted here only because the
     * test-seam parameter ([rpc]) is itself `internal`-typed and therefore cannot appear in a
     * `public` constructor at all (Kotlin visibility rules) - unlike those two classes' `Int` cap
     * parameters, which are public types and can freely default in a public constructor. */
    constructor(
        servers: List<ElectrumServerConfig> = ElectrumServers.PLACEHOLDER,
        connectTimeout: Duration = DEFAULT_ELECTRUM_CONNECT_TIMEOUT,
        maxHistoryEntriesScanned: Int = 2_000,
    ) : this(servers, RealElectrumRpc(servers, connectTimeout), connectTimeout, maxHistoryEntriesScanned)

    /**
     * Fetches [pubkey]'s P2WPKH scripthash history (capped at [maxHistoryEntriesScanned], earliest
     * height first), and for each CONFIRMED candidate (Electrum protocol convention: `height > 0` -
     * `0` or negative means unconfirmed/mempool, never a real "genesis" height a [ChainAnchorClaim]
     * should anchor to) fetches its raw transaction bytes and parses them with `bitcoin-kmp`'s real
     * `Transaction.read`, scanning every input's witness stack for a second item equal to [pubkey]'s
     * compressed bytes - see [BitcoinAddressDerivation]'s class doc comment for why that alone
     * proves "this identity's key authorized a spend" for a P2WPKH input. Returns
     * [TimeAnchorLookupResult.Found] for the first (lowest-height) match, [TimeAnchorLookupResult.NotFound]
     * if none of the scanned candidates match, and [TimeAnchorLookupResult.LookupFailed] - never an
     * uncaught exception - for any RPC failure.
     *
     * An individual candidate transaction that fails to parse (corrupt bytes, a server returning
     * something unexpected for that one entry) is skipped and logged, not treated as a fatal
     * failure of the whole lookup - only an [ElectrumRpcException] (a real RPC/connection failure)
     * aborts the whole call as [TimeAnchorLookupResult.LookupFailed].
     */
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        try {
            val scriptHash = BitcoinAddressDerivation.electrumScriptHash(pubkey)
            val confirmedAscending =
                rpc
                    .scriptHashHistory(scriptHash)
                    .filter { it.height > 0 }
                    .sortedBy { it.height }
                    .take(maxHistoryEntriesScanned)

            val targetPubkeyBytes = pubkey.bytes
            var found: TimeAnchorLookupResult.Found? = null
            for (entry in confirmedAscending) {
                // rpc.rawTransaction() is deliberately OUTSIDE the inner try/catch below - a real
                // ElectrumRpcException from the RPC layer itself must propagate to the outer catch
                // (a whole-lookup LookupFailed), never be conflated with Transaction.read()'s own
                // RuntimeExceptions on merely-unparseable bytes for a single candidate (which alone
                // should be skipped, not treated as a fatal RPC failure).
                val rawBytes = rpc.rawTransaction(entry.txHash)
                val transaction =
                    try {
                        Transaction.read(rawBytes)
                    } catch (e: RuntimeException) {
                        logger.debug(e) { "skipping unparseable candidate transaction at height ${entry.height}" }
                        continue
                    }
                val spendsFromTarget =
                    transaction.txIn.any { txIn ->
                        val stack = txIn.witness.stack
                        stack.size >= 2 && stack[1].toByteArray().contentEquals(targetPubkeyBytes)
                    }
                if (spendsFromTarget) {
                    found = TimeAnchorLookupResult.Found(entry.height, transaction.hash.value.toByteArray())
                    break
                }
            }
            found ?: TimeAnchorLookupResult.NotFound
        } catch (e: ElectrumRpcException) {
            // e.message can embed a compromised/misbehaving Electrum server's raw response text
            // (see e.g. RealElectrumRpc.scriptHashHistory's "unexpected ... response shape: $response"
            // message) - that text must never reach a caller, let alone flow all the way out to an
            // HTTP response body (KarmaAnchorCache.currentClaimFor wraps LookupFailed.reason
            // directly into KarmaAnchorResolutionException.message, which BrowserApi's
            // POST /api/karma handler echoes into its 502 body). The full detail is still logged
            // server-side here, at the one place that actually has it; only a generic, fixed
            // reason crosses this trust boundary.
            logger.warn(e) { "Electrum lookup failed while resolving a Karma time anchor" }
            TimeAnchorLookupResult.LookupFailed("Electrum lookup failed")
        }

    /** @throws ElectrumRpcException on any RPC/connection failure - there is no safe non-throwing
     * value for a chain tip query, see [BitcoinTimeAnchorSource.currentChainTipHeight]'s doc
     * comment. The thrown exception's message is always the fixed, generic string below, never
     * [rpc]'s own - mirrors [findFirstOutgoingTransaction]'s identical sanitization: a raw
     * [ElectrumRpcException] from [ElectrumRpc.tipHeight] can embed a compromised/misbehaving
     * Electrum server's raw response text (see [RealElectrumRpc.tipHeight]'s "... response missing
     * height: $response" message), which must never cross out to a caller - let alone all the way
     * out to an HTTP response body ([KarmaAnchorCache.currentClaimFor] wraps this exception's
     * message directly into [KarmaAnchorResolutionException], which `BrowserApi`'s
     * `POST /api/karma` handler echoes into its 502 body). Full detail is still logged server-side
     * here, at the one place that actually has it. */
    override fun currentChainTipHeight(): Int =
        try {
            rpc.tipHeight()
        } catch (e: ElectrumRpcException) {
            logger.warn(e) { "Electrum chain-tip lookup failed while resolving a Karma time anchor" }
            throw ElectrumRpcException("Electrum chain-tip lookup failed", e)
        }
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun String.hexToByteArray(): ByteArray {
    require(length % 2 == 0) { "hex string must have an even length, was $length" }
    return ByteArray(length / 2) { i -> substring(i * 2, i * 2 + 2).toInt(16).toByte() }
}
