package net.lapisphilosophorum.lapisnet.karma

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.Satoshi
import fr.acinq.bitcoin.ScriptWitness
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.TxIn
import fr.acinq.bitcoin.TxOut
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.time.Duration

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

/** No real network I/O - canned responses only, mirroring the plan's "test-only, no real network"
 * seam for [ElectrumRpc]. */
private class FakeElectrumRpc(
    private val historyByScriptHash: Map<String, List<HistoryEntry>> = emptyMap(),
    private val rawTxByHash: Map<String, ByteArray> = emptyMap(),
    private val tip: Int = 1_000_000,
    private val failHistory: Boolean = false,
    private val failRawTx: Boolean = false,
) : ElectrumRpc {
    override fun scriptHashHistory(scriptHash: ByteArray): List<HistoryEntry> {
        if (failHistory) throw ElectrumRpcException("simulated scripthash history failure")
        return historyByScriptHash[scriptHash.toHex()] ?: emptyList()
    }

    override fun rawTransaction(txHash: ByteArray): ByteArray {
        if (failRawTx) throw ElectrumRpcException("simulated raw transaction failure")
        return rawTxByHash[txHash.toHex()]
            ?: throw ElectrumRpcException("no such transaction in fake: ${txHash.toHex()}")
    }

    override fun tipHeight(): Int = tip
}

/** Builds a real (via `bitcoin-kmp`'s own transaction-building API, not hand-rolled bytes) P2WPKH-
 * style transaction with a single input whose witness stack is `[fakeSignature, pubkey]` - a real
 * signature isn't needed since [ElectrumTimeAnchorSource] never verifies one, only scans for the
 * pubkey as the witness's second stack item (see [BitcoinAddressDerivation]'s doc comment). */
private fun buildSpendingTransaction(
    spenderPubkey: Secp256k1PublicKey,
    seed: Byte = 1,
): Transaction {
    val previousTxId = TxId(ByteArray(32) { seed })
    val outPoint = OutPoint(previousTxId, 0L)
    val fakeSignature = ByteVector(ByteArray(71) { 0x30 })
    val witness = ScriptWitness(listOf(fakeSignature, ByteVector(spenderPubkey.bytes)))
    val txIn = TxIn(outPoint, ByteVector.empty, TxIn.SEQUENCE_FINAL, witness)
    val txOut = TxOut(Satoshi(1_000L), ByteVector(byteArrayOf(0x6a))) // trivial OP_RETURN-shaped output
    return Transaction(version = 2L, txIn = listOf(txIn), txOut = listOf(txOut), lockTime = 0L)
}

/** Builds a transaction that spends from an UNRELATED key - used to prove non-matching candidates
 * are correctly skipped. */
private fun buildUnrelatedTransaction(seed: Byte): Transaction =
    buildSpendingTransaction(Secp256k1KeyPair.generate().publicKey, seed)

private fun anchorSource(rpc: ElectrumRpc): ElectrumTimeAnchorSource =
    ElectrumTimeAnchorSource(emptyList(), rpc, Duration.ofSeconds(1), maxHistoryEntriesScanned = 2_000)

class ElectrumTimeAnchorSourceTest :
    FunSpec({
        test("finds a real P2WPKH-spending transaction built via bitcoin-kmp's own transaction API") {
            val pubkey = Secp256k1KeyPair.generate().publicKey
            val scriptHash = BitcoinAddressDerivation.electrumScriptHash(pubkey)
            val tx = buildSpendingTransaction(pubkey)
            val rawTxBytes = Transaction.write(tx)
            val txHash = ByteArray(32) { 0x11 } // arbitrary Electrum-protocol tx_hash key for the fake

            val rpc =
                FakeElectrumRpc(
                    historyByScriptHash = mapOf(scriptHash.toHex() to listOf(HistoryEntry(txHash, height = 500))),
                    rawTxByHash = mapOf(txHash.toHex() to rawTxBytes),
                )

            val result = anchorSource(rpc).findFirstOutgoingTransaction(pubkey)

            result.shouldBeInstanceOf<TimeAnchorLookupResult.Found>()
            val found = result as TimeAnchorLookupResult.Found
            found.genesisBlockHeight shouldBe 500
            found.genesisTxid.toHex() shouldBe
                tx.hash.value
                    .toByteArray()
                    .toHex()
        }

        test("multiple candidates - the earliest (lowest height) match wins") {
            val pubkey = Secp256k1KeyPair.generate().publicKey
            val scriptHash = BitcoinAddressDerivation.electrumScriptHash(pubkey)

            val earlierTx = buildSpendingTransaction(pubkey, seed = 1)
            val laterTx = buildSpendingTransaction(pubkey, seed = 2)
            val earlierHash = ByteArray(32) { 0x22 }
            val laterHash = ByteArray(32) { 0x33 }

            val rpc =
                FakeElectrumRpc(
                    historyByScriptHash =
                        mapOf(
                            scriptHash.toHex() to
                                listOf(
                                    // Deliberately listed out of ascending order - the source must
                                    // sort by height itself, not trust delivery order.
                                    HistoryEntry(laterHash, height = 900),
                                    HistoryEntry(earlierHash, height = 300),
                                ),
                        ),
                    rawTxByHash =
                        mapOf(
                            earlierHash.toHex() to Transaction.write(earlierTx),
                            laterHash.toHex() to Transaction.write(laterTx),
                        ),
                )

            val result = anchorSource(rpc).findFirstOutgoingTransaction(pubkey)

            result.shouldBeInstanceOf<TimeAnchorLookupResult.Found>()
            val found = result as TimeAnchorLookupResult.Found
            found.genesisBlockHeight shouldBe 300
            found.genesisTxid.toHex() shouldBe
                earlierTx.hash.value
                    .toByteArray()
                    .toHex()
        }

        test("no matching candidate yields NotFound") {
            val pubkey = Secp256k1KeyPair.generate().publicKey
            val scriptHash = BitcoinAddressDerivation.electrumScriptHash(pubkey)
            val unrelatedTx = buildUnrelatedTransaction(seed = 1)
            val txHash = ByteArray(32) { 0x44 }

            val rpc =
                FakeElectrumRpc(
                    historyByScriptHash = mapOf(scriptHash.toHex() to listOf(HistoryEntry(txHash, height = 200))),
                    rawTxByHash = mapOf(txHash.toHex() to Transaction.write(unrelatedTx)),
                )

            anchorSource(rpc).findFirstOutgoingTransaction(pubkey) shouldBe TimeAnchorLookupResult.NotFound
        }

        test("an empty history yields NotFound") {
            val pubkey = Secp256k1KeyPair.generate().publicKey
            val rpc = FakeElectrumRpc()

            anchorSource(rpc).findFirstOutgoingTransaction(pubkey) shouldBe TimeAnchorLookupResult.NotFound
        }

        test("unconfirmed (height <= 0) history entries are never treated as a genesis candidate") {
            val pubkey = Secp256k1KeyPair.generate().publicKey
            val scriptHash = BitcoinAddressDerivation.electrumScriptHash(pubkey)
            val tx = buildSpendingTransaction(pubkey)
            val txHash = ByteArray(32) { 0x55 }

            val rpc =
                FakeElectrumRpc(
                    historyByScriptHash =
                        mapOf(
                            scriptHash.toHex() to
                                listOf(HistoryEntry(txHash, height = 0), HistoryEntry(txHash, height = -1)),
                        ),
                    rawTxByHash = mapOf(txHash.toHex() to Transaction.write(tx)),
                )

            anchorSource(rpc).findFirstOutgoingTransaction(pubkey) shouldBe TimeAnchorLookupResult.NotFound
        }

        test("a simulated RPC failure yields LookupFailed - never silently NotFound") {
            val pubkey = Secp256k1KeyPair.generate().publicKey
            val rpc = FakeElectrumRpc(failHistory = true)

            val result = anchorSource(rpc).findFirstOutgoingTransaction(pubkey)

            result.shouldBeInstanceOf<TimeAnchorLookupResult.LookupFailed>()
        }

        test("a simulated raw-transaction-fetch failure yields LookupFailed") {
            val pubkey = Secp256k1KeyPair.generate().publicKey
            val scriptHash = BitcoinAddressDerivation.electrumScriptHash(pubkey)
            val txHash = ByteArray(32) { 0x66 }

            val rpc =
                FakeElectrumRpc(
                    historyByScriptHash = mapOf(scriptHash.toHex() to listOf(HistoryEntry(txHash, height = 100))),
                    failRawTx = true,
                )

            val result = anchorSource(rpc).findFirstOutgoingTransaction(pubkey)

            result.shouldBeInstanceOf<TimeAnchorLookupResult.LookupFailed>()
        }

        test("history longer than maxHistoryEntriesScanned is capped - a match beyond the cap is not found") {
            val pubkey = Secp256k1KeyPair.generate().publicKey
            val scriptHash = BitcoinAddressDerivation.electrumScriptHash(pubkey)
            val cap = 3

            // cap+1 unrelated entries at the earliest heights, then the real match at a later
            // height - the cap must exclude it.
            val unrelatedEntries =
                (1..cap).map { i ->
                    val tx = buildUnrelatedTransaction(seed = i.toByte())
                    val hash = ByteArray(32) { i.toByte() }
                    hash to Transaction.write(tx) to i
                }
            val matchTx = buildSpendingTransaction(pubkey, seed = 99)
            val matchHash = ByteArray(32) { 0x77 }

            val history =
                unrelatedEntries.map { (pair, height) -> HistoryEntry(pair.first, height) } +
                    HistoryEntry(matchHash, height = cap + 1)
            val rawTxByHash =
                unrelatedEntries.associate { (pair, _) -> pair.first.toHex() to pair.second } +
                    mapOf(matchHash.toHex() to Transaction.write(matchTx))

            val rpc =
                FakeElectrumRpc(
                    historyByScriptHash = mapOf(scriptHash.toHex() to history),
                    rawTxByHash = rawTxByHash,
                )
            val source =
                ElectrumTimeAnchorSource(emptyList(), rpc, Duration.ofSeconds(1), maxHistoryEntriesScanned = cap)

            source.findFirstOutgoingTransaction(pubkey) shouldBe TimeAnchorLookupResult.NotFound
        }

        test("history within maxHistoryEntriesScanned still finds the match") {
            val pubkey = Secp256k1KeyPair.generate().publicKey
            val scriptHash = BitcoinAddressDerivation.electrumScriptHash(pubkey)
            val tx = buildSpendingTransaction(pubkey, seed = 42)
            val txHash = ByteArray(32) { 0x88.toByte() }

            val rpc =
                FakeElectrumRpc(
                    historyByScriptHash = mapOf(scriptHash.toHex() to listOf(HistoryEntry(txHash, height = 1))),
                    rawTxByHash = mapOf(txHash.toHex() to Transaction.write(tx)),
                )
            val source = ElectrumTimeAnchorSource(emptyList(), rpc, Duration.ofSeconds(1), maxHistoryEntriesScanned = 3)

            val result = source.findFirstOutgoingTransaction(pubkey)

            result.shouldBeInstanceOf<TimeAnchorLookupResult.Found>()
        }

        test("currentChainTipHeight delegates to the rpc and returns its value") {
            val rpc = FakeElectrumRpc(tip = 123_456)

            anchorSource(rpc).currentChainTipHeight() shouldBe 123_456
        }

        test("currentChainTipHeight throws (never returns a placeholder) when the rpc fails") {
            val failingRpc =
                object : ElectrumRpc {
                    override fun scriptHashHistory(scriptHash: ByteArray) = emptyList<HistoryEntry>()

                    override fun rawTransaction(txHash: ByteArray) = ByteArray(0)

                    override fun tipHeight(): Int = throw ElectrumRpcException("simulated failure")
                }

            shouldThrow<ElectrumRpcException> { anchorSource(failingRpc).currentChainTipHeight() }
        }

        test("currentChainTipHeight's thrown exception never carries the rpc's raw message") {
            // A raw ElectrumRpcException.message can embed a compromised/misbehaving Electrum
            // server's own response text (see RealElectrumRpc.tipHeight's "... response missing
            // height: $response" message) - that text must never reach a caller, let alone
            // KarmaAnchorCache.currentClaimFor's KarmaAnchorResolutionException and, from there,
            // POST /api/karma's HTTP response body. Mirrors findFirstOutgoingTransaction's
            // identical sanitization for the genesis-lookup path.
            val secretLookingServerText = "attacker-controlled-response-fragment-should-never-leak"
            val failingRpc =
                object : ElectrumRpc {
                    override fun scriptHashHistory(scriptHash: ByteArray) = emptyList<HistoryEntry>()

                    override fun rawTransaction(txHash: ByteArray) = ByteArray(0)

                    override fun tipHeight(): Int = throw ElectrumRpcException(secretLookingServerText)
                }

            val thrown = shouldThrow<ElectrumRpcException> { anchorSource(failingRpc).currentChainTipHeight() }

            thrown.message shouldNotContain secretLookingServerText
        }

        test("RealElectrumRpc against an empty server list throws only when actually used, not on construction") {
            // Constructing must not throw or attempt any connection - see RealElectrumRpc's doc
            // comment on lazy connection. Only an actual call touches the network (or, here, fails
            // immediately because there is nothing configured to connect to).
            val rpc = RealElectrumRpc(emptyList())

            shouldThrow<ElectrumRpcException> { rpc.scriptHashHistory(ByteArray(32)) }
        }

        test("ElectrumTimeAnchorSource's public no-arg constructor with PLACEHOLDER servers never throws by itself") {
            // Mirrors the previous test one layer up - BrowserServer.start() constructs this
            // unconditionally on every start, so it must never throw or block just by existing.
            ElectrumTimeAnchorSource()
        }

        test("using ElectrumServers.PLACEHOLDER end-to-end yields LookupFailed, never a silent NotFound") {
            val pubkey = Secp256k1KeyPair.generate().publicKey
            val source = ElectrumTimeAnchorSource(servers = ElectrumServers.PLACEHOLDER)

            val result = source.findFirstOutgoingTransaction(pubkey)

            result.shouldBeInstanceOf<TimeAnchorLookupResult.LookupFailed>()
        }
    })
