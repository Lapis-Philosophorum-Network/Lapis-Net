package net.lapisphilosophorum.lapisnet.browser

import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.ChainAnchorClaim
import net.lapisphilosophorum.lapisnet.karma.NoAnchorClaim
import net.lapisphilosophorum.lapisnet.karma.TimeAnchorClaim
import net.lapisphilosophorum.lapisnet.karma.TimeAnchorLookupResult
import java.util.concurrent.ConcurrentHashMap

/** Thrown by [KarmaAnchorCache.currentClaimFor] on any failure to resolve a trustworthy
 * [TimeAnchorClaim] - a real [TimeAnchorLookupResult.LookupFailed], a chain-tip query failure, or
 * an inconsistent tip/genesis pair (e.g. a stale cached genesis height ending up above a freshly
 * queried tip height, possible if different calls reach different/reorg'd Electrum servers). Never
 * thrown for the genuine "no anchor" case - see [currentClaimFor]'s doc comment. Callers (see
 * `BrowserApi`'s `POST /api/karma` handler) must catch this and return a clean error response,
 * never let it crash the request. */
class KarmaAnchorResolutionException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * In-memory-only cache of this node's OWN resolved [TimeAnchorClaim], populated by real,
 * client-side [BitcoinTimeAnchorSource] lookups the first time this identity casts a Karma vote.
 * Restart loses it - the same accepted-limitation shape as every other index in this codebase that
 * does not rebuild from durable storage at startup (see e.g.
 * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex]/[net.lapisphilosophorum.lapisnet.karma.KarmaVoteIndex]'s
 * identical in-memory-only nature).
 *
 * **Caches BOTH outcomes of a genesis lookup, with two different lifetimes - not just [Found].**
 * A found genesis transaction is a fixed historical fact: caching it forever (until process
 * restart) is correct, not merely an optimization, since it will never change. A [NotFound] result
 * is only ever a point-in-time fact, though - the same identity could make its first-ever outgoing
 * Bitcoin transaction moments later - so it is cached only for [NOT_FOUND_TTL_SECONDS], a short,
 * bounded window. Without caching [NotFound] AT ALL (the original gap this doc comment used to
 * describe), every single vote cast by an as-yet-unanchored identity would re-trigger a full
 * Electrum scan (up to `maxHistoryEntriesScanned` round-trips - see [BitcoinTimeAnchorSource]) on
 * every call, which is exactly the "wasteful and slow" cost this cache exists to avoid - and, for a
 * burst of votes cast in quick succession by the same unanchored identity, a real DoS-adjacent
 * amplification of outbound Electrum traffic. The bounded TTL (rather than caching [NotFound]
 * forever, the way [Found] is) keeps that fixed while still not permanently locking an identity out
 * of Karma the moment after their first real Bitcoin transaction confirms.
 *
 * **[tipHeightAtVote] is always freshly queried, never cached** - unlike the genesis transaction
 * itself, the chain tip changes roughly every 10 minutes and MUST be current at the moment of each
 * vote for `t` to be meaningful. This holds regardless of which genesis outcome (cached [Found],
 * fresh [Found], or a still-fresh cached [NotFound]) applies.
 *
 * **Keyed by [Secp256k1PublicKey] directly, backed by a [ConcurrentHashMap]** - not a truncated
 * fingerprint string keying a plain, unsynchronized `HashMap`, which this class used to do. This
 * class is called from concurrently-dispatched Ktor request threads (one per in-flight
 * `POST /api/karma`), so an unsynchronized map is a real data race, not a theoretical one.
 * [Secp256k1PublicKey] already has full-content `equals`/`hashCode` (see that class), so keying
 * directly by it - rather than by a lossy, truncated string fingerprint of it - is both simpler and
 * safer: two different public keys can never collide onto the same cache slot the way two
 * fingerprints in principle could. Mirrors
 * [net.lapisphilosophorum.lapisnet.karma.KarmaVoteIndex.votesByVoterMap]'s established
 * key-by-[Secp256k1PublicKey]-directly convention in this same wave.
 */
class KarmaAnchorCache(
    private val source: BitcoinTimeAnchorSource,
) {
    /** One resolved genesis-lookup outcome, cached per [Secp256k1PublicKey] - see this class's doc
     * comment on the two different cache lifetimes these two variants get. */
    private sealed class GenesisCacheEntry {
        /** A real, confirmed genesis transaction - cached forever (until process restart), never
         * expires. */
        data class Found(
            val genesisBlockHeight: Int,
            val genesisTxid: ByteArray,
        ) : GenesisCacheEntry()

        /** A real, confirmed "no recognized outgoing transaction yet" - cached only until
         * [cachedAtEpochSeconds] + [NOT_FOUND_TTL_SECONDS], see this class's doc comment. */
        data class NotFoundUntil(
            val cachedAtEpochSeconds: Long,
        ) : GenesisCacheEntry()
    }

    private val cachedGenesis = ConcurrentHashMap<Secp256k1PublicKey, GenesisCacheEntry>()

    /**
     * Resolves [identity]'s current [TimeAnchorClaim]: a cached (or freshly-resolved) genesis
     * lookup combined with a freshly-queried chain tip.
     *
     * [nowEpochSeconds] defaults to the real current time - callers (namely tests) can override it
     * to deterministically exercise [NOT_FOUND_TTL_SECONDS] expiry without a real `sleep()`,
     * mirroring [net.lapisphilosophorum.lapisnet.virtus.LtrWeightCalculator]'s established
     * caller-supplied-"now" convention for this same reason.
     *
     * - [TimeAnchorLookupResult.NotFound] (a real, confirmed "no recognized outgoing transaction")
     *   resolves to [NoAnchorClaim] - the correct, non-error outcome, per that object's doc comment.
     *   This outcome itself gets cached (see this class's doc comment) - a subsequent call within
     *   [NOT_FOUND_TTL_SECONDS] resolves to [NoAnchorClaim] again without a fresh lookup.
     * - [TimeAnchorLookupResult.LookupFailed] (a genuine failure to get a trustworthy answer) is
     *   **NEVER silently coerced to [NoAnchorClaim]** - it THROWS instead, mirroring
     *   [TimeAnchorLookupResult]'s own doc comment's caller contract exactly. A transient Electrum
     *   outage must not quietly zero out a real voter's Karma anchor. Never cached either way - a
     *   failure is deliberately retried on the very next call, not remembered.
     *
     * @throws KarmaAnchorResolutionException if resolving the genesis transaction or the current
     * chain tip fails - callers (see `BrowserApi`'s `POST /api/karma` handler) must catch this and
     * return a clean error response, never let it crash the request.
     */
    fun currentClaimFor(
        identity: Secp256k1KeyPair,
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000,
    ): TimeAnchorClaim {
        val pubkey = identity.publicKey
        val cached = cachedGenesis[pubkey]
        val usableCached =
            when (cached) {
                is GenesisCacheEntry.Found -> cached
                is GenesisCacheEntry.NotFoundUntil ->
                    if (nowEpochSeconds - cached.cachedAtEpochSeconds < NOT_FOUND_TTL_SECONDS) cached else null
                null -> null
            }

        // Every branch below either yields a GenesisCacheEntry.Found or returns/throws directly
        // (Kotlin types `return`/`throw` as `Nothing`, a subtype of everything) - so `found` below
        // is never actually null; no NoAnchorClaim/exception path falls through to after this.
        val found: GenesisCacheEntry.Found =
            when (usableCached) {
                is GenesisCacheEntry.Found -> usableCached
                is GenesisCacheEntry.NotFoundUntil -> return NoAnchorClaim
                null ->
                    when (val result = source.findFirstOutgoingTransaction(pubkey)) {
                        is TimeAnchorLookupResult.Found -> {
                            val entry = GenesisCacheEntry.Found(result.genesisBlockHeight, result.genesisTxid)
                            cachedGenesis[pubkey] = entry
                            entry
                        }
                        is TimeAnchorLookupResult.NotFound -> {
                            cachedGenesis[pubkey] = GenesisCacheEntry.NotFoundUntil(nowEpochSeconds)
                            return NoAnchorClaim
                        }
                        is TimeAnchorLookupResult.LookupFailed ->
                            throw KarmaAnchorResolutionException(
                                "failed to resolve Bitcoin time anchor for ${pubkey.fingerprint()}: ${result.reason}",
                            )
                    }
            }

        val tipHeight =
            try {
                source.currentChainTipHeight()
            } catch (e: RuntimeException) {
                throw KarmaAnchorResolutionException(
                    "failed to resolve current Bitcoin chain tip height for a Karma vote: ${e.message}",
                    e,
                )
            }
        return try {
            ChainAnchorClaim(found.genesisBlockHeight, found.genesisTxid, tipHeightAtVote = tipHeight)
        } catch (e: IllegalArgumentException) {
            // Structurally inconsistent tip/genesis pair - e.g. a stale cached genesis height
            // ending up above a freshly queried tip height, possible if this call and the original
            // genesis lookup reached different (or reorg'd) Electrum servers. A real, if rare,
            // failure mode - never silently coerced to NoAnchorClaim, same discipline as every
            // other failure path in this function.
            throw KarmaAnchorResolutionException(
                "inconsistent chain anchor for ${pubkey.fingerprint()}: genesisBlockHeight=" +
                    "${found.genesisBlockHeight}, tipHeightAtVote=$tipHeight",
                e,
            )
        }
    }

    companion object {
        /** How long a [TimeAnchorLookupResult.NotFound] outcome stays cached - see this class's doc
         * comment for why this is bounded rather than either "never cached" (the original gap) or
         * "cached forever" (which would permanently lock an identity out of Karma the moment after
         * their first real Bitcoin transaction confirms). A few minutes is enough to absorb a burst
         * of votes cast in quick succession by the same unanchored identity without meaningfully
         * delaying recognition of a genuinely new anchor. */
        const val NOT_FOUND_TTL_SECONDS = 300L
    }
}
