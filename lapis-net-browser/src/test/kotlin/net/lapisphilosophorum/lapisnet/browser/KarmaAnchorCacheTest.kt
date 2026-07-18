package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.ChainAnchorClaim
import net.lapisphilosophorum.lapisnet.karma.NoAnchorClaim
import net.lapisphilosophorum.lapisnet.karma.TimeAnchorLookupResult
import java.util.concurrent.atomic.AtomicInteger

/**
 * A [BitcoinTimeAnchorSource] test double that counts invocations and returns a configurable,
 * swappable outcome for each of the two lookup methods - zero real network I/O, mirroring
 * `BrowserApiRoutingTest`'s `NoAnchorSource`/`FailingAnchorSource` fakes in this same module (this
 * one is reusable across tests because its programmed outcomes are mutable, unlike those two fixed
 * `object`s).
 */
private class CountingAnchorSource(
    private var findResult: TimeAnchorLookupResult = TimeAnchorLookupResult.NotFound,
    private var tipHeight: Int = 1_000,
) : BitcoinTimeAnchorSource {
    val findCallCount = AtomicInteger(0)
    val tipCallCount = AtomicInteger(0)

    fun setFindResult(result: TimeAnchorLookupResult) {
        findResult = result
    }

    fun setTipHeight(height: Int) {
        tipHeight = height
    }

    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult {
        findCallCount.incrementAndGet()
        return findResult
    }

    override fun currentChainTipHeight(): Int {
        tipCallCount.incrementAndGet()
        return tipHeight
    }
}

private fun testGenesis(seed: Byte = 1): ByteArray = ByteArray(32) { seed }

class KarmaAnchorCacheTest :
    FunSpec({
        test("a Found result is cached - a second call for the same identity does not re-invoke the source") {
            val identity = Secp256k1KeyPair.generate()
            val source =
                CountingAnchorSource(
                    findResult = TimeAnchorLookupResult.Found(genesisBlockHeight = 100, genesisTxid = testGenesis()),
                    tipHeight = 500,
                )
            val cache = KarmaAnchorCache(source)

            val first = cache.currentClaimFor(identity)
            val second = cache.currentClaimFor(identity)

            first.shouldBeInstanceOf<ChainAnchorClaim>()
            second.shouldBeInstanceOf<ChainAnchorClaim>()
            first shouldBe second
            source.findCallCount.get() shouldBe 1 // only the FIRST call actually looked up the genesis
        }

        test("Tip height is queried fresh on every call even when genesis is cached") {
            val identity = Secp256k1KeyPair.generate()
            val source =
                CountingAnchorSource(
                    findResult = TimeAnchorLookupResult.Found(genesisBlockHeight = 100, genesisTxid = testGenesis()),
                    tipHeight = 500,
                )
            val cache = KarmaAnchorCache(source)

            cache.currentClaimFor(identity)
            cache.currentClaimFor(identity)
            cache.currentClaimFor(identity)

            source.tipCallCount.get() shouldBe 3
            source.findCallCount.get() shouldBe 1
        }

        test("a NotFound result resolves to NoAnchorClaim and is cached within the TTL") {
            val identity = Secp256k1KeyPair.generate()
            val source = CountingAnchorSource(findResult = TimeAnchorLookupResult.NotFound)
            val cache = KarmaAnchorCache(source)
            val now = 1_700_000_000L

            val first = cache.currentClaimFor(identity, nowEpochSeconds = now)
            val second =
                cache.currentClaimFor(
                    identity,
                    nowEpochSeconds = now + KarmaAnchorCache.NOT_FOUND_TTL_SECONDS - 1,
                )

            first shouldBe NoAnchorClaim
            second shouldBe NoAnchorClaim
            source.findCallCount.get() shouldBe 1 // second call was served from the still-fresh cache
            source.tipCallCount.get() shouldBe 0 // NoAnchorClaim never needs a tip height query
        }

        test("a NotFound result re-queries after the TTL expires") {
            val identity = Secp256k1KeyPair.generate()
            val source = CountingAnchorSource(findResult = TimeAnchorLookupResult.NotFound)
            val cache = KarmaAnchorCache(source)
            val now = 1_700_000_000L

            cache.currentClaimFor(identity, nowEpochSeconds = now) shouldBe NoAnchorClaim
            cache.currentClaimFor(
                identity,
                nowEpochSeconds = now + KarmaAnchorCache.NOT_FOUND_TTL_SECONDS,
            ) shouldBe NoAnchorClaim

            source.findCallCount.get() shouldBe 2 // the TTL had expired - the second call re-queried
        }

        test("an expired NotFound cache entry can transition to Found on the very next lookup") {
            val identity = Secp256k1KeyPair.generate()
            val source = CountingAnchorSource(findResult = TimeAnchorLookupResult.NotFound, tipHeight = 500)
            val cache = KarmaAnchorCache(source)
            val now = 1_700_000_000L

            cache.currentClaimFor(identity, nowEpochSeconds = now) shouldBe NoAnchorClaim

            source.setFindResult(TimeAnchorLookupResult.Found(genesisBlockHeight = 100, genesisTxid = testGenesis()))
            val claim =
                cache.currentClaimFor(identity, nowEpochSeconds = now + KarmaAnchorCache.NOT_FOUND_TTL_SECONDS)

            claim.shouldBeInstanceOf<ChainAnchorClaim>()
            source.findCallCount.get() shouldBe 2
        }

        test("a LookupFailed result throws KarmaAnchorResolutionException, never silently coerced to NoAnchorClaim") {
            val identity = Secp256k1KeyPair.generate()
            val source =
                CountingAnchorSource(findResult = TimeAnchorLookupResult.LookupFailed("simulated Electrum failure"))
            val cache = KarmaAnchorCache(source)

            shouldThrow<KarmaAnchorResolutionException> { cache.currentClaimFor(identity) }
        }

        test("a LookupFailed result is never cached - the very next call retries the lookup") {
            val identity = Secp256k1KeyPair.generate()
            val source =
                CountingAnchorSource(findResult = TimeAnchorLookupResult.LookupFailed("simulated Electrum failure"))
            val cache = KarmaAnchorCache(source)

            shouldThrow<KarmaAnchorResolutionException> { cache.currentClaimFor(identity) }
            shouldThrow<KarmaAnchorResolutionException> { cache.currentClaimFor(identity) }

            source.findCallCount.get() shouldBe 2
        }

        test("a failing tip-height query throws KarmaAnchorResolutionException") {
            val identity = Secp256k1KeyPair.generate()
            val source =
                object : BitcoinTimeAnchorSource {
                    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
                        TimeAnchorLookupResult.Found(genesisBlockHeight = 100, genesisTxid = testGenesis())

                    override fun currentChainTipHeight(): Int =
                        throw IllegalStateException("simulated Electrum failure")
                }
            val cache = KarmaAnchorCache(source)

            shouldThrow<KarmaAnchorResolutionException> { cache.currentClaimFor(identity) }
        }

        test("a stale cached genesis inconsistent with a fresh tip height throws") {
            val identity = Secp256k1KeyPair.generate()
            val source =
                CountingAnchorSource(
                    findResult = TimeAnchorLookupResult.Found(genesisBlockHeight = 900, genesisTxid = testGenesis()),
                    tipHeight = 1_000,
                )
            val cache = KarmaAnchorCache(source)

            // First call: genesis(900) <= tip(1000) - consistent, resolves fine and caches the genesis.
            cache.currentClaimFor(identity).shouldBeInstanceOf<ChainAnchorClaim>()

            // Second call: the cached genesis (900) is now ABOVE a freshly-queried tip (500) - e.g. a
            // reorg, or this call reaching a different/lagging Electrum server than the original
            // lookup did. ChainAnchorClaim's own init block rejects that as structurally inconsistent.
            source.setTipHeight(500)

            shouldThrow<KarmaAnchorResolutionException> { cache.currentClaimFor(identity) }
            source.findCallCount.get() shouldBe 1 // the genesis stayed cached - only the tip query re-ran
        }
    })
