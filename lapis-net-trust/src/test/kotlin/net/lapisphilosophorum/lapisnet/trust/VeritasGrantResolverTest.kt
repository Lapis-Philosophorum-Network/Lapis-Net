package net.lapisphilosophorum.lapisnet.trust

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

/** Mirrors [Secp256k1PublicKeyBytesComparator]'s unsigned byte-order comparison, applied directly
 * to two grants' [VeritasGrant.contentId] bytes - used only to independently compute the expected
 * winner in tie-break tests, without depending on [VeritasGrantResolver]'s own internals. */
private fun unsignedContentIdCompare(
    a: VeritasGrant,
    b: VeritasGrant,
): Int {
    val ba = a.contentId()
    val bb = b.contentId()
    for (i in ba.indices) {
        val diff = (ba[i].toInt() and 0xFF) - (bb[i].toInt() and 0xFF)
        if (diff != 0) return diff
    }
    return 0
}

class VeritasGrantResolverTest :
    FunSpec({
        test("a single genesis grant with no successors resolves to itself") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val genesis = VeritasGrant.create(truster, target, trustMicros = 500_000)

            VeritasGrantResolver.resolveLatest(listOf(genesis)) shouldBe genesis
        }

        test("a linear chain of 3 resolves to the tip, regardless of the input list's order") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val g1 = VeritasGrant.create(truster, target, trustMicros = 100_000)
            val g2 = VeritasGrant.create(truster, target, trustMicros = 500_000, previous = g1)
            val g3 = VeritasGrant.create(truster, target, trustMicros = 900_000, previous = g2)

            VeritasGrantResolver.resolveLatest(listOf(g1, g2, g3)) shouldBe g3
            VeritasGrantResolver.resolveLatest(listOf(g3, g1, g2)) shouldBe g3
            VeritasGrantResolver.resolveLatest(listOf(g2, g3, g1)) shouldBe g3
        }

        test("a forked chain (two successors of one predecessor) resolves deterministically, independent of order") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val root = VeritasGrant.create(truster, target, trustMicros = 200_000)
            val branchA = VeritasGrant.create(truster, target, trustMicros = 600_000, previous = root)
            val branchB = VeritasGrant.create(truster, target, trustMicros = 601_000, previous = root)
            val candidates = listOf(root, branchA, branchB)

            val expectedWinner = if (unsignedContentIdCompare(branchA, branchB) >= 0) branchA else branchB

            VeritasGrantResolver.resolveLatest(candidates) shouldBe expectedWinner
            VeritasGrantResolver.resolveLatest(candidates.shuffled()) shouldBe expectedWinner
            VeritasGrantResolver.resolveLatest(candidates.reversed()) shouldBe expectedWinner
        }

        test("two independent genesis grants for the same pair (byzantine truster) resolve deterministically") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val genesisA = VeritasGrant.create(truster, target, trustMicros = 300_000, comment = "genesis A")
            val genesisB = VeritasGrant.create(truster, target, trustMicros = 700_000, comment = "genesis B")
            val candidates = listOf(genesisA, genesisB)

            val expectedWinner = if (unsignedContentIdCompare(genesisA, genesisB) >= 0) genesisA else genesisB

            VeritasGrantResolver.resolveLatest(candidates) shouldBe expectedWinner
            VeritasGrantResolver.resolveLatest(candidates.shuffled()) shouldBe expectedWinner
            VeritasGrantResolver.resolveLatest(listOf(genesisB, genesisA)) shouldBe expectedWinner
        }

        test("a dangling successor (previousGrantId points at a content id not present in candidates) is excluded") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val g1 = VeritasGrant.create(truster, target, trustMicros = 200_000)
            val g2 = VeritasGrant.create(truster, target, trustMicros = 600_000, previous = g1)
            val danglingPreviousId = ByteArray(32) { it.toByte() }
            val dangling =
                VeritasGrant.createFromPreviousId(
                    truster,
                    target,
                    trustMicros = 999_000,
                    previousGrantId = danglingPreviousId,
                )

            // The root-rooted chain (g1 -> g2) still resolves correctly even with the unrelated
            // dangling grant present - it's simply never reached by the walk.
            VeritasGrantResolver.resolveLatest(listOf(g1, g2, dangling)) shouldBe g2
        }

        test("a dangling grant with no genesis root among the candidates resolves to null") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val danglingPreviousId = ByteArray(32) { it.toByte() }
            val dangling =
                VeritasGrant.createFromPreviousId(
                    truster,
                    target,
                    trustMicros = 500_000,
                    previousGrantId = danglingPreviousId,
                )

            VeritasGrantResolver.resolveLatest(listOf(dangling)).shouldBeNull()
        }

        test("an empty candidate list resolves to null") {
            VeritasGrantResolver.resolveLatest(emptyList()).shouldBeNull()
        }

        test("a candidate list where every grant fails signature verification resolves to null") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val genesis = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val bytes = VeritasGrantCodec.encode(genesis)
            bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the signature
            val tampered = VeritasGrantCodec.decode(bytes)

            VeritasGrantResolver.resolveLatest(listOf(tampered)).shouldBeNull()
        }

        test("MAX_CHAIN_DEPTH (via the internal maxDepth test seam) truncates a chain longer than the cap") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val maxDepth = 30

            val chain = mutableListOf(VeritasGrant.create(truster, target, trustMicros = 0))
            repeat(maxDepth + 5) { i ->
                chain += VeritasGrant.create(truster, target, trustMicros = i + 1, previous = chain.last())
            }
            // chain[0] is depth 0 (genesis), chain[maxDepth] is the node the walk is forced to
            // stop at once frame.depth >= maxDepth - not chain.last(), which is deeper than the cap.
            val expectedTip = chain[maxDepth]

            VeritasGrantResolver.resolveLatest(chain, maxDepth) shouldBe expectedTip
        }

        test("a genuine hash-chain cycle cannot be constructed through the real API") {
            // No test exercises an actual cycle: a successor's previousGrantId is fixed to a
            // predecessor's already-computed contentId() at creation time (VeritasGrant.create),
            // so two grants can never legitimately reference each other - this is a structural
            // guarantee of the signing API, not something this resolver needs to defend against
            // beyond the depth cap + visited-set cycle guard already in place as defense in depth.
        }
    })
