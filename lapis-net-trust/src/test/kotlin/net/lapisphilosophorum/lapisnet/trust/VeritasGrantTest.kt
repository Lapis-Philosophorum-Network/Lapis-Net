package net.lapisphilosophorum.lapisnet.trust

import io.ipfs.cid.Cid
import io.ipfs.multihash.Multihash
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testCid(seed: Byte): Cid = Cid.buildCidV1(Cid.Codec.Raw, Multihash.Type.sha2_256, ByteArray(32) { seed })

private fun tamperedCopy(
    grant: VeritasGrant,
    mutate: (ByteArray) -> Unit,
): VeritasGrant {
    val bytes = VeritasGrantCodec.encode(grant)
    mutate(bytes)
    return VeritasGrantCodec.decode(bytes)
}

class VeritasGrantTest :
    FunSpec({
        test("create then verify round-trips for a genesis grant") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 800_000, comment = "trusted colleague")

            VeritasGrant.verify(grant) shouldBe true
            grant.isGenesis shouldBe true
            grant.previousGrantId.shouldBeNull()
        }

        test("create with a predecessor links into the version chain and verifies") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val first = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val second = VeritasGrant.create(truster, target, trustMicros = 900_000, previous = first)

            VeritasGrant.verify(second) shouldBe true
            second.isGenesis shouldBe false
            second.linksTo(first) shouldBe true
        }

        test("verify(expectedTruster, grant) is true for the real truster and false for a different one") {
            val truster = Secp256k1KeyPair.generate()
            val other = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = MAX_TRUST_MICROS)

            VeritasGrant.verify(truster.publicKey, grant) shouldBe true
            VeritasGrant.verify(other.publicKey, grant) shouldBe false
        }

        test("tampering the target breaks verification") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)

            // Byte 0 of target's compressed key is the parity prefix (0x02/0x03). Incrementing it
            // by 1 lands on a *different* valid prefix about half the time (0x02<->0x03, the same
            // X coordinate's other Y root - still a valid curve point, just a different target key,
            // so decode() succeeds and verify() must catch the now-mismatched signature), and on an
            // invalid prefix (e.g. 0x04) the other half - which VeritasGrantCodec.decode() must
            // reject outright (curve-point validation, see Secp256k1PublicKey's constructor) rather
            // than silently accept. Both outcomes are "tampering was caught"; assert either one
            // instead of assuming a specific branch, since which one occurs depends on the randomly
            // generated key's own parity.
            val result =
                runCatching {
                    tamperedCopy(grant) { bytes ->
                        // target starts right after magic(4) + version(1) + flags(1) + truster(33)
                        bytes[4 + 1 + 1 + 33] = (bytes[4 + 1 + 1 + 33] + 1).toByte()
                    }
                }
            val tampered = result.getOrNull()
            if (tampered != null) {
                VeritasGrant.verify(tampered) shouldBe false
            } else {
                result.exceptionOrNull().shouldBeInstanceOf<MalformedVeritasGrantException>()
            }
        }

        test("tampering trustMicros breaks verification") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)

            val tampered =
                tamperedCopy(grant) { bytes ->
                    // trustMicros starts after magic(4)+version(1)+flags(1)+truster(33)+target(33)
                    val offset = 4 + 1 + 1 + 33 + 33
                    bytes[offset + 3] = (bytes[offset + 3] + 1).toByte()
                }
            VeritasGrant.verify(tampered) shouldBe false
        }

        test("tampering the backward-hash link breaks verification") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val first = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val second = VeritasGrant.create(truster, target, trustMicros = 900_000, previous = first)

            val tampered =
                tamperedCopy(second) { bytes ->
                    // previousGrantId starts after magic(4)+version(1)+flags(1)+truster(33)+target(33)+trustMicros(4)
                    val offset = 4 + 1 + 1 + 33 + 33 + 4
                    bytes[offset] = (bytes[offset] + 1).toByte()
                }
            VeritasGrant.verify(tampered) shouldBe false
            tampered.linksTo(first) shouldBe false
        }

        test("tampering the signature breaks verification") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000)

            val tampered =
                tamperedCopy(grant) { bytes ->
                    bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte()
                }
            VeritasGrant.verify(tampered) shouldBe false
        }

        test("tampering the comment breaks verification") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant = VeritasGrant.create(truster, target, trustMicros = 500_000, comment = "original")

            val tampered =
                tamperedCopy(grant) { bytes ->
                    val offset = 4 + 1 + 1 + 33 + 33 + 4 + 2 // start of comment bytes (genesis, no previous)
                    bytes[offset] = (bytes[offset] + 1).toByte()
                }
            VeritasGrant.verify(tampered) shouldBe false
        }

        test("tampering an occasion reference breaks verification") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val grant =
                VeritasGrant.create(
                    truster,
                    target,
                    trustMicros = 500_000,
                    occasionReferences = listOf(testCid(1)),
                )

            val tampered =
                tamperedCopy(grant) { bytes ->
                    // just before the 64-byte trailing signature, inside the occasion CID bytes
                    bytes[bytes.size - 1 - 64] = (bytes[bytes.size - 1 - 64] + 1).toByte()
                }
            VeritasGrant.verify(tampered) shouldBe false
        }

        test("boundary trust values 0 and 1_000_000 both create and verify") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey

            val distrust = VeritasGrant.create(truster, target, trustMicros = MIN_TRUST_MICROS)
            val selfTrust = VeritasGrant.create(truster, target, trustMicros = MAX_TRUST_MICROS)

            VeritasGrant.verify(distrust) shouldBe true
            VeritasGrant.verify(selfTrust) shouldBe true
            distrust.trustFraction shouldBe 0.0
            selfTrust.trustFraction shouldBe 1.0
        }

        test("trustMicros outside 0..1_000_000 is rejected") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey

            shouldThrowIllegalArgument { VeritasGrant.create(truster, target, trustMicros = -1) }
            shouldThrowIllegalArgument { VeritasGrant.create(truster, target, trustMicros = MAX_TRUST_MICROS + 1) }
        }

        test("a genesis grant never linksTo anything") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val genesis = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val other = VeritasGrant.create(truster, target, trustMicros = 100_000)

            genesis.linksTo(other) shouldBe false
        }

        test("equals/hashCode are consistent for grants built from identical inputs") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val a = VeritasGrant.createFromPreviousId(truster, target, 500_000, "x", emptyList(), null)
            val b = VeritasGrant.createFromPreviousId(truster, target, 500_000, "x", emptyList(), null)

            // ECDSA signing in this project is deterministic (RFC6979 + low-S normalization), so
            // identical inputs produce identical signatures and thus equal grants.
            a shouldBe b
            a.hashCode() shouldBe b.hashCode()
        }

        test("domain separation: a Veritas grant digest differs from an identity-binding digest over the same body") {
            val body = ByteArray(16) { it.toByte() }
            val veritasDigest = domainSeparatedDigest("LapisNet:veritas-trust-edge:v1", body)
            val identityDigest = domainSeparatedDigest("LapisNet:identity-binding:v1", body)
            (veritasDigest.contentEquals(identityDigest)) shouldBe false
        }

        test("returned mutable byte arrays are copies, not live references to internal state") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val previous = VeritasGrant.create(truster, target, trustMicros = 500_000)
            val grant = VeritasGrant.create(truster, target, trustMicros = 900_000, previous = previous)

            val originalSignature = grant.signature.copyOf()
            grant.signature.also { it[0] = (it[0] + 1).toByte() } // mutate the returned copy
            grant.signature.contentEquals(originalSignature) shouldBe true
            VeritasGrant.verify(grant) shouldBe true

            val originalPreviousId = grant.previousGrantId!!.copyOf()
            grant.previousGrantId!!.also { it[0] = (it[0] + 1).toByte() } // mutate the returned copy
            grant.previousGrantId!!.contentEquals(originalPreviousId) shouldBe true
            grant.linksTo(previous) shouldBe true
        }
    })

private fun shouldThrowIllegalArgument(block: () -> Unit) {
    io.kotest.assertions.throwables
        .shouldThrow<IllegalArgumentException> { block() }
}
