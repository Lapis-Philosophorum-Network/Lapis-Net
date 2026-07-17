package net.lapisphilosophorum.lapisnet.trust

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

class VeritasGrantChainTest :
    FunSpec({
        test("a valid 3-grant chain validates, newest grant last") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val g1 = VeritasGrant.create(truster, target, trustMicros = 200_000)
            val g2 = VeritasGrant.create(truster, target, trustMicros = 600_000, previous = g1)
            val g3 = VeritasGrant.create(truster, target, trustMicros = 900_000, previous = g2)

            VeritasGrantChain.validate(listOf(g1, g2, g3)) shouldBe true
        }

        test("a single genesis grant is a valid (trivial) chain") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val genesis = VeritasGrant.create(truster, target, trustMicros = 500_000)

            VeritasGrantChain.validate(listOf(genesis)) shouldBe true
        }

        test("revocation via a trailing zero-trust grant is not a special case and still validates") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val g1 = VeritasGrant.create(truster, target, trustMicros = 800_000)
            val revocation = VeritasGrant.create(truster, target, trustMicros = MIN_TRUST_MICROS, previous = g1)

            VeritasGrantChain.validate(listOf(g1, revocation)) shouldBe true
        }

        test("a broken backward-link (pointing at the wrong predecessor) fails validation") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val g1 = VeritasGrant.create(truster, target, trustMicros = 200_000)
            val unrelated = VeritasGrant.create(truster, target, trustMicros = 100_000)
            // g2 legitimately links to g1, but we validate it against unrelated + g2 in place of g1.
            val g2 = VeritasGrant.create(truster, target, trustMicros = 600_000, previous = g1)

            VeritasGrantChain.validate(listOf(unrelated, g2)) shouldBe false
        }

        test("grants out of order (successor before predecessor) fail validation") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val g1 = VeritasGrant.create(truster, target, trustMicros = 200_000)
            val g2 = VeritasGrant.create(truster, target, trustMicros = 600_000, previous = g1)

            VeritasGrantChain.validate(listOf(g2, g1)) shouldBe false
        }

        test("a chain whose first element is not genesis fails validation") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val g1 = VeritasGrant.create(truster, target, trustMicros = 200_000)
            val g2 = VeritasGrant.create(truster, target, trustMicros = 600_000, previous = g1)

            VeritasGrantChain.validate(listOf(g2)) shouldBe false
        }

        test("a chain with a grant for a different target fails validation") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val otherTarget = Secp256k1KeyPair.generate().publicKey
            val g1 = VeritasGrant.create(truster, target, trustMicros = 200_000)
            val wrongTarget = VeritasGrant.create(truster, otherTarget, trustMicros = 600_000)

            VeritasGrantChain.validate(listOf(g1, wrongTarget)) shouldBe false
        }

        test("a chain with a grant from a different truster fails validation") {
            val truster = Secp256k1KeyPair.generate()
            val otherTruster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val g1 = VeritasGrant.create(truster, target, trustMicros = 200_000)
            val wrongTruster = VeritasGrant.create(otherTruster, target, trustMicros = 600_000)

            VeritasGrantChain.validate(listOf(g1, wrongTruster)) shouldBe false
        }

        test("a chain containing a grant that fails signature verification fails validation") {
            val truster = Secp256k1KeyPair.generate()
            val target = Secp256k1KeyPair.generate().publicKey
            val g1 = VeritasGrant.create(truster, target, trustMicros = 200_000)
            val bytes =
                VeritasGrantCodec.encode(
                    VeritasGrant.create(truster, target, trustMicros = 600_000, previous = g1),
                )
            bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the signature
            val tamperedG2 = VeritasGrantCodec.decode(bytes)

            VeritasGrantChain.validate(listOf(g1, tamperedG2)) shouldBe false
        }

        test("an empty chain fails validation") {
            VeritasGrantChain.validate(emptyList()) shouldBe false
        }
    })
