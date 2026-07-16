package net.lapisphilosophorum.lapisnet.core.crypto

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldHaveLength

class CryptoUtilsTest :
    FunSpec({
        test("domainSeparatedDigest is deterministic for the same inputs") {
            val part = "payload".toByteArray()
            domainSeparatedDigest("tag", part) shouldBe domainSeparatedDigest("tag", part)
        }

        test("domainSeparatedDigest differs for different domain tags with identical parts") {
            val part = "payload".toByteArray()
            domainSeparatedDigest("tag-a", part) shouldNotBe domainSeparatedDigest("tag-b", part)
        }

        test("domainSeparatedDigest differs for different parts with the same tag") {
            domainSeparatedDigest("tag", "one".toByteArray()) shouldNotBe
                domainSeparatedDigest("tag", "two".toByteArray())
        }

        test("domainSeparatedDigest does not let part boundaries shift without changing the digest") {
            val shiftedLeft = domainSeparatedDigest("tag", "AB".toByteArray(), "CD".toByteArray())
            val shiftedRight = domainSeparatedDigest("tag", "A".toByteArray(), "BCD".toByteArray())
            val concatenated = domainSeparatedDigest("tag", "ABCD".toByteArray())
            shiftedLeft.contentEquals(shiftedRight) shouldBe false
            shiftedLeft.contentEquals(concatenated) shouldBe false
            shiftedRight.contentEquals(concatenated) shouldBe false
        }

        test("domainSeparatedDigest rejects an empty domain tag") {
            io.kotest.assertions.throwables.shouldThrow<IllegalArgumentException> {
                domainSeparatedDigest("", "payload".toByteArray())
            }
        }

        test("fingerprintHex is deterministic and 16 hex characters long") {
            val bytes = "some public key bytes".toByteArray()
            val fingerprint = bytes.fingerprintHex()
            fingerprint shouldHaveLength 16
            fingerprint shouldBe bytes.fingerprintHex()
        }
    })
