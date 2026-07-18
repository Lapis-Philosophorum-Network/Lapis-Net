package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testBody(text: String = "hello lapis net"): ByteArray = text.toByteArray(Charsets.UTF_8)

class PostAnnouncementTest :
    FunSpec({
        test("create then verify round-trips for a valid announcement") {
            val author = Secp256k1KeyPair.generate()
            val announcement = PostAnnouncement.create(author, testBody())

            PostAnnouncement.verify(announcement) shouldBe true
            announcement.author shouldBe author.publicKey
            announcement.text() shouldBe "hello lapis net"
        }

        test("verify(expectedAuthor, announcement) is true for the real author and false for a different one") {
            val author = Secp256k1KeyPair.generate()
            val other = Secp256k1KeyPair.generate()
            val announcement = PostAnnouncement.create(author, testBody())

            PostAnnouncement.verify(author.publicKey, announcement) shouldBe true
            PostAnnouncement.verify(other.publicKey, announcement) shouldBe false
        }

        test("boundary bodyBytes sizes 1 and MAX_POST_BODY_BYTES both create and verify") {
            val author = Secp256k1KeyPair.generate()

            val min = PostAnnouncement.create(author, ByteArray(1) { 'a'.code.toByte() })
            val max = PostAnnouncement.create(author, ByteArray(MAX_POST_BODY_BYTES) { 'a'.code.toByte() })

            PostAnnouncement.verify(min) shouldBe true
            PostAnnouncement.verify(max) shouldBe true
            min.bodyBytes.size shouldBe 1
            max.bodyBytes.size shouldBe MAX_POST_BODY_BYTES
        }

        test("an empty body is rejected") {
            val author = Secp256k1KeyPair.generate()

            shouldThrow<IllegalArgumentException> {
                PostAnnouncement.create(author, ByteArray(0))
            }
        }

        test("a body exceeding MAX_POST_BODY_BYTES is rejected") {
            val author = Secp256k1KeyPair.generate()

            shouldThrow<IllegalArgumentException> {
                PostAnnouncement.create(author, ByteArray(MAX_POST_BODY_BYTES + 1))
            }
        }

        test("fromDecoded rejects a nonce that is not exactly 8 bytes") {
            val author = Secp256k1KeyPair.generate().publicKey

            shouldThrow<IllegalArgumentException> {
                PostAnnouncement.fromDecoded(
                    author = author,
                    bodyBytes = testBody(),
                    timestampSeconds = 0,
                    nonce = ByteArray(7),
                    signature = ByteArray(64),
                )
            }
        }

        test("fromDecoded rejects a signature that is not exactly 64 bytes") {
            val author = Secp256k1KeyPair.generate().publicKey

            shouldThrow<IllegalArgumentException> {
                PostAnnouncement.fromDecoded(
                    author = author,
                    bodyBytes = testBody(),
                    timestampSeconds = 0,
                    nonce = ByteArray(8),
                    signature = ByteArray(63),
                )
            }
        }

        test("two independent create() calls with otherwise-identical inputs get distinct nonces and content ids") {
            val author = Secp256k1KeyPair.generate()
            val body = testBody()
            val timestamp = 1_700_000_000L

            val a = PostAnnouncement.create(author, body, timestampSeconds = timestamp)
            val b = PostAnnouncement.create(author, body, timestampSeconds = timestamp)

            a.nonce.contentEquals(b.nonce) shouldBe false
            a.contentId().contentEquals(b.contentId()) shouldBe false
            (a == b) shouldBe false
        }

        test("equals/hashCode are consistent for announcements built from identical fromDecoded inputs") {
            val author = Secp256k1KeyPair.generate().publicKey
            val body = testBody()
            val nonce = ByteArray(8) { it.toByte() }
            val signature = ByteArray(64) { it.toByte() }

            val a = PostAnnouncement.fromDecoded(author, body, 1_700_000_000L, nonce, signature)
            val b = PostAnnouncement.fromDecoded(author, body, 1_700_000_000L, nonce, signature)

            a shouldBe b
            a.hashCode() shouldBe b.hashCode()
        }

        test("toString never includes the raw signature bytes or the post text") {
            val author = Secp256k1KeyPair.generate()
            val announcement = PostAnnouncement.create(author, testBody("a secret-looking message"))

            val signatureHex = announcement.signature.joinToString("") { "%02x".format(it) }
            announcement.toString().contains(signatureHex) shouldBe false
            announcement.toString().contains("secret-looking") shouldBe false
        }

        test("contentId is deterministic and 32 bytes long") {
            val author = Secp256k1KeyPair.generate()
            val announcement = PostAnnouncement.create(author, testBody())

            val idA = announcement.contentId()
            val idB = announcement.contentId()

            idA.size shouldBe 32
            idA.contentEquals(idB) shouldBe true
        }

        test("announcements differing only in author, body, or timestamp have distinct contentIds") {
            val author = Secp256k1KeyPair.generate()
            val otherAuthor = Secp256k1KeyPair.generate()
            val timestamp = 1_700_000_000L

            val base = PostAnnouncement.create(author, testBody("a"), timestampSeconds = timestamp)
            val differentBody = PostAnnouncement.create(author, testBody("b"), timestampSeconds = timestamp)
            val differentAuthor = PostAnnouncement.create(otherAuthor, testBody("a"), timestampSeconds = timestamp)
            val differentTimestamp = PostAnnouncement.create(author, testBody("a"), timestampSeconds = timestamp + 1)

            val ids = listOf(base, differentBody, differentAuthor, differentTimestamp).map { it.contentId().toList() }
            ids.toSet().size shouldBe 4
        }

        test("returned mutable byte arrays are copies, not live references to internal state") {
            val author = Secp256k1KeyPair.generate()
            val announcement = PostAnnouncement.create(author, testBody())

            val originalSignature = announcement.signature.copyOf()
            announcement.signature.also { it[0] = (it[0] + 1).toByte() }
            announcement.signature.contentEquals(originalSignature) shouldBe true
            PostAnnouncement.verify(announcement) shouldBe true

            val originalNonce = announcement.nonce.copyOf()
            announcement.nonce.also { it[0] = (it[0] + 1).toByte() }
            announcement.nonce.contentEquals(originalNonce) shouldBe true

            val originalBody = announcement.bodyBytes.copyOf()
            announcement.bodyBytes.also { it[0] = (it[0] + 1).toByte() }
            announcement.bodyBytes.contentEquals(originalBody) shouldBe true
        }
    })
