package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testBody(text: String = "hello lapis net"): ByteArray = text.toByteArray(Charsets.UTF_8)

class PostAnnouncementCodecTest :
    FunSpec({
        test("decode(encode(announcement)) round-trips to an equal announcement") {
            val author = Secp256k1KeyPair.generate()
            val announcement = PostAnnouncement.create(author, testBody())

            val roundTripped = PostAnnouncementCodec.decode(PostAnnouncementCodec.encode(announcement))

            roundTripped shouldBe announcement
        }

        test("decode(encode(announcement)) round-trips at the 1-byte and MAX_POST_BODY_BYTES boundaries") {
            val author = Secp256k1KeyPair.generate()

            val min = PostAnnouncement.create(author, ByteArray(1) { 'a'.code.toByte() })
            val max = PostAnnouncement.create(author, ByteArray(MAX_POST_BODY_BYTES) { 'a'.code.toByte() })

            PostAnnouncementCodec.decode(PostAnnouncementCodec.encode(min)) shouldBe min
            PostAnnouncementCodec.decode(PostAnnouncementCodec.encode(max)) shouldBe max
        }

        test("contentId is deterministic and 32 bytes long") {
            val author = Secp256k1KeyPair.generate()
            val announcement = PostAnnouncement.create(author, testBody())

            val idA = PostAnnouncementCodec.contentId(announcement)
            val idB = PostAnnouncementCodec.contentId(announcement)

            idA.size shouldBe 32
            idA.contentEquals(idB) shouldBe true
        }

        test("decode does not verify signatures - a signature-tampered announcement still decodes successfully") {
            val author = Secp256k1KeyPair.generate()
            val announcement = PostAnnouncement.create(author, testBody())
            val bytes = PostAnnouncementCodec.encode(announcement)
            bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte()

            val decoded = PostAnnouncementCodec.decode(bytes)

            PostAnnouncement.verify(decoded) shouldBe false
        }

        test("every exception thrown by decode is a MalformedPostAnnouncementException") {
            val author = Secp256k1KeyPair.generate()
            val bytes = PostAnnouncementCodec.encode(PostAnnouncement.create(author, testBody()))

            shouldThrow<MalformedPostAnnouncementException> {
                PostAnnouncementCodec.decode(bytes.copyOf(3))
            }
        }

        test("decode rejects bad magic") {
            val author = Secp256k1KeyPair.generate()
            val bytes = PostAnnouncementCodec.encode(PostAnnouncement.create(author, testBody()))
            bytes[0] = 'X'.code.toByte()

            shouldThrow<MalformedPostAnnouncementException> { PostAnnouncementCodec.decode(bytes) }
        }

        test("decode rejects an unsupported version") {
            val author = Secp256k1KeyPair.generate()
            val bytes = PostAnnouncementCodec.encode(PostAnnouncement.create(author, testBody()))
            bytes[4] = 99 // version byte, right after the 4-byte magic

            shouldThrow<MalformedPostAnnouncementException> { PostAnnouncementCodec.decode(bytes) }
        }

        test("decode rejects a truncated buffer") {
            val author = Secp256k1KeyPair.generate()
            val bytes = PostAnnouncementCodec.encode(PostAnnouncement.create(author, testBody()))

            shouldThrow<MalformedPostAnnouncementException> {
                PostAnnouncementCodec.decode(
                    bytes.copyOf(bytes.size / 2),
                )
            }
        }

        test("decode rejects trailing garbage after the signature") {
            val author = Secp256k1KeyPair.generate()
            val bytes = PostAnnouncementCodec.encode(PostAnnouncement.create(author, testBody()))
            val withTrailingGarbage = bytes + byteArrayOf(1, 2, 3)

            shouldThrow<MalformedPostAnnouncementException> { PostAnnouncementCodec.decode(withTrailingGarbage) }
        }

        test("decode rejects an oversized bodyLen field BEFORE allocating the corresponding buffer") {
            val author = Secp256k1KeyPair.generate()
            val bytes = PostAnnouncementCodec.encode(PostAnnouncement.create(author, testBody()))

            // bodyLen(2) sits right after magic(4)+version(1)+author(33). Overwrite it with 65535
            // (max unsigned short) and truncate everything after it - if the range check did not
            // happen before the read-fully attempt, this would surface as a generic truncation
            // failure instead of the specific "invalid body length" rejection asserted below.
            val bodyLenOffset = 4 + 1 + 33
            val truncated = bytes.copyOf(bodyLenOffset + 2)
            val tooLong = 65535
            truncated[bodyLenOffset] = (tooLong ushr 8).toByte()
            truncated[bodyLenOffset + 1] = tooLong.toByte()

            val exception = shouldThrow<MalformedPostAnnouncementException> { PostAnnouncementCodec.decode(truncated) }
            exception.message.shouldContain("invalid body length")
        }

        test("decode rejects a bodyLen of zero") {
            val author = Secp256k1KeyPair.generate()
            val bytes = PostAnnouncementCodec.encode(PostAnnouncement.create(author, testBody("a")))

            val bodyLenOffset = 4 + 1 + 33
            bytes[bodyLenOffset] = 0
            bytes[bodyLenOffset + 1] = 0

            shouldThrow<MalformedPostAnnouncementException> { PostAnnouncementCodec.decode(bytes) }
        }
    })
