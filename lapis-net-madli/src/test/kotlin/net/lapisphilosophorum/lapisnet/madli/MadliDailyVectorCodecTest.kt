package net.lapisphilosophorum.lapisnet.madli

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun testPeerId(seed: Byte): PeerId = PeerId(ByteArray(34) { seed })

private fun testMetrics(): MadliMetrics =
    MadliMetrics(
        reachabilityMicros = 500_000,
        medianBandwidthBytesPerSec = 10_000_000L,
        medianLatencyMillis = 50,
        deliveryIntegrityMicros = 900_000,
        routingHelpfulnessMicros = 700_000,
        observationCount = 10,
    )

private fun testVector(
    observer: Secp256k1KeyPair = Secp256k1KeyPair.generate(),
    peer: PeerId = testPeerId(1),
    epochDay: Long = 100L,
): MadliDailyVector = MadliDailyVector.create(observer, peer, epochDay, testMetrics())

class MadliDailyVectorCodecTest :
    FunSpec({
        test("encode -> decode round-trips to an equal vector") {
            val vector = testVector()

            val decoded = MadliDailyVectorCodec.decode(MadliDailyVectorCodec.encode(vector))

            decoded shouldBe vector
        }

        test("bad magic is rejected") {
            val bytes = MadliDailyVectorCodec.encode(testVector())
            bytes[0] = bytes[0].inc()

            shouldThrow<MalformedMadliDailyVectorException> { MadliDailyVectorCodec.decode(bytes) }
        }

        test("unsupported version is rejected") {
            val bytes = MadliDailyVectorCodec.encode(testVector())
            bytes[4] = 99 // version byte, right after the 4-byte magic

            shouldThrow<MalformedMadliDailyVectorException> { MadliDailyVectorCodec.decode(bytes) }
        }

        test("truncated buffer is rejected as Malformed, not as an unwrapped EOF/IO exception") {
            val bytes = MadliDailyVectorCodec.encode(testVector())

            shouldThrow<MalformedMadliDailyVectorException> {
                MadliDailyVectorCodec.decode(bytes.copyOfRange(0, bytes.size - 10))
            }
        }

        test("trailing bytes after the signature are rejected") {
            val bytes = MadliDailyVectorCodec.encode(testVector()) + byteArrayOf(1)

            shouldThrow<MalformedMadliDailyVectorException> { MadliDailyVectorCodec.decode(bytes) }
        }

        test("an oversized peerIdLen is rejected before any allocation is attempted") {
            val bytes = MadliDailyVectorCodec.encode(testVector())
            // peerIdLen(2) sits right after magic(4)+version(1)+observer(33).
            val offset = 4 + 1 + 33
            // 0x7FFF (32767) is far beyond MAX_PEER_ID_BYTES (128) but small enough not to
            // overflow the unsigned-short field itself - exercises the length-validated-before-
            // allocation path rather than a generic OOM/overflow.
            bytes[offset] = 0x7F
            bytes[offset + 1] = 0xFF.toByte()

            shouldThrow<MalformedMadliDailyVectorException> { MadliDailyVectorCodec.decode(bytes) }
        }

        test("a zero-length peerIdLen is rejected") {
            val bytes = MadliDailyVectorCodec.encode(testVector())
            val offset = 4 + 1 + 33
            bytes[offset] = 0
            bytes[offset + 1] = 0

            shouldThrow<MalformedMadliDailyVectorException> { MadliDailyVectorCodec.decode(bytes) }
        }

        test("an out-of-range metric field (crafted bytes) is rejected as Malformed") {
            val bytes = MadliDailyVectorCodec.encode(testVector())
            // reachabilityMicros(4) sits right after magic(4)+version(1)+observer(33)+peerIdLen(2)+
            // peerId(34)+epochDay(8).
            val offset = 4 + 1 + 33 + 2 + 34 + 8
            // Write Int.MAX_VALUE - far beyond MadliMetrics.MAX_METRIC_MICROS (1_000_000).
            bytes[offset] = 0x7F
            bytes[offset + 1] = 0xFF.toByte()
            bytes[offset + 2] = 0xFF.toByte()
            bytes[offset + 3] = 0xFF.toByte()

            shouldThrow<MalformedMadliDailyVectorException> { MadliDailyVectorCodec.decode(bytes) }
        }

        test("decode does NOT verify the signature - a sig-invalid but structurally-valid buffer decodes fine") {
            val vector = testVector()
            val bytes = MadliDailyVectorCodec.encode(vector)
            bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // tamper the signature only

            val decoded = MadliDailyVectorCodec.decode(bytes)

            decoded.metrics shouldBe vector.metrics
            MadliDailyVector.verify(decoded) shouldBe false
        }

        test("contentId is stable across repeated calls and equals-preserving") {
            val vector = testVector()

            MadliDailyVectorCodec.contentId(vector) shouldBe MadliDailyVectorCodec.contentId(vector)
        }

        test("contentId differs for two structurally different vectors") {
            val vectorA = testVector(epochDay = 100L)
            val vectorB = testVector(epochDay = 101L)

            MadliDailyVectorCodec.contentId(vectorA) shouldNotBe MadliDailyVectorCodec.contentId(vectorB)
        }
    })
