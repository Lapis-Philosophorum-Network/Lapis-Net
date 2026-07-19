package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair

private fun realDialableMultiaddr(): Multiaddr = Multiaddr("/ip4/203.0.113.10/tcp/4001").withP2P(PeerId.random())

class ConnectUriTest :
    FunSpec({
        test("toUriString then parseOrNull round-trips to an identical multiaddr and public key") {
            val multiaddr = realDialableMultiaddr()
            val publicKey = Secp256k1KeyPair.generate().publicKey

            val uri = ConnectUri.of(multiaddr, publicKey).toUriString()
            val parsed = ConnectUri.parseOrNull(uri)

            parsed.shouldNotBeNull()
            parsed.multiaddr shouldBe multiaddr
            parsed.publicKey shouldBe publicKey
        }

        test("of rejects a multiaddr without a /p2p component") {
            shouldThrow<IllegalArgumentException> {
                ConnectUri.of(Multiaddr("/ip4/203.0.113.10/tcp/4001"), Secp256k1KeyPair.generate().publicKey)
            }
        }

        test("parseOrNull rejects a wrong scheme") {
            val multiaddr = realDialableMultiaddr()
            val publicKey = Secp256k1KeyPair.generate().publicKey
            val uri = ConnectUri.of(multiaddr, publicKey).toUriString().replace("lapisnet://", "http://")

            ConnectUri.parseOrNull(uri).shouldBeNull()
        }

        test("parseOrNull rejects a URI missing the maddr param") {
            val publicKey = Secp256k1KeyPair.generate().publicKey
            val pkHex = publicKey.bytes.joinToString("") { "%02x".format(it) }

            ConnectUri.parseOrNull("lapisnet://connect?pk=$pkHex").shouldBeNull()
        }

        test("parseOrNull rejects a URI missing the pk param") {
            val multiaddr = realDialableMultiaddr()

            ConnectUri.parseOrNull("lapisnet://connect?maddr=$multiaddr").shouldBeNull()
        }

        test("parseOrNull rejects a public key hex that is not a valid curve point") {
            val multiaddr = realDialableMultiaddr()
            val allZerosHex = "0".repeat(66)
            val encodedMaddr = java.net.URLEncoder.encode(multiaddr.toString(), Charsets.UTF_8)

            ConnectUri.parseOrNull("lapisnet://connect?maddr=$encodedMaddr&pk=$allZerosHex").shouldBeNull()
        }

        test("parseOrNull rejects a multiaddr without a /p2p component") {
            val publicKey = Secp256k1KeyPair.generate().publicKey
            val pkHex = publicKey.bytes.joinToString("") { "%02x".format(it) }
            val encodedMaddr = java.net.URLEncoder.encode("/ip4/203.0.113.10/tcp/4001", Charsets.UTF_8)

            ConnectUri.parseOrNull("lapisnet://connect?maddr=$encodedMaddr&pk=$pkHex").shouldBeNull()
        }

        test("parseOrNull rejects an over-length URI") {
            val tooLong = "lapisnet://connect?maddr=" + "a".repeat(ConnectUri.MAX_URI_LENGTH)

            ConnectUri.parseOrNull(tooLong).shouldBeNull()
        }

        test("parseOrNull returns null rather than throwing for complete garbage") {
            ConnectUri.parseOrNull("not a uri at all").shouldBeNull()
            ConnectUri.parseOrNull("").shouldBeNull()
        }
    })
