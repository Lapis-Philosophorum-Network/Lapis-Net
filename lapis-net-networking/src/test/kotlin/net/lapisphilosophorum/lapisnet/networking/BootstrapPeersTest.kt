package net.lapisphilosophorum.lapisnet.networking

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.multiformats.Protocol

class BootstrapPeersTest :
    FunSpec({
        test("PLACEHOLDER is not empty") {
            BootstrapPeers.PLACEHOLDER.shouldNotBeEmpty()
        }

        test("PLACEHOLDER entries parse as valid multiaddrs with IP4, TCP, and P2P components") {
            BootstrapPeers.PLACEHOLDER.forEach { address ->
                address.has(Protocol.IP4).shouldBeTrue()
                address.has(Protocol.TCP).shouldBeTrue()
                address.has(Protocol.P2P).shouldBeTrue()
                address.getPeerId() shouldNotBe null
            }
        }

        test("PLACEHOLDER addresses stay within the RFC 5737 documentation range (203.0.113.0/24)") {
            BootstrapPeers.PLACEHOLDER.forEach { address ->
                val ip = address.getFirstComponent(Protocol.IP4)?.stringValue
                ip?.startsWith("203.0.113.")?.shouldBeTrue()
            }
        }
    })
