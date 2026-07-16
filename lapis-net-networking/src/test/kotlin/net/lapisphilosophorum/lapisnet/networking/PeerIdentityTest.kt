package net.lapisphilosophorum.lapisnet.networking

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.libp2p.core.PeerId
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity

class PeerIdentityTest :
    FunSpec({
        test("deriveLibp2pPeerId is deterministic for the same identity") {
            val identity = DualKeyIdentity.generate()
            identity.deriveLibp2pPeerId() shouldBe identity.deriveLibp2pPeerId()
        }

        test("different identities derive different PeerIds") {
            val a = DualKeyIdentity.generate()
            val b = DualKeyIdentity.generate()
            a.deriveLibp2pPeerId() shouldNotBe b.deriveLibp2pPeerId()
        }

        test("derived PeerId round-trips through base58") {
            val peerId = DualKeyIdentity.generate().deriveLibp2pPeerId()
            PeerId.fromBase58(peerId.toBase58()) shouldBe peerId
        }
    })
