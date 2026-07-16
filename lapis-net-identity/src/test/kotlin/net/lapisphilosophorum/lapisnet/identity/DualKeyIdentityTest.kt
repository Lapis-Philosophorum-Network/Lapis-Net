package net.lapisphilosophorum.lapisnet.identity

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class DualKeyIdentityTest :
    FunSpec({
        test("generate produces an identity whose binding verifies") {
            val identity = DualKeyIdentity.generate()
            identity.verifyBinding() shouldBe true
        }

        test("generate never collides across calls") {
            val a = DualKeyIdentity.generate()
            val b = DualKeyIdentity.generate()
            a.secp256k1KeyPair.privateKey shouldNotBe b.secp256k1KeyPair.privateKey
            a.ed25519KeyPair.privateKey shouldNotBe b.ed25519KeyPair.privateKey
        }
    })
