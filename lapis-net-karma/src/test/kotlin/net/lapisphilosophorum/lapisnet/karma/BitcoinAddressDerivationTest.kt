package net.lapisphilosophorum.lapisnet.karma

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.security.MessageDigest

private fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0)
    return ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

class BitcoinAddressDerivationTest :
    FunSpec({
        // Known test vector: BIP-143's example transaction 1 spending public key. Independently
        // hand-verified (Python: hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest())
        // outside this codebase before writing this test, per this wave's test-plan requirement.
        val knownPubkeyHex = "025476c2e83188368da1ff3e292e7acafcdb356900e92abdba2400b8de938ff0e0"
        val knownWitnessProgramHex = "8f5e7f08162b27d7e4fdbc0cd62decd617231bfa"
        val knownScriptPubKeyHex = "00148f5e7f08162b27d7e4fdbc0cd62decd617231bfa"
        val knownElectrumScriptHashHex = "53c4463b478d701bb754fdd4e8bb26d5c1d298a2e4b2804bc1148b2877fd2650"

        test("p2wpkhWitnessProgram matches a hand-verified BIP-143-style test vector") {
            val pubkey = Secp256k1PublicKey(hexToBytes(knownPubkeyHex))

            val witnessProgram = BitcoinAddressDerivation.p2wpkhWitnessProgram(pubkey)

            witnessProgram.size shouldBe 20
            witnessProgram.toHex() shouldBe knownWitnessProgramHex
        }

        test("electrumScriptHash is SHA256(scriptPubKey) BYTE-REVERSED - hand-verified byte-order test") {
            val pubkey = Secp256k1PublicKey(hexToBytes(knownPubkeyHex))

            // Independently reconstruct the non-reversed digest and confirm the reversal really
            // happened - this is the exact easy-to-get-backwards mistake electrumScriptHash's doc
            // comment warns about.
            val scriptPubKey = hexToBytes(knownScriptPubKeyHex)
            val nonReversedDigest = MessageDigest.getInstance("SHA-256").digest(scriptPubKey)

            val electrumScriptHash = BitcoinAddressDerivation.electrumScriptHash(pubkey)

            electrumScriptHash.size shouldBe 32
            electrumScriptHash.toHex() shouldBe knownElectrumScriptHashHex
            // The reversed result must NOT equal the plain (non-reversed) digest - proves this
            // function actually reverses, rather than accidentally returning the plain digest.
            (electrumScriptHash.contentEquals(nonReversedDigest)) shouldBe false
            // But it MUST equal the plain digest reversed - the two must be byte-for-byte mirror
            // images of each other.
            electrumScriptHash.toHex() shouldBe nonReversedDigest.reversedArray().toHex()
        }

        test("p2wpkhWitnessProgram is deterministic for the same public key") {
            val pubkey = Secp256k1PublicKey(hexToBytes(knownPubkeyHex))

            val a = BitcoinAddressDerivation.p2wpkhWitnessProgram(pubkey)
            val b = BitcoinAddressDerivation.p2wpkhWitnessProgram(pubkey)

            a.toHex() shouldBe b.toHex()
        }

        test("different public keys yield different witness programs and scripthashes") {
            val pubkeyA = Secp256k1PublicKey(hexToBytes(knownPubkeyHex))
            val pubkeyB = Secp256k1KeyPair.generate().publicKey

            BitcoinAddressDerivation.p2wpkhWitnessProgram(pubkeyA).toHex() shouldNotBe
                BitcoinAddressDerivation.p2wpkhWitnessProgram(pubkeyB).toHex()
            BitcoinAddressDerivation.electrumScriptHash(pubkeyA).toHex() shouldNotBe
                BitcoinAddressDerivation.electrumScriptHash(pubkeyB).toHex()
        }
    })
