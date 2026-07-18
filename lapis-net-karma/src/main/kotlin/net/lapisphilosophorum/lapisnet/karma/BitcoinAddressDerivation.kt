package net.lapisphilosophorum.lapisnet.karma

import fr.acinq.bitcoin.Crypto
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.security.MessageDigest

/** `OP_0` - the single push-opcode byte a P2WPKH `scriptPubKey` starts with. */
private const val OP_0: Byte = 0x00

/** Push-20-bytes opcode - a P2WPKH `scriptPubKey`'s second byte, immediately before the 20-byte
 * witness program. */
private const val PUSH_20: Byte = 0x14

private const val WITNESS_PROGRAM_SIZE = 20

/**
 * Derives a single-sig native SegWit (P2WPKH) Bitcoin identity for a Lapis Net secp256k1 public
 * key, and the Electrum-protocol scripthash used to query that identity's transaction history.
 *
 * **Scope limitation, explicitly named, not a silent gap.** Lapis Net identity is a raw secp256k1
 * keypair, not an HD wallet (see
 * [net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair]) - there is no derivation path, no
 * xpub, no notion of "the wallet's addresses" to search. This object recognizes exactly ONE address
 * type for a given public key: single-sig native SegWit P2WPKH
 * (`witness program = HASH160(compressed pubkey)`). A user whose real first Bitcoin activity was
 * via a legacy P2PKH address, a different derivation path, or a multisig/Taproot output will NOT be
 * found by [ElectrumTimeAnchorSource] and will read as [TimeAnchorLookupResult.NotFound] - which
 * [KarmaAnchorCache] correctly resolves to [NoAnchorClaim], the genuine "no anchor" state (see that
 * object's doc comment - NOT an error). This is an accepted, named limitation of this wave, not a
 * bug: extending recognition to other address types is future work.
 *
 * **The actual proof-of-spend check this scope limitation enables** (performed by
 * [ElectrumTimeAnchorSource], not here): for a P2WPKH input, the witness stack is literally
 * `[signature, pubkey]` - scanning a candidate transaction's inputs for a witness whose SECOND stack
 * item equals the target's compressed pubkey bytes directly proves "this identity's key authorized a
 * spend", with no need to resolve the previous output's script (which would require either a second
 * chain lookup per candidate input, or a full UTXO index this wave does not build). This is exactly
 * why P2WPKH - and not, say, P2PKH (where the pubkey similarly appears in the *input* script, but
 * this wave only builds P2WPKH derivation) - was chosen as the one recognized address type.
 */
object BitcoinAddressDerivation {
    /**
     * The P2WPKH witness program for [pubkey]: `HASH160(compressed pubkey)` =
     * `RIPEMD160(SHA256(pubkey bytes))`, 20 bytes. Uses `bitcoin-kmp`'s own `Crypto.hash160` (this
     * module already depends on `bitcoin-kmp` for transaction parsing - see this module's
     * `build.gradle.kts` comment - so reusing its hash160 keeps this a single, consistent
     * implementation rather than a second, hand-rolled one against a separate hash library).
     */
    fun p2wpkhWitnessProgram(pubkey: Secp256k1PublicKey): ByteArray {
        val program = Crypto.hash160(pubkey.bytes)
        check(program.size == WITNESS_PROGRAM_SIZE) {
            "hash160 output must be exactly $WITNESS_PROGRAM_SIZE bytes, was ${program.size}"
        }
        return program
    }

    /**
     * The Electrum-protocol scripthash for [pubkey]'s P2WPKH `scriptPubKey`:
     * `SHA256(scriptPubKey)`, byte-REVERSED.
     *
     * **This byte reversal is an Electrum protocol quirk, easy to get backwards - flagged
     * explicitly here because getting it wrong does NOT throw, it silently returns "no history"
     * for a real, existing address.** The Electrum protocol (`blockchain.scripthash.*` RPCs)
     * defines its scripthash parameter as the REVERSED hex of `sha256(scriptPubKey)` - NOT the
     * plain, non-reversed digest a naive reading of "hash the script" would produce. A caller that
     * forgets the reversal will construct a syntactically valid 32-byte scripthash that simply does
     * not match any real address's Electrum-indexed scripthash, and the server will report an empty
     * history - indistinguishable, from the caller's point of view, from a genuinely fresh address
     * that has never transacted. There is no exception, no protocol-level error, nothing to catch -
     * only a silently wrong (empty) result. See [ElectrumTimeAnchorSource] for where this
     * scripthash is actually sent over the wire.
     */
    fun electrumScriptHash(pubkey: Secp256k1PublicKey): ByteArray {
        val scriptPubKey = p2wpkhScriptPubKey(pubkey)
        val digest = MessageDigest.getInstance("SHA-256").digest(scriptPubKey)
        return digest.reversedArray()
    }

    /** `OP_0 <20-byte witness program>` - the P2WPKH `scriptPubKey`, 22 bytes total. Hand-built
     * directly from opcode bytes rather than via `bitcoin-kmp`'s script-element DSL: this exact
     * 2-opcode shape is fixed and never varies for P2WPKH, so there is nothing a script builder
     * would add beyond what these three lines already express plainly. */
    private fun p2wpkhScriptPubKey(pubkey: Secp256k1PublicKey): ByteArray {
        val program = p2wpkhWitnessProgram(pubkey)
        return byteArrayOf(OP_0, PUSH_20) + program
    }
}
