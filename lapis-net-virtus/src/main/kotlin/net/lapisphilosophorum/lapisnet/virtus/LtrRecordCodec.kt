package net.lapisphilosophorum.lapisnet.virtus

import io.ipfs.cid.Cid
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.security.MessageDigest

/**
 * Thrown when decoding an [LtrRecord]'s canonical byte encoding fails structurally (bad magic,
 * unsupported version, truncated/overrun buffer, out-of-range field, unknown proof type). Never
 * thrown for signature verification failures - [LtrRecordCodec.decode] does not verify
 * signatures, see its doc comment. Mirrors
 * [net.lapisphilosophorum.lapisnet.trust.MalformedVeritasGrantException]'s established
 * same-file-as-its-codec organization.
 */
class MalformedLtrRecordException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** Proof-type discriminator byte for [OnChainProof] - see [LtrRecordCodec]'s class doc comment. */
private const val PROOF_TYPE_ON_CHAIN: Byte = 1

/** Reserved for a future Lightning-based [LtrProof] (V0.6, per the Virtus spec note's "A.
 * Lightning via BOLT-12 Offer" path) - not implemented in this wave. [LtrRecordCodec.decode] must
 * reject this (and every other) proof type it does not itself implement, rather than silently
 * accepting unknown proof bytes. */
private const val PROOF_TYPE_LIGHTNING_RESERVED: Byte = 2

/** Exact encoded length of an [OnChainProof]'s `proofBytes`: `btcTxid(32) | outputIndex(4)`. */
private const val ON_CHAIN_PROOF_BYTES_SIZE = 36
private const val BTC_TXID_SIZE = 32

/**
 * Canonical, deterministic byte encoding for [LtrRecord] - used both to build the digest that
 * gets signed and to compute a record's content id (the gossip dedup key, see
 * [net.lapisphilosophorum.lapisnet.virtus.LtrRecordIndex]). Mirrors
 * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantCodec]'s sequential length-prefixed layout
 * and big-endian integer convention exactly.
 *
 * Layout of [encodeSignedBody]'s output: `magic(4="LNLR") | version(1) | payer(33) | viewId(33) |
 * cidLen(2) | cid(cidLen) | initialValueMsat(8) | timestampSeconds(8) | nonce(8) | proofType(1) |
 * proofLen(2) | proofBytes(proofLen)`. [encode] appends the 64-byte signature after that.
 *
 * `proofType = 1` ([PROOF_TYPE_ON_CHAIN]) is the only proof type this wave implements: an
 * [OnChainProof], whose `proofBytes` MUST be exactly [ON_CHAIN_PROOF_BYTES_SIZE] bytes
 * (`btcTxid(32) | outputIndex(4)`) - any other `proofLen` for type 1 is rejected. `proofType = 2`
 * ([PROOF_TYPE_LIGHTNING_RESERVED]) is reserved for a future Lightning proof and, like every other
 * unrecognized value, is rejected outright by [decode] - never silently accepted as opaque bytes.
 */
object LtrRecordCodec {
    private val MAGIC = "LNLR".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private const val PUBLIC_KEY_SIZE = 33
    private const val SIGNATURE_SIZE = 64
    private const val NONCE_SIZE = 8

    /** Cap on an encoded CID's byte length - see [MAX_BODY_SIZE] for why this exists. */
    const val MAX_CID_BYTES = 128

    /** Cap on an encoded proof's byte length - see [MAX_BODY_SIZE]. Generous headroom above
     * [ON_CHAIN_PROOF_BYTES_SIZE] (36) for a future, larger Lightning proof payload
     * (preimage + payment hash + a signed BOLT-11/12 invoice, per the Virtus spec note). */
    const val MAX_PROOF_BYTES = 1024

    /** [domainSeparatedDigest][net.lapisphilosophorum.lapisnet.core.crypto.domainSeparatedDigest]
     * treats the whole signed body as a single part, capped at this size - mirrors
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantCodec.MAX_BODY_SIZE]'s reasoning. Worst
     * case here is tiny by comparison (magic+version+two keys+cid+three 8-byte fields+proof
     * header+[MAX_PROOF_BYTES] ≈ 1.3 KB), well under the limit. */
    const val MAX_BODY_SIZE = 0xFFFF

    /** Builds the exact bytes that get domain-separated-digested and signed - see
     * [LtrRecord.Companion.create]. */
    fun encodeSignedBody(
        cid: Cid,
        viewId: Secp256k1PublicKey,
        payer: Secp256k1PublicKey,
        initialValueMsat: Long,
        timestampSeconds: Long,
        nonce: ByteArray,
        proof: LtrProof,
    ): ByteArray {
        require(initialValueMsat in MIN_INITIAL_VALUE_MSAT..MAX_INITIAL_VALUE_MSAT) {
            "initialValueMsat must be in $MIN_INITIAL_VALUE_MSAT..$MAX_INITIAL_VALUE_MSAT, was $initialValueMsat"
        }
        require(nonce.size == NONCE_SIZE) { "nonce must be exactly $NONCE_SIZE bytes" }
        val cidBytes = cid.toBytes()
        require(cidBytes.size in 1..MAX_CID_BYTES) { "cid must be 1..$MAX_CID_BYTES bytes, was ${cidBytes.size}" }

        val (proofType, proofBytes) = encodeProof(proof)
        require(
            proofBytes.size <= MAX_PROOF_BYTES,
        ) { "encoded proof exceeds $MAX_PROOF_BYTES bytes: ${proofBytes.size}" }

        val out = ByteArrayOutputStream()
        DataOutputStream(out).apply {
            write(MAGIC)
            writeByte(VERSION.toInt())
            write(payer.bytes)
            write(viewId.bytes)
            writeShort(cidBytes.size)
            write(cidBytes)
            writeLong(initialValueMsat)
            writeLong(timestampSeconds)
            write(nonce)
            writeByte(proofType.toInt())
            writeShort(proofBytes.size)
            write(proofBytes)
        }
        val body = out.toByteArray()
        require(body.size <= MAX_BODY_SIZE) { "encoded record body exceeds $MAX_BODY_SIZE bytes: ${body.size}" }
        return body
    }

    /** As the other [encodeSignedBody] overload, pulling fields off an existing [record]. */
    fun encodeSignedBody(record: LtrRecord): ByteArray =
        encodeSignedBody(
            cid = record.cid,
            viewId = record.viewId,
            payer = record.payer,
            initialValueMsat = record.initialValueMsat,
            timestampSeconds = record.timestampSeconds,
            nonce = record.nonce,
            proof = record.proof,
        )

    /** The full canonical artifact: signed body followed by the 64-byte signature. This is what
     * [net.lapisphilosophorum.lapisnet.virtus.LtrGossip] hands to `NabuStorage.put()` and
     * publishes over GossipSub, and the preimage of [contentId]. */
    fun encode(record: LtrRecord): ByteArray = encodeSignedBody(record) + record.signature

    /** Plain (not domain-separated) SHA-256 of [encode] - the gossip dedup / index lookup key,
     * not itself a signed value. */
    fun contentId(record: LtrRecord): ByteArray = sha256(encode(record))

    /**
     * Structural decode only - does **not** verify the signature, matching
     * [net.lapisphilosophorum.lapisnet.trust.VeritasGrantCodec.decode]'s exact contract. A record
     * typically arrives from an untrusted peer over gossip; callers must explicitly call
     * [LtrRecord.Companion.verify] before trusting it.
     *
     * @throws MalformedLtrRecordException if the bytes are structurally invalid, including an
     * out-of-range field, trailing bytes after the signature, or an unrecognized `proofType`
     * (every non-[PROOF_TYPE_ON_CHAIN] value, including the reserved
     * [PROOF_TYPE_LIGHTNING_RESERVED], is rejected - see this object's class doc comment).
     */
    fun decode(bytes: ByteArray): LtrRecord {
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))

            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            if (!magic.contentEquals(MAGIC)) throw MalformedLtrRecordException("bad magic")

            val version = input.readByte()
            if (version != VERSION) throw MalformedLtrRecordException("unsupported version $version")

            val payerBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }
            val viewIdBytes = ByteArray(PUBLIC_KEY_SIZE).also { input.readFully(it) }

            val cidLen = input.readUnsignedShort()
            if (cidLen !in 1..MAX_CID_BYTES) throw MalformedLtrRecordException("invalid CID length: $cidLen")
            val cidBytes = ByteArray(cidLen).also { input.readFully(it) }

            val initialValueMsat = input.readLong()
            if (initialValueMsat !in MIN_INITIAL_VALUE_MSAT..MAX_INITIAL_VALUE_MSAT) {
                throw MalformedLtrRecordException("initialValueMsat out of range: $initialValueMsat")
            }
            val timestampSeconds = input.readLong()

            val nonce = ByteArray(NONCE_SIZE).also { input.readFully(it) }

            val proofType = input.readByte()
            val proofLen = input.readUnsignedShort()
            if (proofLen > MAX_PROOF_BYTES) throw MalformedLtrRecordException("proof too long: $proofLen")
            val proofBytes = ByteArray(proofLen).also { input.readFully(it) }
            val proof = decodeProof(proofType, proofBytes)

            val signature = ByteArray(SIGNATURE_SIZE).also { input.readFully(it) }
            if (input.available() > 0) throw MalformedLtrRecordException("trailing bytes after signature")

            return LtrRecord.fromDecoded(
                cid = Cid.cast(cidBytes),
                viewId = Secp256k1PublicKey(viewIdBytes),
                payer = Secp256k1PublicKey(payerBytes),
                initialValueMsat = initialValueMsat,
                timestampSeconds = timestampSeconds,
                nonce = nonce,
                proof = proof,
                signature = signature,
            )
        } catch (e: EOFException) {
            throw MalformedLtrRecordException("truncated record bytes", e)
        } catch (e: IOException) {
            throw MalformedLtrRecordException("failed to decode record", e)
        } catch (e: MalformedLtrRecordException) {
            throw e
        } catch (e: RuntimeException) {
            // Covers IllegalArgumentException from LtrRecord's/OnChainProof's own constructor
            // validation and io.ipfs.cid.Cid.CidEncodingException from Cid.cast() on malformed CID
            // bytes - decode() must never leak an arbitrary third-party exception type to callers.
            throw MalformedLtrRecordException("invalid record field", e)
        }
    }

    private fun encodeProof(proof: LtrProof): Pair<Byte, ByteArray> =
        when (proof) {
            is OnChainProof -> {
                val out = ByteArrayOutputStream()
                DataOutputStream(out).apply {
                    write(proof.btcTxid)
                    writeInt(proof.outputIndex)
                }
                PROOF_TYPE_ON_CHAIN to out.toByteArray()
            }
        }

    private fun decodeProof(
        proofType: Byte,
        proofBytes: ByteArray,
    ): LtrProof =
        when (proofType) {
            PROOF_TYPE_ON_CHAIN -> {
                if (proofBytes.size != ON_CHAIN_PROOF_BYTES_SIZE) {
                    throw MalformedLtrRecordException(
                        "OnChainProof payload must be exactly $ON_CHAIN_PROOF_BYTES_SIZE bytes, was ${proofBytes.size}",
                    )
                }
                val txid = proofBytes.copyOfRange(0, BTC_TXID_SIZE)
                val outputIndexInput = DataInputStream(ByteArrayInputStream(proofBytes, BTC_TXID_SIZE, 4))
                val outputIndex = outputIndexInput.readInt()
                if (outputIndex !in 0..OnChainProof.MAX_OUTPUT_INDEX) {
                    throw MalformedLtrRecordException("outputIndex out of range: $outputIndex")
                }
                OnChainProof(txid, outputIndex)
            }
            else -> throw MalformedLtrRecordException("unknown or unsupported proofType: $proofType")
        }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
