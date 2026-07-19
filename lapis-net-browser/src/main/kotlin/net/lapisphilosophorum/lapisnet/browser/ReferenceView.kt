package net.lapisphilosophorum.lapisnet.browser

import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey

/**
 * A single, hardcoded "view" identity - the `viewId` every [net.lapisphilosophorum.lapisnet.virtus.LtrRecord]
 * lookup in this module uses (see [BrowserApi]'s `/api/timeline` handler). A clearly-marked
 * stand-in for real infrastructure that does not exist yet, not something anyone should mistake
 * for a production value - the same convention the pre-V0.4 `BootstrapPeers.PLACEHOLDER` followed
 * before V0.4 replaced it with real, externally-configurable bootstrap config (see
 * [net.lapisphilosophorum.lapisnet.networking.BootstrapConfig]).
 *
 * The Virtus spec models "views" as independent, potentially many, sort-weight namespaces a
 * `(cid, viewId)` pair's accumulated LTR weight is scoped to (see
 * [net.lapisphilosophorum.lapisnet.virtus.LtrRecord]'s doc comment). The Minimal-Browser MVP does
 * not implement multiple views, view registration, or view discovery - it is a single-view
 * pilot-stage stand-in.
 *
 * [PLACEHOLDER_VIEW_ID] is the public key of a real, once-generated
 * [net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair] (via the same
 * [net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair.generate] utility
 * [net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity.generate] uses), hardcoded here as
 * literal compressed-key bytes. The corresponding private key was generated once, used only to
 * produce these 33 bytes, and then discarded - it is not persisted or logged anywhere in this
 * repository, and nobody (including this module's own authors) can sign as this "view" identity.
 * That is intentional: this identity exists only to be a syntactically valid
 * [Secp256k1PublicKey] to key LTR lookups by, never to sign or authenticate anything itself.
 *
 * TODO(post-pilot, before any real multi-view deployment): replace this with real view
 * registration/discovery.
 */
val PLACEHOLDER_VIEW_ID: Secp256k1PublicKey =
    Secp256k1PublicKey(
        hexToBytes("02244f43bdf5ca3a6ebd6343732f0ef41a74b0a0a15eb661c62a526e1a7c23289c"),
    )

private fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "hex string must have an even length" }
    return ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
}
