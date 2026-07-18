// lapis-net-karma: Karma (V0.3) data model. Karma is a cheap, one-click "like" mechanism
// (KarmaVote) with built-in Sybil resistance via two mechanisms combined: (1) a Bitcoin-chain-
// derived time anchor (t = blocks since the voter's own first outgoing Bitcoin transaction) and
// (2) Veritas-weighting of the vote, applied one layer up in lapis-net-browser (see
// KarmaScoring.kt) - never here.
//
// Dependency shape mirrors lapis-net-virtus (see that module's build.gradle.kts comment), for the
// same reasons: lapis-net-identity is `api` because Secp256k1PublicKey/Secp256k1KeyPair appear in
// KarmaVote's public constructor/properties/create()/verify() signatures; java-cid is `api`
// because io.ipfs.cid.Cid appears in KarmaVote's public API; lapis-net-storage is `api` because
// NabuStorage appears directly in KarmaGossip.attach()'s public factory signature (which also
// gives this module lapis-net-networking's GossipPubSub/LapisNode/Host/PeerId transitively).
// lapis-net-core stays `implementation`: domainSeparatedDigest is used internally only.
//
// electrum-client/bitcoin-kmp are `implementation` ONLY, never `api` - their types must never leak
// into any public API signature of this module (see BitcoinTimeAnchorSource/ElectrumTimeAnchorSource's
// doc comments). Real chain lookups only ever run client-side, never in the GossipSub validation
// path (KarmaGossip.onGossipMessage) - see TimeAnchorClaim.kt's doc comment for the full reasoning
// (structural-only gossip acceptance, mirroring OnChainProof's V0.2.1 precedent).
//
// Deliberately NOT a dependency on lapis-net-trust: Karma is a sibling scoring dimension to
// Veritas and Virtus, not built on top of it (see docs/architecture.adoc's Layering section).
// Veritas-weighting of a Karma vote happens one layer up, in lapis-net-browser's KarmaScoring.kt.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-storage"))
    api(rootProject.libs.java.cid)
    implementation(rootProject.libs.electrum.client)
    implementation(rootProject.libs.bitcoin.kmp)
}
