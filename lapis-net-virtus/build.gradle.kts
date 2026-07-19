// lapis-net-virtus: Virtus (LTR economy) data model. V0.2.1 adds the signed LtrRecord (a
// payer-signed claim binding an on-chain OP_RETURN Bitcoin payment to a (cid, view) pair), its
// codec, GossipSub propagation + Nabu persistence (LtrGossip/LtrRecordIndex), and the pure
// time-decay/accumulation weight calculator (LtrWeightCalculator). V0.6 adds LightningProof, the
// second LtrProof implementation - the sealed interface was already shaped for it.
//
// Dependency shape mirrors lapis-net-trust (see that module's build.gradle.kts comment), for the
// same reasons: lapis-net-identity is `api` because Secp256k1PublicKey/Secp256k1KeyPair appear in
// LtrRecord's public constructor/properties/create()/verify() signatures; java-cid is `api`
// because io.ipfs.cid.Cid appears in LtrRecord's public API; lapis-net-storage is `api` because
// NabuStorage appears directly in LtrGossip.attach()'s public factory signature (which also gives
// this module lapis-net-networking's GossipPubSub/LapisNode/Host/PeerId transitively, exactly as
// documented in lapis-net-trust's build.gradle.kts). lapis-net-core stays `implementation`:
// domainSeparatedDigest is used internally only.
//
// lightning-kmp is `implementation` ONLY, never `api` - its fr.acinq.lightning/fr.acinq.bitcoin
// types must never leak into this module's public API. Only LightningProofVerifier uses it,
// entirely internally, mirroring how lapis-net-karma confines electrum-client/bitcoin-kmp to its
// own ElectrumTimeAnchorSource class (see that module's build.gradle.kts comment). The Lightning
// node/wallet machinery that would actually *send* a payment is deliberately not here (V0.6 scope
// cut, see docs/architecture.adoc's "Lightning proof (V0.6)" section) - this module only verifies
// proofs, it does not create Lightning payments.
//
// Version note: lightning-kmp's own published POM pins an older bitcoin-kmp-jvm (0.20.0) than
// this project already depends on elsewhere (0.31.0, via lapis-net-karma) - without an explicit
// bitcoin-kmp dependency in THIS module, Gradle would resolve the older 0.20.0 here (this
// module's own dependency graph has no other bitcoin-kmp requirement to bump it, unlike
// secp256k1-kmp-jni-jvm, which IS already bumped to 0.23.0 by lightning-kmp's own transitive
// secp256k1-kmp-jni-jvm:0.15.0 losing to some other 0.23.0 requirement elsewhere in the graph).
// The explicit `implementation(rootProject.libs.bitcoin.kmp)` below forces the same 0.31.0
// resolved everywhere else in this project (Gradle's default highest-version-wins conflict
// resolution) - verified compatible by this wave's full test suite exercising real
// signed-invoice creation/parsing/verification against the resolved (newer) bitcoin-kmp.
//
// Deliberately NOT a dependency on lapis-net-trust: Virtus is a sibling scoring dimension to
// Veritas, not built on top of it (see docs/architecture.adoc's Layering section). Nothing in
// LtrRecord's data model needs a VeritasGrant type.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-storage"))
    api(rootProject.libs.java.cid)
    implementation(rootProject.libs.lightning.kmp)
    implementation(rootProject.libs.bitcoin.kmp)
}
