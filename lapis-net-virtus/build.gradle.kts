// lapis-net-virtus: Virtus (LTR economy) data model. V0.2.1 adds the signed LtrRecord (a
// payer-signed claim binding an on-chain OP_RETURN Bitcoin payment to a (cid, view) pair), its
// codec, GossipSub propagation + Nabu persistence (LtrGossip/LtrRecordIndex), and the pure
// time-decay/accumulation weight calculator (LtrWeightCalculator). A Lightning-based LtrProof
// (V0.6) is a planned second LtrProof implementation - the sealed interface is shaped for it,
// but it is not built here.
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
// Deliberately NOT a dependency on lapis-net-trust: Virtus is a sibling scoring dimension to
// Veritas, not built on top of it (see docs/architecture.adoc's Layering section). Nothing in
// LtrRecord's data model needs a VeritasGrant type.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-storage"))
    api(rootProject.libs.java.cid)
}
