// lapis-net-trust: Veritas (web-of-trust) data model. V0.1.5 adds the signed, versioned
// trust-edge grant (backward-hash chain); V0.1.6 adds the shortest-path aggregation algorithm;
// V0.1.7 adds GossipSub propagation + Nabu persistence (VeritasGossip/VeritasGrantIndex/
// VeritasGrantResolver).
//
// lapis-net-identity is `api`: Secp256k1PublicKey / Secp256k1KeyPair appear directly in
// VeritasGrant's public constructor, properties, and create()/verify() signatures, so any module
// compiling against lapis-net-trust (the CLI) needs them on its own classpath.
// java-cid is `api` for the same reason: io.ipfs.cid.Cid appears in VeritasGrant's public API
// (occasionReferences). We depend on java-cid directly rather than solely on :lapis-net-storage's
// transitive re-export - this module needs the Cid value type independently of whether storage
// wiring is present.
// lapis-net-storage is now `api` (added in V0.1.7): NabuStorage appears directly in
// VeritasGossip's public factory signature (VeritasGossip.attach(pubsub, storage)), so any module
// compiling against lapis-net-trust needs it on its own classpath too. Because lapis-net-storage
// already declares `api(project(":lapis-net-networking"))`, and lapis-net-networking declares the
// jvm-libp2p dependency as `api`, this single edge also gives lapis-net-trust direct compile-time
// visibility of LapisNode/Host/PeerId/GossipPubSub transitively - no separate edge to
// lapis-net-networking is needed.
// lapis-net-core stays `implementation`: domainSeparatedDigest is used internally only.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(project(":lapis-net-storage"))
    api(rootProject.libs.java.cid)
}
