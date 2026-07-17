// lapis-net-trust: Veritas (web-of-trust) data model. V0.1.5 adds the signed, versioned
// trust-edge grant (backward-hash chain); V0.1.6 adds the shortest-path aggregation algorithm.
//
// lapis-net-identity is `api`: Secp256k1PublicKey / Secp256k1KeyPair appear directly in
// VeritasGrant's public constructor, properties, and create()/verify() signatures, so any module
// compiling against lapis-net-trust (V0.1.7 propagation, the CLI) needs them on its own classpath.
// java-cid is `api` for the same reason: io.ipfs.cid.Cid appears in VeritasGrant's public API
// (occasionReferences). We depend on java-cid directly rather than on :lapis-net-storage on
// purpose - this wave needs only the Cid value type, not Nabu/DHT; pulling in :lapis-net-storage
// would drag the entire libp2p/Bitswap stack into a pure data-model+crypto module. V0.1.7, which
// actually persists grants, will add the :lapis-net-storage dependency then.
// lapis-net-core stays `implementation`: domainSeparatedDigest is used internally only.
dependencies {
    implementation(project(":lapis-net-core"))
    api(project(":lapis-net-identity"))
    api(rootProject.libs.java.cid)
}
