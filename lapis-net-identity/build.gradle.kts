// lapis-net-identity: keypair / peer-identity abstractions.
//
// secp256k1-kmp and Bouncy Castle stay `implementation`: every public type in this module
// wraps their byte representations in this module's own value types, so no third-party
// crypto type ever appears in a public signature that downstream modules would need on
// their own compile classpath.

dependencies {
    implementation(project(":lapis-net-core"))
    implementation(rootProject.libs.secp256k1.kmp)
    implementation(rootProject.libs.secp256k1.kmp.jni.jvm)
    implementation(rootProject.libs.bouncycastle.provider)
}
