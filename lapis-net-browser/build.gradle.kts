// lapis-net-browser: V0.2.2 Minimal-Browser MVP. An embedded, loopback-only Ktor HTTP server
// running inside the same JVM process as a real LapisNode, serving a hand-written,
// framework-free HTML/CSS/vanilla-JS static page against JSON routes. No Compose Multiplatform,
// no KVision/Kilua, no JS build toolchain - just fetch() against the routes in BrowserApi.kt.

plugins {
    application
    alias(libs.plugins.kotlin.serialization)
}

application {
    mainClass.set("net.lapisphilosophorum.lapisnet.browser.BrowserMainKt")
}

dependencies {
    implementation(project(":lapis-net-core"))
    implementation(project(":lapis-net-identity"))
    implementation(project(":lapis-net-networking"))
    implementation(project(":lapis-net-storage"))
    implementation(project(":lapis-net-trust"))
    implementation(project(":lapis-net-virtus"))
    implementation(project(":lapis-net-karma"))

    implementation(rootProject.libs.ktor.server.core)
    implementation(rootProject.libs.ktor.server.netty)
    implementation(rootProject.libs.ktor.server.content.negotiation)
    implementation(rootProject.libs.ktor.server.status.pages)
    implementation(rootProject.libs.ktor.serialization.kotlinx.json)
    implementation(rootProject.libs.kotlinx.serialization.json)
    implementation(rootProject.libs.zxing.core)

    runtimeOnly(rootProject.libs.logback.classic)

    testImplementation(rootProject.libs.ktor.server.test.host)
}
