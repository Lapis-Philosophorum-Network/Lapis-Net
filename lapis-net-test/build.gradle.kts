// lapis-net-test: shared test fixtures and helpers used by other modules' test sources.
// kotest-assertions is exposed as `api` so consumers get matchers transitively.

dependencies {
    implementation(project(":lapis-net-core"))
    api(rootProject.libs.kotest.assertions.core)
}
