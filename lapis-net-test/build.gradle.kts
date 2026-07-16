// lapis-net-test: shared test fixtures and helpers for other modules' test sources.
// Not yet consumed by any module — lands once V0.1.8's multi-node harness needs it.
// kotest-assertions is exposed as `api` so future consumers get matchers transitively.

dependencies {
    api(rootProject.libs.kotest.assertions.core)
}
