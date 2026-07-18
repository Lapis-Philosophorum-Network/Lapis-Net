package net.lapisphilosophorum.lapisnet.browser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.virtus.LtrGossip
import java.nio.file.Files

private val json = Json { ignoreUnknownKeys = true }

/**
 * Sets up one real, never-connected [LapisNode] + [NabuStorage] + [GossipPubSub] +
 * [VeritasGossip]/[LtrGossip]/[PostAnnouncementGossip] - mirrors
 * [net.lapisphilosophorum.lapisnet.virtus.LtrGossipOnGossipMessageTest]'s established "a single,
 * never-connected node is enough" test seam (see that class's doc comment). No real network
 * exercise here at all - `announce()` calls just persist+index locally, gossip `publish()` is a
 * documented no-op with zero mesh peers (see [GossipPubSub.publish]'s doc comment), which is
 * exactly what "seed test data directly, no real network" means for this integration-shaped test.
 */
private class TestHarness(
    val identity: DualKeyIdentity = DualKeyIdentity.generate(),
) {
    val node: LapisNode = LapisNode.create(identity)
    val storage: NabuStorage
    val pubsub: GossipPubSub
    val veritas: VeritasGossip
    val virtus: LtrGossip
    val posts: PostAnnouncementGossip
    val deps: BrowserApiDependencies

    init {
        node.start(bootstrapPeers = emptyList())
        storage = NabuStorage.attach(node, Files.createTempDirectory("browser-api-routing-test"))
        pubsub = GossipPubSub.attach(node)
        veritas = VeritasGossip.attach(pubsub, storage)
        virtus = LtrGossip.attach(pubsub, storage)
        posts = PostAnnouncementGossip.attach(pubsub, storage)
        deps = BrowserApiDependencies(identity, node, storage, veritas, virtus, posts)
    }

    fun stop() {
        posts.stop()
        virtus.stop()
        veritas.stop()
        pubsub.stop()
        storage.stop()
        runCatching { node.stop() }
    }
}

class BrowserApiRoutingTest :
    FunSpec({
        test("GET /api/identity returns the real identity fingerprint and peer id") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }
                    val response = client.get("/api/identity")
                    response.status shouldBe HttpStatusCode.OK
                    val body = json.decodeFromString<IdentityResponse>(response.bodyAsText())
                    body.fingerprint shouldBe
                        harness.identity.secp256k1KeyPair.publicKey
                            .fingerprint()
                    body.peerId shouldBe harness.node.peerId.toBase58()
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/timeline is empty before any post, and POST /api/posts then GET round-trips it") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val empty = client.get("/api/timeline")
                    json.decodeFromString<List<TimelinePostResponse>>(empty.bodyAsText()) shouldBe emptyList()

                    val postResponse =
                        client.post("/api/posts") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(NewPostRequest("hello from the routing test")))
                        }
                    postResponse.status shouldBe HttpStatusCode.OK
                    val posted = json.decodeFromString<NewPostResponse>(postResponse.bodyAsText())
                    posted.cid.isNotBlank() shouldBe true

                    val timeline = client.get("/api/timeline")
                    val entries = json.decodeFromString<List<TimelinePostResponse>>(timeline.bodyAsText())
                    entries.size shouldBe 1
                    entries.single().text shouldBe "hello from the routing test"
                    entries.single().cid shouldBe posted.cid
                    // The local identity's own post is self-authored - always RESOLVED at full
                    // self-trust (see CredibilityCalculatorTest's identical assertion), never
                    // filtered by the default threshold.
                    entries.single().credibilityLevel shouldBe CredibilityLevel.RESOLVED.name
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/trust then a follow-up GET /api/timeline reflects the resolved credibility") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val otherAuthorIdentity = DualKeyIdentity.generate()
                    // Seed a post authored by someone other than the local identity directly
                    // through the real gossip/index path (no network involved - see TestHarness's
                    // doc comment), so /api/timeline has a non-self-authored entry to resolve.
                    val announcement =
                        PostAnnouncement.create(
                            otherAuthorIdentity.secp256k1KeyPair,
                            "post from someone else".toByteArray(),
                        )
                    harness.posts.announce(announcement)

                    val targetHex =
                        otherAuthorIdentity.secp256k1KeyPair.publicKey.bytes.joinToString(
                            "",
                        ) { "%02x".format(it) }
                    val trustResponse =
                        client.post("/api/trust") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    TrustRequest(targetHex, trustMicros = 900_000, comment = "trusted"),
                                ),
                            )
                        }
                    trustResponse.status shouldBe HttpStatusCode.OK

                    val timeline = client.get("/api/timeline")
                    val entries = json.decodeFromString<List<TimelinePostResponse>>(timeline.bodyAsText())
                    val entry = entries.single { it.text == "post from someone else" }
                    entry.credibilityLevel shouldBe CredibilityLevel.RESOLVED.name
                    entry.credibilityScoreMicros shouldBe 900_000
                }
            } finally {
                harness.stop()
            }
        }

        test(
            "the real end-to-end authorPublicKeyHex path: reading it from a live /api/timeline entry and " +
                "feeding it straight into POST /api/trust is accepted and moves that author's credibility",
        ) {
            // Every OTHER test in this file that exercises /api/trust manually recomputes the
            // target hex from a known keypair - `otherAuthorIdentity.secp256k1KeyPair.publicKey.bytes
            // .joinToString(...)`. That never exercises the real client flow (app.js reads
            // `post.authorPublicKeyHex` straight off a `/api/timeline` response entry and feeds that
            // exact string into `/api/trust`, never recomputing it locally) - this test does the
            // real round trip instead.
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val otherAuthorIdentity = DualKeyIdentity.generate()
                    val announcement =
                        PostAnnouncement.create(
                            otherAuthorIdentity.secp256k1KeyPair,
                            "post whose authorPublicKeyHex is read from a real response".toByteArray(),
                        )
                    harness.posts.announce(announcement)

                    // Before any trust grant this author is NO_PATH (not RESOLVED-low) - per
                    // TimelineBuilder.build's filtering rule, NO_PATH entries are NEVER filtered
                    // out (only a genuinely low RESOLVED score is), so this entry is already
                    // visible in the default (non-includeFiltered) view.
                    val beforeTrust = client.get("/api/timeline")
                    val beforeEntries = json.decodeFromString<List<TimelinePostResponse>>(beforeTrust.bodyAsText())
                    val entryBeforeTrust =
                        beforeEntries.single {
                            it.text == "post whose authorPublicKeyHex is read from a real response"
                        }
                    val expectedHex =
                        otherAuthorIdentity.secp256k1KeyPair.publicKey.bytes.joinToString(
                            "",
                        ) { "%02x".format(it) }
                    // Sanity check that the real response's hex actually matches the known keypair
                    // before using it - if this ever drifts, the test below would still "pass" for
                    // the wrong reason (submitting garbage that happens to be accepted).
                    entryBeforeTrust.authorPublicKeyHex shouldBe expectedHex

                    // The real client flow: feed the exact string read off the response straight
                    // into POST /api/trust, no local recomputation.
                    val trustResponse =
                        client.post("/api/trust") {
                            contentType(ContentType.Application.Json)
                            setBody(
                                json.encodeToString(
                                    TrustRequest(
                                        entryBeforeTrust.authorPublicKeyHex,
                                        trustMicros = 700_000,
                                        comment = "trusting via the real timeline-read hex",
                                    ),
                                ),
                            )
                        }
                    trustResponse.status shouldBe HttpStatusCode.OK

                    val afterTrust = client.get("/api/timeline")
                    val afterEntries = json.decodeFromString<List<TimelinePostResponse>>(afterTrust.bodyAsText())
                    val entryAfterTrust =
                        afterEntries.single {
                            it.text == "post whose authorPublicKeyHex is read from a real response"
                        }
                    entryAfterTrust.credibilityLevel shouldBe CredibilityLevel.RESOLVED.name
                    entryAfterTrust.credibilityScoreMicros shouldBe 700_000
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/posts with text exceeding MAX_POST_BODY_BYTES returns 400, not a crash") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val tooLong = "a".repeat(MAX_POST_BODY_BYTES + 1)
                    val response =
                        client.post("/api/posts") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(NewPostRequest(tooLong)))
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                    val body = json.decodeFromString<ErrorResponse>(response.bodyAsText())
                    body.error.isNotBlank() shouldBe true
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/trust with a malformed hex public key returns 400, not a crash") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response =
                        client.post("/api/trust") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(TrustRequest("not-hex-at-all", trustMicros = 500_000)))
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                }
            } finally {
                harness.stop()
            }
        }

        test("POST /api/peers/connect with a malformed multiaddr returns 400, not a crash") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response =
                        client.post("/api/peers/connect") {
                            contentType(ContentType.Application.Json)
                            setBody(json.encodeToString(ConnectPeerRequest("not a real multiaddr")))
                        }

                    response.status shouldBe HttpStatusCode.BadRequest
                    val body = json.decodeFromString<ErrorResponse>(response.bodyAsText())
                    body.error.isNotBlank() shouldBe true
                }
            } finally {
                harness.stop()
            }
        }

        test("GET /api/peers returns an empty list for a never-connected node") {
            val harness = TestHarness()
            try {
                testApplication {
                    application { installBrowserApi(harness.deps) }

                    val response = client.get("/api/peers")
                    response.status shouldBe HttpStatusCode.OK
                    val body = json.decodeFromString<PeersResponse>(response.bodyAsText())
                    body.peers shouldBe emptyList()
                }
            } finally {
                harness.stop()
            }
        }

        // Ktor's testApplication test host never opens a real socket at all (see its doc comment:
        // it runs the application in-process against an in-memory client), so there is no
        // "resolved connector" to introspect for the 127.0.0.1-only requirement here. The real
        // enforcement point is BrowserServer.start()'s own require() guard - exercised directly
        // below, which is the strongest testable proxy for "this server can never bind a
        // non-loopback address" without actually opening a real socket in a unit test.
        test("BrowserServer.start refuses to bind any host other than 127.0.0.1") {
            val identity = DualKeyIdentity.generate()
            val dataDirectory = Files.createTempDirectory("browser-server-bind-guard-test")

            shouldThrow<IllegalArgumentException> {
                BrowserServer.start(
                    identity = identity,
                    httpHost = "0.0.0.0",
                    httpPort = 0,
                    dataDirectory = dataDirectory,
                )
            }
        }
    })
