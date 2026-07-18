package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.libp2p.core.pubsub.ValidationResult
import kotlinx.coroutines.delay
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.Collections
import kotlin.time.Duration.Companion.seconds

private val json = Json { ignoreUnknownKeys = true }

/** Disposable warm-up topic - mirrors
 * [net.lapisphilosophorum.lapisnet.cli.LapisNetCli.WARMUP_TOPIC]'s established mechanism exactly:
 * a separate, non-content-addressed-dedup topic used purely to prove the GossipSub mesh/stream
 * between two directly-dialed peers is hot BEFORE relying on gossip propagation of real,
 * content-addressed-deduped [PostAnnouncement] bytes over
 * [PostAnnouncementGossip.POST_ANNOUNCEMENT_GOSSIP_TOPIC]. */
private const val WARMUP_TOPIC = "lapisnet-browser-pilot-demo:warmup:v1"

/**
 * End-to-end pilot demo: two real, independent [BrowserServer] instances on different loopback
 * ports, connected via a real `POST /api/peers/connect` HTTP call (direct dial, no discovery). One
 * node posts real content; the other issues a real Veritas trust grant (via its own
 * `POST /api/trust`) targeting the poster's identity, then polls its own `GET /api/timeline` (a
 * real HTTP call, never direct object inspection) until the post appears with the exact expected
 * text and the exact granted credibility score - proving both post-announcement gossip propagation
 * and end-to-end trust-graph resolution work through the real HTTP surface, not just the
 * lower-level unit seams the other tests in this module exercise directly.
 */
class TwoNodeBrowserPilotDemoTest :
    FunSpec({
        test("a post from node A propagates to node B and resolves to the trust score B granted A").config(
            timeout = 90.seconds,
        ) {
            val deadline = Instant.now().plus(Duration.ofSeconds(60))

            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val serverA =
                BrowserServer.start(
                    identity = identityA,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("browser-pilot-a"),
                )
            val serverB =
                BrowserServer.start(
                    identity = identityB,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("browser-pilot-b"),
                )
            val httpClient = HttpClient(CIO)

            try {
                // Direct-dial connect via the real public HTTP API - A dials B.
                val bListenAddress = serverB.nodeForTesting.listenAddresses().first()
                val bMultiaddr = bListenAddress.withP2P(serverB.nodeForTesting.peerId).toString()
                val connectResponse: HttpResponse =
                    httpClient.post("http://127.0.0.1:${serverA.boundPort}/api/peers/connect") {
                        contentType(ContentType.Application.Json)
                        setBody(json.encodeToString(ConnectPeerRequest(bMultiaddr)))
                    }
                connectResponse.status.value shouldBe 200

                // Warm-up phase - see WARMUP_TOPIC's doc comment and
                // LapisNetCli.runMultiNodeTrustPropagationDemo's identical mechanism: a disposable
                // topic where every message always validates Valid, so distinct retried payloads
                // keep getting delivered regardless of duplicate content (unlike the real
                // content-addressed-deduped post-announcement topic). NOT optional - skipping it
                // makes this demo flaky in exactly the way the CLI's own doc comment describes.
                val warmupReceivedOnB = Collections.synchronizedList(mutableListOf<ByteArray>())
                serverB.pubsubForTesting.subscribe(WARMUP_TOPIC) { bytes, _ ->
                    warmupReceivedOnB.add(bytes)
                    ValidationResult.Valid
                }
                var warmupSeq = 0
                while (warmupReceivedOnB.isEmpty() && Instant.now().isBefore(deadline)) {
                    warmupSeq++
                    runCatching { serverA.pubsubForTesting.publish(WARMUP_TOPIC, "warmup-$warmupSeq".toByteArray()) }
                    delay(200)
                }
                check(warmupReceivedOnB.isNotEmpty()) { "warm-up phase did not complete before the deadline" }

                // A posts real content via the real HTTP API.
                val postText = "hello from node A via the two-node pilot demo"
                val postResponse =
                    httpClient.post("http://127.0.0.1:${serverA.boundPort}/api/posts") {
                        contentType(ContentType.Application.Json)
                        setBody(json.encodeToString(NewPostRequest(postText)))
                    }
                postResponse.status.value shouldBe 200

                // B issues a real trust grant to A's identity via the real HTTP API - so B's own
                // local timeline resolves A's post to a known, non-default credibility score.
                val targetHex =
                    identityA.secp256k1KeyPair.publicKey.bytes
                        .joinToString("") { "%02x".format(it) }
                val grantedTrustMicros = 800_000
                val trustResponse =
                    httpClient.post("http://127.0.0.1:${serverB.boundPort}/api/trust") {
                        contentType(ContentType.Application.Json)
                        setBody(
                            json.encodeToString(
                                TrustRequest(targetHex, trustMicros = grantedTrustMicros, comment = "pilot demo"),
                            ),
                        )
                    }
                trustResponse.status.value shouldBe 200

                // Bounded polling loop against B's real /api/timeline HTTP endpoint - never a fixed
                // Thread.sleep/delay as the sole wait condition, matching this project's
                // established convention (see e.g. MultiNodeTrustPropagationDemoTest /
                // ThreeNodeVeritasGossipRelayTest's identical poll-until-observed pattern).
                var found: TimelinePostResponse? = null
                while (found == null && Instant.now().isBefore(deadline)) {
                    val timelineResponse = httpClient.get("http://127.0.0.1:${serverB.boundPort}/api/timeline")
                    val entries = json.decodeFromString<List<TimelinePostResponse>>(timelineResponse.bodyAsText())
                    found = entries.find { it.text == postText }
                    if (found == null) delay(300)
                }

                found.shouldNotBeNull()
                found.text shouldBe postText
                found.credibilityLevel shouldBe CredibilityLevel.RESOLVED.name
                found.credibilityScoreMicros shouldBe grantedTrustMicros
            } finally {
                httpClient.close()
                runCatching { serverA.stop() }
                runCatching { serverB.stop() }
            }
        }
    })
