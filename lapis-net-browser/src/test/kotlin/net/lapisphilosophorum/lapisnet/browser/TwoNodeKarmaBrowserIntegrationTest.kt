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
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.BitcoinTimeAnchorSource
import net.lapisphilosophorum.lapisnet.karma.TimeAnchorLookupResult
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import java.util.Collections
import kotlin.time.Duration.Companion.seconds

private val json = Json { ignoreUnknownKeys = true }

/** Disposable warm-up topic - mirrors [TwoNodeBrowserPilotDemoTest]'s own identically-named
 * mechanism (a separate, differently-named topic here so the two test files' warm-up traffic can
 * never collide on the same GossipSub topic string). */
private const val WARMUP_TOPIC = "lapisnet-browser-karma-demo:warmup:v1"

/** A [BitcoinTimeAnchorSource] that always reports "not found", with zero real network I/O -
 * BrowserServer.start()'s default real [net.lapisphilosophorum.lapisnet.karma.ElectrumTimeAnchorSource]
 * would always fail with [TimeAnchorLookupResult.LookupFailed] in this sandboxed test environment
 * (no reachable Electrum server, see [net.lapisphilosophorum.lapisnet.karma.ElectrumServers.PLACEHOLDER]'s
 * doc comment), which would make casting a real vote via `POST /api/karma` impossible - this fake
 * resolves cleanly to [net.lapisphilosophorum.lapisnet.karma.NoAnchorClaim] instead, letting this
 * test exercise the real vote-creation/gossip/propagation path end-to-end without needing a real
 * chain lookup to succeed. */
private object KarmaDemoNoAnchorSource : BitcoinTimeAnchorSource {
    override fun findFirstOutgoingTransaction(pubkey: Secp256k1PublicKey): TimeAnchorLookupResult =
        TimeAnchorLookupResult.NotFound

    override fun currentChainTipHeight(): Int = 0
}

/**
 * End-to-end pilot demo, mirroring [TwoNodeBrowserPilotDemoTest]'s established real-HTTP,
 * real-two-node pattern exactly, but for Karma: node A posts real content and node B casts a real
 * `POST /api/karma` "like" on it via its own real HTTP API - proving a Karma vote gossiped from B
 * propagates back to A and is visible as personalized display data (`karmaVoteCount`) on A's own
 * `GET /api/timeline`, through the real HTTP surface end-to-end, not just the lower-level unit
 * seams `KarmaGossipOnGossipMessageTest`/`TwoNodeKarmaGossipIntegrationTest` (in `lapis-net-karma`)
 * exercise directly.
 */
class TwoNodeKarmaBrowserIntegrationTest :
    FunSpec({
        test("a karma vote cast on node B for a post from node A propagates back and is visible on A").config(
            timeout = 90.seconds,
        ) {
            val deadline = Instant.now().plus(Duration.ofSeconds(60))

            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val serverA =
                BrowserServer.start(
                    identity = identityA,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("browser-karma-demo-a"),
                    karmaAnchorSource = KarmaDemoNoAnchorSource,
                )
            val serverB =
                BrowserServer.start(
                    identity = identityB,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("browser-karma-demo-b"),
                    karmaAnchorSource = KarmaDemoNoAnchorSource,
                )
            val httpClient = HttpClient(CIO)

            try {
                val bListenAddress = serverB.nodeForTesting.listenAddresses().first()
                val bMultiaddr = bListenAddress.withP2P(serverB.nodeForTesting.peerId).toString()
                val connectResponse: HttpResponse =
                    httpClient.post("http://127.0.0.1:${serverA.boundPort}/api/peers/connect") {
                        contentType(ContentType.Application.Json)
                        setBody(json.encodeToString(ConnectPeerRequest(bMultiaddr)))
                    }
                connectResponse.status.value shouldBe 200

                // Warm-up phase - see WARMUP_TOPIC's/TwoNodeBrowserPilotDemoTest's doc comments.
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
                val postText = "a post for the karma two-node demo"
                val postResponse =
                    httpClient.post("http://127.0.0.1:${serverA.boundPort}/api/posts") {
                        contentType(ContentType.Application.Json)
                        setBody(json.encodeToString(NewPostRequest(postText)))
                    }
                postResponse.status.value shouldBe 200
                val postedCid = json.decodeFromString<NewPostResponse>(postResponse.bodyAsText()).cid

                // B waits until A's post is visible on its own timeline (real gossip propagation),
                // then casts a real Karma vote via its own POST /api/karma.
                var seenOnB: TimelinePostResponse? = null
                while (seenOnB == null && Instant.now().isBefore(deadline)) {
                    val timelineOnB = httpClient.get("http://127.0.0.1:${serverB.boundPort}/api/timeline")
                    val entries = json.decodeFromString<List<TimelinePostResponse>>(timelineOnB.bodyAsText())
                    seenOnB = entries.find { it.cid == postedCid }
                    if (seenOnB == null) delay(300)
                }
                seenOnB.shouldNotBeNull()

                val karmaResponse =
                    httpClient.post("http://127.0.0.1:${serverB.boundPort}/api/karma") {
                        contentType(ContentType.Application.Json)
                        setBody(json.encodeToString(NewKarmaVoteRequest(postedCid)))
                    }
                karmaResponse.status.value shouldBe 200

                // Bounded polling loop against A's real /api/timeline HTTP endpoint - never a fixed
                // Thread.sleep/delay as the sole wait condition, matching this project's
                // established convention.
                var foundOnA: TimelinePostResponse? = null
                while (Instant.now().isBefore(deadline)) {
                    val timelineOnA = httpClient.get("http://127.0.0.1:${serverA.boundPort}/api/timeline")
                    val entries = json.decodeFromString<List<TimelinePostResponse>>(timelineOnA.bodyAsText())
                    val candidate = entries.find { it.cid == postedCid }
                    if (candidate != null && candidate.karmaVoteCount > 0) {
                        foundOnA = candidate
                        break
                    }
                    delay(300)
                }

                foundOnA.shouldNotBeNull()
                foundOnA.karmaVoteCount shouldBe 1
            } finally {
                httpClient.close()
                runCatching { serverA.stop() }
                runCatching { serverB.stop() }
            }
        }
    })
