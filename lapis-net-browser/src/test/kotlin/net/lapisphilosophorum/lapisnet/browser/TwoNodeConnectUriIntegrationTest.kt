package net.lapisphilosophorum.lapisnet.browser

import io.kotest.core.spec.style.FunSpec
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
import kotlinx.coroutines.delay
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import java.nio.file.Files
import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

private val json = Json { ignoreUnknownKeys = true }

/**
 * End-to-end proof of the V0.4 QR/deep-link connect flow (Part B): two real, independent
 * [BrowserServer] instances on different loopback ports. Server A's own `GET /api/connect/info` is
 * read via the real HTTP API to obtain its real `lapisnet://connect?...` URI - never hand-built
 * from test-internal knowledge of A's peer id/address, exactly the string a real second device
 * would obtain by scanning A's QR code or copy-pasting its connect link. That URI is then POSTed
 * to server B's `POST /api/connect/uri`, and B's own `GET /api/peers` is polled until it lists A's
 * peer id - proving the whole real-HTTP round trip (info -> URI -> dial -> connected) works, not
 * just [ConnectUri]'s own parse/format unit-level round trip (see [ConnectUriTest]).
 */
class TwoNodeConnectUriIntegrationTest :
    FunSpec({
        test("a lapisnet:// URI read from node A's own /api/connect/info connects node B to node A").config(
            timeout = 60.seconds,
        ) {
            val deadline = Instant.now().plus(Duration.ofSeconds(30))

            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val serverA =
                BrowserServer.start(
                    identity = identityA,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("connect-uri-a"),
                )
            val serverB =
                BrowserServer.start(
                    identity = identityB,
                    httpPort = 0,
                    dataDirectory = Files.createTempDirectory("connect-uri-b"),
                )
            val httpClient = HttpClient(CIO)

            try {
                // Real HTTP read of A's own connect info - the exact string a real client (or QR
                // scan) would obtain, never hand-assembled from test-internal knowledge of A.
                val connectInfoResponse: HttpResponse =
                    httpClient.get("http://127.0.0.1:${serverA.boundPort}/api/connect/info")
                connectInfoResponse.status.value shouldBe 200
                val connectInfo = json.decodeFromString<ConnectInfoResponse>(connectInfoResponse.bodyAsText())
                connectInfo.uri.isNotBlank() shouldBe true

                // B dials A using that exact real URI, via the real POST /api/connect/uri route.
                val connectUriResponse: HttpResponse =
                    httpClient.post("http://127.0.0.1:${serverB.boundPort}/api/connect/uri") {
                        contentType(ContentType.Application.Json)
                        setBody(json.encodeToString(ConnectUriRequest(connectInfo.uri)))
                    }
                connectUriResponse.status.value shouldBe 200
                val connectResult = json.decodeFromString<ConnectUriResponse>(connectUriResponse.bodyAsText())
                connectResult.peerId shouldBe serverA.nodeForTesting.peerId.toBase58()

                // Bounded polling loop against B's real /api/peers HTTP endpoint.
                var connected = false
                while (!connected && Instant.now().isBefore(deadline)) {
                    val peersResponse = httpClient.get("http://127.0.0.1:${serverB.boundPort}/api/peers")
                    val peers = json.decodeFromString<PeersResponse>(peersResponse.bodyAsText())
                    connected = peers.peers.any { it.peerId == serverA.nodeForTesting.peerId.toBase58() }
                    if (!connected) delay(300)
                }

                connected shouldBe true
            } finally {
                httpClient.close()
                runCatching { serverA.stop() }
                runCatching { serverB.stop() }
            }
        }
    })
