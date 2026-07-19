package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ipfs.cid.Cid
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.http.content.staticResources
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.libp2p.core.PeerInfo
import io.libp2p.core.multiformats.Multiaddr
import kotlinx.serialization.Serializable
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey
import net.lapisphilosophorum.lapisnet.karma.KarmaGossip
import net.lapisphilosophorum.lapisnet.karma.KarmaVote
import net.lapisphilosophorum.lapisnet.karma.KarmaVoteCodec
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import net.lapisphilosophorum.lapisnet.trust.MAX_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.MIN_TRUST_MICROS
import net.lapisphilosophorum.lapisnet.trust.TrustGraph
import net.lapisphilosophorum.lapisnet.trust.VeritasGossip
import net.lapisphilosophorum.lapisnet.trust.VeritasGrant
import net.lapisphilosophorum.lapisnet.trust.VeritasGrantCodec
import net.lapisphilosophorum.lapisnet.virtus.LtrGossip

private val logger = KotlinLogging.logger {}

@Serializable
data class IdentityResponse(
    val fingerprint: String,
    val peerId: String,
)

@Serializable
data class TimelinePostResponse(
    val cid: String,
    val author: String,
    /** The author's full 33-byte compressed secp256k1 public key, hex-encoded - unlike [author]
     * (a short, one-way [Secp256k1PublicKey.fingerprint], display-only), this is what the client
     * must send back as `targetPublicKeyHex` in a `POST /api/trust` call to rate this author -
     * a fingerprint alone cannot be reversed back into a usable public key. */
    val authorPublicKeyHex: String,
    val text: String,
    val publishedAtEpochSeconds: Long,
    val credibilityLevel: String,
    val credibilityScoreMicros: Int,
    val ltrWeightMsat: Double,
    val ltrRecordCount: Int,
    val karmaScore: Double,
    val karmaVoteCount: Int,
)

@Serializable
data class NewPostRequest(
    val text: String,
)

@Serializable
data class NewPostResponse(
    val cid: String,
)

@Serializable
data class NewKarmaVoteRequest(
    val targetCid: String,
)

@Serializable
data class NewKarmaVoteResponse(
    val targetCid: String,
    val karmaVoteCount: Int,
)

@Serializable
data class TrustRequest(
    val targetPublicKeyHex: String,
    val trustMicros: Int,
    val comment: String = "",
)

@Serializable
data class TrustResponse(
    val target: String,
    val trustMicros: Int,
)

@Serializable
data class PeerSummary(
    val peerId: String,
    val remoteAddress: String,
)

@Serializable
data class PeersResponse(
    val peers: List<PeerSummary>,
)

@Serializable
data class ConnectPeerRequest(
    val multiaddr: String,
)

@Serializable
data class ConnectPeerResponse(
    val peerId: String,
)

@Serializable
data class ErrorResponse(
    val error: String,
)

@Serializable
data class ConnectInfoResponse(
    val multiaddr: String,
    val publicKeyHex: String,
    val uri: String,
)

@Serializable
data class ConnectUriRequest(
    val uri: String,
)

@Serializable
data class ConnectUriResponse(
    val peerId: String,
    val publicKeyHex: String,
)

@Serializable
data class SelfLinkRequest(
    val targetPublicKeyHex: String,
    val label: String = "",
)

@Serializable
data class SelfLinkResponse(
    val target: String,
    val trustMicros: Int,
)

/** Marker text returned by `GET /api/timeline` in place of a post's real text when the local
 * [NabuStorage.get] lookup misses - see that route's doc comment for why this happens (a
 * gossip-received post whose body bytes this node never durably stored, e.g. past the persistence
 * cap) and why it must never crash or silently return `null`/omit the entry instead. */
const val CONTENT_UNAVAILABLE_MARKER = "<content unavailable>"

/**
 * Everything [installBrowserApi] needs to serve the browser MVP's JSON routes - a plain data
 * holder, not a lifecycle owner (see [BrowserServer], which owns and stops each of these).
 */
class BrowserApiDependencies(
    val identity: DualKeyIdentity,
    val node: LapisNode,
    val storage: NabuStorage,
    val veritas: VeritasGossip,
    val virtus: LtrGossip,
    val karma: KarmaGossip,
    val posts: PostAnnouncementGossip,
    val karmaAnchorCache: KarmaAnchorCache,
)

/**
 * Installs the browser MVP's JSON API routes plus the static UI (see
 * `src/main/resources/static/`) onto [this] [Application]. Called both by [BrowserServer.start]
 * (a real embedded server) and by tests via Ktor's `testApplication { application { ... } }` test
 * host - kept as a standalone `Application.()` extension specifically so both call sites share the
 * exact same route wiring instead of it living only inside [BrowserServer]'s `embeddedServer { }`
 * lambda.
 */
fun Application.installBrowserApi(deps: BrowserApiDependencies) {
    // No CORS plugin is installed here - Ktor never emits Access-Control-Allow-Origin without
    // one, which incidentally blocks browser-originated cross-origin requests today on top of
    // the 127.0.0.1-only bind (see BrowserServer's doc comment). Confirmed safe as of the V0.2.2
    // review; revisit with a real CORS policy if this ever needs to serve a UI hosted elsewhere.
    install(ContentNegotiation) { json() }
    // Defense-in-depth: catches any exception a route handler doesn't explicitly handle (e.g. an
    // unanticipated NabuStorageException from a future route) so it can never reach the client as
    // Ktor's default response, which echoes the raw exception message - including local
    // filesystem paths, as NabuStorageException's messages routinely do (see NabuStorage's doc
    // comments). The real exception is logged server-side; the client only ever sees a generic,
    // sanitized message.
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            logger.error(cause) { "unhandled exception in a browser API route" }
            call.respond(HttpStatusCode.InternalServerError, ErrorResponse("internal server error"))
        }
    }
    routing {
        get("/api/identity") {
            call.respond(
                IdentityResponse(
                    fingerprint =
                        deps.identity.secp256k1KeyPair.publicKey
                            .fingerprint(),
                    peerId = deps.node.peerId.toBase58(),
                ),
            )
        }

        get("/api/timeline") {
            val includeFiltered = call.request.queryParameters["includeFiltered"]?.toBooleanStrictOrNull() ?: false

            val graph = TrustGraph.fromGrants(deps.veritas.currentGrants())
            val tracked = deps.posts.currentPosts()
            val candidates =
                tracked.map { indexed ->
                    TimelineCandidate(
                        cid = indexed.cid,
                        author = indexed.announcement.author,
                        publishedAtEpochSeconds = indexed.announcement.timestampSeconds,
                    )
                }
            // Single-view pilot stage - every lookup is scoped to PLACEHOLDER_VIEW_ID, see that
            // constant's doc comment.
            val ltrRecordsByCid =
                tracked.associate { indexed ->
                    indexed.cid to deps.virtus.currentRecords(indexed.cid, PLACEHOLDER_VIEW_ID)
                }
            val karmaVotesByCid =
                tracked.associate { indexed ->
                    indexed.cid to deps.karma.currentVotesForTarget(indexed.cid)
                }

            val entries =
                TimelineBuilder.build(
                    graph = graph,
                    localIdentity = deps.identity.secp256k1KeyPair.publicKey,
                    candidates = candidates,
                    ltrRecordsByCid = ltrRecordsByCid,
                    karmaVotesByCid = karmaVotesByCid,
                    karmaVotesByVoter = deps.karma::currentVotesByVoter,
                )
            val visible = TimelineBuilder.visible(entries, includeFilteredContent = includeFiltered)

            val response =
                visible.map { entry ->
                    // A gossip-received post's body bytes might not be durably stored locally -
                    // e.g. past PostAnnouncementIndex's body- or wrapper-persistence caps, or a
                    // genuine local storage fault. NabuStorage.get() documents that a real fault
                    // (as opposed to a plain not-found) THROWS NabuStorageException rather than
                    // returning null - runCatching here ensures one corrupted/faulty local block
                    // degrades to the placeholder for that entry only, never fails the whole
                    // response (and never leaks the raw exception message, which can include
                    // local filesystem paths - see NabuStorage's doc comments).
                    val text =
                        runCatching { deps.storage.get(entry.cid) }
                            .getOrNull()
                            ?.toString(Charsets.UTF_8)
                            ?: CONTENT_UNAVAILABLE_MARKER
                    TimelinePostResponse(
                        cid = entry.cid.toString(),
                        author = entry.author.fingerprint(),
                        authorPublicKeyHex = entry.author.bytes.toHexString(),
                        text = text,
                        publishedAtEpochSeconds = entry.publishedAtEpochSeconds,
                        credibilityLevel = entry.credibility.level.name,
                        credibilityScoreMicros = entry.credibility.scoreMicros,
                        ltrWeightMsat = entry.ltrWeightMsat,
                        ltrRecordCount = entry.ltrRecordCount,
                        karmaScore = entry.karmaScore,
                        karmaVoteCount = entry.karmaVoteCount,
                    )
                }
            call.respond(response)
        }

        post("/api/posts") {
            val request = call.receive<NewPostRequest>()
            val bytes = request.text.toByteArray(Charsets.UTF_8)
            if (bytes.size !in 1..MAX_POST_BODY_BYTES) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse("text must be 1..$MAX_POST_BODY_BYTES UTF-8 bytes, was ${bytes.size}"),
                )
                return@post
            }
            val announcement = PostAnnouncement.create(deps.identity.secp256k1KeyPair, bytes)
            val cid = deps.posts.announce(announcement)
            call.respond(NewPostResponse(cid.toString()))
        }

        post("/api/karma") {
            val request = call.receive<NewKarmaVoteRequest>()
            val targetCid = parseCidOrNull(request.targetCid)
            if (targetCid == null) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("targetCid is not a valid CID"))
                return@post
            }
            // Resolves (or lazily populates, on this identity's first-ever vote) this node's own
            // Bitcoin time anchor - a real, client-side Electrum lookup, never a chain call in the
            // gossip path (see KarmaGossip's doc comment). KarmaAnchorResolutionException covers
            // every real failure mode (LookupFailed, a chain-tip query failure, an inconsistent
            // cached genesis/tip pair) - caught here so a transient Electrum outage degrades to a
            // clean 502 response, never an uncaught exception (the installed StatusPages handler
            // would also catch it, but a dedicated response here gives the caller a clearer,
            // Karma-specific error message than the generic "internal server error" fallback).
            val timeAnchor =
                try {
                    deps.karmaAnchorCache.currentClaimFor(deps.identity.secp256k1KeyPair)
                } catch (e: KarmaAnchorResolutionException) {
                    logger.warn(e) { "failed to resolve time anchor for a Karma vote" }
                    call.respond(
                        HttpStatusCode.BadGateway,
                        ErrorResponse("failed to resolve this identity's Bitcoin time anchor: ${e.message}"),
                    )
                    return@post
                }
            val vote = KarmaVote.create(deps.identity.secp256k1KeyPair, targetCid, timeAnchor)
            deps.karma.announce(vote)
            val karmaVoteCount = deps.karma.currentVotesForTarget(targetCid).size
            call.respond(NewKarmaVoteResponse(targetCid = targetCid.toString(), karmaVoteCount = karmaVoteCount))
        }

        post("/api/trust") {
            val request = call.receive<TrustRequest>()
            val target = parseHexPublicKeyOrNull(request.targetPublicKeyHex)
            if (target == null) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse("targetPublicKeyHex must be a 33-byte compressed secp256k1 public key in hex"),
                )
                return@post
            }
            if (request.trustMicros !in MIN_TRUST_MICROS..MAX_TRUST_MICROS) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse("trustMicros must be in $MIN_TRUST_MICROS..$MAX_TRUST_MICROS"),
                )
                return@post
            }
            val grant =
                VeritasGrant.create(
                    truster = deps.identity.secp256k1KeyPair,
                    target = target,
                    trustMicros = request.trustMicros,
                    comment = request.comment,
                )
            deps.veritas.announce(grant)
            call.respond(TrustResponse(target = target.fingerprint(), trustMicros = request.trustMicros))
        }

        get("/api/peers") {
            val peers =
                deps.node.host.network.connections.map { connection ->
                    PeerSummary(
                        peerId = connection.secureSession().remoteId.toBase58(),
                        remoteAddress = connection.remoteAddress().toString(),
                    )
                }
            call.respond(PeersResponse(peers))
        }

        post("/api/peers/connect") {
            val request = call.receive<ConnectPeerRequest>()
            val multiaddr = runCatching { Multiaddr(request.multiaddr) }.getOrNull()
            val peerId = multiaddr?.getPeerId()
            if (multiaddr == null || peerId == null) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse(
                        "multiaddr must be a valid libp2p multiaddr including a /p2p/<peerId> component",
                    ),
                )
                return@post
            }
            runCatching { deps.node.connect(PeerInfo(peerId, listOf(multiaddr))) }
                .onSuccess { call.respond(ConnectPeerResponse(peerId.toBase58())) }
                .onFailure { error ->
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("failed to connect: ${error.message}"))
                }
        }

        // --- V0.4: QR-code / deep-link key exchange (Part B) + self-trust-linking (Part C) ---

        get("/api/connect/info") {
            val maddr = deps.node.bestDialableMultiaddr()
            val pkHex =
                deps.identity.secp256k1KeyPair.publicKey.bytes
                    .toHexString()
            if (maddr == null) {
                call.respond(ConnectInfoResponse(multiaddr = "", publicKeyHex = pkHex, uri = ""))
                return@get
            }
            val uri = ConnectUri.of(maddr, deps.identity.secp256k1KeyPair.publicKey).toUriString()
            call.respond(ConnectInfoResponse(multiaddr = maddr.toString(), publicKeyHex = pkHex, uri = uri))
        }

        get("/api/connect/qr.svg") {
            val maddr = deps.node.bestDialableMultiaddr()
            if (maddr == null) {
                call.respond(HttpStatusCode.ServiceUnavailable, ErrorResponse("no dialable listen address yet"))
                return@get
            }
            val uri = ConnectUri.of(maddr, deps.identity.secp256k1KeyPair.publicKey).toUriString()
            val svg = QrCodeSvg.render(uri)
            call.respondText(svg, ContentType.Image.SVG)
        }

        post("/api/connect/uri") {
            val request = call.receive<ConnectUriRequest>()
            val parsed = ConnectUri.parseOrNull(request.uri)
            if (parsed == null) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("not a valid lapisnet://connect URI"))
                return@post
            }
            val peerId = parsed.multiaddr.getPeerId()!!
            runCatching { deps.node.connect(PeerInfo(peerId, listOf(parsed.multiaddr))) }
                .onSuccess {
                    call.respond(
                        ConnectUriResponse(
                            peerId = peerId.toBase58(),
                            publicKeyHex = parsed.publicKey.bytes.toHexString(),
                        ),
                    )
                }.onFailure { error ->
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("failed to connect: ${error.message}"))
                }
        }

        // Reuses the EXISTING VeritasGrant model verbatim at MAX_TRUST_MICROS - no schema change,
        // no new signature domain tag, no special gossip-path validation (see architecture.adoc
        // "Self-trust linking (V0.4)"). This creates NO new Sybil attack surface: an A->B self-link
        // only propagates A's pre-existing standing one hop further; it cannot manufacture trust a
        // third party didn't already have a path to, and TrustPathFinder's shortest-path rule makes
        // the near (already-known) edge decisive over any far self-linked sock-puppet edge.
        post("/api/self-link") {
            val request = call.receive<SelfLinkRequest>()
            val target = parseHexPublicKeyOrNull(request.targetPublicKeyHex)
            if (target == null) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ErrorResponse("targetPublicKeyHex must be a 33-byte compressed secp256k1 public key in hex"),
                )
                return@post
            }
            if (target == deps.identity.secp256k1KeyPair.publicKey) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("cannot self-link to your own identity"))
                return@post
            }
            val comment = if (request.label.isBlank()) "self-link" else "self-link: ${request.label}"
            // Validate the resulting comment fits VeritasGrantCodec's byte limit BEFORE calling
            // VeritasGrant.create, so an over-long label returns a clean 400 instead of an
            // uncaught IllegalArgumentException from VeritasGrant's init block (mirrors the
            // /api/posts byte-count 400 pattern for MAX_POST_BODY_BYTES). Never silently truncate
            // a user-supplied label.
            if (comment.toByteArray(Charsets.UTF_8).size > VeritasGrantCodec.MAX_COMMENT_BYTES) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse("label is too long"))
                return@post
            }
            val grant =
                VeritasGrant.create(
                    truster = deps.identity.secp256k1KeyPair,
                    target = target,
                    trustMicros = MAX_TRUST_MICROS,
                    comment = comment,
                )
            deps.veritas.announce(grant)
            call.respond(SelfLinkResponse(target = target.fingerprint(), trustMicros = MAX_TRUST_MICROS))
        }

        // Serves src/main/resources/static/ (index.html, style.css, app.js) at the site root -
        // e.g. /index.html, /style.css, /app.js. Mapped LAST relative to the /api/* routes above
        // only for readability; Ktor's routing tree dispatches by exact path match, so ordering
        // among these routes has no behavioral effect.
        staticResources("/", "static")
    }
}

/** Parses [hex] as a 33-byte compressed secp256k1 public key, or `null` for any malformed input
 * (wrong length, non-hex characters, or bytes that don't represent a valid curve point) - never
 * throws, so route handlers can turn this straight into a 400 response instead of crashing. */
private fun parseHexPublicKeyOrNull(hex: String): Secp256k1PublicKey? {
    if (hex.length != 66 || hex.any { it !in HEX_CHARS }) return null
    val bytes = ByteArray(33) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    return runCatching { Secp256k1PublicKey(bytes) }.getOrNull()
}

private val HEX_CHARS = "0123456789abcdefABCDEF"

private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

/** Cheap upper bound on an incoming CID string's length, checked BEFORE it ever reaches
 * [Cid.decode] - mirrors [parseHexPublicKeyOrNull]'s exact-length precondition check, just looser
 * since a base-encoded (base32/base58/etc.) CID string has no single exact length the way a fixed
 * 33-byte hex public key does. Derived from
 * [net.lapisphilosophorum.lapisnet.karma.KarmaVoteCodec.MAX_CID_BYTES] (128 raw bytes) with a
 * generous 4x multiplier to cover multibase encoding expansion (base32 ~1.6x, base58btc ~1.37x,
 * plus a multibase prefix character) - not a tight bound, just enough headroom to reject an
 * obviously-oversized string before wasting decode work on it. */
private val MAX_CID_STRING_LENGTH = KarmaVoteCodec.MAX_CID_BYTES * 4

/** Parses [value] as a [Cid], or `null` for any malformed input - never throws, so route handlers
 * can turn this straight into a 400 response instead of crashing, mirroring
 * [parseHexPublicKeyOrNull]'s established pattern for this file. */
private fun parseCidOrNull(value: String): Cid? {
    if (value.length > MAX_CID_STRING_LENGTH) return null
    return runCatching { Cid.decode(value) }.getOrNull()
}

/** Picks the "best" dialable multiaddr for this node to advertise (V0.4 QR/deep-link connect,
 * see [ConnectUri]): prefers a non-loopback listen address over a `127.0.0.1`/`::1` one, and
 * always appends `/p2p/<peerId>` so the result is directly usable by [LapisNode.connect]/
 * [PeerInfo] on the receiving side. Returns `null` only if this node has no listen address at all
 * (should not happen for a started [LapisNode], but this file never assumes that at a route
 * boundary - see this function's callers' own null-handling). */
private fun LapisNode.bestDialableMultiaddr(): Multiaddr? {
    val addrs = listenAddresses()
    if (addrs.isEmpty()) return null
    val nonLoopback = addrs.firstOrNull { !it.toString().contains("/127.0.0.1/") && !it.toString().contains("/::1/") }
    return (nonLoopback ?: addrs.first()).withP2P(peerId)
}
