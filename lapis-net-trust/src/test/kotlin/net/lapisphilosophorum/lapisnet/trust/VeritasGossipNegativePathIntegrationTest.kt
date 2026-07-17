package net.lapisphilosophorum.lapisnet.trust

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import net.lapisphilosophorum.lapisnet.identity.Secp256k1KeyPair
import net.lapisphilosophorum.lapisnet.networking.GossipPubSub
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

/**
 * Real two-node setup (no mocking). Publishes raw garbage bytes, a signature-tampered valid-looking
 * encoding, and a structurally-valid grant carrying a degenerate (right-length, cryptographically
 * invalid) signature directly on [VeritasGossip.VERITAS_GRANT_GOSSIP_TOPIC] via [GossipPubSub]
 * (bypassing [VeritasGossip.announce]/[VeritasGrantCodec.encode] entirely, to simulate a malicious
 * or buggy peer), and asserts the receiving node's index stays empty for all three - **and that its
 * subscription is still functional afterward**: a real valid grant published next on the same
 * connection must still be accepted. This is the regression test for "a malformed/malicious
 * gossip message must never kill the subscriber".
 *
 * The degenerate-signature case is round-2's C1 regression test: an all-0xFF 64-byte signature is
 * the right length but not a well-formed `(r, s)` pair at all - before the fix, the native
 * `secp256k1-kmp-jvm` call inside [net.lapisphilosophorum.lapisnet.identity.Secp256k1PublicKey.verify]
 * threw an uncaught `Secp256k1Exception` for exactly this shape instead of returning `false`, and
 * [VeritasGossip.onGossipMessage] called it unguarded - so a peer could crash-propagate this to
 * every relaying node for the cost of one gossip message, no private key needed.
 */
class VeritasGossipNegativePathIntegrationTest :
    FunSpec({
        test(
            "malformed, signature-tampered, and degenerate-signature gossip payloads " +
                "are rejected without breaking the subscription",
        ) {
            val identityA = DualKeyIdentity.generate()
            val identityB = DualKeyIdentity.generate()
            val nodeA = LapisNode.create(identityA)
            val nodeB = LapisNode.create(identityB)
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                val storageA = NabuStorage.attach(nodeA, Files.createTempDirectory("veritas-negative-a"))
                val storageB = NabuStorage.attach(nodeB, Files.createTempDirectory("veritas-negative-b"))

                val pubsubA = GossipPubSub.attach(nodeA)
                val pubsubB = GossipPubSub.attach(nodeB)
                val veritasB = VeritasGossip.attach(pubsubB, storageB)

                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val truster = identityA.secp256k1KeyPair
                val target = Secp256k1KeyPair.generate().publicKey

                val garbage = ByteArray(64) { it.toByte() } // not a valid VeritasGrantCodec encoding at all
                val validGrant = VeritasGrant.create(truster, target, trustMicros = 400_000)
                val tamperedBytes = VeritasGrantCodec.encode(validGrant)
                tamperedBytes[tamperedBytes.size - 1] = (tamperedBytes[tamperedBytes.size - 1] + 1).toByte()

                // Structurally-valid encoding, but the trailing 64-byte signature is overwritten
                // with a degenerate all-0xFF value - right length, not a well-formed (r, s) pair.
                // VeritasGrantCodec.decode() does not verify signatures (see its doc comment), so
                // this decodes successfully; it must still be rejected, and rejected WITHOUT the
                // native verify() call throwing past onGossipMessage's control flow.
                val degenerateSignatureGrant =
                    VeritasGrant.create(truster, target, trustMicros = 450_000, comment = "degenerate sig")
                val degenerateSignatureBytes = VeritasGrantCodec.encode(degenerateSignatureGrant)
                for (i in degenerateSignatureBytes.size - 64 until degenerateSignatureBytes.size) {
                    degenerateSignatureBytes[i] = 0xFF.toByte()
                }

                // Publish all three malicious payloads directly via GossipPubSub, bypassing
                // VeritasGossip.announce()/VeritasGrantCodec.encode() entirely - a real malicious
                // peer would not go through this project's own encoder.
                val settleDeadline = Instant.now().plus(Duration.ofSeconds(15))
                while (Instant.now().isBefore(settleDeadline)) {
                    pubsubA.publish(VeritasGossip.VERITAS_GRANT_GOSSIP_TOPIC, garbage)
                    pubsubA.publish(VeritasGossip.VERITAS_GRANT_GOSSIP_TOPIC, tamperedBytes)
                    pubsubA.publish(VeritasGossip.VERITAS_GRANT_GOSSIP_TOPIC, degenerateSignatureBytes)
                    Thread.sleep(500)
                    // Give the malicious payloads a real chance to be processed before moving on -
                    // there's nothing to poll FOR here (we expect nothing to arrive), so this loop
                    // just spends the mesh-formation window retrying delivery, then falls through.
                    if (veritasB.currentGrants().isNotEmpty()) break
                }

                veritasB.currentGrants().shouldBeEmpty()

                // The subscription must still be functional: a real valid grant sent next on the
                // same connection must be accepted normally.
                val deadline = Instant.now().plus(Duration.ofSeconds(20))
                var grantsOnB = veritasB.currentGrants()
                while (grantsOnB.isEmpty() && Instant.now().isBefore(deadline)) {
                    pubsubA.publish(VeritasGossip.VERITAS_GRANT_GOSSIP_TOPIC, VeritasGrantCodec.encode(validGrant))
                    Thread.sleep(500)
                    grantsOnB = veritasB.currentGrants()
                }

                grantsOnB shouldBe listOf(validGrant)

                veritasB.stop()
                pubsubA.stop()
                pubsubB.stop()
            } finally {
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })
