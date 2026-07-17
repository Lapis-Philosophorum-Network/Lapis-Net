package net.lapisphilosophorum.lapisnet.networking

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerInfo
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity
import org.slf4j.LoggerFactory

/**
 * Round-2 N1 regression test: [GossipPubSub.attach] is documented as needing to run before
 * [LapisNode.connect] for a peer to actually gossip with, but nothing previously enforced or even
 * warned about the wrong order - a caller who got it wrong saw no error at all (the peer connects
 * fine at the transport level, GossipSub just silently never sees it). [LapisNode.connect] now
 * counts calls made before [LapisNode.gossipAttached] flips true, and [GossipPubSub.attach] reads
 * that count once it finishes wiring up, logging a `warn` iff it's nonzero - see both classes' doc
 * comments for the full reasoning behind checking at attach()-time rather than at each connect()
 * call (a node that never calls [GossipPubSub.attach] at all must never see this warning).
 *
 * Attaches a real Logback [ListAppender] to the root logger (rather than asserting on internal
 * state) so this actually proves the warning is observable, not just that the underlying condition
 * is computed correctly.
 */
class GossipPubSubConnectOrderTest :
    FunSpec({
        test("connect() before attach() logs a warning naming the number of pre-existing connections") {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            val appender = attachListAppender()
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                // Wrong order, deliberately: connect() first, attach() second.
                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))
                val gossipA = GossipPubSub.attach(nodeA)
                val gossipB = GossipPubSub.attach(nodeB)

                val warnings =
                    appender.list.filter {
                        it.level == Level.WARN && it.formattedMessage.contains("GossipPubSub.attach() was called after")
                    }
                warnings shouldHaveSize 1
                warnings.first().formattedMessage.contains("1 LapisNode.connect() call(s)") shouldBe true

                gossipA.stop()
                gossipB.stop()
            } finally {
                detachListAppender(appender)
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }

        test("attach() before connect() (the documented correct order) logs no such warning") {
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            val appender = attachListAppender()
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                // Correct order: attach() first, connect() second - matches all four existing
                // integration tests' actual ordering (TwoNodeGossipPubSubTest,
                // TwoNodeVeritasGossipIntegrationTest, ThreeNodeVeritasGossipRelayTest,
                // VeritasGossipNegativePathIntegrationTest).
                val gossipA = GossipPubSub.attach(nodeA)
                val gossipB = GossipPubSub.attach(nodeB)
                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val warnings =
                    appender.list.filter {
                        it.level == Level.WARN && it.formattedMessage.contains("GossipPubSub.attach() was called after")
                    }
                warnings.shouldBeEmpty()

                gossipA.stop()
                gossipB.stop()
            } finally {
                detachListAppender(appender)
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }

        test("connect() with GossipPubSub.attach() never called at all logs no such warning") {
            // Trivial by construction: the only code that logs the warning lives inside
            // GossipPubSub.attach() itself (it reads the pre-existing-connect-call count once,
            // when it finishes wiring up - see the class doc comment), which never runs in this
            // scenario. Included anyway per round-3 reviewer request, for completeness alongside
            // the two ordering tests above - a node that only ever calls LapisNode.connect() and
            // never attaches GossipPubSub at all must never see this warning either.
            val nodeA = LapisNode.create(DualKeyIdentity.generate())
            val nodeB = LapisNode.create(DualKeyIdentity.generate())
            val appender = attachListAppender()
            try {
                nodeA.start(bootstrapPeers = emptyList())
                nodeB.start(bootstrapPeers = emptyList())

                // GossipPubSub.attach() is deliberately never called on either node.
                nodeA.connect(PeerInfo(nodeB.peerId, nodeB.listenAddresses()))

                val warnings =
                    appender.list.filter {
                        it.level == Level.WARN && it.formattedMessage.contains("GossipPubSub.attach() was called after")
                    }
                warnings.shouldBeEmpty()
            } finally {
                detachListAppender(appender)
                runCatching { nodeA.stop() }
                runCatching { nodeB.stop() }
            }
        }
    })

private fun attachListAppender(): ListAppender<ILoggingEvent> {
    val root = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as Logger
    val appender = ListAppender<ILoggingEvent>()
    appender.context = root.loggerContext
    appender.start()
    root.addAppender(appender)
    return appender
}

private fun detachListAppender(appender: ListAppender<ILoggingEvent>) {
    val root = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as Logger
    root.detachAppender(appender)
    appender.stop()
}
