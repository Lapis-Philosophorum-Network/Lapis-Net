package net.lapisphilosophorum.lapisnet.networking

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import java.nio.file.Files

private fun randomBootstrapMultiaddr(port: Int = 4001): String =
    "/ip4/203.0.113.10/tcp/$port/p2p/${PeerId.random().toBase58()}"

class BootstrapConfigTest :
    FunSpec({
        test("resolve returns empty when nothing configured") {
            val emptyHome = Files.createTempDirectory("bootstrap-config-test-empty")
            BootstrapConfig.resolve(env = emptyMap(), lapisnetHome = emptyHome) shouldBe emptyList()
        }

        test("resolve parses comma-separated env var multiaddrs including /p2p") {
            val emptyHome = Files.createTempDirectory("bootstrap-config-test-env")
            val a = randomBootstrapMultiaddr(4001)
            val b = randomBootstrapMultiaddr(4002)
            val resolved =
                BootstrapConfig.resolve(
                    env = mapOf(BootstrapConfig.ENV_VAR to "$a,$b"),
                    lapisnetHome = emptyHome,
                )
            resolved shouldContainExactlyInAnyOrder listOf(Multiaddr(a), Multiaddr(b))
        }

        test("resolve skips a malformed env entry but keeps valid ones") {
            val emptyHome = Files.createTempDirectory("bootstrap-config-test-malformed")
            val valid = randomBootstrapMultiaddr()
            val resolved =
                BootstrapConfig.resolve(
                    env = mapOf(BootstrapConfig.ENV_VAR to "not-a-multiaddr-at-all,$valid"),
                    lapisnetHome = emptyHome,
                )
            resolved shouldContainExactlyInAnyOrder listOf(Multiaddr(valid))
        }

        test("resolve rejects a multiaddr lacking a /p2p component") {
            val emptyHome = Files.createTempDirectory("bootstrap-config-test-nop2p")
            val resolved =
                BootstrapConfig.resolve(
                    env = mapOf(BootstrapConfig.ENV_VAR to "/ip4/203.0.113.10/tcp/4001"),
                    lapisnetHome = emptyHome,
                )
            resolved shouldBe emptyList()
        }

        test("resolve reads and merges a bootstrap.peers file, ignoring comments and blank lines") {
            val home = Files.createTempDirectory("bootstrap-config-test-file")
            val a = randomBootstrapMultiaddr(4001)
            val b = randomBootstrapMultiaddr(4002)
            Files.writeString(
                home.resolve(BootstrapConfig.FILE_NAME),
                "# a comment\n\n$a\n\n# another comment\n$b\n",
            )
            val resolved = BootstrapConfig.resolve(env = emptyMap(), lapisnetHome = home)
            resolved shouldContainExactlyInAnyOrder listOf(Multiaddr(a), Multiaddr(b))
        }

        test("resolve merges env and file sources") {
            val home = Files.createTempDirectory("bootstrap-config-test-merge")
            val fromEnv = randomBootstrapMultiaddr(4001)
            val fromFile = randomBootstrapMultiaddr(4002)
            Files.writeString(home.resolve(BootstrapConfig.FILE_NAME), "$fromFile\n")
            val resolved =
                BootstrapConfig.resolve(
                    env = mapOf(BootstrapConfig.ENV_VAR to fromEnv),
                    lapisnetHome = home,
                )
            resolved shouldContainExactlyInAnyOrder listOf(Multiaddr(fromEnv), Multiaddr(fromFile))
        }

        test("resolve caps the number of parsed peers at MAX_BOOTSTRAP_PEERS") {
            val emptyHome = Files.createTempDirectory("bootstrap-config-test-cap")
            val entries = (1..(BootstrapConfig.MAX_BOOTSTRAP_PEERS + 5)).map { randomBootstrapMultiaddr(it) }
            val resolved =
                BootstrapConfig.resolve(
                    env = mapOf(BootstrapConfig.ENV_VAR to entries.joinToString(",")),
                    lapisnetHome = emptyHome,
                )
            resolved shouldHaveSize BootstrapConfig.MAX_BOOTSTRAP_PEERS
        }

        test("resolve de-duplicates identical multiaddrs across env and file") {
            val home = Files.createTempDirectory("bootstrap-config-test-dedup")
            val shared = randomBootstrapMultiaddr()
            Files.writeString(home.resolve(BootstrapConfig.FILE_NAME), "$shared\n")
            val resolved =
                BootstrapConfig.resolve(
                    env = mapOf(BootstrapConfig.ENV_VAR to shared),
                    lapisnetHome = home,
                )
            resolved shouldHaveSize 1
        }

        test("resolveListenAddress defaults to loopback ephemeral") {
            BootstrapConfig.resolveListenAddress(env = emptyMap()) shouldBe Multiaddr("/ip4/127.0.0.1/tcp/0")
        }

        test("resolveListenAddress honors LAPISNET_LISTEN_ADDR") {
            val configured = "/ip4/0.0.0.0/tcp/4001"
            BootstrapConfig.resolveListenAddress(
                env = mapOf(BootstrapConfig.LISTEN_ENV_VAR to configured),
            ) shouldBe Multiaddr(configured)
        }

        test("resolveListenAddress falls back to loopback ephemeral on a malformed value") {
            BootstrapConfig.resolveListenAddress(
                env = mapOf(BootstrapConfig.LISTEN_ENV_VAR to "not-a-multiaddr"),
            ) shouldBe Multiaddr("/ip4/127.0.0.1/tcp/0")
        }
    })
