package net.lapisphilosophorum.lapisnet.browser

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.FileIdentityRepository
import net.lapisphilosophorum.lapisnet.identity.defaultIdentityDirectory
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch

private val logger = KotlinLogging.logger {}

/** Resolves the default on-disk Nabu blockstore directory for the browser MVP:
 * `$LAPISNET_HOME/browser-storage`, or `~/.lapisnet/browser-storage` - a sibling of
 * [defaultIdentityDirectory]'s `identity` directory under the same `LAPISNET_HOME` root. */
private fun defaultBrowserDataDirectory(): Path {
    val home = System.getenv("LAPISNET_HOME") ?: (System.getProperty("user.home") + "/.lapisnet")
    return Path.of(home, "browser-storage")
}

fun main() {
    logger.info { "Starting Lapis Net Browser (V0.2.2 Minimal-Browser MVP)" }

    // Load-or-generate the identity exactly like LapisNetCli.runIdentityAndStorageDemo() does -
    // this process holds the same kind of real signing key, so identity handling must be
    // consistent with the CLI's established, permission-hardened FileIdentityRepository path.
    val repository = FileIdentityRepository(defaultIdentityDirectory())
    val identity = repository.loadDefault() ?: repository.generateAndSave()

    val dataDirectory = defaultBrowserDataDirectory()
    Files.createDirectories(dataDirectory)

    val server = BrowserServer.start(identity = identity, dataDirectory = dataDirectory)

    println("Lapis Net Browser is running.")
    println("Open http://127.0.0.1:${server.boundPort} in your browser.")
    println("Identity fingerprint: ${identity.secp256k1KeyPair.publicKey.fingerprint()}")
    println("Press Ctrl+C to stop.")

    // httpEngine.start(wait = false) inside BrowserServer.start() already returned - this thread
    // must stay alive for the process to keep serving, so it blocks on a latch that only a JVM
    // shutdown hook (SIGINT/SIGTERM) ever counts down, after cleanly stopping the server.
    val shutdownLatch = CountDownLatch(1)
    Runtime.getRuntime().addShutdownHook(
        Thread {
            logger.info { "shutting down Lapis Net Browser" }
            runCatching { server.stop() }
            shutdownLatch.countDown()
        },
    )
    shutdownLatch.await()
}
