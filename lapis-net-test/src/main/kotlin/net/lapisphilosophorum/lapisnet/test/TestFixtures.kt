package net.lapisphilosophorum.lapisnet.test

import io.github.oshai.kotlinlogging.KotlinLogging

private val logger = KotlinLogging.logger {}

/**
 * Placeholder for shared multi-node test fixtures (see V0.1.8: minimal CLI/test harness).
 */
object TestFixtures {
    fun describe(): String {
        logger.info { "lapis-net-test initialized" }
        return "Hello from lapis-net-test"
    }
}
