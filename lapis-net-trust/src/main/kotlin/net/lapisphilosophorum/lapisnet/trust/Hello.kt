package net.lapisphilosophorum.lapisnet.trust

import io.github.oshai.kotlinlogging.KotlinLogging

private val logger = KotlinLogging.logger {}

object Hello {
    fun greet(): String {
        logger.info { "lapis-net-trust initialized" }
        return "Hello from lapis-net-trust"
    }
}
