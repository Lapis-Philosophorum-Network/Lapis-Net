package net.lapisphilosophorum.lapisnet.identity

import io.github.oshai.kotlinlogging.KotlinLogging

private val logger = KotlinLogging.logger {}

object Hello {
    fun greet(): String {
        logger.info { "lapis-net-identity initialized" }
        return "Hello from lapis-net-identity"
    }
}
