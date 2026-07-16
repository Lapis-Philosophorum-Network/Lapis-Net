package net.lapisphilosophorum.lapisnet.networking

import io.github.oshai.kotlinlogging.KotlinLogging

private val logger = KotlinLogging.logger {}

object Hello {
    fun greet(): String {
        logger.info { "lapis-net-networking initialized" }
        return "Hello from lapis-net-networking"
    }
}
