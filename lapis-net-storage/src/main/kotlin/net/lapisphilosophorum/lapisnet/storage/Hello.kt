package net.lapisphilosophorum.lapisnet.storage

import io.github.oshai.kotlinlogging.KotlinLogging

private val logger = KotlinLogging.logger {}

object Hello {
    fun greet(): String {
        logger.info { "lapis-net-storage initialized" }
        return "Hello from lapis-net-storage"
    }
}
