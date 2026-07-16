package net.lapisphilosophorum.lapisnet.core

import io.github.oshai.kotlinlogging.KotlinLogging

private val logger = KotlinLogging.logger {}

object Hello {
    fun greet(): String {
        logger.info { "lapis-net-core initialized" }
        return "Hello from lapis-net-core"
    }
}
