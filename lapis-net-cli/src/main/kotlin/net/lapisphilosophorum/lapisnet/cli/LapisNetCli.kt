package net.lapisphilosophorum.lapisnet.cli

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.core.Hello

private val logger = KotlinLogging.logger {}

fun main() {
    logger.info { "Starting Lapis Net CLI (V0.1.1 skeleton)" }
    println(Hello.greet())
    println("CLI entry point ready for the protocol harness landing in V0.1.8.")
}
