package net.lapisphilosophorum.lapisnet.cli

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.FileIdentityRepository
import net.lapisphilosophorum.lapisnet.identity.defaultIdentityDirectory

private val logger = KotlinLogging.logger {}

fun main() {
    logger.info { "Starting Lapis Net CLI (V0.1.2 skeleton)" }

    val repository = FileIdentityRepository(defaultIdentityDirectory())
    val identity = repository.loadDefault() ?: repository.generateAndSave()

    println("secp256k1 identity fingerprint: ${identity.secp256k1KeyPair.publicKey.fingerprint()}")
    println("Ed25519 (libp2p) fingerprint:   ${identity.ed25519KeyPair.publicKey.fingerprint()}")
    println("identity binding verifies:      ${identity.verifyBinding()}")
    println("CLI entry point ready for the protocol harness landing in V0.1.8.")
}
