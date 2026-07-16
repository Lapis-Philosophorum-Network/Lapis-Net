package net.lapisphilosophorum.lapisnet.cli

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.FileIdentityRepository
import net.lapisphilosophorum.lapisnet.identity.defaultIdentityDirectory
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId

private val logger = KotlinLogging.logger {}

fun main() {
    logger.info { "Starting Lapis Net CLI (V0.1.3 skeleton)" }

    val repository = FileIdentityRepository(defaultIdentityDirectory())
    val identity = repository.loadDefault() ?: repository.generateAndSave()

    println("secp256k1 identity fingerprint: ${identity.secp256k1KeyPair.publicKey.fingerprint()}")
    println("Ed25519 (libp2p) fingerprint:   ${identity.ed25519KeyPair.publicKey.fingerprint()}")
    println("identity binding verifies:      ${identity.verifyBinding()}")
    println("libp2p PeerId:                  ${identity.deriveLibp2pPeerId().toBase58()}")

    // No bootstrap dials here - keeps main() fast and non-hanging, with no real network egress
    // required. The multi-node CLI demo (bootstrap dialing, mDNS discovery, connections) lands
    // in V0.1.8's full harness.
    val node = LapisNode.create(identity)
    try {
        node.start(bootstrapPeers = emptyList())
        println("listening on:                   ${node.listenAddresses()}")
    } finally {
        node.stop()
    }

    println("CLI entry point ready for the protocol harness landing in V0.1.8.")
}
