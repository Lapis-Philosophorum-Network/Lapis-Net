package net.lapisphilosophorum.lapisnet.cli

import io.github.oshai.kotlinlogging.KotlinLogging
import net.lapisphilosophorum.lapisnet.identity.FileIdentityRepository
import net.lapisphilosophorum.lapisnet.identity.defaultIdentityDirectory
import net.lapisphilosophorum.lapisnet.networking.LapisNode
import net.lapisphilosophorum.lapisnet.networking.deriveLibp2pPeerId
import net.lapisphilosophorum.lapisnet.storage.NabuStorage
import java.nio.file.Files

private val logger = KotlinLogging.logger {}

fun main() {
    logger.info { "Starting Lapis Net CLI (V0.1.4 skeleton)" }

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

        // Single-node local storage demo - no DHT/Bitswap network exercise here, just proof
        // that Nabu's blockstore is wired up. The multi-node protocol harness lands in V0.1.8.
        // Temp directory is left in place (JVM/OS temp cleanup applies) - not worth the extra
        // recursive-delete machinery for a throwaway demo directory.
        val storage = NabuStorage.attach(node, Files.createTempDirectory("lapisnet-cli-storage"))
        try {
            val cid = storage.put("hello from the Lapis Net CLI storage demo".toByteArray())
            val roundTripped = storage.get(cid)
            println("Nabu storage demo: put+get cid $cid succeeded: ${roundTripped != null}")
        } finally {
            storage.stop()
        }
    } finally {
        node.stop()
    }

    println("CLI entry point ready for the protocol harness landing in V0.1.8.")
}
