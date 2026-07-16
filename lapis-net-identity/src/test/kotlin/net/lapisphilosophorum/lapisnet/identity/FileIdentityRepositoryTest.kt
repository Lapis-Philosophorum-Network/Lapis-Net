package net.lapisphilosophorum.lapisnet.identity

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeBytes

private val supportsPosix = "posix" in FileSystems.getDefault().supportedFileAttributeViews()

class FileIdentityRepositoryTest :
    FunSpec({
        lateinit var tempDir: java.nio.file.Path

        beforeEach { tempDir = createTempDirectory("lapis-net-identity-test") }
        afterEach { tempDir.toFile().deleteRecursively() }

        test("loadDefault on an empty repository returns null") {
            val repository = FileIdentityRepository(tempDir.resolve("identity"))
            repository.loadDefault().shouldBeNull()
        }

        test("generateAndSave then loadDefault round-trips through real disk I/O") {
            val repository = FileIdentityRepository(tempDir.resolve("identity"))
            val generated = repository.generateAndSave()
            val loaded = repository.loadDefault()

            loaded shouldNotBe null
            loaded!!.secp256k1KeyPair.privateKey shouldBe generated.secp256k1KeyPair.privateKey
            loaded.secp256k1KeyPair.publicKey shouldBe generated.secp256k1KeyPair.publicKey
            loaded.ed25519KeyPair.privateKey shouldBe generated.ed25519KeyPair.privateKey
            loaded.ed25519KeyPair.publicKey shouldBe generated.ed25519KeyPair.publicKey
            loaded.verifyBinding() shouldBe true
        }

        test("saved keystore file has POSIX 0600 permissions") {
            if (!supportsPosix) return@test
            val repository = FileIdentityRepository(tempDir.resolve("identity"))
            repository.generateAndSave()

            val file = Files.list(tempDir.resolve("identity")).use { it.findFirst().orElseThrow() }
            val permissions = Files.getPosixFilePermissions(file)
            PosixFilePermissions.toString(permissions) shouldBe "rw-------"
        }

        test("load refuses a keystore file with loosened permissions") {
            if (!supportsPosix) return@test
            val repository = FileIdentityRepository(tempDir.resolve("identity"))
            repository.generateAndSave()

            val file = Files.list(tempDir.resolve("identity")).use { it.findFirst().orElseThrow() }
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"))

            io.kotest.assertions.throwables.shouldThrow<IllegalStateException> {
                repository.loadDefault()
            }
        }

        test("load rejects a truncated keystore file") {
            val repository = FileIdentityRepository(tempDir.resolve("identity"))
            repository.generateAndSave()

            val file = Files.list(tempDir.resolve("identity")).use { it.findFirst().orElseThrow() }
            file.writeBytes(ByteArray(10))

            io.kotest.assertions.throwables.shouldThrow<CorruptedIdentityFileException> {
                repository.loadDefault()
            }
        }

        test("list returns a handle per saved label without exposing private key material") {
            val repository = FileIdentityRepository(tempDir.resolve("identity"))
            val alice = repository.generateAndSave(label = "alice")
            val bob = repository.generateAndSave(label = "bob")

            val handles = repository.list()
            handles.map { it.label }.sorted() shouldBe listOf("alice", "bob")
            val aliceFingerprint = alice.secp256k1KeyPair.publicKey.fingerprint()
            val bobFingerprint = bob.secp256k1KeyPair.publicKey.fingerprint()
            handles.first { it.label == "alice" }.secp256k1Fingerprint shouldBe aliceFingerprint
            handles.first { it.label == "bob" }.secp256k1Fingerprint shouldBe bobFingerprint
        }
    })
