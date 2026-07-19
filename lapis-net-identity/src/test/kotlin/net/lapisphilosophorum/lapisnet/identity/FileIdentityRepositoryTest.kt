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

private fun fixedPassphraseProvider(passphrase: String): PassphraseProvider =
    PassphraseProvider {
        passphrase.toCharArray()
    }

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

        test("rejects labels that could escape the identity directory") {
            val repository = FileIdentityRepository(tempDir.resolve("identity"))
            val identity = DualKeyIdentity.generate()

            listOf("../escape", "a/b", "/etc/passwd", "..", "").forEach { label ->
                io.kotest.assertions.throwables.shouldThrow<IllegalArgumentException> {
                    repository.save(identity, label)
                }
                io.kotest.assertions.throwables.shouldThrow<IllegalArgumentException> {
                    repository.load(label)
                }
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

        test(
            "generateAndSave then loadDefault round-trips with an encrypting PassphraseProvider, and the on-disk version byte is 2",
        ) {
            val repository =
                FileIdentityRepository(tempDir.resolve("identity"), fixedPassphraseProvider("a passphrase"))
            val generated = repository.generateAndSave()
            val loaded = repository.loadDefault()

            loaded shouldNotBe null
            loaded!!.secp256k1KeyPair.publicKey shouldBe generated.secp256k1KeyPair.publicKey
            loaded.verifyBinding() shouldBe true

            val file = Files.list(tempDir.resolve("identity")).use { it.findFirst().orElseThrow() }
            val bytes = Files.readAllBytes(file)
            KeystoreFileFormat.formatVersionOf(bytes) shouldBe KeystoreFileFormat.FORMAT_VERSION_2
        }

        test("load with the wrong passphrase throws KeystoreDecryptionException") {
            val savingRepository =
                FileIdentityRepository(tempDir.resolve("identity"), fixedPassphraseProvider("correct-passphrase"))
            savingRepository.generateAndSave()

            val loadingRepository =
                FileIdentityRepository(tempDir.resolve("identity"), fixedPassphraseProvider("wrong-passphrase"))
            io.kotest.assertions.throwables.shouldThrow<KeystoreDecryptionException> {
                loadingRepository.loadDefault()
            }
        }

        test("a v1 file is transparently migrated to encrypted v2 on load once a passphrase becomes available") {
            val identityDir = tempDir.resolve("identity")
            val plaintextRepository = FileIdentityRepository(identityDir)
            val generated = plaintextRepository.generateAndSave()

            val file = Files.list(identityDir).use { it.findFirst().orElseThrow() }
            KeystoreFileFormat.formatVersionOf(Files.readAllBytes(file)) shouldBe KeystoreFileFormat.FORMAT_VERSION_1

            val encryptingRepository = FileIdentityRepository(identityDir, fixedPassphraseProvider("a passphrase"))
            val migrated = encryptingRepository.loadDefault()

            migrated shouldNotBe null
            migrated!!.secp256k1KeyPair.publicKey shouldBe generated.secp256k1KeyPair.publicKey
            KeystoreFileFormat.formatVersionOf(Files.readAllBytes(file)) shouldBe KeystoreFileFormat.FORMAT_VERSION_2

            // The migration must be idempotent - a second load reads back the now-v2 file cleanly,
            // with no further re-save required (nothing to assert beyond "it still round-trips").
            val reloaded = encryptingRepository.loadDefault()
            reloaded shouldNotBe null
            reloaded!!.secp256k1KeyPair.publicKey shouldBe generated.secp256k1KeyPair.publicKey
        }

        test("saved encrypted keystore still has POSIX 0600 permissions") {
            if (!supportsPosix) return@test
            val repository =
                FileIdentityRepository(tempDir.resolve("identity"), fixedPassphraseProvider("a passphrase"))
            repository.generateAndSave()

            val file = Files.list(tempDir.resolve("identity")).use { it.findFirst().orElseThrow() }
            val permissions = Files.getPosixFilePermissions(file)
            PosixFilePermissions.toString(permissions) shouldBe "rw-------"
        }
    })
