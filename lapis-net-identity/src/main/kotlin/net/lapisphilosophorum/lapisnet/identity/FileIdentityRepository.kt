package net.lapisphilosophorum.lapisnet.identity

import io.github.oshai.kotlinlogging.KotlinLogging
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.exists
import kotlin.io.path.extension
import kotlin.io.path.nameWithoutExtension

private val logger = KotlinLogging.logger {}

private const val KEYSTORE_FILE_EXTENSION = "lnid"
private val VALID_LABEL = Regex("^[A-Za-z0-9_-]{1,64}$")

private val DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
private val FILE_PERMISSIONS = PosixFilePermissions.fromString("rw-------")

/**
 * File-based [IdentityRepository]. Each identity is stored under `<baseDirectory>/<label>.lnid`
 * in the [KeystoreFileFormat] layout.
 *
 * Private key material is stored in plaintext, protected only by POSIX file permissions (0600
 * files, 0700 directory) - the same trust model `ssh-keygen` uses for `~/.ssh/id_ed25519` by
 * default. This is a deliberate, temporary tradeoff for an early prototype: passphrase-derived
 * encryption at rest should land before this key custodies real funds (Lightning). On
 * filesystems without POSIX permission support (e.g. Windows), hardening is skipped with a
 * warning rather than failing - that host should be treated as lower-trust until a Windows ACL
 * equivalent is implemented.
 */
class FileIdentityRepository(
    private val baseDirectory: Path,
) : IdentityRepository {
    init {
        // The directory holds no secret bytes by itself (unlike the keystore files it contains),
        // so a brief default-permission window between creation and hardening is an acceptable
        // trade for the simpler `createDirectories` call, which also creates any missing parents.
        Files.createDirectories(baseDirectory)
        hardenPermissions(baseDirectory, DIRECTORY_PERMISSIONS)
    }

    /**
     * Lists stored identities. Fully loads (and cryptographically verifies) each one to obtain
     * its fingerprint - the returned [IdentityHandle]s never carry private key material, but a
     * single corrupted or loosely-permissioned file makes the whole call fail loudly rather than
     * silently skipping that entry, consistent with [load]'s tamper-evident-by-default behavior.
     */
    override fun list(): List<IdentityHandle> =
        Files
            .list(baseDirectory)
            .use { paths ->
                paths
                    .filter { it.extension == KEYSTORE_FILE_EXTENSION }
                    .map { it.nameWithoutExtension }
                    .sorted()
                    .toList()
            }.mapNotNull { label ->
                load(label)?.let { IdentityHandle(label, it.secp256k1KeyPair.publicKey.fingerprint()) }
            }

    override fun load(label: String): DualKeyIdentity? {
        val path = fileFor(label)
        if (!path.exists()) return null
        checkPermissionsAreHardened(path)
        return KeystoreFileFormat.decode(Files.readAllBytes(path))
    }

    override fun save(
        identity: DualKeyIdentity,
        label: String,
    ): IdentityHandle {
        val path = fileFor(label)
        // Pass the permissions at creation time (not via a follow-up chmod) so there is never a
        // window where the temp file exists with looser, filesystem-default permissions.
        val tempFile =
            if (supportsPosixPermissions(baseDirectory)) {
                Files.createTempFile(
                    baseDirectory,
                    "$label.",
                    ".tmp",
                    PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS),
                )
            } else {
                Files.createTempFile(baseDirectory, "$label.", ".tmp")
            }
        Files.write(tempFile, KeystoreFileFormat.encode(identity))
        Files.move(tempFile, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        val fingerprint = identity.secp256k1KeyPair.publicKey.fingerprint()
        logger.info { "saved identity '$label' (secp256k1 fingerprint $fingerprint) to $path" }
        return IdentityHandle(label, fingerprint)
    }

    private fun fileFor(label: String): Path {
        require(VALID_LABEL.matches(label)) {
            "invalid identity label '$label' - must match ${VALID_LABEL.pattern} (no path separators or traversal)"
        }
        return baseDirectory.resolve("$label.$KEYSTORE_FILE_EXTENSION")
    }

    private fun supportsPosixPermissions(path: Path): Boolean = "posix" in path.fileSystem.supportedFileAttributeViews()

    private fun hardenPermissions(
        path: Path,
        permissions: Set<PosixFilePermission>,
    ) {
        if (supportsPosixPermissions(path)) {
            Files.setPosixFilePermissions(path, permissions)
        } else {
            logger.warn { "filesystem does not support POSIX permissions - $path is NOT permission-hardened" }
        }
    }

    private fun checkPermissionsAreHardened(path: Path) {
        if (!supportsPosixPermissions(path)) return
        val actual = Files.getPosixFilePermissions(path)
        val tooPermissive =
            actual.any {
                it == PosixFilePermission.GROUP_READ ||
                    it == PosixFilePermission.GROUP_WRITE ||
                    it == PosixFilePermission.GROUP_EXECUTE ||
                    it == PosixFilePermission.OTHERS_READ ||
                    it == PosixFilePermission.OTHERS_WRITE ||
                    it == PosixFilePermission.OTHERS_EXECUTE
            }
        check(!tooPermissive) {
            "refusing to load identity file with loose permissions: $path (expected rw------- / 0600; run `chmod 600 $path`)"
        }
    }
}

/** Resolves the default on-disk identity directory: `$LAPISNET_HOME/identity`, or `~/.lapisnet/identity`. */
fun defaultIdentityDirectory(): Path {
    val home = System.getenv("LAPISNET_HOME") ?: (System.getProperty("user.home") + "/.lapisnet")
    return Path.of(home, "identity")
}
