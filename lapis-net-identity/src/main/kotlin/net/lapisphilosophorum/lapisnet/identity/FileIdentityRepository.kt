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

/** Supplies the passphrase used to encrypt/decrypt keystores at rest (V0.4). A `null` passphrase
 * means "no encryption" - retained ONLY for tests and the migration read-path; production entry
 * points MUST supply a real passphrase (see [net.lapisphilosophorum.lapisnet.identity.resolveKeystorePassphrase]). */
fun interface PassphraseProvider {
    /** Returns a fresh [CharArray] each call (the caller zeroes it after use), or `null` for no
     * encryption. */
    fun get(): CharArray?
}

/**
 * File-based [IdentityRepository]. Each identity is stored under `<baseDirectory>/<label>.lnid`
 * in the [KeystoreFileFormat] layout.
 *
 * **As of V0.4, private key material is encrypted at rest** (Argon2id-derived AES-256-GCM, see
 * [KeystoreEncryption]/[KeystoreFileFormat]'s v2 format) whenever [passphraseProvider] supplies a
 * non-null passphrase - on top of, not instead of, the existing POSIX file permissions (0600
 * files, 0700 directory, still enforced unconditionally below). When [passphraseProvider] returns
 * `null` (its default), identities are stored exactly as before V0.4: plaintext, protected only by
 * POSIX permissions - the same trust model `ssh-keygen` uses for `~/.ssh/id_ed25519` by default.
 * This null-provider default exists for two reasons, not one: it keeps every pre-V0.4 test/caller
 * of this class working unchanged (backward compatibility), and it is also the deliberate,
 * documented behavior for a real headless process with no passphrase source available (see
 * `lapis-net-browser`'s `BrowserMain.warningPassphraseProvider` for how a real process turns that
 * into a loud warning rather than a silent downgrade). On filesystems without POSIX permission
 * support (e.g. Windows), permission hardening is skipped with a warning rather than failing -
 * that host should be treated as lower-trust until a Windows ACL equivalent is implemented,
 * regardless of whether encryption at rest is also active.
 */
class FileIdentityRepository(
    private val baseDirectory: Path,
    private val passphraseProvider: PassphraseProvider = PassphraseProvider { null },
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

    /**
     * Loads and decodes the keystore for [label], auto-detecting legacy plaintext (v1) vs.
     * encrypted (v2) - see [KeystoreFileFormat.decodeAuto]. [passphraseProvider] is asked for a
     * passphrase exactly once per call and the [CharArray] it returns is zeroed in a `finally`
     * regardless of outcome, so it never lingers in memory longer than this one call needs it.
     *
     * **v1-to-v2 migration**: if the on-disk file turns out to be legacy plaintext (v1) AND a real
     * passphrase is available from [passphraseProvider], the loaded identity is immediately
     * re-saved encrypted (v2) via [save] before returning - so simply setting a passphrase and
     * continuing to use an existing identity is enough to upgrade it at rest, no separate migration
     * step required. This is naturally idempotent: the very next [load] reads back a v2 file, so
     * the version check above is false and no re-save happens - no extra guard needed.
     */
    override fun load(label: String): DualKeyIdentity? {
        val path = fileFor(label)
        if (!path.exists()) return null
        checkPermissionsAreHardened(path)
        val bytes = Files.readAllBytes(path)
        val passphrase = passphraseProvider.get()
        try {
            val identity = KeystoreFileFormat.decodeAuto(bytes, passphrase)
            if (KeystoreFileFormat.formatVersionOf(bytes) == KeystoreFileFormat.FORMAT_VERSION_1 &&
                passphrase != null
            ) {
                logger.info { "migrating legacy v1 keystore '$label' to encrypted v2 at rest" }
                save(identity, label)
            }
            return identity
        } finally {
            passphrase?.fill('\u0000')
        }
    }

    /**
     * Encodes and durably (atomically) writes [identity] under [label]. Encrypted (v2, see
     * [KeystoreFileFormat.encodeEncrypted]) whenever [passphraseProvider] supplies a non-null
     * passphrase, else plaintext (v1, unchanged pre-V0.4 behavior) - either way, the resulting
     * bytes are written through the exact same atomic-temp-file + POSIX-0600 path.
     */
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
        val passphrase = passphraseProvider.get()
        try {
            val bytes =
                if (passphrase != null) {
                    KeystoreFileFormat.encodeEncrypted(identity, passphrase)
                } else {
                    KeystoreFileFormat.encode(identity)
                }
            Files.write(tempFile, bytes)
        } finally {
            passphrase?.fill('\u0000')
        }
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
