package net.lapisphilosophorum.lapisnet.identity

/** Env var carrying the keystore passphrase for a non-interactive (headless/CI/service) process -
 * see [resolveKeystorePassphrase]'s doc comment for the full resolution order. */
const val KEYSTORE_PASSPHRASE_ENV_VAR = "LAPISNET_KEYSTORE_PASSPHRASE"

/**
 * Resolves the keystore passphrase for a real process entry point (V0.4): the
 * [KEYSTORE_PASSPHRASE_ENV_VAR] env var if set, else an interactive console prompt (masked, via
 * [java.io.Console.readPassword]), else `null` for a headless process with neither. `null` is a
 * legitimate, expected outcome here (e.g. this project's own CI runs, or `BrowserMain` launched
 * from a process supervisor with no attached TTY) - callers must decide for themselves whether
 * that means "fall back to legacy unencrypted storage with a warning" (see
 * `BrowserMain.warningPassphraseProvider`) rather than this function failing outright.
 */
fun resolveKeystorePassphrase(env: Map<String, String> = System.getenv()): CharArray? {
    env[KEYSTORE_PASSPHRASE_ENV_VAR]?.let { return it.toCharArray() }
    val console = System.console() ?: return null
    return console.readPassword("Lapis Net keystore passphrase: ")
}
