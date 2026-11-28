package decompengine.acp

import decompengine.builtin.provider.parseProviderObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.time.Instant
import java.util.Base64

/** Why a provider credential source could not supply usable material. */
enum class AcpProviderCredentialFailure { MISSING, UNREADABLE, MALFORMED, MECHANISM_UNSUPPORTED, EXPIRED }

/** Fixed text only: never a credential value, a host path or a retained cause. */
internal class AcpProviderCredentialUnavailable(val failure: AcpProviderCredentialFailure) :
    IOException("provider credential is unavailable: ${failure.name}")

/**
 * Host-only credential material for one broker. It never leaves the broker: it is not serializable, it has
 * no public accessor, and it is never put in a process environment, argument, file, archive or diagnostic.
 *
 * [sourceIdentities] are the device and inode keys of the credential file, its directory and every ancestor
 * of that directory, pinned while the credential was read. They are not secret. A sandbox launch that makes
 * any of these objects visible, under any path, would expose the credential.
 */
internal class AcpProviderCredential private constructor(
    val reference: AcpProviderCredentialReference,
    private val accessToken: String,
    private val accountId: String?,
    sourceIdentities: Set<LinuxFileKey>,
) {
    internal val sourceIdentities: Set<LinuxFileKey> = sourceIdentities.toSet()

    /** Broker-owned upstream authorization headers. Validated syntax prevents header injection. */
    internal fun authorizationHeaders(): List<Pair<String, String>> = buildList {
        add("Authorization" to "Bearer $accessToken")
        accountId?.let { add("ChatGPT-Account-ID" to it) }
    }

    /**
     * Values that must never appear in a forwarded response, a sandbox launch or a diagnostic. The account ID
     * is not key material, but it identifies the operator's account and is sent only upstream, so it is
     * treated as secret for echo and launch detection.
     */
    internal fun secretValues(): List<String> = listOfNotNull(accessToken, accountId)

    override fun toString(): String = "AcpProviderCredential(reference=${reference.name}, <redacted>)"

    internal companion object {
        fun chatGptCachedAccessToken(accessToken: String, accountId: String?, sourceIdentities: Set<LinuxFileKey>): AcpProviderCredential =
            AcpProviderCredential(AcpProviderCredentialReference.LOCAL_CODEX_CACHED_AUTH, accessToken, accountId, sourceIdentities)
    }
}

/**
 * Operator-controlled host secret source named by a policy credential reference. The host broker resolves it
 * outside every sandbox. Resolution reads the source again for each broker; nothing is cached across invocations.
 */
internal sealed class AcpProviderCredentialSource {
    abstract val reference: AcpProviderCredentialReference

    /** Host paths that hold the secret. No sandbox launch may make them, or a parent of them, visible. */
    internal abstract val hostPaths: List<Path>

    internal abstract fun resolve(now: Instant): AcpProviderCredential

    /**
     * `LOCAL_CODEX_CACHED_AUTH`: the ChatGPT login that the operator's own Codex CLI keeps in `auth.json`
     * under its Codex home. Only the cached access token and the optional account ID are used. The broker never
     * refreshes the token or writes the file, and an expired token is refused.
     *
     * The Codex home is pinned as a directory descriptor, and `auth.json` is opened below it without following
     * a link, as an `O_PATH` descriptor. Type, owner, mode and link count are checked on that pinned inode,
     * which is then reopened (non-blocking) and read within a fixed bound, so a name swapped after the checks
     * cannot supply other bytes or block the read.
     */
    class LocalCodexCachedAuth internal constructor(
        codexHome: Path,
        private val afterPin: () -> Unit,
    ) : AcpProviderCredentialSource() {
        constructor(codexHome: Path) : this(codexHome, {})

        private val home: Path = codexHome.toAbsolutePath().normalize()
        override val reference: AcpProviderCredentialReference get() = AcpProviderCredentialReference.LOCAL_CODEX_CACHED_AUTH
        override val hostPaths: List<Path> get() = listOfNotNull(home, runCatching { home.toRealPath() }.getOrNull()).distinct()

        override fun resolve(now: Instant): AcpProviderCredential {
            val (document, identities) = readPinnedAuthDocument(home, afterPin)
            document["auth_mode"]?.let { mode ->
                if (mode !is JsonPrimitive || !mode.isString || !mode.content.equals("chatgpt", ignoreCase = true)) {
                    unavailable(AcpProviderCredentialFailure.MECHANISM_UNSUPPORTED)
                }
            }
            // An API-key-only or logged-out cache has no ChatGPT token set.
            val tokens = when (val value = document["tokens"]) {
                null, JsonNull -> unavailable(AcpProviderCredentialFailure.MECHANISM_UNSUPPORTED)
                is JsonObject -> value
                else -> unavailable(AcpProviderCredentialFailure.MALFORMED)
            }
            val accessToken = tokens.stringOrNull("access_token")
                ?.takeIf { token -> token.length in 1..MAXIMUM_ACCESS_TOKEN_CHARACTERS && token.all { it.code in 33..126 } }
                ?: unavailable(AcpProviderCredentialFailure.MALFORMED)
            val accountId = when (tokens["account_id"]) {
                null, JsonNull -> null
                else -> tokens.stringOrNull("account_id")?.takeIf { it.matches(ACCOUNT_ID_SYNTAX) }
                    ?: unavailable(AcpProviderCredentialFailure.MALFORMED)
            }
            val expiry = accessTokenExpiry(accessToken) ?: unavailable(AcpProviderCredentialFailure.MALFORMED)
            if (!expiry.isAfter(now)) unavailable(AcpProviderCredentialFailure.EXPIRED)
            return AcpProviderCredential.chatGptCachedAccessToken(accessToken, accountId, identities)
        }

        override fun toString(): String = "AcpProviderCredentialSource.LocalCodexCachedAuth(<host>)"
    }
}

private const val MAXIMUM_AUTH_DOCUMENT_BYTES = 64 * 1024
private const val MAXIMUM_ACCESS_TOKEN_CHARACTERS = 16 * 1024
private const val GROUP_OR_OTHER_ACCESS = 0b000_111_111
private const val GROUP_OR_OTHER_WRITE = 0b000_010_010
private const val LINUX_ENOENT = 2
private val ACCOUNT_ID_SYNTAX = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,255}")

private fun unavailable(failure: AcpProviderCredentialFailure): Nothing = throw AcpProviderCredentialUnavailable(failure)

/**
 * Pins the Codex home and its `auth.json`, checks the pinned inodes, and reads the pinned file within the
 * bound. Returns the parsed document and the identities of the file, its directory and the directory's
 * ancestors. [afterPin] runs between the checks and the read, for race controls only.
 */
private fun readPinnedAuthDocument(home: Path, afterPin: () -> Unit): Pair<JsonObject, Set<LinuxFileKey>> {
    val directoryPath = try {
        home.toRealPath()
    } catch (_: NoSuchFileException) {
        unavailable(AcpProviderCredentialFailure.MISSING)
    } catch (_: Exception) {
        unavailable(AcpProviderCredentialFailure.UNREADABLE)
    }
    val uid = try {
        (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
    } catch (_: Exception) {
        unavailable(AcpProviderCredentialFailure.UNREADABLE)
    }
    val bytes = try {
        LinuxFilesystemSyscalls.openRoot(directoryPath).use { directory ->
            val directoryIdentity = directory.identity
            // Another user who can write the directory could replace the file between invocations.
            if (!directoryIdentity.isDirectory || directoryIdentity.uid != uid ||
                directoryIdentity.mode.permissions and GROUP_OR_OTHER_WRITE != 0
            ) unavailable(AcpProviderCredentialFailure.UNREADABLE)
            val file = directory.whileOpen { fd -> LinuxFilesystemSyscalls.openRegularFileAtOrNull(fd, AUTH_DOCUMENT_NAME) }
                ?: unavailable(AcpProviderCredentialFailure.MISSING)
            file.use {
                val identity = file.identity
                // One name only: no hard link elsewhere can expose the same inode through another path.
                if (!identity.isRegularFile || identity.uid != uid || identity.linkCount != 1 ||
                    identity.mode.permissions and GROUP_OR_OTHER_ACCESS != 0
                ) unavailable(AcpProviderCredentialFailure.UNREADABLE)
                afterPin()
                val content = LinuxFilesystemSyscalls.openReadableFrom(file).use { readable ->
                    LinuxFilesystemSyscalls.read(readable, MAXIMUM_AUTH_DOCUMENT_BYTES) {}
                }
                content to (setOf(identity.key, directoryIdentity.key) + ancestorIdentities(directoryPath))
            }
        }
    } catch (failure: AcpProviderCredentialUnavailable) {
        throw failure
    } catch (failure: LinuxSyscallException) {
        unavailable(if (failure.errno == LINUX_ENOENT) AcpProviderCredentialFailure.MISSING else AcpProviderCredentialFailure.UNREADABLE)
    } catch (_: Exception) {
        unavailable(AcpProviderCredentialFailure.UNREADABLE)
    }
    val (content, identities) = bytes
    return try {
        parseProviderObject(strictUtf8(content), MAXIMUM_AUTH_DOCUMENT_BYTES) to identities
    } catch (_: Exception) {
        unavailable(AcpProviderCredentialFailure.MALFORMED)
    } finally {
        content.fill(0)
    }
}

/** Identities of every ancestor of the real credential directory, up to and including the root. */
private fun ancestorIdentities(directory: Path): Set<LinuxFileKey> =
    generateSequence(directory.parent) { it.parent }.mapNotNull { ancestor ->
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(ancestor)?.use { it.identity.key }
    }.toSet()

private const val AUTH_DOCUMENT_NAME = "auth.json"

private fun strictUtf8(bytes: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
    .decode(ByteBuffer.wrap(bytes)).toString()

private fun JsonObject.stringOrNull(key: String): String? = (get(key) as? JsonPrimitive)?.takeIf { it.isString }?.content

/**
 * The `exp` claim of a ChatGPT access token. The signature is not checked: this is a local availability check,
 * and the provider still authenticates the token.
 */
private fun accessTokenExpiry(token: String): Instant? {
    val parts = token.split('.')
    if (parts.size != 3 || parts.any { it.isEmpty() || !it.matches(BASE64URL) }) return null
    return try {
        val claims = parseProviderObject(strictUtf8(Base64.getUrlDecoder().decode(parts[1])), MAXIMUM_ACCESS_TOKEN_CHARACTERS)
        val expiry = (claims["exp"] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull ?: return null
        if (expiry <= 0) null else Instant.ofEpochSecond(expiry)
    } catch (_: Exception) {
        null
    }
}

private val BASE64URL = Regex("[A-Za-z0-9_-]+")
