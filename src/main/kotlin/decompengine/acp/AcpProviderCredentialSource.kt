package decompengine.acp

import decompengine.builtin.provider.parseProviderObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFileAttributes
import java.nio.file.attribute.PosixFilePermission
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
 */
internal class AcpProviderCredential private constructor(
    val reference: AcpProviderCredentialReference,
    private val accessToken: String,
    private val accountId: String?,
) {
    /** Broker-owned upstream authorization headers. Validated syntax prevents header injection. */
    internal fun authorizationHeaders(): List<Pair<String, String>> = buildList {
        add("Authorization" to "Bearer $accessToken")
        accountId?.let { add("ChatGPT-Account-ID" to it) }
    }

    /** Values that must never appear in a forwarded response, a sandbox launch or a diagnostic. */
    internal fun secretValues(): List<String> = listOf(accessToken)

    override fun toString(): String = "AcpProviderCredential(reference=${reference.name}, <redacted>)"

    internal companion object {
        fun chatGptCachedAccessToken(accessToken: String, accountId: String?): AcpProviderCredential =
            AcpProviderCredential(AcpProviderCredentialReference.LOCAL_CODEX_CACHED_AUTH, accessToken, accountId)
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
     * refreshes the token, writes the file or follows a symbolic link to it, and an expired token is refused.
     */
    class LocalCodexCachedAuth(codexHome: Path) : AcpProviderCredentialSource() {
        private val home: Path = codexHome.toAbsolutePath().normalize()
        override val reference: AcpProviderCredentialReference get() = AcpProviderCredentialReference.LOCAL_CODEX_CACHED_AUTH
        override val hostPaths: List<Path> get() = listOfNotNull(home, runCatching { home.toRealPath() }.getOrNull()).distinct()

        override fun resolve(now: Instant): AcpProviderCredential {
            val document = readAuthDocument(home.resolve("auth.json"))
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
            return AcpProviderCredential.chatGptCachedAccessToken(accessToken, accountId)
        }

        override fun toString(): String = "AcpProviderCredentialSource.LocalCodexCachedAuth(<host>)"
    }
}

private const val MAXIMUM_AUTH_DOCUMENT_BYTES = 64 * 1024
private const val MAXIMUM_ACCESS_TOKEN_CHARACTERS = 16 * 1024
private val ACCOUNT_ID_SYNTAX = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,255}")
private val GROUP_OR_OTHER_ACCESS = setOf(
    PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
    PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE,
)

private fun unavailable(failure: AcpProviderCredentialFailure): Nothing = throw AcpProviderCredentialUnavailable(failure)

/** Reads one private regular file without following a link, within a fixed bound. */
private fun readAuthDocument(file: Path): JsonObject {
    val attributes = try {
        Files.readAttributes(file, PosixFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (_: NoSuchFileException) {
        unavailable(AcpProviderCredentialFailure.MISSING)
    } catch (_: Exception) {
        unavailable(AcpProviderCredentialFailure.UNREADABLE)
    }
    if (!attributes.isRegularFile || attributes.size() > MAXIMUM_AUTH_DOCUMENT_BYTES ||
        attributes.permissions().any { it in GROUP_OR_OTHER_ACCESS }
    ) unavailable(AcpProviderCredentialFailure.UNREADABLE)
    val bytes = try {
        Files.newByteChannel(file, setOf(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)).use(::readBounded)
    } catch (_: Exception) {
        unavailable(AcpProviderCredentialFailure.UNREADABLE)
    } ?: unavailable(AcpProviderCredentialFailure.UNREADABLE)
    return try {
        parseProviderObject(strictUtf8(bytes), MAXIMUM_AUTH_DOCUMENT_BYTES)
    } catch (_: Exception) {
        unavailable(AcpProviderCredentialFailure.MALFORMED)
    } finally {
        bytes.fill(0)
    }
}

private fun readBounded(channel: SeekableByteChannel): ByteArray? {
    val buffer = ByteBuffer.allocate(MAXIMUM_AUTH_DOCUMENT_BYTES + 1)
    while (buffer.hasRemaining() && channel.read(buffer) >= 0) Unit
    if (buffer.position() > MAXIMUM_AUTH_DOCUMENT_BYTES) {
        buffer.array().fill(0)
        return null
    }
    return buffer.array().copyOf(buffer.position()).also { buffer.array().fill(0) }
}

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
