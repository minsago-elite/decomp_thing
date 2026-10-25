package decompengine.web

import com.sun.net.httpserver.HttpContext
import com.sun.net.httpserver.HttpExchange
import decompengine.jobs.ProgressRedactor
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.Json
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/**
 * The one web-boundary redaction policy. Every versioned JSON document (success and error),
 * live and replayed event frame, server-generated download and support export passes through
 * the instance installed on the listener's HTTP context; persisted failure prose uses
 * [diagnostic] before it is written. Subsystem redactors (progress journals, CLI diagnostics,
 * MVP artifacts) still run first where they own persistence; this layer is the final check at
 * the point where bytes leave the server.
 *
 * Three classes of value are replaced:
 *  - credential literals: values of credential-named environment variables and long opaque
 *    configured values, never the short generic environment values that would corrupt DTOs;
 *  - credential syntax: authorization headers, bearer tokens, `key=value` credential
 *    assignments, URL user information and well-known token prefixes;
 *  - private host paths: the configured storage/home/temporary/working roots and the generic
 *    per-user and temporary directory families on POSIX and Windows hosts.
 *
 * Opaque protocol values (cursors, CSRF tokens, identities, digests and versions) keep their
 * exact bytes unless they contain a configured literal: a substituted cursor would silently
 * break pagination, and those fields are closed-syntax values that cannot carry a path.
 * Committed job content (source chunks and source downloads) is digest-bound user data, not
 * server configuration, and is served verbatim under job authorization.
 */
internal class WebRedactionPolicy private constructor(
    private val literals: List<String>,
    private val privateRoots: List<Regex>,
    private val diagnosticRedactor: ProgressRedactor?,
) {
    /** Replace every redactable span; stable when applied twice. */
    fun text(value: String): String {
        if (value.isEmpty()) return value
        if (value.length > MAXIMUM_TEXT_CHARACTERS) return OVERSIZED_MARK
        var current = value
        // Replacement can synthesize a literal ("fooX" with literals "foo" and "[redacted]X"); repeat
        // until stable and withhold anything that still contains a configured value.
        repeat(MAXIMUM_PASSES) {
            val next = redactOnce(current)
            if (next == current) return if (leaksLiteral(next)) SECRET_MARK else next
            current = next
        }
        return if (leaksLiteral(current) || redactOnce(current) != current) SECRET_MARK else current
    }

    /** Recursively redact string values. Object keys are fixed contract vocabulary and are kept. */
    fun json(value: JsonElement): JsonElement = json(value, opaque = false)

    /**
     * Downloads keep their exact bytes when nothing needs redaction, so digest bindings computed over
     * this projection stay stable. JSON documents are rewritten structurally; other UTF-8 text by span.
     * Bytes that are not UTF-8 text are returned unchanged only when no literal occurs in them.
     */
    fun document(bytes: ByteArray): ByteArray {
        val text = try {
            Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        } catch (_: java.nio.charset.CharacterCodingException) {
            val latin = String(bytes, Charsets.ISO_8859_1)
            return if (leaksLiteral(latin)) SECRET_MARK.toByteArray() else bytes
        }
        if (text(text) == text) return bytes
        val parsed = try { Json.parseToJsonElement(text) } catch (_: Exception) { null }
        return (parsed?.let { json(it).toString() } ?: text(text)).toByteArray(Charsets.UTF_8)
    }

    /** Persisted prose: every configured sensitive value (including short ones) plus this policy. */
    fun diagnostic(value: String, maximumCharacters: Int = 480): String {
        val first = diagnosticRedactor?.text(value, maximumCharacters) ?: value.take(maximumCharacters)
        return text(first)
    }

    /** True when any configured literal or redactable span is present; canary and preview checks. */
    fun leaks(value: String): Boolean = value.isNotEmpty() && (leaksLiteral(value) || redactOnce(value) != value)

    private fun leaksLiteral(value: String): Boolean = literals.any { value.contains(it) }

    private fun json(value: JsonElement, opaque: Boolean): JsonElement = when (value) {
        is JsonObject -> JsonObject(value.mapValues { (key, child) -> json(child, opaqueKey(key)) })
        is JsonArray -> JsonArray(value.map { json(it, opaque) })
        is JsonNull -> value
        is JsonPrimitive -> if (!value.isString) value else {
            val content = value.content
            val safe = if (opaque && OPAQUE_SYNTAX.matches(content)) {
                if (leaksLiteral(content)) SECRET_MARK else content
            } else text(content)
            if (safe == content) value else JsonPrimitive(safe)
        }
    }

    private fun redactOnce(source: String): String {
        var result = source
        for (literal in literals) if (result.contains(literal)) result = result.replace(literal, SECRET_MARK)
        result = URL_USER_INFO.replace(result) { "${it.groupValues[1]}$SECRET_MARK@" }
        for ((pattern, keepPrefix) in CREDENTIAL_PATTERNS) {
            result = pattern.replace(result) { if (keepPrefix) it.groupValues[1] + SECRET_MARK else SECRET_MARK }
        }
        for (root in privateRoots) result = root.replace(result, PATH_MARK)
        result = GENERIC_PRIVATE_PATH.replace(result, PATH_MARK)
        return result
    }

    companion object {
        const val VERSION = "web-redaction-v1"
        const val SECRET_MARK = "[redacted]"
        const val PATH_MARK = "[private-path]"
        private const val OVERSIZED_MARK = "[oversized text omitted]"
        private const val MAXIMUM_TEXT_CHARACTERS = 4 * 1024 * 1024
        private const val MAXIMUM_PASSES = 4
        private const val CONTEXT_ATTRIBUTE = "decompengine.web.redaction"

        /** Fixed syntax only: used where no listener policy is installed (unit-level adapters). */
        val BASELINE = WebRedactionPolicy(emptyList(), emptyList(), null)

        private val CREDENTIAL_NAME = Regex(
            "(?i)(?:^|_)(?:API|AUTH|AUTHORIZATION|TOKEN|SECRET|PASS|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|CREDENTIALS|" +
                "COOKIE|PRIVATE|KEY|PAT|DSN|WEBHOOK|SIGNING|BEARER)(?:_|$)|(?i)(?:APIKEY|ACCESSKEY|SECRETKEY)")
        private val OPAQUE_SYNTAX = Regex("[A-Za-z0-9_.:+=-]{1,512}")
        private val URL_USER_INFO = Regex("(?i)\\b([a-z][a-z0-9+.-]{1,31}://)[^/\\s:@\"'<>]{1,256}:[^/\\s@\"'<>]{1,512}@")
        private val CREDENTIAL_PATTERNS = listOf(
            Regex("(?i)\\b((?:proxy-)?authorization\\s*[:=]\\s*)(?:basic|bearer|token|digest)\\s+[^\\s,;\"'<>]+") to true,
            Regex("(?i)\\b(bearer\\s+)[A-Za-z0-9._~+/=-]{8,}") to true,
            Regex("(?i)\\b((?:api[_-]?key|access[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|" +
                "client[_-]?secret|password|passwd|passphrase|secret|token)\\s*[:=]\\s*)(?!\\[redacted])[^\\s,;\"'&<>]+") to true,
            Regex("(?<![A-Za-z0-9_-])(?:sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|" +
                "github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})") to false,
        )
        // A path starts the value, follows a separator or follows a URL scheme ("file:///home/...");
        // a relative path such as "pkg/home/notes.txt" is public. Path text ends at whitespace or punctuation.
        private const val PATH_START = "(?:(?<=:/{2})|(?<![A-Za-z0-9_.~/\\\\-]))"
        private const val PATH_END = "(?=[/\\\\]|$|[^A-Za-z0-9_.~-])"
        private const val PATH_TAIL = "[^\\s\"'<>;:,)\\]}]*"
        private val GENERIC_PRIVATE_PATH = Regex(
            PATH_START + "(?:/(?:home|Users|root|tmp|private/var|private/tmp|var/folders|var/tmp|run/user)" +
                PATH_END + "(?:/" + PATH_TAIL + ")?" +
                "|[A-Za-z]:[\\\\/](?:Users|Documents and Settings|Windows[\\\\/]Temp|ProgramData)" + PATH_END +
                "(?:[\\\\/]" + PATH_TAIL + ")?)")

        fun create(
            environment: Map<String, String>,
            sensitiveValues: Collection<String>,
            privateRoots: Collection<Path>,
        ): WebRedactionPolicy {
            val named = environment.entries.filter { (name, value) ->
                value.length >= 8 && CREDENTIAL_NAME.containsMatchIn(name)
            }.map { it.value }
            // Long opaque configured values are secret-shaped regardless of their name. Path lists and
            // prose are left to the path rules; short generic values would corrupt public vocabulary.
            val opaque = sensitiveValues.filter { value ->
                value.length in 20..4096 && value.none(Char::isWhitespace) && '/' !in value && '\\' !in value &&
                    value.any(Char::isLetter) && value.any(Char::isDigit)
            }
            val literals = (named + opaque).filter { it.length in 8..4096 }.distinct()
                .sortedByDescending(String::length).take(4096)
            require(literals.sumOf { it.length.toLong() } <= 1024 * 1024) { "redaction literals exceed the configured limit" }
            val roots = privateRoots.flatMap { root ->
                val absolute = root.toAbsolutePath().normalize()
                listOfNotNull(absolute, try {
                    if (Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)) absolute.toRealPath() else null
                } catch (_: Exception) { null })
            }.map { it.toString().trimEnd('/', '\\') }
                .filter { it.length >= 4 && it.count { c -> c == '/' || c == '\\' } >= 1 }
                .distinct().sortedByDescending(String::length)
                .map { Regex(PATH_START + Regex.escape(it) + PATH_END + "(?:[/\\\\]" + PATH_TAIL + ")?") }
            val diagnostic = try { ProgressRedactor(sensitiveValues.take(4096)) } catch (_: Exception) { null }
            return WebRedactionPolicy(literals, roots, diagnostic)
        }

        /** Host roots that must never appear in a public representation. */
        fun defaultPrivateRoots(dataDir: Path): List<Path> = listOfNotNull(
            dataDir,
            System.getProperty("user.home")?.let(Path::of),
            System.getProperty("java.io.tmpdir")?.let(Path::of),
            System.getProperty("user.dir")?.let(Path::of),
            System.getProperty("java.home")?.let(Path::of),
        )

        fun install(context: HttpContext, policy: WebRedactionPolicy) { context.attributes[CONTEXT_ATTRIBUTE] = policy }

        /** The listener policy; adapters exercised without a listener context use [BASELINE]. */
        fun of(exchange: HttpExchange): WebRedactionPolicy = try {
            exchange.httpContext?.attributes?.get(CONTEXT_ATTRIBUTE) as? WebRedactionPolicy
        } catch (_: Exception) { null } ?: BASELINE
    }
}

private val opaqueKeySuffixes = listOf("Id", "Ids", "Sha256", "sha256", "Digest", "digest", "Version", "version",
    "Cursor", "cursor", "Token", "token", "etag", "ETag", "Key")

/** Closed-syntax protocol fields whose exact bytes are load-bearing. */
private fun opaqueKey(key: String): Boolean = key == "id" || key == "version" || opaqueKeySuffixes.any(key::endsWith)
