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
 * Shared web-boundary redaction policy, adopted from the #520 implementation in PR #1704.
 * This standalone log-viewer slice uses the text/credential projection before capture, search
 * and download. Listener-wide DTO/event/download installation and persisted diagnostics remain
 * separate integration work; providing the shared adapters here does not claim those gates.
 * Subsystem redactors (progress journals, CLI diagnostics, MVP artifacts) still own persistence.
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
 * Committed job content (source chunks, source downloads and exact-byte validation output previews) is
 * digest-bound user data, not server configuration, and is served verbatim under job authorization.
 */
internal class WebRedactionPolicy private constructor(
    private val literals: List<String>,
    private val privateRoots: List<Regex>,
    private val diagnosticRedactor: ProgressRedactor?,
) {
    /** Replace every redactable span; stable when applied twice. */
    fun text(value: String): String = text(value, paths = true)

    /** Log adapters may label known roots after credential spans, before generic path masking. */
    fun credentials(value: String): String = text(value, paths = false)

    private fun text(value: String, paths: Boolean): String {
        if (value.isEmpty()) return value
        if (value.length > MAXIMUM_TEXT_CHARACTERS) return OVERSIZED_MARK
        var current = value
        // Replacement can synthesize a literal ("fooX" with literals "foo" and "[redacted]X"); repeat
        // until stable and withhold anything that still contains a configured value.
        repeat(MAXIMUM_PASSES) {
            val next = redactOnce(current, paths)
            if (next == current) return if (leaksLiteral(next)) SECRET_MARK else next
            current = next
        }
        return if (leaksLiteral(current) || redactOnce(current, paths) != current) SECRET_MARK else current
    }

    /** Fixed-contract DTO projection only: protocol vocabulary, routing and byte-preview exemptions apply. */
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
        // Decide on decoded JSON values: escaping can hide a literal (quotes, backslashes) or a path from the raw text.
        val parsed = try { Json.parseToJsonElement(text) } catch (_: Exception) { null }
        if (parsed != null) {
            val safe = documentJson(parsed)
            if (safe == parsed && !leaksLiteral(text)) return bytes
            val serialized = safe.toString()
            // A configured literal can include JSON punctuation (for example a quoted property name).
            // Never return the same leaking serialization after detecting it in the original bytes.
            return if (leaksLiteral(serialized)) "null".toByteArray() else serialized.toByteArray(Charsets.UTF_8)
        }
        return if (text(text) == text) bytes else text(text).toByteArray(Charsets.UTF_8)
    }

    /** Persisted prose: every configured sensitive value (including short ones) plus this policy. */
    fun diagnostic(value: String, maximumCharacters: Int = 480): String {
        require(maximumCharacters >= 0)
        // Preserve complete syntax spans before the progress redactor can mask only a prefix or truncate.
        val safe = text(value)
        val preview = diagnosticRedactor?.text(safe, maximumCharacters) ?: safe.take(maximumCharacters)
        return text(preview)
    }

    /** Arbitrary report JSON has no trusted field names or fixed-DTO exemptions. */
    private fun documentJson(value: JsonElement): JsonElement {
        return when (value) {
            is JsonObject -> {
                val fields = linkedMapOf<String, JsonElement>()
                for ((key, child) in value) {
                    val safeKey = text(key)
                    // Do not silently overwrite distinct properties that collapse to the same public key.
                    if (safeKey in fields) return JsonPrimitive(SECRET_MARK)
                    val safe = if (DOCUMENT_CREDENTIAL_KEY.matches(key)) JsonPrimitive(SECRET_MARK) else documentJson(child)
                    val maximum = PUBLIC_TEXT_BOUNDS[key]
                    fields[safeKey] = if (safe != child && maximum != null && safe is JsonPrimitive && safe.isString && safe.content.length > maximum)
                        JsonPrimitive(SECRET_MARK) else safe
                }
                JsonObject(fields)
            }
            is JsonArray -> JsonArray(value.map(::documentJson))
            is JsonPrimitive -> if (value.isString) JsonPrimitive(text(value.content)) else value
        }
    }

    /** True when any configured literal or redactable span is present; canary and preview checks. */
    fun leaks(value: String): Boolean = value.isNotEmpty() && (leaksLiteral(value) || redactOnce(value) != value)

    private fun leaksLiteral(value: String): Boolean = literals.any { value.contains(it) }

    private fun json(value: JsonElement, opaque: Boolean, routing: Boolean = false): JsonElement = when (value) {
        // Exact-byte previews of recorded program output are digest-bound job content: their text is checked
        // against the hexadecimal bytes, so a substitution would corrupt the record without hiding the bytes.
        is JsonObject -> if (value.keys == BYTE_PREVIEW_KEYS) value
            else JsonObject(value.mapValues { (key, child) ->
                val safe = json(child, opaqueKey(key), routingKey(key))
                // Redaction may expand a valid near-limit name/prose field. Withhold the whole
                // field rather than truncate a replacement (or return an undecodable document).
                val maximum = PUBLIC_TEXT_BOUNDS[key]
                if (safe != child && maximum != null && safe is JsonPrimitive && safe.isString && safe.content.length > maximum)
                    JsonPrimitive(SECRET_MARK) else safe
            })
        is JsonArray -> JsonArray(value.map { json(it, opaque, routing) })
        is JsonNull -> value
        is JsonPrimitive -> if (!value.isString) value else {
            val content = value.content
            val safe = if (opaque && OPAQUE_SYNTAX.matches(content)) {
                if (leaksLiteral(content)) SECRET_MARK else content
            } else if (routing && ROUTE_SYNTAX.matches(content)) {
                // Public URL routes (a base path such as "/home/" or an API href) are not host paths.
                text(content, paths = false)
            } else text(content)
            if (safe == content) value else JsonPrimitive(safe)
        }
    }

    private fun redactOnce(source: String, paths: Boolean = true): String {
        // Collect complete spans against the same original text. Sequential substitutions can erase
        // the assignment prefix/quote before syntax masking, or split an overlapping configured literal.
        var starts: IntArray? = null
        var ends: IntArray? = null
        fun mark(start: Int, end: Int) {
            if (starts == null) {
                starts = IntArray(source.length + 1)
                ends = IntArray(source.length + 1)
            }
            val startCounts = requireNotNull(starts)
            val endCounts = requireNotNull(ends)
            startCounts[start]++
            endCounts[end]++
        }
        for (literal in literals) {
            var start = source.indexOf(literal)
            while (start >= 0) {
                mark(start, start + literal.length)
                start = source.indexOf(literal, start + 1)
            }
        }
        for (match in URL_USER_INFO.findAll(source)) mark(match.groups[1]!!.range.last + 1, match.range.last)
        for ((pattern, keepPrefix) in CREDENTIAL_PATTERNS) {
            for (match in pattern.findAll(source)) {
                mark(if (keepPrefix) match.groups[1]!!.range.last + 1 else match.range.first, match.range.last + 1)
            }
        }
        var result = if (starts == null) source else buildString {
            var active = 0
            var masking = false
            for (index in source.indices) {
                active -= ends!![index]
                if (active == 0) masking = false
                active += starts[index]
                if (active > 0) {
                    if (!masking) append(SECRET_MARK)
                    masking = true
                } else append(source[index])
            }
        }
        if (!paths) return result
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
        private val BYTE_PREVIEW_KEYS = setOf("totalBytes", "prefixBytes", "hex", "text", "textBytes", "truncated")
        // Conservative common bounds when a name is shared by several public DTOs.
        private val PUBLIC_TEXT_BOUNDS = mapOf("displayFilename" to 255, "filename" to 255,
            "displayName" to 255, "message" to 500, "javaVersion" to 64, "gitVersion" to 64)
        /** A same-origin URL path (optionally with a query): what basePath and *Href fields carry. */
        private val ROUTE_SYNTAX = Regex("/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/?)*(?:\\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?")
        private const val CREDENTIAL_KEYS = "api[_-]?key|access[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|" +
            "auth[_-]?token|client[_-]?secret|password|passwd|passphrase|secret|token"
        private val DOCUMENT_CREDENTIAL_KEY = Regex("(?i)(?:$CREDENTIAL_KEYS|(?:proxy-)?authorization|cookie|set-cookie)")
        private val URL_USER_INFO =Regex("(?i)\\b([a-z][a-z0-9+.-]{1,31}://)[^/\\s:@\"'<>]{1,256}:[^/\\s@\"'<>]{1,512}@")
        private val CREDENTIAL_PATTERNS = listOf(
            Regex("(?i)\\b((?:proxy-)?authorization\\s*[:=]\\s*)(?:basic|bearer|token|digest)\\s+[^\\s,;\"'<>]+") to true,
            Regex("(?i)\\b(bearer\\s+)[A-Za-z0-9._~+/=-]{8,}") to true,
            // Consume escaped quotes and the full bounded input, including unterminated previews.
            // Possessive repetition avoids recursive backtracking on long/escape-heavy credentials.
            Regex("""(?i)\b((?:$CREDENTIAL_KEYS)["']?\s*[:=]\s*)(?:"(?:[^"\\\r\n]|\\[^\r\n]?)*+(?:"|(?=[\r\n]|$))|'(?:[^'\\\r\n]|\\[^\r\n]?)*+(?:'|(?=[\r\n]|$)))""") to true,
            Regex("(?i)\\b((?:$CREDENTIAL_KEYS)[\"']?\\s*[:=]\\s*)(?!\\[redacted])[^\\s,;\"'&<>]+") to true,
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
                value.isNotEmpty() && CREDENTIAL_NAME.containsMatchIn(name)
            }.map { it.value }
            // Very short literals can collide with fixed DTO vocabulary and even the redaction
            // markers. Refuse that configuration instead of silently serving a known secret.
            require(named.all { it.length in 8..4096 }) {
                "nonempty credential-named environment values must contain 8 to 4096 characters"
            }
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

/** Public same-origin routing fields; their URL paths are server routes, never host filesystem paths. */
private fun routingKey(key: String): Boolean = key == "basePath" || key.endsWith("Href")

/** Closed-syntax protocol fields whose exact bytes are load-bearing. */
private fun opaqueKey(key: String): Boolean = key == "id" || key == "version" || opaqueKeySuffixes.any(key::endsWith)
