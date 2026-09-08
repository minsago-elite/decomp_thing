package decompengine.web

import com.sun.net.httpserver.HttpExchange
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Collections
import java.util.UUID

data class WebUiAsset(
    val path: String,
    val mediaType: String,
    val sizeBytes: Long,
    val sha256: String,
    val isPublic: Boolean,
)

data class WebUiAssetManifest(
    val applicationVersion: String,
    val buildId: String,
    val entryScript: String,
    val entryStyles: List<String>,
    val files: List<WebUiAsset>,
)

class EmbeddedWebAssetsException(message: String, cause: Throwable? = null) : IllegalStateException(message, cause)

/** The input is an exact classloader resource name, never a user-selected filesystem path. */
internal fun interface WebUiResourceSource {
    fun open(resourceName: String): InputStream?
}

/**
 * Validates the packaged inventory before exposing its explicit public subset.
 * Resources stay classloader streams for both class directories and real JARs.
 * The installation is trusted immutable application input, not job/upload storage.
 */
class EmbeddedWebAssets private constructor(
    val manifest: WebUiAssetManifest,
    val basePath: String,
    private val source: WebUiResourceSource,
) {
    val assetPrefix: String = "${basePath}assets/ui/"
    private val publicAssets = manifest.files.filter(WebUiAsset::isPublic).associateBy(WebUiAsset::path)

    /** Call only after transport-level Host/session routing policy has been applied. */
    fun serveAsset(exchange: HttpExchange) {
        if (!allowReadMethod(exchange)) return
        val rawPath = exchange.requestURI.rawPath
        val relativePath = rawPath.takeIf { it.startsWith(assetPrefix) }?.removePrefix(assetPrefix)
        val asset = relativePath?.takeIf(::safeAssetPath)?.let(publicAssets::get)
        if (asset == null) {
            sendError(exchange, 404, "UI_ASSET_NOT_FOUND", "The requested application asset is unavailable.")
            return
        }
        val etag = "\"${asset.sha256}\""
        exchange.responseHeaders.set("Content-Type", asset.mediaType)
        exchange.responseHeaders.set("Content-Length", asset.sizeBytes.toString())
        exchange.responseHeaders.set("Cache-Control", "public, max-age=31536000, immutable")
        exchange.responseHeaders.set("ETag", etag)
        exchange.responseHeaders.set("X-Content-Type-Options", "nosniff")
        exchange.responseHeaders.set("Referrer-Policy", "no-referrer")
        if (etagMatches(exchange.requestHeaders.getFirst("If-None-Match"), etag)) {
            exchange.sendResponseHeaders(304, -1)
            exchange.close()
            return
        }
        if (exchange.requestMethod == "HEAD") {
            exchange.sendResponseHeaders(200, -1)
            exchange.close()
            return
        }
        val input = source.open(RESOURCE_ROOT + asset.path)
        if (input == null) {
            exchange.responseHeaders.remove("ETag")
            sendError(exchange, 503, "UI_ASSET_UNAVAILABLE", "An application asset is missing; restart after repairing the installation.")
            return
        }
        input.use {
            try {
                // HttpServer uses zero as chunked mode; a zero-byte asset needs an explicitly empty response.
                exchange.sendResponseHeaders(200, if (asset.sizeBytes == 0L) -1 else asset.sizeBytes)
                exchange.responseBody.use { output ->
                    val buffer = ByteArray(BUFFER_BYTES)
                    var remaining = asset.sizeBytes
                    while (remaining > 0) {
                        val read = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                        if (read < 0) throw EmbeddedWebAssetsException("Embedded UI resource changed after startup: ${asset.path}")
                        if (read == 0) continue
                        output.write(buffer, 0, read)
                        remaining -= read
                    }
                    if (input.read() != -1) {
                        throw EmbeddedWebAssetsException("Embedded UI resource grew after startup: ${asset.path}")
                    }
                }
            } finally {
                exchange.close()
            }
        }
    }

    /** Shell links come from the verified manifest, independent of the current navigation URL. */
    fun serveShell(exchange: HttpExchange) {
        if (!allowReadMethod(exchange)) return
        val styles = manifest.entryStyles.joinToString("\n") { path ->
            "    <link rel=\"stylesheet\" href=\"${htmlAttribute(assetPrefix + path)}\">"
        }
        val html = """
            <!doctype html>
            <html lang="en">
              <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="decomp-base-path" content="${htmlAttribute(basePath)}">
                <meta name="decomp-ui-build" content="${manifest.buildId}">
                <meta name="decomp-application-version" content="${htmlAttribute(manifest.applicationVersion)}">
                <meta name="color-scheme" content="light dark">
                <meta name="referrer" content="no-referrer">
                <title>Decomp Workbench</title>
            $styles
                <script type="module" src="${htmlAttribute(assetPrefix + manifest.entryScript)}"></script>
              </head>
              <body>
                <div id="app"></div>
                <noscript>This workbench needs JavaScript. Existing command-line workflows remain available.</noscript>
              </body>
            </html>
        """.trimIndent().toByteArray(StandardCharsets.UTF_8)
        exchange.responseHeaders.set("Content-Type", "text/html; charset=utf-8")
        exchange.responseHeaders.set("Content-Length", html.size.toString())
        exchange.responseHeaders.set("Cache-Control", "no-store")
        exchange.responseHeaders.set("X-Content-Type-Options", "nosniff")
        exchange.responseHeaders.set("Referrer-Policy", "no-referrer")
        exchange.responseHeaders.set("Content-Security-Policy", SHELL_CSP)
        try {
            if (exchange.requestMethod == "HEAD") {
                exchange.sendResponseHeaders(200, -1)
            } else {
                exchange.sendResponseHeaders(200, html.size.toLong())
                exchange.responseBody.use { it.write(html) }
            }
        } finally {
            exchange.close()
        }
    }

    private fun allowReadMethod(exchange: HttpExchange): Boolean {
        if (exchange.requestMethod in setOf("GET", "HEAD")) return true
        exchange.responseHeaders.set("Allow", "GET, HEAD")
        sendError(exchange, 405, "METHOD_NOT_ALLOWED", "Application resources support GET and HEAD.")
        return false
    }

    companion object {
        const val RESOURCE_ROOT: String = "decompengine/web/ui/"
        private const val MANIFEST_PATH = "asset-manifest.json"
        private const val MAX_MANIFEST_BYTES = 1024 * 1024
        private const val MAX_FILES = 2048
        private const val MAX_FILE_BYTES = 16L * 1024 * 1024
        private const val MAX_TOTAL_BYTES = 64L * 1024 * 1024
        private const val BUFFER_BYTES = 64 * 1024
        private const val SHELL_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; " +
            "img-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'self'; " +
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
        private val SHA256 = Regex("[0-9a-f]{64}")
        private val SAFE_SEGMENT = Regex("[A-Za-z0-9_.-]+")
        private val MEDIA_TYPES = mapOf(
            "js" to "text/javascript; charset=utf-8",
            "mjs" to "text/javascript; charset=utf-8",
            "css" to "text/css; charset=utf-8",
            "html" to "text/html; charset=utf-8",
            "json" to "application/json; charset=utf-8",
            "svg" to "image/svg+xml",
            "png" to "image/png",
            "jpg" to "image/jpeg",
            "jpeg" to "image/jpeg",
            "gif" to "image/gif",
            "webp" to "image/webp",
            "avif" to "image/avif",
            "ico" to "image/x-icon",
            "woff" to "font/woff",
            "woff2" to "font/woff2",
            "ttf" to "font/ttf",
            "otf" to "font/otf",
            "wasm" to "application/wasm",
        )

        fun load(
            classLoader: ClassLoader = EmbeddedWebAssets::class.java.classLoader,
            basePath: String = "/",
        ): EmbeddedWebAssets = load(WebUiResourceSource(classLoader::getResourceAsStream), basePath)

        internal fun load(source: WebUiResourceSource, basePath: String = "/"): EmbeddedWebAssets {
            try {
                require(basePath.length <= 256 && basePath.matches(Regex("/([A-Za-z0-9_-]+/)*"))) {
                    "UI base path must be a normalized absolute URL prefix"
                }
                val payload = readSmallResource(source, MANIFEST_PATH)
                val manifest = parseManifest(payload)
                manifest.files.forEach { asset -> validateResource(source, asset) }
                validateViteManifest(source, manifest)
                return EmbeddedWebAssets(manifest, basePath, source)
            } catch (failure: EmbeddedWebAssetsException) {
                throw failure
            } catch (failure: Exception) {
                throw EmbeddedWebAssetsException("Invalid embedded workbench assets: ${failure.message}", failure)
            }
        }

        private fun parseManifest(bytes: ByteArray): WebUiAssetManifest {
            val root = Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).objectValue("asset manifest")
            root.requireKeys("schemaVersion", "applicationVersion", "entryScript", "entryStyles", "files", "buildId")
            require(root.number("schemaVersion").intOrNull == 1) { "unsupported embedded UI manifest schema" }
            val applicationVersion = root.string("applicationVersion")
            require(applicationVersion.matches(Regex("[0-9A-Za-z][0-9A-Za-z.+-]{0,63}"))) {
                "invalid embedded UI application version"
            }
            val buildId = root.string("buildId")
            require(buildId.matches(SHA256)) { "invalid embedded UI build ID" }
            val entryScript = root.string("entryScript")
            val entryStyles = root.stringArray("entryStyles")
            val fileElements = root["files"] as? JsonArray ?: error("embedded UI files must be an array")
            require(fileElements.size in 1..MAX_FILES) { "embedded UI file count exceeds its bound" }
            val files = fileElements.map { element ->
                val item = element.objectValue("asset entry")
                item.requireKeys("path", "mediaType", "sizeBytes", "sha256", "public")
                val path = item.string("path")
                require(path.length <= 512 && safePath(path)) { "invalid embedded UI resource name" }
                val isPublic = item["public"].let { it as? JsonPrimitive }
                    ?.takeUnless(JsonPrimitive::isString)?.booleanOrNull ?: error("asset public flag must be a boolean")
                require(if (isPublic) safeAssetPath(path) else path in setOf("index.html", ".vite/manifest.json")) {
                    "embedded UI resource is outside its allowed namespace"
                }
                require(!isPublic || path.substringAfterLast('.') != "html") {
                    "embedded UI HTML is private"
                }
                val mediaType = item.string("mediaType")
                require(mediaType == MEDIA_TYPES[path.substringAfterLast('.')]) { "unsupported or inconsistent UI media type" }
                val sizeBytes = item.number("sizeBytes").longOrNull ?: error("asset size must be an integer")
                require(sizeBytes in 0..MAX_FILE_BYTES) { "embedded UI resource exceeds its byte limit" }
                val sha256 = item.string("sha256")
                require(sha256.matches(SHA256)) { "invalid embedded UI resource digest" }
                WebUiAsset(path, mediaType, sizeBytes, sha256, isPublic)
            }
            require(files.map(WebUiAsset::path) == files.map(WebUiAsset::path).distinct().sorted()) {
                "embedded UI inventory must have unique sorted resource names"
            }
            require(files.sumOf(WebUiAsset::sizeBytes) <= MAX_TOTAL_BYTES) { "embedded UI inventory exceeds its aggregate byte limit" }
            val index = files.associateBy(WebUiAsset::path)
            require(index["index.html"]?.isPublic == false && index[".vite/manifest.json"]?.isPublic == false) {
                "embedded UI index or Vite manifest is missing"
            }
            require(index[entryScript]?.let { it.isPublic && it.path.endsWith(".js") } == true) {
                "embedded UI entry script is missing or private"
            }
            require(entryStyles == entryStyles.distinct()) { "duplicate embedded UI entry stylesheet" }
            require(entryStyles.all { path -> index[path]?.let { it.isPublic && it.path.endsWith(".css") } == true }) {
                "embedded UI entry stylesheet is missing or private"
            }
            val canonical = buildJsonObject {
                put("schemaVersion", 1)
                put("applicationVersion", applicationVersion)
                put("entryScript", entryScript)
                put("entryStyles", JsonArray(entryStyles.map(::JsonPrimitive)))
                put("files", JsonArray(files.map { asset ->
                    buildJsonObject {
                        put("path", asset.path)
                        put("mediaType", asset.mediaType)
                        put("sizeBytes", asset.sizeBytes)
                        put("sha256", asset.sha256)
                        put("public", asset.isPublic)
                    }
                }))
            }.toString() + "\n"
            require(digest(canonical.toByteArray(StandardCharsets.UTF_8)) == buildId) { "embedded UI build ID does not match its inventory" }
            return WebUiAssetManifest(applicationVersion, buildId, entryScript, Collections.unmodifiableList(entryStyles), Collections.unmodifiableList(files))
        }

        private fun validateResource(source: WebUiResourceSource, asset: WebUiAsset) {
            val digest = MessageDigest.getInstance("SHA-256")
            val input = source.open(RESOURCE_ROOT + asset.path)
                ?: throw EmbeddedWebAssetsException("Missing embedded workbench resource: ${asset.path}")
            input.use {
                val buffer = ByteArray(BUFFER_BYTES)
                var count = 0L
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    count += read
                    require(count <= asset.sizeBytes) { "embedded UI resource size mismatch: ${asset.path}" }
                    digest.update(buffer, 0, read)
                }
                require(count == asset.sizeBytes && digest.digest().hex() == asset.sha256) {
                    "embedded UI resource size or digest mismatch: ${asset.path}"
                }
            }
        }

        private fun validateViteManifest(source: WebUiResourceSource, manifest: WebUiAssetManifest) {
            val root = Json.parseToJsonElement(readSmallResource(source, ".vite/manifest.json").decodeToString(throwOnInvalidSequence = true))
                .objectValue("Vite manifest")
            require(root.size in 1..MAX_FILES) { "Vite manifest entry count exceeds its bound" }
            val publicPaths = manifest.files.filter(WebUiAsset::isPublic).map(WebUiAsset::path).toSet()
            val entries = root.mapValues { (_, value) -> value.objectValue("Vite entry") }
            entries.forEach { (_, entry) ->
                require(entry.string("file") in publicPaths) { "Vite manifest references a missing emitted file" }
                listOf("css", "assets").forEach { key ->
                    require(entry.optionalStringArray(key).all { it in publicPaths }) { "Vite manifest references a missing $key asset" }
                }
                listOf("imports", "dynamicImports").forEach { key ->
                    require(entry.optionalStringArray(key).all { it in entries }) { "Vite manifest references a missing $key entry" }
                }
            }
            val entry = entries["index.html"] ?: error("Vite index entry is missing")
            require((entry["isEntry"] as? JsonPrimitive)?.takeUnless(JsonPrimitive::isString)?.booleanOrNull == true) {
                "Vite index is not an entry module"
            }
            require(entry.string("file") == manifest.entryScript) { "Vite and UI manifest entry scripts disagree" }
            val visited = mutableSetOf<String>()
            val css = linkedSetOf<String>()
            val pending = ArrayDeque<Pair<String, Boolean>>()
            pending.addLast("index.html" to false)
            while (pending.isNotEmpty()) {
                val (key, afterImports) = pending.removeLast()
                val item = entries.getValue(key)
                if (afterImports) {
                    css.addAll(item.optionalStringArray("css"))
                } else if (visited.add(key)) {
                    pending.addLast(key to true)
                    item.optionalStringArray("imports").asReversed().forEach { pending.addLast(it to false) }
                }
            }
            require(css.toList() == manifest.entryStyles) { "Vite and UI manifest entry styles disagree" }
        }

        private fun readSmallResource(source: WebUiResourceSource, path: String): ByteArray {
            val input = source.open(RESOURCE_ROOT + path)
                ?: throw EmbeddedWebAssetsException("Missing embedded workbench resource: $path; rebuild the packaged frontend")
            return input.use {
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(BUFFER_BYTES)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    require(output.size() + read <= MAX_MANIFEST_BYTES) { "embedded UI manifest exceeds its byte limit" }
                    output.write(buffer, 0, read)
                }
                output.toByteArray()
            }
        }

        private fun safePath(path: String): Boolean = path.isNotEmpty() && path.split('/').all { part ->
            part.isNotEmpty() && part !in setOf(".", "..") && SAFE_SEGMENT.matches(part)
        }

        private fun safeAssetPath(path: String): Boolean =
            path.startsWith("assets/") && safePath(path) && path.split('/').none { it.startsWith('.') }

        private fun JsonObject.requireKeys(vararg names: String) {
            require(keys == names.toSet()) { "embedded UI manifest has missing or unknown fields" }
        }

        private fun kotlinx.serialization.json.JsonElement.objectValue(label: String): JsonObject =
            this as? JsonObject ?: error("$label must be an object")

        private fun JsonObject.string(key: String): String =
            (get(key) as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content
                ?: error("embedded UI $key must be a string")

        private fun JsonObject.number(key: String): JsonPrimitive =
            (get(key) as? JsonPrimitive)?.takeUnless(JsonPrimitive::isString)
                ?: error("embedded UI $key must be a number")

        private fun JsonObject.stringArray(key: String): List<String> {
            val array = get(key) as? JsonArray ?: error("embedded UI $key must be an array")
            require(array.size <= MAX_FILES) { "embedded UI $key collection exceeds its bound" }
            return array.map { element ->
                (element as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content
                    ?: error("embedded UI $key entry must be a string")
            }
        }

        private fun JsonObject.optionalStringArray(key: String): List<String> = if (key in this) stringArray(key) else emptyList()

        private fun etagMatches(header: String?, etag: String): Boolean =
            header?.split(',')?.any { it.trim().let { value -> value == "*" || value.removePrefix("W/") == etag } } == true

        private fun htmlAttribute(value: String): String = value.replace("&", "&amp;").replace("\"", "&quot;")
            .replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;")

        private fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).hex()
        private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

        private fun sendError(exchange: HttpExchange, status: Int, code: String, message: String) {
            val requestId = UUID.randomUUID().toString()
            val payload = buildJsonObject {
                put("apiVersion", 1)
                put("kind", "error")
                put("requestId", requestId)
                put("error", buildJsonObject {
                    put("code", code)
                    put("message", message)
                    put("retryable", status == 503)
                    put("details", JsonArray(emptyList()))
                    put("retryAfterMs", kotlinx.serialization.json.JsonNull)
                })
            }.toString().toByteArray(StandardCharsets.UTF_8)
            exchange.responseHeaders.set("Content-Type", "application/json; charset=utf-8")
            exchange.responseHeaders.set("Content-Length", payload.size.toString())
            exchange.responseHeaders.set("Cache-Control", "no-store")
            exchange.responseHeaders.set("X-Content-Type-Options", "nosniff")
            exchange.responseHeaders.set("Referrer-Policy", "no-referrer")
            exchange.responseHeaders.set("X-Request-ID", requestId)
            try {
                if (exchange.requestMethod == "HEAD") exchange.sendResponseHeaders(status, -1)
                else {
                    exchange.sendResponseHeaders(status, payload.size.toLong())
                    exchange.responseBody.use { it.write(payload) }
                }
            } finally {
                exchange.close()
            }
        }
    }
}
