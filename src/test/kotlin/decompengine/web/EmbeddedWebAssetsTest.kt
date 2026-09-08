package decompengine.web

import com.sun.net.httpserver.Headers
import com.sun.net.httpserver.HttpContext
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpPrincipal
import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EmbeddedWebAssetsTest {
    @Test
    fun `generated production inventory loads from the runtime classpath`() {
        val assets = EmbeddedWebAssets.load()
        assertEquals("0.1.0", assets.manifest.applicationVersion)
        assertTrue(assets.manifest.files.any { it.isPublic && it.path == assets.manifest.entryScript })
        assertTrue(assets.manifest.files.any { it.path == ".vite/manifest.json" && !it.isPublic })
    }

    @Test
    fun `class directory and jar resources serve exactly the inventoried bytes`() {
        listOf(false, true).forEach { asJar ->
            val fixture = fixture()
            withClassLoader(fixture, asJar) { loader ->
                val assets = EmbeddedWebAssets.load(loader)
                withServer(assets) { origin ->
                    assets.manifest.files.filter(WebUiAsset::isPublic).forEach { asset ->
                        val response = request(origin, "GET", "/assets/ui/${asset.path}")
                        assertEquals(200, response.status)
                        assertContentEquals(fixture.getValue(asset.path), response.body)
                        assertEquals(asset.mediaType, response.header("Content-Type"))
                        assertEquals("no-referrer", response.header("Referrer-Policy"))
                        assertEquals(asset.sizeBytes.toString(), response.header("Content-Length"))
                        assertEquals("public, max-age=31536000, immutable", response.header("Cache-Control"))
                        assertEquals("\"${asset.sha256}\"", response.header("ETag"))
                    }
                }
            }
        }
    }

    @Test
    fun `head and conditional reads have metadata and no body`() {
        val assets = fromMap(fixture())
        withServer(assets) { origin ->
            val path = "/assets/ui/assets/index-12345678.js"
            val get = request(origin, "GET", path)
            val head = request(origin, "HEAD", path)
            assertEquals(200, head.status)
            assertEquals(get.header("Content-Length"), head.header("Content-Length"))
            assertEquals(get.header("Content-Type"), head.header("Content-Type"))
            assertEquals(get.header("ETag"), head.header("ETag"))
            assertEquals("no-referrer", head.header("Referrer-Policy"))
            assertTrue(head.body.isEmpty())
            listOf(get.header("ETag")!!, "W/${get.header("ETag")}", "*", "\"other\", ${get.header("ETag")}").forEach { tag ->
                val cached = request(origin, "GET", path, mapOf("If-None-Match" to tag))
                assertEquals(304, cached.status)
                assertEquals("no-referrer", cached.header("Referrer-Policy"))
                assertTrue(cached.body.isEmpty())
            }
            assertEquals(200, request(origin, "GET", path, mapOf("If-None-Match" to "\"other\"")).status)
        }
    }

    @Test
    fun `only exact public paths are served and method failures are JSON`() {
        val fixture = fixture().toMutableMap().apply {
            put("private-secret.txt", "synthetic private data".toByteArray())
        }
        val assets = fromMap(fixture)
        withServer(assets) { origin ->
            listOf(
                "/assets/ui/index.html", "/assets/ui/.vite/manifest.json", "/assets/ui/asset-manifest.json",
                "/assets/ui/private-secret.txt", "/assets/ui/assets/missing.js", "/assets/ui/assets/",
                "/assets/ui/assets/index-12345678.js/", "/assets/ui/assets/../index.html",
                "/assets/ui/assets/%69ndex-12345678.js", "/assets/ui/assets%2findex-12345678.js",
                "/assets/ui/%2e%2e/index.html", "/assets/ui/assets//index-12345678.js",
            ).forEach { path ->
                val response = request(origin, "GET", path)
                assertEquals(404, response.status, path)
                assertEquals("application/json; charset=utf-8", response.header("Content-Type"))
                assertEquals("error", Json.parseToJsonElement(response.body.decodeToString()).jsonObject["kind"]?.let { (it as JsonPrimitive).content })
                assertEquals("no-store", response.header("Cache-Control"))
                assertEquals("no-referrer", response.header("Referrer-Policy"))
            }
            val denied = request(origin, "POST", "/assets/ui/assets/index-12345678.js")
            assertEquals(405, denied.status)
            assertEquals("GET, HEAD", denied.header("Allow"))
            assertEquals("application/json; charset=utf-8", denied.header("Content-Type"))
            assertEquals("no-referrer", denied.header("Referrer-Policy"))
        }
    }

    @Test
    fun `shell supports nested base path with manifest links and no executable inline bootstrap`() {
        val assets = fromMap(fixture(), "/workbench/nested/")
        withServer(assets) { origin ->
            val get = request(origin, "GET", "/shell")
            val html = get.body.decodeToString()
            assertEquals(200, get.status)
            assertEquals("no-store", get.header("Cache-Control"))
            assertTrue(html.contains("name=\"decomp-base-path\" content=\"/workbench/nested/\""))
            assertTrue(html.contains("name=\"decomp-application-version\" content=\"0.1.0\""))
            assertTrue(html.contains("src=\"/workbench/nested/assets/ui/assets/index-12345678.js\""))
            assertTrue(html.contains("href=\"/workbench/nested/assets/ui/assets/index-12345678.css\""))
            assertTrue(html.contains("id=\"app\""))
            assertFalse(html.contains("<base"))
            assertFalse(html.contains("<script>"))
            assertTrue(get.header("Content-Security-Policy")!!.contains("script-src 'self'"))
            assertFalse(get.header("Content-Security-Policy")!!.contains("unsafe-inline"))
            val head = request(origin, "HEAD", "/shell")
            assertEquals(get.header("Content-Length"), head.header("Content-Length"))
            assertTrue(head.body.isEmpty())
            assertEquals(200, request(origin, "GET", "/workbench/nested/assets/ui/assets/index-12345678.js").status)
            assertEquals(404, request(origin, "GET", "/assets/ui/assets/index-12345678.js").status)
        }
        listOf("relative/", "/missing-trailing", "/a/../b/", "/a//b/", "/a%20b/", "/a?b/", "/a.b/").forEach { base ->
            assertFailsWith<EmbeddedWebAssetsException> { fromMap(fixture(), base) }
        }
    }

    @Test
    fun `startup rejects absent corrupted and inconsistent inventory resources`() {
        val original = fixture()
        val variants = listOf(
            original - "asset-manifest.json",
            original - "index.html",
            original - "assets/index-12345678.js",
            original + ("assets/index-12345678.js" to "different bytes".toByteArray()),
            changeManifest(original) { root -> root + ("buildId" to JsonPrimitive("0".repeat(64))) },
            changeManifest(original) { root -> root + ("schemaVersion" to JsonPrimitive(2)) },
            changeManifest(original) { root -> root + ("applicationVersion" to JsonPrimitive("invalid_version")) },
            changeManifest(original) { root -> root + ("applicationVersion" to JsonPrimitive("-invalid")) },
            changeManifest(original) { root -> root + ("applicationVersion" to JsonPrimitive("1".repeat(65))) },
            changeManifest(original) { root -> root + ("entryScript" to JsonPrimitive("assets/missing.js")) },
            changeManifest(original) { root -> root + ("files" to JsonArray((root.getValue("files") as JsonArray).let { it + it.first() })) },
            changeManifest(original) { root -> root + ("secret" to JsonPrimitive("synthetic unexpected field")) },
        )
        variants.forEach { invalid ->
            val failure = assertFailsWith<EmbeddedWebAssetsException> { fromMap(invalid) }
            assertTrue(failure.message!!.contains("embedded", ignoreCase = true))
        }
    }

    @Test
    fun `startup validates vite static dynamic and auxiliary references`() {
        listOf("imports", "dynamicImports", "css", "assets").forEach { field ->
            val vite = buildJsonObject {
                put("index.html", buildJsonObject {
                    put("file", "assets/index-12345678.js")
                    put("isEntry", true)
                    put("css", JsonArray(listOf(JsonPrimitive("assets/index-12345678.css"))))
                    put(field, JsonArray(listOf(JsonPrimitive("missing-emitted-reference"))))
                })
            }.toString().toByteArray()
            val failure = assertFailsWith<EmbeddedWebAssetsException> { fromMap(fixture(viteOverride = vite)) }
            assertTrue(failure.message!!.contains("Vite"))
        }
    }

    @Test
    fun `oversized manifest and dishonest size are rejected with streams closed`() {
        var closed = false
        val oversized = WebUiResourceSource {
            object : ByteArrayInputStream(ByteArray(1024 * 1024 + 1)) {
                override fun close() { closed = true; super.close() }
            }
        }
        assertFailsWith<EmbeddedWebAssetsException> { EmbeddedWebAssets.load(oversized) }
        assertTrue(closed)
        val invalid = changeManifest(fixture()) { root ->
            root + ("files" to JsonArray((root.getValue("files") as JsonArray).mapIndexed { index, item ->
                if (index == 0) JsonObject(item.jsonObject + ("sizeBytes" to JsonPrimitive(16L * 1024 * 1024 + 1))) else item
            }))
        }
        assertFailsWith<EmbeddedWebAssetsException> { fromMap(invalid) }
    }

    @Test
    fun `large assets use bounded read buffers and release streams on disconnect`() {
        val fixture = fixture(largeAsset = ByteArray(2 * 1024 * 1024) { (it % 251).toByte() })
        var opened = 0
        var closed = 0
        var largestRead = 0
        val source = WebUiResourceSource { name ->
            fixture[name.removePrefix(EmbeddedWebAssets.RESOURCE_ROOT)]?.let { bytes ->
                opened++
                object : ByteArrayInputStream(bytes) {
                    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                        largestRead = maxOf(largestRead, length)
                        return super.read(buffer, offset, length)
                    }
                    override fun close() { closed++; super.close() }
                }
            }
        }
        val assets = EmbeddedWebAssets.load(source)
        assertEquals(opened, closed)
        val exchange = MemoryExchange("GET", "/assets/ui/assets/large-12345678.wasm", object : OutputStream() {
            override fun write(value: Int) { throw IOException("synthetic disconnected client") }
            override fun write(bytes: ByteArray, offset: Int, length: Int) { throw IOException("synthetic disconnected client") }
        })
        assertFailsWith<IOException> { assets.serveAsset(exchange) }
        assertEquals(opened, closed)
        assertTrue(exchange.closed)
        assertTrue(largestRead <= 64 * 1024)
    }

    @Test
    fun `empty assets have an explicit zero content length`() {
        val assets = fromMap(fixture(largeAsset = ByteArray(0)))
        withServer(assets) { origin ->
            val response = request(origin, "GET", "/assets/ui/assets/large-12345678.wasm")
            assertEquals(200, response.status)
            assertEquals("0", response.header("Content-Length"))
            assertTrue(response.body.isEmpty())
        }
    }

    @Test
    fun `unexpected missing resource replaces successful asset headers with a complete error`() {
        val resources = fixture().toMutableMap()
        val assets = EmbeddedWebAssets.load(WebUiResourceSource { name ->
            resources[name.removePrefix(EmbeddedWebAssets.RESOURCE_ROOT)]?.inputStream()
        })
        resources.remove("assets/index-12345678.js")
        withServer(assets) { origin ->
            val response = request(origin, "GET", "/assets/ui/assets/index-12345678.js")
            assertEquals(503, response.status)
            assertEquals(response.body.size.toString(), response.header("Content-Length"))
            assertEquals("application/json; charset=utf-8", response.header("Content-Type"))
            assertEquals("no-store", response.header("Cache-Control"))
            assertEquals("no-referrer", response.header("Referrer-Policy"))
            assertEquals(null, response.header("ETag"))
            assertTrue(response.body.decodeToString().contains("UI_ASSET_UNAVAILABLE"))
        }
    }

    private fun fixture(viteOverride: ByteArray? = null, largeAsset: ByteArray? = null): Map<String, ByteArray> {
        val result = linkedMapOf(
            "index.html" to "<!doctype html><html><body>private build input</body></html>".toByteArray(),
            "assets/index-12345678.js" to "import './dynamic-12345678.js';\n".toByteArray(),
            "assets/dynamic-12345678.js" to "export const value = 1;\n".toByteArray(),
            "assets/index-12345678.css" to "body { color: black; }\n".toByteArray(),
            "assets/mark-12345678.svg" to "<svg xmlns=\"http://www.w3.org/2000/svg\"/>\n".toByteArray(),
        )
        largeAsset?.let { result["assets/large-12345678.wasm"] = it }
        result[".vite/manifest.json"] = viteOverride ?: buildJsonObject {
            put("index.html", buildJsonObject {
                put("file", "assets/index-12345678.js")
                put("isEntry", true)
                put("dynamicImports", JsonArray(listOf(JsonPrimitive("src/dynamic.ts"))))
                put("css", JsonArray(listOf(JsonPrimitive("assets/index-12345678.css"))))
                put("assets", JsonArray(listOf(JsonPrimitive("assets/mark-12345678.svg"))))
            })
            put("src/dynamic.ts", buildJsonObject { put("file", "assets/dynamic-12345678.js") })
        }.toString().toByteArray()
        val payload = buildJsonObject {
            put("schemaVersion", 1)
            put("applicationVersion", "0.1.0")
            put("entryScript", "assets/index-12345678.js")
            put("entryStyles", JsonArray(listOf(JsonPrimitive("assets/index-12345678.css"))))
            put("files", JsonArray(result.entries.sortedBy { it.key }.map { (path, bytes) ->
                buildJsonObject {
                    put("path", path)
                    put("mediaType", when (path.substringAfterLast('.')) {
                        "js" -> "text/javascript; charset=utf-8"
                        "css" -> "text/css; charset=utf-8"
                        "html" -> "text/html; charset=utf-8"
                        "json" -> "application/json; charset=utf-8"
                        "svg" -> "image/svg+xml"
                        "wasm" -> "application/wasm"
                        else -> error("fixture extension is unsupported")
                    })
                    put("sizeBytes", bytes.size)
                    put("sha256", sha256(bytes))
                    put("public", path.startsWith("assets/"))
                }
            }))
        }
        result["asset-manifest.json"] = JsonObject(payload + ("buildId" to JsonPrimitive(sha256((payload.toString() + "\n").toByteArray())))).toString().toByteArray()
        return result
    }

    private fun fromMap(contents: Map<String, ByteArray>, basePath: String = "/"): EmbeddedWebAssets =
        EmbeddedWebAssets.load(WebUiResourceSource { name -> contents[name.removePrefix(EmbeddedWebAssets.RESOURCE_ROOT)]?.inputStream() }, basePath)

    private fun changeManifest(contents: Map<String, ByteArray>, change: (JsonObject) -> Map<String, kotlinx.serialization.json.JsonElement>): Map<String, ByteArray> =
        contents + ("asset-manifest.json" to JsonObject(change(Json.parseToJsonElement(contents.getValue("asset-manifest.json").decodeToString()).jsonObject)).toString().toByteArray())

    private fun withClassLoader(contents: Map<String, ByteArray>, asJar: Boolean, action: (ClassLoader) -> Unit) {
        val root = createTempDirectory("embedded-ui-")
        try {
            val resource = if (asJar) {
                root.resolve("application.jar").also { jar ->
                    JarOutputStream(Files.newOutputStream(jar)).use { output ->
                        contents.forEach { (path, bytes) ->
                            output.putNextEntry(JarEntry(EmbeddedWebAssets.RESOURCE_ROOT + path))
                            output.write(bytes)
                            output.closeEntry()
                        }
                    }
                }
            } else {
                contents.forEach { (path, bytes) ->
                    val file = root.resolve(EmbeddedWebAssets.RESOURCE_ROOT + path)
                    file.parent.createDirectories()
                    file.writeBytes(bytes)
                }
                root
            }
            URLClassLoader(arrayOf(resource.toUri().toURL()), null).use(action)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun withServer(assets: EmbeddedWebAssets, action: (String) -> Unit) {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { exchange ->
            if (exchange.requestURI.path == "/shell") assets.serveShell(exchange) else assets.serveAsset(exchange)
        }
        server.start()
        try { action("http://127.0.0.1:${server.address.port}") } finally { server.stop(0) }
    }

    private data class Response(val status: Int, val body: ByteArray, val headers: Map<String?, List<String>>) {
        fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value?.firstOrNull()
    }

    private fun request(origin: String, method: String, path: String, headers: Map<String, String> = emptyMap()): Response {
        val connection = URI.create(origin + path).toURL().openConnection() as HttpURLConnection
        connection.requestMethod = method
        connection.connectTimeout = 3000
        connection.readTimeout = 3000
        headers.forEach(connection::setRequestProperty)
        return try {
            val status = connection.responseCode
            val body = (if (status >= 400) connection.errorStream else connection.inputStream)?.use(InputStream::readBytes) ?: ByteArray(0)
            Response(status, body, connection.headerFields)
        } finally { connection.disconnect() }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private class MemoryExchange(private val method: String, path: String, private val output: OutputStream) : HttpExchange() {
        private val uri = URI.create(path)
        private val requestHeaders = Headers()
        private val responseHeaders = Headers()
        var closed = false
        private var status = -1
        override fun getRequestHeaders(): Headers = requestHeaders
        override fun getResponseHeaders(): Headers = responseHeaders
        override fun getRequestURI(): URI = uri
        override fun getRequestMethod(): String = method
        override fun getHttpContext(): HttpContext = throw UnsupportedOperationException()
        override fun close() { closed = true }
        override fun getRequestBody(): InputStream = ByteArrayInputStream(ByteArray(0))
        override fun getResponseBody(): OutputStream = output
        override fun sendResponseHeaders(code: Int, length: Long) { status = code }
        override fun getRemoteAddress(): InetSocketAddress = InetSocketAddress("127.0.0.1", 1)
        override fun getResponseCode(): Int = status
        override fun getLocalAddress(): InetSocketAddress = InetSocketAddress("127.0.0.1", 2)
        override fun getProtocol(): String = "HTTP/1.1"
        override fun getAttribute(name: String): Any? = null
        override fun setAttribute(name: String, value: Any?) = Unit
        override fun setStreams(input: InputStream?, output: OutputStream?) = Unit
        override fun getPrincipal(): HttpPrincipal? = null
    }
}
