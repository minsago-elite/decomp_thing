package decompengine.web

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.io.TempDir
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** A real Chrome/JVM journey, opt-in because ordinary unit-test hosts need not have Chrome. */
class BrowserSessionExpiryTest {
    @TempDir lateinit var directory: Path

    @Test
    fun `injected monotonic clock expires a real HTTP session before fresh operator exchange`() {
        val clock = TestClock()
        val server = UploadServer("127.0.0.1", 0, directory.resolve("jobs"),
            uiMode = WebUiMode.SPA, basePath = "/nested/", webAccessClock = clock)
        val client = HttpClient.newHttpClient()
        fun request(path: String, method: String = "GET", token: String? = null, cookie: String? = null): HttpResponse<String> {
            val builder = HttpRequest.newBuilder(URI("${server.browserOrigin}$path"))
                .header("Accept", "application/json")
            if (cookie != null) builder.header("Cookie", cookie)
            if (method == "POST") builder.header("Origin", server.browserOrigin)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"$token\"}"))
            return client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        }
        server.start()
        try {
            val first = server.issueBrowserBootstrap().token
            val issued = request("/nested/api/v1/session", "POST", first)
            assertEquals(200, issued.statusCode())
            assertFalse(issued.body().contains(first))
            val cookie = issued.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            assertEquals(200, request("/nested/api/v1/bootstrap", cookie = cookie).statusCode())
            clock.advance(Duration.ofHours(8))
            val expired = request("/nested/api/v1/bootstrap", cookie = cookie)
            assertEquals(401, expired.statusCode())
            assertTrue(expired.body().contains("SESSION_EXPIRED"))
            assertTrue(expired.headers().firstValue("Set-Cookie").orElseThrow().contains("Max-Age=0"))
            val fresh = server.issueBrowserBootstrap().token
            assertFalse(fresh == first)
            val reissued = request("/nested/api/v1/session", "POST", fresh)
            assertEquals(200, reissued.statusCode())
            assertFalse(reissued.body().contains(fresh))
            val newCookie = reissued.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            assertEquals(200, request("/nested/api/v1/bootstrap", cookie = newCookie).statusCode())
        } finally { server.stop() }
    }

    @Test
    fun `expired browser session rejects private reads and accepts only an explicit fresh operator link`() {
        val configuredChrome = System.getenv("DECOMP_BROWSER_CHROME")
        assumeTrue(configuredChrome != null && Files.isExecutable(Path.of(configuredChrome)), "set DECOMP_BROWSER_CHROME to run the real browser expiry qualification")
        val chrome = requireNotNull(configuredChrome)
        val runtime = System.getenv("DECOMP_BROWSER_JS_RUNTIME") ?: "node"
        val clock = TestClock()
        val server = UploadServer("127.0.0.1", 0, directory.resolve("jobs"),
            uiMode = WebUiMode.SPA, basePath = "/nested/", webAccessClock = clock)
        var browser: Process? = null
        try {
            server.start()
            val errorFile = directory.resolve("browser-stderr.txt")
            val script = Path.of(System.getProperty("user.dir"), "scripts/check-session-expiry-browser.mjs")
            browser = ProcessBuilder(runtime, script.toString(), chrome)
                .directory(Path.of(System.getProperty("user.dir")).toFile())
                .redirectError(errorFile.toFile()).start()
            val reader = BufferedReader(InputStreamReader(browser.inputStream))
            val writer = browser.outputStream.bufferedWriter()
            val first = server.issueBrowserBootstrap().token
            writer.write("${server.browserOrigin}/nested/#bootstrap=$first\n")
            writer.flush()
            assertEquals("authenticated", stage(reader), browserFailure(errorFile, first))
            clock.advance(Duration.ofHours(8))
            writer.write("advanced\n")
            writer.flush()
            assertEquals("expired", stage(reader), browserFailure(errorFile, first))
            val fresh = server.issueBrowserBootstrap().token
            writer.write("${server.browserOrigin}/nested/#bootstrap=$fresh\n")
            writer.flush()
            assertEquals("reauthenticated", stage(reader), browserFailure(errorFile, first, fresh))
            writer.close()
            assertEquals(0, if (browser.waitFor(15, TimeUnit.SECONDS)) browser.exitValue() else -1,
                browserFailure(errorFile, first, fresh))
            val publicDiagnostic = Files.readString(errorFile)
            assertFalse(publicDiagnostic.contains(first), "Initial token reached browser public diagnostics")
            assertFalse(publicDiagnostic.contains(fresh), "Fresh token reached browser public diagnostics")
        } finally {
            browser?.let { process ->
                if (process.isAlive) {
                    process.destroy()
                    if (!process.waitFor(5, TimeUnit.SECONDS)) {
                        process.destroyForcibly()
                        process.waitFor(5, TimeUnit.SECONDS)
                    }
                }
            }
            server.stop()
        }
    }

    private fun stage(reader: BufferedReader): String? = CompletableFuture.supplyAsync { reader.readLine() }
        .get(40, TimeUnit.SECONDS)

    private fun browserFailure(path: Path, vararg tokens: String): String {
        var diagnostic = Files.readString(path)
            .replace(Regex("#bootstrap=[A-Za-z0-9_-]+"), "#bootstrap=[redacted]")
        for (token in tokens) diagnostic = diagnostic.replace(token, "[redacted]")
        return diagnostic.takeLast(3000)
    }

    private class TestClock : WebAccessClock {
        private val wallBase = Instant.now()
        private val elapsedNanos = AtomicLong()
        override fun instant(): Instant = wallBase.plusNanos(elapsedNanos.get())
        override fun nanoTime(): Long = elapsedNanos.get()
        fun advance(duration: Duration) { elapsedNanos.addAndGet(duration.toNanos()) }
    }
}
