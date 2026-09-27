package decompengine.web

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.io.TempDir
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
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
        val profile = createOwnedProfile()
        var chromeProcess: Process? = null
        var driver: Process? = null
        try {
            server.start()
            chromeProcess = ProcessBuilder(chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run",
                "--no-default-browser-check", "--disable-background-networking", "--disable-extensions",
                "--disable-default-apps", "--disable-sync", "--remote-debugging-port=0",
                "--remote-debugging-address=127.0.0.1", "--user-data-dir=$profile", "about:blank")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD).start()
            val errorFile = directory.resolve("browser-stderr.txt")
            val script = Path.of(System.getProperty("user.dir"), "scripts/check-session-expiry-browser.mjs")
            driver = ProcessBuilder(runtime, script.toString(), profile.toString())
                .directory(Path.of(System.getProperty("user.dir")).toFile())
                .redirectError(errorFile.toFile()).start()
            val reader = BufferedReader(InputStreamReader(driver.inputStream))
            val writer = driver.outputStream.bufferedWriter()
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
            assertEquals(0, if (driver.waitFor(15, TimeUnit.SECONDS)) driver.exitValue() else -1,
                browserFailure(errorFile, first, fresh))
            val publicDiagnostic = Files.readString(errorFile)
            assertFalse(publicDiagnostic.contains(first), "Initial token reached browser public diagnostics")
            assertFalse(publicDiagnostic.contains(fresh), "Fresh token reached browser public diagnostics")
        } finally {
            try { stopProcessTree(driver) } finally {
                try { stopProcessTree(chromeProcess) } finally {
                    try { deleteOwnedProfile(profile) } finally { server.stop() }
                }
            }
        }
    }

    @Test
    fun `timed out driver cleanup stops owned processes and removes only its marked profile`() {
        val sleeper = Path.of("/bin/sleep")
        assumeTrue(Files.isExecutable(sleeper), "the cleanup fixture requires /bin/sleep")
        val profile = createOwnedProfile()
        Files.writeString(profile.resolve("History"), "test-only bootstrap history")
        var driver: Process? = null
        var chromeFixture: Process? = null
        var driverPid = -1L
        var chromePid = -1L
        try {
            driver = ProcessBuilder(sleeper.toString(), "30").start()
            chromeFixture = ProcessBuilder(sleeper.toString(), "30").start()
            driverPid = driver.pid()
            chromePid = chromeFixture.pid()
            val reader = BufferedReader(InputStreamReader(driver.inputStream))
            assertFailsWith<TimeoutException> { stage(reader, 100) }
        } finally {
            try { stopProcessTree(driver) } finally {
                try { stopProcessTree(chromeFixture) } finally { deleteOwnedProfile(profile) }
            }
        }
        assertFalse(ProcessHandle.of(driverPid).map(ProcessHandle::isAlive).orElse(false))
        assertFalse(ProcessHandle.of(chromePid).map(ProcessHandle::isAlive).orElse(false))
        assertFalse(Files.exists(profile))
    }

    private fun stage(reader: BufferedReader, timeoutMs: Long = 40_000): String? {
        val pending = CompletableFuture.supplyAsync { reader.readLine() }
        try { return pending.get(timeoutMs, TimeUnit.MILLISECONDS) }
        catch (failure: TimeoutException) { pending.cancel(true); throw failure }
    }

    private fun createOwnedProfile(): Path {
        val profile = Files.createTempDirectory(directory, "chrome-profile-")
        Files.writeString(profile.resolve(PROFILE_MARKER), PROFILE_MARKER_CONTENT, StandardOpenOption.CREATE_NEW)
        return profile
    }

    private fun stopProcessTree(process: Process?) {
        if (process == null) return
        val root = process.toHandle()
        val descendants = root.descendants().use { it.toList() }
        if (process.isAlive) process.destroy()
        if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroyForcibly()
        for (child in descendants.asReversed()) if (child.isAlive) child.destroyForcibly()
        check(process.waitFor(5, TimeUnit.SECONDS)) { "Test-owned process did not exit" }
        for (child in descendants) if (child.isAlive) child.onExit().get(5, TimeUnit.SECONDS)
        check(descendants.none(ProcessHandle::isAlive)) { "Test-owned child process did not exit" }
    }

    private fun deleteOwnedProfile(profile: Path) {
        check(profile.parent == directory && profile.fileName.toString().startsWith("chrome-profile-")) {
            "Refusing to delete an unowned browser profile"
        }
        check(!Files.isSymbolicLink(profile) && Files.readString(profile.resolve(PROFILE_MARKER)) == PROFILE_MARKER_CONTENT) {
            "Refusing to delete a browser profile without its test marker"
        }
        Files.walkFileTree(profile, object : SimpleFileVisitor<Path>() {
            override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
                Files.delete(file)
                return FileVisitResult.CONTINUE
            }
            override fun postVisitDirectory(dir: Path, failure: java.io.IOException?): FileVisitResult {
                if (failure != null) throw failure
                Files.delete(dir)
                return FileVisitResult.CONTINUE
            }
        })
    }

    companion object {
        private const val PROFILE_MARKER = ".decomp-session-expiry-owned"
        private const val PROFILE_MARKER_CONTENT = "test-owned Chrome profile\n"
    }

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
