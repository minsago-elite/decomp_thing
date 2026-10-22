package decompengine.web

import org.junit.jupiter.api.io.TempDir
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.NetworkInterface
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Loopback is the default and the only bindable class today: a non-loopback host is refused before
 * anything is created or bound, in both browser UI modes, until a remote access profile is qualified.
 */
class WebBindingPolicyTest {
    @TempDir lateinit var directory: Path

    private val nonLoopbackHosts = listOf("0.0.0.0", "::", "192.0.2.1", "10.0.0.1", "169.254.1.1", "224.0.0.1")

    @Test
    fun `non-loopback hosts are refused in both UI modes before anything is created or bound`() {
        for (mode in WebUiMode.entries) for (host in nonLoopbackHosts) {
            val storage = directory.resolve("absent-${mode.name}-${host.filter { it.isLetterOrDigit() }}")
            val failure = assertFailsWith<IllegalArgumentException>("$mode accepted $host") {
                UploadServer(host, 0, storage, uiMode = mode)
            }
            assertTrue(failure.message.orEmpty().contains("loopback"), "refusal for $host must name the loopback policy: ${failure.message}")
            assertFalse(Files.exists(storage), "$mode created storage for refused host $host")
        }
    }

    @Test
    fun `loopback hosts bind and advertise a loopback browser origin in both UI modes`() {
        val hosts = buildList {
            add("127.0.0.1"); add("127.0.0.2"); add("localhost")
            // IPv6 loopback is skipped on hosts without it rather than weakening the assertion.
            val v6 = runCatching { NetworkInterface.getByInetAddress(InetAddress.getByName("::1")) != null }.getOrDefault(false)
            if (v6) add("::1")
        }
        for (mode in WebUiMode.entries) for (host in hosts) {
            val server = UploadServer(host, 0, directory.resolve("ok-${mode.name}-${host.filter { it.isLetterOrDigit() }}"), uiMode = mode)
            try {
                val authority = server.browserOrigin.substringAfter("://").substringBeforeLast(':')
                assertTrue(InetAddress.getByName(authority.trim('[', ']')).isLoopbackAddress, "origin ${server.browserOrigin} for $host is not loopback")
                assertNotEquals(0, server.serverPort)
            } finally { server.stop() }
        }
    }

    private fun runCli(vararg arguments: String): Process = ProcessBuilder(
        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
        "-Djava.io.tmpdir=${System.getProperty("java.io.tmpdir")}", "-cp", System.getProperty("java.class.path"),
        "decompengine.MainKt", "web", *arguments,
    ).apply { environment().clear() }.start()

    @Test
    fun `the web command serves on 127_0_0_1 unless a host is explicitly given`() {
        val process = runCli("--port", "0", "--data-dir", directory.resolve("cli-default").toString())
        try {
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val first = CompletableFuture.supplyAsync { reader.readLine() }.get(60, TimeUnit.SECONDS)
            assertTrue(first.startsWith("Serving decomp_engine legacy UI on http://127.0.0.1:"), first)
        } finally {
            process.destroyForcibly().waitFor(10, TimeUnit.SECONDS)
        }
    }

    @Test
    fun `the web command refuses a non-loopback host in both UI modes and starts nothing`() {
        for (mode in listOf("legacy", "spa")) for (host in listOf("0.0.0.0", "192.0.2.1")) {
            val storage = directory.resolve("cli-$mode-${host.filter { it.isDigit() }}")
            val process = runCli("--host", host, "--port", "0", "--ui", mode, "--data-dir", storage.toString())
            try {
                assertTrue(process.waitFor(60, TimeUnit.SECONDS), "$mode $host did not exit")
                val stdout = process.inputStream.readNBytes(16 * 1024).decodeToString()
                val stderr = process.errorStream.readNBytes(16 * 1024).decodeToString()
                assertNotEquals(0, process.exitValue(), "$mode $host exited successfully")
                assertFalse(stdout.contains("Serving decomp_engine"), "$mode $host started serving: $stdout")
                assertFalse(stdout.contains("bootstrap="), "a session link was issued for a refused host")
                assertTrue(stderr.contains("loopback"), "refusal should name the loopback policy: $stderr")
                assertEquals(false, Files.exists(storage), "$mode $host created storage")
            } finally {
                if (process.isAlive) process.destroyForcibly().waitFor(10, TimeUnit.SECONDS)
            }
        }
    }

    private fun rawSessionExchange(port: Int, host: String, origin: String?, token: String): Pair<Int, String> {
        val body = "{\"token\":\"$token\"}"
        val request = buildString {
            append("POST /nested/api/v1/session HTTP/1.1\r\nHost: $host\r\n")
            if (origin != null) append("Origin: $origin\r\n")
            append("Content-Type: application/json\r\nAccept: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body")
        }
        java.net.Socket("127.0.0.1", port).use { socket ->
            socket.soTimeout = 5_000
            socket.getOutputStream().write(request.toByteArray())
            val response = socket.getInputStream().readBytes().decodeToString()
            return response.lineSequence().first().split(' ')[1].toInt() to response.substringBefore("\r\n\r\n")
        }
    }

    @Test
    fun `a dev frontend origin is an exact Host and Origin allowlist entry and never enables CORS`() {
        val server = UploadServer("127.0.0.1", 0, directory.resolve("dev-origin"), uiMode = WebUiMode.SPA, basePath = "/nested/",
            devFrontendOrigin = "http://localhost:5173")
        server.start()
        try {
            val port = server.serverPort
            val own = "127.0.0.1:$port"
            fun attempt(host: String, origin: String?) = rawSessionExchange(port, host, origin, server.issueBrowserBootstrap().token)
            // The server's own authority and the configured dev authority are admitted only as a matching Host/Origin pair.
            assertEquals(200, attempt(own, "http://$own").first)
            assertEquals(200, attempt("localhost:5173", "http://localhost:5173").first)
            // Everything else fails closed: mismatched pairs, unlisted loopback ports and aliases, foreign hosts, a missing Origin.
            val refused = listOf(
                own to "http://localhost:5173",           // allowlisted origin, but not on the matching Host
                "localhost:5173" to "http://$own",        // the reverse mismatch
                "localhost:5174" to "http://localhost:5174", // unlisted loopback port
                "127.0.0.1:5173" to "http://127.0.0.1:5173", // unlisted loopback alias of the dev port
                "evil.invalid" to "http://evil.invalid",
                "localhost:5173" to "http://evil.invalid",
                "localhost:5173" to "null",
                "localhost:5173" to null,
            )
            for ((host, origin) in refused) {
                val (status, head) = attempt(host, origin)
                assertTrue(status in 400..499, "Host=$host Origin=$origin was admitted ($status)")
                assertFalse(head.lines().any { it.startsWith("Access-Control-", ignoreCase = true) }, "CORS header for Host=$host Origin=$origin")
            }
            // Even an admitted dev pair does not receive permissive CORS headers.
            assertFalse(attempt("localhost:5173", "http://localhost:5173").second.lines().any { it.startsWith("Access-Control-", ignoreCase = true) })
        } finally { server.stop() }
    }
}
