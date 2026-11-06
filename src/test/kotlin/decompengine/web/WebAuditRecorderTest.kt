package decompengine.web

import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Real session/authorization and recorder components, without job/workflow dependencies. */
class WebAuditRecorderTest {
    @Test fun `accepted and denied requests commit preconditions without persisting credential bytes`() {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/web-audit-recorder").toAbsolutePath()), "credentials-")
        val http = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${http.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin), requestDiagnosticOutput = {})
        val log = WebAuditLog(root)
        val recorder = WebAuditRecorder(access, log)
        val sessions = WebSessionController(access)
        val secret = "CANARYsecret0123456789abcdefXYZ"
        val jobSecret = "b".repeat(32)
        val serverShapedSecret = "run_" + "c".repeat(32)
        val context = http.createContext("/") { exchange ->
            val requestedRun = exchange.requestURI.path.removePrefix("/audit/").takeIf { exchange.requestURI.path.startsWith("/audit/") }
            recorder.around(exchange, WebAuditAction.SUPPORT_EXPORT, WebAuditTarget(jobId = jobSecret, runId = requestedRun)) {
                try {
                    if (exchange.requestURI.path == "/session") sessions.handle(exchange)
                    else {
                        access.authorize(exchange, WebEndpointPolicy.privateRead())
                        // Exercise the same response projection used for an exported audit section.
                        sendWebApiResponse(exchange, 200, "auditPage", log.read().toJson())
                    }
                } catch (denied: WebAccessDenied) { access.sendDenied(exchange, denied) }
            }
        }
        WebRedactionPolicy.install(context, WebRedactionPolicy.create(
            mapOf("TEST_TOKEN" to secret, "TEST_JOB_TOKEN" to jobSecret, "TEST_RUN_TOKEN" to serverShapedSecret),
            listOf(secret, jobSecret, serverShapedSecret), emptyList()))
        val client = HttpClient.newHttpClient()
        fun request(path: String, value: String? = null, cookie: String? = null): HttpResponse<String> {
            val builder = HttpRequest.newBuilder(URI(origin + path))
            if (value != null) builder.header("If-Match", "\"$value\"")
            if (cookie != null) builder.header("Cookie", cookie)
            return client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        }
        fun awaitEntries(count: Int) {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (log.read().entries.size < count && System.nanoTime() < deadline) Thread.sleep(10)
            assertEquals(count, log.read().entries.size)
        }
        http.start()
        try {
            val token = access.issueBootstrap().token
            val login = client.send(HttpRequest.newBuilder(URI("$origin/session")).header("Origin", origin)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"$token\"}")).build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(200, login.statusCode(), login.body())
            val cookie = login.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            val csrf = Json.parseToJsonElement(login.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
            val values = listOf(secret, cookie.substringAfter('='), csrf, serverShapedSecret)
            awaitEntries(1)
            for (value in values) {
                assertEquals(401, request("/audit/$value", value).statusCode())
                assertEquals(200, request("/audit/$value", value, cookie).statusCode())
            }
            val serverRun = "run_" + "a".repeat(32)
            assertEquals(200, request("/audit/$serverRun", cookie = cookie).statusCode())
            awaitEntries(2 + 2 * values.size)
            assertEquals(serverRun, log.read().entries.last().target.runId, "canonical server run IDs remain attributable")
            val file = Files.readString(root.resolve(".web-audit/current.jsonl"))
            val exported = request("/audit", cookie = cookie)
            assertEquals(200, exported.statusCode())
            (values + jobSecret).forEach { value ->
                assertFalse(file.contains(value), "credential must not be stored")
                assertFalse(exported.body().contains(value), "credential must not be exported")
            }
            val entries = log.read().entries.filter { it.target.expectedVersion != null }
            assertEquals(2 * values.size, entries.size)
            assertTrue(entries.all { it.target.jobId == null }, "configured-sensitive IDs must be excluded before append")
            assertEquals(values.map { WebAuditRecorder.versionCommitment(it) }.toSet(), entries.map { it.target.expectedVersion }.toSet())
            assertTrue(entries.all { it.target.expectedVersion!!.matches(Regex("ifmatch_[a-f0-9]{64}")) })
            assertEquals(values.map { WebAuditRecorder.runCommitment(it) }.toSet(), entries.map { it.target.runId }.toSet())
            assertEquals(values.size, entries.count { it.outcome == WebAuditOutcome.REJECTED })
            assertEquals(values.size, entries.count { it.outcome == WebAuditOutcome.ACCEPTED })
        } finally { http.stop(0); access.close(); root.toFile().deleteRecursively() }
    }
}
