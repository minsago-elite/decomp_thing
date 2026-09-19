package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.time.Duration
import java.util.concurrent.Executor
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LegacyWebSessionTest {
    @Test
    fun `legacy pages APIs and downloads share session revocation and mutations require CSRF`() {
        val root = createTempDirectory("legacy-session-")
        var executions = 0
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> executions++ },
            JobReconstructor { _, _ -> executions++ }, Executor { it.run() })
        server.start()
        val store = JobStore(root)
        val job = store.createFromUpload("private-fixture.elf", elfFixture())
        val record = root.resolve(job.id).resolve("job.json")
        val before = Files.readAllBytes(record)
        val origin = "http://127.0.0.1:${server.serverPort}"
        val client = HttpClient.newHttpClient()
        fun request(path: String, method: String = "GET", headers: Map<String, String> = emptyMap()): HttpResponse<String> {
            val builder = HttpRequest.newBuilder(URI(origin + path)).timeout(Duration.ofSeconds(5))
                .method(method, HttpRequest.BodyPublishers.noBody())
            headers.forEach { (key, value) -> builder.header(key, value) }
            return client.send(builder.build(), HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
        }
        fun assertCommonSecurity(response: HttpResponse<String>) {
            assertEquals("nosniff", response.headers().firstValue("X-Content-Type-Options").orElseThrow())
            assertEquals("no-referrer", response.headers().firstValue("Referrer-Policy").orElseThrow())
            assertEquals("DENY", response.headers().firstValue("X-Frame-Options").orElseThrow())
            val policy = response.headers().firstValue("Content-Security-Policy").orElseThrow()
            assertFalse(policy.contains("unsafe-inline"))
            assertFalse(policy.contains("unsafe-eval"))
        }
        fun assertApplicationSecurity(response: HttpResponse<String>, trustedScripts: Iterable<String>? = null) {
            assertCommonSecurity(response)
            val policy = response.headers().firstValue("Content-Security-Policy").orElseThrow()
            if (trustedScripts != null) {
                assertEquals(webApplicationContentSecurityPolicy(trustedScripts), policy)
            } else {
                val sessionSource = webApplicationContentSecurityPolicy(listOf(LEGACY_SESSION_SCRIPT))
                    .substringAfter("script-src 'self' ").substringBefore(';')
                assertTrue(policy.contains(sessionSource))
            }
            assertFalse(response.body().contains("style="))
        }
        fun assertInertSecurity(response: HttpResponse<String>) {
            assertCommonSecurity(response)
            assertEquals(WEB_INERT_CONTENT_SECURITY_POLICY,
                response.headers().firstValue("Content-Security-Policy").orElseThrow())
        }
        try {
            val paths = listOf("/", "/jobs/${job.id}", "/api/jobs/${job.id}", "/api/jobs/${job.id}/events",
                "/jobs/${job.id}/source/missing.c", "/jobs/${job.id}/artifacts/reports/missing.txt", "/missing")
            for (path in paths) {
                val denied = request(path)
                assertEquals(401, denied.statusCode(), path)
                assertFalse(denied.body().contains("private-fixture"))
                assertEquals("no-store", denied.headers().firstValue("Cache-Control").orElseThrow())
                if (denied.headers().firstValue("Content-Type").orElse("").startsWith("text/html")) {
                    assertApplicationSecurity(denied, listOf(LEGACY_LOGIN_SCRIPT))
                } else assertInertSecurity(denied)
            }
            val login = request("/login")
            assertEquals(200, login.statusCode())
            assertApplicationSecurity(login, listOf(LEGACY_LOGIN_SCRIPT))
            val style = request("/assets/app.css")
            assertEquals(200, style.statusCode())
            assertInertSecurity(style)
            val session = legacySessionHeaders(server)
            val cookie = session.filterKeys { it == "Cookie" }
            val jobPage = request("/jobs/${job.id}", headers = cookie)
            assertEquals(200, jobPage.statusCode())
            assertApplicationSecurity(jobPage)
            val legacyApi = request("/api/jobs/${job.id}", headers = cookie)
            assertEquals(200, legacyApi.statusCode())
            assertInertSecurity(legacyApi)
            val csrf = request("/api/v1/session/csrf", headers = cookie)
            assertEquals(200, csrf.statusCode())
            assertInertSecurity(csrf)
            for (path in listOf("/jobs", "/jobs/${job.id}/explore", "/jobs/${job.id}/reconstruct")) {
                val contentType = if (path == "/jobs") "multipart/form-data; boundary=fixture" else "application/json"
                val base = mapOf("Origin" to origin, "Content-Type" to contentType)
                assertEquals(401, request(path, "POST", base).statusCode())
                assertEquals(403, request(path, "POST", base + cookie).statusCode())
                assertEquals(403, request(path, "POST", base + session + ("X-CSRF-Token" to "invalid")).statusCode())
            }
            assertContentEquals(before, Files.readAllBytes(record))
            assertEquals(0, executions)
            val logout = request("/api/v1/session", "DELETE", session + mapOf("Origin" to origin, "Content-Type" to "application/json"))
            assertEquals(204, logout.statusCode())
            assertInertSecurity(logout)
            assertTrue(logout.headers().firstValue("Set-Cookie").orElseThrow().contains("Max-Age=0"))
            for (path in paths + "/api/v1/session/csrf") assertEquals(401, request(path, headers = cookie).statusCode(), path)
            assertContentEquals(before, Files.readAllBytes(record))
            assertEquals(0, executions)
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }
}
