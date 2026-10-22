package decompengine.web

import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * One browser session across the real SPA routes: page reload (bootstrap), event reconnect (SSE with
 * Last-Event-ID) and a normal file download all work under it, none of those GETs mutate stored state,
 * and every one of them is refused once the session is logged out or expired.
 */
class WebSessionRealRoutesTest {
    private val root: Path = Files.createTempDirectory(Path.of("build"), "session-real-routes")
    private val http: HttpClient = HttpClient.newHttpClient()

    @AfterTest fun cleanup() { http.close(); root.toFile().deleteRecursively() }

    private class TestClock : WebAccessClock {
        private val wallBase = Instant.now()
        private val elapsedNanos = AtomicLong()
        override fun instant(): Instant = wallBase.plusNanos(elapsedNanos.get())
        override fun nanoTime(): Long = elapsedNanos.get()
        fun advance(duration: Duration) { elapsedNanos.addAndGet(duration.toNanos()) }
    }

    private fun storageDigest(): Map<String, String> = Files.walk(root).use { paths ->
        paths.filter { Files.isRegularFile(it) }.toList().associate { file ->
            root.relativize(file).toString() to MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)).joinToString("") { "%02x".format(it) }
        }
    }

    @Test
    fun `reload, event reconnect and download share one session, GET is read-only, and logout or expiry refuses all of them`() {
        val store = JobStore(root)
        val job = store.createFromUpload("inert.elf", elfFixture())
        val run = WorkflowAttemptStore.open(root).use { owner ->
            val original = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            owner.create(job.id, original.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
        }
        val reports = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/${run.runId}"))
        AgentProgressJournal(reports, "reconstruct").use { it.phase(decompengine.agent.AgentWorkflowPhase.PLANNING) }
        val raw = "{\"fixture\":\"inert session download\"}"
        Files.writeString(reports.resolve("exploration.json"), raw)

        val clock = TestClock()
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected analysis") },
            JobReconstructor { _, _ -> error("unexpected reconstruction") }, uiMode = WebUiMode.SPA, basePath = "/w/", webAccessClock = clock)
        server.start()
        try {
            val origin = "http://127.0.0.1:${server.serverPort}"
            val api = "/w/api/v1"
            val runPath = "$api/jobs/${job.id}/runs/${run.runId}"
            fun call(path: String, method: String = "GET", cookie: String? = null, headers: Map<String, String> = emptyMap(), body: String? = null): HttpResponse<String> {
                val builder = HttpRequest.newBuilder(URI(origin + path)).timeout(Duration.ofSeconds(5)).header("Accept", "application/json")
                if (cookie != null) builder.header("Cookie", cookie)
                if (method != "GET" && method != "HEAD") builder.header("Origin", origin).header("Content-Type", "application/json")
                headers.forEach { (k, v) -> builder.setHeader(k, v) }
                builder.method(method, body?.let { HttpRequest.BodyPublishers.ofString(it) } ?: HttpRequest.BodyPublishers.noBody())
                return http.send(builder.build(), HttpResponse.BodyHandlers.ofString())
            }
            fun signIn(): Pair<String, String> {
                val response = call("$api/session", "POST", body = "{\"token\":\"${server.issueBrowserBootstrap().token}\"}")
                assertEquals(200, response.statusCode())
                val csrf = Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
                return response.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';') to csrf
            }
            /** Opens the SSE stream and returns its status plus the first event id and data line it delivers, if any. */
            fun stream(cookie: String, query: String = "", lastEventId: String? = null): Triple<Int, String?, String?> {
                val builder = HttpRequest.newBuilder(URI("$origin$runPath/events$query")).timeout(Duration.ofSeconds(5))
                    .header("Cookie", cookie).header("Accept", "text/event-stream")
                if (lastEventId != null) builder.header("Last-Event-ID", lastEventId)
                val response = http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream())
                if (response.statusCode() != 200) { response.body().close(); return Triple(response.statusCode(), null, null) }
                return response.body().bufferedReader().use { reader ->
                    CompletableFuture.supplyAsync {
                        var id: String? = null; var data: String? = null
                        var line = reader.readLine()
                        while (line != null && data == null) {
                            if (line.startsWith("id: ")) id = line.removePrefix("id: ")
                            if (line.startsWith("data: ")) data = line.removePrefix("data: ")
                            if (data == null) line = reader.readLine()
                        }
                        Triple(200, id, data)
                    }.get(5, TimeUnit.SECONDS)
                }
            }
            fun artifactHref(cookie: String): String = Json.parseToJsonElement(call("$runPath/reports/exploration", cookie = cookie).body())
                .jsonObject.getValue("data").jsonObject.getValue("sourceArtifact").jsonObject.getValue("contentHref").jsonPrimitive.content

            /** Cursors are bound to the session that read them, so each session takes its own snapshot cursor. */
            fun oldestCursor(cookie: String): String = Json.parseToJsonElement(call("$runPath/snapshot", cookie = cookie).body())
                .jsonObject.getValue("data").jsonObject.getValue("oldestCursor").jsonPrimitive.content

            val (cookie, csrf) = signIn()
            val before = storageDigest()

            // Reads under one session: reload recovery, snapshot, event stream, then a resume from its last event id.
            val reload = call("$api/bootstrap", cookie = cookie)
            assertEquals(200, reload.statusCode())
            assertEquals(csrf, Json.parseToJsonElement(reload.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content)
            val oldest = oldestCursor(cookie)
            val (status, eventId, eventData) = stream(cookie, "?after=$oldest&limit=1")
            assertEquals(200, status)
            assertTrue(eventId != null && eventData != null, "the stream delivered no event: $eventId $eventData")
            val resumed = stream(cookie, lastEventId = eventId)
            assertEquals(200, resumed.first, "reconnect with Last-Event-ID under the same session failed")
            val href = artifactHref(cookie)
            val download = call(href, cookie = cookie, headers = mapOf("Accept" to "application/octet-stream"))
            assertEquals(200, download.statusCode()); assertEquals(raw, download.body())
            assertEquals(200, call("$api/jobs/${job.id}", cookie = cookie).statusCode())
            assertEquals(200, call("$api/jobs/${job.id}/runs", cookie = cookie).statusCode())
            // GET remained read-only: no stored byte changed.
            assertEquals(before, storageDigest(), "a GET changed stored state")

            // Logout: every one of the same requests is now refused, including a reconnect with the same event id.
            assertEquals(204, call("$api/session", "DELETE", cookie, mapOf("X-CSRF-Token" to csrf)).statusCode())
            assertEquals(401, call("$api/bootstrap", cookie = cookie).statusCode())
            assertEquals(401, call("$runPath/snapshot", cookie = cookie).statusCode())
            assertEquals(401, stream(cookie, lastEventId = eventId).first)
            assertEquals(401, call(href, cookie = cookie, headers = mapOf("Accept" to "application/octet-stream")).statusCode())
            assertEquals(401, call(href, "HEAD", cookie, mapOf("Accept" to "application/octet-stream")).statusCode())

            // A different session cannot resume from the first session's event id.
            val (second, _) = signIn()
            val foreign = stream(second, lastEventId = eventId)
            assertTrue(foreign.first in 400..499, "another session resumed a foreign cursor (${foreign.first})")
            assertEquals(200, stream(second, "?after=${oldestCursor(second)}&limit=1").first)

            // Expiry on a monotonic clock refuses the same paths with a distinct session-expired error.
            clock.advance(Duration.ofHours(8))
            val expiredReads = listOf(call("$api/bootstrap", cookie = second), call("$runPath/snapshot", cookie = second),
                call(href, cookie = second, headers = mapOf("Accept" to "application/octet-stream")))
            // The first denied use reports the expiry; the session record is then gone, so later uses are plainly unauthenticated.
            assertTrue(expiredReads.first().body().contains("SESSION_EXPIRED"), expiredReads.first().body())
            for (response in expiredReads) {
                assertEquals(401, response.statusCode())
                assertTrue(response.body().contains("SESSION_EXPIRED") || response.body().contains("SESSION_REQUIRED"), response.body())
            }
            assertEquals(401, stream(second, lastEventId = eventId).first)
            // Reconnecting never resurrects a session: only an explicit fresh link does.
            val (third, _) = signIn()
            assertEquals(200, call("$api/bootstrap", cookie = third).statusCode())
            assertEquals(200, stream(third, "?after=${oldestCursor(third)}&limit=1").first)
        } finally { server.stop() }
    }
}
