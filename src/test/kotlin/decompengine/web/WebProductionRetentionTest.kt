package decompengine.web

import decompengine.jobs.*
import kotlinx.serialization.json.*
import java.net.URI
import java.net.http.*
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.io.path.readBytes
import kotlin.test.*

class WebProductionRetentionTest {
    private data class Seed(val jobId: String, val journal: Path, val state: Path, val stateBytes: ByteArray)
    private fun seed(root: Path, old: Boolean, pinned: Boolean): Seed {
        val job = JobStore(root).createFromUpload("inert.elf", elfFixture())
        val clock = Clock.fixed(Instant.now().minusSeconds(if (old) 90000 else 60), ZoneOffset.UTC)
        val run = WorkflowAttemptStore.open(root, clock).use { owner ->
            val view = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            val queued = owner.create(job.id, view.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
            val running = owner.transition(job.id, queued.runId, queued.version, WorkflowTransition.Start).attempt
            val done = owner.transition(job.id, running.runId, running.version,
                WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.NO_CHANGES)).attempt
            if (pinned) owner.setProgressRetentionPinned(job.id, done.runId, done.version, true).attempt else done
        }
        val reports = root.resolve("${job.id}/reports/runs/${run.runId}")
        AgentProgressJournal(reports, "reconstruct").use { }
        val state = root.resolve("${job.id}/workflow-state.json")
        return Seed(job.id, reports.resolve(AgentProgressJournal.FILE_NAME), state, state.readBytes())
    }
    @Test fun `SPA defaults expire old unpinned progress preserve pins and recent history and report counters privately`() {
        val root = Files.createTempDirectory("web-production-retention-")
        val expired = seed(root, old = true, pinned = false)
        val pinned = seed(root, old = true, pinned = true)
        val recent = seed(root, old = false, pinned = false)
        val protectedBytes = listOf(pinned, recent).associateWith { it.journal.readBytes() }
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("Unexpected analysis") },
            JobReconstructor { _, _ -> error("Unexpected reconstruction") }, uiMode = WebUiMode.SPA)
        val client = HttpClient.newHttpClient()
        try {
            server.start(); val origin = "http://127.0.0.1:${server.serverPort}"
            fun bootstrap(cookie: String? = null) = client.send(HttpRequest.newBuilder(URI("$origin/api/v1/bootstrap"))
                .apply { if (cookie != null) header("Cookie", cookie) }.build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(401, bootstrap().statusCode())
            val session = client.send(HttpRequest.newBuilder(URI("$origin/api/v1/session"))
                .header("Origin", origin).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"${server.issueBrowserBootstrap().token}\"}")).build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(200, session.statusCode())
            val cookie = session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(6)
            var result: JsonObject
            while (true) {
                val response = bootstrap(cookie); assertEquals(200, response.statusCode())
                result = Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject
                if (result.getValue("runtime").jsonObject.getValue("progressRetention").jsonObject.getValue("expired").jsonPrimitive.content == "1") break
                assertTrue(System.nanoTime() < deadline, "automatic expiry did not complete")
                Thread.sleep(20)
            }
            val status = result.getValue("runtime").jsonObject.getValue("progressRetention").jsonObject
            assertEquals(JsonPrimitive(true), status["enabled"]); assertEquals(JsonPrimitive("0"), status["failures"])
            assertEquals(JsonNull, status["lastFailureCode"])
            assertEquals(JsonPrimitive("86400000"), result.getValue("limits").jsonObject["terminalEventRetentionMs"])
            val journal = Json.parseToJsonElement(Files.readString(expired.journal)).jsonObject
            assertTrue(journal.getValue("events").jsonArray.isEmpty()); assertNotNull(journal["retentionExpiredAt"])
            protectedBytes.forEach { (item, bytes) -> assertContentEquals(bytes, item.journal.readBytes()) }
            listOf(expired, pinned, recent).forEach { assertContentEquals(it.stateBytes, it.state.readBytes()) }
        } finally { server.stop(); client.close(); root.toFile().deleteRecursively() }
    }
    @Test fun `legacy mode retains its existing nonperiodic behavior`() {
        val root = Files.createTempDirectory("web-legacy-retention-")
        val old = seed(root, old = true, pinned = false); val bytes = old.journal.readBytes()
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("Unexpected analysis") },
            JobReconstructor { _, _ -> error("Unexpected reconstruction") }, uiMode = WebUiMode.LEGACY)
        try { server.start(); Thread.sleep(1300); assertContentEquals(bytes, old.journal.readBytes()) }
        finally { server.stop(); root.toFile().deleteRecursively() }
    }
}
