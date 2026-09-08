package decompengine.web

import com.sun.net.httpserver.HttpServer
import decompengine.jobs.*
import kotlinx.serialization.json.*
import java.io.BufferedReader
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

/** Owned inert records only: no adapter, analyzer or executor performs workflow work. */
class WebProgressCutoverTest {
    private class Fixture : AutoCloseable {
        val root = Files.createTempDirectory("web-progress-cutover-")
        val store = JobStore(root)
        val job = store.createFromUpload("cutover.elf", elfFixture())
        lateinit var owner: WorkflowAttemptStore
        val service = WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected analysis") },
            JobReconstructor { _, _ -> error("Unexpected reconstruction") },
            attemptStoreFactory = { WorkflowAttemptStore.open(it).also { value -> owner = value } })
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin))
        val resources = WebStreamResources(maximumConnections = 4)
        val httpWorkers = Executors.newFixedThreadPool(2)
        val client = HttpClient.newHttpClient()
        val run: WorkflowAttempt
        val journal: java.nio.file.Path
        val path: String
        val cookie: String
        init {
            service.initializeExistingStorage()
            val original = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            run = owner.create(job.id, original.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
            journal = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/${run.runId}"))
                .resolve(AgentProgressJournal.FILE_NAME)
            publish(0, 0)
            path = "/cutover/api/v1/jobs/${job.id}/runs/${run.runId}"
            val api = WebApiController(access, EmbeddedWebAssets.load(basePath = "/cutover/"), service, resources)
            server.executor = httpWorkers
            server.createContext("/") { exchange -> check(api.route(exchange)) }
            server.start()
            val bootstrap = access.issueBootstrap().token
            val response = client.send(HttpRequest.newBuilder(URI("$origin/cutover/api/v1/session"))
                .header("Origin", origin).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"$bootstrap\"}")).build(), HttpResponse.BodyHandlers.ofString())
            check(response.statusCode() == 200)
            cookie = response.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
        }
        fun publish(first: Int, last: Int) {
            val bytes = buildJsonObject {
                put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", last + 1)
                put("queueDropped", 0); put("historyDropped", first); put("truncated", first > 0)
                put("events", buildJsonArray { (first..last).forEach { sequence -> add(buildJsonObject {
                    put("sequence", sequence); put("runId", "writer_cutover_fixture"); put("workflow", "reconstruct")
                    put("time", "2026-09-08T00:00:00Z"); put("kind", "workflow_phase"); put("phase", "planning")
                    put("text", "PRIVATE_CUTOVER_PROSE")
                }) } })
            }.toString()
            val temporary = journal.resolveSibling("publication.next")
            Files.writeString(temporary, bytes)
            Files.move(temporary, journal, ATOMIC_MOVE, REPLACE_EXISTING)
        }
        fun get(suffix: String): HttpResponse<String> = client.send(HttpRequest.newBuilder(URI(origin + path + suffix))
            .timeout(Duration.ofSeconds(5)).header("Cookie", cookie).header("Accept", "application/json").build(),
            HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
        fun stream(cursor: String): HttpResponse<java.io.InputStream> = client.send(HttpRequest.newBuilder(URI(origin + path + "/events"))
            .timeout(Duration.ofSeconds(5)).header("Cookie", cookie).header("Accept", "text/event-stream")
            .header("Last-Event-ID", cursor).build(), HttpResponse.BodyHandlers.ofInputStream()).also(::assertNoWebCors)
        override fun close() {
            resources.shutdown(); server.stop(0); assertTrue(resources.shutdown())
            service.close(); access.close(); httpWorkers.shutdownNow()
            assertTrue(httpWorkers.awaitTermination(5, TimeUnit.SECONDS))
            client.close(); root.toFile().deleteRecursively()
        }
    }
    private fun data(response: HttpResponse<String>): JsonObject {
        assertEquals(200, response.statusCode())
        assertFalse(response.body().contains("PRIVATE_CUTOVER_PROSE"))
        return Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject
    }
    private fun replay(f: Fixture, cursor: String): List<String> {
        val result = mutableListOf<String>()
        var position = cursor
        repeat(40) {
            val page = data(f.get("/events?transport=poll&limit=7&after=$position"))
            val retry = data(f.get("/events?transport=poll&limit=7&after=$position"))
            assertEquals(page, retry, "Read retries must not acknowledge data on behalf of a client")
            val events = page.getValue("items").jsonArray
            assertTrue(events.size <= 7)
            result += events.map { it.jsonObject.getValue("sequence").jsonPrimitive.content }
            if (!page.getValue("hasMore").jsonPrimitive.boolean) return result
            position = page.getValue("nextCursor").jsonPrimitive.content
        }
        error("Replay exceeded its bounded page count")
    }
    private fun frame(reader: BufferedReader): Map<String, String> {
        val result = linkedMapOf<String, String>()
        while (true) {
            val line = reader.readLine() ?: error("Stream ended before the expected event")
            if (line.isEmpty() && "data" in result) return result
            if (line.startsWith(':')) continue
            if (line.contains(": ")) result[line.substringBefore(": ")] = line.substringAfter(": ")
        }
    }

    @Test fun `racing HTTP snapshots and atomic publication have exact bounded replay cutovers`() = Fixture().use { f ->
        val barrier = CyclicBarrier(2)
        val captured = Array(34) { CountDownLatch(1) }
        val published = Array(34) { CountDownLatch(1) }
        val publisher = Executors.newSingleThreadExecutor()
        val publications = publisher.submit {
            var current = f.run
            for (step in 1..33) {
                barrier.await(10, TimeUnit.SECONDS)
                if (step % 3 == 1) check(captured[step].await(5, TimeUnit.SECONDS))
                f.publish(0, step * 8)
                if (step == 3) current = f.owner.transition(f.job.id, current.runId, current.version, WorkflowTransition.Start).attempt
                if (step == 33) f.owner.transition(f.job.id, current.runId, current.version,
                    WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED))
                published[step].countDown()
                barrier.await(10, TimeUnit.SECONDS)
            }
        }
        var overlappingSnapshots = 0
        try {
            for (step in 1..33) {
                barrier.await(10, TimeUnit.SECONDS)
                if (step % 3 == 2) assertTrue(published[step].await(5, TimeUnit.SECONDS))
                val observed = f.get("/snapshot")
                captured[step].countDown()
                barrier.await(10, TimeUnit.SECONDS)
                val snapshot = if (observed.statusCode() == 200) {
                    overlappingSnapshots++; data(observed)
                } else {
                    assertEquals(0, step % 3, "An ordered read must succeed without publication overlap")
                    assertEquals(503, observed.statusCode())
                    assertEquals("PROGRESS_UNAVAILABLE", Json.parseToJsonElement(observed.body()).jsonObject
                        .getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
                    data(f.get("/snapshot")) // A reported interrupted read must never masquerade as empty history.
                }
                val through = snapshot.getValue("throughSequence").jsonPrimitive.int
                assertTrue(through in (step - 1) * 8..step * 8)
                if (step % 3 == 1) assertEquals((step - 1) * 8, through)
                if (step % 3 == 2) assertEquals(step * 8, through)
                assertEquals((through + 1).toString(), snapshot.getValue("progress").jsonObject.getValue("nextSequence").jsonPrimitive.content)
                val run = snapshot.getValue("run").jsonObject
                assertEquals(f.run.runId, run.getValue("runId").jsonPrimitive.content)
                assertEquals("not-evaluated", run.getValue("acceptance").jsonPrimitive.content)
                when (run.getValue("state").jsonPrimitive.content) {
                    "queued" -> assertTrue(through <= 24)
                    "running" -> assertTrue(through >= 24)
                    "completed" -> assertEquals(264, through)
                    else -> error("Unexpected fixture lifecycle state")
                }
                assertEquals(((through + 1)..(step * 8)).map(Int::toString),
                    replay(f, snapshot.getValue("throughCursor").jsonPrimitive.content))
            }
            publications.get(10, TimeUnit.SECONDS)
            assertTrue(overlappingSnapshots >= 22)
            println("Cutover qualification: 33 rounds, 264 appends, 11 forced-before, 11 forced-after, 11 racing snapshots; $overlappingSnapshots initial snapshots succeeded, ${33 - overlappingSnapshots} explicit interrupted reads recovered.")
        } finally { publisher.shutdownNow(); assertTrue(publisher.awaitTermination(5, TimeUnit.SECONDS)) }
    }

    @Test fun `atomic eviction during SSE gives a gap and fresh snapshot resumes later publication`() = Fixture().use { f ->
        f.publish(0, 7)
        val snapshot = data(f.get("/snapshot"))
        val cursor = snapshot.getValue("throughCursor").jsonPrimitive.content
        val readerWorker = Executors.newSingleThreadExecutor()
        try {
            val connection = f.stream(cursor)
            assertEquals(200, connection.statusCode())
            connection.body().bufferedReader().use { reader ->
                val pending = readerWorker.submit<Map<String, String>> { frame(reader) }
                f.publish(8, 15)
                val gap = pending.get(5, TimeUnit.SECONDS)
                assertEquals("retention.gap", gap["event"]); assertFalse("id" in gap)
                val control = Json.parseToJsonElement(gap.getValue("data")).jsonObject
                assertEquals(JsonNull, control["cursor"]); assertEquals(JsonNull, control["sequence"])
                assertEquals(cursor, control.getValue("payload").jsonObject.getValue("requestedCursor").jsonPrimitive.content)
                assertNull(readerWorker.submit<String?> { reader.readLine() }.get(5, TimeUnit.SECONDS))
            }
            val expired = f.get("/events?transport=poll&after=$cursor")
            assertEquals(410, expired.statusCode())
            assertEquals("EVENT_GAP", Json.parseToJsonElement(expired.body()).jsonObject.getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
            val fresh = data(f.get("/snapshot"))
            assertEquals("8", fresh.getValue("progress").jsonObject.getValue("historyDropped").jsonPrimitive.content)
            val freshCursor = fresh.getValue("throughCursor").jsonPrimitive.content
            val resumed = f.stream(freshCursor)
            assertEquals(200, resumed.statusCode())
            resumed.body().bufferedReader().use { reader ->
                val pending = readerWorker.submit<List<JsonObject>> { (16..23).map {
                    val event = frame(reader)
                    assertEquals("workflow.observation", event["event"])
                    Json.parseToJsonElement(event.getValue("data")).jsonObject.also { value ->
                        assertEquals(value.getValue("cursor").jsonPrimitive.content, event["id"])
                    }
                } }
                f.publish(8, 23)
                val delivered = pending.get(5, TimeUnit.SECONDS)
                assertEquals((16..23).map(Int::toString), delivered.map { it.getValue("sequence").jsonPrimitive.content })
                assertEquals((16..23).map(Int::toString), replay(f, freshCursor))
            }
        } finally { readerWorker.shutdownNow(); assertTrue(readerWorker.awaitTermination(5, TimeUnit.SECONDS)) }
    }
}
