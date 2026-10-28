package decompengine.web

import com.sun.net.httpserver.HttpServer
import decompengine.jobs.ArtifactChangedException
import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.elfFixture
import decompengine.repair.StableFileChangedException
import decompengine.repair.readStableRegularFile
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
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebExplorationContainmentHttpTest {
    @Test fun `exploration changes are conflicts but a missing report remains unavailable`() {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/exploration-containment").toAbsolutePath()), "http-")
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        val run = WorkflowAttemptStore.open(root).use { owner ->
            val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            owner.create(job.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.EXPLORE,
                WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
        }
        val service = WebJobService(store, JobAnalyzer { _, _ -> error("unexpected analysis") },
            JobReconstructor { _, _ -> error("unexpected reconstruction") })
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin))
        val resources = WebStreamResources()
        val client = HttpClient.newHttpClient()
        try {
            service.initializeExistingStorage()
            val version = service.getAttempt(job.id, run.runId).version
            val relative = "reports/runs/${run.runId}/exploration.json"
            val report = Files.createDirectories(root.resolve(job.id).resolve(relative).parent).resolve("exploration.json")
            val duringRead = AtomicReference<(() -> Unit)?>(null)
            val api = WebApiController(access, EmbeddedWebAssets.load(), service,
                WebJobMutationBoundary(access, service), resources, readExplorationArtifact = { id, path, limit ->
                    assertEquals(job.id, id); assertEquals(relative, path)
                    val hook = duringRead.get()
                    if (hook == null) service.readArtifact(id, path, limit) else {
                        // Exercise a real descriptor change deterministically, with the same typed
                        // translation as JobStore's containment boundary, rather than a timing race.
                        try { readStableRegularFile(root, "$id/$path", limit, afterRead = hook) }
                        catch (_: StableFileChangedException) { throw ArtifactChangedException("PRIVATE_CHANGE_CANARY") }
                    }
                })
            server.createContext("/") { check(api.route(it)) }
            server.start()
            fun send(path: String, cookie: String? = null, body: String? = null): HttpResponse<String> {
                val request = HttpRequest.newBuilder(URI.create(origin + path)).timeout(Duration.ofSeconds(5))
                    .header("Accept", "application/json")
                cookie?.let { request.header("Cookie", it) }
                if (body == null) request.GET() else request.header("Origin", origin).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                return client.send(request.build(), HttpResponse.BodyHandlers.ofString())
            }
            val session = send("/api/v1/session", body = "{\"token\":\"${access.issueBootstrap().token}\"}")
            assertEquals(200, session.statusCode())
            val cookie = session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            val path = "/api/v1/jobs/${job.id}/runs/${run.runId}/reports/exploration"
            assertEquals(401, send(path).statusCode())
            val missing = send(path, cookie)
            assertEquals(200, missing.statusCode())
            assertEquals("unknown", Json.parseToJsonElement(missing.body()).jsonObject.getValue("data").jsonObject.getValue("state").jsonPrimitive.content)
            for (replace in listOf(false, true)) {
                Files.writeString(report, "{}")
                val changed = AtomicBoolean()
                duringRead.set {
                    changed.set(true)
                    if (replace) {
                        val replacement = report.resolveSibling("replacement.json")
                        Files.writeString(replacement, "{\"replacement\":true}")
                        Files.move(replacement, report, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                    } else Files.writeString(report, " ", StandardOpenOption.APPEND)
                }
                val response = send(path, cookie)
                assertTrue(changed.get())
                assertEquals(409, response.statusCode(), response.body())
                assertEquals("ARTIFACT_CHANGED", Json.parseToJsonElement(response.body()).jsonObject.getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
                assertFalse(response.body().contains("PRIVATE_CHANGE_CANARY") || response.body().contains(root.toString()))
                assertEquals(version, service.getAttempt(job.id, run.runId).version, "the conflict is not an attempt-version change")
            }
            duringRead.set(null)
            Files.delete(report)
            assertEquals(200, send(path, cookie).statusCode(), "missing reports retain their normal fallback")
        } finally {
            server.stop(0); client.close(); resources.close(); access.close(); service.close()
            root.toFile().deleteRecursively()
        }
    }
}
