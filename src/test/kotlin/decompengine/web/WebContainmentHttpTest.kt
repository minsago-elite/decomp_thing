package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.RandomAccessFile
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Artifact containment and redaction through the real v1 listener with benign isolated fixtures: a
 * report file replaced by a symlink, hard link, linked parent directory, FIFO or oversized sparse file
 * never discloses the outside canary, a private path or a raw failure, and every refusal logs only
 * the fixed request-failure line.
 */
class WebContainmentHttpTest {
    private val scratch: Path = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp")), "web-containment-")
    private val root: Path = Files.createDirectories(scratch.resolve("jobs"))
    private val outside: Path = Files.createDirectories(scratch.resolve("outside"))
    private val http: HttpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()

    @AfterTest fun cleanup() { http.close(); scratch.toFile().deleteRecursively() }

    private val canary = "{\"fixture\":\"OUTSIDE_CONTAINMENT_CANARY\"}".toByteArray()

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    @Test
    fun `report and artifact reads refuse indirection and oversize without disclosing outside bytes or paths`() {
        val job = JobStore(root).createFromUpload("inert.elf", elfFixture())
        val run = WorkflowAttemptStore.open(root).use { owner ->
            val current = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            owner.create(job.id, current.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
        }
        val runs = Files.createDirectories(root.resolve(job.id).resolve("reports/runs"))
        val reports = Files.createDirectories(runs.resolve(run.runId))
        val target = reports.resolve("exploration.json")
        val outsideFile = outside.resolve("exploration.json").also { Files.write(it, canary) }
        val lines = CopyOnWriteArrayList<String>()
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("analysis must remain inert") },
            JobReconstructor { _, _ -> error("reconstruction must remain inert") }, uiMode = WebUiMode.SPA, basePath = "/w/",
            sensitiveValues = emptyList(), requestDiagnosticOutput = { lines += it })
        server.start()
        try {
            val origin = "http://127.0.0.1:${server.serverPort}"
            fun call(path: String, headers: Map<String, String> = emptyMap(), body: String? = null): HttpResponse<ByteArray> {
                val builder = HttpRequest.newBuilder(URI(origin + path)).timeout(Duration.ofSeconds(30))
                    .method(if (body == null) "GET" else "POST", body?.let(HttpRequest.BodyPublishers::ofString) ?: HttpRequest.BodyPublishers.noBody())
                if ("Accept" !in headers) builder.header("Accept", "application/json")
                headers.forEach { (name, value) -> builder.header(name, value) }
                return http.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray()).also(::assertNoWebCors)
            }
            val token = server.issueBrowserBootstrap().token
            val signIn = call("/w/api/v1/session", mapOf("Origin" to origin, "Content-Type" to "application/json"), "{\"token\":\"$token\"}")
            assertEquals(200, signIn.statusCode())
            val cookie = mapOf("Cookie" to signIn.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';'))
            val reportPath = "/w/api/v1/jobs/${job.id}/runs/${run.runId}/reports/exploration"
            val binding = sha256("${job.id}\u0000${run.runId}".toByteArray()).take(32)
            val content = "/w/api/v1/jobs/${job.id}/artifacts/exploration_${binding}_${sha256(canary)}/content"
            val failures = mutableListOf<String>()
            fun requireContained(response: HttpResponse<ByteArray>, label: String) {
                val text = response.body().decodeToString()
                assertFalse(text.contains("OUTSIDE_CONTAINMENT_CANARY"), "$label disclosed outside bytes: $text")
                assertFalse(text.contains(scratch.toAbsolutePath().toString()) || text.contains("/outside"), "$label disclosed a path: $text")
                assertFalse(text.contains("Exception"), "$label disclosed a raw failure: $text")
                if (response.statusCode() >= 400) failures += response.headers().firstValue("X-Request-ID").orElseThrow()
            }
            fun reset() {
                if (Files.isSymbolicLink(reports) || !Files.isDirectory(reports)) Files.delete(reports)
                Files.createDirectories(reports)
                Files.deleteIfExists(target)
            }

            // Positive control: an ordinary report file is projected and downloadable, so the canary would be seen.
            Files.write(target, canary)
            val control = call(reportPath, cookie)
            assertEquals(200, control.statusCode())
            val controlArtifact = Json.parseToJsonElement(control.body().decodeToString()).jsonObject.getValue("data").jsonObject.getValue("sourceArtifact")
            assertEquals(content, controlArtifact.jsonObject.getValue("contentHref").jsonPrimitive.content)
            val download = call(content, cookie + mapOf("Accept" to "application/octet-stream"))
            assertEquals(200, download.statusCode())
            assertTrue(download.body().contentEquals(canary), "the control download must expose the fixture bytes")

            val fixtures = linkedMapOf<String, () -> Unit>(
                "missing" to { },
                "final symlink" to { Files.createSymbolicLink(target, outsideFile) },
                "hard link" to { Files.createLink(target, outsideFile) },
                "linked parent directory" to {
                    Files.delete(reports)
                    Files.createSymbolicLink(reports, outside)
                },
                "FIFO" to {
                    val created = ProcessBuilder("mkfifo", target.toString()).redirectErrorStream(true).start()
                    assertTrue(created.waitFor(30, TimeUnit.SECONDS) && created.exitValue() == 0, "mkfifo fixture")
                },
                "sparse oversize" to {
                    RandomAccessFile(target.toFile(), "rw").use { file -> file.write(canary); file.setLength(1_048_577) }
                },
            )
            for ((label, install) in fixtures) {
                reset()
                install()
                val report = call(reportPath, cookie)
                assertEquals(200, report.statusCode(), label)
                val data = Json.parseToJsonElement(report.body().decodeToString()).jsonObject.getValue("data").jsonObject
                assertEquals("unknown", data.getValue("state").jsonPrimitive.content, "$label report state")
                assertEquals(JsonNull, data.getValue("sourceArtifact"), "$label must not describe an artifact")
                requireContained(report, "$label report")
                val refused = call(content, cookie + mapOf("Accept" to "application/octet-stream"))
                assertEquals(404, refused.statusCode(), "$label download: ${refused.body().decodeToString()}")
                requireContained(refused, "$label download")
            }
            reset()
            assertTrue(Files.readAllBytes(outsideFile).contentEquals(canary), "the outside fixture is never modified")

            // Query, cookie and path canaries never reach the fixed request-failure diagnostics.
            for (path in listOf("/w/api/v1/jobs/${job.id}?OUTSIDE_CONTAINMENT_CANARY=${scratch}", "/w/api/v1/OUTSIDE_CONTAINMENT_CANARY")) {
                requireContained(call(path, cookie), path)
            }
            requireContained(call("/w/api/v1/jobs", mapOf("Cookie" to "decomp_web_session=OUTSIDE_CONTAINMENT_CANARY")), "foreign cookie")
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (lines.size < failures.size && System.nanoTime() < deadline) Thread.sleep(10)
            val pattern = Regex("web-http-failure request_id=([0-9a-f-]{36}) status=[45][0-9]{2} code=[A-Z_]+")
            assertTrue(lines.all { pattern.matches(it) }, "diagnostics carry only fixed fields: $lines")
            assertEquals(failures.toSet(), lines.map { pattern.matchEntire(it)!!.groupValues[1] }.toSet(),
                "each refusal logs exactly its own response ID")
        } finally { server.stop() }
    }
}
