package decompengine.web

import decompengine.agent.AgentWorkflowPhase
import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAcceptanceReference
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowCandidate
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowRunState
import decompengine.jobs.WorkflowStoreException
import decompengine.jobs.WorkflowTerminalReason
import decompengine.jobs.WorkflowTransition
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.time.Duration
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Rehearses the documented backup/restore procedure (docs/web-backup-restore.md) on a populated data
 * directory: an uploaded job with a completed attempt, its accepted revision, retained reports and a
 * source archive, plus an upload-only job. Backup and restore are plain byte copies of a stopped store.
 * The restored store must have the same bytes and serve the same v1 projections; restoring to another
 * absolute path or under an unsupported schema must fail visibly without rewriting stored bytes.
 */
class WebBackupRestoreRehearsalTest {
    private val parent: Path = Files.createTempDirectory(Path.of("build"), "backup-rehearsal").toAbsolutePath()
    private val http: HttpClient = HttpClient.newHttpClient()

    @AfterTest fun cleanup() { http.close(); parent.toFile().deleteRecursively() }

    @Test
    fun `byte copy of a stopped store restores jobs, accepted revisions and artifacts at the same path`() {
        val live = parent.resolve("data/jobs")
        val fixture = populate(live)
        val populated = manifest(live)
        val (beforeReads, beforeManifest) = serve(live) { call -> read(fixture, call) }
        // Opening the store and reading every projection never changes an existing file. The first start
        // may only add the durable workflow record for a job that predates it.
        populated.forEach { (path, digest) -> assertEquals(digest, beforeManifest[path], "startup or reads changed $path") }
        assertTrue((beforeManifest.keys - populated.keys).all { it.endsWith("/workflow-state.json") }, "${beforeManifest.keys - populated.keys}")

        val backup = parent.resolve("backup/jobs")
        copyTree(live, backup)
        assertEquals(manifest(live), manifest(backup), "backup copy changed bytes")

        live.toFile().deleteRecursively()
        copyTree(backup, live)
        assertEquals(beforeManifest, manifest(live), "restore changed bytes")
        val (afterReads, afterManifest) = serve(live) { call -> read(fixture, call) }
        assertEquals(beforeReads, afterReads, "restored projections differ from the original")
        assertEquals(beforeManifest, afterManifest, "the restored server rewrote stored bytes")
        assertEquals(fixture.revisionId, afterReads.getValue("job").jsonObject.getValue("acceptedRevisionId").jsonPrimitive.content)
    }

    @Test
    fun `restore to another absolute path or an unsupported schema fails visibly without rewriting bytes`() {
        val live = parent.resolve("data/jobs")
        val fixture = populate(live)
        val moved = parent.resolve("elsewhere/jobs")
        copyTree(live, moved)
        val movedManifest = manifest(moved)
        serve(moved) { call ->
            // job.json binds binary_path to the original absolute store location.
            assertNotEquals(200, call("/api/v1/jobs/${fixture.jobId}").statusCode())
            // The library refuses a partial listing rather than hiding the mismatched records.
            val listing = call("/api/v1/jobs")
            assertEquals(503, listing.statusCode(), listing.body())
        }
        assertEquals(movedManifest, manifest(moved), "a path-mismatched restore was rewritten")

        val state = live.resolve(fixture.jobId).resolve("workflow-state.json")
        val future = String(state.readBytes()).replaceFirst(Regex("\"schemaVersion\":\\s*1"), "\"schemaVersion\": 2").toByteArray()
        assertNotEquals(String(state.readBytes()), String(future))
        state.writeBytes(future)
        val futureManifest = manifest(live)
        // A newer workflow schema is refused before the server binds; nothing is downgraded or rewritten.
        val refusal = assertFailsWith<WorkflowStoreException> { serve(live) { error("an unsupported schema was served") } }
        assertEquals("UNSUPPORTED_WORKFLOW_SCHEMA", refusal.code)
        assertTrue(!refusal.message.orEmpty().contains(live.toString()), "a host path leaked into the refusal")
        assertEquals(futureManifest, manifest(live), "an unsupported schema was silently rewritten")
        assertTrue(state.readBytes().contentEquals(future))
    }

    private data class Fixture(val jobId: String, val runId: String, val revisionId: String, val uploadOnlyJobId: String)

    private fun populate(root: Path): Fixture {
        Files.createDirectories(root)
        val store = JobStore(root)
        val job = store.createFromUpload("backup-fixture.elf", elfFixture())
        val uploadOnly = store.createFromUpload("upload-only.elf", elfFixture())
        val request = NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))
        val archive = "PK\u0005\u0006".toByteArray() + ByteArray(18)
        val archiveSha = sha256(archive)
        val (runId, revisionId) = WorkflowAttemptStore.open(root).use { owner ->
            val initial = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            val queued = owner.create(job.id, initial.version, request)
            val running = owner.transition(job.id, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start)
            val done = owner.transition(job.id, running.attempt.runId, running.attempt.version,
                WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED,
                    WorkflowCandidate("revision_backup", archiveSha)))
            owner.recordAcceptedRevision(job.id, done.attempt.runId, done.snapshot.version, done.attempt.version,
                WorkflowAcceptanceReference(job.id, done.attempt.runId, "revision_backup", archiveSha,
                    "graph_backup", "artifact_backup", archiveSha))
            done.attempt.runId to "revision_backup"
        }
        val reports = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/$runId"))
        AgentProgressJournal(reports, "reconstruct").use { it.phase(AgentWorkflowPhase.PLANNING) }
        Files.writeString(reports.resolve("exploration.json"), "{\"fixture\":\"backup rehearsal\"}")
        reports.resolve("source-tree.zip").writeBytes(archive)
        return Fixture(job.id, runId, revisionId, uploadOnly.id)
    }

    /** Reads every projection a restored operator would check, dropping only per-request/per-listener identities. */
    private fun read(fixture: Fixture, call: (String) -> HttpResponse<String>): Map<String, JsonElement> {
        val paths = mapOf(
            "job" to "/api/v1/jobs/${fixture.jobId}",
            "uploadOnly" to "/api/v1/jobs/${fixture.uploadOnlyJobId}",
            "runs" to "/api/v1/jobs/${fixture.jobId}/runs",
            "exploration" to "/api/v1/jobs/${fixture.jobId}/runs/${fixture.runId}/reports/exploration",
        )
        return paths.mapValues { (name, path) ->
            val response = call(path)
            assertEquals(200, response.statusCode(), "$name: ${response.body()}")
            Json.parseToJsonElement(response.body()).jsonObject.getValue("data")
        }
    }

    /** Starts the SPA server on [root], signs in once and stops it again; the manifest is taken after stop. */
    private fun <T> serve(root: Path, body: (call: (String) -> HttpResponse<String>) -> T): Pair<T, Map<String, String>> =
        runServer(root, body) to manifest(root)

    private fun <T> runServer(root: Path, body: (call: (String) -> HttpResponse<String>) -> T): T {
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("restore must not analyze") },
            JobReconstructor { _, _ -> error("restore must not reconstruct") }, uiMode = WebUiMode.SPA)
        server.start()
        try {
            val origin = "http://127.0.0.1:${server.serverPort}"
            val signIn = http.send(HttpRequest.newBuilder(URI("$origin/api/v1/session")).timeout(Duration.ofSeconds(5))
                .header("Accept", "application/json").header("Origin", origin).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"${server.issueBrowserBootstrap().token}\"}")).build(),
                HttpResponse.BodyHandlers.ofString())
            assertEquals(200, signIn.statusCode())
            val cookie = signIn.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            val result = body { path ->
                http.send(HttpRequest.newBuilder(URI(origin + path)).timeout(Duration.ofSeconds(5))
                    .header("Accept", "application/json").header("Cookie", cookie).GET().build(), HttpResponse.BodyHandlers.ofString())
            }
            return result
        } finally {
            server.stop()
        }
    }

    private fun copyTree(source: Path, target: Path) {
        Files.walk(source).use { paths ->
            paths.forEach { path ->
                val destination = target.resolve(source.relativize(path).toString())
                if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) Files.createDirectories(destination)
                else Files.copy(path, destination, StandardCopyOption.COPY_ATTRIBUTES, LinkOption.NOFOLLOW_LINKS)
            }
        }
    }

    /** SHA-256 of every regular file except advisory lock files, which carry no content. */
    private fun manifest(root: Path): Map<String, String> = Files.walk(root).use { paths ->
        paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) && !it.fileName.toString().endsWith(".lock") }
            .toList().associate { root.relativize(it).toString() to sha256(it.readBytes()) }
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
