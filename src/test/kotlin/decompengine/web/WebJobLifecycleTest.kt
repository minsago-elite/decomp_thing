package decompengine.web

import com.sun.net.httpserver.HttpServer
import decompengine.jobs.*
import kotlinx.serialization.json.*
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.*
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.test.*

/** Organization metadata, retention protections, deletion/purge and storage accounting over real HTTP. */
class WebJobLifecycleTest {
    private class Fixture(
        val root: Path = Files.createTempDirectory("web-job-lifecycle-"),
        holds: List<JobRetentionHold> = emptyList(),
        configure: (WebJobService) -> Unit = {},
    ) : AutoCloseable {
        val store = JobStore(root)
        lateinit var owner: WorkflowAttemptStore
        val service = WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected analysis") }, JobReconstructor { _, _ -> error("Unexpected reconstruction") },
            attemptStoreFactory = { WorkflowAttemptStore.open(it).also { opened -> owner = opened } }, retentionHolds = holds).also(configure)
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin))
        val resources = WebStreamResources()
        val workers = Executors.newFixedThreadPool(2)
        val client = HttpClient.newHttpClient()
        lateinit var cookie: String
        lateinit var csrf: String
        fun start(): Fixture {
            service.initializeExistingStorage()
            val api = WebApiController(access, EmbeddedWebAssets.load(basePath = "/workbench/"), service,
                WebJobMutationBoundary(access, service), resources)
            server.executor = workers; server.createContext("/") { check(api.route(it)) }; server.start()
            val token = access.issueBootstrap().token
            val session = send("POST", "/session", "{\"token\":\"$token\"}", mapOf("Origin" to origin, "Content-Type" to "application/json"))
            check(session.statusCode() == 200)
            cookie = session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            csrf = Json.parseToJsonElement(session.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
            return this
        }
        fun send(method: String, target: String, body: String? = null, headers: Map<String, String> = emptyMap()): HttpResponse<String> {
            val b = HttpRequest.newBuilder(URI("$origin/workbench/api/v1$target")).timeout(Duration.ofSeconds(10)).method(method,
                body?.let { HttpRequest.BodyPublishers.ofString(it) } ?: HttpRequest.BodyPublishers.noBody())
            b.header("Accept", "application/json"); headers.forEach { (k, v) -> b.header(k, v) }
            return client.send(b.build(), HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
        }
        fun read(target: String) = send("GET", target, headers = mapOf("Cookie" to cookie))
        fun mutation(version: String, key: String) = mapOf("Cookie" to cookie, "Origin" to origin,
            "Content-Type" to "application/json", "X-CSRF-Token" to csrf, "If-Match" to "\"$version\"", "Idempotency-Key" to key)
        fun job(id: String) = data(read("/jobs/$id"), "job")
        fun version(id: String) = job(id).getValue("version").jsonPrimitive.content
        fun delete(id: String, key: String, version: String = version(id), confirm: String = id) =
            send("DELETE", "/jobs/$id", "{\"confirmJobId\":\"$confirm\"}", mutation(version, key))
        fun attempt(jobId: String): WorkflowAttempt {
            val view = (owner.inspect(jobId) as WorkflowJobInspection.Available).snapshot
            return owner.create(jobId, view.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
        }
        fun finish(jobId: String, attempt: WorkflowAttempt): WorkflowAttempt {
            val running = owner.transition(jobId, attempt.runId, attempt.version, WorkflowTransition.Start).attempt
            return owner.transition(jobId, running.runId, running.version,
                WorkflowTransition.Finish(WorkflowRunState.FAILED, WorkflowTerminalReason.FAILED)).attempt
        }
        override fun close() {
            server.stop(0); resources.close(); workers.shutdownNow()
            check(workers.awaitTermination(5, TimeUnit.SECONDS)); client.close(); access.close()
            try { service.close() } catch (_: Exception) { }
            if (Files.exists(root)) Files.walk(root).use { paths -> paths.forEach { runCatching { Files.setPosixFilePermissions(it, PosixFilePermissions.fromString(if (Files.isDirectory(it)) "rwx------" else "rw-------")) } } }
            root.toFile().deleteRecursively()
        }
    }

    companion object {
        fun data(response: HttpResponse<String>, kind: String, status: Int = 200): JsonObject {
            assertEquals(status, response.statusCode(), response.body())
            assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow())
            val document = Json.parseToJsonElement(response.body()).jsonObject
            assertEquals(kind, document.getValue("kind").jsonPrimitive.content)
            return document.getValue("data").jsonObject
        }
        fun error(response: HttpResponse<String>, status: Int, code: String? = null): JsonObject {
            assertEquals(status, response.statusCode(), response.body())
            val error = Json.parseToJsonElement(response.body()).jsonObject.getValue("error").jsonObject
            if (code != null) assertEquals(code, error.getValue("code").jsonPrimitive.content)
            assertFalse(response.body().contains("/tmp") || response.body().contains("web-job-lifecycle-"), "private path leaked")
            return error
        }
        /** Every byte except the separate organization record: identity, run configuration and evidence. */
        fun evidenceDigest(directory: Path): Map<String, String> = Files.walk(directory).use { paths ->
            paths.filter { Files.isRegularFile(it) && it.fileName.toString() != JobOrganization.FILE_NAME }.toList().associate { path ->
                directory.relativize(path).toString() to MessageDigest.getInstance("SHA-256").digest(path.readBytes()).joinToString("") { "%02x".format(it) }
            }
        }
        fun nonRoot() = System.getProperty("user.name") != "root"
    }

    @Test fun `display label and archive change only organization metadata and the public version`() = Fixture().start().use { f ->
        val job = f.store.createFromUpload("inert.elf", elfFixture())
        val run = f.finish(job.id, f.attempt(job.id))
        val before = evidenceDigest(f.root.resolve(job.id))
        val initial = f.job(job.id)
        assertEquals(JsonNull, initial["label"]); assertEquals(JsonPrimitive(false), initial["archived"])
        assertEquals(run.runId, initial.getValue("latestRunId").jsonPrimitive.content)
        val version = initial.getValue("version").jsonPrimitive.content

        val labelled = f.send("PATCH", "/jobs/${job.id}", "{\"label\":\"Firmware 7\",\"archived\":true}", f.mutation(version, "organize_key_0001"))
        val applied = data(labelled, "job")
        assertEquals("Firmware 7", applied.getValue("label").jsonPrimitive.content)
        assertEquals(JsonPrimitive(true), applied["archived"])
        assertNotEquals(version, applied.getValue("version").jsonPrimitive.content)
        assertEquals("\"${applied.getValue("version").jsonPrimitive.content}\"", labelled.headers().firstValue("ETag").orElseThrow())
        assertEquals(initial.getValue("displayFilename"), applied.getValue("displayFilename"))
        assertEquals(initial.getValue("binary"), applied.getValue("binary"))
        assertEquals(before, evidenceDigest(f.root.resolve(job.id)), "input, job.json, workflow state and reports keep their bytes")
        assertEquals(applied, f.job(job.id))

        val replay = f.send("PATCH", "/jobs/${job.id}", "{ \"archived\" : true , \"label\" : \"Firmware 7\" }", f.mutation(version, "organize_key_0001"))
        assertEquals(applied, data(replay, "job")); assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
        error(f.send("PATCH", "/jobs/${job.id}", "{\"label\":\"Other\"}", f.mutation(version, "organize_key_0001")), 409, "IDEMPOTENCY_CONFLICT")
        error(f.send("PATCH", "/jobs/${job.id}", "{\"label\":\"Other\"}", f.mutation(version, "organize_key_0002")), 412, "VERSION_CONFLICT")

        // Archived jobs leave the default library view but remain addressable and listable on request.
        fun listed(query: String) = data(f.read("/jobs$query"), "jobs").getValue("items").jsonArray.map { it.jsonObject.getValue("jobId").jsonPrimitive.content }
        assertEquals(emptyList(), listed(""))
        assertEquals(listOf(job.id), listed("?archived=only"))
        assertEquals(listOf(job.id), listed("?archived=all&search=firmware"))
        error(f.read("/jobs?archived=everything"), 422)

        val cleared = data(f.send("PATCH", "/jobs/${job.id}", "{\"label\":null,\"archived\":false}",
            f.mutation(applied.getValue("version").jsonPrimitive.content, "organize_key_0003")), "job")
        assertEquals(JsonNull, cleared["label"]); assertEquals(version, cleared.getValue("version").jsonPrimitive.content)
        assertEquals(before, evidenceDigest(f.root.resolve(job.id)))
    }

    @Test fun `organization requests are authorized strict and bounded before any write`() = Fixture().start().use { f ->
        val job = f.store.createFromUpload("inert.elf", elfFixture())
        val version = f.version(job.id)
        val headers = f.mutation(version, "organize_key_0001")
        error(f.send("PATCH", "/jobs/${job.id}", "{\"label\":\"x\"}", headers - "Cookie"), 401)
        error(f.send("PATCH", "/jobs/${job.id}", "{\"label\":\"x\"}", headers - "X-CSRF-Token"), 403)
        error(f.send("PATCH", "/jobs/${job.id}", "{\"label\":\"x\"}", headers + ("Origin" to "http://foreign.invalid")), 403)
        error(f.send("PATCH", "/jobs/${job.id}", "{\"label\":\"x\"}", headers - "If-Match"), 428, "PRECONDITION_REQUIRED")
        error(f.send("PATCH", "/jobs/${job.id}", "{\"label\":\"x\"}", headers - "Idempotency-Key"), 400, "INVALID_IDEMPOTENCY_KEY")
        listOf("{}", "{\"filename\":\"x\"}", "{\"label\":\"x\",\"label\":\"y\"}", "[]", "{\"label\":\"x\",\"status\":\"completed\"}").forEach {
            error(f.send("PATCH", "/jobs/${job.id}", it, headers), 400)
        }
        listOf("{\"label\":\"${"x".repeat(121)}\"}", "{\"label\":\" padded\"}", "{\"label\":\"\"}", "{\"label\":\"a\\u0007b\"}",
            "{\"archived\":\"true\"}", "{\"label\":7}").forEach { error(f.send("PATCH", "/jobs/${job.id}", it, headers), 422, "VALIDATION_FAILED") }
        error(f.send("PATCH", "/jobs/${job.id}", " ".repeat(4097), headers), 413)
        error(f.send("PUT", "/jobs/${job.id}", "{\"label\":\"x\"}", headers), 405)
        assertFalse(Files.exists(f.root.resolve("${job.id}/${JobOrganization.FILE_NAME}")))
    }

    @Test fun `read-only job storage preserves the previous organization and reports actionable status`() {
        if (!nonRoot()) return
        Fixture().start().use { f ->
            val job = f.store.createFromUpload("inert.elf", elfFixture())
            val labelled = data(f.send("PATCH", "/jobs/${job.id}", "{\"label\":\"Kept\"}", f.mutation(f.version(job.id), "organize_key_0001")), "job")
            val record = f.root.resolve("${job.id}/${JobOrganization.FILE_NAME}").readBytes()
            Files.setPosixFilePermissions(f.root.resolve(job.id), PosixFilePermissions.fromString("r-x------"))
            try {
                val failure = error(f.send("PATCH", "/jobs/${job.id}", "{\"label\":\"Lost\"}",
                    f.mutation(labelled.getValue("version").jsonPrimitive.content, "organize_key_0002")), 503, "STORAGE_UNAVAILABLE")
                assertTrue(failure.getValue("message").jsonPrimitive.content.contains("previous metadata is preserved"))
            } finally { Files.setPosixFilePermissions(f.root.resolve(job.id), PosixFilePermissions.fromString("rwx------")) }
            assertContentEquals(record, f.root.resolve("${job.id}/${JobOrganization.FILE_NAME}").readBytes())
            assertEquals("Kept", f.job(job.id).getValue("label").jsonPrimitive.content)
        }
    }

    @Test fun `retention policy protects active attempts pinned evidence downloads and registered holds`() {
        val held = mutableSetOf<String>()
        var failingHold = false
        Fixture(holds = listOf(JobRetentionHold { id ->
            if (failingHold) error("hold backend unavailable")
            if (id in held) listOf(JobRetentionHoldReason("git-worktree", "UNPUSHED_COMMITS", "The job's worktree has 2 unpushed commits.")) else emptyList()
        })).start().use { f ->
            val active = f.store.createFromUpload("active.elf", elfFixture())
            f.attempt(active.id) // Queued, never scheduled: still a nonterminal durable attempt.
            val pinned = f.store.createFromUpload("pinned.elf", elfFixture())
            val done = f.finish(pinned.id, f.attempt(pinned.id))
            f.owner.setProgressRetentionPinned(pinned.id, done.runId, done.version, true)
            val git = f.store.createFromUpload("git.elf", elfFixture()).also { held += it.id }
            val download = f.store.createFromUpload("download.elf", elfFixture())
            fun protections(id: String) = data(f.read("/jobs/$id/deletion-preview"), "jobDeletionPreview").let { preview ->
                assertEquals(JsonPrimitive("permanent"), preview["finality"]); assertEquals(JsonPrimitive(false), preview["undoAvailable"])
                preview.getValue("protections").jsonArray.map { it.jsonObject.getValue("code").jsonPrimitive.content }
            }
            assertEquals(listOf("ACTIVE_ATTEMPT"), protections(active.id))
            assertEquals(listOf("PINNED_EVIDENCE"), protections(pinned.id))
            assertEquals(listOf("UNPUSHED_COMMITS"), protections(git.id))
            val lease = f.service.downloadLease(download.id)
            assertEquals(listOf("DOWNLOAD_IN_PROGRESS"), protections(download.id))
            for ((id, code) in listOf(active.id to "ACTIVE_ATTEMPT", pinned.id to "PINNED_EVIDENCE", git.id to "UNPUSHED_COMMITS", download.id to "DOWNLOAD_IN_PROGRESS")) {
                val refusal = error(f.delete(id, "delete_key_$code".take(64).padEnd(16, '0')), 409, "RETENTION_PROTECTED")
                assertEquals(code, refusal.getValue("details").jsonArray.single().jsonObject.getValue("code").jsonPrimitive.content)
                assertTrue(Files.isDirectory(f.root.resolve(id)), "protected job $id must remain")
            }
            lease.close()
            failingHold = true
            assertEquals(listOf("RETENTION_HOLD_UNAVAILABLE"), protections(download.id), "a failing hold fails closed")
            failingHold = false; held.clear()
            // The dry-run maintenance preview reports the same protections and writes nothing.
            val stateBytes = f.root.resolve("${pinned.id}/workflow-state.json").readBytes()
            val preview = data(f.read("/storage/maintenance-preview"), "maintenancePreview")
            assertEquals(JsonPrimitive(true), preview["dryRun"]); assertEquals(JsonPrimitive(false), preview.getValue("policy").jsonObject["automaticJobDeletion"])
            val protectedIds = preview.getValue("protectedJobs").jsonArray.map { it.jsonObject.getValue("jobId").jsonPrimitive.content }.toSet()
            assertEquals(setOf(active.id, pinned.id), protectedIds)
            assertContentEquals(stateBytes, f.root.resolve("${pinned.id}/workflow-state.json").readBytes())
            data(f.delete(git.id, "delete_key_released_hold"), "operation", 202)
        }
    }

    @Test fun `authorized deletion purges without following links and leaves an auditable tombstone`() = Fixture().start().use { f ->
        val job = f.store.createFromUpload("inert.elf", elfFixture())
        val kept = f.store.createFromUpload("kept.elf", elfFixture())
        val outside = Files.createTempDirectory("web-job-lifecycle-outside-")
        try {
            val outsideFile = outside.resolve("precious.bin").also { it.writeBytes(byteArrayOf(1, 2, 3)) }
            val reports = Files.createDirectories(f.root.resolve("${job.id}/reports/runs/run_a/source-tree/src"))
            reports.resolve("main.c").writeBytes("int main(void){return 0;}\n".toByteArray())
            Files.createSymbolicLink(reports.resolve("escape-file"), outsideFile)
            Files.createSymbolicLink(reports.resolve("escape-dir"), outside)
            Files.createLink(f.root.resolve("${job.id}/reports/hardlink.bin"), outsideFile)
            val keptBytes = evidenceDigest(f.root.resolve(kept.id))
            val preview = data(f.read("/jobs/${job.id}/deletion-preview"), "jobDeletionPreview")
            assertEquals(JsonPrimitive(true), preview["deletable"])
            val storage = preview.getValue("storage").jsonObject
            assertEquals(elfFixture().size.toString(), storage.getValue("originalInputs").jsonObject.getValue("bytes").jsonPrimitive.content)
            assertTrue(storage.getValue("sourceSnapshots").jsonObject.getValue("bytes").jsonPrimitive.content.toLong() > 0)
            val version = preview.getValue("version").jsonPrimitive.content

            error(f.send("DELETE", "/jobs/${job.id}", "{\"confirmJobId\":\"${kept.id}\"}", f.mutation(version, "delete_key_mismatch")), 422, "VALIDATION_FAILED")
            error(f.send("DELETE", "/jobs/${job.id}", "{\"confirmJobId\":\"${job.id}\"}", f.mutation(version, "delete_key_00001") - "X-CSRF-Token"), 403)
            error(f.send("DELETE", "/jobs/${job.id}", "{\"confirmJobId\":\"${job.id}\"}", f.mutation(version, "delete_key_00001") - "If-Match"), 428)
            error(f.send("DELETE", "/jobs/${job.id}", "{}", f.mutation(version, "delete_key_00001")), 400)
            error(f.delete(job.id, "delete_key_stale", version = "stale_version"), 412, "VERSION_CONFLICT")

            val accepted = f.delete(job.id, "delete_key_00001", version)
            val operation = data(accepted, "operation", 202)
            assertEquals("job.delete", operation.getValue("action").jsonPrimitive.content)
            assertEquals("completed", operation.getValue("state").jsonPrimitive.content)
            assertTrue(operation.getValue("message").jsonPrimitive.content.contains("cannot be undone"))
            val operationId = operation.getValue("operationId").jsonPrimitive.content
            assertEquals("/workbench/api/v1/jobs/${job.id}/operations/$operationId", accepted.headers().firstValue("Location").orElseThrow())
            assertFalse(Files.exists(f.root.resolve(job.id)))
            assertContentEquals(byteArrayOf(1, 2, 3), outsideFile.readBytes(), "link targets outside the job root survive")
            assertTrue(Files.isDirectory(outside))
            assertEquals(keptBytes, evidenceDigest(f.root.resolve(kept.id)))

            error(f.read("/jobs/${job.id}"), 410, "RESOURCE_GONE")
            error(f.read("/jobs/${job.id}/runs"), 410, "RESOURCE_GONE")
            error(f.read("/jobs/${job.id}/deletion-preview"), 410, "RESOURCE_GONE")
            assertEquals(listOf(kept.id), data(f.read("/jobs?archived=all"), "jobs").getValue("items").jsonArray.map { it.jsonObject.getValue("jobId").jsonPrimitive.content })
            assertEquals(operation, data(f.read("/jobs/${job.id}/operations/$operationId"), "operation"))
            val replay = f.delete(job.id, "delete_key_00001", version)
            assertEquals(operation, data(replay, "operation", 202)); assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
            error(f.delete(job.id, "delete_key_00001", "other_version"), 409, "IDEMPOTENCY_CONFLICT")
            error(f.delete(job.id, "delete_key_00002", version), 410, "RESOURCE_GONE")
            // The audit record keeps identity, actor digest and counts, never the filename or session secrets.
            val record = Files.readString(f.root.resolve("${JobDeletionStore.DIRECTORY}/$operationId.json"))
            assertFalse(record.contains("inert.elf") || record.contains(f.csrf) || record.contains(f.cookie.substringAfter('=')))
            assertTrue(record.contains(job.id))
        } finally { outside.toFile().deleteRecursively() }
    }

    @Test fun `interrupted purge resumes after restart and a crash before removal retains the job`() {
        val root = Files.createTempDirectory("web-job-lifecycle-restart-")
        var hits = 0
        val (deleted, retained) = Fixture(root, configure = { service ->
            service.deletionFaults = JobDeletionFaults { point ->
                if (point == JobDeletionFaultPoint.PURGE_ENTRY && ++hits == 2) throw java.io.IOException("PRIVATE_CRASH_CANARY")
            }
        }).start().let { f ->
            try {
                val job = f.store.createFromUpload("inert.elf", elfFixture())
                Files.createDirectories(f.root.resolve("${job.id}/reports")).resolve("a.json").writeBytes(ByteArray(64))
                val operation = data(f.delete(job.id, "delete_key_interrupt"), "operation", 202)
                assertEquals("running", operation.getValue("state").jsonPrimitive.content)
                error(f.read("/jobs/${job.id}"), 410, "RESOURCE_GONE")
                assertTrue(Files.isDirectory(f.root.resolve("${JobDeletionStore.DIRECTORY}/${operation.getValue("operationId").jsonPrimitive.content}.removing")))
                val other = f.store.createFromUpload("other.elf", elfFixture())
                // A process crash between the durable intent and the rename leaves only an accepted record.
                f.service.deletionFaults = JobDeletionFaults { point -> if (point == JobDeletionFaultPoint.BEFORE_DETACH) throw IllegalStateException("simulated crash") }
                assertEquals(500, f.delete(other.id, "delete_key_crash").statusCode())
                assertTrue(Files.isDirectory(f.root.resolve(other.id)))
                (job.id to operation.getValue("operationId").jsonPrimitive.content) to other.id
            } finally {
                f.server.stop(0); f.resources.close(); f.workers.shutdownNow(); f.client.close(); f.access.close()
                runCatching { f.service.close() }
            }
        }
        Fixture(root).start().use { f ->
            val resumed = data(f.read("/jobs/${deleted.first}/operations/${deleted.second}"), "operation")
            assertEquals("completed", resumed.getValue("state").jsonPrimitive.content)
            assertFalse(Files.exists(f.root.resolve("${JobDeletionStore.DIRECTORY}/${deleted.second}.removing")))
            assertFalse(Files.exists(f.root.resolve(deleted.first)))
            assertEquals("other.elf", f.job(retained).getValue("displayFilename").jsonPrimitive.content)
            val failed = f.service.deletedJob(retained)
            assertNull(failed, "an interrupted-before-removal record is not a tombstone")
            data(f.delete(retained, "delete_key_after_restart"), "operation", 202)
        }
    }

    @Test fun `disk-full and read-only deletion journals leave the job and its metadata intact`() {
        Fixture(configure = { service ->
            service.deletionFaults = JobDeletionFaults { point ->
                if (point == JobDeletionFaultPoint.BEFORE_INTENT) throw java.io.IOException("No space left on device PRIVATE")
            }
        }).start().use { f ->
            val job = f.store.createFromUpload("inert.elf", elfFixture())
            val before = evidenceDigest(f.root.resolve(job.id))
            val failure = error(f.delete(job.id, "delete_key_disk_full"), 503, "STORAGE_UNAVAILABLE")
            assertTrue(failure.getValue("message").jsonPrimitive.content.contains("job is unchanged"))
            assertFalse(failure.toString().contains("PRIVATE"))
            assertEquals(before, evidenceDigest(f.root.resolve(job.id)))
            assertEquals("inert.elf", f.job(job.id).getValue("displayFilename").jsonPrimitive.content)
        }
        if (!nonRoot()) return
        Fixture().start().use { f ->
            val first = f.store.createFromUpload("first.elf", elfFixture())
            data(f.delete(first.id, "delete_key_first"), "operation", 202)
            val job = f.store.createFromUpload("inert.elf", elfFixture())
            val journal = f.root.resolve(JobDeletionStore.DIRECTORY)
            Files.setPosixFilePermissions(journal, PosixFilePermissions.fromString("r-x------"))
            try { error(f.delete(job.id, "delete_key_read_only"), 503, "STORAGE_UNAVAILABLE") }
            finally { Files.setPosixFilePermissions(journal, PosixFilePermissions.fromString("rwx------")) }
            assertEquals("inert.elf", f.job(job.id).getValue("displayFilename").jsonPrimitive.content)
        }
    }

    @Test fun `storage summary distinguishes categories and maintenance preview is a dry run`() = Fixture().start().use { f ->
        val job = f.store.createFromUpload("inert.elf", elfFixture())
        val clock = Clock.fixed(Instant.now().minusSeconds(90_000), ZoneOffset.UTC)
        f.service.close()
        val run = WorkflowAttemptStore.open(f.root, clock).use { owner ->
            val view = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            val queued = owner.create(job.id, view.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
            val running = owner.transition(job.id, queued.runId, queued.version, WorkflowTransition.Start).attempt
            owner.transition(job.id, running.runId, running.version, WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.NO_CHANGES)).attempt
        }
        val reports = f.root.resolve("${job.id}/reports/runs/${run.runId}")
        AgentProgressJournal(reports, "reconstruct").use { }
        Files.createDirectories(reports.resolve("source-tree")).resolve("main.c").writeBytes(ByteArray(100))
        reports.resolve("source-tree.zip").writeBytes(ByteArray(200))
        reports.resolve("exploration.json").writeBytes(ByteArray(300))
        f.root.resolve("${job.id}/.job-metadata-abandoned.tmp").writeBytes(ByteArray(7))
        val journalBytes = reports.resolve(AgentProgressJournal.FILE_NAME).readBytes()
        Fixture(f.root).start().use { g ->
            val summary = data(g.read("/storage"), "storageSummary")
            assertEquals(JsonPrimitive(true), summary["complete"]); assertEquals("1", summary.getValue("jobCount").jsonPrimitive.content)
            val categories = summary.getValue("categories").jsonObject
            fun bytes(name: String) = categories.getValue(name).jsonObject.getValue("bytes").jsonPrimitive.content.toLong()
            assertEquals(elfFixture().size.toLong(), bytes("originalInputs"))
            assertEquals(100, bytes("sourceSnapshots")); assertEquals(200, bytes("archives")); assertEquals(300, bytes("reports"))
            assertEquals(7, bytes("temporary")); assertEquals(journalBytes.size.toLong(), bytes("logs"))
            assertTrue(bytes("metadata") > 0)
            val preview = data(g.read("/storage/maintenance-preview"), "maintenancePreview")
            val action = preview.getValue("actions").jsonArray.single().jsonObject
            assertEquals("progress-journal-expiry", action.getValue("action").jsonPrimitive.content)
            assertEquals(run.runId, action.getValue("runId").jsonPrimitive.content)
            assertEquals("1", preview.getValue("affectedJobs").jsonPrimitive.content)
            assertContentEquals(journalBytes, reports.resolve(AgentProgressJournal.FILE_NAME).readBytes(), "a preview never expires history")
            assertEquals(JsonPrimitive("not-scheduled"), action["schedule"])
        }
    }
}
