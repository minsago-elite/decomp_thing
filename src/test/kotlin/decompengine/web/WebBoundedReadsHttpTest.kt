package decompengine.web

import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowCandidate
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowRunState
import decompengine.jobs.WorkflowTerminalReason
import decompengine.jobs.WorkflowTransition
import decompengine.jobs.elfFixture
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ProjectFileRole
import decompengine.project.SourceTreeManifest
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.put
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Upload cleanup, snapshot-bound pagination and read limits through the real v1 listener. Failed uploads
 * leave no staging entry and no job; continuations stay inside their captured snapshot and selection.
 * Persisted source snapshots are qualified through the listener below; this does not qualify production analysis.
 */
class WebBoundedReadsHttpTest {
    private val root: Path = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp")), "web-bounded-reads-")

    @AfterTest fun cleanup() { root.toFile().deleteRecursively() }

    private fun server() = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("analysis must remain inert") },
        JobReconstructor { _, _ -> error("reconstruction must remain inert") }, uiMode = WebUiMode.SPA, basePath = "/w/",
        sensitiveValues = emptyList()).also { it.start() }

    private fun digest(): Map<String, String> = Files.walk(root).use { paths ->
        paths.filter { Files.isRegularFile(it) && it.fileName.toString() != ".web-owner.lock" }.toList().associate { file ->
            val relative = root.relativize(file).toString()
            // The append-only audit segment is retained as text so restoration can check it is a prefix.
            relative to if (relative == ".web-audit/current.jsonl") Files.readString(file)
                else MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)).joinToString("") { "%02x".format(it) }
        }
    }

    private fun entries(): Set<String> = Files.walk(root).use { paths -> paths.map { root.relativize(it).toString() }.toList().toSet() }

    private fun assertStorageRestored(names: Set<String>, bytes: Map<String, String>) {
        assertEquals(names, entries(), "an upload left a staging, job or nested storage entry")
        val current = digest()
        // Refused uploads are durably audited (#521): the listener's audit segment may only grow by
        // appended entries. Every other stored byte, including the audit loss marker, must be unchanged.
        val segment = ".web-audit/current.jsonl"
        assertEquals(bytes - segment, current - segment, "an upload changed stored bytes")
        if (segment in bytes) {
            val before = bytes.getValue(segment); val after = current.getValue(segment)
            assertTrue(after.startsWith(before), "an upload rewrote existing audit history")
        }
    }

    private fun awaitCondition(label: String, condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
        while (!condition() && System.nanoTime() < deadline) Thread.sleep(10)
        assertTrue(condition(), label)
    }

    private fun awaitHandlers(server: UploadServer) = awaitCondition("HTTP handlers did not finish") {
        server.admissionSnapshot().let { it.workers == 0 && it.queued == 0 && it.responders == 0 }
    }

    @Test
    fun `storage baseline rejects stranded staging nested entries and changed bytes`() {
        val input = Files.write(Files.createDirectories(root.resolve("fixture-job")).resolve("input.elf"), elfFixture())
        val audit = Files.writeString(Files.createDirectories(root.resolve(".web-audit")).resolve("current.jsonl"), "{\"sequence\":1}\n")
        val marker = Files.writeString(audit.resolveSibling("incomplete"), "0")
        val names = entries()
        val bytes = digest()
        val stranded = Files.createDirectories(root.resolve(".upload-stream-v1-123"))
        Files.write(stranded.resolve("input.elf"), elfFixture())
        assertFailsWith<AssertionError> { assertStorageRestored(names, bytes) }
        stranded.toFile().deleteRecursively()
        val nested = Files.createDirectory(input.parent.resolve("stranded"))
        assertFailsWith<AssertionError> { assertStorageRestored(names, bytes) }
        Files.delete(nested)
        Files.write(input, byteArrayOf(1, 2, 3))
        assertFailsWith<AssertionError> { assertStorageRestored(names, bytes) }
        Files.write(input, elfFixture())
        assertStorageRestored(names, bytes)
        // Audit history may only be appended; a rewrite or a changed loss marker is still a change.
        Files.writeString(audit, "{\"sequence\":9}\n")
        assertFailsWith<AssertionError> { assertStorageRestored(names, bytes) }
        Files.writeString(audit, "{\"sequence\":1}\n")
        Files.writeString(marker, "1")
        assertFailsWith<AssertionError> { assertStorageRestored(names, bytes) }
        Files.writeString(marker, "0")
        Files.writeString(audit, "{\"sequence\":1}\n{\"sequence\":2}\n")
        assertStorageRestored(names, bytes)
    }

    @Test
    fun `refused and abandoned uploads leave no staging entry job or changed bytes`() {
        val server = server()
        try {
            WebTestBrowser(server).use { browser ->
                val accepted = browser.upload("first.elf", elfFixture(), "bounded-upload-key-0001")
                assertEquals(201, accepted.statusCode(), accepted.text())
                awaitHandlers(server) // Audit publication can finish after the response.
                val before = digest()
                val names = entries()
                fun refused(response: java.net.http.HttpResponse<ByteArray>, status: Int, code: String, label: String) {
                    assertEquals(status, response.statusCode(), "$label: ${response.text()}")
                    assertEquals(code, response.errorCode(), label)
                    assertFalse(response.headers().firstValue("Location").isPresent, "$label has no success location")
                    awaitHandlers(server)
                    assertStorageRestored(names, before)
                }
                refused(browser.upload("bad.elf", byteArrayOf(1, 2, 3), "bounded-upload-key-0002"), 422, "INVALID_ELF", "non-ELF")
                refused(browser.upload("renamed.elf", elfFixture(), "bounded-upload-key-0001"), 409, "IDEMPOTENCY_CONFLICT", "changed intent")
                refused(browser.upload("large.elf", ByteArray(StreamingMultipartUpload.MAX_REQUEST_BYTES.toInt()), "bounded-upload-key-0003"),
                    413, "UPLOAD_TOO_LARGE", "oversized upload")
                refused(browser.send("POST", "/w/api/v1/jobs", "--b\r\n".toByteArray(), mapOf("Content-Type" to "multipart/form-data; boundary=b",
                    "Idempotency-Key" to "bounded-upload-key-0004")), 400, "MALFORMED_MULTIPART", "truncated multipart")

                // A peer that declares a body and disappears partway through it must not strand its staging directory.
                val port = server.serverPort
                Socket("127.0.0.1", port).use { socket ->
                    val head = "POST /w/api/v1/jobs HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: ${browser.origin}\r\nCookie: ${browser.cookie}\r\n" +
                        "X-CSRF-Token: ${browser.csrf}\r\nAccept: application/json\r\nIdempotency-Key: bounded-upload-key-0005\r\n" +
                        "Content-Type: multipart/form-data; boundary=fixture_boundary\r\nContent-Length: 1000000\r\n\r\n" +
                        "--fixture_boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"partial.elf\"\r\n\r\n"
                    socket.getOutputStream().write(head.toByteArray() + elfFixture() + ByteArray(262_144))
                    socket.getOutputStream().flush()
                    // A client write is not admission evidence. Keep the peer alive until the real
                    // multipart handler has created staging AND persisted part of this request.
                    awaitCondition("the partial upload never reached staging") {
                        Files.list(root).use { paths -> paths.anyMatch { stage ->
                            stage.fileName.toString().startsWith(".upload-stream-v1-") &&
                                Files.isRegularFile(stage.resolve("input.elf")) && Files.size(stage.resolve("input.elf")) > 0
                        } }
                    }
                }
                // First observe completion, not just absence (which could precede admission).
                awaitHandlers(server)
                assertStorageRestored(names, before)
                // The replay of the accepted upload still resolves its original job.
                val replay = browser.upload("first.elf", elfFixture(), "bounded-upload-key-0001")
                assertEquals(201, replay.statusCode())
                assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElse(null))
                assertEquals(accepted.data().getValue("jobId"), replay.data().getValue("jobId"))
                assertEquals(1, JobStore(root).jobIds().size)
                awaitHandlers(server)
                assertStorageRestored(names, before)
            }
        } finally { server.stop() }
    }

    @Test
    fun `job attempt and event continuations stay inside their snapshot session and selection`() {
        val store = JobStore(root)
        val ids = List(3) { store.createFromUpload("fixture-$it.elf", elfFixture()).id }
        val runs = WorkflowAttemptStore.open(root).use { owner ->
            ids.take(2).associateWith { id ->
                val current = (owner.inspect(id) as WorkflowJobInspection.Available).snapshot
                owner.create(id, current.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                    WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt.runId
            }
        }
        runs.forEach { (id, run) ->
            AgentProgressJournal(Files.createDirectories(root.resolve(id).resolve("reports/runs/$run")), "reconstruct")
                .use { it.phase(decompengine.agent.AgentWorkflowPhase.PLANNING) }
        }
        val server = server()
        try {
            WebTestBrowser(server).use { browser ->
                WebTestBrowser(server).use { other ->
                    fun next(page: java.net.http.HttpResponse<ByteArray>): String? =
                        page.data().getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.contentOrNull
                    fun items(page: java.net.http.HttpResponse<ByteArray>): List<String> =
                        page.data().getValue("items").jsonArray.map { it.jsonObject.getValue("jobId").jsonPrimitive.content }

                    val first = browser.get("/w/api/v1/jobs?limit=1")
                    assertEquals(200, first.statusCode(), first.text())
                    val cursor = checkNotNull(next(first))
                    for ((label, path, response) in listOf(
                        Triple("another session", "/w/api/v1/jobs?limit=1&cursor=$cursor", other),
                        Triple("another limit", "/w/api/v1/jobs?limit=2&cursor=$cursor", browser),
                        Triple("another sort", "/w/api/v1/jobs?limit=1&sort=oldest&cursor=$cursor", browser),
                        Triple("another filter", "/w/api/v1/jobs?limit=1&status=uploaded&cursor=$cursor", browser),
                        Triple("another resource", "/w/api/v1/jobs/${ids[0]}/runs?limit=1&cursor=$cursor", browser),
                    )) {
                        val refused = response.get(path)
                        assertEquals(400, refused.statusCode(), "$label: ${refused.text()}")
                        assertEquals("INVALID_CURSOR", refused.errorCode(), label)
                    }
                    // A job published mid-walk never appears inside, or duplicates rows of, the captured snapshot.
                    val inserted = browser.upload("inserted.elf", elfFixture(), "bounded-insert-key-0001")
                    assertEquals(201, inserted.statusCode())
                    val walked = items(first).toMutableList()
                    var continuation: String? = cursor
                    while (continuation != null) {
                        val page = browser.get("/w/api/v1/jobs?limit=1&cursor=$continuation")
                        assertEquals(200, page.statusCode(), page.text())
                        walked += items(page)
                        continuation = next(page)
                    }
                    assertEquals(ids.toSet(), walked.toSet(), "the walk covers exactly the captured jobs")
                    assertEquals(walked.size, walked.toSet().size, "no row is repeated")
                    assertEquals(4, items(browser.get("/w/api/v1/jobs")).size, "a fresh first page sees the new job")

                    // Event cursors are bound to their own job and attempt.
                    val (jobA, runA) = runs.entries.first().toPair()
                    val (jobB, runB) = runs.entries.last().toPair()
                    val snapshot = browser.get("/w/api/v1/jobs/$jobA/runs/$runA/snapshot")
                    assertEquals(200, snapshot.statusCode(), snapshot.text())
                    val eventCursor = checkNotNull(snapshot.data().getValue("oldestCursor").jsonPrimitive.contentOrNull)
                    assertEquals(200, browser.get("/w/api/v1/jobs/$jobA/runs/$runA/events?transport=poll&after=$eventCursor").statusCode())
                    for (path in listOf("/w/api/v1/jobs/$jobB/runs/$runB/events?transport=poll&after=$eventCursor",
                        "/w/api/v1/jobs/$jobA/runs/$runB/events?transport=poll&after=$eventCursor")) {
                        val refused = browser.get(path)
                        assertTrue(refused.statusCode() in setOf(400, 404), "$path: ${refused.text()}")
                        if (refused.statusCode() == 400) assertEquals("INVALID_CURSOR", refused.errorCode(), path)
                    }
                    val foreign = other.get("/w/api/v1/jobs/$jobA/runs/$runA/events?transport=poll&after=$eventCursor")
                    assertEquals(400, foreign.statusCode(), foreign.text())
                    assertEquals("INVALID_CURSOR", foreign.errorCode())
                }
            }
        } finally { server.stop() }
    }

    @Test
    fun `persisted candidate source pages and bounded reads stay bound to exact stored artifacts`() {
        val inputBytes = elfFixture()
        val job = JobStore(root).createFromUpload("source-snapshot.elf", inputBytes)
        val inputSha = sha256(inputBytes)
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        val runningAttempt = WorkflowAttemptStore.open(root).use { owner ->
            val current = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            val queued = owner.create(job.id, current.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WorkflowExecutionLimits(60_000u, 15_000u, 1_048_576u, 16u))).attempt
            owner.transition(job.id, queued.runId, queued.version, WorkflowTransition.Start).attempt
        }
        val runId = runningAttempt.runId
        val sourceRoot = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/$runId/source-tree"))
        val sourceFiles = linkedMapOf<String, ByteArray>()
        sourceFiles["Makefile"] = "all:\n\t@echo inert-source-fixture\n".toByteArray()
        repeat(203) { index ->
            val module = "unit_${index.toString().padStart(3, '0')}"
            sourceFiles["src/modules/$module.c"] = "int $module(void) { return $index; }\n".toByteArray()
        }
        val tooLargeModule = "unit_203"
        sourceFiles["src/modules/$tooLargeModule.c"] = ByteArray((WebRevisionSourceContent.MAXIMUM_FILE_BYTES + 1).toInt()) { 'x'.code.toByte() }

        val inputs = sourceFiles.toSortedMap().map { (path, bytes) ->
            val declaration = profile.layout.declarationForPath(path)
            GeneratedFileEvidence(path, sha256(bytes), "bounded-http-fixture",
                acceptedImplementation = if (ProjectFileRole.MODULE_IMPLEMENTATION in declaration.roles) false else null,
                roles = declaration.roles, contentKind = declaration.contentKind)
        }
        val sourceSha = sha256(sourceFiles.toSortedMap().entries.joinToString("") { (path, bytes) ->
            "${path.length}:$path:${bytes.size}:${sha256(bytes)}\n"
        }.toByteArray())
        val revisionId = webSourceRevisionId(sourceSha)
        for ((path, bytes) in sourceFiles) {
            val destination = sourceRoot.resolve(path)
            Files.createDirectories(destination.parent)
            Files.write(destination, bytes)
        }
        Files.writeString(sourceRoot.resolve("source_tree_manifest.json"), SourceTreeManifest(
            profileId = profile.id, profileSha256 = profile.sha256, inputSha256 = inputSha,
            files = inputs, unresolvedEntityIds = emptyList()).toJson())
        val descriptor = buildJsonObject {
            put("schemaVersion", 3)
            put("sourceRevisionSha256", sourceSha)
            put("sourceInputs", JsonArray(sourceFiles.toSortedMap().map { (path, bytes) -> buildJsonObject {
                put("path", path); put("bytes", bytes.size); put("sha256", sha256(bytes))
            } }))
        }
        val descriptorPath = sourceRoot.resolve("reports/build_contract.json")
        Files.createDirectories(descriptorPath.parent)
        Files.writeString(descriptorPath, descriptor.toString())

        WorkflowAttemptStore.open(root).use { owner -> owner.transition(job.id, runningAttempt.runId, runningAttempt.version,
            WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED,
                WorkflowCandidate(revisionId, sourceSha))) }
        WebSourceCatalogEvidence(listOf(profile), { id -> JobStore(root).readInput(id) },
            { id, path, maximum -> JobStore(root).readArtifact(id, path, maximum) })
            .readRevision(WebRevisionSourceReference(job.id, runId, revisionId, sourceSha, "fixture-version"))

        val server = server()
        try {
            WebTestBrowser(server).use { browser ->
                val base = "/w/api/v1/jobs/${job.id}/runs/$runId/revisions/$revisionId"
                awaitHandlers(server) // Include post-response sign-in auditing in the baseline.
                val beforeNames = entries()
                val beforeBytes = digest()
                val first = browser.get("$base/sources?limit=200")
                assertEquals(200, first.statusCode(), first.text())
                val firstData = first.data()
                assertEquals(job.id, firstData.getValue("binding").jsonObject.getValue("jobId").jsonPrimitive.content)
                assertEquals(runId, firstData.getValue("binding").jsonObject.getValue("runId").jsonPrimitive.content)
                assertEquals(revisionId, firstData.getValue("binding").jsonObject.getValue("revisionId").jsonPrimitive.content)
                assertEquals("source-input-commitments", firstData.getValue("authority").jsonPrimitive.content)
                assertEquals(205, firstData.getValue("totalFiles").jsonPrimitive.int)
                assertEquals(200, firstData.getValue("items").jsonArray.size)
                val cursor = firstData.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.content
                val manifestPath = sourceRoot.resolve("source_tree_manifest.json")
                val originalManifest = Files.readAllBytes(manifestPath)
                Files.write(manifestPath, originalManifest + byteArrayOf('\n'.code.toByte()))
                val expired = browser.get("$base/sources?limit=200&cursor=$cursor")
                assertEquals(410, expired.statusCode(), expired.text())
                assertEquals("CURSOR_EXPIRED", expired.errorCode())
                Files.write(manifestPath, originalManifest)

                val paths = mutableListOf<String>()
                val ids = mutableListOf<String>()
                var continuation: String? = null
                do {
                    val page = browser.get("$base/sources?limit=200" + (continuation?.let { "&cursor=$it" } ?: ""))
                    assertEquals(200, page.statusCode(), page.text())
                    val data = page.data()
                    val rows = data.getValue("items").jsonArray
                    assertTrue(rows.size in 1..200)
                    paths += rows.map { it.jsonObject.getValue("displayName").jsonPrimitive.content }
                    ids += rows.map { it.jsonObject.getValue("fileId").jsonPrimitive.content }
                    continuation = data.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.contentOrNull
                } while (continuation != null)
                assertEquals(sourceFiles.keys.sorted(), paths)
                assertEquals(205, ids.distinct().size, "source file selectors are unique across all pages")

                val metadata = firstData.getValue("items").jsonArray.first().jsonObject
                val fileId = metadata.getValue("fileId").jsonPrimitive.content
                val metadataVersion = firstData.getValue("metadataVersion").jsonPrimitive.content
                val contentPath = "$base/source-files/$fileId/content?metadataVersion=$metadataVersion"
                val content = browser.get(contentPath, mapOf("Accept" to "application/octet-stream"))
                assertEquals(200, content.statusCode(), content.text())
                assertEquals("application/octet-stream", content.headers().firstValue("Content-Type").orElse(null))
                assertEquals(sha256(sourceFiles.getValue("Makefile")), content.headers().firstValue("X-Decomp-Content-SHA256").orElse(null))
                assertContentEquals(sourceFiles.getValue("Makefile"), content.body())

                val chunk = browser.get("$base/source-files/$fileId/chunk?offset=0&maxBytes=8&metadataVersion=$metadataVersion")
                assertEquals(200, chunk.statusCode(), chunk.text())
                val chunkData = chunk.data()
                assertEquals(8, chunkData.getValue("lengthBytes").jsonPrimitive.content.toInt())
                assertEquals(String(sourceFiles.getValue("Makefile").copyOfRange(0, 8)), chunkData.getValue("text").jsonPrimitive.content)
                val invalidChunk = browser.get("$base/source-files/$fileId/chunk?offset=0&maxBytes=131073")
                assertEquals(422, invalidChunk.statusCode(), invalidChunk.text())
                assertEquals("VALIDATION_FAILED", invalidChunk.errorCode())

                val largeId = ids[paths.indexOf("src/modules/$tooLargeModule.c")]
                val tooLarge = browser.get("$base/source-files/$largeId/chunk?offset=0&maxBytes=8")
                assertEquals(413, tooLarge.statusCode(), tooLarge.text())
                assertEquals("SOURCE_FILE_TOO_LARGE", tooLarge.errorCode())

                val changedSource = sourceRoot.resolve("Makefile")
                Files.write(changedSource, "all:\n\t@echo changed\n".toByteArray())
                val refusedChangedBody = browser.get(contentPath, mapOf("Accept" to "application/octet-stream"))
                assertEquals(409, refusedChangedBody.statusCode(), refusedChangedBody.text())
                assertEquals("SOURCE_REVISION_CHANGED", refusedChangedBody.errorCode())
                Files.write(changedSource, sourceFiles.getValue("Makefile"))

                // The selected-source reader must reject a second name even when the bytes
                // still match the admitted manifest; report-download coverage is a different route.
                val alias = Files.createLink(root.resolve("selected-source-alias"), changedSource)
                try {
                    val linkedNames = entries()
                    val linkedBytes = digest()
                    for ((path, accept) in listOf(contentPath to "application/octet-stream",
                        "$base/source-files/$fileId/chunk?offset=0&maxBytes=8&metadataVersion=$metadataVersion" to "application/json")) {
                        val linked = browser.get(path, mapOf("Accept" to accept))
                        assertEquals(503, linked.statusCode(), linked.text())
                        assertEquals("SOURCE_FILE_UNAVAILABLE", linked.errorCode())
                        assertFalse(linked.text().contains(root.toAbsolutePath().toString()))
                        assertFalse(linked.text().contains(alias.fileName.toString()))
                    }
                    assertStorageRestored(linkedNames, linkedBytes)
                } finally { Files.delete(alias) }
                val recovered = browser.get(contentPath, mapOf("Accept" to "application/octet-stream"))
                assertEquals(200, recovered.statusCode(), recovered.text())
                assertContentEquals(sourceFiles.getValue("Makefile"), recovered.body())

                assertEquals(beforeNames, entries(), "read requests create no storage entries")
                assertEquals(beforeBytes, digest(), "read requests do not mutate persisted upload or source artifacts")
            }
        } finally { server.stop() }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }
}
