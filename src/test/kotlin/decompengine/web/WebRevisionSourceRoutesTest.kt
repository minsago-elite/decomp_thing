package decompengine.web

import decompengine.jobs.*
import decompengine.project.*
import kotlinx.serialization.json.*
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import kotlin.io.path.createTempDirectory
import kotlin.test.*

/**
 * Actual listener, store, generated trees and built contracts for two retained candidates of one job. The generated
 * project is built once per attempt as fixture setup; no request executes a compiler, workflow or subject program.
 */
class WebRevisionSourceRoutesTest {
    private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    private val limits = WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u)

    private class Attempt(val runId: String, val revisionId: String, val tree: Path)
    private inner class Fixture(val root: Path, val jobId: String, val first: Attempt, val second: Attempt) {
        lateinit var server: UploadServer
        lateinit var cookie: String
        val api = "/w/api/v1/jobs/$jobId"
        fun revision(attempt: Attempt) = "$api/runs/${attempt.runId}/revisions/${attempt.revisionId}"

        fun start() {
            server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected analysis") },
                JobReconstructor { _, _ -> error("unexpected reconstruction") }, uiMode = WebUiMode.SPA, basePath = "/w/")
            server.start()
            val token = server.issueBrowserBootstrap().token
            val origin = "http://127.0.0.1:${server.serverPort}"
            val session = client.send(HttpRequest.newBuilder(URI("$origin/w/api/v1/session")).header("Origin", origin)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"$token\"}")).build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(200, session.statusCode())
            cookie = session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
        }

        /** Stop the listener so the workflow store can be changed by its single owner, then serve again. */
        fun restart(change: (WorkflowAttemptStore) -> Unit) {
            server.stop()
            WorkflowAttemptStore.open(root).use(change)
            start()
        }
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun generate(root: Path, jobId: String, input: ByteArray, revisionId: String,
        functions: List<RecoveredFunction>, extra: (Path) -> Unit = {}): Attempt {
        val created = WorkflowAttemptStore.open(root).use { owner ->
            val snapshot = (owner.inspect(jobId) as WorkflowJobInspection.Available).snapshot
            val queued = owner.create(jobId, snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, limits))
            owner.transition(jobId, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start).attempt
        }
        val tree = root.resolve(jobId).resolve("reports/runs/${created.runId}/source-tree")
        SourceTreeGenerator.generate(RecoveredProgramModel(inputSha256 = sha256(input), functions = functions), tree)
        assertEquals(0, MakeProjectBuilder.build(tree).returnCode)
        extra(tree)
        val contract = Json.parseToJsonElement(Files.readString(tree.resolve("reports/build_contract.json"))).jsonObject
        val source = contract.getValue("sourceRevisionSha256").jsonPrimitive.content
        WorkflowAttemptStore.open(root).use { owner ->
            owner.transition(jobId, created.runId, created.version, WorkflowTransition.Finish(
                WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED, WorkflowCandidate(revisionId, source)))
        }
        return Attempt(created.runId, revisionId, tree)
    }

    private fun withFixture(block: (Fixture) -> Unit) {
        val parent = Files.createDirectories(Path.of("build/test-tmp/web-revision-routes").toAbsolutePath())
        val root = createTempDirectory(parent, "routes-")
        val store = JobStore(root)
        val input = elfFixture()
        val job = store.createFromUpload("routes.elf", input)
        val first = generate(root, job.id, input, "revision_first", listOf(
            RecoveredFunction("fn_1000", "core", 0x1000uL, "int core(void)"),
            RecoveredFunction("fn_2000", "helper", 0x2000uL, "int helper(void)")))
        val second = generate(root, job.id, input, "revision_second", listOf(
            RecoveredFunction("fn_1000", "core", 0x1000uL, "int core(void)"),
            RecoveredFunction("fn_3000", "added_entry", 0x3000uL, "int added_entry(void)")))
        val fixture = Fixture(root, job.id, first, second)
        try {
            fixture.start()
            block(fixture)
        } finally { fixture.server.stop(); root.toFile().deleteRecursively() }
    }

    private fun get(fixture: Fixture, path: String, accept: String = "application/json", method: String = "GET"): HttpResponse<ByteArray> =
        client.send(HttpRequest.newBuilder(URI("http://127.0.0.1:${fixture.server.serverPort}$path")).timeout(Duration.ofSeconds(30))
            .header("Accept", accept).header("Cookie", fixture.cookie).method(method, HttpRequest.BodyPublishers.noBody()).build(),
            HttpResponse.BodyHandlers.ofByteArray())

    private fun data(response: HttpResponse<ByteArray>, kind: String): JsonObject {
        assertEquals(200, response.statusCode(), String(response.body()))
        val document = Json.parseToJsonElement(String(response.body())).jsonObject
        assertEquals(kind, document.getValue("kind").jsonPrimitive.content)
        return document.getValue("data").jsonObject
    }

    private fun manifest(attempt: Attempt): Map<String, String> =
        Json.parseToJsonElement(Files.readString(attempt.tree.resolve("source_tree_manifest.json"))).jsonObject
            .getValue("files").jsonArray.associate { it.jsonObject.getValue("path").jsonPrimitive.content to it.jsonObject.getValue("sha256").jsonPrimitive.content }

    private fun flat(fixture: Fixture, attempt: Attempt): List<JsonObject> =
        data(get(fixture, "${fixture.revision(attempt)}/sources?limit=200"), "revisionSources").getValue("items").jsonArray.map { it.jsonObject }

    @Test fun `diffs of two retained candidates match their manifests and expose bounded hunks and an exact patch`() = withFixture { fixture ->
        val base = manifest(fixture.first); val head = manifest(fixture.second)
        val query = "baseRunId=${fixture.first.runId}&baseRevisionId=${fixture.first.revisionId}"
        val summary = data(get(fixture, "${fixture.revision(fixture.second)}/source-diff?$query&limit=200"), "sourceDiff")
        assertEquals(fixture.first.revisionId, summary.getValue("base").jsonObject.getValue("revisionId").jsonPrimitive.content)
        val expected = (base.keys + head.keys).sorted().mapNotNull { path ->
            when {
                path !in base -> path to "added"
                path !in head -> path to "removed"
                base[path] != head[path] -> path to "modified"
                else -> null
            }
        }
        val actual = summary.getValue("items").jsonArray.map { it.jsonObject }.map { item ->
            ((item["headFile"] as? JsonObject) ?: item.getValue("baseFile").jsonObject).getValue("displayName").jsonPrimitive.content to
                item.getValue("status").jsonPrimitive.content
        }
        // Renames pair only byte-identical moved files; this fixture has none, so status follows path presence.
        assertEquals(expected, actual)
        assertEquals(base.keys.intersect(head.keys).count { base[it] == head[it] },
            summary.getValue("counts").jsonObject.getValue("unchanged").jsonPrimitive.int)
        val modified = summary.getValue("items").jsonArray.map { it.jsonObject }.first { it.getValue("status").jsonPrimitive.content == "modified" &&
            it.getValue("headFile").jsonObject.getValue("declaredViewable").jsonPrimitive.boolean }
        val fileQuery = "$query&baseFileId=${modified.getValue("baseFile").jsonObject.getValue("fileId").jsonPrimitive.content}" +
            "&headFileId=${modified.getValue("headFile").jsonObject.getValue("fileId").jsonPrimitive.content}"
        val detail = data(get(fixture, "${fixture.revision(fixture.second)}/source-diff/file?$fileQuery"), "sourceFileDiff")
        assertEquals("text", detail.getValue("representation").jsonPrimitive.content)
        assertTrue(detail.getValue("hunks").jsonArray.isNotEmpty())
        val path = modified.getValue("headFile").jsonObject.getValue("displayName").jsonPrimitive.content
        val patch = get(fixture, "${fixture.revision(fixture.second)}/source-diff/patch?$fileQuery", "application/octet-stream")
        assertEquals(200, patch.statusCode())
        assertEquals("application/octet-stream", patch.headers().firstValue("Content-Type").orElseThrow())
        assertTrue(patch.headers().firstValue("Content-Disposition").orElseThrow().startsWith("attachment;"))
        assertEquals("nosniff", patch.headers().firstValue("X-Content-Type-Options").orElseThrow())
        assertEquals(summary.getValue("baseSourceSha256").jsonPrimitive.content, patch.headers().firstValue("X-Decomp-Base-Source-SHA256").orElseThrow())
        assertTrue(String(patch.body()).startsWith("--- a/$path\n+++ b/$path\n@@ "))
        val headOnly = get(fixture, "${fixture.revision(fixture.second)}/source-diff/patch?$fileQuery", "application/octet-stream", "HEAD")
        assertEquals(200, headOnly.statusCode()); assertEquals(0, headOnly.body().size)
        // A cross-job or unknown base revision cannot be compared.
        assertEquals(404, get(fixture, "${fixture.revision(fixture.second)}/source-diff?baseRunId=${fixture.first.runId}&baseRevisionId=other").statusCode())
        assertEquals(404, get(fixture, "/w/api/v1/jobs/${"b".repeat(32)}/runs/${fixture.second.runId}/revisions/${fixture.second.revisionId}/source-diff?$query").statusCode())
    }

    @Test fun `a historical file stays bound to its revision after a later candidate is accepted and removed files stay explicit`() = withFixture { fixture ->
        val oldFiles = flat(fixture, fixture.first)
        val removedPath = manifest(fixture.first).keys.first { it !in manifest(fixture.second) }
        val removed = oldFiles.single { it.getValue("displayName").jsonPrimitive.content == removedPath }
        val removedId = removed.getValue("fileId").jsonPrimitive.content
        val before = get(fixture, "${fixture.revision(fixture.first)}/source-files/$removedId/content", "application/octet-stream")
        assertEquals(200, before.statusCode())
        assertContentEquals(Files.readAllBytes(fixture.first.tree.resolve(removedPath)), before.body())
        // Publish the later candidate as the accepted revision of the job; file identities survive the restart.
        fixture.restart { owner ->
            val snapshot = (owner.inspect(fixture.jobId) as WorkflowJobInspection.Available).snapshot
            val attempt = snapshot.attempts.single { it.runId == fixture.second.runId }
            val candidate = requireNotNull(attempt.candidate)
            owner.recordAcceptedRevision(fixture.jobId, attempt.runId, snapshot.version, attempt.version, WorkflowAcceptanceReference(
                fixture.jobId, attempt.runId, candidate.revisionId, candidate.sourceSha256, "graph_node", "acceptance_artifact", candidate.sourceSha256))
        }
        val after = get(fixture, "${fixture.revision(fixture.first)}/source-files/$removedId/content", "application/octet-stream")
        assertEquals(200, after.statusCode())
        assertContentEquals(before.body(), after.body())
        val metadata = data(get(fixture, "${fixture.revision(fixture.first)}/source-files/$removedId"), "revisionFile")
        assertEquals(fixture.first.revisionId, metadata.getValue("binding").jsonObject.getValue("revisionId").jsonPrimitive.content)
        assertEquals(oldFiles, flat(fixture, fixture.first))
        // The same opaque identity never resolves inside the later revision.
        val foreign = get(fixture, "${fixture.revision(fixture.second)}/source-files/$removedId")
        assertEquals(404, foreign.statusCode())
        assertTrue(String(foreign.body()).contains("SOURCE_FILE_NOT_FOUND"))
    }

    @Test fun `manifest-only reports and notes are browsable through the real reader with digest checks`() = withFixture { fixture ->
        val files = flat(fixture, fixture.first)
        val recorded = files.filter { it.getValue("commitment").jsonPrimitive.content == "manifest-digest" }
        val paths = recorded.map { it.getValue("displayName").jsonPrimitive.content }
        assertTrue(paths.any { it.endsWith(".json") }, paths.toString())
        assertTrue(recorded.all { it.getValue("sizeBytes") == JsonNull })
        val inputs = files.filter { it.getValue("commitment").jsonPrimitive.content == "source-input" }
        assertTrue(inputs.isNotEmpty() && inputs.all { it.getValue("sizeBytes") is JsonPrimitive && it.getValue("sizeBytes") != JsonNull })
        val report = recorded.first { it.getValue("displayName").jsonPrimitive.content.endsWith(".json") }
        val id = report.getValue("fileId").jsonPrimitive.content
        val chunk = data(get(fixture, "${fixture.revision(fixture.first)}/source-files/$id/chunk?maxBytes=131072"), "sourceChunk")
        val bytes = Files.readAllBytes(fixture.first.tree.resolve(report.getValue("displayName").jsonPrimitive.content))
        assertEquals(bytes.size.toString(), chunk.getValue("sizeBytes").jsonPrimitive.content)
        assertEquals("utf8", chunk.getValue("representation").jsonPrimitive.content)
        // Substituted bytes no longer match the manifest digest and are refused instead of displayed.
        Files.write(fixture.first.tree.resolve(report.getValue("displayName").jsonPrimitive.content), bytes + "\n".toByteArray())
        val changed = get(fixture, "${fixture.revision(fixture.first)}/source-files/$id/chunk")
        assertEquals(409, changed.statusCode(), String(changed.body()))
    }
}
