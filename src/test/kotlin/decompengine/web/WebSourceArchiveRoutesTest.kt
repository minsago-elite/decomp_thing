package decompengine.web

import decompengine.jobs.*
import decompengine.project.*
import kotlinx.serialization.json.*
import java.io.ByteArrayInputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.zip.ZipInputStream
import kotlin.io.path.createTempDirectory
import kotlin.test.*

/**
 * Actual listener, store, generated tree, recorded build and packaged archive for one retained candidate. The project
 * is built once as fixture setup (and once more to prove independent rebuild); no request compiles or executes code.
 */
class WebSourceArchiveRoutesTest {
    private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    private val limits = WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u)

    private class Fixture(val server: UploadServer, val root: Path, val jobId: String, val runId: String, val tree: Path,
        val cookie: String, val csrf: String, val origin: String) {
        val revision = "/w/api/v1/jobs/$jobId/runs/$runId/revisions/revision_archive"
        val archive: Path get() = tree.parent.resolve("source-tree.zip")
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun withFixture(beforeStart: (Path) -> Unit = {}, block: (Fixture) -> Unit) {
        val parent = Files.createDirectories(Path.of("build/test-tmp/web-source-archive").toAbsolutePath())
        val root = createTempDirectory(parent, "archive-")
        val store = JobStore(root)
        val input = elfFixture()
        val job = store.createFromUpload("archive.elf", input)
        val created = WorkflowAttemptStore.open(root).use { owner ->
            val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            val queued = owner.create(job.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, limits))
            owner.transition(job.id, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start).attempt
        }
        val tree = root.resolve(job.id).resolve("reports/runs/${created.runId}/source-tree")
        SourceTreeGenerator.generate(RecoveredProgramModel(inputSha256 = sha256(input), functions = listOf(
            RecoveredFunction("fn_1000", "core", 0x1000uL, "int core(void)"))), tree)
        assertEquals(0, MakeProjectBuilder.build(tree).returnCode)
        ArchivalPackager.create(tree, tree.parent.resolve("source-tree.zip"))
        beforeStart(tree)
        val contract = Json.parseToJsonElement(Files.readString(tree.resolve("reports/build_contract.json"))).jsonObject
        WorkflowAttemptStore.open(root).use { owner ->
            owner.transition(job.id, created.runId, created.version, WorkflowTransition.Finish(WorkflowRunState.COMPLETED,
                WorkflowTerminalReason.COMPLETED, WorkflowCandidate("revision_archive", contract.getValue("sourceRevisionSha256").jsonPrimitive.content)))
        }
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected analysis") },
            JobReconstructor { _, _ -> error("unexpected reconstruction") }, uiMode = WebUiMode.SPA, basePath = "/w/")
        server.start()
        try {
            val origin = "http://127.0.0.1:${server.serverPort}"
            val session = client.send(HttpRequest.newBuilder(URI("$origin/w/api/v1/session")).header("Origin", origin)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"${server.issueBrowserBootstrap().token}\"}")).build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(200, session.statusCode())
            val csrf = Json.parseToJsonElement(session.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
            block(Fixture(server, root, job.id, created.runId, tree, session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';'), csrf, origin))
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    private fun get(fixture: Fixture, path: String, accept: String = "application/json") = client.send(
        HttpRequest.newBuilder(URI(fixture.origin + path)).timeout(Duration.ofSeconds(30)).header("Accept", accept)
            .header("Cookie", fixture.cookie).GET().build(), HttpResponse.BodyHandlers.ofByteArray())

    private fun verify(fixture: Fixture, digest: String, key: String = "archive-key-0000001", csrf: String? = fixture.csrf): HttpResponse<ByteArray> {
        val request = HttpRequest.newBuilder(URI("${fixture.origin}${fixture.revision}/archive-verifications")).timeout(Duration.ofSeconds(30))
            .header("Accept", "application/json").header("Content-Type", "application/json").header("Origin", fixture.origin)
            .header("Cookie", fixture.cookie).header("Idempotency-Key", key)
        if (csrf != null) request.header("X-CSRF-Token", csrf)
        return client.send(request.POST(HttpRequest.BodyPublishers.ofString("{\"archiveSha256\":\"$digest\"}")).build(), HttpResponse.BodyHandlers.ofByteArray())
    }

    private fun data(response: HttpResponse<ByteArray>, kind: String, status: Int = 200): JsonObject {
        assertEquals(status, response.statusCode(), String(response.body()))
        val document = Json.parseToJsonElement(String(response.body())).jsonObject
        assertEquals(kind, document.getValue("kind").jsonPrimitive.content)
        return document.getValue("data").jsonObject
    }

    private fun status(fixture: Fixture) = data(get(fixture, "${fixture.revision}/source-archive"), "sourceArchive")
    private fun state(fixture: Fixture) = status(fixture).getValue("verification").jsonObject.getValue("state").jsonPrimitive.content

    private fun finish(fixture: Fixture, operation: JsonObject): JsonObject {
        val id = operation.getValue("operationId").jsonPrimitive.content
        val deadline = System.nanoTime() + 60_000_000_000
        while (System.nanoTime() < deadline) {
            val current = data(get(fixture, "${fixture.revision}/archive-verifications/$id"), "operation")
            if (current.getValue("state").jsonPrimitive.content in setOf("completed", "failed", "interrupted")) return current
            Thread.sleep(25)
        }
        fail("archive verification did not finish")
    }

    @Test fun `archive status identifies revision build and digest and only an explicit verification labels it verified`() = withFixture { fixture ->
        val bytes = Files.readAllBytes(fixture.archive)
        val before = status(fixture)
        assertEquals("revision_archive", before.getValue("binding").jsonObject.getValue("revisionId").jsonPrimitive.content)
        val archive = before.getValue("archive").jsonObject
        assertEquals(sha256(bytes), archive.getValue("sha256").jsonPrimitive.content)
        assertEquals(bytes.size.toString(), archive.getValue("sizeBytes").jsonPrimitive.content)
        val contract = Json.parseToJsonElement(Files.readString(fixture.tree.resolve("reports/build_contract.json"))).jsonObject
        val build = before.getValue("build").jsonObject
        assertEquals("recorded", build.getValue("state").jsonPrimitive.content)
        assertEquals(contract.getValue("artifact").jsonObject.getValue("sha256").jsonPrimitive.content, build.getValue("executableSha256").jsonPrimitive.content)
        assertEquals("not-evaluated", before.getValue("acceptance").jsonPrimitive.content)
        assertEquals(buildJsonObject { put("state", "unavailable"); put("reason", "not-recorded") }, before.getValue("git"))
        assertEquals("not-verified", before.getValue("verification").jsonObject.getValue("state").jsonPrimitive.content)
        // Explicit operation: CSRF, key and the displayed digest are all required before any verification work.
        assertEquals(403, verify(fixture, sha256(bytes), csrf = null).statusCode())
        assertEquals("ARCHIVE_CHANGED", Json.parseToJsonElement(String(verify(fixture, "0".repeat(64)).body())).jsonObject
            .getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
        val accepted = verify(fixture, sha256(bytes), "archive-key-0000002")
        val operation = data(accepted, "operation", 202)
        assertEquals("archive.verify", operation.getValue("action").jsonPrimitive.content)
        assertTrue(accepted.headers().firstValue("Location").orElseThrow().endsWith("/archive-verifications/${operation.getValue("operationId").jsonPrimitive.content}"))
        assertEquals("completed", finish(fixture, operation).getValue("state").jsonPrimitive.content)
        val after = status(fixture).getValue("verification").jsonObject
        assertEquals("verified", after.getValue("state").jsonPrimitive.content)
        assertEquals(operation.getValue("operationId"), after.getValue("operationId"))
        // Exact replay returns the original operation; the key cannot be reused for another archive.
        val replay = verify(fixture, sha256(bytes), "archive-key-0000002")
        assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
        assertEquals(operation.getValue("operationId"), data(replay, "operation", 202).getValue("operationId"))
        assertEquals(409, verify(fixture, "1".repeat(64), "archive-key-0000002").statusCode())
        // The offered download is the verified bytes, compatible with independent extraction and rebuild.
        val download = get(fixture, archive.getValue("contentHref").jsonPrimitive.content, "application/octet-stream")
        assertEquals(200, download.statusCode())
        assertContentEquals(bytes, download.body())
        val extracted = Files.createDirectories(fixture.root.resolve("independent"))
        ZipInputStream(ByteArrayInputStream(download.body())).use { zip ->
            generateSequence { zip.nextEntry }.forEach { entry ->
                assertFalse(entry.name.split('/').any { it == ".git" || it == ".." })
                val target = extracted.resolve(entry.name)
                if (entry.isDirectory) Files.createDirectories(target)
                else { Files.createDirectories(target.parent); Files.write(target, zip.readAllBytes()) }
            }
        }
        val manifest = Json.parseToJsonElement(Files.readString(extracted.resolve("source_tree_manifest.json"))).jsonObject
        for (file in manifest.getValue("files").jsonArray.map { it.jsonObject }) {
            assertEquals(file.getValue("sha256").jsonPrimitive.content,
                sha256(Files.readAllBytes(extracted.resolve(file.getValue("path").jsonPrimitive.content))))
        }
        assertEquals(0, MakeProjectBuilder.build(extracted).returnCode)
        val artifact = contract.getValue("artifact").jsonObject
        assertEquals(artifact.getValue("sha256").jsonPrimitive.content,
            sha256(Files.readAllBytes(extracted.resolve(artifact.getValue("path").jsonPrimitive.content))))
    }

    @Test fun `replaced incomplete or stale archives never keep or gain the verified label`() = withFixture { fixture ->
        val original = Files.readAllBytes(fixture.archive)
        assertEquals("completed", finish(fixture, data(verify(fixture, sha256(original)), "operation", 202)).getValue("state").jsonPrimitive.content)
        val verifiedHref = status(fixture).getValue("archive").jsonObject.getValue("contentHref").jsonPrimitive.content
        // A truncated replacement is a different archive: the previous verification becomes stale, never transferred.
        val truncated = original.copyOf(original.size / 2)
        Files.write(fixture.archive, truncated)
        val stale = status(fixture).getValue("verification").jsonObject
        assertEquals("stale", stale.getValue("state").jsonPrimitive.content)
        assertEquals(sha256(original), stale.getValue("previousVerifiedSha256").jsonPrimitive.content)
        assertEquals(409, get(fixture, verifiedHref, "application/octet-stream").statusCode(), "the old verified link must not serve new bytes")
        val failed = finish(fixture, data(verify(fixture, sha256(truncated), "archive-key-0000003"), "operation", 202))
        assertEquals("failed", failed.getValue("state").jsonPrimitive.content)
        val verification = status(fixture).getValue("verification").jsonObject
        assertEquals("failed", verification.getValue("state").jsonPrimitive.content)
        assertEquals("ARCHIVE_INVALID", verification.getValue("failureCode").jsonPrimitive.content)
        // Restoring the verified bytes restores the label: it follows exact bytes and revision metadata.
        Files.write(fixture.archive, original)
        assertEquals("verified", state(fixture))
    }

    @Test fun `an archive whose payload differs from the current tree is not labeled verified`() = withFixture(beforeStart = { tree ->
        // The archive keeps the original note while the retained tree changes after packaging.
        Files.writeString(tree.resolve("UNRESOLVED.md"), Files.readString(tree.resolve("UNRESOLVED.md")) + "\nchanged after packaging\n")
    }) { fixture ->
        val bytes = Files.readAllBytes(fixture.archive)
        val result = finish(fixture, data(verify(fixture, sha256(bytes)), "operation", 202))
        assertEquals("failed", result.getValue("state").jsonPrimitive.content)
        assertEquals("failed", state(fixture))
    }

    @Test fun `repository metadata in the payload is refused by the archive verifier`() = withFixture(beforeStart = { tree ->
        // Both the retained tree and the archive carry .git, so only the repository-metadata rule can refuse it.
        Files.createDirectories(tree.resolve(".git")); Files.writeString(tree.resolve(".git/config"), "[core]\n")
        val archive = tree.parent.resolve("source-tree.zip")
        val copied = java.io.ByteArrayOutputStream()
        java.util.zip.ZipOutputStream(copied).use { output ->
            ZipInputStream(Files.newInputStream(archive)).use { input ->
                generateSequence { input.nextEntry }.forEach { entry ->
                    output.putNextEntry(java.util.zip.ZipEntry(entry.name)); output.write(input.readAllBytes()); output.closeEntry()
                }
            }
            output.putNextEntry(java.util.zip.ZipEntry(".git/config")); output.write("[core]\n".toByteArray()); output.closeEntry()
        }
        Files.write(archive, copied.toByteArray())
    }) { fixture ->
        val bytes = Files.readAllBytes(fixture.archive)
        val result = finish(fixture, data(verify(fixture, sha256(bytes)), "operation", 202))
        assertEquals("failed", result.getValue("state").jsonPrimitive.content)
    }
}
