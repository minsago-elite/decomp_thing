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

    @Test fun `archive observations share session and global artifact capacity without blocking operation reads or replay`() = withFixture { fixture ->
        val original = Files.readAllBytes(fixture.archive)
        val key = "archive-capacity-replay-01"
        val operation = data(verify(fixture, sha256(original), key), "operation", 202)
        finish(fixture, operation)
        // Hold real pinned download descriptors open by not consuming a body larger than socket buffers.
        Files.write(fixture.archive, ByteArray(48 * 1024 * 1024) { (it % 251).toByte() })
        val href = status(fixture).getValue("archive").jsonObject.getValue("contentHref").jsonPrimitive.content
        val held = mutableListOf<HttpResponse<java.io.InputStream>>()
        fun hold(owner: Fixture) {
            val response = client.send(HttpRequest.newBuilder(URI(owner.origin + href)).timeout(Duration.ofSeconds(30))
                .header("Cookie", owner.cookie).header("Accept", "application/octet-stream").GET().build(), HttpResponse.BodyHandlers.ofInputStream())
            held += response
            assertEquals(200, response.statusCode())
            response.body().readNBytes(1024)
        }
        fun anotherSession(): Fixture {
            val response = client.send(HttpRequest.newBuilder(URI("${fixture.origin}/w/api/v1/session"))
                .header("Origin", fixture.origin).header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"${fixture.server.issueBrowserBootstrap().token}\"}")).build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(200, response.statusCode())
            val csrf = Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
            return Fixture(fixture.server, fixture.root, fixture.jobId, fixture.runId, fixture.tree,
                response.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';'), csrf, fixture.origin)
        }
        fun refused(owner: Fixture) {
            val get = get(owner, "${owner.revision}/source-archive")
            assertEquals(429, get.statusCode())
            assertEquals("DOWNLOAD_LIMIT", Json.parseToJsonElement(String(get.body())).jsonObject.getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
            val head = client.send(HttpRequest.newBuilder(URI("${owner.origin}${owner.revision}/source-archive"))
                .header("Cookie", owner.cookie).header("Accept", "application/json").method("HEAD", HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofByteArray())
            assertEquals(429, head.statusCode())
            val post = verify(owner, "0".repeat(64), "archive-capacity-new-0001")
            assertEquals(429, post.statusCode())
            assertEquals("DOWNLOAD_LIMIT", Json.parseToJsonElement(String(post.body())).jsonObject.getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
        }
        try {
            hold(fixture); hold(fixture)
            refused(fixture) // Two reads in this session, but spare global capacity remains.
            val second = anotherSession()
            assertEquals(200, get(second, "${second.revision}/source-archive").statusCode())
            hold(second); hold(second)
            assertEquals(4, fixture.server.activeArtifactDownloads())
            refused(anotherSession()) // A fresh session cannot bypass the four-global ceiling.
            assertEquals(200, get(fixture, "/w/api/v1/jobs/${fixture.jobId}/runs").statusCode())
            val id = operation.getValue("operationId").jsonPrimitive.content
            assertEquals(200, get(fixture, "${fixture.revision}/archive-verifications/$id").statusCode())
            val replay = verify(fixture, sha256(original), key)
            assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
            assertEquals(operation.getValue("operationId"), data(replay, "operation", 202).getValue("operationId"))
        } finally { held.forEach { it.body().close() } }
        val deadline = System.nanoTime() + 10_000_000_000
        while (fixture.server.activeArtifactDownloads() != 0 && System.nanoTime() < deadline) Thread.sleep(10)
        assertEquals(0, fixture.server.activeArtifactDownloads())
        assertEquals(200, get(fixture, "${fixture.revision}/source-archive").statusCode())
        Files.write(fixture.archive, original)
        // The capacity-refused key was not admitted or bound to the refused digest.
        assertEquals(202, verify(fixture, sha256(original), "archive-capacity-new-0001").statusCode())
    }

    @Test fun `archive routes propagate their own expired exchange deadline before observation admission`() = withFixture { fixture ->
        fixture.server.stop() // Reopen the same persisted fixture under a directly controlled request boundary.
        val store = JobStore(fixture.root)
        WebJobService(store, JobAnalyzer { _, _ -> error("unexpected analysis") },
            JobReconstructor { _, _ -> error("unexpected reconstruction") }).use { service ->
            service.initializeExistingStorage()
            LocalWebAccess(LocalWebAccessConfiguration("http://127.0.0.1:12345")).use { access ->
                WebStreamResources().use { resources ->
                    val evidence = WebArchiveEvidence(store, WebSourceEvidence(store, defaultWebSourceProfiles(), service::readArtifact), service::readArtifact)
                    WebApiController(access, EmbeddedWebAssets.load(basePath = "/w/"), service,
                        WebJobMutationBoundary(access, service), resources, archiveEvidence = evidence).use { api ->
                        val session = MemoryExchange("POST", "/w/api/v1/session", "{\"token\":\"${access.issueBootstrap().token}\"}")
                        session.requestHeaders.set("Origin", "http://127.0.0.1:12345")
                        session.requestHeaders.set("Content-Type", "application/json")
                        assertTrue(api.route(session)); assertEquals(200, session.responseCode)
                        val cookie = session.responseHeaders.getFirst("Set-Cookie").substringBefore(';')
                        val csrf = Json.parseToJsonElement(session.output.toString()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
                        val digest = sha256(Files.readAllBytes(fixture.archive))
                        fun request(method: String) = MemoryExchange(method, fixture.revision +
                            if (method == "POST") "/archive-verifications" else "/source-archive", "{\"archiveSha256\":\"$digest\"}").apply {
                            requestHeaders.set("Cookie", cookie)
                            if (method == "POST") {
                                requestHeaders.set("Origin", "http://127.0.0.1:12345"); requestHeaders.set("Content-Type", "application/json")
                                requestHeaders.set("X-CSRF-Token", csrf); requestHeaders.set("Idempotency-Key", "archive-expired-route-0001")
                            }
                        }
                        val scheduler = object : java.util.concurrent.ScheduledThreadPoolExecutor(1) {
                            lateinit var expire: Runnable
                            override fun schedule(command: Runnable, delay: Long, unit: java.util.concurrent.TimeUnit): java.util.concurrent.ScheduledFuture<*> {
                                expire = command
                                return super.schedule(command, 1, java.util.concurrent.TimeUnit.DAYS)
                            }
                        }
                        try {
                            for (method in listOf("GET", "HEAD", "POST")) {
                                val exchange = request(method)
                                val deadline = WebRequestDeadline(scheduler, AutoCloseable { exchange.close() }, 30_000)
                                WebRequestDeadline.register(exchange, deadline)
                                try {
                                    scheduler.expire.run()
                                    assertTrue(api.route(exchange))
                                    // The memory transport records the generic error a real closed exchange cannot send.
                                    assertEquals(500, exchange.responseCode, "$method must not succeed after its deadline expired")
                                    assertEquals(0, api.artifactDownloads.activeCount())
                                } finally { WebRequestDeadline.release(exchange); deadline.cancel() }
                            }
                            for (method in listOf("GET", "HEAD", "POST")) {
                                val fresh = request(method)
                                assertTrue(api.route(fresh)); assertEquals(if (method == "POST") 202 else 200, fresh.responseCode)
                                assertNull(fresh.responseHeaders.getFirst("Idempotency-Replayed"), "expired POST must not bind the key")
                                assertEquals(0, api.artifactDownloads.activeCount())
                            }
                        } finally { scheduler.shutdownNow() }
                    }
                }
            }
        }
    }

    private class MemoryExchange(private val method: String, path: String, body: String) : com.sun.net.httpserver.HttpExchange() {
        private val incoming = com.sun.net.httpserver.Headers().apply { set("Host", "127.0.0.1:12345"); set("Accept", "application/json") }
        private val outgoing = com.sun.net.httpserver.Headers()
        private val input = body.byteInputStream()
        val output = java.io.ByteArrayOutputStream()
        private var status = -1
        private val uri = URI.create(path)
        override fun getRequestHeaders() = incoming
        override fun getResponseHeaders() = outgoing
        override fun getRequestURI() = uri
        override fun getRequestMethod() = method
        override fun getHttpContext(): com.sun.net.httpserver.HttpContext = throw UnsupportedOperationException()
        override fun close() = Unit
        override fun getRequestBody() = input
        override fun getResponseBody() = output
        override fun sendResponseHeaders(code: Int, length: Long) { status = code }
        override fun getRemoteAddress() = java.net.InetSocketAddress("127.0.0.1", 1)
        override fun getResponseCode() = status
        override fun getLocalAddress() = java.net.InetSocketAddress("127.0.0.1", 12345)
        override fun getProtocol() = "HTTP/1.1"
        override fun getAttribute(name: String): Any? = null
        override fun setAttribute(name: String, value: Any?) = Unit
        override fun setStreams(input: java.io.InputStream?, output: java.io.OutputStream?) = Unit
        override fun getPrincipal(): com.sun.net.httpserver.HttpPrincipal? = null
    }

    @Test fun `operation location and key replay survive missing source metadata`() = withFixture { fixture ->
        val digest = sha256(Files.readAllBytes(fixture.archive))
        val key = "archive-metadata-loss-0001"
        val accepted = verify(fixture, digest, key)
        val operation = data(accepted, "operation", 202)
        val completed = finish(fixture, operation)
        assertEquals("completed", completed.getValue("state").jsonPrimitive.content)
        Files.delete(fixture.tree.resolve("source_tree_manifest.json"))
        val location = accepted.headers().firstValue("Location").orElseThrow()
        assertEquals(completed, data(get(fixture, location), "operation"))
        val replay = verify(fixture, digest, key)
        assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
        assertEquals(completed, data(replay, "operation", 202))
        assertEquals(503, verify(fixture, digest, "archive-new-after-loss-01").statusCode())
    }

    @Test fun `a metadata-only change of the same archive asks for a new check instead of claiming a replacement`() = withFixture { fixture ->
        val bytes = Files.readAllBytes(fixture.archive)
        assertEquals("completed", finish(fixture, data(verify(fixture, sha256(bytes)), "operation", 202)).getValue("state").jsonPrimitive.content)
        // Change a manifest-only note and its recorded digest; the archive file itself is untouched.
        val note = fixture.tree.resolve("UNRESOLVED.md")
        Files.writeString(note, Files.readString(note) + "\nchanged note\n")
        val manifestPath = fixture.tree.resolve("source_tree_manifest.json")
        val manifest = Json.parseToJsonElement(Files.readString(manifestPath)).jsonObject
        val files = manifest.getValue("files").jsonArray.map { item ->
            val file = item.jsonObject
            if (file.getValue("path").jsonPrimitive.content == "UNRESOLVED.md") JsonObject(file + ("sha256" to JsonPrimitive(sha256(Files.readAllBytes(note))))) else file
        }
        Files.writeString(manifestPath, JsonObject(manifest + ("files" to JsonArray(files))).toString())
        val verification = status(fixture).getValue("verification").jsonObject
        assertEquals("not-verified", verification.getValue("state").jsonPrimitive.content)
        assertEquals(JsonNull, verification.getValue("previousVerifiedSha256"))
        assertEquals(sha256(bytes), status(fixture).getValue("archive").jsonObject.getValue("sha256").jsonPrimitive.content)
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
