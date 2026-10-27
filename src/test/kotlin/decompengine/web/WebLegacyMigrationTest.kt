package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ProjectFileRole
import decompengine.project.SourceTreeManifest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.createDirectories
import kotlin.io.path.readBytes
import kotlin.io.path.writeText
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * D13.3 migration evidence (#662, #663, #664). A data directory shaped like one written by the
 * D0 release is opened by the current build in both presentation modes. Every legacy route in
 * docs/web-legacy-migration.md is requested with a valid session; no request starts work, no
 * authoritative byte changes, and only the documented schema-boundary files are ever added.
 */
class WebLegacyMigrationTest {
    private val root: Path = Files.createTempDirectory(Path.of("build").createDirectories(), "legacy-migration")
    private val http: HttpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()

    @AfterTest fun cleanup() { http.close(); root.toFile().deleteRecursively() }

    /** One row of the migration matrix. `{J}` is a completed retained job, `{I}` a historically interrupted one. */
    private data class Route(
        val id: String, val method: String, val path: String,
        val legacy: Int, val spa: Int,
        val accept: String = "*/*",
        val legacyType: String? = null, val spaType: String? = null,
    )

    private val matrix = listOf(
        Route("MIG-01", "GET", "/", 200, 200, legacyType = "text/html", spaType = "text/html"),
        Route("MIG-02", "GET", "/login", 200, 404, legacyType = "text/html", spaType = "application/json"),
        Route("MIG-03", "GET", "/assets/app.css", 200, 404, legacyType = "text/css", spaType = "application/json"),
        Route("MIG-04", "GET", "/jobs/{J}", 200, 200, legacyType = "text/html", spaType = "text/html"),
        Route("MIG-05", "GET", "/jobs/{I}", 200, 200, legacyType = "text/html", spaType = "text/html"),
        Route("MIG-06", "GET", "/jobs/{J}/source/src/modules/core.c", 200, 404, legacyType = "text/html", spaType = "application/json"),
        Route("MIG-07", "GET", "/jobs/{J}/artifacts/reports/exploration.json", 200, 404, legacyType = "application/json", spaType = "application/json"),
        Route("MIG-08", "GET", "/jobs/{J}/artifacts/reports/source-tree.zip", 400, 404, legacyType = "text/html", spaType = "application/json"),
        Route("MIG-09", "GET", "/api/jobs/{J}", 200, 404, accept = "application/json", legacyType = "application/json", spaType = "application/json"),
        Route("MIG-10", "HEAD", "/api/jobs/{J}", 200, 404, accept = "application/json", legacyType = "application/json", spaType = "application/json"),
        Route("MIG-11", "GET", "/api/jobs/{J}/events", 503, 404, accept = "application/json", legacyType = "application/json", spaType = "application/json"),
        Route("MIG-12", "GET", "/api/recovery", 200, 404, accept = "application/json", legacyType = "application/json", spaType = "application/json"),
        Route("MIG-13", "GET", "/api/operator/auth-methods", 200, 404, accept = "application/json", legacyType = "application/json", spaType = "application/json"),
        Route("MIG-14", "GET", "/jobs/{J}/explore", 404, 404, legacyType = "text/html", spaType = "application/json"),
        Route("MIG-15", "GET", "/jobs/{J}/reconstruct", 404, 404, legacyType = "text/html", spaType = "application/json"),
        Route("MIG-16", "GET", "/api/v1/jobs/{J}", 404, 200, accept = "application/json", legacyType = "application/json", spaType = "application/json"),
        Route("MIG-17", "GET", "/api/v1/recovery", 404, 200, accept = "application/json", legacyType = "application/json", spaType = "application/json"),
    )

    /** Explicit execution requests. Only the legacy presentation still accepts them, and never from a GET. */
    private val executionRoutes = listOf("/jobs", "/jobs/{J}/explore", "/jobs/{J}/reconstruct", "/api/operator/auth-methods")

    private class Fixture(val completed: String, val interrupted: String, val uploaded: String)

    private val privateDiagnostic = "PRIVATE_LEGACY_DIAGNOSTIC /home/operator/.secret token=sk-legacy"

    /** Synthetic files in the shape the D0 release wrote: its job.json writer and its unversioned report layout. */
    private fun retainedLegacyStore(): Fixture {
        val store = JobStore(root)
        val completed = store.createFromUpload("retained-complete.elf", elfFixture()).id
        val interrupted = store.createFromUpload("retained-interrupted.elf", elfFixture()).id
        val uploaded = store.createFromUpload("retained-uploaded.elf", elfFixture()).id
        rewriteAsD0(completed, "complete", privateDiagnostic, withUpdatedAt = false)
        rewriteAsD0(interrupted, "analyzing", "historical active record")
        rewriteAsD0(uploaded, "uploaded", null)
        val reports = root.resolve(completed).resolve("reports").createDirectories()
        reports.resolve("exploration.json").writeText(
            """
            {
              "candidateCount": 1,
              "coverageIncreased": false,
              "baselineOutputSignatures": 1,
              "expandedOutputSignatures": 1,
              "newOutputSignatures": [],
              "angr": {"argvStates":1,"stdinStates":1,"argvSteps":4,"stdinSteps":4},
              "confidence": {"score": 0.5, "inputCount": 1, "sourceCount": 1, "outputSignatureCount": 1,
                "newOutputSignatureCount": 0, "sandboxed": true, "networkIsolated": true},
              "candidates": [{"id":"seed_default","source":"SEED","args":[],"stdinHex":""}],
              "observations": [{"candidateId":"seed_default","signature":"0:4f4b0a:","exitCode":0,
                "stdoutHex":"4f4b0a","stderrHex":"","networkIsolated":true}]
            }
            """.trimIndent(),
        )
        val tree = reports.resolve("source-tree")
        tree.resolve("src/modules").createDirectories()
        tree.resolve("reports").createDirectories()
        tree.resolve("src/modules/core.c").writeText("int core(void) { /* <b>retained</b> */ return 0; }\n")
        tree.resolve("Makefile").writeText("all:\n\t@true\n")
        tree.resolve("reports/confidence.json").writeText("{\"projectScore\":0.5,\"modules\":[{\"id\":\"core\",\"score\":0.5}]}")
        writeManifest(tree, listOf("src/modules/core.c", "Makefile", "reports/confidence.json"))
        reports.resolve("reconstruction_progress.json").writeText("{\"phase\":\"modules\",\"completed\":1,\"total\":1,\"module\":\"core\"}")
        // An archive the D0 release linked without verification. It must stay unverified and byte-identical.
        reports.resolve("source-tree.zip").writeText("archive")
        return Fixture(completed, interrupted, uploaded)
    }

    /** The D0 writer (`27feba3` JobStore.persist): pretty-printed, newline-terminated; earlier records lack updated_at. */
    private fun rewriteAsD0(jobId: String, status: String, message: String?, withUpdatedAt: Boolean = true) {
        val current = Json.parseToJsonElement(Files.readString(root.resolve(jobId).resolve("job.json"))).jsonObject
        val record = kotlinx.serialization.json.buildJsonObject {
            put("id", current.getValue("id")); put("filename", current.getValue("filename"))
            put("status", kotlinx.serialization.json.JsonPrimitive(status)); put("created_at", current.getValue("created_at"))
            if (withUpdatedAt) put("updated_at", current.getValue("created_at"))
            message?.let { put("status_message", kotlinx.serialization.json.JsonPrimitive(it)) }
            put("size_bytes", current.getValue("size_bytes")); put("binary_path", current.getValue("binary_path"))
            put("metadata", current.getValue("metadata"))
        }
        root.resolve(jobId).resolve("job.json").writeText(
            Json { prettyPrint = true }.encodeToString(kotlinx.serialization.json.JsonElement.serializer(), record) + "\n")
    }

    private fun writeManifest(tree: Path, paths: List<String>) {
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        val manifest = SourceTreeManifest(
            profileId = profile.id,
            profileSha256 = profile.sha256,
            inputSha256 = sha256(elfFixture()),
            files = paths.map { relative ->
                val declaration = profile.layout.declarationForPath(relative)
                GeneratedFileEvidence(
                    path = relative,
                    sha256 = sha256(tree.resolve(relative).readBytes()),
                    generator = "llm",
                    entityIds = listOf("fn_1000"),
                    acceptedImplementation = if (ProjectFileRole.MODULE_IMPLEMENTATION in declaration.roles) true else null,
                    roles = declaration.roles,
                    contentKind = declaration.contentKind,
                )
            },
            unresolvedEntityIds = emptyList(),
        )
        tree.resolve("source_tree_manifest.json").writeText(manifest.toJson())
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** Every regular file under the data directory, by relative path. */
    private fun storageDigest(base: Path = root): Map<String, String> = Files.walk(base).use { paths ->
        paths.filter { Files.isRegularFile(it) }.toList().associate { base.relativize(it).toString() to sha256(Files.readAllBytes(it)) }
    }

    private fun directories(base: Path = root): Set<String> = Files.walk(base).use { paths ->
        paths.filter { Files.isDirectory(it) && it != base }.map { base.relativize(it).toString() }.toList().toSet()
    }

    private class Server(val server: UploadServer, val executions: AtomicInteger) : AutoCloseable {
        val origin get() = "http://127.0.0.1:${server.serverPort}"
        override fun close() = server.stop()
    }

    private fun start(mode: WebUiMode, data: Path = root): Server {
        val executions = AtomicInteger()
        val server = UploadServer("127.0.0.1", 0, data,
            analyzer = JobAnalyzer { _, _ -> executions.incrementAndGet() },
            reconstructor = JobReconstructor { _, _ -> executions.incrementAndGet() },
            uiMode = mode)
        server.start()
        return Server(server, executions)
    }

    private fun Server.call(method: String, path: String, accept: String = "*/*", headers: Map<String, String> = emptyMap()): HttpResponse<String> {
        val builder = HttpRequest.newBuilder(URI(origin + path)).timeout(Duration.ofSeconds(10)).header("Accept", accept)
        headers.forEach { (name, value) -> builder.setHeader(name, value) }
        builder.method(method, HttpRequest.BodyPublishers.noBody())
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString())
    }

    private fun Route.resolved(fixture: Fixture) = path.replace("{J}", fixture.completed).replace("{I}", fixture.interrupted)

    /** Requests every matrix row under one valid session and checks the documented answer for this mode. */
    private fun sweep(server: Server, mode: WebUiMode, fixture: Fixture) {
        val session = legacySessionHeaders(server.server)
        val cookie = mapOf("Cookie" to session.getValue("Cookie"))
        for (route in matrix) {
            val response = server.call(route.method, route.resolved(fixture), route.accept, cookie)
            val expected = if (mode == WebUiMode.LEGACY) route.legacy else route.spa
            assertEquals(expected, response.statusCode(), "${route.id} ${route.method} ${route.path} in $mode")
            val type = if (mode == WebUiMode.LEGACY) route.legacyType else route.spaType
            if (type != null) assertTrue(response.headers().firstValue("Content-Type").orElse("").startsWith(type),
                "${route.id} content type in $mode: ${response.headers().firstValue("Content-Type")}")
            if (route.method == "HEAD") assertTrue(response.body().isEmpty(), "${route.id} HEAD body")
            // An API or attachment request never receives the SPA shell, and no answer copies private stored diagnostics.
            if (route.path.startsWith("/api/") || route.path.contains("/artifacts/") || route.path.contains("/source/"))
                assertFalse(response.body().contains("decomp-ui-build"), "${route.id} received the SPA shell in $mode")
            assertFalse(response.body().contains("PRIVATE_LEGACY_DIAGNOSTIC") || response.body().contains(".secret"), "${route.id} leaked a stored diagnostic")
            assertFalse(response.body().contains(root.toAbsolutePath().toString()), "${route.id} leaked a host path")
        }
        if (mode == WebUiMode.LEGACY) {
            val legacy = Json.parseToJsonElement(server.call("GET", "/api/jobs/${fixture.completed}", "application/json", cookie).body()).jsonObject
            assertEquals(setOf("id", "filename", "status", "created_at", "updated_at", "size_bytes", "metadata"), legacy.keys)
            assertEquals("complete", legacy.getValue("status").jsonPrimitive.content)
            // A D0 record without updated_at keeps its documented fallback, and entry_point stays numeric.
            assertEquals(legacy.getValue("created_at"), legacy.getValue("updated_at"))
            assertTrue(legacy.getValue("metadata").jsonObject.getValue("entry_point").jsonPrimitive.isString.not())
            val error = Json.parseToJsonElement(server.call("GET", "/api/jobs/${"0".repeat(32)}", "application/json", cookie).body()).jsonObject
            assertEquals(setOf("requestId", "error"), error.keys)
            assertEquals("JOB_NOT_FOUND", error.getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
        } else {
            val v1 = Json.parseToJsonElement(server.call("GET", "/api/v1/jobs/${fixture.completed}", "application/json", cookie).body())
                .jsonObject.getValue("data").jsonObject
            assertEquals(fixture.completed, v1.getValue("jobId").jsonPrimitive.content)
            assertEquals("completed", v1.getValue("status").jsonPrimitive.content)
            val interrupted = Json.parseToJsonElement(server.call("GET", "/api/v1/jobs/${fixture.interrupted}", "application/json", cookie).body())
                .jsonObject.getValue("data").jsonObject
            // The historical interruption is presented as such; no attempt identity is invented for it.
            assertEquals("interrupted", interrupted.getValue("status").jsonPrimitive.content)
            assertEquals(kotlinx.serialization.json.JsonNull, interrupted.getValue("latestRunId"))
            assertFalse(v1.toString().contains("binary_path") || v1.toString().contains("input.elf"))
        }
        // Explicit execution requests are not reachable by opening a link: the GET rows above were 404. In the SPA
        // presentation even a correctly authenticated POST to a legacy execution route is refused before any work.
        if (mode == WebUiMode.SPA) for (path in executionRoutes) {
            val response = server.call("POST", path.replace("{J}", fixture.completed), "*/*",
                session + mapOf("Origin" to server.origin, "Content-Type" to "application/json"))
            assertTrue(response.statusCode() in setOf(404, 405), "POST $path in SPA mode answered ${response.statusCode()}")
        }
        assertEquals(0, server.executions.get(), "a legacy route started work in $mode")
    }

    /** Files the upgrade may add. Nothing else may appear, and no existing byte may change. */
    private fun expectedAdditions(fixture: Fixture) = setOf(".web-owner.lock", ".workflow-owner.lock", "${fixture.interrupted}/workflow-state.json")

    @Test
    fun `every legacy route answers its documented migration outcome in both modes without starting work or writing`() {
        val fixture = retainedLegacyStore()
        for (mode in listOf(WebUiMode.LEGACY, WebUiMode.SPA)) {
            start(mode).use { server ->
                val upgraded = storageDigest()
                sweep(server, mode, fixture)
                assertEquals(upgraded, storageDigest(), "opening legacy links changed stored bytes in $mode")
            }
        }
    }

    @Test
    fun `upgrade restart and presentation rollback preserve every authoritative byte and add only schema-boundary files`() {
        val fixture = retainedLegacyStore()
        val original = storageDigest()
        val originalDirectories = directories()
        val backup = Files.createTempDirectory(Path.of("build"), "legacy-migration-backup")
        try {
            root.toFile().copyRecursively(backup.toFile())
            // Upgrade into the legacy presentation, restart into the SPA, restart again, then roll back to legacy.
            for (mode in listOf(WebUiMode.LEGACY, WebUiMode.SPA, WebUiMode.SPA, WebUiMode.LEGACY)) {
                start(mode).use { server -> sweep(server, mode, fixture) }
                val after = storageDigest()
                for ((path, digest) in original) assertEquals(digest, after[path], "$path changed after $mode lifecycle")
                assertEquals(expectedAdditions(fixture), after.keys - original.keys, "unexpected files after $mode lifecycle")
                assertEquals(originalDirectories, directories(), "the upgrade created or removed directories after $mode")
            }
            // The only job-scoped addition records the historical interruption without an invented attempt.
            val state = Json.parseToJsonElement(Files.readString(root.resolve(fixture.interrupted).resolve("workflow-state.json"))).jsonObject
            assertEquals(1, state.getValue("schemaVersion").jsonPrimitive.int)
            assertEquals(JsonArray(emptyList()), state.getValue("attempts"))
            val legacy = state.getValue("legacy").jsonObject
            assertEquals("analyzing", legacy.getValue("status").jsonPrimitive.content)
            assertTrue(legacy.getValue("recoveredInterrupted").jsonPrimitive.boolean)
            assertEquals(sha256(root.resolve(fixture.interrupted).resolve("job.json").readBytes()), legacy.getValue("originalJobSha256").jsonPrimitive.content)
            assertTrue(Files.size(root.resolve(".web-owner.lock")) == 0L && Files.size(root.resolve(".workflow-owner.lock")) == 0L)
            // Rollback to the pre-upgrade bytes is a stopped-server restore of the backup copy.
            root.toFile().deleteRecursively()
            backup.toFile().copyRecursively(root.toFile())
            assertEquals(original, storageDigest())
            start(WebUiMode.LEGACY).use { server -> sweep(server, WebUiMode.LEGACY, fixture) }
        } finally {
            backup.toFile().deleteRecursively()
        }
    }

    @Test
    fun `a damaged retained record refuses startup with actionable guidance and leaves every byte in place`() {
        val fixture = retainedLegacyStore()
        root.resolve(fixture.uploaded).resolve("job.json").writeText("{\"id\": \"truncated")
        val original = storageDigest()
        for (mode in listOf(WebUiMode.LEGACY, WebUiMode.SPA)) {
            val failure = assertFailsWith<Exception> { start(mode).close() }
            val guidance = assertNotNull(webStorageStartupGuidance(failure), "no guidance for ${failure::class.simpleName}: ${failure.message}")
            assertTrue(guidance.contains("CORRUPT_LEGACY_JOB"), guidance)
            assertTrue(guidance.contains("No recovery changes were applied"), guidance)
            assertTrue(guidance.contains("verified backup"), guidance)
            assertFalse(guidance.contains(root.toAbsolutePath().toString()) || guidance.contains("truncated"), guidance)
            val after = storageDigest()
            for ((path, digest) in original) assertEquals(digest, after[path], "$path changed by refused $mode startup")
            assertTrue((after.keys - original.keys).all { it.startsWith(".") && it.endsWith("-owner.lock") }, "refused startup wrote ${after.keys - original.keys}")
        }
    }

    @Test
    fun `real web contenders receive typed ownership guidance locally and through the launcher`() {
        retainedLegacyStore()
        start(WebUiMode.LEGACY).close()
        for (mode in WebUiMode.entries) {
            // Snapshot while stopped: closing any extra descriptor for a POSIX lock file can
            // release this process's lock. The observer must not invalidate the ownership tested.
            val original = storageDigest()
            start(mode).use { owner ->
                val failure = assertFailsWith<WebJobStoreOwnershipException> { start(mode).close() }
                assertEquals("OWNERSHIP_CONFLICT", failure.code)
                val guidance = assertNotNull(webStorageStartupGuidance(failure))
                assertTrue(guidance.contains("Another server owns this data directory"), guidance)
                assertFalse(guidance.contains(root.toAbsolutePath().toString()), guidance)
                // A matching message on an unrelated exception is not a storage classification.
                assertEquals(null, webStorageStartupGuidance(IllegalStateException(failure.message)))

                // A second JVM cannot see the local owners map: this exercises the actual file lock and
                // Main's refusal boundary, including the fixed stderr message and exit status.
                val process = ProcessBuilder(
                    Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                    "-XX:-UsePerfData", "-Djava.io.tmpdir=${System.getProperty("java.io.tmpdir")}",
                    "-cp", System.getProperty("java.class.path"), "decompengine.MainKt", "web",
                    "--host", "127.0.0.1", "--port", "0", "--ui", mode.name.lowercase(),
                    "--data-dir", root.toAbsolutePath().toString(),
                ).apply { environment().clear() }.start()
                try {
                    assertTrue(process.waitFor(60, TimeUnit.SECONDS), "$mode contender did not exit")
                    val stdout = process.inputStream.readNBytes(16 * 1024).decodeToString()
                    val stderr = process.errorStream.readNBytes(16 * 1024).decodeToString()
                    assertEquals(2, process.exitValue(), stderr)
                    assertEquals(guidance + System.lineSeparator(), stderr)
                    assertEquals("", stdout, "a refused contender advertised serving or a session link")
                    assertEquals(200, owner.call("GET", "/", headers = mapOf("Cookie" to
                        legacySessionHeaders(owner.server).getValue("Cookie"))).statusCode(), "the owner stopped serving")
                } finally {
                    if (process.isAlive) process.destroyForcibly().waitFor(10, TimeUnit.SECONDS)
                }
            }
            assertEquals(original, storageDigest(), "a refused contender changed storage")
        }
    }

    @Test
    fun `startup guidance keeps an uncertain recovery outcome hidden behind a web wrapper`() {
        val uncertain = decompengine.jobs.WorkflowStoreException("STARTUP_RECOVERY_INCOMPLETE",
            "Startup recovery did not finish; changes may have begun.", true,
            WebJobServiceException("STORE_DURABILITY_UNAVAILABLE", "durability"))
        // webStartupFailure reports durability failures through this wrapper while the cause stays uncertain.
        val wrapped = webStartupFailure(uncertain)
        assertTrue(wrapped is WebJobServiceException && wrapped.code == "STORE_DURABILITY_UNAVAILABLE")
        val guidance = assertNotNull(webStorageStartupGuidance(wrapped))
        assertTrue(guidance.contains("STORE_DURABILITY_UNAVAILABLE"), guidance)
        assertTrue(guidance.contains("Recovery changes may have begun"), guidance)
        assertFalse(guidance.contains("No recovery changes were applied"), guidance)
        val certain = assertNotNull(webStorageStartupGuidance(WebJobServiceException("STORE_DURABILITY_UNAVAILABLE", "durability",
            decompengine.jobs.WorkflowStoreException("STARTUP_RECOVERY_INCOMPLETE", "Startup recovery did not finish.", false))))
        assertTrue(certain.contains("No recovery changes were applied"), certain)
    }

    @Test
    fun `a newer workflow schema is refused on rollback instead of being rewritten`() {
        val fixture = retainedLegacyStore()
        start(WebUiMode.SPA).close()
        val state = root.resolve(fixture.interrupted).resolve("workflow-state.json")
        // Simulate storage written by a later release with a schema this build does not understand.
        val current = Files.readString(state)
        val version = Regex("\"schemaVersion\"\\s*:\\s*1\\b")
        assertTrue(version.containsMatchIn(current), current)
        state.writeText(current.replace(version, "\"schemaVersion\": 2"))
        val original = storageDigest()
        for (mode in listOf(WebUiMode.LEGACY, WebUiMode.SPA)) {
            val failure = assertFailsWith<Exception> { start(mode).close() }
            val guidance = assertNotNull(webStorageStartupGuidance(failure), "no guidance for ${failure::class.simpleName}: ${failure.message}")
            assertTrue(guidance.contains("UNSUPPORTED_WORKFLOW_SCHEMA"), guidance)
            assertTrue(guidance.contains("newer application"), guidance)
            assertEquals(original, storageDigest(), "refused $mode startup rewrote storage")
        }
    }

    @Test
    fun `migration never creates or invokes Git and leaves a surrounding user repository untouched`() {
        assertTrue(ProcessBuilder("git", "--version").start().waitFor(10, TimeUnit.SECONDS), "git is required for this check")
        val repository = Files.createTempDirectory(Path.of("build"), "legacy-migration-repository")
        try {
            fun git(vararg args: String): String {
                val process = ProcessBuilder(listOf("git", "-C", repository.toString(), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "-c", "commit.gpgsign=false", *args)).redirectErrorStream(true).start()
                val output = process.inputStream.bufferedReader().readText()
                assertTrue(process.waitFor(30, TimeUnit.SECONDS) && process.exitValue() == 0, "git ${args.joinToString(" ")}: $output")
                return output
            }
            git("init", "-q", "-b", "main")
            repository.resolve("README.md").writeText("user project\n")
            git("add", "README.md")
            git("commit", "-q", "-m", "user history")
            // The job store lives inside the user's working tree, as a careless --data-dir could place it.
            val data = repository.resolve("jobs")
            root.toFile().copyRecursively(data.toFile())
            val store = JobStore(data)
            val job = store.createFromUpload("non-git.elf", elfFixture())
            fun repositoryState() = listOf(git("rev-parse", "HEAD"), git("for-each-ref", "--format=%(refname) %(objectname)"),
                git("count-objects", "-v"), git("stash", "list"), git("config", "--local", "--list"))
            val before = repositoryState()
            val beforeIndex = repository.resolve(".git/index").readBytes()
            val beforeStatus = git("status", "--porcelain=v1", "--untracked-files=all")
            for (mode in listOf(WebUiMode.LEGACY, WebUiMode.SPA)) start(mode, data).use { server ->
                val cookie = mapOf("Cookie" to legacySessionHeaders(server.server).getValue("Cookie"))
                // The non-Git job stays fully usable without any Git attachment.
                assertEquals(200, server.call("GET", "/jobs/${job.id}", headers = cookie).statusCode())
                val api = if (mode == WebUiMode.LEGACY) "/api/jobs/${job.id}" else "/api/v1/jobs/${job.id}"
                assertEquals(200, server.call("GET", api, "application/json", cookie).statusCode())
                // Git routes are not part of this build; nothing answers as if a repository were attached.
                for (path in listOf("/jobs/${job.id}/git", "/api/v1/jobs/${job.id}/git", "/api/v1/jobs/${job.id}/git/status"))
                    assertEquals(404, server.call("GET", path, "application/json", cookie).statusCode(), path)
                assertEquals(0, server.executions.get())
            }
            assertEquals(before, repositoryState())
            assertTrue(beforeIndex.contentEquals(repository.resolve(".git/index").readBytes()), "the user index changed")
            // The only status difference is the job store's own lock files, which the user's repository sees as untracked.
            val added = git("status", "--porcelain=v1", "--untracked-files=all").lines().toSet() - beforeStatus.lines().toSet()
            assertTrue(added.all { it.startsWith("?? jobs/") && it.endsWith("-owner.lock") }, "unexpected repository changes: $added")
            Files.walk(data).use { paths -> assertTrue(paths.noneMatch { it.fileName.toString() == ".git" }, "a .git entry appeared in the job store") }
        } finally {
            repository.toFile().deleteRecursively()
        }
    }

    @Test
    fun `the published migration matrix matches the tested routes`() {
        val document = Files.readAllLines(Path.of("docs/web-legacy-migration.md"))
        val rows = document.filter { it.startsWith("| MIG-") }.associate { line ->
            val cells = line.split('|').map(String::trim)
            cells[1] to listOf(cells[2], cells[3], cells[4])
        }
        assertEquals(matrix.map { it.id }.toSet(), rows.keys, "document and test matrix rows differ")
        for (route in matrix) assertEquals(listOf("`${route.method} ${route.path}`", route.legacy.toString(), route.spa.toString()),
            rows.getValue(route.id), "document row ${route.id}")
    }
}
