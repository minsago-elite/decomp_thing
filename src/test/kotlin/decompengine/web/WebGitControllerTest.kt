package decompengine.web

import com.sun.net.httpserver.HttpServer
import decompengine.git.GitAvailability
import decompengine.git.GitRuntime
import decompengine.git.ManagedGitRepositories
import decompengine.jobs.*
import kotlinx.serialization.json.*
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.*
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

/** Source inputs plus the manifest and schema-3 build contract a completed candidate retains. */
internal val SOURCES = mapOf("Makefile" to "all:\n\tcc -o app src/modules/unit.c\n", "src/modules/unit.c" to "int main(void) { return 0; }\n")

private fun sha256(bytes: ByteArray) = java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

internal fun recordedSourceDigest(files: Map<String, String>): String = sha256(files.toSortedMap().entries.joinToString("") { (path, text) ->
    "${path.length}:$path:${text.toByteArray().size}:${sha256(text.toByteArray())}\n" }.toByteArray())

internal fun recordSourceTree(tree: Path, input: ByteArray, files: Map<String, String>): Path {
    val profile = decompengine.project.GeneratedCMakeReconstructionProfile.descriptor
    files.forEach { (path, text) -> Files.createDirectories(tree.resolve(path).parent); Files.writeString(tree.resolve(path), text) }
    val evidence = files.keys.map { path ->
        val declaration = profile.layout.declarationForPath(path)
        decompengine.project.GeneratedFileEvidence(path, sha256(files.getValue(path).toByteArray()), "fixture",
            acceptedImplementation = if (decompengine.project.ProjectFileRole.MODULE_IMPLEMENTATION in declaration.roles) false else null,
            roles = declaration.roles, contentKind = declaration.contentKind)
    }
    Files.writeString(tree.resolve("source_tree_manifest.json"), decompengine.project.SourceTreeManifest(profileId = profile.id,
        profileSha256 = profile.sha256, inputSha256 = sha256(input), files = evidence, unresolvedEntityIds = emptyList()).toJson())
    Files.createDirectories(tree.resolve("reports"))
    Files.writeString(tree.resolve("reports/build_contract.json"), buildJsonObject {
        put("schemaVersion", 3); put("sourceRevisionSha256", recordedSourceDigest(files))
        put("sourceInputs", JsonArray(files.toSortedMap().map { (path, text) -> buildJsonObject {
            put("path", path); put("bytes", text.toByteArray().size); put("sha256", sha256(text.toByteArray()))
        } }))
        put("command", JsonArray(listOf(JsonPrimitive("make"))))
    }.toString())
    return tree
}

class WebGitControllerTest {
    private val schema = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/contract.schema.json")))
        .jsonObject.getValue("definitions").jsonObject

    private class Fixture(availability: GitAvailability = GitRuntime.detect()) : AutoCloseable {
        val root: Path = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/git").toAbsolutePath()), "web git http ")
        val store = JobStore(root)
        val job = store.createFromUpload("inert.elf", elfFixture())
        lateinit var owner: WorkflowAttemptStore
        val service = WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected analysis") }, JobReconstructor { _, _ -> error("Unexpected reconstruction") },
            attemptStoreFactory = { WorkflowAttemptStore.open(it).also { opened -> owner = opened } })
        val repositories = ManagedGitRepositories(root, availability, service::gitSourceSnapshot)
        val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin))
        val resources = WebStreamResources()
        val workers = Executors.newFixedThreadPool(2)
        val client: HttpClient = HttpClient.newHttpClient()
        val run: WorkflowAttempt
        val cookie: String
        val csrf: String
        val sourceTree: Path
        init {
            service.initializeExistingStorage()
            val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            val queued = owner.create(job.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
            val running = owner.transition(job.id, queued.runId, queued.version, WorkflowTransition.Start).attempt
            run = owner.transition(job.id, running.runId, running.version, WorkflowTransition.Finish(WorkflowRunState.COMPLETED,
                WorkflowTerminalReason.COMPLETED, WorkflowCandidate("revision_one", recordedSourceDigest(SOURCES)))).attempt
            sourceTree = recordSourceTree(root.resolve("${job.id}/reports/runs/${run.runId}/source-tree"), elfFixture(), SOURCES)
            val api = WebApiController(access, EmbeddedWebAssets.load(basePath = "/workbench/"), service,
                WebJobMutationBoundary(access, service), resources, git = WebGitCapability(availability, repositories))
            server.executor = workers; server.createContext("/") { check(api.route(it)) }; server.start()
            val token = access.issueBootstrap().token
            val session = send("POST", "{\"token\":\"$token\"}", mapOf("Origin" to origin, "Content-Type" to "application/json"), "/workbench/api/v1/session")
            check(session.statusCode() == 200)
            cookie = session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            csrf = Json.parseToJsonElement(session.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
        }
        val collection get() = "/workbench/api/v1/jobs/${job.id}/repositories"
        fun send(method: String = "GET", body: String? = null, headers: Map<String, String> = emptyMap(), target: String = collection): HttpResponse<String> {
            val b = HttpRequest.newBuilder(URI(origin + target)).timeout(Duration.ofSeconds(30)).method(method,
                body?.let(HttpRequest.BodyPublishers::ofString) ?: HttpRequest.BodyPublishers.noBody())
            b.header("Accept", "application/json"); headers.forEach { (k, v) -> b.header(k, v) }
            return client.send(b.build(), HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
        }
        fun read(target: String = collection) = send(headers = mapOf("Cookie" to cookie), target = target)
        fun jobVersion(): String = Json.parseToJsonElement(read("/workbench/api/v1/jobs/${job.id}").body()).jsonObject
            .getValue("data").jsonObject.getValue("version").jsonPrimitive.content
        fun headers(version: String = jobVersion(), key: String = "http_git_init_intent_1") = mapOf("Cookie" to cookie, "Origin" to origin,
            "Content-Type" to "application/json", "X-CSRF-Token" to csrf, "If-Match" to "\"$version\"", "Idempotency-Key" to key)
        fun init(branch: String? = null) = buildJsonObject {
            put("action", "git.init"); put("runId", run.runId); put("revisionId", "revision_one")
            put("initialBranch", branch?.let(::JsonPrimitive) ?: JsonNull)
        }.toString()
        override fun close() {
            repositories.close(); server.stop(0); resources.close(); workers.shutdownNow()
            check(workers.awaitTermination(5, TimeUnit.SECONDS)); client.close(); access.close(); service.close(); root.toFile().deleteRecursively()
        }
    }

    private fun data(response: HttpResponse<String>, status: Int, kind: String): JsonObject {
        assertEquals(status, response.statusCode(), response.body())
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow())
        val body = Json.parseToJsonElement(response.body()).jsonObject
        assertEquals(kind, body.getValue("kind").jsonPrimitive.content)
        val value = body.getValue("data").jsonObject
        assertEquals(schema.getValue(kind).jsonObject.getValue("properties").jsonObject.keys, value.keys, "DTO fields differ from the schema")
        return value
    }

    private fun error(response: HttpResponse<String>, status: Int, code: String? = null): JsonObject {
        assertEquals(status, response.statusCode(), response.body())
        val error = Json.parseToJsonElement(response.body()).jsonObject.getValue("error").jsonObject
        if (code != null) assertEquals(code, error.getValue("code").jsonPrimitive.content)
        return error
    }

    private fun Fixture.awaitOperation(location: String): JsonObject {
        val deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos()
        while (true) {
            val operation = data(read(location), 200, "operation")
            if (operation.getValue("state").jsonPrimitive.content !in setOf("queued", "running")) return operation
            check(System.nanoTime() < deadline) { "operation did not finish" }
            Thread.sleep(50)
        }
    }

    @Test fun `bootstrap reports Git availability and import configuration truthfully`(): Unit = Fixture().use { f ->
        val bootstrap = data(f.read("/workbench/api/v1/bootstrap"), 200, "bootstrap")
        val version = bootstrap.getValue("runtime").jsonObject.getValue("gitVersion").jsonPrimitive.content
        assertTrue(version.matches(Regex("[0-9]+\\.[0-9]+\\.[0-9]+")))
        val capabilities = bootstrap.getValue("capabilities").jsonArray.map { it.jsonObject }.associateBy { it.getValue("id").jsonPrimitive.content }
        assertEquals("supported", capabilities.getValue("git").getValue("state").jsonPrimitive.content)
        assertEquals("unavailable", capabilities.getValue("git-import").getValue("state").jsonPrimitive.content)
        assertEquals("GIT_IMPORT_UNCONFIGURED", capabilities.getValue("git-import").getValue("reasonCode").jsonPrimitive.content)
        assertFalse(bootstrap.toString().contains(f.root.toString()))
    }

    @Test fun `initialization is admitted once, published atomically and replayed without repetition`(): Unit = Fixture().use { f ->
        val empty = data(f.read(), 200, "gitRepositories")
        assertEquals(JsonArray(emptyList()), empty["repositories"]); assertEquals(JsonArray(emptyList()), empty["operations"])
        val before = Files.readAllBytes(f.sourceTree.resolve("src/modules/unit.c"))
        val version = f.jobVersion()
        val admitted = f.send("POST", f.init("trunk"), f.headers(version))
        val operation = data(admitted, 202, "operation")
        assertEquals("git.init", operation.getValue("action").jsonPrimitive.content)
        val location = admitted.headers().firstValue("Location").orElseThrow()
        assertEquals("${f.collection}/${operation.getValue("repositoryId").jsonPrimitive.content}/operations/${operation.getValue("operationId").jsonPrimitive.content}", location)
        val completed = f.awaitOperation(location)
        assertEquals("completed", completed.getValue("state").jsonPrimitive.content, completed.toString())
        assertEquals(JsonNull, completed["resultObjectId"]); assertEquals(JsonPrimitive(false), completed["recoveryRequired"])
        val listing = data(f.read(), 200, "gitRepositories")
        val summary = listing.getValue("repositories").jsonArray.single().jsonObject
        assertEquals(schema.getValue("gitRepositorySummary").jsonObject.getValue("properties").jsonObject.keys, summary.keys)
        assertEquals("initialized", summary.getValue("origin").jsonPrimitive.content)
        val workspaceResponse = f.read("${f.collection}/${summary.getValue("repositoryId").jsonPrimitive.content}")
        val workspace = data(workspaceResponse, 200, "gitWorkspace")
        assertEquals("unborn", workspace.getValue("headState").jsonPrimitive.content)
        assertEquals("refs/heads/trunk", workspace.getValue("headRefName").jsonPrimitive.content)
        assertEquals(JsonNull, workspace["headObjectId"]); assertEquals(JsonNull, workspace["headRefId"]); assertEquals(JsonNull, workspace["mapping"])
        assertEquals(JsonPrimitive(true), workspace["dirty"]); assertEquals("revision_one", workspace.getValue("candidateRevisionId").jsonPrimitive.content)
        assertEquals("source-only-v1", workspace.getValue("trackingPolicy").jsonPrimitive.content)
        assertEquals("\"${workspace.getValue("worktreeVersion").jsonPrimitive.content}\"", workspaceResponse.headers().firstValue("ETag").orElseThrow())
        for (body in listOf(admitted.body(), listing.toString(), workspace.toString())) assertFalse(body.contains(f.root.toString()))
        assertContentEquals(before, Files.readAllBytes(f.sourceTree.resolve("src/modules/unit.c")))
        // The original key replays the original operation even though the job guard is unchanged or stale.
        val replay = f.send("POST", f.init("trunk"), f.headers("stale_job_version"))
        assertEquals(operation.getValue("operationId"), data(replay, 202, "operation")["operationId"])
        assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
        error(f.send("POST", f.init("other"), f.headers()), 409, "IDEMPOTENCY_CONFLICT")
        error(f.send("POST", f.init(), f.headers(key = "http_git_second_intent")), 409, "REPOSITORY_EXISTS")
        error(f.read("${f.collection}/repository_${"0".repeat(32)}"), 404, "NOT_FOUND")
        error(f.read("${f.collection}/${summary.getValue("repositoryId").jsonPrimitive.content}/operations/operation_${"0".repeat(32)}"), 404, "NOT_FOUND")
    }

    /** Initialize through HTTP and return the repository path prefix and its on-disk directory. */
    private fun Fixture.initialized(): Pair<String, Path> {
        val admitted = send("POST", init(), headers())
        awaitOperation(admitted.headers().firstValue("Location").orElseThrow())
        val repositoryId = data(admitted, 202, "operation").getValue("repositoryId").jsonPrimitive.content
        return "$collection/$repositoryId" to root.resolve("${job.id}/git/repositories/$repositoryId")
    }

    @Test fun `status history diff and refs reads are bounded anchored and path-free`(): Unit = Fixture().use { f ->
        val (base, directory) = f.initialized()
        decompengine.git.GitTestRepositories().use { g ->
            val gitDir = directory.resolve("repository.git"); val workTree = directory.resolve("worktree")
            fun raw(vararg args: String) = g.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
            val unborn = data(f.read("$base/status"), 200, "gitStatus")
            assertEquals("unborn", unborn.getValue("headState").jsonPrimitive.content)
            assertTrue(unborn.getValue("notices").jsonArray.any { it.jsonObject.getValue("code").jsonPrimitive.content == "unborn" })
            val untracked = unborn.getValue("entries").jsonArray.map { it.jsonObject }
            assertTrue(untracked.single { it.getValue("path").jsonPrimitive.content == "src/modules/unit.c" }.getValue("untracked").jsonPrimitive.content.toBoolean())
            assertEquals(schema.getValue("gitStatusEntry").jsonObject.getValue("properties").jsonObject.keys, untracked.first().keys)
            raw("add", "-A"); raw("commit", "-q", "-m", "first")
            repeat(3) { index -> Files.writeString(workTree.resolve("src/n$index.c"), "int n$index;\n"); raw("add", "-A"); raw("commit", "-q", "-m", "c$index") }
            Files.writeString(workTree.resolve("src/modules/unit.c"), "int main(void) { return 2; }\n")
            Files.writeString(workTree.resolve("src/untracked.c"), "int untracked;\n")
            val status = data(f.read("$base/status?limit=1"), 200, "gitStatus")
            assertEquals("attached", status.getValue("headState").jsonPrimitive.content)
            val entry = status.getValue("entries").jsonArray.single().jsonObject
            assertEquals("modified", entry.getValue("unstaged").jsonPrimitive.content)
            val history = data(f.read("$base/history?limit=2"), 200, "gitHistory")
            assertEquals(2, history.getValue("entries").jsonArray.size)
            val cursor = history.getValue("nextCursor").jsonPrimitive.content
            val head = history.getValue("startObjectId").jsonPrimitive.content
            assertEquals(40, head.length)
            val second = data(f.read("$base/history?cursor=$cursor&limit=2"), 200, "gitHistory")
            assertEquals(2, second.getValue("entries").jsonArray.size); assertEquals(JsonNull, second["nextCursor"])
            assertEquals(JsonNull, second.getValue("entries").jsonArray.first().jsonObject["mapping"])
            val diff = data(f.read("$base/diff?scope=unstaged"), 200, "gitDiff")
            val file = diff.getValue("files").jsonArray.single().jsonObject
            val patch = data(f.read("$base/diff?scope=unstaged&file=${file.getValue("fileId").jsonPrimitive.content}"), 200, "gitDiff")
            assertTrue(patch.getValue("patch").jsonObject.getValue("text").jsonPrimitive.content.contains("return 2"))
            val commitDiff = data(f.read("$base/diff?scope=commit&commit=$head"), 200, "gitDiff")
            assertEquals("src/n2.c", commitDiff.getValue("files").jsonArray.single().jsonObject.getValue("path").jsonPrimitive.content)
            val refs = data(f.read("$base/refs"), 200, "gitRefs")
            assertTrue(refs.getValue("refs").jsonArray.single().jsonObject.getValue("current").jsonPrimitive.content.toBoolean())
            for (body in listOf(status, history, diff, refs)) assertFalse(body.toString().contains(f.root.toString()))
            // A refs continuation is bound to the listing before it: a ref created or deleted
            // ahead of the offset refuses the page instead of repeating or skipping an entry.
            raw("branch", "b"); raw("branch", "c")
            val firstRefs = data(f.read("$base/refs?limit=1"), 200, "gitRefs")
            assertEquals(listOf("refs/heads/b"), firstRefs.getValue("refs").jsonArray.map { it.jsonObject.getValue("displayName").jsonPrimitive.content })
            val refsCursor = firstRefs.getValue("nextCursor").jsonPrimitive.content
            val nextRefs = data(f.read("$base/refs?limit=1&cursor=$refsCursor"), 200, "gitRefs")
            assertEquals(listOf("refs/heads/c"), nextRefs.getValue("refs").jsonArray.map { it.jsonObject.getValue("displayName").jsonPrimitive.content })
            raw("branch", "a")
            error(f.read("$base/refs?limit=1&cursor=$refsCursor"), 409, "REF_CHANGED")
            val restarted = data(f.read("$base/refs?limit=1"), 200, "gitRefs").getValue("nextCursor").jsonPrimitive.content
            raw("branch", "-D", "a")
            error(f.read("$base/refs?limit=1&cursor=$restarted"), 409, "REF_CHANGED")
            error(f.read("$base/refs?cursor=refs~1"), 400, "INVALID_CURSOR")
            // Syntactically plausible cursors must not reach the reader's require(skip) as 500s.
            for (offset in listOf("100001", "999999")) {
                error(f.read("$base/refs?cursor=refs~${"a".repeat(32)}~$offset"), 400, "INVALID_CURSOR")
            }
            raw("branch", "-D", "b"); raw("branch", "-D", "c")
            // A status page cursor is bound to the work-tree version it was taken from.
            val statusCursor = data(f.read("$base/status?limit=1"), 200, "gitStatus").getValue("nextCursor")
            Files.writeString(workTree.resolve("src/extra.c"), "int extra;\n")
            error(f.read("$base/status?cursor=${statusCursor!!.jsonPrimitive.content}"), 409, "REF_CHANGED")
            // Ignored files never change the work-tree version, but they do end a status page walk.
            val ignoredCursor = data(f.read("$base/status?limit=1"), 200, "gitStatus").getValue("nextCursor").jsonPrimitive.content
            Files.writeString(workTree.resolve("aaa.log"), "noise\n")
            error(f.read("$base/status?cursor=$ignoredCursor"), 409, "REF_CHANGED")
            error(f.read("$base/history?start=${head.take(12)}"), 422, "VALIDATION_FAILED")
            error(f.read("$base/history?start=$head&cursor=$cursor"), 400, "INVALID_CURSOR")
            for (offset in listOf("1000001", "9999999")) {
                error(f.read("$base/history?cursor=$head~$offset"), 400, "INVALID_CURSOR")
            }
            error(f.read("$base/history?start=${"0".repeat(40)}"), 404, "NOT_FOUND")
            error(f.read("$base/diff?scope=commit"), 422, "VALIDATION_FAILED")
            error(f.read("$base/diff?scope=staged&commit=$head"), 422, "VALIDATION_FAILED")
            error(f.read("$base/diff?scope=unstaged&file=file_${"0".repeat(32)}"), 404, "NOT_FOUND")
            error(f.read("$base/status?path=/etc"), 400, "VALIDATION_FAILED")
            error(f.read("$base/status?limit=0"), 422, "VALIDATION_FAILED")
            error(f.read("$base/status?limit=1&limit=2"), 400, "VALIDATION_FAILED")
        }
    }

    @Test fun `directory replacements keep workspace status and diff pages usable`(): Unit = Fixture().use { f ->
        val (base, directory) = f.initialized()
        decompengine.git.GitTestRepositories().use { g ->
            val gitDir = directory.resolve("repository.git"); val workTree = directory.resolve("worktree")
            fun raw(vararg args: String) = g.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
            val component = Files.createDirectories(workTree.resolve("component.c"))
            for (name in listOf("a.c", "b.c")) Files.writeString(component.resolve(name), "int original_child_$name;\n")
            raw("add", "-A"); raw("commit", "-q", "-m", "base")
            Files.delete(component.resolve("a.c")); Files.delete(component.resolve("b.c")); Files.delete(component)
            Files.writeString(component, "int replacement;\n")
            for (scope in listOf("unstaged", "staged")) {
                if (scope == "staged") raw("add", "-A")
                val workspace = data(f.read(base), 200, "gitWorkspace")
                assertEquals(JsonPrimitive(true), workspace["dirty"])
                val status = data(f.read("$base/status"), 200, "gitStatus")
                val entries = status.getValue("entries").jsonArray.map { it.jsonObject }
                assertEquals("deleted", entries.single { it.getValue("path").jsonPrimitive.content == "component.c/a.c" }
                    .getValue(scope).jsonPrimitive.content)
                val firstStatus = data(f.read("$base/status?limit=1"), 200, "gitStatus")
                val statusCursor = firstStatus.getValue("nextCursor").jsonPrimitive.content
                data(f.read("$base/status?limit=1&cursor=$statusCursor"), 200, "gitStatus")
                val firstDiff = data(f.read("$base/diff?scope=$scope&limit=1"), 200, "gitDiff")
                val diffCursor = firstDiff.getValue("nextCursor").jsonPrimitive.content
                data(f.read("$base/diff?scope=$scope&limit=1&cursor=$diffCursor"), 200, "gitDiff")
                val diff = data(f.read("$base/diff?scope=$scope"), 200, "gitDiff")
                val deleted = diff.getValue("files").jsonArray.map { it.jsonObject }
                    .single { it.getValue("path").jsonPrimitive.content == "component.c/a.c" }
                val patch = data(f.read("$base/diff?scope=$scope&file=${deleted.getValue("fileId").jsonPrimitive.content}"), 200, "gitDiff")
                    .getValue("patch").jsonObject
                assertTrue(patch.getValue("text").jsonPrimitive.content.contains("-int original_child_a.c;"))
                assertEquals(JsonPrimitive(false), patch["truncated"])
                Files.writeString(component, "int replacement_changed_for_$scope;\n")
                error(f.read("$base/status?limit=1&cursor=$statusCursor"), 409, "REF_CHANGED")
                error(f.read("$base/diff?scope=$scope&limit=1&cursor=$diffCursor"), 409, "REF_CHANGED")
                assertNotEquals(workspace.getValue("worktreeVersion"), data(f.read(base), 200, "gitWorkspace").getValue("worktreeVersion"))
            }
        }
    }

    @Test fun `history HTTP retains every parent of a 65-parent commit`(): Unit = Fixture().use { f ->
        val (base, directory) = f.initialized()
        decompengine.git.GitTestRepositories().use { g ->
            val gitDir = directory.resolve("repository.git"); val workTree = directory.resolve("worktree")
            fun raw(vararg args: String) = g.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree).trim()
            raw("add", "-A"); raw("commit", "-q", "-m", "base")
            val tree = raw("rev-parse", "HEAD^{tree}")
            val parents = (1..65).map { raw("commit-tree", tree, "-m", "parent $it") }
            val merge = raw("commit-tree", tree, *parents.flatMap { listOf("-p", it) }.toTypedArray(), "-m", "65 parents")
            val history = data(f.read("$base/history?start=$merge&limit=1"), 200, "gitHistory")
            val entry = history.getValue("entries").jsonArray.single().jsonObject
            assertEquals(parents, entry.getValue("parentObjectIds").jsonArray.map { it.jsonPrimitive.content })
            assertEquals(3200, schema.getValue("gitCommitSummary").jsonObject.getValue("properties").jsonObject
                .getValue("parentObjectIds").jsonObject.getValue("maxItems").jsonPrimitive.int)
        }
    }

    @Test fun `native filename re-edits invalidate status and diff cursors`(): Unit = Fixture().use { f ->
        val (base, directory) = f.initialized()
        decompengine.git.GitTestRepositories().use { g ->
            val gitDir = directory.resolve("repository.git"); val workTree = directory.resolve("worktree")
            fun raw(vararg args: String) = g.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
            val native = Path.of(URI(workTree.toUri().toASCIIString() + "a%FF.c"))
            Files.writeString(native, "int base;\n")
            Files.writeString(workTree.resolve("z.c"), "int base;\n")
            raw("add", "-A"); raw("commit", "-q", "-m", "base")
            Files.writeString(native, "int first;\n")
            Files.writeString(workTree.resolve("z.c"), "int first;\n")
            val status = data(f.read("$base/status?limit=1"), 200, "gitStatus")
            val diff = data(f.read("$base/diff?scope=unstaged&limit=1"), 200, "gitDiff")
            val statusCursor = status.getValue("nextCursor").jsonPrimitive.content
            val diffCursor = diff.getValue("nextCursor").jsonPrimitive.content
            val beforeVersion = status.getValue("worktreeVersion")
            Files.writeString(native, "int second;\nint more;\n")
            error(f.read("$base/status?cursor=$statusCursor&limit=1"), 409, "REF_CHANGED")
            error(f.read("$base/diff?scope=unstaged&cursor=$diffCursor&limit=1"), 409, "REF_CHANGED")
            val refreshed = data(f.read("$base/status?limit=1"), 200, "gitStatus")
            assertNotEquals(beforeVersion, refreshed.getValue("worktreeVersion"))
            assertEquals(status.getValue("entries").jsonArray.single().jsonObject.getValue("fileId"),
                refreshed.getValue("entries").jsonArray.single().jsonObject.getValue("fileId"))
        }
    }

    @Test fun `initial branch bounds count Unicode code points through HTTP`(): Unit = Fixture().use { f ->
        val branch = List(4) { "🚀".repeat(49) }.joinToString("/") + "x"
        assertEquals(200, branch.codePointCount(0, branch.length))
        assertTrue(branch.length > 200)
        error(f.send("POST", f.init(branch + "x"), f.headers()), 422, "VALIDATION_FAILED")
        assertEquals(JsonArray(emptyList()), data(f.read(), 200, "gitRepositories")["operations"])
        val admitted = f.send("POST", f.init(branch), f.headers())
        val operation = data(admitted, 202, "operation")
        val completed = f.awaitOperation(admitted.headers().firstValue("Location").orElseThrow())
        assertEquals("completed", completed.getValue("state").jsonPrimitive.content, completed.toString())
        val workspace = data(f.read("${f.collection}/${operation.getValue("repositoryId").jsonPrimitive.content}"), 200, "gitWorkspace")
        assertEquals("refs/heads/$branch", workspace.getValue("headRefName").jsonPrimitive.content)
    }

    @Test fun `authorization guards and strict bodies precede any repository operation`(): Unit = Fixture().use { f ->
        val body = f.init()
        error(f.send(), 401)
        error(f.send("POST", body, f.headers() - "Cookie"), 401)
        error(f.send("POST", body, f.headers() - "X-CSRF-Token"), 403)
        error(f.send("POST", body, f.headers() + ("Origin" to "http://foreign.invalid")), 403)
        error(f.send("POST", body, f.headers() + ("Content-Type" to "text/plain")), 415)
        error(f.send("POST", body, f.headers() - "If-Match"), 428, "PRECONDITION_REQUIRED")
        error(f.send("POST", body, f.headers() + ("If-Match" to "*")), 400)
        error(f.send("POST", body, f.headers(version = "stale_job_version")), 412, "VERSION_CONFLICT")
        error(f.send("POST", body, f.headers() - "Idempotency-Key"), 400, "INVALID_IDEMPOTENCY_KEY")
        error(f.send("POST", body, f.headers(), "${f.collection}?path=/etc"), 400)
        error(f.send("POST", "{", f.headers()), 400, "MALFORMED_JSON")
        error(f.send("POST", " ".repeat(2049), f.headers()), 413)
        for (invalid in listOf("{}", "{\"action\":\"git.clone\"}", body.replace("}", ",\"path\":\"/etc\"}"),
            "{\"action\":\"git.init\",\"runId\":\"../x\",\"revisionId\":\"revision_one\",\"initialBranch\":null}",
            "{\"action\":\"git.attach\",\"sourceName\":\"../escape\"}", "{\"action\":\"git.attach\",\"sourceName\":\"/etc\"}")) {
            error(f.send("POST", invalid, f.headers()), 422, "VALIDATION_FAILED")
        }
        error(f.send("POST", f.init("a..b"), f.headers()), 422, "VALIDATION_FAILED")
        // Strings up to their declared bounds reach field validation instead of failing JSON limits.
        error(f.send("POST", f.init("功".repeat(201)), f.headers()), 422, "VALIDATION_FAILED")
        error(f.send("POST", "{\"action\":\"git.attach\",\"sourceName\":\"${"a".repeat(129)}\"}", f.headers()), 422, "VALIDATION_FAILED")
        error(f.send("POST", "{\"action\":\"git.attach\",\"sourceName\":\"${"a".repeat(128)}\"}", f.headers()), 503, "CAPABILITY_UNAVAILABLE")
        error(f.send("POST", body.replace("revision_one", "revision_other"), f.headers()), 422, "SOURCE_REVISION_UNAVAILABLE")
        error(f.send("POST", "{\"action\":\"git.attach\",\"sourceName\":\"anything\"}", f.headers()), 503, "CAPABILITY_UNAVAILABLE")
        error(f.send("PUT", body, f.headers()), 405)
        error(f.send("POST", body, f.headers(), f.collection.replace(f.job.id, "f".repeat(32))), 404)
        error(f.send(headers = mapOf("Cookie" to f.cookie, "If-Match" to "\"x\"")), 400)
        assertEquals(JsonArray(emptyList()), data(f.read(), 200, "gitRepositories")["operations"])
        assertFalse(Files.exists(f.root.resolve("${f.job.id}/git/repositories")))
    }

    @Test fun `every Git route answers explicitly when Git is unusable`(): Unit =
        Fixture(GitAvailability.Unavailable("GIT_NOT_FOUND", "Git is not installed or not executable on the server.")).use { f ->
            val bootstrap = data(f.read("/workbench/api/v1/bootstrap"), 200, "bootstrap")
            assertEquals(JsonNull, bootstrap.getValue("runtime").jsonObject["gitVersion"])
            val git = bootstrap.getValue("capabilities").jsonArray.map { it.jsonObject }.single { it.getValue("id").jsonPrimitive.content == "git" }
            assertEquals("unavailable", git.getValue("state").jsonPrimitive.content)
            assertEquals("GIT_NOT_FOUND", git.getValue("reasonCode").jsonPrimitive.content)
            for (response in listOf(f.read(), f.read("${f.collection}/repository_${"0".repeat(32)}"),
                f.read("${f.collection}/repository_${"0".repeat(32)}/operations/operation_${"0".repeat(32)}"),
                f.send("POST", f.init(), f.headers()))) {
                assertTrue(error(response, 503, "CAPABILITY_UNAVAILABLE").getValue("message").jsonPrimitive.content.contains("not installed"))
            }
            assertFalse(Files.exists(f.root.resolve("${f.job.id}/git")))
        }
}
