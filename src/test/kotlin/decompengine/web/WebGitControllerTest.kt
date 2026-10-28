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

    private class Fixture(availability: GitAvailability = GitRuntime.detect(), audited: Boolean = false) : AutoCloseable {
        val root: Path = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/git").toAbsolutePath()), "web git http ")
        val store = JobStore(root)
        val job = store.createFromUpload("inert.elf", elfFixture())
        lateinit var owner: WorkflowAttemptStore
        val service = WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected analysis") }, JobReconstructor { _, _ -> error("Unexpected reconstruction") },
            attemptStoreFactory = { WorkflowAttemptStore.open(it).also { opened -> owner = opened } })
        val repositories = ManagedGitRepositories(root, availability, service::gitSourceSnapshot)
        val audit = if (audited) WebAuditLog(root) else null
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
                WebJobMutationBoundary(access, service), resources, audit = audit, git = WebGitCapability(availability, repositories))
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

    @Test fun `initialization and refused repository mutations appear in server and job audit exports`(): Unit = Fixture(audited = true).use { f ->
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

        fun repositoryMutations(target: String): List<JsonObject> {
            val export = data(f.read(target), 200, "supportExport")
            val audit = export.getValue("sections").jsonArray.map { it.jsonObject }
                .single { it.getValue("id").jsonPrimitive.content == "audit" }
                .getValue("content").jsonObject.getValue("entries").jsonArray
            return audit.map { it.jsonObject }.filter {
                it.getValue("action").jsonPrimitive.content == WebAuditAction.GIT_REPOSITORY_MUTATION.wireName
            }
        }
        val expectedOutcomes = listOf("accepted:202", "replayed:202", "rejected:409", "rejected:409").sorted()
        for (entries in listOf(
            repositoryMutations("/workbench/api/v1/support-export?scope=server"),
            repositoryMutations("/workbench/api/v1/support-export?scope=job&jobId=${f.job.id}"),
        )) {
            assertEquals(expectedOutcomes, entries.map {
                "${it.getValue("outcome").jsonPrimitive.content}:${it.getValue("status").jsonPrimitive.content}"
            }.sorted())
            assertTrue(entries.all {
                it.getValue("target").jsonObject.getValue("jobId").jsonPrimitive.content == f.job.id
            })
        }
    }

    /** Track directories too: empty runtime/staging directory changes are still writes. */
    private fun storageTree(root: Path): Map<String, List<Byte>?> = Files.walk(root).use { paths ->
        paths.toList().associate { path -> root.relativize(path).toString() to
            if (Files.isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) null else Files.readAllBytes(path).toList() }
    }

    @Test fun `Git GET routes leave fresh and published storage unchanged`(): Unit = Fixture().use { f ->
        val fresh = storageTree(f.root)
        data(f.read(), 200, "gitRepositories")
        error(f.read("${f.collection}/repository_missing"), 404, "NOT_FOUND")
        error(f.read("${f.collection}/repository_missing/operations/operation_missing"), 404, "NOT_FOUND")
        assertEquals(fresh, storageTree(f.root))
        assertFalse(Files.exists(f.root.resolve(".git-runtime")))
        val admitted = f.send("POST", f.init(), f.headers())
        val operation = data(admitted, 202, "operation")
        val location = admitted.headers().firstValue("Location").orElseThrow()
        assertEquals("completed", f.awaitOperation(location).getValue("state").jsonPrimitive.content)
        assertTrue(f.repositories.awaitIdle(5_000))
        val published = storageTree(f.root)
        repeat(2) {
            data(f.read(), 200, "gitRepositories")
            data(f.read("${f.collection}/${operation.getValue("repositoryId").jsonPrimitive.content}"), 200, "gitWorkspace")
            data(f.read(location), 200, "operation")
        }
        assertEquals(published, storageTree(f.root))
    }

    @Test fun `Git GET routes refuse failed startup recovery without changing retained storage`(): Unit = Fixture().use { f ->
        val operations = Files.createDirectories(f.root.resolve("${f.job.id}/git/operations"))
        Files.writeString(operations.resolve("operation_${"0".repeat(32)}.json"), "unreadable record")
        Files.createDirectories(f.root.resolve("${f.job.id}/git/staging/retained/empty/leaf"))
        f.repositories.recover(listOf(f.job.id))
        val before = storageTree(f.root)
        for (target in listOf(f.collection, "${f.collection}/repository_missing",
            "${f.collection}/repository_missing/operations/operation_missing")) {
            val response = f.read(target)
            error(response, 503, "STORAGE_UNAVAILABLE")
            assertFalse(response.body().contains(f.root.toString()))
        }
        assertEquals(before, storageTree(f.root))
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
