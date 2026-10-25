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
                WorkflowTerminalReason.COMPLETED, WorkflowCandidate("revision_one", "a".repeat(64)))).attempt
            sourceTree = Files.createDirectories(root.resolve("${job.id}/reports/runs/${run.runId}/source-tree/src"))
            Files.writeString(sourceTree.resolve("main.c"), "int main(void) { return 0; }\n")
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
        val before = Files.readAllBytes(f.sourceTree.resolve("main.c"))
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
        assertContentEquals(before, Files.readAllBytes(f.sourceTree.resolve("main.c")))
        // The original key replays the original operation even though the job guard is unchanged or stale.
        val replay = f.send("POST", f.init("trunk"), f.headers("stale_job_version"))
        assertEquals(operation.getValue("operationId"), data(replay, 202, "operation")["operationId"])
        assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
        error(f.send("POST", f.init("other"), f.headers()), 409, "IDEMPOTENCY_CONFLICT")
        error(f.send("POST", f.init(), f.headers(key = "http_git_second_intent")), 409, "REPOSITORY_EXISTS")
        error(f.read("${f.collection}/repository_${"0".repeat(32)}"), 404, "NOT_FOUND")
        error(f.read("${f.collection}/${summary.getValue("repositoryId").jsonPrimitive.content}/operations/operation_${"0".repeat(32)}"), 404, "NOT_FOUND")
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
