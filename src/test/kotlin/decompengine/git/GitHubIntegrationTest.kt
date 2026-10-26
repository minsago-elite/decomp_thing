package decompengine.git

import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.net.InetSocketAddress
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Optional GitHub capability (#602, #603, #612) against a loopback fake with the shape of
 * scripts/web-github-fixture.mjs. No network, no real credential.
 */
class GitHubIntegrationTest {
    private val jobId = "0123456789abcdef0123456789abcdef"
    private val token = "fixture-only-token"

    /** Pull-request API of one repository; every recorded request omits headers and bodies. */
    private class FakeGitHub(private val token: String) : AutoCloseable {
        val pulls = mutableListOf<kotlinx.serialization.json.JsonObject>()
        val shas = mutableMapOf<String, String>()
        val requests = mutableListOf<String>()
        @Volatile var rateLimited = false
        @Volatile var dropAfterCreate = false
        /** Record the pull request but answer creation with a body the client cannot read. */
        @Volatile var malformedCreate = false
        /** Answer creation with a server error without creating anything. */
        @Volatile var failCreate = false
        /** Send listing headers and part of a body, then stall. */
        @Volatile var stallBody = false
        /** Report a duplicate the way GitHub often does: a `custom` error with a message. */
        @Volatile var customDuplicate = false
        /** Appended to every created pull request's link. */
        @Volatile var urlSuffix = ""
        private val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 8)
        init {
            server.createContext("/repos/fixture-owner/fixture-repo/pulls") { exchange ->
                requests += "${exchange.requestMethod} ${exchange.requestURI}"
                fun reply(status: Int, body: String, headers: Map<String, String> = emptyMap()) {
                    headers.forEach { (k, v) -> exchange.responseHeaders.set(k, v) }
                    val bytes = body.toByteArray(); exchange.sendResponseHeaders(status, bytes.size.toLong()); exchange.responseBody.use { it.write(bytes) }
                }
                val authorization = exchange.requestHeaders.getFirst("Authorization")
                when {
                    stallBody -> {
                        exchange.sendResponseHeaders(200, 0)
                        exchange.responseBody.write("[".toByteArray()); exchange.responseBody.flush()
                        try { Thread.sleep(3_000) } catch (_: InterruptedException) { }
                    }
                    rateLimited -> reply(403, "{\"message\":\"rate limited\"}", mapOf("X-RateLimit-Remaining" to "0", "Retry-After" to "60"))
                    authorization != null && authorization != "Bearer $token" -> reply(401, "{\"message\":\"bad credential\"}")
                    exchange.requestMethod == "GET" -> {
                        val query = exchange.requestURI.rawQuery.orEmpty().split('&').associate { it.substringBefore('=') to java.net.URLDecoder.decode(it.substringAfter('='), Charsets.UTF_8) }
                        val matching = pulls.filter { pull ->
                            (query["head"] == null || query["head"] == "fixture-owner:" + pull.getValue("head").jsonObject.getValue("ref").jsonPrimitive.content) &&
                                (query["base"] == null || query["base"] == pull.getValue("base").jsonObject.getValue("ref").jsonPrimitive.content)
                        }
                        val size = query["per_page"]?.toInt() ?: 30
                        val page = query["page"]?.toInt() ?: 1
                        val next = if (matching.size > page * size) mapOf("Link" to "<$url${exchange.requestURI.path}?page=${page + 1}>; rel=\"next\"") else emptyMap()
                        reply(200, JsonArray(matching.drop((page - 1) * size).take(size)).toString(), next)
                    }
                    exchange.requestMethod == "POST" && authorization == null -> reply(401, "{\"message\":\"Fixture credential required\"}")
                    else -> {
                        val input = Json.parseToJsonElement(exchange.requestBody.readBytes().toString(Charsets.UTF_8)).jsonObject
                        val head = input.getValue("head").jsonPrimitive.content; val base = input.getValue("base").jsonPrimitive.content
                        if (failCreate) { reply(502, "{\"message\":\"bad gateway\"}"); exchange.close(); return@createContext }
                        if (customDuplicate) {
                            reply(422, "{\"message\":\"Validation Failed\",\"errors\":[{\"resource\":\"PullRequest\",\"code\":\"custom\"," +
                                "\"message\":\"A pull request already exists for fixture-owner:$head.\"}]}")
                            exchange.close(); return@createContext
                        }
                        if (pulls.any { it.getValue("state").jsonPrimitive.content == "open" && it.getValue("head").jsonObject.getValue("ref").jsonPrimitive.content == head &&
                                it.getValue("base").jsonObject.getValue("ref").jsonPrimitive.content == base }) {
                            reply(422, "{\"message\":\"exists\",\"errors\":[{\"code\":\"already_exists\"}]}")
                        } else {
                            val number = pulls.size + 1
                            val pull = buildJsonObject {
                                put("number", number); put("state", "open"); put("title", input.getValue("title").jsonPrimitive.content)
                                put("html_url", "https://fixture.invalid/fixture-owner/fixture-repo/pull/$number$urlSuffix")
                                put("body", input.getValue("body").jsonPrimitive.content)
                                put("head", buildJsonObject { put("ref", head); shas[head]?.let { put("sha", it) } })
                                put("base", buildJsonObject { put("ref", base) })
                            }
                            pulls += pull
                            if (dropAfterCreate) { exchange.close(); return@createContext }
                            if (malformedCreate) { reply(201, "{\"number\":\"one\"}"); exchange.close(); return@createContext }
                            reply(201, pull.toString())
                        }
                    }
                }
                exchange.close()
            }
            server.start()
        }
        val url: URI get() = URI("http://127.0.0.1:${server.address.port}")
        override fun close() = server.stop(0)
    }

    private class Fixture(val repositories: GitTestRepositories = GitTestRepositories()) : AutoCloseable {
        val store: Path = Files.createDirectories(repositories.root.resolve("store"))
        val admitted: Path = Files.createDirectories(repositories.root.resolve("admitted")).toRealPath()
        val seed: Path = Files.createDirectories(repositories.root.resolve("seed"))
        val bare: Path = admitted.resolve("upstream.git")
        var hook: (GitOperationCrashPoint) -> Unit = {}
        private val opened = mutableListOf<ManagedGitRepositories>()
        init {
            Files.createDirectories(store.resolve("0123456789abcdef0123456789abcdef"))
            repositories.git("init", "-q", "--bare", "--initial-branch=main", bare.toString())
            repositories.git("init", "-q", "--initial-branch=main", seed.toString())
            Files.writeString(seed.resolve("README.md"), "remote\n")
            repositories.git("-C", seed.toString(), "add", "-A"); repositories.git("-C", seed.toString(), "commit", "-q", "-m", "base")
            repositories.git("-C", seed.toString(), "checkout", "-q", "-b", "feature")
            Files.writeString(seed.resolve("feature.c"), "int feature;\n")
            repositories.git("-C", seed.toString(), "add", "-A"); repositories.git("-C", seed.toString(), "commit", "-q", "-m", "feature")
            repositories.git("-C", seed.toString(), "push", "-q", bare.toString(), "main", "feature")
        }
        fun featureTip() = repositories.git("-C", seed.toString(), "rev-parse", "feature").trim()
        fun open(github: GitHubConfiguration?) = ManagedGitRepositories(store, GitRuntime.detect(), { _, _, _ -> error("no snapshots") },
            policy = GitRepositoryPolicy(defaultBranch = "main"), crash = { hook(it) },
            remotePolicy = GitRemotePolicy(admittedRoot = admitted), github = github).also(opened::add)
        override fun close() { opened.forEach { it.close() }; repositories.close() }
    }

    private lateinit var service: ManagedGitRepositories
    private lateinit var repositoryId: String
    private var keys = 0
    private fun key() = "github_key_${(++keys).toString().padStart(8, '0')}"

    private fun Fixture.cloned(github: GitHubConfiguration?) {
        service = open(github)
        val admission = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", null), "clone_key_${keys++}_000000")
        assertTrue(service.awaitIdle(60_000)); repositoryId = admission.operation.repositoryId
    }

    private fun remoteId() = service.remotes(jobId, repositoryId).single().record.remoteId

    private fun create(title: String = "Review the feature"): GitSyncRequest {
        val view = service.workspace(jobId, repositoryId)
        val guards = GitGuards(GitWorkspaceVersions.repositoryVersion(view.record, view.observation), GitWorkspaceVersions.worktreeVersion(view.observation),
            view.observation.head.objectId, null, null)
        val tracking = service.remotes(jobId, repositoryId).single().tracking.associate { it.name to it.objectId }
        return GitSyncRequest(GitOperationAction.GITHUB_PR_CREATE, view.worktreeId, guards, mapOf("remoteId" to remoteId(), "headBranch" to "feature",
            "headObjectId" to tracking["refs/remotes/origin/feature"], "baseBranch" to "main", "baseObjectId" to tracking["refs/remotes/origin/main"],
            "title" to title), "Synthetic review body.")
    }

    private fun run(request: GitRepositoryRequest): GitOperationRecord {
        val admission = service.requestWorkspace(jobId, repositoryId, request, key())
        assertTrue(service.awaitIdle(60_000))
        return service.operation(jobId, repositoryId, admission.operation.operationId)
    }

    private fun configuration(fake: FakeGitHub, root: Path, writable: Boolean): GitHubConfiguration {
        val file = root.resolve("github-token").also { Files.writeString(it, "$token\n") }
        return GitHubConfiguration(fake.url, file.takeIf { writable }, listOf(GitHubBinding("admitted:upstream.git", "fixture-owner", "fixture-repo")))
    }

    @Test fun `local Git and remotes stay usable without the integration, and read-only never writes`(): Unit = Fixture().use { f ->
        f.cloned(null)
        val absent = service.githubStatus(jobId, repositoryId, null, remoteId(), "feature")
        assertEquals("unavailable", absent.access)
        assertEquals(f.featureTip(), absent.pushedObjectId)
        assertEquals("GITHUB_UNAVAILABLE", assertFailsWith<ManagedGitException> { service.requestWorkspace(jobId, repositoryId, create(), key()) }.code)
        FakeGitHub(token).use { fake ->
            service = f.open(configuration(fake, f.repositories.root, writable = false))
            val readOnly = service.githubStatus(jobId, repositoryId, null, remoteId(), "feature")
            assertEquals("read-only", readOnly.access); assertTrue(readOnly.pulls.isEmpty()); assertNull(readOnly.problem)
            assertEquals("GITHUB_READ_ONLY", assertFailsWith<ManagedGitException> { service.requestWorkspace(jobId, repositoryId, create(), key()) }.code)
            assertTrue(fake.requests.none { it.startsWith("POST") })
            fake.rateLimited = true
            val limited = service.githubStatus(jobId, repositoryId, null, remoteId(), "feature")
            assertEquals("GITHUB_RATE_LIMITED", limited.problem?.code); assertEquals(60L, limited.problem?.retryAfterSeconds)
        }
    }

    @Test fun `pull requests are created explicitly, tied to the pushed commit, and duplicates reconcile`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            fake.shas["feature"] = f.featureTip()
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            assertEquals("BRANCH_NOT_PUBLISHED", assertFailsWith<ManagedGitException> {
                service.requestWorkspace(jobId, repositoryId, create().let { it.copy(parameters = it.parameters + ("headBranch" to "unpushed")) }, key())
            }.code)
            assertTrue(fake.pulls.isEmpty(), "viewing or refusing never writes")
            val created = run(create())
            assertEquals(GitOperationState.COMPLETED, created.state, created.message)
            assertTrue(created.message.contains("#1") && created.message.contains("not build or reconstruction acceptance"))
            val status = service.githubStatus(jobId, repositoryId, null, remoteId(), "feature")
            val pull = status.pulls.single()
            assertEquals("feature", pull.headRef); assertEquals("main", pull.baseRef); assertEquals(status.pushedObjectId, pull.headSha)
            val again = run(create())
            assertEquals(GitOperationState.COMPLETED, again.state, again.message)
            assertTrue(again.message.contains("already existed"))
            assertEquals(1, fake.pulls.size)
            // The credential is never stored, audited or echoed.
            Files.walk(f.store).use { paths -> paths.filter { Files.isRegularFile(it) }.forEach { file ->
                assertFalse(Files.readAllBytes(file).toString(Charsets.ISO_8859_1).contains(token), file.toString())
            } }
            assertFalse(fake.requests.any { it.contains(token) })
        }
    }

    @Test fun `an uncertain creation is reconciled instead of repeated`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            fake.dropAfterCreate = true
            val uncertain = run(create())
            assertEquals(GitOperationState.RECOVERY_REQUIRED, uncertain.state, uncertain.message)
            assertEquals("PR_UNCONFIRMED", uncertain.failureCode)
            assertEquals("PR_UNCONFIRMED", assertFailsWith<ManagedGitException> { service.requestWorkspace(jobId, repositoryId, create(), key()) }.code)
            fake.dropAfterCreate = false
            val view = service.workspace(jobId, repositoryId)
            val guards = GitGuards(GitWorkspaceVersions.repositoryVersion(view.record, view.observation), GitWorkspaceVersions.worktreeVersion(view.observation),
                view.observation.head.objectId, null, null)
            val reconciled = run(GitSyncRequest(GitOperationAction.GITHUB_PR_RECONCILE, view.worktreeId, guards, mapOf("prOperationId" to uncertain.operationId)))
            assertEquals(GitOperationState.COMPLETED, reconciled.state, reconciled.message)
            val settled = service.operation(jobId, repositoryId, uncertain.operationId)
            assertEquals(GitOperationState.COMPLETED, settled.state, settled.message)
            assertEquals(1, fake.pulls.size)
            assertNotNull(service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").pulls.singleOrNull())
            assertTrue(service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").unconfirmed.isEmpty())
        }
    }

    private fun reconciliation(operationId: String): GitSyncRequest {
        val view = service.workspace(jobId, repositoryId)
        val guards = GitGuards(GitWorkspaceVersions.repositoryVersion(view.record, view.observation), GitWorkspaceVersions.worktreeVersion(view.observation),
            view.observation.head.objectId, null, null)
        return GitSyncRequest(GitOperationAction.GITHUB_PR_RECONCILE, view.worktreeId, guards, mapOf("prOperationId" to operationId))
    }

    private fun reconcile(operationId: String): GitOperationRecord = run(reconciliation(operationId))

    /** Seed clone + 63 uncertain creations without 63 provider writes. The service must be closed. */
    private fun Fixture.fillPullRecoveryQuota(uncertain: GitOperationRecord): Path {
        val operations = store.resolve("$jobId/git/operations")
        val intents = store.resolve("$jobId/git/repositories/$repositoryId/pull-intents")
        val operation = Json.parseToJsonElement(Files.readString(operations.resolve("${uncertain.operationId}.json"))).jsonObject
        val intent = Json.parseToJsonElement(Files.readString(intents.resolve("${uncertain.operationId}.json"))).jsonObject
        for (index in 1..62) {
            val id = "operation_" + index.toString(16).padStart(32, '0')
            val head = "blocked-$index"
            Files.writeString(operations.resolve("$id.json"), buildJsonObject {
                operation.forEach { (name, value) -> put(name, value) }
                put("operationId", id); put("requestKeySha256", GitStorage.sha256(id))
                put("request", buildJsonObject {
                    val request = operation.getValue("request").jsonObject
                    request.forEach { (name, value) -> put(name, value) }
                    put("parameters", buildJsonObject {
                        request.getValue("parameters").jsonObject.forEach { (name, value) -> put(name, value) }
                        put("headBranch", head)
                    })
                })
            }.toString())
            Files.writeString(intents.resolve("$id.json"), buildJsonObject {
                intent.forEach { (name, value) -> put(name, value) }
                put("operationId", id); put("head", head)
            }.toString())
        }
        assertEquals(64L, Files.list(operations).use { it.count() })
        assertEquals(63L, Files.list(intents).use { it.count() })
        return operations
    }

    @Test fun `full PR recovery quota permits bounded retries but not ordinary admission`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            val config = configuration(fake, f.repositories.root, writable = true)
            f.cloned(config)
            fake.failCreate = true
            val uncertain = run(create())
            assertEquals(GitOperationState.RECOVERY_REQUIRED, uncertain.state)
            service.close()
            val operations = f.fillPullRecoveryQuota(uncertain)
            service = f.open(config)
            val request = reconciliation(uncertain.operationId)
            repeat(3) {
                val requestsBefore = fake.requests.size
                assertEquals("QUOTA_EXCEEDED", assertFailsWith<ManagedGitException> {
                    service.requestWorkspace(jobId, repositoryId, create(), key())
                }.code)
                assertEquals(requestsBefore, fake.requests.size, "ordinary admission cannot contact the provider at quota")
                fake.rateLimited = true
                val retryKey = key()
                val admission = service.requestWorkspace(jobId, repositoryId, request, retryKey)
                assertTrue(service.awaitIdle(60_000))
                val failed = service.operation(jobId, repositoryId, admission.operation.operationId)
                assertEquals(GitOperationState.FAILED, failed.state)
                assertEquals("GITHUB_RATE_LIMITED", failed.failureCode)
                assertEquals(65L, Files.list(operations).use { it.count() }, "one shared recovery slot, not unbounded overflow")
                assertTrue(service.requestWorkspace(jobId, repositoryId, request, retryKey).replayed)
                assertEquals(GitOperationState.RECOVERY_REQUIRED, service.operation(jobId, repositoryId, uncertain.operationId).state)
                assertEquals(63, service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").unconfirmed.size)
            }
            fake.rateLimited = false
            assertEquals(GitOperationState.COMPLETED, reconcile(uncertain.operationId).state)
            assertEquals("PR_NOT_CREATED", service.operation(jobId, repositoryId, uncertain.operationId).failureCode)
            assertEquals(62, service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").unconfirmed.size)
            assertEquals(1, fake.requests.count { it.startsWith("POST") }, "recovery never retries creation")
            fake.failCreate = false
            assertEquals(GitOperationState.COMPLETED, run(create()).state, "settlement frees ordinary capacity")
            assertTrue(Files.list(operations).use { it.count() } <= 64)
        }
    }

    @Test fun `PR reconciliation survives restart after a failed attempt in the reserved slot`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            val config = configuration(fake, f.repositories.root, writable = true)
            f.cloned(config)
            fake.dropAfterCreate = true
            val uncertain = run(create())
            assertEquals(GitOperationState.RECOVERY_REQUIRED, uncertain.state)
            service.close()
            val operations = f.fillPullRecoveryQuota(uncertain)
            service = f.open(config)
            fake.rateLimited = true
            assertEquals("GITHUB_RATE_LIMITED", reconcile(uncertain.operationId).failureCode)
            assertEquals(65L, Files.list(operations).use { it.count() })
            service.close(); service = f.open(config)
            assertEquals(63, service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").unconfirmed.size)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, service.operation(jobId, repositoryId, uncertain.operationId).state)
            fake.rateLimited = false; fake.dropAfterCreate = false
            assertEquals(GitOperationState.COMPLETED, reconcile(uncertain.operationId).state)
            assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, uncertain.operationId).state)
            assertEquals(62, service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").unconfirmed.size)
            assertEquals(1, fake.pulls.size)
            assertEquals(1, fake.requests.count { it.startsWith("POST") })
            assertEquals(65L, Files.list(operations).use { it.count() })
            service.close(); service = f.open(config)
            assertEquals(62, service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").unconfirmed.size)
        }
    }

    private fun closedPull(number: Int, title: String) = buildJsonObject {
        put("number", number); put("state", "closed"); put("title", title)
        put("html_url", "https://fixture.invalid/fixture-owner/fixture-repo/pull/$number")
        put("head", buildJsonObject { put("ref", "feature") }); put("base", buildJsonObject { put("ref", "main") })
    }

    @Test fun `a stalled response body is bounded by the deadline`(): Unit = FakeGitHub(token).use { fake ->
        fake.stallBody = true
        val client = GitHubClient(GitHubConfiguration(fake.url, null, emptyList()), bodyTimeout = java.time.Duration.ofMillis(300))
        val started = System.nanoTime()
        val failure = assertFailsWith<GitHubException> { client.pulls(GitHubBinding("admitted:upstream.git", "fixture-owner", "fixture-repo"), "feature") }
        assertEquals("GITHUB_UNREACHABLE", failure.code)
        assertTrue(System.nanoTime() - started < 2_500_000_000L, "the stalled body must not hold the operation")
        fake.stallBody = false
    }

    @Test fun `an unreadable creation answer is unconfirmed and reconciles to the created pull request`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            fake.malformedCreate = true
            val uncertain = run(create())
            assertEquals(GitOperationState.RECOVERY_REQUIRED, uncertain.state, uncertain.message)
            assertEquals("PR_UNCONFIRMED", uncertain.failureCode)
            // The remote cannot be removed while the creation is unconfirmed.
            val view = service.workspace(jobId, repositoryId)
            val guards = GitGuards(GitWorkspaceVersions.repositoryVersion(view.record, view.observation), GitWorkspaceVersions.worktreeVersion(view.observation),
                view.observation.head.objectId, null, null)
            assertEquals("PR_UNCONFIRMED", assertFailsWith<ManagedGitException> {
                service.requestWorkspace(jobId, repositoryId, GitSyncRequest(GitOperationAction.REMOTE_REMOVE, view.worktreeId, guards, mapOf("remoteId" to remoteId())), key())
            }.code)
            fake.malformedCreate = false
            val reconciled = reconcile(uncertain.operationId)
            assertEquals(GitOperationState.COMPLETED, reconciled.state, reconciled.message)
            assertTrue(reconciled.message.contains("#1"), reconciled.message)
            assertEquals(1, fake.pulls.size)
        }
    }

    @Test fun `an older pull request with the same title is never taken as this creation`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            fake.pulls += closedPull(1, "Review the feature")
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            fake.failCreate = true
            val uncertain = run(create())
            assertEquals("PR_UNCONFIRMED", uncertain.failureCode, uncertain.message)
            fake.failCreate = false
            val reconciled = reconcile(uncertain.operationId)
            assertEquals(GitOperationState.COMPLETED, reconciled.state, reconciled.message)
            val settled = service.operation(jobId, repositoryId, uncertain.operationId)
            assertEquals(GitOperationState.FAILED, settled.state, settled.message)
            assertEquals("PR_NOT_CREATED", settled.failureCode)
        }
    }

    @Test fun `reconciliation looks in the repository that was contacted even after the binding changes`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            fake.dropAfterCreate = true
            val uncertain = run(create())
            assertEquals("PR_UNCONFIRMED", uncertain.failureCode, uncertain.message)
            fake.dropAfterCreate = false
            // After a restart the operator binds the remote elsewhere; the fake has no such repository.
            val rebound = configuration(fake, f.repositories.root, writable = true).let { it.copy(bindings = listOf(GitHubBinding("admitted:upstream.git", "other-owner", "other-repo"))) }
            service = f.open(rebound)
            val reconciled = reconcile(uncertain.operationId)
            assertEquals(GitOperationState.COMPLETED, reconciled.state, reconciled.message)
            assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, uncertain.operationId).state)
            assertTrue(fake.requests.none { it.contains("other-owner") })
        }
    }

    private fun openPull(number: Int, title: String) = buildJsonObject {
        put("number", number); put("state", "open"); put("title", title)
        put("html_url", "https://fixture.invalid/fixture-owner/fixture-repo/pull/$number")
        put("head", buildJsonObject { put("ref", "feature") }); put("base", buildJsonObject { put("ref", "main") })
    }

    @Test fun `a created pull request is confirmed by its correlation even after its title changes`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            fake.dropAfterCreate = true
            val uncertain = run(create())
            assertEquals("PR_UNCONFIRMED", uncertain.failureCode, uncertain.message)
            fake.dropAfterCreate = false
            // A collaborator retitles the pull request before reconciliation.
            val created = fake.pulls.single()
            assertTrue(created.getValue("body").jsonPrimitive.content.startsWith("Synthetic review body."))
            fake.pulls[0] = kotlinx.serialization.json.JsonObject(created + ("title" to kotlinx.serialization.json.JsonPrimitive("Renamed by a reviewer")))
            assertEquals(GitOperationState.COMPLETED, reconcile(uncertain.operationId).state)
            assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, uncertain.operationId).state)
        }
    }

    @Test fun `an unidentifiable new pull request keeps the creation unconfirmed`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            fake.failCreate = true
            val uncertain = run(create())
            assertEquals("PR_UNCONFIRMED", uncertain.failureCode, uncertain.message)
            fake.failCreate = false
            // Someone else opened a pull request for the same branches with another title and no correlation.
            fake.pulls += openPull(1, "Someone else's review")
            val attempt = reconcile(uncertain.operationId)
            assertEquals(GitOperationState.FAILED, attempt.state, attempt.message)
            assertEquals("PR_AMBIGUOUS", attempt.failureCode)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, service.operation(jobId, repositoryId, uncertain.operationId).state)
            assertEquals(listOf(uncertain.operationId), service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").unconfirmed.map { it.operationId })
        }
    }

    @Test fun `an existing open pull request is reported without writing, and GitHub's custom duplicate error is recognized`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            fake.pulls += openPull(1, "Already under review")
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            val existed = run(create())
            assertEquals(GitOperationState.COMPLETED, existed.state, existed.message)
            assertTrue(existed.message.contains("already existed") && existed.message.contains("#1"), existed.message)
            assertTrue(fake.requests.none { it.startsWith("POST") })
            fake.customDuplicate = true
            val client = GitHubClient(configuration(fake, f.repositories.root, writable = true))
            assertEquals("GITHUB_PR_EXISTS", assertFailsWith<GitHubException> {
                client.create(GitHubBinding("admitted:upstream.git", "fixture-owner", "fixture-repo"), "feature", "main", "Title", "")
            }.code)
        }
    }

    @Test fun `a long provider link never makes the operation record unreadable`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            fake.urlSuffix = "/" + "x".repeat(1900)
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            val created = run(create())
            assertEquals(GitOperationState.COMPLETED, created.state, created.message)
            assertTrue(created.message.length <= 500)
            service.close(); service = f.open(configuration(fake, f.repositories.root, writable = true))
            assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, created.operationId).state)
            assertNotNull(service.workspace(jobId, repositoryId))
        }
    }

    @Test fun `creation is refused when a reviewed commit moved`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            val stale = create().let { it.copy(parameters = it.parameters + ("headObjectId" to "1".repeat(40))) }
            assertEquals("REF_CHANGED", assertFailsWith<ManagedGitException> { service.requestWorkspace(jobId, repositoryId, stale, key()) }.code)
            assertTrue(fake.requests.none { it.startsWith("POST") })
        }
    }

    @Test fun `recovery searches page two independently of the presentation limit`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            repeat(30) { fake.pulls += closedPull(it + 1, "Historical review") }
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            fake.dropAfterCreate = true
            val uncertain = run(create())
            assertEquals("PR_UNCONFIRMED", uncertain.failureCode)
            assertEquals(30, service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").pulls.size)
            assertEquals(GitOperationState.COMPLETED, reconcile(uncertain.operationId).state)
            assertTrue(service.operation(jobId, repositoryId, uncertain.operationId).message.contains("#31"))
            assertTrue(fake.requests.any { it.contains("page=2") })
        }
    }

    @Test fun `a capped recovery inventory never establishes absence`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            fake.failCreate = true
            val uncertain = run(create())
            repeat(301) { number -> fake.pulls += kotlinx.serialization.json.JsonObject(closedPull(number + 1, "Other") +
                ("body" to kotlinx.serialization.json.JsonPrimitive(GitHubCorrelation.comment("another_$number")))) }
            val client = GitHubClient(configuration(fake, f.repositories.root, writable = true))
            val inventory = client.inventory(GitHubBinding("admitted:upstream.git", "fixture-owner", "fixture-repo"), "feature")
            assertEquals(300, inventory.pulls.size); assertFalse(inventory.complete)
            val attempt = reconcile(uncertain.operationId)
            assertEquals("PR_AMBIGUOUS", attempt.failureCode)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, service.operation(jobId, repositoryId, uncertain.operationId).state)
            assertEquals(1, service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").unconfirmed.size)
        }
    }

    @Test fun `an incomplete preflight inventory refuses creation without posting`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            repeat(301) { fake.pulls += closedPull(it + 1, "History") }
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            assertEquals("PR_AMBIGUOUS", run(create()).failureCode)
            assertTrue(fake.requests.none { it.startsWith("POST") })
            assertTrue(service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").unconfirmed.isEmpty())
        }
    }

    @Test fun `a copied body marker cannot shadow the creating operation`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            fake.dropAfterCreate = true
            val uncertain = run(create().copy(content = "Copied review" + GitHubCorrelation.comment("old_operation")))
            assertEquals("PR_UNCONFIRMED", uncertain.failureCode)
            val body = fake.pulls.single().getValue("body").jsonPrimitive.content
            assertFalse(body.contains("old_operation"))
            assertEquals(uncertain.operationId, GitHubCorrelation.find(body))
            assertEquals(GitOperationState.COMPLETED, reconcile(uncertain.operationId).state)
        }
    }

    @Test fun `legacy conflicting markers preserve uncertainty`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            fake.dropAfterCreate = true
            val uncertain = run(create())
            val pull = fake.pulls.single()
            fake.pulls[0] = kotlinx.serialization.json.JsonObject(pull + ("body" to kotlinx.serialization.json.JsonPrimitive(
                GitHubCorrelation.comment("old_operation") + pull.getValue("body").jsonPrimitive.content)))
            assertEquals("PR_AMBIGUOUS", reconcile(uncertain.operationId).failureCode)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, service.operation(jobId, repositoryId, uncertain.operationId).state)
        }
    }

    @Test fun `an independent same-title creation is ambiguous rather than attributed to this operation`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            fake.failCreate = true
            val uncertain = run(create())
            fake.pulls += openPull(1, "Review the feature")
            assertEquals("PR_AMBIGUOUS", reconcile(uncertain.operationId).failureCode)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, service.operation(jobId, repositoryId, uncertain.operationId).state)
        }
    }

    @Test fun `restart with a different API endpoint refuses recovery without contacting either provider`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { original -> FakeGitHub(token).use { replacement ->
            val config = configuration(original, f.repositories.root, writable = true)
            f.cloned(config)
            original.dropAfterCreate = true
            val uncertain = run(create())
            val originalRequests = original.requests.size
            service.close(); service = f.open(configuration(replacement, f.repositories.root, writable = true))
            assertEquals("PR_UNCONFIRMED", assertFailsWith<ManagedGitException> { reconcile(uncertain.operationId) }.code)
            assertTrue(replacement.requests.isEmpty()); assertEquals(originalRequests, original.requests.size)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, service.operation(jobId, repositoryId, uncertain.operationId).state)
            service.close(); service = f.open(config)
            assertEquals(GitOperationState.COMPLETED, reconcile(uncertain.operationId).state)
            assertEquals(1, original.pulls.size)
        } }
    }

    @Test fun `API identity is canonical across equivalent configured endpoints`() {
        val config = GitHubConfiguration(URI("https://API.GITHUB.COM:443/api/v3/"), null, emptyList())
        assertEquals("https://api.github.com/api/v3", config.apiIdentity)
    }

    @Test fun `audit failure after provider success retains a reconcilable intent`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            val audit = f.store.resolve("$jobId/git/repositories/$repositoryId/audit.jsonl")
            f.hook = { point -> if (point == GitOperationCrashPoint.AFTER_STAGING) {
                Files.deleteIfExists(audit); Files.createDirectory(audit)
            } }
            val uncertain = run(create())
            assertEquals(1, fake.pulls.size)
            assertEquals("PR_UNCONFIRMED", uncertain.failureCode)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, uncertain.state)
            assertEquals(1, service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").unconfirmed.size)
            Files.delete(audit); f.hook = {}
            service.close(); service = f.open(configuration(fake, f.repositories.root, writable = true))
            assertEquals(GitOperationState.COMPLETED, reconcile(uncertain.operationId).state)
            assertEquals(1, fake.pulls.size)
        }
    }

    @Test fun `crash after provider success retains the intent until durable completion`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            val config = configuration(fake, f.repositories.root, writable = true)
            f.cloned(config)
            f.hook = { if (it == GitOperationCrashPoint.AFTER_PUBLISH) throw SimulatedGitCrash() }
            val first = service.requestWorkspace(jobId, repositoryId, create(), key())
            assertTrue(service.awaitIdle(60_000)); assertEquals(1, fake.pulls.size)
            f.hook = {}; service.close(); service = f.open(config)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, service.operation(jobId, repositoryId, first.operation.operationId).state)
            assertEquals(GitOperationState.COMPLETED, reconcile(first.operation.operationId).state)
            assertTrue(service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").unconfirmed.isEmpty())
        }
    }

    @Test fun `restart cleans a confirmed intent left after durable completion`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            val config = configuration(fake, f.repositories.root, writable = true)
            f.cloned(config)
            f.hook = { if (it == GitOperationCrashPoint.BEFORE_PUBLISH) throw SimulatedGitCrash() }
            val first = service.requestWorkspace(jobId, repositoryId, create(), key())
            assertTrue(service.awaitIdle(60_000))
            val intent = f.store.resolve("$jobId/git/repositories/$repositoryId/pull-intents/${first.operation.operationId}.json")
            assertTrue(Files.exists(intent))
            f.hook = {}; service.close(); service = f.open(config)
            assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, first.operation.operationId).state)
            assertFalse(Files.exists(intent))
            assertTrue(service.githubStatus(jobId, repositoryId, null, remoteId(), "feature").unconfirmed.isEmpty())
            assertEquals(1, fake.pulls.size)
        }
    }

    @Test fun `a created pull request is confirmed by its correlation after it is retargeted`(): Unit = Fixture().use { f ->
        FakeGitHub(token).use { fake ->
            f.cloned(configuration(fake, f.repositories.root, writable = true))
            fake.dropAfterCreate = true
            val uncertain = run(create())
            assertEquals("PR_UNCONFIRMED", uncertain.failureCode, uncertain.message)
            fake.dropAfterCreate = false
            // A collaborator retargets the pull request to another base before reconciliation.
            val created = fake.pulls.single()
            fake.pulls[0] = kotlinx.serialization.json.JsonObject(created + ("base" to buildJsonObject { put("ref", "release") }))
            val reconciled = reconcile(uncertain.operationId)
            assertEquals(GitOperationState.COMPLETED, reconciled.state, reconciled.message)
            assertTrue(reconciled.message.contains("#1"), reconciled.message)
            assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, uncertain.operationId).state)
        }
    }
}
