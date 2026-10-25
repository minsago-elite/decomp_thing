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
                    rateLimited -> reply(403, "{\"message\":\"rate limited\"}", mapOf("X-RateLimit-Remaining" to "0", "Retry-After" to "60"))
                    authorization != null && authorization != "Bearer $token" -> reply(401, "{\"message\":\"bad credential\"}")
                    exchange.requestMethod == "GET" -> {
                        val query = exchange.requestURI.rawQuery.orEmpty().split('&').associate { it.substringBefore('=') to java.net.URLDecoder.decode(it.substringAfter('='), Charsets.UTF_8) }
                        reply(200, JsonArray(pulls.filter { pull ->
                            (query["head"] == null || query["head"] == "fixture-owner:" + pull.getValue("head").jsonObject.getValue("ref").jsonPrimitive.content) &&
                                (query["base"] == null || query["base"] == pull.getValue("base").jsonObject.getValue("ref").jsonPrimitive.content)
                        }).toString())
                    }
                    exchange.requestMethod == "POST" && authorization == null -> reply(401, "{\"message\":\"Fixture credential required\"}")
                    else -> {
                        val input = Json.parseToJsonElement(exchange.requestBody.readBytes().toString(Charsets.UTF_8)).jsonObject
                        val head = input.getValue("head").jsonPrimitive.content; val base = input.getValue("base").jsonPrimitive.content
                        if (pulls.any { it.getValue("head").jsonObject.getValue("ref").jsonPrimitive.content == head &&
                                it.getValue("base").jsonObject.getValue("ref").jsonPrimitive.content == base }) {
                            reply(422, "{\"message\":\"exists\",\"errors\":[{\"code\":\"already_exists\"}]}")
                        } else {
                            val number = pulls.size + 1
                            val pull = buildJsonObject {
                                put("number", number); put("state", "open"); put("title", input.getValue("title").jsonPrimitive.content)
                                put("html_url", "https://fixture.invalid/fixture-owner/fixture-repo/pull/$number")
                                put("head", buildJsonObject { put("ref", head); shas[head]?.let { put("sha", it) } })
                                put("base", buildJsonObject { put("ref", base) })
                            }
                            pulls += pull
                            if (dropAfterCreate) { exchange.close(); return@createContext }
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
        return GitSyncRequest(GitOperationAction.GITHUB_PR_CREATE, view.worktreeId, guards, mapOf("remoteId" to remoteId(), "headBranch" to "feature",
            "baseBranch" to "main", "title" to title), "Synthetic review body.")
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
}
