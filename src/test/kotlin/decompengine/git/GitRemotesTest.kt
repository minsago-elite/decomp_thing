package decompengine.git

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GitRemotesTest {
    private val jobId = "0123456789abcdef0123456789abcdef"

    private class Fixture(val repositories: GitTestRepositories = GitTestRepositories()) : AutoCloseable {
        val store: Path = Files.createDirectories(repositories.root.resolve("store"))
        val admitted: Path = Files.createDirectories(repositories.root.resolve("admitted remotes")).toRealPath()
        val snapshot: Path = Files.createDirectories(store.resolve("0123456789abcdef0123456789abcdef/reports/runs/run_1/source-tree"))
        private val opened = mutableListOf<ManagedGitRepositories>()
        var hook: (GitOperationCrashPoint) -> Unit = {}
        init {
            Files.createDirectories(snapshot.resolve("src")); Files.writeString(snapshot.resolve("src/main.c"), "int main(void) { return 0; }\n")
        }
        fun open(policy: GitRemotePolicy = GitRemotePolicy(admittedRoot = admitted)) = ManagedGitRepositories(store, GitRuntime.detect(),
            { _, run, revision -> GitSourceSnapshot(snapshot, run, revision, "a".repeat(64), mapOf("src/main.c" to GitSourceCommitment(
                GitSourceCopy.digestOf(snapshot.resolve("src/main.c")), Files.size(snapshot.resolve("src/main.c"))))) },
            policy = GitRepositoryPolicy(defaultBranch = "main"), crash = { hook(it) }, remotePolicy = policy)
            .also { it.recover(listOf("0123456789abcdef0123456789abcdef")); opened += it }

        /** A bare remote with two commits on `main` and one on `topic`, populated with raw fixture Git. */
        fun remote(name: String = "upstream", format: String = "sha1"): Path {
            val bare = admitted.resolve("$name.git")
            repositories.git("init", "-q", "--bare", "--initial-branch=main", "--object-format=$format", bare.toString())
            val work = Files.createDirectories(repositories.root.resolve("$name seed"))
            repositories.git("init", "-q", "--initial-branch=main", "--object-format=$format", work.toString())
            Files.writeString(work.resolve("README.md"), "remote\n")
            repositories.git("-C", work.toString(), "add", "-A"); repositories.git("-C", work.toString(), "commit", "-q", "-m", "one")
            Files.writeString(work.resolve("util.c"), "int util;\n")
            repositories.git("-C", work.toString(), "add", "-A"); repositories.git("-C", work.toString(), "commit", "-q", "-m", "two")
            repositories.git("-C", work.toString(), "branch", "topic")
            repositories.git("-C", work.toString(), "push", "-q", bare.toString(), "main", "topic")
            // A hook in the remote never runs on the client side; a tripwire proves it.
            Files.writeString(bare.resolve("hooks/post-update"), "#!/bin/sh\ntouch '${repositories.root.resolve("hook-ran")}'\n")
            bare.resolve("hooks/post-update").toFile().setExecutable(true)
            return bare
        }

        override fun close() { opened.forEach { it.close() }; repositories.close() }
    }

    private lateinit var service: ManagedGitRepositories
    private lateinit var repositoryId: String
    private var keys = 0
    private fun key() = "remote_key_${(++keys).toString().padStart(8, '0')}"

    private fun guards(): Pair<GitWorkspaceView, GitGuards> {
        val view = service.workspace(jobId, repositoryId)
        return view to GitGuards(GitWorkspaceVersions.repositoryVersion(view.record, view.observation),
            GitWorkspaceVersions.worktreeVersion(view.observation), view.observation.head.objectId,
            GitWorkspaceVersions.headRefId(view.record, view.observation), null)
    }

    private fun sync(action: GitOperationAction, vararg parameters: Pair<String, String?>): GitOperationRecord {
        val (view, guards) = guards()
        val admission = service.requestWorkspace(jobId, repositoryId, GitSyncRequest(action, view.worktreeId, guards, mapOf(*parameters)), key())
        assertTrue(service.awaitIdle(60_000))
        return service.operation(jobId, repositoryId, admission.operation.operationId)
    }

    private fun refused(code: String, action: GitOperationAction, vararg parameters: Pair<String, String?>) {
        val (view, guards) = guards()
        assertEquals(code, assertFailsWith<ManagedGitException> {
            service.requestWorkspace(jobId, repositoryId, GitSyncRequest(action, view.worktreeId, guards, mapOf(*parameters)), key())
        }.code)
    }

    private fun Fixture.initialized() {
        service = open()
        val admission = service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "init_key_00000001")
        assertTrue(service.awaitIdle(60_000)); repositoryId = admission.operation.repositoryId
    }

    private fun parse(url: String, policy: GitRemotePolicy) = GitRemoteUrls.parse(url, policy)
    private fun refusedUrl(code: String, url: String, policy: GitRemotePolicy) =
        assertEquals(code, assertFailsWith<GitOperationRefusal>(url) { parse(url, policy) }.code, url)

    @Test fun `remote URLs allow only documented transports, allowlisted hosts and no embedded secrets`(): Unit = Fixture().use { f ->
        f.remote()
        val policy = GitRemotePolicy(allowedHosts = setOf("git.example.org"), admittedRoot = f.admitted)
        for (url in listOf("ext::sh%20-c%20touch", "fd::17", "transport::anything", "/srv/repo.git", "./relative", "file:///etc",
            "http://git.example.org/a.git", "git://git.example.org/a.git", "ftp://git.example.org/a.git")) {
            refusedUrl("TRANSPORT_UNSUPPORTED", url, policy)
        }
        refusedUrl("CREDENTIAL_IN_URL", "https://user:secret@git.example.org/a.git", policy)
        refusedUrl("CREDENTIAL_IN_URL", "https://ghp_token@git.example.org/a.git", policy)
        refusedUrl("CREDENTIAL_IN_URL", "ssh://git:pw@git.example.org/a.git", policy)
        refusedUrl("DESTINATION_NOT_ALLOWED", "https://elsewhere.example.org/a.git", policy)
        refusedUrl("DESTINATION_NOT_ALLOWED", "admitted:missing", policy)
        refusedUrl("VALIDATION_FAILED", "ssh://-oProxyCommand=touch/a.git", policy)
        refusedUrl("VALIDATION_FAILED", "-oProxyCommand=x@git.example.org:a.git", policy)
        refusedUrl("VALIDATION_FAILED", "git@git.example.org:-a.git", policy)
        refusedUrl("VALIDATION_FAILED", "https://git.example.org/a.git?token=x", policy)
        refusedUrl("VALIDATION_FAILED", "https://git.example.org/../a.git", policy)
        refusedUrl("VALIDATION_FAILED", "https://git.example.org/a b.git", policy)
        assertEquals("ssh://git@git.example.org/~/team/a.git", parse("git@git.example.org:team/a.git", policy).url)
        assertEquals("https://git.example.org:8443/a.git", parse("https://GIT.example.org:8443/a.git", policy).display)
        val admitted = parse("admitted:upstream.git", policy)
        assertEquals(GitTransport.ADMITTED, admitted.transport)
        assertEquals("admitted:upstream.git", admitted.display)
        assertFalse(admitted.display.contains(f.admitted.toString()))
        refusedUrl("TRANSPORT_UNSUPPORTED", "admitted:upstream.git", GitRemotePolicy(allowedHosts = setOf("git.example.org")))
    }

    @Test fun `admitted clone and fetch refuse indirect Git directories objects and refs`(): Unit = Fixture().use { f ->
        val outside = f.repositories.root.resolve("outside.git")
        f.repositories.git("init", "-q", "--bare", outside.toString())
        val gitfile = Files.createDirectories(f.admitted.resolve("gitfile"))
        Files.writeString(gitfile.resolve(".git"), "gitdir: $outside\n")
        val linked = Files.createDirectories(f.admitted.resolve("linked"))
        Files.createSymbolicLink(linked.resolve(".git"), outside)
        val objects = f.remote("objects")
        GitStorage.deleteTree(objects.resolve("objects"))
        Files.createSymbolicLink(objects.resolve("objects"), outside.resolve("objects"))
        val refs = f.remote("refs")
        GitStorage.deleteTree(refs.resolve("refs"))
        Files.createSymbolicLink(refs.resolve("refs"), outside.resolve("refs"))
        val alternate = f.remote("alternate")
        Files.writeString(alternate.resolve("objects/info/alternates"), outside.resolve("objects").toString() + "\n")
        val httpAlternate = f.remote("http-alternate")
        Files.writeString(httpAlternate.resolve("objects/info/http-alternates"), "https://unreviewed.invalid/objects\n")
        val common = f.remote("common")
        Files.writeString(common.resolve("commondir"), outside.toString() + "\n")
        val loose = f.remote("loose")
        val shard = Files.createDirectories(loose.resolve("objects/aa"))
        Files.createSymbolicLink(shard.resolve("b".repeat(38)), outside.resolve("HEAD"))
        val names = listOf("gitfile", "linked", "objects.git", "refs.git", "alternate.git", "http-alternate.git", "common.git", "loose.git")
        service = f.open()
        for (name in names) {
            assertEquals("DESTINATION_NOT_ALLOWED", assertFailsWith<ManagedGitException>(name) {
                service.request(jobId, GitCloneRequest("admitted:$name", "origin", null), key())
            }.code)
        }
        f.initialized()
        for (name in names) refused("DESTINATION_NOT_ALLOWED", GitOperationAction.REMOTE_ADD, "name" to "origin", "url" to "admitted:$name")
        // A regular non-bare .git directory remains supported, unlike gitfiles and linked .git.
        val mutable = f.remote("mutable")
        val ordinary = f.admitted.resolve("ordinary")
        Files.move(f.repositories.root.resolve("mutable seed"), ordinary)
        val policy = GitRemotePolicy(admittedRoot = f.admitted)
        assertEquals(GitTransport.ADMITTED, parse("admitted:ordinary", policy).transport)
        val reviewed = parse("admitted:mutable.git", policy)
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.REMOTE_ADD, "name" to "origin", "url" to reviewed.display).state)
        val remoteId = service.remotes(jobId, repositoryId).single().record.remoteId
        Files.writeString(mutable.resolve("objects/info/alternates"), outside.resolve("objects").toString() + "\n")
        refused("DESTINATION_NOT_ALLOWED", GitOperationAction.FETCH, "remoteId" to remoteId)
        assertEquals("DESTINATION_NOT_ALLOWED", assertFailsWith<GitOperationRefusal> { GitTransports.context(reviewed, policy) }.code)
        assertTrue(service.remotes(jobId, repositoryId).single().tracking.isEmpty())
    }

    @Test fun `credentials stay in the child environment and SSH always verifies host keys`(): Unit = Fixture().use { f ->
        val token = f.repositories.root.resolve("token")
        Files.writeString(token, "canary-secret-7f3a\n")
        val known = f.repositories.root.resolve("known_hosts").also { Files.writeString(it, "") }
        val credentials = GitCredentialStore(listOf(GitCredential.Https("git.example.org", "bot", token, null),
            GitCredential.Ssh("git.example.org", null, known)))
        val policy = GitRemotePolicy(allowedHosts = setOf("git.example.org", "other.example.org"), credentials = credentials)
        val https = GitTransports.context(parse("https://git.example.org/a.git", policy), policy)
        val invocation = GitInvocation("ls-remote", listOf("--", "https://git.example.org/a.git"), transport = https)
        val argv = f.repositories.runner.argv(invocation).joinToString(" ")
        assertFalse(argv.contains("canary") || argv.contains("Y2FuYXJ5") || argv.contains("Authorization"), argv)
        assertTrue(argv.contains("protocol.https.allow=always") && argv.contains("http.sslVerify=true") && argv.contains("http.followRedirects=false"))
        assertFalse(https.toString().contains("canary") || invocation.toString().contains("canary"))
        assertTrue(https.environment().getValue("GIT_CONFIG_VALUE_0").startsWith("Authorization: Basic "))
        assertEquals("http.https://git.example.org/.extraHeader", https.environment().getValue("GIT_CONFIG_KEY_0"))
        val ssh = GitTransports.context(parse("git@git.example.org:a.git", policy), policy)
        val command = ssh.configuration.single { it.first == "core.sshCommand" }.second
        for (option in listOf("BatchMode=yes", "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null", "-F /dev/null")) {
            assertTrue(command.contains(option), command)
        }
        assertEquals("HOST_KEY_UNVERIFIED", assertFailsWith<GitOperationRefusal> {
            GitTransports.context(parse("ssh://other.example.org/a.git", policy), policy)
        }.code)
        assertEquals("configured", credentials.describe(parse("https://git.example.org/a.git", policy)))
        assertEquals("none", credentials.describe(parse("https://other.example.org/a.git", policy)))
        // The operator file format is parsed strictly; secret material is never read at load time.
        val file = f.repositories.root.resolve("credentials.json")
        Files.writeString(file, """{"https":[{"host":"git.example.org","username":"bot","passwordFile":"$token"}],"ssh":[{"host":"git.example.org","knownHostsFile":"$known"}]}""")
        assertEquals("GitCredentialStore(2 entries)", GitCredentialStore.load(file).toString())
        Files.writeString(file, """{"https":[{"host":"git.example.org","username":"bot","password":"inline"}]}""")
        assertFailsWith<IllegalArgumentException> { GitCredentialStore.load(file) }
    }

    @Test fun `admitted remotes fetch only remote-tracking refs and leave local work untouched`(): Unit = Fixture().use { f ->
        f.remote()
        f.initialized()
        val workTree = f.store.resolve("$jobId/git/repositories/$repositoryId/worktree")
        Files.writeString(workTree.resolve("src/local.c"), "int local_work;\n")
        val before = service.workspace(jobId, repositoryId).observation
        refused("VALIDATION_FAILED", GitOperationAction.REMOTE_ADD, "name" to "bad name", "url" to "admitted:upstream.git")
        refused("TRANSPORT_UNSUPPORTED", GitOperationAction.REMOTE_ADD, "name" to "upstream", "url" to "/etc")
        val added = sync(GitOperationAction.REMOTE_ADD, "name" to "upstream", "url" to "admitted:upstream.git")
        assertEquals(GitOperationState.COMPLETED, added.state, added.message)
        refused("REMOTE_EXISTS", GitOperationAction.REMOTE_ADD, "name" to "upstream", "url" to "admitted:upstream.git")
        val remote = service.remotes(jobId, repositoryId).single()
        assertEquals("admitted:upstream.git", remote.record.location.display)
        assertEquals("not-required", remote.credential)
        assertNull(remote.fetchedAt)
        val fetched = sync(GitOperationAction.FETCH, "remoteId" to remote.record.remoteId)
        assertEquals(GitOperationState.COMPLETED, fetched.state, fetched.message)
        val after = service.remotes(jobId, repositoryId).single()
        assertEquals(setOf("refs/remotes/upstream/main", "refs/remotes/upstream/topic"), after.tracking.map { it.name }.toSet())
        assertNotNull(after.fetchedAt)
        // Fetch never moved HEAD, a local branch, the index or the work tree, and no tags arrived.
        val observed = service.workspace(jobId, repositoryId).observation
        assertEquals(before.head, observed.head)
        assertEquals(before.refs.filter { !it.name.startsWith("refs/remotes/") }, observed.refs.filter { !it.name.startsWith("refs/remotes/") })
        assertEquals(GitWorkspaceVersions.worktreeVersion(before), GitWorkspaceVersions.worktreeVersion(observed))
        assertEquals("int local_work;\n", Files.readString(workTree.resolve("src/local.c")))
        assertFalse(Files.exists(f.repositories.root.resolve("hook-ran")))
        assertFalse(Files.exists(f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git/FETCH_HEAD")))
        GitConfigurationAudit.requireManaged(f.repositories.runner, f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git"))
        val audit = service.auditLog(jobId, repositoryId, 10)
        assertEquals(listOf("fetch", "remote.add"), audit.map { it.getValue("action").toString().trim('"') })
        assertFalse(audit.toString().contains(f.admitted.toString()))
        val removed = sync(GitOperationAction.REMOTE_REMOVE, "remoteId" to remote.record.remoteId)
        assertEquals(GitOperationState.COMPLETED, removed.state, removed.message)
        assertTrue(service.remotes(jobId, repositoryId).isEmpty())
        assertTrue(service.workspace(jobId, repositoryId).observation.refs.none { it.name.startsWith("refs/remotes/") })
    }

    @Test fun `fetch publishes both directions of tracking ref namespace transitions`() {
        for (reverse in listOf(false, true)) Fixture().use { f ->
            val remote = f.remote()
            val old = if (reverse) "topic/sub" else "topic"
            val next = if (reverse) "topic" else "topic/sub"
            if (reverse) {
                f.repositories.git("-C", remote.toString(), "branch", "-m", "topic", old)
            }
            f.initialized()
            assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.REMOTE_ADD, "name" to "origin", "url" to "admitted:upstream.git").state)
            val remoteId = service.remotes(jobId, repositoryId).single().record.remoteId
            assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.FETCH, "remoteId" to remoteId).state)
            val before = service.workspace(jobId, repositoryId).observation
            f.repositories.git("-C", remote.toString(), "branch", "-m", old, next)
            repeat(2) {
                val operation = sync(GitOperationAction.FETCH, "remoteId" to remoteId)
                assertEquals(GitOperationState.COMPLETED, operation.state, operation.message)
                assertEquals(setOf("refs/remotes/origin/main", "refs/remotes/origin/$next"),
                    service.remotes(jobId, repositoryId).single().tracking.map { it.name }.toSet())
                val after = service.workspace(jobId, repositoryId).observation
                assertEquals(before.head, after.head)
                assertEquals(GitWorkspaceVersions.worktreeVersion(before), GitWorkspaceVersions.worktreeVersion(after))
                assertEquals(before.refs.filter { !it.name.startsWith("refs/remotes/") }, after.refs.filter { !it.name.startsWith("refs/remotes/") })
            }
        }
    }

    @Test fun `fetch retries safely after interruption between namespace prune and publication`() {
        for (reverse in listOf(false, true)) Fixture().use { f ->
            val remote = f.remote()
            val old = if (reverse) "topic/sub" else "topic"
            val next = if (reverse) "topic" else "topic/sub"
            if (reverse) f.repositories.git("-C", remote.toString(), "branch", "-m", "topic", old)
            f.initialized()
            assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.REMOTE_ADD, "name" to "origin", "url" to "admitted:upstream.git").state)
            val remoteId = service.remotes(jobId, repositoryId).single().record.remoteId
            assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.FETCH, "remoteId" to remoteId).state)
            val before = service.workspace(jobId, repositoryId).observation
            f.repositories.git("-C", remote.toString(), "branch", "-m", old, next)
            val live = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val quarantine = f.repositories.root.resolve("interrupted-quarantine.git")
            val policy = GitRemotePolicy(admittedRoot = f.admitted)
            assertFailsWith<IllegalStateException> {
                GitTransfers.fetchQuarantined(f.repositories.runner, live, quarantine, GitObjectFormat.SHA1,
                    parse("admitted:upstream.git", policy), "origin", policy, 1024 * 1024, GitProcessControl()) {
                    throw IllegalStateException("Simulated process loss after namespace prune")
                }
            }
            assertEquals(listOf("refs/remotes/origin/main"), service.remotes(jobId, repositoryId).single().tracking.map { it.name })
            service.close()
            service = f.open()
            val operation = sync(GitOperationAction.FETCH, "remoteId" to remoteId)
            assertEquals(GitOperationState.COMPLETED, operation.state, operation.message)
            assertEquals(setOf("refs/remotes/origin/main", "refs/remotes/origin/$next"),
                service.remotes(jobId, repositoryId).single().tracking.map { it.name }.toSet())
            val after = service.workspace(jobId, repositoryId).observation
            assertEquals(before.head, after.head)
            assertEquals(GitWorkspaceVersions.worktreeVersion(before), GitWorkspaceVersions.worktreeVersion(after))
            assertEquals(before.refs.filter { !it.name.startsWith("refs/remotes/") }, after.refs.filter { !it.name.startsWith("refs/remotes/") })
        }
    }

    @Test fun `remote registration audits recover exactly once across mutation and audit crash windows`() {
        for (action in listOf(GitOperationAction.REMOTE_ADD, GitOperationAction.REMOTE_REMOVE)) {
            for (point in listOf(GitOperationCrashPoint.AFTER_REMOTE_MUTATION, GitOperationCrashPoint.AFTER_REMOTE_AUDIT)) Fixture().use { f ->
                f.remote(); f.initialized()
                val original = if (action == GitOperationAction.REMOTE_REMOVE) {
                    assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.REMOTE_ADD, "name" to "upstream", "url" to "admitted:upstream.git").state)
                    service.remotes(jobId, repositoryId).single().record
                } else null
                val parameters = if (original == null) mapOf("name" to "upstream", "url" to "admitted:upstream.git")
                    else mapOf("remoteId" to original.remoteId)
                val (view, guard) = guards()
                f.hook = { if (it == point) throw SimulatedGitCrash() }
                val admission = service.requestWorkspace(jobId, repositoryId, GitSyncRequest(action, view.worktreeId, guard, parameters), key())
                assertTrue(service.awaitIdle(60_000))
                val operationId = admission.operation.operationId
                assertEquals(action == GitOperationAction.REMOTE_ADD, service.remotes(jobId, repositoryId).isNotEmpty())
                fun entries() = service.auditLog(jobId, repositoryId, 100).filter { it["operationId"] == kotlinx.serialization.json.JsonPrimitive(operationId) }
                assertEquals(if (point == GitOperationCrashPoint.AFTER_REMOTE_AUDIT) 1 else 0, entries().size)
                service.close(); f.hook = {}; service = f.open()
                repeat(2) {
                    val recovered = service.operation(jobId, repositoryId, operationId)
                    assertEquals(GitOperationState.COMPLETED, recovered.state, recovered.message)
                    val entry = entries().single()
                    assertEquals(kotlinx.serialization.json.JsonPrimitive(if (original == null) "remote.add" else "remote.remove"), entry["action"])
                    assertEquals(kotlinx.serialization.json.JsonPrimitive("completed"), entry["outcome"])
                    assertEquals(kotlinx.serialization.json.JsonPrimitive("admitted:upstream.git"), entry["destination"])
                    assertEquals(kotlinx.serialization.json.JsonPrimitive(original?.remoteId ?: service.remotes(jobId, repositoryId).single().record.remoteId), entry["remoteId"])
                    assertNull(GitRemoteStore.pendingAudit(f.store.resolve("$jobId/git/repositories/$repositoryId"), operationId))
                    service.close(); service = f.open()
                }
            }
        }
    }

    @Test fun `failed remote audit writes retain recovery ownership until publication succeeds`() {
        for (action in listOf(GitOperationAction.REMOTE_ADD, GitOperationAction.REMOTE_REMOVE)) Fixture().use { f ->
            f.remote(); f.initialized()
            val original = if (action == GitOperationAction.REMOTE_REMOVE) {
                sync(GitOperationAction.REMOTE_ADD, "name" to "upstream", "url" to "admitted:upstream.git")
                service.remotes(jobId, repositoryId).single().record
            } else null
            val directory = f.store.resolve("$jobId/git/repositories/$repositoryId")
            val audit = directory.resolve(GitRemoteStore.AUDIT)
            val backup = directory.resolve("audit-retained")
            f.hook = { if (it == GitOperationCrashPoint.AFTER_REMOTE_MUTATION) {
                if (Files.exists(audit)) Files.move(audit, backup)
                Files.createDirectory(audit) // Real storage error after the registration changed.
            } }
            val parameters = if (original == null) arrayOf("name" to "upstream", "url" to "admitted:upstream.git")
                else arrayOf("remoteId" to original.remoteId)
            val failed = sync(action, *parameters)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, failed.state)
            assertEquals("AUDIT_RECOVERY_REQUIRED", failed.failureCode)
            assertNotNull(GitRemoteStore.pendingAudit(directory, failed.operationId))
            service.close(); f.hook = {}; service = f.open()
            assertEquals(GitOperationState.RECOVERY_REQUIRED, service.operation(jobId, repositoryId, failed.operationId).state)
            refused("WORKTREE_BUSY", GitOperationAction.REMOTE_ADD, "name" to "other", "url" to "admitted:upstream.git")
            Files.delete(audit)
            if (Files.exists(backup)) Files.move(backup, audit)
            service.recover(listOf(jobId))
            assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, failed.operationId).state)
            val entries = service.auditLog(jobId, repositoryId, 100).filter { it["operationId"] == kotlinx.serialization.json.JsonPrimitive(failed.operationId) }
            assertEquals(1, entries.size)
            assertEquals(kotlinx.serialization.json.JsonPrimitive("admitted:upstream.git"), entries.single()["destination"])
            assertNull(GitRemoteStore.pendingAudit(directory, failed.operationId))
        }
    }

    @Test fun `clone publishes a complete managed repository from an admitted remote`(): Unit = Fixture().use { f ->
        f.remote()
        service = f.open()
        assertEquals("TRANSPORT_UNSUPPORTED", assertFailsWith<ManagedGitException> {
            service.request(jobId, GitCloneRequest("file:///etc", "origin", null), "clone_key_0000000")
        }.code)
        val admission = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", null), "clone_key_0000001")
        assertTrue(service.awaitIdle(60_000))
        val operation = service.operation(jobId, admission.operation.repositoryId, admission.operation.operationId)
        assertEquals(GitOperationState.COMPLETED, operation.state, operation.message)
        repositoryId = admission.operation.repositoryId
        val view = service.workspace(jobId, repositoryId)
        assertEquals("cloned", view.record.origin)
        assertEquals("refs/heads/main", view.observation.head.refName)
        assertEquals(view.observation.head.objectId, operation.resultObjectId)
        assertEquals("int util;\n", Files.readString(f.store.resolve("$jobId/git/repositories/$repositoryId/worktree/util.c")))
        assertTrue(view.observation.status.entries.none { !it.ignored })
        assertEquals("origin", service.remotes(jobId, repositoryId).single().record.name)
        assertFalse(Files.exists(f.repositories.root.resolve("hook-ran")))
        assertTrue(Files.list(f.store.resolve("$jobId/git/staging")).use { it.count() } == 0L)
    }

    @Test fun `clone refuses detached remote HEAD without an explicit branch instead of publishing unborn main`() {
        for (format in listOf("sha1", "sha256")) Fixture().use { f ->
            val remote = f.remote(format = format)
            val expected = f.repositories.git("-C", remote.toString(), "rev-parse", "refs/heads/topic").trim()
            f.repositories.git("-C", remote.toString(), "update-ref", "--no-deref", "HEAD", expected)
            f.repositories.git("-C", remote.toString(), "branch", "-D", "main")
            service = f.open()
            val clone = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", null), key())
            assertTrue(service.awaitIdle(60_000))
            val result = service.operation(jobId, clone.operation.repositoryId, clone.operation.operationId)
            assertEquals(GitOperationState.FAILED, result.state, result.message)
            assertEquals("REPOSITORY_UNSUPPORTED", result.failureCode)
            assertTrue(result.message.contains("detached"))
            assertFalse(Files.exists(f.store.resolve("$jobId/git/repositories/${result.repositoryId}")))
            assertEquals(0L, Files.list(f.store.resolve("$jobId/git/staging")).use { it.count() })
            // The refusal is actionable: selecting a real branch publishes that branch and bytes.
            val explicit = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", "topic"), key())
            assertTrue(service.awaitIdle(60_000))
            val completed = service.operation(jobId, explicit.operation.repositoryId, explicit.operation.operationId)
            assertEquals(GitOperationState.COMPLETED, completed.state, completed.message)
            val view = service.workspace(jobId, completed.repositoryId)
            assertEquals("refs/heads/topic", view.observation.head.refName)
            assertEquals(expected, view.observation.head.objectId)
            assertEquals("int util;\n", Files.readString(f.store.resolve("$jobId/git/repositories/${completed.repositoryId}/worktree/util.c")))
        }
    }

    @Test fun `clone refuses an unsupported advertised branch instead of substituting the configured default`() {
        for (format in listOf("sha1", "sha256")) for (fallbackExists in listOf(false, true)) Fixture().use { f ->
            val remote = f.remote(format = format)
            val branch = "b".repeat(201) // Valid Git ref, but beyond the workbench's branch-name bound.
            f.repositories.git("check-ref-format", "refs/heads/$branch")
            assertFalse(GitRefNames.isPlausibleBranchName(branch))
            val expected = f.repositories.git("-C", remote.toString(), "rev-parse", "refs/heads/topic").trim()
            f.repositories.git("-C", remote.toString(), "branch", branch, expected)
            f.repositories.git("-C", remote.toString(), "symbolic-ref", "HEAD", "refs/heads/$branch")
            if (fallbackExists) {
                val fallback = f.repositories.git("-C", remote.toString(), "rev-parse", "$expected^").trim()
                assertFalse(expected == fallback)
                f.repositories.git("-C", remote.toString(), "update-ref", "refs/heads/main", fallback)
            } else f.repositories.git("-C", remote.toString(), "branch", "-D", "main")
            service = f.open()
            val clone = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", null), key())
            assertTrue(service.awaitIdle(60_000))
            val result = service.operation(jobId, clone.operation.repositoryId, clone.operation.operationId)
            assertEquals(GitOperationState.FAILED, result.state, "$format fallbackExists=$fallbackExists: ${result.message}")
            assertEquals("VALIDATION_FAILED", result.failureCode)
            assertTrue(result.message.contains("branch"))
            assertTrue(result.message.contains("explicitly"))
            assertTrue(service.listing(jobId).repositories.isEmpty())
            assertFalse(Files.exists(f.store.resolve("$jobId/git/repositories/${result.repositoryId}")))
            assertEquals(0L, Files.list(f.store.resolve("$jobId/git/staging")).use { it.count() })
            // Reopen does not turn the refusal into success; an explicit supported branch recovers.
            service.close()
            service = f.open()
            assertEquals(GitOperationState.FAILED, service.operation(jobId, result.repositoryId, result.operationId).state)
            val explicit = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", "topic"), key())
            assertTrue(service.awaitIdle(60_000))
            val completed = service.operation(jobId, explicit.operation.repositoryId, explicit.operation.operationId)
            assertEquals(GitOperationState.COMPLETED, completed.state, completed.message)
            val view = service.workspace(jobId, completed.repositoryId)
            assertEquals("refs/heads/topic", view.observation.head.refName)
            assertEquals(expected, view.observation.head.objectId)
            assertEquals(expected, completed.resultObjectId)
            assertEquals("int util;\n", Files.readString(f.store.resolve("$jobId/git/repositories/${completed.repositoryId}/worktree/util.c")))
            assertEquals(0L, Files.list(f.store.resolve("$jobId/git/staging")).use { it.count() })
        }
    }

    @Test fun `clone discovers SHA256 rather than imposing the default including empty remotes`() {
        for (empty in listOf(false, true)) Fixture().use { f ->
            if (empty) f.repositories.git("init", "-q", "--bare", "--initial-branch=main", "--object-format=sha256", f.admitted.resolve("upstream.git").toString())
            else {
                val bare = f.remote(format = "sha256")
                val tip = f.repositories.git("--git-dir=$bare", "rev-parse", "HEAD").trim()
                // Packet diagnostics exceed their retained tail; capability capture stays bounded
                // and must not lose the early object-format line or reject a large advertisement.
                repeat(300) { Files.writeString(bare.resolve("refs/heads/branch$it"), "$tip\n") }
            }
            service = f.open() // New repositories default to SHA-1, but clones preserve the remote format.
            val clone = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", null), key())
            assertTrue(service.awaitIdle(60_000))
            val result = service.operation(jobId, clone.operation.repositoryId, clone.operation.operationId)
            assertEquals(GitOperationState.COMPLETED, result.state, result.message)
            repositoryId = result.repositoryId
            val view = service.workspace(jobId, repositoryId)
            assertEquals(GitObjectFormat.SHA256, view.record.objectFormat)
            assertEquals(GitObjectFormat.SHA256, view.observation.objectFormat)
            if (empty) assertNull(view.observation.head.objectId) else assertEquals(64, view.observation.head.objectId?.length)
            assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.FETCH,
                "remoteId" to service.remotes(jobId, repositoryId).single().record.remoteId).state)
        }
    }

    @Test fun `HTTPS clone discovers and preserves SHA256 with server-only diagnostics`(): Unit = Fixture().use { f ->
        val bare = f.remote(format = "sha256")
        GitHttpsFixture(f.admitted, f.repositories.root.resolve("https sha256"), null, null).use { server ->
            val policy = GitRemotePolicy(allowedHosts = setOf("localhost"), credentials = GitCredentialStore(listOf(
                GitCredential.Https("localhost", "bot", f.repositories.root.resolve("token").also { Files.writeString(it, "inert-token") }, server.certificate))))
            service = f.open(policy)
            val clone = service.request(jobId, GitCloneRequest(server.url(bare.fileName.toString()), "origin", null), key())
            assertTrue(service.awaitIdle(60_000))
            val result = service.operation(jobId, clone.operation.repositoryId, clone.operation.operationId)
            assertEquals(GitOperationState.COMPLETED, result.state, result.message)
            repositoryId = result.repositoryId
            assertEquals(GitObjectFormat.SHA256, service.workspace(jobId, repositoryId).record.objectFormat)
            assertFalse(result.message.contains("packet:") || result.message.contains("object-format="))
            assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.FETCH,
                "remoteId" to service.remotes(jobId, repositoryId).single().record.remoteId).state)
        }
    }

    @Test fun `https transfers verify certificates, use server credentials, and stop on cancel and bounds`(): Unit = Fixture().use { f ->
        val bare = f.remote()
        val token = f.repositories.root.resolve("token").also { Files.writeString(it, "canary-secret-7f3a\n") }
        GitHttpsFixture(f.admitted, f.repositories.root.resolve("https fixture"), "bot", "canary-secret-7f3a").use { server ->
            val url = server.url(bare.fileName.toString())
            fun policy(ca: Boolean, password: Path = token, limits: GitTransferLimits = GitTransferLimits()) = GitRemotePolicy(
                allowedHosts = setOf("localhost"), limits = limits,
                credentials = GitCredentialStore(listOf(GitCredential.Https("localhost", "bot", password, if (ca) server.certificate else null))))
            fun clone(policy: GitRemotePolicy, key: String): GitOperationRecord {
                service = f.open(policy)
                val admission = service.request(jobId, GitCloneRequest(url, "origin", null), key)
                assertTrue(service.awaitIdle(120_000))
                return service.operation(jobId, admission.operation.repositoryId, admission.operation.operationId)
            }
            val untrusted = clone(policy(ca = false), "https_key_0000001")
            assertEquals("CERTIFICATE_INVALID", untrusted.failureCode, untrusted.message)
            val wrong = f.repositories.root.resolve("wrong").also { Files.writeString(it, "not-the-secret\n") }
            val denied = clone(policy(ca = true, password = wrong), "https_key_0000002")
            assertEquals("AUTHENTICATION_REQUIRED", denied.failureCode, denied.message)
            assertFalse(denied.message.contains("canary") || denied.message.contains("not-the-secret"))
            val limited = clone(policy(ca = true, limits = GitTransferLimits(maxRepositoryBytes = 1024)), "https_key_0000003")
            assertEquals("TRANSFER_LIMIT", limited.failureCode, limited.message)
            // A stalled server: cancellation stops the process and the operation ends cancelled.
            server.stall = CountDownLatch(1)
            service = f.open(policy(ca = true))
            val stalled = service.request(jobId, GitCloneRequest(url, "origin", null), "https_key_0000004")
            Thread.sleep(500)
            assertEquals(GitOperationState.CANCELLING, service.cancel(jobId, stalled.operation.repositoryId, stalled.operation.operationId).state)
            assertTrue(service.awaitIdle(60_000))
            val cancelled = service.operation(jobId, stalled.operation.repositoryId, stalled.operation.operationId)
            assertEquals(GitOperationState.CANCELLED, cancelled.state, cancelled.message)
            server.stall?.countDown(); server.stall = null
            assertTrue(service.listing(jobId).repositories.isEmpty())
            val cloned = clone(policy(ca = true), "https_key_0000005")
            assertEquals(GitOperationState.COMPLETED, cloned.state, cloned.message)
            repositoryId = cloned.repositoryId
            assertEquals("configured", service.remotes(jobId, repositoryId).single().credential)
            val remoteId = service.remotes(jobId, repositoryId).single().record.remoteId
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val beforeCancel = GitDiskWatch.bytes(gitDir)
            // Keep Git alive behind a stalled response and cross the on-disk budget. Ending
            // before releasing the server proves the periodic watchdog, not the final gate, ran.
            service.close()
            service = f.open(policy(ca = true, limits = GitTransferLimits(maxRepositoryBytes = 128 * 1024)))
            server.stall = CountDownLatch(1)
            val (limitView, limitGuards) = guards()
            val diskAdmission = service.requestWorkspace(jobId, repositoryId, GitSyncRequest(GitOperationAction.FETCH,
                limitView.worktreeId, limitGuards, mapOf("remoteId" to remoteId)), key())
            val diskStaging = f.store.resolve("$jobId/git/staging/${diskAdmission.operation.operationId}")
            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10)
            while (!Files.isDirectory(diskStaging.resolve("repository.git/objects")) && System.nanoTime() < deadline) Thread.sleep(10)
            assertTrue(Files.isDirectory(diskStaging.resolve("repository.git/objects")))
            Files.write(diskStaging.resolve("watchdog-padding"), ByteArray(128 * 1024))
            assertTrue(service.awaitIdle(60_000))
            assertEquals("TRANSFER_LIMIT", service.operation(jobId, repositoryId, diskAdmission.operation.operationId).failureCode)
            assertEquals(beforeCancel, GitDiskWatch.bytes(gitDir))
            assertFalse(Files.exists(diskStaging))
            server.stall?.countDown(); server.stall = null
            server.stall = CountDownLatch(1)
            val (view, guards) = guards()
            val fetchAdmission = service.requestWorkspace(jobId, repositoryId, GitSyncRequest(GitOperationAction.FETCH,
                view.worktreeId, guards, mapOf("remoteId" to remoteId)), key())
            Thread.sleep(500)
            service.cancel(jobId, repositoryId, fetchAdmission.operation.operationId)
            assertTrue(service.awaitIdle(60_000))
            assertEquals(GitOperationState.CANCELLED, service.operation(jobId, repositoryId, fetchAdmission.operation.operationId).state)
            assertEquals(beforeCancel, GitDiskWatch.bytes(gitDir))
            assertEquals(0L, Files.list(f.store.resolve("$jobId/git/staging")).use { it.count() })
            server.stall?.countDown(); server.stall = null
            val fetched = sync(GitOperationAction.FETCH, "remoteId" to remoteId)
            assertEquals(GitOperationState.COMPLETED, fetched.state, fetched.message)
            // Nothing persisted by the server holds the credential.
            Files.walk(f.store).use { paths ->
                paths.filter { Files.isRegularFile(it) && Files.size(it) < 4 * 1024 * 1024 }.forEach { file ->
                    val text = Files.readAllBytes(file).toString(Charsets.ISO_8859_1)
                    assertFalse(text.contains("canary-secret") || text.contains("Y2FuYXJ5"), file.toString())
                }
            }
        }
    }

    @Test fun `an interrupted fetch is reconciled without repeating it`(): Unit = Fixture().use { f ->
        f.remote()
        f.initialized()
        sync(GitOperationAction.REMOTE_ADD, "name" to "upstream", "url" to "admitted:upstream.git")
        val remoteId = service.remotes(jobId, repositoryId).single().record.remoteId
        // A process death after the fetch was marked running, with a partial pack left behind.
        f.hook = { point -> if (point == GitOperationCrashPoint.AFTER_RUNNING) throw SimulatedGitCrash() }
        val (view, guards) = guards()
        val admission = service.requestWorkspace(jobId, repositoryId, GitSyncRequest(GitOperationAction.FETCH, view.worktreeId, guards,
            mapOf("remoteId" to remoteId)), key())
        assertTrue(service.awaitIdle(60_000))
        f.hook = {}
        service.close()
        val pack = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git/objects/pack/tmp_pack_partial")
        Files.writeString(pack, "partial")
        val quarantine = f.store.resolve("$jobId/git/staging/${admission.operation.operationId}/repository.git/objects")
        Files.createDirectories(quarantine)
        Files.write(quarantine.resolve("completed-but-unadmitted-object"), ByteArray(256 * 1024))
        service = f.open()
        val reconciled = service.operation(jobId, repositoryId, admission.operation.operationId)
        assertEquals(GitOperationState.INTERRUPTED, reconciled.state, reconciled.message)
        assertFalse(Files.exists(pack))
        assertFalse(Files.exists(quarantine))
        assertTrue(service.remotes(jobId, repositoryId).single().tracking.isEmpty())
        // The explicit retry is a new operation; nothing was repeated automatically.
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.FETCH, "remoteId" to remoteId).state)
    }

    @Test fun `remote names form valid refs, registrations have their own identity and removal deletes every tracking ref`(): Unit = Fixture().use { f ->
        val bare = f.remote()
        // Many branches on the remote: removal must not stop at a display bound.
        val seed = f.repositories.root.resolve("upstream seed")
        (1..210).forEach { f.repositories.git("-C", seed.toString(), "branch", "b%03d".format(it)) }
        f.repositories.git("-C", seed.toString(), "push", "-q", bare.toString(), "--all")
        service = f.open()
        val invalid = listOf("release..mirror", "mirror.lock", ".hidden", "HEAD")
        for (name in invalid) assertEquals("VALIDATION_FAILED", assertFailsWith<ManagedGitException>(name) {
            service.request(jobId, GitCloneRequest("admitted:upstream.git", name, null), "clone_key_${name.hashCode().toUInt()}_0000")
        }.code)
        f.initialized()
        for (name in invalid) refused("VALIDATION_FAILED", GitOperationAction.REMOTE_ADD, "name" to name, "url" to "admitted:upstream.git")
        sync(GitOperationAction.REMOTE_ADD, "name" to "upstream", "url" to "admitted:upstream.git")
        val first = service.remotes(jobId, repositoryId).single().record.remoteId
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.FETCH, "remoteId" to first).state)
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        assertEquals(212, f.repositories.git("--git-dir=$gitDir", "for-each-ref", "refs/remotes/upstream/").lines().count { it.isNotBlank() })
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.REMOTE_REMOVE, "remoteId" to first).state)
        assertEquals("", f.repositories.git("--git-dir=$gitDir", "for-each-ref", "refs/remotes/").trim())
        // A re-created remote with the same name is a different registration: a stale request cannot reach it.
        sync(GitOperationAction.REMOTE_ADD, "name" to "upstream", "url" to "admitted:upstream.git")
        val second = service.remotes(jobId, repositoryId).single().record.remoteId
        assertTrue(first != second)
        refused("NOT_FOUND", GitOperationAction.FETCH, "remoteId" to first)
        refused("NOT_FOUND", GitOperationAction.REMOTE_REMOVE, "remoteId" to first)
    }

    @Test fun `rejected fetches discard received objects and a subsequent small fetch recovers`(): Unit = Fixture().use { f ->
        val bare = f.remote()
        f.initialized()
        sync(GitOperationAction.REMOTE_ADD, "name" to "upstream", "url" to "admitted:upstream.git")
        val remoteId = service.remotes(jobId, repositoryId).single().record.remoteId
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.FETCH, "remoteId" to remoteId).state)
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val originalRefs = service.remotes(jobId, repositoryId).single().tracking
        val localFile = f.repositories.root.resolve("local-only.c").also { Files.writeString(it, "int local_only_canary;\n") }
        val localObject = f.repositories.git("--git-dir=$gitDir", "hash-object", "-w", localFile.toString()).trim()
        val originalBytes = GitDiskWatch.bytes(gitDir)
        val seed = f.repositories.root.resolve("upstream seed")
        val oldTip = f.repositories.git("-C", seed.toString(), "rev-parse", "HEAD").trim()
        val payload = ByteArray(2 * 1024 * 1024).also { java.util.Random(1760).nextBytes(it) }
        Files.write(seed.resolve("large.c"), payload)
        f.repositories.git("-C", seed.toString(), "add", "-A")
        f.repositories.git("-C", seed.toString(), "commit", "-q", "-m", "large source")
        f.repositories.git("-C", seed.toString(), "push", "-q", bare.toString(), "main")
        service.close()
        service = f.open(GitRemotePolicy(admittedRoot = f.admitted, limits = GitTransferLimits(maxRepositoryBytes = 128 * 1024)))
        repeat(2) {
            val result = sync(GitOperationAction.FETCH, "remoteId" to remoteId)
            assertEquals("TRANSFER_LIMIT", result.failureCode, result.message)
            assertEquals(originalBytes, GitDiskWatch.bytes(gitDir))
            assertEquals(originalRefs, service.remotes(jobId, repositoryId).single().tracking)
            assertEquals(0L, Files.list(f.store.resolve("$jobId/git/staging")).use { it.count() })
        }
        // Replace the oversized branch with a small forward update; old local objects survive.
        f.repositories.git("-C", seed.toString(), "reset", "--hard", oldTip)
        Files.writeString(seed.resolve("small.c"), "int small;\n")
        f.repositories.git("-C", seed.toString(), "add", "-A")
        f.repositories.git("-C", seed.toString(), "commit", "-q", "-m", "small source")
        f.repositories.git("--git-dir=$bare", "update-ref", "refs/heads/main", oldTip)
        f.repositories.git("-C", seed.toString(), "push", "-q", bare.toString(), "main")
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.FETCH, "remoteId" to remoteId).state)
        assertTrue(GitDiskWatch.bytes(gitDir) <= 128 * 1024)
        assertEquals("commit", f.repositories.git("--git-dir=$gitDir", "cat-file", "-t", oldTip).trim())
        assertEquals("int local_only_canary;", f.repositories.git("--git-dir=$gitDir", "cat-file", "-p", localObject).trim())
        assertFalse(Files.exists(gitDir.resolve("objects/info/alternates")))
    }

    @Test fun `fetch budgets the existing checkout and repository metadata not just Git objects`(): Unit = Fixture().use { f ->
        val bare = f.remote()
        val seed = f.repositories.root.resolve("upstream seed")
        Files.writeString(seed.resolve("large.c"), "x".repeat(64 * 1024))
        f.repositories.git("-C", seed.toString(), "add", "-A")
        f.repositories.git("-C", seed.toString(), "commit", "-q", "-m", "compressible checkout")
        f.repositories.git("-C", seed.toString(), "push", "-q", bare.toString(), "main")
        val cap = 128L * 1024
        service = f.open(GitRemotePolicy(admittedRoot = f.admitted, limits = GitTransferLimits(maxRepositoryBytes = cap)))
        val clone = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", null), key())
        assertTrue(service.awaitIdle(60_000))
        val cloned = service.operation(jobId, clone.operation.repositoryId, clone.operation.operationId)
        assertEquals(GitOperationState.COMPLETED, cloned.state, cloned.message)
        repositoryId = cloned.repositoryId
        val directory = f.store.resolve("$jobId/git/repositories/$repositoryId")
        val gitDir = directory.resolve("repository.git")
        val originalBytes = GitDiskWatch.bytes(gitDir)
        val originalRefs = service.remotes(jobId, repositoryId).single().tracking
        Files.write(seed.resolve("new.c"), ByteArray(72 * 1024).also { java.util.Random(593).nextBytes(it) })
        f.repositories.git("-C", seed.toString(), "add", "-A")
        f.repositories.git("-C", seed.toString(), "commit", "-q", "-m", "fits objects but not entire repository")
        f.repositories.git("-C", seed.toString(), "push", "-q", bare.toString(), "main")
        val result = sync(GitOperationAction.FETCH, "remoteId" to service.remotes(jobId, repositoryId).single().record.remoteId)
        assertEquals("TRANSFER_LIMIT", result.failureCode, result.message)
        assertEquals(originalBytes, GitDiskWatch.bytes(gitDir))
        assertEquals(originalRefs, service.remotes(jobId, repositoryId).single().tracking)
        assertTrue(GitDiskWatch.bytes(directory) <= cap)
        assertEquals("x".repeat(64 * 1024), Files.readString(directory.resolve("worktree/large.c")))
    }

    @Test fun `quarantine final admission rejects a completed pack without touching live objects or refs`(): Unit = Fixture().use { f ->
        val bare = f.remote()
        val seed = f.repositories.root.resolve("upstream seed")
        Files.write(seed.resolve("large.c"), ByteArray(512 * 1024).also { java.util.Random(593).nextBytes(it) })
        f.repositories.git("-C", seed.toString(), "add", "-A")
        f.repositories.git("-C", seed.toString(), "commit", "-q", "-m", "large source")
        f.repositories.git("-C", seed.toString(), "push", "-q", bare.toString(), "main")
        val (live, _) = f.repositories.managed("quarantine destination")
        val originalBytes = GitDiskWatch.bytes(live)
        val quarantine = f.repositories.root.resolve("quarantine.git")
        val policy = GitRemotePolicy(admittedRoot = f.admitted)
        assertEquals("TRANSFER_LIMIT", assertFailsWith<GitOperationRefusal> {
            // Disable periodic checks deliberately: only the final, unthrottled gate can reject.
            GitTransfers.fetchQuarantined(f.repositories.runner, live, quarantine, GitObjectFormat.SHA1,
                parse("admitted:upstream.git", policy), "origin", policy, 128 * 1024, GitProcessControl())
        }.code)
        assertTrue(GitDiskWatch.bytes(quarantine) > 128 * 1024)
        assertEquals(originalBytes, GitDiskWatch.bytes(live))
        assertTrue(GitTransfers.allTrackingRefs(f.repositories.runner, live, GitObjectFormat.SHA1, "origin").isEmpty())
    }

    @Test fun `clone budgets compressible checkout expansion and all publication metadata`(): Unit = Fixture().use { f ->
        val bare = f.remote()
        val seed = f.repositories.root.resolve("upstream seed")
        Files.writeString(seed.resolve("large.c"), "x".repeat(512 * 1024))
        f.repositories.git("-C", seed.toString(), "add", "-A")
        f.repositories.git("-C", seed.toString(), "commit", "-q", "-m", "compressible source")
        f.repositories.git("-C", seed.toString(), "push", "-q", bare.toString(), "main")
        service = f.open(GitRemotePolicy(admittedRoot = f.admitted, limits = GitTransferLimits(maxRepositoryBytes = 128 * 1024)))
        val clone = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", null), "clone_expansion_0001")
        assertTrue(service.awaitIdle(60_000))
        val result = service.operation(jobId, clone.operation.repositoryId, clone.operation.operationId)
        assertEquals("TRANSFER_LIMIT", result.failureCode, result.message)
        assertTrue(service.listing(jobId).repositories.isEmpty())
        assertEquals(0L, Files.list(f.store.resolve("$jobId/git/staging")).use { it.count() })

        // A successful tiny checkout can still cross the cap when its registration is written.
        // Inject extra bytes at the publication crash point to exercise the unconditional gate.
        service.close()
        f.hook = { point -> if (point == GitOperationCrashPoint.BEFORE_PUBLISH) {
            val staging = f.store.resolve("$jobId/git/staging")
            val operationDir = Files.list(staging).use { it.findFirst().orElseThrow() }
            Files.write(operationDir.resolve("publication-padding"), ByteArray(128 * 1024))
        } }
        service = f.open(GitRemotePolicy(admittedRoot = f.admitted, limits = GitTransferLimits(maxRepositoryBytes = 128 * 1024)))
        val finalGate = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", "topic"), "clone_metadata_00001")
        assertTrue(service.awaitIdle(60_000))
        assertEquals("TRANSFER_LIMIT", service.operation(jobId, finalGate.operation.repositoryId, finalGate.operation.operationId).failureCode)
        assertTrue(service.listing(jobId).repositories.isEmpty())
        assertEquals(0L, Files.list(f.store.resolve("$jobId/git/staging")).use { it.count() })
    }

    @Test fun `the size bound is enforced after a transfer that finishes between checks`(): Unit = Fixture().use { f ->
        f.remote()
        service = f.open(GitRemotePolicy(admittedRoot = f.admitted, limits = GitTransferLimits(maxRepositoryBytes = 2048)))
        val clone = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", null), "clone_key_limit_0001")
        assertTrue(service.awaitIdle(60_000))
        assertEquals("TRANSFER_LIMIT", service.operation(jobId, clone.operation.repositoryId, clone.operation.operationId).failureCode)
        assertTrue(service.listing(jobId).repositories.isEmpty())
        service.close()
        f.initialized()
        sync(GitOperationAction.REMOTE_ADD, "name" to "upstream", "url" to "admitted:upstream.git")
        service.close()
        service = f.open(GitRemotePolicy(admittedRoot = f.admitted, limits = GitTransferLimits(maxRepositoryBytes = 2048)))
        val fetched = sync(GitOperationAction.FETCH, "remoteId" to service.remotes(jobId, repositoryId).single().record.remoteId)
        assertEquals("TRANSFER_LIMIT", fetched.failureCode, fetched.message)
        assertTrue(service.remotes(jobId, repositoryId).single().tracking.isEmpty())
    }
}
