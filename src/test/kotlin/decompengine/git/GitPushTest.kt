package decompengine.git

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GitPushTest {
    private val jobId = "0123456789abcdef0123456789abcdef"

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
            remoteCommit("base")
        }
        fun remoteCommit(message: String) {
            repositories.git("-C", seed.toString(), "add", "-A"); repositories.git("-C", seed.toString(), "commit", "-q", "-m", message)
            repositories.git("-C", seed.toString(), "push", "-q", bare.toString(), "main")
        }
        fun remoteTip(branch: String = "main"): String? =
            repositories.git("--git-dir=$bare", "for-each-ref", "--format=%(objectname)", "refs/heads/$branch").trim().ifEmpty { null }
        fun open() = ManagedGitRepositories(store, GitRuntime.detect(), { _, _, _ -> error("no snapshots") },
            policy = GitRepositoryPolicy(defaultBranch = "main"), crash = { hook(it) },
            remotePolicy = GitRemotePolicy(admittedRoot = admitted)).also(opened::add)
        override fun close() { opened.forEach { it.close() }; repositories.close() }
    }

    private lateinit var service: ManagedGitRepositories
    private lateinit var repositoryId: String
    private var keys = 0
    private fun key() = "push_key_${(++keys).toString().padStart(8, '0')}"

    private fun Fixture.cloned() {
        service = open()
        val admission = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", null), "clone_key_0000001")
        assertTrue(service.awaitIdle(60_000)); repositoryId = admission.operation.repositoryId
    }

    private fun Fixture.workTree() = store.resolve("$jobId/git/repositories/$repositoryId/worktree")

    private fun guards(): Pair<GitWorkspaceView, GitGuards> {
        val view = service.workspace(jobId, repositoryId)
        return view to GitGuards(GitWorkspaceVersions.repositoryVersion(view.record, view.observation),
            GitWorkspaceVersions.worktreeVersion(view.observation), view.observation.head.objectId,
            GitWorkspaceVersions.headRefId(view.record, view.observation), view.observation.head.objectId)
    }

    private fun run(request: GitRepositoryRequest): GitOperationRecord {
        val admission = service.requestWorkspace(jobId, repositoryId, request, key())
        assertTrue(service.awaitIdle(60_000))
        return service.operation(jobId, repositoryId, admission.operation.operationId)
    }

    private fun Fixture.localCommit(name: String, text: String) {
        Files.writeString(workTree().resolve(name), text)
        val (view, g) = guards()
        run(GitStageRequest(view.worktreeId, g, view.observation.status.entries.filter { !it.ignored && (it.untracked || it.unstaged != GitIndexChange.NONE) }
            .map { it.path.fileId(view.worktreeId) }, true))
        val (staged, sg) = guards()
        assertEquals(GitOperationState.COMPLETED, run(GitCommitRequest(staged.worktreeId, sg, staged.observation.status.entries
            .filter { it.staged != GitIndexChange.NONE }.map { it.path.fileId(staged.worktreeId) }, "local $name")).state)
    }

    private fun remoteId() = service.remotes(jobId, repositoryId).single().record.remoteId

    private fun pushRequest(preview: ManagedGitRepositories.GitPushPreview, branch: String = preview.remoteBranch): GitSyncRequest {
        val (view, g) = guards()
        return GitSyncRequest(GitOperationAction.PUSH, view.worktreeId, g, mapOf("remoteId" to preview.remote.remoteId,
            "localRefId" to GitWorkspaceVersions.refId(repositoryId, preview.localRef), "remoteBranch" to branch,
            "localObjectId" to preview.localObjectId, "expectedRemoteObjectId" to preview.expectedRemoteObjectId))
    }

    private fun refused(code: String, request: GitRepositoryRequest) = assertEquals(code,
        assertFailsWith<ManagedGitException> { service.requestWorkspace(jobId, repositoryId, request, key()) }.code)

    @Test fun `a reviewed fast-forward push publishes exactly one commit and records its audit`(): Unit = Fixture().use { f ->
        f.cloned()
        val before = f.remoteTip()
        f.localCommit("notes.txt", "local work\n")
        val preview = service.pushPreview(jobId, repositoryId, null, remoteId(), null)
        assertEquals(before, preview.expectedRemoteObjectId)
        assertTrue(preview.fastForward)
        assertEquals(1L, preview.commitCount)
        assertEquals("local notes.txt", preview.commits.single().second)
        refused("VALIDATION_FAILED", pushRequest(preview, branch = "-delete"))
        refused("REF_CHANGED", pushRequest(preview).let { it.copy(parameters = it.parameters + ("localObjectId" to "1".repeat(40))) })
        val pushed = run(pushRequest(preview))
        assertEquals(GitOperationState.COMPLETED, pushed.state, pushed.message)
        assertEquals(preview.localObjectId, f.remoteTip())
        assertEquals(preview.localObjectId, service.remotes(jobId, repositoryId).single().tracking.single { it.name == "refs/remotes/origin/main" }.objectId)
        assertTrue(pushed.message.contains("not validation or acceptance"))
        val audit = service.auditLog(jobId, repositoryId, 2).map { it.getValue("outcome").toString().trim('"') }
        assertEquals(listOf("published", "started"), audit)
        refused("NOTHING_TO_PUSH", pushRequest(service.pushPreview(jobId, repositoryId, null, remoteId(), null)))
        // A new remote branch has no expected object and is created, never overwritten.
        val topic = service.pushPreview(jobId, repositoryId, null, remoteId(), "topic")
        assertNull(topic.expectedRemoteObjectId)
        assertEquals(GitOperationState.COMPLETED, run(pushRequest(topic)).state)
        assertEquals(preview.localObjectId, f.remoteTip("topic"))
    }

    @Test fun `a moved or diverged remote is never overwritten and needs fetch and review`(): Unit = Fixture().use { f ->
        f.cloned()
        f.localCommit("notes.txt", "local work\n")
        val stale = service.pushPreview(jobId, repositoryId, null, remoteId(), null)
        Files.writeString(f.seed.resolve("other.txt"), "remote work\n"); f.remoteCommit("remote work")
        val remoteTip = f.remoteTip()
        // The fetched ref is stale; the push reads the remote first and refuses without pushing.
        val moved = run(pushRequest(stale))
        assertEquals(GitOperationState.FAILED, moved.state, moved.message)
        assertEquals("REMOTE_CHANGED", moved.failureCode)
        assertEquals(remoteTip, f.remoteTip())
        val fetched = run(GitSyncRequest(GitOperationAction.FETCH, guards().first.worktreeId, guards().second, mapOf("remoteId" to remoteId())))
        assertEquals(GitOperationState.COMPLETED, fetched.state)
        val diverged = service.pushPreview(jobId, repositoryId, null, remoteId(), null)
        assertFalse(diverged.fastForward)
        refused("NON_FAST_FORWARD", pushRequest(diverged))
        refused("REMOTE_CHANGED", pushRequest(stale))
        assertEquals(remoteTip, f.remoteTip())
    }

    @Test fun `an unconfirmed push blocks retries until it is reconciled against the remote`(): Unit = Fixture().use { f ->
        f.cloned()
        f.localCommit("notes.txt", "local work\n")
        val original = f.remoteTip()
        // Process death after the intent was recorded but before Git ran: unconfirmed, not published.
        f.hook = { point -> if (point == GitOperationCrashPoint.AFTER_STAGING) throw SimulatedGitCrash() }
        val preview = service.pushPreview(jobId, repositoryId, null, remoteId(), null)
        val first = service.requestWorkspace(jobId, repositoryId, pushRequest(preview), key())
        assertTrue(service.awaitIdle(60_000))
        f.hook = {}
        service.close(); service = f.open()
        val unconfirmed = service.operation(jobId, repositoryId, first.operation.operationId)
        assertEquals(GitOperationState.RECOVERY_REQUIRED, unconfirmed.state, unconfirmed.message)
        assertEquals("PUSH_UNCONFIRMED", unconfirmed.failureCode)
        refused("PUSH_UNCONFIRMED", pushRequest(service.pushPreview(jobId, repositoryId, null, remoteId(), null)))
        refused("PUSH_UNCONFIRMED", GitSyncRequest(GitOperationAction.REMOTE_REMOVE, guards().first.worktreeId, guards().second, mapOf("remoteId" to remoteId())))
        val reconcile = run(GitSyncRequest(GitOperationAction.PUSH_RECONCILE, guards().first.worktreeId, guards().second,
            mapOf("pushOperationId" to first.operation.operationId)))
        assertEquals(GitOperationState.COMPLETED, reconcile.state, reconcile.message)
        val settled = service.operation(jobId, repositoryId, first.operation.operationId)
        assertEquals(GitOperationState.FAILED, settled.state); assertEquals("PUSH_NOT_PUBLISHED", settled.failureCode)
        assertEquals(original, f.remoteTip())
        // Process death after Git pushed but before the outcome was recorded: reconciliation confirms it.
        f.hook = { point -> if (point == GitOperationCrashPoint.AFTER_PUBLISH) throw SimulatedGitCrash() }
        val second = service.requestWorkspace(jobId, repositoryId, pushRequest(service.pushPreview(jobId, repositoryId, null, remoteId(), null)), key())
        assertTrue(service.awaitIdle(60_000))
        f.hook = {}
        service.close(); service = f.open()
        assertEquals(GitOperationState.RECOVERY_REQUIRED, service.operation(jobId, repositoryId, second.operation.operationId).state)
        assertEquals(service.unconfirmedPushes(jobId, repositoryId).single().pushedObjectId, f.remoteTip())
        assertEquals(GitOperationState.COMPLETED, run(GitSyncRequest(GitOperationAction.PUSH_RECONCILE, guards().first.worktreeId, guards().second,
            mapOf("pushOperationId" to second.operation.operationId))).state)
        val confirmed = service.operation(jobId, repositoryId, second.operation.operationId)
        assertEquals(GitOperationState.COMPLETED, confirmed.state, confirmed.message)
        assertTrue(service.unconfirmedPushes(jobId, repositoryId).isEmpty())
        assertEquals(listOf("confirmed", "not_published"), service.auditLog(jobId, repositoryId, 50)
            .filter { it.getValue("action").toString().trim('"') == "push.reconcile" }.map { it.getValue("outcome").toString().trim('"') })
    }
}
