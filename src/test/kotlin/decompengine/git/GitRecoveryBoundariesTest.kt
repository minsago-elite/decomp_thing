package decompengine.git

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Restart and cancellation at every Git boundary (#609): transfer, publication, commit and
 * integration. After each interruption the operation settles without being repeated, and the
 * accepted evidence is untouched. That evidence is the recorded snapshot, the commit's revision
 * mapping with its acceptance, and the commit's independently verified export.
 */
class GitRecoveryBoundariesTest {
    private val jobId = "0123456789abcdef0123456789abcdef"

    private class Fixture(val repositories: GitTestRepositories = GitTestRepositories()) : AutoCloseable {
        val store: Path = Files.createDirectories(repositories.root.resolve("store"))
        val snapshot: Path = Files.createDirectories(store.resolve("0123456789abcdef0123456789abcdef/reports/runs/run_1/source-tree"))
        val admitted: Path = Files.createDirectories(repositories.root.resolve("admitted")).toRealPath()
        val bare: Path = admitted.resolve("upstream.git")
        val seed: Path = repositories.root.resolve("seed")
        var hook: (GitOperationCrashPoint) -> Unit = {}
        private val opened = mutableListOf<ManagedGitRepositories>()
        init {
            mapOf("CMakeLists.txt" to "project(fixture C)\n", "src/main.c" to "int main(void) { return 0; }\n",
                "src/util.c" to "int util;\n").forEach { (name, text) ->
                Files.createDirectories(snapshot.resolve(name).parent); Files.writeString(snapshot.resolve(name), text)
            }
            repositories.git("init", "-q", "--bare", "--initial-branch=main", bare.toString())
        }
        val commitments = listOf("src/main.c", "src/util.c").associateWith {
            GitSourceCommitment(GitSourceCopy.digestOf(snapshot.resolve(it)), Files.size(snapshot.resolve(it)))
        }
        fun open() = ManagedGitRepositories(store, GitRuntime.detect(),
            { _, run, revision -> GitSourceSnapshot(snapshot, run, revision, "a".repeat(64), commitments) },
            policy = GitRepositoryPolicy(defaultBranch = "main"), crash = { hook(it) },
            acceptance = { _, revision, _ -> if (revision == "revision_1") "accepted" to "artifact_1" else "not-evaluated" to null },
            remotePolicy = GitRemotePolicy(admittedRoot = admitted)).also(opened::add)
        override fun close() { opened.forEach { it.close() }; repositories.close() }
    }

    private lateinit var service: ManagedGitRepositories
    private lateinit var repositoryId: String
    private var keys = 0
    private fun key() = "boundary_key_${(++keys).toString().padStart(6, '0')}"

    private fun guards(): Pair<GitWorkspaceView, GitGuards> {
        val view = service.workspace(jobId, repositoryId)
        return view to GitGuards(GitWorkspaceVersions.repositoryVersion(view.record, view.observation),
            GitWorkspaceVersions.worktreeVersion(view.observation), view.observation.head.objectId,
            GitWorkspaceVersions.headRefId(view.record, view.observation), view.observation.head.objectId.takeIf { view.observation.head.refName != null })
    }

    private fun GitWorkspaceView.ids(predicate: (GitStatusEntry) -> Boolean) =
        observation.status.entries.filter(predicate).map { it.path.fileId(worktreeId) }

    private fun run(request: GitRepositoryRequest): GitOperationRecord {
        val admission = service.requestWorkspace(jobId, repositoryId, request, key())
        assertTrue(service.awaitIdle(60_000))
        return service.operation(jobId, repositoryId, admission.operation.operationId)
    }

    private fun sync(action: GitOperationAction, vararg parameters: Pair<String, String?>): GitRepositoryRequest {
        val (view, g) = guards()
        return GitSyncRequest(action, view.worktreeId, g, parameters.toMap())
    }

    /** Admit [request], let the hook interrupt it at [point], then restart the service. */
    private fun Fixture.interrupted(point: GitOperationCrashPoint, request: GitRepositoryRequest): GitOperationRecord {
        hook = { if (it == point) throw SimulatedGitCrash() }
        val admission = service.requestWorkspace(jobId, repositoryId, request, key())
        assertTrue(service.awaitIdle(60_000))
        hook = {}
        service.close(); service = open()
        return service.operation(jobId, repositoryId, admission.operation.operationId)
    }

    private fun Fixture.commitAll(message: String): GitOperationRecord {
        val (view, g) = guards()
        run(GitStageRequest(view.worktreeId, g, view.ids { !it.ignored && (it.untracked || it.unstaged != GitIndexChange.NONE) }, true))
        val (staged, sg) = guards()
        return GitCommitRequest(staged.worktreeId, sg, staged.ids { it.staged != GitIndexChange.NONE }, message).let(::run)
    }

    private data class Evidence(val revision: String?, val acceptance: String?, val exportSha256: String, val verified: Boolean,
        val snapshot: Map<String, String>)

    private fun Fixture.evidence(accepted: String): Evidence {
        val provenance = service.provenance(jobId, repositoryId, accepted)
        return Evidence(provenance.mapping?.record?.revisionId, provenance.mapping?.acceptance, GitStorage.sha256(provenance.export.bytes),
            provenance.verified, commitments.keys.associateWith { GitSourceCopy.digestOf(snapshot.resolve(it)) })
    }

    @Test fun `interruptions at transfer, publication, commit and integration never lose accepted evidence`(): Unit = Fixture().use { f ->
        service = f.open()
        val admission = service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "init_key_00000001")
        assertTrue(service.awaitIdle(60_000)); repositoryId = admission.operation.repositoryId
        val accepted = assertNotNull(f.commitAll("Record the reconstructed snapshot").resultObjectId)
        val evidence = f.evidence(accepted)
        assertEquals(Evidence("revision_1", "accepted", evidence.exportSha256, true, f.commitments.mapValues { it.value.sha256 }), evidence)
        assertEquals(GitOperationState.COMPLETED, run(sync(GitOperationAction.REMOTE_ADD, "name" to "origin", "url" to "admitted:upstream.git")).state)
        val remoteId = service.remotes(jobId, repositoryId).single().record.remoteId

        // Transfer: a restart while a fetch runs leaves it interrupted; a cancel stops it as cancelled.
        val fetch = f.interrupted(GitOperationCrashPoint.AFTER_RUNNING, sync(GitOperationAction.FETCH, "remoteId" to remoteId))
        assertEquals(GitOperationState.INTERRUPTED, fetch.state, fetch.message)
        assertEquals(evidence, f.evidence(accepted))
        // The running fetch waits at its boundary until the cancel names it.
        val admitted = java.util.concurrent.CountDownLatch(1)
        var cancelled = ""
        f.hook = { point ->
            if (point == GitOperationCrashPoint.AFTER_RUNNING) { assertTrue(admitted.await(30, java.util.concurrent.TimeUnit.SECONDS)); service.cancel(jobId, repositoryId, cancelled) }
        }
        val pending = service.requestWorkspace(jobId, repositoryId, sync(GitOperationAction.FETCH, "remoteId" to remoteId), key())
        cancelled = pending.operation.operationId; admitted.countDown()
        assertTrue(service.awaitIdle(60_000)); f.hook = {}
        val stopped = service.operation(jobId, repositoryId, pending.operation.operationId)
        assertEquals(GitOperationState.CANCELLED, stopped.state, stopped.message)
        assertTrue(service.remotes(jobId, repositoryId).single().tracking.isEmpty(), "a cancelled fetch publishes no tracking refs")
        assertEquals(GitOperationState.COMPLETED, run(sync(GitOperationAction.FETCH, "remoteId" to remoteId)).state)
        assertEquals(evidence, f.evidence(accepted))

        // Publication: a restart after Git pushed is unconfirmed until it is reconciled with the remote.
        val preview = service.pushPreview(jobId, repositoryId, null, remoteId, null)
        val (view, g) = guards()
        val push = f.interrupted(GitOperationCrashPoint.AFTER_PUBLISH, GitSyncRequest(GitOperationAction.PUSH, view.worktreeId, g, mapOf(
            "remoteId" to remoteId, "localRefId" to GitWorkspaceVersions.refId(repositoryId, preview.localRef), "remoteBranch" to preview.remoteBranch,
            "localObjectId" to preview.localObjectId, "expectedRemoteObjectId" to preview.expectedRemoteObjectId)))
        assertEquals(GitOperationState.RECOVERY_REQUIRED, push.state, push.message)
        assertEquals("PUSH_UNCONFIRMED", push.failureCode)
        assertEquals(GitOperationState.COMPLETED, run(sync(GitOperationAction.PUSH_RECONCILE, "pushOperationId" to push.operationId)).state)
        assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, push.operationId).state)
        assertEquals(accepted, f.repositories.git("--git-dir=${f.bare}", "rev-parse", "refs/heads/main").trim())
        assertEquals(evidence, f.evidence(accepted))

        // Commit: a restart after Git committed reports the new HEAD and never commits twice.
        val workTree = f.store.resolve("$jobId/git/repositories/$repositoryId/worktree")
        Files.writeString(workTree.resolve("src/util.c"), "int util = 1;\n")
        val (edited, eg) = guards()
        run(GitStageRequest(edited.worktreeId, eg, edited.ids { it.unstaged != GitIndexChange.NONE }, true))
        val (staged, sg) = guards()
        val commit = f.interrupted(GitOperationCrashPoint.AFTER_PUBLISH,
            GitCommitRequest(staged.worktreeId, sg, staged.ids { it.staged != GitIndexChange.NONE }, "Local edit"))
        assertEquals(GitOperationState.RECOVERY_REQUIRED, commit.state, commit.message)
        val local = service.workspace(jobId, repositoryId).observation.head.objectId
        assertEquals(local, commit.resultObjectId)
        assertEquals(listOf(local, accepted), f.repositories.git("--git-dir=${f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")}",
            "rev-list", "main").trim().lines())
        assertEquals(evidence, f.evidence(accepted))

        // Integration: a restart after Git stopped with conflicts keeps the merge for resolution or abort.
        f.repositories.git("clone", "-q", f.bare.toString(), f.seed.toString())
        Files.writeString(f.seed.resolve("src/util.c"), "int util = 2;\n")
        f.repositories.git("-C", f.seed.toString(), "commit", "-q", "-am", "remote edit")
        f.repositories.git("-C", f.seed.toString(), "push", "-q", "origin", "main")
        assertEquals(GitOperationState.COMPLETED, run(sync(GitOperationAction.FETCH, "remoteId" to remoteId)).state)
        val tracking = service.remotes(jobId, repositoryId).single().tracking.single { it.name == "refs/remotes/origin/main" }
        val merge = f.interrupted(GitOperationCrashPoint.AFTER_PUBLISH, sync(GitOperationAction.MERGE,
            "trackingRefId" to GitWorkspaceVersions.refId(repositoryId, tracking.name), "targetObjectId" to tracking.objectId, "strategy" to "merge"))
        assertEquals(GitOperationState.RECOVERY_REQUIRED, merge.state, merge.message)
        assertEquals("MERGE_IN_PROGRESS", merge.failureCode)
        assertTrue(service.conflicts(jobId, repositoryId, null).mergeInProgress)
        assertEquals(evidence, f.evidence(accepted))
        assertEquals(GitOperationState.COMPLETED, run(sync(GitOperationAction.MERGE_ABORT)).state)
        assertEquals(local, service.workspace(jobId, repositoryId).observation.head.objectId)
        assertEquals("int util = 1;\n", Files.readString(workTree.resolve("src/util.c")))
        assertEquals(evidence, f.evidence(accepted))
    }
}
