package decompengine.git

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GitIntegrationTest {
    private val jobId = "0123456789abcdef0123456789abcdef"

    private class Fixture(val repositories: GitTestRepositories = GitTestRepositories()) : AutoCloseable {
        val store: Path = Files.createDirectories(repositories.root.resolve("store"))
        val admitted: Path = Files.createDirectories(repositories.root.resolve("admitted")).toRealPath()
        val seed: Path = Files.createDirectories(repositories.root.resolve("seed"))
        val bare: Path = admitted.resolve("upstream.git")
        var hook: (GitOperationCrashPoint) -> Unit = {}
        val runs = mutableMapOf("run_1" to false)
        var signed = false
        var checkoutLimits = GitCheckoutLimits()
        var clock: java.time.Clock = java.time.Clock.systemUTC()
        var stable = false
        val leases = GitWorkspaceLeases()
        val activity = object : GitJobActivity {
            override fun runs(jobId: String) = runs.toMap()
            override fun <T> withStableRuns(jobId: String, block: (Map<String, Boolean>) -> T): T {
                check(!stable)
                stable = true
                return try { block(runs(jobId)) } finally { stable = false }
            }
        }
        private val opened = mutableListOf<ManagedGitRepositories>()
        init {
            Files.createDirectories(store.resolve("0123456789abcdef0123456789abcdef"))
            repositories.git("init", "-q", "--bare", "--initial-branch=main", bare.toString())
            repositories.git("init", "-q", "--initial-branch=main", seed.toString())
            Files.writeString(seed.resolve("README.md"), "line one\nline two\n")
            Files.writeString(seed.resolve("util.c"), "int util;\n")
            remoteCommit("base")
        }
        /** Commit everything in the seed and push it to the remote's main. */
        fun remoteCommit(message: String) {
            repositories.git("-C", seed.toString(), "add", "-A"); repositories.git("-C", seed.toString(), "commit", "-q", "-m", message)
            repositories.git("-C", seed.toString(), "push", "-q", bare.toString(), "main")
        }
        fun open(recover: Boolean = true) = ManagedGitRepositories(store, GitRuntime.detect(), { _, _, _ -> error("no snapshots") },
            policy = GitRepositoryPolicy(defaultBranch = "main", requireSignedCommits = signed), clock = clock, crash = { hook(it) }, activity = activity,
            remotePolicy = GitRemotePolicy(admittedRoot = admitted), workspaceLeases = leases, importLimits = checkoutLimits).also {
                opened += it
                if (recover) it.recover(listOf("0123456789abcdef0123456789abcdef"))
            }
        override fun close() { opened.forEach { it.close() }; repositories.close() }
    }

    private lateinit var service: ManagedGitRepositories
    private lateinit var repositoryId: String
    private var keys = 0
    private fun key() = "integrate_key_${(++keys).toString().padStart(6, '0')}"

    private fun Fixture.cloned() {
        service = open()
        val admission = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", null), "clone_key_0000001")
        assertTrue(service.awaitIdle(60_000)); repositoryId = admission.operation.repositoryId
        assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, admission.operation.operationId).state)
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

    private fun sync(action: GitOperationAction, parameters: Map<String, String?> = emptyMap(), content: String? = null): GitOperationRecord {
        val (view, guards) = guards()
        return run(GitSyncRequest(action, view.worktreeId, guards, parameters, content))
    }

    private fun refused(code: String, action: GitOperationAction, parameters: Map<String, String?> = emptyMap(), content: String? = null) {
        val (view, guards) = guards()
        assertEquals(code, assertFailsWith<ManagedGitException> {
            service.requestWorkspace(jobId, repositoryId, GitSyncRequest(action, view.worktreeId, guards, parameters, content), key())
        }.code)
    }

    private fun fetch() {
        val remote = service.remotes(jobId, repositoryId).single().record.remoteId
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.FETCH, mapOf("remoteId" to remote)).state)
    }

    private fun tracking(): String = GitWorkspaceVersions.refId(repositoryId, "refs/remotes/origin/main")
    private fun trackingObject(): String = service.remotes(jobId, repositoryId).single().tracking.single { it.name == "refs/remotes/origin/main" }.objectId

    /** Commit one local edit of [path] through the reviewed stage and commit operations. */
    private fun Fixture.localCommit(text: String, path: String = "README.md") {
        Files.writeString(workTree().resolve(path), text)
        val (view, g) = guards()
        run(GitStageRequest(view.worktreeId, g, view.observation.status.entries.filter { it.unstaged != GitIndexChange.NONE }.map { it.path.fileId(view.worktreeId) }, true))
        val (staged, sg) = guards()
        assertEquals(GitOperationState.COMPLETED, run(GitCommitRequest(staged.worktreeId, sg, staged.observation.status.entries
            .filter { it.staged != GitIndexChange.NONE }.map { it.path.fileId(staged.worktreeId) }, "local edit")).state)
    }

    private fun merge(strategy: String, target: String = trackingObject()) =
        mapOf("trackingRefId" to tracking(), "targetObjectId" to target, "strategy" to strategy)

    @Test fun `divergence uses fetched identities and only reviewed strategies integrate`(): Unit = Fixture().use { f ->
        f.cloned()
        val initial = service.divergence(jobId, repositoryId, null, tracking())
        assertEquals(0L, initial.divergence.ahead); assertEquals(0L, initial.divergence.behind); assertNotNull(initial.fetchedAt)
        refused("NOTHING_TO_INTEGRATE", GitOperationAction.MERGE, merge("fast-forward"))
        Files.writeString(f.seed.resolve("util.c"), "int util = 2;\n"); f.remoteCommit("remote change")
        // Not fetched yet: divergence reports the last fetched state only.
        assertEquals(0L, service.divergence(jobId, repositoryId, null, tracking()).divergence.behind)
        fetch()
        val fetched = service.divergence(jobId, repositoryId, null, tracking())
        assertEquals(1L, fetched.divergence.behind); assertEquals(0L, fetched.divergence.ahead)
        refused("STRATEGY_UNSUPPORTED", GitOperationAction.MERGE, merge("rebase"))
        refused("REF_CHANGED", GitOperationAction.MERGE, merge("fast-forward", target = "1".repeat(40)))
        Files.writeString(f.workTree().resolve("unreviewed.c"), "int unreviewed;\n")
        refused("WORKTREE_DIRTY", GitOperationAction.MERGE, merge("fast-forward"))
        Files.delete(f.workTree().resolve("unreviewed.c"))
        Files.writeString(f.workTree().resolve("README.md"), "dirty\n")
        refused("WORKTREE_DIRTY", GitOperationAction.MERGE, merge("fast-forward"))
        Files.writeString(f.workTree().resolve("README.md"), "line one\nline two\n")
        f.runs["run_1"] = true
        refused("ACTIVE_RUN", GitOperationAction.MERGE, merge("fast-forward"))
        f.runs["run_1"] = false
        val target = trackingObject()
        val forwarded = sync(GitOperationAction.MERGE, merge("fast-forward"))
        assertEquals(GitOperationState.COMPLETED, forwarded.state, forwarded.message)
        assertEquals(target, forwarded.resultObjectId)
        assertTrue(forwarded.message.contains("new source candidate"))
        assertEquals("int util = 2;\n", Files.readString(f.workTree().resolve("util.c")))
        assertNull(service.workspace(jobId, repositoryId).mapping)
        assertEquals("fast-forward", service.auditLog(jobId, repositoryId, 1).single().getValue("action").toString().trim('"'))
    }

    @Test fun `conflicts are reviewed, saved with concurrency checks, staged explicitly and committed`(): Unit = Fixture().use { f ->
        f.cloned()
        f.localCommit("line one\nlocal two\n")
        Files.writeString(f.seed.resolve("README.md"), "line one\nremote two\n"); f.remoteCommit("remote edit")
        fetch()
        refused("FAST_FORWARD_UNAVAILABLE", GitOperationAction.MERGE, merge("fast-forward"))
        val before = service.workspace(jobId, repositoryId).observation.head.objectId
        val merged = sync(GitOperationAction.MERGE, merge("merge"))
        assertEquals(GitOperationState.COMPLETED, merged.state, merged.message)
        assertTrue(merged.message.contains("1 conflicted file"), merged.message)
        refused("MERGE_IN_PROGRESS", GitOperationAction.MERGE, merge("merge"))
        val conflicts = service.conflicts(jobId, repositoryId, null)
        assertTrue(conflicts.mergeInProgress)
        assertEquals(before, conflicts.integration?.headBefore)
        val entry = conflicts.files.single()
        assertEquals("README.md", entry.path.exact)
        val fileId = entry.path.fileId(conflicts.worktreeId)
        val detail = service.conflictFile(jobId, repositoryId, null, fileId)
        assertEquals("line one\nline two\n", detail.base); assertEquals("line one\nlocal two\n", detail.ours)
        assertEquals("line one\nremote two\n", detail.theirs); assertTrue(GitIntegrations.hasMarkers(checkNotNull(detail.current)))
        // Marked resolution is refused while markers remain; a stale digest never overwrites newer bytes.
        refused("UNRESOLVED_MARKERS", GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${detail.currentSha256}\n")
        refused("CONTENT_CHANGED", GitOperationAction.CONFLICT_SAVE, mapOf("fileId" to fileId, "expectedSha256" to "0".repeat(64),
            "resolution" to "text"), "line one\nresolved two\n")
        val saved = sync(GitOperationAction.CONFLICT_SAVE, mapOf("fileId" to fileId, "expectedSha256" to detail.currentSha256,
            "resolution" to "text"), "line one\nresolved two\n")
        assertEquals(GitOperationState.COMPLETED, saved.state, saved.message)
        assertEquals("line one\nresolved two\n", Files.readString(f.workTree().resolve("README.md")))
        val current = service.conflictFile(jobId, repositoryId, null, fileId)
        refused("CONTENT_CHANGED", GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${detail.currentSha256}\n")
        val completed = sync(GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${current.currentSha256}\n")
        assertEquals(GitOperationState.COMPLETED, completed.state, completed.message)
        assertTrue(service.conflicts(jobId, repositoryId, null).files.isEmpty())
        // Completion staged only; the final commit is an explicit, reviewed action.
        assertEquals(before, service.workspace(jobId, repositoryId).observation.head.objectId)
        val (view, g) = guards()
        val commit = run(GitCommitRequest(view.worktreeId, g, view.observation.status.entries.filter { it.staged != GitIndexChange.NONE }
            .map { it.path.fileId(view.worktreeId) }, "Merge reviewed remote edit"))
        assertEquals(GitOperationState.COMPLETED, commit.state, commit.message)
        val parents = f.repositories.git("--git-dir=${f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")}",
            "rev-list", "--parents", "-n", "1", checkNotNull(commit.resultObjectId)).trim().split(' ')
        assertEquals(3, parents.size)
        assertFalse(service.conflicts(jobId, repositoryId, null).mergeInProgress)
        assertNull(service.conflicts(jobId, repositoryId, null).integration)
    }

    @Test fun `abort restores the pre-merge state and restarts keep merge state recoverable`(): Unit = Fixture().use { f ->
        f.cloned()
        f.localCommit("line one\nlocal two\n")
        Files.writeString(f.seed.resolve("README.md"), "line one\nremote two\n"); f.remoteCommit("remote edit")
        fetch()
        val before = service.workspace(jobId, repositoryId).observation.head
        refused("NO_MERGE", GitOperationAction.MERGE_ABORT)
        sync(GitOperationAction.MERGE, merge("merge"))
        val aborted = sync(GitOperationAction.MERGE_ABORT)
        assertEquals(GitOperationState.COMPLETED, aborted.state, aborted.message)
        assertEquals(before, service.workspace(jobId, repositoryId).observation.head)
        assertEquals("line one\nlocal two\n", Files.readString(f.workTree().resolve("README.md")))
        assertTrue(service.workspace(jobId, repositoryId).observation.status.entries.none { !it.ignored })
        assertFalse(service.conflicts(jobId, repositoryId, null).mergeInProgress)
        // A restart after Git stopped with conflicts keeps that state for resolution or abort.
        f.hook = { point -> if (point == GitOperationCrashPoint.AFTER_PUBLISH) throw SimulatedGitCrash() }
        val (view, g) = guards()
        val crashed = service.requestWorkspace(jobId, repositoryId, GitSyncRequest(GitOperationAction.MERGE, view.worktreeId, g, merge("merge")), key())
        assertTrue(service.awaitIdle(60_000))
        f.hook = {}
        service.close(); service = f.open()
        val reconciled = service.operation(jobId, repositoryId, crashed.operation.operationId)
        assertEquals(GitOperationState.RECOVERY_REQUIRED, reconciled.state, reconciled.message)
        assertEquals("MERGE_IN_PROGRESS", reconciled.failureCode)
        assertTrue(service.conflicts(jobId, repositoryId, null).mergeInProgress)
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.MERGE_ABORT).state)
        // A restart before Git ran leaves nothing behind and is never repeated.
        f.hook = { point -> if (point == GitOperationCrashPoint.AFTER_STAGING) throw SimulatedGitCrash() }
        val (view2, g2) = guards()
        val early = service.requestWorkspace(jobId, repositoryId, GitSyncRequest(GitOperationAction.MERGE, view2.worktreeId, g2, merge("merge")), key())
        assertTrue(service.awaitIdle(60_000))
        f.hook = {}
        service.close(); service = f.open()
        assertEquals(GitOperationState.INTERRUPTED, service.operation(jobId, repositoryId, early.operation.operationId).state)
        assertFalse(service.conflicts(jobId, repositoryId, null).mergeInProgress)
        assertEquals(before, service.workspace(jobId, repositoryId).observation.head)
    }

    /** Fetch the remote's main and fast-forward onto it. */
    private fun forward() {
        fetch()
        val forwarded = sync(GitOperationAction.MERGE, merge("fast-forward"))
        assertEquals(GitOperationState.COMPLETED, forwarded.state, forwarded.message)
    }

    /** Commit diverging edits of [path] locally and on the remote, then merge into a conflict. */
    private fun Fixture.conflictOn(path: String): String {
        localCommit("line one\nlocal two\n", path)
        Files.writeString(seed.resolve(path), "line one\nremote two\n"); remoteCommit("remote edit")
        fetch()
        val merged = sync(GitOperationAction.MERGE, merge("merge"))
        assertTrue(merged.message.contains("1 conflicted file"), merged.message)
        return service.conflicts(jobId, repositoryId, null).files.single().path.fileId(service.workspace(jobId, repositoryId).worktreeId)
    }

    @Test fun `integration never overwrites ignored local output`(): Unit = Fixture().use { f ->
        f.cloned()
        Files.writeString(f.seed.resolve(".gitignore"), "results.txt\n"); f.remoteCommit("ignore results")
        forward()
        Files.writeString(f.workTree().resolve("results.txt"), "local experiment output\n")
        Files.writeString(f.seed.resolve("results.txt"), "remote results\n")
        f.repositories.git("-C", f.seed.toString(), "add", "-f", "results.txt")
        f.repositories.git("-C", f.seed.toString(), "commit", "-q", "-m", "track results")
        f.repositories.git("-C", f.seed.toString(), "push", "-q", f.bare.toString(), "main")
        fetch()
        val before = service.workspace(jobId, repositoryId).observation.head.objectId
        val refusedMerge = sync(GitOperationAction.MERGE, merge("fast-forward"))
        assertEquals(GitOperationState.FAILED, refusedMerge.state, refusedMerge.message)
        assertEquals("MERGE_REFUSED", refusedMerge.failureCode)
        assertEquals("local experiment output\n", Files.readString(f.workTree().resolve("results.txt")))
        assertEquals(before, service.workspace(jobId, repositoryId).observation.head.objectId)
    }

    @Test fun `a merge resolved to the current tree is still committed with both parents`(): Unit = Fixture().use { f ->
        f.cloned()
        val fileId = f.conflictOn("README.md")
        val before = checkNotNull(service.conflicts(jobId, repositoryId, null).integration).headBefore
        val detail = service.conflictFile(jobId, repositoryId, null, fileId)
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.CONFLICT_SAVE, mapOf("fileId" to fileId,
            "expectedSha256" to detail.currentSha256, "resolution" to "ours")).state)
        val saved = service.conflictFile(jobId, repositoryId, null, fileId)
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${saved.currentSha256}\n").state)
        val (view, g) = guards()
        assertTrue(view.observation.status.entries.none { it.staged != GitIndexChange.NONE }, "the resolved tree matches HEAD")
        // Outside a merge an empty selection is still nothing to commit; inside one it records the merge.
        val commit = run(GitCommitRequest(view.worktreeId, g, emptyList(), "Merge keeping the local edit"))
        assertEquals(GitOperationState.COMPLETED, commit.state, commit.message)
        val parents = f.repositories.git("--git-dir=${f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")}",
            "rev-list", "--parents", "-n", "1", checkNotNull(commit.resultObjectId)).trim().split(' ')
        assertEquals(listOf(before), parents.subList(1, 2))
        assertEquals(3, parents.size)
        assertFalse(service.conflicts(jobId, repositoryId, null).mergeInProgress)
        val (clean, cg) = guards()
        assertEquals("NOTHING_TO_COMMIT", assertFailsWith<ManagedGitException> {
            service.requestWorkspace(jobId, repositoryId, GitCommitRequest(clean.worktreeId, cg, emptyList(), "empty"), key())
        }.code)
    }

    @Test fun `restart finishes published merge metadata cleanup without creating another commit`(): Unit {
        for (secondCrash in listOf(false, true)) Fixture().use { f ->
            f.cloned()
            val fileId = f.conflictOn("README.md")
            val detail = service.conflictFile(jobId, repositoryId, null, fileId)
            sync(GitOperationAction.CONFLICT_SAVE, mapOf("fileId" to fileId, "expectedSha256" to detail.currentSha256, "resolution" to "ours"))
            val saved = service.conflictFile(jobId, repositoryId, null, fileId)
            sync(GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${saved.currentSha256}\n")
            val (view, g) = guards()
            val request = GitCommitRequest(view.worktreeId, g, emptyList(), "Merge keeping ours", true)
            val replayKey = key()
            f.hook = { if (it == GitOperationCrashPoint.AFTER_COMMIT_PUBLISH) throw SimulatedGitCrash() }
            val admission = service.requestWorkspace(jobId, repositoryId, request, replayKey)
            assertTrue(service.awaitIdle(60_000))
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val published = f.repositories.git("--git-dir=$gitDir", "rev-parse", "HEAD").trim()
            assertTrue(GitIntegrations.mergeInProgress(gitDir), "crash is after ref publication but before metadata cleanup")
            service.close()
            f.hook = { if (secondCrash && it == GitOperationCrashPoint.BEFORE_TERMINAL_PERSIST) throw SimulatedGitCrash() }
            service = f.open(recover = !secondCrash)
            if (secondCrash) {
                assertFailsWith<SimulatedGitCrash> { service.recover(listOf(jobId)) }
                assertFalse(GitIntegrations.mergeInProgress(gitDir), "cleanup precedes the interrupted recovery persistence")
                service.close(); f.hook = {}; service = f.open()
            }
            val recovered = service.operation(jobId, repositoryId, admission.operation.operationId)
            // Preserve the existing conservative commit-outcome contract; metadata housekeeping
            // must not invent a completed intent from HEAD alone or replay a commit.
            assertEquals(GitOperationState.RECOVERY_REQUIRED, recovered.state)
            assertEquals("HEAD_MOVED", recovered.failureCode)
            assertFalse(service.conflicts(jobId, repositoryId, null).mergeInProgress)
            assertEquals(published, service.workspace(jobId, repositoryId).observation.head.objectId)
            assertEquals(3, f.repositories.git("--git-dir=$gitDir", "rev-list", "--parents", "-n", "1", published).trim().split(' ').size)
            assertTrue(service.requestWorkspace(jobId, repositoryId, request, replayKey).replayed)
            refused("NO_MERGE", GitOperationAction.MERGE_ABORT)
            val (clean, cg) = guards()
            assertEquals("NOTHING_TO_COMMIT", assertFailsWith<ManagedGitException> {
                service.requestWorkspace(jobId, repositoryId, GitCommitRequest(clean.worktreeId, cg, emptyList(), "duplicate"), key())
            }.code)
            assertEquals(published, service.workspace(jobId, repositoryId).observation.head.objectId)
        }
    }

    @Test fun `merge cleanup recovery preserves mismatched parents and foreign commit locks`(): Unit {
        for (foreignLock in listOf(false, true)) Fixture().use { f ->
            f.cloned()
            val fileId = f.conflictOn("README.md")
            val detail = service.conflictFile(jobId, repositoryId, null, fileId)
            sync(GitOperationAction.CONFLICT_SAVE, mapOf("fileId" to fileId, "expectedSha256" to detail.currentSha256, "resolution" to "ours"))
            val saved = service.conflictFile(jobId, repositoryId, null, fileId)
            sync(GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${saved.currentSha256}\n")
            val (view, g) = guards()
            f.hook = { if (it == GitOperationCrashPoint.AFTER_COMMIT_PUBLISH) throw SimulatedGitCrash() }
            val admission = service.requestWorkspace(jobId, repositoryId, GitCommitRequest(view.worktreeId, g, emptyList(), "merge", true), key())
            assertTrue(service.awaitIdle(60_000)); service.close(); f.hook = {}
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            if (foreignLock) Files.writeString(gitDir.resolve("index.lock"), "foreign writer\n")
            else Files.writeString(gitDir.resolve("MERGE_HEAD"), "${g.expectedHeadObjectId}\n")
            service = f.open()
            val recovered = service.operation(jobId, repositoryId, admission.operation.operationId)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, recovered.state)
            assertTrue(GitIntegrations.mergeInProgress(gitDir), "unproven merge metadata is never discarded")
            if (foreignLock) {
                assertEquals("COMMIT_LOCKS_REQUIRE_REVIEW", recovered.failureCode)
                assertEquals("foreign writer\n", Files.readString(gitDir.resolve("index.lock")))
            } else assertEquals("${g.expectedHeadObjectId}\n", Files.readString(gitDir.resolve("MERGE_HEAD")))
        }
    }

    @Test fun `integration publication owns the shared workflow admission lease`(): Unit = Fixture().use { f ->
        f.cloned()
        Files.writeString(f.seed.resolve("util.c"), "int remote_util;\n"); f.remoteCommit("advance"); fetch()
        fun excludeAdmissions() { f.hook = { if (it == GitOperationCrashPoint.BEFORE_PUBLISH) {
            assertNull(f.leases.tryWorkflowAdmission(jobId), "workflow admission must not enter a file-replacing integration")
        } } }
        excludeAdmissions()
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.MERGE, merge("fast-forward")).state)
        f.hook = {}
        val fileId = f.conflictOn("README.md")
        val detail = service.conflictFile(jobId, repositoryId, null, fileId)
        excludeAdmissions()
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.CONFLICT_SAVE, mapOf("fileId" to fileId,
            "expectedSha256" to detail.currentSha256, "resolution" to "ours")).state)
        val saved = service.conflictFile(jobId, repositoryId, null, fileId)
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${saved.currentSha256}\n").state)
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.MERGE_ABORT).state)
        f.leases.tryWorkflowAdmission(jobId).use { assertNotNull(it, "the lease is released after publication") }
    }

    @Test fun `complete index review commits large merges without splitting incoming changes`(): Unit = Fixture().use { f ->
        f.cloned()
        f.localCommit("local README\n")
        repeat(201) { Files.writeString(f.seed.resolve("incoming-$it.c"), "int remote_$it;\n") }
        Files.writeString(f.seed.resolve("README.md"), "remote README\n"); f.remoteCommit("large remote change"); fetch()
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.MERGE, merge("merge")).state)
        val conflict = service.conflicts(jobId, repositoryId, null).files.single().path.fileId(service.workspace(jobId, repositoryId).worktreeId)
        val detail = service.conflictFile(jobId, repositoryId, null, conflict)
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.CONFLICT_SAVE, mapOf("fileId" to conflict,
            "expectedSha256" to detail.currentSha256, "resolution" to "ours")).state)
        val saved = service.conflictFile(jobId, repositoryId, null, conflict)
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.CONFLICT_COMPLETE, content = "$conflict ${saved.currentSha256}\n").state)
        val (view, reviewedGuards) = guards()
        val ids = view.observation.status.entries.filter { it.staged != GitIndexChange.NONE }.map { it.path.fileId(view.worktreeId) }
        assertEquals(201, ids.size)
        assertEquals("INDEX_CHANGED", assertFailsWith<ManagedGitException> {
            service.requestWorkspace(jobId, repositoryId, GitCommitRequest(view.worktreeId, reviewedGuards, ids.take(200), "partial"), key())
        }.code)
        assertEquals("VALIDATION_FAILED", assertFailsWith<ManagedGitException> {
            service.requestWorkspace(jobId, repositoryId, GitCommitRequest(view.worktreeId, reviewedGuards, ids.take(1), "ambiguous", true), key())
        }.code)
        val request = GitCommitRequest(view.worktreeId, reviewedGuards, emptyList(), "Review complete merge index", true)
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        Files.writeString(f.workTree().resolve("incoming-0.c"), "changed after review\n")
        f.repositories.git("--git-dir=$gitDir", "--work-tree=${f.workTree()}", "add", "incoming-0.c")
        assertEquals("WORKTREE_CHANGED", assertFailsWith<ManagedGitException> {
            service.requestWorkspace(jobId, repositoryId, request, key())
        }.code)
        Files.writeString(f.workTree().resolve("incoming-0.c"), "int remote_0;\n")
        f.repositories.git("--git-dir=$gitDir", "--work-tree=${f.workTree()}", "add", "incoming-0.c")
        val (_, fresh) = guards()
        val accepted = request.copy(guards = fresh)
        val replayKey = key()
        val admitted = service.requestWorkspace(jobId, repositoryId, accepted, replayKey)
        assertTrue(service.awaitIdle(60_000))
        val result = service.operation(jobId, repositoryId, admitted.operation.operationId)
        assertEquals(GitOperationState.COMPLETED, result.state, result.message)
        val parents = f.repositories.git("--git-dir=$gitDir", "rev-list", "--parents", "-n", "1", checkNotNull(result.resultObjectId)).trim().split(' ')
        assertEquals(3, parents.size)
        repeat(201) { assertEquals("int remote_$it;\n", f.repositories.git("--git-dir=$gitDir", "show", "HEAD:incoming-$it.c")) }
        service.close(); service = f.open()
        val replay = service.requestWorkspace(jobId, repositoryId, accepted, replayKey)
        assertTrue(replay.replayed); assertEquals(result.operationId, replay.operation.operationId)
        val (clean, cg) = guards()
        assertEquals("VALIDATION_FAILED", assertFailsWith<ManagedGitException> {
            service.requestWorkspace(jobId, repositoryId, GitCommitRequest(clean.worktreeId, cg, emptyList(), "not a merge", true), key())
        }.code)
    }

    @Test fun `saving a resolution keeps an executable file executable`(): Unit = Fixture().use { f ->
        f.cloned()
        val script = f.seed.resolve("run.sh")
        Files.writeString(script, "line one\nline two\n")
        Files.setPosixFilePermissions(script, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"))
        f.remoteCommit("add script")
        forward()
        assertTrue(Files.isExecutable(f.workTree().resolve("run.sh")))
        val fileId = f.conflictOn("run.sh")
        val detail = service.conflictFile(jobId, repositoryId, null, fileId)
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.CONFLICT_SAVE, mapOf("fileId" to fileId,
            "expectedSha256" to detail.currentSha256, "resolution" to "text"), "line one\nresolved two\n").state)
        assertTrue(Files.isExecutable(f.workTree().resolve("run.sh")), "the resolution keeps the executable mode")
        val saved = service.conflictFile(jobId, repositoryId, null, fileId)
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${saved.currentSha256}\n").state)
        val staged = f.repositories.git("--git-dir=${f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")}",
            "--work-tree=${f.workTree()}", "ls-files", "-s", "--", "run.sh")
        assertTrue(staged.startsWith("100755 "), staged)
    }

    @Test fun `merge commits are refused when signed commits are required, fast-forwards are not`(): Unit = Fixture().use { f ->
        f.cloned()
        f.localCommit("line one\nlocal two\n")
        Files.writeString(f.seed.resolve("util.c"), "int util = 3;\n"); f.remoteCommit("remote change")
        fetch()
        service.close(); f.signed = true; service = f.open()
        val view = service.divergence(jobId, repositoryId, null, tracking())
        assertTrue(view.signingRequired)
        refused("SIGNING_UNAVAILABLE", GitOperationAction.MERGE, merge("merge"))
        assertFalse(service.conflicts(jobId, repositoryId, null).mergeInProgress)
    }

    @Test fun `fast-forwards stay available when signed commits are required`(): Unit = Fixture().use { f ->
        f.signed = true
        f.cloned()
        Files.writeString(f.seed.resolve("util.c"), "int util = 4;\n"); f.remoteCommit("remote change")
        forward()
        assertEquals("int util = 4;\n", Files.readString(f.workTree().resolve("util.c")))
    }

    @Test fun `conflict markers of the configured width are never accepted as resolved`(): Unit = Fixture().use { f ->
        f.cloned()
        Files.writeString(f.seed.resolve(".gitattributes"), "README.md conflict-marker-size=32\n"); f.remoteCommit("wide markers")
        forward()
        val fileId = f.conflictOn("README.md")
        val detail = service.conflictFile(jobId, repositoryId, null, fileId)
        assertTrue(checkNotNull(detail.current).lines().any { it.startsWith("<".repeat(32) + " ") }, detail.current)
        refused("UNRESOLVED_MARKERS", GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${detail.currentSha256}\n")
        assertTrue(GitIntegrations.hasMarkers("a\n" + ">".repeat(32) + " theirs\n", 32))
        assertFalse(GitIntegrations.hasMarkers("a\n" + "<".repeat(40) + "\n", 32))
    }

    @Test fun `marker widths above 1024 cannot bypass completion`(): Unit = Fixture().use { f ->
        f.cloned()
        Files.writeString(f.seed.resolve(".gitattributes"), "README.md conflict-marker-size=2048\n"); f.remoteCommit("very wide markers")
        forward()
        val fileId = f.conflictOn("README.md")
        val detail = service.conflictFile(jobId, repositoryId, null, fileId)
        assertTrue(checkNotNull(detail.current).startsWith("line one\n" + "<".repeat(2048) + " "))
        refused("UNRESOLVED_MARKERS", GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${detail.currentSha256}\n")
        assertEquals(1, service.conflicts(jobId, repositoryId, null).files.size)
        assertFalse(GitIntegrations.hasMarkers("short line", Int.MAX_VALUE))
    }

    @Test fun `conflict detail refuses an ancestor symlink outside the worktree`(): Unit = Fixture().use { f ->
        Files.createDirectories(f.seed.resolve("src"))
        Files.writeString(f.seed.resolve("src/a.c"), "line one\nline two\n"); f.remoteCommit("nested source")
        f.cloned()
        val fileId = f.conflictOn("src/a.c")
        val original = f.repositories.root.resolve("original-src")
        Files.move(f.workTree().resolve("src"), original)
        val outside = Files.createDirectory(f.repositories.root.resolve("outside"))
        Files.writeString(outside.resolve("a.c"), "OUTSIDE_WORKTREE_MARKER")
        Files.createSymbolicLink(f.workTree().resolve("src"), outside)
        assertEquals("UNSUPPORTED_CONFLICT", assertFailsWith<ManagedGitException> {
            service.conflictFile(jobId, repositoryId, null, fileId)
        }.code)
    }

    @Test fun `contained observations retain the directory and reject file replacement races`(): Unit = Fixture().use { f ->
        val tree = Files.createDirectory(f.repositories.root.resolve("tree"))
        val source = Files.createDirectory(tree.resolve("src"))
        val file = source.resolve("a.c")
        Files.writeString(file, "reviewed bytes\n")
        val outside = Files.createDirectory(f.repositories.root.resolve("outside"))
        Files.writeString(outside.resolve("a.c"), "OUTSIDE_WORKTREE_MARKER")
        val retained = f.repositories.root.resolve("retained")
        GitConflictFiles.withParent(tree, "src/a.c") { directory, name ->
            Files.move(source, retained)
            Files.createSymbolicLink(source, outside)
            val observed = GitConflictFiles.observe(directory, name)
            assertEquals("reviewed bytes\n", observed.text)
            assertEquals(GitStorage.sha256(checkNotNull(observed.text).toByteArray()), observed.sha256)
            assertEquals(15L, observed.size)
            assertEquals("CONTENT_CHANGED", assertFailsWith<GitOperationRefusal> {
                GitConflictFiles.observe(directory, name) {
                    val replacement = retained.resolve("replacement")
                    Files.writeString(replacement, "new unreviewed bytes\n")
                    Files.move(replacement, retained.resolve("a.c"), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
                }
            }.code)
        }
    }

    @Test fun `conflict saves respect leases at admission execution and publication`(): Unit = Fixture().use { f ->
        f.cloned()
        val fileId = f.conflictOn("README.md")
        val detail = service.conflictFile(jobId, repositoryId, null, fileId)
        val parameters = mapOf("fileId" to fileId, "expectedSha256" to detail.currentSha256, "resolution" to "text")
        f.runs["run_1"] = true
        refused("ACTIVE_RUN", GitOperationAction.CONFLICT_SAVE, parameters, "resolution\n")
        f.runs["run_1"] = false
        f.hook = { if (it == GitOperationCrashPoint.AFTER_RUNNING) f.runs["run_1"] = true }
        assertEquals("ACTIVE_RUN", sync(GitOperationAction.CONFLICT_SAVE, parameters, "resolution\n").failureCode)
        f.runs["run_1"] = false
        f.hook = { if (it == GitOperationCrashPoint.BEFORE_PUBLISH) f.runs["run_1"] = true }
        assertEquals("ACTIVE_RUN", sync(GitOperationAction.CONFLICT_SAVE, parameters, "resolution\n").failureCode)
        f.runs["run_1"] = false; f.hook = {}
        assertEquals(detail.current, Files.readString(f.workTree().resolve("README.md")))
    }

    @Test fun `a worker edit after validation is never overwritten at publication`(): Unit = Fixture().use { f ->
        f.cloned()
        val fileId = f.conflictOn("README.md")
        val detail = service.conflictFile(jobId, repositoryId, null, fileId)
        f.hook = { if (it == GitOperationCrashPoint.BEFORE_PUBLISH) Files.writeString(f.workTree().resolve("README.md"), "newer worker bytes\n") }
        val result = sync(GitOperationAction.CONFLICT_SAVE, mapOf("fileId" to fileId, "expectedSha256" to detail.currentSha256,
            "resolution" to "text"), "unpublished resolution\n")
        assertEquals("CONTENT_CHANGED", result.failureCode)
        assertEquals("newer worker bytes\n", Files.readString(f.workTree().resolve("README.md")))
        assertTrue(Files.list(f.workTree()).use { paths -> paths.noneMatch { it.fileName.toString().startsWith(".conflict-") } })
    }

    @Test fun `completion stages captured reviewed bytes even if the live file changes`(): Unit = Fixture().use { f ->
        f.cloned()
        val fileId = f.conflictOn("README.md")
        val detail = service.conflictFile(jobId, repositoryId, null, fileId)
        val resolution = "reviewed resolution\n"
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.CONFLICT_SAVE, mapOf("fileId" to fileId,
            "expectedSha256" to detail.currentSha256, "resolution" to "text"), resolution).state)
        val reviewed = service.conflictFile(jobId, repositoryId, null, fileId)
        val unreviewed = "<<<<<<< newer writer\nunreviewed\n=======\n>>>>>>> incoming\n"
        f.hook = { if (it == GitOperationCrashPoint.BEFORE_PUBLISH) Files.writeString(f.workTree().resolve("README.md"), unreviewed) }
        val result = sync(GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${reviewed.currentSha256}\n")
        assertEquals(GitOperationState.COMPLETED, result.state, result.message)
        val staged = f.repositories.git("--git-dir=${f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")}", "show", ":README.md")
        assertEquals(resolution, staged)
        assertEquals(unreviewed, Files.readString(f.workTree().resolve("README.md")))
        assertTrue(service.conflicts(jobId, repositoryId, null).files.isEmpty())
        assertTrue(service.workspace(jobId, repositoryId).observation.status.entries.any { it.unstaged != GitIndexChange.NONE })
    }

    @Test fun `large conflict indexes stream all stages and expose usable live pages and abort`(): Unit = Fixture().use { f ->
        f.cloned()
        f.conflictOn("README.md")
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val blob = f.repositories.git("--git-dir=$gitDir", "rev-parse", "HEAD:README.md").trim()
        val paths = (0 until 6000).map { "conflict${it.toString().padStart(5, '0')}.c" } + "conflict\t\n ü.c"
        val index = buildString { for (path in paths) for (stage in 1..3) append("100644 $blob $stage\t$path\u0000") }.toByteArray()
        f.repositories.runner.run(GitInvocation("update-index", listOf("-z", "--index-info"), gitDir = gitDir, workTree = f.workTree(), input = index))
        val raw = f.repositories.git("--git-dir=$gitDir", "--work-tree=${f.workTree()}", "ls-files", "-u", "-z")
        assertTrue(raw.toByteArray().size > 1024 * 1024, "the fixture exceeds the former complete-output ceiling")
        val all = GitIntegrations.conflicts(f.repositories.runner, gitDir, f.workTree())
        assertEquals(6002, all.size)
        for (entry in all.filter { it.path.exact in paths }) {
            assertEquals(blob, entry.baseObjectId); assertEquals(blob, entry.oursObjectId); assertEquals(blob, entry.theirsObjectId)
            assertEquals(setOf("100644"), entry.modes)
        }
        val listed = mutableListOf<String>()
        var offset = 0
        do {
            val page = service.conflicts(jobId, repositoryId, null, offset)
            assertTrue(page.mergeInProgress)
            assertEquals(6002, page.totalCount); assertEquals(offset, page.offset)
            assertTrue(page.files.size in 1..200)
            listed += page.files.map { checkNotNull(it.path.exact) }
            offset = page.nextOffset ?: break
        } while (true)
        assertEquals(all.map { it.path.exact }, listed)
        assertEquals(listed.size, listed.toSet().size)
        val last = all.last()
        val worktreeId = service.workspace(jobId, repositoryId).worktreeId
        val detail = service.conflictFile(jobId, repositoryId, null, last.path.fileId(worktreeId))
        assertEquals(blob, detail.entry.theirsObjectId)
        assertEquals("absent", detail.currentSha256)
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.MERGE_ABORT).state)
        assertEquals(0, service.conflicts(jobId, repositoryId, null).totalCount)
    }

    @Test fun `streamed Git output retains byte bounds and propagates consumer failures`(): Unit = Fixture().use { f ->
        f.cloned()
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val invocation = GitInvocation("ls-files", listOf("-s", "-z"), gitDir = gitDir, workTree = f.workTree())
        assertEquals(GitCommandException.Kind.OUTPUT_LIMIT, assertFailsWith<GitCommandException> {
            f.repositories.runner.stream(invocation, 16) { _, _ -> }
        }.kind)
        assertEquals("CONSUMER_TEST", assertFailsWith<GitOperationRefusal> {
            f.repositories.runner.stream(invocation, 1024 * 1024) { _, _ -> throw GitOperationRefusal("CONSUMER_TEST", "stop") }
        }.code)
    }

    @Test fun `terminal cleanup never consumes a running integration even when timestamps coincide`(): Unit = Fixture().use { f ->
        f.clock = java.time.Clock.fixed(java.time.Instant.parse("2026-10-26T00:00:00Z"), java.time.ZoneOffset.UTC)
        f.cloned()
        // A completed commit predates the next merge logically, but has the exact same wall clock.
        f.localCommit("local README\n")
        Files.writeString(f.seed.resolve("util.c"), "int incoming = 10;\n"); f.remoteCommit("incoming")
        fetch()
        val before = service.workspace(jobId, repositoryId).observation.head.objectId
        f.hook = { if (it == GitOperationCrashPoint.BEFORE_TERMINAL_PERSIST) throw SimulatedGitCrash() }
        val (view, g) = guards()
        val admission = service.requestWorkspace(jobId, repositoryId,
            GitSyncRequest(GitOperationAction.MERGE, view.worktreeId, g, merge("merge")), key())
        assertTrue(service.awaitIdle(60_000))
        val published = service.workspace(jobId, repositoryId).observation.head.objectId
        assertTrue(published != before)
        service.close(); f.hook = {}; service = f.open()
        val recovered = service.operation(jobId, repositoryId, admission.operation.operationId)
        assertEquals(GitOperationState.COMPLETED, recovered.state, recovered.message)
        assertEquals(published, recovered.resultObjectId)
    }

    @Test fun `merge evidence survives publication and a second crash during reconciliation`(): Unit = Fixture().use { f ->
        f.cloned()
        Files.writeString(f.seed.resolve("util.c"), "int incoming = 8;\n"); f.remoteCommit("incoming")
        fetch()
        val worktreeId = service.workspace(jobId, repositoryId).worktreeId
        val evidence = f.store.resolve("$jobId/git/repositories/$repositoryId/integrations/$worktreeId.json")
        val target = trackingObject()
        f.hook = { if (it == GitOperationCrashPoint.BEFORE_TERMINAL_PERSIST) throw SimulatedGitCrash() }
        val (view, g) = guards()
        val admission = service.requestWorkspace(jobId, repositoryId,
            GitSyncRequest(GitOperationAction.MERGE, view.worktreeId, g, merge("fast-forward")), key())
        assertTrue(service.awaitIdle(60_000))
        assertTrue(Files.exists(evidence), "published result keeps recovery evidence until terminal persistence")
        assertEquals(target, service.workspace(jobId, repositoryId).observation.head.objectId)
        service.close(); service = f.open(recover = false)
        // Only startup/mutation authority reconciles; GET must not perform cleanup.
        assertFailsWith<SimulatedGitCrash> { service.recover(listOf(jobId)) }
        assertTrue(Files.exists(evidence), "a second crash cannot consume the recovery evidence")
        service.close(); f.hook = {}; service = f.open()
        val recovered = service.operation(jobId, repositoryId, admission.operation.operationId)
        assertEquals(GitOperationState.COMPLETED, recovered.state, recovered.message)
        assertEquals(target, recovered.resultObjectId)
        assertFalse(Files.exists(evidence), "cleanup follows the durable terminal result")
    }

    @Test fun `durable terminal merge and abort records survive crashes before evidence cleanup`(): Unit = Fixture().use { f ->
        f.cloned()
        Files.writeString(f.seed.resolve("util.c"), "int incoming = 9;\n"); f.remoteCommit("incoming")
        fetch()
        val worktreeId = service.workspace(jobId, repositoryId).worktreeId
        val evidence = f.store.resolve("$jobId/git/repositories/$repositoryId/integrations/$worktreeId.json")
        f.hook = { if (it == GitOperationCrashPoint.AFTER_TERMINAL_PERSIST) throw SimulatedGitCrash() }
        val forwarded = sync(GitOperationAction.MERGE, merge("fast-forward"))
        assertEquals(GitOperationState.COMPLETED, forwarded.state)
        assertTrue(Files.exists(evidence))
        service.close(); f.hook = {}; service = f.open()
        assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, forwarded.operationId).state)
        assertFalse(Files.exists(evidence), "restart retries post-terminal cleanup")
        f.conflictOn("README.md")
        f.hook = { if (it == GitOperationCrashPoint.BEFORE_TERMINAL_PERSIST) throw SimulatedGitCrash() }
        val (view, g) = guards()
        val abort = service.requestWorkspace(jobId, repositoryId, GitSyncRequest(GitOperationAction.MERGE_ABORT, view.worktreeId, g), key())
        assertTrue(service.awaitIdle(60_000))
        assertFalse(service.conflicts(jobId, repositoryId, null).mergeInProgress)
        assertTrue(Files.exists(evidence), "abort retains evidence until terminal persistence")
        service.close(); f.hook = {}; service = f.open()
        assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, abort.operation.operationId).state)
        assertFalse(Files.exists(evidence))
        assertEquals("line one\nlocal two\n", Files.readString(f.workTree().resolve("README.md")))
    }

    @Test fun `restart never treats unrelated HEAD or branch movement as the reviewed integration`() {
        for (strategy in listOf("fast-forward", "merge")) {
            for (movement in listOf("local-commit", "other-branch", "detached", "target-without-merge")) {
                if (strategy == "fast-forward" && movement == "target-without-merge") continue
                Fixture().use { f ->
                    f.cloned()
                    // Include an old terminal commit: it must not retire this newer uncertain intent.
                    f.localCommit("local README\n")
                    Files.writeString(f.seed.resolve("util.c"), "int incoming = 11;\n"); f.remoteCommit("incoming")
                    fetch()
                    val target = trackingObject()
                    // A fast-forward needs a non-divergent branch; the old local commit stays recorded.
                    val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
                    if (strategy == "fast-forward") {
                        f.repositories.git("--git-dir=$gitDir", "--work-tree=${f.workTree()}", "reset", "--hard", "$target^")
                    }
                    f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) throw SimulatedGitCrash() }
                    val operation = sync(GitOperationAction.MERGE, merge(strategy))
                    val evidence = f.store.resolve("$jobId/git/repositories/$repositoryId/integrations/${operation.worktreeId}.json")
                    service.close()
                    val args = when (movement) {
                        "local-commit" -> arrayOf("commit", "--allow-empty", "-m", "unrelated local commit")
                        "other-branch" -> arrayOf("checkout", "-b", "elsewhere", target)
                        "detached" -> arrayOf("checkout", "--detach", target)
                        else -> arrayOf("reset", "--hard", target)
                    }
                    f.repositories.git("--git-dir=$gitDir", "--work-tree=${f.workTree()}", *args)
                    val actual = f.repositories.git("--git-dir=$gitDir", "rev-parse", "HEAD").trim()
                    f.hook = {}
                    repeat(2) {
                        service = f.open()
                        val recovered = service.operation(jobId, repositoryId, operation.operationId)
                        assertEquals(GitOperationState.RECOVERY_REQUIRED, recovered.state, "$strategy/$movement: ${recovered.message}")
                        assertEquals("HEAD_MOVED", recovered.failureCode)
                        assertEquals(actual, service.workspace(jobId, repositoryId).observation.head.objectId)
                        assertTrue(Files.exists(evidence), "uncertain integration evidence survives repeated restarts")
                        val (current, currentGuards) = guards()
                        assertEquals("WORKTREE_BUSY", assertFailsWith<ManagedGitException> {
                            service.requestWorkspace(jobId, repositoryId, GitSyncRequest(GitOperationAction.MERGE,
                                current.worktreeId, currentGuards, merge(strategy)), key())
                        }.code, "a new merge must not overwrite uncertain recovery evidence")
                        assertTrue(service.auditLog(jobId, repositoryId, 100).none { it["operationId"].toString().trim('"') == operation.operationId })
                        service.close()
                    }
                }
            }
        }
    }

    @Test fun `restart publishes exactly one audit receipt for merges conflicts and aborts before retiring evidence`() {
        for (kind in listOf("fast-forward", "merge", "conflicted", "abort")) Fixture().use { f ->
            f.cloned()
            if (kind == "abort") f.conflictOn("README.md")
            else {
                if (kind != "fast-forward") f.localCommit("local README\n")
                Files.writeString(f.seed.resolve(if (kind == "conflicted") "README.md" else "util.c"), "remote incoming\n")
                f.remoteCommit("incoming"); fetch()
            }
            val (view, g) = guards()
            val integrationBefore = service.conflicts(jobId, repositoryId, null).integration
            val before = integrationBefore?.headBefore ?: view.observation.head.objectId
            val target = integrationBefore?.target ?: trackingObject()
            val evidence = f.store.resolve("$jobId/git/repositories/$repositoryId/integrations/${view.worktreeId}.json")
            val action = if (kind == "abort") GitOperationAction.MERGE_ABORT else GitOperationAction.MERGE
            val parameters = if (kind == "abort") emptyMap() else merge(if (kind == "fast-forward") kind else "merge")
            f.hook = { if (it == GitOperationCrashPoint.AFTER_PUBLISH) throw SimulatedGitCrash() }
            val operation = sync(action, parameters)
            assertTrue(service.auditLog(jobId, repositoryId, 100).none { it["operationId"].toString().trim('"') == operation.operationId })
            assertTrue(Files.exists(evidence))
            val published = service.workspace(jobId, repositoryId).observation.head.objectId
            service.close()
            // A second crash after audit publication but before terminal persistence must not duplicate it.
            f.hook = { if (it == GitOperationCrashPoint.BEFORE_TERMINAL_PERSIST) throw SimulatedGitCrash() }
            service = f.open(recover = false)
            assertFailsWith<SimulatedGitCrash> { service.recover(listOf(jobId)) }
            assertTrue(Files.exists(evidence))
            service.close(); f.hook = {}
            repeat(2) {
                service = f.open()
                val recovered = service.operation(jobId, repositoryId, operation.operationId)
                assertEquals(if (kind == "conflicted") GitOperationState.RECOVERY_REQUIRED else GitOperationState.COMPLETED, recovered.state, recovered.message)
                val receipt = service.auditLog(jobId, repositoryId, 100).single { it["operationId"].toString().trim('"') == operation.operationId }
                assertEquals(if (kind == "abort") "merge.abort" else if (kind == "fast-forward") kind else "merge", receipt["action"].toString().trim('"'))
                assertEquals(if (kind == "conflicted") "conflicted" else "completed", receipt["outcome"].toString().trim('"'))
                assertEquals("refs/heads/main", receipt["ref"].toString().trim('"'))
                assertEquals(if (kind == "abort") target else before, receipt["oldObjectId"].toString().trim('"'))
                assertEquals(if (kind == "conflicted") target else published, receipt["newObjectId"].toString().trim('"'))
                if (kind != "abort") assertTrue(receipt["destination"].toString().contains("admitted:upstream.git"))
                assertEquals(kind == "conflicted", Files.exists(evidence))
                assertEquals(published, service.workspace(jobId, repositoryId).observation.head.objectId)
                service.close()
            }
        }
    }

    @Test fun `audit storage failure retains integration evidence and retries only under recovery authority`(): Unit = Fixture().use { f ->
        f.cloned()
        Files.writeString(f.seed.resolve("util.c"), "int incoming = 12;\n"); f.remoteCommit("incoming"); fetch()
        val directory = f.store.resolve("$jobId/git/repositories/$repositoryId")
        val audit = directory.resolve(GitRemoteStore.AUDIT)
        val retained = Files.readAllBytes(audit)
        f.hook = { point -> if (point == GitOperationCrashPoint.AFTER_PUBLISH) {
            Files.delete(audit); Files.createDirectory(audit)
        } }
        val operation = sync(GitOperationAction.MERGE, merge("fast-forward"))
        assertEquals(GitOperationState.RECOVERY_REQUIRED, operation.state, operation.message)
        assertEquals("STATE_UNKNOWN", operation.failureCode)
        val evidence = directory.resolve("integrations/${operation.worktreeId}.json")
        assertTrue(Files.exists(evidence))
        service.close(); f.hook = {}; service = f.open()
        assertEquals("STATE_UNKNOWN", service.operation(jobId, repositoryId, operation.operationId).failureCode)
        Files.delete(audit); Files.write(audit, retained)
        // Merely reading after storage repair cannot publish the pending audit.
        assertEquals("STATE_UNKNOWN", service.operation(jobId, repositoryId, operation.operationId).failureCode)
        assertTrue(Files.exists(evidence))
        service.recover(listOf(jobId))
        assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, operation.operationId).state)
        assertEquals(1, service.auditLog(jobId, repositoryId, 100).count { it["operationId"].toString().trim('"') == operation.operationId })
        assertFalse(Files.exists(evidence))
    }

    @Test fun `add-add modify-delete and rename conflicts retain exact stages and abort without losing local source`() {
        for (kind in listOf("add-add", "modify-delete", "rename-rename")) Fixture().use { f ->
            f.cloned()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            when (kind) {
                "add-add" -> {
                    Files.writeString(f.workTree().resolve("added.c"), "local added\n")
                    Files.writeString(f.seed.resolve("added.c"), "remote added\n")
                }
                "modify-delete" -> {
                    Files.writeString(f.workTree().resolve("README.md"), "local edited\n")
                    Files.delete(f.seed.resolve("README.md"))
                }
                else -> {
                    f.repositories.git("--git-dir=$gitDir", "--work-tree=${f.workTree()}", "mv", "README.md", "local.md")
                    f.repositories.git("-C", f.seed.toString(), "mv", "README.md", "remote.md")
                }
            }
            val before = f.repositories.commitAll(gitDir, f.workTree(), "local conflict setup")
            f.remoteCommit("remote conflict setup"); fetch()
            val target = trackingObject()
            f.hook = { if (it == GitOperationCrashPoint.AFTER_PUBLISH) throw SimulatedGitCrash() }
            val operation = sync(GitOperationAction.MERGE, merge("merge"))
            service.close(); f.hook = {}; service = f.open()
            val recovered = service.operation(jobId, repositoryId, operation.operationId)
            assertEquals("MERGE_IN_PROGRESS", recovered.failureCode, "$kind: ${recovered.message}")
            val conflicts = service.conflicts(jobId, repositoryId, null)
            assertEquals(before, conflicts.integration?.headBefore)
            assertEquals(target, conflicts.integration?.target)
            assertTrue(conflicts.files.isNotEmpty())
            when (kind) {
                "add-add" -> {
                    val entry = conflicts.files.single()
                    assertEquals("added.c", entry.path.exact)
                    assertNull(entry.baseObjectId); assertNotNull(entry.oursObjectId); assertNotNull(entry.theirsObjectId)
                    val detail = service.conflictFile(jobId, repositoryId, null, entry.path.fileId(conflicts.worktreeId))
                    assertNull(detail.base); assertEquals("local added\n", detail.ours); assertEquals("remote added\n", detail.theirs)
                }
                "modify-delete" -> {
                    val entry = conflicts.files.single()
                    assertEquals("README.md", entry.path.exact)
                    assertNotNull(entry.baseObjectId); assertNotNull(entry.oursObjectId); assertNull(entry.theirsObjectId)
                    refused("VALIDATION_FAILED", GitOperationAction.CONFLICT_SAVE, mapOf("fileId" to entry.path.fileId(conflicts.worktreeId),
                        "expectedSha256" to service.conflictFile(jobId, repositoryId, null, entry.path.fileId(conflicts.worktreeId)).currentSha256,
                        "resolution" to "theirs"))
                }
                else -> assertEquals(setOf("README.md", "local.md", "remote.md"), conflicts.files.map { it.path.exact }.toSet())
            }
            assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.MERGE_ABORT).state)
            assertEquals(before, service.workspace(jobId, repositoryId).observation.head.objectId)
            assertTrue(service.workspace(jobId, repositoryId).observation.status.entries.none { !it.ignored })
            assertEquals(1, service.auditLog(jobId, repositoryId, 100).count { it["operationId"].toString().trim('"') == operation.operationId })
        }
    }

    @Test fun `abort recovery uses retained server branch identity when client ref guards are omitted`() {
        for (retainedIntegration in listOf(true, false)) for (timing in listOf("before", "after", "branch-moved")) Fixture().use { f ->
            f.cloned(); f.conflictOn("README.md")
            val (view, g) = guards()
            val directory = f.store.resolve("$jobId/git/repositories/$repositoryId")
            if (!retainedIntegration) GitIntegrations.delete(directory, view.worktreeId) // An externally started merge.
            f.hook = { if (it == if (timing == "before") GitOperationCrashPoint.BEFORE_PUBLISH else GitOperationCrashPoint.AFTER_PUBLISH) throw SimulatedGitCrash() }
            val operation = run(GitSyncRequest(GitOperationAction.MERGE_ABORT, view.worktreeId,
                g.copy(expectedRefId = null, expectedRefObjectId = null)))
            service.close(); f.hook = {}
            if (timing == "branch-moved") f.repositories.git("--git-dir=${directory.resolve("repository.git")}",
                "--work-tree=${f.workTree()}", "checkout", "-b", "elsewhere")
            service = f.open()
            val recovered = service.operation(jobId, repositoryId, operation.operationId)
            assertEquals(when (timing) { "before" -> GitOperationState.INTERRUPTED; "after" -> GitOperationState.COMPLETED; else -> GitOperationState.RECOVERY_REQUIRED },
                recovered.state, "$retainedIntegration/$timing: ${recovered.message}")
            if (timing == "branch-moved") assertEquals("HEAD_MOVED", recovered.failureCode)
            val receipts = service.auditLog(jobId, repositoryId, 100).filter { it["operationId"].toString().trim('"') == operation.operationId }
            assertEquals(if (timing == "after") 1 else 0, receipts.size)
            if (timing == "after") {
                assertEquals("refs/heads/main", receipts.single()["ref"].toString().trim('"'))
                assertEquals(g.expectedHeadObjectId, recovered.resultObjectId)
                assertEquals("line one\nlocal two\n", Files.readString(f.workTree().resolve("README.md")))
            }
        }
    }

    @Test fun `merge refuses combined file byte and directory quotas before changing the live branch`() {
        for (bound in listOf("files", "bytes", "directories")) Fixture().use { f ->
            f.checkoutLimits = when (bound) {
                "files" -> GitCheckoutLimits(maxFiles = 5)
                "bytes" -> GitCheckoutLimits(maxBytes = 200)
                else -> GitCheckoutLimits(maxDirectories = 3)
            }
            f.cloned()
            for ((tree, side) in listOf(f.workTree() to "local", f.seed to "remote")) {
                if (bound == "bytes") Files.writeString(tree.resolve("$side.c"), "x".repeat(130))
                else repeat(2) { index ->
                    val path = if (bound == "directories") "$side$index/source.c" else "$side$index.c"
                    Files.createDirectories(tree.resolve(path).parent); Files.writeString(tree.resolve(path), "int $side$index;\n")
                }
            }
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val before = f.repositories.commitAll(gitDir, f.workTree(), "local additions")
            f.remoteCommit("remote additions"); fetch()
            val target = trackingObject()
            // Each individual checkout fits. It is their combined result that exceeds this quota.
            for (objectId in listOf(before, target)) GitRepositoryImport.requireCheckoutBounds(f.repositories.runner, gitDir, objectId, f.checkoutLimits)
            refused("REPOSITORY_UNSUPPORTED", GitOperationAction.MERGE, merge("merge"))
            assertEquals(before, service.workspace(jobId, repositoryId).observation.head.objectId)
            assertFalse(GitIntegrations.mergeInProgress(gitDir))
            assertFalse(Files.exists(f.workTree().resolve(if (bound == "bytes") "remote.c" else if (bound == "directories") "remote0" else "remote0.c")))
            assertNull(service.conflicts(jobId, repositoryId, null).integration)
        }
    }

    @Test fun `conflict save flushes file then the pinned rename directory before acknowledging`(): Unit = Fixture().use { f ->
        val tree = Files.createDirectory(f.repositories.root.resolve("tree"))
        val source = Files.createDirectory(tree.resolve("src"))
        val file = Files.writeString(source.resolve("a.c"), "old\n")
        val outside = Files.createDirectory(f.repositories.root.resolve("outside"))
        Files.writeString(outside.resolve("a.c"), "OUTSIDE_WORKTREE_MARKER")
        val retained = f.repositories.root.resolve("retained")
        val expected = GitConflictFiles.observe(tree, "src/a.c").sha256
        val order = mutableListOf<String>()
        GitConflictFiles.replace(tree, "src/a.c", expected, "durable resolution\n".toByteArray(), afterSync = { point ->
            order += point.name
            if (point == GitConflictFiles.DurabilityPoint.PREPARED_FILE) assertEquals("old\n", Files.readString(file))
        }) {
            order += "guard"
            Files.move(source, retained); Files.createSymbolicLink(source, outside)
        }
        assertEquals(listOf("PREPARED_FILE", "guard", "PUBLISHED_DIRECTORY"), order)
        assertEquals("durable resolution\n", Files.readString(retained.resolve("a.c")))
        assertEquals("OUTSIDE_WORKTREE_MARKER", Files.readString(outside.resolve("a.c")))
        assertTrue(Files.list(retained).use { files -> files.noneMatch { it.fileName.toString().startsWith(".conflict-") } })
    }

    @Test fun `symbolic link conflicts remain unsupported even when materialized as plain files`(): Unit = Fixture().use { f ->
        Files.createSymbolicLink(f.seed.resolve("link"), Path.of("base-target")); f.remoteCommit("base link")
        f.cloned()
        f.localCommit("ours-target", "link")
        Files.delete(f.seed.resolve("link")); Files.createSymbolicLink(f.seed.resolve("link"), Path.of("theirs-target")); f.remoteCommit("remote link")
        fetch()
        val merged = sync(GitOperationAction.MERGE, merge("merge"))
        assertTrue(merged.message.contains("1 conflicted file"), merged.message)
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        fun index() = f.repositories.git("--git-dir=$gitDir", "--work-tree=${f.workTree()}", "ls-files", "-s", "--", "link")
        val before = index()
        assertTrue(before.lines().filter { it.isNotBlank() }.all { it.startsWith("120000 ") }, before)
        assertTrue(Files.isRegularFile(f.workTree().resolve("link"), java.nio.file.LinkOption.NOFOLLOW_LINKS))
        val conflicts = service.conflicts(jobId, repositoryId, null)
        val entry = conflicts.files.single()
        assertEquals(setOf("120000"), entry.modes)
        val fileId = entry.path.fileId(conflicts.worktreeId)
        val detail = service.conflictFile(jobId, repositoryId, null, fileId)
        assertNull(detail.current, "the response reports unsupported instead of offering plain-file completion")
        refused("UNSUPPORTED_CONFLICT", GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${detail.currentSha256}\n")
        refused("UNSUPPORTED_CONFLICT", GitOperationAction.CONFLICT_SAVE, mapOf("fileId" to fileId,
            "expectedSha256" to detail.currentSha256, "resolution" to "text"), "new-target")
        assertEquals(before, index(), "no index type or stage changed")
        assertEquals("ours-target", Files.readString(f.workTree().resolve("link")))
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.MERGE_ABORT).state)
    }

    @Test fun `merge and abort exclude workflow admission through publication`(): Unit = Fixture().use { f ->
        f.cloned()
        Files.writeString(f.seed.resolve("util.c"), "int incoming = 7;\n"); f.remoteCommit("incoming")
        fetch()
        val before = service.workspace(jobId, repositoryId).observation.head.objectId
        for (point in listOf(GitOperationCrashPoint.AFTER_STAGING, GitOperationCrashPoint.BEFORE_PUBLISH)) {
            f.hook = { if (it == point) {
                if (point == GitOperationCrashPoint.BEFORE_PUBLISH) assertTrue(f.stable)
                f.runs["run_1"] = true
            } }
            assertEquals("ACTIVE_RUN", sync(GitOperationAction.MERGE, merge("fast-forward")).failureCode)
            assertEquals(before, service.workspace(jobId, repositoryId).observation.head.objectId)
            assertEquals("int util;\n", Files.readString(f.workTree().resolve("util.c")))
            f.runs["run_1"] = false
        }
        f.hook = { if (it == GitOperationCrashPoint.BEFORE_PUBLISH) assertTrue(f.stable) }
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.MERGE, merge("fast-forward")).state)
        f.hook = {}
        f.conflictOn("README.md")
        val conflicted = Files.readString(f.workTree().resolve("README.md"))
        for (point in listOf(GitOperationCrashPoint.AFTER_STAGING, GitOperationCrashPoint.BEFORE_PUBLISH)) {
            f.hook = { if (it == point) {
                if (point == GitOperationCrashPoint.BEFORE_PUBLISH) assertTrue(f.stable)
                f.runs["run_1"] = true
            } }
            assertEquals("ACTIVE_RUN", sync(GitOperationAction.MERGE_ABORT).failureCode)
            assertEquals(conflicted, Files.readString(f.workTree().resolve("README.md")))
            assertTrue(service.conflicts(jobId, repositoryId, null).mergeInProgress)
            f.runs["run_1"] = false
        }
        f.hook = { if (it == GitOperationCrashPoint.BEFORE_PUBLISH) assertTrue(f.stable) }
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.MERGE_ABORT).state)
    }

    @Test fun `a workflow that writes and finishes before exclusion blocks merge`(): Unit = Fixture().use { f ->
        f.cloned()
        Files.writeString(f.seed.resolve("util.c"), "int incoming = 21;\n"); f.remoteCommit("incoming")
        fetch()
        val before = service.workspace(jobId, repositoryId).observation.head.objectId
        f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) {
            assertFalse(f.stable)
            f.runs["run_1"] = true
            Files.writeString(f.workTree().resolve("README.md"), "workflow finished dirty edit\n")
            f.runs["run_1"] = false
        } }
        val result = sync(GitOperationAction.MERGE, merge("fast-forward"))
        assertEquals("WORKTREE_CHANGED", result.failureCode, result.message)
        assertEquals(before, service.workspace(jobId, repositoryId).observation.head.objectId)
        assertEquals("workflow finished dirty edit\n", Files.readString(f.workTree().resolve("README.md")))
        assertEquals("int util;\n", Files.readString(f.workTree().resolve("util.c")))
    }

    @Test fun `abort preserves a newer resolution from a workflow finished before exclusion`(): Unit = Fixture().use { f ->
        f.cloned()
        f.conflictOn("README.md")
        val updated = "new workflow resolution not reviewed by the abort request\n"
        val (review, guard) = guards()
        f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) {
            assertFalse(f.stable)
            f.runs["run_1"] = true
            Files.writeString(f.workTree().resolve("README.md"), updated)
            f.runs["run_1"] = false
        } }
        val result = run(GitSyncRequest(GitOperationAction.MERGE_ABORT, review.worktreeId, guard))
        assertEquals("WORKTREE_CHANGED", result.failureCode, result.message)
        assertEquals(updated, Files.readString(f.workTree().resolve("README.md")))
        assertTrue(service.conflicts(jobId, repositoryId, null).mergeInProgress)
        f.hook = {}
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.MERGE_ABORT).state)
    }

    @Test fun `every published resolution choice recovers and replays as completed`() {
        for (side in listOf("ours", "theirs", "base", "text")) Fixture().use { f ->
            f.cloned()
            val fileId = f.conflictOn("README.md")
            val detail = service.conflictFile(jobId, repositoryId, null, fileId)
            val (view, guard) = guards()
            val request = GitSyncRequest(GitOperationAction.CONFLICT_SAVE, view.worktreeId, guard,
                mapOf("fileId" to fileId, "expectedSha256" to detail.currentSha256, "resolution" to side),
                if (side == "text") "custom resolution\n" else null)
            val expected = when (side) { "ours" -> detail.ours; "theirs" -> detail.theirs; "base" -> detail.base; else -> "custom resolution\n" }
            f.hook = { if (it == GitOperationCrashPoint.BEFORE_TERMINAL_PERSIST) throw SimulatedGitCrash() }
            val idempotencyKey = key()
            val admission = service.requestWorkspace(jobId, repositoryId, request, idempotencyKey)
            assertTrue(service.awaitIdle(60_000))
            assertEquals(expected, Files.readString(f.workTree().resolve("README.md")), side)
            service.close(); f.hook = {}; service = f.open()
            val recovered = service.operation(jobId, repositoryId, admission.operation.operationId)
            assertEquals(GitOperationState.COMPLETED, recovered.state, "$side: ${recovered.message}")
            val replay = service.requestWorkspace(jobId, repositoryId, request, idempotencyKey)
            assertTrue(replay.replayed)
            assertEquals(GitOperationState.COMPLETED, replay.operation.state, side)
            assertEquals(admission.operation.operationId, replay.operation.operationId)
        }
    }

    @Test fun `restart never completes a side save whose bytes were not published or were replaced`() {
        for (changed in listOf(false, true)) Fixture().use { f ->
            f.cloned()
            val fileId = f.conflictOn("README.md")
            val detail = service.conflictFile(jobId, repositoryId, null, fileId)
            val (view, guard) = guards()
            val request = GitSyncRequest(GitOperationAction.CONFLICT_SAVE, view.worktreeId, guard,
                mapOf("fileId" to fileId, "expectedSha256" to detail.currentSha256, "resolution" to "ours"))
            val point = if (changed) GitOperationCrashPoint.BEFORE_TERMINAL_PERSIST else GitOperationCrashPoint.AFTER_STAGING
            f.hook = { if (it == point) throw SimulatedGitCrash() }
            val admission = service.requestWorkspace(jobId, repositoryId, request, key())
            assertTrue(service.awaitIdle(60_000))
            if (changed) Files.writeString(f.workTree().resolve("README.md"), "newer unreviewed bytes\n")
            val expected = Files.readString(f.workTree().resolve("README.md"))
            service.close(); f.hook = {}; service = f.open()
            assertEquals(GitOperationState.INTERRUPTED, service.operation(jobId, repositoryId, admission.operation.operationId).state)
            assertEquals(expected, Files.readString(f.workTree().resolve("README.md")))
        }
    }

    @Test fun `long escaped conflict paths stay selectable and keep operation records readable`(): Unit = Fixture().use { f ->
        val path = ("p" + "\u0001".repeat(99) + "/").repeat(15) + "conflict.c"
        val source = f.seed.resolve(path)
        Files.createDirectories(source.parent)
        Files.writeString(source, "line one\nline two\n")
        f.remoteCommit("admitted long path")
        f.cloned()
        val fileId = f.conflictOn(path)
        val detail = service.conflictFile(jobId, repositoryId, null, fileId)
        assertTrue(detail.entry.path.display.length > 8000)
        val saved = sync(GitOperationAction.CONFLICT_SAVE,
            mapOf("fileId" to fileId, "expectedSha256" to detail.currentSha256, "resolution" to "ours"))
        assertEquals(GitOperationState.COMPLETED, saved.state)
        assertTrue(saved.message.length <= 500)
        service.close(); service = f.open()
        assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, saved.operationId).state)
        val current = service.conflictFile(jobId, repositoryId, null, fileId)
        assertEquals(detail.ours, current.current)
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${current.currentSha256}\n").state)
        assertTrue(service.conflicts(jobId, repositoryId, null).files.isEmpty())
        assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.MERGE_ABORT).state)
        assertEquals(detail.ours, Files.readString(f.workTree().resolve(path)))
    }

    @Test fun `the content digest is streamed and matches the file bytes`(): Unit = Fixture().use { f ->
        val file = f.repositories.root.resolve("large.bin")
        val bytes = ByteArray(3 * 1024 * 1024 + 17) { (it % 251).toByte() }
        Files.write(file, bytes)
        assertEquals(GitStorage.sha256(bytes), GitIntegrations.contentDigest(file))
        assertEquals("absent", GitIntegrations.contentDigest(f.repositories.root.resolve("missing")))
    }

    @Test fun `an oversized conflict is refused at completion without being loaded`(): Unit = Fixture().use { f ->
        f.cloned()
        val large = "x".repeat(GitIntegrations.MAX_TEXT_BYTES)
        f.localCommit("line one\nlocal two\n$large\n")
        Files.writeString(f.seed.resolve("README.md"), "line one\nremote two\n$large\n"); f.remoteCommit("remote edit")
        fetch()
        sync(GitOperationAction.MERGE, merge("merge"))
        val fileId = service.conflicts(jobId, repositoryId, null).files.single().path.fileId(service.workspace(jobId, repositoryId).worktreeId)
        val detail = service.conflictFile(jobId, repositoryId, null, fileId)
        assertNull(detail.current, "an oversized current file is not offered as text")
        refused("UNSUPPORTED_CONFLICT", GitOperationAction.CONFLICT_COMPLETE, content = "$fileId ${detail.currentSha256}\n")
        assertEquals(null, GitIntegrations.fileText(f.workTree().resolve("README.md")))
        assertEquals("", GitIntegrations.fileText(f.workTree().resolve("missing.txt")))
    }
}
