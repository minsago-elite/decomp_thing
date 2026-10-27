package decompengine.git

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.io.path.exists
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GitBranchesWorktreesTest {
    private val jobId = "0123456789abcdef0123456789abcdef"

    private class Fixture(val repositories: GitTestRepositories = GitTestRepositories()) : AutoCloseable {
        val store: Path = Files.createDirectories(repositories.root.resolve("store"))
        val snapshot: Path = Files.createDirectories(store.resolve("0123456789abcdef0123456789abcdef/reports/runs/run_1/source-tree"))
        var hook: (GitOperationCrashPoint) -> Unit = {}
        val runs = java.util.concurrent.ConcurrentHashMap(mapOf("run_1" to false, "run_2" to false))
        val leases = GitWorkspaceLeases()
        private val opened = mutableListOf<ManagedGitRepositories>()
        init {
            mapOf("CMakeLists.txt" to "project(fixture C)\n", "src/main.c" to "int main(void) { return 0; }\n").forEach { (name, text) ->
                Files.createDirectories(snapshot.resolve(name).parent); Files.writeString(snapshot.resolve(name), text)
            }
        }
        fun open() = ManagedGitRepositories(store, GitRuntime.detect(), { _, run, revision ->
            GitSourceSnapshot(snapshot, run, revision, "a".repeat(64), mapOf("src/main.c" to GitSourceCommitment(
                GitSourceCopy.digestOf(snapshot.resolve("src/main.c")), Files.size(snapshot.resolve("src/main.c")))))
        }, policy = GitRepositoryPolicy(defaultBranch = "trunk"), crash = { hook(it) }, activity = { runs.toMap() },
            workspaceLeases = leases).also(opened::add)
        override fun close() { opened.forEach { it.close() }; repositories.close() }
    }

    private lateinit var service: ManagedGitRepositories
    private lateinit var repositoryId: String

    private fun guards(worktreeId: String? = null): Pair<GitWorkspaceView, GitGuards> {
        val view = service.workspace(jobId, repositoryId, worktreeId)
        return view to GitGuards(GitWorkspaceVersions.repositoryVersion(view.record, view.observation),
            GitWorkspaceVersions.worktreeVersion(view.observation), view.observation.head.objectId,
            GitWorkspaceVersions.headRefId(view.record, view.observation),
            view.observation.head.objectId.takeIf { view.observation.head.state == GitHeadState.ATTACHED })
    }

    private var keys = 0
    private fun run(request: GitRepositoryRequest): GitOperationRecord {
        val admission = service.requestWorkspace(jobId, repositoryId, request, "branch_key_${(++keys).toString().padStart(8, '0')}")
        assertTrue(service.awaitIdle(60_000))
        return service.operation(jobId, repositoryId, admission.operation.operationId)
    }

    private fun refused(code: String, request: GitRepositoryRequest) = assertEquals(code,
        assertFailsWith<ManagedGitException>(code) { service.requestWorkspace(jobId, repositoryId, request, "refused_key_${(++keys).toString().padStart(8, '0')}") }.code)

    private fun refId(name: String) = GitWorkspaceVersions.refId(repositoryId, name)

    /** Initialize from the snapshot and commit everything once; returns the base commit. */
    private fun Fixture.prepare(): String {
        service = open()
        val admission = service.request(jobId, GitRepositoryRequest.Init("run_1", "revision_1", null), "init_key_00000001")
        assertTrue(service.awaitIdle(60_000)); repositoryId = admission.operation.repositoryId
        val (view, guards) = guards()
        run(GitStageRequest(view.record.worktreeId, guards, view.observation.status.entries.filter { it.untracked }
            .map { it.path.fileId(view.worktreeId) }, true))
        val (staged, stagedGuards) = guards()
        return assertNotNull(run(GitCommitRequest(staged.record.worktreeId, stagedGuards, staged.observation.status.entries
            .filter { it.staged != GitIndexChange.NONE }.map { it.path.fileId(staged.worktreeId) }, "base")).resultObjectId)
    }

    private fun Fixture.workTree() = store.resolve("$jobId/git/repositories/$repositoryId/worktree")
    private fun Fixture.gitDir() = store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
    private fun Fixture.raw(vararg args: String, worktree: Path = workTree(), gitDir: Path = gitDir()) =
        repositories.git("--git-dir=$gitDir", "--work-tree=$worktree", *args, cwd = worktree)

    @Test fun `worker lock reads distinguish the primary tree from each linked owner`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val primary = service.workspace(jobId, repositoryId).worktreeId
        val owned = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, objectId = base, runId = "run_1")).worktreeId
        val unowned = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, objectId = base)).worktreeId
        assertFalse(service.activeWorker(jobId, repositoryId))
        f.runs["run_2"] = true
        assertTrue(service.activeWorker(jobId, repositoryId, primary))
        assertFalse(service.activeWorker(jobId, repositoryId, owned))
        assertFalse(service.activeWorker(jobId, repositoryId, unowned))
        f.runs["run_1"] = true
        assertTrue(service.activeWorker(jobId, repositoryId, owned))
        assertFalse(service.busy(jobId))
        f.runs.replaceAll { _, _ -> false }
        assertFalse(service.activeWorker(jobId, repositoryId, owned))
        assertFalse(service.activeWorker(jobId, repositoryId))
    }

    @Test fun `branches are created at an exact base and switched only when clean and unleased`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val worktree = service.workspace(jobId, repositoryId).worktreeId
        val (_, g) = guards()
        assertEquals(base, run(GitRefRequest(GitOperationAction.BRANCH_CREATE, worktree, g, name = "feature", objectId = base)).resultObjectId)
        val (_, g2) = guards()
        refused("BRANCH_EXISTS", GitRefRequest(GitOperationAction.BRANCH_CREATE, worktree, g2, name = "feature", objectId = base))
        refused("VALIDATION_FAILED", GitRefRequest(GitOperationAction.BRANCH_CREATE, worktree, g2, name = "bad..name", objectId = base))
        refused("VALIDATION_FAILED", GitRefRequest(GitOperationAction.BRANCH_CREATE, worktree, g2, name = "short", objectId = base.take(12)))
        refused("NOT_FOUND", GitRefRequest(GitOperationAction.BRANCH_CREATE, worktree, g2, name = "missing", objectId = "1".repeat(40)))
        // Dirty work and active workers block a switch; nothing is stashed or discarded.
        Files.writeString(f.workTree().resolve("src/main.c"), "int main(void) { return 9; }\n")
        val (_, dirty) = guards()
        refused("WORKTREE_DIRTY", GitRefRequest(GitOperationAction.SWITCH, worktree, dirty, refId = refId("refs/heads/feature")))
        assertEquals("int main(void) { return 9; }\n", Files.readString(f.workTree().resolve("src/main.c")))
        f.raw("checkout", "--", "src/main.c")
        Files.writeString(f.workTree().resolve("notes.txt"), "kept untracked\n")
        f.runs["run_2"] = true
        val (_, clean) = guards()
        refused("ACTIVE_RUN", GitRefRequest(GitOperationAction.SWITCH, worktree, clean, refId = refId("refs/heads/feature")))
        f.runs["run_2"] = false
        refused("VALIDATION_FAILED", GitRefRequest(GitOperationAction.SWITCH, worktree, clean))
        val switched = run(GitRefRequest(GitOperationAction.SWITCH, worktree, clean, refId = refId("refs/heads/feature")))
        assertEquals(GitOperationState.COMPLETED, switched.state, switched.message)
        assertEquals("refs/heads/feature", service.workspace(jobId, repositoryId).observation.head.refName)
        assertTrue(f.workTree().resolve("notes.txt").exists())
        // Deleting is explicit: never the current branch, never unmerged work.
        Files.delete(f.workTree().resolve("notes.txt"))
        Files.writeString(f.workTree().resolve("src/main.c"), "int main(void) { return 2; }\n")
        f.raw("commit", "-q", "-am", "feature work")
        val featureTip = f.repositories.git("--git-dir=${f.gitDir()}", "rev-parse", "refs/heads/feature").trim()
        val (_, onFeature) = guards()
        refused("BRANCH_CURRENT", GitRefRequest(GitOperationAction.BRANCH_DELETE, worktree, onFeature, refId = refId("refs/heads/feature"), objectId = featureTip))
        run(GitRefRequest(GitOperationAction.SWITCH, worktree, onFeature, refId = refId("refs/heads/trunk")))
        val (_, onTrunk) = guards()
        refused("REF_CHANGED", GitRefRequest(GitOperationAction.BRANCH_DELETE, worktree, onTrunk, refId = refId("refs/heads/feature"), objectId = base))
        refused("BRANCH_UNMERGED", GitRefRequest(GitOperationAction.BRANCH_DELETE, worktree, onTrunk, refId = refId("refs/heads/feature"), objectId = featureTip))
        // Tags identify exact targets and are never overwritten.
        assertEquals(featureTip, run(GitRefRequest(GitOperationAction.TAG, worktree, onTrunk, name = "reviewed-1", objectId = featureTip)).resultObjectId)
        val (_, tagged) = guards()
        refused("TAG_EXISTS", GitRefRequest(GitOperationAction.TAG, worktree, tagged, name = "reviewed-1", objectId = base))
        assertEquals(featureTip, f.repositories.git("--git-dir=${f.gitDir()}", "rev-parse", "refs/tags/reviewed-1").trim())
        val deleted = run(GitRefRequest(GitOperationAction.BRANCH_DELETE, worktree, tagged, refId = refId("refs/heads/feature"), objectId = featureTip))
        assertEquals(GitOperationState.COMPLETED, deleted.state, deleted.message)
        assertNull(GitRefOperations.refObject(f.repositories.runner, f.gitDir(), GitObjectFormat.SHA1, "refs/heads/feature"))
    }

    @Test fun `linked work trees are contained, bounded, owned and removed only when clean and merged`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val primary = service.workspace(jobId, repositoryId).worktreeId
        val (_, g) = guards()
        refused("VALIDATION_FAILED", GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, g, objectId = base, runId = "run_unknown"))
        val added = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, g, name = "experiment", objectId = base, runId = "run_1"))
        assertEquals(GitOperationState.COMPLETED, added.state, added.message)
        val linked = added.worktreeId
        assertNotEquals(primary, linked)
        val path = f.store.resolve("$jobId/git/repositories/$repositoryId/worktrees/$linked")
        assertTrue(path.resolve("src/main.c").exists())
        val view = service.workspace(jobId, repositoryId, linked)
        assertEquals("refs/heads/experiment", view.observation.head.refName); assertEquals("run_1", view.ownerRunId)
        assertEquals(listOf(primary, linked), service.worktrees(jobId, repositoryId).map { it.worktreeId })
        // The linked work tree has its own index and guards: stage and commit there.
        Files.writeString(path.resolve("src/extra.c"), "int extra;\n")
        val (linkedView, linkedGuards) = guards(linked)
        run(GitStageRequest(linked, linkedGuards, linkedView.observation.status.entries.filter { it.untracked }.map { it.path.fileId(linked) }, true))
        val (stagedView, stagedGuards) = guards(linked)
        val commit = run(GitCommitRequest(linked, stagedGuards, stagedView.observation.status.entries.filter { it.staged != GitIndexChange.NONE }
            .map { it.path.fileId(linked) }, "linked work"))
        assertEquals(GitOperationState.COMPLETED, commit.state, commit.message)
        assertEquals(base, service.workspace(jobId, repositoryId).observation.head.objectId)
        // Removal is refused while its owner runs, while dirty, and while detached commits are unmerged.
        f.runs["run_1"] = true
        val (_, leased) = guards(linked)
        refused("ACTIVE_RUN", GitRefRequest(GitOperationAction.WORKTREE_REMOVE, linked, leased))
        f.runs["run_1"] = false
        refused("WORKTREE_PRIMARY", GitRefRequest(GitOperationAction.WORKTREE_REMOVE, primary, guards().second))
        Files.writeString(path.resolve("scratch.c"), "int scratch;\n")
        refused("WORKTREE_DIRTY", GitRefRequest(GitOperationAction.WORKTREE_REMOVE, linked, guards(linked).second))
        Files.delete(path.resolve("scratch.c"))
        // Ignored local files (experiment output) are never deleted with the work tree either.
        Files.writeString(path.resolve("result.log"), "experiment output\n")
        refused("WORKTREE_DIRTY", GitRefRequest(GitOperationAction.WORKTREE_REMOVE, linked, guards(linked).second))
        assertEquals("experiment output\n", Files.readString(path.resolve("result.log")))
        Files.delete(path.resolve("result.log"))
        val linkedGit = f.gitDir().resolve("worktrees/$linked")
        // Files inside an uninitialized gitlink directory are invisible to status but still protected.
        f.raw("update-index", "--add", "--cacheinfo", "160000,$base,vendor", worktree = path, gitDir = linkedGit)
        f.raw("commit", "-q", "-m", "gitlink", worktree = path, gitDir = linkedGit)
        Files.createDirectories(path.resolve("vendor")); Files.writeString(path.resolve("vendor/result.dat"), "output\n")
        assertTrue(service.workspace(jobId, repositoryId, linked).observation.status.entries.isEmpty())
        refused("WORKTREE_DIRTY", GitRefRequest(GitOperationAction.WORKTREE_REMOVE, linked, guards(linked).second))
        assertEquals("output\n", Files.readString(path.resolve("vendor/result.dat")))
        Files.delete(path.resolve("vendor/result.dat"))
        f.raw("checkout", "-q", "--detach", worktree = path, gitDir = linkedGit)
        Files.writeString(path.resolve("src/extra.c"), "int extra = 2;\n")
        f.raw("commit", "-q", "-am", "detached only", worktree = path, gitDir = linkedGit)
        refused("WORKTREE_UNMERGED", GitRefRequest(GitOperationAction.WORKTREE_REMOVE, linked, guards(linked).second))
        f.raw("checkout", "-q", "experiment", worktree = path, gitDir = linkedGit)
        val removed = run(GitRefRequest(GitOperationAction.WORKTREE_REMOVE, linked, guards(linked).second))
        assertEquals(GitOperationState.COMPLETED, removed.state, removed.message)
        assertFalse(path.exists())
        assertEquals(listOf(primary), service.worktrees(jobId, repositoryId).map { it.worktreeId })
        // At most four linked work trees exist at once.
        repeat(GitRefOperations.MAX_LINKED_WORKTREES) {
            assertEquals(GitOperationState.COMPLETED, run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, objectId = base)).state)
        }
        refused("QUOTA_EXCEEDED", GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, objectId = base))
    }

    @Test fun `restart reconciles branch, switch and work-tree intents with actual refs`(): Unit {
        Fixture().use { f ->
            val base = f.prepare()
            val worktree = service.workspace(jobId, repositoryId).worktreeId
            f.hook = { if (it == GitOperationCrashPoint.AFTER_PUBLISH) throw SimulatedGitCrash() }
            val created = service.requestWorkspace(jobId, repositoryId,
                GitRefRequest(GitOperationAction.BRANCH_CREATE, worktree, guards().second, name = "feature", objectId = base), "restart_key_000001")
            assertTrue(service.awaitIdle(60_000)); service.close()
            f.hook = {}
            service = f.open()
            assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, created.operation.operationId).state)
            // A switch that finished, followed by an external deletion of its branch, is reported as unborn.
            f.hook = { if (it == GitOperationCrashPoint.AFTER_PUBLISH) throw SimulatedGitCrash() }
            val switched = service.requestWorkspace(jobId, repositoryId,
                GitRefRequest(GitOperationAction.SWITCH, worktree, guards().second, refId = refId("refs/heads/feature")), "restart_key_000002")
            assertTrue(service.awaitIdle(60_000)); service.close()
            f.repositories.git("--git-dir=${f.gitDir()}", "update-ref", "-d", "refs/heads/feature")
            f.hook = {}
            service = f.open()
            val recovered = service.operation(jobId, repositoryId, switched.operation.operationId)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, recovered.state); assertEquals("REF_DELETED", recovered.failureCode)
            assertEquals(GitHeadState.UNBORN, service.workspace(jobId, repositoryId).observation.head.state)
        }
        Fixture().use { f ->
            val base = f.prepare()
            val primary = service.workspace(jobId, repositoryId).worktreeId
            f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) throw SimulatedGitCrash() }
            val added = service.requestWorkspace(jobId, repositoryId,
                GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, objectId = base), "restart_key_000003")
            assertTrue(service.awaitIdle(60_000)); service.close()
            val path = f.store.resolve("$jobId/git/repositories/$repositoryId/worktrees/${added.operation.worktreeId}")
            assertTrue(path.exists())
            f.hook = {}
            service = f.open()
            assertEquals(GitOperationState.INTERRUPTED, service.operation(jobId, repositoryId, added.operation.operationId).state)
            assertFalse(path.exists())
            assertEquals(listOf(primary), service.worktrees(jobId, repositoryId).map { it.worktreeId })
            assertFalse(f.repositories.git("--git-dir=${f.gitDir()}", "worktree", "list", "--porcelain").contains(added.operation.worktreeId))
            // Recovery never touched the recorded source snapshot.
            assertEquals("int main(void) { return 0; }\n", Files.readString(f.snapshot.resolve("src/main.c")))
        }
    }

    @Test fun `linked work trees cannot share a branch, resolve every ref page and recover their own commits`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val primary = service.workspace(jobId, repositoryId).worktreeId
        val linked = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, objectId = base)).worktreeId
        // The primary checkout is invisible to Git's own check in the bare layout; the workbench refuses.
        refused("BRANCH_CURRENT", GitRefRequest(GitOperationAction.SWITCH, linked, guards(linked).second, refId = refId("refs/heads/trunk")))
        // Branch identities beyond the first 200 refs still resolve.
        (1..210).forEach { f.repositories.git("--git-dir=${f.gitDir()}", "branch", "b%03d".format(it), base) }
        // Past the observed refs bound the guards cannot cover the destination: its reviewed tip is required.
        refused("VALIDATION_FAILED", GitRefRequest(GitOperationAction.SWITCH, linked, guards(linked).second, refId = refId("refs/heads/b205")))
        f.repositories.git("--git-dir=${f.gitDir()}", "update-ref", "refs/heads/b206", f.repositories.git("--git-dir=${f.gitDir()}", "commit-tree",
            "-p", base, "-m", "moved", "$base^{tree}").trim())
        refused("REF_CHANGED", GitRefRequest(GitOperationAction.SWITCH, linked, guards(linked).second, refId = refId("refs/heads/b206"), objectId = base))
        val switched = run(GitRefRequest(GitOperationAction.SWITCH, linked, guards(linked).second, refId = refId("refs/heads/b205"), objectId = base))
        assertEquals(GitOperationState.COMPLETED, switched.state, switched.message)
        assertEquals("refs/heads/b205", service.workspace(jobId, repositoryId, linked).observation.head.refName)
        // A commit in the linked work tree that crashes after Git ran is classified by that work tree's HEAD.
        val path = f.store.resolve("$jobId/git/repositories/$repositoryId/worktrees/$linked")
        Files.writeString(path.resolve("src/new.c"), "int fresh;\n")
        val (view, g) = guards(linked)
        run(GitStageRequest(linked, g, view.observation.status.entries.filter { it.untracked }.map { it.path.fileId(linked) }, true))
        val (staged, stagedGuards) = guards(linked)
        f.hook = { if (it == GitOperationCrashPoint.AFTER_PUBLISH) throw SimulatedGitCrash() }
        val admission = service.requestWorkspace(jobId, repositoryId, GitCommitRequest(linked, stagedGuards,
            staged.observation.status.entries.filter { it.staged != GitIndexChange.NONE }.map { it.path.fileId(linked) }, "linked crash"), "linked_crash_key_01")
        assertTrue(service.awaitIdle(60_000)); service.close()
        f.hook = {}
        service = f.open()
        val recovered = service.operation(jobId, repositoryId, admission.operation.operationId)
        assertEquals(GitOperationState.RECOVERY_REQUIRED, recovered.state)
        assertEquals(service.workspace(jobId, repositoryId, linked).observation.head.objectId, recovered.resultObjectId)
        assertEquals(base, service.workspace(jobId, repositoryId).observation.head.objectId)
    }

    @Test fun `linked attached and detached commits publish to the correct HEAD without shadow refs`() {
        for (attached in listOf(true, false)) Fixture().use { f ->
            val base = f.prepare()
            val primary = service.workspace(jobId, repositoryId).worktreeId
            val branch = "linked-commit".takeIf { attached }
            val linked = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second,
                objectId = base, name = branch)).worktreeId
            val path = f.store.resolve("$jobId/git/repositories/$repositoryId/worktrees/$linked")
            val admin = f.gitDir().resolve("worktrees/$linked")
            Files.writeString(path.resolve("src/new.c"), "int linked_commit;\n")
            val (view, g) = guards(linked)
            assertEquals(GitOperationState.COMPLETED, run(GitStageRequest(linked, g,
                view.observation.status.entries.filter { it.untracked }.map { it.path.fileId(linked) }, true)).state)
            val (staged, stagedGuards) = guards(linked)
            val operation = run(GitCommitRequest(linked, stagedGuards, staged.observation.status.entries
                .filter { it.staged != GitIndexChange.NONE }.map { it.path.fileId(linked) }, "linked publication"))
            assertEquals(GitOperationState.COMPLETED, operation.state, operation.message)
            val commit = assertNotNull(operation.resultObjectId)
            assertNotEquals(base, commit)
            assertEquals(commit, f.raw("rev-parse", "HEAD", worktree = path, gitDir = admin).trim())
            if (attached) assertEquals(commit, f.raw("rev-parse", "refs/heads/$branch").trim())
            assertFalse(Files.exists(admin.resolve("refs/heads/linked-commit")), "Never publish a private shadow branch")
            assertFalse(Files.exists(admin.resolve("index.lock")))
            assertFalse(Files.exists(admin.resolve("HEAD.lock")))
            assertEquals(base, service.workspace(jobId, repositoryId).observation.head.objectId)
            assertFalse(service.workspace(jobId, repositoryId, linked).observation.dirty)
        }
    }

    @Test fun `linked staging and unstaging pin the common branch and private index without shadow locks`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val primary = service.workspace(jobId, repositoryId).worktreeId
        val linked = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second,
            objectId = base, name = "linked-index")).worktreeId
        val path = f.store.resolve("$jobId/git/repositories/$repositoryId/worktrees/$linked")
        val admin = f.gitDir().resolve("worktrees/$linked")
        Files.writeString(path.resolve("src/new.c"), "int linked_index;\n")
        var attempts = 0
        f.hook = { if (it == GitOperationCrashPoint.AFTER_WORKSPACE_VALIDATION) {
            attempts++
            assertTrue(Files.exists(admin.resolve("index.lock")))
            assertTrue(Files.exists(admin.resolve("HEAD.lock")))
            assertTrue(Files.exists(f.gitDir().resolve("refs/heads/linked-index.lock")))
            assertFalse(Files.exists(admin.resolve("refs/heads/linked-index.lock")))
            f.repositories.git("--git-dir=${f.gitDir()}", "update-ref", "refs/heads/linked-index", base, base, expect = 128)
            f.repositories.git("--git-dir=$admin", "--work-tree=$path", "add", "src/main.c", cwd = path, expect = 128)
        } }
        for (stage in listOf(true, false)) {
            val (view, guarded) = guards(linked)
            val result = run(GitStageRequest(linked, guarded, view.observation.status.entries
                .filter { it.path.exact == "src/new.c" }.map { it.path.fileId(linked) }, stage))
            assertEquals(GitOperationState.COMPLETED, result.state, result.message)
            assertEquals(if (stage) "src/new.c\n" else "", f.raw("diff", "--cached", "--name-only", worktree = path, gitDir = admin))
            for (name in listOf("index.lock", "HEAD.lock")) assertFalse(Files.exists(admin.resolve(name)))
            assertFalse(Files.exists(f.gitDir().resolve("refs/heads/linked-index.lock")))
        }
        assertEquals(2, attempts)
        assertEquals("", f.raw("diff", "--cached", "--name-only"), "The primary index stays untouched")
    }

    @Test fun `linked index restart reclaims private and common witnessed locks but preserves a foreign index`(): Unit {
        for (external in listOf(false, true)) Fixture().use { f ->
            val base = f.prepare()
            val primary = service.workspace(jobId, repositoryId).worktreeId
            val linked = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second,
                objectId = base, name = "linked-recovery")).worktreeId
            val path = f.store.resolve("$jobId/git/repositories/$repositoryId/worktrees/$linked")
            val admin = f.gitDir().resolve("worktrees/$linked")
            Files.writeString(path.resolve("src/new.c"), "int linked_restart;\n")
            val (view, guarded) = guards(linked)
            val before = f.raw("ls-files", "--stage", worktree = path, gitDir = admin)
            f.hook = { if (it == GitOperationCrashPoint.AFTER_WORKSPACE_VALIDATION) throw SimulatedGitCrash() }
            val admission = service.requestWorkspace(jobId, repositoryId, GitStageRequest(linked, guarded,
                view.observation.status.entries.filter { it.untracked }.map { it.path.fileId(linked) }, true), "linked_index_crash_01")
            assertTrue(service.awaitIdle(60_000)); service.close(); f.hook = {}
            val operationId = admission.operation.operationId
            val staging = Files.createDirectories(f.store.resolve("$jobId/git/staging/$operationId"))
            val marker = "decomp-operation:$operationId\n"
            for (name in listOf("index.lock", "HEAD.lock", "ref-lock")) {
                val witness = Files.writeString(staging.resolve(name), marker)
                val lock = if (name == "ref-lock") f.gitDir().resolve("refs/heads/linked-recovery.lock") else admin.resolve(name)
                if (external && name == "index.lock") Files.writeString(lock, marker) else Files.createLink(lock, witness)
            }
            Files.writeString(staging.resolve("ref-name"), "refs/heads/linked-recovery")
            service = f.open()
            service.recover(listOf(jobId))
            assertEquals(GitOperationState.INTERRUPTED, service.operation(jobId, repositoryId, operationId).state)
            assertEquals(before, f.raw("ls-files", "--stage", worktree = path, gitDir = admin))
            assertFalse(Files.exists(admin.resolve("HEAD.lock")))
            assertFalse(Files.exists(f.gitDir().resolve("refs/heads/linked-recovery.lock")))
            if (external) {
                assertEquals(marker, Files.readString(admin.resolve("index.lock")))
                Files.delete(admin.resolve("index.lock")) // Release only this fixture-owned foreign lock.
            } else assertFalse(Files.exists(admin.resolve("index.lock")))
            assertEquals("int linked_restart;\n", Files.readString(path.resolve("src/new.c")))
        }
    }

    @Test fun `linked commit restart preserves an unproven common branch lock`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val primary = service.workspace(jobId, repositoryId).worktreeId
        val linked = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second,
            objectId = base, name = "locked-linked")).worktreeId
        val path = f.store.resolve("$jobId/git/repositories/$repositoryId/worktrees/$linked")
        Files.writeString(path.resolve("src/new.c"), "int interrupted_linked;\n")
        val (view, g) = guards(linked)
        run(GitStageRequest(linked, g, view.observation.status.entries.filter { it.untracked }.map { it.path.fileId(linked) }, true))
        val (staged, stagedGuards) = guards(linked)
        f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) throw SimulatedGitCrash() }
        val admission = service.requestWorkspace(jobId, repositoryId, GitCommitRequest(linked, stagedGuards,
            staged.observation.status.entries.filter { it.staged != GitIndexChange.NONE }.map { it.path.fileId(linked) }, "interrupted linked"), "linked_lock_crash_01")
        assertTrue(service.awaitIdle(60_000)); service.close(); f.hook = {}
        val lock = f.gitDir().resolve("refs/heads/locked-linked.lock")
        Files.writeString(lock, "another writer\n")
        service = f.open()
        val recovered = service.operation(jobId, repositoryId, admission.operation.operationId)
        assertEquals(GitOperationState.RECOVERY_REQUIRED, recovered.state)
        assertEquals("COMMIT_LOCKS_REQUIRE_REVIEW", recovered.failureCode)
        assertEquals("another writer\n", Files.readString(lock))
        assertEquals(base, service.workspace(jobId, repositoryId).observation.head.objectId)
        assertEquals(base, service.workspace(jobId, repositoryId, linked).observation.head.objectId)
    }

    @Test fun `switches keep ignored files, refuse option-like names and provenance sees every ref`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val worktree = service.workspace(jobId, repositoryId).worktreeId
        // A branch whose tree tracks a file that is ignored here must not overwrite the local copy.
        f.raw("checkout", "-q", "-b", "with-result")
        Files.writeString(f.workTree().resolve("result.dat"), "tracked on the other branch\n")
        f.raw("add", "-f", "--", "result.dat"); f.raw("commit", "-q", "-m", "track result")
        f.raw("checkout", "-q", "trunk")
        Files.writeString(f.workTree().resolve(".gitignore"), "result.dat\n")
        f.raw("add", "--", ".gitignore"); f.raw("commit", "-q", "-m", "ignore result")
        Files.writeString(f.workTree().resolve("result.dat"), "local experiment output\n")
        val refusedSwitch = run(GitRefRequest(GitOperationAction.SWITCH, worktree, guards().second, refId = refId("refs/heads/with-result")))
        assertEquals(GitOperationState.FAILED, refusedSwitch.state); assertEquals("SWITCH_REFUSED", refusedSwitch.failureCode)
        assertEquals("local experiment output\n", Files.readString(f.workTree().resolve("result.dat")))
        // An imported branch named like an option is never passed to switch as an option.
        f.repositories.git("--git-dir=${f.gitDir()}", "update-ref", "refs/heads/--detach", f.repositories.git("--git-dir=${f.gitDir()}", "rev-parse", "with-result").trim())
        refused("VALIDATION_FAILED", GitRefRequest(GitOperationAction.SWITCH, worktree, guards().second, refId = refId("refs/heads/--detach")))
        // Provenance resolves every ref naming the commit, beyond the first page.
        (1..210).forEach { f.repositories.git("--git-dir=${f.gitDir()}", "branch", "p%03d".format(it), base) }
        assertEquals(210, service.provenance(jobId, repositoryId, base).refNames.count { it.startsWith("refs/heads/p") })
    }

    @Test fun `an interrupted named work-tree addition rolls back its new branch`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val primary = service.workspace(jobId, repositoryId).worktreeId
        f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) throw SimulatedGitCrash() }
        service.requestWorkspace(jobId, repositoryId, GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second,
            name = "experiment", objectId = base), "named_crash_key_001")
        assertTrue(service.awaitIdle(60_000)); service.close()
        assertNotNull(GitRefOperations.refObject(f.repositories.runner, f.gitDir(), GitObjectFormat.SHA1, "refs/heads/experiment"))
        f.hook = {}
        service = f.open()
        service.listing(jobId)
        assertNull(GitRefOperations.refObject(f.repositories.runner, f.gitDir(), GitObjectFormat.SHA1, "refs/heads/experiment"))
        val retried = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, name = "experiment", objectId = base))
        assertEquals(GitOperationState.COMPLETED, retried.state, retried.message)
    }

    @Test fun `checkout and removal exclude workflow admission in both orders`(): Unit {
        for (action in listOf(GitOperationAction.SWITCH, GitOperationAction.WORKTREE_REMOVE)) Fixture().use { f ->
            val base = f.prepare()
            val primary = service.workspace(jobId, repositoryId).worktreeId
            val target = if (action == GitOperationAction.WORKTREE_REMOVE) {
                run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, objectId = base, runId = "run_1")).worktreeId
            } else primary
            fun request() = GitRefRequest(action, target, guards(target).second,
                objectId = base.takeIf { action == GitOperationAction.SWITCH })
            val entered = CountDownLatch(1); val release = CountDownLatch(1)
            f.hook = { if (it == GitOperationCrashPoint.BEFORE_PUBLISH) {
                entered.countDown(); check(release.await(10, TimeUnit.SECONDS))
            } }
            val admitted = service.requestWorkspace(jobId, repositoryId, request(), "lease_order_git_first")
            try {
                assertTrue(entered.await(10, TimeUnit.SECONDS))
                // This is after the final activity check and before the actual file-replacing command.
                assertNull(f.leases.tryWorkflowAdmission(jobId))
                assertNotNull(f.leases.tryWorkflowAdmission("other-job")).close()
            } finally { release.countDown() }
            assertTrue(service.awaitIdle(60_000))
            assertEquals(GitOperationState.COMPLETED, service.operation(jobId, repositoryId, admitted.operation.operationId).state)
            f.hook = {}
            val nextTarget = if (action == GitOperationAction.WORKTREE_REMOVE) {
                run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, objectId = base, runId = "run_1")).worktreeId
            } else primary
            // Workflow admission first: even before an active attempt is published, Git cannot run.
            assertNotNull(f.leases.tryWorkflowAdmission(jobId)).use {
                val operation = run(GitRefRequest(action, nextTarget, guards(nextTarget).second,
                    objectId = base.takeIf { action == GitOperationAction.SWITCH }))
                assertEquals(GitOperationState.FAILED, operation.state)
                assertEquals("ACTIVE_RUN", operation.failureCode)
                f.runs["run_1"] = true // durable activity is published before releasing admission ownership
            }
            refused("ACTIVE_RUN", GitRefRequest(action, nextTarget, guards(nextTarget).second,
                objectId = base.takeIf { action == GitOperationAction.SWITCH }))
            f.runs["run_1"] = false
            assertEquals(GitOperationState.COMPLETED, run(GitRefRequest(action, nextTarget, guards(nextTarget).second,
                objectId = base.takeIf { action == GitOperationAction.SWITCH })).state)
        }
    }

    @Test fun `branch switches pin the reviewed destination through the after-validation race`() {
        for (linked in listOf(false, true)) for (explicitTip in listOf(false, true)) Fixture().use { f ->
            val base = f.prepare()
            val primary = service.workspace(jobId, repositoryId).worktreeId
            val target = if (linked) run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, objectId = base)).worktreeId else primary
            run(GitRefRequest(GitOperationAction.BRANCH_CREATE, primary, guards().second, name = "reviewed", objectId = base))
            // A packed destination must obey the same common-directory lock as a loose one.
            f.raw("pack-refs", "--all", "--prune")
            val moved = f.raw("commit-tree", "-p", base, "-m", "unreviewed tip", "$base^{tree}").trim()
            var raced = false
            f.hook = { if (it == GitOperationCrashPoint.BEFORE_PUBLISH) {
                val update = f.repositories.runner.run(GitInvocation("update-ref", listOf("refs/heads/reviewed", moved, base),
                    gitDir = f.gitDir(), allowedExitCodes = setOf(0, 128)))
                assertEquals(128, update.exitCode, "an external writer cannot change the reviewed destination during checkout")
                raced = true
            } }
            val operation = run(GitRefRequest(GitOperationAction.SWITCH, target, guards(target).second,
                refId = refId("refs/heads/reviewed"), objectId = base.takeIf { explicitTip }))
            assertTrue(raced)
            assertEquals(GitOperationState.COMPLETED, operation.state, operation.message)
            assertEquals(base, operation.resultObjectId)
            val after = service.workspace(jobId, repositoryId, target)
            assertEquals(base, after.observation.head.objectId)
            assertEquals("refs/heads/reviewed", after.observation.head.refName)
            assertFalse(Files.exists(f.gitDir().resolve("refs/heads/reviewed.lock")))
            // Once the operation has released ownership, normal external ref writers work again.
            f.raw("update-ref", "refs/heads/reviewed", moved, base)
        }
    }

    @Test fun `switch restart does not report a later external destination tip as its result`() {
        for (explicit in listOf(false, true)) Fixture().use { f ->
            val base = f.prepare()
            val primary = service.workspace(jobId, repositoryId).worktreeId
            run(GitRefRequest(GitOperationAction.BRANCH_CREATE, primary, guards().second, name = "reviewed", objectId = base))
            f.hook = { if (it == GitOperationCrashPoint.AFTER_PUBLISH) throw SimulatedGitCrash() }
            val admitted = service.requestWorkspace(jobId, repositoryId, GitRefRequest(GitOperationAction.SWITCH, primary, guards().second,
                refId = refId("refs/heads/reviewed"), objectId = base.takeIf { explicit }), "switch_moved_recovery_key")
            assertTrue(service.awaitIdle(60_000)); service.close(); f.hook = {}
            // Retain the durable target as it would survive real process death (which skips finally).
            val staging = Files.createDirectories(f.store.resolve("$jobId/git/staging/${admitted.operation.operationId}"))
            Files.writeString(staging.resolve("switch-target"), base)
            val moved = f.raw("commit-tree", "-p", base, "-m", "later external tip", "$base^{tree}").trim()
            f.raw("update-ref", "refs/heads/reviewed", moved, base)
            service = f.open()
            val recovered = service.operation(jobId, repositoryId, admitted.operation.operationId)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, recovered.state)
            assertEquals("REF_CHANGED", recovered.failureCode)
        }
    }

    @Test fun `switch restart reclaims only its witnessed destination lock`() {
        for (foreign in listOf(false, true)) Fixture().use { f ->
            val base = f.prepare()
            val primary = service.workspace(jobId, repositoryId).worktreeId
            run(GitRefRequest(GitOperationAction.BRANCH_CREATE, primary, guards().second, name = "reviewed", objectId = base))
            f.hook = { if (it == GitOperationCrashPoint.BEFORE_PUBLISH) throw SimulatedGitCrash() }
            val admitted = service.requestWorkspace(jobId, repositoryId, GitRefRequest(GitOperationAction.SWITCH, primary, guards().second,
                refId = refId("refs/heads/reviewed"), objectId = base), "switch_recovery_key")
            assertTrue(service.awaitIdle(60_000)); service.close(); f.hook = {}
            // Emulate process death, where finally cannot unlink the owned branch lock.
            val staging = Files.createDirectories(f.store.resolve("$jobId/git/staging/${admitted.operation.operationId}"))
            Files.writeString(staging.resolve("ref-name"), "refs/heads/reviewed")
            val witness = Files.createFile(staging.resolve("ref-lock"))
            val lock = f.gitDir().resolve("refs/heads/reviewed.lock")
            if (foreign) Files.writeString(lock, "foreign replacement\n") else Files.createLink(lock, witness)
            service = f.open()
            val recovered = service.operation(jobId, repositoryId, admitted.operation.operationId)
            if (foreign) {
                assertEquals(GitOperationState.RECOVERY_REQUIRED, recovered.state)
                assertEquals("SWITCH_LOCK_REQUIRES_REVIEW", recovered.failureCode)
                assertEquals("foreign replacement\n", Files.readString(lock))
            } else {
                assertEquals(GitOperationState.INTERRUPTED, recovered.state)
                assertFalse(Files.exists(lock))
                assertEquals(GitOperationState.COMPLETED, run(GitRefRequest(GitOperationAction.SWITCH, primary, guards().second,
                    refId = refId("refs/heads/reviewed"), objectId = base)).state)
            }
        }
    }

    @Test fun `switches refuse symbolic destinations and preserve foreign destination locks`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val primary = service.workspace(jobId, repositoryId).worktreeId
        f.raw("symbolic-ref", "refs/heads/alias", "refs/heads/trunk")
        val symbolic = run(GitRefRequest(GitOperationAction.SWITCH, primary, guards().second,
            refId = refId("refs/heads/alias"), objectId = base))
        assertEquals(GitOperationState.FAILED, symbolic.state); assertEquals("SWITCH_REFUSED", symbolic.failureCode)
        assertFalse(Files.exists(f.gitDir().resolve("refs/heads/alias.lock")))
        run(GitRefRequest(GitOperationAction.BRANCH_CREATE, primary, guards().second, name = "locked", objectId = base))
        val foreign = f.gitDir().resolve("refs/heads/locked.lock")
        Files.writeString(foreign, "another writer\n")
        val operation = run(GitRefRequest(GitOperationAction.SWITCH, primary, guards().second,
            refId = refId("refs/heads/locked"), objectId = base))
        assertEquals(GitOperationState.FAILED, operation.state); assertEquals("WORKTREE_BUSY", operation.failureCode)
        assertEquals("another writer\n", Files.readString(foreign))
        assertEquals("refs/heads/trunk", service.workspace(jobId, repositoryId).observation.head.refName)
    }

    @Test fun `branch deletion compares the reviewed tip even if the branch moves after validation`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val primary = service.workspace(jobId, repositoryId).worktreeId
        run(GitRefRequest(GitOperationAction.BRANCH_CREATE, primary, guards().second, name = "reviewed", objectId = base))
        val moved = f.repositories.git("--git-dir=${f.gitDir()}", "commit-tree", "-p", base, "-m", "unique unmerged tip", "$base^{tree}").trim()
        f.hook = { if (it == GitOperationCrashPoint.BEFORE_PUBLISH) {
            f.repositories.git("--git-dir=${f.gitDir()}", "update-ref", "refs/heads/reviewed", moved, base)
        } }
        val operation = run(GitRefRequest(GitOperationAction.BRANCH_DELETE, primary, guards().second,
            refId = refId("refs/heads/reviewed"), objectId = base))
        assertEquals(GitOperationState.FAILED, operation.state); assertEquals("REF_CHANGED", operation.failureCode)
        assertEquals(moved, GitRefOperations.refObject(f.repositories.runner, f.gitDir(), GitObjectFormat.SHA1, "refs/heads/reviewed"))
    }

    @Test fun `work-tree command failure rolls back partial creation and permits retry after restart`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val primary = service.workspace(jobId, repositoryId).worktreeId
        // A historical object can fit the checkout bounds but contain a filename that the host
        // cannot materialize. Git creates -b's branch before checkout fails inside worktree add.
        val blob = f.raw("rev-parse", "$base:src/main.c").trim()
        f.raw("update-index", "--add", "--cacheinfo", "100644,$blob,${"x".repeat(256)}")
        val tree = f.raw("write-tree").trim()
        val historical = f.raw("commit-tree", "-p", base, "-m", "uncheckoutable history", tree).trim()
        f.raw("read-tree", base)
        GitRepositoryImport.requireCheckoutBounds(f.repositories.runner, f.gitDir(), historical, GitCheckoutLimits())
        for (name in listOf("failed-checkout", null)) {
            val failed = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second,
                name = name, objectId = historical))
            assertEquals(GitOperationState.FAILED, failed.state, failed.message)
            assertEquals("REPOSITORY_UNAVAILABLE", failed.failureCode)
            assertFalse(f.gitDir().parent.resolve("worktrees/${failed.worktreeId}").exists())
            assertFalse(f.gitDir().resolve("worktrees/${failed.worktreeId}").exists())
            assertFalse(f.raw("worktree", "list", "--porcelain").contains(failed.worktreeId))
            assertNull(GitRefOperations.refObject(f.repositories.runner, f.gitDir(), GitObjectFormat.SHA1, "refs/heads/failed-checkout"))
            service.close(); service = f.open()
            assertEquals(GitOperationState.FAILED, service.operation(jobId, repositoryId, failed.operationId).state)
            assertEquals(listOf(primary), service.worktrees(jobId, repositoryId).map { it.worktreeId })
            assertNull(GitRefOperations.refObject(f.repositories.runner, f.gitDir(), GitObjectFormat.SHA1, "refs/heads/failed-checkout"))
            val retried = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, name = name, objectId = base))
            assertEquals(GitOperationState.COMPLETED, retried.state, retried.message)
            assertEquals(GitOperationState.COMPLETED, run(GitRefRequest(GitOperationAction.WORKTREE_REMOVE,
                retried.worktreeId, guards(retried.worktreeId).second)).state)
            if (name != null) assertEquals(GitOperationState.COMPLETED, run(GitRefRequest(GitOperationAction.BRANCH_DELETE,
                primary, guards().second, refId = refId("refs/heads/$name"), objectId = base)).state)
        }
        assertEquals(base, service.workspace(jobId, repositoryId).observation.head.objectId)
        assertTrue(service.workspace(jobId, repositoryId).observation.status.entries.isEmpty())
        assertEquals("int main(void) { return 0; }\n", Files.readString(f.snapshot.resolve("src/main.c")))
    }

    @Test fun `ordinary work-tree registration failure rolls back allocation and branch across restart`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val primary = service.workspace(jobId, repositoryId).worktreeId
        val records = f.gitDir().parent.resolve("worktree-records")
        f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) Files.writeString(records, "storage obstruction") }
        val failed = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, name = "experiment", objectId = base))
        assertEquals(GitOperationState.FAILED, failed.state); assertEquals("STORAGE_FAILED", failed.failureCode)
        assertFalse(f.gitDir().parent.resolve("worktrees/${failed.worktreeId}").exists())
        assertNull(GitRefOperations.refObject(f.repositories.runner, f.gitDir(), GitObjectFormat.SHA1, "refs/heads/experiment"))
        service.close(); Files.delete(records); f.hook = {}; service = f.open()
        assertEquals(GitOperationState.FAILED, service.operation(jobId, repositoryId, failed.operationId).state)
        assertEquals(listOf(primary), service.worktrees(jobId, repositoryId).map { it.worktreeId })
        // No invisible allocation consumes disk or branch names, and the full quota is reusable.
        repeat(GitRefOperations.MAX_LINKED_WORKTREES) { index ->
            assertEquals(GitOperationState.COMPLETED, run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second,
                name = if (index == 0) "experiment" else null, objectId = base)).state)
        }
        refused("QUOTA_EXCEEDED", GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, objectId = base))
    }

    @Test fun `failed registration with a moved branch retains recovery ownership until reconciled`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val primary = service.workspace(jobId, repositoryId).worktreeId
        val records = f.gitDir().parent.resolve("worktree-records")
        val moved = f.repositories.git("--git-dir=${f.gitDir()}", "commit-tree", "-p", base, "-m", "external", "$base^{tree}").trim()
        f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) {
            f.repositories.git("--git-dir=${f.gitDir()}", "update-ref", "refs/heads/experiment", moved, base)
            Files.writeString(records, "storage obstruction")
        } }
        val failed = run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, name = "experiment", objectId = base))
        assertEquals(GitOperationState.RECOVERY_REQUIRED, failed.state); assertEquals("REF_CONFLICT", failed.failureCode)
        service.close(); Files.delete(records); f.hook = {}; service = f.open()
        assertEquals(GitOperationState.RECOVERY_REQUIRED, service.operation(jobId, repositoryId, failed.operationId).state)
        refused("WORKTREE_BUSY", GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second, objectId = base))
        assertEquals(moved, GitRefOperations.refObject(f.repositories.runner, f.gitDir(), GitObjectFormat.SHA1, "refs/heads/experiment"))
        // An explicit operator repair can be reconciled without forgetting or replaying the failed add.
        f.repositories.git("--git-dir=${f.gitDir()}", "update-ref", "refs/heads/experiment", base, moved)
        assertEquals(GitOperationState.COMPLETED, run(GitRefRequest(GitOperationAction.WORKTREE_ADD, primary, guards().second,
            name = "experiment", objectId = base)).state)
    }

    @Test fun `exports and verification refuse unsafe portable paths and aliases`(): Unit = Fixture().use { f ->
        f.prepare()
        val unsafe = listOf("..\\escaped.txt", "C:\\escaped.txt", "trailing.", "NUL.txt")
        for (name in unsafe) {
            Files.writeString(f.workTree().resolve(name), "payload")
            f.raw("add", "-f", "--", name); f.raw("commit", "-q", "-m", "unsafe file")
            val head = f.repositories.git("--git-dir=${f.gitDir()}", "rev-parse", "HEAD").trim()
            assertEquals("REPOSITORY_UNSUPPORTED", assertFailsWith<ManagedGitException> { service.export(jobId, repositoryId, head) }.code)
            f.raw("rm", "--", name); f.raw("commit", "-q", "-m", "remove unsafe file")
        }
        for (names in unsafe.map { listOf(it) } + listOf(listOf("/absolute"), listOf("../escape"), listOf(".GIT/config"),
            listOf("A.c", "a.c"), listOf("Dir/a", "dir/b"), listOf("é.c", "e\u0301.c"), listOf("a", "a/b"))) {
            val payload = "payload".toByteArray()
            val digest = java.security.MessageDigest.getInstance("SHA-1").digest("blob ${payload.size}\u0000".toByteArray() + payload)
                .joinToString("") { "%02x".format(it) }
            val output = java.io.ByteArrayOutputStream()
            java.util.zip.ZipOutputStream(output).use { zip -> names.forEach { name ->
                zip.putNextEntry(java.util.zip.ZipEntry(name)); zip.write(payload); zip.closeEntry()
            } }
            assertFalse(GitSourceExports.verify(output.toByteArray(), GitObjectFormat.SHA1, names.associateWith { digest }), names.toString())
        }
        val paths = GitExportPaths()
        assertTrue(paths.add("src/normal.c")); assertTrue(paths.add("src/other.c")); assertFalse(paths.add("src/normal.c"))
    }

    @Test fun `verification requires a complete consistent archive including the valid empty case`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val export = service.export(jobId, repositoryId, base)
        assertTrue(GitSourceExports.verify(export.bytes, GitObjectFormat.SHA1, export.blobs))
        val empty = java.io.ByteArrayOutputStream().also { java.util.zip.ZipOutputStream(it).close() }.toByteArray()
        assertTrue(GitSourceExports.verify(empty, GitObjectFormat.SHA1, emptyMap()))
        assertTrue(GitSourceExports.verify(empty, GitObjectFormat.SHA256, emptyMap()))
        for (bytes in listOf(byteArrayOf(), "not a zip".toByteArray(), empty.copyOf(empty.size - 1), empty + byteArrayOf(0))) {
            assertFalse(GitSourceExports.verify(bytes, GitObjectFormat.SHA1, emptyMap()))
        }
        val buffer = java.nio.ByteBuffer.wrap(export.bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        val end = export.bytes.size - 22
        val central = buffer.getInt(end + 16)
        // Local entries and correct blob contents alone are not a complete ZIP.
        for (length in listOf(central, central + 10, end, export.bytes.size - 1)) {
            assertFalse(GitSourceExports.verify(export.bytes.copyOf(length), GitObjectFormat.SHA1, export.blobs), "truncation at $length")
        }
        // Inconsistent central metadata must fail even when local entries and blob IDs are intact.
        for (at in listOf(central + 16, central + 20, central + 24, central + 42, central + 46, end + 8, end + 12, end + 16)) {
            val changed = export.bytes.copyOf().also { it[at] = (it[at].toInt() xor 1).toByte() }
            assertFalse(GitSourceExports.verify(changed, GitObjectFormat.SHA1, export.blobs), "metadata at $at")
        }
        assertFalse(GitSourceExports.verify(export.bytes + byteArrayOf(0), GitObjectFormat.SHA1, export.blobs))
    }

    @Test fun `a large file exports within the capture bounds`(): Unit = Fixture().use { f ->
        f.prepare()
        Files.write(f.workTree().resolve("table.dat"), ByteArray(40 * 1024 * 1024) { (it % 251).toByte() })
        f.raw("add", "--", "table.dat"); f.raw("commit", "-q", "-m", "large")
        val head = f.repositories.git("--git-dir=${f.gitDir()}", "rev-parse", "HEAD").trim()
        val export = service.export(jobId, repositoryId, head)
        assertTrue(export.bytes.size > 40 * 1024 * 1024)
        assertTrue(GitSourceExports.verify(export.bytes, GitObjectFormat.SHA1, export.blobs))
    }

    @Test fun `exports are deterministic, exclude Git metadata and verify independently of ref names`(): Unit = Fixture().use { f ->
        val base = f.prepare()
        val first = service.export(jobId, repositoryId, base)
        assertTrue(GitSourceExports.verify(first.bytes, GitObjectFormat.SHA1, first.blobs))
        assertEquals(setOf("CMakeLists.txt", "src/main.c"), first.blobs.keys)
        // The same tree under a different message, author and date exports byte for byte the same.
        f.repositories.git("--git-dir=${f.gitDir()}", "--work-tree=${f.workTree()}", "-c", "user.name=Other", "commit", "-q",
            "--allow-empty", "--date=2030-01-01T00:00:00Z", "-m", "same tree, other metadata", cwd = f.workTree())
        val same = f.repositories.git("--git-dir=${f.gitDir()}", "rev-parse", "HEAD").trim()
        assertNotEquals(base, same)
        assertContentEquals(first.bytes, service.export(jobId, repositoryId, same).bytes)
        // Uncommitted work never reaches an export of a commit.
        Files.writeString(f.workTree().resolve("src/main.c"), "int main(void) { return 7; }\n")
        Files.writeString(f.workTree().resolve("dirty.c"), "int dirty;\n")
        assertContentEquals(first.bytes, service.export(jobId, repositoryId, base).bytes)
        java.util.zip.ZipInputStream(first.bytes.inputStream()).use { zip ->
            generateSequence { zip.nextEntry }.forEach {
                assertFalse(it.name.contains(".git"), it.name); assertEquals(java.time.LocalDateTime.of(1980, 1, 2, 0, 0), it.timeLocal)
            }
        }
        // The archive bytes do not depend on the JVM's default time zone, and no entry carries an extra field.
        val zone = java.util.TimeZone.getDefault()
        try {
            for (id in listOf("UTC", "Asia/Seoul", "America/New_York", "Pacific/Kiritimati")) {
                java.util.TimeZone.setDefault(java.util.TimeZone.getTimeZone(id))
                assertContentEquals(first.bytes, service.export(jobId, repositoryId, base).bytes, id)
            }
        } finally { java.util.TimeZone.setDefault(zone) }
        var offset = 0
        val buffer = java.nio.ByteBuffer.wrap(first.bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        while (buffer.getInt(offset) == 0x04034b50) {
            assertEquals(0, buffer.getShort(offset + 28).toInt(), "local header extra field")
            offset += 30 + buffer.getShort(offset + 26) + buffer.getInt(offset + 18)
        }
        // A tampered payload fails verification; a moved ref changes no identity.
        val tampered = first.bytes.copyOf().also { bytes -> val at = String(bytes, Charsets.ISO_8859_1).indexOf("return 0"); bytes[at + 7] = '1'.code.toByte() }
        assertFalse(GitSourceExports.verify(tampered, GitObjectFormat.SHA1, first.blobs))
        val before = service.provenance(jobId, repositoryId, base)
        assertTrue(before.verified); assertEquals(first.sha256, before.export.sha256)
        f.repositories.git("--git-dir=${f.gitDir()}", "update-ref", "refs/heads/trunk", same)
        f.repositories.git("--git-dir=${f.gitDir()}", "tag", "moved", same)
        val after = service.provenance(jobId, repositoryId, base)
        assertEquals(before.export.sha256, after.export.sha256); assertEquals(base, after.commit.objectId)
        assertFalse("refs/heads/trunk" in after.refNames)
        assertNotNull(before.mapping); assertEquals(before.mapping, after.mapping)
    }
}
