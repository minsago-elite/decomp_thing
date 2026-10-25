package decompengine.git

import java.nio.file.Files
import java.nio.file.Path
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
        val runs = mutableMapOf("run_1" to false, "run_2" to false)
        private val opened = mutableListOf<ManagedGitRepositories>()
        init {
            mapOf("CMakeLists.txt" to "project(fixture C)\n", "src/main.c" to "int main(void) { return 0; }\n").forEach { (name, text) ->
                Files.createDirectories(snapshot.resolve(name).parent); Files.writeString(snapshot.resolve(name), text)
            }
        }
        fun open() = ManagedGitRepositories(store, GitRuntime.detect(), { _, run, revision ->
            GitSourceSnapshot(snapshot, run, revision, "a".repeat(64), mapOf("src/main.c" to GitSourceCommitment(
                GitSourceCopy.digestOf(snapshot.resolve("src/main.c")), Files.size(snapshot.resolve("src/main.c")))))
        }, policy = GitRepositoryPolicy(defaultBranch = "trunk"), crash = { hook(it) }, activity = { runs.toMap() }).also(opened::add)
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
