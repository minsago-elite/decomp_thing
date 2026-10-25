package decompengine.git

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GitWorkspaceMutationsTest {
    private val jobId = "0123456789abcdef0123456789abcdef"

    private class Fixture(val repositories: GitTestRepositories = GitTestRepositories()) : AutoCloseable {
        val store: Path = Files.createDirectories(repositories.root.resolve("store"))
        val snapshot: Path = Files.createDirectories(store.resolve("0123456789abcdef0123456789abcdef/reports/runs/run_1/source-tree"))
        var hook: (GitOperationCrashPoint) -> Unit = {}
        var accepted = false
        private val opened = mutableListOf<ManagedGitRepositories>()
        init {
            mapOf("CMakeLists.txt" to "project(fixture C)\n", "src/main.c" to "int main(void) { return 0; }\n",
                "src/util.c" to "int util;\n", "input.elf" to "ELF", "build/out.o" to "obj").forEach { (name, text) ->
                Files.createDirectories(snapshot.resolve(name).parent); Files.writeString(snapshot.resolve(name), text)
            }
        }
        /** Recorded once, like a completed attempt's build-input commitments. */
        val commitments = listOf("src/main.c", "src/util.c").associateWith {
            GitSourceCommitment(GitSourceCopy.digestOf(snapshot.resolve(it)), Files.size(snapshot.resolve(it)))
        }
        fun open(policy: GitRepositoryPolicy = GitRepositoryPolicy(defaultBranch = "trunk")) = ManagedGitRepositories(store,
            GitRuntime.detect(), { _, run, revision -> GitSourceSnapshot(snapshot, run, revision, "a".repeat(64), commitments) },
            policy = policy, crash = { hook(it) },
            acceptance = { _, revision, _ -> if (accepted && revision == "revision_1") "accepted" to "artifact_1" else "not-evaluated" to null },
        ).also(opened::add)
        override fun close() { opened.forEach { it.close() }; repositories.close() }
    }

    private fun ManagedGitRepositories.initialized(): String {
        val admission = request("0123456789abcdef0123456789abcdef", GitRepositoryRequest.Init("run_1", "revision_1", null), "init_key_00000001")
        assertTrue(awaitIdle(60_000))
        return admission.operation.repositoryId
    }

    private fun ManagedGitRepositories.guards(repositoryId: String): Pair<GitWorkspaceView, GitGuards> {
        val view = workspace(jobId, repositoryId)
        return view to GitGuards(GitWorkspaceVersions.repositoryVersion(view.record, view.observation),
            GitWorkspaceVersions.worktreeVersion(view.observation), view.observation.head.objectId,
            GitWorkspaceVersions.headRefId(view.record, view.observation), view.observation.head.objectId.takeIf { view.observation.head.refName != null })
    }

    private fun GitWorkspaceView.ids(predicate: (GitStatusEntry) -> Boolean) =
        observation.status.entries.filter(predicate).map { it.path.fileId(record.worktreeId) }

    private fun ManagedGitRepositories.run(repositoryId: String, request: GitRepositoryRequest, key: String): GitOperationRecord {
        val admission = requestWorkspace(jobId, repositoryId, request, key)
        assertTrue(awaitIdle(60_000))
        return operation(jobId, repositoryId, admission.operation.operationId)
    }

    @Test fun `selected files are staged, unstaged and committed exactly with a validated revision mapping`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val (initial, guards) = service.guards(repositoryId)
        assertTrue(initial.observation.status.entries.single { it.path.exact == "input.elf" }.ignored)
        val main = initial.ids { it.path.exact == "src/main.c" }
        val staged = service.run(repositoryId, GitStageRequest(initial.record.worktreeId, guards, main, true), "stage_key_0000001")
        assertEquals(GitOperationState.COMPLETED, staged.state, staged.message)
        val (afterStage, stageGuards) = service.guards(repositoryId)
        assertEquals(GitIndexChange.ADDED, afterStage.observation.status.entries.single { it.path.exact == "src/main.c" }.staged)
        assertTrue(afterStage.observation.status.entries.single { it.path.exact == "src/util.c" }.untracked)
        // Unstage restores the unborn index entry without touching the file.
        service.run(repositoryId, GitStageRequest(afterStage.record.worktreeId, stageGuards, main, false), "unstage_key_00001")
        val (afterUnstage, unstageGuards) = service.guards(repositoryId)
        assertTrue(afterUnstage.observation.status.entries.single { it.path.exact == "src/main.c" }.untracked)
        assertTrue(Files.exists(afterUnstage.record.let { f.store.resolve("$jobId/git/repositories/$repositoryId/worktree/src/main.c") }))
        // Stage every selectable source file, then commit exactly that set.
        val sources = afterUnstage.ids { it.untracked }
        service.run(repositoryId, GitStageRequest(afterUnstage.record.worktreeId, unstageGuards, sources, true), "stage_key_0000002")
        val (review, commitGuards) = service.guards(repositoryId)
        val commit = service.run(repositoryId, GitCommitRequest(review.record.worktreeId, commitGuards, review.ids { it.staged != GitIndexChange.NONE },
            "Record the reconstructed snapshot\n\nNo validation is implied."), "commit_key_000001")
        assertEquals(GitOperationState.COMPLETED, commit.state, commit.message)
        val objectId = assertNotNull(commit.resultObjectId)
        val (committed, _) = service.guards(repositoryId)
        assertEquals(objectId, committed.observation.head.objectId)
        val mapping = assertNotNull(committed.mapping)
        assertEquals("revision_1", mapping.record.revisionId); assertEquals("not-evaluated", mapping.acceptance)
        f.accepted = true
        assertEquals("accepted", service.workspace(jobId, repositoryId).mapping?.acceptance)
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val author = f.repositories.git("--git-dir=$gitDir", "log", "-1", "--format=%an <%ae>|%cn|%B").trim()
        assertEquals("Decomp Workbench <workbench@localhost.invalid>|Decomp Workbench|Record the reconstructed snapshot\n\nNo validation is implied.", author)
        assertEquals(setOf("CMakeLists.txt", "src/main.c", "src/util.c"),
            f.repositories.git("--git-dir=$gitDir", "ls-tree", "-r", "--name-only", objectId).lines().filter { it.isNotEmpty() }.toSet())
        // A commit whose tree differs from the snapshot is a new candidate and stays unmapped.
        val workTree = f.store.resolve("$jobId/git/repositories/$repositoryId/worktree")
        Files.writeString(workTree.resolve("src/util.c"), "int util = 2;\n")
        val (edited, editGuards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(edited.record.worktreeId, editGuards, edited.ids { it.unstaged != GitIndexChange.NONE }, true), "stage_key_0000003")
        val (second, secondGuards) = service.guards(repositoryId)
        val next = service.run(repositoryId, GitCommitRequest(second.record.worktreeId, secondGuards, second.ids { it.staged != GitIndexChange.NONE }, "Edit util"), "commit_key_000002")
        assertEquals(GitOperationState.COMPLETED, next.state)
        assertTrue(next.message.contains("not mapped"))
        assertNull(service.workspace(jobId, repositoryId).mapping)
        assertEquals(setOf(objectId), service.mappings(jobId, repositoryId, listOf(objectId, next.resultObjectId!!)).keys)
    }

    @Test fun `stale guards, foreign selections, exclusions and invalid commits are refused before Git runs`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val (view, guards) = service.guards(repositoryId)
        val worktree = view.record.worktreeId
        val main = view.ids { it.path.exact == "src/main.c" }
        fun refused(code: String, request: GitRepositoryRequest, key: String) = assertEquals(code,
            assertFailsWith<ManagedGitException>(code) { service.requestWorkspace(jobId, repositoryId, request, key) }.code)
        refused("WORKTREE_CHANGED", GitStageRequest(worktree, guards.copy(worktreeVersion = "worktree_v_stale"), main, true), "refuse_key_000001")
        refused("REF_CHANGED", GitStageRequest(worktree, guards.copy(repositoryVersion = "repository_v_stale"), main, true), "refuse_key_000002")
        refused("REF_CHANGED", GitStageRequest(worktree, guards.copy(expectedHeadObjectId = "1".repeat(40)), main, true), "refuse_key_000003")
        refused("SELECTION_CHANGED", GitStageRequest(worktree, guards, listOf("file_" + "0".repeat(32)), true), "refuse_key_000004")
        refused("EXCLUDED_PATH", GitStageRequest(worktree, guards, view.ids { it.path.exact == "input.elf" }, true), "refuse_key_000005")
        refused("NOTHING_SELECTED", GitStageRequest(worktree, guards, main, false), "refuse_key_000006")
        refused("NOTHING_TO_COMMIT", GitCommitRequest(worktree, guards, main, "Nothing staged"), "refuse_key_000007")
        refused("NOT_FOUND", GitStageRequest("worktree_other", guards, main, true), "refuse_key_000008")
        // An in-tree .gitignore negation cannot make a credential stageable.
        val workTree = f.store.resolve("$jobId/git/repositories/$repositoryId/worktree")
        Files.writeString(workTree.resolve(".gitignore"), "!secret.key\n"); Files.writeString(workTree.resolve("secret.key"), "PRIVATE")
        val (negated, negatedGuards) = service.guards(repositoryId)
        assertTrue(negated.observation.status.entries.single { it.path.exact == "secret.key" }.ignored)
        val secretId = GitPath.of("secret.key".toByteArray()).fileId(worktree)
        refused("EXCLUDED_PATH", GitStageRequest(worktree, negatedGuards, listOf(secretId), true), "refuse_key_000009")
        // The commit selection must equal the staged set exactly.
        service.run(repositoryId, GitStageRequest(worktree, negatedGuards, negated.ids { it.path.exact in setOf("src/main.c", "src/util.c") }, true), "stage_key_0000010")
        val (staged, stagedGuards) = service.guards(repositoryId)
        refused("INDEX_CHANGED", GitCommitRequest(worktree, stagedGuards, staged.ids { it.path.exact == "src/main.c" }, "Partial"), "refuse_key_000010")
        val all = staged.ids { it.staged != GitIndexChange.NONE }
        refused("VALIDATION_FAILED", GitCommitRequest(worktree, stagedGuards, all, "   "), "refuse_key_000011")
        refused("VALIDATION_FAILED", GitCommitRequest(worktree, stagedGuards, all, "bad\u0007bell"), "refuse_key_000012")
        val signing = f.open(GitRepositoryPolicy(defaultBranch = "trunk", requireSignedCommits = true))
        assertEquals("SIGNING_UNAVAILABLE", assertFailsWith<ManagedGitException> {
            signing.requestWorkspace(jobId, repositoryId, GitCommitRequest(worktree, stagedGuards, all, "Signed"), "refuse_key_000013")
        }.code)
        // Keyed replay returns the original operation; the same key with other intent conflicts.
        val first = service.run(repositoryId, GitCommitRequest(worktree, stagedGuards, all, "Commit once"), "commit_key_000010")
        val replay = service.requestWorkspace(jobId, repositoryId, GitCommitRequest(worktree, stagedGuards, all, "Commit once"), "commit_key_000010")
        assertTrue(replay.replayed); assertEquals(first.operationId, replay.operation.operationId)
        refused("IDEMPOTENCY_CONFLICT", GitCommitRequest(worktree, stagedGuards, all, "Commit twice"), "commit_key_000010")
        assertEquals(1, f.repositories.git("--git-dir=${f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")}",
            "rev-list", "--count", "HEAD").trim().toInt())
    }

    @Test fun `large rename selections unstage through bounded stdin and incomplete status never commits`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val (initial, guards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(initial.record.worktreeId, guards, initial.ids { it.untracked }, true), "stage_key_0000020")
        val (staged, stagedGuards) = service.guards(repositoryId)
        service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, stagedGuards, staged.ids { it.staged != GitIndexChange.NONE }, "base"), "commit_key_000020")
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val workTree = f.store.resolve("$jobId/git/repositories/$repositoryId/worktree")
        fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
        (1..140).forEach { Files.writeString(workTree.resolve("old-$it.c"), "int unique_value_$it = $it; /* padding to keep renames detectable */\n") }
        raw("add", "-A"); raw("commit", "-q", "-m", "files to rename")
        (1..140).forEach { raw("mv", "old-$it.c", "new-$it.c") }
        val (renamed, renameGuards) = service.guards(repositoryId)
        val selection = renamed.ids { it.staged == GitIndexChange.RENAMED }.take(200)
        assertEquals(140, selection.size)
        val unstaged = service.run(repositoryId, GitStageRequest(renamed.record.worktreeId, renameGuards, selection, false), "unstage_key_00020")
        assertEquals(GitOperationState.COMPLETED, unstaged.state, unstaged.message)
        assertTrue(service.workspace(jobId, repositoryId).observation.status.entries.none { it.staged != GitIndexChange.NONE })
        // A truncated observation can never confirm a staged set.
        val (view, _) = service.guards(repositoryId)
        val incomplete = view.observation.copy(status = view.observation.status.copy(complete = false))
        assertEquals("STATUS_INCOMPLETE", assertFailsWith<GitOperationRefusal> {
            GitWorkspaceMutations.requireStagedSet(view.record, incomplete, listOf("file_" + "0".repeat(32)))
        }.code)
    }

    @Test fun `deletions never stage replacement directories and unborn unstaging keeps edits`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val workTree = f.store.resolve("$jobId/git/repositories/$repositoryId/worktree")
        // Staged then edited again on the unborn branch: unstaging still works and keeps the edit.
        val (initial, guards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(initial.record.worktreeId, guards, initial.ids { it.path.exact == "src/main.c" }, true), "stage_key_0000030")
        Files.writeString(workTree.resolve("src/main.c"), "int main(void) { return 5; }\n")
        val (edited, editedGuards) = service.guards(repositoryId)
        val unstaged = service.run(repositoryId, GitStageRequest(edited.record.worktreeId, editedGuards, edited.ids { it.path.exact == "src/main.c" }, false), "unstage_key_00030")
        assertEquals(GitOperationState.COMPLETED, unstaged.state, unstaged.message)
        assertTrue(service.workspace(jobId, repositoryId).observation.status.entries.single { it.path.exact == "src/main.c" }.untracked)
        assertEquals("int main(void) { return 5; }\n", Files.readString(workTree.resolve("src/main.c")))
        // Commit, then replace a file by a directory: staging the deletion must not add the directory.
        val (all, allGuards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(all.record.worktreeId, allGuards, all.ids { it.untracked }, true), "stage_key_0000031")
        val (staged, stagedGuards) = service.guards(repositoryId)
        service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, stagedGuards, staged.ids { it.staged != GitIndexChange.NONE }, "base"), "commit_key_000031")
        Files.delete(workTree.resolve("src/util.c"))
        Files.createDirectories(workTree.resolve("src/util.c")); Files.writeString(workTree.resolve("src/util.c/extra.c"), "int unselected;\n")
        val (replaced, replacedGuards) = service.guards(repositoryId)
        val deletion = replaced.ids { it.path.exact == "src/util.c" && it.unstaged == GitIndexChange.DELETED }
        assertEquals(1, deletion.size)
        val stagedDeletion = service.run(repositoryId, GitStageRequest(replaced.record.worktreeId, replacedGuards, deletion, true), "stage_key_0000032")
        assertEquals(GitOperationState.COMPLETED, stagedDeletion.state, stagedDeletion.message)
        val after = service.workspace(jobId, repositoryId).observation.status.entries
        assertEquals(GitIndexChange.DELETED, after.single { it.path.exact == "src/util.c" }.staged)
        assertTrue(after.single { it.path.exact == "src/util.c/extra.c" }.untracked)
    }

    @Test fun `a snapshot changed after initialization never lends its revision to a commit`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val workTree = f.store.resolve("$jobId/git/repositories/$repositoryId/worktree")
        Files.writeString(f.snapshot.resolve("src/main.c"), "int main(void) { return 42; }\n")
        Files.writeString(workTree.resolve("src/main.c"), "int main(void) { return 42; }\n")
        val (view, guards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "stage_key_0000040")
        val (staged, stagedGuards) = service.guards(repositoryId)
        val commit = service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, stagedGuards, staged.ids { it.staged != GitIndexChange.NONE }, "drifted"), "commit_key_000040")
        assertEquals(GitOperationState.COMPLETED, commit.state)
        assertNull(service.workspace(jobId, repositoryId).mapping)
    }

    @Test fun `an external edit between admission and execution fails the operation instead of committing it`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val workTree = f.store.resolve("$jobId/git/repositories/$repositoryId/worktree")
        val (view, guards) = service.guards(repositoryId)
        f.hook = { point -> if (point == GitOperationCrashPoint.AFTER_RUNNING) Files.writeString(workTree.resolve("src/racing.c"), "int race;\n") }
        val raced = service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "race_key_00000001")
        assertEquals(GitOperationState.FAILED, raced.state); assertEquals("WORKTREE_CHANGED", raced.failureCode)
        val (after, _) = service.guards(repositoryId)
        assertTrue(after.observation.status.entries.none { it.staged != GitIndexChange.NONE })
    }

    @Test fun `restart never repeats a commit and reports whether HEAD moved`(): Unit {
        for ((point, state) in listOf(GitOperationCrashPoint.AFTER_STAGING to GitOperationState.INTERRUPTED,
            GitOperationCrashPoint.AFTER_PUBLISH to GitOperationState.RECOVERY_REQUIRED)) Fixture().use { f ->
            val service = f.open()
            val repositoryId = service.initialized()
            val (view, guards) = service.guards(repositoryId)
            service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "stage_key_00000${point.ordinal}")
            val (staged, stagedGuards) = service.guards(repositoryId)
            f.hook = { if (it == point) throw SimulatedGitCrash() }
            val admission = service.requestWorkspace(jobId, repositoryId, GitCommitRequest(staged.record.worktreeId, stagedGuards,
                staged.ids { it.staged != GitIndexChange.NONE }, "Crash during commit"), "crash_commit_key_${point.ordinal}")
            assertTrue(service.awaitIdle(60_000)); service.close()
            f.hook = {}
            val restarted = f.open()
            val recovered = restarted.operation(jobId, repositoryId, admission.operation.operationId)
            assertEquals(state, recovered.state, point.name)
            val head = restarted.workspace(jobId, repositoryId).observation.head.objectId
            if (state == GitOperationState.INTERRUPTED) assertNull(head) else assertEquals(head, recovered.resultObjectId)
            assertTrue(Files.notExists(f.store.resolve("$jobId/git/staging/${admission.operation.operationId}")))
        }
    }
}
