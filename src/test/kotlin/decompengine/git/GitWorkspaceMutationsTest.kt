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

    @Test fun `staging guards reject equal length preserved mtime edits including already modified files`(): Unit {
        for (format in listOf(GitObjectFormat.SHA1, GitObjectFormat.SHA256)) for (tracked in listOf(false, true)) Fixture().use { f ->
            val service = f.open(GitRepositoryPolicy(defaultBranch = "trunk", objectFormat = format))
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val workTree = gitDir.parent.resolve("worktree")
            if (tracked) f.repositories.commitAll(gitDir, workTree, "baseline")
            val file = workTree.resolve("src/main.c")
            Files.writeString(file, "int safe = 1;\n")
            val (review, guards) = service.guards(repositoryId)
            val time = Files.getLastModifiedTime(file)
            val indexBefore = f.repositories.git("--git-dir=$gitDir", "ls-files", "--stage")
            Files.writeString(file, "int evil = 1;\n")
            Files.setLastModifiedTime(file, time)
            assertEquals("WORKTREE_CHANGED", assertFailsWith<ManagedGitException> {
                service.requestWorkspace(jobId, repositoryId, GitStageRequest(review.record.worktreeId, guards,
                    review.ids { it.path.exact == "src/main.c" }, true), "preserved_mtime_0001")
            }.code)
            assertEquals(indexBefore, f.repositories.git("--git-dir=$gitDir", "ls-files", "--stage"))
        }
    }

    @Test fun `content capture authenticates opened regular inode without blocking on a raced FIFO`(): Unit = Fixture().use { f ->
        val root = Files.createDirectories(f.repositories.root.resolve("fifo-worktree"))
        val file = root.resolve("raced.c")
        Files.writeString(file, "int ordinary;\\n")
        val failure = assertFailsWith<GitRepositoryException> {
            GitWorkspaceContent.fingerprint(root, file, GitWorkspaceContent.Budget(), beforeOpen = {
                Files.delete(file)
                val process = ProcessBuilder("mkfifo", file.toString()).start()
                assertEquals(0, process.waitFor())
            })
        }
        assertEquals("REPOSITORY_UNAVAILABLE", failure.code)
        Files.delete(file)
        Files.writeString(file, "int ordinary;\\n")
        val expected = GitWorkspaceContent.fingerprint(root, file, GitWorkspaceContent.Budget())
        Files.createSymbolicLink(root.resolve("link.c"), Path.of("raced.c"))
        assertTrue(GitWorkspaceContent.fingerprint(root, root.resolve("link.c"), GitWorkspaceContent.Budget()).startsWith("120000:"))
        assertTrue(expected.startsWith("100644:"))
    }

    @Test fun `staging verifies capture and never indexes bytes written after capture`(): Unit {
        for (format in listOf(GitObjectFormat.SHA1, GitObjectFormat.SHA256)) for (afterCapture in listOf(false, true)) Fixture().use { f ->
            val service = f.open(GitRepositoryPolicy(defaultBranch = "trunk", objectFormat = format))
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val file = gitDir.parent.resolve("worktree/src/main.c")
            Files.writeString(file, "int safe = 1;\n")
            val (review, guards) = service.guards(repositoryId)
            val time = Files.getLastModifiedTime(file)
            var interleaved = false
            f.hook = { point -> if (point == if (afterCapture) GitOperationCrashPoint.AFTER_WORKSPACE_CAPTURE else GitOperationCrashPoint.AFTER_WORKSPACE_VALIDATION) {
                interleaved = true
                Files.writeString(file, "int evil = 1;\n")
                Files.setLastModifiedTime(file, time)
            } }
            val result = service.run(repositoryId, GitStageRequest(review.record.worktreeId, guards,
                review.ids { it.path.exact == "src/main.c" }, true), "capture_content_0001")
            assertTrue(interleaved)
            if (afterCapture) {
                assertEquals(GitOperationState.COMPLETED, result.state, result.message)
                assertEquals("int safe = 1;\n", f.repositories.git("--git-dir=$gitDir", "show", ":src/main.c"))
            } else {
                assertEquals(GitOperationState.FAILED, result.state, result.message)
                assertEquals("WORKTREE_CHANGED", result.failureCode)
                assertEquals("", f.repositories.git("--git-dir=$gitDir", "ls-files", "--stage"))
            }
            assertEquals("int evil = 1;\n", Files.readString(file))
            assertTrue(Files.notExists(gitDir.resolve("index.lock")))
        }
    }

    @Test fun `captured index entries preserve literal names executable modes and link bytes`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val workTree = gitDir.parent.resolve("worktree")
        val literal = "src/literal[\t\n].c"
        Files.writeString(workTree.resolve(literal), "int literal;\n")
        Files.setPosixFilePermissions(workTree.resolve(literal), java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"))
        Files.createSymbolicLink(workTree.resolve("src/link.c"), Path.of("../src/main.c"))
        val (review, guards) = service.guards(repositoryId)
        val result = service.run(repositoryId, GitStageRequest(review.record.worktreeId, guards,
            review.ids { it.path.exact in setOf(literal, "src/link.c") }, true), "capture_modes_000001")
        assertEquals(GitOperationState.COMPLETED, result.state, result.message)
        assertEquals("int literal;\n", f.repositories.git("--git-dir=$gitDir", "show", ":$literal"))
        assertEquals("../src/main.c", f.repositories.git("--git-dir=$gitDir", "show", ":src/link.c"))
        val index = f.repositories.git("--git-dir=$gitDir", "ls-files", "--stage", "-z")
        assertTrue(index.split('\u0000').single { it.endsWith("\t$literal") }.startsWith("100755 "))
        assertTrue(index.split('\u0000').single { it.endsWith("\tsrc/link.c") }.startsWith("120000 "))
        assertEquals("REPOSITORY_UNAVAILABLE", assertFailsWith<GitRepositoryException> {
            GitWorkspaceContent.fingerprint(workTree, workTree.resolve(literal), GitWorkspaceContent.Budget(4))
        }.code)
    }

    @Test fun `external index additions before locked validation preserve an unselected rename descendant`(): Unit {
        for (format in listOf(GitObjectFormat.SHA1, GitObjectFormat.SHA256)) Fixture().use { f ->
            val service = f.open(GitRepositoryPolicy(defaultBranch = "trunk", objectFormat = format))
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val workTree = gitDir.parent.resolve("worktree")
            fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
            Files.writeString(workTree.resolve("a.c"), "int rename_source;\n")
            f.repositories.commitAll(gitDir, workTree, "baseline")
            raw("mv", "a.c", "b.c")
            val (review, guards) = service.guards(repositoryId)
            val selection = review.ids { it.path.exact == "b.c" && it.staged == GitIndexChange.RENAMED }
            assertEquals(1, selection.size)
            f.hook = { if (it == GitOperationCrashPoint.AFTER_RUNNING) {
                Files.createDirectory(workTree.resolve("a.c"))
                Files.writeString(workTree.resolve("a.c/extra.c"), "int unselected;\n")
                raw("add", "--", "a.c/extra.c")
            } }
            val result = service.run(repositoryId, GitStageRequest(review.record.worktreeId, guards, selection, false), "rename_external_0001")
            assertEquals(GitOperationState.FAILED, result.state, result.message)
            assertEquals("WORKTREE_CHANGED", result.failureCode)
            assertEquals(setOf("a.c/extra.c", "b.c", "CMakeLists.txt", "src/main.c", "src/util.c"),
                raw("ls-files").lines().filter { it.isNotEmpty() }.toSet())
        }
    }

    @Test fun `unstage refuses hidden gitlinks before reset pathspec can remove them`(): Unit {
        for (format in listOf(GitObjectFormat.SHA1, GitObjectFormat.SHA256)) Fixture().use { f ->
            val service = f.open(GitRepositoryPolicy(defaultBranch = "trunk", objectFormat = format))
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val workTree = gitDir.parent.resolve("worktree")
            fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
            Files.writeString(workTree.resolve("a.c"), "int rename_source;\\n")
            val parent = f.repositories.commitAll(gitDir, workTree, "baseline")
            raw("mv", "a.c", "b.c")
            val (review, guards) = service.guards(repositoryId)
            val selection = review.ids { it.path.exact == "b.c" && it.staged == GitIndexChange.RENAMED }
            assertEquals(1, selection.size)
            val hidden = "a.c/hidden.c"
            raw("update-index", "--add", "--cacheinfo", "160000,$parent,$hidden")
            val before = raw("ls-files", "--stage", "-z")
            val result = service.run(repositoryId,
                GitStageRequest(review.record.worktreeId, guards, selection, false), "unstage_hidden_gitlink_01")
            assertEquals(GitOperationState.FAILED, result.state, result.message)
            assertEquals("EXCLUDED_PATH", result.failureCode)
            assertEquals(before, raw("ls-files", "--stage", "-z"), "refusal preserves both rename and hidden gitlink")
            assertTrue(raw("ls-files", "--stage", "-z").contains(hidden))
        }
    }

    @Test fun `staging refuses unchanged gitlinks hidden beneath selected file paths`(): Unit {
        for (format in listOf(GitObjectFormat.SHA1, GitObjectFormat.SHA256)) Fixture().use { f ->
            val service = f.open(GitRepositoryPolicy(defaultBranch = "trunk", objectFormat = format))
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val workTree = gitDir.parent.resolve("worktree")
            fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
            f.repositories.commitAll(gitDir, workTree, "baseline")
            val parent = raw("rev-parse", "HEAD").trim()
            val hidden = "a/hidden.c"
            raw("update-index", "--add", "--cacheinfo", "160000,$parent,$hidden")
            raw("commit", "-q", "-m", "baseline gitlink")
            val headBefore = raw("rev-parse", "HEAD").trim()
            Files.writeString(workTree.resolve("a"), "int ordinary;\n")
            val before = raw("ls-files", "--stage", "-z")
            val (review, guards) = service.guards(repositoryId)
            val selection = review.ids { it.path.exact == "a" && it.untracked }
            assertEquals(1, selection.size)

            val result = service.run(repositoryId,
                GitStageRequest(review.record.worktreeId, guards, selection, true), "stage_unchanged_gitlink_01")
            assertEquals(GitOperationState.FAILED, result.state, result.message)
            assertEquals("EXCLUDED_PATH", result.failureCode)
            assertEquals(before, raw("ls-files", "--stage", "-z"), "refusal preserves the unchanged gitlink")
            assertEquals(headBefore, raw("rev-parse", "HEAD").trim())
        }
    }

    @Test fun `staging refuses hidden regular index entries that conflict with selected file paths`(): Unit {
        for (format in listOf(GitObjectFormat.SHA1, GitObjectFormat.SHA256)) Fixture().use { f ->
            val service = f.open(GitRepositoryPolicy(defaultBranch = "trunk", objectFormat = format))
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val workTree = gitDir.parent.resolve("worktree")
            fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
            val hidden = "a/child.c"
            Files.createDirectories(workTree.resolve("a"))
            Files.writeString(workTree.resolve(hidden), "int retained;\n")
            f.repositories.commitAll(gitDir, workTree, "baseline")
            raw("update-index", "--skip-worktree", hidden)
            Files.delete(workTree.resolve(hidden))
            Files.delete(workTree.resolve("a"))
            Files.writeString(workTree.resolve("a"), "int replacement;\n")
            val before = raw("ls-files", "--stage", "-z")
            val (review, guards) = service.guards(repositoryId)
            val selection = review.ids { it.path.exact == "a" && it.untracked }
            assertEquals(1, selection.size)

            val result = service.run(repositoryId,
                GitStageRequest(review.record.worktreeId, guards, selection, true), "stage_hidden_regular_01")
            assertEquals(GitOperationState.FAILED, result.state, result.message)
            assertEquals("EXCLUDED_PATH", result.failureCode)
            assertEquals(before, raw("ls-files", "--stage", "-z"), "refusal preserves the hidden regular entry")
            assertTrue(before.contains(hidden))
        }
    }

    @Test fun `staging an edited symlink placeholder preserves its reviewed logical mode`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val workTree = gitDir.parent.resolve("worktree")
        fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
        val target = "../src/main.c"
        val targetFile = f.repositories.root.resolve("symlink-target")
        Files.writeString(targetFile, target)
        val blob = raw("hash-object", "-w", "--", targetFile.toString()).trim()
        raw("update-index", "--add", "--cacheinfo", "120000,$blob,src/link.c")
        raw("commit", "-q", "-m", "symlink baseline")
        val placeholder = workTree.resolve("src/link.c")
        Files.writeString(placeholder, target)
        assertTrue(Files.isRegularFile(placeholder, java.nio.file.LinkOption.NOFOLLOW_LINKS))
        assertEquals("../src/main.c", Files.readString(placeholder))
        Files.writeString(placeholder, "../src/util.c")
        val (review, guards) = service.guards(repositoryId)
        val entry = review.observation.status.entries.single { it.path.exact == "src/link.c" }
        assertEquals("120000", entry.indexMode)
        assertEquals("120000", entry.worktreeMode)

        val result = service.run(repositoryId, GitStageRequest(review.record.worktreeId, guards,
            review.ids { it.path.exact == "src/link.c" }, true), "stage_symlink_placeholder_01")
        assertEquals(GitOperationState.COMPLETED, result.state, result.message)
        val indexEntry = f.repositories.git("--git-dir=$gitDir", "ls-files", "--stage", "--", "src/link.c")
        assertTrue(indexEntry.startsWith("120000 "), indexEntry)
        assertEquals("../src/util.c", f.repositories.git("--git-dir=$gitDir", "show", ":src/link.c"))
    }

    @Test fun `staging refuses hidden gitlinks that conflict with selected file paths`(): Unit {
        for (format in listOf(GitObjectFormat.SHA1, GitObjectFormat.SHA256)) Fixture().use { f ->
            val service = f.open(GitRepositoryPolicy(defaultBranch = "trunk", objectFormat = format))
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val workTree = gitDir.parent.resolve("worktree")
            fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
            val parent = f.repositories.commitAll(gitDir, workTree, "baseline")
            Files.writeString(workTree.resolve("a"), "int ordinary;\n")
            val hidden = "a/hidden.c"
            raw("update-index", "--add", "--cacheinfo", "160000,$parent,$hidden")
            val before = raw("ls-files", "--stage", "-z")
            val (review, guards) = service.guards(repositoryId)
            val selection = review.ids { it.path.exact == "a" && it.untracked }
            assertEquals(1, selection.size)

            val result = service.run(repositoryId,
                GitStageRequest(review.record.worktreeId, guards, selection, true), "stage_hidden_gitlink_01")
            assertEquals(GitOperationState.FAILED, result.state, result.message)
            assertEquals("EXCLUDED_PATH", result.failureCode)
            assertEquals(before, raw("ls-files", "--stage", "-z"), "refusal preserves the hidden gitlink")
            assertTrue(before.contains(hidden))
        }
    }

    @Test fun `external Git writers cannot change index or parent between validation and mutation`(): Unit {
        for (format in listOf(GitObjectFormat.SHA1, GitObjectFormat.SHA256)) for (stage in listOf(false, true)) Fixture().use { f ->
            val service = f.open(GitRepositoryPolicy(defaultBranch = "trunk", objectFormat = format))
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val workTree = gitDir.parent.resolve("worktree")
            fun raw(vararg args: String, expect: Int = 0) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree, expect = expect)
            Files.writeString(workTree.resolve("a.c"), "int rename_source;\n")
            val parent = f.repositories.commitAll(gitDir, workTree, "baseline")
            if (stage) Files.writeString(workTree.resolve("b.c"), "int new_source;\n") else raw("mv", "a.c", "b.c")
            val (review, guards) = service.guards(repositoryId)
            val selection = review.ids { it.path.exact == "b.c" }
            assertEquals(1, selection.size)
            var attempted = false
            f.hook = { if (it == GitOperationCrashPoint.AFTER_WORKSPACE_VALIDATION) {
                attempted = true
                if (stage) Files.writeString(workTree.resolve("extra.c"), "int unselected;\n") else {
                    Files.createDirectory(workTree.resolve("a.c"))
                    Files.writeString(workTree.resolve("a.c/extra.c"), "int unselected;\n")
                }
                raw("add", "--", if (stage) "extra.c" else "a.c/extra.c", expect = 128)
                raw("update-ref", "refs/heads/trunk", parent, parent, expect = 128)
            } }
            val result = service.run(repositoryId, GitStageRequest(review.record.worktreeId, guards, selection, stage), "locked_boundary_0001")
            assertTrue(attempted)
            assertEquals(GitOperationState.COMPLETED, result.state, result.message)
            assertEquals(if (stage) "b.c\n" else "", raw("diff", "--cached", "--name-only"))
            assertEquals(parent, raw("rev-parse", "HEAD").trim())
            for (lock in listOf("index.lock", "HEAD.lock", "refs/heads/trunk.lock")) assertTrue(Files.notExists(gitDir.resolve(lock)), lock)
        }
    }

    @Test fun `interrupted index transactions reclaim only witnessed locks and never replay`(): Unit {
        for (stage in listOf(false, true)) for (external in listOf(false, true)) Fixture().use { f ->
            val service = f.open()
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            if (!stage) {
                val (view, guards) = service.guards(repositoryId)
                service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards,
                    view.ids { it.path.exact == "src/main.c" }, true), "recovery_setup_0001")
            }
            val (review, guards) = service.guards(repositoryId)
            val before = f.repositories.git("--git-dir=$gitDir", "ls-files", "--stage")
            val request = GitStageRequest(review.record.worktreeId, guards, review.ids { it.path.exact == "src/main.c" }, stage)
            f.hook = { if (it == GitOperationCrashPoint.AFTER_WORKSPACE_VALIDATION) throw SimulatedGitCrash() }
            val admission = service.requestWorkspace(jobId, repositoryId, request, "crash_index_tx_0001")
            assertTrue(service.awaitIdle(60_000)); service.close(); f.hook = {}
            val operationId = admission.operation.operationId
            val staging = Files.createDirectories(f.store.resolve("$jobId/git/staging/$operationId"))
            val marker = "decomp-operation:$operationId\n"
            for (name in listOf("index.lock", "HEAD.lock", "ref-lock")) {
                val witness = Files.writeString(staging.resolve(name), marker)
                val lock = gitDir.resolve(if (name == "ref-lock") "refs/heads/trunk.lock" else name)
                if (external && name == "index.lock") Files.writeString(lock, marker) else Files.createLink(lock, witness)
            }
            Files.writeString(staging.resolve("ref-name"), "refs/heads/trunk")
            val restarted = f.open()
            restarted.recover(listOf(jobId))
            assertEquals(GitOperationState.INTERRUPTED, restarted.operation(jobId, repositoryId, operationId).state)
            assertEquals(before, f.repositories.git("--git-dir=$gitDir", "ls-files", "--stage"))
            assertTrue(Files.notExists(gitDir.resolve("HEAD.lock")))
            assertTrue(Files.notExists(gitDir.resolve("refs/heads/trunk.lock")))
            if (external) {
                assertEquals(marker, Files.readString(gitDir.resolve("index.lock")))
                Files.delete(gitDir.resolve("index.lock")) // Explicitly release our fixture's external lock.
            } else assertTrue(Files.notExists(gitDir.resolve("index.lock")))
            val retried = restarted.run(repositoryId, request, "retry_index_tx_0001")
            assertEquals(GitOperationState.COMPLETED, retried.state, retried.message)
        }
    }

    @Test fun `unstage private index uses the guarded parent rather than mutable HEAD`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val workTree = gitDir.parent.resolve("worktree")
        val parent = f.repositories.commitAll(gitDir, workTree, "baseline")
        Files.writeString(workTree.resolve("src/main.c"), "int changed;\n")
        f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", "add", "src/main.c")
        val (review, _) = service.guards(repositoryId)
        val entries = GitWorkspaceMutations.select(review.record, review.observation, review.ids { it.path.exact == "src/main.c" }, false)
        val privateIndex = f.repositories.root.resolve("private-index")
        Files.copy(gitDir.resolve("index"), privateIndex)
        f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", "commit", "-q", "-m", "external new head")
        GitWorkspaceMutations.unstage(f.repositories.runner, gitDir, workTree, entries, parent, privateIndex)
        assertEquals(f.repositories.git("--git-dir=$gitDir", "show", "$parent:src/main.c"),
            f.repositories.git("--git-dir=$gitDir", "show", ":src/main.c", variables = mapOf("GIT_INDEX_FILE" to privateIndex.toString())))
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
        val descendant = replaced.ids { it.path.exact == "src/util.c/extra.c" }
        assertEquals("SELECTION_OVERLAP", assertFailsWith<ManagedGitException> {
            service.requestWorkspace(jobId, repositoryId,
                GitStageRequest(replaced.record.worktreeId, replacedGuards, descendant, true), "stage_child_only_01")
        }.code)
        val unchanged = service.guards(repositoryId)
        assertEquals(replacedGuards, unchanged.second, "refusal must leave the index unchanged")
        // Explicitly selecting both affected entries is allowed; the index-only deletion runs first.
        assertEquals(2, GitWorkspaceMutations.select(replaced.record, replaced.observation, deletion + descendant, true).size)
        val stagedDeletion = service.run(repositoryId, GitStageRequest(replaced.record.worktreeId, replacedGuards, deletion, true), "stage_key_0000032")
        assertEquals(GitOperationState.COMPLETED, stagedDeletion.state, stagedDeletion.message)
        val after = service.workspace(jobId, repositoryId).observation.status.entries
        assertEquals(GitIndexChange.DELETED, after.single { it.path.exact == "src/util.c" }.staged)
        assertTrue(after.single { it.path.exact == "src/util.c/extra.c" }.untracked)
        // Once the ancestor deletion is already staged, adding the child sweeps in nothing else.
        val (afterDeletion, afterDeletionGuards) = service.guards(repositoryId)
        val child = service.run(repositoryId, GitStageRequest(afterDeletion.record.worktreeId, afterDeletionGuards, descendant, true), "stage_child_safe_01")
        assertEquals(GitOperationState.COMPLETED, child.state, child.message)
        assertEquals(GitIndexChange.ADDED, service.workspace(jobId, repositoryId).observation.status.entries.single {
            it.path.exact == "src/util.c/extra.c"
        }.staged)
    }

    @Test fun `coalesced untracked replacements retain overlap protection for staged deletions`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val workTree = gitDir.parent.resolve("worktree")
        fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
        Files.delete(workTree.resolve("src/util.c"))
        Files.createDirectory(workTree.resolve("src/util.c"))
        Files.writeString(workTree.resolve("src/util.c/extra.c"), "int extra;\n")
        f.repositories.commitAll(gitDir, workTree, "directory baseline")
        Files.delete(workTree.resolve("src/util.c/extra.c")); Files.delete(workTree.resolve("src/util.c"))
        Files.writeString(workTree.resolve("src/util.c"), "int replacement;\n")
        raw("add", "-A", "--", "src/util.c")
        Files.delete(workTree.resolve("src/util.c")); Files.createDirectory(workTree.resolve("src/util.c"))
        Files.writeString(workTree.resolve("src/util.c/extra.c"), "int extra = 2;\n")
        val (view, guards) = service.guards(repositoryId)
        val parent = view.ids { it.path.exact == "src/util.c" }
        val child = view.observation.status.entries.single { it.path.exact == "src/util.c/extra.c" }
        assertEquals(GitIndexChange.DELETED, child.staged)
        assertTrue(child.untracked, "the replacement is coalesced with the staged deletion")
        val before = raw("diff", "--cached", "--raw", "--no-renames")
        assertEquals("SELECTION_OVERLAP", assertFailsWith<ManagedGitException> {
            service.requestWorkspace(jobId, repositoryId,
                GitStageRequest(view.record.worktreeId, guards, parent, false), "coalesced_overlap_01")
        }.code)
        assertEquals(before, raw("diff", "--cached", "--raw", "--no-renames"))
        assertEquals(guards, service.guards(repositoryId).second)
        assertEquals("int extra = 2;\n", Files.readString(workTree.resolve("src/util.c/extra.c")))
        // Explicit selection of both tracked changes remains supported.
        val both = parent + child.path.fileId(view.record.worktreeId)
        val result = service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, both, false), "coalesced_overlap_02")
        assertEquals(GitOperationState.COMPLETED, result.state, result.message)
        assertEquals("", raw("diff", "--cached", "--name-only"))
    }

    @Test fun `unstaging deleted descendants never removes unselected staged ancestors`(): Unit {
        for (format in listOf(GitObjectFormat.SHA1, GitObjectFormat.SHA256)) for (rename in listOf(false, true)) Fixture().use { f ->
            val service = f.open(GitRepositoryPolicy(defaultBranch = "trunk", objectFormat = format))
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val workTree = gitDir.parent.resolve("worktree")
            fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
            val parent = workTree.resolve("component.c")
            Files.createDirectory(parent)
            Files.writeString(parent.resolve("child.c"), "int child;\n")
            f.repositories.commitAll(gitDir, workTree, "directory baseline")
            if (rename) raw("mv", "component.c/child.c", "moved.c") else Files.delete(parent.resolve("child.c"))
            Files.delete(parent)
            Files.writeString(parent, "int replacement;\n")
            raw("add", "-A", "--", "component.c")
            val (view, guards) = service.guards(repositoryId)
            val child = view.ids {
                if (rename) it.originalPath?.exact == "component.c/child.c" && it.staged == GitIndexChange.RENAMED
                else it.path.exact == "component.c/child.c" && it.staged == GitIndexChange.DELETED
            }
            val ancestor = view.ids { it.path.exact == "component.c" && it.staged == GitIndexChange.ADDED }
            assertEquals(1, child.size); assertEquals(1, ancestor.size)
            val before = raw("ls-files", "--stage")
            assertEquals("SELECTION_OVERLAP", assertFailsWith<ManagedGitException> {
                service.requestWorkspace(jobId, repositoryId,
                    GitStageRequest(view.record.worktreeId, guards, child, false), "unstage_ancestor_01")
            }.code)
            assertEquals(before, raw("ls-files", "--stage"), "refusal must preserve the unselected ancestor")
            assertEquals(guards, service.guards(repositoryId).second)
            assertEquals("int replacement;\n", Files.readString(parent))
            // Selecting both affected entries is explicit and must still complete.
            val result = service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, child + ancestor, false), "unstage_ancestor_02")
            assertEquals(GitOperationState.COMPLETED, result.state, result.message)
            assertEquals("", raw("diff", "--cached", "--name-only"))
            assertEquals("int replacement;\n", Files.readString(parent))
        }
    }

    @Test fun `commits refuse hidden staged gitlink additions changes deletions and type changes`(): Unit {
        for (format in listOf(GitObjectFormat.SHA1, GitObjectFormat.SHA256)) {
            for (change in listOf("unborn", "added", "modified", "deleted", "to-gitlink", "from-gitlink")) Fixture().use { f ->
                val service = f.open(GitRepositoryPolicy(defaultBranch = "trunk", objectFormat = format))
                val repositoryId = service.initialized()
                val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
                val workTree = gitDir.parent.resolve("worktree")
                fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
                val hidden = "hidden\tmodule\nlink"
                val base = if (change == "unborn") {
                    raw("add", "--", "src/main.c")
                    raw("commit-tree", raw("write-tree").trim(), "-m", "unpublished gitlink target").trim()
                } else f.repositories.commitAll(gitDir, workTree, "source baseline")
                if (change in listOf("modified", "deleted", "from-gitlink")) {
                    raw("update-index", "--add", "--cacheinfo", "160000,$base,$hidden")
                    raw("commit", "-q", "-m", "fixture gitlink baseline")
                } else if (change == "to-gitlink") {
                    Files.writeString(workTree.resolve(hidden), "ordinary source\n")
                    raw("add", "--", hidden); raw("commit", "-q", "-m", "fixture regular baseline")
                }
                Files.writeString(workTree.resolve("src/main.c"), "int main(void) { return 7; }\n")
                raw("add", "--", "src/main.c")
                when (change) {
                    "deleted" -> raw("update-index", "--force-remove", "--", hidden)
                    "from-gitlink" -> raw("update-index", "--cacheinfo", "100644,${raw("rev-parse", "HEAD:src/util.c").trim()},$hidden")
                    else -> {
                        val target = if (change == "modified") raw("rev-parse", "HEAD").trim() else base
                        raw("update-index", "--add", "--cacheinfo", "160000,$target,$hidden")
                    }
                }
                val (view, guards) = service.guards(repositoryId)
                val selected = view.ids { it.path.exact == "src/main.c" }
                val before = raw("diff", "--cached", "--raw", "--ignore-submodules=none")
                assertEquals("EXCLUDED_PATH", assertFailsWith<ManagedGitException>("$format / $change") {
                    service.requestWorkspace(jobId, repositoryId,
                        GitCommitRequest(view.record.worktreeId, guards, selected, "Only reviewed source"), "gitlink_refusal_01")
                }.code)
                assertEquals(guards.expectedHeadObjectId, service.workspace(jobId, repositoryId).observation.head.objectId)
                assertEquals(before, raw("diff", "--cached", "--raw", "--ignore-submodules=none"))
                assertTrue(Files.notExists(gitDir.resolve("index.lock")))
                assertTrue(Files.notExists(gitDir.resolve("HEAD.lock")))
            }
        }
    }

    @Test fun `captured commit indices refuse gitlinks even when the observation predates their staging`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val workTree = gitDir.parent.resolve("worktree")
        val base = f.repositories.commitAll(gitDir, workTree, "source baseline")
        Files.writeString(workTree.resolve("src/main.c"), "int main(void) { return 7; }\n")
        f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", "add", "--", "src/main.c")
        val review = service.workspace(jobId, repositoryId)
        f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", "update-index", "--add", "--cacheinfo", "160000,$base,hidden-submodule")
        val staging = Files.createDirectory(f.repositories.root.resolve("private-commit"))
        val message = Files.writeString(staging.resolve("message"), "Only reviewed source")
        assertEquals("EXCLUDED_PATH", assertFailsWith<GitOperationRefusal> {
            GitWorkspaceMutations.withCommitLocks(gitDir, staging, "capture_gitlink") {
                GitWorkspaceMutations.createCommit(f.repositories.runner, gitDir, workTree, message,
                    GitRepositoryPolicy(), review.observation)
            }
        }.code)
        val capturedIndex = staging.resolve("reviewed-index")
        assertTrue(Files.isRegularFile(capturedIndex))
        // Removing it from the live index cannot hide it from validation of the captured copy.
        f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", "update-index", "--force-remove", "--", "hidden-submodule")
        GitWorkspaceMutations.requireNoStagedGitlinks(f.repositories.runner, gitDir, workTree, base)
        assertEquals("EXCLUDED_PATH", assertFailsWith<GitOperationRefusal> {
            GitWorkspaceMutations.requireNoStagedGitlinks(f.repositories.runner, gitDir, workTree, base, capturedIndex)
        }.code)
        assertEquals(base, service.workspace(jobId, repositoryId).observation.head.objectId)
        assertTrue(Files.notExists(gitDir.resolve("index.lock")))
        assertTrue(Files.notExists(gitDir.resolve("HEAD.lock")))
    }

    @Test fun `a gitlink staged after admission fails execution without publishing a commit`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val workTree = gitDir.parent.resolve("worktree")
        val base = f.repositories.commitAll(gitDir, workTree, "source baseline")
        Files.writeString(workTree.resolve("src/main.c"), "int main(void) { return 7; }\n")
        f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", "add", "--", "src/main.c")
        val (review, guards) = service.guards(repositoryId)
        var inserted = false
        f.hook = { if (it == GitOperationCrashPoint.AFTER_RUNNING) {
            inserted = true
            f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", "update-index", "--add", "--cacheinfo", "160000,$base,hidden-submodule")
        } }
        val result = service.run(repositoryId, GitCommitRequest(review.record.worktreeId, guards,
            review.ids { it.path.exact == "src/main.c" }, "Only reviewed source"), "gitlink_execution_01")
        assertTrue(inserted)
        assertEquals(GitOperationState.FAILED, result.state, result.message)
        assertEquals("EXCLUDED_PATH", result.failureCode)
        assertNull(result.resultObjectId)
        assertEquals(base, service.workspace(jobId, repositoryId).observation.head.objectId)
        assertTrue(f.repositories.git("--git-dir=$gitDir", "ls-files", "--stage").contains("160000 $base"))
    }

    @Test fun `routine work-tree operations retire old terminal records instead of exhausting the quota`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val operations = f.store.resolve(jobId).resolve("git").resolve("operations")
        val first = mutableListOf<String>()
        repeat(ManagedGitRepositories.MAX_OPERATIONS / 2 + 2) { cycle ->
            for (stage in listOf(true, false)) {
                val (view, guards) = service.guards(repositoryId)
                val record = service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.path.exact == "src/main.c" }, stage),
                    "cycle_${if (stage) "s" else "u"}_${"%04d".format(cycle)}_000000")
                assertEquals(GitOperationState.COMPLETED, record.state, record.message)
                if (cycle == 0) first += record.operationId
            }
        }
        val retained = Files.list(operations).use { files -> files.map { it.fileName.toString() }.toList() }
        assertTrue(retained.size <= ManagedGitRepositories.MAX_OPERATIONS, "retained ${retained.size}")
        assertTrue(first.none { "$it.json" in retained }, "the oldest work-tree records are retired first")
        val (view, guards) = service.guards(repositoryId)
        assertTrue("${view.record.operationId}.json" in retained, "initialization records are never retired")
        // The newest key still replays its original record.
        val request = GitStageRequest(view.record.worktreeId, guards, view.ids { it.path.exact == "src/main.c" }, true)
        val latest = service.run(repositoryId, request, "cycle_latest_key_0000")
        assertEquals(GitOperationState.COMPLETED, latest.state, latest.message)
        assertTrue(service.requestWorkspace(jobId, repositoryId, request, "cycle_latest_key_0000").replayed)
    }

    @Test fun `a staged deletion with an untracked replacement unstages and stages by action`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val workTree = f.store.resolve("$jobId/git/repositories/$repositoryId/worktree")
        val (all, allGuards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(all.record.worktreeId, allGuards, all.ids { it.untracked }, true), "stage_key_0000060")
        val (staged, stagedGuards) = service.guards(repositoryId)
        service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, stagedGuards, staged.ids { it.staged != GitIndexChange.NONE }, "base"), "commit_key_000060")
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
        raw("rm", "-q", "--cached", "--", "src/util.c")
        Files.writeString(workTree.resolve("src/util.c"), "int replacement;\n")
        // Git reports a staged deletion (D.) and an untracked record (?); status merges them into one entry.
        val (view, guards) = service.guards(repositoryId)
        val records = view.observation.status.entries.filter { it.path.exact == "src/util.c" }
        assertEquals(listOf(GitIndexChange.DELETED to true), records.map { it.staged to it.untracked })
        val id = view.ids { it.path.exact == "src/util.c" }.distinct().single()
        val unstaged = service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, listOf(id), false), "unstage_key_00061")
        assertEquals(GitOperationState.COMPLETED, unstaged.state, unstaged.message)
        val after = service.workspace(jobId, repositoryId).observation.status.entries.single { it.path.exact == "src/util.c" }
        assertEquals(GitIndexChange.NONE, after.staged); assertEquals(GitIndexChange.MODIFIED, after.unstaged)
        assertEquals("int replacement;\n", Files.readString(workTree.resolve("src/util.c")))
        // The same pair staged by action adds the replacement instead of refusing the selection.
        raw("rm", "-q", "--cached", "--", "src/util.c")
        val (again, againGuards) = service.guards(repositoryId)
        val restaged = service.run(repositoryId, GitStageRequest(again.record.worktreeId, againGuards, listOf(id), true), "stage_key_0000062")
        assertEquals(GitOperationState.COMPLETED, restaged.state, restaged.message)
        assertEquals(GitIndexChange.MODIFIED, service.workspace(jobId, repositoryId).observation.status.entries.single { it.path.exact == "src/util.c" }.staged)
    }

    @Test fun `unstaging a rename refuses invalid native descendants beneath its original path`() {
        for (format in listOf(GitObjectFormat.SHA1, GitObjectFormat.SHA256)) Fixture().use { f ->
            val service = f.open(GitRepositoryPolicy(defaultBranch = "trunk", objectFormat = format))
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val workTree = gitDir.parent.resolve("worktree")
            fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
            Files.writeString(workTree.resolve("a.c"), "int rename_source;\n")
            f.repositories.commitAll(gitDir, workTree, "baseline")
            raw("mv", "a.c", "b.c")
            val invalidChild = Path.of(java.net.URI(workTree.toUri().toASCIIString() + "a.c/%FF.c"))
            Files.createDirectories(invalidChild.parent)
            Files.writeString(invalidChild, "int unselected;\n")
            raw("add", "-A")

            val (view, guards) = service.guards(repositoryId)
            val invalidEntry = view.observation.status.entries.single { it.path.display == "a.c/\\xff.c" }
            assertNull(invalidEntry.path.exact)
            assertTrue(invalidEntry.path.bytes.contentEquals(byteArrayOf(97, 46, 99, 47, 0xff.toByte(), 46, 99)))
            val rename = view.ids { it.path.exact == "b.c" && it.staged == GitIndexChange.RENAMED }
            assertEquals(1, rename.size)
            val indexBefore = raw("ls-files", "--stage")
            assertEquals("SELECTION_OVERLAP", assertFailsWith<ManagedGitException> {
                service.requestWorkspace(jobId, repositoryId,
                    GitStageRequest(view.record.worktreeId, guards, rename, false), "native_overlap_${format.name}")
            }.code)
            assertEquals(indexBefore, raw("ls-files", "--stage"))
        }
    }

    @Test fun `unstaging a rename never touches staged entries beneath its original path`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val workTree = f.store.resolve("$jobId/git/repositories/$repositoryId/worktree")
        val (all, allGuards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(all.record.worktreeId, allGuards, all.ids { it.untracked }, true), "stage_key_0000050")
        val (staged, stagedGuards) = service.guards(repositoryId)
        service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, stagedGuards, staged.ids { it.staged != GitIndexChange.NONE }, "base"), "commit_key_000050")
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        fun raw(vararg args: String) = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree)
        raw("mv", "src/util.c", "src/moved.c")
        Files.createDirectories(workTree.resolve("src/util.c")); Files.writeString(workTree.resolve("src/util.c/extra.c"), "int extra;\n")
        raw("add", "--", "src/util.c/extra.c")
        val (view, guards) = service.guards(repositoryId)
        val rename = view.ids { it.staged == GitIndexChange.RENAMED }
        assertEquals(1, rename.size)
        assertEquals("SELECTION_OVERLAP", assertFailsWith<ManagedGitException> {
            service.requestWorkspace(jobId, repositoryId, GitStageRequest(view.record.worktreeId, guards, rename, false), "overlap_key_000051")
        }.code)
        assertEquals(GitIndexChange.ADDED, service.workspace(jobId, repositoryId).observation.status.entries.single { it.path.exact == "src/util.c/extra.c" }.staged)
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

    @Test fun `external staging after the reviewed tree is captured cannot enter the commit`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val workTree = gitDir.parent.resolve("worktree")
        val (view, guards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.path.exact == "src/main.c" }, true), "stage_race_key_001")
        val (staged, commitGuards) = service.guards(repositoryId)
        var attempted = false
        f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) {
            attempted = true
            val output = f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", "add", "--", "src/util.c", expect = 128)
            assertTrue(output.contains("index.lock"))
        } }
        val commit = service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, commitGuards,
            staged.ids { it.staged != GitIndexChange.NONE }, "Only main"), "commit_race_key_01")
        assertTrue(attempted)
        assertEquals(GitOperationState.COMPLETED, commit.state, commit.message)
        assertEquals("src/main.c", f.repositories.git("--git-dir=$gitDir", "ls-tree", "-r", "--name-only", assertNotNull(commit.resultObjectId)).trim())
        assertTrue(service.workspace(jobId, repositoryId).observation.status.entries.single { it.path.exact == "src/util.c" }.untracked)
        assertTrue(Files.notExists(gitDir.resolve("index.lock")))
        assertTrue(Files.notExists(gitDir.resolve("HEAD.lock")))
    }

    @Test fun `commit locks refuse competing writers without deleting their locks`(): Unit {
        for (name in listOf("index.lock", "HEAD.lock", "refs/heads/trunk.lock")) Fixture().use { f ->
            val service = f.open()
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val (view, guards) = service.guards(repositoryId)
            service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "stage_lock_key_001")
            val (staged, commitGuards) = service.guards(repositoryId)
            val externalLock = gitDir.resolve(name)
            Files.createDirectories(externalLock.parent)
            f.hook = { if (it == GitOperationCrashPoint.AFTER_RUNNING) Files.writeString(externalLock, "external writer\n") }
            val commit = service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, commitGuards,
                staged.ids { it.staged != GitIndexChange.NONE }, "must not publish"), "commit_lock_key_01")
            assertEquals(GitOperationState.FAILED, commit.state, commit.message)
            assertEquals("WORKTREE_BUSY", commit.failureCode)
            assertNull(commit.resultObjectId)
            assertNull(service.workspace(jobId, repositoryId).observation.head.objectId)
            assertEquals("external writer\n", Files.readString(externalLock))
        }
    }

    @Test fun `a writer bypassing index locks still cannot change the captured commit tree`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val workTree = gitDir.parent.resolve("worktree")
        val (view, guards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.path.exact == "src/main.c" }, true), "stage_bypass_0001")
        val (staged, commitGuards) = service.guards(repositoryId)
        f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) {
            // A non-cooperating writer ignores our lock and replaces the live index directly.
            val index = Files.copy(gitDir.resolve("index"), gitDir.resolve("external-index"))
            f.repositories.git("--git-dir=$gitDir", "--work-tree=$workTree", "add", "--", "src/util.c",
                variables = mapOf("GIT_INDEX_FILE" to index.toString()))
            Files.move(index, gitDir.resolve("index"), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        } }
        val commit = service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, commitGuards,
            staged.ids { it.staged != GitIndexChange.NONE }, "captured tree"), "commit_bypass_001")
        assertEquals(GitOperationState.COMPLETED, commit.state, commit.message)
        assertEquals("src/main.c", f.repositories.git("--git-dir=$gitDir", "ls-tree", "-r", "--name-only", assertNotNull(commit.resultObjectId)).trim())
        assertEquals(GitIndexChange.ADDED, service.workspace(jobId, repositoryId).observation.status.entries.single { it.path.exact == "src/util.c" }.staged)
    }

    @Test fun `publication compares the reviewed parent instead of overwriting an external ref update`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val (view, guards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "stage_ref_key_0001")
        val tree = f.repositories.git("--git-dir=$gitDir", "write-tree").trim()
        val external = f.repositories.git("--git-dir=$gitDir", "commit-tree", tree, "-m", "External writer").trim()
        val (staged, commitGuards) = service.guards(repositoryId)
        f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) {
            // Model an external files-backend ref publisher. The target CAS must still refuse
            // even when that publisher bypasses HEAD.lock (ordinary update-ref is blocked).
            val ref = gitDir.resolve("refs/heads/trunk")
            val refLock = Files.createFile(ref.resolveSibling("trunk.lock"))
            Files.writeString(refLock, "$external\n")
            Files.move(refLock, ref, java.nio.file.StandardCopyOption.ATOMIC_MOVE)
        } }
        val commit = service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, commitGuards,
            staged.ids { it.staged != GitIndexChange.NONE }, "Reviewed writer"), "commit_ref_key_001")
        assertEquals(GitOperationState.FAILED, commit.state, commit.message)
        assertEquals("REF_CHANGED", commit.failureCode)
        assertNull(commit.resultObjectId)
        assertEquals(external, service.workspace(jobId, repositoryId).observation.head.objectId)
    }

    @Test fun `reviewed commits preserve detached parents in both object formats`(): Unit {
        for (format in listOf(GitObjectFormat.SHA1, GitObjectFormat.SHA256)) Fixture().use { f ->
            val service = f.open(GitRepositoryPolicy(defaultBranch = "trunk", objectFormat = format))
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val workTree = gitDir.parent.resolve("worktree")
            val (view, guards) = service.guards(repositoryId)
            service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "stage_detached_01")
            val (staged, commitGuards) = service.guards(repositoryId)
            val base = service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, commitGuards,
                staged.ids { it.staged != GitIndexChange.NONE }, "base"), "commit_detached_1")
            val parent = assertNotNull(base.resultObjectId)
            f.repositories.git("--git-dir=$gitDir", "update-ref", "--no-deref", "HEAD", parent)
            Files.writeString(workTree.resolve("src/util.c"), "int util = 7;\n")
            val (edited, editGuards) = service.guards(repositoryId)
            service.run(repositoryId, GitStageRequest(edited.record.worktreeId, editGuards, edited.ids { it.unstaged != GitIndexChange.NONE }, true), "stage_detached_02")
            val (review, nextGuards) = service.guards(repositoryId)
            val next = service.run(repositoryId, GitCommitRequest(review.record.worktreeId, nextGuards,
                review.ids { it.staged != GitIndexChange.NONE }, "detached"), "commit_detached_2")
            assertEquals(GitOperationState.COMPLETED, next.state, next.message)
            val objectId = assertNotNull(next.resultObjectId)
            assertEquals(parent, f.repositories.git("--git-dir=$gitDir", "rev-parse", "$objectId^").trim())
            val after = service.workspace(jobId, repositoryId).observation
            assertEquals(GitHeadState.DETACHED, after.head.state)
            assertEquals(objectId, after.head.objectId)
            assertTrue(after.status.entries.none { it.staged != GitIndexChange.NONE })
        }
    }

    @Test fun `adding undeclared files to snapshot and worktree cannot borrow the initialized revision`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        f.accepted = true
        val workTree = f.store.resolve("$jobId/git/repositories/$repositoryId/worktree")
        Files.writeString(f.snapshot.resolve("unvalidated.c"), "int unvalidated;\n")
        Files.writeString(workTree.resolve("unvalidated.c"), "int unvalidated;\n")
        val (view, guards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "stage_added_key_01")
        val (staged, commitGuards) = service.guards(repositoryId)
        val commit = service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, commitGuards,
            staged.ids { it.staged != GitIndexChange.NONE }, "enlarged"), "commit_added_key_1")
        assertEquals(GitOperationState.COMPLETED, commit.state, commit.message)
        assertNull(service.workspace(jobId, repositoryId).mapping)
        assertTrue(service.mappings(jobId, repositoryId, listOf(assertNotNull(commit.resultObjectId))).isEmpty())
    }

    @Test fun `snapshot mutation after capture cannot mix canonical and Git hashes`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val workTree = f.store.resolve("$jobId/git/repositories/$repositoryId/worktree")
        val replacement = "int main(void) { return 99; }\n"
        Files.writeString(workTree.resolve("src/main.c"), replacement)
        val (view, guards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "stage_capture_001")
        val (staged, commitGuards) = service.guards(repositoryId)
        var mutated = false
        f.hook = { if (it == GitOperationCrashPoint.AFTER_SNAPSHOT_CAPTURE) {
            mutated = true
            Files.writeString(f.snapshot.resolve("src/main.c"), replacement)
        } }
        val commit = service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, commitGuards,
            staged.ids { it.staged != GitIndexChange.NONE }, "different bytes"), "commit_capture_01")
        assertEquals(GitOperationState.COMPLETED, commit.state, commit.message)
        assertTrue(mutated)
        assertNull(service.workspace(jobId, repositoryId).mapping)
    }

    @Test fun `result identity is the published commit even when another writer advances HEAD`(): Unit = Fixture().use { f ->
        val service = f.open()
        val repositoryId = service.initialized()
        val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
        val (view, guards) = service.guards(repositoryId)
        service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "stage_identity_01")
        val (staged, commitGuards) = service.guards(repositoryId)
        var published: String? = null
        var external: String? = null
        f.hook = { if (it == GitOperationCrashPoint.AFTER_PUBLISH) {
            published = f.repositories.git("--git-dir=$gitDir", "rev-parse", "HEAD").trim()
            val tree = f.repositories.git("--git-dir=$gitDir", "rev-parse", "HEAD^{tree}").trim()
            external = f.repositories.git("--git-dir=$gitDir", "commit-tree", tree, "-p", assertNotNull(published), "-m", "external").trim()
            f.repositories.git("--git-dir=$gitDir", "update-ref", "HEAD", assertNotNull(external), assertNotNull(published))
        } }
        val commit = service.run(repositoryId, GitCommitRequest(staged.record.worktreeId, commitGuards,
            staged.ids { it.staged != GitIndexChange.NONE }, "our commit"), "commit_identity_1")
        assertEquals(GitOperationState.COMPLETED, commit.state, commit.message)
        assertEquals(assertNotNull(published), commit.resultObjectId)
        assertEquals(assertNotNull(external), service.workspace(jobId, repositoryId).observation.head.objectId)
        assertTrue(service.mappings(jobId, repositoryId, listOf(assertNotNull(published))).isNotEmpty())
    }

    @Test fun `ordinary post-publication errors retain the exact commit and mapping IO stays optional`(): Unit {
        for (mappingFailure in listOf(false, true)) Fixture().use { f ->
            val service = f.open()
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val (view, guards) = service.guards(repositoryId)
            service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "stage_outcome_001")
            val (staged, commitGuards) = service.guards(repositoryId)
            f.hook = { if (it == GitOperationCrashPoint.AFTER_PUBLISH) {
                if (mappingFailure) Files.writeString(gitDir.parent.resolve("mappings"), "blocks mapping directory")
                else throw java.io.IOException("ordinary post-publication fault")
            } }
            val request = GitCommitRequest(staged.record.worktreeId, commitGuards, staged.ids { it.staged != GitIndexChange.NONE }, "published once")
            val commit = service.run(repositoryId, request, "commit_outcome_01")
            assertEquals(if (mappingFailure) GitOperationState.COMPLETED else GitOperationState.RECOVERY_REQUIRED, commit.state, commit.message)
            val objectId = assertNotNull(commit.resultObjectId)
            assertEquals(objectId, service.workspace(jobId, repositoryId).observation.head.objectId)
            assertNull(service.workspace(jobId, repositoryId).mapping)
            service.close(); f.hook = {}
            val restarted = f.open()
            restarted.recover(listOf(jobId))
            val recovered = restarted.operation(jobId, repositoryId, commit.operationId)
            assertEquals(commit.state, recovered.state)
            assertEquals(objectId, recovered.resultObjectId)
            assertTrue(restarted.requestWorkspace(jobId, repositoryId, request, "commit_outcome_01").replayed)
            assertEquals("1", f.repositories.git("--git-dir=$gitDir", "rev-list", "--count", "HEAD").trim())
        }
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

    @Test fun `commit locks retain inode witnesses and preserve replacements on exceptional cleanup`(): Unit {
        for (replacement in listOf(null, "index.lock", "HEAD.lock")) GitTestRepositories().use { repositories ->
            val (gitDir, _) = repositories.managed("lock-witness")
            val staging = Files.createDirectory(repositories.root.resolve("staging"))
            val marker = "decomp-operation:operation_1\n"
            assertFailsWith<IllegalStateException> {
                GitWorkspaceMutations.withCommitLocks(gitDir, staging, "operation_1") {
                    for (name in listOf("index.lock", "HEAD.lock")) {
                        assertTrue(Files.isSameFile(gitDir.resolve(name), staging.resolve(name)))
                        assertEquals(marker, Files.readString(staging.resolve(name)))
                    }
                    if (replacement != null) {
                        Files.delete(gitDir.resolve(replacement))
                        // Identical bytes do not prove ownership of a replacement inode.
                        Files.writeString(gitDir.resolve(replacement), marker)
                    }
                    error("fail before publication")
                }
            }
            for (name in listOf("index.lock", "HEAD.lock")) {
                if (name == replacement) assertEquals(marker, Files.readString(gitDir.resolve(name)))
                else assertTrue(Files.notExists(gitDir.resolve(name)))
            }
        }
    }

    @Test fun `restart reclaims empty partial and complete owned commit locks and permits explicit retry`(): Unit {
        for (name in listOf("index.lock", "HEAD.lock")) {
            for (contents in listOf("", "decomp-operation:", "complete")) Fixture().use { f ->
                val service = f.open()
                val repositoryId = service.initialized()
                val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
                val (view, guards) = service.guards(repositoryId)
                service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "stage_recovery_01")
                val (staged, stagedGuards) = service.guards(repositoryId)
                val request = GitCommitRequest(staged.record.worktreeId, stagedGuards,
                    staged.ids { it.staged != GitIndexChange.NONE }, "Explicit retry after restart")
                f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) {
                    val stagingRoot = f.store.resolve("$jobId/git/staging")
                    val operationStaging = Files.list(stagingRoot).use { it.toList().single() }
                    for (lock in listOf("index.lock", "HEAD.lock")) {
                        assertTrue(Files.isSameFile(gitDir.resolve(lock), operationStaging.resolve(lock)))
                    }
                    throw SimulatedGitCrash()
                } }
                val admission = service.requestWorkspace(jobId, repositoryId, request, "crash_recovery_01")
                assertTrue(service.awaitIdle(60_000)); service.close(); f.hook = {}
                // SimulatedGitCrash unwinds finally blocks. Restore persisted states reachable
                // immediately after either lock is linked, or while its contents are incomplete.
                // These are deterministic filesystem injections, not an OS process-kill test.
                val operationId = admission.operation.operationId
                val staging = Files.createDirectories(f.store.resolve("$jobId/git/staging/$operationId"))
                val marker = "decomp-operation:$operationId\n"
                for (lock in if (name == "index.lock") listOf(name) else listOf("index.lock", name)) {
                    val witness = Files.writeString(staging.resolve(lock), marker)
                    Files.createLink(gitDir.resolve(lock), witness)
                }
                Files.writeString(gitDir.resolve(name), if (contents == "complete") marker else contents)
                val restarted = f.open()
                restarted.recover(listOf(jobId))
                val recovered = restarted.operation(jobId, repositoryId, operationId)
                assertEquals(GitOperationState.INTERRUPTED, recovered.state, "$name / $contents")
                for (lock in listOf("index.lock", "HEAD.lock")) assertTrue(Files.notExists(gitDir.resolve(lock)))
                assertTrue(Files.notExists(staging))
                val retried = restarted.run(repositoryId, request, "retry_recovery_01")
                assertEquals(GitOperationState.COMPLETED, retried.state, retried.message)
                assertNotNull(retried.resultObjectId)
            }
        }
    }

    @Test fun `restart preserves external replacement commit locks even with identical markers`(): Unit {
        for (replacement in listOf("index.lock", "HEAD.lock")) Fixture().use { f ->
            val service = f.open()
            val repositoryId = service.initialized()
            val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
            val (view, guards) = service.guards(repositoryId)
            service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "stage_external_01")
            val (staged, stagedGuards) = service.guards(repositoryId)
            val request = GitCommitRequest(staged.record.worktreeId, stagedGuards,
                staged.ids { it.staged != GitIndexChange.NONE }, "Explicit retry after external unlock")
            f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) throw SimulatedGitCrash() }
            val admission = service.requestWorkspace(jobId, repositoryId, request, "crash_external_01")
            assertTrue(service.awaitIdle(60_000)); service.close(); f.hook = {}
            val operationId = admission.operation.operationId
            val staging = Files.createDirectories(f.store.resolve("$jobId/git/staging/$operationId"))
            val marker = "decomp-operation:$operationId\n"
            for (name in listOf("index.lock", "HEAD.lock")) {
                val witness = Files.writeString(staging.resolve(name), marker)
                if (name == replacement) Files.writeString(gitDir.resolve(name), marker)
                else Files.createLink(gitDir.resolve(name), witness)
            }
            val restarted = f.open()
            restarted.recover(listOf(jobId))
            val recovered = restarted.operation(jobId, repositoryId, operationId)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, recovered.state)
            assertEquals("COMMIT_LOCKS_REQUIRE_REVIEW", recovered.failureCode)
            assertEquals(marker, Files.readString(gitDir.resolve(replacement)))
            val owned = if (replacement == "index.lock") "HEAD.lock" else "index.lock"
            assertTrue(Files.notExists(gitDir.resolve(owned)))
            assertTrue(Files.notExists(staging))
            val blocked = restarted.run(repositoryId, request, "busy_external_001")
            assertEquals("WORKTREE_BUSY", blocked.failureCode)
            assertEquals(marker, Files.readString(gitDir.resolve(replacement)))
            Files.delete(gitDir.resolve(replacement)) // Release this test-owned external writer's lock explicitly.
            val retried = restarted.run(repositoryId, request, "retry_external_01")
            assertEquals(GitOperationState.COMPLETED, retried.state, retried.message)
        }
    }

    @Test fun `legacy unproven partial locks require recovery while complete markers remain reclaimable`(): Unit {
        for (name in listOf("index.lock", "HEAD.lock", "refs/heads/trunk.lock")) {
            for (contents in listOf("", "decomp-operation:", "complete")) Fixture().use { f ->
                val service = f.open()
                val repositoryId = service.initialized()
                val gitDir = f.store.resolve("$jobId/git/repositories/$repositoryId/repository.git")
                val (view, guards) = service.guards(repositoryId)
                service.run(repositoryId, GitStageRequest(view.record.worktreeId, guards, view.ids { it.untracked }, true), "stage_legacy_001")
                val (staged, stagedGuards) = service.guards(repositoryId)
                f.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) throw SimulatedGitCrash() }
                val admission = service.requestWorkspace(jobId, repositoryId, GitCommitRequest(staged.record.worktreeId, stagedGuards,
                    staged.ids { it.staged != GitIndexChange.NONE }, "Interrupted legacy commit"), "crash_legacy_001")
                assertTrue(service.awaitIdle(60_000)); service.close(); f.hook = {}
                val bytes = if (contents == "complete") "decomp-operation:${admission.operation.operationId}\n" else contents
                val file = gitDir.resolve(name)
                Files.createDirectories(file.parent)
                Files.writeString(file, bytes) // No private inode witness exists for this legacy/external lock.
                val restarted = f.open()
                restarted.recover(listOf(jobId))
                val recovered = restarted.operation(jobId, repositoryId, admission.operation.operationId)
                if (contents == "complete" && name != "refs/heads/trunk.lock") {
                    assertEquals(GitOperationState.INTERRUPTED, recovered.state)
                    assertTrue(Files.notExists(file))
                } else {
                    assertEquals(GitOperationState.RECOVERY_REQUIRED, recovered.state, "$name / $contents")
                    assertEquals("COMMIT_LOCKS_REQUIRE_REVIEW", recovered.failureCode)
                    assertEquals(bytes, Files.readString(file))
                }
                assertNull(recovered.resultObjectId)
            }
        }
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
            restarted.recover(listOf(jobId))
            val recovered = restarted.operation(jobId, repositoryId, admission.operation.operationId)
            assertEquals(state, recovered.state, point.name)
            val head = restarted.workspace(jobId, repositoryId).observation.head.objectId
            if (state == GitOperationState.INTERRUPTED) assertNull(head) else assertEquals(head, recovered.resultObjectId)
            assertTrue(Files.notExists(f.store.resolve("$jobId/git/staging/${admission.operation.operationId}")))
        }
    }
}
