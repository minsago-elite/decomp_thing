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
        var clock: java.time.Clock = java.time.Clock.systemUTC()
        var stable = false
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
        fun open() = ManagedGitRepositories(store, GitRuntime.detect(), { _, _, _ -> error("no snapshots") },
            policy = GitRepositoryPolicy(defaultBranch = "main", requireSignedCommits = signed), clock = clock, crash = { hook(it) }, activity = activity,
            remotePolicy = GitRemotePolicy(admittedRoot = admitted)).also(opened::add)
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
        service.close(); service = f.open()
        // Reconciliation computes the result, but dies before persisting it. Evidence must still survive.
        assertFailsWith<SimulatedGitCrash> { service.operation(jobId, repositoryId, admission.operation.operationId) }
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
