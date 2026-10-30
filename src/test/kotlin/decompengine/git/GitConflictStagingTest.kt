package decompengine.git

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GitConflictStagingTest {
    private class Fixture : AutoCloseable {
        val jobId = "0123456789abcdef0123456789abcdef"
        private val repositories = GitTestRepositories()
        private val store = Files.createDirectories(repositories.root.resolve("store"))
        private val admitted = Files.createDirectories(repositories.root.resolve("admitted")).toRealPath()
        private val seed = Files.createDirectories(repositories.root.resolve("seed"))
        private val bare = admitted.resolve("upstream.git")
        private val leases = GitWorkspaceLeases()
        private val opened = mutableListOf<ManagedGitRepositories>()
        private var keyNumber = 0
        var hook: (GitOperationCrashPoint) -> Unit = {}
        lateinit var repositoryId: String
            private set
        lateinit var service: ManagedGitRepositories
            private set

        init {
            Files.createDirectories(store.resolve(jobId))
            repositories.git("init", "-q", "--bare", "--initial-branch=main", bare.toString())
            repositories.git("init", "-q", "--initial-branch=main", seed.toString())
            Files.writeString(seed.resolve("README.md"), "line one\nline two\n")
            Files.writeString(seed.resolve("util.c"), "int util;\n")
            remoteCommit("base")
            service = open()
            val cloned = service.request(jobId, GitCloneRequest("admitted:upstream.git", "origin", null), key())
            assertTrue(service.awaitIdle(60_000))
            repositoryId = cloned.operation.repositoryId
            assertEquals(
                GitOperationState.COMPLETED,
                service.operation(jobId, repositoryId, cloned.operation.operationId).state,
            )
        }

        private fun key(): String = "conflict_staging_key_${(++keyNumber).toString().padStart(6, '0')}"

        private fun remoteCommit(message: String) {
            repositories.git("-C", seed.toString(), "add", "-A")
            repositories.git("-C", seed.toString(), "commit", "-q", "-m", message)
            repositories.git("-C", seed.toString(), "push", "-q", bare.toString(), "main")
        }

        private fun open(recover: Boolean = true): ManagedGitRepositories =
            ManagedGitRepositories(
                store,
                GitRuntime.detect(),
                { _, _, _ -> error("no snapshots") },
                policy = GitRepositoryPolicy(defaultBranch = "main"),
                crash = { hook(it) },
                activity =
                    object : GitJobActivity {
                        override fun runs(jobId: String) = emptyMap<String, Boolean>()

                        override fun <T> withStableRuns(
                            jobId: String,
                            block: (Map<String, Boolean>) -> T,
                        ): T = block(runs(jobId))
                    },
                remotePolicy = GitRemotePolicy(admittedRoot = admitted),
                workspaceLeases = leases,
            ).also {
                opened += it
                if (recover) it.recover(listOf(jobId))
            }

        fun restart() {
            service.close()
            service = open()
        }

        fun workTree(): Path = store.resolve("$jobId/git/repositories/$repositoryId/worktree")

        fun gitDir(): Path = store.resolve("$jobId/git/repositories/$repositoryId/repository.git")

        fun staging(operationId: String): Path = store.resolve("$jobId/git/repositories/$repositoryId/staging/$operationId")

        private fun guards(): Pair<GitWorkspaceView, GitGuards> {
            val view = service.workspace(jobId, repositoryId)
            return view to
                GitGuards(
                    GitWorkspaceVersions.repositoryVersion(view.record, view.observation),
                    GitWorkspaceVersions.worktreeVersion(view.observation),
                    view.observation.head.objectId,
                    GitWorkspaceVersions.headRefId(view.record, view.observation),
                    view.observation.head.objectId,
                )
        }

        fun sync(
            action: GitOperationAction,
            parameters: Map<String, String?> = emptyMap(),
            content: String? = null,
        ): GitOperationRecord {
            val (view, currentGuards) = guards()
            val admission =
                service.requestWorkspace(
                    jobId,
                    repositoryId,
                    GitSyncRequest(action, view.worktreeId, currentGuards, parameters, content),
                    key(),
                )
            assertTrue(service.awaitIdle(60_000))
            return service.operation(jobId, repositoryId, admission.operation.operationId)
        }

        fun createConflict(): String {
            Files.writeString(workTree().resolve("README.md"), "line one\nlocal two\n")
            repositories.git("--git-dir=${gitDir()}", "--work-tree=${workTree()}", "add", "--", "README.md")
            repositories.git("--git-dir=${gitDir()}", "--work-tree=${workTree()}", "commit", "-q", "-m", "local edit")
            Files.writeString(seed.resolve("README.md"), "line one\nremote two\n")
            remoteCommit("remote edit")
            val remoteId =
                service
                    .remotes(jobId, repositoryId)
                    .single()
                    .record.remoteId
            assertEquals(GitOperationState.COMPLETED, sync(GitOperationAction.FETCH, mapOf("remoteId" to remoteId)).state)
            val tracking = GitWorkspaceVersions.refId(repositoryId, "refs/remotes/origin/main")
            val target =
                service
                    .remotes(jobId, repositoryId)
                    .single()
                    .tracking
                    .single {
                        it.name == "refs/remotes/origin/main"
                    }.objectId
            val merge =
                sync(
                    GitOperationAction.MERGE,
                    mapOf(
                        "trackingRefId" to tracking,
                        "targetObjectId" to target,
                        "strategy" to "merge",
                    ),
                )
            assertTrue(merge.message.contains("conflicted file"), merge.message)
            val conflicts = service.conflicts(jobId, repositoryId, null)
            return conflicts.files
                .single()
                .path
                .fileId(conflicts.worktreeId)
        }

        fun saveConflict(fileId: String): GitOperationRecord {
            val detail = service.conflictFile(jobId, repositoryId, null, fileId)
            return sync(
                GitOperationAction.CONFLICT_SAVE,
                mapOf(
                    "fileId" to fileId,
                    "expectedSha256" to detail.currentSha256,
                    "resolution" to "text",
                ),
                "line one\nresolved two\n",
            )
        }

        fun completeConflict(fileId: String): GitOperationRecord {
            val detail = service.conflictFile(jobId, repositoryId, null, fileId)
            return sync(
                GitOperationAction.CONFLICT_COMPLETE,
                content = "$fileId ${detail.currentSha256}\n",
            )
        }

        override fun close() {
            opened.forEach { it.close() }
            repositories.close()
        }
    }

    @Test fun `terminal conflict operations remove repository staging`() =
        Fixture().use { fixture ->
            val fileId = fixture.createConflict()
            val saved = fixture.saveConflict(fileId)
            assertEquals(GitOperationState.COMPLETED, saved.state, saved.message)
            assertFalse(Files.exists(fixture.staging(saved.operationId)))

            val completed = fixture.completeConflict(fileId)
            assertEquals(GitOperationState.COMPLETED, completed.state, completed.message)
            assertFalse(Files.exists(fixture.staging(completed.operationId)))
        }

    @Test fun `restart retires repository staging after terminal persistence`() =
        Fixture().use { fixture ->
            val fileId = fixture.createConflict()
            val detail = fixture.service.conflictFile(fixture.jobId, fixture.repositoryId, null, fileId)
            fixture.hook = { if (it == GitOperationCrashPoint.AFTER_TERMINAL_PERSIST) throw SimulatedGitCrash() }
            val (view, guards) =
                fixture.service.workspace(fixture.jobId, fixture.repositoryId).let { current ->
                    current to
                        GitGuards(
                            GitWorkspaceVersions.repositoryVersion(current.record, current.observation),
                            GitWorkspaceVersions.worktreeVersion(current.observation),
                            current.observation.head.objectId,
                            GitWorkspaceVersions.headRefId(current.record, current.observation),
                            current.observation.head.objectId,
                        )
                }
            val admission =
                fixture.service.requestWorkspace(
                    fixture.jobId,
                    fixture.repositoryId,
                    GitSyncRequest(
                        GitOperationAction.CONFLICT_SAVE,
                        view.worktreeId,
                        guards,
                        mapOf("fileId" to fileId, "expectedSha256" to detail.currentSha256, "resolution" to "ours"),
                    ),
                    "conflict_terminal_crash_key_000001",
                )
            assertTrue(fixture.service.awaitIdle(60_000))
            val staging = fixture.staging(admission.operation.operationId)
            assertTrue(Files.isDirectory(staging), "crash after terminal persistence leaves cleanup for restart")
            fixture.hook = {}
            fixture.restart()
            assertEquals(
                GitOperationState.COMPLETED,
                fixture.service.operation(fixture.jobId, fixture.repositoryId, admission.operation.operationId).state,
            )
            assertFalse(Files.exists(staging))
        }

    @Test fun `restart preserves conflict staging while an unowned Git lock remains`() =
        Fixture().use { fixture ->
            val fileId = fixture.createConflict()
            val detail = fixture.service.conflictFile(fixture.jobId, fixture.repositoryId, null, fileId)
            val (view, guards) =
                fixture.service.workspace(fixture.jobId, fixture.repositoryId).let { current ->
                    current to
                        GitGuards(
                            GitWorkspaceVersions.repositoryVersion(current.record, current.observation),
                            GitWorkspaceVersions.worktreeVersion(current.observation),
                            current.observation.head.objectId,
                            GitWorkspaceVersions.headRefId(current.record, current.observation),
                            current.observation.head.objectId,
                        )
                }
            fixture.hook = { if (it == GitOperationCrashPoint.AFTER_STAGING) throw SimulatedGitCrash() }
            val admission =
                fixture.service.requestWorkspace(
                    fixture.jobId,
                    fixture.repositoryId,
                    GitSyncRequest(
                        GitOperationAction.CONFLICT_SAVE,
                        view.worktreeId,
                        guards,
                        mapOf("fileId" to fileId, "expectedSha256" to detail.currentSha256, "resolution" to "ours"),
                    ),
                    "conflict_foreign_lock_key_000001",
                )
            assertTrue(fixture.service.awaitIdle(60_000))
            val staging = fixture.staging(admission.operation.operationId)
            fixture.service.close()
            Files.writeString(fixture.gitDir().resolve("index.lock"), "foreign writer\n")
            fixture.hook = {}
            fixture.restart()
            val recovered = fixture.service.operation(fixture.jobId, fixture.repositoryId, admission.operation.operationId)
            assertEquals(GitOperationState.RECOVERY_REQUIRED, recovered.state)
            assertEquals("foreign writer\n", Files.readString(fixture.gitDir().resolve("index.lock")))
            assertTrue(Files.isDirectory(staging))
        }
}
