package decompengine.git

import decompengine.git.GitStorage.hex
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.security.SecureRandom
import java.time.Clock
import java.time.Instant
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

enum class GitOperationAction(val wireName: String) { INIT("git.init"), ATTACH("git.attach") }

enum class GitOperationState(val wireName: String, val terminal: Boolean) {
    QUEUED("queued", false), RUNNING("running", false), COMPLETED("completed", true), FAILED("failed", true),
    INTERRUPTED("interrupted", true), RECOVERY_REQUIRED("recovery-required", true),
}

sealed interface GitRepositoryRequest {
    val action: GitOperationAction
    /** Normalized intent; equal requests have equal digests. */
    val digest: String

    data class Init(val runId: String, val revisionId: String, val initialBranch: String?) : GitRepositoryRequest {
        override val action get() = GitOperationAction.INIT
        override val digest get() = GitStorage.sha256("git.init\n$runId\n$revisionId\n${initialBranch ?: "\u0000"}\n")
    }

    data class Attach(val sourceName: String) : GitRepositoryRequest {
        override val action get() = GitOperationAction.ATTACH
        override val digest get() = GitStorage.sha256("git.attach\n$sourceName\n")
    }
}

/** Durable operation record. `requestKeySha256` scopes idempotency; the raw key is never stored. */
data class GitOperationRecord(
    val operationId: String,
    val jobId: String,
    val repositoryId: String,
    val worktreeId: String,
    val action: GitOperationAction,
    val state: GitOperationState,
    val revision: Int,
    val createdAt: Instant,
    val endedAt: Instant?,
    val resultObjectId: String?,
    val failureCode: String?,
    val message: String,
    val requestKeySha256: String,
    val request: GitRepositoryRequest,
) {
    val version: String get() = "operation_v$revision"
    val recoveryRequired: Boolean get() = state == GitOperationState.RECOVERY_REQUIRED
}

/** Registration published atomically with its repository directory. */
data class GitRepositoryRecord(
    val repositoryId: String,
    val worktreeId: String,
    val jobId: String,
    val operationId: String,
    val origin: String,
    val objectFormat: GitObjectFormat,
    val createdAt: Instant,
    val runId: String?,
    val candidateRevisionId: String?,
    val sourceSha256: String?,
    val sourceManifestSha256: String?,
    val initialHeadObjectId: String?,
) {
    val trackingPolicy: String get() = GitTrackingPolicy.VERSION
}

/** Read view of one registered repository plus its current bounded observation. */
data class GitWorkspaceView(val record: GitRepositoryRecord, val observation: GitWorkspaceObservation)

data class GitRepositoryListing(val repositories: List<GitRepositoryRecord>, val operations: List<GitOperationRecord>)

data class GitOperationAdmission(val operation: GitOperationRecord, val replayed: Boolean)

/** Recorded source snapshot selected for initialization; the resolver owns run/revision authority. */
/** One recorded build-input commitment of a candidate: exact SHA-256 and byte size. */
data class GitSourceCommitment(val sha256: String, val sizeBytes: Long) {
    init { require(sha256.matches(Regex("[0-9a-f]{64}")) && sizeBytes >= 0) }
}

/**
 * Recorded source snapshot selected for initialization. [commitments] are the candidate's canonical
 * build-input declarations (`path -> digest/size`); the copy must reproduce every one of them.
 */
data class GitSourceSnapshot(
    val directory: Path,
    val runId: String,
    val revisionId: String,
    val sourceSha256: String,
    val commitments: Map<String, GitSourceCommitment>,
) {
    init { require(commitments.isNotEmpty()) { "a source snapshot needs its recorded commitments" } }
}

fun interface GitSourceSnapshotResolver {
    /** Throws [ManagedGitException] `SOURCE_REVISION_UNAVAILABLE` when the attempt has no such candidate. */
    fun resolve(jobId: String, runId: String, revisionId: String): GitSourceSnapshot
}

/** Server policy for new repositories. The default branch is configuration, never assumed by code. */
data class GitRepositoryPolicy(
    val defaultBranch: String = "main",
    val objectFormat: GitObjectFormat = GitObjectFormat.SHA1,
    val identityName: String = "Decomp Workbench",
    val identityEmail: String = "workbench@localhost.invalid",
) {
    init {
        require(GitRefNames.isPlausibleBranchName(defaultBranch) && objectFormat != GitObjectFormat.UNKNOWN)
        require(identityName.isNotBlank() && identityName.length <= 128 && identityName.none { it.isISOControl() || it in "<>" })
        require(identityEmail.matches(Regex("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}")))
    }
}

class ManagedGitException(val code: String, message: String) : RuntimeException(message)

/** One reason a job's Git storage must be retained (#509); codes and messages are fixed public text. */
data class GitRetentionReason(val code: String, val message: String) {
    companion object {
        val OPERATION_ACTIVE = GitRetentionReason("GIT_OPERATION_ACTIVE",
            "A Git repository operation for this job is queued or running. Wait until it finishes, then review the job again.")
        val UNCOMMITTED_CHANGES = GitRetentionReason("GIT_UNCOMMITTED_CHANGES",
            "A managed Git work tree has uncommitted changes. Commit or remove them before deleting the job.")
        val UNPUSHED_COMMITS = GitRetentionReason("GIT_UNPUSHED_COMMITS",
            "Managed Git history has commits that no remote-tracking branch contains. Preserve them before deleting the job.")
        val UNREADABLE = GitRetentionReason("GIT_STATE_UNAVAILABLE",
            "A managed Git repository could not be inspected, so its work is retained. Check Git on the server.")
    }
}

/** Crash points for recovery tests; a crash leaves records and staging exactly as a process death would. */
enum class GitOperationCrashPoint { AFTER_RUNNING, AFTER_STAGING, BEFORE_PUBLISH, AFTER_PUBLISH }
internal class SimulatedGitCrash : Error("simulated process death")

/**
 * Registry and executor for managed repositories (#571-#573). Storage lives in each job's private
 * `git/` directory: durable operation records, an operation-private staging tree and published
 * repositories. A repository directory appears only through one atomic rename of a completely
 * prepared staging tree, so readers never see a half-initialized repository, and nothing is ever
 * written under the job's recorded source snapshots.
 */
class ManagedGitRepositories(
    storeRoot: Path,
    private val availability: GitAvailability,
    private val sources: GitSourceSnapshotResolver,
    importRoot: Path? = null,
    private val policy: GitRepositoryPolicy = GitRepositoryPolicy(),
    private val clock: Clock = Clock.systemUTC(),
    private val crash: (GitOperationCrashPoint) -> Unit = {},
    private val importLimits: GitCheckoutLimits = GitCheckoutLimits(),
    /** How long [close] waits for the Git worker to stop before reporting it still running. */
    private val shutdownTimeout: java.time.Duration = java.time.Duration.ofSeconds(30),
) : AutoCloseable {
    private val root = storeRoot.toAbsolutePath().normalize()
    private val importRoot: Path? = importRoot?.let { configured ->
        try { configured.toRealPath().takeIf { Files.isDirectory(it) } } catch (_: IOException) { null }
    }
    private val lock = Any()
    private val reconciled = HashSet<String>()
    private val active = HashSet<String>()
    private val random = SecureRandom()
    private var closed = false
    private var runner: GitCommandRunner? = null
    private val executor = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(MAX_QUEUED)) { task ->
        Thread(task, "decomp-git-operations").apply { isDaemon = true }
    }

    val importConfigured: Boolean get() = importRoot != null

    // ---- Admission ------------------------------------------------------------------------

    /**
     * Admit one request. A retained key replays its original operation before [precondition]
     * (the caller's fresh guard) runs, so a replay never depends on a guard that is now stale.
     */
    fun request(jobId: String, request: GitRepositoryRequest, requestKey: String,
        precondition: () -> Unit = {}): GitOperationAdmission {
        val runner = requireRunner()
        require(requestKey.matches(Regex("[A-Za-z0-9_-]{16,128}")))
        val keyDigest = GitStorage.sha256("git-repositories-post\n$jobId\n$requestKey")
        synchronized(lock) {
            if (closed) throw ManagedGitException("SERVER_DRAINING", "The server is stopping; no new Git operation was admitted.")
            val directory = jobGitDirectory(jobId)
            reconcile(jobId)
            val operations = operations(jobId)
            operations.firstOrNull { it.requestKeySha256 == keyDigest }?.let { existing ->
                if (existing.request.digest != request.digest) {
                    throw ManagedGitException("IDEMPOTENCY_CONFLICT", "The request key was used for a different repository request.")
                }
                return GitOperationAdmission(existing, replayed = true)
            }
            precondition()
            if (repositories(jobId).isNotEmpty()) {
                throw ManagedGitException("REPOSITORY_EXISTS", "This job already has a managed repository.")
            }
            if (operations.any { !it.state.terminal }) {
                throw ManagedGitException("WORKTREE_BUSY", "Another repository operation is still running for this job.")
            }
            if (operations.size >= MAX_OPERATIONS || executor.queue.remainingCapacity() == 0) {
                throw ManagedGitException("QUOTA_EXCEEDED", "Repository operation capacity is exhausted. Review existing operations first.")
            }
            when (request) {
                is GitRepositoryRequest.Init -> {
                    sources.resolve(jobId, request.runId, request.revisionId)
                    request.initialBranch?.let { branch ->
                        try { GitRefNames.requireBranchName(runner, branch) } catch (_: IllegalArgumentException) {
                            throw ManagedGitException("VALIDATION_FAILED", "The initial branch name is not a valid Git branch name.")
                        }
                    }
                }
                is GitRepositoryRequest.Attach -> {
                    val admitted = importRoot ?: throw ManagedGitException("IMPORT_UNAVAILABLE",
                        "Repository import is not configured on this server.")
                    if (!GitRepositoryImport.isValidName(request.sourceName)) {
                        throw ManagedGitException("VALIDATION_FAILED", "The import source must be one admitted repository name.")
                    }
                    GitRepositoryImport.locate(admitted, request.sourceName) ?: throw ManagedGitException("IMPORT_SOURCE_UNAVAILABLE",
                        "No admitted repository has that name.")
                }
            }
            val operation = GitOperationRecord(identity("operation"), jobId, identity("repository"), identity("worktree"),
                request.action, GitOperationState.QUEUED, 1, clock.instant(), null, null, null, QUEUED_MESSAGE, keyDigest, request)
            persist(directory, operation)
            active += operation.operationId
            try {
                executor.execute { execute(operation) }
            } catch (_: RejectedExecutionException) {
                active -= operation.operationId
                persist(directory, finish(operation, GitOperationState.FAILED, "QUOTA_EXCEEDED",
                    "Repository operation capacity was exhausted before this operation started."))
            }
            return GitOperationAdmission(operations(jobId).single { it.operationId == operation.operationId }, replayed = false)
        }
    }

    // ---- Retention --------------------------------------------------------------------------

    /**
     * Why the job's Git storage must be retained (#509): a queued or running operation owns its
     * staging and records, and a work tree with uncommitted changes or a branch with commits no
     * remote-tracking ref contains would be lost by deletion. Read-only; an uninspectable repository
     * is retained. The caller (job deletion) serializes this check with Git admission.
     */
    fun retentionHolds(jobId: String): List<GitRetentionReason> {
        if (!jobId.matches(JOB_ID) || !Files.isDirectory(root.resolve(jobId).resolve("git"), NOFOLLOW_LINKS)) return emptyList()
        val reasons = LinkedHashSet<GitRetentionReason>()
        val records = try {
            synchronized(lock) {
                if (availability is GitAvailability.Available) reconcile(jobId)
                if (operations(jobId).any { !it.state.terminal }) reasons += GitRetentionReason.OPERATION_ACTIVE
                repositories(jobId)
            }
        } catch (_: Exception) { return listOf(GitRetentionReason.UNREADABLE) }
        if (records.isEmpty()) return reasons.toList()
        val runner = try { requireRunner() } catch (_: ManagedGitException) { return (reasons + GitRetentionReason.UNREADABLE).toList() }
        for (record in records) {
            val directory = root.resolve(jobId).resolve("git").resolve("repositories").resolve(record.repositoryId)
            try {
                val observation = GitRepositoryInspector.inspect(runner, directory.resolve(GIT_DIR), directory.resolve(WORK_TREE))
                // A fresh initialization with no commit whose work tree still holds exactly the job's
                // recorded candidate source contains no user work: deleting the job deletes only its own data.
                if (observation.dirty && !(observation.head.state == GitHeadState.UNBORN &&
                        unchangedInitialization(record, directory.resolve(WORK_TREE)))) {
                    reasons += GitRetentionReason.UNCOMMITTED_CHANGES
                }
                if (unpushed(runner, directory.resolve(GIT_DIR), observation.head.objectId)) reasons += GitRetentionReason.UNPUSHED_COMMITS
            } catch (_: Exception) {
                reasons += GitRetentionReason.UNREADABLE
            }
        }
        return reasons.toList()
    }

    /**
     * Whether an initialized work tree still holds exactly the files copied from its source snapshot:
     * no file added, modified or deleted. Anything unreadable or beyond the copy bound counts as changed.
     */
    private fun unchangedInitialization(record: GitRepositoryRecord, workTree: Path): Boolean {
        val expected = record.sourceManifestSha256?.takeIf { record.origin == "initialized" } ?: return false
        val digests = sortedMapOf<String, String>()
        Files.walk(workTree).use { paths ->
            for (path in paths) {
                GitStorage.checkInterrupted()
                if (path == workTree) continue
                val relative = workTree.relativize(path)
                // The copy never includes these roots, so output written there is not part of the comparison.
                if (relative.getName(0).toString() in GitTrackingPolicy.UNCOPIED_ROOTS) continue
                if (Files.isDirectory(path, NOFOLLOW_LINKS)) continue
                if (!Files.isRegularFile(path, NOFOLLOW_LINKS) || digests.size >= GitSourceCopy.MAX_FILES) return false
                digests[relative.toString()] = GitSourceCopy.digestOf(path)
            }
        }
        return GitSourceCopy.manifestDigest(digests) == expected
    }

    /**
     * Local history is expendable only when a remote-tracking ref contains every tip, including
     * detached HEAD and tag-only history. No configured remote is not evidence of a push. Git's
     * contains check peels annotated tags; non-commit tags fail closed through the unreadable hold.
     */
    private fun unpushed(runner: GitCommandRunner, gitDir: Path, headObjectId: String?): Boolean {
        fun refs(vararg arguments: String) = runner.run(GitInvocation("for-each-ref", listOf(*arguments), gitDir = gitDir))
            .text.lines().filter { it.isNotBlank() }
        val tips = refs("--count=${MAX_RETENTION_BRANCHES + 1}", "--format=%(objectname)", "refs/heads/", "refs/tags/")
        if (tips.size > MAX_RETENTION_BRANCHES) return true
        return (tips + listOfNotNull(headObjectId)).distinct().any { tip ->
            refs("--count=1", "--format=%(refname)", "--contains", tip, "refs/remotes/").isEmpty()
        }
    }

    // ---- Reads ----------------------------------------------------------------------------

    fun listing(jobId: String): GitRepositoryListing = synchronized(lock) {
        requireRunner()
        reconcile(jobId)
        GitRepositoryListing(repositories(jobId), operations(jobId).sortedWith(
            compareByDescending<GitOperationRecord> { it.createdAt }.thenByDescending { it.operationId }).take(MAX_LISTED_OPERATIONS))
    }

    fun operation(jobId: String, repositoryId: String, operationId: String): GitOperationRecord = synchronized(lock) {
        requireRunner()
        reconcile(jobId)
        operations(jobId).singleOrNull { it.operationId == operationId && it.repositoryId == repositoryId }
            ?: throw ManagedGitException("NOT_FOUND", "The repository operation is unavailable.")
    }

    fun workspace(jobId: String, repositoryId: String): GitWorkspaceView {
        val runner = requireRunner()
        val record = synchronized(lock) {
            reconcile(jobId)
            repositories(jobId).singleOrNull { it.repositoryId == repositoryId }
                ?: throw ManagedGitException("NOT_FOUND", "The managed repository is unavailable.")
        }
        val directory = jobGitDirectory(jobId).resolve("repositories").resolve(record.repositoryId)
        val observation = try {
            GitRepositoryInspector.inspect(runner, directory.resolve(GIT_DIR), directory.resolve(WORK_TREE))
        } catch (failure: GitRepositoryException) {
            throw ManagedGitException(failure.code, failure.message ?: "The repository could not be read.")
        }
        if (observation.objectFormat != record.objectFormat) {
            throw ManagedGitException("REPOSITORY_CORRUPT", "The repository object format changed after registration.")
        }
        return GitWorkspaceView(record, observation)
    }

    /** Startup sweep. Each job is also reconciled before its first use by this instance. */
    fun recover(jobIds: Collection<String>) = synchronized(lock) {
        if (availability !is GitAvailability.Available) return@synchronized
        jobIds.filter { it.matches(JOB_ID) && Files.isDirectory(root.resolve(it).resolve("git"), NOFOLLOW_LINKS) }.forEach { jobId ->
            // An unreadable record must not block startup; that job retries and reports it on first use.
            try { reconcile(jobId) } catch (_: Exception) { }
        }
    }

    /** Test and shutdown helper: wait until queued work has finished. */
    fun awaitIdle(timeoutMillis: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            if (synchronized(lock) { active.isEmpty() }) return true
            Thread.sleep(10)
        }
        return false
    }

    /**
     * Stop admitting work, interrupt the Git worker and wait for it to stop. Long copy and cleanup
     * loops check interruption, and Git processes are killed on interrupt. [terminated] reports
     * whether the worker has stopped; storage ownership must not be released before it is true.
     */
    override fun close() {
        synchronized(lock) { closed = true }
        executor.shutdownNow()
        try { executor.awaitTermination(shutdownTimeout.toMillis(), TimeUnit.MILLISECONDS) } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    /** True once no Git worker can still touch repository storage. */
    val terminated: Boolean get() = executor.isTerminated

    // ---- Execution ------------------------------------------------------------------------

    private fun execute(queued: GitOperationRecord) {
        val directory = root.resolve(queued.jobId).resolve("git")
        val staging = directory.resolve("staging").resolve(queued.operationId)
        var current = queued
        var published = false
        try {
            current = synchronized(lock) { advance(directory, current, GitOperationState.RUNNING, RUNNING_MESSAGE) }
            crash(GitOperationCrashPoint.AFTER_RUNNING)
            GitStorage.deleteTree(staging)
            GitStorage.directories(directory, "staging", queued.operationId)
            val record = when (val request = queued.request) {
                is GitRepositoryRequest.Init -> initialize(queued, request, staging)
                is GitRepositoryRequest.Attach -> import(queued, request, staging)
            }
            crash(GitOperationCrashPoint.AFTER_STAGING)
            GitStorage.replaceAtomically(staging.resolve(RECORD), encode(record).toByteArray())
            GitStorage.forceDirectory(staging)
            crash(GitOperationCrashPoint.BEFORE_PUBLISH)
            synchronized(lock) {
                val repositories = GitStorage.directories(directory, "repositories")
                val target = repositories.resolve(queued.repositoryId)
                if (Files.exists(target, NOFOLLOW_LINKS) || repositories(queued.jobId).isNotEmpty()) {
                    throw GitOperationFailure("PUBLICATION_CONFLICT", "A repository already occupies this job's publication location; nothing was overwritten.")
                }
                // rename(2) of a directory onto a missing name; an existing target was refused above.
                Files.move(staging, target, ATOMIC_MOVE)
                published = true
                GitStorage.forceDirectory(repositories)
                crash(GitOperationCrashPoint.AFTER_PUBLISH)
                current = finish(current, GitOperationState.COMPLETED, null, completedMessage(queued.action), record.initialHeadObjectId)
                persist(directory, current)
            }
        } catch (_: SimulatedGitCrash) {
            // Leave the records exactly as a process death would; a new instance reconciles them.
            synchronized(lock) { active -= queued.operationId }
            return
        } catch (failure: Throwable) {
            val (code, message) = when (failure) {
                is GitOperationFailure -> failure.code to (failure.message ?: "")
                is GitRepositoryException -> failure.code to (failure.message ?: "")
                is ManagedGitException -> failure.code to (failure.message ?: "")
                is GitCommandException -> if (failure.kind == GitCommandException.Kind.INTERRUPTED) "INTERRUPTED" to INTERRUPTED_MESSAGE
                    else "REPOSITORY_UNAVAILABLE" to "Git did not complete within its bounds. Nothing was published."
                is InterruptedException, is java.io.InterruptedIOException -> "INTERRUPTED" to INTERRUPTED_MESSAGE
                else -> "STORAGE_FAILED" to "Repository storage could not be prepared. Nothing was published."
            }
            synchronized(lock) {
                if (published) {
                    // The repository is visible; only the record update failed. Restart reconciliation
                    // completes it from the registration, so never report a published repository as failed.
                    try { persist(directory, finish(current, GitOperationState.COMPLETED, null, completedMessage(queued.action))) }
                    catch (_: Exception) { /* reconciled after restart */ }
                    return
                }
                val cleaned = try { GitStorage.deleteTree(staging); true } catch (_: Exception) { false }
                current = when {
                    !cleaned -> finish(current, GitOperationState.RECOVERY_REQUIRED, "STAGING_RETAINED", STAGING_RETAINED_MESSAGE)
                    code == "INTERRUPTED" -> finish(current, GitOperationState.INTERRUPTED, code, message)
                    else -> finish(current, GitOperationState.FAILED, code, message.take(500))
                }
                try { persist(directory, current) } catch (_: Exception) { /* reconciled after restart */ }
            }
        } finally {
            synchronized(lock) { active -= queued.operationId }
        }
    }

    /** No commit, no staged index entry: every copied file is untracked until an explicit commit. */
    private fun initialize(operation: GitOperationRecord, request: GitRepositoryRequest.Init, staging: Path): GitRepositoryRecord {
        val runner = requireRunner()
        val snapshot = sources.resolve(operation.jobId, request.runId, request.revisionId)
        val workTree = GitStorage.directories(staging, WORK_TREE)
        val digests = GitSourceCopy.copy(snapshot.directory, workTree)
        // The retained tree may have changed after the attempt ended: every recorded build input must
        // be present with its committed digest and size, or the copy is not this revision.
        for ((path, commitment) in snapshot.commitments) {
            val copied = workTree.resolve(path)
            if (digests[path] != commitment.sha256 || !Files.isRegularFile(copied, NOFOLLOW_LINKS) || Files.size(copied) != commitment.sizeBytes) {
                throw GitOperationFailure("SOURCE_REVISION_UNAVAILABLE",
                    "The retained source snapshot no longer matches its recorded candidate commitments. Nothing was published.")
            }
        }
        val gitDir = staging.resolve(GIT_DIR)
        val branch = request.initialBranch ?: policy.defaultBranch
        runner.run(GitInvocation("init", listOf("--quiet", "--bare", "--initial-branch=$branch",
            "--object-format=${policy.objectFormat.wireName}", gitDir.toString())))
        configureManaged(runner, gitDir)
        val observation = GitRepositoryInspector.inspect(runner, gitDir, workTree)
        check(observation.head.state == GitHeadState.UNBORN && observation.refs.isEmpty())
        // The work tree must still hold exactly the copied bytes after Git has looked at it.
        if (digests.any { (path, digest) -> GitSourceCopy.digestOf(workTree.resolve(path)) != digest }) {
            throw GitOperationFailure("SOURCE_REVISION_UNAVAILABLE", "The work tree changed while the repository was initialized.")
        }
        return GitRepositoryRecord(operation.repositoryId, operation.worktreeId, operation.jobId, operation.operationId, "initialized",
            observation.objectFormat, clock.instant(), snapshot.runId, snapshot.revisionId, snapshot.sourceSha256,
            GitSourceCopy.manifestDigest(digests), null)
    }

    /** Fresh managed repository receiving only objects and branch/tag refs, then a server-side checkout. */
    private fun import(operation: GitOperationRecord, request: GitRepositoryRequest.Attach, staging: Path): GitRepositoryRecord {
        val runner = requireRunner()
        val source = importRoot?.let { GitRepositoryImport.locate(it, request.sourceName) }
            ?: throw GitOperationFailure("IMPORT_SOURCE_UNAVAILABLE", "No admitted repository has that name.")
        val layout = GitRepositoryImport.layout(runner, source)
        val gitDir = staging.resolve(GIT_DIR)
        runner.run(GitInvocation("init", listOf("--quiet", "--bare", "--initial-branch=${policy.defaultBranch}",
            "--object-format=${layout.objectFormat.wireName}", gitDir.toString())))
        GitRepositoryImport.copyHistory(layout, gitDir)
        configureManaged(runner, gitDir)
        GitRepositoryImport.verify(runner, gitDir)
        val workTree = GitStorage.directories(staging, WORK_TREE)
        val format = GitRepositoryInspector.objectFormat(runner, gitDir)
        val head = try { GitRepositoryInspector.head(runner, gitDir, format) } catch (failure: GitRepositoryException) {
            throw GitOperationFailure(failure.code, failure.message ?: "")
        }
        head.objectId?.let { objectId ->
            // Object-store limits do not bound expansion (one compressed blob may be referenced by many
            // paths), so the tree's declared sizes are checked before anything is written.
            GitRepositoryImport.requireCheckoutBounds(runner, gitDir, objectId, importLimits)
            runner.run(GitInvocation("read-tree", listOf("--reset", "-u", objectId), gitDir = gitDir, workTree = workTree,
                limits = GitExecutionLimits(java.time.Duration.ofMinutes(2), 1024 * 1024, 64 * 1024)))
        }
        val observation = GitRepositoryInspector.inspect(runner, gitDir, workTree)
        return GitRepositoryRecord(operation.repositoryId, operation.worktreeId, operation.jobId, operation.operationId, "imported",
            observation.objectFormat, clock.instant(), null, null, null, null, observation.head.objectId)
    }

    private fun configureManaged(runner: GitCommandRunner, gitDir: Path) {
        val config = gitDir.resolve("config").toString()
        for ((key, value) in listOf("user.name" to policy.identityName, "user.email" to policy.identityEmail, "user.useConfigOnly" to "true")) {
            runner.run(GitInvocation("config", listOf("--file", config, key, value)))
        }
        // Source-only exclusions plus the attribute file that keeps checkout byte-exact.
        GitManagedLayout.prepare(gitDir)
        GitConfigurationAudit.requireManaged(runner, gitDir)
    }

    // ---- Recovery -------------------------------------------------------------------------

    /**
     * Reconcile records left by an earlier process before this instance first uses a job. A
     * published repository whose operation record still says queued/running completed before the
     * restart. Anything else stopped before publication: its private staging tree is removed and
     * the operation becomes `interrupted`, never retried. A staging tree that cannot be removed
     * makes the operation `recovery-required` and is left untouched for inspection.
     */
    private fun reconcile(jobId: String) {
        if (jobId in reconciled) return
        val directory = root.resolve(jobId).resolve("git")
        if (Files.isDirectory(directory, NOFOLLOW_LINKS)) {
            val published = repositories(jobId).associateBy { it.operationId }
            for (operation in operations(jobId)) {
                if (operation.state.terminal || operation.operationId in active) continue
                val staging = directory.resolve("staging").resolve(operation.operationId)
                val recovered = published[operation.operationId]?.let { repository ->
                    finish(operation, GitOperationState.COMPLETED, null,
                        "Publication finished before the server restarted; the repository is available.", repository.initialHeadObjectId)
                } ?: try {
                    GitStorage.deleteTree(staging)
                    finish(operation, GitOperationState.INTERRUPTED, "INTERRUPTED", RESTART_MESSAGE)
                } catch (_: Exception) {
                    finish(operation, GitOperationState.RECOVERY_REQUIRED, "STAGING_RETAINED", STAGING_RETAINED_MESSAGE)
                }
                persist(directory, recovered)
            }
            // Staging trees without a live operation belong to no visible state; remove them.
            val stagingRoot = directory.resolve("staging")
            if (Files.isDirectory(stagingRoot, NOFOLLOW_LINKS)) {
                val live = operations(jobId).filter { it.state == GitOperationState.RECOVERY_REQUIRED || it.operationId in active }
                    .map { it.operationId }.toSet()
                Files.newDirectoryStream(stagingRoot).use { entries ->
                    entries.take(MAX_OPERATIONS * 2).filter { it.fileName.toString() !in live }.forEach { stale ->
                        try { GitStorage.deleteTree(stale) } catch (_: Exception) { /* retained for inspection */ }
                    }
                }
            }
        }
        reconciled += jobId
    }

    // ---- Records --------------------------------------------------------------------------

    private fun requireRunner(): GitCommandRunner = when (val current = availability) {
        is GitAvailability.Unavailable -> throw ManagedGitException("CAPABILITY_UNAVAILABLE", current.message)
        is GitAvailability.Available -> synchronized(lock) {
            runner ?: try { current.runner(GitEnvironment.prepare(root.resolve(".git-runtime"))) } catch (_: Exception) {
                throw ManagedGitException("CAPABILITY_UNAVAILABLE", "The server-owned Git runtime directory is unavailable.")
            }.also { runner = it }
        }
    }

    private fun jobGitDirectory(jobId: String): Path {
        if (!jobId.matches(JOB_ID) || !Files.isDirectory(root.resolve(jobId), NOFOLLOW_LINKS)) {
            throw ManagedGitException("NOT_FOUND", "The requested job is unavailable.")
        }
        return try { GitStorage.directories(root.resolve(jobId), "git") } catch (_: IOException) {
            throw ManagedGitException("STORAGE_FAILED", "Repository storage is unavailable.")
        }
    }

    private fun identity(kind: String): String = "${kind}_" + ByteArray(16).also(random::nextBytes).hex()

    private fun advance(directory: Path, operation: GitOperationRecord, state: GitOperationState, message: String) =
        operation.copy(state = state, revision = operation.revision + 1, message = message).also { persist(directory, it) }

    private fun finish(operation: GitOperationRecord, state: GitOperationState, code: String?, message: String,
        resultObjectId: String? = null) = operation.copy(state = state, revision = operation.revision + 1,
        endedAt = clock.instant(), failureCode = code, message = message, resultObjectId = resultObjectId)

    private fun persist(directory: Path, operation: GitOperationRecord) {
        val operations = GitStorage.directories(directory, "operations")
        GitStorage.replaceAtomically(operations.resolve("${operation.operationId}.json"), encode(operation).toByteArray())
    }

    private fun operations(jobId: String): List<GitOperationRecord> {
        val directory = root.resolve(jobId).resolve("git").resolve("operations")
        if (!Files.isDirectory(directory, NOFOLLOW_LINKS)) return emptyList()
        return Files.newDirectoryStream(directory).use { entries ->
            entries.filter { it.fileName.toString().matches(Regex("operation_[0-9a-f]{32}\\.json")) }.take(MAX_OPERATIONS + 1).map { file ->
                decodeOperation(jobId, file.fileName.toString().removeSuffix(".json"), file)
            }
        }
    }

    private fun repositories(jobId: String): List<GitRepositoryRecord> {
        val directory = root.resolve(jobId).resolve("git").resolve("repositories")
        if (!Files.isDirectory(directory, NOFOLLOW_LINKS)) return emptyList()
        return Files.newDirectoryStream(directory).use { entries ->
            // A directory is a repository only with its registration: publication renames a complete
            // staging tree that already contains it, so anything else was never published by us.
            entries.filter { it.fileName.toString().matches(Regex("repository_[0-9a-f]{32}")) &&
                Files.exists(it.resolve(RECORD), NOFOLLOW_LINKS) }.take(2).map { published ->
                decodeRepository(jobId, published.fileName.toString(), published.resolve(RECORD))
            }
        }
    }

    private fun encode(operation: GitOperationRecord): String = buildJsonObject {
        put("schemaVersion", 1)
        put("operationId", operation.operationId); put("jobId", operation.jobId)
        put("repositoryId", operation.repositoryId); put("worktreeId", operation.worktreeId)
        put("action", operation.action.wireName); put("state", operation.state.wireName); put("revision", operation.revision)
        put("createdAt", operation.createdAt.toString()); put("endedAt", operation.endedAt?.toString()?.let(::JsonPrimitive) ?: JsonNull)
        put("resultObjectId", operation.resultObjectId?.let(::JsonPrimitive) ?: JsonNull)
        put("failureCode", operation.failureCode?.let(::JsonPrimitive) ?: JsonNull)
        put("message", operation.message); put("requestKeySha256", operation.requestKeySha256)
        put("request", when (val request = operation.request) {
            is GitRepositoryRequest.Init -> buildJsonObject {
                put("runId", request.runId); put("revisionId", request.revisionId)
                put("initialBranch", request.initialBranch?.let(::JsonPrimitive) ?: JsonNull)
            }
            is GitRepositoryRequest.Attach -> buildJsonObject { put("sourceName", request.sourceName) }
        })
    }.toString()

    private fun encode(repository: GitRepositoryRecord): String = buildJsonObject {
        put("schemaVersion", 1)
        put("repositoryId", repository.repositoryId); put("worktreeId", repository.worktreeId); put("jobId", repository.jobId)
        put("operationId", repository.operationId); put("origin", repository.origin)
        put("objectFormat", repository.objectFormat.wireName); put("trackingPolicy", repository.trackingPolicy)
        put("createdAt", repository.createdAt.toString())
        fun nullable(name: String, value: String?) = put(name, value?.let(::JsonPrimitive) ?: JsonNull)
        nullable("runId", repository.runId); nullable("candidateRevisionId", repository.candidateRevisionId)
        nullable("sourceSha256", repository.sourceSha256); nullable("sourceManifestSha256", repository.sourceManifestSha256)
        nullable("initialHeadObjectId", repository.initialHeadObjectId)
    }.toString()

    private fun decodeOperation(jobId: String, operationId: String, file: Path): GitOperationRecord = try {
        val bytes = GitStorage.read(file, MAX_RECORD_BYTES)
        val value = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
        require(value.int("schemaVersion") == 1 && value.text("operationId") == operationId && value.text("jobId") == jobId)
        val action = GitOperationAction.entries.single { it.wireName == value.text("action") }
        val request = value.getValue("request").jsonObject.let { request ->
            when (action) {
                GitOperationAction.INIT -> GitRepositoryRequest.Init(request.text("runId"), request.text("revisionId"), request.nullableText("initialBranch"))
                GitOperationAction.ATTACH -> GitRepositoryRequest.Attach(request.text("sourceName"))
            }
        }
        GitOperationRecord(operationId, jobId, value.text("repositoryId").also { require(it.matches(ID)) },
            value.text("worktreeId").also { require(it.matches(ID)) }, action,
            GitOperationState.entries.single { it.wireName == value.text("state") }, value.int("revision").also { require(it in 1..1_000_000) },
            Instant.parse(value.text("createdAt")), value.nullableText("endedAt")?.let(Instant::parse),
            value.nullableText("resultObjectId")?.also { require(it.matches(Regex("[0-9a-f]{40}|[0-9a-f]{64}"))) },
            value.nullableText("failureCode"), value.text("message").also { require(it.length <= 500) },
            value.text("requestKeySha256").also { require(it.matches(Regex("[0-9a-f]{64}"))) }, request)
    } catch (_: Exception) {
        throw ManagedGitException("STORAGE_FAILED", "A repository operation record is unreadable. Preserve storage and inspect it.")
    }

    private fun decodeRepository(jobId: String, repositoryId: String, file: Path): GitRepositoryRecord = try {
        val bytes = GitStorage.read(file, MAX_RECORD_BYTES)
        val value = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
        require(value.int("schemaVersion") == 1 && value.text("repositoryId") == repositoryId && value.text("jobId") == jobId &&
            value.text("trackingPolicy") == GitTrackingPolicy.VERSION)
        GitRepositoryRecord(repositoryId, value.text("worktreeId").also { require(it.matches(ID)) }, jobId,
            value.text("operationId").also { require(it.matches(ID)) }, value.text("origin").also { require(it in setOf("initialized", "imported")) },
            GitObjectFormat.fromGit(value.text("objectFormat")).also { require(it != GitObjectFormat.UNKNOWN) },
            Instant.parse(value.text("createdAt")), value.nullableText("runId"), value.nullableText("candidateRevisionId"),
            value.nullableText("sourceSha256"), value.nullableText("sourceManifestSha256"), value.nullableText("initialHeadObjectId"))
    } catch (_: Exception) {
        throw ManagedGitException("STORAGE_FAILED", "A repository registration is unreadable. Preserve storage and inspect it.")
    }

    private fun JsonObject.text(name: String): String = (getValue(name) as JsonPrimitive).also { require(it.isString) }.content
    private fun JsonObject.nullableText(name: String): String? = getValue(name).let { if (it == JsonNull) null else (it as JsonPrimitive).also { p -> require(p.isString) }.content }
    private fun JsonObject.int(name: String): Int = (getValue(name) as JsonPrimitive).also { require(!it.isString) }.intOrNull ?: error("integer")

    private fun completedMessage(action: GitOperationAction) = when (action) {
        GitOperationAction.INIT -> "Initialized without a commit. Every copied source file is untracked until an explicit commit."
        GitOperationAction.ATTACH -> "Imported branches, tags and objects into an isolated managed copy. Imported configuration, hooks and submodules were not copied."
    }

    internal companion object {
        const val GIT_DIR = "repository.git"
        const val WORK_TREE = "worktree"
        const val RECORD = "repository.json"
        const val MAX_OPERATIONS = 64
        const val MAX_LISTED_OPERATIONS = 20
        const val MAX_QUEUED = 8
        const val MAX_RECORD_BYTES = 16 * 1024
        /** Local branch/tag tips inspected for unpushed work; excess tips retain conservatively. */
        const val MAX_RETENTION_BRANCHES = 256
        val JOB_ID = Regex("[a-f0-9]{32}")
        val ID = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
        const val QUEUED_MESSAGE = "Queued. The repository becomes visible only after it is completely prepared."
        const val RUNNING_MESSAGE = "Preparing the repository in private staging."
        const val INTERRUPTED_MESSAGE = "Stopped before publication. No repository was published; start a new request explicitly."
        const val RESTART_MESSAGE = "Interrupted by a server restart before publication. No repository was published and the source snapshot was not changed. Start a new request explicitly."
        const val STAGING_RETAINED_MESSAGE = "Interrupted staging could not be removed. Preserve storage and inspect it before retrying."
    }
}
