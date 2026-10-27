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

enum class GitOperationAction(val wireName: String, val workspace: Boolean = false) {
    INIT("git.init"), ATTACH("git.attach"),
    STAGE("git.stage", true), UNSTAGE("git.unstage", true), COMMIT("git.commit", true),
    BRANCH_CREATE("git.branch.create", true), SWITCH("git.switch", true), BRANCH_DELETE("git.branch.delete", true),
    TAG("git.tag", true), WORKTREE_ADD("git.worktree.add", true), WORKTREE_REMOVE("git.worktree.remove", true),
    CLONE("git.clone"), REMOTE_ADD("git.remote.add", true), REMOTE_REMOVE("git.remote.remove", true), FETCH("git.fetch", true),
    MERGE("git.merge", true), MERGE_ABORT("git.merge.abort", true), CONFLICT_SAVE("git.conflict.save", true),
    CONFLICT_COMPLETE("git.conflict.complete", true),
}

enum class GitOperationState(val wireName: String, val terminal: Boolean) {
    QUEUED("queued", false), RUNNING("running", false), COMPLETED("completed", true), FAILED("failed", true),
    INTERRUPTED("interrupted", true), RECOVERY_REQUIRED("recovery-required", true),
    CANCELLING("cancelling", false), CANCELLED("cancelled", true),
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
    /** Latest transfer progress of a running operation; process-local and never persisted. */
    val progress: GitProgress? = null,
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
data class GitWorkspaceView(
    val record: GitRepositoryRecord,
    val observation: GitWorkspaceObservation,
    val mapping: GitMappingView? = null,
    val worktreeId: String = record.worktreeId,
    val ownerRunId: String? = null,
) {
    val primary: Boolean get() = worktreeId == record.worktreeId
}

/** One diff read: the comparison, its changed files and an optional selected patch. */
data class GitDiffView(
    val record: GitRepositoryRecord,
    val scope: GitDiffScope,
    val commit: String?,
    val parent: String?,
    val listing: GitDiffListing,
    val patch: Pair<GitDiffFile, GitPatch>?,
    val worktreeId: String = record.worktreeId,
)

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
    /** No signing capability exists yet; a policy that requires signatures refuses every commit. */
    val requireSignedCommits: Boolean = false,
) {
    init {
        require(GitRefNames.isPlausibleBranchName(defaultBranch) && objectFormat != GitObjectFormat.UNKNOWN)
        require(identityName.isNotBlank() && identityName.length <= 128 && identityName.none { it.isISOControl() || it in "<>" })
        require(identityEmail.matches(Regex("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}")))
    }
}

class ManagedGitException(val code: String, message: String) : RuntimeException(message)

/** Crash points for recovery tests; a crash leaves records and staging exactly as a process death would. */
enum class GitOperationCrashPoint { AFTER_RUNNING, AFTER_STAGING, BEFORE_PUBLISH, AFTER_PUBLISH, BEFORE_TERMINAL_PERSIST, AFTER_TERMINAL_PERSIST }
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
    private val acceptance: GitAcceptanceResolver = GitAcceptanceResolver { _, _, _ -> "not-evaluated" to null },
    private val activity: GitJobActivity = GitJobActivity { emptyMap() },
    /** Remote transports, destinations and credentials (#585, #586); closed unless configured. */
    val remotePolicy: GitRemotePolicy = GitRemotePolicy(),
) : AutoCloseable {
    private val root = storeRoot.toAbsolutePath().normalize()
    private val importRoot: Path? = importRoot?.let { configured ->
        try { configured.toRealPath().takeIf { Files.isDirectory(it) } } catch (_: IOException) { null }
    }
    private val lock = Any()
    private val reconciled = HashSet<String>()
    private val active = HashSet<String>()
    /** Cancellation requests and latest progress of running transfers, by operation (#594). */
    private val cancellations = HashMap<String, java.util.concurrent.atomic.AtomicBoolean>()
    private val progress = java.util.concurrent.ConcurrentHashMap<String, GitProgress>()
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
                is GitStageRequest, is GitCommitRequest, is GitRetainedCommit, is GitRefRequest, is GitSyncRequest ->
                    throw IllegalArgumentException("workspace requests use requestWorkspace")
                is GitCloneRequest -> {
                    refusing { GitRemoteUrls.parse(request.url, remotePolicy) }
                    if (!GitRemoteStore.validName(request.remoteName)) {
                        throw ManagedGitException("VALIDATION_FAILED", "A remote name is 1 to 64 letters, digits, '.', '_' or '-' that form valid Git ref names.")
                    }
                    request.branch?.let { branch ->
                        try { GitRefNames.requireBranchName(runner, branch) } catch (_: IllegalArgumentException) {
                            throw ManagedGitException("VALIDATION_FAILED", "The branch name is not a valid Git branch name.")
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
            if (operation.action in GitSyncRequest.CANCELLABLE) cancellations[operation.operationId] = java.util.concurrent.atomic.AtomicBoolean()
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
        operations(jobId).singleOrNull { it.operationId == operationId && it.repositoryId == repositoryId }?.let(::live)
            ?: throw ManagedGitException("NOT_FOUND", "The repository operation is unavailable.")
    }

    /** A running record with its process-local progress and any pending cancellation. */
    private fun live(operation: GitOperationRecord): GitOperationRecord {
        if (operation.state.terminal) return operation
        val cancelling = cancellations[operation.operationId]?.get() == true
        return operation.copy(state = if (cancelling) GitOperationState.CANCELLING else operation.state, progress = progress[operation.operationId])
    }

    /**
     * Request cancellation of a queued or running transfer (#594). The process is stopped at its
     * next check, the operation ends `cancelled`, and partial objects are removed; local branches,
     * the work tree and accepted snapshots are never touched. A finished operation is returned as is.
     */
    fun cancel(jobId: String, repositoryId: String, operationId: String): GitOperationRecord = synchronized(lock) {
        requireRunner()
        reconcile(jobId)
        val operation = operations(jobId).singleOrNull { it.operationId == operationId && it.repositoryId == repositoryId }
            ?: throw ManagedGitException("NOT_FOUND", "The repository operation is unavailable.")
        if (operation.state.terminal) return@synchronized operation
        val flag = cancellations[operationId] ?: throw ManagedGitException("NOT_CANCELLABLE",
            "Only fetch and clone transfers can be cancelled; this operation finishes on its own.")
        flag.set(true)
        live(operation)
    }

    private fun transferControl(operationId: String, directory: Path, maxBytes: Long = remotePolicy.limits.maxRepositoryBytes): GitProcessControl {
        val flag = synchronized(lock) { cancellations[operationId] } ?: java.util.concurrent.atomic.AtomicBoolean()
        val watch = GitDiskWatch(directory, maxBytes) { flag.get() }
        return GitProcessControl(stop = watch::stop, progress = { line -> GitProgress.parse(line)?.let { progress[operationId] = it } })
    }

    private fun cancelledBeforeStart(operationId: String) = synchronized(lock) { cancellations[operationId]?.get() == true }

    /** Fresh bounded observation of one work tree (the primary one by default). */
    fun workspace(jobId: String, repositoryId: String, worktreeId: String? = null): GitWorkspaceView {
        val runner = requireRunner()
        val located = locate(jobId, repositoryId, worktreeId)
        val record = located.record
        val observation = try {
            GitRepositoryInspector.inspect(runner, located.gitDir, located.workTree, located.commonDir)
        } catch (failure: GitRepositoryException) {
            throw ManagedGitException(failure.code, failure.message ?: "The repository could not be read.")
        }
        if (observation.objectFormat != record.objectFormat) {
            throw ManagedGitException("REPOSITORY_CORRUPT", "The repository object format changed after registration.")
        }
        // A repository .gitignore can re-include a policy exclusion; report those files as ignored too.
        val excluded = try { GitTrackingPolicy.excluded(runner, observation.status.entries.filter { it.untracked }.mapNotNull { it.path.exact }) }
            catch (_: GitCommandException) { emptySet() }
        val shown = if (excluded.isEmpty()) observation else observation.copy(status = observation.status.copy(
            entries = observation.status.entries.map { if (it.untracked && it.path.exact in excluded) it.copy(untracked = false, ignored = true) else it }))
        return GitWorkspaceView(record, shown, observation.head.objectId?.let { mappingView(jobId, record, it) },
            located.worktreeId, located.ownerRunId)
    }

    /** The primary work tree and every registered linked work tree. */
    fun worktrees(jobId: String, repositoryId: String): List<GitWorkspaceView> {
        val record = repository(jobId, repositoryId)
        return listOf(workspace(jobId, repositoryId)) + linkedWorktrees(jobId, record).map { workspace(jobId, repositoryId, it.worktreeId) }
    }

    /** True while a queued or running operation holds this job's repository. */
    fun busy(jobId: String): Boolean = synchronized(lock) {
        reconcile(jobId)
        operations(jobId).any { !it.state.terminal }
    }

    /**
     * Resolved storage of one registered work tree. Linked work trees share the primary repository
     * as their common directory and have a private administrative directory beneath it.
     */
    private data class Located(val record: GitRepositoryRecord, val gitDir: Path, val workTree: Path, val commonDir: Path,
        val worktreeId: String, val ownerRunId: String?) {
        val primary: Boolean get() = gitDir == commonDir
    }

    private fun repositoryDirectory(jobId: String, repositoryId: String): Path =
        root.resolve(jobId).resolve("git/repositories").resolve(repositoryId)

    private fun linkedWorktrees(jobId: String, record: GitRepositoryRecord): List<GitWorktreeRecord> {
        val directory = repositoryDirectory(jobId, record.repositoryId).resolve(WORKTREE_RECORDS)
        if (!Files.isDirectory(directory, NOFOLLOW_LINKS)) return emptyList()
        return Files.newDirectoryStream(directory).use { entries ->
            entries.filter { it.fileName.toString().matches(Regex("worktree_[0-9a-f]{32}\\.json")) }.take(GitRefOperations.MAX_LINKED_WORKTREES + 1).mapNotNull { file ->
                GitRefOperations.decodeWorktree(record.repositoryId, file.fileName.toString().removeSuffix(".json"),
                    try { GitStorage.read(file, MAX_RECORD_BYTES) } catch (_: IOException) { return@mapNotNull null })
            }.sortedBy { it.createdAt }
        }
    }

    private fun locate(jobId: String, repositoryId: String, worktreeId: String? = null): Located {
        val record = synchronized(lock) {
            reconcile(jobId)
            repositories(jobId).singleOrNull { it.repositoryId == repositoryId }
                ?: throw ManagedGitException("NOT_FOUND", "The managed repository is unavailable.")
        }
        val directory = jobGitDirectory(jobId).resolve("repositories").resolve(record.repositoryId)
        val commonDir = directory.resolve(GIT_DIR)
        if (worktreeId == null || worktreeId == record.worktreeId) {
            return Located(record, commonDir, directory.resolve(WORK_TREE), commonDir, record.worktreeId, null)
        }
        val linked = linkedWorktrees(jobId, record).singleOrNull { it.worktreeId == worktreeId }
            ?: throw ManagedGitException("NOT_FOUND", "The work tree is not registered.")
        return Located(record, commonDir.resolve("worktrees").resolve(worktreeId), directory.resolve(LINKED_WORK_TREES).resolve(worktreeId),
            commonDir, worktreeId, linked.ownerRunId)
    }

    fun repository(jobId: String, repositoryId: String): GitRepositoryRecord {
        requireRunner()
        return locate(jobId, repositoryId).record
    }

    private fun <T> reading(block: () -> T): T = try { block() } catch (failure: GitRepositoryException) {
        throw ManagedGitException(failure.code, failure.message ?: "The repository could not be read.")
    } catch (failure: GitCommandException) {
        throw ManagedGitException(if (failure.kind == GitCommandException.Kind.FAILED) "REPOSITORY_CORRUPT" else "REPOSITORY_UNAVAILABLE",
            "The repository could not be read within its bounds.")
    }

    private fun audit(runner: GitCommandRunner, located: Located) =
        if (located.primary) GitConfigurationAudit.requireManaged(runner, located.gitDir)
        else GitConfigurationAudit.requireManagedWorktree(runner, located.commonDir, located.gitDir)

    /** History from a fixed start object; null starts at the work tree's HEAD (an unborn HEAD has none). */
    fun history(jobId: String, repositoryId: String, start: String?, skip: Int, limit: Int, worktreeId: String? = null): Pair<String?, GitHistoryPage> {
        val runner = requireRunner()
        val located = locate(jobId, repositoryId, worktreeId)
        return reading {
            audit(runner, located)
            val format = located.record.objectFormat
            val origin = start ?: GitRepositoryInspector.head(runner, located.gitDir, format).objectId
                ?: return@reading null to GitHistoryPage(emptyList(), false)
            if (!commitExists(runner, located.commonDir, origin)) throw ManagedGitException("NOT_FOUND", "The commit is not in this repository.")
            origin to GitReads.history(runner, located.commonDir, format, origin, skip, limit)
        }
    }

    /** Changed files for one comparison and, when [fileId] selects one, its bounded patch. */
    fun diff(jobId: String, repositoryId: String, scope: GitDiffScope, commit: String?, fileId: String?, worktreeId: String? = null): GitDiffView {
        val runner = requireRunner()
        val located = locate(jobId, repositoryId, worktreeId)
        return reading {
            audit(runner, located)
            val format = located.record.objectFormat
            val parent = commit?.let {
                if (!commitExists(runner, located.commonDir, it)) throw ManagedGitException("NOT_FOUND", "The commit is not in this repository.")
                GitReads.history(runner, located.commonDir, format, it, 0, 1).entries.single().parentObjectIds.firstOrNull()
            }
            val listing = GitReads.diff(runner, located.gitDir, located.workTree, format, scope, commit, parent)
            val selected = fileId?.let { id ->
                listing.files.firstOrNull { it.path.fileId(located.worktreeId) == id }
                    ?: throw ManagedGitException("NOT_FOUND", "The file is not part of this comparison.")
            }
            GitDiffView(located.record, scope, commit, parent, listing,
                selected?.let { it to GitReads.patch(runner, located.gitDir, located.workTree, scope, commit, parent, it) }, located.worktreeId)
        }
    }

    fun refs(jobId: String, repositoryId: String, skip: Int, limit: Int): Pair<GitRepositoryRecord, GitRefsPage> {
        val runner = requireRunner()
        val located = locate(jobId, repositoryId)
        return reading {
            GitConfigurationAudit.requireManaged(runner, located.gitDir)
            located.record to GitReads.refsPage(runner, located.gitDir, located.record.objectFormat, skip, limit)
        }
    }

    /** Deterministic export of one exact commit tree; ref names play no part in its identity. */
    fun export(jobId: String, repositoryId: String, objectId: String): GitSourceExport {
        val runner = requireRunner()
        val located = locate(jobId, repositoryId)
        return reading {
            GitConfigurationAudit.requireManaged(runner, located.commonDir)
            val format = located.record.objectFormat
            if (format.objectIdOrNull(objectId) == null || !commitExists(runner, located.commonDir, objectId)) {
                throw ManagedGitException("NOT_FOUND", "The commit is not in this repository.")
            }
            GitSourceExports.build(runner, located.commonDir, format, objectId)
        }
    }

    /**
     * Provenance envelope of one commit (#581): its exact object, the recorded revision mapping (with
     * the work tree's dirty state at commit time), the refs that currently name it for display only,
     * and the deterministic export's digest after independent blob-ID verification.
     */
    fun provenance(jobId: String, repositoryId: String, objectId: String): GitProvenanceView {
        val runner = requireRunner()
        val export = export(jobId, repositoryId, objectId)
        val located = locate(jobId, repositoryId)
        return reading {
            val format = located.record.objectFormat
            val commit = GitReads.history(runner, located.commonDir, format, objectId, 0, 1).entries.single()
            val refs = GitReads.allRefs(runner, located.commonDir, format)
            GitProvenanceView(located.record, commit, refs.filter { (it.peeledObjectId ?: it.objectId) == objectId }.map { it.name },
                mappingView(jobId, located.record, objectId), export, GitSourceExports.verify(export.bytes, format, export.blobs))
        }
    }

    private fun commitExists(runner: GitCommandRunner, gitDir: Path, objectId: String): Boolean =
        runner.run(GitInvocation("cat-file", listOf("-e", "$objectId^{commit}"), gitDir = gitDir, allowedExitCodes = setOf(0, 1, 128))).exitCode == 0

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

    override fun close() {
        synchronized(lock) { closed = true }
        executor.shutdownNow()
        executor.awaitTermination(10, TimeUnit.SECONDS)
    }

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
                is GitCloneRequest -> clone(queued, request, staging)
                is GitStageRequest, is GitCommitRequest, is GitRetainedCommit, is GitRefRequest, is GitSyncRequest ->
                    error("workspace operations run separately")
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
                // Include checkout, index, registration and audit bytes, not just transferred objects.
                if (queued.request is GitCloneRequest) {
                    if (cancelledBeforeStart(queued.operationId)) throw GitOperationFailure("CANCELLED", "The clone was cancelled before publication.")
                    if (GitDiskWatch(staging, remotePolicy.limits.maxRepositoryBytes) { false }.exceeded()) {
                        throw GitOperationFailure("TRANSFER_LIMIT", "The clone exceeded the repository size bound. Nothing was published.")
                    }
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
                is GitCommandException -> when {
                    failure.kind == GitCommandException.Kind.INTERRUPTED -> "INTERRUPTED" to INTERRUPTED_MESSAGE
                    queued.request is GitCloneRequest -> GitTransports.classify(failure, failure.diagnostic,
                        try { GitRemoteUrls.parse(queued.request.url, remotePolicy).transport } catch (_: Exception) { GitTransport.HTTPS })
                    else -> "REPOSITORY_UNAVAILABLE" to "Git did not complete within its bounds. Nothing was published."
                }
                is GitOperationRefusal -> failure.code to (failure.message ?: "")
                is InterruptedException -> "INTERRUPTED" to INTERRUPTED_MESSAGE
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
                    code == "CANCELLED" -> finish(current, GitOperationState.CANCELLED, code, "The clone was cancelled. Its staging was removed and nothing was published.")
                    else -> finish(current, GitOperationState.FAILED, code, message.take(500))
                }
                try { persist(directory, current) } catch (_: Exception) { /* reconciled after restart */ }
            }
        } finally {
            synchronized(lock) { active -= queued.operationId; cancellations -= queued.operationId; progress -= queued.operationId }
        }
    }

    /**
     * Fetch an allowlisted remote into a fresh managed repository in private staging (#592). Only
     * branches (as remote-tracking refs) and tags arrive; hooks, filters, submodules and LFS stay
     * inert, the transfer is bounded in time and bytes, and the repository is published only when
     * complete. A failure or cancellation removes the staging tree.
     */
    private fun clone(operation: GitOperationRecord, request: GitCloneRequest, staging: Path): GitRepositoryRecord {
        val runner = requireRunner()
        if (cancelledBeforeStart(operation.operationId)) throw GitOperationFailure("CANCELLED", "The clone was cancelled before it started.")
        val location = try { GitRemoteUrls.parse(request.url, remotePolicy) } catch (refusal: GitOperationRefusal) {
            throw GitOperationFailure(refusal.code, refusal.message ?: "The remote is not allowed.")
        }
        val gitDir = staging.resolve(GIT_DIR)
        val watch = GitDiskWatch(staging, remotePolicy.limits.maxRepositoryBytes) { false }
        val control = transferControl(operation.operationId, staging)
        val advertisement = GitTransfers.advertisement(runner, location, remotePolicy, control)
        // A detached advertised HEAD is not an empty remote and must not silently become unborn
        // on our configured default branch. This clone path materializes branches only.
        if (request.branch == null && advertisement.branch == null && advertisement.headObjectId != null) {
            throw GitOperationFailure("REPOSITORY_UNSUPPORTED", "The remote HEAD is detached. Select a branch explicitly to clone it.")
        }
        // An advertised branch that exceeds our naming policy is not an absent branch. Refuse
        // it instead of substituting a default that could be unborn or point to different source.
        val branch = request.branch ?: advertisement.branch ?: policy.defaultBranch
        try { GitRefNames.requireBranchName(runner, branch) } catch (_: IllegalArgumentException) {
            throw GitOperationFailure("VALIDATION_FAILED", "The remote's default branch name cannot be used by the workbench. Select a supported branch explicitly to clone it.")
        }
        runner.run(GitInvocation("init", listOf("--quiet", "--bare", "--initial-branch=${policy.defaultBranch}",
            "--object-format=${advertisement.format.wireName}", gitDir.toString())))
        configureManaged(runner, gitDir)
        GitTransfers.fetch(runner, gitDir, location, request.remoteName, remotePolicy, control, tags = true)
        if (watch.exceeded()) throw GitOperationFailure("TRANSFER_LIMIT", "The clone exceeded the repository size bound. Nothing was published.")
        GitConfigurationAudit.requireManaged(runner, gitDir)
        GitRepositoryImport.verify(runner, gitDir)
        val format = GitRepositoryInspector.objectFormat(runner, gitDir)
        val tip = GitRefOperations.refObject(runner, gitDir, format, "refs/remotes/${request.remoteName}/$branch")
        if (tip == null && request.branch != null) throw GitOperationFailure("REMOTE_REF_NOT_FOUND", "The remote has no branch named ${request.branch}.")
        runner.run(GitInvocation("symbolic-ref", listOf("HEAD", "refs/heads/$branch"), gitDir = gitDir))
        val workTree = GitStorage.directories(staging, WORK_TREE)
        tip?.let { objectId ->
            GitRefOperations.createRef(runner, gitDir, "refs/heads/$branch", objectId, "BRANCH_EXISTS")
            GitRepositoryImport.requireCheckoutBounds(runner, gitDir, objectId, importLimits, repositoryBudget = watch.remaining())
            runner.run(GitInvocation("read-tree", listOf("--reset", "-u", objectId), gitDir = gitDir, workTree = workTree,
                limits = GitExecutionLimits(java.time.Duration.ofMinutes(2), 1024 * 1024, 64 * 1024), control = control))
        }
        if (watch.exceeded()) throw GitOperationFailure("TRANSFER_LIMIT", "The clone exceeded the repository size bound. Nothing was published.")
        val observation = GitRepositoryInspector.inspect(runner, gitDir, workTree)
        val remote = GitRemoteRecord(GitRemoteStore.remoteId(operation.repositoryId, request.remoteName, operation.operationId), operation.repositoryId,
            request.remoteName, location, clock.instant(), operation.operationId)
        GitRemoteStore.write(staging, remote)
        writeFetchState(staging, remote.remoteId, operation.operationId)
        GitRemoteStore.audit(staging, GitRemoteStore.auditEntry("clone", operation.operationId, "completed", remote, clock.instant(),
            ref = "refs/heads/$branch", newObjectId = tip))
        return GitRepositoryRecord(operation.repositoryId, operation.worktreeId, operation.jobId, operation.operationId, "cloned",
            observation.objectFormat, clock.instant(), null, null, null, null, observation.head.objectId)
    }

    private fun writeFetchState(directory: Path, remoteId: String, operationId: String) {
        val states = GitStorage.directories(directory, FETCH_STATE)
        GitStorage.replaceAtomically(states.resolve("$remoteId.json"), buildJsonObject {
            put("remoteId", remoteId); put("operationId", operationId); put("fetchedAt", clock.instant().toString())
        }.toString().toByteArray())
    }

    private fun fetchState(directory: Path, remoteId: String): Pair<Instant, String>? = try {
        val file = directory.resolve(FETCH_STATE).resolve("$remoteId.json")
        if (!Files.isRegularFile(file, NOFOLLOW_LINKS)) null else {
            val value = Json.parseToJsonElement(GitStorage.read(file, 4096).toString(Charsets.UTF_8)).jsonObject
            Instant.parse(value.text("fetchedAt")) to value.text("operationId")
        }
    } catch (_: Exception) { null }

    // ---- Remotes (#585-#587) --------------------------------------------------------------

    /** A registered remote with its server-side credential state and remote-tracking refs. */
    data class GitRemoteView(val record: GitRemoteRecord, val credential: String, val allowed: Boolean,
        val tracking: List<GitRefEntry>, val fetchedAt: Instant?, val fetchOperationId: String?)

    fun remotes(jobId: String, repositoryId: String): List<GitRemoteView> {
        val runner = requireRunner()
        val located = locate(jobId, repositoryId)
        val directory = repositoryDirectory(jobId, repositoryId)
        return reading {
            GitRemoteStore.list(directory, repositoryId).map { remote ->
                val allowed = try { GitRemoteUrls.parse(remote.location.display, remotePolicy); true } catch (_: GitOperationRefusal) { false }
                val fetched = fetchState(directory, remote.remoteId)
                GitRemoteView(remote, remotePolicy.credentials.describe(remote.location), allowed,
                    GitTransfers.trackingRefs(runner, located.commonDir, located.record.objectFormat, remote.name), fetched?.first, fetched?.second)
            }
        }
    }

    /** Newest audit entries first: remote changes, transfers and their outcomes (#585, #601). */
    fun auditLog(jobId: String, repositoryId: String, limit: Int): List<JsonObject> {
        requireRunner()
        locate(jobId, repositoryId)
        return GitRemoteStore.auditEntries(repositoryDirectory(jobId, repositoryId), limit)
    }

    private fun remoteFor(located: Located, remoteId: String?): GitRemoteRecord {
        val id = remoteId ?: GitWorkspaceMutations.refuse("VALIDATION_FAILED", "A remote identity is required.")
        return GitRemoteStore.list(repositoryDirectory(located.record.jobId, located.record.repositoryId), located.record.repositoryId)
            .singleOrNull { it.remoteId == id } ?: GitWorkspaceMutations.refuse("NOT_FOUND", "The remote is not registered for this repository.")
    }

    private fun requireRepositoryGuard(located: Located, observation: GitWorkspaceObservation, guards: GitGuards) {
        if (GitWorkspaceVersions.repositoryVersion(located.record, observation) != guards.repositoryVersion) {
            GitWorkspaceMutations.refuse("REF_CHANGED", "The repository changed since this action was reviewed. Read it again first.")
        }
    }

    /** The remote's location under today's policy; a destination the operator removed is refused. */
    private fun allowedLocation(remote: GitRemoteRecord): GitRemoteLocation = GitRemoteUrls.parse(remote.location.display, remotePolicy)

    private fun validateSync(runner: GitCommandRunner, located: Located, observation: GitWorkspaceObservation, request: GitSyncRequest) {
        if (request.action !in GitSyncRequest.REMOTE) return validateIntegration(runner, located, observation, request)
        if (!remotePolicy.configured) GitWorkspaceMutations.refuse("REMOTES_UNAVAILABLE", "Remote operations are not configured on this server.")
        val directory = repositoryDirectory(located.record.jobId, located.record.repositoryId)
        when (request.action) {
            GitOperationAction.REMOTE_ADD -> {
                requireRepositoryGuard(located, observation, request.guards)
                val name = request.text("name")
                if (!GitRemoteStore.validName(name)) {
                    GitWorkspaceMutations.refuse("VALIDATION_FAILED", "A remote name is 1 to 64 letters, digits, '.', '_' or '-'.")
                }
                val existing = GitRemoteStore.list(directory, located.record.repositoryId)
                if (existing.any { it.name == name }) GitWorkspaceMutations.refuse("REMOTE_EXISTS", "A remote with that name already exists; nothing is overwritten.")
                if (existing.size >= GitRemoteStore.MAX_REMOTES) GitWorkspaceMutations.refuse("QUOTA_EXCEEDED", "This repository already has the maximum of ${GitRemoteStore.MAX_REMOTES} remotes.")
                GitRemoteUrls.parse(request.text("url"), remotePolicy)
            }
            GitOperationAction.REMOTE_REMOVE -> {
                requireRepositoryGuard(located, observation, request.guards)
                remoteFor(located, request.parameters["remoteId"])
            }
            GitOperationAction.FETCH -> allowedLocation(remoteFor(located, request.parameters["remoteId"]))
            else -> error("not a sync request")
        }
    }

    // ---- Integration and conflicts (#595-#598) ----------------------------------------------

    /** One remote-tracking ref by its identity, from every ref page. */
    private fun trackingRef(runner: GitCommandRunner, located: Located, refId: String?): GitRefEntry {
        val id = refId ?: GitWorkspaceMutations.refuse("VALIDATION_FAILED", "A remote-tracking ref identity is required.")
        return GitRemoteStore.list(repositoryDirectory(located.record.jobId, located.record.repositoryId), located.record.repositoryId)
            .flatMap { GitTransfers.trackingRefs(runner, located.commonDir, located.record.objectFormat, it.name) }
            .singleOrNull { GitWorkspaceVersions.refId(located.record.repositoryId, it.name) == id }
            ?: GitWorkspaceMutations.refuse("NOT_FOUND", "The remote-tracking ref is not present. Fetch the remote first.")
    }

    data class GitDivergenceView(val worktreeId: String, val localRef: String, val localObjectId: String, val tracking: GitRefEntry,
        val remote: GitRemoteRecord?, val fetchedAt: Instant?, val divergence: GitDivergence, val mergeInProgress: Boolean,
        val signingRequired: Boolean = false)

    /** Divergence of the work tree's branch from one remote-tracking ref, from fetched state only (#595). */
    fun divergence(jobId: String, repositoryId: String, worktreeId: String?, trackingRefId: String): GitDivergenceView {
        val runner = requireRunner()
        val located = locate(jobId, repositoryId, worktreeId)
        return refusing {
            val head = GitRepositoryInspector.head(runner, located.gitDir, located.record.objectFormat)
            if (head.state == GitHeadState.UNBORN) GitWorkspaceMutations.refuse("NO_COMMITS",
                "The branch has no commits yet. Commit first, or clone the remote into a new repository.")
            val local = head.refName?.takeIf { head.state == GitHeadState.ATTACHED } ?: GitWorkspaceMutations.refuse("DETACHED",
                "The work tree is not on a branch. Switch to the branch you want to integrate into first.")
            val tracking = trackingRef(runner, located, trackingRefId)
            val directory = repositoryDirectory(jobId, repositoryId)
            val remote = GitRemoteStore.list(directory, repositoryId).singleOrNull { tracking.name.startsWith(it.trackingPrefix) }
            GitDivergenceView(located.worktreeId, local, checkNotNull(head.objectId), tracking, remote,
                remote?.let { fetchState(directory, it.remoteId)?.first },
                GitIntegrations.divergence(runner, located.commonDir, checkNotNull(head.objectId), tracking.objectId),
                GitIntegrations.mergeInProgress(located.gitDir), policy.requireSignedCommits)
        }
    }

    data class GitConflictView(val worktreeId: String, val integration: GitIntegrationRecord?, val mergeInProgress: Boolean,
        val files: List<GitConflictEntry>, val offset: Int, val totalCount: Int, val nextOffset: Int?)

    data class GitConflictFileView(val worktreeId: String, val entry: GitConflictEntry, val base: String?, val ours: String?,
        val theirs: String?, val current: String?, val currentSha256: String, val currentSize: Long?)

    /** A bounded live page of unresolved paths (#597). Mutations always revalidate file identities
     * and digests; page offsets are navigation, not a claim of a stable index snapshot. */
    fun conflicts(jobId: String, repositoryId: String, worktreeId: String?, offset: Int = 0): GitConflictView {
        require(offset in 0..200_000)
        val runner = requireRunner()
        val located = locate(jobId, repositoryId, worktreeId)
        return refusing {
            val merging = GitIntegrations.mergeInProgress(located.gitDir)
            val files = GitIntegrations.conflicts(runner, located.gitDir, located.workTree)
            GitConflictView(located.worktreeId, if (merging) GitIntegrations.record(repositoryDirectory(jobId, repositoryId), located.worktreeId) else null,
                merging, files.drop(offset).take(200), offset, files.size, (offset + 200).takeIf { it < files.size })
        }
    }

    /** Bounded text of one conflict's stages and current file; binary or large content is reported as unsupported. */
    fun conflictFile(jobId: String, repositoryId: String, worktreeId: String?, fileId: String): GitConflictFileView {
        val runner = requireRunner()
        val located = locate(jobId, repositoryId, worktreeId)
        return refusing {
            val entry = GitIntegrations.conflicts(runner, located.gitDir, located.workTree).singleOrNull { it.path.fileId(located.worktreeId) == fileId }
                ?: GitWorkspaceMutations.refuse("NOT_FOUND", "The file is not an unresolved conflict in this work tree.")
            val path = entry.path.exact ?: GitWorkspaceMutations.refuse("UNSUPPORTED_CONFLICT", "This file name is not valid UTF-8.")
            val current = GitConflictFiles.observe(located.workTree, path)
            fun stage(objectId: String?) = objectId?.let { GitIntegrations.blobText(runner, located.commonDir, it) }
            GitConflictFileView(located.worktreeId, entry, stage(entry.baseObjectId), stage(entry.oursObjectId), stage(entry.theirsObjectId),
                current.text.takeIf { entry.plainFile }, current.sha256, current.size)
        }
    }

    private fun conflictFor(runner: GitCommandRunner, located: Located, fileId: String?): GitConflictEntry {
        val id = fileId ?: GitWorkspaceMutations.refuse("VALIDATION_FAILED", "A conflicted file identity is required.")
        return GitIntegrations.conflicts(runner, located.gitDir, located.workTree).singleOrNull { it.path.fileId(located.worktreeId) == id }
            ?: GitWorkspaceMutations.refuse("SELECTION_CHANGED", "The file is no longer an unresolved conflict. Read the conflicts again.")
    }

    /** Work-tree path of a conflict, refusing names the workbench cannot write safely. */
    private fun conflictPath(runner: GitCommandRunner, located: Located, entry: GitConflictEntry): Path {
        if (!entry.plainFile) GitWorkspaceMutations.refuse("UNSUPPORTED_CONFLICT",
            "This conflict includes a symbolic link or another non-plain index type. Resolve it outside the workbench, or abort the merge.")
        val path = entry.path.exact ?: GitWorkspaceMutations.refuse("UNSUPPORTED_CONFLICT", "This file name is not valid UTF-8; resolve it outside the workbench.")
        if (GitTrackingPolicy.excluded(runner, listOf(path)).isNotEmpty()) {
            GitWorkspaceMutations.refuse("EXCLUDED_PATH", "This conflicted file is excluded by the source-only policy and cannot be resolved here.")
        }
        val file = located.workTree.resolve(path).normalize()
        val parent = file.parent
        if (!file.startsWith(located.workTree) || (Files.exists(parent, NOFOLLOW_LINKS) && !parent.toRealPath().startsWith(located.workTree.toRealPath())) ||
            Files.isSymbolicLink(file)) GitWorkspaceMutations.refuse("UNSUPPORTED_CONFLICT", "This conflicted path is not a plain file inside the work tree.")
        return file
    }

    private fun completionList(request: GitSyncRequest): List<Pair<String, String>> {
        val lines = request.content?.lines()?.filter { it.isNotEmpty() } ?: GitWorkspaceMutations.refuse("VALIDATION_FAILED", "Reviewed files are required.")
        val pairs = lines.map { line -> line.split(' ').takeIf { it.size == 2 }?.let { it[0] to it[1] }
            ?: GitWorkspaceMutations.refuse("VALIDATION_FAILED", "Each reviewed file names its identity and content digest.") }
        if (pairs.size !in 1..200 || pairs.map { it.first }.toSet().size != pairs.size) {
            GitWorkspaceMutations.refuse("VALIDATION_FAILED", "Name 1 to 200 distinct reviewed files.")
        }
        return pairs
    }

    private fun validateIntegration(runner: GitCommandRunner, located: Located, observation: GitWorkspaceObservation, request: GitSyncRequest) {
        GitWorkspaceMutations.checkGuards(located.record, observation, request.guards)
        val merging = GitIntegrations.mergeInProgress(located.gitDir)
        when (request.action) {
            GitOperationAction.MERGE -> {
                requireNoLease(located)
                val strategy = GitIntegrationStrategy.entries.singleOrNull { it.wireName == request.parameters["strategy"] }
                    ?: GitWorkspaceMutations.refuse("VALIDATION_FAILED", "The strategy is fast-forward or merge.")
                if (strategy == GitIntegrationStrategy.REBASE) GitWorkspaceMutations.refuse("STRATEGY_UNSUPPORTED",
                    "Rebasing rewrites history and is not supported by the workbench. Use a fast-forward or a merge.")
                // A merge creates a commit, which the policy would require signed; a fast-forward creates none.
                if (strategy == GitIntegrationStrategy.MERGE && policy.requireSignedCommits) GitWorkspaceMutations.refuse("SIGNING_UNAVAILABLE",
                    "Policy requires signed commits, but this server has no signing capability. A fast-forward is still possible when available.")
                if (merging) GitWorkspaceMutations.refuse("MERGE_IN_PROGRESS", "A merge is already in progress. Resolve and commit it, or abort it, first.")
                if (observation.head.state == GitHeadState.UNBORN) GitWorkspaceMutations.refuse("NO_COMMITS",
                    "The branch has no commits yet. Commit first, or clone the remote into a new repository.")
                if (observation.head.state != GitHeadState.ATTACHED) GitWorkspaceMutations.refuse("DETACHED",
                    "The work tree is not on a branch. Switch to the branch you want to integrate into first.")
                val entries = relevant(observation)
                if (!observation.status.complete || entries.any { it.untracked || it.conflict != null || it.staged != GitIndexChange.NONE || it.unstaged != GitIndexChange.NONE }) {
                    GitWorkspaceMutations.refuse("WORKTREE_DIRTY", "The work tree has uncommitted changes. Commit them, or unstage and keep them, before integrating.")
                }
                val tracking = trackingRef(runner, located, request.parameters["trackingRefId"])
                if (tracking.objectId != request.parameters["targetObjectId"]) GitWorkspaceMutations.refuse("REF_CHANGED",
                    "The remote-tracking ref moved since it was reviewed. Review the new divergence first.")
                val divergence = GitIntegrations.divergence(runner, located.commonDir, checkNotNull(observation.head.objectId), tracking.objectId)
                if (divergence.behind == 0L) GitWorkspaceMutations.refuse("NOTHING_TO_INTEGRATE", "The branch already contains every commit of that ref.")
                if (strategy == GitIntegrationStrategy.FAST_FORWARD && divergence.ahead > 0) GitWorkspaceMutations.refuse("FAST_FORWARD_UNAVAILABLE",
                    "The branch has ${divergence.ahead} local commit(s), so it cannot be fast-forwarded. Review a merge instead.")
                GitRepositoryImport.requireCheckoutBounds(runner, located.commonDir, tracking.objectId, importLimits)
            }
            GitOperationAction.MERGE_ABORT -> {
                requireNoLease(located)
                if (!merging) GitWorkspaceMutations.refuse("NO_MERGE", "No merge is in progress in this work tree.")
            }
            GitOperationAction.CONFLICT_SAVE -> {
                requireNoLease(located)
                if (!merging) GitWorkspaceMutations.refuse("NO_MERGE", "No merge is in progress in this work tree.")
                val entry = conflictFor(runner, located, request.parameters["fileId"])
                conflictPath(runner, located, entry)
                when (request.parameters["resolution"]) {
                    "text" -> {
                        val text = request.content ?: GitWorkspaceMutations.refuse("VALIDATION_FAILED", "A text resolution needs its content.")
                        if (text.toByteArray().size > GitIntegrations.MAX_TEXT_BYTES) GitWorkspaceMutations.refuse("SIZE_EXCEEDED",
                            "A resolution is at most ${GitIntegrations.MAX_TEXT_BYTES / 1024} KiB of text.")
                    }
                    "ours", "theirs", "base" -> {
                        val objectId = when (request.parameters["resolution"]) { "ours" -> entry.oursObjectId; "theirs" -> entry.theirsObjectId; else -> entry.baseObjectId }
                            ?: GitWorkspaceMutations.refuse("VALIDATION_FAILED", "That side does not exist for this conflict (the file was added or deleted there).")
                        GitIntegrations.blobText(runner, located.commonDir, objectId) ?: GitWorkspaceMutations.refuse("UNSUPPORTED_CONFLICT",
                            "That side is binary or larger than ${GitIntegrations.MAX_TEXT_BYTES / 1024} KiB; resolve it outside the workbench.")
                    }
                    else -> GitWorkspaceMutations.refuse("VALIDATION_FAILED", "The resolution is ours, theirs, base or text.")
                }
                if (GitConflictFiles.observe(located.workTree, checkNotNull(entry.path.exact)).sha256 != request.parameters["expectedSha256"]) GitWorkspaceMutations.refuse("CONTENT_CHANGED",
                    "The file changed since it was reviewed (another tab or a worker wrote it). Read it again; nothing was overwritten.")
            }
            GitOperationAction.CONFLICT_COMPLETE -> {
                requireNoLease(located)
                if (!merging) GitWorkspaceMutations.refuse("NO_MERGE", "No merge is in progress in this work tree.")
                for ((fileId, sha256) in completionList(request)) {
                    val entry = conflictFor(runner, located, fileId)
                    conflictPath(runner, located, entry)
                    val current = GitConflictFiles.observe(located.workTree, checkNotNull(entry.path.exact))
                    if (current.sha256 != sha256) GitWorkspaceMutations.refuse("CONTENT_CHANGED",
                        "A file changed since it was reviewed. Read it again before marking it resolved.")
                    val text = current.text
                    if (text == null) GitWorkspaceMutations.refuse("UNSUPPORTED_CONFLICT", "A reviewed file is binary or too large to resolve in the workbench.")
                    val size = GitIntegrations.markerSize(runner, located.gitDir, located.workTree, checkNotNull(conflictFor(runner, located, fileId).path.exact))
                    if (GitIntegrations.hasMarkers(text, size)) GitWorkspaceMutations.refuse("UNRESOLVED_MARKERS",
                        "A reviewed file still contains conflict markers. Finish resolving it first.")
                }
            }
            else -> error("not an integration request")
        }
    }

    private fun executeIntegration(runner: GitCommandRunner, located: Located, operation: GitOperationRecord, request: GitSyncRequest): Pair<String?, String?> {
        val directory = repositoryDirectory(operation.jobId, operation.repositoryId)
        val observation = GitRepositoryInspector.inspect(runner, located.gitDir, located.workTree, located.commonDir)
        return when (request.action) {
            GitOperationAction.MERGE -> {
                val strategy = GitIntegrationStrategy.entries.single { it.wireName == request.parameters["strategy"] }
                val tracking = trackingRef(runner, located, request.parameters["trackingRefId"])
                val branch = checkNotNull(observation.head.refName)
                val before = checkNotNull(observation.head.objectId)
                GitIntegrations.write(directory, GitIntegrationRecord(operation.operationId, located.worktreeId, strategy, branch, before,
                    tracking.objectId, tracking.name, clock.instant()))
                crash(GitOperationCrashPoint.AFTER_STAGING)
                val message = "Merge ${tracking.name.removePrefix("refs/remotes/")} into ${branch.removePrefix("refs/heads/")}"
                val conflicted = activity.withStableRuns(located.record.jobId) { runs ->
                    requireNoLease(located, runs)
                    crash(GitOperationCrashPoint.BEFORE_PUBLISH)
                    requireNoLease(located)
                    // A workflow can have written and finished before exclusion was acquired.
                    // Recheck the reviewed guards and all integration prerequisites under it.
                    validateIntegration(runner, located,
                        GitRepositoryInspector.inspect(runner, located.gitDir, located.workTree, located.commonDir), request)
                    GitIntegrations.merge(runner, located.gitDir, located.workTree, tracking.objectId, strategy, message, policy)
                }
                crash(GitOperationCrashPoint.AFTER_PUBLISH)
                val head = GitRepositoryInspector.head(runner, located.gitDir, located.record.objectFormat).objectId
                val remote = GitRemoteStore.list(directory, located.record.repositoryId).singleOrNull { tracking.name.startsWith(it.trackingPrefix) }
                GitRemoteStore.audit(directory, GitRemoteStore.auditEntry(strategy.wireName, operation.operationId,
                    if (conflicted) "conflicted" else "completed", remote, clock.instant(), ref = branch, oldObjectId = before,
                    newObjectId = if (conflicted) tracking.objectId else head))
                if (conflicted) {
                    val count = GitIntegrations.conflicts(runner, located.gitDir, located.workTree).size
                    null to "The merge stopped with $count conflicted file(s). Resolve and stage them, then commit explicitly, or abort the merge."
                } else {
                    head to (if (strategy == GitIntegrationStrategy.FAST_FORWARD) "Fast-forwarded ${branch.removePrefix("refs/heads/")}." else "Created a merge commit.") +
                        " The result is a new source candidate: it is not validated or accepted until existing checks run."
                }
            }
            GitOperationAction.MERGE_ABORT -> {
                val record = GitIntegrations.record(directory, located.worktreeId)
                crash(GitOperationCrashPoint.AFTER_STAGING)
                activity.withStableRuns(located.record.jobId) { runs ->
                    requireNoLease(located, runs)
                    crash(GitOperationCrashPoint.BEFORE_PUBLISH)
                    requireNoLease(located)
                    // Abort must not discard a newer resolution from a now-finished workflow.
                    validateIntegration(runner, located,
                        GitRepositoryInspector.inspect(runner, located.gitDir, located.workTree, located.commonDir), request)
                    GitIntegrations.abort(runner, located.gitDir, located.workTree)
                }
                crash(GitOperationCrashPoint.AFTER_PUBLISH)
                GitRemoteStore.audit(directory, GitRemoteStore.auditEntry("merge.abort", operation.operationId, "completed", null, clock.instant(),
                    ref = record?.branch, oldObjectId = record?.target, newObjectId = record?.headBefore))
                GitRepositoryInspector.head(runner, located.gitDir, located.record.objectFormat).objectId to
                    "Aborted the merge and restored the branch and work tree to their state before it. Accepted snapshots were not touched."
            }
            GitOperationAction.CONFLICT_SAVE -> {
                val entry = conflictFor(runner, located, request.parameters["fileId"])
                conflictPath(runner, located, entry)
                val bytes = when (request.parameters["resolution"]) {
                    "text" -> checkNotNull(request.content).toByteArray()
                    else -> {
                        val objectId = checkNotNull(when (request.parameters["resolution"]) { "ours" -> entry.oursObjectId; "theirs" -> entry.theirsObjectId; else -> entry.baseObjectId })
                        checkNotNull(GitIntegrations.blobText(runner, located.commonDir, objectId)).toByteArray()
                    }
                }
                crash(GitOperationCrashPoint.AFTER_STAGING)
                // Workflow admission and final digest/publication share the activity owner's lock.
                activity.withStableRuns(located.record.jobId) { runs ->
                    requireNoLease(located, runs)
                    GitConflictFiles.replace(located.workTree, checkNotNull(entry.path.exact),
                        checkNotNull(request.parameters["expectedSha256"]), bytes) {
                        crash(GitOperationCrashPoint.BEFORE_PUBLISH)
                        requireNoLease(located)
                    }
                }
                null to "Saved the resolution of ${entry.path.fileId(located.worktreeId)}. It is not staged; mark it resolved when the review is complete."
            }
            GitOperationAction.CONFLICT_COMPLETE -> {
                val count = activity.withStableRuns(located.record.jobId) { runs ->
                    requireNoLease(located, runs)
                    val reviewed = completionList(request).map { (fileId, sha256) ->
                        val entry = conflictFor(runner, located, fileId)
                        conflictPath(runner, located, entry)
                        val path = checkNotNull(entry.path.exact)
                        val current = GitConflictFiles.observe(located.workTree, path)
                        if (current.sha256 != sha256) GitWorkspaceMutations.refuse("CONTENT_CHANGED", "A file changed since review. Nothing was staged.")
                        val text = current.text ?: GitWorkspaceMutations.refuse("UNSUPPORTED_CONFLICT", "A reviewed file is binary or too large.")
                        if (GitIntegrations.hasMarkers(text, GitIntegrations.markerSize(runner, located.gitDir, located.workTree, path))) {
                            GitWorkspaceMutations.refuse("UNRESOLVED_MARKERS", "A reviewed file still contains conflict markers. Nothing was staged.")
                        }
                        entry.path to current
                    }
                    crash(GitOperationCrashPoint.BEFORE_PUBLISH)
                    requireNoLease(located)
                    GitIntegrations.stageReviewed(runner, located.gitDir, located.workTree, located.record.objectFormat, reviewed)
                    reviewed.size
                }
                val remaining = GitIntegrations.conflicts(runner, located.gitDir, located.workTree).size
                null to "Staged $count resolved file(s); $remaining conflict(s) remain. Commit explicitly when the review is complete."
            }
            else -> error("not an integration request")
        }
    }

    /** Apply one validated remote intent. Returns the result object and a completion message. */
    private fun executeSync(runner: GitCommandRunner, located: Located, operation: GitOperationRecord, request: GitSyncRequest): Pair<String?, String?> {
        if (request.action !in GitSyncRequest.REMOTE) return executeIntegration(runner, located, operation, request)
        val directory = repositoryDirectory(operation.jobId, operation.repositoryId)
        return when (request.action) {
            GitOperationAction.REMOTE_ADD -> {
                val location = GitRemoteUrls.parse(request.text("url"), remotePolicy)
                val name = request.text("name")
                val remote = GitRemoteRecord(GitRemoteStore.remoteId(operation.repositoryId, name, operation.operationId), operation.repositoryId, name, location,
                    clock.instant(), operation.operationId)
                GitRemoteStore.write(directory, remote)
                GitRemoteStore.audit(directory, GitRemoteStore.auditEntry("remote.add", operation.operationId, "completed", remote, clock.instant()))
                null to "Registered remote $name at ${location.display}. Nothing was fetched or pushed."
            }
            GitOperationAction.REMOTE_REMOVE -> {
                val remote = remoteFor(located, request.parameters["remoteId"])
                GitTransfers.allTrackingRefs(runner, located.commonDir, located.record.objectFormat, remote.name).forEach { ref ->
                    GitRefOperations.deleteRef(runner, located.commonDir, ref.name, ref.objectId)
                }
                GitRemoteStore.delete(directory, remote.remoteId)
                Files.deleteIfExists(directory.resolve(FETCH_STATE).resolve("${remote.remoteId}.json"))
                GitRemoteStore.audit(directory, GitRemoteStore.auditEntry("remote.remove", operation.operationId, "completed", remote, clock.instant()))
                null to "Removed remote ${remote.name} and its remote-tracking refs. Local branches and commits are unchanged."
            }
            GitOperationAction.FETCH -> {
                val remote = remoteFor(located, request.parameters["remoteId"])
                val location = allowedLocation(remote)
                val staging = GitStorage.directories(root.resolve(operation.jobId).resolve("git"), "staging", operation.operationId)
                // The cap covers the entire managed repository, including primary/linked
                // checkouts and records. Reserve space for the success audit/fetch-state writes.
                val remaining = (remotePolicy.limits.maxRepositoryBytes - GitDiskWatch.bytes(directory) - 4096).coerceAtLeast(0)
                val changed = try {
                    GitTransfers.fetchQuarantined(runner, located.commonDir, staging.resolve(GIT_DIR), located.record.objectFormat,
                        location, remote.name, remotePolicy, remaining, transferControl(operation.operationId, staging, remaining))
                } catch (failure: Exception) {
                    val code = when (failure) {
                        is GitCommandException -> GitTransports.classify(failure, failure.diagnostic, location.transport).first
                        is GitOperationRefusal -> failure.code
                        else -> "TRANSFER_FAILED"
                    }
                    GitRemoteStore.audit(directory, GitRemoteStore.auditEntry("fetch", operation.operationId, code.lowercase(), remote, clock.instant()))
                    throw failure
                }
                writeFetchState(directory, remote.remoteId, operation.operationId)
                GitRemoteStore.audit(directory, GitRemoteStore.auditEntry("fetch", operation.operationId, "completed", remote, clock.instant(),
                    detail = "$changed remote-tracking refs changed"))
                null to "Fetched ${remote.name}: $changed remote-tracking ref(s) changed. Nothing was merged or checked out."
            }
            else -> error("not a sync request")
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

    // ---- Workspace mutations (#576, #577) -------------------------------------------------

    /**
     * Admit one stage, unstage or commit. Keyed replay precedes [precondition]; then the request's
     * guards and selection are checked against a fresh observation under the job lock, and again
     * by the executor immediately before Git runs, so a race with another tab, a worker or an
     * external edit fails instead of committing something nobody reviewed.
     */
    fun requestWorkspace(jobId: String, repositoryId: String, request: GitRepositoryRequest, requestKey: String,
        precondition: () -> Unit = {}): GitOperationAdmission {
        require(request.action.workspace && request !is GitRetainedCommit)
        val runner = requireRunner()
        require(requestKey.matches(Regex("[A-Za-z0-9_-]{16,128}")))
        val keyDigest = GitStorage.sha256("git-operations-post\n$jobId\n$repositoryId\n$requestKey")
        synchronized(lock) {
            if (closed) throw ManagedGitException("SERVER_DRAINING", "The server is stopping; no new Git operation was admitted.")
            val directory = jobGitDirectory(jobId)
            reconcile(jobId)
            val operations = operations(jobId)
            operations.firstOrNull { it.requestKeySha256 == keyDigest }?.let { existing ->
                if (existing.request.digest != request.digest || existing.repositoryId != repositoryId) {
                    throw ManagedGitException("IDEMPOTENCY_CONFLICT", "The request key was used for a different repository operation.")
                }
                return GitOperationAdmission(existing, replayed = true)
            }
            precondition()
            val located = locate(jobId, repositoryId, targetWorktree(request))
            if (operations.any { !it.state.terminal }) {
                throw ManagedGitException("WORKTREE_BUSY", "Another repository operation is still running for this job.")
            }
            if (retireTerminalWorkspace(jobId, operations).size >= MAX_OPERATIONS || executor.queue.remainingCapacity() == 0) {
                throw ManagedGitException("QUOTA_EXCEEDED", "Repository operation capacity is exhausted. Review existing operations first.")
            }
            refusing { validate(runner, located, request) }
            // A new work tree's identity is assigned at admission and is the operation's work tree.
            val worktreeId = if (request.action == GitOperationAction.WORKTREE_ADD) identity("worktree") else located.worktreeId
            val operation = GitOperationRecord(identity("operation"), jobId, repositoryId, worktreeId,
                request.action, GitOperationState.QUEUED, 1, clock.instant(), null, null, null, QUEUED_WORKSPACE_MESSAGE, keyDigest, request)
            persist(directory, operation)
            active += operation.operationId
            if (operation.action in GitSyncRequest.CANCELLABLE) cancellations[operation.operationId] = java.util.concurrent.atomic.AtomicBoolean()
            try {
                executor.execute { executeWorkspace(operation, located) }
            } catch (_: RejectedExecutionException) {
                active -= operation.operationId
                persist(directory, finish(operation, GitOperationState.FAILED, "QUOTA_EXCEEDED",
                    "Repository operation capacity was exhausted before this operation started."))
            }
            return GitOperationAdmission(operations(jobId).single { it.operationId == operation.operationId }, replayed = false)
        }
    }

    private fun targetWorktree(request: GitRepositoryRequest): String? = when (request) {
        is GitStageRequest -> request.worktreeId
        is GitCommitRequest -> request.worktreeId
        is GitRetainedCommit -> request.worktreeId
        is GitRefRequest -> request.worktreeId
        is GitSyncRequest -> request.worktreeId
        else -> null
    }

    /** Wait briefly for a just-admitted operation so small actions answer with their outcome. */
    fun awaitOperation(jobId: String, repositoryId: String, operationId: String, timeoutMillis: Long): GitOperationRecord {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline && synchronized(lock) { operationId in active }) Thread.sleep(10)
        return operation(jobId, repositoryId, operationId)
    }

    private fun <T> refusing(block: () -> T): T = try { block() } catch (refusal: GitOperationRefusal) {
        throw ManagedGitException(refusal.code, refusal.message ?: "The repository operation was refused.")
    } catch (failure: GitRepositoryException) {
        throw ManagedGitException(failure.code, failure.message ?: "The repository could not be read.")
    }

    /** Guards, selection and policy for one workspace request against the current observation. */
    private fun validate(runner: GitCommandRunner, located: Located, request: GitRepositoryRequest): GitWorkspaceObservation {
        val observation = GitRepositoryInspector.inspect(runner, located.gitDir, located.workTree, located.commonDir)
        when (request) {
            is GitStageRequest -> {
                GitWorkspaceMutations.checkGuards(located.record, observation, request.guards)
                val entries = GitWorkspaceMutations.select(located.record, observation, request.fileIds, request.stage, located.worktreeId)
                if (request.stage) {
                    val paths = entries.flatMap { listOfNotNull(it.path.exact, it.originalPath?.exact) }
                    if (GitTrackingPolicy.excluded(runner, paths).isNotEmpty()) {
                        GitWorkspaceMutations.refuse("EXCLUDED_PATH", "A selected file is excluded by the source-only tracking policy and cannot be staged.")
                    }
                }
            }
            is GitCommitRequest -> {
                GitWorkspaceMutations.validateMessage(request.message)
                if (policy.requireSignedCommits) GitWorkspaceMutations.refuse("SIGNING_UNAVAILABLE",
                    "Policy requires signed commits, but this server has no signing capability. Nothing was committed.")
                GitWorkspaceMutations.checkGuards(located.record, observation, request.guards)
                GitWorkspaceMutations.requireStagedSet(located.record, observation, request.fileIds, located.worktreeId,
                    mergeInProgress = GitIntegrations.mergeInProgress(located.gitDir), reviewedMergeIndex = request.reviewedMergeIndex)
            }
            is GitRefRequest -> validateRef(runner, located, observation, request)
            is GitSyncRequest -> validateSync(runner, located, observation, request)
            else -> error("not a workspace request")
        }
        return observation
    }

    /**
     * A work tree is leased to active workflow attempts: the primary one to any active attempt of
     * the job, and a linked one to the attempt that owns it. Checkout or removal never replaces
     * files under a running worker.
     */
    private fun requireNoLease(located: Located, runs: Map<String, Boolean> = activity.runs(located.record.jobId)) {
        val held = if (located.primary) runs.any { it.value } else located.ownerRunId?.let { runs[it] } == true
        if (held) GitRefOperations.refuse("ACTIVE_RUN", "A workflow attempt is running against this work tree. Wait for it to finish; nothing was changed.")
    }

    private fun relevant(observation: GitWorkspaceObservation) = observation.status.entries.filter { !it.ignored }

    /** Every work tree's symbolic HEAD, so a branch checked out anywhere is never deleted. */
    private fun checkedOutBranches(runner: GitCommandRunner, located: Located): Set<String> {
        val linked = linkedWorktrees(located.record.jobId, located.record).map { located.commonDir.resolve("worktrees").resolve(it.worktreeId) }
        return (listOf(located.commonDir) + linked).filter { Files.isDirectory(it, NOFOLLOW_LINKS) }.mapNotNull { gitDir ->
            val result = runner.run(GitInvocation("symbolic-ref", listOf("-q", "HEAD"), gitDir = gitDir, allowedExitCodes = setOf(0, 1)))
            result.text.trim().takeIf { result.exitCode == 0 && it.isNotEmpty() }
        }.toSet()
    }

    private fun branchFor(runner: GitCommandRunner, located: Located, refId: String?): Pair<String, String> {
        val id = refId ?: GitRefOperations.refuse("VALIDATION_FAILED", "A branch ref identity is required.")
        val refs = GitReads.allRefs(runner, located.commonDir, located.record.objectFormat)
        val ref = refs.singleOrNull { it.name.startsWith("refs/heads/") && GitWorkspaceVersions.refId(located.record.repositoryId, it.name) == id }
            ?: GitRefOperations.refuse("NOT_FOUND", "The branch is not registered in this repository.")
        return ref.name to ref.objectId
    }

    private fun validateRef(runner: GitCommandRunner, located: Located, observation: GitWorkspaceObservation, request: GitRefRequest) {
        val record = located.record
        val format = record.objectFormat
        GitWorkspaceMutations.checkGuards(record, observation, request.guards)
        when (request.action) {
            GitOperationAction.BRANCH_CREATE, GitOperationAction.TAG -> {
                val namespace = if (request.action == GitOperationAction.TAG) "tags" else "heads"
                val name = GitRefOperations.requireName(runner, request.name, namespace)
                GitRefOperations.requireCommit(runner, located.commonDir, format, request.objectId)
                if (GitRefOperations.refObject(runner, located.commonDir, format, "refs/$namespace/$name") != null) {
                    GitRefOperations.refuse(if (namespace == "tags") "TAG_EXISTS" else "BRANCH_EXISTS",
                        "That name already exists; nothing is ever overwritten. Choose another name.")
                }
            }
            GitOperationAction.SWITCH -> {
                requireNoLease(located)
                val entries = relevant(observation)
                if (entries.any { it.conflict != null }) GitRefOperations.refuse("CONFLICTED", "Resolve conflicted files before switching.")
                if (entries.any { it.staged != GitIndexChange.NONE || it.unstaged != GitIndexChange.NONE }) {
                    GitRefOperations.refuse("WORKTREE_DIRTY", "The work tree has uncommitted changes. Commit them, or unstage and keep them, before switching; switching never discards or stashes work.")
                }
                if (request.refId == null && request.objectId == null) {
                    GitRefOperations.refuse("VALIDATION_FAILED", "A switch names a branch (with its reviewed tip) or one commit.")
                }
                val target = request.refId?.let { refId ->
                    val (name, tip) = branchFor(runner, located, refId)
                    // The guards cover only the bounded ref observation; the reviewed tip covers the
                    // destination itself, so a branch that moved after review is never checked out.
                    if (request.objectId != null && request.objectId != tip) {
                        GitRefOperations.refuse("REF_CHANGED", "The branch moved since it was reviewed; nothing was checked out. Read it again first.")
                    }
                    if (request.objectId == null && observation.refsTruncated) GitRefOperations.refuse("VALIDATION_FAILED",
                        "This repository has more refs than one review covers, so a branch switch must name the branch's reviewed tip.")
                    // An imported name such as `--detach` would be read as a switch option; refuse it.
                    if (name.removePrefix("refs/heads/").startsWith("-")) {
                        GitRefOperations.refuse("VALIDATION_FAILED", "That branch name starts with '-' and cannot be switched to by the workbench.")
                    }
                    // The bare common layout hides the primary checkout from Git's own check; use ours.
                    if (name != observation.head.refName && name in checkedOutBranches(runner, located)) {
                        GitRefOperations.refuse("BRANCH_CURRENT", "That branch is checked out in another work tree. Use a new branch or switch that work tree first.")
                    }
                    tip
                } ?: GitRefOperations.requireCommit(runner, located.commonDir, format, request.objectId)
                GitRepositoryImport.requireCheckoutBounds(runner, located.commonDir, target, importLimits)
            }
            GitOperationAction.BRANCH_DELETE -> {
                val (name, tip) = branchFor(runner, located, request.refId)
                if (request.objectId != tip) GitRefOperations.refuse("REF_CHANGED", "The branch moved since it was reviewed; nothing was deleted.")
                if (name in checkedOutBranches(runner, located)) {
                    GitRefOperations.refuse("BRANCH_CURRENT", "The branch is checked out in a work tree. Switch that work tree first.")
                }
                val unmerged = GitRefOperations.unmergedCount(runner, located.commonDir, tip, name)
                if (unmerged > 0) GitRefOperations.refuse("BRANCH_UNMERGED",
                    "$unmerged commit(s) are reachable only from this branch. Merge or tag them first; nothing is force-deleted.")
            }
            GitOperationAction.WORKTREE_ADD -> {
                if (!located.primary) GitRefOperations.refuse("VALIDATION_FAILED", "New work trees are created from the primary work tree.")
                if (linkedWorktrees(record.jobId, record).size >= GitRefOperations.MAX_LINKED_WORKTREES) {
                    GitRefOperations.refuse("QUOTA_EXCEEDED", "This repository already has the maximum of ${GitRefOperations.MAX_LINKED_WORKTREES} linked work trees.")
                }
                val start = GitRefOperations.requireCommit(runner, located.commonDir, format, request.objectId)
                request.name?.let { name ->
                    GitRefOperations.requireName(runner, name, "heads")
                    if (GitRefOperations.refObject(runner, located.commonDir, format, "refs/heads/$name") != null) {
                        GitRefOperations.refuse("BRANCH_EXISTS", "That branch already exists; nothing is ever overwritten.")
                    }
                }
                request.runId?.let { runId ->
                    if (runId !in activity.runs(record.jobId)) GitRefOperations.refuse("VALIDATION_FAILED", "The owning attempt is not a run of this job.")
                }
                GitRepositoryImport.requireCheckoutBounds(runner, located.commonDir, start, importLimits)
            }
            GitOperationAction.WORKTREE_REMOVE -> {
                if (located.primary) GitRefOperations.refuse("WORKTREE_PRIMARY", "The primary work tree cannot be removed.")
                requireNoLease(located)
                // Ignored files count too: `git worktree remove` deletes them without --force,
                // and they are often experiment output. An incomplete status is never clean.
                if (observation.status.entries.isNotEmpty() || !observation.status.complete) GitRefOperations.refuse("WORKTREE_DIRTY",
                    "The work tree has uncommitted, untracked or ignored local files. Commit or move them first; nothing is force-removed.")
                // Status ignores submodules, so files inside a gitlink's directory are invisible to it;
                // look at those directories directly (nothing is initialized or executed).
                GitRefOperations.gitlinkPaths(runner, located.gitDir, located.workTree).forEach { path ->
                    val directory = path?.let(located.workTree::resolve)
                    val occupied = directory == null || (Files.isDirectory(directory, NOFOLLOW_LINKS) &&
                        Files.newDirectoryStream(directory).use { it.iterator().hasNext() })
                    if (occupied) GitRefOperations.refuse("WORKTREE_DIRTY",
                        "A submodule directory in the work tree holds local files. Move them first; nothing is force-removed.")
                }
                val head = observation.head
                if (head.state == GitHeadState.DETACHED) {
                    val unmerged = GitRefOperations.unmergedCount(runner, located.commonDir, checkNotNull(head.objectId), null)
                    if (unmerged > 0) GitRefOperations.refuse("WORKTREE_UNMERGED",
                        "$unmerged commit(s) exist only in this detached work tree. Create a branch or tag for them first.")
                }
            }
            else -> error("not a ref request")
        }
    }

    private fun executeWorkspace(queued: GitOperationRecord, located: Located) {
        val directory = root.resolve(queued.jobId).resolve("git")
        val staging = directory.resolve("staging").resolve(queued.operationId)
        var current = queued
        try {
            val runner = requireRunner()
            current = synchronized(lock) { advance(directory, current, GitOperationState.RUNNING, RUNNING_WORKSPACE_MESSAGE) }
            crash(GitOperationCrashPoint.AFTER_RUNNING)
            // Recheck immediately before Git runs: the lease is the single executor plus the job lock.
            val observation = synchronized(lock) { validate(runner, located, queued.request) }
            var result: String? = null
            var message = completedMessage(queued.action)
            when (val request = queued.request) {
                is GitStageRequest -> {
                    val entries = GitWorkspaceMutations.select(located.record, observation, request.fileIds, request.stage, located.worktreeId)
                    if (request.stage) GitWorkspaceMutations.stage(runner, located.gitDir, located.workTree, entries)
                    else GitWorkspaceMutations.unstage(runner, located.gitDir, located.workTree, entries,
                        observation.head.state == GitHeadState.UNBORN)
                }
                is GitCommitRequest -> {
                    GitStorage.deleteTree(staging)
                    GitStorage.directories(directory, "staging", queued.operationId)
                    val messageFile = staging.resolve("message")
                    Files.writeString(messageFile, request.message)
                    crash(GitOperationCrashPoint.AFTER_STAGING)
                    GitWorkspaceMutations.commit(runner, located.gitDir, located.workTree, messageFile, policy)
                    crash(GitOperationCrashPoint.AFTER_PUBLISH)
                    val after = GitRepositoryInspector.inspect(runner, located.gitDir, located.workTree, located.commonDir)
                    result = checkNotNull(after.head.objectId)
                    if (recordMapping(runner, located, result, after.dirty) == null) {
                        message += " The commit tree differs from the recorded candidate snapshot, so it is not mapped to a reconstruction revision."
                    }
                }
                is GitRefRequest -> result = executeRef(runner, located, queued, request)
                is GitSyncRequest -> {
                    if (cancelledBeforeStart(queued.operationId)) throw GitOperationRefusal("CANCELLED", "The transfer was cancelled before it started.")
                    val (objectId, text) = executeSync(runner, located, queued, request)
                    result = objectId; text?.let { message = it }
                }
                else -> error("not a workspace request")
            }
            synchronized(lock) { current = finish(current, GitOperationState.COMPLETED, null, message, result); persist(directory, current) }
        } catch (_: SimulatedGitCrash) {
            synchronized(lock) { active -= queued.operationId }
            return
        } catch (failure: Throwable) {
            val (code, message) = when (failure) {
                is GitOperationRefusal -> failure.code to (failure.message ?: "")
                is GitRepositoryException -> failure.code to (failure.message ?: "")
                is ManagedGitException -> failure.code to (failure.message ?: "")
                is GitCommandException -> when {
                    failure.kind == GitCommandException.Kind.INTERRUPTED -> "INTERRUPTED" to INTERRUPTED_MESSAGE
                    queued.request is GitSyncRequest -> GitTransports.classify(failure, failure.diagnostic,
                        try { remoteFor(located, (queued.request as GitSyncRequest).parameters["remoteId"]).location.transport } catch (_: Exception) { GitTransport.HTTPS })
                    else -> "REPOSITORY_UNAVAILABLE" to "Git did not complete within its bounds. Read the current status before trying again."
                }
                else -> "STORAGE_FAILED" to "Repository storage could not be written. Read the current status before trying again."
            }
            synchronized(lock) {
                val state = when (code) {
                    "INTERRUPTED" -> GitOperationState.INTERRUPTED
                    "CANCELLED" -> GitOperationState.CANCELLED
                    else -> GitOperationState.FAILED
                }
                current = finish(current, state, code, message.take(500))
                try { persist(directory, current) } catch (_: Exception) { /* reconciled after restart */ }
            }
        } finally {
            try { GitStorage.deleteTree(staging) } catch (_: Exception) { /* removed by reconciliation */ }
            synchronized(lock) { active -= queued.operationId; cancellations -= queued.operationId; progress -= queued.operationId }
        }
    }

    /** Apply one validated branch, tag or work-tree intent. Returns the resulting object, if any. */
    private fun executeRef(runner: GitCommandRunner, located: Located, operation: GitOperationRecord, request: GitRefRequest): String? {
        val format = located.record.objectFormat
        return when (request.action) {
            GitOperationAction.BRANCH_CREATE, GitOperationAction.TAG -> {
                val namespace = if (request.action == GitOperationAction.TAG) "tags" else "heads"
                val objectId = checkNotNull(request.objectId)
                GitRefOperations.createRef(runner, located.commonDir, "refs/$namespace/${request.name}", objectId,
                    if (namespace == "tags") "TAG_EXISTS" else "BRANCH_EXISTS")
                crash(GitOperationCrashPoint.AFTER_PUBLISH)
                objectId
            }
            GitOperationAction.SWITCH -> {
                val branch = request.refId?.let { branchFor(runner, located, it).first.removePrefix("refs/heads/") }
                GitRefOperations.switch(runner, located.gitDir, located.workTree, branch, request.objectId)
                crash(GitOperationCrashPoint.AFTER_PUBLISH)
                GitRepositoryInspector.head(runner, located.gitDir, format).objectId
            }
            GitOperationAction.BRANCH_DELETE -> {
                val (name, tip) = branchFor(runner, located, request.refId)
                GitRefOperations.deleteRef(runner, located.commonDir, name, tip)
                crash(GitOperationCrashPoint.AFTER_PUBLISH)
                null
            }
            GitOperationAction.WORKTREE_ADD -> {
                val directory = repositoryDirectory(operation.jobId, operation.repositoryId)
                val path = GitStorage.directories(directory, LINKED_WORK_TREES).resolve(operation.worktreeId)
                if (Files.exists(path, NOFOLLOW_LINKS)) GitRefOperations.refuse("STORAGE_FAILED", "The work-tree location is already occupied.")
                val objectId = checkNotNull(request.objectId)
                GitRefOperations.addWorktree(runner, located.commonDir, path, objectId, request.name)
                crash(GitOperationCrashPoint.AFTER_STAGING)
                val records = GitStorage.directories(directory, WORKTREE_RECORDS)
                GitStorage.replaceAtomically(records.resolve("${operation.worktreeId}.json"), GitRefOperations.encodeWorktree(
                    GitWorktreeRecord(operation.worktreeId, operation.repositoryId, operation.jobId, operation.operationId, request.runId,
                        clock.instant())).toByteArray())
                crash(GitOperationCrashPoint.AFTER_PUBLISH)
                objectId
            }
            GitOperationAction.WORKTREE_REMOVE -> {
                GitRefOperations.removeWorktree(runner, located.commonDir, located.workTree)
                crash(GitOperationCrashPoint.AFTER_STAGING)
                Files.deleteIfExists(repositoryDirectory(operation.jobId, operation.repositoryId).resolve(WORKTREE_RECORDS).resolve("${located.worktreeId}.json"))
                null
            }
            else -> error("not a ref request")
        }
    }

    // TODO(#509, PR #1694): once JobRetentionHold lands, hold the job while its work tree is dirty or
    // it has commits without a published mapping, so retention never deletes unpublished Git work.

    /**
     * Record a commit-to-revision mapping only when the commit tree holds exactly the copied bytes of
     * the repository's candidate snapshot. Any other commit is a new candidate and stays unmapped.
     */
    private fun recordMapping(runner: GitCommandRunner, located: Located, commit: String, dirty: Boolean): GitMappingRecord? {
        val record = located.record
        val revisionId = record.candidateRevisionId ?: return null
        val runId = record.runId ?: return null
        val sourceSha256 = record.sourceSha256 ?: return null
        val snapshot = try { sources.resolve(record.jobId, runId, revisionId) } catch (_: Exception) { return null }
        if (snapshot.sourceSha256 != sourceSha256) return null
        // The retained snapshot must still hold its canonical build-input commitments; a changed
        // snapshot cannot lend the original revision's identity to a commit.
        for ((path, commitment) in snapshot.commitments) {
            val file = snapshot.directory.resolve(path)
            if (!Files.isRegularFile(file, NOFOLLOW_LINKS) || Files.size(file) != commitment.sizeBytes ||
                GitSourceCopy.digestOf(file) != commitment.sha256) return null
        }
        // Policy-excluded files are copied but can never be committed, so they are not expected.
        val copied = GitWorkspaceMutations.snapshotBlobs(snapshot.directory, record.objectFormat) ?: return null
        val expected = copied - GitTrackingPolicy.excluded(runner, copied.keys)
        val actual = GitWorkspaceMutations.commitBlobs(runner, located.commonDir, record.objectFormat, commit) ?: return null
        if (expected != actual) return null
        val mapping = GitMappingRecord(record.repositoryId, commit, revisionId, sourceSha256, clock.instant(), dirty)
        val mappings = GitStorage.directories(located.commonDir.parent, "mappings")
        GitStorage.replaceAtomically(mappings.resolve("$commit.json"), GitWorkspaceMutations.encodeMapping(mapping).toByteArray())
        return mapping
    }

    /** The recorded mapping for one object with acceptance derived from canonical job evidence. */
    private fun mappingView(jobId: String, record: GitRepositoryRecord, objectId: String): GitMappingView? {
        if (record.objectFormat.objectIdOrNull(objectId) == null) return null
        val file = root.resolve(jobId).resolve("git/repositories").resolve(record.repositoryId).resolve("mappings").resolve("$objectId.json")
        if (!Files.isRegularFile(file, NOFOLLOW_LINKS)) return null
        val mapping = GitWorkspaceMutations.decodeMapping(record.repositoryId, objectId,
            try { GitStorage.read(file, MAX_RECORD_BYTES) } catch (_: IOException) { return null }) ?: return null
        val (state, artifact) = try { acceptance.acceptance(jobId, mapping.revisionId, mapping.sourceSha256) } catch (_: Exception) { "unknown" to null }
        return GitMappingView(mapping, state, artifact.takeIf { state == "accepted" })
    }

    /** Mappings for listed commits; absent records stay null rather than being inferred. */
    fun mappings(jobId: String, repositoryId: String, objectIds: Collection<String>): Map<String, GitMappingView> {
        val record = repository(jobId, repositoryId)
        return objectIds.mapNotNull { objectId -> mappingView(jobId, record, objectId)?.let { objectId to it } }.toMap()
    }

    /**
     * After a restart a workspace operation is never repeated. Stage and unstage may have partly
     * updated the index, so they become `interrupted` and status must be re-read. A commit is
     * `interrupted` while HEAD is still the reviewed parent; if HEAD moved it becomes
     * `recovery-required` with the new HEAD, because the commit may or may not be the requested one.
     */
    private fun reconcileWorkspace(jobId: String, operation: GitOperationRecord): GitOperationRecord {
        (operation.request as? GitRefRequest)?.let { return reconcileRef(jobId, operation, it) }
        (operation.request as? GitSyncRequest)?.let { return reconcileSync(jobId, operation, it) }
        if (operation.action != GitOperationAction.COMMIT) {
            return finish(operation, GitOperationState.INTERRUPTED, "INTERRUPTED",
                "Interrupted by a server restart. The index may be partly updated; read the current status before a new request.")
        }
        val guards = (operation.request as? GitRetainedCommit)?.guards
        val head = try {
            val runner = requireRunner()
            // Reconciliation runs inside reconcile(); read the registration directly, never through locate().
            val record = repositories(jobId).single { it.repositoryId == operation.repositoryId }
            val commonDir = root.resolve(jobId).resolve("git/repositories").resolve(record.repositoryId).resolve(GIT_DIR)
            // A commit may target a linked work tree; classify it by that work tree's own HEAD.
            val gitDir = if (operation.worktreeId == record.worktreeId) commonDir else commonDir.resolve("worktrees").resolve(operation.worktreeId)
            GitRepositoryInspector.head(runner, gitDir, record.objectFormat).objectId
        } catch (_: Exception) { return finish(operation, GitOperationState.RECOVERY_REQUIRED, "HEAD_UNKNOWN",
            "Interrupted by a server restart and HEAD could not be read. Inspect the repository before a new request.") }
        return if (head == guards?.expectedHeadObjectId) finish(operation, GitOperationState.INTERRUPTED, "INTERRUPTED",
            "Interrupted by a server restart before a commit was created. Review the staged files and commit again explicitly.")
        else finish(operation, GitOperationState.RECOVERY_REQUIRED, "HEAD_MOVED",
            "Interrupted by a server restart after HEAD moved. Inspect the latest history entry before any new commit.", head)
    }

    /**
     * Compare a branch, tag or work-tree intent with the actual refs after a restart. An effect that
     * is fully present completes the operation; an absent effect makes it `interrupted`; anything
     * in between is `recovery-required`. HEAD states are named explicitly, including a HEAD left on
     * a branch that no longer exists. Nothing is repeated and accepted snapshots are never touched.
     */
    private fun reconcileRef(jobId: String, operation: GitOperationRecord, request: GitRefRequest): GitOperationRecord {
        fun interrupted(message: String) = finish(operation, GitOperationState.INTERRUPTED, "INTERRUPTED", message)
        fun completed(message: String, objectId: String? = null) = finish(operation, GitOperationState.COMPLETED, null, message, objectId)
        fun recovery(code: String, message: String, objectId: String? = null) =
            finish(operation, GitOperationState.RECOVERY_REQUIRED, code, message, objectId)
        return try {
            val runner = requireRunner()
            val record = repositories(jobId).single { it.repositoryId == operation.repositoryId }
            val directory = repositoryDirectory(jobId, record.repositoryId)
            val commonDir = directory.resolve(GIT_DIR)
            val format = record.objectFormat
            when (request.action) {
                GitOperationAction.BRANCH_CREATE, GitOperationAction.TAG -> {
                    val namespace = if (request.action == GitOperationAction.TAG) "tags" else "heads"
                    when (GitRefOperations.refObject(runner, commonDir, format, "refs/$namespace/${request.name}")) {
                        null -> interrupted("Interrupted by a server restart before the name was created. Create it again explicitly.")
                        request.objectId -> completed("The name was created before the server restarted.", request.objectId)
                        else -> recovery("REF_CONFLICT", "A ref with that name now names a different object. Inspect it before any new request.")
                    }
                }
                GitOperationAction.BRANCH_DELETE -> {
                    val refs = GitReads.allRefs(runner, commonDir, format)
                    val present = refs.any { it.name.startsWith("refs/heads/") && GitWorkspaceVersions.refId(record.repositoryId, it.name) == request.refId }
                    if (present) interrupted("Interrupted by a server restart before the branch was deleted; it is unchanged.")
                    else completed("The branch was deleted before the server restarted.")
                }
                GitOperationAction.SWITCH -> {
                    val gitDir = if (operation.worktreeId == record.worktreeId) commonDir else commonDir.resolve("worktrees").resolve(operation.worktreeId)
                    val head = GitRepositoryInspector.head(runner, gitDir, format)
                    val target = request.refId?.let { refId ->
                        GitReads.allRefs(runner, commonDir, format).singleOrNull { GitWorkspaceVersions.refId(record.repositoryId, it.name) == refId }?.name
                    }
                    when {
                        head.state == GitHeadState.UNBORN && head.refName != null && target == null && request.refId != null ->
                            recovery("REF_DELETED", "HEAD names a branch that no longer exists (unborn). Choose a branch or commit before new work.")
                        target != null && head.refName == target -> completed("The switch finished before the server restarted.", head.objectId)
                        request.objectId != null && head.state == GitHeadState.DETACHED && head.objectId == request.objectId ->
                            completed("The switch finished before the server restarted.", head.objectId)
                        head.objectId == request.guards.expectedHeadObjectId && (request.guards.expectedRefId == null ||
                            head.refName?.let { GitWorkspaceVersions.refId(record.repositoryId, it) } == request.guards.expectedRefId) ->
                            interrupted("Interrupted by a server restart before HEAD moved. Read the status before switching again.")
                        else -> recovery("HEAD_MOVED", "Interrupted by a server restart during checkout; HEAD is ${head.state.wireName}. " +
                            "Read the status and inspect the work tree before any new request.", head.objectId)
                    }
                }
                GitOperationAction.WORKTREE_ADD -> {
                    val recordFile = directory.resolve(WORKTREE_RECORDS).resolve("${operation.worktreeId}.json")
                    if (Files.isRegularFile(recordFile, NOFOLLOW_LINKS)) completed("The work tree was created before the server restarted.", request.objectId)
                    else {
                        // A work tree without its registration was never visible: remove Git's metadata and the files.
                        val path = directory.resolve(LINKED_WORK_TREES).resolve(operation.worktreeId)
                        if (Files.exists(path, NOFOLLOW_LINKS)) {
                            try { GitRefOperations.removeWorktree(runner, commonDir, path, force = true) } catch (_: GitOperationRefusal) { }
                            GitStorage.deleteTree(path)
                        }
                        runner.run(GitInvocation("worktree", listOf("prune"), gitDir = commonDir))
                        // `worktree add -b` also created the branch; roll it back only at the exact start object.
                        val branch = request.name?.let { "refs/heads/$it" }
                        val tip = branch?.let { GitRefOperations.refObject(runner, commonDir, format, it) }
                        when {
                            tip == null -> interrupted("Interrupted by a server restart before the work tree was registered; nothing was created.")
                            tip == request.objectId -> {
                                GitRefOperations.deleteRef(runner, commonDir, checkNotNull(branch), tip)
                                interrupted("Interrupted by a server restart before the work tree was registered; its new branch was rolled back and nothing remains.")
                            }
                            else -> recovery("REF_CONFLICT", "The work tree's new branch now names a different commit. Inspect it before any new request.")
                        }
                    }
                }
                GitOperationAction.WORKTREE_REMOVE -> {
                    val path = directory.resolve(LINKED_WORK_TREES).resolve(operation.worktreeId)
                    if (Files.exists(path, NOFOLLOW_LINKS)) interrupted("Interrupted by a server restart before the work tree was removed; it is unchanged.")
                    else {
                        Files.deleteIfExists(directory.resolve(WORKTREE_RECORDS).resolve("${operation.worktreeId}.json"))
                        completed("The work tree was removed before the server restarted.")
                    }
                }
                else -> interrupted("Interrupted by a server restart.")
            }
        } catch (_: Exception) {
            recovery("STATE_UNKNOWN", "Interrupted by a server restart and the repository state could not be read. Inspect it before a new request.")
        }
    }

    /**
     * A remote intent after a restart (#594). A fetch updates remote-tracking refs only after
     * admission. A namespace transition may have pruned obsolete conflicting refs before the
     * remaining CAS publication; an explicit retry refreshes that state. Partial packs are removed
     * and the fetch becomes `interrupted`. Registration changes complete when their record is present
     * (add) or absent (remove).
     */
    private fun reconcileSync(jobId: String, operation: GitOperationRecord, request: GitSyncRequest): GitOperationRecord {
        val directory = repositoryDirectory(jobId, operation.repositoryId)
        if (request.action !in GitSyncRequest.REMOTE) return reconcileIntegration(jobId, operation, request)
        val remotes = try { GitRemoteStore.list(directory, operation.repositoryId) } catch (_: Exception) { emptyList() }
        return when (request.action) {
            GitOperationAction.FETCH -> {
                try { GitTransfers.removePartialPacks(directory.resolve(GIT_DIR)) } catch (_: Exception) { }
                finish(operation, GitOperationState.INTERRUPTED, "INTERRUPTED",
                    "Interrupted by a server restart. Remote-tracking refs may have been updated or obsolete refs pruned; fetch again to refresh them.")
            }
            GitOperationAction.REMOTE_ADD -> if (remotes.any { it.name == request.parameters["name"] })
                finish(operation, GitOperationState.COMPLETED, null, "The remote was registered before the server restarted.")
                else finish(operation, GitOperationState.INTERRUPTED, "INTERRUPTED", "Interrupted by a server restart before the remote was registered.")
            GitOperationAction.REMOTE_REMOVE -> if (remotes.none { it.remoteId == request.parameters["remoteId"] })
                finish(operation, GitOperationState.COMPLETED, null, "The remote was removed before the server restarted.")
                else finish(operation, GitOperationState.INTERRUPTED, "INTERRUPTED",
                    "Interrupted by a server restart before the remote was removed. Some remote-tracking refs may already be gone.")
            else -> finish(operation, GitOperationState.INTERRUPTED, "INTERRUPTED", "Interrupted by a server restart.")
        }
    }

    /**
     * An integration after a restart (#596, #598). A merge whose state Git retained becomes
     * `recovery-required` so its conflicts can be resolved or aborted; one that never started is
     * `interrupted`; one whose commit exists is `completed`. Nothing is repeated or discarded.
     */
    private fun reconcileIntegration(jobId: String, operation: GitOperationRecord, request: GitSyncRequest): GitOperationRecord = try {
        val runner = requireRunner()
        val record = repositories(jobId).single { it.repositoryId == operation.repositoryId }
        val directory = repositoryDirectory(jobId, record.repositoryId)
        val commonDir = directory.resolve(GIT_DIR)
        val gitDir = if (operation.worktreeId == record.worktreeId) commonDir else commonDir.resolve("worktrees").resolve(operation.worktreeId)
        val workTree = if (operation.worktreeId == record.worktreeId) directory.resolve(WORK_TREE) else directory.resolve(LINKED_WORK_TREES).resolve(operation.worktreeId)
        val merging = GitIntegrations.mergeInProgress(gitDir)
        val head = GitRepositoryInspector.head(runner, gitDir, record.objectFormat).objectId
        when (request.action) {
            GitOperationAction.MERGE -> {
                val integration = GitIntegrations.record(directory, operation.worktreeId)?.takeIf { it.operationId == operation.operationId }
                when {
                    merging -> finish(operation, GitOperationState.RECOVERY_REQUIRED, "MERGE_IN_PROGRESS",
                        "The server restarted during the merge. Its state is retained: resolve and commit the conflicts, or abort the merge.")
                    integration == null || head == integration.headBefore -> {
                        finish(operation, GitOperationState.INTERRUPTED, "INTERRUPTED", "Interrupted by a server restart before the merge changed the branch.")
                    }
                    else -> {
                        finish(operation, GitOperationState.COMPLETED, null, "The merge finished before the server restarted. It is a new candidate until validated.", head)
                    }
                }
            }
            GitOperationAction.MERGE_ABORT -> if (merging) finish(operation, GitOperationState.INTERRUPTED, "INTERRUPTED",
                "Interrupted by a server restart before the merge was aborted; it is still in progress.")
                else finish(operation, GitOperationState.COMPLETED, null, "The merge was aborted before the server restarted.", head)
            GitOperationAction.CONFLICT_SAVE -> {
                val entry = GitIntegrations.conflicts(runner, gitDir, workTree)
                    .singleOrNull { it.path.fileId(operation.worktreeId) == request.parameters["fileId"] }
                val saved = entry?.path?.exact?.let { GitConflictFiles.observe(workTree, it).sha256 }
                // Side choices have no request content digest. Their unchanged conflict stages
                // retain the immutable blob selected for publication, without changing replay identity.
                val expected = when (request.parameters["resolution"]) {
                    "text" -> request.contentSha256
                    else -> {
                        val objectId = when (request.parameters["resolution"]) {
                            "ours" -> entry?.oursObjectId
                            "theirs" -> entry?.theirsObjectId
                            "base" -> entry?.baseObjectId
                            else -> null
                        }
                        objectId?.let { GitIntegrations.blobText(runner, commonDir, it) }?.let(GitStorage::sha256)
                    }
                }
                if (saved != null && saved == expected) finish(operation, GitOperationState.COMPLETED, null, "The resolution was saved before the server restarted.")
                else finish(operation, GitOperationState.INTERRUPTED, "INTERRUPTED", "Interrupted by a server restart; read the file again before saving.")
            }
            else -> finish(operation, GitOperationState.INTERRUPTED, "INTERRUPTED",
                "Interrupted by a server restart. The index may be partly updated; read the conflicts again.")
        }
    } catch (_: Exception) {
        finish(operation, GitOperationState.RECOVERY_REQUIRED, "STATE_UNKNOWN", "Interrupted by a server restart and the repository state could not be read.")
    }

    private fun encodeGuards(guards: GitGuards) = buildJsonObject {
        put("repositoryVersion", guards.repositoryVersion); put("worktreeVersion", guards.worktreeVersion)
        put("expectedHeadObjectId", guards.expectedHeadObjectId?.let(::JsonPrimitive) ?: JsonNull)
        put("expectedRefId", guards.expectedRefId?.let(::JsonPrimitive) ?: JsonNull)
        put("expectedRefObjectId", guards.expectedRefObjectId?.let(::JsonPrimitive) ?: JsonNull)
    }

    private fun decodeGuards(value: JsonObject) = GitGuards(value.text("repositoryVersion"), value.text("worktreeVersion"),
        value.nullableText("expectedHeadObjectId"), value.nullableText("expectedRefId"), value.nullableText("expectedRefObjectId"))

    private fun fileIds(request: JsonObject): List<String> = (request.getValue("fileIds") as kotlinx.serialization.json.JsonArray)
        .map { (it as JsonPrimitive).also { primitive -> require(primitive.isString) }.content }

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
                if (operation.state.terminal) { retireIntegration(operation); continue }
                if (operation.operationId in active) continue
                val staging = directory.resolve("staging").resolve(operation.operationId)
                if (operation.action.workspace) {
                    persist(directory, reconcileWorkspace(jobId, operation))
                    try { GitStorage.deleteTree(staging) } catch (_: Exception) { /* retained for inspection */ }
                    continue
                }
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
        if (operation.action.workspace && operation.state.terminal) crash(GitOperationCrashPoint.BEFORE_TERMINAL_PERSIST)
        GitStorage.replaceAtomically(operations.resolve("${operation.operationId}.json"), encode(operation).toByteArray())
        if (operation.action.workspace && operation.state.terminal) crash(GitOperationCrashPoint.AFTER_TERMINAL_PERSIST)
        retireIntegration(operation)
    }

    /** Evidence is retired only after its terminal operation is durable, including during recovery.
     * A restart retries this idempotent cleanup for already-terminal records as well. */
    private fun retireIntegration(operation: GitOperationRecord) {
        if (!(operation.state == GitOperationState.COMPLETED && operation.action in setOf(GitOperationAction.MERGE,
                GitOperationAction.MERGE_ABORT, GitOperationAction.COMMIT) ||
                operation.state == GitOperationState.INTERRUPTED && operation.action == GitOperationAction.MERGE)) return
        try {
            val directory = repositoryDirectory(operation.jobId, operation.repositoryId)
            val integration = GitIntegrations.record(directory, operation.worktreeId) ?: return
            // Never let an older completed merge retire the evidence of a newer integration.
            if (operation.action == GitOperationAction.MERGE && integration.operationId != operation.operationId) return
            // Wall clocks can coincide or move backwards. Only durable owner state proves that
            // a different terminal commit/abort may clean this evidence during the startup sweep.
            if (operations(operation.jobId).any { it.operationId == integration.operationId && !it.state.terminal }) return
            val record = repositories(operation.jobId).single { it.repositoryId == operation.repositoryId }
            val gitDir = directory.resolve(GIT_DIR).let { if (operation.worktreeId == record.worktreeId) it else it.resolve("worktrees").resolve(operation.worktreeId) }
            if (!GitIntegrations.mergeInProgress(gitDir)) GitIntegrations.delete(directory, operation.worktreeId)
        } catch (_: Exception) { /* Terminal state is durable; retry cleanup at the next restart. */ }
    }

    /**
     * Routine work-tree operations must not use up the job's record quota. When the next
     * admission would reach it, the oldest terminal work-tree records are retired so that the
     * newest `MAX_OPERATIONS - 1` stay replayable by their keys. Initialization and import
     * records are never retired. A retired key that is sent again is admitted as a new request,
     * and its reviewed guards then refuse it unless the state it was reviewed against still
     * holds.
     */
    private fun retireTerminalWorkspace(jobId: String, operations: List<GitOperationRecord>): List<GitOperationRecord> {
        val excess = operations.size - (MAX_OPERATIONS - 1)
        if (excess <= 0) return operations
        val directory = root.resolve(jobId).resolve("git").resolve("operations")
        // A recovery-required record awaits an operator and keeps its staging tree; it is never retired.
        val retired = operations.filter { it.action.workspace && it.state.terminal && it.state != GitOperationState.RECOVERY_REQUIRED }
            .sortedBy { it.createdAt }.take(excess)
        retired.forEach { Files.deleteIfExists(directory.resolve("${it.operationId}.json")) }
        return operations - retired.toSet()
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
            is GitStageRequest -> buildJsonObject {
                put("worktreeId", request.worktreeId); put("guards", encodeGuards(request.guards))
                put("fileIds", kotlinx.serialization.json.JsonArray(request.fileIds.map(::JsonPrimitive)))
            }
            is GitCommitRequest -> buildJsonObject {
                put("worktreeId", request.worktreeId); put("guards", encodeGuards(request.guards))
                put("fileIds", kotlinx.serialization.json.JsonArray(request.fileIds.map(::JsonPrimitive)))
                put("messageSha256", GitStorage.sha256(request.message))
                if (request.reviewedMergeIndex) put("reviewedMergeIndex", true)
            }
            is GitRefRequest -> buildJsonObject {
                put("worktreeId", request.worktreeId); put("guards", encodeGuards(request.guards))
                put("name", request.name?.let(::JsonPrimitive) ?: JsonNull); put("refId", request.refId?.let(::JsonPrimitive) ?: JsonNull)
                put("objectId", request.objectId?.let(::JsonPrimitive) ?: JsonNull); put("runId", request.runId?.let(::JsonPrimitive) ?: JsonNull)
            }
            is GitRetainedCommit -> buildJsonObject {
                put("worktreeId", request.worktreeId); put("guards", encodeGuards(request.guards))
                put("fileIds", kotlinx.serialization.json.JsonArray(request.fileIds.map(::JsonPrimitive)))
                put("messageSha256", request.messageSha256)
                if (request.reviewedMergeIndex) put("reviewedMergeIndex", true)
            }
            is GitSyncRequest -> buildJsonObject {
                put("worktreeId", request.worktreeId); put("guards", encodeGuards(request.guards))
                put("parameters", buildJsonObject { request.parameters.toSortedMap().forEach { (key, value) -> put(key, value?.let(::JsonPrimitive) ?: JsonNull) } })
                put("contentSha256", request.contentSha256?.let(::JsonPrimitive) ?: JsonNull)
            }
            is GitCloneRequest -> buildJsonObject {
                put("url", request.url); put("remoteName", request.remoteName); put("branch", request.branch?.let(::JsonPrimitive) ?: JsonNull)
            }
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
                GitOperationAction.STAGE, GitOperationAction.UNSTAGE -> GitStageRequest(request.text("worktreeId"),
                    decodeGuards(request.getValue("guards").jsonObject), fileIds(request), action == GitOperationAction.STAGE)
                // The message itself is kept only for execution; a retained record proves its digest.
                GitOperationAction.BRANCH_CREATE, GitOperationAction.SWITCH, GitOperationAction.BRANCH_DELETE, GitOperationAction.TAG,
                GitOperationAction.WORKTREE_ADD, GitOperationAction.WORKTREE_REMOVE -> GitRefRequest(action, request.text("worktreeId"),
                    decodeGuards(request.getValue("guards").jsonObject), request.nullableText("name"), request.nullableText("refId"),
                    request.nullableText("objectId"), request.nullableText("runId"))
                GitOperationAction.COMMIT -> GitRetainedCommit(request.text("worktreeId"), decodeGuards(request.getValue("guards").jsonObject),
                    fileIds(request), request.text("messageSha256"), request["reviewedMergeIndex"].let {
                        require(it == null || it == JsonPrimitive(true)); it != null
                    })
                GitOperationAction.CLONE -> GitCloneRequest(request.text("url"), request.text("remoteName"), request.nullableText("branch"))
                else -> {
                    require(action in GitSyncRequest.ACTIONS)
                    val parameters = request.getValue("parameters").jsonObject.mapValues { (_, value) ->
                        if (value == JsonNull) null else (value as JsonPrimitive).also { require(it.isString) }.content
                    }
                    GitSyncRequest(action, request.text("worktreeId"), decodeGuards(request.getValue("guards").jsonObject),
                        parameters + listOfNotNull(request.nullableText("contentSha256")?.let { "contentSha256" to it }))
                }
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
            value.text("operationId").also { require(it.matches(ID)) }, value.text("origin").also { require(it in setOf("initialized", "imported", "cloned")) },
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
        GitOperationAction.STAGE -> "Staged exactly the selected files. Nothing was committed."
        GitOperationAction.UNSTAGE -> "Unstaged exactly the selected files. Work-tree contents were not changed."
        GitOperationAction.COMMIT -> "Committed exactly the reviewed staged files. A commit records source state; it is not validation or acceptance."
        GitOperationAction.BRANCH_CREATE -> "Created the branch at the reviewed commit. Nothing was checked out."
        GitOperationAction.SWITCH -> "Switched the work tree. No changes were discarded or stashed."
        GitOperationAction.BRANCH_DELETE -> "Deleted the branch; all of its commits remain reachable from other refs."
        GitOperationAction.TAG -> "Created the tag at the reviewed commit. Existing tags are never overwritten."
        GitOperationAction.WORKTREE_ADD -> "Created a linked work tree at the reviewed commit."
        GitOperationAction.WORKTREE_REMOVE -> "Removed the clean linked work tree; its commits remain reachable."
        GitOperationAction.CLONE -> "Cloned into an isolated managed repository. Hooks, filters, submodules and LFS stay inert; nothing was validated."
        GitOperationAction.REMOTE_ADD -> "Registered the remote. Nothing was fetched or pushed."
        GitOperationAction.REMOTE_REMOVE -> "Removed the remote and its remote-tracking refs."
        GitOperationAction.FETCH -> "Fetched remote-tracking refs only. Nothing was merged or checked out."
        GitOperationAction.MERGE -> "Integrated the reviewed remote-tracking commit. The result is a new candidate until validated."
        GitOperationAction.MERGE_ABORT -> "Aborted the merge."
        GitOperationAction.CONFLICT_SAVE -> "Saved the resolution; it is not staged."
        GitOperationAction.CONFLICT_COMPLETE -> "Staged the reviewed resolutions. Commit explicitly to finish."
    }

    internal companion object {
        const val GIT_DIR = "repository.git"
        const val WORK_TREE = "worktree"
        const val LINKED_WORK_TREES = "worktrees"
        const val WORKTREE_RECORDS = "worktree-records"
        const val FETCH_STATE = "fetch-state"
        const val RECORD = "repository.json"
        const val MAX_OPERATIONS = 64
        const val MAX_LISTED_OPERATIONS = 20
        const val MAX_QUEUED = 8
        const val MAX_RECORD_BYTES = 16 * 1024
        val JOB_ID = Regex("[a-f0-9]{32}")
        val ID = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
        const val QUEUED_MESSAGE = "Queued. The repository becomes visible only after it is completely prepared."
        const val RUNNING_MESSAGE = "Preparing the repository in private staging."
        const val QUEUED_WORKSPACE_MESSAGE = "Queued. Guards are rechecked immediately before Git runs."
        const val RUNNING_WORKSPACE_MESSAGE = "Rechecking the reviewed state and applying the change."
        const val INTERRUPTED_MESSAGE = "Stopped before publication. No repository was published; start a new request explicitly."
        const val RESTART_MESSAGE = "Interrupted by a server restart before publication. No repository was published and the source snapshot was not changed. Start a new request explicitly."
        const val STAGING_RETAINED_MESSAGE = "Interrupted staging could not be removed. Preserve storage and inspect it before retrying."
    }
}
