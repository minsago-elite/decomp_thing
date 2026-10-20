package decompengine.web

import decompengine.jobs.Job
import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAttempt
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowRunState
import decompengine.jobs.WorkflowStoreException
import decompengine.jobs.WorkflowTerminalReason
import decompengine.jobs.WorkflowTransition
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Legacy adapters retain their legacy provenance; they are not durable workflow registrations. */
enum class WebWorkflow { EXPLORE, RECONSTRUCT }
sealed interface WebWorkflowAdmission {
    data class Started(val jobId: String) : WebWorkflowAdmission
    data object AlreadyRunning : WebWorkflowAdmission
    data object Unavailable : WebWorkflowAdmission
}

/** Both upload adapters must retain uncertainty before returning a recovery-required failure. */
internal fun <T> withWebUploadPublicationOutcome(
    retainUncertain: (WebJobDiagnostic) -> Unit,
    publish: () -> T,
): T = try {
    publish()
} catch (failure: Exception) {
    val jobId = when (failure) {
        is decompengine.jobs.UploadPublicationUncertainException -> failure.jobId
        is decompengine.jobs.UploadPublicationUncertain -> failure.jobId
        else -> throw failure
    }
    retainUncertain(WebJobDiagnostic(jobId, "RECOVERY_REQUIRED",
        "An upload may have been published. Reopen storage before admitting more work; do not retry blindly."))
    throw WebJobServiceException("RECOVERY_REQUIRED", "Upload publication is uncertain. Inspect storage before retrying.", failure)
}

/** Terminal publication and shutdown signalling share this fence, independently of cleanup locks. */
internal class WebCompletionPublicationFence(private val publishShutdown: () -> Unit) {
    private val mutex = ReentrantLock(true)
    fun signalShutdown() = mutex.withLock { publishShutdown() }
    fun <T> publishCompletion(publish: () -> T): T = mutex.withLock { publish() }
}

internal fun selectWebLegacyCompletion(status: String, message: String, stopped: Boolean): Pair<String, String> =
    if (status == "complete" && stopped) "failed" to "Server stopped before the operation reported completion"
    else status to message

/**
 * Shared service boundary. HTTP adapters authorize before calling it. Initialization is explicit,
 * runs before requests, and recovers only an existing root; reads never acquire ownership or recover.
 * Production durable adapters remain unregistered until their limits and capabilities are qualified.
 */
class WebJobService(
    private val store: JobStore,
    private val analyzer: JobAnalyzer,
    private val reconstructor: JobReconstructor,
    executor: Executor? = null,
    workers: Int = 2,
    queueCapacity: Int = 32,
    durableAdapters: List<DurableWebWorkflowAdapter> = emptyList(),
    private val attemptStoreFactory: (Path) -> WorkflowAttemptStore = { WorkflowAttemptStore.open(it) },
    private val shutdownTimeoutMs: Long = 1000,
    maximumRetainedStorageBytes: Long = WebUploadStorage.DEFAULT_MAXIMUM_BYTES,
    private val failureDiagnostic: (Exception) -> String = { "Workflow failed; inspect its available diagnostics before retrying" },
    progressRetentionIntervalMs: Long? = null,
) : AutoCloseable {
    private data class Registration(val adapter: DurableWebWorkflowAdapter, val limits: decompengine.jobs.WorkflowExecutionLimits,
        val harnessCapabilityId: String?)
    private val registrations = durableAdapters.associate { it.workflow to Registration(it, it.limits, it.harnessCapabilityId) }.also {
        require(it.size == durableAdapters.size) { "duplicate durable workflow registration" }
        require(shutdownTimeoutMs in 0..5000) { "invalid workflow shutdown deadline" }
        require(it.values.all { row -> row.harnessCapabilityId == null || row.harnessCapabilityId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")) }) {
            "invalid registered harness capability identity"
        }
    }
    private val maximumInFlight = run {
        require(workers in 1..2 && queueCapacity in 1..32) { "invalid workflow worker or queue bound" }
        workers + queueCapacity
    }
    private val ownedExecutor = if (executor == null) {
        require(workers in 1..2 && queueCapacity in 1..32)
        ThreadPoolExecutor(workers, workers, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(queueCapacity), { task ->
            Thread(task, "decomp-web-workflow").apply { isDaemon = true }
        }, ThreadPoolExecutor.AbortPolicy())
    } else null
    private val configuredQueueCapacity = queueCapacity
    private val workflowExecutor = executor ?: ownedExecutor!!
    private val active = mutableMapOf<String, OwnedTask>()
    private val uploads = mutableMapOf<Thread, CountDownLatch>()
    private val uploadStorage = WebUploadStorage(store.storageRoot, maximumRetainedStorageBytes)

    /** Internal seam for deterministic publication-failure fixtures; production code never reassigns this. */
    internal var uploadPublisher = decompengine.jobs.StagedJobUpload(store.storageRoot)
    private val publicationFailures = mutableMapOf<String, WebJobDiagnostic>()
    private var attempts: WorkflowAttemptStore? = null
    @Volatile private var initialized = false
    @Volatile private var stopping = false
    @Volatile private var closed = false
    private val completionPublication = WebCompletionPublicationFence { stopping = true }
    private val retentionJobs = java.util.ArrayDeque<String>()
    private val retentionRuns = java.util.ArrayDeque<Pair<String, String>>()
    private var retentionCycleActive = false
    @Volatile private var retentionStatus = WebProgressRetentionStatus(progressRetentionIntervalMs != null, 0, 0, 0, null)
    private val retentionWorker = progressRetentionIntervalMs?.let { interval ->
        WebProgressRetentionWorker(interval, ::runProgressRetentionBatch) {
            synchronized(this) { releaseIfQuiescent() }
        }
    }

    // Immutable observation only: a bootstrap read must not wait for storage work.
    internal fun progressRetentionStatus(): WebProgressRetentionStatus = retentionStatus

    /** At most 32 discovery/attempt units per tick. Release the service monitor between each unit. */
    private fun runProgressRetentionBatch() {
        repeat(32) {
            val continueBatch = synchronized(this) {
                if (!initialized || closed || stopping || attempts == null || publicationFailures.isNotEmpty() || uploads.isNotEmpty())
                    return@synchronized false
                try {
                    if (retentionRuns.isNotEmpty()) {
                        val (jobId, runId) = retentionRuns.removeFirst()
                        val result = expireProgressJournal(jobId, runId, protectedFromRetention = false)
                        retentionStatus = retentionStatus.copy(examined = incrementRetentionCount(retentionStatus.examined),
                            expired = if (result == decompengine.jobs.ProgressRetentionResult.EXPIRED) incrementRetentionCount(retentionStatus.expired) else retentionStatus.expired)
                        true
                    } else {
                        if (retentionJobs.isEmpty()) {
                            if (retentionCycleActive) { retentionCycleActive = false; return@synchronized false }
                            retentionJobs.addAll(store.jobIds())
                            retentionCycleActive = true
                            if (retentionJobs.isEmpty()) { retentionCycleActive = false; return@synchronized false }
                        }
                        val jobId = retentionJobs.removeFirst()
                        val inspection = inspectStoredJob(attempts!!, jobId)
                        if (inspection is WorkflowJobInspection.Available) {
                            // One bounded attempt inventory at a time; each decision is revalidated on execution.
                            retentionRuns.addAll(inspection.snapshot.attempts.map { jobId to it.runId })
                        } else recordRetentionFailure("JOB_RECORD_UNAVAILABLE")
                        true
                    }
                } catch (failure: Exception) {
                    val code = when (failure) {
                        is WebJobServiceException -> failure.code
                        is WorkflowStoreException -> failure.code
                        else -> "RETENTION_UNAVAILABLE"
                    }
                    recordRetentionFailure(code)
                    retentionCycleActive // A failed root inventory must wait for the next tick.
                }
            }
            if (!continueBatch || Thread.currentThread().isInterrupted) return
        }
    }
    private fun incrementRetentionCount(value: Long) = if (value == Long.MAX_VALUE) value else value + 1
    private fun recordRetentionFailure(code: String) {
        retentionStatus = retentionStatus.copy(failures = incrementRetentionCount(retentionStatus.failures),
            lastFailureCode = code.takeIf { it.matches(Regex("[A-Z][A-Z0-9_]{0,63}")) } ?: "RETENTION_UNAVAILABLE")
    }

    /** Aggregate executor telemetry only; independent readings are approximate, never admission authority.
     * Passive sampling does not acquire the monitor used for storage and workflow transitions.
     */
    fun schedulerSnapshot(): WebSchedulerSnapshot {
        requireInitializedRead()
        val sampledAt = java.time.Instant.now()
        val pool = ownedExecutor ?: return WebSchedulerSnapshot.Unavailable(sampledAt)
        return WebSchedulerSnapshot.Available(sampledAt, stopping, pool.activeCount, pool.maximumPoolSize,
            pool.queue.size, configuredQueueCapacity)
    }

    /** Serialize with terminal publication before acquiring the service, executor or listener cleanup locks. */
    internal fun signalShutdown() = completionPublication.signalShutdown()

    @Synchronized fun beginShutdown() { completionPublication.signalShutdown(); retentionWorker?.stop() }

    /** True when the service is closed and no workflows or uploads remain; ownership-handoff evidence. */
    internal fun isIdle(): Boolean = synchronized(this) { closed && active.isEmpty() && uploads.isEmpty() && retentionWorker?.isIdle != false }

    /** Invoked whenever quiescence is (re)established after close; used to release outer ownership. */
    internal var onQuiescent: (() -> Unit)? = null

    @Synchronized
    fun initializeExistingStorage() = initializeExistingStorage { false }

    @Synchronized
    internal fun initializeExistingStorage(cancellation: () -> Boolean) {
        check(!closed && active.isEmpty()) { "Storage initialization requires an idle service" }
        if (initialized) return
        fun checkCancellation() {
            if (stopping || Thread.currentThread().isInterrupted || cancellation()) throw decompengine.jobs.WorkflowStoreException(
                "RECOVERY_CANCELLED", "Startup recovery was cancelled; preserve any already reconciled storage.", attempts != null)
        }
        checkCancellation()
        if (Files.exists(store.storageRoot, NOFOLLOW_LINKS)) acquireAndRecover(cancellation)
        checkCancellation()
        initialized = true
        if (!stopping) retentionWorker?.start()
    }

    private fun acquireAndRecover(cancellation: () -> Boolean = { false }): WorkflowAttemptStore {
        attempts?.let { return it }
        if (stopping || Thread.currentThread().isInterrupted || cancellation()) throw decompengine.jobs.WorkflowStoreException(
            "RECOVERY_CANCELLED", "Startup recovery was cancelled before acquiring storage.")
        val acquired = attemptStoreFactory(store.storageRoot)
        try {
            acquired.recoverForStartup(cancellation = { stopping || cancellation() }) { check ->
                check()
                try {
                    store.prepareStorageDirectories()
                } catch (failure: Exception) {
                    throw WebJobServiceException("STORE_DURABILITY_UNAVAILABLE",
                        "Store directory durability could not be confirmed. Preserve stored data and verify filesystem support before retrying.", failure)
                }
                check()
                decompengine.jobs.UploadStagingRecovery.recover(store.storageRoot, check)
            }
            attempts = acquired
            return acquired
        } catch (failure: Throwable) {
            try { acquired.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            throw failure
        }
    }

    private fun writableStore(): WorkflowAttemptStore {
        if (closed || stopping) throw WebJobServiceException("SERVICE_STOPPED", "The job service is stopping.")
        requirePublicationAvailable()
        if (!initialized) initializeExistingStorage()
        return acquireAndRecover()
    }

    private fun requirePublicationAvailable() {
        if (publicationFailures.isNotEmpty()) throw WebJobServiceException("RECOVERY_REQUIRED",
            "Workflow publication failed. Stop the service and reopen storage to reconcile before admitting more work.")
    }

    private fun inspectStoredJob(owner: WorkflowAttemptStore, jobId: String): WorkflowJobInspection {
        if (!jobId.matches(Regex("[0-9a-f]{32}"))) throw WebJobServiceException("JOB_NOT_FOUND", "The requested job is unavailable.")
        val result = try { owner.inspect(jobId) } catch (failure: WorkflowStoreException) {
            if (failure.code == "JOB_NOT_FOUND") throw WebJobServiceException("JOB_NOT_FOUND", "The requested job is unavailable.")
            throw failure
        }
        if (result is WorkflowJobInspection.Unavailable && result.diagnostic.code == "JOB_NOT_FOUND") {
            throw WebJobServiceException("JOB_NOT_FOUND", "The requested job is unavailable.")
        }
        return if (result is WorkflowJobInspection.Unavailable) {
            WorkflowJobInspection.Unavailable(result.jobId, publicWorkflowDiagnostic(result.diagnostic.code))
        } else result
    }

    private fun requireInitializedRead() {
        if (!initialized) throw WebJobServiceException("SERVICE_NOT_INITIALIZED", "Job storage must be initialized before serving reads.")
        if (closed) throw WebJobServiceException("SERVICE_STOPPED", "The job service is stopped.")
    }

    /** Bounded display-only inspection; never acquires ownership, replays work or removes files. */
    @Synchronized
    fun recoveryInventory(): decompengine.jobs.JobRecoveryInventory {
        requireInitializedRead()
        // Multipart writers release this monitor while their staging directories are live.
        // Keep upload admission excluded throughout the scan when there are no active writers.
        if (uploads.isNotEmpty()) throw WebJobServiceException("RECOVERY_INSPECTION_BUSY",
            "Recovery inspection is paused while uploads are in progress. Refresh after uploads finish.")
        return store.recoveryInventory()
    }

    @Synchronized
    fun inspect(jobId: String): WebJobInspection {
        requireInitializedRead()
        publicationFailures[jobId]?.let { return WebJobInspection.Unavailable(it) }
        if (!jobId.matches(Regex("[0-9a-f]{32}")) || attempts == null) return WebJobInspection.Unavailable(
            WebJobDiagnostic(jobId, "JOB_NOT_FOUND", "The requested job is unavailable."))
        return try {
            val inspected = attempts?.inspect(jobId)
            if (inspected is WorkflowJobInspection.Unavailable) return WebJobInspection.Unavailable(
                publicWebDiagnostic(jobId, inspected.diagnostic.code))
            val snapshot = (inspected as? WorkflowJobInspection.Available)?.snapshot
            val raw = store.get(jobId)
            requirePublicElfCategories(raw.metadata)
            if (snapshot != null && snapshot.attempts.isNotEmpty()) {
                require(snapshot.version.matches(Regex("version_[a-f0-9]{32}"))) { "Invalid stored workflow version" }
            }
            val latest = snapshot?.latestRun
            val legacyInterrupted = latest == null && snapshot?.legacy?.recoveredInterrupted == true &&
                raw.status in setOf("queued", "analyzing") && active[jobId] !is LegacyTask
            val job = when {
                latest != null -> raw.copy(status = legacyStatus(latest.state),
                    updatedAt = (latest.endedAt ?: latest.startedAt ?: latest.createdAt).toString(),
                    statusMessage = "Workflow ${latest.workflow.wireName}: ${latest.state.wireName}. Completion does not establish acceptance.")
                legacyInterrupted ->
                    raw.copy(status = "failed", statusMessage = "Historical legacy work was interrupted; its workflow identity is unknown.")
                else -> raw
            }
            val reports = latest?.let { context(jobId, it.runId) }
                ?: WebReportContext(store.storageRoot.resolve(jobId).resolve("reports"))
            WebJobInspection.Available(WebJobPresentation(job, snapshot, reports,
                (inspected as? WorkflowJobInspection.Available)?.diagnostics.orEmpty()
                    .map { publicWorkflowDiagnostic(it.code) }, legacyInterrupted))
        } catch (failure: WorkflowStoreException) {
            WebJobInspection.Unavailable(publicWebDiagnostic(jobId, failure.code))
        } catch (_: Exception) {
            WebJobInspection.Unavailable(publicWebDiagnostic(jobId, "JOB_RECORD_UNAVAILABLE"))
        }
    }

    @Synchronized
    fun listInspections(): List<WebJobInspection> {
        requireInitializedRead()
        return store.jobIds().map(::inspect).sortedWith(
            compareByDescending<WebJobInspection> { (it as? WebJobInspection.Available)?.presentation?.job?.createdAt.orEmpty() }
                .thenByDescending { when (it) {
                    is WebJobInspection.Available -> it.presentation.job.id
                    is WebJobInspection.Unavailable -> it.diagnostic.jobId
                } },
        )
    }

    /** Short per-record locks allow status reads between bounded snapshot collection steps. */
    internal fun collectionRecords(): Sequence<kotlinx.serialization.json.JsonObject> {
        val ids = synchronized(this) {
            requireInitializedRead()
            try { store.jobIds() } catch (_: decompengine.jobs.JobStoreException) {
                throw WebJobServiceException("LISTING_UNAVAILABLE", "Job identities cannot be listed within the storage limits. Inspect storage before retrying.")
            }
        }
        return ids.asSequence().map { webJob(presentation(it)) }
    }

    fun presentation(jobId: String): WebJobPresentation = when (val value = inspect(jobId)) {
        is WebJobInspection.Available -> value.presentation
        is WebJobInspection.Unavailable -> throw WebJobServiceException(value.diagnostic.code, value.diagnostic.message)
    }
    fun get(jobId: String): Job = presentation(jobId).job
    fun list(): List<Job> = listInspections().map { value -> when (value) {
        is WebJobInspection.Available -> value.presentation.job
        is WebJobInspection.Unavailable -> throw WebJobServiceException(value.diagnostic.code, value.diagnostic.message)
    } }

    @Synchronized
    fun inspectDurableJob(jobId: String): WorkflowJobInspection {
        requireInitializedRead()
        publicationFailures[jobId]?.let { return WorkflowJobInspection.Unavailable(jobId,
            decompengine.jobs.WorkflowStoreDiagnostic(it.code, it.message)) }
        return attempts?.let { inspectStoredJob(it, jobId) } ?: throw WebJobServiceException("JOB_NOT_FOUND", "The requested job is unavailable.")
    }

    @Synchronized
    fun getAttempt(jobId: String, runId: String): WorkflowAttempt {
        val available = when (val inspected = inspectDurableJob(jobId)) {
            is WorkflowJobInspection.Available -> inspected
            is WorkflowJobInspection.Unavailable -> throw WebJobServiceException(inspected.diagnostic.code, inspected.diagnostic.message)
        }
        return available.snapshot.attempts.singleOrNull { it.runId == runId }
            ?: throw WebJobServiceException("RUN_NOT_FOUND", "The requested attempt does not belong to this job.")
    }

    private fun context(jobId: String, runId: String): WebReportContext =
        WebReportContext(store.runReportsDirectory(jobId, runId), "reports/runs/$runId", runId)

    @Synchronized
    fun reportContext(jobId: String, runId: String? = null): WebReportContext {
        if (runId == null) return presentation(jobId).reports
        getAttempt(jobId, runId)
        return context(jobId, runId)
    }

    @Synchronized
    internal fun listArtifactSummaries(jobId: String, runId: String? = null): List<WebArtifactSummary> =
        listLegacyArtifactSummaries(reportContext(jobId, runId))

    @Synchronized
    internal fun listArtifactSummaries(jobId: String, runId: String?,
        recordedRepair: decompengine.repair.RepairHistoryReadResult?): List<WebArtifactSummary> =
        listLegacyArtifactSummaries(reportContext(jobId, runId), recordedRepair)

    @Synchronized
    internal fun listArtifactSummaries(jobId: String, runId: String?,
        recordedRepair: decompengine.repair.RepairHistoryReadResult?,
        page: decompengine.repair.RepairRecordedHistoryPage?): List<WebArtifactSummary> =
        listLegacyArtifactSummaries(reportContext(jobId, runId), recordedRepair, page)

    /** Authorize the selected durable job/run before the fixed retained canonical read. */
    @Synchronized
    internal fun readRecordedRepairHistory(jobId: String, runId: String? = null): decompengine.repair.RepairHistoryReadResult {
        requireInitializedRead()
        val selected = reportContext(jobId, runId)
        return store.readRecordedRepairHistory(jobId, selected.runId)
    }

    /** Shared fixed-path journal read for both HTTP adapters; absence is not empty history. */
    @Synchronized
    internal fun readProgressJournal(jobId: String, runId: String? = null): ByteArray {
        val context = reportContext(jobId, runId)
        return try {
            readArtifact(jobId, "${context.artifactPrefix}/${decompengine.jobs.AgentProgressJournal.FILE_NAME}",
                decompengine.jobs.AgentProgressJournal.MAXIMUM_READ_BYTES.toLong()).bytes
        } catch (_: Exception) {
            throw WebJobServiceException("PROGRESS_UNAVAILABLE",
                "The retained progress journal is unavailable. Missing data does not establish an empty history.")
        }
    }

    /** Hold durable run state stable across the checked atomic journal read, not HTTP delivery. */
    @Synchronized
    internal fun readProgressSnapshot(jobId: String, runId: String): Pair<WorkflowAttempt, ByteArray> {
        getAttempt(jobId, runId) // Enforce initialization and publication-failure admission first.
        val owner = attempts ?: throw WebJobServiceException("JOB_NOT_FOUND", "The requested job is unavailable.")
        return try {
            owner.withAttemptSnapshot(jobId, runId) { attempt ->
                attempt to readProgressJournal(jobId, attempt.runId)
            }
        } catch (failure: WorkflowStoreException) {
            throw WebJobServiceException(failure.code, "The requested progress snapshot is unavailable.")
        }
    }

    /** Explicit maintenance, serialized with bounded artifact capture and service shutdown.
     * Durable progress pins are enforced by the store; callers keep any additional protection
     * decision (such as read leases or broader job policy) stable through this call.
     * No request handler or automatic scheduler invokes this until that policy is integrated.
     */
    @Synchronized
    internal fun expireProgressJournal(jobId: String, runId: String, protectedFromRetention: Boolean,
        retention: java.time.Duration = decompengine.jobs.AgentProgressJournalRetention.DEFAULT_TERMINAL_RETENTION,
    ): decompengine.jobs.ProgressRetentionResult {
        val owner = writableStore()
        getAttempt(jobId, runId)
        // Terminal metadata can precede worker exit; keep all artifacts until work really releases.
        if (protectedFromRetention || active.containsKey(jobId) || uploads.isNotEmpty())
            return decompengine.jobs.ProgressRetentionResult.RETAINED
        return try { owner.expireProgressJournal(jobId, runId, protectedFromRetention = false, retention = retention) }
        catch (failure: WorkflowStoreException) {
            throw WebJobServiceException(failure.code,
                "Progress retention did not finish. Preserve its journal and pending retention file, then retry maintenance with storage ownership.", failure)
        }
    }

    /** Internal command boundary. Coordinate policy publication with the owned task's version. */
    @Synchronized
    internal fun setProgressRetentionPinned(jobId: String, runId: String, expectedRunVersion: String,
        pinned: Boolean, actor: decompengine.jobs.WorkflowPinActor = decompengine.jobs.WorkflowPinActor.INTERNAL): WorkflowAttempt =
        coordinatePinPublication(jobId, runId, { owner -> owner.setProgressRetentionPinned(jobId, runId, expectedRunVersion, pinned, actor).attempt }, { it })

    @Synchronized
    internal fun requestProgressRetentionPinned(jobId: String, runId: String, expectedRunVersion: String,
        pinned: Boolean, actor: decompengine.jobs.WorkflowPinActor, requestKey: String): decompengine.jobs.WorkflowPinRequestResult =
        coordinatePinPublication(jobId, runId, { owner -> owner.requestProgressRetentionPinned(jobId, runId, expectedRunVersion, pinned, actor, requestKey) }, { it.attempt })

    /** Called only under the service monitor. A replay's original response version must never
     * replace the current version used by a queued/running task's next lifecycle transition.
     */
    private fun <T> coordinatePinPublication(jobId: String, runId: String, command: (WorkflowAttemptStore) -> T,
        currentAttempt: (T) -> WorkflowAttempt): T {
        val owner = writableStore()
        getAttempt(jobId, runId)
        val task = (active[jobId] as? DurableTask)?.takeIf { it.attempt.runId == runId }
        return try {
            command(owner).also { result -> task?.attempt = currentAttempt(result) }
        } catch (failure: Throwable) {
            if (failure is WorkflowStoreException && !failure.outcomeUnknown) {
                throw WebJobServiceException(failure.code, "The progress retention pin request was not applied. Refresh the attempt before retrying.", failure)
            }
            val diagnostic = WebJobDiagnostic(jobId, "RECOVERY_REQUIRED",
                "Retention pin publication is uncertain. Reopen storage before making further changes.")
            publicationFailures[jobId] = diagnostic
            val unavailable = WebJobServiceException(diagnostic.code, diagnostic.message, failure)
            task?.failPublication(unavailable)
            if (failure !is Exception) throw failure
            throw unavailable
        }
    }

    @Synchronized
    fun resolveArtifact(jobId: String, relativePath: String): Path {
        requireInitializedRead()
        val segments = canonicalReportSegments(relativePath)
        if (segments[1] == "runs") {
            getAttempt(jobId, segments[2])
            return store.resolveRunArtifact(jobId, segments[2], segments.drop(3).joinToString("/"))
        }
        presentation(jobId) // Validate the record before resolving an explicitly legacy artifact.
        return store.resolveArtifact(jobId, relativePath)
    }

    /** Validate the report namespace and attempt ownership before a bounded retained-descriptor read. */
    @Synchronized
    internal fun readArtifact(jobId: String, relativePath: String, maximumBytes: Long): decompengine.repair.StableRegularFile {
        requireInitializedRead()
        val segments = canonicalReportSegments(relativePath)
        if (segments[1] == "runs") getAttempt(jobId, segments[2]) else presentation(jobId)
        return store.readArtifact(jobId, relativePath, maximumBytes)
    }

    @Synchronized
    fun upload(filename: String, content: ByteArray): Job {
        writableStore()
        if (uploads.isNotEmpty()) throw WebJobServiceException("UPLOAD_CAPACITY", "Upload storage is reserved by another transfer.")
        return publishUpload { store.createFromUpload(filename, content) }
    }

    private fun <T> publishUpload(publish: () -> T): T = withWebUploadPublicationOutcome(
        retainUncertain = { diagnostic -> synchronized(this) { publicationFailures[diagnostic.jobId] = diagnostic } },
        publish = publish,
    )

    /** Multipart bytes are copied outside the service monitor; publication retains root ownership through completion. */
    fun uploadMultipart(input: java.io.InputStream, contentType: String): Job =
        uploadMultipartReceipt(input, contentType).job

    /** Receipt-aware operation used by authenticated HTTP capabilities and idempotent uploads. */
    internal fun uploadMultipartReceipt(input: java.io.InputStream, contentType: String, idempotencyKey: String? = null, progress: WebUploadProgress.Transfer? = null): decompengine.jobs.PublishedJobUpload {
        val worker = Thread.currentThread()
        val finished = synchronized(this) {
            writableStore()
            if (uploads.size >= 2 || worker in uploads) throw WebJobServiceException("UPLOAD_CAPACITY", "Two uploads are already in progress. Retry later.")
            if (active.isNotEmpty()) throw WebJobServiceException("UPLOAD_CAPACITY", "Wait for active workflows before uploading.")
            CountDownLatch(1).also { uploads[worker] = it }
        }
        var reservation: AutoCloseable? = null
        try {
            reservation = uploadStorage.reserve()
            return publishUpload {
                uploadPublisher.publish(idempotencyKey) { sink ->
                    StreamingMultipartUpload.copy(input, contentType, sink, onReceived = { progress?.received(it) }).also { progress?.validating() }.filename
                }
            }
        } finally {
            reservation?.close()
            synchronized(this) { uploads.remove(worker); finished.countDown(); releaseIfQuiescent() }
        }
    }

    /** Compatibility startup entry point; recovery never rewrites historical job.json bytes. */
    fun recoverInterruptedJobs() = initializeExistingStorage()

    @Synchronized
    fun start(jobId: String, workflow: WebWorkflow): WebWorkflowAdmission {
        if (closed || stopping || uploads.isNotEmpty()) return WebWorkflowAdmission.Unavailable
        if (publicationFailures.isNotEmpty()) return WebWorkflowAdmission.Unavailable
        val owner = writableStore()
        val record = inspectStoredJob(owner, jobId) as? WorkflowJobInspection.Available ?: return WebWorkflowAdmission.Unavailable
        if (active.containsKey(jobId)) return WebWorkflowAdmission.AlreadyRunning
        // Legacy shared report locations cannot be used to write into a job with durable history.
        if (record.snapshot.attempts.isNotEmpty()) return WebWorkflowAdmission.Unavailable
        store.get(jobId)
        val task = LegacyTask(jobId, workflow)
        active[jobId] = task
        try {
            store.updateStatus(jobId, "queued", "Waiting for a legacy workflow worker; attempt provenance is unavailable")
            workflowExecutor.execute(task)
        } catch (_: RejectedExecutionException) {
            task.finish("failed", "Workflow capacity is unavailable; retry when a worker is available")
            return WebWorkflowAdmission.Unavailable
        } catch (failure: Throwable) {
            try { task.finish("failed", "Workflow could not be scheduled; retry when a worker is available") }
            catch (cleanup: Throwable) { if (cleanup !== failure) failure.addSuppressed(cleanup) }
            throw failure
        }
        return WebWorkflowAdmission.Started(jobId)
    }

    @Synchronized
    fun startDurable(jobId: String, expectedJobVersion: String, request: DurableWebWorkflowRequest): DurableWebWorkflowAdmission {
        if (uploads.isNotEmpty()) return DurableWebWorkflowAdmission.Unavailable("UPLOAD_CAPACITY")
        if (closed || stopping) return DurableWebWorkflowAdmission.Unavailable("SERVICE_STOPPED")
        if (publicationFailures.isNotEmpty()) return DurableWebWorkflowAdmission.Unavailable("RECOVERY_REQUIRED")
        val registration = registrations[request.workflow] ?: return DurableWebWorkflowAdmission.Unsupported(request.workflow)
        val owner = writableStore()
        val view = inspectStoredJob(owner, jobId) as? WorkflowJobInspection.Available
            ?: throw WebJobServiceException("JOB_RECORD_UNAVAILABLE", "The job record is unavailable; inspect its storage diagnostic.")
        val publicVersion = webJob(presentation(jobId)).getValue("version").jsonPrimitive.content
        if (publicVersion != expectedJobVersion) throw WorkflowStoreException("VERSION_CONFLICT", "The workflow version changed; refresh before starting another attempt.")
        if (active.containsKey(jobId) || view.snapshot.attempts.any { !it.state.terminal }) return DurableWebWorkflowAdmission.AlreadyRunning
        if (request.inputRevisionId != null && request.inputRevisionId != view.snapshot.acceptedRevision?.revisionId) {
            throw WebJobServiceException("INPUT_REVISION_UNAVAILABLE", "The requested input revision has no trusted publication reference for this job.")
        }
        val job = store.get(jobId)
        val queued = owner.create(jobId, view.snapshot.version,
            NewWorkflowAttempt(request.workflow, registration.limits, request.inputRevisionId,
                harnessCapabilityId = registration.harnessCapabilityId, previousRunId = request.previousRunId))
        val task = DurableTask(job, queued.attempt, registration.adapter)
        active[jobId] = task
        try { workflowExecutor.execute(task) }
        catch (_: RejectedExecutionException) {
            task.finish(WorkflowTransition.Finish(WorkflowRunState.FAILED, WorkflowTerminalReason.REFUSED))
            return DurableWebWorkflowAdmission.Unavailable("CAPACITY_UNAVAILABLE")
        } catch (failure: Throwable) {
            try { task.finish(WorkflowTransition.Finish(WorkflowRunState.FAILED, WorkflowTerminalReason.FAILED)) }
            catch (cleanup: Throwable) { if (cleanup !== failure) failure.addSuppressed(cleanup) }
            throw failure
        }
        return DurableWebWorkflowAdmission.Started(jobId, queued.attempt.runId)
    }

    /** Transport availability is not runtime readiness. Existing receipts remain replayable
     * after registrations are removed; default production registrations are still empty.
     * Called only after the shared HTTP mutation boundary authorizes the request.
     */
    @Synchronized
    internal fun durableStartRouteAvailable(jobId: String): Boolean {
        requireInitializedRead()
        requirePublicationAvailable()
        if (registrations.isNotEmpty()) return true
        val owner = attempts ?: return false
        return when (val view = inspectStoredJob(owner, jobId)) {
            is WorkflowJobInspection.Available -> view.snapshot.attempts.any { it.startReceipt != null }
            is WorkflowJobInspection.Unavailable -> throw WebJobServiceException(view.diagnostic.code, view.diagnostic.message)
        }
    }

    /** Caller must authorize the command before this service boundary. A replay is read-only;
     * a new command validates its public If-Match before using the separate storage CAS token.
     * Once admitted durably, a scheduler refusal retains that run rather than inviting re-execution.
     */
    @Synchronized
    internal fun requestDurableStart(jobId: String, expectedJobVersion: String, request: NewWorkflowAttempt,
        requestKey: String): DurableWebWorkflowStartResult {
        requireInitializedRead()
        requirePublicationAvailable()
        if (!jobId.matches(Regex("[0-9a-f]{32}"))) throw WebJobServiceException("JOB_NOT_FOUND", "The requested job is unavailable.")
        if (!requestKey.matches(Regex("[A-Za-z0-9_-]{16,128}"))) throw WebJobServiceException("INVALID_IDEMPOTENCY_KEY", "The workflow start key is invalid.")
        if (!expectedJobVersion.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")) || request.previousRunId != null) {
            throw WebJobServiceException("INVALID_WORKFLOW_REQUEST", "The workflow start request is invalid; explicit recovery requires a separate operation.")
        }
        val owner = attempts
        val replay = try { owner?.replayStart(jobId, request, requestKey, expectedJobVersion) }
        catch (failure: WorkflowStoreException) {
            throw WebJobServiceException(failure.code, "The recorded workflow start is unavailable. Refresh its state before retrying.", failure)
        }
        if (replay != null) return DurableWebWorkflowStartResult(replay.attempt, replayed = true)
        if (stopping) throw WebJobServiceException("SERVICE_STOPPED", "The job service is stopping.")
        if (uploads.isNotEmpty()) throw WebJobServiceException("UPLOAD_CAPACITY", "Upload capacity is currently in use.")
        val registration = registrations[request.workflow]
            ?: throw WebJobServiceException("WORKFLOW_UNAVAILABLE", "The requested workflow is unavailable.")
        if (request.limits != registration.limits) throw WebJobServiceException("WORKFLOW_LIMITS_UNAVAILABLE", "The requested workflow limits are unavailable.")
        if (request.harnessCapabilityId != registration.harnessCapabilityId) {
            throw WebJobServiceException("HARNESS_UNAVAILABLE", "The requested harness capability is unavailable.")
        }
        if (owner == null) throw WebJobServiceException("JOB_NOT_FOUND", "The requested job is unavailable.")
        val view = inspectStoredJob(owner, jobId) as? WorkflowJobInspection.Available
            ?: throw WebJobServiceException("JOB_RECORD_UNAVAILABLE", "The job record is unavailable; inspect its storage diagnostic.")
        val publicVersion = webJob(presentation(jobId)).getValue("version").jsonPrimitive.content
        if (publicVersion != expectedJobVersion) throw WebJobServiceException("VERSION_CONFLICT", "The job version changed. Refresh before starting new work.")
        if (active.containsKey(jobId) || view.snapshot.attempts.any { !it.state.terminal }) {
            throw WebJobServiceException("ACTIVE_RUN", "This job already has an active workflow attempt.")
        }
        // Admission uses owned task accounting, never sampled executor telemetry.
        if (active.size >= maximumInFlight) throw WebJobServiceException("CAPACITY_UNAVAILABLE", "Workflow capacity is currently full.")
        if (request.inputRevisionId != null && request.inputRevisionId != view.snapshot.acceptedRevision?.revisionId) {
            throw WebJobServiceException("INPUT_REVISION_UNAVAILABLE", "The selected input revision is unavailable for this job.")
        }
        val job = store.get(jobId)
        val admitted = publishStart(jobId) {
            owner.createIdempotent(jobId, view.snapshot.version, request, requestKey, expectedJobVersion)
        }
        if (admitted.replayed) return DurableWebWorkflowStartResult(admitted.attempt, replayed = true)
        val task = DurableTask(job, admitted.attempt, registration.adapter)
        active[jobId] = task
        try { workflowExecutor.execute(task) }
        catch (_: RejectedExecutionException) {
            task.finish(WorkflowTransition.Finish(WorkflowRunState.FAILED, WorkflowTerminalReason.REFUSED))
        } catch (failure: Throwable) {
            try { task.finish(WorkflowTransition.Finish(WorkflowRunState.FAILED, WorkflowTerminalReason.FAILED)) }
            catch (cleanup: Throwable) { if (cleanup !== failure) failure.addSuppressed(cleanup) }
            if (failure !is Exception) throw failure
            if (publicationFailures.isNotEmpty()) throw WebJobServiceException("RECOVERY_REQUIRED",
                "Workflow publication is uncertain. Reopen storage before starting more work.", failure)
            throw WebJobServiceException("SCHEDULING_FAILED", "Workflow scheduling did not finish. Read its retained attempt before retrying.", failure)
        }
        return DurableWebWorkflowStartResult(task.attempt, replayed = false)
    }

    private fun <T> publishStart(jobId: String, command: () -> T): T = try { command() }
    catch (failure: Throwable) {
        if (failure is WorkflowStoreException && !failure.outcomeUnknown) {
            throw WebJobServiceException(failure.code, "The workflow start was not recorded. Refresh its state before retrying.", failure)
        }
        val diagnostic = WebJobDiagnostic(jobId, "RECOVERY_REQUIRED", "Workflow publication is uncertain. Reopen storage before starting more work.")
        publicationFailures[jobId] = diagnostic
        if (failure !is Exception) throw failure
        throw WebJobServiceException(diagnostic.code, diagnostic.message, failure)
    }

    /** Internal command boundary; HTTP adapters must authorize and bind command replay separately. */
    @Synchronized
    internal fun cancelDurable(jobId: String, runId: String, expectedRunVersion: String): WorkflowAttempt {
        requireInitializedRead()
        if (stopping) throw WebJobServiceException("SERVICE_STOPPED", "The job service is stopping.")
        requirePublicationAvailable()
        val current = getAttempt(jobId, runId)
        if (current.version != expectedRunVersion)
            throw WebJobServiceException("VERSION_CONFLICT", "The attempt changed; refresh before requesting cancellation.")
        if (current.state.terminal) return current
        val task = (active[jobId] as? DurableTask)?.takeIf { it.attempt.runId == runId }
            ?: throw WebJobServiceException("RECOVERY_REQUIRED", "This attempt has no owned worker; reopen storage to reconcile it.")
        if (current.state == WorkflowRunState.CANCELLING) return current
        task.attempt = recordCancellation(jobId, task) {
            checkNotNull(attempts).transition(jobId, runId, expectedRunVersion, WorkflowTransition.RequestCancellation).attempt
        }
        signalCancellation(task)
        return task.attempt
    }

    /** Authorized adapters supply actor/key; a replay never restores an old task version or repeats a signal. */
    @Synchronized
    internal fun requestDurableCancellation(jobId: String, runId: String, expectedRunVersion: String,
        actor: decompengine.jobs.WorkflowCancellationActor, requestKey: String): decompengine.jobs.WorkflowCancellationRequestResult {
        requireInitializedRead()
        if (stopping) throw WebJobServiceException("SERVICE_STOPPED", "The job service is stopping.")
        requirePublicationAvailable()
        val current = getAttempt(jobId, runId)
        val task = (active[jobId] as? DurableTask)?.takeIf { it.attempt.runId == runId }
        if (!current.state.terminal && task == null)
            throw WebJobServiceException("RECOVERY_REQUIRED", "This attempt has no owned worker; reopen storage to reconcile it.")
        val result = recordCancellation(jobId, task) {
            checkNotNull(attempts).requestCancellation(jobId, runId, expectedRunVersion, actor, requestKey)
        }
        if (task != null) {
            task.attempt = result.attempt
            if (!task.attempt.state.terminal) signalCancellation(task)
        }
        return result.copy(attempt = task?.attempt ?: result.attempt)
    }

    private fun <T> recordCancellation(jobId: String, task: DurableTask?, operation: () -> T): T = try { operation() }
    catch (failure: Throwable) {
        if (failure is WorkflowStoreException && !failure.outcomeUnknown)
            throw WebJobServiceException(failure.code, "Cancellation was not recorded; refresh the attempt before retrying.", failure)
        val diagnostic = WebJobDiagnostic(jobId, "RECOVERY_REQUIRED", "Cancellation publication is uncertain. Reopen storage before making further changes.")
        publicationFailures[diagnostic.jobId] = diagnostic
        val unavailable = WebJobServiceException(diagnostic.code, diagnostic.message, failure)
        task?.failPublication(unavailable)
        if (failure !is Exception) throw failure
        throw unavailable
    }

    private fun signalCancellation(task: DurableTask) {
        if (task.cancellationRequested) return
        // Publication precedes signalling. Uncooperative running workers remain cancelling.
        task.cancellationRequested = true
        if (!task.started) {
            ownedExecutor?.remove(task)
            task.finish(WorkflowTransition.Finish(WorkflowRunState.CANCELLED, WorkflowTerminalReason.CANCELLED))
        } else task.worker?.interrupt()
    }

    override fun close() {
        var problem: Throwable? = null
        val running = synchronized(this) {
            if (closed) return
            completionPublication.signalShutdown()
            closed = true
            retentionWorker?.stop()
            ownedExecutor?.shutdownNow()
            active.values.filter { !it.started }.toList().forEach { task ->
                try { task.stopPending() } catch (failure: Throwable) {
                    if (problem == null) problem = failure else problem.addSuppressed(failure)
                }
            }
            val runningUploads = uploads.toList()
            runningUploads.forEach { (worker, _) -> worker.interrupt() }
            active.values.toList().also { tasks -> if (ownedExecutor == null) tasks.forEach { it.worker?.interrupt() }; releaseIfQuiescent() } to runningUploads
        }
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(shutdownTimeoutMs)
        running.first.forEach { task ->
            val remaining = deadline - System.nanoTime()
            if (remaining > 0 && task.worker !== Thread.currentThread()) task.finished.await(remaining, TimeUnit.NANOSECONDS)
        }
        running.second.forEach { (worker, finished) ->
            val remaining = deadline - System.nanoTime()
            if (remaining > 0 && worker !== Thread.currentThread()) finished.await(remaining, TimeUnit.NANOSECONDS)
        }
        retentionWorker?.awaitStopped(deadline - System.nanoTime())
        synchronized(this) {
            releaseIfQuiescent()
            if (active.isNotEmpty() || uploads.isNotEmpty() || retentionWorker?.isIdle == false) {
                val failure = WebJobServiceException("SHUTDOWN_INCOMPLETE", "Owned work has not stopped; storage ownership is retained until it exits.")
                if (problem == null) problem = failure else problem.addSuppressed(failure)
            }
        }
        problem?.let { throw it }
    }

    private fun releaseIfQuiescent() {
        if (closed && active.isEmpty() && uploads.isEmpty() && retentionWorker?.isIdle != false) {
            val restoreInterrupt = Thread.interrupted()
            try { attempts?.close(); attempts = null }
            finally { if (restoreInterrupt) Thread.currentThread().interrupt() }
            try { onQuiescent?.invoke() } catch (_: Exception) { }
        }
    }

    private abstract inner class OwnedTask(val jobId: String) : Runnable {
        var started = false
        var terminal = false
        var worker: Thread? = null
        val finished = CountDownLatch(1)
        abstract fun stopPending()
        fun release() {
            active.remove(jobId, this)
            finished.countDown()
            releaseIfQuiescent()
        }
    }

    private inner class LegacyTask(jobId: String, val workflow: WebWorkflow) : OwnedTask(jobId) {
        override fun run() {
            try {
                val job = synchronized(this@WebJobService) {
                    if (terminal || active[jobId] !== this) return
                    if (closed || stopping) { stopPending(); return }
                    started = true
                    worker = Thread.currentThread()
                    store.updateStatus(jobId, "analyzing", "Legacy ${workflow.name.lowercase()} workflow is running; attempt provenance is unavailable")
                }
                val reports = store.reportsDirectory(jobId)
                when (workflow) {
                    WebWorkflow.EXPLORE -> analyzer.analyze(job, reports)
                    WebWorkflow.RECONSTRUCT -> reconstructor.reconstruct(job, reports)
                }
                synchronized(this@WebJobService) {
                    if (closed || stopping || Thread.currentThread().isInterrupted) finish("failed", "Server stopped before the operation reported completion")
                    else finish("complete", "Legacy workflow completed; completion does not establish accepted revision evidence")
                }
            } catch (failure: Exception) {
                synchronized(this@WebJobService) { finish("failed", failureDiagnostic(failure)) }
            } finally { synchronized(this@WebJobService) { release() } }
        }
        override fun stopPending() = finish("failed", "Server stopped before the operation started")
        fun finish(status: String, message: String) = completionPublication.publishCompletion<Unit> {
            if (terminal || active[jobId] !== this) return@publishCompletion
            terminal = true
            val restoreInterrupt = Thread.interrupted()
            val selected = selectWebLegacyCompletion(status, message, closed || stopping || restoreInterrupt)
            try { store.updateStatus(jobId, selected.first, selected.second) }
            finally {
                if (restoreInterrupt) Thread.currentThread().interrupt()
                if (!started) release()
            }
        }
    }

    private inner class DurableTask(val job: Job, var attempt: WorkflowAttempt, val adapter: DurableWebWorkflowAdapter) : OwnedTask(job.id) {
        private var publicationFailure: WebJobServiceException? = null
        var cancellationRequested = false
        fun failPublication(failure: WebJobServiceException) {
            publicationFailure = failure
            if (!started) { terminal = true; release() }
        }
        override fun run() {
            try {
                val context = synchronized(this@WebJobService) {
                    if (terminal || active[jobId] !== this) return
                    if (closed || stopping) { stopPending(); return }
                    started = true
                    worker = Thread.currentThread()
                    attempt = checkNotNull(attempts).transition(jobId, attempt.runId, attempt.version, WorkflowTransition.Start).attempt
                    DurableWebWorkflowContext(job, attempt, store.runReportsDirectory(jobId, attempt.runId, create = true))
                }
                val outcome = adapter.execute(context)
                synchronized(this@WebJobService) {
                    if (closed || stopping || (Thread.currentThread().isInterrupted && !cancellationRequested)) finish(interrupted())
                    else finish(when (outcome) {
                        is DurableWebWorkflowOutcome.Completed -> WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED, outcome.candidate, outcome.usage)
                        is DurableWebWorkflowOutcome.Failed -> WorkflowTransition.Finish(WorkflowRunState.FAILED, outcome.reason, outcome.candidate, outcome.usage)
                    })
                }
            } catch (failure: Exception) {
                synchronized(this@WebJobService) {
                    publicationFailure?.let { throw it }
                    try { finish(if (closed || stopping || Thread.currentThread().isInterrupted || failure is InterruptedException) interrupted()
                        else WorkflowTransition.Finish(WorkflowRunState.FAILED, WorkflowTerminalReason.FAILED)) }
                    catch (cleanup: Exception) { if (cleanup !== failure) failure.addSuppressed(cleanup); throw failure }
                }
            } finally { synchronized(this@WebJobService) { release() } }
        }
        override fun stopPending() = finish(interrupted())
        fun finish(transition: WorkflowTransition.Finish) = completionPublication.publishCompletion<Unit> {
            publicationFailure?.let { throw it }
            if (terminal || active[jobId] !== this) return@publishCompletion
            // A cooperative worker can return with its interrupt flag set. Decide the outcome first,
            // then clear that flag only around the bounded atomic metadata operation and restore it.
            val restoreInterrupt = Thread.interrupted()
            val selected = if (closed || stopping || (restoreInterrupt && !cancellationRequested)) interrupted() else transition
            try {
                attempt = checkNotNull(attempts).transition(jobId, attempt.runId, attempt.version, selected).attempt
                terminal = true
            } catch (failure: Throwable) {
                val diagnostic = WebJobDiagnostic(jobId, "RECOVERY_REQUIRED",
                    "The workflow terminal outcome could not be published. Stop the service and reopen storage to reconcile; no further work is admitted.")
                publicationFailures[jobId] = diagnostic
                val unavailable = WebJobServiceException(diagnostic.code, diagnostic.message, failure)
                publicationFailure = unavailable
                if (failure !is Exception) throw failure
                throw unavailable
            } finally {
                if (restoreInterrupt) Thread.currentThread().interrupt()
                if (!started) release()
            }
        }
        private fun interrupted() = if (cancellationRequested && !closed && !stopping)
            WorkflowTransition.Finish(WorkflowRunState.CANCELLED, WorkflowTerminalReason.CANCELLED)
        else WorkflowTransition.Finish(WorkflowRunState.INTERRUPTED, WorkflowTerminalReason.PROCESS_INTERRUPTED)
    }

    private fun legacyStatus(state: WorkflowRunState): String = when (state) {
        WorkflowRunState.QUEUED -> "queued"
        WorkflowRunState.RUNNING, WorkflowRunState.CANCELLING -> "analyzing"
        WorkflowRunState.COMPLETED -> "complete"
        else -> "failed"
    }
}
