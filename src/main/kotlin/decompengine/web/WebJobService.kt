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

internal fun startupRecoveryLimitsForWeb(uiMode: WebUiMode): decompengine.jobs.WorkflowStartupRecoveryLimits =
    if (uiMode == WebUiMode.SPA) decompengine.jobs.WorkflowStartupRecoveryLimits.webLibrary()
    else decompengine.jobs.WorkflowStartupRecoveryLimits()

/** Keep the web refusal contract while retaining the coordinator's recovery context as a private cause. */
internal fun webStartupFailure(failure: Throwable): Throwable {
    val recovery = failure as? decompengine.jobs.WorkflowStoreException ?: return failure
    val maintenance = recovery.cause as? WebJobServiceException ?: return failure
    return if (recovery.code == "STARTUP_RECOVERY_INCOMPLETE" && maintenance.code == "STORE_DURABILITY_UNAVAILABLE")
        WebJobServiceException(maintenance.code, publicWebDiagnosticMessage(maintenance.code), recovery)
    else failure
}

internal data class WebDashboardRows(val jobs: List<Job>, val unavailable: List<WebJobDiagnostic>)

internal data class WebDashboardReadLimits(
    val maximumEntries: Int = 4096,
    val maximumReadBytes: Long = 64L * 1024 * 1024,
    val maximumRetainedTextUnits: Long = 16L * 1024 * 1024,
) {
    init {
        require(maximumEntries in 1..4096)
        require(maximumReadBytes in 1..64L * 1024 * 1024)
        require(maximumRetainedTextUnits in 1..16L * 1024 * 1024)
    }
}

/** Counts successful bytes; the first incomplete physical read latches refusal before any next read. */
internal class WebDashboardReadBudget(
    private val limits: WebDashboardReadLimits = WebDashboardReadLimits(),
    private val cancellation: () -> Boolean = { false },
) {
    var entries: Int = 0; private set
    var readBytes: Long = 0; private set
    var retainedRows: Int = 0; private set
    var retainedTextUnits: Long = 0; private set
    private var failureCode: String? = null
    private var failureCause: Exception? = null

    private fun refuse(code: String, cause: Exception? = null): Nothing {
        if (failureCode == null) { failureCode = code; failureCause = cause }
        val selected = checkNotNull(failureCode)
        throw WebJobServiceException(selected, when (selected) {
            "STORE_LIMIT" -> "The complete dashboard listing exceeds its configured inspection limits."
            "SERVICE_STOPPED" -> "The dashboard listing stopped before completing."
            else -> "The complete dashboard listing could not be inspected. Preserve storage before retrying."
        }, failureCause)
    }
    fun checkpoint() {
        failureCode?.let { refuse(it) }
        if (Thread.currentThread().isInterrupted || cancellation()) refuse("SERVICE_STOPPED")
    }
    fun entry() {
        checkpoint()
        if (entries >= limits.maximumEntries) refuse("STORE_LIMIT")
        entries++
    }
    fun read(maximum: Int, reader: (Long, () -> Unit) -> ByteArray): ByteArray {
        require(maximum > 0)
        checkpoint()
        val remaining = limits.maximumReadBytes - readBytes
        if (remaining == 0L) refuse("STORE_LIMIT")
        val allowance = minOf(maximum.toLong(), remaining)
        val bytes = try { reader(allowance, ::checkpoint) } catch (failure: Exception) {
            refuse(if (failure is decompengine.repair.RepairBudgetExceededException) "STORE_LIMIT" else "JOB_STORAGE_UNAVAILABLE", failure)
        }
        if (bytes.size.toLong() > allowance || bytes.size.toLong() > limits.maximumReadBytes - readBytes) refuse("STORE_LIMIT")
        readBytes += bytes.size.toLong()
        checkpoint()
        return bytes
    }
    fun retain(textUnits: Long) {
        checkpoint()
        require(textUnits >= 0)
        if (retainedRows >= limits.maximumEntries || textUnits > limits.maximumRetainedTextUnits - retainedTextUnits) refuse("STORE_LIMIT")
        retainedRows++
        retainedTextUnits += textUnits
    }
    fun incomplete(failure: Exception): Nothing = refuse("JOB_STORAGE_UNAVAILABLE", failure)
}

internal data class WebJobLibraryEntryLimits(val maximumEntries: Int = 10_512, val maximumJobs: Int = 10_000) {
    init {
        require(maximumEntries in 1..10_512 && maximumJobs in 1..10_000 && maximumJobs <= maximumEntries)
    }
}

/** The API retains its ten-thousand-job profile while counting every root entry before metadata reads. */
internal fun collectWebJobLibraryIds(
    rootEntries: Sequence<String>, checkpoint: () -> Unit,
    limits: WebJobLibraryEntryLimits = WebJobLibraryEntryLimits(),
): List<String> = try {
    checkpoint()
    var entries = 0
    val jobName = Regex("[0-9a-f]{32}")
    val ids = ArrayList<String>()
    for (name in rootEntries) {
        checkpoint()
        if (entries >= limits.maximumEntries) throw WebJobServiceException("STORE_LIMIT", "The job library exceeds its complete root-entry limit.")
        entries++
        if (jobName.matches(name)) {
            if (ids.size >= limits.maximumJobs) throw WebJobServiceException("STORE_LIMIT", "The job library exceeds its job-identity limit.")
            ids += name
        }
    }
    checkpoint()
    ids.sorted().also { checkpoint() }
} catch (failure: WebAccessDenied) { throw failure } catch (failure: WebJobServiceException) { throw failure }
catch (failure: Exception) {
    throw WebJobServiceException("JOB_STORAGE_UNAVAILABLE", "The complete job library could not be inspected. Preserve storage before retrying.", failure)
}

/** Preserve the caller's latched deadline even when a per-record catch runs around an interrupted read. */
internal fun readWebJobCollectionMetadata(
    budget: WebDashboardReadBudget, maximum: Int, progress: () -> Unit,
    reader: (Long, () -> Unit) -> ByteArray,
): ByteArray {
    progress()
    try {
        val bytes = budget.read(maximum) { allowance, check -> reader(allowance) { progress(); check() } }
        progress()
        return bytes
    } catch (failure: Exception) {
        progress()
        throw failure
    }
}

/** Full enumeration precedes reads; only compact rows survive each temporary workflow snapshot. */
internal fun collectWebDashboardRows(
    rootEntries: Sequence<String>, budget: WebDashboardReadBudget, inspect: (String) -> WebJobInspection,
): WebDashboardRows = try {
    budget.checkpoint()
    val jobName = Regex("[0-9a-f]{32}")
    val ids = ArrayList<String>()
    for (name in rootEntries) { budget.entry(); if (jobName.matches(name)) ids += name }
    val jobs = ArrayList<Job>()
    val unavailable = ArrayList<WebJobDiagnostic>()
    for (id in ids.sorted()) {
        budget.checkpoint()
        val row = inspect(id)
        budget.checkpoint() // An ordinary per-record catch cannot hide an incomplete physical read.
        when (row) {
            is WebJobInspection.Available -> {
                val job = row.presentation.job
                check(job.id == id) { "Dashboard job identity changed" }
                val metadata = job.metadata
                budget.retain(listOf(job.id, job.filename, job.status, job.createdAt, job.updatedAt,
                    job.statusMessage.orEmpty(), job.binaryPath.toString(), metadata.format, metadata.endianness,
                    metadata.osAbi, metadata.objectType, metadata.machine).sumOf { it.length.toLong() })
                jobs += job
            }
            is WebJobInspection.Unavailable -> {
                val diagnostic = row.diagnostic
                check(diagnostic.jobId == id) { "Dashboard diagnostic identity changed" }
                budget.retain(listOf(diagnostic.jobId, diagnostic.code, diagnostic.message).sumOf { it.length.toLong() })
                unavailable += diagnostic
            }
        }
    }
    budget.checkpoint()
    WebDashboardRows(jobs.sortedWith(compareByDescending<Job> { it.createdAt }.thenByDescending { it.id }),
        unavailable.sortedByDescending { it.jobId })
} catch (failure: WebJobServiceException) { throw failure } catch (failure: Exception) { budget.incomplete(failure) }

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
    sourceProfiles: List<decompengine.project.ReconstructionProfile> = defaultWebSourceProfiles(),
    retentionHolds: List<JobRetentionHold> = emptyList(),
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
    private val sourceCatalogEvidence = WebSourceCatalogEvidence(sourceProfiles, ::readSourceCatalogInput, ::readArtifact)

    /** Internal seam for deterministic publication-failure fixtures; production code never reassigns this. */
    internal var uploadPublisher = decompengine.jobs.StagedJobUpload(store.storageRoot)
    private val publicationFailures = mutableMapOf<String, WebJobDiagnostic>()
    /** Internal seams for disk-full/read-only and interrupted-cleanup fixtures. */
    internal var organizationWriter: decompengine.jobs.JobOrganizationWriter = decompengine.jobs.AtomicJobOrganizationWriter
    internal var deletionFaults: decompengine.jobs.JobDeletionFaults = decompengine.jobs.JobDeletionFaults {}
    private var deletions: decompengine.jobs.JobDeletionStore? = null
    private val deletionWorkers = mutableMapOf<Thread, CountDownLatch>()
    private val downloadLeases = mutableMapOf<String, Int>()
    private val holds = java.util.concurrent.CopyOnWriteArrayList(retentionHolds)
    private var attempts: WorkflowAttemptStore? = null
    private var startupRecoveryLimits = decompengine.jobs.WorkflowStartupRecoveryLimits()
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
        resumeOnePendingDeletion()
        repeat(32) {
            val continueBatch = synchronized(this) {
                if (!initialized || closed || stopping || attempts == null || publicationFailures.isNotEmpty() || uploads.isNotEmpty() || deletionWorkers.isNotEmpty())
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
    internal fun isIdle(): Boolean = synchronized(this) { closed && active.isEmpty() && uploads.isEmpty() && deletionWorkers.isEmpty() && retentionWorker?.isIdle != false }

    /** Invoked whenever quiescence is (re)established after close; used to release outer ownership. */
    internal var onQuiescent: (() -> Unit)? = null

    @Synchronized
    fun initializeExistingStorage() = initializeExistingStorage { false }

    @Synchronized
    internal fun initializeExistingStorage(cancellation: () -> Boolean) =
        initializeExistingStorage(decompengine.jobs.WorkflowStartupRecoveryLimits(), cancellation)

    @Synchronized
    internal fun initializeExistingStorage(limits: decompengine.jobs.WorkflowStartupRecoveryLimits, cancellation: () -> Boolean) {
        check(!closed && active.isEmpty()) { "Storage initialization requires an idle service" }
        if (initialized) return
        startupRecoveryLimits = limits
        fun checkCancellation() {
            if (stopping || Thread.currentThread().isInterrupted || cancellation()) throw decompengine.jobs.WorkflowStoreException(
                "RECOVERY_CANCELLED", "Startup recovery was cancelled; preserve any already reconciled storage.", attempts != null)
        }
        checkCancellation()
        if (Files.exists(store.storageRoot, NOFOLLOW_LINKS)) {
            acquireAndRecover(cancellation)
            // Interrupted purges resume before any request is admitted; a rename that never
            // happened is recorded as failed and its job is retained unchanged.
            deletions?.let { journal ->
                for (pending in journal.pending()) {
                    checkCancellation()
                    val running = journal.reconcileBeforePurge(pending)
                    if (running.state == decompengine.jobs.JobDeletionState.RUNNING) {
                        journal.record(running, journal.purge(running, { !stopping && !cancellation() }))
                    }
                }
            }
        }
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
            acquired.recoverForStartup(limits = startupRecoveryLimits, cancellation = { stopping || cancellation() }) { check ->
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
            deletions = decompengine.jobs.JobDeletionStore(store.storageRoot, faults = { point -> deletionFaults.hit(point) }).also { journal ->
                try { journal.load() } catch (failure: WorkflowStoreException) {
                    throw WebJobServiceException(failure.code, "The job deletion journal is invalid. Preserve it before reopening storage.", failure)
                }
            }
            attempts = acquired
            return acquired
        } catch (failure: Throwable) {
            try { acquired.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            throw webStartupFailure(failure)
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
    fun inspect(jobId: String): WebJobInspection = inspectJob(jobId)

    private fun inspectJob(jobId: String, read: ((String, Int) -> ByteArray)? = null): WebJobInspection {
        requireInitializedRead()
        publicationFailures[jobId]?.let { return WebJobInspection.Unavailable(it) }
        if (!jobId.matches(Regex("[0-9a-f]{32}")) || attempts == null) return WebJobInspection.Unavailable(
            WebJobDiagnostic(jobId, "JOB_NOT_FOUND", "The requested job is unavailable."))
        return try {
            val inspected = if (read == null) attempts?.inspect(jobId) else attempts?.inspectForListing(jobId, read)
            if (inspected is WorkflowJobInspection.Unavailable) return WebJobInspection.Unavailable(
                publicWebDiagnostic(jobId, inspected.diagnostic.code))
            val snapshot = (inspected as? WorkflowJobInspection.Available)?.snapshot
            val raw = if (read == null) store.get(jobId) else store.getForListing(jobId, read)
            requirePublicElfCategories(raw.metadata)
            val organizations = decompengine.jobs.JobOrganizationStore(store.storageRoot, organizationWriter)
            val organization = if (read == null) organizations.read(jobId) else organizations.read(jobId, read)
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
                    .map { publicWorkflowDiagnostic(it.code) }, legacyInterrupted, organization))
        } catch (failure: WorkflowStoreException) {
            WebJobInspection.Unavailable(publicWebDiagnostic(jobId, failure.code))
        } catch (_: Exception) {
            WebJobInspection.Unavailable(publicWebDiagnostic(jobId, "JOB_RECORD_UNAVAILABLE"))
        }
    }

    private fun listingReader(budget: WebDashboardReadBudget, progress: () -> Unit = {}): (String, Int) -> ByteArray =
        { relative, maximum ->
            val perFile = if (relative.endsWith("/job.json")) minOf(maximum, 256 * 1024) else maximum
            readWebJobCollectionMetadata(budget, perFile, progress) { allowance, check ->
                decompengine.repair.readStableRegularFile(store.storageRoot, relative, allowance, cancellationCheck = check).bytes
            }
        }

    /** Complete bounded HTML collection. Reads never acquire ownership or retain workflow histories. */
    @Synchronized
    internal fun dashboardRows(): WebDashboardRows {
        requireInitializedRead()
        val budget = WebDashboardReadBudget(cancellation = { stopping })
        val read = listingReader(budget)
        try {
            budget.checkpoint()
            if (Files.notExists(store.storageRoot, NOFOLLOW_LINKS)) {
                budget.checkpoint()
                return WebDashboardRows(emptyList(), emptyList())
            }
            check(Files.isDirectory(store.storageRoot, NOFOLLOW_LINKS)) { "Dashboard storage root is unavailable" }
            val rows = Files.newDirectoryStream(store.storageRoot).use { entries ->
                collectWebDashboardRows(entries.asSequence().map { it.fileName.toString() }, budget) { id -> inspectJob(id, read) }
            }
            budget.checkpoint()
            return rows
        } catch (failure: WebJobServiceException) { throw failure } catch (failure: Exception) { budget.incomplete(failure) }
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
    internal fun collectionRecords(): Sequence<kotlinx.serialization.json.JsonObject> = collectionRecordsWithProgress {}

    internal fun collectionRecordsWithProgress(progress: () -> Unit): Sequence<kotlinx.serialization.json.JsonObject> {
        val budget = WebDashboardReadBudget(cancellation = { stopping })
        val read = listingReader(budget, progress)
        fun checkpoint() { progress(); budget.checkpoint() }
        val ids = synchronized(this) {
            requireInitializedRead()
            try {
                checkpoint()
                val root = store.storageRoot
                val inspected = if (Files.notExists(root, NOFOLLOW_LINKS)) emptyList() else {
                    check(Files.isDirectory(root, NOFOLLOW_LINKS)) { "Job library root is unavailable" }
                    Files.newDirectoryStream(root).use { entries ->
                        collectWebJobLibraryIds(entries.asSequence().map { it.fileName.toString() }, ::checkpoint)
                    }
                }
                checkpoint()
                inspected
            } catch (failure: WebAccessDenied) { throw failure } catch (failure: WebJobServiceException) { throw failure }
            catch (failure: Exception) { progress(); budget.incomplete(failure) }
        }
        return sequence {
            for (id in ids) {
                checkpoint()
                val record = synchronized(this@WebJobService) {
                    requireInitializedRead()
                    val inspection = inspectJob(id, read)
                    checkpoint()
                    when (inspection) {
                        is WebJobInspection.Available -> webJob(inspection.presentation)
                        is WebJobInspection.Unavailable -> throw WebJobServiceException(inspection.diagnostic.code, inspection.diagnostic.message)
                    }
                }
                checkpoint()
                yield(record)
            }
            checkpoint()
        }
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

    /** One existing read unit under lifecycle ownership; manifest parsing never holds this monitor. */
    @Synchronized
    private fun readSourceCatalogInput(jobId: String): decompengine.repair.StableRegularFile {
        requireInitializedRead()
        return store.readInput(jobId)
    }

    /** Authorize before capture and again before returning, without locking jobs during JSON parsing. */
    internal fun readSourceCatalog(jobId: String, runId: String): WebSourceCatalogSnapshot {
        val attempt = getAttempt(jobId, runId)
        val snapshot = try { sourceCatalogEvidence.read(jobId, attempt.runId) }
            catch (changed: WebAccessDenied) { throw changed }
            catch (_: Exception) {
                throw WebAccessDenied(503, "SOURCE_CATALOG_UNAVAILABLE", "The source catalog is unavailable or exceeds its metadata limits.")
            }
        if (getAttempt(jobId, runId).version != attempt.version) {
            throw WebAccessDenied(409, "SOURCE_CATALOG_CHANGED", "The attempt changed during capture. Refresh its source catalog.")
        }
        return snapshot
    }

    @Synchronized
    private fun revisionSourceReference(jobId: String, runId: String, revisionId: String): WebRevisionSourceReference =
        when (val inspected = inspectDurableJob(jobId)) {
            is WorkflowJobInspection.Available -> selectWebRevisionSource(inspected.snapshot, jobId, runId, revisionId)
            is WorkflowJobInspection.Unavailable -> throw WebJobServiceException(inspected.diagnostic.code, inspected.diagnostic.message)
        }

    /** The persisted candidate supplies identity; bounded descriptors supply only source commitments. */
    internal fun readRevisionSources(jobId: String, runId: String, revisionId: String): WebRevisionSourceSnapshot {
        val reference = revisionSourceReference(jobId, runId, revisionId)
        val snapshot = try { sourceCatalogEvidence.readRevision(reference) }
            catch (changed: WebAccessDenied) { throw changed }
            catch (_: Exception) {
                throw WebAccessDenied(503, "SOURCE_REVISION_UNAVAILABLE", "The revision source input metadata is unavailable or exceeds its limits.")
            }
        if (revisionSourceReference(jobId, runId, revisionId) != reference) revisionSourceChanged()
        return snapshot
    }

    /** Generation declarations use the same current-candidate and bounded metadata capture boundary. */
    internal fun readRevisionFileMetadata(jobId: String, runId: String, revisionId: String,
        fileId: String): WebRevisionFileMetadataSnapshot {
        revisionSourceFileIndex(fileId)
        val reference = revisionSourceReference(jobId, runId, revisionId)
        val captured = try { sourceCatalogEvidence.readFileMetadata(reference, fileId) }
            catch (changed: WebAccessDenied) { throw changed }
            catch (failure: Exception) {
                if (failure is java.util.concurrent.CancellationException || failure is InterruptedException) throw failure
                throw WebAccessDenied(503, "SOURCE_REVISION_UNAVAILABLE", "The revision metadata is unavailable or exceeds its limits.")
            }
        if (revisionSourceReference(jobId, runId, revisionId) != reference) revisionSourceChanged()
        return captured
    }

    /** Source body capture shares metadata admission and rechecks the actual persisted candidate. */
    internal fun readRevisionSourceFile(jobId: String, runId: String, revisionId: String, fileId: String,
        purpose: WebSourceReadPurpose, expectedMetadataVersion: String? = null): WebRevisionSourceContent {
        revisionSourceFileIndex(fileId) // Reject malformed selectors before metadata or source IO.
        val reference = revisionSourceReference(jobId, runId, revisionId)
        val content = try { sourceCatalogEvidence.readFile(reference, fileId, purpose, expectedMetadataVersion, ::readSourceInput) }
            catch (changed: WebAccessDenied) { throw changed }
            catch (_: Exception) {
                throw WebAccessDenied(503, "SOURCE_FILE_UNAVAILABLE", "The selected source file is unavailable or cannot be captured within its limits.")
            }
        if (revisionSourceReference(jobId, runId, revisionId) != reference) revisionSourceChanged()
        return content
    }

    @Synchronized
    private fun readSourceInput(jobId: String, runId: String, path: String, maximumBytes: Long): decompengine.repair.StableRegularFile {
        requireInitializedRead()
        getAttempt(jobId, runId)
        return store.readSourceInput(jobId, runId, path, maximumBytes)
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
            if (deletionWorkers.isNotEmpty()) throw WebJobServiceException("UPLOAD_CAPACITY", "Wait for job deletion cleanup before uploading.")
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

    /** Future Git workspace adapters (and fixtures) register read-only holds here; see #509. */
    fun registerRetentionHold(hold: JobRetentionHold): AutoCloseable {
        holds += hold
        return AutoCloseable { holds.remove(hold) }
    }

    /** Download delivery keeps a lease so deletion cannot remove bytes a response is still sending. */
    internal fun downloadLease(jobId: String): AutoCloseable = synchronized(this) {
        requireInitializedRead()
        downloadLeases[jobId] = (downloadLeases[jobId] ?: 0) + 1
        var released = false
        AutoCloseable {
            synchronized(this) {
                if (!released) {
                    released = true
                    val remaining = (downloadLeases[jobId] ?: 1) - 1
                    if (remaining <= 0) downloadLeases.remove(jobId) else downloadLeases[jobId] = remaining
                }
            }
        }
    }

    /** A retained deletion tombstone, so readers can report "deleted" rather than "never existed". */
    @Synchronized
    internal fun deletedJob(jobId: String): decompengine.jobs.JobDeletionOperation? =
        if (!jobId.matches(Regex("[0-9a-f]{32}"))) null else deletions?.deleted(jobId)

    @Synchronized
    internal fun jobDeletionOperation(jobId: String, operationId: String): decompengine.jobs.JobDeletionOperation {
        requireInitializedRead()
        return deletions?.get(operationId)?.takeIf { it.jobId == jobId }
            ?: throw WebJobServiceException("JOB_NOT_FOUND", "The requested operation is unavailable.")
    }

    /** Explicit, fixed policy. Under it nothing deletes a job automatically; every path re-checks this list. */
    private fun protectionsLocked(jobId: String, snapshot: decompengine.jobs.WorkflowJobSnapshot?): List<WebRetentionProtection> {
        val result = ArrayList<WebRetentionProtection>()
        val attempts = snapshot?.attempts.orEmpty()
        if (attempts.any { !it.state.terminal }) result += WebRetentionProtection.ACTIVE_ATTEMPT
        if (active.containsKey(jobId)) result += WebRetentionProtection.OWNED_WORKER
        if (attempts.any { it.publicationPending }) result += WebRetentionProtection.PUBLICATION_PENDING
        if (attempts.any { it.progressRetentionPinned }) result += WebRetentionProtection.PINNED_EVIDENCE
        if ((downloadLeases[jobId] ?: 0) > 0) result += WebRetentionProtection.DOWNLOAD_IN_PROGRESS
        if (uploads.isNotEmpty()) result += WebRetentionProtection.STORAGE_BUSY
        if (publicationFailures.isNotEmpty()) result += WebRetentionProtection.RECOVERY_REQUIRED
        for (hold in holds) {
            val reasons = try { hold.holds(jobId) } catch (_: Exception) { null }
            if (reasons == null) result += WebRetentionProtection.HOLD_UNAVAILABLE
            else reasons.take(8).forEach { result += WebRetentionProtection.hold(it) }
        }
        return result.distinct().take(32)
    }

    /** Read-only per-job dry run: the same protection list and storage categories deletion would use. */
    internal fun jobDeletionPreview(jobId: String): WebJobDeletionPreview {
        val (presentation, protections, version) = synchronized(this) {
            requireInitializedRead()
            deletedJob(jobId)?.let { throw WebJobServiceException("JOB_DELETED", "The job was deleted.") }
            val selected = presentation(jobId)
            Triple(selected, protectionsLocked(jobId, selected.snapshot), webJob(selected).getValue("version").jsonPrimitive.content)
        }
        val scan = decompengine.jobs.JobStorageAccounting.scan(store.storageRoot, onlyJob = jobId)
        return WebJobDeletionPreview(presentation, version, scan.jobs[jobId] ?: decompengine.jobs.StorageBreakdown.EMPTY,
            scan.complete, protections)
    }

    /** Authorized capability boundary; actor identity comes only from the session. Key lookup precedes
     * every precondition, so an exact replay returns the original operation even after the job is gone.
     */
    @Synchronized
    internal fun requestJobDeletion(jobId: String, expectedVersion: String, sessionId: String, requestKey: String): WebJobDeletionAdmission {
        requireInitializedRead()
        if (!jobId.matches(Regex("[0-9a-f]{32}"))) throw WebJobServiceException("JOB_NOT_FOUND", "The requested job is unavailable.")
        require(requestKey.matches(Regex("[A-Za-z0-9_-]{16,128}")) && expectedVersion.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")))
        val actor = lifecycleDigest("decomp-job-delete-actor-v1:$sessionId")
        val keyDigest = lifecycleDigest("decomp-job-delete-request-v1\u0000$jobId\u0000$actor\u0000$requestKey")
        val requestDigest = lifecycleDigest("decomp-job-delete-intent-v1\u0000$jobId\u0000$expectedVersion")
        if (closed || stopping) throw WebJobServiceException("SERVICE_STOPPED", "The job service is stopping.")
        val journal = deletions ?: run { writableStore(); deletions } ?: throw WebJobServiceException("JOB_NOT_FOUND", "The requested job is unavailable.")
        try { journal.replay(keyDigest, requestDigest)?.let { return WebJobDeletionAdmission(it, replayed = true) } }
        catch (_: decompengine.jobs.JobDeletionKeyConflictException) {
            throw WebJobServiceException("IDEMPOTENCY_CONFLICT", "The request key was used for a different deletion.")
        }
        journal.deleted(jobId)?.let { throw WebJobServiceException("JOB_DELETED", "The job was already deleted.") }
        val selected = presentation(jobId)
        if (webJob(selected).getValue("version").jsonPrimitive.content != expectedVersion) {
            throw WebJobServiceException("VERSION_CONFLICT", "The job changed. Review it again before deleting.")
        }
        val protections = protectionsLocked(jobId, selected.snapshot)
        if (protections.isNotEmpty()) throw WebJobRetentionConflict(protections)
        val admitted = try { journal.admit(jobId, actor, keyDigest, requestDigest) }
            catch (_: decompengine.jobs.JobDeletionCapacityException) {
                throw WebJobServiceException("DELETION_CAPACITY", "Deletion history is at capacity. Retry after older records age out.")
            } catch (failure: decompengine.jobs.JobStorageWriteException) {
                throw WebJobServiceException("STORAGE_UNAVAILABLE", "The deletion could not be recorded: storage is full, read-only or unavailable. The job is unchanged.", failure)
            }
        val running = try { journal.detach(admitted) } catch (failure: decompengine.jobs.JobStorageWriteException) {
            throw WebJobServiceException("STORAGE_UNAVAILABLE", "The job could not be removed: storage is full, read-only or unavailable. The job is unchanged.", failure)
        }
        return WebJobDeletionAdmission(running, replayed = false)
    }

    /** Purge outside the monitor with registered ownership; an incomplete pass stays resumable. */
    internal fun continueJobDeletion(operation: decompengine.jobs.JobDeletionOperation,
        maximumNanos: Long = 5_000_000_000L): decompengine.jobs.JobDeletionOperation {
        val worker = Thread.currentThread()
        val journal: decompengine.jobs.JobDeletionStore
        val finished = synchronized(this) {
            journal = deletions ?: return operation
            val current = journal.get(operation.operationId) ?: return operation
            // Concurrent purges touch disjoint detached directories; uploads measure the whole root.
            if (current.state != decompengine.jobs.JobDeletionState.RUNNING || closed || stopping ||
                worker in deletionWorkers || uploads.isNotEmpty()) return current
            CountDownLatch(1).also { deletionWorkers[worker] = it }
        }
        try {
            val result = journal.purge(operation, { !closed && !stopping }, maximumNanos)
            return synchronized(this) { journal.record(operation, result) }
        } finally {
            synchronized(this) { deletionWorkers.remove(worker); finished.countDown(); releaseIfQuiescent() }
        }
    }

    private fun resumeOnePendingDeletion() {
        val pending = synchronized(this) {
            if (!initialized || closed || stopping || uploads.isNotEmpty()) return
            val journal = deletions ?: return
            journal.pending().firstOrNull()?.let(journal::reconcileBeforePurge)
        } ?: return
        if (pending.state == decompengine.jobs.JobDeletionState.RUNNING) continueJobDeletion(pending, 1_000_000_000L)
    }

    /** Allowlisted display metadata. It changes only organization.json and the public version. */
    @Synchronized
    internal fun requestJobOrganization(jobId: String, expectedVersion: String, change: decompengine.jobs.JobOrganizationChange,
        sessionId: String, requestKey: String): Pair<WebJobPresentation, Boolean> {
        requireInitializedRead()
        if (!jobId.matches(Regex("[0-9a-f]{32}"))) throw WebJobServiceException("JOB_NOT_FOUND", "The requested job is unavailable.")
        if (closed || stopping) throw WebJobServiceException("SERVICE_STOPPED", "The job service is stopping.")
        writableStore()
        deletedJob(jobId)?.let { throw WebJobServiceException("JOB_DELETED", "The job was deleted.") }
        val actor = lifecycleDigest("decomp-job-organization-actor-v1:$sessionId")
        val keyDigest = lifecycleDigest("decomp-job-organization-request-v1\u0000$jobId\u0000$actor\u0000$requestKey")
        val requestDigest = lifecycleDigest("decomp-job-organization-intent-v1\u0000$expectedVersion\u0000${change.canonical()}")
        val organizations = decompengine.jobs.JobOrganizationStore(store.storageRoot, organizationWriter)
        try {
            organizations.replay(jobId, keyDigest, requestDigest)?.let { return presentation(jobId) to true }
            val current = presentation(jobId)
            if (webJob(current).getValue("version").jsonPrimitive.content != expectedVersion) {
                throw WebJobServiceException("VERSION_CONFLICT", "The job changed. Refresh it before editing.")
            }
            organizations.apply(jobId, change, keyDigest, requestDigest, java.time.Instant.now())
        } catch (_: decompengine.jobs.JobOrganizationKeyConflictException) {
            throw WebJobServiceException("IDEMPOTENCY_CONFLICT", "The request key was used for a different change.")
        } catch (_: decompengine.jobs.JobOrganizationReceiptCapacityException) {
            throw WebJobServiceException("ORGANIZATION_RECEIPT_CAPACITY", "Edit history is at capacity. Retry later.")
        } catch (failure: decompengine.jobs.JobStorageWriteException) {
            throw WebJobServiceException(if (failure.applied) "STORAGE_UNCONFIRMED" else "STORAGE_UNAVAILABLE",
                if (failure.applied) "The change was written but could not be confirmed durable. Refresh the job."
                else "The change was not saved: storage is full, read-only or unavailable. The previous metadata is preserved.", failure)
        } catch (failure: WorkflowStoreException) {
            throw WebJobServiceException(failure.code, publicWebDiagnosticMessage(failure.code), failure)
        }
        return presentation(jobId) to false
    }

    /** Read-only, tolerant library accounting. Runs without the monitor; never blocks status reads. */
    internal fun storageSummary(): WebStorageSummary {
        val pending = synchronized(this) {
            requireInitializedRead()
            deletions?.pending().orEmpty().size
        }
        return WebStorageSummary(decompengine.jobs.JobStorageAccounting.scan(store.storageRoot), pending, java.time.Instant.now())
    }

    /** Dry run of the maintenance that really runs. Short per-job monitor holds; no write, no workflow. */
    internal fun maintenancePreview(nanoTime: () -> Long = System::nanoTime): WebMaintenancePreview {
        val started = nanoTime()
        val now = java.time.Instant.now()
        val ids = synchronized(this) { requireInitializedRead(); if (attempts == null) emptyList() else store.jobIds() }
        val actions = ArrayList<WebMaintenanceAction>()
        val protectedJobs = ArrayList<Pair<String, List<WebRetentionProtection>>>()
        var complete = true
        var readBytes = 0L
        val scan = decompengine.jobs.JobStorageAccounting.scan(store.storageRoot)
        if (!scan.complete) complete = false
        synchronized(this) {
            deletions?.pending().orEmpty().forEach { operation ->
                actions += WebMaintenanceAction("deletion-resume", operation.jobId, null,
                    scan.pendingDeletions[operation.operationId]?.bytes ?: 0, if (retentionWorker != null) "periodic" else "startup")
            }
        }
        for (id in ids) {
            if (nanoTime() - started > 5_000_000_000L || readBytes > 64L * 1024 * 1024 || Thread.currentThread().isInterrupted) { complete = false; break }
            synchronized(this) {
                requireInitializedRead()
                val owner = attempts ?: return@synchronized
                val inspection = try { inspectStoredJob(owner, id) } catch (_: Exception) { null }
                val snapshot = (inspection as? WorkflowJobInspection.Available)?.snapshot
                if (snapshot == null) { complete = false; return@synchronized }
                val protections = protectionsLocked(id, snapshot)
                if (protections.isNotEmpty()) protectedJobs += id to protections
                if (active.containsKey(id)) return@synchronized
                for (attempt in snapshot.attempts) {
                    if (!attempt.state.terminal || attempt.publicationPending || attempt.progressRetentionPinned) continue
                    val path = "reports/runs/${attempt.runId}/${decompengine.jobs.AgentProgressJournal.FILE_NAME}"
                    val bytes = try { store.readArtifact(id, path, decompengine.jobs.AgentProgressJournal.MAXIMUM_READ_BYTES.toLong()).bytes }
                        catch (_: Exception) { null } ?: continue
                    readBytes += bytes.size
                    val replacement = try { decompengine.jobs.AgentProgressJournalRetention.expiredSnapshot(attempt, bytes, now) }
                        catch (_: Exception) { complete = false; null } ?: continue
                    actions += WebMaintenanceAction("progress-journal-expiry", id, attempt.runId,
                        maxOf(0L, bytes.size.toLong() - replacement.size), if (retentionWorker != null) "periodic" else "not-scheduled")
                }
            }
        }
        return WebMaintenancePreview(now, complete, retentionWorker != null, actions, protectedJobs)
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
            val runningUploads = uploads.toList() + deletionWorkers.toList()
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
            if (active.isNotEmpty() || uploads.isNotEmpty() || deletionWorkers.isNotEmpty() || retentionWorker?.isIdle == false) {
                val failure = WebJobServiceException("SHUTDOWN_INCOMPLETE", "Owned work has not stopped; storage ownership is retained until it exits.")
                if (problem == null) problem = failure else problem.addSuppressed(failure)
            }
        }
        problem?.let { throw it }
    }

    private fun releaseIfQuiescent() {
        if (closed && active.isEmpty() && uploads.isEmpty() && deletionWorkers.isEmpty() && retentionWorker?.isIdle != false) {
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
