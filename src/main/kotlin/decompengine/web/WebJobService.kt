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
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Legacy adapters retain their legacy provenance; they are not durable workflow registrations. */
enum class WebWorkflow { EXPLORE, RECONSTRUCT }
sealed interface WebWorkflowAdmission {
    data class Started(val jobId: String) : WebWorkflowAdmission
    data object AlreadyRunning : WebWorkflowAdmission
    data object Unavailable : WebWorkflowAdmission
}

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
) : AutoCloseable {
    private data class Registration(val adapter: DurableWebWorkflowAdapter, val limits: decompengine.jobs.WorkflowExecutionLimits)
    private val registrations = durableAdapters.associate { it.workflow to Registration(it, it.limits) }.also {
        require(it.size == durableAdapters.size) { "duplicate durable workflow registration" }
        require(shutdownTimeoutMs in 0..5000) { "invalid workflow shutdown deadline" }
    }
    private val ownedExecutor = if (executor == null) {
        require(workers in 1..2 && queueCapacity in 1..32)
        ThreadPoolExecutor(workers, workers, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(queueCapacity), { task ->
            Thread(task, "decomp-web-workflow").apply { isDaemon = true }
        }, ThreadPoolExecutor.AbortPolicy())
    } else null
    private val workflowExecutor = executor ?: ownedExecutor!!
    private val active = mutableMapOf<String, OwnedTask>()
    private val uploads = mutableMapOf<Thread, CountDownLatch>()
    private val uploadPublisher = decompengine.jobs.StagedJobUpload(store.storageRoot)
    private val publicationFailures = mutableMapOf<String, WebJobDiagnostic>()
    private var attempts: WorkflowAttemptStore? = null
    private var initialized = false
    private var closed = false

    @Synchronized
    fun initializeExistingStorage() {
        check(!closed && active.isEmpty()) { "Storage initialization requires an idle service" }
        if (initialized) return
        if (Files.exists(store.storageRoot, NOFOLLOW_LINKS)) acquireAndRecover()
        initialized = true
    }

    private fun acquireAndRecover(): WorkflowAttemptStore {
        attempts?.let { return it }
        val acquired = attemptStoreFactory(store.storageRoot)
        try {
            acquired.recoverAll() // Unavailable records remain isolated and visible through inspect/listInspections.
            attempts = acquired
            return acquired
        } catch (failure: Throwable) {
            try { acquired.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            throw failure
        }
    }

    private fun writableStore(): WorkflowAttemptStore {
        check(!closed) { "The job service is stopped" }
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
        return result
    }

    private fun requireInitializedRead() {
        if (!initialized) throw WebJobServiceException("SERVICE_NOT_INITIALIZED", "Job storage must be initialized before serving reads.")
        if (closed) throw WebJobServiceException("SERVICE_STOPPED", "The job service is stopped.")
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
                WebJobDiagnostic(jobId, inspected.diagnostic.code, inspected.diagnostic.message))
            val snapshot = (inspected as? WorkflowJobInspection.Available)?.snapshot
            val raw = store.get(jobId)
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
                (inspected as? WorkflowJobInspection.Available)?.diagnostics.orEmpty(), legacyInterrupted))
        } catch (failure: WorkflowStoreException) {
            WebJobInspection.Unavailable(WebJobDiagnostic(jobId, failure.code, failure.message ?: "Job storage is unavailable."))
        } catch (_: Exception) {
            WebJobInspection.Unavailable(WebJobDiagnostic(jobId, "JOB_RECORD_UNAVAILABLE",
                "The job record is unavailable or invalid. Preserve its storage and restore a verified backup before retrying."))
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
        return store.createFromUpload(filename, content)
    }

    /** Multipart bytes are copied outside the service monitor; publication retains root ownership through completion. */
    fun uploadMultipart(input: java.io.InputStream, contentType: String): Job = uploadMultipartReceipt(input, contentType).job

    internal fun uploadMultipartReceipt(input: java.io.InputStream, contentType: String, idempotencyKey: String? = null): decompengine.jobs.PublishedJobUpload {
        val worker = Thread.currentThread()
        val finished = synchronized(this) {
            writableStore()
            if (uploads.size >= 2 || worker in uploads) throw WebJobServiceException("UPLOAD_CAPACITY", "Two uploads are already in progress. Retry later.")
            if (Files.getFileStore(store.storageRoot).usableSpace < 64L * 1024 * 1024) throw WebJobServiceException("UPLOAD_STORAGE", "Upload staging needs at least 64 MiB of free storage.")
            CountDownLatch(1).also { uploads[worker] = it }
        }
        try {
            return uploadPublisher.publish(idempotencyKey) { sink ->
                StreamingMultipartUpload.copy(input, contentType, sink).filename
            }
        } catch (failure: decompengine.jobs.UploadPublicationUncertain) {
            synchronized(this) {
                publicationFailures[failure.jobId] = WebJobDiagnostic(failure.jobId, "RECOVERY_REQUIRED", "An upload may have been published. Reopen storage before admitting more work; do not retry blindly.")
            }
            throw WebJobServiceException("RECOVERY_REQUIRED", "Upload publication is uncertain. Inspect storage before retrying.", failure)
        } finally {
            synchronized(this) { uploads.remove(worker); finished.countDown(); releaseIfQuiescent() }
        }
    }

    /** Compatibility startup entry point; recovery never rewrites historical job.json bytes. */
    fun recoverInterruptedJobs() = initializeExistingStorage()

    @Synchronized
    fun start(jobId: String, workflow: WebWorkflow): WebWorkflowAdmission {
        if (closed) return WebWorkflowAdmission.Unavailable
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
        if (closed) return DurableWebWorkflowAdmission.Unavailable("SERVICE_STOPPED")
        if (publicationFailures.isNotEmpty()) return DurableWebWorkflowAdmission.Unavailable("RECOVERY_REQUIRED")
        val registration = registrations[request.workflow] ?: return DurableWebWorkflowAdmission.Unsupported(request.workflow)
        val owner = writableStore()
        val view = inspectStoredJob(owner, jobId) as? WorkflowJobInspection.Available
            ?: throw WebJobServiceException("JOB_RECORD_UNAVAILABLE", "The job record is unavailable; inspect its storage diagnostic.")
        if (view.snapshot.version != expectedJobVersion) throw WorkflowStoreException("VERSION_CONFLICT", "The workflow version changed; refresh before starting another attempt.")
        if (active.containsKey(jobId) || view.snapshot.attempts.any { !it.state.terminal }) return DurableWebWorkflowAdmission.AlreadyRunning
        if (request.inputRevisionId != null && request.inputRevisionId != view.snapshot.acceptedRevision?.revisionId) {
            throw WebJobServiceException("INPUT_REVISION_UNAVAILABLE", "The requested input revision has no trusted publication reference for this job.")
        }
        val job = store.get(jobId)
        val queued = owner.create(jobId, expectedJobVersion,
            NewWorkflowAttempt(request.workflow, registration.limits, request.inputRevisionId, previousRunId = request.previousRunId))
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

    override fun close() {
        var problem: Throwable? = null
        val running = synchronized(this) {
            if (closed) return
            closed = true
            ownedExecutor?.shutdownNow()
            active.values.filter { !it.started }.toList().forEach { task ->
                try { task.stopPending() } catch (failure: Throwable) {
                    if (problem == null) problem = failure else problem.addSuppressed(failure)
                }
            }
            val runningUploads = uploads.toList()
            runningUploads.forEach { (worker, _) -> worker.interrupt() }
            active.values.toList().also { tasks -> tasks.forEach { it.worker?.interrupt() }; releaseIfQuiescent() } to runningUploads
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
        synchronized(this) {
            releaseIfQuiescent()
            if (active.isNotEmpty() || uploads.isNotEmpty()) {
                val failure = WebJobServiceException("SHUTDOWN_INCOMPLETE", "A workflow has not stopped; storage ownership is retained until it exits.")
                if (problem == null) problem = failure else problem.addSuppressed(failure)
            }
        }
        problem?.let { throw it }
    }

    private fun releaseIfQuiescent() {
        if (closed && active.isEmpty() && uploads.isEmpty()) {
            val restoreInterrupt = Thread.interrupted()
            try { attempts?.close(); attempts = null }
            finally { if (restoreInterrupt) Thread.currentThread().interrupt() }
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
                    if (closed) { stopPending(); return }
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
                    if (closed || Thread.currentThread().isInterrupted) finish("failed", "Workflow was interrupted by server shutdown")
                    else finish("complete", "Legacy workflow completed; completion does not establish accepted revision evidence")
                }
            } catch (_: Exception) {
                synchronized(this@WebJobService) { finish("failed", "Workflow failed; inspect its available diagnostics before retrying") }
            } finally { synchronized(this@WebJobService) { release() } }
        }
        override fun stopPending() = finish("failed", "Workflow was interrupted by server shutdown")
        fun finish(status: String, message: String) {
            if (terminal || active[jobId] !== this) return
            terminal = true
            try { store.updateStatus(jobId, status, message) }
            finally { if (!started) release() }
        }
    }

    private inner class DurableTask(val job: Job, var attempt: WorkflowAttempt, val adapter: DurableWebWorkflowAdapter) : OwnedTask(job.id) {
        private var publicationFailure: WebJobServiceException? = null
        override fun run() {
            try {
                val reports = synchronized(this@WebJobService) {
                    if (terminal || active[jobId] !== this) return
                    if (closed) { stopPending(); return }
                    started = true
                    worker = Thread.currentThread()
                    attempt = checkNotNull(attempts).transition(jobId, attempt.runId, attempt.version, WorkflowTransition.Start).attempt
                    store.runReportsDirectory(jobId, attempt.runId, create = true)
                }
                val outcome = adapter.execute(DurableWebWorkflowContext(job, attempt, reports))
                synchronized(this@WebJobService) {
                    if (closed || Thread.currentThread().isInterrupted) finish(interrupted())
                    else finish(when (outcome) {
                        is DurableWebWorkflowOutcome.Completed -> WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED, outcome.candidate, outcome.usage)
                        is DurableWebWorkflowOutcome.Failed -> WorkflowTransition.Finish(WorkflowRunState.FAILED, outcome.reason, outcome.candidate, outcome.usage)
                    })
                }
            } catch (failure: Exception) {
                synchronized(this@WebJobService) {
                    publicationFailure?.let { throw it }
                    try { finish(if (closed || Thread.currentThread().isInterrupted || failure is InterruptedException) interrupted()
                        else WorkflowTransition.Finish(WorkflowRunState.FAILED, WorkflowTerminalReason.FAILED)) }
                    catch (cleanup: Exception) { if (cleanup !== failure) failure.addSuppressed(cleanup); throw failure }
                }
            } finally { synchronized(this@WebJobService) { release() } }
        }
        override fun stopPending() = finish(interrupted())
        fun finish(transition: WorkflowTransition.Finish) {
            publicationFailure?.let { throw it }
            if (terminal || active[jobId] !== this) return
            // A cooperative worker can return with its interrupt flag set. Decide the outcome first,
            // then clear that flag only around the bounded atomic metadata operation and restore it.
            val restoreInterrupt = Thread.interrupted()
            val selected = if (closed || restoreInterrupt) interrupted() else transition
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
        private fun interrupted() = WorkflowTransition.Finish(WorkflowRunState.INTERRUPTED, WorkflowTerminalReason.PROCESS_INTERRUPTED)
    }

    private fun legacyStatus(state: WorkflowRunState): String = when (state) {
        WorkflowRunState.QUEUED -> "queued"
        WorkflowRunState.RUNNING, WorkflowRunState.CANCELLING -> "analyzing"
        WorkflowRunState.COMPLETED -> "complete"
        else -> "failed"
    }
}
