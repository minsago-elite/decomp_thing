package decompengine.web

import decompengine.jobs.Job
import decompengine.jobs.JobStore
import java.nio.file.Path
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** HTTP adapters select an operation; they cannot supply executable code or paths. */
enum class WebWorkflow {
    EXPLORE,
    RECONSTRUCT,
}

sealed interface WebWorkflowAdmission {
    data class Started(val jobId: String) : WebWorkflowAdmission
    data object AlreadyRunning : WebWorkflowAdmission
    data object Unavailable : WebWorkflowAdmission
}

/**
 * Shared job and workflow boundary for legacy and versioned HTTP adapters.
 *
 * Jobs and paths returned here are internal models for trusted JVM callers, never
 * wire DTOs. Authentication belongs to the adapter before any call. Only explicit
 * start() requests invoke the injected workflow adapters. Durable attempts and
 * revision publication are supplied by the lifecycle store in the next slice.
 */
class WebJobService(
    private val store: JobStore,
    private val analyzer: JobAnalyzer,
    private val reconstructor: JobReconstructor,
    executor: Executor? = null,
    workers: Int = 2,
    queueCapacity: Int = 32,
) : AutoCloseable {
    private val ownedExecutor = if (executor == null) {
        require(workers in 1..2 && queueCapacity in 1..32)
        ThreadPoolExecutor(workers, workers, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(queueCapacity), { task ->
            Thread(task, "decomp-web-workflow").apply { isDaemon = true }
        }, ThreadPoolExecutor.AbortPolicy())
    } else null
    private val workflowExecutor = executor ?: ownedExecutor!!
    private val active = mutableMapOf<String, WorkflowTask>()
    private var closed = false

    fun list(): List<Job> = store.list()
    fun get(jobId: String): Job = store.get(jobId)
    fun resolveArtifact(jobId: String, relativePath: String): Path = store.resolveArtifact(jobId, relativePath)

    @Synchronized
    fun upload(filename: String, content: ByteArray): Job {
        check(!closed) { "The job service is stopped" }
        return store.createFromUpload(filename, content)
    }

    @Synchronized
    fun recoverInterruptedJobs() {
        check(active.isEmpty() && !closed) { "Recovery requires an idle job service" }
        store.recoverInterruptedJobs()
    }

    @Synchronized
    fun start(jobId: String, workflow: WebWorkflow): WebWorkflowAdmission {
        if (closed) return WebWorkflowAdmission.Unavailable
        val job = store.get(jobId)
        if (active.containsKey(job.id)) return WebWorkflowAdmission.AlreadyRunning
        val task = WorkflowTask(job.id, workflow)
        active[job.id] = task
        try {
            store.updateStatus(job.id, "queued", when (workflow) {
                WebWorkflow.EXPLORE -> "Waiting for an exploration worker"
                WebWorkflow.RECONSTRUCT -> "Waiting for a source-tree worker"
            })
            workflowExecutor.execute(task)
        } catch (_: RejectedExecutionException) {
            task.finish("failed", "Workflow capacity is unavailable; retry when a worker is available")
            return WebWorkflowAdmission.Unavailable
        } catch (failure: Throwable) {
            try {
                task.finish("failed", "Workflow could not be scheduled; retry when a worker is available")
            } catch (cleanupFailure: Throwable) {
                if (cleanupFailure !== failure) failure.addSuppressed(cleanupFailure)
            } finally {
                active.remove(job.id, task)
            }
            throw failure
        }
        return WebWorkflowAdmission.Started(job.id)
    }

    override fun close() {
        synchronized(this) {
            if (closed) return
            closed = true
            ownedExecutor?.shutdownNow()
            // Revoke our pending tasks even on a caller-owned executor. Later
            // delivery of their Runnable cannot modify or execute anything.
            var failure: Exception? = null
            active.values.filter { !it.started }.toList().forEach { task ->
                try {
                    task.finish("failed", "Workflow was interrupted by server shutdown")
                } catch (exception: Exception) {
                    if (failure == null) failure = exception else failure.addSuppressed(exception)
                }
            }
            failure?.let { throw it }
        }
    }

    private inner class WorkflowTask(val jobId: String, val workflow: WebWorkflow) : Runnable {
        var started = false
        private var terminal = false

        override fun run() {
            try {
                val job = synchronized(this@WebJobService) {
                    if (terminal || active[jobId] !== this) return
                    if (closed) {
                        finish("failed", "Workflow was interrupted by server shutdown")
                        return
                    }
                    started = true
                    store.updateStatus(jobId, "analyzing", when (workflow) {
                        WebWorkflow.EXPLORE -> "Generating and executing candidate inputs"
                        WebWorkflow.RECONSTRUCT -> "Recovering program structure and generating source modules"
                    })
                }
                val reports = store.reportsDirectory(jobId)
                when (workflow) {
                    WebWorkflow.EXPLORE -> analyzer.analyze(job, reports)
                    WebWorkflow.RECONSTRUCT -> reconstructor.reconstruct(job, reports)
                }
                synchronized(this@WebJobService) {
                    if (closed || Thread.currentThread().isInterrupted) {
                        finish("failed", "Workflow was interrupted by server shutdown")
                    } else {
                        finish("complete", when (workflow) {
                            WebWorkflow.EXPLORE -> "Exploration completed successfully"
                            WebWorkflow.RECONSTRUCT -> "Archival source tree generated successfully"
                        })
                    }
                }
            } catch (_: Exception) {
                synchronized(this@WebJobService) {
                    finish("failed", "Workflow failed; inspect its available diagnostics before retrying")
                }
            } finally {
                synchronized(this@WebJobService) {
                    // Also release ownership if the adapter throws an Error.
                    // Conditional removal cannot revoke a newer admission.
                    active.remove(jobId, this)
                }
            }
        }

        fun finish(status: String, message: String) {
            if (terminal || active[jobId] !== this) return
            terminal = true
            try {
                store.updateStatus(jobId, status, message)
            } finally {
                active.remove(jobId, this)
            }
        }
    }
}
