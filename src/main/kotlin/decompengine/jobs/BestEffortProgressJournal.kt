package decompengine.jobs

import decompengine.agent.*
import java.nio.file.Path

/** Owns an optional display journal without making it part of workflow success. */
internal class BestEffortProgressJournal(
    reportsDirectory: Path,
    workflow: String,
    sensitiveValues: Collection<String> = emptyList(),
    onPhase: (AgentWorkflowPhase) -> Unit = {},
    private val onUnavailable: () -> Unit = {
        System.err.println("Progress reporting is unavailable; workflow results remain authoritative.")
    },
) : AgentWorkflowProgress, AutoCloseable {
    private var failed = false
    private var journal: AgentProgressJournal? = null
    internal val journalRunId: String? get() = journal?.journalRunId

    init {
        observe { journal = AgentProgressJournal(reportsDirectory, workflow, sensitiveValues, onPhase = onPhase) }
    }

    private inline fun observe(evenIfFailed: Boolean = false, action: () -> Unit) {
        if (failed && !evenIfFailed) return
        try {
            action()
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            if (!failed) {
                failed = true
                // A warning sink is another display observer, never workflow authority.
                try {
                    onUnavailable()
                } catch (warningFailure: Exception) {
                    if (warningFailure is InterruptedException) Thread.currentThread().interrupt()
                }
            }
        }
    }

    override fun beginTask(taskId: String, request: AgentExecutionRequest): AgentTaskProgress =
        task { it.beginTask(taskId, request) }

    override fun beginTask(taskId: String, request: AgentExecutionRequest, workflowRunId: String): AgentTaskProgress =
        task { it.beginTask(taskId, request, workflowRunId) }

    private fun task(begin: (AgentProgressJournal) -> AgentTaskProgress): AgentTaskProgress {
        var progress = AgentTaskProgress.NONE
        observe { journal?.let { progress = begin(it) } }
        return object : AgentTaskProgress {
            override fun event(event: AgentExecutionEvent) = observe { progress.event(event) }
            override fun complete(receipt: AgentExecutionReceipt) = observe { progress.complete(receipt) }
        }
    }

    override fun phase(phase: AgentWorkflowPhase, taskId: String?, acceptedRevisionSha256: String?) =
        observe { journal?.phase(phase, taskId, acceptedRevisionSha256) }

    override fun runState(observation: AgentWorkflowRunObservation) = observe { journal?.runState(observation) }

    override fun close() {
        val interrupted = Thread.interrupted()
        try {
            observe(evenIfFailed = true) { journal?.close() }
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
    }
}
