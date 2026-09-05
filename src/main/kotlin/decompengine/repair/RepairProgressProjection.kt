package decompengine.repair

import decompengine.agent.*
import decompengine.jobs.AgentProgressJournal
import java.nio.file.Path

/** Optional operator projection. Neither persistence nor observer failure changes repair authority. */
internal class RepairProgressProjection(reportsDirectory: Path) : AutoCloseable {
    private var warned = false
    private var journal: AgentProgressJournal? = null

    init {
        observe { journal = AgentProgressJournal(reportsDirectory, "repair", System.getenv().values) }
    }

    fun task(id: String, request: AgentExecutionRequest, graph: ModuleRevisionGraph): AgentTaskProgress {
        var task: AgentTaskProgress = AgentTaskProgress.NONE
        observe { task = journal?.beginTask(id, request, graph.snapshot.runs.last().id) ?: AgentTaskProgress.NONE }
        return object : AgentTaskProgress {
            override fun event(event: AgentExecutionEvent) = observe { task.event(event) }
            override fun complete(receipt: AgentExecutionReceipt) = observe { task.complete(receipt) }
        }
    }

    fun state(graph: ModuleRevisionGraph, phase: AgentWorkflowPhase? = null, revisionId: String? = null) = observe {
        val snapshot = graph.snapshot
        val run = snapshot.runs.lastOrNull() ?: return@observe
        val actualPhase = phase ?: when (run.status) {
            RepairRunStatus.FULLY_ACCEPTED -> AgentWorkflowPhase.ACCEPTED
            RepairRunStatus.COMPILE_VALID -> AgentWorkflowPhase.COMPILE_VALID
            RepairRunStatus.ITERATION_EXHAUSTED -> AgentWorkflowPhase.EXHAUSTED
            RepairRunStatus.RESOURCE_EXHAUSTED -> AgentWorkflowPhase.RESOURCE_EXHAUSTED
            RepairRunStatus.CANCELLED -> AgentWorkflowPhase.CANCELLED
            RepairRunStatus.INTERRUPTED -> AgentWorkflowPhase.INTERRUPTED
            RepairRunStatus.NO_CHANGES, RepairRunStatus.REJECTED -> AgentWorkflowPhase.REJECTED
            RepairRunStatus.VALIDATION_FAILED -> AgentWorkflowPhase.FAILED
            RepairRunStatus.RUNNING -> AgentWorkflowPhase.UNRESOLVED
        }
        val accepted = if (actualPhase == AgentWorkflowPhase.ACCEPTED) {
            require(run.status == RepairRunStatus.FULLY_ACCEPTED)
            snapshot.nodes.single { it.id == run.acceptedHeadId }.sourceRevisionSha256
        } else null
        journal?.runState(AgentWorkflowRunObservation(run.id, actualPhase,
            revisionId ?: run.provisionalHeadId ?: run.acceptedHeadId ?: run.baselineId,
            taskId = revisionId, acceptedRevisionSha256 = accepted))
    }

    private inline fun observe(evenIfFailed: Boolean = false, action: () -> Unit) {
        if (warned && !evenIfFailed) return
        try {
            action()
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            if (!warned) {
                warned = true
                System.err.println("Repair progress is unavailable; durable repair state remains authoritative.")
            }
        }
    }

    override fun close() {
        val interrupted = Thread.interrupted()
        try {
            observe(evenIfFailed = true) { journal?.close() }
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
    }
}
