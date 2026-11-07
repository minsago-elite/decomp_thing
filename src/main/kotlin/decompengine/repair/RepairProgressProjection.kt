package decompengine.repair

import decompengine.agent.*
import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.ProgressWarnings
import java.nio.file.Path

/** Optional operator projection. Neither persistence nor observer failure changes repair authority. */
internal class RepairProgressProjection(
    reportsDirectory: Path,
    private val onUnavailable: () -> Unit = {
        ProgressWarnings.repairUnavailable()
    },
    private val journalFactory: (Path) -> AgentProgressJournal = { directory ->
        AgentProgressJournal(directory, "repair", System.getenv().values)
    },
) : AutoCloseable {
    private var warned = false
    private var journal: AgentProgressJournal? = null

    init { observe { journal = journalFactory(reportsDirectory) } }

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
        val actualPhase = if (run.status == RepairRunStatus.ROLLBACK_FAILED) AgentWorkflowPhase.FAILED else phase ?: when (run.status) {
            RepairRunStatus.FULLY_ACCEPTED -> AgentWorkflowPhase.ACCEPTED
            RepairRunStatus.COMPILE_VALID -> AgentWorkflowPhase.COMPILE_VALID
            RepairRunStatus.ITERATION_EXHAUSTED -> AgentWorkflowPhase.EXHAUSTED
            RepairRunStatus.RESOURCE_EXHAUSTED -> AgentWorkflowPhase.RESOURCE_EXHAUSTED
            RepairRunStatus.CANCELLED -> AgentWorkflowPhase.CANCELLED
            RepairRunStatus.INTERRUPTED -> AgentWorkflowPhase.INTERRUPTED
            RepairRunStatus.NO_CHANGES, RepairRunStatus.REJECTED -> AgentWorkflowPhase.REJECTED
            RepairRunStatus.VALIDATION_FAILED, RepairRunStatus.ROLLBACK_FAILED -> AgentWorkflowPhase.FAILED
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
                try {
                    onUnavailable()
                } catch (warningFailure: Exception) {
                    if (warningFailure is InterruptedException) Thread.currentThread().interrupt()
                }
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

    /** Close the optional projection, then retain enclosing workspace ownership until no writer remains. */
    internal fun closeAndAwaitWriterTermination() {
        try { close() } finally { journal?.awaitWriterTermination() }
    }

    companion object {
        private val testFactory = ThreadLocal<((Path) -> RepairProgressProjection)?>()

        internal fun create(reportsDirectory: Path): RepairProgressProjection =
            testFactory.get()?.invoke(reportsDirectory) ?: RepairProgressProjection(reportsDirectory)

        /** Scoped deterministic writer control for exercising the actual repair-loop boundary. */
        internal fun <T> withFactoryForTesting(
            factory: (Path) -> RepairProgressProjection,
            action: () -> T,
        ): T {
            check(testFactory.get() == null) { "repair progress test factory is already installed" }
            testFactory.set(factory)
            return try { action() } finally { testFactory.remove() }
        }
    }
}
