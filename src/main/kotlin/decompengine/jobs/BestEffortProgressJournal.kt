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
        ProgressWarnings.journalUnavailable()
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

/** Only fixed warning kinds cross the mailbox; no run, task, credential or exception is retained. */
internal enum class ProgressWarning(val flag: Int, val message: String) {
    JOURNAL(1, "Progress reporting is unavailable; workflow results remain authoritative."),
    REPAIR(2, "Repair progress is unavailable; durable repair state remains authoritative."),
}

/** One process-wide daemon, with two coalesced pending bits and no workflow-owned resources. */
internal object ProgressWarnings {
    private val mailbox by lazy { ProgressWarningMailbox { message -> System.err.println(message) } }

    fun journalUnavailable() = mailbox.report(ProgressWarning.JOURNAL)
    fun repairUnavailable() = mailbox.report(ProgressWarning.REPAIR)
}

/** A blocked sink never holds the mailbox monitor; it can retain only this one daemon. */
internal class ProgressWarningMailbox(private val write: (String) -> Unit) : AutoCloseable {
    private val monitor = Object()
    private var pending = 0
    private var closed = false
    private val worker = Thread(::drain, "decomp-progress-warning").apply { isDaemon = true; start() }

    fun report(warning: ProgressWarning) {
        synchronized(monitor) {
            if (!closed) {
                pending = pending or warning.flag
                monitor.notifyAll()
            }
        }
    }

    private fun drain() {
        try {
            while (true) {
                val batch = synchronized(monitor) {
                    while (pending == 0 && !closed) monitor.wait()
                    if (closed) return
                    pending.also { pending = 0 }
                }
                for (warning in ProgressWarning.entries) {
                    if ((batch and warning.flag) == 0) continue
                    if (synchronized(monitor) { closed }) return
                    try {
                        write(warning.message)
                    } catch (failure: Exception) {
                        // Ordinary warning failures cannot replace a durable workflow result.
                        if (failure is InterruptedException) {
                            Thread.currentThread().interrupt()
                            return
                        }
                    }
                }
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    override fun close() {
        val interrupted = Thread.interrupted()
        synchronized(monitor) { closed = true; pending = 0; monitor.notifyAll() }
        worker.interrupt()
        try {
            if (Thread.currentThread() !== worker) worker.join(200)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
        // Noninterruptible output may retain this daemon until process exit; never wait longer.
    }
}
