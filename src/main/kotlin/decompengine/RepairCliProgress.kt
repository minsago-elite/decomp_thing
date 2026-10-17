package decompengine

import decompengine.agent.AgentWorkflowPhase
import decompengine.agent.AgentWorkflowProgress
import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.BestEffortProgressJournal
import java.io.PrintStream
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.serialization.json.*

internal enum class CliProgressWorkflow(val wireName: String) {
    REPAIR("repair"), RECONSTRUCTION("reconstruction"),
}

/** Own reconstruction display resources; explicit close also drains before CLI early exit. */
internal fun <T> withReconstructionCliProgress(
    reportsDirectory: Path,
    sensitiveValues: Collection<String> = emptyList(),
    output: PrintStream = System.err,
    action: (ReconstructionCliProgress) -> T,
): T = ReconstructionCliProgress.open(reportsDirectory, sensitiveValues, output).use(action)

internal class ReconstructionCliProgress private constructor(
    private val journal: BestEffortProgressJournal,
    private val observer: CliProgressObserver,
) : AgentWorkflowProgress by journal, AutoCloseable {
    private val closed = AtomicBoolean()

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        try {
            journal.close()
        } finally {
            observer.close()
        }
    }

    companion object {
        fun open(
            reportsDirectory: Path,
            sensitiveValues: Collection<String>,
            output: PrintStream,
            readSnapshot: (Path) -> JsonObject? = { directory -> AgentProgressJournal.read(directory) },
        ): ReconstructionCliProgress {
            val observer = CliProgressObserver(reportsDirectory, output, CliProgressWorkflow.RECONSTRUCTION, readSnapshot)
            var journal: BestEffortProgressJournal? = null
            try {
                val owned = BestEffortProgressJournal(
                    reportsDirectory, "reconstruction", sensitiveValues,
                    onPhase = observer::reconstructionPhase,
                    onUnavailable = observer::unavailable,
                )
                journal = owned
                owned.journalRunId?.let(observer::bindReconstructionRun)
                return ReconstructionCliProgress(owned, observer)
            } catch (failure: Throwable) {
                try { journal?.close() } finally { observer.close() }
                throw failure
            }
        }
    }
}

internal class RepairCliProgress(
    reportsDirectory: Path,
    output: PrintStream = System.err,
) : AutoCloseable by CliProgressObserver(reportsDirectory, output)

/** One CLI observer; console backpressure never runs on a workflow or journal-writer thread. */
internal class CliProgressObserver(
    private val reportsDirectory: Path,
    private val output: PrintStream = System.err,
    private val workflow: CliProgressWorkflow = CliProgressWorkflow.REPAIR,
    private val readSnapshot: (Path) -> JsonObject? = { directory -> AgentProgressJournal.read(directory) },
) : AutoCloseable {
    private val stopped = AtomicBoolean()
    private val drainRequested = AtomicBoolean()
    private val wakeUp = Object()
    private val reconstructionRunId = AtomicReference<String?>()
    private val warningRequested = AtomicBoolean()
    private val reconstructionPhases = java.util.ArrayDeque<AgentWorkflowPhase>()
    private var omittedReconstructionPhases = 0L
    private val cursor = if (workflow == CliProgressWorkflow.REPAIR) RepairCliProgressCursor(
        runCatching { readSnapshot(reportsDirectory) }.getOrNull(), workflow,
    ) else null
    private val worker = Thread(::observe, "${workflow.wireName}-cli-progress").apply { isDaemon = true; start() }

    fun unavailable() {
        warningRequested.set(true)
        synchronized(wakeUp) { wakeUp.notifyAll() }
    }

    fun bindReconstructionRun(runId: String) {
        check(workflow == CliProgressWorkflow.RECONSTRUCTION)
        check(reconstructionRunId.compareAndSet(null, runId))
        synchronized(wakeUp) { wakeUp.notifyAll() }
    }

    /** Fixed owned enum values only; no console or filesystem work on a workflow callback. */
    fun reconstructionPhase(phase: AgentWorkflowPhase) {
        check(workflow == CliProgressWorkflow.RECONSTRUCTION)
        synchronized(wakeUp) {
            if (stopped.get() || warningRequested.get() || reconstructionRunId.get() == null) return@synchronized
            if (reconstructionPhases.size == 32) {
                reconstructionPhases.removeFirst()
                omittedReconstructionPhases = Math.addExact(omittedReconstructionPhases, 1L)
            }
            reconstructionPhases.addLast(phase)
            wakeUp.notifyAll()
        }
    }

    private fun emitReconstructionPhases() {
        val (omitted, phases) = synchronized(wakeUp) {
            val batch = omittedReconstructionPhases to reconstructionPhases.toList()
            omittedReconstructionPhases = 0L
            reconstructionPhases.clear()
            batch
        }
        if (stopped.get() || warningRequested.get()) return
        if (omitted > 0) output.println("reconstruction progress omitted $omitted older phase update(s)")
        phases.forEach { phase ->
            if (!stopped.get() && !warningRequested.get())
                output.println("reconstruction: ${phase.name.lowercase().replace('_', ' ')}")
        }
    }

    private fun observe() {
        var warned = false
        fun warnUnavailable() {
            if (!warned && !stopped.get()) {
                warned = true
                output.println(when (workflow) {
                    CliProgressWorkflow.REPAIR -> "repair progress unavailable; durable repair state remains authoritative"
                    CliProgressWorkflow.RECONSTRUCTION -> "Progress reporting is unavailable; workflow results remain authoritative."
                })
            }
        }
        while (!stopped.get()) {
            // Reconstruction drains owned phase notifications without a final storage read.
            val finalPoll = drainRequested.get()
            try {
                if (warningRequested.get()) warnUnavailable()
                if (!warningRequested.get()) {
                    if (workflow == CliProgressWorkflow.RECONSTRUCTION) {
                        emitReconstructionPhases()
                    } else {
                        val snapshot = readSnapshot(reportsDirectory)
                        if (snapshot != null) checkNotNull(cursor).advance(snapshot).forEach { line ->
                            if (!stopped.get() && !warningRequested.get()) output.println(line)
                        }
                    }
                }
            } catch (_: Exception) {
                warnUnavailable()
            }
            if (finalPoll) return
            try {
                synchronized(wakeUp) {
                    if (!drainRequested.get() && !stopped.get() &&
                        (workflow != CliProgressWorkflow.RECONSTRUCTION || warningRequested.get() || reconstructionPhases.isEmpty())) {
                        wakeUp.wait(250)
                    }
                }
            } catch (_: InterruptedException) { return }
        }
    }

    override fun close() {
        if (workflow == CliProgressWorkflow.RECONSTRUCTION) drainRequested.set(true) else stopped.set(true)
        // The reconstruction mailbox is ready after the journal owner's bounded close.
        synchronized(wakeUp) { wakeUp.notifyAll() }
        val interrupted = Thread.interrupted()
        try {
            worker.join(200)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } finally {
            stopped.set(true)
            worker.interrupt()
            if (interrupted) Thread.currentThread().interrupt()
        }
        // A blocked console may retain this sole daemon until process exit; never wait on it
        // from a workflow or turn a successful durable outcome into a display failure.
    }
}

/** Observe only new records; names and peer content are never copied into live console lines. */
internal class RepairCliProgressCursor(
    initial: JsonObject?,
    private val workflow: CliProgressWorkflow = CliProgressWorkflow.REPAIR,
) {
    private var next = initial?.get("nextSequence")?.jsonPrimitive?.long ?: 0L

    fun advance(snapshot: JsonObject, reconstructionRunId: String? = null): List<String> {
        if (workflow == CliProgressWorkflow.RECONSTRUCTION && reconstructionRunId == null) return emptyList()
        val end = snapshot.getValue("nextSequence").jsonPrimitive.long
        val lines = ArrayList<String>()
        if (end < next) {
            lines += when (workflow) {
                CliProgressWorkflow.REPAIR -> "repair progress history restarted; inspect durable repair state"
                CliProgressWorkflow.RECONSTRUCTION -> "reconstruction progress history restarted; inspect workflow results"
            }
            next = 0
        }
        val events = snapshot.getValue("events").jsonArray.map { it.jsonObject }
            .filter { it.getValue("sequence").jsonPrimitive.long >= next }
        var expected = next
        var omitted = 0L
        val phases = ArrayList<String>()
        events.forEach { event ->
            val sequence = event.getValue("sequence").jsonPrimitive.long
            omitted = Math.addExact(omitted, sequence - expected)
            expected = sequence + 1
            val kind = if (workflow == CliProgressWorkflow.REPAIR) "workflow_run_state" else "workflow_phase"
            if (event["workflow"]?.jsonPrimitive?.content != workflow.wireName ||
                event["kind"]?.jsonPrimitive?.content != kind) return@forEach
            if (workflow == CliProgressWorkflow.RECONSTRUCTION &&
                event["runId"]?.jsonPrimitive?.content != reconstructionRunId) return@forEach
            val phase = event["phase"]?.jsonPrimitive?.content ?: return@forEach
            if (AgentWorkflowPhase.entries.none { it.name.lowercase() == phase }) return@forEach
            when (workflow) {
                CliProgressWorkflow.REPAIR -> {
                    val run = event["workflowRunIdSha256"]?.jsonPrimitive?.content ?: return@forEach
                    if (!run.matches(Regex("[0-9a-f]{64}"))) return@forEach
                    phases += "repair progress ${run.take(12)}: $phase"
                }
                CliProgressWorkflow.RECONSTRUCTION -> phases += "reconstruction: ${phase.replace('_', ' ')}"
            }
        }
        omitted = Math.addExact(omitted, end - expected)
        if (omitted > 0) lines += when (workflow) {
            CliProgressWorkflow.REPAIR -> "repair progress omitted $omitted event(s); inspect the retained journal and durable state"
            CliProgressWorkflow.RECONSTRUCTION -> "reconstruction progress omitted $omitted event(s); inspect the retained journal and workflow results"
        }
        if (phases.size > 32) lines += "${workflow.wireName} progress omitted ${phases.size - 32} older phase update(s)"
        lines += phases.takeLast(32)
        next = end
        return lines
    }
}
