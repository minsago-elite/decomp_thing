package decompengine

import decompengine.agent.AgentWorkflowPhase
import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.BestEffortProgressJournal
import java.io.PrintStream
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.serialization.json.*

internal enum class CliProgressWorkflow(val wireName: String) {
    REPAIR("repair"), RECONSTRUCTION("reconstruction"),
}

/** Own reconstruction display resources; both phases and unavailable warnings use the observer. */
internal fun <T> withReconstructionCliProgress(
    reportsDirectory: Path,
    sensitiveValues: Collection<String> = emptyList(),
    output: PrintStream = System.err,
    action: (BestEffortProgressJournal) -> T,
): T = CliProgressObserver(reportsDirectory, output, CliProgressWorkflow.RECONSTRUCTION).use { observer ->
    BestEffortProgressJournal(
        reportsDirectory, "reconstruction", sensitiveValues,
        onUnavailable = observer::unavailable,
    ).use(action)
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
) : AutoCloseable {
    private val stopped = AtomicBoolean()
    private val warningRequested = AtomicBoolean()
    private val cursor = RepairCliProgressCursor(
        runCatching { AgentProgressJournal.read(reportsDirectory) }.getOrNull(), workflow,
    )
    private val worker = Thread(::observe, "${workflow.wireName}-cli-progress").apply { isDaemon = true; start() }

    fun unavailable() { warningRequested.set(true) }

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
            try {
                if (warningRequested.get()) warnUnavailable()
                val snapshot = AgentProgressJournal.read(reportsDirectory)
                if (snapshot != null) cursor.advance(snapshot).forEach { line ->
                    if (!stopped.get()) output.println(line)
                }
            } catch (_: Exception) {
                warnUnavailable()
            }
            try { Thread.sleep(250) } catch (_: InterruptedException) { return }
        }
    }

    override fun close() {
        stopped.set(true)
        worker.interrupt()
        val interrupted = Thread.interrupted()
        try {
            worker.join(200)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } finally {
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

    fun advance(snapshot: JsonObject): List<String> {
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
