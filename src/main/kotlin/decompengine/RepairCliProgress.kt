package decompengine

import decompengine.agent.AgentWorkflowPhase
import decompengine.jobs.AgentProgressJournal
import java.io.PrintStream
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.serialization.json.*

/** One CLI observer; console backpressure never runs on the repair or journal-writer thread. */
internal class RepairCliProgress(
    private val reportsDirectory: Path,
    private val output: PrintStream = System.err,
) : AutoCloseable {
    private val stopped = AtomicBoolean()
    private val cursor = RepairCliProgressCursor(runCatching { AgentProgressJournal.read(reportsDirectory) }.getOrNull())
    private val worker = Thread(::observe, "repair-cli-progress").apply { isDaemon = true; start() }

    private fun observe() {
        var warned = false
        while (!stopped.get()) {
            try {
                val snapshot = AgentProgressJournal.read(reportsDirectory)
                if (snapshot != null) cursor.advance(snapshot).forEach { line ->
                    if (!stopped.get()) output.println(line)
                }
            } catch (_: Exception) {
                if (!warned && !stopped.get()) {
                    warned = true
                    output.println("repair progress unavailable; durable repair state remains authoritative")
                }
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
        // from the repair loop or turn a successful durable outcome into a display failure.
    }
}

/** Observe only new records; names and peer content are never copied into live console lines. */
internal class RepairCliProgressCursor(initial: JsonObject?) {
    private var next = initial?.get("nextSequence")?.jsonPrimitive?.long ?: 0L

    fun advance(snapshot: JsonObject): List<String> {
        val end = snapshot.getValue("nextSequence").jsonPrimitive.long
        val lines = ArrayList<String>()
        if (end < next) {
            lines += "repair progress history restarted; inspect durable repair state"
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
            if (event["workflow"]?.jsonPrimitive?.content != "repair" ||
                event["kind"]?.jsonPrimitive?.content != "workflow_run_state") return@forEach
            val phase = event["phase"]?.jsonPrimitive?.content ?: return@forEach
            if (AgentWorkflowPhase.entries.none { it.name.lowercase() == phase }) return@forEach
            val run = event["workflowRunIdSha256"]?.jsonPrimitive?.content ?: return@forEach
            if (!run.matches(Regex("[0-9a-f]{64}"))) return@forEach
            phases += "repair progress ${run.take(12)}: $phase"
        }
        omitted = Math.addExact(omitted, end - expected)
        if (omitted > 0) lines += "repair progress omitted $omitted event(s); inspect the retained journal and durable state"
        if (phases.size > 32) lines += "repair progress omitted ${phases.size - 32} older phase update(s)"
        lines += phases.takeLast(32)
        next = end
        return lines
    }
}
