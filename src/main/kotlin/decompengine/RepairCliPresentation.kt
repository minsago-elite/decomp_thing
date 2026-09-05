package decompengine

import decompengine.repair.RepairRunOutcome
import decompengine.repair.RepairRunStatus

/** Concise operator output from typed workflow results; peer summaries stay out of the console. */
internal data class RepairCliPresentation(val exitCode: Int, val lines: List<String>)

internal fun presentRepairOutcome(outcome: RepairRunOutcome): RepairCliPresentation {
    val run = outcome.runState
    val report = outcome.validation
    val accepted = run.status == RepairRunStatus.FULLY_ACCEPTED && report != null &&
        report.cases.isNotEmpty() && report.matches
    val lines = buildList {
        add("repair run ${run.id}: ${run.status.name.lowercase()} (${run.attemptedCount}/${run.maximumAttempts} attempts)")
        if (outcome.iterations.size > 20) add("${outcome.iterations.size - 20} earlier iterations omitted; see durable repair history")
        outcome.iterations.takeLast(20).forEach {
            add("repair iteration ${it.index}: ${it.disposition.name.lowercase()}")
        }
        if (accepted) add("repair passed ${requireNotNull(report).cases.size} retained regression case(s)")
        else add("repair did not establish full acceptance; inspect durable repair state and retained reports")
    }
    return RepairCliPresentation(if (accepted) 0 else 1, lines)
}
