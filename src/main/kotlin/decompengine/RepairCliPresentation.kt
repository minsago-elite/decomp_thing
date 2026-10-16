package decompengine

import decompengine.repair.RepairRunOutcome
import decompengine.repair.RepairRunStatus
import decompengine.repair.repairAttemptLabel
import decompengine.repair.repairRunLabel
import decompengine.repair.repairRollbackRunLabel
import decompengine.repair.repairPublicRevisionLabel
import decompengine.repair.RepairHistoryReadResult
import decompengine.repair.RepairHistoryReadStatus
import decompengine.repair.recordedRepairAttemptLabel
import decompengine.repair.recordedRepairRollbackLabel

/** Concise operator output from typed workflow results; peer summaries stay out of the console. */
internal data class RepairCliPresentation(val exitCode: Int, val lines: List<String>)

internal fun presentRepairOutcome(outcome: RepairRunOutcome): RepairCliPresentation {
    val run = outcome.runState
    val report = outcome.validation
    val accepted = run.status == RepairRunStatus.FULLY_ACCEPTED && report != null &&
        report.cases.isNotEmpty() && report.matches
    val lines = buildList {
        add("repair run ${run.id}: ${repairRunLabel(run.status.name.lowercase())} [${run.status.name.lowercase()}] (${run.attemptedCount}/${run.maximumAttempts} attempts)")
        repairRollbackRunLabel(run)?.let(::add)
        add("accepted revision: ${run.acceptedHeadId?.let(::repairPublicRevisionLabel) ?: "none"}")
        if (outcome.iterations.size > 20) add("${outcome.iterations.size - 20} earlier iterations omitted; see durable repair history")
        outcome.iterations.takeLast(20).forEach {
            add("repair iteration ${it.index}: ${repairAttemptLabel(it)}")
        }
        if (accepted) add("repair passed ${requireNotNull(report).cases.size} retained regression case(s)")
        else add("repair did not establish full acceptance; inspect durable repair state and retained reports")
    }
    return RepairCliPresentation(if (accepted) 0 else 1, lines)
}

/** A read-only restart/reconnect view. It neither opens a repair runtime nor contacts a provider. */
internal fun presentRecordedRepairHistory(result: RepairHistoryReadResult): RepairCliPresentation {
    when (result.status) {
        RepairHistoryReadStatus.NOT_RECORDED -> return RepairCliPresentation(0, listOf("No canonical repair history is recorded."))
        RepairHistoryReadStatus.UNAVAILABLE -> return RepairCliPresentation(1, listOf("Recorded repair history is unavailable or invalid."))
        RepairHistoryReadStatus.RECORDED -> Unit
    }
    val snapshot = requireNotNull(result.snapshot)
    val lines = buildList {
        add("Recorded repair metadata; current source and execution have not been revalidated.")
        add("published revision: ${snapshot.publishedHead.value}")
        add("provisional revision: ${snapshot.provisionalHead?.value ?: "none"}")
        add("fully accepted revision: ${snapshot.fullyAcceptedHead?.value ?: "none"}")
        add("history projection: ${result.projection.status.name.lowercase().replace('_', '-')}")
        val historicalFailures = snapshot.attempts.count { it.rollback?.failureCode != null } +
            if (snapshot.pending?.rollback?.failureCode != null) 1 else 0
        add("recorded restoration failures retained: $historicalFailures")
        if (snapshot.runs.size > 20) add("${snapshot.runs.size - 20} earlier recorded runs omitted")
        snapshot.runs.takeLast(20).forEach { run ->
            add("repair run ${run.identity.value}: ${repairRunLabel(run.status.name.lowercase())} (${run.attemptedCount}/${run.maximumAttempts} attempts)")
            run.rollbackFailureAttempt?.let { attempt ->
                add("rollback failure attempt: ${attempt.value} (${requireNotNull(run.rollbackResolution).name.lowercase().replace('_', '-')})")
            }
        }
        if (snapshot.attempts.size > 20) add("${snapshot.attempts.size - 20} earlier recorded attempts omitted")
        for (attempt in snapshot.attempts.takeLast(20) + listOfNotNull(snapshot.pending)) {
            val index = attempt.iterationIndex ?: attempt.ordinal
            add("repair iteration $index: ${recordedRepairAttemptLabel(attempt)} [${attempt.identity.value}]")
            add("rollback: ${recordedRepairRollbackLabel(attempt.rollback)}")
            add("retained regression cases: ${attempt.retainedCases.size}")
            if (attempt.invocation != null) add("ACP receipt: recorded association; content not independently read or verified.")
        }
        if (snapshot.attempts.isEmpty() && snapshot.pending == null) add("No repair attempts are recorded.")
    }
    return RepairCliPresentation(0, lines)
}
