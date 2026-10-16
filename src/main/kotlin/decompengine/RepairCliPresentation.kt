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
import decompengine.repair.RepairRecordedHistorySelection
import decompengine.repair.RepairRecordedSelectionFailure
import decompengine.repair.RepairRecordedEvidence
import decompengine.repair.recordedRepairHistoryPage
import decompengine.repair.parseRecordedRepairSelection
import decompengine.repair.recordedRepairSummary
import decompengine.repair.recordedRepairAssuranceLabel
import decompengine.repair.recordedRepairEvidenceLabel
import java.nio.file.Path

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

internal data class RecordedRepairHistoryCliOptions(val project: Path, val selection: RepairRecordedHistorySelection)

internal fun parseRecordedRepairHistoryArguments(args: List<String>): RecordedRepairHistoryCliOptions {
    require(args.size in 1..7 && args.size % 2 == 1 && args[0].isNotBlank() && !args[0].startsWith("-")) {
        "Recorded history arguments are invalid."
    }
    val values = linkedMapOf<String, String>()
    for (index in 1 until args.size step 2) {
        val key = args[index]
        require(key in setOf("--page", "--case-page", "--graph") && values.put(key, args[index + 1]) == null) {
            "Recorded history arguments are invalid."
        }
    }
    return RecordedRepairHistoryCliOptions(Path.of(args[0]),
        parseRecordedRepairSelection(values["--page"], values["--case-page"], values["--graph"]))
}

/** A read-only restart/reconnect view. It neither opens a repair runtime nor contacts a provider. */
internal fun presentRecordedRepairHistory(result: RepairHistoryReadResult): RepairCliPresentation =
    presentRecordedRepairHistory(result, RepairRecordedHistorySelection())

internal fun presentRecordedRepairHistory(result: RepairHistoryReadResult,
    selection: RepairRecordedHistorySelection): RepairCliPresentation {
    val page = try { recordedRepairHistoryPage(result, selection, 20) }
        catch (failure: RepairRecordedSelectionFailure) { return RepairCliPresentation(2, listOf(requireNotNull(failure.message))) }
    when (result.status) {
        RepairHistoryReadStatus.NOT_RECORDED -> return RepairCliPresentation(0, listOf("No canonical repair history is recorded."))
        RepairHistoryReadStatus.UNAVAILABLE -> return RepairCliPresentation(1, listOf("Recorded repair history is unavailable or invalid."))
        RepairHistoryReadStatus.RECORDED -> Unit
    }
    val snapshot = requireNotNull(result.snapshot)
    val selected = requireNotNull(page)
    fun evidence(value: RepairRecordedEvidence?): String {
        if (value == null) return "Not recorded."
        val label = recordedRepairEvidenceLabel(value.kind)
        val reference = value.artifact ?: return "$label evidence; artifact was not retained."
        return "$label evidence; recorded reference ${reference.value}; content not independently read or verified."
    }
    val lines = buildList {
        add("Recorded repair metadata; current source and execution have not been revalidated.")
        add("recorded graph: ${snapshot.graphSha256}")
        add("history page ${selection.pageNumber} of ${selected.totalPages}")
        add("case reference page ${selection.casePageNumber} of ${selected.casePages}; at most 20 per attempt")
        add("published revision: ${snapshot.publishedHead.value}")
        add("provisional revision: ${snapshot.provisionalHead?.value ?: "none"}")
        add("fully accepted revision: ${snapshot.fullyAcceptedHead?.value ?: "none"}")
        add("history projection: ${result.projection.status.name.lowercase().replace('_', '-')}")
        val historicalFailures = snapshot.attempts.count { it.rollback?.failureCode != null } +
            if (snapshot.pending?.rollback?.failureCode != null) 1 else 0
        add("recorded restoration failures retained: $historicalFailures")
        if (selected.earlierRuns > 0) add("${selected.earlierRuns} earlier recorded runs omitted from this page")
        if (selected.newerRuns > 0) add("${selected.newerRuns} newer recorded runs omitted from this page")
        selected.runs.forEach { run ->
            add("repair run ${run.identity.value}: ${repairRunLabel(run.status.name.lowercase())} (${run.attemptedCount}/${run.maximumAttempts} attempts)")
            run.rollbackFailureAttempt?.let { attempt ->
                add("rollback failure attempt: ${attempt.value} (${requireNotNull(run.rollbackResolution).name.lowercase().replace('_', '-')})")
            }
        }
        if (selected.earlierAttempts > 0) add("${selected.earlierAttempts} earlier recorded attempts omitted from this page")
        if (selected.newerAttempts > 0) add("${selected.newerAttempts} newer recorded attempts omitted from this page")
        for (attempt in selected.attempts) {
            val index = attempt.iterationIndex ?: attempt.ordinal
            add("repair iteration $index: ${recordedRepairAttemptLabel(attempt)} [${attempt.identity.value}]")
            add("recorded run: ${attempt.run?.value ?: "none"}")
            add("summary: ${recordedRepairSummary(attempt)}")
            add("rollback: ${recordedRepairRollbackLabel(attempt.rollback)}")
            add("evidence assurance: ${recordedRepairAssuranceLabel(attempt)}")
            add("before: ${evidence(attempt.before)}")
            add("after: ${evidence(attempt.after)}")
            add("retained regression cases: ${attempt.retainedCases.size}")
            add("retained case corpus: ${attempt.corpusSha256 ?: "unavailable"}")
            val references = selected.caseReferences(attempt)
            add("retained case references: " + if (attempt.corpusSha256 == null) "unavailable; recorded corpus is missing."
                else references.joinToString(", ") { it.value }.ifEmpty { "none on this page" })
            if (attempt.retainedCases.size > references.size)
                add("${attempt.retainedCases.size - references.size} case references omitted from this page")
            if (attempt.invocation != null) add("ACP receipt: recorded association; content not independently read or verified.")
        }
        if (snapshot.attempts.isEmpty() && snapshot.pending == null) add("No repair attempts are recorded.")
        else if (selected.attempts.isEmpty()) add("No repair attempts are on this page.")
        fun navigation(label: String, historyPage: Int, casePage: Int) {
            add("$label: --page $historyPage --case-page $casePage --graph ${snapshot.graphSha256}")
        }
        if (selection.pageNumber > 1) navigation("Newer history", selection.pageNumber - 1, 1)
        if (selection.pageNumber < selected.totalPages) navigation("Older history", selection.pageNumber + 1, 1)
        if (selection.casePageNumber > 1) navigation("Previous case references", selection.pageNumber, selection.casePageNumber - 1)
        if (selection.casePageNumber < selected.casePages) navigation("More case references", selection.pageNumber, selection.casePageNumber + 1)
    }
    return RepairCliPresentation(0, lines)
}
