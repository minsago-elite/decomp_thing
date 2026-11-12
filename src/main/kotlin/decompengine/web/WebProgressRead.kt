package decompengine.web

import decompengine.jobs.WorkflowAttempt

/** Shared read transaction for snapshots, polling and streaming; no lock survives this call. */
internal fun readWebProgress(jobs: WebJobService, jobId: String, runId: String): Pair<WorkflowAttempt, ByteArray> =
    jobs.readProgressSnapshot(jobId, runId)

/**
 * The journal writer republishes by atomic rename, so a descriptor-pinned read can observe its
 * path binding change mid-read. Re-read a bounded number of times before reporting the journal
 * unavailable; a budget refusal, interruption or the final failure is never retried or masked.
 */
internal fun <T> readAcrossJournalPublication(attempts: Int = JOURNAL_READ_ATTEMPTS, read: () -> T): T {
    require(attempts in 1..JOURNAL_READ_ATTEMPTS)
    var remaining = attempts
    while (true) {
        try { return read() }
        catch (failure: Exception) {
            if (--remaining == 0 || failure is InterruptedException || failure is java.util.concurrent.CancellationException ||
                failure is decompengine.repair.RepairBudgetExceededException || Thread.currentThread().isInterrupted) throw failure
        }
    }
}

internal const val JOURNAL_READ_ATTEMPTS = 3
