package decompengine.web

import decompengine.jobs.WorkflowAttempt

/** Same guarded artifact read for snapshots, polling and streaming. Not a publication transaction. */
internal fun readWebProgress(jobs: WebJobService, jobId: String, runId: String): Pair<WorkflowAttempt, ByteArray> {
    val attempt = jobs.getAttempt(jobId, runId)
    val bytes = try { jobs.readProgressJournal(jobId, attempt.runId) }
        catch (_: Exception) {
            throw WebAccessDenied(503, "PROGRESS_UNAVAILABLE", "The retained progress journal is unavailable. Missing data does not establish an empty history.")
        }
    if (jobs.getAttempt(jobId, runId).version != attempt.version) {
        throw WebAccessDenied(409, "PROGRESS_CHANGED", "The attempt changed during this read. Read a fresh snapshot.")
    }
    return attempt to bytes
}
