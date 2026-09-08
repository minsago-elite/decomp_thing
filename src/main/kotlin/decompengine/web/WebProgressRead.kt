package decompengine.web

import decompengine.jobs.WorkflowAttempt

/** Shared read transaction for snapshots, polling and streaming; no lock survives this call. */
internal fun readWebProgress(jobs: WebJobService, jobId: String, runId: String): Pair<WorkflowAttempt, ByteArray> =
    jobs.readProgressSnapshot(jobId, runId)
