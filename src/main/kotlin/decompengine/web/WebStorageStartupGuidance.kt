package decompengine.web

import decompengine.jobs.WorkflowStoreException

/**
 * Operator guidance for a startup that job storage refused. Text is fixed per code: stored record
 * bytes, host paths and exception messages never reach it. Returns null for unrelated failures.
 */
internal fun webStorageStartupGuidance(failure: Throwable): String? {
    val (code, changesMayHaveBegun) = generateSequence(failure) { it.cause }.take(8).firstNotNullOfOrNull { cause ->
        when (cause) {
            is WorkflowStoreException -> cause.code to cause.outcomeUnknown
            is WebJobServiceException -> cause.code to false
            else -> null
        }
    } ?: return null
    val reason = when (code) {
        "UNSUPPORTED_WORKFLOW_SCHEMA" ->
            "A workflow-state.json file uses a schema version this build does not support. It was probably written by a newer application version; start that version again or restore a verified backup taken before the upgrade."
        "CORRUPT_LEGACY_JOB" ->
            "A job.json upload record is damaged or uses an unsupported shape. Preserve it and restore a verified backup of that job directory before retrying."
        "CORRUPT_WORKFLOW_STATE" ->
            "A workflow-state.json file is damaged or inconsistent. Preserve it and restore a verified backup of that job directory before retrying."
        "OWNERSHIP_CONFLICT" -> "Another server owns this data directory. Stop it before starting this one."
        else -> publicWebDiagnosticMessage(code)
    }
    val outcome = if (changesMayHaveBegun)
        "Recovery changes may have begun. Preserve the whole data directory and reconcile it before retrying."
    else "No recovery changes were applied; stored job files are unchanged."
    return "Job storage refused startup ($code). $reason\n$outcome\n" +
        "Back up the stopped data directory before editing it; see docs/web-legacy-migration.md (Migration failure and rollback)."
}
