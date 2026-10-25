package decompengine.web

import decompengine.jobs.JobStoreException
import decompengine.jobs.WorkflowAttempt
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowRunState
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.ModulePlanJson
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * The bounded report files one reconstruction attempt wrote into its own report directory, captured
 * between two reads of the same attempt version. Nothing here plans, executes or validates work.
 */
internal data class WebModuleProgressCapture(
    val attempt: WorkflowAttempt,
    val progress: ByteArray?,
    val summary: ByteArray?,
    val plan: ByteArray?,
    val generation: ByteArray?,
)

internal const val MODULE_PROGRESS_SMALL_BYTES = 64L * 1024
internal const val MODULE_PROGRESS_EVIDENCE_BYTES = 16L * 1024 * 1024

/** Reads only the attempt's own fixed report names; a changed attempt version refuses the capture. */
internal fun WebJobService.readModuleProgress(jobId: String, runId: String): WebModuleProgressCapture {
    val attempt = getAttempt(jobId, runId)
    // An absent, oversized or replaced report is unrecorded for this read; it never fails the whole view.
    fun read(name: String, maximum: Long): ByteArray? = if (attempt.workflow != WorkflowKind.RECONSTRUCT) null else try {
        readArtifact(jobId, "reports/runs/${attempt.runId}/$name", maximum).bytes
    } catch (_: JobStoreException) { null } catch (failure: Exception) {
        if (failure is InterruptedException || failure is WebJobServiceException) throw failure
        null
    }
    val progress = read("reconstruction_progress.json", MODULE_PROGRESS_SMALL_BYTES)
    val capture = WebModuleProgressCapture(attempt, progress, read("reconstruction.json", MODULE_PROGRESS_SMALL_BYTES),
        read("source-tree/reports/module_plan.json", MODULE_PROGRESS_EVIDENCE_BYTES),
        // Per-module outcomes are written when generation finishes, before the build; skip the large read only
        // while an active attempt is still generating modules.
        if (generationFinished(parsedProgress(progress)) || attempt.state.terminal)
            read("source-tree/reports/confidence.json", MODULE_PROGRESS_EVIDENCE_BYTES) else null)
    if (getAttempt(jobId, runId).version != attempt.version)
        throw WebAccessDenied(409, "REPORT_CHANGED", "The attempt changed during this read. Refresh its module progress.")
    return capture
}

private data class ReportedProgress(val phase: String, val completed: Long, val total: Long, val module: String?)
private data class ReportedSummary(val moduleCount: Long, val buildExitCode: Long, val unresolvedEntityCount: Long, val profileSha256: String)
private data class ReportedPlan(val sha256: String, val moduleIds: List<String>)

private val SMALL = StrictJsonLimits(MODULE_PROGRESS_SMALL_BYTES.toInt(), MODULE_PROGRESS_SMALL_BYTES.toInt(), 8, 256, 1024,
    MODULE_PROGRESS_SMALL_BYTES.toInt(), 32)
private val LARGE = StrictJsonLimits(MODULE_PROGRESS_EVIDENCE_BYTES.toInt(), MODULE_PROGRESS_EVIDENCE_BYTES.toInt(), 32, 1_000_000,
    16 * 1024, MODULE_PROGRESS_EVIDENCE_BYTES.toInt(), 32)
private val MODULE_ID = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
private val DIGEST = Regex("[0-9a-f]{64}")
private const val MAXIMUM_LISTED_MODULES = 100

private fun parse(bytes: ByteArray?, limits: StrictJsonLimits): JsonObject? = bytes?.let {
    try { OracleJson.parse(it, limits) as? JsonObject } catch (_: Exception) { null }
}
private fun JsonObject.text(name: String): String? = (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
private fun JsonObject.count(name: String): Long? = (this[name] as? JsonPrimitive)?.takeUnless { it.isString }
    ?.content?.takeIf { it.matches(Regex("0|[1-9][0-9]{0,17}")) }?.toLong()

/** A partially rewritten or unknown progress record is unknown, never a stage outcome. */
private fun parsedProgress(bytes: ByteArray?): ReportedProgress? {
    val root = parse(bytes, SMALL) ?: return null
    val phase = root.text("phase")?.takeIf { it in setOf("planning", "modules", "complete", "unresolved") } ?: return null
    val completed = root.count("completed") ?: return null
    val total = root.count("total") ?: return null
    if (completed > total) return null
    return ReportedProgress(phase, completed, total, root.text("module")?.takeIf(MODULE_ID::matches))
}

/** Generation finished once every planned module is generated, even if the later build never completes. */
private fun generationFinished(progress: ReportedProgress?): Boolean = progress != null &&
    (progress.phase in setOf("complete", "unresolved") || progress.phase == "modules" && progress.total > 0 && progress.completed == progress.total)

private fun parsedSummary(bytes: ByteArray?): ReportedSummary? {
    val root = parse(bytes, SMALL) ?: return null
    val profile = root.text("profileSha256")?.takeIf(DIGEST::matches) ?: return null
    // The exit code is an integer the producer wrote; a negative value is a signal-style failure.
    val exit = (root["buildExitCode"] as? JsonPrimitive)?.takeUnless { it.isString }?.content?.toLongOrNull() ?: return null
    return ReportedSummary(root.count("moduleCount") ?: return null, exit, root.count("unresolvedEntityCount") ?: return null, profile)
}

private fun parsedPlan(bytes: ByteArray?): ReportedPlan? = bytes?.let {
    try {
        val plan = ModulePlanJson.readCanonical(it, MODULE_PROGRESS_EVIDENCE_BYTES.toInt())
        val ids = plan.modules.map { module -> module.id }
        if (ids.any { id -> !MODULE_ID.matches(id) } || ids.distinct().size != ids.size) null
        else ReportedPlan(WebExplorationArtifact.sha256(it), ids.sorted())
    } catch (failure: Exception) {
        if (failure is InterruptedException) throw failure
        null
    }
}

/** Planned modules the generation record reports as unresolved, restricted to the recorded plan. */
private fun unresolvedModules(bytes: ByteArray?, plan: ReportedPlan?): List<String>? {
    val root = parse(bytes, LARGE) ?: return null
    val modules = ((root["sourceGenerationBudgetEvidence"] as? JsonObject)?.get("modules") as? JsonArray) ?: return null
    val planned = plan?.moduleIds?.toSet() ?: return null
    val outcomes = modules.map { row ->
        val item = row as? JsonObject ?: return null
        val id = item.text("moduleId")?.takeIf { it in planned } ?: return null
        id to (item.text("outcome") ?: return null)
    }
    if (outcomes.map { it.first }.toSet() != planned || outcomes.size != planned.size) return null
    return outcomes.filter { it.second != "accepted" }.map { it.first }.sorted()
}

/** One option's view of a retained plan: whether a recovery could reuse it, and why not. */
internal data class WebPlanCompatibility(val optionId: String, val compatibility: String, val reasonCode: String?)

/**
 * Compares a retained attempt's recorded configuration with a currently registered reconstruction option.
 * The core generator remains the authority: it reuses a module checkpoint only when the input, profile,
 * plan fingerprint, reconstructor identity and execution evidence all match. This explains in advance
 * which of those a recovery could satisfy; it never selects or reuses anything itself.
 */
internal fun webPlanCompatibility(attempt: WorkflowAttempt, adapter: DurableWebWorkflowAdapter,
    prerequisites: WebWorkflowPrerequisites?): WebPlanCompatibility {
    val optionId = webWorkflowCapabilityId(adapter)
    fun result(compatibility: String, reason: String?) = WebPlanCompatibility(optionId, compatibility, reason)
    val recorded = attempt.configuration ?: return result("unknown", "CONFIGURATION_NOT_RECORDED")
    val reconstruction = recorded.reconstruction ?: return result("unknown", "CONFIGURATION_NOT_RECORDED")
    val scope = adapter.reconstruction ?: return result("incompatible", "PROFILE_CHANGED")
    // A different profile digest means the deterministic planner would produce a different plan.
    if (scope.profileSha256 != reconstruction.profileSha256) return result("incompatible", "PROFILE_CHANGED")
    val harness = adapter.launch?.harness
    val recordedHarness = recorded.harness
    if ((harness == null) != (recordedHarness == null) || harness != null && harness.wireName != recordedHarness?.kind)
        return result("stale", "HARNESS_DIFFERS")
    if (harness != null && recordedHarness != null) {
        val current = prerequisites?.harnesses?.get(harness)?.provenance ?: return result("unknown", "HARNESS_UNRESOLVED")
        if (current.stableDescriptor != WebAdmittedHarness.of(harness, recordedHarness).expectedDescriptor)
            return result("stale", "HARNESS_CONFIGURATION_CHANGED")
    }
    if (reconstruction.maxContextCharacters != null && scope.defaultContextCharacters?.toULong() != reconstruction.maxContextCharacters)
        return result("stale", "CONTEXT_DIFFERS")
    return result("compatible", null)
}

/**
 * Stage-separated module progress for one attempt, from its own retained reports and durable state.
 * Stages are analysis, planning, generation, validation (the profile build) and publication (the
 * recorded candidate revision); unresolved modules are reported from the generation record.
 */
internal fun webModuleProgress(jobId: String, capture: WebModuleProgressCapture, options: List<DurableWebWorkflowAdapter>,
    prerequisites: WebWorkflowPrerequisites?): JsonObject {
    val attempt = capture.attempt
    val reconstruct = attempt.workflow == WorkflowKind.RECONSTRUCT
    val progress = parsedProgress(capture.progress)
    val summary = parsedSummary(capture.summary)
    val plan = parsedPlan(capture.plan)
    val unresolved = unresolvedModules(capture.generation, plan)
    val queued = attempt.state == WorkflowRunState.QUEUED
    val running = attempt.state == WorkflowRunState.RUNNING || attempt.state == WorkflowRunState.CANCELLING
    val phase = progress?.phase

    fun ended(reached: Boolean) = when { queued -> "pending"; running -> if (reached) "active" else "pending"; reached -> "stopped"; else -> "not-reached" }
    // Evidence that a later stage finished establishes every earlier one. Reports are captured separately and may
    // be missing, oversized or from different moments, so the stages are reconciled into one ordered sequence.
    val validationDone = summary != null
    val generationDone = validationDone || generationFinished(progress)
    val planningDone = generationDone || phase == "modules" || plan != null && phase != "planning"
    val analysisDone = planningDone || progress != null || plan != null
    val published = attempt.candidate != null || attempt.acceptedRevision != null
    fun stage(name: String, done: Boolean, previousDone: Boolean, completed: Long? = null, total: Long? = null, outcome: String? = null) = buildJsonObject {
        put("stage", name)
        put("state", if (done) "completed" else ended(previousDone))
        put("completedUnits", completed?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
        put("totalUnits", total?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
        put("outcome", outcome?.let(::JsonPrimitive) ?: JsonNull)
    }
    val stages = if (!reconstruct) emptyList() else listOf(
        stage("analysis", analysisDone, true),
        stage("planning", planningDone, analysisDone, outcome = if (plan != null) "plan-recorded" else null),
        // The final summary outranks a progress record captured at another moment.
        stage("generation", generationDone, planningDone, summary?.moduleCount ?: progress?.completed, summary?.moduleCount ?: progress?.total),
        stage("validation", validationDone, generationDone, outcome = summary?.let { if (it.buildExitCode == 0L) "build-passed" else "build-failed" }),
        // A candidate retained after an unfinished build is recorded, but its publication never completed.
        stage("publication", published && validationDone, validationDone || published, outcome = when {
            attempt.acceptedRevision != null -> "accepted"
            attempt.candidate != null -> "candidate-recorded"
            else -> null
        }),
    )
    val recoverable = reconstruct && attempt.state in setOf(WorkflowRunState.FAILED, WorkflowRunState.CANCELLED, WorkflowRunState.INTERRUPTED)
    val recoveryReason = when {
        !reconstruct -> null
        !attempt.state.terminal -> "ATTEMPT_ACTIVE"
        !recoverable -> "ATTEMPT_COMPLETED"
        attempt.configuration == null -> "CONFIGURATION_NOT_RECORDED"
        plan == null -> "PLAN_NOT_RECORDED"
        else -> null
    }
    return buildJsonObject {
        put("binding", buildJsonObject { put("jobId", jobId); put("runId", attempt.runId) })
        put("workflow", attempt.workflow.wireName)
        put("attemptState", attempt.state.wireName)
        put("attemptVersion", attempt.version)
        put("state", when { !reconstruct -> "not-applicable"; progress == null && plan == null && summary == null -> "not-recorded"; else -> "recorded" })
        put("stages", JsonArray(stages))
        put("plan", plan?.let { recorded -> buildJsonObject {
            put("sha256", recorded.sha256); put("moduleCount", recorded.moduleIds.size.toString())
            put("profileId", attempt.configuration?.reconstruction?.profileId?.let(::JsonPrimitive) ?: JsonNull)
        } } ?: JsonNull)
        // The progress record names a module only after it finished; it is the last generated one while others remain.
        put("lastGeneratedModuleId", progress?.module?.takeIf { running && !generationFinished(progress) && phase == "modules" }
            ?.let(::JsonPrimitive) ?: JsonNull)
        put("unresolved", if (!reconstruct) JsonNull else buildJsonObject {
            put("moduleCount", unresolved?.let { JsonPrimitive(it.size.toString()) } ?: JsonNull)
            put("entityCount", summary?.let { JsonPrimitive(it.unresolvedEntityCount.toString()) } ?: JsonNull)
            put("moduleIds", JsonArray(unresolved.orEmpty().take(MAXIMUM_LISTED_MODULES).map(::JsonPrimitive)))
            put("truncated", (unresolved?.size ?: 0) > MAXIMUM_LISTED_MODULES)
        })
        put("recovery", if (!reconstruct) JsonNull else buildJsonObject {
            put("eligible", recoveryReason == null)
            put("reasonCode", recoveryReason?.let(::JsonPrimitive) ?: JsonNull)
            put("planSha256", plan?.sha256?.let(::JsonPrimitive) ?: JsonNull)
            // Modules whose generation finished before the attempt ended; their checkpoints are retained.
            put("retainedModules", progress?.takeIf { recoverable && it.phase == "modules" }?.let { JsonPrimitive(it.completed.toString()) } ?: JsonNull)
            put("recordedContextCharacters", attempt.configuration?.reconstruction?.maxContextCharacters?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
            put("options", JsonArray(if (recoveryReason != null) emptyList() else options
                .filter { it.workflow == WorkflowKind.RECONSTRUCT && it.launch != null }
                .map { webPlanCompatibility(attempt, it, prerequisites) }
                .map { row -> buildJsonObject {
                    put("optionId", row.optionId); put("compatibility", row.compatibility)
                    put("reasonCode", row.reasonCode?.let(::JsonPrimitive) ?: JsonNull)
                } }))
        })
        put("limitations", JsonArray(listOf(
            "Progress comes from this attempt's own retained reports and durable state; it is not validation or acceptance.",
            "The deterministic planner owns every module boundary. A recovery reuses a module only when the core generator verifies its checkpoint.",
        ).map(::JsonPrimitive)))
    }
}
