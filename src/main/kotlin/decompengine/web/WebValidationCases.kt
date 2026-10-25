package decompengine.web

import decompengine.jobs.WorkflowAttemptValidation
import decompengine.jobs.WorkflowValidationCases
import decompengine.repair.RepairHistoryReadStatus
import decompengine.repair.readProjectRecordedRepairHistory
import decompengine.repair.repairRegressionCorpusSha256
import decompengine.validation.ProcessInput
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.nio.file.Path
import java.util.TreeMap

/** The only server-approved validation case preset: the server's default case plus the revision's retained corpus. */
internal const val WEB_VALIDATION_PRESET = "retained-corpus-v1"
/** Server-defined cases every validation adds; the uploaded binary runs with no arguments and empty input. */
internal val WEB_VALIDATION_DEFAULT_CASES: List<ProcessInput> = listOf(ProcessInput("default"))

internal data class WebValidationCase(val caseId: String, val retained: Boolean, val arguments: List<String>?, val stdinBytes: Int)

/**
 * The exact corpus a validation of one retained source tree runs: the graph's retained cases merged with
 * the server defaults by identity, as the repair graph merges them. [corpusSha256] is that corpus's
 * canonical digest, so a request that names it names exactly these cases.
 */
internal data class WebValidationCasePlan(val reasonCode: String?, val corpusSha256: String?, val cases: List<WebValidationCase>) {
    val available: Boolean get() = reasonCode == null

    companion object {
        fun unavailable(reason: String) = WebValidationCasePlan(reason, null, emptyList())

        /** Read-only: the recorded graph metadata of [sourceTree], never a graph store or execution authority. */
        fun of(sourceTree: Path): WebValidationCasePlan {
            val displayIds = HashMap<String, String>()
            val history = readProjectRecordedRepairHistory(sourceTree)
            val retained = when (history.status) {
                RepairHistoryReadStatus.NOT_RECORDED -> emptyList()
                RepairHistoryReadStatus.UNAVAILABLE -> return unavailable("CASES_UNVERIFIABLE")
                RepairHistoryReadStatus.RECORDED -> {
                    val snapshot = checkNotNull(history.snapshot)
                    val inputs = history.retainedCorpus() ?: return unavailable("CASES_UNVERIFIABLE")
                    if (inputs.size != snapshot.retainedCases.size) return unavailable("CASES_UNVERIFIABLE")
                    // A recorded identifier outside the public identity form is shown by its opaque graph identity.
                    inputs.zip(snapshot.retainedCases).forEach { (input, identity) ->
                        if (!PUBLIC_ID.matches(input.id)) displayIds[input.id] = identity.value
                    }
                    if (repairRegressionCorpusSha256(inputs) != snapshot.corpusSha256) return unavailable("CASES_UNVERIFIABLE")
                    inputs
                }
            }
            val merged = TreeMap<String, ProcessInput>()
            retained.forEach { merged[it.id] = it }
            for (default in WEB_VALIDATION_DEFAULT_CASES) {
                val existing = merged.putIfAbsent(default.id, default)
                // The graph refuses a retained case that reuses a default identity with different data.
                if (existing != null && existing != default) return unavailable("CASES_UNVERIFIABLE")
            }
            val corpus = merged.values.toList()
            val retainedIds = retained.map { it.id }.toSet()
            return WebValidationCasePlan(null, repairRegressionCorpusSha256(corpus), corpus.map { input ->
                WebValidationCase(displayIds[input.id] ?: input.id, input.id in retainedIds, input.args.takeIf(::displayable), input.stdin.size)
            })
        }

        private val PUBLIC_ID = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")

        /** Arguments are shown only as short printable text; anything else stays recorded but undisplayed. */
        private fun displayable(arguments: List<String>): Boolean = arguments.size <= 16 &&
            arguments.all { argument -> argument.length <= 256 && argument.all { it.code in 0x20..0x7e } }
    }
}

/** Binds a request's reviewed selection to the plan admission recomputed; refusals are fixed codes. */
internal fun webAdmitValidationCases(plan: WebValidationCasePlan, requested: WorkflowValidationCases): WorkflowAttemptValidation {
    if (requested.presetId != WEB_VALIDATION_PRESET || !plan.available) throw WebJobServiceException("VALIDATION_CASES_UNAVAILABLE",
        "The selected revision's validation cases cannot be verified.")
    if (requested.corpusSha256 != plan.corpusSha256) throw WebJobServiceException("VALIDATION_CASES_CHANGED",
        "The selected revision's validation cases differ from the reviewed cases. Review them again.")
    return WorkflowAttemptValidation(WEB_VALIDATION_PRESET, requested.corpusSha256, plan.cases.size)
}

private const val MAXIMUM_LISTED_CASES = 50

/** `validationCasePlan`: the reviewed case definitions for one revision; display data, never runner configuration. */
internal fun webValidationCasePlan(jobId: String, revisionId: String, plan: WebValidationCasePlan): JsonObject = buildJsonObject {
    put("binding", buildJsonObject { put("jobId", jobId); put("revisionId", revisionId) })
    put("presetId", WEB_VALIDATION_PRESET)
    put("state", if (plan.available) "available" else "unavailable")
    put("reasonCode", plan.reasonCode?.let(::JsonPrimitive) ?: JsonNull)
    put("corpusSha256", plan.corpusSha256?.let(::JsonPrimitive) ?: JsonNull)
    put("totalCases", plan.cases.size)
    put("truncated", plan.cases.size > MAXIMUM_LISTED_CASES)
    put("cases", JsonArray(plan.cases.take(MAXIMUM_LISTED_CASES).map { case -> buildJsonObject {
        put("caseId", case.caseId)
        put("origin", if (case.retained) "retained" else "server-default")
        put("arguments", case.arguments?.let { JsonArray(it.map(::JsonPrimitive)) } ?: JsonNull)
        put("stdinBytes", case.stdinBytes.toString())
    } }))
    put("limitations", JsonArray(listOf(
        "Cases are recorded data the server runs inside its sandbox; they are never commands, paths or runner settings.",
        "A request names these cases only by the corpus digest. Admission recomputes it and refuses a different corpus.",
    ).map(::JsonPrimitive)))
}
