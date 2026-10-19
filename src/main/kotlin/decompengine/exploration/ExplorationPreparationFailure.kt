package decompengine.exploration

import kotlinx.serialization.json.*
import java.io.IOException

internal const val EXPLORATION_PREPARATION_FAILURE_SCHEMA = "decomp-exploration-preparation-failure"
internal enum class ExplorationPreparationStage(val wire: String) {
    ANGR("angr-generation"), STATIC_HINTS("static-hints"), MUTATIONS("mutation-expansion"),
}
internal enum class ExplorationPreparationReason(val kind: String, val code: String) {
    FAILED("generation-failure", "candidate-generation-failed"),
    IO_FAILED("generation-failure", "candidate-generation-io-failed"),
    INTERRUPTED("interrupted", "candidate-generation-interrupted");
    companion object {
        fun from(failure: Exception) = when (failure) {
            is InterruptedException -> INTERRUPTED
            is IOException -> IO_FAILED
            else -> FAILED
        }
    }
}

/** Same callbacks, order and multiplicity; a failed generator never advances to a later stage. */
internal fun proposeExplorationInputs(
    seeds: List<CandidateInput>,
    angr: () -> List<CandidateInput>,
    staticHints: () -> List<CandidateInput>,
    mutate: (List<CandidateInput>) -> List<CandidateInput>,
    retainFailure: (ExplorationPreparationFailureRecord) -> Unit,
): List<CandidateInput> {
    var angrInputs: List<CandidateInput>? = null
    var staticInputs: List<CandidateInput>? = null
    fun <T> capture(stage: ExplorationPreparationStage, action: () -> T): T = try {
        action()
    } catch (failure: Exception) {
        try {
            retainFailure(ExplorationPreparationFailureRecord(stage, ExplorationPreparationReason.from(failure), seeds, angrInputs, staticInputs))
        } catch (retentionFailure: Exception) {
            if (retentionFailure !== failure) failure.addSuppressed(retentionFailure)
        }
        throw failure
    }
    val generated = seeds + capture(ExplorationPreparationStage.ANGR, angr).also { angrInputs = it } +
        capture(ExplorationPreparationStage.STATIC_HINTS, staticHints).also { staticInputs = it }
    return generated + capture(ExplorationPreparationStage.MUTATIONS) { mutate(generated) }
}

internal data class ExplorationPreparationFailureRecord(
    val stage: ExplorationPreparationStage,
    val reason: ExplorationPreparationReason,
    val seeds: List<CandidateInput>,
    val angr: List<CandidateInput>?,
    val staticHints: List<CandidateInput>?,
) {
    fun toJson(): String {
        val include = detailsWithinBudget()
        fun inputs(values: List<CandidateInput>?): JsonElement = values?.let { list -> JsonArray(list.map { value ->
            buildJsonObject {
                put("id", value.id); put("source", value.source.name)
                put("args", JsonArray(value.args.map(::JsonPrimitive)))
                put("stdinHex", value.stdin.joinToString("") { "%02x".format(it) })
            }
        }) } ?: JsonNull
        return buildJsonObject {
            put("schema", EXPLORATION_PREPARATION_FAILURE_SCHEMA); put("schemaVersion", 1); put("state", "partial")
            put("failure", buildJsonObject { put("stage", stage.wire); put("kind", reason.kind); put("code", reason.code) })
            put("availableInputs", buildJsonObject {
                put("seeds", seeds.size); put("angr", angr?.size?.let(::JsonPrimitive) ?: JsonNull)
                put("staticHints", staticHints?.size?.let(::JsonPrimitive) ?: JsonNull); put("expanded", JsonNull)
            })
            put("observationState", "not-started")
            put("details", if (include) buildJsonObject {
                put("seeds", inputs(seeds)); put("angr", inputs(angr)); put("staticHints", inputs(staticHints))
            } else JsonNull)
            put("detailsOmitted", if (include) JsonNull else JsonPrimitive("detail-budget"))
            put("coverage", JsonNull); put("confidence", JsonNull)
        }.toString() + "\n"
    }

    private fun detailsWithinBudget(): Boolean {
        var bytes = 1_000_000L
        var nodes = 90_000
        for (group in listOfNotNull(seeds, angr, staticHints)) {
            if (group.size > 1000) return false
            for (input in group) {
                if (input.id.length > 128 || input.args.size > 256) return false
                nodes -= 16 + input.args.size
                bytes -= 256L + 6L * (input.id.length.toLong() + input.source.name.length) + 12L * input.stdin.size
                if (bytes < 0 || nodes < 0) return false
                for (arg in input.args) {
                    bytes -= 8L + 6L * arg.length
                    if (bytes < 0) return false
                }
            }
        }
        return true
    }
}

/** Reported preparation progress supplies neither candidate results nor launch/cleanup authority. */
internal fun explorationPreparationFailureLimitation(root: JsonObject): String {
    fun exact(value: JsonObject, vararg fields: String) = require(value.keys == fields.toSet())
    fun text(value: JsonObject, name: String): String = value.getValue(name).jsonPrimitive.let {
        require(it.isString); it.content
    }
    fun count(value: JsonElement): Int = value.jsonPrimitive.let {
        require(!it.isString); requireNotNull(it.intOrNull).also { number -> require(number >= 0) }
    }
    exact(root, "schema", "schemaVersion", "state", "failure", "availableInputs", "observationState", "details", "detailsOmitted", "coverage", "confidence")
    require(text(root, "schema") == EXPLORATION_PREPARATION_FAILURE_SCHEMA && count(root.getValue("schemaVersion")) == 1)
    require(text(root, "state") == "partial" && text(root, "observationState") == "not-started")
    require(root.getValue("coverage") == JsonNull && root.getValue("confidence") == JsonNull)
    val failure = root.getValue("failure").jsonObject
    exact(failure, "stage", "kind", "code")
    val stage = ExplorationPreparationStage.entries.single { it.wire == text(failure, "stage") }
    val reason = ExplorationPreparationReason.entries.single { it.kind == text(failure, "kind") && it.code == text(failure, "code") }
    val available = root.getValue("availableInputs").jsonObject
    exact(available, "seeds", "angr", "staticHints", "expanded")
    count(available.getValue("seeds"))
    val angr = available.getValue("angr").takeUnless { it == JsonNull }?.let(::count)
    val staticHints = available.getValue("staticHints").takeUnless { it == JsonNull }?.let(::count)
    require(available.getValue("expanded") == JsonNull)
    when (stage) {
        ExplorationPreparationStage.ANGR -> require(angr == null && staticHints == null)
        ExplorationPreparationStage.STATIC_HINTS -> require(angr != null && staticHints == null)
        ExplorationPreparationStage.MUTATIONS -> require(angr != null && staticHints != null)
    }
    val detail = root.getValue("details")
    if (detail == JsonNull) require(text(root, "detailsOmitted") == "detail-budget")
    else {
        require(root.getValue("detailsOmitted") == JsonNull)
        val groups = detail.jsonObject
        exact(groups, "seeds", "angr", "staticHints")
        for (group in listOf("seeds", "angr", "staticHints")) {
            val expected = available.getValue(group)
            val values = groups.getValue(group)
            if (expected == JsonNull) require(values == JsonNull)
            else {
                val inputs = values.jsonArray
                require(inputs.size == count(expected) && inputs.size <= 1000)
                inputs.forEach { item ->
                    val input = item.jsonObject
                    exact(input, "id", "source", "args", "stdinHex")
                    require(text(input, "id").length <= 128)
                    CandidateSource.valueOf(text(input, "source"))
                    val args = input.getValue("args").jsonArray
                    require(args.size <= 256); args.forEach { require(it.jsonPrimitive.isString) }
                    val hex = text(input, "stdinHex")
                    require(hex.length % 2 == 0 && hex.all { it in '0'..'9' || it in 'a'..'f' })
                }
            }
        }
    }
    val omitted = if (detail == JsonNull) " Input details were omitted by their budget." else ""
    return "The producer reported ${reason.code} during ${stage.wire}, before candidate observation started." +
        " The final expanded proposal and sample counts are unknown; coverage and confidence are unavailable." +
        " This record does not establish tooling availability, launch, cleanup, containment or acceptance.$omitted"
}
