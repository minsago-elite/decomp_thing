package decompengine.exploration

import decompengine.validation.BehaviorExecutionOutcomeException
import decompengine.validation.BehaviorExecutionTimeoutException
import decompengine.validation.BehaviorOutputLimitException
import decompengine.validation.SandboxUnavailableException
import kotlinx.serialization.json.*
import java.io.IOException

internal const val EXPLORATION_FAILURE_SCHEMA = "decomp-exploration-failure"
private const val MAXIMUM_DETAIL_CASES = 1000
private const val MAXIMUM_DETAIL_ARGUMENTS = 256

internal enum class ExplorationSamplePhase(val wire: String) {
    BASELINE("baseline"), EXPANDED("expanded"),
}

internal enum class ExplorationFailureReason(val kind: String, val code: String, val description: String) {
    TIMEOUT("timeout", "behavior-deadline-exceeded", "a timeout"),
    SANDBOX_UNAVAILABLE("tooling-unavailable", "sandbox-unavailable", "unavailable sandbox tooling"),
    OUTPUT_LIMIT("execution-failure", "output-limit-exceeded", "an output-limit failure"),
    UNVERIFIED_COMPLETION("execution-failure", "completion-unverified", "unverified execution completion"),
    INTERRUPTED("interrupted", "producer-interrupted", "an interruption"),
    IO_FAILURE("execution-failure", "execution-io-failed", "an execution I/O failure"),
    UNCLASSIFIED("unclassified", "unclassified-exception", "an unclassified producer exception");

    companion object {
        fun from(failure: Exception): ExplorationFailureReason = when (failure) {
            is BehaviorExecutionTimeoutException -> TIMEOUT
            is SandboxUnavailableException -> SANDBOX_UNAVAILABLE
            is BehaviorOutputLimitException -> OUTPUT_LIMIT
            is BehaviorExecutionOutcomeException -> UNVERIFIED_COMPLETION
            is InterruptedException -> INTERRUPTED
            is IOException -> IO_FAILURE
            else -> UNCLASSIFIED
        }
    }
}

/** Retention is metadata only: neither continuing work nor replacing the original failure. */
internal class ExplorationFailureCapture(
    private val baseline: List<CandidateInput>,
    private val expanded: List<CandidateInput>,
    private val retain: (ExplorationFailureRecord) -> Unit,
) {
    private val baselineObserved = mutableListOf<CandidateObservation>()
    private val expandedObserved = mutableListOf<CandidateObservation>()
    private var baselineCompleted = 0
    private var expandedCompleted = 0

    fun completed(phase: ExplorationSamplePhase, observation: CandidateObservation) {
        val observations = if (phase == ExplorationSamplePhase.BASELINE) baselineObserved else expandedObserved
        if (observations.size < MAXIMUM_DETAIL_CASES) observations += observation
        if (phase == ExplorationSamplePhase.BASELINE) baselineCompleted++ else expandedCompleted++
    }

    fun failed(phase: ExplorationSamplePhase, candidateIndex: Int, failure: Exception): Nothing = retainExplorationFailure(failure) {
        retain(ExplorationFailureRecord(
            phase, candidateIndex, ExplorationFailureReason.from(failure), baseline, expanded,
            baselineCompleted, expandedCompleted, baselineObserved.toList(), expandedObserved.toList(),
        ))
    }
}

/** Clear only around bounded metadata retention; preserve old and newly arriving interrupts. */
internal fun retainExplorationFailure(
    failure: Exception,
    takeInterrupt: () -> Boolean = { Thread.interrupted() },
    restoreInterrupt: () -> Unit = { Thread.currentThread().interrupt() },
    retain: () -> Unit,
): Nothing {
    val interrupted = takeInterrupt()
    try {
        try { retain() } catch (retentionFailure: Exception) {
            if (retentionFailure !== failure) failure.addSuppressed(retentionFailure)
        }
    } finally {
        if (interrupted) restoreInterrupt()
    }
    throw failure
}

internal data class ExplorationFailureRecord(
    val phase: ExplorationSamplePhase,
    val candidateIndex: Int,
    val reason: ExplorationFailureReason,
    val baseline: List<CandidateInput>,
    val expanded: List<CandidateInput>,
    val baselineCompleted: Int,
    val expandedCompleted: Int,
    val baselineObserved: List<CandidateObservation>,
    val expandedObserved: List<CandidateObservation>,
) {
    fun toJson(): String {
        val includeDetails = detailsWithinBudget()
        return buildJsonObject {
            put("schema", EXPLORATION_FAILURE_SCHEMA)
            put("schemaVersion", 1)
            put("state", "partial")
            put("failure", buildJsonObject {
                put("phase", phase.wire); put("candidateIndex", candidateIndex)
                put("kind", reason.kind); put("code", reason.code)
            })
            put("samples", buildJsonObject {
                put("baselineInputs", baseline.size); put("expandedInputs", expanded.size)
                put("baselineObserved", baselineCompleted); put("expandedObserved", expandedCompleted)
            })
            put("details", if (includeDetails) buildJsonObject {
                put("baselineInputs", JsonArray(baseline.map { it.failureJson() }))
                put("expandedInputs", JsonArray(expanded.map { it.failureJson() }))
                put("baselineObservations", JsonArray(baselineObserved.map { it.failureJson() }))
                put("expandedObservations", JsonArray(expandedObserved.map { it.failureJson() }))
            } else JsonNull)
            put("detailsOmitted", if (includeDetails) JsonNull else JsonPrimitive("detail-budget"))
            put("coverage", JsonNull); put("confidence", JsonNull)
        }.toString() + "\n"
    }

    /** Conservative UTF-8/JSON upper bound before allocating any detail JSON tree or output. */
    private fun detailsWithinBudget(): Boolean {
        if (baseline.size > MAXIMUM_DETAIL_CASES || expanded.size > MAXIMUM_DETAIL_CASES ||
            baselineObserved.size != baselineCompleted || expandedObserved.size != expandedCompleted
        ) return false
        var remaining = 1_000_000L
        var remainingNodes = 90_000
        for (inputs in listOf(baseline, expanded)) for (input in inputs) {
            if (input.id.length > 128 || input.args.size > MAXIMUM_DETAIL_ARGUMENTS) return false
            remainingNodes -= 16 + input.args.size
            remaining -= 256L + 6L * (input.id.length.toLong() + input.source.name.length) + 12L * input.stdin.size
            if (remaining < 0 || remainingNodes < 0) return false
            for (arg in input.args) {
                remaining -= 8L + 6L * arg.length
                if (remaining < 0) return false
            }
        }
        for (observations in listOf(baselineObserved, expandedObserved)) for (observation in observations) {
            remainingNodes -= 24
            remaining -= 256L + 6L * (observation.candidateId.length.toLong() + observation.signature.length +
                observation.stdoutHex.length + observation.stderrHex.length)
            if (remaining < 0 || remainingNodes < 0) return false
        }
        return true
    }
}

private fun CandidateInput.failureJson() = buildJsonObject {
    put("id", id); put("source", source.name)
    put("args", JsonArray(args.map(::JsonPrimitive)))
    put("stdinHex", stdin.joinToString("") { "%02x".format(it) })
}

private fun CandidateObservation.failureJson() = buildJsonObject {
    put("candidateId", candidateId); put("signature", signature); put("exitCode", exitCode)
    put("stdoutHex", stdoutHex); put("stderrHex", stderrHex); put("networkIsolated", networkIsolated)
}

/** Validate only a known producer record. Its exception classification is not oracle authority. */
internal fun explorationFailureLimitation(root: JsonObject): String {
    fun exact(value: JsonObject, vararg fields: String) = require(value.keys == fields.toSet())
    fun count(value: JsonObject, name: String): Int {
        val number = value.getValue(name).jsonPrimitive
        require(!number.isString)
        return requireNotNull(number.intOrNull).also { require(it >= 0) }
    }
    fun text(value: JsonObject, name: String): String {
        val string = value.getValue(name).jsonPrimitive
        require(string.isString)
        return string.content
    }
    fun hex(value: JsonObject, name: String): String = text(value, name).also { string ->
        require(string.length % 2 == 0 && string.all { it in '0'..'9' || it in 'a'..'f' })
    }
    exact(root, "schema", "schemaVersion", "state", "failure", "samples", "details", "detailsOmitted", "coverage", "confidence")
    require(text(root, "schema") == EXPLORATION_FAILURE_SCHEMA && count(root, "schemaVersion") == 1)
    require(text(root, "state") == "partial" && root.getValue("coverage") == JsonNull && root.getValue("confidence") == JsonNull)
    val failure = root.getValue("failure").jsonObject
    exact(failure, "phase", "candidateIndex", "kind", "code")
    val phase = ExplorationSamplePhase.entries.single { it.wire == text(failure, "phase") }
    val reason = ExplorationFailureReason.entries.single {
        it.kind == text(failure, "kind") && it.code == text(failure, "code")
    }
    val index = count(failure, "candidateIndex")
    val samples = root.getValue("samples").jsonObject
    exact(samples, "baselineInputs", "expandedInputs", "baselineObserved", "expandedObserved")
    val baselineCount = count(samples, "baselineInputs"); val expandedCount = count(samples, "expandedInputs")
    val baselineObserved = count(samples, "baselineObserved"); val expandedObserved = count(samples, "expandedObserved")
    when (phase) {
        ExplorationSamplePhase.BASELINE -> require(index < baselineCount && baselineObserved == index && expandedObserved == 0)
        ExplorationSamplePhase.EXPANDED -> require(index < expandedCount && baselineObserved == baselineCount && expandedObserved == index)
    }
    val detail = root.getValue("details")
    if (detail == JsonNull) {
        require(text(root, "detailsOmitted") == "detail-budget")
    } else {
        require(root.getValue("detailsOmitted") == JsonNull)
        val value = detail.jsonObject
        exact(value, "baselineInputs", "expandedInputs", "baselineObservations", "expandedObservations")
        fun validateSample(inputsName: String, observationsName: String, planned: Int, completed: Int) {
            val inputs = value.getValue(inputsName).jsonArray
            val observations = value.getValue(observationsName).jsonArray
            require(inputs.size == planned && observations.size == completed && inputs.size <= MAXIMUM_DETAIL_CASES)
            inputs.forEach { item ->
                val input = item.jsonObject
                exact(input, "id", "source", "args", "stdinHex")
                require(text(input, "id").length <= 128)
                CandidateSource.valueOf(text(input, "source"))
                val args = input.getValue("args").jsonArray
                require(args.size <= MAXIMUM_DETAIL_ARGUMENTS)
                args.forEach { require(it.jsonPrimitive.isString) }
                hex(input, "stdinHex")
            }
            observations.forEachIndexed { position, item ->
                val observation = item.jsonObject
                exact(observation, "candidateId", "signature", "exitCode", "stdoutHex", "stderrHex", "networkIsolated")
                require(text(observation, "candidateId") == text(inputs[position].jsonObject, "id"))
                val exit = observation.getValue("exitCode").jsonPrimitive
                require(!exit.isString)
                val code = requireNotNull(exit.intOrNull)
                val stdout = hex(observation, "stdoutHex"); val stderr = hex(observation, "stderrHex")
                require(text(observation, "signature") == "$code:$stdout:$stderr")
                val isolated = observation.getValue("networkIsolated").jsonPrimitive
                require(!isolated.isString && isolated.booleanOrNull != null)
            }
        }
        validateSample("baselineInputs", "baselineObservations", baselineCount, baselineObserved)
        validateSample("expandedInputs", "expandedObservations", expandedCount, expandedObserved)
    }
    val omitted = if (detail == JsonNull) " Input/output detail was omitted by its budget." else ""
    return "The producer reported ${reason.description} while observing the ${phase.wire} sample at zero-based position $index." +
        " Coverage and confidence are unavailable; this record is not independent containment or acceptance evidence.$omitted"
}
