package decompengine.project

import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.RepairResourceBudget
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Host-owned ceilings for contained generated-C validation processes. */
internal data class GeneratedCValidationHostSafetyLimits(
    val maximumStdoutBytes: Long = 8L * 1024 * 1024,
    val maximumStderrBytes: Long = 8L * 1024 * 1024,
    val maximumOutputBytes: Long = 16L * 1024 * 1024,
    val maximumExecutionMillis: Long = 30_000,
) {
    init {
        require(maximumStdoutBytes > 0 && maximumStderrBytes > 0)
        require(maximumOutputBytes >= maxOf(maximumStdoutBytes, maximumStderrBytes))
        require(maximumExecutionMillis > 0)
    }
}

/** Admits the immutable repair budget before a validation snapshot or child process is created. */
internal class GeneratedCValidationBudgetPolicy(
    private val host: GeneratedCValidationHostSafetyLimits = GeneratedCValidationHostSafetyLimits(),
) {
    fun admit(budget: RepairResourceBudget): JsonObject {
        if (budget.maximumBehaviorStdoutBytes > host.maximumStdoutBytes ||
            budget.maximumBehaviorStderrBytes > host.maximumStderrBytes ||
            budget.maximumBehaviorOutputBytes > host.maximumOutputBytes ||
            budget.maximumBehaviorExecutionMillis > host.maximumExecutionMillis) {
            throw RepairBudgetExceededException("generated-C validation budget exceeds independent host ceilings")
        }
        return evidence(budget)
    }

    fun evidence(budget: RepairResourceBudget): JsonObject = JsonObject(mapOf(
        "profileLimits" to limits(budget.maximumBehaviorStdoutBytes, budget.maximumBehaviorStderrBytes,
            budget.maximumBehaviorOutputBytes, budget.maximumBehaviorExecutionMillis),
        "hostSafetyLimits" to limits(host.maximumStdoutBytes, host.maximumStderrBytes,
            host.maximumOutputBytes, host.maximumExecutionMillis),
        "effectiveLimits" to limits(minOf(budget.maximumBehaviorStdoutBytes, host.maximumStdoutBytes),
            minOf(budget.maximumBehaviorStderrBytes, host.maximumStderrBytes),
            minOf(budget.maximumBehaviorOutputBytes, host.maximumOutputBytes),
            minOf(budget.maximumBehaviorExecutionMillis, host.maximumExecutionMillis)),
    ))

    private fun limits(stdout: Long, stderr: Long, output: Long, millis: Long): JsonObject = JsonObject(mapOf(
        "maximumStdoutBytes" to JsonPrimitive(stdout),
        "maximumStderrBytes" to JsonPrimitive(stderr),
        "maximumOutputBytes" to JsonPrimitive(output),
        "maximumExecutionMillis" to JsonPrimitive(millis),
    ))

    companion object {
        val DEFAULT = GeneratedCValidationBudgetPolicy()
    }
}
