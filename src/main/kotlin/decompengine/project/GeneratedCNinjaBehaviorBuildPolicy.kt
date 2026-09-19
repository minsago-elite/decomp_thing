package decompengine.project

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/** Ninja behavior evidence keeps the exact profile-owned build invocation and budgets. */
internal object GeneratedCNinjaBehaviorBuildPolicy : BehaviorBuildPolicy by GeneratedCBehaviorBuildPolicy {
    override fun parseContract(contract: JsonObject, profile: ReconstructionProfile): BehaviorBuildContract {
        val parsed = GeneratedCBehaviorBuildPolicy.parseContract(contract, profile)
        fun number(name: String): Long {
            val value = contract.getValue(name).jsonPrimitive
            require(!value.isString) { "Ninja build $name must be numeric" }
            return requireNotNull(value.longOrNull) { "Ninja build $name must be an integer" }
        }
        fun strings(name: String): List<String> = contract.getValue(name).jsonArray.map {
            require(it.jsonPrimitive.isString) { "Ninja build $name must contain strings" }
            it.jsonPrimitive.content
        }
        val parallelism = number("parallelism")
        require(parallelism in 1..256) { "Ninja build parallelism is outside its supported range" }
        val expected = GeneratedCNinjaReconstructionAdapter.invocation(profile, parallelism.toInt())
        require(strings("command") == expected.command) { "Ninja build command differs from the selected profile" }
        require(strings("declaredDependencies") == expected.dependencies) { "Ninja build dependencies differ from the selected profile" }
        require(number("wallClockTimeoutMillis") in 1..profile.budgets.buildWallClockMillis) {
            "Ninja build time budget exceeds the selected profile"
        }
        require(number("maximumOutputBytes") in 1..profile.budgets.buildMaximumOutputBytes) {
            "Ninja build output budget exceeds the selected profile"
        }
        return parsed
    }
}
