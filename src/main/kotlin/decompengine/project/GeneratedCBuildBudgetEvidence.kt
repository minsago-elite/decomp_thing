package decompengine.project

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

internal const val GENERATED_C_BUILD_CONTRACT_SCHEMA_VERSION = 2

/** Checks the budget commitments retained by the shared generated-C build boundary. */
internal fun JsonObject.requireGeneratedCBuildBudgetEvidence(profile: ReconstructionProfile) {
    require(string("profileId") == profile.id) { "build contract profile ID differs from the selected profile" }
    require(string("profileSha256") == profile.sha256) { "build contract profile digest differs from the selected profile" }
    require(getValue("profileBudgets") == Json.parseToJsonElement(profile.budgets.canonicalJson()).jsonObject) {
        "build contract profile budgets differ from the selected profile"
    }

    val host = getValue("hostSafetyLimits").jsonObject
    require(host.keys == setOf("buildWallClockMillis", "buildMaximumOutputBytes")) {
        "build contract host safety limits are incomplete"
    }
    val hostWallClock = host.number("buildWallClockMillis")
    val hostOutput = host.number("buildMaximumOutputBytes")
    require(hostWallClock >= profile.budgets.buildWallClockMillis) {
        "build contract host wall-clock ceiling does not admit the selected profile"
    }
    require(hostOutput >= profile.budgets.buildMaximumOutputBytes) {
        "build contract host output ceiling does not admit the selected profile"
    }

    val configuration = getValue("configuration").jsonObject
    require(configuration.keys == setOf(
        "makeExecutable", "compilerExecutable", "parallelism", "cFlags",
        "wallClockTimeoutMillis", "maximumOutputBytes", "terminationGraceMillis", "buildDefinition",
    )) { "build contract configuration is incomplete" }
    require(configuration.string("makeExecutable").isNotBlank())
    require(configuration.string("compilerExecutable").isNotBlank())
    require(configuration.string("buildDefinition") == profile.layout.declaration("build-definition").materialize()) {
        "build contract build definition differs from the selected profile"
    }
    val flags = configuration.getValue("cFlags").jsonArray
    require(flags.isNotEmpty() && flags.all { it.jsonPrimitive.isString }) {
        "build contract compiler flags are invalid"
    }
    val configuredParallelism = configuration.number("parallelism")
    require(configuredParallelism in 1..256 && configuredParallelism == number("parallelism")) {
        "build contract parallelism is inconsistent"
    }
    val configuredWallClock = configuration.number("wallClockTimeoutMillis")
    val configuredOutput = configuration.number("maximumOutputBytes")
    require(configuration.number("terminationGraceMillis") in 0..30_000)
    require(configuredWallClock == number("wallClockTimeoutMillis") &&
        configuredOutput == number("maximumOutputBytes")) {
        "build contract effective limits are inconsistent with its configuration"
    }
    require(configuredWallClock in 1..profile.budgets.buildWallClockMillis && configuredWallClock <= hostWallClock) {
        "build contract wall-clock limit exceeds an admitted ceiling"
    }
    require(configuredOutput in 1..profile.budgets.buildMaximumOutputBytes && configuredOutput <= hostOutput) {
        "build contract output limit exceeds an admitted ceiling"
    }
}

private fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.also {
    require(it.isString) { "$name must be a string" }
}.content

private fun JsonObject.number(name: String): Long = getValue(name).jsonPrimitive.also {
    require(!it.isString) { "$name must be an integer" }
}.longOrNull ?: throw IllegalArgumentException("$name must be an integer")

