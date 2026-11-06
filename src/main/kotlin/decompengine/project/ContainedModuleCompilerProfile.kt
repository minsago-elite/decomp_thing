package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Only requested budgets vary; the registered layout and compiler adapter remain fixed.
 * The caller admits its selected host policy; this boundary retains the compiler's separate fixed caps.
 */
internal fun requireContainedModuleCompilerProfile(profile: ReconstructionProfile): ReconstructionProfile {
    val base = ReconstructionProfiles.named(profile.id)
    val admitted = ReconstructionProfile(base.schemaVersion, base.id, base.layout, profile.budgets, base.adapterConfiguration)
    require(profile.canonicalJson() == admitted.canonicalJson()) {
        "module compiler profile may vary only registered reconstruction budgets"
    }
    return admitted
}

/** Whole-second containment never widens the requested operation budget or the fixed host cap. */
internal fun moduleCompilerOperationWallMillis(profile: ReconstructionProfile): Long {
    val effective = minOf(profile.budgets.buildWallClockMillis, 120_000L) / 1000L * 1000L
    require(effective >= 2000L) { "module compiler operation requires at least two whole seconds within the requested budget" }
    return effective
}

/** Reconstruct a passive descriptor from a closed record, never an executable runtime. */
internal fun parseContainedModuleCompilerProfile(record: JsonObject): ReconstructionProfile {
    // Bound even caller-constructed JSON before inspecting nested values.
    OracleJson.canonicalBytes(record, MODULE_COMPILER_PROFILE_LIMITS)
    require(record.keys == setOf("schemaVersion", "id", "layout", "budgets", "adapterConfiguration")) {
        "module compiler profile fields differ from the closed contract"
    }
    val id = (record["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        ?: throw IllegalArgumentException("module compiler profile ID must be a string")
    val base = ReconstructionProfiles.named(id)
    val budgets = record["budgets"] as? JsonObject
        ?: throw IllegalArgumentException("module compiler profile budgets must be an object")
    require(budgets.keys == MODULE_COMPILER_BUDGET_FIELDS) { "module compiler budget fields differ from the closed contract" }
    val requested = ReconstructionBudgets(
        exportWallClockMillis = budgets.budgetLong("exportWallClockMillis"),
        exportMaximumResidentBytes = budgets.budgetLong("exportMaximumResidentBytes"),
        plannerMaximumEntities = budgets.budgetInt("plannerMaximumEntities"),
        plannerMaximumDependencyEdges = budgets.budgetLong("plannerMaximumDependencyEdges"),
        plannerMaximumWorkUnits = budgets.budgetLong("plannerMaximumWorkUnits"),
        maximumFunctionsPerModule = budgets.budgetInt("maximumFunctionsPerModule"),
        reconstructionMaximumContextCharacters = budgets.budgetInt("reconstructionMaximumContextCharacters"),
        buildWallClockMillis = budgets.budgetLong("buildWallClockMillis"),
        buildMaximumOutputBytes = budgets.budgetLong("buildMaximumOutputBytes"),
        archiveMaximumEntries = budgets.budgetInt("archiveMaximumEntries"),
        archiveMaximumFileBytes = budgets.budgetLong("archiveMaximumFileBytes"),
        archiveMaximumTotalBytes = budgets.budgetLong("archiveMaximumTotalBytes"),
    )
    val profile = requireContainedModuleCompilerProfile(
        ReconstructionProfile(base.schemaVersion, base.id, base.layout, requested, base.adapterConfiguration))
    val expected = OracleJson.parse(profile.canonicalJson().toByteArray(), MODULE_COMPILER_PROFILE_LIMITS)
    require(record == expected) { "module compiler profile changed registered schema, layout, or adapter configuration" }
    return profile
}

private fun JsonObject.budgetLong(field: String): Long {
    val primitive = this[field] as? JsonPrimitive
        ?: throw IllegalArgumentException("module compiler budget $field must be an integer")
    require(!primitive.isString && primitive.content.matches(Regex("[1-9][0-9]*"))) {
        "module compiler budget $field must be a positive integer"
    }
    return primitive.content.toLongOrNull()
        ?: throw IllegalArgumentException("module compiler budget $field exceeds its integer bound")
}

private fun JsonObject.budgetInt(field: String): Int {
    val value = budgetLong(field)
    require(value <= Int.MAX_VALUE) { "module compiler budget $field exceeds its integer bound" }
    return value.toInt()
}

private val MODULE_COMPILER_BUDGET_FIELDS = setOf("exportWallClockMillis", "exportMaximumResidentBytes",
    "plannerMaximumEntities", "plannerMaximumDependencyEdges", "plannerMaximumWorkUnits", "maximumFunctionsPerModule",
    "reconstructionMaximumContextCharacters", "buildWallClockMillis", "buildMaximumOutputBytes", "archiveMaximumEntries",
    "archiveMaximumFileBytes", "archiveMaximumTotalBytes")
private val MODULE_COMPILER_PROFILE_LIMITS = StrictJsonLimits(maximumInputBytes = 64 * 1024,
    maximumCanonicalBytes = 64 * 1024, maximumDepth = 8, maximumNodes = 2048, maximumStringBytes = 4096,
    maximumTotalStringBytes = 64 * 1024, maximumNumberCharacters = 20)
