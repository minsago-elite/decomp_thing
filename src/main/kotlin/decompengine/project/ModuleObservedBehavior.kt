package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.put

/** A producer's recovered-function trace attribution, not an authenticated oracle assertion. */
class ModuleObservationAttribution(functionIds: Collection<String>, val evidenceSha256: String) {
    val functionIds: List<String> = java.util.List.copyOf(functionIds)

    init {
        require(this.functionIds.isNotEmpty() && this.functionIds.size <= 1024) { "trace attribution needs bounded function IDs" }
        require(this.functionIds.distinct().size == this.functionIds.size) { "duplicate attributed function ID" }
        this.functionIds.forEach { requireObservationIdentifier(it) }
        requireObservationDigest(evidenceSha256)
    }
}

/** Immutable input/output snapshot tied by its producer to an observed recovered-function trace. */
class ModuleObservedCase(
    val caseId: String,
    val attribution: ModuleObservationAttribution,
    args: Collection<String>,
    val stdinHex: String,
    val exitCode: Int,
    val stdoutHex: String,
    val stderrHex: String,
) {
    val args: List<String> = java.util.List.copyOf(args)

    init {
        requireObservationIdentifier(caseId)
        require(this.args.size <= 32 && this.args.all { it.length <= 1024 && '\u0000' !in it }) {
            "observed arguments exceed their bounds or contain NUL"
        }
        listOf(stdinHex, stdoutHex, stderrHex).forEach {
            require(it.length <= 32 * 1024 && it.length % 2 == 0 && it.all { digit -> digit in "0123456789abcdef" }) {
                "observed byte evidence must be bounded lowercase hexadecimal"
            }
        }
    }
}

/**
 * File handoff for producers that actually retain recovered-function entry traces. The trace digest
 * identifies producer evidence; neither this writer nor prompt selection authenticates that evidence.
 * Opaque whole-program exploration must not be attributed by guessing from arguments or call graphs.
 */
object ModuleObservedBehavior {
    const val FILE_NAME = "module-observations.json"
    internal const val KIND = "module-observed-behavior"
    internal const val MAXIMUM_BYTES = 4 * 1024 * 1024
    internal val limits = StrictJsonLimits(
        maximumInputBytes = MAXIMUM_BYTES,
        maximumCanonicalBytes = MAXIMUM_BYTES,
        maximumDepth = 8,
        maximumNodes = 100_000,
        maximumStringBytes = 32 * 1024,
        maximumTotalStringBytes = MAXIMUM_BYTES,
        maximumNumberCharacters = 12,
    )

    /** Publish a bounded atomic snapshot, suitable for ReconstructionExplorationInput's real handoff. */
    fun write(outputDir: Path, inputSha256: String, cases: Collection<ModuleObservedCase>): Path {
        val snapshot = java.util.List.copyOf(cases)
        requireObservationDigest(inputSha256)
        require(snapshot.size <= 1024) { "too many module observation cases" }
        require(snapshot.map { it.caseId }.distinct().size == snapshot.size) { "duplicate module observation caseId" }
        val bytes = OracleJson.canonicalBytes(envelope(inputSha256, snapshot), limits)
        Files.createDirectories(outputDir)
        return outputDir.resolve(FILE_NAME).also { writeProjectEvidenceAtomically(it, bytes) }
    }

    internal fun parse(text: String): ObservationDocument = decode(parseObject(text))

    internal fun parseObject(text: String): JsonObject {
        require(text.length <= MAXIMUM_BYTES) { "module observations exceed the host character bound" }
        return OracleJson.parse(text.toByteArray(Charsets.UTF_8), limits) {
            if (Thread.currentThread().isInterrupted) throw InterruptedException("module observation read cancelled")
        } as? JsonObject ?: throw IllegalArgumentException("module observations must be an object")
    }

    internal fun decode(root: JsonObject): ObservationDocument {
        root.requireKeys("kind", "schemaVersion", "inputSha256", "cases")
        require(root.text("kind") == KIND) { "unsupported module observation kind" }
        require(root.integer("schemaVersion") == 1) { "unsupported module observation schemaVersion" }
        val inputSha256 = root.text("inputSha256").also(::requireObservationDigest)
        val cases = root.array("cases")
        require(cases.size <= 1024) { "too many module observation cases" }
        val decoded = cases.map { element ->
            val case = element as? JsonObject ?: throw IllegalArgumentException("module observation case must be an object")
            case.requireKeys("caseId", "functionIds", "attribution", "input", "observed")
            val attribution = case.obj("attribution")
            attribution.requireKeys("kind", "evidenceSha256")
            require(attribution.text("kind") == "observed-function-entry-trace") { "unsupported observation attribution" }
            val input = case.obj("input")
            input.requireKeys("args", "stdinHex")
            val observed = case.obj("observed")
            observed.requireKeys("exitCode", "stdoutHex", "stderrHex")
            ModuleObservedCase(
                case.text("caseId"),
                ModuleObservationAttribution(case.array("functionIds").map { it.string() }, attribution.text("evidenceSha256")),
                input.array("args").map { it.string() }, input.text("stdinHex"),
                observed.integer("exitCode"), observed.text("stdoutHex"), observed.text("stderrHex"),
            )
        }
        require(decoded.map { it.caseId }.distinct().size == decoded.size) { "duplicate module observation caseId" }
        return ObservationDocument(inputSha256, java.util.List.copyOf(decoded))
    }

    internal fun envelope(inputSha256: String, cases: List<ModuleObservedCase>): JsonObject = buildJsonObject {
        put("kind", KIND)
        put("schemaVersion", 1)
        put("inputSha256", inputSha256)
        put("cases", JsonArray(cases.sortedBy { it.caseId }.map { case ->
            buildJsonObject {
                put("caseId", case.caseId)
                put("functionIds", JsonArray(case.attribution.functionIds.sorted().map(::JsonPrimitive)))
                put("attribution", buildJsonObject {
                    put("kind", "observed-function-entry-trace")
                    put("evidenceSha256", case.attribution.evidenceSha256)
                })
                put("input", buildJsonObject {
                    put("args", JsonArray(case.args.map(::JsonPrimitive)))
                    put("stdinHex", case.stdinHex)
                })
                put("observed", buildJsonObject {
                    put("exitCode", case.exitCode)
                    put("stdoutHex", case.stdoutHex)
                    put("stderrHex", case.stderrHex)
                })
            }
        }))
    }
}

internal data class ObservationDocument(val inputSha256: String, val cases: List<ModuleObservedCase>)

internal fun selectModuleObservedBehavior(observed: String?, module: PlannedModule, model: RecoveredProgramModel): String {
    val unavailable = "Module observed behavior unavailable: no cases with recovered-function trace attribution were supplied."
    if (observed == null) return unavailable
    val unscoped = "Module observed behavior unavailable: legacy or opaque exploration is unscoped; no module attribution can be inferred."
    val root = try {
        ModuleObservedBehavior.parseObject(observed)
    } catch (failure: IllegalArgumentException) {
        if (ModuleObservedBehavior.KIND in observed) throw failure
        return unscoped
    }
    if ((root["kind"] as? JsonPrimitive)?.content != ModuleObservedBehavior.KIND) return unscoped
    val document = ModuleObservedBehavior.decode(root)
    require(document.inputSha256 == model.inputSha256) { "module observations belong to a different input" }
    val knownFunctions = model.functions.map { it.id }.toSet()
    require(module.functionIds.all { it in knownFunctions }) { "module owns unknown recovered function IDs" }
    require(document.cases.all { case -> case.attribution.functionIds.all { it in knownFunctions } }) {
        "module observations contain unknown recovered function IDs"
    }
    val owned = module.functionIds.toSet()
    val selected = document.cases.filter { case -> case.attribution.functionIds.any { it in owned } }
    if (selected.isEmpty()) return "Module observed behavior unavailable: no supplied traced case intersects this module's recovered functions."
    return "Non-authoritative observed prompt evidence; producer-supplied trace attribution is not an authenticated oracle, " +
        "module-only output attribution, coverage proof, or behavioral equivalence. Outputs describe each whole execution.\n" +
        OracleJson.canonicalBytes(ModuleObservedBehavior.envelope(document.inputSha256, selected), ModuleObservedBehavior.limits)
            .decodeToString()
}

private fun requireObservationIdentifier(value: String) {
    require(value.length in 1..256 && value.none { it.isISOControl() }) { "observation identifier must be bounded and nonempty" }
}

private fun requireObservationDigest(value: String) {
    require(value.length == 64 && value.all { it in "0123456789abcdef" }) { "observation digest must be lowercase SHA-256" }
}

private fun JsonObject.requireKeys(vararg keys: String) {
    require(this.keys == keys.toSet()) { "unexpected or missing module observation fields" }
}
private fun JsonElement.string(): String = (this as? JsonPrimitive)?.takeIf { it.isString }?.content
    ?: throw IllegalArgumentException("module observation field must be a string")
private fun JsonObject.text(name: String): String = getValue(name).string()
private fun JsonObject.integer(name: String): Int = (getValue(name) as? JsonPrimitive)?.takeUnless { it.isString }?.intOrNull
    ?: throw IllegalArgumentException("module observation field must be an integer")
private fun JsonObject.array(name: String): JsonArray = getValue(name) as? JsonArray
    ?: throw IllegalArgumentException("module observation field must be an array")
private fun JsonObject.obj(name: String): JsonObject = getValue(name) as? JsonObject
    ?: throw IllegalArgumentException("module observation field must be an object")
