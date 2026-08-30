package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.ByteArrayOutputStream
import java.math.BigDecimal
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import kotlin.math.abs
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class StructuralRecoveryV1Exception(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

data class StructuralRecoveryV1Limits(
    val maximumJsonInputBytes: Int = 64 * 1024 * 1024,
    val maximumReportBytes: Int = 128 * 1024 * 1024,
    val maximumTotalInputBytes: Long = 192L * 1024 * 1024,
    val maximumEntities: Int = 50_000,
    val maximumFacts: Int = 500_000,
    val maximumFactsPerEntity: Int = 20_000,
    val maximumEvidencePerFact: Int = 32,
    val maximumMappings: Int = 100_000,
    val maximumTotalEntities: Int = 50_000,
    val maximumTotalFacts: Int = 600_000,
    val maximumTotalEvidence: Int = 2_000_000,
    val maximumReportEntries: Int = 600_000,
    val maximumProjectedReportBytes: Long = 96L * 1024 * 1024,
    val maximumTextCharacters: Int = 16_384,
    val maximumIdentifierCharacters: Int = 4_096,
    val maximumJsonNumberCharacters: Int = 128,
    val maximumAbiClasses: Int = 256,
    val maximumCallingConventions: Int = 128,
    val maximumRegisters: Int = 256,
) {
    init {
        require(maximumJsonInputBytes in 1..DEFAULT_MAXIMUM_JSON_INPUT_BYTES)
        require(maximumReportBytes in 1..DEFAULT_MAXIMUM_REPORT_BYTES)
        require(maximumTotalInputBytes in 1L..DEFAULT_MAXIMUM_TOTAL_INPUT_BYTES)
        require(maximumEntities in 1..DEFAULT_MAXIMUM_ENTITIES)
        require(maximumFacts in 1..DEFAULT_MAXIMUM_FACTS)
        require(maximumFactsPerEntity in 1..DEFAULT_MAXIMUM_FACTS_PER_ENTITY)
        require(maximumEvidencePerFact in 1..DEFAULT_MAXIMUM_EVIDENCE_PER_FACT)
        require(maximumMappings in 1..DEFAULT_MAXIMUM_MAPPINGS)
        require(maximumTotalEntities in 1..DEFAULT_MAXIMUM_TOTAL_ENTITIES)
        require(maximumTotalFacts in 1..DEFAULT_MAXIMUM_TOTAL_FACTS)
        require(maximumTotalEvidence in 1..DEFAULT_MAXIMUM_TOTAL_EVIDENCE)
        require(maximumReportEntries in 1..DEFAULT_MAXIMUM_REPORT_ENTRIES)
        require(maximumProjectedReportBytes in 1L..DEFAULT_MAXIMUM_PROJECTED_REPORT_BYTES)
        require(maximumTextCharacters in 1..DEFAULT_MAXIMUM_TEXT_CHARACTERS)
        require(maximumIdentifierCharacters in 1..DEFAULT_MAXIMUM_IDENTIFIER_CHARACTERS)
        require(maximumJsonNumberCharacters in 1..DEFAULT_MAXIMUM_JSON_NUMBER_CHARACTERS)
        require(maximumAbiClasses in 1..DEFAULT_MAXIMUM_ABI_CLASSES)
        require(maximumCallingConventions in 1..DEFAULT_MAXIMUM_CALLING_CONVENTIONS)
        require(maximumRegisters in 1..DEFAULT_MAXIMUM_REGISTERS)
    }

    internal fun reportPolicy(): JsonObject = JsonObject(
        mapOf(
            // The v1 wire contract records its historical hard ceilings. A caller may
            // choose stricter runtime caps, but doing so must not silently mint a new
            // report contract or change otherwise identical report bytes.
            "maxEntities" to JsonPrimitive(DEFAULT_MAXIMUM_ENTITIES),
            "maxEvidencePerFact" to JsonPrimitive(DEFAULT_MAXIMUM_EVIDENCE_PER_FACT),
            "maxFacts" to JsonPrimitive(DEFAULT_MAXIMUM_FACTS),
            "maxFactsPerEntity" to JsonPrimitive(DEFAULT_MAXIMUM_FACTS_PER_ENTITY),
            "maxJsonInputBytes" to JsonPrimitive(DEFAULT_MAXIMUM_JSON_INPUT_BYTES),
            "maxJsonNumberCharacters" to JsonPrimitive(DEFAULT_MAXIMUM_JSON_NUMBER_CHARACTERS),
            "maxMappings" to JsonPrimitive(DEFAULT_MAXIMUM_MAPPINGS),
            "maxProjectedReportBytes" to JsonPrimitive(DEFAULT_MAXIMUM_PROJECTED_REPORT_BYTES),
            "maxReportBytes" to JsonPrimitive(DEFAULT_MAXIMUM_REPORT_BYTES),
            "maxReportEntries" to JsonPrimitive(DEFAULT_MAXIMUM_REPORT_ENTRIES),
            "maxTextCharacters" to JsonPrimitive(DEFAULT_MAXIMUM_TEXT_CHARACTERS),
            "maxTotalEntities" to JsonPrimitive(DEFAULT_MAXIMUM_TOTAL_ENTITIES),
            "maxTotalEvidence" to JsonPrimitive(DEFAULT_MAXIMUM_TOTAL_EVIDENCE),
            "maxTotalFacts" to JsonPrimitive(DEFAULT_MAXIMUM_TOTAL_FACTS),
            "maxTotalInputBytes" to JsonPrimitive(DEFAULT_MAXIMUM_TOTAL_INPUT_BYTES),
        ),
    )

    private companion object {
        const val DEFAULT_MAXIMUM_JSON_INPUT_BYTES = 64 * 1024 * 1024
        const val DEFAULT_MAXIMUM_REPORT_BYTES = 128 * 1024 * 1024
        const val DEFAULT_MAXIMUM_TOTAL_INPUT_BYTES = 192L * 1024 * 1024
        const val DEFAULT_MAXIMUM_ENTITIES = 50_000
        const val DEFAULT_MAXIMUM_FACTS = 500_000
        const val DEFAULT_MAXIMUM_FACTS_PER_ENTITY = 20_000
        const val DEFAULT_MAXIMUM_EVIDENCE_PER_FACT = 32
        const val DEFAULT_MAXIMUM_MAPPINGS = 100_000
        const val DEFAULT_MAXIMUM_TOTAL_ENTITIES = 50_000
        const val DEFAULT_MAXIMUM_TOTAL_FACTS = 600_000
        const val DEFAULT_MAXIMUM_TOTAL_EVIDENCE = 2_000_000
        const val DEFAULT_MAXIMUM_REPORT_ENTRIES = 600_000
        const val DEFAULT_MAXIMUM_PROJECTED_REPORT_BYTES = 96L * 1024 * 1024
        const val DEFAULT_MAXIMUM_TEXT_CHARACTERS = 16_384
        const val DEFAULT_MAXIMUM_IDENTIFIER_CHARACTERS = 4_096
        const val DEFAULT_MAXIMUM_JSON_NUMBER_CHARACTERS = 128
        const val DEFAULT_MAXIMUM_ABI_CLASSES = 256
        const val DEFAULT_MAXIMUM_CALLING_CONVENTIONS = 128
        const val DEFAULT_MAXIMUM_REGISTERS = 256
    }
}

internal class StructuralSnapshot(
    val path: Path,
    bytes: ByteArray,
) {
    private val content = bytes.copyOf()
    val bytes: ByteArray get() = content.copyOf()
    val size: Int = content.size
    val sha256: String = OracleArtifacts.sha256(content)
}

class StructuralTargetAbiV1 internal constructor(
    internal val snapshot: StructuralSnapshot,
    val document: JsonObject,
    val id: String,
    val addressBits: Int,
    val maximumAddress: ULong,
    val objectFormat: String,
    val callingConventions: Set<String>,
    val conventionAliases: Map<String, String>,
    val abiClasses: Set<String>,
)

class StructuralFunctionOracleV1 internal constructor(
    internal val snapshot: StructuralSnapshot,
    val document: JsonObject,
    val id: String,
    val scope: String,
    val artifactManifestSha256: String?,
    val nearMissBytes: Int,
    internal val artifacts: Map<String, StructuralFunctionArtifactV1>,
    internal val scoredFunctionIds: Set<String>,
    internal val scoreableFunctionsByTwin: Map<String, Map<String, StructuralFunctionScoreRecordV1>>,
    internal val expectedExcludedFunctions: JsonArray,
)

internal data class StructuralFunctionArtifactV1(
    val inputSha256: String,
    val elfType: String,
    val elfImageBase: ULong,
    val executableRvaRanges: List<Pair<ULong, ULong>>,
)

internal data class StructuralFunctionScoreRecordV1(
    val rva: ULong,
    val aliases: JsonArray,
)

class StructuralOracleV1 internal constructor(
    internal val snapshot: StructuralSnapshot,
    val document: JsonObject,
)

class StructuralBoundaryMappingV1 internal constructor(
    internal val snapshot: StructuralSnapshot,
    internal val upstreamOracleSnapshot: StructuralSnapshot,
    val document: JsonObject,
    val twin: String,
    val projectionAdapterId: String,
    val projectionAdapterVersion: String,
    val objectFormat: String,
    val inputSha256: String,
    val modelImageBase: ULong,
    val executableRvaRanges: List<Pair<ULong, ULong>>,
    val oracleToRecovered: Map<String, String>,
    val recoveredToOracle: Map<String, String>,
    val oracleFunctionIds: Set<String>,
    val recoveredFunctionIds: Set<String>,
    val excludedOracleIds: Set<String>,
    val ignoredRecoveredIds: Set<String>,
)

class StructuralIdentityMapV1 internal constructor(
    internal val snapshot: StructuralSnapshot,
    val document: JsonObject,
    val recoveredToOracle: Map<StructuralEntityKey, String>,
    val oracleToRecovered: Map<StructuralEntityKey, String>,
)

class RecoveredStructureV1 internal constructor(
    internal val snapshot: StructuralSnapshot,
    val document: JsonObject,
    val payloadSha256: String,
)

data class StructuralEntityKey(val kind: String, val id: String)

internal object StructuralRecoveryV1Contract {
    const val SCHEMA_VERSION = 1
    const val BOUNDARY_PROJECTION_ADAPTER_ID = "function-recovery-score-elf"
    const val BOUNDARY_PROJECTION_ADAPTER_VERSION = "1"
    const val NORMALIZATION_PROFILE_ID = "structural-source-normalization"
    const val NORMALIZATION_PROFILE_VERSION = "1"
    const val NORMALIZATION_PROFILE_CONFIGURATION_SHA256 =
        "4385f86a45a39e55a8f9f072e5563720f4775edbb53d8d4c290f9f232982ae80"

    const val IDENTITY_SELECTION_POLICY =
        "function and internal-call endpoint identities come only from the selected " +
            "function-boundary report; global and type identities come only from the " +
            "separately reviewed identity map; facts align by canonical dimension and slot"
    const val ABI_EQUIVALENCE_POLICY =
        "exact requires identical source and ABI projections; ABI-equivalent requires " +
            "different source projections and identical non-null projections validated by " +
            "the selected target descriptor"
    const val SOURCE_NORMALIZATION_POLICY =
        "language-neutral tagged source projections interpreted only under the exact " +
            "normalization-profile ID, version, and configuration digest; adapter-local " +
            "declarations and display names are forbidden"

    val OUTCOMES = listOf(
        "exact",
        "abi-equivalent",
        "recovered-unknown",
        "oracle-unobservable",
        "contradicted",
        "fabricated",
    )

    val DIMENSIONS = listOf(
        "function.prototype",
        "function.calling-convention",
        "function.variadic",
        "function.parameter-abi-class",
        "function.return-abi-class",
        "call.internal",
        "call.external",
        "call.indirect",
        "global.reference",
        "global.storage",
        "global.linkage",
        "global.type",
        "type.aggregate.kind",
        "type.aggregate.size-bits",
        "type.aggregate.alignment-bits",
        "type.aggregate.member-offset-bits",
        "type.aggregate.member-type",
        "type.enum.underlying-abi-class",
        "type.enum.enumerator-value",
        "type.typedef.target",
    )

    val ABI_EQUIVALENT_DIMENSIONS = setOf(
        "function.calling-convention",
        "function.parameter-abi-class",
        "function.return-abi-class",
        "global.type",
        "type.aggregate.member-type",
        "type.enum.underlying-abi-class",
        "type.typedef.target",
    )

    val TYPE_REFERENCE_DIMENSIONS = setOf(
        "function.parameter-abi-class",
        "function.return-abi-class",
        "global.type",
        "type.aggregate.member-type",
        "type.enum.underlying-abi-class",
        "type.typedef.target",
    )

    val STRING_SOURCE_DIMENSIONS = setOf(
        "function.prototype",
        "function.calling-convention",
        "function.parameter-abi-class",
        "function.return-abi-class",
        "call.internal",
        "call.external",
        "call.indirect",
        "global.reference",
        "global.storage",
        "global.linkage",
        "global.type",
        "type.aggregate.kind",
        "type.aggregate.member-type",
        "type.enum.underlying-abi-class",
        "type.typedef.target",
    )

    val INTEGER_SOURCE_DIMENSIONS = setOf(
        "type.aggregate.size-bits",
        "type.aggregate.alignment-bits",
        "type.aggregate.member-offset-bits",
        "type.enum.enumerator-value",
    )

    val DIMENSION_ENTITY_KIND: Map<String, String> = DIMENSIONS.associateWith { dimension ->
        when {
            dimension.startsWith("function.") || dimension.startsWith("call.") ||
                dimension == "global.reference" -> "function"
            dimension.startsWith("global.") -> "global"
            else -> "type"
        }
    }

    val CODE_POINT_ORDER: Comparator<String> = Comparator(::compareCodePoints)
    val ENTITY_KEY_ORDER: Comparator<StructuralEntityKey> = Comparator { left, right ->
        compareCodePoints(left.kind, right.kind).takeIf { it != 0 }
            ?: compareCodePoints(left.id, right.id)
    }

    val SHA256 = Regex("^[0-9a-f]{64}$")
    val IDENTIFIER = Regex("^[A-Za-z0-9][A-Za-z0-9._:/@+\\-]{0,4095}$")
    val ADDRESS = Regex("^0x(?:0|[1-9a-f][0-9a-f]{0,15})$")
    val PARAMETER_SLOT = Regex("^parameter:(0|[1-9][0-9]{0,8})$")
    val CALL_SLOT = Regex("^call:(0x(?:0|[1-9a-f][0-9a-f]{0,15})):(internal|external|indirect)$")
    val GLOBAL_REFERENCE_SLOT = Regex("^global-ref:(0x(?:0|[1-9a-f][0-9a-f]{0,15}))$")
    val MEMBER_SLOT = Regex("^member:(0|[1-9][0-9]{0,8}):(offset|type)$")
    val ENUMERATOR_SLOT = Regex("^enumerator:[A-Za-z_][A-Za-z0-9_]{0,1023}$")
    private const val NORMALIZED_TOKEN = "[A-Za-z0-9_][A-Za-z0-9._:/@+\\-]{0,4094}"
    val PROTOTYPE_SOURCE = Regex("^prototype:$NORMALIZED_TOKEN$")
    val CONVENTION_SOURCE = Regex("^convention:$NORMALIZED_TOKEN$")
    val TYPE_SOURCE = Regex("^(?:type-token|type-entity):$NORMALIZED_TOKEN$")
    val FUNCTION_SOURCE = Regex("^function:$NORMALIZED_TOKEN$")
    val EXTERNAL_SOURCE = Regex("^external:$NORMALIZED_TOKEN$")
    val INDIRECT_SOURCE = Regex("^signature:$NORMALIZED_TOKEN$")
    val GLOBAL_SOURCE = Regex("^global:$NORMALIZED_TOKEN$")
    val STORAGE_SOURCE = Regex(
        "^(?:static-rva|tls-offset):0x(?:0|[1-9a-f][0-9a-f]{0,15})$" +
            "|^(?:external-storage|register):$NORMALIZED_TOKEN$",
    )
    val LINKAGE_SOURCES = setOf("internal", "external", "weak", "common", "unique", "none")
    val AGGREGATE_KIND_SOURCES = setOf("record", "overlay", "variant", "sequence")
}

internal fun readStructuralDocument(
    path: Path,
    label: String,
    schema: String,
    limits: StructuralRecoveryV1Limits,
): Pair<StructuralSnapshot, JsonObject> {
    val artifact = try {
        OracleArtifacts.read(path, OracleArtifactLimits(limits.maximumJsonInputBytes))
    } catch (failure: Exception) {
        throw StructuralRecoveryV1Exception("cannot read $label", failure)
    }
    val jsonLimits = StrictJsonLimits(
        maximumInputBytes = limits.maximumJsonInputBytes,
        maximumCanonicalBytes = limits.maximumJsonInputBytes,
        maximumDepth = 128,
        maximumNodes = 1_000_000,
        maximumStringBytes = minOf(limits.maximumJsonInputBytes, 1024 * 1024),
        maximumTotalStringBytes = limits.maximumJsonInputBytes,
        maximumNumberCharacters = limits.maximumJsonNumberCharacters,
    )
    val document = try {
        OracleJson.parse(artifact.bytes, jsonLimits) as? JsonObject
            ?: throw StructuralRecoveryV1Exception("$label root must be an object")
    } catch (failure: StructuralRecoveryV1Exception) {
        throw failure
    } catch (failure: Exception) {
        throw StructuralRecoveryV1Exception("$label is not strict bounded JSON", failure)
    }
    try {
        OracleSchemas.validate(schema, document)
    } catch (failure: Exception) {
        throw StructuralRecoveryV1Exception("$label fails the bundled $schema schema", failure)
    }
    return StructuralSnapshot(path.toAbsolutePath().normalize(), artifact.bytes) to document
}

internal fun JsonElement.requireObject(path: String, keys: Set<String>): JsonObject {
    val value = this as? JsonObject ?: structuralFail("$path must be an object")
    if (value.keys != keys) structuralFail("$path must contain exactly ${keys.sortedWith(StructuralRecoveryV1Contract.CODE_POINT_ORDER)}")
    return value
}

internal fun JsonElement.requireArray(path: String, maximum: Int, minimum: Int = 0): JsonArray {
    val value = this as? JsonArray ?: structuralFail("$path must be an array")
    if (value.size !in minimum..maximum) structuralFail("$path must contain $minimum..$maximum entries")
    return value
}

internal fun JsonElement.requireString(path: String, maximum: Int): String {
    val primitive = this as? JsonPrimitive ?: structuralFail("$path must be a string")
    if (!primitive.isString) structuralFail("$path must be a string")
    val value = primitive.content
    if (value.codePointLength() !in 1..maximum) structuralFail("$path is empty or exceeds $maximum characters")
    return value
}

internal fun JsonElement.requireNullableString(path: String, maximum: Int): String? = when (this) {
    JsonNull -> null
    else -> requireString(path, maximum)
}

internal fun JsonElement.requireBoolean(path: String): Boolean {
    val primitive = this as? JsonPrimitive ?: structuralFail("$path must be a boolean")
    if (primitive.isString || primitive.content !in setOf("true", "false")) structuralFail("$path must be a boolean")
    return primitive.content == "true"
}

internal fun JsonElement.requireInteger(
    path: String,
    minimum: BigInteger = BigInteger.ZERO,
    maximum: BigInteger = UNSIGNED_64_MAXIMUM,
): BigInteger {
    val primitive = this as? JsonPrimitive ?: structuralFail("$path must be an integer")
    if (primitive.isString || primitive.content.any { it in ".eE" }) structuralFail("$path must be an integer")
    val value = try {
        BigInteger(primitive.content)
    } catch (failure: NumberFormatException) {
        throw StructuralRecoveryV1Exception("$path must be an integer", failure)
    }
    if (value < minimum || value > maximum) structuralFail("$path is outside its integer range")
    return value
}

internal fun JsonElement.requireInt(path: String, minimum: Int = 0, maximum: Int = Int.MAX_VALUE): Int =
    requireInteger(path, BigInteger.valueOf(minimum.toLong()), BigInteger.valueOf(maximum.toLong())).toInt()

internal fun JsonElement.requireLong(path: String, minimum: Long = 0L, maximum: Long = Long.MAX_VALUE): Long =
    requireInteger(path, BigInteger.valueOf(minimum), BigInteger.valueOf(maximum)).toLong()

internal fun JsonElement.requireIdentifier(path: String, limits: StructuralRecoveryV1Limits): String {
    val value = requireString(path, limits.maximumIdentifierCharacters)
    if (!StructuralRecoveryV1Contract.IDENTIFIER.matches(value)) structuralFail("$path is not a canonical identifier")
    return value
}

internal fun JsonElement.requireSha256(path: String): String {
    val value = requireString(path, 64)
    if (!StructuralRecoveryV1Contract.SHA256.matches(value)) structuralFail("$path is not a lowercase SHA-256 digest")
    return value
}

internal fun JsonElement.requireAddress(path: String, maximum: ULong): ULong {
    val value = requireString(path, 18)
    if (!StructuralRecoveryV1Contract.ADDRESS.matches(value)) structuralFail("$path is not a canonical address")
    val parsed = value.removePrefix("0x").toULongOrNull(16) ?: structuralFail("$path exceeds 64 bits")
    if (parsed > maximum) structuralFail("$path exceeds the selected target address width")
    return parsed
}

internal fun JsonObject.field(name: String, path: String): JsonElement =
    this[name] ?: structuralFail("$path.$name is required")

internal fun requireSchemaVersion(document: JsonObject, label: String) {
    if (document.field("schemaVersion", label).requireInt("$label.schemaVersion", 1, 1) != 1) {
        structuralFail("$label schemaVersion must be 1")
    }
}

internal fun validateNormalizationProfile(value: JsonElement, path: String): JsonObject {
    val profile = value.requireObject(path, setOf("id", "version", "configurationSha256"))
    val expected = mapOf(
        "id" to StructuralRecoveryV1Contract.NORMALIZATION_PROFILE_ID,
        "version" to StructuralRecoveryV1Contract.NORMALIZATION_PROFILE_VERSION,
        "configurationSha256" to StructuralRecoveryV1Contract.NORMALIZATION_PROFILE_CONFIGURATION_SHA256,
    )
    expected.forEach { (key, expectedValue) ->
        if (profile.field(key, path).requireString("$path.$key", 128) != expectedValue) {
            structuralFail("$path does not match the checked structural normalization profile")
        }
    }
    return profile
}

internal fun validateToolIdentity(value: JsonElement, path: String, limits: StructuralRecoveryV1Limits) {
    val tool = value.requireObject(path, setOf("id", "version", "executableSha256", "configurationSha256"))
    tool.field("id", path).requireIdentifier("$path.id", limits)
    tool.field("version", path).requireIdentifier("$path.version", limits)
    tool.field("executableSha256", path).requireSha256("$path.executableSha256")
    tool.field("configurationSha256", path).requireSha256("$path.configurationSha256")
}

internal fun fixturePayloadSha256(document: JsonObject, maximumBytes: Int): String {
    val withoutAttestation = JsonObject(document.filterKeys { it != "attestation" })
    return OracleArtifacts.sha256(
        StructuralJsonEncoder(maximumBytes, pretty = false, ensureAscii = true).encode(withoutAttestation),
    )
}

internal fun canonicalStructuralReportBytes(document: JsonObject, maximumBytes: Int): ByteArray =
    StructuralJsonEncoder(maximumBytes, pretty = true, ensureAscii = false).encode(document)

internal class StructuralJsonEncoder(
    maximumBytes: Int,
    private val pretty: Boolean,
    private val ensureAscii: Boolean,
) {
    private val output = BoundedStructuralBytes(maximumBytes)

    fun encode(value: JsonElement): ByteArray {
        write(value, 0)
        if (pretty) output.ascii("\n")
        return output.bytes()
    }

    private fun write(value: JsonElement, indent: Int) {
        when (value) {
            JsonNull -> output.ascii("null")
            is JsonObject -> writeObject(value, indent)
            is JsonArray -> writeArray(value, indent)
            is JsonPrimitive -> writePrimitive(value)
        }
    }

    private fun writeObject(value: JsonObject, indent: Int) {
        if (value.isEmpty()) {
            output.ascii("{}")
            return
        }
        output.ascii(if (pretty) "{\n" else "{")
        val entries = value.entries.sortedWith { left, right -> compareCodePoints(left.key, right.key) }
        entries.forEachIndexed { index, entry ->
            if (pretty) output.spaces((indent + 1) * 2)
            writeString(entry.key)
            output.ascii(if (pretty) ": " else ":")
            write(entry.value, indent + 1)
            if (index != entries.lastIndex) output.ascii(",")
            if (pretty) output.ascii("\n")
        }
        if (pretty) output.spaces(indent * 2)
        output.ascii("}")
    }

    private fun writeArray(value: JsonArray, indent: Int) {
        if (value.isEmpty()) {
            output.ascii("[]")
            return
        }
        output.ascii(if (pretty) "[\n" else "[")
        value.forEachIndexed { index, item ->
            if (pretty) output.spaces((indent + 1) * 2)
            write(item, indent + 1)
            if (index != value.lastIndex) output.ascii(",")
            if (pretty) output.ascii("\n")
        }
        if (pretty) output.spaces(indent * 2)
        output.ascii("]")
    }

    private fun writePrimitive(value: JsonPrimitive) {
        if (value.isString) writeString(value.content) else output.ascii(canonicalNumber(value.content))
    }

    private fun writeString(value: String) {
        output.ascii("\"")
        var index = 0
        while (index < value.length) {
            val current = value[index]
            when (current) {
                '"' -> output.ascii("\\\"")
                '\\' -> output.ascii("\\\\")
                '\b' -> output.ascii("\\b")
                '\u000c' -> output.ascii("\\f")
                '\n' -> output.ascii("\\n")
                '\r' -> output.ascii("\\r")
                '\t' -> output.ascii("\\t")
                else -> when {
                    current.code < 0x20 || ensureAscii && current.code > 0x7f ->
                        output.ascii("\\u${current.code.toString(16).padStart(4, '0')}")
                    Character.isHighSurrogate(current) -> {
                        if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                            structuralFail("cannot encode an unpaired high surrogate")
                        }
                        if (ensureAscii) {
                            output.ascii("\\u${current.code.toString(16).padStart(4, '0')}")
                            val low = value[++index]
                            output.ascii("\\u${low.code.toString(16).padStart(4, '0')}")
                        } else {
                            output.utf8(value.substring(index, index + 2))
                            index++
                        }
                    }
                    Character.isLowSurrogate(current) -> structuralFail("cannot encode an unpaired low surrogate")
                    else -> output.utf8(current.toString())
                }
            }
            index++
        }
        output.ascii("\"")
    }
}

private class BoundedStructuralBytes(private val maximum: Int) {
    private val output = ByteArrayOutputStream(minOf(maximum, 8192))

    fun ascii(value: String) = write(value.toByteArray(StandardCharsets.US_ASCII))
    fun utf8(value: String) = write(value.toByteArray(StandardCharsets.UTF_8))
    fun spaces(count: Int) = repeat(count) { write(byteArrayOf(0x20)) }
    fun bytes(): ByteArray = output.toByteArray()

    private fun write(value: ByteArray) {
        if (output.size() > maximum - value.size) structuralFail("structural JSON exceeds the configured byte limit")
        output.write(value)
    }
}

private fun canonicalNumber(token: String): String {
    if (token == "true" || token == "false") return token
    if (!Regex("^-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$").matches(token)) {
        structuralFail("invalid JSON number")
    }
    val floating = '.' in token || token.any { it == 'e' || it == 'E' }
    if (!floating) return try {
        BigInteger(token).toString()
    } catch (failure: NumberFormatException) {
        throw StructuralRecoveryV1Exception("invalid JSON integer", failure)
    }
    val value = token.toDoubleOrNull() ?: structuralFail("invalid JSON number")
    if (!value.isFinite()) structuralFail("non-finite JSON number")
    if (value == 0.0) return if (java.lang.Double.doubleToRawLongBits(value) < 0) "-0.0" else "0.0"
    val decimal = BigDecimal.valueOf(abs(value)).stripTrailingZeros()
    val adjustedExponent = decimal.precision() - decimal.scale() - 1
    val magnitude = if (adjustedExponent < -4 || adjustedExponent >= 16) {
        val digits = decimal.unscaledValue().abs().toString()
        val significand = if (digits.length == 1) digits else "${digits[0]}.${digits.substring(1)}"
        val sign = if (adjustedExponent >= 0) '+' else '-'
        "$significand" + "e$sign${abs(adjustedExponent).toString().padStart(2, '0')}"
    } else {
        decimal.toPlainString().let { if ('.' in it) it else "$it.0" }
    }
    return if (value < 0) "-$magnitude" else magnitude
}

internal fun compareCodePoints(left: String, right: String): Int {
    var leftOffset = 0
    var rightOffset = 0
    while (leftOffset < left.length && rightOffset < right.length) {
        val leftPoint = Character.codePointAt(left, leftOffset)
        val rightPoint = Character.codePointAt(right, rightOffset)
        if (leftPoint != rightPoint) return leftPoint.compareTo(rightPoint)
        leftOffset += Character.charCount(leftPoint)
        rightOffset += Character.charCount(rightPoint)
    }
    return (left.length - leftOffset).compareTo(right.length - rightOffset)
}

internal fun String.codePointLength(): Int = codePointCount(0, length)

internal fun structuralFail(message: String): Nothing = throw StructuralRecoveryV1Exception(message)

internal val UNSIGNED_64_MAXIMUM: BigInteger = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
internal val SIGNED_64_MAGNITUDE_MAXIMUM: BigInteger = UNSIGNED_64_MAXIMUM
