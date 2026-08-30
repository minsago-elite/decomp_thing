package decompengine.oracle.structural

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import decompengine.oracle.core.OracleArtifacts
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredGlobal
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveredType
import decompengine.project.RecoveryStatus
import java.util.LinkedHashSet
import java.util.Locale

/** Explicit allocation and syntax bounds for the canonical schema-v1 Ghidra program model. */
internal data class CanonicalProgramModelStreamingLimits(
    val maximumInputBytes: Int = 512 * 1024 * 1024,
    val maximumFunctions: Int = 20_000,
    val maximumGlobals: Int = 1_000_000,
    val maximumTypes: Int = 1_000_000,
    val maximumReferencesPerFunction: Int = 100_000,
    val maximumIdentifierCodePoints: Int = 4_096,
    val maximumPrototypeCodePoints: Int = 1_048_576,
    val maximumTextCodePoints: Int = 16 * 1024 * 1024,
    val maximumTotalStringBytes: Long = maximumInputBytes.toLong(),
    val maximumNodes: Long = 32_000_000,
    val maximumTokens: Long = 64_000_000,
    val maximumDepth: Int = 8,
) {
    init {
        require(maximumInputBytes in 1..HARD_MAXIMUM_INPUT_BYTES)
        require(maximumFunctions in 0..HARD_MAXIMUM_FUNCTIONS)
        require(maximumGlobals in 0..HARD_MAXIMUM_GLOBALS_OR_TYPES)
        require(maximumTypes in 0..HARD_MAXIMUM_GLOBALS_OR_TYPES)
        require(maximumReferencesPerFunction in 0..HARD_MAXIMUM_REFERENCES_PER_FUNCTION)
        require(maximumIdentifierCodePoints in 1..HARD_MAXIMUM_IDENTIFIER_CODE_POINTS)
        require(maximumPrototypeCodePoints in 1..HARD_MAXIMUM_PROTOTYPE_CODE_POINTS)
        require(maximumTextCodePoints in 1..HARD_MAXIMUM_TEXT_CODE_POINTS)
        require(maximumTotalStringBytes in 1L..maximumInputBytes.toLong())
        require(maximumNodes in 1L..HARD_MAXIMUM_NODES)
        require(maximumTokens in 1L..HARD_MAXIMUM_TOKENS)
        require(maximumDepth in 1..HARD_MAXIMUM_DEPTH)
    }

    internal val maximumDecodedStringCharacters: Int
        get() = minOf(
            maximumInputBytes.toLong(),
            2L * maxOf(
                maximumIdentifierCodePoints,
                maximumPrototypeCodePoints,
                maximumTextCodePoints,
            ).toLong(),
        ).toInt()

    private companion object {
        const val HARD_MAXIMUM_INPUT_BYTES = 512 * 1024 * 1024
        const val HARD_MAXIMUM_FUNCTIONS = 131_072
        const val HARD_MAXIMUM_GLOBALS_OR_TYPES = 1_000_000
        const val HARD_MAXIMUM_REFERENCES_PER_FUNCTION = 100_000
        const val HARD_MAXIMUM_IDENTIFIER_CODE_POINTS = 4_096
        const val HARD_MAXIMUM_PROTOTYPE_CODE_POINTS = 1_048_576
        const val HARD_MAXIMUM_TEXT_CODE_POINTS = 16 * 1024 * 1024
        const val HARD_MAXIMUM_NODES = 64_000_000L
        const val HARD_MAXIMUM_TOKENS = 128_000_000L
        const val HARD_MAXIMUM_DEPTH = 32
    }
}

/** Immutable result derived from one private byte snapshot. */
internal class CanonicalProgramModelSnapshot internal constructor(
    val model: RecoveredProgramModel,
    val sha256: String,
    val sizeBytes: Int,
)

/**
 * Parses the exact schema-v1 exporter wire form without constructing a generic JSON tree.
 *
 * The input is copied only after its byte bound is checked. Jackson then enforces strict UTF-8,
 * duplicate-key, token, number, and nesting limits while this parser enforces the closed field
 * order and allocation counts before appending to any collection. Finally an allocation-free
 * renderer compares every canonical output byte with the private snapshot.
 */
internal object CanonicalProgramModelStreaming {
    fun readCanonical(
        bytes: ByteArray,
        limits: CanonicalProgramModelStreamingLimits = CanonicalProgramModelStreamingLimits(),
    ): CanonicalProgramModelSnapshot {
        if (bytes.isEmpty() || bytes.size > limits.maximumInputBytes) {
            modelFail("program model bytes are empty or exceed the configured streaming limit")
        }
        val snapshot = bytes.copyOf()
        if (snapshot.size >= UTF8_BOM.size && snapshot.copyOfRange(0, UTF8_BOM.size).contentEquals(UTF8_BOM)) {
            modelFail("program model must not contain a UTF-8 BOM")
        }
        val model = try {
            jsonFactory(limits).createParser(snapshot).use { parser ->
                TypedReader(parser, limits).readModel()
            }
        } catch (failure: StructuralRecoveryV1Exception) {
            throw failure
        } catch (failure: Exception) {
            throw StructuralRecoveryV1Exception(
                "program model is not strict bounded schema-v1 UTF-8 JSON: ${failure.message}",
                failure,
            )
        }
        ExactCanonicalModelComparator(snapshot).verify(model)
        return CanonicalProgramModelSnapshot(model, OracleArtifacts.sha256(snapshot), snapshot.size)
    }

    private fun jsonFactory(limits: CanonicalProgramModelStreamingLimits): JsonFactory = JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .streamReadConstraints(
            StreamReadConstraints.builder()
                .maxDocumentLength(limits.maximumInputBytes.toLong())
                .maxTokenCount(limits.maximumTokens)
                .maxNestingDepth(limits.maximumDepth)
                .maxStringLength(limits.maximumDecodedStringCharacters)
                .maxNameLength(MAXIMUM_FIELD_NAME_CHARACTERS)
                .maxNumberLength(MAXIMUM_NUMBER_CHARACTERS)
                .build(),
        )
        .build()

    private val UTF8_BOM = byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte())
    private const val MAXIMUM_FIELD_NAME_CHARACTERS = 32
    private const val MAXIMUM_NUMBER_CHARACTERS = 16
}

private class TypedReader(
    private val parser: JsonParser,
    private val limits: CanonicalProgramModelStreamingLimits,
) {
    private val budget = ModelBudget(limits)

    fun readModel(): RecoveredProgramModel {
        requireToken(parser.nextToken(), JsonToken.START_OBJECT, "program model root must be an object")
        budget.chargeNode("root object")

        expectField("schemaVersion")
        requireToken(parser.nextToken(), JsonToken.VALUE_NUMBER_INT, "program model schemaVersion must be an integer")
        budget.chargeNode("schemaVersion")
        if (parser.text != "1") modelFail("program model schemaVersion must be exactly 1")

        expectField("inputSha256")
        val inputSha256 = readString(
            "program model inputSha256",
            maximumCodePoints = limits.maximumIdentifierCodePoints,
            allowEmpty = true,
        )

        expectField("functions")
        val functions = readFunctions()
        expectField("globals")
        val globals = readGlobals()
        expectField("types")
        val types = readTypes()

        requireToken(parser.nextToken(), JsonToken.END_OBJECT, "program model has missing or extra root fields")
        if (parser.nextToken() != null) modelFail("program model has trailing JSON content")
        return try {
            RecoveredProgramModel(1, inputSha256, functions, globals, types)
        } catch (failure: IllegalArgumentException) {
            throw StructuralRecoveryV1Exception("program model entity identities are invalid", failure)
        }
    }

    private fun readFunctions(): List<RecoveredFunction> {
        requireToken(parser.nextToken(), JsonToken.START_ARRAY, "program model functions must be an array")
        budget.chargeNode("functions array")
        val result = arrayListOf<RecoveredFunction>()
        val ids = hashSetOf<String>()
        var previousAddress: ULong? = null
        var previousId: String? = null
        while (true) {
            val token = parser.nextToken() ?: modelFail("program model functions array is truncated")
            if (token == JsonToken.END_ARRAY) break
            if (result.size >= limits.maximumFunctions) modelFail("program model exceeds its function-record limit")
            requireToken(token, JsonToken.START_OBJECT, "program model function must be an object")
            budget.chargeNode("function object")

            expectField("id")
            val id = readString("program model function id", limits.maximumIdentifierCodePoints, allowEmpty = false)
            if (!ids.add(id)) modelFail("program model contains a duplicate function ID")
            expectField("name")
            val name = readString("program model function name", limits.maximumIdentifierCodePoints, allowEmpty = false)
            expectField("address")
            val address = readAddress("program model function address")
            requireCanonicalEntityOrder(previousAddress, previousId, address, id, "function")
            previousAddress = address
            previousId = id
            expectField("prototype")
            val prototype = readString(
                "program model function prototype",
                limits.maximumPrototypeCodePoints,
                allowEmpty = true,
            )
            expectField("status")
            val status = readStatus("program model function status")
            expectField("calls")
            val calls = readStringSet("program model function calls", limits.maximumIdentifierCodePoints)
            expectField("referencedGlobals")
            val referencedGlobals = readStringSet(
                "program model function referencedGlobals",
                limits.maximumIdentifierCodePoints,
            )
            expectField("strings")
            val strings = readStringSet("program model function strings", limits.maximumTextCodePoints)
            expectField("decompiledC")
            val decompiledC = readNullableString("program model function decompiledC", limits.maximumTextCodePoints)
            requireToken(parser.nextToken(), JsonToken.END_OBJECT, "program model function has missing or extra fields")
            result += RecoveredFunction(
                id,
                name,
                address,
                prototype,
                decompiledC,
                calls,
                referencedGlobals,
                strings,
                status,
            )
        }
        return result
    }

    private fun readGlobals(): List<RecoveredGlobal> {
        requireToken(parser.nextToken(), JsonToken.START_ARRAY, "program model globals must be an array")
        budget.chargeNode("globals array")
        val result = arrayListOf<RecoveredGlobal>()
        val ids = hashSetOf<String>()
        var previousAddress: ULong? = null
        var previousId: String? = null
        while (true) {
            val token = parser.nextToken() ?: modelFail("program model globals array is truncated")
            if (token == JsonToken.END_ARRAY) break
            if (result.size >= limits.maximumGlobals) modelFail("program model exceeds its global-record limit")
            requireToken(token, JsonToken.START_OBJECT, "program model global must be an object")
            budget.chargeNode("global object")

            expectField("id")
            val id = readString("program model global id", limits.maximumIdentifierCodePoints, allowEmpty = true)
            if (!ids.add(id)) modelFail("program model contains a duplicate global ID")
            expectField("name")
            val name = readString("program model global name", limits.maximumIdentifierCodePoints, allowEmpty = true)
            expectField("address")
            val address = readAddress("program model global address")
            requireCanonicalEntityOrder(previousAddress, previousId, address, id, "global")
            previousAddress = address
            previousId = id
            expectField("type")
            val type = readString("program model global type", limits.maximumTextCodePoints, allowEmpty = true)
            expectField("initializer")
            val initializer = readNullableString("program model global initializer", limits.maximumTextCodePoints)
            expectField("status")
            val status = readStatus("program model global status")
            requireToken(parser.nextToken(), JsonToken.END_OBJECT, "program model global has missing or extra fields")
            result += RecoveredGlobal(id, name, address, type, initializer, status)
        }
        return result
    }

    private fun readTypes(): List<RecoveredType> {
        requireToken(parser.nextToken(), JsonToken.START_ARRAY, "program model types must be an array")
        budget.chargeNode("types array")
        val result = arrayListOf<RecoveredType>()
        var previousId: String? = null
        while (true) {
            val token = parser.nextToken() ?: modelFail("program model types array is truncated")
            if (token == JsonToken.END_ARRAY) break
            if (result.size >= limits.maximumTypes) modelFail("program model exceeds its type-record limit")
            requireToken(token, JsonToken.START_OBJECT, "program model type must be an object")
            budget.chargeNode("type object")

            expectField("id")
            val id = readString("program model type id", limits.maximumIdentifierCodePoints, allowEmpty = true)
            if (previousId != null && previousId.compareTo(id) >= 0) {
                modelFail("program model type records are duplicated or not in canonical order")
            }
            previousId = id
            expectField("declaration")
            val declaration = readString("program model type declaration", limits.maximumTextCodePoints, allowEmpty = true)
            expectField("sourceAddress")
            val sourceAddress = readNullableAddress("program model type sourceAddress")
            expectField("status")
            val status = readStatus("program model type status")
            requireToken(parser.nextToken(), JsonToken.END_OBJECT, "program model type has missing or extra fields")
            result += RecoveredType(id, declaration, sourceAddress, status)
        }
        return result
    }

    private fun readStringSet(label: String, maximumCodePoints: Int): Set<String> {
        requireToken(parser.nextToken(), JsonToken.START_ARRAY, "$label must be an array")
        budget.chargeNode("$label array")
        val result = LinkedHashSet<String>()
        var previous: String? = null
        while (true) {
            val token = parser.nextToken() ?: modelFail("$label array is truncated")
            if (token == JsonToken.END_ARRAY) break
            if (result.size >= limits.maximumReferencesPerFunction) {
                modelFail("$label exceeds its collection-entry limit")
            }
            requireToken(token, JsonToken.VALUE_STRING, "$label entries must be strings")
            val value = readCurrentString(label, maximumCodePoints, allowEmpty = true)
            if (previous != null && previous.compareTo(value) >= 0) {
                modelFail("$label entries are duplicated or not in canonical order")
            }
            result += value
            previous = value
        }
        return result
    }

    private fun expectField(expected: String) {
        requireToken(parser.nextToken(), JsonToken.FIELD_NAME, "program model field $expected is missing")
        val actual = parser.currentName()
        budget.chargeNode("field $expected")
        budget.chargeString(actual, MAXIMUM_FIELD_NAME_CODE_POINTS, allowEmpty = false, "program model field name")
        if (actual != expected) modelFail("program model fields are missing, extra, duplicated, or not in canonical order")
    }

    private fun readString(label: String, maximumCodePoints: Int, allowEmpty: Boolean): String {
        requireToken(parser.nextToken(), JsonToken.VALUE_STRING, "$label must be a string")
        return readCurrentString(label, maximumCodePoints, allowEmpty)
    }

    private fun readCurrentString(label: String, maximumCodePoints: Int, allowEmpty: Boolean): String {
        budget.chargeNode(label)
        return parser.text.also { budget.chargeString(it, maximumCodePoints, allowEmpty, label) }
    }

    private fun readNullableString(label: String, maximumCodePoints: Int): String? = when (parser.nextToken()) {
        JsonToken.VALUE_NULL -> {
            budget.chargeNode(label)
            null
        }
        JsonToken.VALUE_STRING -> readCurrentString(label, maximumCodePoints, allowEmpty = true)
        else -> modelFail("$label must be a string or null")
    }

    private fun readStatus(label: String): RecoveryStatus {
        val value = readString(label, MAXIMUM_STATUS_CODE_POINTS, allowEmpty = false)
        return when (value) {
            "recovered" -> RecoveryStatus.RECOVERED
            "partial" -> RecoveryStatus.PARTIAL
            "failed" -> RecoveryStatus.FAILED
            "synthetic" -> RecoveryStatus.SYNTHETIC
            else -> modelFail("$label is unsupported")
        }
    }

    private fun readAddress(label: String): ULong = parseAddress(
        readString(label, MAXIMUM_ADDRESS_CODE_POINTS, allowEmpty = false),
        label,
    )

    private fun readNullableAddress(label: String): ULong? = when (parser.nextToken()) {
        JsonToken.VALUE_NULL -> {
            budget.chargeNode(label)
            null
        }
        JsonToken.VALUE_STRING -> parseAddress(
            readCurrentString(label, MAXIMUM_ADDRESS_CODE_POINTS, allowEmpty = false),
            label,
        )
        else -> modelFail("$label must be a canonical address or null")
    }

    private fun parseAddress(value: String, label: String): ULong {
        if (!CANONICAL_ADDRESS.matches(value)) modelFail("$label is not a canonical unsigned address")
        return value.removePrefix("0x").toULongOrNull(16)
            ?: modelFail("$label exceeds the unsigned 64-bit range")
    }

    private fun requireCanonicalEntityOrder(
        previousAddress: ULong?,
        previousId: String?,
        address: ULong,
        id: String,
        kind: String,
    ) {
        if (previousAddress != null &&
            (previousAddress > address || previousAddress == address && requireNotNull(previousId).compareTo(id) >= 0)
        ) modelFail("program model $kind records are not in canonical address and ID order")
    }

    private fun requireToken(actual: JsonToken?, expected: JsonToken, message: String) {
        if (actual != expected) modelFail(message)
    }

    private companion object {
        const val MAXIMUM_FIELD_NAME_CODE_POINTS = 32
        const val MAXIMUM_STATUS_CODE_POINTS = 16
        const val MAXIMUM_ADDRESS_CODE_POINTS = 18
        val CANONICAL_ADDRESS = Regex("^0x(?:0|[1-9a-f][0-9a-f]{0,15})$")
    }
}

private class ModelBudget(private val limits: CanonicalProgramModelStreamingLimits) {
    private var nodes = 0L
    private var totalStringBytes = 0L

    fun chargeNode(label: String) {
        nodes = try {
            Math.addExact(nodes, 1L)
        } catch (failure: ArithmeticException) {
            throw StructuralRecoveryV1Exception("program model node count overflowed at $label", failure)
        }
        if (nodes > limits.maximumNodes) modelFail("program model exceeds its node limit")
    }

    fun chargeString(value: String, maximumCodePoints: Int, allowEmpty: Boolean, label: String) {
        val measurement = measureScalarUtf8(value, label)
        if (measurement.codePoints > maximumCodePoints || !allowEmpty && measurement.codePoints == 0) {
            modelFail("$label is empty or exceeds its code-point limit")
        }
        totalStringBytes = try {
            Math.addExact(totalStringBytes, measurement.utf8Bytes)
        } catch (failure: ArithmeticException) {
            throw StructuralRecoveryV1Exception("program model string-byte count overflowed", failure)
        }
        if (totalStringBytes > limits.maximumTotalStringBytes) {
            modelFail("program model strings exceed their aggregate UTF-8 byte limit")
        }
    }
}

private data class ScalarUtf8Measurement(val codePoints: Int, val utf8Bytes: Long)

private fun measureScalarUtf8(value: String, label: String): ScalarUtf8Measurement {
    var offset = 0
    var points = 0
    var bytes = 0L
    while (offset < value.length) {
        val first = value[offset]
        val codePoint = when {
            Character.isHighSurrogate(first) -> {
                if (offset + 1 >= value.length || !Character.isLowSurrogate(value[offset + 1])) {
                    modelFail("$label contains an unpaired surrogate")
                }
                Character.toCodePoint(first, value[offset + 1]).also { offset++ }
            }
            Character.isLowSurrogate(first) -> modelFail("$label contains an unpaired surrogate")
            else -> first.code
        }
        points++
        bytes += when {
            codePoint <= 0x7f -> 1
            codePoint <= 0x7ff -> 2
            codePoint <= 0xffff -> 3
            else -> 4
        }
        offset++
    }
    return ScalarUtf8Measurement(points, bytes)
}

/** Emits the historical [RecoveredProgramModel.toJson] form while comparing, never buffering it. */
private class ExactCanonicalModelComparator(private val expected: ByteArray) {
    private var offset = 0

    fun verify(model: RecoveredProgramModel) {
        ascii("{\n  \"schemaVersion\": ")
        ascii(model.schemaVersion.toString())
        ascii(",\n  \"inputSha256\": ")
        jsonString(model.inputSha256)
        ascii(",\n  \"functions\": [")
        if (model.functions.isNotEmpty()) ascii("\n")
        model.functions.forEachIndexed { index, function ->
            if (index > 0) ascii(",\n")
            ascii("    {\n      \"id\": ")
            jsonString(function.id)
            ascii(",\n      \"name\": ")
            jsonString(function.name)
            ascii(",\n      \"address\": ")
            jsonString("0x${function.address.toString(16)}")
            ascii(",\n      \"prototype\": ")
            jsonString(function.prototype)
            ascii(",\n      \"status\": ")
            jsonString(function.status.name.lowercase(Locale.ROOT))
            ascii(",\n      \"calls\": [")
            stringSet(function.calls)
            ascii("],\n      \"referencedGlobals\": [")
            stringSet(function.referencedGlobals)
            ascii("],\n      \"strings\": [")
            stringSet(function.strings)
            ascii("],\n      \"decompiledC\": ")
            nullableString(function.decompiledC)
            ascii("\n    }")
        }
        ascii("\n  ],\n  \"globals\": [")
        if (model.globals.isNotEmpty()) ascii("\n")
        model.globals.forEachIndexed { index, global ->
            if (index > 0) ascii(",\n")
            ascii("    {\n      \"id\": ")
            jsonString(global.id)
            ascii(",\n      \"name\": ")
            jsonString(global.name)
            ascii(",\n      \"address\": ")
            jsonString("0x${global.address.toString(16)}")
            ascii(",\n      \"type\": ")
            jsonString(global.type)
            ascii(",\n      \"initializer\": ")
            nullableString(global.initializer)
            ascii(",\n      \"status\": ")
            jsonString(global.status.name.lowercase(Locale.ROOT))
            ascii("\n    }")
        }
        ascii("\n  ],\n  \"types\": [")
        if (model.types.isNotEmpty()) ascii("\n")
        model.types.forEachIndexed { index, type ->
            if (index > 0) ascii(",\n")
            ascii("    {\n      \"id\": ")
            jsonString(type.id)
            ascii(",\n      \"declaration\": ")
            jsonString(type.declaration)
            ascii(",\n      \"sourceAddress\": ")
            if (type.sourceAddress == null) ascii("null") else jsonString("0x${type.sourceAddress.toString(16)}")
            ascii(",\n      \"status\": ")
            jsonString(type.status.name.lowercase(Locale.ROOT))
            ascii("\n    }")
        }
        ascii("\n  ]\n}\n")
        if (offset != expected.size) canonicalFail()
    }

    private fun stringSet(values: Set<String>) {
        values.forEachIndexed { index, value ->
            if (index > 0) ascii(", ")
            jsonString(value)
        }
    }

    private fun nullableString(value: String?) {
        if (value == null) ascii("null") else jsonString(value)
    }

    private fun jsonString(value: String) {
        byte('"'.code)
        var index = 0
        while (index < value.length) {
            val current = value[index]
            when (current) {
                '\\' -> ascii("\\\\")
                '"' -> ascii("\\\"")
                '\n' -> ascii("\\n")
                '\r' -> ascii("\\r")
                '\t' -> ascii("\\t")
                else -> when {
                    current.code < 0x20 -> ascii("\\u${current.code.toString(16).padStart(4, '0')}")
                    Character.isHighSurrogate(current) -> {
                        if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) canonicalFail()
                        utf8(Character.toCodePoint(current, value[++index]))
                    }
                    Character.isLowSurrogate(current) -> canonicalFail()
                    else -> utf8(current.code)
                }
            }
            index++
        }
        byte('"'.code)
    }

    private fun ascii(value: String) {
        value.forEach { character ->
            if (character.code > 0x7f) canonicalFail()
            byte(character.code)
        }
    }

    private fun utf8(codePoint: Int) {
        when {
            codePoint <= 0x7f -> byte(codePoint)
            codePoint <= 0x7ff -> {
                byte(0xc0 or (codePoint shr 6))
                byte(0x80 or (codePoint and 0x3f))
            }
            codePoint <= 0xffff -> {
                byte(0xe0 or (codePoint shr 12))
                byte(0x80 or (codePoint shr 6 and 0x3f))
                byte(0x80 or (codePoint and 0x3f))
            }
            else -> {
                byte(0xf0 or (codePoint shr 18))
                byte(0x80 or (codePoint shr 12 and 0x3f))
                byte(0x80 or (codePoint shr 6 and 0x3f))
                byte(0x80 or (codePoint and 0x3f))
            }
        }
    }

    private fun byte(value: Int) {
        if (offset >= expected.size || (expected[offset].toInt() and 0xff) != value) canonicalFail()
        offset++
    }

    private fun canonicalFail(): Nothing = modelFail(
        "program model bytes are not in exact canonical schema-v1 byte form at byte $offset",
    )
}

private fun modelFail(message: String): Nothing = throw StructuralRecoveryV1Exception(message)
