package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.DigestInputStream
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/** Bindings for raw, recovered Ghidra data observations; these fields never provide oracle identity. */
data class GlobalTypeObservationBindingsV1(
    val inputSha256: String,
    val exporterSha256: String,
    val archiveSha256: String,
    val programModelBytes: Long,
    val programModelSha256: String,
    val languageId: String,
    val compilerSpecId: String,
    val imageBase: String,
)

data class GlobalTypeObservationLimitsV1(
    val maximumBytes: Long = 64L * 1024 * 1024,
    val maximumLineBytes: Int = 1024 * 1024,
    val maximumDefinedData: Int = 131_072,
    val maximumFunctions: Int = 131_072,
    val maximumAddressSpaces: Int = 256,
    val maximumGraphNodes: Int = 200_000,
    val maximumGraphEdges: Int = 1_000_000,
    val maximumReferences: Int = 1_000_000,
    val maximumTotalRecords: Long = 1_700_000,
    val maximumStringBytes: Int = 4096,
) {
    init {
        require(maximumBytes in 1..64L * 1024 * 1024)
        require(maximumLineBytes in 1..1024 * 1024 && maximumDefinedData in 0..131_072)
        require(maximumFunctions in 0..131_072 && maximumAddressSpaces in 1..256)
        require(maximumGraphNodes in 0..200_000 && maximumGraphEdges in 0..1_000_000)
        require(maximumReferences in 0..1_000_000 && maximumTotalRecords in 0..1_700_000)
        require(maximumStringBytes in 1..4096)
    }
}

data class GlobalTypeObservationSummaryV1(
    val sidecarBytes: Long,
    val sidecarSha256: String,
    val definedDataEntities: Long,
    val functionsInCapture: Long,
    val typeNodes: Long,
    val typeEdges: Long,
    val enumMembers: Long,
    val functionGlobalReferences: Long,
    val unresolvedFunctionGlobalReferences: Long,
) {
    /** Empty source census has a distinct state and cannot stand in for production population. */
    val suppliedListingCensusState: String = if (definedDataEntities == 0L) "empty" else "captured-nonempty"
    val authorityBoundary: String = "recovered-observations-only"
    val populationBoundary: String = "oracle-population-identity-and-visibility-not-supplied"
}

/**
 * Strict bounded NDJSON reader. Its callback is speculative until successful return; consumers
 * must discard staged rows on any exception. Raw address keys are capture locators, not identities.
 */
object GlobalTypeObservationsV1 {
    private const val POLICY = "ghidra-global-type-observations-v1"
    private val DIGEST = Regex("[a-f0-9]{64}")
    private val CAPTURE_KEY = Regex("as(0|[1-9][0-9]{0,2})@[a-f0-9]{16}")
    private val FUNCTION_ID = Regex("fn_[a-f0-9]{16}")

    fun validate(
        expectedBindings: GlobalTypeObservationBindingsV1,
        expectedBytes: Long,
        expectedSha256: String,
        expectedFunctionIds: Set<String>,
        limits: GlobalTypeObservationLimitsV1 = GlobalTypeObservationLimitsV1(),
        checkpoint: () -> Unit,
        openObservations: () -> InputStream,
        consume: (JsonObject) -> Unit = {},
    ): GlobalTypeObservationSummaryV1 {
        require(expectedBytes in 1..limits.maximumBytes && DIGEST.matches(expectedSha256))
        require(expectedFunctionIds.size <= limits.maximumFunctions && expectedFunctionIds.all(FUNCTION_ID::matches)) {
            "global/type function identities exceed their independently supplied bound"
        }
        val functionIds = expectedFunctionIds.toSet()
        listOf(expectedBindings.inputSha256, expectedBindings.exporterSha256, expectedBindings.archiveSha256,
            expectedBindings.programModelSha256).forEach { require(DIGEST.matches(it)) }
        require(expectedBindings.programModelBytes in 1..512L * 1024 * 1024)
        val digest = MessageDigest.getInstance("SHA-256")
        var totalBytes = 0L
        var totalRecords = 0L
        var expectedData = -1L
        var expectedFunctions = -1L
        var expectedSpaces = -1
        var dataCount = 0L
        var typeRoots = 0L
        var typeNodes = 0L
        var typeEdges = 0L
        var enumMembers = 0L
        var references = 0L
        var unresolved = 0L
        var referenceSection = false
        var currentDataOrdinal = -1L
        var graphRoots = 0L
        val spaces = arrayListOf<JsonObject>()
        val dataKeys = HashSet<String>()
        val nodeIds = HashSet<Pair<Long, Long>>()
        val rootIds = HashSet<Long>()
        val graphEdgeKeys = HashSet<String>()
        val edgeTargets = arrayListOf<Triple<Long, Long, Long?>>()
        val roots = arrayListOf<Pair<Long, Long>>()
        var headerSeen = false
        openObservations().use { source ->
            val input = BufferedInputStream(DigestInputStream(source, digest), 65536)
            while (true) {
                checkpoint()
                val line = readLine(input, limits.maximumLineBytes) ?: break
                totalBytes = Math.addExact(totalBytes, line.size.toLong() + 1L)
                require(totalBytes <= expectedBytes && totalBytes <= limits.maximumBytes) { "global/type observations exceed their byte bound" }
                require(line.isNotEmpty() && line.none { it == '\r'.code.toByte() }) { "global/type observations contain an empty or CR line" }
                val json = OracleJson.parse(line, StrictJsonLimits(
                    maximumInputBytes = limits.maximumLineBytes,
                    maximumCanonicalBytes = limits.maximumLineBytes,
                    maximumDepth = 32,
                    maximumNodes = 20_000,
                    maximumStringBytes = limits.maximumStringBytes,
                    maximumTotalStringBytes = 256 * 1024,
                    maximumNumberCharacters = 32,
                ), checkpoint = { checkpoint() })
                val row = json as? JsonObject ?: fail("global/type NDJSON line must be an object")
                if (!headerSeen) {
                    parseHeader(row, expectedBindings, limits).also { header ->
                        expectedData = header.first
                        expectedFunctions = header.second
                        expectedSpaces = header.third
                        spaces += header.fourth
                    }
                    headerSeen = true
                    continue
                }
                totalRecords++
                require(totalRecords <= limits.maximumTotalRecords) { "global/type record count exceeds its bound" }
                when (row.string("recordKind")) {
                    "defined-data" -> {
                        require(!referenceSection) { "defined data followed function references" }
                        row.fields("addressSpace", "addressSpaceIndex", "captureKey", "dataOrdinal", "length", "linkageState",
                            "recordKind", "symbolExternal", "symbolGlobal", "symbolName", "symbolSource", "symbolType", "typePathCaptureKey")
                        val ordinal = row.number("dataOrdinal")
                        require(ordinal == dataCount && ordinal < expectedData) { "defined data ordinals are incomplete or unordered" }
                        currentDataOrdinal = ordinal
                        val key = row.string("captureKey")
                        val index = row.number("addressSpaceIndex").toInt()
                        validateAddress(key, index, spaces)
                        require(dataKeys.add(key)) { "defined data capture key repeats" }
                        require(row.string("addressSpace") == spaces[index].string("name"))
                        require(row.number("length") in 0..Int.MAX_VALUE.toLong())
                        require(row.string("linkageState") in setOf("no-primary-symbol", "primary-symbol-present"))
                        requireNullableString(row, "symbolName", limits)
                        requireNullableString(row, "symbolSource", limits)
                        requireNullableString(row, "symbolType", limits)
                        requireNullableBoolean(row, "symbolGlobal")
                        requireNullableBoolean(row, "symbolExternal")
                        require(row.string("typePathCaptureKey").let { it.isNotEmpty() && it.toByteArray(Charsets.UTF_8).size <= limits.maximumStringBytes })
                        dataCount++
                        graphRoots++
                        consume(row)
                    }
                    "type-node" -> {
                        row.fields("alignment", "alignedLength", "childCount", "dataOrdinal", "details", "expansion", "id", "kind", "length", "nativeClass", "notYetDefined", "recordKind", "scopeKind", "undefined", "zeroLength")
                        require(!referenceSection) { "type graph followed function references" }
                        require(row.string("scopeKind") == "defined-data")
                        val ordinal = row.number("dataOrdinal")
                        require(ordinal in 0 until dataCount && ordinal == currentDataOrdinal)
                        val id = row.number("id")
                        require(id in 0..Int.MAX_VALUE.toLong() && nodeIds.add(ordinal to id))
                        require(row.string("kind").isNotEmpty() && row.string("nativeClass").isNotEmpty() &&
                            row.number("childCount") in 0..4096 && row.number("alignment") in -1..Int.MAX_VALUE.toLong() &&
                            row.number("alignedLength") in -1..Int.MAX_VALUE.toLong() && row.number("length") in -1..Int.MAX_VALUE.toLong())
                        require(++typeNodes <= limits.maximumGraphNodes)
                        consume(row)
                    }
                    "type-edge" -> {
                        row.fields("bitField", "dataOrdinal", "fieldName", "length", "offset", "ordinal", "recordKind", "referenceState", "relation", "scopeKind", "source", "target", "undefined", "zeroBitField")
                        require(!referenceSection) { "type graph followed function references" }
                        require(row.string("scopeKind") == "defined-data")
                        val ordinal = row.number("dataOrdinal")
                        require(ordinal in 0 until dataCount && ordinal == currentDataOrdinal)
                        val source = row.number("source")
                        val edgeOrdinal = row.number("ordinal")
                        require(source >= 0 && edgeOrdinal >= 0)
                        val target = when (val value = row["target"]) {
                            JsonNull -> null
                            is JsonPrimitive -> value.content.toLongOrNull() ?: fail("type edge target must be an integer or null")
                            else -> fail("type edge target must be an integer or null")
                        }
                        require(target == null || target >= 0)
                        require(graphEdgeKeys.add("$ordinal:$source:$edgeOrdinal"))
                        edgeTargets.add(Triple(ordinal, source, target))
                        require(++typeEdges <= limits.maximumGraphEdges)
                        consume(row)
                    }
                    "type-root" -> {
                        row.fields("dataOrdinal", "recordKind", "rootNode")
                        require(!referenceSection && row.number("dataOrdinal") == currentDataOrdinal)
                        val root = row.number("rootNode")
                        require(root >= 0 && rootIds.add(currentDataOrdinal))
                        roots.add(currentDataOrdinal to root)
                        typeRoots++
                        consume(row)
                    }
                    "enum-member" -> {
                        row.fields("dataOrdinal", "enumeratorName", "recordKind", "value", "valueBits")
                        require(!referenceSection && row.number("dataOrdinal") == currentDataOrdinal)
                        val name = row.string("enumeratorName")
                        require(name.isNotEmpty() && name.toByteArray(Charsets.UTF_8).size <= limits.maximumStringBytes)
                        require(row.number("value") == row.string("valueBits").toULong(16).toLong())
                        require(++enumMembers <= limits.maximumGraphEdges)
                        consume(row)
                    }
                    "function-global-reference" -> {
                        referenceSection = true
                        row.fields("dataCaptureKey", "functionId", "operandIndex", "recordKind", "referenceAddress", "targetAddress")
                        require(row.string("functionId") in functionIds)
                        validateAddress(row.string("dataCaptureKey"), captureSpace(row.string("dataCaptureKey")), spaces)
                        validateAddress(row.string("referenceAddress"), captureSpace(row.string("referenceAddress")), spaces)
                        validateAddress(row.string("targetAddress"), captureSpace(row.string("targetAddress")), spaces)
                        require(row.string("dataCaptureKey") in dataKeys)
                        require(row.number("operandIndex") in -1..Int.MAX_VALUE.toLong())
                        require(++references <= limits.maximumReferences)
                        consume(row)
                    }
                    "function-global-reference-unresolved" -> {
                        referenceSection = true
                        row.fields("functionId", "operandIndex", "reason", "recordKind", "referenceAddress", "targetAddress")
                        require(row.string("functionId") in functionIds)
                        require(row.string("reason") in setOf("non-memory-target", "no-defined-data-containing-target"))
                        validateAddress(row.string("referenceAddress"), captureSpace(row.string("referenceAddress")), spaces)
                        validateAddress(row.string("targetAddress"), captureSpace(row.string("targetAddress")), spaces)
                        require(row.number("operandIndex") in -1..Int.MAX_VALUE.toLong())
                        require(++unresolved <= limits.maximumReferences)
                        consume(row)
                    }
                    else -> fail("unknown global/type observation record")
                }
            }
            require(headerSeen) { "global/type observations omit their header" }
            require(totalBytes == expectedBytes) { "global/type observation byte count differs" }
            require(MessageDigest.isEqual(digest.digest(), expectedSha256.hexBytes())) { "global/type observation digest differs" }
        }
        require(dataCount == expectedData && typeRoots == expectedData && rootIds.size.toLong() == expectedData) {
            "defined-data census or per-entity type-root conservation failed"
        }
        require(roots.all { (ordinal, root) -> (ordinal to root) in nodeIds } &&
            edgeTargets.all { (ordinal, source, target) -> (ordinal to source) in nodeIds &&
                (target == null || (ordinal to target) in nodeIds) }) { "type graph contains a dangling node reference" }
        require(spaces.size == expectedSpaces && expectedFunctions == functionIds.size.toLong())
        return GlobalTypeObservationSummaryV1(totalBytes, expectedSha256, dataCount, expectedFunctions,
            typeNodes, typeEdges, enumMembers, references, unresolved)
    }

    private data class Header(val first: Long, val second: Long, val third: Int, val fourth: List<JsonObject>)

    private fun parseHeader(row: JsonObject, expected: GlobalTypeObservationBindingsV1,
        limits: GlobalTypeObservationLimitsV1): Header {
        row.fields("addressSpaces", "bindings", "definedDataCount", "functionCount", "policy", "recordKind")
        require(row.string("recordKind") == "header" && row.string("policy") == POLICY)
        val bindings = row.objectValue("bindings")
        bindings.fields("archiveSha256", "compilerSpecId", "exporterSha256", "imageBase", "inputSha256", "languageId", "programModelBytes", "programModelSha256")
        require(bindings.string("inputSha256") == expected.inputSha256 && bindings.string("exporterSha256") == expected.exporterSha256 &&
            bindings.string("archiveSha256") == expected.archiveSha256 && bindings.number("programModelBytes") == expected.programModelBytes &&
            bindings.string("programModelSha256") == expected.programModelSha256 && bindings.string("languageId") == expected.languageId &&
            bindings.string("compilerSpecId") == expected.compilerSpecId && bindings.string("imageBase") == expected.imageBase) {
            "global/type capture bindings differ from the selected program"
        }
        val dataCount = row.number("definedDataCount")
        val functionCount = row.number("functionCount")
        val rawSpaces = row.array("addressSpaces")
        require(dataCount in 0..limits.maximumDefinedData.toLong() && functionCount in 0..limits.maximumFunctions.toLong() &&
            rawSpaces.size in 1..limits.maximumAddressSpaces)
        val spaces = rawSpaces.mapIndexed { index, value ->
            val space = value as? JsonObject ?: fail("address space must be an object")
            space.fields("addressableUnitSize", "index", "name", "overlay", "signedOffsets", "sizeBits", "type")
            require(space.number("index") == index.toLong() && space.string("name").isNotEmpty() &&
                space.number("type") >= 0 && space.number("sizeBits") in 1..128 &&
                space.number("addressableUnitSize") in 1..Int.MAX_VALUE.toLong())
            require(space.string("name").toByteArray(Charsets.UTF_8).size <= limits.maximumStringBytes)
            space
        }
        return Header(dataCount, functionCount, rawSpaces.size, spaces)
    }

    private fun validateAddress(key: String, expectedIndex: Int, spaces: List<JsonObject>) {
        val match = CAPTURE_KEY.matchEntire(key) ?: fail("address capture key is malformed")
        val index = match.groupValues[1].toInt()
        require(index == expectedIndex && index in spaces.indices) { "address capture key references an absent address space" }
    }

    private fun captureSpace(key: String): Int = CAPTURE_KEY.matchEntire(key)?.groupValues?.get(1)?.toInt()
        ?: fail("address capture key is malformed")

    private fun readLine(input: InputStream, maximum: Int): ByteArray? {
        val output = ByteArrayOutputStream(minOf(maximum, 4096))
        while (true) {
            val value = input.read()
            if (value < 0) return if (output.size() == 0) null else fail("global/type observations lack a final newline")
            if (value == '\n'.code) return output.toByteArray()
            require(output.size() < maximum) { "global/type record line exceeds its byte bound" }
            output.write(value)
        }
    }

    private fun JsonObject.fields(vararg expected: String) = require(keys == expected.toSet()) { "global/type record fields are invalid" }
    private fun JsonObject.string(name: String): String = (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
        ?: fail("global/type $name must be a string")
    private fun JsonObject.number(name: String): Long = (this[name] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull()
        ?: fail("global/type $name must be a bounded integer")
    private fun JsonObject.boolean(name: String): Boolean = (this[name] as? JsonPrimitive)?.takeIf { !it.isString && it.content in setOf("true", "false") }?.content?.toBooleanStrict()
        ?: fail("global/type $name must be a boolean")
    private fun JsonObject.objectValue(name: String): JsonObject = this[name] as? JsonObject ?: fail("global/type $name must be an object")
    private fun JsonObject.array(name: String): JsonArray = this[name] as? JsonArray ?: fail("global/type $name must be an array")
    private fun requireNullableString(row: JsonObject, name: String, limits: GlobalTypeObservationLimitsV1) {
        val item = row[name]
        if (item != JsonNull) require(item is JsonPrimitive && item.isString && item.content.toByteArray(Charsets.UTF_8).size <= limits.maximumStringBytes)
    }
    private fun requireNullableBoolean(row: JsonObject, name: String) {
        if (row[name] != JsonNull) row.boolean(name)
    }
    private fun String.hexBytes(): ByteArray {
        require(length == 64)
        return ByteArray(32) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }
    private fun fail(message: String): Nothing = throw IllegalArgumentException(message)
}
