package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.structural.CanonicalProgramModelStreaming
import io.github.optimumcode.json.schema.JsonSchema
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import kotlin.test.*
import kotlinx.serialization.json.*

/** Authored byte controls validate transport and coverage, never ABI accuracy or live provenance. */
class NativeInterfaceObservationsV1Test {
    @Test
    fun `typed observations preserve formal effective automatic indirect and ordered storage facts`() {
        val seen = mutableListOf<NativeInterfaceRecordV1>()
        val result = assess(fixture(), consume = seen::add)
        val function = seen.filterIsInstance<NativeInterfaceFunctionV1>()[1]
        assertEquals("USER_DEFINED", function.signatureSource)
        assertEquals("__thiscall", function.convention.resolvedModel)
        assertTrue(function.varArgs)
        assertTrue(function.customStorage)
        assertEquals(0, function.returned!!.formalType)
        assertEquals(1, function.returned!!.effectiveType)
        val parameter = function.parameters.single()
        assertTrue(parameter.autoParameter)
        assertEquals("THIS", parameter.autoParameterType)
        assertTrue(parameter.forcedIndirect)
        assertEquals(2, parameter.formalType)
        assertEquals(3, parameter.effectiveType)
        assertEquals(listOf(addrValue(2, 0x10), addrValue(3, -8)), parameter.storage.varnodes.map { it.address })
        assertEquals(16, parameter.storage.size)
        assertEquals(listOf("structure", "pointer", "structure", "pointer"), seen.filterIsInstance<NativeInterfaceTypeV1>().map { it.kind })
        assertEquals(NativeInterfaceScanV1(4, 3, 1, 1, 1, 1, 4, 3), result.scan)
        assertFalse(result.authoritativeOracleEvidence)
        assertFalse(result.recoveredModelScored)
        assertFalse(result.productionInterfacesAdmitted)
        assertFalse(result.releaseEligible)
        assertEquals("not-captured", result.highFunctionState)
        assertEquals("not-captured", result.typeClosureState)
        assertEquals("not-captured", result.abiClassificationState)
    }

    @Test
    fun `complete projection retains missing model external thunk and off space functions`() {
        val result = assess(fixture())
        assertEquals(listOf("missing-listing-function", "matched"), result.modelFunctions.map { it.state })
        assertEquals(listOf("external-unmapped", "matched", "unmatched-observed-function", "different-address-space"), result.observedFunctions.map { it.state })
        assertEquals(listOf("model-only", "named-unrelated").sorted(), result.modelFunctions.map { it.id }.sorted())
        assertEquals(listOf("named-unrelated"), result.observedFunctions[1].modelIds)
        assertEquals(4, result.observedFunctions.size)
        assertEquals(2, result.modelFunctions.size)
        assertEquals("0000000000000030", result.modelFunctions.single { it.id == "model-only" }.modelAddressBits)
        assertTrue(result.modelFunctions.single { it.id == "model-only" }.candidateEntries.isEmpty())
    }

    @Test
    fun `duplicate model coordinates preserve every identity as ambiguous without name joins`() {
        val duplicated = model(listOf("first" to 0x10uL, "second" to 0x10uL, "missing" to 0x30uL))
        val result = assess(fixture(duplicated), duplicated)
        assertEquals(listOf("ambiguous-model-address", "missing-listing-function", "ambiguous-model-address"), result.modelFunctions.map { it.state })
        assertEquals(listOf("first", "second"), result.observedFunctions[1].modelIds)
        assertEquals("ambiguous-model-address", result.observedFunctions[1].state)
    }

    @Test
    fun `scalar model coordinates cannot choose between base and overlay native entries`() {
        val collision = assess(set(fixture(), addr(4, 0x10), "records", 3, "entry"))
        val row = collision.modelFunctions.single { it.id == "named-unrelated" }
        assertEquals("ambiguous-native-address", row.state)
        assertEquals(listOf(addrValue(1, 0x10), addrValue(4, 0x10)), row.candidateEntries)
        assertEquals("ambiguous-native-address", collision.observedFunctions[1].state)
        assertEquals("ambiguous-native-address", collision.observedFunctions[3].state)
        val offSpaceModel = model(listOf("overlay-scalar" to 0x40uL))
        val offSpace = assess(fixture(offSpaceModel), offSpaceModel)
        assertEquals("different-address-space", offSpace.modelFunctions.single().state)
        assertEquals(listOf(addrValue(4, 0x40)), offSpace.modelFunctions.single().candidateEntries)
    }

    @Test
    fun `empty listing conserves all model obligations without asserting recovered zero arity`() {
        var document = set(fixture(), JsonArray(emptyList()), "records")
        for (key in listOf("functions", "internalFunctions", "externalFunctions", "thunks", "parameters", "autoParameters", "types", "storageVarnodes"))
            document = set(document, JsonPrimitive(0), "summary", key)
        val result = assess(document)
        assertEquals(0L, result.scan.functions)
        assertTrue(result.observedFunctions.isEmpty())
        assertTrue(result.modelFunctions.all { it.state == "missing-listing-function" })
        assertEquals(2, result.modelFunctions.size)
    }

    @Test
    fun `raw automatic count disagreement is retained without replacing observed parameter flags`() {
        val seen = mutableListOf<NativeInterfaceRecordV1>()
        val result = assess(set(fixture(), JsonPrimitive(0), "records", 1, "autoParameterCount"), consume = seen::add)
        val function = seen.filterIsInstance<NativeInterfaceFunctionV1>()[1]
        assertEquals(0, function.autoParameterCount)
        assertTrue(function.parameters.single().autoParameter)
        assertFalse(function.autoParameterCountMatchesObserved)
        assertEquals(1L, result.scan.autoParameters)
    }

    @Test
    fun `signature root occurrences cannot alias omit reorder or fabricate types`() {
        val base = fixture()
        reject(set(base, JsonPrimitive(0), "records", 1, "return", "effectiveType"))
        reject(set(base, JsonPrimitive(4), "records", 1, "parameters", 0, "formalType"))
        reject(set(base, JsonPrimitive(1), "records", 4, "ordinal"))
        reject(set(base, JsonPrimitive("signed"), "records", 4, "signedness"))
        reject(set(base, JsonPrimitive("captured"), "records", 4, "typeClosure"))
        val rows = base.getValue("records").jsonArray
        reject(set(base, JsonArray(rows.dropLast(1)), "records"))
        reject(set(base, JsonArray(rows + rows.last()), "records"))
        reject(set(base, JsonArray(rows.toMutableList().apply { val saved = this[3]; this[3] = this[4]; this[4] = saved }), "records"))
    }

    @Test
    fun `storage special states remain distinct and inconsistent assigned metadata is rejected`() {
        for (state in listOf("bad", "unassigned", "void", "absent")) {
            var document = set(fixture(), storage(state, emptyList()), "records", 1, "parameters", 0, "storage")
            document = set(document, JsonPrimitive(1), "summary", "storageVarnodes")
            val seen = mutableListOf<NativeInterfaceRecordV1>()
            assess(document, consume = seen::add)
            assertEquals(state, seen.filterIsInstance<NativeInterfaceFunctionV1>()[1].parameters.single().storage.state)
        }
        val base = fixture()
        reject(set(base, JsonPrimitive(8), "records", 1, "parameters", 0, "storage", "size"))
        reject(set(base, JsonPrimitive("unassigned"), "records", 1, "parameters", 0, "storage", "state"))
        reject(set(base, JsonPrimitive(false), "records", 1, "parameters", 0, "storage", "autoStorage"))
        reject(set(base, JsonPrimitive(0), "records", 1, "parameters", 0, "storage", "varnodes", 0, "size"))
        reject(set(base, obj("kind" to "no-address"), "records", 1, "parameters", 0, "storage", "varnodes", 0, "address"))
    }

    @Test
    fun `closed metadata rejects authority source cardinality and coordinate substitutions`() {
        val base = fixture()
        for (path in listOf(emptyList(), listOf("bindings"), listOf("records", 1), listOf("records", 1, "return"), listOf("records", 1, "parameters", 0, "storage"), listOf("records", 4), listOf("summary"))) {
            reject(edit(base, path) { JsonObject(it.jsonObject + ("productionVerified" to JsonPrimitive(true))) })
        }
        for ((path, value) in listOf(
            listOf("records", 1, "highFunction") to JsonPrimitive("captured"),
            listOf("records", 1, "signatureSource") to JsonPrimitive("ORACLE"),
            listOf("records", 1, "parameterCount") to JsonPrimitive(0),
            listOf("records", 1, "autoParameterCount") to JsonPrimitive(2),
            listOf("records", 1, "parameters", 0, "ordinal") to JsonPrimitive(1),
            listOf("records", 1, "return", "ordinal") to JsonPrimitive(0),
            listOf("records", 1, "parameters", 0, "autoParameterType") to JsonNull,
            listOf("records", 0, "isExternal") to JsonPrimitive(false),
            listOf("records", 2, "immediateThunkTarget") to JsonNull,
            listOf("records", 2, "immediateThunkTarget") to addr(1, 0x99),
            listOf("records", 1, "convention", "resolvedModel") to JsonNull,
            listOf("records", 1, "convention", "state") to JsonPrimitive("default"),
            listOf("records", 4, "kind") to JsonPrimitive("integer"),
            listOf("summary", "functions") to JsonPrimitive(3),
            listOf("addressSpaces", 1, "index") to JsonPrimitive(0),
            listOf("records", 1, "entry", "offsetBits") to JsonPrimitive("000000000000001A"),
        )) reject(edit(base, path) { value })
    }

    @Test
    fun `typed address order uniqueness and sign extension are enforced`() {
        val base = fixture()
        reject(set(base, addr(1, 0x10), "records", 2, "entry"))
        reject(set(base, addr(1, 9), "records", 2, "entry"))
        reject(set(base, JsonPrimitive(16), "addressSpaces", 3, "sizeBits").let {
            set(it, JsonPrimitive("000000000000fff8"), "records", 1, "parameters", 0, "storage", "varnodes", 1, "address", "offsetBits")
        })
        assess(set(base, JsonPrimitive(16), "addressSpaces", 3, "sizeBits"))
    }

    @Test
    fun `native addressable units bound byte offsets and HASH metadata is retained`() {
        var document = set(fixture(), JsonPrimitive(8), "addressSpaces", 2, "sizeBits")
        document = set(document, JsonPrimitive(2), "addressSpaces", 2, "addressableUnitSize")
        document = set(document, JsonPrimitive("0000000000000100"), "records", 1, "parameters", 0, "storage", "varnodes", 0, "address", "offsetBits")
        assess(document)
        reject(set(document, JsonPrimitive("0000000000000200"), "records", 1, "parameters", 0, "storage", "varnodes", 0, "address", "offsetBits"))
        reject(set(fixture(), JsonPrimitive(2), "addressSpaces", 1, "addressableUnitSize"))
        assess(set(fixture(), JsonPrimitive(14), "addressSpaces", 2, "type"))
    }

    @Test
    fun `exact frozen model input runtime and observation byte commitments reject substitutions`() {
        val base = fixture()
        for (field in listOf("inputSha256", "collectorSha256", "programModelSha256", "programModelExporterSha256", "ghidraArchiveSha256"))
            reject(set(base, JsonPrimitive("f".repeat(64)), "bindings", field))
        reject(set(base, JsonPrimitive("other"), "bindings", "languageId"))
        reject(set(base, JsonPrimitive("other"), "bindings", "compilerSpecId"))
        reject(set(base, JsonPrimitive(1), "bindings", "programModelBytes"))
        val bytes = canonical(base)
        val manifest = manifest(bytes)
        assertFails { assessBytes(bytes + ' '.code.toByte(), manifest) }
        assertFails { assessBytes(bytes.copyOf().apply { this[lastIndex] = 'x'.code.toByte() }, manifest) }
        assertFails { assessBytes(bytes, manifest, model(listOf("replacement" to 0x10uL))) }
        assertFails { assessBytes(bytes, canonical(JsonObject(OracleJson.parseCanonical(manifest).jsonObject + ("authority" to JsonPrimitive(true))))) }
    }

    @Test
    fun `paired full model accepts a prototype beyond historical scoring limits within explicit byte bounds`() {
        val expandedModel = RecoveredProgramModel(inputSha256 = INPUT, functions = listOf(
            RecoveredFunction("large-prototype", "same-display-name", 0x10uL, "p".repeat(1024 * 1024 + 1)),
        )).toJson().toByteArray()
        assertFails { CanonicalProgramModelStreaming.readCanonical(expandedModel) }
        val result = assess(fixture(expandedModel), expandedModel)
        assertEquals("matched", result.modelFunctions.single().state)
        assertEquals(expandedModel.size.toLong(), result.bindings.programModelBytes)
        assertEquals(sha(expandedModel), result.bindings.programModelSha256)
        assertFails { assess(fixture(expandedModel), expandedModel,
            NativeInterfaceObservationLimitsV1(maximumModelBytes = expandedModel.size - 1)) }
    }

    @Test
    fun `explicit work byte and aggregate limits fail closed and cancellation closes stream`() {
        val base = fixture()
        val limits = listOf(
            NativeInterfaceObservationLimitsV1(maximumFunctions = 3),
            NativeInterfaceObservationLimitsV1(maximumTypes = 3),
            NativeInterfaceObservationLimitsV1(maximumStorageVarnodes = 2),
            NativeInterfaceObservationLimitsV1(maximumVarnodesPerStorage = 1),
            NativeInterfaceObservationLimitsV1(maximumAddressSpaces = 4),
            NativeInterfaceObservationLimitsV1(maximumCombinedBytes = 1000),
            NativeInterfaceObservationLimitsV1(maximumModelBytes = 1),
            NativeInterfaceObservationLimitsV1(maximumStringBytes = 10),
            NativeInterfaceObservationLimitsV1(maximumRecordBytes = 100, maximumStringBytes = 100),
        )
        limits.forEach { limit -> assertFails { assess(base, limits = limit) } }
        val bytes = canonical(base)
        val stream = object : ByteArrayInputStream(bytes) {
            var closed = false
            override fun close() { closed = true; super.close() }
        }
        val cancellation = IllegalStateException("cancel authored observation")
        var checkpoints = 0
        val failure = assertFails {
            NativeInterfaceObservationsV1.validate(manifest(bytes), bindings(MODEL), MODEL, checkpoint = {
                if (++checkpoints == 6) throw cancellation
            }, openObservations = { stream })
        }
        assertSame(cancellation, failure.cause)
        assertTrue(stream.closed)
    }

    @Test
    fun `validated projected universes and nested parameter collections cannot be mutated`() {
        val seen = mutableListOf<NativeInterfaceRecordV1>()
        val result = assess(fixture(), consume = seen::add)
        assertFails { (result.modelFunctions as MutableList).clear() }
        assertFails { (result.observedFunctions as MutableList).clear() }
        assertFails { (result.modelFunctions.single { it.state == "matched" }.candidateEntries as MutableList).clear() }
        assertFails { (result.observedFunctions.single { it.state == "matched" }.modelIds as MutableList).clear() }
        val parameters = seen.filterIsInstance<NativeInterfaceFunctionV1>()[1].parameters
        assertFails { (parameters as MutableList).clear() }
        assertFails { (parameters.single().storage.varnodes as MutableList).clear() }
    }

    @Test
    fun `closed published schemas accept authored records and reject extra authority`() {
        for ((resource, document) in listOf(
            "/project/native-interface-observations-v1.schema.json" to fixture(),
            "/project/native-interface-observation-manifest-v1.schema.json" to OracleJson.parseCanonical(manifest(canonical(fixture()))).jsonObject,
        )) {
            val schema = JsonSchema.fromDefinition(checkNotNull(javaClass.getResourceAsStream(resource)).use { it.readBytes().decodeToString() })
            assertTrue(schema.validate(document) {})
            assertFalse(schema.validate(JsonObject(document + ("productionVerified" to JsonPrimitive(true)))) {})
        }
    }

    private fun assess(document: JsonObject, model: ByteArray = MODEL, limits: NativeInterfaceObservationLimitsV1 = NativeInterfaceObservationLimitsV1(), consume: (NativeInterfaceRecordV1) -> Unit = {}): NativeInterfaceObservationSummaryV1 {
        val bytes = canonical(document)
        return NativeInterfaceObservationsV1.validate(manifest(bytes, model), bindings(model), model, limits, {}, { ByteArrayInputStream(bytes) }, consume)
    }
    private fun assessBytes(bytes: ByteArray, manifest: ByteArray, model: ByteArray = MODEL) =
        NativeInterfaceObservationsV1.validate(manifest, bindings(model), model, checkpoint = {}, openObservations = { ByteArrayInputStream(bytes) })
    private fun reject(document: JsonObject) { assertFails { assess(document) } }
    private fun fixture(model: ByteArray = MODEL): JsonObject = obj(
        "addressSpaces" to listOf(space(0, "EXTERNAL", 10), space(1, "ram", 1), space(2, "register", 4), space(3, "stack", 5, signed = true), space(4, "overlay", 1, overlay = true)),
        "bindings" to bindingJson(model), "policy" to "ghidra-native-interface-observations-v1", "schemaVersion" to 1,
        "records" to listOf(
            function(addr(0, 0x80), external = true),
            JsonObject(function(addr(1, 0x10)) + mapOf(
                "signatureSource" to JsonPrimitive("USER_DEFINED"), "varArgs" to JsonPrimitive(true), "customStorage" to JsonPrimitive(true),
                "convention" to obj("name" to "__thiscall", "resolvedModel" to "__thiscall", "state" to "named-resolved"),
                "return" to parameter(-1, 0, storage("assigned", listOf(piece(2, 0, 8)))),
                "parameters" to JsonArray(listOf(parameter(0, 2, storage("assigned", listOf(piece(2, 0x10, 8), piece(3, -8, 8)), auto = true), auto = true))),
                "parameterCount" to JsonPrimitive(1), "autoParameterCount" to JsonPrimitive(1))),
            JsonObject(function(addr(1, 0x20)) + mapOf("isThunk" to JsonPrimitive(true), "immediateThunkTarget" to addr(1, 0x10))),
            function(addr(4, 0x40)), type(0, "structure"), type(1, "pointer"), type(2, "structure"), type(3, "pointer")),
        "summary" to obj("coverage" to "all-currently-listed-internal-and-external-functions", "functions" to 4, "internalFunctions" to 3, "externalFunctions" to 1, "thunks" to 1, "parameters" to 1, "autoParameters" to 1, "types" to 4, "storageVarnodes" to 3, "highFunction" to "not-captured", "typeClosure" to "not-captured", "abiClassification" to "not-captured"),
    )
    private fun function(entry: JsonObject, external: Boolean = false) = obj("recordKind" to "function", "entry" to entry, "name" to "same-display-name", "isExternal" to external, "isThunk" to false, "immediateThunkTarget" to null, "signatureSource" to "DEFAULT", "convention" to obj("name" to null, "resolvedModel" to null, "state" to "unknown"), "varArgs" to false, "customStorage" to false, "parameterCount" to 0, "autoParameterCount" to 0, "return" to null, "parameters" to emptyList<Any>(), "highFunction" to "not-captured")
    private fun parameter(ordinal: Int, type: Int, storage: JsonObject, auto: Boolean = false) = obj("ordinal" to ordinal, "name" to null, "source" to "USER_DEFINED", "autoParameter" to auto, "autoParameterType" to if (auto) "THIS" else null, "forcedIndirect" to true, "formalType" to type, "effectiveType" to type + 1, "storage" to storage)
    private fun storage(state: String, pieces: List<JsonObject>, auto: Boolean = false) = obj("state" to state, "size" to if (state == "absent") null else pieces.sumOf { it.getValue("size").jsonPrimitive.int }, "autoStorage" to if (state == "absent") null else auto, "autoParameterType" to if (auto) "THIS" else null, "forcedIndirect" to if (state == "absent") null else true, "varnodes" to pieces)
    private fun piece(space: Int, offset: Long, size: Int) = obj("address" to addr(space, offset), "size" to size)
    private fun type(ordinal: Int, kind: String) = obj("recordKind" to "type", "ordinal" to ordinal, "kind" to kind, "nativeClass" to "authored.$kind", "name" to "same-name", "path" to "/same-name", "length" to if (kind == "structure") 24 else 8, "alignedLength" to if (kind == "structure") 24 else 8, "alignment" to 8, "undefined" to false, "notYetDefined" to false, "signedness" to null, "layout" to "not-captured", "typeClosure" to "not-captured")
    private fun space(index: Int, name: String, type: Int, signed: Boolean = false, overlay: Boolean = false) = obj("index" to index, "name" to name, "type" to type, "sizeBits" to 64, "addressableUnitSize" to 1, "overlay" to overlay, "signedOffsets" to signed)
    private fun addr(space: Int, offset: Long) = obj("kind" to "address", "spaceIndex" to space, "offsetBits" to offset.toULong().toString(16).padStart(16, '0'))
    private fun addrValue(space: Int, offset: Long) = NativeInterfaceAddressV1(space, offset.toULong().toString(16).padStart(16, '0'))
    private fun bindingJson(model: ByteArray) = obj("collectorSha256" to "b".repeat(64), "compilerSpecId" to "windows", "ghidraArchiveSha256" to "c".repeat(64), "imageBase" to addr(1, 0), "inputSha256" to INPUT, "languageId" to "x86:LE:64:default", "programModelBytes" to model.size, "programModelExporterSha256" to "d".repeat(64), "programModelSha256" to sha(model))
    private fun bindings(model: ByteArray) = NativeInterfaceBindingsV1("b".repeat(64), "windows", "c".repeat(64), addrValue(1, 0), INPUT, "x86:LE:64:default", model.size.toLong(), "d".repeat(64), sha(model))
    private fun manifest(bytes: ByteArray, model: ByteArray = MODEL) = canonical(obj("bytes" to bytes.size, "collectorSha256" to "b".repeat(64), "file" to "native-interfaces.json", "inputSha256" to INPUT, "kind" to "ghidra-native-interface-observation-manifest-v1", "programModelSha256" to sha(model), "schemaVersion" to 1, "sha256" to sha(bytes)))
    private fun set(root: JsonObject, value: JsonElement, vararg path: Any) = edit(root, path.toList()) { value }
    private fun edit(root: JsonObject, path: List<Any>, change: (JsonElement) -> JsonElement): JsonObject {
        fun walk(value: JsonElement, at: Int): JsonElement = if (at == path.size) change(value) else when (val key = path[at]) {
            is String -> JsonObject(value.jsonObject.toMutableMap().apply { this[key] = walk(getValue(key), at + 1) })
            is Int -> JsonArray(value.jsonArray.toMutableList().apply { this[key] = walk(this[key], at + 1) })
            else -> error("invalid authored path")
        }
        return walk(root, 0).jsonObject
    }
    companion object {
        private val INPUT = "a".repeat(64)
        private val MODEL = model(listOf("named-unrelated" to 0x10uL, "model-only" to 0x30uL))
        private fun model(functions: List<Pair<String, ULong>>) = RecoveredProgramModel(inputSha256 = INPUT, functions = functions.map { (id, address) -> RecoveredFunction(id, "same-display-name", address, "unparsed display") }).toJson().toByteArray()
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        private fun canonical(value: JsonElement) = OracleJson.canonicalBytes(value)
        private fun json(value: Any?): JsonElement = when (value) { null -> JsonNull; is JsonElement -> value; is String -> JsonPrimitive(value); is Boolean -> JsonPrimitive(value); is Number -> JsonPrimitive(value); is List<*> -> JsonArray(value.map(::json)); else -> error("unsupported authored value") }
        private fun obj(vararg fields: Pair<String, Any?>) = JsonObject(fields.associate { it.first to json(it.second) })
    }
}
