package decompengine.project

import decompengine.oracle.core.OracleJson
import io.github.optimumcode.json.schema.JsonSchema
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import kotlin.test.*
import kotlinx.serialization.json.*

/** Authored transport controls do not qualify an inference engine or grant production authority. */
class NativeInferredInterfaceObservationsV1Test {
    @Test
    fun `separate inferred symbols preserve listing zero parameters and complete model obligations`() {
        val seen = mutableListOf<NativeInferredInterfaceRecordV1>()
        val result = InferredInterfaceFixture.assess(consume = seen::add)
        val function = seen.filterIsInstance<NativeInferredInterfaceFunctionV1>().last()
        assertEquals(0L, result.listing.scan.parameters)
        assertEquals(1, function.parameters.size)
        assertEquals(1L, result.scan.parameters)
        assertEquals(listOf("matched", "missing-listing-function"), result.listing.modelFunctions.map { it.state })
        assertEquals(listOf("listing", "listing", "inferred", "inferred"), seen.filterIsInstance<NativeInterfaceTypeRootV1>().map { it.scope.channel })
        assertEquals(listOf("integer", "integer", "pointer", "structure"), seen.filterIsInstance<NativeInterfaceTypeNodeV1>().map { it.kind })
        assertEquals("backedge", seen.filterIsInstance<NativeInterfaceTypeEdgeV1>().last().referenceState)
        assertFalse(result.authoritativeOracleEvidence)
        assertFalse(result.recoveredModelScored)
        assertFalse(result.productionInterfacesAdmitted)
        assertFalse(result.releaseEligible)
        assertEquals("not-captured", result.abiClassification)
        assertEquals("not-captured", result.sourceTypeIdentity)
    }

    @Test
    fun `raw count category and high variable differences stay explicit without formal slot claims`() {
        var doc = InferredInterfaceFixture.fixture()
        doc = InferredInterfaceFixture.set(doc, JsonPrimitive(2), "records", InferredInterfaceFixture.FUNCTION, "prototype", "parameterCount")
        doc = InferredInterfaceFixture.set(doc, JsonPrimitive(false), "records", InferredInterfaceFixture.FUNCTION, "prototype", "parameterCountsMatch")
        doc = InferredInterfaceFixture.set(doc, JsonPrimitive(9), "records", InferredInterfaceFixture.FUNCTION, "parameters", 0, "categoryIndex")
        doc = InferredInterfaceFixture.set(doc, JsonPrimitive("absent"), "records", InferredInterfaceFixture.FUNCTION, "parameters", 0, "highVariableState")
        doc = InferredInterfaceFixture.set(doc, JsonNull, "records", InferredInterfaceFixture.FUNCTION, "parameters", 0, "highParamSlot")
        val seen = mutableListOf<NativeInferredInterfaceRecordV1>()
        InferredInterfaceFixture.assess(doc, consume = seen::add)
        val fn = seen.filterIsInstance<NativeInferredInterfaceFunctionV1>().last()
        assertFalse(fn.prototype!!.parameterCountsMatch)
        assertEquals(2, fn.prototype!!.parameterCount)
        assertEquals(1, fn.prototype!!.localSymbolParameterCount)
        assertEquals(9, fn.parameters.single().categoryIndex)
        assertNull(fn.parameters.single().highParamSlot)
        assertEquals("unavailable-native-api", fn.parameters.single().formalEffectiveRelation)
        assertEquals("unavailable-for-plain-decoded-storage", fn.parameters.single().forcedIndirectMeaning)
        assertFalse(fn.parameters.single().storage.forcedIndirect!!)
        assertEquals("first-mapping-only", fn.prototype!!.allMappings)
        assertEquals("unavailable-native-api", fn.prototype!!.privateFlags)
    }

    @Test
    fun `all failure and unsupported dispositions preserve their function instead of a zero arity success`() {
        val states = NativeInferredInterfaceObservationsV1.dispositions - setOf("high-function-observed", "not-attempted-external")
        for (state in states) {
            val doc = InferredInterfaceFixture.withOutcome(state)
            val seen = mutableListOf<NativeInferredInterfaceRecordV1>()
            val result = InferredInterfaceFixture.assess(doc, consume = seen::add)
            val fn = seen.filterIsInstance<NativeInferredInterfaceFunctionV1>().last()
            assertEquals(state, fn.disposition)
            assertNull(fn.prototype)
            assertTrue(fn.parameters.isEmpty())
            assertEquals(2L, result.scan.functions)
            assertEquals(0L, result.scan.observed)
            assertEquals(1L, result.scan.dispositions[state])
        }
    }

    @Test
    fun `listing graph roots must retain exact occurrence roles metadata and null presence`() {
        val base = InferredInterfaceFixture.fixture()
        for ((path, value) in listOf(
            listOf("records", 0, "length") to JsonPrimitive(8),
            listOf("records", 0, "nativeClass") to JsonPrimitive("forged.SameSize"),
            listOf("records", 0, "undefined") to JsonPrimitive(true),
            listOf("records", 1, "listingTypeOrdinal") to JsonPrimitive(1),
            listOf("records", 1, "role") to JsonPrimitive("parameter-formal"),
            listOf("records", 1, "node") to JsonNull,
            listOf("records", 2, "slot") to JsonPrimitive(0),
            listOf("records", 2, "channel") to JsonPrimitive("inferred"),
        )) InferredInterfaceFixture.reject(InferredInterfaceFixture.edit(base, path) { value })
    }

    @Test
    fun `complete census rejects missing duplicate substituted and reordered outcomes or roots`() {
        val base = InferredInterfaceFixture.fixture(); val rows = base.getValue("records").jsonArray
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonArray(rows.dropLast(1)), "records"))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonArray(rows + rows.last()), "records"))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonArray(rows.filterIndexed { index, _ -> index != 2 }), "records"))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, InferredInterfaceFixture.addr(1, 0x11), "records", InferredInterfaceFixture.FUNCTION, "entry"))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive(0), "records", InferredInterfaceFixture.FUNCTION, "functionOrdinal"))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive(true), "records", InferredInterfaceFixture.FUNCTION, "isExternal"))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive(true), "records", InferredInterfaceFixture.FUNCTION, "isThunk"))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive(0), "records", InferredInterfaceFixture.FUNCTION, "parameters", 0, "type"))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive(1), "records", InferredInterfaceFixture.FUNCTION, "prototype", "returnType"))
    }

    @Test
    fun `every binding and fixed inference configuration is compared to the exact frozen listing`() {
        val base = InferredInterfaceFixture.fixture()
        for (name in listOf("collectorSha256", "wrapperSha256", "nativeDecompilerSha256", "listingSha256", "listingManifestSha256", "configurationSha256"))
            InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive("f".repeat(64)), "bindings", name))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive(61), "configuration", "maximumSecondsPerFunction"))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive(false), "configuration", "syntaxTree"))
        assertFails { InferredInterfaceFixture.assess(base, expected = InferredInterfaceFixture.bindings().copy(configurationSha256 = "f".repeat(64))) }
        assertFails { InferredInterfaceFixture.assess(base, listingManifest = InferredInterfaceFixture.listingManifest() + byteArrayOf(10)) }
        assertFails { InferredInterfaceFixture.assess(base, model = InferredInterfaceFixture.model + byteArrayOf(10)) }
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive("other"), "addressSpaces", 1, "name"))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive(0), "bindings", "listingBindings", "programModelBytes"))
    }

    @Test
    fun `raw result flags storage and parameter population inconsistencies are rejected`() {
        val base = InferredInterfaceFixture.fixture()
        for ((path, value) in listOf(
            listOf("records", InferredInterfaceFixture.FUNCTION, "result", "timedOut") to JsonPrimitive(true),
            listOf("records", InferredInterfaceFixture.FUNCTION, "result", "completed") to JsonPrimitive(false),
            listOf("records", InferredInterfaceFixture.FUNCTION, "attempt") to JsonPrimitive(0),
            listOf("records", InferredInterfaceFixture.FUNCTION, "prototype", "parameterCountsMatch") to JsonPrimitive(false),
            listOf("records", InferredInterfaceFixture.FUNCTION, "prototype", "localSymbolParameterCount") to JsonPrimitive(0),
            listOf("records", InferredInterfaceFixture.FUNCTION, "prototype", "allMappings") to JsonPrimitive("complete"),
            listOf("records", InferredInterfaceFixture.FUNCTION, "parameters", 0, "highParamSlot") to JsonNull,
            listOf("records", InferredInterfaceFixture.FUNCTION, "parameters", 0, "index") to JsonPrimitive(1),
            listOf("records", InferredInterfaceFixture.FUNCTION, "parameters", 0, "storage", "size") to JsonPrimitive(4),
            listOf("records", InferredInterfaceFixture.FUNCTION, "parameters", 0, "storage", "state") to JsonPrimitive("unassigned"),
            listOf("records", InferredInterfaceFixture.FUNCTION, "parameters", 0, "storage", "autoParameterType") to JsonPrimitive("ORACLE"),
            listOf("records", InferredInterfaceFixture.FUNCTION, "parameters", 0, "storage", "varnodes", 0, "address", "offsetBits") to JsonPrimitive("ffffffffffffffff"),
            listOf("records", InferredInterfaceFixture.FUNCTION, "parameters", 0, "storage", "varnodes", 0, "address") to InferredInterfaceFixture.obj("kind" to "no-address"),
        )) InferredInterfaceFixture.reject(InferredInterfaceFixture.edit(base, path) { value })
    }

    @Test
    fun `summary cannot hide outcomes graph work source closure or authority`() {
        val base = InferredInterfaceFixture.fixture()
        for (name in listOf("functions", "attempted", "observed", "parameters", "roots", "graphNodes", "graphEdges", "graphWork", "storageVarnodes"))
            InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive(0), "summary", name))
        for (name in listOf("authoritativeOracleEvidence", "recoveredModelScored", "productionInterfacesAdmitted", "releaseEligible"))
            InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive(true), "summary", name))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive("captured"), "summary", "sourceTypeIdentity"))
        InferredInterfaceFixture.reject(InferredInterfaceFixture.set(base, JsonPrimitive(0), "summary", "dispositions", "not-attempted-external"))
        for (path in listOf(emptyList(), listOf("bindings"), listOf("dataOrganization"), listOf("records", 0, "details"), listOf("records", InferredInterfaceFixture.FUNCTION, "prototype"), listOf("records", InferredInterfaceFixture.FUNCTION, "parameters", 0), listOf("summary"))) {
            InferredInterfaceFixture.reject(InferredInterfaceFixture.edit(base, path) { JsonObject(it.jsonObject + ("productionVerified" to JsonPrimitive(true))) })
        }
    }

    @Test
    fun `exact byte graph and census limits accept boundary and reject one less without partial success`() {
        val bytes = InferredInterfaceFixture.bytes(InferredInterfaceFixture.fixture()); val manifest = InferredInterfaceFixture.manifest(bytes)
        val total = InferredInterfaceFixture.model.size + InferredInterfaceFixture.listingBytes.size + InferredInterfaceFixture.listingManifest().size + bytes.size + manifest.size
        val exact = NativeInferredInterfaceObservationLimitsV1(maximumCombinedBytes = total.toLong(), maximumFunctions = 2,
            maximumListingTypes = 2, maximumGraphNodes = 4, maximumGraphEdges = 2, maximumRoots = 4, maximumGraphWork = 25, maximumGraphDepth = 1)
        InferredInterfaceFixture.assess(limits = exact)
        for (limit in listOf(exact.copy(maximumCombinedBytes = total - 1L), exact.copy(maximumGraphNodes = 3), exact.copy(maximumGraphEdges = 1),
            exact.copy(maximumRoots = 3), exact.copy(maximumGraphWork = 24), exact.copy(maximumGraphDepth = 0), exact.copy(maximumGraphChildren = 0),
            exact.copy(maximumFunctions = 1), exact.copy(maximumListingTypes = 1), exact.copy(maximumModelBytes = InferredInterfaceFixture.model.size - 1),
            exact.copy(maximumStringBytes = 10), exact.copy(maximumRecordBytes = 200, maximumStringBytes = 200))) assertFails { InferredInterfaceFixture.assess(limits = limit) }
    }

    @Test
    fun `noncanonical malformed and substituted byte streams fail despite updated digest commitments`() {
        val base = InferredInterfaceFixture.bytes(InferredInterfaceFixture.fixture())
        for (bytes in listOf(base + byteArrayOf(10), (" " + base.decodeToString()).toByteArray(),
            base.decodeToString().replace("\"schemaVersion\": 1", "\"schemaVersion\": 1,\n  \"schemaVersion\": 1").toByteArray(),
            base.copyOf(base.size - 1))) assertFails { InferredInterfaceFixture.assessBytes(bytes, InferredInterfaceFixture.manifest(bytes)) }
        assertFails { InferredInterfaceFixture.assessBytes(base + byteArrayOf(10), InferredInterfaceFixture.manifest(base)) }
    }

    @Test
    fun `cancelled validation closes its stream and published nested collections resist mutation`() {
        val seen = mutableListOf<NativeInferredInterfaceRecordV1>(); val result = InferredInterfaceFixture.assess(consume = seen::add)
        val function = seen.filterIsInstance<NativeInferredInterfaceFunctionV1>().last()
        assertFails { (function.parameters as MutableList).clear() }
        assertFails { (function.parameters.single().storage.varnodes as MutableList).clear() }
        assertFails { (result.scan.dispositions as MutableMap).clear() }
        val details = seen.filterIsInstance<NativeInterfaceTypeNodeV1>().first().details
        assertFails { (details.entries.first() as MutableMap.MutableEntry<String, JsonElement>).setValue(JsonPrimitive(false)) }
        val organization = result.dataOrganization
        assertFails { (organization.entries.first() as MutableMap.MutableEntry<String, JsonElement>).setValue(JsonNull) }
        val alignment = organization.getValue("sizeAlignments").jsonArray.first().jsonObject
        assertFails { (alignment.entries.first() as MutableMap.MutableEntry<String, JsonElement>).setValue(JsonPrimitive(0)) }
        assertFails { (NativeInferredInterfaceObservationsV1.configurationJson.entries.first() as MutableMap.MutableEntry<String, JsonElement>).setValue(JsonNull) }
        val bytes = InferredInterfaceFixture.bytes(InferredInterfaceFixture.fixture())
        val stream = object : ByteArrayInputStream(bytes) { var closed = false; override fun close() { closed = true; super.close() } }
        var checkpoints = 0
        var opened = false
        assertFails {
            NativeInferredInterfaceObservationsV1.validate(InferredInterfaceFixture.manifest(bytes), InferredInterfaceFixture.bindings(), InferredInterfaceFixture.model, InferredInterfaceFixture.listingManifest(), checkpoint = {
                if (opened && ++checkpoints == 4) error("authored cancellation")
            }, openListing = { ByteArrayInputStream(InferredInterfaceFixture.listingBytes) }, openObservations = { opened = true; stream })
        }
        assertTrue(stream.closed)
    }

    @Test
    fun `closed schemas accept authored transport and reject nested authority and incomplete shapes`() {
        for ((resource, document) in listOf(
            "/project/native-inferred-interface-observations-v1.schema.json" to InferredInterfaceFixture.fixture(),
            "/project/native-inferred-interface-observation-manifest-v1.schema.json" to OracleJson.parseCanonical(InferredInterfaceFixture.manifest(InferredInterfaceFixture.bytes(InferredInterfaceFixture.fixture()))).jsonObject,
        )) {
            val schema = JsonSchema.fromDefinition(checkNotNull(javaClass.getResourceAsStream(resource)).use { it.readBytes().decodeToString() })
            assertTrue(schema.validate(document) {})
            assertFalse(schema.validate(JsonObject(document + ("productionVerified" to JsonPrimitive(true)))) {})
        }
        val schema = JsonSchema.fromDefinition(checkNotNull(javaClass.getResourceAsStream("/project/native-inferred-interface-observations-v1.schema.json")).use { it.readBytes().decodeToString() })
        assertFalse(schema.validate(InferredInterfaceFixture.set(InferredInterfaceFixture.fixture(), InferredInterfaceFixture.obj("signed" to true, "oracle" to true), "records", 0, "details")) {})
        assertFalse(schema.validate(InferredInterfaceFixture.set(InferredInterfaceFixture.fixture(), InferredInterfaceFixture.obj(), "records", 0, "details")) {})
    }
}

internal object InferredInterfaceFixture {
    const val FUNCTION = 11
    val input = "a".repeat(64)
    val model = RecoveredProgramModel(inputSha256 = input, functions = listOf(RecoveredFunction("found", "unrelated", 0x10uL, "display only"), RecoveredFunction("missing", "same", 0x30uL, "display only"))).toJson().toByteArray()
    val spaces = listOf(space(0, "EXTERNAL", 10), space(1, "ram", 1), space(2, "register", 4))
    val listingBytes: ByteArray get() = bytes(listing())
    fun bindings() = NativeInferredInterfaceBindingsV1(listingBindings(), "e".repeat(64), "6".repeat(64), "7".repeat(64), listingBytes.size.toLong(), sha(listingBytes), sha(listingManifest()), NativeInferredInterfaceObservationsV1.configurationSha256)
    fun listingBindings() = NativeInterfaceBindingsV1("b".repeat(64), "gcc", "c".repeat(64), NativeInterfaceAddressV1(1, "0000000000000000"), input, "x86:LE:64:default", model.size.toLong(), "d".repeat(64), sha(model))
    fun fixture(): JsonObject = obj("addressSpaces" to spaces, "bindings" to bindingJson(), "configuration" to NativeInferredInterfaceObservationsV1.configurationJson,
        "dataOrganization" to organization(), "policy" to "ghidra-native-inferred-interface-observations-v1", "schemaVersion" to 1,
        "records" to listOf(
            node("listing", 1, 0, "integer", 0, obj("signed" to true)), root("listing", 1, "return-formal", -1, 0, 0), root("listing", 1, "return-effective", -1, 1, 0),
            function(0, external = true),
            node("inferred", 1, 0, "integer", 0, obj("signed" to true)), root("inferred", 1, "inferred-return", -1, null, 0),
            node("inferred", 1, 1, "pointer", 1, obj("pointerSize" to 8), length = 8),
            edge("inferred", 1, 1, 0, "pointer-target", 2, "new-node"),
            node("inferred", 1, 2, "structure", 1, compositeDetails(1), length = 8),
            edge("inferred", 1, 2, 0, "component", 1, "backedge", component = true),
            root("inferred", 1, "inferred-parameter", 0, null, 1),
            function(1),
        ), "summary" to summary())
    // Index of the successful function is last; keep one named constant for mutation controls.
    fun function(index: Int, external: Boolean = false) = obj("recordKind" to "function", "functionOrdinal" to index,
        "entry" to if (external) addr(0, 0x80) else addr(1, 0x10), "isExternal" to external, "isThunk" to false,
        "disposition" to if (external) "not-attempted-external" else "high-function-observed", "attempt" to if (external) 0 else 1,
        "result" to if (external) null else result(), "prototype" to if (external) null else prototype(),
        "parameters" to if (external) emptyList<Any>() else listOf(parameter()))
    fun result(state: String = "high-function-observed") = obj("completed" to (state in setOf("high-function-observed", "completed-without-high-function", "unsupported-high-representation")), "valid" to true,
        "timedOut" to (state == "decompile-timeout"), "cancelled" to (state == "decompile-cancelled"), "failedToStart" to (state == "decompiler-start-failed"), "diagnostic" to "")
    fun prototype() = obj("parameterCount" to 1, "localSymbolParameterCount" to 1, "parameterCountsMatch" to true, "backedByLocalSymbols" to true,
        "modelName" to "__cdecl", "varArgs" to false, "extraPop" to 0, "hasThis" to false, "noReturn" to false, "inline" to false,
        "constructor" to false, "destructor" to false, "returnType" to 0, "returnStorage" to storage(4),
        "formalEffectiveRelation" to "unavailable-native-api", "allMappings" to "first-mapping-only", "privateFlags" to "unavailable-native-api")
    fun parameter() = obj("index" to 0, "categoryIndex" to 0, "highParamSlot" to 0, "highVariableState" to "parameter", "nativeIdBits" to "0000000000000001",
        "name" to null, "type" to 1, "typeLocked" to false, "nameLocked" to false, "isThisPointer" to false, "isHiddenReturn" to false,
        "storage" to storage(8), "firstUse" to addr(1, 0x10), "formalEffectiveRelation" to "unavailable-native-api",
        "forcedIndirectMeaning" to "unavailable-for-plain-decoded-storage", "allMappings" to "first-mapping-only")
    fun storage(size: Int) = obj("state" to "assigned", "size" to size, "autoStorage" to false, "autoParameterType" to null,
        "forcedIndirect" to false, "varnodes" to listOf(obj("address" to addr(2, 0), "size" to size)))
    fun node(channel: String, function: Int, id: Int, kind: String, children: Int, details: JsonObject, length: Int = 4,
        expansion: String = when (kind) { "pointer", "array", "structure", "union", "bitfield" -> "expanded"; "typedef", "function-definition" -> "partial"; "unsupported" -> "unsupported"; else -> "terminal" }) =
        obj("recordKind" to "type-node", "channel" to channel, "functionOrdinal" to function, "id" to id, "nativeClass" to "authored.$kind",
            "kind" to kind, "length" to length, "alignedLength" to length, "alignment" to 4, "zeroLength" to (length == 0), "notYetDefined" to false,
            "undefined" to (kind == "undefined"), "expansion" to expansion, "childCount" to children, "details" to details)
    fun root(channel: String, function: Int, role: String, slot: Int, occurrence: Int?, node: Int?) = obj("recordKind" to "type-root", "channel" to channel, "functionOrdinal" to function,
        "role" to role, "slot" to slot, "listingTypeOrdinal" to occurrence, "node" to node)
    fun edge(channel: String, function: Int, source: Int, ordinal: Int, relation: String, target: Int?, state: String, component: Boolean = false) = obj(
        "recordKind" to "type-edge", "channel" to channel, "functionOrdinal" to function, "source" to source, "ordinal" to ordinal, "relation" to relation, "target" to target,
        "referenceState" to state, "offset" to if (component) 0 else null, "length" to if (component) 8 else null, "fieldName" to null,
        "undefined" to if (component) false else null, "bitField" to if (component) false else null, "zeroBitField" to if (component) false else null)
    fun compositeDetails(count: Int) = obj("componentCount" to count, "definedComponentCount" to count, "packingType" to "DEFAULT", "explicitPackingValue" to -1,
        "alignmentType" to "DEFAULT", "explicitMinimumAlignment" to -1)
    fun summary() = obj("functions" to 2, "internalFunctions" to 1, "externalFunctions" to 1, "thunks" to 0, "attempted" to 1, "observed" to 1,
        "parameters" to 1, "storageVarnodes" to 2, "roots" to 4, "graphNodes" to 4, "graphEdges" to 2, "graphWork" to 25,
        "dispositions" to JsonObject(NativeInferredInterfaceObservationsV1.dispositions.associateWith { JsonPrimitive(if (it in setOf("high-function-observed", "not-attempted-external")) 1 else 0) }),
        "coverage" to "all-currently-listed-internal-and-external-functions", "authoritativeOracleEvidence" to false, "recoveredModelScored" to false,
        "productionInterfacesAdmitted" to false, "releaseEligible" to false, "abiClassification" to "not-captured", "sourceTypeIdentity" to "not-captured")
    fun organization(): JsonObject {
        val scalars = listOf("pointerSize", "pointerShift", "charSize", "wideCharSize", "shortSize", "integerSize", "longSize", "longLongSize", "floatSize", "doubleSize", "longDoubleSize", "absoluteMaxAlignment", "machineAlignment", "defaultAlignment", "defaultPointerAlignment")
        return JsonObject(scalars.associateWith { JsonPrimitive(8) } + mapOf("bigEndian" to JsonPrimitive(false), "signedChar" to JsonPrimitive(true),
            "sizeAlignments" to JsonArray(listOf(obj("size" to 1, "alignment" to 1), obj("size" to 4, "alignment" to 4))),
            "bitFieldPacking" to obj("msConvention" to false, "typeAlignmentEnabled" to true, "zeroLengthBoundary" to 0)))
    }
    fun withOutcome(state: String): JsonObject {
        var fn = function(1)
        fn = set(fn, JsonPrimitive(state), "disposition"); fn = set(fn, JsonNull, "prototype"); fn = set(fn, JsonArray(emptyList()), "parameters")
        fn = set(fn, if (state.startsWith("not-attempted")) JsonNull else result(state), "result")
        fn = set(fn, JsonPrimitive(if (state.startsWith("not-attempted")) 0 else 1), "attempt")
        var doc = set(fixture(), JsonArray(fixture().getValue("records").jsonArray.take(4) + fn), "records")
        for ((key,value) in mapOf("attempted" to if (state.startsWith("not-attempted")) 0 else 1, "observed" to 0, "parameters" to 0, "storageVarnodes" to 0, "roots" to 2, "graphNodes" to 1, "graphEdges" to 0, "graphWork" to 8)) doc = set(doc, JsonPrimitive(value), "summary", key)
        doc = set(doc, JsonPrimitive(0), "summary", "dispositions", "high-function-observed")
        return set(doc, JsonPrimitive(1), "summary", "dispositions", state)
    }
    fun listing() = obj("addressSpaces" to spaces, "bindings" to listingBindingJson(), "policy" to "ghidra-native-interface-observations-v1", "schemaVersion" to 1,
        "records" to listOf(listedFunction(true), listedFunction(false), listedType(0), listedType(1)),
        "summary" to obj("coverage" to "all-currently-listed-internal-and-external-functions", "functions" to 2, "internalFunctions" to 1, "externalFunctions" to 1, "thunks" to 0,
            "parameters" to 0, "autoParameters" to 0, "types" to 2, "storageVarnodes" to 1, "highFunction" to "not-captured", "typeClosure" to "not-captured", "abiClassification" to "not-captured"))
    private fun listedFunction(external: Boolean) = obj("recordKind" to "function", "entry" to if (external) addr(0, 0x80) else addr(1, 0x10), "name" to "unrelated", "isExternal" to external, "isThunk" to false, "immediateThunkTarget" to null,
        "signatureSource" to "DEFAULT", "convention" to obj("name" to "default", "resolvedModel" to "__cdecl", "state" to "default"), "varArgs" to false, "customStorage" to false,
        "parameterCount" to 0, "autoParameterCount" to 0, "return" to if (external) null else obj("ordinal" to -1, "name" to null, "source" to "DEFAULT", "autoParameter" to false, "autoParameterType" to null,
            "forcedIndirect" to false, "formalType" to 0, "effectiveType" to 1, "storage" to storage(4)), "parameters" to emptyList<Any>(), "highFunction" to "not-captured")
    private fun listedType(id: Int) = obj("recordKind" to "type", "ordinal" to id, "kind" to "integer", "nativeClass" to "authored.integer", "name" to "same", "path" to "/same", "length" to 4,
        "alignedLength" to 4, "alignment" to 4, "undefined" to false, "notYetDefined" to false, "signedness" to "signed", "layout" to "not-captured", "typeClosure" to "not-captured")
    private fun listingBindingJson() = obj("collectorSha256" to "b".repeat(64), "compilerSpecId" to "gcc", "ghidraArchiveSha256" to "c".repeat(64), "imageBase" to addr(1,0), "inputSha256" to input, "languageId" to "x86:LE:64:default", "programModelBytes" to model.size, "programModelExporterSha256" to "d".repeat(64), "programModelSha256" to sha(model))
    private fun bindingJson() = obj("listingBindings" to listingBindingJson(), "collectorSha256" to "e".repeat(64), "wrapperSha256" to "6".repeat(64), "nativeDecompilerSha256" to "7".repeat(64), "listingBytes" to listingBytes.size, "listingSha256" to sha(listingBytes), "listingManifestSha256" to sha(listingManifest()), "configurationSha256" to NativeInferredInterfaceObservationsV1.configurationSha256)
    fun listingManifest() = bytes(obj("bytes" to listingBytes.size, "collectorSha256" to "b".repeat(64), "file" to "native-interfaces.json", "inputSha256" to input, "kind" to "ghidra-native-interface-observation-manifest-v1", "programModelSha256" to sha(model), "schemaVersion" to 1, "sha256" to sha(listingBytes)))
    fun manifest(content: ByteArray) = bytes(obj("bytes" to content.size, "collectorSha256" to "e".repeat(64), "configurationSha256" to NativeInferredInterfaceObservationsV1.configurationSha256, "file" to "native-inferred-interfaces.json", "inputSha256" to input, "kind" to "ghidra-native-inferred-interface-observation-manifest-v1", "listingSha256" to sha(listingBytes), "programModelSha256" to sha(model), "schemaVersion" to 1, "sha256" to sha(content)))
    fun assess(doc: JsonObject = fixture(), limits: NativeInferredInterfaceObservationLimitsV1 = NativeInferredInterfaceObservationLimitsV1(), expected: NativeInferredInterfaceBindingsV1 = bindings(), model: ByteArray = this.model, listingManifest: ByteArray = listingManifest(), consume: (NativeInferredInterfaceRecordV1) -> Unit = {}): NativeInferredInterfaceSummaryV1 {
        val content = bytes(doc)
        return NativeInferredInterfaceObservationsV1.validate(manifest(content), expected, model, listingManifest, limits, {}, { ByteArrayInputStream(listingBytes) }, { ByteArrayInputStream(content) }, consume)
    }
    fun assessBytes(content: ByteArray, manifest: ByteArray) = NativeInferredInterfaceObservationsV1.validate(manifest, bindings(), model, listingManifest(), checkpoint = {}, openListing = { ByteArrayInputStream(listingBytes) }, openObservations = { ByteArrayInputStream(content) })
    fun reject(doc: JsonObject) { assertFails { assess(doc) } }
    fun space(index: Int, name: String, type: Int) = obj("index" to index, "name" to name, "type" to type, "sizeBits" to 64, "addressableUnitSize" to 1, "overlay" to false, "signedOffsets" to false)
    fun addr(space: Int, offset: Long) = obj("kind" to "address", "spaceIndex" to space, "offsetBits" to offset.toULong().toString(16).padStart(16,'0'))
    fun bytes(value: JsonElement) = OracleJson.canonicalBytes(value)
    fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    fun obj(vararg pairs: Pair<String, Any?>) = JsonObject(pairs.associate { it.first to json(it.second) })
    fun json(value: Any?): JsonElement = when (value) { null -> JsonNull; is JsonElement -> value; is String -> JsonPrimitive(value); is Boolean -> JsonPrimitive(value); is Number -> JsonPrimitive(value); is List<*> -> JsonArray(value.map(::json)); else -> error("unsupported authored value") }
    fun set(root: JsonObject, value: JsonElement, vararg path: Any) = edit(root, path.toList()) { value }
    fun edit(root: JsonObject, path: List<Any>, change: (JsonElement) -> JsonElement): JsonObject {
        fun walk(value: JsonElement, at: Int): JsonElement = if (at == path.size) change(value) else when (val key=path[at]) {
            is String -> JsonObject(value.jsonObject.toMutableMap().apply { this[key] = walk(getValue(key), at+1) })
            is Int -> JsonArray(value.jsonArray.toMutableList().apply { this[key] = walk(this[key], at+1) })
            else -> error("invalid authored path")
        }
        return walk(root,0).jsonObject
    }
}
