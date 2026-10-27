package decompengine.oracle.structural

import decompengine.project.*
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonNull

class RecoveredAbiInterfaceCandidateProjectionV1Test {
    @Test
    fun `complete listing formal graph root yields a capture local ABI candidate without HighFunction slot joins`() {
        val base = fixture()
        val parameter = NativeInterfaceParameterV1(0, "x", "USER_DEFINED", false, null, false, 0, 0,
            NativeInterfaceStorageV1("none", null, null, null, null, emptyList()))
        val function = base.listingFunction.copy(parameterCount = 1, parameters = listOf(parameter))
        val listing = base.listing.copy(scan = base.listing.scan.copy(parameters = 1, types = 1))
        val inferred = base.inferred.copy(
            listing = listing,
            dataOrganization = JsonObject(mapOf(
                "bigEndian" to JsonPrimitive(false), "pointerSize" to JsonPrimitive(8), "pointerShift" to JsonPrimitive(0),
                "charSize" to JsonPrimitive(1), "shortSize" to JsonPrimitive(2), "integerSize" to JsonPrimitive(4),
                "longSize" to JsonPrimitive(8), "longLongSize" to JsonPrimitive(8), "floatSize" to JsonPrimitive(4),
                "doubleSize" to JsonPrimitive(8), "sizeAlignments" to JsonArray(emptyList()),
            )),
            scan = base.inferred.scan.copy(roots = 1, graphNodes = 1, graphEdges = 0, graphWork = 5),
        )
        val type = NativeInterfaceTypeV1(0, "integer", "ghidra.program.model.data.IntegerDataType", "int", "/int",
            4, 4, 4, false, false, "signed")
        val node = NativeInterfaceTypeNodeV1(NativeInterfaceGraphScopeV1("listing", 0), 0,
            type.nativeClass, "integer", 4, 4, 4, false, false, false, "terminal", 0,
            JsonObject(mapOf("signed" to JsonPrimitive(true))))
        val root = NativeInterfaceTypeRootV1(node.scope, "parameter-formal", 0, 0, 0)
        val document = RecoveredAbiInterfaceCandidateProjectionV1.project(
            listing, listOf(function, type), inferred, listOf(base.inferredFunction, node, root), base.target,
        ).document
        val entity = document.getValue("candidateEntities").jsonArray.single().jsonObject
        val fact = entity.getValue("facts").jsonArray.map { it.jsonObject }
            .single { it.getValue("dimension").jsonPrimitive.content == "function.parameter-abi-class" }
        assertEquals("recovered", fact.getValue("state").jsonPrimitive.content)
        val value = fact.getValue("value").jsonObject
        assertTrue(value.getValue("source").jsonPrimitive.content.startsWith("type-token:"))
        assertEquals(listOf("INTEGER"), value.getValue("abi").jsonObject.getValue("classes").jsonArray.map { it.jsonPrimitive.content })
        assertEquals("32", value.getValue("abi").jsonObject.getValue("sizeBits").jsonPrimitive.content)
        assertEquals("untrusted-component-candidate", document.getValue("scope").jsonPrimitive.content)
    }

    @Test
    fun `automatic or unsupported formal roots remain explicit unknown candidates`() {
        val base = fixture()
        val parameter = NativeInterfaceParameterV1(0, "this", "USER_DEFINED", true, "THIS", false, 0, 0,
            NativeInterfaceStorageV1("none", null, null, "THIS", null, emptyList()))
        val function = base.listingFunction.copy(parameterCount = 1, autoParameterCount = 1, parameters = listOf(parameter))
        val listing = base.listing.copy(scan = base.listing.scan.copy(parameters = 1, autoParameters = 1, types = 1))
        val inferred = base.inferred.copy(listing = listing,
            dataOrganization = JsonObject(mapOf(
                "bigEndian" to JsonPrimitive(false), "pointerSize" to JsonPrimitive(8), "pointerShift" to JsonPrimitive(0),
                "charSize" to JsonPrimitive(1), "shortSize" to JsonPrimitive(2), "integerSize" to JsonPrimitive(4),
                "longSize" to JsonPrimitive(8), "longLongSize" to JsonPrimitive(8), "floatSize" to JsonPrimitive(4),
                "doubleSize" to JsonPrimitive(8), "sizeAlignments" to JsonArray(emptyList()),
            )),
            scan = base.inferred.scan.copy(roots = 1, graphNodes = 1, graphWork = 5))
        val type = NativeInterfaceTypeV1(0, "unsupported", "unsupported", "unknown", "/unknown", 4, 4, 4, false, false, null)
        val node = NativeInterfaceTypeNodeV1(NativeInterfaceGraphScopeV1("listing", 0), 0,
            "unsupported", "unsupported", 4, 4, 4, false, false, false, "terminal", 0, JsonObject(emptyMap()))
        val root = NativeInterfaceTypeRootV1(node.scope, "parameter-formal", 0, 0, 0)
        val document = RecoveredAbiInterfaceCandidateProjectionV1.project(
            listing, listOf(function, type), inferred, listOf(base.inferredFunction, node, root), base.target,
        ).document
        val fact = document.getValue("candidateEntities").jsonArray.single().jsonObject.getValue("facts").jsonArray
            .map { it.jsonObject }.single { it.getValue("dimension").jsonPrimitive.content == "function.parameter-abi-class" }
        assertEquals("recovered-unknown", fact.getValue("state").jsonPrimitive.content)
        assertEquals(JsonNull, fact.getValue("value"))
    }

    @Test
    fun `projection preserves matched census and only emits exact convention and paired varargs candidates`() {
        val fixture = fixture()
        val projection = project(fixture)
        val document = projection.document
        assertEquals("untrusted-component-candidate", document.getValue("scope").jsonPrimitive.content)
        assertEquals("not-scored", document.getValue("scoreStatus").jsonPrimitive.content)
        assertEquals(1, document.getValue("candidateEntities").jsonArray.size)
        val entity = document.getValue("candidateEntities").jsonArray.single().jsonObject
        val facts = entity.getValue("facts").jsonArray.map { it.jsonObject }
        val convention = facts.single { it.getValue("dimension").jsonPrimitive.content == "function.calling-convention" }
        assertEquals("recovered", convention.getValue("state").jsonPrimitive.content)
        assertEquals("sysv-amd64", convention.getValue("value").jsonObject.getValue("abi").jsonObject
            .getValue("callingConvention").jsonPrimitive.content)
        val variadic = facts.single { it.getValue("dimension").jsonPrimitive.content == "function.variadic" }
        assertEquals("recovered", variadic.getValue("state").jsonPrimitive.content)
        assertTrue(entity.getValue("inferredObservation").jsonObject.getValue("prototype").jsonObject.containsKey("returnTypeOrdinal"))
        assertFalse(entity.getValue("inferredObservation").jsonObject.getValue("prototype").jsonObject.containsKey("hiddenReturn"))
        assertEquals(0, document.getValue("nativeOnlyFunctions").jsonArray.size)
    }

    @Test
    fun `varargs disagreement and unresolved convention remain unknown while raw channels remain distinct`() {
        val fixture = fixture(inferredVarArgs = false, conventionState = "named-unresolved")
        val document = project(fixture).document
        val entity = document.getValue("candidateEntities").jsonArray.single().jsonObject
        val facts = entity.getValue("facts").jsonArray.map { it.jsonObject }
        assertTrue(facts.filter { it.getValue("dimension").jsonPrimitive.content in setOf("function.calling-convention", "function.variadic") }
            .all { it.getValue("state").jsonPrimitive.content == "recovered-unknown" })
        assertNotEquals(entity.getValue("listingObservation"), entity.getValue("inferredObservation"))
    }

    @Test
    fun `mapped thunk varargs remain unknown despite completed agreeing observations`() {
        val original = fixture()
        val function = original.listingFunction.copy(isThunk = true, immediateThunkTarget = original.listingFunction.entry)
        val listing = original.listing.copy(scan = original.listing.scan.copy(thunks = 1))
        val input = original.withListing(listing).withListingFunction(function)
            .withInferenceFunction(original.inferredFunction.copy(isThunk = true))
        val document = project(input).document
        val entity = document.getValue("candidateEntities").jsonArray.single().jsonObject
        val variadic = entity.getValue("facts").jsonArray.map { it.jsonObject }
            .single { it.getValue("dimension").jsonPrimitive.content == "function.variadic" }
        assertEquals("recovered-unknown", variadic.getValue("state").jsonPrimitive.content)
    }

    @Test
    fun `listing report and listing manifest commitments remain distinct`() {
        val fixture = fixture()
        val bindings = project(fixture).document.getValue("bindings").jsonObject
        val reportDigest = bindings.getValue("claimedListingObservationsSha256").jsonPrimitive.content
        val manifestDigest = bindings.getValue("claimedListingManifestSha256").jsonPrimitive.content
        assertNotEquals(reportDigest, manifestDigest)
        assertEquals("b".repeat(64), reportDigest)
        assertEquals("c".repeat(64), manifestDigest)
    }

    @Test
    fun `same count caller-constructed record mutation changes candidate without changing claimed stream digest`() {
        val original = fixture()
        val changedFunction = original.listingFunction.copy(varArgs = false)
        val changed = original.withListingFunction(changedFunction)
        val before = project(original).document
        val after = project(changed).document
        assertEquals(before.getValue("bindings").jsonObject.getValue("claimedListingObservationsSha256"),
            after.getValue("bindings").jsonObject.getValue("claimedListingObservationsSha256"))
        assertNotEquals(before.getValue("candidateEntities"), after.getValue("candidateEntities"))
        assertEquals("untrusted-component-candidate", after.getValue("scope").jsonPrimitive.content)
    }

    @Test
    fun `candidate state and reference sets must agree with the recomputed census`() {
        val original = fixture()
        val model = original.listing.modelFunctions.single()
        val falseMissing = original.listing.copy(modelFunctions = listOf(model.copy(state = "missing-listing-function")))
        kotlin.test.assertFailsWith<IllegalArgumentException> { project(original.withListing(falseMissing)) }

        val observed = original.listing.observedFunctions.single()
        val falseUnmatched = original.listing.copy(observedFunctions = listOf(observed.copy(state = "unmatched-observed-function", modelIds = emptyList())))
        kotlin.test.assertFailsWith<IllegalArgumentException> { project(original.withListing(falseUnmatched)) }
    }

    @Test
    fun `paired listing inference metadata and scan totals must conserve`() {
        val original = fixture()
        kotlin.test.assertFailsWith<IllegalArgumentException> {
            project(original.withInferenceFunction(original.inferredFunction.copy(isThunk = true)))
        }
        kotlin.test.assertFailsWith<IllegalArgumentException> {
            project(original.withListing(original.listing.copy(scan = original.listing.scan.copy(autoParameters = 1))))
        }
    }

    @Test
    fun `cumulative text and output bounds reject before returning a partial candidate`() {
        val fixture = fixture()
        kotlin.test.assertFailsWith<IllegalArgumentException> {
            project(fixture, RecoveredAbiInterfaceCandidateProjectionLimitsV1(maximumInputTextBytes = 1))
        }
        kotlin.test.assertFailsWith<IllegalArgumentException> {
            project(fixture, RecoveredAbiInterfaceCandidateProjectionLimitsV1(maximumOutputBytes = 1))
        }
    }

    @Test
    fun `mapped thunk with complete formal return and parameter graphs never promotes ABI classes`() {
        val ordinary = projectFormalGraph().getValue("candidateEntities").jsonArray.single().jsonObject
        val thunk = projectFormalGraph(thunk = true).getValue("candidateEntities").jsonArray.single().jsonObject
        val dimensions = setOf("function.return-abi-class", "function.parameter-abi-class")
        for (entity in listOf(ordinary, thunk)) {
            val facts = entity.getValue("facts").jsonArray.map { it.jsonObject }
                .filter { it.getValue("dimension").jsonPrimitive.content in dimensions }
            assertEquals(2, facts.size)
            facts.forEach {
                assertEquals(if (entity == thunk) "recovered-unknown" else "recovered", it.getValue("state").jsonPrimitive.content)
                if (entity == thunk) assertEquals(JsonNull, it.getValue("value"))
            }
        }
        assertEquals(2, thunk.getValue("decisions").jsonArray.map { it.jsonObject }.count {
            it.getValue("reason").jsonPrimitive.content == "thunk-signature-is-not-an-independent-interface" &&
                it.getValue("channel").jsonPrimitive.content == "listing-formal-type-graph"
        })
    }

    @Test
    fun `one zero parameter function admits both listing return roots and inferred return root at exact limits`() {
        val document = projectFormalGraph(parameter = false, limits = RecoveredAbiInterfaceCandidateProjectionLimitsV1(
            maximumNativeFunctions = 1, maximumParameters = 0,
        ))
        val returned = document.getValue("candidateEntities").jsonArray.single().jsonObject
            .getValue("facts").jsonArray.map { it.jsonObject }
            .single { it.getValue("dimension").jsonPrimitive.content == "function.return-abi-class" }
        assertEquals("recovered", returned.getValue("state").jsonPrimitive.content)
    }

    @Test
    fun `LP64 observations from incompatible captured languages or compilers remain unknown`() {
        for ((language, compiler) in listOf("AARCH64:LE:64:v8A" to "gcc", "x86:LE:64:default" to "windows")) {
            val document = projectFormalGraph(language = language, compiler = compiler)
            val entity = document.getValue("candidateEntities").jsonArray.single().jsonObject
            val facts = entity.getValue("facts").jsonArray.map { it.jsonObject }.filter {
                it.getValue("dimension").jsonPrimitive.content in setOf("function.return-abi-class", "function.parameter-abi-class")
            }
            assertEquals(2, facts.size)
            assertTrue(facts.all { it.getValue("state").jsonPrimitive.content == "recovered-unknown" && it.getValue("value") == JsonNull })
            assertEquals(2, entity.getValue("decisions").jsonArray.map { it.jsonObject }.count {
                it.getValue("reason").jsonPrimitive.content == "captured-language-or-compiler-is-not-the-supported-sysv-amd64-profile"
            })
        }
    }

    private fun projectFormalGraph(
        thunk: Boolean = false,
        parameter: Boolean = true,
        language: String = "x86:LE:64:default",
        compiler: String = "gcc",
        limits: RecoveredAbiInterfaceCandidateProjectionLimitsV1 = RecoveredAbiInterfaceCandidateProjectionLimitsV1(),
    ): JsonObject {
        val base = fixture()
        val formal = NativeInterfaceParameterV1(0, "x", "USER_DEFINED", false, null, false, 0, 0,
            NativeInterfaceStorageV1("none", null, null, null, null, emptyList()))
        val function = base.listingFunction.copy(isThunk = thunk,
            immediateThunkTarget = if (thunk) base.listingFunction.entry else null,
            returned = formal.copy(ordinal = -1), parameterCount = if (parameter) 1 else 0,
            parameters = if (parameter) listOf(formal) else emptyList())
        val listing = base.listing.copy(bindings = base.listing.bindings.copy(languageId = language, compilerSpecId = compiler),
            scan = base.listing.scan.copy(thunks = if (thunk) 1 else 0, parameters = if (parameter) 1 else 0, types = 1))
        val type = NativeInterfaceTypeV1(0, "integer", "ghidra.program.model.data.IntegerDataType", "int", "/int",
            4, 4, 4, false, false, "signed")
        val node = NativeInterfaceTypeNodeV1(NativeInterfaceGraphScopeV1("listing", 0), 0,
            type.nativeClass, "integer", 4, 4, 4, false, false, false, "terminal", 0,
            JsonObject(mapOf("signed" to JsonPrimitive(true))))
        val inferredNode = node.copy(scope = NativeInterfaceGraphScopeV1("inferred", 0))
        val roots = listOf(
            NativeInterfaceTypeRootV1(node.scope, "return-formal", -1, 0, 0),
            NativeInterfaceTypeRootV1(node.scope, "return-effective", -1, 0, 0),
            NativeInterfaceTypeRootV1(inferredNode.scope, "inferred-return", -1, null, 0),
        ) + if (parameter) listOf(
            NativeInterfaceTypeRootV1(node.scope, "parameter-formal", 0, 0, 0),
            NativeInterfaceTypeRootV1(node.scope, "parameter-effective", 0, 0, 0),
        ) else emptyList()
        val inferred = base.inferred.copy(listing = listing,
            bindings = base.inferred.bindings.copy(listingBindings = listing.bindings),
            dataOrganization = JsonObject(mapOf(
                "bigEndian" to JsonPrimitive(false), "pointerSize" to JsonPrimitive(8), "pointerShift" to JsonPrimitive(0),
                "charSize" to JsonPrimitive(1), "shortSize" to JsonPrimitive(2), "integerSize" to JsonPrimitive(4),
                "longSize" to JsonPrimitive(8), "longLongSize" to JsonPrimitive(8), "floatSize" to JsonPrimitive(4),
                "doubleSize" to JsonPrimitive(8), "sizeAlignments" to JsonArray(emptyList()),
            )), scan = base.inferred.scan.copy(thunks = if (thunk) 1 else 0, roots = roots.size.toLong(), graphNodes = 2, graphWork = roots.size.toLong() + 7))
        val inferredFunction = base.inferredFunction.copy(isThunk = thunk,
            prototype = base.inferredFunction.prototype!!.copy(returnType = 0))
        return RecoveredAbiInterfaceCandidateProjectionV1.project(listing, listOf(function, type), inferred,
            listOf(inferredFunction, node, inferredNode) + roots, base.target, limits).document
    }

    private fun project(
        fixture: Fixture,
        limits: RecoveredAbiInterfaceCandidateProjectionLimitsV1 = RecoveredAbiInterfaceCandidateProjectionLimitsV1(),
    ) = RecoveredAbiInterfaceCandidateProjectionV1.project(
        fixture.listing, listOf(fixture.listingFunction), fixture.inferred, listOf(fixture.inferredFunction), fixture.target, limits,
    )

    private data class Fixture(
        val listing: NativeInterfaceObservationSummaryV1,
        val listingFunction: NativeInterfaceFunctionV1,
        val inferred: NativeInferredInterfaceSummaryV1,
        val inferredFunction: NativeInferredInterfaceFunctionV1,
        val target: StructuralTargetAbiV1,
    ) {
        fun withListingFunction(value: NativeInterfaceFunctionV1) = Fixture(listing, value, inferred, inferredFunction, target)
        fun withListing(value: NativeInterfaceObservationSummaryV1) = Fixture(value, listingFunction,
            inferred.copy(listing = value, scan = inferred.scan.copy(
                internalFunctions = value.scan.internalFunctions, externalFunctions = value.scan.externalFunctions, thunks = value.scan.thunks,
            )), inferredFunction, target)
        fun withInferenceFunction(value: NativeInferredInterfaceFunctionV1) = Fixture(listing, listingFunction, inferred, value, target)
    }

    private fun fixture(inferredVarArgs: Boolean = true, conventionState: String = "named-resolved"): Fixture {
        val digest = "a".repeat(64)
        val address = NativeCallAddressV1(0, "0000000000000001")
        val binding = NativeCallBindingsV1(digest, "gcc", digest, NativeCallAddressV1(0, "0000000000000000"),
            digest, "x86:LE:64:default", 1, digest, digest)
        val listingReportDigest = "b".repeat(64)
        val listingManifestDigest = "c".repeat(64)
        val listingManifest = NativeInterfaceManifestV1(1, digest, digest, digest, listingReportDigest)
        val listingFunction = NativeInterfaceFunctionV1(address, "candidate", false, false, null, "DEFAULT",
            NativeInterfaceConventionV1("sysv", if (conventionState == "named-resolved") "__cdecl" else null, conventionState),
            true, false, 0, 0, null, emptyList())
        val listing = NativeInterfaceObservationSummaryV1(listingManifest, binding, emptyList(),
            NativeInterfaceScanV1(1, 1, 0, 0, 0, 0, 0, 0),
            listOf(NativeInterfaceModelFunctionV1("model-1", "0000000000000001", listOf(address), "matched")),
            listOf(NativeInterfaceObservedFunctionV1(address, "matched", listOf("model-1"))))
        val storage = NativeInterfaceStorageV1("none", null, null, null, null, emptyList())
        val result = NativeInferredInterfaceResultV1(true, true, false, false, false, "")
        val prototype = NativeInferredInterfacePrototypeV1(0, 0, true, true, "model", inferredVarArgs, 0,
            false, false, false, false, false, null, storage)
        val inferredFunction = NativeInferredInterfaceFunctionV1(0, address, false, false,
            "high-function-observed", 1, result, prototype, emptyList())
        val inferredBindings = NativeInferredInterfaceBindingsV1(binding, digest, digest, digest, 1,
            listingReportDigest, listingManifestDigest, digest, digest)
        val inferredManifest = NativeInferredInterfaceManifestV1(1, digest, digest, digest, listingReportDigest, digest, digest, digest)
        val inferred = NativeInferredInterfaceSummaryV1(inferredManifest, inferredBindings, listing,
            JsonObject(mapOf("sizeAlignments" to JsonArray(emptyList()))),
            NativeInferredInterfaceScanV1(1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, mapOf("high-function-observed" to 1)))
        val target = StructuralRecoveryV1Inputs.loadTargetAbi(Path.of("src/test/resources/oracle/structural-v1/target-abi.json"))
        return Fixture(listing, listingFunction, inferred, inferredFunction, target)
    }
}
