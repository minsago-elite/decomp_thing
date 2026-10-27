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

class RecoveredAbiInterfaceCandidateProjectionV1Test {
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
    fun `contradictory formal local and observed parameter counts keep varargs unknown`() {
        for (parameterCount in listOf(0, 1)) {
            val original = fixture(parameterCount = parameterCount)
            val prototype = checkNotNull(original.inferredFunction.prototype)
            val differentCount = parameterCount + 1
            val mutations = listOf(
                prototype.copy(localSymbolParameterCount = differentCount),
                prototype.copy(parameterCount = differentCount),
                prototype.copy(parameterCount = differentCount, localSymbolParameterCount = differentCount),
                prototype.copy(parameterCountsMatch = false),
            )
            for (mutation in mutations) {
                val changed = original.withInferenceFunction(original.inferredFunction.copy(prototype = mutation))
                val entity = project(changed).document.getValue("candidateEntities").jsonArray.single().jsonObject
                val variadic = entity.getValue("facts").jsonArray.map { it.jsonObject }
                    .single { it.getValue("dimension").jsonPrimitive.content == "function.variadic" }
                assertEquals("recovered-unknown", variadic.getValue("state").jsonPrimitive.content,
                    "observed=$parameterCount, prototype=$mutation")
                assertEquals(kotlinx.serialization.json.JsonNull, variadic.getValue("value"))
                val decision = entity.getValue("decisions").jsonArray.map { it.jsonObject }
                    .single { it.getValue("factId") == variadic.getValue("id") }
                assertEquals("highfunction-parameter-counts-do-not-match", decision.getValue("reason").jsonPrimitive.content)
            }
        }
    }

    @Test
    fun `consistent nonzero formal local and observed parameter counts permit paired varargs`() {
        val entity = project(fixture(parameterCount = 1)).document.getValue("candidateEntities").jsonArray.single().jsonObject
        val prototype = entity.getValue("inferredObservation").jsonObject.getValue("prototype").jsonObject
        assertEquals("1", prototype.getValue("parameterCount").jsonPrimitive.content)
        assertEquals("1", prototype.getValue("localSymbolParameterCount").jsonPrimitive.content)
        assertEquals(1, entity.getValue("inferredObservation").jsonObject.getValue("parameters").jsonArray.size)
        val variadic = entity.getValue("facts").jsonArray.map { it.jsonObject }
            .single { it.getValue("dimension").jsonPrimitive.content == "function.variadic" }
        assertEquals("recovered", variadic.getValue("state").jsonPrimitive.content)
        assertEquals("true", variadic.getValue("value").jsonObject.getValue("abi").jsonObject.getValue("variadic").jsonPrimitive.content)
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

    private fun fixture(inferredVarArgs: Boolean = true, conventionState: String = "named-resolved", parameterCount: Int = 0): Fixture {
        val digest = "a".repeat(64)
        val address = NativeCallAddressV1(0, "0000000000000001")
        val binding = NativeCallBindingsV1(digest, "compiler", digest, NativeCallAddressV1(0, "0000000000000000"),
            digest, "language", 1, digest, digest)
        val listingReportDigest = "b".repeat(64)
        val listingManifestDigest = "c".repeat(64)
        val listingManifest = NativeInterfaceManifestV1(1, digest, digest, digest, listingReportDigest)
        val storage = NativeInterfaceStorageV1("none", null, null, null, null, emptyList())
        val listingParameters = List(parameterCount) { index ->
            NativeInterfaceParameterV1(index, null, "DEFAULT", false, null, false, null, null, storage)
        }
        val inferredParameters = List(parameterCount) { index ->
            NativeInferredInterfaceParameterV1(index, index, null, "absent", "0000000000000000", null, null,
                false, false, false, false, storage, null)
        }
        val listingFunction = NativeInterfaceFunctionV1(address, "candidate", false, false, null, "DEFAULT",
            NativeInterfaceConventionV1("sysv", if (conventionState == "named-resolved") "__cdecl" else null, conventionState),
            true, false, parameterCount, 0, null, listingParameters)
        val listing = NativeInterfaceObservationSummaryV1(listingManifest, binding, emptyList(),
            NativeInterfaceScanV1(1, 1, 0, 0, parameterCount.toLong(), 0, 0, 0),
            listOf(NativeInterfaceModelFunctionV1("model-1", "0000000000000001", listOf(address), "matched")),
            listOf(NativeInterfaceObservedFunctionV1(address, "matched", listOf("model-1"))))
        val result = NativeInferredInterfaceResultV1(true, true, false, false, false, "")
        val prototype = NativeInferredInterfacePrototypeV1(parameterCount, parameterCount, true, true, "model", inferredVarArgs, 0,
            false, false, false, false, false, null, storage)
        val inferredFunction = NativeInferredInterfaceFunctionV1(0, address, false, false,
            "high-function-observed", 1, result, prototype, inferredParameters)
        val inferredBindings = NativeInferredInterfaceBindingsV1(binding, digest, digest, digest, 1,
            listingReportDigest, listingManifestDigest, digest, digest)
        val inferredManifest = NativeInferredInterfaceManifestV1(1, digest, digest, digest, listingReportDigest, digest, digest, digest)
        val inferred = NativeInferredInterfaceSummaryV1(inferredManifest, inferredBindings, listing,
            JsonObject(mapOf("sizeAlignments" to JsonArray(emptyList()))),
            NativeInferredInterfaceScanV1(1, 1, 0, 0, 1, 1, parameterCount.toLong(), 0, 0, 0, 0, 1, mapOf("high-function-observed" to 1)))
        val target = StructuralRecoveryV1Inputs.loadTargetAbi(Path.of("src/test/resources/oracle/structural-v1/target-abi.json"))
        return Fixture(listing, listingFunction, inferred, inferredFunction, target)
    }
}
