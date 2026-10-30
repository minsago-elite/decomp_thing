package decompengine.project

import decompengine.oracle.core.OracleArtifacts
import java.io.ByteArrayInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlinx.serialization.json.*

class GlobalTypeObservationsV1Test {
    private val bindings = GlobalTypeObservationBindingsV1(
        inputSha256 = "a".repeat(64), exporterSha256 = "b".repeat(64), archiveSha256 = "c".repeat(64),
        programModelBytes = 123, programModelSha256 = "d".repeat(64), languageId = "x86:LE:64:default",
        compilerSpecId = "gcc", imageBase = "as0@0000000000400000",
    )

    @Test
    fun retainsCompleteTypedListingCensusAndFunctionOwnedReferencesWithoutOracleAuthority() {
        val bytes = fixture(typeRoot = true)
        val summary = GlobalTypeObservationsV1.validate(bindings, bytes.size.toLong(), OracleArtifacts.sha256(bytes),
            expectedFunctionIds = setOf("fn_0000000000000001"),
            checkpoint = {}, openObservations = { ByteArrayInputStream(bytes) })

        assertEquals(1, summary.definedDataEntities)
        assertEquals(1, summary.typeNodes)
        assertEquals(1, summary.functionGlobalReferences)
        assertEquals(1, summary.unresolvedFunctionGlobalReferences)
        assertEquals("captured-nonempty", summary.suppliedListingCensusState)
        assertEquals("recovered-observations-only", summary.authorityBoundary)
        assertEquals("oracle-population-identity-and-visibility-not-supplied", summary.populationBoundary)
    }

    @Test
    fun refusesAnEntityWithoutItsTypeRoot() {
        val bytes = fixture(typeRoot = false)
        assertFailsWith<IllegalArgumentException> {
            GlobalTypeObservationsV1.validate(bindings, bytes.size.toLong(), OracleArtifacts.sha256(bytes),
                expectedFunctionIds = setOf("fn_0000000000000001"),
                checkpoint = {}, openObservations = { ByteArrayInputStream(bytes) })
        }
    }

    @Test
    fun refusesAReferenceToAnUncensusedDataKey() {
        val bytes = fixture(typeRoot = true, danglingReference = true)
        assertFailsWith<IllegalArgumentException> {
            GlobalTypeObservationsV1.validate(bindings, bytes.size.toLong(), OracleArtifacts.sha256(bytes),
                expectedFunctionIds = setOf("fn_0000000000000001"),
                checkpoint = {}, openObservations = { ByteArrayInputStream(bytes) })
        }
    }

    @Test
    fun refusesAFunctionReferenceOwnerOutsideTheIndependentlyValidatedFunctionMap() {
        val bytes = fixture(typeRoot = true)
        assertFailsWith<IllegalArgumentException> {
            GlobalTypeObservationsV1.validate(bindings, bytes.size.toLong(), OracleArtifacts.sha256(bytes),
                expectedFunctionIds = setOf("fn_0000000000000002"),
                checkpoint = {}, openObservations = { ByteArrayInputStream(bytes) })
        }
    }

    @Test
    fun refusesRehashedMalformedTypedNodesIncludingIndependentAuditControls() {
        val original = fixture(typeRoot = true).toString(Charsets.UTF_8)
        for ((before, after) in listOf(
            "\"childCount\":0" to "\"childCount\":1",
            "\"undefined\":false" to "\"undefined\":\"not-a-bool\"",
            "\"details\":{\"signed\":true}" to "\"details\":null",
            "\"details\":{\"signed\":true}" to "\"details\":{\"signed\":\"true\"}",
            "\"expansion\":\"terminal\"" to "\"expansion\":\"expanded\"",
            "\"id\":0" to "\"id\":1",
            "\"overlay\":false" to "\"overlay\":\"false\"",
        )) {
            val mutated = original.replace(before, after)
            check(mutated != original)
            assertFails(after) { validate(mutated.toByteArray()) }
        }
    }

    @Test
    fun validatesDataScopedCompleteDfsAndRejectsRehashedRelationshipAndReferenceStateMutations() {
        val rows = listOf(
            InferredInterfaceFixture.node("listing", 0, 0, "pointer", 1, InferredInterfaceFixture.obj("pointerSize" to 8), length = 8),
            InferredInterfaceFixture.edge("listing", 0, 0, 0, "pointer-target", 1, "new-node"),
            InferredInterfaceFixture.node("listing", 0, 1, "structure", 1, InferredInterfaceFixture.compositeDetails(1), length = 8),
            InferredInterfaceFixture.edge("listing", 0, 1, 0, "component", 0, "backedge", component = true),
            InferredInterfaceFixture.root("listing", 0, "return-formal", -1, 0, 0),
        ).map(::dataScoped)
        val summary = validate(fixture(true, graphRows = rows))
        assertEquals(2L, summary.typeNodes)
        assertEquals(2L, summary.typeEdges)
        for ((index, key, value) in listOf(
            Triple(1, "referenceState", JsonPrimitive("reused-node")),
            Triple(1, "relation", JsonPrimitive("array-element")),
            Triple(1, "ordinal", JsonPrimitive(1)),
            Triple(1, "target", JsonPrimitive("1")),
            Triple(3, "referenceState", JsonPrimitive("reused-node")),
            Triple(3, "undefined", JsonPrimitive("false")),
            Triple(3, "source", JsonPrimitive(0)),
            Triple(4, "rootNode", JsonPrimitive(2)),
        )) assertFails("$index/$key") {
            validate(fixture(true, graphRows = rows.mapIndexed { at, row ->
                if (at == index) JsonObject(row + (key to value)) else row
            }))
        }
        assertFails { validate(fixture(true, graphRows = rows.filterIndexed { index, _ -> index != 3 })) }
        assertFails { validate(fixture(true, graphRows = rows + rows.last())) }
        assertFails { validate(fixture(true, graphRows = rows + rows.first())) }
    }

    @Test
    fun enforcesDataGraphDepthAndDirectEnumPopulationConservation() {
        val deep = buildList {
            for (id in 0..65) {
                add(dataScoped(InferredInterfaceFixture.node("listing", 0, id, "pointer", 1,
                    InferredInterfaceFixture.obj("pointerSize" to 8), length = 8)))
                add(dataScoped(InferredInterfaceFixture.edge("listing", 0, id, 0, "pointer-target",
                    if (id < 65) id + 1 else null, if (id < 65) "new-node" else "missing")))
            }
            add(dataScoped(InferredInterfaceFixture.root("listing", 0, "return-formal", -1, 0, 0)))
        }
        assertFails { validate(fixture(true, graphRows = deep)) }
        val enumeration = listOf(
            dataScoped(InferredInterfaceFixture.node("listing", 0, 0, "enum", 0,
                InferredInterfaceFixture.obj("enumeratorCount" to 1, "signedState" to "signed", "enumeratorsState" to "not-captured"))),
            dataScoped(InferredInterfaceFixture.root("listing", 0, "return-formal", -1, 0, 0)),
        )
        val member = InferredInterfaceFixture.obj("dataOrdinal" to 0, "recordKind" to "enum-member",
            "enumeratorName" to "ONE", "value" to 1, "valueBits" to "0000000000000001")
        assertEquals(1L, validate(fixture(true, graphRows = enumeration + member)).enumMembers)
        assertFails { validate(fixture(true, graphRows = enumeration)) }
        assertFails { validate(fixture(true, graphRows = enumeration + member + member)) }
        assertFails { validate(fixture(true, graphRows = listOf(member) + enumeration)) }
    }

    private fun validate(bytes: ByteArray) = GlobalTypeObservationsV1.validate(bindings, bytes.size.toLong(),
        OracleArtifacts.sha256(bytes), setOf("fn_0000000000000001"), checkpoint = {},
        openObservations = { ByteArrayInputStream(bytes) })

    private fun dataScoped(row: JsonObject): JsonObject = if (row["recordKind"] == JsonPrimitive("type-root"))
        InferredInterfaceFixture.obj("dataOrdinal" to 0, "recordKind" to "type-root", "rootNode" to row.getValue("node"))
    else JsonObject((row - setOf("channel", "functionOrdinal")) + mapOf(
        "scopeKind" to JsonPrimitive("defined-data"), "dataOrdinal" to JsonPrimitive(0)))

    private fun fixture(typeRoot: Boolean, danglingReference: Boolean = false, graphRows: List<JsonObject>? = null): ByteArray {
        val key = "as0@0000000000001000"
        val space = """{"addressableUnitSize":1,"index":0,"name":"ram","overlay":false,"signedOffsets":false,"sizeBits":32,"type":0}"""
        val header = """{"addressSpaces":[$space],"bindings":{"archiveSha256":"${bindings.archiveSha256}","compilerSpecId":"${bindings.compilerSpecId}","exporterSha256":"${bindings.exporterSha256}","imageBase":"${bindings.imageBase}","inputSha256":"${bindings.inputSha256}","languageId":"${bindings.languageId}","programModelBytes":${bindings.programModelBytes},"programModelSha256":"${bindings.programModelSha256}"},"definedDataCount":1,"functionCount":1,"policy":"ghidra-global-type-observations-v1","recordKind":"header"}"""
        val rows = mutableListOf(
            """{"addressSpace":"ram","addressSpaceIndex":0,"captureKey":"$key","dataOrdinal":0,"length":4,"linkageState":"primary-symbol-present","recordKind":"defined-data","symbolExternal":false,"symbolGlobal":true,"symbolName":"g","symbolSource":"ANALYSIS","symbolType":"Global","typePathCaptureKey":"/int"}""",
            """{"alignment":4,"alignedLength":4,"childCount":0,"dataOrdinal":0,"details":{"signed":true},"expansion":"terminal","id":0,"kind":"integer","length":4,"nativeClass":"ghidra.program.model.data.DWordDataType","notYetDefined":false,"recordKind":"type-node","scopeKind":"defined-data","undefined":false,"zeroLength":false}""",
        )
        if (typeRoot) rows += """{"dataOrdinal":0,"recordKind":"type-root","rootNode":0}"""
        if (graphRows != null) {
            rows.subList(1, rows.size).clear()
            rows += graphRows.map(JsonObject::toString)
        }
        val refDataKey = if (danglingReference) "as0@0000000000002000" else key
        rows += """{"dataCaptureKey":"$refDataKey","functionId":"fn_0000000000000001","operandIndex":0,"recordKind":"function-global-reference","referenceAddress":"as0@0000000000001004","targetAddress":"as0@0000000000001000"}"""
        rows += """{"functionId":"fn_0000000000000001","operandIndex":1,"reason":"no-defined-data-containing-target","recordKind":"function-global-reference-unresolved","referenceAddress":"as0@0000000000001008","targetAddress":"as0@0000000000002000"}"""
        return (listOf(header) + rows).joinToString(separator = "\n", postfix = "\n").toByteArray(Charsets.UTF_8)
    }
}
