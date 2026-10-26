package decompengine.project

import decompengine.oracle.core.OracleArtifacts
import java.io.ByteArrayInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

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

    private fun fixture(typeRoot: Boolean, danglingReference: Boolean = false): ByteArray {
        val key = "as0@0000000000001000"
        val space = """{"addressableUnitSize":1,"index":0,"name":"ram","overlay":false,"signedOffsets":false,"sizeBits":32,"type":0}"""
        val header = """{"addressSpaces":[$space],"bindings":{"archiveSha256":"${bindings.archiveSha256}","compilerSpecId":"${bindings.compilerSpecId}","exporterSha256":"${bindings.exporterSha256}","imageBase":"${bindings.imageBase}","inputSha256":"${bindings.inputSha256}","languageId":"${bindings.languageId}","programModelBytes":${bindings.programModelBytes},"programModelSha256":"${bindings.programModelSha256}"},"definedDataCount":1,"functionCount":1,"policy":"ghidra-global-type-observations-v1","recordKind":"header"}"""
        val rows = mutableListOf(
            """{"addressSpace":"ram","addressSpaceIndex":0,"captureKey":"$key","dataOrdinal":0,"length":4,"linkageState":"primary-symbol-present","recordKind":"defined-data","symbolExternal":false,"symbolGlobal":true,"symbolName":"g","symbolSource":"ANALYSIS","symbolType":"Global","typePathCaptureKey":"/int"}""",
            """{"alignment":4,"alignedLength":4,"childCount":0,"dataOrdinal":0,"details":{"signed":true},"expansion":"terminal","id":0,"kind":"integer","length":4,"nativeClass":"ghidra.program.model.data.DWordDataType","notYetDefined":false,"recordKind":"type-node","scopeKind":"defined-data","undefined":false,"zeroLength":false}""",
        )
        if (typeRoot) rows += """{"dataOrdinal":0,"recordKind":"type-root","rootNode":0}"""
        val refDataKey = if (danglingReference) "as0@0000000000002000" else key
        rows += """{"dataCaptureKey":"$refDataKey","functionId":"fn_0000000000000001","operandIndex":0,"recordKind":"function-global-reference","referenceAddress":"as0@0000000000001004","targetAddress":"as0@0000000000001000"}"""
        rows += """{"functionId":"fn_0000000000000001","operandIndex":1,"reason":"no-defined-data-containing-target","recordKind":"function-global-reference-unresolved","referenceAddress":"as0@0000000000001008","targetAddress":"as0@0000000000002000"}"""
        return (listOf(header) + rows).joinToString(separator = "\n", postfix = "\n").toByteArray(Charsets.UTF_8)
    }
}
