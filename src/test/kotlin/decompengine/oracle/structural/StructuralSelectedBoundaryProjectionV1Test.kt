package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class StructuralSelectedBoundaryProjectionV1Test {
    @Test
    fun `real selected replay preserves complete scored and excluded populations without call facts`() = withProjectionFixture { fixture ->
        val projection = StructuralSelectedBoundaryProjectionV1.fromObservation(fixture.observation)
        assertFalse(projection.productionVerified)
        assertEquals("rich", projection.twin)
        assertEquals(0x400000UL, projection.selectedModelImageBase)
        assertEquals(listOf(0UL to 0x1000UL), projection.executableRvaRanges)
        assertEquals(OracleArtifacts.sha256(fixture.model), projection.programModelSha256)
        assertEquals(fixture.model.size.toLong(), projection.programModelBytes)
        assertEquals(OracleArtifacts.sha256(fixture.oracle), projection.functionOracleSha256)
        assertEquals(OracleArtifacts.sha256(fixture.observation), projection.boundaryObservationSha256)
        assertNull(projection.boundaryScoreSha256)
        assertNull(projection.profileId)
        assertNull(projection.fullExportBindingSha256)
        assertEquals(setOf("die-cu0-10-alpha", "die-cu0-20-beta", "die-cu0-30-gamma", "die-cu0-40-delta",
            "die-cu0-50-epsilon"), projection.oracleFunctions.keys)
        assertEquals(setOf("fn_0000000000400010", "fn_0000000000400022", "fn_0000000000400040",
            "fn_0000000000400050", "fn_0000000000400080"), projection.recoveredFunctions.keys)
        assertEquals(0x30UL, projection.oracleFunctions.getValue("die-cu0-30-gamma").rva) // False negative.
        assertEquals(0x80UL, projection.recoveredFunctions.getValue("fn_0000000000400080").rva) // False positive.
        assertEquals(mapOf("fn_0000000000400010" to "die-cu0-10-alpha", "fn_0000000000400022" to "die-cu0-20-beta",
            "fn_0000000000400040" to "die-cu0-40-delta", "fn_0000000000400050" to "die-cu0-50-epsilon"), projection.recoveredToOracle)
        assertEquals(projection.recoveredToOracle.entries.associate { (recovered, oracle) -> oracle to recovered },
            projection.oracleToRecovered)
        assertEquals(0x20UL, projection.oracleFunctions.getValue("die-cu0-20-beta").rva)
        assertEquals(0x22UL, projection.recoveredFunctions.getValue("fn_0000000000400022").rva)
        assertEquals(setOf("symbol-60-clone", "die-cu0-70-inline-helper"), projection.excludedOracleIds)
        assertEquals(setOf("fn_0000000000400060"), projection.ignoredRecoveredIds)
        assertTrue(projection.oracleFunctions.keys.intersect(projection.excludedOracleIds).isEmpty())
        assertTrue(projection.recoveredFunctions.keys.intersect(projection.ignoredRecoveredIds).isEmpty())
        assertNull(projection.excludedFunctions.getValue("die-cu0-70-inline-helper").rva)
    }

    @Test
    fun `exclusion and ignored evidence survives with original nested aliases`() = withProjectionFixture { fixture ->
        val projection = StructuralSelectedBoundaryProjectionV1.fromObservation(fixture.observation)
        val observation = fixture.document()
        for (row in observation.projectionTestRows("excludedFunctions")) {
            val entry = projection.excludedFunctions.getValue(row.projectionTestText("oracleId"))
            assertEquals(row, entry.evidence)
            assertContentEquals(OracleJson.canonicalBytes(row), entry.canonicalEvidenceBytes)
        }
        for (row in observation.getValue("result").jsonObject.projectionTestRows("ignoredExcludedRecoveries")) {
            val entry = projection.ignoredRecoveries.getValue(row.projectionTestText("recoveredId"))
            assertEquals(row, entry.evidence)
            assertEquals(row.projectionTestText("oracleId"), entry.oracleId)
        }
        val evidence = projection.excludedFunctions.getValue("symbol-60-clone").evidence
        val alias = (evidence.getValue("aliases") as JsonArray).single().jsonObject
        assertEquals(setOf("rich", "stripped"), alias.getValue("availability").jsonObject.keys)
        assertTrue((alias.getValue("evidence") as JsonArray).isNotEmpty())
    }

    @Test
    fun `projection never rematches by recovered names`() = withProjectionFixture { fixture ->
        val original = StructuralSelectedBoundaryProjectionV1.fromObservation(fixture.observation)
        val observation = fixture.document()
        val result = observation.getValue("result").jsonObject
        val renamed = JsonObject(result.mapValues { (key, value) ->
            if (key in setOf("exactMatches", "nearMisses", "falsePositives", "ignoredExcludedRecoveries")) {
                JsonArray((value as JsonArray).map { it.jsonObject.changed("recoveredName", JsonPrimitive("alpha")) })
            } else value
        })
        val projected = StructuralSelectedBoundaryProjectionV1.fromObservation(
            observation.changed("result", renamed).observationTestBytes())
        assertEquals(original.recoveredToOracle, projected.recoveredToOracle)
        assertEquals(original.oracleFunctions, projected.oracleFunctions)
        assertEquals(original.recoveredFunctions, projected.recoveredFunctions)
    }

    @Test
    fun `omission duplication and inconsistent exact near or ignored partitions fail`() = withProjectionFixture { fixture ->
        val observation = fixture.document()
        val result = observation.getValue("result").jsonObject
        val exact = result.projectionTestRows("exactMatches")
        val near = result.projectionTestRows("nearMisses")
        val ignored = result.projectionTestRows("ignoredExcludedRecoveries")
        val mutations = listOf(
            result.changed("falseNegatives", JsonArray(emptyList())),
            result.changed("falsePositives", JsonArray(emptyList())),
            result.changed("exactMatches", JsonArray(exact + exact.first())),
            result.changed("nearMisses", JsonArray(near.map { it.changed("deltaBytes", JsonPrimitive(0)) })),
            result.changed("ignoredExcludedRecoveries", JsonArray(ignored.map { it.changed("oracleId", JsonPrimitive("die-cu0-10-alpha")) })),
        )
        for (changed in mutations) assertFailsWith<IllegalArgumentException> {
            StructuralSelectedBoundaryProjectionV1.fromObservation(observation.changed("result", changed).observationTestBytes())
        }
    }

    @Test
    fun `unbound incomplete envelopes and noncanonical commitments fail`() = withProjectionFixture { fixture ->
        val observation = fixture.document()
        val mutations = listOf(
            JsonObject(observation - "programModelSha256"),
            observation.changed("inputSha256", JsonPrimitive("F".repeat(64))),
            observation.changed("functionOracleSha256", JsonPrimitive("short")),
            observation.changed("programModelBytes", JsonPrimitive("123")),
            observation.changed("programModelBytes", JsonPrimitive(0)),
            observation.changed("programModelBytes", JsonPrimitive(536_870_913)),
            observation.changed("selectedModelImageBase", JsonPrimitive("0x0400000")),
            observation.changed("complete", JsonPrimitive(true)),
            observation.changed("scored", JsonPrimitive(true)),
            observation.changed("releaseEligible", JsonPrimitive(true)),
            observation.changed("productionVerified", JsonPrimitive(true)),
            observation.changed("twins", JsonObject(emptyMap())),
        )
        for (changed in mutations) assertFailsWith<IllegalArgumentException> {
            StructuralSelectedBoundaryProjectionV1.fromObservation(changed.observationTestBytes())
        }
        assertFailsWith<IllegalArgumentException> {
            StructuralSelectedBoundaryProjectionV1.fromObservation(fixture.observation + '\n'.code.toByte())
        }
    }

    @Test
    fun `executable range substitutions cannot lose a retained function`() = withProjectionFixture { fixture ->
        val observation = fixture.document()
        val mutations = listOf(
            JsonArray(emptyList()),
            JsonArray(listOf(testRange("0x0", "0x70"))), // The false positive at 0x80 still belongs to the universe.
            JsonArray(listOf(testRange("0x0", "0x50"))), // Ignored exclusion at 0x60 is retained too.
            JsonArray(listOf(testRange("0x0", "0x100"), testRange("0x80", "0x200"))),
            JsonArray(listOf(testRange("0x100", "0x200"), testRange("0x0", "0x100"))),
        )
        for (ranges in mutations) assertFailsWith<IllegalArgumentException> {
            StructuralSelectedBoundaryProjectionV1.fromObservation(
                observation.changed("executableRvaRanges", ranges).observationTestBytes())
        }
    }

    @Test
    fun `serialized production flags grant no authority and bind the entire observation`() = withProjectionFixture { fixture ->
        val bytes = fixture.report().reportTestBytes()
        val projection = StructuralSelectedBoundaryProjectionV1.fromReport(bytes)
        assertFalse(projection.productionVerified)
        assertEquals("fixture-selected-profile", projection.profileId)
        assertEquals(OracleArtifacts.sha256(bytes), projection.boundaryScoreSha256)
        assertContentEquals(bytes, projection.canonicalBoundaryReportBytes)
        assertContentEquals(fixture.observation, projection.canonicalObservationBytes)
        assertEquals(StructuralSelectedBoundaryProjectionV1.fromObservation(fixture.observation).recoveredToOracle,
            projection.recoveredToOracle)
    }

    @Test
    fun `public synthetic constructors cannot replace a live capability with a verification flag`() = withProjectionFixture { fixture ->
        // Kotlin can emit a public bridge for a companion-accessed private constructor. Exercise
        // that JVM surface too: arbitrary report bytes and a null capability must remain untrusted.
        for (constructor in StructuralSelectedBoundaryProjectionV1::class.java.constructors) {
            val types = constructor.parameterTypes.toList()
            assertTrue(VerifiedStructuralInputsV1::class.java in types)
            assertFalse(Boolean::class.javaPrimitiveType in types || Boolean::class.javaObjectType in types)
            var bytesIndex = 0
            val arguments = types.map { type ->
                when (type) {
                    ByteArray::class.java -> if (bytesIndex++ == 0) fixture.observation else fixture.report().reportTestBytes()
                    VerifiedStructuralInputsV1::class.java -> null
                    else -> {
                        assertEquals("kotlin.jvm.internal.DefaultConstructorMarker", type.name)
                        null
                    }
                }
            }.toTypedArray()
            val projection = constructor.newInstance(*arguments) as StructuralSelectedBoundaryProjectionV1
            assertFalse(projection.productionVerified)
        }
    }

    @Test
    fun `report substitution of model input oracle observation or export binding fails`() = withProjectionFixture { fixture ->
        val report = fixture.report()
        val mutations = listOf("inputSha256", "programModelSha256", "functionOracleSha256", "boundaryObservationSha256",
            "fullExportBindingSha256").map { report.changed(it, JsonPrimitive("f".repeat(64))) } + listOf(
            report.changed("programModelBytes", JsonPrimitive(fixture.model.size + 1)),
            report.changed("boundaryObservation", fixture.document().changed("twin", JsonPrimitive("stripped"))),
            report.changed("fullExportBinding", JsonObject(mapOf("replaced" to JsonPrimitive(true)))),
        )
        for (changed in mutations) assertFailsWith<IllegalArgumentException> {
            StructuralSelectedBoundaryProjectionV1.fromReport(changed.reportTestBytes())
        }
    }

    @Test
    fun `source and returned bytes collections and nested evidence cannot mutate the projection`() = withProjectionFixture { fixture ->
        val bytes = fixture.observation.copyOf()
        val projection = StructuralSelectedBoundaryProjectionV1.fromObservation(bytes)
        bytes.fill(0)
        projection.canonicalObservationBytes.fill(0)
        assertContentEquals(fixture.observation, projection.canonicalObservationBytes)
        assertFailsWith<UnsupportedOperationException> {
            (projection.oracleFunctions as MutableMap).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            (projection.recoveredToOracle as MutableMap).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            (projection.executableRvaRanges as MutableList).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            (projection.excludedOracleIds as MutableSet).clear()
        }
        val exclusion = projection.excludedFunctions.getValue("symbol-60-clone")
        val original = exclusion.evidence
        exclusion.canonicalEvidenceBytes.fill(0)
        assertEquals(original, exclusion.evidence)
        assertNotSame(original, exclusion.evidence)
        assertNotSame(original.getValue("aliases"), exclusion.evidence.getValue("aliases"))
        val ignored = projection.ignoredRecoveries.getValue("fn_0000000000400060")
        val originalIgnored = ignored.evidence
        ignored.canonicalEvidenceBytes.fill(0)
        assertEquals(originalIgnored, ignored.evidence)
        val report = fixture.report().reportTestBytes()
        val fromReport = StructuralSelectedBoundaryProjectionV1.fromReport(report)
        val expected = report.copyOf()
        report.fill(0)
        checkNotNull(fromReport.canonicalBoundaryReportBytes).fill(0)
        assertContentEquals(expected, fromReport.canonicalBoundaryReportBytes)
    }
}

private class ProjectionFixture(val oracle: ByteArray, val model: ByteArray, val observation: ByteArray) {
    fun document(): JsonObject = OracleJson.parse(observation, StructuralProductionReplayContract.FUNCTION_ACCURACY_LIMITS).jsonObject
    fun report(): JsonObject {
        val observation = document()
        val binding = JsonObject(mapOf("fixture" to JsonPrimitive("untrusted serialized binding")))
        return JsonObject(mapOf(
            "provider" to JsonPrimitive("structural-selected-boundary-production-score-v1"),
            "schemaVersion" to JsonPrimitive(1), "scope" to JsonPrimitive("model-provenance-and-selected-function-boundaries"),
            "profileId" to JsonPrimitive("fixture-selected-profile"),
            "inputSha256" to observation.getValue("inputSha256"),
            "programModelSha256" to observation.getValue("programModelSha256"),
            "programModelBytes" to observation.getValue("programModelBytes"),
            "functionOracleSha256" to observation.getValue("functionOracleSha256"),
            "fullExportBinding" to binding,
            "fullExportBindingSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(binding))),
            "boundaryObservation" to observation,
            "boundaryObservationSha256" to JsonPrimitive(OracleArtifacts.sha256(this.observation)),
            "productionVerified" to JsonPrimitive(true), "scored" to JsonPrimitive(true),
            "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
        ))
    }
}

private fun withProjectionFixture(block: (ProjectionFixture) -> Unit) {
    fun resource(path: String): ByteArray = checkNotNull(StructuralSelectedBoundaryProjectionV1Test::class.java
        .getResourceAsStream(path)).use { it.readAllBytes() }
    val oracle = resource("/oracle/structural-v1/function-oracle.json")
    val model = resource("/oracle/structural-boundary-replay-v1/rich-model.json")
    val directory = Files.createTempDirectory(Files.createDirectories(Path.of("build", "tmp", "selected-boundary-projection-tests")), "fixture-")
    return try {
        val path = directory.resolve("function-oracle.json")
        Files.write(path, oracle)
        setPermissions(path, "rw-------")
        val selected = StructuralBoundaryReplayV1.observeSelected(StructuralRecoveryV1Inputs.loadFunctionOracle(path),
            "rich", model, 0x400000UL)
        block(ProjectionFixture(oracle, model, selected.canonicalBytes))
    } finally {
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}

private fun JsonObject.projectionTestText(field: String): String = getValue(field).jsonPrimitive.content
private fun JsonObject.projectionTestRows(field: String): List<JsonObject> = (getValue(field) as JsonArray).map { it.jsonObject }
private fun JsonObject.changed(field: String, value: JsonElement): JsonObject = JsonObject(this + (field to value))
private fun JsonObject.observationTestBytes(): ByteArray = StructuralJsonEncoder(64 * 1024 * 1024, true, true).encode(this)
private fun JsonObject.reportTestBytes(): ByteArray = OracleJson.canonicalBytes(this, StructuralProductionReplayContract.FUNCTION_ACCURACY_LIMITS)
private fun testRange(start: String, end: String): JsonObject = JsonObject(mapOf(
    "start" to JsonPrimitive(start), "endExclusive" to JsonPrimitive(end)))
