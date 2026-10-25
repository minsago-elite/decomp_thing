package decompengine.project

import decompengine.oracle.core.OracleJson
import java.util.concurrent.CancellationException
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class RecoveryAssessmentProjectionV1Test {
    @Test
    fun `typed census preserves cross-kind IDs and every extraction status`() {
        val analysis = ProgramAnalysisResult.fromModel(model())
        val plan = plan()
        val projection = RecoveryAssessmentProjectionV1.derive(analysis, plan)
        val root = projection.document
        assertEquals(1, root.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals("reported-assessment", root.getValue("authority").jsonPrimitive.content)
        assertEquals("selected-function-starts-and-surviving-symbol-identities",
            root.getValue("scope").jsonPrimitive.content)
        assertEquals("unassessed", root.getValue("recoveryAssessmentState").jsonPrimitive.content)
        assertEquals(JsonPrimitive(false), root["complete"])
        assertEquals(JsonPrimitive(false), root["releaseEligible"])
        assertPopulation(root.getValue("population").jsonObject, 2, 1, 1)
        val extraction = root.getValue("extraction").jsonObject
        assertEquals("uncalibrated", extraction.getValue("calibration").jsonPrimitive.content)
        for (status in listOf("recovered", "partial", "failed", "synthetic")) {
            assertEquals(1L, extraction.getValue(status).jsonPrimitive.long)
        }
        val rows = root.getValue("modules").jsonArray.map { it.jsonObject }
        assertEquals(setOf("private_alpha", "private_beta"), rows.map { it.getValue("moduleId").jsonPrimitive.content }.toSet())
        assertPopulation(rows.single { it.getValue("moduleId").jsonPrimitive.content == "private_alpha" }
            .getValue("population").jsonObject, 1, 1, 0)
        assertPopulation(rows.single { it.getValue("moduleId").jsonPrimitive.content == "private_beta" }
            .getValue("population").jsonObject, 1, 0, 1)
        rows.forEach { assertEquals(JsonNull, it["candidateMeasurements"]) }
        assertEquals(JsonNull, root["measurements"])
        assertEquals(JsonNull, root["unassigned"])
        assertEquals("no-structural-evidence", projection.verificationDisposition(analysis, plan))
    }

    @Test
    fun `all structural dimensions retain unknown fact denominators`() {
        val projection = RecoveryAssessmentProjectionV1.derive(ProgramAnalysisResult.fromModel(model()), plan())
        val dimensions = projection.document.getValue("dimensions").jsonArray.map { it.jsonObject }
        assertEquals(20, dimensions.size)
        assertEquals(20, dimensions.map { it.getValue("id").jsonPrimitive.content }.distinct().size)
        dimensions.forEach { dimension ->
            assertEquals("unassessed", dimension.getValue("state").jsonPrimitive.content)
            assertEquals(JsonNull, dimension["factDenominator"])
            val expected = when (dimension.getValue("entityKind").jsonPrimitive.content) {
                "function" -> 2L
                "global", "type" -> 1L
                else -> error("unexpected dimension entity kind")
            }
            assertEquals(expected, dimension.getValue("applicableEntityCount").jsonPrimitive.long)
        }
    }

    @Test
    fun `missing invented and duplicate typed ownership fail rather than lose rows`() {
        val analysis = ProgramAnalysisResult.fromModel(model())
        val plan = plan()
        val first = plan.modules.first()
        val other = plan.modules.last()
        val invalid = listOf(
            plan.copy(modules = listOf(first.copy(functionIds = emptyList()), other)),
            plan.copy(modules = listOf(first.copy(globalIds = emptyList()), other)),
            plan.copy(modules = listOf(first, other.copy(typeIds = emptyList()))),
            plan.copy(modules = listOf(first.copy(functionIds = first.functionIds + first.functionIds), other)),
            plan.copy(modules = listOf(first, other.copy(globalIds = first.globalIds))),
            plan.copy(modules = listOf(first.copy(typeIds = listOf("invented")), other)),
            plan.copy(modules = plan.modules + first),
        )
        invalid.forEach { candidate ->
            assertFails { RecoveryAssessmentProjectionV1.derive(analysis, candidate) }
        }
        assertPopulation(RecoveryAssessmentProjectionV1.derive(analysis, plan).document.getValue("population").jsonObject,
            2, 1, 1)
    }

    @Test
    fun `derivation retains one plan snapshot when caller ownership changes after capture`() {
        val analysis = ProgramAnalysisResult.fromModel(model())
        val alphaFunctions = mutableListOf("private_shared")
        val betaFunctions = mutableListOf("private_second")
        val mutablePlan = ModulePlan(modules = listOf(
            module("private_alpha", alphaFunctions, listOf("private_shared")),
            module("private_beta", betaFunctions, typeIds = listOf("private_shared")),
        ))
        val expected = RecoveryAssessmentProjectionV1.derive(analysis, mutablePlan)
        var changed = false
        val captured = RecoveryAssessmentProjectionV1.derive(analysis, mutablePlan, checkpoint = { stage ->
            if (stage == "counting complete typed model census" && !changed) {
                betaFunctions.addAll(alphaFunctions)
                alphaFunctions.clear()
                changed = true
            }
        })
        assertTrue(changed, "mutation control did not reach the post-capture checkpoint")
        assertContentEquals(expected.canonicalBytes, captured.canonicalBytes)
        assertEquals(expected.document.getValue("modules"), captured.document.getValue("modules"))
        val later = RecoveryAssessmentProjectionV1.derive(analysis, mutablePlan)
        assertNotEquals(expected.sha256, later.sha256)
        assertNotEquals(expected.document.getValue("modules"), later.document.getValue("modules"))
    }

    @Test
    fun `historical schemas retain exact bindings without publishing non-digest input labels`() {
        for (version in 1..4) {
            val model = RecoveredProgramModel(version, "input-sha",
                listOf(RecoveredFunction("private_function", "private_name", 1u, "void private_name(void)")))
            val plan = ModulePlan(modules = listOf(module("private_alpha", listOf("private_function"))))
            val analysis = ProgramAnalysisResult.fromModel(model)
            val projection = RecoveryAssessmentProjectionV1.derive(analysis, plan)
            val bindings = projection.document.getValue("bindings").jsonObject
            assertEquals(JsonNull, bindings["inputSha256"])
            assertEquals(analysis.modelSha256, bindings.getValue("modelSha256").jsonPrimitive.content)
            assertEquals(analysis.modelBytes, bindings.getValue("modelBytes").jsonPrimitive.long)
            assertEquals(version, bindings.getValue("modelSchemaVersion").jsonPrimitive.int)
            assertEquals(sha256(plan.toJson().toByteArray()), bindings.getValue("planSha256").jsonPrimitive.content)
            assertEquals(plan.toJson().toByteArray().size.toLong(), bindings.getValue("planBytes").jsonPrimitive.long)
            assertEquals(2, bindings.getValue("planSchemaVersion").jsonPrimitive.int)
            assertEquals(JsonNull, bindings["sourceOverlay"])
            assertTrue(bindings.getValue("censusSha256").jsonPrimitive.content.matches(Regex("[0-9a-f]{64}")))
            val summary = projection.publicSummary("b".repeat(64))
            assertEquals(JsonNull, summary.document.getValue("bindings").jsonObject["inputSha256"])
            assertFalse("input-sha" in summary.toJson())
            assertContentEquals(projection.canonicalBytes,
                RecoveryAssessmentProjectionV1.parsePassive(projection.canonicalBytes, analysis, plan).canonicalBytes)
        }
    }

    @Test
    fun `passive round trip remains unassessed and cannot assert production authority`() {
        val analysis = ProgramAnalysisResult.fromModel(model())
        val plan = plan()
        val projection = RecoveryAssessmentProjectionV1.derive(analysis, plan)
        val passive = RecoveryAssessmentProjectionV1.parsePassive(projection.canonicalBytes)
        assertContentEquals(projection.canonicalBytes, OracleJson.canonicalBytes(projection.document))
        assertContentEquals(projection.canonicalBytes, passive.canonicalBytes)
        assertEquals(projection.sha256, passive.sha256)
        assertEquals("no-structural-evidence", passive.verificationDisposition(analysis, plan))
        for (field in listOf("productionVerified", "liveAdmission", "verified")) {
            assertFails {
                RecoveryAssessmentProjectionV1.parsePassive(changed(projection.document, field, JsonPrimitive(true)))
            }
        }
        for ((key, value) in listOf("authority" to JsonPrimitive("production-verified"),
            "complete" to JsonPrimitive(true), "releaseEligible" to JsonPrimitive(true),
            "recoveryAssessmentState" to JsonPrimitive("assessed"), "schemaVersion" to JsonPrimitive(2))) {
            assertFails { RecoveryAssessmentProjectionV1.parsePassive(changed(projection.document, key, value)) }
        }
    }

    @Test
    fun `recorded selected counts preserve missing aliases and remain origin unverified`() {
        val analysis = ProgramAnalysisResult.fromModel(model())
        val plan = plan()
        val ordinary = RecoveryAssessmentProjectionV1.derive(analysis, plan)
        // These are authored recorded claims with a synthetic source digest, never a live capability.
        val recorded = recordedSelectedDocument(ordinary.document)
        val projection = RecoveryAssessmentProjectionV1.parsePassive(OracleJson.canonicalBytes(recorded), analysis, plan)
        assertEquals("recorded-origin-unverified", projection.verificationDisposition(analysis, plan))
        assertEquals("reported-assessment", projection.document.getValue("authority").jsonPrimitive.content)
        val measurements = projection.document.getValue("measurements").jsonObject
        val starts = measurements.getValue("functionStarts").jsonObject
        assertEquals(2L, starts.getValue("rawRecoveredCount").jsonPrimitive.long)
        assertEquals(1L, starts.getValue("ignoredExcludedCount").jsonPrimitive.long)
        assertEquals(1L, starts.getValue("oracleOnlyFunctionCount").jsonPrimitive.long)
        val aliases = measurements.getValue("survivingSymbolIdentity").jsonObject
        assertEquals(4L, aliases.getValue("population").jsonPrimitive.long)
        assertEquals(2L, aliases.getValue("missing").jsonPrimitive.long)
        assertEquals(0.25, aliases.getValue("identityRecovery").jsonObject.getValue("value").jsonPrimitive.double)
        val unassigned = projection.document.getValue("unassigned").jsonObject
        assertEquals(2L, unassigned.getValue("survivingAliasCount").jsonPrimitive.long)
        assertEquals(3L, unassigned.getValue("oracleFunctionCount").jsonPrimitive.long)
        val summary = projection.publicSummary("b".repeat(64))
        assertEquals(measurements, summary.document["measurements"])
        assertEquals(unassigned, summary.document["unassigned"])

        val missingAlias = JsonObject(unassigned + ("survivingAliasCount" to JsonPrimitive(1)))
        assertFails { RecoveryAssessmentProjectionV1.parsePassive(changed(recorded, "unassigned", missingAlias)) }
        val falseRatio = JsonObject(aliases.getValue("identityRecovery").jsonObject + ("value" to JsonPrimitive(1)))
        val falseAliases = JsonObject(aliases + ("identityRecovery" to falseRatio))
        val falseMeasurements = JsonObject(measurements + ("survivingSymbolIdentity" to falseAliases))
        assertFails { RecoveryAssessmentProjectionV1.parsePassive(changed(recorded, "measurements", falseMeasurements)) }
        assertFails { RecordedRecoverySummaryV1.parse(JsonObject(summary.document + ("measurements" to falseMeasurements))) }
        val rows = recorded.getValue("modules").jsonArray
        val first = rows.first().jsonObject
        val candidate = first.getValue("candidateMeasurements").jsonObject
        val alteredCandidate = JsonObject(candidate + ("exactSurvivingAliasCount" to JsonPrimitive(0)))
        val alteredRows = JsonArray(listOf(JsonObject(first + ("candidateMeasurements" to alteredCandidate))) + rows.drop(1))
        assertFails { RecoveryAssessmentProjectionV1.parsePassive(changed(recorded, "modules", alteredRows)) }
    }

    @Test
    fun `passive bound parsing rejects stale model plan and census commitments`() {
        val analysis = ProgramAnalysisResult.fromModel(model())
        val plan = plan()
        val projection = RecoveryAssessmentProjectionV1.derive(analysis, plan)
        val changedModel = ProgramAnalysisResult.fromModel(model().copy(functions = model().functions.map {
            it.copy(name = it.name + "_changed")
        }))
        val changedPlan = plan.copy(modules = plan.modules.map { it.copy(boundaryEvidence = listOf("different evidence")) })
        assertFails { RecoveryAssessmentProjectionV1.parsePassive(projection.canonicalBytes, changedModel, plan) }
        assertFails { RecoveryAssessmentProjectionV1.parsePassive(projection.canonicalBytes, analysis, changedPlan) }
        val bindings = projection.document.getValue("bindings").jsonObject
        for (key in listOf("modelSha256", "planSha256", "censusSha256")) {
            val changedBindings = JsonObject(bindings + (key to JsonPrimitive("f".repeat(64))))
            assertFails {
                RecoveryAssessmentProjectionV1.parsePassive(changed(projection.document, "bindings", changedBindings),
                    analysis, plan)
            }
        }
    }

    @Test
    fun `passive parser rejects invalid counts omitted fields and impossible unassessed populations`() {
        val projection = RecoveryAssessmentProjectionV1.derive(ProgramAnalysisResult.fromModel(model()), plan())
        val population = projection.document.getValue("population").jsonObject
        for ((key, value) in listOf("modelEntityCount" to JsonPrimitive(-1),
            "modelEntityCount" to JsonPrimitive("4"), "modelEntityCount" to JsonPrimitive(5),
            "assessedEntityCount" to JsonPrimitive(1), "unassessedEntityCount" to JsonPrimitive(3),
            "functionCount" to JsonPrimitive(Long.MAX_VALUE))) {
            val changedPopulation = JsonObject(population + (key to value))
            assertFails {
                RecoveryAssessmentProjectionV1.parsePassive(changed(projection.document, "population", changedPopulation))
            }
        }
        assertFails { RecoveryAssessmentProjectionV1.parsePassive(OracleJson.canonicalBytes(
            JsonObject(projection.document - "dimensions"))) }
        assertFails { RecoveryAssessmentProjectionV1.parsePassive(changed(projection.document, "dimensions", JsonArray(emptyList()))) }
    }

    @Test
    fun `public summary excludes private entities and rebinding changes no projection commitments`() {
        val analysis = ProgramAnalysisResult.fromModel(model())
        val projection = RecoveryAssessmentProjectionV1.derive(analysis, plan())
        val beforeBytes = projection.canonicalBytes
        val summary = projection.publicSummary("b".repeat(64))
        val rebound = summary.rebindConfidenceSha256("c".repeat(64))
        assertFalse("modules" in summary.document)
        for (privateValue in listOf("private_", "src/", "include/", "0x1", "int secret")) {
            assertFalse(privateValue in summary.toJson(), "summary disclosed $privateValue")
        }
        assertEquals(projection.sha256, summary.document.getValue("projectionSha256").jsonPrimitive.content)
        assertEquals("b".repeat(64), summary.document.getValue("confidenceSha256").jsonPrimitive.content)
        assertEquals("c".repeat(64), rebound.document.getValue("confidenceSha256").jsonPrimitive.content)
        assertEquals(summary.document - "confidenceSha256", rebound.document - "confidenceSha256")
        assertNotEquals(summary.canonicalBytes.toList(), rebound.canonicalBytes.toList())
        assertContentEquals(beforeBytes, projection.canonicalBytes)
        assertFalse("confidenceSha256" in projection.document)
        assertEquals(sha256(beforeBytes), projection.sha256)
        assertContentEquals(summary.canonicalBytes, RecordedRecoverySummaryV1.parse(summary.toJsonObject()).canonicalBytes)
        assertFails { summary.rebindConfidenceSha256("not-a-digest") }
        assertFails { RecordedRecoverySummaryV1.parse(JsonObject(summary.document + ("productionVerified" to JsonPrimitive(true)))) }
    }

    @Test
    fun `projection and summary bytes are defensive`() {
        val projection = RecoveryAssessmentProjectionV1.derive(ProgramAnalysisResult.fromModel(model()), plan())
        val expected = projection.canonicalBytes
        val input = expected.copyOf()
        val parsed = RecoveryAssessmentProjectionV1.parsePassive(input)
        input.fill(0)
        parsed.canonicalBytes.fill(1)
        assertContentEquals(expected, parsed.canonicalBytes)
        assertEquals(sha256(expected), parsed.sha256)
        val summary = parsed.publicSummary("b".repeat(64))
        val expectedSummary = summary.canonicalBytes
        summary.canonicalBytes.fill(2)
        assertContentEquals(expectedSummary, summary.canonicalBytes)
    }

    @Test
    fun `empty populations stay unassessed without manufacturing ratios`() {
        val analysis = ProgramAnalysisResult.fromModel(RecoveredProgramModel(4, "a".repeat(64), emptyList()))
        val plan = ModulePlan(modules = emptyList())
        val projection = RecoveryAssessmentProjectionV1.derive(analysis, plan)
        assertPopulation(projection.document.getValue("population").jsonObject, 0, 0, 0)
        assertEquals(JsonNull, projection.document["measurements"])
        projection.document.getValue("dimensions").jsonArray.forEach {
            assertEquals(0L, it.jsonObject.getValue("applicableEntityCount").jsonPrimitive.long)
            assertEquals(JsonNull, it.jsonObject["factDenominator"])
        }
        fun zeroClaims(value: JsonElement): JsonElement = when (value) {
            is JsonObject -> JsonObject(value.mapValues { (key, child) -> if (key == "value") JsonNull else zeroClaims(child) })
            is JsonPrimitive -> if (value.isString) value else JsonPrimitive(0)
            else -> error("unexpected recorded measurement structure")
        }
        val claims = recordedSelectedDocument(projection.document)
        val emptyClaims = JsonObject(claims + mapOf("measurements" to zeroClaims(claims.getValue("measurements")),
            "unassigned" to zeroClaims(claims.getValue("unassigned"))))
        val recorded = RecoveryAssessmentProjectionV1.parsePassive(OracleJson.canonicalBytes(emptyClaims), analysis, plan)
        assertEquals("recorded-origin-unverified", recorded.verificationDisposition(analysis, plan))
        val measurements = recorded.document.getValue("measurements").jsonObject
        val starts = measurements.getValue("functionStarts").jsonObject
        for (ratio in listOf(starts.getValue("precision"), starts.getValue("recall"),
            measurements.getValue("survivingSymbolIdentity").jsonObject.getValue("identityRecovery"))) {
            assertEquals(0L, ratio.jsonObject.getValue("denominator").jsonPrimitive.long)
            assertEquals(JsonNull, ratio.jsonObject["value"])
        }
        val falsePrecision = JsonObject(starts.getValue("precision").jsonObject + ("value" to JsonPrimitive(1)))
        val falseStarts = JsonObject(starts + ("precision" to falsePrecision))
        val falseMeasurements = JsonObject(measurements + ("functionStarts" to falseStarts))
        assertFails { RecoveryAssessmentProjectionV1.parsePassive(changed(emptyClaims, "measurements", falseMeasurements)) }
    }

    @Test
    fun `byte limits and cancellation reject partial derivations and passive parses`() {
        val analysis = ProgramAnalysisResult.fromModel(model())
        val plan = plan()
        val projection = RecoveryAssessmentProjectionV1.derive(analysis, plan)
        val size = projection.canonicalBytes.size
        assertFails { RecoveryAssessmentProjectionV1.derive(analysis, plan, maximumBytes = size - 1) }
        assertFails { RecoveryAssessmentProjectionV1.parsePassive(projection.canonicalBytes, maximumBytes = size - 1) }
        assertFails { RecoveryAssessmentProjectionV1.parsePassive(projection.canonicalBytes, analysis, plan,
            maximumBytes = size - 1) }
        assertContentEquals(projection.canonicalBytes,
            RecoveryAssessmentProjectionV1.derive(analysis, plan, maximumBytes = size).canonicalBytes)
        val cancelled = CancellationException("controlled projection cancellation")
        assertSame(cancelled, assertFailsWith<CancellationException> {
            RecoveryAssessmentProjectionV1.derive(analysis, plan, checkpoint = { throw cancelled })
        })
        assertSame(cancelled, assertFailsWith<CancellationException> {
            RecoveryAssessmentProjectionV1.parsePassive(projection.canonicalBytes, checkpoint = { throw cancelled })
        })
        assertSame(cancelled, assertFailsWith<CancellationException> {
            RecoveryAssessmentProjectionV1.parsePassive(projection.canonicalBytes, analysis, plan,
                checkpoint = { throw cancelled })
        })
    }

    private fun model() = RecoveredProgramModel(4, "a".repeat(64), functions = listOf(
        RecoveredFunction("private_shared", "private_function", 1u, "int secret(void)", status = RecoveryStatus.RECOVERED),
        RecoveredFunction("private_second", "private_second_function", 2u, "int secret_second(void)", status = RecoveryStatus.PARTIAL),
    ), globals = listOf(RecoveredGlobal("private_shared", "private_global", 3u, "int", status = RecoveryStatus.FAILED)),
        types = listOf(RecoveredType("private_shared", "typedef int private_type;", status = RecoveryStatus.SYNTHETIC)))

    private fun plan() = ModulePlan(modules = listOf(
        module("private_alpha", listOf("private_shared"), listOf("private_shared")),
        module("private_beta", listOf("private_second"), typeIds = listOf("private_shared")),
    ))

    private fun module(id: String, functionIds: List<String>, globalIds: List<String> = emptyList(),
        typeIds: List<String> = emptyList()) = PlannedModule(id, "src/$id.c", "include/$id.h",
        functionIds, globalIds, typeIds, boundaryEvidence = emptyList())

    private fun assertPopulation(population: JsonObject, functions: Long, globals: Long, types: Long) {
        val total = functions + globals + types
        assertEquals("model-entities", population.getValue("unit").jsonPrimitive.content)
        assertEquals(functions, population.getValue("functionCount").jsonPrimitive.long)
        assertEquals(globals, population.getValue("globalCount").jsonPrimitive.long)
        assertEquals(types, population.getValue("typeCount").jsonPrimitive.long)
        assertEquals(total, population.getValue("modelEntityCount").jsonPrimitive.long)
        assertEquals(0L, population.getValue("assessedEntityCount").jsonPrimitive.long)
        assertEquals(total, population.getValue("unassessedEntityCount").jsonPrimitive.long)
    }

    private fun recordedSelectedDocument(ordinary: JsonObject): JsonObject {
        fun counts(vararg values: Pair<String, Long>) = JsonObject(values.associate { it.first to JsonPrimitive(it.second) })
        fun ratio(unit: String, numerator: Long, denominator: Long) = buildJsonObject {
            put("unit", unit); put("numerator", numerator); put("denominator", denominator)
            put("value", if (denominator == 0L) JsonNull else JsonPrimitive(numerator.toDouble() / denominator))
        }
        val starts = JsonObject(counts("rawRecoveredCount" to 2L, "scoredRecoveredCount" to 1L,
            "ignoredExcludedCount" to 1L, "exactMatches" to 1L, "nearMisses" to 0L, "falsePositives" to 0L,
            "falseNegatives" to 1L, "oracleFunctionCount" to 3L, "scoreableOracleFunctionCount" to 2L,
            "excludedOracleFunctionCount" to 1L, "oracleOnlyFunctionCount" to 1L) + mapOf(
            "precision" to ratio("recovered-function-starts", 1, 1), "recall" to ratio("oracle-function-starts", 1, 2)))
        val aliases = JsonObject(counts("population" to 4L, "exact" to 1L, "nameMismatch" to 1L, "missing" to 2L) +
            ("identityRecovery" to ratio("surviving-oracle-aliases", 1, 4)))
        val source = buildJsonObject {
            put("sha256", "d".repeat(64)); put("bytes", 1); put("schemaVersion", 1)
            put("scope", "selected-function-starts-and-surviving-symbol-identities-with-complete-model-census")
        }
        val bindings = JsonObject(ordinary.getValue("bindings").jsonObject + ("sourceOverlay" to source))
        val modules = JsonArray(ordinary.getValue("modules").jsonArray.map { item ->
            val module = item.jsonObject
            val exact = module.getValue("moduleId").jsonPrimitive.content == "private_alpha"
            val candidates = counts("rawRecoveredCount" to 1L, "scoredRecoveredCount" to if (exact) 1L else 0L,
                "ignoredExcludedCount" to if (exact) 0L else 1L, "exactMatches" to if (exact) 1L else 0L,
                "nearMisses" to 0L, "unmatchedCount" to 0L, "survivingAliasCount" to if (exact) 2L else 0L,
                "exactSurvivingAliasCount" to if (exact) 1L else 0L, "mismatchedSurvivingAliasCount" to if (exact) 1L else 0L)
            JsonObject(module + ("candidateMeasurements" to candidates))
        })
        return JsonObject(ordinary + mapOf("bindings" to bindings, "modules" to modules,
            "measurements" to buildJsonObject { put("functionStarts", starts); put("survivingSymbolIdentity", aliases) },
            "unassigned" to counts("oracleFunctionCount" to 3L, "oracleOnlyFunctionCount" to 1L,
                "excludedOracleFunctionCount" to 1L, "survivingAliasCount" to 2L)))
    }

    private fun changed(document: JsonObject, field: String, value: JsonElement): ByteArray =
        OracleJson.canonicalBytes(JsonObject(document + (field to value)))
}
