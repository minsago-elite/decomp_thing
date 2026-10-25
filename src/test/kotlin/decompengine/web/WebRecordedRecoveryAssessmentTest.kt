package decompengine.web

import decompengine.project.*
import kotlinx.serialization.json.*
import kotlin.test.*

/** Authored scalar commitments only: no execution, live capability, model file or oracle file reads. */
class WebRecordedRecoveryAssessmentTest {
    private val profile = GeneratedCMakeReconstructionProfile.descriptor
    private val secret = "PRIVATE_ENTITY_NAME"
    private val inputSha256 = "a".repeat(64)
    private val confidenceSha256 = "c".repeat(64)

    private fun manifest(selected: Boolean = false, change: (JsonObject) -> JsonObject = { it }): SourceTreeManifest {
        val model = RecoveredProgramModel(inputSha256 = inputSha256,
            functions = listOf(RecoveredFunction(secret, secret, 1uL, "void $secret(void)")),
            globals = listOf(RecoveredGlobal(secret, secret, 2uL, "int")),
            types = listOf(RecoveredType(secret, "typedef int $secret;")))
        val module = PlannedModule("module_1", "src/module_1.cpp", "include/module_1.h",
            listOf(secret), listOf(secret), listOf(secret), emptyList())
        val analysis = ProgramAnalysisResult.fromModel(model)
        val projection = RecoveryAssessmentProjectionV1.derive(analysis, ModulePlan(modules = listOf(module)))
        var summary = projection.publicSummary(confidenceSha256).toJsonObject()
        if (selected) {
            val bindings = summary.getValue("bindings").jsonObject
            fun ratio(unit: String, numerator: Int, denominator: Int) = buildJsonObject {
                put("unit", unit); put("numerator", numerator); put("denominator", denominator)
                put("value", numerator.toDouble() / denominator)
            }
            summary = JsonObject(summary + mapOf(
                "bindings" to JsonObject(bindings + ("sourceOverlay" to buildJsonObject {
                    put("sha256", "e".repeat(64)); put("bytes", 100); put("schemaVersion", 1)
                    put("scope", "selected-function-starts-and-surviving-symbol-identities-with-complete-model-census")
                })),
                "measurements" to buildJsonObject {
                    put("functionStarts", buildJsonObject {
                        put("rawRecoveredCount", 1); put("scoredRecoveredCount", 1); put("ignoredExcludedCount", 0)
                        put("exactMatches", 1); put("nearMisses", 0); put("falsePositives", 0); put("falseNegatives", 1)
                        put("oracleFunctionCount", 2); put("scoreableOracleFunctionCount", 2); put("excludedOracleFunctionCount", 0)
                        put("oracleOnlyFunctionCount", 1); put("precision", ratio("recovered-function-starts", 1, 1))
                        put("recall", ratio("oracle-function-starts", 1, 2))
                    })
                    put("survivingSymbolIdentity", buildJsonObject {
                        put("population", 2); put("exact", 1); put("nameMismatch", 0); put("missing", 1)
                        put("identityRecovery", ratio("surviving-oracle-aliases", 1, 2))
                    })
                },
                "unassigned" to buildJsonObject {
                    put("oracleFunctionCount", 2); put("oracleOnlyFunctionCount", 1); put("excludedOracleFunctionCount", 0)
                    put("survivingAliasCount", 1)
                },
            ))
        }
        fun evidence(id: String, digest: String) = GeneratedFileEvidence(profile.layout.declaration(id).materialize(),
            digest, "authored", roles = profile.layout.declaration(id).roles, contentKind = ProjectContentKind.UTF8_TEXT)
        val bindings = projection.document.getValue("bindings").jsonObject
        return SourceTreeManifest(schemaVersion = 4, profileId = profile.id, profileSha256 = profile.sha256,
            inputSha256 = inputSha256, files = listOf(evidence("program-model-evidence", analysis.modelSha256),
                evidence("module-plan-evidence", bindings.getValue("planSha256").jsonPrimitive.content),
                evidence("confidence-evidence", confidenceSha256)), unresolvedEntityIds = emptyList(),
            recordedRecoverySummary = RecordedRecoverySummaryV1.parse(change(summary)))
    }

    @Test fun `selected passive summary preserves complete typed population and unverified origin without names`() {
        val value = manifest(selected = true)
        val result = WebRecordedRecoveryAssessment.project(profile, value)
        assertEquals("recorded", result.getValue("state").jsonPrimitive.content)
        assertEquals("reported-assessment", result.getValue("authority").jsonPrimitive.content)
        assertEquals("recorded-origin-unverified", result.getValue("origin").jsonPrimitive.content)
        val summary = result.getValue("summary").jsonObject
        assertEquals(value.recordedRecoverySummary!!.toJsonObject(), summary)
        assertEquals(3, summary.getValue("population").jsonObject.getValue("modelEntityCount").jsonPrimitive.int)
        assertEquals(20, summary.getValue("dimensions").jsonArray.size)
        assertTrue(summary.getValue("dimensions").jsonArray.all {
            it.jsonObject["state"] == JsonPrimitive("unassessed") && it.jsonObject["factDenominator"] == JsonNull
        })
        assertFalse(result.toString().contains(secret)); assertFalse(result.toString().contains("module_1"))
        assertFalse(result.toString().contains("productionVerified"))
        assertTrue(summary.toString().toByteArray(Charsets.UTF_8).size < WebRecordedRecoveryAssessment.MAXIMUM_BYTES)
    }

    @Test fun `ordinary new summary and legacy unavailable remain distinct`() {
        val fresh = WebRecordedRecoveryAssessment.project(profile, manifest())
        assertEquals("recorded", fresh.getValue("state").jsonPrimitive.content)
        assertEquals(JsonNull, fresh.getValue("summary").jsonObject["measurements"])
        val original = manifest()
        val legacy = SourceTreeManifest(profileId = original.profileId, profileSha256 = original.profileSha256,
            inputSha256 = original.inputSha256, files = original.files, unresolvedEntityIds = emptyList())
        val result = WebRecordedRecoveryAssessment.project(profile, legacy)
        assertEquals("unavailable", result.getValue("state").jsonPrimitive.content)
        assertEquals("legacy-manifest", result.getValue("reason").jsonPrimitive.content)
        assertEquals(JsonNull, result["summary"])
    }

    @Test fun `summary cannot substitute input model plan or confidence commitments`() {
        for (field in listOf("inputSha256", "modelSha256", "planSha256")) {
            val value = manifest(change = { root -> JsonObject(root + ("bindings" to
                JsonObject(root.getValue("bindings").jsonObject + (field to JsonPrimitive("f".repeat(64)))))) })
            assertFailsWith<IllegalArgumentException> { WebRecordedRecoveryAssessment.project(profile, value) }
        }
        assertFailsWith<IllegalArgumentException> {
            WebRecordedRecoveryAssessment.project(profile, manifest(change = {
                JsonObject(it + ("confidenceSha256" to JsonPrimitive("f".repeat(64))))
            }))
        }
    }

    @Test fun `malformed new summaries and stored authority flags are rejected rather than treated as legacy`() {
        assertFailsWith<IllegalArgumentException> { manifest(change = { JsonObject(it + ("productionVerified" to JsonPrimitive(true))) }) }
        assertFailsWith<IllegalArgumentException> { manifest(change = { JsonObject(it + ("scope" to JsonPrimitive(secret))) }) }
        assertFailsWith<IllegalArgumentException> { manifest(change = {
            val population = it.getValue("population").jsonObject
            JsonObject(it + ("population" to JsonObject(population + ("unassessedEntityCount" to JsonPrimitive(0)))))
        }) }
    }
}
