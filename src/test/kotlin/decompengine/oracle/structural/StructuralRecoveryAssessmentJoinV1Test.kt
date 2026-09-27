package decompengine.oracle.structural

import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredGlobal
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveredType
import decompengine.project.RecoveryStatus
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class StructuralRecoveryAssessmentJoinV1Test {
    @Test
    fun `fixture findings join by exact model bytes and stable entity identity without assessing extraction`() =
        withStructuralFixture { fixture ->
            val inputs = fixture.load()
            val score = StructuralRecoveryV1.scoreFixture(
                inputs.oracle,
                inputs.recovered,
                inputs.boundary,
                inputs.identity,
                inputs.target,
            )
            val model = programModel(inputs.recovered.document)
            val bytes = model.toJson().toByteArray(Charsets.UTF_8)
            val binding = FixtureStructuralFindingJoinBindingV1.capture(bytes, score, inputs.target)

            val joined = StructuralRecoveryAssessmentJoinV1.joinFixture(bytes, score, inputs.target, binding)
            val population = StructuralRecoveryAssessmentJoinV1.summarizeFixture(joined)

            assertEquals("fixture-only", joined.authority)
            assertEquals("unassessed", joined.recoveryAssessmentState)
            assertEquals(binding.programModelSha256, joined.programModelSha256)
            assertEquals(binding.inputBinarySha256, joined.inputBinarySha256)
            assertTrue(joined.entities.all { it.recoveryAssessment == "unassessed" })
            assertTrue(joined.entities.any { it.outcomes.contains("recovered-unknown") })
            assertTrue(joined.entities.any { it.outcomes.contains("oracle-unobservable") })
            assertTrue(joined.entities.any { it.outcomes.contains("contradicted") })
            assertTrue(joined.entities.any { it.outcomes.contains("fabricated") })
            assertTrue(joined.entities.any { it.outcomes.contains("exact") })
            assertTrue(joined.entities.any { it.outcomes.contains("abi-equivalent") })
            assertTrue(joined.oracleOnlyEntities.isNotEmpty())
            assertTrue(joined.oracleOnlyEntities.any { row -> row.facts.any { it.getValue("outcome").jsonPrimitive.content == "recovered-unknown" } })
            assertEquals("fixture-only", population.authority)
            assertEquals("unassessed", population.recoveryAssessmentState)
            assertEquals(joined.entities.size, population.modelEntityCount)
            assertEquals(joined.entities.count { it.facts.isNotEmpty() }, population.entitiesWithFindings)
            assertEquals(joined.oracleOnlyEntities.size, population.oracleOnlyEntityCount)
            val expectedOutcomes = score.getValue("aggregate").jsonObject.getValue("outcomes").jsonObject
            expectedOutcomes.forEach { (outcome, total) ->
                assertEquals(total.jsonPrimitive.content.toInt(),
                    population.recoveredOutcomeCounts.getValue(outcome) +
                        population.oracleOnlyOutcomeCounts.getValue(outcome), outcome)
            }
            assertEquals(3, population.recoveredOutcomeCounts.getValue("fabricated"))
            assertEquals(2, population.recoveredOutcomeCounts.getValue("contradicted"))
            assertEquals("unassessed", population.toJson().getValue("recoveryAssessmentState").jsonPrimitive.content)

            val observedGlobal = joined.entities.single { it.kind == "global" && it.entityId == "recovered.global.900" }
            assertTrue(observedGlobal.facts.any {
                it.getValue("dimension").jsonPrimitive.content == "global.linkage" &&
                    it.getValue("slot").jsonPrimitive.content == "linkage" &&
                    it.getValue("outcome").jsonPrimitive.content == "contradicted"
            })
            val unobservablePrototype = joined.entities.single { it.entityId == "fn_0000000000400022" }
            assertTrue(unobservablePrototype.facts.any {
                it.getValue("dimension").jsonPrimitive.content == "function.prototype" &&
                    it.getValue("outcome").jsonPrimitive.content == "oracle-unobservable"
            })

            val typed = decompengine.project.ProgramModelJson.readCanonical(bytes)
            assertTrue(typed.toJson().toByteArray(Charsets.UTF_8).contentEquals(bytes))
            assertTrue(typed.functions.all { typed.isRecoveryUnresolved(it.status) })
            assertTrue(typed.globals.all { typed.isRecoveryUnresolved(it.status) })
            assertTrue(typed.types.all { typed.isRecoveryUnresolved(it.status) })
        }

    @Test
    fun `stale model or changed finding report is rejected against captured fixture binding`(): Unit =
        withStructuralFixture { fixture ->
            val inputs = fixture.load()
            val score = StructuralRecoveryV1.scoreFixture(
                inputs.oracle,
                inputs.recovered,
                inputs.boundary,
                inputs.identity,
                inputs.target,
            )
            val model = programModel(inputs.recovered.document)
            val originalBytes = model.toJson().toByteArray(Charsets.UTF_8)
            val binding = FixtureStructuralFindingJoinBindingV1.capture(originalBytes, score, inputs.target)

            val changedModelBytes = model.copy(
                functions = model.functions.mapIndexed { index, function ->
                    if (index == 0) function.copy(prototype = function.prototype + " /* changed */") else function
                },
            ).toJson().toByteArray(Charsets.UTF_8)
            assertFails {
                StructuralRecoveryAssessmentJoinV1.joinFixture(changedModelBytes, score, inputs.target, binding)
            }

            val changedReport = JsonObject(score + ("model" to JsonObject(
                score.getValue("model").jsonObject + ("id" to kotlinx.serialization.json.JsonPrimitive("other-model")),
            )))
            assertFails {
                StructuralRecoveryAssessmentJoinV1.joinFixture(originalBytes, changedReport, inputs.target, binding)
            }
        }

    @Test
    fun `model entities without a finding remain unassessed and rows cannot name absent entities`(): Unit =
        withStructuralFixture { fixture ->
            val inputs = fixture.load()
            val score = StructuralRecoveryV1.scoreFixture(
                inputs.oracle,
                inputs.recovered,
                inputs.boundary,
                inputs.identity,
                inputs.target,
            )
            val model = programModel(inputs.recovered.document).copy(
                functions = programModel(inputs.recovered.document).functions + RecoveredFunction(
                    id = "fn_without_finding",
                    name = "fn_without_finding",
                    address = 0x7fffUL,
                    prototype = "undefined8 fn_without_finding(void)",
                    status = RecoveryStatus.RECOVERED,
                ),
            )
            val bytes = model.toJson().toByteArray(Charsets.UTF_8)
            val binding = FixtureStructuralFindingJoinBindingV1.capture(bytes, score, inputs.target)

            val joined = StructuralRecoveryAssessmentJoinV1.joinFixture(bytes, score, inputs.target, binding)
            val missing = joined.entities.single { it.entityId == "fn_without_finding" }
            assertEquals("unassessed", missing.recoveryAssessment)
            assertTrue(missing.outcomes.isEmpty())
            val population = StructuralRecoveryAssessmentJoinV1.summarizeFixture(joined)
            assertTrue("function" to "fn_without_finding" in population.missingFindingEntities)
            assertEquals(joined.entities.size,
                population.entitiesWithFindings + population.missingFindingEntities.size)

            val entity = score.getValue("entities").jsonArray.first { it.jsonObject["recoveredId"] != null }
            val badEntities = JsonArray(score.getValue("entities").jsonArray.map { row ->
                if (row == entity) JsonObject(row.jsonObject + ("recoveredId" to kotlinx.serialization.json.JsonPrimitive("fn_absent")))
                else row
            })
            val mismatch = JsonObject(score + ("entities" to badEntities))
            assertFails {
                StructuralRecoveryAssessmentJoinV1.joinFixture(bytes, mismatch, inputs.target, binding)
            }
        }

    private fun programModel(recovered: JsonObject): RecoveredProgramModel {
        val provenance = recovered.getValue("provenance").jsonObject
        val inputSha256 = provenance.getValue("inputBinary").jsonObject.getValue("sha256").jsonPrimitive.content
        val entities = recovered.getValue("entities").jsonArray.map { it.jsonObject }
        val functions = entities.filter { it.getValue("kind").jsonPrimitive.content == "function" }
            .mapIndexed { index, entity ->
                val id = entity.getValue("id").jsonPrimitive.content
                RecoveredFunction(
                    id = id,
                    name = id,
                    address = id.substringAfterLast('_').toULong(16),
                    prototype = when {
                        id.endsWith("400010") -> "int $id(int)"
                        id.endsWith("400022") -> "uint64_t $id(void)"
                        id.endsWith("400040") -> "undefined8 $id(void)"
                        id.endsWith("400050") -> "void $id(void)"
                        else -> "uint64_t $id(void)"
                    },
                    calls = if (id.endsWith("400010")) setOf(
                        "fn_0000000000400022", "runtime.write", "signature:void-to-integer",
                    ) else emptySet(),
                    referencedGlobals = if (id.endsWith("400010")) setOf("recovered.global.900") else emptySet(),
                    status = RecoveryStatus.RECOVERED,
                )
            }
        val globals = entities.filter { it.getValue("kind").jsonPrimitive.content == "global" }
            .map { entity ->
                val id = entity.getValue("id").jsonPrimitive.content
                RecoveredGlobal(
                    id = id,
                    name = id,
                    address = if (id == "recovered.global.900") 0x400900UL else 0x400980UL,
                    type = "int",
                    status = RecoveryStatus.RECOVERED,
                )
            }
        val types = entities.filter { it.getValue("kind").jsonPrimitive.content == "type" }
            .map { entity ->
                val id = entity.getValue("id").jsonPrimitive.content
                RecoveredType(id = id, declaration = "typedef int ${id.replace('.', '_')};", status = RecoveryStatus.RECOVERED)
            }
        return RecoveredProgramModel(
            schemaVersion = 2,
            inputSha256 = inputSha256,
            functions = functions,
            globals = globals,
            types = types,
        )
    }
}
