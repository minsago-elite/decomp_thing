package decompengine.oracle.structural

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.math.BigInteger
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class StructuralGlobalTypeRecoveredProjectionV1Test {
    @Test
    fun `projection roundtrips through fixture loader and existing scorer`() {
        withStructuralFixture { fixture ->
            val inputs = fixture.load()
            val recoveredPath = fixture.path("recovered.json")
            val recoveredDocument = parseProjectionTestObject(recoveredPath)
            val originalEntities = recoveredDocument.getValue("entities") as JsonArray
            val observations = originalEntities.mapNotNull { raw ->
                val entity = raw as JsonObject
                val key = entity.projectionEntityKey()
                val facts = (entity.getValue("facts") as JsonArray).map { it as JsonObject }
                val selectedFacts = facts.filter { fact ->
                    val dimension = (fact.getValue("dimension") as JsonPrimitive).content
                    key.kind in setOf("global", "type") || (key.kind == "function" && dimension == "global.reference")
                }
                if (selectedFacts.isEmpty() || key.kind !in setOf("global", "type", "function")) return@mapNotNull null
                StructuralRecoveredEntityObservationV1(key.kind, key.id, selectedFacts.map(::toProjectionObservation))
            }
            val projection = StructuralGlobalTypeRecoveredProjectionV1.project(observations, inputs.target)
            assertTrue(projection.allInputEntitiesProjectable)
            val candidateEntities = projection.requireAllInputEntitiesProjectableForFixtureScoring()
            val projectedByKey = candidateEntities.associateBy { (it as JsonObject).projectionEntityKey() }
            val mergedEntities = originalEntities.map { raw ->
                val original = raw as JsonObject
                val key = original.projectionEntityKey()
                val candidate = projectedByKey[key] as? JsonObject
                when {
                    key.kind in setOf("global", "type") && candidate != null -> candidate
                    key.kind == "function" && candidate != null -> {
                        val oldFacts = original.getValue("facts") as JsonArray
                        val kept = oldFacts.filterNot { fact ->
                            (fact as JsonObject).getValue("dimension") == JsonPrimitive("global.reference")
                        }
                        JsonObject(original + ("facts" to JsonArray(kept + (candidate.getValue("facts") as JsonArray))))
                    }
                    else -> original
                }
            }
            val changedDocument = JsonObject(recoveredDocument + ("entities" to JsonArray(mergedEntities)))
            writeProjectionTestCanonical(recoveredPath, reattestProjectionTest(changedDocument))

            val recovered = StructuralRecoveryV1Inputs.loadFixtureRecoveredStructure(
                recoveredPath,
                inputs.target,
                inputs.oracle,
                inputs.boundary,
                inputs.identity,
            )
            val report = StructuralRecoveryV1.scoreFixture(
                inputs.oracle,
                recovered,
                inputs.boundary,
                inputs.identity,
                inputs.target,
            )
            val aggregate = report.getValue("aggregate") as JsonObject
            val outcomes = aggregate.getValue("outcomes") as JsonObject
            assertEquals(14, outcomes.requiredProjectionInt("exact"))
            assertEquals(4, outcomes.requiredProjectionInt("abi-equivalent"))
            assertEquals(3, outcomes.requiredProjectionInt("recovered-unknown"))
            assertEquals(1, outcomes.requiredProjectionInt("oracle-unobservable"))
            assertEquals(2, outcomes.requiredProjectionInt("contradicted"))
            assertEquals(3, outcomes.requiredProjectionInt("fabricated"))
            val dimensions = report.getValue("dimensions") as JsonArray
            listOf("global.reference", "global.storage", "global.linkage", "global.type", "type.aggregate.kind")
                .forEach { dimension ->
                    val row = dimensions.map { it as JsonObject }.single {
                        it.getValue("dimension") == JsonPrimitive(dimension)
                    }
                    assertTrue((row.getValue("oracleDenominator") as JsonPrimitive).content.toInt() > 0, dimension)
                }
            Unit
        }
    }

    @Test
    fun `typed G T and function global-reference rows project deterministically and conserve zero-fact census`() =
        withStructuralFixture { fixture ->
            val target = fixture.load().target
            val rows = listOf(
                StructuralRecoveredEntityObservationV1(
                    "global", "g:data", listOf(
                        observation("global.storage", "storage", StructuralRecoveredSourceV1.Text("static-rva:0x900")).copy(
                            evidence = listOf(
                                StructuralRecoveredEvidenceV1("capture", "z-last"),
                                StructuralRecoveredEvidenceV1("capture", "a-first"),
                            ),
                        ),
                        observation("global.linkage", "linkage", StructuralRecoveredSourceV1.Text("external")),
                    ),
                ),
                StructuralRecoveredEntityObservationV1(
                    "type", "t:packet", listOf(
                        observation("type.aggregate.kind", "aggregate-kind", StructuralRecoveredSourceV1.Text("record")),
                        observation("type.aggregate.size-bits", "aggregate-size", StructuralRecoveredSourceV1.Integer(BigInteger.ZERO),
                            state = StructuralRecoveredFactStateV1.RECOVERED_UNKNOWN),
                    ),
                ),
                StructuralRecoveredEntityObservationV1(
                    "function", "fn:reader", listOf(
                        observation("global.reference", "global-ref:0x128", StructuralRecoveredSourceV1.Text("global:g:data")),
                    ),
                ),
                StructuralRecoveredEntityObservationV1("global", "g:empty", emptyList()),
            )

            val projected = StructuralGlobalTypeRecoveredProjectionV1.project(rows, target)
            val reversed = StructuralGlobalTypeRecoveredProjectionV1.project(rows.reversed(), target)

            assertEquals(3, projected.projectedEntities.size)
            assertEquals(listOf(StructuralEntityKey("global", "g:empty")), projected.unprojectableEntityKeys)
            assertEquals(4, projected.inputEntityKeys.size)
            assertTrue(projected.entityCensusConserved)
            assertFalse(projected.allInputEntitiesProjectable)
            assertFailsWith<IllegalArgumentException> { projected.requireAllInputEntitiesProjectableForFixtureScoring() }
            assertEquals(projected.projectedEntities, reversed.projectedEntities)
            assertEquals(
                "function",
                ((projected.projectedEntities.first() as kotlinx.serialization.json.JsonObject).getValue("kind") as kotlinx.serialization.json.JsonPrimitive).content,
            )
        }

    @Test
    fun `projection rejects unrelated function facts`() {
        withStructuralFixture { fixture ->
            val target = fixture.load().target
            val empty = StructuralGlobalTypeRecoveredProjectionV1.project(emptyList(), target)
            assertFalse(empty.allInputEntitiesProjectable)
            assertFailsWith<IllegalArgumentException> { empty.requireAllInputEntitiesProjectableForFixtureScoring() }
            assertFailsWith<IllegalArgumentException> {
                StructuralGlobalTypeRecoveredProjectionV1.project(
                    listOf(StructuralRecoveredEntityObservationV1("function", "fn:1", listOf(
                        observation("function.prototype", "prototype", StructuralRecoveredSourceV1.Text("prototype:u64-from-void")),
                    ))),
                    target,
                )
            }
            assertFailsWith<IllegalArgumentException> {
                StructuralGlobalTypeRecoveredProjectionV1.project(
                    listOf(StructuralRecoveredEntityObservationV1("global", "g:escaped", listOf(
                        observation("global.storage", "storage", StructuralRecoveredSourceV1.Text("x".repeat(40))),
                    ))),
                    target,
                    StructuralRecoveryV1Limits(maximumProjectedReportBytes = 256),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                StructuralGlobalTypeRecoveredProjectionV1.project(
                    listOf(StructuralRecoveredEntityObservationV1("type", "t:huge", listOf(
                        observation("type.enum.enumerator-value", "enumerator:HUGE", StructuralRecoveredSourceV1.Integer(BigInteger.ONE.shiftLeft(1_000))),
                    ))),
                    target,
                    StructuralRecoveryV1Limits(maximumJsonNumberCharacters = 16),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                StructuralGlobalTypeRecoveredProjectionV1.project(
                    listOf(StructuralRecoveredEntityObservationV1("global", "g:bad-utf16", listOf(
                        observation("global.storage", "storage", StructuralRecoveredSourceV1.Text("\uD800")),
                    ))),
                    target,
                )
            }
        }
    }

    private fun observation(
        dimension: String,
        slot: String,
        source: StructuralRecoveredSourceV1,
        state: StructuralRecoveredFactStateV1 = StructuralRecoveredFactStateV1.RECOVERED,
    ) = StructuralRecoveredFactObservationV1(
        dimension = dimension,
        slot = slot,
        state = state,
        value = if (state == StructuralRecoveredFactStateV1.RECOVERED) source else null,
        abi = JsonNull,
        evidence = listOf(StructuralRecoveredEvidenceV1("capture", "typed:$dimension:$slot")),
    )

    private data class ProjectionEntityKey(val kind: String, val id: String)

    private fun JsonObject.projectionEntityKey() = ProjectionEntityKey(
        (getValue("kind") as JsonPrimitive).content,
        (getValue("id") as JsonPrimitive).content,
    )

    private fun JsonObject.requiredProjectionInt(name: String): Int = (getValue(name) as JsonPrimitive).content.toInt()

    private fun toProjectionObservation(fact: JsonObject): StructuralRecoveredFactObservationV1 {
        val dimension = (fact.getValue("dimension") as JsonPrimitive).content
        val slot = (fact.getValue("slot") as JsonPrimitive).content
        val state = when ((fact.getValue("state") as JsonPrimitive).content) {
            "recovered" -> StructuralRecoveredFactStateV1.RECOVERED
            "recovered-unknown" -> StructuralRecoveredFactStateV1.RECOVERED_UNKNOWN
            else -> error("fixture has unsupported recovered state")
        }
        val rawValue = fact.getValue("value")
        val source = if (rawValue == JsonNull) null else {
            val sourceValue = (rawValue as JsonObject).getValue("source") as JsonPrimitive
            when {
                sourceValue.isString -> StructuralRecoveredSourceV1.Text(sourceValue.content)
                sourceValue.content == "true" || sourceValue.content == "false" ->
                    StructuralRecoveredSourceV1.BooleanValue(sourceValue.content.toBoolean())
                else -> StructuralRecoveredSourceV1.Integer(BigInteger(sourceValue.content))
            }
        }
        val abi = if (rawValue == JsonNull) JsonNull else (rawValue as JsonObject).getValue("abi")
        val evidence = (fact.getValue("evidence") as JsonArray).map { raw ->
            val row = raw as JsonObject
            StructuralRecoveredEvidenceV1(
                (row.getValue("kind") as JsonPrimitive).content,
                (row.getValue("locator") as JsonPrimitive).content,
            )
        }
        return StructuralRecoveredFactObservationV1(dimension, slot, state, source, abi, evidence)
    }

    private fun parseProjectionTestObject(path: java.nio.file.Path): JsonObject =
        OracleJson.parse(Files.readAllBytes(path), PROJECTION_TEST_JSON_LIMITS) as JsonObject

    private fun writeProjectionTestCanonical(path: java.nio.file.Path, document: JsonObject) {
        Files.write(path, OracleJson.canonicalBytes(document, PROJECTION_TEST_JSON_LIMITS))
        setPermissions(path, "rw-------")
    }

    private fun reattestProjectionTest(document: JsonObject): JsonObject {
        val payloadSha256 = fixturePayloadSha256(document, 64 * 1024 * 1024)
        val attestation = document.getValue("attestation") as JsonObject
        return JsonObject(document + ("attestation" to JsonObject(attestation + ("payloadSha256" to JsonPrimitive(payloadSha256)))))
    }

    private companion object {
        val PROJECTION_TEST_JSON_LIMITS = StrictJsonLimits(
            maximumInputBytes = 64 * 1024 * 1024,
            maximumCanonicalBytes = 64 * 1024 * 1024,
            maximumDepth = 128,
            maximumNodes = 1_000_000,
            maximumStringBytes = 1024 * 1024,
            maximumTotalStringBytes = 64 * 1024 * 1024,
            maximumNumberCharacters = 128,
        )
    }
}
