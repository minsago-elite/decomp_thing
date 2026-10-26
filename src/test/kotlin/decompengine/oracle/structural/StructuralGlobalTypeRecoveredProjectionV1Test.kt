package decompengine.oracle.structural

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonNull

class StructuralGlobalTypeRecoveredProjectionV1Test {
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
}
