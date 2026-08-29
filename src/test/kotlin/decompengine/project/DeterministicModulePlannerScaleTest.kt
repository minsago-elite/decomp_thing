package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.measureTime

class DeterministicModulePlannerScaleTest {
    @Test
    fun `sparse planner work tracks evidence entries instead of function pairs`() {
        val small = DeterministicModulePlanner().planWithComplexity(sparseModel(functionCount = 512, globalCount = 256))
        val large = DeterministicModulePlanner().planWithComplexity(sparseModel(functionCount = 4_096, globalCount = 2_048))

        assertTrue(
            large.complexity.sparseWorkUnits <= small.complexity.sparseWorkUnits * 9,
            "eightfold input growth expanded indexed work from ${small.complexity.sparseWorkUnits} " +
                "to ${large.complexity.sparseWorkUnits}",
        )
        assertTrue(
            large.complexity.sparseWorkUnits < 100L * (large.complexity.functionCount + large.complexity.globalCount),
            "sparse work unexpectedly approached the entity-pair search space: ${large.complexity}",
        )
    }

    @Test
    fun `gcc-sized sparse model meets planning budget with exact ownership`() {
        val model = sparseModel(functionCount = 2_524, globalCount = 1_389)
        lateinit var run: IndexedPlannerRun

        val elapsed = measureTime {
            run = DeterministicModulePlanner().planWithComplexity(model)
        }

        assertTrue(elapsed < 120.seconds, "GCC-sized synthetic plan took $elapsed")
        assertEquals(model.functions.map { it.id }.sorted(), run.plan.modules.flatMap { it.functionIds }.sorted())
        assertEquals(model.globals.map { it.id }.sorted(), run.plan.modules.flatMap { it.globalIds }.sorted())
        assertTrue(run.plan.modules.all { it.functionIds.isEmpty() || it.boundaryEvidence.isNotEmpty() })
        assertTrue(
            run.complexity.indexedEvidenceEntries < 20L * (model.functions.size + model.globals.size),
            "planner retained more than sparse evidence indexes: ${run.complexity}",
        )
    }

    @Test
    fun `planner fails closed at every profile supplied structural bound`() {
        val model = sparseModel(functionCount = 8, globalCount = 4)
        val dependencyEdges = model.functions.sumOf { it.calls.size.toLong() + it.referencedGlobals.size }

        assertFailsWith<IllegalArgumentException> {
            DeterministicModulePlanner(maximumEntities = 11).plan(model)
        }
        assertFailsWith<IllegalArgumentException> {
            DeterministicModulePlanner(maximumDependencyEdges = dependencyEdges - 1).plan(model)
        }
        assertFailsWith<IllegalArgumentException> {
            DeterministicModulePlanner(maximumWorkUnits = 1).plan(model)
        }
    }

    private fun sparseModel(functionCount: Int, globalCount: Int): RecoveredProgramModel {
        require(functionCount > 0 && functionCount % 2 == 0)
        val pairCount = functionCount / 2
        val functions = buildList {
            repeat(pairCount) { index ->
                val namedId = "named_$index"
                val anonymousId = "anonymous_$index"
                val globalId = "global_${index % globalCount}"
                val marker = "marker_$index"
                add(
                    RecoveredFunction(
                        id = namedId,
                        name = "module${index.toString().padStart(5, '0')}_entry",
                        address = (index * 2).toULong(),
                        prototype = "int entry_$index(void)",
                        calls = setOf(anonymousId),
                        referencedGlobals = setOf(globalId),
                        strings = setOf(marker),
                    ),
                )
                add(
                    RecoveredFunction(
                        id = anonymousId,
                        name = "FUN_${(index * 2 + 1).toString(16)}",
                        address = (index * 2 + 1).toULong(),
                        prototype = "int anonymous_$index(void)",
                        calls = buildSet {
                            add(namedId)
                            if (index + 1 < pairCount) add("anonymous_${index + 1}")
                        },
                        referencedGlobals = setOf(globalId),
                        strings = setOf(marker),
                    ),
                )
            }
        }
        val globals = List(globalCount) { index ->
            RecoveredGlobal(
                id = "global_$index",
                name = "global_$index",
                address = (0x100000UL + index.toULong()),
                type = "int",
            )
        }
        return RecoveredProgramModel(inputSha256 = "sparse-$functionCount-$globalCount", functions = functions, globals = globals)
    }
}
