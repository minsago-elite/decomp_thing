package decompengine.web

import decompengine.project.ModulePlan
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredGlobal
import decompengine.project.stableFunctionId
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.*

/** Graph adjacency, the population digest and the scorecard are charged to the cache entry that retains them. */
class WebStructureCacheChargeTest {
    private fun id(index: Int) = stableFunctionId(0x401000uL + index.toULong() * 16uL)

    /** Two revisions of one job with a call chain, globals and a three-module plan. */
    private fun populated(fixture: WebStructureFixture) {
        val functions = (0 until 120).map { index ->
            RecoveredFunction(id(index), "f$index", 0x401000uL + index.toULong() * 16uL, "void f$index(void)", null,
                calls = setOf(id((index + 1) % 120), id((index + 7) % 120), "fn_unrecorded_${index % 5}"),
                referencedGlobals = setOf("global_0000000000500000"))
        }
        val model = fixture.model(functions, listOf(RecoveredGlobal("global_0000000000500000", "g", 0x500000u, "int")))
        val plan = ModulePlan(modules = listOf(fixture.planned("core", (0 until 40).map(::id), listOf("global_0000000000500000")),
            fixture.planned("edge", (40 until 80).map(::id)), fixture.planned("rest", (80 until 120).map(::id))))
        fixture.revision("run_1", "revision_1", model, plan)
        fixture.revision("run_2", "revision_2", model, plan)
    }

    private fun read(fixture: WebStructureFixture, run: Int) =
        fixture.pages.functions("owner", fixture.jobId, "run_$run", "revision_$run", null)

    private fun derive(fixture: WebStructureFixture, run: Int) {
        val job = fixture.jobId
        fixture.pages.neighborhood(job, "run_$run", "revision_$run", "view=calls&focus=${id(0)}&depth=3")
        fixture.pages.neighborhood(job, "run_$run", "revision_$run", "view=modules&focus=core&depth=2")
        fixture.pages.scorecard("owner", job, "run_$run", "revision_$run", null)
        fixture.pages.comparison("owner", job, "run_$run", "revision_$run", "baselineRunId=run_$run&baselineRevisionId=revision_$run")
    }

    private fun WebProgramStructureCache.index(run: Int) = retained().singleOrNull { it.reference.runId == "run_$run" }
    private val derived = listOf("call-graph", "module-graph", "scorecard", "population-digest")

    /** Charged sizes of revision 1, revision 2 and revision 2's derived values, measured with ample ceilings. */
    private fun measure(): Triple<Long, Long, Long> {
        val probe = WebStructureFixture()
        populated(probe)
        read(probe, 1); val first = probe.cache.retainedBytes()
        read(probe, 2); val both = probe.cache.retainedBytes()
        derive(probe, 2)
        val charged = probe.cache.retainedBytes() - both
        assertTrue(charged > 0, "graph and scorecard reads must charge the retaining entry")
        assertTrue(derived.all { checkNotNull(probe.cache.index(2)).retainsDerived(it) })
        return Triple(first, both - first, charged)
    }

    @Test fun `derived reads on a populated cache stay within the retained ceiling by evicting the older entry`() {
        val (first, second, charged) = measure()
        // Both projections fit, but not both with revision 2's derived values.
        val ceiling = first + second + charged - 1
        val fixture = WebStructureFixture(WebProgramStructureCache(capacity = 2, maximumRetainedBytes = ceiling))
        populated(fixture)
        read(fixture, 1); read(fixture, 2)
        assertEquals(first + second, fixture.cache.retainedBytes())
        derive(fixture, 2)
        assertTrue(fixture.cache.retainedBytes() <= ceiling)
        assertNull(fixture.cache.index(1), "the least recently used entry is evicted to admit the charge")
        assertEquals(second + charged, fixture.cache.retainedBytes())
        assertTrue(derived.all { checkNotNull(fixture.cache.index(2)).retainsDerived(it) })
    }

    @Test fun `derived values beyond the entry ceiling are rebuilt instead of retained`() {
        val (_, second, _) = measure()
        val fixture = WebStructureFixture(WebProgramStructureCache(capacity = 2, maximumEntryBytes = second))
        populated(fixture)
        read(fixture, 2)
        derive(fixture, 2)
        val index = checkNotNull(fixture.cache.index(2))
        assertTrue(derived.none { index.retainsDerived(it) })
        assertEquals(second, fixture.cache.retainedBytes())
        // The reads still answer from request-local values.
        assertEquals("available", fixture.pages.scorecard("owner", fixture.jobId, "run_2", "revision_2", null)
            .getValue("confidence").jsonObject.getValue("state").jsonPrimitive.content)
    }
}
