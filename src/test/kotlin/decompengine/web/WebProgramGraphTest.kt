package decompengine.web

import decompengine.project.*
import kotlinx.serialization.json.*
import kotlin.test.*

/** Bounded call and module-dependency neighborhoods over synthetic recorded graphs. */
class WebProgramGraphTest {
    private val fixture = WebStructureFixture()
    private val run = "run_1"
    private val revision = "revision_1"

    private fun id(index: Int) = stableFunctionId(0x401000uL + index.toULong() * 16uL)
    private fun function(index: Int, vararg calls: Int, extra: Set<String> = emptySet(), globals: Set<String> = emptySet(),
        status: RecoveryStatus = RecoveryStatus.RECOVERED) =
        RecoveredFunction(id(index), "f$index", 0x401000uL + index.toULong() * 16uL, "void f$index(void)", null,
            calls = calls.map(::id).toSet() + extra, referencedGlobals = globals, status = status)

    private fun read(query: String): JsonObject =
        fixture.pages.neighborhood(fixture.jobId, run, revision, query).also { fixture.assertContract("structureNeighborhood", it) }

    private fun JsonObject.neighborhood() = getValue("neighborhood").jsonObject
    private fun JsonObject.nodes() = neighborhood().getValue("nodes").jsonArray.map { it.jsonObject }
    private fun JsonObject.edges() = neighborhood().getValue("edges").jsonArray.map { it.jsonObject }
    private fun JsonObject.completeness() = neighborhood().getValue("completeness").jsonObject
    private fun JsonObject.int(name: String) = getValue(name).jsonPrimitive.intOrNull
    private fun JsonObject.text(name: String) = getValue(name).jsonPrimitive.contentOrNull
    private fun JsonObject.entity(index: Int) = nodes().single { it.text("entityId") == id(index) }

    /** Cycle 0→1→2→0, a self call on 3, an isolated 4, a hub 5 with many callers and callees, and an unrecorded target. */
    private fun standard() {
        val callers = (100 until 400).map { function(it, 5) }
        val callees = (400 until 600).map { function(it) }
        val model = fixture.model(listOf(function(0, 1), function(1, 2, status = RecoveryStatus.PARTIAL), function(2, 0),
            function(3, 3), function(4), function(5, *IntArray(200) { 400 + it }), function(6, 0, extra = setOf("fn_missing"))) + callers + callees)
        fixture.revision(run, revision, model, ModulePlan(modules = listOf(fixture.planned("core", model.functions.map { it.id }))))
    }

    @Test fun `cycles keep every recorded edge once and report a complete neighborhood`() {
        standard()
        val page = read("view=calls&focus=${id(0)}&depth=2")
        assertEquals("available", page.text("graphState"))
        assertEquals(setOf(id(0), id(1), id(2), id(6), "fn_missing"), page.nodes().map { it.text("entityId") }.toSet())
        assertEquals(0, page.nodes().first().int("depth"))
        val ids = page.nodes().map { it.text("entityId") }
        assertEquals(setOf(id(0) to id(1), id(1) to id(2), id(2) to id(0), id(6) to id(0), id(6) to "fn_missing"),
            page.edges().map { ids[it.int("source")!!] to ids[it.int("target")!!] }.toSet())
        val completeness = page.completeness()
        assertEquals("complete", completeness.text("state")); assertEquals(0, completeness.int("omittedNodes")); assertEquals(0, completeness.int("omittedEdges"))
        assertEquals(5, completeness.int("reachableNodes")); assertEquals(5, completeness.int("reachableEdges"))
        // Recorded semantics: partial extraction stays inferred; the call kind is explicitly not recorded.
        assertEquals("inferred", page.entity(1).text("evidenceState"))
        val families = page.getValue("relationships").jsonArray.associate { it.jsonObject.text("id") to it.jsonObject.text("state") }
        assertEquals("not-recorded", families["call-kind"]); assertEquals("not-recorded", families["external-call"])
        assertEquals("available", families["unrecorded-call-target"])
        val unrecorded = page.nodes().single { it.text("entityId") == "fn_missing" }
        assertEquals("unrecorded-function", unrecorded.text("kind")); assertNull(unrecorded.text("selector"))
        assertEquals("no-record", page.edges().single { ids[it.int("target")!!] == "fn_missing" }.text("resolution"))
        // A self call is one edge whose source and target are the same node.
        val recursive = read("view=calls&focus=${id(3)}")
        assertEquals(1, recursive.nodes().size); assertEquals(listOf(0 to 0), recursive.edges().map { it.int("source") to it.int("target") })
    }

    @Test fun `disconnected entities and direction filters stay explicit`() {
        standard()
        val isolated = read("view=calls&focus=${id(4)}&depth=3")
        assertEquals(1, isolated.nodes().size); assertTrue(isolated.edges().isEmpty())
        assertEquals("complete", isolated.completeness().text("state")); assertEquals(0, isolated.completeness().int("edgesBeyondDepth"))
        val outgoing = read("view=calls&focus=${id(0)}&direction=outgoing")
        assertEquals(listOf(id(0), id(1)), outgoing.nodes().map { it.text("entityId") })
        // The graph continues past depth 1 and the focus has two callers outside the requested direction.
        assertEquals(1, outgoing.completeness().int("edgesBeyondDepth"))
        assertEquals(2, outgoing.nodes().first().getValue("incoming").jsonObject.int("total"))
        val excluded = read("view=calls&focus=${id(6)}&unresolved=omit")
        assertTrue(excluded.nodes().none { it.text("kind") == "unrecorded-function" })
        assertEquals(1, excluded.completeness().int("filteredEdges"))
    }

    @Test fun `high degree hubs truncate with exact omitted counts`() {
        standard()
        val page = read("view=calls&focus=${id(5)}&nodeLimit=50&edgeLimit=30")
        val completeness = page.completeness()
        assertEquals("truncated", completeness.text("state"))
        assertEquals(listOf("NODE_LIMIT", "EDGE_LIMIT"), completeness.getValue("reasons").jsonArray.map { it.jsonPrimitive.content })
        assertEquals(501, completeness.int("reachableNodes")); assertEquals(451, completeness.int("omittedNodes"))
        assertEquals(500, completeness.int("reachableEdges")); assertEquals(470, completeness.int("omittedEdges"))
        assertEquals(50, page.nodes().size); assertEquals(30, page.edges().size)
        val hub = page.nodes().first()
        assertEquals(200, hub.getValue("outgoing").jsonObject.int("total")); assertEquals(300, hub.getValue("incoming").jsonObject.int("total"))
        val shown = hub.getValue("outgoing").jsonObject.int("shown")!! + hub.getValue("incoming").jsonObject.int("shown")!!
        assertEquals(30, shown)
        // Every included edge is incident to the focus, nearest relationships first.
        assertTrue(page.edges().all { it.int("source") == 0 || it.int("target") == 0 })
    }

    @Test fun `long recorded identities shrink the neighborhood to its byte budget and say so`() {
        val long = (1..199).map { index ->
            RecoveredFunction("fn_${"%04d".format(index)}_${"x".repeat(4000)}", "n".repeat(4000) + index, 0x500000uL + index.toULong() * 16uL,
                "void f(void)", null)
        }
        val model = fixture.model(listOf(function(0, extra = long.map { it.id }.toSet())) + long)
        fixture.revision(run, revision, model, ModulePlan(modules = listOf(fixture.planned("core", model.functions.map { it.id }))))
        val page = read("view=calls&focus=${id(0)}&nodeLimit=200&edgeLimit=400")
        assertTrue(page.toString().toByteArray().size < 1_048_576)
        val completeness = page.completeness()
        assertEquals("truncated", completeness.text("state"))
        assertEquals(listOf("BYTE_LIMIT"), completeness.getValue("reasons").jsonArray.map { it.jsonPrimitive.content })
        assertEquals(100, page.nodes().size); assertEquals(99, page.edges().size)
        assertEquals(200, completeness.int("reachableNodes")); assertEquals(100, completeness.int("omittedNodes"))
        assertEquals(100, completeness.int("omittedEdges"))
    }

    @Test fun `exploration beyond the visit bound reports unknown totals`() {
        standard()
        read("view=calls&focus=${id(5)}")
        val index = fixture.cache.retained().single()
        val graph = index.callGraph
        val bounded = WebGraphNeighborhood.of(graph, index.table(WebStructureKind.FUNCTION).index.getValue(id(5)), 3, true, true,
            40, 40, maximumVisits = 100)
        assertEquals(listOf("VISIT_LIMIT", "NODE_LIMIT", "EDGE_LIMIT").take(bounded.reasons.size), bounded.reasons)
        assertNull(bounded.reachableNodes); assertNull(bounded.reachableEdges); assertNull(bounded.edgesBeyondDepth)
        assertTrue(bounded.nodes.size <= 40 && bounded.edges.size <= 40)
    }

    @Test fun `module dependencies derive from recorded calls and ownership with unattributed references counted`() {
        val model = fixture.model(listOf(function(0, 2, globals = setOf("global_0000000000500000")), function(1, 2), function(2, 3),
            function(3, 0, extra = setOf("fn_missing")), function(4, 0)),
            listOf(RecoveredGlobal("global_0000000000500000", "g", 0x500000u, "int")))
        fixture.revision(run, revision, model, ModulePlan(modules = listOf(fixture.planned("alpha", listOf(id(0), id(1))),
            fixture.planned("beta", listOf(id(2))), fixture.planned("gamma", listOf(id(3)), listOf("global_0000000000500000"))),
            dependencyCycles = listOf(listOf("alpha", "beta", "gamma"))))
        val page = read("view=modules&focus=alpha&depth=2")
        val ids = page.nodes().map { it.text("moduleId") }
        assertEquals(listOf("alpha", "beta", "gamma"), ids)
        val edges = page.edges().associate { (ids[it.int("source")!!] to ids[it.int("target")!!]) to it }
        assertEquals(2, edges.getValue("alpha" to "beta").int("references"))
        assertEquals("module-global-reference", page.edges().single { ids[it.int("target")!!] == "gamma" && ids[it.int("source")!!] == "alpha" }.text("relationship"))
        assertTrue(page.edges().all { it.getValue("recordedCycle").jsonPrimitive.boolean })
        // gamma's call to an unrecorded target and the unowned function 4 are counted, never assigned to a module.
        assertEquals(1, page.nodes().single { it.text("moduleId") == "gamma" }.int("unattributedReferences"))
        assertEquals("not-recorded", page.getValue("relationships").jsonArray.map { it.jsonObject }.single { it.text("id") == "call-kind" }.text("state"))
        assertNotNull(page.nodes().first().text("implementationFileId"))
    }

    @Test fun `unavailable records never yield an empty successful graph`() {
        fixture.revision(run, revision, null, null)
        val missing = read("view=calls&focus=${id(0)}")
        assertEquals("not-recorded", missing.text("graphState")); assertEquals(JsonNull, missing.getValue("neighborhood"))
        val model = fixture.model(listOf(function(0)))
        fixture.revision("run_2", "revision_2", model, null)
        val unplanned = fixture.pages.neighborhood(fixture.jobId, "run_2", "revision_2", "view=modules&focus=core")
        fixture.assertContract("structureNeighborhood", unplanned)
        assertEquals("not-recorded", unplanned.text("graphState")); assertEquals("PLAN_NOT_RECORDED", unplanned.text("graphReason"))
    }

    @Test fun `limits focus and pins are validated`() {
        standard()
        for (query in listOf("view=calls", "view=calls&focus=${id(0)}&depth=4", "view=calls&focus=${id(0)}&nodeLimit=201",
            "view=calls&focus=${id(0)}&edgeLimit=0", "view=modules&focus=core&unresolved=omit", "view=other&focus=${id(0)}",
            "view=calls&focus=${id(0)}&direction=sideways", "view=calls&focus=${id(0)}&limit=5")) {
            assertEquals("VALIDATION_FAILED", assertFailsWith<WebAccessDenied>(query) { read(query) }.code, query)
        }
        assertEquals("ENTITY_NOT_FOUND", assertFailsWith<WebAccessDenied> { read("view=calls&focus=fn_unknown") }.code)
        assertEquals("MODULE_NOT_FOUND", assertFailsWith<WebAccessDenied> { read("view=modules&focus=missing") }.code)
        assertEquals("STRUCTURE_CHANGED", assertFailsWith<WebAccessDenied> {
            read("view=calls&focus=${id(0)}&structureVersion=${"0".repeat(64)}")
        }.code)
    }

    @Test fun `a 100000 function call graph answers bounded neighborhoods within budget`() {
        val count = 100_000
        val functions = (0 until count).map { index ->
            // A ring with a hub every 1000 functions; function 0 is called by every hub.
            function(index, (index + 1) % count, *(if (index % 1000 == 0) intArrayOf(0) else IntArray(0)))
        }
        val model = fixture.model(functions)
        fixture.revision(run, revision, model, ModulePlan(modules = functions.chunked(24).mapIndexed { index, chunk -> fixture.planned("module_$index", chunk.map { it.id }) }))
        fixture.pages.functions("owner", fixture.jobId, run, revision, "limit=1")
        var started = System.nanoTime()
        val first = read("view=calls&focus=${id(0)}&depth=3&nodeLimit=200&edgeLimit=400")
        val firstMs = (System.nanoTime() - started) / 1_000_000
        started = System.nanoTime()
        val modules = read("view=modules&focus=module_0&depth=2")
        val moduleMs = (System.nanoTime() - started) / 1_000_000
        val warm = (1..10).map {
            started = System.nanoTime(); read("view=calls&focus=${id(it * 997)}&depth=3"); (System.nanoTime() - started) / 1_000_000
        }.sorted()
        println("program-graph-scale functions=$count firstGraphMs=$firstMs moduleGraphMs=$moduleMs warmP50Ms=${warm[5]} " +
            "bytes=${first.toString().length} reachable=${first.completeness().int("reachableNodes")}")
        assertTrue(first.nodes().size <= 200 && first.edges().size <= 400 && first.toString().length < 1_000_000)
        assertTrue(modules.nodes().isNotEmpty())
        assertTrue(firstMs < 1_000 && warm[5] < 500, "graph latency first=$firstMs warm=$warm")
    }
}
