package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ProgramModelTest {
    @Test
    fun `program model JSON is deterministic and retains provenance`() {
        val model = fixtureModel()

        val first = model.toJson()
        val second = model.copy(functions = model.functions.reversed()).toJson()

        assertEquals(first, second)
        assertTrue(first.contains("\"address\": \"0x401000\""))
        assertTrue(first.contains("\"calls\": [\"fn_0000000000401020\"]"))
        assertTrue(first.contains("\"status\": \"partial\""))
    }

    @Test
    fun `planner assigns every entity once and honors overrides`() {
        val model = fixtureModel()
        val plan = DeterministicModulePlanner(maximumFunctionsPerModule = 1).plan(
            model,
            overrides = mapOf("fn_0000000000401020" to "User Interface"),
        )

        assertEquals(model.functions.map { it.id }.sorted(), plan.modules.flatMap { it.functionIds }.sorted())
        assertEquals(model.globals.map { it.id }.sorted(), plan.modules.flatMap { it.globalIds }.sorted())
        assertEquals("user_interface", plan.modules.single { "fn_0000000000401020" in it.functionIds }.id)
        assertTrue(plan.toJson().contains("symbol prefix"))
        assertTrue(plan.toJson().contains("user override"))
    }

    @Test
    fun `planner rejects overrides for unknown entities`() {
        assertFailsWith<IllegalArgumentException> {
            DeterministicModulePlanner().plan(fixtureModel(), mapOf("missing" to "core"))
        }
    }

    @Test
    fun `planner diagnoses cross-module dependency cycles`() {
        val first = RecoveredFunction("fn_1", "parse_one", 1UL, "int parse_one(void)", calls = setOf("fn_2"))
        val second = RecoveredFunction("fn_2", "render_two", 2UL, "int render_two(void)", calls = setOf("fn_1"))

        val plan = DeterministicModulePlanner().plan(RecoveredProgramModel(inputSha256 = "cycle", functions = listOf(first, second)))

        assertEquals(listOf(listOf("parse", "render")), plan.dependencyCycles)
        assertTrue(plan.toJson().contains("dependencyCycles"))
    }

    @Test
    fun `program model parser rejects schema drift and missing entity arrays`() {
        assertFailsWith<IllegalArgumentException> {
            ProgramModelJson.read("{\"schemaVersion\":2,\"inputSha256\":\"x\",\"functions\":[],\"globals\":[],\"types\":[]}")
        }
        assertFailsWith<NoSuchElementException> {
            ProgramModelJson.read("{\"schemaVersion\":1,\"inputSha256\":\"x\",\"functions\":[]}")
        }
    }

    @Test
    fun `symbol-bearing and stripped naming remain deterministic`() {
        val named = fixtureModel()
        val stripped = named.copy(functions = named.functions.map { it.copy(name = "FUN_${it.address.toString(16)}") })

        assertEquals(named.toJson(), ProgramModelJson.read(named.toJson()).toJson())
        assertEquals(stripped.toJson(), ProgramModelJson.read(stripped.toJson()).toJson())
        assertTrue(stripped.functions.all { it.id == stableFunctionId(it.address) })
    }

    @Test
    fun `anonymous functions use call graph shared data and string affinity`() {
        val parse = RecoveredFunction("fn_10", "parse_input", 0x10UL, "int parse_input(void)", strings = setOf("token"))
        val render = RecoveredFunction("fn_20", "render_page", 0x20UL, "int render_page(void)", referencedGlobals = setOf("global_ui"))
        val byCall = RecoveredFunction("fn_30", "FUN_30", 0x30UL, "int FUN_30(void)", calls = setOf("fn_10"))
        val byData = RecoveredFunction("fn_40", "FUN_40", 0x40UL, "int FUN_40(void)", referencedGlobals = setOf("global_ui"))
        val byString = RecoveredFunction("fn_50", "FUN_50", 0x50UL, "int FUN_50(void)", strings = setOf("token"))
        val model = RecoveredProgramModel(inputSha256 = "affinity", functions = listOf(parse, render, byCall, byData, byString))

        val plan = DeterministicModulePlanner().plan(model)

        assertTrue("fn_30" in plan.modules.single { it.id == "parse" }.functionIds)
        assertTrue("fn_40" in plan.modules.single { it.id == "render" }.functionIds)
        assertTrue("fn_50" in plan.modules.single { it.id == "parse" }.functionIds)
        assertTrue(plan.modules.single { it.id == "parse" }.boundaryEvidence.any { "call-graph affinity" in it })
        assertTrue(plan.modules.single { it.id == "render" }.boundaryEvidence.any { "shared globals" in it })
    }

    @Test
    fun `indexed affinity retains per-function weights and deterministic tie breaks`() {
        val parseFirst = RecoveredFunction(
            "fn_10",
            "parse_first",
            0x10UL,
            "int parse_first(void)",
            referencedGlobals = setOf("shared", "parse_only"),
            strings = setOf("marker"),
        )
        val parseSecond = RecoveredFunction(
            "fn_20",
            "parse_second",
            0x20UL,
            "int parse_second(void)",
            referencedGlobals = setOf("shared"),
            strings = setOf("marker"),
        )
        val render = RecoveredFunction(
            "fn_30",
            "render_page",
            0x30UL,
            "int render_page(void)",
            calls = setOf("fn_40"),
        )
        val anonymous = RecoveredFunction(
            "fn_40",
            "FUN_40",
            0x40UL,
            "int FUN_40(void)",
            calls = setOf("fn_30"),
            referencedGlobals = setOf("parse_only", "shared"),
            strings = setOf("marker"),
        )
        val model = RecoveredProgramModel(
            inputSha256 = "weighted-affinity",
            functions = listOf(anonymous, render, parseSecond, parseFirst),
        )

        val forward = DeterministicModulePlanner().plan(model)
        val reversed = DeterministicModulePlanner().plan(model.copy(functions = model.functions.reversed()))

        assertEquals(forward, reversed)
        val parseModule = forward.modules.single { "fn_40" in it.functionIds }
        assertEquals("parse", parseModule.id)
        assertTrue(
            parseModule.boundaryEvidence.any {
                "shared globals with parse: parse_only,shared" in it &&
                    "shared globals with parse: shared" in it &&
                    "shared strings with parse" in it
            },
        )
    }

    @Test
    fun `global-only overrides create owned modules instead of dropping globals`() {
        val global = RecoveredGlobal("global_10", "counter", 0x10UL, "int")
        val model = RecoveredProgramModel(inputSha256 = "global-override", functions = emptyList(), globals = listOf(global))

        val plan = DeterministicModulePlanner().plan(model, mapOf(global.id to "Runtime State"))

        assertEquals(listOf(global.id), plan.modules.flatMap { it.globalIds })
        assertEquals("runtime_state", plan.modules.single { global.id in it.globalIds }.id)
    }

    @Test
    fun `dependency diagnostics collapse overlapping cycles into one sparse component`() {
        val functions = listOf(
            RecoveredFunction("fn_1", "alpha_one", 1UL, "void alpha_one(void)", calls = setOf("fn_2", "fn_3")),
            RecoveredFunction("fn_2", "bravo_two", 2UL, "void bravo_two(void)", calls = setOf("fn_1", "fn_3")),
            RecoveredFunction("fn_3", "charlie_three", 3UL, "void charlie_three(void)", calls = setOf("fn_1")),
        )

        val plan = DeterministicModulePlanner().plan(RecoveredProgramModel(inputSha256 = "scc", functions = functions))

        assertEquals(listOf(listOf("alpha", "bravo", "charlie")), plan.dependencyCycles)
    }

    private fun fixtureModel() = RecoveredProgramModel(
        inputSha256 = "abc123",
        functions = listOf(
            RecoveredFunction(
                id = "fn_0000000000401020",
                name = "render_page",
                address = 0x401020UL,
                prototype = "int render_page(void)",
                referencedGlobals = setOf("global_404000"),
                status = RecoveryStatus.PARTIAL,
            ),
            RecoveredFunction(
                id = "fn_0000000000401000",
                name = "parse_input",
                address = 0x401000UL,
                prototype = "int parse_input(void)",
                calls = setOf("fn_0000000000401020"),
            ),
        ),
        globals = listOf(RecoveredGlobal("global_404000", "page_count", 0x404000UL, "int")),
    )
}
