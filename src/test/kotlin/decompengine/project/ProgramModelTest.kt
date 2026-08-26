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
        assertTrue(plan.toJson().contains("stable symbol/address grouping"))
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
