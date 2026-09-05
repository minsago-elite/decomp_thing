package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

class ModulePlanJsonTest {
    private val layout = GeneratedCMakeReconstructionProfile.descriptor.layout
    private val model = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
        RecoveredFunction("f1", "alpha_first", 1u, "void alpha_first(void)", calls = setOf("f2")),
        RecoveredFunction("f2", "beta_second", 2u, "void beta_second(void)", calls = setOf("f1")),
    ), globals = listOf(RecoveredGlobal("g", "counter", 3u, "int")),
        types = listOf(RecoveredType("t", "typedef int number;")))
    private val plan = DeterministicModulePlanner(1, layout).plan(model)

    @Test
    fun `canonical planner output preserves ownership cycles and escaped evidence`() {
        val withEvidence = plan.copy(modules = plan.modules.map {
            it.copy(boundaryEvidence = it.boundaryEvidence + "braces {[ and quote \" and slash \\")
        })
        val bytes = withEvidence.toJson().toByteArray()
        val parsed = ModulePlanJson.readCanonical(bytes, bytes.size)
        assertEquals(withEvidence, parsed)
        ModulePlanJson.requireExactOwnership(parsed, model, layout, 1)
        val empty = model.copy(functions = emptyList(), globals = emptyList(), types = emptyList())
        ModulePlanJson.requireExactOwnership(DeterministicModulePlanner().plan(empty), empty, layout, 1)
    }

    @Test
    fun `reject noncanonical schema types fields ordering encodings and excessive nesting`() {
        val text = plan.toJson()
        listOf(text + " ", text.replace("\"schemaVersion\": 2", "\"schemaVersion\": \"2\""),
            text.replace("\"schemaVersion\": 2", "\"schemaVersion\": 1"),
            text.replace("\"schemaVersion\": 2", "\"extra\": 0, \"schemaVersion\": 2"),
            text.replace("\"schemaVersion\": 2", "\"schemaVersion\": 2, \"schemaVersion\": 2"),
            text.replace("\"f1\"", "1"),
            "[".repeat(10000) + "]".repeat(10000),
            text.replace("\"modules\": [", "\"modules\": [null,"),
        ).forEach { invalid -> assertFails { ModulePlanJson.readCanonical(invalid.toByteArray(), 1024 * 1024) } }
        val bytes = text.toByteArray()
        assertFails { ModulePlanJson.readCanonical(bytes, bytes.size - 1) }
        assertFails { ModulePlanJson.readCanonical(bytes + byteArrayOf(0xc0.toByte()), 1024 * 1024) }
    }

    @Test
    fun `reject missing invented duplicate ownership and layout substitution`() {
        fun changed(transform: (PlannedModule) -> PlannedModule) = plan.copy(
            modules = listOf(transform(plan.modules.first())) + plan.modules.drop(1))
        val ownerGlobal = plan.modules.indexOfFirst { it.globalIds.isNotEmpty() }
        val ownerType = plan.modules.indexOfFirst { it.typeIds.isNotEmpty() }
        val invalid = listOf(
            changed { it.copy(functionIds = emptyList()) },
            changed { it.copy(functionIds = listOf("unknown")) },
            changed { it.copy(functionIds = it.functionIds + it.functionIds) },
            plan.copy(modules = plan.modules + plan.modules.first()),
            changed { it.copy(sourcePath = "../outside.c") },
            changed { it.copy(headerPath = it.sourcePath) },
            plan.copy(modules = plan.modules.mapIndexed { i, module ->
                if (i == ownerGlobal) module.copy(globalIds = emptyList()) else module }),
            plan.copy(modules = plan.modules.mapIndexed { i, module ->
                if (i == ownerType) module.copy(typeIds = module.typeIds + module.typeIds) else module }),
            changed { it.copy(globalIds = it.globalIds + "invented") },
            changed { it.copy(typeIds = it.typeIds + "invented") },
        )
        invalid.forEach { candidate ->
            // These have canonical bytes: format checks alone cannot establish ownership.
            val parsed = ModulePlanJson.readCanonical(candidate.toJson().toByteArray(), 1024 * 1024)
            assertFails { ModulePlanJson.requireExactOwnership(parsed, model, layout, 10) }
        }
    }

    @Test
    fun `reject invalid cycle references and function population ceiling`() {
        val ids = plan.modules.map { it.id }
        listOf(listOf(listOf(ids.first())), listOf(listOf(ids.first(), "unknown")),
            listOf(ids, ids), listOf(listOf(ids.first(), ids.first())), listOf(ids.reversed())).forEach { cycles ->
            assertFails { ModulePlanJson.requireExactOwnership(plan.copy(dependencyCycles = cycles), model, layout, 1) }
        }
        val oneModule = plan.modules.first().copy(functionIds = listOf("f1", "f2"), globalIds = listOf("g"), typeIds = listOf("t"))
        assertFails { ModulePlanJson.requireExactOwnership(ModulePlan(modules = listOf(oneModule)), model, layout, 1) }
    }
}
