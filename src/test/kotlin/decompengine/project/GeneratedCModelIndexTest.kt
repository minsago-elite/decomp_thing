package decompengine.project

import decompengine.repair.RepairResourceBudget
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class GeneratedCModelIndexTest {
    @Test
    fun `schema two preserves indexed ownership and dependencies without assessing recovery`() {
        val project = createTempDirectory("model-version-index-")
        val model = RecoveredProgramModel(
            inputSha256 = "a".repeat(64),
            functions = listOf(
                RecoveredFunction("entry", "main", 1u, "int main(void)", calls = setOf("helper")),
                RecoveredFunction("helper", "helper", 2u, "int helper(void)", referencedGlobals = setOf("global")),
            ),
            globals = listOf(RecoveredGlobal("global", "counter", 3u, "int")),
            types = listOf(RecoveredType("type", "typedef int counter_t;")),
        )
        SourceTreeGenerator.generate(model, project)
        val historical = GeneratedCRepairIndexProfile.resolve(project, RepairResourceBudget())
        SourceTreeGenerator.generate(model.copy(schemaVersion = 2), project)
        val current = GeneratedCRepairIndexProfile.resolve(project, RepairResourceBudget())
        // Evidence origins retain the source schema version, but schema migration must preserve
        // the resolved ownership and dependency layout used by repair planning.
        assertEquals(historical.sourcePaths, current.sourcePaths)
        assertEquals(historical.editablePaths, current.editablePaths)
        assertEquals(historical.modules, current.modules)
        assertEquals(historical.entities, current.entities)
        assertEquals(listOf("helper"), current.entities.single { it.id == "entry" }.dependencyEntityIds)
        assertEquals(listOf("global"), current.entities.single { it.id == "helper" }.dependencyEntityIds)
        val path = project.resolve("reports/program_model.json")
        val original = path.readText()
        for (claim in listOf("recovered", "abi-equivalent")) {
            path.writeText(original.replace("\"recoveryAssessment\": \"unassessed\"",
                "\"recoveryAssessment\": \"$claim\""))
            assertFailsWith<IllegalArgumentException> {
                GeneratedCRepairIndexProfile.resolve(project, RepairResourceBudget())
            }
        }
    }
}
