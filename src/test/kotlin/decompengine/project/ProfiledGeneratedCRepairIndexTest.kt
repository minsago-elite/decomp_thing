package decompengine.project

import decompengine.repair.load
import decompengine.repair.open
import decompengine.repair.ModuleRepairIndex
import decompengine.repair.ModuleRevisionGraph
import decompengine.repair.RepairResourceBudget
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class ProfiledGeneratedCRepairIndexTest {
    private fun profile(base: ReconstructionProfile) = ReconstructionProfile(
        base.schemaVersion, base.id,
        ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map {
            val path = when (it.id) {
                "module-plan-evidence" -> "reports/planning/modules.json"
                "program-model-evidence" -> "reports/inputs/model.json"
                else -> it.pathTemplate
            }
            ProjectFileDeclaration(it.id, path,
                if (it.id in setOf("shared-interface", "module-interface")) it.roles - ProjectFileRole.EDITABLE else it.roles, it.contentKind)
        }), base.budgets, base.adapterConfiguration,
    )

    @Test
    fun `Make and Ninja index declared evidence and recover the same graph`() {
        for (base in ReconstructionProfiles.builtIn) {
            val descriptor = profile(base)
            val profile = GeneratedCRepairIndexProfile.forProfile(descriptor)
            val project = createTempDirectory("profile-repair-index-")
            SourceTreeGenerator.generate(RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
                RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)", calls = setOf("fn_beta")),
                RecoveredFunction("fn_beta", "beta_read", 0x2000UL, "int beta_read(void)"),
            )), project, profile = descriptor)
            project.resolve("src/unlisted.c").writeText("/* authored read-only auxiliary input */\n")
            val index = ModuleRepairIndex.load(project, profile)
            val buildDefinition = descriptor.layout.declaration("build-definition").materialize()
            assertTrue(buildDefinition in index.sourcePaths)
            assertTrue(buildDefinition in index.editablePaths)
            assertFalse("include/decomp_types.h" in index.editablePaths)
            assertFalse("src/unlisted.c" in index.editablePaths)
            val selection = index.select("compile", "src/modules/alpha.c:1: error: authored diagnostic")
            assertEquals(listOf("alpha"), selection.seedModules)
            assertEquals(listOf("beta"), selection.dependencyModules)
            assertTrue("include/modules/beta.h" in selection.readablePaths)
            assertFalse("include/decomp_types.h" in selection.writablePaths)
            assertTrue("include/modules/alpha.h" in selection.readablePaths)
            assertFalse("include/modules/alpha.h" in selection.writablePaths)
            assertTrue(profile.authorizesRecoveryLayout(index.sourcePaths, index.editablePaths.sorted(), RepairResourceBudget()))
            val target = project.resolve("src/modules/alpha.c")
            val accepted = target.readBytes()
            val candidate = accepted + "\n/* pending authored revision */\n".toByteArray()
            ModuleRevisionGraph.open(project, profile).use { graph ->
                val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
                graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
            }
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            val before = graphPath.readBytes()
            val changed = GeneratedCRepairIndexProfile.forProfile(base)
            assertFalse(changed.configurationSha256() == profile.configurationSha256())
            val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(project, changed) }
            assertTrue(failure.message.orEmpty().contains("profile fingerprint differs"))
            assertContentEquals(candidate, target.readBytes())
            assertContentEquals(before, graphPath.readBytes())
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile.forProfile(descriptor)).use { recovered ->
                assertContentEquals(accepted, target.readBytes())
                assertEquals(null, recovered.snapshot.pendingAttemptId)
            }
        }
    }

    @Test
    fun `unregistered repair descriptors are rejected at construction`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        assertFailsWith<IllegalArgumentException> {
            GeneratedCRepairIndexProfile.forProfile(ReconstructionProfile(base.schemaVersion, "unregistered-repair-v1",
                base.layout, base.budgets, base.adapterConfiguration))
        }
    }
}
