package decompengine.project

import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProfiledModulePlanningTest {
    @Test
    fun `default generation enforces profile planner bounds before writes`() {
        for (base in ReconstructionProfiles.builtIn) {
            for ((name, budgets) in structuralBounds(base.budgets)) {
                assertRejectedBeforeWrites(profile(base, budgets), null, name)
            }
        }
    }

    @Test
    fun `default generation follows profile module size and declared module paths`() {
        for (base in ReconstructionProfiles.builtIn) {
            val layout = changedLayout(base.layout, mapOf(
                "module-implementation" to "src/modules/planned_{module}.c",
                "module-interface" to "include/modules/planned_{module}.h",
            ))
            val selected = profile(base, base.budgets.copy(maximumFunctionsPerModule = 1), layout)
            val (project, plan) = generateAndReadPlan(selected)
            assertSingleFunctionOwnership(plan)
            for (module in plan.modules) {
                assertEquals("src/modules/planned_${module.id}.c", module.sourcePath)
                assertEquals("include/modules/planned_${module.id}.h", module.headerPath)
                assertTrue(project.resolve(module.sourcePath).exists())
                assertTrue(project.resolve(module.headerPath).exists())
                assertFalse(project.resolve("src/modules/${module.id}.c").exists())
                assertFalse(project.resolve("include/modules/${module.id}.h").exists())
            }
            val manifest = SourceTreeManifestReader.read(project, selected)
            assertEquals(plan.modules.map { it.sourcePath }.toSet(), manifest.files.filter {
                ProjectFileRole.MODULE_IMPLEMENTATION in it.roles
            }.map { it.path }.toSet())
            assertEquals(model().functions.map { it.id }.sorted(), manifest.unresolvedImplementationIds.sorted())
        }
    }

    @Test
    fun `supplied planners preserve stricter structural and module size limits`() {
        for (base in ReconstructionProfiles.builtIn) {
            for ((name, planner) in listOf(
                "entities" to DeterministicModulePlanner(maximumEntities = 2),
                "edges" to DeterministicModulePlanner(maximumDependencyEdges = 1),
                "work" to DeterministicModulePlanner(maximumWorkUnits = 1),
            )) {
                assertRejectedBeforeWrites(base, planner, name)
            }
            val selected = profile(base, base.budgets.copy(maximumFunctionsPerModule = 3))
            val (_, plan) = generateAndReadPlan(selected, DeterministicModulePlanner(maximumFunctionsPerModule = 1))
            assertSingleFunctionOwnership(plan)
        }
    }

    @Test
    fun `supplied planners cannot raise profile structural or module size limits`() {
        for (base in ReconstructionProfiles.builtIn) {
            for ((name, budgets) in structuralBounds(base.budgets)) {
                assertRejectedBeforeWrites(profile(base, budgets), DeterministicModulePlanner(), name)
            }
            val selected = profile(base, base.budgets.copy(maximumFunctionsPerModule = 1))
            val (_, plan) = generateAndReadPlan(selected, DeterministicModulePlanner(maximumFunctionsPerModule = 3))
            assertSingleFunctionOwnership(plan)
        }
    }

    @Test
    fun `supplied planner module declarations must match before writes`() {
        for (base in ReconstructionProfiles.builtIn) {
            for ((declaration, path) in mapOf(
                "module-implementation" to "src/modules/foreign_{module}.c",
                "module-interface" to "include/modules/foreign_{module}.h",
            )) {
                val planner = DeterministicModulePlanner(layout = changedLayout(base.layout, mapOf(declaration to path)))
                assertRejectedBeforeWrites(base, planner, declaration)
            }
        }
    }

    private fun assertRejectedBeforeWrites(
        profile: ReconstructionProfile,
        planner: DeterministicModulePlanner?,
        label: String,
    ) {
        val project = createTempDirectory("profile-planning-rejected-").resolve("project")
        var calls = 0
        assertFailsWith<IllegalArgumentException>(label) {
            SourceTreeGenerator.generate(model(), project, planner = planner, profile = profile,
                reconstructor = ModuleReconstructor { calls++; error("planning must fail before reconstruction") })
        }
        assertEquals(0, calls, label)
        assertFalse(project.exists(), label)
    }

    private fun generateAndReadPlan(
        profile: ReconstructionProfile,
        planner: DeterministicModulePlanner? = null,
    ): Pair<Path, ModulePlan> {
        val project = createTempDirectory("profile-planning-generated-").resolve("project")
        val requestedModules = mutableListOf<PlannedModule>()
        // Keep implementations explicitly unresolved: these checks cover planning and ownership, not builds.
        SourceTreeGenerator.generate(model(), project, planner = planner, profile = profile,
            reconstructor = ModuleReconstructor { request ->
                requestedModules += request.module
                EvidenceModuleReconstructor().reconstruct(request)
            })
        val plan = ModulePlanJson.readCanonical(project.resolve(
            profile.layout.declaration("module-plan-evidence").materialize(),
        ).readBytes(), 64 * 1024)
        assertEquals(plan.modules.sortedBy { it.id }, requestedModules.sortedBy { it.id })
        return project to plan
    }

    private fun assertSingleFunctionOwnership(plan: ModulePlan) {
        assertEquals(3, plan.modules.size)
        assertTrue(plan.modules.all { it.functionIds.size == 1 })
        assertEquals(model().functions.map { it.id }.sorted(), plan.modules.flatMap { it.functionIds }.sorted())
    }

    private fun structuralBounds(budgets: ReconstructionBudgets) = listOf(
        "entities" to budgets.copy(plannerMaximumEntities = 2),
        "edges" to budgets.copy(plannerMaximumDependencyEdges = 1),
        "work" to budgets.copy(plannerMaximumWorkUnits = 1),
    )

    private fun profile(base: ReconstructionProfile, budgets: ReconstructionBudgets,
        layout: ProjectLayoutProfile = base.layout) = ReconstructionProfile(
        base.schemaVersion, base.id, layout, budgets, base.adapterConfiguration,
    )

    private fun changedLayout(layout: ProjectLayoutProfile, paths: Map<String, String>) = ProjectLayoutProfile(
        layout.schemaVersion,
        layout.declarations.map { declaration ->
            ProjectFileDeclaration(declaration.id, paths[declaration.id] ?: declaration.pathTemplate,
                declaration.roles, declaration.contentKind)
        },
    )

    private fun model() = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
        RecoveredFunction("fn_alpha", "unit_alpha", 0x1000UL, "int unit_alpha(void)", calls = setOf("fn_beta")),
        RecoveredFunction("fn_beta", "unit_beta", 0x2000UL, "int unit_beta(void)", calls = setOf("fn_gamma")),
        RecoveredFunction("fn_gamma", "unit_gamma", 0x3000UL, "int unit_gamma(void)"),
    ))
}
