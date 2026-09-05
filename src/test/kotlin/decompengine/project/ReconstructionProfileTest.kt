package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class ReconstructionProfileTest {
    @Test
    fun `canonical profile digest is stable across collection order`() {
        val original = GeneratedCMakeReconstructionProfile.descriptor
        val reversedConfiguration = linkedMapOf<String, List<String>>().apply {
            original.adapterConfiguration.entries.reversed().forEach { (key, value) -> put(key, value.reversed().reversed()) }
        }
        val rebuilt = ReconstructionProfile(
            schemaVersion = original.schemaVersion,
            id = original.id,
            layout = ProjectLayoutProfile(original.layout.schemaVersion, original.layout.declarations.reversed()),
            budgets = original.budgets.copy(),
            adapterConfiguration = reversedConfiguration,
        )

        assertEquals(original.canonicalJson(), rebuilt.canonicalJson())
        assertEquals(original.sha256, rebuilt.sha256)
        assertEquals("a448a139a09f28ad9f2e08bfcebcb9d85765a0a557ebb11db6d7634bc145f28f", original.sha256)
        assertTrue(original.sha256.matches(Regex("[0-9a-f]{64}")))
        assertNotEquals(
            original.sha256,
            ReconstructionProfile(
                schemaVersion = original.schemaVersion,
                id = original.id,
                layout = original.layout,
                budgets = original.budgets.copy(buildWallClockMillis = original.budgets.buildWallClockMillis + 1),
                adapterConfiguration = original.adapterConfiguration,
            ).sha256,
        )
    }

    @Test
    fun `profile construction takes immutable snapshots of caller collections`() {
        val mutableRoles = mutableSetOf(ProjectFileRole.EVIDENCE, ProjectFileRole.VIEWABLE)
        val declaration = ProjectFileDeclaration(
            id = "record",
            pathTemplate = "records/{unit}.txt",
            roles = mutableRoles,
            contentKind = ProjectContentKind.UTF8_TEXT,
        )
        val mutableDeclarations = mutableListOf(declaration)
        val layout = ProjectLayoutProfile(ProjectLayoutProfile.CURRENT_SCHEMA_VERSION, mutableDeclarations)
        val mutableValues = mutableListOf("one", "two")
        val mutableConfiguration = mutableMapOf("adapter.values" to mutableValues)
        val profile = ReconstructionProfile(
            ReconstructionProfile.CURRENT_SCHEMA_VERSION,
            "immutable-fixture-v1",
            layout,
            budgets(),
            mutableConfiguration,
        )

        mutableRoles.clear()
        mutableDeclarations.clear()
        mutableValues.clear()
        mutableConfiguration.clear()

        assertEquals(setOf(ProjectFileRole.EVIDENCE, ProjectFileRole.VIEWABLE), declaration.roles)
        assertEquals(listOf(declaration), profile.layout.declarations)
        assertEquals(listOf("one", "two"), profile.adapterConfiguration.getValue("adapter.values"))
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (declaration.roles as MutableSet<ProjectFileRole>).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (profile.layout.declarations as MutableList<ProjectFileDeclaration>).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (profile.adapterConfiguration as MutableMap<String, List<String>>).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (profile.adapterConfiguration.getValue("adapter.values") as MutableList<String>).clear()
        }
    }

    @Test
    fun `layout rejects malformed paths roles and template parameters`() {
        assertFailsWith<IllegalArgumentException> {
            ProjectFileDeclaration("record", "../record.txt", setOf(ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT)
        }
        assertFailsWith<IllegalArgumentException> {
            ProjectFileDeclaration("record", "/record.txt", setOf(ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT)
        }
        assertFailsWith<IllegalArgumentException> {
            ProjectFileDeclaration("record", "records/{unit}/{unit}.txt", setOf(ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT)
        }
        assertFailsWith<IllegalArgumentException> {
            ProjectFileDeclaration("record", "record.txt", emptySet(), ProjectContentKind.UTF8_TEXT)
        }
        assertFailsWith<IllegalArgumentException> {
            ProjectFileDeclaration("record", "record.bin", setOf(ProjectFileRole.EDITABLE), ProjectContentKind.BINARY)
        }

        val declaration = ProjectFileDeclaration(
            "record",
            "records/{unit}.txt",
            setOf(ProjectFileRole.EVIDENCE),
            ProjectContentKind.UTF8_TEXT,
        )
        assertEquals("records/alpha.txt", declaration.materialize(mapOf("unit" to "alpha")))
        assertFailsWith<IllegalArgumentException> { declaration.materialize(mapOf("unit" to "../escape")) }
        assertFailsWith<IllegalArgumentException> {
            ProjectLayoutProfile(ProjectLayoutProfile.CURRENT_SCHEMA_VERSION, listOf(declaration, declaration))
        }
    }

    @Test
    fun `host safety contract rejects a profile request above any ceiling`() {
        val requested = budgets()
        val host = ReconstructionHostSafetyLimits(requested)
        host.requireAllows(requested)

        val rejected = listOf(
            requested.copy(exportWallClockMillis = requested.exportWallClockMillis + 1),
            requested.copy(exportMaximumResidentBytes = requested.exportMaximumResidentBytes + 1),
            requested.copy(plannerMaximumEntities = requested.plannerMaximumEntities + 1),
            requested.copy(plannerMaximumDependencyEdges = requested.plannerMaximumDependencyEdges + 1),
            requested.copy(plannerMaximumWorkUnits = requested.plannerMaximumWorkUnits + 1),
            requested.copy(maximumFunctionsPerModule = requested.maximumFunctionsPerModule + 1),
            requested.copy(
                reconstructionMaximumContextCharacters = requested.reconstructionMaximumContextCharacters + 1,
            ),
            requested.copy(buildWallClockMillis = requested.buildWallClockMillis + 1),
            requested.copy(buildMaximumOutputBytes = requested.buildMaximumOutputBytes + 1),
            requested.copy(archiveMaximumEntries = requested.archiveMaximumEntries + 1),
            requested.copy(archiveMaximumFileBytes = requested.archiveMaximumFileBytes + 1),
            requested.copy(archiveMaximumTotalBytes = requested.archiveMaximumTotalBytes + 1),
        )
        rejected.forEach { overLimit ->
            assertFailsWith<IllegalArgumentException> { host.requireAllows(overLimit) }
        }
    }

    @Test
    fun `planner honours declared non-C source paths`() {
        val rustLayout = ProjectLayoutProfile(
            ProjectLayoutProfile.CURRENT_SCHEMA_VERSION,
            listOf(
                ProjectFileDeclaration("shared-interface", "src/lib.rs", setOf(ProjectFileRole.PUBLIC_INTERFACE, ProjectFileRole.VIEWABLE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("module-interface", "src/modules/{module}.rs", setOf(ProjectFileRole.PUBLIC_INTERFACE, ProjectFileRole.VIEWABLE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("module-private-interface", "src/modules/{module}_internal.rs", setOf(ProjectFileRole.PRIVATE_INTERFACE, ProjectFileRole.VIEWABLE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("module-implementation", "src/modules/{module}.rs.impl", setOf(ProjectFileRole.MODULE_IMPLEMENTATION, ProjectFileRole.VIEWABLE, ProjectFileRole.EDITABLE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("entrypoint-implementation", "src/main.rs", setOf(ProjectFileRole.ENTRYPOINT_IMPLEMENTATION, ProjectFileRole.VIEWABLE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("build-definition", "Cargo.toml", setOf(ProjectFileRole.BUILD_DEFINITION, ProjectFileRole.VIEWABLE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("program-model-evidence", "reports/program_model.json", setOf(ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("module-plan-evidence", "reports/module_plan.json", setOf(ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("module-evidence", "reports/modules/{module}.json", setOf(ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("confidence-evidence", "reports/confidence.json", setOf(ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("toolchain-evidence", "reports/toolchain.json", setOf(ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("unresolved-evidence", "UNRESOLVED.md", setOf(ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT),
            ),
        )
        val budgets = budgets()
        val profile = ReconstructionProfile(ReconstructionProfile.CURRENT_SCHEMA_VERSION, "rust-test-v1", rustLayout, budgets)
        val planner = DeterministicModulePlanner(maximumFunctionsPerModule = 8, layout = profile.layout)
        val model = RecoveredProgramModel(
            inputSha256 = "a".repeat(64),
            functions = listOf(
                RecoveredFunction(id = "fn_a", name = "fn_a", address = 0x1000u, prototype = "void fn_a()", decompiledC = "void fn_a() {}", calls = emptySet(), referencedGlobals = emptySet(), strings = emptySet(), status = RecoveryStatus.RECOVERED),
                RecoveredFunction(id = "fn_b", name = "fn_b", address = 0x1010u, prototype = "void fn_b()", decompiledC = "void fn_b() {}", calls = setOf("fn_a"), referencedGlobals = emptySet(), strings = emptySet(), status = RecoveryStatus.RECOVERED),
            ),
            globals = emptyList(),
            types = emptyList(),
        )
        val plan = planner.plan(model)
        assertTrue(plan.modules.isNotEmpty())
        plan.modules.forEach { module ->
            assertTrue(module.sourcePath.endsWith(".rs.impl"))
            assertTrue(module.headerPath.endsWith(".rs"))
        }
    }

    private fun budgets() = ReconstructionBudgets(
        exportWallClockMillis = 1_000,
        exportMaximumResidentBytes = 1_024,
        plannerMaximumEntities = 100,
        plannerMaximumDependencyEdges = 200,
        plannerMaximumWorkUnits = 300,
        maximumFunctionsPerModule = 10,
        reconstructionMaximumContextCharacters = 4_096,
        buildWallClockMillis = 2_000,
        buildMaximumOutputBytes = 8_192,
        archiveMaximumEntries = 100,
        archiveMaximumFileBytes = 16_384,
        archiveMaximumTotalBytes = 32_768,
    )
}
