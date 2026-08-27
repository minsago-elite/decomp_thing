package decompengine.project

/** Explicit adapter descriptor for the generated-C project assembled with GNU Make. */
object GeneratedCMakeReconstructionProfile {
    const val PROFILE_ID = "generated-c-make-v1"

    val descriptor = ReconstructionProfile(
        schemaVersion = ReconstructionProfile.CURRENT_SCHEMA_VERSION,
        id = PROFILE_ID,
        layout = ProjectLayoutProfile(
            schemaVersion = ProjectLayoutProfile.CURRENT_SCHEMA_VERSION,
            declarations = listOf(
                textFile(
                    "shared-interface",
                    "include/decomp_types.h",
                    ProjectFileRole.PUBLIC_INTERFACE,
                    ProjectFileRole.BUILD_INPUT,
                    ProjectFileRole.EDITABLE,
                ),
                textFile(
                    "module-interface",
                    "include/modules/{module}.h",
                    ProjectFileRole.PUBLIC_INTERFACE,
                    ProjectFileRole.BUILD_INPUT,
                    ProjectFileRole.EDITABLE,
                ),
                textFile(
                    "module-private-interface",
                    "src/modules/{module}_internal.h",
                    ProjectFileRole.PRIVATE_INTERFACE,
                    ProjectFileRole.BUILD_INPUT,
                    ProjectFileRole.EDITABLE,
                ),
                textFile(
                    "module-implementation",
                    "src/modules/{module}.c",
                    ProjectFileRole.MODULE_IMPLEMENTATION,
                    ProjectFileRole.BUILD_INPUT,
                    ProjectFileRole.EDITABLE,
                ),
                textFile(
                    "entrypoint-implementation",
                    "src/main.c",
                    ProjectFileRole.ENTRYPOINT_IMPLEMENTATION,
                    ProjectFileRole.BUILD_INPUT,
                    ProjectFileRole.EDITABLE,
                ),
                textFile(
                    "build-definition",
                    "Makefile",
                    ProjectFileRole.BUILD_DEFINITION,
                    ProjectFileRole.BUILD_INPUT,
                    ProjectFileRole.EDITABLE,
                ),
                textFile("module-evidence", "reports/modules/{module}.json", ProjectFileRole.EVIDENCE),
                textFile("program-model-evidence", "reports/program_model.json", ProjectFileRole.EVIDENCE),
                textFile("module-plan-evidence", "reports/module_plan.json", ProjectFileRole.EVIDENCE),
                textFile("confidence-evidence", "reports/confidence.json", ProjectFileRole.EVIDENCE),
                textFile("toolchain-evidence", "reports/toolchain.json", ProjectFileRole.EVIDENCE),
                textFile("unresolved-evidence", "UNRESOLVED.md", ProjectFileRole.EVIDENCE),
            ),
        ),
        budgets = ReconstructionBudgets(
            exportWallClockMillis = 10L * 60 * 1_000,
            exportMaximumResidentBytes = 4L * 1024 * 1024 * 1024,
            plannerMaximumEntities = 250_000,
            plannerMaximumDependencyEdges = 2_000_000,
            plannerMaximumWorkUnits = 50_000_000,
            maximumFunctionsPerModule = 24,
            reconstructionMaximumContextCharacters = 120_000,
            buildWallClockMillis = 10L * 60 * 1_000,
            buildMaximumOutputBytes = 32L * 1024 * 1024,
            archiveMaximumEntries = 100_000,
            archiveMaximumFileBytes = 128L * 1024 * 1024,
            archiveMaximumTotalBytes = 1024L * 1024 * 1024,
        ),
        adapterConfiguration = mapOf(
            "build-system" to listOf("gnu-make"),
            "build-executable" to listOf("make"),
            "compiler-driver" to listOf("cc"),
            "compiler-flags" to listOf("-std=c11", "-g", "-Wall", "-Wextra", "-Werror", "-Iinclude"),
            "entry-symbol-candidates" to listOf("main", "decomp_engine_main", "entry", "recovered__start"),
            "source-language" to listOf("c11"),
        ),
    )

    private fun textFile(
        id: String,
        pathTemplate: String,
        vararg specificRoles: ProjectFileRole,
    ) = ProjectFileDeclaration(
        id = id,
        pathTemplate = pathTemplate,
        roles = specificRoles.toSet() + setOf(ProjectFileRole.VIEWABLE, ProjectFileRole.ARCHIVE_PAYLOAD),
        contentKind = ProjectContentKind.UTF8_TEXT,
    )
}
