package decompengine.project

import decompengine.analysis.GhidraJvmAnalyzer
import decompengine.jobs.elfFixture
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.isExecutable
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

class ProfiledReconstructionPipelineTest {
    @Test
    fun `pipeline carries the admitted profile through export generation and build`() {
        for (base in ReconstructionProfiles.builtIn) {
            val root = createTempDirectory("profiled-pipeline-")
            try {
                val bytes = elfFixture()
                val binary = root.resolve("authored.elf").also { it.writeBytes(bytes) }
                val work = root.resolve("work")
                val budgets = base.budgets.copy(
                    exportWallClockMillis = 1_234,
                    exportMaximumResidentBytes = 64L * 1024 * 1024,
                    maximumFunctionsPerModule = 1,
                    reconstructionMaximumContextCharacters = 120_001,
                    buildWallClockMillis = 30_000,
                    buildMaximumOutputBytes = 1024 * 1024,
                )
                val profile = profile(base, budgets)
                val analyzer = RecordingAnalyzer(model(sha256(bytes)))
                val reconstructionProfiles = mutableListOf<String>()
                val reconstructor = ModuleReconstructor { request ->
                    reconstructionProfiles += request.profile.sha256
                    RecoveredCModuleReconstructor().reconstruct(request)
                }

                val report = ReconstructionPipeline(GhidraJvmAnalyzer(analyzer)).generate(
                    binary, work, profile,
                    hostSafetyLimits = ReconstructionHostSafetyLimits(budgets), reconstructor = reconstructor,
                )

                assertEquals(listOf(budgets), analyzer.bindings)
                assertEquals(listOf(binary to work.resolve("analysis")), analyzer.calls)
                assertEquals(listOf(profile.sha256, profile.sha256), reconstructionProfiles)
                assertEquals(work.resolve("project"), report.projectDir)
                assertEquals(0, report.returnCode)
                assertEquals(profile.adapterConfiguration.getValue("build-executable").single(), report.command.first())
                val buildDefinition = profile.layout.declaration("build-definition").materialize()
                assertTrue(report.projectDir.resolve(buildDefinition).exists())
                if (base.id == GeneratedCNinjaReconstructionProfile.PROFILE_ID) {
                    assertFalse(report.projectDir.resolve("Makefile").exists())
                }
                assertTrue(report.projectDir.resolve("build/reconstructed").isExecutable())
                val manifest = SourceTreeManifestReader.read(report.projectDir, profile)
                assertEquals(profile.sha256, manifest.profileSha256)
                assertTrue(manifest.unresolvedImplementationIds.isEmpty())
                val planPath = profile.layout.declaration("module-plan-evidence").materialize()
                val plan = Json.parseToJsonElement(report.projectDir.resolve(planPath).readText()).jsonObject
                assertEquals(2, plan.getValue("modules").jsonArray.size)
                val contract = Json.parseToJsonElement(report.projectDir.resolve("reports/build_contract.json").readText()).jsonObject
                assertEquals(budgets.buildWallClockMillis, contract.getValue("wallClockTimeoutMillis").jsonPrimitive.long)
                assertEquals(budgets.buildMaximumOutputBytes, contract.getValue("maximumOutputBytes").jsonPrimitive.long)
                assertTrue(report.projectDir.resolve("reports/unresolved.json").exists())
            } finally {
                root.toFile().deleteRecursively()
            }
        }
    }

    @Test
    fun `pipeline admits host budgets before binding analysis or creating output`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val requested = profile(base, base.budgets.copy(
            exportWallClockMillis = ReconstructionHostSafetyLimits.DEFAULT.maximum.exportWallClockMillis + 1,
        ))
        assertRejectedBeforeBinding(requested, "host safety limit")
    }

    @Test
    fun `pipeline resolves a registered adapter before binding analysis or creating output`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val requested = ReconstructionProfile(base.schemaVersion, "unregistered-fixture", base.layout,
            base.budgets, base.adapterConfiguration)
        assertRejectedBeforeBinding(requested, "no reconstruction adapter registered")
    }

    @Test
    fun `profile pipeline rejects an analyzer without export budget support before writes`() {
        val root = createTempDirectory("profiled-pipeline-unsupported-")
        try {
            var called = false
            val analyzer = GhidraJvmAnalyzer { _, _ ->
                called = true
                error("unsupported analyzer must not start")
            }
            val work = root.resolve("work")

            val failure = assertFailsWith<IllegalArgumentException> {
                ReconstructionPipeline(analyzer).generate(root.resolve("unused-input"), work,
                    GeneratedCMakeReconstructionProfile.descriptor)
            }

            assertTrue(failure.message.orEmpty().contains("cannot apply reconstruction export budgets"))
            assertFalse(called)
            assertFalse(work.exists())
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `direct profile generation admits host budgets before creating report directories`() {
        val root = createTempDirectory("profiled-generator-admission-")
        try {
            val bytes = elfFixture()
            val binary = root.resolve("authored.elf").also { it.writeBytes(bytes) }
            val analysis = GhidraJvmAnalyzer { _, _ -> model(sha256(bytes)) }.analyze(binary, root.resolve("analysis"))
            val base = GeneratedCNinjaReconstructionProfile.descriptor
            val requested = profile(base, base.budgets.copy(reconstructionMaximumContextCharacters = 120_001))
            val project = root.resolve("project")
            var called = false

            val failure = assertFailsWith<IllegalArgumentException> {
                RecompilableProjectGenerator.generate(analysis, project, requested, reconstructor = ModuleReconstructor {
                    called = true
                    error("unadmitted generation must not start")
                })
            }

            assertTrue(failure.message.orEmpty().contains("host safety limit"))
            assertFalse(called)
            assertFalse(project.exists())
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `supplemental report destinations are reserved during profile admission`() {
        val root = createTempDirectory("profiled-report-admission-")
        try {
            val bytes = elfFixture()
            val binary = root.resolve("authored.elf").also { it.writeBytes(bytes) }
            val model = model(sha256(bytes))
            val analysis = GhidraJvmAnalyzer { _, _ -> model }.analyze(binary, root.resolve("existing-analysis"))
            val base = GeneratedCNinjaReconstructionProfile.descriptor
            val declarations = listOf("reports/analysis.json", "reports/{module}.json", "reports",
                "reports/unresolved.json/notes.txt")
            for ((index, path) in declarations.withIndex()) {
                val layout = ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations + ProjectFileDeclaration(
                    "supplemental-fixture", path, setOf(ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT,
                ))
                val profile = ReconstructionProfile(base.schemaVersion, base.id, layout, base.budgets, base.adapterConfiguration)
                val analyzer = RecordingAnalyzer(model)
                val work = root.resolve("pipeline-$index")
                val pipelineFailure = assertFailsWith<IllegalArgumentException>(path) {
                    ReconstructionPipeline(GhidraJvmAnalyzer(analyzer)).generate(binary, work, profile)
                }
                assertTrue(pipelineFailure.message.orEmpty().contains("supplemental report"), path)
                assertTrue(analyzer.bindings.isEmpty(), path)
                assertTrue(analyzer.calls.isEmpty(), path)
                assertFalse(work.exists(), path)

                val project = root.resolve("direct-$index")
                val generationFailure = assertFailsWith<IllegalArgumentException>(path) {
                    RecompilableProjectGenerator.generate(analysis, project, profile)
                }
                assertTrue(generationFailure.message.orEmpty().contains("supplemental report"), path)
                assertFalse(project.exists(), path)
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun assertRejectedBeforeBinding(profile: ReconstructionProfile, expectedMessage: String) {
        val root = createTempDirectory("profiled-pipeline-admission-")
        try {
            val analyzer = RecordingAnalyzer(model("a".repeat(64)))
            val work = root.resolve("work")
            val failure = assertFailsWith<IllegalArgumentException> {
                ReconstructionPipeline(GhidraJvmAnalyzer(analyzer)).generate(root.resolve("unused-input"), work, profile)
            }
            assertTrue(failure.message.orEmpty().contains(expectedMessage))
            assertTrue(analyzer.bindings.isEmpty())
            assertTrue(analyzer.calls.isEmpty())
            assertFalse(work.exists())
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private class RecordingAnalyzer(private val model: RecoveredProgramModel) : ExportBudgetedProgramModelAnalyzer {
        val bindings = mutableListOf<ReconstructionBudgets>()
        val calls = mutableListOf<Pair<Path, Path>>()

        override fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel =
            error("profile pipeline must use the budget-bound analyzer")

        override fun withExportBudgets(budgets: ReconstructionBudgets): ProgramModelAnalyzer {
            bindings += budgets
            return ProgramModelAnalyzer { binary, work ->
                calls += binary to work
                work.resolve("reports").createDirectories().resolve("program_model.json").writeText(model.toJson())
                model
            }
        }
    }

    private fun profile(base: ReconstructionProfile, budgets: ReconstructionBudgets) =
        ReconstructionProfile(base.schemaVersion, base.id, base.layout, budgets, base.adapterConfiguration)

    private fun model(inputSha256: String) = RecoveredProgramModel(inputSha256 = inputSha256, functions = listOf(
        RecoveredFunction("fn_1000", "authored_leaf", 0x1000UL, "int authored_leaf(void)",
            "int authored_leaf(void) { return 7; }"),
        RecoveredFunction("fn_2000", "decomp_engine_main", 0x2000UL, "int decomp_engine_main(void)",
            "int decomp_engine_main(void) { return authored_leaf(); }", calls = setOf("fn_1000")),
    ))
}
