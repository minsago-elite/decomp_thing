package decompengine.project

import decompengine.agent.AgentWorkflowProgress
import decompengine.agent.AgentWorkflowPhase

import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive

class GeneratedCNinjaIntegrationTest {
    private fun model() = RecoveredProgramModel(
        inputSha256 = "a".repeat(64),
        functions = listOf(
            RecoveredFunction("fn_1000", "parse_leaf", 0x1000UL, "int parse_leaf(void)",
                "int parse_leaf(void) { return 3; }"),
            RecoveredFunction("fn_2000", "decomp_engine_main", 0x2000UL, "int decomp_engine_main(void)",
                "int decomp_engine_main(void) { return parse_leaf(); }", calls = setOf("fn_1000")),
        ),
    )

    @Test
    fun `Ninja profile generates validates archives extracts and rebuilds accepted modules without Make`() {
        val temp = createTempDirectory("ninja-reconstruction-")
        val profile = GeneratedCNinjaReconstructionProfile.descriptor
        val analyzer = ProgramModelAnalyzer { _, _ -> model() }
        val phases = mutableListOf<AgentWorkflowPhase>()
        val progress = object : AgentWorkflowProgress by AgentWorkflowProgress.NONE {
            override fun phase(phase: AgentWorkflowPhase, taskId: String?, acceptedRevisionSha256: String?) {
                phases += phase
            }
        }
        val result = ArchivalReconstructionService(analyzer, RecoveredCModuleReconstructor(), profile, progress = progress)
            .reconstruct(temp.resolve("authored-model-input"), temp.resolve("result"))
        assertEquals(AgentWorkflowPhase.COMPLETED, phases.last())
        assertTrue(requireNotNull(result.bundle.audit).unresolvedEntityIds.isEmpty())
        val summary = Json.parseToJsonElement(temp.resolve("result/reconstruction.json").readText()).jsonObject
        assertEquals("complete", summary.getValue("implementationStatus").jsonPrimitive.content)
        assertEquals("0", summary.getValue("unresolvedEntityCount").jsonPrimitive.content)
        val savedProgress = Json.parseToJsonElement(temp.resolve("result/reconstruction_progress.json").readText()).jsonObject
        assertEquals("complete", savedProgress.getValue("phase").jsonPrimitive.content)
        assertEquals("ninja", result.build.command.first())
        assertFalse(result.projectDir.resolve("Makefile").exists())
        assertTrue(result.projectDir.resolve("build.ninja").exists())
        val audit = ArchivalProjectAuditor.audit(result.projectDir, profile)
        assertTrue(audit.moduleCompilationEvidenceProblems.isEmpty())
        assertEquals(2, audit.moduleCompilationEvidence.size)
        assertTrue(audit.unresolvedEntityIds.isEmpty())
        val contract = Json.parseToJsonElement(result.projectDir.resolve("reports/build_contract.json").readText()).jsonObject
        val dependencies = contract.getValue("declaredDependencies").jsonArray.map { it.jsonPrimitive.content }
        assertTrue("Ninja" in dependencies)
        assertFalse(dependencies.any { "Make" in it })
        assertTrue(result.projectDir.resolve("BUILDING.md").readText().contains("ninja -f build.ninja -j 4"))
        val process = ProcessBuilder(result.projectDir.resolve("build/reconstructed").toString()).start()
        try {
            assertTrue(process.waitFor(5, TimeUnit.SECONDS))
            assertEquals(3, process.exitValue())
        } finally {
            if (process.isAlive) process.destroyForcibly()
        }
        val extracted = temp.resolve("extracted")
        ArchivalBundleVerifier.extractAndVerifySnapshot(result.bundle.archivePath.readBytes(), extracted,
            ArchivalBundleLimits(), profile, 2048)
        assertFalse(extracted.resolve("Makefile").exists())
        assertFalse(extracted.resolve("build/reconstructed").exists())
        val rebuilt = ReconstructionAdapters.resolve(profile).build(extracted, profile)
        assertEquals(result.build.command, rebuilt.command)
        assertEquals(0, rebuilt.returnCode)
        assertEquals(sha256(result.projectDir.resolve("build/reconstructed").readBytes()),
            sha256(extracted.resolve("build/reconstructed").readBytes()))
        assertEquals(audit.toJson(), ArchivalProjectAuditor.audit(extracted, profile).toJson())
        assertEquals(contract, Json.parseToJsonElement(extracted.resolve("reports/build_contract.json").readText()).jsonObject)
    }

    @Test
    fun `Ninja archive rejects command dependency and budget records from another build policy`() {
        val profile = GeneratedCNinjaReconstructionProfile.descriptor
        val temp = createTempDirectory("ninja-build-record-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(model(), project, reconstructor = RecoveredCModuleReconstructor(), profile = profile)
        ReconstructionAdapters.resolve(profile).build(project, profile)
        val path = project.resolve("reports/build_contract.json")
        val original = path.readText()
        val record = Json.parseToJsonElement(original).jsonObject
        val changes = mapOf(
            "command" to JsonArray(listOf(JsonPrimitive("other-build-tool"))),
            "declaredDependencies" to JsonArray(listOf(JsonPrimitive("GNU Make"))),
            "wallClockTimeoutMillis" to JsonPrimitive(profile.budgets.buildWallClockMillis + 1),
            "maximumOutputBytes" to JsonPrimitive(profile.budgets.buildMaximumOutputBytes + 1),
            "parallelism" to JsonPrimitive("4"),
        )
        for ((field, value) in changes) {
            path.writeText(JsonObject(record + (field to value)).toString())
            val archive = temp.resolve("rejected-$field.zip")
            assertFailsWith<IllegalArgumentException>(field) { ArchivalPackager.create(project, archive, profile = profile) }
            assertFalse(archive.exists(), field)
        }
        path.writeText(original)
        ArchivalPackager.create(project, temp.resolve("accepted.zip"), profile = profile)
    }

    @Test
    fun `Ninja build rejects an unowned source before accepting an artifact`() {
        val profile = GeneratedCNinjaReconstructionProfile.descriptor
        val project = createTempDirectory("ninja-unowned-source-")
        SourceTreeGenerator.generate(model(), project, reconstructor = RecoveredCModuleReconstructor(), profile = profile)
        project.resolve("src/unowned.c").writeText("int unrelated(void) { return 9; }\n")
        assertFailsWith<BuildException> { ReconstructionAdapters.resolve(profile).build(project, profile) }
        assertFalse(Files.exists(project.resolve("build/reconstructed")))
    }
}
