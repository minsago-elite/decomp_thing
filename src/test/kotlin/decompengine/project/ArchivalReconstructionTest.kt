package decompengine.project

import decompengine.agent.AgentWorkflowProgress
import decompengine.agent.AgentWorkflowPhase

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive

import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class ArchivalReconstructionTest {
    @Test
    fun `service recovers builds and packages a complete source tree`() {
        val temp = createTempDirectory("archival-service-")
        val binary = temp.resolve("input.elf").also { it.writeBytes(byteArrayOf(1, 2, 3)) }
        val analyzer = ProgramModelAnalyzer { supplied, work ->
            assertEquals(binary, supplied)
            assertTrue(work.toString().endsWith("analysis"))
            RecoveredProgramModel(
                inputSha256 = sha256(supplied.toFile().readBytes()),
                functions = listOf(RecoveredFunction("fn_1000", "decomp_engine_main", 0x1000UL, "int decomp_engine_main(void)")),
            )
        }

        val base = GeneratedCMakeReconstructionProfile.descriptor
        val profile = ReconstructionProfile(base.schemaVersion, base.id, base.layout, base.budgets,
            base.adapterConfiguration + mapOf(
                "build-executable" to listOf("/usr/bin/make"),
                "compiler-driver" to listOf("/usr/bin/cc"),
            ))
        val phases = mutableListOf<AgentWorkflowPhase>()
        val progress = object : AgentWorkflowProgress by AgentWorkflowProgress.NONE {
            override fun phase(phase: AgentWorkflowPhase, taskId: String?, acceptedRevisionSha256: String?) {
                phases += phase
            }
        }
        val result = ArchivalReconstructionService(analyzer, profile = profile, progress = progress)
            .reconstruct(binary, temp.resolve("result"))
        val audit = requireNotNull(result.bundle.audit)
        assertTrue(audit.unresolvedEntityIds.isNotEmpty())
        assertEquals(AgentWorkflowPhase.UNRESOLVED, phases.last())
        val summary = Json.parseToJsonElement(temp.resolve("result/reconstruction.json").readText()).jsonObject
        assertEquals("unresolved", summary.getValue("implementationStatus").jsonPrimitive.content)
        assertEquals(audit.unresolvedEntityIds.size.toString(), summary.getValue("unresolvedEntityCount").jsonPrimitive.content)
        val savedProgress = Json.parseToJsonElement(temp.resolve("result/reconstruction_progress.json").readText()).jsonObject
        assertEquals("unresolved", savedProgress.getValue("phase").jsonPrimitive.content)

        assertEquals(0, result.build.returnCode)
        assertEquals("/usr/bin/make", result.build.command.first())
        assertTrue("CC=/usr/bin/cc" in result.build.command)
        assertTrue(result.projectDir.resolve("src/modules/decomp.c").exists())
        assertTrue(result.bundle.archivePath.exists())
        assertTrue(temp.resolve("result/reconstruction.json").readText().contains(result.bundle.archiveSha256))
        val extracted = temp.resolve("extracted")
        ArchivalBundleVerifier.extractAndVerify(result.bundle.archivePath, extracted, profile = profile)
        val rebuilt = ReconstructionAdapters.resolve(profile).build(extracted, profile)
        assertEquals(0, rebuilt.returnCode)
        assertEquals(result.build.command, rebuilt.command)
        assertEquals(ArchivalProjectAuditor.audit(result.projectDir, profile).moduleRevisionSha256,
            ArchivalProjectAuditor.audit(extracted, profile).moduleRevisionSha256)
    }

    @Test
    fun `service archives declared report paths and rebuilds the extracted project`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val relocated = mapOf(
            "build-definition" to "config/rebuild.mk",
            "program-model-evidence" to "reports/inputs/model.json",
            "module-plan-evidence" to "reports/planning/modules.json",
            "confidence-evidence" to "reports/assessment/confidence.json",
            "toolchain-evidence" to "reports/environment/tools.json",
            "unresolved-evidence" to "reports/assessment/unresolved.md",
        )
        val layout = ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map { declaration ->
            ProjectFileDeclaration(declaration.id, relocated[declaration.id] ?: declaration.pathTemplate,
                declaration.roles, declaration.contentKind)
        })
        val profile = ReconstructionProfile(base.schemaVersion, base.id, layout, base.budgets, base.adapterConfiguration)
        val temp = createTempDirectory("declared-archive-reports-")
        val input = temp.resolve("input.bin").also { it.writeBytes(byteArrayOf(4, 5, 6)) }
        val analyzer = ProgramModelAnalyzer { _, _ -> RecoveredProgramModel(
            inputSha256 = sha256(input.toFile().readBytes()),
            functions = listOf(RecoveredFunction("fn_1000", "decomp_engine_main", 0x1000UL, "int decomp_engine_main(void)")),
        ) }
        val result = ArchivalReconstructionService(analyzer, profile = profile).reconstruct(input, temp.resolve("result"))
        assertEquals(listOf("-f", "config/rebuild.mk"), result.build.command.takeLast(2))
        val contract = Json.parseToJsonElement(result.projectDir.resolve("reports/build_contract.json").readText()).jsonObject
        val plannedModules = Json.parseToJsonElement(result.projectDir.resolve(relocated.getValue("module-plan-evidence"))
            .readText()).jsonObject.getValue("modules").jsonArray.map { it.jsonObject }
        assertTrue(plannedModules.isNotEmpty())
        val buildOwners = contract.getValue("modules").jsonArray.map { it.jsonObject }
        for (module in plannedModules) {
            val owner = buildOwners.single { it.getValue("source") == module.getValue("sourcePath") }
            assertEquals(module.getValue("id"), owner.getValue("id"))
        }
        val definitionInput = contract.getValue("sourceInputs").jsonArray.single {
            it.jsonObject.getValue("path").jsonPrimitive.content == "config/rebuild.mk"
        }.jsonObject
        assertEquals(sha256(result.projectDir.resolve("config/rebuild.mk").toFile().readBytes()),
            definitionInput.getValue("sha256").jsonPrimitive.content)
        for ((id, path) in relocated) {
            assertTrue(result.projectDir.resolve(path).exists(), id)
            assertFalse(result.projectDir.resolve(base.layout.declaration(id).materialize()).exists(), id)
        }
        val extracted = temp.resolve("extracted")
        ArchivalBundleVerifier.extractAndVerifySnapshot(result.bundle.archivePath.toFile().readBytes(), extracted,
            ArchivalBundleLimits(), profile, 2048)
        for (path in relocated.values) assertEquals(result.projectDir.resolve(path).readText(), extracted.resolve(path).readText())
        assertEquals(0, ReconstructionAdapters.resolve(profile).build(extracted, profile).returnCode)
        assertEquals(contract, Json.parseToJsonElement(extracted.resolve("reports/build_contract.json").readText()).jsonObject)
        assertEquals(ArchivalProjectAuditor.audit(result.projectDir, profile).toJson(),
            ArchivalProjectAuditor.audit(extracted, profile).toJson())
    }

    @Test
    fun `requested profile budgets cannot raise the default host ceiling`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val host = ReconstructionHostSafetyLimits.DEFAULT
        val raised = base.budgets.copy(
            reconstructionMaximumContextCharacters = host.maximum.reconstructionMaximumContextCharacters + 1,
        )
        val profile = ReconstructionProfile(base.schemaVersion, base.id, base.layout, raised, base.adapterConfiguration)
        val digest = profile.sha256
        var calls = 0
        val analyzer = ProgramModelAnalyzer { _, _ -> calls++; error("must not analyze") }
        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalReconstructionService(analyzer, profile = profile)
        }
        assertTrue(failure.message.orEmpty().contains("context budget exceeds the host safety limit"))
        assertFailsWith<IllegalArgumentException> { GhidraHeadlessProgramModelAnalyzer.bundled(profile) }
        assertEquals(0, calls)
        assertEquals(digest, profile.sha256)
        // A host caller can explicitly authorize another ceiling; this does not alter the request.
        val explicitHost = ReconstructionHostSafetyLimits(raised)
        ArchivalReconstructionService(analyzer, profile = profile, hostSafetyLimits = explicitHost)
        GhidraHeadlessProgramModelAnalyzer.bundled(profile, explicitHost)
        assertEquals(0, calls)
        assertEquals(digest, profile.sha256)
        assertEquals(base.budgets.reconstructionMaximumContextCharacters,
            host.maximum.reconstructionMaximumContextCharacters)
    }

    @Test
    fun `service rejects unsupported profiles before analysis or output writes`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val profile = ReconstructionProfile(base.schemaVersion, "unsupported-service-v1", base.layout,
            base.budgets, base.adapterConfiguration)
        val temp = createTempDirectory("unsupported-service-")
        val output = temp.resolve("result")
        var calls = 0
        val analyzer = ProgramModelAnalyzer { _, _ -> calls++; error("must not analyze") }
        assertFailsWith<IllegalArgumentException> {
            ArchivalReconstructionService(analyzer, profile = profile).reconstruct(temp.resolve("unused"), output)
        }
        assertEquals(0, calls)
        assertFalse(output.exists())
    }

}
