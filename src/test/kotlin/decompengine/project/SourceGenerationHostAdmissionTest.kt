package decompengine.project

import decompengine.agent.AgentWorkflowProgress
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SourceGenerationHostAdmissionTest {
    @Test
    fun `direct generation rejects budgets above the default host before writes`() {
        for (base in ReconstructionProfiles.builtIn) {
            for ((name, budgets) in aboveDefaultCeilings(base.budgets)) {
                val profile = profile(base, budgets)
                val digest = profile.sha256
                val project = createTempDirectory("source-host-rejected-").resolve("project")
                var reconstructionCalls = 0
                var progressCalls = 0
                val failure = assertFailsWith<IllegalArgumentException>(name) {
                    SourceTreeGenerator.generate(model(), project, profile = profile,
                        reconstructor = ModuleReconstructor {
                            reconstructionCalls++
                            error("host admission must precede reconstruction")
                        }) { _, _, _ -> progressCalls++ }
                }
                assertTrue(failure.message.orEmpty().contains("host safety limit"), name)
                assertEquals(0, reconstructionCalls, name)
                assertEquals(0, progressCalls, name)
                assertFalse(project.exists(), name)
                assertEquals(digest, profile.sha256, name)
                assertEquals(budgets, profile.budgets, name)
            }
        }
    }

    @Test
    fun `direct generation accepts an explicitly admitted host ceiling`() {
        for (base in ReconstructionProfiles.builtIn) {
            val temp = createTempDirectory("source-host-admitted-")
            val profile = raisedContextProfile(base)
            val digest = profile.sha256
            val explicitHost = ReconstructionHostSafetyLimits(profile.budgets)
            var reconstructionCalls = 0
            val reconstructor = ModuleReconstructor { request ->
                reconstructionCalls++
                EvidenceModuleReconstructor().reconstruct(request)
            }
            val callbackResults = mutableListOf<Pair<Int, Int>>()
            // Exercise the original full positional signature, including its callback argument.
            val original = SourceTreeGenerator.generate(model(), temp.resolve("default"), null, reconstructor,
                emptyMap(), null, base, AgentWorkflowProgress.NONE,
                { completed, total, _ -> callbackResults += completed to total })
            assertEquals(base.sha256, original.profileSha256)
            val admitted = SourceTreeGenerator.generate(model(), temp.resolve("admitted"),
                hostSafetyLimits = explicitHost, reconstructor = reconstructor, profile = profile,
            ) { completed, total, _ -> callbackResults += completed to total }
            assertEquals(2, reconstructionCalls)
            assertEquals(listOf(1 to 1, 1 to 1), callbackResults)
            assertEquals(listOf("fn_host"), admitted.unresolvedImplementationIds)
            assertEquals(digest, admitted.profileSha256)
            assertEquals(digest, profile.sha256)
            assertEquals(120_001, profile.budgets.reconstructionMaximumContextCharacters)
            assertEquals(120_000, ReconstructionHostSafetyLimits.DEFAULT.maximum.reconstructionMaximumContextCharacters)
        }
    }

    @Test
    fun `service forwards its admitted host ceiling to source generation`() {
        for (base in ReconstructionProfiles.builtIn) {
            val temp = createTempDirectory("service-source-host-")
            val binary = temp.resolve("authored-input.bin").also { it.writeBytes(byteArrayOf(1, 2, 3)) }
            val profile = raisedContextProfile(base)
            val digest = profile.sha256
            var analysisCalls = 0
            var reconstructionCalls = 0
            val analyzer = ProgramModelAnalyzer { supplied, _ ->
                analysisCalls++
                assertEquals(binary, supplied)
                model(sha256(supplied.readBytes()))
            }
            val reconstructor = ModuleReconstructor { request ->
                reconstructionCalls++
                assertEquals(digest, request.profile.sha256)
                EvidenceModuleReconstructor().reconstruct(request)
            }
            val output = temp.resolve("result")
            val result = ArchivalReconstructionService(analyzer, reconstructor, profile,
                hostSafetyLimits = ReconstructionHostSafetyLimits(profile.budgets),
            ).reconstruct(binary, output)
            assertEquals(1, analysisCalls)
            assertEquals(1, reconstructionCalls)
            assertEquals(0, result.build.returnCode)
            assertEquals(base.adapterConfiguration.getValue("build-executable").single(), result.build.command.first())
            assertTrue(result.bundle.archivePath.exists())
            assertEquals(listOf("fn_host"), requireNotNull(result.bundle.audit).unresolvedEntityIds)
            assertEquals(digest, SourceTreeManifestReader.read(result.projectDir, profile).profileSha256)
            val summary = Json.parseToJsonElement(output.resolve("reconstruction.json").readText()).jsonObject
            assertEquals(digest, summary.getValue("profileSha256").jsonPrimitive.content)
            assertEquals("unresolved", summary.getValue("implementationStatus").jsonPrimitive.content)
            assertEquals(digest, profile.sha256)
        }
    }

    @Test
    fun `source generation retains exact profile host and module outcome evidence`() {
        for (base in ReconstructionProfiles.builtIn) {
            val profile = raisedContextProfile(base)
            val host = ReconstructionHostSafetyLimits(profile.budgets)
            val project = createTempDirectory("source-budget-evidence-")
            SourceTreeGenerator.generate(
                model(),
                project,
                hostSafetyLimits = host,
                profile = profile,
                reconstructor = ModuleReconstructor { request ->
                    EvidenceModuleReconstructor().reconstruct(request).copy(
                        promptCharacters = 8,
                        promptBudgetCharacters = profile.budgets.reconstructionMaximumContextCharacters,
                    )
                },
            )

            val report = Json.parseToJsonElement(
                project.resolve("reports/confidence.json").readText(),
            ).jsonObject
            val evidence = report.getValue("sourceGenerationBudgetEvidence").jsonObject
            val selectedProfile = evidence.getValue("selectedProfile").jsonObject
            assertEquals(profile.id, selectedProfile.getValue("id").jsonPrimitive.content)
            assertEquals(profile.sha256, selectedProfile.getValue("sha256").jsonPrimitive.content)
            assertEquals(
                Json.parseToJsonElement(profile.canonicalJson()),
                selectedProfile.getValue("descriptor"),
            )
            assertEquals(
                Json.parseToJsonElement(host.maximum.canonicalJson()),
                evidence.getValue("hostSafetyLimits").jsonObject.getValue("budgets"),
            )
            assertEquals("true", evidence.getValue("admission").jsonObject.getValue("profileWithinHost").jsonPrimitive.content)
            val outcome = evidence.getValue("outcome").jsonObject
            assertEquals("1", outcome.getValue("plannedModules").jsonPrimitive.content)
            assertEquals("1", outcome.getValue("completedModules").jsonPrimitive.content)
            assertEquals("0", outcome.getValue("acceptedModules").jsonPrimitive.content)
            assertEquals("1", outcome.getValue("unresolvedModules").jsonPrimitive.content)
            val module = evidence.getValue("modules").jsonArray.single().jsonObject
            assertEquals("unresolved", module.getValue("outcome").jsonPrimitive.content)
            assertEquals("8", module.getValue("promptCharacters").jsonPrimitive.content)
            assertEquals(
                profile.budgets.reconstructionMaximumContextCharacters.toString(),
                module.getValue("promptBudgetCharacters").jsonPrimitive.content,
            )
        }
    }

    @Test
    fun `source generation rejects prompt budget metadata beyond profile for custom reconstructors`() {
        for (base in ReconstructionProfiles.builtIn) {
            val profile = profile(base, base.budgets.copy(reconstructionMaximumContextCharacters = 4_096))
            val project = createTempDirectory("source-custom-budget-")
            val manifest = SourceTreeGenerator.generate(
                model(),
                project,
                profile = profile,
                reconstructor = ModuleReconstructor { request ->
                    EvidenceModuleReconstructor().reconstruct(request).copy(
                        generator = "authored",
                        promptCharacters = 10,
                        promptBudgetCharacters = 4_097,
                    )
                },
            )

            assertEquals(listOf("fn_host"), manifest.unresolvedImplementationIds)
            val module = DeterministicModulePlanner(layout = profile.layout).plan(model()).modules.single()
            val checkpoint = Json.parseToJsonElement(project.resolve(
                profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id)),
            ).readText()).jsonObject
            assertEquals("custom", checkpoint.getValue("reconstructorIdentity").jsonPrimitive.content)
            assertEquals("false", checkpoint.getValue("accepted").jsonPrimitive.content)
            assertTrue(checkpoint.getValue("issues").jsonArray.any {
                it.jsonObject.getValue("code").jsonPrimitive.content == "prompt-budget-invalid"
            })
        }
    }

    private fun raisedContextProfile(base: ReconstructionProfile) = profile(base,
        base.budgets.copy(reconstructionMaximumContextCharacters = 120_001))

    private fun profile(base: ReconstructionProfile, budgets: ReconstructionBudgets) = ReconstructionProfile(
        base.schemaVersion, base.id, base.layout, budgets, base.adapterConfiguration,
    )

    private fun aboveDefaultCeilings(budgets: ReconstructionBudgets): List<Pair<String, ReconstructionBudgets>> {
        val host = ReconstructionHostSafetyLimits.DEFAULT.maximum
        return listOf(
            "export wall clock" to budgets.copy(exportWallClockMillis = host.exportWallClockMillis + 1),
            "export memory" to budgets.copy(exportMaximumResidentBytes = host.exportMaximumResidentBytes + 1),
            "planner entities" to budgets.copy(plannerMaximumEntities = host.plannerMaximumEntities + 1),
            "planner edges" to budgets.copy(plannerMaximumDependencyEdges = host.plannerMaximumDependencyEdges + 1),
            "planner work" to budgets.copy(plannerMaximumWorkUnits = host.plannerMaximumWorkUnits + 1),
            "module size" to budgets.copy(maximumFunctionsPerModule = host.maximumFunctionsPerModule + 1),
            "context" to budgets.copy(reconstructionMaximumContextCharacters = host.reconstructionMaximumContextCharacters + 1),
            "build wall clock" to budgets.copy(buildWallClockMillis = host.buildWallClockMillis + 1),
            "build output" to budgets.copy(buildMaximumOutputBytes = host.buildMaximumOutputBytes + 1),
            "archive entries" to budgets.copy(archiveMaximumEntries = host.archiveMaximumEntries + 1),
            "archive file" to budgets.copy(archiveMaximumFileBytes = host.archiveMaximumFileBytes + 1),
            "archive total" to budgets.copy(archiveMaximumTotalBytes = host.archiveMaximumTotalBytes + 1),
        )
    }

    private fun model(inputSha256: String = "a".repeat(64)) = RecoveredProgramModel(
        inputSha256 = inputSha256,
        functions = listOf(RecoveredFunction("fn_host", "decomp_engine_main", 0x1000UL, "int decomp_engine_main(void)")),
    )
}
