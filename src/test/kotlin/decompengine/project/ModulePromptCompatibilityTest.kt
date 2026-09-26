package decompengine.project

import decompengine.agent.AgentHarness
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentStopReason
import java.nio.file.Path
import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class ModulePromptCompatibilityTest {
    @Test
    fun `generated C prompt commitments remain stable for Make and Ninja`() {
        for (base in ReconstructionProfiles.builtIn) {
            for ((configuredBudget, profileBudget) in listOf(4096 to 120000, 120000 to 4096, 4096 to 4096)) {
                val profile = withBudget(base, profileBudget)
                var invoked = false
                val reconstructor = BoundedLlmModuleReconstructor(
                    AgentHarness { _, _ -> invoked = true; error("must not execute") }, configuredBudget,
                )
                val failure = assertFailsWith<ModuleContextBudgetExceededException> {
                    reconstructor.reconstruct(request(profile, Path.of("unused-workspace")))
                }
                // Recorded from the production prompt path before extraction into the adapter.
                assertEquals(5515, failure.promptCharacters)
                assertEquals("b85179ae06e54680ce7c5d5113e8d39169bfc2a2bab34bc24acdb9276180a064", failure.promptSha256)
                assertEquals(4096, failure.promptBudgetCharacters)
                assertTrue(":context-4096:" in reconstructor.cacheIdentity(profile))
                assertEquals(profileBudget, profile.budgets.reconstructionMaximumContextCharacters)
                assertFalse(invoked)
            }
        }
    }

    @Test
    fun `candidate assessment applies profile budgets to every agent identity form`() {
        for ((generator, identity) in listOf(
            "agent:authored" to "custom", "authored" to "agent:authored", "unresolved:agent:authored" to "agent:authored",
        )) {
            val profile = withBudget(GeneratedCMakeReconstructionProfile.descriptor, 4096)
            val project = createTempDirectory("candidate-profile-budget-")
            val reconstructor = object : ModuleReconstructor {
                override fun cacheIdentity(): String = identity
                override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule =
                    EvidenceModuleReconstructor(true).reconstruct(request).copy(
                        generator = generator,
                        promptCharacters = if (generator.startsWith("unresolved:agent:")) 5000 else 10,
                        promptBudgetCharacters = 4097,
                    )
            }
            val manifest = SourceTreeGenerator.generate(model(), project, profile = profile, reconstructor = reconstructor)
            assertEquals(listOf("fn_alpha"), manifest.unresolvedImplementationIds)
            val module = DeterministicModulePlanner(layout = profile.layout).plan(model()).modules.single()
            val checkpoint = Json.parseToJsonElement(project.resolve(
                profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id)),
            ).readText()).jsonObject
            assertEquals(JsonPrimitive(false), checkpoint.getValue("accepted"))
            assertEquals(kotlinx.serialization.json.JsonNull, checkpoint.getValue("compilation"))
            assertTrue(checkpoint.getValue("issues").jsonArray.any {
                it.jsonObject.getValue("code").jsonPrimitive.content == "prompt-budget-invalid"
            })
            if (generator.startsWith("unresolved:agent:")) {
                assertEquals(0, ReconstructionAdapters.resolve(profile).build(project, profile).returnCode)
                assertFailsWith<Exception> {
                    ArchivalPackager.create(project, project.parent.resolve("returned-candidate.zip"), profile = profile)
                }
            }
        }
    }

    @Test
    fun `candidate assessment records profile and usage budget violations independently`() {
        val profile = withBudget(GeneratedCMakeReconstructionProfile.descriptor, 4096)
        val project = createTempDirectory("candidate-dual-budget-violations-")
        val reconstructor = object : ModuleReconstructor {
            override fun cacheIdentity(): String = "custom"
            override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule =
                EvidenceModuleReconstructor(true).reconstruct(request).copy(
                    generator = "custom", promptCharacters = 5000, promptBudgetCharacters = 4097,
                )
        }
        val manifest = SourceTreeGenerator.generate(model(), project, profile = profile, reconstructor = reconstructor)
        assertEquals(listOf("fn_alpha"), manifest.unresolvedImplementationIds)
        val module = DeterministicModulePlanner(layout = profile.layout).plan(model()).modules.single()
        val checkpoint = Json.parseToJsonElement(project.resolve(
            profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id)),
        ).readText()).jsonObject
        val codes = checkpoint.getValue("issues").jsonArray.map {
            it.jsonObject.getValue("code").jsonPrimitive.content
        }
        assertTrue("context-budget-exceeded" in codes)
        assertTrue("prompt-budget-invalid" in codes)
    }

    @Test
    fun `exact profile prompt limit is dispatched and recorded on cancellation`() {
        for (base in ReconstructionProfiles.builtIn) {
            val profile = withBudget(base, 5515)
            var calls = 0
            val reconstructor = BoundedLlmModuleReconstructor(AgentHarness { _, _ ->
                calls++
                AgentExecutionResult(AgentStopReason.CANCELLED)
            })
            val failure = assertFailsWith<ModuleReconstructionInterruptedException> {
                reconstructor.reconstruct(request(profile, createTempDirectory("exact-prompt-budget-")))
            }
            assertEquals(1, calls)
            assertEquals(5515, failure.promptCharacters)
            assertEquals(5515, failure.promptBudgetCharacters)
            assertTrue(":context-5515:" in reconstructor.cacheIdentity(profile))
            assertEquals(reconstructor.cacheIdentity(), reconstructor.cacheIdentity(base))
        }
    }

    @Test
    fun `workflow archives undispatched agent modules as unresolved for both profiles`() {
        for (base in ReconstructionProfiles.builtIn) {
            val profile = withBudget(base, 1)
            val project = createTempDirectory("profile-module-budget-")
            val reconstructor = BoundedLlmModuleReconstructor(AgentHarness { _, _ -> error("must not execute") })
            val manifest = SourceTreeGenerator.generate(model(), project, profile = profile, reconstructor = reconstructor)
            assertEquals(listOf("fn_alpha"), manifest.unresolvedImplementationIds)
            val module = DeterministicModulePlanner(layout = profile.layout).plan(model()).modules.single()
            val checkpoint = Json.parseToJsonElement(project.resolve(
                profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id)),
            ).readText()).jsonObject
            assertEquals(JsonPrimitive(1), checkpoint.getValue("promptBudgetCharacters"))
            assertEquals(JsonPrimitive(reconstructor.cacheIdentity(profile)), checkpoint.getValue("reconstructorIdentity"))
            assertEquals(JsonPrimitive(false), checkpoint.getValue("accepted"))
            assertEquals(JsonPrimitive("pre-dispatch-context-budget-fallback"),
                checkpoint.getValue("workflowOrigin"))
            assertTrue(checkpoint.getValue("issues").jsonArray.any {
                it.jsonObject.getValue("code").jsonPrimitive.content == "context-budget-exceeded"
            })
            val generationEvidence = Json.parseToJsonElement(
                project.resolve("reports/confidence.json").readText(),
            ).jsonObject.getValue("sourceGenerationBudgetEvidence").jsonObject
            val moduleEvidence = generationEvidence.getValue("modules").jsonArray.single().jsonObject
            assertTrue(moduleEvidence.getValue("promptCharacters").jsonPrimitive.content.toInt() > 1)
            assertEquals("1", moduleEvidence.getValue("promptBudgetCharacters").jsonPrimitive.content)
            assertEquals("unresolved", moduleEvidence.getValue("outcome").jsonPrimitive.content)
            assertEquals(0, ReconstructionAdapters.resolve(profile).build(project, profile).returnCode)
            val bundle = ArchivalPackager.create(project, project.parent.resolve("undispatched.zip"), profile = profile)
            assertEquals(listOf("fn_alpha"), requireNotNull(bundle.audit).unresolvedEntityIds)
        }
    }

    @Test
    fun `returned candidate cannot impersonate a pre-dispatch budget fallback`() {
        val profile = withBudget(GeneratedCMakeReconstructionProfile.descriptor, 1)
        val project = createTempDirectory("forged-budget-fallback-")
        val reconstructor = object : ModuleReconstructor {
            override fun cacheIdentity(): String = "agent:forged-budget"
            override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule =
                EvidenceModuleReconstructor(true).reconstruct(request).copy(
                    generator = "unresolved:agent:forged-budget",
                    promptCharacters = 5515,
                    promptBudgetCharacters = 1,
                    issues = listOf(ModuleReconstructionIssue(
                        "context-budget-exceeded", "module context required 5515 characters; limit=1",
                        request.module.functionIds + request.module.globalIds,
                    )),
                    retryable = true,
                    agentExecutionEvidence = null,
                )
        }
        SourceTreeGenerator.generate(model(), project, profile = profile, reconstructor = reconstructor)
        val module = DeterministicModulePlanner(layout = profile.layout).plan(model()).modules.single()
        val checkpoint = Json.parseToJsonElement(project.resolve(
            profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id)),
        ).readText()).jsonObject
        assertEquals(JsonPrimitive("reconstructor-return"), checkpoint.getValue("workflowOrigin"))
        assertFailsWith<Exception> {
            ArchivalPackager.create(project, project.parent.resolve("forged-budget-fallback.zip"), profile = profile)
        }
    }

    @Test
    fun `custom reconstructor exception cannot impersonate the trusted prompt boundary`() {
        val profile = withBudget(GeneratedCMakeReconstructionProfile.descriptor, 1)
        val project = createTempDirectory("forged-budget-exception-")
        val reconstructor = object : ModuleReconstructor {
            override fun cacheIdentity(): String = "agent:forged-exception"
            override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule =
                throw ModuleContextBudgetExceededException(request.module.id, 5515, 1, "a".repeat(64))
        }
        SourceTreeGenerator.generate(model(), project, profile = profile, reconstructor = reconstructor)
        val module = DeterministicModulePlanner(layout = profile.layout).plan(model()).modules.single()
        val checkpoint = Json.parseToJsonElement(project.resolve(
            profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id)),
        ).readText()).jsonObject
        assertEquals(JsonPrimitive("exception-fallback"), checkpoint.getValue("workflowOrigin"))
        assertFailsWith<Exception> {
            ArchivalPackager.create(project, project.parent.resolve("forged-budget-exception.zip"), profile = profile)
        }
    }

    @Test
    fun `dispatched harness exception cannot impersonate the prompt boundary`() {
        val profile = withBudget(GeneratedCMakeReconstructionProfile.descriptor, 120000)
        val project = createTempDirectory("forged-harness-budget-")
        val reconstructor = BoundedLlmModuleReconstructor(AgentHarness { _, _ ->
            throw ModuleContextBudgetExceededException("alpha", 120001, 120000, "a".repeat(64))
        }, maximumContextCharacters = 120000)
        SourceTreeGenerator.generate(model(), project, profile = profile, reconstructor = reconstructor)
        val module = DeterministicModulePlanner(layout = profile.layout).plan(model()).modules.single()
        val checkpoint = Json.parseToJsonElement(project.resolve(
            profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id)),
        ).readText()).jsonObject
        assertEquals(JsonPrimitive("exception-fallback"), checkpoint.getValue("workflowOrigin"))
        assertFailsWith<Exception> {
            ArchivalPackager.create(project, project.parent.resolve("forged-harness-budget.zip"), profile = profile)
        }
    }

    @Test
    fun `archive evidence gate accepts authenticated repair of an undispatched fallback`() {
        val profile = withBudget(GeneratedCMakeReconstructionProfile.descriptor, 1)
        val project = createTempDirectory("repaired-budget-fallback-")
        val reconstructor = BoundedLlmModuleReconstructor(AgentHarness { _, _ -> error("must not execute") })
        val manifest = SourceTreeGenerator.generate(model(), project, profile = profile, reconstructor = reconstructor)
        val source = manifest.files.single { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }
        val sourcePath = project.resolve(source.path)
        val originalBytes = sourcePath.readBytes()
        val repairedText = sourcePath.readText() + "\n/* accepted repair fixture */\n"
        sourcePath.writeText(repairedText)
        val repairedBytes = sourcePath.readBytes()
        val repairedSource = GeneratedFileEvidence(
            path = source.path,
            sha256 = sha256(repairedBytes),
            generator = "repair-revision",
            promptSha256 = source.promptSha256,
            entityIds = source.entityIds,
            acceptedImplementation = true,
            roles = source.roles,
            contentKind = source.contentKind,
        )
        val repairedManifest = SourceTreeManifest(
            profileId = manifest.profileId,
            profileSha256 = manifest.profileSha256,
            inputSha256 = manifest.inputSha256,
            files = manifest.files.map { if (it.path == source.path) repairedSource else it },
            unresolvedEntityIds = emptyList(),
            unresolvedImplementationIds = emptyList(),
        )
        val lineage = ArchivedRepairReleaseLineage.of(
            sources = listOf(ArchivedRepairSourceLineage(
                source.path, source.sha256, originalBytes.size.toLong(), sha256(repairedBytes),
                repairedBytes.size.toLong(), "accepted-revision",
            )),
            graphHeadId = "accepted-revision",
            graphHeadRevisionSha256 = "a".repeat(64),
            acceptedAcpContributions = emptyList(),
        )
        val payloadSha256 = repairedManifest.files.associate { it.path to sha256(project.resolve(it.path).readBytes()) }
        val payloadSizes = repairedManifest.files.associate { it.path to Files.size(project.resolve(it.path)) }

        assertTrue(ReconstructionAcpEvidenceArchiveVerifier.verify(
            project, payloadSha256, payloadSizes, repairedManifest, profile, lineage,
        ).isEmpty())
    }

    private fun model() = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
        RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)",
            "int alpha_run(void) { return 7; }"),
    ))

    private fun request(profile: ReconstructionProfile, workspace: Path): ModuleReconstructionRequest {
        val model = model()
        val module = DeterministicModulePlanner(layout = profile.layout).plan(model).modules.single()
        return ModuleReconstructionRequest(module, model, "x".repeat(4096),
            "int alpha_run(void);", "/* private interface */", mapOf("include/modules/dep.h" to "int dep(void);"),
            workspace, observedBehavior = "authored observation", profile = profile)
    }

    private fun withBudget(base: ReconstructionProfile, budget: Int) = ReconstructionProfile(
        schemaVersion = base.schemaVersion,
        id = base.id,
        layout = base.layout,
        budgets = base.budgets.copy(reconstructionMaximumContextCharacters = budget),
        adapterConfiguration = base.adapterConfiguration,
    )
}
