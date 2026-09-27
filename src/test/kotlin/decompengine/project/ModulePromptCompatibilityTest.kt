package decompengine.project

import decompengine.agent.AgentHarness
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentStopReason
import decompengine.oracle.behavior.LlvmBehaviorCandidateAcpLineageIndexV2Publisher
import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
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
            val profile = base
            val qualificationRoot = createTempDirectory("profile-module-budget-")
            val project = Files.createDirectory(qualificationRoot.resolve("project"))
            val reconstructor = BoundedLlmModuleReconstructor(
                AgentHarness { _, _ -> error("must not execute") }, maximumContextCharacters = 4_096,
            )
            val manifest = SourceTreeGenerator.generate(
                model(), project, profile = profile, reconstructor = reconstructor,
                observedBehavior = "x".repeat(4_096),
            )
            assertEquals(listOf("fn_alpha"), manifest.unresolvedImplementationIds)
            val module = DeterministicModulePlanner(layout = profile.layout).plan(model()).modules.single()
            val checkpoint = Json.parseToJsonElement(project.resolve(
                profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id)),
            ).readText()).jsonObject
            assertEquals(JsonPrimitive(4_096), checkpoint.getValue("promptBudgetCharacters"))
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
            assertTrue(moduleEvidence.getValue("promptCharacters").jsonPrimitive.content.toInt() > 4_096)
            assertEquals("4096", moduleEvidence.getValue("promptBudgetCharacters").jsonPrimitive.content)
            assertEquals("unresolved", moduleEvidence.getValue("outcome").jsonPrimitive.content)
            assertFalse(Files.exists(project.resolve("reports/repair-revisions")))
            assertEquals(listOf("fn_alpha"), ArchivalProjectAuditor.audit(project, profile,
                limits = ArchivalBundleLimits(maximumEntries = manifest.files.size + 1)).unresolvedEntityIds)
            assertEquals(0, ReconstructionAdapters.resolve(profile).build(project, profile).returnCode)
            val archive = qualificationRoot.resolve("${project.fileName}.zip")
            val bundle = ArchivalPackager.create(project, archive, profile = profile)
            assertEquals(listOf("fn_alpha"), requireNotNull(bundle.audit).unresolvedEntityIds)
            val extracted = qualificationRoot.resolve("${project.fileName}-extracted")
            ArchivalBundleVerifier.extractAndVerify(bundle.archivePath, extracted, profile = profile)
            assertEquals(listOf("fn_alpha"), ArchivalProjectAuditor.audit(extracted, profile).unresolvedEntityIds)
            if (profile.id == GeneratedCMakeReconstructionProfile.PROFILE_ID) {
                val indexParent = project.resolve("fallback-lineage-index")
                Files.createDirectories(indexParent)
                Files.setPosixFilePermissions(indexParent, setOf(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE,
                ))
                val failure = assertFailsWith<IllegalArgumentException> {
                    LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(
                        bundle.archivePath,
                        indexParent.resolve("candidate-acp-lineage-index-v2.json"),
                    )
                }
                assertTrue(
                    failure.message.orEmpty().contains("no accepted first-class ACP contribution"),
                    "unexpected candidate lineage rejection: ${failure.message}",
                )
            }
        }
    }

    @Test
    fun `direct audit authenticates unrepaired fallbacks with relocated evidence`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "relocated-fallback-audit-")
        try {
            for (base in ReconstructionProfiles.builtIn) {
                val profile = ReconstructionProfile(base.schemaVersion, base.id,
                    ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map { declaration ->
                        ProjectFileDeclaration(declaration.id,
                            declaration.pathTemplate.replace(Regex("^reports/"), "evidence/"),
                            declaration.roles, declaration.contentKind)
                    }), base.budgets, base.adapterConfiguration)
                val project = temp.resolve(profile.id)
                Files.createDirectories(project)
                val manifest = SourceTreeGenerator.generate(model(), project, profile = profile,
                    reconstructor = BoundedLlmModuleReconstructor(
                        AgentHarness { _, _ -> error("must not execute") }, maximumContextCharacters = 4_096),
                    observedBehavior = "x".repeat(4_096))
                assertFalse(Files.exists(project.resolve("reports")))
                val limits = ArchivalBundleLimits(maximumEntries = manifest.files.size + 1)
                assertEquals(listOf("fn_alpha"),
                    ArchivalProjectAuditor.audit(project, profile, limits = limits, publish = false).unresolvedEntityIds)
                assertFalse(Files.exists(project.resolve("reports")))
                Files.createDirectory(project.resolve("reports"))
                assertEquals(listOf("fn_alpha"),
                    ArchivalProjectAuditor.audit(project, profile, limits = limits).unresolvedEntityIds)
                assertTrue(Files.exists(project.resolve("reports/archival_audit.json")))
            }
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun `direct audit rejects an unplanned agent fallback retained in the manifest`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val project = Files.createTempDirectory(scratch, "unplanned-fallback-audit-")
        try {
            val profile = GeneratedCMakeReconstructionProfile.descriptor
            val manifest = SourceTreeGenerator.generate(model(), project, profile = profile,
                reconstructor = EvidenceModuleReconstructor(false))
            val source = manifest.files.single { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }
            val extraPath = profile.layout.declaration("module-implementation")
                .materialize(mapOf("module" to "zz_unplanned"))
            Files.copy(project.resolve(source.path), project.resolve(extraPath))
            val extra = GeneratedFileEvidence(extraPath, source.sha256, "unresolved:agent:unplanned",
                acceptedImplementation = false, roles = source.roles, contentKind = source.contentKind)
            project.resolve("source_tree_manifest.json").writeText(SourceTreeManifest(
                profileId = manifest.profileId, profileSha256 = manifest.profileSha256,
                inputSha256 = manifest.inputSha256, files = manifest.files + extra,
                unresolvedEntityIds = manifest.unresolvedEntityIds,
                unresolvedImplementationIds = manifest.unresolvedImplementationIds).toJson())
            val failure = assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.audit(project, profile) }
            assertTrue(failure.message.orEmpty().contains("checkpoint is absent from the source manifest"))
            assertFalse(Files.exists(project.resolve("reports/archival_audit.json")))
        } finally {
            Files.walk(project).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun `direct audit preserves unresolved non-agent modules without repair evidence`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "non-agent-unresolved-audit-")
        try {
            for (profile in ReconstructionProfiles.builtIn) {
                val project = temp.resolve(profile.id)
                Files.createDirectories(project)
                val manifest = SourceTreeGenerator.generate(model(), project, profile = profile,
                    reconstructor = EvidenceModuleReconstructor(false))
                assertEquals(listOf("fn_alpha"), manifest.unresolvedImplementationIds)
                assertTrue(manifest.files.filter { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }
                    .none { it.generator.startsWith("unresolved:agent:") })
                assertFalse(Files.exists(project.resolve("reports/repair-revisions")))
                val audit = ArchivalProjectAuditor.audit(project, profile)
                assertEquals(listOf("fn_alpha"), audit.unresolvedEntityIds)
                assertTrue(audit.moduleConfidenceEvidenceProblems.isEmpty())
                assertTrue(Files.exists(project.resolve("reports/archival_audit.json")))
            }
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun `archive evidence gate rejects rehashed fallback budgets outside the profile or identity`() {
        val profile = withBudget(GeneratedCMakeReconstructionProfile.descriptor, 8_192)
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val project = Files.createTempDirectory(scratch, "fallback-budget-binding-")
        try {
            val reconstructor = BoundedLlmModuleReconstructor(
                AgentHarness { _, _ -> error("must not execute") },
                maximumContextCharacters = 4_096,
                harnessProvenanceDescriptor = "archive-fallback-budget-fixture",
            )
            val manifest = SourceTreeGenerator.generate(
                model(), project, profile = profile, reconstructor = reconstructor,
                observedBehavior = "x".repeat(8_192),
            )
            val source = manifest.files.single { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }
            val module = DeterministicModulePlanner(layout = profile.layout).plan(model()).modules.single()
            val checkpointPath = profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id))
            val checkpoint = Json.parseToJsonElement(project.resolve(checkpointPath).readText()).jsonObject
            val manifestJson = Json.parseToJsonElement(manifest.toJson()).jsonObject
            val promptCharacters = checkpoint.getValue("promptCharacters").jsonPrimitive.content.toLong()
            val originalIdentity = reconstructor.cacheIdentity(profile)
            assertEquals(JsonPrimitive("pre-dispatch-context-budget-fallback"), checkpoint.getValue("workflowOrigin"))
            assertTrue(promptCharacters > 8_193)

            fun verifyCurrentProject(): List<VerifiedCandidateAcpContribution> {
                val current = SourceTreeManifestReader.read(project, profile)
                return ReconstructionAcpEvidenceArchiveVerifier.verify(
                    project,
                    current.files.associate { it.path to sha256(project.resolve(it.path).readBytes()) },
                    current.files.associate { it.path to Files.size(project.resolve(it.path)) },
                    current,
                    profile,
                )
            }
            assertTrue(verifyCurrentProject().isEmpty())

            val mutations = listOf(
                Triple("zero-budget", 0, originalIdentity.replace(":context-4096:", ":context-0:")),
                Triple("below-configured-minimum", 4_095, originalIdentity.replace(":context-4096:", ":context-4095:")),
                Triple("above-profile", 8_193, originalIdentity.replace(":context-4096:", ":context-8193:")),
                Triple("budget-above-identity", 4_097, originalIdentity),
                Triple("identity-above-budget", 4_096, originalIdentity.replace(":context-4096:", ":context-4097:")),
                Triple("missing-context", 4_096, originalIdentity.replace(":context-4096:", ":")),
                Triple("decoy-context", 4_096, originalIdentity.replace(":context-4096:", ":context-4096:context-4095:")),
                Triple("malformed-factory", 4_096, originalIdentity.replace(Regex("factory-[0-9a-f]{64}"), "factory-invalid")),
                Triple("trailing-identity-text", 4_096, "$originalIdentity:extra"),
            )
            for ((name, budget, identity) in mutations) {
                val changedCheckpoint = JsonObject(LinkedHashMap(checkpoint).apply {
                    put("promptBudgetCharacters", JsonPrimitive(budget))
                    put("reconstructorIdentity", JsonPrimitive(identity))
                    put("generator", JsonPrimitive("unresolved:$identity"))
                    put("issues", JsonArray(checkpoint.getValue("issues").jsonArray.map { item ->
                        JsonObject(LinkedHashMap(item.jsonObject).apply {
                            if (getValue("code").jsonPrimitive.content == "context-budget-exceeded") {
                                put("message", JsonPrimitive("module context required $promptCharacters characters; limit=$budget"))
                            }
                        })
                    }))
                })
                val changedBytes = (changedCheckpoint.toString() + "\n").toByteArray()
                Files.write(project.resolve(checkpointPath), changedBytes)
                val changedManifest = JsonObject(LinkedHashMap(manifestJson).apply {
                    put("files", JsonArray(manifestJson.getValue("files").jsonArray.map { item ->
                        JsonObject(LinkedHashMap(item.jsonObject).apply {
                            when (getValue("path").jsonPrimitive.content) {
                                checkpointPath -> put("sha256", JsonPrimitive(sha256(changedBytes)))
                                source.path -> put("generator", JsonPrimitive("unresolved:$identity"))
                            }
                        })
                    }))
                })
                project.resolve("source_tree_manifest.json").writeText(changedManifest.toString() + "\n")

                val failure = assertFailsWith<IllegalArgumentException>(name) { verifyCurrentProject() }
                assertTrue(failure.message.orEmpty().contains("pre-dispatch fallback prompt budget differs"),
                    "$name failed at the wrong gate: ${failure.message}")
            }
        } finally {
            Files.walk(project).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun `audit validates confidence evidence when every implementation is an undispatched fallback`() {
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val project = Files.createTempDirectory(scratch, "all-fallback-confidence-")
        try {
            val generated = SourceTreeGenerator.generate(
                model(), project, profile = profile,
                reconstructor = BoundedLlmModuleReconstructor(
                    AgentHarness { _, _ -> error("must not execute") }, maximumContextCharacters = 4_096,
                ),
                observedBehavior = "x".repeat(4_096),
            )
            assertEquals(listOf("fn_alpha"), generated.unresolvedImplementationIds)
            val module = DeterministicModulePlanner(layout = profile.layout).plan(model()).modules.single()
            val checkpoint = Json.parseToJsonElement(project.resolve(
                profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id)),
            ).readText()).jsonObject
            assertEquals(JsonPrimitive("pre-dispatch-context-budget-fallback"), checkpoint.getValue("workflowOrigin"))

            val confidencePath = project.resolve("reports/confidence.json")
            val confidence = Json.parseToJsonElement(confidencePath.readText()).jsonObject
            val changedConfidence = JsonObject(LinkedHashMap(confidence).apply {
                put("unresolvedImplementationIds", JsonArray(emptyList()))
            })
            val changedBytes = (changedConfidence.toString() + "\n").toByteArray()
            Files.write(confidencePath, changedBytes)

            val manifestPath = project.resolve("source_tree_manifest.json")
            val manifest = Json.parseToJsonElement(manifestPath.readText()).jsonObject
            val confidencePathInLayout = profile.layout.declaration("confidence-evidence").materialize()
            val files = manifest.getValue("files").jsonArray.map { item ->
                val fields = LinkedHashMap(item.jsonObject)
                if (fields.getValue("path").jsonPrimitive.content == confidencePathInLayout) {
                    fields["sha256"] = JsonPrimitive(sha256(changedBytes))
                }
                JsonObject(fields)
            }
            manifestPath.writeText((JsonObject(LinkedHashMap(manifest).apply {
                put("files", JsonArray(files))
            }).toString()) + "\n")

            val failure = assertFailsWith<IllegalArgumentException> {
                ArchivalProjectAuditor.audit(project, profile, publish = false)
            }
            assertTrue(failure.message.orEmpty().contains("confidence unresolvedImplementationIds differs"))
        } finally {
            Files.walk(project).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
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
        assertUnrepairedAgentAuditRejected(project, profile)
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
        assertUnrepairedAgentAuditRejected(project, profile)
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
        assertUnrepairedAgentAuditRejected(project, profile)
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

    private fun assertUnrepairedAgentAuditRejected(project: Path, profile: ReconstructionProfile) {
        assertFalse(Files.exists(project.resolve("reports/repair-revisions")))
        for (publish in listOf(false, true)) {
            val failure = assertFailsWith<IllegalArgumentException> {
                ArchivalProjectAuditor.audit(project, profile, publish = publish)
            }
            assertTrue(failure.message.orEmpty().contains("agent-generated module is not accepted"),
                "unexpected direct audit rejection: ${failure.message}")
            assertFalse(Files.exists(project.resolve("reports/archival_audit.json")))
        }
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
