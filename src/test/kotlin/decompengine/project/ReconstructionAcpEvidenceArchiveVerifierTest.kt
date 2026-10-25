package decompengine.project

import decompengine.acp.ACP_KOTLIN_SDK_VERSION
import decompengine.acp.ACP_STABLE_PROTOCOL_VERSION
import decompengine.acp.AcpExecutionEvidenceSnapshot
import decompengine.acp.AcpExecutionCleanupDisposition
import decompengine.acp.AcpExecutionEvidenceCompleteness
import decompengine.acp.AcpExecutionLifecyclePhase
import decompengine.acp.AcpHarnessProvenance
import decompengine.acp.AcpInvocationEvidenceSnapshot
import decompengine.acp.AcpNegotiatedAgentEvidence
import decompengine.acp.AcpNegotiatedCapabilitiesEvidence
import decompengine.acp.AcpProcessDiagnostics
import decompengine.acp.AcpProducedOutputEvidence
import decompengine.acp.AcpRuntimeClosureLimits
import decompengine.acp.AcpSandboxEvidence
import decompengine.acp.AcpSandboxResourceLimits
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentMessageEvent
import decompengine.agent.AgentMessageRole
import decompengine.agent.AgentSessionReference
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentUsage
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.renderAgentPrompt
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.time.Duration
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.deleteExisting
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.relativeTo
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@org.junit.jupiter.api.parallel.Execution(org.junit.jupiter.api.parallel.ExecutionMode.SAME_THREAD)
@org.junit.jupiter.api.parallel.ResourceLock("contained-module-compilation-runtime")
class ReconstructionAcpEvidenceArchiveVerifierTest {
    @org.junit.jupiter.api.BeforeEach
    fun requireConfiguredCompilerForLiveAcceptance(test: org.junit.jupiter.api.TestInfo) = requireHostedModuleCompiler(test)

    @Test
    @org.junit.jupiter.api.Tag("ci-live")
    fun `authorized large observations dispatch successfully without retained fallback input`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "large-authorized-observation-")
        try {
            val base = GeneratedCMakeReconstructionProfile.descriptor
            val profile = ReconstructionProfile(base.schemaVersion, base.id, base.layout,
                base.budgets.copy(reconstructionMaximumContextCharacters = 600_000), base.adapterConfiguration)
            val project = temp.resolve("project")
            val harness = ArchiveEvidenceHarness(accepted = true)
            val observation = attributedObservation(stdoutHex = "78".repeat(16_384), cases = 17)
            assertTrue(observation.toByteArray().size > MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES)
            val manifest = SourceTreeGenerator.generate(
                model = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
                    RecoveredFunction("fn_0000000000401000", "parse_input", 0x401000UL, "int parse_input(void)"))),
                projectDir = project,
                hostSafetyLimits = ReconstructionHostSafetyLimits(profile.budgets),
                reconstructor = BoundedLlmModuleReconstructor(harness, maximumContextCharacters = 600_000,
                    harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor),
                observedBehavior = observation,
                profile = profile,
            )
            assertTrue(manifest.unresolvedImplementationIds.isEmpty())
            val checkpoint = Json.parseToJsonElement(project.resolve(CHECKPOINT_PATH).readText()).jsonObject
            assertEquals(JsonPrimitive(true), checkpoint.getValue("accepted"))
            assertEquals(JsonPrimitive("reconstructor-return"), checkpoint.getValue("workflowOrigin"))
            assertEquals(JsonPrimitive(600_000), checkpoint.getValue("promptBudgetCharacters"))
            assertFalse("preDispatchObservedBehavior" in checkpoint)
            assertTrue(project.resolve(EVIDENCE_PATH).exists())
            val contributions = ReconstructionAcpEvidenceArchiveVerifier.verify(project,
                manifest.files.associate { it.path to sha256(project.resolve(it.path).readBytes()) },
                manifest.files.associate { it.path to Files.size(project.resolve(it.path)) }, manifest, profile)
            assertEquals(1, contributions.size)
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun `authorized large observations dispatch with the complete prompt commitment`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "large-authorized-observation-")
        try {
            val base = GeneratedCMakeReconstructionProfile.descriptor
            val profile = ReconstructionProfile(base.schemaVersion, base.id, base.layout,
                base.budgets.copy(reconstructionMaximumContextCharacters = 600_000), base.adapterConfiguration)
            val project = temp.resolve("project")
            val harness = ArchiveEvidenceHarness(accepted = true)
            val observation = attributedObservation(stdoutHex = "78".repeat(16_384), cases = 17)
            assertTrue(observation.toByteArray().size > MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES)
            val model = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
                RecoveredFunction("fn_0000000000401000", "parse_input", 0x401000UL, "int parse_input(void)")))
            val plan = DeterministicModulePlanner(layout = profile.layout).plan(model)
            Files.createDirectories(project.resolve(SOURCE_PATH).parent)
            val request = ProfileModulePromptInputs(model, plan, profile).request("parse", project, null)
                .copy(observedBehavior = observation)
            val reconstructed = BoundedLlmModuleReconstructor(harness, maximumContextCharacters = 600_000,
                harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor).reconstruct(request)
            val prompt = modulePromptEvidence(request).text
            assertEquals(sha256(prompt.toByteArray()), reconstructed.promptSha256)
            assertEquals(prompt.length, reconstructed.promptCharacters)
            assertEquals(600_000, reconstructed.promptBudgetCharacters)
            assertTrue(reconstructed.issues.isEmpty())
            assertTrue(reconstructed.agentExecutionEvidence != null)
            assertEquals(reconstructed.promptSha256, sha256(renderAgentPrompt(
                harness.executedRequest.objective, harness.executedRequest.contextInputs).toByteArray()))
            // Direct dispatch proves prompt budgeting; it grants no module compiler acceptance.
            assertFalse(project.resolve(CHECKPOINT_PATH).exists())
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun `archive rejects semantically incomplete retained ACP receipts after every commitment is rebound`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "acp-incomplete-receipt-")
        try {
            for (profile in ReconstructionProfiles.builtIn) {
                val profileRoot = temp.resolve(profile.id)
                val baseline = createHistoricalAgentProject(profileRoot.resolve("baseline"), accepted = true, profile = profile)
                val sourceBytes = baseline.resolve(SOURCE_PATH).readBytes()
                val buildContractPath = ReconstructionAdapters.resolve(profile).archiveBuild.contractPaths(profile).contractPath
                val buildContractBytes = baseline.resolve(buildContractPath).readBytes()
                val baselineArchive = profileRoot.resolve("accepted.zip")
                ArchivalPackager.create(baseline, baselineArchive, profile = profile)
                assertTrue(baselineArchive.exists(), profile.id)

                val mutations = listOf(
                    listOf("refused", "\"stopReason\":\"completed\"", "\"stopReason\":\"refused\"",
                        "release ACP receipt result is not completed"),
                    listOf("release-incomplete", "\"releaseComplete\": true", "\"releaseComplete\": false",
                        "ACP receipt release-complete marker is false"),
                )
                for ((name, before, after, expectedMessage) in mutations) {
                    val project = profileRoot.resolve(name)
                    copyTree(baseline, project)
                    rewriteEvidenceAndBindings(project) { it.replaceFirst(before, after) }
                    assertTrue(sourceBytes.contentEquals(project.resolve(SOURCE_PATH).readBytes()))
                    assertTrue(buildContractBytes.contentEquals(project.resolve(buildContractPath).readBytes()))
                    // Confidence and all digest bindings must pass before packaging reaches the
                    // retained receipt's semantic release checks.
                    assertTrue(ArchivalProjectAuditor.audit(project, profile).moduleConfidenceEvidenceProblems.isEmpty())

                    val archive = profileRoot.resolve("$name.zip")
                    val failure = assertFailsWith<IllegalArgumentException>("${profile.id}/$name") {
                        ArchivalPackager.create(project, archive, profile = profile)
                    }
                    assertEquals(expectedMessage, failure.message, "${profile.id}/$name")
                    assertFalse(archive.exists(), "${profile.id}/$name published an archive")
                }
            }
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun `archive gate rejects closed-schema and semantic ACP evidence tampering`() {
        val temp = createTempDirectory("acp-archive-tampering-")
        val baseline = createHistoricalAgentProject(temp.resolve("baseline"), accepted = true)
        val sourceSha256 = sha256(baseline.resolve(SOURCE_PATH).readBytes())
        val sourceBytes = Files.size(baseline.resolve(SOURCE_PATH))
        val acceptedChangeAggregate = agentFileChangeSetSha256(
            listOf(
                AgentFileChange(
                    AgentWorkspacePath("project", SOURCE_PATH),
                    AgentFileChangeKind.CREATED,
                    beforeSha256 = null,
                    afterSha256 = sourceSha256,
                    sizeBytes = sourceBytes,
                ),
            ),
        )
        val mutations = linkedMapOf<String, (String) -> String>(
            "duplicate-field" to { text ->
                text.replaceFirst(
                    "  \"kind\": \"$EVIDENCE_KIND\",",
                    "  \"kind\": \"$EVIDENCE_KIND\",\n  \"kind\": \"$EVIDENCE_KIND\",",
                )
            },
            "unknown-field" to { text ->
                text.replaceFirst("  \"kind\":", "  \"unknown\": true,\n  \"kind\":")
            },
            "unknown-nested-field" to { text ->
                text.replaceFirst(
                    "    \"contractVersion\":",
                    "    \"unknownBound\": true,\n    \"contractVersion\":",
                )
            },
            "wrong-schema" to { text -> text.replaceFirst("\"schemaVersion\": 2", "\"schemaVersion\": 1") },
            "wrong-kind" to { text -> text.replaceFirst(EVIDENCE_KIND, "decomp-engine.patch-acp-execution") },
            "wrong-module" to { text -> text.replaceFirst("\"moduleId\": \"parse\"", "\"moduleId\": \"other\"") },
            "non-completed" to { text -> text.replaceFirst("\"stopReason\":\"completed\"", "\"stopReason\":\"refused\"") },
            "deprecated-factory" to { text -> text.replaceFirst("\"deprecated\": false", "\"deprecated\": true") },
            "result-source" to { text ->
                text.replaceFirst("\"afterSha256\":\"$sourceSha256\"", "\"afterSha256\":\"${"0".repeat(64)}\"")
            },
            "result-change-aggregate" to { text ->
                text.replace(acceptedChangeAggregate, "0".repeat(64))
            },
            "release-complete" to { text ->
                text.replaceFirst("\"releaseComplete\": true", "\"releaseComplete\": false")
            },
            "malformed-commitment" to { text ->
                text.replaceFirst("\"encoding\":\"utf-8\"", "\"encoding\":\"jvm-utf16be\"")
            },
            "invalid-modified-change" to { text ->
                text.replaceFirst(
                    "\"kind\":\"created\",\"beforeSha256\":null",
                    "\"kind\":\"modified\",\"beforeSha256\":null",
                )
            },
            "invalid-modified-digest" to { text ->
                text.replaceFirst(
                    "\"kind\":\"created\",\"beforeSha256\":null,\"afterSha256\":\"$sourceSha256\"",
                    "\"kind\":\"modified\",\"beforeSha256\":\"$sourceSha256\",\"afterSha256\":\"$sourceSha256\"",
                )
            },
            "invalid-event-role" to { text ->
                text.replaceFirst("\"role\":\"assistant\"", "\"role\":\"owner\"")
            },
            "process-network" to { text ->
                text.replaceFirst("\"networkIsolated\": true", "\"networkIsolated\": false")
            },
            "token-bound" to { text -> text.replaceFirst("\"maximumInputTokens\": null", "\"maximumInputTokens\": 5") },
        )

        mutations.forEach { (name, mutation) ->
            val project = temp.resolve(name)
            copyTree(baseline, project)
            rewriteEvidenceAndBindings(project, mutation)

            val failure = assertFailsWith<Exception>(name) {
                ArchivalPackager.create(project, temp.resolve("$name.zip"))
            }
            assertTrue(failure.message.orEmpty().isNotBlank(), name)
        }
    }

    @Test
    @org.junit.jupiter.api.Tag("ci-live")
    fun `fresh mismatched wire prompt retains receipt and rolls back candidate to unresolved source`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "v4-fresh-wire-mismatch-")
        try {
            for (profile in ReconstructionProfiles.builtIn) {
                val project = temp.resolve(profile.id)
                val mismatchedWire = "0".repeat(64)
                val harness = ArchiveEvidenceHarness(accepted = true, wirePromptOverride = mismatchedWire)
                val model = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
                    RecoveredFunction("fn_0000000000401000", "parse_input", 0x401000UL, "int parse_input(void)")))
                val manifest = SourceTreeGenerator.generate(model, project, profile = profile,
                    reconstructor = BoundedLlmModuleReconstructor(harness,
                        harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor))
                assertEquals(listOf("fn_0000000000401000"), manifest.unresolvedImplementationIds)
                val source = manifest.files.single { it.path == SOURCE_PATH }
                assertEquals(false, source.acceptedImplementation)
                assertTrue(source.generator.startsWith("unresolved:agent:"))
                val plan = DeterministicModulePlanner(layout = profile.layout).plan(model)
                val fallbackRequest = ProfileModulePromptInputs(model, plan, profile).request("parse", project, null)
                val fallbackSource = ReconstructionAdapters.resolve(profile).defaultReconstructor()
                    .reconstruct(fallbackRequest).source.trimEnd() + "\n"
                assertEquals(fallbackSource, project.resolve(SOURCE_PATH).readText())
                assertFalse("return 17;" in project.resolve(SOURCE_PATH).readText())
                val checkpoint = Json.parseToJsonElement(project.resolve(CHECKPOINT_PATH).readText()).jsonObject
                assertEquals(JsonPrimitive(false), checkpoint.getValue("accepted"))
                assertEquals(JsonPrimitive("exception-fallback"), checkpoint.getValue("workflowOrigin"))
                assertEquals(JsonNull, checkpoint.getValue("compilation"))
                assertEquals(JsonPrimitive("returned-completed"), checkpoint.getValue("executionTerminalOutcome"))
                assertTrue(project.resolve(EVIDENCE_PATH).exists())
                val receipt = Json.parseToJsonElement(project.resolve(EVIDENCE_PATH).readText()).jsonObject
                val request = receipt.getValue("request").jsonObject
                assertEquals(JsonPrimitive(mismatchedWire), request.getValue("wirePromptSha256"))
                assertEquals(checkpoint.getValue("promptSha256"), request.getValue("promptSha256"))
                assertTrue(request.getValue("promptSha256") != request.getValue("wirePromptSha256"))
                assertEquals(JsonPrimitive(sha256(project.resolve(EVIDENCE_PATH).readBytes())),
                    checkpoint.getValue("executionEvidenceSha256"))
                val failure = assertFailsWith<IllegalArgumentException> {
                    ReconstructionAcpEvidenceArchiveVerifier.verify(project,
                        manifest.files.associate { it.path to sha256(project.resolve(it.path).readBytes()) },
                        manifest.files.associate { it.path to Files.size(project.resolve(it.path)) }, manifest, profile)
                }
                assertTrue(failure.message.orEmpty().contains("not accepted"), failure.message)
            }
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    @org.junit.jupiter.api.Tag("ci-live")
    fun `v4 archive rejects a different wire prompt after every receipt commitment is rebound`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "v4-wire-prompt-replay-")
        try {
            for (profile in ReconstructionProfiles.builtIn) {
                val project = temp.resolve(profile.id)
                val harness = ArchiveEvidenceHarness(accepted = true)
                createAgentProject(project, accepted = true, profile = profile, harness = harness)
                val receipt = Json.parseToJsonElement(project.resolve(EVIDENCE_PATH).readText()).jsonObject
                val originalRequest = receipt.getValue("request").jsonObject
                val actualWireSha256 = sha256(renderAgentPrompt(
                    harness.executedRequest.objective, harness.executedRequest.contextInputs).toByteArray())
                assertEquals(JsonPrimitive(actualWireSha256), originalRequest.getValue("wirePromptSha256"))
                assertEquals(originalRequest.getValue("promptSha256"), originalRequest.getValue("wirePromptSha256"))
                val originalSource = project.resolve(SOURCE_PATH).readBytes()
                rewriteEvidenceAndBindings(project) { text ->
                    val root = Json.parseToJsonElement(text).jsonObject
                    val request = root.getValue("request").jsonObject
                    JsonObject(root + ("request" to JsonObject(request +
                        ("wirePromptSha256" to JsonPrimitive("0".repeat(64)))))).toString() + "\n"
                }
                assertTrue(originalSource.contentEquals(project.resolve(SOURCE_PATH).readBytes()))
                val manifest = SourceTreeManifestReader.read(project, profile)
                val failure = assertFailsWith<IllegalArgumentException>(profile.id) {
                    ReconstructionAcpEvidenceArchiveVerifier.verify(project,
                        manifest.files.associate { it.path to sha256(project.resolve(it.path).readBytes()) },
                        manifest.files.associate { it.path to Files.size(project.resolve(it.path)) }, manifest, profile)
                }
                assertEquals("module-minimal ACP wire prompt digest differs from its complete prompt commitment", failure.message)
            }
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    @org.junit.jupiter.api.Tag("ci-live")
    fun `v4 archive rejects rehashed header and prior-source read grants on accepted receipts`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "v4-policy-replay-")
        try {
            for (profile in ReconstructionProfiles.builtIn) {
                val profileRoot = temp.resolve(profile.id)
                val harness = ArchiveEvidenceHarness(accepted = true)
                val baseline = createAgentProject(profileRoot.resolve("baseline"), accepted = true,
                    profile = profile, harness = harness)
                val originalRequest = harness.executedRequest
                val originalPolicy = AgentExecutionRequestBinding.capture(originalRequest).accessPolicySha256
                val originalSource = baseline.resolve(SOURCE_PATH).readBytes()
                assertEquals(setOf(AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE),
                    originalRequest.accessPolicy.allowedOperations)
                assertEquals(1, originalRequest.accessPolicy.pathRules.size)
                val baselineManifest = SourceTreeManifestReader.read(baseline, profile)
                assertEquals(1, ReconstructionAcpEvidenceArchiveVerifier.verify(baseline,
                    baselineManifest.files.associate { it.path to sha256(baseline.resolve(it.path).readBytes()) },
                    baselineManifest.files.associate { it.path to Files.size(baseline.resolve(it.path)) },
                    baselineManifest, profile).size)

                for ((name, path) in listOf("header-read" to "include/modules/parse.h", "prior-source-read" to SOURCE_PATH)) {
                    val project = profileRoot.resolve(name)
                    copyTree(baseline, project)
                    val broaderRequest = AgentExecutionRequest(
                        objective = originalRequest.objective,
                        workspaceRoots = originalRequest.workspaceRoots,
                        contextInputs = originalRequest.contextInputs,
                        accessPolicy = AgentAccessPolicy(originalRequest.accessPolicy.pathRules + AgentPathRule(
                            AgentWorkspacePath("project", path), setOf(AgentOperation.READ_FILE))),
                        limits = originalRequest.limits,
                        sessionContinuation = originalRequest.sessionContinuation,
                    )
                    val broaderBinding = AgentExecutionRequestBinding.capture(broaderRequest)
                    assertTrue(broaderBinding.accessPolicySha256 != originalPolicy)
                    rewriteEvidenceAndBindings(project) { text ->
                        val receipt = Json.parseToJsonElement(text).jsonObject
                        val request = receipt.getValue("request").jsonObject
                        JsonObject(receipt + ("request" to JsonObject(request + mapOf(
                            "accessPolicySha256" to JsonPrimitive(broaderBinding.accessPolicySha256),
                            "requestSha256" to JsonPrimitive(broaderBinding.requestSha256),
                        )))).toString() + "\n"
                    }
                    val checkpoint = Json.parseToJsonElement(project.resolve(CHECKPOINT_PATH).readText()).jsonObject
                    rewriteCheckpointConfidenceAndManifest(project, JsonObject(checkpoint +
                        ("executionRequestSha256" to JsonPrimitive(broaderBinding.requestSha256))))
                    assertTrue(originalSource.contentEquals(project.resolve(SOURCE_PATH).readBytes()))
                    val manifest = SourceTreeManifestReader.read(project, profile)
                    val failure = assertFailsWith<IllegalArgumentException>("${profile.id}/$name") {
                        ReconstructionAcpEvidenceArchiveVerifier.verify(project,
                            manifest.files.associate { it.path to sha256(project.resolve(it.path).readBytes()) },
                            manifest.files.associate { it.path to Files.size(project.resolve(it.path)) }, manifest, profile)
                    }
                    assertEquals("module-minimal ACP receipt differs from its owned-source write policy", failure.message)
                }
            }
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun `archive gate rejects checkpoint path and digest ambiguity`() {
        val temp = createTempDirectory("acp-archive-checkpoint-")
        val baseline = createHistoricalAgentProject(temp.resolve("baseline"), accepted = true)

        listOf("path", "digest", "factory-cache-identity", "request-binding", "terminal-outcome").forEach { mutation ->
            val project = temp.resolve(mutation)
            copyTree(baseline, project)
            rewriteCheckpointAndManifest(project) { checkpoint ->
                when (mutation) {
                    "path" -> checkpoint.replace(
                        "\"executionEvidencePath\": \"$EVIDENCE_PATH\"",
                        "\"executionEvidencePath\": \"reports/agent-executions/stale.json\"",
                    )
                    "digest" -> checkpoint.replace(
                        Regex("\"executionEvidenceSha256\": \"[0-9a-f]{64}\""),
                        "\"executionEvidenceSha256\": \"${"0".repeat(64)}\"",
                    )
                    "request-binding" -> checkpoint.replace(
                        Regex("\"executionRequestSha256\": \"[0-9a-f]{64}\""),
                        "\"executionRequestSha256\": \"${"0".repeat(64)}\"",
                    )
                    "terminal-outcome" -> checkpoint.replace(
                        "\"executionTerminalOutcome\": \"returned-completed\"",
                        "\"executionTerminalOutcome\": \"returned-refused\"",
                    )
                    else -> checkpoint.replace(
                        Regex("factory-[0-9a-f]{64}:v4"),
                        "factory-${"0".repeat(64)}:v4",
                    )
                }
            }

            assertFailsWith<Exception>(mutation) {
                ArchivalPackager.create(project, temp.resolve("checkpoint-$mutation.zip"))
            }
        }
    }

    @Test
    fun `archive release gate rejects schema-v3 checkpoint downgrade`() {
        val temp = createTempDirectory("acp-archive-downgrade-")
        val project = createHistoricalAgentProject(temp.resolve("project"), accepted = true)
        rewriteCheckpointAndManifest(project) { checkpoint ->
            checkpoint.replaceFirst("\"schemaVersion\": 6", "\"schemaVersion\": 3")
        }

        val failure = assertFailsWith<Exception> {
            ArchivalPackager.create(project, temp.resolve("downgraded.zip"))
        }
        assertTrue(failure.message.orEmpty().contains("schema"))
    }

    @Test
    fun `historical archive gate binds local compiler facts to the profile and source bytes`() {
        val temp = createTempDirectory("acp-archive-compiler-")
        val baseline = createHistoricalAgentProject(temp.resolve("baseline"), accepted = true)
        val mutations = mapOf<String, (String) -> String>(
            "failed" to { it.replace("\"outcome\":\"passed\"", "\"outcome\":\"failed\"") },
            "source" to {
                it.replace(
                    "\"compilation\": {\"sourceSha256\":\"${sha256(baseline.resolve(SOURCE_PATH).readBytes())}\"",
                    "\"compilation\": {\"sourceSha256\":\"${"0".repeat(64)}\"",
                )
            },
            "flags" to { it.replace("\"-Werror\"", "\"-Wno-error\"") },
            "binary" to { it.replace(Regex("\"inputBinarySha256\": \"[^\"]*\""), "\"inputBinarySha256\": \"other-input\"") },
            "model-schema" to { it.replace(Regex("\"modelSchemaVersion\": [0-9]+"), "\"modelSchemaVersion\": 99") },
            "profile" to { it.replace(Regex("\"profileSha256\": \"[^\"]*\""), "\"profileSha256\": \"${"0".repeat(64)}\"") },
            "missing" to { it.replace(Regex("\"compilation\": \\{[^\\n]*}"), "\"compilation\": null") },
        )
        mutations.forEach { (name, mutation) ->
            val project = temp.resolve(name)
            copyTree(baseline, project)
            rewriteCheckpointAndManifest(project, mutation)
            assertFailsWith<Exception>(name) { ArchivalPackager.create(project, temp.resolve("$name.zip")) }
        }
    }

    @Test
    fun `independently verified historical v4 archives remain readable`() {
        val temp = createTempDirectory("acp-archive-historical-v4-")
        val project = createHistoricalAgentProject(temp.resolve("project"), accepted = true)
        rewriteCheckpointAndManifest(project) { checkpoint ->
            checkpoint.replace("\"schemaVersion\": 6", "\"schemaVersion\": 4")
                .lineSequence().filterNot { line ->
                    listOf("inputBinarySha256", "modelSchemaVersion", "profileSha256", "workflowOrigin")
                        .any { "\"$it\":" in line }
                }.joinToString("\n")
                .replace(Regex("  \"compilation\": [^\\n]*\\n"), "")
        }
        ArchivalPackager.create(project, temp.resolve("historical.zip"))
    }

    @Test
    @org.junit.jupiter.api.Tag("ci-live")
    fun `compiler read failure restores accepted ACP receipt and retains the failed attempt receipt`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "acp-compiler-read-failure-")
        try {
            for (profile in ReconstructionProfiles.builtIn) {
                val project = createAgentProject(temp.resolve(profile.id), accepted = true, profile = profile)
                val preservedPaths = listOf(SOURCE_PATH, CHECKPOINT_PATH, EVIDENCE_PATH,
                    "source_tree_manifest.json", "reports/confidence.json")
                val before = preservedPaths.associateWith { project.resolve(it).readBytes() }
                val harness = ArchiveEvidenceHarness(accepted = true, returnValueOverride = 23)
                val model = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
                    RecoveredFunction("fn_0000000000401000", "parse_input", 0x401000UL, "int parse_input(void)")))
                var candidateSha256: String? = null
                var candidateReceipt: ByteArray? = null
                val progress = object : decompengine.agent.AgentWorkflowProgress by decompengine.agent.AgentWorkflowProgress.NONE {
                    override fun phase(phase: decompengine.agent.AgentWorkflowPhase, taskId: String?, acceptedRevisionSha256: String?) {
                        if (phase == decompengine.agent.AgentWorkflowPhase.BUILD_VALIDATING) {
                            assertTrue("return 23;" in project.resolve(SOURCE_PATH).readText())
                            candidateSha256 = sha256(project.resolve(SOURCE_PATH).readBytes())
                            candidateReceipt = project.resolve(EVIDENCE_PATH).readBytes()
                            assertFalse(before.getValue(EVIDENCE_PATH).contentEquals(candidateReceipt))
                            Files.delete(project.resolve(SOURCE_PATH))
                            Files.readAllBytes(project.resolve(SOURCE_PATH))
                        }
                    }
                }
                val failure = assertFailsWith<java.nio.file.NoSuchFileException> {
                    SourceTreeGenerator.generate(model, project, profile = profile,
                        reconstructor = BoundedLlmModuleReconstructor(harness,
                            harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor),
                        observedBehavior = attributedObservation(stdoutHex = "78"), progress = progress)
                }
                assertEquals(project.resolve(SOURCE_PATH).toString(), failure.file)
                preservedPaths.forEach { assertTrue(before.getValue(it).contentEquals(project.resolve(it).readBytes()), it) }
                val attemptPath = "reports/modules/parse.attempt.execution.json"
                val attemptReceipt = project.resolve(attemptPath).readBytes()
                assertTrue(requireNotNull(candidateReceipt).contentEquals(attemptReceipt))
                val attempt = Json.parseToJsonElement(project.resolve("reports/modules/parse.attempt.json").readText()).jsonObject
                assertEquals(JsonPrimitive("validation-failed"), attempt.getValue("status"))
                assertEquals(JsonPrimitive(candidateSha256), attempt.getValue("candidateSourceSha256"))
                assertEquals(JsonPrimitive(sha256(before.getValue(SOURCE_PATH))), attempt.getValue("previousAcceptedSourceSha256"))
                assertEquals(JsonPrimitive(attemptPath), attempt.getValue("executionEvidencePath"))
                assertEquals(JsonPrimitive(sha256(attemptReceipt)), attempt.getValue("executionEvidenceSha256"))
                assertEquals(JsonPrimitive("returned-completed"), attempt.getValue("executionTerminalOutcome"))
                val manifest = SourceTreeManifestReader.read(project, profile)
                assertEquals(1, ReconstructionAcpEvidenceArchiveVerifier.verify(project,
                    manifest.files.associate { it.path to sha256(project.resolve(it.path).readBytes()) },
                    manifest.files.associate { it.path to Files.size(project.resolve(it.path)) }, manifest, profile).size)
            }
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    @org.junit.jupiter.api.Tag("ci-live")
    fun `rejected ACP revision retains its receipt and restores accepted release evidence`() {
        val temp = createTempDirectory("acp-rejected-revision-")
        val project = createAgentProject(temp.resolve("project"), accepted = true)
        val preservedPaths = listOf(SOURCE_PATH, CHECKPOINT_PATH, EVIDENCE_PATH)
        val before = preservedPaths.associateWith { project.resolve(it).readText() }
        val harness = ArchiveEvidenceHarness(accepted = false)
        val model = RecoveredProgramModel(
            inputSha256 = "a".repeat(64),
            functions = listOf(RecoveredFunction("fn_0000000000401000", "parse_input", 0x401000UL, "int parse_input(void)")),
        )

        assertFailsWith<ModuleReconstructionRevisionRejectedException> {
            SourceTreeGenerator.generate(
                model, project,
                reconstructor = BoundedLlmModuleReconstructor(harness, harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor),
                observedBehavior = "new module evidence",
            )
        }

        preservedPaths.forEach { assertEquals(before.getValue(it), project.resolve(it).readText(), it) }
        val attemptReceipt = project.resolve("reports/modules/parse.attempt.execution.json")
        assertTrue(attemptReceipt.exists())
        assertTrue(project.resolve("reports/modules/parse.attempt.json").readText().contains("parse.attempt.execution.json"))
        SourceTreeGenerator.generate(
            model, project,
            reconstructor = BoundedLlmModuleReconstructor(harness, harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor),
        )
        assertFalse(attemptReceipt.exists())
        MakeProjectBuilder.build(project)
        ArchivalPackager.create(project, temp.resolve("preserved.zip"))
    }

    @Test
    fun `archive gate rejects missing and extra ACP evidence artifacts`() {
        val temp = createTempDirectory("acp-archive-cardinality-")
        val baseline = createHistoricalAgentProject(temp.resolve("baseline"), accepted = true)

        val missing = temp.resolve("missing")
        copyTree(baseline, missing)
        missing.resolve(EVIDENCE_PATH).deleteExisting()
        assertFailsWith<Exception> {
            ArchivalPackager.create(missing, temp.resolve("missing.zip"))
        }

        val extra = temp.resolve("extra")
        copyTree(baseline, extra)
        extra.resolve("reports/agent-executions/stale.json").writeText("{}\n")
        val extraFailure = assertFailsWith<Exception> {
            ArchivalPackager.create(extra, temp.resolve("extra.zip"))
        }
        assertTrue(extraFailure.message.orEmpty().contains("extra") || extraFailure.message.orEmpty().contains("stale"))
    }

    @Test
    @org.junit.jupiter.api.Tag("ci-live")
    fun `archive gate rejects an agent-generated unresolved module`() {
        val temp = createTempDirectory("acp-archive-unresolved-")
        val project = createAgentProject(temp.resolve("project"), accepted = false)

        val failure = assertFailsWith<Exception> {
            ArchivalPackager.create(project, temp.resolve("unresolved.zip"))
        }

        assertTrue(failure.message.orEmpty().contains("not accepted") || failure.message.orEmpty().contains("unresolved"))
    }

    @Test
    @org.junit.jupiter.api.Tag("ci-live")
    fun `rehashed rejected ACP candidates cannot impersonate undispatched budget fallbacks`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "forged-fallback-replay-")
        try {
            val baseline = createAgentProject(temp.resolve("baseline"), accepted = false)
            val original = Json.parseToJsonElement(baseline.resolve(CHECKPOINT_PATH).readText()).jsonObject
            assertEquals(JsonPrimitive(false), original.getValue("accepted"))
            assertEquals(JsonPrimitive("reconstructor-return"), original.getValue("workflowOrigin"))
            assertTrue(baseline.resolve(EVIDENCE_PATH).exists())
            val sourceSha256 = sha256(baseline.resolve(SOURCE_PATH).readBytes())
            val profile = GeneratedCMakeReconstructionProfile.descriptor
            val model = ProgramModelJson.read(baseline.resolve("reports/program_model.json").readText())
            val plan = ModulePlanJson.readCanonical(baseline.resolve("reports/module_plan.json").readBytes(), 4 * 1024 * 1024)
            val inputs = ProfileModulePromptInputs(model, plan, profile)
            val identity = original.getValue("reconstructorIdentity").jsonPrimitive.content
                .replace(Regex(":context-[0-9]+:factory-"), ":context-4096:factory-")

            for (paddedObservation in listOf(false, true)) {
                val name = if (paddedObservation) "padded-observation" else "fabricated-prompt"
                val project = temp.resolve(name)
                copyTree(baseline, project)
                val observed = if (paddedObservation) attributedObservation(stdoutHex = "78".repeat(2_048)) else null
                val request = inputs.request("parse", project, observed)
                val prompt = modulePromptEvidence(request).text
                assertEquals(paddedObservation, prompt.length > 4_096)
                val claimedCharacters = if (paddedObservation) prompt.length else prompt.length + 4_096
                val forged = JsonObject(original + mapOf(
                    "generator" to JsonPrimitive("unresolved:$identity"),
                    "reconstructorIdentity" to JsonPrimitive(identity),
                    "workflowOrigin" to JsonPrimitive("pre-dispatch-context-budget-fallback"),
                    "preDispatchObservedBehavior" to (observed?.let(::JsonPrimitive) ?: JsonNull),
                    "promptCharacters" to JsonPrimitive(claimedCharacters),
                    "promptBudgetCharacters" to JsonPrimitive(4_096),
                    "promptSha256" to JsonPrimitive(sha256(prompt.toByteArray())),
                    "fingerprint" to JsonPrimitive(inputs.fingerprint(request)),
                    "executionEvidencePath" to JsonNull,
                    "executionEvidenceSha256" to JsonNull,
                    "executionEvidenceSchemaVersion" to JsonNull,
                    "executionRequestSha256" to JsonNull,
                    "executionTerminalOutcome" to JsonNull,
                    "executionReleaseComplete" to JsonNull,
                    "issues" to JsonArray(listOf(JsonObject(mapOf(
                        "code" to JsonPrimitive("context-budget-exceeded"),
                        "message" to JsonPrimitive("module context required $claimedCharacters characters; limit=4096"),
                        "entityIds" to JsonArray(request.module.functionIds.map(::JsonPrimitive)),
                    )))),
                ))
                rewriteCheckpointConfidenceAndManifest(project, forged, removeExecutionEvidence = true)
                assertEquals(sourceSha256, sha256(project.resolve(SOURCE_PATH).readBytes()))
                assertFalse(project.resolve(EVIDENCE_PATH).exists())
                // The padded case carries a valid prompt commitment and input fingerprint, but
                // retains the rejected harness output instead of the profile's deterministic stub.
                val expected = if (paddedObservation) "fallback source differs" else "fallback prompt differs"
                val auditFailure = assertFailsWith<IllegalArgumentException>(name) {
                    ArchivalProjectAuditor.audit(project)
                }
                assertTrue(auditFailure.message.orEmpty().contains(expected), "$name: ${auditFailure.message}")
                assertFalse(project.resolve("reports/archival_audit.json").exists())
                val archive = temp.resolve("$name.zip")
                val failure = assertFailsWith<IllegalArgumentException>(name) {
                    ArchivalPackager.create(project, archive)
                }
                assertTrue(failure.message.orEmpty().contains(expected), "$name: ${failure.message}")
                assertFalse(archive.exists())
            }
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun `undispatched fallback rejects rehashed compiler claims for every supported outcome`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "fallback-compiler-claims-")
        try {
            val baseline = temp.resolve("baseline")
            val profile = GeneratedCMakeReconstructionProfile.descriptor
            val manifest = SourceTreeGenerator.generate(
                RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
                    RecoveredFunction("fn_0000000000401000", "parse_input", 0x401000UL,
                        "int parse_input(void)", "/* ${"context".repeat(2_000)} */"))),
                baseline,
                reconstructor = BoundedLlmModuleReconstructor(
                    AgentHarness { _, _ -> error("oversized prompt must not dispatch") },
                    maximumContextCharacters = 4_096,
                ),
            )
            val checkpoint = Json.parseToJsonElement(baseline.resolve(CHECKPOINT_PATH).readText()).jsonObject
            assertEquals(JsonPrimitive("pre-dispatch-context-budget-fallback"), checkpoint.getValue("workflowOrigin"))
            assertEquals(JsonNull, checkpoint.getValue("compilation"))
            assertTrue(ReconstructionAcpEvidenceArchiveVerifier.verify(baseline,
                manifest.files.associate { it.path to sha256(baseline.resolve(it.path).readBytes()) },
                manifest.files.associate { it.path to Files.size(baseline.resolve(it.path)) }, manifest, profile).isEmpty())
            assertEquals(0, MakeProjectBuilder.build(baseline).returnCode)
            ArchivalPackager.create(baseline, temp.resolve("baseline.zip"))
            for (outcome in listOf("passed", "failed", "failed-to-start", "timed-out", "source-changed", "output-limit-exceeded")) {
                val project = temp.resolve(outcome)
                copyTree(baseline, project)
                Files.deleteIfExists(project.resolve("reports/archival_audit.json"))
                val compilation = JsonObject(mapOf(
                    "sourceSha256" to checkpoint.getValue("sourceSha256"),
                    "command" to JsonArray(ReconstructionCompilationPolicies.resolve(profile)
                        .command(profile, SOURCE_PATH).map(::JsonPrimitive)),
                    "outcome" to JsonPrimitive(outcome),
                    "returnCode" to when (outcome) {
                        "passed" -> JsonPrimitive(0)
                        "failed" -> JsonPrimitive(1)
                        else -> JsonNull
                    },
                    "diagnosticsSha256" to JsonPrimitive(sha256(byteArrayOf())),
                    "diagnosticsBytes" to JsonPrimitive(0),
                ))
                rewriteCheckpointConfidenceAndManifest(project, JsonObject(checkpoint + ("compilation" to compilation)))
                val confidence = Json.parseToJsonElement(project.resolve("reports/confidence.json").readText()).jsonObject
                assertEquals(compilation, confidence.getValue("modules").jsonArray.single().jsonObject
                    .getValue("revisionEvidence").jsonObject.getValue("compilation"))
                val auditFailure = assertFailsWith<IllegalArgumentException>(outcome) { ArchivalProjectAuditor.audit(project) }
                assertTrue(auditFailure.message.orEmpty().contains("pre-dispatch fallback retains compiler evidence"), auditFailure.message)
                assertFalse(project.resolve("reports/archival_audit.json").exists())
                val archive = temp.resolve("$outcome.zip")
                val archiveFailure = assertFailsWith<IllegalArgumentException>(outcome) { ArchivalPackager.create(project, archive) }
                assertTrue(archiveFailure.message.orEmpty().contains("pre-dispatch fallback retains compiler evidence"), archiveFailure.message)
                assertFalse(archive.exists())
            }
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun `legacy null observation fallback passes independently replayed model overflow`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "legacy-fallback-replay-")
        try {
            val project = temp.resolve("project")
            SourceTreeGenerator.generate(
                RecoveredProgramModel(
                    inputSha256 = "a".repeat(64),
                    functions = listOf(RecoveredFunction(
                        "fn_0000000000401000", "parse_input", 0x401000UL, "int parse_input(void)",
                        "/* ${"context".repeat(2_000)} */",
                        referencedGlobals = setOf("aa_global"),
                    )),
                    // Manifest entity IDs are sorted globally, not functions-before-globals.
                    globals = listOf(RecoveredGlobal("aa_global", "parse_counter", 0x402000UL, "int", "7")),
                ),
                project,
                reconstructor = BoundedLlmModuleReconstructor(
                    AgentHarness { _, _ -> error("oversized prompt must not dispatch") },
                    maximumContextCharacters = 4_096,
                ),
            )
            val checkpoint = Json.parseToJsonElement(project.resolve(CHECKPOINT_PATH).readText()).jsonObject
            assertEquals(JsonPrimitive("pre-dispatch-context-budget-fallback"), checkpoint.getValue("workflowOrigin"))
            assertEquals(JsonNull, checkpoint.getValue("preDispatchObservedBehavior"))
            assertEquals(listOf("aa_global", "fn_0000000000401000"),
                checkpoint.getValue("entityStatuses").jsonArray.map { it.jsonObject.getValue("id").jsonPrimitive.content })
            assertEquals(0, MakeProjectBuilder.build(project).returnCode)
            ArchivalPackager.create(project, temp.resolve("current.zip"))

            rewriteCheckpointConfidenceAndManifest(project, JsonObject(checkpoint - "preDispatchObservedBehavior"))
            val archive = temp.resolve("legacy.zip")
            ArchivalPackager.create(project, archive)
            assertTrue(archive.exists())
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun `all fallback archives reject rehashed confidence claims`() = verifyFallbackConfidence(withAccepted = false)

    @Test
    @org.junit.jupiter.api.Tag("ci-live")
    fun `mixed current accepted archives reject rehashed confidence claims`() = verifyFallbackConfidence(withAccepted = true)

    private fun verifyFallbackConfidence(withAccepted: Boolean) {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "fallback-confidence-")
        try {
            run {
                val project = temp.resolve(if (withAccepted) "mixed" else "all-fallback")
                val harness = ArchiveEvidenceHarness(accepted = true)
                val oversizedEvidence = "/* ${"context".repeat(2_000)} */"
                val manifest = SourceTreeGenerator.generate(
                    RecoveredProgramModel(
                        inputSha256 = "a".repeat(64),
                        functions = listOf(
                            RecoveredFunction("fn_0000000000401000", "parse_input", 0x401000UL,
                                "int parse_input(void)", if (withAccepted) null else oversizedEvidence),
                            RecoveredFunction("fn_beta", "beta_read", 0x402000UL,
                                "int beta_read(void)", oversizedEvidence),
                        ),
                    ),
                    project,
                    reconstructor = BoundedLlmModuleReconstructor(
                        harness, maximumContextCharacters = 4_096,
                        harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor,
                    ),
                )
                assertEquals(withAccepted, manifest.files.single { it.path == SOURCE_PATH }.acceptedImplementation)
                assertTrue("fn_beta" in manifest.unresolvedImplementationIds)
                val baselineAudit = ArchivalProjectAuditor.audit(project)
                assertTrue(baselineAudit.moduleConfidenceEvidenceProblems.isEmpty())
                assertEquals(0, MakeProjectBuilder.build(project).returnCode)
                ArchivalPackager.create(project, temp.resolve("baseline-$withAccepted.zip"))

                val confidencePath = project.resolve("reports/confidence.json")
                val confidenceBytes = confidencePath.readBytes()
                val report = Json.parseToJsonElement(confidenceBytes.decodeToString()).jsonObject
                val manifestText = project.resolve("source_tree_manifest.json").readText()
                fun field(record: JsonObject, name: String, value: JsonElement) = JsonObject(record + (name to value))
                fun revision(report: JsonObject, moduleId: String, change: (JsonObject) -> JsonObject): JsonObject =
                    field(report, "modules", JsonArray(report.getValue("modules").jsonArray.map { item ->
                        val module = item.jsonObject
                        if (module.getValue("id").jsonPrimitive.content == moduleId) {
                            field(module, "revisionEvidence", change(module.getValue("revisionEvidence").jsonObject))
                        } else module
                    }))
                val mutations = linkedMapOf<String, (JsonObject) -> JsonObject>(
                    "outer-unresolved" to { field(it, "unresolvedImplementationIds", JsonArray(emptyList())) },
                    "source-digest" to { revision(it, "beta") { value -> field(value, "sourceSha256", JsonPrimitive("0".repeat(64))) } },
                    "accepted" to { revision(it, "beta") { value -> field(value, "acceptedImplementation", JsonPrimitive(true)) } },
                    "compilation" to { revision(it, "beta") { value ->
                        field(value, "compilation", JsonObject(mapOf("outcome" to JsonPrimitive("passed"))))
                    } },
                    "behavior-status" to { revision(it, "beta") { value ->
                        field(value, "behavior", field(value.getValue("behavior").jsonObject, "status", JsonPrimitive("matched")))
                    } },
                    "behavior-reason" to { revision(it, "beta") { value ->
                        field(value, "behavior", field(value.getValue("behavior").jsonObject, "reason", JsonPrimitive("all behavior verified")))
                    } },
                    "behavior-coverage" to { revision(it, "beta") { value ->
                        field(value, "behavior", field(value.getValue("behavior").jsonObject, "coverage", JsonPrimitive(1.0)))
                    } },
                )
                if (withAccepted) {
                    // This failure is handled by the separate accepted-revision catch.
                    mutations["accepted-source-digest"] = { revision(it, "parse") { value ->
                        field(value, "sourceSha256", JsonPrimitive("0".repeat(64)))
                    } }
                }
                for ((name, mutate) in mutations) {
                    val changed = (mutate(report).toString() + "\n").toByteArray()
                    confidencePath.writeText(changed.decodeToString())
                    project.resolve("source_tree_manifest.json").writeText(
                        manifestText.replace(sha256(confidenceBytes), sha256(changed)),
                    )
                    val expected = when (name) {
                        "outer-unresolved" -> "confidence unresolvedImplementationIds differs"
                        "accepted-source-digest" -> "accepted module confidence evidence"
                        else -> "fallback module confidence evidence"
                    }
                    val auditFailure = assertFailsWith<IllegalArgumentException>("$withAccepted/$name") {
                        ArchivalProjectAuditor.audit(project)
                    }
                    assertTrue(auditFailure.message.orEmpty().contains(expected), "$name: ${auditFailure.message}")
                    val archive = temp.resolve("$withAccepted-$name.zip")
                    val archiveFailure = assertFailsWith<IllegalArgumentException>("$withAccepted/$name") {
                        ArchivalPackager.create(project, archive)
                    }
                    assertTrue(archiveFailure.message.orEmpty().contains(expected), "$name: ${archiveFailure.message}")
                    assertFalse(archive.exists())
                }
            }
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    private fun attributedObservation(stdoutHex: String, cases: Int = 1): String =
        ModuleObservedBehavior.envelope("a".repeat(64), (0 until cases).map { index ->
            ModuleObservedCase("case-$index",
                ModuleObservationAttribution(listOf("fn_0000000000401000"), "b".repeat(64)),
                emptyList(), "", 0, stdoutHex, "")
        }).toString()

    /** Exact pinned schema-six producer output: this never runs a current compiler or mints a permit. */
    private fun createHistoricalAgentProject(
        project: Path,
        accepted: Boolean,
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
    ): Path {
        require(accepted)
        val bytes = requireNotNull(javaClass.getResourceAsStream(
            "/project/historical-module-local-v6/${profile.id}.zip")).use { it.readBytes() }
        val expected = when (profile.id) {
            "generated-c-make-v1" -> "f5ea388c658d49c19176b0bd85d2315769c053d90094377c48a7d94741a5b891"
            "generated-c-ninja-v1" -> "fb2cb1658e73294f74b0fcd765e65a450e26541a6b0c38263e0a4dd95e8e95bd"
            else -> error("no pinned historical fixture for ${profile.id}")
        }
        assertEquals(expected, sha256(bytes))
        Files.createDirectories(project.parent)
        val archive = project.resolveSibling("${project.fileName}.historical.zip")
        Files.write(archive, bytes)
        ArchivalBundleVerifier.extractAndVerify(archive, project, profile = profile)
        // The portable fixture intentionally omits host build outputs. Rebuild only the
        // archive build artifact; the retained schema-six compiler record stays untouched.
        assertEquals(0, ReconstructionAdapters.resolve(profile).build(project, profile).returnCode)
        return project
    }

    private fun createAgentProject(
        project: Path,
        accepted: Boolean,
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
        harness: ArchiveEvidenceHarness = ArchiveEvidenceHarness(accepted),
    ): Path {
        SourceTreeGenerator.generate(
            RecoveredProgramModel(
                inputSha256 = "a".repeat(64),
                functions = listOf(
                    RecoveredFunction(
                        "fn_0000000000401000",
                        "parse_input",
                        0x401000UL,
                        "int parse_input(void)",
                    ),
                ),
            ),
            project,
            reconstructor = BoundedLlmModuleReconstructor(
                harness,
                harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor,
            ),
            profile = profile,
        )
        assertEquals(0, ReconstructionAdapters.resolve(profile).build(project, profile).returnCode)
        return project
    }

    private fun rewriteEvidenceAndBindings(project: Path, transform: (String) -> String) {
        val evidence = project.resolve(EVIDENCE_PATH)
        val oldEvidenceSha256 = sha256(evidence.readBytes())
        val transformed = transform(evidence.readText())
        require(transformed != evidence.readText()) { "test mutation did not change ACP evidence" }
        evidence.writeText(transformed)
        val newEvidenceSha256 = sha256(evidence.readBytes())

        val checkpoint = Json.parseToJsonElement(project.resolve(CHECKPOINT_PATH).readText()).jsonObject
        require(checkpoint.getValue("executionEvidenceSha256") == JsonPrimitive(oldEvidenceSha256))
        rewriteCheckpointConfidenceAndManifest(project, JsonObject(checkpoint +
            ("executionEvidenceSha256" to JsonPrimitive(newEvidenceSha256))))
        val manifestPath = project.resolve("source_tree_manifest.json")
        val manifest = Json.parseToJsonElement(manifestPath.readText()).jsonObject
        val files = manifest.getValue("files").jsonArray.map { item ->
            val file = item.jsonObject
            if (file.getValue("path").jsonPrimitive.content != EVIDENCE_PATH) file else {
                require(file.getValue("sha256") == JsonPrimitive(oldEvidenceSha256))
                JsonObject(file + ("sha256" to JsonPrimitive(newEvidenceSha256)))
            }
        }
        manifestPath.writeText(JsonObject(manifest + ("files" to JsonArray(files))).toString() + "\n")
    }

    private fun rewriteCheckpointAndManifest(project: Path, transform: (String) -> String) {
        val checkpoint = project.resolve(CHECKPOINT_PATH)
        val oldSha256 = sha256(checkpoint.readBytes())
        val transformed = transform(checkpoint.readText())
        require(transformed != checkpoint.readText()) { "test mutation did not change checkpoint" }
        checkpoint.writeText(transformed)
        val newSha256 = sha256(checkpoint.readBytes())
        val manifest = project.resolve("source_tree_manifest.json")
        manifest.writeText(manifest.readText().replace(oldSha256, newSha256))
    }

    /** Rebind every mutable commitment so tamper cases reach semantic fallback validation. */
    private fun rewriteCheckpointConfidenceAndManifest(
        project: Path,
        checkpoint: JsonObject,
        removeExecutionEvidence: Boolean = false,
    ) {
        val checkpointBytes = (checkpoint.toString() + "\n").toByteArray()
        Files.write(project.resolve(CHECKPOINT_PATH), checkpointBytes)
        val confidencePath = project.resolve("reports/confidence.json")
        val confidence = Json.parseToJsonElement(confidencePath.readText()).jsonObject
        val modules = confidence.getValue("modules").jsonArray.map { item ->
            val module = item.jsonObject
            if (module.getValue("id").jsonPrimitive.content != "parse") module else {
                val revision = module.getValue("revisionEvidence").jsonObject
                JsonObject(module + ("revisionEvidence" to JsonObject(revision + mapOf(
                    "checkpointSha256" to JsonPrimitive(sha256(checkpointBytes)),
                    "sourceSha256" to checkpoint.getValue("sourceSha256"),
                    "inputFingerprint" to checkpoint.getValue("fingerprint"),
                    "acceptedImplementation" to checkpoint.getValue("accepted"),
                    "compilation" to checkpoint.getValue("compilation"),
                ))))
            }
        }
        val confidenceBytes = (JsonObject(confidence + ("modules" to JsonArray(modules))).toString() + "\n").toByteArray()
        Files.write(confidencePath, confidenceBytes)
        val manifestPath = project.resolve("source_tree_manifest.json")
        val manifest = Json.parseToJsonElement(manifestPath.readText()).jsonObject
        val files = manifest.getValue("files").jsonArray.mapNotNull { item ->
            val file = item.jsonObject
            when (file.getValue("path").jsonPrimitive.content) {
                EVIDENCE_PATH -> if (removeExecutionEvidence) null else file
                CHECKPOINT_PATH -> JsonObject(file + ("sha256" to JsonPrimitive(sha256(checkpointBytes))))
                "reports/confidence.json" -> JsonObject(file + ("sha256" to JsonPrimitive(sha256(confidenceBytes))))
                SOURCE_PATH -> JsonObject(file + mapOf(
                    "generator" to checkpoint.getValue("generator"),
                    "promptSha256" to checkpoint.getValue("promptSha256"),
                    "acceptedImplementation" to checkpoint.getValue("accepted"),
                ))
                else -> file
            }
        }
        manifestPath.writeText(JsonObject(manifest + ("files" to JsonArray(files))).toString() + "\n")
        if (removeExecutionEvidence) Files.delete(project.resolve(EVIDENCE_PATH))
    }

    private fun copyTree(source: Path, destination: Path) {
        Files.walk(source).use { paths ->
            paths.forEach { path ->
                val target = destination.resolve(path.relativeTo(source).toString())
                if (Files.isDirectory(path)) {
                    target.createDirectories()
                } else {
                    target.parent.createDirectories()
                    Files.copy(path, target, StandardCopyOption.COPY_ATTRIBUTES)
                }
            }
        }
    }

    private class ArchiveEvidenceHarness(
        private val accepted: Boolean,
        private val wirePromptOverride: String? = null,
        private val returnValueOverride: Int? = null,
    ) : AgentHarness {
        private var evidence: AcpExecutionEvidenceSnapshot? = null
        private lateinit var requestBinding: AgentExecutionRequestBinding
        lateinit var executedRequest: AgentExecutionRequest
            private set
        val factoryProvenance = AcpHarnessProvenance(
            harness = "acp",
            implementationId = IMPLEMENTATION_ID,
            agentExecutionContractVersion = 1,
            acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION,
            acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
            configurationSha256 = "b".repeat(64),
            deprecated = false,
        )

        override fun implementationIdentifier(): String = IMPLEMENTATION_ID

        override fun execute(
            request: AgentExecutionRequest,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionResult {
            executedRequest = request
            requestBinding = AgentExecutionRequestBinding.capture(request)
            val target = request.accessPolicy.pathRules.single { rule ->
                decompengine.agent.AgentOperation.WRITE_FILE in rule.operations
            }.path
            val returnValue = returnValueOverride ?: if (accepted) 17 else 0
            val source = """
                #include "modules/parse.h"
                /* fn_0000000000401000 */
                int parse_input(void) { return $returnValue; }
            """.trimIndent() + "\n"
            val targetFile = target.resolve(request.workspaceRoots)
            val before = targetFile.takeIf { it.exists() }?.readBytes()
            targetFile.writeText(source)
            val bytes = source.toByteArray()
            val change = AgentFileChange(
                target,
                if (before == null) AgentFileChangeKind.CREATED else AgentFileChangeKind.MODIFIED,
                beforeSha256 = before?.let(::sha256),
                afterSha256 = sha256(bytes),
                sizeBytes = bytes.size.toLong(),
            )
            onEvent(AgentMessageEvent(0, "message", AgentMessageRole.ASSISTANT, "working", true))
            onEvent(decompengine.agent.AgentContextUsageEvent(1, 1024, 8192, 0.125, "USD"))
            onEvent(AgentFileChangeEvent(2, change))
            evidence = snapshot()
            return AgentExecutionResult(
                AgentStopReason.COMPLETED,
                "complete",
                listOf(change),
                AgentSessionReference(IMPLEMENTATION_ID, "session"),
                AgentUsage(10, 20, 3, 0, Duration.ofMillis(100)),
            )
        }

        override fun executeReceipt(
            request: AgentExecutionRequest,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionReceipt {
            val result = execute(request, onEvent)
            val complete = requireNotNull(evidence)
            return AgentExecutionReceipt(
                requestBinding,
                AgentExecutionOutcome.Returned(result),
                AcpInvocationEvidenceSnapshot(
                    factoryProvenance = complete.factoryProvenance,
                    phaseReached = AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT,
                    cleanupDisposition = AcpExecutionCleanupDisposition.VERIFIED,
                    negotiatedAgent = complete.negotiatedAgent,
                    wirePromptSha256 = complete.wirePromptSha256,
                    diagnostics = complete.diagnostics,
                    filesystemAudit = complete.filesystemAudit,
                    terminalAudit = complete.terminalAudit,
                    permissionAudit = complete.permissionAudit,
                    sandboxEvidence = complete.sandboxEvidence,
                    completeness = AcpExecutionEvidenceCompleteness(true, true, true),
                    completeExecutionEvidence = complete,
                ),
            )
        }

        private fun snapshot(): AcpExecutionEvidenceSnapshot = AcpExecutionEvidenceSnapshot(
            factoryProvenance = factoryProvenance,
            negotiatedAgent = AcpNegotiatedAgentEvidence(
                ACP_STABLE_PROTOCOL_VERSION,
                "archive-test-agent",
                "1",
                null,
                AcpNegotiatedCapabilitiesEvidence(false, false, false, false, false, false, false),
            ),
            wirePromptSha256 = wirePromptOverride ?:
                sha256(renderAgentPrompt(executedRequest.objective, executedRequest.contextInputs).toByteArray()),
            diagnostics = AcpProcessDiagnostics(
                pid = 123,
                exitCode = 0,
                stderr = "",
                stderrTruncated = false,
                producedOutputBytes = 0,
                producedOutputLimitBytes = 1_024,
                outputLimitExceeded = false,
                forcedTermination = false,
                rootTerminationRequested = false,
                remainingProcessIds = emptyList(),
                containment = "linux-bubblewrap",
                networkIsolated = true,
                sandboxCleanupVerified = true,
            ),
            filesystemAudit = emptyList(),
            terminalAudit = emptyList(),
            permissionAudit = emptyList(),
            sandboxEvidence = AcpSandboxEvidence(
                provider = "sandbox-evidence-v1",
                providerVersion = "1",
                providerExecutableSha256 = "d".repeat(64),
                providerExecutableMode = 365,
                resourceLimiterSha256 = "e".repeat(64),
                scopeSupervisorSha256 = "f".repeat(64),
                scopeInspectorSha256 = "1".repeat(64),
                environmentFdOpenerSha256 = "2".repeat(64),
                securityExecutables = emptyList(),
                outerAgentLimits = AcpSandboxResourceLimits(),
                runtimeClosureLimits = AcpRuntimeClosureLimits(),
                cgroupV2PidsLimited = true,
                cgroupV2MemoryLimited = true,
                cgroupV2CpuLimited = true,
                networkIsolated = true,
                outerAgentContained = true,
                nestedUserNamespacesDisabled = true,
                newSession = true,
                dieWithParent = true,
                policySha256 = "3".repeat(64),
                terminalLimits = null,
                launches = emptyList(),
                authorities = emptyList(),
                terminalAudit = emptyList(),
                outerProcessOutput = AcpProducedOutputEvidence(1_024, 0, false),
            ),
        )
    }

    private companion object {
        const val IMPLEMENTATION_ID = "archive-test-acp"
        const val SOURCE_PATH = "src/modules/parse.c"
        const val CHECKPOINT_PATH = "reports/modules/parse.json"
        const val EVIDENCE_PATH = "reports/agent-executions/parse.json"
        const val EVIDENCE_KIND = "decomp-engine.reconstruction-acp-execution-receipt"

        fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it) }
    }
}
