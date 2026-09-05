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

class ReconstructionAcpEvidenceArchiveVerifierTest {
    @Test
    fun `archive gate rejects closed-schema and semantic ACP evidence tampering`() {
        val temp = createTempDirectory("acp-archive-tampering-")
        val baseline = createAgentProject(temp.resolve("baseline"), accepted = true)
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
    fun `archive gate rejects checkpoint path and digest ambiguity`() {
        val temp = createTempDirectory("acp-archive-checkpoint-")
        val baseline = createAgentProject(temp.resolve("baseline"), accepted = true)

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
                        Regex("factory-[0-9a-f]{64}:v2"),
                        "factory-${"0".repeat(64)}:v2",
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
        val project = createAgentProject(temp.resolve("project"), accepted = true)
        rewriteCheckpointAndManifest(project) { checkpoint ->
            checkpoint.replaceFirst("\"schemaVersion\": 5", "\"schemaVersion\": 3")
        }

        val failure = assertFailsWith<Exception> {
            ArchivalPackager.create(project, temp.resolve("downgraded.zip"))
        }
        assertTrue(failure.message.orEmpty().contains("schema"))
    }

    @Test
    fun `archive gate binds compiler acceptance to the profile and source bytes`() {
        val temp = createTempDirectory("acp-archive-compiler-")
        val baseline = createAgentProject(temp.resolve("baseline"), accepted = true)
        val mutations = mapOf<String, (String) -> String>(
            "failed" to { it.replace("\"outcome\":\"passed\"", "\"outcome\":\"failed\"") },
            "source" to {
                it.replace(
                    "\"compilation\": {\"sourceSha256\":\"${sha256(baseline.resolve(SOURCE_PATH).readBytes())}\"",
                    "\"compilation\": {\"sourceSha256\":\"${"0".repeat(64)}\"",
                )
            },
            "flags" to { it.replace("\"-Werror\"", "\"-Wno-error\"") },
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
        val project = createAgentProject(temp.resolve("project"), accepted = true)
        rewriteCheckpointAndManifest(project) { checkpoint ->
            checkpoint.replace("\"schemaVersion\": 5", "\"schemaVersion\": 4")
                .replace(Regex("  \"compilation\": [^\\n]*\\n"), "")
        }
        ArchivalPackager.create(project, temp.resolve("historical.zip"))
    }

    @Test
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
        val baseline = createAgentProject(temp.resolve("baseline"), accepted = true)

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
    fun `archive gate rejects an agent-generated unresolved module`() {
        val temp = createTempDirectory("acp-archive-unresolved-")
        val project = createAgentProject(temp.resolve("project"), accepted = false)

        val failure = assertFailsWith<Exception> {
            ArchivalPackager.create(project, temp.resolve("unresolved.zip"))
        }

        assertTrue(failure.message.orEmpty().contains("not accepted") || failure.message.orEmpty().contains("unresolved"))
    }

    private fun createAgentProject(project: Path, accepted: Boolean): Path {
        val harness = ArchiveEvidenceHarness(accepted)
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
        )
        MakeProjectBuilder.build(project)
        return project
    }

    private fun rewriteEvidenceAndBindings(project: Path, transform: (String) -> String) {
        val evidence = project.resolve(EVIDENCE_PATH)
        val oldEvidenceSha256 = sha256(evidence.readBytes())
        val transformed = transform(evidence.readText())
        require(transformed != evidence.readText()) { "test mutation did not change ACP evidence" }
        evidence.writeText(transformed)
        val newEvidenceSha256 = sha256(evidence.readBytes())

        val checkpoint = project.resolve(CHECKPOINT_PATH)
        val oldCheckpointSha256 = sha256(checkpoint.readBytes())
        checkpoint.writeText(checkpoint.readText().replace(oldEvidenceSha256, newEvidenceSha256))
        val newCheckpointSha256 = sha256(checkpoint.readBytes())

        val manifest = project.resolve("source_tree_manifest.json")
        manifest.writeText(
            manifest.readText()
                .replace(oldEvidenceSha256, newEvidenceSha256)
                .replace(oldCheckpointSha256, newCheckpointSha256),
        )
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

    private class ArchiveEvidenceHarness(private val accepted: Boolean) : AgentHarness {
        private var evidence: AcpExecutionEvidenceSnapshot? = null
        private lateinit var requestBinding: AgentExecutionRequestBinding
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
            requestBinding = AgentExecutionRequestBinding.capture(request)
            val target = request.accessPolicy.pathRules.single { rule ->
                decompengine.agent.AgentOperation.WRITE_FILE in rule.operations
            }.path
            val returnValue = if (accepted) 17 else 0
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
            onEvent(AgentFileChangeEvent(1, change))
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
            wirePromptSha256 = "c".repeat(64),
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
