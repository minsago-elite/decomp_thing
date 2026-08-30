package decompengine.project

import com.agentclientprotocol.model.PermissionOptionKind
import decompengine.acp.ACP_KOTLIN_SDK_VERSION
import decompengine.acp.ACP_STABLE_PROTOCOL_VERSION
import decompengine.acp.AcpExecutionEvidenceSnapshot
import decompengine.acp.AcpExecutionEvidenceSource
import decompengine.acp.AcpFilesystemAuditOutcome
import decompengine.acp.AcpFilesystemAuditReason
import decompengine.acp.AcpFilesystemAuditRecord
import decompengine.acp.AcpHarnessProvenance
import decompengine.acp.AcpNegotiatedAgentEvidence
import decompengine.acp.AcpNegotiatedCapabilitiesEvidence
import decompengine.acp.AcpPermissionAuditOutcome
import decompengine.acp.AcpPermissionAuditReason
import decompengine.acp.AcpPermissionAuditRecord
import decompengine.acp.AcpProcessDiagnostics
import decompengine.acp.AcpProducedOutputEvidence
import decompengine.acp.AcpRuntimeClosureLimits
import decompengine.acp.AcpSandboxEvidence
import decompengine.acp.AcpSandboxResourceLimits
import decompengine.acp.AcpTerminalAuditOutcome
import decompengine.acp.AcpTerminalAuditReason
import decompengine.acp.AcpTerminalAuditRecord
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentMessageEvent
import decompengine.agent.AgentMessageRole
import decompengine.agent.AgentPermissionDecision
import decompengine.agent.AgentPermissionEvent
import decompengine.agent.AgentSessionReference
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentToolEvent
import decompengine.agent.AgentToolStatus
import decompengine.agent.AgentUsage
import java.time.Duration
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AgentExecutionEvidenceTest {
    @Test
    fun `tool detail commitments cannot move delimiters between keys and values`() {
        assertNotEquals(
            digestCanonicalEvidenceMap(mapOf("a" to "b\u0000c")),
            digestCanonicalEvidenceMap(mapOf("a\u0000b" to "c")),
        )
    }

    @Test
    fun `ACP reconstruction archives bounded execution and validation evidence`() {
        val temp = createTempDirectory("acp-execution-evidence-")
        val project = temp.resolve("project")
        val sessionId = "session-secret-must-not-be-archived"
        val message = "peer assistant text must be represented by digest"
        val toolTitle = "peer tool title must be represented by digest"
        val harness = EvidenceHarness(sessionId, message, toolTitle)
        val factoryProvenance = harness.factoryProvenance

        val manifest = SourceTreeGenerator.generate(
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
                globals = emptyList(),
                types = emptyList(),
            ),
            project,
            reconstructor = BoundedLlmModuleReconstructor(
                harness,
                harnessProvenanceDescriptor = factoryProvenance.stableDescriptor,
            ),
        )

        val evidencePath = "reports/agent-executions/parse.json"
        val evidenceFile = project.resolve(evidencePath)
        assertTrue(evidenceFile.exists())
        val text = evidenceFile.readText()
        val evidence = Json.parseToJsonElement(text).jsonObject
        assertEquals(1, evidence.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals("acp", evidence.getValue("factoryProvenance").jsonObject.getValue("harness").jsonPrimitive.content)
        assertEquals(ACP_STABLE_PROTOCOL_VERSION, evidence.getValue("protocol").jsonObject.getValue("version").jsonPrimitive.int)
        val negotiatedImplementation = evidence.getValue("agent").jsonObject
            .getValue("negotiatedImplementation").jsonObject
        assertEquals(digest("fake-acp-agent"), negotiatedImplementation.getValue("nameSha256").jsonPrimitive.content)
        assertEquals(14, negotiatedImplementation.getValue("nameUtf8Bytes").jsonPrimitive.int)
        assertTrue(
            evidence.getValue("agent").jsonObject
                .getValue("negotiatedCapabilities").jsonObject.getValue("promptEmbeddedContext").jsonPrimitive.boolean,
        )
        assertEquals(4, evidence.getValue("events").jsonArray.size)
        val turn = evidence.getValue("turn").jsonObject
        assertEquals(digest("exact wire prompt bytes"), turn.getValue("wirePromptSha256").jsonPrimitive.content)
        assertEquals(harness.requestBinding.requestSha256, turn.getValue("requestSha256").jsonPrimitive.content)
        assertEquals(
            harness.requestBinding.accessPolicySha256,
            turn.getValue("accessPolicySha256").jsonPrimitive.content,
        )
        listOf(
            "requestSha256",
            "wirePromptSha256",
            "workspaceRootsSha256",
            "contextInputsSha256",
            "accessPolicySha256",
        ).forEach { field ->
            assertTrue(turn.getValue(field).jsonPrimitive.content.matches(Regex("[0-9a-f]{64}")), field)
        }
        val bounds = evidence.getValue("bounds").jsonObject
        assertEquals("null", bounds.getValue("maximumInputTokens").toString())
        assertEquals("null", bounds.getValue("maximumOutputTokens").toString())
        assertEquals(1, evidence.getValue("result").jsonObject.getValue("changes").jsonArray.size)
        assertEquals(1, evidence.getValue("policyAudits").jsonObject.getValue("filesystem").jsonArray.size)
        assertEquals(1, evidence.getValue("policyAudits").jsonObject.getValue("terminal").jsonArray.size)
        assertEquals(1, evidence.getValue("policyAudits").jsonObject.getValue("permission").jsonArray.size)
        assertEquals("sandbox-evidence-v1", evidence.getValue("sandbox").jsonObject.getValue("provider").jsonPrimitive.content)
        assertTrue(evidence.getValue("validation").jsonObject.getValue("accepted").jsonPrimitive.boolean)
        assertFalse(text.contains(sessionId))
        assertFalse(text.contains(message))
        assertFalse(text.contains(toolTitle))
        assertFalse(text.contains("stderr peer output"))

        val checkpoint = project.resolve("reports/modules/parse.json").readText()
        assertTrue(checkpoint.contains("\"schemaVersion\": 3"))
        assertTrue(checkpoint.contains("\"executionEvidencePath\": \"$evidencePath\""))
        assertTrue(checkpoint.contains(sha256(evidenceFile.readBytes())))
        val manifestEntry = manifest.files.single { it.path == evidencePath }
        assertEquals(sha256(evidenceFile.readBytes()), manifestEntry.sha256)
        assertEquals("acp-execution-evidence:v1", manifestEntry.generator)

        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        val bundle = ArchivalPackager.create(project, temp.resolve("source-tree.zip"))
        assertTrue(evidencePath in bundle.payloadFiles)
        val extracted = temp.resolve("extracted")
        ArchivalBundleVerifier.extractAndVerify(bundle.archivePath, extracted)
        assertEquals(text, extracted.resolve(evidencePath).readText())
    }

    private class EvidenceHarness(
        private val sessionId: String,
        private val message: String,
        private val toolTitle: String,
    ) : AgentHarness, AcpExecutionEvidenceSource {
        private var evidence: AcpExecutionEvidenceSnapshot? = null
        lateinit var requestBinding: AgentExecutionRequestBinding
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
            requestBinding = AgentExecutionRequestBinding.capture(request)
            val target = request.accessPolicy.pathRules.single { rule ->
                decompengine.agent.AgentOperation.WRITE_FILE in rule.operations
            }.path
            val source = """
                #include "modules/parse.h"
                /* fn_0000000000401000 */
                int parse_input(void) { return 17; }
            """.trimIndent() + "\n"
            target.resolve(request.workspaceRoots).writeText(source)
            val change = AgentFileChange(
                target,
                AgentFileChangeKind.CREATED,
                beforeSha256 = null,
                afterSha256 = sha256(source.toByteArray()),
                sizeBytes = source.toByteArray().size.toLong(),
            )
            onEvent(AgentMessageEvent(0, "message-1", AgentMessageRole.ASSISTANT, message, completed = true))
            onEvent(AgentToolEvent(1, "tool-1", toolTitle, AgentToolStatus.SUCCEEDED, mapOf("kind" to "edit")))
            onEvent(
                AgentPermissionEvent(
                    2,
                    "permission-1",
                    AgentPermissionDecision.ALLOW_ONCE,
                    selectedOptionId = "allow-1",
                    reason = "selected",
                ),
            )
            onEvent(AgentFileChangeEvent(3, change))
            evidence = snapshot(target)
            return AgentExecutionResult(
                AgentStopReason.COMPLETED,
                "peer completion summary",
                listOf(change),
                AgentSessionReference(IMPLEMENTATION_ID, sessionId),
                AgentUsage(10, 20, 3, 1, Duration.ofMillis(250)),
            )
        }

        override fun latestAcpExecutionEvidence(): AcpExecutionEvidenceSnapshot? = evidence

        private fun snapshot(target: decompengine.agent.AgentWorkspacePath): AcpExecutionEvidenceSnapshot {
            val terminal = AcpTerminalAuditRecord(
                sequence = 0,
                sessionId = sessionId,
                method = "terminal/create",
                requestSha256 = digest("terminal request"),
                terminalIdSha256 = digest("terminal-1"),
                toolCallIdSha256 = digest("tool-1"),
                outcome = AcpTerminalAuditOutcome.ALLOWED,
                reason = AcpTerminalAuditReason.CREATED,
                networkIsolated = true,
                retainedOutputBytes = 12,
                producedOutputBytes = 12,
                outputTruncated = false,
            )
            return AcpExecutionEvidenceSnapshot(
                factoryProvenance = factoryProvenance,
                negotiatedAgent = AcpNegotiatedAgentEvidence(
                    ACP_STABLE_PROTOCOL_VERSION,
                    "fake-acp-agent",
                    "1.2.3",
                    "Fake ACP Agent",
                    AcpNegotiatedCapabilitiesEvidence(
                        loadSession = false,
                        promptImage = false,
                        promptAudio = false,
                        promptEmbeddedContext = true,
                        mcpHttp = false,
                        mcpSse = false,
                        sessionAdditionalDirectories = false,
                    ),
                ),
                wirePromptSha256 = digest("exact wire prompt bytes"),
                diagnostics = AcpProcessDiagnostics(
                    pid = 123,
                    exitCode = 0,
                    stderr = "stderr peer output",
                    stderrTruncated = false,
                    producedOutputBytes = 512,
                    producedOutputLimitBytes = 1_024,
                    outputLimitExceeded = false,
                    forcedTermination = false,
                    rootTerminationRequested = false,
                    remainingProcessIds = emptyList(),
                    containment = "linux-bubblewrap",
                    networkIsolated = true,
                    sandboxCleanupVerified = true,
                ),
                filesystemAudit = listOf(
                    AcpFilesystemAuditRecord(
                        0,
                        sessionId,
                        "fs/write_text_file",
                        digest(target.relativePath),
                        target,
                        AcpFilesystemAuditOutcome.ALLOWED,
                        AcpFilesystemAuditReason.COMPLETED,
                    ),
                ),
                terminalAudit = listOf(terminal),
                permissionAudit = listOf(
                    AcpPermissionAuditRecord(
                        0,
                        sessionId,
                        digest("tool-1"),
                        2,
                        digest("allow-1"),
                        PermissionOptionKind.ALLOW_ONCE,
                        AcpPermissionAuditOutcome.ALLOWED,
                        AcpPermissionAuditReason.SELECTED,
                        authorityExpanded = false,
                    ),
                ),
                sandboxEvidence = AcpSandboxEvidence(
                    provider = "sandbox-evidence-v1",
                    providerVersion = "1",
                    providerExecutableSha256 = "c".repeat(64),
                    providerExecutableMode = 365,
                    resourceLimiterSha256 = "d".repeat(64),
                    scopeSupervisorSha256 = "e".repeat(64),
                    scopeInspectorSha256 = "f".repeat(64),
                    environmentFdOpenerSha256 = "1".repeat(64),
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
                    policySha256 = "2".repeat(64),
                    terminalLimits = null,
                    launches = emptyList(),
                    authorities = emptyList(),
                    terminalAudit = listOf(terminal),
                    outerProcessOutput = AcpProducedOutputEvidence(1_024, 512, false),
                ),
            )
        }
    }

    private companion object {
        const val IMPLEMENTATION_ID = "test-acp"

        fun digest(value: String): String = java.security.MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }
}
