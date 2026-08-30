package decompengine.project

import com.agentclientprotocol.model.PermissionOptionKind
import decompengine.acp.ACP_KOTLIN_SDK_VERSION
import decompengine.acp.ACP_STABLE_PROTOCOL_VERSION
import decompengine.acp.AcpExecutionEvidenceSnapshot
import decompengine.acp.AcpExecutionCleanupDisposition
import decompengine.acp.AcpExecutionEvidenceCompleteness
import decompengine.acp.AcpExecutionLifecyclePhase
import decompengine.acp.AcpFilesystemAuditOutcome
import decompengine.acp.AcpFilesystemAuditReason
import decompengine.acp.AcpFilesystemAuditRecord
import decompengine.acp.AcpHarnessProvenance
import decompengine.acp.AcpInvocationEvidenceSnapshot
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
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentMessageEvent
import decompengine.agent.AgentMessageRole
import decompengine.agent.AgentPermissionDecision
import decompengine.agent.AgentPermissionEvent
import decompengine.agent.AgentSessionReference
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentToolEvent
import decompengine.agent.AgentToolStatus
import decompengine.agent.AgentUsage
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import java.time.Duration
import kotlin.io.path.createTempDirectory
import kotlin.io.path.createDirectories
import kotlin.io.path.deleteIfExists
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
import kotlin.test.assertFailsWith
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
    fun `event recorder retains an explicit bounded incomplete prefix`() {
        val recorder = BoundedAgentExecutionEventRecorder(maximumEvents = 1)
        recorder.record(AgentMessageEvent(0, "first", AgentMessageRole.ASSISTANT, "one"))

        assertFailsWith<IllegalArgumentException> {
            recorder.record(AgentMessageEvent(1, "second", AgentMessageRole.ASSISTANT, "two"))
        }

        val snapshot = recorder.receiptSnapshot()
        assertFalse(snapshot.complete)
        assertEquals(2, snapshot.observedEventCount)
        assertEquals(1, snapshot.events.size)
        assertEquals("event-count-limit", snapshot.truncationReason)
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
        assertEquals(2, evidence.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals("acp", evidence.getValue("factoryProvenance").jsonObject.getValue("harness").jsonPrimitive.content)
        assertEquals(ACP_STABLE_PROTOCOL_VERSION, evidence.getValue("protocol").jsonObject.getValue("version").jsonPrimitive.int)
        val negotiatedImplementation = evidence.getValue("agent").jsonObject
            .getValue("negotiatedImplementation").jsonObject
        assertEquals(
            digest("fake-acp-agent"),
            negotiatedImplementation.getValue("name").jsonObject.getValue("sha256").jsonPrimitive.content,
        )
        assertEquals(
            14,
            negotiatedImplementation.getValue("name").jsonObject.getValue("encodedBytes").jsonPrimitive.int,
        )
        assertTrue(
            evidence.getValue("agent").jsonObject
                .getValue("negotiatedCapabilities").jsonObject.getValue("promptEmbeddedContext").jsonPrimitive.boolean,
        )
        assertEquals(4, evidence.getValue("events").jsonObject.getValue("records").jsonArray.size)
        val turn = evidence.getValue("request").jsonObject
        assertEquals(digest("exact wire prompt bytes"), turn.getValue("wirePromptSha256").jsonPrimitive.content)
        assertEquals(harness.requestBinding.requestSha256, turn.getValue("requestSha256").jsonPrimitive.content)
        assertEquals(
            harness.requestBinding.accessPolicySha256,
            turn.getValue("accessPolicySha256").jsonPrimitive.content,
        )
        listOf(
            "requestSha256",
            "wirePromptSha256",
            "accessPolicySha256",
        ).forEach { field ->
            assertTrue(turn.getValue(field).jsonPrimitive.content.matches(Regex("[0-9a-f]{64}")), field)
        }
        val bounds = evidence.getValue("request").jsonObject
        assertEquals("null", bounds.getValue("maximumInputTokens").toString())
        assertEquals("null", bounds.getValue("maximumOutputTokens").toString())
        assertEquals(
            1,
            evidence.getValue("outcome").jsonObject.getValue("result").jsonObject
                .getValue("changes").jsonObject.getValue("records").jsonArray.size,
        )
        assertEquals(
            1,
            evidence.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
                .getValue("records").jsonArray.size,
        )
        assertEquals(
            1,
            evidence.getValue("policyAudits").jsonObject.getValue("terminal").jsonObject
                .getValue("records").jsonArray.size,
        )
        assertEquals(
            1,
            evidence.getValue("policyAudits").jsonObject.getValue("permission").jsonObject
                .getValue("records").jsonArray.size,
        )
        assertEquals(
            digest("sandbox-evidence-v1"),
            evidence.getValue("sandbox").jsonObject.getValue("provider").jsonObject
                .getValue("sha256").jsonPrimitive.content,
        )
        assertTrue(evidence.getValue("lifecycle").jsonObject.getValue("releaseComplete").jsonPrimitive.boolean)
        assertFalse(text.contains(sessionId))
        assertFalse(text.contains(message))
        assertFalse(text.contains(toolTitle))
        assertFalse(text.contains("stderr peer output"))

        val checkpoint = project.resolve("reports/modules/parse.json").readText()
        assertTrue(checkpoint.contains("\"schemaVersion\": 4"))
        assertTrue(checkpoint.contains("\"executionEvidencePath\": \"$evidencePath\""))
        assertTrue(checkpoint.contains(sha256(evidenceFile.readBytes())))
        val manifestEntry = manifest.files.single { it.path == evidencePath }
        assertEquals(sha256(evidenceFile.readBytes()), manifestEntry.sha256)
        assertEquals("acp-execution-receipt:v2", manifestEntry.generator)

        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        val bundle = ArchivalPackager.create(project, temp.resolve("source-tree.zip"))
        assertTrue(evidencePath in bundle.payloadFiles)
        val extracted = temp.resolve("extracted")
        ArchivalBundleVerifier.extractAndVerify(bundle.archivePath, extracted)
        assertEquals(text, extracted.resolve(evidencePath).readText())
    }

    @Test
    fun `agent candidate changed by publication normalization is rejected`() {
        val temp = createTempDirectory("acp-normalization-binding-")
        val project = temp.resolve("project")
        val harness = EvidenceHarness("session", "message", "tool", appendFinalNewline = false)

        val manifest = SourceTreeGenerator.generate(
            evidenceModel(),
            project,
            reconstructor = BoundedLlmModuleReconstructor(
                harness,
                harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor,
            ),
        )

        val checkpoint = project.resolve("reports/modules/parse.json").readText()
        assertTrue(checkpoint.contains("\"accepted\": false"))
        assertTrue(checkpoint.contains("agent-source-normalization-changed-bytes"))
        assertTrue("fn_0000000000401000" in manifest.unresolvedImplementationIds)
        assertFailsWith<Exception> {
            ArchivalPackager.create(project, temp.resolve("rejected.zip"))
        }
    }

    @Test
    fun `receipt persistence failure never becomes an evidence-free fallback and can retry`() {
        val temp = createTempDirectory("acp-receipt-persistence-")
        val project = temp.resolve("project")
        var blockPersistence = true
        val harness = EvidenceHarness("session", "message", "tool", beforeReturn = { request ->
            if (blockPersistence) {
                val blocker = request.workspaceRoots.single().path.resolve("reports/agent-executions")
                blocker.parent.createDirectories()
                blocker.writeText("not a directory")
            }
        })
        val reconstructor = BoundedLlmModuleReconstructor(
            harness,
            harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor,
        )

        repeat(2) {
            assertFailsWith<Exception> {
                SourceTreeGenerator.generate(evidenceModel(), project, reconstructor = reconstructor)
            }
            assertFalse(project.resolve("reports/modules/parse.json").exists())
            assertFalse(project.resolve("src/modules/parse.c").exists())
        }

        project.resolve("reports/agent-executions").deleteIfExists()
        blockPersistence = false
        val manifest = SourceTreeGenerator.generate(evidenceModel(), project, reconstructor = reconstructor)
        assertTrue(manifest.unresolvedImplementationIds.isEmpty())
        assertTrue(project.resolve("reports/agent-executions/parse.json").exists())
    }

    @Test
    fun `ordinary refused cancelled limit and typed failure outcomes persist invocation receipts`() {
        val temp = createTempDirectory("acp-terminal-receipts-")
        val scenarios = listOf(
            "refused" to EvidenceHarness(
                "session-refused", "message", "tool", terminalStopReason = AgentStopReason.REFUSED,
            ),
            "cancelled" to EvidenceHarness(
                "session-cancelled", "message", "tool", terminalStopReason = AgentStopReason.CANCELLED,
            ),
            "limit-exhausted" to EvidenceHarness(
                "session-limit", "message", "tool", terminalStopReason = AgentStopReason.LIMIT_EXHAUSTED,
            ),
            "failed-protocol" to EvidenceHarness(
                "session-failed", "message", "tool", failWithProtocolOutcome = true,
            ),
        )

        scenarios.forEach { (name, harness) ->
            val project = temp.resolve(name)
            val reconstructor = BoundedLlmModuleReconstructor(
                harness,
                harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor,
            )
            if (name in setOf("cancelled", "limit-exhausted")) {
                assertFailsWith<ModuleReconstructionInterruptedException> {
                    SourceTreeGenerator.generate(evidenceModel(), project, reconstructor = reconstructor)
                }
            } else {
                val manifest = SourceTreeGenerator.generate(evidenceModel(), project, reconstructor = reconstructor)
                assertTrue("fn_0000000000401000" in manifest.unresolvedImplementationIds)
            }
            val evidence = project.resolve("reports/agent-executions/parse.json")
            assertTrue(evidence.exists(), name)
            val text = evidence.readText()
            assertTrue(text.contains("\"releaseComplete\": false"), name)
            assertTrue(
                text.contains("\"stopReason\":\"${name.removePrefix("failed-")}\"") ||
                    text.contains("\"kind\":\"protocol\""),
                name,
            )
            assertFalse(text.contains("typed protocol failure"), name)
        }
    }

    @Test
    fun `malformed peer text persists as an injective partial v2 commitment`() {
        val temp = createTempDirectory("acp-malformed-receipt-")
        val project = temp.resolve("project")
        val malformed = "peer-\uD800-text"
        val harness = EvidenceHarness("session", malformed, "tool")

        val manifest = SourceTreeGenerator.generate(
            evidenceModel(),
            project,
            reconstructor = BoundedLlmModuleReconstructor(
                harness,
                harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor,
            ),
        )

        val text = project.resolve("reports/agent-executions/parse.json").readText()
        assertTrue(text.contains("\"encoding\":\"jvm-utf16be\""))
        assertTrue(text.contains("\"releaseComplete\": false"))
        assertFalse(text.contains(malformed))
        assertTrue("fn_0000000000401000" in manifest.unresolvedImplementationIds)
        assertFailsWith<Exception> {
            ArchivalPackager.create(project, temp.resolve("malformed.zip"))
        }

        val root = AgentWorkspaceRoot("root", temp.resolve("binding-root"))
        val path = AgentWorkspacePath(root.id, "candidate.c")
        fun binding(objective: String): AgentExecutionRequestBinding = AgentExecutionRequestBinding.capture(
            AgentExecutionRequest(
                objective = objective,
                workspaceRoots = listOf(root),
                accessPolicy = AgentAccessPolicy(
                    listOf(AgentPathRule(path, setOf(AgentOperation.READ_FILE))),
                ),
            ),
        )
        val first = binding("objective-\uD800")
        assertEquals(first, binding("objective-\uD800"))
        assertNotEquals(first.requestSha256, binding("objective-\uDFFF").requestSha256)
    }

    @Test
    fun `compact receipt fallback and exposed assessment share false release marker`() {
        val temp = createTempDirectory("acp-compact-receipt-")
        temp.resolve("src/modules").createDirectories()
        val root = AgentWorkspaceRoot("project", temp)
        val target = AgentWorkspacePath(root.id, "src/modules/parse.c")
        val request = AgentExecutionRequest(
            objective = "reconstruct",
            workspaceRoots = listOf(root),
            accessPolicy = AgentAccessPolicy(
                listOf(
                    AgentPathRule(
                        target,
                        setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE),
                    ),
                ),
            ),
        )
        val harness = EvidenceHarness("session", "message", "tool")
        val recorder = BoundedAgentExecutionEventRecorder()
        val receipt = harness.executeReceipt(request, recorder::record)

        val evidence = requireNotNull(
            ReconstructionAgentExecutionEvidence.captureOrNull(
                request = request,
                moduleId = "parse",
                promptSha256 = "a".repeat(64),
                receipt = receipt,
                events = recorder.receiptSnapshot(),
                maximumFullArtifactBytes = 1,
            ),
        )
        val text = evidence.toReceiptJson("parse")
        assertFalse(evidence.releaseComplete)
        assertTrue(text.contains("\"releaseComplete\": false"))
        assertTrue(text.contains("\"truncationReason\": \"artifact-byte-limit\""))
    }

    private class EvidenceHarness(
        private val sessionId: String,
        private val message: String,
        private val toolTitle: String,
        private val appendFinalNewline: Boolean = true,
        private val beforeReturn: (AgentExecutionRequest) -> Unit = {},
        private val terminalStopReason: AgentStopReason = AgentStopReason.COMPLETED,
        private val failWithProtocolOutcome: Boolean = false,
    ) : AgentHarness {
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
            """.trimIndent() + if (appendFinalNewline) "\n" else ""
            val changes = if (terminalStopReason == AgentStopReason.COMPLETED) {
                target.resolve(request.workspaceRoots).writeText(source)
                listOf(
                    AgentFileChange(
                        target,
                        AgentFileChangeKind.CREATED,
                        beforeSha256 = null,
                        afterSha256 = sha256(source.toByteArray()),
                        sizeBytes = source.toByteArray().size.toLong(),
                    ),
                )
            } else {
                emptyList()
            }
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
            changes.singleOrNull()?.let { change -> onEvent(AgentFileChangeEvent(3, change)) }
            evidence = snapshot(target)
            beforeReturn(request)
            return AgentExecutionResult(
                terminalStopReason,
                "peer completion summary",
                changes,
                AgentSessionReference(IMPLEMENTATION_ID, sessionId),
                AgentUsage(10, 20, 3, 1, Duration.ofMillis(250)),
            )
        }

        override fun executeReceipt(
            request: AgentExecutionRequest,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionReceipt {
            if (failWithProtocolOutcome) {
                requestBinding = AgentExecutionRequestBinding.capture(request)
                val target = request.accessPolicy.pathRules.single { rule ->
                    decompengine.agent.AgentOperation.WRITE_FILE in rule.operations
                }.path
                onEvent(AgentMessageEvent(0, "failed-message", AgentMessageRole.ASSISTANT, message))
                evidence = snapshot(target)
                beforeReturn(request)
                return AgentExecutionReceipt(
                    requestBinding = requestBinding,
                    outcome = AgentExecutionOutcome.Failed(
                        AgentFailure(
                            AgentFailureKind.PROTOCOL,
                            "typed protocol failure must remain committed but redacted",
                            retryable = true,
                            session = AgentSessionReference(IMPLEMENTATION_ID, sessionId),
                        ),
                    ),
                    providerEvidence = requireNotNull(evidence).asInvocationEvidence(),
                )
            }
            val result = execute(request, onEvent)
            val complete = requireNotNull(evidence)
            return AgentExecutionReceipt(
                requestBinding = requestBinding,
                outcome = AgentExecutionOutcome.Returned(result),
                providerEvidence = complete.asInvocationEvidence(),
            )
        }

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

    private fun evidenceModel(): RecoveredProgramModel = RecoveredProgramModel(
        inputSha256 = "a".repeat(64),
        functions = listOf(
            RecoveredFunction(
                "fn_0000000000401000",
                "parse_input",
                0x401000UL,
                "int parse_input(void)",
            ),
        ),
    )
}

private fun AcpExecutionEvidenceSnapshot.asInvocationEvidence(): AcpInvocationEvidenceSnapshot =
    AcpInvocationEvidenceSnapshot(
        factoryProvenance = factoryProvenance,
        phaseReached = AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT,
        cleanupDisposition = AcpExecutionCleanupDisposition.VERIFIED,
        negotiatedAgent = negotiatedAgent,
        wirePromptSha256 = wirePromptSha256,
        diagnostics = diagnostics,
        filesystemAudit = filesystemAudit,
        terminalAudit = terminalAudit,
        permissionAudit = permissionAudit,
        sandboxEvidence = sandboxEvidence,
        completeness = AcpExecutionEvidenceCompleteness(true, true, true),
        completeExecutionEvidence = this,
    )
