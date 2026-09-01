package decompengine.project

import com.agentclientprotocol.model.PermissionOptionKind
import decompengine.acp.ACP_CLIENT_IMPLEMENTATION_NAME
import decompengine.acp.ACP_CLIENT_IMPLEMENTATION_VERSION
import decompengine.acp.ACP_KOTLIN_SDK_VERSION
import decompengine.acp.ACP_STABLE_PROTOCOL_VERSION
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.AcpFilesystemAuditOutcome
import decompengine.acp.AcpFilesystemAuditReason
import decompengine.acp.AcpPermissionAuditOutcome
import decompengine.acp.AcpPermissionAuditReason
import decompengine.acp.AcpTerminalAuditOutcome
import decompengine.acp.AcpTerminalAuditReason
import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentMessageRole
import decompengine.agent.AgentPermissionDecision
import decompengine.agent.AgentPlanStatus
import decompengine.agent.AgentToolStatus
import decompengine.agent.AgentWorkspacePath
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Treats reconstruction ACP evidence as an authenticated archive input rather than an opaque
 * report. All security-relevant reads walk from a pinned project root without following links,
 * and both checkpoint and execution-evidence JSON use a bounded duplicate-rejecting parser.
 */
internal data class VerifiedAcpTextCommitment(
    val sha256: String,
    val encodedBytes: Long,
    val encoding: String,
)

internal data class VerifiedAcpReceiptChange(
    val rootId: VerifiedAcpTextCommitment,
    val relativePath: VerifiedAcpTextCommitment,
    val kind: String,
    val beforeSha256: String?,
    val afterSha256: String?,
    val sizeBytes: Long?,
)

internal class VerifiedAcpReceiptChangeSet(
    val aggregateSha256: String,
    records: List<VerifiedAcpReceiptChange>,
) {
    val records: List<VerifiedAcpReceiptChange> = Collections.unmodifiableList(records.toList())
}

internal class VerifiedAcpAgentSessionFacts(
    val factoryImplementationId: String,
    val factoryConfigurationSha256: String,
    val factoryDescriptor: String,
    val negotiatedName: VerifiedAcpTextCommitment,
    val negotiatedVersion: VerifiedAcpTextCommitment,
    val negotiatedTitle: VerifiedAcpTextCommitment?,
    negotiatedCapabilities: Map<String, Boolean>,
    val sessionId: VerifiedAcpTextCommitment,
    val resumeReference: VerifiedAcpTextCommitment?,
) {
    val negotiatedCapabilities: Map<String, Boolean> =
        Collections.unmodifiableMap(TreeMap(negotiatedCapabilities))
}

internal class VerifiedAcpReleaseReceiptFacts(
    val session: VerifiedAcpAgentSessionFacts,
    changes: List<VerifiedAcpReceiptChange>,
) {
    val changes: List<VerifiedAcpReceiptChange> = Collections.unmodifiableList(changes.toList())
}

internal fun expectedAcpTextCommitment(value: String): VerifiedAcpTextCommitment {
    val bytes = value.toByteArray(StandardCharsets.UTF_8)
    return VerifiedAcpTextCommitment(sha256(bytes), bytes.size.toLong(), "utf-8")
}

internal object ReconstructionAcpEvidenceArchiveVerifier {
    fun verify(
        projectDir: Path,
        payloadSha256: Map<String, String>,
        payloadSizes: Map<String, Long>,
        manifest: SourceTreeManifest,
        profile: ReconstructionProfile,
        repairLineage: ArchivedRepairReleaseLineage = ArchivedRepairReleaseLineage.NONE,
    ): List<VerifiedCandidateAcpContribution> {
        val sourceDeclaration = profile.layout.declaration("module-implementation")
        val checkpointDeclaration = profile.layout.declaration("module-evidence")
        val executionDeclaration = profile.layout.declarations
            .singleOrNull { it.id == "module-agent-execution-evidence" }
        val manifestByPath = manifest.files.associateBy(GeneratedFileEvidence::path)
        val expectedExecutionPaths = linkedSetOf<String>()
        val acceptedContributions = mutableListOf<VerifiedCandidateAcpContribution>()

        manifest.files
            .filter { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }
            .forEach { source ->
                val moduleId = extractModuleId(sourceDeclaration, source.path)
                val repairedSource = repairLineage.repairedSource(source.path)
                val checkpointPath = checkpointDeclaration.materialize(mapOf("module" to moduleId))
                val checkpointManifest = requireNotNull(manifestByPath[checkpointPath]) {
                    "agent evidence checkpoint is absent from the source manifest: $checkpointPath"
                }
                val checkpointBytes = readBoundedRegularFile(
                    projectDir,
                    checkpointPath,
                    MAXIMUM_RECONSTRUCTION_CHECKPOINT_BYTES,
                )
                requirePayloadIdentity(checkpointPath, checkpointBytes, payloadSha256, payloadSizes)
                require(sha256(checkpointBytes) == checkpointManifest.sha256) {
                    "agent evidence checkpoint differs from its source manifest: $checkpointPath"
                }
                val checkpoint = parseCheckpoint(checkpointBytes, moduleId, source, repairedSource)
                val receiptSource = repairedSource?.let { lineage ->
                    GeneratedFileEvidence(
                        path = source.path,
                        sha256 = lineage.rootSha256,
                        generator = checkpoint.generator,
                        promptSha256 = checkpoint.promptSha256,
                        entityIds = source.entityIds,
                        acceptedImplementation = checkpoint.accepted,
                        roles = source.roles,
                        contentKind = source.contentKind,
                    )
                } ?: source
                val agentGenerated = receiptSource.generator.isAgentGenerated() ||
                    checkpoint.generator.isAgentGenerated() ||
                    checkpoint.reconstructorIdentity.startsWith("agent:")

                if (!agentGenerated) {
                    require(checkpoint.hasNoExecutionEvidence()) {
                        "non-agent module retains stale ACP execution evidence: $moduleId"
                    }
                    return@forEach
                }

                require(source.acceptedImplementation == true && checkpoint.accepted) {
                    "agent-generated module is not accepted at the archive release gate: $moduleId"
                }
                require(source.entityIds.none(manifest.unresolvedImplementationIds::contains)) {
                    "agent-generated module is unresolved at the archive release gate: $moduleId"
                }
                require(checkpoint.schemaVersion == 4L &&
                    checkpoint.executionEvidenceSchemaVersion == 2L &&
                    checkpoint.executionReleaseComplete == true &&
                    checkpoint.executionTerminalOutcome == "returned-completed"
                ) { "agent-generated module lacks release-complete receipt assessment: $moduleId" }
                val evidenceDeclaration = requireNotNull(executionDeclaration) {
                    "reconstruction profile does not declare ACP execution evidence"
                }
                val evidencePath = evidenceDeclaration.materialize(mapOf("module" to moduleId))
                require(checkpoint.executionEvidencePath == evidencePath) {
                    "module checkpoint ACP evidence path differs from the reconstruction profile: $moduleId"
                }
                val evidenceManifest = requireNotNull(manifestByPath[evidencePath]) {
                    "ACP execution evidence is absent from the source manifest: $evidencePath"
                }
                require(evidenceManifest.generator == ACP_RECEIPT_GENERATOR &&
                    evidenceManifest.entityIds == source.entityIds
                ) {
                    "ACP execution evidence manifest provenance is invalid: $evidencePath"
                }
                val evidenceBytes = readBoundedRegularFile(
                    projectDir,
                    evidencePath,
                    MAXIMUM_RECONSTRUCTION_ACP_EVIDENCE_BYTES,
                )
                requirePayloadIdentity(evidencePath, evidenceBytes, payloadSha256, payloadSizes)
                val evidenceSha256 = sha256(evidenceBytes)
                require(evidenceSha256 == evidenceManifest.sha256 &&
                    evidenceSha256 == checkpoint.executionEvidenceSha256
                ) {
                    "module checkpoint ACP evidence digest does not identify the archived artifact: $moduleId"
                }
                val receiptSourceBytes = repairedSource?.rootBytes ?: requirePayloadSize(source.path, payloadSizes)
                val verifiedReceipt = verifyExecutionReceipt(
                    bytes = evidenceBytes,
                    moduleId = moduleId,
                    source = receiptSource,
                    sourceBytes = receiptSourceBytes,
                    checkpoint = checkpoint,
                )
                val releaseFacts = requireNotNull(verifiedReceipt.releaseFacts)
                val exactChange = releaseFacts.changes.single()
                acceptedContributions += VerifiedCandidateAcpContribution(
                    workflow = "reconstruction",
                    taskId = moduleId,
                    receiptPath = evidencePath,
                    receiptBytes = evidenceBytes.size.toLong(),
                    receiptSha256 = evidenceSha256,
                    requestSha256 = verifiedReceipt.requestSha256,
                    promptSha256 = verifiedReceipt.promptSha256,
                    resultChangesSha256 = verifiedReceipt.resultChangesSha256,
                    session = releaseFacts.session,
                    changes = listOf(
                        VerifiedCandidateAcpChange(
                            path = receiptSource.path,
                            kind = exactChange.kind,
                            beforeSha256 = exactChange.beforeSha256,
                            afterSha256 = exactChange.afterSha256,
                            bytes = exactChange.sizeBytes,
                        ),
                    ),
                    parentSourceRevisionSha256 = null,
                    resultSourceRevisionSha256 = null,
                )
                expectedExecutionPaths += evidencePath
            }

        val manifestExecutionPaths = executionDeclaration?.let { declaration ->
            manifest.files.filter { declaration.matches(it.path) }.mapTo(linkedSetOf(), GeneratedFileEvidence::path)
        }.orEmpty()
        val payloadExecutionPaths = executionDeclaration?.let { declaration ->
            payloadSha256.keys.filter(declaration::matches).toCollection(linkedSetOf())
        }.orEmpty()
        require(manifestExecutionPaths == expectedExecutionPaths) {
            "source manifest contains missing, extra, or stale reconstruction ACP evidence"
        }
        require(payloadExecutionPaths == expectedExecutionPaths) {
            "archive contains missing, extra, or stale reconstruction ACP evidence"
        }
        return acceptedContributions.toList()
    }

    /**
     * Recomputes the provider-neutral release predicate for a schema-v2 ACP receipt. Workflow
     * adapters still validate their task identity and exact candidate separately; this validates
     * every retained lifecycle/protocol/session/event/audit/process/sandbox record which makes a
     * `releaseComplete=true` marker meaningful.
     */
    internal fun verifyReleaseCompleteReceipt(root: JsonObject): VerifiedAcpReleaseReceiptFacts {
        val requestBounds = verifyGenericReceiptRequest(root)
        val provider = root.requiredObject("provider", "ACP receipt")
        provider.requireExactKeys(RECEIPT_PROVIDER_FIELDS, "ACP receipt provider")
        require(provider.requiredString("id", "ACP receipt provider") == "acp" &&
            provider.requiredLong("evidenceSchemaVersion", "ACP receipt provider") == 2L
        ) { "release receipt is not invocation-bound ACP-v2 evidence" }

        val lifecycle = root.requiredObject("lifecycle", "ACP receipt")
        lifecycle.requireExactKeys(RECEIPT_LIFECYCLE_FIELDS, "ACP receipt lifecycle")
        require(lifecycle.requiredString("phaseReached", "ACP receipt lifecycle") ==
            "final-workspace-snapshot" &&
            lifecycle.requiredString("cleanupDisposition", "ACP receipt lifecycle") == "verified" &&
            lifecycle.requiredBoolean("filesystemAuditComplete", "ACP receipt lifecycle") &&
            lifecycle.requiredBoolean("terminalAuditComplete", "ACP receipt lifecycle") &&
            lifecycle.requiredBoolean("permissionAuditComplete", "ACP receipt lifecycle") &&
            lifecycle.requiredBoolean("releaseComplete", "ACP receipt lifecycle")
        ) { "ACP receipt release lifecycle is incomplete" }

        val factory = verifyFactoryAndProtocol(root)
        val session = verifyReceiptAgentAndSession(root, factory)
        val eventChanges = verifyReceiptEvents(root.requiredObject("events", "ACP receipt"))
        val resultChanges = verifyGenericReceiptOutcome(
            root.requiredObject("outcome", "ACP receipt"),
            requestBounds,
        )
        require(eventChanges == resultChanges.records) {
            "ACP receipt events do not commit the complete returned change set"
        }
        verifyReceiptPolicyAudits(root, session.sessionId)
        verifyReceiptProcess(root)
        verifyReceiptSandbox(root)
        return VerifiedAcpReleaseReceiptFacts(session, resultChanges.records)
    }

    private fun parseCheckpoint(
        bytes: ByteArray,
        moduleId: String,
        source: GeneratedFileEvidence,
        repairedSource: ArchivedRepairSourceLineage?,
    ): ReconstructionCheckpoint {
        val root = strictObject(bytes, CHECKPOINT_JSON_LIMITS, "module checkpoint")
        val schemaVersion = root.requiredLong("schemaVersion", "module checkpoint")
        require(schemaVersion == 4L) {
            "unsupported module checkpoint schema for ACP archive evidence: $moduleId"
        }
        root.requireExactKeys(CHECKPOINT_V4_FIELDS, "module checkpoint")
        root.requiredSha256("fingerprint", "module checkpoint")
        val sourceSha256 = root.requiredSha256("sourceSha256", "module checkpoint")
        val generator = root.requiredString("generator", "module checkpoint")
        val reconstructorIdentity = root.requiredString("reconstructorIdentity", "module checkpoint")
        val promptSha256 = root.requiredSha256("promptSha256", "module checkpoint")
        val promptCharacters = root.optionalNonNegativeLong("promptCharacters", "module checkpoint")
        val promptBudgetCharacters = root.optionalNonNegativeLong("promptBudgetCharacters", "module checkpoint")
        require(promptCharacters == null || promptBudgetCharacters == null || promptCharacters <= promptBudgetCharacters) {
            "module checkpoint prompt exceeds its recorded budget: $moduleId"
        }
        val executionEvidencePath = root.optionalString("executionEvidencePath", "module checkpoint")
        executionEvidencePath?.let { requireNormalizedProjectPath(it, "module checkpoint execution evidence path") }
        val executionEvidenceSha256 = root.optionalSha256("executionEvidenceSha256", "module checkpoint")
        require((executionEvidencePath == null) == (executionEvidenceSha256 == null)) {
            "module checkpoint ACP evidence path and digest must be present together: $moduleId"
        }
        val executionEvidenceSchemaVersion =
            root.optionalNonNegativeLong("executionEvidenceSchemaVersion", "module checkpoint")
        val executionRequestSha256 = root.optionalSha256("executionRequestSha256", "module checkpoint")
        val executionTerminalOutcome = root.optionalString("executionTerminalOutcome", "module checkpoint")
        val executionReleaseComplete = root.optionalBoolean("executionReleaseComplete", "module checkpoint")
        val fields = listOf(
            executionEvidencePath,
            executionEvidenceSha256,
            executionEvidenceSchemaVersion,
            executionRequestSha256,
            executionTerminalOutcome,
            executionReleaseComplete,
        )
        require(fields.all { it == null } || fields.all { it != null }) {
            "module checkpoint receipt assessment binding is incomplete: $moduleId"
        }
        val accepted = root.requiredBoolean("accepted", "module checkpoint")
        root.requiredBoolean("retryable", "module checkpoint")

        val statuses = root.requiredArray("entityStatuses", "module checkpoint").map { element ->
            val status = element.requiredObject("module checkpoint entity status")
            status.requireExactKeys(ENTITY_STATUS_FIELDS, "module checkpoint entity status")
            status.requiredString("id", "module checkpoint entity status") to
                status.requiredString("status", "module checkpoint entity status")
        }
        require(statuses.map(Pair<String, String>::first) == source.entityIds) {
            "module checkpoint entity identities differ from the source manifest: $moduleId"
        }
        require(statuses.all { (_, status) -> status == if (accepted) "accepted" else "unresolved" }) {
            "module checkpoint entity status disagrees with acceptance: $moduleId"
        }
        val issues = root.requiredArray("issues", "module checkpoint")
        issues.forEach { element ->
            val issue = element.requiredObject("module checkpoint issue")
            issue.requireExactKeys(CHECKPOINT_ISSUE_FIELDS, "module checkpoint issue")
            issue.requiredString("code", "module checkpoint issue")
            issue.requiredString("message", "module checkpoint issue")
            issue.requiredArray("entityIds", "module checkpoint issue").forEach {
                it.requiredString("module checkpoint issue entity ID")
            }
        }
        require(accepted == issues.isEmpty()) {
            "module checkpoint acceptance and validation issues disagree: $moduleId"
        }
        if (repairedSource == null) {
            require(sourceSha256 == source.sha256 && generator == source.generator &&
                accepted == source.acceptedImplementation && promptSha256 == source.promptSha256
            ) {
                "module checkpoint provenance differs from the source manifest: $moduleId"
            }
        } else {
            require(sourceSha256 == repairedSource.rootSha256 &&
                source.sha256 == repairedSource.headSha256 && source.acceptedImplementation == true &&
                source.generator == "repair-revision"
            ) {
                "historical reconstruction checkpoint is not bound to the accepted repair lineage: $moduleId"
            }
        }
        return ReconstructionCheckpoint(
            schemaVersion,
            generator,
            reconstructorIdentity,
            promptSha256,
            promptBudgetCharacters,
            executionEvidencePath,
            executionEvidenceSha256,
            executionEvidenceSchemaVersion,
            executionRequestSha256,
            executionTerminalOutcome,
            executionReleaseComplete,
            accepted,
        )
    }

    private fun verifyExecutionReceipt(
        bytes: ByteArray,
        moduleId: String,
        source: GeneratedFileEvidence,
        sourceBytes: Long,
        checkpoint: ReconstructionCheckpoint,
    ): VerifiedAcpExecutionReceiptDocument {
        val root = strictObject(bytes, EVIDENCE_JSON_LIMITS, "reconstruction ACP execution receipt")
        root.requireExactKeys(RECEIPT_FIELDS, "reconstruction ACP execution receipt")
        require(root.requiredLong("schemaVersion", "ACP receipt") == 2L) {
            "unsupported reconstruction ACP execution receipt schema: $moduleId"
        }
        require(root.requiredString("kind", "ACP receipt") == RECONSTRUCTION_ACP_RECEIPT_KIND) {
            "wrong reconstruction ACP execution receipt kind: $moduleId"
        }
        require(root.requiredString("moduleId", "ACP receipt") == moduleId) {
            "reconstruction ACP execution receipt names the wrong module: $moduleId"
        }

        val requestBounds = verifyReceiptRequest(root, checkpoint)
        val provider = root.requiredObject("provider", "ACP receipt")
        provider.requireExactKeys(RECEIPT_PROVIDER_FIELDS, "ACP receipt provider")
        require(provider.requiredString("id", "ACP receipt provider") == "acp" &&
            provider.requiredLong("evidenceSchemaVersion", "ACP receipt provider") == 2L
        ) { "reconstruction receipt is not invocation-bound ACP-v2 evidence" }

        val lifecycle = root.requiredObject("lifecycle", "ACP receipt")
        lifecycle.requireExactKeys(RECEIPT_LIFECYCLE_FIELDS, "ACP receipt lifecycle")
        require(lifecycle.requiredString("phaseReached", "ACP receipt lifecycle") ==
            "final-workspace-snapshot" &&
            lifecycle.requiredString("cleanupDisposition", "ACP receipt lifecycle") == "verified" &&
            lifecycle.requiredBoolean("filesystemAuditComplete", "ACP receipt lifecycle") &&
            lifecycle.requiredBoolean("terminalAuditComplete", "ACP receipt lifecycle") &&
            lifecycle.requiredBoolean("permissionAuditComplete", "ACP receipt lifecycle")
        ) { "ACP receipt lifecycle is incomplete" }

        val factory = verifyFactoryAndProtocol(root)
        require(source.generator == "agent:${factory.implementationId}" &&
            checkpoint.generator == source.generator &&
            checkpoint.reconstructorIdentity == checkpoint.expectedReconstructorIdentity(factory)
        ) { "ACP receipt factory provenance differs from module generator provenance: $moduleId" }
        val session = verifyReceiptAgentAndSession(root, factory)

        val eventChanges = verifyReceiptEvents(root.requiredObject("events", "ACP receipt"))
        val resultChanges = verifyReceiptOutcome(
            root.requiredObject("outcome", "ACP receipt"),
            requestBounds,
            source,
            sourceBytes,
        )
        require(eventChanges == resultChanges.records) {
            "ACP receipt events do not commit the complete returned change set: $moduleId"
        }
        val exactChange = resultChanges.records.single()
        val expectedAggregate = agentFileChangeSetSha256(
            listOf(
                AgentFileChange(
                    AgentWorkspacePath("project", source.path),
                    when (exactChange.kind) {
                        "created" -> AgentFileChangeKind.CREATED
                        "modified" -> AgentFileChangeKind.MODIFIED
                        else -> error("reconstruction receipt cannot delete its accepted module source")
                    },
                    exactChange.beforeSha256,
                    exactChange.afterSha256,
                    exactChange.sizeBytes,
                ),
            ),
        )
        require(resultChanges.aggregateSha256 == expectedAggregate) {
            "ACP receipt result aggregate differs from its exact archived module change: $moduleId"
        }
        verifyReceiptPolicyAudits(root, session.sessionId)
        verifyReceiptProcess(root)
        verifyReceiptSandbox(root)

        require(lifecycle.requiredBoolean("releaseComplete", "ACP receipt lifecycle")) {
            "ACP receipt release-complete marker is false"
        }
        require(checkpoint.executionRequestSha256 == requestBounds.requestSha256 &&
            checkpoint.executionTerminalOutcome == "returned-completed" &&
            checkpoint.executionReleaseComplete == true
        ) { "checkpoint assessment is cross-paired with a different ACP invocation receipt" }
        return VerifiedAcpExecutionReceiptDocument(
            requestSha256 = requestBounds.requestSha256,
            promptSha256 = checkpoint.promptSha256,
            resultChangesSha256 = resultChanges.aggregateSha256,
            terminalOutcome = "returned-completed",
            releaseComplete = true,
            releaseFacts = VerifiedAcpReleaseReceiptFacts(session, resultChanges.records),
        )
    }

    private fun verifyReceiptRequest(
        root: JsonObject,
        checkpoint: ReconstructionCheckpoint,
    ): ReceiptBounds {
        val request = root.requiredObject("request", "ACP receipt")
        request.requireExactKeys(RECEIPT_REQUEST_FIELDS, "ACP receipt request")
        require(request.requiredLong("contractVersion", "ACP receipt request") ==
            AGENT_EXECUTION_CONTRACT_VERSION.toLong()
        ) { "ACP receipt request uses an unsupported contract" }
        val requestSha256 = request.requiredSha256("requestSha256", "ACP receipt request")
        require(requestSha256 == checkpoint.executionRequestSha256) {
            "ACP receipt request digest differs from its checkpoint assessment"
        }
        request.requiredSha256("accessPolicySha256", "ACP receipt request")
        verifyTextCommitment(
            request.requiredObject("objective", "ACP receipt request"),
            "ACP objective",
            requireNonEmpty = true,
        )
        require(request.requiredSha256("promptSha256", "ACP receipt request") == checkpoint.promptSha256) {
            "ACP receipt prompt digest differs from the reconstruction checkpoint"
        }
        request.requiredSha256("wirePromptSha256", "ACP receipt request")
        verifyTextCommitmentList(
            request.requiredObject("workspaceRootIds", "ACP receipt request"),
            listOf("project"),
            "ACP workspace root IDs",
        )
        verifyTextCommitmentList(
            request.requiredObject("contextInputIds", "ACP receipt request"),
            listOf("recovered-module-evidence", "observed-behavior"),
            "ACP context input IDs",
        )
        require(request.requiredBoolean("filesystemCapabilityEnabled", "ACP receipt request") &&
            !request.requiredBoolean("terminalCapabilityEnabled", "ACP receipt request")
        ) { "reconstruction ACP receipt has unexpected tool capabilities" }
        require(request.requiredNonNegativeLong("maximumTurns", "ACP receipt request") >= 1L) {
            "ACP receipt request excludes its recorded turn"
        }
        val maximumToolCalls = request.requiredNonNegativeLong("maximumToolCalls", "ACP receipt request")
        val maximumOutputBytes = request.requiredNonNegativeLong("maximumOutputBytes", "ACP receipt request")
        requireNonNegativeDecimal(request.requiredString("wallClockTimeoutNanos", "ACP receipt request"))
        requireNonNegativeDecimal(request.requiredString("idleTimeoutNanos", "ACP receipt request"))
        val maximumInputTokens = request.optionalNonNegativeLong("maximumInputTokens", "ACP receipt request")
        val maximumOutputTokens = request.optionalNonNegativeLong("maximumOutputTokens", "ACP receipt request")
        return ReceiptBounds(
            requestSha256,
            maximumToolCalls,
            maximumOutputBytes,
            maximumInputTokens,
            maximumOutputTokens,
        )
    }

    private fun verifyGenericReceiptRequest(root: JsonObject): ReceiptBounds {
        val request = root.requiredObject("request", "ACP receipt")
        request.requireExactKeys(RECEIPT_REQUEST_FIELDS, "ACP receipt request")
        require(request.requiredLong("contractVersion", "ACP receipt request") ==
            AGENT_EXECUTION_CONTRACT_VERSION.toLong()
        ) { "ACP receipt request uses an unsupported contract" }
        val requestSha256 = request.requiredSha256("requestSha256", "ACP receipt request")
        request.requiredSha256("accessPolicySha256", "ACP receipt request")
        verifyTextCommitment(
            request.requiredObject("objective", "ACP receipt request"),
            "ACP objective",
            requireNonEmpty = true,
        )
        request.requiredSha256("promptSha256", "ACP receipt request")
        request.requiredSha256("wirePromptSha256", "ACP receipt request")
        verifyGenericTextCommitmentList(
            request.requiredObject("workspaceRootIds", "ACP receipt request"),
            "ACP workspace root IDs",
            requireNonEmpty = true,
        )
        verifyGenericTextCommitmentList(
            request.requiredObject("contextInputIds", "ACP receipt request"),
            "ACP context input IDs",
        )
        request.requiredBoolean("filesystemCapabilityEnabled", "ACP receipt request")
        request.requiredBoolean("terminalCapabilityEnabled", "ACP receipt request")
        require(request.requiredNonNegativeLong("maximumTurns", "ACP receipt request") >= 1L) {
            "ACP receipt request excludes its recorded turn"
        }
        val maximumToolCalls = request.requiredNonNegativeLong("maximumToolCalls", "ACP receipt request")
        val maximumOutputBytes = request.requiredNonNegativeLong("maximumOutputBytes", "ACP receipt request")
        require(maximumOutputBytes > 0L) { "ACP receipt request has no output-byte capacity" }
        requireNonNegativeDecimal(request.requiredString("wallClockTimeoutNanos", "ACP receipt request"))
        requireNonNegativeDecimal(request.requiredString("idleTimeoutNanos", "ACP receipt request"))
        val maximumInputTokens = request.optionalNonNegativeLong("maximumInputTokens", "ACP receipt request")
        val maximumOutputTokens = request.optionalNonNegativeLong("maximumOutputTokens", "ACP receipt request")
        return ReceiptBounds(
            requestSha256,
            maximumToolCalls,
            maximumOutputBytes,
            maximumInputTokens,
            maximumOutputTokens,
        )
    }

    private fun verifyReceiptAgentAndSession(
        root: JsonObject,
        factory: FactoryIdentity,
    ): VerifiedAcpAgentSessionFacts {
        val agent = root.requiredObject("agent", "ACP receipt")
        agent.requireExactKeys(AGENT_FIELDS, "ACP receipt agent")
        require(agent.requiredString("configuredImplementationId", "ACP receipt agent") == factory.implementationId) {
            "configured ACP receipt identity differs from factory provenance"
        }
        val negotiated = agent.requiredObject("negotiatedImplementation", "ACP receipt agent")
        negotiated.requireExactKeys(RECEIPT_NEGOTIATED_IMPLEMENTATION_FIELDS, "negotiated ACP receipt implementation")
        val negotiatedName = verifyTextCommitment(
            negotiated.requiredObject("name", "negotiated ACP receipt implementation"),
            "ACP agent name",
            requireNonEmpty = true,
            maximumBytes = MAXIMUM_NEGOTIATED_IDENTITY_BYTES,
        )
        val negotiatedVersion = verifyTextCommitment(
            negotiated.requiredObject("version", "negotiated ACP receipt implementation"),
            "ACP agent version",
            requireNonEmpty = true,
            maximumBytes = MAXIMUM_NEGOTIATED_IDENTITY_BYTES,
        )
        val negotiatedTitle = negotiated.getValue("title").let { title ->
            if (title is JsonNull) null else verifyTextCommitment(
                title.requiredObject("ACP agent title"),
                "ACP agent title",
                maximumBytes = MAXIMUM_NEGOTIATED_IDENTITY_BYTES,
            )
        }
        val capabilities = agent.requiredObject("negotiatedCapabilities", "ACP receipt agent")
        capabilities.requireExactKeys(CAPABILITY_FIELDS, "negotiated ACP receipt capabilities")
        val negotiatedCapabilities = CAPABILITY_FIELDS.sorted().associateWith { field ->
            capabilities.requiredBoolean(field, "negotiated ACP receipt capabilities")
        }

        val session = root.requiredObject("session", "ACP receipt")
        session.requireExactKeys(RECEIPT_SESSION_FIELDS, "ACP receipt session")
        verifyTextCommitment(
            session.requiredObject("harnessId", "ACP receipt session"),
            "ACP session harness",
            expected = factory.implementationId,
        )
        val sessionId = verifyTextCommitment(
            session.requiredObject("sessionId", "ACP receipt session"),
            "ACP session ID",
            requireNonEmpty = true,
            maximumBytes = MAXIMUM_ARCHIVED_EVENT_PEER_BYTES,
        )
        val resumeReference = session.getValue("resumeReference").let { resume ->
            if (resume is JsonNull) null else verifyTextCommitment(
                resume.requiredObject("ACP session resume reference"),
                "ACP session resume reference",
            )
        }
        return VerifiedAcpAgentSessionFacts(
            factoryImplementationId = factory.implementationId,
            factoryConfigurationSha256 = factory.configurationSha256,
            factoryDescriptor = factory.descriptor,
            negotiatedName = negotiatedName,
            negotiatedVersion = negotiatedVersion,
            negotiatedTitle = negotiatedTitle,
            negotiatedCapabilities = negotiatedCapabilities,
            sessionId = sessionId,
            resumeReference = resumeReference,
        )
    }

    private fun verifyReceiptEvents(events: JsonObject): List<VerifiedAcpReceiptChange> {
        events.requireExactKeys(RECEIPT_EVENTS_FIELDS, "ACP receipt events")
        require(events.requiredNonNegativeLong("maximumRetainedEvents", "ACP receipt events") ==
            MAXIMUM_RECONSTRUCTION_ACP_EVENTS.toLong()
        ) { "ACP receipt event bound is unsupported" }
        val observed = events.requiredNonNegativeLong("observedEventCount", "ACP receipt events")
        val retained = events.requiredNonNegativeLong("retainedEventCount", "ACP receipt events")
        require(events.requiredBoolean("complete", "ACP receipt events") &&
            events.getValue("truncationReason") is JsonNull
        ) { "ACP receipt event stream is incomplete" }
        val records = events.requiredArray("records", "ACP receipt events")
        require(observed == retained && retained == records.size.toLong() &&
            retained <= MAXIMUM_RECONSTRUCTION_ACP_EVENTS.toLong()
        ) { "ACP receipt event counts disagree" }
        val changes = mutableListOf<VerifiedAcpReceiptChange>()
        records.forEachIndexed { index, element ->
            val event = element.requiredObject("ACP receipt event")
            require(event.requiredLong("sequence", "ACP receipt event") == index.toLong()) {
                "ACP receipt events are missing or reorder a sequence"
            }
            when (event.requiredString("type", "ACP receipt event")) {
                "message" -> {
                    event.requireExactKeys(RECEIPT_MESSAGE_EVENT_FIELDS, "ACP receipt message event")
                    require(event.requiredString("role", "ACP receipt message event") in MESSAGE_ROLES) {
                        "ACP receipt message role is invalid"
                    }
                    verifyTextCommitment(
                        event.requiredObject("messageId", "ACP receipt message event"),
                        "ACP message ID",
                        requireNonEmpty = true,
                    )
                    verifyTextCommitment(event.requiredObject("text", "ACP receipt message event"), "ACP message text")
                    event.requiredBoolean("completed", "ACP receipt message event")
                }
                "plan" -> {
                    event.requireExactKeys(RECEIPT_PLAN_EVENT_FIELDS, "ACP receipt plan event")
                    event.requiredArray("entries", "ACP receipt plan event").forEach { planElement ->
                        val entry = planElement.requiredObject("ACP receipt plan entry")
                        entry.requireExactKeys(RECEIPT_PLAN_ENTRY_FIELDS, "ACP receipt plan entry")
                        verifyTextCommitment(
                            entry.requiredObject("id", "ACP receipt plan entry"),
                            "ACP plan entry ID",
                            requireNonEmpty = true,
                        )
                        verifyTextCommitment(
                            entry.requiredObject("description", "ACP receipt plan entry"),
                            "ACP plan description",
                            requireNonEmpty = true,
                        )
                        require(entry.requiredString("status", "ACP receipt plan entry") in PLAN_STATUSES) {
                            "ACP receipt plan status is invalid"
                        }
                    }
                }
                "tool" -> {
                    event.requireExactKeys(RECEIPT_TOOL_EVENT_FIELDS, "ACP receipt tool event")
                    verifyTextCommitment(
                        event.requiredObject("toolCallId", "ACP receipt tool event"),
                        "ACP tool-call ID",
                        requireNonEmpty = true,
                    )
                    verifyTextCommitment(
                        event.requiredObject("title", "ACP receipt tool event"),
                        "ACP tool title",
                        requireNonEmpty = true,
                    )
                    require(event.requiredString("status", "ACP receipt tool event") in TOOL_STATUSES) {
                        "ACP receipt tool status is invalid"
                    }
                    event.requiredSha256("detailsSha256", "ACP receipt tool event")
                    event.requiredNonNegativeLong("detailCount", "ACP receipt tool event")
                }
                "permission" -> {
                    event.requireExactKeys(RECEIPT_PERMISSION_EVENT_FIELDS, "ACP receipt permission event")
                    verifyTextCommitment(
                        event.requiredObject("requestId", "ACP receipt permission event"),
                        "ACP permission request ID",
                        requireNonEmpty = true,
                    )
                    require(event.requiredString("decision", "ACP receipt permission event") in PERMISSION_DECISIONS) {
                        "ACP receipt permission decision is invalid"
                    }
                    listOf("selectedOptionId", "reason").forEach { field ->
                        event.getValue(field).let { value ->
                            if (value !is JsonNull) verifyTextCommitment(
                                value.requiredObject("ACP receipt permission $field"),
                                "ACP permission $field",
                            )
                        }
                    }
                }
                "file-change" -> {
                    event.requireExactKeys(FILE_CHANGE_EVENT_FIELDS, "ACP receipt file-change event")
                    changes += verifyReceiptChange(event.requiredObject("change", "ACP receipt file-change event"))
                }
                else -> throw IllegalArgumentException("unknown ACP receipt event type")
            }
        }
        return changes
    }

    private fun verifyGenericReceiptOutcome(
        outcome: JsonObject,
        bounds: ReceiptBounds,
    ): VerifiedAcpReceiptChangeSet {
        outcome.requireExactKeys(RECEIPT_OUTCOME_FIELDS, "ACP receipt outcome")
        require(outcome.requiredString("type", "ACP receipt outcome") == "returned" &&
            outcome.getValue("failure") is JsonNull
        ) { "release ACP receipt does not contain a returned outcome" }
        val result = outcome.requiredObject("result", "ACP receipt outcome")
        result.requireExactKeys(RECEIPT_RESULT_FIELDS, "ACP receipt result")
        require(result.requiredString("stopReason", "ACP receipt result") == "completed") {
            "release ACP receipt result is not completed"
        }
        result.getValue("summary").let { summary ->
            if (summary !is JsonNull) verifyTextCommitment(
                summary.requiredObject("ACP receipt result summary"),
                "ACP result summary",
            )
        }
        val changes = result.requiredObject("changes", "ACP receipt result")
        changes.requireExactKeys(RECEIPT_CHANGE_SET_FIELDS, "ACP receipt result changes")
        val observed = changes.requiredNonNegativeLong("observedCount", "ACP receipt result changes")
        val retained = changes.requiredNonNegativeLong("retainedCount", "ACP receipt result changes")
        require(changes.requiredBoolean("complete", "ACP receipt result changes")) {
            "ACP receipt result changes are truncated"
        }
        // The aggregate commits the redacted raw values and is intentionally commitment-only.
        val aggregateSha256 = changes.requiredSha256("aggregateSha256", "ACP receipt result changes")
        val records = changes.requiredArray("records", "ACP receipt result changes")
        require(observed == retained && retained == records.size.toLong() &&
            retained <= MAXIMUM_RECONSTRUCTION_ACP_EVENTS.toLong()
        ) { "ACP receipt result change counts disagree" }
        val verifiedChanges = records.map(::verifyReceiptChange)

        val usageElement = result.getValue("usage")
        if (usageElement is JsonNull) {
            require(bounds.maximumInputTokens == null && bounds.maximumOutputTokens == null) {
                "ACP receipt omits token usage required by request ceilings"
            }
        } else {
            val usage = usageElement.requiredObject("ACP receipt usage")
            usage.requireExactKeys(RECEIPT_USAGE_FIELDS, "ACP receipt usage")
            val input = usage.optionalNonNegativeLong("inputTokens", "ACP receipt usage")
            val output = usage.optionalNonNegativeLong("outputTokens", "ACP receipt usage")
            usage.optionalNonNegativeLong("cachedInputTokens", "ACP receipt usage")
            val toolCalls = usage.optionalNonNegativeLong("toolCalls", "ACP receipt usage")
            usage.getValue("wallClockNanos").let { wallClock ->
                if (wallClock !is JsonNull) requireNonNegativeDecimal(
                    wallClock.requiredString("ACP receipt wall-clock nanoseconds"),
                )
            }
            require(bounds.maximumInputTokens == null ||
                input?.let { it <= bounds.maximumInputTokens } == true
            ) { "ACP receipt input-token usage is missing or exceeds its ceiling" }
            require(bounds.maximumOutputTokens == null ||
                output?.let { it <= bounds.maximumOutputTokens } == true
            ) { "ACP receipt output-token usage is missing or exceeds its ceiling" }
            require(toolCalls == null || toolCalls <= bounds.maximumToolCalls) {
                "ACP receipt tool-call usage exceeds its ceiling"
            }
        }
        return VerifiedAcpReceiptChangeSet(aggregateSha256, verifiedChanges)
    }

    private fun verifyReceiptOutcome(
        outcome: JsonObject,
        bounds: ReceiptBounds,
        source: GeneratedFileEvidence,
        sourceBytes: Long,
    ): VerifiedAcpReceiptChangeSet {
        outcome.requireExactKeys(RECEIPT_OUTCOME_FIELDS, "ACP receipt outcome")
        require(outcome.requiredString("type", "ACP receipt outcome") == "returned" &&
            outcome.getValue("failure") is JsonNull
        ) { "release ACP receipt does not contain a returned outcome" }
        val result = outcome.requiredObject("result", "ACP receipt outcome")
        result.requireExactKeys(RECEIPT_RESULT_FIELDS, "ACP receipt result")
        require(result.requiredString("stopReason", "ACP receipt result") == "completed") {
            "release ACP receipt result is not completed"
        }
        result.getValue("summary").let { summary ->
            if (summary !is JsonNull) verifyTextCommitment(
                summary.requiredObject("ACP receipt result summary"),
                "ACP result summary",
            )
        }
        val changes = result.requiredObject("changes", "ACP receipt result")
        changes.requireExactKeys(RECEIPT_CHANGE_SET_FIELDS, "ACP receipt result changes")
        val observed = changes.requiredNonNegativeLong("observedCount", "ACP receipt result changes")
        val retained = changes.requiredNonNegativeLong("retainedCount", "ACP receipt result changes")
        require(changes.requiredBoolean("complete", "ACP receipt result changes")) {
            "ACP receipt result changes are truncated"
        }
        val aggregateSha256 = changes.requiredSha256("aggregateSha256", "ACP receipt result changes")
        val records = changes.requiredArray("records", "ACP receipt result changes")
        require(observed == retained && retained == records.size.toLong() &&
            retained <= MAXIMUM_RECONSTRUCTION_ACP_EVENTS.toLong()
        ) { "ACP receipt result change counts disagree" }
        val verifiedChanges = records.map(::verifyReceiptChange)
        val expectedRoot = expectedAcpTextCommitment("project")
        val expectedPath = expectedAcpTextCommitment(source.path)
        require(verifiedChanges.size == 1 &&
            verifiedChanges.single().rootId == expectedRoot &&
            verifiedChanges.single().relativePath == expectedPath &&
            verifiedChanges.single().kind in setOf("created", "modified") &&
            verifiedChanges.single().afterSha256 == source.sha256 &&
            (verifiedChanges.single().sizeBytes == null || verifiedChanges.single().sizeBytes == sourceBytes) &&
            sourceBytes <= bounds.maximumOutputBytes
        ) { "ACP receipt result change does not identify the archived module source" }

        val usageElement = result.getValue("usage")
        if (usageElement is JsonNull) {
            require(bounds.maximumInputTokens == null && bounds.maximumOutputTokens == null) {
                "ACP receipt omits token usage required by request ceilings"
            }
        } else {
            val usage = usageElement.requiredObject("ACP receipt usage")
            usage.requireExactKeys(RECEIPT_USAGE_FIELDS, "ACP receipt usage")
            val input = usage.optionalNonNegativeLong("inputTokens", "ACP receipt usage")
            val output = usage.optionalNonNegativeLong("outputTokens", "ACP receipt usage")
            usage.optionalNonNegativeLong("cachedInputTokens", "ACP receipt usage")
            val toolCalls = usage.optionalNonNegativeLong("toolCalls", "ACP receipt usage")
            usage.getValue("wallClockNanos").let { wallClock ->
                if (wallClock !is JsonNull) requireNonNegativeDecimal(
                    wallClock.requiredString("ACP receipt wall-clock nanoseconds"),
                )
            }
            require(bounds.maximumInputTokens == null ||
                input?.let { it <= bounds.maximumInputTokens } == true
            ) { "ACP receipt input-token usage is missing or exceeds its ceiling" }
            require(bounds.maximumOutputTokens == null ||
                output?.let { it <= bounds.maximumOutputTokens } == true
            ) { "ACP receipt output-token usage is missing or exceeds its ceiling" }
            require(toolCalls == null || toolCalls <= bounds.maximumToolCalls) {
                "ACP receipt tool-call usage exceeds its ceiling"
            }
        }
        return VerifiedAcpReceiptChangeSet(aggregateSha256, verifiedChanges)
    }

    private fun verifyReceiptChange(element: JsonElement): VerifiedAcpReceiptChange {
        val change = element.requiredObject("ACP receipt file change")
        change.requireExactKeys(FILE_CHANGE_FIELDS, "ACP receipt file change")
        val rootId = verifyTextCommitment(
            change.requiredObject("rootId", "ACP receipt file change"),
            "ACP change root ID",
        )
        val relativePath = verifyTextCommitment(
            change.requiredObject("relativePath", "ACP receipt file change"),
            "ACP change relative path",
        )
        val kind = change.requiredString("kind", "ACP receipt file change")
        require(kind in setOf("created", "modified", "deleted")) { "ACP receipt file-change kind is invalid" }
        val before = change.optionalSha256("beforeSha256", "ACP receipt file change")
        val after = change.optionalSha256("afterSha256", "ACP receipt file change")
        require(
            when (kind) {
                "created" -> before == null && after != null
                "modified" -> before != null && after != null && before != after
                else -> before != null && after == null
            },
        ) { "ACP receipt file-change digest transition is invalid" }
        return VerifiedAcpReceiptChange(
            rootId,
            relativePath,
            kind,
            before,
            after,
            change.optionalNonNegativeLong("sizeBytes", "ACP receipt file change"),
        )
    }

    private fun verifyReceiptPolicyAudits(
        root: JsonObject,
        expectedSessionId: VerifiedAcpTextCommitment,
    ) {
        val audits = root.requiredObject("policyAudits", "ACP receipt")
        audits.requireExactKeys(POLICY_AUDIT_FIELDS, "ACP receipt policy audits")
        verifyReceiptAuditCollection(audits, "filesystem", RECEIPT_FILESYSTEM_AUDIT_FIELDS) { record ->
            require(verifyTextCommitment(
                record.requiredObject("sessionId", "ACP filesystem audit"),
                "ACP audit session ID",
                requireNonEmpty = true,
            ) == expectedSessionId) { "ACP filesystem audit is cross-paired with another session" }
            verifyTextCommitment(
                record.requiredObject("method", "ACP filesystem audit"),
                "ACP filesystem method",
                requireNonEmpty = true,
            )
            verifyTextCommitment(
                record.requiredObject("requestedPathSha256", "ACP filesystem audit"),
                "ACP requested-path digest",
            )
            record.getValue("policyPath").let { pathElement ->
                if (pathElement !is JsonNull) {
                    val path = pathElement.requiredObject("ACP receipt policy path")
                    path.requireExactKeys(RECEIPT_POLICY_PATH_FIELDS, "ACP receipt policy path")
                    verifyTextCommitment(path.requiredObject("rootId", "ACP receipt policy path"), "ACP policy root ID")
                    verifyTextCommitment(
                        path.requiredObject("relativePath", "ACP receipt policy path"),
                        "ACP policy relative path",
                    )
                }
            }
            require(record.requiredString("outcome", "ACP filesystem audit") in FILESYSTEM_AUDIT_OUTCOMES) {
                "ACP filesystem audit outcome is invalid"
            }
            require(record.requiredString("reason", "ACP filesystem audit") in FILESYSTEM_AUDIT_REASONS) {
                "ACP filesystem audit reason is invalid"
            }
        }
        verifyReceiptAuditCollection(audits, "terminal", RECEIPT_TERMINAL_AUDIT_FIELDS) { record ->
            require(verifyTextCommitment(
                record.requiredObject("sessionId", "ACP terminal audit"),
                "ACP audit session ID",
                requireNonEmpty = true,
            ) == expectedSessionId) { "ACP terminal audit is cross-paired with another session" }
            verifyTextCommitment(
                record.requiredObject("method", "ACP terminal audit"),
                "ACP terminal method",
                requireNonEmpty = true,
            )
            verifyTextCommitment(
                record.requiredObject("requestSha256", "ACP terminal audit"),
                "ACP terminal request digest",
            )
            listOf("terminalIdSha256", "toolCallIdSha256").forEach { field ->
                record.getValue(field).let { value ->
                    if (value !is JsonNull) verifyTextCommitment(
                        value.requiredObject("ACP terminal audit $field"),
                        "ACP terminal $field",
                    )
                }
            }
            require(record.requiredString("outcome", "ACP terminal audit") in TERMINAL_AUDIT_OUTCOMES) {
                "ACP terminal audit outcome is invalid"
            }
            require(record.requiredString("reason", "ACP terminal audit") in TERMINAL_AUDIT_REASONS) {
                "ACP terminal audit reason is invalid"
            }
            record.requiredBoolean("networkIsolated", "ACP terminal audit")
            record.optionalNonNegativeLong("retainedOutputBytes", "ACP terminal audit")
            record.optionalNonNegativeLong("producedOutputBytes", "ACP terminal audit")
            record.optionalBoolean("outputTruncated", "ACP terminal audit")
        }
        verifyReceiptAuditCollection(audits, "permission", RECEIPT_PERMISSION_AUDIT_FIELDS) { record ->
            require(verifyTextCommitment(
                record.requiredObject("sessionId", "ACP permission audit"),
                "ACP audit session ID",
                requireNonEmpty = true,
            ) == expectedSessionId) { "ACP permission audit is cross-paired with another session" }
            verifyTextCommitment(
                record.requiredObject("toolCallIdSha256", "ACP permission audit"),
                "ACP permission tool-call digest",
            )
            record.requiredNonNegativeLong("offeredOptionCount", "ACP permission audit")
            record.getValue("selectedOptionIdSha256").let { value ->
                if (value !is JsonNull) verifyTextCommitment(
                    value.requiredObject("ACP permission selected option"),
                    "ACP permission selected-option digest",
                )
            }
            record.optionalString("selectedKind", "ACP permission audit")?.let { selectedKind ->
                require(selectedKind in PERMISSION_OPTION_KINDS) { "ACP permission option kind is invalid" }
            }
            require(record.requiredString("outcome", "ACP permission audit") in PERMISSION_AUDIT_OUTCOMES) {
                "ACP permission audit outcome is invalid"
            }
            require(record.requiredString("reason", "ACP permission audit") in PERMISSION_AUDIT_REASONS) {
                "ACP permission audit reason is invalid"
            }
            require(!record.requiredBoolean("authorityExpanded", "ACP permission audit")) {
                "ACP permission audit expands workflow authority"
            }
        }
    }

    private inline fun verifyReceiptAuditCollection(
        audits: JsonObject,
        field: String,
        recordFields: Set<String>,
        verifyRecord: (JsonObject) -> Unit,
    ) {
        val collection = audits.requiredObject(field, "ACP receipt policy audits")
        collection.requireExactKeys(RECEIPT_AUDIT_COLLECTION_FIELDS, "ACP receipt $field audits")
        require(collection.requiredNonNegativeLong("maximumRetainedRecords", "ACP receipt $field audits") ==
            MAXIMUM_RECONSTRUCTION_ACP_AUDIT_RECORDS.toLong()
        ) { "ACP receipt $field audit bound is unsupported" }
        val count = collection.requiredNonNegativeLong("recordCount", "ACP receipt $field audits")
        // This digest commits the unredacted, length-delimited record values. The archive exposes
        // only injective text commitments, so release verification checks every retained record
        // directly while treating this whole-list digest as a commitment, not a recomputable hash.
        collection.requiredSha256("aggregateSha256", "ACP receipt $field audits")
        val records = collection.requiredArray("records", "ACP receipt $field audits")
        require(count == records.size.toLong() && count <= MAXIMUM_RECONSTRUCTION_ACP_AUDIT_RECORDS.toLong()) {
            "ACP receipt $field audit counts disagree"
        }
        records.forEachIndexed { index, element ->
            val record = element.requiredObject("ACP receipt $field audit")
            record.requireExactKeys(recordFields, "ACP receipt $field audit")
            require(record.requiredLong("sequence", "ACP receipt $field audit") == index.toLong()) {
                "ACP receipt $field audits are missing or reorder a sequence"
            }
            verifyRecord(record)
        }
    }

    private fun verifyReceiptProcess(root: JsonObject) {
        val process = root.requiredObject("process", "ACP receipt")
        process.requireExactKeys(RECEIPT_PROCESS_FIELDS, "ACP receipt process")
        process.optionalLong("exitCode", "ACP receipt process")
        verifyTextCommitment(process.requiredObject("stderr", "ACP receipt process"), "ACP process stderr")
        process.requiredBoolean("stderrTruncated", "ACP receipt process")
        val produced = process.requiredNonNegativeLong("producedOutputBytes", "ACP receipt process")
        val maximum = process.requiredNonNegativeLong("producedOutputLimitBytes", "ACP receipt process")
        require(produced <= maximum && !process.requiredBoolean("outputLimitExceeded", "ACP receipt process")) {
            "completed ACP receipt process exceeded its output bound"
        }
        require(!process.requiredBoolean("forcedTermination", "ACP receipt process") &&
            !process.requiredBoolean("rootTerminationRequested", "ACP receipt process") &&
            process.requiredNonNegativeLong("remainingProcessCount", "ACP receipt process") == 0L &&
            process.requiredBoolean("sandboxCleanupVerified", "ACP receipt process")
        ) { "completed ACP receipt process lacks cleanup evidence" }
        verifyTextCommitment(
            process.requiredObject("containment", "ACP receipt process"),
            "ACP process containment",
        )
        require(process.requiredBoolean("networkIsolated", "ACP receipt process")) {
            "completed ACP receipt process lacks network isolation evidence"
        }
    }

    private fun verifyReceiptSandbox(root: JsonObject) {
        val sandbox = root.requiredObject("sandbox", "ACP receipt")
        sandbox.requireExactKeys(RECEIPT_SANDBOX_FIELDS, "ACP receipt sandbox")
        sandbox.requiredSha256("evidenceSha256", "ACP receipt sandbox")
        require(!sandbox.requiredBoolean("detailsRetained", "ACP receipt sandbox")) {
            "ACP receipt sandbox unexpectedly retains expanded detail lists"
        }
        verifyTextCommitment(sandbox.requiredObject("provider", "ACP receipt sandbox"), "ACP sandbox provider")
        verifyTextCommitment(
            sandbox.requiredObject("providerVersion", "ACP receipt sandbox"),
            "ACP sandbox provider version",
        )
        listOf(
            "providerExecutableSha256", "resourceLimiterSha256", "scopeSupervisorSha256",
            "scopeInspectorSha256", "environmentFdOpenerSha256",
        ).forEach { sandbox.requiredSha256(it, "ACP receipt sandbox") }
        sandbox.requiredNonNegativeLong("providerExecutableMode", "ACP receipt sandbox")
        sandbox.optionalSha256("policySha256", "ACP receipt sandbox")
        listOf(
            "networkIsolated", "outerAgentContained", "nestedUserNamespacesDisabled", "newSession",
            "dieWithParent", "cgroupV2PidsLimited", "cgroupV2MemoryLimited", "cgroupV2CpuLimited",
        ).forEach { field ->
            require(sandbox.requiredBoolean(field, "ACP receipt sandbox")) {
                "ACP receipt sandbox does not prove $field"
            }
        }
        verifyResourceLimits(sandbox.requiredObject("outerAgentLimits", "ACP receipt sandbox"))
        val closure = sandbox.requiredObject("runtimeClosureLimits", "ACP receipt sandbox")
        closure.requireExactKeys(RUNTIME_CLOSURE_FIELDS, "ACP receipt runtime closure limits")
        RUNTIME_CLOSURE_FIELDS.forEach { closure.requiredNonNegativeLong(it, "ACP receipt runtime closure limits") }
        val securityExecutables = sandbox.requiredNonNegativeLong("securityExecutableCount", "ACP receipt sandbox")
        val authorities = sandbox.requiredNonNegativeLong("authorityCount", "ACP receipt sandbox")
        val launches = sandbox.requiredNonNegativeLong("launchCount", "ACP receipt sandbox")
        val runtimeMounts = sandbox.requiredNonNegativeLong("runtimeMountCount", "ACP receipt sandbox")
        val terminalAudits = sandbox.requiredNonNegativeLong("terminalAuditCount", "ACP receipt sandbox")
        val maximumLaunches = sandbox.requiredNonNegativeLong("maximumRecordedLaunches", "ACP receipt sandbox")
        val maximumMounts = sandbox.requiredNonNegativeLong("maximumRecordedRuntimeMounts", "ACP receipt sandbox")
        require(securityExecutables <= 32L && authorities <= 64L && launches <= maximumLaunches &&
            runtimeMounts <= maximumMounts && terminalAudits <= MAXIMUM_RECONSTRUCTION_ACP_AUDIT_RECORDS.toLong()
        ) { "ACP receipt sandbox list counts exceed their authenticated bounds" }
        require(sandbox.requiredNonNegativeLong("maximumCanonicalMetadataBytes", "ACP receipt sandbox") ==
            MAXIMUM_RECONSTRUCTION_ACP_EVIDENCE_BYTES.toLong()
        ) { "ACP receipt sandbox metadata bound is unsupported" }
        sandbox.getValue("outerProcessOutput").let { outputElement ->
            if (outputElement !is JsonNull) {
                val output = outputElement.requiredObject("ACP receipt outer process output")
                output.requireExactKeys(PRODUCED_OUTPUT_FIELDS, "ACP receipt outer process output")
                val maximum = output.requiredNonNegativeLong("maximumBytes", "ACP receipt outer process output")
                val observed = output.requiredNonNegativeLong("observedBytes", "ACP receipt outer process output")
                require(observed <= maximum && !output.requiredBoolean("limitExceeded", "ACP receipt outer process output")) {
                    "ACP receipt outer process output exceeds its bound"
                }
            }
        }
    }

    private fun verifyTextCommitment(
        value: JsonObject,
        label: String,
        expected: String? = null,
        requireNonEmpty: Boolean = false,
        maximumBytes: Long? = null,
    ): VerifiedAcpTextCommitment {
        value.requireExactKeys(TEXT_COMMITMENT_FIELDS, label)
        val commitment = VerifiedAcpTextCommitment(
            value.requiredSha256("sha256", label),
            value.requiredNonNegativeLong("encodedBytes", label),
            value.requiredString("encoding", label),
        )
        require(commitment.encoding == "utf-8") { "$label is not valid UTF-8 release evidence" }
        require(!requireNonEmpty || commitment.encodedBytes > 0L) { "$label must not be empty" }
        require(maximumBytes == null || commitment.encodedBytes <= maximumBytes) {
            "$label exceeds its release evidence byte bound"
        }
        expected?.let {
            require(commitment == expectedAcpTextCommitment(it)) { "$label differs from its expected identity" }
        }
        return commitment
    }

    private fun verifyTextCommitmentList(value: JsonObject, expected: List<String>, label: String) {
        value.requireExactKeys(TEXT_COMMITMENT_LIST_FIELDS, label)
        val observed = value.requiredNonNegativeLong("observedCount", label)
        val retained = value.requiredNonNegativeLong("retainedCount", label)
        require(value.requiredBoolean("complete", label)) { "$label is truncated" }
        value.requiredSha256("aggregateSha256", label)
        val records = value.requiredArray("records", label)
        require(observed == retained && retained == records.size.toLong() && records.size == expected.size) {
            "$label counts disagree"
        }
        records.forEachIndexed { index, element ->
            verifyTextCommitment(element.requiredObject("$label record"), "$label record", expected[index])
        }
    }

    private fun verifyGenericTextCommitmentList(
        value: JsonObject,
        label: String,
        requireNonEmpty: Boolean = false,
    ) {
        value.requireExactKeys(TEXT_COMMITMENT_LIST_FIELDS, label)
        val observed = value.requiredNonNegativeLong("observedCount", label)
        val retained = value.requiredNonNegativeLong("retainedCount", label)
        require(value.requiredBoolean("complete", label)) { "$label is truncated" }
        value.requiredSha256("aggregateSha256", label)
        val records = value.requiredArray("records", label)
        require(observed == retained && retained == records.size.toLong() &&
            retained <= MAXIMUM_RECONSTRUCTION_ACP_REQUEST_IDENTIFIERS.toLong()
        ) { "$label counts disagree" }
        require(!requireNonEmpty || records.isNotEmpty()) { "$label must not be empty" }
        records.forEach { element ->
            verifyTextCommitment(
                element.requiredObject("$label record"),
                "$label record",
                requireNonEmpty = true,
            )
        }
    }

    private fun requireNonNegativeDecimal(value: String) {
        require(value.matches(Regex("0|[1-9][0-9]{0,127}")) && BigInteger(value).signum() >= 0) {
            "ACP receipt duration is not a bounded non-negative decimal"
        }
    }

    private fun verifyFactoryAndProtocol(root: JsonObject): FactoryIdentity {
        val provenance = root.requiredObject("factoryProvenance", "ACP evidence")
        provenance.requireExactKeys(FACTORY_FIELDS, "ACP factory provenance")
        val descriptor = provenance.requiredString("descriptor", "ACP factory provenance")
        require(provenance.requiredString("harness", "ACP factory provenance") == "acp") {
            "reconstruction agent evidence is not ACP factory provenance"
        }
        val implementationId = provenance.requiredString("implementationId", "ACP factory provenance")
        require(implementationId.matches(PROVENANCE_ID)) { "ACP factory implementation ID is invalid" }
        require(provenance.requiredLong("agentExecutionContractVersion", "ACP factory provenance") ==
            AGENT_EXECUTION_CONTRACT_VERSION.toLong()
        ) { "ACP factory provenance uses an unsupported agent contract" }
        val configurationSha256 = provenance.requiredSha256("configurationSha256", "ACP factory provenance")
        require(!provenance.requiredBoolean("deprecated", "ACP factory provenance")) {
            "deprecated agent factory provenance cannot satisfy an ACP archive"
        }

        val protocol = root.requiredObject("protocol", "ACP evidence")
        protocol.requireExactKeys(PROTOCOL_FIELDS, "ACP protocol")
        require(protocol.requiredString("name", "ACP protocol") == "acp" &&
            protocol.requiredLong("version", "ACP protocol") == ACP_STABLE_PROTOCOL_VERSION.toLong() &&
            protocol.requiredString("sdkVersion", "ACP protocol") == ACP_KOTLIN_SDK_VERSION
        ) { "ACP protocol provenance is unsupported" }
        val client = protocol.requiredObject("clientImplementation", "ACP protocol")
        client.requireExactKeys(CLIENT_FIELDS, "ACP client implementation")
        require(client.requiredString("name", "ACP client implementation") == ACP_CLIENT_IMPLEMENTATION_NAME &&
            client.requiredString("version", "ACP client implementation") == ACP_CLIENT_IMPLEMENTATION_VERSION
        ) { "ACP client implementation provenance is unsupported" }
        val expectedDescriptor = listOf(
            "agent-harness-v1",
            "acp",
            "contract-$AGENT_EXECUTION_CONTRACT_VERSION",
            "acp-$ACP_STABLE_PROTOCOL_VERSION",
            "sdk-$ACP_KOTLIN_SDK_VERSION",
            "implementation-$implementationId",
            "configuration-$configurationSha256",
            "supported",
        ).joinToString(":")
        require(descriptor == expectedDescriptor) { "ACP factory descriptor is internally inconsistent" }
        return FactoryIdentity(implementationId, configurationSha256, descriptor)
    }

    private fun verifyResourceLimits(limits: JsonObject) {
        limits.requireExactKeys(RESOURCE_LIMIT_FIELDS, "ACP sandbox resource limits")
        RESOURCE_LIMIT_FIELDS.forEach { limits.requiredNonNegativeLong(it, "ACP sandbox resource limits") }
    }

    private fun readBoundedRegularFile(projectDir: Path, relativePath: String, maximumBytes: Int): ByteArray {
        val normalized = requireNormalizedProjectPath(relativePath, "archive evidence path")
        val components = normalized.split('/')
        val directories = mutableListOf<LinuxDescriptor>()
        try {
            val root = projectDir.toAbsolutePath().normalize()
            LinuxFilesystemSyscalls.requireSupported(root)
            var directory = LinuxFilesystemSyscalls.openRoot(root).also(directories::add)
            components.dropLast(1).forEach { component ->
                directory = LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, component)
                    .also(directories::add)
            }
            val file = requireNotNull(
                LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, components.last()),
            ) { "archive evidence is missing or is not a regular file: $normalized" }
            file.use { pinned ->
                val pinnedPath = LinuxFilesystemSyscalls.stableDescriptorPath(pinned.fd)
                val size = Files.size(pinnedPath)
                require(size in 0..maximumBytes.toLong()) {
                    "archive evidence exceeds its $maximumBytes-byte limit: $normalized"
                }
                val bytes = LinuxFilesystemSyscalls.openReadableFrom(pinned).use { readable ->
                    LinuxFilesystemSyscalls.read(readable, maximumBytes, cancellationCheck = {})
                }
                require(bytes.size.toLong() == size) { "archive evidence changed while being read: $normalized" }
                return bytes
            }
        } finally {
            directories.asReversed().forEach(LinuxDescriptor::close)
        }
    }

    private fun requirePayloadIdentity(
        path: String,
        bytes: ByteArray,
        payloadSha256: Map<String, String>,
        payloadSizes: Map<String, Long>,
    ) {
        require(payloadSha256[path] == sha256(bytes) && payloadSizes[path] == bytes.size.toLong()) {
            "archive evidence changed after payload inspection: $path"
        }
    }

    private fun requirePayloadSize(path: String, payloadSizes: Map<String, Long>): Long =
        requireNotNull(payloadSizes[path]) { "module source is missing from the archive payload: $path" }

    private fun strictObject(bytes: ByteArray, limits: StrictJsonLimits, label: String): JsonObject =
        OracleJson.parse(bytes, limits).requiredObject(label)

    private fun extractModuleId(declaration: ProjectFileDeclaration, path: String): String {
        val marker = "{module}"
        require(declaration.pathTemplate.countOccurrences(marker) == 1) {
            "module implementation declaration must contain exactly one module placeholder"
        }
        val prefix = declaration.pathTemplate.substringBefore(marker)
        val suffix = declaration.pathTemplate.substringAfter(marker)
        require(path.startsWith(prefix) && path.endsWith(suffix) && path.length > prefix.length + suffix.length) {
            "module implementation path does not match the reconstruction profile: $path"
        }
        val end = path.length - suffix.length
        val moduleId = path.substring(prefix.length, end)
        require(declaration.materialize(mapOf("module" to moduleId)) == path) {
            "module implementation path does not bind one safe module identity: $path"
        }
        return moduleId
    }

    private fun String.countOccurrences(fragment: String): Int {
        var count = 0
        var index = 0
        while (true) {
            index = indexOf(fragment, index)
            if (index < 0) return count
            count++
            index += fragment.length
        }
    }

    private fun String.isAgentGenerated(): Boolean = startsWith("agent:") || startsWith("unresolved:agent:")

    private fun Enum<*>.wireName(): String = name.lowercase().replace('_', '-')

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private data class ReconstructionCheckpoint(
        val schemaVersion: Long,
        val generator: String,
        val reconstructorIdentity: String,
        val promptSha256: String,
        val promptBudgetCharacters: Long?,
        val executionEvidencePath: String?,
        val executionEvidenceSha256: String?,
        val executionEvidenceSchemaVersion: Long?,
        val executionRequestSha256: String?,
        val executionTerminalOutcome: String?,
        val executionReleaseComplete: Boolean?,
        val accepted: Boolean,
    ) {
        fun hasNoExecutionEvidence(): Boolean = listOf(
            executionEvidencePath,
            executionEvidenceSha256,
            executionEvidenceSchemaVersion,
            executionRequestSha256,
            executionTerminalOutcome,
            executionReleaseComplete,
        ).all { it == null }

        fun expectedReconstructorIdentity(factory: FactoryIdentity): String {
            val budget = requireNotNull(promptBudgetCharacters) {
                "agent reconstruction checkpoint is missing its prompt budget"
            }
            return "agent:${factory.implementationId}:context-$budget:" +
                "factory-${sha256(factory.descriptor.toByteArray(StandardCharsets.UTF_8))}:v2"
        }
    }

    private data class FactoryIdentity(
        val implementationId: String,
        val configurationSha256: String,
        val descriptor: String,
    )

    private data class ReceiptBounds(
        val requestSha256: String,
        val maximumToolCalls: Long,
        val maximumOutputBytes: Long,
        val maximumInputTokens: Long?,
        val maximumOutputTokens: Long?,
    )

    private val CHECKPOINT_JSON_LIMITS = StrictJsonLimits(
        maximumInputBytes = MAXIMUM_RECONSTRUCTION_CHECKPOINT_BYTES,
        maximumCanonicalBytes = MAXIMUM_RECONSTRUCTION_CHECKPOINT_BYTES,
        maximumDepth = 32,
        maximumNodes = 100_000,
        maximumStringBytes = 1024 * 1024,
        maximumTotalStringBytes = 2 * 1024 * 1024,
    )
    private val EVIDENCE_JSON_LIMITS = StrictJsonLimits(
        maximumInputBytes = MAXIMUM_RECONSTRUCTION_ACP_EVIDENCE_BYTES,
        maximumCanonicalBytes = MAXIMUM_RECONSTRUCTION_ACP_EVIDENCE_BYTES,
        maximumDepth = 64,
        maximumNodes = 1_000_000,
        maximumStringBytes = 16 * 1024 * 1024,
        maximumTotalStringBytes = MAXIMUM_RECONSTRUCTION_ACP_EVIDENCE_BYTES,
    )

    private const val MAXIMUM_RECONSTRUCTION_CHECKPOINT_BYTES = 4 * 1024 * 1024
    private const val MAXIMUM_RECONSTRUCTION_ACP_EVIDENCE_BYTES = 64 * 1024 * 1024
    private const val MAXIMUM_RECONSTRUCTION_ACP_EVENTS = 8_192
    private const val MAXIMUM_RECONSTRUCTION_ACP_AUDIT_RECORDS = 4_096
    private const val MAXIMUM_RECONSTRUCTION_ACP_REQUEST_IDENTIFIERS = 1_024
    private const val MAXIMUM_NEGOTIATED_IDENTITY_BYTES = 4_096L
    private const val MAXIMUM_ARCHIVED_EVENT_PEER_BYTES = 16L * 1024L * 1024L
    private const val ACP_RECEIPT_GENERATOR = "acp-execution-receipt:v2"
    private const val RECONSTRUCTION_ACP_RECEIPT_KIND =
        "decomp-engine.reconstruction-acp-execution-receipt"
    private val PROVENANCE_ID = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
    private val MESSAGE_ROLES = AgentMessageRole.entries.mapTo(linkedSetOf()) { it.wireName() }
    private val PLAN_STATUSES = AgentPlanStatus.entries.mapTo(linkedSetOf()) { it.wireName() }
    private val TOOL_STATUSES = AgentToolStatus.entries.mapTo(linkedSetOf()) { it.wireName() }
    private val PERMISSION_DECISIONS = AgentPermissionDecision.entries.mapTo(linkedSetOf()) { it.wireName() }
    private val FILESYSTEM_AUDIT_OUTCOMES =
        AcpFilesystemAuditOutcome.entries.mapTo(linkedSetOf()) { it.wireName() }
    private val FILESYSTEM_AUDIT_REASONS =
        AcpFilesystemAuditReason.entries.mapTo(linkedSetOf()) { it.wireName() }
    private val TERMINAL_AUDIT_OUTCOMES =
        AcpTerminalAuditOutcome.entries.mapTo(linkedSetOf()) { it.wireName() }
    private val TERMINAL_AUDIT_REASONS =
        AcpTerminalAuditReason.entries.mapTo(linkedSetOf()) { it.wireName() }
    private val PERMISSION_AUDIT_OUTCOMES =
        AcpPermissionAuditOutcome.entries.mapTo(linkedSetOf()) { it.wireName() }
    private val PERMISSION_AUDIT_REASONS =
        AcpPermissionAuditReason.entries.mapTo(linkedSetOf()) { it.wireName() }
    private val PERMISSION_OPTION_KINDS = PermissionOptionKind.entries.mapTo(linkedSetOf()) { it.wireName() }

    private val CHECKPOINT_V3_FIELDS = setOf(
        "schemaVersion", "fingerprint", "sourceSha256", "generator", "reconstructorIdentity",
        "promptSha256", "promptCharacters", "promptBudgetCharacters", "executionEvidencePath",
        "executionEvidenceSha256", "accepted", "retryable", "entityStatuses", "issues",
    )
    private val CHECKPOINT_V4_FIELDS = CHECKPOINT_V3_FIELDS + setOf(
        "executionEvidenceSchemaVersion", "executionRequestSha256", "executionTerminalOutcome",
        "executionReleaseComplete",
    )
    private val ENTITY_STATUS_FIELDS = setOf("id", "status")
    private val CHECKPOINT_ISSUE_FIELDS = setOf("code", "message", "entityIds")
    private val RECEIPT_FIELDS = setOf(
        "schemaVersion", "kind", "moduleId", "request", "provider", "lifecycle",
        "factoryProvenance", "protocol", "agent", "session", "events", "outcome",
        "policyAudits", "process", "sandbox",
    )
    private val RECEIPT_REQUEST_FIELDS = setOf(
        "contractVersion", "requestSha256", "accessPolicySha256", "objective", "promptSha256",
        "wirePromptSha256", "workspaceRootIds", "contextInputIds", "filesystemCapabilityEnabled",
        "terminalCapabilityEnabled", "maximumTurns", "maximumToolCalls", "maximumOutputBytes",
        "wallClockTimeoutNanos", "idleTimeoutNanos", "maximumInputTokens", "maximumOutputTokens",
    )
    private val RECEIPT_PROVIDER_FIELDS = setOf("id", "evidenceSchemaVersion")
    private val RECEIPT_LIFECYCLE_FIELDS = setOf(
        "phaseReached", "cleanupDisposition", "filesystemAuditComplete", "terminalAuditComplete",
        "permissionAuditComplete", "releaseComplete",
    )
    private val FACTORY_FIELDS = setOf(
        "descriptor", "harness", "implementationId", "agentExecutionContractVersion",
        "configurationSha256", "deprecated",
    )
    private val PROTOCOL_FIELDS = setOf("name", "version", "sdkVersion", "clientImplementation")
    private val CLIENT_FIELDS = setOf("name", "version")
    private val AGENT_FIELDS = setOf("configuredImplementationId", "negotiatedImplementation", "negotiatedCapabilities")
    private val RECEIPT_NEGOTIATED_IMPLEMENTATION_FIELDS = setOf("name", "version", "title")
    private val CAPABILITY_FIELDS = setOf(
        "loadSession", "promptImage", "promptAudio", "promptEmbeddedContext", "mcpHttp", "mcpSse",
        "sessionAdditionalDirectories",
    )
    private val RECEIPT_SESSION_FIELDS = setOf("harnessId", "sessionId", "resumeReference")
    private val FILE_CHANGE_EVENT_FIELDS = setOf("sequence", "type", "change")
    private val FILE_CHANGE_FIELDS = setOf(
        "rootId", "relativePath", "kind", "beforeSha256", "afterSha256", "sizeBytes",
    )
    private val RECEIPT_EVENTS_FIELDS = setOf(
        "maximumRetainedEvents", "observedEventCount", "retainedEventCount", "complete",
        "truncationReason", "records",
    )
    private val RECEIPT_MESSAGE_EVENT_FIELDS = setOf(
        "sequence", "type", "role", "messageId", "text", "completed",
    )
    private val RECEIPT_PLAN_EVENT_FIELDS = setOf("sequence", "type", "entries")
    private val RECEIPT_PLAN_ENTRY_FIELDS = setOf("id", "description", "status")
    private val RECEIPT_TOOL_EVENT_FIELDS = setOf(
        "sequence", "type", "toolCallId", "title", "status", "detailsSha256", "detailCount",
    )
    private val RECEIPT_PERMISSION_EVENT_FIELDS = setOf(
        "sequence", "type", "requestId", "decision", "selectedOptionId", "reason",
    )
    private val RECEIPT_OUTCOME_FIELDS = setOf("type", "result", "failure")
    private val RECEIPT_RESULT_FIELDS = setOf("stopReason", "summary", "changes", "usage")
    private val RECEIPT_CHANGE_SET_FIELDS = setOf(
        "observedCount", "retainedCount", "complete", "aggregateSha256", "records",
    )
    private val RECEIPT_USAGE_FIELDS = setOf(
        "inputTokens", "outputTokens", "cachedInputTokens", "toolCalls", "wallClockNanos",
    )
    private val POLICY_AUDIT_FIELDS = setOf("filesystem", "terminal", "permission")
    private val RECEIPT_AUDIT_COLLECTION_FIELDS = setOf(
        "maximumRetainedRecords", "recordCount", "aggregateSha256", "records",
    )
    private val RECEIPT_FILESYSTEM_AUDIT_FIELDS = setOf(
        "sequence", "sessionId", "method", "requestedPathSha256", "policyPath", "outcome", "reason",
    )
    private val RECEIPT_POLICY_PATH_FIELDS = setOf("rootId", "relativePath")
    private val RECEIPT_TERMINAL_AUDIT_FIELDS = setOf(
        "sequence", "sessionId", "method", "requestSha256", "terminalIdSha256",
        "toolCallIdSha256", "outcome", "reason", "networkIsolated", "retainedOutputBytes",
        "producedOutputBytes", "outputTruncated",
    )
    private val RECEIPT_PERMISSION_AUDIT_FIELDS = setOf(
        "sequence", "sessionId", "toolCallIdSha256", "offeredOptionCount",
        "selectedOptionIdSha256", "selectedKind", "outcome", "reason", "authorityExpanded",
    )
    private val RECEIPT_PROCESS_FIELDS = setOf(
        "exitCode", "stderr", "stderrTruncated", "producedOutputBytes", "producedOutputLimitBytes",
        "outputLimitExceeded", "forcedTermination", "rootTerminationRequested", "remainingProcessCount",
        "containment", "networkIsolated", "sandboxCleanupVerified",
    )
    private val RECEIPT_SANDBOX_FIELDS = setOf(
        "evidenceSha256", "detailsRetained", "provider", "providerVersion",
        "providerExecutableSha256", "providerExecutableMode", "resourceLimiterSha256",
        "scopeSupervisorSha256", "scopeInspectorSha256", "environmentFdOpenerSha256",
        "policySha256", "networkIsolated", "outerAgentContained", "nestedUserNamespacesDisabled",
        "newSession", "dieWithParent", "cgroupV2PidsLimited", "cgroupV2MemoryLimited",
        "cgroupV2CpuLimited", "outerAgentLimits", "runtimeClosureLimits",
        "securityExecutableCount", "authorityCount", "launchCount", "runtimeMountCount",
        "terminalAuditCount", "maximumRecordedLaunches", "maximumRecordedRuntimeMounts",
        "maximumCanonicalMetadataBytes", "outerProcessOutput",
    )
    private val TEXT_COMMITMENT_FIELDS = setOf("sha256", "encodedBytes", "encoding")
    private val TEXT_COMMITMENT_LIST_FIELDS = setOf(
        "observedCount", "retainedCount", "complete", "aggregateSha256", "records",
    )
    private val RESOURCE_LIMIT_FIELDS = setOf(
        "maximumProcesses", "maximumOpenFiles", "maximumFileBytes", "maximumAddressSpaceBytes", "maximumCpuSeconds",
    )
    private val RUNTIME_CLOSURE_FIELDS = setOf("maximumEntries", "maximumUserOwnedFileBytes", "maximumDepth")
    private val PRODUCED_OUTPUT_FIELDS = setOf("maximumBytes", "observedBytes", "limitExceeded")
}

private fun JsonObject.requireExactKeys(expected: Set<String>, label: String) {
    require(keys == expected) { "$label fields do not match its schema" }
}

private fun JsonObject.requiredString(name: String, label: String): String =
    getValue(name).requiredString("$label $name")

private fun JsonElement.requiredString(label: String): String {
    val primitive = this as? JsonPrimitive ?: throw IllegalArgumentException("$label must be a string")
    require(primitive.isString) { "$label must be a string" }
    return primitive.content
}

private fun JsonObject.optionalString(name: String, label: String): String? = getValue(name).let { element ->
    if (element is JsonNull) null else element.requiredString("$label $name")
}

private fun JsonObject.requiredSha256(name: String, label: String): String =
    requiredString(name, label).also { require(it.matches(LOWERCASE_SHA256)) { "$label $name is not lowercase SHA-256" } }

private fun JsonObject.optionalSha256(name: String, label: String): String? =
    optionalString(name, label)?.also { require(it.matches(LOWERCASE_SHA256)) { "$label $name is not lowercase SHA-256" } }

private fun JsonObject.requiredLong(name: String, label: String): Long = getValue(name).requiredLong("$label $name")

private fun JsonElement.requiredLong(label: String): Long {
    val primitive = this as? JsonPrimitive ?: throw IllegalArgumentException("$label must be an integer")
    require(!primitive.isString) { "$label must be an integer" }
    return primitive.longOrNull ?: throw IllegalArgumentException("$label must be an integer")
}

private fun JsonObject.optionalLong(name: String, label: String): Long? = getValue(name).let { element ->
    if (element is JsonNull) null else element.requiredLong("$label $name")
}

private fun JsonObject.requiredNonNegativeLong(name: String, label: String): Long =
    requiredLong(name, label).also { require(it >= 0L) { "$label $name must not be negative" } }

private fun JsonObject.optionalNonNegativeLong(name: String, label: String): Long? =
    optionalLong(name, label)?.also { require(it >= 0L) { "$label $name must not be negative" } }

private fun JsonObject.requiredBoolean(name: String, label: String): Boolean {
    val primitive = getValue(name) as? JsonPrimitive ?: throw IllegalArgumentException("$label $name must be Boolean")
    require(!primitive.isString) { "$label $name must be Boolean" }
    return primitive.booleanOrNull ?: throw IllegalArgumentException("$label $name must be Boolean")
}

private fun JsonObject.optionalBoolean(name: String, label: String): Boolean? = getValue(name).let { element ->
    if (element is JsonNull) null else {
        val primitive = element as? JsonPrimitive ?: throw IllegalArgumentException("$label $name must be Boolean or null")
        require(!primitive.isString) { "$label $name must be Boolean or null" }
        primitive.booleanOrNull ?: throw IllegalArgumentException("$label $name must be Boolean or null")
    }
}

private fun JsonObject.requiredObject(name: String, label: String): JsonObject =
    getValue(name).requiredObject("$label $name")

private fun JsonElement.requiredObject(label: String): JsonObject =
    this as? JsonObject ?: throw IllegalArgumentException("$label must be an object")

private fun JsonObject.requiredArray(name: String, label: String): JsonArray =
    getValue(name) as? JsonArray ?: throw IllegalArgumentException("$label $name must be an array")

private fun JsonObject.requiredStringArray(name: String, label: String, requireUnique: Boolean): List<String> =
    requiredArray(name, label).map { it.requiredString("$label $name entry") }.also { values ->
        require(!requireUnique || values.distinct().size == values.size) { "$label $name must contain unique strings" }
    }

private val LOWERCASE_SHA256 = Regex("[0-9a-f]{64}")
