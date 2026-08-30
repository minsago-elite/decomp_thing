package decompengine.project

import decompengine.acp.ACP_CLIENT_IMPLEMENTATION_NAME
import decompengine.acp.ACP_CLIENT_IMPLEMENTATION_VERSION
import decompengine.acp.ACP_KOTLIN_SDK_VERSION
import decompengine.acp.ACP_STABLE_PROTOCOL_VERSION
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
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
internal object ReconstructionAcpEvidenceArchiveVerifier {
    fun verify(
        projectDir: Path,
        payloadSha256: Map<String, String>,
        payloadSizes: Map<String, Long>,
        manifest: SourceTreeManifest,
        profile: ReconstructionProfile,
    ) {
        val sourceDeclaration = profile.layout.declaration("module-implementation")
        val checkpointDeclaration = profile.layout.declaration("module-evidence")
        val executionDeclaration = profile.layout.declarations
            .singleOrNull { it.id == "module-agent-execution-evidence" }
        val manifestByPath = manifest.files.associateBy(GeneratedFileEvidence::path)
        val expectedExecutionPaths = linkedSetOf<String>()

        manifest.files
            .filter { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }
            .forEach { source ->
                val moduleId = extractModuleId(sourceDeclaration, source.path)
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
                val checkpoint = parseCheckpoint(checkpointBytes, moduleId, source)
                val agentGenerated = source.generator.isAgentGenerated() ||
                    checkpoint.generator.isAgentGenerated() ||
                    checkpoint.reconstructorIdentity.startsWith("agent:")

                if (!agentGenerated) {
                    require(checkpoint.executionEvidencePath == null && checkpoint.executionEvidenceSha256 == null) {
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
                require(evidenceManifest.generator == ACP_EVIDENCE_GENERATOR &&
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
                verifyExecutionEvidence(
                    bytes = evidenceBytes,
                    moduleId = moduleId,
                    source = source,
                    sourceBytes = requirePayloadSize(source.path, payloadSizes),
                    checkpoint = checkpoint,
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
    }

    private fun parseCheckpoint(
        bytes: ByteArray,
        moduleId: String,
        source: GeneratedFileEvidence,
    ): ReconstructionCheckpoint {
        val root = strictObject(bytes, CHECKPOINT_JSON_LIMITS, "module checkpoint")
        root.requireExactKeys(CHECKPOINT_FIELDS, "module checkpoint")
        require(root.requiredLong("schemaVersion", "module checkpoint") == 3L) {
            "unsupported module checkpoint schema for ACP archive evidence: $moduleId"
        }
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
        require(sourceSha256 == source.sha256 && generator == source.generator &&
            accepted == source.acceptedImplementation && promptSha256 == source.promptSha256
        ) {
            "module checkpoint provenance differs from the source manifest: $moduleId"
        }
        return ReconstructionCheckpoint(
            generator,
            reconstructorIdentity,
            promptSha256,
            executionEvidencePath,
            executionEvidenceSha256,
            accepted,
        )
    }

    private fun verifyExecutionEvidence(
        bytes: ByteArray,
        moduleId: String,
        source: GeneratedFileEvidence,
        sourceBytes: Long,
        checkpoint: ReconstructionCheckpoint,
    ) {
        val root = strictObject(bytes, EVIDENCE_JSON_LIMITS, "reconstruction ACP execution evidence")
        root.requireExactKeys(EVIDENCE_FIELDS, "reconstruction ACP execution evidence")
        require(root.requiredLong("schemaVersion", "ACP evidence") == 1L) {
            "unsupported reconstruction ACP execution evidence schema: $moduleId"
        }
        require(root.requiredString("kind", "ACP evidence") == RECONSTRUCTION_ACP_EVIDENCE_KIND) {
            "wrong reconstruction ACP execution evidence kind: $moduleId"
        }
        require(root.requiredString("moduleId", "ACP evidence") == moduleId) {
            "reconstruction ACP execution evidence names the wrong module: $moduleId"
        }

        val implementationId = verifyFactoryAndProtocol(root)
        require(source.generator == "agent:$implementationId" &&
            checkpoint.generator == source.generator &&
            checkpoint.reconstructorIdentity.startsWith("agent:$implementationId:")
        ) {
            "ACP factory provenance differs from module generator provenance: $moduleId"
        }
        verifyAgentAndSession(root, implementationId)
        val bounds = verifyTurnAndBounds(root, checkpoint)
        val eventChanges = verifyEvents(root.requiredArray("events", "ACP evidence"), bounds.archivedEventCount)
        val resultChanges = verifyResult(root, bounds, source, sourceBytes)
        require(eventChanges == resultChanges) {
            "ACP event evidence does not commit the complete result change set: $moduleId"
        }
        verifyPolicyAudits(root)
        verifyProcess(root)
        verifySandbox(root)
        verifyValidation(root, source)
    }

    private fun verifyFactoryAndProtocol(root: JsonObject): String {
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
        return implementationId
    }

    private fun verifyAgentAndSession(root: JsonObject, implementationId: String) {
        val agent = root.requiredObject("agent", "ACP evidence")
        agent.requireExactKeys(AGENT_FIELDS, "ACP agent")
        require(agent.requiredString("configuredImplementationId", "ACP agent") == implementationId) {
            "configured ACP agent identity differs from factory provenance"
        }
        val negotiated = agent.requiredObject("negotiatedImplementation", "ACP agent")
        negotiated.requireExactKeys(NEGOTIATED_IMPLEMENTATION_FIELDS, "negotiated ACP implementation")
        negotiated.requiredSha256("nameSha256", "negotiated ACP implementation")
        negotiated.requiredNonNegativeLong("nameUtf8Bytes", "negotiated ACP implementation")
        negotiated.requiredSha256("versionSha256", "negotiated ACP implementation")
        negotiated.requiredNonNegativeLong("versionUtf8Bytes", "negotiated ACP implementation")
        val titleSha256 = negotiated.optionalSha256("titleSha256", "negotiated ACP implementation")
        val titleBytes = negotiated.optionalNonNegativeLong("titleUtf8Bytes", "negotiated ACP implementation")
        require((titleSha256 == null) == (titleBytes == null)) {
            "negotiated ACP title digest and length must be present together"
        }
        val capabilities = agent.requiredObject("negotiatedCapabilities", "ACP agent")
        capabilities.requireExactKeys(CAPABILITY_FIELDS, "negotiated ACP capabilities")
        CAPABILITY_FIELDS.forEach { capabilities.requiredBoolean(it, "negotiated ACP capabilities") }

        val session = root.requiredObject("session", "ACP evidence")
        session.requireExactKeys(SESSION_FIELDS, "ACP session")
        require(session.requiredString("harnessId", "ACP session") == implementationId) {
            "ACP session does not bind the configured factory implementation"
        }
        session.requiredSha256("sessionIdSha256", "ACP session")
        session.optionalSha256("resumeReferenceSha256", "ACP session")
    }

    private fun verifyTurnAndBounds(root: JsonObject, checkpoint: ReconstructionCheckpoint): EvidenceBounds {
        val turn = root.requiredObject("turn", "ACP evidence")
        turn.requireExactKeys(TURN_FIELDS, "ACP turn")
        require(turn.requiredLong("ordinal", "ACP turn") == 1L) {
            "reconstruction ACP evidence must describe exactly one turn"
        }
        turn.requiredSha256("requestSha256", "ACP turn")
        turn.requiredSha256("objectiveSha256", "ACP turn")
        turn.requiredNonNegativeLong("objectiveUtf8Bytes", "ACP turn")
        require(turn.requiredSha256("promptSha256", "ACP turn") == checkpoint.promptSha256) {
            "ACP turn prompt digest differs from the reconstruction checkpoint"
        }
        turn.requiredSha256("wirePromptSha256", "ACP turn")
        turn.requiredSha256("workspaceRootsSha256", "ACP turn")
        turn.requiredSha256("contextInputsSha256", "ACP turn")
        turn.requiredSha256("accessPolicySha256", "ACP turn")

        val bounds = root.requiredObject("bounds", "ACP evidence")
        bounds.requireExactKeys(BOUND_FIELDS, "ACP bounds")
        require(bounds.requiredLong("maximumArchivedBytes", "ACP bounds") ==
            MAXIMUM_RECONSTRUCTION_ACP_EVIDENCE_BYTES.toLong()
        ) { "ACP evidence records an unsupported artifact byte bound" }
        val maximumEvents = bounds.requiredNonNegativeLong("maximumArchivedEvents", "ACP bounds")
        require(maximumEvents == MAXIMUM_RECONSTRUCTION_ACP_EVENTS.toLong()) {
            "ACP evidence records an unsupported event-count bound"
        }
        val archivedEvents = bounds.requiredNonNegativeLong("archivedEventCount", "ACP bounds")
        require(archivedEvents <= maximumEvents) { "ACP evidence event count exceeds its bound" }
        val maximumTurns = bounds.requiredNonNegativeLong("maximumTurns", "ACP bounds")
        require(maximumTurns >= 1L) { "ACP evidence turn bound excludes its recorded turn" }
        val maximumToolCalls = bounds.requiredNonNegativeLong("maximumToolCalls", "ACP bounds")
        val maximumOutputBytes = bounds.requiredNonNegativeLong("maximumOutputBytes", "ACP bounds")
        bounds.requiredNonNegativeLong("wallClockTimeoutMillis", "ACP bounds")
        bounds.requiredNonNegativeLong("idleTimeoutMillis", "ACP bounds")
        val maximumInputTokens = bounds.optionalNonNegativeLong("maximumInputTokens", "ACP bounds")
        val maximumOutputTokens = bounds.optionalNonNegativeLong("maximumOutputTokens", "ACP bounds")
        require(bounds.requiredStringArray("workspaceRootIds", "ACP bounds", requireUnique = true) == listOf("project")) {
            "reconstruction ACP evidence has unexpected workspace authority"
        }
        require(bounds.requiredStringArray("contextInputIds", "ACP bounds", requireUnique = true) ==
            listOf("recovered-module-evidence", "observed-behavior")
        ) { "reconstruction ACP evidence has unexpected context inputs" }
        require(bounds.requiredBoolean("filesystemCapabilityEnabled", "ACP bounds") &&
            !bounds.requiredBoolean("terminalCapabilityEnabled", "ACP bounds")
        ) { "reconstruction ACP evidence has unexpected tool capabilities" }
        return EvidenceBounds(
            archivedEvents,
            maximumToolCalls,
            maximumOutputBytes,
            maximumInputTokens,
            maximumOutputTokens,
        )
    }

    private fun verifyEvents(events: JsonArray, expectedCount: Long): List<EvidenceChange> {
        require(events.size.toLong() == expectedCount) { "ACP event count differs from its recorded bound" }
        val changes = mutableListOf<EvidenceChange>()
        events.forEachIndexed { index, element ->
            val event = element.requiredObject("ACP event")
            require(event.requiredLong("sequence", "ACP event") == index.toLong()) {
                "ACP events are missing or reorder a sequence"
            }
            when (event.requiredString("type", "ACP event")) {
                "message" -> {
                    event.requireExactKeys(MESSAGE_EVENT_FIELDS, "ACP message event")
                    event.requiredString("role", "ACP message event")
                    event.requiredSha256("messageIdSha256", "ACP message event")
                    event.requiredSha256("textSha256", "ACP message event")
                    event.requiredNonNegativeLong("textUtf8Bytes", "ACP message event")
                    event.requiredBoolean("completed", "ACP message event")
                }
                "plan" -> {
                    event.requireExactKeys(PLAN_EVENT_FIELDS, "ACP plan event")
                    event.requiredArray("entries", "ACP plan event").forEach { planElement ->
                        val entry = planElement.requiredObject("ACP plan entry")
                        entry.requireExactKeys(PLAN_ENTRY_FIELDS, "ACP plan entry")
                        entry.requiredSha256("idSha256", "ACP plan entry")
                        entry.requiredSha256("descriptionSha256", "ACP plan entry")
                        entry.requiredNonNegativeLong("descriptionUtf8Bytes", "ACP plan entry")
                        entry.requiredString("status", "ACP plan entry")
                    }
                }
                "tool" -> {
                    event.requireExactKeys(TOOL_EVENT_FIELDS, "ACP tool event")
                    event.requiredSha256("toolCallIdSha256", "ACP tool event")
                    event.requiredSha256("titleSha256", "ACP tool event")
                    event.requiredString("status", "ACP tool event")
                    event.requiredSha256("detailsSha256", "ACP tool event")
                    event.requiredNonNegativeLong("detailCount", "ACP tool event")
                }
                "permission" -> {
                    event.requireExactKeys(PERMISSION_EVENT_FIELDS, "ACP permission event")
                    event.requiredSha256("requestIdSha256", "ACP permission event")
                    event.requiredString("decision", "ACP permission event")
                    event.optionalSha256("selectedOptionIdSha256", "ACP permission event")
                    event.optionalSha256("reasonSha256", "ACP permission event")
                }
                "file-change" -> {
                    event.requireExactKeys(FILE_CHANGE_EVENT_FIELDS, "ACP file-change event")
                    changes += verifyChange(event.requiredObject("change", "ACP file-change event"))
                }
                else -> throw IllegalArgumentException("unknown ACP event type")
            }
        }
        return changes
    }

    private fun verifyResult(
        root: JsonObject,
        bounds: EvidenceBounds,
        source: GeneratedFileEvidence,
        sourceBytes: Long,
    ): List<EvidenceChange> {
        val result = root.requiredObject("result", "ACP evidence")
        result.requireExactKeys(RESULT_FIELDS, "ACP result")
        require(result.requiredString("stopReason", "ACP result") == "completed") {
            "reconstruction ACP result is not completed"
        }
        val summarySha256 = result.optionalSha256("summarySha256", "ACP result")
        val summaryBytes = result.optionalNonNegativeLong("summaryUtf8Bytes", "ACP result")
        require((summarySha256 == null) == (summaryBytes == null)) {
            "ACP result summary digest and length must be present together"
        }
        val changes = result.requiredArray("changes", "ACP result").map(::verifyChange)
        require(changes.size == 1 && changes.single().rootId == "project" &&
            changes.single().relativePath == source.path &&
            changes.single().kind in setOf("created", "modified") &&
            changes.single().afterSha256 == source.sha256 &&
            (changes.single().sizeBytes == null || changes.single().sizeBytes == sourceBytes)
        ) { "ACP result change does not identify the archived module source" }

        val usageElement = result.getValue("usage")
        if (usageElement !is JsonNull) {
            val usage = usageElement.requiredObject("ACP usage")
            usage.requireExactKeys(USAGE_FIELDS, "ACP usage")
            val input = usage.optionalNonNegativeLong("inputTokens", "ACP usage")
            val output = usage.optionalNonNegativeLong("outputTokens", "ACP usage")
            usage.optionalNonNegativeLong("cachedInputTokens", "ACP usage")
            val toolCalls = usage.optionalNonNegativeLong("toolCalls", "ACP usage")
            usage.optionalNonNegativeLong("wallClockMillis", "ACP usage")
            require(bounds.maximumInputTokens == null || input != null) {
                "ACP evidence omits input-token usage required by its bound"
            }
            require(bounds.maximumOutputTokens == null || output != null) {
                "ACP evidence omits output-token usage required by its bound"
            }
            require(input == null || bounds.maximumInputTokens == null || input <= bounds.maximumInputTokens) {
                "ACP input-token usage exceeds its bound"
            }
            require(output == null || bounds.maximumOutputTokens == null || output <= bounds.maximumOutputTokens) {
                "ACP output-token usage exceeds its bound"
            }
            require(toolCalls == null || toolCalls <= bounds.maximumToolCalls) {
                "ACP tool-call usage exceeds its bound"
            }
        } else {
            require(bounds.maximumInputTokens == null && bounds.maximumOutputTokens == null) {
                "ACP evidence omits token usage required by its bounds"
            }
        }
        return changes
    }

    private fun verifyChange(element: JsonElement): EvidenceChange {
        val change = element.requiredObject("ACP file change")
        change.requireExactKeys(FILE_CHANGE_FIELDS, "ACP file change")
        val rootId = change.requiredString("rootId", "ACP file change")
        val relativePath = requireNormalizedProjectPath(
            change.requiredString("relativePath", "ACP file change"),
            "ACP file-change path",
        )
        val kind = change.requiredString("kind", "ACP file change")
        require(kind in setOf("created", "modified", "deleted")) { "ACP file-change kind is invalid" }
        val before = change.optionalSha256("beforeSha256", "ACP file change")
        val after = change.optionalSha256("afterSha256", "ACP file change")
        val size = change.optionalNonNegativeLong("sizeBytes", "ACP file change")
        return EvidenceChange(rootId, relativePath, kind, before, after, size)
    }

    private fun verifyPolicyAudits(root: JsonObject) {
        val audits = root.requiredObject("policyAudits", "ACP evidence")
        audits.requireExactKeys(POLICY_AUDIT_FIELDS, "ACP policy audits")
        audits.requiredArray("filesystem", "ACP policy audits").forEach { element ->
            val record = element.requiredObject("ACP filesystem audit")
            record.requireExactKeys(FILESYSTEM_AUDIT_FIELDS, "ACP filesystem audit")
            record.requiredNonNegativeLong("sequence", "ACP filesystem audit")
            record.requiredSha256("sessionIdSha256", "ACP filesystem audit")
            record.requiredString("method", "ACP filesystem audit")
            record.requiredSha256("requestedPathSha256", "ACP filesystem audit")
            record.getValue("policyPath").let { pathElement ->
                if (pathElement !is JsonNull) {
                    val path = pathElement.requiredObject("ACP policy path")
                    path.requireExactKeys(POLICY_PATH_FIELDS, "ACP policy path")
                    path.requiredString("rootId", "ACP policy path")
                    requireNormalizedProjectPath(path.requiredString("relativePath", "ACP policy path"), "ACP policy path")
                }
            }
            record.requiredString("outcome", "ACP filesystem audit")
            record.requiredString("reason", "ACP filesystem audit")
        }
        audits.requiredArray("terminal", "ACP policy audits").forEach { element ->
            val record = element.requiredObject("ACP terminal audit")
            record.requireExactKeys(TERMINAL_AUDIT_FIELDS, "ACP terminal audit")
            record.requiredNonNegativeLong("sequence", "ACP terminal audit")
            record.requiredSha256("sessionIdSha256", "ACP terminal audit")
            record.requiredString("method", "ACP terminal audit")
            record.requiredSha256("requestSha256", "ACP terminal audit")
            record.optionalSha256("terminalIdSha256", "ACP terminal audit")
            record.optionalSha256("toolCallIdSha256", "ACP terminal audit")
            record.requiredString("outcome", "ACP terminal audit")
            record.requiredString("reason", "ACP terminal audit")
            record.requiredBoolean("networkIsolated", "ACP terminal audit")
            record.optionalNonNegativeLong("retainedOutputBytes", "ACP terminal audit")
            record.optionalNonNegativeLong("producedOutputBytes", "ACP terminal audit")
            record.optionalBoolean("outputTruncated", "ACP terminal audit")
        }
        audits.requiredArray("permission", "ACP policy audits").forEach { element ->
            val record = element.requiredObject("ACP permission audit")
            record.requireExactKeys(PERMISSION_AUDIT_FIELDS, "ACP permission audit")
            record.requiredNonNegativeLong("sequence", "ACP permission audit")
            record.requiredSha256("sessionIdSha256", "ACP permission audit")
            record.requiredSha256("toolCallIdSha256", "ACP permission audit")
            record.requiredNonNegativeLong("offeredOptionCount", "ACP permission audit")
            record.optionalSha256("selectedOptionIdSha256", "ACP permission audit")
            record.optionalString("selectedKind", "ACP permission audit")
            record.requiredString("outcome", "ACP permission audit")
            record.requiredString("reason", "ACP permission audit")
            record.requiredBoolean("authorityExpanded", "ACP permission audit")
        }
    }

    private fun verifyProcess(root: JsonObject) {
        val process = root.requiredObject("process", "ACP evidence")
        process.requireExactKeys(PROCESS_FIELDS, "ACP process")
        process.optionalLong("exitCode", "ACP process")
        process.requiredSha256("stderrSha256", "ACP process")
        process.requiredNonNegativeLong("stderrUtf8Bytes", "ACP process")
        process.requiredBoolean("stderrTruncated", "ACP process")
        val produced = process.requiredNonNegativeLong("producedOutputBytes", "ACP process")
        val maximum = process.requiredNonNegativeLong("producedOutputLimitBytes", "ACP process")
        require(produced <= maximum && !process.requiredBoolean("outputLimitExceeded", "ACP process")) {
            "completed ACP process exceeded its output bound"
        }
        require(!process.requiredBoolean("forcedTermination", "ACP process") &&
            !process.requiredBoolean("rootTerminationRequested", "ACP process") &&
            process.requiredNonNegativeLong("remainingProcessCount", "ACP process") == 0L &&
            process.requiredBoolean("sandboxCleanupVerified", "ACP process")
        ) { "completed ACP process lacks cleanup evidence" }
        process.requiredString("containment", "ACP process")
        process.requiredBoolean("networkIsolated", "ACP process")
    }

    private fun verifySandbox(root: JsonObject) {
        val sandbox = root.requiredObject("sandbox", "ACP evidence")
        sandbox.requireExactKeys(SANDBOX_FIELDS, "ACP sandbox")
        listOf(
            "evidenceSha256", "providerExecutableSha256", "resourceLimiterSha256",
            "scopeSupervisorSha256", "scopeInspectorSha256", "environmentFdOpenerSha256",
        ).forEach { sandbox.requiredSha256(it, "ACP sandbox") }
        sandbox.requiredString("provider", "ACP sandbox")
        sandbox.requiredString("providerVersion", "ACP sandbox")
        sandbox.requiredNonNegativeLong("providerExecutableMode", "ACP sandbox")
        sandbox.optionalSha256("policySha256", "ACP sandbox")
        listOf(
            "networkIsolated", "outerAgentContained", "nestedUserNamespacesDisabled", "newSession",
            "dieWithParent", "cgroupV2PidsLimited", "cgroupV2MemoryLimited", "cgroupV2CpuLimited",
        ).forEach { field ->
            require(sandbox.requiredBoolean(field, "ACP sandbox")) {
                "ACP sandbox evidence does not prove $field"
            }
        }
        verifyResourceLimits(sandbox.requiredObject("outerAgentLimits", "ACP sandbox"))
        val closure = sandbox.requiredObject("runtimeClosureLimits", "ACP sandbox")
        closure.requireExactKeys(RUNTIME_CLOSURE_FIELDS, "ACP runtime closure limits")
        RUNTIME_CLOSURE_FIELDS.forEach { closure.requiredNonNegativeLong(it, "ACP runtime closure limits") }
        sandbox.requiredArray("securityExecutables", "ACP sandbox").forEach { element ->
            val executable = element.requiredObject("ACP security executable")
            executable.requireExactKeys(SECURITY_EXECUTABLE_FIELDS, "ACP security executable")
            executable.requiredString("role", "ACP security executable")
            executable.requiredSha256("canonicalPathSha256", "ACP security executable")
            executable.requiredSha256("contentSha256", "ACP security executable")
            executable.requiredNonNegativeLong("mode", "ACP security executable")
            executable.requiredSha256("metadataSha256", "ACP security executable")
        }
        sandbox.requiredArray("authorities", "ACP sandbox").forEach { element ->
            val authority = element.requiredObject("ACP sandbox authority")
            authority.requireExactKeys(AUTHORITY_FIELDS, "ACP sandbox authority")
            authority.requiredString("rootId", "ACP sandbox authority")
            authority.requiredSha256("rootPathSha256", "ACP sandbox authority")
            authority.requiredString("mode", "ACP sandbox authority")
            authority.getValue("quota").let { quotaElement ->
                if (quotaElement !is JsonNull) {
                    val quota = quotaElement.requiredObject("ACP sandbox quota")
                    quota.requireExactKeys(QUOTA_FIELDS, "ACP sandbox quota")
                    quota.requiredString("provider", "ACP sandbox quota")
                    quota.requiredNonNegativeLong("mountId", "ACP sandbox quota")
                    quota.requiredNonNegativeLong("maximumBytes", "ACP sandbox quota")
                    quota.requiredNonNegativeLong("maximumEntries", "ACP sandbox quota")
                    quota.requiredSha256("mountPathSha256", "ACP sandbox quota")
                }
            }
        }
        sandbox.requiredArray("launches", "ACP sandbox").forEach(::verifySandboxLaunch)
        sandbox.getValue("outerProcessOutput").let { outputElement ->
            if (outputElement !is JsonNull) {
                val output = outputElement.requiredObject("ACP outer process output")
                output.requireExactKeys(PRODUCED_OUTPUT_FIELDS, "ACP outer process output")
                val maximum = output.requiredNonNegativeLong("maximumBytes", "ACP outer process output")
                val observed = output.requiredNonNegativeLong("observedBytes", "ACP outer process output")
                val exceeded = output.requiredBoolean("limitExceeded", "ACP outer process output")
                require(observed <= maximum && !exceeded) { "ACP outer process output exceeds its bound" }
            }
        }
    }

    private fun verifySandboxLaunch(element: JsonElement) {
        val launch = element.requiredObject("ACP sandbox launch")
        launch.requireExactKeys(SANDBOX_LAUNCH_FIELDS, "ACP sandbox launch")
        launch.requiredString("purpose", "ACP sandbox launch")
        verifyResourceLimits(launch.requiredObject("resourceLimits", "ACP sandbox launch"))
        val controllers = launch.requiredObject("controllers", "ACP sandbox launch")
        controllers.requireExactKeys(CONTROLLER_FIELDS, "ACP cgroup controllers")
        (CONTROLLER_FIELDS - "memoryOomGroup").forEach {
            controllers.requiredNonNegativeLong(it, "ACP cgroup controllers")
        }
        controllers.requiredBoolean("memoryOomGroup", "ACP cgroup controllers")
        launch.requiredSha256("commandSha256", "ACP sandbox launch")
        val gate = launch.requiredObject("startGate", "ACP sandbox launch")
        gate.requireExactKeys(START_GATE_FIELDS, "ACP sandbox start gate")
        gate.requiredNonNegativeLong("descriptor", "ACP sandbox start gate")
        gate.requiredSha256("waiterExecutableSha256", "ACP sandbox start gate")
        gate.requiredSha256("helperProtocolSha256", "ACP sandbox start gate")
        require(gate.requiredBoolean("positiveByteRequired", "ACP sandbox start gate")) {
            "ACP sandbox launch start gate is not fail-closed"
        }
        val environment = launch.requiredObject("environment", "ACP sandbox launch")
        environment.requireExactKeys(ENVIRONMENT_FIELDS, "ACP sandbox environment")
        environment.requiredSha256("sandboxPathSha256", "ACP sandbox environment")
        environment.requiredSha256("bindingNamesSha256", "ACP sandbox environment")
        (ENVIRONMENT_FIELDS - setOf("sandboxPathSha256", "bindingNamesSha256")).forEach {
            environment.requiredNonNegativeLong(it, "ACP sandbox environment")
        }
        val rlimits = launch.requiredObject("effectiveRlimits", "ACP sandbox launch")
        rlimits.requireExactKeys(EFFECTIVE_RLIMIT_FIELDS, "ACP effective rlimits")
        EFFECTIVE_RLIMIT_FIELDS.forEach { rlimits.requiredNonNegativeLong(it, "ACP effective rlimits") }
        verifyMount(launch.requiredObject("executableMount", "ACP sandbox launch"))
        launch.requiredArray("runtimeMounts", "ACP sandbox launch").forEach { mount ->
            verifyMount(mount.requiredObject("ACP sandbox mount"))
        }
    }

    private fun verifyResourceLimits(limits: JsonObject) {
        limits.requireExactKeys(RESOURCE_LIMIT_FIELDS, "ACP sandbox resource limits")
        RESOURCE_LIMIT_FIELDS.forEach { limits.requiredNonNegativeLong(it, "ACP sandbox resource limits") }
    }

    private fun verifyMount(mount: JsonObject) {
        mount.requireExactKeys(MOUNT_FIELDS, "ACP sandbox mount")
        mount.requiredSha256("sourcePathSha256", "ACP sandbox mount")
        mount.requiredSha256("destinationPathSha256", "ACP sandbox mount")
        mount.requiredSha256("manifestSha256", "ACP sandbox mount")
        mount.requiredNonNegativeLong("device", "ACP sandbox mount")
        mount.requiredNonNegativeLong("inode", "ACP sandbox mount")
        mount.requiredNonNegativeLong("mode", "ACP sandbox mount")
        mount.requiredBoolean("directory", "ACP sandbox mount")
    }

    private fun verifyValidation(root: JsonObject, source: GeneratedFileEvidence) {
        val validation = root.requiredObject("validation", "ACP evidence")
        validation.requireExactKeys(VALIDATION_FIELDS, "ACP validation")
        require(validation.requiredBoolean("accepted", "ACP validation") &&
            validation.requiredSha256("sourceSha256", "ACP validation") == source.sha256
        ) { "ACP validation does not accept the archived module source" }
        val issues = validation.requiredArray("issues", "ACP validation")
        issues.forEach { element ->
            val issue = element.requiredObject("ACP validation issue")
            issue.requireExactKeys(VALIDATION_ISSUE_FIELDS, "ACP validation issue")
            issue.requiredString("code", "ACP validation issue")
            issue.requiredSha256("messageSha256", "ACP validation issue")
            issue.requiredNonNegativeLong("messageUtf8Bytes", "ACP validation issue")
            issue.requiredStringArray("entityIds", "ACP validation issue", requireUnique = true)
        }
        require(issues.isEmpty()) { "accepted ACP validation unexpectedly records rejection issues" }
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

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private data class ReconstructionCheckpoint(
        val generator: String,
        val reconstructorIdentity: String,
        val promptSha256: String,
        val executionEvidencePath: String?,
        val executionEvidenceSha256: String?,
        val accepted: Boolean,
    )

    private data class EvidenceBounds(
        val archivedEventCount: Long,
        val maximumToolCalls: Long,
        val maximumOutputBytes: Long,
        val maximumInputTokens: Long?,
        val maximumOutputTokens: Long?,
    )

    private data class EvidenceChange(
        val rootId: String,
        val relativePath: String,
        val kind: String,
        val beforeSha256: String?,
        val afterSha256: String?,
        val sizeBytes: Long?,
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
    private const val ACP_EVIDENCE_GENERATOR = "acp-execution-evidence:v1"
    private const val RECONSTRUCTION_ACP_EVIDENCE_KIND = "decomp-engine.reconstruction-acp-execution"
    private val PROVENANCE_ID = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")

    private val CHECKPOINT_FIELDS = setOf(
        "schemaVersion", "fingerprint", "sourceSha256", "generator", "reconstructorIdentity",
        "promptSha256", "promptCharacters", "promptBudgetCharacters", "executionEvidencePath",
        "executionEvidenceSha256", "accepted", "retryable", "entityStatuses", "issues",
    )
    private val ENTITY_STATUS_FIELDS = setOf("id", "status")
    private val CHECKPOINT_ISSUE_FIELDS = setOf("code", "message", "entityIds")
    private val EVIDENCE_FIELDS = setOf(
        "schemaVersion", "kind", "moduleId", "factoryProvenance", "protocol", "agent", "session",
        "turn", "bounds", "events", "result", "policyAudits", "process", "sandbox", "validation",
    )
    private val FACTORY_FIELDS = setOf(
        "descriptor", "harness", "implementationId", "agentExecutionContractVersion",
        "configurationSha256", "deprecated",
    )
    private val PROTOCOL_FIELDS = setOf("name", "version", "sdkVersion", "clientImplementation")
    private val CLIENT_FIELDS = setOf("name", "version")
    private val AGENT_FIELDS = setOf("configuredImplementationId", "negotiatedImplementation", "negotiatedCapabilities")
    private val NEGOTIATED_IMPLEMENTATION_FIELDS = setOf(
        "nameSha256", "nameUtf8Bytes", "versionSha256", "versionUtf8Bytes", "titleSha256", "titleUtf8Bytes",
    )
    private val CAPABILITY_FIELDS = setOf(
        "loadSession", "promptImage", "promptAudio", "promptEmbeddedContext", "mcpHttp", "mcpSse",
        "sessionAdditionalDirectories",
    )
    private val SESSION_FIELDS = setOf("harnessId", "sessionIdSha256", "resumeReferenceSha256")
    private val TURN_FIELDS = setOf(
        "ordinal", "requestSha256", "objectiveSha256", "objectiveUtf8Bytes", "promptSha256",
        "wirePromptSha256", "workspaceRootsSha256", "contextInputsSha256", "accessPolicySha256",
    )
    private val BOUND_FIELDS = setOf(
        "maximumArchivedBytes", "maximumArchivedEvents", "archivedEventCount", "maximumTurns",
        "maximumToolCalls", "maximumOutputBytes", "wallClockTimeoutMillis", "idleTimeoutMillis",
        "maximumInputTokens", "maximumOutputTokens", "workspaceRootIds", "contextInputIds",
        "filesystemCapabilityEnabled", "terminalCapabilityEnabled",
    )
    private val MESSAGE_EVENT_FIELDS = setOf(
        "sequence", "type", "role", "messageIdSha256", "textSha256", "textUtf8Bytes", "completed",
    )
    private val PLAN_EVENT_FIELDS = setOf("sequence", "type", "entries")
    private val PLAN_ENTRY_FIELDS = setOf("idSha256", "descriptionSha256", "descriptionUtf8Bytes", "status")
    private val TOOL_EVENT_FIELDS = setOf(
        "sequence", "type", "toolCallIdSha256", "titleSha256", "status", "detailsSha256", "detailCount",
    )
    private val PERMISSION_EVENT_FIELDS = setOf(
        "sequence", "type", "requestIdSha256", "decision", "selectedOptionIdSha256", "reasonSha256",
    )
    private val FILE_CHANGE_EVENT_FIELDS = setOf("sequence", "type", "change")
    private val FILE_CHANGE_FIELDS = setOf(
        "rootId", "relativePath", "kind", "beforeSha256", "afterSha256", "sizeBytes",
    )
    private val RESULT_FIELDS = setOf("stopReason", "summarySha256", "summaryUtf8Bytes", "changes", "usage")
    private val USAGE_FIELDS = setOf(
        "inputTokens", "outputTokens", "cachedInputTokens", "toolCalls", "wallClockMillis",
    )
    private val POLICY_AUDIT_FIELDS = setOf("filesystem", "terminal", "permission")
    private val FILESYSTEM_AUDIT_FIELDS = setOf(
        "sequence", "sessionIdSha256", "method", "requestedPathSha256", "policyPath", "outcome", "reason",
    )
    private val POLICY_PATH_FIELDS = setOf("rootId", "relativePath")
    private val TERMINAL_AUDIT_FIELDS = setOf(
        "sequence", "sessionIdSha256", "method", "requestSha256", "terminalIdSha256", "toolCallIdSha256",
        "outcome", "reason", "networkIsolated", "retainedOutputBytes", "producedOutputBytes", "outputTruncated",
    )
    private val PERMISSION_AUDIT_FIELDS = setOf(
        "sequence", "sessionIdSha256", "toolCallIdSha256", "offeredOptionCount", "selectedOptionIdSha256",
        "selectedKind", "outcome", "reason", "authorityExpanded",
    )
    private val PROCESS_FIELDS = setOf(
        "exitCode", "stderrSha256", "stderrUtf8Bytes", "stderrTruncated", "producedOutputBytes",
        "producedOutputLimitBytes", "outputLimitExceeded", "forcedTermination", "rootTerminationRequested",
        "remainingProcessCount", "containment", "networkIsolated", "sandboxCleanupVerified",
    )
    private val SANDBOX_FIELDS = setOf(
        "evidenceSha256", "provider", "providerVersion", "providerExecutableSha256", "providerExecutableMode",
        "resourceLimiterSha256", "scopeSupervisorSha256", "scopeInspectorSha256", "environmentFdOpenerSha256",
        "policySha256", "networkIsolated", "outerAgentContained", "nestedUserNamespacesDisabled", "newSession",
        "dieWithParent", "cgroupV2PidsLimited", "cgroupV2MemoryLimited", "cgroupV2CpuLimited",
        "outerAgentLimits", "runtimeClosureLimits", "securityExecutables", "authorities", "launches",
        "outerProcessOutput",
    )
    private val RESOURCE_LIMIT_FIELDS = setOf(
        "maximumProcesses", "maximumOpenFiles", "maximumFileBytes", "maximumAddressSpaceBytes", "maximumCpuSeconds",
    )
    private val RUNTIME_CLOSURE_FIELDS = setOf("maximumEntries", "maximumUserOwnedFileBytes", "maximumDepth")
    private val SECURITY_EXECUTABLE_FIELDS = setOf(
        "role", "canonicalPathSha256", "contentSha256", "mode", "metadataSha256",
    )
    private val AUTHORITY_FIELDS = setOf("rootId", "rootPathSha256", "mode", "quota")
    private val QUOTA_FIELDS = setOf("provider", "mountId", "maximumBytes", "maximumEntries", "mountPathSha256")
    private val PRODUCED_OUTPUT_FIELDS = setOf("maximumBytes", "observedBytes", "limitExceeded")
    private val SANDBOX_LAUNCH_FIELDS = setOf(
        "purpose", "resourceLimits", "controllers", "commandSha256", "startGate", "environment",
        "effectiveRlimits", "executableMount", "runtimeMounts",
    )
    private val CONTROLLER_FIELDS = setOf(
        "pidsMax", "memoryMaxBytes", "memorySwapMaxBytes", "cpuQuotaMicros", "cpuPeriodMicros",
        "memoryOomGroup", "runtimeMaxMicros", "timeoutStopMicros",
    )
    private val START_GATE_FIELDS = setOf(
        "descriptor", "waiterExecutableSha256", "helperProtocolSha256", "positiveByteRequired",
    )
    private val ENVIRONMENT_FIELDS = setOf(
        "sandboxPathSha256", "bindingNamesSha256", "bindingCount", "encodedBytes", "device", "inode",
        "mountId", "mode", "linkCount",
    )
    private val EFFECTIVE_RLIMIT_FIELDS = setOf(
        "processesSoft", "processesHard", "openFilesSoft", "openFilesHard", "fileBytesSoft", "fileBytesHard",
        "coreBytesSoft", "coreBytesHard", "addressSpaceSoft", "addressSpaceHard", "cpuSecondsSoft",
        "cpuSecondsHard",
    )
    private val MOUNT_FIELDS = setOf(
        "sourcePathSha256", "destinationPathSha256", "manifestSha256", "device", "inode", "mode", "directory",
    )
    private val VALIDATION_FIELDS = setOf("accepted", "sourceSha256", "issues")
    private val VALIDATION_ISSUE_FIELDS = setOf("code", "messageSha256", "messageUtf8Bytes", "entityIds")
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
