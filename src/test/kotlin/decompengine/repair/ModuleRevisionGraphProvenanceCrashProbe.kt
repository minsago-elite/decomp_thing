package decompengine.repair

import decompengine.agent.AgentStopReason
import decompengine.project.AcpChangeAssessment
import decompengine.project.AcpChangeObservationStatus
import decompengine.project.AcpChangePolicyVerdict
import decompengine.project.AcpChangePublicationEligibility
import decompengine.project.AcpChangeValidationStatus
import decompengine.project.AgentTurnIntent
import decompengine.project.GeneratedCRepairIndexProfile
import decompengine.project.verifyAcpExecutionReceiptDocument
import decompengine.project.sha256
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import kotlin.io.path.readBytes

/** Child-JVM hard-halt probe for the complete schema-7 repair provenance sequence. */
internal object ModuleRevisionGraphProvenanceCrashProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 5)
        val project = Path.of(arguments[0])
        val relative = arguments[1]
        val documentKind = arguments[2]
        val crashPoint = arguments[3]
        val expectationPath = Path.of(arguments[4])
        require(documentKind in setOf("intent", "receipt", "assessment", "decision"))
        require(crashPoint in setOf("E1", "E2", "E3", "G1", "G2", "G3", "persisted", "source-exchanged", "tamper-assessment"))
        require((documentKind == "decision") == (crashPoint in setOf("persisted", "source-exchanged", "tamper-assessment")))

        var expectationId = "unassigned"
        var armed = false
        var decisionMustBePublished = false
        fun decisionIsPublished(): Boolean = runCatching {
            val root = Json.parseToJsonElement(
                Files.readString(project.resolve("reports/repair-revisions/graph.json")),
            ).jsonObject
            val pending = root["pending"] as? JsonObject ?: return@runCatching false
            pending["acceptanceDecision"] is JsonObject
        }.getOrDefault(false)

        fun pointReached(point: ModuleRevisionFaultPoint): Boolean {
            val expectedEvidenceName = when (documentKind) {
                "intent" -> "${expectationId}.acp-intent.json"
                "receipt" -> "${expectationId}.acp-receipt.json"
                "assessment" -> "${expectationId}.acp-assessment.json"
                "decision" -> ""
                else -> error("unsupported evidence kind")
            }
            if (documentKind != "decision") {
                val evidenceScope = "revision-invocation-evidence"
                val graphScope = "revision-state"
                return when (crashPoint) {
                    "E1" -> point is ModuleRevisionFaultPoint.AfterStateTemporaryDirectorySync &&
                        point.scope == evidenceScope && point.name == expectedEvidenceName
                    "E2" -> point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                        point.scope == evidenceScope && point.name == expectedEvidenceName
                    "E3" -> point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                        point.scope == evidenceScope && point.name == expectedEvidenceName
                    "G1" -> point is ModuleRevisionFaultPoint.AfterStateTemporaryDirectorySync &&
                        point.scope == graphScope && point.name == "graph.json"
                    "G2" -> point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                        point.scope == graphScope && point.name == "graph.json"
                    "G3" -> point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                        point.scope == graphScope && point.name == "graph.json"
                    else -> false
                }
            }
            return when (crashPoint) {
                "persisted", "tamper-assessment" -> point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                    point.scope == "revision-state" && point.name == "graph.json" &&
                    decisionMustBePublished && decisionIsPublished()
                "source-exchanged" -> point is ModuleRevisionFaultPoint.AfterPublicationExchange &&
                    point.phase == "schema6-roll-forward" && point.path == relative && point.index == 0
                else -> false
            }
        }

        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && pointReached(point)) Runtime.getRuntime().halt(86)
            },
        )
        graph.enableRunContract()
        graph.enableDurableTurnProvenance()
        val fixture = ModuleRevisionGraphTest()
        val metadata = fixture.beginSyntheticAcceptedRun(
            graph,
            RepairPublicationMode.ACP_RELEASE,
            template = RevisionRepairMetadata(
            iterationIndex = 1,
            failureKind = "compile",
            prompt = "bounded failure",
            summary = null,
            retainedRegressionIds = emptyList(),
            before = null,
            regressionCorpusSha256 = null,
            publicationMode = RepairPublicationMode.ACP_RELEASE,
        ))
        val attempt = graph.beginAttempt(listOf(relative), metadata)
        expectationId = attempt.id
        val before = project.resolve(relative).readBytes()
        val candidate = before + "\n/* schema-seven child crash candidate */\n".toByteArray()
        val workflowId = "schema-seven-process-crash-workflow"
        val receipt = fixture.completeAcpReceiptDocument(
            project, attempt, relative, before, candidate, turnWorkflowId = workflowId,
        )
        val verified = verifyAcpExecutionReceiptDocument(
            receipt.json.toByteArray(Charsets.UTF_8),
            TRACE_REPAIR_ACP_RECEIPT_KIND,
            TRACE_REPAIR_ACP_TASK_FIELD,
            attempt.id,
        )
        val identity = requireNotNull(receipt.turnIdentity)
        val parentSource = graph.snapshot.nodes.single {
            it.id == (graph.snapshot.provisionalHeadId ?: graph.snapshot.headId)
        }.sourceRevisionSha256
        val intent = AgentTurnIntent.create(
            identity,
            workflowId,
            attempt.id,
            graph.snapshot.profileSha256,
            verified.accessPolicySha256,
            parentSource,
        )

        val assessment: AcpChangeAssessment?
        val proof: RepairValidationProof?
        if (documentKind in setOf("assessment", "decision")) {
            graph.persistAndBindAgentTurnIntent(attempt, intent)
            graph.persistAndBindAgentInvocation(attempt, receipt)
            graph.installCandidate(attempt, mapOf(relative to candidate))
            proof = fixture.syntheticAcceptedProof(graph, attempt)
            assessment = AcpChangeAssessment.create(
                intent = intent,
                receiptSha256 = receipt.sha256,
                sessionIdSha256 = verified.sessionIdCommitmentSha256?.let {
                    sha256("acp-session-commitment-v1:$it".toByteArray(Charsets.UTF_8))
                },
                changesSha256 = verified.resultChangesSha256,
                beforeSha256 = intent.beforeSha256,
                afterSha256 = proof.sourceRevisionSha256,
                observation = AcpChangeObservationStatus.COMPLETE,
                protocolStopCode = null,
                normalizedStopReason = AgentStopReason.COMPLETED,
                policyVerdict = AcpChangePolicyVerdict.ALLOW,
                reasonCodes = emptyList(),
                validationStatus = AcpChangeValidationStatus.PASSED,
                validationProofSha256 = listOf(proof.evidenceSha256),
                eligibility = AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION,
                updatesSha256 = verified.updatesSha256,
            )
        } else {
            assessment = null
            proof = null
        }

        val expected = listOf(
            attempt.id,
            Base64.getEncoder().encodeToString(intent.canonicalBytes()),
            Base64.getEncoder().encodeToString(receipt.json.toByteArray(Charsets.UTF_8)),
            assessment?.let { Base64.getEncoder().encodeToString(it.canonicalBytes()) }.orEmpty(),
            Base64.getEncoder().encodeToString(candidate),
        ).joinToString("\n")
        Files.writeString(expectationPath, expected)

        if (documentKind == "intent") {
            armed = true
            graph.persistAndBindAgentTurnIntent(attempt, intent)
        } else if (documentKind == "receipt") {
            graph.persistAndBindAgentTurnIntent(attempt, intent)
            armed = true
            graph.persistAndBindAgentInvocation(attempt, receipt)
        } else if (documentKind == "assessment") {
            armed = true
            graph.persistAndBindAgentAssessment(attempt, requireNotNull(assessment))
        } else {
            graph.persistAndBindAgentAssessment(attempt, requireNotNull(assessment))
            armed = true
            decisionMustBePublished = true
            graph.accept(attempt, RepairEvidence("valid", "schema-seven crash probe"), requireNotNull(proof))
        }

        graph.close()
        kotlin.system.exitProcess(87)
    }
}
