package decompengine.repair

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.AcpExecutionCleanupDisposition
import decompengine.acp.AcpExecutionEvidenceCompleteness
import decompengine.acp.AcpExecutionEvidenceSnapshot
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
import decompengine.acp.ACP_KOTLIN_SDK_VERSION
import decompengine.acp.ACP_STABLE_PROTOCOL_VERSION
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentSessionReference
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentTurnIdentity
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import decompengine.agent.AgentHarness
import decompengine.project.AcpExecutionReceiptDocument
import decompengine.project.AcpChangePublicationEligibility
import decompengine.project.BoundedAgentExecutionEventRecorder
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.SourceTreeGenerator
import decompengine.project.SourceTreeManifestReader
import decompengine.project.BoundedLlmModuleReconstructor
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.ReconstructionHostSafetyLimits
import decompengine.project.ReconstructionProfile
import decompengine.project.ReconstructionOutputWorkspace
import decompengine.project.ProjectLayoutProfile
import decompengine.project.ProjectFileDeclaration
import decompengine.project.ArchivalBundleVerifier
import decompengine.project.ArchivalBundleLimits
import decompengine.project.ArchivalProjectAuditor
import decompengine.project.ArchivalPackager
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import decompengine.project.SourceTreeManifest
import decompengine.project.captureBuildSourceRevision
import decompengine.project.MakeProjectBuilder
import decompengine.project.GeneratedCRepairIndexProfile
import decompengine.project.sha256
import decompengine.project.moduleIdForPath
import decompengine.oracle.behavior.LlvmBehaviorCandidateAcpLineageIndexV2Publisher
import decompengine.validation.ProcessInput
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonArray
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.acp.acpSandboxCanonicalStringDigest
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readLines
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ModuleRevisionGraphTest {
    @Test
    fun `exploration snapshot copies corpus and rejects changed graph before repair preparation`() {
        val project = generatedProject()
        val binarySha256 = "a".repeat(64)
        val originalInput = ProcessInput("retained", listOf("one"), byteArrayOf(0, 1))
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            graph.retainRegressionInputs(listOf(originalInput))
        }
        val snapshot = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            graph.captureExplorationSnapshot(binarySha256)
        }
        assertEquals(binarySha256, snapshot.originalBinarySha256)
        val exposed = snapshot.inputs.single()
        exposed.stdin[0] = 99
        assertEquals(0, snapshot.inputs.single().stdin[0].toInt())

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            graph.requireCurrentExplorationSnapshot(snapshot)
        }

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            graph.retainRegressionInputs(listOf(originalInput, ProcessInput("later", emptyList(), byteArrayOf(2))))
        }
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val stale = assertFailsWith<IllegalArgumentException> {
                graph.requireCurrentExplorationSnapshot(snapshot)
            }
            assertTrue(stale.message.orEmpty().contains("stale"))
        }
        assertEquals(listOf(originalInput), snapshot.inputs, "snapshot inputs must be detached from later graph writes")
    }

    @Test
    fun `legacy generated C fingerprint is rejected before pending recovery writes`() {
        val current = decompengine.project.GeneratedCMakeReconstructionProfile.descriptor
        val priorFingerprints = listOf(
            sha256(current.id.toByteArray(Charsets.UTF_8)),
            sha256(("generated-c-repair-index-v2\n" + current.sha256 + "\n").toByteArray(Charsets.UTF_8)),
        )
        for (legacyFingerprint in priorFingerprints) {
            val project = generatedProject()
            val profile = GeneratedCRepairIndexProfile
            assertFalse(legacyFingerprint == profile.configurationSha256())
            assertEquals(profile.configurationSha256(), profile.configurationSha256(RepairResourceBudget()))
            val legacyProfile = object : RepairIndexProfile by profile {
                override fun configurationSha256(): String = legacyFingerprint
                override fun configurationSha256(budget: RepairResourceBudget): String = legacyFingerprint
            }
            val target = project.resolve("src/modules/alpha.c")
            val accepted = target.readBytes()
            val candidate = accepted + "\n/* authored pending legacy revision */\n".toByteArray()
            ModuleRevisionGraph.openLegacyForTesting(project, legacyProfile).use { graph ->
                val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
                graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
            }
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            val graphBefore = graphPath.readBytes()
            val failure = assertFailsWith<IllegalArgumentException> {
                ModuleRevisionGraph.open(project, profile)
            }
            assertTrue(failure.message.orEmpty().contains("profile fingerprint differs"))
            assertContentEquals(candidate, target.readBytes())
            assertContentEquals(graphBefore, graphPath.readBytes())
            // The matching historical policy can still recover its own pending transaction. The
            // production registry intentionally does not offer this test-only compatibility adapter.
            ModuleRevisionGraph.open(project, legacyProfile).use { recovered ->
                assertContentEquals(accepted, target.readBytes())
                assertEquals(null, recovered.snapshot.pendingAttemptId)
            }
        }
    }

    @Test
    fun `repair graph persists failed ACP receipt before rejection and detects later tampering`() {
        val project = generatedProject()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val corpus = graph.retainedRegressionCorpus()
        val attempt = graph.beginAttempt(
            listOf("src/modules/alpha.c"),
            RevisionRepairMetadata(
                1,
                "compile",
                "bounded failure",
                null,
                emptyList(),
                null,
                corpus.sha256,
            ),
        )
        val document = failedAcpReceiptDocument(project, attempt)

        val pending = graph.persistAndBindAgentInvocation(attempt, document)
        assertEquals(RepairAgentAssessmentStatus.PENDING, pending.assessmentStatus)
        assertFalse(pending.receiptReleaseComplete)
        val receiptPath = project.resolve(pending.receiptPath)
        assertTrue(receiptPath.exists())
        assertFalse(receiptPath.readText().contains("peer-controlled failure text"))
        val acceptanceFailure = assertFailsWith<IllegalArgumentException> {
            graph.accept(attempt, RepairEvidence("valid", "must not accept failed invocation"))
        }
        assertTrue(acceptanceFailure.message.orEmpty().contains("incomplete ACP"))
        val rejected = graph.reject(attempt, RepairEvidence("agent-failure-protocol", "provider invocation failed"))
        assertEquals(
            RepairAgentAssessmentStatus.REJECTED,
            rejected.repairMetadata?.agentInvocation?.assessmentStatus,
        )
        val rejectedProjection = Json.parseToJsonElement(renderRepairHistoryProjection(
            graph.derivedRepairIterations(), emptyList(), MAXIMUM_REPAIR_PROJECTION_BYTES,
            runs = graph.snapshot.runs,
        )).jsonObject
        val historyJob = decompengine.jobs.Job("fixture", "fixture", "complete", "now", sizeBytes = 0,
            binaryPath = project.resolve("fixture.elf"), metadata = decompengine.binary.ElfMetadata("ELF64", "little", 1u,
                "fixture", "executable", "fixture", 0uL, 0u, 0u, 0u, 0u))
        val rejectedHtml = decompengine.web.renderRepairHistory(
            historyJob,
            reportContext = decompengine.web.WebReportContext(project.resolve("reports")),
            payload = rejectedProjection,
        )
        assertTrue(rejectedHtml.contains("Rollback: Unverified; this history does not record restoration completion or failure."), rejectedHtml)
        assertTrue(rejectedHtml.contains("ACP receipt is unavailable; release completeness is not established."), rejectedHtml)
        assertFalse(rejectedHtml.contains("bounded failure"), rejectedHtml)
        assertFalse(rejectedHtml.contains("provider invocation failed"), rejectedHtml)
        assertFalse(rejectedHtml.contains(pending.receiptPath), rejectedHtml)
        graph.close()

        receiptPath.writeText(receiptPath.readText().replaceFirst("\"schemaVersion\": 2", "\"schemaVersion\": 1"))
        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }
        assertTrue(failure.message.orEmpty().contains("digest"))
    }

    @Test
    fun `accepted agent repair is bound to one release-complete ACP receipt`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val before = target.readBytes()
        val after = before + "\n/* receipt-bound candidate */\n".toByteArray()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val corpus = graph.retainedRegressionCorpus()
        val attemptMetadata = beginSyntheticAcceptedRun(graph, RepairPublicationMode.ACP_RELEASE,
            RevisionRepairMetadata(
                1,
                "compile",
                "bounded failure",
                null,
                emptyList(),
                null,
                corpus.sha256,
            ))
        val attempt = graph.beginAttempt(listOf(relative), attemptMetadata)

        val document = completeAcpReceiptDocument(project, attempt, relative, before, after)
        assertTrue(document.releaseComplete)
        graph.persistAndBindAgentInvocation(attempt, document)
        graph.installCandidate(attempt, mapOf(relative to after))
        val accepted = graph.accept(attempt, RepairEvidence("valid", "candidate passed validation"),
            syntheticAcceptedProof(graph, attempt))

        val binding = requireNotNull(accepted.repairMetadata?.agentInvocation)
        assertEquals(RepairAgentAssessmentStatus.ACCEPTED, binding.assessmentStatus)
        assertEquals("returned-completed", binding.terminalOutcome)
        assertTrue(binding.receiptReleaseComplete)
        assertEquals(document.requestSha256, binding.requestSha256)
        assertEquals(document.resultChangesSha256, binding.resultChangesSha256)
        assertEquals(document.sha256, binding.receiptSha256)
        graph.close()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            val iteration = reopened.derivedRepairIterations().single()
            assertTrue(iteration.releaseComplete)
            assertEquals(RepairAttemptDisposition.FULLY_ACCEPTED, iteration.disposition)
            assertEquals(RepairPublicationMode.ACP_RELEASE, iteration.publicationMode)
            assertEquals(binding, iteration.agentInvocation)
            assertEquals("accepted", repairAttemptLabel(iteration))
            reopened.enableRunContract()
            val migrated = reopened.derivedRepairIterations().single()
            assertEquals(ModuleRevisionStatus.ACCEPTED, reopened.snapshot.nodes.last().status)
            assertEquals(RepairAttemptDisposition.FULLY_ACCEPTED, migrated.disposition)
            assertEquals(binding, migrated.agentInvocation)
            assertEquals(accepted.id, reopened.snapshot.fullyAcceptedHeadId)
            val run = reopened.beginRun(1, 60_000)
            val cli = decompengine.presentRepairOutcome(RepairRunOutcome(listOf(migrated), null, run))
            assertTrue(cli.lines.contains("accepted revision: ${accepted.id}"))
            val payload = Json.parseToJsonElement(renderRepairHistoryProjection(listOf(migrated), emptyList(),
                MAXIMUM_REPAIR_PROJECTION_BYTES, runs = reopened.snapshot.runs)).jsonObject
            val job = decompengine.jobs.Job("fixture", "fixture", "complete", "now", sizeBytes = 0,
                binaryPath = target, metadata = decompengine.binary.ElfMetadata("ELF64", "little", 1u,
                    "fixture", "executable", "fixture", 0uL, 0u, 0u, 0u, 0u))
            val html = decompengine.web.renderRepairHistory(job, payload = payload)
            assertTrue(html.contains("Compile repair — accepted"), html)
            assertTrue(html.contains("Accepted revision: <code>${accepted.id}</code>"), html)
            assertFalse(html.contains("Compile repair — unverified"), html)
            reopened.finishRun(RepairRunStatus.REJECTED, null)
        }
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        graphPath.writeText(
            graphPath.readText().replaceFirst(
                "\"requestSha256\":\"${binding.requestSha256}\"",
                "\"requestSha256\":\"${"9".repeat(64)}\"",
            ),
        )
        val crossPair = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }
        assertTrue(crossPair.message.orEmpty().contains("cross-paired"))
    }

    @Test
    fun `schema six recovery authenticates its ACP receipt before source exchange`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val before = target.readBytes()
        val originalKey = Files.readAttributes(target, BasicFileAttributes::class.java).fileKey()
        val after = before + "\n/* receipt recovery authority */\n".toByteArray()
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePublicationExchange &&
                    point.phase == "schema6-roll-forward") {
                    throw IllegalStateException("leave a durable release decision before source publication")
                }
            },
        )
        val corpus = graph.retainedRegressionCorpus()
        val metadata = beginSyntheticAcceptedRun(
            graph,
            RepairPublicationMode.ACP_RELEASE,
            RevisionRepairMetadata(1, "compile", "bounded failure", null, emptyList(), null, corpus.sha256),
        )
        val attempt = graph.beginAttempt(listOf(relative), metadata)
        val receipt = completeAcpReceiptDocument(project, attempt, relative, before, after)
        graph.persistAndBindAgentInvocation(attempt, receipt)
        graph.installCandidate(attempt, mapOf(relative to after))
        assertFailsWith<RepairAcceptancePendingException> {
            graph.accept(attempt, RepairEvidence("valid", "release candidate passed"),
                syntheticAcceptedProof(graph, attempt))
        }
        graph.close()

        val receiptPath = project.resolve("reports/repair-revisions/${attempt.id}.acp-receipt.json")
        Files.delete(receiptPath)
        assertFailsWith<Exception> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        }
        assertContentEquals(before, target.readBytes(), "missing ACP receipt must refuse before source exchange")
        assertEquals(originalKey, Files.readAttributes(target, BasicFileAttributes::class.java).fileKey())
        val decidedGraphBytes = project.resolve("reports/repair-revisions/graph.json").readBytes()
        Files.writeString(receiptPath, receipt.json)
        val extraReceipt = project.resolve("reports/repair-revisions/revision_99999999_stale.acp-receipt.json")
        Files.writeString(extraReceipt, "unreferenced receipt bytes")
        val inventoryFailure = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        }
        assertTrue(inventoryFailure.message.orEmpty().contains("inventory"), inventoryFailure.message.orEmpty())
        assertContentEquals(before, target.readBytes(), "extra receipt inventory must refuse before source exchange")
        assertEquals(originalKey, Files.readAttributes(target, BasicFileAttributes::class.java).fileKey())
        assertContentEquals(decidedGraphBytes, project.resolve("reports/repair-revisions/graph.json").readBytes())
        val durable = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject
        assertTrue(durable.getValue("pending").jsonObject.getValue("acceptanceDecision") is JsonObject)
        assertEquals(1, durable.getValue("nodes").jsonArray.size,
            "failed receipt authentication must not persist an accepted graph node")
    }

    @Test
    fun `schema six recovery authenticates provisional ancestor receipts before promotion`() {
        val project = generatedProject()
        val betaPath = "src/modules/beta.c"
        val alphaPath = "src/modules/alpha.c"
        val beta = project.resolve(betaPath)
        val alpha = project.resolve(alphaPath)
        val betaBefore = beta.readBytes()
        val alphaBefore = alpha.readBytes()
        val betaKey = Files.readAttributes(beta, BasicFileAttributes::class.java).fileKey()
        val alphaKey = Files.readAttributes(alpha, BasicFileAttributes::class.java).fileKey()
        var leaveDecision = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (leaveDecision && point is ModuleRevisionFaultPoint.BeforePublicationExchange &&
                    point.phase == "schema6-roll-forward") {
                    throw IllegalStateException("leave the accepted promotion decision before exchange")
                }
            },
        )
        val firstMetadata = beginSyntheticAcceptedRun(graph, RepairPublicationMode.ACP_RELEASE)
            .copy(prompt = "bounded failure")
        val provisional = graph.beginAttempt(listOf(betaPath), firstMetadata)
        val betaCandidate = betaBefore + "\n/* retained provisional contribution */\n".toByteArray()
        graph.persistAndBindAgentInvocation(
            provisional,
            completeAcpReceiptDocument(project, provisional, betaPath, betaBefore, betaCandidate),
        )
        graph.installCandidate(provisional, mapOf(betaPath to betaCandidate))
        graph.recordProvisional(
            provisional,
            RepairEvidence("behavior", "retain provisional candidate"),
            syntheticAcceptedProof(graph, provisional),
        )

        val corpus = graph.retainedRegressionCorpus()
        val secondMetadata = firstMetadata.copy(
            iterationIndex = 2,
            prompt = "bounded failure",
            retainedRegressionIds = corpus.inputs.map { it.id },
            regressionCorpusSha256 = corpus.sha256,
        )
        val accepted = graph.beginAttempt(listOf(alphaPath), secondMetadata)
        val alphaCandidate = alphaBefore + "\n/* accepted candidate */\n".toByteArray()
        graph.persistAndBindAgentInvocation(
            accepted,
            completeAcpReceiptDocument(project, accepted, alphaPath, alphaBefore, alphaCandidate),
        )
        graph.installCandidate(accepted, mapOf(alphaPath to alphaCandidate))
        leaveDecision = true
        assertFailsWith<RepairAcceptancePendingException> {
            graph.accept(accepted, RepairEvidence("valid", "accepted with complete validation"),
                syntheticAcceptedProof(graph, accepted))
        }
        graph.close()

        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val decidedGraph = graphPath.readBytes()
        val provisionalReceiptPath = project.resolve("reports/repair-revisions/${provisional.id}.acp-receipt.json")
        val receiptBytes = provisionalReceiptPath.readBytes()
        val originalReceiptSha = sha256(receiptBytes)

        fun assertRefusedBeforePublication(receipt: ByteArray, updateBinding: Boolean, label: String) {
            provisionalReceiptPath.writeBytes(receipt)
            if (updateBinding) {
                val changedGraph = decidedGraph.decodeToString().replace(originalReceiptSha, sha256(receipt))
                assertNotEquals(decidedGraph.decodeToString(), changedGraph, "$label must update the retained receipt binding")
                graphPath.writeText(changedGraph)
            } else {
                graphPath.writeBytes(decidedGraph)
            }
            val expectedGraph = graphPath.readBytes()
            assertFailsWith<IllegalArgumentException>(label) {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
            }
            assertContentEquals(betaBefore, beta.readBytes(), "$label must not publish provisional source")
            assertContentEquals(alphaBefore, alpha.readBytes(), "$label must not publish accepted source")
            assertEquals(betaKey, Files.readAttributes(beta, BasicFileAttributes::class.java).fileKey())
            assertEquals(alphaKey, Files.readAttributes(alpha, BasicFileAttributes::class.java).fileKey())
            assertContentEquals(expectedGraph, graphPath.readBytes(), "$label must leave the durable decision unchanged")
        }

        assertRefusedBeforePublication(receiptBytes + byteArrayOf('\n'.code.toByte()), updateBinding = false,
            label = "provisional receipt digest mismatch")
        assertRefusedBeforePublication("{".toByteArray(), updateBinding = true,
            label = "malformed provisional receipt with a refreshed graph digest")
        val forgedReleaseReceipt = receiptBytes.decodeToString().replace(
            "\"networkIsolated\":true",
            "\"networkIsolated\":false",
        ).toByteArray()
        assertNotEquals(receiptBytes.decodeToString(), forgedReleaseReceipt.decodeToString())
        assertRefusedBeforePublication(forgedReleaseReceipt, updateBinding = true,
            label = "semantically forged provisional release receipt with a refreshed graph digest")
    }

    @Test
    fun `repair candidate cannot differ from the exact ACP result change set`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val before = target.readBytes()
        val declaredAfter = before + "\n/* agent-declared candidate */\n".toByteArray()
        val installedAfter = before + "\n/* cross-paired candidate */\n".toByteArray()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val corpus = graph.retainedRegressionCorpus()
        val attemptMetadata = beginSyntheticAcceptedRun(graph, RepairPublicationMode.ACP_RELEASE,
            RevisionRepairMetadata(
                1,
                "compile",
                "bounded failure",
                null,
                emptyList(),
                null,
                corpus.sha256,
            ))
        val attempt = graph.beginAttempt(listOf(relative), attemptMetadata)
        graph.persistAndBindAgentInvocation(
            attempt,
            completeAcpReceiptDocument(project, attempt, relative, before, declaredAfter),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            graph.installCandidate(attempt, mapOf(relative to installedAfter))
        }

        assertTrue(
            failure.message.orEmpty().contains("differ from the bound ACP result"),
            failure.message.orEmpty(),
        )
        graph.reject(attempt, RepairEvidence("candidate-error", "cross-paired change rejected"))
        graph.close()
        assertContentEquals(before, target.readBytes())
    }

    @Test
    fun `forged release marker cannot hide incomplete ACP process evidence`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val before = target.readBytes()
        val after = before + "\n/* forged-release regression */\n".toByteArray()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val corpus = graph.retainedRegressionCorpus()
        val attemptMetadata = beginSyntheticAcceptedRun(graph, RepairPublicationMode.ACP_RELEASE,
            RevisionRepairMetadata(
                1,
                "compile",
                "bounded failure",
                null,
                emptyList(),
                null,
                corpus.sha256,
            ))
        val attempt = graph.beginAttempt(listOf(relative), attemptMetadata)
        val document = completeAcpReceiptDocument(project, attempt, relative, before, after)
        graph.persistAndBindAgentInvocation(attempt, document)
        graph.installCandidate(attempt, mapOf(relative to after))
        val accepted = graph.accept(attempt, RepairEvidence("valid", "candidate passed validation"),
            syntheticAcceptedProof(graph, attempt))
        val binding = requireNotNull(accepted.repairMetadata?.agentInvocation)
        graph.close()

        val receiptPath = project.resolve(binding.receiptPath)
        val tampered = receiptPath.readText().replaceFirst(
            "\"networkIsolated\":true",
            "\"networkIsolated\":false",
        )
        receiptPath.writeText(tampered)
        val tamperedSha256 = sha256(tampered.toByteArray())
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        graphPath.writeText(
            graphPath.readText().replaceFirst(binding.receiptSha256, tamperedSha256),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }
        assertTrue(failure.message.orEmpty().contains("network isolation"))
    }

    @Test
    fun `pending assessment failure preserves raw ACP receipt without fallback finalization`() {
        val project = generatedProject()
        var armed = false
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                    point.scope == "revision-state" && point.name == "graph.json"
                ) {
                    throw IllegalStateException("injected pending-assessment persistence failure")
                }
            },
        )
        val corpus = graph.retainedRegressionCorpus()
        val attempt = graph.beginAttempt(
            listOf("src/modules/alpha.c"),
            RevisionRepairMetadata(
                1,
                "compile",
                "bounded failure",
                null,
                emptyList(),
                null,
                corpus.sha256,
            ),
        )
        armed = true

        val failure = assertFailsWith<RepairAgentEvidencePersistenceException> {
            graph.persistAndBindAgentInvocation(attempt, failedAcpReceiptDocument(project, attempt))
        }

        assertTrue(failure.message.orEmpty().contains("preserved"))
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        val receiptPath = project.resolve("reports/repair-revisions/${attempt.id}.acp-receipt.json")
        assertTrue(receiptPath.exists())
        graph.close()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            val recovered = reopened.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, recovered.status)
            assertTrue(recovered.recoveredAfterCrash)
            assertEquals(
                RepairAgentAssessmentStatus.REJECTED,
                recovered.repairMetadata?.agentInvocation?.assessmentStatus,
            )
        }
        assertTrue(receiptPath.exists())
    }

    @Test
    fun `startup reconciles an assessment persisted before its graph binding`() {
        val project = generatedProject()
        var armed = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                    point.scope == "revision-state" && point.name == "graph.json"
                ) throw IllegalStateException("simulated process stop after assessment sidecar publication")
            },
        )
        val sourcePath = "src/modules/alpha.c"
        val before = project.resolve(sourcePath).readBytes()
        val after = before + "\n/* durable assessment recovery fixture */\n".toByteArray()
        val corpus = graph.retainedRegressionCorpus()
        graph.beginRun(1, 60_000)
        val attempt = graph.beginAttempt(
            listOf(sourcePath),
            RevisionRepairMetadata(1, "compile", "bounded failure", null, emptyList(), null, corpus.sha256),
        )
        val receipt = completeAcpReceiptDocument(
            project, attempt, sourcePath, before, after, turnWorkflowId = "assessment-recovery-workflow",
        )
        val verified = decompengine.project.verifyAcpExecutionReceiptDocument(
            receipt.json.toByteArray(Charsets.UTF_8),
            TRACE_REPAIR_ACP_RECEIPT_KIND,
            TRACE_REPAIR_ACP_TASK_FIELD,
            attempt.id,
        )
        val identity = requireNotNull(receipt.turnIdentity)
        val intent = decompengine.project.AgentTurnIntent.create(
            identity,
            "assessment-recovery-workflow",
            attempt.id,
            graph.snapshot.profileSha256,
            verified.accessPolicySha256,
            graph.snapshot.nodes.single { it.id == graph.snapshot.headId }.sourceRevisionSha256,
        )
        graph.persistAndBindAgentTurnIntent(attempt, intent)
        graph.persistAndBindAgentInvocation(attempt, receipt)
        val assessment = decompengine.project.AcpChangeAssessment.create(
            intent = intent,
            receiptSha256 = receipt.sha256,
            sessionIdSha256 = verified.sessionIdCommitmentSha256?.let {
                sha256("acp-session-commitment-v1:$it".toByteArray(Charsets.UTF_8))
            },
            changesSha256 = verified.resultChangesSha256,
            beforeSha256 = intent.beforeSha256,
            afterSha256 = null,
            observation = decompengine.project.AcpChangeObservationStatus.UNKNOWN,
            protocolStopCode = null,
            normalizedStopReason = AgentStopReason.COMPLETED,
            policyVerdict = decompengine.project.AcpChangePolicyVerdict.REJECT,
            reasonCodes = listOf("candidate_not_authorized"),
            validationStatus = decompengine.project.AcpChangeValidationStatus.NOT_RUN,
            validationProofSha256 = emptyList(),
            eligibility = decompengine.project.AcpChangePublicationEligibility.REJECTED,
            updatesSha256 = verified.updatesSha256,
        )
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val receiptOnlyGraph = graphPath.readBytes()
        armed = true
        assertFailsWith<RepairAgentEvidencePersistenceException> {
            graph.persistAndBindAgentAssessment(attempt, assessment)
        }
        graph.close()
        // Model a crash after the immutable sidecar was published but before the graph reference
        // was committed. The sidecar remains authoritative only when it matches the pending turn.
        graphPath.writeBytes(receiptOnlyGraph)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            val recovered = reopened.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, recovered.status)
            assertTrue(recovered.recoveredAfterCrash)
            assertEquals(RepairAgentAssessmentStatus.REJECTED,
                recovered.repairMetadata?.agentInvocation?.assessmentStatus)
            assertEquals(assessment.sha256, recovered.repairMetadata?.agentInvocation?.assessmentSha256)
        }
    }

    @Test
    fun `startup recovers an intent when graph binding fails after immutable publication`() {
        val project = generatedProject()
        var armed = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point ==
                    ModuleRevisionFaultPoint.AfterStateTemporaryDirectorySync("revision-state", "graph.json")) {
                    throw IllegalStateException("simulated stop after intent publication")
                }
            },
        )
        val relative = "src/modules/alpha.c"
        val corpus = graph.retainedRegressionCorpus()
        val attempt = graph.beginAttempt(
            listOf(relative),
            RevisionRepairMetadata(1, "compile", "durable intent recovery", null, emptyList(), null, corpus.sha256),
        )
        val request = AgentExecutionRequest(
            objective = "repair one module",
            workspaceRoots = listOf(AgentWorkspaceRoot("project", project)),
            accessPolicy = AgentAccessPolicy(listOf(AgentPathRule(
                AgentWorkspacePath("project", relative),
                setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
            ))),
        )
        val workflowId = "orphaned-intent-recovery-workflow"
        val identity = AgentTurnIdentity.create(attempt.id, request, workflowId)
        val requestBinding = AgentExecutionRequestBinding.capture(request)
        val parentSource = graph.snapshot.nodes.single { it.id == graph.snapshot.headId }.sourceRevisionSha256
        val intent = decompengine.project.AgentTurnIntent.create(
            identity,
            workflowId,
            attempt.id,
            graph.snapshot.profileSha256,
            requestBinding.accessPolicySha256,
            parentSource,
        )

        armed = true
        assertFailsWith<RepairAgentEvidencePersistenceException> {
            graph.persistAndBindAgentTurnIntent(attempt, intent)
        }
        val intentPath = project.resolve("reports/repair-revisions/${attempt.id}.acp-intent.json")
        assertTrue(Files.isRegularFile(intentPath))
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        graph.close()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            val rejected = reopened.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertTrue(rejected.recoveredAfterCrash)
            assertEquals(intent.sha256, rejected.repairMetadata?.turnIntent?.intentSha256)
            assertEquals(intent.turnId, rejected.repairMetadata?.turnIntent?.turnId)
            assertNull(rejected.repairMetadata?.agentInvocation)
            assertEquals(1, reopened.snapshot.nodes.count { it.repairMetadata?.turnIntent?.intentSha256 == intent.sha256 })
        }
        assertTrue(Files.isRegularFile(intentPath), "recovered intent remains part of the graph evidence inventory")
    }

    @Test
    fun `new repair turns migrate a legacy graph before dispatch without inventing history`() {
        val project = generatedProject()
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            schemaVersion = 4,
        )
        assertEquals(4, graph.snapshot.schemaVersion)
        graph.enableRunContract()
        assertEquals(5, graph.snapshot.schemaVersion)
        val historicalNodeIds = graph.snapshot.nodes.map { it.id }
        assertTrue(graph.snapshot.nodes.all { it.repairMetadata?.turnIntent == null })

        graph.enableDurableTurnProvenance()
        assertEquals(7, graph.snapshot.schemaVersion)
        assertEquals(historicalNodeIds, graph.snapshot.nodes.map { it.id })
        assertTrue(graph.snapshot.nodes.all { it.repairMetadata?.turnIntent == null })

        val metadata = beginSyntheticAcceptedRun(graph)
        val relative = "src/modules/alpha.c"
        val attempt = graph.beginAttempt(listOf(relative), metadata)
        val request = AgentExecutionRequest(
            objective = "repair one module",
            workspaceRoots = listOf(AgentWorkspaceRoot("project", project)),
            accessPolicy = AgentAccessPolicy(listOf(AgentPathRule(
                AgentWorkspacePath("project", relative),
                setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
            ))),
        )
        val workflowId = "migrated-legacy-turn-workflow"
        val identity = AgentTurnIdentity.create(attempt.id, request, workflowId)
        val binding = AgentExecutionRequestBinding.capture(request)
        val parentSource = graph.snapshot.nodes.single { it.id == graph.snapshot.headId }.sourceRevisionSha256
        val intent = decompengine.project.AgentTurnIntent.create(
            identity,
            workflowId,
            attempt.id,
            graph.snapshot.profileSha256,
            binding.accessPolicySha256,
            parentSource,
        )
        graph.persistAndBindAgentTurnIntent(attempt, intent)
        graph.close()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            assertEquals(7, reopened.snapshot.schemaVersion)
            assertTrue(reopened.snapshot.nodes.all { node ->
                node.id !in historicalNodeIds || node.repairMetadata?.turnIntent == null
            })
            val recovered = reopened.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, recovered.status)
            assertTrue(recovered.recoveredAfterCrash)
            assertEquals(intent.sha256, recovered.repairMetadata?.turnIntent?.intentSha256)
            assertEquals(intent.turnId, recovered.repairMetadata?.turnIntent?.turnId)
        }
    }

    @Test
    fun `raw receipt persistence failure cannot be converted into a repair rejection`() {
        val project = generatedProject()
        var armed = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                    point.scope == "revision-invocation-evidence"
                ) {
                    throw IllegalStateException("injected raw-receipt persistence failure")
                }
            },
        )
        val corpus = graph.retainedRegressionCorpus()
        val attempt = graph.beginAttempt(
            listOf("src/modules/alpha.c"),
            RevisionRepairMetadata(
                1,
                "compile",
                "bounded failure",
                null,
                emptyList(),
                null,
                corpus.sha256,
            ),
        )
        armed = true

        val failure = assertFailsWith<RepairAgentEvidencePersistenceException> {
            graph.persistAndBindAgentInvocation(attempt, failedAcpReceiptDocument(project, attempt))
        }

        assertTrue(failure.message.orEmpty().contains("before assessment"))
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        assertEquals(1, graph.snapshot.nodes.size)
        assertFalse(project.resolve("reports/repair-revisions/${attempt.id}.acp-receipt.json").exists())
        graph.close()
    }

    @Test
    fun `multi-module diagnostics select only dependency-indexed context`() {
        val project = generatedProject()
        val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)

        val selection = index.select(
            "compile",
            "src/modules/alpha.c:12: error: bad declaration\nsrc/modules/charlie.c:3: error: missing expression",
        )

        assertEquals(listOf("alpha", "charlie"), selection.seedModules)
        assertEquals(listOf("beta"), selection.dependencyModules)
        assertTrue("src/modules/alpha.c" in selection.writablePaths)
        assertTrue("include/modules/alpha.h" in selection.writablePaths)
        assertTrue("src/modules/alpha_internal.h" in selection.writablePaths)
        assertTrue("src/modules/charlie.c" in selection.writablePaths)
        assertTrue("include/modules/beta.h" in selection.readablePaths)
        assertFalse("src/modules/beta.c" in selection.readablePaths)
        assertFalse(selection.readablePaths.any { "delta" in it })
    }

    @Test
    fun `source-bound build owners select context when aggregate output has no source path`() {
        val project = generatedProject()
        val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
        project.resolve("reports/build_contract.json").writeText(
            "{\"schemaVersion\":3,\"sourceStableDuringBuild\":true," +
                "\"sourceRevisionSha256\":\"${index.sourceRevisionSha256}\"," +
                "\"failedOwners\":[\"charlie\"],\"modules\":[{\"id\":\"charlie\"}]}",
        )

        val selection = index.select("compile", "make: *** [all] Error 2")

        assertEquals(listOf("charlie"), selection.seedModules)
        assertTrue("src/modules/charlie.c" in selection.writablePaths)
        assertFalse(selection.readablePaths.any { "alpha" in it || "delta" in it })

        val boundSelection = index.select(
            "compile",
            "src/modules/alpha.c:1: error: unauthenticated text must not widen the build owner",
        )
        assertEquals(listOf("charlie"), boundSelection.seedModules)
        assertFalse("src/modules/alpha.c" in boundSelection.readablePaths)
    }

    @Test
    fun `present generated C build ownership evidence is validated and bounded without fallback`() {
        run {
            val project = generatedProject()
            val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
            project.resolve("reports/build_contract.json").writeText("{}")

            val failure = assertFailsWith<IllegalArgumentException> {
                index.select("compile", "src/modules/alpha.c: error: exact path must not bypass bad evidence")
            }

            assertTrue(failure.message.orEmpty().contains("schemaVersion"))
        }
        run {
            val project = generatedProject()
            val budget = RepairResourceBudget(maximumContextModules = 1)
            val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile, budget)
            project.resolve("reports/build_contract.json").writeText(
                "{\"schemaVersion\":3,\"sourceStableDuringBuild\":true," +
                    "\"sourceRevisionSha256\":\"${index.sourceRevisionSha256}\"," +
                    "\"failedOwners\":[\"alpha\",\"beta\"]," +
                    "\"modules\":[{\"id\":\"alpha\"},{\"id\":\"beta\"}]}",
            )

            val failure = assertFailsWith<RepairBudgetExceededException> {
                index.select("compile", "aggregate failure")
            }

            assertTrue(failure.message.orEmpty().contains("failed owners"))
        }
    }

    @Test
    fun `rejected candidate restores byte-identical files and records downstream invalidation`() {
        val project = generatedProject()
        val alpha = project.resolve("src/modules/alpha.c")
        val beta = project.resolve("src/modules/beta.c")
        val alphaBefore = alpha.readBytes()
        val betaBefore = beta.readBytes()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c", "src/modules/beta.c"))
            graph.installCandidate(
                attempt,
                mapOf(
                    "src/modules/alpha.c" to alphaBefore + byteArrayOf(0, 1, 2, 3),
                    "src/modules/beta.c" to betaBefore + "\n/* candidate beta */\n".toByteArray(),
                ),
            )
            val rejected = graph.reject(attempt, RepairEvidence("compile", "candidate did not compile"))

            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertEquals(listOf("alpha", "beta"), rejected.changedModules)
            assertContentEquals(alphaBefore, alpha.readBytes())
            assertContentEquals(betaBefore, beta.readBytes())
            assertEquals(graph.snapshot.nodes.first().id, graph.snapshot.headId)
        }
    }

    @Test
    fun `accepted change explicitly invalidates all transitive dependents and restart is stable`() {
        val project = generatedProject()
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        lateinit var acceptedId: String
        lateinit var acceptedSha256: String
        val candidate = project.resolve("src/modules/beta.c").readBytes() + "\n/* accepted beta */\n".toByteArray()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val metadata = beginSyntheticAcceptedRun(graph)
            val attempt = graph.beginAttempt(listOf("src/modules/beta.c"), metadata)
            acceptedSha256 = sha256(candidate)
            graph.installCandidate(attempt, mapOf("src/modules/beta.c" to candidate))
            val accepted = graph.accept(attempt, RepairEvidence("valid", "retained cases matched", "reports/case.json"),
                syntheticAcceptedProof(graph, attempt))
            acceptedId = accepted.id

            assertEquals(ModuleRevisionStatus.ACCEPTED, accepted.status)
            assertEquals(listOf("beta"), accepted.changedModules)
            assertEquals(listOf("alpha"), accepted.invalidatedModules)
            assertEquals(accepted.id, graph.snapshot.headId)
        }
        assertTrue(project.resolve("source_tree_manifest.json").readText().contains(acceptedSha256))
        assertTrue(project.resolve("source_tree_manifest.json").readText().contains("repair-revision"))
        val graphBytes = graphPath.readBytes()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            assertEquals(acceptedId, reopened.snapshot.headId)
            assertEquals(2, reopened.snapshot.nodes.size)
        }

        assertContentEquals(graphBytes, graphPath.readBytes())
    }

    @Test
    fun `restart rejects a blob-only pending candidate without changing the source tree`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val acceptedBytes = target.readBytes()
        val legitimateRepairFile = project.resolve("src/modules/.legitimate.repair")
        legitimateRepairFile.writeText("user-owned repair notes")

        val interrupted = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val attempt = interrupted.beginAttempt(listOf("src/modules/alpha.c"))
        interrupted.installCandidate(
            attempt,
            mapOf("src/modules/alpha.c" to acceptedBytes + "\n/* interrupted candidate */\n".toByteArray()),
        )
        interrupted.close()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertContentEquals(acceptedBytes, target.readBytes())
            assertEquals("user-owned repair notes", legitimateRepairFile.readText())
            val node = recovered.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, node.status)
            assertTrue(node.recoveredAfterCrash)
            assertEquals("crash-recovery", node.evidenceKind)
            assertEquals(recovered.snapshot.nodes.first().id, recovered.snapshot.headId)
        }
        val recoveredGraph = project.resolve("reports/repair-revisions/graph.json").readText()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        assertEquals(recoveredGraph, project.resolve("reports/repair-revisions/graph.json").readText())
    }

    @Test
    fun `opening the graph preserves arbitrary user-owned repair-suffixed files`() {
        val project = generatedProject()
        val notes = project.resolve("src/modules/.legitimate.repair")
        notes.writeText("keep these user notes byte-for-byte\n")
        val before = notes.readBytes()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertEquals(null, graph.snapshot.pendingAttemptId)
        }

        assertContentEquals(before, notes.readBytes())
    }

    @Test
    fun `pre-candidate rejection preserves source identity metadata and bytes`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val relative = "src/modules/alpha.c"
        val parent = target.parent
        val beforeBytes = readProjectSourceWithoutAtime(project, relative)
        val beforeFile = LinuxFilesystemSyscalls.openRoot(parent).use { directory ->
            LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, target.fileName.toString())!!.use {
                LinuxFilesystemSyscalls.fileState(it)
            }
        }
        val beforeDirectory = LinuxFilesystemSyscalls.openRoot(parent).use(LinuxFilesystemSyscalls::directoryMetadata)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf(relative))
            graph.reject(attempt, RepairEvidence("agent-error", "agent failed before candidate installation"))
        }

        val afterFile = LinuxFilesystemSyscalls.openRoot(parent).use { directory ->
            LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, target.fileName.toString())!!.use {
                LinuxFilesystemSyscalls.fileState(it)
            }
        }
        val afterDirectory = LinuxFilesystemSyscalls.openRoot(parent).use(LinuxFilesystemSyscalls::directoryMetadata)
        assertContentEquals(beforeBytes, readProjectSourceWithoutAtime(project, relative))
        assertEquals(beforeFile, afterFile, "agent failure must preserve complete source file metadata")
        assertEquals(beforeDirectory, afterDirectory, "agent failure must preserve complete ancestor metadata")
    }

    @Test
    fun `rejected detached candidate leaves source inode and ancestor metadata unchanged`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val parent = target.parent
        val beforeBytes = readProjectSourceWithoutAtime(project, relative)
        val beforeFile = LinuxFilesystemSyscalls.openRoot(parent).use { directory ->
            LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, target.fileName.toString())!!.use {
                LinuxFilesystemSyscalls.fileState(it)
            }
        }
        val beforeDirectory = LinuxFilesystemSyscalls.openRoot(parent).use(LinuxFilesystemSyscalls::directoryMetadata)
        val candidate = beforeBytes + "\n/* rejected blob-only candidate */\n".toByteArray()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val metadata = beginSyntheticAcceptedRun(graph)
            val attempt = graph.beginAttempt(listOf(relative), metadata)
            assertEquals(6, graph.snapshot.schemaVersion)
            graph.installCandidate(attempt, mapOf(relative to candidate))
            graph.reject(attempt, RepairEvidence("compile", "candidate rejected"))
        }

        val afterFile = LinuxFilesystemSyscalls.openRoot(parent).use { directory ->
            LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, target.fileName.toString())!!.use {
                LinuxFilesystemSyscalls.fileState(it)
            }
        }
        val afterDirectory = LinuxFilesystemSyscalls.openRoot(parent).use(LinuxFilesystemSyscalls::directoryMetadata)
        assertContentEquals(beforeBytes, readProjectSourceWithoutAtime(project, relative))
        assertEquals(beforeFile, afterFile, "rejected blob-only candidate must preserve complete file metadata")
        assertEquals(beforeDirectory, afterDirectory, "rejected blob-only candidate must preserve complete ancestor metadata")
    }

    @Test
    fun `child crash after partial private staging recovers undecided schema six without touching source`() {
        val project = generatedProject()
        val paths = listOf("src/modules/alpha.c", "src/modules/beta.c")
        data class TreeWitness(
            val files: Map<String, Pair<decompengine.acp.LinuxFileState, String>>,
            val directories: Map<String, Pair<decompengine.acp.LinuxFileState, List<String>>>,
        )
        fun witness(): TreeWitness {
            val files = sortedMapOf<String, Pair<decompengine.acp.LinuxFileState, String>>()
            val directories = sortedMapOf<String, Pair<decompengine.acp.LinuxFileState, List<String>>>()
            LinuxFilesystemSyscalls.openRoot(project).use { root ->
                var directory = root
                val owned = mutableListOf<decompengine.acp.LinuxDescriptor>()
                try {
                    val ancestors = mutableListOf("." to directory)
                    paths.forEach { relative ->
                        val components = relative.split('/')
                        var parent = root
                        components.dropLast(1).forEachIndexed { index, component ->
                            val key = components.take(index + 1).joinToString("/")
                            val found = ancestors.firstOrNull { it.first == key }?.second
                                ?: LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, component).also {
                                    owned += it
                                    ancestors += key to it
                                }
                            parent = found
                        }
                        val file = requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, components.last()))
                        file.use { held ->
                            val state = LinuxFilesystemSyscalls.fileState(held)
                            files[relative] = state to LinuxFilesystemSyscalls.sha256WithoutAtime(held, state.size)
                        }
                    }
                    ancestors.forEach { (relative, descriptor) ->
                        directories[relative] = LinuxFilesystemSyscalls.fileState(descriptor) to
                            LinuxFilesystemSyscalls.directoryEntryNamesWithoutAtime(descriptor, 100_000)
                    }
                } finally {
                    owned.asReversed().forEach(decompengine.acp.LinuxDescriptor::close)
                }
            }
            return TreeWitness(files, directories)
        }

        val before = witness()
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", System.getProperty("java.class.path"),
            ModuleRevisionGraphPublicationCrashProbe::class.java.name,
            project.toString(), paths.joinToString(","), "create-undecided-stage", "0",
        ).redirectErrorStream(true).start()
        val outputReader = Executors.newSingleThreadExecutor()
        try {
            val output = outputReader.submit<String> { process.inputStream.use { it.readBytes().toString(Charsets.UTF_8) } }
            val exited = process.waitFor(20, TimeUnit.SECONDS)
            if (!exited) {
                process.destroyForcibly()
                process.waitFor(5, TimeUnit.SECONDS)
            }
            assertTrue(exited, "undecided schema-6 crash probe did not terminate")
            assertEquals(86, process.exitValue(), "probe did not halt after its first durable stage: ${output.get(5, TimeUnit.SECONDS)}")
        } finally {
            if (process.isAlive) process.destroyForcibly()
            outputReader.shutdownNow()
        }
        assertEquals(before, witness(), "staging and child death must leave source file and directory metadata unchanged")

        val firstGraph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(ModuleRevisionStatus.REJECTED, recovered.snapshot.nodes.last().status)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
            assertEquals(recovered.snapshot.nodes.first().id, recovered.snapshot.headId)
            assertEquals(null, recovered.snapshot.fullyAcceptedHeadId)
            assertEquals(RepairRunStatus.INTERRUPTED, recovered.snapshot.runs.single().status)
            assertEquals(1, recovered.snapshot.runs.single().attemptedCount)
            project.resolve("reports/repair-revisions/graph.json").readBytes()
        }
        assertEquals(before, witness(), "undecided recovery must preserve exact source and ancestor metadata")
        assertEquals(0L, Files.list(project.resolve("reports/repair-revisions/publication-staging")).use { it.count() })
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            assertEquals(ModuleRevisionStatus.REJECTED, reopened.snapshot.nodes.last().status)
        }
        assertEquals(firstGraph.toList(), project.resolve("reports/repair-revisions/graph.json").readBytes().toList(),
            "a second reopen must be idempotent")
        assertEquals(before, witness())
    }

    @Test
    fun `exception after schema six decision exchange leaves an undecided attempt recoverable`() {
        val temporaryParent = Path.of("build/test-tmp").also { Files.createDirectories(it) }
        val project = generatedProject(temporaryParent = temporaryParent)
        val relative = "src/modules/alpha.c"
        val sourcePaths = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile).sourcePaths
        val before = Schema6SourceInventoryWitness.capture(project, sourcePaths)
        val candidate = readProjectSourceWithoutAtime(project, relative) +
            "\n/* ambiguous state exchange must not accept */\n".toByteArray()
        fun decisionIsPublished(): Boolean = runCatching {
            val root = Json.parseToJsonElement(project.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
            val pending = root["pending"] as? JsonObject ?: return@runCatching false
            pending["acceptanceDecision"] is JsonObject
        }.getOrDefault(false)
        var injected = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (!injected && point == ModuleRevisionFaultPoint.AfterStatePublicationExchange("revision-state", "graph.json") &&
                    decisionIsPublished()
                ) {
                    injected = true
                    throw IllegalStateException("injected decision exchange interruption")
                }
            },
        )
        val metadata = beginSyntheticAcceptedRun(graph)
        val attempt = graph.beginAttempt(listOf(relative), metadata)
        graph.installCandidate(attempt, mapOf(relative to candidate))
        val originalHead = graph.snapshot.headId

        val failure = assertFailsWith<RepairAcceptancePendingException> {
            graph.accept(attempt, RepairEvidence("valid", "decision exchange boundary"), syntheticAcceptedProof(graph, attempt))
        }
        assertTrue(injected)
        assertTrue(failure.message.orEmpty().contains("ambiguous"))
        assertFailsWith<IllegalStateException> { graph.snapshot }
        graph.close()

        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val onDiskPending = Json.parseToJsonElement(graphPath.readText()).jsonObject.getValue("pending").jsonObject
        assertEquals(JsonNull, onDiskPending.getValue("acceptanceDecision"), "the state store must restore its prior graph")
        assertTrue(onDiskPending.getValue("predecisionStageFiles").jsonArray.isNotEmpty())
        val revisions = project.resolve("reports/repair-revisions")
        assertFalse(Files.exists(revisions.resolve(".graph.json.repair-atomic.tmp")))

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(ModuleRevisionStatus.REJECTED, recovered.snapshot.nodes.last().status)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
            assertEquals(originalHead, recovered.snapshot.headId)
            assertNull(recovered.snapshot.fullyAcceptedHeadId)
            assertEquals(RepairRunStatus.INTERRUPTED, recovered.snapshot.runs.last().status)
        }
        assertEquals(before, Schema6SourceInventoryWitness.capture(project, sourcePaths))
        assertEquals(0L, Files.list(revisions.resolve("publication-staging")).use { it.count() })
        assertFalse(Files.exists(graphPath.resolveSibling(".graph.json.repair-atomic.tmp")))
    }

    @Test
    fun `child crash before the schema six decision exchange recovers exact undecided source`() {
        val temporaryParent = Path.of("build/test-tmp").also { Files.createDirectories(it) }
        val project = generatedProject(temporaryParent = temporaryParent)
        val relative = "src/modules/alpha.c"
        val sourcePaths = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile).sourcePaths
        val before = Schema6SourceInventoryWitness.capture(project, sourcePaths)
        val command = listOf(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", System.getProperty("java.class.path"),
            ModuleRevisionGraphPublicationCrashProbe::class.java.name,
            project.toString(), relative, "decision-prevalidated",
        )
        val process = ProcessBuilder(command).redirectErrorStream(true).start()
        val outputReader = Executors.newSingleThreadExecutor()
        try {
            val output = outputReader.submit<String> { process.inputStream.use { it.readBytes().toString(Charsets.UTF_8) } }
            val exited = process.waitFor(20, TimeUnit.SECONDS)
            if (!exited) {
                process.destroyForcibly()
                process.waitFor(5, TimeUnit.SECONDS)
            }
            assertTrue(exited, "decision-prevalidated probe did not terminate")
            assertEquals(86, process.exitValue(), "probe did not halt at the prepared decision: ${output.get(5, TimeUnit.SECONDS)}")
        } finally {
            if (process.isAlive) process.destroyForcibly()
            outputReader.shutdownNow()
        }

        val revisions = project.resolve("reports/repair-revisions")
        val pending = Json.parseToJsonElement(revisions.resolve("graph.json").readText()).jsonObject
            .getValue("pending").jsonObject
        assertEquals(JsonNull, pending.getValue("acceptanceDecision"))
        assertTrue(Files.exists(revisions.resolve(".graph.json.repair-atomic.tmp")),
            "the crash must leave the prepared decision in the private state temporary")
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(ModuleRevisionStatus.REJECTED, recovered.snapshot.nodes.last().status)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
            assertNull(recovered.snapshot.fullyAcceptedHeadId)
        }
        assertEquals(before, Schema6SourceInventoryWitness.capture(project, sourcePaths))
        assertEquals(0L, Files.list(revisions.resolve("publication-staging")).use { it.count() })
        assertFalse(Files.exists(revisions.resolve(".graph.json.repair-atomic.tmp")))
    }

    @Test
    fun `child crash after the schema six decision exchange rolls forward exact staged identities`() {
        val temporaryParent = Path.of("build/test-tmp").also { Files.createDirectories(it) }
        val project = generatedProject(temporaryParent = temporaryParent)
        val relative = "src/modules/alpha.c"
        val sourcePaths = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile).sourcePaths
        val before = Schema6SourceInventoryWitness.capture(project, sourcePaths)
        val command = listOf(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", System.getProperty("java.class.path"),
            ModuleRevisionGraphPublicationCrashProbe::class.java.name,
            project.toString(), relative, "decision-exchanged",
        )
        val process = ProcessBuilder(command).redirectErrorStream(true).start()
        val outputReader = Executors.newSingleThreadExecutor()
        try {
            val output = outputReader.submit<String> { process.inputStream.use { it.readBytes().toString(Charsets.UTF_8) } }
            val exited = process.waitFor(20, TimeUnit.SECONDS)
            if (!exited) {
                process.destroyForcibly()
                process.waitFor(5, TimeUnit.SECONDS)
            }
            assertTrue(exited, "decision-exchanged probe did not terminate")
            assertEquals(86, process.exitValue(), "probe did not halt after exchanging the decision: ${output.get(5, TimeUnit.SECONDS)}")
        } finally {
            if (process.isAlive) process.destroyForcibly()
            outputReader.shutdownNow()
        }

        val revisions = project.resolve("reports/repair-revisions")
        val pending = Json.parseToJsonElement(revisions.resolve("graph.json").readText()).jsonObject
            .getValue("pending").jsonObject
        val decision = pending.getValue("acceptanceDecision").jsonObject
        assertTrue(Files.exists(revisions.resolve(".graph.json.repair-atomic.tmp")),
            "the displaced undecided state must remain until recovery")
        assertTrue(Files.exists(revisions.resolve("publication-staging").resolve(
            decision.getValue("stagedFiles").jsonArray.single().jsonObject.getValue("stagingName").jsonPrimitive.content,
        )))

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(ModuleRevisionStatus.ACCEPTED, recovered.snapshot.nodes.last().status)
            assertEquals(RepairRunStatus.FULLY_ACCEPTED, recovered.snapshot.runs.last().status)
            assertNull(recovered.snapshot.pendingAttemptId)
        }
        val staged = decision.getValue("stagedFiles").jsonArray.single().jsonObject
        val after = Schema6SourceInventoryWitness.capture(project, sourcePaths)
        sourcePaths.filterNot { it == relative }.forEach { unchanged ->
            assertEquals(before.files.getValue(unchanged), after.files.getValue(unchanged),
                "unchanged source must retain exact identity and metadata: $unchanged")
        }
        val installed = after.files.getValue(relative)
        assertEquals(staged.getValue("sha256").jsonPrimitive.content, installed.sha256)
        assertEquals(staged.getValue("device").jsonPrimitive.content.toLong(), installed.state.identity.key.device)
        assertEquals(staged.getValue("inode").jsonPrimitive.content.toLong(), installed.state.identity.key.inode)
        assertEquals(staged.getValue("mode").jsonPrimitive.content.toInt(), installed.state.identity.mode)
        assertEquals(staged.getValue("uid").jsonPrimitive.content.toInt(), installed.state.identity.uid)
        assertEquals(staged.getValue("gid").jsonPrimitive.content.toInt(), installed.state.identity.gid)
        assertEquals(1, installed.state.identity.linkCount)
        before.directories.forEach { (path, directory) ->
            val recoveredDirectory = after.directories.getValue(path)
            assertEquals(directory.state.identity, recoveredDirectory.state.identity, "directory identity changed: $path")
            assertEquals(directory.names, recoveredDirectory.names, "directory inventory changed: $path")
            assertEquals(directory.state.size, recoveredDirectory.state.size, "directory size changed: $path")
            assertEquals(directory.state.accessTimeSeconds, recoveredDirectory.state.accessTimeSeconds,
                "directory atime seconds changed: $path")
            assertEquals(directory.state.accessTimeNanoseconds, recoveredDirectory.state.accessTimeNanoseconds,
                "directory atime nanos changed: $path")
        }
        assertEquals(0L, Files.list(revisions.resolve("publication-staging")).use { it.count() })
        assertFalse(Files.exists(revisions.resolve(".graph.json.repair-atomic.tmp")))
    }

    @Test
    fun `undecided schema six recovery refuses a staged inode replacement before cleanup`() {
        val project = generatedProject()
        val paths = listOf("src/modules/alpha.c", "src/modules/beta.c")
        val sourceBefore = paths.associateWith { project.resolve(it).readBytes() }
        val sourceKeys = paths.associateWith {
            Files.readAttributes(project.resolve(it), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey()
        }
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", System.getProperty("java.class.path"),
            ModuleRevisionGraphPublicationCrashProbe::class.java.name,
            project.toString(), paths.joinToString(","), "create-undecided-stage", "0",
        ).redirectErrorStream(true).start()
        val outputReader = Executors.newSingleThreadExecutor()
        try {
            val output = outputReader.submit<String> { process.inputStream.use { it.readBytes().toString(Charsets.UTF_8) } }
            val exited = process.waitFor(20, TimeUnit.SECONDS)
            if (!exited) {
                process.destroyForcibly()
                process.waitFor(5, TimeUnit.SECONDS)
            }
            assertTrue(exited, "undecided schema-6 tamper probe did not terminate")
            assertEquals(86, process.exitValue(), "probe did not halt after private staging: ${output.get(5, TimeUnit.SECONDS)}")
        } finally {
            if (process.isAlive) process.destroyForcibly()
            outputReader.shutdownNow()
        }

        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val graphBefore = graphPath.readBytes()
        val pending = Json.parseToJsonElement(graphBefore.toString(Charsets.UTF_8)).jsonObject
            .getValue("pending").jsonObject
        val stage = pending.getValue("predecisionStageFiles").jsonArray.first().jsonObject
        val stageName = stage.getValue("stagingName").jsonPrimitive.content
        val stagePath = project.resolve("reports/repair-revisions/publication-staging").resolve(stageName)
        val stageBytes = Files.readAllBytes(stagePath)
        val stagePermissions = Files.getPosixFilePermissions(stagePath, LinkOption.NOFOLLOW_LINKS)
        val expectedDevice = stage.getValue("device").jsonPrimitive.content.toLong()
        val expectedInode = stage.getValue("inode").jsonPrimitive.content.toLong()
        val heldOriginal = LinuxFilesystemSyscalls.openRoot(stagePath.parent).use { directory ->
            requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, stageName))
        }
        try {
            Files.delete(stagePath)
            Files.write(stagePath, stageBytes)
            Files.setPosixFilePermissions(stagePath, stagePermissions)
            val replacementState = LinuxFilesystemSyscalls.openRoot(stagePath.parent).use { directory ->
                requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, stageName)).use {
                    LinuxFilesystemSyscalls.fileState(it)
                }
            }
            assertTrue(replacementState.identity.key.device != expectedDevice ||
                replacementState.identity.key.inode != expectedInode,
                "held original inode should prevent inode-number reuse during the replacement control")

            assertFailsWith<IllegalArgumentException> {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
            }
            assertContentEquals(graphBefore, graphPath.readBytes(), "failed predecision authentication must preserve the graph")
            paths.forEach { relative ->
                assertContentEquals(sourceBefore.getValue(relative), project.resolve(relative).readBytes())
                assertEquals(sourceKeys.getValue(relative), Files.readAttributes(project.resolve(relative),
                    BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey())
            }
            assertContentEquals(stageBytes, Files.readAllBytes(stagePath), "foreign stage must remain as unresolved evidence")
        } finally {
            heldOriginal.close()
        }
    }

    @Test
    fun `undecided schema six recovery accepts a registered stage inode that was never linked`() {
        val project = generatedProject()
        val paths = listOf("src/modules/alpha.c", "src/modules/beta.c")
        val sourceBefore = paths.associateWith { project.resolve(it).readBytes() }
        val sourceKeys = paths.associateWith {
            Files.readAttributes(project.resolve(it), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey()
        }
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", System.getProperty("java.class.path"),
            ModuleRevisionGraphPublicationCrashProbe::class.java.name,
            project.toString(), paths.joinToString(","), "create-undecided-stage-intent", "0",
        ).redirectErrorStream(true).start()
        val outputReader = Executors.newSingleThreadExecutor()
        try {
            val output = outputReader.submit<String> { process.inputStream.use { it.readBytes().toString(Charsets.UTF_8) } }
            val exited = process.waitFor(20, TimeUnit.SECONDS)
            if (!exited) {
                process.destroyForcibly()
                process.waitFor(5, TimeUnit.SECONDS)
            }
            assertTrue(exited, "pre-link stage-intent probe did not terminate")
            assertEquals(86, process.exitValue(), "probe did not halt after the durable stage intent: ${output.get(5, TimeUnit.SECONDS)}")
        } finally {
            if (process.isAlive) process.destroyForcibly()
            outputReader.shutdownNow()
        }

        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val pending = Json.parseToJsonElement(graphPath.readText()).jsonObject.getValue("pending").jsonObject
        val stage = pending.getValue("predecisionStageFiles").jsonArray.single().jsonObject
        val stagePath = project.resolve("reports/repair-revisions/publication-staging")
            .resolve(stage.getValue("stagingName").jsonPrimitive.content)
        assertFalse(Files.exists(stagePath), "the crash occurs after inode registration and before linkat")

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(ModuleRevisionStatus.REJECTED, recovered.snapshot.nodes.last().status)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
            assertEquals(recovered.snapshot.nodes.first().id, recovered.snapshot.headId)
        }
        paths.forEach { relative ->
            assertContentEquals(sourceBefore.getValue(relative), project.resolve(relative).readBytes())
            assertEquals(sourceKeys.getValue(relative), Files.readAttributes(project.resolve(relative),
                BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey())
        }
        assertEquals(0L, Files.list(stagePath.parent).use { it.count() })
    }

    @Test
    fun `schema six decided publication resumes after abrupt exchange crash`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val before = target.readBytes()
        val candidate = before + "\n/* accepted decision candidate */\n".toByteArray()
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "schema6-roll-forward") {
                    throw IllegalStateException("stop after durable decision and before first exchange")
                }
            },
        )
        val metadata = beginSyntheticAcceptedRun(graph)
        val attempt = graph.beginAttempt(listOf(relative), metadata)
        graph.installCandidate(attempt, mapOf(relative to candidate))

        assertFailsWith<RepairAcceptancePendingException> {
            graph.accept(attempt, RepairEvidence("valid", "decision crash control"),
                syntheticAcceptedProof(graph, attempt))
        }
        graph.close()
        val durablePending = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject.getValue("pending").jsonObject
        assertEquals(JsonPrimitive(6), Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject.getValue("schemaVersion"))
        assertTrue(durablePending.getValue("acceptanceDecision") is JsonObject)
        val fileWitness = durablePending.getValue("preimageMetadata").jsonObject.getValue(relative).jsonObject
        assertTrue(fileWitness.getValue("ancestorMetadata").jsonArray.isNotEmpty())

        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", System.getProperty("java.class.path"),
            ModuleRevisionGraphPublicationCrashProbe::class.java.name, project.toString(), relative,
        ).redirectErrorStream(true).start()
        val outputReader = Executors.newSingleThreadExecutor()
        try {
            val output = outputReader.submit<String> { process.inputStream.use { it.readBytes().toString(Charsets.UTF_8) } }
            val exited = process.waitFor(20, TimeUnit.SECONDS)
            if (!exited) {
                process.destroyForcibly()
                process.waitFor(5, TimeUnit.SECONDS)
            }
            assertTrue(exited, "schema-6 publication crash probe did not terminate")
            assertEquals(86, process.exitValue(), "probe did not halt after the source exchange: ${output.get(5, TimeUnit.SECONDS)}")
        } finally {
            if (process.isAlive) process.destroyForcibly()
            outputReader.shutdownNow()
        }
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(ModuleRevisionStatus.ACCEPTED, recovered.snapshot.nodes.last().status)
            assertEquals(attempt.id, recovered.snapshot.fullyAcceptedHeadId)
            assertEquals(null, recovered.snapshot.pendingAttemptId)
            assertEquals(RepairRunStatus.FULLY_ACCEPTED, recovered.snapshot.runs.last().status)
        }
        assertContentEquals(candidate, target.readBytes(), "startup must preserve decided publication residue")
    }

    @Test
    fun `schema seven recovery authenticates intent and assessment before source roll forward`() {
        for (missingEvidence in listOf("intent", "assessment", "retained-assessment", "none")) {
            val project = generatedProject()
            val relative = "src/modules/alpha.c"
            val target = project.resolve(relative)
            val before = target.readBytes()
            val candidate = before + "\n/* accepted provenance recovery candidate */\n".toByteArray()
            val graph = ModuleRevisionGraph.openForTesting(
                project,
                GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (point is ModuleRevisionFaultPoint.BeforePublicationExchange &&
                        point.phase == "schema6-roll-forward") {
                        throw IllegalStateException("stop after durable provenance-bound decision")
                    }
                },
            )
            var metadata = beginSyntheticAcceptedRun(
                graph,
                if (missingEvidence == "retained-assessment") RepairPublicationMode.ACP_RELEASE
                else RepairPublicationMode.TEST_ONLY_NON_RELEASE,
            ).copy(prompt = "bounded failure")
            var retainedAssessmentPath: Path? = null
            var retainedAncestorOriginal: ByteArray? = null
            if (missingEvidence == "retained-assessment") {
                val ancestorPath = "src/modules/beta.c"
                val ancestorBefore = project.resolve(ancestorPath).readBytes()
                retainedAncestorOriginal = ancestorBefore
                val ancestorCandidate = ancestorBefore + "\n/* retained assessed ancestor */\n".toByteArray()
                val ancestor = graph.beginAttempt(listOf(ancestorPath), metadata)
                val ancestorWorkflow = "schema-seven-ancestor-workflow"
                val ancestorDocument = completeAcpReceiptDocument(
                    project, ancestor, ancestorPath, ancestorBefore, ancestorCandidate,
                    turnWorkflowId = ancestorWorkflow,
                )
                val ancestorReceipt = decompengine.project.verifyAcpExecutionReceiptDocument(
                    ancestorDocument.json.toByteArray(Charsets.UTF_8),
                    TRACE_REPAIR_ACP_RECEIPT_KIND,
                    TRACE_REPAIR_ACP_TASK_FIELD,
                    ancestor.id,
                )
                val ancestorIdentity = requireNotNull(ancestorDocument.turnIdentity)
                val ancestorIntent = decompengine.project.AgentTurnIntent.create(
                    ancestorIdentity,
                    ancestorWorkflow,
                    ancestor.id,
                    graph.snapshot.profileSha256,
                    ancestorReceipt.accessPolicySha256,
                    graph.snapshot.nodes.single {
                        it.id == (graph.snapshot.provisionalHeadId ?: graph.snapshot.headId)
                    }.sourceRevisionSha256,
                )
                graph.persistAndBindAgentTurnIntent(ancestor, ancestorIntent)
                graph.persistAndBindAgentInvocation(ancestor, ancestorDocument)
                graph.installCandidate(ancestor, mapOf(ancestorPath to ancestorCandidate))
                val ancestorProof = syntheticAcceptedProof(graph, ancestor)
                val ancestorAssessment = decompengine.project.AcpChangeAssessment.create(
                    intent = ancestorIntent,
                    receiptSha256 = ancestorDocument.sha256,
                    sessionIdSha256 = ancestorReceipt.sessionIdCommitmentSha256?.let {
                        sha256("acp-session-commitment-v1:$it".toByteArray(Charsets.UTF_8))
                    },
                    changesSha256 = ancestorReceipt.resultChangesSha256,
                    beforeSha256 = ancestorIntent.beforeSha256,
                    afterSha256 = ancestorProof.sourceRevisionSha256,
                    observation = decompengine.project.AcpChangeObservationStatus.COMPLETE,
                    protocolStopCode = null,
                    normalizedStopReason = AgentStopReason.COMPLETED,
                    policyVerdict = decompengine.project.AcpChangePolicyVerdict.ALLOW,
                    reasonCodes = emptyList(),
                    validationStatus = decompengine.project.AcpChangeValidationStatus.PASSED,
                    validationProofSha256 = listOf(ancestorProof.evidenceSha256),
                    eligibility = decompengine.project.AcpChangePublicationEligibility.PROVISIONAL,
                    updatesSha256 = ancestorReceipt.updatesSha256,
                )
                graph.persistAndBindAgentAssessment(ancestor, ancestorAssessment)
                graph.recordProvisional(
                    ancestor,
                    RepairEvidence("behavior", "retain provisional assessed contribution"),
                    ancestorProof,
                )
                retainedAssessmentPath = project.resolve("reports/repair-revisions/${ancestor.id}.acp-assessment.json")
                val corpus = graph.retainedRegressionCorpus()
                metadata = metadata.copy(
                    iterationIndex = 2,
                    retainedRegressionIds = corpus.inputs.map { it.id },
                    regressionCorpusSha256 = corpus.sha256,
                )
            }
            val attempt = graph.beginAttempt(listOf(relative), metadata)
            val workflowId = "schema-seven-recovery-$missingEvidence"
            val document = completeAcpReceiptDocument(
                project, attempt, relative, before, candidate, turnWorkflowId = workflowId,
            )
            val verified = decompengine.project.verifyAcpExecutionReceiptDocument(
                document.json.toByteArray(Charsets.UTF_8),
                TRACE_REPAIR_ACP_RECEIPT_KIND,
                TRACE_REPAIR_ACP_TASK_FIELD,
                attempt.id,
            )
            val identity = requireNotNull(document.turnIdentity)
            val intent = decompengine.project.AgentTurnIntent.create(
                identity,
                workflowId,
                attempt.id,
                graph.snapshot.profileSha256,
                verified.accessPolicySha256,
                graph.snapshot.nodes.single {
                    it.id == (graph.snapshot.provisionalHeadId ?: graph.snapshot.headId)
                }.sourceRevisionSha256,
            )
            graph.persistAndBindAgentTurnIntent(attempt, intent)
            graph.persistAndBindAgentInvocation(attempt, document)
            graph.installCandidate(attempt, mapOf(relative to candidate))
            val proof = syntheticAcceptedProof(graph, attempt)
            val assessment = decompengine.project.AcpChangeAssessment.create(
                intent = intent,
                receiptSha256 = document.sha256,
                sessionIdSha256 = verified.sessionIdCommitmentSha256?.let {
                    sha256("acp-session-commitment-v1:$it".toByteArray(Charsets.UTF_8))
                },
                changesSha256 = verified.resultChangesSha256,
                beforeSha256 = intent.beforeSha256,
                afterSha256 = proof.sourceRevisionSha256,
                observation = decompengine.project.AcpChangeObservationStatus.COMPLETE,
                protocolStopCode = null,
                normalizedStopReason = AgentStopReason.COMPLETED,
                policyVerdict = decompengine.project.AcpChangePolicyVerdict.ALLOW,
                reasonCodes = emptyList(),
                validationStatus = decompengine.project.AcpChangeValidationStatus.PASSED,
                validationProofSha256 = listOf(proof.evidenceSha256),
                eligibility = decompengine.project.AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION,
                updatesSha256 = verified.updatesSha256,
            )
            graph.persistAndBindAgentAssessment(attempt, assessment)

            assertFailsWith<RepairAcceptancePendingException> {
                graph.accept(attempt, RepairEvidence("valid", "provenance-bound recovery"), proof)
            }
            graph.close()
            assertContentEquals(before, target.readBytes(), "the durable decision must precede source publication")
            if (missingEvidence == "none") {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
                    assertEquals(ModuleRevisionStatus.ACCEPTED, recovered.snapshot.nodes.last().status)
                    assertEquals(intent.sha256, recovered.snapshot.nodes.last().repairMetadata?.turnIntent?.intentSha256)
                    assertEquals(assessment.sha256, recovered.snapshot.nodes.last().repairMetadata
                        ?.agentInvocation?.assessmentSha256)
                }
                assertContentEquals(candidate, target.readBytes(), "valid bound provenance permits roll-forward")
            } else {
                val missingPath = when (missingEvidence) {
                    "intent" -> project.resolve("reports/repair-revisions/${attempt.id}.acp-intent.json")
                    "assessment" -> project.resolve("reports/repair-revisions/${attempt.id}.acp-assessment.json")
                    "retained-assessment" -> requireNotNull(retainedAssessmentPath)
                    else -> error("unexpected evidence control")
                }
                if (missingEvidence == "retained-assessment") {
                    Files.write(missingPath, "tampered retained assessment".toByteArray(Charsets.UTF_8))
                } else {
                    assertTrue(Files.deleteIfExists(missingPath), "fixture must remove the selected bound sidecar")
                }
                val decisionBytes = project.resolve("reports/repair-revisions/graph.json").readBytes()

                val refusal = assertFailsWith<IllegalArgumentException>("missing $missingEvidence must refuse roll-forward") {
                    ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
                }
                assertTrue(
                    refusal.message.orEmpty().contains("intent") ||
                        refusal.message.orEmpty().contains("assessment") ||
                        refusal.message.orEmpty().contains("evidence"),
                    refusal.message,
                )
                assertContentEquals(before, target.readBytes(), "missing $missingEvidence must not publish candidate bytes")
                retainedAncestorOriginal?.let {
                    assertContentEquals(it, project.resolve("src/modules/beta.c").readBytes(),
                        "corrupt retained evidence must not publish provisional ancestor bytes")
                }
                assertContentEquals(decisionBytes, project.resolve("reports/repair-revisions/graph.json").readBytes(),
                    "refusal must preserve the durable decision and recovery material")
            }
        }
    }

    @Test
    fun `schema six validates the complete committed graph before source publication`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val before = target.readBytes()
        val candidate = before + "\n/* malformed decision control */\n".toByteArray()
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "schema6-roll-forward") {
                    throw IllegalStateException("leave a durable decision before publication")
                }
            },
        )
        val metadata = beginSyntheticAcceptedRun(graph)
        val attempt = graph.beginAttempt(listOf(relative), metadata)
        graph.installCandidate(attempt, mapOf(relative to candidate))
        assertFailsWith<RepairAcceptancePendingException> {
            graph.accept(attempt, RepairEvidence("valid", "malformed decision control"),
                syntheticAcceptedProof(graph, attempt))
        }
        graph.close()

        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val originalGraphBytes = graphPath.readBytes()
        val root = Json.parseToJsonElement(originalGraphBytes.decodeToString()).jsonObject
        val pending = root.getValue("pending").jsonObject
        val decision = pending.getValue("acceptanceDecision").jsonObject
        val committedNode = decision.getValue("committedNode").jsonObject
        val malformedRun = JsonObject(decision.getValue("committedRun").jsonObject +
            ("acceptedHeadId" to JsonPrimitive("revision_99999999_forged")))
        val malformedProof = JsonObject(committedNode.getValue("validationProof").jsonObject +
            ("evidenceSha256" to JsonPrimitive("0".repeat(64))))
        val undecidedRollback = pending.getValue("rollbackRecord").jsonObject

        fun rejectCommittedNode(mutated: JsonObject, label: String) {
            val malformedDecision = JsonObject(decision + ("committedNode" to mutated))
            graphPath.writeText(JsonObject(root + ("pending" to JsonObject(pending +
                ("acceptanceDecision" to malformedDecision)))).toString())
            val malformedBytes = graphPath.readBytes()
            val originalKey = Files.readAttributes(target, BasicFileAttributes::class.java).fileKey()
            assertFailsWith<IllegalArgumentException>(label) {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
            }
            assertContentEquals(before, target.readBytes(), "$label must be rejected before source exchange")
            assertEquals(originalKey, Files.readAttributes(target, BasicFileAttributes::class.java).fileKey(),
                "$label must not replace the source inode")
            assertContentEquals(malformedBytes, graphPath.readBytes(), "$label must not rewrite the durable decision")
            graphPath.writeBytes(originalGraphBytes)
        }

        rejectCommittedNode(JsonObject(committedNode +
            ("parentId" to JsonPrimitive("revision_99999999_forged"))), "forged parent")
        rejectCommittedNode(JsonObject(committedNode +
            ("evidenceSummary" to JsonPrimitive("forged acceptance summary"))), "forged acceptance evidence")
        rejectCommittedNode(JsonObject(committedNode + ("validationProof" to malformedProof)), "forged validation proof")
        rejectCommittedNode(JsonObject(committedNode + ("recoveredAfterCrash" to JsonPrimitive(true))),
            "forged recovery status")
        rejectCommittedNode(JsonObject(committedNode + ("rollbackRecord" to undecidedRollback)),
            "forged rollback record")
        rejectCommittedNode(JsonObject(committedNode + ("changedModules" to JsonArray(listOf(JsonPrimitive("forged_module"))))),
            "forged changed-module projection")
        rejectCommittedNode(JsonObject(committedNode + ("invalidatedModules" to JsonArray(listOf(JsonPrimitive("forged_module"))))),
            "forged invalidated-module projection")

        val malformedRunDecision = JsonObject(decision + ("committedRun" to malformedRun))
        graphPath.writeText(JsonObject(root + ("pending" to JsonObject(pending +
            ("acceptanceDecision" to malformedRunDecision)))).toString())
        assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        }
        assertContentEquals(before, target.readBytes(), "invalid committed run must be rejected before exchange")
    }

    @Test
    fun `schema six preflights every staged file before the first exchange`() {
        val project = generatedProject()
        val alphaPath = "src/modules/alpha.c"
        val betaPath = "src/modules/beta.c"
        val alpha = project.resolve(alphaPath)
        val beta = project.resolve(betaPath)
        val alphaBefore = alpha.readBytes()
        val betaBefore = beta.readBytes()
        val alphaCandidate = alphaBefore + "\n/* preflight alpha */\n".toByteArray()
        val betaCandidate = betaBefore + "\n/* preflight beta */\n".toByteArray()
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "schema6-roll-forward") {
                    throw IllegalStateException("leave a durable multi-file decision before publication")
                }
            },
        )
        val metadata = beginSyntheticAcceptedRun(graph)
        val attempt = graph.beginAttempt(listOf(alphaPath, betaPath), metadata)
        graph.installCandidate(attempt, mapOf(alphaPath to alphaCandidate, betaPath to betaCandidate))
        assertFailsWith<RepairAcceptancePendingException> {
            graph.accept(attempt, RepairEvidence("valid", "multi-file preflight control"),
                syntheticAcceptedProof(graph, attempt))
        }
        graph.close()

        val graphRoot = Json.parseToJsonElement(
            project.resolve("reports/repair-revisions/graph.json").readText(),
        ).jsonObject
        val staged = graphRoot.getValue("pending").jsonObject.getValue("acceptanceDecision").jsonObject
            .getValue("stagedFiles").jsonArray.map { it.jsonObject }
            .single { it.getValue("path").jsonPrimitive.content == betaPath }
        val stagingPath = project.resolve("reports/repair-revisions/publication-staging")
            .resolve(staged.getValue("stagingName").jsonPrimitive.content)
        Files.delete(stagingPath)
        Files.write(stagingPath, "foreign replacement bytes".toByteArray())

        assertFailsWith<RepairAcceptancePendingException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        }
        assertContentEquals(alphaBefore, alpha.readBytes(), "valid first pair must remain untouched when a later pair fails preflight")
        assertContentEquals(betaBefore, beta.readBytes())
    }

    @Test
    fun `schema six multi-file roll-forward survives repeated crashes between sync boundaries`() {
        val project = generatedProject()
        val alphaPath = "src/modules/alpha.c"
        val betaPath = "src/modules/beta.c"
        val alpha = project.resolve(alphaPath)
        val beta = project.resolve(betaPath)
        val alphaBefore = alpha.readBytes()
        val betaBefore = beta.readBytes()
        val alphaCandidate = alphaBefore + "\n/* crash matrix alpha */\n".toByteArray()
        val betaCandidate = betaBefore + "\n/* crash matrix beta */\n".toByteArray()
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "schema6-roll-forward") {
                    throw IllegalStateException("leave a durable multi-file decision before publication")
                }
            },
        )
        val metadata = beginSyntheticAcceptedRun(graph)
        val attempt = graph.beginAttempt(listOf(alphaPath, betaPath), metadata)
        graph.installCandidate(attempt, mapOf(alphaPath to alphaCandidate, betaPath to betaCandidate))
        assertFailsWith<RepairAcceptancePendingException> {
            graph.accept(attempt, RepairEvidence("valid", "multi-file crash matrix"),
                syntheticAcceptedProof(graph, attempt))
        }
        graph.close()

        fun runCrashProbe(mode: String, path: String, index: Int?) {
            val command = mutableListOf(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"),
                ModuleRevisionGraphPublicationCrashProbe::class.java.name, project.toString(), path, mode,
            )
            index?.let { command += it.toString() }
            val process = ProcessBuilder(command).redirectErrorStream(true).start()
            val outputReader = Executors.newSingleThreadExecutor()
            try {
                val output = outputReader.submit<String> { process.inputStream.use { it.readBytes().toString(Charsets.UTF_8) } }
                val exited = process.waitFor(20, TimeUnit.SECONDS)
                if (!exited) {
                    process.destroyForcibly()
                    process.waitFor(5, TimeUnit.SECONDS)
                }
                assertTrue(exited, "schema-6 multi-file crash probe timed out at $mode")
                assertEquals(86, process.exitValue(), "probe did not halt at $mode: ${output.get(5, TimeUnit.SECONDS)}")
            } finally {
                if (process.isAlive) process.destroyForcibly()
                outputReader.shutdownNow()
            }
        }

        // The first process dies after the target directory sync but before the staging-directory
        // sync. Recovery recognizes the already-exchanged alpha pair and continues with beta.
        runCrashProbe("after-target-sync", alphaPath, 0)
        // A second recovery dies after exchanging the second file. A third open must finish the
        // exact same durable decision without undoing alpha or re-exchanging beta.
        runCrashProbe("after-exchange", betaPath, 1)
        // A final crash after the committed graph write leaves only cleanup residue.
        runCrashProbe("after-recovered-persist", "", null)
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(attempt.id, recovered.snapshot.headId)
            assertEquals(RepairRunStatus.FULLY_ACCEPTED, recovered.snapshot.runs.last().status)
            assertEquals(null, recovered.snapshot.pendingAttemptId)
        }
        assertContentEquals(alphaCandidate, alpha.readBytes())
        assertContentEquals(betaCandidate, beta.readBytes())
    }

    @Test
    fun `declarative profile supports arbitrary source layout without C conventions`() {
        val project = createTempDirectory("repair-declarative-").resolve("project")
        project.resolve("code").createDirectories()
        project.resolve("config").createDirectories()
        project.resolve("reports").createDirectories()
        project.resolve("code/unit.rs").writeText("pub fn answer() -> i32 { 41 }\n")
        project.resolve("config/build.toml").writeText("entry = \"code/unit.rs\"\n")
        project.resolve("reports/module_plan.json").writeText(
            "{\"modules\":[{\"id\":\"wrong\",\"sourcePath\":\"missing.c\",\"headerPath\":\"missing.h\"}]}",
        )
        project.resolve("reports/program_model.json").writeText(
            "{\"functions\":[{\"id\":\"wrong\",\"calls\":[\"missing\"]}]}",
        )
        val profile = DeclarativeRepairIndexProfile(
            "rust-layout-fixture-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/unit.rs", "config/build.toml"),
                editablePaths = listOf("code/unit.rs"),
                modules = listOf(
                    RepairModuleEvidence(
                        id = "rust_unit",
                        ownedPaths = listOf("code/unit.rs", "config/build.toml"),
                    ),
                ),
                sharedContextPaths = listOf("config/build.toml"),
                pathDependencies = mapOf(
                    "code/unit.rs" to emptyList(),
                    "config/build.toml" to listOf("code/unit.rs"),
                ),
                behaviorRootModuleIds = listOf("rust_unit"),
            ),
        )

        val index = ModuleRepairIndex.load(project, profile)
        val selection = index.select("compile", "config/build.toml:1: failure")
        assertEquals(listOf("rust_unit"), selection.seedModules)
        assertEquals(listOf("code/unit.rs"), selection.writablePaths)
        assertTrue("config/build.toml" in selection.readablePaths)
        ModuleRevisionGraph.open(project, profile).use { graph ->
            val metadata = beginSyntheticAcceptedRun(graph)
            val attempt = graph.beginAttempt(selection.writablePaths, metadata)
            graph.installCandidate(attempt, mapOf("code/unit.rs" to "pub fn answer() -> i32 { 42 }\n".toByteArray()))
            graph.accept(attempt, RepairEvidence("valid", "layout-independent validation passed"),
                syntheticAcceptedProof(graph, attempt))
        }
        assertEquals("pub fn answer() -> i32 { 42 }\n", project.resolve("code/unit.rs").readText())

        val wrongProfile = DeclarativeRepairIndexProfile(
            "rust-layout-fixture-v2",
            profile.resolve(project, RepairResourceBudget()),
        )
        assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(project, wrongProfile) }
    }

    @Test
    fun `compile selection requires exact ownership and never widens writable authority`() {
        val project = genericProject(
            "repair-exact-ownership-",
            mapOf(
                "code/unit.src" to "editable unit\n",
                "code/unrelated.src" to "unrelated editable\n",
                "config/only.cfg" to "read only owner\n",
                "config/unit.cfg" to "unit configuration\n",
            ),
        )
        val profile = DeclarativeRepairIndexProfile(
            "exact-ownership-v1",
            RepairIndexLayout(
                sourcePaths = listOf(
                    "code/unit.src",
                    "code/unrelated.src",
                    "config/only.cfg",
                    "config/unit.cfg",
                ),
                editablePaths = listOf("code/unit.src", "code/unrelated.src"),
                modules = listOf(
                    RepairModuleEvidence("read_only", listOf("config/only.cfg")),
                    RepairModuleEvidence("unit", listOf("code/unit.src", "config/unit.cfg")),
                    RepairModuleEvidence("unrelated", listOf("code/unrelated.src")),
                ),
            ),
        )
        val index = ModuleRepairIndex.load(project, profile)

        val selected = index.select("compile", "config/unit.cfg:1: failure")

        assertEquals(listOf("unit"), selected.seedModules)
        assertEquals(listOf("code/unit.src", "config/unit.cfg"), selected.readablePaths)
        assertEquals(listOf("code/unit.src"), selected.writablePaths)
        assertFalse("code/unrelated.src" in selected.readablePaths)
        val missing = assertFailsWith<IllegalArgumentException> {
            index.select("compile", "aggregate tool failure with no indexed owner")
        }
        assertTrue(missing.message.orEmpty().contains("exact"))
        val readOnly = assertFailsWith<IllegalArgumentException> {
            index.select("compile", "config/only.cfg: failure")
        }
        assertTrue(readOnly.message.orEmpty().contains("editable"))
    }

    @Test
    fun `profile failure ownership rejects unknown module IDs instead of dropping them`() {
        val project = genericProject("repair-unknown-owner-", mapOf("code/unit.src" to "unit\n"))
        val layout = RepairIndexLayout(
            sourcePaths = listOf("code/unit.src"),
            editablePaths = listOf("code/unit.src"),
            modules = listOf(RepairModuleEvidence("unit", listOf("code/unit.src"))),
        )
        val profile = object : RepairIndexProfile {
            override fun profileId() = "unknown-failure-owner-v1"
            override fun resolve(projectRoot: Path, budget: RepairResourceBudget) = layout
            override fun failureOwnership(
                projectRoot: Path,
                sourceRevisionSha256: String,
                budget: RepairResourceBudget,
            ) = RepairFailureOwnership(listOf("missing_owner"))
        }
        val index = ModuleRepairIndex.load(project, profile)

        val failure = assertFailsWith<IllegalArgumentException> {
            index.select("compile", "aggregate failure")
        }

        assertTrue(failure.message.orEmpty().contains("unknown modules"))
    }

    @Test
    fun `ambiguous diagnostic basenames fail closed instead of selecting multiple owners`() {
        val project = genericProject(
            "repair-ambiguous-diagnostic-",
            mapOf("first/unit.src" to "first\n", "second/unit.src" to "second\n"),
        )
        val profile = DeclarativeRepairIndexProfile(
            "ambiguous-diagnostic-v1",
            RepairIndexLayout(
                sourcePaths = listOf("first/unit.src", "second/unit.src"),
                editablePaths = listOf("first/unit.src", "second/unit.src"),
                modules = listOf(
                    RepairModuleEvidence("first", listOf("first/unit.src")),
                    RepairModuleEvidence("second", listOf("second/unit.src")),
                ),
            ),
        )
        val index = ModuleRepairIndex.load(project, profile)

        val failure = assertFailsWith<IllegalArgumentException> {
            index.select("compile", "unit.src: failure")
        }
        assertTrue(failure.message.orEmpty().contains("ambiguous"))
        assertEquals(
            listOf("first/unit.src"),
            index.select("compile", "first/unit.src: failure").writablePaths,
        )
    }

    @Test
    fun `exact indexed paths outrank raw tokens while ambiguous token evidence cannot widen writes`() {
        val project = genericProject(
            "repair-token-authority-",
            mapOf(
                "code/alpha + 한글.src" to "alpha\n",
                "code/beta.src" to "beta\n",
            ),
        )
        val profile = DeclarativeRepairIndexProfile(
            "token-authority-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/alpha + 한글.src", "code/beta.src"),
                editablePaths = listOf("code/alpha + 한글.src", "code/beta.src"),
                modules = listOf(
                    RepairModuleEvidence(
                        id = "alpha",
                        ownedPaths = listOf("code/alpha + 한글.src"),
                        entityIds = listOf("entity_alpha"),
                    ),
                    RepairModuleEvidence(
                        id = "beta",
                        ownedPaths = listOf("code/beta.src"),
                        entityIds = listOf("entity_beta"),
                    ),
                ),
                entities = listOf(
                    RepairEntityEvidence("entity_alpha", listOf("shared_token", "token_alpha")),
                    RepairEntityEvidence("entity_beta", listOf("alpha", "shared_token", "token_beta")),
                ),
            ),
        )
        val index = ModuleRepairIndex.load(project, profile)

        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                index.select("compile", "shared_token")
            }.message.orEmpty().contains("ambiguous"),
        )
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                index.select("compile", "token_alpha token_beta")
            }.message.orEmpty().contains("multiple"),
        )
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                index.select("compile", "alpha")
            }.message.orEmpty().contains("ambiguous"),
        )

        val exact = index.select(
            "compile",
            "code/alpha + 한글.src:1: error: shared_token token_beta",
        )
        assertEquals(listOf("alpha"), exact.seedModules)
        assertEquals(listOf("code/alpha + 한글.src"), exact.writablePaths)
        assertFalse("code/beta.src" in exact.readablePaths)

        val exactMultiFile = index.select(
            "compile",
            "code/alpha + 한글.src:1: error: first\ncode/beta.src:2: error: second",
        )
        assertEquals(listOf("alpha", "beta"), exactMultiFile.seedModules)
        assertEquals(listOf("code/alpha + 한글.src", "code/beta.src"), exactMultiFile.writablePaths)
    }

    @Test
    fun `profile transformed diagnostics are rebound before indexing`() {
        val project = genericProject("repair-filtered-diagnostic-budget-", mapOf("code/unit.src" to "unit\n"))
        val layout = RepairIndexLayout(
            sourcePaths = listOf("code/unit.src"),
            editablePaths = listOf("code/unit.src"),
            modules = listOf(RepairModuleEvidence("unit", listOf("code/unit.src"))),
        )
        val profile = object : RepairIndexProfile {
            override fun profileId() = "filtered-diagnostic-budget-v1"
            override fun resolve(projectRoot: Path, budget: RepairResourceBudget) = layout
            override fun diagnosticEvidence(hint: String) = "x".repeat(9)
        }
        val index = ModuleRepairIndex.load(
            project,
            profile,
            RepairResourceBudget(maximumDiagnosticCharacters = 8),
        )

        val failure = assertFailsWith<RepairBudgetExceededException> {
            index.select("compile", "x")
        }

        assertTrue(failure.message.orEmpty().contains("profile-filtered"))
    }

    @Test
    fun `shared readable context grants writes only through explicit invalidation ownership`() {
        val project = genericProject("repair-shared-authority-", mapOf("config/shared.cfg" to "shared\n"))
        fun profile(id: String, layout: RepairIndexLayout) = object : RepairIndexProfile {
            override fun profileId() = id
            override fun resolve(projectRoot: Path, budget: RepairResourceBudget) = layout
            override fun failureOwnership(
                projectRoot: Path,
                sourceRevisionSha256: String,
                budget: RepairResourceBudget,
            ) = RepairFailureOwnership(includesSharedContext = true)
        }
        val readOnlyShared = profile(
            "shared-read-only-v1",
            RepairIndexLayout(
                sourcePaths = listOf("config/shared.cfg"),
                editablePaths = listOf("config/shared.cfg"),
                sharedContextPaths = listOf("config/shared.cfg"),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            ModuleRepairIndex.load(project, readOnlyShared).select("compile", "aggregate failure")
        }

        val explicitlyInvalidating = profile(
            "shared-invalidation-v1",
            RepairIndexLayout(
                sourcePaths = listOf("config/shared.cfg"),
                editablePaths = listOf("config/shared.cfg"),
                sharedContextPaths = listOf("config/shared.cfg"),
                sharedInvalidationPaths = listOf("config/shared.cfg"),
            ),
        )
        val selection = ModuleRepairIndex.load(project, explicitlyInvalidating)
            .select("compile", "aggregate failure")
        assertEquals(emptyList(), selection.seedModules)
        assertEquals(listOf("config/shared.cfg"), selection.readablePaths)
        assertEquals(listOf("config/shared.cfg"), selection.writablePaths)
    }

    @Test
    fun `fallback IDs and declared behavior roots must resolve exactly`() {
        val sources = listOf("code/a.src", "code/b.src")
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                modules = listOf(RepairModuleEvidence("explicit", listOf("code/a.src"))),
                fallbackModuleIdsByPath = mapOf("code/a.src" to "fallback"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                fallbackModuleIdsByPath = mapOf("code/a.src" to "same", "code/b.src" to "same"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                modules = listOf(RepairModuleEvidence("claimed", listOf("code/a.src"))),
                fallbackModuleIdsByPath = mapOf("code/b.src" to "claimed"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                sharedContextPaths = listOf("code/a.src"),
                fallbackModuleIdsByPath = mapOf("code/a.src" to "shared_context_fallback"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                sharedInvalidationPaths = listOf("code/a.src"),
                fallbackModuleIdsByPath = mapOf("code/a.src" to "shared_fallback"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                behaviorRootModuleIds = listOf("unknown_root"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                behaviorRootEntityIds = listOf("unknown_entity"),
            )
        }

        val declared = RepairIndexLayout(
            sourcePaths = listOf("code/a.src"),
            editablePaths = listOf("code/a.src"),
            fallbackModuleIdsByPath = mapOf("code/a.src" to "declared_root"),
            behaviorRootModuleIds = listOf("declared_root"),
        )
        assertEquals(listOf("declared_root"), declared.behaviorRootModuleIds)
    }

    @Test
    fun `partial ownership requires complete explicit fallback coverage`() {
        val project = genericProject(
            "repair-explicit-fallback-",
            mapOf("code/a.src" to "owned\n", "code/b.src" to "fallback\n"),
        )
        val incomplete = DeclarativeRepairIndexProfile(
            "incomplete-fallback-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/a.src", "code/b.src"),
                editablePaths = listOf("code/a.src", "code/b.src"),
                modules = listOf(RepairModuleEvidence("explicit_a", listOf("code/a.src"))),
            ),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRepairIndex.load(project, incomplete)
        }
        assertTrue(failure.message.orEmpty().contains("explicitly and exactly"))

        val complete = DeclarativeRepairIndexProfile(
            "complete-fallback-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/a.src", "code/b.src"),
                editablePaths = listOf("code/a.src", "code/b.src"),
                modules = listOf(RepairModuleEvidence("explicit_a", listOf("code/a.src"))),
                fallbackModuleIdsByPath = mapOf("code/b.src" to "declared_b"),
            ),
        )
        val index = ModuleRepairIndex.load(project, complete)
        assertEquals(listOf("declared_b", "explicit_a"), index.moduleIds)
        assertEquals(listOf("declared_b"), index.select("compile", "code/b.src: failure").seedModules)
    }

    @Test
    fun `generated C rejects a module plan that claims the entry source`() {
        val project = genericProject(
            "repair-generated-entry-owner-",
            mapOf(
                "Makefile" to "all:\n\t@true\n",
                "include/decomp_types.h" to "#pragma once\n",
                "include/main.h" to "#pragma once\nint main(void);\n",
                "src/main.c" to "#include \"main.h\"\nint main(void) { return 0; }\n",
                "reports/module_plan.json" to
                    "{\"schemaVersion\":1,\"modules\":[{\"id\":\"owned_entry\"," +
                    "\"sourcePath\":\"src/main.c\",\"headerPath\":\"include/main.h\"," +
                    "\"functionIds\":[\"fn_main\"],\"globalIds\":[],\"boundaryEvidence\":[]}]," +
                    "\"dependencyCycles\":[]}",
                "reports/program_model.json" to
                    "{\"schemaVersion\":1,\"inputSha256\":\"fixture\",\"functions\":[{" +
                    "\"id\":\"fn_main\",\"name\":\"main\",\"address\":\"0x1\"," +
                    "\"prototype\":\"int main(void)\",\"status\":\"recovered\",\"calls\":[]," +
                    "\"referencedGlobals\":[],\"strings\":[],\"decompiledC\":null}]," +
                    "\"globals\":[],\"types\":[]}",
            ),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
        }
        assertTrue(failure.message.orEmpty().contains("declared discovered input"))
    }

    @Test
    fun `present generated C index evidence requires its complete versioned shape`() {
        val project = minimalGeneratedCProject(
            "{\"schemaVersion\":1,\"inputSha256\":\"fixture\",\"functions\":[{" +
                "\"id\":\"fn_main\",\"name\":\"main\",\"address\":\"0x1\"," +
                "\"prototype\":\"int main(void)\",\"status\":\"recovered\"," +
                "\"referencedGlobals\":[],\"strings\":[],\"decompiledC\":null}]," +
                "\"globals\":[],\"types\":[]}",
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
        }

        assertTrue(failure.message.orEmpty().contains("calls"))
    }

    @Test
    fun `generated C nested evidence is structurally bounded before collection transforms`() {
        val project = minimalGeneratedCProject(
            "{\"schemaVersion\":1,\"inputSha256\":\"fixture\",\"functions\":[{" +
                "\"id\":\"fn_main\",\"name\":\"main\",\"address\":\"0x1\"," +
                "\"prototype\":\"int main(void)\",\"status\":\"recovered\"," +
                "\"calls\":[\"fn_main\",\"fn_main\"],\"referencedGlobals\":[]," +
                "\"strings\":[],\"decompiledC\":null}],\"globals\":[],\"types\":[]}",
        )

        val failure = assertFailsWith<RepairBudgetExceededException> {
            ModuleRepairIndex.load(
                project,
                GeneratedCRepairIndexProfile,
                RepairResourceBudget(maximumDependencyEdges = 2),
            )
        }

        assertTrue(failure.message.orEmpty().contains("structural entries"))
    }

    @Test
    fun `behavior selection requires explicit roots and keeps the declared frontier exact`() {
        val project = genericProject(
            "repair-behavior-roots-",
            mapOf(
                "code/dep.src" to "dependency\n",
                "code/isolated.src" to "disconnected\n",
                "code/root.src" to "root\n",
            ),
        )
        val modules = listOf(
            RepairModuleEvidence("dep", listOf("code/dep.src"), dependencyModuleIds = listOf("root")),
            RepairModuleEvidence("isolated", listOf("code/isolated.src")),
            RepairModuleEvidence("root", listOf("code/root.src"), dependencyModuleIds = listOf("dep")),
        )
        val sources = listOf("code/dep.src", "code/isolated.src", "code/root.src")
        val withoutRoots = DeclarativeRepairIndexProfile(
            "behavior-no-roots-v1",
            RepairIndexLayout(sourcePaths = sources, editablePaths = sources, modules = modules),
        )

        val noRootFailure = assertFailsWith<IllegalArgumentException> {
            ModuleRepairIndex.load(project, withoutRoots).select("behavior", "")
        }
        assertTrue(noRootFailure.message.orEmpty().contains("explicit profile-declared roots"))

        val withRoot = DeclarativeRepairIndexProfile(
            "behavior-explicit-root-v1",
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                modules = modules,
                behaviorRootModuleIds = listOf("root"),
            ),
        )
        val index = ModuleRepairIndex.load(project, withRoot)
        val frontier = index.select("behavior", "")
        assertEquals(listOf("root"), frontier.seedModules)
        assertEquals(listOf("dep"), frontier.dependencyModules)
        assertEquals(listOf("code/root.src"), frontier.writablePaths)
        assertTrue("code/dep.src" in frontier.readablePaths)
        assertFalse("code/dep.src" in frontier.writablePaths)
        assertFalse("code/isolated.src" in frontier.readablePaths)

        val diagnosed = index.select("behavior", "code/dep.src: mismatch")
        assertEquals(listOf("dep"), diagnosed.seedModules)
        assertEquals(listOf("code/dep.src"), diagnosed.writablePaths)
        assertTrue("code/root.src" in diagnosed.readablePaths)
    }

    @Test
    fun `layout canonicalization is bounded after structural count preflight`() {
        val project = genericProject(
            "repair-layout-budget-",
            mapOf("code/a.src" to "a\n", "code/b.src" to "b\n"),
        )
        val oneModule = DeclarativeRepairIndexProfile(
            "canonical-budget-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/a.src"),
                editablePaths = listOf("code/a.src"),
                modules = listOf(RepairModuleEvidence("a", listOf("code/a.src"))),
            ),
        )
        val canonicalFailure = assertFailsWith<RepairBudgetExceededException> {
            ModuleRepairIndex.load(
                project,
                oneModule,
                RepairResourceBudget(maximumIndexEvidenceBytes = 64),
            )
        }
        assertTrue(canonicalFailure.message.orEmpty().contains("canonical bytes"))

        val twoModules = DeclarativeRepairIndexProfile(
            "count-before-canonical-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/a.src", "code/b.src"),
                editablePaths = listOf("code/a.src", "code/b.src"),
                modules = listOf(
                    RepairModuleEvidence("a", listOf("code/a.src")),
                    RepairModuleEvidence("b", listOf("code/b.src")),
                ),
            ),
        )
        val countFailure = assertFailsWith<RepairBudgetExceededException> {
            ModuleRepairIndex.load(
                project,
                twoModules,
                RepairResourceBudget(
                    maximumIndexedModules = 1,
                    maximumIndexEvidenceBytes = 1,
                    maximumContextModules = 1,
                ),
            )
        }
        assertTrue(countFailure.message.orEmpty().contains("2 modules"))
    }

    @Test
    fun `begin attempt preflights aggregate preimage bytes before retaining captured bodies`() {
        val project = genericProject(
            "repair-preimage-preflight-",
            mapOf("code/a.bin" to "a".repeat(40), "code/b.bin" to "b".repeat(40)),
        )
        val profile = DeclarativeRepairIndexProfile(
            "preimage-preflight-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/a.bin", "code/b.bin"),
                editablePaths = listOf("code/a.bin", "code/b.bin"),
            ),
        )
        val budget = RepairResourceBudget(
            maximumContextBytes = 64,
            maximumStagingBytes = 64,
            maximumPatchBytes = 64,
        )
        var preimageRead = false
        ModuleRevisionGraph.openForTesting(
            project,
            profile,
            budget,
            ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePreimageRead) preimageRead = true
            },
        ).use { graph ->
            val oversizedWithoutSafeIteration = object : AbstractCollection<String>() {
                override val size: Int = 257
                override fun iterator(): Iterator<String> = error("oversized path collection was iterated")
            }
            assertFailsWith<RepairBudgetExceededException> {
                graph.beginAttempt(oversizedWithoutSafeIteration)
            }
            val failure = assertFailsWith<RepairBudgetExceededException> {
                graph.beginAttempt(listOf("code/a.bin", "code/b.bin"))
            }
            assertTrue(failure.message.orEmpty().contains("80 bytes"))
            assertFalse(preimageRead)
            assertEquals(null, graph.snapshot.pendingAttemptId)
        }
        assertEquals("a".repeat(40), project.resolve("code/a.bin").readText())
        assertEquals("b".repeat(40), project.resolve("code/b.bin").readText())
    }

    @Test
    fun `startup restores a dirty candidate before invoking a content-sensitive profile`() {
        val project = createTempDirectory("repair-content-profile-").resolve("project")
        project.resolve("code").createDirectories()
        val source = project.resolve("code/program.bin")
        val parent = byteArrayOf(1, 3, 5, 7)
        val candidate = byteArrayOf(2, 4, 6, 8)
        source.writeBytes(parent)
        val layout = RepairIndexLayout(
            sourcePaths = listOf("code/program.bin"),
            editablePaths = listOf("code/program.bin"),
            fallbackModuleIdsByPath = mapOf("code/program.bin" to "program"),
        )
        var liveResolutions = 0
        var recoveryResolutions = 0
        val profile = object : RepairIndexProfile {
            override fun profileId() = "content-sensitive-binary-v1"
            override fun configurationSha256() = "7".repeat(64)
            override fun authorizesRecoveryLayout(
                sourcePaths: List<String>,
                editablePaths: List<String>,
                budget: RepairResourceBudget,
            ) = sourcePaths == listOf("code/program.bin") && editablePaths == sourcePaths
            override fun resolve(projectRoot: Path, budget: RepairResourceBudget): RepairIndexLayout {
                require(!projectRoot.resolve("code/program.bin").readBytes().contentEquals(candidate)) {
                    "profile cannot resolve a dirty candidate"
                }
                assertContentEquals(parent, projectRoot.resolve("code/program.bin").readBytes())
                liveResolutions++
                return layout
            }
            override fun resolveForRecovery(
                projectRoot: Path, budget: RepairResourceBudget,
                sourcePaths: List<String>, editablePaths: List<String>, readSource: (String) -> ByteArray,
            ): RepairIndexLayout {
                assertEquals(layout.sourcePaths, sourcePaths)
                assertEquals(layout.editablePaths, editablePaths)
                assertContentEquals(candidate, projectRoot.resolve("code/program.bin").readBytes())
                assertContentEquals(parent, readSource("code/program.bin"))
                recoveryResolutions++
                return layout
            }
        }
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            profile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterPublicationMove && point.phase == "candidate") {
                    throw SimulatedRepairCrash()
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("code/program.bin"))
        assertFailsWith<SimulatedRepairCrash> {
            graph.installCandidate(attempt, mapOf("code/program.bin" to candidate))
        }
        graph.close()
        assertContentEquals(candidate, source.readBytes())

        val beforeRecoveryLiveResolutions = liveResolutions
        ModuleRevisionGraph.open(project, profile).use { recovered ->
            assertTrue(recoveryResolutions > 0)
            assertTrue(liveResolutions > beforeRecoveryLiveResolutions)
            assertContentEquals(parent, source.readBytes())
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
        }
    }

    @Test
    fun `pending recovery remains valid when staging budget is below context budget`() {
        val project = createTempDirectory("repair-staging-context-recovery-").resolve("project")
        project.resolve("code").createDirectories()
        val source = project.resolve("code/program.bin")
        val parent = byteArrayOf(1, 2, 3, 4)
        val candidate = byteArrayOf(5, 6, 7, 8)
        source.writeBytes(parent)
        val profile = DeclarativeRepairIndexProfile(
            "staging-below-context-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/program.bin"),
                editablePaths = listOf("code/program.bin"),
            ),
        )
        val budget = RepairResourceBudget(
            maximumContextBytes = 16,
            maximumStagingBytes = 8,
            maximumPatchBytes = 8,
        )
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            profile,
            budget,
            ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterPublicationMove && point.phase == "candidate") {
                    throw SimulatedRepairCrash()
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("code/program.bin"))
        assertFailsWith<SimulatedRepairCrash> {
            graph.installCandidate(attempt, mapOf("code/program.bin" to candidate))
        }
        graph.close()
        assertContentEquals(candidate, source.readBytes())

        ModuleRevisionGraph.open(project, profile, budget).use { recovered ->
            assertContentEquals(parent, source.readBytes())
            assertEquals(null, recovered.snapshot.pendingAttemptId)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
        }
    }

    @Test
    fun `identical repairs produce equivalent revision content in different roots`() {
        val first = generatedProject()
        val second = generatedProject()

        listOf(first, second).forEach { project ->
            val before = project.resolve("src/modules/beta.c").readBytes()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                val metadata = beginSyntheticAcceptedRun(graph)
                val attempt = graph.beginAttempt(listOf("src/modules/beta.c"), metadata)
                graph.installCandidate(
                    attempt,
                    mapOf("src/modules/beta.c" to before + "\n/* portable candidate */\n".toByteArray()),
                )
                graph.accept(attempt, RepairEvidence("valid", "same evidence", "reports/result.json"),
                    syntheticAcceptedProof(graph, attempt))
            }
        }

        val firstGraph = Json.parseToJsonElement(first.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
        val secondGraph = Json.parseToJsonElement(second.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
        assertEquals(firstGraph.getValue("headId"), secondGraph.getValue("headId"))
        fun stableNodes(graph: kotlinx.serialization.json.JsonObject) =
            JsonArray(graph.getValue("nodes").jsonArray.map { element ->
                JsonObject(element.jsonObject - "publicationPreimageMetadata")
            })
        // Device/inode and ctime are intentionally installation-local. The logical revision
        // content, proof and IDs remain deterministic across otherwise identical roots.
        assertEquals(stableNodes(firstGraph), stableNodes(secondGraph))
        assertEquals(firstGraph.getValue("acceptedProof"), secondGraph.getValue("acceptedProof"))
        assertContentEquals(
            first.resolve("source_tree_manifest.json").readBytes(),
            second.resolve("source_tree_manifest.json").readBytes(),
        )
    }

    @Test
    fun `out-of-band source edits cannot be attached to the accepted graph head`() {
        val project = generatedProject()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        val graphBytes = project.resolve("reports/repair-revisions/graph.json").readBytes()
        val alpha = project.resolve("src/modules/alpha.c")
        alpha.writeBytes(alpha.readBytes() + "\n/* unbound external edit */\n".toByteArray())

        val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile) }

        assertTrue(failure.message.orEmpty().contains("do not match revision graph head"))
        assertContentEquals(graphBytes, project.resolve("reports/repair-revisions/graph.json").readBytes())
    }

    @Test
    fun `source inputs added after indexing cannot enter an atomic attempt`() {
        val project = generatedProject()
        val added = project.resolve("src/modules/unbound.c")

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            added.writeText("int unbound(void) { return 0; }\n")

            val failure = assertFailsWith<IllegalArgumentException> {
                graph.beginAttempt(listOf("src/modules/alpha.c"))
            }

            assertTrue(failure.message.orEmpty().contains("source input set changed"))
        }
    }

    @Test
    fun `local include dependencies drive minimal context and downstream invalidation`() {
        val project = dependencyOnlyProject(includeDependency = true, globalDependency = false)
        val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)

        val selection = index.select("compile", "src/modules/consumer.c:3: error: invalid expression")

        assertEquals(listOf("consumer"), selection.seedModules)
        assertEquals(listOf("provider"), selection.dependencyModules)
        assertTrue("include/modules/provider.h" in selection.readablePaths)
        assertEquals(listOf("consumer"), index.downstreamInvalidations(listOf("src/modules/provider.c")))
    }

    @Test
    fun `referenced global ownership drives dependencies without a function call or include`() {
        val project = dependencyOnlyProject(includeDependency = false, globalDependency = true)
        val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)

        val selection = index.select("compile", "src/modules/consumer.c:3: error: invalid expression")

        assertEquals(listOf("consumer"), selection.seedModules)
        assertEquals(listOf("provider"), selection.dependencyModules)
        assertEquals(listOf("consumer"), index.downstreamInvalidations(listOf("src/modules/provider.c")))
    }

    @Test
    fun `unknown semantic references are rejected instead of silently dropped`() {
        val project = dependencyOnlyProject(includeDependency = false, globalDependency = true)
        val model = project.resolve("reports/program_model.json")
        model.writeText(model.readText().replace("\"referencedGlobals\":[\"global_state\"]", "\"referencedGlobals\":[\"missing_global\"]"))

        val failure = assertFailsWith<IllegalArgumentException> { ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile) }

        assertTrue(failure.message.orEmpty().contains("unknown global"))
    }

    @Test
    fun `candidate that changes include dependency evidence is restored and rejected`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/beta.c")
        val before = target.readBytes()
        val candidate = "#include \"modules/delta.h\"\n" + before.decodeToString()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val metadata = beginSyntheticAcceptedRun(graph)
            val attempt = graph.beginAttempt(listOf("src/modules/beta.c"), metadata)
            graph.installCandidate(attempt, mapOf("src/modules/beta.c" to candidate.toByteArray()))
            val failure = assertFailsWith<IllegalArgumentException> {
                graph.accept(attempt, RepairEvidence("valid", "dependency evidence must remain fixed"),
                    syntheticAcceptedProof(graph, attempt))
            }
            assertTrue(failure.message.orEmpty().contains("dependency evidence"))
            graph.reject(attempt, RepairEvidence("dependency-change", failure.message.orEmpty()))
        }

        assertContentEquals(before, target.readBytes())
    }

    @Test
    fun `candidate publication CAS preserves a concurrent replacement at the commit gap`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val held = project.resolve("src/modules/.alpha-original.repair")
        val parent = target.readBytes()
        val concurrent = parent + "\n/* concurrent external replacement */\n".toByteArray()
        val candidate = parent + "\n/* graph candidate */\n".toByteArray()
        var injected = false
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (!injected && point is ModuleRevisionFaultPoint.BeforePublicationExchange &&
                    point.phase == "candidate" && point.path == "src/modules/alpha.c"
                ) {
                    Files.move(target, held)
                    target.writeBytes(concurrent)
                    injected = true
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))

        val failure = assertFailsWith<IllegalArgumentException> {
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
        }

        assertTrue(failure.message.orEmpty().contains("exchange") || failure.suppressed.isNotEmpty())
        assertContentEquals(concurrent, target.readBytes())
        Files.delete(target)
        Files.move(held, target)
        graph.reject(attempt, RepairEvidence("cas-conflict", "concurrent candidate publication rejected"))
        graph.close()
        assertContentEquals(parent, target.readBytes())
    }

    @Test
    fun `rollback publication CAS preserves a concurrent replacement at the commit gap`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val held = project.resolve("src/modules/.alpha-candidate.repair")
        val parent = target.readBytes()
        val candidate = parent + "\n/* graph candidate */\n".toByteArray()
        val concurrent = parent + "\n/* concurrent rollback replacement */\n".toByteArray()
        var injected = false
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (!injected && point is ModuleRevisionFaultPoint.BeforePublicationExchange &&
                    point.phase == "rollback" && point.path == "src/modules/alpha.c"
                ) {
                    Files.move(target, held)
                    target.writeBytes(concurrent)
                    injected = true
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
        graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))

        assertFailsWith<IllegalArgumentException> {
            graph.reject(attempt, RepairEvidence("test", "exercise rollback CAS"))
        }

        assertContentEquals(concurrent, target.readBytes())
        val failedRecord = project.resolve("reports/repair-revisions/graph.json").readText()
        assertTrue(failedRecord.contains("restore_failed_unresolved"))
        assertTrue(failedRecord.contains("unrecognized_source_state") ||
            failedRecord.contains("restore_operation_failed"))
        Files.delete(target)
        Files.move(held, target)
        val rejected = graph.reject(attempt, RepairEvidence("cas-conflict", "concurrent rollback publication rejected"))
        assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, requireNotNull(rejected.rollbackRecord).state)
        graph.close()
        assertContentEquals(parent, target.readBytes())
    }

    @Test
    fun `CAS compensation preserves a replacement introduced at the actual rollback exchange gap`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val heldCandidate = project.resolve("src/modules/alpha.concurrent-held")
        val parent = target.readBytes()
        val candidate = parent + "\n/* graph candidate */\n".toByteArray()
        val concurrent = parent + "\n/* concurrent final-gap replacement */\n".toByteArray()
        var forceRollback = true
        var racedRollback = false
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                when {
                    forceRollback && point is ModuleRevisionFaultPoint.AfterPublicationExchange &&
                        point.phase == "candidate" && point.path == "src/modules/alpha.c" -> {
                        forceRollback = false
                        throw IllegalStateException("force publication rollback")
                    }
                    !racedRollback && point is ModuleRevisionFaultPoint.BeforeRollbackExchange &&
                        point.phase == "candidate" && point.path == "src/modules/alpha.c" -> {
                        Files.move(target, heldCandidate)
                        target.writeBytes(concurrent)
                        racedRollback = true
                    }
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))

        val failure = assertFailsWith<IllegalStateException> {
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
        }

        assertTrue(racedRollback)
        assertTrue(failure.suppressed.isNotEmpty())
        assertContentEquals(concurrent, target.readBytes())
        assertContentEquals(candidate, heldCandidate.readBytes())
        val journal = Files.list(target.parent).use { entries ->
            entries.iterator().asSequence().single {
                val name = it.fileName.toString()
                name.startsWith(".alpha.c.") && name.endsWith(".repair")
            }
        }
        assertContentEquals(parent, journal.readBytes())

        Files.delete(target)
        Files.move(journal, target)
        Files.delete(heldCandidate)
        graph.reject(attempt, RepairEvidence("cas-conflict", "rollback gap replacement was preserved"))
        graph.close()
        assertContentEquals(parent, target.readBytes())
    }

    @Test
    fun `forged pending preimage is rejected before any source mutation`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val beforeBytes = target.readBytes()
        val beforeKey = Files.readAttributes(target, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey()
        val graph = ModuleRevisionGraph.openLegacyForTesting(project, GeneratedCRepairIndexProfile)
        graph.beginAttempt(listOf("src/modules/alpha.c"))
        graph.close()
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val payload = graphPath.readText()
        val pendingOffset = payload.indexOf("\"pending\": {")
        assertTrue(pendingOffset >= 0)
        val prefix = payload.substring(0, pendingOffset)
        val pending = payload.substring(pendingOffset)
        val originalDigest = Regex("\"beforeSha256\":\"([0-9a-f]{64})\"")
            .find(pending)?.groupValues?.get(1) ?: error("pending preimage digest missing")
        val otherDigest = Regex("\"afterSha256\":\"([0-9a-f]{64})\"")
            .findAll(prefix).map { it.groupValues[1] }.first { it != originalDigest }
        graphPath.writeText(pending.replaceFirst(originalDigest, otherDigest).let(prefix::plus))

        assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }

        assertContentEquals(beforeBytes, target.readBytes())
        assertEquals(beforeKey, Files.readAttributes(target, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey())
    }

    @Test
    fun `self-consistent graph paths outside the current profile cannot trigger recovery writes`() {
        val project = createTempDirectory("repair-forged-layout-").resolve("project")
        project.resolve("code").createDirectories()
        project.resolve("code/main.txt").writeText("main\n")
        val privatePath = project.resolve("private.txt")
        privatePath.writeText("private parent\n")
        val profileId = "layout-binding-test-v1"
        val profileSha = "b".repeat(64)
        val graphLayout = RepairIndexLayout(
            sourcePaths = listOf("code/main.txt", "private.txt"),
            editablePaths = listOf("code/main.txt", "private.txt"),
            fallbackModuleIdsByPath = mapOf(
                "code/main.txt" to "main",
                "private.txt" to "private",
            ),
        )
        val currentLayout = RepairIndexLayout(
            sourcePaths = listOf("code/main.txt"),
            editablePaths = listOf("code/main.txt"),
            fallbackModuleIdsByPath = mapOf("code/main.txt" to "main"),
        )
        fun profile(layout: RepairIndexLayout) = object : RepairIndexProfile {
            override fun profileId(): String = profileId
            override fun configurationSha256(): String = profileSha
            override fun authorizesRecoveryLayout(
                sourcePaths: List<String>,
                editablePaths: List<String>,
                budget: RepairResourceBudget,
            ) = sourcePaths == layout.sourcePaths && editablePaths == layout.editablePaths
            override fun resolve(projectRoot: Path, budget: RepairResourceBudget): RepairIndexLayout = layout
        }
        val graph = ModuleRevisionGraph.openLegacyForTesting(project, profile(graphLayout))
        val attempt = graph.beginAttempt(listOf("private.txt"))
        val candidate = "forged graph candidate\n".toByteArray()
        graph.installCandidate(attempt, mapOf("private.txt" to candidate))
        graph.close()
        val candidateKey = Files.readAttributes(
            privatePath,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        ).fileKey()

        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, profile(currentLayout))
        }

        assertTrue(failure.message.orEmpty().contains("source paths"))
        assertContentEquals(candidate, privatePath.readBytes())
        assertEquals(
            candidateKey,
            Files.readAttributes(privatePath, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey(),
        )
    }

    @Test
    fun `duplicate unknown and noncanonical graph encodings fail closed without source mutation`() {
        listOf<(String) -> String>(
            { canonical -> canonical.replaceFirst("\"schemaVersion\": 2,", "\"schemaVersion\": 2,\n  \"schemaVersion\": 2,") },
            { canonical -> canonical.replaceFirst("\"schemaVersion\": 2,", "\"schemaVersion\": 2,\n  \"unexpected\": true,") },
            { canonical -> " \n$canonical" },
        ).forEach { tamper ->
            val project = generatedProject()
            val target = project.resolve("src/modules/alpha.c")
            val before = target.readBytes()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            val legacy = authoredLegacyGraphFixture(graphPath.readText(), 2)
            graphPath.writeText(tamper(legacy))

            assertFailsWith<IllegalArgumentException> {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
            }

            assertContentEquals(before, target.readBytes())
        }
    }

    @Test
    fun `schema six preimage metadata binds retained name and requires numeric scalars`() {
        val project = generatedProject()
        val source = project.resolve("src/modules/alpha.c")
        val original = source.readBytes()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            graph.beginAttempt(listOf("src/modules/alpha.c"))
        }
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val canonical = graphPath.readText()
        val document = Json.parseToJsonElement(canonical).jsonObject
        val pending = document.getValue("pending").jsonObject
        val metadata = pending.getValue("preimageMetadata").jsonObject
        val path = metadata.keys.single()
        val record = metadata.getValue(path).jsonObject
        assertEquals(
            setOf(
                "metadataVersion", "device", "inode", "mode", "uid", "gid", "size",
                "atimeSeconds", "atimeNanoseconds",
                "mtimeSeconds", "mtimeNanoseconds", "ctimeSeconds", "ctimeNanoseconds",
                "retainedName", "xattrPolicy", "ancestorMetadata",
            ),
            record.keys,
        )
        assertEquals(2, record.getValue("metadataVersion").jsonPrimitive.content.toInt())
        assertEquals("NONE", record.getValue("xattrPolicy").jsonPrimitive.content)
        assertEquals(true, record.getValue("device").jsonPrimitive.isString.not())
        assertEquals(true, record.getValue("retainedName").jsonPrimitive.isString)

        val retainedName = record.getValue("retainedName").jsonPrimitive.content
        val wrongRetainedName = ".revision_wrong-${"0".repeat(64)}.preimage"
        val wrongNameGraph = canonical.replace(
            "\"retainedName\":\"$retainedName\"",
            "\"retainedName\":\"$wrongRetainedName\"",
        )
        assertNotEquals(canonical, wrongNameGraph)
        graphPath.writeText(wrongNameGraph)
        assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }
        assertContentEquals(original, source.readBytes())

        val device = record.getValue("device").jsonPrimitive.content
        val stringDeviceGraph = canonical.replaceFirst("\"device\":$device", "\"device\":\"$device\"")
        assertNotEquals(canonical, stringDeviceGraph)
        graphPath.writeText(stringDeviceGraph)
        assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }
        assertContentEquals(original, source.readBytes())
    }

    @Test
    fun `legacy schema graph remains readable but cannot begin an agent repair`() {
        val project = generatedProject()
        ModuleRevisionGraph.openLegacyForTesting(project, GeneratedCRepairIndexProfile, schemaVersion = 1).use { }

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertEquals(1, graph.snapshot.schemaVersion)
            val corpus = graph.retainedRegressionCorpus()
            val failure = assertFailsWith<IllegalArgumentException> {
                graph.beginAttempt(
                    listOf("src/modules/alpha.c"),
                    RevisionRepairMetadata(
                        1,
                        "compile",
                        "legacy compatibility must not create a release record",
                        null,
                        emptyList(),
                        null,
                        corpus.sha256,
                    ),
                )
            }
            assertTrue(failure.message.orEmpty().contains("non-release"))
        }
    }

    @Test
    fun `unbound extra ACP receipt cannot enter repair history`() {
        val project = generatedProject()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        project.resolve("reports/repair-revisions/revision_stale.acp-receipt.json")
            .writeText("{}\n")

        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }

        assertTrue(failure.message.orEmpty().contains("extra, or stale"))
    }

    @Test
    fun `accept revalidates current dependency evidence before persisting the head`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/beta.c")
        val parent = target.readBytes()
        val candidate = parent + "\n/* candidate */\n".toByteArray()
        val model = project.resolve("reports/program_model.json")
        val originalEvidence = model.readText()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val metadata = beginSyntheticAcceptedRun(graph)
        val attempt = graph.beginAttempt(listOf("src/modules/beta.c"), metadata)
        graph.installCandidate(attempt, mapOf("src/modules/beta.c" to candidate))
        model.writeText(originalEvidence.replaceFirst("alpha_run", "alpha_run_changed"))

        val failure = assertFailsWith<IllegalArgumentException> {
            graph.accept(attempt, RepairEvidence("valid", "must not commit stale index evidence"),
                syntheticAcceptedProof(graph, attempt))
        }

        assertTrue(failure.message.orEmpty().contains("evidence"))
        assertEquals(graph.snapshot.nodes.first().id, graph.snapshot.headId)
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        model.writeText(originalEvidence)
        graph.reject(attempt, RepairEvidence("evidence-changed", "fresh index rejected the candidate"))
        graph.close()
        assertContentEquals(parent, target.readBytes())
    }

    @Test
    fun `accept repeats full evidence validation at the final head commit boundary`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/beta.c")
        val parent = target.readBytes()
        val unrelatedSource = project.resolve("src/modules/alpha.c")
        val unrelatedSourceBytes = unrelatedSource.readBytes()
        var injected = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (!injected && point == ModuleRevisionFaultPoint.Schema6DecisionPrevalidated) {
                    unrelatedSource.writeBytes(unrelatedSourceBytes + "\n/* changed at decision boundary */\n".toByteArray())
                    injected = true
                }
            },
        )
        val metadata = beginSyntheticAcceptedRun(graph)
        val attempt = graph.beginAttempt(listOf("src/modules/beta.c"), metadata)
        graph.installCandidate(
            attempt,
            mapOf("src/modules/beta.c" to (parent + "\n/* candidate */\n".toByteArray())),
        )
        val candidateGraph = project.resolve("reports/repair-revisions/graph.json").readBytes()

        assertFailsWith<IllegalArgumentException> {
            graph.accept(attempt, RepairEvidence("valid", "must not commit across stale evidence"),
                syntheticAcceptedProof(graph, attempt))
        }

        assertTrue(injected)
        assertEquals(graph.snapshot.nodes.first().id, graph.snapshot.headId)
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        assertContentEquals(candidateGraph, project.resolve("reports/repair-revisions/graph.json").readBytes())
        graph.close()
        assertContentEquals(parent, target.readBytes())
    }

    @Test
    fun `schema six cancellation and deadline at decision boundary leave source uncommitted`() {
        val interruptions: List<Pair<String, () -> Exception>> = listOf(
            "cancellation" to { RepairTransportCancelledException() },
            "deadline" to { RepairBudgetExceededException("aggregate repair wall-clock budget exhausted") },
        )
        interruptions.forEach { (label, interruption) ->
            val project = generatedProject()
            val relative = "src/modules/beta.c"
            val target = project.resolve(relative)
            data class SourceState(
                val file: decompengine.acp.LinuxFileState,
                val contentSha256: String,
                val parent: decompengine.acp.LinuxDirectoryMetadata,
                val parentEntries: List<String>,
            )
            fun sourceState(): SourceState = LinuxFilesystemSyscalls.openRoot(project).use { root ->
                LinuxFilesystemSyscalls.openDirectoryAt(root.fd, "src").use { src ->
                    LinuxFilesystemSyscalls.openDirectoryAt(src.fd, "modules").use { modules ->
                        requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(modules.fd, "beta.c")).use { file ->
                            val state = LinuxFilesystemSyscalls.fileState(file)
                            SourceState(
                                file = state,
                                contentSha256 = LinuxFilesystemSyscalls.sha256WithoutAtime(file, state.size),
                                parent = LinuxFilesystemSyscalls.directoryMetadata(modules),
                                parentEntries = LinuxFilesystemSyscalls.directoryEntryNamesWithoutAtime(modules, 128).sorted(),
                            )
                        }
                    }
                }
            }

            val before = sourceState()
            val cancellationRequested = java.util.concurrent.atomic.AtomicBoolean(false)
            var decisionBoundaryReached = false
            ModuleRevisionGraph.openForTesting(
                project,
                GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (point == ModuleRevisionFaultPoint.BeforeSchema6DecisionPersist) {
                        decisionBoundaryReached = true
                        cancellationRequested.set(true)
                    }
                },
            ).use { graph ->
                val metadata = beginSyntheticAcceptedRun(graph)
                val attempt = graph.beginAttempt(listOf(relative), metadata)
                val candidateBytes = readProjectSourceWithoutAtime(project, relative) +
                    "\n/* must remain uncommitted after $label */\n".toByteArray()
                graph.installCandidate(attempt, mapOf(relative to candidateBytes))
                val proof = syntheticAcceptedProof(graph, attempt)
                val originalHead = graph.snapshot.headId

                val failure = assertFailsWith<Exception>(label) {
                    graph.accept(
                        attempt,
                        RepairEvidence("valid", "candidate passed before $label at decision boundary"),
                        proof,
                    ) {
                        if (cancellationRequested.get()) throw interruption()
                    }
                }

                assertEquals(interruption().javaClass, failure.javaClass, "$label should propagate unchanged")
                assertTrue(decisionBoundaryReached, "$label was not injected at the durable decision boundary")
                assertEquals(originalHead, graph.snapshot.headId, "$label must not advance the accepted head")
                assertEquals(attempt.id, graph.snapshot.pendingAttemptId, "$label must leave the candidate rejectable")
                assertNull(graph.snapshot.fullyAcceptedHeadId, "$label must not record an accepted revision")
                val pending = Json.parseToJsonElement(
                    project.resolve("reports/repair-revisions/graph.json").readText(),
                ).jsonObject.getValue("pending").jsonObject
                assertEquals(JsonNull, pending.getValue("acceptanceDecision"), "$label must precede the decision")
                assertTrue(pending.getValue("predecisionStageFiles").jsonArray.isEmpty(),
                    "$label must clean all private staging entries")
                assertEquals(0L, Files.list(project.resolve("reports/repair-revisions/publication-staging")).use { it.count() })

                graph.reject(attempt, RepairEvidence("cancelled", "decision gate refused $label"))
            }
            assertEquals(before, sourceState(), "$label changed source bytes, inode, metadata, or ancestor entries")
            assertTrue(Files.exists(target))
        }
    }

    @Test
    fun `schema six final witness follows the last canonical source scan`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/beta.c")
        val parent = target.readBytes()
        val unrelated = project.resolve("src/modules/alpha.c")
        val originalMode = Files.getPosixFilePermissions(unrelated)
        var armed = false
        var injected = false
        ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && !injected && point ==
                    ModuleRevisionFaultPoint.AfterStateTemporaryDirectorySync("revision-state", "graph.json")) {
                    Files.setPosixFilePermissions(unrelated, originalMode - java.nio.file.attribute.PosixFilePermission.OWNER_WRITE)
                    injected = true
                }
            },
        ).use { graph ->
            val metadata = beginSyntheticAcceptedRun(graph)
            val attempt = graph.beginAttempt(listOf("src/modules/beta.c"), metadata)
            graph.installCandidate(attempt, mapOf("src/modules/beta.c" to (parent + "\n/* candidate */\n".toByteArray())))
            armed = true
            val decisionPath = project.resolve("reports/repair-revisions/graph.json")
            val pendingBytes = decisionPath.readBytes()

            assertFailsWith<IllegalArgumentException> {
                graph.accept(attempt, RepairEvidence("valid", "must not accept a changed witness"),
                    syntheticAcceptedProof(graph, attempt))
            }

            assertTrue(injected)
            assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
            assertContentEquals(pendingBytes, decisionPath.readBytes())
            assertEquals(0L, Files.list(project.resolve("reports/repair-revisions/publication-staging")).use { it.count() })
        }
        assertContentEquals(parent, target.readBytes())
    }

    @Test
    fun `schema six predecision preparation failure cleans stages and permits retry`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/beta.c")
        val before = target.readBytes()
        val candidate = before + "\n/* retry after predecision failure */\n".toByteArray()
        var failOnce = true
        ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (failOnce && point == ModuleRevisionFaultPoint.Schema6DecisionPrevalidated) {
                    failOnce = false
                    throw IllegalArgumentException("injected schema-6 predecision failure")
                }
            },
        ).use { graph ->
            val metadata = beginSyntheticAcceptedRun(graph)
            val attempt = graph.beginAttempt(listOf("src/modules/beta.c"), metadata)
            graph.installCandidate(attempt, mapOf("src/modules/beta.c" to candidate))
            val proof = syntheticAcceptedProof(graph, attempt)

            assertFailsWith<IllegalArgumentException> {
                graph.accept(attempt, RepairEvidence("valid", "retryable staged decision"), proof)
            }

            assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
            val staging = project.resolve("reports/repair-revisions/publication-staging")
            assertEquals(0L, Files.list(staging).use { it.count() })
            assertEquals(graph.snapshot.nodes.first().id, graph.snapshot.headId)

            val accepted = graph.accept(attempt, RepairEvidence("valid", "retryable staged decision"), proof)
            assertEquals(ModuleRevisionStatus.ACCEPTED, accepted.status)
            assertContentEquals(candidate, target.readBytes())
        }
    }

    @Test
    fun `schema six retry preserves bindings after partial predecision stage cleanup`() {
        val project = generatedProject()
        val alphaPath = "src/modules/alpha.c"
        val betaPath = "src/modules/beta.c"
        val alpha = project.resolve(alphaPath)
        val beta = project.resolve(betaPath)
        val alphaBefore = alpha.readBytes()
        val betaBefore = beta.readBytes()
        val alphaCandidate = alphaBefore + "\n/* retry alpha */\n".toByteArray()
        val betaCandidate = betaBefore + "\n/* retry beta */\n".toByteArray()
        var failDecisionOnce = true
        var failSecondCleanupOnce = true
        ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (failDecisionOnce && point == ModuleRevisionFaultPoint.Schema6DecisionPrevalidated) {
                    failDecisionOnce = false
                    throw IllegalArgumentException("injected predecision failure before partial cleanup")
                }
                if (failSecondCleanupOnce && point == ModuleRevisionFaultPoint.BeforeUndecidedStageUnlink(betaPath)) {
                    failSecondCleanupOnce = false
                    throw IllegalStateException("injected second-stage cleanup failure")
                }
            },
        ).use { graph ->
            val metadata = beginSyntheticAcceptedRun(graph)
            val attempt = graph.beginAttempt(listOf(alphaPath, betaPath), metadata)
            graph.installCandidate(attempt, mapOf(alphaPath to alphaCandidate, betaPath to betaCandidate))
            val proof = syntheticAcceptedProof(graph, attempt)

            assertFailsWith<IllegalArgumentException> {
                graph.accept(attempt, RepairEvidence("valid", "retry partial cleanup"), proof)
            }

            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            val pending = Json.parseToJsonElement(graphPath.readText()).jsonObject
                .getValue("pending").jsonObject
            val registered = pending.getValue("predecisionStageFiles").jsonArray.map { it.jsonObject }
            assertEquals(listOf(alphaPath, betaPath), registered.map { it.getValue("path").jsonPrimitive.content })
            val staging = project.resolve("reports/repair-revisions/publication-staging")
            val stageByPath = registered.associateBy { it.getValue("path").jsonPrimitive.content }
            assertFalse(Files.exists(staging.resolve(stageByPath.getValue(alphaPath)
                .getValue("stagingName").jsonPrimitive.content)))
            assertTrue(Files.exists(staging.resolve(stageByPath.getValue(betaPath)
                .getValue("stagingName").jsonPrimitive.content)))
            assertEquals(graph.snapshot.nodes.first().id, graph.snapshot.headId)
            assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
            assertContentEquals(alphaBefore, readProjectSourceWithoutAtime(project, alphaPath))
            assertContentEquals(betaBefore, readProjectSourceWithoutAtime(project, betaPath))

            val accepted = graph.accept(attempt, RepairEvidence("valid", "retry after authenticating residue"), proof)
            assertEquals(ModuleRevisionStatus.ACCEPTED, accepted.status)
            assertContentEquals(alphaCandidate, alpha.readBytes())
            assertContentEquals(betaCandidate, beta.readBytes())
            assertEquals(0L, Files.list(staging).use { it.count() })
        }
    }

    @Test
    fun `oversized metadata is rejected before canonical graph persistence and remains reopenable`() {
        val budget = RepairResourceBudget(
            maximumRegressionInputBytes = 32,
            maximumRequestBytes = 64,
        )
        run {
            val project = generatedProject()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val before = project.resolve("reports/repair-revisions/graph.json").readBytes()
                val corpus = graph.retainedRegressionCorpus()
                assertFailsWith<IllegalArgumentException> {
                    graph.beginAttempt(
                        listOf("src/modules/alpha.c"),
                        RevisionRepairMetadata(1, "compile", "x".repeat(65), null, emptyList(), null, corpus.sha256),
                    )
                }
                assertContentEquals(before, project.resolve("reports/repair-revisions/graph.json").readBytes())
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
        }
        run {
            val project = generatedProject()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val corpus = graph.retainedRegressionCorpus()
                val attempt = graph.beginAttempt(
                    listOf("src/modules/alpha.c"),
                    RevisionRepairMetadata(1, "compile", "short", null, emptyList(), null, corpus.sha256),
                )
                val before = project.resolve("reports/repair-revisions/graph.json").readBytes()
                assertFailsWith<IllegalArgumentException> { graph.annotateAttempt(attempt, "s".repeat(65)) }
                assertContentEquals(before, project.resolve("reports/repair-revisions/graph.json").readBytes())
                graph.reject(attempt, RepairEvidence("rejected", "bounded"))
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
        }
        run {
            val project = generatedProject()
            val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget)
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            val before = project.resolve("reports/repair-revisions/graph.json").readBytes()
            assertFailsWith<IllegalArgumentException> {
                graph.reject(attempt, RepairEvidence("rejected", "e".repeat(65)))
            }
            assertContentEquals(before, project.resolve("reports/repair-revisions/graph.json").readBytes())
            graph.close()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
        }
    }

    @Test
    fun `aggregate rejection evidence is refused before restoration or schema upgrade`() {
        for (nativeSchema in listOf(false, true)) for (graphLimit in listOf(false, true)) {
            val project = generatedProject()
            val target = project.resolve("src/modules/alpha.c")
            val original = target.readBytes()
            val candidate = original + "\n/* aggregate evidence preflight */\n".toByteArray()
            val budget = if (graphLimit) RepairResourceBudget(maximumGraphBytes = 16L * 1024)
                else RepairResourceBudget(maximumProjectionBytes = 16L * 1024)
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            ModuleRevisionGraph.openLegacyForTesting(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                if (nativeSchema) graph.enableRunContract()
                val corpus = graph.retainedRegressionCorpus()
                val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"),
                    RevisionRepairMetadata(1, "compile", "short", "bounded", emptyList(), null, corpus.sha256,
                        publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE))
                graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
                val before = graphPath.readBytes()
                val snapshot = graph.snapshot
                val graphKey = Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey()
                val sourceKey = Files.readAttributes(target, BasicFileAttributes::class.java).fileKey()
                val evidence = RepairEvidence("rejected", "x".repeat(32 * 1024))
                assertTrue(evidence.summary.length < budget.maximumRequestBytes)
                assertFailsWith<RepairBudgetExceededException> { graph.reject(attempt, evidence) }
                assertContentEquals(before, graphPath.readBytes())
                assertContentEquals(candidate, target.readBytes())
                assertEquals(graphKey, Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey())
                assertEquals(sourceKey, Files.readAttributes(target, BasicFileAttributes::class.java).fileKey())
                assertEquals(snapshot, graph.snapshot)
                assertEquals(5, graph.snapshot.schemaVersion)
                val rejected = graph.reject(attempt, RepairEvidence("rejected", "bounded evidence"))
                assertEquals(attempt.id, rejected.id)
                assertContentEquals(original, target.readBytes())
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).close()
        }
    }

    @Test
    fun `only the first rollback record may retain a legacy migration origin`() {
        val project = generatedProject()
        val budget = RepairResourceBudget(maximumGraphBytes = 16L * 1024)
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val target = project.resolve("src/modules/alpha.c")
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            val first = graph.beginAttempt(listOf("src/modules/alpha.c"))
            graph.reject(first, RepairEvidence("rejected", "legacy pending attempt"))
            val second = graph.beginAttempt(listOf("src/modules/alpha.c"))
            graph.reject(second, RepairEvidence("rejected", "native attempt"))
        }
        val authentic = graphPath.readText()
        val source = target.readBytes()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).close()
        val twoOrigins = authentic.replace("\"legacyPendingStateUnknown\":false", "\"legacyPendingStateUnknown\":true")
        // Swap the two flags without changing any identities, source facts, or record ordering.
        val split = authentic.split("\"legacyPendingStateUnknown\":")
        assertEquals(3, split.size)
        val swapped = split[0] + "\"legacyPendingStateUnknown\":" + split[1].replaceFirst("true", "false") +
            "\"legacyPendingStateUnknown\":" + split[2].replaceFirst("false", "true")
        val padding = (budget.maximumGraphBytes + 1024 - twoOrigins.toByteArray().size).toInt()
        assertTrue(padding > 0)
        val oversizedOrigins = twoOrigins.replace("legacy pending attempt", "legacy pending attempt" + "x".repeat(padding))
        assertEquals(budget.maximumGraphBytes + 1024, oversizedOrigins.toByteArray().size.toLong())
        val budgetFailure = assertFailsWith<IllegalArgumentException> {
            requireRepairGraphByteBudget(oversizedOrigins.toByteArray(), budget)
        }
        assertTrue(budgetFailure.message.orEmpty().contains("legacy rollback origins"))
        for (forged in listOf(twoOrigins, swapped, oversizedOrigins)) {
            graphPath.writeText(forged)
            val key = Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey()
            val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget) }
            assertTrue(failure.message.orEmpty().contains("legacy rollback origins"))
            assertEquals(forged, graphPath.readText())
            assertEquals(key, Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey())
            assertContentEquals(source, target.readBytes())
        }
        graphPath.writeText(authentic)
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).close()
    }

    @Test
    fun `forged root projection cannot trigger pending recovery writes`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val graph = ModuleRevisionGraph.openLegacyForTesting(project, GeneratedCRepairIndexProfile)
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
        val candidate = target.readBytes() + "\n/* pending */\n".toByteArray()
        graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
        graph.close()
        val candidateKey = Files.readAttributes(target, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey()
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        graphPath.writeText(graphPath.readText().replaceFirst("\"changedModules\": []", "\"changedModules\": [\"forged\"]"))

        assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }

        assertContentEquals(candidate, target.readBytes())
        assertEquals(candidateKey, Files.readAttributes(target, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey())
    }

    @Test
    fun `repair profiles cannot claim graph-owned source or projection paths`() {
        listOf(
            "source_tree_manifest.json",
            "reports/source_revisions.jsonl",
            "reports/repair_history.json",
            "reports/repair-revisions/graph.json",
        ).forEach { reserved ->
            assertFailsWith<IllegalArgumentException> {
                RepairIndexLayout(sourcePaths = listOf(reserved), editablePaths = listOf(reserved))
            }
        }
    }

    @Test
    fun `independent graph owners merge and persist a deterministic full regression corpus`() {
        val first = generatedProject()
        val second = generatedProject()
        listOf(first, second).forEachIndexed { index, project ->
            val batches = if (index == 0) {
                listOf(listOf(ProcessInput("z", listOf("2"), byteArrayOf(2))), listOf(ProcessInput("a", stdin = byteArrayOf(1))))
            } else {
                listOf(listOf(ProcessInput("a", stdin = byteArrayOf(1))), listOf(ProcessInput("z", listOf("2"), byteArrayOf(2))))
            }
            batches.forEach { batch ->
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                    graph.retainRegressionInputs(batch)
                }
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                val corpus = graph.retainedRegressionCorpus()
                assertEquals(listOf("a", "z"), corpus.inputs.map { it.id })
                assertEquals(corpus.sha256, graph.snapshot.regressionCorpusSha256)
            }
        }
        assertContentEquals(
            first.resolve("reports/repair-revisions/graph.json").readBytes(),
            second.resolve("reports/repair-revisions/graph.json").readBytes(),
        )
    }

    @Test
    fun `regression corpus bounds empty case and argv structural amplification before persistence`() {
        val project = generatedProject()
        val budget = RepairResourceBudget(
            maximumRegressionInputs = 2,
            maximumRegressionArguments = 2,
        )
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            val before = graphPath.readBytes()

            assertFailsWith<RepairBudgetExceededException> {
                graph.retainRegressionInputs(listOf(ProcessInput("a"), ProcessInput("b"), ProcessInput("c")))
            }
            assertContentEquals(before, graphPath.readBytes())
            assertFailsWith<RepairBudgetExceededException> {
                graph.retainRegressionInputs(listOf(ProcessInput("a", listOf("", "", ""))))
            }
            assertContentEquals(before, graphPath.readBytes())
            assertTrue(graph.retainedRegressionCorpus().inputs.isEmpty())
        }
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
    }

    @Test
    fun `history projection fails from aggregate accounting before decoding retained blobs`() {
        val project = generatedProject()
        val budget = RepairResourceBudget(maximumProjectionBytes = 512)
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget)
        val corpus = graph.retainedRegressionCorpus()
        val unrelated = graph.snapshot.nodes.first().changes.single { it.path == "src/modules/delta.c" }
        val digest = unrelated.afterBlobSha256
        val blob = project.resolve("reports/repair-revisions/blobs/$digest")
        val originalBlob = blob.readBytes()
        blob.writeText("corrupt only after graph open")

        val failure = assertFailsWith<RepairBudgetExceededException> {
            graph.beginAttempt(
                listOf("src/modules/alpha.c"),
                RevisionRepairMetadata(1, "compile", "bounded", null, emptyList(), null, corpus.sha256),
            )
        }

        assertTrue(failure.message.orEmpty().contains("projection"))
        assertEquals(null, graph.snapshot.pendingAttemptId)
        blob.writeBytes(originalBlob)
        graph.close()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
    }

    @Test
    fun `compatibility log emits one bounded evidence record for a multi-file revision`() {
        val project = generatedProject()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val paths = listOf("src/modules/alpha.c", "src/modules/beta.c")
            val candidates = paths.associateWith { path ->
                project.resolve(path).readBytes() + "\n/* candidate */\n".toByteArray()
            }
            val attempt = graph.beginAttempt(paths)
            graph.installCandidate(attempt, candidates)
            graph.reject(attempt, RepairEvidence("compile", "one revision-level evidence value"))
            graph.synchronizeCompatibilityLog()
        }

        val record = project.resolve("reports/source_revisions.jsonl").readLines().single()
        assertEquals(1, Regex("\\\"evidenceKind\\\"").findAll(record).count())
        assertEquals(2, Regex("\\\"path\\\"").findAll(record).count())
        assertTrue(record.contains("\"changes\":["))
    }

    @Test
    fun `pending recovery enforces context and patch cardinality before source restoration`() {
        val project = generatedProject()
        val highBudget = RepairResourceBudget(maximumContextFiles = 2, maximumPatchFiles = 2)
        val lowBudget = RepairResourceBudget(maximumContextFiles = 1, maximumPatchFiles = 1)
        val paths = listOf("src/modules/alpha.c", "src/modules/beta.c")
        val candidates = paths.associateWith { path ->
            project.resolve(path).readBytes() + "\n/* oversized pending shape */\n".toByteArray()
        }
        ModuleRevisionGraph.openLegacyForTesting(project, GeneratedCRepairIndexProfile, highBudget).use { graph ->
            val attempt = graph.beginAttempt(paths)
            graph.installCandidate(attempt, candidates)
        }
        val keys = paths.associateWith { path ->
            Files.readAttributes(
                project.resolve(path),
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            ).fileKey()
        }
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val reducedGraph = graphPath.readText()
            .replace("\"maximumContextFiles\":2", "\"maximumContextFiles\":1")
            .replace("\"maximumPatchFiles\":2", "\"maximumPatchFiles\":1")
        graphPath.writeText(reducedGraph)
        val reducedBudgetJson = Json.parseToJsonElement(reducedGraph).jsonObject.getValue("budget").toString()
        val bindingPath = project.resolve("reports/repair-revisions/recovery-binding.json")
        bindingPath.writeText(
            bindingPath.readText().replace(
                Regex("(?<=\\\"budgetSha256\\\": \\\")[0-9a-f]{64}"),
                sha256(reducedBudgetJson.toByteArray()),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, lowBudget)
        }

        paths.forEach { path ->
            assertContentEquals(candidates.getValue(path), project.resolve(path).readBytes())
            assertEquals(
                keys.getValue(path),
                Files.readAttributes(
                    project.resolve(path),
                    BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                ).fileKey(),
            )
        }
    }

    @Test
    fun `generated C discovery counts excluded repair entries and directory depth`() {
        val project = createTempDirectory("repair-discovery-budget-").resolve("project")
        project.resolve("src").createDirectories()
        project.resolve("include").createDirectories()
        project.resolve("Makefile").writeText("all:\n\t@true\n")
        project.resolve("src/program.c").writeText("int main(void) { return 0; }\n")
        repeat(12) { project.resolve("src/.note-$it.repair").writeText("ignored") }

        assertFailsWith<RepairBudgetExceededException> {
            ModuleRepairIndex.load(
                project,
                GeneratedCRepairIndexProfile,
                RepairResourceBudget(maximumDiscoveryEntries = 8, maximumDiscoveryDirectories = 8),
            )
        }

        val deep = project.resolve("src/a/b/c").createDirectories()
        deep.resolve("leaf.h").writeText("#define LEAF 1\n")
        assertFailsWith<IllegalArgumentException> {
            ModuleRepairIndex.load(
                project,
                GeneratedCRepairIndexProfile,
                RepairResourceBudget(maximumDiscoveryDepth = 2),
            )
        }
    }

    @Test
    fun `source replacement preserves exact mode and rejects unsupported metadata`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val originalMode = setOf(
            java.nio.file.attribute.PosixFilePermission.OWNER_READ,
            java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
            java.nio.file.attribute.PosixFilePermission.GROUP_READ,
        )
        Files.setPosixFilePermissions(target, originalMode)
        val modeCandidate = target.readBytes() + "\n/* mode */\n".toByteArray()
        ModuleRevisionGraph.openLegacyForTesting(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to modeCandidate))
            assertEquals(originalMode, Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS))
            graph.reject(attempt, RepairEvidence("test", "restore mode"))
            assertEquals(originalMode, Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS))
        }

        val linkedProject = generatedProject()
        val linkedTarget = linkedProject.resolve("src/modules/alpha.c")
        Files.createLink(linkedProject.resolve("src/modules/alpha-hardlink.c"), linkedTarget)
        val linkedBytes = linkedTarget.readBytes()
        ModuleRevisionGraph.openLegacyForTesting(linkedProject, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            assertFailsWith<IllegalArgumentException> {
                graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to (linkedBytes + byteArrayOf(1))))
            }
            graph.reject(attempt, RepairEvidence("metadata", "hard link rejected"))
        }
    }

    @Test
    fun `schema five refuses an existing xattr before committing the no-xattr preimage policy`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val source = project.resolve(relative)
        val attributes = Files.getFileAttributeView(
            source,
            java.nio.file.attribute.UserDefinedFileAttributeView::class.java,
            LinkOption.NOFOLLOW_LINKS,
        ) ?: return
        try {
            attributes.write("repair-preimage", java.nio.ByteBuffer.wrap(byteArrayOf(4, 2)))
        } catch (_: UnsupportedOperationException) {
            return
        } catch (_: java.io.IOException) {
            return
        }

        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val failure = assertFailsWith<IllegalArgumentException> {
            graph.beginAttempt(listOf(relative))
        }
        assertTrue(failure.message.orEmpty().contains("no-extended-attributes"), failure.message)
        assertNull(graph.snapshot.pendingAttemptId, "an impossible xattr policy must not become durable pending state")
        graph.close()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            assertNull(reopened.snapshot.pendingAttemptId)
        }
    }

    @Test
    fun `ordinary derived-view failures after head commit still return committed success`() {
        listOf(
            ModuleRevisionFaultPoint.AfterHeadPersist,
            ModuleRevisionFaultPoint.BeforeSourceManifestSync,
            ModuleRevisionFaultPoint.BeforeCompatibilityLogSync,
        ).forEach { injectedPoint ->
            val project = generatedProject()
            val target = project.resolve("src/modules/beta.c")
            val candidate = target.readBytes() + "\n/* accepted despite projection failure */\n".toByteArray()
            val graph = ModuleRevisionGraph.openForTesting(
                project,
                GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (point == injectedPoint) throw IllegalStateException("injected derived-view I/O failure")
                },
            )
            val metadata = beginSyntheticAcceptedRun(graph)
            val attempt = graph.beginAttempt(listOf("src/modules/beta.c"), metadata)
            graph.installCandidate(attempt, mapOf("src/modules/beta.c" to candidate))

            val accepted = graph.accept(attempt, RepairEvidence("valid", "canonical commit succeeded"),
                syntheticAcceptedProof(graph, attempt))

            assertEquals(ModuleRevisionStatus.ACCEPTED, accepted.status)
            assertEquals(accepted.id, graph.snapshot.headId)
            graph.close()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
                assertEquals(accepted.id, reopened.snapshot.headId)
            }
        }
    }

    @Test
    fun `committed preimage cleanup failure is retried before the next graph mutation`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val before = target.readBytes()
        val candidate = before + "\n/* committed cleanup retry */\n".toByteArray()
        var failCleanupOnce = true
        var cleanupFaultObserved = false
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (failCleanupOnce && point is ModuleRevisionFaultPoint.BeforeOwnedEntryUnlink &&
                    point.phase == "committed-preimage-cleanup") {
                    failCleanupOnce = false
                    cleanupFaultObserved = true
                    throw IllegalStateException("interrupt committed preimage cleanup")
                }
            },
        )
        val inputs = listOf(ProcessInput("cleanup-retry", emptyList(), byteArrayOf()))
        val corpus = graph.retainRegressionInputs(inputs)
        graph.beginRun(1, 60_000)
        val attempt = graph.beginAttempt(listOf(relative), RevisionRepairMetadata(
            iterationIndex = 1,
            failureKind = "compile",
            prompt = "committed cleanup retry",
            summary = null,
            retainedRegressionIds = inputs.map(ProcessInput::id),
            before = null,
            regressionCorpusSha256 = corpus.sha256,
            publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE,
        ))
        graph.installCandidate(attempt, mapOf(relative to candidate))
        val proof = archiveValidationProofFixture(graph, attempt, project, inputs)
        graph.bindOriginalBinary(requireNotNull(proof.originalBinarySha256))
        graph.bindExpectedObservations(sha256(buildString {
            append(proof.originalBinarySha256).append('\n')
            inputs.forEach { input ->
                append(input.id.length).append(':').append(input.id).append(":0:")
                    .append(sha256(byteArrayOf())).append(':').append(sha256(byteArrayOf())).append('\n')
            }
        }.toByteArray()))
        val accepted = graph.accept(attempt, RepairEvidence("valid", "commit before retained-link cleanup"), proof)
        assertTrue(cleanupFaultObserved, "committed cleanup fault point was not reached")
        assertEquals(ModuleRevisionStatus.ACCEPTED, accepted.status,
            "a durable graph commit must not be reported as rejected when post-commit cleanup fails")
        assertContentEquals(candidate, target.readBytes())
        val retainedName = ".${attempt.id}-${sha256(relative.toByteArray())}.preimage"
        val revisions = project.resolve("reports/repair-revisions")
        assertTrue(Files.exists(revisions.resolve(retainedName), LinkOption.NOFOLLOW_LINKS),
            "retained preimage was not restored after cleanup failure: ${Files.list(revisions).use { stream -> stream.map { it.fileName.toString() }.toList() }}")

        assertEquals(accepted.id, graph.snapshot.headId)
        val next = graph.beginAttempt(listOf(relative))
        assertFalse(Files.exists(revisions.resolve(retainedName), LinkOption.NOFOLLOW_LINKS))
        graph.reject(next, RepairEvidence("rejected", "no new candidate was installed"))
        graph.close()
    }

    @Test
    fun `project-root paths in repair metadata are portable across equivalent roots`() {
        val first = generatedProject()
        val second = generatedProject()
        listOf(first, second).forEach { project ->
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                val corpus = graph.retainRegressionInputs(listOf(ProcessInput("case")))
                val attempt = graph.beginAttempt(
                    listOf("src/modules/beta.c"),
                    RevisionRepairMetadata(
                        1,
                        "compile",
                        "command failed in $project/src/modules/beta.c",
                        null,
                        listOf("case"),
                        RepairEvidence("compile", "working directory was $project", "$project/reports/build.log"),
                        corpus.sha256,
                    ),
                )
                graph.annotateAttempt(attempt, "diagnostic rooted at $project")
                graph.reject(attempt, RepairEvidence("agent-error", "agent log was under $project"))
            }
        }

        val firstGraph = first.resolve("reports/repair-revisions/graph.json").readBytes()
        val secondGraph = second.resolve("reports/repair-revisions/graph.json").readBytes()
        assertContentEquals(firstGraph, secondGraph)
        assertFalse(firstGraph.toString(Charsets.UTF_8).contains(first.toString()))
        assertTrue(firstGraph.toString(Charsets.UTF_8).contains("\${PROJECT_ROOT}"))
    }

    @Test
    fun `publication and rollback crashes after each file move recover every preimage on restart`() {
        listOf("after-exchange", "before-unlink", "after-move").forEach { crashStage ->
            listOf("candidate", "rollback").forEach { failingPhase ->
                repeat(2) { failingMove ->
                val project = generatedProject()
                val alpha = project.resolve("src/modules/alpha.c")
                val beta = project.resolve("src/modules/beta.c")
                val alphaBefore = alpha.readBytes()
                val betaBefore = beta.readBytes()
                val alphaOriginalKey = Files.readAttributes(alpha, java.nio.file.attribute.BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS).fileKey()
                val betaOriginalKey = Files.readAttributes(beta, java.nio.file.attribute.BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS).fileKey()
                val graph = ModuleRevisionGraph.openLegacyForTesting(
                    project,
                    GeneratedCRepairIndexProfile,
                    faultInjector = ModuleRevisionFaultInjector { point ->
                        val matches = when (point) {
                            is ModuleRevisionFaultPoint.AfterPublicationExchange ->
                                crashStage == "after-exchange" && point.phase == failingPhase && point.index == failingMove
                            is ModuleRevisionFaultPoint.AfterPublicationMove ->
                                crashStage == "after-move" && point.phase == failingPhase && point.index == failingMove
                            is ModuleRevisionFaultPoint.BeforeOwnedEntryUnlink ->
                                crashStage == "before-unlink" && point.phase == failingPhase && point.index == failingMove
                            else -> false
                        }
                        if (matches) {
                            throw SimulatedRepairCrash()
                        }
                    },
                )
                val attempt = graph.beginAttempt(listOf("src/modules/alpha.c", "src/modules/beta.c"))

                if (failingPhase == "candidate") {
                    assertFailsWith<SimulatedRepairCrash> {
                        graph.installCandidate(
                            attempt,
                            mapOf(
                                "src/modules/alpha.c" to alphaBefore + "\n/* crash alpha */\n".toByteArray(),
                                "src/modules/beta.c" to betaBefore + "\n/* crash beta */\n".toByteArray(),
                            ),
                        )
                    }
                } else {
                    graph.installCandidate(
                        attempt,
                        mapOf(
                            "src/modules/alpha.c" to alphaBefore + "\n/* crash alpha */\n".toByteArray(),
                            "src/modules/beta.c" to betaBefore + "\n/* crash beta */\n".toByteArray(),
                        ),
                    )
                    assertFailsWith<SimulatedRepairCrash> {
                        graph.reject(attempt, RepairEvidence("rejected", "exercise rollback crash"))
                    }
                }
                graph.close()

                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
                    assertContentEquals(alphaBefore, alpha.readBytes())
                    assertContentEquals(betaBefore, beta.readBytes())
                    assertEquals(alphaOriginalKey, Files.readAttributes(alpha,
                        java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey(),
                        "recovery must restore the displaced alpha inode")
                    assertEquals(betaOriginalKey, Files.readAttributes(beta,
                        java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey(),
                        "recovery must restore the displaced beta inode")
                    assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
                    assertEquals(
                        RepairRollbackState.RESTORED_VERIFIED,
                        requireNotNull(recovered.snapshot.nodes.last().rollbackRecord).state,
                    )
                }
            }
            }
        }
    }

    @Test
    fun `restart refuses same-bytes rollback whose restored preimage mode drifted`() {
        val project = generatedProject()
        val alpha = project.resolve("src/modules/alpha.c")
        val original = alpha.readBytes()
        val originalPermissions = Files.getPosixFilePermissions(alpha, LinkOption.NOFOLLOW_LINKS)
        var armed = false
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterPublicationExchange &&
                    point.phase == "rollback" && point.index == 0) throw SimulatedRepairCrash()
            },
        )
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
        graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to
            original + "\n/* metadata drift recovery */\n".toByteArray()))
        armed = true
        assertFailsWith<SimulatedRepairCrash> {
            graph.reject(attempt, RepairEvidence("rejected", "interrupt after original inode restore"))
        }
        graph.close()

        Files.setPosixFilePermissions(alpha, originalPermissions + PosixFilePermission.OWNER_EXECUTE)
        assertContentEquals(original, alpha.readBytes())
        assertFailsWith<Exception> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        }
    }

    @Test
    fun `schema 5 metadata survives a second crash during startup rollback`() {
        val project = generatedProject()
        val alpha = project.resolve("src/modules/alpha.c")
        val original = alpha.readBytes()
        var crashDuringExplicitRollback = false
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (crashDuringExplicitRollback && point is ModuleRevisionFaultPoint.AfterPublicationExchange &&
                    point.phase == "rollback" && point.index == 0) throw SimulatedRepairCrash()
            },
        )
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
        graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to
            original + "\n/* repeated startup recovery */\n".toByteArray()))
        crashDuringExplicitRollback = true
        assertFailsWith<SimulatedRepairCrash> {
            graph.reject(attempt, RepairEvidence("rejected", "force first rollback crash"))
        }
        graph.close()

        assertFailsWith<SimulatedRepairCrash> {
            ModuleRevisionGraph.openForTesting(
                project,
                GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (point is ModuleRevisionFaultPoint.AfterPublicationMove &&
                        point.phase == "startup-rollback" && point.index == 0) throw SimulatedRepairCrash()
                },
            )
        }
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val interruptedRecovery = Json.parseToJsonElement(graphPath.readText()).jsonObject
        assertEquals(5, interruptedRecovery.getValue("schemaVersion").jsonPrimitive.content.toInt())
        assertTrue(interruptedRecovery.getValue("pending").jsonObject
            .getValue("preimageMetadata").jsonObject.isNotEmpty())

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertContentEquals(original, alpha.readBytes())
            assertEquals(5, recovered.snapshot.schemaVersion)
            assertEquals(RepairRollbackState.RESTORED_VERIFIED,
                requireNotNull(recovered.snapshot.nodes.last().rollbackRecord).state)
        }
    }

    @Test
    fun `startup rollback reaps restore cleanup quarantine after abrupt process death`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val original = target.readBytes()
        val deliberatelyOldAtime = java.nio.file.attribute.FileTime.fromMillis(1_000_000L)
        Files.setAttribute(target, "basic:lastAccessTime", deliberatelyOldAtime, LinkOption.NOFOLLOW_LINKS)
        assertEquals(deliberatelyOldAtime, Files.readAttributes(
            target, java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS,
        ).lastAccessTime())
        val originalKey = Files.readAttributes(
            target, java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS,
        ).fileKey()
        val graph = ModuleRevisionGraph.openLegacyForTesting(project, GeneratedCRepairIndexProfile)
        val attempt = graph.beginAttempt(listOf(relative))
        graph.installCandidate(attempt, mapOf(relative to original + "\n/* stranded restore cleanup */\n".toByteArray()))
        graph.close()

        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", System.getProperty("java.class.path"),
            ModuleRevisionGraphRestoreCleanupCrashProbe::class.java.name,
            project.toString(), relative,
        ).redirectErrorStream(true).start()
        val outputReader = Executors.newSingleThreadExecutor()
        try {
            val output = outputReader.submit<String> {
                process.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
            }
            val exited = process.waitFor(20, TimeUnit.SECONDS)
            if (!exited) {
                process.destroyForcibly()
                process.waitFor(5, TimeUnit.SECONDS)
            }
            assertTrue(exited, "restore-cleanup crash probe did not terminate")
            assertEquals(86, process.exitValue(),
                "probe did not halt at the quarantined cleanup boundary: ${output.get(5, TimeUnit.SECONDS)}")
        } finally {
            if (process.isAlive) process.destroyForcibly()
            outputReader.shutdownNow()
        }
        val restoreCleanup = target.parent.resolve(".${target.fileName}.${attempt.id}.repair.restore.cleanup")
        assertTrue(Files.exists(restoreCleanup, LinkOption.NOFOLLOW_LINKS),
            "child process did not leave the expected post-quarantine crash residue")

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(deliberatelyOldAtime, Files.readAttributes(
                target, java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS,
            ).lastAccessTime(), "rollback recovery must preserve the committed regular-file atime")
            assertEquals(originalKey, Files.readAttributes(
                target, java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS,
            ).fileKey(), "startup recovery must restore the original inode")
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
            assertEquals(RepairRollbackState.RESTORED_VERIFIED,
                requireNotNull(recovered.snapshot.nodes.last().rollbackRecord).state)
        }
        assertContentEquals(original, target.readBytes())
        assertFalse(Files.exists(restoreCleanup, LinkOption.NOFOLLOW_LINKS),
            "startup recovery left the quarantined candidate in the source directory")
        assertFalse(Files.list(target.parent).use { entries ->
            entries.anyMatch { it.fileName.toString().contains(".restore.cleanup") }
        }, "recovery residue remains discoverable beside generated sources")
    }

    @Test
    fun `retrying rollback cleans a restored candidate left by restore unlink failure`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val original = target.readBytes()
        var failRestoreUnlink = true
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (failRestoreUnlink && point is ModuleRevisionFaultPoint.BeforeOwnedEntryUnlink &&
                    point.phase == "rollback" && point.path == relative) {
                    failRestoreUnlink = false
                    throw IllegalStateException("injected restore-entry unlink failure")
                }
            },
        )
        val attempt = graph.beginAttempt(listOf(relative))
        val candidate = original + "\n/* rollback cleanup retry */\n".toByteArray()
        graph.installCandidate(attempt, mapOf(relative to candidate))

        assertFailsWith<IllegalStateException> {
            graph.reject(attempt, RepairEvidence("agent-error", "first rollback cleanup is interrupted"))
        }
        assertContentEquals(original, target.readBytes(), "the failure is after restoring the canonical source")
        val restoreResidue = target.parent.resolve(".${target.fileName}.${attempt.id}.repair.restore")
        assertTrue(Files.exists(restoreResidue, LinkOption.NOFOLLOW_LINKS),
            "the injected unlink failure did not leave the retryable restore entry")
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId,
            "failed cleanup must retain the pending rollback record")

        val rejected = graph.reject(attempt, RepairEvidence("agent-error", "retry reconciles restore cleanup"))
        assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
        assertContentEquals(original, target.readBytes())
        assertFalse(Files.exists(restoreResidue, LinkOption.NOFOLLOW_LINKS))
        assertFalse(Files.exists(Path.of("$restoreResidue.cleanup"), LinkOption.NOFOLLOW_LINKS))
        graph.close()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            assertEquals(rejected.id, reopened.snapshot.nodes.last().id)
            assertEquals(ModuleRevisionStatus.REJECTED, reopened.snapshot.nodes.last().status)
        }
    }

    @Test
    fun `durable rollback failure remains visible and later recovery records restoration after failure`() {
        val project = generatedProject()
        val alpha = project.resolve("src/modules/alpha.c")
        val beta = project.resolve("src/modules/beta.c")
        val alphaOriginal = alpha.readBytes()
        val betaOriginal = beta.readBytes()
        val alphaCandidate = alphaOriginal + "\n/* rollback retry alpha */\n".toByteArray()
        val betaCandidate = betaOriginal + "\n/* rollback retry beta */\n".toByteArray()
        var armed = false
        var failRollbackOnce = true
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && failRollbackOnce && point is ModuleRevisionFaultPoint.AfterPublicationMove &&
                    point.phase == "rollback" && point.index == 0
                ) {
                    failRollbackOnce = false
                    throw IllegalStateException("injected failure after first restored source")
                }
            },
        )
        graph.enableRunContract()
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c", "src/modules/beta.c"))
        graph.installCandidate(
            attempt,
            mapOf("src/modules/alpha.c" to alphaCandidate, "src/modules/beta.c" to betaCandidate),
        )
        armed = true

        assertFailsWith<IllegalStateException> {
            graph.reject(attempt, RepairEvidence("rejected", "rollback failure is retained"))
        }
        assertContentEquals(alphaOriginal, alpha.readBytes())
        assertContentEquals(betaCandidate, beta.readBytes())
        val unresolvedGraph = project.resolve("reports/repair-revisions/graph.json").readText()
        assertTrue(unresolvedGraph.contains("restore_failed_unresolved"))
        assertTrue(unresolvedGraph.contains("restore_operation_failed"))
        val failedRecord = Json.parseToJsonElement(unresolvedGraph).jsonObject
            .getValue("pending").jsonObject.getValue("rollbackRecord").jsonObject
        assertTrue(
            failedRecord.getValue("observedSourceRevisionSha256").jsonPrimitive.content !=
                failedRecord.getValue("expectedSourceRevisionSha256").jsonPrimitive.content,
        )
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        graph.close()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertContentEquals(alphaOriginal, alpha.readBytes())
            assertContentEquals(betaOriginal, beta.readBytes())
            val outcome = requireNotNull(recovered.snapshot.nodes.last().rollbackRecord)
            assertEquals(attempt.id, outcome.attemptId)
            assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, outcome.state)
            assertEquals(RepairRollbackStage.SOURCE_RESTORE, outcome.failureStage)
            assertEquals(RepairRollbackFailureCode.RESTORE_OPERATION_FAILED, outcome.failureCode)
            assertEquals(outcome.expectedSourceRevisionSha256, outcome.observedSourceRevisionSha256)
            assertEquals(true, outcome.candidateSourceInstallStarted)
        }
    }

    @Test
    fun `failure to publish rollback is retained until restart recovery`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val original = target.readBytes()
        val candidate = original + "\n/* retained rollback marker */\n".toByteArray()
        var armed = false
        var rollbackFaulted = false
        var graphSyncCount = 0
        var markerDurableBeforeExchange = false
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed) {
                    if (!rollbackFaulted && point is ModuleRevisionFaultPoint.BeforePublicationExchange &&
                        point.phase == "rollback") {
                        rollbackFaulted = true
                        val durableGraph = project.resolve("reports/repair-revisions/graph.json").readText()
                        markerDurableBeforeExchange = durableGraph.contains("restore_in_progress") &&
                            !durableGraph.contains("restore_failed_unresolved")
                        throw IllegalStateException("injected rollback exchange failure")
                    }
                    if (rollbackFaulted && point is ModuleRevisionFaultPoint.AfterStateTemporaryDirectorySync &&
                        point.scope == "revision-state" && point.name == "graph.json" && graphSyncCount++ == 0) {
                        throw IllegalStateException("injected failure-record publication failure")
                    }
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
        graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
        armed = true

        assertFailsWith<IllegalStateException> { graph.reject(attempt, RepairEvidence("rejected", "retry after write failure")) }
        assertTrue(rollbackFaulted)
        assertTrue(markerDurableBeforeExchange)
        assertContentEquals(candidate, target.readBytes())
        val marker = project.resolve("reports/repair-revisions/graph.json").readText()
        assertTrue(marker.contains("restore_in_progress"))
        assertFalse(marker.contains("restore_failed_unresolved"))
        graph.close()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertContentEquals(original, target.readBytes())
            val outcome = requireNotNull(recovered.snapshot.nodes.last().rollbackRecord)
            assertEquals(RepairRollbackState.RESTORED_VERIFIED, outcome.state)
            assertEquals(null, outcome.failureCode)
            assertEquals("NONE",
                recovered.snapshot.nodes.last().publicationPreimageMetadata.getValue("src/modules/alpha.c").xattrPolicy)
        }
    }

    @Test
    fun `persisted schema two pending attempt migrates as unknown and restores its bound parent`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val original = target.readBytes()
        val candidate = original + "\n/* schema two recovery */\n".toByteArray()
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
        }
        val legacyGraph = authoredLegacyGraphFixture(graphPath.readText(), 2).also(graphPath::writeText).toByteArray()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertContentEquals(original, target.readBytes())
            val outcome = requireNotNull(recovered.snapshot.nodes.last().rollbackRecord)
            assertEquals(RepairRollbackState.RESTORED_VERIFIED, outcome.state)
            assertTrue(outcome.legacyPendingStateUnknown)
            assertEquals(null, outcome.candidateSourceInstallStarted)
            assertEquals(null, outcome.runId)
        }
        assertContentEquals(
            legacyGraph,
            graphPath.parent.resolve("legacy-graph-${sha256(legacyGraph)}.json").readBytes(),
        )
    }

    @Test
    fun `persisted schema four pending attempt recovers without fabricating legacy unknown state`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val original = target.readBytes()
        val candidate = original + "\n/* schema four recovery */\n".toByteArray()
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        ModuleRevisionGraph.openLegacyForTesting(project, GeneratedCRepairIndexProfile, schemaVersion = 4).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
        }
        val schemaFour = authoredLegacyGraphFixture(graphPath.readText(), 4).also(graphPath::writeText)
        assertEquals(JsonPrimitive(4), Json.parseToJsonElement(schemaFour).jsonObject.getValue("schemaVersion"))

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertContentEquals(original, target.readBytes())
            assertEquals(4, recovered.snapshot.schemaVersion)
            val record = requireNotNull(recovered.snapshot.nodes.last().rollbackRecord)
            assertEquals(RepairRollbackState.RESTORED_VERIFIED, record.state)
            assertFalse(record.legacyPendingStateUnknown)
            assertEquals(true, record.candidateSourceInstallStarted)
        }
        val recoveredNode = Json.parseToJsonElement(graphPath.readText()).jsonObject
            .getValue("nodes").jsonArray.last().jsonObject
        assertFalse("publicationChanges" in recoveredNode)
        assertFalse("publicationPreimageMetadata" in recoveredNode)
        assertContentEquals(schemaFour.toByteArray(), graphPath.parent.resolve(
            "legacy-graph-${sha256(schemaFour.toByteArray())}.json").readBytes())
    }

    @Test
    fun `historical schema one through four writer fixtures reopen and recover pending attempts`() {
        for (schema in 1..4) {
            val fixtureName = "legacy-schema${schema}-writer-pending"
            val resource = Path.of(requireNotNull(javaClass.getResource("/repair/$fixtureName")).toURI())
            val project = createTempDirectory("historical-schema-$schema-writer-")
            resource.toFile().copyRecursively(project.toFile(), overwrite = true)

            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            val document = Json.parseToJsonElement(graphPath.readText()).jsonObject
            assertEquals(schema, document.getValue("schemaVersion").jsonPrimitive.content.toInt())
            val historicalProfile = object : RepairIndexProfile by GeneratedCRepairIndexProfile {
                override fun profileId(): String = document.getValue("profileId").jsonPrimitive.content
                override fun configurationSha256(): String = document.getValue("profileSha256").jsonPrimitive.content
                override fun configurationSha256(budget: RepairResourceBudget): String = configurationSha256()
            }
            val pending = document.getValue("pending").jsonObject
            if (schema == 4) {
                assertEquals(false, pending.getValue("legacyRecoveryRequired").jsonPrimitive.content.toBoolean())
            }
            val change = pending.getValue("candidateChanges").jsonArray.single().jsonObject
            val beforeSha256 = change.getValue("beforeBlobSha256").jsonPrimitive.content
            val before = project.resolve("reports/repair-revisions/blobs/$beforeSha256").readBytes()
            val source = project.resolve("src/modules/alpha.c")
            assertEquals(beforeSha256, sha256(before), "schema $schema preimage blob must be content addressed")
            if (schema == 3) {
                assertEquals(beforeSha256, sha256(source.readBytes()), "schema 3 detached candidate must not alter live source")
            } else {
                assertNotEquals(beforeSha256, sha256(source.readBytes()), "schema $schema fixture must retain its installed pending candidate")
            }

            ModuleRevisionGraph.open(project, historicalProfile).use { recovered ->
                assertTrue(recovered.snapshot.schemaVersion in schema..4,
                    "schema $schema open must retain or migrate only within the historical schema range")
                assertEquals(null, recovered.snapshot.pendingAttemptId)
                assertEquals(ModuleRevisionStatus.REJECTED, recovered.snapshot.nodes.last().status)
                assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
                assertEquals(recovered.snapshot.nodes.first().id, recovered.snapshot.headId)
                recovered.enableRunContract()
                assertEquals(5, recovered.snapshot.schemaVersion)
            }
            assertContentEquals(before, source.readBytes(), "schema $schema recovery must restore the writer's preimage")
            assertTrue(graphPath.readText().contains("\"schemaVersion\": 5"))
        }
    }

    @Test
    fun `saturated legacy pending graphs retain bounded recovery headroom across marker crash and failure`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        for (schema in 1..3) {
            val project = generatedProject(temporaryParent = parent)
            val target = project.resolve("src/modules/alpha.c")
            val original = target.readBytes()
            val candidate = original + "\n/* saturated legacy recovery */\n".toByteArray()
            val budget = RepairResourceBudget(maximumGraphBytes = 16 * 1024)
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            val bindingPath = graphPath.parent.resolve("recovery-binding.json")
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                if (schema == 3) {
                    graph.enableRunContract()
                    graph.beginRun(2, 60_000)
                }
                val corpus = graph.retainedRegressionCorpus()
                val metadata = RevisionRepairMetadata(1, "compile", "short", "LEGACY_PADDING", emptyList(),
                    null, corpus.sha256, publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE)
                val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"), metadata)
                graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
            }
            var legacy = authoredLegacyGraphFixture(graphPath.readText(), schema)
            val fill = (budget.maximumGraphBytes - legacy.toByteArray().size).toInt()
            assertTrue(fill > 0)
            legacy = legacy.replace("LEGACY_PADDING", "x".repeat("LEGACY_PADDING".length + fill))
            graphPath.writeText(legacy)
            assertEquals(budget.maximumGraphBytes, graphPath.readBytes().size.toLong(), "source schema=$schema")
            val binding = bindingPath.readBytes()
            val installedBefore = target.readBytes()
            graphPath.writeText(legacy.replace("\"summary\":\"", "\"summary\":\"z"))
            assertFailsWith<RepairBudgetExceededException> {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget)
            }
            assertContentEquals(installedBefore, target.readBytes())
            graphPath.writeText(legacy)

            assertFailsWith<SimulatedRepairCrash> {
                ModuleRevisionGraph.openForTesting(project, GeneratedCRepairIndexProfile, budget,
                    ModuleRevisionFaultInjector { point ->
                        if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                            point.scope == "revision-state" && point.name == "graph.json") throw SimulatedRepairCrash()
                    }).close()
            }
            val marker = graphPath.readBytes()
            assertTrue(marker.size.toLong() > budget.maximumGraphBytes)
            assertContentEquals(installedBefore, target.readBytes())
            assertContentEquals(binding, bindingPath.readBytes())
            requireDeclaredGraphBudget(project, marker, budget)
            // Retained prior producers wrote every null node explicitly. Their allowance is
            // computed using that recognized wire, not the new compact serializer's byte count.
            val oldMarker = explicitNullNodeWire(marker.toString(Charsets.UTF_8)).toByteArray()
            assertTrue(oldMarker.size.toLong() > budget.maximumGraphBytes)
            requireDeclaredGraphBudget(project, oldMarker, budget)
            val compactMarker = Json.parseToJsonElement(marker.toString(Charsets.UTF_8)).toString().toByteArray()
            assertTrue(compactMarker.size.toLong() > budget.maximumGraphBytes)
            assertFailsWith<IllegalArgumentException> { requireDeclaredGraphBudget(project, compactMarker, budget) }

            // The read envelope is not admission: ordinary metadata cannot spend the reserved
            // migration bytes, and rejection still precedes any source exchange.
            graphPath.writeText(marker.toString(Charsets.UTF_8).replace("\"summary\":\"", "\"summary\":\"" + "y".repeat(2048)))
            assertFailsWith<RepairBudgetExceededException> {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget)
            }
            assertContentEquals(installedBefore, target.readBytes())
            graphPath.writeBytes(marker)
            target.writeText("unrecognized concurrent replacement")
            assertFailsWith<IllegalStateException> {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget)
            }
            assertTrue(graphPath.readText().contains("restore_failed_unresolved"))
            target.writeBytes(installedBefore)
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { recovered ->
                assertContentEquals(original, target.readBytes())
                val rollback = requireNotNull(recovered.snapshot.nodes.last().rollbackRecord)
                assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, rollback.state)
                assertTrue(rollback.legacyPendingStateUnknown)
                assertEquals(null, rollback.candidateSourceInstallStarted)
                assertEquals(RepairRollbackFailureCode.UNRECOGNIZED_SOURCE_STATE, rollback.failureCode)
            }
            assertContentEquals(binding, bindingPath.readBytes())
            requireDeclaredGraphBudget(project, graphPath.readBytes(), budget)
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).close()
        }
    }

    @Test
    fun `declared schema one two and three sources reserve successful recovery and interruption at the original cap`() {
        for (schema in 1..3) {
            val fixture = declaredBudgetFixture(schema)
            val path = fixture.project.resolve("reports/repair-revisions/graph.json")
            val binding = path.parent.resolve("recovery-binding.json").readBytes()
            ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, fixture.budget).use { graph ->
                val record = requireNotNull(graph.snapshot.nodes.last().rollbackRecord)
                assertEquals(RepairRollbackState.RESTORED_VERIFIED, record.state, "schema=$schema")
                assertTrue(record.legacyPendingStateUnknown)
                assertNull(record.candidateSourceInstallStarted)
                assertEquals(record.expectedSourceRevisionSha256, record.observedSourceRevisionSha256)
                if (schema == 3) {
                    val run = graph.snapshot.runs.single()
                    assertEquals(RepairRunStatus.INTERRUPTED, run.status)
                    assertEquals(RepairEvidence("interrupted", "repair run reopened without a completed terminal publication"), run.lastEvidence)
                    assertNull(run.rollbackFailureAttemptId)
                } else assertTrue(graph.snapshot.runs.isEmpty())
                graph.synchronizeRepairHistory()
            }
            assertContentEquals(binding, path.parent.resolve("recovery-binding.json").readBytes())
            assertContentEquals(fixture.originalSource, fixture.project.resolve("src/modules/alpha.c").readBytes())
            requireDeclaredGraphBudget(fixture.project, path.readBytes(), fixture.budget)
            val preserved = path.parent.resolve("legacy-graph-${sha256(fixture.legacy)}.json")
            assertContentEquals(fixture.legacy, preserved.readBytes())
            // This authored schema-3 pending fixture has one retained original graph. Unlike
            // a historical on-disk upgrade, it has no earlier schema-2 graph to preserve.
            if (schema == 3) assertEquals(1, Files.newDirectoryStream(path.parent, "legacy-graph-*.json").use { it.count() })
            ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, fixture.budget).close()
        }
    }

    @Test
    fun `over cap migration requires a unique joined source and charges schema two ordinary plus one growth`() {
        val fixture = declaredBudgetFixture(2)
        val root = fixture.project
        val path = root.resolve("reports/repair-revisions/graph.json")
        assertFailsWith<SimulatedRepairCrash> {
            ModuleRevisionGraph.openForTesting(root, GeneratedCRepairIndexProfile, fixture.budget,
                ModuleRevisionFaultInjector { point ->
                    if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                        point.scope == "revision-state" && point.name == "graph.json") throw SimulatedRepairCrash()
                }).close()
        }
        val marker = path.readBytes()
        assertTrue(marker.size.toLong() > fixture.budget.maximumGraphBytes)
        requireDeclaredGraphBudget(root, marker, fixture.budget) // Actual producer at charged M.
        assertFailsWith<RepairBudgetExceededException> { requireRepairGraphByteBudget(marker, fixture.budget) }
        val source = root.resolve("src/modules/alpha.c")
        val bytes = source.readBytes()
        val key = Files.readAttributes(source, BasicFileAttributes::class.java).fileKey()
        fun refuse(action: () -> Unit) {
            val graphKey = Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()
            action()
            assertContentEquals(marker, path.readBytes())
            assertContentEquals(bytes, source.readBytes())
            assertEquals(key, Files.readAttributes(source, BasicFileAttributes::class.java).fileKey())
            assertEquals(graphKey, Files.readAttributes(path, BasicFileAttributes::class.java).fileKey())
        }
        val declaredPath = path.parent.resolve("legacy-graph-${sha256(fixture.legacy)}.json")
        Files.delete(declaredPath)
        refuse { assertFailsWith<RepairBudgetExceededException> { ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, fixture.budget) } }
        declaredPath.writeBytes(fixture.legacy)
        // A canonical cross-snapshot declaration does not join even when self-hashed.
        Files.delete(declaredPath)
        val originalText = fixture.legacy.toString(Charsets.UTF_8)
        val index = Json.parseToJsonElement(originalText).jsonObject.getValue("indexSha256").jsonPrimitive.content
        val originalGraph = Json.parseToJsonElement(originalText).jsonObject
        val originalRoot = originalGraph.getValue("nodes").jsonArray.first().jsonObject
        val originalPending = originalGraph.getValue("pending").jsonObject
        val rootId = originalRoot.getValue("id").jsonPrimitive.content
        val foreignRoot = "root_${sha256(("0".repeat(64) + "\n" + originalRoot.getValue("sourceRevisionSha256").jsonPrimitive.content).toByteArray()).take(24)}"
        val ordinal = originalPending.getValue("ordinal").jsonPrimitive.content
        val allowed = originalPending.getValue("allowedPaths").jsonArray.map { it.jsonPrimitive.content }
        val foreignAttempt = "revision_${ordinal.padStart(8, '0')}_${sha256((foreignRoot + "\n" + ordinal + "\n" + allowed.joinToString("\n")).toByteArray()).take(16)}"
        val unjoined = originalText.replace("\"indexSha256\": \"$index\"", "\"indexSha256\": \"${"0".repeat(64)}\"")
            .replace(rootId, foreignRoot).replace(originalPending.getValue("id").jsonPrimitive.content, foreignAttempt).toByteArray()
        assertFalse(fixture.legacy.contentEquals(unjoined))
        rollbackPairPrivate("validateDeclaredGraphSemantics", requireNotNull(rollbackPairPrivate("parseGraph", unjoined.toString(Charsets.UTF_8))))
        val unjoinedPath = path.parent.resolve("legacy-graph-${sha256(unjoined)}.json").also { it.writeBytes(unjoined) }
        refuse { assertFailsWith<RepairBudgetExceededException> { ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, fixture.budget) } }
        Files.delete(unjoinedPath)
        declaredPath.writeBytes(fixture.legacy)
        // Both declarations can have identical semantic defaults. Never choose schema1's larger credit.
        val schemaOne = originalText.replaceFirst("\"schemaVersion\": 2", "\"schemaVersion\": 1")
            .replace(",\"agentInvocation\":null,\"publicationMode\":\"test_only_non_release\"", "").toByteArray()
        val alternative = path.parent.resolve("legacy-graph-${sha256(schemaOne)}.json").also { it.writeBytes(schemaOne) }
        refuse {
            val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, fixture.budget) }
            assertTrue(failure.message.orEmpty().contains("multiple declared legacy graphs"))
        }
        Files.delete(alternative)
        val corruptName = path.parent.resolve("legacy-graph-${"0".repeat(64)}.json")
        corruptName.writeBytes(fixture.legacy)
        refuse {
            val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, fixture.budget) }
            assertEquals("declared legacy graph digest changed", failure.message)
        }
        Files.delete(corruptName)
        val plusOne = marker.toString(Charsets.UTF_8).replace("\"summary\":\"", "\"summary\":\"z").toByteArray()
        assertEquals(marker.size + 1, plusOne.size)
        assertFailsWith<RepairBudgetExceededException> { requireDeclaredGraphBudget(root, plusOne, fixture.budget) }
        path.writeBytes(plusOne)
        val plusOneKey = Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()
        assertFailsWith<RepairBudgetExceededException> { ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, fixture.budget) }
        assertEquals(plusOneKey, Files.readAttributes(path, BasicFileAttributes::class.java).fileKey())
        assertContentEquals(plusOne, path.readBytes())
        assertContentEquals(bytes, source.readBytes())
        path.writeBytes(marker)
        ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, fixture.budget).close()
    }

    @Test
    fun `empty run context cannot turn a declared schema three source into schema two credit`() {
        // Authored budget-helper input only: old schema3 without a run is not native recovery authority.
        val fixture = declaredBudgetFixture(3, withRun = false)
        val marker = fixture.nativeGraph.toString(Charsets.UTF_8)
            .replace("\"legacyRecoveryRequired\":false", "\"legacyRecoveryRequired\":true")
            .replace("\"legacyPendingStateUnknown\":false", "\"legacyPendingStateUnknown\":true")
            .replace(Regex("\"candidateSourceInstallStarted\":(?:true|false)"),
                "\"candidateSourceInstallStarted\":null").toByteArray()
        val name = "legacy-graph-${sha256(fixture.legacy)}.json"
        assertFailsWith<RepairBudgetExceededException> {
            requireRepairGraphByteBudget(marker, fixture.budget) { consume -> consume(name, fixture.legacy) }
        }
        val plusOne = marker.toString(Charsets.UTF_8).replace("\"summary\":\"", "\"summary\":\"z").toByteArray()
        assertEquals(marker.size + 1, plusOne.size)
        assertFailsWith<RepairBudgetExceededException> {
            requireRepairGraphByteBudget(plusOne, fixture.budget) { consume -> consume(name, fixture.legacy) }
        }
    }

    @Test
    fun `declared graph store admits exact aggregate bytes and refuses all name and payload overruns`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val root = Files.createTempDirectory(parent, "declared-source-bounds-")
        LinuxFilesystemSyscalls.openRoot(root).use { descriptor ->
            RepairStateStore.open(descriptor).use { store ->
                val revisions = root.resolve("reports/repair-revisions")
                fun body(value: String): Path = revisions.resolve("legacy-graph-${sha256(value.toByteArray())}.json")
                    .also { it.writeText(value) }
                val one = body("a")
                val two = body("bc")
                val budget = RepairResourceBudget(maximumGraphBytes = 2, maximumIndexEvidenceBytes = 3)
                val seen = mutableListOf<ByteArray>()
                // Raw body-reader control only; these strings are not graph or history evidence.
                store.forEachDeclaredLegacyGraph(budget) { _, bytes -> seen += bytes }
                assertEquals(3, seen.sumOf { it.size })
                val extra = body("d")
                val failure = assertFailsWith<RepairBudgetExceededException> {
                    store.forEachDeclaredLegacyGraph(budget) { _, _ -> }
                }
                assertTrue(failure.message.orEmpty().contains("remaining evidence budget"))
                Files.delete(extra)
                val tooLarge = body("xyz")
                assertFailsWith<RepairBudgetExceededException> { store.forEachDeclaredLegacyGraph(budget) { _, _ -> } }
                Files.delete(tooLarge)
                // Every direct name counts against T, including irrelevant files and blobs directory.
                val traversal = budget.copy(maximumRevisionNodes = 2, maximumStateDirectoryEntries = 3)
                val limit = repairRevisionDirectoryEntryLimit(traversal)
                val present = Files.list(revisions).use { it.count().toInt() }
                val fillers = (0..(limit - present)).map { index ->
                    revisions.resolve("irrelevant-$index").also { it.writeText("") }
                }
                assertEquals(limit + 1L, Files.list(revisions).use { it.count() })
                assertFailsWith<decompengine.acp.LinuxResourceLimitException> {
                    store.forEachDeclaredLegacyGraph(traversal) { _, _ -> }
                }
                Files.delete(fillers.last())
                assertEquals(limit.toLong(), Files.list(revisions).use { it.count() })
                store.forEachDeclaredLegacyGraph(traversal) { _, _ -> }
                fillers.dropLast(1).forEach { Files.delete(it) }
                Files.delete(two)
                val link = revisions.resolve("legacy-graph-${"0".repeat(64)}.json")
                Files.createSymbolicLink(link, one.fileName)
                var reachedLink = false
                kotlin.test.assertFails { store.forEachDeclaredLegacyGraph(budget) { name, _ -> if (name == link.fileName.toString()) reachedLink = true } }
                assertFalse(reachedLink)
            }
        }
    }

    @Test
    fun `later native run evidence cannot enlarge a declared migration allowance`() {
        val fixture = declaredBudgetFixture(2, reserve = 8192)
        assertEquals(16L * 1024, fixture.budget.maximumGraphBytes)
        assertTrue(fixture.reservedBytes in 1L..8192L, "actual producer must leave positive ordinary-run slack")
        assertEquals(fixture.budget.maximumGraphBytes - fixture.reservedBytes, fixture.legacy.size.toLong())
        val path = fixture.project.resolve("reports/repair-revisions/graph.json")
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, fixture.budget).use { graph ->
            assertNull(graph.snapshot.pendingAttemptId)
            assertTrue(graph.snapshot.runs.isEmpty())
            requireDeclaredGraphBudget(fixture.project, path.readBytes(), fixture.budget)
            graph.beginRun(1, 60_000)
            assertEquals(RepairRunStatus.RUNNING, graph.snapshot.runs.single().status)
            val completed = graph.finishRun(RepairRunStatus.NO_CHANGES, RepairEvidence("unchanged", "bounded later native run"))
            assertEquals(RepairRunStatus.NO_CHANGES, completed.status)
            requireDeclaredGraphBudget(fixture.project, path.readBytes(), fixture.budget)
            graph.beginRun(1, 60_000)
            assertEquals(listOf(RepairRunStatus.NO_CHANGES, RepairRunStatus.RUNNING), graph.snapshot.runs.map { it.status })
            requireDeclaredGraphBudget(fixture.project, path.readBytes(), fixture.budget)
            val before = path.readBytes()
            val snapshot = graph.snapshot
            val source = fixture.project.resolve("src/modules/alpha.c")
            val sourceBytes = source.readBytes()
            val key = Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()
            assertFailsWith<RepairBudgetExceededException> {
                graph.finishRun(RepairRunStatus.INTERRUPTED, RepairEvidence("interrupted", "n".repeat(20 * 1024)))
            }
            assertEquals(snapshot, graph.snapshot)
            assertContentEquals(before, path.readBytes())
            assertEquals(key, Files.readAttributes(path, BasicFileAttributes::class.java).fileKey())
            assertContentEquals(sourceBytes, source.readBytes())
        }
    }

    @Test
    fun `archive over cap source scanning cannot skip a corrupt declaration for a later valid history`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val fixture = releaseRepairFixture(temporaryParent = parent, legacyRejectedPrefix = true)
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("declared-source-base.zip"))
        ArchivalBundleVerifier.extractAndVerify(bundle.archivePath, fixture.project.parent.resolve("declared-source-base-control"))
        val forged = fixture.project.parent.resolve("declared-source-corrupt.zip")
        rewriteArchive(bundle.archivePath, forged) { entries ->
            val graphPath = "reports/repair-revisions/graph.json"
            val text = entries.getValue(graphPath).toString(Charsets.UTF_8)
            val graph = Json.parseToJsonElement(text).jsonObject
            val oldCap = graph.getValue("budget").jsonObject.getValue("maximumGraphBytes").jsonPrimitive.content
            val cap = text.toByteArray().size - 128
            assertTrue(cap > 0)
            val changed = text.replace("\"maximumGraphBytes\":$oldCap", "\"maximumGraphBytes\":$cap")
            assertTrue(changed.toByteArray().size > cap)
            entries[graphPath] = changed.toByteArray() // Preserve the real canonical graph whitespace.
            val retained = entries.entries.single { it.key.startsWith("reports/repair-revisions/legacy-graph-") &&
                Json.parseToJsonElement(it.value.toString(Charsets.UTF_8)).jsonObject["pending"] != JsonNull }.value
            assertTrue(retained.size <= cap, "source body admission must reach its digest check")
            entries["reports/repair-revisions/legacy-graph-${"0".repeat(64)}.json"] = retained
        }
        val output = fixture.project.parent.resolve("declared-source-corrupt-refused")
        val failure = assertFailsWith<IllegalArgumentException> { ArchivalBundleVerifier.extractAndVerify(forged, output) }
        assertTrue(failure.message.orEmpty().contains("declared legacy graph digest changed"), failure.message)
        assertFalse(output.exists())
    }

    @Test
    fun `content-addressed blobs are rehashed and corruption prevents graph open`() {
        val project = generatedProject()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        val graphText = project.resolve("reports/repair-revisions/graph.json").readText()
        val digest = Regex("\\\"afterBlobSha256\\\":\\\"([0-9a-f]{64})\\\"")
            .find(graphText)?.groupValues?.get(1) ?: error("root graph did not reference a blob")
        project.resolve("reports/repair-revisions/blobs/$digest").writeText("corrupt")

        val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile) }

        assertTrue(failure.message.orEmpty().contains("blob"))
    }

    @Test
    fun `preimage mutation between head check and descriptor read cannot enter the journal`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        ModuleRevisionGraph.openLegacyForTesting(project, GeneratedCRepairIndexProfile).use { }
        val graphBytesBefore = project.resolve("reports/repair-revisions/graph.json").readBytes()
        ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePreimageRead) target.writeText("raced preimage\n")
            },
        ).use { graph ->
            val failure = assertFailsWith<IllegalArgumentException> {
                graph.beginAttempt(listOf("src/modules/alpha.c"))
            }
            assertTrue(failure.message.orEmpty().contains("preimage"))
            assertEquals(null, graph.snapshot.pendingAttemptId)
        }
        assertContentEquals(graphBytesBefore, project.resolve("reports/repair-revisions/graph.json").readBytes())
    }

    @Test
    fun `descriptor-bound preimage read cannot be redirected by a swap and restore around open`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val held = project.resolve("src/modules/alpha-held.c.repair")
        val substitute = project.resolve("src/modules/alpha-substitute.c.repair")
        val original = target.readBytes()
        val different = original.copyOf().also { bytes -> bytes[0] = (bytes[0].toInt() xor 1).toByte() }
        substitute.writeBytes(different)
        var swapped = false
        var restored = false

        ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                when (point) {
                    is ModuleRevisionFaultPoint.BeforeDescriptorBoundRead -> {
                        Files.move(target, held)
                        Files.move(substitute, target)
                        swapped = true
                    }
                    is ModuleRevisionFaultPoint.AfterDescriptorBoundRead -> {
                        Files.move(target, substitute)
                        Files.move(held, target)
                        restored = true
                    }
                    else -> Unit
                }
            },
        ).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            assertTrue(swapped && restored)
            graph.reject(attempt, RepairEvidence("test", "descriptor identity remained pinned"))
        }

        assertContentEquals(original, target.readBytes())
        assertContentEquals(different, substitute.readBytes())
    }

    @Test
    fun `accepted non-ACP repair remains explicitly non-release at the archive gate`() {
        val project = generatedProject()
        val betaPath = project.resolve("src/modules/beta.c")
        val repaired = betaPath.readText() + "\n/* accepted repair revision */\n"
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val metadata = beginSyntheticAcceptedRun(graph)
            val attempt = graph.beginAttempt(listOf("src/modules/beta.c"), metadata)
            graph.installCandidate(attempt, mapOf("src/modules/beta.c" to repaired.toByteArray()))
            graph.accept(attempt, RepairEvidence("valid", "compile and retained behavior accepted"),
                syntheticAcceptedProof(graph, attempt))
            graph.synchronizeRepairHistory()
        }

        MakeProjectBuilder.build(project)
        val archive = project.parent.resolve("repaired-project.zip")
        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(project, archive)
        }

        assertTrue(failure.message.orEmpty().contains("non-ACP repair evidence"), failure.message)
        assertTrue(project.resolve("source_tree_manifest.json").readText().contains(sha256(repaired.toByteArray())))
    }

    @Test
    fun `accepted ACP repair archives and extracts through its historical reconstruction lineage`() {
        val fixture = releaseRepairFixture()
        val archive = fixture.project.parent.resolve("repair-release.zip")

        val bundle = ArchivalPackager.create(fixture.project, archive)
        val extracted = fixture.project.parent.resolve("repair-release-extracted")
        val candidateLineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(
            bundle.archivePath,
            extracted,
        )

        assertContentEquals(fixture.after, extracted.resolve(fixture.relativePath).readBytes())
        assertTrue(extracted.resolve("reports/repair_history.json").exists())
        assertTrue(extracted.resolve(fixture.receiptPath).exists())
        val contribution = candidateLineage.source.acceptedAcpContributions.single()
        assertEquals("repair", contribution.workflow)
        assertEquals(fixture.receiptPath, contribution.receiptPath)
        assertEquals(fixture.relativePath, contribution.changes.single().path)
        assertEquals(candidateLineage.source.repairGraphHeadRevisionSha256, contribution.resultSourceRevisionSha256)
        assertEquals(
            captureBuildSourceRevision(extracted).sha256,
            candidateLineage.source.sourceRevision.sha256,
        )
        val lineageParent = fixture.project.parent.resolve("repair-lineage-index").createDirectories()
        Files.setPosixFilePermissions(
            lineageParent,
            setOf(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE,
            ),
        )
        val publishedLineage = LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(
            bundle.archivePath,
            lineageParent.resolve("candidate-acp-lineage-index-v2.json"),
        )
        assertEquals(1, publishedLineage.acceptedAcpCount)
        assertEquals(0, publishedLineage.reconstructionCount)
        assertEquals(1, publishedLineage.repairCount)
        assertEquals(candidateLineage.source.sourceRevision.sha256, publishedLineage.sourceRevisionSha256)
    }

    @Test
    fun `intent-only interrupted repair remains archivable before a later accepted repair`() {
        val fixture = releaseRepairFixture(intentOnlyRejectedPrefix = true, schema7AgentEvidence = true)
        var interruptedIntentPath = ""
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).use { graph ->
            val interrupted = graph.snapshot.nodes.drop(1).first()
            assertEquals(ModuleRevisionStatus.REJECTED, interrupted.status)
            assertNotNull(interrupted.repairMetadata?.turnIntent)
            assertNull(interrupted.repairMetadata?.agentInvocation)
            interruptedIntentPath = requireNotNull(interrupted.repairMetadata?.turnIntent?.intentPath)
            assertEquals(ModuleRevisionStatus.ACCEPTED, graph.snapshot.nodes.last().status)
        }

        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("intent-only-prefix.zip"))
        val extracted = fixture.project.parent.resolve("intent-only-prefix-extracted")
        val lineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(bundle.archivePath, extracted)
        assertContentEquals(fixture.after, extracted.resolve(fixture.relativePath).readBytes())
        assertEquals(1, lineage.source.acceptedAcpContributions.size)
        assertTrue(extracted.resolve(interruptedIntentPath).exists())
    }

    @Test
    fun `provisional assessment before graph disposition recovers as rejected and remains archivable`() {
        val fixture = releaseRepairFixture(
            provisionalAssessmentCrashPrefix = true,
            schema7AgentEvidence = true,
        )
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).use { graph ->
            val crashedAttempt = graph.snapshot.nodes.drop(1).first()
            assertEquals(ModuleRevisionStatus.REJECTED, crashedAttempt.status)
            assertTrue(crashedAttempt.recoveredAfterCrash)
            assertEquals(AcpChangePublicationEligibility.PROVISIONAL,
                decompengine.project.AcpChangeAssessment.parse(
                    fixture.project.resolve(requireNotNull(crashedAttempt.repairMetadata?.agentInvocation?.assessmentPath))
                        .readBytes(),
                ).eligibility)
            assertEquals(ModuleRevisionStatus.ACCEPTED, graph.snapshot.nodes.last().status)
        }
        val bundle = ArchivalPackager.create(
            fixture.project,
            fixture.project.parent.resolve("provisional-assessment-crash-prefix.zip"),
        )
        val extracted = fixture.project.parent.resolve("provisional-assessment-crash-prefix-extracted")
        val lineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(bundle.archivePath, extracted)
        assertContentEquals(fixture.after, extracted.resolve(fixture.relativePath).readBytes())
        assertEquals(1, lineage.source.acceptedAcpContributions.size)
    }

    @Test
    fun `accepted ACP repair of undispatched fallback clears unresolved manifest ownership`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        val manifest = SourceTreeManifestReader.read(fixture.project, GeneratedCMakeReconstructionProfile.descriptor)
        assertFalse("fn_alpha" in manifest.unresolvedImplementationIds)
        assertEquals(manifest.unresolvedImplementationIds,
            manifest.files.single { it.path == "UNRESOLVED.md" }.entityIds)
        val confidence = Json.parseToJsonElement(fixture.project.resolve("reports/confidence.json").readText()).jsonObject
        assertEquals(manifest.unresolvedImplementationIds,
            confidence.getValue("unresolvedImplementationIds").jsonArray.map { it.jsonPrimitive.content })
        val alphaRevision = confidence.getValue("modules").jsonArray.map { it.jsonObject }
            .single { it.getValue("id").jsonPrimitive.content == "alpha" }
            .getValue("revisionEvidence").jsonObject
        val alphaCheckpointPath = GeneratedCMakeReconstructionProfile.descriptor.layout
            .declaration("module-evidence").materialize(mapOf("module" to "alpha"))
        val alphaCheckpoint = Json.parseToJsonElement(fixture.project.resolve(alphaCheckpointPath).readText()).jsonObject
        assertEquals(alphaCheckpoint.getValue("sourceSha256"), alphaRevision.getValue("sourceSha256"))
        assertEquals(alphaCheckpoint.getValue("accepted"), alphaRevision.getValue("acceptedImplementation"))
        assertEquals(JsonPrimitive(false), alphaRevision.getValue("acceptedImplementation"))
        assertFalse("fn_alpha" in ArchivalProjectAuditor.audit(fixture.project).unresolvedEntityIds)
        val unresolved = fixture.project.resolve("UNRESOLVED.md").readText()
        assertFalse("| `fn_alpha` |" in unresolved)
        assertTrue("| `fn_beta` |" in unresolved)
        val confidenceTemporary = fixture.project.resolve("reports/.confidence.json.repair-atomic.tmp")
        val unresolvedTemporary = fixture.project.resolve(".UNRESOLVED.md.repair-atomic.tmp")
        confidenceTemporary.writeBytes("prior confidence evidence\n".toByteArray())
        unresolvedTemporary.writeBytes("prior unresolved evidence\n".toByteArray())
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).use { }
        assertFalse(confidenceTemporary.exists(), "reopen retained an exchanged confidence report")
        assertFalse(unresolvedTemporary.exists(), "reopen retained an exchanged unresolved report")
        val archive = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("repaired-fallback.zip"))
        val extracted = fixture.project.parent.resolve("repaired-fallback-extracted")
        val lineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(archive.archivePath, extracted)
        assertContentEquals(fixture.after, extracted.resolve(fixture.relativePath).readBytes())
        assertEquals(1, lineage.source.acceptedAcpContributions.size)
    }

    @Test
    fun `direct archive packaging rejects retained repair report preimages`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        fixture.project.resolve("reports/.confidence.json.repair-atomic.tmp")
            .writeText("stale confidence preimage")
        val archive = fixture.project.parent.resolve("retained-repair-preimages.zip")

        assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.audit(fixture.project)
        }
        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(fixture.project, archive)
        }

        assertTrue(failure.message.orEmpty().contains("retained repair atomic temporary"))
        assertFalse(archive.exists())
    }

    @Test
    fun `direct audit rejects root-level unresolved report preimage`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        fixture.project.resolve(".UNRESOLVED.md.repair-atomic.tmp")
            .writeText("stale unresolved preimage")

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.audit(fixture.project)
        }

        assertTrue(failure.message.orEmpty().contains("profile-declared atomic temporary"))
    }

    @Test
    fun `archive verification rejects a retained repair projection temporary`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        val valid = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("valid-repair.zip"))
        val tampered = fixture.project.parent.resolve("retained-repair-temp.zip")
        rewriteArchive(valid.archivePath, tampered) { entries ->
            entries[".UNRESOLVED.md.repair-atomic.tmp"] = "stale unresolved preimage".toByteArray()
        }

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalBundleVerifier.extractAndVerify(tampered, fixture.project.parent.resolve("rejected-temp-extract"))
        }

        assertTrue(failure.message.orEmpty().contains("retained repair atomic temporary"))
        assertFalse(fixture.project.parent.resolve("rejected-temp-extract").exists())
    }

    @Test
    fun `repair audit charges nonmanifest evidence against its remaining byte budget`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        val manifest = SourceTreeManifestReader.read(fixture.project, GeneratedCMakeReconstructionProfile.descriptor)
        val manifestBytes = Files.size(fixture.project.resolve("source_tree_manifest.json"))
        val manifestInputBytes = manifestBytes + manifest.files.sumOf { Files.size(fixture.project.resolve(it.path)) }
        val largestInput = maxOf(manifestBytes, manifest.files.maxOf { Files.size(fixture.project.resolve(it.path)) })
        assertFalse("fn_alpha" in ArchivalProjectAuditor.audit(fixture.project).unresolvedEntityIds)

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.audit(fixture.project, limits = ArchivalBundleLimits(
                maximumFileBytes = largestInput,
                maximumTotalBytes = manifestInputBytes,
            ))
        }
        assertTrue(failure.message.orEmpty().contains("bound"))
    }

    @Test
    fun `repair audit bounds its inventory by entries left after manifest inputs`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        val manifest = SourceTreeManifestReader.read(fixture.project, GeneratedCMakeReconstructionProfile.descriptor)
        val consumedEntries = manifest.files.size + 1

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.audit(
                fixture.project,
                limits = ArchivalBundleLimits(maximumEntries = consumedEntries),
            )
        }

        assertTrue(failure.message.orEmpty().contains("remaining entry bound"))
    }

    @Test
    fun `repair audit charges only new payload files while scanning manifest-bound reports`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val reportDeclaration = ProjectFileDeclaration(
            "ordinary-report", "reports/ordinary-{report}.validation.json",
            setOf(ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT,
        )
        val profile = ReconstructionProfile(base.schemaVersion, base.id,
            ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations + reportDeclaration),
            base.budgets, base.adapterConfiguration)
        val fixture = releaseRepairFixture(undispatchedFallback = true, profile = profile)
        assertFalse("fn_alpha" in ArchivalProjectAuditor.audit(fixture.project, profile).unresolvedEntityIds)
        val original = SourceTreeManifestReader.read(fixture.project, profile)
        val manifestBoundReports = (0 until 10).map { index ->
            val path = reportDeclaration.materialize(mapOf("report" to index.toString()))
            val bytes = "manifest-bound report $index\n".toByteArray()
            fixture.project.resolve(path).writeBytes(bytes)
            GeneratedFileEvidence(
                path = path,
                sha256 = sha256(bytes),
                generator = "test-report-fixture",
                roles = setOf(ProjectFileRole.EVIDENCE),
                contentKind = ProjectContentKind.UTF8_TEXT,
            )
        }
        val manifest = SourceTreeManifest(
            profileId = original.profileId,
            profileSha256 = original.profileSha256,
            inputSha256 = original.inputSha256,
            files = original.files + manifestBoundReports,
            unresolvedEntityIds = original.unresolvedEntityIds,
            unresolvedImplementationIds = original.unresolvedImplementationIds,
        )
        fixture.project.resolve("source_tree_manifest.json").writeText(manifest.toJson())
        val manifestPaths = manifest.files.mapTo(hashSetOf()) { it.path }
        val additionalInventoryFiles = Files.walk(fixture.project.resolve("reports")).use { stream ->
            stream.filter { path ->
                val relative = fixture.project.relativize(path).toString().replace('\\', '/')
                relative.startsWith("reports/repair-revisions/") || relative == "reports/repair_history.json" ||
                    relative.endsWith(".validation.json")
            }.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }
                .map { fixture.project.relativize(it).toString().replace('\\', '/') }
                .filter { it !in manifestPaths }
                .toList()
        }
        assertTrue(additionalInventoryFiles.isNotEmpty())

        val audit = ArchivalProjectAuditor.audit(
            fixture.project, profile,
            limits = ArchivalBundleLimits(maximumEntries = manifest.files.size + 1 + additionalInventoryFiles.size),
        )

        assertFalse("fn_alpha" in audit.unresolvedEntityIds)
        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.audit(fixture.project, profile,
                limits = ArchivalBundleLimits(maximumEntries = manifest.files.size + additionalInventoryFiles.size))
        }
        assertTrue(failure.message.orEmpty().contains("remaining entry bound"))
    }

    @Test
    fun `repair and behavior reports share one audit byte budget`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        val manifest = SourceTreeManifestReader.read(fixture.project, GeneratedCMakeReconstructionProfile.descriptor)
        val manifestPaths = manifest.files.mapTo(hashSetOf()) { it.path }
        val manifestBytes = Files.size(fixture.project.resolve("source_tree_manifest.json"))
        val manifestInputBytes = manifestBytes + manifest.files.sumOf { Files.size(fixture.project.resolve(it.path)) }
        val extraFiles = Files.walk(fixture.project.resolve("reports")).use { stream ->
            stream.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }
                .filter { path ->
                    val relative = fixture.project.relativize(path).toString().replace('\\', '/')
                    relative !in manifestPaths && (relative.startsWith("reports/repair-revisions/") ||
                        relative == "reports/repair_history.json" || relative.endsWith(".validation.json"))
                }.toList()
        }
        assertTrue(extraFiles.isNotEmpty())
        val extraBytes = extraFiles.sumOf(Files::size)
        val largestInput = maxOf(manifestBytes,
            manifest.files.maxOf { Files.size(fixture.project.resolve(it.path)) }, extraFiles.maxOf(Files::size))
        fixture.project.resolve("reports/extra.behavior.json").writeBytes("extra behavior".toByteArray())

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.audit(fixture.project, limits = ArchivalBundleLimits(
                maximumFileBytes = largestInput,
                maximumTotalBytes = manifestInputBytes + extraBytes,
            ))
        }
        assertTrue(failure.message.orEmpty().contains("remaining aggregate bound"))
    }

    @Test
    fun `repair audit rejects a historical checkpoint changed to a dispatched rejection`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        val module = profile.layout.declaration("module-implementation").moduleIdForPath(fixture.relativePath)
        val checkpointPath = profile.layout.declaration("module-evidence").materialize(mapOf("module" to module))
        val checkpoint = fixture.project.resolve(checkpointPath)
        val before = checkpoint.readBytes()
        val after = checkpoint.readText().replace(
            "pre-dispatch-context-budget-fallback", "reconstructor-return",
        ).toByteArray()
        assertFalse(before.contentEquals(after))
        checkpoint.writeBytes(after)
        val manifestPath = fixture.project.resolve("source_tree_manifest.json")
        val manifestBefore = manifestPath.readText()
        val manifestAfter = manifestBefore.replace(sha256(before), sha256(after))
        assertFalse(manifestBefore == manifestAfter)
        manifestPath.writeText(manifestAfter)

        assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.audit(fixture.project) }
    }

    @Test
    fun `repair audit authenticates header-only repair state`() {
        val fixture = releaseRepairFixture(
            undispatchedFallback = true,
            relativePath = "include/modules/alpha.h",
        )
        val manifest = SourceTreeManifestReader.read(fixture.project, GeneratedCMakeReconstructionProfile.descriptor)
        assertEquals("repair-revision", manifest.files.single { it.path == fixture.relativePath }.generator)
        val graph = fixture.project.resolve("reports/repair-revisions/graph.json")
        assertTrue(graph.exists())
        val audit = ArchivalProjectAuditor.audit(fixture.project)
        assertTrue("fn_alpha" in audit.unresolvedEntityIds)

        Files.delete(graph)
        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.audit(fixture.project)
        }
        assertTrue(failure.message.orEmpty().contains("missing repair_history.json or repair-revisions/graph.json"))
    }

    @Test
    fun `direct audit rejects a retained source manifest preimage for a header-only repair`() {
        val fixture = releaseRepairFixture(
            undispatchedFallback = true,
            relativePath = "include/modules/alpha.h",
        )
        assertTrue("fn_alpha" in ArchivalProjectAuditor.audit(fixture.project).unresolvedEntityIds)
        fixture.project.resolve(".source_tree_manifest.json.repair-atomic.tmp")
            .writeText("stale source manifest preimage")

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.audit(fixture.project)
        }

        assertTrue(failure.message.orEmpty().contains("source-manifest atomic temporary"))
    }

    @Test
    fun `repair audit rejects nonempty directories beyond its traversal depth`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        var nested = fixture.project.resolve("reports")
        repeat(40) {
            nested = nested.resolve("d")
            Files.createDirectories(nested)
        }
        Files.writeString(nested.resolve("deep-evidence.json"), "out-of-bound evidence")

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.audit(fixture.project)
        }
        assertTrue(failure.message.orEmpty().contains("depth bound"))
    }

    @Test
    fun `repair audit rejects confidence evidence cross paired with the repaired source or another checkpoint`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        assertFalse("fn_alpha" in ArchivalProjectAuditor.audit(fixture.project).unresolvedEntityIds)
        val priorAudit = fixture.project.resolve("reports/archival_audit.json").readBytes()
        val confidencePath = fixture.project.resolve("reports/confidence.json")
        val before = confidencePath.readBytes()
        val confidence = Json.parseToJsonElement(before.decodeToString()).jsonObject
        val modules = confidence.getValue("modules").jsonArray
        val alpha = modules.single { it.jsonObject.getValue("id").jsonPrimitive.content == "alpha" }.jsonObject
        val historicalSourceSha256 = alpha.getValue("revisionEvidence").jsonObject.getValue("sourceSha256")
        val checkpoint = Json.parseToJsonElement(fixture.project.resolve("reports/modules/alpha.json").readText()).jsonObject
        assertEquals(checkpoint.getValue("sourceSha256"), historicalSourceSha256)
        val repairedSourceSha256 = JsonPrimitive(sha256(fixture.after))
        val otherSourceSha256 = modules.single { it.jsonObject.getValue("id").jsonPrimitive.content == "beta" }
            .jsonObject.getValue("revisionEvidence").jsonObject.getValue("sourceSha256")
        val manifestPath = fixture.project.resolve("source_tree_manifest.json")
        val manifest = Json.parseToJsonElement(manifestPath.readText()).jsonObject
        for (wrongSourceSha256 in listOf(repairedSourceSha256, otherSourceSha256)) {
            assertFalse(historicalSourceSha256 == wrongSourceSha256)
            val changedModules = modules.map { element ->
                val module = element.jsonObject
                if (module.getValue("id").jsonPrimitive.content != "alpha") element else {
                    JsonObject(LinkedHashMap(module).apply {
                        put("revisionEvidence", JsonObject(LinkedHashMap(module.getValue("revisionEvidence").jsonObject).apply {
                            put("sourceSha256", wrongSourceSha256)
                        }))
                    })
                }
            }
            val after = JsonObject(LinkedHashMap(confidence).apply {
                put("modules", JsonArray(changedModules))
            }).toString().toByteArray()
            assertFalse(before.contentEquals(after))
            confidencePath.writeBytes(after)
            manifestPath.writeText(JsonObject(LinkedHashMap(manifest).apply {
                put("files", JsonArray(manifest.getValue("files").jsonArray.map { element ->
                    val file = element.jsonObject
                    if (file.getValue("path").jsonPrimitive.content != "reports/confidence.json") element else {
                        JsonObject(LinkedHashMap(file).apply { put("sha256", JsonPrimitive(sha256(after))) })
                    }
                }))
            }).toString())

            val failure = assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.audit(fixture.project) }
            assertTrue(failure.message.orEmpty().contains("repaired module confidence evidence"))
            assertContentEquals(priorAudit, fixture.project.resolve("reports/archival_audit.json").readBytes())
        }
    }

    @Test
    fun `mixed repaired and unresolved fallback audit rejects rehashed confidence claims`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        val audit = ArchivalProjectAuditor.audit(fixture.project)
        assertFalse("fn_alpha" in audit.unresolvedEntityIds)
        assertTrue("fn_beta" in audit.unresolvedEntityIds)
        val confidencePath = fixture.project.resolve("reports/confidence.json")
        val original = Json.parseToJsonElement(confidencePath.readText()).jsonObject
        val manifestPath = fixture.project.resolve("source_tree_manifest.json")
        val manifest = Json.parseToJsonElement(manifestPath.readText()).jsonObject
        fun changeFallbackRevision(change: (MutableMap<String, JsonElement>) -> Unit): JsonObject =
            JsonObject(LinkedHashMap(original).apply {
                put("modules", JsonArray(original.getValue("modules").jsonArray.map { item ->
                    val module = item.jsonObject
                    if (module.getValue("id").jsonPrimitive.content != "beta") item else {
                        val revision = LinkedHashMap(module.getValue("revisionEvidence").jsonObject)
                        assertEquals(JsonPrimitive(false), revision.getValue("acceptedImplementation"))
                        change(revision)
                        JsonObject(LinkedHashMap(module).apply { put("revisionEvidence", JsonObject(revision)) })
                    }
                }))
            })
        val mutations = listOf(
            "confidence unresolvedImplementationIds differs" to JsonObject(LinkedHashMap(original).apply {
                put("unresolvedImplementationIds", JsonArray(emptyList()))
            }),
            "fallback module confidence evidence differs" to changeFallbackRevision { revision ->
                revision["acceptedImplementation"] = JsonPrimitive(true)
            },
            "fallback module confidence evidence overstates" to changeFallbackRevision { revision ->
                revision["behavior"] = JsonObject(LinkedHashMap(revision.getValue("behavior").jsonObject).apply {
                    put("status", JsonPrimitive("measured"))
                })
            },
        )
        for ((expectedFailure, changed) in mutations) {
            val changedBytes = (changed.toString() + "\n").toByteArray(Charsets.UTF_8)
            confidencePath.writeBytes(changedBytes)
            val changedManifest = JsonObject(LinkedHashMap(manifest).apply {
                put("files", JsonArray(manifest.getValue("files").jsonArray.map { item ->
                    val file = item.jsonObject
                    if (file.getValue("path").jsonPrimitive.content != "reports/confidence.json") item else {
                        JsonObject(LinkedHashMap(file).apply { put("sha256", JsonPrimitive(sha256(changedBytes))) })
                    }
                }))
            })
            manifestPath.writeText(changedManifest.toString() + "\n")
            val failure = assertFailsWith<IllegalArgumentException> {
                ArchivalProjectAuditor.audit(fixture.project)
            }
            assertTrue(failure.message.orEmpty().contains(expectedFailure),
                "unexpected mixed fallback rejection: ${failure.message}")
        }
    }

    @Test
    fun `repair projection refuses a modified report without its manifest preimage`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        val confidence = fixture.project.resolve("reports/confidence.json")
        confidence.writeText(confidence.readText().replace(
            "structural recovery heuristic; not implementation acceptance or measured behavioral confidence",
            "forged confidence claim",
        ))
        val manifestBefore = fixture.project.resolve("source_tree_manifest.json").readBytes()

        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).use { }
        assertContentEquals(manifestBefore, fixture.project.resolve("source_tree_manifest.json").readBytes())
        assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.audit(fixture.project) }
    }

    @Test
    fun `repair projection recovers a durable report exchange from manifest preimages`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        val finalManifest = fixture.project.resolve("source_tree_manifest.json").readBytes()
        val finalConfidence = fixture.project.resolve("reports/confidence.json").readBytes()
        val finalUnresolved = fixture.project.resolve("UNRESOLVED.md").readBytes()
        fixture.project.resolve("source_tree_manifest.json").writeBytes(fixture.beforeManifest)
        val confidenceTemporary = fixture.project.resolve("reports/.confidence.json.repair-atomic.tmp")
        val unresolvedTemporary = fixture.project.resolve(".UNRESOLVED.md.repair-atomic.tmp")
        confidenceTemporary.writeBytes(fixture.beforeConfidence)
        unresolvedTemporary.writeBytes(fixture.beforeUnresolved)

        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).use { }

        assertContentEquals(finalManifest, fixture.project.resolve("source_tree_manifest.json").readBytes())
        assertContentEquals(finalConfidence, fixture.project.resolve("reports/confidence.json").readBytes())
        assertContentEquals(finalUnresolved, fixture.project.resolve("UNRESOLVED.md").readBytes())
        assertFalse(confidenceTemporary.exists())
        assertFalse(unresolvedTemporary.exists())
    }

    @Test
    fun `repair projection requires the manifest bound module plan`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        val plan = fixture.project.resolve("reports/module_plan.json")
        plan.writeText(plan.readText() + " ")
        val manifestBefore = fixture.project.resolve("source_tree_manifest.json").readBytes()
        val unresolvedBefore = fixture.project.resolve("UNRESOLVED.md").readBytes()

        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).use { }
        assertContentEquals(manifestBefore, fixture.project.resolve("source_tree_manifest.json").readBytes())
        assertContentEquals(unresolvedBefore, fixture.project.resolve("UNRESOLVED.md").readBytes())
        assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.audit(fixture.project) }
    }

    @Test
    fun `accepted header repair does not resolve an undispatched implementation fallback`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true, relativePath = "include/modules/alpha.h")
        val manifest = SourceTreeManifestReader.read(fixture.project, GeneratedCMakeReconstructionProfile.descriptor)
        assertTrue("fn_alpha" in manifest.unresolvedImplementationIds)
        assertEquals(null, manifest.files.single { it.path == fixture.relativePath }.acceptedImplementation)
        assertTrue("| `fn_alpha` |" in fixture.project.resolve("UNRESOLVED.md").readText())
    }

    @Test
    fun `direct audit authenticates header-only repair lineage`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true, relativePath = "include/modules/alpha.h")
        val receipt = fixture.project.resolve(fixture.receiptPath)
        receipt.writeBytes(receipt.readBytes() + "tampered".toByteArray())

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.audit(fixture.project)
        }

        assertTrue(failure.message.orEmpty().contains("receipt"))
    }

    @Test
    fun `custom repair synchronizes source manifest without assuming relocated report semantics`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val relocated = mapOf(
            "confidence-evidence" to "reports/assessment/confidence.validation.json",
            "unresolved-evidence" to "reports/assessment/unresolved.md",
            "module-plan-evidence" to "reports/planning/modules.json",
        )
        val layout = ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map { declaration ->
            ProjectFileDeclaration(declaration.id, relocated[declaration.id] ?: declaration.pathTemplate,
                declaration.roles, declaration.contentKind)
        })
        val reconstruction = ReconstructionProfile(base.schemaVersion, base.id, layout, base.budgets, base.adapterConfiguration)
        val parent = Path.of("build", "custom-repair-manifest-fixtures").toAbsolutePath().createDirectories()
        val directory = Files.createTempDirectory(parent, "case-")
        val input = directory.resolve("reference.fixture").apply { writeText("reference") }
        val projectRoot = directory.resolve("published")
        try {
            generatePublishedProject(
                projectRoot,
                input,
                RecoveredProgramModel(inputSha256 = sha256(input.readBytes()), functions = listOf(
                    RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)",
                        decompiledC = "/* ${"context".repeat(900)} */"),
                )),
                BoundedLlmModuleReconstructor(
                    AgentHarness { _, _ -> error("pre-dispatch fixture must not execute") }, maximumContextCharacters = 4096,
                ),
                profile = reconstruction,
            )
            val project = projectRoot.resolve("source-tree")
            val generatedPolicy = GeneratedCRepairIndexProfile.forProfile(reconstruction)
            val customRepairIndexProfile = object : RepairIndexProfile by generatedPolicy {
                override fun reconstructionProfile(): ReconstructionProfile? = null
            }
            assertEquals(null, customRepairIndexProfile.reconstructionProfile())
            val relative = "src/modules/alpha.c"
            val source = project.resolve(relative)
            val candidate = source.readBytes() + "\n/* accepted custom-profile repair */\n".toByteArray()
            val manifestPath = project.resolve("source_tree_manifest.json")
            val originalManifest = manifestPath.readBytes()
            val before = SourceTreeManifestReader.read(project, reconstruction)
            assertTrue("fn_alpha" in before.unresolvedImplementationIds)
            assertEquals(false, before.files.single { it.path == relative }.acceptedImplementation)
            val reportBytes = relocated.values.associateWith { project.resolve(it).readBytes() }
            val unownedTemporaries = listOf("reports/.confidence.json.repair-atomic.tmp", ".UNRESOLVED.md.repair-atomic.tmp")
                .associateWith { "custom-owned temporary: $it\n".toByteArray() }
            unownedTemporaries.forEach { (path, bytes) -> project.resolve(path).writeBytes(bytes) }

            fun assertSourcePublication(acceptedId: String) {
                val manifest = SourceTreeManifestReader.read(project, reconstruction)
                val updated = manifest.files.single { it.path == relative }
                assertEquals(sha256(candidate), updated.sha256)
                assertEquals("repair-revision", updated.generator)
                assertEquals(sha256("revision:$acceptedId".toByteArray(Charsets.UTF_8)), updated.promptSha256)
                assertEquals(true, updated.acceptedImplementation)
                assertFalse("fn_alpha" in manifest.unresolvedImplementationIds)
                assertContentEquals(candidate, source.readBytes())
                reportBytes.forEach { (path, bytes) ->
                    assertContentEquals(bytes, project.resolve(path).readBytes())
                    assertEquals(before.files.single { it.path == path }.sha256, manifest.files.single { it.path == path }.sha256)
                }
                unownedTemporaries.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes()) }
                assertFalse(project.resolve("reports/confidence.json").exists())
                assertFalse(project.resolve("UNRESOLVED.md").exists())
            }

            val acceptedId = ModuleRevisionGraph.open(project, customRepairIndexProfile).use { graph ->
                val metadata = beginSyntheticAcceptedRun(graph)
                val attempt = graph.beginAttempt(listOf(relative), metadata)
                graph.installCandidate(attempt, mapOf(relative to candidate))
                val accepted = graph.accept(attempt, RepairEvidence("valid", "custom-profile candidate accepted"),
                    syntheticAcceptedProof(graph, attempt))
                assertEquals(ModuleRevisionStatus.ACCEPTED, accepted.status)
                assertEquals(accepted.id, graph.snapshot.headId)
                assertSourcePublication(accepted.id)
                accepted.id
            }
            val publishedManifest = manifestPath.readBytes()
            // A durable accepted head can be reopened before its derived source manifest was written.
            manifestPath.writeBytes(originalManifest)
            ModuleRevisionGraph.open(project, customRepairIndexProfile).use { reopened ->
                assertEquals(acceptedId, reopened.snapshot.headId)
                assertSourcePublication(acceptedId)
            }
            assertContentEquals(publishedManifest, manifestPath.readBytes())
            ModuleRevisionGraph.open(project, customRepairIndexProfile).use { }
            assertContentEquals(publishedManifest, manifestPath.readBytes())
            assertSourcePublication(acceptedId)
        } finally {
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun `publication projection synchronization refuses an unreadable source manifest`() {
        val fixture = releaseRepairFixture(undispatchedFallback = true)
        val manifest = fixture.project.resolve("source_tree_manifest.json")
        val original = manifest.readBytes()

        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).use { graph ->
            manifest.writeText("{ malformed source manifest")
            assertFailsWith<IllegalArgumentException> { graph.synchronizePublicationProjections() }
            manifest.writeBytes(original)
            graph.synchronizePublicationProjections()
        }

        assertContentEquals(original, manifest.readBytes())
        ArchivalProjectAuditor.audit(fixture.project)
    }

    @Test
    fun `accepted fallback repair synchronizes relocated reports`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val relocated = mapOf(
            "confidence-evidence" to "reports/assessment/confidence.validation.json",
            "unresolved-evidence" to "reports/assessment/unresolved.md",
            "module-plan-evidence" to "reports/planning/modules.json",
        )
        val layout = ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map { declaration ->
            ProjectFileDeclaration(declaration.id, relocated[declaration.id] ?: declaration.pathTemplate,
                declaration.roles, declaration.contentKind)
        })
        val profile = ReconstructionProfile(base.schemaVersion, base.id, layout, base.budgets, base.adapterConfiguration)
        val fixture = releaseRepairFixture(undispatchedFallback = true, profile = profile)
        val manifest = SourceTreeManifestReader.read(fixture.project, profile)
        assertFalse("fn_alpha" in manifest.unresolvedImplementationIds)
        assertFalse("fn_alpha" in ArchivalProjectAuditor.audit(fixture.project, profile).unresolvedEntityIds)
        assertFalse("| `fn_alpha` |" in fixture.project.resolve(relocated.getValue("unresolved-evidence")).readText())
        val confidenceTemporary = fixture.project.resolve("reports/assessment/.confidence.validation.json.repair-atomic.tmp")
        val unresolvedTemporary = fixture.project.resolve("reports/assessment/.unresolved.md.repair-atomic.tmp")
        confidenceTemporary.writeBytes("prior confidence evidence\n".toByteArray())
        unresolvedTemporary.writeBytes("prior unresolved evidence\n".toByteArray())
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile.forProfile(profile)).use { }
        assertFalse(confidenceTemporary.exists())
        assertFalse(unresolvedTemporary.exists())
        val retainedProjection = fixture.project.resolve("reports/assessment/.unresolved.md.repair-atomic.tmp")
        retainedProjection.writeText("stale relocated unresolved preimage")
        val auditFailure = assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.audit(fixture.project, profile)
        }
        assertTrue(auditFailure.message.orEmpty().contains("profile-declared atomic temporary"))
        Files.delete(retainedProjection)
        val archive = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("relocated-fallback.zip"),
            profile = profile)
        ArchivalBundleVerifier.extractAndVerify(archive.archivePath,
            fixture.project.parent.resolve("relocated-fallback-extracted"), profile = profile)
    }

    @Test
    fun `accepted repair recovers projections with maximum byte length report names`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val confidenceName = "c".repeat(250) + ".json"
        val unresolvedName = "é".repeat(126) + ".md"
        assertEquals(255, confidenceName.toByteArray(Charsets.UTF_8).size)
        assertEquals(255, unresolvedName.toByteArray(Charsets.UTF_8).size)
        val relocated = mapOf(
            "confidence-evidence" to "reports/assessment/$confidenceName",
            "unresolved-evidence" to unresolvedName,
        )
        val layout = ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map { declaration ->
            ProjectFileDeclaration(declaration.id, relocated[declaration.id] ?: declaration.pathTemplate,
                declaration.roles, declaration.contentKind)
        })
        val profile = ReconstructionProfile(base.schemaVersion, base.id, layout, base.budgets, base.adapterConfiguration)
        val fixture = releaseRepairFixture(undispatchedFallback = true, profile = profile)
        val confidence = fixture.project.resolve(relocated.getValue("confidence-evidence"))
        val unresolved = fixture.project.resolve(relocated.getValue("unresolved-evidence"))
        val manifestPath = fixture.project.resolve("source_tree_manifest.json")
        val finalManifest = manifestPath.readBytes()
        val finalConfidence = confidence.readBytes()
        val finalUnresolved = unresolved.readBytes()
        assertFalse("fn_alpha" in SourceTreeManifestReader.read(fixture.project, profile).unresolvedImplementationIds)
        assertFalse("fn_alpha" in ArchivalProjectAuditor.audit(fixture.project, profile).unresolvedEntityIds)

        // Recreate a crash after both report exchanges but before the manifest commit. The
        // hashed siblings retain exactly the manifest-bound preimages needed by reopen.
        val confidenceTemporary = confidence.resolveSibling(repairAtomicTemporaryName(confidenceName))
        val unresolvedTemporary = unresolved.resolveSibling(repairAtomicTemporaryName(unresolvedName))
        for (temporary in listOf(confidenceTemporary, unresolvedTemporary)) {
            assertTrue(temporary.fileName.toString().toByteArray(Charsets.UTF_8).size <= 255)
            assertTrue(decompengine.project.isRepairAtomicTemporary(temporary))
        }
        manifestPath.writeBytes(fixture.beforeManifest)
        confidenceTemporary.writeBytes(fixture.beforeConfidence)
        unresolvedTemporary.writeBytes(fixture.beforeUnresolved)
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile.forProfile(profile)).use { }
        assertContentEquals(finalManifest, manifestPath.readBytes())
        assertContentEquals(finalConfidence, confidence.readBytes())
        assertContentEquals(finalUnresolved, unresolved.readBytes())
        assertFalse(confidenceTemporary.exists())
        assertFalse(unresolvedTemporary.exists())

        // Root-level hashed preimages must be rejected by the exact profile-path check too.
        unresolvedTemporary.writeBytes(fixture.beforeUnresolved)
        val auditFailure = assertFailsWith<IllegalArgumentException> {
            ArchivalProjectAuditor.audit(fixture.project, profile)
        }
        assertTrue(auditFailure.message.orEmpty().contains("profile-declared atomic temporary"))
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile.forProfile(profile)).use { }
        assertFalse(unresolvedTemporary.exists())
        assertFalse("fn_alpha" in ArchivalProjectAuditor.audit(fixture.project, profile).unresolvedEntityIds)

        val valid = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("long-reports.zip"),
            profile = profile)
        val tampered = fixture.project.parent.resolve("long-reports-retained-temp.zip")
        rewriteArchive(valid.archivePath, tampered) { entries ->
            entries[unresolvedTemporary.fileName.toString()] = fixture.beforeUnresolved
        }
        val extracted = fixture.project.parent.resolve("long-reports-rejected-temp")
        val archiveFailure = assertFailsWith<IllegalArgumentException> {
            ArchivalBundleVerifier.extractAndVerify(tampered, extracted, profile = profile)
        }
        assertTrue(archiveFailure.message.orEmpty().contains("retained repair atomic temporary"))
        assertFalse(extracted.exists())
    }

    @Test
    fun `compact and old explicit null node wires remain readable with raw archive identity`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val fixture = releaseRepairFixture(temporaryParent = parent)
        val graphPath = fixture.project.resolve("reports/repair-revisions/graph.json")
        val compact = graphPath.readText()
        val explicit = explicitNullNodeWire(compact)
        assertNotEquals(compact, explicit)
        assertEquals(JsonNull, Json.parseToJsonElement(explicit).jsonObject.getValue("nodes")
            .jsonArray.first().jsonObject.getValue("rollbackRecord")) // Prior producer compatibility.
        for ((name, wire) in listOf("compact" to compact, "explicit" to explicit)) {
            graphPath.writeText(wire)
            ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).use { graph ->
                assertEquals(6, graph.snapshot.schemaVersion)
                assertEquals(RepairRunStatus.FULLY_ACCEPTED, graph.snapshot.runs.last().status)
            }
            assertEquals(wire, graphPath.readText()) // Admission does not normalize/hash other bytes.
            val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("$name-wire.zip"))
            val extracted = fixture.project.parent.resolve("$name-wire-extracted")
            ArchivalBundleVerifier.extractAndVerify(bundle.archivePath, extracted)
            assertContentEquals(wire.toByteArray(), extracted.resolve("reports/repair-revisions/graph.json").readBytes())
            assertContentEquals(fixture.after, extracted.resolve(fixture.relativePath).readBytes())
        }
        graphPath.writeText(compact)
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("archive-whitespace-base.zip"))
        val minified = fixture.project.parent.resolve("archive-whitespace-minified.zip")
        rewriteArchive(bundle.archivePath, minified) { entries ->
            entries["reports/repair-revisions/graph.json"] = Json.parseToJsonElement(compact).toString().toByteArray()
        }
        val extracted = fixture.project.parent.resolve("archive-whitespace-extracted")
        ArchivalBundleVerifier.extractAndVerify(minified, extracted) // Existing under-cap archive formatting contract.
        assertContentEquals(fixture.after, extracted.resolve(fixture.relativePath).readBytes())
    }

    @Test
    fun `mixed null node styles unknown malformed and duplicate fields refuse before source changes`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val fixture = releaseRepairFixture(temporaryParent = parent)
        val graphPath = fixture.project.resolve("reports/repair-revisions/graph.json")
        val compact = graphPath.readText()
        val anchor = "      \"recoveredAfterCrash\": "
        val nullLine = "      \"rollbackRecord\": null,\n"
        assertTrue(compact.indexOf(anchor) != compact.lastIndexOf(anchor)) // Two null nodes, so a mixture is real.
        val forgeries = listOf(
            compact.replaceFirst(anchor, nullLine + anchor),
            compact.replaceFirst(anchor, "      \"unexpected\": true,\n" + anchor),
            compact.replaceFirst(anchor, "      \"rollbackRecord\": 0,\n" + anchor),
            compact.replaceFirst(anchor, nullLine + nullLine + anchor),
        )
        val source = fixture.project.resolve(fixture.relativePath)
        val originalSource = source.readBytes()
        val key = Files.readAttributes(source, BasicFileAttributes::class.java).fileKey()
        val valid = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("null-style-valid.zip"))
        for ((number, forged) in forgeries.withIndex()) {
            graphPath.writeText(forged)
            val graphKey = Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey()
            assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).close() }
            assertEquals(forged, graphPath.readText())
            assertEquals(graphKey, Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey())
            assertContentEquals(originalSource, source.readBytes())
            assertEquals(key, Files.readAttributes(source, BasicFileAttributes::class.java).fileKey())
            val archive = fixture.project.parent.resolve("null-style-forged-$number.zip")
            rewriteArchive(valid.archivePath, archive) { entries ->
                entries["reports/repair-revisions/graph.json"] = forged.toByteArray()
            }
            val destination = fixture.project.parent.resolve("null-style-refused-$number")
            assertFailsWith<IllegalArgumentException> { ArchivalBundleVerifier.extractAndVerify(archive, destination) }
            assertFalse(destination.exists())
        }
        graphPath.writeText(" \n$compact")
        assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).close() }
        graphPath.writeText(compact)
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).close()
    }

    @Test
    fun `nonpending schema three at exact graph cap refuses upgrade without changing legacy bytes`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val budget = RepairResourceBudget(maximumGraphBytes = 32L * 1024)
        val fixture = releaseRepairFixture(temporaryParent = parent, budget = budget)
        val graphPath = fixture.project.resolve("reports/repair-revisions/graph.json")
        val bindingPath = graphPath.parent.resolve("recovery-binding.json")
        val binding = bindingPath.readBytes()
        val sourcePath = fixture.project.resolve(fixture.relativePath)
        val source = sourcePath.readBytes()
        val compact = graphPath.readText()
        val legacy = authoredLegacyGraphFixture(compact, 3)
        assertEquals(JsonPrimitive(3), Json.parseToJsonElement(legacy).jsonObject.getValue("schemaVersion"))
        val summary = "synthetic archive fixture observations matched"
        val summaryField = "      \"evidenceSummary\": \"$summary\","
        assertEquals(1, Regex(Regex.escape(summaryField)).findAll(legacy).count())
        val padding = (budget.maximumGraphBytes - legacy.toByteArray().size).toInt()
        assertTrue(padding > 0)
        val paddedSummary = summary + "p".repeat(padding)
        val paddedSummaryField = "      \"evidenceSummary\": \"$paddedSummary\","
        val saturated = legacy.replace(summaryField, paddedSummaryField)
        assertEquals(budget.maximumGraphBytes, saturated.toByteArray().size.toLong())
        graphPath.writeText(saturated)
        val artifacts = Files.list(graphPath.parent).use { files -> files.map { it.fileName.toString() }.sorted().toList() }
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, budget).use { graph ->
            assertEquals(3, graph.snapshot.schemaVersion)
            assertFailsWith<RepairBudgetExceededException> { graph.enableRunContract() }
            assertEquals(3, graph.snapshot.schemaVersion)
        }
        assertContentEquals(saturated.toByteArray(), graphPath.readBytes())
        val preservedName = "legacy-graph-${sha256(saturated.toByteArray())}.json"
        assertContentEquals(saturated.toByteArray(), graphPath.parent.resolve(preservedName).readBytes())
        assertEquals((artifacts + preservedName).sorted(), Files.list(graphPath.parent).use { files ->
            files.map { it.fileName.toString() }.sorted().toList() })
        assertContentEquals(binding, bindingPath.readBytes())
        assertContentEquals(source, sourcePath.readBytes())
        assertEquals(1, Regex(Regex.escape(paddedSummaryField)).findAll(saturated).count())
        val plusOne = saturated.replace(paddedSummaryField, paddedSummaryField.replace(paddedSummary, paddedSummary + "q"))
        assertEquals(budget.maximumGraphBytes + 1, plusOne.toByteArray().size.toLong())
        assertFailsWith<RepairBudgetExceededException> { requireRepairGraphByteBudget(plusOne.toByteArray(), budget) }
        graphPath.writeText(plusOne)
        val key = Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey()
        assertFailsWith<RepairBudgetExceededException> { ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, budget).close() }
        assertEquals(plusOne, graphPath.readText())
        assertEquals(key, Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey())
        assertContentEquals(source, sourcePath.readBytes())
        graphPath.writeText(saturated)
        assertContentEquals(saturated.toByteArray(), graphPath.readBytes())
    }

    /** Exact prior node wire; leave nonnull records and every other byte untouched. */
    private fun explicitNullNodeWire(compact: String): String = compact.replace(
        Regex("(?m)(      \"validationProof\": [^\n]*,\n)(      \"recoveredAfterCrash\": )"),
    ) { match -> match.groupValues[1] + "      \"rollbackRecord\": null,\n" + match.groupValues[2] }

    @Test
    fun `archive requires native and recovered pending rollback records with either null encoding`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        for (legacyPending in listOf(false, true)) {
            val fixture = releaseRepairFixture(temporaryParent = parent,
                rejectedAttempts = if (legacyPending) 0 else 1, legacyRejectedPrefix = legacyPending)
            val valid = ArchivalPackager.create(fixture.project,
                fixture.project.parent.resolve("required-record-$legacyPending.zip"))
            ArchivalBundleVerifier.extractAndVerify(valid.archivePath,
                fixture.project.parent.resolve("required-record-$legacyPending-control"))
            for (explicitNull in listOf(false, true)) {
                val tampered = fixture.project.parent.resolve("missing-record-$legacyPending-$explicitNull.zip")
                rewriteArchive(valid.archivePath, tampered) { entries ->
                    val path = "reports/repair-revisions/graph.json"
                    val graph = Json.parseToJsonElement(entries.getValue(path).decodeToString()).jsonObject
                    assertEquals(JsonPrimitive(if (legacyPending) 5 else 6), graph.getValue("schemaVersion"))
                    val rejected = graph.getValue("nodes").jsonArray.single {
                        it.jsonObject.getValue("status").jsonPrimitive.content == "rejected" }.jsonObject
                    assertTrue(rejected.getValue("rollbackRecord") is JsonObject)
                    val nodes = graph.getValue("nodes").jsonArray.map { element ->
                        val node = element.jsonObject
                        val stripped = if (node.getValue("id") == rejected.getValue("id")) node - "rollbackRecord" else node
                        if (explicitNull && (stripped["rollbackRecord"] == null || stripped["rollbackRecord"] is JsonNull))
                            JsonObject(stripped + ("rollbackRecord" to JsonNull)) else JsonObject(stripped)
                    }
                    entries[path] = JsonObject(graph + ("nodes" to JsonArray(nodes))).toString().toByteArray()
                    // ACP receipts, blobs, validation receipts and history remain complete and unchanged.
                }
                val output = fixture.project.parent.resolve("missing-record-$legacyPending-$explicitNull-refused")
                val failure = assertFailsWith<IllegalArgumentException> { ArchivalBundleVerifier.extractAndVerify(tampered, output) }
                assertTrue(failure.message.orEmpty().contains("lacks a finalized rollback record"), failure.message)
                assertFalse(output.exists())
            }
        }
    }

    @Test
    fun `archive cannot erase a prior rollback failure by deleting its record and downgrading both run copies`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val fixture = releaseRepairFixture(temporaryParent = parent, recoveredRollbackPrefix = true)
        val valid = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("failure-record-present.zip"))
        ArchivalBundleVerifier.extractAndVerify(valid.archivePath, fixture.project.parent.resolve("failure-record-present-control"))
        for (mode in listOf("plain", "fabricated-legacy", "graph-schema-three")) {
            val tampered = fixture.project.parent.resolve("failure-record-erased-$mode.zip")
            rewriteArchive(valid.archivePath, tampered) { entries ->
                val path = "reports/repair-revisions/graph.json"
                val graph = Json.parseToJsonElement(entries.getValue(path).decodeToString()).jsonObject
                val failed = graph.getValue("nodes").jsonArray.single { element ->
                    element.jsonObject["rollbackRecord"]?.takeUnless { it is JsonNull }?.jsonObject
                        ?.get("failureCode")?.let { it !is JsonNull } == true }.jsonObject
                val record = failed.getValue("rollbackRecord").jsonObject
                assertEquals("restored_after_failure", record.getValue("state").jsonPrimitive.content)
                val owner = record.getValue("runId")
                val nodes = graph.getValue("nodes").jsonArray.map { element ->
                    val node = element.jsonObject
                    if (node.getValue("id") == failed.getValue("id")) JsonObject(node - "rollbackRecord") else node
                }
                entries[path] = JsonObject(graph + ("nodes" to JsonArray(nodes))).toString().toByteArray()
                for (documentPath in listOf(path, "reports/repair_history.json")) {
                    val document = Json.parseToJsonElement(entries.getValue(documentPath).decodeToString()).jsonObject
                    var rewritten = 0
                    val runs = document.getValue("runs").jsonArray.map { element ->
                        val run = element.jsonObject
                        if (run.getValue("id") != owner) run else {
                            rewritten++
                            assertEquals("rollback_failed", run.getValue("status").jsonPrimitive.content)
                            JsonObject((run - setOf("rollbackFailureAttemptId", "rollbackResolution")) + mapOf(
                                "schemaVersion" to JsonPrimitive(1), "status" to JsonPrimitive("validation_failed")))
                        }
                    }
                    assertEquals(1, rewritten)
                    entries[documentPath] = JsonObject(document + ("runs" to JsonArray(runs))).toString().toByteArray()
                }
                if (mode != "plain") {
                    val stripped = Json.parseToJsonElement(entries.getValue(path).decodeToString()).jsonObject
                    val declared = authoredLegacyGraphFixture(stripped.toString(), 3).toByteArray()
                    if (mode == "fabricated-legacy") {
                        // Same resealed context/nodes/runs/proofs/blobs: a correct hash is not a
                        // pre-migration commitment and must not exempt the missing failure record.
                        entries["reports/repair-revisions/legacy-graph-${sha256(declared)}.json"] = declared
                    } else {
                        assertEquals("graph-schema-three", mode)
                        entries[path] = declared // Downgrade every node, not merely the failed one.
                    }
                }
            }
            val output = fixture.project.parent.resolve("failure-record-erased-$mode-refused")
            val failure = assertFailsWith<IllegalArgumentException> { ArchivalBundleVerifier.extractAndVerify(tampered, output) }
            assertTrue(
                failure.message.orEmpty().contains("lacks a finalized rollback record") ||
                    failure.message.orEmpty().contains("physical publication plan") ||
                    failure.message.orEmpty().contains("missing, extra, or duplicate fields"),
                failure.message,
            )
            assertFalse(output.exists())
        }
    }

    @Test
    fun `archive local schema three declarations never exempt missing finalized rollback records`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val budget = RepairResourceBudget(maximumGraphBytes = 64L * 1024)
        val fixture = releaseRepairFixture(temporaryParent = parent, rejectedAttempts = 1, budget = budget)
        val graphPath = fixture.project.resolve("reports/repair-revisions/graph.json")
        val current = graphPath.readText()
        // AUTHORED historical wire compatibility input, not a claim that an old native writer ran.
        // Retain this declared schema3 document before asking the real runtime to upgrade it.
        val authored = authoredLegacyGraphFixture(current, 3)
        assertNotEquals(current, authored)
        val origin = Json.parseToJsonElement(authored).jsonObject
        assertEquals(JsonPrimitive(3), origin.getValue("schemaVersion"))
        assertEquals(JsonNull, origin.getValue("pending"))
        assertTrue(origin.getValue("nodes").jsonArray.all { "rollbackRecord" !in it.jsonObject })
        graphPath.writeText(authored)
        val legacyFailure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("authored-schema-three-refused.zip"))
        }
        assertTrue(legacyFailure.message.orEmpty().contains("lacks a finalized rollback record"), legacyFailure.message)
        val originName = "legacy-graph-${sha256(authored.toByteArray())}.json"
        graphPath.parent.resolve(originName).writeText(authored)
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, budget).use { graph ->
            graph.enableRunContract()
            graph.synchronizeRepairHistory()
            assertEquals(5, graph.snapshot.schemaVersion)
            assertNull(graph.snapshot.nodes.single { it.status == ModuleRevisionStatus.REJECTED }.rollbackRecord)
        }
        assertContentEquals(fixture.after, fixture.project.resolve(fixture.relativePath).readBytes())
        val upgradedFailure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("authored-origin-upgraded-refused.zip"))
        }
        assertTrue(upgradedFailure.message.orEmpty().contains("lacks a finalized rollback record"), upgradedFailure.message)

        // Local compatibility reading/recovery is supported, but adding genuine current-writer
        // attempts cannot supply the missing finalized outcome for an earlier rejected attempt.
        val appended = fixture.after + "\n/* later native origin control */\n".toByteArray()
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, budget).use { graph ->
            val corpus = graph.retainedRegressionCorpus()
            val iteration = requireNotNull(graph.snapshot.nodes.last().repairMetadata).iterationIndex + 1
            graph.beginRun(2, 60_000)
            fun attempt(index: Int): ModuleRevisionAttempt {
                val value = graph.beginAttempt(listOf(fixture.relativePath), RevisionRepairMetadata(
                    index, "compile", "bounded failure", null, corpus.inputs.map(ProcessInput::id), null, corpus.sha256))
                graph.persistAndBindAgentInvocation(value, completeAcpReceiptDocument(
                    fixture.project, value, fixture.relativePath, fixture.after, appended))
                graph.installCandidate(value, mapOf(fixture.relativePath to appended))
                return value
            }
            val rejected = graph.reject(attempt(iteration), RepairEvidence("rejected", "later native rejection"))
            assertEquals(false, requireNotNull(rejected.rollbackRecord).legacyPendingStateUnknown)
            val accepted = attempt(iteration + 1)
            val proof = archiveValidationProofFixture(graph, accepted, fixture.project, corpus.inputs,
                receiptName = "archive-native-origin.validation.json")
            graph.bindOriginalBinary(requireNotNull(proof.originalBinarySha256))
            graph.bindExpectedObservations(sha256(buildString {
                append(proof.originalBinarySha256).append('\n')
                corpus.inputs.forEach { input -> append(input.id.length).append(':').append(input.id).append(":0:")
                    .append(sha256(byteArrayOf())).append(':').append(sha256(byteArrayOf())).append('\n') }
            }.toByteArray()))
            graph.accept(accepted, RepairEvidence("valid", "later native fixture observations matched"), proof)
            graph.synchronizeRepairHistory()
        }
        assertEquals(0, MakeProjectBuilder.build(fixture.project).returnCode)
        val mixedFailure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("authored-origin-native-append-refused.zip"))
        }
        assertTrue(mixedFailure.message.orEmpty().contains("lacks a finalized rollback record"), mixedFailure.message)
        assertContentEquals(appended, fixture.project.resolve(fixture.relativePath).readBytes())
        assertTrue(graphPath.readBytes().size.toLong() < budget.maximumGraphBytes,
            "missing-record checks must run even when byte-credit admission returns early")

        // Separate supported positive: complete current-writer records, not a nullable legacy
        // baseline. Every resealed substitution below starts from this verified native archive.
        val nativeFixture = releaseRepairFixture(temporaryParent = parent, rejectedAttempts = 1, budget = budget)
        val valid = ArchivalPackager.create(nativeFixture.project, nativeFixture.project.parent.resolve("native-records-complete.zip"))
        val control = nativeFixture.project.parent.resolve("native-records-complete-control")
        ArchivalBundleVerifier.extractAndVerify(valid.archivePath, control)
        assertContentEquals(nativeFixture.after, control.resolve(nativeFixture.relativePath).readBytes())
        val nativeGraph = Json.parseToJsonElement(nativeFixture.project.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
        val nativeRejected = nativeGraph.getValue("nodes").jsonArray.filter {
            it.jsonObject.getValue("status").jsonPrimitive.content == "rejected"
        }
        assertEquals(1, nativeRejected.size)
        assertTrue(nativeRejected.all { it.jsonObject.getValue("rollbackRecord") is JsonObject })
        val nativeAuthored = authoredLegacyGraphFixture(nativeGraph.toString(), 3)
        val nativeOrigin = Json.parseToJsonElement(nativeAuthored).jsonObject
        val nativeOriginPath = "reports/repair-revisions/legacy-graph-${sha256(nativeAuthored.toByteArray())}.json"
        for (mode in listOf("native-absent", "native-null", "missing", "malformed", "context", "prefix", "conflicting", "oversize")) {
            val tampered = nativeFixture.project.parent.resolve("authored-origin-$mode.zip")
            rewriteArchive(valid.archivePath, tampered) { entries ->
                if (mode.startsWith("native-")) {
                    val path = "reports/repair-revisions/graph.json"
                    val graph = Json.parseToJsonElement(entries.getValue(path).decodeToString()).jsonObject
                    val nodes = graph.getValue("nodes").jsonArray
                    val rejected = nodes.last { it.jsonObject.getValue("status").jsonPrimitive.content == "rejected" }.jsonObject
                    assertTrue(rejected.getValue("rollbackRecord") is JsonObject)
                    val changed = nodes.map { element ->
                        val node = element.jsonObject
                        val stripped = if (node.getValue("id") == rejected.getValue("id")) node - "rollbackRecord" else node
                        if (mode == "native-null" && (stripped["rollbackRecord"] == null || stripped["rollbackRecord"] is JsonNull))
                            JsonObject(stripped + ("rollbackRecord" to JsonNull)) else JsonObject(stripped)
                    }
                    entries[path] = JsonObject(graph + ("nodes" to JsonArray(changed))).toString().toByteArray()
                } else {
                    val graphPath = "reports/repair-revisions/graph.json"
                    val currentGraph = Json.parseToJsonElement(entries.getValue(graphPath).decodeToString()).jsonObject
                    entries[graphPath] = JsonObject(currentGraph + ("nodes" to JsonArray(
                        currentGraph.getValue("nodes").jsonArray.map { JsonObject(it.jsonObject - "rollbackRecord") }
                    ))).toString().toByteArray()
                    entries[nativeOriginPath] = nativeAuthored.toByteArray()
                    if (mode != "conflicting") entries.remove(nativeOriginPath)
                    val changed: ByteArray? = when (mode) {
                        "missing" -> null
                        "malformed" -> JsonObject(nativeOrigin + ("unexpectedOriginField" to JsonPrimitive(true))).toString().toByteArray()
                        "context" -> JsonObject(nativeOrigin + ("indexSha256" to JsonPrimitive(
                            if (nativeOrigin.getValue("indexSha256").jsonPrimitive.content == "0".repeat(64)) "1".repeat(64) else "0".repeat(64)
                        ))).toString().toByteArray()
                        "prefix", "conflicting" -> JsonObject(nativeOrigin + ("nodes" to JsonArray(nativeOrigin.getValue("nodes").jsonArray.map { element ->
                            val node = element.jsonObject
                            if (node.getValue("status").jsonPrimitive.content == "rejected")
                                JsonObject(node + ("evidenceSummary" to JsonPrimitive("different declared node"))) else node
                        }))).toString().toByteArray()
                        "oversize" -> nativeAuthored.toByteArray().copyOf((budget.maximumGraphBytes + 1).toInt()).also { bytes ->
                            java.util.Arrays.fill(bytes, nativeAuthored.toByteArray().size, bytes.size, ' '.code.toByte()) }
                        else -> error("unhandled origin control")
                    }
                    changed?.let { bytes -> entries["reports/repair-revisions/legacy-graph-${sha256(bytes)}.json"] = bytes }
                }
                // Self-declared source variants are substitution/refusal controls, not authority
                // tests for the removed context/prefix collector. All receipt/blob/validation evidence remains.
            }
            val output = nativeFixture.project.parent.resolve("authored-origin-$mode-refused")
            val failure = assertFailsWith<IllegalArgumentException> { ArchivalBundleVerifier.extractAndVerify(tampered, output) }
            val expected = if (mode == "oversize") "remaining evidence budget"
                else if (mode == "malformed") "missing, extra, or duplicate fields"
                else "lacks a finalized rollback record"
            assertTrue(failure.message.orEmpty().contains(expected), "$mode: ${failure.message}")
            assertFalse(output.exists())
        }
    }

    @Test
    fun `archive extraction rejects a root rollback claim with valid payload hashes`() {
        val fixture = releaseRepairFixture()
        val valid = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("root-rollback-valid.zip"))
        val verified = fixture.project.parent.resolve("root-rollback-valid-extracted")
        ArchivalBundleVerifier.extractAndVerify(valid.archivePath, verified)
        assertContentEquals(fixture.after, verified.resolve(fixture.relativePath).readBytes())

        val tampered = fixture.project.parent.resolve("root-rollback-tampered.zip")
        rewriteArchive(valid.archivePath, tampered) { entries ->
            val graphPath = "reports/repair-revisions/graph.json"
            val graph = Json.parseToJsonElement(requireNotNull(entries[graphPath]).toString(Charsets.UTF_8)).jsonObject
            assertEquals(JsonPrimitive(6), graph.getValue("schemaVersion"))
            val nodes = graph.getValue("nodes").jsonArray
            val root = nodes.first().jsonObject
            val accepted = nodes.last().jsonObject
            assertFalse("rollbackRecord" in root) // New producer omits only null node records.
            val rollback = JsonObject(mapOf(
                "schemaVersion" to JsonPrimitive(1),
                "attemptId" to accepted.getValue("id"),
                "runId" to accepted.getValue("repairMetadata").jsonObject.getValue("runId"),
                "targetRevisionId" to root.getValue("id"),
                "expectedSourceRevisionSha256" to root.getValue("sourceRevisionSha256"),
                "state" to JsonPrimitive("restored_verified"),
                "failureStage" to JsonNull,
                "failureCode" to JsonNull,
                "observedSourceRevisionSha256" to root.getValue("sourceRevisionSha256"),
                "legacyPendingStateUnknown" to JsonPrimitive(false),
                "candidateSourceInstallStarted" to JsonPrimitive(true),
            ))
            // Keep the source revisions, runs, receipts, and recovery binding intact. The archive
            // helper recomputes every payload hash, so rejection must come from root semantics.
            val changedRoot = JsonObject(root + ("rollbackRecord" to rollback))
            entries[graphPath] = JsonObject(graph + ("nodes" to JsonArray(listOf(changedRoot) + nodes.drop(1))))
                .toString().toByteArray(Charsets.UTF_8)
        }

        val extracted = fixture.project.parent.resolve("root-rollback-rejected")
        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalBundleVerifier.extractAndVerify(tampered, extracted)
        }
        assertTrue(failure.message.orEmpty().contains("repair release graph root is invalid"), failure.message)
        assertFalse(extracted.exists())
    }

    @Test
    fun `schema six archive rejects publication metadata without exact ancestor witnesses`() {
        val fixture = releaseRepairFixture()
        val valid = ArchivalPackager.create(fixture.project,
            fixture.project.parent.resolve("schema-six-ancestor-valid.zip"))
        val tampered = fixture.project.parent.resolve("schema-six-ancestor-stripped.zip")
        rewriteArchive(valid.archivePath, tampered) { entries ->
            val path = "reports/repair-revisions/graph.json"
            val graph = Json.parseToJsonElement(entries.getValue(path).decodeToString()).jsonObject
            assertEquals(JsonPrimitive(6), graph.getValue("schemaVersion"))
            val nodes = graph.getValue("nodes").jsonArray.map { element ->
                val node = element.jsonObject
                if (node.getValue("status").jsonPrimitive.content != "accepted") return@map element
                val metadata = node.getValue("publicationPreimageMetadata").jsonObject
                val pathEntry = metadata.entries.single()
                val downgraded = JsonObject(pathEntry.value.jsonObject - "ancestorMetadata" -
                    "atimeSeconds" - "atimeNanoseconds" + ("metadataVersion" to JsonPrimitive(1)))
                JsonObject(node + ("publicationPreimageMetadata" to JsonObject(mapOf(pathEntry.key to downgraded))))
            }
            entries[path] = JsonObject(graph + ("nodes" to JsonArray(nodes))).toString().toByteArray()
        }

        val output = fixture.project.parent.resolve("schema-six-ancestor-stripped-output")
        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalBundleVerifier.extractAndVerify(tampered, output)
        }
        assertTrue(failure.message.orEmpty().contains(
            "schema-6 accepted repair release node lacks exact publication and ancestor metadata"), failure.message)
        assertFalse(output.exists())

        val partial = fixture.project.parent.resolve("schema-six-ancestor-partial.zip")
        rewriteArchive(valid.archivePath, partial) { entries ->
            val path = "reports/repair-revisions/graph.json"
            val graph = Json.parseToJsonElement(entries.getValue(path).decodeToString()).jsonObject
            val nodes = graph.getValue("nodes").jsonArray.map { element ->
                val node = element.jsonObject
                if (node.getValue("status").jsonPrimitive.content != "accepted") element
                else {
                    val metadata = node.getValue("publicationPreimageMetadata").jsonObject
                    val pathEntry = metadata.entries.single()
                    val original = pathEntry.value.jsonObject
                    val ancestors = original.getValue("ancestorMetadata").jsonArray
                    assertTrue(ancestors.size > 1)
                    val partialMetadata = JsonObject(original + (
                        "ancestorMetadata" to JsonArray(listOf(ancestors.first()))
                    ))
                    JsonObject(node + ("publicationPreimageMetadata" to JsonObject(
                        metadata + (pathEntry.key to partialMetadata)
                    )))
                }
            }
            entries[path] = JsonObject(graph + ("nodes" to JsonArray(nodes))).toString().toByteArray()
        }
        val partialOutput = fixture.project.parent.resolve("schema-six-ancestor-partial-output")
        val partialFailure = assertFailsWith<IllegalArgumentException> {
            ArchivalBundleVerifier.extractAndVerify(partial, partialOutput)
        }
        assertTrue(partialFailure.message.orEmpty().contains(
            "schema-6 accepted repair release node lacks exact publication and ancestor metadata"), partialFailure.message)
        assertFalse(partialOutput.exists())

        val erased = fixture.project.parent.resolve("schema-six-publication-erased.zip")
        rewriteArchive(valid.archivePath, erased) { entries ->
            val path = "reports/repair-revisions/graph.json"
            val graph = Json.parseToJsonElement(entries.getValue(path).decodeToString()).jsonObject
            val nodes = graph.getValue("nodes").jsonArray.map { element ->
                val node = element.jsonObject
                if (node.getValue("status").jsonPrimitive.content != "accepted") element
                else JsonObject(node + ("publicationChanges" to JsonArray(emptyList())) +
                    ("publicationPreimageMetadata" to JsonObject(emptyMap())))
            }
            entries[path] = JsonObject(graph + ("nodes" to JsonArray(nodes))).toString().toByteArray()
        }
        val erasedOutput = fixture.project.parent.resolve("schema-six-publication-erased-output")
        val erasedFailure = assertFailsWith<IllegalArgumentException> {
            ArchivalBundleVerifier.extractAndVerify(erased, erasedOutput)
        }
        assertTrue(erasedFailure.message.orEmpty().contains(
            "schema-6 accepted repair release node lacks exact publication and ancestor metadata"), erasedFailure.message)
        assertFalse(erasedOutput.exists())
    }

    @Test
    fun `recovery profile cache owns copies and charges distinct source bytes before retention`() {
        val paths = listOf("a.src", "b.src")
        val budget = RepairResourceBudget(maximumSourceFiles = 2, maximumSourceFileBytes = 8,
            maximumSourceBytes = 8, maximumContextFiles = 2, maximumContextBytes = 8,
            maximumStagingDirectories = 2, maximumStagingBytes = 8, maximumPatchFiles = 1, maximumPatchBytes = 8)
        val bytes = mutableMapOf("a.src" to "aaaa".toByteArray(), "b.src" to "bbbb".toByteArray())
        var physicalReads = 0
        val view = object : RepairRecoverySourceView {
            override val sourcePaths = paths
            override val editablePaths = paths
            override fun readSource(relative: String): ByteArray { physicalReads++; return bytes.getValue(relative) }
        }
        val type = Class.forName("decompengine.repair.RecoveryProfileSourceCache")
        val constructor = type.getDeclaredConstructor(RepairRecoverySourceView::class.java, RepairResourceBudget::class.java)
            .apply { isAccessible = true }
        val read = type.getDeclaredMethod("readSource", String::class.java).apply { isAccessible = true }
        fun source(cache: Any, path: String): ByteArray = try { read.invoke(cache, path) as ByteArray }
            catch (failure: java.lang.reflect.InvocationTargetException) { throw failure.targetException }
        val cache = constructor.newInstance(view, budget)
        for (path in listOf("unknown.src", "../a.src")) assertFailsWith<IllegalArgumentException> { source(cache, path) }
        assertEquals(0, physicalReads)
        val first = source(cache, "a.src")
        first.fill(0)
        bytes.getValue("a.src").fill(1) // Neither callback nor reader aliases may retarget the retained bytes.
        repeat(8) { assertContentEquals("aaaa".toByteArray(), source(cache, "a.src")) }
        assertEquals(1, physicalReads)
        assertContentEquals("bbbb".toByteArray(), source(cache, "b.src"))
        assertEquals(2, physicalReads) // Exactly8 admitted bytes across two distinct paths.

        bytes["a.src"] = ByteArray(9)
        val refused = constructor.newInstance(view, budget)
        assertFailsWith<RepairBudgetExceededException> { source(refused, "a.src") }
        bytes["a.src"] = ByteArray(8)
        assertEquals(8, source(refused, "a.src").size)
        assertFailsWith<RepairBudgetExceededException> { source(refused, "b.src") } // Eight plus four is over cap.
        bytes["b.src"] = byteArrayOf()
        assertContentEquals(byteArrayOf(), source(refused, "b.src")) // Failed admission retained no partial entry.
        assertEquals(6, physicalReads)
    }

    @Test
    fun `concurrent recovery profile lookups admit same path once and return independent copies`() {
        val paths = listOf("code.src")
        val expected = "original".toByteArray()
        val budget = RepairResourceBudget(maximumSourceFiles = 1, maximumSourceFileBytes = 8,
            maximumSourceBytes = 8, maximumContextFiles = 1, maximumContextBytes = 8,
            maximumStagingDirectories = 1, maximumStagingBytes = 8, maximumPatchFiles = 1, maximumPatchBytes = 8)
        val ready = java.util.concurrent.CountDownLatch(2)
        val start = java.util.concurrent.CountDownLatch(1)
        val physicalEntered = java.util.concurrent.CountDownLatch(1)
        val releasePhysical = java.util.concurrent.CountDownLatch(1)
        val physicalReads = java.util.concurrent.atomic.AtomicInteger()
        lateinit var cache: Any
        val view = object : RepairRecoverySourceView {
            override val sourcePaths = paths
            override val editablePaths = paths
            override fun readSource(relative: String): ByteArray {
                physicalReads.incrementAndGet()
                physicalEntered.countDown()
                // Observe actual monitor ownership, not a delay guessed to imply exclusion.
                assertTrue(Thread.holdsLock(cache))
                assertTrue(releasePhysical.await(2, TimeUnit.SECONDS))
                return expected
            }
        }
        val type = Class.forName("decompengine.repair.RecoveryProfileSourceCache")
        cache = type.getDeclaredConstructor(RepairRecoverySourceView::class.java, RepairResourceBudget::class.java)
            .apply { isAccessible = true }.newInstance(view, budget)
        val read = type.getDeclaredMethod("readSource", String::class.java).apply { isAccessible = true }
        fun lookup(): ByteArray = try { read.invoke(cache, "code.src") as ByteArray }
            catch (failure: java.lang.reflect.InvocationTargetException) { throw failure.targetException }
        val executor = Executors.newFixedThreadPool(2)
        try {
            val results = (0..1).map {
                executor.submit<ByteArray> {
                    ready.countDown()
                    assertTrue(start.await(2, TimeUnit.SECONDS))
                    lookup()
                }
            }
            assertTrue(ready.await(2, TimeUnit.SECONDS))
            start.countDown()
            assertTrue(physicalEntered.await(2, TimeUnit.SECONDS))
            // Do not wait for a second physical admission: correctly serialized misses forbid it.
            releasePhysical.countDown()
            val first = results[0].get(2, TimeUnit.SECONDS)
            val second = results[1].get(2, TimeUnit.SECONDS)
            assertEquals(1, physicalReads.get())
            assertTrue(first !== second)
            assertContentEquals(expected, first)
            assertContentEquals(expected, second)
            first.fill(0)
            assertContentEquals(expected, second)
            assertContentEquals(expected, lookup())
            assertEquals(1, physicalReads.get())
        } finally {
            start.countDown(); releasePhysical.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(2, TimeUnit.SECONDS))
        }
    }

    @Test
    fun `recovery profile may repeat immutable lookups while two physical snapshots still detect blob mutation`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val paths = listOf("a.src", "b.src")
        val originals = mapOf("a.src" to "aaaaaaaa".toByteArray(), "b.src" to "bbbbbbbb".toByteArray())
        val candidate = "cccccccc".toByteArray()
        val budget = RepairResourceBudget(maximumSourceFiles = 2, maximumSourceFileBytes = 8,
            maximumSourceBytes = 16, maximumContextFiles = 2, maximumContextBytes = 16,
            maximumStagingDirectories = 2, maximumStagingBytes = 16,
            maximumPatchFiles = 1, maximumPatchBytes = 8)
        for (mutateBlob in listOf(false, true)) {
            val root = Files.createTempDirectory(parent, "repeated-recovery-lookup-")
            originals.forEach { (path, bytes) -> root.resolve(path).writeBytes(bytes) }
            val layout = RepairIndexLayout(paths, paths, modules = listOf(
                RepairModuleEvidence("a", listOf("a.src")), RepairModuleEvidence("b", listOf("b.src"))))
            var profileFinished = false
            var lookups = 0
            var blobMutated = false
            val profile = object : RepairIndexProfile {
                override fun profileId() = "repeated-authenticated-recovery-profile"
                override fun resolve(projectRoot: Path, budget: RepairResourceBudget): RepairIndexLayout {
                    originals.forEach { (path, bytes) ->
                        require(projectRoot.resolve(path).readBytes().contentEquals(bytes)) { "source-sensitive layout requires target bytes" }
                    }
                    return layout
                }
                override fun authorizesRecoveryLayout(sourcePaths: List<String>, editablePaths: List<String>,
                    budget: RepairResourceBudget) = sourcePaths == paths && editablePaths == paths
                override fun resolveForRecovery(projectRoot: Path, budget: RepairResourceBudget,
                    sourcePaths: List<String>, editablePaths: List<String>, readSource: (String) -> ByteArray): RepairIndexLayout {
                    assertEquals(paths, sourcePaths)
                    repeat(6) {
                        paths.forEach { path ->
                            val bytes = readSource(path)
                            lookups++
                            assertContentEquals(originals.getValue(path), bytes)
                            bytes.fill(0) // A caller may mutate its copy, never the retained cache.
                        }
                    }
                    profileFinished = true
                    return layout
                }
                override fun validateSourceContent(path: String, bytes: ByteArray) {
                    if (mutateBlob && profileFinished && !blobMutated && path == "a.src") {
                        // Runs after the profile returns, during the first uncached snapshot.
                        // A cached second snapshot would miss this physical content replacement.
                        root.resolve("reports/repair-revisions/blobs/" + sha256(originals.getValue(path)))
                            .writeBytes("xxxxxxxx".toByteArray())
                        blobMutated = true
                    }
                }
            }
            class CandidateCrash : Error()
            ModuleRevisionGraph.openLegacyForTesting(root, profile, budget, ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterPublicationExchange && point.phase == "candidate") throw CandidateCrash()
            }).use { graph ->
                graph.enableRunContract()
                val attempt = graph.beginAttempt(listOf("a.src"))
                assertFailsWith<CandidateCrash> { graph.installCandidate(attempt, mapOf("a.src" to candidate)) }
            }
            val graphPath = root.resolve("reports/repair-revisions/graph.json")
            val beforeGraph = graphPath.readBytes()
            val graphKey = Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey()
            val sourceKey = Files.readAttributes(root.resolve("a.src"), BasicFileAttributes::class.java).fileKey()
            var exchanges = 0
            if (mutateBlob) {
                val failure = assertFailsWith<IllegalArgumentException> {
                    ModuleRevisionGraph.openForTesting(root, profile, budget, ModuleRevisionFaultInjector { point ->
                        if (point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "startup-rollback") exchanges++
                    }).close()
                }
                assertEquals("recovery source view preimage digest or size differs", failure.message)
                assertTrue(blobMutated)
                assertEquals(12, lookups)
                assertEquals(0, exchanges)
                assertContentEquals(beforeGraph, graphPath.readBytes())
                assertEquals(graphKey, Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey())
                assertContentEquals(candidate, root.resolve("a.src").readBytes())
                assertEquals(sourceKey, Files.readAttributes(root.resolve("a.src"), BasicFileAttributes::class.java).fileKey())
            } else {
                ModuleRevisionGraph.open(root, profile, budget).use { graph ->
                    assertEquals(12, lookups)
                    originals.forEach { (path, bytes) -> assertContentEquals(bytes, root.resolve(path).readBytes()) }
                    assertEquals(RepairRollbackState.RESTORED_VERIFIED, graph.snapshot.nodes.last().rollbackRecord?.state)
                    assertTrue(graph.snapshot.runs.isEmpty())
                }
            }
        }
    }

    @Test
    fun `native rollback marker state matrix preserves in progress and failure outcomes`() {
        val digest = "a".repeat(64)
        val record = RepairRollbackRecord(attemptId = "revision_marker", runId = null,
            targetRevisionId = "root_marker", expectedSourceRevisionSha256 = digest,
            state = RepairRollbackState.NOT_REQUIRED_VERIFIED, observedSourceRevisionSha256 = digest)
        for (started in listOf(false, true)) {
            record.copy(state = RepairRollbackState.RESTORE_IN_PROGRESS,
                candidateSourceInstallStarted = started, observedSourceRevisionSha256 = null)
            for (state in listOf(RepairRollbackState.RESTORE_FAILED_UNRESOLVED, RepairRollbackState.RESTORED_AFTER_FAILURE)) {
                val failed = record.copy(state = state, candidateSourceInstallStarted = started,
                    failureStage = RepairRollbackStage.SOURCE_RESTORE,
                    failureCode = RepairRollbackFailureCode.RESTORE_OPERATION_FAILED)
                assertEquals(started, failed.candidateSourceInstallStarted)
                assertEquals(state, failed.state)
            }
        }
        assertEquals(false, record.candidateSourceInstallStarted)
        assertEquals(true, record.copy(state = RepairRollbackState.RESTORED_VERIFIED,
            candidateSourceInstallStarted = true).candidateSourceInstallStarted)
        // Null belongs to a genuinely changed legacy migration, checked with its node context on load.
        assertNull(record.copy(state = RepairRollbackState.RESTORED_VERIFIED,
            legacyPendingStateUnknown = true, candidateSourceInstallStarted = null).candidateSourceInstallStarted)
        for (state in RepairRollbackState.entries) {
            val failureState = state in setOf(RepairRollbackState.RESTORE_FAILED_UNRESOLVED, RepairRollbackState.RESTORED_AFTER_FAILURE)
            val failure = assertFailsWith<IllegalArgumentException> {
                record.copy(state = state, candidateSourceInstallStarted = null,
                    failureStage = if (failureState) RepairRollbackStage.SOURCE_RESTORE else null,
                    failureCode = if (failureState) RepairRollbackFailureCode.RESTORE_OPERATION_FAILED else null)
            }
            assertEquals("native rollback requires a known source-install marker", failure.message)
        }
        assertEquals("failure-free restored rollback has an unstarted source-install marker",
            assertFailsWith<IllegalArgumentException> {
                record.copy(state = RepairRollbackState.RESTORED_VERIFIED)
            }.message)
        assertEquals("not-required rollback requires an unstarted source-install marker",
            assertFailsWith<IllegalArgumentException> {
                record.copy(candidateSourceInstallStarted = true)
            }.message)
    }

    @Test
    fun `native pending and finalized records bind known install marker to actual restoration`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val profile = DeclarativeRepairIndexProfile("native-install-marker",
            RepairIndexLayout(listOf("code.c"), listOf("code.c"), modules = listOf(RepairModuleEvidence("code", listOf("code.c")))))
        for (installed in listOf(false, true)) {
            val root = Files.createTempDirectory(parent, "native-install-marker-")
            val source = root.resolve("code.c").also { it.writeText("before") }
            val path = root.resolve("reports/repair-revisions/graph.json")
            var armed = false
            val graph = ModuleRevisionGraph.openLegacyForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                    point.scope == "revision-state" && point.name == "graph.json") throw SimulatedRepairCrash()
            })
            try {
                graph.enableRunContract() // Native schema4 without an active run uses actual non-detached source installation.
                val attempt = graph.beginAttempt(listOf("code.c"))
                if (installed) graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
                armed = true
                assertFailsWith<SimulatedRepairCrash> { graph.reject(attempt, RepairEvidence("rejected", "marker recovery")) }
            } finally {
                graph.close()
            }
            fun refuseForgedRecord(canonical: String, pending: Boolean) {
                val document = Json.parseToJsonElement(canonical).jsonObject
                val record = if (pending) document.getValue("pending").jsonObject.getValue("rollbackRecord").jsonObject
                    else document.getValue("nodes").jsonArray.last().jsonObject.getValue("rollbackRecord").jsonObject
                val terminal = if (installed) "not_required_verified" else "restored_verified"
                val cases = listOf(
                    Triple<JsonElement, String, String>(JsonNull, record.getValue("state").jsonPrimitive.content,
                        "native rollback requires a known source-install marker"),
                    Triple(JsonPrimitive(installed), terminal, if (installed)
                        "not-required rollback requires an unstarted source-install marker"
                        else "failure-free restored rollback has an unstarted source-install marker"))
                for ((marker, state, expectedMessage) in cases) {
                    val forgedRecord = JsonObject(record + mapOf("candidateSourceInstallStarted" to marker,
                        "state" to JsonPrimitive(state),
                        "observedSourceRevisionSha256" to record.getValue("expectedSourceRevisionSha256")))
                    val forgedDocument = if (pending) JsonObject(document + ("pending" to JsonObject(
                        document.getValue("pending").jsonObject + ("rollbackRecord" to forgedRecord))))
                        else JsonObject(document + ("nodes" to JsonArray(document.getValue("nodes").jsonArray.mapIndexed { index, node ->
                            if (index == document.getValue("nodes").jsonArray.lastIndex)
                                JsonObject(node.jsonObject + ("rollbackRecord" to forgedRecord)) else node
                        })))
                    val forged = forgedDocument.toString()
                    assertNotEquals(canonical, forged)
                    path.writeText(forged)
                    val sourceBytes = source.readBytes()
                    val sourceKey = Files.readAttributes(source, BasicFileAttributes::class.java).fileKey()
                    val graphKey = Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()
                    val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(root, profile).close() }
                    assertEquals(expectedMessage, failure.message)
                    assertEquals(forged, path.readText())
                    assertContentEquals(sourceBytes, source.readBytes())
                    assertEquals(sourceKey, Files.readAttributes(source, BasicFileAttributes::class.java).fileKey())
                    assertEquals(graphKey, Files.readAttributes(path, BasicFileAttributes::class.java).fileKey())
                }
                path.writeText(canonical)
            }
            val pending = authoredLegacyGraphFixture(path.readText(), 4).also(path::writeText)
            val pendingRecord = Json.parseToJsonElement(pending).jsonObject.getValue("pending").jsonObject
                .getValue("rollbackRecord").jsonObject
            assertEquals(JsonPrimitive(false), pendingRecord.getValue("legacyPendingStateUnknown"))
            assertEquals(JsonPrimitive(installed), pendingRecord.getValue("candidateSourceInstallStarted"))
            assertEquals("restore_in_progress", pendingRecord.getValue("state").jsonPrimitive.content)
            refuseForgedRecord(pending, true)
            ModuleRevisionGraph.open(root, profile).use { recovered ->
                val outcome = requireNotNull(recovered.snapshot.nodes.last().rollbackRecord)
                assertFalse(outcome.legacyPendingStateUnknown)
                assertEquals(installed, outcome.candidateSourceInstallStarted)
                assertEquals(if (installed) RepairRollbackState.RESTORED_VERIFIED else RepairRollbackState.NOT_REQUIRED_VERIFIED, outcome.state)
                assertEquals("before", source.readText())
                assertTrue(recovered.snapshot.runs.isEmpty())
            }
            ModuleRevisionGraph.open(root, profile).use { it.enableRunContract() }
            val upgraded = Json.parseToJsonElement(path.readText()).jsonObject
            assertEquals(JsonPrimitive(5), upgraded.getValue("schemaVersion"))
            val finalized = upgraded.getValue("nodes").jsonArray.last().jsonObject
            assertEquals(JsonArray(emptyList()), finalized.getValue("publicationChanges"))
            assertEquals(JsonObject(emptyMap()), finalized.getValue("publicationPreimageMetadata"))
            ModuleRevisionGraph.open(root, profile).close()
            refuseForgedRecord(path.readText(), false)
            ModuleRevisionGraph.open(root, profile).close()
        }
    }

    @Test
    fun `native unstarted rollback does not certify recovery after preimage metadata is lost`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val root = Files.createTempDirectory(parent, "native-unstarted-failure-")
        val source = root.resolve("code.c").also { it.writeText("before") }
        val profile = DeclarativeRepairIndexProfile("native-unstarted-failure",
            RepairIndexLayout(listOf("code.c"), listOf("code.c"), modules = listOf(RepairModuleEvidence("code", listOf("code.c")))))
        var armed = false
        val graph = ModuleRevisionGraph.openLegacyForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
            if (armed && point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                point.scope == "revision-state" && point.name == "graph.json") {
                armed = false
                // Model an external atomic replacement. Truncating in place would mutate the
                // retained preimage inode too, which correctly makes exact-metadata recovery
                // impossible rather than representing a replace-style workspace edit.
                val foreign = source.resolveSibling("foreign.tmp")
                foreign.writeText("foreign")
                Files.move(foreign, source, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            }
        })
        try {
            graph.enableRunContract()
            val attempt = graph.beginAttempt(listOf("code.c"))
            armed = true
            assertFailsWith<IllegalStateException> { graph.reject(attempt, RepairEvidence("rejected", "unstarted failure")) }
            val pending = Json.parseToJsonElement(root.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
                .getValue("pending").jsonObject.getValue("rollbackRecord").jsonObject
            assertEquals(JsonPrimitive(false), pending.getValue("legacyPendingStateUnknown"))
            assertEquals(JsonPrimitive(false), pending.getValue("candidateSourceInstallStarted"))
            assertEquals("restore_failed_unresolved", pending.getValue("state").jsonPrimitive.content)
            assertEquals("source_verification", pending.getValue("failureStage").jsonPrimitive.content)
            assertEquals("target_digest_mismatch", pending.getValue("failureCode").jsonPrimitive.content)
            assertEquals("foreign", source.readText())
        } finally {
            graph.close()
        }
        // The fixture restores the unrelated edit; recovery must retain the genuine failure instead of NOT_REQUIRED.
        source.writeText("before")
        val refusal = assertFailsWith<IllegalStateException> { ModuleRevisionGraph.open(root, profile).close() }
        assertTrue(refusal.message.orEmpty().contains("committed preimage"), refusal.message)
        assertEquals("before", source.readText())
        val unresolved = Json.parseToJsonElement(root.resolve("reports/repair-revisions/graph.json").readText())
            .jsonObject.getValue("pending").jsonObject.getValue("rollbackRecord").jsonObject
        assertEquals("restore_failed_unresolved", unresolved.getValue("state").jsonPrimitive.content)
        assertEquals("source_verification", unresolved.getValue("failureStage").jsonPrimitive.content)
        assertEquals("target_digest_mismatch", unresolved.getValue("failureCode").jsonPrimitive.content)
    }

    @Test
    fun `legacy changed pending and finalized records require unknown install marker while no change remains false`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val profile = DeclarativeRepairIndexProfile("legacy-install-marker",
            RepairIndexLayout(listOf("code.c"), listOf("code.c"), modules = listOf(RepairModuleEvidence("code", listOf("code.c")))))
        for (hasChanges in listOf(false, true)) {
            val root = Files.createTempDirectory(parent, "legacy-install-marker-")
            val source = root.resolve("code.c").also { it.writeText("before") }
            ModuleRevisionGraph.open(root, profile).use { graph ->
                val attempt = graph.beginAttempt(listOf("code.c")) // Schema2, before the install-marker wire existed.
                if (hasChanges) graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
            }
            val path = root.resolve("reports/repair-revisions/graph.json")
            path.writeText(authoredLegacyGraphFixture(path.readText(), 2))
            assertFailsWith<SimulatedRepairCrash> {
                ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
                    if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                        point.scope == "revision-state" && point.name == "graph.json") throw SimulatedRepairCrash()
                }).close()
            }
            fun refuseFalseCertainty(canonical: String, currentState: String) {
                for (marker in listOf("false", "true")) {
                    val forged = canonical.replace("\"candidateSourceInstallStarted\":null", "\"candidateSourceInstallStarted\":$marker")
                        .let { if (marker == "false" && currentState != "restore_in_progress")
                            it.replace("\"state\":\"$currentState\"", "\"state\":\"not_required_verified\"") else it }
                    assertNotEquals(canonical, forged)
                    path.writeText(forged)
                    val bytes = source.readBytes()
                    val key = Files.readAttributes(source, BasicFileAttributes::class.java).fileKey()
                    val graphKey = Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()
                    val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(root, profile).close() }
                    assertEquals("legacy changed attempt has a fabricated source-install marker", failure.message)
                    assertEquals(forged, path.readText())
                    assertContentEquals(bytes, source.readBytes())
                    assertEquals(key, Files.readAttributes(source, BasicFileAttributes::class.java).fileKey())
                    assertEquals(graphKey, Files.readAttributes(path, BasicFileAttributes::class.java).fileKey())
                }
                path.writeText(canonical)
            }
            fun refuseUnknownForUnchanged(canonical: String, finalized: Boolean) {
                val forged = canonical.replace("\"candidateSourceInstallStarted\":false", "\"candidateSourceInstallStarted\":null")
                    .let { if (finalized) it.replace("\"state\":\"not_required_verified\"", "\"state\":\"restored_verified\"") else it }
                assertNotEquals(canonical, forged)
                path.writeText(forged)
                val bytes = source.readBytes()
                val key = Files.readAttributes(source, BasicFileAttributes::class.java).fileKey()
                val graphKey = Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()
                val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(root, profile).close() }
                assertEquals("legacy unchanged attempt has a fabricated source-install marker", failure.message)
                assertEquals(forged, path.readText())
                assertContentEquals(bytes, source.readBytes())
                assertEquals(key, Files.readAttributes(source, BasicFileAttributes::class.java).fileKey())
                assertEquals(graphKey, Files.readAttributes(path, BasicFileAttributes::class.java).fileKey())
                path.writeText(canonical)
            }
            val pending = path.readText()
            val pendingRecord = Json.parseToJsonElement(pending).jsonObject.getValue("pending").jsonObject
                .getValue("rollbackRecord").jsonObject
            assertEquals(JsonPrimitive(true), pendingRecord.getValue("legacyPendingStateUnknown"))
            assertEquals(if (hasChanges) JsonNull else JsonPrimitive(false), pendingRecord.getValue("candidateSourceInstallStarted"))
            if (hasChanges) refuseFalseCertainty(pending, "restore_in_progress")
            else refuseUnknownForUnchanged(pending, false)
            ModuleRevisionGraph.open(root, profile).use { graph ->
                val record = requireNotNull(graph.snapshot.nodes.last().rollbackRecord)
                assertTrue(record.legacyPendingStateUnknown)
                assertEquals(if (hasChanges) null else false, record.candidateSourceInstallStarted)
                assertEquals(if (hasChanges) RepairRollbackState.RESTORED_VERIFIED else RepairRollbackState.NOT_REQUIRED_VERIFIED, record.state)
                assertEquals("before", source.readText())
                assertTrue(graph.snapshot.runs.isEmpty())
            }
            if (hasChanges) refuseFalseCertainty(path.readText(), "restored_verified")
            else refuseUnknownForUnchanged(path.readText(), true)
            ModuleRevisionGraph.open(root, profile).close()
        }
    }

    @Test
    fun `startup rollback restores captured atime when candidate state committed before first exchange`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val root = Files.createTempDirectory(parent, "unexchanged-candidate-atime-")
        val source = root.resolve("code.c").also { it.writeText("before") }
        val profile = DeclarativeRepairIndexProfile("unexchanged-candidate-atime",
            RepairIndexLayout(listOf("code.c"), listOf("code.c"), modules = listOf(RepairModuleEvidence("code", listOf("code.c")))))
        class CandidateStateCrash : Error()
        lateinit var committedAtime: Pair<Long, Int>
        ModuleRevisionGraph.openLegacyForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
            if (point == ModuleRevisionFaultPoint.AfterCandidateStatePersist) throw CandidateStateCrash()
        }).use { graph ->
            graph.enableRunContract()
            val attempt = graph.beginAttempt(listOf("code.c"))
            val pending = Json.parseToJsonElement(root.resolve("reports/repair-revisions/graph.json").readText())
                .jsonObject.getValue("pending").jsonObject
            val metadata = pending.getValue("preimageMetadata").jsonObject.getValue("code.c").jsonObject
            committedAtime = metadata.getValue("atimeSeconds").jsonPrimitive.content.toLong() to
                metadata.getValue("atimeNanoseconds").jsonPrimitive.content.toInt()
            assertFailsWith<CandidateStateCrash> {
                graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
            }
        }

        // Model a normal read of the original inode after the durable candidate record but
        // before any source exchange or retained hard link exists.
        Files.setAttribute(source, "basic:lastAccessTime",
            java.nio.file.attribute.FileTime.from(java.time.Instant.ofEpochSecond(1)), LinkOption.NOFOLLOW_LINKS)
        assertEquals("before", Files.readString(source))
        val driftedAtime = LinuxFilesystemSyscalls.openRoot(root).use { directory ->
            LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, "code.c")!!.use {
                val state = LinuxFilesystemSyscalls.fileState(it)
                state.accessTimeSeconds to state.accessTimeNanoseconds
            }
        }
        assertNotEquals(committedAtime, driftedAtime, "the fixture must observe a real atime change before recovery")

        ModuleRevisionGraph.open(root, profile).use { recovered ->
            val restoredAtime = LinuxFilesystemSyscalls.openRoot(root).use { directory ->
                LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, "code.c")!!.use {
                    val state = LinuxFilesystemSyscalls.fileState(it)
                    state.accessTimeSeconds to state.accessTimeNanoseconds
                }
            }
            assertEquals(committedAtime, restoredAtime, "startup must restore the committed atime before accepting rollback")
            assertEquals("before", source.readText())
            assertEquals(RepairRollbackState.RESTORED_VERIFIED, recovered.snapshot.nodes.last().rollbackRecord?.state)
            assertTrue(recovered.snapshot.runs.isEmpty())
        }
    }

    @Test
    fun `generated adapter recovers dirty C bodies and changed includes from authenticated virtual preimages`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        for (changeIncludes in listOf(false, true)) {
            val project = generatedProject(temporaryParent = parent)
            val target = project.resolve("src/modules/alpha.c")
            val original = target.readBytes()
            val before = GeneratedCRepairIndexProfile.resolve(project, RepairResourceBudget())
            assertTrue(before.pathDependencies.getValue("src/modules/alpha.c").isNotEmpty())
            val invalidBody = "int broken( { /* intentionally invalid C syntax */\n".toByteArray()
            val candidate = if (changeIncludes) invalidBody else original + "\n".toByteArray() + invalidBody
            class CandidateCrash : Error()
            var indexSha = ""
            ModuleRevisionGraph.openLegacyForTesting(project, GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (point is ModuleRevisionFaultPoint.AfterPublicationExchange && point.phase == "candidate") throw CandidateCrash()
                }).use { graph ->
                graph.enableRunContract()
                indexSha = graph.snapshot.indexSha256
                val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
                assertFailsWith<CandidateCrash> { graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate)) }
            }
            assertContentEquals(candidate, target.readBytes())
            if (changeIncludes) {
                assertNotEquals(before.pathDependencies,
                    GeneratedCRepairIndexProfile.resolve(project, RepairResourceBudget()).pathDependencies)
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                assertEquals(indexSha, graph.snapshot.indexSha256)
                assertContentEquals(original, target.readBytes())
                assertTrue(graph.snapshot.nodes.last().changedModules.isNotEmpty())
                assertEquals(RepairRollbackState.RESTORED_VERIFIED, graph.snapshot.nodes.last().rollbackRecord?.state)
                assertTrue(graph.snapshot.runs.isEmpty()) // No fabricated run for standalone recovery.
            }
        }
    }

    @Test
    fun `archive retains genuine recovered rollback failure before a later accepted run`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val fixture = releaseRepairFixture(recoveredRollbackPrefix = true, temporaryParent = parent)
        val canonical = ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).use { it.snapshot }
        assertEquals(listOf(RepairRunStatus.ROLLBACK_FAILED, RepairRunStatus.FULLY_ACCEPTED), canonical.runs.map { it.status })
        val failed = canonical.runs.first()
        val recovered = canonical.nodes[1]
        val rollback = requireNotNull(recovered.rollbackRecord)
        assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, failed.rollbackResolution)
        assertEquals(recovered.id, failed.rollbackFailureAttemptId)
        assertEquals(failed.id, rollback.runId)
        assertEquals(recovered.id, rollback.attemptId)
        assertEquals(failed.rollbackResolution, rollback.state)
        assertTrue(recovered.recoveredAfterCrash)
        assertEquals(ModuleRevisionStatus.REJECTED, recovered.status)
        assertEquals(1, failed.attemptedCount)
        assertNull(failed.acceptedHeadId)
        assertEquals(canonical.headId, canonical.runs.last().acceptedHeadId)
        assertEquals(canonical.headId, canonical.fullyAcceptedHeadId)
        assertNull(canonical.provisionalHeadId)
        assertNull(canonical.pendingAttemptId)

        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("recovered-failure-prefix.zip"))
        val extracted = fixture.project.parent.resolve("recovered-failure-prefix-extracted")
        val lineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(bundle.archivePath, extracted)
        val selected = lineage.source.acceptedAcpContributions.single()
        assertEquals(canonical.nodes.last().id, selected.taskId)
        assertTrue(selected.taskId != failed.rollbackFailureAttemptId)
        assertContentEquals(fixture.after, extracted.resolve(fixture.relativePath).readBytes())
        val archivedGraph = Json.parseToJsonElement(extracted.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
        val archivedHistory = Json.parseToJsonElement(extracted.resolve("reports/repair_history.json").readText()).jsonObject
        for (document in listOf(archivedGraph, archivedHistory)) {
            val runs = document.getValue("runs").jsonArray.map { parseRepairRunState(it.toString()) }
            assertEquals(canonical.runs, runs)
            assertEquals(RepairRunStatus.ROLLBACK_FAILED, runs.first().status)
            assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, runs.first().rollbackResolution)
            assertEquals(RepairRunStatus.FULLY_ACCEPTED, runs.last().status)
        }
        assertEquals(JsonNull, archivedGraph.getValue("pending"))
        assertEquals(archivedGraph.getValue("headId"), archivedGraph.getValue("fullyAcceptedHeadId"))
        assertEquals("restored_after_failure", archivedGraph.getValue("nodes").jsonArray[1].jsonObject
            .getValue("rollbackRecord").jsonObject.getValue("state").jsonPrimitive.content)
    }

    @Test
    fun `archive refuses schema one run hiding a genuine resolved rollback failure`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val fixture = releaseRepairFixture(recoveredRollbackPrefix = true, temporaryParent = parent)
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("resolved-failure-schema-two.zip"))
        // Genuine schema2 failure/recovery plus later accepted contribution remains a positive.
        val positive = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(bundle.archivePath,
            fixture.project.parent.resolve("resolved-failure-schema-two-control"))
        val contribution = positive.source.acceptedAcpContributions.single()
        for (terminal in listOf("validation_failed", "interrupted", "rejected")) {
            val tampered = fixture.project.parent.resolve("hidden-failure-schema-one-$terminal.zip")
            rewriteArchive(bundle.archivePath, tampered) { entries ->
                val graph = Json.parseToJsonElement(entries.getValue("reports/repair-revisions/graph.json").decodeToString()).jsonObject
                val record = graph.getValue("nodes").jsonArray[1].jsonObject.getValue("rollbackRecord").jsonObject
                assertEquals("restored_after_failure", record.getValue("state").jsonPrimitive.content)
                assertTrue(record.getValue("failureCode") != JsonNull)
                assertEquals(contribution.taskId, graph.getValue("nodes").jsonArray.last().jsonObject.getValue("id").jsonPrimitive.content)
                for (path in listOf("reports/repair-revisions/graph.json", "reports/repair_history.json")) {
                    val document = Json.parseToJsonElement(entries.getValue(path).decodeToString()).jsonObject
                    val runs = document.getValue("runs").jsonArray
                    assertEquals(2, runs.size)
                    val historical = runs.first().jsonObject
                    assertEquals("rollback_failed", historical.getValue("status").jsonPrimitive.content)
                    assertEquals(record.getValue("attemptId"), historical.getValue("rollbackFailureAttemptId"))
                    val hidden = JsonObject((historical - setOf("rollbackFailureAttemptId", "rollbackResolution")) + mapOf(
                        "schemaVersion" to JsonPrimitive(1), "status" to JsonPrimitive(terminal)))
                    assertEquals("fully_accepted", runs.last().jsonObject.getValue("status").jsonPrimitive.content)
                    entries[path] = JsonObject(document + ("runs" to JsonArray(listOf(hidden) + runs.drop(1))))
                        .toString().toByteArray()
                }
                // All node/source/receipt/contribution bytes remain unchanged; helper reseals outer manifest.
            }
            val output = fixture.project.parent.resolve("hidden-failure-schema-one-$terminal-rejected")
            val failure = assertFailsWith<IllegalArgumentException> { ArchivalBundleVerifier.extractAndVerify(tampered, output) }
            assertTrue(failure.message.orEmpty().contains("schema-1 repair release run owns failure-coded rollback records"), failure.message)
            assertFalse(output.exists())
        }
    }

    @Test
    fun `archive supports both run schemas and refuses cross paired rollback run claims`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val fixture = releaseRepairFixture(rejectedAttempts = 1, temporaryParent = parent)
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("run-schema-two.zip"))
        ArchivalBundleVerifier.extractAndVerify(bundle.archivePath, fixture.project.parent.resolve("run-schema-two-control"))
        val legacy = fixture.project.parent.resolve("run-schema-one.zip")
        rewriteArchive(bundle.archivePath, legacy) { entries ->
            for (path in listOf("reports/repair-revisions/graph.json", "reports/repair_history.json")) {
                val document = Json.parseToJsonElement(entries.getValue(path).decodeToString()).jsonObject
                val runs = document.getValue("runs").jsonArray.map { element ->
                    val run = element.jsonObject
                    assertEquals(JsonPrimitive(2), run.getValue("schemaVersion"))
                    JsonObject((run - setOf("rollbackFailureAttemptId", "rollbackResolution")) +
                        ("schemaVersion" to JsonPrimitive(1)))
                }
                entries[path] = JsonObject(document + ("runs" to JsonArray(runs))).toString().toByteArray()
            }
        }
        ArchivalBundleVerifier.extractAndVerify(legacy, fixture.project.parent.resolve("run-schema-one-control"))
        // Payload hashes and graph/history pairing are recomputed; only semantic linkage is forged.
        for (mode in listOf("missing-attempt", "accepted-attempt", "wrong-resolution")) {
            val tampered = fixture.project.parent.resolve("run-rollback-$mode.zip")
            rewriteArchive(bundle.archivePath, tampered) { entries ->
                val graph = Json.parseToJsonElement(entries.getValue("reports/repair-revisions/graph.json").decodeToString()).jsonObject
                val nodes = graph.getValue("nodes").jsonArray
                val rejected = nodes[1].jsonObject.getValue("id")
                val accepted = nodes.last().jsonObject.getValue("id")
                val attempt = when (mode) {
                    "missing-attempt" -> JsonPrimitive("revision_missing")
                    "accepted-attempt" -> accepted
                    else -> rejected
                }
                for (path in listOf("reports/repair-revisions/graph.json", "reports/repair_history.json")) {
                    val document = Json.parseToJsonElement(entries.getValue(path).decodeToString()).jsonObject
                    val run = document.getValue("runs").jsonArray.single().jsonObject
                    val changed = JsonObject(run + mapOf(
                        "status" to JsonPrimitive("rollback_failed"),
                        "rollbackFailureAttemptId" to attempt,
                        "rollbackResolution" to JsonPrimitive("restored_after_failure")))
                    entries[path] = JsonObject(document + ("runs" to JsonArray(listOf(changed)))).toString().toByteArray()
                }
            }
            val output = fixture.project.parent.resolve("run-rollback-$mode-refused")
            val failure = assertFailsWith<IllegalArgumentException> { ArchivalBundleVerifier.extractAndVerify(tampered, output) }
            assertTrue(failure.message.orEmpty().contains("rollback"), failure.message)
            assertFalse(output.exists())
        }
    }

    @Test
    fun `archive distinguishes genuine legacy unknown install from native and no change false markers`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        for (mode in listOf("legacy-changed", "legacy-unchanged", "native-changed")) {
            val fixture = releaseRepairFixture(temporaryParent = parent,
                rejectedAttempts = if (mode == "native-changed") 1 else 0,
                legacyRejectedPrefix = mode != "native-changed", legacyPrefixHasChanges = mode != "legacy-unchanged")
            val document = Json.parseToJsonElement(fixture.project.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
            val rejected = document.getValue("nodes").jsonArray.single { it.jsonObject.getValue("status").jsonPrimitive.content == "rejected" }.jsonObject
            val record = rejected.getValue("rollbackRecord").jsonObject
            assertEquals(mode != "legacy-unchanged", rejected.getValue("changes").jsonArray.isNotEmpty())
            assertEquals(JsonPrimitive(mode != "native-changed"), record.getValue("legacyPendingStateUnknown"))
            assertEquals(if (mode == "legacy-changed") JsonNull else JsonPrimitive(false), record.getValue("candidateSourceInstallStarted"))
            assertEquals(if (mode == "legacy-changed") "restored_verified" else "not_required_verified", record.getValue("state").jsonPrimitive.content)
            val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("$mode-marker.zip"))
            val extracted = fixture.project.parent.resolve("$mode-marker-control")
            ArchivalBundleVerifier.extractAndVerify(bundle.archivePath, extracted)
            assertContentEquals(fixture.after, extracted.resolve(fixture.relativePath).readBytes())
            val forgeries: List<Triple<JsonElement, String, String>> = when (mode) {
                "legacy-changed" -> listOf(
                    Triple(JsonPrimitive(false), "not_required_verified", "repair release legacy changed attempt has a fabricated source-install marker"),
                    Triple(JsonPrimitive(true), "restored_verified", "repair release legacy changed attempt has a fabricated source-install marker"))
                "legacy-unchanged" -> listOf(
                    Triple(JsonNull, "restored_verified", "repair release legacy unchanged attempt has a fabricated source-install marker"),
                    Triple(JsonPrimitive(true), "restored_verified", "repair release legacy unchanged attempt has a fabricated source-install marker"))
                else -> listOf(
                    Triple(JsonNull, "not_required_verified", "repair release native rollback requires a known source-install marker"),
                    Triple(JsonPrimitive(false), "restored_verified", "repair release failure-free restored rollback has an unstarted source-install marker"),
                    Triple(JsonPrimitive(true), "not_required_verified", "repair release not-required rollback requires an unstarted source-install marker"))
            }
            for ((index, forgery) in forgeries.withIndex()) {
                val (started, state, expectedMessage) = forgery
                val forged = fixture.project.parent.resolve("$mode-marker-$index.zip")
                rewriteArchive(bundle.archivePath, forged) { entries ->
                    val path = "reports/repair-revisions/graph.json"
                    val graph = Json.parseToJsonElement(entries.getValue(path).toString(Charsets.UTF_8)).jsonObject
                    val nodes = graph.getValue("nodes").jsonArray.map { element ->
                        val node = element.jsonObject
                        if (node.getValue("id") != rejected.getValue("id")) node else JsonObject(node +
                            ("rollbackRecord" to JsonObject(node.getValue("rollbackRecord").jsonObject + mapOf(
                                "candidateSourceInstallStarted" to started,
                                "state" to JsonPrimitive(state)))))
                    }
                    entries[path] = JsonObject(graph + ("nodes" to JsonArray(nodes))).toString().toByteArray()
                }
                val output = fixture.project.parent.resolve("$mode-marker-$index-refused")
                val failure = assertFailsWith<IllegalArgumentException> { ArchivalBundleVerifier.extractAndVerify(forged, output) }
                assertTrue(failure.message.orEmpty().contains(expectedMessage), failure.message)
                assertFalse(output.exists())
            }
        }
    }

    @Test
    fun `archive rejects duplicate migration origins on otherwise bound rejected attempts`() {
        val fixture = releaseRepairFixture(rejectedAttempts = 2)
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("rollback-origins.zip"))
        ArchivalBundleVerifier.extractAndVerify(bundle.archivePath, fixture.project.parent.resolve("rollback-origins-control"))
        val tampered = fixture.project.parent.resolve("duplicate-rollback-origins.zip")
        rewriteArchive(bundle.archivePath, tampered) { entries ->
            val graphPath = "reports/repair-revisions/graph.json"
            val graph = Json.parseToJsonElement(entries.getValue(graphPath).toString(Charsets.UTF_8)).jsonObject
            val nodes = graph.getValue("nodes").jsonArray.map { element ->
                val node = element.jsonObject
                if (node.getValue("status").jsonPrimitive.content != "rejected") node else {
                    val rollback = node.getValue("rollbackRecord").jsonObject
                    JsonObject(node + ("rollbackRecord" to JsonObject(rollback + mapOf(
                        "legacyPendingStateUnknown" to JsonPrimitive(true),
                        "candidateSourceInstallStarted" to JsonNull,
                        "state" to JsonPrimitive("restored_verified"),
                    ))))
                }
            }
            entries[graphPath] = JsonObject(graph + ("nodes" to JsonArray(nodes))).toString().toByteArray()
        }
        val output = fixture.project.parent.resolve("duplicate-origins-rejected")
        val failure = assertFailsWith<IllegalArgumentException> { ArchivalBundleVerifier.extractAndVerify(tampered, output) }
        assertTrue(failure.message.orEmpty().contains("legacy rollback origins"), failure.message)
        assertFalse(output.exists())
    }

    @Test
    fun `archive includes provisional contributions only through a fully accepted composed revision`() {
        val fixture = releaseRepairFixture(
            includeProvisional = true,
            budget = RepairResourceBudget(maximumPatchFiles = 1),
        )
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("composed-repair.zip"))
        val extracted = fixture.project.parent.resolve("composed-repair-extracted")
        val lineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(bundle.archivePath, extracted)
        val contributions = lineage.source.acceptedAcpContributions
        assertEquals(2, contributions.size)
        assertEquals(listOf("src/modules/beta.c", fixture.relativePath), contributions.map { it.changes.single().path })
        assertEquals(contributions[0].resultSourceRevisionSha256, contributions[1].parentSourceRevisionSha256)
        assertEquals(lineage.source.repairGraphHeadRevisionSha256, contributions[1].resultSourceRevisionSha256)
        assertTrue(extracted.resolve("src/modules/beta.c").readText().contains("provisional archive improvement"))
        assertContentEquals(fixture.after, extracted.resolve(fixture.relativePath).readBytes())
        val manifest = Json.parseToJsonElement(extracted.resolve("source_tree_manifest.json").readText()).jsonObject
        val touched = (manifest.getValue("files") as JsonArray).map { it.jsonObject }
            .filter { (it.getValue("path") as JsonPrimitive).content in setOf("src/modules/beta.c", fixture.relativePath) }
        assertEquals(2, touched.size)
        val acceptedPrompt = sha256("revision:${contributions[1].taskId}".toByteArray())
        touched.forEach { assertEquals(acceptedPrompt, (it.getValue("promptSha256") as JsonPrimitive).content) }
        val graph = Json.parseToJsonElement(extracted.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
        assertEquals(listOf("root", "provisional", "accepted"), (graph.getValue("nodes") as JsonArray).map {
            (it.jsonObject.getValue("status") as JsonPrimitive).content
        })
    }

    @Test
    fun `schema six recorded pending witness includes provisional paths through preindex recovery`() {
        val project = generatedProject()
        val beta = project.resolve("src/modules/beta.c")
        val betaBefore = beta.readBytes()
        val alpha = project.resolve("src/modules/alpha.c")
        val alphaBefore = alpha.readBytes()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val metadata = beginSyntheticAcceptedRun(graph)
            val provisional = graph.beginAttempt(listOf("src/modules/beta.c"), metadata)
            graph.installCandidate(provisional, mapOf(
                "src/modules/beta.c" to betaBefore + "\n/* provisional witness */\n".toByteArray(),
            ))
            graph.recordProvisional(
                provisional,
                RepairEvidence("behavior", "synthetic retained mismatch"),
                syntheticAcceptedProof(graph, provisional),
            )

            val corpus = graph.retainedRegressionCorpus()
            graph.beginAttempt(listOf("src/modules/alpha.c"), RevisionRepairMetadata(
                iterationIndex = 2,
                failureKind = "compile",
                prompt = "second synthetic attempt",
                summary = null,
                retainedRegressionIds = corpus.inputs.map { it.id },
                before = null,
                regressionCorpusSha256 = corpus.sha256,
            ))
            val pending = Json.parseToJsonElement(
                project.resolve("reports/repair-revisions/graph.json").readText(),
            ).jsonObject.getValue("pending").jsonObject
            assertEquals(
                listOf("src/modules/alpha.c", "src/modules/beta.c"),
                pending.getValue("preimageMetadata").jsonObject.keys.sorted(),
            )
        }

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(ModuleRevisionStatus.REJECTED, recovered.snapshot.nodes.last().status)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
            assertContentEquals(alphaBefore, alpha.readBytes())
            assertContentEquals(betaBefore, beta.readBytes())
        }
    }

    @Test
    fun `schema six final decision rechecks metadata for provisional promotion paths`() {
        val project = generatedProject()
        val beta = project.resolve("src/modules/beta.c")
        val betaBefore = beta.readBytes()
        val alpha = project.resolve("src/modules/alpha.c")
        val alphaBefore = alpha.readBytes()
        var injected = false
        ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (!injected && point == ModuleRevisionFaultPoint.Schema6DecisionPrevalidated) {
                    injected = true
                    Files.setPosixFilePermissions(
                        beta,
                        Files.getPosixFilePermissions(beta, LinkOption.NOFOLLOW_LINKS) + PosixFilePermission.OWNER_EXECUTE,
                    )
                }
            },
        ).use { graph ->
            val firstMetadata = beginSyntheticAcceptedRun(graph)
            val provisional = graph.beginAttempt(listOf("src/modules/beta.c"), firstMetadata)
            graph.installCandidate(provisional, mapOf(
                "src/modules/beta.c" to betaBefore + "\n/* provisional-only contribution */\n".toByteArray(),
            ))
            graph.recordProvisional(
                provisional,
                RepairEvidence("behavior", "retain provisional contribution"),
                syntheticAcceptedProof(graph, provisional),
            )

            val corpus = graph.retainedRegressionCorpus()
            val secondMetadata = firstMetadata.copy(
                iterationIndex = 2,
                prompt = "accept composed candidate",
                retainedRegressionIds = corpus.inputs.map { it.id },
                regressionCorpusSha256 = corpus.sha256,
            )
            val accepted = graph.beginAttempt(listOf("src/modules/alpha.c"), secondMetadata)
            graph.installCandidate(accepted, mapOf(
                "src/modules/alpha.c" to alphaBefore + "\n/* accepted contribution */\n".toByteArray(),
            ))

            assertFailsWith<IllegalArgumentException> {
                graph.accept(
                    accepted,
                    RepairEvidence("valid", "must recheck the complete promotion witness"),
                    syntheticAcceptedProof(graph, accepted),
                )
            }

            assertTrue(injected)
            assertEquals(accepted.id, graph.snapshot.pendingAttemptId)
            assertEquals(provisional.id, graph.snapshot.provisionalHeadId)
            assertNull(graph.snapshot.fullyAcceptedHeadId)
            val persisted = Json.parseToJsonElement(
                project.resolve("reports/repair-revisions/graph.json").readText(),
            ).jsonObject.getValue("pending").jsonObject
            assertEquals(JsonNull, persisted.getValue("acceptanceDecision"))
            val staging = project.resolve("reports/repair-revisions/publication-staging")
            assertEquals(0L, Files.list(staging).use { it.count() })
        }
    }

    @Test
    fun `self-hashed partial legacy graph cannot exempt a missing physical publication plan`() {
        val fixture = releaseRepairFixture()
        val graphPath = fixture.project.resolve("reports/repair-revisions/graph.json")
        val original = graphPath.readText()
        val document = Json.parseToJsonElement(original).jsonObject
        val nodes = document.getValue("nodes").jsonArray.mapIndexed { index, element ->
            if (index != document.getValue("nodes").jsonArray.lastIndex) element else {
                val node = element.jsonObject
                JsonObject(node + mapOf(
                    "publicationChanges" to JsonArray(emptyList()),
                    "publicationPreimageMetadata" to JsonObject(emptyMap()),
                ))
            }
        }
        graphPath.writeText(canonicalRepairGraphFixture(JsonObject(document + ("nodes" to JsonArray(nodes))).toString(), original))
        assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("stripped-plan-no-origin.zip"))
        }

        val currentNodeId = document.getValue("nodes").jsonArray.last().jsonObject
            .getValue("id").jsonPrimitive.content
        val fakeLegacy = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(4),
            "nodes" to JsonArray(listOf(JsonObject(mapOf("id" to JsonPrimitive(currentNodeId))))),
        )).toString().toByteArray()
        val fakeName = "legacy-graph-${sha256(fakeLegacy)}.json"
        Files.write(fixture.project.resolve("reports/repair-revisions/$fakeName"), fakeLegacy)
        val output = fixture.project.parent.resolve("fake-origin.zip")
        assertFailsWith<IllegalArgumentException> { ArchivalPackager.create(fixture.project, output) }
        assertFalse(output.exists())
        Files.delete(fixture.project.resolve("reports/repair-revisions/$fakeName"))

        val legacyCopy = authoredLegacyGraphFixture(original, 4)
        val legacyDocument = Json.parseToJsonElement(legacyCopy).jsonObject
        val runlessLegacy = canonicalRepairGraphFixture(
            JsonObject(legacyDocument + ("runs" to JsonArray(emptyList()))).toString(),
            legacyCopy,
        ).toByteArray()
        val runlessName = "legacy-graph-${sha256(runlessLegacy)}.json"
        Files.write(fixture.project.resolve("reports/repair-revisions/$runlessName"), runlessLegacy)
        val runlessOutput = fixture.project.parent.resolve("runless-origin.zip")
        assertFailsWith<IllegalArgumentException> { ArchivalPackager.create(fixture.project, runlessOutput) }
        assertFalse(runlessOutput.exists())
    }

    @Test
    fun `archive retains exhausted provisional evidence without accepting its abandoned source changes`() {
        val fixture = releaseRepairFixture(includeProvisional = true, abandonProvisional = true)
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("abandoned-repair.zip"))
        val extracted = fixture.project.parent.resolve("abandoned-repair-extracted")
        val lineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(bundle.archivePath, extracted)
        assertEquals(listOf(fixture.relativePath), lineage.source.acceptedAcpContributions.map { it.changes.single().path })
        assertFalse(extracted.resolve("src/modules/beta.c").readText().contains("provisional archive improvement"))
        assertTrue(extracted.resolve("reports/archive-provisional.validation.json").exists())
        val graph = Json.parseToJsonElement(extracted.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
        assertEquals(listOf("iteration_exhausted", "fully_accepted"), (graph.getValue("runs") as JsonArray).map {
            (it.jsonObject.getValue("status") as JsonPrimitive).content
        })
        assertEquals(listOf("root", "provisional", "accepted"), (graph.getValue("nodes") as JsonArray).map {
            (it.jsonObject.getValue("status") as JsonPrimitive).content
        })
    }

    @Test
    fun `archive accepts a complete legacy origin after the current regression corpus grows`() {
        val fixture = releaseRepairFixture(
            legacyRejectedPrefix = true,
            growRegressionCorpusAfterLegacyPrefix = true,
        )
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("legacy-corpus-growth.zip"))
        val extracted = fixture.project.parent.resolve("legacy-corpus-growth-extracted")
        ArchivalBundleVerifier.extractAndVerifyCandidateLineage(bundle.archivePath, extracted)
    }

    @Test
    fun `archive creation rejects missing extra stale and cross-paired repair evidence`() {
        data class Mutation(val label: String, val expected: String, val apply: (ReleaseRepairFixture) -> Unit)
        val mutations = listOf(
            Mutation("missing-graph", "missing repair_history", { fixture ->
                Files.delete(fixture.project.resolve("reports/repair-revisions/graph.json"))
            }),
            Mutation("missing-history", "missing repair_history", { fixture ->
                Files.delete(fixture.project.resolve("reports/repair_history.json"))
            }),
            Mutation("missing-receipt", "missing, extra, or stale ACP receipts", { fixture ->
                Files.delete(fixture.project.resolve(fixture.receiptPath))
            }),
            Mutation("extra-receipt", "missing, extra, or stale ACP receipts", { fixture ->
                Files.copy(
                    fixture.project.resolve(fixture.receiptPath),
                    fixture.project.resolve("reports/repair-revisions/revision_99999999_stale.acp-receipt.json"),
                )
            }),
            Mutation("cross-paired", "cross-paired", { fixture ->
                val graph = fixture.project.resolve("reports/repair-revisions/graph.json")
                graph.writeText(
                    graph.readText().replaceFirst(
                        "\"requestSha256\":\"${fixture.requestSha256}\"",
                        "\"requestSha256\":\"${"0".repeat(64)}\"",
                    ),
                )
            }),
            Mutation("removed-physical-plan", "schema-6 accepted repair release node lacks exact publication and ancestor metadata", { fixture ->
                val graph = fixture.project.resolve("reports/repair-revisions/graph.json")
                val document = Json.parseToJsonElement(graph.readText()).jsonObject
                val nodes = document.getValue("nodes").jsonArray.mapIndexed { index, element ->
                    if (index != document.getValue("nodes").jsonArray.lastIndex) element else {
                        val node = element.jsonObject
                        JsonObject(node + mapOf(
                            "publicationChanges" to JsonArray(emptyList()),
                            "publicationPreimageMetadata" to JsonObject(emptyMap()),
                        ))
                    }
                }
                graph.writeText(JsonObject(document + ("nodes" to JsonArray(nodes))).toString())
            }),
            Mutation("stale-history", "history is cross-paired", { fixture ->
                val history = fixture.project.resolve("reports/repair_history.json")
                history.writeText(
                    history.readText().replaceFirst(
                        "\"assessmentStatus\":\"accepted\"",
                        "\"assessmentStatus\":\"rejected\"",
                    ),
                )
            }),
            Mutation("legacy-schema", "schema-v1/v2 repair evidence is non-release", { fixture ->
                val graph = fixture.project.resolve("reports/repair-revisions/graph.json")
                graph.writeText(authoredLegacyGraphFixture(graph.readText(), 1))
            }),
            Mutation("receipt-record-cross-pair", "records differ from the exact workflow change set", { fixture ->
                val receipt = fixture.project.resolve(fixture.receiptPath)
                val oldReceiptSha256 = sha256(receipt.readBytes())
                val expectedPathCommitment = sha256(fixture.relativePath.toByteArray())
                val otherSameLengthPath = "src/modules/bravo.c"
                check(otherSameLengthPath.toByteArray().size == fixture.relativePath.toByteArray().size)
                receipt.writeText(
                    receipt.readText().replace(
                        expectedPathCommitment,
                        sha256(otherSameLengthPath.toByteArray()),
                    ),
                )
                val newReceiptSha256 = sha256(receipt.readBytes())
                listOf(
                    "reports/repair-revisions/graph.json",
                    "reports/repair_history.json",
                ).forEach { relative ->
                    val path = fixture.project.resolve(relative)
                    path.writeText(path.readText().replace(oldReceiptSha256, newReceiptSha256))
                }
            }),
        )

        mutations.forEach { mutation ->
            val fixture = releaseRepairFixture()
            mutation.apply(fixture)
            val failure = assertFailsWith<IllegalArgumentException>(mutation.label) {
                ArchivalPackager.create(
                    fixture.project,
                    fixture.project.parent.resolve("${mutation.label}.zip"),
                )
            }
            assertTrue(failure.message.orEmpty().contains(mutation.expected), failure.message)
        }
    }

    @Test
    fun `repair assessment provenance is cross checked against the immutable ACP receipt`() {
        val fields = listOf(
            "sessionIdSha256" to "0".repeat(64),
            "updatesSha256" to "1".repeat(64),
            "normalizedStopReason" to "no_changes",
            "policySha256" to "2".repeat(64),
        )
        fields.forEach { (field, replacement) ->
            val fixture = releaseRepairFixture(schema7AgentEvidence = true)
            val graphPath = fixture.project.resolve("reports/repair-revisions/graph.json")
            val graph = Json.parseToJsonElement(graphPath.readText()).jsonObject
            val acceptedNode = graph.getValue("nodes").jsonArray.last().jsonObject
            val invocation = acceptedNode.getValue("repairMetadata").jsonObject
                .getValue("agentInvocation").jsonObject
            val assessmentPath = fixture.project.resolve(invocation.getValue("assessmentPath").jsonPrimitive.content)
            val oldDigest = invocation.getValue("assessmentSha256").jsonPrimitive.content
            val changedAssessment = JsonObject(
                Json.parseToJsonElement(assessmentPath.readText()).jsonObject +
                    (field to JsonPrimitive(replacement)),
            )
            val bytes = OracleJson.canonicalBytes(changedAssessment, StrictJsonLimits())
            val newDigest = sha256(bytes)
            assessmentPath.writeBytes(bytes)
            listOf(graphPath, fixture.project.resolve("reports/repair_history.json")).forEach { path ->
                path.writeText(path.readText().replace(oldDigest, newDigest))
            }

            val failure = assertFailsWith<IllegalArgumentException>(field) {
                ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile)
            }
            assertTrue(failure.message.orEmpty().contains("assessment") ||
                failure.message.orEmpty().contains("invocation"), failure.message)
        }
    }

    @Test
    fun `ordinary pre-decision cancellation may reject a validated assessment after verified rollback`() {
        val fixture = releaseRepairFixture(
            schema7AgentEvidence = true,
            cancelAfterValidatedAssessment = true,
        )

        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).use { graph ->
            val rejected = graph.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertFalse(rejected.recoveredAfterCrash)
            assertEquals(RepairRollbackState.NOT_REQUIRED_VERIFIED, rejected.rollbackRecord?.state)
            assertFalse(rejected.rollbackRecord?.candidateSourceInstallStarted ?: true)
            val invocation = requireNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, invocation.assessmentStatus)
            val assessment = decompengine.project.AcpChangeAssessment.parse(
                fixture.project.resolve(requireNotNull(invocation.assessmentPath)).readBytes(),
            )
            assertEquals(
                decompengine.project.AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION,
                assessment.eligibility,
            )
        }
    }

    @Test
    fun `archive creation rejects a pending repair assessment`() {
        val fixture = releaseRepairFixture()
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).use { graph ->
            val corpus = graph.retainedRegressionCorpus()
            graph.beginRun(1, 60_000)
            graph.beginAttempt(
                listOf(fixture.relativePath),
                RevisionRepairMetadata(
                    iterationIndex = 2,
                    failureKind = "compile",
                    prompt = "second bounded failure",
                    summary = null,
                    retainedRegressionIds = corpus.inputs.map(ProcessInput::id),
                    before = null,
                    regressionCorpusSha256 = corpus.sha256,
                ),
            )
            graph.synchronizeRepairHistory()
        }

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("pending.zip"))
        }
        assertTrue(failure.message.orEmpty().contains("pending workflow assessment"), failure.message)
    }

    @Test
    fun `archive validation recomputes source corpus runtime and behavior authority from receipt bytes`() {
        fun JsonObject.changed(field: String, value: JsonElement) = JsonObject(toMutableMap().apply { put(field, value) })
        fun JsonObject.scopeChanged(index: Int, change: (JsonObject) -> JsonObject): JsonObject {
            val scopes = (getValue("scopes") as JsonArray).toMutableList()
            scopes[index] = change(scopes[index].jsonObject)
            return changed("scopes", JsonArray(scopes))
        }
        data class Mutation(val label: String, val expected: String, val change: (JsonObject) -> JsonObject)
        val mutations = listOf(
            Mutation("snapshot", "source manifest", { receipt -> receipt.changed("sourceSnapshot",
                receipt.getValue("sourceSnapshot").jsonObject.changed("manifestSha256", JsonPrimitive("0".repeat(64)))) }),
            Mutation("runtime", "runtime configuration", { it.changed("runtimeConfiguration", JsonObject(emptyMap())) }),
            Mutation("behavior-budgets", "behavior budgets differ", { receipt ->
                val evidence = receipt.getValue("behaviorBudgetEvidence").jsonObject
                val limits = evidence.getValue("effectiveLimits").jsonObject
                receipt.changed("behaviorBudgetEvidence", evidence.changed("effectiveLimits",
                    limits.changed("maximumExecutionMillis", JsonPrimitive(1)))) }),
            Mutation("corpus", "retained corpus", { it.changed("inputs", JsonArray(emptyList())) }),
            Mutation("omitted-scope", "scope inventory", { it.changed("scopes", JsonArray((it.getValue("scopes") as JsonArray).dropLast(1))) }),
            Mutation("case-count", "scope inventory", { it.changed("caseCount", JsonPrimitive(0)) }),
            Mutation("cleanup", "contained validation authority", { it.changed("cleanupVerified", JsonPrimitive(false)) }),
            Mutation("reference-binary", "executable identity", { receipt -> receipt.changed("originalExecutable",
                receipt.getValue("originalExecutable").jsonObject.changed("sha256", JsonPrimitive("0".repeat(64)))) }),
            Mutation("forged-match", "every retained observation", { receipt -> receipt.scopeChanged(2) { scope ->
                scope.changed("output", scope.getValue("output").jsonObject.changed("stderrBase64", JsonPrimitive("YQ=="))) } }),
            Mutation("changed-reference", "reference observations", { receipt ->
                var changed = receipt
                listOf(1, 2).forEach { index -> changed = changed.scopeChanged(index) { scope ->
                    scope.changed("output", scope.getValue("output").jsonObject.changed("stdoutBase64", JsonPrimitive("YQ=="))) } }
                changed
            }),
            Mutation("unbounded-quota", "finite dedicated", { receipt -> receipt.scopeChanged(0) { scope ->
                scope.changed("writableQuota", scope.getValue("writableQuota").jsonObject.changed("maximumEntries", JsonPrimitive(0))) } }),
        )
        mutations.forEach { mutation ->
            val fixture = releaseRepairFixture()
            val receipt = fixture.project.resolve("reports/archive-fixture.validation.json")
            val oldDigest = sha256(receipt.readBytes())
            receipt.writeBytes(OracleJson.canonicalBytes(mutation.change(Json.parseToJsonElement(receipt.readText()).jsonObject), StrictJsonLimits()))
            val newDigest = sha256(receipt.readBytes())
            // Update the outer proof commitment to reach independent receipt-content admission.
            val graph = fixture.project.resolve("reports/repair-revisions/graph.json")
            graph.writeText(graph.readText().replace(oldDigest, newDigest))
            val failure = assertFailsWith<IllegalArgumentException>(mutation.label) {
                ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("${mutation.label}.zip"))
            }
            assertTrue(failure.message.orEmpty().contains(mutation.expected), "${mutation.label}: ${failure.message}")
        }
        val fixture = releaseRepairFixture()
        Files.delete(fixture.project.resolve("reports/archive-fixture.validation.json"))
        val missing = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("missing-validation.zip"))
        }
        assertTrue(missing.message.orEmpty().contains("validation receipt is missing"), missing.message)
    }

    @Test
    fun `archive extraction independently rejects missing and stale repair assessments`() {
        listOf("missing-receipt", "stale-history").forEach { mutation ->
            val fixture = releaseRepairFixture()
            val valid = ArchivalPackager.create(
                fixture.project,
                fixture.project.parent.resolve("valid-$mutation.zip"),
            )
            val tampered = fixture.project.parent.resolve("tampered-$mutation.zip")
            rewriteArchive(valid.archivePath, tampered) { entries ->
                when (mutation) {
                    "missing-receipt" -> entries.remove(fixture.receiptPath)
                    "stale-history" -> {
                        val path = "reports/repair_history.json"
                        entries[path] = requireNotNull(entries[path]).toString(Charsets.UTF_8)
                            .replaceFirst(
                                "\"assessmentStatus\":\"accepted\"",
                                "\"assessmentStatus\":\"rejected\"",
                            ).toByteArray()
                    }
                }
            }

            val failure = assertFailsWith<IllegalArgumentException>(mutation) {
                ArchivalBundleVerifier.extractAndVerify(
                    tampered,
                    fixture.project.parent.resolve("extract-$mutation"),
                )
            }
            val expected = if (mutation == "missing-receipt") {
                "missing, extra, or stale ACP receipts"
            } else {
                "history is cross-paired"
            }
            assertTrue(failure.message.orEmpty().contains(expected), failure.message)
        }
    }

    @Test
    fun `context and patch resource budgets are enforced`() {
        val contextProject = generatedProject()
        val tinyContext = RepairResourceBudget(maximumContextBytes = 64, maximumPatchBytes = 32)
        assertFailsWith<RepairBudgetExceededException> {
            ModuleRepairIndex.load(contextProject, GeneratedCRepairIndexProfile, tinyContext).select("compile", "src/modules/alpha.c: error")
        }

        val patchProject = generatedProject()
        val tinyPatch = RepairResourceBudget(maximumPatchBytes = 8)
        ModuleRevisionGraph.open(patchProject, GeneratedCRepairIndexProfile, tinyPatch).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            assertFailsWith<RepairBudgetExceededException> {
                graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to ByteArray(9)))
            }
            graph.reject(attempt, RepairEvidence("budget", "candidate exceeded patch budget"))
        }
    }

    @Test
    fun `sparse index selects bounded context for more than five thousand functions`() {
        val project = createTempDirectory("repair-index-scale-").resolve("project")
        createScaleProject(project, moduleCount = 256, functionsPerModule = 20)

        val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
        val selection = index.select("compile", "src/modules/module_0255.c:99: error: invalid initializer")

        assertEquals(256, index.moduleIds.size)
        assertEquals(listOf("module_0255"), selection.seedModules)
        assertEquals(listOf("module_0254"), selection.dependencyModules)
        assertTrue(selection.readablePaths.size <= 6)
        assertFalse(selection.readablePaths.any { "module_0000" in it })
        assertTrue(selection.totalBytes < RepairResourceBudget().maximumContextBytes)

        val bounded = RepairResourceBudget(maximumContextModules = 3)
        val behavior = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile, bounded).select("behavior", "module_0255")
        assertEquals(listOf("module_0253", "module_0254"), behavior.dependencyModules)
        assertTrue("module_0252" in behavior.deferredModules)
        assertEquals(
            listOf("include/modules/module_0255.h", "src/modules/module_0255.c", "src/modules/module_0255_internal.h"),
            behavior.writablePaths,
        )
    }

    @Test
    fun `same JVM aliases wait and a graph opened on one thread can close on another`() {
        val project = generatedProject()
        val aliasContainer = createTempDirectory("repair-root-alias-")
        val parentAlias = aliasContainer.resolve("project-parent")
        Files.createSymbolicLink(parentAlias, project.parent)
        val alias = parentAlias.resolve(project.fileName)
        val first = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val started = CountDownLatch(1)
        val acquired = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val waiter = executor.submit<ModuleRevisionGraph> {
                started.countDown()
                ModuleRevisionGraph.open(alias, GeneratedCRepairIndexProfile).also { acquired.countDown() }
            }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            assertFalse(acquired.await(200, TimeUnit.MILLISECONDS), "same-root alias bypassed JVM coordination")

            val closeFailure = AtomicReference<Throwable?>()
            val closer = Thread({
                runCatching(first::close).exceptionOrNull()?.let(closeFailure::set)
            }, "repair-graph-cross-thread-close")
            closer.start()
            closer.join(5_000)
            assertFalse(closer.isAlive, "cross-thread graph close did not finish")
            assertEquals(null, closeFailure.get())

            assertTrue(acquired.await(5, TimeUnit.SECONDS), "same-JVM waiter did not progress after close")
            waiter.get(5, TimeUnit.SECONDS).close()
        } finally {
            runCatching(first::close)
            executor.shutdownNow()
        }
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
    }

    @Test
    fun `open graph remains bound to renamed root while replacement root uses independent locks`() {
        val original = generatedProject()
        val replacementSeed = generatedProject()
        val renamed = original.parent.resolve("renamed-project")
        val graph = ModuleRevisionGraph.openLegacyForTesting(original, GeneratedCRepairIndexProfile)
        Files.move(original, renamed)
        Files.move(replacementSeed, original)
        val originalTarget = renamed.resolve("src/modules/alpha.c")
        val replacementTarget = original.resolve("src/modules/alpha.c")
        val parent = originalTarget.readBytes()
        val replacementBytes = replacementTarget.readBytes()

        val contender = Executors.newSingleThreadExecutor()
        try {
            val replacementGraph = contender.submit<ModuleRevisionGraph> {
                ModuleRevisionGraph.open(original, GeneratedCRepairIndexProfile)
            }.get(5, TimeUnit.SECONDS)
            replacementGraph.close()

            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            val candidate = parent + "\n/* pinned renamed root */\n".toByteArray()
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
            assertContentEquals(candidate, originalTarget.readBytes())
            assertContentEquals(replacementBytes, replacementTarget.readBytes())
            graph.reject(attempt, RepairEvidence("test", "renamed root stayed pinned"))
            assertContentEquals(parent, originalTarget.readBytes())
            assertContentEquals(replacementBytes, replacementTarget.readBytes())
        } finally {
            runCatching(graph::close)
            contender.shutdownNow()
        }
    }

    @Test
    fun `durable graph publication crash points recover an exact pending attempt`() {
        val stages: List<(ModuleRevisionFaultPoint) -> Boolean> = listOf(
            { point ->
                point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                    point.scope == "revision-state" && point.name == "graph.json"
            },
            { point ->
                point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                    point.scope == "revision-state" && point.name == "graph.json"
            },
        )
        stages.forEachIndexed { stageIndex, matches ->
            val project = generatedProject()
            val target = project.resolve("src/modules/alpha.c")
            val accepted = target.readBytes()
            var armed = false
            val graph = ModuleRevisionGraph.openLegacyForTesting(
                project,
                GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (armed && matches(point)) throw SimulatedRepairCrash()
                },
            )
            graph.enableRunContract()
            armed = true

            assertFailsWith<SimulatedRepairCrash>("state publication stage $stageIndex") {
                graph.beginAttempt(listOf("src/modules/alpha.c"))
            }
            assertFailsWith<IllegalStateException> {
                graph.snapshot
            }
            graph.close()
            assertContentEquals(accepted, target.readBytes())

            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
                assertEquals(null, recovered.snapshot.pendingAttemptId)
                assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
                assertContentEquals(accepted, target.readBytes())
            }
            assertFalse(
                project.resolve("reports/repair-revisions/.graph.json.repair-atomic.tmp").exists(),
                "state publication stage $stageIndex left its exact recovery name",
            )
        }
    }

    @Test
    fun `non-exception termination preserves crash residue and poisons the live graph`() {
        val project = generatedProject()
        var armed = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                    point.scope == "revision-state" && point.name == "graph.json"
                ) {
                    throw SimulatedRepairTermination()
                }
            },
        )
        graph.enableRunContract()
        armed = true

        assertFailsWith<SimulatedRepairTermination> {
            graph.beginAttempt(listOf("src/modules/alpha.c"))
        }
        assertTrue(project.resolve("reports/repair-revisions/.graph.json.repair-atomic.tmp").exists())
        assertFailsWith<IllegalStateException> { graph.snapshot }
        graph.close()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(null, recovered.snapshot.pendingAttemptId)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
        }
    }

    @Test
    fun `ordinary state publication faults agree with the durable commit boundary`() {
        run {
            val project = generatedProject()
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            var armed = false
            var injected = false
            val graph = ModuleRevisionGraph.openForTesting(
                project,
                GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (armed && !injected &&
                        point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                        point.scope == "revision-state" && point.name == "graph.json"
                    ) {
                        injected = true
                        throw IllegalStateException("ordinary precommit publication fault")
                    }
                },
            )
            val before = graphPath.readBytes()
            armed = true

            assertFailsWith<IllegalStateException> {
                graph.beginAttempt(listOf("src/modules/alpha.c"))
            }
            assertEquals(null, graph.snapshot.pendingAttemptId)
            assertContentEquals(before, graphPath.readBytes())
            assertFalse(project.resolve("reports/repair-revisions/.graph.json.repair-atomic.tmp").exists())
            graph.close()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
                assertEquals(null, reopened.snapshot.pendingAttemptId)
            }
        }

        run {
            val project = generatedProject()
            var armed = false
            var injected = false
            val graph = ModuleRevisionGraph.openForTesting(
                project,
                GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (armed && !injected &&
                        point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                        point.scope == "revision-state" && point.name == "graph.json"
                    ) {
                        injected = true
                        throw IllegalStateException("ordinary postcommit publication fault")
                    }
                },
            )
            armed = true

            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
            assertTrue(project.resolve("reports/repair-revisions/graph.json").readText().contains(attempt.id))
            graph.reject(attempt, RepairEvidence("test", "postcommit fault was a committed success"))
            graph.close()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
                assertEquals(ModuleRevisionStatus.REJECTED, reopened.snapshot.nodes.last().status)
            }
        }
    }

    @Test
    fun `projection capacity is reserved before pending and completed state commits`() {
        run {
            val project = generatedProject()
            val budget = RepairResourceBudget(maximumProjectionBytes = 512)
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val corpus = graph.retainedRegressionCorpus()
                assertFailsWith<RepairBudgetExceededException> {
                    graph.beginAttempt(
                        listOf("src/modules/alpha.c"),
                        RevisionRepairMetadata(
                            1,
                            "compile",
                            "bounded failure",
                            null,
                            emptyList(),
                            null,
                            corpus.sha256,
                        ),
                    )
                }
                assertEquals(null, graph.snapshot.pendingAttemptId)
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { reopened ->
                assertEquals(null, reopened.snapshot.pendingAttemptId)
            }
        }

        run {
            val project = generatedProject()
            val target = project.resolve("src/modules/alpha.c")
            val accepted = target.readBytes()
            val budget = RepairResourceBudget(maximumProjectionBytes = 16L * 1024)
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val corpus = graph.retainedRegressionCorpus()
                val metadata = beginSyntheticAcceptedRun(graph, template = RevisionRepairMetadata(
                    1,
                    "compile",
                    "repair one module",
                    "bounded summary",
                    emptyList(),
                    null,
                    corpus.sha256,
                    publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE,
                ))
                val attempt = graph.beginAttempt(
                    listOf("src/modules/alpha.c"),
                    metadata,
                )
                graph.installCandidate(
                    attempt,
                    mapOf("src/modules/alpha.c" to accepted + "\n/* candidate */\n".toByteArray()),
                )

                assertFailsWith<RepairBudgetExceededException> {
                    graph.accept(attempt, RepairEvidence("valid", "x".repeat(5_000)),
                        syntheticAcceptedProof(graph, attempt))
                }
                assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
                graph.reject(attempt, RepairEvidence("projection-budget", "oversized acceptance evidence rejected"))
                assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                assertContentEquals(accepted, target.readBytes())
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { reopened ->
                assertEquals(ModuleRevisionStatus.REJECTED, reopened.snapshot.nodes.last().status)
                assertEquals(null, reopened.snapshot.pendingAttemptId)
            }
        }
    }

    @Test
    fun `pending candidate reserves graph bytes for deterministic recovery`() {
        val project = genericProject("repair-recovery-graph-budget-", mapOf("code/unit.src" to "unit\n"))
        val modules = (0 until 256).map { index ->
            val id = "module_${index.toString().padStart(3, '0')}"
            RepairModuleEvidence(
                id = id,
                ownedPaths = if (index == 0) listOf("code/unit.src") else emptyList(),
                dependencyModuleIds = if (index == 0) {
                    emptyList()
                } else {
                    listOf("module_${(index - 1).toString().padStart(3, '0')}")
                },
            )
        }
        val profile = DeclarativeRepairIndexProfile(
            "recovery-graph-budget-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/unit.src"),
                editablePaths = listOf("code/unit.src"),
                modules = modules,
            ),
        )
        val budget = RepairResourceBudget(maximumGraphBytes = 6L * 1024)
        val target = project.resolve("code/unit.src")
        val before = target.readBytes()

        ModuleRevisionGraph.open(project, profile, budget).use { graph ->
            val attempt = graph.beginAttempt(listOf("code/unit.src"))
            val failure = assertFailsWith<RepairBudgetExceededException> {
                graph.installCandidate(attempt, mapOf("code/unit.src" to "changed\n".toByteArray()))
            }
            assertTrue(failure.message.orEmpty().contains("graph"))
            assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        }

        ModuleRevisionGraph.open(project, profile, budget).use { recovered ->
            assertEquals(null, recovered.snapshot.pendingAttemptId)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
            assertContentEquals(before, target.readBytes())
        }
    }

    @Test
    fun `startup removes a bounded crashed blob atomic before graph recovery`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val accepted = target.readBytes()
        var armed = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterStateTemporaryDirectorySync &&
                    point.scope == "revision-blob"
                ) {
                    throw SimulatedRepairCrash()
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
        armed = true

        assertFailsWith<SimulatedRepairCrash> {
            graph.installCandidate(
                attempt,
                mapOf("src/modules/alpha.c" to accepted + "\n/* interrupted blob */\n".toByteArray()),
            )
        }
        graph.close()
        val blobs = project.resolve("reports/repair-revisions/blobs")
        assertTrue(Files.list(blobs).use { entries ->
            entries.anyMatch { it.fileName.toString().matches(Regex("\\.[0-9a-f]{64}\\.repair-atomic\\.tmp")) }
        })

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(null, recovered.snapshot.pendingAttemptId)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
            assertContentEquals(accepted, target.readBytes())
        }
        assertFalse(Files.list(blobs).use { entries ->
            entries.anyMatch { it.fileName.toString().endsWith(".repair-atomic.tmp") }
        })
    }

    @Test
    fun `invalid state targets do not leak descriptors across rejected writes`() {
        val project = createTempDirectory("repair-invalid-state-fd-").resolve("project")
        project.resolve("reports/repair-revisions/blobs").createDirectories()
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        graphPath.writeText("invalid")
        Files.createLink(project.resolve("reports/repair-revisions/graph.alias"), graphPath)

        LinuxFilesystemSyscalls.openRoot(project).use { root ->
            RepairStateStore.open(root).use { store ->
                val before = Files.list(Path.of("/proc/self/fd")).use { it.count() }
                repeat(128) {
                    assertFailsWith<IllegalArgumentException> { store.writeGraph("state".toByteArray()) }
                }
                val after = Files.list(Path.of("/proc/self/fd")).use { it.count() }
                assertEquals(before, after)
            }
        }
    }

    @Test
    fun `open graph keeps all repair state bound when the reports name is replaced`() {
        val project = generatedProject()
        val reports = project.resolve("reports")
        val heldReports = project.resolve("reports-held")
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val heldGraph = reports.resolve("repair-revisions/graph.json")
        val before = heldGraph.readBytes()

        Files.move(reports, heldReports)
        reports.resolve("repair-revisions/blobs").createDirectories()
        val replacementGraph = reports.resolve("repair-revisions/graph.json")
        val canary = "replacement state must remain untouched\n".toByteArray()
        replacementGraph.writeBytes(canary)

        try {
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            graph.reject(attempt, RepairEvidence("test", "descriptor-pinned state stayed bound"))
            assertContentEquals(canary, replacementGraph.readBytes())
            assertFalse(reports.resolve("source_revisions.jsonl").exists())
            assertFalse(before.contentEquals(heldReports.resolve("repair-revisions/graph.json").readBytes()))
        } finally {
            graph.close()
        }

        Files.delete(replacementGraph)
        Files.delete(reports.resolve("repair-revisions/blobs"))
        Files.delete(reports.resolve("repair-revisions"))
        Files.delete(reports)
        Files.move(heldReports, reports)
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            assertEquals(null, reopened.snapshot.pendingAttemptId)
            assertEquals(ModuleRevisionStatus.REJECTED, reopened.snapshot.nodes.last().status)
        }
    }

    @Test
    fun `ancestor retarget cannot redirect an open graph or share replacement locks`() {
        val original = generatedProject()
        val replacement = generatedProject()
        val aliasContainer = createTempDirectory("repair-ancestor-retarget-")
        val parentAlias = aliasContainer.resolve("parent")
        Files.createSymbolicLink(parentAlias, original.parent)
        val alias = parentAlias.resolve(original.fileName)
        val graph = ModuleRevisionGraph.openLegacyForTesting(alias, GeneratedCRepairIndexProfile)
        Files.delete(parentAlias)
        Files.createSymbolicLink(parentAlias, replacement.parent)
        val originalTarget = original.resolve("src/modules/alpha.c")
        val replacementTarget = replacement.resolve("src/modules/alpha.c")
        val parent = originalTarget.readBytes()
        val replacementBytes = replacementTarget.readBytes()

        val contender = Executors.newSingleThreadExecutor()
        try {
            val replacementGraph = contender.submit<ModuleRevisionGraph> {
                ModuleRevisionGraph.open(alias, GeneratedCRepairIndexProfile)
            }.get(5, TimeUnit.SECONDS)
            replacementGraph.close()

            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            val candidate = parent + "\n/* pinned ancestor */\n".toByteArray()
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
            assertContentEquals(candidate, originalTarget.readBytes())
            assertContentEquals(replacementBytes, replacementTarget.readBytes())
            graph.reject(attempt, RepairEvidence("test", "ancestor retarget stayed pinned"))
        } finally {
            runCatching(graph::close)
            contender.shutdownNow()
        }
        assertContentEquals(parent, originalTarget.readBytes())
        assertContentEquals(replacementBytes, replacementTarget.readBytes())
    }

    @Test
    fun `reentrant close and same-root open cannot release or bypass an active operation`() {
        val project = generatedProject()
        val closeFailure = AtomicReference<Throwable?>()
        val openFailure = AtomicReference<Throwable?>()
        lateinit var graph: ModuleRevisionGraph
        graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePreimageRead) {
                    closeFailure.set(runCatching(graph::close).exceptionOrNull())
                    openFailure.set(
                        runCatching {
                            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).close()
                        }.exceptionOrNull(),
                    )
                }
            },
        )

        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
        assertTrue(closeFailure.get() is IllegalStateException)
        assertTrue(openFailure.get() is IllegalStateException)
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        graph.reject(attempt, RepairEvidence("test", "reentrant close/open rejected"))
        graph.close()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
    }

    @Test
    fun `close and contender remain blocked until an in-flight graph operation exits`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val before = target.readBytes()
        val operationEntered = CountDownLatch(1)
        val releaseOperation = CountDownLatch(1)
        val closeStarted = CountDownLatch(1)
        val closeCompleted = CountDownLatch(1)
        val contenderStarted = CountDownLatch(1)
        val contenderAcquired = CountDownLatch(1)
        val graph = ModuleRevisionGraph.openLegacyForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePreimageRead) {
                    operationEntered.countDown()
                    assertTrue(releaseOperation.await(10, TimeUnit.SECONDS), "operation callback was not released")
                }
            },
        )
        val executor = Executors.newFixedThreadPool(3)
        try {
            val operation = executor.submit<ModuleRevisionAttempt> {
                graph.beginAttempt(listOf("src/modules/alpha.c"))
            }
            assertTrue(operationEntered.await(5, TimeUnit.SECONDS))
            val close = executor.submit {
                closeStarted.countDown()
                graph.close()
                closeCompleted.countDown()
            }
            val contender = executor.submit<ModuleRevisionGraphSnapshot> {
                contenderStarted.countDown()
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
                    contenderAcquired.countDown()
                    reopened.snapshot
                }
            }
            assertTrue(closeStarted.await(5, TimeUnit.SECONDS))
            assertTrue(contenderStarted.await(5, TimeUnit.SECONDS))
            assertFalse(closeCompleted.await(200, TimeUnit.MILLISECONDS), "close escaped the active operation monitor")
            assertFalse(contenderAcquired.await(200, TimeUnit.MILLISECONDS), "contender bypassed the active graph lease")

            releaseOperation.countDown()
            operation.get(5, TimeUnit.SECONDS)
            close.get(5, TimeUnit.SECONDS)
            val recovered = contender.get(10, TimeUnit.SECONDS)
            assertTrue(closeCompleted.await(1, TimeUnit.SECONDS))
            assertTrue(contenderAcquired.await(1, TimeUnit.SECONDS))
            assertEquals(null, recovered.pendingAttemptId)
            assertEquals(ModuleRevisionStatus.REJECTED, recovered.nodes.last().status)
            assertTrue(recovered.nodes.last().recoveredAfterCrash)
            assertContentEquals(before, target.readBytes())
        } finally {
            releaseOperation.countDown()
            runCatching(graph::close)
            executor.shutdownNow()
        }
    }

    @Test
    fun `interrupted same JVM waiter releases its coordinator reference`() {
        val project = generatedProject()
        val first = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val started = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        val interruptRestored = AtomicReference(false)
        val waiter = Thread({
            started.countDown()
            failure.set(runCatching { ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile) }.exceptionOrNull())
            interruptRestored.set(Thread.currentThread().isInterrupted)
        }, "repair-graph-interrupted-waiter")
        waiter.start()
        assertTrue(started.await(5, TimeUnit.SECONDS))
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (waiter.state !in setOf(Thread.State.WAITING, Thread.State.TIMED_WAITING) &&
            System.nanoTime() < deadline
        ) Thread.onSpinWait()
        waiter.interrupt()
        waiter.join(5_000)
        assertFalse(waiter.isAlive)
        assertTrue(failure.get() is IllegalStateException)
        assertTrue(interruptRestored.get())
        first.close()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
    }

    @Test
    fun `same JVM and operating system graph lock waits are budgeted`() {
        val project = generatedProject()
        val budget = RepairResourceBudget(maximumGraphLockWaitMillis = 100)
        val first = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val failure = executor.submit<Throwable?> {
                runCatching {
                    ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).close()
                }.exceptionOrNull()
            }.get(5, TimeUnit.SECONDS)
            assertTrue(failure is RepairGraphLockTimeoutException, failure.toString())
        } finally {
            first.close()
            executor.shutdownNow()
        }
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
    }

    @Test
    fun `blob cleanup charges directory entries before materializing or deleting them`() {
        val project = generatedProject()
        val budget = RepairResourceBudget(maximumStateDirectoryEntries = 128)
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
        val blobs = project.resolve("reports/repair-revisions/blobs")
        repeat(129) { index ->
            blobs.resolve("unowned-${index.toString().padStart(3, '0')}").writeText("preserve")
        }

        assertFailsWith<decompengine.acp.LinuxResourceLimitException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).close()
        }
        assertEquals(129L, Files.list(blobs).use { entries ->
            entries.filter { it.fileName.toString().startsWith("unowned-") }.count()
        })
    }

    @Test
    fun `blob publication cannot create a graph that exceeds its own reopen traversal budget`() {
        val project = genericProject(
            "repair-blob-publication-budget-",
            mapOf("code/first.src" to "first\n", "code/second.src" to "second\n"),
        )
        val layout = RepairIndexLayout(
            sourcePaths = listOf("code/first.src", "code/second.src"),
            editablePaths = listOf("code/first.src", "code/second.src"),
            modules = listOf(
                RepairModuleEvidence("first", listOf("code/first.src")),
                RepairModuleEvidence("second", listOf("code/second.src")),
            ),
        )
        val profile = DeclarativeRepairIndexProfile("blob-publication-budget-v1", layout)
        val budget = RepairResourceBudget(maximumStateDirectoryEntries = 2)
        val blobs = project.resolve("reports/repair-revisions/blobs")

        assertFailsWith<RepairBudgetExceededException> {
            ModuleRevisionGraph.open(
                project,
                profile,
                RepairResourceBudget(maximumStateDirectoryEntries = 1),
            ).close()
        }
        assertTrue(project.resolve("reports/repair-revisions/recovery-binding.json").exists())
        assertFalse(project.resolve("reports/repair-revisions/graph.json").exists())
        assertEquals(0L, Files.list(blobs).use { it.count() })

        ModuleRevisionGraph.open(project, profile, budget).use { graph ->
            val attempt = graph.beginAttempt(layout.editablePaths)
            assertFailsWith<RepairBudgetExceededException> {
                graph.installCandidate(
                    attempt,
                    mapOf(
                        "code/first.src" to "changed first\n".toByteArray(),
                        "code/second.src" to "changed second\n".toByteArray(),
                    ),
                )
            }
            assertEquals(2L, Files.list(blobs).use { it.count() })
        }

        ModuleRevisionGraph.open(project, profile, budget).use { reopened ->
            assertEquals(null, reopened.snapshot.pendingAttemptId)
            assertTrue(reopened.snapshot.nodes.last().recoveredAfterCrash)
        }
        assertEquals(2L, Files.list(blobs).use { it.count() })
    }

    @Test
    fun `graphless initialization retry removes bounded orphan blobs before rebinding`() {
        val project = genericProject(
            "repair-orphan-initialization-",
            mapOf("code/first.src" to "first\n", "code/second.src" to "second\n"),
        )
        val layout = RepairIndexLayout(
            sourcePaths = listOf("code/first.src", "code/second.src"),
            editablePaths = listOf("code/first.src", "code/second.src"),
            modules = listOf(
                RepairModuleEvidence("first", listOf("code/first.src")),
                RepairModuleEvidence("second", listOf("code/second.src")),
            ),
        )
        val profile = DeclarativeRepairIndexProfile("orphan-initialization-v1", layout)
        val failedBudget = RepairResourceBudget(
            maximumStateDirectoryEntries = 2,
            maximumProjectionBytes = 1,
        )
        val blobs = project.resolve("reports/repair-revisions/blobs")

        val sourceBytes = layout.sourcePaths.associateWith { project.resolve(it).readBytes() }
        val sourceKeys = layout.sourcePaths.associateWith {
            Files.readAttributes(project.resolve(it), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey()
        }
        val failure = assertFailsWith<RepairBudgetExceededException> {
            ModuleRevisionGraph.open(project, profile, failedBudget).close()
        }
        assertEquals("repair history exceeds its 1-byte limit", failure.message)
        layout.sourcePaths.forEach { relative ->
            assertContentEquals(sourceBytes.getValue(relative), project.resolve(relative).readBytes())
            assertEquals(sourceKeys.getValue(relative),
                Files.readAttributes(project.resolve(relative), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey())
        }
        assertFalse(project.resolve("reports/repair-revisions/graph.json").exists())
        assertEquals(2L, Files.list(blobs).use { it.count() })
        project.resolve("code/first.src").writeText("changed first\n")
        project.resolve("code/second.src").writeText("changed second\n")

        val validBudget = RepairResourceBudget(maximumStateDirectoryEntries = 2)
        ModuleRevisionGraph.open(project, profile, validBudget).use { reopened ->
            assertEquals(6, reopened.snapshot.schemaVersion)
            assertEquals(ModuleRevisionStatus.ROOT, reopened.snapshot.nodes.single().status)
            assertTrue(reopened.derivedRepairIterations().isEmpty())
            assertEquals(null, reopened.snapshot.pendingAttemptId)
        }
        assertEquals(2L, Files.list(blobs).use { it.count() })
        assertTrue(Files.list(blobs).use { entries ->
            entries.map { it.fileName.toString() }.allMatch { digest ->
                digest == sha256("changed first\n".toByteArray()) ||
                    digest == sha256("changed second\n".toByteArray())
            }
        })
    }

    @Test
    fun `separate JVM cannot acquire the project graph until the OS lock is released`() {
        val project = generatedProject()
        val first = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val java = Path.of(System.getProperty("java.home"), "bin", "java")
        val process = ProcessBuilder(
            java.toString(),
            "-cp",
            System.getProperty("java.class.path"),
            ModuleRevisionGraphLockProbe::class.java.name,
            project.toString(),
        ).redirectErrorStream(true).start()
        val reader = process.inputStream.bufferedReader()
        val outputReader = Executors.newSingleThreadExecutor()
        try {
            assertEquals("READY", outputReader.submit<String?> { reader.readLine() }.get(10, TimeUnit.SECONDS))
            val acquired = outputReader.submit<String?> { reader.readLine() }
            assertFailsWith<TimeoutException> { acquired.get(500, TimeUnit.MILLISECONDS) }

            first.close()
            assertEquals("ACQUIRED", acquired.get(10, TimeUnit.SECONDS))
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "separate-JVM graph probe did not exit")
            assertEquals(0, process.exitValue())
        } finally {
            runCatching(first::close)
            outputReader.shutdownNow()
            if (process.isAlive) process.destroyForcibly()
        }
    }

    @Test
    fun `separate JVM cannot bypass the root lock by replacing reports`() {
        val project = generatedProject()
        val reports = project.resolve("reports")
        val heldReports = project.resolve("reports-held")
        val first = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        Files.move(reports, heldReports)
        reports.createDirectories()
        Files.copy(heldReports.resolve("program_model.json"), reports.resolve("program_model.json"))
        Files.copy(heldReports.resolve("module_plan.json"), reports.resolve("module_plan.json"))

        val java = Path.of(System.getProperty("java.home"), "bin", "java")
        val process = ProcessBuilder(
            java.toString(),
            "-cp",
            System.getProperty("java.class.path"),
            ModuleRevisionGraphLockProbe::class.java.name,
            project.toString(),
        ).redirectErrorStream(true).start()
        val reader = process.inputStream.bufferedReader()
        val outputReader = Executors.newSingleThreadExecutor()
        try {
            assertEquals("READY", outputReader.submit<String?> { reader.readLine() }.get(10, TimeUnit.SECONDS))
            val acquired = outputReader.submit<String?> { reader.readLine() }
            assertFailsWith<TimeoutException> { acquired.get(500, TimeUnit.MILLISECONDS) }

            first.close()
            assertEquals("ACQUIRED", acquired.get(10, TimeUnit.SECONDS))
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "replacement-reports graph probe did not exit")
            assertEquals(0, process.exitValue())
        } finally {
            runCatching(first::close)
            outputReader.shutdownNow()
            if (process.isAlive) process.destroyForcibly()
        }
    }

    @Test
    fun `graph ingress and every caller-visible snapshot are deeply detached and Java immutable`() {
        val project = generatedProject()
        val mutableArgs = arrayListOf("original")
        val mutableStdin = byteArrayOf(1, 2, 3)
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val retained = graph.retainRegressionInputs(listOf(ProcessInput("case", mutableArgs, mutableStdin)))
        mutableArgs[0] = "mutated"
        mutableStdin[0] = 99

        assertEquals(listOf("original"), retained.inputs.single().args)
        assertContentEquals(byteArrayOf(1, 2, 3), retained.inputs.single().stdin)
        val detachedStdin = retained.inputs.single().stdin
        detachedStdin[1] = 88
        assertContentEquals(byteArrayOf(1, 2, 3), retained.inputs.single().stdin)
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (retained.inputs as MutableList<ProcessInput>).clear()
        }

        val context = graph.selectContext("compile", "src/modules/alpha.c: error")
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (context.readablePaths as MutableList<String>).add("forged.c")
        }
        val target = project.resolve("src/modules/alpha.c")
        val replacement = target.readBytes() + "\n/* detached candidate */\n".toByteArray()
        val installedBytes = replacement.copyOf()
        val metadata = beginSyntheticAcceptedRun(graph)
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"), metadata)
        val deltas = graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to replacement))
        replacement.fill(0)
        assertContentEquals(installedBytes, graph.candidateSources(attempt).getValue("src/modules/alpha.c"))
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (deltas as MutableList<RevisionFileDelta>).clear()
        }

        val accepted = graph.accept(attempt, RepairEvidence("valid", "detached acceptance"),
            syntheticAcceptedProof(graph, attempt))
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (accepted.changes as MutableList<RevisionFileDelta>).clear()
        }
        val snapshot = graph.snapshot
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (snapshot.nodes as MutableList<ModuleRevisionNode>).clear()
        }
        graph.close()
        assertFailsWith<IllegalStateException> { graph.snapshot }
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (snapshot.nodes.first().changedModules as MutableList<String>).add("forged")
        }

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            assertContentEquals(installedBytes, reopened.candidateSources().getValue("src/modules/alpha.c"))
            assertEquals(installedBytes.contentEquals(target.readBytes()), true)
            assertEquals(listOf("original"), reopened.retainedRegressionCorpus().inputs.single().args)
            assertContentEquals(byteArrayOf(1, 2, 3), reopened.retainedRegressionCorpus().inputs.single().stdin)
        }
    }

    @Test
    fun `under cap original pending origins are mandatory unique and reused for recorded admission`() {
        for (schema in 1..3) {
            // Schema3 uses the existing authored legacy-format fixture, not historical chronology.
            val fixture = declaredBudgetFixture(schema, reserve = 8192)
            val path = fixture.project.resolve("reports/repair-revisions/graph.json")
            assertFailsWith<SimulatedRepairCrash> {
                ModuleRevisionGraph.openForTesting(fixture.project, GeneratedCRepairIndexProfile, fixture.budget,
                    ModuleRevisionFaultInjector { point ->
                        if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                            point.scope == "revision-state" && point.name == "graph.json") throw SimulatedRepairCrash()
                    }).close()
            }
            val marker = path.readBytes()
            assertTrue(marker.size.toLong() <= fixture.budget.maximumGraphBytes)
            val binding = path.parent.resolve("recovery-binding.json").readBytes()
            val declarations = semanticDeclaredInputs(fixture.project)
            var scans = 0
            val view = recordedRepairHistorySnapshot(marker, binding, fixture.budget) { consume ->
                scans++; declarations.forEach { consume(it.name, it.bytes) }
            }
            assertEquals(1, scans)
            assertEquals(true, view.pending?.rollback?.legacyPendingStateUnknown)
            assertFailsWith<RepairHistorySnapshotRefusal> { recordedRepairHistorySnapshot(marker, binding, fixture.budget) }
            val source = path.parent.resolve("legacy-graph-${sha256(fixture.legacy)}.json")
            assertContentEquals(fixture.legacy, source.readBytes())
            Files.delete(source)
            val key = Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()
            val installed = fixture.project.resolve("src/modules/alpha.c").readBytes()
            assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, fixture.budget).close() }
            assertContentEquals(marker, path.readBytes()); assertEquals(key, Files.readAttributes(path, BasicFileAttributes::class.java).fileKey())
            assertContentEquals(installed, fixture.project.resolve("src/modules/alpha.c").readBytes())
            source.writeBytes(fixture.legacy)
            if (schema == 2) {
                val other = fixture.legacy.toString(Charsets.UTF_8).replaceFirst("\"schemaVersion\": 2", "\"schemaVersion\": 1")
                    .replace(",\"agentInvocation\":null,\"publicationMode\":\"test_only_non_release\"", "").toByteArray()
                val ambiguous = declarations + RepairHistoryDeclaredGraph("legacy-graph-${sha256(other)}.json", other)
                assertFailsWith<RepairHistorySnapshotRefusal> { recordedRepairHistorySnapshot(marker, binding, fixture.budget, ambiguous) }
                val alternative = path.parent.resolve("legacy-graph-${sha256(other)}.json").also { it.writeBytes(other) }
                assertTrue(assertFailsWith<IllegalArgumentException> {
                    ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, fixture.budget).close()
                }.message.orEmpty().contains("multiple declared legacy graphs"))
                Files.delete(alternative)
            }
            ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, fixture.budget).use { recovered ->
                assertEquals(RepairRollbackState.RESTORED_VERIFIED, recovered.snapshot.nodes.last().rollbackRecord?.state)
            }
            assertContentEquals(fixture.originalSource, fixture.project.resolve("src/modules/alpha.c").readBytes())
            assertNotNull(recordedRepairHistorySnapshot(path.readBytes(), binding, fixture.budget,
                semanticDeclaredInputs(fixture.project)).attempts.last().rollback)
            val finalized = path.readText()
            val finalRecord = Json.parseToJsonElement(finalized).jsonObject.getValue("nodes").jsonArray.last().jsonObject.getValue("rollbackRecord").toString()
            val erased = finalized.replace("      \"rollbackRecord\": $finalRecord,\n", "")
            assertNotEquals(finalized, erased)
            for (wire in listOf(erased, explicitNullNodeWire(erased))) {
                assertFailsWith<RepairHistorySnapshotRefusal> { recordedRepairHistorySnapshot(wire.toByteArray(), binding,
                    fixture.budget, semanticDeclaredInputs(fixture.project)) }
                path.writeText(wire)
                assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, fixture.budget).close() }
                assertEquals(wire, path.readText())
            }
            path.writeText(finalized)
        }
    }

    @Test
    fun `native flag or erased finalized records cannot acquire under cap local compatibility`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val project = generatedProject(temporaryParent = parent)
        val relative = "src/modules/alpha.c"
        val source = project.resolve(relative); val original = source.readBytes()
        ModuleRevisionGraph.openLegacyForTesting(project, GeneratedCRepairIndexProfile).use { graph ->
            graph.enableRunContract()
            val attempt = graph.beginAttempt(listOf(relative))
            graph.installCandidate(attempt, mapOf(relative to original + "\n/* native */\n".toByteArray()))
            graph.reject(attempt)
            assertEquals(false, graph.snapshot.nodes.last().rollbackRecord?.legacyPendingStateUnknown)
        }
        val path = project.resolve("reports/repair-revisions/graph.json")
        val canonical = path.readText(); val binding = path.parent.resolve("recovery-binding.json").readBytes()
        val record = Json.parseToJsonElement(canonical).jsonObject.getValue("nodes").jsonArray.last().jsonObject.getValue("rollbackRecord").toString()
        val invented = canonical.replace(record, record.replace("\"legacyPendingStateUnknown\":false", "\"legacyPendingStateUnknown\":true")
            .replace("\"candidateSourceInstallStarted\":true", "\"candidateSourceInstallStarted\":null"))
        val line = "      \"rollbackRecord\": $record,\n"
        assertTrue(line in canonical); assertNotEquals(canonical, invented)
        val missing = canonical.replace(line, "")
        for (forged in listOf(invented, missing, explicitNullNodeWire(missing))) {
            assertTrue(forged.toByteArray().size.toLong() <= RepairResourceBudget().maximumGraphBytes)
            assertFailsWith<RepairHistorySnapshotRefusal> {
                recordedRepairHistorySnapshot(forged.toByteArray(), binding, RepairResourceBudget(), semanticDeclaredInputs(project))
            }
            path.writeText(forged)
            val key = Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()
            assertTrue(assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).close() }
                .message.orEmpty().contains("complete declared rollback origin"))
            assertEquals(forged, path.readText()); assertEquals(key, Files.readAttributes(path, BasicFileAttributes::class.java).fileKey())
            assertContentEquals(original, source.readBytes())
        }
        path.writeText(canonical)
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).close()
    }

    @Test
    fun `original schema two nonpending prefix is preserved unique and earns zero graph credit`() {
        val fixture = semanticNonpendingFixture()
        val root = fixture.project; val path = root.resolve("reports/repair-revisions/graph.json")
        val original = path.readBytes(); val binding = path.parent.resolve("recovery-binding.json").readBytes()
        assertEquals(JsonPrimitive(2), Json.parseToJsonElement(original.toString(Charsets.UTF_8)).jsonObject.getValue("schemaVersion"))
        // Build a complete current rejected node, then project it through the test-only exact
        // schema-2 writer helper. This exercises compatibility parsing, not historical chronology.
        ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, fixture.budget).use { graph -> graph.enableRunContract() }
        val current = path.readBytes(); val declarations = semanticDeclaredInputs(root)
        val name = "legacy-graph-${sha256(original)}.json"
        assertContentEquals(original, path.parent.resolve(name).readBytes())
        assertNull(recordedRepairHistorySnapshot(current, binding, fixture.budget, declarations).attempts.last().rollback)
        assertEquals(RepairHistoryReadStatus.RECORDED, readProjectRecordedRepairHistory(root).status)
        ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, fixture.budget).close()
        assertFailsWith<RepairHistorySnapshotRefusal> { recordedRepairHistorySnapshot(current, binding, fixture.budget) }
        val text = original.toString(Charsets.UTF_8)
        val equivalent = text.replaceFirst("\"schemaVersion\": 2", "\"schemaVersion\": 1")
            .replace(",\"agentInvocation\":null,\"publicationMode\":\"test_only_non_release\"", "").toByteArray()
        assertFailsWith<RepairHistorySnapshotRefusal> { recordedRepairHistorySnapshot(current, binding, fixture.budget,
            declarations + RepairHistoryDeclaredGraph("legacy-graph-${sha256(equivalent)}.json", equivalent)) }
        Files.delete(path.parent.resolve(name))
        val changed = text.replace("PREFIX_PADDING", "DIFFERENT_PREFIX").toByteArray()
        assertNotEquals(sha256(original), sha256(changed))
        val changedPath = path.parent.resolve("legacy-graph-${sha256(changed)}.json").also { it.writeBytes(changed) }
        val key = Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()
        assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, fixture.budget).close() }
        assertEquals(key, Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()); assertContentEquals(current, path.readBytes())
        Files.delete(changedPath); path.parent.resolve(name).writeBytes(original)
        // A later native rejection cannot use the earlier nullable-prefix declaration.
        ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, fixture.budget).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c")); graph.reject(attempt)
            assertNotNull(graph.snapshot.nodes.last().rollbackRecord)
        }
        val tail = path.readText(); val record = Json.parseToJsonElement(tail).jsonObject.getValue("nodes").jsonArray.last().jsonObject.getValue("rollbackRecord").toString()
        val erased = tail.replace("      \"rollbackRecord\": $record,\n", "")
        assertNotEquals(tail, erased)
        assertFailsWith<RepairHistorySnapshotRefusal> { recordedRepairHistorySnapshot(erased.toByteArray(), binding, fixture.budget, semanticDeclaredInputs(root)) }
        for (saturated in listOf(false, true)) {
            val bounded = semanticNonpendingFixture(saturate = saturated)
            val selectedPath = bounded.project.resolve("reports/repair-revisions/graph.json")
            val before = selectedPath.readBytes(); val source = bounded.project.resolve("src/modules/alpha.c").readBytes()
            ModuleRevisionGraph.open(bounded.project, GeneratedCRepairIndexProfile, bounded.budget).use { graph ->
                if (saturated) {
                    assertEquals(bounded.budget.maximumGraphBytes, before.size.toLong())
                    assertFailsWith<RepairBudgetExceededException> { graph.enableRunContract() }
                    assertContentEquals(before, selectedPath.readBytes())
                    assertContentEquals(source, bounded.project.resolve("src/modules/alpha.c").readBytes())
                } else graph.enableRunContract()
            }
        }
    }

    @Test
    fun `complete pending source validation refuses foreign context and changed original metadata before mutation`() {
        val fixture = declaredBudgetFixture(2, reserve = 8192)
        val path = fixture.project.resolve("reports/repair-revisions/graph.json")
        assertFailsWith<SimulatedRepairCrash> {
            ModuleRevisionGraph.openForTesting(fixture.project, GeneratedCRepairIndexProfile, fixture.budget,
                ModuleRevisionFaultInjector { point -> if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                    point.scope == "revision-state" && point.name == "graph.json") throw SimulatedRepairCrash() }).close()
        }
        val marker = path.readBytes(); val binding = path.parent.resolve("recovery-binding.json").readBytes()
        val original = fixture.legacy.toString(Charsets.UTF_8)
        val parsed = Json.parseToJsonElement(original).jsonObject
        val profileId = parsed.getValue("profileId").jsonPrimitive.content
        val profileSha = parsed.getValue("profileSha256").jsonPrimitive.content
        val originalPrompt = parsed.getValue("pending").jsonObject.getValue("repairMetadata").jsonObject
            .getValue("prompt").jsonPrimitive.content
        assertEquals(sha256("short".toByteArray()), originalPrompt)
        val alternatives = listOf(
            original.replace("\"profileId\": \"$profileId\"", "\"profileId\": \"foreign_profile\""),
            original.replace("\"profileSha256\": \"$profileSha\"", "\"profileSha256\": \"${"0".repeat(64)}\""),
            original.replace("\"maximumGraphBytes\":16384", "\"maximumGraphBytes\":16385"),
            original.replace("\"prompt\":\"$originalPrompt\"", "\"prompt\":\"${sha256("changed original prompt".toByteArray())}\""),
            original.replace("\"storedBlobBytes\": ", "\"storedBlobBytes\": -"),
        )
        for (alternative in alternatives) {
            assertNotEquals(original, alternative)
            assertFailsWith<RepairHistorySnapshotRefusal> { recordedRepairHistorySnapshot(marker, binding, fixture.budget,
                listOf(RepairHistoryDeclaredGraph("legacy-graph-${sha256(alternative.toByteArray())}.json", alternative.toByteArray()))) }
        }
        val originalPath = path.parent.resolve("legacy-graph-${sha256(fixture.legacy)}.json")
        Files.delete(originalPath)
        val changed = alternatives.first().toByteArray(); val foreign = path.parent.resolve("legacy-graph-${sha256(changed)}.json").also { it.writeBytes(changed) }
        val beforeSource = fixture.project.resolve("src/modules/alpha.c").readBytes(); val key = Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()
        assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, fixture.budget).close() }
        assertContentEquals(marker, path.readBytes()); assertEquals(key, Files.readAttributes(path, BasicFileAttributes::class.java).fileKey())
        assertContentEquals(beforeSource, fixture.project.resolve("src/modules/alpha.c").readBytes())
        Files.delete(foreign); originalPath.writeBytes(fixture.legacy)
    }

    @Test
    fun `archive joins complete pending origin under cap and rejects a resealed changed owning run`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val fixture = releaseRepairFixture(temporaryParent = parent, legacyRejectedPrefix = true)
        val path = fixture.project.resolve("reports/repair-revisions/graph.json")
        val graphBytes = path.readBytes()
        assertTrue(graphBytes.size.toLong() < RepairResourceBudget().maximumGraphBytes)
        assertEquals(RepairHistoryReadStatus.RECORDED, readProjectRecordedRepairHistory(fixture.project).status)
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("semantic-origin-valid.zip"))
        val extracted = fixture.project.parent.resolve("semantic-origin-valid")
        ArchivalBundleVerifier.extractAndVerify(bundle.archivePath, extracted)
        assertContentEquals(fixture.after, extracted.resolve(fixture.relativePath).readBytes())
        val forged = fixture.project.parent.resolve("semantic-origin-forged.zip")
        rewriteArchive(bundle.archivePath, forged) { entries ->
            val sourcePath = entries.keys.single { key -> key.startsWith("reports/repair-revisions/legacy-graph-") &&
                Json.parseToJsonElement(entries.getValue(key).toString(Charsets.UTF_8)).jsonObject["pending"] != JsonNull }
            val source = entries.remove(sourcePath)!!.toString(Charsets.UTF_8)
            val parsed = Json.parseToJsonElement(source).jsonObject
            val run = parseRepairRunState(parsed.getValue("runs").jsonArray.single().toString())
            val changed = source.replace(run.toJson(), run.copy(maximumAttempts = run.maximumAttempts + 1).toJson()).toByteArray()
            assertFalse(source.toByteArray().contentEquals(changed))
            entries["reports/repair-revisions/legacy-graph-${sha256(changed)}.json"] = changed
        }
        val output = fixture.project.parent.resolve("semantic-origin-forged-refused")
        val refusal = assertFailsWith<IllegalArgumentException> { ArchivalBundleVerifier.extractAndVerify(forged, output) }
        assertTrue(refusal.message.orEmpty().contains("complete declared rollback origin"), refusal.message)
        assertFalse(output.exists())
    }

    @Test
    fun `genuine legacy pending failure origin retains all four valid pair replays through resolution`() {
        val allowed = listOf(
            RepairRollbackStage.SOURCE_RESTORE to RepairRollbackFailureCode.UNRECOGNIZED_SOURCE_STATE,
            RepairRollbackStage.SOURCE_RESTORE to RepairRollbackFailureCode.RESTORE_OPERATION_FAILED,
            RepairRollbackStage.SOURCE_VERIFICATION to RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
            RepairRollbackStage.SOURCE_VERIFICATION to RepairRollbackFailureCode.RESTORE_OPERATION_FAILED,
        )
        for ((stage, code) in allowed) {
            val fixture = declaredBudgetFixture(2, reserve = 8192)
            val path = fixture.project.resolve("reports/repair-revisions/graph.json")
            val source = fixture.project.resolve("src/modules/alpha.c")
            source.writeText("unknown concurrent replacement")
            assertFailsWith<IllegalStateException> { ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, fixture.budget).close() }
            val failed = path.readText()
            assertTrue("restore_failed_unresolved" in failed)
            // Replay metadata uses an actually persisted failure/original source. It does not
            // claim the filesystem injected each native failure site individually.
            val replay = rollbackPairReplace(failed, true, stage, code)
            val binding = path.parent.resolve("recovery-binding.json").readBytes()
            val declarations = semanticDeclaredInputs(fixture.project)
            val pending = recordedRepairHistorySnapshot(replay.toByteArray(), binding, fixture.budget, declarations)
            assertEquals(stage, pending.pending?.rollback?.failureStage)
            assertEquals(code, pending.pending?.rollback?.failureCode)
            path.writeText(replay); source.writeBytes(fixture.originalSource)
            ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile, fixture.budget).use { graph ->
                val record = requireNotNull(graph.snapshot.nodes.last().rollbackRecord)
                assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, record.state)
                assertEquals(stage, record.failureStage); assertEquals(code, record.failureCode)
                assertTrue(record.legacyPendingStateUnknown)
                assertTrue(graph.snapshot.runs.isEmpty())
            }
            val resolved = recordedRepairHistorySnapshot(path.readBytes(), binding, fixture.budget, semanticDeclaredInputs(fixture.project))
            assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, resolved.attempts.last().rollback?.state)
            assertContentEquals(fixture.originalSource, source.readBytes())
        }
    }

    @Test
    fun `native pending attempt preserves a nullable legacy prefix without a duplicate origin`() {
        val fixture = semanticNonpendingFixture()
        val root = fixture.project; val path = root.resolve("reports/repair-revisions/graph.json")
        val nonpending = path.readBytes()
        val source = root.resolve("src/modules/alpha.c")
        ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, fixture.budget).use { graph ->
            val corpus = graph.retainedRegressionCorpus()
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"), RevisionRepairMetadata(2, "compile", "second original attempt",
                null, emptyList(), null, corpus.sha256, publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE))
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to source.readBytes() + "\n/* second */\n".toByteArray()))
        }
        val pendingSource = path.readBytes()
        assertFailsWith<SimulatedRepairCrash> {
            ModuleRevisionGraph.openForTesting(root, GeneratedCRepairIndexProfile, fixture.budget,
                ModuleRevisionFaultInjector { point -> if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                    point.scope == "revision-state" && point.name == "graph.json") throw SimulatedRepairCrash() }).close()
        }
        val marker = path.readBytes(); val binding = path.parent.resolve("recovery-binding.json").readBytes()
        val declared = semanticDeclaredInputs(root)
        val view = recordedRepairHistorySnapshot(marker, binding, fixture.budget, declared)
        assertNull(view.attempts.single().rollback)
        val pendingRollback = requireNotNull(view.pending).rollback
        assertNotNull(pendingRollback)
        assertFalse(pendingRollback.legacyPendingStateUnknown)
        val pendingName = "legacy-graph-${sha256(pendingSource)}.json"
        assertFalse(Files.exists(path.parent.resolve(pendingName), LinkOption.NOFOLLOW_LINKS),
            "current native pending records do not create a duplicate legacy-origin witness")
        // The complete NONPENDING frame covers the old nullable prefix. The current pending
        // record has native rollback state, so it does not require a duplicate legacy origin.
        val prefixOnly = RepairHistoryDeclaredGraph("legacy-graph-${sha256(nonpending)}.json", nonpending)
        val prefixView = recordedRepairHistorySnapshot(marker, binding, fixture.budget, listOf(prefixOnly))
        assertFalse(requireNotNull(prefixView.pending?.rollback).legacyPendingStateUnknown)
        ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, fixture.budget).use { graph ->
            assertNull(graph.snapshot.nodes[1].rollbackRecord)
            assertEquals(RepairRollbackState.RESTORED_VERIFIED, graph.snapshot.nodes.last().rollbackRecord?.state)
        }
        assertEquals(RepairHistoryReadStatus.RECORDED, readProjectRecordedRepairHistory(root).status)
        assertContentEquals(fixture.originalSource, source.readBytes())
    }

    /** Bounded test corpus only, not a production scan or historical-writer authority. */
    private fun semanticDeclaredInputs(project: Path): List<RepairHistoryDeclaredGraph> =
        Files.newDirectoryStream(project.resolve("reports/repair-revisions"), "legacy-graph-*.json").use { stream ->
            stream.sortedBy { it.fileName.toString() }.map { RepairHistoryDeclaredGraph(it.fileName.toString(), it.readBytes()) }
        }

    private fun semanticNonpendingFixture(saturate: Boolean = false): DeclaredBudgetFixture {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val root = generatedProject(temporaryParent = parent)
        val relative = "src/modules/alpha.c"; val target = root.resolve(relative); val original = target.readBytes()
        val selected = RepairResourceBudget(maximumGraphBytes = 16 * 1024)
        val path = root.resolve("reports/repair-revisions/graph.json")
        lateinit var finalized: String
        ModuleRevisionGraph.open(root, GeneratedCRepairIndexProfile, selected).use { graph ->
            val corpus = graph.retainedRegressionCorpus()
            val attempt = graph.beginAttempt(listOf(relative), RevisionRepairMetadata(1, "compile", "PREFIX_PADDING", "PREFIX_PADDING",
                emptyList(), null, corpus.sha256, publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE))
            graph.installCandidate(attempt, mapOf(relative to original + "\n/* original2 */\n".toByteArray()))
            val originalPending = path.readText()
            val state = requireNotNull(rollbackPairPrivate("parseGraph", originalPending))
            fun value(name: String): Any? = state.javaClass.getDeclaredField(name).also { it.isAccessible = true }.get(state)
            val pending = requireNotNull(value("pending"))
            val finalizer = graph.javaClass.declaredMethods.single { it.name == "finalizeNode" }.also { it.isAccessible = true }
            val node = finalizer.invoke(graph, pending, ModuleRevisionStatus.REJECTED, RepairEvidence("rejected", "original-format fixture"), false, null) as ModuleRevisionNode
            val copy = state.javaClass.declaredMethods.single { it.name == "copy" }.also { it.isAccessible = true }
            assertEquals(17, copy.parameterCount)
            val fields: Array<Any?> = (1..copy.parameterCount).map { component -> state.javaClass.getDeclaredMethod("component$component")
                .also { it.isAccessible = true }.invoke(state) }.toTypedArray()
            @Suppress("UNCHECKED_CAST")
            val nodes = value("nodes") as List<ModuleRevisionNode>
            fields[9] = nodes + node; fields[10] = null
            val completed = requireNotNull(copy.invoke(state, *fields))
            val canonical = requireNotNull(rollbackPairPrivate("parseCanonicalGraph", originalPending.toByteArray(), "original schema2 fixture"))
            val wire = requireNotNull(canonical.javaClass.getDeclaredField("nullNodeWire").also { it.isAccessible = true }.get(canonical))
            finalized = authoredLegacyGraphFixture(
                requireNotNull(rollbackPairPrivate("renderGraph", completed, wire)).toString(), 2,
            )
        }
        target.writeBytes(original)
        if (saturate) {
            val padding = (selected.maximumGraphBytes - finalized.toByteArray().size).toInt()
            assertTrue(padding > 0)
            finalized = finalized.replace("PREFIX_PADDING", "PREFIX_PADDING" + "p".repeat(padding))
        }
        path.writeText(finalized)
        val binding = path.parent.resolve("recovery-binding.json").readBytes()
        val originalView = recordedRepairHistorySnapshot(finalized.toByteArray(), binding, selected)
        assertNull(originalView.attempts.last().rollback)
        return DeclaredBudgetFixture(root, selected, finalized.toByteArray(), finalized.toByteArray(), original, 0)
    }

    private data class DeclaredBudgetFixture(val project: Path, val budget: RepairResourceBudget,
        val legacy: ByteArray, val nativeGraph: ByteArray, val originalSource: ByteArray, val reservedBytes: Long)

    private fun declaredBudgetFixture(schema: Int, withRun: Boolean = true, reserve: Int = 0): DeclaredBudgetFixture {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val project = generatedProject(temporaryParent = parent)
        val target = project.resolve("src/modules/alpha.c")
        val original = target.readBytes()
        val budget = RepairResourceBudget(maximumGraphBytes = 16 * 1024)
        val path = project.resolve("reports/repair-revisions/graph.json")
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            if (schema == 3) {
                graph.enableRunContract()
                if (withRun) graph.beginRun(2, 60_000)
            }
            val metadata = RevisionRepairMetadata(1, "compile", "short", "DECLARED_GRAPH_PADDING", emptyList(),
                null, graph.retainedRegressionCorpus().sha256, publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE)
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"), metadata)
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to original + "\n/* declared source */\n".toByteArray()))
        }
        var native = path.readText()
        fun legacy(text: String): String = authoredLegacyGraphFixture(text, schema)
        val unpaddedBytes = legacy(native).toByteArray().size.toLong()
        val headroom = budget.maximumGraphBytes - unpaddedBytes
        assertTrue(headroom > 0, "declared schema=$schema unpadded=$unpaddedBytes cap=${budget.maximumGraphBytes}")
        require(reserve >= 0)
        // Reserve only slack actually available from this producer; keep at least one padding byte.
        // Defaults still saturate the unchanged cap exactly. No compatibility credit is enlarged.
        val admittedReserve = minOf(reserve.toLong(), headroom - 1)
        val padding = (headroom - admittedReserve).toInt()
        assertTrue(padding > 0)
        native = native.replace("DECLARED_GRAPH_PADDING", "p".repeat("DECLARED_GRAPH_PADDING".length + padding))
        val old = legacy(native).toByteArray()
        assertEquals(budget.maximumGraphBytes - admittedReserve, old.size.toLong(), "declared schema=$schema")
        path.writeBytes(old)
        return DeclaredBudgetFixture(project, budget, old, native.toByteArray(), original, admittedReserve)
    }

    private fun requireDeclaredGraphBudget(project: Path, payload: ByteArray, budget: RepairResourceBudget) {
        requireRepairGraphByteBudget(payload, budget) { consume ->
            Files.newDirectoryStream(project.resolve("reports/repair-revisions"), "legacy-graph-*.json").use { paths ->
                paths.sortedBy { it.fileName.toString() }.forEach { consume(it.fileName.toString(), it.readBytes()) }
            }
        }
    }

    private fun generatedProject(
        undispatchedFallback: Boolean = false,
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
        temporaryParent: Path? = null,
    ): Path {
        val projectRoot = if (temporaryParent == null) createTempDirectory("module-revision-")
            else Files.createTempDirectory(temporaryParent, "module-revision-")
        val input = projectRoot.resolve("reference.fixture").apply { writeText("reference") }
        val promptContext = if (undispatchedFallback) "/* ${"context".repeat(900)} */" else null
        generatePublishedProject(
            projectRoot,
            input,
            RecoveredProgramModel(
                inputSha256 = sha256(input.readBytes()),
                functions = listOf(
                    RecoveredFunction(
                        id = "fn_alpha",
                        name = "alpha_run",
                        address = 0x1000UL,
                        prototype = "int alpha_run(void)",
                        decompiledC = promptContext,
                        calls = setOf("fn_beta"),
                    ),
                    RecoveredFunction("fn_beta", "beta_read", 0x2000UL, "int beta_read(void)", promptContext),
                    RecoveredFunction("fn_charlie", "charlie_emit", 0x3000UL, "int charlie_emit(void)", promptContext),
                    RecoveredFunction("fn_delta", "delta_idle", 0x4000UL, "int delta_idle(void)", promptContext),
                ),
            ),
            if (undispatchedFallback) BoundedLlmModuleReconstructor(
                AgentHarness { _, _ -> error("pre-dispatch fixture must not execute") }, maximumContextCharacters = 4096,
            ) else null,
            profile = profile,
        )
        return projectRoot.resolve("source-tree")
    }

    private fun generatePublishedProject(
        reportRoot: Path,
        input: Path,
        model: RecoveredProgramModel,
        reconstructor: decompengine.project.ModuleReconstructor? = null,
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
    ) {
        ReconstructionOutputWorkspace.open(reportRoot, input).use { workspace ->
            val result = workspace.publish(setOf("source-tree"), { stage ->
                SourceTreeGenerator.generateWithCompilerFeedback(
                    model,
                    stage.resolve("source-tree"),
                    ReconstructionHostSafetyLimits.DEFAULT,
                    reconstructor = reconstructor,
                    profile = profile,
                    publicationLock = workspace.publicationLock,
                )
            })
            check(result == decompengine.project.PublicationResult.PUBLISHED) {
                "fixture source tree was not published: $result"
            }
        }
    }


    @Test
    fun `rollback failure records and parser admit only the four producer stage code pairs`() {
        val allowed = listOf(
            RepairRollbackStage.SOURCE_RESTORE to RepairRollbackFailureCode.UNRECOGNIZED_SOURCE_STATE,
            RepairRollbackStage.SOURCE_RESTORE to RepairRollbackFailureCode.RESTORE_OPERATION_FAILED,
            RepairRollbackStage.SOURCE_VERIFICATION to RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
            RepairRollbackStage.SOURCE_VERIFICATION to RepairRollbackFailureCode.RESTORE_OPERATION_FAILED,
        )
        val forbidden = listOf(
            RepairRollbackStage.SOURCE_RESTORE to RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
            RepairRollbackStage.SOURCE_VERIFICATION to RepairRollbackFailureCode.UNRECOGNIZED_SOURCE_STATE,
        )
        for (state in listOf(RepairRollbackState.RESTORE_FAILED_UNRESOLVED, RepairRollbackState.RESTORED_AFTER_FAILURE)) {
            val digest = "a".repeat(64)
            val base = RepairRollbackRecord(attemptId = "revision_pair", runId = null, targetRevisionId = "root_pair",
                expectedSourceRevisionSha256 = digest, state = state,
                failureStage = allowed.first().first, failureCode = allowed.first().second,
                observedSourceRevisionSha256 = if (state == RepairRollbackState.RESTORED_AFTER_FAILURE) digest else null,
                candidateSourceInstallStarted = true)
            for ((stage, code) in allowed) {
                val record = base.copy(failureStage = stage, failureCode = code)
                val parsed = rollbackPairPrivate("parseRepairRollbackRecord", rollbackPairJson(record)) as RepairRollbackRecord
                assertEquals(record, parsed)
                assertEquals(stage, parsed.failureStage); assertEquals(code, parsed.failureCode)
            }
            for ((stage, code) in forbidden) {
                assertEquals("rollback failure stage/code pair is invalid",
                    assertFailsWith<IllegalArgumentException> { base.copy(failureStage = stage, failureCode = code) }.message)
                val forged = JsonObject(rollbackPairJson(base) + mapOf(
                    "failureStage" to JsonPrimitive(stage.name.lowercase()), "failureCode" to JsonPrimitive(code.name.lowercase())))
                assertEquals("rollback failure stage/code pair is invalid",
                    assertFailsWith<IllegalArgumentException> { rollbackPairPrivate("parseRepairRollbackRecord", forged) }.message)
            }
        }
        val digest = "a".repeat(64)
        val noFailure = RepairRollbackRecord(attemptId = "revision_none", runId = null, targetRevisionId = "root_none",
            expectedSourceRevisionSha256 = digest, state = RepairRollbackState.NOT_REQUIRED_VERIFIED,
            observedSourceRevisionSha256 = digest)
        assertNull(noFailure.failureStage); assertNull(noFailure.failureCode)
        assertEquals(noFailure, rollbackPairPrivate("parseRepairRollbackRecord", rollbackPairJson(noFailure)))
    }

    @Test
    fun `recorded and reopened pending and resolved failures preserve every allowed pair`() {
        val allowed = listOf(
            RepairRollbackStage.SOURCE_RESTORE to RepairRollbackFailureCode.UNRECOGNIZED_SOURCE_STATE,
            RepairRollbackStage.SOURCE_RESTORE to RepairRollbackFailureCode.RESTORE_OPERATION_FAILED,
            RepairRollbackStage.SOURCE_VERIFICATION to RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
            RepairRollbackStage.SOURCE_VERIFICATION to RepairRollbackFailureCode.RESTORE_OPERATION_FAILED,
        )
        for (pending in listOf(true, false)) for ((stage, code) in allowed) {
            val fixture = rollbackPairFixture(pending)
            val changed = rollbackPairReplace(fixture.canonical, pending, stage, code)
            val view = recordedRepairHistorySnapshot(changed.toByteArray(), fixture.binding, RepairResourceBudget())
            val record = requireNotNull(if (pending) view.pending?.rollback else view.attempts.last().rollback)
            assertEquals(stage, record.failureStage); assertEquals(code, record.failureCode)
            assertEquals(if (pending) RepairRollbackState.RESTORE_FAILED_UNRESOLVED else RepairRollbackState.RESTORED_AFTER_FAILURE, record.state)
            fixture.root.resolve("reports/repair-revisions/graph.json").writeText(changed)
            ModuleRevisionGraph.open(fixture.root, fixture.profile).use { reopened ->
                val restored = requireNotNull(reopened.snapshot.nodes.last().rollbackRecord)
                assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, restored.state)
                assertEquals(stage, restored.failureStage); assertEquals(code, restored.failureCode)
                assertEquals(restored.expectedSourceRevisionSha256, restored.observedSourceRevisionSha256)
                assertEquals("before", fixture.root.resolve("code.c").readText())
                assertTrue(reopened.snapshot.runs.isEmpty()) // No fabricated run for a standalone failure.
            }
        }
    }

    @Test
    fun `impossible pending and resolved pairs refuse before reopen mutation or recorded credit`() {
        val forbidden = listOf(
            RepairRollbackStage.SOURCE_RESTORE to RepairRollbackFailureCode.TARGET_DIGEST_MISMATCH,
            RepairRollbackStage.SOURCE_VERIFICATION to RepairRollbackFailureCode.UNRECOGNIZED_SOURCE_STATE,
        )
        for (pending in listOf(true, false)) for ((stage, code) in forbidden) {
            val fixture = rollbackPairFixture(pending)
            val baseline = recordedRepairHistorySnapshot(fixture.canonical.toByteArray(), fixture.binding, RepairResourceBudget())
            assertNotNull(if (pending) baseline.pending?.rollback else baseline.attempts.last().rollback)
            val changed = rollbackPairReplace(fixture.canonical, pending, stage, code)
            val graphPath = fixture.root.resolve("reports/repair-revisions/graph.json")
            graphPath.writeText(changed)
            val graphKey = Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey()
            val source = fixture.root.resolve("code.c")
            val sourceBytes = source.readBytes()
            val sourceKey = Files.readAttributes(source, BasicFileAttributes::class.java).fileKey()
            val refusal = assertFailsWith<RepairHistorySnapshotRefusal> {
                recordedRepairHistorySnapshot(changed.toByteArray(), fixture.binding, RepairResourceBudget())
            }
            assertEquals("Recorded repair metadata is invalid or exceeds its bound.", refusal.message)
            assertEquals("rollback failure stage/code pair is invalid",
                assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(fixture.root, fixture.profile).close() }.message)
            assertEquals(changed, graphPath.readText())
            assertEquals(graphKey, Files.readAttributes(graphPath, BasicFileAttributes::class.java).fileKey())
            assertContentEquals(sourceBytes, source.readBytes())
            assertEquals(sourceKey, Files.readAttributes(source, BasicFileAttributes::class.java).fileKey())
            assertContentEquals(fixture.binding, fixture.root.resolve("reports/repair-revisions/recovery-binding.json").readBytes())
        }
    }

    @Test
    fun `resealed archive preserves valid failure pairs and refuses only impossible cross pairs`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val fixture = releaseRepairFixture(recoveredRollbackPrefix = true, temporaryParent = parent)
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("rollback-pairs-original.zip"))
        val positive = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(bundle.archivePath,
            fixture.project.parent.resolve("rollback-pairs-original-control"))
        val accepted = positive.source.acceptedAcpContributions.single().taskId
        val pairs = listOf(
            Triple("source_restore", "unrecognized_source_state", true),
            Triple("source_restore", "restore_operation_failed", true),
            Triple("source_verification", "target_digest_mismatch", true),
            Triple("source_verification", "restore_operation_failed", true),
            Triple("source_restore", "target_digest_mismatch", false),
            Triple("source_verification", "unrecognized_source_state", false),
        )
        for ((stage, code, valid) in pairs) {
            val archive = fixture.project.parent.resolve("rollback-pair-$stage-$code.zip")
            rewriteArchive(bundle.archivePath, archive) { entries ->
                val path = "reports/repair-revisions/graph.json"
                val graph = Json.parseToJsonElement(entries.getValue(path).decodeToString()).jsonObject
                val nodes = graph.getValue("nodes").jsonArray
                val failed = nodes[1].jsonObject
                val record = failed.getValue("rollbackRecord").jsonObject
                val run = graph.getValue("runs").jsonArray.first().jsonObject
                assertEquals("restored_after_failure", record.getValue("state").jsonPrimitive.content)
                assertEquals("rejected", failed.getValue("status").jsonPrimitive.content)
                assertEquals("rollback_failed", run.getValue("status").jsonPrimitive.content)
                assertEquals(record.getValue("attemptId"), run.getValue("rollbackFailureAttemptId"))
                assertEquals(record.getValue("runId"), run.getValue("id"))
                assertEquals(record.getValue("state"), run.getValue("rollbackResolution"))
                assertEquals(record.getValue("expectedSourceRevisionSha256"), record.getValue("observedSourceRevisionSha256"))
                assertEquals(accepted, nodes.last().jsonObject.getValue("id").jsonPrimitive.content)
                assertEquals(nodes.last().jsonObject.getValue("id"), graph.getValue("fullyAcceptedHeadId"))
                val changed = JsonObject(record + mapOf("failureStage" to JsonPrimitive(stage), "failureCode" to JsonPrimitive(code)))
                entries[path] = JsonObject(graph + ("nodes" to JsonArray(nodes.mapIndexed { index, element ->
                    if (index == 1) JsonObject(element.jsonObject + ("rollbackRecord" to changed)) else element
                }))).toString().toByteArray()
                // Only this record pair changes. Run/history/source/receipt/proof bytes stay coherent; manifest is resealed.
            }
            val output = fixture.project.parent.resolve("rollback-pair-$stage-$code-output")
            if (valid) {
                val lineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(archive, output)
                assertEquals(accepted, lineage.source.acceptedAcpContributions.single().taskId)
                assertContentEquals(fixture.after, output.resolve(fixture.relativePath).readBytes())
            } else {
                val failure = assertFailsWith<IllegalArgumentException> { ArchivalBundleVerifier.extractAndVerify(archive, output) }
                assertEquals("repair release rollback failure stage/code pair is invalid", failure.message)
                assertFalse(output.exists())
            }
        }
    }

    private data class RollbackFailurePairFixture(
        val root: Path, val profile: RepairIndexProfile, val canonical: String, val binding: ByteArray,
    )

    private fun rollbackPairFixture(pending: Boolean): RollbackFailurePairFixture {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val root = Files.createTempDirectory(parent, "rollback-pair-")
        root.resolve("code.c").writeText("before")
        val profile = DeclarativeRepairIndexProfile("rollback-pair", RepairIndexLayout(listOf("code.c"), listOf("code.c")))
        class RestoreRefusal : IllegalStateException("authored rollback operation refusal")
        var armed = false
        ModuleRevisionGraph.openLegacyForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
            if (armed && point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "rollback") throw RestoreRefusal()
        }).use { graph ->
            graph.enableRunContract()
            val attempt = graph.beginAttempt(listOf("code.c"))
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
            armed = true
            assertFailsWith<RestoreRefusal> { graph.reject(attempt) }
        }
        if (!pending) ModuleRevisionGraph.open(root, profile).close()
        val revisions = root.resolve("reports/repair-revisions")
        val canonical = revisions.resolve("graph.json").readText()
        val json = Json.parseToJsonElement(canonical).jsonObject
        val record = if (pending) json.getValue("pending").jsonObject.getValue("rollbackRecord").jsonObject
            else json.getValue("nodes").jsonArray.last().jsonObject.getValue("rollbackRecord").jsonObject
        assertEquals(if (pending) "restore_failed_unresolved" else "restored_after_failure", record.getValue("state").jsonPrimitive.content)
        assertEquals("source_restore", record.getValue("failureStage").jsonPrimitive.content)
        assertEquals("restore_operation_failed", record.getValue("failureCode").jsonPrimitive.content)
        return RollbackFailurePairFixture(root, profile, canonical, revisions.resolve("recovery-binding.json").readBytes())
    }

    private fun rollbackPairReplace(canonical: String, pending: Boolean, stage: RepairRollbackStage, code: RepairRollbackFailureCode): String {
        val graph = Json.parseToJsonElement(canonical).jsonObject
        val record = if (pending) graph.getValue("pending").jsonObject.getValue("rollbackRecord").jsonObject
            else graph.getValue("nodes").jsonArray.last().jsonObject.getValue("rollbackRecord").jsonObject
        val before = record.toString()
        assertTrue(before in canonical)
        assertEquals(canonical.indexOf(before), canonical.lastIndexOf(before))
        val changed = JsonObject(record + mapOf("failureStage" to JsonPrimitive(stage.name.lowercase()),
            "failureCode" to JsonPrimitive(code.name.lowercase()))).toString()
        return canonical.replace(before, changed) // Preserve every other canonical byte, including wire style.
    }

    private fun rollbackPairJson(record: RepairRollbackRecord): JsonObject = Json.parseToJsonElement(
        rollbackPairPrivate("toJson", record).toString()).jsonObject

    private fun rollbackPairPrivate(name: String, vararg arguments: Any): Any? = try {
        Class.forName("decompengine.repair.ModuleRevisionGraphKt").declaredMethods
            .single { method -> method.name == name && method.parameterCount == arguments.size &&
                method.parameterTypes.indices.all { index -> method.parameterTypes[index].isAssignableFrom(arguments[index].javaClass) }
            }.also { it.isAccessible = true }
            .invoke(null, *arguments)
    } catch (failure: java.lang.reflect.InvocationTargetException) { throw failure.targetException }


    @Test
    fun `revision directory role helper admits three immutable invocation documents per revision`() {
        assertFailsWith<IllegalArgumentException> { RepairResourceBudget(maximumRevisionNodes = 1) }
        for ((nodes, expected) in listOf(2 to 22, 64 to 208, 1_000_000 to 3_000_016)) {
            val selected = RepairResourceBudget(maximumRevisionNodes = nodes, maximumStateDirectoryEntries = 2)
            assertEquals(expected, repairRevisionDirectoryEntryLimit(selected))
            assertEquals(2, selected.maximumStateDirectoryEntries)
            assertEquals(nodes, selected.maximumRevisionNodes)
        }
    }

    @Test
    fun `archive name iterator charges all observations before duplicates or filtering`() {
        val selected = RepairResourceBudget(maximumRevisionNodes = 2, maximumStateDirectoryEntries = 2)
        val limit = repairRevisionDirectoryEntryLimit(selected)
        val fixed = listOf("graph.json", "recovery-binding.json", "blobs", "revision_00000001_abcd.acp-receipt.json",
            "legacy-graph-" + "0".repeat(64) + ".json", "legacy-graph-" + "1".repeat(64) + ".json")
        val names = fixed + (0 until limit - fixed.size).map { "irrelevant-$it" }
        class Entries(private val values: List<String>) : Iterable<Path>, AutoCloseable {
            var advanced = 0
            var closes = 0
            override fun iterator(): Iterator<Path> = object : Iterator<Path> {
                private var index = 0
                override fun hasNext() = index < values.size
                override fun next(): Path { advanced++; return Path.of(values[index++]) }
            }
            override fun close() { closes++ }
        }
        val exact = Entries(names)
        exact.use {
            assertEquals(names.toSet(), decompengine.project.RepairAcpEvidenceArchiveVerifier.boundedDeclaredSourceEntryNames(it, limit))
        }
        assertEquals(limit, exact.advanced); assertEquals(1, exact.closes)
        val overflow = Entries(names + "overflow")
        overflow.use {
            assertEquals("repair release declared source inventory exceeds its entry bound",
                assertFailsWith<IllegalArgumentException> {
                    decompengine.project.RepairAcpEvidenceArchiveVerifier.boundedDeclaredSourceEntryNames(it, limit)
                }.message)
        }
        assertEquals(limit + 1, overflow.advanced); assertEquals(1, overflow.closes)
        val duplicate = Entries(listOf("same", "same"))
        duplicate.use {
            assertEquals("repair release declared source inventory contains a duplicate entry",
                assertFailsWith<IllegalArgumentException> {
                    decompengine.project.RepairAcpEvidenceArchiveVerifier.boundedDeclaredSourceEntryNames(it, limit)
                }.message)
        }
        assertEquals(2, duplicate.advanced); assertEquals(1, duplicate.closes)
    }

    @Test
    fun `store candidate count refuses before first body while tiny blob migration really recovers`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val raw = Files.createTempDirectory(parent, "role-bound-raw-")
        LinuxFilesystemSyscalls.openRoot(raw).use { descriptor ->
            RepairStateStore.open(descriptor).use { store ->
                val revisions = raw.resolve("reports/repair-revisions")
                val selected = RepairResourceBudget(maximumRevisionNodes = 16, maximumStateDirectoryEntries = 2)
                val candidates = listOf("a", "b", "c").map { text ->
                    revisions.resolve("legacy-graph-" + sha256(text.toByteArray()) + ".json").also { it.writeText(text) }
                }
                revisions.resolve("irrelevant").writeText("not a body")
                revisions.resolve("revision_00000001_abcd.acp-receipt.json").writeText("traversal only; no receipt authority")
                var bodies = 0
                assertEquals("declared legacy graph candidate count exceeds its entry budget",
                    assertFailsWith<IllegalArgumentException> { store.forEachDeclaredLegacyGraph(selected) { _, _ -> bodies++ } }.message)
                assertEquals(0, bodies)
                Files.delete(candidates.last())
                val names = mutableListOf<String>()
                store.forEachDeclaredLegacyGraph(selected) { name, bytes -> names += name; assertEquals(1, bytes.size); bodies++ }
                assertEquals(2, bodies)
                assertEquals(candidates.take(2).map { it.fileName.toString() }.sorted(), names)
                assertTrue(Files.list(revisions).use { it.count() } > selected.maximumStateDirectoryEntries)
            }
        }
        val root = Files.createTempDirectory(parent, "role-bound-migration-")
        root.resolve("code.c").writeText("before")
        val profile = DeclarativeRepairIndexProfile("role-bound-migration", RepairIndexLayout(listOf("code.c"), listOf("code.c")))
        val selected = RepairResourceBudget(maximumRevisionNodes = 2, maximumStateDirectoryEntries = 2)
        ModuleRevisionGraph.open(root, profile, selected).use { graph ->
            val attempt = graph.beginAttempt(listOf("code.c")) // Actual pre-marker schema2.
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
        }
        val revisions = root.resolve("reports/repair-revisions")
        assertEquals(2L, Files.list(revisions.resolve("blobs")).use { it.count() })
        ModuleRevisionGraph.open(root, profile, selected).use { recovered ->
            assertEquals(6, recovered.snapshot.schemaVersion)
            assertNull(recovered.snapshot.pendingAttemptId)
            val record = requireNotNull(recovered.snapshot.nodes.last().rollbackRecord)
            assertEquals(RepairRollbackState.NOT_REQUIRED_VERIFIED, record.state)
            assertFalse(record.legacyPendingStateUnknown)
            assertEquals(false, record.candidateSourceInstallStarted)
            assertEquals(record.expectedSourceRevisionSha256, record.observedSourceRevisionSha256)
            assertEquals("before", root.resolve("code.c").readText())
        }
        assertTrue(Files.list(revisions).use { it.count() } > selected.maximumStateDirectoryEntries)
        // Fresh schema-6 recovery has no historical graph bytes to retain or migrate.
        assertEquals(0L, Files.newDirectoryStream(revisions, "legacy-graph-*.json").use { it.count().toLong() })
        assertEquals(2L, Files.list(revisions.resolve("blobs")).use { it.count() })
        ModuleRevisionGraph.open(root, profile, selected).close()
        assertEquals("before", root.resolve("code.c").readText())
    }

    @Test
    fun `archive candidate count is independent and refuses before invalid first payload`() {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize().also { Files.createDirectories(it) }
        val selected = RepairResourceBudget(maximumRevisionNodes = 128, maximumStateDirectoryEntries = 64)
        val fixture = releaseRepairFixture(temporaryParent = parent, budget = selected, legacyRejectedPrefix = true)
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("role-bound-archive.zip"))
        val overflow = fixture.project.parent.resolve("role-bound-declarations-overflow.zip")
        val declaredGraph = Regex("reports/repair-revisions/legacy-graph-[0-9a-f]{64}\\.json")
        rewriteArchive(bundle.archivePath, overflow) { entries ->
            val retained = entries.filterKeys(declaredGraph::matches)
            assertTrue(retained.isNotEmpty()) // The actual producer retained its pre-upgrade graph.
            assertTrue(retained.size <= selected.maximumStateDirectoryEntries)
            // Invalid bodies are behind the name-count gate. Admission must refuse on count
            // before attempting to parse the lexically first empty candidate below.
            repeat(selected.maximumStateDirectoryEntries - retained.size) { index ->
                val bytes = "{\"schemaVersion\":3,\"authoredIndex\":$index}".toByteArray()
                entries["reports/repair-revisions/legacy-graph-" + sha256(bytes) + ".json"] = bytes
            }
            assertEquals(selected.maximumStateDirectoryEntries, entries.keys.count(declaredGraph::matches))
            retained.forEach { (name, bytes) -> assertContentEquals(bytes, entries.getValue(name)) }
            // Lexically first matching candidate would fail size/hash admission if any body opened.
            entries["reports/repair-revisions/legacy-graph-" + "0".repeat(64) + ".json"] = byteArrayOf()
            assertEquals(selected.maximumStateDirectoryEntries + 1, entries.keys.count(declaredGraph::matches))
            val total = entries.keys.count { it.startsWith("reports/repair-revisions/") &&
                '/' !in it.removePrefix("reports/repair-revisions/") } + 1 // blobs directory
            assertTrue(total <= repairRevisionDirectoryEntryLimit(selected))
        }
        val refused = fixture.project.parent.resolve("role-bound-declarations-overflow-output")
        val failure = assertFailsWith<IllegalArgumentException> { ArchivalBundleVerifier.extractAndVerify(overflow, refused) }
        assertEquals("repair release declared graph candidate count exceeds its entry budget", failure.message)
        assertFalse(refused.exists())
    }

    private data class ReleaseRepairFixture(
        val project: Path,
        val relativePath: String,
        val after: ByteArray,
        val receiptPath: String,
        val requestSha256: String,
        val beforeManifest: ByteArray,
        val beforeConfidence: ByteArray,
        val beforeUnresolved: ByteArray,
    )

    private fun releaseRepairFixture(
        includeProvisional: Boolean = false,
        abandonProvisional: Boolean = false,
        rejectedAttempts: Int = 0,
        undispatchedFallback: Boolean = false,
        relativePath: String = "src/modules/alpha.c",
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
        temporaryParent: Path? = null,
        recoveredRollbackPrefix: Boolean = false,
        growRegressionCorpusAfterLegacyPrefix: Boolean = false,
        budget: RepairResourceBudget = RepairResourceBudget(),
        legacyRejectedPrefix: Boolean = false,
        legacyPrefixHasChanges: Boolean = true,
        intentOnlyRejectedPrefix: Boolean = false,
        provisionalAssessmentCrashPrefix: Boolean = false,
        schema7AgentEvidence: Boolean = false,
        cancelAfterValidatedAssessment: Boolean = false,
    ): ReleaseRepairFixture {
        require(!abandonProvisional || includeProvisional)
        val project = generatedProject(undispatchedFallback, profile, temporaryParent)
        val beforeManifest = project.resolve("source_tree_manifest.json").readBytes()
        val beforeConfidence = project.resolve(profile.layout.declaration("confidence-evidence").materialize()).readBytes()
        val beforeUnresolved = project.resolve(profile.layout.declaration("unresolved-evidence").materialize()).readBytes()
        val relative = relativePath
        val target = project.resolve(relative)
        val before = target.readBytes()
        val after = before + "\n/* archive release ACP repair */\n".toByteArray()
        require(listOf(
            recoveredRollbackPrefix,
            legacyRejectedPrefix,
            intentOnlyRejectedPrefix,
            provisionalAssessmentCrashPrefix,
        ).count { it } <= 1)
        require(!intentOnlyRejectedPrefix || schema7AgentEvidence)
        require(!provisionalAssessmentCrashPrefix || schema7AgentEvidence)
        val prefixAttempts = if (
            recoveredRollbackPrefix || legacyRejectedPrefix || intentOnlyRejectedPrefix || provisionalAssessmentCrashPrefix
        ) 1 else 0
        if (intentOnlyRejectedPrefix) {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile.forProfile(profile), budget).use { graph ->
                val corpus = graph.retainRegressionInputs(listOf(ProcessInput("archive-case", emptyList(), byteArrayOf())))
                graph.beginRun(2, 60_000)
                val attempt = graph.beginAttempt(listOf(relative), RevisionRepairMetadata(
                    1, "compile", "bounded failure", null, corpus.inputs.map(ProcessInput::id), null, corpus.sha256))
                val identity = decompengine.agent.AgentTurnIdentity(
                    java.util.UUID.randomUUID().toString(), attempt.id, "a".repeat(64), "interrupted-archive-workflow",
                )
                graph.createAndPersistAgentTurnIntent(
                    attempt, identity, "interrupted-archive-workflow", "b".repeat(64),
                )
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile.forProfile(profile), budget).use { graph ->
                val interrupted = graph.snapshot.nodes.last()
                assertEquals(ModuleRevisionStatus.REJECTED, interrupted.status)
                assertNotNull(interrupted.repairMetadata?.turnIntent)
                assertNull(interrupted.repairMetadata?.agentInvocation)
                graph.synchronizeRepairHistory()
            }
        }
        if (provisionalAssessmentCrashPrefix) {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile.forProfile(profile), budget).use { graph ->
                val corpus = graph.retainRegressionInputs(listOf(ProcessInput("archive-case", emptyList(), byteArrayOf())))
                graph.beginRun(2, 60_000)
                val attempt = graph.beginAttempt(listOf(relative), RevisionRepairMetadata(
                    1, "compile", "bounded failure", null, corpus.inputs.map(ProcessInput::id), null, corpus.sha256))
                val workflowId = "provisional-crash-archive-workflow"
                val document = completeAcpReceiptDocument(
                    project, attempt, relative, before, after,
                    turnWorkflowId = workflowId,
                )
                val verified = decompengine.project.verifyAcpExecutionReceiptDocument(
                    document.json.toByteArray(Charsets.UTF_8),
                    TRACE_REPAIR_ACP_RECEIPT_KIND,
                    TRACE_REPAIR_ACP_TASK_FIELD,
                    attempt.id,
                )
                val identity = requireNotNull(document.turnIdentity)
                val intent = decompengine.project.AgentTurnIntent.create(
                    identity,
                    workflowId,
                    attempt.id,
                    graph.snapshot.profileSha256,
                    verified.accessPolicySha256,
                    graph.snapshot.nodes.single { it.id == graph.snapshot.headId }.sourceRevisionSha256,
                )
                graph.persistAndBindAgentTurnIntent(attempt, intent)
                graph.persistAndBindAgentInvocation(attempt, document)
                graph.installCandidate(attempt, mapOf(relative to after))
                val proof = archiveValidationProofFixture(
                    graph, attempt, project, corpus.inputs, matched = false,
                    receiptName = "provisional-assessment-crash.validation.json",
                )
                graph.bindOriginalBinary(requireNotNull(proof.originalBinarySha256))
                graph.bindExpectedObservations(sha256(buildString {
                    append(proof.originalBinarySha256).append('\n')
                    corpus.inputs.forEach { input ->
                        append(input.id.length).append(':').append(input.id).append(":0:")
                            .append(sha256(byteArrayOf())).append(':').append(sha256(byteArrayOf())).append('\n')
                    }
                }.toByteArray()))
                val assessment = decompengine.project.AcpChangeAssessment.create(
                    intent = intent,
                    receiptSha256 = document.sha256,
                    sessionIdSha256 = verified.sessionIdCommitmentSha256?.let {
                        sha256("acp-session-commitment-v1:$it".toByteArray(Charsets.UTF_8))
                    },
                    changesSha256 = verified.resultChangesSha256,
                    beforeSha256 = intent.beforeSha256,
                    afterSha256 = proof.sourceRevisionSha256,
                    observation = decompengine.project.AcpChangeObservationStatus.COMPLETE,
                    protocolStopCode = null,
                    normalizedStopReason = AgentStopReason.COMPLETED,
                    policyVerdict = decompengine.project.AcpChangePolicyVerdict.ALLOW,
                    reasonCodes = emptyList(),
                    validationStatus = decompengine.project.AcpChangeValidationStatus.PASSED,
                    validationProofSha256 = listOf(proof.evidenceSha256),
                    eligibility = decompengine.project.AcpChangePublicationEligibility.PROVISIONAL,
                    updatesSha256 = verified.updatesSha256,
                )
                graph.persistAndBindAgentAssessment(attempt, assessment)
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile.forProfile(profile), budget).use { graph ->
                val recovered = graph.snapshot.nodes.last()
                assertEquals(ModuleRevisionStatus.REJECTED, recovered.status)
                assertTrue(recovered.recoveredAfterCrash)
                assertEquals(
                    RepairAgentAssessmentStatus.REJECTED,
                    recovered.repairMetadata?.agentInvocation?.assessmentStatus,
                )
                assertEquals(
                    decompengine.project.AcpChangePublicationEligibility.PROVISIONAL,
                    decompengine.project.AcpChangeAssessment.parse(
                        project.resolve(requireNotNull(recovered.repairMetadata?.agentInvocation?.assessmentPath))
                            .readBytes(),
                    ).eligibility,
                )
                graph.synchronizeRepairHistory()
            }
        }
        if (legacyRejectedPrefix) {
            require(!includeProvisional && rejectedAttempts == 0)
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile.forProfile(profile), budget).use { graph ->
                val corpus = graph.retainRegressionInputs(listOf(ProcessInput("archive-case", emptyList(), byteArrayOf())))
                graph.beginRun(1, 60_000)
                val attempt = graph.beginAttempt(listOf(relative), RevisionRepairMetadata(
                    1, "compile", "bounded failure", null, corpus.inputs.map(ProcessInput::id), null, corpus.sha256))
                graph.persistAndBindAgentInvocation(attempt, completeAcpReceiptDocument(project, attempt, relative, before, after,
                    includeModification = legacyPrefixHasChanges))
                if (legacyPrefixHasChanges) graph.installCandidate(attempt, mapOf(relative to after))
                // Detached candidate installation does not exchange the canonical source tree.
            }
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            val current = graphPath.readText()
            val schema3 = authoredLegacyGraphFixture(current, 3)
            assertNotEquals(current, schema3)
            graphPath.writeText(schema3)
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile.forProfile(profile), budget).use { graph ->
                val rejected = graph.snapshot.nodes.last()
                val record = requireNotNull(rejected.rollbackRecord)
                assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
                assertEquals(legacyPrefixHasChanges, rejected.changes.isNotEmpty())
                assertTrue(record.legacyPendingStateUnknown)
                assertEquals(if (legacyPrefixHasChanges) null else false, record.candidateSourceInstallStarted)
                assertEquals(if (legacyPrefixHasChanges) RepairRollbackState.RESTORED_VERIFIED
                    else RepairRollbackState.NOT_REQUIRED_VERIFIED, record.state)
                assertContentEquals(before, target.readBytes())
                graph.synchronizeRepairHistory()
            }
        }
        if (recoveredRollbackPrefix) {
            require(!includeProvisional && rejectedAttempts == 0)
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile.forProfile(profile), budget).use { }
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            val nativeWire = graphPath.readText()
            graphPath.writeText(authoredLegacyGraphFixture(nativeWire, 4))
            var prefixAttemptId = ""
            ModuleRevisionGraph.openForTesting(project, GeneratedCRepairIndexProfile.forProfile(profile), budget,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (point is ModuleRevisionFaultPoint.AfterPublicationExchange && point.phase == "promotion") {
                        throw SimulatedRepairCrash()
                    }
                }).use { graph ->
                val corpus = graph.retainRegressionInputs(listOf(ProcessInput("archive-case", emptyList(), byteArrayOf())))
                graph.beginRun(1, 60_000)
                val attempt = graph.beginAttempt(listOf(relative), RevisionRepairMetadata(
                    1, "compile", "bounded failure", null, corpus.inputs.map(ProcessInput::id), null, corpus.sha256))
                prefixAttemptId = attempt.id
                graph.persistAndBindAgentInvocation(attempt, completeAcpReceiptDocument(project, attempt, relative, before, after))
                graph.installCandidate(attempt, mapOf(relative to after))
                // This source/input/runtime tuple is genuinely identical to the later accepted proof.
                val proof = archiveValidationProofFixture(graph, attempt, project, corpus.inputs)
                graph.bindOriginalBinary(requireNotNull(proof.originalBinarySha256))
                graph.bindExpectedObservations(sha256(buildString {
                    append(proof.originalBinarySha256).append('\n')
                    corpus.inputs.forEach { input ->
                        append(input.id.length).append(':').append(input.id).append(":0:")
                            .append(sha256(byteArrayOf())).append(':').append(sha256(byteArrayOf())).append('\n')
                    }
                }.toByteArray()))
                assertFailsWith<SimulatedRepairCrash> {
                    graph.accept(attempt, RepairEvidence("valid", "synthetic archive prefix observations matched"), proof)
                }
                // Error poisons this instance. Only its close path is used after interruption.
            }
            assertContentEquals(after, target.readBytes())
            class PrefixRestoreRefusal : IllegalStateException("authored archive prefix startup restoration failure")
            var refusedExchanges = 0
            assertFailsWith<PrefixRestoreRefusal> {
                ModuleRevisionGraph.openForTesting(project, GeneratedCRepairIndexProfile.forProfile(profile), budget,
                    faultInjector = ModuleRevisionFaultInjector { point ->
                        if (point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "startup-rollback") {
                            refusedExchanges++
                            throw PrefixRestoreRefusal()
                        }
                    }).use { }
            }
            assertEquals(1, refusedExchanges)
            assertContentEquals(after, target.readBytes())
            val durable = Json.parseToJsonElement(project.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
            val failedRun = parseRepairRunState(durable.getValue("runs").jsonArray.single().toString())
            val pendingRecord = durable.getValue("pending").jsonObject.getValue("rollbackRecord").jsonObject
            assertEquals(RepairRunStatus.ROLLBACK_FAILED, failedRun.status)
            assertEquals(prefixAttemptId, failedRun.rollbackFailureAttemptId)
            assertEquals(RepairRollbackState.RESTORE_FAILED_UNRESOLVED, failedRun.rollbackResolution)
            assertEquals(prefixAttemptId, pendingRecord.getValue("attemptId").jsonPrimitive.content)
            assertEquals(failedRun.id, pendingRecord.getValue("runId").jsonPrimitive.content)
            assertEquals("restore_failed_unresolved", pendingRecord.getValue("state").jsonPrimitive.content)
            assertEquals("source_restore", pendingRecord.getValue("failureStage").jsonPrimitive.content)
            assertEquals("restore_operation_failed", pendingRecord.getValue("failureCode").jsonPrimitive.content)
            assertEquals(1, durable.getValue("nodes").jsonArray.size) // Still pending; no invented finalized iteration.
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile.forProfile(profile), budget).use { graph ->
                assertContentEquals(before, target.readBytes())
                val failed = graph.snapshot.runs.single()
                val rollback = requireNotNull(graph.snapshot.nodes.last().rollbackRecord)
                assertEquals(RepairRunStatus.ROLLBACK_FAILED, failed.status)
                assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, failed.rollbackResolution)
                assertEquals(failed.rollbackFailureAttemptId, rollback.attemptId)
                assertEquals(failed.id, rollback.runId)
                assertEquals(failed.rollbackResolution, rollback.state)
            }
        }
        lateinit var binding: RepairAgentInvocationBinding
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile.forProfile(profile), budget).use { graph ->
            var corpus = graph.retainRegressionInputs(listOf(ProcessInput("archive-case", emptyList(), byteArrayOf())))
            if (growRegressionCorpusAfterLegacyPrefix) {
                corpus = graph.retainRegressionInputs(listOf(
                    ProcessInput("archive-case", emptyList(), byteArrayOf()),
                    ProcessInput("later-archive-case", emptyList(), byteArrayOf(1)),
                ))
            }
            graph.beginRun((if (includeProvisional && !abandonProvisional) 2 else 1) + rejectedAttempts, 60_000)
            fun persistInvocationWithIntent(
                attempt: ModuleRevisionAttempt,
                document: AcpExecutionReceiptDocument,
            ): decompengine.project.AgentTurnIntent? {
                if (!schema7AgentEvidence) {
                    graph.persistAndBindAgentInvocation(attempt, document)
                    return null
                }
                val verified = decompengine.project.verifyAcpExecutionReceiptDocument(
                    document.json.toByteArray(Charsets.UTF_8),
                    TRACE_REPAIR_ACP_RECEIPT_KIND,
                    TRACE_REPAIR_ACP_TASK_FIELD,
                    attempt.id,
                )
                val identity = requireNotNull(document.turnIdentity)
                val workflowId = requireNotNull(identity.workflowRunId)
                val intent = decompengine.project.AgentTurnIntent.create(
                    identity,
                    workflowId,
                    attempt.id,
                    graph.snapshot.profileSha256,
                    verified.accessPolicySha256,
                    graph.snapshot.nodes.single {
                        it.id == (graph.snapshot.provisionalHeadId ?: graph.snapshot.headId)
                    }.sourceRevisionSha256,
                )
                assertEquals(attempt.id, intent.attemptId)
                assertEquals(attempt.id, intent.taskId)
                graph.persistAndBindAgentTurnIntent(attempt, intent)
                graph.persistAndBindAgentInvocation(attempt, document)
                return intent
            }
            fun bindObservations(proof: RepairValidationProof) {
                graph.bindOriginalBinary(requireNotNull(proof.originalBinarySha256))
                graph.bindExpectedObservations(sha256(buildString {
                    append(proof.originalBinarySha256).append('\n')
                    corpus.inputs.forEach { input ->
                        append(input.id.length).append(':').append(input.id).append(":0:")
                            .append(sha256(byteArrayOf())).append(':').append(sha256(byteArrayOf())).append('\n')
                    }
                }.toByteArray()))
            }
            repeat(rejectedAttempts) { index ->
                val rejected = graph.beginAttempt(listOf(relative), RevisionRepairMetadata(
                    prefixAttempts + index + 1, "compile", "bounded failure", null, corpus.inputs.map(ProcessInput::id), null, corpus.sha256))
                persistInvocationWithIntent(rejected,
                    completeAcpReceiptDocument(
                        project, rejected, relative, before, after,
                        turnWorkflowId = "archive-schema-seven-workflow".takeIf { schema7AgentEvidence },
                    ))
                graph.installCandidate(rejected, mapOf(relative to after))
                graph.reject(rejected, RepairEvidence("rejected", "synthetic prior rejected candidate"))
            }
            if (includeProvisional) {
                val path = "src/modules/beta.c"
                val betaBefore = project.resolve(path).readBytes()
                val betaAfter = betaBefore + "\n/* provisional archive improvement */\n".toByteArray()
                val provisional = graph.beginAttempt(listOf(path), RevisionRepairMetadata(
                    iterationIndex = prefixAttempts + rejectedAttempts + 1, failureKind = "compile", prompt = "bounded failure", summary = null,
                    retainedRegressionIds = corpus.inputs.map(ProcessInput::id), before = null,
                    regressionCorpusSha256 = corpus.sha256))
                persistInvocationWithIntent(provisional,
                    completeAcpReceiptDocument(
                        project, provisional, path, betaBefore, betaAfter,
                        turnWorkflowId = "archive-schema-seven-workflow".takeIf { schema7AgentEvidence },
                    ))
                graph.installCandidate(provisional, mapOf(path to betaAfter))
                val proof = archiveValidationProofFixture(graph, provisional, project, corpus.inputs,
                    matched = false, receiptName = "archive-provisional.validation.json")
                bindObservations(proof)
                graph.recordProvisional(provisional, RepairEvidence("behavior", "synthetic retained mismatch"), proof)
                assertContentEquals(betaBefore, project.resolve(path).readBytes())
                if (abandonProvisional) {
                    graph.finishRun(RepairRunStatus.ITERATION_EXHAUSTED, RepairEvidence("exhausted", "synthetic attempt budget exhausted"))
                    graph.beginRun(1, 60_000)
                }
            }
            val attempt = graph.beginAttempt(
                listOf(relative),
                RevisionRepairMetadata(
                    iterationIndex = prefixAttempts + (if (includeProvisional) 2 else 1) + rejectedAttempts,
                    failureKind = "compile",
                    prompt = "bounded failure",
                    summary = null,
                    retainedRegressionIds = corpus.inputs.map(ProcessInput::id),
                    before = null,
                    regressionCorpusSha256 = corpus.sha256,
                ),
            )
            val document = completeAcpReceiptDocument(
                project, attempt, relative, before, after,
                turnWorkflowId = "archive-schema-seven-workflow".takeIf { schema7AgentEvidence },
            )
            val intent = persistInvocationWithIntent(attempt, document)
            graph.installCandidate(attempt, mapOf(relative to after))
            val proof = archiveValidationProofFixture(graph, attempt, project, corpus.inputs)
            bindObservations(proof)
            if (intent != null) {
                val verified = decompengine.project.verifyAcpExecutionReceiptDocument(
                    document.json.toByteArray(Charsets.UTF_8),
                    TRACE_REPAIR_ACP_RECEIPT_KIND,
                    TRACE_REPAIR_ACP_TASK_FIELD,
                    attempt.id,
                )
                val assessment = decompengine.project.AcpChangeAssessment.create(
                    intent = intent,
                    receiptSha256 = document.sha256,
                    sessionIdSha256 = verified.sessionIdCommitmentSha256?.let {
                        sha256("acp-session-commitment-v1:$it".toByteArray(Charsets.UTF_8))
                    },
                    changesSha256 = verified.resultChangesSha256,
                    beforeSha256 = intent.beforeSha256,
                    afterSha256 = proof.sourceRevisionSha256,
                    observation = decompengine.project.AcpChangeObservationStatus.COMPLETE,
                    protocolStopCode = null,
                    normalizedStopReason = AgentStopReason.COMPLETED,
                    policyVerdict = decompengine.project.AcpChangePolicyVerdict.ALLOW,
                    reasonCodes = emptyList(),
                    validationStatus = decompengine.project.AcpChangeValidationStatus.PASSED,
                    validationProofSha256 = listOf(proof.evidenceSha256),
                    eligibility = decompengine.project.AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION,
                    updatesSha256 = verified.updatesSha256,
                )
                graph.persistAndBindAgentAssessment(attempt, assessment)
            }
            if (cancelAfterValidatedAssessment) {
                assertFailsWith<IllegalStateException> {
                    graph.accept(attempt, RepairEvidence("valid", "synthetic validated candidate"), proof) {
                        throw IllegalStateException("synthetic cancellation after durable assessment")
                    }
                }
                val rejected = graph.reject(attempt, RepairEvidence("cancelled", "pre-decision cancellation"))
                binding = requireNotNull(rejected.repairMetadata?.agentInvocation)
            } else {
                val accepted = graph.accept(attempt, RepairEvidence("valid", "synthetic archive fixture observations matched"), proof)
                binding = requireNotNull(accepted.repairMetadata?.agentInvocation)
            }
            graph.synchronizeRepairHistory()
        }
        assertEquals(0, MakeProjectBuilder.build(project, profile = profile).returnCode)
        return ReleaseRepairFixture(project, relative, after, binding.receiptPath, binding.requestSha256,
            beforeManifest, beforeConfidence, beforeUnresolved)
    }

    /** Synthetic serialization fixture only; this never qualifies the real validation provider. */
    private fun archiveValidationProofFixture(
        graph: ModuleRevisionGraph,
        attempt: ModuleRevisionAttempt,
        project: Path,
        inputs: List<ProcessInput>,
        matched: Boolean = true,
        receiptName: String = "archive-fixture.validation.json",
    ): RepairValidationProof {
        fun element(value: Any?): JsonElement = when (value) {
            null -> JsonNull
            is JsonElement -> value
            is String -> JsonPrimitive(value)
            is Boolean -> JsonPrimitive(value)
            is Number -> JsonPrimitive(value)
            is List<*> -> JsonArray(value.map(::element))
            else -> error("unsupported archive fixture JSON type")
        }
        fun obj(vararg fields: Pair<String, Any?>) = JsonObject(fields.associate { it.first to element(it.second) })
        fun canonical(value: JsonElement) = OracleJson.canonicalBytes(value, StrictJsonLimits())
        val snapshot = graph.snapshot
        val sources = graph.candidateSources(attempt)
        val sourceDigest = repairCandidateSourceSha256(sources)
        val referenceDigest = sha256("synthetic archive reference".toByteArray())
        val rebuiltDigest = sha256("synthetic archive rebuilt".toByteArray())
        val referenceManifest = sha256("synthetic reference runtime manifest".toByteArray())
        val rebuiltManifest = sha256("synthetic rebuilt runtime manifest".toByteArray())
        val tools = JsonObject(decompengine.project.GeneratedCRepairRuntimeConfiguration.TOOL_NAMES.mapValues { (role, name) ->
            obj("source" to "/fixture/tools/$name", "destination" to "/decomp-generated-c-tools/$name",
                "sha256" to sha256("synthetic tool $role".toByteArray()))
        })
        val runtime = obj("runtime" to obj("schemaVersion" to 1, "profileId" to GeneratedCRepairIndexProfile.profileId(),
            "sandboxConfigurationFile" to "/fixture/sandbox.json", "tools" to tools,
            "buildRuntimeMounts" to emptyList<JsonElement>(), "programRuntimeMounts" to emptyList<JsonElement>(),
            "sourceTmpfs" to "/fixture/source", "outputTmpfs" to "/fixture/output"),
            "sandboxConfigurationSha256" to sha256("synthetic sandbox configuration".toByteArray()))
        val runtimeDigest = sha256(canonical(runtime))
        fun quota(mount: Int, target: String) = obj("provider" to "dedicated-tmpfs-size+nr_inodes",
            "mountId" to mount, "maximumBytes" to 1_048_576, "maximumEntries" to 512,
            "mountPathSha256" to sha256(target.toByteArray()))
        val outputQuota = quota(102, "/fixture/output")
        val files = JsonArray(sources.toSortedMap().map { (path, bytes) -> obj("path" to path,
            "role" to if (path == "Makefile") "build-file" else "source", "mode" to 292,
            "bytes" to bytes.size, "sha256" to sha256(bytes)) })
        fun executable(digest: String, manifest: String, role: String) = obj("sha256" to digest,
            "runtimeManifestSha256" to manifest, "bytes" to 64, "mode" to 320, "role" to role)
        fun scope(role: String, input: ProcessInput?, manifest: String?): JsonObject {
            val command = listOf("/fixture/$role") + input?.args.orEmpty()
            val fields = linkedMapOf("provider" to "bubblewrap+systemd-cgroup-v2",
                "launch[0].purpose" to "CANDIDATE_VALIDATION", "launch[0].mergeError" to "false",
                "launch[0].command" to acpSandboxCanonicalStringDigest(command),
                "launch[0].writableMountClosure" to sha256("synthetic mount closure".toByteArray()),
                "authority[0].mode" to "READ_WRITE")
            listOf("cgroup.pids", "cgroup.memory", "cgroup.cpu", "network", "nestedUserns", "newSession",
                "dieWithParent", "launch[0].gate.positiveByte").forEach { fields[it] = "true" }
            mapOf("provider" to "provider", "mount" to "mountId", "bytes" to "maximumBytes",
                "entries" to "maximumEntries", "path" to "mountPathSha256").forEach { (field, key) ->
                fields["authority[0].quota.$field"] = (outputQuota.getValue(key) as JsonPrimitive).content
            }
            manifest?.let {
                fields["launch[0].executable.manifest"] = it
                fields["launch[0].executable.configuredManifest"] = it
            }
            val sandboxDigest = sha256(buildString {
                fields.forEach { (name, value) -> append(name.length).append(':').append(name)
                    .append(value.length).append(':').append(value).append(';') }
            }.toByteArray())
            return obj("role" to role, "inputId" to input?.id,
                "output" to obj("command" to command, "exitCode" to 0, "stdoutBase64" to "",
                    "stderrBase64" to if (!matched && role == "candidate") "ZGlmZg==" else "",
                    "networkIsolated" to true), "sandboxSha256" to sandboxDigest,
                "sandboxFields" to fields.map { listOf(it.key, it.value) }, "writableQuota" to outputQuota,
                "cleanupVerified" to true)
        }
        val receipt = obj("schemaVersion" to 2, "provider" to "generated-c-linux-bubblewrap-cgroup-v1",
            "profileId" to GeneratedCRepairIndexProfile.profileId(), "profileSha256" to snapshot.profileSha256,
            "indexSha256" to snapshot.indexSha256, "sourceRevisionSha256" to sourceDigest,
            "regressionCorpusSha256" to repairRegressionCorpusSha256(inputs), "runtimeSha256" to runtimeDigest,
            "runtimeConfiguration" to runtime,
            "behaviorBudgetEvidence" to decompengine.project.GeneratedCValidationBudgetPolicy.DEFAULT.admit(RepairResourceBudget()),
            "sourceSnapshot" to obj("manifestSha256" to sha256(canonical(files)), "files" to files,
                "quota" to quota(101, "/fixture/source")),
            "buildOutputLink" to obj("path" to "build", "role" to "application-owned-output-link",
                "target" to "/fixture/output/staging", "quota" to outputQuota),
            "originalExecutable" to executable(referenceDigest, referenceManifest, "reference"),
            "rebuiltExecutable" to executable(rebuiltDigest, rebuiltManifest, "candidate"),
            "inputs" to inputs.map { obj("id" to it.id, "args" to it.args,
                "stdinBase64" to java.util.Base64.getEncoder().encodeToString(it.stdin)) },
            "scopes" to listOf(scope("build", null, null)) + inputs.flatMap {
                listOf(scope("reference", it, referenceManifest), scope("candidate", it, rebuiltManifest)) },
            "outcome" to "behavior-checked", "caseCount" to inputs.size, "matches" to matched,
            "cleanupVerified" to true, "assurance" to "strict-contained")
        val bytes = canonical(receipt)
        val receiptPath = project.resolve("reports/$receiptName")
        if (Files.exists(receiptPath, LinkOption.NOFOLLOW_LINKS)) {
            // Reuse only an identical, currently bound payload; never rewrite an earlier proof.
            assertTrue(Files.isRegularFile(receiptPath, LinkOption.NOFOLLOW_LINKS))
            assertContentEquals(bytes, receiptPath.readBytes(), "archive fixture receipt path has different bound bytes")
        } else {
            Files.write(receiptPath, bytes, java.nio.file.StandardOpenOption.CREATE_NEW, java.nio.file.StandardOpenOption.WRITE)
        }
        return RepairValidationProof(sourceDigest, snapshot.profileSha256, snapshot.indexSha256,
            repairRegressionCorpusSha256(inputs), referenceDigest, rebuiltDigest, runtimeDigest, sha256(bytes), true,
            RepairValidationAssurance.STRICT_CONTAINED)
    }

    /** Synthetic proof material for graph-mechanics tests; this is not provider qualification. */
    private fun beginSyntheticAcceptedRun(
        graph: ModuleRevisionGraph,
        mode: RepairPublicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE,
        template: RevisionRepairMetadata? = null,
    ): RevisionRepairMetadata {
        var corpus = graph.retainedRegressionCorpus()
        if (corpus.inputs.isEmpty()) {
            corpus = graph.retainRegressionInputs(listOf(ProcessInput("synthetic-acceptance", emptyList(), byteArrayOf(0))))
        }
        graph.beginRun(maximumAttempts = 16, maximumWallMillis = 60_000)
        graph.bindOriginalBinary(sha256("synthetic original binary".toByteArray()))
        graph.bindExpectedObservations(sha256("synthetic expected observations".toByteArray()))
        val nextIteration = (graph.snapshot.nodes.mapNotNull { it.repairMetadata?.iterationIndex }.maxOrNull() ?: 0) + 1
        return (template ?: RevisionRepairMetadata(
            iterationIndex = nextIteration,
            failureKind = "compile",
            prompt = "synthetic graph acceptance control",
            summary = null,
            retainedRegressionIds = corpus.inputs.map { it.id },
            before = null,
            regressionCorpusSha256 = corpus.sha256,
            publicationMode = mode,
        )).copy(
            iterationIndex = nextIteration,
            retainedRegressionIds = corpus.inputs.map { it.id },
            regressionCorpusSha256 = corpus.sha256,
            publicationMode = mode,
            runId = null,
        )
    }

    private fun syntheticAcceptedProof(graph: ModuleRevisionGraph, attempt: ModuleRevisionAttempt): RepairValidationProof {
        val snapshot = graph.snapshot
        val corpus = graph.retainedRegressionCorpus()
        val sources = graph.candidateSources(attempt)
        val digest = sha256("synthetic graph validation evidence".toByteArray())
        return RepairValidationProof(
            sourceRevisionSha256 = repairCandidateSourceSha256(sources),
            profileSha256 = snapshot.profileSha256,
            indexSha256 = snapshot.indexSha256,
            regressionCorpusSha256 = corpus.sha256,
            originalBinarySha256 = sha256("synthetic original binary".toByteArray()),
            rebuiltBinarySha256 = sha256("synthetic rebuilt binary".toByteArray()),
            runtimeSha256 = sha256("synthetic runtime".toByteArray()),
            evidenceSha256 = digest,
            cleanupVerified = true,
            assurance = RepairValidationAssurance.STRICT_CONTAINED,
        )
    }

    private fun rewriteArchive(
        source: Path,
        target: Path,
        mutation: (MutableMap<String, ByteArray>) -> Unit,
    ) {
        val entries = linkedMapOf<String, ByteArray>()
        ZipInputStream(Files.newInputStream(source)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                entries[entry.name] = zip.readBytes()
                zip.closeEntry()
            }
        }
        entries.remove("ARCHIVE_MANIFEST.sha256")
        mutation(entries)
        entries["ARCHIVE_MANIFEST.sha256"] = entries.toSortedMap().entries.joinToString("") { (path, bytes) ->
            "${sha256(bytes)}  $path\n"
        }.toByteArray()
        ZipOutputStream(Files.newOutputStream(target)).use { zip ->
            entries.toSortedMap().forEach { (path, bytes) ->
                val crc = CRC32().apply { update(bytes) }
                val entry = ZipEntry(path).apply {
                    method = ZipEntry.STORED
                    size = bytes.size.toLong()
                    compressedSize = size
                    this.crc = crc.value
                    time = 0L
                }
                zip.putNextEntry(entry)
                zip.write(bytes)
                zip.closeEntry()
            }
        }
    }

    private fun genericProject(prefix: String, files: Map<String, String>): Path {
        val project = createTempDirectory(prefix).resolve("project")
        files.forEach { (relative, content) ->
            val target = project.resolve(relative)
            target.parent.createDirectories()
            target.writeText(content)
        }
        return project
    }

    private fun minimalGeneratedCProject(programModelJson: String): Path = genericProject(
        "repair-generated-evidence-",
        mapOf(
            "Makefile" to "all:\n\t@true\n",
            "include/decomp_types.h" to "#pragma once\n",
            "include/main.h" to "#pragma once\nint main(void);\n",
            "src/main.c" to "#include \"main.h\"\nint main(void) { return 0; }\n",
            "reports/module_plan.json" to
                "{\"schemaVersion\":1,\"modules\":[{\"id\":\"main_module\"," +
                "\"sourcePath\":\"src/main.c\",\"headerPath\":\"include/main.h\"," +
                "\"functionIds\":[\"fn_main\"],\"globalIds\":[],\"boundaryEvidence\":[]}]," +
                "\"dependencyCycles\":[]}",
            "reports/program_model.json" to programModelJson,
        ),
    )

    private fun dependencyOnlyProject(includeDependency: Boolean, globalDependency: Boolean): Path {
        val project = createTempDirectory("repair-dependency-").resolve("project")
        project.resolve("src/modules").createDirectories()
        project.resolve("include/modules").createDirectories()
        project.resolve("reports").createDirectories()
        project.resolve("Makefile").writeText("all:\n\t@true\n")
        project.resolve("include/decomp_types.h").writeText("#pragma once\n")
        project.resolve("include/modules/consumer.h").writeText("#pragma once\n")
        project.resolve("include/modules/provider.h").writeText("#pragma once\n")
        project.resolve("src/modules/consumer_internal.h").writeText("#pragma once\n")
        project.resolve("src/modules/provider_internal.h").writeText("#pragma once\n")
        val providerInclude = if (includeDependency) "#include \"modules/provider.h\"\n" else ""
        project.resolve("src/modules/consumer.c").writeText(
            "#include \"modules/consumer.h\"\n${providerInclude}int consumer_run(void) { return 0; }\n",
        )
        project.resolve("src/modules/provider.c").writeText(
            "#include \"modules/provider.h\"\nint provider_run(void) { return 0; }\n",
        )
        val providerGlobals = if (globalDependency) "[\"global_state\"]" else "[]"
        val globals = if (globalDependency) {
            "[{\"id\":\"global_state\",\"name\":\"global_state\",\"address\":\"0x3000\",\"type\":\"int\",\"initializer\":null,\"status\":\"recovered\"}]"
        } else {
            "[]"
        }
        val references = if (globalDependency) "[\"global_state\"]" else "[]"
        project.resolve("reports/module_plan.json").writeText(
            "{\"schemaVersion\":1,\"modules\":[" +
                "{\"id\":\"consumer\",\"sourcePath\":\"src/modules/consumer.c\",\"headerPath\":\"include/modules/consumer.h\",\"functionIds\":[\"fn_consumer\"],\"globalIds\":[],\"boundaryEvidence\":[]}," +
                "{\"id\":\"provider\",\"sourcePath\":\"src/modules/provider.c\",\"headerPath\":\"include/modules/provider.h\",\"functionIds\":[\"fn_provider\"],\"globalIds\":$providerGlobals,\"boundaryEvidence\":[]}],\"dependencyCycles\":[]}",
        )
        project.resolve("reports/program_model.json").writeText(
            "{\"schemaVersion\":1,\"inputSha256\":\"fixture\",\"functions\":[" +
                "{\"id\":\"fn_consumer\",\"name\":\"consumer_run\",\"address\":\"0x1\",\"prototype\":\"int consumer_run(void)\",\"status\":\"recovered\",\"calls\":[],\"referencedGlobals\":$references,\"strings\":[],\"decompiledC\":null}," +
                "{\"id\":\"fn_provider\",\"name\":\"provider_run\",\"address\":\"0x2\",\"prototype\":\"int provider_run(void)\",\"status\":\"recovered\",\"calls\":[],\"referencedGlobals\":[],\"strings\":[],\"decompiledC\":null}],\"globals\":$globals,\"types\":[]}",
        )
        return project
    }

    private fun failedAcpReceiptDocument(
        project: Path,
        attempt: ModuleRevisionAttempt,
    ): AcpExecutionReceiptDocument {
        val request = AgentExecutionRequest(
            objective = "repair one module",
            workspaceRoots = listOf(AgentWorkspaceRoot("project", project)),
            accessPolicy = AgentAccessPolicy(emptyList()),
        )
        val receipt = AgentExecutionReceipt(
            requestBinding = AgentExecutionRequestBinding.capture(request),
            outcome = AgentExecutionOutcome.Failed(
                AgentFailure(AgentFailureKind.PROTOCOL, "peer-controlled failure text"),
            ),
            providerEvidence = AcpInvocationEvidenceSnapshot(
                factoryProvenance = null,
                phaseReached = AcpExecutionLifecyclePhase.REQUEST_BOUND,
                cleanupDisposition = AcpExecutionCleanupDisposition.NOT_REQUIRED,
                negotiatedAgent = null,
                wirePromptSha256 = null,
                diagnostics = null,
                filesystemAudit = emptyList(),
                terminalAudit = emptyList(),
                permissionAudit = emptyList(),
                sandboxEvidence = null,
                completeness = AcpExecutionEvidenceCompleteness(true, true, true),
                completeExecutionEvidence = null,
            ),
        )
        return requireNotNull(
            AcpExecutionReceiptDocument.captureOrNull(
                request,
                sha256("bounded failure".toByteArray()),
                receipt,
                BoundedAgentExecutionEventRecorder().receiptSnapshot(),
                "decomp-engine.trace-repair-acp-execution-receipt",
                "attemptId",
                attempt.id,
            ),
        )
    }

    internal fun completeAcpReceiptDocument(
        project: Path,
        attempt: ModuleRevisionAttempt,
        relativePath: String,
        before: ByteArray,
        after: ByteArray,
        includeModification: Boolean = true,
        turnWorkflowId: String? = null,
    ): AcpExecutionReceiptDocument {
        val workspacePath = AgentWorkspacePath("project", relativePath)
        val request = AgentExecutionRequest(
            objective = "repair one module",
            workspaceRoots = listOf(AgentWorkspaceRoot("project", project)),
            accessPolicy = AgentAccessPolicy(
                listOf(AgentPathRule(workspacePath, setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE))),
            ),
        )
        val changes = if (includeModification) listOf(AgentFileChange(
            workspacePath,
            AgentFileChangeKind.MODIFIED,
            sha256(before),
            sha256(after),
            after.size.toLong(),
        )) else emptyList()
        val implementationId = "repair-test-acp"
        val turnIdentity = turnWorkflowId?.let { workflowId ->
            val requestBinding = AgentExecutionRequestBinding.capture(request)
            AgentTurnIdentity(java.util.UUID.randomUUID().toString(), attempt.id,
                requestBinding.requestSha256, workflowId)
        }
        val factory = AcpHarnessProvenance(
            harness = "acp",
            implementationId = implementationId,
            agentExecutionContractVersion = 1,
            acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION,
            acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
            configurationSha256 = "a".repeat(64),
            deprecated = false,
        )
        val negotiated = AcpNegotiatedAgentEvidence(
            ACP_STABLE_PROTOCOL_VERSION,
            "repair test agent",
            "1",
            null,
            AcpNegotiatedCapabilitiesEvidence(false, false, false, false, false, false, false),
        )
        val diagnostics = AcpProcessDiagnostics(
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
        )
        val sandbox = AcpSandboxEvidence(
            provider = "sandbox-evidence-v1",
            providerVersion = "1",
            providerExecutableSha256 = "b".repeat(64),
            providerExecutableMode = 365,
            resourceLimiterSha256 = "c".repeat(64),
            scopeSupervisorSha256 = "d".repeat(64),
            scopeInspectorSha256 = "e".repeat(64),
            environmentFdOpenerSha256 = "f".repeat(64),
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
            policySha256 = "1".repeat(64),
            terminalLimits = null,
            launches = emptyList(),
            authorities = emptyList(),
            terminalAudit = emptyList(),
            outerProcessOutput = AcpProducedOutputEvidence(1_024, 0, false),
        )
        val complete = AcpExecutionEvidenceSnapshot(
            factory,
            negotiated,
            "2".repeat(64),
            diagnostics,
            emptyList(),
            emptyList(),
            emptyList(),
            sandbox,
        )
        val result = AgentExecutionResult(
            AgentStopReason.COMPLETED,
            "peer completion summary",
            changes,
            AgentSessionReference(implementationId, "repair-session"),
        )
        val recorder = BoundedAgentExecutionEventRecorder().also {
            changes.forEachIndexed { index, change -> it.record(AgentFileChangeEvent(index.toLong(), change)) }
        }
        val receipt = AgentExecutionReceipt(
            AgentExecutionRequestBinding.capture(request),
            AgentExecutionOutcome.Returned(result),
            AcpInvocationEvidenceSnapshot(
                factory,
                AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT,
                AcpExecutionCleanupDisposition.VERIFIED,
                negotiated,
                complete.wirePromptSha256,
                diagnostics,
                emptyList(),
                emptyList(),
                emptyList(),
                sandbox,
                AcpExecutionEvidenceCompleteness(true, true, true),
                complete,
            ),
            turnIdentity = turnIdentity,
        )
        return requireNotNull(
            AcpExecutionReceiptDocument.captureOrNull(
                request,
                sha256("bounded failure".toByteArray()),
                receipt,
                recorder.receiptSnapshot(),
                "decomp-engine.trace-repair-acp-execution-receipt",
                "attemptId",
                attempt.id,
            ),
        )
    }

    private class SimulatedRepairCrash : Error("simulated repair process crash")
    private class SimulatedRepairTermination : Throwable("simulated non-exception process termination")

    private fun createScaleProject(project: Path, moduleCount: Int, functionsPerModule: Int) {
        project.resolve("src/modules").createDirectories()
        project.resolve("include/modules").createDirectories()
        project.resolve("reports").createDirectories()
        project.resolve("Makefile").writeText("all:\n\t@true\n")
        project.resolve("include/decomp_types.h").writeText("#pragma once\n")

        val modules = (0 until moduleCount).map { index -> "module_${index.toString().padStart(4, '0')}" }
        modules.forEach { module ->
            project.resolve("src/modules/$module.c").writeText("#include \"modules/$module.h\"\n")
            project.resolve("src/modules/${module}_internal.h").writeText("#pragma once\n")
            project.resolve("include/modules/$module.h").writeText("#pragma once\n")
        }
        val functionIds = modules.associateWith { module ->
            (0 until functionsPerModule).map { offset -> "fn_${module}_$offset" }
        }
        project.resolve("reports/module_plan.json").writeText(
            buildString {
                append("{\"schemaVersion\":1,\"modules\":[")
                append(modules.joinToString(",") { module ->
                    "{\"id\":\"$module\",\"sourcePath\":\"src/modules/$module.c\"," +
                        "\"headerPath\":\"include/modules/$module.h\",\"functionIds\":" +
                        functionIds.getValue(module).joinToString(prefix = "[", postfix = "]") { "\"$it\"" } +
                        ",\"globalIds\":[],\"boundaryEvidence\":[]}"
                })
                append("],\"dependencyCycles\":[]}")
            },
        )
        project.resolve("reports/program_model.json").writeText(
            buildString {
                append("{\"schemaVersion\":1,\"inputSha256\":\"scale\",\"functions\":[")
                append(modules.flatMapIndexed { moduleIndex, module ->
                    functionIds.getValue(module).mapIndexed { functionIndex, id ->
                        val calls = if (functionIndex == 0 && moduleIndex > 0) {
                            "[\"${functionIds.getValue(modules[moduleIndex - 1]).first()}\"]"
                        } else {
                            "[]"
                        }
                        "{\"id\":\"$id\",\"name\":\"${module}_function_$functionIndex\"," +
                            "\"address\":\"0x1\",\"prototype\":\"int f(void)\",\"status\":\"recovered\"," +
                            "\"calls\":$calls,\"referencedGlobals\":[],\"strings\":[],\"decompiledC\":null}"
                    }
                }.joinToString(","))
                append("],\"globals\":[],\"types\":[]}")
            },
        )
    }
}

private fun readProjectSourceWithoutAtime(root: Path, relative: String): ByteArray {
    val components = relative.split('/')
    return LinuxFilesystemSyscalls.openRoot(root).use { rootDescriptor ->
        var parent = rootDescriptor
        val opened = mutableListOf<decompengine.acp.LinuxDescriptor>()
        try {
            components.dropLast(1).forEach { segment ->
                parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, segment)
                opened += parent
            }
            val pinned = requireNotNull(
                LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, components.last()),
            )
            pinned.use { file ->
                LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(file).use { readable ->
                    LinuxFilesystemSyscalls.readWithoutAtime(readable, 1_048_576)
                }
            }
        } finally {
            opened.asReversed().forEach(decompengine.acp.LinuxDescriptor::close)
        }
    }
}
