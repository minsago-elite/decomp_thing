package decompengine.repair

import decompengine.acp.*
import decompengine.agent.*
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.GeneratedCRepairIndexProfile
import decompengine.project.AcpExecutionReceiptDocument
import decompengine.project.BoundedAgentExecutionEventRecorder
import decompengine.project.SourceTreeGenerator
import decompengine.project.providerDataFixtureInvocationForTest
import decompengine.project.sha256
import decompengine.project.verifyAcpExecutionReceiptDocument
import decompengine.validation.BehaviorComparisonReport
import decompengine.validation.ProcessInput
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.io.path.writeBytes
import kotlin.test.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Data fixtures exercise normal graph publication; they never launch or qualify a provider. */
class RepairProviderReceiptRetentionTest {
    @Test
    fun `normal repair loop durably rejects a provider v3 failure before any candidate is installed`() = withProject { project ->
        val original = project.resolve("fixture.original").also { it.writeBytes(byteArrayOf(1, 2, 3)) }
        val before = project.resolve("src/modules/alpha.c").readBytes()
        var calls = 0
        val harness = object : CapturedRepairAgentHarness {
            override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit): AgentExecutionResult =
                error("receipt path required")
            override fun executeCaptured(request: AgentExecutionRequest, initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput, onEvent: (AgentExecutionEvent) -> Unit): AgentExecutionResult =
                error("receipt path required")
            override fun executeCapturedReceipt(request: AgentExecutionRequest, initialFiles: Map<String, ByteArray>,
                output: BoundedRepairOutput, onEvent: (AgentExecutionEvent) -> Unit): AgentExecutionReceipt {
                calls++
                return AgentExecutionReceipt(AgentExecutionRequestBinding.capture(request),
                    AgentExecutionOutcome.Failed(AgentFailure(AgentFailureKind.PROTOCOL, "fixture protocol failure")),
                    providerDataFixtureInvocationForTest(request, AcpHarnessProvenance("acp", "provider-fixture",
                        AGENT_EXECUTION_CONTRACT_VERSION, ACP_STABLE_PROTOCOL_VERSION, ACP_KOTLIN_SDK_VERSION,
                        "1".repeat(64), false)))
            }
        }
        // This data-only validation fixture starts no process and supplies no release authority.
        val validation = object : RepairValidationStrategy {
            override val assurance = RepairValidationAssurance.TEST_ONLY_HOST_PROCESS
            override fun requireAvailable() = Unit
            override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget) =
                CompileFailure(listOf("fixture-compile"), 1, "", "src/modules/alpha.c:1: fixture failure")
            override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path = error("no candidate")
            override fun evaluateBehavior(id: String, projectDir: Path, originalBinary: Path, rebuiltBinary: Path,
                inputs: List<ProcessInput>, reportsDir: Path, budget: RepairResourceBudget): BehaviorComparisonReport =
                error("no candidate")
        }
        val history = RepairHistory(project.resolve("reports/repair_history.json"))
        val outcome = TraceGuidedRepairLoop.forTesting(harness, history, GeneratedCRepairIndexProfile, validation,
            CapturedRepairStagingAuthority).use { it.runRepair(project, original, emptyList(), maxIterations = 1) }
        assertEquals(1, calls)
        assertNotEquals(RepairRunStatus.FULLY_ACCEPTED, outcome.runState.status)
        val iteration = history.all().single()
        assertFalse(iteration.succeeded)
        val binding = assertNotNull(iteration.agentInvocation)
        assertEquals(3, binding.receiptSchemaVersion)
        assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
        assertEquals("failed-protocol", binding.terminalOutcome)
        assertFalse(binding.receiptReleaseComplete)
        assertEquals(binding.receiptSha256, sha256(project.resolve(binding.receiptPath).readBytes()))
        assertContentEquals(before, project.resolve("src/modules/alpha.c").readBytes())
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { replay ->
            val node = replay.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, node.status)
            assertTrue(node.changes.isEmpty())
            assertEquals(binding, node.repairMetadata?.agentInvocation)
            assertNotEquals(node.id, replay.snapshot.headId)
        }
    }

    @Test
    fun `normal graph publication retains binds rejects and replays provider v3 without an orphan`() = withProject { project ->
        lateinit var binding: RepairAgentInvocationBinding
        lateinit var document: AcpExecutionReceiptDocument
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = attempt(graph)
            document = receipt(project, attempt.id, providerV3 = true)
            binding = try {
                graph.persistAndBindAgentInvocation(attempt, document)
            } catch (failure: Exception) {
                val raw = project.resolve("reports/repair-revisions/${attempt.id}.acp-receipt.json")
                throw AssertionError("schema-v3 publication failed; immutable receipt exists=${Files.exists(raw)}", failure)
            }
            assertEquals(3, binding.receiptSchemaVersion)
            assertEquals(RepairAgentAssessmentStatus.PENDING, binding.assessmentStatus)
            assertFalse(binding.receiptReleaseComplete)
            assertEquals(document.sha256, binding.receiptSha256)
            assertEquals(document.requestSha256, binding.requestSha256)
            assertEquals(document.resultChangesSha256, binding.resultChangesSha256)
            val rejected = graph.reject(attempt, RepairEvidence("agent-failure", "fixture protocol failure"))
            binding = assertNotNull(rejected.repairMetadata?.agentInvocation)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
            graph.synchronizeRepairHistory()
        }
        val raw = project.resolve(binding.receiptPath).readBytes()
        assertContentEquals(document.json.toByteArray(), raw)
        assertEquals(binding.receiptSha256, sha256(raw))
        assertEquals("3", Json.parseToJsonElement(raw.decodeToString()).jsonObject.getValue("schemaVersion").jsonPrimitive.content)
        val verified = verifyAcpExecutionReceiptDocument(raw, TRACE_REPAIR_ACP_RECEIPT_KIND, TRACE_REPAIR_ACP_TASK_FIELD,
            Path.of(binding.receiptPath).fileName.toString().removeSuffix(".acp-receipt.json"))
        assertFalse(verified.releaseComplete)
        assertNull(verified.releaseFacts)
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { replay ->
            assertEquals(binding, replay.snapshot.nodes.last().repairMetadata?.agentInvocation)
            assertNotEquals(replay.snapshot.nodes.last().id, replay.snapshot.headId)
        }
        val history = RepairHistory(project.resolve("reports/repair_history.json")).all().single()
        assertEquals(binding, history.agentInvocation)
        assertFalse(history.releaseComplete)
    }

    @Test
    fun `durable unbound provider v3 recovers as rejected with its actual version`() = withProject { project ->
        var armed = false
        val graph = ModuleRevisionGraph.openForTesting(project, GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                    point.scope == "revision-state" && point.name == "graph.json") {
                    throw IllegalStateException("injected graph publication failure")
                }
            })
        val attempt = attempt(graph)
        val document = receipt(project, attempt.id, providerV3 = true)
        armed = true
        val failure = assertFailsWith<RepairAgentEvidencePersistenceException> {
            graph.persistAndBindAgentInvocation(attempt, document)
        }
        assertTrue(failure.message.orEmpty().contains("preserved"))
        val rawPath = project.resolve("reports/repair-revisions/${attempt.id}.acp-receipt.json")
        assertContentEquals(document.json.toByteArray(), rawPath.readBytes())
        val pending = Json.parseToJsonElement(project.resolve("reports/repair-revisions/graph.json").readText())
            .jsonObject.getValue("pending").jsonObject
        assertEquals(attempt.id, pending.getValue("id").jsonPrimitive.content)
        assertEquals(JsonNull, pending.getValue("repairMetadata").jsonObject.getValue("agentInvocation"),
            "recovery must discover an unbound durable receipt rather than replay an already-bound one")
        graph.close()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            val node = recovered.snapshot.nodes.last()
            assertTrue(node.recoveredAfterCrash)
            assertEquals(ModuleRevisionStatus.REJECTED, node.status)
            val binding = assertNotNull(node.repairMetadata?.agentInvocation)
            assertEquals(3, binding.receiptSchemaVersion)
            assertEquals(document.sha256, binding.receiptSha256)
            assertEquals(document.requestSha256, binding.requestSha256)
            assertEquals(document.resultChangesSha256, binding.resultChangesSha256)
            assertFalse(binding.receiptReleaseComplete)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, binding.assessmentStatus)
        }
        assertEquals(document.sha256, sha256(rawPath.readBytes()))
    }

    @Test
    fun `replay rejects a schema v3 receipt cross-paired with a schema v2 graph binding`() = withProject { project ->
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = attempt(graph)
            graph.persistAndBindAgentInvocation(attempt, receipt(project, attempt.id, providerV3 = true))
            graph.reject(attempt, RepairEvidence("agent-failure", "fixture protocol failure"))
        }
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val before = graphPath.readText()
        val schema = Regex("(\"receiptSchemaVersion\"\\s*:\\s*)3")
        assertEquals(1, schema.findAll(before).count())
        graphPath.writeText(schema.replace(before) { "${it.groupValues[1]}2" })
        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).close()
        }
        assertTrue(failure.message.orEmpty().contains("cross-paired"), failure.message)
    }

    @Test
    fun `provider v3 binding cannot claim release or promote a retained fixture`() {
        val pending = RepairAgentInvocationBinding("reports/repair-revisions/revision_00000001_aaaaaaaaaaaaaaaa.acp-receipt.json",
            "a".repeat(64), 3, "b".repeat(64), "c".repeat(64), "returned-completed", false,
            RepairAgentAssessmentStatus.PENDING)
        assertFailsWith<IllegalArgumentException> { pending.copy(receiptReleaseComplete = true) }
        assertFailsWith<IllegalArgumentException> { pending.copy(assessmentStatus = RepairAgentAssessmentStatus.ACCEPTED) }
        assertFailsWith<IllegalArgumentException> { pending.copy(assessmentStatus = RepairAgentAssessmentStatus.PROVISIONAL) }
        assertFailsWith<IllegalArgumentException> { pending.copy(receiptSchemaVersion = 4) }
        assertEquals(2, pending.copy(receiptSchemaVersion = 2, receiptReleaseComplete = true,
            assessmentStatus = RepairAgentAssessmentStatus.ACCEPTED).receiptSchemaVersion)
    }

    @Test
    fun `schema v2 failed invocation retains identical bytes and binding on replay`() = withProject { project ->
        lateinit var binding: RepairAgentInvocationBinding
        lateinit var document: AcpExecutionReceiptDocument
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = attempt(graph)
            document = receipt(project, attempt.id, providerV3 = false)
            assertEquals(2, document.schemaVersion)
            graph.persistAndBindAgentInvocation(attempt, document)
            binding = assertNotNull(graph.reject(attempt, RepairEvidence("agent-failure", "fixture protocol failure"))
                .repairMetadata?.agentInvocation)
        }
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { replay ->
            assertEquals(binding, replay.snapshot.nodes.last().repairMetadata?.agentInvocation)
            assertEquals(2, binding.receiptSchemaVersion)
        }
        assertContentEquals(document.json.toByteArray(), project.resolve(binding.receiptPath).readBytes())
        assertEquals(document.sha256, sha256(project.resolve(binding.receiptPath).readBytes()))
    }

    private fun attempt(graph: ModuleRevisionGraph): ModuleRevisionAttempt {
        val corpus = graph.retainedRegressionCorpus()
        return graph.beginAttempt(listOf("src/modules/alpha.c"), RevisionRepairMetadata(1, "compile", PROMPT,
            null, emptyList(), null, corpus.sha256))
    }

    internal fun receipt(project: Path, attemptId: String, providerV3: Boolean): AcpExecutionReceiptDocument {
        val request = AgentExecutionRequest("repair one module", workspaceRoots = listOf(AgentWorkspaceRoot("project", project)),
            accessPolicy = AgentAccessPolicy(emptyList()))
        val invocation = if (providerV3) providerDataFixtureInvocationForTest(request,
            AcpHarnessProvenance("acp", "provider-fixture", AGENT_EXECUTION_CONTRACT_VERSION,
                ACP_STABLE_PROTOCOL_VERSION, ACP_KOTLIN_SDK_VERSION, "1".repeat(64), false))
        else AcpInvocationEvidenceSnapshot(null, AcpExecutionLifecyclePhase.REQUEST_BOUND,
            AcpExecutionCleanupDisposition.NOT_REQUIRED, null, null, null, emptyList(), emptyList(), emptyList(),
            null, AcpExecutionEvidenceCompleteness(true, true, true), null)
        return requireNotNull(AcpExecutionReceiptDocument.captureOrNull(request, sha256(PROMPT.toByteArray()),
            AgentExecutionReceipt(AgentExecutionRequestBinding.capture(request),
                AgentExecutionOutcome.Failed(AgentFailure(AgentFailureKind.PROTOCOL, "fixture protocol failure")), invocation),
            BoundedAgentExecutionEventRecorder().receiptSnapshot(), TRACE_REPAIR_ACP_RECEIPT_KIND,
            TRACE_REPAIR_ACP_TASK_FIELD, attemptId))
    }

    private fun withProject(body: (Path) -> Unit) {
        val root = Path.of("build/test-tmp").toAbsolutePath().normalize().createDirectories()
        val project = Files.createTempDirectory(root, "repair-provider-retention-")
        try {
            SourceTreeGenerator.generate(RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
                RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)"),
                RecoveredFunction("fn_beta", "beta_read", 0x2000UL, "int beta_read(void)"))), project)
            body(project)
        } finally {
            Files.walk(project).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    private companion object { const val PROMPT = "bounded failure" }
}
