package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import decompengine.repair.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class BuiltinRepairJournalFactoryTest {
    @TempDir lateinit var directory: Path
    private val base = mapOf("source.c" to "old".toByteArray())
    private val identity = AgentWorkflowIdentity(AgentWorkflow.REPAIR, "revision_1", "a".repeat(64), "b".repeat(64))
    private fun factory(): BuiltinRepairJournalFactory {
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
        return BuiltinRepairJournalFactory(directory, "fixture", "scripted-v1")
    }
    private fun request(root: AgentWorkspaceRoot, workflow: AgentWorkflowIdentity? = identity, objective: String = "repair") =
        AgentExecutionRequest(objective, listOf(root), accessPolicy = AgentAccessPolicy(listOf(
            AgentPathRule(AgentWorkspacePath(root.id, "source.c"), setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)),
        )), workflowIdentity = workflow)
    private fun response(calls: List<ModelToolCall> = emptyList()) = ModelResponse("", calls,
        if (calls.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS, ModelUsage(100, 10, false), 1)
    private fun execute(harness: BuiltinCapturedRepairHarness, request: AgentExecutionRequest) =
        CapturedRepairStagingAuthority.executeReceipt(harness, base, base.keys, RepairResourceBudget(), { request }) {}
    private fun request(workflow: AgentWorkflowIdentity? = identity, objective: String = "repair") =
        request(AgentWorkspaceRoot("project", decompengine.acp.ACP_CAPTURED_REPAIR_WORKSPACE), workflow, objective)

    @Test fun `fresh attempts bind the actual captured subset and full accepted revision separately`() {
        val factory = factory()
        var turns = 0
        val harness = BuiltinCapturedRepairHarness(ModelProvider { _, _ ->
            if (turns++ % 2 == 0) response(listOf(ModelToolCall("write1", "write_text", buildJsonObject {
                put("root", "project"); put("path", "source.c"); put("content", "candidate")
            }))) else response()
        }, journalFactory = factory)
        val paths = mutableSetOf<Path>()
        for (task in listOf("revision_1", "revision_2")) {
            val request = request(identity.copy(taskId = task))
            val execution = execute(harness, request)
            assertEquals(AgentStopReason.COMPLETED, execution.result.stopReason)
            assertEquals("candidate", execution.files.getValue("source.c")!!.decodeToString())
            val evidence = assertIs<BuiltinCapturedExecutionEvidence>(execution.receipt.providerEvidence)
            assertEquals(request.workflowIdentity, evidence.workflowIdentity)
            val configuration = factory.create(request, base, 1024)
            paths.add(configuration.path)
            val journal = assertNotNull(evidence.journalIdentity)
            assertEquals(identity.acceptedRevisionSha256, journal.acceptedRevisionSha256)
            assertNotEquals(journal.acceptedRevisionSha256, journal.sourceSha256)
            assertEquals(BuiltinWorkspaceSnapshot.capture(base.mapKeys { AgentWorkspacePath("project", it.key) }).sha256, journal.sourceSha256)
            val archiveIdentity = BuiltinInvocationArchiveIdentity("repair", task, identity.promptSha256,
                execution.receipt.requestBinding, journal)
            assertTrue(BuiltinInvocationArchiveDocument.capture(archiveIdentity, request, execution.receipt, configuration)
                .verified.candidateEvidenceComplete)
            assertFails {
                BuiltinInvocationArchiveDocument.capture(BuiltinInvocationArchiveIdentity("repair", "different-task", identity.promptSha256,
                    execution.receipt.requestBinding, journal), request, execution.receipt, configuration)
            }
        }
        assertEquals(2, paths.size)
        assertEquals(4, turns)
        assertContentEquals("old".toByteArray(), base.getValue("source.c"))
    }

    @Test fun `changing a request cannot reopen or overwrite an already executed durable task`() {
        val factory = factory()
        var calls = 0
        val harness = BuiltinCapturedRepairHarness(ModelProvider { _, _ -> calls++; response() }, journalFactory = factory)
        val first = request()
        assertIs<AgentExecutionOutcome.Returned>(execute(harness, first).receipt.outcome)
        val path = factory.create(first, base, 1024).path
        val bytes = Files.readAllBytes(path)
        val changed = request(objective = "different prompt")
        assertEquals(path, factory.create(changed, base, 1024).path)
        assertNotEquals(factory.create(first, base, 1024).identity.stageSha256, factory.create(changed, base, 1024).identity.stageSha256)
        assertIs<AgentExecutionOutcome.Failed>(execute(harness, changed).receipt.outcome)
        assertEquals(1, calls)
        assertContentEquals(bytes, Files.readAllBytes(path))
    }

    @Test fun `missing or wrong workflow identity stops before journal creation and model calls`() {
        var calls = 0
        val harness = BuiltinCapturedRepairHarness(ModelProvider { _, _ -> calls++; response() }, journalFactory = factory())
        for (workflow in listOf(null, identity.copy(workflow = AgentWorkflow.RECONSTRUCTION))) {
            val receipt = execute(harness, request(workflow)).receipt
            assertEquals(AgentFailureKind.INVALID_REQUEST, assertIs<AgentExecutionOutcome.Failed>(receipt.outcome).failure.kind)
        }
        assertEquals(0, calls)
        Files.list(directory).use { assertEquals(0L, it.count()) }
    }

    @Test fun `static journal configuration cannot contradict workflow revision or stage binding`() {
        val request = request()
        val configuration = factory().create(request, base, 1024)
        val valid = configuration.identity
        var calls = 0
        for (wrong in listOf(
            BuiltinJournalIdentity(valid.provider, valid.model, valid.sourceSha256, valid.stageSha256, "c".repeat(64)),
            BuiltinJournalIdentity(valid.provider, valid.model, valid.sourceSha256, "d".repeat(64), valid.acceptedRevisionSha256),
        )) {
            val harness = BuiltinCapturedRepairHarness(ModelProvider { _, _ -> calls++; response() },
                journalConfiguration = BuiltinJournalConfiguration(configuration.path, wrong))
            assertIs<AgentExecutionOutcome.Failed>(execute(harness, request).receipt.outcome)
        }
        assertEquals(0, calls)
        assertFalse(Files.exists(configuration.path))
    }

    @Test fun `shared session continuation fails before model tools or journal creation`() {
        val original = request()
        for (policy in AgentSessionResumePolicy.entries) {
            val request = AgentExecutionRequest(original.objective, original.workspaceRoots,
                accessPolicy = original.accessPolicy, workflowIdentity = identity,
                sessionContinuation = AgentSessionContinuation(directory.resolve("session"), "e".repeat(64),
                    identity.taskId, mapOf(AgentWorkspacePath("project", "source.c") to "a".repeat(64)),
                    identity.acceptedRevisionSha256, policy))
            val provider = ModelProvider { _, _ -> error("unsupported continuation reached provider") }
            val ordinary = BuiltinAgentHarness(provider, { _, _ -> error("unsupported continuation opened tools") })
            val captured = BuiltinCapturedRepairHarness(provider, journalFactory = factory())
            for (receipt in listOf(ordinary.executeReceipt(request) {}, execute(captured, request).receipt)) {
                assertEquals(AgentFailureKind.INVALID_REQUEST, assertIs<AgentExecutionOutcome.Failed>(receipt.outcome).failure.kind)
                assertEquals(AgentExecutionRequestBinding.capture(request), receipt.requestBinding)
            }
            Files.list(directory).use { assertEquals(0L, it.count()) }
        }
    }

    @Test fun `source snapshot admission remains bounded before any provider effect`() {
        var calls = 0
        val harness = BuiltinCapturedRepairHarness(ModelProvider { _, _ -> calls++; response() },
            limits = BuiltinLoopLimits(maximumEvidenceBytes = 1), journalFactory = factory())
        assertIs<AgentExecutionOutcome.Failed>(execute(harness, request()).receipt.outcome)
        assertEquals(0, calls)
        Files.list(directory).use { assertEquals(0L, it.count()) }
    }
}
