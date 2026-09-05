package decompengine.builtin

import com.agentclientprotocol.protocol.AcpExpectedError
import decompengine.acp.*
import decompengine.agent.*
import decompengine.builtin.provider.*
import decompengine.repair.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.*

class BuiltinFilesystemToolsTest {
    private fun request(root: AgentWorkspaceRoot) = AgentExecutionRequest("repair source", listOf(root), accessPolicy = AgentAccessPolicy(listOf(
        AgentPathRule(AgentWorkspacePath(root.id, "source.c"), setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)),
        AgentPathRule(AgentWorkspacePath(root.id, "oracle.txt"), setOf(AgentOperation.READ_FILE)),
    )))
    private fun call(id: String, name: String, path: String = "source.c", extra: Map<String, String> = emptyMap()) =
        ModelToolCall(id, name, buildJsonObject { put("root", "project"); put("path", path); extra.forEach { (k,v) -> put(k,v) } })
    private fun result(calls: List<ModelToolCall> = emptyList()) = ModelResponse("", calls,
        if (calls.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS, ModelUsage(20, 10, false), 1)
    private fun provider(vararg batches: List<ModelToolCall>): ModelProvider {
        val iterator = batches.iterator()
        return ModelProvider { _, _ -> if (iterator.hasNext()) result(iterator.next()) else result() }
    }
    private fun captured(provider: ModelProvider, initial: Map<String, ByteArray> = initial(), limits: BuiltinLoopLimits = BuiltinLoopLimits()): RepairStagingExecution =
        CapturedRepairStagingAuthority.executeReceipt(BuiltinCapturedRepairHarness(provider, limits), initial, setOf("source.c"),
            RepairResourceBudget(), ::request) {}
    private fun initial() = mapOf("source.c" to "old source\n".toByteArray(), "oracle.txt" to "immutable evidence\n".toByteArray())
    private fun evidence(execution: RepairStagingExecution) = assertIs<BuiltinCapturedExecutionEvidence>(execution.receipt.providerEvidence)

    @Test fun `built-in read write read traverses the captured authority and retains exact candidate hashes`() {
        val exists = Files.exists(ACP_CAPTURED_REPAIR_WORKSPACE)
        var step = 0
        val model = ModelProvider { request, _ ->
            when (step++) {
                0 -> result(listOf(call("read_1", "read_text")))
                1 -> { assertEquals("old source\n", request.messages.last().content); result(listOf(call("write_1", "write_text", extra = mapOf("content" to "new source\n")))) }
                2 -> result(listOf(call("read_2", "read_text")))
                else -> { assertEquals("new source\n", request.messages.last().content); result() }
            }
        }
        val execution = captured(model)
        assertContentEquals("new source\n".toByteArray(), execution.files.getValue("source.c"))
        assertContentEquals(initial().getValue("oracle.txt"), execution.files.getValue("oracle.txt"))
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, evidence(execution).loop.stop)
        assertEquals(listOf("read_1", "write_1", "read_2"), evidence(execution).filesystemAudit.map { it.sessionId })
        assertTrue(evidence(execution).filesystemAudit.all { it.reason == AcpFilesystemAuditReason.COMPLETED })
        assertEquals(decompengine.project.sha256("new source\n".toByteArray()), execution.result.changes.single().afterSha256)
        assertEquals(exists, Files.exists(ACP_CAPTURED_REPAIR_WORKSPACE))
    }

    @Test fun `oracle writes and undeclared paths remain denied by the same captured policy`() {
        val execution = captured(provider(listOf(call("denied", "write_text", "oracle.txt", mapOf("content" to "forged")))))
        assertEquals(BuiltinStop.TOOL_FAILED, evidence(execution).loop.stop)
        assertContentEquals(initial().getValue("oracle.txt"), execution.files.getValue("oracle.txt"))
        assertEquals(AcpFilesystemAuditReason.POLICY_DENIED, evidence(execution).filesystemAudit.single().reason)
        assertIs<AgentExecutionOutcome.Failed>(execution.receipt.outcome)
        val escaped = captured(provider(listOf(call("escape", "read_text", "../outside"))))
        assertEquals(BuiltinStop.TOOL_FAILED, evidence(escaped).loop.stop)
        assertEquals(0, evidence(escaped).filesystemAudit.size)
    }

    @Test fun `typed and direct ACP captured callbacks produce the same changes and decision evidence`() {
        val typed = captured(provider(listOf(call("read", "read_text")), listOf(call("write", "write_text", extra = mapOf("content" to "replacement")))))
        val input = initial()
        val output = BoundedRepairOutput(input, setOf("source.c"), RepairResourceBudget())
        val direct = AcpCapturedRepairFilesystem(input, output)
        val audit = AcpFilesystemAuditRecorder()
        val req = request(AgentWorkspaceRoot("project", ACP_CAPTURED_REPAIR_WORKSPACE))
        direct.open(req, AcpFilesystemLimits(), audit).use { session -> runBlocking {
            session.readTextFile("read", "$ACP_CAPTURED_REPAIR_WORKSPACE/source.c", null, null)
            session.writeTextFile("write", "$ACP_CAPTURED_REPAIR_WORKSPACE/source.c", "replacement")
        } }
        assertEquals(direct.changes(), typed.result.changes)
        assertEquals(audit.snapshot(), evidence(typed).filesystemAudit)
        assertContentEquals(output.finish().getValue("source.c"), typed.files.getValue("source.c"))
    }

    @Test fun `literal search bounds matches and explicitly reports omitted matches`() {
        var step = 0
        val model = ModelProvider { request, _ ->
            if (step++ == 0) result(listOf(call("search", "search_text", extra = mapOf("query" to "needle"))))
            else {
                val result = Json.parseToJsonElement(request.messages.last().content).jsonObject
                assertTrue(result.getValue("truncated").jsonPrimitive.boolean)
                assertEquals(100, result.getValue("matches").jsonArray.size)
                assertEquals(1, result.getValue("matches").jsonArray.first().jsonObject.getValue("line").jsonPrimitive.int)
                result()
            }
        }
        val input = initial() + ("source.c" to "needle\n".repeat(101).toByteArray())
        val execution = captured(model, input)
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, evidence(execution).loop.stop)
        assertTrue(execution.result.changes.isEmpty())
    }

    @Test fun `captured file ceilings reject source and replacements without host fallback`() {
        val limits = BuiltinLoopLimits(maxToolResultBytes = 64)
        val oversizedInput = captured(provider(), initial() + ("source.c" to ByteArray(65) { 65 }), limits)
        assertIs<AgentExecutionOutcome.Failed>(oversizedInput.receipt.outcome)
        assertEquals(0, evidence(oversizedInput).loop.modelCalls)
        val oversizedWrite = captured(provider(listOf(call("write", "write_text", extra = mapOf("content" to "x".repeat(65))))), limits = limits)
        assertContentEquals(initial().getValue("source.c"), oversizedWrite.files.getValue("source.c"))
        assertEquals(BuiltinStop.TOOL_FAILED, evidence(oversizedWrite).loop.stop)
        assertEquals(AcpFilesystemAuditReason.RESOURCE_LIMIT, evidence(oversizedWrite).filesystemAudit.single().reason)
        val ordinary = BuiltinCapturedRepairHarness(provider()).executeReceipt(request(AgentWorkspaceRoot("project", Path.of("/fixture/project")))) {}
        assertEquals(AgentFailureKind.CONFIGURATION, assertIs<AgentExecutionOutcome.Failed>(ordinary.outcome).failure.kind)
    }

    @Test fun `typed host callbacks share descriptor containment atomic writes and symlink denial with ACP`() {
        val directory = createTempDirectory("builtin-shared-filesystem-")
        try {
            val source = directory.resolve("source.c").apply { writeText("old") }
            val oracle = directory.resolve("oracle.txt").apply { writeText("oracle") }
            val req = request(AgentWorkspaceRoot("project", directory.toAbsolutePath().normalize()))
            val control = BuiltinExecutionControl(req, System.nanoTime() + req.limits.wallClockTimeout.toNanos())
            val audit = AcpFilesystemAuditRecorder()
            AcpFilesystemBroker.open(req, AcpFilesystemLimits(), audit).use { broker ->
                val dispatcher = BuiltinFilesystemDispatcher(req, broker, 4096)
                assertEquals("old", dispatcher.execute(call("typed-read", "read_text"), control).content)
                assertFalse(dispatcher.execute(call("typed-write", "write_text", extra = mapOf("content" to "new")), control).failed)
                assertEquals("new", runBlocking { broker.readTextFile("direct-read", source.toString(), null, null) }.content)
                assertEquals("new", source.readText())
                assertTrue(dispatcher.execute(call("typed-deny", "write_text", "oracle.txt", mapOf("content" to "bad")), control).failed)
                assertFailsWith<AcpExpectedError> { runBlocking { broker.writeTextFile("direct-deny", oracle.toString(), "bad") } }
                Files.delete(source); Files.createSymbolicLink(source, oracle)
                assertTrue(dispatcher.execute(call("typed-link", "read_text"), control).failed)
                assertFailsWith<AcpExpectedError> { runBlocking { broker.readTextFile("direct-link", source.toString(), null, null) } }
                val records = audit.snapshot()
                assertEquals(records[3].reason, records[4].reason)
                assertEquals(records[5].reason, records[6].reason)
                assertEquals("oracle", oracle.readText())
            }
        } finally {
            Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    @Test fun `refused and failed turns retain staged change hashes without accepting the revision`() {
        for (failed in listOf(false, true)) {
            var calls = 0
            val model = ModelProvider { _, _ ->
                if (calls++ == 0) result(listOf(call("write", "write_text", extra = mapOf("content" to "candidate"))))
                else if (failed) throw ModelProviderException(ModelFailureKind.TRANSPORT)
                else ModelResponse("", emptyList(), ModelFinishReason.REFUSED, ModelUsage(1, 1, false), 1)
            }
            val execution = captured(model)
            val proof = evidence(execution)
            assertEquals(if (failed) BuiltinStop.PROVIDER_FAILED else BuiltinStop.REFUSED, proof.loop.stop)
            assertEquals(decompengine.project.sha256("candidate".toByteArray()), proof.candidateChanges.single().afterSha256)
            assertContentEquals("candidate".toByteArray(), execution.files.getValue("source.c"))
            if (!failed) assertEquals(proof.candidateChanges, execution.result.changes)
            else assertIs<AgentExecutionOutcome.Failed>(execution.receipt.outcome)
        }
    }
}
