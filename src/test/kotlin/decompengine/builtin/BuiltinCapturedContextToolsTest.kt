package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import decompengine.repair.*
import kotlinx.serialization.json.*
import java.nio.file.Path
import java.time.Duration
import kotlin.test.*

class BuiltinCapturedContextToolsTest {
    private fun request(context: List<AgentContextInput> = emptyList(), root: AgentWorkspaceRoot = AgentWorkspaceRoot("project", Path.of("/fixture"))) =
        AgentExecutionRequest("inspect authorized context", listOf(root), context, AgentAccessPolicy(listOf(
            AgentPathRule(AgentWorkspacePath("project", "src/a.c"), setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)),
            AgentPathRule(AgentWorkspacePath("project", "src/b.c"), setOf(AgentOperation.READ_FILE)),
            AgentPathRule(AgentWorkspacePath("project", "write-only.c"), setOf(AgentOperation.WRITE_FILE)),
        )))
    private fun control(request: AgentExecutionRequest) = BuiltinExecutionControl(request, System.nanoTime() + Duration.ofSeconds(10).toNanos())
    private fun call(name: String, fields: Map<String, JsonPrimitive> = emptyMap(), offset: Int = 0) = ModelToolCall("context_1", name, buildJsonObject {
        put("offset", offset); fields.forEach { (name, value) -> put(name, value) }
    })
    private fun response(tools: List<ModelToolCall> = emptyList()) = ModelResponse("", tools,
        if (tools.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS, ModelUsage(10, 10, false), 1)

    @Test fun `directory inventory is sorted virtual and restricted by shared read policy`() {
        val request = request()
        val tools = BuiltinCapturedContextTools(request, listOf("write-only.c", "src/b.c", "hidden.c", "src/a.c"), 8192, 10)
        fun list(path: String) = Json.parseToJsonElement(tools.execute(call("list_directory", mapOf("path" to JsonPrimitive(path))), control(request)).content).jsonObject
        val root = list("")
        assertEquals(listOf("src"), root.getValue("entries").jsonArray.map { it.jsonObject.getValue("name").jsonPrimitive.content })
        assertEquals(listOf("a.c", "b.c"), list("src").getValue("entries").jsonArray.map { it.jsonObject.getValue("name").jsonPrimitive.content })
        assertEquals(2, tools.audit().size)
        assertTrue(tools.audit().all { it.resultSha256.length == 64 && !it.failed })
    }

    @Test fun `evidence inventory pages bind immutable input hashes without losing entries`() {
        val inputs = (0 until 70).map { AgentContextInput("evidence-%02d".format(it), "content $it") }.reversed()
        val request = request(inputs)
        val tools = BuiltinCapturedContextTools(request, emptyList(), 16_384, 10)
        val first = Json.parseToJsonElement(tools.execute(call("list_evidence"), control(request)).content).jsonObject
        assertEquals(64, first.getValue("evidence").jsonArray.size)
        assertEquals(64, first.getValue("nextOffset").jsonPrimitive.int)
        val second = Json.parseToJsonElement(tools.execute(call("list_evidence", offset = 64), control(request)).content).jsonObject
        assertEquals(6, second.getValue("evidence").jsonArray.size)
        assertEquals(JsonNull, second["nextOffset"])
        val firstItem = first.getValue("evidence").jsonArray.first().jsonObject
        assertEquals("evidence-00", firstItem.getValue("id").jsonPrimitive.content)
        assertEquals(decompengine.project.sha256("content 0".toByteArray()), firstItem.getValue("sha256").jsonPrimitive.content)
    }

    @Test fun `evidence text pages preserve surrogate pairs and the complete input digest`() {
        val text = "a".repeat(4095) + "😀" + "tail"
        val request = request(listOf(AgentContextInput("trace", text)))
        val tools = BuiltinCapturedContextTools(request, emptyList(), 8192, 10)
        fun read(offset: Int) = Json.parseToJsonElement(tools.execute(call("read_evidence", mapOf("id" to JsonPrimitive("trace")), offset), control(request)).content).jsonObject
        val first = read(0)
        val second = read(first.getValue("nextOffset").jsonPrimitive.int)
        assertEquals(4095, first.getValue("nextOffset").jsonPrimitive.int)
        assertEquals(text, first.getValue("text").jsonPrimitive.content + second.getValue("text").jsonPrimitive.content)
        assertEquals(first["sha256"], second["sha256"])
        assertEquals(JsonNull, second["nextOffset"])
        assertTrue(tools.execute(call("read_evidence", mapOf("id" to JsonPrimitive("trace")), 4096), control(request)).failed)
    }

    @Test fun `invalid paths offsets and unknown evidence fail without host lookup`() {
        val request = request()
        val tools = BuiltinCapturedContextTools(request, listOf("src/a.c"), 8192, 10)
        for (path in listOf("../outside", "/etc", "src/../other")) {
            assertTrue(tools.execute(call("list_directory", mapOf("path" to JsonPrimitive(path))), control(request)).failed)
        }
        assertTrue(tools.execute(call("list_directory", mapOf("path" to JsonPrimitive("")), 10), control(request)).failed)
        assertTrue(tools.execute(call("read_evidence", mapOf("id" to JsonPrimitive("missing"))), control(request)).failed)
        assertTrue(tools.audit().all { it.failed })
    }

    @Test fun `serialized output and audit bounds are enforced before success`() {
        val request = request(listOf(AgentContextInput("large", "a".repeat(500))))
        val bounded = BuiltinCapturedContextTools(request, emptyList(), 64, 10)
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, assertFailsWith<ModelProviderException> {
            bounded.execute(call("read_evidence", mapOf("id" to JsonPrimitive("large"))), control(request))
        }.kind)
        val audit = BuiltinCapturedContextTools(request, emptyList(), 8192, 1)
        audit.execute(call("list_evidence"), control(request))
        assertFailsWith<ModelProviderException> { audit.execute(call("list_evidence"), control(request)) }
        assertEquals(1, audit.audit().size)
        assertFailsWith<UnsupportedOperationException> { (audit.audit() as MutableList).clear() }
    }

    @Test fun `captured harness routes directory and evidence tools into receipt audits`() {
        var step = 0
        val provider = ModelProvider { request, _ ->
            when (step++) {
                0 -> response(listOf(call("list_directory", mapOf("path" to JsonPrimitive("src")))))
                1 -> {
                    assertEquals(2, Json.parseToJsonElement(request.messages.last().content).jsonObject.getValue("entries").jsonArray.size)
                    response(listOf(ModelToolCall("context_2", "read_evidence", buildJsonObject { put("id", "trace"); put("offset", 0) })))
                }
                else -> {
                    assertEquals("diagnostics", Json.parseToJsonElement(request.messages.last().content).jsonObject.getValue("text").jsonPrimitive.content)
                    response()
                }
            }
        }
        val files = mapOf("src/a.c" to "a".toByteArray(), "src/b.c" to "b".toByteArray(), "write-only.c" to "private".toByteArray())
        val execution = CapturedRepairStagingAuthority.executeReceipt(BuiltinCapturedRepairHarness(provider), files,
            setOf("src/a.c", "write-only.c"), RepairResourceBudget(), { root -> request(listOf(AgentContextInput("trace", "diagnostics")), root) }) {}
        val evidence = assertIs<BuiltinCapturedExecutionEvidence>(execution.receipt.providerEvidence)
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, evidence.loop.stop)
        assertEquals(listOf("list_directory", "read_evidence"), evidence.contextAudit.map { it.tool })
        assertTrue(evidence.candidateChanges.isEmpty())
    }
}
