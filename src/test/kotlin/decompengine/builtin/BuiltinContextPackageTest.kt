package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import decompengine.repair.*
import kotlinx.serialization.json.*
import java.nio.file.Path
import java.time.Duration
import kotlin.test.*

class BuiltinContextPackageTest {
    private fun request(inputs: List<AgentContextInput>, rules: List<AgentPathRule> = emptyList(), root: AgentWorkspaceRoot = AgentWorkspaceRoot("project", Path.of("/not-exposed-host-root"))) =
        AgentExecutionRequest("inspect source", listOf(root), inputs, AgentAccessPolicy(rules))
    private fun pack(request: AgentExecutionRequest, capacity: Int = 5000, retrieval: Boolean = true,
        evidenceBytes: Long = 100_000, resultBytes: Int = 8192) =
        BuiltinContextAssembler.assemble(request, capacity, evidenceBytes, resultBytes, retrieval,
            BuiltinExecutionControl(request, System.nanoTime() + Duration.ofSeconds(10).toNanos())) { messages ->
            boundedProviderJson(capacity) { out ->
                out.writeStartArray()
                messages.forEach { message ->
                    out.writeStartObject(); out.writeStringField("role", message.role.name); out.writeStringField("content", message.content)
                    out.writeArrayFieldStart("calls"); out.writeEndArray(); out.writeEndObject()
                }
                out.writeEndArray()
            }
        }

    private fun readEvidence(request: AgentExecutionRequest, input: AgentContextInput, offset: Int, resultBytes: Int = 32_000) =
        BuiltinCapturedContextTools(request, emptyList(), resultBytes, 10).execute(
            ModelToolCall("read", "read_evidence", buildJsonObject { put("id", input.id); put("offset", offset) }),
            BuiltinExecutionControl(request, System.nanoTime() + Duration.ofSeconds(10).toNanos()),
        )

    @Test fun `selection is deterministic and explicitly binds included and omitted input hashes`() {
        val inputs = listOf(AgentContextInput("large", "x".repeat(10_000)), AgentContextInput("small", "diagnostic"))
        val first = pack(request(inputs))
        val second = pack(request(inputs.reversed()))
        assertEquals(first.sha256, second.sha256)
        assertEquals(first.entries, second.entries)
        assertEquals(listOf(false, true), first.entries.map { it.included })
        assertEquals(decompengine.project.sha256("x".repeat(10_000).toByteArray()), first.entries.first().sha256)
        assertTrue(first.messages.none { it.content.contains("x".repeat(100)) })
        val manifest = Json.parseToJsonElement(first.messages[3].content).jsonObject
        assertFalse(manifest.getValue("inputs").jsonArray.first().jsonObject.getValue("included").jsonPrimitive.boolean)
        assertFailsWith<UnsupportedOperationException> { (first.entries as MutableList).clear() }
    }

    @Test fun `authority uses sorted transport-neutral paths rather than host roots`() {
        val path = AgentWorkspacePath("project", "source.c")
        val rules = listOf(AgentPathRule(path, setOf(AgentOperation.WRITE_FILE)), AgentPathRule(path, setOf(AgentOperation.READ_FILE)))
        val first = pack(request(emptyList(), rules))
        val second = pack(request(emptyList(), rules.reversed()))
        assertEquals(first.sha256, second.sha256)
        assertTrue(first.messages[2].content.contains("source.c"))
        assertFalse(first.messages.any { it.content.contains("/not-exposed-host-root") })
    }

    @Test fun `unsupported omission mandatory metadata and total evidence limits fail before a model request`() {
        assertFailsWith<ModelProviderException> { pack(request(listOf(AgentContextInput("large", "x".repeat(10_000)))), retrieval = false) }
        assertFailsWith<ModelProviderException> { pack(request(emptyList()), capacity = 64) }
        assertFailsWith<ModelProviderException> { pack(request(listOf(AgentContextInput("large", "x".repeat(1000)))), evidenceBytes = 100) }
        assertFailsWith<ModelProviderException> { pack(request(listOf(AgentContextInput("huge-id-".repeat(1000), "")))) }
    }

    @Test fun `omitted evidence is refused before dispatch when no bounded read page can fit`() {
        val unreadableId = "unreadable-".repeat(40)
        val input = AgentContextInput(unreadableId, "x".repeat(10_000))
        val failure = assertFailsWith<ModelProviderException> {
            pack(request(listOf(input)), capacity = 5000, resultBytes = 256)
        }
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, failure.kind)

        val readable = pack(request(listOf(input)), capacity = 5000, resultBytes = 2048)
        assertFalse(readable.entries.single().included)
    }

    @Test fun `retrieval preflight covers escaped supplementary text and terminal null offsets`() {
        val content = "😀".repeat(1000)
        val input = AgentContextInput("astral", content)
        val contextRequest = request(listOf(input))
        val terminalOffset = content.length - 2
        val terminal = readEvidence(contextRequest, input, terminalOffset)
        assertFalse(terminal.failed)
        assertContains(terminal.content, "\\uD83D\\uDE00")
        val exactTerminalBytes = terminal.content.toByteArray().size

        val exact = pack(contextRequest, capacity = 3000, resultBytes = exactTerminalBytes)
        assertFalse(exact.entries.single().included)
        assertFailsWith<ModelProviderException> {
            pack(contextRequest, capacity = 3000, resultBytes = exactTerminalBytes - 1)
        }

        val shortContent = "x".repeat(999)
        val shortInput = AgentContextInput("short", shortContent)
        val shortRequest = request(listOf(shortInput))
        val shortTerminal = readEvidence(shortRequest, shortInput, shortContent.length - 1)
        assertFalse(shortTerminal.failed)
        val shortTerminalBytes = shortTerminal.content.toByteArray().size
        val shortExact = pack(shortRequest, capacity = 1000, resultBytes = shortTerminalBytes)
        assertFalse(shortExact.entries.single().included)
        assertFailsWith<ModelProviderException> {
            pack(shortRequest, capacity = 1000, resultBytes = shortTerminalBytes - 1)
        }
    }

    @Test fun `empty evidence has a bounded terminal page`() {
        val input = AgentContextInput("empty", "")
        val contextRequest = request(listOf(input))
        val roomyPage = readEvidence(contextRequest, input, 0)
        assertFalse(roomyPage.failed)
        val parsed = Json.parseToJsonElement(roomyPage.content).jsonObject
        assertEquals("", parsed.getValue("text").jsonPrimitive.content)
        assertNull(parsed.getValue("nextOffset").jsonPrimitive.contentOrNull)

        val exactBytes = roomyPage.content.toByteArray().size
        val control = BuiltinExecutionControl(contextRequest, System.nanoTime() + Duration.ofSeconds(10).toNanos())
        val digest = decompengine.project.sha256(input.content.toByteArray())
        assertTrue(canReadAnyEvidencePage(input, digest, exactBytes, control))
        assertFalse(canReadAnyEvidencePage(input, digest, exactBytes - 1, control))

        val exactPage = readEvidence(contextRequest, input, 0, exactBytes)
        assertFalse(exactPage.failed)
        val tooSmall = readEvidence(contextRequest, input, 0, exactBytes - 1)
        assertTrue(tooSmall.failed)
    }

    @Test fun `escaping is charged and whole inputs are selected without hidden truncation`() {
        val text = "\u0001".repeat(1000)
        val pkg = pack(request(listOf(AgentContextInput("escaped", text), AgentContextInput("utf8", "가나다"))), capacity = 3000)
        assertFalse(pkg.entries.first().included)
        assertEquals(9, pkg.entries.last().bytes)
        assertTrue(pkg.entries.last().included)
        assertTrue(pkg.serializedBytes <= 3000)
        assertTrue(pkg.messages.last().content.endsWith("가나다"))
    }

    @Test fun `captured loop retrieves omitted evidence within its reserved history capacity`() {
        val large = "x".repeat(40_000)
        var step = 0
        val provider = ModelProvider { request, _ ->
            if (step++ == 0) {
                assertTrue(request.messages.none { it.content.contains("x".repeat(100)) })
                ModelResponse("", listOf(ModelToolCall("read_1", "read_evidence", buildJsonObject { put("id", "large"); put("offset", 0) })),
                    ModelFinishReason.TOOL_CALLS, ModelUsage(100, 10, true), 1)
            } else {
                val result = Json.parseToJsonElement(request.messages.last().content).jsonObject
                assertEquals(4096, result.getValue("text").jsonPrimitive.content.length)
                assertEquals(4096, result.getValue("nextOffset").jsonPrimitive.int)
                ModelResponse("", emptyList(), ModelFinishReason.STOP, ModelUsage(100, 10, true), 1)
            }
        }
        val limits = BuiltinLoopLimits(maxContextBytes = 24_000, maxToolResultBytes = 8192, contextHistoryReserveBytes = 12_000)
        val execution = CapturedRepairStagingAuthority.executeReceipt(BuiltinCapturedRepairHarness(provider, limits), mapOf("source.c" to "source".toByteArray()),
            emptySet(), RepairResourceBudget(), { root -> request(listOf(AgentContextInput("large", large)),
                listOf(AgentPathRule(AgentWorkspacePath("project", "source.c"), setOf(AgentOperation.READ_FILE))), root) }) {}
        val proof = assertIs<BuiltinCapturedExecutionEvidence>(execution.receipt.providerEvidence)
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, proof.loop.stop)
        assertFalse(proof.loop.contextEntries.single().included)
        assertEquals("read_evidence", proof.contextAudit.single().tool)
    }
}
