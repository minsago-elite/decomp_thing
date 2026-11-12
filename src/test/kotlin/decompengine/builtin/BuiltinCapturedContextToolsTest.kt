package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import decompengine.repair.*
import com.fasterxml.jackson.core.JsonFactory
import kotlinx.serialization.json.*
import java.io.ByteArrayOutputStream
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

    private fun serializedEvidencePageSize(items: List<AgentContextInput>, total: Int, count: Int): Int {
        val bytes = ByteArrayOutputStream()
        JsonFactory().createGenerator(bytes).use { out ->
            out.writeStartObject(); out.writeArrayFieldStart("evidence")
            items.take(count).forEach { item ->
                out.writeStartObject(); out.writeStringField("id", item.id); out.writeStringField("mediaType", item.mediaType)
                out.writeFieldName("description"); item.description?.let(out::writeString) ?: out.writeNull()
                out.writeStringField("sha256", decompengine.project.sha256(item.content.toByteArray()))
                out.writeNumberField("utf8Bytes", item.content.toByteArray().size); out.writeEndObject()
            }
            out.writeEndArray(); out.writeNumberField("totalEntries", total)
            out.writeFieldName("nextOffset"); if (count < total) out.writeNumber(count) else out.writeNull()
            out.writeEndObject()
        }
        return bytes.size()
    }

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

    @Test fun `evidence inventory shrinks pages to the byte budget without gaps or duplicates`() {
        val inputs = (0 until 12).map { index ->
            AgentContextInput("evidence-%02d-Ω".format(index), "content-$index", description = "line\n\"quoted Ω😀\" ".repeat(8))
        }.reversed()
        val request = request(inputs)
        val byteLimit = 1024
        val tools = BuiltinCapturedContextTools(request, emptyList(), byteLimit, 100)
        val ids = mutableListOf<String>()
        var offset = 0
        var firstPageSize = -1
        while (true) {
            val result = tools.execute(call("list_evidence", offset = offset), control(request))
            assertFalse(result.failed, result.content)
            assertTrue(result.content.toByteArray().size <= byteLimit)
            val page = Json.parseToJsonElement(result.content).jsonObject
            assertEquals(inputs.size, page.getValue("totalEntries").jsonPrimitive.int)
            val entries = page.getValue("evidence").jsonArray.map { it.jsonObject }
            assertTrue(entries.isNotEmpty() || offset == inputs.size)
            if (offset == 0) {
                firstPageSize = entries.size
                assertTrue(firstPageSize in 1 until inputs.size, "expected byte limit to reduce the first page, got $firstPageSize")
                val ordered = inputs.sortedBy { it.id }
                val largerPageBytes = serializedEvidencePageSize(ordered, inputs.size, firstPageSize + 1)
                assertTrue(largerPageBytes > byteLimit,
                    "the next sorted entry must not fit: count=$firstPageSize serialized=$largerPageBytes limit=$byteLimit")
                val nextEntry = ordered[firstPageSize]
                assertTrue(nextEntry.id > entries.last().getValue("id").jsonPrimitive.content)
            }
            entries.forEach { entry ->
                val id = entry.getValue("id").jsonPrimitive.content
                ids += id
                val source = inputs.single { it.id == id }
                assertEquals(decompengine.project.sha256(source.content.toByteArray()), entry.getValue("sha256").jsonPrimitive.content)
                assertEquals(source.content.toByteArray().size, entry.getValue("utf8Bytes").jsonPrimitive.int)
            }
            val next = page.getValue("nextOffset")
            if (next == JsonNull) break
            assertEquals(offset + entries.size, next.jsonPrimitive.int)
            offset = next.jsonPrimitive.int
        }
        assertEquals(inputs.map { it.id }.sorted(), ids)
        assertEquals(ids.distinct(), ids)
    }

    @Test fun `evidence inventory stops at an oversized entry without skipping later entries`() {
        val request = request(listOf(
            AgentContextInput("a-small", "first"),
            AgentContextInput("b-large", "middle", description = "Ω".repeat(2_000)),
            AgentContextInput("c-small", "last"),
        ))
        val tools = BuiltinCapturedContextTools(request, emptyList(), 1024, 10)
        val first = Json.parseToJsonElement(tools.execute(call("list_evidence"), control(request)).content).jsonObject
        assertEquals(listOf("a-small"), first.getValue("evidence").jsonArray.map { it.jsonObject.getValue("id").jsonPrimitive.content })
        assertEquals(1, first.getValue("nextOffset").jsonPrimitive.int)

        val blocked = tools.execute(call("list_evidence", offset = 1), control(request))
        assertTrue(blocked.failed)
        assertTrue(blocked.content.contains("next evidence entry"))
    }

    @Test fun `empty evidence inventory returns an empty terminal page`() {
        val request = request()
        val result = BuiltinCapturedContextTools(request, emptyList(), 1024, 10)
            .execute(call("list_evidence"), control(request))
        assertFalse(result.failed)
        val page = Json.parseToJsonElement(result.content).jsonObject
        assertTrue(page.getValue("evidence").jsonArray.isEmpty())
        assertEquals(0, page.getValue("totalEntries").jsonPrimitive.int)
        assertEquals(JsonNull, page["nextOffset"])
    }

    @Test fun `evidence inventory refuses an entry that cannot fit instead of skipping it`() {
        val request = request(listOf(AgentContextInput("too-large", "small", description = "Ω".repeat(2_000))))
        val tools = BuiltinCapturedContextTools(request, emptyList(), 1024, 10)
        val result = tools.execute(call("list_evidence"), control(request))
        assertTrue(result.failed)
        assertTrue(result.content.contains("exceeds the configured result limit"))
        assertTrue(tools.audit().single().failed)
    }

    @Test fun `evidence inventory accepts exact serialized byte boundary and rejects one byte less`() {
        val request = request(listOf(AgentContextInput("boundary-Ω", "bytes", description = "quoted \"text\"\n😀")))
        val reference = BuiltinCapturedContextTools(request, emptyList(), 8192, 10)
            .execute(call("list_evidence"), control(request))
        val exactLimit = reference.content.toByteArray().size
        val exact = BuiltinCapturedContextTools(request, emptyList(), exactLimit, 10)
            .execute(call("list_evidence"), control(request))
        assertFalse(exact.failed)
        assertEquals(exactLimit, exact.content.toByteArray().size)

        val tooSmall = BuiltinCapturedContextTools(request, emptyList(), exactLimit - 1, 10)
            .execute(call("list_evidence"), control(request))
        assertTrue(tooSmall.failed)
        assertTrue(tooSmall.content.contains("exceeds the configured result limit"))
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

        val bounded = BuiltinCapturedContextTools(request, emptyList(), 1024, 10)
        val boundedPage = Json.parseToJsonElement(bounded.execute(call("read_evidence", mapOf("id" to JsonPrimitive("trace"))), control(request)).content).jsonObject
        assertTrue(boundedPage.getValue("text").jsonPrimitive.content.length < 4095)
        assertTrue(boundedPage.getValue("nextOffset").jsonPrimitive.int > 0)
        assertTrue(bounded.execute(call("read_evidence", mapOf("id" to JsonPrimitive("trace"))), control(request)).content.toByteArray().size <= 1024)
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
        val tooSmall = bounded.execute(call("read_evidence", mapOf("id" to JsonPrimitive("large"))), control(request))
        assertTrue(tooSmall.failed)
        assertTrue(tooSmall.content.contains("result limit"))
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
