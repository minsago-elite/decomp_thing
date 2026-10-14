package decompengine.acp

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AcpProviderResponseStreamTest {
    @Test
    fun `byte chunks preserve UTF8 and release complete validated events`() {
        val stream = stream()
        val delta = delta("hello 🌍")
        val completion = completed(7, 11)
        val emitted = (delta + completion).flatMap { stream.accept(byteArrayOf(it)) }.toMutableList()
        val receipt = stream.finish()
        emitted.addAll(stream.drainFinished())
        assertEquals(2, emitted.size)
        assertContentEquals(delta, emitted[0])
        assertContentEquals(completion, emitted[1])
        assertEquals(AcpProviderStreamReceipt((delta.size + completion.size).toLong(), 2, 11, 7), receipt)
    }

    @Test
    fun `CRLF and multiline data are normalized only after validation`() {
        val stream = stream()
        val event = "event: response.created\r\ndata: {\r\ndata: \"type\":\"response.created\"\r\ndata: }\r\n\r\n".toByteArray()
        val result = stream.accept(event).single()
        assertContentEquals(event.toString(Charsets.UTF_8).replace("\r\n", "\n").toByteArray(), result)
        assertFalse('\r' in result.toString(Charsets.UTF_8))
        stream.accept(completed(0))
        assertEquals(2, stream.finish().eventCount)
    }

    @Test
    fun `data-only SSE derives its type from the strict JSON object`() {
        val stream = stream()
        val event = "data: {\"type\":\"response.created\"}\n\n".toByteArray()
        assertContentEquals(event, stream.accept(event).single())
        stream.accept(completed(0))
        stream.finish()
    }

    @Test
    fun `unknown fields and ambiguous SSE declarations fail closed`() {
        val json = "{\"type\":\"response.created\"}"
        for (event in listOf(
            "id: 1\ndata: $json\n\n", "retry: 1\ndata: $json\n\n", ": keepalive\ndata: $json\n\n",
            "url: https://example.invalid\ndata: $json\n\n", "event: response.created\n\n",
            "event: response.created\nevent: response.created\ndata: $json\n\n",
            "event: response.completed\ndata: $json\n\n", "event: https://example.invalid\ndata: $json\n\n",
            "data: $json\rX\n\n", "\n\n",
        )) {
            assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE, event.toByteArray())
        }
    }

    @Test
    fun `duplicate JSON fields excessive depth and trailing documents are rejected`() {
        for (json in listOf(
            "{\"type\":\"response.created\",\"type\":\"response.created\"}",
            "{\"type\":\"response.created\",\"metadata\":{\"x\":1,\"x\":2}}",
            "{\"type\":\"response.created\",\"nested\":" + "[".repeat(65) + "0" + "]".repeat(65) + "}",
            "{\"type\":\"response.created\"} {\"type\":\"response.created\"}",
            "[]", "{\"type\":42}", "{\"type\":\"response.created\",\"text\":\"\\uD800\"}",
            "{\"type\":\"response.created\",\"text\":\"\\uDC00\"}",
        )) {
            assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE, "data: $json\n\n".toByteArray())
        }
    }

    @Test
    fun `malformed UTF8 is refused even when split across network chunks`() {
        val stream = stream()
        assertTrue(stream.accept("data: {\"type\":\"response.created\",\"text\":\"".toByteArray()).isEmpty())
        assertTrue(stream.accept(byteArrayOf(0xc3.toByte())).isEmpty())
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) {
            stream.accept(byteArrayOf(0x28) + "\"}\n\n".toByteArray())
        }
    }

    @Test
    fun `raw credential across network chunks never leaves quarantine`() {
        val stream = stream(secrets = listOf("credential-value"))
        assertTrue(stream.accept("data: {\"type\":\"response.created\",\"text\":\"credential-".toByteArray()).isEmpty())
        val failure = assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) { stream.accept("value\"}\n\n".toByteArray()) }
        assertFalse(failure.toString().contains("credential-value"))
        assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) { stream.accept(completed(0)) }
        assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) { stream.finish() }
    }

    @Test
    fun `escaped credentials in decoded strings names and nested JSON are rejected`() {
        val encoded = "\\u0073\\u0065\\u0063\\u0072\\u0065\\u0074"
        for (json in listOf(
            "{\"type\":\"response.created\",\"text\":\"$encoded\"}",
            "{\"type\":\"response.created\",\"$encoded\":false}",
            "{\"type\":\"response.created\",\"nested\":[{\"text\":\"$encoded\"}]}",
        )) {
            assertRejected(AcpProviderTerminalKind.SECRET_EXPOSURE, "data: $json\n\n".toByteArray(), secrets = listOf("secret"))
        }
    }

    @Test
    fun `credential fragments over three escaped output deltas remain held`() {
        val stream = stream(secrets = listOf("secret"))
        assertTrue(stream.accept(delta("se")).isEmpty())
        assertTrue(stream.accept("data: {\"type\":\"response.output_text.delta\",\"delta\":\"\\u0063\\u0072\"}\n\n".toByteArray()).isEmpty())
        assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) { stream.accept(delta("et")) }
    }

    @Test
    fun `every accepted renderable delta rejects split and escaped credential fragments`() {
        for (type in listOf("response.output_text.delta", "response.reasoning_summary_text.delta",
            "response.reasoning_text.delta", "response.function_call_arguments.delta", "response.custom_tool_call_input.delta")) {
            val stream = stream(secrets = listOf("secret"))
            assertTrue(stream.accept("data: {\"type\":\"$type\",\"delta\":\"se\"}\n\n".toByteArray()).isEmpty())
            assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) {
                stream.accept("data: {\"type\":\"$type\",\"delta\":\"\\u0063\\u0072et\"}\n\n".toByteArray())
            }
        }
    }

    @Test
    fun `unknown delta and metadata extensions are refused before forwarding`() {
        for (type in listOf("response.unknown.delta", "response.future_event", "response.metadata", "codex.response.metadata")) {
            assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE, event(type))
        }
    }

    @Test
    fun `interleaved logical output streams cannot reset another credential prefix`() {
        val stream = stream(secrets = listOf("ABCDEF"))
        assertTrue(stream.accept(indexedDelta("response.output_text.delta", "ABC", 0)).isEmpty())
        assertTrue(stream.accept(indexedDelta("response.output_text.delta", "unrelated", 1)).isEmpty())
        assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) {
            stream.accept(indexedDelta("response.output_text.delta", "DEF", 0))
        }
    }

    @Test
    fun `cross type interleaving cannot release a reasoning or output credential prefix`() {
        for ((first, other) in listOf(
            "response.reasoning_summary_text.delta" to "response.output_text.delta",
            "response.output_text.delta" to "response.reasoning_summary_text.delta",
        )) {
            val stream = stream(secrets = listOf("ABCDEF"))
            assertTrue(stream.accept(indexedDelta(first, "ABC", 0)).isEmpty())
            assertTrue(stream.accept(indexedDelta(other, "unrelated", 0)).isEmpty())
            assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) { stream.accept(indexedDelta(first, "DEF", 0)) }
        }
    }

    @Test
    fun `changing optional stream identity cannot alias a stable output index`() {
        for (lastId in listOf("changed_item", null)) {
            val stream = stream(secrets = listOf("ABCDEF"))
            assertTrue(stream.accept(indexedDelta("response.output_text.delta", "ABC", 0, "first_item")).isEmpty())
            assertTrue(stream.accept(indexedDelta("response.output_text.delta", "unrelated", 1, "other_item")).isEmpty())
            assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) {
                stream.accept(indexedDelta("response.output_text.delta", "DEF", 0, lastId))
            }
        }
    }

    @Test
    fun `custom tool item identity joins a later call id fallback alias`() {
        val stream = stream(secrets = listOf("ABCDEF"))
        val first = "data: {\"type\":\"response.custom_tool_call_input.delta\",\"delta\":\"ABC\",\"item_id\":\"A\",\"call_id\":\"B\"}\n\n".toByteArray()
        val unrelated = "data: {\"type\":\"response.custom_tool_call_input.delta\",\"delta\":\"x\",\"item_id\":\"C\"}\n\n".toByteArray()
        val fallback = "data: {\"type\":\"response.custom_tool_call_input.delta\",\"delta\":\"DEF\",\"call_id\":\"A\"}\n\n".toByteArray()
        assertTrue(stream.accept(first).isEmpty())
        assertTrue(stream.accept(unrelated).isEmpty())
        assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) { stream.accept(fallback) }
    }

    @Test
    fun `added and done assistant message parts cannot render a split credential`() {
        for (type in listOf("response.output_item.added", "response.output_item.done")) {
            assertRejected(AcpProviderTerminalKind.SECRET_EXPOSURE, message(type, listOf("ABC", "DEF")), secrets = listOf("ABCDEF"))
        }
    }

    @Test
    fun `both native assistant text projections reject their exact concatenation`() {
        val outputOnly = message("response.output_item.done", listOf("ABC", "unrelated", "DEF"),
            kinds = listOf("output_text", "input_text", "output_text"))
        assertRejected(AcpProviderTerminalKind.SECRET_EXPOSURE, outputOnly, secrets = listOf("ABCDEF"))
        val allText = message("response.output_item.done", listOf("ABC", "DEF"), kinds = listOf("input_text", "output_text"))
        assertRejected(AcpProviderTerminalKind.SECRET_EXPOSURE, allText, secrets = listOf("ABCDEF"))
    }

    @Test
    fun `interleaved message items cannot release another rendered credential prefix`() {
        val stream = stream(secrets = listOf("ABCDEF"))
        assertTrue(stream.accept(message("response.output_item.added", listOf("ABC"), "A", 0)).isEmpty())
        assertTrue(stream.accept(message("response.output_item.done", listOf("unrelated"), "B", 1)).isEmpty())
        assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) {
            stream.accept(message("response.output_item.done", listOf("DEF"), "A", 0))
        }
    }

    @Test
    fun `a message seed and later output delta share their rendered item identity`() {
        val stream = stream(secrets = listOf("ABCDEF"))
        assertTrue(stream.accept(message("response.output_item.added", listOf("ABC"), "A", 0)).isEmpty())
        assertTrue(stream.accept(indexedDelta("response.output_text.delta", "unrelated", 1, "B")).isEmpty())
        assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) {
            stream.accept(indexedDelta("response.output_text.delta", "DEF", 0, "A"))
        }
    }

    @Test
    fun `safe rendered message parts preserve the validated original event`() {
        val stream = stream()
        val event = message("response.output_item.done", listOf("hello", "world"))
        assertContentEquals(event, stream.accept(event).single())
        assertTrue(stream.accept(completed(2)).isEmpty())
        assertEquals(2, stream.finish().outputTokens)
        assertEquals(1, stream.drainFinished().size)
    }

    @Test
    fun `native citation removal markup is explicitly unsupported before it can join credentials`() {
        val transformed = "ABC<oai-mem-citation>x</oai-mem-citation>DEF"
        assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE, delta(transformed), secrets = listOf("ABCDEF"))
        assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE,
            message("response.output_item.done", listOf("ABC<oai-mem-", "citation>x</oai-mem-citation>DEF")),
            secrets = listOf("ABCDEF"))
    }

    @Test
    fun `split opening and closing citation markers stay quarantined through interleaving`() {
        for ((first, last) in listOf("<oai-mem-" to "citation>", "</oai-mem-" to "citation>")) {
            val stream = stream()
            assertTrue(stream.accept(indexedDelta("response.output_text.delta", first, 0)).isEmpty())
            assertTrue(stream.accept(indexedDelta("response.output_text.delta", "unrelated", 1)).isEmpty())
            assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) {
                stream.accept(indexedDelta("response.output_text.delta", last, 0))
            }
        }
    }

    @Test
    fun `citation marker split across rendered content parts is refused`() {
        assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE,
            message("response.output_item.done", listOf("<oai-mem-", "citation>")))
        assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE,
            message("response.output_item.done", listOf("</oai-mem-", "citation>")))
    }

    @Test
    fun `JSON escaped citation marker literals cannot bypass the unsupported markup boundary`() {
        val escaped = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"\\u003coai-mem-citation\\u003e\"}\n\n".toByteArray()
        assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE, escaped)
    }

    @Test
    fun `disproved citation prefix releases held events in order`() {
        val stream = stream()
        val first = delta("<oai-mem-")
        val second = delta("X")
        assertTrue(stream.accept(first).isEmpty())
        val events = stream.accept(second)
        assertEquals(2, events.size)
        assertContentEquals(first, events[0])
        assertContentEquals(second, events[1])
    }

    @Test
    fun `logical matcher identities have a finite count and canonical field bounds`() {
        val stream = stream()
        repeat(15) { assertEquals(1, stream.accept(indexedDelta("response.output_text.delta", "ok", it)).size) }
        assertFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) {
            stream.accept(indexedDelta("response.output_text.delta", "ok", 15))
        }
        for (identity in listOf("\"${"x".repeat(129)}\"", "\"non/ascii\"", "null", "false")) {
            assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE,
                "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\",\"item_id\":$identity}\n\n".toByteArray())
        }
        for (index in listOf("-1", "1.0", "\"1\"", "2147483648", "null")) {
            assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE,
                "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\",\"output_index\":$index}\n\n".toByteArray())
        }
    }

    @Test
    fun `overlapping credential prefixes use continuation state across delta events`() {
        val stream = stream(secrets = listOf("ababac", "bababa"))
        assertTrue(stream.accept(delta("ababa")).isEmpty())
        assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) { stream.accept(delta("c")) }
    }

    @Test
    fun `disproved semantic prefix releases held events in their original order`() {
        val stream = stream(secrets = listOf("secret"))
        val first = delta("se")
        val second = delta("x")
        assertTrue(stream.accept(first).isEmpty())
        val emitted = stream.accept(second)
        assertEquals(2, emitted.size)
        assertContentEquals(first, emitted[0])
        assertContentEquals(second, emitted[1])
        stream.accept(completed(2))
        stream.finish()
    }

    @Test
    fun `actual EOF safely ends an unfinished semantic credential prefix`() {
        val stream = stream(secrets = listOf("secret"))
        assertTrue(stream.accept(delta("se")).isEmpty())
        assertTrue(stream.accept(completed(1)).isEmpty())
        assertEquals(1, stream.finish().outputTokens)
        assertEquals(2, stream.drainFinished().size)
    }

    @Test
    fun `raw credential spanning adjacent complete SSE events is held and rejected`() {
        val first = event("response.created")
        val second = event("response.in_progress")
        val secret = first.takeLast(4).toByteArray() + second.take(12).toByteArray()
        val stream = AcpProviderResponseStream(AcpProviderTransportBounds(), listOf(secret), 4096)
        assertTrue(stream.accept(first).isEmpty())
        assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) { stream.accept(second) }
    }

    @Test
    fun `normalized emitted credential spanning CRLF events cannot bypass wire scanning`() {
        val first = event("response.created")
        val second = event("response.in_progress")
        val secret = first.takeLast(4).toByteArray() + second.take(12).toByteArray()
        val stream = AcpProviderResponseStream(AcpProviderTransportBounds(), listOf(secret), 4096)
        val crlfFirst = first.toString(Charsets.UTF_8).replace("\n", "\r\n").toByteArray()
        val crlfSecond = second.toString(Charsets.UTF_8).replace("\n", "\r\n").toByteArray()
        assertTrue(stream.accept(crlfFirst).isEmpty())
        assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) { stream.accept(crlfSecond) }
    }

    @Test
    fun `credential quarantine cannot exceed the finite queue capacity`() {
        val bounds = AcpProviderTransportBounds(maximumChunkBytes = 256, maximumQueuedChunks = 1)
        val stream = stream(bounds, listOf("abcdef"))
        var held = 0
        for (part in listOf("a", "b", "c", "d", "e")) {
            val event = delta(part)
            if (held + event.size <= 256) {
                assertTrue(stream.accept(event).isEmpty())
                held += event.size
            } else {
                assertFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { stream.accept(event) }
                return
            }
        }
        error("the control did not exercise the queue bound")
    }

    @Test
    fun `a released batch including prior quarantine cannot exceed the queue capacity`() {
        val bounds = AcpProviderTransportBounds(maximumChunkBytes = 256, maximumQueuedChunks = 1)
        val stream = stream(bounds, listOf("secret"))
        assertTrue(stream.accept(delta("se")).isEmpty())
        val incoming = event("response.created") + delta("x") + event("response.created")
        assertTrue(incoming.size <= bounds.maximumChunkBytes)
        assertFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { stream.accept(incoming) }
    }

    @Test
    fun `event byte boundary accepts exactly the limit and refuses one more byte`() {
        val bounds = AcpProviderTransportBounds(maximumChunkBytes = 256)
        val base = "data: {\"type\":\"response.created\",\"padding\":\"\"}\n\n"
        val exact = base.replace("\"padding\":\"\"", "\"padding\":\"${"x".repeat(256 - base.length)}\"").toByteArray()
        assertEquals(256, exact.size)
        val allowed = stream(bounds)
        assertContentEquals(exact, allowed.accept(exact).single())
        allowed.accept(completed(0))
        allowed.finish()
        val tooLarge = exact.toString(Charsets.UTF_8).replace("padding\":\"", "padding\":\"x").toByteArray()
        assertRejected(AcpProviderTerminalKind.RESOURCE_EXHAUSTED, tooLarge, bounds)
    }

    @Test
    fun `cumulative response bytes are charged before parsing or retaining a chunk`() {
        val bounds = AcpProviderTransportBounds(maximumResponseBytes = 256, maximumChunkBytes = 256)
        val stream = stream(bounds)
        val first = event("response.created")
        assertEquals(1, stream.accept(first).size)
        assertFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { stream.accept(ByteArray(257 - first.size)) }
    }

    @Test
    fun `stream event count has a finite cumulative parse work bound`() {
        val stream = stream()
        val created = event("response.created")
        repeat(AcpProviderResponseStream.MAXIMUM_EVENTS) { assertEquals(1, stream.accept(created).size) }
        assertFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { stream.accept(completed(0)) }
    }

    @Test
    fun `cumulative JSON token work is bounded independently of the response byte limit`() {
        val stream = stream()
        val manyTokens = "data: {\"type\":\"response.created\",\"numbers\":[${List(8192) { "0" }.joinToString(",")}]}\n\n".toByteArray()
        var accepted = 0
        while (true) {
            try {
                assertEquals(1, stream.accept(manyTokens).size)
                accepted++
            } catch (failure: AcpProviderStreamFailure) {
                assertEquals(AcpProviderTerminalKind.RESOURCE_EXHAUSTED, failure.kind)
                assertTrue(accepted in 1 until AcpProviderResponseStream.MAXIMUM_EVENTS)
                assertTrue((accepted + 1L) * manyTokens.size < AcpProviderTransportBounds().maximumResponseBytes)
                return
            }
        }
    }

    @Test
    fun `completion requires exact nonnegative integer usage and completed status`() {
        for (output in listOf("null", "\"1\"", "-1", "1.0", "1e0", "2147483648", "true")) {
            val json = "{\"type\":\"response.completed\",\"response\":{\"id\":\"resp_fixture\",\"status\":\"completed\",\"usage\":{\"input_tokens\":0,\"total_tokens\":0,\"output_tokens\":$output}}}"
            assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE, "data: $json\n\n".toByteArray())
        }
        for (json in listOf(
            "{\"type\":\"response.completed\"}",
            "{\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}",
            "{\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{}}}",
            "{\"type\":\"response.completed\",\"response\":{\"status\":\"in_progress\",\"usage\":{\"output_tokens\":0}}}",
            "{\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"output_tokens\":0,\"input_tokens\":2147483648}}}",
        )) {
            assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE, "data: $json\n\n".toByteArray())
        }
    }

    @Test
    fun `output token usage consumes the remaining invocation budget`() {
        val stream = AcpProviderResponseStream(AcpProviderTransportBounds(), emptyList(), 3)
        assertFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { stream.accept(completed(4)) }
        val atLimit = AcpProviderResponseStream(AcpProviderTransportBounds(), emptyList(), 3)
        assertTrue(atLimit.accept(completed(3)).isEmpty())
        assertEquals(3, atLimit.finish().outputTokens)
        assertEquals(1, atLimit.drainFinished().size)
    }

    @Test
    fun `pinned native completion fields and optional metadata remain held until EOF`() {
        val terminal = completedResponse("""{"id":"resp_native","status":"completed","end_turn":true,"usage_metadata":{"amount":"0.01","metadata":{"extension":true}},"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3,"input_tokens_details":{"cached_tokens":1,"cache_write_tokens":0},"output_tokens_details":{"reasoning_tokens":1},"codex_rollout_budget_units":0.5},"future_field":[1]}""")
        val stream = stream()
        assertTrue(stream.accept(terminal).isEmpty())
        val receipt = stream.finish()
        assertEquals(1, receipt.inputTokens)
        assertEquals(2, receipt.outputTokens)
        assertContentEquals(terminal, stream.drainFinished().single())
    }

    @Test
    fun `pinned completion rejects missing id and each required integer usage field`() {
        for (id in listOf(null, "null", "7", "true", "[]", "{}")) {
            val field = if (id == null) "" else "\"id\":$id,"
            assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE,
                completedResponse("""{${field}"status":"completed","usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}"""))
        }
        for (field in listOf("input_tokens", "output_tokens", "total_tokens")) {
            val invalidValues = listOf(null, "null", "\"0\"", "true", "1.0", "1e0", "9223372036854775808") +
                if (field == "total_tokens") emptyList() else listOf("-1", "2147483648")
            for (invalid in invalidValues) {
                val fields = linkedMapOf("input_tokens" to "1", "output_tokens" to "2", "total_tokens" to "3")
                if (invalid == null) fields.remove(field) else fields[field] = invalid
                val usage = fields.entries.joinToString(",") { "\"${it.key}\":${it.value}" }
                assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE,
                    completedResponse("""{"id":"resp_native","status":"completed","usage":{$usage}}"""))
            }
        }
        // This exact formerly accepted envelope cannot produce the pinned native Completed event.
        val stream = stream()
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) {
            stream.accept(completedResponse("""{"status":"completed","usage":{"output_tokens":0}}"""))
        }
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) { stream.finish() }
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) { stream.drainFinished() }
    }

    @Test
    fun `pinned completion rejects malformed present detail and metadata shapes`() {
        for (extra in listOf(
            "\"end_turn\":\"true\"", "\"end_turn\":0", "\"usage_metadata\":[]",
            "\"usage_metadata\":{\"amount\":1}",
        )) {
            assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE,
                completedResponse("""{"id":"resp_native","status":"completed",$extra,"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}"""))
        }
        for (extra in listOf(
            "\"input_tokens_details\":[]", "\"input_tokens_details\":{}",
            "\"input_tokens_details\":{\"cached_tokens\":\"1\"}",
            "\"input_tokens_details\":{\"cached_tokens\":1,\"cache_write_tokens\":null}",
            "\"input_tokens_details\":{\"cached_tokens\":9223372036854775808}",
            "\"output_tokens_details\":[]", "\"output_tokens_details\":{}",
            "\"output_tokens_details\":{\"reasoning_tokens\":true}",
            "\"codex_rollout_budget_units\":\"0.5\"", "\"codex_rollout_budget_units\":true",
            "\"codex_rollout_budget_units\":[]", "\"codex_rollout_budget_units\":1e400",
        )) {
            assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE,
                completedResponse("""{"id":"resp_native","status":"completed","usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3,$extra}}"""))
        }
        val terminal = completedResponse("""{"id":"resp_native","status":"completed","end_turn":null,"usage_metadata":{"amount":null,"metadata":null},"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":null,"codex_rollout_budget_units":null}}""")
        val stream = stream()
        assertTrue(stream.accept(terminal).isEmpty())
        stream.finish()
        assertContentEquals(terminal, stream.drainFinished().single())
    }

    @Test
    fun `known optional wire fields reject wrong present types without requiring absent fields`() {
        for (field in listOf("item_id", "call_id", "delta", "text")) {
            for (invalid in listOf("7", "true", "[]", "{}")) {
                assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE,
                    "data: {\"type\":\"response.output_text.done\",\"$field\":$invalid}\n\n".toByteArray())
            }
        }
        for (field in listOf("summary_index", "content_index")) {
            for (invalid in listOf("\"0\"", "true", "1.0", "1e0", "9223372036854775808")) {
                assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE,
                    "data: {\"type\":\"response.output_text.done\",\"$field\":$invalid}\n\n".toByteArray())
            }
        }
        val ignored = "data: {\"type\":\"response.output_text.done\",\"item_id\":null,\"call_id\":null,\"delta\":null,\"text\":null,\"summary_index\":null,\"content_index\":null,\"output_index\":\"extension\",\"sequence_number\":{\"extension\":true}}\n\n".toByteArray()
        assertContentEquals(ignored, stream().accept(ignored).single())
        val signedIndices = "data: {\"type\":\"response.output_text.done\",\"summary_index\":-9223372036854775808,\"content_index\":9223372036854775807}\n\n".toByteArray()
        assertContentEquals(signedIndices, stream().accept(signedIndices).single())
    }

    @Test
    fun `pinned ignored kinds preserve type only events and unknown fields`() {
        for (type in listOf("response.in_progress", "response.content_part.added", "response.content_part.done",
            "response.output_text.done", "response.custom_tool_call_input.done", "response.function_call_arguments.delta",
            "response.function_call_arguments.done", "response.reasoning_summary_part.done")) {
            // The adapter retains its existing stricter delta policy even for this native-ignored kind.
            val extra = if (type == "response.function_call_arguments.delta") ",\"delta\":\"safe\"" else ""
            val ignored = "data: {\"type\":\"$type\",\"future_field\":true$extra}\n\n".toByteArray()
            val stream = stream()
            assertContentEquals(ignored, stream.accept(ignored).single())
            assertTrue(stream.accept(completed(0)).isEmpty())
            assertEquals(2, stream.finish().eventCount)
            assertEquals(1, stream.drainFinished().size)
        }
    }

    @Test
    fun `input token cap requires reported usage and refuses excess before terminal release`() {
        val missing = AcpProviderResponseStream(AcpProviderTransportBounds(), emptyList(), 3, 10)
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) { missing.accept(completed(0, null)) }
        val excess = AcpProviderResponseStream(AcpProviderTransportBounds(), emptyList(), 3, 10)
        assertFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { excess.accept(completed(0, 11)) }
        val atLimit = AcpProviderResponseStream(AcpProviderTransportBounds(), emptyList(), 3, 10)
        assertTrue(atLimit.accept(completed(0, 10)).isEmpty())
        assertEquals(10, atLimit.finish().inputTokens)
        assertEquals(1, atLimit.drainFinished().size)
    }

    @Test
    fun `completion and held prefixes are not released before actual EOF`() {
        val stream = stream(secrets = listOf("secret"))
        assertTrue(stream.accept(delta("se")).isEmpty())
        assertTrue(stream.accept(completed(1)).isEmpty())
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) { stream.drainFinished() }
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) { stream.accept(byteArrayOf(0x20)) }
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) { stream.finish() }
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) { stream.drainFinished() }
    }

    @Test
    fun `finished terminal quarantine drains exactly once after successful EOF`() {
        val stream = stream()
        val terminal = completed(0)
        assertTrue(stream.accept(terminal).isEmpty())
        stream.finish()
        assertContentEquals(terminal, stream.drainFinished().single())
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) { stream.drainFinished() }
    }

    @Test
    fun `error events refuse their raw body and never return it`() {
        for (type in listOf("error", "response.error", "response.failed", "response.incomplete")) {
            assertRejected(AcpProviderTerminalKind.MALFORMED_RESPONSE, event(type, "private upstream diagnostic"))
        }
    }

    @Test
    fun `EOF without completion and incomplete event are refused`() {
        for (bytes in listOf(ByteArray(0), event("response.created"), completed(0).dropLast(1).toByteArray())) {
            val stream = stream()
            stream.accept(bytes)
            assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) { stream.finish() }
        }
    }

    @Test
    fun `bytes after completion and calls after finish cannot reopen the stream`() {
        val stream = stream()
        stream.accept(completed(0))
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) { stream.accept(event("response.created")) }
        val finished = stream()
        finished.accept(completed(0))
        finished.finish()
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) { finished.accept(ByteArray(0)) }
        assertFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) { finished.finish() }
    }

    @Test
    fun `scanner copies credential material and bounds its own initialization`() {
        val secret = "secret".toByteArray()
        val stream = AcpProviderResponseStream(AcpProviderTransportBounds(), listOf(secret), 4096)
        secret.fill(0)
        assertFailure(AcpProviderTerminalKind.SECRET_EXPOSURE) { stream.accept(delta("secret")) }
        assertFailsWith<IllegalArgumentException> { AcpProviderResponseStream(AcpProviderTransportBounds(), listOf(ByteArray(0)), 4096) }
        assertFailsWith<IllegalArgumentException> { AcpProviderResponseStream(AcpProviderTransportBounds(), listOf(ByteArray(8193)), 4096) }
        assertFailsWith<IllegalArgumentException> { AcpProviderResponseStream(AcpProviderTransportBounds(), List(17) { byteArrayOf(1) }, 4096) }
        assertFailsWith<IllegalArgumentException> { AcpProviderResponseStream(AcpProviderTransportBounds(), emptyList(), 4097) }
    }

    private fun stream(bounds: AcpProviderTransportBounds = AcpProviderTransportBounds(), secrets: List<String> = emptyList()) =
        AcpProviderResponseStream(bounds, secrets.map { it.toByteArray() }, bounds.maximumOutputTokens)

    private fun event(type: String, text: String? = null): ByteArray {
        val fields = linkedMapOf("type" to JsonPrimitive(type))
        text?.let { fields["text"] = JsonPrimitive(it) }
        return "event: $type\ndata: ${JsonObject(fields)}\n\n".toByteArray()
    }

    private fun delta(text: String): ByteArray = "event: response.output_text.delta\ndata: ${JsonObject(mapOf(
        "type" to JsonPrimitive("response.output_text.delta"), "delta" to JsonPrimitive(text),
    ))}\n\n".toByteArray()

    private fun indexedDelta(type: String, text: String, index: Int, itemId: String? = null): ByteArray {
        val fields = linkedMapOf("type" to JsonPrimitive(type), "delta" to JsonPrimitive(text), "output_index" to JsonPrimitive(index))
        itemId?.let { fields["item_id"] = JsonPrimitive(it) }
        return "data: ${JsonObject(fields)}\n\n".toByteArray()
    }

    private fun message(type: String, text: List<String>, id: String = "A", index: Int = 0,
        kinds: List<String> = List(text.size) { "output_text" }): ByteArray {
        val content = JsonArray(text.mapIndexed { part, value -> JsonObject(mapOf(
            "type" to JsonPrimitive(kinds[part]), "text" to JsonPrimitive(value),
        )) })
        val item = JsonObject(mapOf("type" to JsonPrimitive("message"), "role" to JsonPrimitive("assistant"),
            "id" to JsonPrimitive(id), "content" to content))
        val fields = JsonObject(mapOf("type" to JsonPrimitive(type), "output_index" to JsonPrimitive(index), "item" to item))
        return "data: $fields\n\n".toByteArray()
    }

    private fun completed(output: Int, input: Int? = 0): ByteArray {
        val usage = linkedMapOf("output_tokens" to JsonPrimitive(output),
            "total_tokens" to JsonPrimitive(output.toLong() + (input?.toLong() ?: 0L)))
        input?.let { usage["input_tokens"] = JsonPrimitive(it) }
        val json = JsonObject(mapOf("type" to JsonPrimitive("response.completed"), "response" to JsonObject(mapOf(
            "id" to JsonPrimitive("resp_fixture"), "status" to JsonPrimitive("completed"), "usage" to JsonObject(usage),
        ))))
        return "event: response.completed\ndata: $json\n\n".toByteArray()
    }

    private fun completedResponse(response: String): ByteArray =
        "data: {\"type\":\"response.completed\",\"response\":$response}\n\n".toByteArray()

    private fun assertRejected(kind: AcpProviderTerminalKind, bytes: ByteArray,
        bounds: AcpProviderTransportBounds = AcpProviderTransportBounds(), secrets: List<String> = emptyList()) {
        assertFailure(kind) { stream(bounds, secrets).accept(bytes) }
    }

    private fun assertFailure(kind: AcpProviderTerminalKind, action: () -> Any?): AcpProviderStreamFailure =
        assertFailsWith<AcpProviderStreamFailure> { action() }.also { assertEquals(kind, it.kind) }
}
