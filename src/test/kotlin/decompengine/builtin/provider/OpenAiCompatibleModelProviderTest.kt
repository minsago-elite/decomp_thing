package decompengine.builtin.provider

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import decompengine.agent.AgentCancellationSource
import kotlinx.serialization.json.*
import java.net.InetSocketAddress
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

class OpenAiCompatibleModelProviderTest {
    private val key = "fixture-secret-not-a-credential"
    private fun request(limits: ModelCallLimits = ModelCallLimits(), tools: List<ModelToolDefinition> = emptyList()) =
        ModelRequest(listOf(ModelMessage(ModelRole.USER, "inspect source")), tools, limits)
    private fun tool() = ModelToolDefinition("read_file", "Read authorized source", buildJsonObject {
        put("type", "object"); putJsonObject("properties") { putJsonObject("path") { put("type", "string") } }
    })
    private fun chunk(delta: JsonObject = buildJsonObject {}, finish: String? = null) = buildJsonObject {
        putJsonArray("choices") { add(buildJsonObject {
            put("index", 0); put("delta", delta); put("finish_reason", finish?.let(::JsonPrimitive) ?: JsonNull)
        }) }
    }.toString()
    private fun text(value: String) = chunk(buildJsonObject { put("content", value) })
    private fun usage(input: Long = 5, output: Long = 2) = buildJsonObject {
        putJsonArray("choices") {}
        putJsonObject("usage") { put("prompt_tokens", input); put("completion_tokens", output) }
    }.toString()
    private fun events(vararg data: String) = data.joinToString("") { "data: $it\n\n" }
    private fun success(value: String = "hello") = events(text(value), chunk(finish = "stop"), usage(), "[DONE]")
    private fun call(index: Int = 0, id: String? = "call_1", name: String? = "read_file", args: String) = chunk(buildJsonObject {
        putJsonArray("tool_calls") { add(buildJsonObject {
            put("index", index); id?.let { put("id", it); put("type", "function") }
            putJsonObject("function") { name?.let { put("name", it) }; put("arguments", args) }
        }) }
    })

    @Test fun `streams text before completion and maps measured usage`() = server({ exchange, _ ->
        val body = Json.parseToJsonElement(exchange.requestBody.readAllBytes().decodeToString()).jsonObject
        assertEquals("fixture-model", body["model"]?.jsonPrimitive?.content)
        assertEquals(true, body["stream"]?.jsonPrimitive?.boolean)
        assertEquals(false, body["store"]?.jsonPrimitive?.boolean)
        assertEquals("Bearer $key", exchange.requestHeaders.getFirst("Authorization"))
        exchange.sse(success("안녕"))
    }) { provider, _ ->
        val seen = mutableListOf<ModelEvent>()
        val response = provider.generate(request()) { seen += it }
        assertEquals("안녕", response.text)
        assertEquals(ModelUsage(5, 2, false), response.usage)
        assertEquals(ModelFinishReason.STOP, response.finishReason)
        assertIs<ModelEvent.TextDelta>(seen.first())
        assertIs<ModelEvent.Finished>(seen.last())
        assertEquals(1, response.attempts)
    }

    @Test fun `text callback occurs while server is still generating`() {
        val observed = CountDownLatch(1)
        server({ exchange, _ ->
            exchange.beginSse()
            exchange.responseBody.write(events(text("first")).toByteArray()); exchange.responseBody.flush()
            assertTrue(observed.await(3, TimeUnit.SECONDS))
            exchange.responseBody.write(events(text("second"), chunk(finish = "stop"), "[DONE]").toByteArray())
        }) { provider, _ ->
            val response = provider.generate(request()) { if (it is ModelEvent.TextDelta) observed.countDown() }
            assertEquals("firstsecond", response.text)
            assertTrue(response.usage.estimated)
            assertEquals(11, response.usage.outputTokens)
        }
    }

    @Test fun `assembles interleaved typed tool calls before dispatch`() = server({ exchange, _ ->
        exchange.sse(events(call(args = "{\"path\":"), call(1, "call_2", args = "{\"path\":\"b.c\"}"),
            call(id = null, name = null, args = "\"a.c\"}"), chunk(finish = "tool_calls"), usage(), "[DONE]"))
    }) { provider, _ ->
        val seen = mutableListOf<ModelEvent>()
        val response = provider.generate(request(tools = listOf(tool()))) { seen += it }
        assertEquals(listOf("call_1", "call_2"), response.toolCalls.map { it.id })
        assertEquals("a.c", response.toolCalls.first().arguments["path"]?.jsonPrimitive?.content)
        assertEquals(2, seen.filterIsInstance<ModelEvent.ToolCall>().size)
        assertEquals(ModelFinishReason.TOOL_CALLS, response.finishReason)
    }

    @Test fun `tool history is encoded without provider wire types in the request`() = server({ exchange, _ ->
        val messages = Json.parseToJsonElement(exchange.requestBody.readAllBytes().decodeToString()).jsonObject.getValue("messages").jsonArray
        assertEquals("call_1", messages[1].jsonObject["tool_call_id"]?.jsonPrimitive?.content)
        assertEquals("read_file", messages[0].jsonObject.getValue("tool_calls").jsonArray[0].jsonObject
            .getValue("function").jsonObject["name"]?.jsonPrimitive?.content)
        exchange.sse(success())
    }) { provider, _ ->
        val call = ModelToolCall("call_1", "read_file", buildJsonObject { put("path", "a.c") })
        provider.generate(ModelRequest(listOf(ModelMessage(ModelRole.ASSISTANT, "", listOf(call)),
            ModelMessage(ModelRole.TOOL, "source", toolCallId = "call_1")), listOf(tool()))) {}
    }

    @Test fun `classifies terminal HTTP errors and never echoes response or configuration secrets`() {
        mapOf(400 to ModelFailureKind.INVALID_REQUEST, 401 to ModelFailureKind.AUTHENTICATION,
            403 to ModelFailureKind.AUTHORIZATION, 404 to ModelFailureKind.MODEL_UNAVAILABLE,
            422 to ModelFailureKind.INVALID_REQUEST, 501 to ModelFailureKind.UNSUPPORTED_FEATURE).forEach { (status, kind) ->
            server({ exchange, _ -> exchange.reply(status, key) }) { provider, count ->
                val failure = assertFailsWith<ModelProviderException> { provider.generate(request()) {} }
                assertEquals(kind, failure.kind)
                assertEquals(status, failure.httpStatus)
                assertFalse(failure.stackTraceToString().contains(key))
                assertNull(failure.cause)
                assertEquals(1, count.get())
            }
        }
    }

    @Test fun `bounded transient retries honor retry guidance`() = server({ exchange, count ->
        if (count < 3) { exchange.responseHeaders.set("Retry-After", "0"); exchange.reply(429, key) }
        else exchange.sse(success())
    }) { provider, count ->
        val seen = mutableListOf<ModelEvent>()
        val limits = ModelCallLimits(retryBaseDelay = Duration.ofMillis(2), maxRetryDelay = Duration.ofMillis(10))
        val response = provider.generate(request(limits)) { seen += it }
        assertEquals(3, response.attempts)
        assertEquals(3, count.get())
        assertEquals(listOf(1, 2), seen.filterIsInstance<ModelEvent.Retrying>().map { it.attempt })
    }

    @Test fun `retry exhaustion and excessive guidance fail without extra requests`() {
        server({ exchange, _ -> exchange.reply(503, key) }) { provider, count ->
            val limits = ModelCallLimits(maxRetries = 1, retryBaseDelay = Duration.ofMillis(1))
            val failure = assertFailsWith<ModelProviderException> { provider.generate(request(limits)) {} }
            assertTrue(failure.retryable); assertEquals(2, count.get())
        }
        server({ exchange, _ -> exchange.responseHeaders.set("Retry-After", "3600"); exchange.reply(429, key) }) { provider, count ->
            assertFailsWith<ModelProviderException> { provider.generate(request()) {} }
            assertEquals(1, count.get())
        }
    }

    @Test fun `malformed streams and indeterminate partial responses are never retried`() {
        listOf(events("garbage"), events(text("partial")), events("[DONE]"),
            events(chunk(finish = "unknown"), "[DONE]"), events(chunk(finish = "stop"), text("late"), "[DONE]"),
            events(chunk(finish = "stop"), usage(-1), "[DONE]")).forEach { body ->
            server({ exchange, _ -> exchange.sse(body) }) { provider, count ->
                assertFailsWith<ModelProviderException> { provider.generate(request()) {} }
                assertEquals(1, count.get())
            }
        }
    }

    @Test fun `unregistered incomplete duplicate and secret bearing tool calls cannot escape`() {
        val bad = listOf(
            events(call(name = "host_shell", args = "{}"), chunk(finish = "tool_calls"), "[DONE]"),
            events(call(args = "{"), chunk(finish = "tool_calls"), "[DONE]"),
            events(call(args = "{}"), call(1, args = "{}"), chunk(finish = "tool_calls"), "[DONE]"),
            events(call(args = "{\"path\":\"$key\"}"), chunk(finish = "tool_calls"), "[DONE]"),
            events(call(args = "{\"path\":\"" + key.map { "\\u%04x".format(it.code) }.joinToString("") + "\"}"),
                chunk(finish = "tool_calls"), "[DONE]"),
            events(call(args = "{}"), chunk(finish = "stop"), "[DONE]"),
        )
        bad.forEach { body -> server({ exchange, _ -> exchange.sse(body) }) { provider, _ ->
            val seen = mutableListOf<ModelEvent>()
            assertFailsWith<ModelProviderException> { provider.generate(request(tools = listOf(tool()))) { seen += it } }
            assertTrue(seen.none { it is ModelEvent.ToolCall || it is ModelEvent.Finished })
        } }
    }

    @Test fun `redacts credentials and request secrets across every chunk split`() {
        for (split in 1 until key.length) {
            val output = StringBuilder()
            val redactor = StreamingRedactor(listOf(key)) { output.append(it) }
            redactor.append("before " + key.take(split)); redactor.append(key.drop(split) + " after"); redactor.finish()
            assertEquals("before [REDACTED] after", output.toString())
        }
        server({ exchange, _ -> exchange.sse(events(text(key.take(4)), text(key.drop(4)), text(" private-input"),
            chunk(finish = "stop"), "[DONE]")) }) { provider, _ ->
            val seen = mutableListOf<ModelEvent>()
            val response = provider.generate(ModelRequest(listOf(ModelMessage(ModelRole.USER, "private-input")),
                secrets = listOf("private-input"))) { seen += it }
            assertEquals("[REDACTED] [REDACTED]", response.text)
            assertFalse(seen.filterIsInstance<ModelEvent.TextDelta>().joinToString("") { it.text }.contains(key))
        }
    }

    @Test fun `request response and event ceilings fail explicitly`() {
        server({ exchange, _ -> exchange.sse(success("x".repeat(1000))) }) { provider, count ->
            assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, assertFailsWith<ModelProviderException> {
                provider.generate(request(ModelCallLimits(maxRequestBytes = 1))) {}
            }.kind)
            assertEquals(0, count.get())
            for (limits in listOf(ModelCallLimits(maxResponseBytes = 200, maxEventBytes = 200), ModelCallLimits(maxEventBytes = 100))) {
                assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, assertFailsWith<ModelProviderException> {
                    provider.generate(request(limits)) {}
                }.kind)
            }
        }
    }

    @Test fun `invalid configuration is sanitized and insecure endpoints require explicit loopback opt in`() {
        for (url in listOf("not a url $key", "http://example.com", "https://user:$key@example.com",
            "https://example.com?key=$key", "https://example.com/#$key", "file:///tmp/provider")) {
            val failure = assertFailsWith<ModelProviderException> { OpenAiCompatibleConfiguration(url, "model", key) }
            assertEquals(ModelFailureKind.CONFIGURATION, failure.kind)
            assertFalse(failure.stackTraceToString().contains(key))
        }
        assertFalse(OpenAiCompatibleConfiguration("https://example.com/v1", "model", key).toString().contains(key))
    }

    @Test fun `unsupported tool capability fails before transport`() = server({ exchange, _ -> exchange.sse(success()) }) { _, count ->
        val provider = OpenAiCompatibleModelProvider(OpenAiCompatibleConfiguration("https://example.invalid", "model", key, false))
        assertEquals(ModelFailureKind.UNSUPPORTED_FEATURE, assertFailsWith<ModelProviderException> {
            provider.generate(request(tools = listOf(tool()))) {}
        }.kind)
        assertEquals(0, count.get())
    }

    @Test fun `cancellation before request has no traffic`() = server({ exchange, _ -> exchange.sse(success()) }) { provider, count ->
        val cancellation = AgentCancellationSource().apply { cancel() }
        assertEquals(ModelFailureKind.CANCELLED, assertFailsWith<ModelProviderException> {
            provider.generate(ModelRequest(request().messages, cancellation = cancellation.cancellation)) {}
        }.kind)
        assertEquals(0, count.get())
    }

    @Test fun `cancellation during streaming closes promptly and has no tool dispatch`() {
        val cancel = AgentCancellationSource()
        val release = CountDownLatch(1)
        server({ exchange, _ ->
            exchange.beginSse(); exchange.responseBody.write(events(text("waiting")).toByteArray()); exchange.responseBody.flush()
            release.await(3, TimeUnit.SECONDS)
        }) { provider, count ->
            val started = System.nanoTime()
            try {
                assertEquals(ModelFailureKind.CANCELLED, assertFailsWith<ModelProviderException> {
                    provider.generate(ModelRequest(request().messages, cancellation = cancel.cancellation)) {
                        if (it is ModelEvent.TextDelta) cancel.cancel()
                    }
                }.kind)
                assertTrue(Duration.ofNanos(System.nanoTime() - started) < Duration.ofSeconds(2))
                assertEquals(1, count.get())
            } finally { release.countDown() }
        }
    }

    @Test fun `stream idle and whole request deadlines stop stalled bodies`() {
        for (limits in listOf(ModelCallLimits(streamIdleTimeout = Duration.ofMillis(100)),
            ModelCallLimits(requestTimeout = Duration.ofMillis(150)), ModelCallLimits(overallTimeout = Duration.ofMillis(150)))) {
            val release = CountDownLatch(1)
            server({ exchange, _ -> exchange.beginSse(); exchange.responseBody.flush(); release.await(3, TimeUnit.SECONDS) }) { provider, _ ->
                try {
                    assertEquals(ModelFailureKind.TIMEOUT, assertFailsWith<ModelProviderException> { provider.generate(request(limits)) {} }.kind)
                } finally { release.countDown() }
            }
        }
    }

    @Test fun `redirects cannot forward authorization to another route`() = server({ exchange, _ ->
        exchange.responseHeaders.set("Location", "/untrusted"); exchange.reply(302, key)
    }) { provider, count ->
        assertFailsWith<ModelProviderException> { provider.generate(request()) {} }
        assertEquals(1, count.get())
    }

    @Test fun `length refusal and missing usage remain distinguishable`() {
        for ((wire, expected) in listOf("length" to ModelFinishReason.LENGTH, "content_filter" to ModelFinishReason.REFUSED)) {
            server({ exchange, _ -> exchange.sse(events(text("answer"), chunk(finish = wire), "[DONE]")) }) { provider, _ ->
                val response = provider.generate(request()) {}
                assertEquals(expected, response.finishReason)
                assertTrue(response.usage.estimated)
                assertEquals(6, response.usage.outputTokens)
            }
        }
    }

    @Test fun `duplicate keys deep nesting and invalid UTF8 cannot become actions`() {
        val ambiguous = "{\"choices\":[],\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}"
        val deep = "{\"extra\":" + "[".repeat(100) + "0" + "]".repeat(100) + ",\"choices\":[]}"
        for (body in listOf(events(ambiguous, "[DONE]"), events(deep, "[DONE]"),
            events(call(args = "{\"path\":\"a\",\"path\":\"b\"}"), chunk(finish = "tool_calls"), "[DONE]"))) {
            server({ exchange, _ -> exchange.sse(body) }) { provider, _ ->
                assertEquals(ModelFailureKind.MALFORMED_RESPONSE, assertFailsWith<ModelProviderException> {
                    provider.generate(request(tools = listOf(tool()))) {}
                }.kind)
            }
        }
        server({ exchange, _ -> exchange.beginSse(); exchange.responseBody.write(byteArrayOf(0xc3.toByte(), 0x28, 10)) }) { provider, _ ->
            assertEquals(ModelFailureKind.MALFORMED_RESPONSE, assertFailsWith<ModelProviderException> { provider.generate(request()) {} }.kind)
        }
    }

    @Test fun `escaping and tool schemas are charged during bounded serialization`() = server({ exchange, _ -> exchange.sse(success()) }) { provider, count ->
        val escaped = ModelRequest(listOf(ModelMessage(ModelRole.USER, "\u0001".repeat(1000))), limits = ModelCallLimits(maxRequestBytes = 1200))
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, assertFailsWith<ModelProviderException> { provider.generate(escaped) {} }.kind)
        val largeSchema = ModelToolDefinition("read_file", "x".repeat(10_000), tool().parameters)
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, assertFailsWith<ModelProviderException> {
            provider.generate(request(ModelCallLimits(maxRequestBytes = 1200), listOf(largeSchema))) {}
        }.kind)
        assertEquals(0, count.get())
    }

    @Test fun `headers timeout and cancellation abandon the owned HTTP subscription`() {
        for (cancelled in listOf(false, true)) {
            val source = AgentCancellationSource()
            val release = CountDownLatch(1)
            server({ _, _ -> if (cancelled) source.cancel(); release.await(3, TimeUnit.SECONDS) }) { provider, _ ->
                try {
                    val request = ModelRequest(request().messages, limits = ModelCallLimits(requestTimeout = Duration.ofMillis(200)),
                        cancellation = source.cancellation)
                    assertEquals(if (cancelled) ModelFailureKind.CANCELLED else ModelFailureKind.TIMEOUT,
                        assertFailsWith<ModelProviderException> { provider.generate(request) {} }.kind)
                } finally { release.countDown() }
            }
        }
    }

    @Test fun `retry wait is cancellable and shares the overall deadline`() = server({ exchange, _ -> exchange.reply(429, key) }) { provider, count ->
        val source = AgentCancellationSource()
        val req = ModelRequest(request().messages, cancellation = source.cancellation)
        assertEquals(ModelFailureKind.CANCELLED, assertFailsWith<ModelProviderException> {
            provider.generate(req) { if (it is ModelEvent.Retrying) source.cancel() }
        }.kind)
        assertEquals(1, count.get())
        val limits = ModelCallLimits(overallTimeout = Duration.ofMillis(300), retryBaseDelay = Duration.ofSeconds(1))
        assertFailsWith<ModelProviderException> { provider.generate(request(limits)) {} }
        assertEquals(2, count.get())
    }

    private fun HttpExchange.beginSse() { responseHeaders.set("Content-Type", "text/event-stream; charset=utf-8"); sendResponseHeaders(200, 0) }
    private fun HttpExchange.sse(body: String) { beginSse(); responseBody.write(body.toByteArray()) }
    private fun HttpExchange.reply(status: Int, body: String) { sendResponseHeaders(status, body.toByteArray().size.toLong()); responseBody.write(body.toByteArray()) }

    private fun server(handler: (HttpExchange, Int) -> Unit, test: (ModelProvider, AtomicInteger) -> Unit) {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 4)
        val executor = Executors.newVirtualThreadPerTaskExecutor()
        val requests = AtomicInteger()
        val failures = ConcurrentLinkedQueue<Throwable>()
        server.executor = executor
        server.createContext("/") { exchange ->
            try { handler(exchange, requests.incrementAndGet()) }
            catch (failure: Throwable) { if (failure !is java.io.IOException) failures.add(failure) }
            finally { exchange.close() }
        }
        server.start()
        try {
            val configuration = OpenAiCompatibleConfiguration("http://127.0.0.1:${server.address.port}/v1", "fixture-model", key,
                allowLoopbackHttp = true)
            test(OpenAiCompatibleModelProvider(configuration), requests)
            failures.peek()?.let { throw AssertionError("Fixture server failed", it) }
        } finally { server.stop(0); executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)) }
    }
}
