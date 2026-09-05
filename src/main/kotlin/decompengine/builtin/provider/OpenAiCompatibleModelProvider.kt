package decompengine.builtin.provider

import kotlinx.serialization.json.*
import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.time.Duration
import java.time.Instant
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.*
import kotlin.random.Random

/** Credentials are private runtime configuration, never part of a workflow request or diagnostic. */
class OpenAiCompatibleConfiguration(
    baseUrl: String,
    internal val model: String,
    internal val apiKey: String,
    internal val supportsTools: Boolean = true,
    allowLoopbackHttp: Boolean = false,
) {
    internal val endpoint: URI
    init {
        endpoint = try {
            val uri = URI(baseUrl)
            require(uri.scheme == "https" || (allowLoopbackHttp && uri.scheme == "http" &&
                uri.host in setOf("127.0.0.1", "[::1]")))
            require(!uri.host.isNullOrBlank() && uri.userInfo == null && uri.query == null && uri.fragment == null)
            require(uri.port == -1 || uri.port in 1..65535)
            require(model.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")))
            require(apiKey.isNotBlank() && apiKey.length <= 8192 && apiKey.all { it.code in 33..126 })
            URI(baseUrl.trimEnd('/') + "/chat/completions")
        } catch (_: Exception) { throw ModelProviderException(ModelFailureKind.CONFIGURATION) }
    }
    override fun toString() = "OpenAiCompatibleConfiguration(redacted)"
}

/** Streaming Chat Completions is confined to this adapter; the harness sees ModelProvider v1. */
class OpenAiCompatibleModelProvider(private val configuration: OpenAiCompatibleConfiguration) : ModelProvider {
    override fun generate(request: ModelRequest, onEvent: (ModelEvent) -> Unit): ModelResponse {
        val limits = request.limits
        val deadline = System.nanoTime() + limits.overallTimeout.toNanos()
        checkActive(request, deadline)
        if (request.tools.isNotEmpty() && !configuration.supportsTools) fail(ModelFailureKind.UNSUPPORTED_FEATURE)
        val body = encode(request)
        if (body.size > limits.maxRequestBytes) fail(ModelFailureKind.RESOURCE_EXHAUSTED)
        val secrets = (request.secrets + configuration.apiKey).distinct().sortedByDescending { it.length }
        HttpClient.newBuilder().connectTimeout(limits.connectTimeout).followRedirects(HttpClient.Redirect.NEVER)
            .build().use { client ->
                for (attempt in 1..limits.maxRetries + 1) {
                    checkActive(request, deadline)
                    val attemptDeadline = minOf(deadline, System.nanoTime() + limits.requestTimeout.toNanos())
                    val wire = HttpRequest.newBuilder(configuration.endpoint)
                        .header("Authorization", "Bearer ${configuration.apiKey}")
                        .header("Content-Type", "application/json").header("Accept", "text/event-stream")
                        .timeout(minOf(limits.requestTimeout, remaining(deadline)))
                        .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build()
                    val stream = BoundedBody(limits.maxResponseBytes)
                    val exchange = try { client.sendAsync(wire) { stream } }
                    catch (_: Exception) { fail(ModelFailureKind.TRANSPORT) }
                    try {
                        val response = await(exchange, request, attemptDeadline)
                        val status = response.statusCode()
                        if (status != 200) {
                            val kind = when (status) {
                                401 -> ModelFailureKind.AUTHENTICATION
                                403 -> ModelFailureKind.AUTHORIZATION
                                404 -> ModelFailureKind.MODEL_UNAVAILABLE
                                408, 504 -> ModelFailureKind.TIMEOUT
                                429 -> ModelFailureKind.RATE_LIMIT
                                400, 422 -> ModelFailureKind.INVALID_REQUEST
                                501 -> ModelFailureKind.UNSUPPORTED_FEATURE
                                else -> ModelFailureKind.TRANSPORT
                            }
                            val transient = status in setOf(408, 429, 500, 502, 503, 504)
                            stream.close() // Never consume or retain error bodies, even when they echo secrets.
                            if (!transient || attempt > limits.maxRetries) {
                                throw ModelProviderException(kind, transient, status)
                            }
                            val guidance = response.headers().firstValue("Retry-After").orElse(null)
                            val delay = retryDelay(guidance, attempt, limits)
                            if (delay >= remaining(deadline)) throw ModelProviderException(kind, true, status)
                            onEvent(ModelEvent.Retrying(attempt, kind, delay))
                            pause(delay, request, deadline)
                            continue
                        }
                        if (response.headers().firstValue("Content-Type").orElse("").substringBefore(';').trim()
                            .lowercase() != "text/event-stream") fail(ModelFailureKind.MALFORMED_RESPONSE)
                        return decode(stream, request, attemptDeadline, body.size, secrets, attempt, onEvent)
                    } finally {
                        // Own the subscriber before headers arrive, including cancellation races.
                        stream.close()
                        if (!exchange.isDone) exchange.cancel(true)
                    }
                }
            }
        error("Unreachable provider retry state")
    }

    private fun encode(request: ModelRequest): ByteArray = boundedProviderJson(request.limits.maxRequestBytes) { json ->
        json.writeStartObject()
        json.writeStringField("model", configuration.model)
        json.writeBooleanField("stream", true)
        json.writeBooleanField("store", false)
        json.writeNumberField("max_completion_tokens", request.limits.maxOutputTokens)
        json.writeObjectFieldStart("stream_options"); json.writeBooleanField("include_usage", true); json.writeEndObject()
        json.writeArrayFieldStart("messages")
        request.messages.forEach { message ->
            json.writeStartObject()
            json.writeStringField("role", message.role.name.lowercase())
            json.writeStringField("content", message.content)
            message.toolCallId?.let { json.writeStringField("tool_call_id", it) }
            if (message.toolCalls.isNotEmpty()) {
                json.writeArrayFieldStart("tool_calls")
                message.toolCalls.forEach { call ->
                    json.writeStartObject()
                    json.writeStringField("id", call.id); json.writeStringField("type", "function")
                    json.writeObjectFieldStart("function")
                    json.writeStringField("name", call.name)
                    val arguments = boundedProviderJson(request.limits.maxRequestBytes) { it.writeProviderValue(call.arguments) }
                    json.writeStringField("arguments", arguments.decodeToString())
                    json.writeEndObject(); json.writeEndObject()
                }
                json.writeEndArray()
            }
            json.writeEndObject()
        }
        json.writeEndArray()
        if (request.tools.isNotEmpty()) {
            json.writeArrayFieldStart("tools")
            request.tools.forEach { tool ->
                json.writeStartObject(); json.writeStringField("type", "function")
                json.writeObjectFieldStart("function")
                json.writeStringField("name", tool.name); json.writeStringField("description", tool.description)
                json.writeFieldName("parameters"); json.writeProviderValue(tool.parameters)
                json.writeEndObject(); json.writeEndObject()
            }
            json.writeEndArray()
        }
        json.writeEndObject()
    }

    private fun decode(
        stream: BoundedBody, request: ModelRequest, deadline: Long, inputBytes: Int,
        secrets: List<String>, attempt: Int, onEvent: (ModelEvent) -> Unit,
    ): ModelResponse {
        val limits = request.limits
        val text = StringBuilder()
        val redactor = StreamingRedactor(secrets) { delta ->
            if (delta.isNotEmpty()) { text.append(delta); onEvent(ModelEvent.TextDelta(delta)) }
        }
        val tools = sortedMapOf<Int, PartialTool>()
        var finish: ModelFinishReason? = null
        var usage: ModelUsage? = null
        var done = false
        var outputBytes = 0L
        val parser = SseParser(limits.maxEventBytes) { payload ->
            checkActive(request, deadline)
            if (done) fail(ModelFailureKind.MALFORMED_RESPONSE)
            if (payload == "[DONE]") {
                if (finish == null) fail(ModelFailureKind.MALFORMED_RESPONSE)
                done = true
            } else {
                val textDeltas = mutableListOf<String>()
                try {
                val chunk = parseProviderObject(payload, limits.maxEventBytes)
                if ("error" in chunk) fail(ModelFailureKind.MALFORMED_RESPONSE)
                chunk["usage"]?.takeUnless { it == JsonNull }?.jsonObject?.let {
                    if (usage != null) fail(ModelFailureKind.MALFORMED_RESPONSE)
                    usage = ModelUsage(it.getValue("prompt_tokens").jsonPrimitive.long,
                        it.getValue("completion_tokens").jsonPrimitive.long, false)
                }
                val choices = chunk.getValue("choices").jsonArray
                if (choices.size > 1 || (choices.isEmpty() && usage == null)) fail(ModelFailureKind.MALFORMED_RESPONSE)
                choices.singleOrNull()?.jsonObject?.let { choice ->
                    if (choice.getValue("index").jsonPrimitive.int != 0 || finish != null) fail(ModelFailureKind.MALFORMED_RESPONSE)
                    val delta = choice.getValue("delta").jsonObject
                    delta["role"]?.let { if (it.jsonPrimitive.content != "assistant") fail(ModelFailureKind.MALFORMED_RESPONSE) }
                    delta["content"]?.takeUnless { it == JsonNull }?.let {
                        val value = it.jsonPrimitive.also { p -> require(p.isString) }.content
                        outputBytes += value.toByteArray().size
                        textDeltas += value
                    }
                    delta["refusal"]?.takeUnless { it == JsonNull }?.let {
                        val value = it.jsonPrimitive.also { p -> require(p.isString) }.content
                        outputBytes += value.toByteArray().size
                        textDeltas += value
                    }
                    if ("function_call" in delta) fail(ModelFailureKind.UNSUPPORTED_FEATURE)
                    delta["tool_calls"]?.jsonArray?.forEach { element ->
                        val call = element.jsonObject
                        val index = call.getValue("index").jsonPrimitive.int
                        require(index in 0 until limits.maxToolCalls)
                        val partial = tools.getOrPut(index) { PartialTool() }
                        call["id"]?.let { require(partial.id == null); partial.id = it.jsonPrimitive.content }
                        call["type"]?.let { require(it.jsonPrimitive.content == "function") }
                        call["function"]?.jsonObject?.let { function ->
                            function["name"]?.let { partial.name.append(it.jsonPrimitive.content) }
                            function["arguments"]?.let {
                                val value = it.jsonPrimitive.also { p -> require(p.isString) }.content
                                outputBytes += value.toByteArray().size
                                partial.arguments.append(value)
                            }
                        }
                    }
                    choice["finish_reason"]?.takeUnless { it == JsonNull }?.let {
                        finish = when (it.jsonPrimitive.content) {
                            "stop" -> ModelFinishReason.STOP
                            "tool_calls" -> ModelFinishReason.TOOL_CALLS
                            "length" -> ModelFinishReason.LENGTH
                            "content_filter" -> ModelFinishReason.REFUSED
                            else -> fail(ModelFailureKind.UNSUPPORTED_FEATURE)
                        }
                    }
                }
            } catch (failure: ModelProviderException) { throw failure }
            catch (_: Exception) { fail(ModelFailureKind.MALFORMED_RESPONSE) }
                // Consumer cancellation/budget exceptions are not malformed provider JSON.
                textDeltas.forEach(redactor::append)
            }
        }
        while (!done) {
            checkActive(request, deadline)
            val bytes = stream.next(request, deadline, limits.streamIdleTimeout) ?: break
            parser.accept(bytes)
        }
        if (!done || finish == null) fail(ModelFailureKind.MALFORMED_RESPONSE)
        redactor.finish()
        val calls = try { tools.values.map { tool ->
            val call = ModelToolCall(requireNotNull(tool.id), tool.name.toString(),
                parseProviderObject(tool.arguments.toString(), limits.maxResponseBytes))
            require(request.tools.any { it.name == call.name })
            if (secrets.any { secret -> containsSecret(call.arguments, secret) || call.id.contains(secret) || call.name.contains(secret) }) {
                fail(ModelFailureKind.SECRET_EXPOSURE)
            }
            call
        } } catch (failure: ModelProviderException) { throw failure }
        catch (_: Exception) { fail(ModelFailureKind.MALFORMED_RESPONSE) }
        if (calls.map { it.id }.distinct().size != calls.size ||
            (finish == ModelFinishReason.TOOL_CALLS) != calls.isNotEmpty()) fail(ModelFailureKind.MALFORMED_RESPONSE)
        // Unknown tokenizers use one UTF-8 byte per token as a conservative measured equivalent.
        val measured = usage ?: ModelUsage(inputBytes.toLong(), outputBytes, true)
        if (measured.outputTokens > limits.maxOutputTokens) fail(ModelFailureKind.RESOURCE_EXHAUSTED)
        calls.forEach { onEvent(ModelEvent.ToolCall(it)) }
        onEvent(ModelEvent.Usage(measured))
        onEvent(ModelEvent.Finished(finish))
        return ModelResponse(text.toString(), calls, finish, measured, attempt)
    }

    private class PartialTool {
        var id: String? = null
        val name = StringBuilder()
        val arguments = StringBuilder()
    }

    private fun containsSecret(value: JsonElement, secret: String): Boolean = when (value) {
        is JsonObject -> value.any { (key, item) -> key.contains(secret) || containsSecret(item, secret) }
        is JsonArray -> value.any { containsSecret(it, secret) }
        is JsonPrimitive -> value.content.contains(secret)
    }
}

private fun fail(kind: ModelFailureKind): Nothing = throw ModelProviderException(kind)
private fun remaining(deadline: Long): Duration = Duration.ofNanos(maxOf(1, deadline - System.nanoTime()))
private fun checkActive(request: ModelRequest, deadline: Long) {
    if (request.cancellation.isCancellationRequested() || Thread.currentThread().isInterrupted) fail(ModelFailureKind.CANCELLED)
    if (System.nanoTime() >= deadline) fail(ModelFailureKind.TIMEOUT)
}

private fun <T> await(future: CompletableFuture<T>, request: ModelRequest, deadline: Long): T {
    while (true) {
        checkActive(request, deadline)
        try { return future.get(minOf(25_000_000, remaining(deadline).toNanos()), TimeUnit.NANOSECONDS) }
        catch (_: TimeoutException) { continue }
        catch (_: InterruptedException) { Thread.currentThread().interrupt(); fail(ModelFailureKind.CANCELLED) }
        catch (failure: ExecutionException) {
            fail(if (failure.cause is java.net.http.HttpTimeoutException) ModelFailureKind.TIMEOUT else ModelFailureKind.TRANSPORT)
        }
    }
}

private fun pause(delay: Duration, request: ModelRequest, deadline: Long) {
    val end = System.nanoTime() + delay.toNanos()
    while (System.nanoTime() < end) {
        checkActive(request, deadline)
        try { TimeUnit.NANOSECONDS.sleep(minOf(25_000_000, maxOf(1, end - System.nanoTime()))) }
        catch (_: InterruptedException) { Thread.currentThread().interrupt(); fail(ModelFailureKind.CANCELLED) }
    }
}

private fun retryDelay(header: String?, attempt: Int, limits: ModelCallLimits): Duration {
    val guidance = header?.let {
        it.toLongOrNull()?.takeIf { seconds -> seconds >= 0 && seconds <= 86400 }?.let(Duration::ofSeconds)
            ?: runCatching { Duration.between(Instant.now(), ZonedDateTime.parse(it, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant()) }
                .getOrNull()?.takeIf { duration -> !duration.isNegative }
    }
    // Never retry earlier than provider guidance; an excessive delay stops this call instead.
    if (guidance != null && guidance > limits.maxRetryDelay) throw ModelProviderException(ModelFailureKind.RATE_LIMIT, true)
    val ceiling = minOf(limits.maxRetryDelay.toNanos(), limits.retryBaseDelay.toNanos() * (1L shl (attempt - 1)))
    return maxOf(guidance ?: Duration.ZERO, Duration.ofNanos(Random.nextLong(ceiling / 2, ceiling + 1)))
}

/** One demanded body batch, plus a terminal signal; no unbounded read thread or publisher queue. */
private class BoundedBody(private val limit: Int) : HttpResponse.BodySubscriber<BoundedBody>, AutoCloseable {
    private val queue = ArrayBlockingQueue<Any>(2)
    @Volatile private var subscription: Flow.Subscription? = null
    @Volatile private var closed = false
    private var total = 0L
    override fun getBody(): CompletionStage<BoundedBody> = CompletableFuture.completedFuture(this)
    override fun onSubscribe(value: Flow.Subscription) {
        subscription = value
        if (closed) value.cancel() else value.request(1)
    }
    override fun onNext(item: List<ByteBuffer>) {
        val size = item.sumOf { it.remaining().toLong() }
        total += size
        if (total > limit) { queue.offer(ModelFailureKind.RESOURCE_EXHAUSTED); close(); return }
        val bytes = ByteArray(size.toInt())
        var offset = 0
        item.forEach { buffer -> val length = buffer.remaining(); buffer.get(bytes, offset, length); offset += length }
        if (!queue.offer(bytes)) { queue.clear(); queue.offer(ModelFailureKind.RESOURCE_EXHAUSTED); close() }
    }
    override fun onError(throwable: Throwable) { queue.offer(ModelFailureKind.TRANSPORT) }
    override fun onComplete() { queue.offer(Unit) }
    fun next(request: ModelRequest, deadline: Long, idle: Duration): ByteArray? {
        val idleDeadline = System.nanoTime() + idle.toNanos()
        while (true) {
            checkActive(request, minOf(deadline, idleDeadline))
            val item = try { queue.poll(25, TimeUnit.MILLISECONDS) }
            catch (_: InterruptedException) { Thread.currentThread().interrupt(); fail(ModelFailureKind.CANCELLED) }
            when (item) {
                null -> continue
                is ByteArray -> { subscription?.request(1); return item }
                is ModelFailureKind -> fail(item)
                else -> return null
            }
        }
    }
    override fun close() { closed = true; subscription?.cancel() }
}

private class SseParser(private val limit: Int, private val event: (String) -> Unit) {
    private val line = ByteArrayOutputStream()
    private val data = StringBuilder()
    private var eventBytes = 0
    fun accept(bytes: ByteArray) {
        for (byte in bytes) {
            if (++eventBytes > limit) fail(ModelFailureKind.RESOURCE_EXHAUSTED)
            if (byte == 10.toByte()) {
                val value = try { Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(line.toByteArray())).toString().removeSuffix("\r") }
                catch (_: Exception) { fail(ModelFailureKind.MALFORMED_RESPONSE) }
                line.reset()
                if (value.isEmpty()) {
                    if (data.isNotEmpty()) event(data.toString().removeSuffix("\n"))
                    data.setLength(0); eventBytes = 0
                } else if (value.startsWith("data:")) data.append(value.substring(5).removePrefix(" ")).append('\n')
                else if (!value.startsWith(":")) fail(ModelFailureKind.MALFORMED_RESPONSE)
            } else line.write(byte.toInt())
        }
    }
}

/** Holds only suffixes that could become a secret across chunk boundaries. */
internal class StreamingRedactor(private val secrets: List<String>, private val emit: (String) -> Unit) {
    private var pending = ""
    fun append(value: String) { pending += value; drain(false) }
    fun finish() = drain(true)
    private fun drain(final: Boolean) {
        val output = StringBuilder()
        var offset = 0
        while (offset < pending.length) {
            val match = secrets.firstOrNull { pending.startsWith(it, offset) }
            if (match != null) { output.append("[REDACTED]"); offset += match.length }
            else if (!final && secrets.any { it.length > pending.length - offset &&
                    it.regionMatches(0, pending, offset, pending.length - offset) }) break
            else { output.append(pending[offset]); offset++ }
        }
        pending = pending.substring(offset)
        emit(output.toString())
    }
}
