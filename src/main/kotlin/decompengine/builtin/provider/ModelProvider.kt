package decompengine.builtin.provider

import decompengine.agent.AgentCancellation
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.time.Duration
import java.util.Collections

const val MODEL_PROVIDER_CONTRACT_VERSION = 1

enum class ModelRole { SYSTEM, USER, ASSISTANT, TOOL }
enum class ModelFinishReason { STOP, TOOL_CALLS, LENGTH, REFUSED }
enum class ModelFailureKind {
    CONFIGURATION, INVALID_REQUEST, AUTHENTICATION, AUTHORIZATION, RATE_LIMIT,
    MODEL_UNAVAILABLE, UNSUPPORTED_FEATURE, TRANSPORT, TIMEOUT, MALFORMED_RESPONSE,
    CANCELLED, RESOURCE_EXHAUSTED, SECRET_EXPOSURE,
}

/** Diagnostic messages and exception causes never contain wire bodies, URLs or credentials. */
class ModelProviderException(
    val kind: ModelFailureKind,
    val retryable: Boolean = false,
    val httpStatus: Int? = null,
) : RuntimeException("Model provider: ${kind.name.lowercase()}" + (httpStatus?.let { " (HTTP $it)" } ?: ""))

class ModelToolDefinition(val name: String, val description: String, parameters: JsonObject) {
    val parameters = Json.parseToJsonElement(parameters.toString()) as JsonObject
    init {
        require(name.matches(Regex("[A-Za-z_][A-Za-z0-9_-]{0,63}"))) { "Invalid tool name" }
        require(this.parameters["type"]?.toString() == "\"object\"") { "Tool parameters must be an object schema" }
    }
    override fun toString() = "ModelToolDefinition(redacted)"
}

class ModelToolCall(val id: String, val name: String, arguments: JsonObject) {
    val arguments = Json.parseToJsonElement(arguments.toString()) as JsonObject
    init {
        require(id.matches(Regex("[A-Za-z0-9_-]{1,128}"))) { "Invalid tool call id" }
        require(name.matches(Regex("[A-Za-z_][A-Za-z0-9_-]{0,63}"))) { "Invalid tool call name" }
    }
    override fun toString() = "ModelToolCall(redacted)"
}

class ModelMessage(
    val role: ModelRole,
    val content: String,
    toolCalls: List<ModelToolCall> = emptyList(),
    val toolCallId: String? = null,
) {
    val toolCalls: List<ModelToolCall> = Collections.unmodifiableList(ArrayList(toolCalls))
    init {
        require((role == ModelRole.TOOL) == (toolCallId != null)) { "Tool results require a call id" }
        require(this.toolCalls.isEmpty() || role == ModelRole.ASSISTANT) { "Only assistant messages carry calls" }
    }
    override fun toString() = "ModelMessage(role=$role, content=redacted)"
}

data class ModelCallLimits(
    val connectTimeout: Duration = Duration.ofSeconds(10),
    val requestTimeout: Duration = Duration.ofSeconds(60),
    val streamIdleTimeout: Duration = Duration.ofSeconds(30),
    val overallTimeout: Duration = Duration.ofMinutes(3),
    val maxRequestBytes: Int = 2 * 1024 * 1024,
    val maxResponseBytes: Int = 4 * 1024 * 1024,
    val maxEventBytes: Int = 256 * 1024,
    val maxToolCalls: Int = 32,
    val maxOutputTokens: Int = 8192,
    val maxRetries: Int = 2,
    val retryBaseDelay: Duration = Duration.ofMillis(200),
    val maxRetryDelay: Duration = Duration.ofSeconds(10),
) {
    init {
        listOf(connectTimeout, requestTimeout, streamIdleTimeout, overallTimeout, retryBaseDelay, maxRetryDelay).forEach {
            require(!it.isNegative && !it.isZero && it <= Duration.ofDays(1)) { "Invalid provider timeout" }
        }
        require(maxRequestBytes in 1..64 * 1024 * 1024 && maxResponseBytes in 1..64 * 1024 * 1024)
        require(maxEventBytes in 1..maxResponseBytes && maxToolCalls in 1..1024 && maxOutputTokens > 0)
        require(maxRetries in 0..10 && retryBaseDelay <= maxRetryDelay)
    }
}

class ModelRequest(
    messages: List<ModelMessage>,
    tools: List<ModelToolDefinition> = emptyList(),
    val limits: ModelCallLimits = ModelCallLimits(),
    val cancellation: AgentCancellation = AgentCancellation.NONE,
    secrets: Collection<String> = emptyList(),
) {
    val schemaVersion = MODEL_PROVIDER_CONTRACT_VERSION
    val messages: List<ModelMessage> = Collections.unmodifiableList(ArrayList(messages))
    val tools: List<ModelToolDefinition> = Collections.unmodifiableList(ArrayList(tools))
    internal val secrets: List<String> = Collections.unmodifiableList(secrets.filter { it.isNotEmpty() }.distinct())
    init {
        require(this.messages.isNotEmpty()) { "Model request requires messages" }
        require(this.tools.map { it.name }.distinct().size == this.tools.size) { "Duplicate model tool" }
    }
    override fun toString() = "ModelRequest(schemaVersion=$schemaVersion, content=redacted)"
}

data class ModelUsage(val inputTokens: Long, val outputTokens: Long, val estimated: Boolean) {
    init { require(inputTokens >= 0 && outputTokens >= 0) }
}

sealed interface ModelEvent {
    class TextDelta(val text: String) : ModelEvent { override fun toString() = "TextDelta(redacted)" }
    class ToolCall(val call: ModelToolCall) : ModelEvent { override fun toString() = "ToolCall(redacted)" }
    data class Usage(val usage: ModelUsage) : ModelEvent
    data class Finished(val reason: ModelFinishReason) : ModelEvent
    data class Retrying(val attempt: Int, val kind: ModelFailureKind, val delay: Duration) : ModelEvent
}

class ModelResponse(
    val text: String,
    toolCalls: List<ModelToolCall>,
    val finishReason: ModelFinishReason,
    val usage: ModelUsage,
    val attempts: Int,
) {
    val toolCalls: List<ModelToolCall> = Collections.unmodifiableList(ArrayList(toolCalls))
    override fun toString() = "ModelResponse(finishReason=$finishReason, content=redacted)"
}

/** A response proposes actions. It never authorizes tools or accepts a workspace revision. */
fun interface ModelProvider {
    fun generate(request: ModelRequest, onEvent: (ModelEvent) -> Unit): ModelResponse
}
