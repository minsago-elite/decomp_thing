package decompengine.repair

import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionLimits
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.chatgpt.ChatGptPlanAccount
import decompengine.chatgpt.ChatGptPlanAuthenticationException
import decompengine.chatgpt.ChatGptPlanCredentialStore
import decompengine.chatgpt.ChatGptPlanOAuth
import decompengine.project.sha256
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

data class ChatGptPlanModel(val slug: String, val displayName: String)

/** Direct local SIWC Responses API adapter for the existing captured-repair contract. */
class ChatGptPlanRepairClient(
    private val store: ChatGptPlanCredentialStore = ChatGptPlanCredentialStore.default(),
    private val oauth: ChatGptPlanOAuth = ChatGptPlanOAuth(store),
    private val profileId: String? = System.getenv()["DECOMP_CHATGPT_PROFILE"]?.takeIf(String::isNotBlank),
    private val httpClient: HttpClient = defaultHttpClient(),
    private val bodyExecutor: Executor = HTTP_BODY_EXECUTOR,
) : RepairClient {
    override fun modelIdentifier(): String? = selectedAccount()?.model

    fun listModels(): List<ChatGptPlanModel> {
        var models: List<ChatGptPlanModel>? = null
        store.withFreshAccessToken(profileId, refresh = oauth::refreshTokens) { account ->
            requirePlanScope(account)
            val request = HttpRequest.newBuilder(MODELS_ENDPOINT)
                .timeout(MODEL_LIST_TIMEOUT)
                .header("Authorization", "Bearer ${account.accessToken}")
                .header("Accept", "application/json")
                .GET()
                .build()
            val response = try { httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream()) }
            catch (failure: Exception) {
                throw AgentExecutionException(
                    AgentFailure(AgentFailureKind.TRANSPORT, "ChatGPT model catalog request failed", retryable = true),
                    failure,
                )
            }
            val body = response.body().use { readCapped(it, MAXIMUM_MODEL_CATALOG_BYTES) }
            if (response.statusCode() !in 200..299) {
                throw providerFailure("ChatGPT model catalog request", response.statusCode(), body)
            }
            val root = parseJson(decodeUtf8(body), "ChatGPT model catalog")
            val rows = runCatching { root.jsonObject.getValue("models").jsonArray }
                .getOrElse { fail(AgentFailureKind.PROTOCOL, "ChatGPT model catalog did not contain a models array") }
            models = rows.mapNotNull { element ->
                val row = element.jsonObject
                val slug = row["slug"]?.jsonPrimitive?.contentOrNull ?: return@mapNotNull null
                if (row["visibility"]?.jsonPrimitive?.contentOrNull != "list") return@mapNotNull null
                val name = row["display_name"]?.jsonPrimitive?.contentOrNull ?: slug
                if (!slug.matches(MODEL_ID_PATTERN) || name.isBlank() || name.length > MAXIMUM_MODEL_NAME_BYTES) {
                    fail(AgentFailureKind.PROTOCOL, "ChatGPT model catalog contained an invalid model entry")
                }
                ChatGptPlanModel(slug, name)
            }
        }
        return models ?: emptyList()
    }

    fun selectModel(slug: String) {
        val available = listModels()
        if (available.none { it.slug == slug }) {
            throw AgentExecutionException(
                AgentFailure(AgentFailureKind.CONFIGURATION, "selected model is not visible in this ChatGPT account's model catalog"),
            )
        }
        store.setModel(profileId, slug)
    }

    override fun requestRepair(request: RepairRequest): RepairResponse = requestRepair(
        request,
        RepairClientInvocation(RepairResourceBudget(), AgentExecutionLimits(), AgentCancellation.NONE),
    )

    override fun requestRepair(request: RepairRequest, invocation: RepairClientInvocation): RepairResponse {
        requireNotCancelled(invocation.cancellation, null)
        val account = selectedAccount()
            ?: throw AgentExecutionException(AgentFailure(AgentFailureKind.CONFIGURATION, "Sign in with ChatGPT first: run llm_bin_patch chatgpt login."))
        if (!account.canUseChatGptPlan) {
            throw AgentExecutionException(
                AgentFailure(AgentFailureKind.AUTHENTICATION, "This ChatGPT registration did not grant chatgpt.tokens.use.direct."),
            )
        }
        val model = account.model
            ?: throw AgentExecutionException(AgentFailure(AgentFailureKind.CONFIGURATION, "Select an account-available model with llm_bin_patch chatgpt models --select <slug>."))
        val body = encodeRequestBody(request, invocation.budget, model)
        val deadline = deadlineAfter(invocation.limits.wallClockTimeout)
        var result: RepairResponse? = null
        store.withFreshAccessToken(profileId, refresh = oauth::refreshTokens) { freshAccount ->
            requirePlanScope(freshAccount)
            val httpRequest = HttpRequest.newBuilder(RESPONSES_ENDPOINT)
                .timeout(invocation.limits.wallClockTimeout)
                .header("Authorization", "Bearer ${freshAccount.accessToken}")
                .header("Content-Type", "application/json")
                .header("Accept", "text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build()
            val exchange = try {
                httpClient.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofInputStream())
            } catch (failure: Exception) {
                throw AgentExecutionException(AgentFailure(AgentFailureKind.TRANSPORT, "could not start ChatGPT Responses request", retryable = true), failure)
            }
            val response = await(exchange, deadline, invocation.cancellation)
            if (response.statusCode() !in 200..299) {
                val error = readBodyAsync(response.body(), ERROR_BODY_BYTES, deadline, invocation.cancellation, exchange)
                throw providerFailure("ChatGPT Responses request", response.statusCode(), error)
            }
            val contentType = response.headers().firstValue("Content-Type").orElse("")
            if (!contentType.lowercase().startsWith("text/event-stream")) {
                response.body().close()
                throw AgentExecutionException(AgentFailure(AgentFailureKind.PROTOCOL, "ChatGPT Responses request did not return an event stream"))
            }
            val text = readEventStreamAsync(
                response.body(),
                minOf(invocation.limits.maxOutputBytes, invocation.budget.maximumResponseBytes),
                deadline,
                invocation.cancellation,
                exchange,
            )
            result = parseRepairResponse(text, invocation)
        }
        return result ?: throw AgentExecutionException(AgentFailure(AgentFailureKind.PROTOCOL, "ChatGPT Responses stream was empty"))
    }

    private fun selectedAccount(): ChatGptPlanAccount? = profileId?.let(store::account) ?: store.activeAccount()

    private fun requirePlanScope(account: ChatGptPlanAccount) {
        if (!account.canUseChatGptPlan) {
            throw AgentExecutionException(
                AgentFailure(AgentFailureKind.AUTHENTICATION, "This ChatGPT registration did not grant chatgpt.tokens.use.direct."),
            )
        }
    }

    private fun encodeRequestBody(request: RepairRequest, budget: RepairResourceBudget, model: String): ByteArray {
        if (request.projectFiles.size > budget.maximumContextFiles) {
            throw RepairBudgetExceededException("ChatGPT request has too many project files")
        }
        if (request.regressionInputs.size > budget.maximumRegressionInputs) {
            throw RepairBudgetExceededException("ChatGPT request has too many regression inputs")
        }
        if (request.regressionInputs.sumOf { it.args.size.toLong() } > budget.maximumRegressionArguments) {
            throw RepairBudgetExceededException("ChatGPT request has too many regression arguments")
        }
        val prompt = buildString {
            append("Failure kind: ").append(request.failureKind)
            append("\n\nFailure details:\n").append(request.prompt)
            append("\n\nRegression inputs:\n")
            request.regressionInputs.forEach { input ->
                append("- ").append(input.id).append(": args=[")
                append(input.args.joinToString(", "))
                append("] stdinHex=").append(input.stdin.toLowerHex()).append('\n')
            }
            append("\nProject files:\n")
            request.projectFiles.toSortedMap().forEach { (path, content) ->
                append("### ").append(path).append("\n").append(content).append("\n\n")
            }
        }
        val body = BoundedUtf8JsonBody(budget.maximumRequestBytes)
        body.appendAscii("{\"model\":")
        body.appendJsonString(model)
        body.appendAscii(",\"instructions\":")
        body.appendJsonString(
            "Return source patches as JSON with summary and patches. Each patch must have relativePath and replacement. " +
                "Do not include markdown fences or paths outside the provided project files.",
        )
        body.appendAscii(",\"input\":[{\"role\":\"user\",\"content\":")
        body.appendJsonString(prompt)
        body.appendAscii("}],\"store\":false,\"stream\":true}")
        return body.toByteArray()
    }

    private fun parseRepairResponse(content: String, invocation: RepairClientInvocation): RepairResponse {
        val normalized = content.trim().removePrefix("```json").removePrefix("```").removeSuffix("```").trim()
        val response = runCatching { Json.parseToJsonElement(normalized).jsonObject }
            .getOrElse { throw AgentExecutionException(AgentFailure(AgentFailureKind.PROTOCOL, "ChatGPT response was not valid patch JSON"), it) }
        val summary = response["summary"]?.jsonPrimitive?.contentOrNull?.ifBlank { null } ?: "ChatGPT plan repair response"
        val patchElements = response["patches"]?.jsonArray.orEmpty()
        if (patchElements.isEmpty() || patchElements.size > invocation.budget.maximumPatchFiles) {
            throw AgentExecutionException(AgentFailure(AgentFailureKind.PROTOCOL, "ChatGPT response did not include an acceptable patch set"))
        }
        var totalBytes = 0L
        val patches = patchElements.map { value ->
            val patch = value.jsonObject
            val relativePath = patch["relativePath"]?.jsonPrimitive?.contentOrNull
                ?: throw AgentExecutionException(AgentFailure(AgentFailureKind.PROTOCOL, "ChatGPT patch omitted relativePath"))
            val replacement = patch["replacement"]?.jsonPrimitive?.contentOrNull
                ?: throw AgentExecutionException(AgentFailure(AgentFailureKind.PROTOCOL, "ChatGPT patch omitted replacement"))
            val bytes = replacement.toByteArray(StandardCharsets.UTF_8).size.toLong()
            if (bytes > invocation.budget.maximumSourceFileBytes) throw RepairBudgetExceededException("ChatGPT patch file exceeds its source-size limit")
            totalBytes = Math.addExact(totalBytes, bytes)
            if (totalBytes > invocation.budget.maximumPatchBytes) throw RepairBudgetExceededException("ChatGPT patch set exceeds its byte limit")
            SourcePatch(relativePath, replacement)
        }
        if (patches.map(SourcePatch::relativePath).distinct().size != patches.size) {
            throw AgentExecutionException(AgentFailure(AgentFailureKind.PROTOCOL, "ChatGPT returned duplicate patch paths"))
        }
        return RepairResponse(summary, patches)
    }

    private fun readEventStreamAsync(
        input: InputStream,
        maximumBytes: Long,
        deadline: Long,
        cancellation: AgentCancellation,
        exchange: CompletableFuture<*>,
    ): String = readAsync(input, deadline, cancellation, exchange) { stream ->
        val output = StringBuilder()
        var eventData = StringBuilder()
        var eventType: String? = null
        var receivedCompleted = false
        var bytes = 0L
        fun dispatch() {
            if (eventData.isEmpty()) { eventType = null; return }
            val data = eventData.toString()
            val json = if (data == "[DONE]") null else runCatching { Json.parseToJsonElement(data).jsonObject }.getOrElse {
                throw AgentExecutionException(AgentFailure(AgentFailureKind.PROTOCOL, "ChatGPT Responses stream contained malformed event data"), it)
            }
            val type = eventType ?: json?.get("type")?.jsonPrimitive?.contentOrNull
            when (type) {
                "response.output_text.delta" -> {
                    val delta = json?.get("delta")?.jsonPrimitive?.contentOrNull
                        ?: throw AgentExecutionException(AgentFailure(AgentFailureKind.PROTOCOL, "ChatGPT text event omitted its delta"))
                    bytes += delta.toByteArray(StandardCharsets.UTF_8).size
                    if (bytes > maximumBytes) throw AgentExecutionException(AgentFailure(AgentFailureKind.RESOURCE_EXHAUSTED, "ChatGPT response exceeded its output limit"))
                    output.append(delta)
                }
                "response.completed" -> receivedCompleted = true
                "response.failed", "error" -> {
                    val code = json?.get("response")?.jsonObject?.get("error")?.jsonObject?.get("code")?.jsonPrimitive?.contentOrNull
                    throw AgentExecutionException(AgentFailure(AgentFailureKind.TRANSPORT, "ChatGPT Responses request failed${code?.let { ": $it" }.orEmpty()}"))
                }
            }
            eventData = StringBuilder()
            eventType = null
        }
        while (true) {
            val line = readBoundedLine(stream, MAXIMUM_SSE_LINE_BYTES) ?: break
            if (line.isEmpty()) dispatch()
            else if (line.startsWith("data:")) {
                if (eventData.isNotEmpty()) eventData.append('\n')
                eventData.append(line.removePrefix("data:").removePrefix(" "))
                if (eventData.length > MAXIMUM_SSE_EVENT_BYTES) throw AgentExecutionException(AgentFailure(AgentFailureKind.RESOURCE_EXHAUSTED, "ChatGPT Responses event exceeded its size limit"))
            } else if (line.startsWith("event:")) {
                eventType = line.removePrefix("event:").trim().take(MAXIMUM_SSE_EVENT_NAME_BYTES)
            }
        }
        dispatch()
        if (!receivedCompleted) {
            throw AgentExecutionException(AgentFailure(AgentFailureKind.PROTOCOL, "ChatGPT Responses stream ended before response.completed"))
        }
        output.toString()
    }

    private fun <T> readAsync(
        input: InputStream,
        deadline: Long,
        cancellation: AgentCancellation,
        exchange: CompletableFuture<*>,
        action: (InputStream) -> T,
    ): T {
        val reading = CompletableFuture.supplyAsync({ input.use(action) }, bodyExecutor)
        return try { awaitFuture(reading, deadline, cancellation) }
        catch (failure: Throwable) {
            runCatching { input.close() }.onFailure(failure::addSuppressed)
            reading.cancel(true)
            exchange.cancel(true)
            throw failure
        }
    }

    private fun readBodyAsync(
        input: InputStream,
        limit: Long,
        deadline: Long,
        cancellation: AgentCancellation,
        exchange: CompletableFuture<*>,
    ): ByteArray = readAsync(input, deadline, cancellation, exchange) { readCapped(it, limit) }

    private fun readCapped(input: InputStream, maximumBytes: Long): ByteArray {
        val output = ByteArrayOutputStream(minOf(maximumBytes.toInt(), 8192))
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) return output.toByteArray()
            if (output.size().toLong() + count > maximumBytes) {
                val remaining = (maximumBytes - output.size()).coerceAtLeast(0).toInt()
                if (remaining > 0) output.write(buffer, 0, remaining)
                return output.toByteArray()
            }
            output.write(buffer, 0, count)
        }
    }

    private fun readBoundedLine(input: InputStream, maximumBytes: Int): String? {
        val line = ByteArrayOutputStream()
        while (true) {
            val value = input.read()
            if (value < 0) return if (line.size() == 0) null else decodeUtf8(line.toByteArray()).trimEnd('\r')
            if (value == '\n'.code) return decodeUtf8(line.toByteArray()).trimEnd('\r')
            if (line.size() >= maximumBytes) throw AgentExecutionException(AgentFailure(AgentFailureKind.RESOURCE_EXHAUSTED, "ChatGPT Responses stream line exceeded its size limit"))
            line.write(value)
        }
    }

    private fun providerFailure(operation: String, status: Int, body: ByteArray): AgentExecutionException {
        val digest = sha256(body)
        return AgentExecutionException(
            AgentFailure(
                if (status == 401 || status == 403) AgentFailureKind.AUTHENTICATION else AgentFailureKind.TRANSPORT,
                "$operation failed with HTTP $status; response body redacted (prefixSha256=$digest, capturedBytes=${body.size})",
                retryable = status >= 500 || status == 429,
            ),
        )
    }

    private fun await(
        future: CompletableFuture<HttpResponse<InputStream>>,
        deadline: Long,
        cancellation: AgentCancellation,
    ): HttpResponse<InputStream> = awaitFuture(future, deadline, cancellation)

    private fun <T> awaitFuture(future: CompletableFuture<T>, deadline: Long, cancellation: AgentCancellation): T {
        while (true) {
            requireNotCancelled(cancellation, future)
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0) {
                future.cancel(true)
                throw AgentExecutionException(AgentFailure(AgentFailureKind.TIMEOUT, "ChatGPT request exceeded its wall deadline"))
            }
            try { return future.get(minOf(remaining, POLL_NANOS), TimeUnit.NANOSECONDS) }
            catch (_: TimeoutException) { }
            catch (failure: InterruptedException) {
                Thread.currentThread().interrupt()
                future.cancel(true)
                throw AgentExecutionException(AgentFailure(AgentFailureKind.TRANSPORT, "ChatGPT request was interrupted", retryable = true), failure)
            } catch (failure: ExecutionException) {
                val cause = failure.cause ?: failure
                if (cause is AgentExecutionException) throw cause
                throw AgentExecutionException(AgentFailure(AgentFailureKind.TRANSPORT, "ChatGPT request transport failed", retryable = true), cause)
            }
        }
    }

    private fun requireNotCancelled(cancellation: AgentCancellation, future: CompletableFuture<*>?) {
        if (!cancellation.isCancellationRequested()) return
        future?.cancel(true)
        throw RepairTransportCancelledException()
    }

    private fun decodeUtf8(bytes: ByteArray): String = try {
        StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString()
    } catch (failure: Exception) {
        throw AgentExecutionException(AgentFailure(AgentFailureKind.PROTOCOL, "ChatGPT response was not valid UTF-8"), failure)
    }

    private fun parseJson(body: String, label: String) = runCatching { Json.parseToJsonElement(body) }
        .getOrElse { throw AgentExecutionException(AgentFailure(AgentFailureKind.PROTOCOL, "$label was not valid JSON"), it) }

    private fun deadlineAfter(timeout: Duration): Long = runCatching { Math.addExact(System.nanoTime(), timeout.toNanos()) }.getOrDefault(Long.MAX_VALUE)

    private fun fail(kind: AgentFailureKind, message: String): Nothing = throw AgentExecutionException(AgentFailure(kind, message))

    private fun ByteArray.toLowerHex(): String = joinToString("") { "%02x".format(it) }

    companion object {
        private val MODELS_ENDPOINT = URI.create("https://api.openai.com/v1/models")
        private val RESPONSES_ENDPOINT = URI.create("https://api.openai.com/v1/responses")
        private val MODEL_LIST_TIMEOUT = Duration.ofSeconds(30)
        private const val MAXIMUM_MODEL_CATALOG_BYTES = 1024L * 1024L
        private const val MAXIMUM_MODEL_NAME_BYTES = 256
        private const val MAXIMUM_SSE_LINE_BYTES = 64 * 1024
        private const val MAXIMUM_SSE_EVENT_BYTES = 256 * 1024
        private const val MAXIMUM_SSE_EVENT_NAME_BYTES = 128
        private const val ERROR_BODY_BYTES = 8192L
        private const val POLL_NANOS = 25_000_000L
        private val MODEL_ID_PATTERN = Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")
        private val HTTP_BODY_EXECUTOR = Executors.newFixedThreadPool(4) { runnable ->
            Thread(runnable, "chatgpt-plan-stream").apply { isDaemon = true }
        }
        private fun defaultHttpClient() = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build()
    }
}
