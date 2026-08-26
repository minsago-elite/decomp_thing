package decompengine.repair

import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentContextInput
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionLimits
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import decompengine.validation.BehaviorCaseResult
import decompengine.validation.BehaviorComparator
import decompengine.validation.BehaviorComparisonReport
import decompengine.validation.ProcessInput
import decompengine.project.sha256
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.ArrayList
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.Executor
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.name
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.readBytes
import kotlin.io.path.isRegularFile
import kotlin.io.path.relativeTo

data class StreamDiff(
    val expectedHex: String,
    val actualHex: String,
    val firstDifferenceOffset: Int?,
)

data class CaseDiff(
    val id: String,
    val args: List<String>,
    val stdinHex: String,
    val exitCodeExpected: Int,
    val exitCodeActual: Int,
    val exitCodeMatches: Boolean,
    val stdout: StreamDiff,
    val stderr: StreamDiff,
    val matches: Boolean,
)

data class StructuredBehaviorDiff(
    val id: String,
    val cases: List<CaseDiff>,
) {
    val matches: Boolean = cases.all { it.matches }
}

data class CompileFailure(
    val command: List<String>,
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
) {
    fun toPrompt(): String = """
        Compile command: ${command.joinToString(" ")}
        Exit code: $exitCode
        stdout:
        $stdout
        stderr:
        $stderr
    """.trimIndent()
}

/** Text-only legacy repair-client response DTO. Generic revision history uses [RepairPatch]. */
data class SourcePatch(
    val relativePath: String,
    val replacement: String,
)

/** Immutable byte-neutral patch content stored in graph-derived compatibility history. */
class RepairPatch(
    val relativePath: String,
    replacementBytes: ByteArray,
) {
    private val content = replacementBytes.copyOf()

    val replacementBytes: ByteArray get() = content.copyOf()

    override fun equals(other: Any?): Boolean =
        other is RepairPatch && relativePath == other.relativePath && content.contentEquals(other.content)

    override fun hashCode(): Int = 31 * relativePath.hashCode() + content.contentHashCode()
    override fun toString(): String = "RepairPatch(relativePath=$relativePath, replacementBytes=${content.size})"
}

data class RepairRequest(
    val failureKind: String,
    val prompt: String,
    val projectFiles: Map<String, String>,
    val regressionInputs: List<ProcessInput>,
)

data class RepairResponse(
    val summary: String,
    val patches: List<SourcePatch>,
)

interface RepairClient {
    /** Convenience entry remains bounded by the persisted default repair/agent limits. */
    fun requestRepair(request: RepairRequest): RepairResponse = requestRepair(
        request,
        RepairClientInvocation(RepairResourceBudget(), AgentExecutionLimits(), AgentCancellation.NONE),
    )
    /** Mandatory transport contract; implementations may not discard deadline/cancellation/budgets. */
    fun requestRepair(request: RepairRequest, invocation: RepairClientInvocation): RepairResponse
    fun modelIdentifier(): String? = null
}

data class RepairClientInvocation(
    val budget: RepairResourceBudget,
    val limits: AgentExecutionLimits,
    val cancellation: AgentCancellation,
)

internal class RepairTransportCancelledException : RuntimeException("repair transport was cancelled")

class HttpOpenAiCompatibleRepairClient(
    private val apiKey: String,
    private val model: String,
    baseUrl: URI,
    reasoningEffort: String? = null,
    private val httpClient: HttpClient = HttpClient.newHttpClient(),
    private val defaultBudget: RepairResourceBudget = RepairResourceBudget(),
    private val defaultLimits: AgentExecutionLimits = AgentExecutionLimits(),
    private val defaultCancellation: AgentCancellation = AgentCancellation.NONE,
    private val bodyExecutor: Executor = HTTP_BODY_EXECUTOR,
) : RepairClient {
    override fun modelIdentifier(): String = model
    private val endpoint = URI.create(baseUrl.toString().trimEnd('/') + "/chat/completions")
    private val reasoningEffort = reasoningEffort?.trim()?.takeIf { it.isNotEmpty() }

    init {
        require(apiKey.isNotBlank()) { "API_KEY must not be blank" }
        require(model.isNotBlank()) { "MODEL must not be blank" }
        require(baseUrl.scheme in setOf("http", "https") && !baseUrl.host.isNullOrBlank()) {
            "BASE_URL must be an absolute HTTP(S) URL"
        }
        require(this.reasoningEffort == null || this.reasoningEffort in SUPPORTED_REASONING_EFFORTS) {
            "REASONING_EFFORT must be one of ${SUPPORTED_REASONING_EFFORTS.joinToString(", ")}"
        }
    }

    override fun requestRepair(request: RepairRequest): RepairResponse = requestRepair(
        request,
        RepairClientInvocation(defaultBudget, defaultLimits, defaultCancellation),
    )

    override fun requestRepair(request: RepairRequest, invocation: RepairClientInvocation): RepairResponse {
        requireNotCancelled(invocation.cancellation, null)
        val encodedBody = encodeRequestBody(request, invocation.budget)
        val httpRequest = HttpRequest.newBuilder(endpoint)
            .header("Authorization", "Bearer $apiKey")
            .header("Content-Type", "application/json")
            .timeout(invocation.limits.wallClockTimeout)
            .POST(HttpRequest.BodyPublishers.ofByteArray(encodedBody))
            .build()
        val deadline = deadlineAfter(invocation.limits.wallClockTimeout)
        val exchange = try {
            httpClient.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofInputStream())
        } catch (failure: Exception) {
            throw AgentExecutionException(
                AgentFailure(AgentFailureKind.TRANSPORT, "could not start OpenAI-compatible repair request", retryable = true),
                failure,
            )
        }
        val response = awaitHttp(exchange, deadline, invocation.cancellation)
        val successful = response.statusCode() in 200..299
        val limit = if (successful) {
            minOf(
                invocation.limits.maxOutputBytes,
                invocation.budget.maximumResponseBytes,
                (Int.MAX_VALUE - 8).toLong(),
            )
        } else {
            minOf(
                ERROR_BODY_BYTES,
                invocation.limits.maxOutputBytes,
                invocation.budget.maximumResponseBytes,
                (Int.MAX_VALUE - 8).toLong(),
            )
        }
        val bodyResult = readHttpBody(response.body(), limit, deadline, invocation.cancellation, exchange)
        if (response.statusCode() !in 200..299) {
            val digest = sha256(bodyResult.bytes)
            throw AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.TRANSPORT,
                    "OpenAI-compatible repair request failed with HTTP ${response.statusCode()}; " +
                        "error body redacted (prefixSha256=$digest, capturedBytes=${bodyResult.bytes.size}, " +
                        "truncated=${bodyResult.truncated})",
                    retryable = response.statusCode() >= 500,
                ),
            )
        }
        if (bodyResult.truncated) {
            throw AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.RESOURCE_EXHAUSTED,
                    "OpenAI-compatible response exceeds its ${limit}-byte transport limit",
                ),
            )
        }
        val responseText = decodeHttpUtf8(bodyResult.bytes)
        return parseRepairResponse(extractMessageContent(responseText, invocation), invocation)
    }

    private fun encodeRequestBody(request: RepairRequest, budget: RepairResourceBudget): ByteArray {
        if (request.projectFiles.size > budget.maximumContextFiles) {
            throw RepairBudgetExceededException(
                "OpenAI-compatible request has ${request.projectFiles.size} project files; " +
                    "limit=${budget.maximumContextFiles}",
            )
        }
        if (request.regressionInputs.size > budget.maximumRegressionInputs) {
            throw RepairBudgetExceededException(
                "OpenAI-compatible request has ${request.regressionInputs.size} regression inputs; " +
                    "limit=${budget.maximumRegressionInputs}",
            )
        }
        val argumentCount = request.regressionInputs.sumOf { it.args.size.toLong() }
        if (argumentCount > budget.maximumRegressionArguments) {
            throw RepairBudgetExceededException(
                "OpenAI-compatible request has $argumentCount regression arguments; " +
                    "limit=${budget.maximumRegressionArguments}",
            )
        }

        val body = BoundedUtf8JsonBody(budget.maximumRequestBytes)
        body.appendAscii("{\"model\":")
        body.appendJsonString(model)
        reasoningEffort?.let {
            body.appendAscii(",\"reasoning_effort\":")
            body.appendJsonString(it)
        }
        body.appendAscii(",\"messages\":[{\"role\":\"system\",\"content\":")
        body.appendJsonString(SYSTEM_MESSAGE)
        body.appendAscii("},{\"role\":\"user\",\"content\":\"")
        body.appendJsonContent("Failure kind: ")
        body.appendJsonContent(request.failureKind)
        body.appendJsonContent("\n\nFailure details:\n")
        body.appendJsonContent(request.prompt)
        body.appendJsonContent("\n\nRegression inputs:\n")
        request.regressionInputs.forEachIndexed { inputIndex, input ->
            if (inputIndex > 0) body.appendJsonContent("\n")
            body.appendJsonContent("- ")
            body.appendJsonContent(input.id)
            body.appendJsonContent(": args=[")
            input.args.forEachIndexed { argumentIndex, argument ->
                if (argumentIndex > 0) body.appendJsonContent(", ")
                body.appendJsonContent(argument)
            }
            body.appendJsonContent("] stdinHex=")
            body.appendLowerHex(input.stdin)
        }
        body.appendJsonContent("\n\nProject files:\n")
        request.projectFiles.keys.sorted().forEachIndexed { fileIndex, path ->
            if (fileIndex > 0) body.appendJsonContent("\n\n")
            body.appendJsonContent("### ")
            body.appendJsonContent(path)
            body.appendJsonContent("\n")
            body.appendJsonContent(request.projectFiles.getValue(path))
        }
        body.appendAscii("\"}]}")
        return body.toByteArray()
    }

    private fun extractMessageContent(body: String, invocation: RepairClientInvocation): String = runCatching {
        Json.parseToJsonElement(body).jsonObject
            .getValue("choices").jsonArray.first().jsonObject
            .getValue("message").jsonObject
            .getValue("content").jsonPrimitive.content
    }.getOrElse {
        throw AgentExecutionException(
            AgentFailure(AgentFailureKind.PROTOCOL, "OpenAI-compatible response did not include valid message content"),
            it,
        )
    }.also { content ->
        requireTransportBytes(
            content,
            minOf(invocation.limits.maxOutputBytes, invocation.budget.maximumResponseBytes),
            "OpenAI-compatible message content",
        )
    }

    private fun parseRepairResponse(content: String, invocation: RepairClientInvocation): RepairResponse {
        val normalized = content.trim().removeSurrounding("```json", "```").trim()
        val response = runCatching { Json.parseToJsonElement(normalized).jsonObject }
            .getOrElse {
                throw AgentExecutionException(
                    AgentFailure(AgentFailureKind.PROTOCOL, "OpenAI-compatible message content was not valid patch JSON"),
                    it,
                )
            }
        val summary = response["summary"]?.jsonPrimitive?.contentOrNull?.ifBlank { null }
            ?: "OpenAI-compatible repair response"
        requireTransportBytes(summary, invocation.budget.maximumRequestBytes, "OpenAI-compatible repair summary")
        val patchElements = response["patches"]?.jsonArray.orEmpty()
        if (patchElements.size > invocation.budget.maximumPatchFiles) {
            throw RepairBudgetExceededException(
                "OpenAI-compatible response has ${patchElements.size} patches; " +
                    "limit=${invocation.budget.maximumPatchFiles}",
            )
        }
        var patchBytes = 0L
        val patches = patchElements.map { item ->
            val patch = item.jsonObject
            val relativePath = patch.getValue("relativePath").jsonPrimitive.content
            requireTransportBytes(relativePath, MAXIMUM_PATCH_PATH_BYTES, "OpenAI-compatible patch path")
            val replacement = patch.getValue("replacement").jsonPrimitive.content
            val replacementBytes = replacement.toByteArray(StandardCharsets.UTF_8).size.toLong()
            if (replacementBytes > invocation.budget.maximumSourceFileBytes) {
                throw RepairBudgetExceededException(
                    "OpenAI-compatible replacement $relativePath has $replacementBytes bytes; " +
                        "limit=${invocation.budget.maximumSourceFileBytes}",
                )
            }
            patchBytes = Math.addExact(patchBytes, replacementBytes)
            if (patchBytes > invocation.budget.maximumPatchBytes) {
                throw RepairBudgetExceededException(
                    "OpenAI-compatible replacements contain $patchBytes bytes; " +
                        "limit=${invocation.budget.maximumPatchBytes}",
                )
            }
            SourcePatch(relativePath, replacement)
        }
        if (patches.isEmpty()) {
            throw AgentExecutionException(
                AgentFailure(AgentFailureKind.PROTOCOL, "OpenAI-compatible response did not include source patches"),
            )
        }
        return RepairResponse(summary, patches)
    }

    private fun readHttpBody(
        input: InputStream,
        maximumBytes: Long,
        deadline: Long,
        cancellation: AgentCancellation,
        exchange: CompletableFuture<*>,
    ): CappedHttpBody {
        val reading = CompletableFuture.supplyAsync({ input.use { readCapped(it, maximumBytes) } }, bodyExecutor)
        return try {
            awaitHttp(reading, deadline, cancellation)
        } catch (failure: Throwable) {
            runCatching { input.close() }.onFailure(failure::addSuppressed)
            reading.cancel(true)
            exchange.cancel(true)
            throw failure
        }
    }

    private fun readCapped(input: InputStream, maximumBytes: Long): CappedHttpBody {
        require(maximumBytes > 0 && maximumBytes < Int.MAX_VALUE)
        val output = ByteArrayOutputStream(minOf(maximumBytes.toInt(), 8192))
        val buffer = ByteArray(8192)
        var total = 0L
        while (true) {
            val count = input.read(buffer)
            if (count < 0) return CappedHttpBody(output.toByteArray(), false)
            val remaining = maximumBytes - total
            if (count.toLong() > remaining) {
                if (remaining > 0) output.write(buffer, 0, remaining.toInt())
                return CappedHttpBody(output.toByteArray(), true)
            }
            output.write(buffer, 0, count)
            total += count
        }
    }

    private fun <T> awaitHttp(
        future: CompletableFuture<T>,
        deadline: Long,
        cancellation: AgentCancellation,
    ): T {
        while (true) {
            requireNotCancelled(cancellation, future)
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0) {
                future.cancel(true)
                throw AgentExecutionException(
                    AgentFailure(AgentFailureKind.TIMEOUT, "OpenAI-compatible repair request exceeded its wall deadline"),
                )
            }
            try {
                return future.get(minOf(remaining, POLL_NANOS), TimeUnit.NANOSECONDS)
            } catch (_: TimeoutException) {
                // Poll cancellation while the exchange or body read remains in flight.
            } catch (failure: InterruptedException) {
                Thread.currentThread().interrupt()
                future.cancel(true)
                throw AgentExecutionException(
                    AgentFailure(AgentFailureKind.TRANSPORT, "OpenAI-compatible repair request was interrupted", true),
                    failure,
                )
            } catch (failure: ExecutionException) {
                val cause = failure.cause ?: failure
                if (cause is AgentExecutionException) throw cause
                throw AgentExecutionException(
                    AgentFailure(AgentFailureKind.TRANSPORT, "OpenAI-compatible repair transport failed", true),
                    cause,
                )
            }
        }
    }

    private fun requireNotCancelled(cancellation: AgentCancellation, future: CompletableFuture<*>?) {
        if (!cancellation.isCancellationRequested()) return
        future?.cancel(true)
        throw RepairTransportCancelledException()
    }

    private fun requireTransportBytes(value: String, maximumBytes: Long, label: String) {
        val bytes = value.toByteArray(StandardCharsets.UTF_8).size.toLong()
        if (bytes > maximumBytes) {
            throw RepairBudgetExceededException("$label has $bytes bytes; limit=$maximumBytes")
        }
    }

    private fun decodeHttpUtf8(bytes: ByteArray): String = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (failure: java.nio.charset.CharacterCodingException) {
        throw AgentExecutionException(
            AgentFailure(AgentFailureKind.PROTOCOL, "OpenAI-compatible response was not valid UTF-8"),
            failure,
        )
    }

    private fun deadlineAfter(timeout: Duration): Long {
        val now = System.nanoTime()
        return runCatching { Math.addExact(now, timeout.toNanos()) }.getOrDefault(Long.MAX_VALUE)
    }

    companion object {
        fun fromEnvironment(environment: Map<String, String> = System.getenv()): HttpOpenAiCompatibleRepairClient =
            HttpOpenAiCompatibleRepairClient(
                apiKey = environment["API_KEY"].orEmpty(),
                model = environment["MODEL"].orEmpty(),
                baseUrl = URI.create(environment["BASE_URL"].orEmpty()),
                reasoningEffort = environment["REASONING_EFFORT"],
            )

        private val SUPPORTED_REASONING_EFFORTS = setOf("none", "minimal", "low", "medium", "high", "xhigh")
        private const val ERROR_BODY_BYTES = 8192L
        private const val MAXIMUM_PATCH_PATH_BYTES = 4096L
        private const val POLL_NANOS = 25_000_000L
        private const val SYSTEM_MESSAGE =
            "Return source patches as JSON with summary and patches. Each patch has relativePath and replacement."
        private val HTTP_BODY_EXECUTOR = Executors.newFixedThreadPool(4) { runnable ->
            Thread(runnable, "repair-http-body").apply { isDaemon = true }
        }
    }

    private data class CappedHttpBody(val bytes: ByteArray, val truncated: Boolean)
}

/** Builds the exact UTF-8 request body without allocating an unbounded escaped intermediate string. */
private class BoundedUtf8JsonBody(private val maximumBytes: Long) {
    private val output = ByteArrayOutputStream(minOf(maximumBytes, 8192L).toInt())

    init {
        require(maximumBytes in 1 until Int.MAX_VALUE.toLong())
    }

    fun appendAscii(value: String) {
        require(value.all { it.code < 0x80 })
        reserve(value.length)
        value.forEach { output.write(it.code) }
    }

    fun appendJsonString(value: String) {
        appendAscii("\"")
        appendJsonContent(value)
        appendAscii("\"")
    }

    fun appendJsonContent(value: String) {
        value.forEach { char ->
            when (char) {
                '\\' -> appendAscii("\\\\")
                '"' -> appendAscii("\\\"")
                '\n' -> appendAscii("\\n")
                '\r' -> appendAscii("\\r")
                '\t' -> appendAscii("\\t")
                in '\u0000'..'\u001f', in '\ud800'..'\udfff' -> {
                    appendAscii("\\u")
                    appendAscii(char.code.toString(16).padStart(4, '0'))
                }
                else -> appendUtf8(char.code)
            }
        }
    }

    fun appendLowerHex(bytes: ByteArray) {
        reserve(Math.multiplyExact(bytes.size, 2))
        bytes.forEach { byte ->
            val value = byte.toInt() and 0xff
            output.write(LOWER_HEX[value ushr 4].code)
            output.write(LOWER_HEX[value and 0x0f].code)
        }
    }

    fun toByteArray(): ByteArray = output.toByteArray()

    private fun appendUtf8(codePoint: Int) {
        when {
            codePoint <= 0x7f -> {
                reserve(1)
                output.write(codePoint)
            }
            codePoint <= 0x7ff -> {
                reserve(2)
                output.write(0xc0 or (codePoint ushr 6))
                output.write(0x80 or (codePoint and 0x3f))
            }
            else -> {
                reserve(3)
                output.write(0xe0 or (codePoint ushr 12))
                output.write(0x80 or ((codePoint ushr 6) and 0x3f))
                output.write(0x80 or (codePoint and 0x3f))
            }
        }
    }

    private fun reserve(additionalBytes: Int) {
        val required = output.size().toLong() + additionalBytes
        if (required > maximumBytes) {
            throw RepairBudgetExceededException(
                "encoded OpenAI-compatible request exceeds its $maximumBytes-byte limit",
            )
        }
    }

    private companion object {
        const val LOWER_HEX = "0123456789abcdef"
    }
}

object StructuredDiffBuilder {
    fun from(id: String, cases: List<BehaviorCaseResult>): StructuredBehaviorDiff =
        StructuredBehaviorDiff(
            id = id,
            cases = cases.map {
                CaseDiff(
                    id = it.input.id,
                    args = it.input.args,
                    stdinHex = it.input.stdin.toHex(),
                    exitCodeExpected = it.original.exitCode,
                    exitCodeActual = it.rebuilt.exitCode,
                    exitCodeMatches = it.exitCodeMatches,
                    stdout = streamDiff(it.original.stdout, it.rebuilt.stdout),
                    stderr = streamDiff(it.original.stderr, it.rebuilt.stderr),
                    matches = it.matches,
                )
            },
        )

    private fun streamDiff(expected: ByteArray, actual: ByteArray): StreamDiff =
        StreamDiff(
            expectedHex = expected.toHex(),
            actualHex = actual.toHex(),
            firstDifferenceOffset = firstDifferenceOffset(expected, actual),
        )

    private fun firstDifferenceOffset(expected: ByteArray, actual: ByteArray): Int? {
        val limit = minOf(expected.size, actual.size)
        for (index in 0 until limit) {
            if (expected[index] != actual[index]) return index
        }
        return if (expected.size == actual.size) null else limit
    }
}

data class RepairIteration(
    val index: Int,
    val failureKind: String,
    val prompt: String,
    val summary: String,
    val patches: List<RepairPatch>,
    val retainedRegressionIds: List<String>,
    val before: RepairEvidence? = null,
    val after: RepairEvidence? = null,
    val succeeded: Boolean = false,
)

data class RepairEvidence(
    val kind: String,
    val summary: String,
    val artifactPath: String? = null,
)

data class RepairRunResult(
    val iterations: List<RepairIteration>,
    val validation: BehaviorComparisonReport,
)

internal fun RepairIteration.deepFrozenCopy(): RepairIteration = RepairIteration(
    index = index,
    failureKind = failureKind,
    prompt = prompt,
    summary = summary,
    patches = Collections.unmodifiableList(ArrayList(patches.map { RepairPatch(it.relativePath, it.replacementBytes) })),
    retainedRegressionIds = Collections.unmodifiableList(ArrayList(retainedRegressionIds)),
    before = before?.copy(),
    after = after?.copy(),
    succeeded = succeeded,
)

private fun ProcessInput.detachedCopy(): ProcessInput = ProcessInput(
    id = id,
    args = Collections.unmodifiableList(ArrayList(args)),
    stdin = stdin.copyOf(),
)

class RepairExhaustedException(message: String) : RuntimeException(message)

class RepairHistory(
    path: Path,
    private val maximumBytes: Long = MAXIMUM_REPAIR_PROJECTION_BYTES,
) {
    private val path = path.toAbsolutePath().normalize()
    private val iterations = mutableListOf<RepairIteration>()
    private val regressionInputs = mutableListOf<ProcessInput>()

    init {
        require(maximumBytes in 1..MAXIMUM_REPAIR_PROJECTION_BYTES) { "repair history byte limit is invalid" }
        path.parent.createDirectories()
        require(!Files.isSymbolicLink(path.parent) && !Files.isSymbolicLink(path)) {
            "repair history path must not use a symbolic link"
        }
        cleanupExactRepairEvidenceTemporary(path)
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            val payload = readStableRepairFile(path.parent, path.fileName.toString(), maximumBytes)
            load(decodeRepairUtf8(payload, path.pathString))
        }
    }

    @Synchronized
    fun retain(inputs: List<ProcessInput>) {
        inputs.forEach { candidate ->
            val copied = candidate.detachedCopy()
            val existing = regressionInputs.indexOfFirst { it.id == copied.id }
            require(existing < 0 || regressionInputs[existing] == copied) {
                "regression input id ${copied.id} refers to different input data"
            }
            if (existing < 0) regressionInputs += copied
        }
        persist()
    }

    @Synchronized
    fun append(iteration: RepairIteration) {
        iterations += iteration.deepFrozenCopy()
        persist()
    }

    @Synchronized
    fun reconcile(
        authoritative: List<RepairIteration>,
        authoritativeRegressionInputs: List<ProcessInput> = regressionInputs,
    ) {
        if (!adoptCanonicalProjection(authoritative, authoritativeRegressionInputs)) return
        persist()
    }

    /** Refresh this compatibility view after the descriptor-pinned graph has published it. */
    @Synchronized
    internal fun adoptCanonicalProjection(
        authoritative: List<RepairIteration>,
        authoritativeRegressionInputs: List<ProcessInput>,
    ): Boolean {
        val frozenIterations = authoritative.map(RepairIteration::deepFrozenCopy)
        val frozenInputs = authoritativeRegressionInputs.map(ProcessInput::detachedCopy)
        require(frozenIterations.map { it.index } == frozenIterations.map { it.index }.distinct().sorted()) {
            "authoritative repair iterations must have unique ordered indexes"
        }
        require(frozenInputs.map { it.id } == frozenInputs.map { it.id }.distinct().sorted()) {
            "authoritative retained regression inputs must have unique sorted IDs"
        }
        if (iterations == frozenIterations && regressionInputs == frozenInputs) return false
        iterations.clear()
        iterations += frozenIterations
        regressionInputs.clear()
        regressionInputs += frozenInputs
        return true
    }

    @Synchronized
    fun all(): List<RepairIteration> = Collections.unmodifiableList(ArrayList(iterations.map(RepairIteration::deepFrozenCopy)))

    @Synchronized
    fun retainedInputs(): List<ProcessInput> =
        Collections.unmodifiableList(ArrayList(regressionInputs.map(ProcessInput::detachedCopy)))

    @Synchronized
    fun toJson(): String {
        requireBoundedProjection()
        return """
            {
              "regressionInputs": [
            ${regressionInputs.joinToString(",\n") { it.toJson().prependIndent("    ") }}
              ],
              "iterations": [
            ${iterations.joinToString(",\n") { it.toJson().prependIndent("    ") }}
              ]
            }
        """.trimIndent() + "\n"
    }

    private fun persist() {
        path.parent.createDirectories()
        requireBoundedProjection()
        val payload = toJson()
        require(payload.toByteArray().size.toLong() <= maximumBytes) {
            "repair history exceeds its $maximumBytes-byte limit"
        }
        writeRepairEvidenceAtomically(path, payload)
    }

    private fun requireBoundedProjection() {
        var projected = 256L
        fun addText(value: String?) {
            if (value == null) return
            projected = Math.addExact(
                projected,
                Math.multiplyExact(value.toByteArray(Charsets.UTF_8).size.toLong(), 6L),
            )
        }
        regressionInputs.forEach { input ->
            projected = Math.addExact(projected, Math.multiplyExact(input.stdin.size.toLong(), 2L) + 128L)
            addText(input.id)
            input.args.forEach(::addText)
        }
        iterations.forEach { iteration ->
            projected = Math.addExact(projected, 1024L)
            addText(iteration.failureKind)
            addText(iteration.prompt)
            addText(iteration.summary)
            iteration.retainedRegressionIds.forEach(::addText)
            listOfNotNull(iteration.before, iteration.after).forEach { evidence ->
                addText(evidence.kind)
                addText(evidence.summary)
                addText(evidence.artifactPath)
            }
            iteration.patches.forEach { patch ->
                addText(patch.relativePath)
                projected = Math.addExact(projected, Math.multiplyExact(patch.replacementBytes.size.toLong(), 2L) + 128L)
            }
            require(projected <= maximumBytes) { "repair history exceeds its $maximumBytes-byte limit" }
        }
        require(projected <= maximumBytes) { "repair history exceeds its $maximumBytes-byte limit" }
    }

    private fun load(payload: String) {
        val root = runCatching { Json.parseToJsonElement(payload).jsonObject }
            .getOrElse { error("invalid repair history at ${path.pathString}: ${it.message}") }
        root["regressionInputs"]?.jsonArray?.map(::parseProcessInput)?.map(ProcessInput::detachedCopy)
            ?.let(regressionInputs::addAll)
        root["iterations"]?.jsonArray?.map(::parseIteration)?.map(RepairIteration::deepFrozenCopy)
            ?.let(iterations::addAll)
    }
}

private data class RepairTask(
    val failureKind: String,
    val prompt: String,
    val context: RepairContextSelection,
    val regressionInputs: List<ProcessInput>,
    val regressionCorpusSha256: String,
    val iterationIndex: Int,
    val before: RepairEvidence?,
)

/**
 * Program/build-specific validation capability; repair core never assumes a tool or output path.
 *
 * Implementations used by public repair entry points must contain candidate-controlled builds and
 * programs as a complete process tree, clear the host environment, deny network access, mount only
 * authenticated profile-authorized inputs, and enforce pids, memory, writable-file, wall-clock, and
 * output limits. There is intentionally no host-process fallback in the repair loop.
 */
interface RepairValidationStrategy {
    val assurance: RepairValidationAssurance
    /** Fail before graph mutation or agent execution when the required boundary is unavailable. */
    fun requireAvailable()
    fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure?
    fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path

    fun evaluateBehavior(
        id: String,
        projectDir: Path,
        originalBinary: Path,
        rebuiltBinary: Path,
        inputs: List<ProcessInput>,
        reportsDir: Path,
        budget: RepairResourceBudget,
    ): BehaviorComparisonReport
}

enum class RepairValidationAssurance { STRICT_CONTAINED, TEST_ONLY_HOST_PROCESS }

class TraceGuidedRepairLoop private constructor(
    harnessCandidate: AgentHarness?,
    historyCandidate: RepairHistory?,
    registeredProfileCandidate: Any?,
    validationStrategyCandidate: RepairValidationStrategy?,
    stagingAuthorityCandidate: RepairStagingAuthority?,
    limitsCandidate: AgentExecutionLimits?,
    cancellationCandidate: AgentCancellation?,
    onAgentEventCandidate: ((AgentExecutionEvent) -> Unit)?,
    resourceBudgetCandidate: RepairResourceBudget?,
    allowTestOnlyValidationCandidate: Boolean,
) : AutoCloseable {
    private val harness: AgentHarness
    private val history: RepairHistory
    private val registeredProfile: Any
    private val validationStrategy: RepairValidationStrategy
    private val stagingAuthority: RepairStagingAuthority
    private val limits: AgentExecutionLimits
    private val cancellation: AgentCancellation
    private val onAgentEvent: (AgentExecutionEvent) -> Unit
    private val resourceBudget: RepairResourceBudget
    private val allowTestOnlyValidation: Boolean

    @Volatile
    private var closed: Boolean

    init {
        // Kotlin emits a synthetic marker constructor for private constructors. The Java-owned,
        // one-shot construction scope makes that bytecode path fail before component use.
        SecureRepairRuntime.consumeLoopConstruction()
        closed = false
        harness = requireNotNull(harnessCandidate) { "repair agent harness is required" }
        history = requireNotNull(historyCandidate) { "repair history is required" }
        registeredProfile = requireNotNull(registeredProfileCandidate) { "registered repair profile is required" }
        validationStrategy = requireNotNull(validationStrategyCandidate) { "repair validation strategy is required" }
        stagingAuthority = requireNotNull(stagingAuthorityCandidate) { "repair staging authority is required" }
        limits = limitsCandidate ?: AgentExecutionLimits()
        cancellation = cancellationCandidate ?: AgentCancellation.NONE
        onAgentEvent = onAgentEventCandidate ?: {}
        resourceBudget = resourceBudgetCandidate ?: RepairResourceBudget()
        allowTestOnlyValidation = allowTestOnlyValidationCandidate
        require(stagingAuthority.assurance == RepairStagingAssurance.STRICT_CAPTURED) {
            "public repair execution requires a strict captured/quota staging authority"
        }
        require(
            validationStrategy.assurance == RepairValidationAssurance.STRICT_CONTAINED || allowTestOnlyValidation,
        ) {
            "public repair execution requires a strict contained build/behavior validation strategy"
        }
    }

    companion object {
        /** JVM bridge owned by [SecureRepairRuntime]; a forged identity is rejected first. */
        fun openAuthorized(
            runtimeIdentity: Any?,
            harness: AgentHarness?,
            history: RepairHistory?,
            registeredProfile: Any?,
            validationStrategy: RepairValidationStrategy?,
            stagingAuthority: RepairStagingAuthority?,
            limits: AgentExecutionLimits?,
            cancellation: AgentCancellation?,
            onAgentEvent: ((AgentExecutionEvent) -> Unit)?,
            resourceBudget: RepairResourceBudget?,
            allowTestOnlyValidation: Boolean,
        ): TraceGuidedRepairLoop {
            SecureRepairRuntime.requireRuntimeIdentity(runtimeIdentity)
            return try {
                SecureRepairRuntime.authorizeLoopConstruction(registeredProfile)
                TraceGuidedRepairLoop(
                    harness,
                    history,
                    registeredProfile,
                    validationStrategy,
                    stagingAuthority,
                    limits,
                    cancellation,
                    onAgentEvent,
                    resourceBudget,
                    allowTestOnlyValidation,
                )
            } finally {
                SecureRepairRuntime.clearConstructionAuthorization()
            }
        }
    }

    fun repairCompileError(projectDir: Path, failure: CompileFailure, regressionInputs: List<ProcessInput>): RepairIteration {
        checkOpen()
        validationStrategy.requireAvailable()
        val corpus = prepareProjectState(projectDir, regressionInputs)
        val request = RepairTask(
            failureKind = "compile",
            prompt = failure.toPrompt(),
            context = repairContext(projectDir, "compile", failure.stdout + "\n" + failure.stderr),
            regressionInputs = corpus.inputs,
            regressionCorpusSha256 = corpus.sha256,
            iterationIndex = nextIterationIndex(projectDir),
            before = RepairEvidence("compile", "compiler exited with code ${failure.exitCode}"),
        )
        return applyRepair(projectDir, request)
    }

    fun repairBehaviorMismatch(
        projectDir: Path,
        originalBinary: Path,
        rebuiltBinary: Path,
        inputs: List<ProcessInput>,
        reportsDir: Path,
    ): RepairIteration {
        checkOpen()
        validationStrategy.requireAvailable()
        val corpus = prepareProjectState(projectDir, inputs)
        val comparison = openGraph(projectDir).use {
            validationStrategy.evaluateBehavior(
                "behavior_repair",
                projectDir,
                originalBinary,
                rebuiltBinary,
                corpus.inputs,
                reportsDir,
                resourceBudget,
            )
        }
        if (comparison.matches) error("behavior already matched for ${comparison.id}; no repair needed")
        val diff = StructuredDiffBuilder.from("behavior_repair", comparison.cases)
        val diffPath = reportsDir.resolve("behavior_repair.diff.json")
        writeRepairEvidenceAtomically(diffPath, diff.toJson())
        val before = RepairEvidence("behavior", "${diff.cases.count { !it.matches }} mismatched case(s)", diffPath.pathString)
        val request = RepairTask(
            failureKind = "behavior",
            prompt = diff.toPrompt(),
            context = repairContext(projectDir, "behavior"),
            regressionInputs = corpus.inputs,
            regressionCorpusSha256 = corpus.sha256,
            iterationIndex = nextIterationIndex(projectDir),
            before = before,
        )
        val execution = executeRepair(projectDir, request)
        try {
            val after = assess(
                projectDir,
                originalBinary,
                reportsDir,
                "iteration_${request.iterationIndex}",
                request.regressionInputs,
                graphLockHeld = true,
            )
            if (after is RepairAssessment.Valid) {
                execution.accept(after.evidence)
            } else {
                execution.reject(after.evidence)
            }
            execution.reconcile()
            return execution.iteration(request.iterationIndex)
        } catch (failure: Exception) {
            execution.abortAndClose(failure, "assessment-error")
            throw failure
        } finally {
            execution.close()
        }
    }

    fun repairUntilValid(
        projectDir: Path,
        originalBinary: Path,
        inputs: List<ProcessInput>,
        reportsDir: Path = projectDir.resolve("reports"),
        maxIterations: Int = 5,
    ): RepairRunResult {
        checkOpen()
        require(maxIterations > 0) { "maxIterations must be positive" }
        validationStrategy.requireAvailable()
        val corpus = prepareProjectState(projectDir, inputs)
        reportsDir.createDirectories()
        val completed = mutableListOf<RepairIteration>()
        val firstIterationIndex = nextIterationIndex(projectDir)
        var assessment = assess(projectDir, originalBinary, reportsDir, "initial", corpus.inputs)
        if (assessment is RepairAssessment.Valid) {
            return RepairRunResult(emptyList(), assessment.report)
        }

        repeat(maxIterations) { offset ->
            val request = assessment.toTask(
                repairContext(projectDir, assessment.failureKind(), assessment.contextHint()),
                corpus.inputs,
                corpus.sha256,
                Math.addExact(firstIterationIndex, offset),
            )
            val execution = executeRepair(projectDir, request)
            try {
                val after = assess(
                    projectDir,
                    originalBinary,
                    reportsDir,
                    "iteration_${Math.addExact(firstIterationIndex, offset)}",
                    request.regressionInputs,
                    graphLockHeld = true,
                )
                val rolledBack = introducesRetainedRegression(assessment, after)
                if (rolledBack) {
                    execution.reject(
                        RepairEvidence(
                            "retained-regression",
                            "candidate regressed behavior that matched before this attempt: ${after.evidence.summary}",
                            after.evidence.artifactPath,
                        ),
                    )
                } else {
                    execution.accept(after.evidence)
                }
                execution.reconcile()
                completed += execution.iteration(request.iterationIndex)
                if (after is RepairAssessment.Valid) {
                    return RepairRunResult(completed.toList(), after.report)
                }
                assessment = if (rolledBack) assessment else after
            } catch (failure: Exception) {
                execution.abortAndClose(failure, "assessment-error")
                throw failure
            } finally {
                execution.close()
            }
        }
        throw RepairExhaustedException(
            "repair did not converge after $maxIterations iteration(s); see ${reportsDir.resolve("repair_history.json")}",
        )
    }

    private fun applyRepair(
        projectDir: Path,
        request: RepairTask,
    ): RepairIteration {
        val execution = executeRepair(projectDir, request)
        try {
            val compileFailure = validationStrategy.compile(
                projectDir,
                projectDir.resolve("reports/iteration_${request.iterationIndex}.compile.log"),
                resourceBudget,
            )
            if (compileFailure == null) {
                execution.accept(RepairEvidence("compile-valid", "candidate compiled after source-bound staging"))
            } else {
                execution.reject(
                    RepairEvidence("compile", "candidate compiler exited with code ${compileFailure.exitCode}"),
                )
            }
            execution.reconcile()
            return execution.iteration(request.iterationIndex)
        } catch (failure: Exception) {
            execution.abortAndClose(failure, "validation-error")
            throw failure
        } finally {
            execution.close()
        }
    }

    private data class AppliedPatch(
        val path: String,
        val beforeSha256: String,
        val afterSha256: String,
        val beforeContent: ByteArray,
        val afterContent: ByteArray,
    )

    private class ExecutedRepair(
        val result: AgentExecutionResult,
        val applied: List<AppliedPatch>,
        val patches: List<RepairPatch>,
        val graph: ModuleRevisionGraph,
        val attempt: ModuleRevisionAttempt,
        val projectionHistory: RepairHistory,
    ) : AutoCloseable {
        private var finalized = false
        private var closed = false

        fun accept(evidence: RepairEvidence?): ModuleRevisionNode = graph.accept(attempt, evidence).also {
            finalized = true
        }

        fun reject(evidence: RepairEvidence?): ModuleRevisionNode = graph.reject(attempt, evidence).also {
            finalized = true
        }

        /** Preserve [original] while making rollback/close failures available as suppressed detail. */
        fun abortAndClose(original: Exception, evidenceKind: String) {
            if (!finalized) {
                runCatching {
                    reject(RepairEvidence(evidenceKind, original.message.orEmpty()))
                }.onFailure(original::addSuppressed)
            }
            runCatching(::close).onFailure(original::addSuppressed)
        }
        fun reconcile() {
            try {
                graph.synchronizeCompatibilityLog()
            } catch (_: Exception) {
                // Compatibility projections are recovered from the canonical graph on next entry.
            }
            try {
                graph.synchronizeRepairHistory()
            } catch (_: Exception) {
                // A committed graph head remains an unambiguous success if this projection fails.
            }
            projectionHistory.adoptCanonicalProjection(
                graph.derivedRepairIterations(),
                graph.retainedRegressionCorpus().inputs,
            )
        }
        fun iteration(index: Int): RepairIteration = graph.derivedRepairIterations().single { it.index == index }
        override fun close() {
            if (closed) return
            closed = true
            graph.close()
        }
    }

    private fun executeRepair(projectDir: Path, repair: RepairTask): ExecutedRepair {
        val base = projectDir.toAbsolutePath().normalize()
        val regressionBytes = repair.regressionInputs.fold(0L) { total, input ->
            val inputBytes = input.id.toByteArray().size.toLong() + input.stdin.size +
                input.args.sumOf { it.toByteArray().size.toLong() }
            Math.addExact(total, inputBytes)
        }
        if (regressionBytes > resourceBudget.maximumRegressionInputBytes) {
            throw RepairBudgetExceededException(
                "retained regression inputs contain $regressionBytes bytes; limit=${resourceBudget.maximumRegressionInputBytes}",
            )
        }
        val regressionContext = repair.regressionInputs.joinToString("\n") { input ->
            "${input.id}: args=${input.args} stdinHex=${input.stdin.toHex()}"
        }.ifEmpty { "<none>" }
        val indexedContext = repair.context.toContextJson()
        val requestBytes = repair.context.totalBytes + repair.prompt.toByteArray().size +
            regressionContext.toByteArray().size + indexedContext.toByteArray().size + 512L
        if (requestBytes > resourceBudget.maximumRequestBytes) {
            throw RepairBudgetExceededException(
                "repair request requires $requestBytes bytes; limit=${resourceBudget.maximumRequestBytes}",
            )
        }
        val graph = openGraph(base)
        val readable = repair.context.readablePaths
        val writable = repair.context.writablePaths.toSet()
        val baseContent = try {
            graph.requireContextBinding(repair.context)
            graph.preflightStagingContext(repair.context)
        } catch (failure: Exception) {
            runCatching(graph::close).onFailure(failure::addSuppressed)
            throw failure
        }
        val attempt = try {
            graph.beginAttempt(
                repair.context.writablePaths,
                RevisionRepairMetadata(
                    iterationIndex = repair.iterationIndex,
                    failureKind = repair.failureKind,
                    prompt = repair.prompt,
                    summary = null,
                    retainedRegressionIds = repair.regressionInputs.map { it.id },
                    before = repair.before,
                    regressionCorpusSha256 = repair.regressionCorpusSha256,
                ),
            )
        } catch (failure: Exception) {
            runCatching(graph::close).onFailure(failure::addSuppressed)
            throw failure
        }
        val stagedBefore = baseContent
        val stagedExecution = try {
            stagingAuthority.execute(
                harness = harness,
                initialFiles = stagedBefore,
                writablePaths = writable,
                budget = resourceBudget,
                requestFactory = { root ->
                    val rules = readable.map { relative ->
                        val operations = if (relative in writable) {
                            setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)
                        } else {
                            setOf(AgentOperation.READ_FILE)
                        }
                        AgentPathRule(AgentWorkspacePath(root.id, relative), operations)
                    }
                    AgentExecutionRequest(
                        objective = """
                            Repair the ${repair.failureKind} failure in the authorized project workspace.
                            Edit only the allowed project files in place and preserve all retained regression behavior.

                            ${repair.prompt}
                        """.trimIndent(),
                        workspaceRoots = listOf(root),
                        contextInputs = listOf(
                            AgentContextInput(RepairClientAgentHarness.FAILURE_KIND_CONTEXT_ID, repair.failureKind),
                            AgentContextInput("retained-regression-inputs", regressionContext),
                            AgentContextInput("dependency-indexed-repair-context", indexedContext, "application/json"),
                        ),
                        accessPolicy = AgentAccessPolicy(rules),
                        limits = limits,
                        cancellation = cancellation,
                    )
                },
                onEvent = onAgentEvent,
            )
        } catch (failure: Exception) {
            abortPendingGraph(graph, attempt, failure, "agent-error")
            throw failure
        }
        val result = stagedExecution.result
        try {
            graph.annotateAttempt(attempt, result.summary ?: "agent repair attempt")
            require(result.stopReason == AgentStopReason.COMPLETED) {
                "repair agent stopped with ${result.stopReason.name.lowercase()}: ${result.summary.orEmpty()}"
            }
            require(result.changes.isNotEmpty()) { "repair agent completed without changing a source file" }
            require(result.changes.map { it.path.relativePath }.distinct().size == result.changes.size) {
                "repair agent reported a source path more than once"
            }
            val declared = result.changes.associateBy { change ->
                require(change.path.rootId == "project" && change.path.relativePath in writable) {
                    "repair agent reported an unauthorized file change: ${change.path.rootId}:${change.path.relativePath}"
                }
                change.path.relativePath
            }
            val stagedAfter = stagedExecution.files
            require(stagedAfter.keys == readable.toSet()) {
                "strict repair staging returned an unexpected file set"
            }
            val actualChanged = readable.filterTo(mutableSetOf()) { relative ->
                stagedAfter.getValue(relative)?.contentEquals(stagedBefore.getValue(relative)) != true
            }
            require(actualChanged == declared.keys) {
                "repair agent change report does not match workspace changes: actual=$actualChanged reported=${declared.keys}"
            }
            val applied = declared.entries.sortedBy { it.key }.map { (relative, change) ->
                require(change.kind == AgentFileChangeKind.MODIFIED) {
                    "repair may only modify existing project files: $relative"
                }
                val beforeContent = baseContent.getValue(relative)
                val afterContent = requireNotNull(stagedAfter.getValue(relative)) {
                    "repair agent deleted an allowed project file: $relative"
                }
                require(change.beforeSha256 == sha256(beforeContent) && change.afterSha256 == sha256(afterContent)) {
                    "repair agent digests do not match workspace file: $relative"
                }
                require(change.sizeBytes == null || change.sizeBytes == afterContent.size.toLong()) {
                    "repair agent size does not match workspace file: $relative"
                }
                AppliedPatch(relative, sha256(beforeContent), sha256(afterContent), beforeContent, afterContent)
            }
            val replacements = applied.associate { patch -> patch.path to patch.afterContent }
            graph.installCandidate(attempt, replacements)
            val patches = applied.map { patch -> RepairPatch(patch.path, patch.afterContent) }
            return ExecutedRepair(result, applied, patches, graph, attempt, history)
        } catch (failure: Exception) {
            abortPendingGraph(graph, attempt, failure, "candidate-error")
            throw failure
        }
    }

    private fun abortPendingGraph(
        graph: ModuleRevisionGraph,
        attempt: ModuleRevisionAttempt,
        original: Exception,
        evidenceKind: String,
    ) {
        runCatching {
            graph.reject(attempt, RepairEvidence(evidenceKind, original.message.orEmpty()))
        }.onFailure(original::addSuppressed)
        runCatching(graph::close).onFailure(original::addSuppressed)
    }

    private fun assess(
        projectDir: Path,
        originalBinary: Path,
        reportsDir: Path,
        label: String,
        regressionInputs: List<ProcessInput>,
        graphLockHeld: Boolean = false,
    ): RepairAssessment {
        if (!graphLockHeld) {
            return openGraph(projectDir).use { graph ->
                val corpus = graph.retainedRegressionCorpus()
                require(corpus.inputs == regressionInputs) {
                    "retained regression corpus changed; restart assessment with the merged corpus"
                }
                assess(projectDir, originalBinary, reportsDir, label, corpus.inputs, graphLockHeld = true)
            }
        }
        val compile = validationStrategy.compile(projectDir, reportsDir.resolve("$label.compile.log"), resourceBudget)
        if (compile != null) return RepairAssessment.CompileError(compile, reportsDir.resolve("$label.compile.log"))
        val rebuilt = validationStrategy.rebuiltProgram(projectDir, resourceBudget)
        val report = validationStrategy.evaluateBehavior(
            "${label}_behavior",
            projectDir,
            originalBinary,
            rebuilt,
            regressionInputs,
            reportsDir,
            resourceBudget,
        )
        if (report.matches) return RepairAssessment.Valid(report)
        val diff = StructuredDiffBuilder.from(report.id, report.cases)
        val path = reportsDir.resolve("${report.id}.diff.json")
        writeRepairEvidenceAtomically(path, diff.toJson())
        return RepairAssessment.BehaviorError(diff, path)
    }

    private fun repairContext(projectDir: Path, failureKind: String, diagnosticHint: String? = null): RepairContextSelection =
        openGraph(projectDir).use { graph ->
            graph.selectContext(failureKind, diagnosticHint)
        }

    private fun prepareProjectState(
        projectDir: Path,
        additions: Collection<ProcessInput> = emptyList(),
    ): RetainedRegressionCorpus {
        openGraph(projectDir).use { graph ->
            // Import a pre-graph compatibility history once, then keep the graph authoritative.
            // A stale compatibility projection can only contribute an identical/subset input; ID
            // collisions with different bytes fail closed in retainRegressionInputs.
            val corpus = graph.retainRegressionInputs(history.retainedInputs() + additions)
            try {
                graph.synchronizeCompatibilityLog()
            } catch (_: Exception) {
                // Best-effort compatibility projection; the graph remains authoritative.
            }
            try {
                graph.synchronizeRepairHistory()
            } catch (_: Exception) {
                // The next public entry retries projection reconciliation.
            }
            history.adoptCanonicalProjection(graph.derivedRepairIterations(), corpus.inputs)
            return corpus
        }
    }

    private fun nextIterationIndex(projectDir: Path): Int = openGraph(projectDir)
        .use { graph -> Math.addExact(graph.derivedRepairIterations().maxOfOrNull { it.index } ?: 0, 1) }

    private fun openGraph(projectDir: Path): ModuleRevisionGraph =
        SecureRepairRuntime.openGraph(registeredProfile, projectDir, resourceBudget)

    private fun checkOpen() = check(!closed) { "secure repair loop is closed" }

    override fun close() {
        closed = true
    }

}

private sealed interface RepairAssessment {
    val evidence: RepairEvidence

    data class CompileError(val failure: CompileFailure, val logPath: Path) : RepairAssessment {
        override val evidence = RepairEvidence(
            kind = "compile",
            summary = "compiler exited with code ${failure.exitCode}",
            artifactPath = logPath.pathString,
        )
    }

    data class BehaviorError(val diff: StructuredBehaviorDiff, val diffPath: Path) : RepairAssessment {
        override val evidence = RepairEvidence(
            kind = "behavior",
            summary = "${diff.cases.count { !it.matches }} of ${diff.cases.size} regression case(s) mismatched",
            artifactPath = diffPath.pathString,
        )
    }

    data class Valid(val report: BehaviorComparisonReport) : RepairAssessment {
        override val evidence = RepairEvidence(
            kind = "valid",
            summary = "all ${report.cases.size} regression case(s) compiled and matched",
            artifactPath = report.reportPath.pathString,
        )
    }
}

private fun RepairAssessment.contextHint(): String? = when (this) {
    is RepairAssessment.CompileError -> failure.stdout + "\n" + failure.stderr
    is RepairAssessment.BehaviorError, is RepairAssessment.Valid -> null
}

private fun RepairAssessment.failureKind(): String = when (this) {
    is RepairAssessment.CompileError -> "compile"
    is RepairAssessment.BehaviorError -> "behavior"
    is RepairAssessment.Valid -> error("valid projects do not need a repair request")
}

private fun RepairAssessment.toTask(
    context: RepairContextSelection,
    regressionInputs: List<ProcessInput>,
    regressionCorpusSha256: String,
    iterationIndex: Int,
): RepairTask = when (this) {
    is RepairAssessment.CompileError -> RepairTask(
        failureKind = "compile",
        prompt = failure.toPrompt(),
        context = context,
        regressionInputs = regressionInputs,
        regressionCorpusSha256 = regressionCorpusSha256,
        iterationIndex = iterationIndex,
        before = evidence,
    )
    is RepairAssessment.BehaviorError -> RepairTask(
        failureKind = "behavior",
        prompt = diff.toPrompt(),
        context = context,
        regressionInputs = regressionInputs,
        regressionCorpusSha256 = regressionCorpusSha256,
        iterationIndex = iterationIndex,
        before = evidence,
    )
    is RepairAssessment.Valid -> error("valid projects do not need a repair request")
}

private fun introducesRetainedRegression(before: RepairAssessment, after: RepairAssessment): Boolean {
    if (before !is RepairAssessment.CompileError && after is RepairAssessment.CompileError) return true
    if (before !is RepairAssessment.BehaviorError || after !is RepairAssessment.BehaviorError) return false
    val afterById = after.diff.cases.associateBy { it.id }
    return before.diff.cases.any { prior ->
        prior.matches && afterById[prior.id]?.matches != true
    }
}

fun StructuredBehaviorDiff.toPrompt(): String = """
    Structured behavior diff for $id:
    ${cases.joinToString("\n") {
        "- ${it.id}: exit expected=${it.exitCodeExpected} actual=${it.exitCodeActual}; " +
            "stdout offset=${it.stdout.firstDifferenceOffset} expected=${it.stdout.expectedHex} actual=${it.stdout.actualHex}; " +
            "stderr offset=${it.stderr.firstDifferenceOffset} expected=${it.stderr.expectedHex} actual=${it.stderr.actualHex}"
    }}
""".trimIndent()

fun StructuredBehaviorDiff.toJson(): String = """
{
  "id": "${id.escapeJson()}",
  "matches": $matches,
  "cases": [
${cases.joinToString(",\n") { it.toJson().prependIndent("    ") }}
  ]
}
""".trimIndent() + "\n"

private fun CaseDiff.toJson(): String = """
{
  "id": "${id.escapeJson()}",
  "args": [${args.joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "stdinHex": "$stdinHex",
  "matches": $matches,
  "exitCode": {
    "expected": $exitCodeExpected,
    "actual": $exitCodeActual,
    "matches": $exitCodeMatches
  },
  "stdout": ${stdout.toJson()},
  "stderr": ${stderr.toJson()}
}
""".trimIndent()

private fun StreamDiff.toJson(): String = """
{
  "expectedHex": "$expectedHex",
  "actualHex": "$actualHex",
  "firstDifferenceOffset": ${firstDifferenceOffset ?: "null"}
}
""".trimIndent()

private fun RepairIteration.toJson(): String = """
{
  "index": $index,
  "failureKind": "${failureKind.escapeJson()}",
  "prompt": "${prompt.escapeJson()}",
  "summary": "${summary.escapeJson()}",
  "succeeded": $succeeded,
  "retainedRegressionIds": [${retainedRegressionIds.joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "before": ${before?.toJson() ?: "null"},
  "after": ${after?.toJson() ?: "null"},
  "patches": [
${patches.joinToString(",\n") { it.toJson().prependIndent("    ") }}
  ]
}
""".trimIndent()

private fun RepairEvidence.toJson(): String = """
{
  "kind": "${kind.escapeJson()}",
  "summary": "${summary.escapeJson()}",
  "artifactPath": ${artifactPath?.let { "\"${it.escapeJson()}\"" } ?: "null"}
}
""".trimIndent()

private fun RepairPatch.toJson(): String = """
{
  "relativePath": "${relativePath.escapeJson()}",
  "replacementHex": "${replacementBytes.toHex()}"
}
""".trimIndent()

private fun ProcessInput.toJson(): String = """
{
  "id": "${id.escapeJson()}",
  "args": [${args.joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "stdinHex": "${stdin.toHex()}"
}
""".trimIndent()

private fun parseProcessInput(element: kotlinx.serialization.json.JsonElement): ProcessInput {
    val value = element.jsonObject
    return ProcessInput(
        id = value.requiredString("id"),
        args = value["args"]?.jsonArray?.map { it.jsonPrimitive.content } ?: emptyList(),
        stdin = value.requiredString("stdinHex").hexToBytes(),
    )
}

private fun parseIteration(element: kotlinx.serialization.json.JsonElement): RepairIteration {
    val value = element.jsonObject
    return RepairIteration(
        index = value["index"]?.jsonPrimitive?.intOrNull ?: error("repair history iteration is missing index"),
        failureKind = value.requiredString("failureKind"),
        prompt = value["prompt"]?.jsonPrimitive?.contentOrNull.orEmpty(),
        summary = value.requiredString("summary"),
        patches = value["patches"]?.jsonArray?.map { patch ->
            val item = patch.jsonObject
            val relative = item.requiredString("relativePath")
            val bytes = item["replacementHex"]?.jsonPrimitive?.contentOrNull?.hexToBytes()
                ?: item.requiredString("replacement").toByteArray(Charsets.UTF_8)
            RepairPatch(relative, bytes)
        } ?: emptyList(),
        retainedRegressionIds = value["retainedRegressionIds"]?.jsonArray?.map { it.jsonPrimitive.content } ?: emptyList(),
        before = value["before"]?.let(::parseEvidence),
        after = value["after"]?.let(::parseEvidence),
        succeeded = value["succeeded"]?.jsonPrimitive?.contentOrNull?.toBooleanStrictOrNull() ?: false,
    )
}

private fun parseEvidence(element: kotlinx.serialization.json.JsonElement): RepairEvidence? {
    if (element.toString() == "null") return null
    val value = element.jsonObject
    return RepairEvidence(
        kind = value.requiredString("kind"),
        summary = value.requiredString("summary"),
        artifactPath = value["artifactPath"]?.jsonPrimitive?.contentOrNull,
    )
}

private fun JsonObject.requiredString(name: String): String =
    get(name)?.jsonPrimitive?.contentOrNull ?: error("repair history is missing $name")

private fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "hex input must contain pairs of characters" }
    return ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun decodeRepairUtf8(bytes: ByteArray, path: String): String = try {
    Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
} catch (failure: java.nio.charset.CharacterCodingException) {
    throw IllegalArgumentException("repair output is not UTF-8 source text: $path", failure)
}

private fun String.escapeJson(): String =
    buildString {
        for (char in this@escapeJson) {
            when (char) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                in '\u0000'..'\u001f', in '\ud800'..'\udfff' -> {
                    append("\\u")
                    append(char.code.toString(16).padStart(4, '0'))
                }
                else -> append(char)
            }
        }
    }

private fun String.unescapeJson(): String {
    val result = StringBuilder()
    var index = 0
    while (index < length) {
        val char = this[index++]
        if (char == '\\' && index < length) {
            result.append(
                when (val escaped = this[index++]) {
                    'n' -> '\n'
                    'r' -> '\r'
                    't' -> '\t'
                    '"' -> '"'
                    '\\' -> '\\'
                    else -> escaped
                },
            )
        } else {
            result.append(char)
        }
    }
    return result.toString()
}
