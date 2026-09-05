package decompengine.web

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import decompengine.acp.AcpHarnessFactory
import decompengine.acp.AcpHarnessProvenance
import decompengine.exploration.AutomaticExplorer
import decompengine.exploration.CandidateInput
import decompengine.exploration.CandidateSource
import decompengine.jobs.InvalidUploadException
import decompengine.jobs.Job
import decompengine.jobs.JobStore
import decompengine.jobs.JobStoreException
import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.BestEffortProgressJournal
import decompengine.agent.AgentWorkflowProgress
import decompengine.agent.AgentWorkflowPhase
import decompengine.jobs.toJson
import decompengine.project.ArchivalReconstructionService
import decompengine.project.BoundedLlmModuleReconstructor
import decompengine.project.EvidenceModuleReconstructor
import decompengine.project.GhidraHeadlessProgramModelAnalyzer
import decompengine.project.ModuleReconstructor
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.io.path.name
import kotlin.io.path.pathString

fun interface JobAnalyzer {
    fun analyze(job: Job, reportsDir: Path)
}

fun interface JobReconstructor {
    fun reconstruct(job: Job, reportsDir: Path)
}

class AutomaticJobAnalyzer : JobAnalyzer {
    override fun analyze(job: Job, reportsDir: Path) {
        AutomaticExplorer().explore(
            binaryPath = job.binaryPath,
            seedInputs = listOf(CandidateInput("seed_default", CandidateSource.SEED)),
            reportsDir = reportsDir,
        )
    }
}

class SourceTreeJobReconstructor(
    private val environment: Map<String, String> = System.getenv(),
) : JobReconstructor {
    override fun reconstruct(job: Job, reportsDir: Path) {
        BestEffortProgressJournal(reportsDir, "reconstruction", environment.values).use { progress ->
            try {
                val strategy = selectWebReconstructionStrategy(environment, progress)
                java.nio.file.Files.createDirectories(reportsDir)
                java.nio.file.Files.writeString(
                    reportsDir.resolve(WEB_RECONSTRUCTION_HARNESS_REPORT),
                    renderWebReconstructionHarnessSelection(strategy),
                )
                ArchivalReconstructionService(
                    GhidraHeadlessProgramModelAnalyzer.fromEnvironment(environment),
                    strategy.reconstructor,
                    progress = progress,
                ).reconstruct(job.binaryPath, reportsDir)
            } catch (failure: Exception) {
                progress.phase(AgentWorkflowPhase.FAILED)
                throw failure
            }
        }
    }
}

internal enum class WebReconstructionMode(val configurationValue: String) {
    AGENT("agent"),
    EVIDENCE_ONLY("evidence-only"),
}

internal data class WebReconstructionStrategy(
    val mode: WebReconstructionMode,
    val reconstructor: ModuleReconstructor,
    val harnessProvenance: AcpHarnessProvenance?,
)

/** Resolves exactly one web reconstruction mode without credential-based fallbacks. */
internal fun selectWebReconstructionStrategy(
    environment: Map<String, String>,
    progress: AgentWorkflowProgress = AgentWorkflowProgress.NONE,
): WebReconstructionStrategy {
    val configuredMode = environment[WEB_RECONSTRUCTION_MODE_ENVIRONMENT] ?: WebReconstructionMode.AGENT.configurationValue
    return when (configuredMode) {
        WebReconstructionMode.AGENT.configurationValue -> {
            val selection = AcpHarnessFactory.fromEnvironment(environment)
            WebReconstructionStrategy(
                WebReconstructionMode.AGENT,
                BoundedLlmModuleReconstructor(
                    selection.createHarness(),
                    harnessProvenanceDescriptor = selection.provenance.stableDescriptor,
                    progress = progress,
                ),
                selection.provenance,
            )
        }
        WebReconstructionMode.EVIDENCE_ONLY.configurationValue -> WebReconstructionStrategy(
            WebReconstructionMode.EVIDENCE_ONLY,
            EvidenceModuleReconstructor(),
            null,
        )
        else -> throw IllegalArgumentException(
            "$WEB_RECONSTRUCTION_MODE_ENVIRONMENT must be exactly " +
                "${WebReconstructionMode.AGENT.configurationValue} or " +
                WebReconstructionMode.EVIDENCE_ONLY.configurationValue,
        )
    }
}

/** Stable, non-secret selection metadata. This does not claim that an ACP session has run. */
internal fun renderWebReconstructionHarnessSelection(strategy: WebReconstructionStrategy): String {
    val selection = strategy.harnessProvenance?.let { provenance ->
        buildJsonObject {
            put("stableDescriptor", provenance.stableDescriptor)
            put("harness", provenance.harness)
            put("implementationId", provenance.implementationId)
            put("agentExecutionContractVersion", provenance.agentExecutionContractVersion)
            put(
                "acpProtocolVersion",
                provenance.acpProtocolVersion?.let(::JsonPrimitive) ?: JsonNull,
            )
            put("acpSdkVersion", provenance.acpSdkVersion?.let(::JsonPrimitive) ?: JsonNull)
            put(
                "configurationSha256",
                provenance.configurationSha256?.let(::JsonPrimitive) ?: JsonNull,
            )
            put("deprecated", provenance.deprecated)
        }
    }
    val report = buildJsonObject {
        put("schemaVersion", 1)
        put("mode", strategy.mode.configurationValue)
        put("selection", selection ?: JsonNull)
    }
    return Json { prettyPrint = true }.encodeToString(JsonElement.serializer(), report) + "\n"
}

private const val WEB_RECONSTRUCTION_MODE_ENVIRONMENT = "WEB_RECONSTRUCTION_MODE"
private const val WEB_RECONSTRUCTION_HARNESS_REPORT = "reconstruction_harness_selection.json"

class UploadServer(
    host: String,
    port: Int,
    dataDir: Path,
    private val analyzer: JobAnalyzer = AutomaticJobAnalyzer(),
    private val reconstructor: JobReconstructor = SourceTreeJobReconstructor(),
    executor: Executor? = null,
) {
    private val server = HttpServer.create(InetSocketAddress(host, port), 0)
    private val store = JobStore(dataDir)
    private val ownedExecutor: ExecutorService? = if (executor == null) {
        Executors.newFixedThreadPool(2) { runnable ->
            Thread(runnable, "decomp-web-analysis").apply { isDaemon = true }
        }
    } else {
        null
    }
    private val analysisExecutor: Executor = executor ?: ownedExecutor!!
    private val runningJobs = ConcurrentHashMap.newKeySet<String>()
    val serverPort: Int get() = server.address.port

    init {
        store.recoverInterruptedJobs()
        server.createContext("/") { exchange -> route(exchange) }
    }

    fun start() = server.start()

    fun stop(delaySeconds: Int = 0) {
        server.stop(delaySeconds)
        ownedExecutor?.shutdownNow()
    }

    private fun route(exchange: HttpExchange) {
        val segments = exchange.requestURI.path.split('/').filter(String::isNotBlank)
        try {
            when {
                exchange.requestMethod == "GET" && segments.isEmpty() ->
                    exchange.sendHtml(200, renderDashboard(store.list()))
                exchange.requestMethod == "GET" && segments == listOf("assets", "app.css") ->
                    exchange.sendBytes(200, APP_CSS.toByteArray(), "text/css; charset=utf-8", cache = true)
                exchange.requestMethod == "POST" && segments == listOf("jobs") -> handlePostJob(exchange)
                exchange.requestMethod == "GET" && segments.size == 2 && segments[0] == "jobs" ->
                    exchange.sendHtml(200, renderJob(store.get(decode(segments[1]))))
                exchange.requestMethod == "POST" && segments.size == 3 && segments[0] == "jobs" && segments[2] == "explore" ->
                    handleExplore(exchange, decode(segments[1]))
                exchange.requestMethod == "POST" && segments.size == 3 && segments[0] == "jobs" && segments[2] == "reconstruct" ->
                    handleReconstruct(exchange, decode(segments[1]))
                exchange.requestMethod == "GET" && segments.size >= 4 && segments[0] == "jobs" && segments[2] == "source" ->
                    handleSource(exchange, decode(segments[1]), segments.drop(3).joinToString("/").let(::decode))
                exchange.requestMethod == "GET" && segments.size >= 4 && segments[0] == "jobs" && segments[2] == "artifacts" ->
                    handleArtifact(exchange, decode(segments[1]), segments.drop(3).joinToString("/").let(::decode))
                exchange.requestMethod == "GET" && segments.size == 3 && segments[0] == "api" && segments[1] == "jobs" ->
                    exchange.sendJson(200, encodeJob(store.get(decode(segments[2]))))
                exchange.requestMethod == "GET" && segments.size == 4 && segments[0] == "api" && segments[1] == "jobs" && segments[3] == "events" -> {
                    val job = store.get(decode(segments[2]))
                    val snapshot = AgentProgressJournal.read(store.reportsDirectory(job.id))
                    exchange.sendJson(200, snapshot?.toString() ?: "{\"schemaVersion\":1,\"displayOnly\":true,\"nextSequence\":0,\"queueDropped\":0,\"historyDropped\":0,\"truncated\":false,\"events\":[]}")
                }
                else -> exchange.sendHtml(404, renderErrorPage(404, "Page not found", "The requested route does not exist."))
            }
        } catch (exception: JobStoreException) {
            exchange.sendHtml(404, renderErrorPage(404, "Job not found", exception.message ?: "The job does not exist."))
        } catch (exception: IllegalArgumentException) {
            exchange.sendHtml(400, renderErrorPage(400, "Invalid request", exception.message ?: "The request was invalid."))
        } catch (exception: Exception) {
            exchange.sendHtml(500, renderErrorPage(500, "Unexpected error", exception.message ?: "The operation failed."))
        }
    }

    private fun handlePostJob(exchange: HttpExchange) {
        try {
            val declaredLength = exchange.requestHeaders.getFirst("Content-Length")?.toLongOrNull()
            require(declaredLength == null || declaredLength <= MAX_UPLOAD_BYTES) { "upload exceeds the 32 MiB limit" }
            val contentType = exchange.requestHeaders.getFirst("Content-Type") ?: ""
            val upload = MultipartUpload.parse(exchange.requestBody.readLimited(MAX_UPLOAD_BYTES), contentType)
            val job = store.createFromUpload(upload.filename, upload.content)
            if ((exchange.requestHeaders.getFirst("Accept") ?: "").contains("application/json")) {
                exchange.sendJson(201, encodeJob(job))
            } else {
                exchange.redirect("/jobs/${job.id}")
            }
        } catch (exception: InvalidUploadException) {
            exchange.sendHtml(400, renderErrorPage(400, "Unsupported binary", exception.message ?: "Upload a Linux ELF binary."))
        }
    }

    private fun handleExplore(exchange: HttpExchange, jobId: String) {
        val job = store.get(jobId)
        schedule(
            exchange,
            job,
            queuedMessage = "Waiting for an exploration worker",
            activeMessage = "Generating and executing candidate inputs",
            completeMessage = "Exploration completed successfully",
        ) { analyzer.analyze(it, store.reportsDirectory(it.id)) }
    }

    private fun handleReconstruct(exchange: HttpExchange, jobId: String) {
        val job = store.get(jobId)
        schedule(
            exchange,
            job,
            queuedMessage = "Waiting for a source-tree worker",
            activeMessage = "Recovering program structure and generating source modules",
            completeMessage = "Archival source tree generated successfully",
        ) { reconstructor.reconstruct(it, store.reportsDirectory(it.id)) }
    }

    private fun schedule(
        exchange: HttpExchange,
        job: Job,
        queuedMessage: String,
        activeMessage: String,
        completeMessage: String,
        operation: (Job) -> Unit,
    ) {
        if (!runningJobs.add(job.id)) {
            exchange.sendHtml(409, renderErrorPage(409, "Analysis already running", "This job already has an active background operation."))
            return
        }
        store.updateStatus(job.id, "queued", queuedMessage)
        try {
            analysisExecutor.execute {
                try {
                    val active = store.updateStatus(job.id, "analyzing", activeMessage)
                    operation(active)
                    store.updateStatus(job.id, "complete", completeMessage)
                } catch (failure: Exception) {
                    store.updateStatus(job.id, "failed", failure.message ?: failure.javaClass.simpleName)
                } finally {
                    runningJobs.remove(job.id)
                }
            }
        } catch (failure: Exception) {
            runningJobs.remove(job.id)
            store.updateStatus(job.id, "failed", "Analysis worker rejected the job")
            throw failure
        }
        exchange.redirect("/jobs/${job.id}")
    }

    private fun handleSource(exchange: HttpExchange, jobId: String, relativePath: String) {
        require(relativePath.isNotBlank()) { "source path must not be blank" }
        val normalized = relativePath.replace('\\', '/')
        require(!normalized.startsWith('/') && normalized.split('/').none { it.isBlank() || it == ".." || it == "." }) {
            "source path must remain inside the generated tree"
        }
        require(normalized == "Makefile" || normalized.endsWith(".c") || normalized.endsWith(".h") ||
            normalized.endsWith(".json") || normalized.endsWith(".md") || normalized.endsWith(".log")) {
            "only generated text files may be viewed"
        }
        val source = store.resolveArtifact(jobId, "reports/source-tree/$normalized")
        exchange.sendHtml(200, renderSourceFile(store.get(jobId), normalized, java.nio.file.Files.readString(source)))
    }

    private fun handleArtifact(exchange: HttpExchange, jobId: String, relativePath: String) {
        val artifact = store.resolveArtifact(jobId, relativePath)
        exchange.responseHeaders.add("Content-Disposition", "attachment; filename=\"${artifact.name.replace("\"", "")}\"")
        exchange.sendBytes(200, java.nio.file.Files.readAllBytes(artifact), contentType(artifact))
    }

    private fun encodeJob(job: Job): String =
        Json.encodeToString(JsonElement.serializer(), job.toJson())

    private fun decode(value: String): String = URLDecoder.decode(value, StandardCharsets.UTF_8)

    private companion object {
        const val MAX_UPLOAD_BYTES = 32L * 1024 * 1024
    }
}

data class Upload(val filename: String, val content: ByteArray)

object MultipartUpload {
    fun parse(body: ByteArray, contentType: String): Upload {
        require(contentType.startsWith("multipart/form-data")) { "expected multipart/form-data" }
        val boundary = contentType.substringAfter("boundary=", "").substringBefore(';').trim().trim('"')
        require(boundary.isNotBlank()) { "missing multipart boundary" }
        val delimiter = "--$boundary"
        val text = body.toString(StandardCharsets.ISO_8859_1)
        for (part in text.split(delimiter)) {
            if (!part.contains("name=\"binary\"")) continue
            val headerEnd = part.indexOf("\r\n\r\n")
            require(headerEnd >= 0) { "malformed binary upload part" }
            val headers = part.substring(0, headerEnd)
            val filename = Regex("filename=\"([^\"]*)\"").find(headers)?.groupValues?.get(1)
                ?.ifBlank { "input.elf" } ?: "input.elf"
            var payload = part.substring(headerEnd + 4)
            payload = payload.removeSuffix("\r\n").removeSuffix("--").removeSuffix("\r\n")
            return Upload(filename, payload.toByteArray(StandardCharsets.ISO_8859_1))
        }
        error("missing binary upload field")
    }
}

private fun java.io.InputStream.readLimited(maxBytes: Long): ByteArray {
    val result = ByteArrayOutputStream()
    val buffer = ByteArray(8192)
    var total = 0L
    while (true) {
        val read = read(buffer)
        if (read < 0) break
        total += read
        require(total <= maxBytes) { "upload exceeds the 32 MiB limit" }
        result.write(buffer, 0, read)
    }
    return result.toByteArray()
}

private fun HttpExchange.redirect(location: String) {
    responseHeaders.add("Location", location)
    sendResponseHeaders(303, -1)
    close()
}

private fun HttpExchange.sendHtml(status: Int, body: String) =
    sendBytes(status, body.toByteArray(StandardCharsets.UTF_8), "text/html; charset=utf-8")

private fun HttpExchange.sendJson(status: Int, body: String) =
    sendBytes(status, body.toByteArray(StandardCharsets.UTF_8), "application/json; charset=utf-8")

private fun HttpExchange.sendBytes(
    status: Int,
    body: ByteArray,
    contentType: String,
    cache: Boolean = false,
) {
    responseHeaders.add("Content-Type", contentType)
    responseHeaders.add("X-Content-Type-Options", "nosniff")
    responseHeaders.add("Referrer-Policy", "no-referrer")
    responseHeaders.add(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
    )
    responseHeaders.add("Cache-Control", if (cache) "public, max-age=3600" else "no-store")
    sendResponseHeaders(status, body.size.toLong())
    responseBody.use { it.write(body) }
}

private fun contentType(path: Path): String = when (path.fileName.toString().substringAfterLast('.', "")) {
    "json" -> "application/json; charset=utf-8"
    "zip" -> "application/zip"
    "log", "txt", "c", "h", "md" -> "text/plain; charset=utf-8"
    else -> "application/octet-stream"
}
