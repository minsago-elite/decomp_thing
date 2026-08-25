package decompengine.web

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import decompengine.exploration.AutomaticExplorer
import decompengine.exploration.CandidateInput
import decompengine.exploration.CandidateSource
import decompengine.jobs.InvalidUploadException
import decompengine.jobs.Job
import decompengine.jobs.JobStore
import decompengine.jobs.JobStoreException
import decompengine.jobs.toJson
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
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

class AutomaticJobAnalyzer : JobAnalyzer {
    override fun analyze(job: Job, reportsDir: Path) {
        AutomaticExplorer().explore(
            binaryPath = job.binaryPath,
            seedInputs = listOf(CandidateInput("seed_default", CandidateSource.SEED)),
            reportsDir = reportsDir,
        )
    }
}

class UploadServer(
    host: String,
    port: Int,
    dataDir: Path,
    private val analyzer: JobAnalyzer = AutomaticJobAnalyzer(),
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
                exchange.requestMethod == "GET" && segments.size >= 4 && segments[0] == "jobs" && segments[2] == "artifacts" ->
                    handleArtifact(exchange, decode(segments[1]), segments.drop(3).joinToString("/").let(::decode))
                exchange.requestMethod == "GET" && segments.size == 3 && segments[0] == "api" && segments[1] == "jobs" ->
                    exchange.sendJson(200, encodeJob(store.get(decode(segments[2]))))
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
        if (!runningJobs.add(job.id)) {
            exchange.sendHtml(409, renderErrorPage(409, "Analysis already running", "This job already has an active exploration run."))
            return
        }
        store.updateStatus(job.id, "queued", "Waiting for an analysis worker")
        try {
            analysisExecutor.execute {
                try {
                    val active = store.updateStatus(job.id, "analyzing", "Generating and executing candidate inputs")
                    analyzer.analyze(active, store.reportsDirectory(job.id))
                    store.updateStatus(job.id, "complete", "Exploration completed successfully")
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
    "log", "txt", "c", "h", "md" -> "text/plain; charset=utf-8"
    else -> "application/octet-stream"
}
