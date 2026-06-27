package decompengine.web

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import decompengine.jobs.InvalidUploadException
import decompengine.jobs.Job
import decompengine.jobs.JobStore
import decompengine.jobs.JobStoreException
import decompengine.jobs.toJson
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.readText

class UploadServer(
    host: String,
    port: Int,
    dataDir: Path,
) {
    private val server = HttpServer.create(InetSocketAddress(host, port), 0)
    private val store = JobStore(dataDir)
    val serverPort: Int get() = server.address.port

    init {
        server.createContext("/") { exchange ->
            when {
                exchange.requestMethod == "GET" && exchange.requestURI.path == "/" -> exchange.sendHtml(200, renderIndex())
                exchange.requestMethod == "GET" && exchange.requestURI.path.startsWith("/jobs/") -> handleGetJob(exchange)
                exchange.requestMethod == "POST" && exchange.requestURI.path == "/jobs" -> handlePostJob(exchange)
                else -> exchange.sendText(404, "not found")
            }
        }
    }

    fun start() = server.start()
    fun stop(delaySeconds: Int = 0) = server.stop(delaySeconds)

    private fun handleGetJob(exchange: HttpExchange) {
        val jobId = URLDecoder.decode(exchange.requestURI.path.removePrefix("/jobs/"), StandardCharsets.UTF_8)
        try {
            exchange.sendHtml(200, renderJob(store.get(jobId)))
        } catch (exception: JobStoreException) {
            exchange.sendText(404, exception.message ?: "job not found")
        }
    }

    private fun handlePostJob(exchange: HttpExchange) {
        try {
            val contentType = exchange.requestHeaders.getFirst("Content-Type") ?: ""
            val upload = MultipartUpload.parse(exchange.requestBody.readBytes(), contentType)
            val job = store.createFromUpload(upload.filename, upload.content)
            if ((exchange.requestHeaders.getFirst("Accept") ?: "").contains("application/json")) {
                exchange.sendJson(201, Json.encodeToString(JsonElement.serializer(), job.toJson()))
            } else {
                exchange.responseHeaders.add("Location", "/jobs/${job.id}")
                exchange.sendResponseHeaders(303, -1)
            }
        } catch (exception: InvalidUploadException) {
            exchange.sendText(400, exception.message ?: "invalid upload")
        } catch (exception: IllegalArgumentException) {
            exchange.sendText(400, exception.message ?: "invalid upload")
        }
    }
}

data class Upload(val filename: String, val content: ByteArray)

object MultipartUpload {
    fun parse(body: ByteArray, contentType: String): Upload {
        require(contentType.startsWith("multipart/form-data")) { "expected multipart/form-data" }
        val boundary = contentType.substringAfter("boundary=", "").trim().trim('"')
        require(boundary.isNotBlank()) { "missing multipart boundary" }
        val delimiter = "--$boundary"
        val text = body.toString(StandardCharsets.ISO_8859_1)
        for (part in text.split(delimiter)) {
            if (!part.contains("name=\"binary\"")) continue
            val headerEnd = part.indexOf("\r\n\r\n")
            require(headerEnd >= 0) { "malformed binary upload part" }
            val headers = part.substring(0, headerEnd)
            val filename = Regex("filename=\"([^\"]*)\"").find(headers)?.groupValues?.get(1)?.ifBlank { "input.elf" } ?: "input.elf"
            var payload = part.substring(headerEnd + 4)
            payload = payload.removeSuffix("\r\n").removeSuffix("--").removeSuffix("\r\n")
            return Upload(filename, payload.toByteArray(StandardCharsets.ISO_8859_1))
        }
        error("missing binary upload field")
    }
}

fun renderIndex(): String = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>decomp_engine</title>
</head>
<body>
  <main>
    <h1>decomp_engine</h1>
    <form action="/jobs" method="post" enctype="multipart/form-data">
      <label for="binary">ELF binary</label>
      <input id="binary" name="binary" type="file" accept=".elf,application/x-elf" required>
      <button type="submit">Upload</button>
    </form>
  </main>
</body>
</html>
"""

fun renderJob(job: Job): String {
    val metadata = job.metadata.toJson().entries.joinToString("\n") { (key, value) ->
        "      <dt>${key.replace('_', ' ').title()}</dt><dd>${value.toString().trim('"').escapeHtml()}</dd>"
    }
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Job ${job.id.escapeHtml()}</title>
</head>
<body>
  <main>
    <h1>Job ${job.id.escapeHtml()}</h1>
    <dl>
      <dt>Status</dt><dd>${job.status.escapeHtml()}</dd>
      <dt>Filename</dt><dd>${job.filename.escapeHtml()}</dd>
      <dt>Size</dt><dd>${job.sizeBytes} bytes</dd>
      <dt>Created</dt><dd>${job.createdAt.escapeHtml()}</dd>
$metadata
    </dl>
    ${renderRepairHistory(job)}
  </main>
</body>
</html>
"""
}

fun renderRepairHistory(job: Job): String {
    val historyPath = job.binaryPath.parent.resolve("reports").resolve("repair_history.json")
    if (!historyPath.exists()) return ""
    val payload = runCatching { Json.parseToJsonElement(historyPath.readText()).jsonObject }.getOrNull()
        ?: return "<section><h2>Repair History</h2><p>Repair history could not be loaded.</p></section>"
    val iterations = payload["iterations"]?.let { it as? JsonArray } ?: return ""
    if (iterations.isEmpty()) return ""
    val items = iterations.mapNotNull { it as? kotlinx.serialization.json.JsonObject }.joinToString("") { iteration ->
        val index = iteration["index"]?.toString()?.escapeHtml() ?: "?"
        val failureKind = iteration["failureKind"]?.toString()?.trim('"')?.escapeHtml() ?: "unknown"
        val summary = iteration["summary"]?.toString()?.trim('"')?.escapeHtml() ?: ""
        val regressions = (iteration["retainedRegressionIds"] as? JsonArray)
            ?.joinToString(", ") { it.toString().trim('"').escapeHtml() }
            ?: ""
        "<li><strong>Iteration $index</strong> <span>$failureKind</span> <p>$summary</p> <p>Regressions: $regressions</p></li>"
    }
    return "<section><h2>Repair History</h2><ol>$items</ol></section>"
}

private fun HttpExchange.sendHtml(status: Int, body: String) = sendBytes(status, body, "text/html; charset=utf-8")
private fun HttpExchange.sendText(status: Int, body: String) = sendBytes(status, body, "text/plain; charset=utf-8")
private fun HttpExchange.sendJson(status: Int, body: String) = sendBytes(status, body, "application/json")

private fun HttpExchange.sendBytes(status: Int, body: String, contentType: String) {
    val bytes = body.toByteArray(StandardCharsets.UTF_8)
    responseHeaders.add("Content-Type", contentType)
    sendResponseHeaders(status, bytes.size.toLong())
    responseBody.use { it.write(bytes) }
}

private fun String.escapeHtml(): String = replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
private fun String.title(): String = split(" ").joinToString(" ") { it.replaceFirstChar { char -> char.uppercase() } }
