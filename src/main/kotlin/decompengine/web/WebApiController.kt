package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.jobs.Job
import decompengine.jobs.JobStoreException
import decompengine.jobs.toJson
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.MessageDigest
import java.util.UUID

/** Versioned presentation only. Job paths and workflow adapters never enter a JSON response. */
internal class WebApiController(
    private val access: LocalWebAccess,
    private val assets: EmbeddedWebAssets,
    private val jobs: WebJobService,
) {
    private val prefix = "${assets.basePath}api/v1/"
    private val applicationBuildId = applicationBuildId()
    private val uploadProgress = WebUploadProgress()
    private val runPages = WebRunPages { jobId ->
        when (val inspection = jobs.inspectDurableJob(jobId)) {
            is decompengine.jobs.WorkflowJobInspection.Available -> inspection.snapshot
            is decompengine.jobs.WorkflowJobInspection.Unavailable -> throw WebJobServiceException(inspection.diagnostic.code, inspection.diagnostic.message)
        }
    }
    private val jobPages = WebJobPages(jobs::collectionRecords)

    fun route(exchange: HttpExchange): Boolean {
        val path = exchange.requestURI.rawPath
        if (!path.startsWith("${assets.basePath}api/")) return false
        val resource = path.removePrefix(prefix)
        if (!path.startsWith(prefix) || !(resource in setOf("session", "bootstrap", "jobs") || resource.matches(Regex("(?:jobs|uploads)/[^/]+|jobs/[^/]+/runs(?:/[^/]+(?:/reports/exploration)?)?")))) {
            try {
                val policy = if (exchange.requestMethod in setOf("POST", "PUT", "PATCH", "DELETE")) {
                    WebEndpointPolicy.jsonMutation(exchange.requestMethod)
                } else WebEndpointPolicy.privateRead(allowHead = true)
                access.authorize(exchange, policy)
                access.sendDenied(exchange, WebAccessDenied(404, "NOT_FOUND", "The requested API route is unavailable."))
            } catch (failure: WebAccessDenied) {
                access.sendDenied(exchange, failure)
            }
            return true
        }
        try {
            if (resource == "session") {
                access.authorize(exchange, WebEndpointPolicy.transport(setOf("POST", "DELETE")))
            }
            when {
                resource == "session" && exchange.requestMethod == "POST" -> {
                    requireNoQuery(exchange)
                    requireJsonAccept(exchange)
                    val credentials = access.establishSession(exchange)
                    exchange.responseHeaders.add("Set-Cookie", checkNotNull(credentials.setCookie))
                    send(exchange, 200, "session", buildJsonObject {
                        put("csrfToken", credentials.csrfToken)
                        put("expiresAt", credentials.session.expiresAt.toString())
                    })
                }
                resource == "session" && exchange.requestMethod == "DELETE" -> {
                    requireNoQuery(exchange)
                    requireJsonAccept(exchange)
                    val cookie = access.logout(exchange)
                    exchange.responseHeaders.add("Set-Cookie", cookie)
                    commonHeaders(exchange, UUID.randomUUID().toString())
                    exchange.sendResponseHeaders(204, -1)
                    exchange.close()
                }
                resource == "session" -> throw WebAccessDenied(
                    405, "METHOD_NOT_ALLOWED", "The session endpoint supports POST and DELETE.", setOf("POST", "DELETE"),
                )
                resource == "jobs" && exchange.requestMethod == "POST" -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.multipartUpload()))
                    requireNoQuery(exchange)
                    requireJsonAccept(exchange)
                    val key = singleUploadHeader(exchange, "Idempotency-Key")
                    if (key == null || !key.matches(Regex("[A-Za-z0-9_-]{16,128}"))) throw WebAccessDenied(400, "INVALID_IDEMPOTENCY_KEY", "Upload requires one 16–128 character idempotency key.")
                    if (exchange.requestHeaders.containsKey("If-Match")) throw WebAccessDenied(400, "INVALID_HEADER", "Upload creates a new job and does not accept If-Match.")
                    val length = singleUploadHeader(exchange, "Content-Length")
                    if (length != null && (!length.matches(Regex("0|[1-9][0-9]{0,18}")) || length.toLongOrNull() == null)) throw WebAccessDenied(400, "INVALID_HEADER", "The upload Content-Length is invalid.")
                    val uploadId = singleUploadHeader(exchange, "X-Upload-ID")
                    if (uploadId != null && !uploadId.matches(Regex("[a-f0-9]{32}"))) throw WebAccessDenied(400, "INVALID_UPLOAD_ID", "Upload progress requires one canonical transfer identity.")
                    val progress = uploadId?.let { uploadProgress.begin(session.sessionId, it, length?.toLong()?.takeIf { size -> size <= StreamingMultipartUpload.MAX_REQUEST_BYTES }) }
                    val result = try {
                        jobs.uploadMultipartReceipt(exchange.requestBody, checkNotNull(singleUploadHeader(exchange, "Content-Type")), key, progress)
                            .also { progress?.finish(it.job.id) }
                    } finally { progress?.finish() }
                    exchange.responseHeaders.set("Location", "${assets.basePath}api/v1/jobs/${result.job.id}")
                    if (result.replayed) exchange.responseHeaders.set("Idempotency-Replayed", "true")
                    send(exchange, 201, "job", webJob(result.job))
                }
                resource.startsWith("uploads/") -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead()))
                    requireNoQuery(exchange); requireJsonAccept(exchange)
                    val id = resource.removePrefix("uploads/")
                    if (!id.matches(Regex("[a-f0-9]{32}"))) throw WebAccessDenied(404, "NOT_FOUND", "Upload progress is unavailable.")
                    val progress = uploadProgress.read(session.sessionId, id) ?: throw WebAccessDenied(404, "NOT_FOUND", "Upload progress is unavailable or expired.")
                    send(exchange, 200, "uploadProgress", buildJsonObject {
                        put("uploadId", progress.uploadId); put("receivedBytes", progress.receivedBytes.toString())
                        put("totalBytes", progress.totalBytes?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
                        put("state", progress.state); put("jobId", progress.jobId?.let { JsonPrimitive(it) } ?: JsonNull)
                    })
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+/reports/exploration")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead())
                    requireNoQuery(exchange); requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    val attempt = jobs.getAttempt(parts[1], parts[3])
                    val bytes = try { jobs.readArtifact(parts[1], "reports/runs/${attempt.runId}/exploration.json", 1_048_576).bytes }
                        catch (_: JobStoreException) { null }
                    if (jobs.getAttempt(parts[1], parts[3]).version != attempt.version) throw WebJobServiceException("REPORT_CHANGED", "The attempt changed during this read. Refresh its evidence.")
                    send(exchange, 200, "report", webExplorationReport(parts[1], parts[3], bytes))
                }
                resource.matches(Regex("jobs/[^/]+/runs")) -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead()))
                    requireJsonAccept(exchange)
                    send(exchange, 200, "runs", runPages.page(session.sessionId, resource.split('/')[1], exchange.requestURI.rawQuery))
                }
                resource.matches(Regex("jobs/[^/]+/runs/[^/]+")) -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead())
                    requireNoQuery(exchange); requireJsonAccept(exchange)
                    val parts = resource.split('/')
                    send(exchange, 200, "run", webRun(jobs.getAttempt(parts[1], parts[3])))
                }
                resource == "jobs" -> {
                    val session = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead()))
                    requireJsonAccept(exchange)
                    val (query, cursor) = WebJobQuery.parse(exchange.requestURI.rawQuery)
                    send(exchange, 200, "jobs", jobPages.page(session.sessionId, query, cursor))
                }
                resource == "bootstrap" -> {
                    val credentials = access.csrfForSession(exchange)
                    requireNoQuery(exchange)
                    requireJsonAccept(exchange)
                    send(exchange, 200, "bootstrap", bootstrap(credentials))
                }
                else -> {
                    access.authorize(exchange, WebEndpointPolicy.privateRead())
                    requireNoQuery(exchange)
                    requireJsonAccept(exchange)
                    val value = webJob(jobs.presentation(resource.removePrefix("jobs/")))
                    val etag = "\"${value.getValue("version").let { (it as JsonPrimitive).content }}\""
                    exchange.responseHeaders.set("ETag", etag)
                    if (exchange.requestHeaders.getFirst("If-None-Match") == etag) {
                        commonHeaders(exchange, UUID.randomUUID().toString())
                        exchange.sendResponseHeaders(304, -1)
                        exchange.close()
                    } else send(exchange, 200, "job", value)
                }
            }
        } catch (failure: WebAccessDenied) {
            access.sendDenied(exchange, failure)
        } catch (_: decompengine.jobs.UploadIdempotencyConflict) {
            access.sendDenied(exchange, WebAccessDenied(409, "IDEMPOTENCY_CONFLICT", "The upload key was already used for different content or filename."))
        } catch (_: decompengine.jobs.UploadReceiptUnavailable) {
            access.sendDenied(exchange, WebAccessDenied(503, "UPLOAD_RECEIPT_UNAVAILABLE", "The retained upload receipt is unavailable. Inspect storage before retrying."))
        } catch (failure: UploadBodyException) {
            val status = when (failure.reasonCode) { "UPLOAD_TOO_LARGE" -> 413; "UNSUPPORTED_MEDIA_TYPE" -> 415; else -> 400 }
            access.sendDenied(exchange, WebAccessDenied(status, failure.reasonCode, failure.message ?: "The upload body is invalid."))
        } catch (_: decompengine.jobs.InvalidUploadException) {
            access.sendDenied(exchange, WebAccessDenied(422, "INVALID_ELF", "Upload a supported ELF binary with a complete header."))
        } catch (failure: WebJobServiceException) {
            val status = if (failure.code in setOf("JOB_NOT_FOUND", "RUN_NOT_FOUND")) 404 else 503
            access.sendDenied(exchange, WebAccessDenied(status, if (status == 404) "NOT_FOUND" else failure.code,
                failure.message ?: "Job storage is unavailable."))
        } catch (_: JobStoreException) {
            access.sendDenied(exchange, WebAccessDenied(404, "NOT_FOUND", "The requested job is unavailable."))
        } catch (_: Exception) {
            if (exchange.responseCode != -1) exchange.close()
            else access.sendDenied(exchange, WebAccessDenied(500, "INTERNAL_ERROR", "The request could not be completed."))
        }
        return true
    }

    private fun bootstrap(credentials: WebSessionCredentials): JsonObject = buildJsonObject {
        put("apiVersions", JsonArray(listOf(JsonPrimitive(1))))
        put("applicationBuildId", applicationBuildId)
        put("uiBuildId", assets.manifest.buildId)
        put("basePath", assets.basePath)
        put("readiness", "degraded")
        put("sessionExpiresAt", credentials.session.expiresAt.toString())
        put("csrfToken", credentials.csrfToken)
        put("capabilities", JsonArray(listOf(buildJsonObject {
            put("id", "workflows")
            put("state", "unavailable")
            put("reasonCode", "PREVIEW_UNAVAILABLE")
            put("message", "Workflow actions are unavailable in this preview.")
            put("workflows", JsonArray(emptyList()))
            put("agentContractVersion", JsonNull)
            put("limits", JsonNull)
        })))
        // Configured ceilings for the API profile; unavailable resources remain
        // unavailable until their adapters enforce these limits and are enabled.
        put("limits", buildJsonObject {
            put("requestDeadlineMs", "30000")
            put("uploadDeadlineMs", "120000")
            put("downloadIdleMs", "120000")
            put("maxJsonBytes", "1048576")
            put("maxUploadBytes", StreamingMultipartUpload.MAX_REQUEST_BYTES.toString())
            put("maxSourceChunkBytes", "0")
            put("maxLogChunkBytes", "0")
            put("maxEventCount", "0")
            put("maxEventBytes", "0")
            put("terminalEventRetentionMs", "0")
            put("defaultPageLimit", 50)
            put("maxPageLimit", 200)
        })
        put("runtime", buildJsonObject {
            put("javaVersion", Runtime.version().toString().take(64))
            put("osName", when (System.getProperty("os.name").lowercase()) {
                "linux" -> "linux"
                "mac os x" -> "macos"
                else -> if (System.getProperty("os.name").lowercase().startsWith("windows")) "windows" else "unknown"
            })
            put("architecture", when (System.getProperty("os.arch").lowercase()) {
                "amd64", "x86_64" -> "x86_64"
                "aarch64", "arm64" -> "aarch64"
                else -> "unknown"
            })
            put("gitVersion", JsonNull)
        })
    }

    private fun singleUploadHeader(exchange: HttpExchange, name: String): String? {
        val values = exchange.requestHeaders[name] ?: return null
        if (values.size != 1 || values.single().length > 256) throw WebAccessDenied(400, "INVALID_HEADER", "An upload header is duplicated or too long.")
        return values.single()
    }

    private fun requireNoQuery(exchange: HttpExchange) {
        if (!exchange.requestURI.rawQuery.isNullOrEmpty()) {
            throw WebAccessDenied(400, "VALIDATION_FAILED", "This endpoint does not accept query parameters.")
        }
    }

    private fun requireJsonAccept(exchange: HttpExchange) {
        val values = exchange.requestHeaders["Accept"] ?: return
        if (values.size != 1 || values.single().length > 512) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The Accept header exceeds its limit.")
        }
        val ranges = values.single().split(',').mapNotNull { entry ->
            val parts = entry.trim().lowercase().split(';').map(String::trim)
            val specificity = when (parts[0]) {
                "application/json" -> 2
                "application/*" -> 1
                "*/*" -> 0
                else -> return@mapNotNull null
            }
            if (parts.size > 2) return@mapNotNull null
            val quality = if (parts.size == 1) 1.0 else {
                if (!parts[1].matches(Regex("q=(?:0(?:\\.[0-9]{0,3})?|1(?:\\.0{0,3})?)"))) return@mapNotNull null
                parts[1].removePrefix("q=").toDouble()
            }
            specificity to quality
        }
        val specificity = ranges.maxOfOrNull { it.first }
        val accepted = specificity != null && ranges.filter { it.first == specificity }.any { it.second > 0 }
        if (!accepted) throw WebAccessDenied(406, "NOT_ACCEPTABLE", "This endpoint returns application/json.")
    }

    private fun send(exchange: HttpExchange, status: Int, kind: String, data: JsonElement) {
        val requestId = UUID.randomUUID().toString()
        val body = buildJsonObject {
            put("apiVersion", 1)
            put("kind", kind)
            put("requestId", requestId)
            put("data", data)
        }.toString().toByteArray(Charsets.UTF_8)
        check(body.size <= 1024 * 1024) { "The API response exceeds its byte ceiling" }
        commonHeaders(exchange, requestId)
        exchange.responseHeaders.set("Content-Type", "application/json; charset=utf-8")
        exchange.responseHeaders.set("Content-Length", body.size.toString())
        try {
            if (exchange.requestMethod == "HEAD") exchange.sendResponseHeaders(status, -1)
            else {
                exchange.sendResponseHeaders(status, body.size.toLong())
                exchange.responseBody.use { it.write(body) }
            }
        } finally { exchange.close() }
    }

    private fun commonHeaders(exchange: HttpExchange, requestId: String) {
        exchange.responseHeaders.set("X-Request-ID", requestId)
        exchange.responseHeaders.set("Cache-Control", "no-store")
        exchange.responseHeaders.set("Referrer-Policy", "no-referrer")
        exchange.responseHeaders.set("X-Content-Type-Options", "nosniff")
    }
}

internal fun webJob(presentation: WebJobPresentation): JsonObject {
    val fields = webJob(presentation.job).toMutableMap()
    val snapshot = presentation.snapshot ?: return JsonObject(fields)
    fields["version"] = JsonPrimitive(snapshot.version)
    val latest = snapshot.latestRun
    if (latest != null) {
        fields["status"] = JsonPrimitive(if (latest.state == decompengine.jobs.WorkflowRunState.CANCELLING) "running" else latest.state.wireName)
        fields["latestRunId"] = JsonPrimitive(latest.runId)
        fields["acceptedRevisionId"] = snapshot.acceptedRevision?.revisionId?.let(::JsonPrimitive) ?: JsonNull
    } else if (presentation.legacyInterrupted) {
        fields["status"] = JsonPrimitive("interrupted")
    }
    return JsonObject(fields)
}

internal fun webJob(job: Job): JsonObject = buildJsonObject {
    require(job.sizeBytes >= 0) { "Invalid stored job size" }
    put("jobId", job.id)
    put("displayFilename", job.filename.take(255))
    put("status", when (job.status) {
        "uploaded", "queued", "failed" -> job.status
        "analyzing" -> "running"
        "complete" -> "completed"
        else -> "unknown"
    })
    put("createdAt", job.createdAt)
    put("updatedAt", job.updatedAt)
    put("sizeBytes", job.sizeBytes.toString())
    put("binary", buildJsonObject {
        put("format", job.metadata.format)
        put("endianness", job.metadata.endianness)
        put("objectType", job.metadata.objectType)
        put("machine", job.metadata.machine)
        put("osAbi", job.metadata.osAbi)
        put("entryPoint", "0x${job.metadata.entryPoint.toString(16)}")
    })
    put("version", MessageDigest.getInstance("SHA-256").digest(job.toJson().toString().toByteArray())
        .joinToString("") { "%02x".format(it) })
    put("latestRunId", JsonNull)
    put("acceptedRevisionId", JsonNull)
}

private fun applicationBuildId(): String {
    val source = WebApiController::class.java.protectionDomain.codeSource.location
    if (source.protocol != "file") return "unavailable"
    val path = java.nio.file.Path.of(source.toURI())
    if (!java.nio.file.Files.isRegularFile(path)) return "development"
    val digest = MessageDigest.getInstance("SHA-256")
    java.nio.file.Files.newInputStream(path).use { input ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val size = input.read(buffer)
            if (size < 0) break
            digest.update(buffer, 0, size)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}
