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

    fun route(exchange: HttpExchange): Boolean {
        val path = exchange.requestURI.rawPath
        if (!path.startsWith("${assets.basePath}api/")) return false
        val resource = path.removePrefix(prefix)
        if (!path.startsWith(prefix) || !(resource in setOf("session", "bootstrap") || resource.matches(Regex("jobs/[^/]+")))) {
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
                    val job = jobs.get(resource.removePrefix("jobs/"))
                    val value = webJob(job)
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
            put("maxUploadBytes", "0")
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
