package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.acp.AcpPreflightCancelledException
import decompengine.agent.AgentCancellation
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** Public, fixed-vocabulary view of the last explicit agent preflight. */
internal data class WebAgentPreflightSnapshot(val status: String, val inspectionId: String?, val reasonCode: String?)

/**
 * Single-flight, operator-triggered agent preflight. Nothing here runs unless [start] is called, so
 * passive readiness never launches the configured agent. [inspect] performs the preflight and may
 * throw; its exception text, and anything it returns, is discarded so no environment or
 * configuration value can reach a response.
 */
internal class WebAgentPreflight(private val inspect: (AgentCancellation) -> Unit) : AutoCloseable {
    sealed interface Start {
        data class Started(val snapshot: WebAgentPreflightSnapshot) : Start
        data class Busy(val snapshot: WebAgentPreflightSnapshot) : Start
        data object Closed : Start
    }

    private val lock = Any()
    private var current = WebAgentPreflightSnapshot("idle", null, null)
    private var closed = false
    private val cancelled = AtomicBoolean(false)

    fun snapshot(): WebAgentPreflightSnapshot = synchronized(lock) { current }

    fun start(): Start = synchronized(lock) {
        if (closed) return Start.Closed
        if (current.status == "inspecting") return Start.Busy(current)
        val id = UUID.randomUUID().toString().replace("-", "")
        val running = WebAgentPreflightSnapshot("inspecting", id, null)
        current = running
        try {
            Thread({ run(id) }, "decomp-web-agent-preflight").apply { isDaemon = true }.start()
        } catch (_: Throwable) {
            current = WebAgentPreflightSnapshot("failed", id, REASON_FAILED)
        }
        Start.Started(current)
    }

    private fun run(id: String) {
        val outcome = try {
            inspect(AgentCancellation { cancelled.get() })
            WebAgentPreflightSnapshot("ready", id, null)
        } catch (_: AcpPreflightCancelledException) {
            WebAgentPreflightSnapshot("cancelled", id, null)
        } catch (_: Throwable) {
            WebAgentPreflightSnapshot("failed", id, REASON_FAILED)
        }
        synchronized(lock) { if (current.inspectionId == id) current = outcome }
    }

    override fun close() {
        synchronized(lock) { closed = true }
        cancelled.set(true)
    }

    companion object { const val REASON_FAILED = "AGENT_PREFLIGHT_FAILED" }
}

/** `GET`/`POST /api/v1/agent/preflight`: read the last result, or explicitly start one inspection. */
internal class WebAgentPreflightController(
    private val access: LocalWebAccess,
    private val preflight: WebAgentPreflight,
    private val basePath: String,
) {
    fun handle(exchange: HttpExchange) {
        val post = exchange.requestMethod == "POST"
        if (post) access.authorize(exchange, WebEndpointPolicy.jsonMutation("POST"))
        else access.authorize(exchange, WebEndpointPolicy.privateRead())
        requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
        if (!post) {
            send(exchange, 200, preflight.snapshot())
            return
        }
        readRequest(exchange)
        when (val started = preflight.start()) {
            is WebAgentPreflight.Start.Started -> {
                exchange.responseHeaders.set("Location", "${basePath}api/v1/agent/preflight")
                send(exchange, 202, started.snapshot)
            }
            is WebAgentPreflight.Start.Busy ->
                throw WebAccessDenied(409, "AGENT_PREFLIGHT_IN_PROGRESS", "An agent inspection is already running. Read its result.")
            WebAgentPreflight.Start.Closed ->
                throw WebAccessDenied(503, "AGENT_PREFLIGHT_UNAVAILABLE", "The server is stopping.")
        }
    }

    private fun send(exchange: HttpExchange, status: Int, snapshot: WebAgentPreflightSnapshot) {
        sendWebApiResponse(exchange, status, "agentPreflight", buildJsonObject {
            put("status", snapshot.status)
            put("inspectionId", snapshot.inspectionId?.let { JsonPrimitive(it) } ?: JsonNull)
            put("reasonCode", snapshot.reasonCode?.let { JsonPrimitive(it) } ?: JsonNull)
        })
    }

    private fun readRequest(exchange: HttpExchange) {
        val lengths = exchange.requestHeaders["Content-Length"]
        if (lengths != null && (lengths.size != 1 || !lengths.single().matches(Regex("0|[1-9][0-9]{0,18}")) || lengths.single().toLongOrNull() == null)) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request length is invalid.")
        }
        if (lengths != null && lengths.single().toLong() > 1024) throw WebAccessDenied(413, "BODY_TOO_LARGE", "The inspection request exceeds its byte limit.")
        val bytes = exchange.requestBody.use { it.readNBytes(1025) }
        if (bytes.size > 1024) throw WebAccessDenied(413, "BODY_TOO_LARGE", "The inspection request exceeds its byte limit.")
        val value = try { OracleJson.parse(bytes, StrictJsonLimits(1024, 1024, 4, 16, 128, 512, 32)) }
            catch (_: Exception) { throw WebAccessDenied(400, "MALFORMED_JSON", "The inspection request must be a bounded JSON object.") }
        if (value !is JsonObject || value.keys != setOf("action") || value["action"] != JsonPrimitive("inspect"))
            throw WebAccessDenied(422, "VALIDATION_FAILED", "The inspection request must contain only action: inspect.")
    }
}
