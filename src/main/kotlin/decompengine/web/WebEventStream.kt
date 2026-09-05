package decompengine.web

import com.sun.net.httpserver.HttpExchange
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Bounded SSE over the same observational records and signed cursors as JSON polling. */
internal class WebEventStream(
    private val access: LocalWebAccess,
    private val resources: WebStreamResources,
    private val pages: WebProgressPages,
    private val read: (String, String) -> ByteArray,
    private val pollMs: Long = 1000,
    private val heartbeatMs: Long = 15_000,
) {
    init { require(pollMs in 1..1000 && heartbeatMs in 1..15_000) }

    fun open(exchange: HttpExchange, session: AuthorizedWebSession, jobId: String, runId: String, snapshotHref: String) {
        val (query, queryCursor) = WebProgressQuery.parse(exchange.requestURI.rawQuery)
        val headers = exchange.requestHeaders["Last-Event-ID"]
        if (headers != null && (headers.size != 1 || headers.single().length > 128)) {
            throw WebAccessDenied(400, "INVALID_HEADER", "Last-Event-ID must contain one bounded progress cursor.")
        }
        val lastId = headers?.single()
        if (lastId != null && (queryCursor != null || !lastId.matches(Regex("[A-Za-z0-9_-]{1,128}")))) {
            throw WebAccessDenied(400, "INVALID_CURSOR", "Use one resume position: Last-Event-ID, after or cursor.")
        }
        val initialCursor = lastId ?: queryCursor
        resources.submit(session, AutoCloseable { exchange.close() }) {
            var cursor = initialCursor
            var latestBytes: ByteArray? = null
            fun authorize() {
                val current = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead()))
                if (current.sessionId != session.sessionId) throw WebAccessDenied(401, "SESSION_REQUIRED", "Open a local browser session.")
            }
            fun write(bytes: ByteArray) {
                authorize()
                exchange.responseBody.write(bytes)
                exchange.responseBody.flush()
            }
            try {
                var lastHeartbeat = System.nanoTime()
                while (!Thread.currentThread().isInterrupted) {
                    authorize()
                    val bytes = read(jobId, runId)
                    latestBytes = bytes
                    val raw = "limit=${query.limit}" + (cursor?.let { "&cursor=$it" } ?: "")
                    val page = pages.page(session.sessionId, jobId, runId, bytes, raw)
                    if (exchange.responseCode == -1) {
                        authorize()
                        webApiHeaders(exchange, UUID.randomUUID().toString())
                        exchange.responseHeaders.set("Content-Type", "text/event-stream; charset=utf-8")
                        exchange.responseHeaders.set("X-Accel-Buffering", "no")
                        exchange.sendResponseHeaders(200, 0)
                        write(": connected\n\n".toByteArray())
                    }
                    for (item in page.getValue("items").jsonArray) {
                        val event = item.jsonObject
                        write(webSseFrame(event))
                        cursor = event.getValue("cursor").jsonPrimitive.content
                    }
                    if (System.nanoTime() - lastHeartbeat >= TimeUnit.MILLISECONDS.toNanos(heartbeatMs)) {
                        write(": heartbeat\n\n".toByteArray())
                        lastHeartbeat = System.nanoTime()
                    }
                    if (!page.getValue("hasMore").jsonPrimitive.boolean) Thread.sleep(pollMs)
                }
            } catch (failure: WebAccessDenied) {
                if (exchange.responseCode == -1) access.sendDenied(exchange, failure)
                else if (failure.code == "PROGRESS_GAP" && cursor != null && latestBytes != null) {
                    // No id on a gap: it must never advance the browser's acknowledged position.
                    authorize()
                    val boundary = pages.boundary(session.sessionId, jobId, runId, latestBytes)
                    write(webSseFrame(buildJsonObject {
                        put("apiVersion", 1); put("kind", "event"); put("type", "retention.gap")
                        put("jobId", jobId); put("runId", runId); put("cursor", JsonNull); put("sequence", JsonNull)
                        put("occurredAt", Instant.now().toString()); put("originRequestId", JsonNull)
                        put("agentInvocationId", JsonNull); put("agentSequence", JsonNull)
                        put("payload", buildJsonObject {
                            put("requestedCursor", cursor)
                            put("oldestCursor", boundary.oldestCursor?.let(::JsonPrimitive) ?: JsonNull)
                            put("latestCursor", boundary.throughCursor?.let(::JsonPrimitive) ?: JsonNull)
                            put("snapshotHref", snapshotHref)
                        })
                    }))
                }
            } catch (failure: WebJobServiceException) {
                if (exchange.responseCode == -1) {
                    val missing = failure.code in setOf("JOB_NOT_FOUND", "RUN_NOT_FOUND")
                    access.sendDenied(exchange, WebAccessDenied(if (missing) 404 else 503,
                        if (missing) "NOT_FOUND" else "PROGRESS_UNAVAILABLE", "The requested progress is unavailable."))
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            } catch (_: Exception) {
                if (exchange.responseCode == -1) access.sendDenied(exchange,
                    WebAccessDenied(503, "PROGRESS_UNAVAILABLE", "The requested progress is unavailable."))
            }
        }
    }
}

/** Serialize only already-projected events; fixed line fields cannot alter SSE framing. */
internal fun webSseFrame(event: JsonObject): ByteArray {
    val type = event.getValue("type").jsonPrimitive.content
    require(type in setOf("workflow.observation", "retention.gap"))
    val cursor = event.getValue("cursor")
    val id = if (type == "retention.gap") {
        require(cursor == JsonNull && event.getValue("sequence") == JsonNull)
        ""
    } else {
        require(cursor is JsonPrimitive && cursor.isString)
        val value = cursor.content
        require(value.matches(Regex("[A-Za-z0-9_-]{1,128}")))
        "id: $value\n"
    }
    val data = event.toString().toByteArray(Charsets.UTF_8)
    require(data.size <= 65_536)
    return (id + "event: $type\ndata: ").toByteArray(Charsets.UTF_8) + data + "\n\n".toByteArray()
}
