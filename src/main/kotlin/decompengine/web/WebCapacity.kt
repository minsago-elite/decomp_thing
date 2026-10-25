package decompengine.web

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.time.Clock
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Admission defaults for one listener. Every bound is finite; the bootstrap and capacity
 * resources report the values in force so clients never infer a limit.
 */
data class WebAdmissionLimits(
    val workerThreads: Int = 16,
    val queueCapacity: Int = 64,
    val responderThreads: Int = 2,
    val listenBacklog: Int = 64,
    /** Time a connection may take to deliver its request line and headers once a worker reads it. */
    val headerDeadlineMs: Long = 10_000,
    /** Whole-exchange deadline (body read, handling and response write) for ordinary requests. */
    val requestDeadlineMs: Long = 30_000,
    /** Whole-exchange deadline for multipart uploads. */
    val uploadDeadlineMs: Long = 120_000,
    val maxHeaderCount: Int = 100,
    val maxHeaderBytes: Int = 32 * 1024,
) {
    init {
        require(workerThreads in 1..256 && queueCapacity in 1..4096 && responderThreads in 1..16)
        require(listenBacklog in 1..4096)
        require(headerDeadlineMs in 50..60_000 && requestDeadlineMs in 50..300_000 && uploadDeadlineMs in 50..600_000)
        require(maxHeaderCount in 8..200 && maxHeaderBytes in 1024..65_536)
    }
}

/** Point-in-time executor occupancy, sampled independently (approximate under concurrency). */
internal data class WebAdmissionSample(val activeWorkers: Int, val queuedRequests: Int, val activeResponders: Int)

/**
 * Aggregate request outcomes for one listener lifetime. Only counts and fixed public error codes are
 * retained: no path, query, header, body, job identity or exception text ever reaches these counters.
 */
internal class WebCapacityMetrics(private val clock: Clock = Clock.systemUTC()) {
    val since: Instant = clock.instant()
    private val successful = AtomicLong()
    private val clientErrors = AtomicLong()
    private val serverErrors = AtomicLong()
    private val unanswered = AtomicLong()
    val overloadResponses = AtomicLong()
    val overloadConnectionsClosed = AtomicLong()
    val headerDeadlineClosures = AtomicLong()
    val requestDeadlineClosures = AtomicLong()
    val headerLimitRejections = AtomicLong()
    private val reasons = ConcurrentHashMap<String, AtomicLong>()

    /** [code] is the public error code of a denial, already from the closed vocabulary or null. */
    fun recordResponse(status: Int, code: String?) {
        when (status) {
            in 100..399 -> successful
            in 400..499 -> clientErrors
            in 500..599 -> serverErrors
            else -> unanswered
        }.incrementAndGet()
        if (status >= 400 && code != null) reasons.computeIfAbsent(publicWebFailureCode(code)) { AtomicLong() }.incrementAndGet()
    }

    fun snapshot(limits: WebAdmissionLimits, sample: WebAdmissionSample, streams: WebStreamResources.Snapshot,
                 streamLimits: WebStreamResources.Limits): JsonObject = buildJsonObject {
        put("schemaVersion", 1)
        put("sampledAt", clock.instant().toString())
        put("since", since.toString())
        put("http", buildJsonObject {
            put("workerLimit", limits.workerThreads)
            put("activeWorkers", sample.activeWorkers.coerceIn(0, limits.workerThreads))
            put("queueCapacity", limits.queueCapacity)
            put("queuedRequests", sample.queuedRequests.coerceIn(0, limits.queueCapacity))
            put("responderLimit", limits.responderThreads)
            put("activeResponders", sample.activeResponders.coerceIn(0, limits.responderThreads))
            put("listenBacklog", limits.listenBacklog)
            put("headerDeadlineMs", limits.headerDeadlineMs.toString())
            put("requestDeadlineMs", limits.requestDeadlineMs.toString())
            put("uploadDeadlineMs", limits.uploadDeadlineMs.toString())
            put("maxHeaderCount", limits.maxHeaderCount)
            put("maxHeaderBytes", limits.maxHeaderBytes)
            put("maxJsonResponseBytes", "1048576")
            put("maxUploadBytes", StreamingMultipartUpload.MAX_REQUEST_BYTES.toString())
        })
        put("streams", buildJsonObject {
            put("limit", streamLimits.maximumConnections)
            put("perSessionLimit", streamLimits.maximumPerSession)
            put("active", streams.active.coerceIn(0, streamLimits.maximumConnections))
            put("lifetimeMs", streamLimits.lifetimeMs.toString())
        })
        put("outcomes", buildJsonObject {
            put("successful", successful.get().toString())
            put("clientErrors", clientErrors.get().toString())
            put("serverErrors", serverErrors.get().toString())
            put("closedWithoutResponse", unanswered.get().toString())
            put("overloadResponses", overloadResponses.get().toString())
            put("overloadConnectionsClosed", overloadConnectionsClosed.get().toString())
            put("headerDeadlineClosures", headerDeadlineClosures.get().toString())
            put("requestDeadlineClosures", requestDeadlineClosures.get().toString())
            put("headerLimitRejections", headerLimitRejections.get().toString())
        })
        put("failureReasons", JsonArray(reasons.entries.sortedBy { it.key }.take(MAXIMUM_REASONS).map { (code, count) ->
            buildJsonObject { put("code", code); put("count", count.get().toString()) }
        }))
    }

    /** One fixed-vocabulary log line; it carries counts only. */
    fun summaryLine(): String = "web-capacity-summary successful=${successful.get()} client_errors=${clientErrors.get()} " +
        "server_errors=${serverErrors.get()} closed_without_response=${unanswered.get()} " +
        "overload_responses=${overloadResponses.get()} overload_closed=${overloadConnectionsClosed.get()} " +
        "header_deadline_closures=${headerDeadlineClosures.get()} request_deadline_closures=${requestDeadlineClosures.get()} " +
        "header_limit_rejections=${headerLimitRejections.get()}"

    companion object {
        const val MAXIMUM_REASONS = 128
    }
}
