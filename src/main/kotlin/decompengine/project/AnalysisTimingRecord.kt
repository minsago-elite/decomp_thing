package decompengine.project

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.nio.file.Files
import java.nio.file.Path
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.StandardCopyOption
import java.util.TreeMap
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.io.path.createDirectories

/** Diagnostic-only monotonic timings. This record is deliberately separate from cache and archive state. */
internal class AnalysisTimingRecord(
    private val directory: Path,
    private val recoveryMode: String,
    private val analysisToolSha256: String,
    private val profileSha256: String?,
    private val configurationSha256: String,
    private val publicationExecutor: ExecutorService = SIDECAR_PUBLICATION_EXECUTOR,
    private val publicationWaitMillis: Long = DEFAULT_PUBLICATION_WAIT_MILLIS,
) {
    init {
        require(profileSha256 == null || profileSha256.matches(Regex("[0-9a-f]{64}")))
        require(publicationWaitMillis in 0..5_000)
    }

    private val startedAtNanos = System.nanoTime()
    val invocationId = UUID.randomUUID().toString()
    private val spans = mutableListOf<JsonObject>()
    private val workerSpans = mutableListOf<JsonObject>()
    private var inputSha256: String? = null
    private var exporterSha256: String? = null
    private var terminalStatus = "incomplete"
    private var workerTerminalStatus: String? = null
    private var telemetryTruncated = false
    private var telemetryError: String? = null
    private val openWorkerSpans = TreeMap<String, Long>()
    private var nextWorkerSequence = 0L
    private var lastWorkerElapsedNanos: Long? = null
    private var workerTerminalElapsedNanos: Long? = null

    @Synchronized
    fun bind(inputSha256: String? = this.inputSha256, exporterSha256: String? = this.exporterSha256) {
        this.inputSha256 = inputSha256
        this.exporterSha256 = exporterSha256
    }

    fun <T> measure(phase: String, action: () -> T): T {
        val offset = System.nanoTime() - startedAtNanos
        val began = System.nanoTime()
        var status = "succeeded"
        try {
            return action()
        } catch (failure: Throwable) {
            status = "failed"
            throw failure
        } finally {
            val duration = (System.nanoTime() - began).coerceAtLeast(0L)
            synchronized(this) {
                spans += buildJsonObject {
                    put("phase", phase)
                    put("clockDomain", "parent-monotonic")
                    put("startOffsetNanos", offset.coerceAtLeast(0L))
                    put("durationNanos", duration)
                    put("status", status)
                }
            }
        }
    }

    /** Parse a bounded, framed worker timing stream without allowing telemetry to affect execution. */
    @Synchronized
    fun captureWorkerTelemetry(stdout: ByteArray, truncated: Boolean) {
        telemetryTruncated = telemetryTruncated || truncated
        val prefix = "DECOMP_ANALYSIS_TIMING_V1 "
        var count = 0
        for (line in stdout.toString(StandardCharsets.UTF_8).lineSequence()) {
            if (!line.startsWith(prefix)) continue
            if (workerTerminalStatus != null) {
                telemetryError = "worker timing frame followed the terminal marker"
                return
            }
            if (line.length > 256 || ++count > 64) {
                telemetryTruncated = true
                telemetryError = "worker timing frame bound exceeded"
                return
            }
            val fields = line.removePrefix(prefix).split(' ')
            if (fields.size != 5 || fields[0] != invocationId) {
                telemetryError = "worker timing frame is malformed or belongs to another invocation"
                return
            }
            val sequence = fields[1].toLongOrNull()
            val elapsedNanos = fields[4].toLongOrNull()
            val priorElapsed = lastWorkerElapsedNanos
            if (sequence != nextWorkerSequence || elapsedNanos == null || elapsedNanos < 0L ||
                (priorElapsed != null && elapsedNanos < priorElapsed)) {
                telemetryError = "worker timing sequence or monotonic offset is invalid"
                return
            }
            nextWorkerSequence++
            lastWorkerElapsedNanos = elapsedNanos
            when (fields[2]) {
                "begin" -> {
                    if ((!isWorkerPhase(fields[3])) || openWorkerSpans.putIfAbsent(fields[3], elapsedNanos) != null) {
                        telemetryError = "worker timing phase begin is invalid or duplicated"
                        return
                    }
                }
                "end" -> {
                    val began = openWorkerSpans.remove(fields[3])
                    if (began == null || elapsedNanos < began) {
                        telemetryError = "worker timing phase end has no valid begin"
                        return
                    }
                    workerSpans += buildJsonObject {
                        put("phase", fields[3])
                        put("clockDomain", "worker-monotonic")
                        put("startOffsetNanos", began)
                        put("durationNanos", elapsedNanos - began)
                        put("status", "completed")
                    }
                }
                "terminal" -> {
                    if (fields[3] !in setOf("succeeded", "failed") || workerTerminalStatus != null ||
                        (fields[3] == "succeeded" && openWorkerSpans.isNotEmpty())) {
                        telemetryError = "worker terminal timing marker is invalid"
                        return
                    }
                    openWorkerSpans.forEach { (phase, began) ->
                        workerSpans += buildJsonObject {
                            put("phase", phase)
                            put("clockDomain", "worker-monotonic")
                            put("startOffsetNanos", began)
                            put("durationNanos", (elapsedNanos - began).coerceAtLeast(0L))
                            put("status", "incomplete")
                        }
                    }
                    openWorkerSpans.clear()
                    workerTerminalStatus = fields[3]
                    workerTerminalElapsedNanos = elapsedNanos
                }
                else -> {
                    telemetryError = "worker timing event type is unsupported"
                    return
                }
            }
        }
    }

    @Synchronized
    fun publish(success: Boolean) {
        terminalStatus = if (success) "succeeded" else "failed"
        val document = buildJsonObject {
            put("schemaVersion", 1)
            put("analysisInvocationId", invocationId)
            put("recoveryMode", recoveryMode)
            put("analysisToolSha256", analysisToolSha256)
            profileSha256?.let { put("profileSha256", it) }
            put("configurationSha256", configurationSha256)
            inputSha256?.let { put("inputSha256", it) }
            exporterSha256?.let { put("exporterSha256", it) }
            put("parentTotalElapsedNanos", (System.nanoTime() - startedAtNanos).coerceAtLeast(0L))
            put("terminalStatus", terminalStatus)
            put("spans", JsonArray(spans.toList()))
            put("workerTerminalStatus", workerTerminalStatus ?: "missing")
            workerTerminalElapsedNanos?.let { put("workerTerminalElapsedNanos", it) }
            put("workerSpans", JsonArray(workerSpans.toList()))
            put("coverage", buildJsonObject {
                val expected = setOf("worker-entry-to-parent-permit", "application-initialization",
                    "project-import-analysis-pre-script")
                val observed = workerSpans.map { (it["phase"] as JsonPrimitive).content }.toSet()
                val missing = (expected + if (workerSpans.none { (it["phase"] as JsonPrimitive).content.startsWith("exporter:") }) {
                    setOf("exporter-inclusive")
                } else emptySet()) - observed
                put("complete", missing.isEmpty() && workerTerminalStatus != null && telemetryError == null && !telemetryTruncated)
                put("missingPhases", JsonArray(missing.sorted().map(::JsonPrimitive)))
                put("truncated", telemetryTruncated)
                telemetryError?.let { put("collectionError", it) }
            })
        }
        val encoded = document.toString() + "\n"
        var publication: Future<*>? = null
        runCatching {
            publication = publicationExecutor.submit { publishAtomically(encoded) }
            publication?.get(publicationWaitMillis, TimeUnit.MILLISECONDS)
        }.onFailure { failure ->
            if (failure is TimeoutException) publication?.cancel(true)
            if (failure is InterruptedException) Thread.currentThread().interrupt()
        }
    }

    private fun publishAtomically(encoded: String) {
        var staging: Path? = null
        try {
            directory.createDirectories()
            val target = directory.resolve("$invocationId.json")
            staging = Files.createTempFile(directory, ".$invocationId-", ".tmp")
            Files.newBufferedWriter(staging, StandardCharsets.UTF_8).use { writer ->
                writer.write(encoded)
            }
            try {
                Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(staging, target)
            }
            staging = null
        } finally {
            staging?.let { runCatching { Files.deleteIfExists(it) } }
        }
    }

    private companion object {
        const val DEFAULT_PUBLICATION_WAIT_MILLIS = 250L
        val SIDECAR_PUBLICATION_EXECUTOR: ExecutorService = ThreadPoolExecutor(
            1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(32), { task ->
                Thread(task, "analysis-timing-sidecar-publisher").apply { isDaemon = true }
            }, ThreadPoolExecutor.AbortPolicy(),
        )

        fun isWorkerPhase(phase: String): Boolean = phase in setOf("worker-entry-to-parent-permit",
            "application-initialization", "project-import-analysis-pre-script") ||
            phase in setOf("exporter:ExportProgramModel.java", "exporter:ExportProgramModelOwned.java",
                "exporter:ExportRecoveredCallSites.java", "exporter:ExportDecompiledC.java",
                "exporter:ExportNativeCallsV1.class", "exporter:ExportNativeInterfacesV1.class")
    }
}

internal fun timingConfigurationSha256(parts: List<String>): String {
    val digest = java.security.MessageDigest.getInstance("SHA-256")
        .digest(parts.joinToString("\u0000").toByteArray(Charsets.UTF_8))
    return digest.joinToString("") { "%02x".format(it) }
}
