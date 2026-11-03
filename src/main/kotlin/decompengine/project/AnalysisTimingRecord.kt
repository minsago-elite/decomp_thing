package decompengine.project

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.nio.file.Files
import java.nio.file.Path
import java.nio.charset.StandardCharsets
import java.util.TreeMap
import java.util.UUID
import kotlin.io.path.createDirectories

/** Diagnostic-only monotonic timings. This record is deliberately separate from cache and archive state. */
internal class AnalysisTimingRecord(
    private val directory: Path,
    private val recoveryMode: String,
    private val analysisToolSha256: String,
    private val configurationSha256: String,
) {
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
            if (sequence != nextWorkerSequence || elapsedNanos == null || elapsedNanos < 0L) {
                telemetryError = "worker timing sequence or monotonic offset is invalid"
                return
            }
            nextWorkerSequence++
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
            put("runId", invocationId)
            put("analysisInvocationId", invocationId)
            put("recoveryMode", recoveryMode)
            put("analysisToolSha256", analysisToolSha256)
            put("configurationSha256", configurationSha256)
            inputSha256?.let { put("inputSha256", it) }
            exporterSha256?.let { put("exporterSha256", it) }
            put("parentTotalElapsedNanos", (System.nanoTime() - startedAtNanos).coerceAtLeast(0L))
            put("terminalStatus", terminalStatus)
            put("spans", JsonArray(spans.toList()))
            put("workerTerminalStatus", workerTerminalStatus ?: "missing")
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
        runCatching {
            directory.createDirectories()
            val path = directory.resolve("$invocationId.json")
            Files.newOutputStream(path, java.nio.file.StandardOpenOption.CREATE_NEW, java.nio.file.StandardOpenOption.WRITE).bufferedWriter().use {
                it.write(document.toString())
                it.newLine()
            }
        }
    }

    private companion object {
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
