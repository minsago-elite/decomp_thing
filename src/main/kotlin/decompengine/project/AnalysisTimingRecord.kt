package decompengine.project

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.nio.file.Files
import java.nio.file.Path
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
    private val invocationId = UUID.randomUUID().toString()
    private val spans = mutableListOf<JsonObject>()
    private var inputSha256: String? = null
    private var exporterSha256: String? = null
    private var terminalStatus = "incomplete"

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
            put("coverage", buildJsonObject {
                put("complete", false)
                put("missingPhases", JsonArray(listOf(
                    "worker-entry", "application-initialization", "project-import-analysis", "exporter",
                ).map(::JsonPrimitive)))
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
}

internal fun timingConfigurationSha256(parts: List<String>): String {
    val digest = java.security.MessageDigest.getInstance("SHA-256")
        .digest(parts.joinToString("\u0000").toByteArray(Charsets.UTF_8))
    return digest.joinToString("") { "%02x".format(it) }
}
