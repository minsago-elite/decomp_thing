package decompengine.web

import decompengine.jobs.WorkflowJobInspection
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.time.Clock
import java.util.UUID

/** The explicit scope of one support export; no default scope exists. */
internal sealed interface WebSupportExportScope {
    data object Server : WebSupportExportScope
    data class Job(val jobId: String) : WebSupportExportScope

    companion object {
        private val JOB_ID = Regex("[a-f0-9]{32}")

        /** `scope=server` or `scope=job&jobId=<id>`, each parameter exactly once, nothing else. */
        fun parse(rawQuery: String?): WebSupportExportScope {
            fun invalid(): Nothing = throw WebAccessDenied(400, "VALIDATION_FAILED",
                "A support export requires scope=server or scope=job with one jobId.")
            if (rawQuery.isNullOrEmpty() || rawQuery.length > 256) invalid()
            val pairs = rawQuery.split('&').map { part ->
                val (name, value) = part.split('=', limit = 2).takeIf { it.size == 2 } ?: invalid()
                name to value
            }
            if (pairs.map { it.first }.toSet().size != pairs.size) invalid()
            val values = pairs.toMap()
            return when (values["scope"]) {
                "server" -> if (values.keys == setOf("scope")) Server else invalid()
                "job" -> {
                    val jobId = values["jobId"]
                    if (values.keys != setOf("scope", "jobId") || jobId == null || !JOB_ID.matches(jobId)) invalid()
                    Job(jobId)
                }
                else -> invalid()
            }
        }
    }
}

/**
 * Builds one previewable support export. The document is assembled only from existing public
 * projections (bootstrap runtime/limits/capabilities, the recovery inventory, job and run DTOs and
 * the audit log), then served through the shared redaction policy like every other DTO; the
 * browser downloads exactly the previewed document. Sections that are never exported, and sections
 * that could not be read, are listed in `omittedSections` instead of disappearing silently.
 */
internal class WebSupportExport(
    private val jobs: WebJobService,
    private val audit: WebAuditLog?,
    private val runtime: () -> JsonObject,
    private val limits: () -> JsonObject,
    private val capabilities: () -> JsonArray,
    private val clock: Clock = Clock.systemUTC(),
) {
    fun build(scope: WebSupportExportScope): JsonObject {
        val sections = mutableListOf<JsonObject>()
        val omitted = linkedMapOf<String, String>()
        fun section(id: String, read: () -> JsonElement) {
            try {
                sections += buildJsonObject { put("id", id); put("content", read()) }
            } catch (failure: Exception) {
                if (failure is InterruptedException) Thread.currentThread().interrupt()
                omitted[id] = "unavailable"
            }
        }
        when (scope) {
            WebSupportExportScope.Server -> {
                section("runtime", runtime)
                section("limits", limits)
                section("capabilities", capabilities)
                section("recovery") { jobs.recoveryInventory().toJson() }
                if (audit != null) section("audit") { audit.read(limit = AUDIT_ENTRIES).toJson() } else omitted["audit"] = "unavailable"
                omitted["job"] = "not-in-scope"
                omitted["runs"] = "not-in-scope"
            }
            is WebSupportExportScope.Job -> {
                // A missing job is a sanitized 404, not an export that silently omits everything.
                val job = try { webJob(jobs.presentation(scope.jobId)) } catch (failure: WebJobServiceException) {
                    if (failure.code == "JOB_NOT_FOUND") throw WebAccessDenied(404, "NOT_FOUND", "The requested job is unavailable.")
                    null
                } catch (_: decompengine.jobs.JobStoreException) {
                    throw WebAccessDenied(404, "NOT_FOUND", "The requested job is unavailable.")
                }
                if (job != null) sections += buildJsonObject { put("id", "job"); put("content", job) } else omitted["job"] = "unavailable"
                section("runs") {
                    val attempts = when (val inspection = jobs.inspectDurableJob(scope.jobId)) {
                        is WorkflowJobInspection.Available -> inspection.snapshot.attempts
                        is WorkflowJobInspection.Unavailable -> error("runs unavailable")
                    }
                    buildJsonObject {
                        put("items", JsonArray(attempts.takeLast(RUN_ITEMS).map(::webRun)))
                        put("omittedRuns", maxOf(0, attempts.size - RUN_ITEMS).toString())
                    }
                }
                if (audit != null) section("audit") { audit.read(scope.jobId, AUDIT_ENTRIES).toJson() } else omitted["audit"] = "unavailable"
                omitted["runtime"] = "not-in-scope"
                omitted["limits"] = "not-in-scope"
                omitted["capabilities"] = "not-in-scope"
                omitted["recovery"] = "not-in-scope"
            }
        }
        NEVER_EXPORTED.forEach { (id, reason) -> omitted[id] = reason }
        return buildJsonObject {
            put("schemaVersion", 1)
            put("exportId", UUID.randomUUID().toString())
            put("generatedAt", clock.instant().toString())
            put("redactionVersion", WebRedactionPolicy.VERSION)
            put("scope", buildJsonObject {
                when (scope) {
                    WebSupportExportScope.Server -> { put("kind", "server"); put("jobId", JsonNull) }
                    is WebSupportExportScope.Job -> { put("kind", "job"); put("jobId", JsonPrimitive(scope.jobId)) }
                }
            })
            put("sections", JsonArray(sections))
            put("omittedSections", buildJsonArray {
                omitted.forEach { (id, reason) -> add(buildJsonObject { put("id", id); put("reason", reason) }) }
            })
        }
    }

    companion object {
        const val RUN_ITEMS = 50
        const val AUDIT_ENTRIES = 100

        /** Never part of any support export, whatever the scope. */
        val NEVER_EXPORTED = linkedMapOf(
            "input-binary" to "job-content",
            "source-content" to "job-content",
            "artifact-content" to "job-content",
            "progress-events" to "job-content",
            "environment" to "private-configuration",
            "host-paths" to "private-configuration",
            "credentials" to "secret",
            "session-material" to "secret",
            "agent-reasoning" to "not-recorded",
        )
    }
}
