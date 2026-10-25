package decompengine.web

import decompengine.jobs.WorkflowAttempt
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException
import kotlinx.serialization.json.*

/** One explicit verification of exact archive bytes against one exact candidate revision. */
internal class WebArchiveVerification(
    val operationId: String, val jobId: String, val runId: String, val revisionId: String,
    val archiveSha256: String, val sourceSha256: String, val metadataVersion: String,
    val idempotencyKey: String, val createdAt: Instant,
) {
    @Volatile var state: String = "queued"
    @Volatile var endedAt: Instant? = null
    @Volatile var failureCode: String? = null
    @Volatile var version: Int = 1
    val verified: Boolean get() = state == "completed"
    val terminal: Boolean get() = state == "completed" || state == "failed" || state == "interrupted"
}

/**
 * Source-archive status and explicit verification operations for persisted candidates.
 *
 * "Verified" is reported only for the exact archive digest and revision metadata a completed operation checked with
 * the authoritative [WebArchiveEvidence] verifier: the ZIP extracts within its limits, its payload equals the current
 * source tree, and the recorded build contract still matches the retained executable. That is an integrity and
 * identity check of source bytes; it never compiles, runs the subject program, or establishes behavioral fidelity.
 * Records live in memory for this listener; after a restart an archive reads as not verified until checked again.
 */
internal class WebSourceArchives(
    private val revision: (String, String, String) -> WebRevisionSourceSnapshot,
    private val attempt: (String, String) -> WorkflowAttempt,
    private val store: WebArtifactStore,
    private val readContract: (String, String) -> ByteArray?,
    private val verify: (String, String, String) -> WebArchiveSnapshot,
    private val executor: ExecutorService,
    private val clock: Clock = Clock.systemUTC(),
) : AutoCloseable {
    private val records = LinkedHashMap<String, WebArchiveVerification>()
    private val keys = HashMap<String, String>()

    /** Observed digest of the retained archive, or null when no archive file is retained for the attempt. */
    private fun observe(jobId: String, runId: String): Pair<String, Long>? {
        if (!store.present(jobId, runId, ARCHIVE)) return null
        val digest = store.stream(jobId, runId, ARCHIVE, { if (it > MAXIMUM_ARCHIVE_BYTES) throw WebArtifactTooLarge() }, { _, _ -> }, {})
        return digest.sha256 to digest.size
    }

    fun status(basePath: String, jobId: String, runId: String, revisionId: String): JsonObject {
        val snapshot = revision(jobId, runId, revisionId)
        val run = attempt(jobId, runId)
        check(snapshot.reference.jobId == jobId && snapshot.reference.runId == runId && snapshot.reference.revisionId == revisionId)
        var tooLarge = false
        val current = try { observe(jobId, runId) } catch (_: WebArtifactTooLarge) { tooLarge = true; null }
        val history = synchronized(this) { records.values.filter { it.jobId == jobId && it.runId == runId && it.revisionId == revisionId }.toList() }
        fun matches(record: WebArchiveVerification) = current != null && record.archiveSha256 == current.first && record.metadataVersion == snapshot.metadataVersion
        val latest = history.lastOrNull(::matches)
        // "stale" names a replaced archive only; a metadata-only change of the same bytes just needs a new check.
        val previous = history.lastOrNull { it.verified && current != null && it.archiveSha256 != current.first }
        val state = when {
            current == null -> if (tooLarge) "too-large" else "missing"
            latest == null -> if (previous != null) "stale" else "not-verified"
            latest.verified -> "verified"
            latest.state == "failed" || latest.state == "interrupted" -> "failed"
            else -> "running"
        }
        return buildJsonObject {
            put("binding", buildJsonObject { put("jobId", jobId); put("runId", runId); put("revisionId", revisionId) })
            put("sourceSha256", snapshot.reference.sourceSha256); put("metadataVersion", snapshot.metadataVersion)
            put("archive", buildJsonObject {
                put("state", if (current != null) "present" else if (tooLarge) "too-large" else "missing")
                put("artifactId", current?.let { JsonPrimitive(webArtifactId(jobId, runId, WebArtifactFamily.ARCHIVE, it.first)) } ?: JsonNull)
                put("sha256", current?.let { JsonPrimitive(it.first) } ?: JsonNull)
                put("sizeBytes", current?.let { JsonPrimitive(it.second.toString()) } ?: JsonNull)
                put("contentHref", current?.let { JsonPrimitive("${basePath}api/v1/jobs/$jobId/artifacts/${webArtifactId(jobId, runId, WebArtifactFamily.ARCHIVE, it.first)}/content") } ?: JsonNull)
                put("mediaType", "application/zip")
            })
            put("verification", buildJsonObject {
                put("authority", "archive-verifier")
                put("state", state)
                put("operationId", latest?.operationId?.let(::JsonPrimitive) ?: JsonNull)
                put("verifiedAt", latest?.takeIf { it.verified }?.endedAt?.toString()?.let(::JsonPrimitive) ?: JsonNull)
                put("failureCode", latest?.takeIf { !it.verified }?.failureCode?.let(::JsonPrimitive) ?: JsonNull)
                put("previousVerifiedSha256", previous?.archiveSha256?.takeIf { state == "stale" }?.let(::JsonPrimitive) ?: JsonNull)
            })
            put("build", build(jobId, runId))
            put("acceptance", if (run.acceptedRevision?.revisionId == revisionId) "accepted" else "not-evaluated")
            // Git provenance belongs to the #205 envelope; until a repository records it, the mapping is unavailable.
            put("git", buildJsonObject { put("state", "unavailable"); put("reason", "not-recorded") })
        }
    }

    /** The reconstruction's recorded build: contract and executable digests, never a build run by this read. */
    private fun build(jobId: String, runId: String): JsonObject {
        val bytes = try { readContract(jobId, runId) } catch (failure: Exception) {
            if (failure is InterruptedException) throw failure
            null
        }
        val artifact = bytes?.let { contract ->
            runCatching { (OracleJson.parse(contract, CONTRACT_LIMITS) as JsonObject)["artifact"] as? JsonObject }.getOrNull()
        }
        val sha = (artifact?.get("sha256") as? JsonPrimitive)?.takeIf { it.isString && it.content.matches(SHA256) }?.content
        val size = (artifact?.get("bytes") as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull?.takeIf { it >= 0 }
        return buildJsonObject {
            put("state", if (bytes != null && sha != null && size != null) "recorded" else "not-recorded")
            put("contractSha256", bytes?.let { JsonPrimitive(WebExplorationArtifact.sha256(it)) } ?: JsonNull)
            put("executableSha256", sha?.takeIf { size != null }?.let(::JsonPrimitive) ?: JsonNull)
            put("executableBytes", size?.takeIf { sha != null }?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
        }
    }

    class Started(val record: WebArchiveVerification, val replayed: Boolean)

    /**
     * Admit one verification of the archive digest the caller displayed. A replayed key returns its original
     * operation; the same key with another intent conflicts. A verification already queued or running for the same
     * archive and revision metadata is returned instead of starting a second one.
     */
    fun start(jobId: String, runId: String, revisionId: String, archiveSha256: String, key: String): Started {
        val snapshot = revision(jobId, runId, revisionId)
        val intent = listOf(jobId, runId, revisionId, archiveSha256).joinToString("\u0000")
        synchronized(this) {
            keys[key]?.let { id ->
                val prior = records.getValue(id)
                if (listOf(prior.jobId, prior.runId, prior.revisionId, prior.archiveSha256).joinToString("\u0000") != intent) {
                    throw WebAccessDenied(409, "IDEMPOTENCY_CONFLICT", "The request key was used for a different archive verification.")
                }
                return Started(prior, true)
            }
        }
        val current = try { observe(jobId, runId) } catch (_: WebArtifactTooLarge) {
            throw WebAccessDenied(413, "ARCHIVE_TOO_LARGE", "The retained source archive exceeds the verifier's 64 MiB limit.")
        } ?: throw WebAccessDenied(404, "ARCHIVE_NOT_FOUND", "No source archive is retained for this attempt.")
        if (current.first != archiveSha256) throw WebAccessDenied(409, "ARCHIVE_CHANGED",
            "The retained archive differs from the displayed digest. Refresh the archive status before verifying.")
        synchronized(this) {
            records.values.lastOrNull { !it.terminal && it.jobId == jobId && it.runId == runId && it.revisionId == revisionId &&
                it.archiveSha256 == archiveSha256 && it.metadataVersion == snapshot.metadataVersion }?.let { running ->
                keys[key] = running.operationId // A deduplicated request still binds its key to the returned operation.
                return Started(running, false)
            }
            if (records.values.count { !it.terminal } >= MAXIMUM_ACTIVE) {
                throw WebAccessDenied(429, "ARCHIVE_VERIFICATION_BUSY", "Another archive verification is in progress. Try again after it finishes.")
            }
            val record = WebArchiveVerification("operation_${UUID.randomUUID().toString().replace("-", "")}", jobId, runId, revisionId,
                archiveSha256, snapshot.reference.sourceSha256, snapshot.metadataVersion, key, clock.instant())
            records[record.operationId] = record; keys[key] = record.operationId
            while (records.size > MAXIMUM_RECORDS) {
                val oldest = records.values.firstOrNull { it.terminal } ?: break
                records.remove(oldest.operationId); keys.values.removeAll { it == oldest.operationId }
            }
            try { executor.execute { run(record) } }
            catch (_: RejectedExecutionException) {
                finish(record, "interrupted", "SERVER_STOPPING")
                throw WebAccessDenied(503, "ARCHIVE_VERIFICATION_UNAVAILABLE", "The server is stopping.")
            }
            return Started(record, false)
        }
    }

    private fun run(record: WebArchiveVerification) {
        synchronized(this) { if (record.terminal) return; record.state = "running"; record.version++ }
        val failure = try {
            val verified = verify(record.jobId, record.runId, record.archiveSha256)
            val now = recapture(record)
            when {
                verified.sha256 != record.archiveSha256 -> "ARCHIVE_CHANGED"
                // The archive's own build contract must be the descriptor that binds this revision's source digest.
                verified.contractSha256 != now.descriptorSha256 || now.metadataVersion != record.metadataVersion -> "REVISION_MISMATCH"
                else -> null
            }
        } catch (interrupted: InterruptedException) {
            finish(record, "interrupted", "SERVER_STOPPING"); Thread.currentThread().interrupt(); return
        } catch (denied: WebAccessDenied) { if (denied.code == "SOURCE_REVISION_CHANGED") "REVISION_MISMATCH" else "REVISION_UNAVAILABLE" }
        catch (_: IllegalArgumentException) { "ARCHIVE_INVALID" }
        catch (_: Exception) { "ARCHIVE_UNAVAILABLE" }
        finish(record, if (failure == null) "completed" else "failed", failure)
    }

    /** The shared metadata capture admits one reader; a concurrent page read is waited out, not reported as a failure. */
    private fun recapture(record: WebArchiveVerification): WebRevisionSourceSnapshot {
        repeat(RECAPTURE_ATTEMPTS - 1) {
            try { return revision(record.jobId, record.runId, record.revisionId) }
            catch (busy: WebAccessDenied) { if (busy.code != "SOURCE_CATALOG_BUSY") throw busy }
            Thread.sleep(RECAPTURE_DELAY_MS)
        }
        return revision(record.jobId, record.runId, record.revisionId)
    }

    private fun finish(record: WebArchiveVerification, state: String, failure: String?) = synchronized(this) {
        if (record.terminal) return@synchronized
        record.state = state; record.failureCode = failure; record.endedAt = clock.instant(); record.version++
    }

    fun operation(jobId: String, runId: String, revisionId: String, operationId: String): WebArchiveVerification {
        revision(jobId, runId, revisionId)
        return synchronized(this) { records[operationId]?.takeIf { it.jobId == jobId && it.runId == runId && it.revisionId == revisionId } }
            ?: throw WebAccessDenied(404, "OPERATION_NOT_FOUND", "The archive verification is unavailable. After a restart, request a new verification.")
    }

    override fun close() {
        executor.shutdownNow()
        synchronized(this) { records.values.filter { !it.terminal }.forEach { finish(it, "interrupted", "SERVER_STOPPING") } }
    }

    companion object {
        const val ARCHIVE = "source-tree.zip"
        const val MAXIMUM_ARCHIVE_BYTES = 64L * 1024 * 1024
        const val MAXIMUM_RECORDS = 256
        const val MAXIMUM_ACTIVE = 2
        private const val RECAPTURE_ATTEMPTS = 50
        private const val RECAPTURE_DELAY_MS = 20L
        private val SHA256 = Regex("[a-f0-9]{64}")
        private val CONTRACT_LIMITS = StrictJsonLimits(maximumInputBytes = 1_048_576, maximumCanonicalBytes = 1_048_576,
            maximumDepth = 32, maximumNodes = 100_000, maximumStringBytes = 16 * 1024, maximumTotalStringBytes = 1_048_576)
    }
}

/** Closed operation projection; archive verification has no repository, worktree or Git result object. */
internal fun webArchiveOperation(record: WebArchiveVerification): JsonObject = buildJsonObject {
    put("operationId", record.operationId); put("jobId", record.jobId)
    put("repositoryId", JsonNull); put("worktreeId", JsonNull); put("action", "archive.verify")
    put("state", record.state); put("version", "version_${record.version}")
    put("createdAt", record.createdAt.toString()); put("endedAt", record.endedAt?.toString()?.let(::JsonPrimitive) ?: JsonNull)
    put("resultObjectId", JsonNull); put("recoveryRequired", false)
    put("message", when {
        record.state == "completed" -> JsonPrimitive("The archive digest, payload and recorded build contract match this revision.")
        record.failureCode != null -> JsonPrimitive(ARCHIVE_FAILURE_MESSAGES[record.failureCode] ?: "The archive was not verified.")
        else -> JsonNull
    })
}

internal val ARCHIVE_FAILURE_MESSAGES = mapOf(
    "ARCHIVE_INVALID" to "The archive is incomplete, malformed, or its payload differs from the current source tree or build contract.",
    "ARCHIVE_CHANGED" to "The archive bytes changed during verification.",
    "REVISION_MISMATCH" to "The archive's build contract does not bind this revision's recorded source.",
    "REVISION_UNAVAILABLE" to "The revision metadata could not be captured consistently.",
    "ARCHIVE_UNAVAILABLE" to "The archive could not be read within its limits.",
    "SERVER_STOPPING" to "The server stopped before verification finished.",
)
