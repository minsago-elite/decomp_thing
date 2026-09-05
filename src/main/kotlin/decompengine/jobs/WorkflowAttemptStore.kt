package decompengine.jobs

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.Collections
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.withLock
import kotlin.concurrent.write

enum class WorkflowKind(val wireName: String) { EXPLORE("explore"), RECONSTRUCT("reconstruct"), BUILD("build"), VALIDATE("validate"), REPAIR("repair") }
enum class WorkflowRunState(val wireName: String) {
    QUEUED("queued"), RUNNING("running"), CANCELLING("cancelling"), COMPLETED("completed"), FAILED("failed"), CANCELLED("cancelled"), INTERRUPTED("interrupted");
    val terminal: Boolean get() = this in setOf(COMPLETED, FAILED, CANCELLED, INTERRUPTED)
}
enum class WorkflowTerminalReason { COMPLETED, NO_CHANGES, REFUSED, CANCELLED, LIMIT_EXHAUSTED, FAILED, PROCESS_INTERRUPTED }

data class WorkflowExecutionLimits(val wallClockMs: ULong, val idleMs: ULong, val maxOutputBytes: ULong, val maxToolCalls: ULong) {
    init { require(wallClockMs > 0uL && idleMs > 0uL && idleMs <= wallClockMs && maxOutputBytes > 0uL) { "invalid workflow execution limits" } }
}
data class WorkflowUsage(val inputTokens: ULong? = null, val outputTokens: ULong? = null, val cachedInputTokens: ULong? = null, val toolCalls: ULong? = null, val wallClockMs: ULong? = null)
data class WorkflowCandidate(val revisionId: String, val sourceSha256: String) {
    init { requireId(revisionId); requireSha(sourceSha256) }
}

/** A reference attested by a trusted publication adapter; this store does not validate source or infer acceptance. */
data class WorkflowAcceptanceReference(
    val jobId: String, val runId: String, val revisionId: String, val sourceSha256: String,
    val graphNodeId: String, val artifactId: String, val artifactSha256: String,
) {
    init { requireJobId(jobId); listOf(runId, revisionId, graphNodeId, artifactId).forEach(::requireId); requireSha(sourceSha256); requireSha(artifactSha256) }
}

data class NewWorkflowAttempt(
    val workflow: WorkflowKind, val limits: WorkflowExecutionLimits,
    val inputRevisionId: String? = null, val harnessCapabilityId: String? = null, val previousRunId: String? = null,
) {
    init { listOfNotNull(inputRevisionId, harnessCapabilityId, previousRunId).forEach(::requireId) }
}

data class WorkflowAttempt(
    val runId: String, val jobId: String, val workflow: WorkflowKind, val state: WorkflowRunState, val version: String,
    val createdAt: Instant, val startedAt: Instant?, val endedAt: Instant?, val previousRunId: String?,
    val inputRevisionId: String?, val harnessCapabilityId: String?, val limits: WorkflowExecutionLimits,
    val terminalReason: WorkflowTerminalReason?, val usage: WorkflowUsage?, val candidate: WorkflowCandidate?,
    val acceptedRevision: WorkflowAcceptanceReference?,
) {
    val publicationPending: Boolean get() = state == WorkflowRunState.COMPLETED && candidate != null && acceptedRevision == null
}

sealed interface WorkflowTransition {
    data object Start : WorkflowTransition
    data object RequestCancellation : WorkflowTransition
    data class Finish(val state: WorkflowRunState, val reason: WorkflowTerminalReason, val candidate: WorkflowCandidate? = null, val usage: WorkflowUsage? = null) : WorkflowTransition
}

data class LegacyWorkflowObservation(val originalJobSha256: String, val status: String, val recoveredInterrupted: Boolean)
data class LegacyJobRecord(val jobId: String, val displayFilename: String, val createdAt: Instant, val updatedAt: Instant, val status: String, val sizeBytes: Long)
data class WorkflowJobSnapshot(
    val jobId: String, val version: String, val legacy: LegacyWorkflowObservation, val attempts: List<WorkflowAttempt>,
    val acceptedRevision: WorkflowAcceptanceReference?,
) {
    val latestRun: WorkflowAttempt? get() = attempts.lastOrNull()
}
data class WorkflowStoreDiagnostic(val code: String, val message: String)
sealed interface WorkflowJobInspection {
    val jobId: String
    data class Available(val legacyJob: LegacyJobRecord, val snapshot: WorkflowJobSnapshot, val diagnostics: List<WorkflowStoreDiagnostic>) : WorkflowJobInspection {
        override val jobId: String get() = snapshot.jobId
    }
    data class Unavailable(override val jobId: String, val diagnostic: WorkflowStoreDiagnostic) : WorkflowJobInspection
}
data class WorkflowMutation(val snapshot: WorkflowJobSnapshot, val attempt: WorkflowAttempt)
class WorkflowStoreException(val code: String, message: String, val outcomeUnknown: Boolean = false, cause: Throwable? = null) : RuntimeException(message, cause)

internal enum class WorkflowStoreFaultPoint { AFTER_TEMP_WRITE, AFTER_TEMP_FSYNC, BEFORE_RENAME, AFTER_RENAME, AFTER_DIRECTORY_FSYNC }
internal fun interface WorkflowStoreFaultInjector { fun hit(point: WorkflowStoreFaultPoint) }

/**
 * Owns the storage root for its entire lifetime: a second server cannot recover a live server's work.
 * Original job.json bytes remain migration input and are never rewritten here. All execution,
 * scheduling, artifact registration and authoritative acceptance checks remain outside this store.
 * The configured root and reserved state/lock filenames are application-owned, not upload paths.
 */
class WorkflowAttemptStore private constructor(
    private val root: Path, private val ownerChannel: FileChannel, private val ownerLock: FileLock,
    private val clock: Clock, private val faultInjector: WorkflowStoreFaultInjector, private val ownerToken: Any,
) : AutoCloseable {
    private val lifetime = ReentrantReadWriteLock(true)
    private val stripes = Array(64) { ReentrantLock() }
    private val poisoned = AtomicBoolean()
    private var closed = false

    fun inspect(jobId: String): WorkflowJobInspection = withJob(jobId) { directory -> inspectLocked(jobId, directory) }

    fun create(jobId: String, expectedJobVersion: String, request: NewWorkflowAttempt): WorkflowMutation = withJob(jobId) { directory ->
        val current = available(jobId, directory).snapshot
        checkVersion(current.version, expectedJobVersion)
        requireRecovered(current, directory)
        if (current.attempts.any { !it.state.terminal }) fail("ACTIVE_RUN", "This job already has an active workflow attempt.")
        if (current.attempts.size >= MAX_ATTEMPTS) fail("STORE_LIMIT", "This job reached its retained workflow attempt limit.")
        request.previousRunId?.let { previous ->
            if (current.attempts.none { it.runId == previous && it.state.terminal }) fail("INVALID_PREVIOUS_RUN", "The previous attempt must be a terminal attempt of this job.")
        }
        val attempt = WorkflowAttempt(newId("run"), jobId, request.workflow, WorkflowRunState.QUEUED, newId("version"),
            clock.instant(), null, null, request.previousRunId, request.inputRevisionId, request.harnessCapabilityId,
            request.limits, null, null, null, null)
        val updated = current.copy(version = newId("version"), attempts = immutable(current.attempts + attempt))
        persist(directory, updated)
        WorkflowMutation(updated, attempt)
    }

    fun transition(jobId: String, runId: String, expectedRunVersion: String, transition: WorkflowTransition): WorkflowMutation = withJob(jobId) { directory ->
        val current = available(jobId, directory).snapshot
        requireRecovered(current, directory)
        val old = current.attempts.singleOrNull { it.runId == runId } ?: fail("RUN_NOT_FOUND", "The requested workflow attempt does not belong to this job.")
        checkVersion(old.version, expectedRunVersion)
        if (old.state.terminal) fail("INVALID_TRANSITION", "A terminal attempt is immutable; start a new attempt for a retry.")
        val now = maxOf(clock.instant(), old.startedAt ?: old.createdAt)
        val updatedAttempt = when (transition) {
            WorkflowTransition.Start -> {
                if (old.state != WorkflowRunState.QUEUED) fail("INVALID_TRANSITION", "Only a queued attempt can start.")
                old.copy(state = WorkflowRunState.RUNNING, startedAt = now)
            }
            WorkflowTransition.RequestCancellation -> {
                if (old.state !in setOf(WorkflowRunState.QUEUED, WorkflowRunState.RUNNING)) fail("INVALID_TRANSITION", "Cancellation is already pending.")
                old.copy(state = WorkflowRunState.CANCELLING)
            }
            is WorkflowTransition.Finish -> {
                validateTerminal(transition.state, transition.reason)
                if (old.startedAt == null && transition.state == WorkflowRunState.COMPLETED) {
                    fail("INVALID_TRANSITION", "An unstarted attempt cannot report completed execution.")
                }
                if (old.startedAt == null && transition.candidate != null) fail("INVALID_TRANSITION", "An unstarted attempt cannot publish candidate output.")
                old.copy(state = transition.state, endedAt = now, terminalReason = transition.reason, candidate = transition.candidate, usage = transition.usage)
            }
        }.copy(version = newId("version"))
        val updated = replace(current, updatedAttempt)
        persist(directory, updated)
        WorkflowMutation(updated, updatedAttempt)
    }

    /** Call only after a trusted adapter verifies canonical source, graph and acceptance artifact binding. */
    fun recordAcceptedRevision(jobId: String, runId: String, expectedJobVersion: String, expectedRunVersion: String, reference: WorkflowAcceptanceReference): WorkflowMutation = withJob(jobId) { directory ->
        val current = available(jobId, directory).snapshot
        checkVersion(current.version, expectedJobVersion)
        requireRecovered(current, directory)
        val old = current.attempts.singleOrNull { it.runId == runId } ?: fail("RUN_NOT_FOUND", "The requested workflow attempt does not belong to this job.")
        checkVersion(old.version, expectedRunVersion)
        if (current.latestRun?.runId != runId || old.state != WorkflowRunState.COMPLETED || old.acceptedRevision != null ||
            reference.jobId != jobId || reference.runId != runId || old.candidate != WorkflowCandidate(reference.revisionId, reference.sourceSha256)) {
            fail("ACCEPTANCE_BINDING_CONFLICT", "Acceptance must bind the latest completed candidate and its exact job, attempt and source revision.")
        }
        val attempt = old.copy(version = newId("version"), acceptedRevision = reference)
        val updated = replace(current, attempt).copy(acceptedRevision = reference)
        persist(directory, updated)
        WorkflowMutation(updated, attempt)
    }

    /** Explicit startup operation under the exclusive root lease; it cannot execute or resume a workflow. */
    fun recoverAfterRestart(jobId: String): WorkflowJobInspection = withJob(jobId) { directory ->
        val inspected = inspectLocked(jobId, directory)
        if (inspected !is WorkflowJobInspection.Available) return@withJob inspected
        val current = inspected.snapshot
        removePending(directory)
        val attempts = current.attempts.map { attempt ->
            if (attempt.state.terminal) attempt else attempt.copy(state = WorkflowRunState.INTERRUPTED, version = newId("version"),
                endedAt = maxOf(clock.instant(), attempt.startedAt ?: attempt.createdAt), terminalReason = WorkflowTerminalReason.PROCESS_INTERRUPTED)
        }
        val legacy = current.legacy.let { observation ->
            if (observation.status in setOf("queued", "analyzing") && !observation.recoveredInterrupted) observation.copy(recoveredInterrupted = true) else observation
        }
        if (attempts != current.attempts || legacy != current.legacy) {
            persist(directory, current.copy(version = newId("version"), attempts = immutable(attempts), legacy = legacy))
        }
        inspectLocked(jobId, directory)
    }

    fun recoverAll(): List<WorkflowJobInspection> = lifetime.read {
        ensureOpen()
        val ids = mutableListOf<String>()
        Files.newDirectoryStream(root).use { entries ->
            for (entry in entries) {
                val name = entry.fileName.toString()
                if (JOB_ID.matches(name)) {
                    if (ids.size >= MAX_JOBS) fail("STORE_LIMIT", "The job storage scan exceeds its configured bound.")
                    ids += name
                }
            }
        }
        immutable(ids.sorted().map { id ->
            try { recoverAfterRestart(id) } catch (failure: WorkflowStoreException) {
                if (failure.outcomeUnknown || poisoned.get()) throw failure
                WorkflowJobInspection.Unavailable(id, WorkflowStoreDiagnostic(failure.code, failure.message ?: "Job recovery failed."))
            }
        })
    }

    override fun close() = lifetime.write {
        if (!closed) {
            closed = true
            try { ownerLock.release() } finally {
                try { ownerChannel.close() } finally { JVM_OWNERS.remove(root, ownerToken) }
            }
        }
    }

    private fun inspectLocked(jobId: String, directory: Path): WorkflowJobInspection = try {
        val (legacy, bytes) = readLegacy(jobId, directory)
        val statePath = directory.resolve(STATE_FILE)
        val snapshot = if (Files.exists(statePath, NOFOLLOW_LINKS)) {
            val stateBytes = readRegular(statePath, STATE_BYTES)
            val persisted = parseState(stateBytes, jobId)
            // Before durable migration, legacy adapters can still change job.json. Bind the read/CAS
            // version to both files so a retained recovery sidecar cannot hide a legacy status change.
            if (persisted.attempts.isEmpty()) {
                val digest = MessageDigest.getInstance("SHA-256")
                digest.update("decomp-web-legacy-version-v1\u0000".toByteArray())
                digest.update(stateBytes)
                digest.update(0.toByte())
                digest.update(bytes)
                persisted.copy(version = "legacy_" + digest.digest().joinToString("") { "%02x".format(it) })
            } else persisted
        } else {
            val sha = sha256(bytes)
            WorkflowJobSnapshot(jobId, "legacy_$sha", LegacyWorkflowObservation(sha, legacy.status, false), emptyList(), null)
        }
        val diagnostics = buildList {
            if (snapshot.legacy.status in setOf("queued", "analyzing")) add(WorkflowStoreDiagnostic(
                if (snapshot.legacy.recoveredInterrupted) "LEGACY_INTERRUPTED" else "LEGACY_RECOVERY_REQUIRED",
                "The legacy status has no workflow identity. Its historical operation is unverified; an explicit new attempt is required.",
            ))
            if (snapshot.attempts.any(WorkflowAttempt::publicationPending)) add(WorkflowStoreDiagnostic("PUBLICATION_PENDING", "Completed candidate output awaits canonical publication review; it is not accepted evidence."))
            if (Files.exists(directory.resolve(PENDING_FILE), NOFOLLOW_LINKS)) add(WorkflowStoreDiagnostic("RECOVERY_REQUIRED", "An unpublished state write remains; run startup recovery before admitting work."))
        }
        WorkflowJobInspection.Available(legacy, snapshot, immutable(diagnostics))
    } catch (failure: WorkflowStoreException) {
        WorkflowJobInspection.Unavailable(jobId, WorkflowStoreDiagnostic(failure.code, failure.message ?: "The job record is unavailable."))
    }

    private fun available(jobId: String, directory: Path): WorkflowJobInspection.Available = when (val value = inspectLocked(jobId, directory)) {
        is WorkflowJobInspection.Available -> value
        is WorkflowJobInspection.Unavailable -> fail(value.diagnostic.code, value.diagnostic.message)
    }

    private fun requireRecovered(snapshot: WorkflowJobSnapshot, directory: Path) {
        if ((snapshot.legacy.status in setOf("queued", "analyzing") && !snapshot.legacy.recoveredInterrupted) || Files.exists(directory.resolve(PENDING_FILE), NOFOLLOW_LINKS)) {
            fail("RECOVERY_REQUIRED", "Startup recovery is required before admitting workflow changes.")
        }
    }

    private fun persist(directory: Path, snapshot: WorkflowJobSnapshot) {
        validateSnapshot(snapshot)
        val bytes = try { OracleJson.canonicalBytes(encodeState(snapshot), JSON_LIMITS) } catch (failure: Exception) {
            throw WorkflowStoreException("STORE_LIMIT", "The workflow state exceeds its persistence limits.", cause = failure)
        }
        val target = directory.resolve(STATE_FILE)
        val pending = directory.resolve(PENDING_FILE)
        if (Files.exists(pending, NOFOLLOW_LINKS)) fail("RECOVERY_REQUIRED", "An unpublished state write requires startup recovery.")
        var renameAttempted = false
        var committed = false
        try {
            FileChannel.open(pending, CREATE_NEW, WRITE, NOFOLLOW_LINKS).use { channel ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) channel.write(buffer)
                faultInjector.hit(WorkflowStoreFaultPoint.AFTER_TEMP_WRITE)
                channel.force(true)
                faultInjector.hit(WorkflowStoreFaultPoint.AFTER_TEMP_FSYNC)
            }
            // A provider may throw after changing the directory entry; a failed return cannot prove rollback.
            renameAttempted = true
            faultInjector.hit(WorkflowStoreFaultPoint.BEFORE_RENAME)
            Files.move(pending, target, ATOMIC_MOVE, REPLACE_EXISTING)
            faultInjector.hit(WorkflowStoreFaultPoint.AFTER_RENAME)
            forceDirectory(directory)
            committed = true
            faultInjector.hit(WorkflowStoreFaultPoint.AFTER_DIRECTORY_FSYNC)
        } catch (failure: Throwable) {
            if (failure !is Exception) {
                poisoned.set(true)
                throw failure
            }
            if (committed) return // An ordinary post-commit failure cannot turn a durable admission into failure.
            if (!renameAttempted) {
                try { removePending(directory) } catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
            } else poisoned.set(true)
            throw WorkflowStoreException("PERSISTENCE_FAILED", if (renameAttempted) "Workflow publication may have committed; close and reopen storage to reconcile before retrying." else "Workflow state was not published; the prior durable state is preserved.", renameAttempted, failure)
        }
    }

    private fun removePending(directory: Path) {
        val path = directory.resolve(PENDING_FILE)
        if (Files.exists(path, NOFOLLOW_LINKS)) {
            if (!Files.isRegularFile(path, NOFOLLOW_LINKS) || Files.size(path) > STATE_BYTES) fail("CORRUPT_WORKFLOW_STATE", "The reserved pending state file is invalid; preserve storage for recovery.")
            Files.delete(path)
            forceDirectory(directory)
        }
    }

    private fun readLegacy(jobId: String, directory: Path): Pair<LegacyJobRecord, ByteArray> {
        val path = directory.resolve("job.json")
        if (!Files.exists(path, NOFOLLOW_LINKS)) fail("JOB_NOT_FOUND", "The job has no persisted upload record.")
        val bytes = readRegular(path, LEGACY_BYTES)
        try {
            val root = OracleJson.parse(bytes, JSON_LIMITS.copy(maximumInputBytes = LEGACY_BYTES)).asObject()
            require(root.string("id") == jobId)
            val filename = root.string("filename").also { require(it.length in 1..1024) }
            val status = root.string("status").also { require(it in LEGACY_STATUSES) }
            val created = Instant.parse(root.string("created_at"))
            val updated = root["updated_at"]?.let { Instant.parse(it.stringValue()) } ?: created
            val size = root.number("size_bytes").longOrNull?.also { require(it in 0..Int.MAX_VALUE.toLong()) } ?: error("invalid legacy size")
            root.string("binary_path").also { require(it.length in 1..4096) }
            val metadata = root.getValue("metadata").asObject()
            listOf("format", "endianness", "os_abi", "object_type", "machine").forEach { key -> require(metadata.string(key).length in 1..128) }
            listOf("elf_version", "entry_point", "elf_header_size", "program_header_count", "section_header_count", "section_name_table_index").forEach { key -> require(metadata.number(key).longOrNull != null) }
            // binary_path and arbitrary metadata content never determine a path used by this store.
            return LegacyJobRecord(jobId, filename, created, updated, status, size) to bytes
        } catch (failure: Exception) {
            throw WorkflowStoreException("CORRUPT_LEGACY_JOB", "The legacy upload record is invalid; preserve job.json and restore a verified backup before retrying.", cause = failure)
        }
    }

    private fun parseState(bytes: ByteArray, jobId: String): WorkflowJobSnapshot = try {
        val root = OracleJson.parse(bytes, JSON_LIMITS).asObject()
        if (root.number("schemaVersion").intOrNull != 1) fail("UNSUPPORTED_WORKFLOW_SCHEMA", "This workflow storage version is unsupported; use a compatible application or restore a backup.")
        root.keysExactly("schemaVersion", "jobId", "version", "legacy", "attempts", "acceptedRevision")
        require(root.string("jobId") == jobId)
        val legacy = root.getValue("legacy").asObject().also { it.keysExactly("originalJobSha256", "status", "recoveredInterrupted") }
        val attempts = root.getValue("attempts") as? JsonArray ?: error("invalid attempts")
        require(attempts.size <= MAX_ATTEMPTS)
        WorkflowJobSnapshot(jobId, root.string("version"), LegacyWorkflowObservation(legacy.string("originalJobSha256"), legacy.string("status"), legacy.boolean("recoveredInterrupted")),
            immutable(attempts.map(::parseAttempt)), root.optional("acceptedRevision")?.let(::parseAcceptance)).also(::validateSnapshot)
    } catch (failure: WorkflowStoreException) {
        if (failure.code == "UNSUPPORTED_WORKFLOW_SCHEMA") throw failure
        throw WorkflowStoreException("CORRUPT_WORKFLOW_STATE", "The workflow state has inconsistent lifecycle records; preserve it and restore a verified backup.", cause = failure)
    } catch (failure: Exception) {
        throw WorkflowStoreException("CORRUPT_WORKFLOW_STATE", "The workflow state is invalid; preserve workflow-state.json and restore a verified backup before retrying.", cause = failure)
    }

    private fun <T> withJob(jobId: String, operation: (Path) -> T): T = lifetime.read {
        ensureOpen()
        requireJobId(jobId)
        stripes[(jobId.hashCode() and Int.MAX_VALUE) % stripes.size].withLock {
            ensureOpen()
            val directory = root.resolve(jobId)
            if (!Files.isDirectory(directory, NOFOLLOW_LINKS)) fail("JOB_NOT_FOUND", "The job storage directory is missing or invalid.")
            operation(directory)
        }
    }
    private fun ensureOpen() {
        if (closed) fail("STORE_CLOSED", "Workflow storage ownership has been released.")
        if (poisoned.get()) fail("RECOVERY_REQUIRED", "Workflow storage must be closed and reopened after an uncertain publication.")
    }

    companion object {
        private const val STATE_FILE = "workflow-state.json"
        private const val PENDING_FILE = "workflow-state.pending.json"
        private const val STATE_BYTES = 8 * 1024 * 1024
        private const val LEGACY_BYTES = 1024 * 1024
        private const val MAX_ATTEMPTS = 1024
        private const val MAX_JOBS = 10_000
        private val LEGACY_STATUSES = setOf("uploaded", "queued", "analyzing", "complete", "failed")
        private val JSON_LIMITS = StrictJsonLimits(STATE_BYTES, STATE_BYTES, 32, 100_000, LEGACY_BYTES, STATE_BYTES, 32)
        private val JVM_OWNERS = ConcurrentHashMap<Path, Any>()

        fun open(root: Path, clock: Clock = Clock.systemUTC()): WorkflowAttemptStore = open(root, clock, WorkflowStoreFaultInjector {})
        internal fun open(root: Path, clock: Clock, faultInjector: WorkflowStoreFaultInjector): WorkflowAttemptStore {
            val normalized = root.toAbsolutePath().normalize()
            Files.createDirectories(normalized)
            if (!Files.isDirectory(normalized, NOFOLLOW_LINKS)) fail("INVALID_STORAGE_ROOT", "Workflow storage must be an owned directory.")
            val canonical = normalized.toRealPath()
            val token = Any()
            if (JVM_OWNERS.putIfAbsent(canonical, token) != null) fail("OWNERSHIP_CONFLICT", "Another server owns this job storage; stop it before opening workflow storage.")
            var channel: FileChannel? = null
            try {
                channel = FileChannel.open(canonical.resolve(".workflow-owner.lock"), CREATE, WRITE, NOFOLLOW_LINKS)
                val lock = try { channel.tryLock() } catch (_: OverlappingFileLockException) { null }
                if (lock == null) fail("OWNERSHIP_CONFLICT", "Another server owns this job storage; stop it before opening workflow storage.")
                return WorkflowAttemptStore(canonical, channel, lock, clock, faultInjector, token)
            } catch (failure: Throwable) {
                try { channel?.close() } finally { JVM_OWNERS.remove(canonical, token) }
                throw failure
            }
        }

        private fun readRegular(path: Path, maximum: Int): ByteArray = try {
            if (!Files.isRegularFile(path, NOFOLLOW_LINKS)) fail("INVALID_STORAGE_ENTRY", "A persisted job record is not an owned regular file.")
            FileChannel.open(path, READ, NOFOLLOW_LINKS).use { channel ->
                val size = channel.size()
                if (size > maximum) fail("STORE_LIMIT", "A persisted job record exceeds its byte limit.")
                val buffer = ByteBuffer.allocate(size.toInt())
                while (buffer.hasRemaining()) if (channel.read(buffer) < 0) fail("INVALID_STORAGE_ENTRY", "A persisted job record changed while reading.")
                if (channel.read(ByteBuffer.allocate(1)) != -1) fail("INVALID_STORAGE_ENTRY", "A persisted job record changed while reading.")
                buffer.array()
            }
        } catch (failure: WorkflowStoreException) { throw failure } catch (failure: Exception) {
            throw WorkflowStoreException("INVALID_STORAGE_ENTRY", "A persisted job record could not be read; preserve storage and inspect its permissions or restore a verified backup.", cause = failure)
        }
        private fun forceDirectory(directory: Path) { FileChannel.open(directory, READ).use { it.force(true) } }
        private fun replace(current: WorkflowJobSnapshot, attempt: WorkflowAttempt): WorkflowJobSnapshot =
            current.copy(version = newId("version"), attempts = immutable(current.attempts.map { if (it.runId == attempt.runId) attempt else it }))
        private fun checkVersion(actual: String, expected: String) { if (actual != expected) fail("VERSION_CONFLICT", "The persisted workflow version changed; refresh before applying another transition.") }
        private fun validateTerminal(state: WorkflowRunState, reason: WorkflowTerminalReason) {
            val valid = when (state) {
                WorkflowRunState.COMPLETED -> reason in setOf(WorkflowTerminalReason.COMPLETED, WorkflowTerminalReason.NO_CHANGES)
                WorkflowRunState.FAILED -> reason in setOf(WorkflowTerminalReason.FAILED, WorkflowTerminalReason.REFUSED, WorkflowTerminalReason.LIMIT_EXHAUSTED)
                WorkflowRunState.CANCELLED -> reason == WorkflowTerminalReason.CANCELLED
                WorkflowRunState.INTERRUPTED -> reason == WorkflowTerminalReason.PROCESS_INTERRUPTED
                else -> false
            }
            if (!valid) fail("INVALID_TRANSITION", "The terminal state and reason are inconsistent.")
        }
        private fun validateSnapshot(snapshot: WorkflowJobSnapshot) {
            requireJobId(snapshot.jobId); requireId(snapshot.version); requireSha(snapshot.legacy.originalJobSha256)
            require(snapshot.legacy.status in LEGACY_STATUSES && snapshot.attempts.size <= MAX_ATTEMPTS)
            require(!snapshot.legacy.recoveredInterrupted || snapshot.legacy.status in setOf("queued", "analyzing"))
            require(snapshot.attempts.map(WorkflowAttempt::runId).distinct().size == snapshot.attempts.size)
            require(snapshot.attempts.count { !it.state.terminal } <= 1)
            require(snapshot.attempts.none { !it.state.terminal } || !snapshot.attempts.last().state.terminal)
            val previous = mutableSetOf<String>()
            snapshot.attempts.forEach { attempt ->
                requireId(attempt.runId); requireId(attempt.version); require(attempt.jobId == snapshot.jobId)
                listOfNotNull(attempt.inputRevisionId, attempt.harnessCapabilityId, attempt.previousRunId).forEach(::requireId)
                require(attempt.previousRunId == null || attempt.previousRunId in previous)
                require(attempt.previousRunId == null || snapshot.attempts.first { it.runId == attempt.previousRunId }.state.terminal)
                require(attempt.startedAt == null || attempt.startedAt >= attempt.createdAt)
                if (attempt.state.terminal) {
                    validateTerminal(attempt.state, requireNotNull(attempt.terminalReason))
                    require(attempt.endedAt != null && attempt.endedAt >= (attempt.startedAt ?: attempt.createdAt))
                } else require(attempt.endedAt == null && attempt.terminalReason == null && attempt.candidate == null && attempt.usage == null)
                require(attempt.state != WorkflowRunState.QUEUED || attempt.startedAt == null)
                require(attempt.state != WorkflowRunState.RUNNING || attempt.startedAt != null)
                require(attempt.state != WorkflowRunState.COMPLETED || attempt.startedAt != null)
                require(attempt.candidate == null || attempt.startedAt != null)
                attempt.acceptedRevision?.let { reference ->
                    require(attempt.state == WorkflowRunState.COMPLETED && reference.jobId == snapshot.jobId && reference.runId == attempt.runId)
                    require(attempt.candidate == WorkflowCandidate(reference.revisionId, reference.sourceSha256))
                }
                previous += attempt.runId
            }
            require(snapshot.acceptedRevision == snapshot.attempts.mapNotNull(WorkflowAttempt::acceptedRevision).lastOrNull())
        }

        private fun encodeState(snapshot: WorkflowJobSnapshot): JsonObject = buildJsonObject {
            put("schemaVersion", 1); put("jobId", snapshot.jobId); put("version", snapshot.version)
            put("legacy", buildJsonObject { put("originalJobSha256", snapshot.legacy.originalJobSha256); put("status", snapshot.legacy.status); put("recoveredInterrupted", snapshot.legacy.recoveredInterrupted) })
            put("attempts", JsonArray(snapshot.attempts.map(::encodeAttempt)))
            put("acceptedRevision", snapshot.acceptedRevision?.let(::encodeAcceptance) ?: JsonNull)
        }
        private fun encodeAttempt(a: WorkflowAttempt): JsonObject = buildJsonObject {
            put("runId", a.runId); put("jobId", a.jobId); put("workflow", a.workflow.wireName); put("state", a.state.wireName); put("version", a.version)
            put("createdAt", a.createdAt.toString()); put("startedAt", a.startedAt?.toString()); put("endedAt", a.endedAt?.toString())
            put("previousRunId", a.previousRunId); put("inputRevisionId", a.inputRevisionId); put("harnessCapabilityId", a.harnessCapabilityId)
            put("limits", buildJsonObject { put("wallClockMs", a.limits.wallClockMs.toString()); put("idleMs", a.limits.idleMs.toString()); put("maxOutputBytes", a.limits.maxOutputBytes.toString()); put("maxToolCalls", a.limits.maxToolCalls.toString()) })
            put("terminalReason", a.terminalReason?.name)
            put("usage", a.usage?.let { u -> buildJsonObject { put("inputTokens", u.inputTokens?.toString()); put("outputTokens", u.outputTokens?.toString()); put("cachedInputTokens", u.cachedInputTokens?.toString()); put("toolCalls", u.toolCalls?.toString()); put("wallClockMs", u.wallClockMs?.toString()) } } ?: JsonNull)
            put("candidate", a.candidate?.let { c -> buildJsonObject { put("revisionId", c.revisionId); put("sourceSha256", c.sourceSha256) } } ?: JsonNull)
            put("acceptedRevision", a.acceptedRevision?.let(::encodeAcceptance) ?: JsonNull)
        }
        private fun encodeAcceptance(a: WorkflowAcceptanceReference): JsonObject = buildJsonObject {
            put("jobId", a.jobId); put("runId", a.runId); put("revisionId", a.revisionId); put("sourceSha256", a.sourceSha256)
            put("graphNodeId", a.graphNodeId); put("artifactId", a.artifactId); put("artifactSha256", a.artifactSha256)
        }
        private fun parseAttempt(value: JsonElement): WorkflowAttempt {
            val a = value.asObject().also { it.keysExactly("runId", "jobId", "workflow", "state", "version", "createdAt", "startedAt", "endedAt", "previousRunId", "inputRevisionId", "harnessCapabilityId", "limits", "terminalReason", "usage", "candidate", "acceptedRevision") }
            val limits = a.getValue("limits").asObject().also { it.keysExactly("wallClockMs", "idleMs", "maxOutputBytes", "maxToolCalls") }
            val usage = a.optional("usage")?.asObject()?.also { it.keysExactly("inputTokens", "outputTokens", "cachedInputTokens", "toolCalls", "wallClockMs") }
            val candidate = a.optional("candidate")?.asObject()?.also { it.keysExactly("revisionId", "sourceSha256") }
            return WorkflowAttempt(a.string("runId"), a.string("jobId"), WorkflowKind.entries.single { it.wireName == a.string("workflow") }, WorkflowRunState.entries.single { it.wireName == a.string("state") }, a.string("version"),
                Instant.parse(a.string("createdAt")), a.optionalString("startedAt")?.let(Instant::parse), a.optionalString("endedAt")?.let(Instant::parse), a.optionalString("previousRunId"), a.optionalString("inputRevisionId"), a.optionalString("harnessCapabilityId"),
                WorkflowExecutionLimits(limits.uint("wallClockMs"), limits.uint("idleMs"), limits.uint("maxOutputBytes"), limits.uint("maxToolCalls")), a.optionalString("terminalReason")?.let(WorkflowTerminalReason::valueOf),
                usage?.let { WorkflowUsage(it.optionalUInt("inputTokens"), it.optionalUInt("outputTokens"), it.optionalUInt("cachedInputTokens"), it.optionalUInt("toolCalls"), it.optionalUInt("wallClockMs")) },
                candidate?.let { WorkflowCandidate(it.string("revisionId"), it.string("sourceSha256")) }, a.optional("acceptedRevision")?.let(::parseAcceptance))
        }
        private fun parseAcceptance(value: JsonElement): WorkflowAcceptanceReference {
            val a = value.asObject().also { it.keysExactly("jobId", "runId", "revisionId", "sourceSha256", "graphNodeId", "artifactId", "artifactSha256") }
            return WorkflowAcceptanceReference(a.string("jobId"), a.string("runId"), a.string("revisionId"), a.string("sourceSha256"), a.string("graphNodeId"), a.string("artifactId"), a.string("artifactSha256"))
        }
    }
}

private val JOB_ID = Regex("[0-9a-f]{32}")
private fun requireJobId(value: String) { require(JOB_ID.matches(value)) { "invalid persisted job identity" } }
private fun requireId(value: String) { require(value.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) { "invalid workflow identity" } }
private fun requireSha(value: String) { require(value.matches(Regex("[0-9a-f]{64}"))) { "invalid workflow digest" } }
private fun newId(prefix: String): String = "${prefix}_${UUID.randomUUID().toString().replace("-", "") }"
private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
private fun <T> immutable(values: List<T>): List<T> = Collections.unmodifiableList(values.toList())
private fun fail(code: String, message: String): Nothing = throw WorkflowStoreException(code, message)
private fun JsonElement.asObject(): JsonObject = this as? JsonObject ?: error("object required")
private fun JsonElement.stringValue(): String = (this as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content ?: error("string required")
private fun JsonObject.string(key: String): String = getValue(key).stringValue()
private fun JsonObject.number(key: String): JsonPrimitive = (getValue(key) as? JsonPrimitive)?.takeUnless(JsonPrimitive::isString) ?: error("number required")
private fun JsonObject.boolean(key: String): Boolean = number(key).booleanOrNull ?: error("boolean required")
private fun JsonObject.optional(key: String): JsonElement? = getValue(key).takeUnless { it == JsonNull }
private fun JsonObject.optionalString(key: String): String? = optional(key)?.stringValue()
private fun JsonObject.uint(key: String): ULong = string(key).let { value -> require(value.matches(Regex("0|[1-9][0-9]{0,19}"))); value.toULong() }
private fun JsonObject.optionalUInt(key: String): ULong? = if (optional(key) == null) null else uint(key)
private fun JsonObject.keysExactly(vararg names: String) { require(keys == names.toSet()) { "missing or unknown persisted fields" } }
