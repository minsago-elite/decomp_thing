package decompengine.jobs

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls as Linux
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

enum class JobDeletionState(val wireName: String, val terminal: Boolean) {
    ACCEPTED("queued", false), RUNNING("running", false), COMPLETED("completed", true), FAILED("failed", true),
}

/**
 * Durable audit record of one authorized job deletion. It keeps the job identity, a
 * domain-separated actor digest, request digests, timing and the purged byte count. It never
 * retains the filename, label, binary facts or any report content of the removed job.
 */
data class JobDeletionOperation(
    val operationId: String,
    val jobId: String,
    val state: JobDeletionState,
    val revision: Long,
    val createdAt: Instant,
    val endedAt: Instant?,
    internal val actorDigest: String,
    internal val keyDigest: String,
    internal val requestDigest: String,
    val removedBytes: Long,
    val removedEntries: Long,
    val failureCode: String?,
) {
    init {
        require(operationId.matches(OPERATION_ID) && jobId.matches(JOB_IDENTITY))
        require(listOf(actorDigest, keyDigest, requestDigest).all { it.matches(Regex("[0-9a-f]{64}")) })
        require(revision >= 1 && removedBytes >= 0 && removedEntries >= 0)
        require(state.terminal == (endedAt != null)) { "deletion end time must match its state" }
        require((failureCode != null) == (state == JobDeletionState.FAILED)) { "deletion failure code must match its state" }
        require(failureCode == null || failureCode.matches(Regex("[A-Z][A-Z0-9_]{0,63}")))
    }

    internal fun toJson(): JsonObject = buildJsonObject {
        put("schemaVersion", 1); put("operationId", operationId); put("jobId", jobId); put("state", state.name)
        put("revision", revision); put("createdAt", createdAt.toString())
        put("endedAt", endedAt?.toString()?.let(::JsonPrimitive) ?: JsonNull)
        put("actorDigest", actorDigest); put("keyDigest", keyDigest); put("requestDigest", requestDigest)
        put("removedBytes", removedBytes.toString()); put("removedEntries", removedEntries.toString())
        put("failureCode", failureCode?.let(::JsonPrimitive) ?: JsonNull)
    }

    companion object {
        internal val OPERATION_ID = Regex("jobdel_[0-9a-f]{32}")
        private val JOB_IDENTITY = Regex("[0-9a-f]{32}")
        internal val LIMITS = StrictJsonLimits(8192, 8192, 4, 64, 512, 8192, 32)

        internal fun decode(bytes: ByteArray): JobDeletionOperation {
            val value = OracleJson.parse(bytes, LIMITS).jsonObject
            require(value.keys == setOf("schemaVersion", "operationId", "jobId", "state", "revision", "createdAt", "endedAt",
                "actorDigest", "keyDigest", "requestDigest", "removedBytes", "removedEntries", "failureCode")) { "deletion record fields are invalid" }
            fun text(name: String) = value.getValue(name).jsonPrimitive.also { require(it.isString) }.content
            fun optional(name: String) = value.getValue(name).takeUnless { it == JsonNull }?.let { text(name) }
            fun count(name: String) = text(name).also { require(it.matches(Regex("0|[1-9][0-9]{0,18}"))) }.toLong()
            require(value.getValue("schemaVersion").jsonPrimitive.let { !it.isString && it.content == "1" })
            return JobDeletionOperation(text("operationId"), text("jobId"), JobDeletionState.valueOf(text("state")),
                requireNotNull(value.getValue("revision").jsonPrimitive.also { require(!it.isString) }.longOrNull),
                Instant.parse(text("createdAt")), optional("endedAt")?.let(Instant::parse), text("actorDigest"), text("keyDigest"),
                text("requestDigest"), count("removedBytes"), count("removedEntries"), optional("failureCode"))
        }
    }
}

internal enum class JobDeletionFaultPoint { BEFORE_INTENT, BEFORE_DETACH, AFTER_DETACH, PURGE_ENTRY, BEFORE_COMPLETION }
internal fun interface JobDeletionFaults { @Throws(IOException::class) fun hit(point: JobDeletionFaultPoint) }

internal class JobDeletionCapacityException : IllegalStateException("deletion record capacity")
internal class JobDeletionKeyConflictException : IllegalStateException("deletion key conflict")
/** The owned subtree contained an entry this cleanup must not traverse (mount, foreign owner, special file). */
internal class JobDeletionContainmentException(message: String) : IOException(message)

/**
 * Restart-safe deletion journal under the exclusively owned job root. Order: durable intent
 * record, atomic no-replace rename of the job directory into `.job-deletions/<id>.removing`
 * (the job disappears from every listing and lookup at once), then a descriptor-relative purge
 * that never follows links or crosses mounts, then a terminal record. Each step is idempotent so
 * startup and periodic maintenance can resume an interrupted purge. The caller serializes all
 * record changes under its storage monitor; only [purge] runs outside it.
 */
internal class JobDeletionStore(
    private val root: Path,
    private val clock: Clock = Clock.systemUTC(),
    private val faults: JobDeletionFaults = JobDeletionFaults {},
    private val newOperationId: () -> String = { "jobdel_" + UUID.randomUUID().toString().replace("-", "") },
    /** Fixture seam only; production compares every descendant's owner with the owned root. */
    private val owned: (name: String, entry: decompengine.acp.LinuxFileIdentity, root: decompengine.acp.LinuxFileIdentity) -> Boolean =
        { _, entry, root -> entry.uid == root.uid },
) {
    private val directory = root.resolve(DIRECTORY)
    private val records = linkedMapOf<String, JobDeletionOperation>()
    private var loaded = false

    /** Bounded, complete load. An unreadable record fails closed rather than forgetting a key. */
    fun load() {
        records.clear(); loaded = false
        if (!Files.exists(directory, NOFOLLOW_LINKS)) { loaded = true; return }
        if (!Files.isDirectory(directory, NOFOLLOW_LINKS)) throw WorkflowStoreException("INVALID_STORAGE_ENTRY", "The deletion journal is not an owned directory.")
        var entries = 0
        Files.newDirectoryStream(directory).use { stream ->
            for (entry in stream) {
                if (++entries > MAX_RECORDS * 3) throw WorkflowStoreException("STORE_LIMIT", "The deletion journal exceeds its entry limit.")
                val name = entry.fileName.toString()
                if (!name.endsWith(".json")) continue
                val id = name.removeSuffix(".json")
                if (!JobDeletionOperation.OPERATION_ID.matches(id)) continue
                val record = try {
                    JobDeletionOperation.decode(decompengine.repair.readStableRegularFile(root, "$DIRECTORY/$name", 8192).bytes)
                } catch (failure: Exception) {
                    throw WorkflowStoreException("CORRUPT_DELETION_RECORD", "A deletion record is invalid; preserve the deletion journal before retrying.", cause = failure)
                }
                require(record.operationId == id)
                records[id] = record
            }
        }
        loaded = true
    }

    private fun requireLoaded() { check(loaded) { "deletion journal is not loaded" } }
    fun all(): List<JobDeletionOperation> { requireLoaded(); return records.values.sortedBy { it.createdAt } }
    fun get(operationId: String): JobDeletionOperation? { requireLoaded(); return records[operationId] }
    fun latestForJob(jobId: String): JobDeletionOperation? { requireLoaded(); return records.values.filter { it.jobId == jobId }.maxByOrNull { it.createdAt } }
    /** A completed record is the tombstone that lets readers distinguish "deleted" from "never existed". */
    fun deleted(jobId: String): JobDeletionOperation? = latestForJob(jobId)?.takeIf {
        // A containment stop happens after detachment: the job is gone even though bytes were preserved.
        it.state == JobDeletionState.COMPLETED || it.state == JobDeletionState.RUNNING || it.failureCode == "CLEANUP_CONTAINMENT"
    }
    fun pending(): List<JobDeletionOperation> = all().filter { !it.state.terminal }

    fun replay(keyDigest: String, requestDigest: String): JobDeletionOperation? {
        requireLoaded()
        val existing = records.values.firstOrNull { it.keyDigest == keyDigest } ?: return null
        if (existing.requestDigest != requestDigest) throw JobDeletionKeyConflictException()
        return existing
    }

    fun purgeDirectoryExists(operationId: String): Boolean = Files.exists(directory.resolve("$operationId.removing"), NOFOLLOW_LINKS)

    /** Record the intent durably. Nothing about the job has changed if this throws. */
    fun admit(jobId: String, actorDigest: String, keyDigest: String, requestDigest: String): JobDeletionOperation {
        requireLoaded()
        val now = clock.instant()
        if (records.size >= MAX_RECORDS) {
            val evictable = records.values.filter { it.state.terminal && Duration.between(checkNotNull(it.endedAt), now) >= TOMBSTONE_RETENTION }
                .minByOrNull { it.createdAt } ?: throw JobDeletionCapacityException()
            try { Files.deleteIfExists(directory.resolve("${evictable.operationId}.json")) }
            catch (failure: IOException) { throw JobStorageWriteException(false, failure) }
            records.remove(evictable.operationId)
        }
        val operation = JobDeletionOperation(newOperationId(), jobId, JobDeletionState.ACCEPTED, 1, now, null,
            actorDigest, keyDigest, requestDigest, 0, 0, null)
        try {
            faults.hit(JobDeletionFaultPoint.BEFORE_INTENT)
            if (!Files.exists(directory, NOFOLLOW_LINKS)) {
                Files.createDirectory(directory)
                force(root)
            }
            write(operation)
        } catch (failure: JobStorageWriteException) { throw failure }
        catch (failure: IOException) { throw JobStorageWriteException(false, failure) }
        records[operation.operationId] = operation
        return operation
    }

    /** Atomically remove the job from the library namespace. Returns the running record. */
    fun detach(operation: JobDeletionOperation): JobDeletionOperation {
        try {
            faults.hit(JobDeletionFaultPoint.BEFORE_DETACH)
            Linux.openRoot(root).use { rootDirectory ->
                Linux.openDirectoryAt(rootDirectory.fd, DIRECTORY).use { journal ->
                    Linux.renameNoReplace(rootDirectory.fd, operation.jobId, journal.fd, "${operation.operationId}.removing")
                    Linux.synchronize(rootDirectory)
                    Linux.synchronize(journal)
                }
            }
        } catch (failure: IOException) {
            if (!purgeDirectoryExists(operation.operationId)) {
                // The rename did not happen: retain the job and finish the audit record as failed.
                finish(operation, JobDeletionState.FAILED, failureCode = "STORAGE_UNAVAILABLE")
                throw JobStorageWriteException(false, failure)
            }
        }
        val running = operation.copy(state = JobDeletionState.RUNNING, revision = operation.revision + 1)
        records[running.operationId] = running
        try { faults.hit(JobDeletionFaultPoint.AFTER_DETACH); write(running) } catch (_: IOException) {
            // The accepted record plus the detached directory is enough for resume to finish.
        }
        return running
    }

    data class PurgeResult(val complete: Boolean, val bytes: Long, val entries: Long, val failureCode: String?)

    /** Runs without the caller's monitor. Only this operation's detached directory is touched. */
    fun purge(operation: JobDeletionOperation, check: () -> Boolean, maximumNanos: Long = 10_000_000_000L): PurgeResult {
        val started = System.nanoTime()
        var bytes = 0L
        var entries = 0L
        val name = "${operation.operationId}.removing"
        fun proceed(): Boolean = check() && System.nanoTime() - started < maximumNanos && !Thread.currentThread().isInterrupted
        try {
            Linux.openRoot(root).use { rootDirectory ->
                Linux.openDirectoryAt(rootDirectory.fd, DIRECTORY).use { journal ->
                    val top = Linux.openPathAtOrNull(journal.fd, name) ?: return PurgeResult(true, 0, 0, null)
                    top.use { pinned ->
                        val identity = pinned.identity
                        if (identity.isSymbolicLink || !identity.isDirectory || identity.mountId != rootDirectory.identity.mountId ||
                            identity.uid != rootDirectory.identity.uid) throw JobDeletionContainmentException("detached job directory is not owned")
                        fun clear(directory: LinuxDescriptor, depth: Int): Boolean {
                            if (depth > 64) throw JobDeletionContainmentException("detached job tree is too deep")
                            for (child in Linux.directoryEntryNames(directory, 200_000)) {
                                if (!proceed()) return false
                                faults.hit(JobDeletionFaultPoint.PURGE_ENTRY)
                                val entry = Linux.openPathAtOrNull(directory.fd, child) ?: continue
                                entry.use { selected ->
                                    val current = selected.identity
                                    // A foreign-owned entry is never removed or traversed, even when permissions would allow it.
                                    if (!owned(child, current, rootDirectory.identity)) throw JobDeletionContainmentException("job tree contains a foreign-owned entry")
                                    if (current.isDirectory && !current.isSymbolicLink) {
                                        if (current.mountId != rootDirectory.identity.mountId) throw JobDeletionContainmentException("job tree crosses a mount")
                                        Linux.openDirectoryAt(directory.fd, child).use { opened ->
                                            if (opened.identity != current) throw JobDeletionContainmentException("job directory changed during cleanup")
                                            if (!clear(opened, depth + 1)) return false
                                        }
                                        Linux.removeDirectory(directory.fd, child)
                                    } else {
                                        // Links (symbolic or hard) are removed as names; their targets are never opened.
                                        val size = if (current.isRegularFile && !current.isSymbolicLink) Files.size(Linux.descriptorPath(selected)) else 0L
                                        Linux.unlink(directory.fd, child)
                                        bytes += size // Charged only once the name is really gone, so retries never double-count.
                                    }
                                    entries++
                                }
                            }
                            Linux.synchronize(directory)
                            return true
                        }
                        Linux.openDirectoryAt(journal.fd, name).use { opened ->
                            if (opened.identity != identity) throw JobDeletionContainmentException("detached job directory changed")
                            if (!clear(opened, 0)) return PurgeResult(false, bytes, entries, null)
                        }
                        Linux.removeDirectory(journal.fd, name)
                        Linux.synchronize(journal)
                    }
                }
            }
        } catch (failure: JobDeletionContainmentException) {
            return PurgeResult(false, bytes, entries, "CLEANUP_CONTAINMENT")
        } catch (_: IOException) {
            return PurgeResult(false, bytes, entries, "STORAGE_UNAVAILABLE")
        }
        return PurgeResult(true, bytes, entries, null)
    }

    /** Fold one purge pass into the durable record. Incomplete passes stay running for resume. */
    fun record(operation: JobDeletionOperation, result: PurgeResult): JobDeletionOperation {
        val current = records[operation.operationId] ?: operation
        val accumulated = current.copy(removedBytes = saturatingAdd(current.removedBytes, result.bytes),
            removedEntries = saturatingAdd(current.removedEntries, result.entries))
        return when {
            result.complete -> finish(accumulated, JobDeletionState.COMPLETED)
            result.failureCode == "CLEANUP_CONTAINMENT" -> finish(accumulated, JobDeletionState.FAILED, failureCode = "CLEANUP_CONTAINMENT")
            else -> {
                val next = accumulated.copy(revision = accumulated.revision + 1)
                records[next.operationId] = next
                try { write(next) } catch (_: IOException) { }
                next
            }
        }
    }

    /** Reconcile one interrupted record after restart; never re-deletes a job whose rename did not happen. */
    fun reconcileBeforePurge(operation: JobDeletionOperation): JobDeletionOperation {
        if (operation.state != JobDeletionState.ACCEPTED) return operation
        return if (purgeDirectoryExists(operation.operationId)) {
            operation.copy(state = JobDeletionState.RUNNING, revision = operation.revision + 1).also {
                records[it.operationId] = it
                try { write(it) } catch (_: IOException) { }
            }
        } else if (Files.exists(root.resolve(operation.jobId), NOFOLLOW_LINKS)) {
            finish(operation, JobDeletionState.FAILED, failureCode = "INTERRUPTED_BEFORE_REMOVAL")
        } else {
            // Neither the job nor its detached directory remains: the rename and purge both happened but
            // their records were never persisted (for example, a full disk). The job is gone; keep the tombstone.
            finish(operation, JobDeletionState.COMPLETED)
        }
    }

    private fun finish(operation: JobDeletionOperation, state: JobDeletionState, failureCode: String? = null): JobDeletionOperation {
        val terminal = operation.copy(state = state, revision = operation.revision + 1, endedAt = clock.instant(), failureCode = failureCode)
        records[terminal.operationId] = terminal
        try { faults.hit(JobDeletionFaultPoint.BEFORE_COMPLETION); write(terminal) } catch (_: IOException) {
            // Disk-full or read-only: the earlier record remains valid and resume re-derives this state.
        }
        return terminal
    }

    private fun write(operation: JobDeletionOperation) {
        val bytes = OracleJson.canonicalBytes(operation.toJson(), JobDeletionOperation.LIMITS)
        val temporary = Files.createTempFile(directory, ".job-deletion-", ".tmp")
        try {
            FileChannel.open(temporary, WRITE).use { channel ->
                val buffer = java.nio.ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            Files.move(temporary, directory.resolve("${operation.operationId}.json"), ATOMIC_MOVE, REPLACE_EXISTING)
            force(directory)
        } finally {
            try { Files.deleteIfExists(temporary) } catch (_: IOException) { }
        }
    }

    private fun force(path: Path) { FileChannel.open(path, READ).use { it.force(true) } }

    companion object {
        const val DIRECTORY = ".job-deletions"
        internal const val MAX_RECORDS = 1024
        val TOMBSTONE_RETENTION: Duration = Duration.ofHours(24)
        private fun saturatingAdd(left: Long, right: Long) = if (Long.MAX_VALUE - left < right) Long.MAX_VALUE else left + right
    }
}
