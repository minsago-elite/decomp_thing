package decompengine.jobs

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls as Fs
import decompengine.acp.LinuxSyscallException
import kotlinx.serialization.json.*
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.BasicFileAttributes
import java.time.Duration
import java.time.Instant

internal enum class ProgressRetentionResult { RETAINED, NO_JOURNAL, WRITER_ACTIVE, EXPIRED }
internal enum class ProgressRetentionFaultPoint { AFTER_TEMP_SYNC, AFTER_PENDING_SYNC, AFTER_EXCHANGE, AFTER_PUBLISH_SYNC, AFTER_UNLINK }

/** Called only while the durable storage owner stabilizes the selected attempt and retention policy.
 * All mutation is descriptor-relative in the fixed run report directory. The reserved pending name
 * holds either the synced replacement or the previous journal until publication is durable.
 */
internal object AgentProgressJournalMaintenance {
    const val PENDING_FILE = ".agent-progress-retention.pending.json"
    private const val LOCK_FILE = "agent-progress.lock"
    private const val JOURNAL = AgentProgressJournal.FILE_NAME

    fun expire(root: Path, attempt: WorkflowAttempt, now: Instant, retention: Duration,
        fault: (ProgressRetentionFaultPoint) -> Unit = {}): ProgressRetentionResult {
        require(!retention.isZero && !retention.isNegative)
        if (!attempt.state.terminal || attempt.publicationPending || attempt.progressRetentionPinned ||
            Duration.between(requireNotNull(attempt.endedAt), now) < retention) return ProgressRetentionResult.RETAINED
        require(attempt.jobId.matches(Regex("[a-f0-9]{32}")))
        require(attempt.runId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")))
        Fs.requireSupported(root)
        val parts = listOf(attempt.jobId, "reports", "runs", attempt.runId)
        val directories = mutableListOf<LinuxDescriptor>()
        try {
            directories += Fs.openRoot(root)
            for (part in parts) {
                try { directories += Fs.openDirectoryAt(directories.last().fd, part) }
                catch (failure: LinuxSyscallException) {
                    if (failure.errno == 2) return ProgressRetentionResult.NO_JOURNAL
                    throw failure
                }
            }
            val directory = directories.last()
            fun validateDirectories() {
                val reopened = mutableListOf<LinuxDescriptor>()
                try {
                    reopened += Fs.openRoot(root)
                    for (part in parts) reopened += Fs.openDirectoryAt(reopened.last().fd, part)
                    require(reopened.map { it.identity } == directories.map { it.identity }) { "retention directory changed" }
                } finally { reopened.asReversed().forEach { it.close() } }
            }
            val lease = AgentProgressJournalLease.tryAcquire(Fs.descriptorPath(directory)) {
                var lock = Fs.openRegularFileAtOrNull(directory.fd, LOCK_FILE)
                if (lock == null) {
                    Fs.createRegularFile(directory.fd, LOCK_FILE, 384).use { Fs.synchronize(it) }
                    Fs.synchronize(directory)
                    lock = requireNotNull(Fs.openRegularFileAtOrNull(directory.fd, LOCK_FILE))
                }
                lock.use {
                    require(it.identity.linkCount == 1) { "retention lock has multiple names" }
                    FileChannel.open(Fs.descriptorPath(it), WRITE)
                }
            } ?: return ProgressRetentionResult.WRITER_ACTIVE
            lease.use {
                validateDirectories()
                val current = read(directory, JOURNAL) ?: run {
                    require(read(directory, PENDING_FILE) == null) { "retention journal missing with pending publication" }
                    return ProgressRetentionResult.NO_JOURNAL
                }
                val pending = read(directory, PENDING_FILE)
                if (pending != null) {
                    // Exactly one side must be the prepared expiration of the other, for this attempt.
                    val currentTime = expiryTime(current.bytes)
                    val pendingTime = expiryTime(pending.bytes)
                    when {
                        currentTime != null && pendingTime == null -> {
                            require(currentTime <= now && matches(attempt, pending.bytes, current.bytes, currentTime, retention))
                            finish(directory, current, pending, ::validateDirectories, fault)
                            return ProgressRetentionResult.EXPIRED
                        }
                        currentTime == null && pendingTime != null -> {
                            require(pendingTime <= now && matches(attempt, current.bytes, pending.bytes, pendingTime, retention))
                            publish(directory, current, pending, ::validateDirectories, fault)
                            return ProgressRetentionResult.EXPIRED
                        }
                        else -> error("ambiguous progress retention publication")
                    }
                }
                val replacement = AgentProgressJournalRetention.expiredSnapshot(attempt, current.bytes, now, retention)
                    ?: run { Fs.synchronize(directory); return ProgressRetentionResult.RETAINED }
                Fs.createTemporaryAt(directory.fd).use { temporary ->
                    Fs.write(temporary, replacement) {}
                    Fs.synchronize(temporary)
                    fault(ProgressRetentionFaultPoint.AFTER_TEMP_SYNC)
                    validateDirectories()
                    requireCurrent(directory, JOURNAL, current)
                    Fs.linkTemporaryAt(temporary, directory.fd, PENDING_FILE)
                }
                Fs.synchronize(directory)
                fault(ProgressRetentionFaultPoint.AFTER_PENDING_SYNC)
                val prepared = requireNotNull(read(directory, PENDING_FILE))
                require(prepared.bytes.contentEquals(replacement))
                publish(directory, current, prepared, ::validateDirectories, fault)
                return ProgressRetentionResult.EXPIRED
            }
        } finally { directories.asReversed().forEach { it.close() } }
    }

    private data class Captured(val bytes: ByteArray, val identity: LinuxFileIdentity)
    private fun read(directory: LinuxDescriptor, name: String): Captured? {
        val path = Fs.openRegularFileAtOrNull(directory.fd, name) ?: return null
        return path.use { authorized ->
            require(authorized.identity.linkCount == 1) { "retention journal has multiple names" }
            Fs.openReadableFrom(authorized).use { readable ->
                val descriptorPath = Fs.descriptorPath(readable)
                val before = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
                val bytes = Fs.read(readable, AgentProgressJournal.MAXIMUM_READ_BYTES) {}
                val after = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
                require(before.size() == bytes.size.toLong() && before.size() == after.size() &&
                    before.lastModifiedTime() == after.lastModifiedTime() && Fs.identity(readable.fd) == authorized.identity)
                AgentProgressJournal.decode(bytes)
                Captured(bytes, authorized.identity)
            }
        }
    }
    private fun requireCurrent(directory: LinuxDescriptor, name: String, expected: Captured) {
        val actual = requireNotNull(read(directory, name))
        require(actual.identity == expected.identity && actual.bytes.contentEquals(expected.bytes)) { "retention journal changed" }
    }
    private fun expiryTime(bytes: ByteArray): Instant? = AgentProgressJournal.decode(bytes)["retentionExpiredAt"]
        ?.jsonPrimitive?.content?.let(Instant::parse)
    private fun matches(attempt: WorkflowAttempt, original: ByteArray, expired: ByteArray, time: Instant, retention: Duration) =
        AgentProgressJournalRetention.expiredSnapshot(attempt, original, time, retention)?.contentEquals(expired) == true

    private fun publish(directory: LinuxDescriptor, original: Captured, prepared: Captured,
        validate: () -> Unit, fault: (ProgressRetentionFaultPoint) -> Unit) {
        validate()
        requireCurrent(directory, JOURNAL, original); requireCurrent(directory, PENDING_FILE, prepared)
        Fs.exchange(directory.fd, JOURNAL, PENDING_FILE)
        fault(ProgressRetentionFaultPoint.AFTER_EXCHANGE)
        finish(directory, prepared, original, validate, fault)
    }
    private fun finish(directory: LinuxDescriptor, current: Captured, previous: Captured,
        validate: () -> Unit, fault: (ProgressRetentionFaultPoint) -> Unit) {
        validate()
        requireCurrent(directory, JOURNAL, current); requireCurrent(directory, PENDING_FILE, previous)
        Fs.synchronize(directory)
        fault(ProgressRetentionFaultPoint.AFTER_PUBLISH_SYNC)
        validate()
        requireCurrent(directory, PENDING_FILE, previous)
        Fs.unlink(directory.fd, PENDING_FILE)
        fault(ProgressRetentionFaultPoint.AFTER_UNLINK)
        Fs.synchronize(directory)
    }
}
