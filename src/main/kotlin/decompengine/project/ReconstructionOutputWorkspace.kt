package decompengine.project

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileState
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.jobs.FullRunJournal
import decompengine.jobs.WorkflowStartupRecoveryBudget
import java.nio.ByteBuffer
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.Condition
import java.util.concurrent.locks.ReentrantLock
import java.util.concurrent.locks.StampedLock
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*

internal open class ReconstructionOutputReadUnavailableException(message: String) : IllegalStateException(message)

internal class ReconstructionOutputBusyException : ReconstructionOutputReadUnavailableException(
    "another reconstruction owns this output directory",
)

/** Routes generated state by input identity while preserving the original receipt-bound active paths. */
internal class ReconstructionOutputWorkspace private constructor(
    private val root: Path,
    private val ownerKey: Any,
    private val channel: FileChannel,
    private val lock: FileLock,
    private val ownership: ReconstructionPublicationLock,
    private val syncParentDirectory: (Path) -> Unit,
    val inputSha256: String,
    private val processGate: ProcessGate,
    private val processGateStamp: Long,
) : AutoCloseable {
    private var closed = false

    /** Capability for later publication steps; it is valid only while this workspace is open. */
    internal val publicationLock: ReconstructionPublicationLock get() = ownership

    /** Build and publish an explicit subset while this workspace owns the output lease. */
    @Synchronized
    internal fun publish(
        members: Set<String>,
        buildStage: (Path) -> Unit,
        cancellationCheck: () -> Unit = {},
        onCommitted: () -> Unit = {},
        beforeDecision: (Path) -> Unit = {},
    ): PublicationResult {
        check(!closed) { "reconstruction output workspace is closed" }
        ownership.borrow(root, inputSha256)
        return ReconstructionOutputPublication.ownedBy(ownership, syncParentDirectory)
            .publish(members, buildStage, cancellationCheck, onCommitted, beforeDecision)
    }

    private fun activate(recoveryBudget: WorkflowStartupRecoveryBudget? = null, onCommittedPublication: () -> Unit = {}) {
        ownership.validate()
        LinuxFilesystemSyscalls.openRoot(root).use { rootDescriptor ->
            removeAbandonedRepairMutationTemps(rootDescriptor, root)
        }
        if (Files.exists(root.resolve(REPAIR_MUTATION), NOFOLLOW_LINKS)) {
            throw ReconstructionOutputReadUnavailableException(
                "repair recovery is required before reconstruction output can be activated",
            )
        }
        ReconstructionOutputPublication.recover(ownership, syncParentDirectory, recoveryBudget, onCommittedPublication)
        recoverSwitch()
        val archiveEntries = presentEntries(root)
        val hasActiveIdentity = Files.exists(root.resolve(ACTIVE), NOFOLLOW_LINKS)
        val current = readObject(root.resolve(ACTIVE))?.let {
            require(it.keys == setOf("schemaVersion", "inputSha256") && it["schemaVersion"] == JsonPrimitive(1))
            it.getValue("inputSha256").jsonPrimitive.content.also { key -> require(HASH.matches(key)) }
        } ?: inferInput() ?: if (
            !hasActiveIdentity && !Files.exists(cacheRoot(), NOFOLLOW_LINKS) &&
            "exploration.json" in archiveEntries && archiveEntries.none(INITIAL_RECONSTRUCTION_OUTPUTS::contains)
        ) inputSha256 else null
        if (current == inputSha256) {
            writeActive()
            return
        }
        if (archiveEntries.isEmpty() && !Files.exists(cacheRoot(), NOFOLLOW_LINKS)) {
            writeActive()
            return
        }
        val fromKey = current ?: "unidentified-${UUID.randomUUID()}"
        val previous = cacheDirectory(fromKey)
        val incoming = cacheDirectory(inputSha256)
        require(previous != incoming)
        val restoreEntries = presentEntries(incoming)
        val transaction = buildJsonObject {
            put("schemaVersion", 1)
            put("from", fromKey)
            put("to", inputSha256)
            put("phase", "archive")
            put("archiveEntries", JsonArray(archiveEntries.map(::JsonPrimitive)))
            put("restoreEntries", JsonArray(restoreEntries.map(::JsonPrimitive)))
        }
        writeObject(root.resolve(SWITCH), transaction)
        recoverSwitch()
    }

    private fun inferInput(): String? {
        val identities = (listOf("analysis/reports/program_model.json", "source-tree/reports/program_model.json", "reconstruction.json")
            .mapNotNull { relative ->
                var path = root
                for (part in Path.of(relative)) {
                    path = path.resolve(part)
                    if (!Files.exists(path, NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) return@mapNotNull null
                }
                if (!Files.isRegularFile(path, NOFOLLOW_LINKS)) return@mapNotNull null
                val prefix = Files.newInputStream(path, READ, NOFOLLOW_LINKS).use { it.readNBytes(4096) }.toString(Charsets.UTF_8)
                Regex("\"inputSha256\"\\s*:\\s*\"([0-9a-f]{64})\"").find(prefix)?.groupValues?.get(1)
            } + inferObservationInput()?.let(::listOf).orEmpty()).distinct()
        return identities.singleOrNull()
    }

    /** Module observations carry their input identity; opaque exploration reports do not. */
    private fun inferObservationInput(): String? {
        val path = root.resolve(ModuleObservedBehavior.FILE_NAME)
        if (!Files.exists(path, NOFOLLOW_LINKS)) return null
        require(!Files.isSymbolicLink(path) && Files.isRegularFile(path, NOFOLLOW_LINKS)) {
            "module observations must be an ordinary file"
        }
        val bytes = Files.newInputStream(path, READ, NOFOLLOW_LINKS).use {
            it.readNBytes(ModuleObservedBehavior.MAXIMUM_BYTES + 1)
        }
        require(bytes.size <= ModuleObservedBehavior.MAXIMUM_BYTES) { "module observations exceed their input identity bound" }
        return ModuleObservedBehavior.parse(bytes.toString(Charsets.UTF_8)).inputSha256
    }

    private fun recoverSwitch() {
        val transaction = readObject(root.resolve(SWITCH)) ?: return
        require(transaction.keys == setOf("schemaVersion", "from", "to", "phase", "archiveEntries", "restoreEntries"))
        require(transaction["schemaVersion"] == JsonPrimitive(1))
        val from = transaction.getValue("from").jsonPrimitive.content
        val to = transaction.getValue("to").jsonPrimitive.content
        require(KEY.matches(from) && HASH.matches(to) && from != to)
        val phase = transaction.getValue("phase").jsonPrimitive.content
        require(phase in setOf("archive", "restore"))
        fun entries(key: String): List<String> = transaction.getValue(key).jsonArray.map { it.jsonPrimitive.content }.also {
            require(it.size <= ENTRIES.size && it.distinct().size == it.size && it.all(ENTRIES::contains))
        }
        val archiveEntries = entries("archiveEntries")
        val restoreEntries = entries("restoreEntries")
        val outgoing = cacheDirectory(from)
        val incoming = cacheDirectory(to)
        if (phase == "archive") {
            moveEntries(root, outgoing, archiveEntries)
            writeObject(root.resolve(SWITCH), JsonObject(transaction + ("phase" to JsonPrimitive("restore"))))
        }
        moveEntries(incoming, root, restoreEntries)
        writeObject(root.resolve(ACTIVE), buildJsonObject { put("schemaVersion", 1); put("inputSha256", to) })
        Files.delete(root.resolve(SWITCH))
        sync(root)
    }

    private fun moveEntries(source: Path, target: Path, entries: List<String>) {
        ownership.validate()
        for (name in entries) {
            val from = source.resolve(name)
            val to = target.resolve(name)
            val hasSource = Files.exists(from, NOFOLLOW_LINKS)
            val hasTarget = Files.exists(to, NOFOLLOW_LINKS)
            require(!(hasSource && hasTarget)) { "input switch has conflicting preserved entries: $name" }
            require(hasSource || hasTarget) { "input switch is missing a preserved entry: $name" }
            require(!Files.isSymbolicLink(from) && !Files.isSymbolicLink(to)) { "input switch entries must not be links" }
            if (hasSource) {
                Files.move(from, to, ATOMIC_MOVE)
                sync(source); sync(target)
            }
        }
    }

    private fun cacheRoot(): Path = root.resolve(CACHE)
    private fun cacheDirectory(key: String): Path {
        require(KEY.matches(key))
        val cache = cacheRoot()
        if (!Files.exists(cache, NOFOLLOW_LINKS)) Files.createDirectory(cache)
        require(Files.isDirectory(cache, NOFOLLOW_LINKS)) { "input cache must be an ordinary directory" }
        // Repeat the parent sync even when the directory already exists: an earlier sync may
        // have failed after creation, and a retry must not treat that entry as durable.
        syncParentDirectory(root)
        val directory = cache.resolve(key)
        if (!Files.exists(directory, NOFOLLOW_LINKS)) Files.createDirectory(directory)
        require(Files.isDirectory(directory, NOFOLLOW_LINKS)) { "input cache entry must be an ordinary directory" }
        // Persist each per-input entry before publishing the switch transaction or moving any
        // preserved output into it, including entries left by a failed earlier sync.
        syncParentDirectory(cache)
        return directory
    }

    private fun presentEntries(directory: Path): List<String> = ENTRIES.filter {
        val path = directory.resolve(it)
        require(!Files.isSymbolicLink(path)) { "generated reconstruction entries must not be links" }
        Files.exists(path, NOFOLLOW_LINKS)
    }

    private fun writeActive() = writeObject(root.resolve(ACTIVE), buildJsonObject {
        put("schemaVersion", 1); put("inputSha256", inputSha256)
    })

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        fun close(action: () -> Unit) {
            try { action() } catch (caught: Throwable) {
                if (failure == null) failure = caught else if (failure !== caught) failure!!.addSuppressed(caught)
            }
        }
        close { ownership.closeOwnership() }
        close { if (lock.isValid) lock.release() }
        close { channel.close() }
        synchronized(OWNERS) { OWNERS.remove(ownerKey) }
        processGate.lock.unlockWrite(processGateStamp)
        releaseGate(processGate)
        failure?.let { throw it }
    }

    companion object {
        private data class SharedFileLock(
            val root: LinuxDescriptor,
            val lockFile: LinuxDescriptor,
            val channel: FileChannel,
            val lock: FileLock,
        )

        private class ProcessGate {
            // StampedLock permits the owning lease to be retired from a different thread. CLI
            // progress writers can outlive the command thread, so a thread-owned RW lock would
            // strand the process-local publication gate when that cleanup worker closes it.
            val lock = StampedLock()
            data class ReadHold(val stamp: Long, var leases: Int)
            val readHolds = java.util.IdentityHashMap<Thread, ReadHold>()
            var users: Int = 0
            val sharedLockMonitor = ReentrantLock()
            val sharedLockChanged: Condition = sharedLockMonitor.newCondition()
            var sharedLockTransition: Boolean = false
            var sharedReaders: Int = 0
            var sharedFileLock: SharedFileLock? = null
        }

        internal const val ACTIVE = ".reconstruction-active-input.json"
        internal const val SWITCH = ".reconstruction-input-switch.json"
        internal const val PUBLICATION = ".reconstruction-publication.json"
        private const val REPAIR_MUTATION = ".reconstruction-repair-in-progress"
        private const val REPAIR_MUTATION_TEMP_PREFIX = ".reconstruction-repair-in-progress."
        private val REPAIR_MUTATION_BYTES = "repair-mutation-v1\n".toByteArray(Charsets.US_ASCII)
        internal const val CACHE = "input-cache"
        private val INITIAL_RECONSTRUCTION_OUTPUTS = setOf(
            "analysis", "source-tree", "source-tree.zip", "reconstruction.json", "reconstruction_progress.json",
        )
        internal val ENTRIES = listOf(
            "analysis", "source-tree", "source-tree.zip", "reconstruction.json", "reconstruction_progress.json",
            "exploration.json", ModuleObservedBehavior.FILE_NAME, "agent-progress.json", FullRunJournal.DIRECTORY,
            ModuleCompilerFeedbackStore.DIRECTORY, ".decomp-agent-sessions",
        )
        private val HASH = Regex("[0-9a-f]{64}")
        private val KEY = Regex("[0-9a-f]{64}|unidentified-[0-9a-f-]{36}")
        private val OWNERS = mutableSetOf<Any>()
        private val PROCESS_GATES = mutableMapOf<Path, ProcessGate>()

        /** Run a complete cooperating read against one stable publication generation. */
        internal fun <T> withReadLease(reportDirectory: Path, action: () -> T): T =
            acquireReadLease(reportDirectory).use { action() }

        /** Apply the lease only to directories that are explicitly managed as publication roots. */
        internal fun <T> withReadLeaseIfManaged(reportDirectory: Path, action: () -> T): T =
            withReadLeaseIfManaged(reportDirectory, failFast = true, action = action)

        internal fun <T> withReadLeaseIfManaged(
            reportDirectory: Path,
            failFast: Boolean,
            action: () -> T,
        ): T {
            val lease = acquireReadLeaseIfManaged(reportDirectory, failFast) ?: return action()
            return lease.use { action() }
        }

        /** Return null only for a clean legacy/unmanaged root; transaction residue always refuses. */
        internal fun acquireReadLeaseIfManaged(reportDirectory: Path, failFast: Boolean): AutoCloseable? {
            val canonicalRoot = reportDirectory.toRealPath()
            val active = canonicalRoot.resolve(ACTIVE)
            val lock = canonicalRoot.resolve(LOCK_FILE)
            val hasActive = Files.exists(active, NOFOLLOW_LINKS)
            val hasLock = Files.exists(lock, NOFOLLOW_LINKS)
            if (!hasActive && !hasLock) {
                requireReadablePublicationState(canonicalRoot)
                return null
            }
            // A lock-only root is a legacy/inactive workspace: retain the lock protocol if one
            // was already created, but do not require an active-input marker until activation.
            // If the active marker exists, the lock must be present and both names must be safe.
            if ((hasActive && !hasLock) ||
                (hasActive && (!Files.isRegularFile(active, NOFOLLOW_LINKS) || Files.isSymbolicLink(active))) ||
                (hasLock && (!Files.isRegularFile(lock, NOFOLLOW_LINKS) || Files.isSymbolicLink(lock)))) {
                throw ReconstructionOutputReadUnavailableException(
                    "published reconstruction workspace markers are incomplete",
                )
            }
            return acquireReadLease(canonicalRoot, failFast)
        }

        /**
         * Hold the reconstruction-output read lease while a CLI repair consumes a published
         * `source-tree`. Ordinary user projects have no adjacent workspace marker and remain
         * outside this lease protocol.
         */
        internal fun <T> withProjectReadLease(projectDirectory: Path, action: (Path) -> T): T {
            val project = resolveProjectAuthority(projectDirectory)
            // Resolve aliases before deciding whether this is an ordinary project. A caller may
            // reach the published source tree through a differently named symlink; checking the
            // lexical basename first would let that read bypass the publication lease.
            if (project.fileName?.toString() != "source-tree") return action(project)
            val reports = project.parent ?: return action(project)
            val hasActiveMarker = Files.exists(reports.resolve(ACTIVE), NOFOLLOW_LINKS)
            val hasLockMarker = Files.exists(reports.resolve(LOCK_FILE), NOFOLLOW_LINKS)
            if (!hasActiveMarker && !hasLockMarker) {
                requireReadablePublicationState(reports)
                return action(project)
            }
            if (!Files.isRegularFile(reports.resolve(ACTIVE), NOFOLLOW_LINKS) ||
                !Files.isRegularFile(reports.resolve(LOCK_FILE), NOFOLLOW_LINKS)) {
                throw ReconstructionOutputReadUnavailableException(
                    "published reconstruction workspace markers are incomplete",
                )
            }
            return withReadLease(reports) { action(project) }
        }

        /** Hold an exclusive publication lease while a CLI repair mutates a published project. */
        internal fun <T> withProjectMutationLease(
            projectDirectory: Path,
            canRetireRepairMarker: (T) -> Boolean,
            action: (Path) -> T,
        ): T {
            val project = resolveProjectAuthority(projectDirectory)
            if (project.fileName?.toString() != "source-tree") return action(project)
            val reports = project.parent ?: return action(project)
            val hasActiveMarker = Files.exists(reports.resolve(ACTIVE), NOFOLLOW_LINKS)
            val hasLockMarker = Files.exists(reports.resolve(LOCK_FILE), NOFOLLOW_LINKS)
            if (!hasActiveMarker && !hasLockMarker) {
                requireReadablePublicationState(reports)
                return action(project)
            }
            if (!Files.isRegularFile(reports.resolve(ACTIVE), NOFOLLOW_LINKS) ||
                !Files.isRegularFile(reports.resolve(LOCK_FILE), NOFOLLOW_LINKS)) {
                throw ReconstructionOutputReadUnavailableException(
                    "published reconstruction workspace markers are incomplete",
                )
            }

            val canonicalRoot = try { reports.toRealPath() } catch (_: IOException) {
                throw ReconstructionOutputReadUnavailableException(
                    "published reconstruction workspace root is unavailable",
                )
            }
            val gate = retainGate(canonicalRoot)
            var stamp = 0L
            var gateOwned = false
            var rootDescriptor: LinuxDescriptor? = null
            var lockDescriptor: LinuxDescriptor? = null
            var channel: FileChannel? = null
            var fileLock: FileLock? = null
            try {
                stamp = acquireWriteLock(gate)
                gateOwned = true
                rootDescriptor = LinuxFilesystemSyscalls.openRoot(canonicalRoot)
                lockDescriptor = LinuxFilesystemSyscalls.openRegularFileAtOrNull(rootDescriptor.fd, LOCK_FILE)
                    ?: throw ReconstructionOutputReadUnavailableException(
                        "published reconstruction output lock is unavailable",
                    )
                channel = FileChannel.open(LinuxFilesystemSyscalls.descriptorPath(lockDescriptor), READ, WRITE)
                while (fileLock == null) {
                    if (Thread.currentThread().isInterrupted) throw InterruptedException(
                        "published reconstruction mutation lease acquisition was interrupted",
                    )
                    try { fileLock = channel.tryLock() }
                    catch (_: java.nio.channels.OverlappingFileLockException) { /* another local owner is retiring */ }
                    if (fileLock == null) TimeUnit.MILLISECONDS.sleep(100)
                }
                normalizePublicationLock(rootDescriptor, lockDescriptor, channel)
                val identity = LinuxFilesystemSyscalls.identity(lockDescriptor.fd)
                require(identity.isRegularFile && identity.linkCount == 1 &&
                    (identity.mode and 0xfff) == OWNER_READ_WRITE && identity.uid == rootDescriptor.identity.uid) {
                    "reconstruction output lock is not an owned private regular file"
                }
                validateExclusiveMutationAuthority(rootDescriptor, lockDescriptor, canonicalRoot)
                val active = readObject(canonicalRoot.resolve(ACTIVE))
                    ?: throw ReconstructionOutputReadUnavailableException(
                        "published reconstruction input identity disappeared during mutation lease acquisition",
                    )
                require(active.keys == setOf("schemaVersion", "inputSha256") &&
                    active["schemaVersion"] == JsonPrimitive(1) &&
                    active["inputSha256"]?.jsonPrimitive?.content?.matches(HASH) == true) {
                    "published reconstruction input identity is malformed"
                }
                requireReadablePublicationState(canonicalRoot, allowRepairInProgress = true)
                removeAbandonedRepairMutationTemps(rootDescriptor, canonicalRoot)
                ensureRepairMutationMarker(rootDescriptor, canonicalRoot)
                val result = action(project)
                validateExclusiveMutationAuthority(rootDescriptor, lockDescriptor, canonicalRoot)
                if (!canRetireRepairMarker(result)) return result
                val restoreInterrupt = Thread.interrupted()
                try {
                    try {
                        LinuxFilesystemSyscalls.unlink(rootDescriptor.fd, REPAIR_MUTATION)
                        LinuxFilesystemSyscalls.synchronize(rootDescriptor)
                        sync(canonicalRoot)
                    } catch (failure: Throwable) {
                        try { ensureRepairMutationMarker(rootDescriptor, canonicalRoot) }
                        catch (restoreFailure: Throwable) { if (failure !== restoreFailure) failure.addSuppressed(restoreFailure) }
                        throw failure
                    }
                } finally {
                    if (restoreInterrupt) Thread.currentThread().interrupt()
                }
                return result
            } finally {
                try { fileLock?.takeIf(FileLock::isValid)?.release() }
                finally {
                    try { channel?.close() }
                    finally {
                        try { lockDescriptor?.close() }
                        finally {
                            try { rootDescriptor?.close() }
                            finally {
                                if (gateOwned) gate.lock.unlockWrite(stamp)
                                releaseGate(gate)
                            }
                        }
                    }
                }
            }
        }

        /** Resolve a possibly absent source-tree against its real parent before any lock wait. */
        private fun resolveProjectAuthority(projectDirectory: Path): Path {
            val requested = projectDirectory.toAbsolutePath().normalize()
            return try {
                requested.toRealPath()
            } catch (_: IOException) {
                if (Files.exists(requested, NOFOLLOW_LINKS)) {
                    throw ReconstructionOutputReadUnavailableException(
                        "published reconstruction project authority could not be resolved",
                    )
                }
                if (requested.fileName?.toString() == "source-tree") {
                    val parent = requested.parent ?: throw ReconstructionOutputReadUnavailableException(
                        "published reconstruction project parent could not be resolved",
                    )
                    try { parent.toRealPath().resolve("source-tree") }
                    catch (_: IOException) {
                        throw ReconstructionOutputReadUnavailableException(
                            "published reconstruction project parent could not be resolved",
                        )
                    }
                } else requested
            }
        }

        private fun validateExclusiveMutationAuthority(root: LinuxDescriptor, lock: LinuxDescriptor, namedRoot: Path) {
            LinuxFilesystemSyscalls.openRoot(namedRoot).use { currentRoot ->
                if (!sameObject(currentRoot.identity, LinuxFilesystemSyscalls.identity(root.fd))) {
                    throw ReconstructionOutputReadUnavailableException(
                        "reconstruction output root name changed during mutation lease acquisition",
                    )
                }
                val currentLock = LinuxFilesystemSyscalls.openRegularFileAtOrNull(currentRoot.fd, LOCK_FILE)
                    ?: throw ReconstructionOutputReadUnavailableException(
                        "reconstruction output lock name disappeared during mutation lease acquisition",
                    )
                currentLock.use {
                    if (!sameObject(it.identity, LinuxFilesystemSyscalls.identity(lock.fd))) {
                        throw ReconstructionOutputReadUnavailableException(
                            "reconstruction output lock name changed during mutation lease acquisition",
                        )
                    }
                }
            }
        }

        private fun requireReadablePublicationState(reportDirectory: Path, allowRepairInProgress: Boolean = false) {
            LinuxFilesystemSyscalls.openRoot(reportDirectory).use { root ->
                LinuxFilesystemSyscalls.openPathAtOrNull(root.fd, SWITCH)?.use {
                    throw ReconstructionOutputReadUnavailableException(
                        "reconstruction input recovery is required before reading this output",
                    )
                }
                LinuxFilesystemSyscalls.openPathAtOrNull(root.fd, PUBLICATION)?.use {
                    throw ReconstructionOutputReadUnavailableException(
                        "reconstruction publication recovery is required before reading this output",
                    )
                }
                val repairMarkerExists = LinuxFilesystemSyscalls.openPathAtOrNull(root.fd, REPAIR_MUTATION).use { it != null }
                val repairTempExists = LinuxFilesystemSyscalls.directoryEntryNames(root, ReconstructionOutputTree.MAX_ENTRIES)
                    .any { it.matches(Regex("\\.reconstruction-repair-in-progress\\.[0-9a-f-]{36}\\.tmp")) }
                if (repairMarkerExists || repairTempExists) {
                    if (allowRepairInProgress) return@use
                    throw ReconstructionOutputReadUnavailableException(
                        "repair recovery is required before reading this output",
                    )
                }
                val privateResidue = LinuxFilesystemSyscalls.directoryEntryNames(root, ReconstructionOutputTree.MAX_ENTRIES)
                    .firstOrNull { name -> name.startsWith(".reconstruction-stage-") ||
                        name.startsWith(".reconstruction-previous-") || name.startsWith(".publication-") }
                if (privateResidue != null) {
                    throw ReconstructionOutputReadUnavailableException(
                        "reconstruction publication recovery is required before reading private transaction residue",
                    )
                }
            }
        }

        private fun ensureRepairMutationMarker(root: LinuxDescriptor, canonicalRoot: Path) {
            val marker = LinuxFilesystemSyscalls.openRegularFileAtOrNull(root.fd, REPAIR_MUTATION)
                ?: run {
                    val temporaryName = "$REPAIR_MUTATION_TEMP_PREFIX${UUID.randomUUID()}.tmp"
                    val created = LinuxFilesystemSyscalls.createRegularFile(root.fd, temporaryName, OWNER_READ_WRITE)
                    try {
                        FileChannel.open(LinuxFilesystemSyscalls.descriptorPath(created), WRITE).use { channel ->
                            val buffer = ByteBuffer.wrap(REPAIR_MUTATION_BYTES)
                            while (buffer.hasRemaining()) channel.write(buffer)
                            channel.force(true)
                        }
                        LinuxFilesystemSyscalls.synchronize(created)
                        LinuxFilesystemSyscalls.renameNoReplace(root.fd, temporaryName, root.fd, REPAIR_MUTATION)
                        LinuxFilesystemSyscalls.synchronize(root)
                        created.close()
                        LinuxFilesystemSyscalls.openRegularFileAtOrNull(root.fd, REPAIR_MUTATION)
                            ?: throw ReconstructionOutputReadUnavailableException("repair mutation marker publication failed")
                    } catch (failure: Throwable) {
                        runCatching { created.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                        runCatching { LinuxFilesystemSyscalls.unlink(root.fd, temporaryName) }
                            .exceptionOrNull()?.let(failure::addSuppressed)
                        throw failure
                    }
                }
            marker.use {
                val identity = LinuxFilesystemSyscalls.identity(it.fd)
                require(identity.isRegularFile && !identity.isSymbolicLink && identity.linkCount == 1 &&
                    identity.uid == root.identity.uid && (identity.mode and 0xfff) == OWNER_READ_WRITE) {
                    "repair mutation marker is not an owned private regular file"
                }
                val bytes = FileChannel.open(LinuxFilesystemSyscalls.descriptorPath(it), READ).use { channel ->
                    val buffer = ByteBuffer.allocate(REPAIR_MUTATION_BYTES.size + 1)
                    while (buffer.hasRemaining()) {
                        val count = channel.read(buffer)
                        if (count < 0) break
                    }
                    buffer.flip()
                    ByteArray(buffer.remaining()).also(buffer::get)
                }
                require(bytes.contentEquals(REPAIR_MUTATION_BYTES)) { "repair mutation marker is malformed" }
                // A previous attempt may have renamed the marker but failed its directory
                // durability fence. Re-sync both the marker and its name before admitting any
                // source mutation, including when reusing an existing marker.
                LinuxFilesystemSyscalls.reopenReadWrite(it).use(LinuxFilesystemSyscalls::synchronize)
            }
            LinuxFilesystemSyscalls.synchronize(root)
            sync(canonicalRoot)
        }

        /** Remove only private marker staging files left before atomic marker publication. */
        private fun removeAbandonedRepairMutationTemps(root: LinuxDescriptor, canonicalRoot: Path) {
            val names = LinuxFilesystemSyscalls.directoryEntryNames(root, ReconstructionOutputTree.MAX_ENTRIES)
                .filter { it.startsWith(REPAIR_MUTATION_TEMP_PREFIX) }
            require(names.size <= 8) { "too many abandoned repair mutation marker files" }
            for (name in names) {
                require(name.matches(Regex("\\.reconstruction-repair-in-progress\\.[0-9a-f-]{36}\\.tmp"))) {
                    "repair mutation temporary name is malformed"
                }
                val staged = LinuxFilesystemSyscalls.openRegularFileAtOrNull(root.fd, name)
                    ?: throw ReconstructionOutputReadUnavailableException("repair mutation temporary is unavailable")
                staged.use {
                    val identity = LinuxFilesystemSyscalls.identity(it.fd)
                    require(identity.isRegularFile && identity.linkCount == 1 && identity.uid == root.identity.uid &&
                        (identity.mode and 0xfff) == OWNER_READ_WRITE) {
                        "repair mutation temporary is not an owned private regular file"
                    }
                }
                LinuxFilesystemSyscalls.unlink(root.fd, name)
            }
            if (names.isNotEmpty()) {
                LinuxFilesystemSyscalls.synchronize(root)
                sync(canonicalRoot)
            }
        }

        /** Acquire a read lease for APIs that must return a path consumed synchronously later. */
        internal fun acquireReadLease(reportDirectory: Path, failFast: Boolean = false): AutoCloseable {
            val canonicalRoot = reportDirectory.toRealPath()
            val gate = retainGate(canonicalRoot)
            val ownerThread = Thread.currentThread()
            val inherited = synchronized(gate) {
                gate.readHolds[ownerThread]?.also { it.leases++ }
            }
            var gateStamp = inherited?.stamp ?: 0L
            var readHoldRegistered = inherited != null
            var sharedReaderAcquired = false
            try {
                if (inherited == null) {
                    gateStamp = if (failFast) gate.lock.tryReadLock() else acquireReadLock(gate)
                    if (gateStamp == 0L) throw ReconstructionOutputReadUnavailableException(
                        "published reconstruction workspace is currently being updated",
                    )
                    synchronized(gate) {
                        check(gate.readHolds.put(ownerThread, ProcessGate.ReadHold(gateStamp, 1)) == null) {
                            "a read lease was concurrently registered for the same thread"
                        }
                        readHoldRegistered = true
                    }
                }
                acquireSharedReader(gate, canonicalRoot, failFast)
                sharedReaderAcquired = true
                validateSharedReaderAuthority(gate, canonicalRoot)
            } catch (failure: Throwable) {
                if (sharedReaderAcquired) {
                    try { releaseSharedReader(gate) } catch (closing: Throwable) {
                        if (failure !== closing) failure.addSuppressed(closing)
                    }
                }
                if (readHoldRegistered) releaseReadHold(gate, ownerThread)
                else if (gateStamp != 0L) gate.lock.unlockRead(gateStamp)
                releaseGate(gate)
                throw failure
            }
            val closed = AtomicBoolean()
            val lease = AutoCloseable {
                if (closed.compareAndSet(false, true)) {
                    var failure: Throwable? = null
                    var stampToRelease = 0L
                    try { releaseSharedReader(gate) } catch (caught: Throwable) { failure = caught }
                    try {
                        synchronized(gate) {
                            val hold = checkNotNull(gate.readHolds[ownerThread]) {
                                "shared publication read hold disappeared"
                            }
                            check(hold.leases > 0) { "shared publication read hold count underflow" }
                            hold.leases--
                            if (hold.leases == 0) {
                                gate.readHolds.remove(ownerThread)
                                stampToRelease = hold.stamp
                            }
                        }
                    } catch (caught: Throwable) {
                        if (failure == null) failure = caught else if (failure !== caught) failure!!.addSuppressed(caught)
                    }
                    finally {
                        if (stampToRelease != 0L) gate.lock.unlockRead(stampToRelease)
                        releaseGate(gate)
                    }
                    failure?.let { throw it }
                }
            }
            try {
                requireReadablePublicationState(canonicalRoot)
                return lease
            } catch (failure: Throwable) {
                try { lease.close() } catch (closing: Throwable) { if (failure !== closing) failure.addSuppressed(closing) }
                throw failure
            }
        }

        /**
         * One local reader opens the shared OS lock outside all process-gate monitors. Other
         * readers wait interruptibly for that transition, so cancellation cannot strand a
         * workflow behind a synchronized block while cross-process lock acquisition is blocked.
         */
        private fun acquireSharedReader(gate: ProcessGate, root: Path, failFast: Boolean) {
            val monitor = gate.sharedLockMonitor
            while (true) {
                var opener = false
                monitor.lockInterruptibly()
                try {
                    if (gate.sharedFileLock != null) {
                        gate.sharedReaders++
                        return
                    }
                    if (!gate.sharedLockTransition) {
                        gate.sharedLockTransition = true
                        opener = true
                    } else if (failFast) {
                        throw ReconstructionOutputReadUnavailableException(
                            "published reconstruction workspace is currently being updated",
                        )
                    } else {
                        gate.sharedLockChanged.await()
                    }
                } finally {
                    monitor.unlock()
                }
                if (!opener) continue

                var opened: SharedFileLock? = null
                var installed = false
                try {
                    opened = openSharedFileLock(root, failFast)
                    monitor.lock()
                    try {
                        check(gate.sharedFileLock == null && gate.sharedReaders == 0 && gate.sharedLockTransition)
                        gate.sharedFileLock = opened
                        gate.sharedReaders = 1
                        installed = true
                        gate.sharedLockTransition = false
                        gate.sharedLockChanged.signalAll()
                    } finally {
                        monitor.unlock()
                    }
                    return
                } catch (failure: Throwable) {
                    if (opened != null && !installed) {
                        try { closeSharedFileLock(opened) } catch (closing: Throwable) {
                            if (failure !== closing) failure.addSuppressed(closing)
                        }
                    }
                    monitor.lock()
                    try {
                        gate.sharedLockTransition = false
                        gate.sharedLockChanged.signalAll()
                    } finally {
                        monitor.unlock()
                    }
                    throw failure
                }
            }
        }

        /** A wait or local-reader reuse may outlive replacement of either authorized name. */
        private fun validateSharedReaderAuthority(gate: ProcessGate, root: Path) {
            val monitor = gate.sharedLockMonitor
            monitor.lock()
            val shared = try {
                check(gate.sharedReaders > 0)
                checkNotNull(gate.sharedFileLock)
            } finally {
                monitor.unlock()
            }
            LinuxFilesystemSyscalls.openRoot(root).use { namedRoot ->
                if (!sameObject(namedRoot.identity, LinuxFilesystemSyscalls.identity(shared.root.fd))) {
                    throw ReconstructionOutputReadUnavailableException(
                        "reconstruction output root changed while its publication lease was acquired",
                    )
                }
                val namedLock = LinuxFilesystemSyscalls.openRegularFileAtOrNull(namedRoot.fd, LOCK_FILE)
                    ?: throw ReconstructionOutputReadUnavailableException(
                        "reconstruction output lock name disappeared while its publication lease was acquired",
                    )
                namedLock.use {
                    if (!sameObject(it.identity, LinuxFilesystemSyscalls.identity(shared.lockFile.fd))) {
                        throw ReconstructionOutputReadUnavailableException(
                            "reconstruction output lock changed while its publication lease was acquired",
                        )
                    }
                }
            }
        }

        private fun sameObject(first: decompengine.acp.LinuxFileIdentity, second: decompengine.acp.LinuxFileIdentity): Boolean =
            first.key == second.key && first.mountId == second.mountId &&
                first.isDirectory == second.isDirectory && first.isRegularFile == second.isRegularFile &&
                first.isSymbolicLink == second.isSymbolicLink

        private fun releaseSharedReader(gate: ProcessGate) {
            val monitor = gate.sharedLockMonitor
            var closing: SharedFileLock? = null
            monitor.lock()
            try {
                check(gate.sharedReaders > 0) { "shared publication reader count underflow" }
                gate.sharedReaders--
                if (gate.sharedReaders == 0) {
                    closing = checkNotNull(gate.sharedFileLock) { "shared publication lock disappeared" }
                    gate.sharedFileLock = null
                    gate.sharedLockTransition = true
                }
            } finally {
                monitor.unlock()
            }
            val old = closing ?: return
            var failure: Throwable? = null
            try { closeSharedFileLock(old) } catch (caught: Throwable) { failure = caught }
            finally {
                monitor.lock()
                try {
                    gate.sharedLockTransition = false
                    gate.sharedLockChanged.signalAll()
                } finally {
                    monitor.unlock()
                }
            }
            failure?.let { throw it }
        }

        /** Release an acquisition that failed before its shared OS lease was installed. */
        private fun releaseReadHold(gate: ProcessGate, ownerThread: Thread) {
            var stamp = 0L
            synchronized(gate) {
                val hold = checkNotNull(gate.readHolds[ownerThread]) { "shared publication read hold disappeared" }
                check(hold.leases > 0) { "shared publication read hold count underflow" }
                hold.leases--
                if (hold.leases == 0) {
                    gate.readHolds.remove(ownerThread)
                    stamp = hold.stamp
                }
            }
            if (stamp != 0L) gate.lock.unlockRead(stamp)
        }

        private fun openSharedFileLock(root: Path, failFast: Boolean): SharedFileLock {
            var rootDescriptor: LinuxDescriptor? = null
            var lockDescriptor: LinuxDescriptor? = null
            var channel: FileChannel? = null
            try {
                rootDescriptor = LinuxFilesystemSyscalls.openRoot(root)
                lockDescriptor = LinuxFilesystemSyscalls.openRegularFileAtOrNull(rootDescriptor.fd, LOCK_FILE)
                    ?: throw ReconstructionOutputReadUnavailableException(
                        "published reconstruction workspace lock is unavailable",
                    )
                channel = FileChannel.open(LinuxFilesystemSyscalls.descriptorPath(lockDescriptor), READ)
                val current = LinuxFilesystemSyscalls.identity(lockDescriptor.fd)
                if (!current.isRegularFile || current.linkCount != 1 || current.uid != rootDescriptor.identity.uid ||
                    !isSafeReadPublicationLockMode(current.mode)) {
                    throw ReconstructionOutputReadUnavailableException(
                        "published reconstruction workspace lock is not a validated private lock",
                    )
                }
                val fileLock = if (failFast) channel.tryLock(0L, Long.MAX_VALUE, true)
                    else channel.lock(0L, Long.MAX_VALUE, true)
                if (fileLock == null) throw ReconstructionOutputReadUnavailableException(
                    "published reconstruction workspace is currently being updated",
                )
                val identity = LinuxFilesystemSyscalls.identity(lockDescriptor.fd)
                require(identity.isRegularFile && identity.linkCount == 1 &&
                    isSafeReadPublicationLockMode(identity.mode) && identity.uid == rootDescriptor.identity.uid) {
                    "reconstruction output lock is not an owned private regular file"
                }
                val shared = SharedFileLock(rootDescriptor, lockDescriptor, channel, fileLock)
                validateSharedFileLockAuthority(shared, root)
                return shared
            } catch (failure: Throwable) {
                runCatching { channel?.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                runCatching { lockDescriptor?.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                runCatching { rootDescriptor?.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }

        private fun validateSharedFileLockAuthority(shared: SharedFileLock, root: Path) {
            LinuxFilesystemSyscalls.openRoot(root).use { namedRoot ->
                if (!sameObject(namedRoot.identity, LinuxFilesystemSyscalls.identity(shared.root.fd))) {
                    throw ReconstructionOutputReadUnavailableException(
                        "reconstruction output root name changed during publication lease acquisition",
                    )
                }
                val namedLock = LinuxFilesystemSyscalls.openRegularFileAtOrNull(namedRoot.fd, LOCK_FILE)
                    ?: throw ReconstructionOutputReadUnavailableException(
                        "reconstruction output lock name disappeared after lock acquisition",
                    )
                namedLock.use {
                    if (!sameObject(it.identity, LinuxFilesystemSyscalls.identity(shared.lockFile.fd))) {
                        throw ReconstructionOutputReadUnavailableException(
                            "reconstruction output lock name changed during publication lease acquisition",
                        )
                    }
                }
            }
        }

        private fun normalizePublicationLock(root: LinuxDescriptor, lock: LinuxDescriptor, channel: FileChannel) {
            val identity = LinuxFilesystemSyscalls.identity(lock.fd)
            require(identity.isRegularFile && identity.linkCount == 1 && identity.uid == root.identity.uid &&
                identity.mountId == lock.identity.mountId && identity.key == lock.identity.key &&
                (identity.mode and 0x12) == 0) {
                "reconstruction output lock has an unsafe owner, type, link count, or writable mode"
            }
            if ((identity.mode and 0xfff) != OWNER_READ_WRITE) {
                // Do not close a second descriptor for this inode while the POSIX record lock is
                // held: Linux releases this process's locks on that inode after any such close.
                LinuxFilesystemSyscalls.chmodPinnedViaProcFd(lock, OWNER_READ_WRITE)
                channel.force(true)
                LinuxFilesystemSyscalls.synchronize(root)
            }
        }

        private fun closeSharedFileLock(shared: SharedFileLock) {
            var failure: Throwable? = null
            fun close(action: () -> Unit) {
                try { action() } catch (caught: Throwable) {
                    if (failure == null) failure = caught else if (failure !== caught) failure!!.addSuppressed(caught)
                }
            }
            close { if (shared.lock.isValid) shared.lock.release() }
            close { shared.channel.close() }
            close { shared.lockFile.close() }
            close { shared.root.close() }
            failure?.let { throw it }
        }

        private fun retainGate(root: Path): ProcessGate = synchronized(PROCESS_GATES) {
            val gate = PROCESS_GATES.getOrPut(root) { ProcessGate() }
            gate.users++
            gate
        }

        private fun releaseGate(gate: ProcessGate) = synchronized(PROCESS_GATES) {
            gate.users--
            check(gate.users >= 0)
            if (gate.users == 0) PROCESS_GATES.entries.removeIf { it.value === gate }
        }

        fun open(root: Path, input: Path): ReconstructionOutputWorkspace =
            openInternal(root, input, ::sync)

        /** Startup-only entry point: aggregate accepted-tree traversal into the store recovery budget. */
        internal fun openForStartupRecovery(
            root: Path,
            input: Path,
            recoveryBudget: WorkflowStartupRecoveryBudget,
            onCommittedPublication: () -> Unit = {},
        ): ReconstructionOutputWorkspace = openInternal(root, input, ::sync, recoveryBudget, onCommittedPublication)

        internal fun openWithParentSyncForTest(
            root: Path,
            input: Path,
            syncParentDirectory: (Path) -> Unit,
        ): ReconstructionOutputWorkspace = openInternal(root, input, syncParentDirectory)

        private fun openInternal(
            root: Path,
            input: Path,
            syncParentDirectory: (Path) -> Unit,
            recoveryBudget: WorkflowStartupRecoveryBudget? = null,
            onCommittedPublication: () -> Unit = {},
        ): ReconstructionOutputWorkspace {
            require(Files.isRegularFile(input)) { "reconstruction input must be a regular file" }
            Files.createDirectories(root)
            require(Files.isDirectory(root, NOFOLLOW_LINKS)) { "reconstruction output must be an ordinary directory" }
            val canonicalRoot = root.toRealPath()
            val canonicalInput = input.toRealPath()
            val attributes = Files.readAttributes(canonicalRoot, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
            val key = root.fileSystem to (attributes.fileKey() ?: root.toRealPath())
            synchronized(OWNERS) { if (!OWNERS.add(key)) throw ReconstructionOutputBusyException() }
            val processGate = retainGate(canonicalRoot)
            var processGateStamp = 0L
            var gateOwned = false
            var channel: FileChannel? = null
            var lease: ReconstructionOutputWorkspace? = null
            var rootDescriptor: LinuxDescriptor? = null
            var lockDescriptor: LinuxDescriptor? = null
            var inputParentDescriptor: LinuxDescriptor? = null
            var inputDescriptor: LinuxDescriptor? = null
            try {
                // Workspace acquisition runs inside the bounded workflow child. StampedLock's
                // unbounded writeLock ignores interruption, so wait in interruptible slices; a
                // deadline or cancellation can then unwind without holding OWNERS or the gate.
                processGateStamp = acquireWriteLock(processGate)
                gateOwned = true
                rootDescriptor = LinuxFilesystemSyscalls.openRoot(canonicalRoot)
                lockDescriptor = LinuxFilesystemSyscalls.openRegularFileAtOrNull(rootDescriptor.fd, LOCK_FILE)
                    ?: LinuxFilesystemSyscalls.createRegularFile(rootDescriptor.fd, LOCK_FILE, OWNER_READ_WRITE).also {
                        LinuxFilesystemSyscalls.synchronize(rootDescriptor)
                    }
                require(lockDescriptor.identity.isRegularFile && !lockDescriptor.identity.isSymbolicLink && lockDescriptor.identity.linkCount == 1) {
                    "reconstruction output lock must be an unlinked regular file"
                }
                channel = FileChannel.open(LinuxFilesystemSyscalls.descriptorPath(lockDescriptor), READ, WRITE)
                val lock = channel.tryLock() ?: throw ReconstructionOutputBusyException()
                normalizePublicationLock(rootDescriptor, lockDescriptor, channel)
                inputParentDescriptor = LinuxFilesystemSyscalls.openRoot(canonicalInput.parent)
                inputDescriptor = LinuxFilesystemSyscalls.openRegularFileAtOrNull(
                    inputParentDescriptor.fd, canonicalInput.fileName.toString(),
                ) ?: error("reconstruction input disappeared while opening its workspace")
                require(inputDescriptor.identity.isRegularFile && !inputDescriptor.identity.isSymbolicLink && inputDescriptor.identity.linkCount == 1) {
                    "reconstruction input must be an unlinked regular file"
                }
                val digest = MessageDigest.getInstance("SHA-256")
                recoveryBudget?.checkpoint()
                val inputBefore = LinuxFilesystemSyscalls.fileState(inputDescriptor)
                require(inputBefore.size >= 0) { "reconstruction input has an invalid size" }
                // Startup recovery re-hashes the admitted input before it can inspect any
                // publication journal. Charge that read against the same aggregate recovery
                // allowance and checkpoint within the stream, not merely before opening it.
                recoveryBudget?.publicationRecoveryBytes(inputBefore.size)
                // Preserve atime when O_NOATIME is permitted. Read-only host bind mounts owned
                // by another UID fall back only on EPERM to an ordinary pinned-descriptor read;
                // compare content-stability metadata independently of atime either way.
                LinuxFilesystemSyscalls.openReadableWithoutAtimeOrFallbackFrom(inputDescriptor).use { inputReadable ->
                    require(inputReadable.identity == inputDescriptor.identity) {
                        "reconstruction input descriptor changed while opening its reader"
                    }
                    var readBytes = 0L
                    while (readBytes < inputBefore.size) {
                        recoveryBudget?.checkpoint()
                        val request = minOf(65536L, inputBefore.size - readBytes).toInt()
                        val bytes = LinuxFilesystemSyscalls.readWithoutAtime(inputReadable, request)
                        if (bytes.isEmpty()) {
                            throw java.io.IOException("reconstruction input ended while its workspace identity was admitted")
                        }
                        digest.update(bytes)
                        readBytes = Math.addExact(readBytes, bytes.size.toLong())
                    }
                }
                require(sameInputContentState(inputBefore, LinuxFilesystemSyscalls.fileState(inputDescriptor))) {
                    "reconstruction input changed while its workspace identity was admitted"
                }
                val inputSha = digest.digest().joinToString("") { "%02x".format(it) }
                val ownership = ReconstructionPublicationLock.opened(
                    canonicalRoot,
                    canonicalInput,
                    inputSha,
                    channel,
                    lock,
                    rootDescriptor,
                    lockDescriptor,
                    inputParentDescriptor,
                    inputDescriptor,
                )
                lease = ReconstructionOutputWorkspace(canonicalRoot, key, channel, lock, ownership, syncParentDirectory,
                    inputSha, processGate, processGateStamp)
                lease.activate(recoveryBudget, onCommittedPublication)
                return lease
            } catch (failure: Throwable) {
                var gateReleasedByLease = false
                if (lease != null) {
                    gateOwned = false // close() releases the writer gate, even if resource closing fails.
                    try { lease.close() } catch (closing: Throwable) {
                        if (failure !== closing) failure.addSuppressed(closing)
                    } finally {
                        gateReleasedByLease = true
                    }
                } else {
                    try { channel?.close() } finally {
                        inputDescriptor?.close()
                        inputParentDescriptor?.close()
                        lockDescriptor?.close()
                        rootDescriptor?.close()
                        synchronized(OWNERS) { OWNERS.remove(key) }
                    }
                }
                if (!gateReleasedByLease) {
                    if (gateOwned) processGate.lock.unlockWrite(processGateStamp)
                    releaseGate(processGate)
                }
                throw failure
            }
        }

        private fun acquireWriteLock(gate: ProcessGate): Long {
            while (true) {
                val stamp = gate.lock.tryWriteLock(100, TimeUnit.MILLISECONDS)
                if (stamp != 0L) return stamp
            }
        }

        private fun acquireReadLock(gate: ProcessGate): Long {
            while (true) {
                val stamp = gate.lock.tryReadLock(100, TimeUnit.MILLISECONDS)
                if (stamp != 0L) return stamp
            }
        }

        private const val LOCK_FILE = ".reconstruction.lock"
        private const val OWNER_READ_WRITE = 0x180 // 0600; mkdir/file modes are numeric at the syscall seam.

        /** Historical umask-created locks are read-only compatible, then normalized by a writer. */
        private fun isSafeReadPublicationLockMode(mode: Int): Boolean {
            val permissions = mode and 0xfff
            return (permissions and OWNER_READ_WRITE) == OWNER_READ_WRITE &&
                (permissions and 0x5b) == 0 && (permissions and 0xe00) == 0
        }

        private fun sameInputContentState(before: LinuxFileState, after: LinuxFileState): Boolean =
            before.identity == after.identity && before.size == after.size &&
                before.modificationTimeSeconds == after.modificationTimeSeconds &&
                before.modificationTimeNanoseconds == after.modificationTimeNanoseconds &&
                before.changeTimeSeconds == after.changeTimeSeconds &&
                before.changeTimeNanoseconds == after.changeTimeNanoseconds

        private fun readObject(path: Path): JsonObject? {
            if (!Files.exists(path, NOFOLLOW_LINKS)) return null
            require(Files.isRegularFile(path, NOFOLLOW_LINKS)) { "input state must be an ordinary file" }
            val bytes = Files.newInputStream(path, READ, NOFOLLOW_LINKS).use { it.readNBytes(16_385) }
            return OracleJson.parse(bytes, StrictJsonLimits(maximumInputBytes = 16_384)).jsonObject
        }

        private fun writeObject(path: Path, value: JsonObject) {
            require(!Files.isSymbolicLink(path))
            val temporary = Files.createTempFile(path.parent, ".input-state-", ".tmp")
            try {
                FileChannel.open(temporary, WRITE, NOFOLLOW_LINKS).use { channel ->
                    val buffer = ByteBuffer.wrap(value.toString().toByteArray(Charsets.UTF_8))
                    while (buffer.hasRemaining()) channel.write(buffer)
                    channel.force(true)
                }
                Files.move(temporary, path, ATOMIC_MOVE, REPLACE_EXISTING)
                sync(path.parent)
            } finally { Files.deleteIfExists(temporary) }
        }
        private fun sync(directory: Path) { FileChannel.open(directory, READ).use { it.force(true) } }
    }
}
