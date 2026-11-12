package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.jobs.WorkflowStartupRecoveryBudget
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.security.MessageDigest
import java.util.UUID
import kotlinx.serialization.json.*

/** A failed or ambiguous publication is deliberately distinguishable from a rejection. */
internal enum class PublicationResult { PUBLISHED, REJECTED, PENDING }

/** The durable attempt must remain unavailable until workspace recovery reconciles this journal. */
internal class ReconstructionPublicationPendingException :
    IllegalStateException("reconstruction publication is uncertain; reopen storage to recover its journal")

/** Crash-recoverable replacement of an explicit subset of the workspace's fixed members. */
internal class ReconstructionOutputPublication private constructor(
    private val ownership: ReconstructionPublicationLock,
    private val syncDirectory: (Path) -> Unit,
    private val recoveryBudget: WorkflowStartupRecoveryBudget? = null,
) {
    private val root: Path get() = ownership.canonicalRoot
    private val inputSha256: String get() = ownership.admittedInputSha256

    /**
     * The builder receives a private, empty staging directory. It may create only [members].
     * Exceptions and cancellation before the durable decision preserve the live tree. Once the
     * decision has been attempted, failures return PENDING and leave all evidence in place.
     */
    fun publish(
        members: Set<String>,
        buildStage: (Path) -> Unit,
        cancellationCheck: () -> Unit = {},
        onCommitted: () -> Unit = {},
        beforeDecision: (Path) -> Unit = {},
    ): PublicationResult {
        require(members.isNotEmpty() && members.all(PUBLISHABLE::contains))
        require(inputSha256.matches(HASH))
        val txid = UUID.randomUUID().toString()
        val stage = root.resolve(".reconstruction-stage-$txid")
        val previous = root.resolve(".reconstruction-previous-$txid")
        var decisionAttempted = false
        try {
            ownership.borrow(root, inputSha256)
            check(!existsAtRoot(ReconstructionOutputWorkspace.PUBLICATION)) {
                "a pending reconstruction publication requires recovery before another publication"
            }
            openDirectoryPath(root).use { rootHandle ->
                val children = LinuxFilesystemSyscalls.directoryEntryNames(rootHandle, MAX_ENTRIES)
                check(children.none {
                    it.startsWith(".reconstruction-stage-") || it.startsWith(".reconstruction-previous-") ||
                        it.startsWith(".publication-")
                }) {
                    "orphaned publication roots require recovery before another publication"
                }
            }

            // Persist intent before creating either private root. A crash from this point onward
            // is recoverable as an abort unless the durable phase later becomes `decided`.
            val oldMembers = memberRecords(root, members)
            var journal = Journal(
                txid, inputSha256, "preparing", members.sorted(), identity(root, false), null, null,
                oldMembers, emptyMap(),
            )
            writeJournal(journal)
            createPrivateDirectory(stage)
            createPrivateDirectory(previous)
            syncDirectory(root)
            journal = journal.copy(stage = identity(stage), previous = identity(previous))
            writeJournal(journal)
            ownership.withPublicationStage(stage, inputSha256) { buildStage(stage) }
            validateMemberSet(stage, members)
            syncTree(stage)
            // Capture metadata after durability traversal: some filesystems can update directory
            // access times as part of fsync/enumeration even when all content reads are no-atime.
            val newMembers = memberRecords(stage, members)
            journal = journal.copy(phase = "staged", new = newMembers)
            writeJournal(journal)
            ownership.borrow(root, inputSha256)
            verifyPreDecision(journal)
            beforeDecision(stage)
            cancellationCheck() // Last cancellable point; no checks or rejection follow this line.
            decisionAttempted = true
            writeJournal(journal.copy(phase = "decided"))
            rollForward(journal.copy(phase = "decided"))
            ownership.borrow(root, inputSha256)
            writeJournal(journal.copy(phase = "swapped"))
            ownership.borrow(root, inputSha256)
            onCommitted()
            cleanup(journal.copy(phase = "swapped"), alreadyVerified = true)
            return PublicationResult.PUBLISHED
        } catch (failure: Throwable) {
            if (!decisionAttempted) {
                // A cancellation/limit interrupt can arrive while staging or while a blocking
                // file operation is unwinding. Clear it only while restoring the durable
                // pre-decision state; otherwise interruptible FileChannel operations can prevent
                // rollback and strand a journal that was never committed.
                val restoreInterrupt = Thread.interrupted()
                try {
                    recover(ownership, syncDirectory)
                } catch (recoveryFailure: Throwable) {
                    if (failure !== recoveryFailure) failure.addSuppressed(recoveryFailure)
                    return PublicationResult.PENDING
                } finally {
                    if (restoreInterrupt) Thread.currentThread().interrupt()
                }
                if (failure is java.util.concurrent.CancellationException || failure is InterruptedException)
                    return PublicationResult.REJECTED
                throw failure
            }
            // The decision write may have reached durable storage even when force/rename failed.
            return PublicationResult.PENDING
        }
    }

    companion object {
        private const val MAX_JOURNAL = 64 * 1024
        private const val MAX_ENTRIES = ReconstructionOutputTree.MAX_ENTRIES
        private const val MAX_CLEANUP_DEPTH = 256
        private val HASH = Regex("[0-9a-f]{64}")
        private val PUBLISHABLE = setOf("source-tree", "source-tree.zip", "reconstruction.json", ".decomp-agent-sessions")
        private val FIXED = PUBLISHABLE
        private val JOURNAL_KEYS = setOf("schemaVersion", "txid", "inputSha256", "phase", "members", "root", "stage", "previous", "old", "new")
        private val METADATA_JOURNAL_KEYS = JOURNAL_KEYS + setOf("metadataVersion", "xattrPolicy")
        private val LEGACY_ENTRY_KEYS = setOf("present", "type", "mode", "dev", "ino", "commitment")
        private val ENTRY_KEYS = LEGACY_ENTRY_KEYS + setOf("uid", "gid", "nlink", "size", "atimeSec", "atimeNanos", "mtimeSec", "mtimeNanos", "metadataVerified")

        internal fun ownedBy(
            ownership: ReconstructionPublicationLock,
            syncDirectory: (Path) -> Unit,
            recoveryBudget: WorkflowStartupRecoveryBudget? = null,
        ): ReconstructionOutputPublication = ReconstructionOutputPublication(ownership, syncDirectory, recoveryBudget)

        // Recovery follows the existing workspace lease. It may finish a transaction for the
        // previously active input before the newly admitted input is routed into place.
        internal fun recover(
            ownership: ReconstructionPublicationLock,
            syncDirectory: (Path) -> Unit,
            recoveryBudget: WorkflowStartupRecoveryBudget? = null,
            onCommitted: () -> Unit = {},
        ) {
            ownership.validate()
            val root = ownership.canonicalRoot
            val publisher = ownedBy(ownership, syncDirectory, recoveryBudget)
            if (!publisher.existsAtRoot(ReconstructionOutputWorkspace.PUBLICATION)) {
                publisher.cleanupJournalTemps()
                val orphan = publisher.openDirectoryPath(root).use { rootHandle ->
                    publisher.directoryEntryNames(rootHandle, MAX_ENTRIES).firstOrNull {
                        it.startsWith(".reconstruction-stage-") || it.startsWith(".reconstruction-previous-")
                    }
                }
                require(orphan == null) { "orphaned publication roots require manual recovery" }
                return
            }
            val journal = publisher.readJournal()
            require(publisher.activeInputSha256() == journal.inputSha256) {
                "publication journal does not match the active workspace input"
            }
            when (journal.phase) {
                "preparing" -> {
                    publisher.verifyPreparingRoots(journal, allowMissing = false, allowUnrecordedEmpty = true)
                    publisher.writeJournal(journal.copy(phase = "preparing-cleanup"))
                    publisher.finishPreparingCleanup(journal.copy(phase = "preparing-cleanup"))
                }
                "preparing-cleanup" -> publisher.finishPreparingCleanup(journal)
                "staged" -> {
                    publisher.verifyRoots(journal)
                    ownership.validate()
                    // No output rename is legal before the durable decision. Preserve live bytes.
                    publisher.verifyPreDecision(journal)
                    publisher.writeJournal(journal.copy(phase = "aborting"))
                    publisher.finishAbort(journal.copy(phase = "aborting"))
                }
                "aborting" -> { publisher.verifyRoots(journal); publisher.finishAbort(journal) }
                "decided", "swapped" -> {
                    if (journal.phase == "decided") publisher.verifyRoots(journal)
                    ownership.validate()
                    if (journal.phase == "swapped") publisher.verifySwapped(journal) else {
                        publisher.rollForward(journal)
                        publisher.writeJournal(journal.copy(phase = "swapped"))
                    }
                    onCommitted()
                    publisher.cleanup(journal.copy(phase = "swapped"), alreadyVerified = true)
                }
                else -> error("unknown publication phase")
            }
            publisher.cleanupJournalTemps()
        }
    }

    /** Opens an output directory only by walking names below the lease-pinned root descriptor. */
    private fun openDirectoryPath(path: Path): LinuxDescriptor {
        val relative = relativePath(path)
        var current = LinuxFilesystemSyscalls.openDirectoryFrom(ownership.rootDirectoryDescriptor())
        try {
            for (component in relative) {
                val next = LinuxFilesystemSyscalls.openDirectoryAt(current.fd, component)
                current.close()
                current = next
            }
            return current
        } catch (failure: Throwable) {
            current.close()
            throw failure
        }
    }

    private fun relativePath(path: Path): List<String> {
        val normalized = path.toAbsolutePath().normalize()
        require(normalized.startsWith(root)) { "publication path escapes its leased output root" }
        val relative = root.relativize(normalized)
        val components = if (relative.toString().isEmpty()) emptyList() else
            relative.iterator().asSequence().map { it.toString() }.toList()
        return components.also { parts ->
            require(parts.all { it.isNotEmpty() && it != "." && it != ".." && '/' !in it && '\u0000' !in it }) {
                "publication path is not canonical"
            }
        }
    }

    private inline fun <T> withParent(path: Path, action: (LinuxDescriptor, String) -> T): T? {
        val parts = relativePath(path)
        require(parts.isNotEmpty()) { "publication root is not a member path" }
        val parentParts = parts.dropLast(1)
        val parentPath = parentParts.fold(root) { current, part -> current.resolve(part) }
        val parent = try { openDirectoryPath(parentPath) } catch (failure: decompengine.acp.LinuxSyscallException) {
            if (failure.errno == 2) return null
            throw failure
        }
        parent.use { return action(parent, parts.last()) }
    }

    private fun existsAtRoot(name: String): Boolean =
        LinuxFilesystemSyscalls.openPathAtOrNull(ownership.rootDirectoryDescriptor().fd, name)?.use { true } ?: false

    private fun createPrivateDirectory(path: Path) {
        withParent(path) { parent, name ->
            LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)?.use {
                error("publication private directory already exists")
            }
            LinuxFilesystemSyscalls.createDirectory(parent.fd, name, 0x1c0) // 0700
            val created = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
            created.use {
                require((it.identity.mode and 0xfff) == 0x1c0 && it.identity.uid == LinuxFilesystemSyscalls.identity(parent.fd).uid) {
                    "publication root must be owned and mode 0700"
                }
                LinuxFilesystemSyscalls.synchronize(it)
                syncDirectoryCallback(path)
            }
        } ?: error("publication parent directory is missing")
    }

    private fun syncDirectory(path: Path) {
        recoveryBudget?.checkpoint()
        val directory = openDirectoryPath(path)
        directory.use {
            LinuxFilesystemSyscalls.synchronize(it)
            syncDirectoryCallback(path)
        }
    }

    private fun identity(path: Path, requirePrivate: Boolean = true): RootIdentity {
        val descriptor = openDirectoryPath(path)
        descriptor.use {
            if (requirePrivate) require((it.identity.mode and 0xfff) == 0x1c0 &&
                it.identity.uid == LinuxFilesystemSyscalls.identity(ownership.rootDirectoryDescriptor().fd).uid) {
                "publication root must be owned and mode 0700"
            }
            if (requirePrivate) require(it.identity.mountId == ownership.rootDirectoryDescriptor().identity.mountId) {
                "publication private root crossed a mount boundary"
            }
            return RootIdentity(it.identity.key.device.toString(), it.identity.key.inode.toString())
        }
    }

    private fun rootIdentityIfPresent(path: Path): RootIdentity? = try {
        identity(path)
    } catch (failure: decompengine.acp.LinuxSyscallException) {
        if (failure.errno == 2) null else throw failure
    }

    private fun deleteTree(path: Path, depth: Int = 0, entries: IntArray = intArrayOf(0)) {
        recoveryBudget?.checkpoint()
        recoveryBudget?.publicationRecoveryEntry()
        require(depth <= MAX_CLEANUP_DEPTH) { "publication cleanup exceeds depth bound" }
        entries[0] = Math.addExact(entries[0], 1)
        require(entries[0] <= MAX_ENTRIES) { "publication cleanup exceeds entry bound" }
        withParent(path) { parent, name ->
            val pathEntry = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name) ?: return@withParent
            pathEntry.use { entry ->
                val identity = entry.identity
                require(identity.mountId == ownership.rootDirectoryDescriptor().identity.mountId) {
                    "publication cleanup crossed a mount boundary"
                }
                if (identity.isDirectory) {
                    val directory = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
                    directory.use {
                        require(it.identity.key == identity.key && it.identity.mountId == identity.mountId) {
                            "publication directory changed during cleanup"
                        }
                        val remaining = MAX_ENTRIES - entries[0]
                        require(remaining > 0) { "publication cleanup exceeds entry bound" }
                        val children = directoryEntryNames(it, remaining)
                        for (child in children) deleteTree(path.resolve(child), depth + 1, entries)
                        LinuxFilesystemSyscalls.synchronize(it)
                    }
                    LinuxFilesystemSyscalls.removeDirectory(parent.fd, name)
                } else {
                    // unlinkat removes only this directory entry; it does not follow a symlink
                    // or modify another name for a hard-linked inode.
                    LinuxFilesystemSyscalls.unlink(parent.fd, name)
                }
                LinuxFilesystemSyscalls.synchronize(parent)
            }
        }
    }

    private fun syncTree(path: Path) {
        val directory = openDirectoryPath(path)
        directory.use { syncTreeAt(it, path) }
    }

    private fun syncTreeAt(directory: LinuxDescriptor, path: Path) {
        recoveryBudget?.checkpoint()
        val names = LinuxFilesystemSyscalls.directoryEntryNamesWithoutAtime(directory, MAX_ENTRIES)
        for (name in names) {
            val entry = LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)
                ?: throw IllegalStateException("publication entry disappeared during synchronization")
            entry.use {
                require(!it.identity.isSymbolicLink && (it.identity.isRegularFile || it.identity.isDirectory)) {
                    "publication sync encountered a link or special file"
                }
                require(it.identity.mountId == ownership.rootDirectoryDescriptor().identity.mountId) {
                    "publication synchronization crossed a mount boundary"
                }
                if (it.identity.isDirectory) {
                    val child = LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, name)
                    child.use {
                        require(it.identity.key == entry.identity.key && it.identity.mountId == entry.identity.mountId)
                        syncTreeAt(it, path.resolve(name))
                    }
                } else {
                    require(it.identity.linkCount == 1) { "publication sync encountered a hard link" }
                    val file = LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, name)
                        ?: throw IllegalStateException("publication file disappeared during synchronization")
                    file.use {
                        val readable = LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(it)
                        readable.use { LinuxFilesystemSyscalls.synchronize(it) }
                    }
                }
            }
        }
        LinuxFilesystemSyscalls.synchronize(directory)
        syncDirectoryCallback(path)
    }

    private fun unlinkRoot(name: String) {
        LinuxFilesystemSyscalls.unlink(ownership.rootDirectoryDescriptor().fd, name)
    }

    private fun syncDirectoryCallback(path: Path) = this.syncDirectory.invoke(path)

    private fun directoryEntryNames(directory: LinuxDescriptor, maximum: Int): List<String> {
        recoveryBudget?.checkpoint()
        return LinuxFilesystemSyscalls.directoryEntryNamesWithoutAtime(
            directory,
            maximum,
            cancellationCheck = { recoveryBudget?.checkpoint() },
            onEntry = { recoveryBudget?.publicationRecoveryEntry() },
        )
    }

    private fun activeInputSha256(): String {
        val bytes = withParent(root.resolve(ReconstructionOutputWorkspace.ACTIVE)) { parent, name ->
            val descriptor = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)
                ?: return@withParent null
            descriptor.use {
                require(it.identity.linkCount == 1 && (it.identity.mode and 0x1ff) == 0x180 &&
                    it.identity.uid == LinuxFilesystemSyscalls.identity(ownership.rootDirectoryDescriptor().fd).uid) {
                    "active input marker must be an owned private regular file"
                }
                LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(it).use { readable ->
                    LinuxFilesystemSyscalls.read(readable, 16_385) { }
                }
            }
        } ?: return ""
        val json = OracleJson.parse(bytes, StrictJsonLimits(maximumInputBytes = 16_384)).jsonObject
        require(json.keys == setOf("schemaVersion", "inputSha256") && json["schemaVersion"] == JsonPrimitive(1))
        return json.getValue("inputSha256").jsonPrimitive.content.also { require(HASH.matches(it)) }
    }

    /** A durable cleanup phase permits either private root to have been removed already. */
    private fun finishPreparingCleanup(j: Journal) {
        verifyPreparingRoots(j, allowMissing = true, allowUnrecordedEmpty = true)
        ownership.validate()
        for (name in j.members) {
            require(recordAt(root.resolve(name), schemaVersion = j.schemaVersion) == j.old.getValue(name)) {
                "live output changed before publication reached its staged phase"
            }
        }
        require(directoryIsEmptyIfPresent(previous(j))) {
            "previous output root is not empty before the publication decision"
        }
        deleteTree(previous(j))
        deleteTree(stage(j))
        syncDirectory(root)
        unlinkRoot(ReconstructionOutputWorkspace.PUBLICATION)
        try {
            syncDirectory(root)
        } catch (failure: Throwable) {
            runCatching { writeJournal(j) }
            throw failure
        }
    }

    private fun verifyPreparingRoots(j: Journal, allowMissing: Boolean, allowUnrecordedEmpty: Boolean) {
        require(identity(root, false) == j.root)
        fun verify(path: Path, expected: RootIdentity?) {
            val actual = rootIdentityIfPresent(path)
            if (actual == null) require(allowMissing || expected == null) {
                "publication private root disappeared before cleanup"
            } else if (expected != null) require(actual == expected) { "publication private root identity changed" }
            else if (allowUnrecordedEmpty) require(directoryIsEmptyIfPresent(path)) {
                "unrecorded publication root is not empty"
            } else error("publication private root identity was not recorded")
        }
        verify(stage(j), j.stage)
        verify(previous(j), j.previous)
    }

    private fun directoryIsEmptyIfPresent(path: Path): Boolean {
        val descriptor = try { openDirectoryPath(path) }
        catch (failure: decompengine.acp.LinuxSyscallException) {
            if (failure.errno == 2) return true else throw failure
        }
        return descriptor.use { directoryEntryNames(it, 1).isEmpty() }
    }

    /** Remove only private, bounded journal-write sidecars left by an interrupted atomic replace. */
    private fun cleanupJournalTemps() {
        val rootDescriptor = ownership.rootDirectoryDescriptor()
        var removed = false
        val names = directoryEntryNames(rootDescriptor, MAX_ENTRIES)
        for (name in names.filter { it.startsWith(".publication-") }) {
            require(name.matches(Regex("\\.publication-[0-9a-f-]{36}\\.tmp"))) {
                "unrecognized publication journal sidecar requires manual recovery"
            }
            val temp = LinuxFilesystemSyscalls.openRegularFileAtOrNull(rootDescriptor.fd, name)
                ?: error("publication journal sidecar changed during recovery")
            temp.use {
                val state = LinuxFilesystemSyscalls.fileState(temp)
                require(temp.identity.linkCount == 1 && (temp.identity.mode and 0xfff) == 0x180 &&
                    temp.identity.uid == rootDescriptor.identity.uid && state.size in 0..MAX_JOURNAL.toLong()) {
                    "publication journal sidecar is not a bounded private regular file"
                }
            }
            LinuxFilesystemSyscalls.unlink(rootDescriptor.fd, name)
            removed = true
        }
        if (removed) {
            LinuxFilesystemSyscalls.synchronize(rootDescriptor)
            syncDirectoryCallback(root)
        }
    }

    private fun readJournal(): Journal {
        val bytes = withParent(root.resolve(ReconstructionOutputWorkspace.PUBLICATION)) { parent, name ->
            val descriptor = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)
                ?: throw IllegalStateException("publication journal is missing")
            descriptor.use {
                require(it.identity.linkCount == 1 && (it.identity.mode and 0xfff) == 0x180) {
                    "publication journal must be a private mode-0600 regular file"
                }
                val initial = LinuxFilesystemSyscalls.fileState(it)
                require(initial.size in 0..MAX_JOURNAL.toLong()) { "publication journal exceeds 64 KiB" }
                recoveryBudget?.publicationRecoveryBytes(initial.size)
                val readable = LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(it)
                val bytes = readable.use { LinuxFilesystemSyscalls.read(it, MAX_JOURNAL + 1) { recoveryBudget?.checkpoint() } }
                require(initial == LinuxFilesystemSyscalls.fileState(it)) { "publication journal changed while it was read" }
                bytes
            }
        } ?: throw IllegalStateException("publication journal parent is missing")
        require(bytes.size <= MAX_JOURNAL) { "publication journal exceeds 64 KiB" }
        val json = OracleJson.parse(bytes, StrictJsonLimits(maximumInputBytes = MAX_JOURNAL)).jsonObject
        fun JsonElement.strictString(): String {
            val primitive = jsonPrimitive
            require(primitive.isString) { "publication journal string has the wrong JSON scalar type" }
            return primitive.content
        }
        fun JsonElement.strictBoolean(): Boolean {
            val primitive = jsonPrimitive
            require(!primitive.isString && primitive.booleanOrNull != null) {
                "publication journal boolean has the wrong JSON scalar type"
            }
            return requireNotNull(primitive.booleanOrNull)
        }
        fun JsonElement.strictInt(): Int {
            val primitive = jsonPrimitive
            require(!primitive.isString && primitive.intOrNull != null) {
                "publication journal integer has the wrong JSON scalar type"
            }
            return requireNotNull(primitive.intOrNull)
        }
        fun JsonElement.strictLong(): Long {
            val primitive = jsonPrimitive
            require(!primitive.isString && primitive.longOrNull != null) {
                "publication journal integer has the wrong JSON scalar type"
            }
            return requireNotNull(primitive.longOrNull)
        }
        val schema = json["schemaVersion"]?.jsonPrimitive
        require(schema != null && !schema.isString && schema.intOrNull in setOf(3, 4))
        val schemaVersion = requireNotNull(schema.intOrNull)
        require(json.keys == if (schemaVersion == 3) JOURNAL_KEYS else METADATA_JOURNAL_KEYS)
        if (schemaVersion == 4) {
            require(json.getValue("metadataVersion").strictInt() == 1)
            require(json.getValue("xattrPolicy").strictString() == "NONE")
        }
        val members = json.getValue("members").jsonArray.map(JsonElement::strictString)
        require(members.isNotEmpty() && members == members.distinct().sorted() && members.all(FIXED::contains))
        val phase = json.getValue("phase").strictString()
        require(phase in setOf("preparing", "preparing-cleanup", "staged", "aborting", "decided", "swapped"))
        fun records(name: String): Map<String, EntryRecord> {
            val obj = json.getValue(name).jsonObject
            require(obj.keys == if (phase in setOf("preparing", "preparing-cleanup") && name == "new") emptySet() else members.toSet())
            return obj.mapValues { (_, v) ->
                val o = v.jsonObject
                require(o.keys == if (schemaVersion == 3) LEGACY_ENTRY_KEYS else ENTRY_KEYS)
                val present = o.getValue("present").strictBoolean()
                val type = o.getValue("type").strictString()
                val mode = o.getValue("mode").strictInt()
                val dev = o.getValue("dev").strictString()
                val ino = o.getValue("ino").strictString()
                val commitment = o.getValue("commitment").strictString()
                require(if (present) type in setOf("file", "directory") && mode in 0..0xfff && dev.matches(Regex("[0-9]+")) && ino.matches(Regex("[0-9]+")) && commitment.matches(HASH)
                    else type == "absent" && mode == 0 && dev.isEmpty() && ino.isEmpty() && commitment.isEmpty())
                val record = if (schemaVersion == 3) EntryRecord(present, type, mode, dev, ino, commitment, metadataVerified = false)
                else EntryRecord(present, type, mode, dev, ino, commitment,
                    o.getValue("uid").strictInt(), o.getValue("gid").strictInt(), o.getValue("nlink").strictInt(),
                    o.getValue("size").strictLong(), o.getValue("atimeSec").strictLong(), o.getValue("atimeNanos").strictInt(),
                    o.getValue("mtimeSec").strictLong(), o.getValue("mtimeNanos").strictInt(), o.getValue("metadataVerified").strictBoolean())
                require(schemaVersion == 3 || if (present) record.linkCount >= 1 && record.size >= 0 && record.atimeNanoseconds in 0 until 1_000_000_000 &&
                    record.mtimeNanoseconds in 0 until 1_000_000_000 && record.metadataVerified
                    else record.uid == 0 && record.gid == 0 && record.linkCount == 0 && record.size == 0L &&
                        record.atimeSeconds == 0L && record.atimeNanoseconds == 0 && record.mtimeSeconds == 0L &&
                        record.mtimeNanoseconds == 0 && record.metadataVerified)
                record
            }
        }
        fun rootIdentity(key: String, nullable: Boolean = false): RootIdentity? {
            val element = json.getValue(key)
            if (nullable && element == JsonNull) return null
            val value = element.jsonObject; require(value.keys == setOf("dev", "ino"))
            val dev = value.getValue("dev").strictString()
            val ino = value.getValue("ino").strictString()
            require(dev.matches(Regex("[0-9]+")) && ino.matches(Regex("[0-9]+")))
            return RootIdentity(dev, ino)
        }
        val txid = json.getValue("txid").strictString()
        require(txid.matches(Regex("[0-9a-f-]{36}")))
        val hash = json.getValue("inputSha256").strictString(); require(hash.matches(HASH))
        val root = requireNotNull(rootIdentity("root"))
        val stage = rootIdentity("stage", nullable = true)
        val previous = rootIdentity("previous", nullable = true)
        val old = records("old")
        val fresh = records("new")
        when (phase) {
            "preparing", "preparing-cleanup" -> require(fresh.isEmpty())
            else -> require(stage != null && previous != null && fresh.keys == members.toSet())
        }
        return Journal(txid, hash, phase, members, root, stage, previous, old, fresh, schemaVersion)
    }

    private fun verifyRoots(j: Journal) {
        require(identity(root, false) == j.root)
        val stageIdentity = rootIdentityIfPresent(stage(j))
        val previousIdentity = rootIdentityIfPresent(previous(j))
        if (j.phase == "swapped") {
            require(stageIdentity == null || stageIdentity == j.stage) { "staging root identity changed" }
            require(previousIdentity == null || previousIdentity == j.previous) { "previous root identity changed" }
        } else if (j.phase == "aborting") {
            require(stageIdentity == null || stageIdentity == j.stage) { "staging root identity changed" }
            require(previousIdentity == null || previousIdentity == j.previous) { "previous root identity changed" }
        } else {
            require(stageIdentity == j.stage) { "staging root identity changed" }
            require(previousIdentity == j.previous) { "previous root identity changed" }
        }
    }
    private fun verifyPreDecision(j: Journal) {
        verifyAllCopies(j)
        validatePrivateMembers(stage(j), j.members.toSet())
        validatePrivateMembers(previous(j), emptySet())
        for (name in j.members) {
            require(recordAt(root.resolve(name), schemaVersion = j.schemaVersion) == j.old.getValue(name)) { "pre-decision live output changed" }
            require(recordAt(stage(j).resolve(name), schemaVersion = j.schemaVersion) == j.new.getValue(name)) { "pre-decision stage changed" }
            require(!recordAt(previous(j).resolve(name)).present) { "illegal previous copy before decision" }
        }
    }

    private fun finishAbort(j: Journal) {
        verifyRoots(j)
        for (name in j.members) {
            require(recordAt(root.resolve(name), schemaVersion = j.schemaVersion) == j.old.getValue(name)) {
                "live output changed while aborting an undecided publication"
            }
            require(!recordAt(previous(j).resolve(name)).present) {
                "previous output appeared during abort cleanup"
            }
            // Staged output is disposable after the aborting decision. Its exact contents may
            // already be partially removed by an earlier cleanup attempt; the recursive remover
            // still rejects links, special files, mount crossings and hard links.
        }
        validatePrivateMembers(stage(j), j.members.toSet())
        validatePrivateMembers(previous(j), emptySet())
        deleteTree(previous(j))
        syncDirectory(root)
        deleteTree(stage(j))
        syncDirectory(root)
        unlinkRoot(ReconstructionOutputWorkspace.PUBLICATION)
        try {
            syncDirectory(root)
        } catch (failure: Throwable) {
            runCatching { writeJournal(j) }
            throw failure
        }
    }

    private fun verifyAllCopies(j: Journal) {
        validatePrivateMembers(stage(j), j.members.toSet())
        validatePrivateMembers(previous(j), j.members.toSet())
        val liveBudget = recoveryTreeBudget()
        val stageBudget = recoveryTreeBudget()
        val previousBudget = recoveryTreeBudget()
        for (name in j.members) {
            val old = j.old.getValue(name); val fresh = j.new.getValue(name)
            val live = recordAt(root.resolve(name), liveBudget, j.schemaVersion); val staged = recordAt(stage(j).resolve(name), stageBudget, j.schemaVersion); val backup = recordAt(previous(j).resolve(name), previousBudget, j.schemaVersion)
            val oldAtLive = live == old && old.present
            val oldAtBackup = backup == old && old.present
            val newAtStage = staged == fresh && fresh.present
            val newAtLive = live == fresh && fresh.present
            require((live == old || live == fresh || !live.present) && (staged == fresh || !staged.present) && (backup == old || !backup.present)) {
                "conflicting or corrupt publication copy: $name old=$old fresh=$fresh live=$live stage=$staged previous=$backup"
            }
            require((!old.present || oldAtLive.xor(oldAtBackup)) && (!fresh.present || newAtStage.xor(newAtLive))) {
                "publication copy is missing or duplicated: $name"
            }
            require(!(oldAtLive && newAtLive)) { "old and new copies conflict at live location" }
        }
    }

    private fun verifySwapped(j: Journal) {
        verifyRoots(j)
        validatePrivateMembers(stage(j), j.members.toSet())
        validatePrivateMembers(previous(j), j.members.toSet())
        val liveBudget = recoveryTreeBudget()
        val previousBudget = recoveryTreeBudget()
        val stageBudget = recoveryTreeBudget()
        for (name in j.members) {
            val live = recordAt(root.resolve(name), liveBudget, j.schemaVersion)
            val expected = j.new.getValue(name)
            require(live == expected) { "swapped live tree is corrupt: $name expected=$expected actual=$live" }
            // Either private copy can be partly deleted after a crash during cleanup. Hashing
            // every remaining tree still enforces the same bounds and rejects unsafe entries.
            recordAt(previous(j).resolve(name), previousBudget)
            recordAt(stage(j).resolve(name), stageBudget)
        }
    }

    private fun rollForward(j: Journal) {
        ownership.validate()
        verifyRoots(j)
        verifyAllCopies(j)
        for (name in j.members) {
            val old = j.old.getValue(name)
            if (old.present) {
                val live = root.resolve(name); val backup = previous(j).resolve(name)
                if (!recordAt(backup).present) moveDurable(live, backup)
            }
        }
        for (name in j.members) {
            val fresh = j.new.getValue(name)
            if (fresh.present) {
                val staged = stage(j).resolve(name); val live = root.resolve(name)
                if (!recordAt(live).present) moveDurable(staged, live)
            }
        }
        verifyAllCopies(j)
    }

    private fun moveDurable(from: Path, to: Path) {
        recoveryBudget?.checkpoint()
        ownership.validate()
        withParent(from) { fromParent, fromName ->
            withParent(to) { toParent, toName ->
                val source = LinuxFilesystemSyscalls.openPathAtOrNull(fromParent.fd, fromName)
                    ?: error("publication source disappeared before rename")
                source.use {
                    require(!it.identity.isSymbolicLink && (it.identity.isDirectory || it.identity.isRegularFile)) {
                        "publication source is not an ordinary tree member"
                    }
                    LinuxFilesystemSyscalls.openPathAtOrNull(toParent.fd, toName)?.use {
                        error("publication destination already exists")
                    }
                    LinuxFilesystemSyscalls.renameNoReplace(fromParent.fd, fromName, toParent.fd, toName)
                }
                LinuxFilesystemSyscalls.synchronize(fromParent)
                syncDirectoryCallback(from.parent)
                if (from.parent != to.parent) {
                    LinuxFilesystemSyscalls.synchronize(toParent)
                    syncDirectoryCallback(to.parent)
                }
            } ?: error("publication destination parent is missing")
        } ?: error("publication source parent is missing")
    }

    private fun writeJournal(j: Journal) {
        val bytes = encode(j).toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_JOURNAL)
        val rootDescriptor = ownership.rootDirectoryDescriptor()
        val tempName = ".publication-${UUID.randomUUID()}.tmp"
        val temporary = LinuxFilesystemSyscalls.createRegularFile(rootDescriptor.fd, tempName, 0x180)
        var failure: Throwable? = null
        try {
            FileChannel.open(LinuxFilesystemSyscalls.descriptorPath(temporary), WRITE).use { ch ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) ch.write(buffer)
                ch.force(true)
            }
            LinuxFilesystemSyscalls.synchronize(temporary)
            LinuxFilesystemSyscalls.renameReplace(rootDescriptor.fd, tempName, rootDescriptor.fd,
                ReconstructionOutputWorkspace.PUBLICATION)
            LinuxFilesystemSyscalls.synchronize(rootDescriptor)
            syncDirectoryCallback(root)
        } catch (caught: Throwable) {
            failure = caught
        } finally {
            try { temporary.close() } catch (caught: Throwable) {
                if (failure == null) failure = caught else if (failure !== caught) failure!!.addSuppressed(caught)
            }
            try {
                val leftover = LinuxFilesystemSyscalls.openPathAtOrNull(rootDescriptor.fd, tempName)
                if (leftover != null) {
                    leftover.close()
                    LinuxFilesystemSyscalls.unlink(rootDescriptor.fd, tempName)
                    LinuxFilesystemSyscalls.synchronize(rootDescriptor)
                    syncDirectoryCallback(root)
                }
            } catch (caught: Throwable) {
                if (failure == null) failure = caught else if (failure !== caught) failure!!.addSuppressed(caught)
            }
        }
        failure?.let { throw it }
    }

    private fun cleanup(j: Journal, alreadyVerified: Boolean = false) {
        if (!alreadyVerified) verifySwapped(j)
        validatePrivateMembers(previous(j), j.members.toSet())
        validatePrivateMembers(stage(j), j.members.toSet())
        deleteTree(previous(j)); syncDirectory(root)
        deleteTree(stage(j)); syncDirectory(root)
        unlinkRoot(ReconstructionOutputWorkspace.PUBLICATION)
        try {
            syncDirectory(root)
        } catch (failure: Throwable) {
            // The unlink may or may not have reached stable storage. Reinstall a complete
            // swapped journal before returning pending so the next opener can verify live data.
            runCatching { writeJournal(j) }
            throw failure
        }
    }

    private fun memberRecords(base: Path, members: Set<String>): Map<String, EntryRecord> {
        val budget = PublicationTreeBudget()
        return members.associateWith { name -> recordAt(base.resolve(name), budget) }
    }
    private fun validatePrivateMembers(directory: Path, allowed: Set<String>) {
        val descriptor = try { openDirectoryPath(directory) }
        catch (failure: decompengine.acp.LinuxSyscallException) { if (failure.errno == 2) return else throw failure }
        descriptor.use {
            val names = directoryEntryNames(it, MAX_ENTRIES)
            require(names.all(allowed::contains)) { "publication private root contains an unjournaled member" }
        }
    }
    private fun validateMemberSet(stage: Path, members: Set<String>) {
        openDirectoryPath(stage).use { descriptor ->
            val unexpected = LinuxFilesystemSyscalls.directoryEntryNames(descriptor, MAX_ENTRIES).filterNot(members::contains).sorted()
            require(unexpected.isEmpty()) { "stage contains non-member entries: ${unexpected.joinToString(",")}" }
        }
    }

    private fun recordAt(path: Path, budget: PublicationTreeBudget = recoveryTreeBudget(), schemaVersion: Int = 4): EntryRecord {
        val result = withParent(path) { parent, name ->
            if (schemaVersion == 3) ReconstructionOutputTree.legacyRecordAt(parent, Path.of(name), budget)
            else ReconstructionOutputTree.recordAt(parent, Path.of(name), budget)
        } ?: ReconstructionOutputTree.absent().let { if (schemaVersion == 3) it.copy(metadataVerified = false) else it }
        return EntryRecord(result.present, result.type, result.mode, result.dev, result.ino, result.commitment,
            result.uid, result.gid, result.linkCount, result.size, result.atimeSeconds, result.atimeNanoseconds,
            result.mtimeSeconds, result.mtimeNanoseconds, result.metadataVerified)
    }

    private fun recoveryTreeBudget(): PublicationTreeBudget = PublicationTreeBudget(
        accountEntry = { recoveryBudget?.publicationRecoveryEntry() },
        accountBytes = { bytes -> recoveryBudget?.publicationRecoveryBytes(bytes) },
        checkpoint = { recoveryBudget?.checkpoint() },
    )

    private fun stage(j: Journal) = root.resolve(".reconstruction-stage-${j.txid}")
    private fun previous(j: Journal) = root.resolve(".reconstruction-previous-${j.txid}")

    private fun encode(j: Journal): String = buildJsonObject {
        put("schemaVersion", j.schemaVersion); put("txid", j.txid); put("inputSha256", j.inputSha256); put("phase", j.phase)
        if (j.schemaVersion >= 4) { put("metadataVersion", 1); put("xattrPolicy", "NONE") }
        put("members", JsonArray(j.members.map(::JsonPrimitive)))
        fun ident(v: RootIdentity) = buildJsonObject { put("dev", v.dev); put("ino", v.ino) }
        put("root", ident(j.root)); put("stage", j.stage?.let(::ident) ?: JsonNull); put("previous", j.previous?.let(::ident) ?: JsonNull)
        fun rec(r: EntryRecord) = buildJsonObject {
            put("present", r.present); put("type", r.type); put("mode", r.mode); put("dev", r.dev); put("ino", r.ino); put("commitment", r.commitment)
            if (j.schemaVersion >= 4) {
                put("uid", r.uid); put("gid", r.gid); put("nlink", r.linkCount); put("size", r.size)
                put("atimeSec", r.atimeSeconds); put("atimeNanos", r.atimeNanoseconds)
                put("mtimeSec", r.mtimeSeconds); put("mtimeNanos", r.mtimeNanoseconds); put("metadataVerified", r.metadataVerified)
            }
        }
        put("old", buildJsonObject { j.old.toSortedMap().forEach { (k, v) -> put(k, rec(v)) } })
        put("new", buildJsonObject { j.new.toSortedMap().forEach { (k, v) -> put(k, rec(v)) } })
    }.toString()

    private data class RootIdentity(val dev: String, val ino: String)
    private data class EntryRecord(val present: Boolean, val type: String, val mode: Int, val dev: String, val ino: String, val commitment: String,
        val uid: Int = 0, val gid: Int = 0, val linkCount: Int = 0, val size: Long = 0, val atimeSeconds: Long = 0,
        val atimeNanoseconds: Int = 0, val mtimeSeconds: Long = 0, val mtimeNanoseconds: Int = 0, val metadataVerified: Boolean = false)
    private data class Journal(val txid: String, val inputSha256: String, val phase: String, val members: List<String>, val root: RootIdentity, val stage: RootIdentity?, val previous: RootIdentity?, val old: Map<String, EntryRecord>, val new: Map<String, EntryRecord>, val schemaVersion: Int = 4)

}
