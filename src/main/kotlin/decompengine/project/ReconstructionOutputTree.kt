package decompengine.project

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileState
import decompengine.acp.LinuxFilesystemSyscalls
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.nio.file.StandardOpenOption.READ
import java.security.MessageDigest

/** One authenticated member observation; absent has one canonical encoding. */
internal data class PublicationEntryRecord(
    val present: Boolean,
    val type: String,
    val mode: Int,
    val dev: String,
    val ino: String,
    val commitment: String,
    val uid: Int = 0,
    val gid: Int = 0,
    val linkCount: Int = 0,
    val size: Long = 0,
    val atimeSeconds: Long = 0,
    val atimeNanoseconds: Int = 0,
    val mtimeSeconds: Long = 0,
    val mtimeNanoseconds: Int = 0,
    val metadataVerified: Boolean = true,
)

/** Shared accounting across every member in one complete tree image. */
internal data class PublicationTreeBudget(
    var entries: Int = 0,
    var bytes: Long = 0,
    val accountEntry: () -> Unit = {},
    val accountBytes: (Long) -> Unit = {},
    val checkpoint: () -> Unit = {},
)

/** Descriptor-relative, bounded versioned commitments for workspace publication members. */
internal object ReconstructionOutputTree {
    const val MAX_ENTRIES = 200_000
    const val MAX_DEPTH = 64
    const val MAX_BYTES = 4L * 1024 * 1024 * 1024

    private val FILE_DOMAIN = "reconstruction-file-v3\u0000".toByteArray(StandardCharsets.US_ASCII)
    private val DIRECTORY_DOMAIN = "reconstruction-directory-v3\u0000".toByteArray(StandardCharsets.US_ASCII)
    private val LEGACY_FILE_DOMAIN = "reconstruction-file-v2\u0000".toByteArray(StandardCharsets.US_ASCII)
    private val LEGACY_DIRECTORY_DOMAIN = "reconstruction-directory-v2\u0000".toByteArray(StandardCharsets.US_ASCII)
    private val HASH = Regex("[0-9a-f]{64}")

    fun recordAt(root: LinuxDescriptor, relative: Path, budget: PublicationTreeBudget): PublicationEntryRecord {
        require(!relative.isAbsolute)
        val parts = relative.iterator().asSequence().map { it.toString() }.toList()
        require(parts.isNotEmpty() && parts.all(::validComponent))
        var parent = root
        var ownedParent: LinuxDescriptor? = null
        try {
            for (component in parts.dropLast(1)) {
                val pathEntry = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, component) ?: return absent()
                val next = pathEntry.use {
                    require(it.identity.isDirectory && !it.identity.isSymbolicLink) {
                        "publication member path has a non-directory parent"
                    }
                    LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, component).also { opened ->
                        require(sameObject(it.identity, opened.identity)) {
                            "publication directory changed while it was opened"
                        }
                    }
                }
                ownedParent?.close()
                ownedParent = next
                parent = next
            }
            return recordEntryAt(parent, parts.last(), "", 0, root.identity.mountId, budget) ?: absent()
        } finally {
            ownedParent?.close()
        }
    }

    private fun recordEntryAt(
        parent: LinuxDescriptor,
        name: String,
        relativeName: String,
        depth: Int,
        rootMountId: Long,
        budget: PublicationTreeBudget,
        alreadyAccounted: Boolean = false,
    ): PublicationEntryRecord? {
        val entry = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name) ?: return null
        entry.use {
            val before = LinuxFilesystemSyscalls.identity(entry.fd)
            require(!before.isSymbolicLink && (before.isDirectory || before.isRegularFile)) {
                "publication tree contains a link or special file"
            }
            require(before.mountId == rootMountId) { "publication tree crosses a mount boundary" }
            return recordEntry(parent, name, entry, before, relativeName.ifEmpty { name }, depth, rootMountId,
                budget, alreadyAccounted)
        }
    }

    private fun recordEntry(
        parent: LinuxDescriptor,
        name: String,
        entry: LinuxDescriptor,
        before: decompengine.acp.LinuxFileIdentity,
        relativeName: String,
        depth: Int,
        rootMountId: Long,
        budget: PublicationTreeBudget,
        alreadyAccounted: Boolean,
    ): PublicationEntryRecord {
        require(depth <= MAX_DEPTH) { "publication tree exceeds depth bound" }
        if (!alreadyAccounted) accountEntry(budget)
        val mode = before.mode and 0xfff
        if (before.isRegularFile) {
            require(before.linkCount == 1) { "hard-linked publication file" }
            val opened = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)
                ?: throw IOException("publication file disappeared while it was opened")
            opened.use {
                require(sameObject(before, opened.identity)) { "publication file changed while it was opened" }
                    val readable = LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(opened)
                readable.use {
                    val initial = LinuxFilesystemSyscalls.fileState(readable)
                    require(sameObject(before, initial.identity) && initial.identity.linkCount == 1) {
                        "publication file descriptor identity changed"
                    }
                    require(initial.size in 0..MAX_BYTES) { "publication file exceeds byte bound" }
                    // Reserve the descriptor-observed size before reading any bytes. Recovery
                    // shares this accounting across journals, generations, and repeated checks.
                    budget.accountBytes(initial.size)
                    require(initial.size <= MAX_BYTES - budget.bytes) {
                        "publication tree exceeds byte bound"
                    }
                    val contentDigest = MessageDigest.getInstance("SHA-256")
                    val bufferBytes = ByteArray(64 * 1024)
                    val buffer = ByteBuffer.wrap(bufferBytes)
                    var fileBytes = 0L
                    // Read only the size reserved above. Reads use the descriptor opened with
                    // O_NOATIME, so hashing cannot alter the metadata being committed.
                    while (fileBytes < initial.size) {
                        budget.checkpoint()
                        val chunk = LinuxFilesystemSyscalls.readWithoutAtime(readable,
                            minOf(bufferBytes.size.toLong(), initial.size - fileBytes).toInt())
                        if (chunk.isEmpty()) throw IOException("publication file ended before its observed size")
                        val count = chunk.size
                        val nextTreeBytes = Math.addExact(budget.bytes, count.toLong())
                        require(nextTreeBytes <= MAX_BYTES) { "publication tree exceeds byte bound" }
                        fileBytes = Math.addExact(fileBytes, count.toLong())
                        contentDigest.update(chunk)
                        budget.bytes = nextTreeBytes
                    }
                    val finalState = LinuxFilesystemSyscalls.fileState(readable)
                    require(initial == finalState && fileBytes == finalState.size) {
                        "publication file changed while its content was committed"
                    }
                    val freshName = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)
                        ?: throw IOException("publication file name disappeared after hashing")
                    freshName.use {
                        require(sameObject(freshName.identity, before)) {
                            "publication file name changed while its content was committed"
                        }
                    }
                    requireNoXattrs(opened)
                    require(finalState == LinuxFilesystemSyscalls.fileState(readable)) {
                        "publication file metadata changed while its xattr policy was checked"
                    }
                    val treeDigest = MessageDigest.getInstance("SHA-256")
                    treeDigest.update(FILE_DOMAIN)
                    updateMetadata(treeDigest, before, finalState, fileBytes)
                    treeDigest.update(contentDigest.digest())
                    return record("file", before, finalState, fileBytes, hex(treeDigest.digest()))
                }
            }
        }

        require(before.isDirectory && !before.isSymbolicLink) { "publication tree contains a special file" }
        val directory = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
        directory.use {
            require(sameObject(before, directory.identity)) { "publication directory changed while it was opened" }
            val remainingEntries = MAX_ENTRIES - budget.entries
            require(remainingEntries > 0) { "publication tree exceeds entry bound" }
            val initialState = LinuxFilesystemSyscalls.fileState(directory)
            val names = LinuxFilesystemSyscalls.directoryEntryNamesWithoutAtime(
                directory,
                remainingEntries,
                cancellationCheck = budget.checkpoint,
                onEntry = { child ->
                    require(validComponent(child)) { "publication tree has an unsupported entry name" }
                    accountEntry(budget)
                },
            )
                .onEach { child -> require(validComponent(child)) { "publication tree has an unsupported entry name" } }
                .sortedWith(::compareUtf8)
            requireNoXattrs(directory)
            val children = ArrayList<Pair<ByteArray, PublicationEntryRecord>>(names.size)
            for (childName in names) {
                val childRecord = recordEntryAt(directory, childName, append(relativeName, childName),
                    depth + 1, rootMountId, budget, alreadyAccounted = true)
                    ?: throw IOException("publication directory entry disappeared during commitment")
                children += childName.toByteArray(StandardCharsets.UTF_8) to childRecord
            }
            val freshDirectory = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
            freshDirectory.use {
                require(sameObject(freshDirectory.identity, before)) {
                    "publication directory name changed while its content was committed"
                }
            }
            require(withoutAccessTime(initialState) == withoutAccessTime(LinuxFilesystemSyscalls.fileState(directory))) {
                "publication directory changed while its content was committed"
            }
            val finalState = LinuxFilesystemSyscalls.fileState(directory)
            require(withoutAccessTime(initialState) == withoutAccessTime(finalState)) {
                "publication directory changed while its content was committed"
            }
            requireNoXattrs(directory)
            require(withoutAccessTime(finalState) == withoutAccessTime(LinuxFilesystemSyscalls.fileState(directory))) {
                "publication directory metadata changed while its xattr policy was checked"
            }
            val committedDirectoryState = finalState.copy(accessTimeSeconds = 0, accessTimeNanoseconds = 0)
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(DIRECTORY_DOMAIN)
            updateMetadata(digest, before, committedDirectoryState, finalState.size)
            digest.update(intBytes(children.size))
            children.forEach { (childName, child) ->
                digest.update(intBytes(childName.size))
                digest.update(childName)
                digest.update(if (child.type == "file") 1 else 2)
                val childDevice = child.dev.toByteArray(StandardCharsets.US_ASCII)
                val childInode = child.ino.toByteArray(StandardCharsets.US_ASCII)
                digest.update(intBytes(childDevice.size))
                digest.update(childDevice)
                digest.update(intBytes(childInode.size))
                digest.update(childInode)
                digest.update(hexBytes(child.commitment))
            }
            // Directory atime is advanced by ordinary enumeration itself and is not a stable
            // publication property. Regular-file atime remains committed.
            return record("directory", before, committedDirectoryState, finalState.size, hex(digest.digest()))
        }
    }

    fun absent(): PublicationEntryRecord = PublicationEntryRecord(false, "absent", 0, "", "", "")

    /** v3 journal verification deliberately reproduces the prior content/mode/tree identity hash. */
    fun legacyRecordAt(root: LinuxDescriptor, relative: Path, budget: PublicationTreeBudget): PublicationEntryRecord {
        // The old hash is recomputed by the dedicated legacy traversal below, without inferring
        // any historical metadata from the current filesystem.
        return legacyRecordAtInternal(root, relative, budget)
    }

    private fun legacyRecordAtInternal(root: LinuxDescriptor, relative: Path, budget: PublicationTreeBudget): PublicationEntryRecord {
        val parts = relative.iterator().asSequence().map { it.toString() }.toList()
        require(parts.size == 1) { "legacy journal member must be a direct child" }
        return legacyEntry(root, parts.single(), root.identity.mountId, budget) ?: absent().copy(metadataVerified = false)
    }

    private fun legacyEntry(parent: LinuxDescriptor, name: String, mount: Long, budget: PublicationTreeBudget): PublicationEntryRecord? {
        val entry = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name) ?: return null
        entry.use {
            budget.accountEntry(); budget.entries = Math.addExact(budget.entries, 1)
            require(budget.entries <= MAX_ENTRIES) { "publication tree exceeds entry bound" }
            val before = LinuxFilesystemSyscalls.identity(entry.fd)
            require(before.mountId == mount) { "publication tree crosses a mount boundary" }
            val mode = before.mode and 0xfff
            if (before.isRegularFile) {
                require(before.linkCount == 1)
                val opened = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name) ?: throw IOException("legacy publication file disappeared")
                opened.use {
                    require(sameObject(before, opened.identity))
                    val readable = LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(opened)
                    readable.use {
                        val state = LinuxFilesystemSyscalls.fileState(readable)
                        require(state.size in 0..MAX_BYTES)
                        budget.accountBytes(state.size)
                        require(state.size <= MAX_BYTES - budget.bytes)
                        val digest = MessageDigest.getInstance("SHA-256")
                        val bufferBytes = ByteArray(64 * 1024)
                        val buffer = ByteBuffer.wrap(bufferBytes)
                        var count = 0L
                        while (count < state.size) {
                            budget.checkpoint()
                            val chunk = LinuxFilesystemSyscalls.readWithoutAtime(readable,
                                minOf(bufferBytes.size.toLong(), state.size - count).toInt())
                            if (chunk.isEmpty()) throw IOException("legacy publication file truncated")
                            digest.update(chunk); count += chunk.size
                            budget.bytes = Math.addExact(budget.bytes, chunk.size.toLong())
                        }
                        require(state == LinuxFilesystemSyscalls.fileState(readable))
                        val tree = MessageDigest.getInstance("SHA-256"); tree.update(LEGACY_FILE_DOMAIN)
                        tree.update(intBytes(mode)); tree.update(longBytes(count)); tree.update(digest.digest())
                        return PublicationEntryRecord(true, "file", mode, before.key.device.toString(), before.key.inode.toString(), hex(tree.digest()), metadataVerified = false)
                    }
                }
            }
            require(before.isDirectory && before.mountId == mount && !before.isSymbolicLink)
            val dir = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
            dir.use {
                require(sameObject(before, dir.identity))
                val initialState = LinuxFilesystemSyscalls.fileState(dir)
                val names = LinuxFilesystemSyscalls.directoryEntryNamesWithoutAtime(dir, MAX_ENTRIES).sortedWith(::compareUtf8)
                val children = names.map { child -> child.toByteArray(StandardCharsets.UTF_8) to
                    (legacyEntry(dir, child, mount, budget) ?: throw IOException("legacy publication child disappeared")) }
                val freshDirectory = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
                freshDirectory.use {
                    require(sameObject(before, freshDirectory.identity)) { "legacy publication directory name changed" }
                }
                require(initialState == LinuxFilesystemSyscalls.fileState(dir)) { "legacy publication directory changed" }
                val tree = MessageDigest.getInstance("SHA-256"); tree.update(LEGACY_DIRECTORY_DOMAIN); tree.update(intBytes(mode)); tree.update(intBytes(children.size))
                children.forEach { (childName, child) ->
                    tree.update(intBytes(childName.size)); tree.update(childName); tree.update(if (child.type == "file") 1 else 2)
                    val dev = child.dev.toByteArray(StandardCharsets.US_ASCII); val ino = child.ino.toByteArray(StandardCharsets.US_ASCII)
                    tree.update(intBytes(dev.size)); tree.update(dev); tree.update(intBytes(ino.size)); tree.update(ino); tree.update(hexBytes(child.commitment))
                }
                return PublicationEntryRecord(true, "directory", mode, before.key.device.toString(), before.key.inode.toString(), hex(tree.digest()), metadataVerified = false)
            }
        }
    }

    private fun requireNoXattrs(descriptor: LinuxDescriptor) {
        require(LinuxFilesystemSyscalls.extendedAttributeNames(descriptor).isEmpty()) {
            "publication entry violates the xattr policy NONE"
        }
    }

    private fun record(type: String, identity: decompengine.acp.LinuxFileIdentity,
        state: decompengine.acp.LinuxFileState, size: Long, commitment: String) = PublicationEntryRecord(
        true, type, identity.mode and 0xfff, identity.key.device.toString(), identity.key.inode.toString(), commitment,
        identity.uid, identity.gid, identity.linkCount, size, state.accessTimeSeconds, state.accessTimeNanoseconds,
        state.modificationTimeSeconds, state.modificationTimeNanoseconds, true,
    )

    private fun updateMetadata(digest: MessageDigest, identity: decompengine.acp.LinuxFileIdentity,
        state: decompengine.acp.LinuxFileState, size: Long) {
        digest.update(intBytes(identity.mode and 0xfff)); digest.update(intBytes(identity.uid)); digest.update(intBytes(identity.gid))
        digest.update(intBytes(identity.linkCount)); digest.update(longBytes(size))
        digest.update(longBytes(state.accessTimeSeconds)); digest.update(intBytes(state.accessTimeNanoseconds))
        digest.update(longBytes(state.modificationTimeSeconds)); digest.update(intBytes(state.modificationTimeNanoseconds))
        digest.update(longBytes(identity.key.device)); digest.update(longBytes(identity.key.inode))
        digest.update("xattr-policy-none\u0000".toByteArray(StandardCharsets.US_ASCII))
    }

    /** Directory atime is excluded from the commitment and from traversal race checks. */
    private fun withoutAccessTime(state: LinuxFileState): LinuxFileState =
        state.copy(accessTimeSeconds = 0, accessTimeNanoseconds = 0)

    private fun append(prefix: String, component: String): String = if (prefix.isEmpty()) component else "$prefix/$component"

    private fun validComponent(value: String): Boolean = value.isNotEmpty() && value != "." && value != ".." &&
        '/' !in value && '\u0000' !in value && '\ufffd' !in value &&
        value.toByteArray(StandardCharsets.UTF_8).toString(StandardCharsets.UTF_8) == value

    private fun compareUtf8(left: String, right: String): Int {
        val a = left.toByteArray(StandardCharsets.UTF_8)
        val b = right.toByteArray(StandardCharsets.UTF_8)
        val limit = minOf(a.size, b.size)
        for (index in 0 until limit) {
            val compared = (a[index].toInt() and 0xff).compareTo(b[index].toInt() and 0xff)
            if (compared != 0) return compared
        }
        return a.size.compareTo(b.size)
    }

    private fun sameObject(a: decompengine.acp.LinuxFileIdentity, b: decompengine.acp.LinuxFileIdentity): Boolean =
        a.key == b.key && a.mountId == b.mountId && a.mode == b.mode && a.uid == b.uid && a.gid == b.gid &&
            a.linkCount == b.linkCount && a.isRegularFile == b.isRegularFile && a.isDirectory == b.isDirectory &&
            a.isSymbolicLink == b.isSymbolicLink

    private fun accountEntry(budget: PublicationTreeBudget) {
        budget.accountEntry()
        budget.entries = Math.addExact(budget.entries, 1)
        require(budget.entries <= MAX_ENTRIES) { "publication tree exceeds entry bound" }
    }

    private fun intBytes(value: Int): ByteArray = ByteBuffer.allocate(Int.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putInt(value).array()
    private fun longBytes(value: Long): ByteArray = ByteBuffer.allocate(Long.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putLong(value).array()
    private fun hex(value: ByteArray): String = value.joinToString("") { "%02x".format(it) }
    private fun hexBytes(value: String): ByteArray {
        require(HASH.matches(value)) { "publication tree commitment is invalid" }
        return ByteArray(value.length / 2) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }
}
