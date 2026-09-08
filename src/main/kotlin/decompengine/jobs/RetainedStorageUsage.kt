package decompengine.jobs

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls as Linux
import java.nio.file.Files
import java.nio.file.Path

/**
 * Bounded, read-only logical-byte accounting for an exclusively owned, quiescent job root.
 * Includes hidden and temporary entries. This is an admission snapshot, not a filesystem quota:
 * callers must coordinate writers and reserve future growth separately.
 */
internal object RetainedStorageUsage {
    data class Usage(val logicalBytes: Long, val entries: Int)

    fun measure(
        root: Path,
        maximumBytes: Long,
        maximumEntries: Int = 100_000,
        maximumDepth: Int = 32,
        maximumNanos: Long = 2_000_000_000,
        nanoTime: () -> Long = System::nanoTime,
    ): Usage {
        require(maximumBytes >= 0 && maximumEntries > 0 && maximumDepth in 0..64 && maximumNanos > 0)
        val started = nanoTime()
        var bytes = 0L
        var entries = 0
        fun checkBudget() {
            check(!Thread.currentThread().isInterrupted) { "Storage accounting interrupted" }
            check(nanoTime() - started < maximumNanos) { "Storage accounting deadline exceeded" }
        }
        try {
            Linux.openRoot(root).use { pinnedRoot ->
                fun visit(directory: LinuxDescriptor, depth: Int) {
                    checkBudget()
                    check(depth <= maximumDepth) { "Storage accounting depth exceeded" }
                    val names = Linux.directoryEntryNames(directory, maxOf(1, maximumEntries - entries), ::checkBudget)
                    for (name in names) {
                        checkBudget()
                        check(entries < maximumEntries) { "Storage accounting entry limit exceeded" }
                        entries++
                        Linux.openPathAtOrNull(directory.fd, name).use { selected ->
                            val pinned = requireNotNull(selected) { "Storage entry disappeared" }
                            val identity = pinned.identity
                            check(identity.mountId == pinnedRoot.identity.mountId && identity.uid == pinnedRoot.identity.uid) {
                                "Storage entry ownership or mount differs"
                            }
                            check(!identity.isSymbolicLink && (identity.isRegularFile || identity.isDirectory)) {
                                "Unsupported storage entry"
                            }
                            // Count directory sizes too; regular-file lengths include sparse logical extents.
                            // Hard links are charged per name, conservatively, including links outside the root.
                            val size = Files.size(Linux.descriptorPath(pinned))
                            check(size >= 0 && size <= maximumBytes - bytes) { "Retained storage byte limit exceeded" }
                            bytes += size
                            if (identity.isDirectory) {
                                Linux.openDirectoryAt(directory.fd, name).use { child ->
                                    check(child.identity == identity) { "Storage directory changed" }
                                    visit(child, depth + 1)
                                }
                            }
                            check(Linux.identity(pinned.fd) == identity && Files.size(Linux.descriptorPath(pinned)) == size) {
                                "Storage entry changed during accounting"
                            }
                            Linux.openPathAtOrNull(directory.fd, name).use { current ->
                                check(current?.identity == identity) { "Storage entry was replaced" }
                            }
                        }
                    }
                    check(Linux.directoryEntryNames(directory, maxOf(1, names.size), ::checkBudget).toSet() == names.toSet()) {
                        "Storage directory entries changed"
                    }
                }
                visit(pinnedRoot, 0)
                checkBudget()
            }
            return Usage(bytes, entries)
        } catch (failure: Exception) {
            throw WorkflowStoreException("STORAGE_ACCOUNTING_UNAVAILABLE",
                "Retained storage could not be measured within its limits. Preserve data and inspect storage before admitting more writes.", cause = failure)
        }
    }
}
