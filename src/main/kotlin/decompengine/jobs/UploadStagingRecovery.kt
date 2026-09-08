package decompengine.jobs

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls as Linux
import decompengine.acp.permissions
import java.nio.file.Path

/** Startup-only maintenance; caller holds the exclusive job-root lease and has admitted no work. */
internal object UploadStagingRecovery {
    private val stageName = Regex("\\.upload-[0-9]{1,20}") // Files.createTempDirectory's existing reserved namespace
    private val files = setOf("input.elf", "job.json", "upload-receipt.json")
    private data class Stage(val name: String, val identity: LinuxFileIdentity, val entries: Map<String, LinuxFileIdentity>)

    fun recover(root: Path): Int {
        try {
            return Linux.openRoot(root).use { directory ->
                // Bound the complete scan before deleting anything, including unrelated root entries.
                val candidates = Linux.directoryEntryNames(directory, 10_512).filter { stageName.matches(it) }.sorted()
                require(candidates.size <= 256) { "Too many upload staging entries" }
                val inspected = candidates.map { inspect(directory, it) }
                for (stage in inspected) {
                    require(inspect(directory, stage.name) == stage) { "Upload staging changed before cleanup" }
                    Linux.openDirectoryAt(directory.fd, stage.name).use { child ->
                        require(child.identity == stage.identity) { "Upload staging directory changed" }
                        for ((name, identity) in stage.entries) {
                            Linux.openPathAtOrNull(child.fd, name).use { current ->
                                require(current?.identity == identity) { "Upload staging file changed" }
                                Linux.unlink(child.fd, name)
                            }
                        }
                        require(Linux.directoryEntryNames(child, 1).isEmpty()) { "Upload staging gained unexpected entries" }
                        Linux.synchronize(child)
                        Linux.openPathAtOrNull(directory.fd, stage.name).use { current ->
                            require(current?.identity == stage.identity) { "Upload staging path changed" }
                            Linux.removeDirectory(directory.fd, stage.name)
                        }
                    }
                    Linux.synchronize(directory)
                }
                inspected.size
            }
        } catch (failure: Exception) {
            throw WorkflowStoreException("UPLOAD_STAGING_RECOVERY_REQUIRED",
                "Upload staging could not be safely reconciled. Preserve unexpected entries and inspect storage before reopening.", cause = failure)
        }
    }

    private fun inspect(root: LinuxDescriptor, name: String): Stage {
        Linux.openPathAtOrNull(root.fd, name).use { selected ->
            val identity = requireNotNull(selected).identity
            require(identity.isDirectory && !identity.isSymbolicLink && identity.uid == root.identity.uid &&
                identity.mode.permissions == 0x1c0 && identity.mountId == root.identity.mountId) { "Upload staging is not an owned private directory" }
            Linux.openDirectoryAt(root.fd, name).use { directory ->
                require(directory.identity == identity) { "Upload staging directory identity changed" }
                val names = Linux.directoryEntryNames(directory, 4).sorted()
                require(names.all { it in files }) { "Upload staging contains an unexpected entry" }
                val entries = names.associateWith { entry ->
                    Linux.openPathAtOrNull(directory.fd, entry).use { file ->
                        val observed = requireNotNull(file).identity
                        require(observed.isRegularFile && !observed.isSymbolicLink && observed.linkCount == 1 &&
                            observed.uid == root.identity.uid && observed.mountId == identity.mountId) { "Upload staging entry is not an owned regular file" }
                        observed
                    }
                }
                require(Linux.directoryEntryNames(directory, 4).sorted() == names && Linux.identity(directory.fd) == identity) {
                    "Upload staging changed during inspection"
                }
                return Stage(name, identity, entries)
            }
        }
    }
}
