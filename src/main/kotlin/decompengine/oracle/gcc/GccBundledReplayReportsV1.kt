package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls

/** Export may add subdirectories; after the freeze every directory identity field is fixed. */
internal class GccBundledReplayReportsV1 private constructor(
    private val frozen: LinuxFileIdentity,
    private val names: Set<String>,
) {
    fun requireCurrent(reports: LinuxDescriptor) {
        require(reports.identity == frozen && LinuxFilesystemSyscalls.identity(reports.fd) == frozen) {
            "structural replay reports directory changed after its post-export freeze"
        }
        require(LinuxFilesystemSyscalls.directoryEntryNames(reports, names.size + 1).toSet() == names) {
            "structural replay reports membership changed after its post-export freeze"
        }
    }

    companion object {
        fun capture(run: LinuxDescriptor, prepared: LinuxFileIdentity,
            nativeCallSibling: Boolean = false): GccBundledReplayReportsV1 =
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
                // Full/native export legitimately adds its fixed output subdirectories.
                // Preserve every other preparation-time identity field, then pin the current count.
                require(reports.identity.copy(linkCount = prepared.linkCount) == prepared) {
                    "structural replay reports directory differs from its prepared owner"
                }
                val names = setOf("program_model.json", "program_model.json.progress.json", "program_model.json.export") +
                    if (nativeCallSibling) setOf("native-calls-v1") else emptySet()
                GccBundledReplayReportsV1(reports.identity, names).also { it.requireCurrent(reports) }
            }
    }
}
