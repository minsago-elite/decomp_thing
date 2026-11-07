package decompengine.repair

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileState
import decompengine.acp.LinuxFilesystemSyscalls
import java.nio.file.Path

/** Metadata-neutral source-tree witness used by schema-6 publication crash tests. */
internal object Schema6SourceInventoryWitness {
    data class FileEntry(val state: LinuxFileState, val sha256: String)
    data class DirectoryEntry(val state: LinuxFileState, val names: List<String>)
    data class Snapshot(
        val files: Map<String, FileEntry>,
        val directories: Map<String, DirectoryEntry>,
    )

    fun capture(project: Path, sourcePaths: Collection<String>): Snapshot {
        val files = sortedMapOf<String, FileEntry>()
        val directories = sortedMapOf<String, DirectoryEntry>()
        LinuxFilesystemSyscalls.openRoot(project).use { root ->
            val known = linkedMapOf("." to root)
            val owned = mutableListOf<LinuxDescriptor>()
            try {
                sourcePaths.sorted().forEach { relative ->
                    val components = relative.split('/')
                    require(components.isNotEmpty() && components.none { it.isEmpty() || it == "." || it == ".." })
                    var parent = root
                    components.dropLast(1).forEachIndexed { index, component ->
                        val key = components.take(index + 1).joinToString("/")
                        parent = known[key] ?: LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, component).also {
                            known[key] = it
                            owned += it
                        }
                    }
                    val file = requireNotNull(
                        LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, components.last()),
                    ) { "source inventory entry is missing: $relative" }
                    file.use { held ->
                        val state = LinuxFilesystemSyscalls.fileState(held)
                        val digest = LinuxFilesystemSyscalls.sha256WithoutAtime(held, state.size)
                        files[relative] = FileEntry(state, digest)
                    }
                }
                known.forEach { (relative, descriptor) ->
                    directories[relative] = DirectoryEntry(
                        LinuxFilesystemSyscalls.fileState(descriptor),
                        LinuxFilesystemSyscalls.directoryEntryNamesWithoutAtime(descriptor, 100_000).sorted(),
                    )
                }
            } finally {
                owned.asReversed().forEach(LinuxDescriptor::close)
            }
        }
        return Snapshot(files, directories)
    }
}
