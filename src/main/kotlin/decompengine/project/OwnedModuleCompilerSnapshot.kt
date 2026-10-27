package decompengine.project

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandInput
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Files
import java.nio.file.Path

/** Host-side bounded executable materialization; never make the leased scratch filesystem executable. */
internal fun materializeOwnedModuleCompilerSnapshot(
    input: KotlinSystemdCgroupCommandInput,
    destination: Path,
    checkpoint: () -> Unit = {},
): KotlinSystemdCgroupCommandInput {
    require(input.bytes in 1..MAXIMUM_MODULE_COMPILER_SNAPSHOT_BYTES)
    requireCompilerAbsolutePath(destination)
    require(destination.parent.toRealPath() == destination.parent) { "compiler snapshot parent must be canonical" }
    requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(input.path)).use { original ->
        require(original.identity.uid == 0 && original.identity.isRegularFile && !original.identity.isSymbolicLink &&
            original.identity.linkCount == 1 && original.identity.mode and 0x12 == 0 && original.identity.mode and 0x49 != 0) {
            "module compiler snapshot requires a single-linked host-root executable without untrusted writes"
        }
    }
    StableControlFile.openWithCheckpoint(input.path, input.bytes, "module compiler snapshot source") { checkpoint() }.use { source ->
        source.requireSingleLink("module compiler snapshot source")
        require(source.size == input.bytes && source.authenticatedSha256 == input.sha256) { "module compiler snapshot source digest differs" }
        LinuxFilesystemSyscalls.openRoot(destination.parent).use { parent ->
            require(parent.identity.isDirectory && parent.identity.mode and 0x3f == 0) {
                "compiler snapshot parent must be private"
            }
            LinuxFilesystemSyscalls.createRegularFile(parent.fd, destination.fileName.toString(), 384).use { output ->
                var offset = 0L
                while (offset < source.size) {
                    checkpoint()
                    val bytes = source.readExactly(offset, minOf(65536L, source.size - offset).toInt(), "module compiler snapshot")
                    LinuxFilesystemSyscalls.write(output, bytes, checkpoint)
                    offset += bytes.size
                }
                LinuxFilesystemSyscalls.chmod(output, 320) // owner read/execute only
                LinuxFilesystemSyscalls.synchronize(output)
            }
            LinuxFilesystemSyscalls.synchronize(parent)
        }
        source.verifyUnchanged("module compiler snapshot source after copy")
    }
    require(destination.toRealPath() == destination && Files.isExecutable(destination)) {
        "module compiler snapshot requires an executable host staging filesystem, never executable scratch"
    }
    StableControlFile.openWithCheckpoint(destination, input.bytes, "owned module compiler snapshot") { checkpoint() }.use { snapshot ->
        snapshot.requireSingleLink("owned module compiler snapshot")
        require(snapshot.size == input.bytes && snapshot.authenticatedSha256 == input.sha256) { "owned compiler snapshot digest differs" }
        snapshot.verifyUnchanged("owned module compiler snapshot after materialization")
    }
    return KotlinSystemdCgroupCommandInput(destination, input.bytes, input.sha256)
}

private const val MAXIMUM_MODULE_COMPILER_SNAPSHOT_BYTES = 64L * 1024 * 1024
