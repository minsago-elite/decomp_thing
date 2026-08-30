package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64

/** Separate-process fixture that intentionally exits without releasing an acquired ext4 lease. */
internal object FullTreeDiskScratchCrashProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 5)
        val mount = Path.of(arguments[0]).toAbsolutePath().normalize()
        val operationId = arguments[1]
        val maximumBytes = arguments[2].toLong()
        val maximumInodes = arguments[3].toLong()
        val activeRun = arguments[4].toBooleanStrict()
        val operation = FullTreeDiskScratchOperation(
            operationId = operationId,
            requestSha256 = "2".repeat(64),
            shardId = "clang-lib-driver",
            scopeSha256 = "3".repeat(64),
        )
        val lease = FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(
            mount,
            operation,
            FullTreeDiskScratchPolicy(
                requiredAvailableBytes = 1,
                maximumFilesystemBytes = maximumBytes,
                requiredAvailableInodes = 4,
                maximumFilesystemInodes = maximumInodes,
            ),
        )
        if (activeRun) {
            val run = lease.scratchParent.resolve(runDirectoryName(operation.operationId))
            Files.createDirectory(run)
            Files.setPosixFilePermissions(run, PosixFilePermissions.fromString("rwx------"))
        }
        val encodedEvidence = Base64.getEncoder().encodeToString(lease.evidence.canonicalBytes())
        println("READY:$encodedEvidence")
        System.out.flush()
        Runtime.getRuntime().halt(0)
    }
}
