package decompengine.oracle.gcc

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import java.nio.file.Path
import java.security.SecureRandom

internal object GccBundledCliCommand {
    fun run(options: GccBundledCliOptions, arguments: List<String>): Path {
        require(GccBundledCliOptions.parse(arguments) == options)
        listOf(options.binary, options.profile, options.archive, options.output, options.scratch).forEach { path ->
            require(path.toRealPath() == path) { "CLI paths must resolve without links" }
        }
        val invocation = LinuxFilesystemSyscalls.openRoot(options.output).use { output ->
            require(output.identity.mode.permissions == 448 && LinuxFilesystemSyscalls.directoryEntryNames(output, 1).isEmpty()) {
                "--output requires an existing empty private directory (mode 0700)"
            }
            val identities = linkedMapOf<Path, LinuxFileIdentity>(options.output to output.identity)
            for (name in listOf("inputs", "journal")) {
                LinuxFilesystemSyscalls.createDirectory(output.fd, name, 448)
                LinuxFilesystemSyscalls.openDirectoryAt(output.fd, name).use { child ->
                    LinuxFilesystemSyscalls.chmod(child, 448)
                    LinuxFilesystemSyscalls.synchronize(child)
                    identities[options.output.resolve(name)] = LinuxFilesystemSyscalls.identity(child.fd)
                }
            }
            LinuxFilesystemSyscalls.synchronize(output)
            GccBundledCliInvocation(options, arguments, identities).also { selected ->
                selected.requireCurrent()
                DescriptorBoundAtomicStateFile.publishNoReplace(output, "invocation.json", selected.canonicalBytes, 256 * 1024)
                selected.requireCurrent()
            }
        }
        val operationId = ByteArray(32).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }
        val journal = options.output.resolve("journal")
        val intent = GccBundledCliIntentBuilder.build(operationId, options.engineId,
            if (options.resumeAfterCheckpoint == null) GccCompilerEngineContainmentRunKind.FRESH_CONTROL else GccCompilerEngineContainmentRunKind.INTERRUPTED,
            options.binary, options.profile, options.archive, options.output.resolve("inputs"), journal, options.scratch,
            options.diskPolicy, invocation)
        return GccBundledOperationCoordinator.prepareNew(intent, journal, options.scratch).use { owner ->
            if (options.resumeAfterCheckpoint == null) owner.execute()
            else {
                owner.executeUntilCheckpoint(options.resumeAfterCheckpoint)
                owner.resume()
            }
            owner.plan()
            owner.publishCliResult()
        }
    }
}
