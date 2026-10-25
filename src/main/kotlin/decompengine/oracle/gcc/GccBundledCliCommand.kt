package decompengine.oracle.gcc

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import java.nio.file.Path
import java.security.SecureRandom

internal object GccBundledCliCommand {
    fun run(options: GccBundledCliOptions, arguments: List<String>): Path = runOwned(options, arguments, null) { owner ->
        if (options.runtimeDiagnostics) {
            owner.executeRuntimeDiagnostic()
        } else if (options.nativeCallObservations) {
            owner.executeNativeCallObservations()
            owner.publishNativeCallCliResult()
        } else if (options.fullRecoveryExport) {
            publishFullExport(owner, options).resultPath
        } else {
            if (options.resumeAfterCheckpoint == null) owner.execute()
            else {
                owner.executeUntilCheckpoint(options.resumeAfterCheckpoint)
                owner.resume()
            }
            owner.plan()
            owner.publishCliResult()
        }
    }

    fun runDriverAnalysis(options: GccBundledCliOptions, arguments: List<String>,
        reconstruction: GccStructuralReconstructionInvocation): GccBundledFullExportPublication {
        require(options.engineId == "driver" && options.fullRecoveryExport && !options.runtimeDiagnostics &&
            !options.nativeCallObservations && options.resumeAfterCheckpoint == null)
        reconstruction.requireAnalysisSelection(options, arguments)
        return runOwned(options, arguments, reconstruction) { owner -> publishFullExport(owner, options) }
    }

    private fun publishFullExport(owner: GccBundledPreparedOperation, options: GccBundledCliOptions): GccBundledFullExportPublication {
        val fullExport = owner.executeFullExport()
        val parallelProfile = options.profile.fileName.toString() == "compiler-engines-exporter17-parallel.json"
        val structuralInputs = GccDriverStructuralInputsV1.load(options.profile.parent, options.engineId, parallelProfile)
        return owner.publishFullExportResult(structuralInputs.captureFullExport(fullExport))
    }

    private fun <T> runOwned(options: GccBundledCliOptions, arguments: List<String>,
        reconstruction: GccStructuralReconstructionInvocation?, operation: (GccBundledPreparedOperation) -> T): T {
        require(GccBundledCliOptions.parse(arguments, fullRecoveryExport = options.fullRecoveryExport,
            runtimeDiagnostics = options.runtimeDiagnostics, nativeCallObservations = options.nativeCallObservations) == options)
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
            GccBundledCliInvocation(options, arguments, identities, reconstruction).also { selected ->
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
            options.diskPolicy, invocation, fullRecoveryExport = options.fullRecoveryExport,
            runtimeDiagnostics = options.runtimeDiagnostics, nativeCallObservations = options.nativeCallObservations)
        val parallelProfile = options.profile.fileName.toString() == "compiler-engines-exporter17-parallel.json"
        if (options.fullRecoveryExport && !options.runtimeDiagnostics) {
            GccDriverStructuralInputsV1.load(options.profile.parent, options.engineId, parallelProfile)
                .requireFullExportIntent(intent.canonicalBytes)
        }
        return GccBundledOperationCoordinator.prepareNew(intent, journal, options.scratch).use(operation)
    }
}
