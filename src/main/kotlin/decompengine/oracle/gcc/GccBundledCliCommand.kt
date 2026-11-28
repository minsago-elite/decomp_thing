package decompengine.oracle.gcc

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import java.nio.file.Path
import java.security.MessageDigest
import java.security.SecureRandom

internal object GccBundledCliCommand {
    fun run(options: GccBundledCliOptions, arguments: List<String>): Path {
        if (options.recoverOperationId != null) return recover(options, arguments)
        return runAdmitted(options, arguments)
    }

    private fun runAdmitted(options: GccBundledCliOptions, arguments: List<String>): Path = admit(options, arguments).use { owner ->
        if (options.runtimeDiagnostics) {
            owner.executeRuntimeDiagnostic()
        } else if (options.nativeCallObservations) {
            owner.executeNativeCallObservations()
            owner.publishNativeCallCliResult()
        } else if (options.fullRecoveryExport) {
            val fullExport = owner.executeFullExport()
            val structuralInputs = GccDriverStructuralInputsV1.load(options.profile.parent, options.engineId, parallelProfile(options))
            owner.publishFullExportCliResult(structuralInputs.captureFullExport(fullExport))
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

    /**
     * Runs every CLI admission check that precedes contained START and returns the coordinator's prepared owner.
     * The caller owns the result; no worker has started, and closing it retains the scratch lease for recovery.
     */
    fun admit(options: GccBundledCliOptions, arguments: List<String>): GccBundledPreparedOperation {
        require(options.recoverOperationId == null) { "a later-invocation recovery selection is admitted only by recover" }
        requireSelection(options, arguments)
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
            options.diskPolicy, invocation, fullRecoveryExport = options.fullRecoveryExport,
            runtimeDiagnostics = options.runtimeDiagnostics, nativeCallObservations = options.nativeCallObservations)
        if (options.fullRecoveryExport && !options.runtimeDiagnostics) {
            GccDriverStructuralInputsV1.load(options.profile.parent, options.engineId, parallelProfile(options))
                .requireFullExportIntent(intent.canonicalBytes)
        }
        return GccBundledOperationCoordinator.prepareNew(intent, journal, options.scratch)
    }

    /**
     * Later-invocation recovery: the original interrupted gcc-engine-plan argv plus `--recover-operation <id>`.
     * The retained invocation, intent and journal must be exactly the ones the earlier owner recorded, and the
     * coordinator refuses while that owner is live. Only resume, planning and result publication follow.
     */
    fun recover(options: GccBundledCliOptions, arguments: List<String>): Path = admitRecovery(options, arguments).use { owner ->
        owner.resume()
        owner.plan()
        owner.publishCliResult()
    }

    /** Rebuilds the earlier invocation's exact selection and returns the coordinator's recovered live owner. */
    fun admitRecovery(options: GccBundledCliOptions, arguments: List<String>): GccBundledPreparedOperation {
        val operationId = requireNotNull(options.recoverOperationId) { "later-invocation recovery requires --recover-operation" }
        requireSelection(options, arguments)
        val selector = arguments.indexOf("--recover-operation")
        require(selector >= 0 && arguments.lastIndexOf("--recover-operation") == selector && arguments[selector + 1] == operationId)
        val originalArguments = arguments.take(selector) + arguments.drop(selector + 2)
        val originalOptions = options.copy(recoverOperationId = null)
        require(GccBundledCliOptions.parse(originalArguments) == originalOptions)
        val invocation = LinuxFilesystemSyscalls.openRoot(options.output).use { output ->
            require(output.identity.mode.permissions == 448 &&
                LinuxFilesystemSyscalls.directoryEntryNames(output, 4).toSet() == setOf("invocation.json", "inputs", "journal")) {
                "--recover-operation requires the retained private output of an unfinished interrupted invocation"
            }
            val identities = linkedMapOf<Path, LinuxFileIdentity>(options.output to output.identity)
            for (name in listOf("inputs", "journal")) {
                identities[options.output.resolve(name)] = LinuxFilesystemSyscalls.openDirectoryAt(output.fd, name).use { it.identity }
            }
            val rebuilt = GccBundledCliInvocation(originalOptions, originalArguments, identities)
            val retained = DescriptorBoundAtomicStateFile.readOrNull(output, "invocation.json", 256 * 1024)
            require(retained != null && MessageDigest.isEqual(retained.bytes, rebuilt.canonicalBytes)) {
                "later invocation argv, options or output identity differs from the retained invocation"
            }
            rebuilt.requireCurrent()
            rebuilt
        }
        val journal = options.output.resolve("journal")
        val intent = GccBundledCliIntentBuilder.build(operationId, options.engineId, GccCompilerEngineContainmentRunKind.INTERRUPTED,
            options.binary, options.profile, options.archive, options.output.resolve("inputs"), journal, options.scratch,
            options.diskPolicy, invocation, retainedControls = true)
        return GccBundledOperationCoordinator.recoverInterrupted(intent, journal, options.scratch,
            listOf(options.commandName) + arguments)
    }

    private fun requireSelection(options: GccBundledCliOptions, arguments: List<String>) {
        require(GccBundledCliOptions.parse(arguments, fullRecoveryExport = options.fullRecoveryExport,
            runtimeDiagnostics = options.runtimeDiagnostics, nativeCallObservations = options.nativeCallObservations) == options)
        listOf(options.binary, options.profile, options.archive, options.output, options.scratch).forEach { path ->
            require(path.toRealPath() == path) { "CLI paths must resolve without links" }
        }
    }

    private fun parallelProfile(options: GccBundledCliOptions) =
        options.profile.fileName.toString() == "compiler-engines-exporter17-parallel.json"
}
