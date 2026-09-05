package decompengine.oracle.gcc

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.fulltree.FullTreeDiskScratchAuthority
import decompengine.oracle.fulltree.FullTreeDiskScratchLease
import decompengine.oracle.fulltree.FullTreeDiskScratchRunRoot
import decompengine.oracle.fulltree.FullTreeDiskScratchStage
import java.nio.file.Path

private object GCC_BUNDLED_PREPARED_OPERATION_PERMIT

internal class GccBundledPreparedOperation internal constructor(
    val intent: GccBundledOperationIntent,
    private val inputs: GccBundledOperationInputs,
    private val journal: GccBundledOperationJournal,
    private val lease: FullTreeDiskScratchLease,
    private val runRoot: FullTreeDiskScratchRunRoot,
    private val directories: Map<String, LinuxFileIdentity>,
    definitionBytes: ByteArray,
    constructionPermit: Any,
) : AutoCloseable {
    val authority: String = "gcc-bundled-live-prepared-operation-v1"
    val complete: Boolean = false
    val startAuthorized: Boolean = false
    val releaseEligible: Boolean = false
    private val definition = definitionBytes.copyOf()
    private val prepared = journal.preparedBytes
    private val diskEvidence = lease.evidence.canonicalBytes()
    private var closed = false
    private var poisoned = false

    val definitionBytes: ByteArray
        get() = definition.copyOf()
    val preparedReceiptBytes: ByteArray
        get() = prepared.copyOf()
    val diskEvidenceBytes: ByteArray
        get() = diskEvidence.copyOf()

    init {
        check(constructionPermit === GCC_BUNDLED_PREPARED_OPERATION_PERMIT) { "GCC prepared operation requires retained coordinator ownership" }
    }

    @Synchronized
    fun requireCurrent() {
        check(!closed && !poisoned) { "GCC bundled prepared operation is closed or poisoned" }
        try {
            inputs.verify("before prepared operation revalidation")
            journal.verify("before prepared operation revalidation")
            requirePreparedLayout()
            inputs.verify("after prepared operation revalidation")
            journal.verify("after prepared operation revalidation")
            requirePreparedLayout()
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    private fun requirePreparedLayout() {
        lease.withCurrentOperationRunRootBeforeLaunch(runRoot) { borrowed ->
            borrowed.withPinnedDescriptor { descriptor ->
                require(LinuxFilesystemSyscalls.directoryEntryNames(descriptor, directories.size + 1).toSet() == directories.keys) {
                    "GCC prepared run membership changed"
                }
                for ((name, expected) in directories) {
                    LinuxFilesystemSyscalls.openDirectoryAt(descriptor.fd, name).use { selected ->
                        require(LinuxFilesystemSyscalls.identity(selected.fd) == expected &&
                            LinuxFilesystemSyscalls.directoryEntryNames(selected, 1).isEmpty()
                        ) { "GCC prepared $name directory changed" }
                    }
                }
            }
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        fun record(next: Throwable) {
            val first = failure
            if (first == null) failure = next else if (next !== first) first.addSuppressed(next)
        }
        runCatching { lease.abandonForRecovery() }.exceptionOrNull()?.let(::record)
        runCatching { journal.close() }.exceptionOrNull()?.let(::record)
        runCatching { inputs.close() }.exceptionOrNull()?.let(::record)
        failure?.let { throw it }
    }
}

internal object GccBundledOperationCoordinator {
    fun prepareNew(
        intent: GccBundledOperationIntent,
        journalRoot: Path,
        provisionedMount: Path,
    ): GccBundledPreparedOperation {
        requireGccBundledOperationPath(journalRoot)
        requireGccBundledOperationPath(provisionedMount)
        require(journalRoot.toRealPath() == journalRoot && provisionedMount.toRealPath() == provisionedMount) {
            "GCC bundled operation roots must be canonical existing directories"
        }
        require(!journalRoot.startsWith(provisionedMount) && !provisionedMount.startsWith(journalRoot)) {
            "GCC bundled journal and dedicated scratch must be disjoint"
        }
        var inputs: GccBundledOperationInputs? = null
        var journal: GccBundledOperationJournal? = null
        var lease: FullTreeDiskScratchLease? = null
        try {
            val openedInputs = GccBundledOperationInputs.open(intent, listOf(journalRoot, provisionedMount))
            inputs = openedInputs
            val openedJournal = GccBundledOperationJournal.create(journalRoot, intent.operationId, intent.canonicalBytes)
            journal = openedJournal
            val openedLease = FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(provisionedMount, intent.diskOperation(), intent.diskPolicy)
            lease = openedLease
            openedInputs.verify("before GCC dedicated lease publication")
            openedLease.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
            openedJournal.recordLease(openedLease.evidence)
            openedLease.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
            val runRoot = openedLease.createEmptyOperationRunRoot()
            val directories = linkedMapOf<String, LinuxFileIdentity>()
            val definition = openedLease.withCurrentOperationRunRootBeforeLaunch(runRoot) { borrowed ->
                borrowed.withPinnedDescriptor { descriptor ->
                    require(LinuxFilesystemSyscalls.directoryEntryNames(descriptor, 1).isEmpty()) { "new GCC prepared run is not empty" }
                    for (name in listOf("state", "reports", "tmp")) {
                        LinuxFilesystemSyscalls.createDirectory(descriptor.fd, name, 448)
                        LinuxFilesystemSyscalls.openDirectoryAt(descriptor.fd, name).use { child ->
                            LinuxFilesystemSyscalls.chmod(child, 448)
                            val identity = LinuxFilesystemSyscalls.identity(child.fd)
                            require(identity.uid == descriptor.identity.uid && identity.mountId == descriptor.identity.mountId &&
                                identity.mode.permissions == 448 && identity.isDirectory && !identity.isSymbolicLink &&
                                LinuxFilesystemSyscalls.directoryEntryNames(child, 1).isEmpty()
                            ) { "new GCC prepared directory is not private on the dedicated mount" }
                            LinuxFilesystemSyscalls.synchronize(child)
                            directories[name] = identity
                        }
                    }
                    LinuxFilesystemSyscalls.synchronize(descriptor)
                    val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
                    val policy = intent.diskPolicy
                    val output = GccCompilerEngineOutputLeaseIdentity(
                        borrowed.path, identity.key.device, identity.key.inode, identity.mountId,
                        identity.uid, identity.gid, identity.mode.permissions, policy.requiredAvailableBytes,
                        policy.maximumFilesystemBytes, policy.requiredAvailableInodes, policy.maximumFilesystemInodes,
                    )
                    val state = GccCompilerEngineAnalysisStateIdentity(
                        GccCompilerEngineAnalysisStateMode.FRESH_EMPTY, borrowed.path.resolve("state"), null, 0, 0,
                    )
                    GccCompilerEngineContainmentContract.assessDefinition(GccCompilerEngineContainmentRequest(
                        intent.engineId, intent.runKind, intent.artifacts, state,
                        intent.bundledRuntime.command(intent.artifacts, state, output), intent.environment,
                        output, intent.budgets, intent.bundledRuntime,
                    )).canonicalBytes
                }
            }
            openedInputs.verify("before GCC prepared operation publication")
            openedJournal.recordPrepared(definition, openedInputs.deploymentClosureSha256)
            val prepared = GccBundledPreparedOperation(
                intent, openedInputs, openedJournal, openedLease, runRoot,
                java.util.Map.copyOf(directories), definition, GCC_BUNDLED_PREPARED_OPERATION_PERMIT,
            )
            prepared.requireCurrent()
            inputs = null
            journal = null
            lease = null
            return prepared
        } catch (failure: Throwable) {
            runCatching { lease?.abandonForRecovery() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
            runCatching { journal?.close() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
            runCatching { inputs?.close() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
            throw failure
        }
    }
}
