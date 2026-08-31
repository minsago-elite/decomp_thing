package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import decompengine.oracle.core.DescriptorBoundStateFaultPoint
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class FullTreeFunctionObservationOperationCoordinatorTest {
    @Test
    fun `cold leased coordinator reconciles exact evidence with both coarse disk populations`() {
        val mount = provisionedMount()

        listOf(false, true).forEachIndexed { index, activeRun ->
            val operationBinding = binding(operationSeed = if (activeRun) "a" else "9")
            assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

            withJournalRoot { root ->
                val leaseRoot = mount.resolve(operationBinding.leaseDirectoryName)
                val recordPath = leaseRoot.resolve(LEASE_RECORD_FILE)
                val runPath = leaseRoot.resolve(runDirectoryName(operationBinding.operationId))
                val opaqueRunContent = runPath.resolve("opaque-run-content")
                var live: AutoCloseable? = null
                try {
                    FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                        val fresh = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                            authority,
                            operationBinding,
                            mount,
                        )
                        live = fresh
                        if (activeRun) {
                            val prepared = fresh.prepareRunRoot()
                            live = prepared
                            prepared.close()
                        } else {
                            fresh.close()
                        }
                        live = null
                        if (activeRun) {
                            Files.writeString(opaqueRunContent, "bounded opaque run content")
                        }

                        val journalDirectory = root.resolve(operationBinding.journalDirectoryName)
                        val journalBefore = immutableFileSnapshot(journalDirectory)
                        val mountNames = entryNames(mount)
                        val leaseNames = entryNames(leaseRoot)
                        val runNames = if (activeRun) entryNames(runPath) else emptyList()
                        val opaqueBytes = if (activeRun) Files.readAllBytes(opaqueRunContent) else byteArrayOf()
                        val recordBytes = Files.readAllBytes(recordPath)
                        val expectedPopulation = if (activeRun) {
                            FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN
                        } else {
                            FullTreeDiskScratchColdPopulation.RECORD_ONLY
                        }

                        assertFailsWith<FullTreeDiskScratchException> {
                            FullTreeFunctionObservationOperationCoordinator
                                .openExistingLeasedReadOnly(
                                    authority,
                                    operationBinding,
                                    root.resolve("missing-disk-mount"),
                                )
                        }
                        requireNotNull(authority.openExisting(operationBinding)).close()
                        assertEquals(journalBefore, immutableFileSnapshot(journalDirectory))

                        val cold = FullTreeFunctionObservationOperationCoordinator
                            .openExistingLeasedReadOnly(authority, operationBinding, mount)
                        val stableHistory = cold.leasedHistory
                        val stableEvidence = cold.diskEvidence
                        try {
                            assertEquals(
                                FullTreeFunctionObservationOperationPhase.LEASED,
                                stableHistory.latest?.phase,
                            )
                            assertSame(stableHistory.diskEvidence, stableEvidence)
                            assertSame(
                                stableEvidence,
                                stableHistory.requireDiskEvidenceIntroducedAt(
                                    FullTreeFunctionObservationOperationPhase.LEASED,
                                ),
                            )
                            assertEquals(expectedPopulation, cold.observedPopulation)

                            cold.requireCurrentReadOnly()
                            cold.requireCurrentReadOnly()
                            assertSame(stableHistory, cold.leasedHistory)
                            assertSame(stableEvidence, cold.diskEvidence)
                            assertEquals(expectedPopulation, cold.observedPopulation)

                            assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                                authority.openExisting(operationBinding)
                            }
                            assertFailsWith<FullTreeDiskScratchException> {
                                FullTreeDiskScratchAuthority.openExistingReadOnly(
                                    mount,
                                    operationBinding.diskOperation(),
                                    operationBinding.diskPolicy(),
                                )
                            }
                            assertFailsWith<FullTreeDiskScratchException> {
                                FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(
                                    mount,
                                    binding(
                                        operationSeed = if (index == 0) "b" else "c",
                                    ).diskOperation(),
                                    operationBinding.diskPolicy(),
                                )
                            }
                        } finally {
                            cold.close()
                        }
                        cold.close()
                        assertFailsWith<IllegalStateException> {
                            cold.requireCurrentReadOnly()
                        }

                        assertEquals(journalBefore, immutableFileSnapshot(journalDirectory))
                        assertEquals(mountNames, entryNames(mount))
                        assertEquals(leaseNames, entryNames(leaseRoot))
                        assertContentEquals(recordBytes, Files.readAllBytes(recordPath))
                        if (activeRun) {
                            assertEquals(runNames, entryNames(runPath))
                            assertContentEquals(opaqueBytes, Files.readAllBytes(opaqueRunContent))
                        }

                        requireNotNull(authority.openExisting(operationBinding)).use { journal ->
                            val reopened = requireNotNull(journal.loadOrNull())
                            val evidence = reopened.requireDiskEvidenceIntroducedAt(
                                FullTreeFunctionObservationOperationPhase.LEASED,
                            )
                            assertContentEquals(stableEvidence.canonicalBytes(), evidence.canonicalBytes())
                        }
                        FullTreeDiskScratchAuthority.openExistingReadOnly(
                            mount,
                            operationBinding.diskOperation(),
                            operationBinding.diskPolicy(),
                        ).use { disk ->
                            assertEquals(
                                expectedPopulation,
                                disk.requireCurrent(stableEvidence).population,
                            )
                        }

                        assertEquals(journalBefore, immutableFileSnapshot(journalDirectory))
                        assertEquals(mountNames, entryNames(mount))
                        assertEquals(leaseNames, entryNames(leaseRoot))
                        assertContentEquals(recordBytes, Files.readAllBytes(recordPath))
                        if (activeRun) {
                            assertEquals(runNames, entryNames(runPath))
                            assertContentEquals(opaqueBytes, Files.readAllBytes(opaqueRunContent))
                        }
                    }
                } finally {
                    runCatching { live?.close() }
                    if (activeRun) {
                        Files.deleteIfExists(opaqueRunContent)
                        removeActiveRunLease(leaseRoot, operationBinding.operationId)
                    } else {
                        removeRecordOnlyLease(leaseRoot)
                    }
                }
            }
            assertTrue(entryNames(mount).isEmpty())
        }
    }

    @Test
    fun `cold unit-attached coordinator retains exact historical evidence and both locks`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "8")
        val leaseRoot = mount.resolve(binding.leaseDirectoryName)
        val runPath = leaseRoot.resolve(runDirectoryName(binding.operationId))
        val opaqueContent = runPath.resolve("opaque-unit-attached-content")
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    val attached = createUnitAttachedActiveResidue(authority, binding, mount)
                    Files.writeString(opaqueContent, "historical active-run content")
                    val journalDirectory = root.resolve(binding.journalDirectoryName)
                    val journalBefore = immutableFileSnapshot(journalDirectory)
                    val mountNames = entryNames(mount)
                    val leaseNames = entryNames(leaseRoot)
                    val runNames = entryNames(runPath)
                    val opaqueBytes = Files.readAllBytes(opaqueContent)
                    val recordBytes = Files.readAllBytes(leaseRoot.resolve(LEASE_RECORD_FILE))

                    val cold = FullTreeFunctionObservationOperationCoordinator
                        .openExistingUnitAttachedReadOnly(authority, binding, mount)
                    val stableHistory = cold.attachedHistory
                    val stableEvidence = cold.diskEvidence
                    val stableReceipt = cold.unitAttachmentReceipt
                    var bootAuthority: FullTreeFunctionObservationColdUnitAttachedBootAuthority? = null
                    try {
                        assertEquals(
                            listOf(
                                FullTreeFunctionObservationOperationPhase.PREPARING,
                                FullTreeFunctionObservationOperationPhase.LEASED,
                                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            ),
                            stableHistory.transitions.map { it.phase },
                        )
                        assertSame(stableHistory.diskEvidence, stableEvidence)
                        assertSame(stableHistory.unitAttachmentReceipt, stableReceipt)
                        assertContentEquals(
                            checkNotNull(attached.unitAttachmentReceipt).canonicalBytes(),
                            stableReceipt.canonicalBytes(),
                        )
                        assertEquals(
                            FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN,
                            cold.observedPopulation,
                        )

                        cold.requireCurrentReadOnly()
                        val boot = cold.transferToBootAuthority()
                        bootAuthority = boot
                        assertFailsWith<IllegalStateException> { cold.requireCurrentReadOnly() }
                        assertFailsWith<IllegalStateException> {
                            cold.withCurrentRunRootAtBoot { }
                        }
                        cold.close()
                        assertSame(stableHistory, boot.attachedHistory)
                        assertSame(stableEvidence, boot.diskEvidence)
                        assertSame(stableReceipt, boot.unitAttachmentReceipt)
                        assertEquals(cold.observedPopulation, boot.observedPopulation)

                        var capturedBorrow: FullTreeDiskScratchBorrowedRunRoot? = null
                        assertEquals(
                            "observed",
                            boot.withCurrentRunRootAtBoot { borrowed ->
                                capturedBorrow = borrowed
                                assertEquals(runPath, borrowed.path)
                                "observed"
                            },
                        )
                        assertFailsWith<IllegalStateException> {
                            checkNotNull(capturedBorrow).path
                        }
                        boot.requireCurrentReadOnly()
                        boot.requireCurrentReadOnly()
                        assertSame(stableHistory, boot.attachedHistory)
                        assertSame(stableEvidence, boot.diskEvidence)
                        assertSame(stableReceipt, boot.unitAttachmentReceipt)

                        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                            authority.openExisting(binding)
                        }
                        assertFailsWith<FullTreeDiskScratchException> {
                            FullTreeDiskScratchAuthority.openExistingReadOnly(
                                mount,
                                binding.diskOperation(),
                                binding.diskPolicy(),
                            )
                        }
                    } finally {
                        bootAuthority?.close()
                        cold.close()
                    }
                    checkNotNull(bootAuthority).close()
                    cold.close()
                    assertFailsWith<IllegalStateException> {
                        checkNotNull(bootAuthority).requireCurrentReadOnly()
                    }

                    assertEquals(journalBefore, immutableFileSnapshot(journalDirectory))
                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(leaseRoot))
                    assertEquals(runNames, entryNames(runPath))
                    assertContentEquals(opaqueBytes, Files.readAllBytes(opaqueContent))
                    assertContentEquals(recordBytes, Files.readAllBytes(leaseRoot.resolve(LEASE_RECORD_FILE)))

                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        assertContentEquals(
                            stableReceipt.canonicalBytes(),
                            requireNotNull(journal.loadOrNull()).requireUnitAttachmentReceiptIntroducedAt(
                                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            ).canonicalBytes(),
                        )
                    }
                    FullTreeDiskScratchAuthority.openExistingReadOnly(
                        mount,
                        binding.diskOperation(),
                        binding.diskPolicy(),
                    ).use { disk ->
                        assertEquals(
                            FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN,
                            disk.requireCurrent(stableEvidence).population,
                        )
                    }
                }
            } finally {
                Files.deleteIfExists(opaqueContent)
                removeActiveRunLease(leaseRoot, binding.operationId)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `cold unit-attached coordinator rejects active run root replacement across observations`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "2")
        val leaseRoot = mount.resolve(binding.leaseDirectoryName)
        val runPath = leaseRoot.resolve(runDirectoryName(binding.operationId))
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            var pinnedOriginal: decompengine.acp.LinuxDescriptor? = null
            var cold: FullTreeFunctionObservationColdUnitAttachedOperation? = null
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    val attached = createUnitAttachedActiveResidue(authority, binding, mount)
                    val stableEvidence = checkNotNull(attached.diskEvidence)
                    val opened = FullTreeFunctionObservationOperationCoordinator
                        .openExistingUnitAttachedReadOnly(authority, binding, mount)
                    cold = opened
                    val original = LinuxFilesystemSyscalls.openRoot(runPath)
                    pinnedOriginal = original
                    val originalIdentity = LinuxFilesystemSyscalls.identity(original.fd)

                    Files.delete(runPath)
                    Files.createDirectory(runPath)
                    Files.setPosixFilePermissions(
                        runPath,
                        PosixFilePermissions.fromString("rwx------"),
                    )
                    LinuxFilesystemSyscalls.openRoot(runPath).use { replacement ->
                        val replacementIdentity = LinuxFilesystemSyscalls.identity(replacement.fd)
                        assertTrue(
                            replacementIdentity.key != originalIdentity.key ||
                                replacementIdentity.mountId != originalIdentity.mountId,
                            "pinned deleted root unexpectedly reused its identity",
                        )
                    }

                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        opened.requireCurrentReadOnly()
                    }
                    var callbackEntered = false
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        opened.withCurrentRunRootAtBoot { callbackEntered = true }
                    }
                    assertTrue(!callbackEntered)
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        authority.openExisting(binding)
                    }
                    assertFailsWith<FullTreeDiskScratchException> {
                        FullTreeDiskScratchAuthority.openExistingReadOnly(
                            mount,
                            binding.diskOperation(),
                            binding.diskPolicy(),
                        )
                    }

                    opened.close()
                    cold = null
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        FullTreeFunctionObservationOperationCoordinator
                            .openExistingUnitAttachedReadOnly(authority, binding, mount)
                    }
                    requireNotNull(authority.openExisting(binding)).close()
                    FullTreeDiskScratchAuthority.openExistingReadOnly(
                        mount,
                        binding.diskOperation(),
                        binding.diskPolicy(),
                    ).use { disk ->
                        assertEquals(
                            FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN,
                            disk.requireCurrent(stableEvidence).population,
                        )
                    }
                }
            } finally {
                runCatching { cold?.close() }
                runCatching { pinnedOriginal?.close() }
                Files.deleteIfExists(runPath)
                removeRecordOnlyLease(leaseRoot)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `cold unit-attached coordinator rejects record-only residue and releases both locks`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "3")
        val leaseRoot = mount.resolve(binding.leaseDirectoryName)
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        authority,
                        binding,
                        mount,
                    ).close()
                    val attached = requireNotNull(authority.openExisting(binding)).use { journal ->
                        val leased = requireNotNull(journal.loadOrNull())
                        journal.recordUnitAttached(
                            attachmentReceipt(binding, checkNotNull(leased.latest), mount),
                        )
                    }
                    val journalDirectory = root.resolve(binding.journalDirectoryName)
                    val journalBefore = immutableFileSnapshot(journalDirectory)
                    val mountNames = entryNames(mount)
                    val leaseNames = entryNames(leaseRoot)
                    val recordBytes = Files.readAllBytes(leaseRoot.resolve(LEASE_RECORD_FILE))

                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        FullTreeFunctionObservationOperationCoordinator
                            .openExistingUnitAttachedReadOnly(authority, binding, mount)
                    }

                    assertEquals(journalBefore, immutableFileSnapshot(journalDirectory))
                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(leaseRoot))
                    assertContentEquals(recordBytes, Files.readAllBytes(leaseRoot.resolve(LEASE_RECORD_FILE)))
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        assertContentEquals(
                            checkNotNull(attached.unitAttachmentReceipt).canonicalBytes(),
                            requireNotNull(journal.loadOrNull()).requireUnitAttachmentReceiptIntroducedAt(
                                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            ).canonicalBytes(),
                        )
                    }
                    FullTreeDiskScratchAuthority.openExistingReadOnly(
                        mount,
                        binding.diskOperation(),
                        binding.diskPolicy(),
                    ).use { disk ->
                        assertEquals(
                            FullTreeDiskScratchColdPopulation.RECORD_ONLY,
                            disk.requireCurrent(checkNotNull(attached.diskEvidence)).population,
                        )
                    }
                }
            } finally {
                removeRecordOnlyLease(leaseRoot)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `cold unit-attached coordinator rejects absent journal before disk lookup`() =
        withJournalRoot { root ->
            val binding = binding(operationSeed = "a")
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                val before = entryNames(root)
                assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                    FullTreeFunctionObservationOperationCoordinator
                        .openExistingUnitAttachedReadOnly(
                            authority,
                            binding,
                            root.resolve("missing-disk-mount"),
                        )
                }
                assertEquals(before, entryNames(root))
            }
        }

    @Test
    fun `cold unit-attached coordinator rejects staged and post-attached histories before disk lookup`() {
        val mount = provisionedMount()
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        val stagedBinding = binding(operationSeed = "b")
        val stagedLeaseRoot = mount.resolve(stagedBinding.leaseDirectoryName)
        withJournalRoot { root ->
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    val leased = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        authority,
                        stagedBinding,
                        mount,
                    )
                    val prepared = leased.prepareRunRoot()
                    leased.close()
                    prepared.close()
                    val receipt = requireNotNull(authority.openExisting(stagedBinding)).use { journal ->
                        val history = requireNotNull(journal.loadOrNull())
                        attachmentReceipt(stagedBinding, checkNotNull(history.latest), mount).also { staged ->
                            assertFailsWith<SimulatedCoordinatorProcessDeath> {
                                journal.recordUnitAttached(
                                    staged,
                                    receiptFaultInjector = DescriptorBoundStateFaultInjector { point ->
                                        if (
                                            point ==
                                            DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_DIRECTORY_SYNC
                                        ) throw SimulatedCoordinatorProcessDeath()
                                    },
                                )
                            }
                        }
                    }
                    val journalDirectory = root.resolve(stagedBinding.journalDirectoryName)
                    val journalBefore = immutableFileSnapshot(journalDirectory)
                    val mountNames = entryNames(mount)
                    val leaseNames = entryNames(stagedLeaseRoot)

                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        FullTreeFunctionObservationOperationCoordinator
                            .openExistingUnitAttachedReadOnly(
                                authority,
                                stagedBinding,
                                root.resolve("missing-disk-mount"),
                            )
                    }

                    assertEquals(journalBefore, immutableFileSnapshot(journalDirectory))
                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(stagedLeaseRoot))
                    requireNotNull(authority.openExisting(stagedBinding)).use { journal ->
                        val staged = requireNotNull(journal.loadOrNull())
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.LEASED,
                            staged.latest?.phase,
                        )
                        assertContentEquals(
                            receipt.canonicalBytes(),
                            checkNotNull(staged.unitAttachmentReceipt).canonicalBytes(),
                        )
                        assertFailsWith<SimulatedCoordinatorProcessDeath> {
                            journal.recordUnitAttached(
                                receipt,
                                transitionFaultInjector = DescriptorBoundStateFaultInjector { point ->
                                    if (
                                        point ==
                                        DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC
                                    ) throw SimulatedCoordinatorProcessDeath()
                                },
                            )
                        }
                    }
                    val pendingBefore = immutableFileSnapshot(journalDirectory)
                    assertTrue(
                        DescriptorBoundAtomicStateFile.temporaryName("transition-0002.json") in
                            pendingBefore,
                    )
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        FullTreeFunctionObservationOperationCoordinator
                            .openExistingUnitAttachedReadOnly(
                                authority,
                                stagedBinding,
                                root.resolve("missing-disk-mount"),
                            )
                    }
                    assertEquals(pendingBefore, immutableFileSnapshot(journalDirectory))
                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(stagedLeaseRoot))
                }
            } finally {
                removeActiveRunLease(stagedLeaseRoot, stagedBinding.operationId)
            }
        }
        assertTrue(entryNames(mount).isEmpty())

        val postBinding = binding(operationSeed = "c")
        val postLeaseRoot = mount.resolve(postBinding.leaseDirectoryName)
        withJournalRoot { root ->
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    createUnitAttachedActiveResidue(authority, postBinding, mount)
                    requireNotNull(authority.openExisting(postBinding)).use { journal ->
                        val attached = requireNotNull(journal.loadOrNull())
                        journal.append(
                            FullTreeFunctionObservationOperationTransition.recoveredAbort(
                                postBinding,
                                checkNotNull(attached.latest),
                            ),
                        )
                    }
                    val journalDirectory = root.resolve(postBinding.journalDirectoryName)
                    val journalBefore = immutableFileSnapshot(journalDirectory)
                    val mountNames = entryNames(mount)
                    val leaseNames = entryNames(postLeaseRoot)

                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        FullTreeFunctionObservationOperationCoordinator
                            .openExistingUnitAttachedReadOnly(
                                authority,
                                postBinding,
                                root.resolve("missing-disk-mount"),
                            )
                    }

                    assertEquals(journalBefore, immutableFileSnapshot(journalDirectory))
                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(postLeaseRoot))
                    requireNotNull(authority.openExisting(postBinding)).use { journal ->
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
                            requireNotNull(journal.loadOrNull()).latest?.phase,
                        )
                    }
                }
            } finally {
                removeActiveRunLease(postLeaseRoot, postBinding.operationId)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `cold unit-attached coordinator rejects substituted receipt without touching disk residue`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "d")
        val leaseRoot = mount.resolve(binding.leaseDirectoryName)
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            val receiptPath = root.resolve(binding.journalDirectoryName).resolve(UNIT_ATTACHMENT_RECEIPT_FILE)
            var originalReceiptBytes: ByteArray? = null
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    val attached = createUnitAttachedActiveResidue(authority, binding, mount)
                    val leasedTransition = attached.transitions.single {
                        it.phase == FullTreeFunctionObservationOperationPhase.LEASED
                    }
                    originalReceiptBytes = Files.readAllBytes(receiptPath)
                    val substitutedReceipt = attachmentReceipt(
                        binding,
                        leasedTransition,
                        mount,
                        identitySeed = 100,
                    )
                    Files.setPosixFilePermissions(
                        receiptPath,
                        PosixFilePermissions.fromString("rw-------"),
                    )
                    Files.write(receiptPath, substitutedReceipt.canonicalBytes())
                    Files.setPosixFilePermissions(
                        receiptPath,
                        PosixFilePermissions.fromString("r--------"),
                    )
                    val journalDirectory = root.resolve(binding.journalDirectoryName)
                    val journalBefore = immutableFileSnapshot(journalDirectory)
                    val mountNames = entryNames(mount)
                    val leaseNames = entryNames(leaseRoot)
                    val recordBytes = Files.readAllBytes(leaseRoot.resolve(LEASE_RECORD_FILE))

                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        FullTreeFunctionObservationOperationCoordinator
                            .openExistingUnitAttachedReadOnly(
                                authority,
                                binding,
                                root.resolve("missing-disk-mount"),
                            )
                    }

                    assertEquals(journalBefore, immutableFileSnapshot(journalDirectory))
                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(leaseRoot))
                    assertContentEquals(recordBytes, Files.readAllBytes(leaseRoot.resolve(LEASE_RECORD_FILE)))
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                            journal.loadOrNull()
                        }
                    }
                    FullTreeDiskScratchAuthority.openExistingReadOnly(
                        mount,
                        binding.diskOperation(),
                        binding.diskPolicy(),
                    ).use { disk ->
                        assertEquals(
                            FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN,
                            disk.requireCurrent(checkNotNull(attached.diskEvidence)).population,
                        )
                    }

                    Files.delete(receiptPath)
                    val missingBefore = immutableFileSnapshot(journalDirectory)
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        FullTreeFunctionObservationOperationCoordinator
                            .openExistingUnitAttachedReadOnly(
                                authority,
                                binding,
                                root.resolve("missing-disk-mount"),
                            )
                    }
                    assertEquals(missingBefore, immutableFileSnapshot(journalDirectory))
                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(leaseRoot))
                }
            } finally {
                originalReceiptBytes?.let { original ->
                    Files.deleteIfExists(receiptPath)
                    writeImmutable(receiptPath, original)
                }
                removeActiveRunLease(leaseRoot, binding.operationId)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `cold leased coordinator rejects preparing history without consulting disk or mutating journal`() =
        withJournalRoot { root ->
            val binding = binding(operationSeed = "d")
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(binding).use { journal ->
                    assertEquals(
                        FullTreeFunctionObservationOperationPhase.PREPARING,
                        journal.initialize().latest?.phase,
                    )
                }
                val journalDirectory = root.resolve(binding.journalDirectoryName)
                val before = immutableFileSnapshot(journalDirectory)

                assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                    FullTreeFunctionObservationOperationCoordinator.openExistingLeasedReadOnly(
                        authority,
                        binding,
                        root.resolve("missing-disk-mount"),
                    )
                }

                assertEquals(before, immutableFileSnapshot(journalDirectory))
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    val history = requireNotNull(journal.loadOrNull())
                    assertEquals(
                        listOf(FullTreeFunctionObservationOperationPhase.PREPARING),
                        history.transitions.map { it.phase },
                    )
                }
                assertEquals(before, immutableFileSnapshot(journalDirectory))
            }
        }

    @Test
    fun `cold leased coordinator leaves pending journal publication explicit and unlocks it`() =
        withJournalRoot { root ->
            val binding = binding(operationSeed = "e")
            val pendingName = DescriptorBoundAtomicStateFile.temporaryName("transition-0000.json")
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                var temporarySyncs = 0
                authority.createNew(binding).use { journal ->
                    assertFailsWith<SimulatedCoordinatorProcessDeath> {
                        journal.initialize(
                            DescriptorBoundStateFaultInjector { point ->
                                if (
                                    point == DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC &&
                                    ++temporarySyncs == 2
                                ) {
                                    throw SimulatedCoordinatorProcessDeath()
                                }
                            },
                        )
                    }
                }
                val journalDirectory = root.resolve(binding.journalDirectoryName)
                val before = immutableFileSnapshot(journalDirectory)
                assertTrue(pendingName in before)
                assertTrue("transition-0000.json" !in before)

                assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                    FullTreeFunctionObservationOperationCoordinator.openExistingLeasedReadOnly(
                        authority,
                        binding,
                        root.resolve("missing-disk-mount"),
                    )
                }

                assertEquals(before, immutableFileSnapshot(journalDirectory))
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.loadOrNull()
                    }
                }
                assertEquals(before, immutableFileSnapshot(journalDirectory))
                assertTrue(Files.exists(journalDirectory.resolve(pendingName), LinkOption.NOFOLLOW_LINKS))
                assertTrue(
                    !Files.exists(
                        journalDirectory.resolve("transition-0000.json"),
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                )
            }
        }

    @Test
    fun `cold leased coordinator rejects published evidence beside preparing before consulting disk`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "5")
        val leaseRoot = mount.resolve(binding.leaseDirectoryName)
        val recordPath = leaseRoot.resolve(LEASE_RECORD_FILE)
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    assertFailsWith<SimulatedCoordinatorProcessDeath> {
                        FullTreeFunctionObservationOperationCoordinator.prepareNew(
                            authority,
                            binding,
                            mount,
                            transitionFaultInjector = DescriptorBoundStateFaultInjector { point ->
                                if (point == DescriptorBoundStateFaultPoint.AFTER_UNNAMED_FILE_SYNC) {
                                    throw SimulatedCoordinatorProcessDeath()
                                }
                            },
                        )
                    }

                    val journalDirectory = root.resolve(binding.journalDirectoryName)
                    val before = immutableFileSnapshot(journalDirectory)
                    val mountNames = entryNames(mount)
                    val leaseNames = entryNames(leaseRoot)
                    val recordBytes = Files.readAllBytes(recordPath)
                    assertTrue(DISK_EVIDENCE_FILE in before)
                    assertTrue("transition-0001.json" !in before)
                    assertTrue(
                        DescriptorBoundAtomicStateFile.temporaryName("transition-0001.json") !in before,
                    )

                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        FullTreeFunctionObservationOperationCoordinator.openExistingLeasedReadOnly(
                            authority,
                            binding,
                            root.resolve("missing-disk-mount"),
                        )
                    }

                    assertEquals(before, immutableFileSnapshot(journalDirectory))
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        val history = requireNotNull(journal.loadOrNull())
                        assertEquals(
                            listOf(FullTreeFunctionObservationOperationPhase.PREPARING),
                            history.transitions.map { it.phase },
                        )
                        assertContentEquals(
                            before.getValue(DISK_EVIDENCE_FILE).toByteArray(),
                            requireNotNull(history.diskEvidence).canonicalBytes(),
                        )
                    }
                    assertEquals(before, immutableFileSnapshot(journalDirectory))
                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(leaseRoot))
                    assertContentEquals(recordBytes, Files.readAllBytes(recordPath))
                }
            } finally {
                removeRecordOnlyLease(leaseRoot)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `cold leased coordinator rejects pending leased link without completing it or consulting disk`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "6")
        val leaseRoot = mount.resolve(binding.leaseDirectoryName)
        val recordPath = leaseRoot.resolve(LEASE_RECORD_FILE)
        val pendingName = DescriptorBoundAtomicStateFile.temporaryName("transition-0001.json")
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    assertFailsWith<SimulatedCoordinatorProcessDeath> {
                        FullTreeFunctionObservationOperationCoordinator.prepareNew(
                            authority,
                            binding,
                            mount,
                            transitionFaultInjector = DescriptorBoundStateFaultInjector { point ->
                                if (point == DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC) {
                                    throw SimulatedCoordinatorProcessDeath()
                                }
                            },
                        )
                    }

                    val journalDirectory = root.resolve(binding.journalDirectoryName)
                    val before = immutableFileSnapshot(journalDirectory)
                    val mountNames = entryNames(mount)
                    val leaseNames = entryNames(leaseRoot)
                    val recordBytes = Files.readAllBytes(recordPath)
                    assertTrue(DISK_EVIDENCE_FILE in before)
                    assertTrue(pendingName in before)
                    assertTrue("transition-0001.json" !in before)

                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        FullTreeFunctionObservationOperationCoordinator.openExistingLeasedReadOnly(
                            authority,
                            binding,
                            root.resolve("missing-disk-mount"),
                        )
                    }

                    assertEquals(before, immutableFileSnapshot(journalDirectory))
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                            journal.loadOrNull()
                        }
                    }
                    assertEquals(before, immutableFileSnapshot(journalDirectory))
                    assertTrue(Files.exists(journalDirectory.resolve(pendingName), LinkOption.NOFOLLOW_LINKS))
                    assertTrue(
                        !Files.exists(
                            journalDirectory.resolve("transition-0001.json"),
                            LinkOption.NOFOLLOW_LINKS,
                        ),
                    )
                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(leaseRoot))
                    assertContentEquals(recordBytes, Files.readAllBytes(recordPath))
                }
            } finally {
                removeRecordOnlyLease(leaseRoot)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `cold leased coordinator rejects fully published unit-attached before consulting disk`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "7")
        val leaseRoot = mount.resolve(binding.leaseDirectoryName)
        val recordPath = leaseRoot.resolve(LEASE_RECORD_FILE)
        var live: FullTreeFunctionObservationLeasedOperation? = null
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    val leased = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        authority,
                        binding,
                        mount,
                    )
                    live = leased
                    leased.close()
                    live = null

                    val journalDirectory = root.resolve(binding.journalDirectoryName)
                    val history = requireNotNull(authority.openExisting(binding)).use { journal ->
                        requireNotNull(journal.loadOrNull())
                    }
                    val leasedTransition = checkNotNull(history.latest)
                    val receipt = attachmentReceipt(binding, leasedTransition, mount)
                    val attached = FullTreeFunctionObservationOperationTransition.unitAttached(
                        binding,
                        leasedTransition,
                        receipt,
                    )
                    writeImmutable(
                        journalDirectory.resolve(UNIT_ATTACHMENT_RECEIPT_FILE),
                        receipt.canonicalBytes(),
                    )
                    writeImmutable(
                        journalDirectory.resolve(attached.fileName),
                        attached.canonicalBytes(),
                    )
                    val before = immutableFileSnapshot(journalDirectory)
                    val mountNames = entryNames(mount)
                    val leaseNames = entryNames(leaseRoot)
                    val recordBytes = Files.readAllBytes(recordPath)
                    assertTrue("transition-0002.json" in before)

                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        FullTreeFunctionObservationOperationCoordinator.openExistingLeasedReadOnly(
                            authority,
                            binding,
                            root.resolve("missing-disk-mount"),
                        )
                    }

                    assertEquals(before, immutableFileSnapshot(journalDirectory))
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        val history = requireNotNull(journal.loadOrNull())
                        assertEquals(
                            listOf(
                                FullTreeFunctionObservationOperationPhase.PREPARING,
                                FullTreeFunctionObservationOperationPhase.LEASED,
                                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            ),
                            history.transitions.map { it.phase },
                        )
                    }
                    assertEquals(before, immutableFileSnapshot(journalDirectory))
                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(leaseRoot))
                    assertContentEquals(recordBytes, Files.readAllBytes(recordPath))
                }
            } finally {
                runCatching { live?.close() }
                removeRecordOnlyLease(leaseRoot)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `cold leased coordinator rejects recovered abort before consulting disk`() =
        withJournalRoot { root ->
            val binding = binding(operationSeed = "8")
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(binding).use { journal ->
                    val preparing = journal.initialize()
                    journal.append(
                        FullTreeFunctionObservationOperationTransition.recoveredAbort(
                            binding,
                            checkNotNull(preparing.latest),
                        ),
                    )
                }

                val journalDirectory = root.resolve(binding.journalDirectoryName)
                val before = immutableFileSnapshot(journalDirectory)
                assertTrue("transition-0001.json" in before)

                assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                    FullTreeFunctionObservationOperationCoordinator.openExistingLeasedReadOnly(
                        authority,
                        binding,
                        root.resolve("missing-disk-mount"),
                    )
                }

                assertEquals(before, immutableFileSnapshot(journalDirectory))
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    val history = requireNotNull(journal.loadOrNull())
                    assertEquals(
                        listOf(
                            FullTreeFunctionObservationOperationPhase.PREPARING,
                            FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
                        ),
                        history.transitions.map { it.phase },
                    )
                }
                assertEquals(before, immutableFileSnapshot(journalDirectory))
            }
        }

    @Test
    fun `run root preparation transfers every authority and preserves exact active residue`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "3")
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            val leaseRoot = mount.resolve(binding.leaseDirectoryName)
            val recordPath = leaseRoot.resolve(LEASE_RECORD_FILE)
            val expectedRunRoot = leaseRoot.resolve(runDirectoryName(binding.operationId))
            var leased: FullTreeFunctionObservationLeasedOperation? = null
            var prepared: FullTreeFunctionObservationPreparedRun? = null
            var isolationAuthority: FullTreeFunctionObservationPreparedIsolationAuthority? = null
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    val operation = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        authority,
                        binding,
                        mount,
                    )
                    leased = operation
                    val run = operation.prepareRunRoot()
                    prepared = run

                    assertSame(operation.leasedHistory, run.leasedHistory)
                    assertSame(operation.diskEvidence, run.diskEvidence)
                    assertEquals(
                        FullTreeFunctionObservationOperationPhase.LEASED,
                        run.leasedHistory.latest?.phase,
                    )
                    assertTrue(
                        Files.isDirectory(expectedRunRoot, LinkOption.NOFOLLOW_LINKS),
                        "prepared operation run root is not a directory",
                    )
                    assertEquals(
                        PosixFilePermissions.fromString("rwx------"),
                        Files.getPosixFilePermissions(expectedRunRoot, LinkOption.NOFOLLOW_LINKS),
                    )
                    assertTrue(entryNames(expectedRunRoot).isEmpty())

                    assertFailsWith<IllegalStateException> {
                        operation.requireCurrentAuthorized()
                    }
                    assertFailsWith<IllegalStateException> {
                        operation.prepareRunRoot()
                    }
                    operation.close()
                    leased = null

                    run.requireCurrentBeforeLaunch()
                    lateinit var capturedBorrow: FullTreeDiskScratchBorrowedRunRoot
                    assertEquals(
                        "prepared-borrow",
                        run.withCurrentRunRootBeforeLaunch { borrowed ->
                            capturedBorrow = borrowed
                            assertEquals(expectedRunRoot, borrowed.path)
                            assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                                run.close()
                            }
                            assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                                run.withCurrentRunRootBeforeLaunch {
                                    error("nested prepared-run borrow callback must not run")
                                }
                            }
                            val tree = BorrowedObservationRunTree.initialize(borrowed)
                            assertEquals(expectedRunRoot, tree.path)
                            assertEquals(listOf("runtime", "scratch", "tmp"), entryNames(expectedRunRoot))
                            listOf("runtime", "scratch", "tmp").forEach { name ->
                                assertEquals(
                                    PosixFilePermissions.fromString("rwx------"),
                                    Files.getPosixFilePermissions(
                                        expectedRunRoot.resolve(name),
                                        LinkOption.NOFOLLOW_LINKS,
                                    ),
                                )
                            }
                            tree.close()
                            assertFailsWith<IllegalStateException> { tree.path }
                            assertFailsWith<IllegalStateException> {
                                tree.withPinnedDescriptor { error("closed tree descriptor callback must not run") }
                            }
                            borrowed.withPinnedDescriptor { descriptor ->
                                assertTrue(
                                    Files.isSameFile(
                                        expectedRunRoot,
                                        LinuxFilesystemSyscalls.descriptorPath(descriptor),
                                    ),
                                )
                                assertEquals(
                                    listOf("runtime", "scratch", "tmp"),
                                    LinuxFilesystemSyscalls.directoryEntryNames(descriptor, 4).sorted(),
                                )
                            }
                            "prepared-borrow"
                        },
                    )
                    assertFailsWith<IllegalStateException> { capturedBorrow.path }

                    val initializedNames = entryNames(expectedRunRoot)
                    val initializedModes = initializedNames.associateWith { name ->
                        Files.getPosixFilePermissions(expectedRunRoot.resolve(name), LinkOption.NOFOLLOW_LINKS)
                    }
                    assertFailsWith<FullTreeFunctionObservationIsolationException> {
                        run.withCurrentRunRootBeforeLaunch { borrowed ->
                            BorrowedObservationRunTree.initialize(borrowed).close()
                        }
                    }
                    assertEquals(initializedNames, entryNames(expectedRunRoot))
                    assertEquals(
                        initializedModes,
                        initializedNames.associateWith { name ->
                            Files.getPosixFilePermissions(
                                expectedRunRoot.resolve(name),
                                LinkOption.NOFOLLOW_LINKS,
                            )
                        },
                    )

                    val callbackFailure = SimulatedPreparedRunBorrowFailure()
                    val retainedFailure = assertFailsWith<SimulatedPreparedRunBorrowFailure> {
                        run.withCurrentRunRootBeforeLaunch { throw callbackFailure }
                    }
                    assertSame(callbackFailure, retainedFailure)
                    assertTrue(retainedFailure.suppressed.isEmpty())
                    run.requireCurrentBeforeLaunch()

                    val transferred = run.transferToPreparedIsolationAuthority()
                    isolationAuthority = transferred
                    assertSame(run.leasedHistory, transferred.leasedHistory)
                    assertSame(run.diskEvidence, transferred.diskEvidence)
                    assertFailsWith<IllegalStateException> { run.requireCurrentBeforeLaunch() }
                    assertFailsWith<IllegalStateException> {
                        run.withCurrentRunRootBeforeLaunch {
                            error("transferred prepared-run callback must not run")
                        }
                    }
                    run.close()
                    prepared = null
                    transferred.requireCurrentBeforeLaunch()
                    transferred.withCurrentRunRootBeforeLaunch { borrowed ->
                        borrowed.withPinnedDescriptor { descriptor ->
                            assertEquals(
                                initializedNames,
                                LinuxFilesystemSyscalls.directoryEntryNames(descriptor, 4).sorted(),
                            )
                        }
                    }
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        transferred.requireCurrentAfterScopeAttachment()
                    }
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        transferred.requireCurrentAfterCgroupAbsence()
                    }

                    lateinit var attachmentBorrow: FullTreeDiskScratchBorrowedRunRoot
                    val attachmentFailure = SimulatedPreparedRunBorrowFailure()
                    val retainedAttachmentFailure = assertFailsWith<SimulatedPreparedRunBorrowFailure> {
                        transferred.withCurrentRunRootForScopeAttachment { borrowed ->
                            attachmentBorrow = borrowed
                            assertEquals(expectedRunRoot, borrowed.path)
                            assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                                transferred.close()
                            }
                            assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                                transferred.withCurrentRunRootAfterScopeAttachment {
                                    error("nested attached-stage borrow callback must not run")
                                }
                            }
                            throw attachmentFailure
                        }
                    }
                    assertSame(attachmentFailure, retainedAttachmentFailure)
                    assertTrue(retainedAttachmentFailure.suppressed.isEmpty())
                    assertFailsWith<IllegalStateException> { attachmentBorrow.path }
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        transferred.requireCurrentBeforeLaunch()
                    }
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        transferred.withCurrentRunRootForScopeAttachment {
                            error("a second scope-attachment callback must not run")
                        }
                    }
                    transferred.requireCurrentAfterScopeAttachment()
                    lateinit var attachedBorrow: FullTreeDiskScratchBorrowedRunRoot
                    assertEquals(
                        "attached-borrow",
                        transferred.withCurrentRunRootAfterScopeAttachment { borrowed ->
                            attachedBorrow = borrowed
                            borrowed.withPinnedDescriptor { descriptor ->
                                assertEquals(
                                    initializedNames,
                                    LinuxFilesystemSyscalls.directoryEntryNames(descriptor, 4).sorted(),
                                )
                            }
                            "attached-borrow"
                        },
                    )
                    assertFailsWith<IllegalStateException> { attachedBorrow.path }
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        transferred.close()
                    }
                    transferred.requireCurrentAfterCgroupAbsence()
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        transferred.requireCurrentAfterScopeAttachment()
                    }
                    assertEquals(
                        FullTreeFunctionObservationOperationPhase.LEASED,
                        transferred.leasedHistory.latest?.phase,
                    )
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        FullTreeFunctionObservationJournalAuthority.open(root)
                    }
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        authority.openExisting(binding)
                    }
                    assertFailsWith<FullTreeDiskScratchException> {
                        FullTreeDiskScratchAuthority.openExistingReadOnly(
                            mount,
                            binding.diskOperation(),
                            binding.diskPolicy(),
                        )
                    }

                    val recordBytes = Files.readAllBytes(recordPath)
                    val evidenceBytes = run.diskEvidence.canonicalBytes()
                    val mountNames = entryNames(mount)
                    val leaseNames = entryNames(leaseRoot)
                    val displacedRunRoot = leaseRoot.resolve(".displaced-during-authority-close")
                    Files.move(expectedRunRoot, displacedRunRoot)
                    try {
                        assertFailsWith<FullTreeDiskScratchException> { transferred.close() }
                    } finally {
                        if (Files.exists(displacedRunRoot, LinkOption.NOFOLLOW_LINKS)) {
                            Files.move(displacedRunRoot, expectedRunRoot)
                        }
                    }
                    isolationAuthority = null
                    transferred.close()

                    assertFailsWith<IllegalStateException> {
                        run.requireCurrentBeforeLaunch()
                    }
                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(leaseRoot))
                    assertEquals(initializedNames, entryNames(expectedRunRoot))
                    assertContentEquals(recordBytes, Files.readAllBytes(recordPath))

                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        val reopened = requireNotNull(journal.loadOrNull())
                        val journalEvidence = reopened.requireDiskEvidenceIntroducedAt(
                            FullTreeFunctionObservationOperationPhase.LEASED,
                        )
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.LEASED,
                            reopened.latest?.phase,
                        )
                        assertContentEquals(evidenceBytes, journalEvidence.canonicalBytes())

                        FullTreeDiskScratchAuthority.openExistingReadOnly(
                            mount,
                            binding.diskOperation(),
                            binding.diskPolicy(),
                        ).use { cold ->
                            val snapshot = cold.requireCurrent(journalEvidence)
                            assertEquals(
                                FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN,
                                snapshot.population,
                            )
                            assertEquals(
                                journalEvidence.leaseRecordSha256,
                                snapshot.leaseRecordSha256,
                            )
                        }
                    }

                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(leaseRoot))
                    assertEquals(initializedNames, entryNames(expectedRunRoot))
                    assertContentEquals(recordBytes, Files.readAllBytes(recordPath))
                }
            } finally {
                runCatching { isolationAuthority?.close() }
                runCatching { prepared?.close() }
                runCatching { leased?.close() }
                listOf("runtime", "scratch", "tmp").forEach { name ->
                    runCatching { Files.deleteIfExists(expectedRunRoot.resolve(name)) }
                }
                removeActiveRunLease(leaseRoot, binding.operationId)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `unit attachment transfer consumes leased authority and retains exact attached locks`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "d")
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            val leaseRoot = mount.resolve(binding.leaseDirectoryName)
            val expectedRunRoot = leaseRoot.resolve(runDirectoryName(binding.operationId))
            var leased: FullTreeFunctionObservationLeasedOperation? = null
            var preparedRun: FullTreeFunctionObservationPreparedRun? = null
            var preparedIsolation: FullTreeFunctionObservationPreparedIsolationAuthority? = null
            var attachedIsolation: FullTreeFunctionObservationUnitAttachedIsolationAuthority? = null
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    val operation = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        authority,
                        binding,
                        mount,
                    )
                    leased = operation
                    val run = operation.prepareRunRoot()
                    preparedRun = run
                    operation.close()
                    leased = null

                    val prepared = run.transferToPreparedIsolationAuthority()
                    preparedIsolation = prepared
                    run.close()
                    preparedRun = null
                    prepared.withCurrentRunRootForScopeAttachment { borrowed ->
                        assertEquals(expectedRunRoot, borrowed.path)
                    }
                    prepared.requireCurrentAfterScopeAttachment()

                    val receipt = attachmentReceipt(binding, checkNotNull(prepared.leasedHistory.latest), mount)
                    var liveReceiptChecks = 0
                    val attached = prepared.transferToUnitAttachedIsolationAuthority(
                        receipt = receipt,
                        requireLiveReceipt = { liveReceiptChecks += 1 },
                    )
                    attachedIsolation = attached
                    prepared.close()
                    preparedIsolation = null

                    assertEquals(2, liveReceiptChecks)
                    assertEquals(
                        listOf(
                            FullTreeFunctionObservationOperationPhase.PREPARING,
                            FullTreeFunctionObservationOperationPhase.LEASED,
                            FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                        ),
                        attached.attachedHistory.transitions.map { it.phase },
                    )
                    assertContentEquals(
                        receipt.canonicalBytes(),
                        attached.unitAttachmentReceipt.canonicalBytes(),
                    )
                    assertContentEquals(
                        prepared.diskEvidence.canonicalBytes(),
                        attached.diskEvidence.canonicalBytes(),
                    )
                    assertEquals(
                        receipt.receiptSha256,
                        attached.attachedHistory.latest?.unitAttachmentReceiptSha256,
                    )
                    assertFailsWith<IllegalStateException> {
                        prepared.requireCurrentAfterScopeAttachment()
                    }
                    attached.requireCurrentAtBoot()
                    attached.withCurrentRunRootAtBoot { borrowed ->
                        assertEquals(expectedRunRoot, borrowed.path)
                    }
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        authority.openExisting(binding)
                    }
                    assertFailsWith<FullTreeDiskScratchException> {
                        FullTreeDiskScratchAuthority.openExistingReadOnly(
                            mount,
                            binding.diskOperation(),
                            binding.diskPolicy(),
                        )
                    }

                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        attached.close()
                    }
                    attached.requireCurrentAtBoot()
                    attached.requireCurrentAfterCgroupAbsence()
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        attached.requireCurrentAtBoot()
                    }
                    attached.close()
                    attachedIsolation = null

                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        val reopened = requireNotNull(journal.loadOrNull())
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            reopened.latest?.phase,
                        )
                        assertContentEquals(
                            receipt.canonicalBytes(),
                            reopened.requireUnitAttachmentReceiptIntroducedAt(
                                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            ).canonicalBytes(),
                        )
                    }
                }
            } finally {
                runCatching {
                    attachedIsolation?.requireCurrentAfterCgroupAbsence()
                    attachedIsolation?.close()
                }
                runCatching {
                    preparedIsolation?.let { prepared ->
                        if (prepared.attachmentPublicationWasAttempted()) {
                            prepared.closeAfterFailedAttachmentPublication()
                        } else {
                            prepared.requireCurrentAfterCgroupAbsence()
                            prepared.close()
                        }
                    }
                }
                runCatching { preparedRun?.close() }
                runCatching { leased?.close() }
                removeActiveRunLease(leaseRoot, binding.operationId)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `attached terminal close releases locks even when final journal validation poisons`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "0")
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            val leaseRoot = mount.resolve(binding.leaseDirectoryName)
            val foreignJournalEntry = root.resolve(binding.journalDirectoryName).resolve("foreign-entry")
            var attachedIsolation: FullTreeFunctionObservationUnitAttachedIsolationAuthority? = null
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    val operation = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        authority,
                        binding,
                        mount,
                    )
                    val run = operation.prepareRunRoot()
                    operation.close()
                    val prepared = run.transferToPreparedIsolationAuthority()
                    run.close()
                    prepared.withCurrentRunRootForScopeAttachment { }
                    val receipt = attachmentReceipt(binding, checkNotNull(prepared.leasedHistory.latest), mount)
                    val attached = prepared.transferToUnitAttachedIsolationAuthority(
                        receipt,
                        requireLiveReceipt = { },
                    )
                    attachedIsolation = attached
                    prepared.close()
                    Files.writeString(foreignJournalEntry, "unowned journal residue")

                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        attached.closeAfterProvedCgroupAbsence()
                    }
                    attachedIsolation = null
                    FullTreeDiskScratchAuthority.openExistingReadOnly(
                        mount,
                        binding.diskOperation(),
                        binding.diskPolicy(),
                    ).use { cold ->
                        assertEquals(
                            FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN,
                            cold.requireCurrent(attached.diskEvidence).population,
                        )
                    }
                    Files.delete(foreignJournalEntry)
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            requireNotNull(journal.loadOrNull()).latest?.phase,
                        )
                    }
                }
            } finally {
                runCatching { attachedIsolation?.closeAfterProvedCgroupAbsence() }
                Files.deleteIfExists(foreignJournalEntry)
                removeActiveRunLease(leaseRoot, binding.operationId)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `failed attachment publication stays cleanup-only and releases poison for cold completion`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "e")
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            val leaseRoot = mount.resolve(binding.leaseDirectoryName)
            var preparedIsolation: FullTreeFunctionObservationPreparedIsolationAuthority? = null
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    val operation = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        authority,
                        binding,
                        mount,
                    )
                    val run = operation.prepareRunRoot()
                    operation.close()
                    val prepared = run.transferToPreparedIsolationAuthority()
                    preparedIsolation = prepared
                    run.close()
                    prepared.withCurrentRunRootForScopeAttachment { }
                    val receipt = attachmentReceipt(binding, checkNotNull(prepared.leasedHistory.latest), mount)
                    val failure = SimulatedCoordinatorProcessDeath()

                    val retained = assertFailsWith<SimulatedCoordinatorProcessDeath> {
                        prepared.transferToUnitAttachedIsolationAuthority(
                            receipt = receipt,
                            requireLiveReceipt = { },
                            receiptFaultInjector = DescriptorBoundStateFaultInjector { point ->
                                if (point == DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC) {
                                    throw failure
                                }
                            },
                        )
                    }
                    assertSame(failure, retained)
                    assertTrue(prepared.attachmentPublicationWasAttempted())
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        prepared.requireCurrentAfterScopeAttachment()
                    }
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        prepared.close()
                    }
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        authority.openExisting(binding)
                    }
                    assertFailsWith<FullTreeDiskScratchException> {
                        FullTreeDiskScratchAuthority.openExistingReadOnly(
                            mount,
                            binding.diskOperation(),
                            binding.diskPolicy(),
                        )
                    }

                    prepared.closeAfterFailedAttachmentPublication()
                    preparedIsolation = null

                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        val completion = journal.completeExactPendingPublication()
                        assertEquals(
                            FullTreeFunctionObservationColdCompletionKind.UNIT_ATTACHMENT_RECEIPT,
                            completion.kind,
                        )
                        val staged = requireNotNull(completion.history)
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.LEASED,
                            staged.latest?.phase,
                        )
                        assertContentEquals(
                            receipt.canonicalBytes(),
                            requireNotNull(staged.unitAttachmentReceipt).canonicalBytes(),
                        )
                    }
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        FullTreeFunctionObservationOperationCoordinator.openExistingLeasedReadOnly(
                            authority,
                            binding,
                            root.resolve("missing-disk-mount"),
                        )
                    }
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        val attached = journal.recordUnitAttached(receipt)
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            attached.latest?.phase,
                        )
                        assertContentEquals(
                            receipt.canonicalBytes(),
                            attached.requireUnitAttachmentReceiptIntroducedAt(
                                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            ).canonicalBytes(),
                        )
                    }
                }
            } finally {
                runCatching {
                    preparedIsolation?.let { prepared ->
                        if (prepared.attachmentPublicationWasAttempted()) {
                            prepared.closeAfterFailedAttachmentPublication()
                        } else {
                            prepared.requireCurrentAfterCgroupAbsence()
                            prepared.close()
                        }
                    }
                }
                removeActiveRunLease(leaseRoot, binding.operationId)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `attachment transaction validation marks cleanup-only before journal poison`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "f")
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            val leaseRoot = mount.resolve(binding.leaseDirectoryName)
            val foreignJournalEntry = root.resolve(binding.journalDirectoryName).resolve("foreign-entry")
            var preparedIsolation: FullTreeFunctionObservationPreparedIsolationAuthority? = null
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    val operation = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        authority,
                        binding,
                        mount,
                    )
                    val run = operation.prepareRunRoot()
                    operation.close()
                    val prepared = run.transferToPreparedIsolationAuthority()
                    preparedIsolation = prepared
                    run.close()
                    prepared.withCurrentRunRootForScopeAttachment { }
                    val receipt = attachmentReceipt(binding, checkNotNull(prepared.leasedHistory.latest), mount)
                    Files.writeString(foreignJournalEntry, "unowned journal residue")

                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        prepared.transferToUnitAttachedIsolationAuthority(
                            receipt = receipt,
                            requireLiveReceipt = { },
                        )
                    }
                    assertTrue(prepared.attachmentPublicationWasAttempted())
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        prepared.requireCurrentAfterScopeAttachment()
                    }
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        prepared.requireCurrentAfterCgroupAbsence()
                    }
                    assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                        prepared.requireCurrentAfterProvedLaunchBoundaryAbsence()
                    }
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        authority.openExisting(binding)
                    }

                    prepared.closeAfterFailedAttachmentPublication()
                    preparedIsolation = null
                    Files.delete(foreignJournalEntry)
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.LEASED,
                            requireNotNull(journal.loadOrNull()).latest?.phase,
                        )
                    }
                }
            } finally {
                runCatching {
                    preparedIsolation?.let { prepared ->
                        if (prepared.attachmentPublicationWasAttempted()) {
                            prepared.closeAfterFailedAttachmentPublication()
                        } else {
                            prepared.requireCurrentAfterCgroupAbsence()
                            prepared.close()
                        }
                    }
                }
                Files.deleteIfExists(foreignJournalEntry)
                removeActiveRunLease(leaseRoot, binding.operationId)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `run root synchronization fault leaves a closed lease and exact active residue`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "4")
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            val leaseRoot = mount.resolve(binding.leaseDirectoryName)
            val recordPath = leaseRoot.resolve(LEASE_RECORD_FILE)
            val runPath = leaseRoot.resolve(runDirectoryName(binding.operationId))
            var leased: FullTreeFunctionObservationLeasedOperation? = null
            val fault = FullTreeDiskScratchRunRootFaultInjector { point ->
                if (point == FullTreeDiskScratchRunRootFaultPoint.AFTER_ROOT_SYNC) {
                    throw SimulatedCoordinatorProcessDeath()
                }
            }
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    val operation = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        authority,
                        binding,
                        mount,
                    )
                    leased = operation
                    assertFailsWith<SimulatedCoordinatorProcessDeath> {
                        operation.prepareRunRoot(fault)
                    }
                    leased = null

                    assertFailsWith<IllegalStateException> {
                        operation.requireCurrentAuthorized()
                    }
                    assertTrue(Files.isDirectory(runPath, LinkOption.NOFOLLOW_LINKS))
                    assertTrue(entryNames(runPath).isEmpty())
                    val recordBytes = Files.readAllBytes(recordPath)
                    val mountNames = entryNames(mount)
                    val leaseNames = entryNames(leaseRoot)

                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        val history = requireNotNull(journal.loadOrNull())
                        val evidence = history.requireDiskEvidenceIntroducedAt(
                            FullTreeFunctionObservationOperationPhase.LEASED,
                        )
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.LEASED,
                            history.latest?.phase,
                        )

                        FullTreeDiskScratchAuthority.openExistingReadOnly(
                            mount,
                            binding.diskOperation(),
                            binding.diskPolicy(),
                        ).use { cold ->
                            val snapshot = cold.requireCurrent(evidence)
                            assertEquals(
                                FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN,
                                snapshot.population,
                            )
                            assertEquals(evidence.leaseRecordSha256, snapshot.leaseRecordSha256)
                        }
                    }

                    assertEquals(mountNames, entryNames(mount))
                    assertEquals(leaseNames, entryNames(leaseRoot))
                    assertTrue(entryNames(runPath).isEmpty())
                    assertContentEquals(recordBytes, Files.readAllBytes(recordPath))
                }
            } finally {
                runCatching { leased?.close() }
                removeActiveRunLease(leaseRoot, binding.operationId)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `prepared operation retains all authorities and reopens against exact journal evidence`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "1")
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            val leaseRoot = mount.resolve(binding.leaseDirectoryName)
            val recordPath = leaseRoot.resolve(LEASE_RECORD_FILE)
            var prepared: FullTreeFunctionObservationLeasedOperation? = null
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    val operation = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        authority,
                        binding,
                        mount,
                    )
                    prepared = operation
                    try {
                        val history = operation.leasedHistory
                        val accepted = history.requireDiskEvidenceIntroducedAt(
                            FullTreeFunctionObservationOperationPhase.LEASED,
                        )

                        assertEquals(FullTreeFunctionObservationOperationPhase.LEASED, history.latest?.phase)
                        assertSame(history.diskEvidence, operation.diskEvidence)
                        assertSame(accepted, operation.diskEvidence)
                        assertEquals(operation.diskEvidence.evidenceSha256, history.latest?.diskEvidenceSha256)
                        assertEquals(leaseRoot, operation.scratchParent)
                        assertContentEquals(
                            operation.diskEvidence.canonicalBytes(),
                            Files.readAllBytes(
                                root.resolve(binding.journalDirectoryName).resolve(DISK_EVIDENCE_FILE),
                            ),
                        )
                        operation.requireCurrentAuthorized()

                        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                            FullTreeFunctionObservationJournalAuthority.open(root)
                        }
                        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                            authority.openExisting(binding)
                        }
                        assertFailsWith<FullTreeDiskScratchException> {
                            FullTreeDiskScratchAuthority.openExistingReadOnly(
                                mount,
                                binding.diskOperation(),
                                binding.diskPolicy(),
                            )
                        }

                        val recordBytes = Files.readAllBytes(recordPath)
                        val mountNames = entryNames(mount)
                        val leaseNames = entryNames(leaseRoot)
                        operation.close()
                        prepared = null
                        operation.close()

                        assertEquals(mountNames, entryNames(mount))
                        assertEquals(leaseNames, entryNames(leaseRoot))
                        assertContentEquals(recordBytes, Files.readAllBytes(recordPath))

                        requireNotNull(authority.openExisting(binding)).use { journal ->
                            val reopened = requireNotNull(journal.loadOrNull())
                            val journalEvidence = reopened.requireDiskEvidenceIntroducedAt(
                                FullTreeFunctionObservationOperationPhase.LEASED,
                            )
                            assertContentEquals(
                                operation.diskEvidence.canonicalBytes(),
                                journalEvidence.canonicalBytes(),
                            )
                            assertEquals(
                                FullTreeFunctionObservationOperationPhase.LEASED,
                                reopened.latest?.phase,
                            )

                            FullTreeDiskScratchAuthority.openExistingReadOnly(
                                mount,
                                binding.diskOperation(),
                                binding.diskPolicy(),
                            ).use { cold ->
                                val snapshot = cold.requireCurrent(journalEvidence)
                                assertEquals(
                                    FullTreeDiskScratchColdPopulation.RECORD_ONLY,
                                    snapshot.population,
                                )
                                assertEquals(journalEvidence.leaseRecordSha256, snapshot.leaseRecordSha256)
                                assertContentEquals(recordBytes, Files.readAllBytes(recordPath))
                            }
                        }

                        assertEquals(mountNames, entryNames(mount))
                        assertEquals(leaseNames, entryNames(leaseRoot))
                        assertContentEquals(recordBytes, Files.readAllBytes(recordPath))
                    } finally {
                        operation.close()
                        prepared = null
                    }
                }
            } finally {
                runCatching { prepared?.close() }
                removeRecordOnlyLease(leaseRoot)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    @Test
    fun `recording faults abandon the live lease without changing exact recoverable residue`() {
        val mount = provisionedMount()
        val binding = binding(operationSeed = "2")
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")

        withJournalRoot { root ->
            val leaseRoot = mount.resolve(binding.leaseDirectoryName)
            val recordPath = leaseRoot.resolve(LEASE_RECORD_FILE)
            val fault = DescriptorBoundStateFaultInjector { point ->
                if (point == DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_DIRECTORY_SYNC) {
                    throw SimulatedCoordinatorProcessDeath()
                }
            }
            try {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    assertFailsWith<SimulatedCoordinatorProcessDeath> {
                        FullTreeFunctionObservationOperationCoordinator.prepareNew(
                            authority,
                            binding,
                            mount,
                            transitionFaultInjector = fault,
                        )
                    }

                    assertEquals(listOf(binding.leaseDirectoryName), entryNames(mount))
                    assertEquals(listOf(LEASE_RECORD_FILE), entryNames(leaseRoot))
                    val recordBytes = Files.readAllBytes(recordPath)
                    val journalDirectory = root.resolve(binding.journalDirectoryName)
                    val evidenceBytes = Files.readAllBytes(journalDirectory.resolve(DISK_EVIDENCE_FILE))

                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        val history = requireNotNull(journal.loadOrNull())
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.LEASED,
                            history.latest?.phase,
                        )
                        val evidence = history.requireDiskEvidenceIntroducedAt(
                            FullTreeFunctionObservationOperationPhase.LEASED,
                        )
                        assertSame(history.diskEvidence, evidence)
                        assertContentEquals(evidence.canonicalBytes(), evidenceBytes)

                        FullTreeDiskScratchAuthority.openExistingReadOnly(
                            mount,
                            binding.diskOperation(),
                            binding.diskPolicy(),
                        ).use { cold ->
                            val snapshot = cold.requireCurrent(evidence)
                            assertEquals(
                                FullTreeDiskScratchColdPopulation.RECORD_ONLY,
                                snapshot.population,
                            )
                            assertEquals(evidence.leaseRecordSha256, snapshot.leaseRecordSha256)
                        }
                    }

                    assertEquals(listOf(binding.leaseDirectoryName), entryNames(mount))
                    assertEquals(listOf(LEASE_RECORD_FILE), entryNames(leaseRoot))
                    assertContentEquals(recordBytes, Files.readAllBytes(recordPath))
                    assertContentEquals(
                        evidenceBytes,
                        Files.readAllBytes(journalDirectory.resolve(DISK_EVIDENCE_FILE)),
                    )
                }
            } finally {
                removeRecordOnlyLease(leaseRoot)
            }
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    private fun binding(operationSeed: String): FullTreeFunctionObservationOperationBinding =
        FullTreeFunctionObservationOperationBinding.create(
            operationId = operationSeed.repeat(64),
            shardId = "clang-lib-driver",
            shardInputSha256 = "4".repeat(64),
            scopeSha256 = "5".repeat(64),
            inventoryArtifactSha256 = "6".repeat(64),
            richArtifactSha256 = "7".repeat(64),
            isolationConfiguration = isolationConfiguration(),
            output = Path.of("/var/lib/decomp-oracle/output/clang-lib-driver-$operationSeed.json"),
            diskPolicy = FullTreeDiskScratchPolicy(
                requiredAvailableBytes = 1,
                maximumFilesystemBytes = EXPECTED_MAXIMUM_FILESYSTEM_BYTES,
                requiredAvailableInodes = 4,
                maximumFilesystemInodes = EXPECTED_MAXIMUM_FILESYSTEM_INODES,
            ),
        )

    private fun createUnitAttachedActiveResidue(
        authority: FullTreeFunctionObservationJournalAuthority,
        binding: FullTreeFunctionObservationOperationBinding,
        mount: Path,
    ): FullTreeFunctionObservationOperationHistory {
        val leased = FullTreeFunctionObservationOperationCoordinator.prepareNew(
            authority,
            binding,
            mount,
        )
        val prepared = leased.prepareRunRoot()
        leased.close()
        prepared.close()
        return requireNotNull(authority.openExisting(binding)).use { journal ->
            val history = requireNotNull(journal.loadOrNull())
            journal.recordUnitAttached(
                attachmentReceipt(binding, checkNotNull(history.latest), mount),
            )
        }
    }

    private fun attachmentReceipt(
        binding: FullTreeFunctionObservationOperationBinding,
        leased: FullTreeFunctionObservationOperationTransition,
        mount: Path,
        identitySeed: Long = 0,
    ): FullTreeFunctionObservationUnitAttachmentReceipt {
        fun process(
            role: FullTreeFunctionObservationAttachmentProcessRole,
            hostPid: Long,
            parentRole: FullTreeFunctionObservationAttachmentProcessRole?,
            namespacePids: List<Long>,
            executableDevice: Long,
            executableInode: Long,
            executableMountId: Long,
        ): FullTreeFunctionObservationAttachmentProcessIdentity {
            val seededHostPid = Math.addExact(hostPid, identitySeed)
            val seededNamespacePids = namespacePids.mapIndexed { index, pid ->
                if (index == 0) Math.addExact(pid, identitySeed) else pid
            }
            return FullTreeFunctionObservationAttachmentProcessIdentity(
                role = role,
                hostPid = seededHostPid,
                startTimeTicks = seededHostPid * 100L,
                parentRole = parentRole,
                namespacePids = seededNamespacePids,
                executableDevice = executableDevice,
                executableInode = executableInode,
                executableMountId = executableMountId,
            )
        }
        val runRootIdentity = runCatching {
            LinuxFilesystemSyscalls.openRoot(
                mount.resolve(binding.leaseDirectoryName).resolve(runDirectoryName(binding.operationId)),
            ).use { descriptor -> LinuxFilesystemSyscalls.identity(descriptor.fd) }
        }.getOrNull()
        return FullTreeFunctionObservationUnitAttachmentReceipt.create(
            binding = binding,
            leasedTransition = leased,
            bootId = "1".padStart(32, '0'),
            invocationId = "2".padStart(32, '0'),
            controlGroup = "/user.slice/user-1000.slice/user@1000.service/app.slice/${binding.unitName}",
            cgroupDevice = 301,
            cgroupInode = 401,
            cgroupMountId = 501,
            runRootDevice = runRootIdentity?.key?.device ?: 1,
            runRootInode = runRootIdentity?.key?.inode ?: 1,
            runRootMountId = runRootIdentity?.mountId ?: 1,
            processes = listOf(
                process(
                    FullTreeFunctionObservationAttachmentProcessRole.OUTER_BUBBLEWRAP,
                    1010,
                    null,
                    listOf(1010),
                    101,
                    111,
                    121,
                ),
                process(
                    FullTreeFunctionObservationAttachmentProcessRole.NAMESPACE_INIT_BUBBLEWRAP,
                    1011,
                    FullTreeFunctionObservationAttachmentProcessRole.OUTER_BUBBLEWRAP,
                    listOf(1011, 1),
                    101,
                    111,
                    121,
                ),
                process(
                    FullTreeFunctionObservationAttachmentProcessRole.SUPERVISOR_JVM,
                    1012,
                    FullTreeFunctionObservationAttachmentProcessRole.NAMESPACE_INIT_BUBBLEWRAP,
                    listOf(1012, 2),
                    201,
                    211,
                    221,
                ),
                process(
                    FullTreeFunctionObservationAttachmentProcessRole.WORKER_JVM,
                    1013,
                    FullTreeFunctionObservationAttachmentProcessRole.SUPERVISOR_JVM,
                    listOf(1013, 3),
                    201,
                    211,
                    221,
                ),
            ),
        )
    }

    private fun isolationConfiguration(): FullTreeFunctionObservationIsolationConfiguration {
        val javaRuntime = Path.of("/provisioned/java")
        val tool = Path.of("/provisioned/tools")
        return FullTreeFunctionObservationIsolationConfiguration(
            javaExecutable = javaRuntime.resolve("bin/java"),
            javaRuntime = FullTreeFunctionObservationRuntimeMount(
                javaRuntime,
                Path.of("/runtime/java"),
                "8".repeat(64),
            ),
            systemLibraryMounts = listOf(
                FullTreeFunctionObservationRuntimeMount(
                    Path.of("/provisioned/libraries"),
                    Path.of("/runtime/libraries"),
                    "9".repeat(64),
                ),
            ),
            bubblewrapExecutable = tool.resolve("bwrap"),
            resourceLimiterExecutable = tool.resolve("prlimit"),
            scopeSupervisorExecutable = tool.resolve("systemd-run"),
            scopeInspectorExecutable = tool.resolve("systemctl"),
            systemdUserRuntimeDirectory = Path.of("/run/user/1000"),
            workerClassPath = listOf(
                FullTreeFunctionObservationClassPathEntry(
                    Path.of("/provisioned/application/worker.jar"),
                    "a".repeat(64),
                ),
            ),
            expectedJavaSha256 = "b".repeat(64),
            expectedBubblewrapSha256 = "c".repeat(64),
            expectedResourceLimiterSha256 = "d".repeat(64),
            expectedScopeSupervisorSha256 = "e".repeat(64),
            expectedScopeInspectorSha256 = "f".repeat(64),
        )
    }

    private fun provisionedMount(): Path {
        val configured = System.getenv("DECOMP_TEST_ORACLE_EXT4_SCRATCH")
        if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
            assertTrue(!configured.isNullOrBlank(), "required CI ext4 scratch slot was not provisioned")
        }
        assumeTrue(
            !configured.isNullOrBlank(),
            "set DECOMP_TEST_ORACLE_EXT4_SCRATCH to an empty user-owned 0700 ext4 mount with " +
                "rw,nodev,nosuid,noexec,noatime",
        )
        return Path.of(requireNotNull(configured)).toAbsolutePath().normalize()
    }

    private fun removeRecordOnlyLease(leaseRoot: Path) {
        Files.deleteIfExists(leaseRoot.resolve(LEASE_RECORD_FILE))
        Files.deleteIfExists(leaseRoot)
    }

    private fun removeActiveRunLease(leaseRoot: Path, operationId: String) {
        Files.deleteIfExists(leaseRoot.resolve(runDirectoryName(operationId)))
        removeRecordOnlyLease(leaseRoot)
    }

    private fun entryNames(directory: Path): List<String> =
        Files.list(directory).use { entries ->
            entries.map { it.fileName.toString() }.sorted().toList()
        }

    private fun immutableFileSnapshot(directory: Path): Map<String, List<Byte>> =
        Files.list(directory).use { entries ->
            entries.sorted().toList().associate { path ->
                path.fileName.toString() to Files.readAllBytes(path).toList()
            }
        }

    private fun writeImmutable(path: Path, bytes: ByteArray) {
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
    }

    private inline fun withJournalRoot(action: (Path) -> Unit) {
        val container = createTempDirectory("function-operation-coordinator-")
            .toAbsolutePath().normalize()
        Files.setPosixFilePermissions(container, PosixFilePermissions.fromString("rwx------"))
        val root = Files.createDirectory(container.resolve("root"))
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            action(root)
        } finally {
            if (Files.exists(container, LinkOption.NOFOLLOW_LINKS)) {
                Files.walk(container).use { entries ->
                    entries.sorted(Comparator.reverseOrder()).toList()
                }.forEach(Files::deleteIfExists)
            }
        }
    }

    private class SimulatedCoordinatorProcessDeath : RuntimeException()

    private class SimulatedPreparedRunBorrowFailure : RuntimeException()

    private companion object {
        const val EXPECTED_MAXIMUM_FILESYSTEM_BYTES = 64L * 1024 * 1024
        const val EXPECTED_MAXIMUM_FILESYSTEM_INODES = 4096L
        const val LEASE_RECORD_FILE = "lease.json"
        const val DISK_EVIDENCE_FILE = "disk-evidence.json"
        const val UNIT_ATTACHMENT_RECEIPT_FILE = "unit-attachment.json"
    }
}
