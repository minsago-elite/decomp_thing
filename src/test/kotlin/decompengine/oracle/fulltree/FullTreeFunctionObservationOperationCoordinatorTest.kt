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
                    val legacyAttached = FullTreeFunctionObservationOperationTransition.unitAttached(
                        binding,
                        checkNotNull(history.latest),
                    )
                    writeImmutable(
                        journalDirectory.resolve(legacyAttached.fileName),
                        legacyAttached.canonicalBytes(),
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
                    transferred.close()
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
    }
}
