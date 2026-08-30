package decompengine.oracle.fulltree

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
                        operation.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)

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

    private fun entryNames(directory: Path): List<String> =
        Files.list(directory).use { entries ->
            entries.map { it.fileName.toString() }.sorted().toList()
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

    private companion object {
        const val EXPECTED_MAXIMUM_FILESYSTEM_BYTES = 64L * 1024 * 1024
        const val EXPECTED_MAXIMUM_FILESYSTEM_INODES = 4096L
        const val LEASE_RECORD_FILE = "lease.json"
        const val DISK_EVIDENCE_FILE = "disk-evidence.json"
    }
}
