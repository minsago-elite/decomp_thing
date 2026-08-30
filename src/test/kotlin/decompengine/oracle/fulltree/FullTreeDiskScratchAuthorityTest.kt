package decompengine.oracle.fulltree

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.acp.LinuxFilesystemCapacity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFilePermissions
import java.time.Instant
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue

class FullTreeDiskScratchAuthorityTest {
    @Test
    fun `mountinfo parser preserves exact identities paths options and nesting`() {
        val mounts = parseFullTreeDiskMountTable(
            """
            36 25 0:31 / / rw,relatime - xfs /dev/root rw
            42 36 7:1 / /var/lib/decomp\040scratch rw,nosuid,nodev,noexec,noatime - ext4 /dev/loop0 rw
            43 42 0:44 / /var/lib/decomp\040scratch/nested rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=4096k
            """.trimIndent() + "\n",
        )

        assertEquals(3, mounts.size)
        assertEquals(42L, mounts[1].mountId)
        assertEquals(36L, mounts[1].parentMountId)
        assertEquals("7:1", mounts[1].device)
        assertEquals(Path.of("/"), mounts[1].root)
        assertEquals(Path.of("/var/lib/decomp scratch"), mounts[1].mountPoint)
        assertEquals(listOf("noatime", "nodev", "noexec", "nosuid", "rw"), mounts[1].options)
        assertEquals("ext4", mounts[1].fileSystemType)

        assertFailsWith<FullTreeDiskScratchException> {
            parseFullTreeDiskMountTable(
                "42 36 7:1 / /var/lib/bad\\777 rw - ext4 /dev/loop0 rw\n",
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            parseFullTreeDiskMountTable(
                "42 36 7:1 / /one rw - ext4 /dev/loop0 rw\n" +
                    "42 36 7:2 / /two rw - ext4 /dev/loop1 rw\n",
            )
        }

        val live = parseFullTreeDiskMountTable(Files.readString(Path.of("/proc/self/mountinfo")))
        assertTrue(live.isNotEmpty())
        assertEquals(live.size, live.map { it.mountId }.distinct().size)
    }

    @Test
    fun `scratch evidence has frozen canonical bytes and self hash`() {
        val operation = operation()
        val policy = FullTreeDiskScratchPolicy(
            requiredAvailableBytes = 1024,
            maximumFilesystemBytes = 8192,
            requiredAvailableInodes = 4,
            maximumFilesystemInodes = 64,
        )
        val evidence = FullTreeDiskScratchEvidence.create(
            operation = operation,
            policy = policy,
            mountPathSha256 = "4".repeat(64),
            mount = FullTreeDiskMount(
                mountId = 42,
                parentMountId = 36,
                device = "7:1",
                root = Path.of("/"),
                mountPoint = Path.of("/var/lib/decomp-scratch"),
                options = listOf("noatime", "nodev", "noexec", "nosuid", "rw"),
                fileSystemType = "ext4",
            ),
            mountIdentity = identity(device = 7, inode = 2, mountId = 42),
            capacity = LinuxFilesystemCapacity(
                fragmentBytes = 4096,
                totalBytes = 8192,
                availableBytes = 4096,
                totalInodes = 64,
                availableInodes = 60,
                maximumNameBytes = 255,
                readOnly = false,
            ),
            leaseIdentity = identity(device = 7, inode = 12, mountId = 42),
            leaseRecordSha256 = "5".repeat(64),
        )

        assertEquals(1, evidence.schemaVersion)
        assertEquals("dedicated-ext4-filesystem-v1", evidence.provider)
        assertEquals(evidence.evidenceSha256, sha256(evidence.canonicalBytesWithoutSelfHashForTest()))
        assertEquals(FROZEN_EVIDENCE_SHA256, evidence.evidenceSha256)
        assertEquals(FROZEN_EVIDENCE_ARTIFACT_SHA256, sha256(evidence.canonicalBytes()))
        assertEquals(
            evidence.canonicalBytes().toList(),
            FullTreeDiskScratchEvidence.parseCanonical(evidence.canonicalBytes()).canonicalBytes().toList(),
        )
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchEvidence.parseCanonical(evidence.canonicalBytes() + '\n'.code.toByte())
        }

        val root = OracleJson.parse(evidence.canonicalBytes()) as JsonObject
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchEvidence.parseCanonical(
                OracleJson.canonicalBytes(JsonObject(root + ("unknown" to JsonPrimitive(true)))),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchEvidence.parseCanonical(
                mutateEvidence(evidence, "schemaVersion", JsonPrimitive("1")),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchEvidence.parseCanonical(
                mutateEvidence(evidence, "provider", JsonPrimitive("ordinary-directory-v1")),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchEvidence.parseCanonical(
                mutateEvidence(
                    evidence,
                    "mountFlags",
                    JsonArray(listOf("nodev", "noexec", "nosuid", "rw").map(::JsonPrimitive)),
                ),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchEvidence.parseCanonical(
                mutateEvidence(evidence, "mode", JsonPrimitive(0x1e0)),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchEvidence.parseCanonical(
                mutateEvidence(evidence, "initialAvailableBytes", JsonPrimitive(1023)),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchEvidence.parseCanonical(
                mutateEvidence(evidence, "initialAvailableInodes", JsonPrimitive(3)),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchEvidence.parseCanonical(
                OracleJson.canonicalBytes(
                    JsonObject(root + ("evidenceSha256" to JsonPrimitive("0".repeat(64)))),
                ),
            )
        }
    }

    @Test
    fun `lease record is strict canonical self hashed and frozen`() {
        val record = leaseRecord()

        assertEquals(record.recordSha256, sha256(record.canonicalBytesWithoutSelfHashForTest()))
        assertEquals(FROZEN_LEASE_RECORD_SHA256, record.recordSha256)
        assertEquals(FROZEN_LEASE_RECORD_ARTIFACT_SHA256, sha256(record.canonicalBytes()))
        assertEquals(
            record.canonicalBytes().toList(),
            FullTreeDiskScratchLeaseRecord.parseCanonical(record.canonicalBytes()).canonicalBytes().toList(),
        )
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchLeaseRecord.parseCanonical(record.canonicalBytes() + '\n'.code.toByte())
        }

        val root = OracleJson.parse(record.canonicalBytes()) as JsonObject
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchLeaseRecord.parseCanonical(
                OracleJson.canonicalBytes(JsonObject(root + ("unknown" to JsonPrimitive(true)))),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchLeaseRecord.parseCanonical(
                mutateRecord(record, "schemaVersion", JsonPrimitive("1")),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchLeaseRecord.parseCanonical(
                mutateRecord(record, "provider", JsonPrimitive("ordinary-directory-v1")),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchLeaseRecord.parseCanonical(
                mutateRecord(
                    record,
                    "mountFlags",
                    JsonArray(listOf("rw", "nodev", "noexec", "nosuid", "noatime").map(::JsonPrimitive)),
                ),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchLeaseRecord.parseCanonical(
                mutateRecord(
                    record,
                    "mountFlags",
                    JsonArray(listOf("nodev", "noexec", "nosuid", "rw").map(::JsonPrimitive)),
                ),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchLeaseRecord.parseCanonical(
                mutateRecord(
                    record,
                    "mountFlags",
                    JsonArray(
                        listOf("noatime", "noatime", "nodev", "noexec", "nosuid", "rw")
                            .map(::JsonPrimitive),
                    ),
                ),
            )
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchLeaseRecord.parseCanonical(
                OracleJson.canonicalBytes(
                    JsonObject(root + ("recordSha256" to JsonPrimitive("0".repeat(64)))),
                ),
            )
        }
    }

    @Test
    fun `ordinary workspace directories cannot be promoted to disk quota authority`() {
        val directory = createTempDirectory("ordinary-oracle-scratch-").toAbsolutePath().normalize()
        try {
            assertFailsWith<FullTreeDiskScratchException> {
                FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(
                    directory,
                    operation(),
                    FullTreeDiskScratchPolicy(1, Long.MAX_VALUE, 4, Long.MAX_VALUE),
                )
            }
            assertFailsWith<FullTreeDiskScratchException> {
                FullTreeDiskScratchAuthority.openExistingReadOnly(
                    directory,
                    operation(),
                    FullTreeDiskScratchPolicy(1, Long.MAX_VALUE, 4, Long.MAX_VALUE),
                )
            }
            assertTrue(Files.list(directory).use { it.findAny().isEmpty })
        } finally {
            Files.deleteIfExists(directory)
        }
    }

    @Test
    fun `provisioned ext4 slot is exclusive revalidated and cleanly released`() {
        val configured = System.getenv("DECOMP_TEST_ORACLE_EXT4_SCRATCH")
        if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
            assertTrue(!configured.isNullOrBlank(), "required CI ext4 scratch slot was not provisioned")
        }
        assumeTrue(
            !configured.isNullOrBlank(),
            "set DECOMP_TEST_ORACLE_EXT4_SCRATCH to an empty user-owned 0700 ext4 mount with " +
                "rw,nodev,nosuid,noexec,noatime",
        )
        val mount = Path.of(configured).toAbsolutePath().normalize()
        val capacity = LinuxFilesystemSyscalls.openRoot(mount).use {
            LinuxFilesystemSyscalls.filesystemCapacity(it)
        }
        assertTrue(capacity.totalBytes <= EXPECTED_MAXIMUM_FILESYSTEM_BYTES)
        assertTrue(capacity.totalInodes <= EXPECTED_MAXIMUM_FILESYSTEM_INODES)
        val policy = FullTreeDiskScratchPolicy(
            requiredAvailableBytes = 1,
            maximumFilesystemBytes = EXPECTED_MAXIMUM_FILESYSTEM_BYTES,
            requiredAvailableInodes = 4,
            maximumFilesystemInodes = EXPECTED_MAXIMUM_FILESYSTEM_INODES,
        )
        val operation = operation()
        val lease = FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(mount, operation, policy)
        var active: Path? = null
        var released = false
        try {
            lease.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
            assertFailsWith<FullTreeDiskScratchException> {
                lease.requireCurrent(FullTreeDiskScratchStage.BEFORE_LAUNCH)
            }
            assertEquals(
                PosixFilePermissions.fromString("r--------"),
                Files.getPosixFilePermissions(lease.scratchParent.resolve("lease.json"), LinkOption.NOFOLLOW_LINKS),
            )
            assertFailsWith<FullTreeDiskScratchException> {
                FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(mount, operation("6"), policy)
            }
            val wrongRun = lease.scratchParent.resolve(".function-observation-run-${"7".repeat(64)}")
            Files.createDirectory(wrongRun)
            Files.setPosixFilePermissions(wrongRun, PosixFilePermissions.fromString("rwx------"))
            active = wrongRun
            assertFailsWith<FullTreeDiskScratchException> {
                lease.requireCurrent(FullTreeDiskScratchStage.BEFORE_LAUNCH)
            }
            Files.delete(wrongRun)
            active = null
            val run = lease.scratchParent.resolve(".function-observation-run-${operation.operationId}")
            Files.createDirectory(run)
            Files.setPosixFilePermissions(run, PosixFilePermissions.fromString("rwx------"))
            active = run
            lease.requireCurrent(FullTreeDiskScratchStage.BEFORE_LAUNCH)
            lease.requireCurrent(FullTreeDiskScratchStage.AFTER_SCOPE_ATTACHMENT)
            lease.requireCurrent(FullTreeDiskScratchStage.FROZEN_BARRIER)
            lease.requireCurrent(FullTreeDiskScratchStage.AFTER_CGROUP_ABSENCE)
            assertFailsWith<FullTreeDiskScratchException> {
                lease.requireCurrent(FullTreeDiskScratchStage.BEFORE_PUBLICATION)
            }
            requireInodeExhaustion(run, capacity.totalInodes)
            requireByteExhaustion(run, capacity.totalBytes)
            Files.delete(run)
            active = null
            lease.requireCurrent(FullTreeDiskScratchStage.BEFORE_PUBLICATION)
            lease.requireCurrent(FullTreeDiskScratchStage.AFTER_PUBLICATION)
            lease.requireCleanAndRelease()
            released = true
            assertTrue(Files.list(mount).use { it.findAny().isEmpty })
        } finally {
            active?.let(Files::deleteIfExists)
            if (!released) runCatching { lease.requireCleanAndRelease() }
            runCatching { lease.close() }
        }
    }

    @Test
    fun `closing a live ext4 lease preserves exact residue for cold recovery`() {
        val configured = System.getenv("DECOMP_TEST_ORACLE_EXT4_SCRATCH")
        assumeTrue(
            !configured.isNullOrBlank(),
            "set DECOMP_TEST_ORACLE_EXT4_SCRATCH for live lease abandonment coverage",
        )
        val mount = Path.of(configured).toAbsolutePath().normalize()
        val policy = FullTreeDiskScratchPolicy(
            requiredAvailableBytes = 1,
            maximumFilesystemBytes = EXPECTED_MAXIMUM_FILESYSTEM_BYTES,
            requiredAvailableInodes = 4,
            maximumFilesystemInodes = EXPECTED_MAXIMUM_FILESYSTEM_INODES,
        )

        listOf(false, true).forEach { activeRun ->
            val operation = operation(if (activeRun) "5" else "4")
            val leaseRoot = mount.resolve(".decomp-oracle-lease-${operation.operationId}")
            val recordPath = leaseRoot.resolve("lease.json")
            val runPath = leaseRoot.resolve(runDirectoryName(operation.operationId))
            var lease: FullTreeDiskScratchLease? = null
            try {
                assertTrue(Files.list(mount).use { it.findAny().isEmpty })
                val acquired = FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(
                    mount,
                    operation,
                    policy,
                )
                lease = acquired
                if (activeRun) {
                    Files.createDirectory(runPath)
                    Files.setPosixFilePermissions(runPath, PosixFilePermissions.fromString("rwx------"))
                    acquired.requireCurrent(FullTreeDiskScratchStage.BEFORE_LAUNCH)
                } else {
                    acquired.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
                }
                val expectedEvidence = acquired.evidence
                val recordBytes = Files.readAllBytes(recordPath)
                val expectedRecord = FullTreeDiskScratchLeaseRecord.parseCanonical(recordBytes)
                val mountNames = entryNames(mount)
                val leaseNames = entryNames(leaseRoot)

                assertFailsWith<FullTreeDiskScratchException> {
                    FullTreeDiskScratchAuthority.openExistingReadOnly(mount, operation, policy)
                }
                if (activeRun) {
                    acquired.close()
                    acquired.close()
                    acquired.abandonForRecovery()
                } else {
                    assertFailsWith<SimulatedLeaseUseFailure> {
                        acquired.use { throw SimulatedLeaseUseFailure() }
                    }
                    acquired.abandonForRecovery()
                    acquired.abandonForRecovery()
                    acquired.close()
                }

                assertFailsWith<IllegalStateException> {
                    acquired.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
                }
                assertFailsWith<IllegalStateException> {
                    acquired.requireCleanAndRelease()
                }
                assertEquals(mountNames, entryNames(mount))
                assertEquals(leaseNames, entryNames(leaseRoot))
                assertEquals(recordBytes.toList(), Files.readAllBytes(recordPath).toList())
                assertEquals(
                    expectedEvidence.canonicalBytes().toList(),
                    acquired.evidence.canonicalBytes().toList(),
                )

                FullTreeDiskScratchAuthority.openExistingReadOnly(mount, operation, policy).use { cold ->
                    val snapshot = cold.requireCurrent(expectedEvidence)
                    val expectedPopulation = if (activeRun) {
                        FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN
                    } else {
                        FullTreeDiskScratchColdPopulation.RECORD_ONLY
                    }
                    assertEquals(expectedEvidence.leaseRecordSha256, snapshot.leaseRecordSha256)
                    assertEquals(expectedRecord.recordSha256, snapshot.recordSelfSha256)
                    assertEquals(expectedPopulation, snapshot.population)
                    assertEquals(expectedPopulation, cold.requireCurrent(expectedEvidence).population)
                }

                assertEquals(mountNames, entryNames(mount))
                assertEquals(leaseNames, entryNames(leaseRoot))
                assertEquals(recordBytes.toList(), Files.readAllBytes(recordPath).toList())
                FullTreeDiskScratchAuthority.openExistingReadOnly(mount, operation, policy).close()
            } finally {
                runCatching { lease?.abandonForRecovery() }
                Files.deleteIfExists(runPath)
                Files.deleteIfExists(recordPath)
                Files.deleteIfExists(leaseRoot)
            }
        }
        assertTrue(Files.list(mount).use { it.findAny().isEmpty })
    }

    @Test
    fun `crashed ext4 lease can be cold opened without mutation or release`() {
        val configured = System.getenv("DECOMP_TEST_ORACLE_EXT4_SCRATCH")
        assumeTrue(
            !configured.isNullOrBlank(),
            "set DECOMP_TEST_ORACLE_EXT4_SCRATCH for cold lease integration coverage",
        )
        val mount = Path.of(configured).toAbsolutePath().normalize()
        val policy = FullTreeDiskScratchPolicy(
            requiredAvailableBytes = 1,
            maximumFilesystemBytes = EXPECTED_MAXIMUM_FILESYSTEM_BYTES,
            requiredAvailableInodes = 4,
            maximumFilesystemInodes = EXPECTED_MAXIMUM_FILESYSTEM_INODES,
        )

        listOf(false, true).forEachIndexed { index, activeRun ->
            val operation = operation(if (activeRun) "8" else "7")
            val leaseRoot = mount.resolve(".decomp-oracle-lease-${operation.operationId}")
            val recordPath = leaseRoot.resolve("lease.json")
            val runPath = leaseRoot.resolve(runDirectoryName(operation.operationId))
            try {
                assertTrue(Files.list(mount).use { it.findAny().isEmpty })
                val expectedEvidence = leaveCrashedLease(
                    mount,
                    operation,
                    activeRun,
                )
                val expectedRecordArtifactSha256 = expectedEvidence.leaseRecordSha256
                val recordBytes = Files.readAllBytes(recordPath)
                val residualCapacity = LinuxFilesystemSyscalls.openRoot(mount).use {
                    LinuxFilesystemSyscalls.filesystemCapacity(it)
                }
                val mountNames = entryNames(mount)
                val leaseNames = entryNames(leaseRoot)
                val observedPaths = buildList {
                    add(mount)
                    add(leaseRoot)
                    add(recordPath)
                    if (activeRun) add(runPath)
                }
                observedPaths.forEach { observed ->
                    Files.setAttribute(
                        observed,
                        "basic:lastAccessTime",
                        SENTINEL_ACCESS_TIME,
                        LinkOption.NOFOLLOW_LINKS,
                    )
                }

                assertEquals(expectedRecordArtifactSha256, sha256(recordBytes))
                assertTrue(
                    residualCapacity.availableInodes < expectedEvidence.initialAvailableInodes,
                    "cold disk-scratch availability must remain historical after lease artifacts consume inodes",
                )
                listOf(
                    operation.copy(requestSha256 = "a".repeat(64)),
                    operation.copy(shardId = "different-shard"),
                    operation.copy(scopeSha256 = "b".repeat(64)),
                ).forEach { mismatchedOperation ->
                    assertFailsWith<FullTreeDiskScratchException> {
                        FullTreeDiskScratchAuthority.openExistingReadOnly(
                            mount,
                            mismatchedOperation,
                            policy,
                        )
                    }
                    FullTreeDiskScratchAuthority.openExistingReadOnly(mount, operation, policy).close()
                }
                assertFailsWith<FullTreeDiskScratchException> {
                    FullTreeDiskScratchAuthority.openExistingReadOnly(
                        mount,
                        operation(if (activeRun) "a" else "b"),
                        policy,
                    )
                }
                assertEquals(mountNames, entryNames(mount))
                assertEquals(leaseNames, entryNames(leaseRoot))

                FullTreeDiskScratchAuthority.openExistingReadOnly(mount, operation, policy).use { cold ->
                    val leaseRecord = FullTreeDiskScratchLeaseRecord.parseCanonical(recordBytes)
                    assertNotEquals(expectedRecordArtifactSha256, leaseRecord.recordSha256)
                    val first = cold.requireCurrent(expectedEvidence)
                    val second = cold.requireCurrent(expectedEvidence)
                    val expectedPopulation = if (activeRun) {
                        FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN
                    } else {
                        FullTreeDiskScratchColdPopulation.RECORD_ONLY
                    }
                    assertEquals(expectedRecordArtifactSha256, first.leaseRecordSha256)
                    assertEquals(leaseRecord.recordSha256, first.recordSelfSha256)
                    assertEquals(expectedPopulation, first.population)
                    assertEquals(expectedPopulation, second.population)

                    listOf(
                        "initialAvailableBytes" to JsonPrimitive(
                            differentHistoricalAvailability(
                                expectedEvidence.initialAvailableBytes,
                                expectedEvidence.requiredAvailableBytes,
                                expectedEvidence.totalBytes,
                            ),
                        ),
                        "initialAvailableInodes" to JsonPrimitive(
                            differentHistoricalAvailability(
                                expectedEvidence.initialAvailableInodes,
                                expectedEvidence.requiredAvailableInodes,
                                expectedEvidence.totalInodes,
                            ),
                        ),
                    ).forEach { (field, value) ->
                        val alternateHistory = validMutatedEvidence(expectedEvidence, field, value)
                        assertEquals(expectedPopulation, cold.requireCurrent(alternateHistory).population)
                    }

                    val selfHashSubstitution = validMutatedEvidence(
                        expectedEvidence,
                        "leaseRecordSha256",
                        JsonPrimitive(leaseRecord.recordSha256),
                    )
                    assertFailsWith<FullTreeDiskScratchException> {
                        cold.requireCurrent(selfHashSubstitution)
                    }

                    val mismatches: List<Pair<String, JsonElement>> = buildList {
                        add("requestSha256" to JsonPrimitive("a".repeat(64)))
                        add("mountPathSha256" to JsonPrimitive("b".repeat(64)))
                        add("mountId" to JsonPrimitive(differentPositive(expectedEvidence.mountId)))
                        add(
                            "mountFlags" to JsonArray(
                                (expectedEvidence.mountFlags + "zztest").distinct().sorted().map(::JsonPrimitive),
                            ),
                        )
                        add("fragmentBytes" to JsonPrimitive(differentPositive(expectedEvidence.fragmentBytes)))
                        add("ownerUid" to JsonPrimitive(if (expectedEvidence.ownerUid == 0) 1 else 0))
                        add(
                            "maximumFilesystemBytes" to
                                JsonPrimitive(Math.addExact(expectedEvidence.maximumFilesystemBytes, 1L)),
                        )
                        add(
                            "leaseRootInode" to
                                JsonPrimitive(differentPositive(expectedEvidence.leaseRootInode)),
                        )
                    }
                    mismatches.forEach { (field, value) ->
                        val mismatch = validMutatedEvidence(expectedEvidence, field, value)
                        assertFailsWith<FullTreeDiskScratchException>(
                            "cold disk-scratch evidence accepted mismatched $field",
                        ) {
                            cold.requireCurrent(mismatch)
                        }
                    }

                    assertEquals(expectedPopulation, cold.requireCurrent(expectedEvidence).population)
                    assertFailsWith<FullTreeDiskScratchException> {
                        FullTreeDiskScratchAuthority.openExistingReadOnly(mount, operation, policy)
                    }
                    assertFailsWith<FullTreeDiskScratchException> {
                        FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(
                            mount,
                            operation(if (index == 0) "c" else "d"),
                            policy,
                        )
                    }
                }

                assertEquals(mountNames, entryNames(mount))
                assertEquals(leaseNames, entryNames(leaseRoot))
                observedPaths.forEach { observed ->
                    assertEquals(
                        SENTINEL_ACCESS_TIME,
                        Files.getAttribute(observed, "basic:lastAccessTime", LinkOption.NOFOLLOW_LINKS),
                        "cold inspection changed the access time of $observed",
                    )
                }
                assertEquals(recordBytes.toList(), Files.readAllBytes(recordPath).toList())
                FullTreeDiskScratchAuthority.openExistingReadOnly(mount, operation, policy).close()
                assertFailsWith<FullTreeDiskScratchException> {
                    FullTreeDiskScratchAuthority.openExistingReadOnly(
                        mount,
                        operation,
                        policy.copy(requiredAvailableBytes = 2),
                    )
                }
                FullTreeDiskScratchAuthority.openExistingReadOnly(mount, operation, policy).close()
                assertFailsWith<FullTreeDiskScratchException> {
                    FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(
                        mount,
                        operation(if (index == 0) "e" else "f"),
                        policy,
                    )
                }
                assertEquals(mountNames, entryNames(mount))
                assertEquals(leaseNames, entryNames(leaseRoot))
            } finally {
                Files.deleteIfExists(runPath)
                Files.deleteIfExists(recordPath)
                Files.deleteIfExists(leaseRoot)
            }
        }
        assertTrue(Files.list(mount).use { it.findAny().isEmpty })
    }

    private fun operation(seed: String = "1") = FullTreeDiskScratchOperation(
        operationId = seed.repeat(64),
        requestSha256 = "2".repeat(64),
        shardId = "clang-lib-driver",
        scopeSha256 = "3".repeat(64),
    )

    private fun leaveCrashedLease(
        mount: Path,
        operation: FullTreeDiskScratchOperation,
        activeRun: Boolean,
    ): FullTreeDiskScratchEvidence {
        val java = Path.of(System.getProperty("java.home"), "bin", "java")
        val process = ProcessBuilder(
            java.toString(),
            "-classpath",
            System.getProperty("java.class.path"),
            FullTreeDiskScratchCrashProbe::class.java.name,
            mount.toString(),
            operation.operationId,
            EXPECTED_MAXIMUM_FILESYSTEM_BYTES.toString(),
            EXPECTED_MAXIMUM_FILESYSTEM_INODES.toString(),
            activeRun.toString(),
        ).redirectErrorStream(true).start()
        val exited = process.waitFor(30, TimeUnit.SECONDS)
        if (!exited) {
            process.destroyForcibly()
            process.waitFor(5, TimeUnit.SECONDS)
        }
        assertTrue(exited, "crash-lease child process did not exit")
        val rawOutput = process.inputStream.readNBytes(64 * 1024 + 1).decodeToString()
        val output = rawOutput.removeSuffix("\n").removeSuffix("\r")
        assertEquals(0, process.exitValue(), output)
        assertTrue(output.matches(CRASH_EVIDENCE_OUTPUT), output)
        val encoded = output.removePrefix("READY:")
        val evidenceBytes = Base64.getDecoder().decode(encoded)
        assertEquals(encoded, Base64.getEncoder().encodeToString(evidenceBytes))
        return FullTreeDiskScratchEvidence.parseCanonical(evidenceBytes)
    }

    private fun entryNames(directory: Path): List<String> = Files.list(directory).use { entries ->
        entries.map { it.fileName.toString() }.sorted().toList()
    }

    private fun identity(device: Long, inode: Long, mountId: Long) = LinuxFileIdentity(
        key = LinuxFileKey(device, inode),
        mode = 0x41c0,
        uid = 1000,
        gid = 1000,
        linkCount = 2,
        mountId = mountId,
        isRegularFile = false,
        isDirectory = true,
        isSymbolicLink = false,
    )

    private fun sha256(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { byte -> "%02x".format(byte) }

    private class SimulatedLeaseUseFailure : RuntimeException()

    private fun leaseRecord(): FullTreeDiskScratchLeaseRecord = FullTreeDiskScratchLeaseRecord.create(
        operation = operation(),
        policy = FullTreeDiskScratchPolicy(
            requiredAvailableBytes = 1024,
            maximumFilesystemBytes = 8192,
            requiredAvailableInodes = 4,
            maximumFilesystemInodes = 64,
        ),
        mountPath = Path.of("/var/lib/decomp-scratch"),
        mount = FullTreeDiskMount(
            mountId = 42,
            parentMountId = 36,
            device = "7:1",
            root = Path.of("/"),
            mountPoint = Path.of("/var/lib/decomp-scratch"),
            options = listOf("noatime", "nodev", "noexec", "nosuid", "rw"),
            fileSystemType = "ext4",
        ),
        mountIdentity = identity(device = 7, inode = 2, mountId = 42),
        capacity = LinuxFilesystemCapacity(
            fragmentBytes = 4096,
            totalBytes = 8192,
            availableBytes = 4096,
            totalInodes = 64,
            availableInodes = 60,
            maximumNameBytes = 255,
            readOnly = false,
        ),
        leaseIdentity = identity(device = 7, inode = 12, mountId = 42),
    )

    private fun mutateRecord(
        record: FullTreeDiskScratchLeaseRecord,
        field: String,
        value: kotlinx.serialization.json.JsonElement,
    ): ByteArray {
        val root = OracleJson.parse(record.canonicalBytes()) as JsonObject
        val changed = root + (field to value)
        val selfHash = sha256(OracleJson.canonicalBytes(JsonObject(changed - "recordSha256")))
        return OracleJson.canonicalBytes(
            JsonObject(changed + ("recordSha256" to JsonPrimitive(selfHash))),
        )
    }

    private fun mutateEvidence(
        evidence: FullTreeDiskScratchEvidence,
        field: String,
        value: kotlinx.serialization.json.JsonElement,
    ): ByteArray {
        val root = OracleJson.parse(evidence.canonicalBytes()) as JsonObject
        val changed = root + (field to value)
        val selfHash = sha256(OracleJson.canonicalBytes(JsonObject(changed - "evidenceSha256")))
        return OracleJson.canonicalBytes(
            JsonObject(changed + ("evidenceSha256" to JsonPrimitive(selfHash))),
        )
    }

    private fun validMutatedEvidence(
        evidence: FullTreeDiskScratchEvidence,
        field: String,
        value: JsonElement,
    ): FullTreeDiskScratchEvidence = FullTreeDiskScratchEvidence.parseCanonical(
        mutateEvidence(evidence, field, value),
    )

    private fun differentPositive(value: Long): Long =
        if (value == Long.MAX_VALUE) value - 1L else value + 1L

    private fun differentHistoricalAvailability(value: Long, minimum: Long, total: Long): Long =
        if (value > minimum) value - 1L else Math.addExact(value, 1L).also { require(it <= total) }

    private fun requireByteExhaustion(run: Path, totalBytes: Long) {
        assumeTrue(totalBytes <= 128L * 1024 * 1024, "integration scratch is too large for exhaustion coverage")
        LinuxFilesystemSyscalls.openRoot(run).use { root ->
            val availableBefore = LinuxFilesystemSyscalls.filesystemCapacity(root).availableBytes
            try {
                val failure = assertFailsWith<LinuxSyscallException> {
                    LinuxFilesystemSyscalls.createRegularFile(root.fd, BYTE_EXHAUSTION_FILE, OWNER_FILE_MODE)
                        .use { target ->
                            val block = ByteArray(1024 * 1024)
                            var attempted = 0L
                            while (attempted <= totalBytes + block.size) {
                                LinuxFilesystemSyscalls.write(target, block) {}
                                attempted = Math.addExact(attempted, block.size.toLong())
                            }
                        }
                }
                assertEquals(LinuxFilesystemSyscalls.ENOSPC, failure.errno)
                val exhausted = LinuxFilesystemSyscalls.filesystemCapacity(root)
                assertTrue(
                    exhausted.availableBytes <= BYTE_EXHAUSTION_TOLERANCE_BYTES &&
                        exhausted.availableBytes < availableBefore,
                    "ext4 reported ENOSPC while retaining too much descriptor-pinned available capacity",
                )
            } finally {
                LinuxFilesystemSyscalls.unlinkIfPresent(root.fd, BYTE_EXHAUSTION_FILE)
                LinuxFilesystemSyscalls.synchronize(root)
            }
        }
    }

    private fun requireInodeExhaustion(run: Path, totalInodes: Long) {
        assumeTrue(totalInodes <= 8192L, "integration scratch has too many inodes for exhaustion coverage")
        LinuxFilesystemSyscalls.openRoot(run).use { root ->
            val availableBefore = LinuxFilesystemSyscalls.filesystemCapacity(root).availableInodes
            val created = ArrayList<String>()
            try {
                val failure = assertFailsWith<LinuxSyscallException> {
                    for (index in 0..totalInodes) {
                        val name = "inode-$index"
                        LinuxFilesystemSyscalls.createRegularFile(root.fd, name, OWNER_FILE_MODE).close()
                        created.add(name)
                    }
                }
                assertEquals(LinuxFilesystemSyscalls.ENOSPC, failure.errno)
                assertEquals(
                    0L,
                    LinuxFilesystemSyscalls.filesystemCapacity(root).availableInodes,
                    "ext4 reported ENOSPC before exhausting descriptor-pinned available inodes",
                )
            } finally {
                created.asReversed().forEach { LinuxFilesystemSyscalls.unlinkIfPresent(root.fd, it) }
                LinuxFilesystemSyscalls.synchronize(root)
            }
            assertEquals(
                availableBefore,
                LinuxFilesystemSyscalls.filesystemCapacity(root).availableInodes,
                "ext4 did not recover every inode consumed by the exhaustion probe",
            )
        }
    }

    private companion object {
        const val EXPECTED_MAXIMUM_FILESYSTEM_BYTES = 64L * 1024 * 1024
        const val EXPECTED_MAXIMUM_FILESYSTEM_INODES = 4096L
        const val BYTE_EXHAUSTION_TOLERANCE_BYTES = 4L * 1024 * 1024
        const val OWNER_FILE_MODE = 0x180 // 0600
        const val BYTE_EXHAUSTION_FILE = "byte-exhaustion"
        val CRASH_EVIDENCE_OUTPUT = Regex("READY:[A-Za-z0-9+/]+={0,2}")
        val SENTINEL_ACCESS_TIME: FileTime = FileTime.from(Instant.parse("2000-01-01T00:00:00Z"))
        const val FROZEN_EVIDENCE_SHA256 = "b9d2cce2265e1b35b2905baddd4d6b0fd4cd12bcbc3faab81490aad122faf2ec"
        const val FROZEN_EVIDENCE_ARTIFACT_SHA256 =
            "6f5799528a592a414fed2a5ee3ff0546d855a5096ac20dd0d12cf617a486243b"
        const val FROZEN_LEASE_RECORD_SHA256 =
            "9042ba47bacb9797df67400b884abc1dd71e78f589c39eb315b9d20c1dfc738d"
        const val FROZEN_LEASE_RECORD_ARTIFACT_SHA256 =
            "9922c89acc2a99b29e14f17501519d3138de425701c98a97c55d392672978f72"
    }
}
