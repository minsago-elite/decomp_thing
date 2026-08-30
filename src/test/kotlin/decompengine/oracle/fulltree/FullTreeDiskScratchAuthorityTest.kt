package decompengine.oracle.fulltree

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.acp.LinuxFilesystemCapacity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class FullTreeDiskScratchAuthorityTest {
    @Test
    fun `mountinfo parser preserves exact identities paths options and nesting`() {
        val mounts = parseFullTreeDiskMountTable(
            """
            36 25 0:31 / / rw,relatime - xfs /dev/root rw
            42 36 7:1 / /var/lib/decomp\040scratch rw,nosuid,nodev,noexec,relatime - ext4 /dev/loop0 rw
            43 42 0:44 / /var/lib/decomp\040scratch/nested rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=4096k
            """.trimIndent() + "\n",
        )

        assertEquals(3, mounts.size)
        assertEquals(42L, mounts[1].mountId)
        assertEquals(36L, mounts[1].parentMountId)
        assertEquals("7:1", mounts[1].device)
        assertEquals(Path.of("/"), mounts[1].root)
        assertEquals(Path.of("/var/lib/decomp scratch"), mounts[1].mountPoint)
        assertEquals(listOf("nodev", "noexec", "nosuid", "relatime", "rw"), mounts[1].options)
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
                options = listOf("nodev", "noexec", "nosuid", "relatime", "rw"),
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
                "rw,nodev,nosuid,noexec",
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
            assertTrue(Files.list(mount).use { it.findAny().isEmpty })
        } finally {
            active?.let(Files::deleteIfExists)
            runCatching { lease.close() }
        }
    }

    private fun operation(seed: String = "1") = FullTreeDiskScratchOperation(
        operationId = seed.repeat(64),
        requestSha256 = "2".repeat(64),
        shardId = "clang-lib-driver",
        scopeSha256 = "3".repeat(64),
    )

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
        const val FROZEN_EVIDENCE_SHA256 = "5785e1afe93bda94698b7a6b888954388e39c3d40b10fc85c7e508f73b4205e9"
        const val FROZEN_EVIDENCE_ARTIFACT_SHA256 =
            "601758c6ebfd9eebec6ee46c73f8f215e09fea36ae53bb37bb68d4ba62b7d880"
    }
}
