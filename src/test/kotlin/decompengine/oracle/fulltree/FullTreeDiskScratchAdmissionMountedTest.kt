package decompengine.oracle.fulltree

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag

/** Actual kernel mount controls for admission; JSON mutations are covered separately. */
@Tag("ci-live")
class FullTreeDiskScratchAdmissionMountedTest {
    @Test
    fun `mounted exact ext4 root pins capacity and rejects a second lock`() = withFixture { fixture ->
        LinuxFilesystemSyscalls.openRoot(fixture.scratch).use { pinned ->
            val capacity = LinuxFilesystemSyscalls.filesystemCapacity(pinned)
            assertTrue(capacity.totalBytes in 1..MAXIMUM_BYTES)
            assertTrue(capacity.totalInodes in 4..MAXIMUM_INODES)
            assertTrue(!capacity.readOnly)
            // Refuse on the lock itself while the mount is still empty: recovery-required
            // residue must not be able to mask a missing acquisition lock check.
            assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(pinned))
            try {
                refuseWithoutMutation(fixture.scratch, expectedMessage = ALREADY_LEASED)
            } finally {
                LinuxFilesystemSyscalls.unlock(pinned)
            }
            val lease = acquire(fixture.scratch)
            try {
                lease.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
                assertEquals(pinned.identity.mountId, lease.evidence.mountId)
                assertEquals(pinned.identity.key.device, lease.evidence.device)
                assertEquals(pinned.identity.key.inode, lease.evidence.rootInode)
                assertEquals(capacity.totalBytes, lease.evidence.totalBytes)
                assertEquals(capacity.totalInodes, lease.evidence.totalInodes)
                assertEquals(capacity.availableBytes, lease.evidence.initialAvailableBytes)
                assertEquals(capacity.availableInodes, lease.evidence.initialAvailableInodes)
                // An independent open file description must conflict with the live lease,
                // even though its lease directory would also prevent another acquisition.
                val acquired = LinuxFilesystemSyscalls.tryExclusiveLock(pinned)
                try {
                    assertTrue(!acquired, "production lease did not retain its exclusive mount lock")
                } finally {
                    if (acquired) LinuxFilesystemSyscalls.unlock(pinned)
                }
                refuseWithoutMutation(fixture.scratch, expectedMessage = ALREADY_LEASED)
                assertSameObject(pinned.identity, LinuxFilesystemSyscalls.identity(pinned.fd))
            } finally {
                lease.requireCleanAndRelease()
            }
        }
        assertTrue(entryNames(fixture.scratch).isEmpty())
    }

    @Test
    fun `mounted ext4 total byte maximum is enforced`() = withFixture { fixture ->
        val capacity = fixture.capacity()
        refuseWithoutMutation(fixture.scratch, POLICY.copy(maximumFilesystemBytes = capacity.totalBytes - 1))
    }

    @Test
    fun `mounted ext4 total inode maximum is enforced`() = withFixture { fixture ->
        val capacity = fixture.capacity()
        refuseWithoutMutation(fixture.scratch, POLICY.copy(maximumFilesystemInodes = capacity.totalInodes - 1))
    }

    @Test
    fun `mounted ext4 available byte minimum is enforced`() = withFixture { fixture ->
        val capacity = fixture.capacity()
        assertTrue(capacity.availableBytes < capacity.totalBytes)
        refuseWithoutMutation(fixture.scratch, POLICY.copy(requiredAvailableBytes = capacity.availableBytes + 1))
    }

    @Test
    fun `mounted ext4 available inode minimum is enforced`() = withFixture { fixture ->
        val capacity = fixture.capacity()
        assertTrue(capacity.availableInodes < capacity.totalInodes)
        refuseWithoutMutation(fixture.scratch, POLICY.copy(requiredAvailableInodes = capacity.availableInodes + 1))
    }

    @Test
    fun `mounted ext4 without nodev is refused`() = refuseChangedMount("missing-nodev")

    @Test
    fun `mounted ext4 without nosuid is refused`() = refuseChangedMount("missing-nosuid")

    @Test
    fun `mounted ext4 without noexec is refused`() = refuseChangedMount("missing-noexec")

    @Test
    fun `mounted ext4 without noatime is refused`() = refuseChangedMount("missing-noatime")

    @Test
    fun `mounted read only ext4 is refused`() = refuseChangedMount("readonly")

    @Test
    fun `mounted tmpfs is refused`() = refuseChangedMount("tmpfs")

    @Test
    fun `mounted nested filesystem is refused`() = refuseChangedMount("nested")

    @Test
    fun `mounted bind subtree is refused`() = withFixture { fixture ->
        fixture.change("bind-subtree")
        val subtreeMount = mountedAt(fixture.subtree)
        assertEquals("ext4", subtreeMount.fileSystemType)
        assertNotEquals(Path.of("/"), subtreeMount.root)
        refuseWithoutMutation(fixture.subtree)
    }

    @Test
    fun `mounted visible same device alias is refused`() = refuseChangedMount("bind-alias")

    @Test
    fun `mounted root owned by another user is refused`() = withFixture { fixture ->
        fixture.change("wrong-owner")
        assertEquals(0, Files.getAttribute(fixture.scratch, "unix:uid", LinkOption.NOFOLLOW_LINKS))
        assertFailsWith<FullTreeDiskScratchException> { acquire(fixture.scratch) }
    }

    @Test
    fun `mounted root with permissive mode is refused`() = withFixture { fixture ->
        val identity = identity(fixture.scratch)
        try {
            Files.setPosixFilePermissions(fixture.scratch, PosixFilePermissions.fromString("rwxr-xr-x"))
            refuseWithoutMutation(fixture.scratch)
        } finally {
            assertSameObject(identity, identity(fixture.scratch))
            Files.setPosixFilePermissions(fixture.scratch, PosixFilePermissions.fromString("rwx------"))
        }
    }

    @Test
    fun `mounted ordinary subdirectory and symlink are refused without changing alien canary`() = withFixture { fixture ->
        val directory = Files.createDirectory(fixture.scratch.resolve("admission-owned-directory"))
        val canary = Files.writeString(directory.resolve("alien-canary"), "retain unrelated directory state\n")
        val expectedCanary = Files.readAllBytes(canary)
        val directoryIdentity = identity(directory)
        val canaryIdentity = Files.readAttributes(canary, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS)
        val link = fixture.evidenceRoot.resolve("admission-owned-symlink")
        assertTrue(!Files.exists(link, LinkOption.NOFOLLOW_LINKS))
        Files.createSymbolicLink(link, fixture.scratch)
        try {
            refuseWithoutMutation(directory)
            assertFailsWith<FullTreeDiskScratchException> { acquire(link) }
            assertEquals(expectedCanary.toList(), Files.readAllBytes(canary).toList())
            assertEquals(canaryIdentity, Files.readAttributes(canary, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS))
            assertEquals(fixture.scratch, Files.readSymbolicLink(link))
        } finally {
            assertEquals(fixture.scratch, Files.readSymbolicLink(link))
            Files.delete(link)
            assertSameObject(directoryIdentity, identity(directory))
            assertEquals(canaryIdentity, Files.readAttributes(canary, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS))
            assertEquals(expectedCanary.toList(), Files.readAllBytes(canary).toList())
            Files.delete(canary)
            Files.delete(directory)
        }
    }

    @Test
    fun `mounted replacement refuses stale lease release and preserves both filesystems`() = withFixture { fixture ->
        val lease = acquire(fixture.scratch)
        val leaseName = lease.scratchParent.fileName.toString()
        val leaseIdentity = identity(lease.scratchParent)
        val record = lease.scratchParent.resolve("lease.json")
        val recordIdentity = Files.readAttributes(record, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS)
        val recordBytes = Files.readAllBytes(record)
        val originalMount = identity(fixture.scratch)
        var restored = false
        try {
            fixture.change("replace-root")
            assertNotEquals(originalMount.mountId, identity(fixture.scratch).mountId)
            assertSameObject(originalMount, identity(fixture.retained))
            fixture.assertReplacementCanary(atScratch = true)
            assertFailsWith<FullTreeDiskScratchException> { lease.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED) }
            assertFailsWith<FullTreeDiskScratchException> { lease.requireCleanAndRelease() }
            fixture.assertReplacementCanary(atScratch = true)
            val retainedRecord = fixture.retained.resolve(leaseName).resolve("lease.json")
            assertEquals(recordIdentity, Files.readAttributes(retainedRecord, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS))
            assertEquals(recordBytes.toList(), Files.readAllBytes(retainedRecord).toList())
            fixture.restore()
            restored = true
            assertEquals(originalMount, identity(fixture.scratch))
            fixture.assertReplacementCanary(atScratch = false)
        } finally {
            lease.close()
            if (!restored) fixture.restore()
            // The failed release deliberately retained this test's own record. Authenticate its
            // original mount, directory and bytes before removing only those exact two entries.
            assertEquals(originalMount, identity(fixture.scratch))
            assertEquals(leaseIdentity, identity(lease.scratchParent))
            assertEquals(listOf("lease.json"), entryNames(lease.scratchParent))
            assertEquals(recordIdentity, Files.readAttributes(record, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS))
            assertEquals(recordBytes.toList(), Files.readAllBytes(record).toList())
            Files.delete(record)
            Files.delete(lease.scratchParent)
        }
    }

    private fun refuseChangedMount(action: String) = withFixture { fixture ->
        fixture.change(action)
        val mount = mountedAt(fixture.scratch)
        when (action) {
            "missing-nodev", "missing-nosuid", "missing-noexec", "missing-noatime" -> {
                val absent = action.removePrefix("missing-")
                assertEquals("ext4", mount.fileSystemType)
                assertTrue(absent !in mount.options)
                assertTrue(mount.options.containsAll(REQUIRED_FLAGS - absent))
            }
            "readonly" -> {
                assertEquals("ext4", mount.fileSystemType)
                assertTrue("ro" in mount.options && "rw" !in mount.options)
                assertTrue(fixture.capacity().readOnly)
            }
            "tmpfs" -> assertEquals("tmpfs", mount.fileSystemType)
            "nested" -> assertTrue(mounts().any {
                it.mountPoint != fixture.scratch && it.mountPoint.startsWith(fixture.scratch) && it.fileSystemType == "tmpfs"
            })
            "bind-alias" -> assertTrue(mounts().any {
                it.mountId != mount.mountId && it.device == mount.device && it.mountPoint == fixture.scratch.parent.resolve("alias")
            })
            else -> error("unexpected mounted control $action")
        }
        refuseWithoutMutation(
            fixture.scratch,
            // A nested mount necessarily introduces a directory. Do not credit the later
            // nonempty-filesystem recovery refusal if nested-mount validation is bypassed.
            expectedMessage = if (action == "nested") CONTAINS_NESTED_MOUNT else null,
        )
    }

    private fun refuseWithoutMutation(
        path: Path,
        policy: FullTreeDiskScratchPolicy = POLICY,
        expectedMessage: String? = null,
    ) {
        val beforeIdentity = identity(path)
        val beforeNames = entryNames(path)
        val failure = assertFailsWith<FullTreeDiskScratchException> { acquire(path, policy) }
        expectedMessage?.let { assertEquals(it, failure.message, "wrong admission predicate refused the control") }
        assertEquals(beforeIdentity, identity(path))
        assertEquals(beforeNames, entryNames(path))
    }

    private fun acquire(path: Path, policy: FullTreeDiskScratchPolicy = POLICY) =
        FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(path, OPERATION, policy)

    private fun withFixture(block: (Fixture) -> Unit) {
        val configured = System.getenv("DECOMP_TEST_ORACLE_EXT4_ADMISSION_SCRATCH")
        val helper = System.getenv("DECOMP_TEST_ORACLE_EXT4_ADMISSION_HELPER")
        if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_ADMISSION") == "true") {
            assertTrue(!configured.isNullOrBlank() && !helper.isNullOrBlank(), "required hosted mount-admission fixture missing")
        }
        assumeTrue(!configured.isNullOrBlank() && !helper.isNullOrBlank(), "requires the dedicated hosted mount-admission fixture")
        val fixture = Fixture(Path.of(configured), Path.of(helper))
        fixture.inspect()
        assertTrue(identity(fixture.scratch).uid != 0, "the admission caller must be the unprivileged fixture owner")
        assertTrue(entryNames(fixture.scratch).isEmpty())
        try {
            block(fixture)
        } finally {
            fixture.restore()
            fixture.inspect()
            fixture.assertReplacementCanary(atScratch = false)
            assertTrue(entryNames(fixture.scratch).isEmpty())
        }
    }

    private class Fixture(val scratch: Path, private val helper: Path) {
        val evidenceRoot: Path = Path.of("build/issue930-evidence").toAbsolutePath().normalize().also(Files::createDirectories)
        private val parent = scratch.parent
        val subtree: Path = parent.resolve("subtree")
        val retained: Path = parent.resolve("retained")
        private val replacement = parent.resolve("replacement")
        private var canaryName: String? = null
        private var canaryContent: String? = null

        init {
            assertEquals(Path.of("/var/lib/decomp-oracle-ext4-admission-ci/scratch"), scratch)
            assertEquals(Path.of("scripts/ci-oracle-ext4-admission.py").toAbsolutePath().normalize(), helper)
            assertEquals(helper, helper.toRealPath())
        }

        fun capacity() = LinuxFilesystemSyscalls.openRoot(scratch).use(LinuxFilesystemSyscalls::filesystemCapacity)
        fun inspect() { action("inspect") }
        fun change(name: String) { action(name) }
        fun restore() { action("restore") }

        fun assertReplacementCanary(atScratch: Boolean) {
            val path = (if (atScratch) scratch else replacement).resolve(checkNotNull(canaryName))
            assertTrue(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
            assertEquals(checkNotNull(canaryContent), Files.readString(path))
        }

        private fun action(name: String) {
            val output = Files.createTempFile(evidenceRoot, "$name-", ".json")
            val error = Files.createTempFile(evidenceRoot, "$name-", ".stderr")
            val process = ProcessBuilder("sudo", "-n", "python3", "-I", "-S", helper.toString(), name)
                .redirectOutput(output.toFile()).redirectError(error.toFile()).start()
            val exited = process.waitFor(45, TimeUnit.SECONDS)
            if (!exited) {
                process.destroyForcibly()
                process.waitFor(5, TimeUnit.SECONDS)
            }
            assertTrue(exited, "finite fixture action $name timed out")
            assertTrue(Files.size(output) <= 32 * 1024 && Files.size(error) <= 32 * 1024)
            assertEquals(0, process.exitValue(), "fixture $name failed: ${Files.readString(error)}")
            val report = Json.parseToJsonElement(Files.readString(output)).jsonObject
            assertEquals(scratch.toString(), report.getValue("scratch").jsonPrimitive.content)
            assertEquals(subtree.toString(), report.getValue("subtree").jsonPrimitive.content)
            assertEquals(retained.toString(), report.getValue("retained").jsonPrimitive.content)
            assertEquals(replacement.toString(), report.getValue("replacement").jsonPrimitive.content)
            val canary = Path.of(report.getValue("canary").jsonPrimitive.content)
            assertTrue(canary.parent == scratch || canary.parent == replacement)
            val content = report.getValue("canaryContent").jsonPrimitive.content
            assertTrue(content.isNotBlank() && content.length < 256)
            canaryName?.let { assertEquals(it, canary.fileName.toString()) }
            canaryContent?.let { assertEquals(it, content) }
            canaryName = canary.fileName.toString()
            canaryContent = content
        }
    }

    companion object {
        private const val MAXIMUM_BYTES = 64L * 1024 * 1024
        private const val MAXIMUM_INODES = 4096L
        private const val ALREADY_LEASED = "dedicated disk-scratch filesystem is already leased"
        private const val CONTAINS_NESTED_MOUNT = "dedicated disk-scratch filesystem contains a nested mount"
        private val POLICY = FullTreeDiskScratchPolicy(1, MAXIMUM_BYTES, 4, MAXIMUM_INODES)
        private val OPERATION = FullTreeDiskScratchOperation("9".repeat(64), "2".repeat(64), "clang-lib-driver", "3".repeat(64))
        private val REQUIRED_FLAGS = setOf("rw", "nodev", "nosuid", "noexec", "noatime")

        private fun mounts() = parseFullTreeDiskMountTable(Files.readString(Path.of("/proc/self/mountinfo")))
        private fun mountedAt(path: Path): FullTreeDiskMount {
            val mountId = identity(path).mountId
            return mounts().single { it.mountId == mountId && it.mountPoint == path }
        }
        private fun identity(path: Path) = LinuxFilesystemSyscalls.openRoot(path).use { LinuxFilesystemSyscalls.identity(it.fd) }
        private fun entryNames(path: Path): List<String> = Files.list(path).use { it.map { entry -> entry.fileName.toString() }.sorted().toList() }
        private fun assertSameObject(expected: LinuxFileIdentity, actual: LinuxFileIdentity) {
            assertEquals(expected.key, actual.key)
            assertEquals(expected.mountId, actual.mountId)
        }
    }
}
