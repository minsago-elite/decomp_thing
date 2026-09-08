package decompengine.jobs

import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JobRecoveryInventoryTest {
    @Test
    fun `inventory counts retained candidates without reading or changing published data`() {
        val root = createTempDirectory("recovery-inventory-")
        val store = JobStore(root)
        val job = store.createFromUpload("input.elf", elfFixture())
        val before = job.binaryPath.readBytes()
        val temporary = job.binaryPath.parent.resolve(".job-metadata-private.tmp")
        temporary.writeBytes(ByteArray(3))
        val stage = Files.createDirectory(root.resolve(".upload-private"))
        stage.resolve("input.elf").writeBytes(ByteArray(5))
        stage.resolve("job.json").writeBytes(ByteArray(2))
        val reports = Files.createDirectory(job.binaryPath.parent.resolve("reports"))
        reports.resolve(".job-metadata-not-a-candidate").writeBytes(ByteArray(100))

        val inventory = store.recoveryInventory()
        assertTrue(inventory.inventoryComplete)
        assertEquals(1, inventory.retainedUploadStages)
        assertEquals(1, inventory.retainedMetadataFiles)
        assertEquals(10L, inventory.observedBytes)
        assertEquals(0, inventory.uninspectedEntries)
        assertContentEquals(before, job.binaryPath.readBytes())
        assertTrue(Files.exists(temporary))
        assertTrue(Files.exists(stage.resolve("job.json")))
        assertEquals(job, store.get(job.id))
    }

    @Test
    fun `symlinks and unknown nested layouts are retained without traversal`() {
        val root = createTempDirectory("recovery-links-")
        val outside = createTempDirectory("recovery-outside-")
        val secret = outside.resolve("secret")
        secret.writeBytes(ByteArray(40))
        Files.createSymbolicLink(root.resolve(".upload-link"), outside)
        val job = Files.createDirectory(root.resolve("a".repeat(32)))
        Files.createSymbolicLink(job.resolve(".job-metadata-link"), secret)
        val stage = Files.createDirectory(root.resolve(".upload-nested"))
        Files.createDirectory(stage.resolve("unknown")).resolve("secret").writeBytes(ByteArray(30))
        val inventory = inspectJobRecoveryInventory(root)
        assertFalse(inventory.inventoryComplete)
        assertEquals(3, inventory.uninspectedEntries)
        assertEquals(0L, inventory.observedBytes)
        assertEquals(1, inventory.retainedUploadStages)
        assertEquals(0, inventory.retainedMetadataFiles)
        assertEquals(40, secret.readBytes().size)
        assertTrue(Files.isSymbolicLink(root.resolve(".upload-link")))
    }

    @Test
    fun `entry budget charges unrelated files too`() {
        val root = createTempDirectory("recovery-entries-")
        repeat(10) { root.resolve("unrelated-$it").writeBytes(byteArrayOf()) }
        val inventory = inspectJobRecoveryInventory(root, maximumEntries = 4)
        assertEquals(4, inventory.scannedEntries)
        assertFalse(inventory.inventoryComplete)
    }

    @Test
    fun `candidate budget retains uninspected candidates`() {
        val root = createTempDirectory("recovery-candidates-")
        repeat(3) { Files.createDirectory(root.resolve(".upload-$it")) }
        val inventory = inspectJobRecoveryInventory(root, maximumCandidates = 2)
        assertEquals(2, inventory.retainedUploadStages)
        assertFalse(inventory.inventoryComplete)
        Files.list(root).use { assertEquals(3L, it.count()) }
    }

    @Test
    fun `byte budget reports an incomplete lower bound without opening content`() {
        val root = createTempDirectory("recovery-bytes-")
        val stage = Files.createDirectory(root.resolve(".upload-large"))
        val input = stage.resolve("input.elf")
        input.writeBytes(ByteArray(6))
        val inventory = inspectJobRecoveryInventory(root, maximumBytes = 5)
        assertFalse(inventory.inventoryComplete)
        assertEquals(0L, inventory.observedBytes)
        assertEquals(6L, Files.size(input))
    }

    @Test
    fun `missing store is empty and is not created by inspection`() {
        val root = createTempDirectory("recovery-missing-").resolve("missing")
        assertEquals(JobRecoveryInventory(0, 0, 0, 0, 0, true), inspectJobRecoveryInventory(root))
        assertFalse(Files.exists(root))
    }
}
