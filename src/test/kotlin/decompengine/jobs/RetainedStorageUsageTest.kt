package decompengine.jobs

import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.WRITE
import kotlin.io.path.createTempDirectory
import kotlin.test.*

class RetainedStorageUsageTest {
    @Test fun `counts binaries reports metadata hidden files and directory sizes without changing contents`() = withRoot { root ->
        val job = Files.createDirectory(root.resolve("job"))
        val reports = Files.createDirectories(job.resolve("reports/runs/attempt"))
        val files = listOf(job.resolve("input.elf"), job.resolve("job.json"), job.resolve("upload-receipt.json"),
            job.resolve(".job-metadata-old.tmp"), reports.resolve("result.json"), root.resolve(".owner"))
        files.forEachIndexed { index, file -> Files.write(file, ByteArray(index + 1) { index.toByte() }) }
        val before = files.associateWith(Files::readAllBytes)
        val all = Files.walk(root).use { paths -> paths.filter { it != root }.toList() }
        val usage = RetainedStorageUsage.measure(root, Long.MAX_VALUE)
        assertEquals(all.sumOf(Files::size), usage.logicalBytes)
        assertEquals(all.size, usage.entries)
        before.forEach { (file, content) -> assertContentEquals(content, Files.readAllBytes(file)) }
        assertEquals(usage, RetainedStorageUsage.measure(root, usage.logicalBytes))
        assertUnavailable { RetainedStorageUsage.measure(root, usage.logicalBytes - 1) }
    }

    @Test fun `sparse files are charged by logical length and hard links by each name`() = withRoot { root ->
        val sparse = Files.createFile(root.resolve("sparse"))
        FileChannel.open(sparse, WRITE).use { file ->
            file.position(16L * 1024 * 1024 - 1)
            file.write(java.nio.ByteBuffer.wrap(byteArrayOf(1)))
        }
        Files.createLink(root.resolve("alias"), sparse)
        assertEquals(32L * 1024 * 1024, RetainedStorageUsage.measure(root, Long.MAX_VALUE).logicalBytes)
        assertUnavailable { RetainedStorageUsage.measure(root, 16L * 1024 * 1024) }
    }

    @Test fun `links are rejected without reading targets`() = withRoot { root ->
        Files.createSymbolicLink(root.resolve("link"), root.resolve("missing"))
        assertUnavailable { RetainedStorageUsage.measure(root, Long.MAX_VALUE) }
        assertTrue(Files.isSymbolicLink(root.resolve("link")))
    }

    @Test fun `entry depth deadline and cancellation budgets fail closed`() = withRoot { root ->
        Files.createDirectories(root.resolve("one/two"))
        assertUnavailable { RetainedStorageUsage.measure(root, Long.MAX_VALUE, maximumEntries = 1) }
        assertUnavailable { RetainedStorageUsage.measure(root, Long.MAX_VALUE, maximumDepth = 1) }
        assertEquals(2, RetainedStorageUsage.measure(root, Long.MAX_VALUE, maximumEntries = 2).entries)
        var time = 0L
        assertUnavailable { RetainedStorageUsage.measure(root, Long.MAX_VALUE, maximumNanos = 2, nanoTime = { time++ }) }
        Thread.currentThread().interrupt()
        try {
            assertUnavailable { RetainedStorageUsage.measure(root, Long.MAX_VALUE) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    private fun assertUnavailable(action: () -> Unit) {
        assertEquals("STORAGE_ACCOUNTING_UNAVAILABLE", assertFailsWith<WorkflowStoreException>(block = action).code)
    }

    private fun withRoot(action: (Path) -> Unit) {
        val root = createTempDirectory("retained-storage-")
        try { action(root) } finally { root.toFile().deleteRecursively() }
    }
}
