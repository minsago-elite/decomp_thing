package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import decompengine.oracle.core.DescriptorBoundStateFaultPoint
import decompengine.oracle.fulltree.ContainedCommandOperationDeadline
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class GccBundledDeadlineBoundPublicationTest {
    @Test
    fun `current deadline publishes exactly one owner-only result without staging residue`() = fixture { root ->
        val clock = Clock()
        var checks = 0
        val published = publish(root, clock.deadline(), afterCommit = { checks++ })
        assertContentEquals(BYTES, published.bytes)
        assertContentEquals(BYTES, Files.readAllBytes(root.resolve(NAME)))
        assertEquals("r--------", PosixFilePermissions.toString(Files.getPosixFilePermissions(root.resolve(NAME))))
        assertEquals(setOf(NAME), entries(root))
        assertEquals(1, checks)
    }

    @Test
    fun `expiry at every staging and commit point leaves no result and no staging residue`() {
        for (point in DescriptorBoundStateFaultPoint.entries) fixture { root ->
            val clock = Clock()
            val failure = assertFailsWith<Throwable>(point.name) {
                publish(root, clock.deadline(), fault = { hit -> if (hit == point) clock.expire() })
            }
            if (point == DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_DIRECTORY_SYNC) {
                assertTrue(failure.message.orEmpty().contains("deadline"), failure.toString())
            }
            assertEquals(emptySet(), entries(root), point.name)
        }
    }

    @Test
    fun `a rename that returns after expiry is revoked instead of published`() = fixture { root ->
        val clock = Clock()
        val failure = assertFailsWith<java.io.IOException> {
            publish(root, clock.deadline(), fault = { hit ->
                if (hit == DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_RENAME) {
                    assertTrue(Files.exists(root.resolve(NAME)), "the rename has committed before its late return")
                    clock.expire()
                }
            })
        }
        assertTrue(failure.message.orEmpty().contains("outside its admission"), failure.toString())
        assertEquals(emptySet(), entries(root))
    }

    @Test
    fun `commit is refused without its reserve and every post-commit failure revokes the result`() {
        fixture { root ->
            val clock = Clock()
            val failure = assertFailsWith<IllegalStateException> {
                publish(root, clock.deadline(), fault = { hit ->
                    if (hit == DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC) clock.now = 1_500_000_000L
                })
            }
            assertTrue(failure.message.orEmpty().contains("requires 1000 ms"), failure.toString())
            assertEquals(emptySet(), entries(root))
        }
        fixture { root ->
            val clock = Clock()
            assertFailsWith<IllegalStateException> { publish(root, clock.deadline(), afterCommit = { clock.expire() }) }
            assertEquals(emptySet(), entries(root))
        }
        fixture { root ->
            val failure = assertFailsWith<IllegalArgumentException> {
                publish(root, Clock().deadline(), afterCommit = { throw IllegalArgumentException("inputs changed") })
            }
            assertEquals("inputs changed", failure.message)
            assertEquals(emptySet(), entries(root))
        }
    }

    @Test
    fun `blocked staging and a blocked rename return bounded failures and their owned steps leave nothing`() {
        for (point in listOf(DescriptorBoundStateFaultPoint.AFTER_UNNAMED_FILE_SYNC, DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_RENAME)) {
            fixture { root ->
                val tracker = GccBundledHostWorkTracker()
                val blocked = CountDownLatch(1)
                val release = CountDownLatch(1)
                val started = System.nanoTime()
                assertFailsWith<GccBundledHostWorkTimeoutException>(point.name) {
                    publish(root, Clock().deadline(), tracker = tracker, fault = { hit ->
                        if (hit == point) { blocked.countDown(); awaitIgnoringInterrupts(release) }
                    })
                }
                val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
                assertTrue(blocked.count == 0L && elapsedMillis in 2_000..12_000, "${point.name}: $elapsedMillis ms")
                assertEquals(listOf("result publication"), tracker.inFlightStages, point.name)
                release.countDown()
                tracker.requireRetired(10_000)
                assertEquals(emptySet(), entries(root), point.name)
            }
        }
    }

    @Test
    fun `existing results and residue are refused and left untouched`() {
        for (existing in listOf(NAME, ".$NAME.atomic")) fixture { root ->
            Files.write(root.resolve(existing), byteArrayOf(1))
            assertFailsWith<java.io.IOException>(existing) { publish(root, Clock().deadline()) }
            assertEquals(setOf(existing), entries(root))
            assertContentEquals(byteArrayOf(1), Files.readAllBytes(root.resolve(existing)))
        }
    }

    private class Clock {
        var now = 0L
        fun deadline() = ContainedCommandOperationDeadline(2_000) { now }
        fun expire() { now = 2_000_000_000L }
    }

    private fun publish(
        root: Path,
        deadline: ContainedCommandOperationDeadline,
        tracker: GccBundledHostWorkTracker = GccBundledHostWorkTracker(),
        afterCommit: () -> Unit = {},
        fault: (DescriptorBoundStateFaultPoint) -> Unit = {},
    ) = LinuxFilesystemSyscalls.openRoot(root).use { parent ->
        GccBundledDeadlineBoundPublication.publish(tracker, parent, NAME, BYTES, 1024, deadline,
            DescriptorBoundStateFaultInjector { fault(it) }, afterCommit)
    }.also { tracker.requireRetired(10_000) }

    private fun awaitIgnoringInterrupts(latch: CountDownLatch) {
        while (true) {
            try { if (latch.await(10, TimeUnit.SECONDS)) return } catch (_: InterruptedException) { }
        }
    }

    private fun entries(root: Path): Set<String> = Files.list(root).use { paths -> paths.map { it.fileName.toString() }.toList().toSet() }

    private fun fixture(action: (Path) -> Unit) {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val root = Files.createTempDirectory(scratch, "gcc-result-publication-").toRealPath()
        try {
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
            action(root)
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private companion object {
        const val NAME = "result.json"
        val BYTES = "{\"complete\":false}\n".toByteArray()
    }
}
