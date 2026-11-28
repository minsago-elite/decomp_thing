package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundCommitFaultInjector
import decompengine.oracle.core.DescriptorBoundCommitFaultPoint
import decompengine.oracle.fulltree.ContainedCommandOperationDeadline
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
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
        val published = publish(root, Clock().deadline())
        assertContentEquals(BYTES, published.bytes)
        assertContentEquals(BYTES, Files.readAllBytes(root.resolve(NAME)))
        assertEquals("r--------", PosixFilePermissions.toString(Files.getPosixFilePermissions(root.resolve(NAME))))
        assertEquals(setOf(NAME), entries(root))
    }

    @Test
    fun `expiry at every preparation and commit point leaves no result and no staging residue`() {
        val points = DescriptorBoundCommitFaultPoint.entries - DescriptorBoundCommitFaultPoint.BEFORE_REVOCATION
        for (point in points) fixture { root ->
            val clock = Clock()
            assertFailsWith<Throwable>(point.name) { publish(root, clock.deadline(), fault = { hit -> if (hit == point) clock.expire() }) }
            assertEquals(emptySet(), entries(root), point.name)
        }
    }

    @Test
    fun `a commit link that returns after expiry is revoked instead of published`() = fixture { root ->
        val clock = Clock()
        val failure = assertFailsWith<java.io.IOException> {
            publish(root, clock.deadline(), fault = { hit ->
                if (hit == DescriptorBoundCommitFaultPoint.AFTER_COMMIT) {
                    assertTrue(Files.exists(root.resolve(NAME)), "the link has committed before its late return")
                    clock.expire()
                }
            })
        }
        assertTrue(failure.message.orEmpty().contains("outside its admission"), failure.toString())
        assertEquals(emptySet(), entries(root))
    }

    @Test
    fun `commit is refused without its reserve`() = fixture { root ->
        val clock = Clock()
        val failure = assertFailsWith<IllegalStateException> {
            publish(root, clock.deadline(), fault = { hit ->
                if (hit == DescriptorBoundCommitFaultPoint.AFTER_PREPARED_SYNC) clock.leave(500)
            })
        }
        assertTrue(failure.message.orEmpty().contains("requires 1000 ms"), failure.toString())
        assertEquals(emptySet(), entries(root))
    }

    @Test
    fun `blocked preparation, link return and post-commit sync give bounded failures and leave nothing`() {
        for (point in listOf(DescriptorBoundCommitFaultPoint.AFTER_PREPARED_SYNC, DescriptorBoundCommitFaultPoint.AFTER_COMMIT,
            DescriptorBoundCommitFaultPoint.AFTER_COMMIT_DIRECTORY_SYNC)) fixture { root ->
            val tracker = GccBundledHostWorkTracker()
            val blocked = CountDownLatch(1)
            val release = CountDownLatch(1)
            val started = System.nanoTime()
            assertFailsWith<GccBundledHostWorkTimeoutException>(point.name) {
                publish(root, Clock(BLOCKED_ALLOWANCE_MILLIS).deadline(), tracker = tracker, fault = { hit ->
                    if (hit == point) { blocked.countDown(); awaitIgnoringInterrupts(release) }
                })
            }
            val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue(blocked.count == 0L && elapsedMillis in BLOCKED_ALLOWANCE_MILLIS..BLOCKED_ALLOWANCE_MILLIS + 10_000,
                "${point.name}: $elapsedMillis ms")
            assertEquals(listOf("result publication"), tracker.inFlightStages, point.name)
            release.countDown()
            tracker.requireRetired(10_000)
            assertEquals(emptySet(), entries(root), point.name)
        }
    }

    @Test
    fun `a competing writer's result is never published or removed by this commit`() {
        fixture { root ->
            // The commit links the prepared inode itself, so a name that appears first is refused.
            val failure = assertFailsWith<java.io.IOException> {
                publish(root, Clock().deadline(), fault = { hit ->
                    if (hit == DescriptorBoundCommitFaultPoint.BEFORE_COMMIT) Files.write(root.resolve(NAME), FOREIGN)
                })
            }
            assertTrue(failure.message.orEmpty().contains("errno 17"), failure.toString())
            assertEquals(setOf(NAME), entries(root))
            assertContentEquals(FOREIGN, Files.readAllBytes(root.resolve(NAME)))
        }
        fixture { root ->
            // Another writer replaces the committed name before revocation; revocation proves the inode and restores theirs.
            val clock = Clock()
            val failure = assertFailsWith<java.io.IOException> {
                publish(root, clock.deadline(), fault = { hit ->
                    when (hit) {
                        DescriptorBoundCommitFaultPoint.AFTER_COMMIT -> clock.expire()
                        DescriptorBoundCommitFaultPoint.BEFORE_REVOCATION -> Files.move(Files.write(root.resolve("foreign"), FOREIGN),
                            root.resolve(NAME), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
                        else -> {}
                    }
                })
            }
            val messages = listOf(failure) + failure.suppressed
            assertTrue(messages.any { it.message.orEmpty().contains("another writer's entry") }, failure.stackTraceToString())
            assertEquals(setOf(NAME), entries(root))
            assertContentEquals(FOREIGN, Files.readAllBytes(root.resolve(NAME)))
        }
    }

    @Test
    fun `existing results are refused and left untouched`() = fixture { root ->
        Files.write(root.resolve(NAME), FOREIGN)
        assertFailsWith<java.io.IOException> { publish(root, Clock().deadline()) }
        assertEquals(setOf(NAME), entries(root))
        assertContentEquals(FOREIGN, Files.readAllBytes(root.resolve(NAME)))
    }

    /** A frozen operation clock; a large default allowance keeps slow host fsyncs from timing out ordinary cases. */
    private class Clock(val maximumMillis: Long = 60_000) {
        var now = 0L
        fun deadline() = ContainedCommandOperationDeadline(maximumMillis) { now }
        fun expire() { now = maximumMillis * 1_000_000L }
        fun leave(millis: Long) { now = (maximumMillis - millis) * 1_000_000L }
    }

    private fun publish(
        root: Path,
        deadline: ContainedCommandOperationDeadline,
        tracker: GccBundledHostWorkTracker = GccBundledHostWorkTracker(),
        fault: (DescriptorBoundCommitFaultPoint) -> Unit = {},
    ) = LinuxFilesystemSyscalls.openRoot(root).use { parent ->
        GccBundledDeadlineBoundPublication.publish(tracker, parent, NAME, BYTES, 1024, deadline,
            DescriptorBoundCommitFaultInjector { fault(it) })
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
        const val BLOCKED_ALLOWANCE_MILLIS = 5_000L
        val BYTES = "{\"complete\":false}\n".toByteArray()
        val FOREIGN = "{\"foreign\":true}\n".toByteArray()
    }
}
