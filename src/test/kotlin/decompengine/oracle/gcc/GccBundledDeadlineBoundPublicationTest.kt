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
        val points = listOf(DescriptorBoundCommitFaultPoint.AFTER_PREPARED_SYNC, DescriptorBoundCommitFaultPoint.BEFORE_COMMIT,
            DescriptorBoundCommitFaultPoint.AFTER_COMMIT, DescriptorBoundCommitFaultPoint.AFTER_COMMIT_DIRECTORY_SYNC)
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
    fun `blocked preparation, link return and a post-sync stall give bounded failures and leave nothing`() {
        for (point in listOf(DescriptorBoundCommitFaultPoint.AFTER_PREPARED_SYNC, DescriptorBoundCommitFaultPoint.AFTER_COMMIT,
            DescriptorBoundCommitFaultPoint.AFTER_COMMIT_DIRECTORY_SYNC)) fixture { root ->
            val tracker = GccBundledHostWorkTracker()
            val blocked = CountDownLatch(1)
            val release = CountDownLatch(1)
            try {
                // AFTER_COMMIT_DIRECTORY_SYNC stalls the step after its post-commit directory sync returns.
                val outcome = callBounded {
                    publish(root, Clock(BLOCKED_ALLOWANCE_MILLIS).deadline(), tracker = tracker, fault = { hit ->
                        if (hit == point) { blocked.countDown(); awaitIgnoringInterrupts(release) }
                    })
                }
                assertTrue(outcome.returned, "${point.name}: the caller must return while the step is stalled")
                assertTrue(outcome.failure is GccBundledHostWorkTimeoutException, "${point.name}: ${outcome.failure}")
                assertTrue(blocked.count == 0L && outcome.elapsedMillis in BLOCKED_ALLOWANCE_MILLIS..BLOCKED_ALLOWANCE_MILLIS + 10_000,
                    "${point.name}: ${outcome.elapsedMillis} ms")
                assertEquals(listOf("result publication"), tracker.inFlightStages, point.name)
            } finally {
                release.countDown()
            }
            tracker.requireRetired(10_000)
            assertEquals(emptySet(), entries(root), point.name)
        }
    }

    @Test
    fun `losing the authenticated directory or leaf during a post-sync stall never reports success`() {
        fixture { root ->
            val moved = root.resolveSibling(root.fileName.toString() + "-moved")
            try {
                val failure = assertFailsWith<java.io.IOException> {
                    publish(root, Clock().deadline(), fault = { hit ->
                        if (hit == DescriptorBoundCommitFaultPoint.AFTER_COMMIT_DIRECTORY_SYNC) {
                            Files.move(root, moved)
                            Files.createDirectory(root, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                        }
                    })
                }
                assertTrue(failure.message.orEmpty().contains("no longer resolves at its authenticated path"), failure.toString())
                assertEquals(emptySet(), entries(root))
                assertEquals(emptySet(), entries(moved), "revocation through the pinned descriptor follows the renamed directory")
            } finally {
                if (Files.exists(moved)) { Files.delete(root); Files.move(moved, root) }
            }
        }
        fixture { root ->
            val failure = assertFailsWith<java.io.IOException> {
                publish(root, Clock().deadline(), fault = { hit ->
                    if (hit == DescriptorBoundCommitFaultPoint.AFTER_COMMIT_DIRECTORY_SYNC) replaceWithForeign(root, FOREIGN)
                })
            }
            assertTrue(failure.message.orEmpty().contains("entry was replaced"), failure.toString())
            assertEquals(setOf(NAME), entries(root))
            assertContentEquals(FOREIGN, Files.readAllBytes(root.resolve(NAME)))
        }
        fixture { root ->
            val failure = assertFailsWith<IllegalArgumentException> {
                publish(root, Clock().deadline(), requireBindings = { throw IllegalArgumentException("CLI directory identity changed") })
            }
            assertEquals("CLI directory identity changed", failure.message)
            assertEquals(emptySet(), entries(root))
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
                        DescriptorBoundCommitFaultPoint.BEFORE_REVOCATION -> replaceWithForeign(root, FOREIGN)
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
    fun `a leaf replaced while the CLI bindings are rechecked is never accepted`() = fixture { root ->
        var checked = false
        val failure = assertFailsWith<java.io.IOException> {
            // The binding recheck replaces the leaf and then returns normally.
            publish(root, Clock().deadline(), requireBindings = { replaceWithForeign(root, FOREIGN); checked = true })
        }
        assertTrue(checked)
        assertTrue(failure.message.orEmpty().contains("entry was replaced"), failure.toString())
        assertEquals(setOf(NAME), entries(root))
        assertContentEquals(FOREIGN, Files.readAllBytes(root.resolve(NAME)))
    }

    @Test
    fun `a late AT_EMPTY_PATH failure never starts the descriptor fallback without renewed admission`() = fixture { root ->
        val clock = Clock()
        var attempts = 0
        val injector = object : DescriptorBoundCommitFaultInjector {
            override fun hit(point: DescriptorBoundCommitFaultPoint) {}
            // The first link attempt returns ENOENT only after the commit reserve has elapsed.
            override fun emptyPathLinkErrno(): Int { attempts++; clock.leave(500); return 2 }
        }
        val failure = assertFailsWith<IllegalStateException> { publish(root, clock.deadline(), injector = injector) }
        assertTrue(failure.message.orEmpty().contains("requires 1000 ms"), failure.toString())
        assertEquals(1, attempts)
        assertEquals(emptySet(), entries(root), "the procfs fallback must not have linked the result")
    }

    @Test
    fun `an abandoned or lapsed commit admits no further link attempt`() {
        val clock = Clock()
        val abandoned = GccBundledDeadlineCommitGate(clock.deadline())
        abandoned.beginCommit()
        abandoned.beginCommit()
        abandoned.abandon()
        assertFailsWith<IllegalStateException> { abandoned.beginCommit() }
        val lapsed = GccBundledDeadlineCommitGate(clock.deadline())
        lapsed.beginCommit()
        clock.leave(999)
        assertFailsWith<IllegalStateException> { lapsed.beginCommit() }
        assertEquals(GccBundledDeadlineCommitGate.State.ABANDONED, lapsed.state)
    }

    @Test
    fun `a name recreated during revocation keeps the other writer's entry at its reported private path`() = fixture { root ->
        val clock = Clock()
        val recreated = "{\"recreated\":true}\n".toByteArray()
        val failure = assertFailsWith<java.io.IOException> {
            publish(root, clock.deadline(), fault = { hit ->
                when (hit) {
                    DescriptorBoundCommitFaultPoint.AFTER_COMMIT -> clock.expire()
                    DescriptorBoundCommitFaultPoint.BEFORE_REVOCATION -> replaceWithForeign(root, FOREIGN)
                    DescriptorBoundCommitFaultPoint.BEFORE_REVOCATION_RESTORE -> Files.write(root.resolve(NAME), recreated)
                    DescriptorBoundCommitFaultPoint.BEFORE_REVOCATION_CONFLICT_SYNC -> throw java.io.IOException("injected sync failure")
                    else -> {}
                }
            })
        }
        val preserved = entries(root) - NAME
        assertEquals(1, preserved.size, entries(root).toString())
        val report = failure.suppressed.single { it.message.orEmpty().contains("preserved another writer's entry") }
        assertTrue(report.message.orEmpty().contains("at ${root.resolve(preserved.single())}"), report.toString())
        assertEquals(listOf("injected sync failure"), report.suppressed.map { it.message }, "a later sync failure is attached")
        assertContentEquals(FOREIGN, Files.readAllBytes(root.resolve(preserved.single())))
        assertContentEquals(recreated, Files.readAllBytes(root.resolve(NAME)))
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
        requireBindings: () -> Unit = {},
        fault: (DescriptorBoundCommitFaultPoint) -> Unit = {},
        injector: DescriptorBoundCommitFaultInjector = DescriptorBoundCommitFaultInjector { fault(it) },
    ) = LinuxFilesystemSyscalls.openRoot(root).use { parent ->
        GccBundledDeadlineBoundPublication.publish(tracker, parent, root, NAME, BYTES, 1024, deadline, injector, requireBindings)
    }.also { tracker.requireRetired(10_000) }

    private fun replaceWithForeign(root: Path, bytes: ByteArray) {
        Files.move(Files.write(root.resolve("foreign"), bytes), root.resolve(NAME),
            StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
    }

    private class Outcome(val returned: Boolean, val failure: Throwable?, val elapsedMillis: Long)

    /** A separate caller thread lets a regression that waits unboundedly fail instead of hanging the suite. */
    private fun callBounded(action: () -> Unit): Outcome {
        val failure = arrayOfNulls<Throwable>(1)
        val started = System.nanoTime()
        val caller = Thread { failure[0] = runCatching(action).exceptionOrNull() }.apply { isDaemon = true; start() }
        caller.join(BLOCKED_ALLOWANCE_MILLIS + 20_000)
        return Outcome(!caller.isAlive, failure[0], TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started))
    }

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
