package decompengine.acp

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LinuxFilesystemSyscallsTest {
    @Test
    fun `prefix observations retain successful owners through a later failed pin and cleanup`() {
        var clock = 0L
        val prefix = requireNotNull(RuntimeCopyStatistics.Prefix.create {
            val elapsed = clock++
            longArrayOf(elapsed, 100L - elapsed)
        })
        val prepare = RuntimeCopyStatistics()
        prefix.retain(RuntimeCopyStatistics.Prefix.Owner.PREPARE, prepare)
        prefix.measure(RuntimeCopyStatistics.Prefix.Phase.PREPARE) {
            prepare.copy.started(); prepare.copy.read(13); prepare.copy.written(13); prepare.copy.completed()
        }
        val validation = requireNotNull(prefix.statistics(RuntimeCopyStatistics.Prefix.Owner.VALIDATE))
        prefix.measure(RuntimeCopyStatistics.Prefix.Phase.VALIDATE) {
            validation.hash.started(); validation.hash.read(7); validation.hash.completed()
        }
        val primary = IllegalStateException("authored action failure")
        val caught = assertFailsWith<IllegalStateException> {
            prefix.measure(RuntimeCopyStatistics.Prefix.Phase.LAUNCH) {
                prefix.measure(RuntimeCopyStatistics.Prefix.Phase.LAUNCH_PINNING) {
                    prefix.failureCurrent(RuntimeCopyStatistics.Prefix.Failure.TIMEOUT)
                    throw primary
                }
            }
        }
        assertTrue(caught === primary)
        prefix.measure(RuntimeCopyStatistics.Prefix.Phase.BOUNDARY_CLOSE) { Unit }
        val mapped = mappedPrefixFailure(prefix, primary)
        assertTrue(mapped.cause === primary)
        assertTrue(mappedPrefixFailure(prefix, primary).suppressed.isEmpty())
        assertTrue(primary.suppressed.isEmpty())
        val summary = mapped.suppressed.single().message.orEmpty()
        assertTrue(summary.contains("firstObservedFailure=LAUNCH_PINNING,kind=TIMEOUT"), summary)
        assertTrue(summary.contains("failureElapsedNs=8,failureRemainingNs=92"), summary)
        assertTrue(summary.contains("PREPARE:COPY[observed=true,supported=true,files=1/1,readBytes=13"), summary)
        assertTrue(summary.contains("VALIDATE:COPY[observed=false"), summary)
        assertTrue(summary.contains("HASH[observed=true,supported=true,files=1/1,readBytes=7"), summary)
        assertTrue(summary.contains("LAUNCH:3") && summary.contains("inclusiveNs=unknown"), summary)
        assertTrue(summary.contains("BOUNDARY_CLOSE:2"), summary)
        assertTrue(summary.contains("inclusive-overlap-do-not-sum"), summary)
    }

    @Test
    fun `unavailable diagnostic clock cannot change action result or primary failure`() {
        val prefix = requireNotNull(RuntimeCopyStatistics.Prefix.create { error("unavailable observation clock") })
        var actions = 0
        assertEquals(37, prefix.measure(RuntimeCopyStatistics.Prefix.Phase.PREPARE) { actions++; 37 })
        assertEquals(1, actions)
        val primary = IOException("authored primary")
        assertTrue(assertFailsWith<IOException> {
            prefix.measure(RuntimeCopyStatistics.Prefix.Phase.LAUNCH) { throw primary }
        } === primary)
        val mapped = mappedPrefixFailure(prefix, primary)
        assertTrue(mapped.suppressed.single().message.orEmpty().contains("supported=false"))
        assertTrue(primary.suppressed.isEmpty())
        assertEquals("authored primary", primary.message)
    }

    @Test
    fun `repeated phase observations remain bounded and never skip the action`() {
        val prefix = requireNotNull(RuntimeCopyStatistics.Prefix.create { longArrayOf(0, 1) })
        var actions = 0
        repeat(1000) { prefix.measure(RuntimeCopyStatistics.Prefix.Phase.PREPARE) { actions++ } }
        assertEquals(1000, actions)
        val primary = IOException("bounded diagnostic")
        val mapped = mappedPrefixFailure(prefix, primary)
        val summary = mapped.suppressed.single().message.orEmpty()
        assertTrue(primary.suppressed.isEmpty())
        assertTrue(RuntimeCopyStatistics.Prefix.Phase.entries.size <= 32)
        assertTrue(summary.length <= 16 * 1024)
        assertTrue(summary.contains("supported=false"))
        assertFalse(summary.contains("bounded diagnostic"))
    }

    @Test
    fun `fresh prefix mapping never inspects foreign causes or appends fallback records`() {
        val cause = OpaquePrefixCause()
        val existing = List(9) { IOException("existing foreign $it") }
        existing.forEach(cause::addSuppressed)
        val facts = decompengine.agent.AgentFailure(
            decompengine.agent.AgentFailureKind.CONFIGURATION, "authored mapped failure",
            retryable = true, details = mapOf("fixed" to "control"),
        )
        val prefix = requireNotNull(RuntimeCopyStatistics.Prefix.create { longArrayOf(0, 1) })
        val first = mappedPrefixFailure(prefix, cause, facts)
        assertTrue(first.failure === facts && first.cause === cause)
        assertEquals(null, first.receipt)
        assertEquals(facts.message, first.message)
        assertEquals(1, first.suppressed.size)
        assertFalse(first.suppressed.single().message.orEmpty().contains("foreign"))
        assertTrue(mappedPrefixFailure(prefix, cause, facts).suppressed.isEmpty())
        assertTrue(mappedPrefixFailure(null, cause, facts).suppressed.isEmpty())
        val wrongOwner = requireNotNull(RuntimeCopyStatistics.Prefix.create { longArrayOf(0, 1) })
        wrongOwner.javaClass.getDeclaredField("ownerThread").apply { isAccessible = true }
            .set(wrongOwner, Thread("unstarted-observation-owner")) // Never start a thread.
        assertTrue(mappedPrefixFailure(wrongOwner, cause, facts).suppressed.isEmpty())
        assertEquals(existing, cause.suppressed.toList())
        assertTrue(RuntimeCopyStatistics.Prefix::class.java.declaredMethods.none { method ->
            method.parameterTypes.any { Throwable::class.java.isAssignableFrom(it) }
        }) // No caller-supplied carrier publication API remains.
    }

    @Test
    fun `optional owner allocation failure does not skip or repeat the original action`() {
        val prefix = requireNotNull(RuntimeCopyStatistics.Prefix.create { longArrayOf(0, 1) })
        var allocations = 0
        val allocate: () -> RuntimeCopyStatistics = { allocations++; throw OutOfMemoryError("authored allocation failure") }
        val statisticsWith = prefix.javaClass.getDeclaredMethod("statisticsWith",
            RuntimeCopyStatistics.Prefix.Owner::class.java, Function0::class.java).apply { isAccessible = true }
        val statistics = statisticsWith.invoke(prefix, RuntimeCopyStatistics.Prefix.Owner.PREPARE, allocate)
        assertEquals(null, statistics)
        assertEquals(1, allocations)
        var actions = 0
        assertEquals(37, prefix.measure(RuntimeCopyStatistics.Prefix.Phase.PREPARE) { actions++; 37 })
        assertEquals(1, actions)
        val original = IOException("authored product failure")
        assertTrue(assertFailsWith<IOException> {
            prefix.measure(RuntimeCopyStatistics.Prefix.Phase.LAUNCH) { actions++; throw original }
        } === original)
        assertEquals(2, actions)
        assertTrue(original.suppressed.isEmpty())
        val summary = mappedPrefixFailure(prefix, original).suppressed.single().message.orEmpty()
        assertTrue(summary.contains("supported=false"), summary)
        assertTrue(summary.contains("PREPARE:unobserved"), summary)
    }

    @Test
    fun `unavailable prefix entry argument preserves leaf action once and original failure`() {
        var entries = 0
        val unavailable = OutOfMemoryError("authored entry argument failure")
        val budgetArgument: () -> ((Long) -> LongArray) = { throw unavailable }
        val create: () -> RuntimeCopyStatistics.Prefix? = {
            entries++
            RuntimeCopyStatistics.Prefix.create(budgetArgument())
        }
        val entry = Class.forName("decompengine.acp.AcpAgentHarnessKt")
            .getDeclaredMethod("createOptionalPrelaunchObservation", Function0::class.java)
            .apply { isAccessible = true }
        assertNull(entry.invoke(null, create)) // Failure occurs before Prefix.create is entered.
        assertEquals(1, entries)

        val leaf = Class.forName("decompengine.acp.LinuxFilesystemSyscallsKt")
            .getDeclaredMethod("measuredCopyOperation", RuntimeCopyStatistics.Bucket::class.java,
                RuntimeCopyStatistics.Operation::class.java, Function0::class.java)
            .apply { isAccessible = true }
        fun invokeLeaf(bucket: RuntimeCopyStatistics.Bucket?, action: () -> Int): Any? = try {
            leaf.invoke(null, bucket, RuntimeCopyStatistics.Operation.CHECK, action)
        } catch (failure: java.lang.reflect.InvocationTargetException) { throw failure.targetException }
        val statistics = RuntimeCopyStatistics()
        val primary = IOException("authored leaf primary")
        var actions = 0
        for (bucket in listOf(null, statistics.copy)) {
            assertEquals(37, invokeLeaf(bucket) { actions++; 37 })
            assertTrue(assertFailsWith<IOException> {
                invokeLeaf(bucket) { actions++; throw primary }
            } === primary)
        }
        assertEquals(4, actions)
        assertTrue(primary.suppressed.isEmpty())
        assertTrue(statistics.copy.summary().contains("CHECK=2/"))
    }

    private class OpaquePrefixCause : IOException("foreign graph must remain opaque") {
        override val cause: Throwable? get() = error("foreign cause graph was read")
    }

    private fun mappedPrefixFailure(
        prefix: RuntimeCopyStatistics.Prefix?,
        cause: Throwable,
        failure: decompengine.agent.AgentFailure = decompengine.agent.AgentFailure(
            decompengine.agent.AgentFailureKind.CONFIGURATION, "authored mapped failure"),
    ): decompengine.agent.AgentExecutionException = Class.forName("decompengine.acp.AcpAgentHarnessKt")
        .getDeclaredMethod("mappedPrelaunchFailure", decompengine.agent.AgentFailure::class.java,
            Throwable::class.java, RuntimeCopyStatistics.Prefix::class.java)
        .apply { isAccessible = true }.invoke(null, failure, cause, prefix) as decompengine.agent.AgentExecutionException

    @Test
    fun `owned statx scratch resets all bytes and retains fresh immutable identities across scopes`() {
        LinuxFilesystemSyscalls.StatxIdentityScratch().use { first ->
            LinuxFilesystemSyscalls.StatxIdentityScratch().use { second ->
                var firstBuffer: com.sun.jna.Memory? = null
                var calls = 0
                var fallbacks = 0
                val fallback = LinuxFileIdentity(LinuxFileKey(3, 99), 0x4000, 4, 5, 6, 7, false, true, false)
                val identities = listOf(11L, 12L).map { inode ->
                    scriptedStatx(first, query = { buffer ->
                        calls++
                        assertEquals(256L, buffer.size())
                        assertContentEquals(ByteArray(256), buffer.getByteArray(0, 256))
                        if (firstBuffer == null) firstBuffer = buffer else assertTrue(firstBuffer === buffer)
                        writeStatxIdentity(buffer, inode)
                        buffer.setByte(255, 0x7f)
                        0L
                    }, fallback = { fallbacks++; fallback })
                }
                assertEquals(listOf(11L, 12L), identities.map { it.key.inode })
                assertEquals(LinuxFileIdentity(LinuxFileKey(2049, 11), 0x81a0, 1001, 1002, 2, 42,
                    true, false, false), identities[0])
                assertTrue(identities[0] !== identities[1])
                assertEquals(11L, identities[0].key.inode) // A later syscall cannot retarget a returned value.
                assertEquals(0, fallbacks)
                val incomplete = scriptedStatx(first, query = { buffer ->
                    calls++
                    assertContentEquals(ByteArray(256), buffer.getByteArray(0, 256))
                    buffer.setInt(0, 0x11f) // Prior valid mount id must not survive the missing mask.
                    0L
                }, fallback = { fallbacks++; fallback })
                assertEquals(fallback, incomplete)
                assertEquals(1, fallbacks)
                assertEquals(3, calls)
                scriptedStatx(second, query = { buffer ->
                    assertTrue(firstBuffer !== buffer)
                    assertContentEquals(ByteArray(256), buffer.getByteArray(0, 256))
                    writeStatxIdentity(buffer, 13)
                    0L
                })
                assertEquals(11L, identities[0].key.inode)
            }
        }
    }

    @Test
    fun `owned statx scratch preserves retries missing backend fallback and genuine errno refusals`() {
        LinuxFilesystemSyscalls.StatxIdentityScratch().use { scratch ->
            var calls = 0
            val identity = scriptedStatx(scratch, query = { buffer ->
                calls++
                if (calls == 1) { com.sun.jna.Native.setLastError(4); -1L }
                else { writeStatxIdentity(buffer, 21); 0L }
            })
            assertEquals(2, calls)
            assertEquals(21L, identity.key.inode)
            val fallback = identity.copy(key = LinuxFileKey(7, 22))
            for (errno in listOf(1, 38, 95)) {
                var fallbacks = 0
                val actual = scriptedStatx(scratch, query = {
                    com.sun.jna.Native.setLastError(errno); -1L
                }, fallback = { fallbacks++; fallback })
                assertEquals(fallback, actual)
                assertEquals(1, fallbacks)
            }
            var missingBackendFallbacks = 0
            assertEquals(fallback, scriptedStatx(scratch, query = { throw UnsatisfiedLinkError("scripted absent statx") },
                fallback = { missingBackendFallbacks++; fallback }))
            assertEquals(1, missingBackendFallbacks)
            for (errno in listOf(5, 9, 13)) {
                var fallbacks = 0
                val failure = assertFailsWith<LinuxSyscallException> {
                    scriptedStatx(scratch, query = { com.sun.jna.Native.setLastError(errno); -1L },
                        fallback = { fallbacks++; fallback })
                }
                assertEquals(errno, failure.errno)
                assertEquals("inspect pinned descriptor identity failed with errno $errno", failure.message)
                assertEquals(0, fallbacks)
            }
            for (mountId in listOf(0L, -1L)) {
                val failure = assertFailsWith<IOException> {
                    scriptedStatx(scratch, query = { writeStatxIdentity(it, 23); it.setLong(0x90, mountId); 0L })
                }
                assertEquals("descriptor statx returned an invalid mount identity", failure.message)
            }
            val primary = IOException("scripted proc fallback failure")
            val observed = assertFailsWith<IOException> {
                scriptedStatx(scratch, query = { 0L }, fallback = { throw primary })
            }
            assertTrue(observed === primary)
        }
    }

    @Test
    fun `owned statx scratch serializes close with query and never closes borrowed descriptor`() {
        val handle = scriptedMountHandle(-301)
        val scratch = LinuxFilesystemSyscalls.StatxIdentityScratch()
        val memory = CountingStatxMemory()
        replaceStatxMemory(scratch, memory)
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val closing = java.util.concurrent.CountDownLatch(1)
        val executor = java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val query = executor.submit<LinuxFileIdentity> {
                scriptedStatx(scratch, fd = handle.fd, query = { buffer ->
                    assertTrue(Thread.holdsLock(scratch))
                    entered.countDown()
                    assertTrue(release.await(2, TimeUnit.SECONDS))
                    assertEquals(0, memory.closes)
                    writeStatxIdentity(buffer, 31)
                    0L
                })
            }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val close = executor.submit { closing.countDown(); scratch.close() }
            assertTrue(closing.await(2, TimeUnit.SECONDS))
            assertEquals(0, memory.closes) // Query owns the monitor; no timing-based success criterion.
            release.countDown()
            assertEquals(31L, query.get(2, TimeUnit.SECONDS).key.inode)
            close.get(2, TimeUnit.SECONDS)
            assertEquals(1, memory.closes)
            scratch.close()
            assertEquals(1, memory.closes)
            var queries = 0
            assertFailsWith<IllegalStateException> { scriptedStatx(scratch, query = { queries++; 0L }) }
            assertFailsWith<IllegalStateException> { scratch.identity(handle.fd) }
            assertEquals(0, queries)
            assertEquals(-301, handle.whileOpen { it })
        } finally {
            release.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(2, TimeUnit.SECONDS))
            scratch.close()
        }
    }

    private fun writeStatxIdentity(buffer: com.sun.jna.Memory, inode: Long) {
        buffer.setInt(0, 0x111f)
        buffer.setInt(0x10, 2)
        buffer.setInt(0x14, 1001)
        buffer.setInt(0x18, 1002)
        buffer.setShort(0x1c, 0x81a0.toShort())
        buffer.setLong(0x20, inode)
        buffer.setInt(0x88, 8)
        buffer.setInt(0x8c, 1)
        buffer.setLong(0x90, 42)
    }

    private fun scriptedStatx(
        scratch: LinuxFilesystemSyscalls.StatxIdentityScratch,
        fd: Int = -300,
        query: (com.sun.jna.Memory) -> Long,
        fallback: () -> LinuxFileIdentity = { error("unexpected scripted proc fallback") },
    ): LinuxFileIdentity = try {
        val method = scratch.javaClass.getDeclaredMethod("identityWith", Int::class.javaPrimitiveType,
            Function1::class.java, Function0::class.java).apply { isAccessible = true }
        method.invoke(scratch, fd, query, fallback) as LinuxFileIdentity
    } catch (failure: java.lang.reflect.InvocationTargetException) { throw failure.targetException }

    private class CountingStatxMemory : com.sun.jna.Memory(256) {
        @Volatile var closes = 0
        override fun close() { closes++; super.close() }
    }

    private fun replaceStatxMemory(scratch: LinuxFilesystemSyscalls.StatxIdentityScratch, memory: com.sun.jna.Memory) {
        val field = scratch.javaClass.getDeclaredField("statistics").apply { isAccessible = true }
        (field.get(scratch) as com.sun.jna.Memory).close()
        field.set(scratch, memory)
    }

    @Test
    fun `owned mount poll scratch resets stale bytes isolates scopes and never caches observations`() {
        val firstHandle = scriptedMountHandle(-101)
        val secondHandle = scriptedMountHandle(-102)
        LinuxFilesystemSyscalls.MountMetadataPollScratch(firstHandle).use { first ->
            LinuxFilesystemSyscalls.MountMetadataPollScratch(secondHandle).use { second ->
                var firstBuffer: com.sun.jna.Memory? = null
                var secondBuffer: com.sun.jna.Memory? = null
                var calls = 0
                val changed = listOf(0, 2, 0).map { event ->
                    val observation = scriptedMountPoll(first) { buffer ->
                        calls++
                        assertEquals(8L, buffer.size())
                        assertEquals(-101, buffer.getInt(0))
                        assertEquals(10, buffer.getShort(4).toInt()) // POLLPRI | POLLERR
                        assertEquals(0, buffer.getShort(6).toInt())
                        if (firstBuffer == null) firstBuffer = buffer else assertTrue(firstBuffer === buffer)
                        buffer.setShort(6, event.toShort())
                        1
                    }
                    LinuxFilesystemSyscalls.mountMetadataPollChanged(observation)
                }
                assertEquals(listOf(false, true, false), changed) // Scope latch is separate; scratch never caches.
                assertEquals(3, calls)
                scriptedMountPoll(second) { buffer ->
                    secondBuffer = buffer
                    assertEquals(-102, buffer.getInt(0))
                    assertEquals(0, buffer.getShort(6).toInt())
                    0
                }
                assertTrue(firstBuffer !== secondBuffer)
                val raw = scriptedMountPoll(first) { buffer -> buffer.setShort(6, 0x8002.toShort()); 1 }
                assertEquals((1L shl 32) or 0x8002L, raw)
                assertTrue(LinuxFilesystemSyscalls.mountMetadataPollChanged(raw))
                val zero = scriptedMountPoll(first) { buffer -> buffer.setShort(6, 8); 0 }
                assertFalse(LinuxFilesystemSyscalls.mountMetadataPollChanged(zero))
            }
        }
        assertEquals(-101, firstHandle.whileOpen { it }) // Scratch must not close the borrowed descriptors.
        assertEquals(-102, secondHandle.whileOpen { it })
    }

    @Test
    fun `owned mount poll keeps EINTR errno invalid and hangup semantics`() {
        LinuxFilesystemSyscalls.MountMetadataPollScratch(scriptedMountHandle(-103)).use { scratch ->
            var attempts = 0
            val observation = scriptedMountPoll(scratch) { buffer ->
                attempts++
                if (attempts == 1) { com.sun.jna.Native.setLastError(4); -1 }
                else { buffer.setShort(6, 2); 1 }
            }
            assertEquals(2, attempts)
            assertTrue(LinuxFilesystemSyscalls.mountMetadataPollChanged(observation))
            attempts = 0
            val failure = assertFailsWith<LinuxSyscallException> {
                scriptedMountPoll(scratch) { _ -> attempts++; com.sun.jna.Native.setLastError(5); -1 }
            }
            assertEquals(1, attempts)
            assertEquals(5, failure.errno)
            assertEquals("inspect host mount metadata events failed with errno 5", failure.message)
            for (events in listOf(16, 32)) { // POLLHUP and POLLNVAL remain refused.
                attempts = 0
                val invalid = assertFailsWith<IOException> {
                    scriptedMountPoll(scratch) { buffer -> attempts++; buffer.setShort(6, events.toShort()); 1 }
                }
                assertEquals(1, attempts)
                assertEquals("mountinfo event descriptor is invalid", invalid.message)
            }
            assertEquals(0L, scriptedMountPoll(scratch) { buffer ->
                assertEquals(0, buffer.getShort(6).toInt())
                0
            })
        }
    }

    @Test
    fun `owned mount poll close and closed borrowed handle refuse before query`() {
        val handle = scriptedMountHandle(-104)
        val scratch = LinuxFilesystemSyscalls.MountMetadataPollScratch(handle)
        var queries = 0
        scratch.close(); scratch.close()
        assertFailsWith<IllegalStateException> { scriptedMountPoll(scratch) { queries++; 0 } }
        assertFailsWith<IllegalStateException> { scratch.poll() } // Must refuse before hardwired native poll.
        assertEquals(0, queries)
        assertEquals(-104, handle.whileOpen { it })
        LinuxFilesystemSyscalls.MountMetadataPollScratch(handle).use { active ->
            LinuxDescriptor::class.java.getDeclaredField("ownsDescriptor").apply { isAccessible = true }.setBoolean(handle, false)
            assertFailsWith<IllegalStateException> { scriptedMountPoll(active) { queries++; 0 } }
            assertEquals(0, queries)
        }
    }

    @Test
    fun `owned mount poll close waits for in flight query before freeing its buffer`() {
        val handle = scriptedMountHandle(-105)
        val scratch = LinuxFilesystemSyscalls.MountMetadataPollScratch(handle)
        val memory = CountingMountPollMemory()
        replaceMountPollMemory(scratch, memory)
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val closeStarted = java.util.concurrent.CountDownLatch(1)
        val closeDone = java.util.concurrent.CountDownLatch(1)
        val executor = java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val poll = executor.submit<Long> { scriptedMountPoll(scratch) { buffer ->
                entered.countDown()
                assertTrue(release.await(2, TimeUnit.SECONDS))
                assertEquals(0, memory.closes)
                buffer.setShort(6, 2)
                1
            } }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val closing = executor.submit { closeStarted.countDown(); scratch.close(); closeDone.countDown() }
            assertTrue(closeStarted.await(2, TimeUnit.SECONDS))
            assertFalse(closeDone.await(50, TimeUnit.MILLISECONDS))
            assertEquals(0, memory.closes)
            release.countDown()
            assertTrue(LinuxFilesystemSyscalls.mountMetadataPollChanged(poll.get(2, TimeUnit.SECONDS)))
            closing.get(2, TimeUnit.SECONDS)
            assertEquals(1, memory.closes)
            scratch.close()
            assertEquals(1, memory.closes)
            assertEquals(-105, handle.whileOpen { it })
        } finally {
            release.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(2, TimeUnit.SECONDS))
            scratch.close()
        }
    }

    private fun scriptedMountHandle(fd: Int) = LinuxDescriptor(fd,
        LinuxFileIdentity(LinuxFileKey(0, 0), 0, 0, 0, 1, 1, false, false, false))

    private fun scriptedMountPoll(
        scratch: LinuxFilesystemSyscalls.MountMetadataPollScratch,
        query: (com.sun.jna.Memory) -> Int,
    ): Long = try {
        val method = scratch.javaClass.getDeclaredMethod("pollWith", Function1::class.java).apply { isAccessible = true }
        method.invoke(scratch, query) as Long
    } catch (failure: java.lang.reflect.InvocationTargetException) { throw failure.targetException }

    private class CountingMountPollMemory : com.sun.jna.Memory(8) {
        @Volatile var closes = 0
        override fun close() { closes++; super.close() }
    }

    private fun replaceMountPollMemory(scratch: LinuxFilesystemSyscalls.MountMetadataPollScratch, memory: com.sun.jna.Memory) {
        val field = scratch.javaClass.getDeclaredField("polled").apply { isAccessible = true }
        (field.get(scratch) as com.sun.jna.Memory).close()
        field.set(scratch, memory)
    }

    @Test
    fun `filesystem capacity is read through the pinned directory descriptor`() {
        withLinuxDirectory("linux-syscall-capacity-") { path, directory ->
            val capacity = LinuxFilesystemSyscalls.filesystemCapacity(directory)
            val store = Files.getFileStore(path)

            assertEquals(store.totalSpace, capacity.totalBytes)
            assertTrue(capacity.fragmentBytes > 0L)
            assertTrue(capacity.availableBytes in 0L..capacity.totalBytes)
            assertTrue(capacity.totalInodes > 0L)
            assertTrue(capacity.availableInodes in 0L..capacity.totalInodes)
            assertTrue(capacity.maximumNameBytes >= 255L)
            assertFalse(capacity.readOnly)
        }
    }

    @Test
    fun `regular files can be opened reopened and synchronized through descriptors`() {
        withLinuxDirectory("linux-syscall-regular-") { _, directory ->
            val content = "descriptor-owned-state".toByteArray()
            LinuxFilesystemSyscalls.createRegularFile(directory.fd, "state", OWNER_READ_WRITE).use { created ->
                LinuxFilesystemSyscalls.write(created, content) {}
                LinuxFilesystemSyscalls.synchronize(created)
            }
            LinuxFilesystemSyscalls.synchronize(directory)

            LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, "state")!!.use { authorized ->
                LinuxFilesystemSyscalls.openReadableFrom(authorized).use { readable ->
                    assertContentEquals(content, LinuxFilesystemSyscalls.read(readable, content.size + 1) {})
                }
                LinuxFilesystemSyscalls.reopenWritable(authorized).use { writable ->
                    LinuxFilesystemSyscalls.synchronize(writable)
                }
                LinuxFilesystemSyscalls.reopenReadWrite(authorized).use { readWrite ->
                    assertContentEquals(content, LinuxFilesystemSyscalls.read(readWrite, content.size + 1) {})
                    LinuxFilesystemSyscalls.synchronize(readWrite)
                }
            }

            assertNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, "missing"))
        }
    }

    @Test
    fun `symbolic links fifos and directories are rejected without blocking`() {
        withLinuxDirectory("linux-syscall-special-") { path, directory ->
            Files.writeString(path.resolve("target"), "regular")
            Files.createSymbolicLink(path.resolve("link"), Path.of("target"))
            Files.createDirectory(path.resolve("child"))
            createFifo(path.resolve("fifo"))

            listOf("link", "fifo", "child").forEach { name ->
                assertCompletesPromptly("inspect $name") {
                    assertFailsWith<IOException> {
                        LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, name)?.close()
                    }
                }
                LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)!!.use { authorized ->
                    assertCompletesPromptly("reopen $name for reading") {
                        assertFailsWith<IOException> {
                            LinuxFilesystemSyscalls.openReadableFrom(authorized).close()
                        }
                    }
                    assertCompletesPromptly("reopen $name for writing") {
                        assertFailsWith<IOException> {
                            LinuxFilesystemSyscalls.reopenWritable(authorized).close()
                        }
                    }
                    assertCompletesPromptly("reopen $name for reading and writing") {
                        assertFailsWith<IOException> {
                            LinuxFilesystemSyscalls.reopenReadWrite(authorized).close()
                        }
                    }
                }
            }
        }
    }

    @Test
    fun `exclusive locks expose a nonblocking deadline primitive and explicit unlock`() {
        withLinuxDirectory("linux-syscall-lock-") { _, directory ->
            LinuxFilesystemSyscalls.createRegularFile(directory.fd, "graph.lock", OWNER_READ_WRITE).use { first ->
                LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, "graph.lock")!!.use { authorized ->
                    LinuxFilesystemSyscalls.reopenReadWrite(authorized).use { second ->
                        var firstLocked = false
                        var secondLocked = false
                        try {
                            assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(first))
                            firstLocked = true

                            assertFalse(LinuxFilesystemSyscalls.tryExclusiveLock(second))
                            assertFalse(tryUntil(second, Duration.ofMillis(25)))

                            LinuxFilesystemSyscalls.unlock(first)
                            firstLocked = false
                            assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(second))
                            secondLocked = true
                        } finally {
                            if (secondLocked) LinuxFilesystemSyscalls.unlock(second)
                            if (firstLocked) LinuxFilesystemSyscalls.unlock(first)
                        }
                    }
                }
            }
            LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, ".").use { first ->
                LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, ".").use { second ->
                    assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(first))
                    try {
                        assertFalse(LinuxFilesystemSyscalls.tryExclusiveLock(second))
                    } finally {
                        LinuxFilesystemSyscalls.unlock(first)
                    }
                    assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(second))
                    LinuxFilesystemSyscalls.unlock(second)
                }
            }
        }
    }

    @Test
    fun `constrained root lookup admits only the reviewed native LP64 ABIs`() {
        for (architecture in listOf("amd64", "x86_64", "aarch64")) {
            assertTrue(LinuxFilesystemSyscalls.supportsConstrainedPathAbi("Linux", architecture, 8, 8))
            assertFalse(LinuxFilesystemSyscalls.supportsConstrainedPathAbi("Linux", architecture, 4, 4))
            assertFalse(LinuxFilesystemSyscalls.supportsConstrainedPathAbi("Linux", architecture, 8, 4))
        }
        assertFalse(LinuxFilesystemSyscalls.supportsConstrainedPathAbi("Linux", "x32", 8, 8))
        assertFalse(LinuxFilesystemSyscalls.supportsConstrainedPathAbi("Windows", "amd64", 8, 8))
    }

    @Test
    fun `constrained lookup retries share eight attempts and only ENOSYS selects fallback`() {
        var attempts = 0
        assertEquals(19L, LinuxFilesystemSyscalls.boundedConstrainedPathAttempt {
            attempts++
            if (attempts == 8) 19L to 0 else -1L to if (attempts % 2 == 0) 4 else 11
        })
        assertEquals(8, attempts)
        attempts = 0
        assertFailsWith<IOException> {
            LinuxFilesystemSyscalls.boundedConstrainedPathAttempt {
                attempts++
                -1L to if (attempts % 2 == 0) 4 else 11
            }
        }
        assertEquals(8, attempts)
        for (error in listOf(1, 2, 13, 18, 20, 22, 40, 7)) {
            attempts = 0
            val failure = assertFailsWith<LinuxSyscallException> {
                LinuxFilesystemSyscalls.boundedConstrainedPathAttempt { attempts++; -1L to error }
            }
            assertEquals(error, failure.errno)
            assertEquals(1, attempts)
        }
        attempts = 0
        assertNull(LinuxFilesystemSyscalls.boundedConstrainedPathAttempt { attempts++; -1L to 38 })
        assertEquals(1, attempts)
    }

    @Test
    fun `constrained root lookup preserves regular directory and final symlink descriptor kinds`() {
        // These native controls are deliberately not a fallback-as-pass: the required supported lane
        // must actually exercise openat2. Separate pure controls establish ENOSYS/ABI refusal behavior.
        val path = createTempDirectory(Files.createDirectories(Path.of("build")).toAbsolutePath(),
            "constrained-root-").normalize()
        try {
            Files.createDirectory(path.resolve("directory"))
            Files.writeString(path.resolve("regular"), "owned")
            Files.createSymbolicLink(path.resolve("link"), Path.of("regular"))
            Files.createSymbolicLink(path.resolve("ancestor"), Path.of("directory"))
            LinuxFilesystemSyscalls.openRoot(path).use { anchor ->
                for (name in listOf("regular", "directory", "link")) {
                    val opened = LinuxFilesystemSyscalls.openConstrainedPathAt(anchor, name)
                        ?: throw IOException("required constrained-lookup lane is unsupported")
                    opened.use {
                        val expected = LinuxFilesystemSyscalls.openPathAtOrNull(anchor.fd, name)!!
                        expected.use { original ->
                            assertEquals(original.identity.key, it.identity.key)
                            assertEquals(original.identity.mountId, it.identity.mountId)
                            assertEquals(name == "link", it.identity.isSymbolicLink)
                        }
                    }
                }
                // Kernel NO_SYMLINKS rejects an intermediate symlink; final O_PATH symlinks are
                // returned and must be rejected by the root-location identity/type guard.
                assertFailsWith<LinuxSyscallException> {
                    LinuxFilesystemSyscalls.openConstrainedPathAt(anchor, "ancestor/missing")
                }
                assertFailsWith<LinuxSyscallException> {
                    LinuxFilesystemSyscalls.openConstrainedPathAt(anchor, "missing")
                }
            }
        } finally {
            path.toFile().deleteRecursively()
        }
    }

    private fun withLinuxDirectory(prefix: String, action: (Path, LinuxDescriptor) -> Unit) {
        val path = createTempDirectory(prefix).toAbsolutePath().normalize()
        try {
            LinuxFilesystemSyscalls.requireSupported(path)
            LinuxFilesystemSyscalls.openRoot(path).use { directory -> action(path, directory) }
        } finally {
            path.toFile().deleteRecursively()
        }
    }

    private fun createFifo(path: Path) {
        val process = ProcessBuilder("mkfifo", path.toString()).redirectErrorStream(true).start()
        val completed = process.waitFor(5, TimeUnit.SECONDS)
        if (!completed) process.destroyForcibly()
        assertTrue(completed, "mkfifo did not complete")
        assertEquals(0, process.exitValue(), process.inputStream.bufferedReader().readText())
    }

    private fun assertCompletesPromptly(operation: String, action: () -> Unit) {
        val started = System.nanoTime()
        action()
        val elapsed = Duration.ofNanos(System.nanoTime() - started)
        assertTrue(elapsed < Duration.ofSeconds(2), "$operation blocked for $elapsed")
    }

    private fun tryUntil(descriptor: LinuxDescriptor, wait: Duration): Boolean {
        val deadline = System.nanoTime() + wait.toNanos()
        do {
            if (LinuxFilesystemSyscalls.tryExclusiveLock(descriptor)) return true
            Thread.sleep(1)
        } while (System.nanoTime() < deadline)
        return false
    }

    private companion object {
        const val OWNER_READ_WRITE = 0x180 // 0600
    }
}
