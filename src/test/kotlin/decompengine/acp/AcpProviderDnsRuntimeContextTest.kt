package decompengine.acp

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.IdentityHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Privileged registry fixtures exercise authority checks; they do not issue production contexts. */
class AcpProviderDnsRuntimeContextTest {
    @Test fun `unregistered context cannot grant launch authority`() {
        val context = newContext()
        assertFailsWith<IllegalArgumentException> { consume(context, Any(), BINDING, end()) }
    }

    @Test fun `wrong consumer revokes and consumes registered context`() = fixture { f ->
        assertFailsWith<IllegalArgumentException> { consume(f.context, Any(), BINDING, f.deadline) }
        assertFailsWith<IllegalArgumentException> { f.consume() }
        assertFails { f.lease.admitDispatch(f.deadline) }
    }

    @Test fun `wrong binding revokes and consumes registered context`() = fixture { f ->
        assertFailsWith<IllegalArgumentException> { consume(f.context, f.consumer, "b".repeat(64), f.deadline) }
        assertFailsWith<IllegalArgumentException> { f.consume() }
    }

    @Test fun `deadline mismatch revokes and consumes registered context`() = fixture { f ->
        assertFailsWith<IllegalArgumentException> { consume(f.context, f.consumer, BINDING, f.deadline - 1) }
        assertFailsWith<IllegalArgumentException> { f.consume() }
    }

    @Test fun `valid context transfers only once and clamps dispatch deadline`() = fixture { f ->
        assertSame(f.lease, f.consume())
        assertFailsWith<IllegalArgumentException> { f.consume() }
        assertEquals(f.deadline, f.lease.clampDeadline(f.deadline + TimeUnit.SECONDS.toNanos(1)))
        assertEquals(f.deadline - 1, f.lease.clampDeadline(f.deadline - 1))
        val ticket = f.lease.admitDispatch(f.deadline + 1)
        assertEquals(f.deadline, ticket.deadlineNanos)
        assertFails { f.lease.admitDispatch(f.deadline) }
    }

    @Test fun `eight lifetime admissions exhaust the lease even after verified slots`() = fixture { f ->
        f.consume()
        repeat(8) {
            val ticket = f.lease.admitDispatch(f.deadline)
            // Synthetic completion exercises only the counter. Actual owner completion remains
            // mandatory in production and is separately tested by real-process component controls.
            ticket.javaClass.getDeclaredField("verified").also { it.isAccessible = true }.setBoolean(ticket, true)
        }
        assertFails { f.lease.admitDispatch(f.deadline) }
    }

    @Test fun `revoked context cannot transfer or dispatch`() = fixture { f ->
        f.lease.javaClass.getDeclaredMethod("markRevoked").also { it.isAccessible = true }.invoke(f.lease)
        assertFails { f.consume() }
        assertFails { f.lease.admitDispatch(f.deadline) }
    }

    @Test fun `concurrent replay admits at most one transfer`() = fixture { f ->
        val go = CountDownLatch(1)
        val count = AtomicInteger()
        val threads = List(2) { thread { go.await(); if (runCatching { f.consume() }.isSuccess) count.incrementAndGet() } }
        go.countDown()
        threads.forEach { it.join(1000); assertFalse(it.isAlive) }
        assertEquals(1, count.get())
    }

    @Test fun `close racing transfer revokes future admissions`() = fixture { f ->
        val go = CountDownLatch(1)
        val transfer = thread { go.await(); runCatching { f.consume() } }
        val close = thread { go.await(); assertTrue(f.lease.closeBefore(end())) }
        go.countDown()
        listOf(transfer, close).forEach { it.join(1000); assertFalse(it.isAlive) }
        assertTrue(f.lease.isClosed())
        assertFails { f.lease.admitDispatch(f.deadline) }
    }

    @Test fun `expired shared cleanup checkpoint retains remaining private entries`() {
        val base = Path.of(System.getProperty("user.dir"), "build/provider-dns-context-controls")
        Files.createDirectories(base)
        val root = Files.createTempDirectory(base, "cleanup-")
        val file = Files.writeString(root.resolve("retained"), "credential-free")
        try {
            LinuxFilesystemSyscalls.openRoot(root).use { directory ->
                assertFailsWith<IOException> {
                    deletePrivateTreeContents(directory, AcpRuntimeClosureLimits(16, 1024, 4)) {
                        throw IOException("fixed expired cleanup checkpoint")
                    }
                }
            }
            assertTrue(Files.isRegularFile(file))
        } finally { Files.deleteIfExists(file); Files.deleteIfExists(root) }
    }

    @Test fun `expired trusted helper cleanup retains exact owner until explicit remediation`() {
        val groupType = Class.forName("decompengine.acp.TrustedControlProcesses")
        val group = groupType.getDeclaredConstructor().also { it.isAccessible = true }.newInstance()
        fun invoke(target: Any, name: String, vararg args: Any): Any? = target.javaClass.declaredMethods
            .single { it.name == name && it.parameterCount == args.size }.also { it.isAccessible = true }.invoke(target, *args)
        val owner = checkNotNull(invoke(group, "admit"))
        val child = ProcessBuilder("/usr/bin/sleep", "30").also { it.environment().clear() }.start()
        try {
            invoke(owner, "publish", child)
            // A native process exists, but its original caller has not finished its pipe access.
            assertFalse(invoke(group, "completeBefore", owner, System.nanoTime() - 1) as Boolean)
            assertFalse(invoke(group, "isEmpty") as Boolean)
            val owners = Class.forName("decompengine.acp.LinuxBubblewrapBoundaryKt")
                .getDeclaredField("TRUSTED_CONTROL_OWNERS").also { it.isAccessible = true }.get(null) as Set<*>
            synchronized(owners) { assertTrue(owner in owners) }
            invoke(owner, "finishCall")
            assertTrue(invoke(group, "completeBefore", owner, end()) as Boolean)
            assertTrue(invoke(group, "isEmpty") as Boolean)
            synchronized(owners) { assertFalse(owner in owners) }
            assertTrue(child.waitFor(1, TimeUnit.SECONDS))
            assertFalse(child.isAlive)
        } finally {
            child.toHandle().destroyForcibly()
            child.waitFor(1, TimeUnit.SECONDS)
            invoke(owner, "finishCall")
            invoke(group, "completeBefore", owner, end())
        }
    }

    private class Fixture(val context: AcpProviderDnsRuntimeContext, val consumer: Any,
        val deadline: Long, val lease: AcpProviderDnsInvocationLease) {
        fun consume() = consume(context, consumer, BINDING, deadline)
    }

    private fun fixture(block: (Fixture) -> Unit) {
        val type = Class.forName("decompengine.acp.ProviderDnsControlLease")
        val deadline = end()
        val constructor = type.declaredConstructors.single().also { it.isAccessible = true }
        val lease = constructor.newInstance(BINDING, deadline, AcpRuntimeClosureLimits(), emptySet<Any>()) as AcpProviderDnsInvocationLease
        // Skip real runtime IO only in this private reflection control. No path or starter is supplied.
        type.getDeclaredField("preparing").also { it.isAccessible = true }.setBoolean(lease, false)
        val context = newContext()
        val consumer = Any()
        val recordType = Class.forName("decompengine.acp.ProviderDnsContextRecord")
        val record = recordType.declaredConstructors.single().also { it.isAccessible = true }
            .newInstance(consumer, BINDING, lease)
        val registry = LinuxBubblewrapBoundary::class.java.getDeclaredField("PROVIDER_DNS_CONTEXTS")
            .also { it.isAccessible = true }.get(null) as IdentityHashMap<Any, Any>
        val guard = LinuxBubblewrapBoundary::class.java.getDeclaredField("PROVIDER_DNS_CONTEXT_GUARD")
            .also { it.isAccessible = true }.get(null)
        synchronized(guard) { registry[context] = record }
        try { block(Fixture(context, consumer, deadline, lease)) }
        finally {
            synchronized(guard) { registry.remove(context) }
            assertTrue(lease.closeBefore(end()))
        }
    }

    companion object {
        private const val BINDING = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        private fun end() = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        private fun newContext(): AcpProviderDnsRuntimeContext =
            Class.forName("decompengine.acp.BoundaryProviderDnsRuntimeContext").getDeclaredConstructor()
                .also { it.isAccessible = true }.newInstance() as AcpProviderDnsRuntimeContext
        private fun consume(context: AcpProviderDnsRuntimeContext, consumer: Any, binding: String, deadline: Long) =
            LinuxBubblewrapBoundary.consumeProviderDnsRuntimeContext(context, consumer, binding, deadline)
    }
}
