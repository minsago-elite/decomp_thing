package decompengine.acp

import decompengine.agent.*
import java.io.ByteArrayOutputStream
import java.lang.reflect.InvocationTargetException
import java.net.Socket
import java.net.URI
import java.nio.ByteBuffer
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Flow
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.*
import org.apache.hc.core5.http.ContentType
import org.apache.hc.core5.http.io.entity.ByteArrayEntity
import org.apache.hc.core5.http.message.BasicClassicHttpRequest

/** Inert ownership controls: no resolver, socket connection, credentials source or HTTP dispatch. */
class AcpProviderBrokerReviewRegressionTest {
    @Test fun `binding setup consumes the original enclosing deadline`() {
        val armed = AtomicBoolean()
        val base = Path.of(System.getProperty("user.dir"))
        val delayed = object : Path by base {
            override fun normalize(): Path = this
            override fun toString(): String {
                if (armed.compareAndSet(true, false)) Thread.sleep(650)
                return base.toString()
            }
        }
        val request = AgentExecutionRequest("inert setup control", listOf(AgentWorkspaceRoot("fixture", delayed)),
            accessPolicy = AgentAccessPolicy(emptyList()), limits = AgentExecutionLimits(wallClockTimeout = Duration.ofSeconds(5)))
        val backend = InertBackend()
        var broker: AcpProviderBroker? = null
        armed.set(true)
        try {
            val failure = assertFailsWith<AcpProviderBrokerFailure> {
                broker = AcpProviderBroker.openForTesting(policy(), request, Duration.ofMillis(500),
                    AcpProviderCredentialMaterial.cachedChatGpt("synthetic_token", "synthetic_account"), backend)
                broker!!.channelSetupPayload()
            }
            assertEquals(AcpProviderTerminalKind.TIMEOUT, failure.kind)
            assertEquals(0, backend.starts)
        } finally { broker?.close() }
    }

    @Test fun `all external terminal failures erase parser quarantine and secret matcher state`() {
        for (kind in listOf(AcpProviderTerminalKind.CANCELLED, AcpProviderTerminalKind.TIMEOUT,
            AcpProviderTerminalKind.AUTHENTICATION, AcpProviderTerminalKind.TRANSPORT, AcpProviderTerminalKind.REVOKED)) {
            val broker = open(InertBackend())
            try {
                broker.bindSession("synthetic-session", "synthetic-turn")
                val capability = AcpProviderBrokerProtocol.decodeChannelSetupPayload(broker.channelSetupPayload()).capability
                val exchange = broker.beginRequest(1, capability,
                    """{"model":"gpt-6.1-sol","input":[{"role":"user","content":"fixture"}],"reasoning":{"effort":"low"},"store":false,"stream":true}""".toByteArray())
                val parser = field(exchange, "parser") as AcpProviderResponseStream
                parser.accept("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"synthetic_".toByteArray())
                val event = field(parser, "event") as ByteArrayOutputStream
                val backing = byteStreamBacking(event)
                assertTrue(backing.any { it != 0.toByte() })
                broker.revoke(kind)
                assertTrue(backing.all { it == 0.toByte() }, "partial backing bytes survived $kind")
                assertEquals(0, event.size())
                for (pattern in field(parser, "secretPatterns") as List<*>) {
                    assertTrue((field(pattern!!, "bytes") as ByteArray).all { it == 0.toByte() })
                    assertTrue((field(pattern, "prefixes") as IntArray).all { it == 0 })
                }
                assertTrue((field(parser, "pending") as Collection<*>).isEmpty())
                assertNull(field(exchange, "owner")); assertNull(field(exchange, "subscription"))
                assertEquals(kind, broker.snapshot().requests.single().terminal)
            } finally { broker.close() }
        }
    }

    @Test fun `late failed owner is cancelled without restoring terminal exchange retention`() {
        var cancelled = 0
        val backend = object : AcpProviderBrokerTestBackend {
            override fun start(request: AcpProviderBackendRequest, receiver: AcpProviderBackendReceiver): AcpProviderBackendRequestOwner {
                receiver.failed()
                return object : AcpProviderBackendRequestOwner { override fun cancel() { cancelled++ } }
            }
            override fun closeWithin(timeout: Duration) = true
        }
        val broker = open(backend)
        try {
            broker.bindSession("synthetic-session", "synthetic-turn")
            val capability = AcpProviderBrokerProtocol.decodeChannelSetupPayload(broker.channelSetupPayload()).capability
            val exchange = broker.beginRequest(1, capability,
                """{"model":"gpt-6.1-sol","input":[{"role":"user","content":"fixture"}],"reasoning":{"effort":"low"},"store":false,"stream":true}""".toByteArray())
            assertEquals(1, cancelled)
            assertNull(field(exchange, "owner"))
            assertEquals(AcpProviderTerminalKind.TRANSPORT, broker.snapshot().requests.single().terminal)
        } finally { broker.close() }
    }

    @Test fun `late cleanup completion cannot retroactively satisfy the original grace`() {
        var closes = 0
        val backend = object : AcpProviderBrokerTestBackend {
            override fun start(request: AcpProviderBackendRequest, receiver: AcpProviderBackendReceiver): AcpProviderBackendRequestOwner = error("no dispatch")
            override fun closeWithin(timeout: Duration): Boolean { closes++; Thread.sleep(100); return true }
        }
        val broker = open(backend, AcpProviderTransportBounds(cleanupTimeout = Duration.ofMillis(20)))
        assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
        assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
        assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
        assertEquals(1, closes)
    }

    @Test fun `late lifecycle wait success cannot satisfy the original cleanup grace`() {
        assertLateLifecycleObservation(terminalObservation = false)
    }

    @Test fun `late terminal observation cannot satisfy the original cleanup grace`() {
        assertLateLifecycleObservation(terminalObservation = true)
    }

    private fun assertLateLifecycleObservation(terminalObservation: Boolean) {
        val broker = open(InertBackend(), AcpProviderTransportBounds(cleanupTimeout = Duration.ofMillis(20)))
        val lifecycleField = AcpProviderBroker::class.java.getDeclaredField("lifecycle").also { it.isAccessible = true }
        val original = lifecycleField.get(broker) as java.util.concurrent.ScheduledThreadPoolExecutor
        original.shutdownNow()
        assertTrue(original.awaitTermination(1, TimeUnit.SECONDS))
        var waits = 0
        var observations = 0
        val late = object : java.util.concurrent.ScheduledThreadPoolExecutor(1) {
            override fun awaitTermination(timeout: Long, unit: TimeUnit): Boolean {
                waits++
                if (!terminalObservation) Thread.sleep(100)
                return true
            }
            override fun isTerminated(): Boolean {
                observations++
                if (terminalObservation) Thread.sleep(100)
                return true
            }
        }
        lifecycleField.set(broker, late)
        try {
            assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
            assertTrue(broker.snapshot().revoked)
            assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
            assertEquals(1, waits)
            assertEquals(1, observations)
            assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
            assertEquals(1, waits, "cleanup retry obtained a fresh lifecycle wait")
            assertEquals(1, observations, "cleanup retry upgraded the terminal observation")
        } finally {
            late.shutdownNow()
            runCatching { broker.close() }
        }
    }

    @Test fun `HTTP owner cannot renew an elapsed absolute deadline`() {
        val authority = authority()
        val type = Class.forName("decompengine.acp.ProviderHttpAttempt")
        val constructor = type.declaredConstructors.single().also { it.isAccessible = true }
        val body = "synthetic body".toByteArray()
        val wire = BasicClassicHttpRequest("POST", URI("https://chatgpt.com/backend-api/codex/responses"))
        val end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500)
        Thread.sleep(650)
        val owner = if (constructor.parameterCount == 5) constructor.newInstance(authority, end, wire, body, Receiver())
            else constructor.newInstance(authority, Duration.ofMillis(500), wire, Receiver())
        try {
            val active = type.getDeclaredMethod("activeMillis").also { it.isAccessible = true }
            val failure = assertFailsWith<InvocationTargetException> { active.invoke(owner) }
            assertIs<java.net.SocketTimeoutException>(failure.cause)
        } finally { type.getDeclaredMethod("notSubmitted").also { it.isAccessible = true }.invoke(owner) }
    }

    @Test fun `held raw close delays completion then discards bearer body receiver and retired owner`() {
        val receiver = Receiver()
        val body = "synthetic body".toByteArray()
        val wire = BasicClassicHttpRequest("POST", URI("https://chatgpt.com/backend-api/codex/responses")).also {
            it.setHeader("Authorization", "Bearer synthetic-only")
            it.entity = ByteArrayEntity(body, ContentType.APPLICATION_JSON)
        }
        val authority = authority()
        val type = Class.forName("decompengine.acp.ProviderHttpAttempt")
        val owner = type.declaredConstructors.single().also { it.isAccessible = true }
            .newInstance(authority, System.nanoTime() + TimeUnit.SECONDS.toNanos(1), wire, body, receiver)
        val raw = field(owner, "raw") as AtomicReference<Socket?>
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val closed = AtomicBoolean()
        raw.set(object : Socket() {
            override fun close() { entered.countDown(); check(release.await(3, TimeUnit.SECONDS)); closed.set(true) }
            override fun isClosed(): Boolean = closed.get()
        })
        val finish = type.declaredMethods.single { it.name == "finishTransport" }.also { it.isAccessible = true }
        val error = AtomicReference<Throwable?>()
        val thread = Thread {
            try { finish.invoke(owner, null, AcpProviderTerminalKind.COMPLETED, receiver) }
            catch (failure: Throwable) { error.set(failure) }
        }.also { it.isDaemon = true; it.start() }
        try {
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            assertEquals(0, receiver.completed)
            assertFalse(closed.get())
        } finally { release.countDown(); thread.join(2000) }
        assertFalse(thread.isAlive); assertNull(error.get())
        assertTrue(closed.get()); assertEquals(1, receiver.completed)
        assertTrue(body.all { it == 0.toByte() }); assertTrue(wire.headers.isEmpty()); assertNull(wire.entity)
        assertNull((field(owner, "wire") as AtomicReference<*>).get())
        assertNull((field(owner, "receiver") as AtomicReference<*>).get())
        type.getDeclaredMethod("attach", java.util.concurrent.Future::class.java).also { it.isAccessible = true }
            .invoke(owner, CompletableFuture.completedFuture(Unit))
        val backendType = Class.forName("decompengine.acp.CoreAcpProviderBackend")
        val backend = backendType.declaredConstructors.single().also { it.isAccessible = true }.newInstance(authority)
        @Suppress("UNCHECKED_CAST") val owners = field(backend, "owners") as MutableList<Any>
        owners.add(owner)
        val snapshot = backendType.getDeclaredMethod("cleanupSnapshot").also { it.isAccessible = true }
            .invoke(backend) as AcpProviderConcreteBackendCleanupSnapshot
        assertEquals(1, snapshot.requestFutureCount); assertEquals(1, snapshot.terminalFutureCount)
        assertTrue(owners.isEmpty(), "terminal receiver/request remained in owner registry")
        assertTrue((backend as AcpProviderBrokerTestBackend).closeWithin(Duration.ofSeconds(1)))
    }

    @Test fun `terminal rejected owner releases wire secrets while cleanup counts remain exact`() {
        val body = "synthetic rejected body".toByteArray()
        val wire = BasicClassicHttpRequest("POST", URI("https://chatgpt.com/backend-api/codex/responses")).also {
            it.setHeader("Authorization", "Bearer synthetic-only")
            it.entity = ByteArrayEntity(body, ContentType.APPLICATION_JSON)
        }
        val authority = authority()
        val type = Class.forName("decompengine.acp.ProviderHttpAttempt")
        val constructor = type.declaredConstructors.single().also { it.isAccessible = true }
        val owner = if (constructor.parameterCount == 5) constructor.newInstance(authority, System.nanoTime() + TimeUnit.SECONDS.toNanos(1), wire, body, Receiver())
            else constructor.newInstance(authority, Duration.ofSeconds(1), wire, Receiver())
        type.getDeclaredMethod("notSubmitted").also { it.isAccessible = true }.invoke(owner)
        val backendType = Class.forName("decompengine.acp.CoreAcpProviderBackend")
        val backend = backendType.declaredConstructors.single().also { it.isAccessible = true }.newInstance(authority)
        @Suppress("UNCHECKED_CAST") val owners = field(backend, "owners") as MutableList<Any>
        owners.add(owner)
        try {
            val snapshotMethod = backendType.getDeclaredMethod("cleanupSnapshot").also { it.isAccessible = true }
            repeat(2) {
                val snapshot = snapshotMethod.invoke(backend) as AcpProviderConcreteBackendCleanupSnapshot
                assertEquals(1, snapshot.requestFutureCount); assertEquals(1, snapshot.terminalFutureCount)
                assertTrue(owners.isEmpty(), "terminal rejected owner was retained")
            }
            assertTrue(wire.headers.isEmpty()); assertNull(wire.entity)
            assertTrue(body.all { it == 0.toByte() })
        } finally { assertTrue((backend as AcpProviderBrokerTestBackend).closeWithin(Duration.ofSeconds(1))) }
    }

    private fun field(owner: Any, name: String): Any? = owner.javaClass.getDeclaredField(name).also { it.isAccessible = true }.get(owner)
    private fun byteStreamBacking(stream: ByteArrayOutputStream): ByteArray {
        // Inert test-only read of JDK protected storage, without opening JDK modules or adding a secret-returning API.
        val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").also { it.isAccessible = true }.get(null) as sun.misc.Unsafe
        return unsafe.getObject(stream, unsafe.objectFieldOffset(ByteArrayOutputStream::class.java.getDeclaredField("buf"))) as ByteArray
    }
    private fun policy(bounds: AcpProviderTransportBounds = AcpProviderTransportBounds()) = AcpProviderTransportPolicy.issueApproved(URI("https://chatgpt.com/backend-api/codex/responses"),
        "gpt-6.1-sol", AcpProviderReasoning.LOW, bounds)
    private fun authority(): Any = Class.forName("decompengine.acp.ChatGptAcpProviderNetworkAuthority")
        .declaredConstructors.single().also { it.isAccessible = true }.newInstance(policy())
    private fun open(backend: AcpProviderBrokerTestBackend, bounds: AcpProviderTransportBounds = AcpProviderTransportBounds()) = AcpProviderBroker.openForTesting(policy(bounds),
        AgentExecutionRequest("inert control", listOf(AgentWorkspaceRoot("fixture", Path.of(System.getProperty("user.dir")))),
            accessPolicy = AgentAccessPolicy(emptyList())), Duration.ofSeconds(2),
        AcpProviderCredentialMaterial.cachedChatGpt("synthetic_token", "synthetic_account"), backend)
    private class InertBackend : AcpProviderBrokerTestBackend {
        var starts = 0
        override fun start(request: AcpProviderBackendRequest, receiver: AcpProviderBackendReceiver): AcpProviderBackendRequestOwner {
            starts++; return object : AcpProviderBackendRequestOwner { override fun cancel() {} }
        }
        override fun closeWithin(timeout: Duration) = true
    }
    private class Receiver : AcpProviderBackendReceiver {
        @Volatile var completed = 0
        override fun headers(status: Int, headers: Map<String, List<String>>) = Unit
        override fun subscribe(subscription: Flow.Subscription) = Unit
        override fun bytes(buffers: List<ByteBuffer>) = Unit
        override fun complete() { completed++ }
        override fun failed() { error("unexpected inert transport failure") }
        override fun timedOut() { error("unexpected inert timeout") }
    }
}
