package decompengine.acp

import decompengine.agent.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.int
import java.net.URI
import java.nio.ByteBuffer
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.Flow
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.*
import org.junit.jupiter.api.Timeout

@Timeout(value = 20, unit = TimeUnit.SECONDS)
class AcpProviderBrokerTest {
    @Test
    fun `throwing cancellation callback revokes a stalled exchange without consumer progress`() {
        val failCallback = AtomicBoolean(false)
        val backend = FixtureBackend()
        val broker = open(backend, cancellation = AgentCancellation {
            if (failCallback.get()) throw IllegalStateException(TEST_TOKEN)
            false
        })
        try {
            broker.bindSession("actual-session", "turn-1")
            val exchange = broker.beginRequest(1, capability(broker), body())
            backend.headers(); backend.subscribe()
            failCallback.set(true)
            await { broker.snapshot().revoked }
            assertTrue(backend.cancelled)
            val failure = assertFailsWith<AcpProviderBrokerFailure> { exchange.nextChunk() }
            assertEquals(AcpProviderTerminalKind.TRANSPORT, failure.kind)
            assertNull(failure.cause)
            assertFalse(failure.toString().contains(TEST_TOKEN))
            assertEquals(AcpProviderTerminalKind.TRANSPORT, broker.snapshot().requests.single().terminal)
            assertEquals(1, backend.starts)
        } finally { broker.close() }
    }

    @Test
    fun `quoted output token limit is refused before backend dispatch`() {
        val backend = FixtureBackend()
        val broker = open(backend)
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            val malformed = body().decodeToString().dropLast(1) + ",\"max_output_tokens\":\"5\"}"
            assertKind(AcpProviderTerminalKind.UNSUPPORTED_OPERATION) { broker.beginRequest(1, cap, malformed.toByteArray()) }
            assertEquals(0, backend.starts)
            assertTrue(broker.snapshot().requests.isEmpty())
            assertEquals(AcpProviderTerminalKind.UNSUPPORTED_OPERATION, broker.snapshot().admissionDenial!!.terminal)
        } finally { broker.close() }
    }

    @Test
    fun `interrupted backend cleanup preserves cancellation and unverified cleanup`() {
        val backend = FixtureBackend(interruptCleanup = true)
        val broker = open(backend)
        try {
            assertFalse(Thread.currentThread().isInterrupted)
            assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
            assertTrue(broker.snapshot().revoked)
        } finally {
            Thread.interrupted()
            backend.interruptCleanup = false
            broker.close()
        }
    }

    @Test
    fun `interrupted lifecycle cleanup preserves cancellation and unverified cleanup`() {
        val broker = open(FixtureBackend())
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        // Keep the real owner alive through shutdownNow so awaitTermination, rather than only
        // backend cleanup, must observe the caller's interrupt. No production injection seam.
        val lifecycle = AcpProviderBroker::class.java.getDeclaredField("lifecycle").let {
            it.isAccessible = true
            it.get(broker) as ScheduledThreadPoolExecutor
        }
        lifecycle.execute {
            started.countDown()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (release.count > 0 && System.nanoTime() < deadline) {
                try { release.await(10, TimeUnit.MILLISECONDS) } catch (_: InterruptedException) { }
            }
        }
        try {
            assertTrue(started.await(1, TimeUnit.SECONDS))
            Thread.currentThread().interrupt()
            assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
        } finally {
            Thread.interrupted()
            release.countDown()
            broker.close()
        }
    }

    @Test
    fun `exactly exhausted input token budget refuses the next request before dispatch`() {
        val backend = FixtureBackend()
        val broker = open(backend, inputTokens = 1)
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            val first = broker.beginRequest(1, cap, body())
            backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
            assertNotNull(first.nextChunk()); assertNull(first.nextChunk())
            assertEquals(1, broker.snapshot().requests.single().inputTokens)
            assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { broker.beginRequest(2, cap, body()) }
            assertEquals(1, backend.starts)
            assertEquals(AcpProviderTerminalKind.RESOURCE_EXHAUSTED, broker.snapshot().admissionDenial!!.terminal)
            assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
        } finally { broker.close() }
    }

    @Test
    fun `completed final chunk freezes evidence before a later cancellation close or callback`() {
        for (scenario in 0..3) {
            val backend = FixtureBackend()
            val cancelled = AgentCancellationSource()
            val broker = open(backend, cancellation = cancelled.cancellation)
            try {
                broker.bindSession("actual-session", "turn-1")
                val exchange = broker.beginRequest(1, capability(broker), body())
                backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
                assertNotNull(exchange.nextChunk())
                assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
                when (scenario) {
                    0 -> { cancelled.cancel(); await { broker.snapshot().revoked } }
                    1 -> broker.close()
                    2 -> exchange.cancel()
                    else -> backend.receiver!!.failed()
                }
                assertNull(exchange.nextChunk())
                assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
                assertEquals(1, broker.snapshot().requests.size)
            } finally { broker.close() }
        }
    }

    @Test
    fun `validated completion with undelivered chunks remains cancellable`() {
        val backend = FixtureBackend()
        val broker = open(backend)
        try {
            broker.bindSession("actual-session", "turn-1")
            val exchange = broker.beginRequest(1, capability(broker), body())
            backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
            exchange.cancel()
            assertKind(AcpProviderTerminalKind.CANCELLED) { exchange.nextChunk() }
            assertEquals(AcpProviderTerminalKind.CANCELLED, broker.snapshot().requests.single().terminal)
        } finally { broker.close() }
    }

    @Test
    fun `released completed exchange cannot revoke the next request through stale callbacks`() {
        val backend = FixtureBackend()
        val broker = open(backend, inputTokens = 2)
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            val first = broker.beginRequest(1, cap, body())
            val firstReceiver = backend.receiver!!
            backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
            assertNotNull(first.nextChunk())
            val second = broker.beginRequest(2, cap, body())
            firstReceiver.failed()
            first.cancel()
            assertFalse(broker.snapshot().revoked)
            assertFalse(backend.cancelled)
            assertNull(first.nextChunk())
            backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
            assertNotNull(second.nextChunk())
            assertEquals(listOf(AcpProviderTerminalKind.COMPLETED, AcpProviderTerminalKind.COMPLETED), broker.snapshot().requests.map { it.terminal })
            assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { broker.beginRequest(3, cap, body()) }
            assertEquals(2, backend.starts)
        } finally { broker.close() }
    }

    @Test
    fun `multi chunk completion freezes only after its final EOF validated chunk is delivered`() {
        for (cancelBeforeLast in listOf(true, false)) {
            val backend = FixtureBackend()
            val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumChunkBytes = 256, maximumQueuedChunks = 2)))
            try {
                broker.bindSession("actual-session", "turn-1")
                val exchange = broker.beginRequest(1, capability(broker), body())
                backend.headers(); backend.subscribe()
                // The suffix is a credential prefix, so this entire delta stays quarantined
                // until actual upstream EOF disproves continuation of the synthetic secret.
                backend.emit(delta("x".repeat(70) + "s")); backend.emit(completed(3)); backend.complete()
                assertEquals(256, exchange.nextChunk()!!.size)
                assertTrue(broker.snapshot().requests.isEmpty(), "one undelivered chunk cannot be recorded as delivered completion")
                if (cancelBeforeLast) {
                    exchange.cancel()
                    assertKind(AcpProviderTerminalKind.CANCELLED) { exchange.nextChunk() }
                    assertEquals(AcpProviderTerminalKind.CANCELLED, broker.snapshot().requests.single().terminal)
                } else {
                    val last = exchange.nextChunk()!!
                    assertTrue(last.size in 1..255)
                    assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
                    broker.close()
                    assertNull(exchange.nextChunk())
                    assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
                }
            } finally { broker.close() }
        }
    }

    @Test
    fun `disabled policy missing credentials and excessive enclosing duration create no backend request`() {
        val backend = FixtureBackend()
        assertFailsWith<AcpProviderBrokerFailure> { open(backend, policy = AcpProviderTransportPolicy.DISABLED) }
        assertFailsWith<AcpProviderBrokerFailure> { open(backend, credentials = null) }
        assertFailsWith<IllegalArgumentException> { open(backend, remaining = Duration.ZERO) }
        assertFailsWith<IllegalArgumentException> { open(backend, remaining = Duration.ofSeconds(20)) }
        assertEquals(0, backend.starts)
        assertEquals(0, backend.closes)
    }

    @Test
    fun `routing operation model reasoning and duplicate JSON are refused before dispatch`() {
        for (scenario in 0..7) {
            val backend = FixtureBackend()
            val broker = open(backend)
            try {
                broker.bindSession("actual-session", "turn-1")
                val cap = capability(broker)
                val expected = when (scenario) {
                    2, 6 -> AcpProviderTerminalKind.UNSUPPORTED_MODEL
                    5 -> AcpProviderTerminalKind.MALFORMED_REQUEST
                    else -> AcpProviderTerminalKind.UNSUPPORTED_OPERATION
                }
                assertKind(expected) {
                    when (scenario) {
                        0 -> broker.beginRequest(1, cap, body(), requestedEndpoint = "https://example.invalid/responses")
                        1 -> broker.beginRequest(1, cap, body(), requestedOperation = "MODEL_LIST")
                        2 -> broker.beginRequest(1, cap, body(model = "other-model"))
                        3 -> broker.beginRequest(1, cap, body(effort = "high"))
                        4 -> broker.beginRequest(1, cap, body().decodeToString().dropLast(1).plus(",\"service_tier\":\"priority\"}").toByteArray())
                        5 -> broker.beginRequest(1, cap, body().decodeToString().dropLast(1).plus(",\"model\":\"gpt-6.1-sol\"}").toByteArray())
                        6 -> broker.beginRequest(1, cap, body().decodeToString().replace("\"gpt-6.1-sol\"", "{}").toByteArray())
                        else -> broker.beginRequest(1, cap, body().decodeToString().replace("\"stream\":true", "\"stream\":\"true\"").toByteArray())
                    }
                }
                assertTrue(broker.snapshot().revoked)
                assertEquals(expected, broker.snapshot().admissionDenial!!.terminal)
                assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(1, cap, body()) }
                assertEquals(0, backend.starts)
                assertTrue(broker.snapshot().requests.isEmpty(), "a denial has no invented wire receipt")
            } finally { broker.close() }
        }
    }

    @Test
    fun `session capability and strict request sequence precede every backend side effect`() {
        for (scenario in 0..4) {
            val backend = FixtureBackend()
            val broker = open(backend)
            val other = open(FixtureBackend())
            try {
                val cap = capability(broker)
                if (scenario != 0) broker.bindSession("actual-session", "turn-1")
                if (scenario >= 3) broker.beginRequest(1, cap, body())
                assertKind(AcpProviderTerminalKind.REVOKED) {
                    when (scenario) {
                        0 -> broker.beginRequest(1, cap, body())
                        1 -> broker.beginRequest(1, capability(other), body())
                        2 -> broker.beginRequest(2, cap, body())
                        3 -> broker.beginRequest(1, cap, body())
                        else -> broker.beginRequest(2, cap, body())
                    }
                }
                assertTrue(broker.snapshot().revoked)
                assertEquals(if (scenario >= 3) 1 else 0, backend.starts)
                assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(1, cap, body()) }
            } finally { broker.close(); other.close() }
        }
    }

    @Test
    fun `declared output budget comes from admitted request and streams obey demand`() {
        val backend = FixtureBackend()
        val broker = open(backend, outputTokens = 5)
        try {
            broker.bindSession("actual-session", "turn-1")
            val exchange = broker.beginRequest(1, capability(broker), body())
            assertEquals(5, Json.parseToJsonElement(backend.lastRequest!!.body.decodeToString()).jsonObject.getValue("max_output_tokens").jsonPrimitive.int)
            backend.headers()
            backend.subscribe()
            assertEquals(1L, backend.demand)
            // '!' cannot continue the token/account prefixes or the random capability hex.
            backend.emit(delta("safe candidate!"))
            assertEquals(0L, backend.demand, "a queued chunk must apply backpressure")
            assertEquals(200, exchange.awaitHeaders().status)
            assertTrue(exchange.nextChunk()!!.decodeToString().contains("safe candidate!"))
            assertEquals(1L, backend.demand)
            backend.emit(completed(3))
            backend.complete()
            assertNotNull(exchange.nextChunk())
            assertNull(exchange.nextChunk())
            val evidence = broker.snapshot()
            assertEquals(3L, evidence.outputTokens)
            assertEquals(AcpProviderTerminalKind.COMPLETED, evidence.requests.single().terminal)
            assertNotEquals(evidence.requests.single().admittedBodySha256, evidence.requests.single().wireBodySha256)
            assertFalse(evidence.adapterQualified)
            assertFalse(evidence.providerCostCancellationProven)
        } finally { broker.close() }
    }

    @Test
    fun `capability prefix quarantine requests one bounded item until disproof or secret refusal`() {
        for (completeSecret in listOf(false, true)) {
            val backend = FixtureBackend()
            val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumChunkBytes = 256, maximumQueuedChunks = 1)))
            try {
                broker.bindSession("actual-session", "turn-1")
                val cap = capability(broker)
                val capabilityText = cap.joinToString("") { "%02x".format(it) }
                val exchange = broker.beginRequest(1, cap, body())
                backend.headers(); backend.subscribe()
                val heldEvent = delta(capabilityText.take(32))
                backend.emit(heldEvent)
                assertEquals(1L, backend.demand, "held prefix permits exactly one further bounded item")
                if (completeSecret) {
                    backend.emit(delta(capabilityText.drop(32)))
                    assertKind(AcpProviderTerminalKind.SECRET_EXPOSURE) { exchange.nextChunk() }
                    assertEquals(0L, backend.demand)
                    assertTrue(backend.cancelled)
                    assertEquals(AcpProviderTerminalKind.SECRET_EXPOSURE, broker.snapshot().requests.single().terminal)
                } else {
                    val disproof = delta("!")
                    backend.emit(disproof)
                    assertEquals(0L, backend.demand, "disproved prefix is now queued and applies backpressure")
                    assertContentEquals(heldEvent + disproof, exchange.nextChunk())
                    assertEquals(1L, backend.demand)
                    backend.emit(completed(1)); backend.complete()
                    assertNotNull(exchange.nextChunk()); assertNull(exchange.nextChunk())
                    assertEquals(AcpProviderTerminalKind.COMPLETED, broker.snapshot().requests.single().terminal)
                }
                assertEquals(1, backend.starts, "quarantine progress must not dispatch another provider request")
            } finally { broker.close() }
        }
    }

    @Test
    fun `all capability first nibbles distinguish quarantined prefixes from publishable chunks`() {
        for (nibble in "0123456789abcdef") {
            val syntheticCapability = "$nibble" + "0".repeat(63)
            fun stream() = AcpProviderResponseStream(
                AcpProviderTransportBounds(maximumChunkBytes = 256, maximumQueuedChunks = 1),
                listOf(TEST_TOKEN.toByteArray(), "fixture_account".toByteArray(), syntheticCapability.toByteArray()),
                maximumRemainingOutputTokens = 5,
            )
            for (publishable in listOf(false, true)) {
                val parser = stream()
                val event = delta(if (publishable) "safe candidate!" else "safe candidate")
                val held = !publishable && nibble == 'e'
                val firstRelease = parser.accept(event)
                if (held) assertTrue(firstRelease.isEmpty()) else assertContentEquals(event, firstRelease.single())
                val disproof = delta("!")
                val afterDisproof = parser.accept(disproof)
                if (held) {
                    assertEquals(2, afterDisproof.size)
                    assertContentEquals(event, afterDisproof[0])
                    assertContentEquals(disproof, afterDisproof[1])
                } else assertContentEquals(disproof, afterDisproof.single())
                assertTrue(parser.accept(completed(1)).isEmpty())
                parser.finish()
                assertEquals(1, parser.drainFinished().size)
            }
            val refusing = stream()
            assertTrue(refusing.accept(delta(syntheticCapability.take(32))).isEmpty())
            assertEquals(AcpProviderTerminalKind.SECRET_EXPOSURE,
                assertFailsWith<AcpProviderStreamFailure> { refusing.accept(delta(syntheticCapability.drop(32))) }.kind)
        }
    }

    @Test
    fun `response token quota is invocation cumulative`() {
        val backend = FixtureBackend()
        val broker = open(backend, outputTokens = 5)
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            var exchange = broker.beginRequest(1, cap, body())
            backend.headers(); backend.subscribe(); backend.emit(completed(3)); backend.complete()
            assertNotNull(exchange.nextChunk()); assertNull(exchange.nextChunk())
            exchange = broker.beginRequest(2, cap, body())
            assertEquals(2, Json.parseToJsonElement(backend.lastRequest!!.body.decodeToString()).jsonObject.getValue("max_output_tokens").jsonPrimitive.int)
            backend.headers(); backend.subscribe(); backend.emit(completed(3)); backend.complete()
            assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { exchange.nextChunk() }
            assertTrue(broker.snapshot().revoked)
        } finally { broker.close() }
    }

    @Test
    fun `wire request byte budget does not reset after completed exchange`() {
        val backend = FixtureBackend()
        val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumRequestBytes = 256)))
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            val first = broker.beginRequest(1, cap, body())
            backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
            assertNotNull(first.nextChunk()); assertNull(first.nextChunk())
            assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { broker.beginRequest(2, cap, body()) }
            assertEquals(1, backend.starts)
        } finally { broker.close() }
    }

    @Test
    fun `response byte budget does not reset after completed exchange`() {
        val backend = FixtureBackend()
        val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumResponseBytes = 300, maximumChunkBytes = 256)))
        try {
            broker.bindSession("actual-session", "turn-1")
            val cap = capability(broker)
            var observed = 0
            var sequence = 1L
            while (observed + completed(1).size <= 300) {
                val exchange = broker.beginRequest(sequence++, cap, body())
                backend.headers(); backend.subscribe(); backend.emit(completed(1)); backend.complete()
                assertNotNull(exchange.nextChunk()); assertNull(exchange.nextChunk())
                observed += completed(1).size
            }
            val refused = broker.beginRequest(sequence, cap, body())
            backend.headers(); backend.subscribe(); backend.emit(completed(1))
            assertKind(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) { refused.nextChunk() }
            assertTrue(broker.snapshot().revoked)
        } finally { broker.close() }
    }

    @Test
    fun `malformed Unicode session identities are refused without replacement hashing`() {
        val backend = FixtureBackend()
        val broker = open(backend)
        try {
            val failure = assertFailsWith<IllegalArgumentException> { broker.bindSession("bad\uD800", "turn-1") }
            assertNull(failure.cause)
            assertFalse(failure.message!!.contains("bad"))
            assertFailsWith<IllegalArgumentException> { broker.bindSession("session", "bad\uDC00") }
            broker.bindSession("valid-session", "valid-turn")
            assertEquals(0, backend.starts)
        } finally { broker.close() }
    }

    @Test
    fun `concrete HTTP transport and lifecycle terminate without any provider request`() {
        val request = AgentExecutionRequest("construct and close host owner only", listOf(AgentWorkspaceRoot("fixture", Path.of(System.getProperty("user.dir")))),
            accessPolicy = AgentAccessPolicy(emptyList()), limits = AgentExecutionLimits(wallClockTimeout = Duration.ofSeconds(10)))
        val broker = AcpProviderBroker.openForProtectedQualification(policy(), request, Duration.ofSeconds(2),
            AcpProviderCredentialMaterial.cachedChatGpt(TEST_TOKEN, "fixture_account"))
        assertEquals(AcpProviderBrokerCleanup.NOT_ATTEMPTED, broker.snapshot().cleanup)
        broker.close()
        assertEquals(AcpProviderBrokerCleanup.VERIFIED, broker.snapshot().cleanup)
        assertEquals(0L, broker.snapshot().wireRequestBytes)
        assertTrue(broker.snapshot().requests.isEmpty())
        assertFalse(broker.snapshot().adapterQualified)
    }

    @Test
    fun `raw upstream authentication error body is never exposed or retained`() {
        val backend = FixtureBackend()
        val broker = open(backend)
        try {
            broker.bindSession("actual-session", "turn-1")
            val exchange = broker.beginRequest(1, capability(broker), body())
            backend.receiver!!.headers(401, mapOf("content-type" to listOf("application/json"), "x-secret" to listOf(TEST_TOKEN)))
            backend.receiver!!.bytes(listOf(ByteBuffer.wrap(("error=" + TEST_TOKEN).toByteArray())))
            val failure = assertFailsWith<AcpProviderBrokerFailure> { exchange.awaitHeaders() }
            assertEquals(AcpProviderTerminalKind.AUTHENTICATION, failure.kind)
            assertFalse(failure.toString().contains(TEST_TOKEN))
            assertNull(failure.cause)
            assertEquals(0L, broker.snapshot().responseBytes)
            assertEquals(AcpProviderTerminalKind.AUTHENTICATION, broker.snapshot().requests.single().terminal)
        } finally { broker.close() }
    }

    @Test
    fun `successful response secret split is refused before any candidate chunk`() {
        val backend = FixtureBackend()
        val broker = open(backend)
        try {
            broker.bindSession("actual-session", "turn-1")
            val exchange = broker.beginRequest(1, capability(broker), body())
            backend.headers(); backend.subscribe()
            backend.emit(delta(TEST_TOKEN.take(8)))
            assertEquals(1L, backend.demand, "quarantined prefix allows one further bounded network item")
            backend.emit(delta(TEST_TOKEN.drop(8)))
            assertKind(AcpProviderTerminalKind.SECRET_EXPOSURE) { exchange.nextChunk() }
            assertTrue(broker.snapshot().revoked)
            assertEquals(AcpProviderTerminalKind.SECRET_EXPOSURE, broker.snapshot().requests.single().terminal)
        } finally { broker.close() }
    }

    @Test
    fun `cancellation revokes stalled consumer and cleanup failure retains owner`() {
        val cancelled = AgentCancellationSource()
        val backend = FixtureBackend(clean = false)
        val broker = open(backend, cancellation = cancelled.cancellation)
        broker.bindSession("actual-session", "turn-1")
        val cap = capability(broker)
        broker.beginRequest(1, cap, body())
        backend.headers(); backend.subscribe()
        cancelled.cancel()
        await { broker.snapshot().revoked }
        assertTrue(backend.cancelled)
        assertEquals(AcpProviderTerminalKind.CANCELLED, broker.snapshot().requests.single().terminal)
        assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
        assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
        assertKind(AcpProviderTerminalKind.REVOKED) { broker.beginRequest(2, cap, body()) }
        backend.clean = true
        broker.close()
        assertEquals(AcpProviderBrokerCleanup.VERIFIED, broker.snapshot().cleanup)
    }

    @Test
    fun `deadline and idle expiry revoke without response consumer progress`() {
        val backend = FixtureBackend()
        val bounds = AcpProviderTransportBounds(overallTimeout = Duration.ofMillis(150), idleTimeout = Duration.ofMillis(20), cleanupTimeout = Duration.ofMillis(100))
        val broker = open(backend, policy = policy(bounds), remaining = Duration.ofMillis(100))
        try {
            broker.bindSession("actual-session", "turn-1")
            broker.beginRequest(1, capability(broker), body())
            backend.headers(); backend.subscribe()
            await { broker.snapshot().revoked }
            assertTrue(backend.cancelled)
            assertEquals(AcpProviderTerminalKind.TIMEOUT, broker.snapshot().requests.single().terminal)
        } finally { broker.close() }
    }

    @Test
    fun `header caps streaming queue overflow and invalid content type refuse publication`() {
        for (scenario in 0..2) {
            val backend = FixtureBackend()
            val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumQueuedChunks = 1, maximumHeaderBytes = 64)))
            try {
                broker.bindSession("actual-session", "turn-1")
                val exchange = broker.beginRequest(1, capability(broker), body())
                when (scenario) {
                    0 -> backend.receiver!!.headers(200, mapOf("huge" to listOf("x".repeat(65))))
                    1 -> backend.receiver!!.headers(200, mapOf("content-type" to listOf("text/plain")))
                    else -> { backend.headers(); backend.subscribe(); backend.emit(delta("x".repeat(32768)) + delta("y".repeat(32768))) }
                }
                val failure = assertFailsWith<AcpProviderBrokerFailure> { exchange.nextChunk() }
                assertEquals(if (scenario == 1) AcpProviderTerminalKind.MALFORMED_RESPONSE else AcpProviderTerminalKind.RESOURCE_EXHAUSTED, failure.kind)
                assertTrue(broker.snapshot().revoked)
            } finally { broker.close() }
        }
    }

    @Test
    fun `multiple small events in one network batch coalesce without false overflow`() {
        val backend = FixtureBackend()
        val broker = open(backend, policy = policy(AcpProviderTransportBounds(maximumQueuedChunks = 1)))
        try {
            broker.bindSession("actual-session", "turn-1")
            val exchange = broker.beginRequest(1, capability(broker), body())
            backend.headers(); backend.subscribe()
            backend.emit(delta("one") + delta("two") + delta("three") + completed(1))
            assertFalse(broker.snapshot().revoked)
            backend.complete()
            val combined = exchange.nextChunk()!!.decodeToString()
            assertTrue(combined.contains("one") && combined.contains("two") && combined.contains("three") && combined.contains("response.completed"))
            assertNull(exchange.nextChunk())
        } finally { broker.close() }
    }

    private fun open(
        backend: FixtureBackend,
        policy: AcpProviderTransportPolicy = policy(),
        credentials: AcpProviderCredentialMaterial? = AcpProviderCredentialMaterial.cachedChatGpt(TEST_TOKEN, "fixture_account"),
        remaining: Duration = Duration.ofSeconds(2),
        outputTokens: Long? = null,
        inputTokens: Long? = null,
        cancellation: AgentCancellation = AgentCancellation.NONE,
    ): AcpProviderBroker = AcpProviderBroker.openForTesting(
        policy,
        AgentExecutionRequest("credential-free broker control", listOf(AgentWorkspaceRoot("fixture", Path.of(System.getProperty("user.dir")))),
            accessPolicy = AgentAccessPolicy(emptyList()), limits = AgentExecutionLimits(wallClockTimeout = Duration.ofSeconds(10), maxOutputTokens = outputTokens, maxInputTokens = inputTokens), cancellation = cancellation),
        remaining, credentials, backend,
    )

    private fun policy(bounds: AcpProviderTransportBounds = AcpProviderTransportBounds()): AcpProviderTransportPolicy.Approved =
        AcpProviderTransportPolicy.issueApproved(URI("https://chatgpt.com/backend-api/codex/responses"), "gpt-6.1-sol", AcpProviderReasoning.LOW, bounds)

    private fun capability(broker: AcpProviderBroker): ByteArray = AcpProviderBrokerProtocol.decodeChannelSetupPayload(broker.channelSetupPayload()).capability
    private fun body(model: String = "gpt-6.1-sol", effort: String = "low"): ByteArray =
        """{"model":"$model","input":[{"role":"user","content":"synthetic fixture"}],"reasoning":{"effort":"$effort"},"store":false,"stream":true}""".toByteArray()
    private fun delta(text: String): ByteArray = ("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":" + kotlinx.serialization.json.JsonPrimitive(text).toString() + "}\n\n").toByteArray()
    private fun completed(tokens: Int): ByteArray = """event: response.completed
data: {"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":1,"output_tokens":$tokens}}}

""".toByteArray()
    private fun assertKind(kind: AcpProviderTerminalKind, action: () -> Unit) = assertEquals(kind, assertFailsWith<AcpProviderBrokerFailure>(block = action).kind)
    private fun await(condition: () -> Boolean) {
        val stop = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (!condition() && System.nanoTime() < stop) Thread.sleep(2)
        assertTrue(condition(), "bounded lifecycle control did not finish")
    }

    private class FixtureBackend(var clean: Boolean = true, var interruptCleanup: Boolean = false) : AcpProviderBrokerTestBackend {
        var starts = 0
        var closes = 0
        @Volatile var cancelled = false
        var receiver: AcpProviderBackendReceiver? = null
        var lastRequest: AcpProviderBackendRequest? = null
        var demand = 0L
        override fun start(request: AcpProviderBackendRequest, receiver: AcpProviderBackendReceiver): AcpProviderBackendRequestOwner {
            starts++; this.receiver = receiver; lastRequest = request; cancelled = false; demand = 0
            return object : AcpProviderBackendRequestOwner { override fun cancel() { cancelled = true } }
        }
        override fun closeWithin(timeout: Duration): Boolean {
            closes++
            if (interruptCleanup) throw InterruptedException("synthetic cleanup interruption")
            return clean
        }
        fun headers() = receiver!!.headers(200, mapOf("content-type" to listOf("text/event-stream")))
        fun subscribe() = receiver!!.subscribe(object : Flow.Subscription {
            override fun request(n: Long) { demand += n }
            override fun cancel() { cancelled = true }
        })
        fun emit(bytes: ByteArray) { check(demand > 0); demand--; receiver!!.bytes(listOf(ByteBuffer.wrap(bytes))) }
        fun complete() = receiver!!.complete()
    }

    private companion object { const val TEST_TOKEN = "synthetic-provider-secret-canary" }
}
