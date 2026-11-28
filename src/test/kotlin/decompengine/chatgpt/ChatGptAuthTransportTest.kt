package decompengine.chatgpt

import java.net.http.*
import java.nio.ByteBuffer
import java.util.concurrent.*
import java.util.concurrent.atomic.*
import kotlin.test.*

class ChatGptAuthTransportTest {

    @Test fun trustedExpiryAfterSubscriptionInstallIsCheckedBeforeDemand() {
        val time = AuthTestClock(); val port = AuthScriptPort()
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val armed = AtomicBoolean()
        val samples = AtomicInteger()
        val transport = newChatGptAuthTransport(port, {
            if (Thread.currentThread().name == "chatgpt-auth-reaper" && armed.compareAndSet(true, false)) {
                entered.countDown(); authAwait(release)
            }
            if (Thread.currentThread().stackTrace.any { it.className.contains("AuthCall") && it.methodName == "onSubscribe" } &&
                samples.incrementAndGet() == 2) time.advance(10)
            time.nanos.get()
        }, time.now::get)
        port.scripts.add(AuthScript(action = { }))
        val call = transport.prepareDiscovery(time.operation()); call.start(authGate())
        try {
            armed.set(true); authAwait(entered)
            val exchange = port.exchanges.single(); exchange.subscribe()
            assertEquals(2, samples.get()); assertEquals(0, exchange.demands.get())
            assertTrue(exchange.cancellations.get() > 0)
        } finally { release.countDown(); authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED } }
    }

    @Test fun discoveryWaitsForDelayedPhysicalAcknowledgement() = delayedPhysicalAck(ChatGptAuthHttpPurpose.DISCOVERY)
    @Test fun jwksWaitsForDelayedPhysicalAcknowledgement() = delayedPhysicalAck(ChatGptAuthHttpPurpose.JWKS)
    @Test fun codeWaitsForDelayedPhysicalAcknowledgementAndProvesRealRsa() = delayedPhysicalAck(ChatGptAuthHttpPurpose.CODE)
    @Test fun refreshWaitsForDelayedPhysicalAcknowledgement() = delayedPhysicalAck(ChatGptAuthHttpPurpose.REFRESH)
    @Test fun revokeWaitsForDelayedPhysicalAcknowledgement() = delayedPhysicalAck(ChatGptAuthHttpPurpose.REVOCATION)
    private fun delayedPhysicalAck(purpose: ChatGptAuthHttpPurpose): Unit = AuthTestRig().use { rig ->
        val ready = CountDownLatch(1); val consumed = CountDownLatch(1)
        val failure = AtomicReference<Throwable>(); val outcome = AtomicReference<ChatGptAuthHttpOutcome>()
        val reference = AtomicReference<ChatGptAuthHttpCall>()
        val key = AuthSigningKey()
        val before = AtomicInteger()
        val worker = Thread({
            try {
                val operation = rig.clock.operation()
                val bound = if (purpose == ChatGptAuthHttpPurpose.CODE) authBound(rig) else null
                val endpoint = if (purpose == ChatGptAuthHttpPurpose.REVOCATION) {
                    rig.port.scripts.add(AuthScript(authDiscovery("https://auth.openai.com/oauth/revoke")))
                    rig.metadata.discovery(operation).revocation!!
                } else null
                val bytes = when (purpose) {
                    ChatGptAuthHttpPurpose.DISCOVERY -> authDiscovery()
                    ChatGptAuthHttpPurpose.JWKS -> key.jwks()
                    ChatGptAuthHttpPurpose.CODE -> key.response(bound!!.code, rig.clock.now.get())
                    ChatGptAuthHttpPurpose.REFRESH -> "{}".toByteArray()
                    ChatGptAuthHttpPurpose.REVOCATION -> ByteArray(0)
                }
                before.set(rig.port.submitted.get())
                rig.port.settled.set(false); rig.port.scripts.add(AuthScript(bytes))
                val call = when (purpose) {
                    ChatGptAuthHttpPurpose.DISCOVERY -> rig.transport.prepareDiscovery(operation)
                    ChatGptAuthHttpPurpose.JWKS -> rig.transport.prepareJwks(operation)
                    ChatGptAuthHttpPurpose.CODE -> rig.transport.prepareCode(bound!!.binding, bound.code, operation)
                    ChatGptAuthHttpPurpose.REFRESH -> rig.transport.prepareRefresh("oaiapp_test", "synthetic-refresh", operation)
                    ChatGptAuthHttpPurpose.REVOCATION -> rig.transport.prepareRevocation(endpoint!!,
                        ChatGptLocalLogout(ChatGptPlanAccount("ack-account", ChatGptPlanOidc.ISSUER, "oaiapp_test", "Ack",
                            null, null, 0, 0, ChatGptPlanAccount.State.SIGNED_OUT, emptySet(), null), "oaiapp_test", "synthetic-refresh", false), operation)
                }
                reference.set(call); call.start(authGate()); ready.countDown()
                val result = call.await(); outcome.set(result)
                assertEquals(before.get() + 1, rig.port.submitted.get())
                assertEquals(0, authTransportCount(rig.transport, "calls"))
                when (purpose) {
                    ChatGptAuthHttpPurpose.DISCOVERY, ChatGptAuthHttpPurpose.JWKS -> {
                        val document = assertIs<ChatGptAuthHttpOutcome.Document>(result).reply
                        assertEquals(1, authTransportCount(rig.transport, "permits"))
                        if (purpose == ChatGptAuthHttpPurpose.DISCOVERY) document.discovery(operation) else document.jwks(operation)
                        document.discard()
                    }
                    ChatGptAuthHttpPurpose.CODE -> {
                        val reply = assertIs<ChatGptAuthHttpOutcome.Token>(result).reply
                        assertEquals(1, authTransportCount(rig.transport, "permits"))
                        rig.port.scripts.add(AuthScript(key.jwks()))
                        assertTrue(rig.metadata.validateAuthorization(reply, operation).registration.subject == "test-subject")
                    }
                    ChatGptAuthHttpPurpose.REFRESH -> {
                        val reply = assertIs<ChatGptAuthHttpOutcome.Token>(result).reply
                        assertEquals(1, authTransportCount(rig.transport, "permits")); reply.discard()
                    }
                    ChatGptAuthHttpPurpose.REVOCATION -> assertIs<ChatGptAuthHttpOutcome.Revoked>(result)
                }
                assertEquals(0, authTransportCount(rig.transport, "permits"))
            } catch (e: Throwable) { failure.set(e) }
            finally { consumed.countDown(); ready.countDown() }
        }, "chatgpt-auth-delayed-positive-owner")
        worker.start()
        try {
            authAwait(ready)
            failure.get()?.let { throw it }
            authEventually { worker.state == Thread.State.TIMED_WAITING && worker.stackTrace.any {
                it.className == "decompengine.chatgpt.AuthCall" && it.methodName == "settle"
            } }
            assertNull(outcome.get(), "await started before physical acknowledgement")
            assertEquals(1, authTransportCount(rig.transport, "calls"))
            rig.port.settled.set(true)
            authAwait(consumed); authJoin(worker)
            failure.get()?.let { throw it }
            assertNotNull(outcome.get())
            assertEquals(ChatGptAuthSettlement.SETTLED, reference.get().cancelAndSettle(0))
        } finally { rig.port.settled.set(true); authJoin(worker) }
    }

    @Test fun firstPositiveCleanupWaitsForAsynchronousAckWithoutReaperProgress() {
        val time = AuthTestClock(); val port = AuthScriptPort(); port.settled.set(false)
        val transport = newChatGptAuthTransport(port, time.nanos::get, time.now::get)
        port.scripts.add(AuthScript(action = { }))
        val call = transport.prepareDiscovery(time.operation()); call.start(authGate())
        val result = AtomicReference<ChatGptAuthSettlement>()
        val closer = Thread({ result.set(call.cancelAndSettle(250_000_000L)) }, "chatgpt-auth-positive-cancel")
        try {
            closer.start()
            authEventually { closer.state == Thread.State.TIMED_WAITING && closer.stackTrace.any { it.methodName == "settle" } }
            assertNull(result.get()); port.settled.set(true); authJoin(closer)
            assertEquals(ChatGptAuthSettlement.SETTLED, result.get())
        } finally { port.settled.set(true); authJoin(closer); authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED } }
    }

    @Test fun independentTransportProbeCannotExpireLiveTrustedOperation(): Unit = AuthTestRig().use { rig ->
        rig.clock.nanos.set(Long.MIN_VALUE)
        rig.port.scripts.add(AuthScript(authDiscovery()))
        val op = rig.clock.operation(); val call = rig.transport.prepareDiscovery(op)
        call.start(authGate())
        val reply = assertIs<ChatGptAuthHttpOutcome.Document>(call.await()).reply
        reply.discovery(op); reply.discard()
    }
    @Test fun productionAlwaysDeniedEvenAfterEntryAndLateProperties() {
        ChatGptAuthProduction.recordProcessEntry()
        authFailure(ChatGptAuthHttpFailure.RUNTIME_UNQUALIFIED) { ChatGptAuthProduction.production() }
        authFailure(ChatGptAuthHttpFailure.RUNTIME_UNQUALIFIED) { ChatGptAuthProduction.metadata() }
    }
    @Test fun prepareIsInertAndInlineCompletionSettlesOneRegisteredCall(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(AuthScript())
        val call = rig.transport.prepareDiscovery(rig.clock.operation())
        assertEquals(0, rig.port.acquired.get())
        rig.port.sendHook = { assertEquals(ChatGptAuthDispatchEvidence.MAY_HAVE_BEEN_SENT, call.dispatchEvidence) }
        call.start(authGate())
        assertTrue(call.await() is ChatGptAuthHttpOutcome.Document)
        assertEquals(1, rig.port.submitted.get())
        assertEquals(ChatGptAuthSettlement.SETTLED, call.cancelAndSettle(250_000_000))
        assertEquals(ChatGptAuthHttpFailure.ALREADY_USED, (call.await() as ChatGptAuthHttpOutcome.Failed).failure)
    }
    @Test fun synchronousSendThrowIsAmbiguousAndCauseFree(): Unit = AuthTestRig().use { rig ->
        rig.port.sendHook = { error("synthetic private detail") }
        val call = rig.transport.prepareDiscovery(rig.clock.operation())
        call.start(authGate())
        assertEquals(ChatGptAuthDispatchEvidence.MAY_HAVE_BEEN_SENT, call.dispatchEvidence)
        assertEquals(ChatGptAuthHttpFailure.TLS_OR_IO, (call.await() as ChatGptAuthHttpOutcome.Failed).failure)
        assertEquals(1, rig.port.submitted.get())
    }
    @Test fun cancelledBeforeStartNeverAcquiresOrClaimsGate(): Unit = AuthTestRig().use { rig ->
        val call = rig.transport.prepareDiscovery(rig.clock.operation())
        call.cancel(); call.start(authGate { fail("gate must not run") })
        assertTrue(call.await() is ChatGptAuthHttpOutcome.Failed)
        assertEquals(0, rig.port.acquired.get()); assertEquals(0, rig.port.submitted.get())
        assertEquals(ChatGptAuthDispatchEvidence.NOT_SUBMITTED, call.dispatchEvidence)
    }
    @Test fun gateDenialAndRepeatedStartNeverResubmit(): Unit = AuthTestRig().use { rig ->
        val claims = AtomicInteger()
        val call = rig.transport.prepareDiscovery(rig.clock.operation())
        call.start(authGate { claims.incrementAndGet(); false })
        authFailure(ChatGptAuthHttpFailure.ALREADY_USED) { call.start(authGate { claims.incrementAndGet(); true }) }
        assertEquals(1, claims.get()); assertEquals(0, rig.port.submitted.get())
        call.await()
    }
    @Test fun acquireCancellationRetainsSlotUntilLateResourceAcknowledges(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val ref = AtomicReference<ChatGptAuthHttpCall>()
        rig.port.acquireHook = { entered.countDown(); authAwait(release) }
        val worker = Thread {
            val call = rig.transport.prepareDiscovery(rig.clock.operation()); ref.set(call)
            call.start(authGate()); call.await()
        }
        worker.start()
        try {
            authAwait(entered)
            assertEquals(ChatGptAuthSettlement.UNSETTLED, ref.get().cancelAndSettle(250_000_000))
            authFailure(ChatGptAuthHttpFailure.UNSETTLED) { rig.transport.prepareJwks(rig.clock.operation()) }
            assertEquals(0, rig.port.submitted.get())
        } finally { release.countDown(); authJoin(worker) }
        authEventually { ref.get().cancelAndSettle(0) == ChatGptAuthSettlement.SETTLED }
        assertTrue(rig.port.stopped.get() > 0)
    }
    @Test fun cancellationBeforeFutureInstallationAndSubscriptionIsSticky(): Unit = AuthTestRig().use { rig ->
        lateinit var call: ChatGptAuthHttpCall
        rig.port.scripts.add(AuthScript(action = { exchange ->
            call.cancel()
            exchange.subscribe()
            assertEquals(0, exchange.demands.get())
            assertTrue(exchange.cancellations.get() > 0)
        }))
        call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
        authEventually { rig.port.exchanges.single().future.isCancelled }
        assertTrue(rig.port.exchanges.single().future.isCancelled)
        assertTrue(call.await() is ChatGptAuthHttpOutcome.Failed)
        assertEquals(ChatGptAuthDispatchEvidence.MAY_HAVE_BEEN_SENT, call.dispatchEvidence)
    }
    @Test fun duplicateSubscriptionAndLateCompletionCannotPublish(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(AuthScript(action = { exchange -> exchange.subscribe(); exchange.subscribe(); exchange.complete() }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
        assertTrue(call.await() is ChatGptAuthHttpOutcome.Failed)
        assertTrue(rig.port.exchanges.single().cancellations.get() >= 2)
    }
    @Test fun precopyRejectsEntireOversizedBatchWithoutAdvancingAnyBuffer(): Unit = AuthTestRig().use { rig ->
        val first = ByteBuffer.wrap(ByteArray(1)); val second = ByteBuffer.wrap(ByteArray(262144)).asReadOnlyBuffer()
        rig.port.scripts.add(AuthScript(action = { e -> e.subscribe(); e.body(first, second); e.complete() }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
        assertEquals(ChatGptAuthHttpFailure.BODY_LIMIT, (call.await() as ChatGptAuthHttpOutcome.Failed).failure)
        assertEquals(0, first.position()); assertEquals(0, second.position())
    }
    @Test fun exactBodyLimitSplitSlicesAndEmptyBuffersAccepted(): Unit = AuthTestRig().use { rig ->
        val body = ("{\"x\":\"" + "a".repeat(262136) + "\"}").toByteArray()
        assertEquals(262144, body.size)
        rig.port.scripts.add(AuthScript(action = { e ->
            e.subscribe(); e.body(ByteBuffer.wrap(body, 0, 10).slice().asReadOnlyBuffer(), ByteBuffer.allocate(0))
            e.body(ByteBuffer.wrap(body, 10, body.size - 10).slice()); e.complete()
        }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
        val result = call.await(); assertTrue(result is ChatGptAuthHttpOutcome.Document); result.reply.discard()
    }
    @Test fun headerMimeFramingAndStatusFailClosed() {
        val bad = listOf(
            emptyMap(), mapOf("Content-Type" to listOf("text/html")),
            mapOf("Content-Type" to listOf("application/json", "application/json")),
            mapOf("Content-Type" to listOf("application/json;charset=latin1")),
            mapOf("Content-Type" to listOf("application/json"), "Content-Encoding" to listOf("gzip")),
            mapOf("Content-Type" to listOf("application/json"), "Content-Length" to listOf("2", "2")),
            mapOf("Content-Type" to listOf("application/json"), "Content-Length" to listOf("2"), "Transfer-Encoding" to listOf("chunked")),
            mapOf("Content-Type" to listOf("application/json"), "X-Test" to listOf("x".repeat(8193))),
            mapOf("Content-Type" to listOf("application/json"), "X-Test" to List(64) { "x" }),
            mapOf("Content-Type" to listOf("application/json"), "X-Test" to List(4) { "x".repeat(8192) }),
        )
        for (headers in bad) AuthTestRig().use { rig ->
            rig.port.scripts.add(AuthScript(headers = headers))
            val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
            assertTrue(call.await() is ChatGptAuthHttpOutcome.Failed, "invalid response headers")
        }
        for (status in listOf(204, 301, 302, 303, 307, 308)) AuthTestRig().use { rig ->
            rig.port.scripts.add(AuthScript(status = status))
            val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
            assertFalse(call.await() is ChatGptAuthHttpOutcome.Document, "non-success status")
            assertEquals(1, rig.port.submitted.get())
        }
    }
    @Test fun declaredBodyTooLargeShortAndLongReject() {
        for (length in listOf("262145", "1", "3")) AuthTestRig().use { rig ->
            rig.port.scripts.add(AuthScript(headers = mapOf("Content-Type" to listOf("application/json"), "Content-Length" to listOf(length))))
            val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
            assertTrue(call.await() is ChatGptAuthHttpOutcome.Failed)
        }
    }
    @Test fun boundedAuthErrorsRecognizeOnlyLiteralTopLevelStrings() {
        for ((body, expected) in listOf(
            "{\"error\":\"invalid_grant\",\"error_description\":\"synthetic-private\"}" to ChatGptAuthOAuthError.INVALID_GRANT,
            "{\"error\":\"invalid_client\"}" to ChatGptAuthOAuthError.INVALID_CLIENT,
            "{\"error\":{\"code\":\"invalid_grant\"}}" to null,
            "{\"error\":\"unknown\"}" to null,
        )) AuthTestRig().use { rig ->
            rig.port.scripts.add(AuthScript(body.toByteArray(), 400))
            val call = rig.transport.prepareRefresh("oaiapp_test", "synthetic-refresh", rig.clock.operation()); call.start(authGate())
            val result = call.await(); assertTrue(result is ChatGptAuthHttpOutcome.Rejected)
            assertEquals(expected, result.error); assertFalse(result.toString().contains("synthetic-private"))
        }
    }
    @Test fun requestPublisherEmitsOnlyOnceAndRefreshHasExactFixedFields(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(AuthScript())
        val call = rig.transport.prepareRefresh("oaiapp_test", "a +/é", rig.clock.operation()); call.start(authGate())
        val request = rig.port.requests.single()
        // Request is stopped after completion; inspect through a pending call instead below.
        assertTrue(request.headers().firstValue("Authorization").isEmpty)
        (call.await() as ChatGptAuthHttpOutcome.Token).reply.discard()
        rig.port.scripts.add(AuthScript(action = { e -> e.subscribe() }))
        val second = rig.transport.prepareRefresh("oaiapp_test", "a +/é", rig.clock.operation()); second.start(authGate())
        val publisher = rig.port.requests.last().bodyPublisher().get()
        val output = java.io.ByteArrayOutputStream(); val errors = AtomicInteger()
        val subscriber = object : Flow.Subscriber<ByteBuffer> {
            override fun onSubscribe(s: Flow.Subscription) { s.request(1) }
            override fun onNext(b: ByteBuffer) { while (b.hasRemaining()) output.write(b.get().toInt()) }
            override fun onError(t: Throwable) { errors.incrementAndGet() }
            override fun onComplete() {}
        }
        publisher.subscribe(subscriber)
        assertTrue(output.toString(Charsets.US_ASCII) == "grant_type=refresh_token&client_id=oaiapp_test&refresh_token=a+%2B%2F%C3%A9&resource=https%3A%2F%2Fapi.openai.com%2Fv1", "literal fixed refresh form")
        val size = output.size(); publisher.subscribe(subscriber)
        assertEquals(size, output.size()); assertEquals(1, errors.get())
        second.cancelAndSettle(250_000_000)
    }
    @Test fun malformedAndOverlongFormsFailBeforeAcquisition(): Unit = AuthTestRig().use { rig ->
        for (token in listOf("", "x".repeat(16385), "\ud800", "bad\nvalue", "é".repeat(8193)))
            authFailure(ChatGptAuthHttpFailure.INVALID_FORM) { rig.transport.prepareRefresh("oaiapp_test", token, rig.clock.operation()) }
        assertEquals(0, rig.port.acquired.get())
    }
    @Test fun eightCallSlotsAndEightUndiscardedReplyPermitsAreBounded(): Unit = AuthTestRig().use { rig ->
        val calls = List(8) { rig.transport.prepareDiscovery(rig.clock.operation()) }
        authFailure(ChatGptAuthHttpFailure.CAPACITY) { rig.transport.prepareDiscovery(rig.clock.operation()) }
        calls.forEach { it.cancelAndSettle(250_000_000) }
        val replies = List(8) {
            rig.port.scripts.add(AuthScript())
            val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
            (call.await() as ChatGptAuthHttpOutcome.Document).reply
        }
        authFailure(ChatGptAuthHttpFailure.CAPACITY) { rig.transport.prepareDiscovery(rig.clock.operation()) }
        replies.forEach { it.discard() }
        rig.transport.prepareDiscovery(rig.clock.operation()).cancelAndSettle(250_000_000)
    }
    @Test fun setupConsumesHttpAndParentBudgetAndConnectIsClipped(): Unit = AuthTestRig().use { rig ->
        rig.port.acquireHook = { rig.clock.advance(10) }
        val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
        assertEquals(0, rig.port.submitted.get())
        assertEquals(ChatGptAuthHttpFailure.DEADLINE, (call.await() as ChatGptAuthHttpOutcome.Failed).failure)
        assertEquals(5_000_000_000L, rig.port.connect.single())
        authEventually { call.cancelAndSettle(0) == ChatGptAuthSettlement.SETTLED }
        rig.port.acquireHook = null
        val op = rig.clock.operation(seconds = 1)
        val second = rig.transport.prepareDiscovery(op)
        second.start(authGate { false }); second.await()
        assertTrue(rig.port.connect.last() <= 1_000_000_000L)
    }
    @Test fun ownerThreadCallbacksNeverRunFromTimerOrWireCallbacks(): Unit = AuthTestRig().use { rig ->
        val owner = Thread.currentThread(); val wrong = AtomicBoolean()
        val operation = rig.clock.operation(cancelled = { if (Thread.currentThread() !== owner) wrong.set(true); false })
        rig.port.scripts.add(AuthScript(action = { e ->
            val callback = Thread { e.deliver() }; callback.start(); authJoin(callback)
        }))
        val call = rig.transport.prepareDiscovery(operation); call.start(authGate())
        (call.await() as ChatGptAuthHttpOutcome.Document).reply.discard()
        assertFalse(wrong.get())
    }
    @Test fun cancelledFutureIsNotPhysicalSettlementAndCleanupBudgetNeverRenews(): Unit = AuthTestRig().use { rig ->
        rig.port.settled.set(false)
        rig.port.scripts.add(AuthScript(action = { e -> e.subscribe() }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
        assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(1))
        authEventually { rig.port.exchanges.single().future.isCancelled }
        authFailure(ChatGptAuthHttpFailure.UNSETTLED) { rig.transport.prepareDiscovery(rig.clock.operation()) }
        rig.clock.advance(1)
        assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(250_000_000))
        rig.port.settled.set(true)
        authEventually { call.cancelAndSettle(0) == ChatGptAuthSettlement.SETTLED }
        assertEquals(1, rig.port.submitted.get())
    }
    @Test fun blockedCleanupCannotBlockCallerOrTimerAndRequiresRealAcknowledgement(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        rig.port.shutdownHook = { entered.countDown(); authAwait(release) }
        rig.port.scripts.add(AuthScript(action = { it.subscribe() }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
        try {
            val start = System.nanoTime()
            assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(50_000_000))
            assertTrue(System.nanoTime() - start < 500_000_000, "bounded caller cleanup")
            authAwait(entered)
            authFailure(ChatGptAuthHttpFailure.UNSETTLED) { rig.transport.prepareDiscovery(rig.clock.operation()) }
        } finally { release.countDown() }
        authEventually { call.cancelAndSettle(0) == ChatGptAuthSettlement.SETTLED }
        assertTrue(call.await() is ChatGptAuthHttpOutcome.Failed)
    }
    @Test fun cancellationDuringBodyCallbackKeepsCallbackOwnershipUntilReleased(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        var callback: Thread? = null
        rig.port.scripts.add(AuthScript(action = { e ->
            e.subscribe()
            callback = Thread {
                val buffers = object : AbstractList<ByteBuffer>() {
                    override val size = 1
                    override fun get(index: Int): ByteBuffer { entered.countDown(); authAwait(release); return ByteBuffer.wrap("{}".toByteArray()) }
                }
                e.subscriber.onNext(buffers); e.complete()
            }.also { it.start() }
        }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
        try {
            authAwait(entered)
            assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(50_000_000))
            assertTrue(call.await() is ChatGptAuthHttpOutcome.Failed)
        } finally { release.countDown(); callback?.let(::authJoin) }
        authEventually { call.cancelAndSettle(0) == ChatGptAuthSettlement.SETTLED }
    }
    @Test fun postCompletionCancellationRevokesRetainedTokenReply(): Unit = AuthTestRig().use { rig ->
        val bound = authBound(rig); val op = rig.clock.operation(); val key = AuthSigningKey()
        rig.port.scripts.add(AuthScript(key.response(bound.code, rig.clock.now.get())))
        val call = rig.transport.prepareCode(bound.binding, bound.code, op); call.start(authGate())
        val reply = (call.await() as ChatGptAuthHttpOutcome.Token).reply
        call.cancel()
        val keys = ChatGptPlanOidc.validateJwksDocument(key.jwks(), op)
        authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) { reply.validateAuthorization(keys, rig.clock.now.get(), op, false) }
    }

    @Test fun shutdownRevokesDeliveredRepliesAndNoOwnerChecksRunOnReaper(): Unit = AuthTestRig().use { rig ->
        val owner = Thread.currentThread(); val wrong = AtomicBoolean()
        val op = rig.clock.operation(cancelled = { if (Thread.currentThread() !== owner) wrong.set(true); false })
        rig.port.scripts.add(AuthScript())
        val call = rig.transport.prepareDiscovery(op); call.start(authGate())
        val reply = (call.await() as ChatGptAuthHttpOutcome.Document).reply
        assertEquals(ChatGptAuthSettlement.SETTLED, rig.transport.shutdown(250_000_000))
        authFailure { reply.cachePolicy(op) }; assertFalse(wrong.get())
    }
    @Test fun capturedDeadlineCancelsPendingFutureWithoutCallerPolling(): Unit = AuthTestRig().use { rig ->
        val owner = Thread.currentThread(); val wrong = AtomicBoolean()
        rig.port.scripts.add(AuthScript(action = { it.subscribe() }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation(cancelled = { if (Thread.currentThread() !== owner) wrong.set(true); false }))
        call.start(authGate()); rig.clock.advance(10)
        authEventually { rig.port.exchanges.single().future.isCancelled }
        assertEquals(ChatGptAuthHttpFailure.DEADLINE, (call.await() as ChatGptAuthHttpOutcome.Failed).failure)
        assertFalse(wrong.get())
    }

    @Test fun cancelWithoutAwaitStartsStickyCleanupClock(): Unit = AuthTestRig().use { rig ->
        rig.port.settled.set(false)
        rig.port.scripts.add(AuthScript(action = { it.subscribe() }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
        call.cancel(); rig.clock.advance(1)
        val start = System.nanoTime()
        assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(250_000_000))
        assertTrue(System.nanoTime() - start < 200_000_000, "no renewed cleanup allowance")
        rig.port.settled.set(true)
        authEventually { call.cancelAndSettle(0) == ChatGptAuthSettlement.SETTLED }
    }

    @Test fun registeredPreparationOwnsBlockedFormBeforeReturningAnyHandle(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val checks = AtomicInteger(); val returned = AtomicBoolean()
        val worker = Thread {
            val op = rig.clock.operation(cancelled = {
                if (checks.incrementAndGet() == 2) { entered.countDown(); authAwait(release) }
                false
            })
            try { rig.transport.prepareRefresh("oaiapp_test", "synthetic-refresh", op); returned.set(true) } catch (_: Exception) { }
        }
        worker.start()
        try {
            authAwait(entered)
            assertEquals(ChatGptAuthSettlement.UNSETTLED, rig.transport.shutdown(50_000_000))
            assertEquals(0, rig.port.acquired.get())
        } finally { release.countDown(); authJoin(worker) }
        assertFalse(returned.get())
    }
    @Test fun concurrentAndReentrantStartsCannotClaimGateOrSendTwice(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(AuthScript()); val claims = AtomicInteger()
        val call = rig.transport.prepareDiscovery(rig.clock.operation())
        call.start(authGate {
            claims.incrementAndGet()
            authFailure(ChatGptAuthHttpFailure.ALREADY_USED) { call.start(authGate()) }
            val competitor = Thread { authFailure(ChatGptAuthHttpFailure.ALREADY_USED) { call.start(authGate()) } }
            competitor.start(); authJoin(competitor)
            true
        })
        (call.await() as ChatGptAuthHttpOutcome.Document).reply.discard()
        assertEquals(1, claims.get()); assertEquals(1, rig.port.submitted.get())
    }
    @Test fun throwingCleanupRemainsQuarantinedUntilAcknowledged(): Unit = AuthTestRig().use { rig ->
        rig.port.shutdownHook = { error("synthetic cleanup detail") }
        rig.port.scripts.add(AuthScript(action = { it.subscribe() }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
        assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(1))
        authFailure(ChatGptAuthHttpFailure.UNSETTLED) { rig.transport.prepareDiscovery(rig.clock.operation()) }
        rig.port.shutdownHook = null
        authEventually { call.cancelAndSettle(0) == ChatGptAuthSettlement.SETTLED }
    }

    // Promoted verbatim from independent review v2; historical red evidence remains intact.
    private fun physicallyIdle(transport: ChatGptAuthTransport) {
        val lock = transport.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(transport)
        val calls = transport.javaClass.getDeclaredField("calls").apply { isAccessible = true }
        authEventually { synchronized(lock) { (calls.get(transport) as Set<*>).isEmpty() } }
    }
    @Test fun cancelledPhysicallyCompleteCandidateReleasesPermitWithoutAwait(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(AuthScript())
        val completed = rig.transport.prepareDiscovery(rig.clock.operation())
        completed.start(authGate()); physicallyIdle(rig.transport)
        completed.cancel()
        val admitted = mutableListOf<ChatGptAuthHttpCall>()
        var failure: ChatGptAuthHttpFailure? = null
        try {
            repeat(8) {
                try { admitted.add(rig.transport.prepareDiscovery(rig.clock.operation())) }
                catch (e: ChatGptAuthHttpException) { failure = e.failure }
            }
            println("candidate_cancel admitted=" + admitted.size + " failure=" + failure)
        } finally {
            completed.cancelAndSettle(250_000_000)
            admitted.forEach { it.cancelAndSettle(250_000_000) }
        }
        assertEquals(8, admitted.size, "cancelled settled candidate releases permit")
    }
    @Test fun shutdownDropsUnawaitedPhysicallyCompleteCandidate(): Unit = AuthTestRig().use { rig ->
        val bound = authBound(rig); val key = AuthSigningKey(); val op = rig.clock.operation()
        rig.port.scripts.add(AuthScript(key.response(bound.code, rig.clock.now.get())))
        val call = rig.transport.prepareCode(bound.binding, bound.code, op)
        call.start(authGate()); physicallyIdle(rig.transport)
        try {
            assertEquals(ChatGptAuthSettlement.SETTLED, rig.transport.shutdown(250_000_000))
            // Read-only observation: retain no actual response or binding in fixture evidence.
            val bodyHeld = call.javaClass.getDeclaredField("response").apply { isAccessible = true }.get(call) != null
            val bindingHeld = call.javaClass.getDeclaredField("binding").apply { isAccessible = true }.get(call) != null
            println("shutdown_candidate bodyHeld=" + bodyHeld + " bindingHeld=" + bindingHeld)
            assertFalse(bodyHeld || bindingHeld, "settled shutdown drops candidate authority")
        } finally { call.cancelAndSettle(250_000_000) }
    }
    @Test fun cancelledAcquisitionDeniesAdmissionUntilAcknowledged(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val callRef = AtomicReference<ChatGptAuthHttpCall>()
        rig.port.acquireHook = { entered.countDown(); authAwait(release) }
        val worker = Thread {
            val call = rig.transport.prepareDiscovery(rig.clock.operation()); callRef.set(call); call.start(authGate())
        }
        worker.start()
        try {
            authAwait(entered)
            assertEquals(ChatGptAuthSettlement.UNSETTLED, callRef.get().cancelAndSettle(1))
            authFailure(ChatGptAuthHttpFailure.UNSETTLED) { rig.transport.prepareDiscovery(rig.clock.operation()) }
            assertEquals(0, rig.port.submitted.get())
        } finally { release.countDown(); authJoin(worker); rig.port.acquireHook = null }
        authEventually { callRef.get().cancelAndSettle(0) == ChatGptAuthSettlement.SETTLED }
        assertEquals(0, rig.port.submitted.get())
    }

    @Test fun unawaitedCandidateExpiryReapsAuthorityAndEightPermits(): Unit = AuthTestRig().use { rig ->
        val bound = authBound(rig); val key = AuthSigningKey()
        rig.port.scripts.add(AuthScript(key.response(bound.code, rig.clock.now.get())))
        val call = rig.transport.prepareCode(bound.binding, bound.code, rig.clock.operation())
        call.start(authGate()); physicallyIdle(rig.transport)
        assertTrue(authCallHasPrivateCandidate(call))
        assertEquals(1, authTransportCount(rig.transport, "permits"))
        rig.clock.advance(10)
        authEventually { authTransportCount(rig.transport, "permits") == 0 }
        assertFalse(authCallHasPrivateCandidate(call))
        assertEquals(0, authTransportCount(rig.transport, "pending"))
        assertEightInertAdmissions(rig)
    }
    @Test fun completedCandidateCapacityAndConcurrentCancelAreIdempotent(): Unit = AuthTestRig().use { rig ->
        val calls = List(8) {
            rig.port.scripts.add(AuthScript())
            rig.transport.prepareDiscovery(rig.clock.operation()).also { it.start(authGate()) }
        }
        physicallyIdle(rig.transport)
        assertEquals(8, authTransportCount(rig.transport, "pending"))
        authFailure(ChatGptAuthHttpFailure.CAPACITY) { rig.transport.prepareDiscovery(rig.clock.operation()) }
        val cancellers = List(4) { Thread({ repeat(4) { calls.forEach { it.cancel() } } }, "chatgpt-auth-fixture-cancel") }
        cancellers.forEach { it.start() }; cancellers.forEach(::authJoin)
        assertEquals(0, authTransportCount(rig.transport, "permits"))
        assertEquals(0, authTransportCount(rig.transport, "pending"))
        calls.forEach { assertFalse(authCallHasPrivateCandidate(it)) }
        assertEightInertAdmissions(rig)
    }
    @Test fun cancelDuringReplyHandoffRetainsOwnershipUntilAcknowledged() = handoffRace("cancel")
    @Test fun shutdownDuringReplyHandoffCannotSettleOrPublish() = handoffRace("shutdown")
    @Test fun reaperDuringReplyHandoffFencesAndDefersPermitRelease() = handoffRace("expiry")
    private fun handoffRace(action: String): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val armed = AtomicBoolean(); val wrongThread = AtomicBoolean(); val good = AtomicBoolean()
        val callRef = AtomicReference<ChatGptAuthHttpCall>()
        val bound = authBound(rig); val key = AuthSigningKey()
        val worker = Thread({
            val owner = Thread.currentThread()
            val op = rig.clock.operation(cancelled = {
                if (Thread.currentThread() !== owner) wrongThread.set(true)
                if (armed.get() && authTransportCount(rig.transport, "replies") == 1) {
                    entered.countDown(); authAwait(release)
                }
                false
            })
            rig.port.scripts.add(AuthScript(key.response(bound.code, rig.clock.now.get())))
            val call = rig.transport.prepareCode(bound.binding, bound.code, op); callRef.set(call)
            call.start(authGate()); armed.set(true)
            good.set(call.await() is ChatGptAuthHttpOutcome.Token)
        }, "chatgpt-auth-fixture-handoff")
        worker.start()
        try {
            authAwait(entered); physicallyIdle(rig.transport)
            assertEquals(1, authTransportCount(rig.transport, "pending"))
            when (action) {
                "cancel" -> {
                    callRef.get().cancel()
                    assertEquals(ChatGptAuthSettlement.UNSETTLED, callRef.get().cancelAndSettle(1))
                    authFailure(ChatGptAuthHttpFailure.UNSETTLED) { rig.transport.prepareDiscovery(rig.clock.operation()) }
                }
                "shutdown" -> assertEquals(ChatGptAuthSettlement.UNSETTLED, rig.transport.shutdown(50_000_000))
                else -> {
                    rig.clock.advance(10)
                    authEventually { !authCallHasPrivateCandidate(callRef.get()) }
                }
            }
            assertEquals(1, authTransportCount(rig.transport, "permits"), "blocked owner still holds its outcome")
        } finally { release.countDown(); authJoin(worker) }
        assertFalse(good.get()); assertFalse(wrongThread.get())
        authEventually { authTransportCount(rig.transport, "permits") == 0 }
        assertEquals(0, authTransportCount(rig.transport, "pending"))
        assertEquals(0, authTransportCount(rig.transport, "replies"))
        assertFalse(authCallHasPrivateCandidate(callRef.get()))
        if (action == "shutdown") authEventually { rig.transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        else assertEightInertAdmissions(rig)
    }
    private fun assertEightInertAdmissions(rig: AuthTestRig) {
        val calls = mutableListOf<ChatGptAuthHttpCall>()
        try {
            repeat(8) { calls.add(rig.transport.prepareDiscovery(rig.clock.operation())) }
            authFailure(ChatGptAuthHttpFailure.CAPACITY) { rig.transport.prepareDiscovery(rig.clock.operation()) }
        } finally { calls.forEach { it.cancelAndSettle(250_000_000) } }
        authEventually { authTransportCount(rig.transport, "permits") == 0 }
    }

    @Test fun ordinaryCancelReleasesOnlyAfterPhysicalAcknowledgement(): Unit = AuthTestRig().use { rig ->
        rig.port.settled.set(false); rig.port.scripts.add(AuthScript())
        val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate()); call.cancel()
        assertTrue(rig.port.exchanges.single().future.isDone)
        authEventually { rig.port.stopped.get() > 0 }
        assertEquals(1, authTransportCount(rig.transport, "calls"))
        assertEquals(1, authTransportCount(rig.transport, "pending"))
        assertEquals(1, authTransportCount(rig.transport, "permits"))
        // Neither await nor cancelAndSettle is needed to reap the acknowledged late resource.
        rig.port.settled.set(true)
        authEventually { authTransportCount(rig.transport, "permits") == 0 && authTransportCount(rig.transport, "calls") == 0 }
        assertEightInertAdmissions(rig)
    }

    @Test fun shutdownCannotWaitForBlockedBindingCancellationCallback(): Unit = AuthTestRig().use { rig ->
        val armed = AtomicBoolean(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val shutdownEntered = CountDownLatch(1); val shutdownDone = CountDownLatch(1)
        val proof = AtomicBoolean(); val result = AtomicReference<ChatGptAuthSettlement>()
        val bound = authBound(rig, cancelled = { if (armed.get()) { entered.countDown(); authAwait(release) }; false })
        val op = rig.clock.operation(); val key = AuthSigningKey(); val reply = authToken(rig, bound, key, op)
        rig.port.scripts.add(AuthScript(key.jwks())); armed.set(true)
        val validator = Thread({ try { rig.metadata.validateAuthorization(reply, op); proof.set(true) } catch (_: Exception) { } }, "chatgpt-auth-fixture-binding-validator")
        val shutdown = Thread({ shutdownEntered.countDown(); try { result.set(rig.transport.shutdown(1)) } finally { shutdownDone.countDown() } }, "chatgpt-auth-fixture-binding-shutdown")
        var finished = false; var blockedOnBinding = false
        validator.start()
        try {
            authAwait(entered); shutdown.start(); authAwait(shutdownEntered)
            finished = shutdownDone.await(350, TimeUnit.MILLISECONDS)
            blockedOnBinding = shutdown.state == Thread.State.BLOCKED && shutdown.stackTrace.any {
                it.className == "decompengine.chatgpt.CodeBinding" && it.methodName == "discard"
            }
            println("binding_shutdown finishedWithin350ms=" + finished + " blockedOnBinding=" + blockedOnBinding)
        } finally {
            release.countDown(); authJoin(validator)
            if (shutdown.state != Thread.State.NEW) authJoin(shutdown)
            reply.discard()
        }
        assertFalse(proof.get(), "shutdown fences proof")
        assertTrue(finished, "shutdown must return within fixed allowance despite blocked owner callback")
    }

    @Test fun blockedBindingCancelRetainsPendingUntilAcknowledged() = bindingValidationRace("cancel")
    @Test fun blockedBindingDiscardRetainsPendingUntilAcknowledged() = bindingValidationRace("discard")
    @Test fun blockedBindingShutdownRetainsPendingUntilAcknowledged() = bindingValidationRace("shutdown")
    @Test fun discardDuringFinalBindingCheckFencesProof() = bindingValidationRace("discard", finalCheck = true)
    @Test fun throwingBindingCallbackReleasesPendingExactlyOnce() = bindingValidationRace("discard", throws = true)
    @Test fun concurrentBindingValidationCannotClearFirstValidator() = bindingValidationRace("validate")

    private fun bindingValidationRace(action: String, finalCheck: Boolean = false, throws: Boolean = false): Unit = AuthTestRig().use { rig ->
        val armed = AtomicBoolean(); val checks = AtomicInteger(); val held = AtomicBoolean()
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val done = CountDownLatch(1)
        val succeeded = AtomicBoolean(); val ref = AtomicReference<ChatGptAuthCodeBinding>()
        val bound = authBound(rig, cancelled = {
            if (armed.get() && checks.incrementAndGet() == if (finalCheck) 2 else 1) {
                held.set(Thread.holdsLock(ref.get())); entered.countDown(); authAwait(release)
                if (throws) error("synthetic binding callback failure")
            }
            false
        }); ref.set(bound.binding)
        val op = rig.clock.operation(); val key = AuthSigningKey()
        rig.port.scripts.add(AuthScript(key.jwks())); rig.metadata.keys(op).close()
        rig.port.scripts.add(AuthScript(key.response(bound.code, rig.clock.now.get())))
        val call = rig.transport.prepareCode(bound.binding, bound.code, op); call.start(authGate())
        val reply = (call.await() as ChatGptAuthHttpOutcome.Token).reply
        val keys = ChatGptPlanOidc.validateJwksDocument(key.jwks(), op)
        armed.set(true)
        val validator = Thread({
            try { rig.metadata.validateAuthorization(reply, op); succeeded.set(true) } catch (_: Exception) { }
        }, "chatgpt-auth-fixture-binding-owner")
        val settlement = AtomicReference<ChatGptAuthSettlement>()
        val closer = Thread({
            try {
                when (action) {
                    "cancel" -> call.cancel()
                    "discard" -> repeat(3) { reply.discard() }
                    "shutdown" -> settlement.set(rig.transport.shutdown(1))
                    "validate" -> authFailure(ChatGptAuthHttpFailure.ALREADY_USED) {
                        reply.validateAuthorization(keys, rig.clock.now.get(), op, false)
                    }
                }
            } finally { done.countDown() }
        }, "chatgpt-auth-fixture-binding-closer")
        validator.start()
        try {
            authAwait(entered); closer.start()
            assertTrue(done.await(350, TimeUnit.MILLISECONDS), "revocation cannot wait on binding callback")
            assertFalse(held.get(), "callback must not own binding monitor")
            assertEquals(1, authTransportCount(rig.transport, "pending"))
            assertEquals(1, authTransportCount(rig.transport, "permits"))
            assertEquals(1, authTransportCount(rig.transport, "replies"))
            assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(1))
            if (action == "shutdown") assertEquals(ChatGptAuthSettlement.UNSETTLED, settlement.get())
            authFailure(ChatGptAuthHttpFailure.CANCELLED) { bound.binding.authorizationRequest() }
        } finally {
            release.countDown(); authJoin(validator)
            if (closer.state != Thread.State.NEW) authJoin(closer)
            reply.discard()
        }
        assertFalse(succeeded.get(), "revocation fences final proof")
        assertEquals(ChatGptAuthSettlement.SETTLED, call.cancelAndSettle(0))
        assertEquals(0, authTransportCount(rig.transport, "pending"))
        assertEquals(0, authTransportCount(rig.transport, "permits"))
        assertEquals(0, authTransportCount(rig.transport, "replies"))
        repeat(3) { reply.discard(); call.cancel() }
        assertEquals(0, authTransportCount(rig.transport, "permits"))
        if (action == "shutdown") authEventually { rig.transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        else assertEightInertAdmissions(rig)
    }

    @Test fun reentrantBindingShutdownCannotAcknowledgeItsOwnValidator() = bindingReentry(true)
    @Test fun reentrantBindingDiscardCannotPublishProof() = bindingReentry(false)
    private fun bindingReentry(shutdown: Boolean): Unit = AuthTestRig().use { rig ->
        val armed = AtomicBoolean(); val ref = AtomicReference<ChatGptAuthTokenReply>()
        val binding = AtomicReference<ChatGptAuthCodeBinding>(); val ran = AtomicBoolean()
        val bound = authBound(rig, cancelled = {
            if (armed.compareAndSet(true, false)) {
                ran.set(true); assertFalse(Thread.holdsLock(binding.get()))
                if (shutdown) assertEquals(ChatGptAuthSettlement.UNSETTLED, rig.transport.shutdown(1))
                else ref.get().discard()
                assertEquals(1, authTransportCount(rig.transport, "pending"))
                assertEquals(1, authTransportCount(rig.transport, "permits"))
            }
            false
        }); binding.set(bound.binding)
        val op = rig.clock.operation(); val key = AuthSigningKey()
        rig.port.scripts.add(AuthScript(key.jwks())); rig.metadata.keys(op).close()
        val reply = authToken(rig, bound, key, op); ref.set(reply); armed.set(true)
        authFailure { rig.metadata.validateAuthorization(reply, op) }
        assertTrue(ran.get()); assertEquals(0, authTransportCount(rig.transport, "permits"))
        if (shutdown) authEventually { rig.transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        else assertEightInertAdmissions(rig)
    }

    @Test fun concurrentDiscardDoesNotHoldReplyMonitorOrAcknowledgeBindingRevocation(): Unit = AuthTestRig().use { rig ->
        val bound = authBound(rig); val op = rig.clock.operation(); val key = AuthSigningKey()
        val reply = authToken(rig, bound, key, op)
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val done = CountDownLatch(1)
        val holder = Thread({ synchronized(bound.binding) { entered.countDown(); authAwait(release) } },
            "chatgpt-auth-fixture-binding-monitor")
        val discarder = Thread({ reply.discard() }, "chatgpt-auth-fixture-first-discard")
        val observer = Thread({ try { reply.discard() } finally { done.countDown() } }, "chatgpt-auth-fixture-second-discard")
        holder.start()
        try {
            authAwait(entered); discarder.start()
            authEventually { discarder.state == Thread.State.BLOCKED && discarder.stackTrace.any {
                it.className == "decompengine.chatgpt.CodeBinding" && it.methodName == "discard"
            } }
            observer.start()
            assertTrue(done.await(350, TimeUnit.MILLISECONDS), "reply monitor cannot nest the binding monitor")
            assertEquals(1, authTransportCount(rig.transport, "pending"))
            assertEquals(1, authTransportCount(rig.transport, "permits"))
            assertEquals(ChatGptAuthSettlement.UNSETTLED, rig.transport.shutdown(1))
        } finally {
            release.countDown(); authJoin(holder)
            if (discarder.state != Thread.State.NEW) authJoin(discarder)
            if (observer.state != Thread.State.NEW) authJoin(observer)
            reply.discard()
        }
        assertEquals(0, authTransportCount(rig.transport, "pending"))
        assertEquals(0, authTransportCount(rig.transport, "permits"))
        authEventually { rig.transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
    }

    @Test fun shutdownFencesBindingDuringBlockedCodePreparation(): Unit = AuthTestRig().use { rig ->
        val armed = AtomicBoolean(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val done = CountDownLatch(1); val probeDone = CountDownLatch(1)
        val prepared = AtomicBoolean(); val settlement = AtomicReference<ChatGptAuthSettlement>()
        val probeFailure = AtomicReference<ChatGptAuthHttpFailure>()
        val bound = authBound(rig, cancelled = { if (armed.get()) { entered.countDown(); authAwait(release) }; false })
        armed.set(true)
        val owner = Thread({
            try { rig.transport.prepareCode(bound.binding, bound.code, rig.clock.operation()); prepared.set(true) } catch (_: Exception) { }
        }, "chatgpt-auth-fixture-code-preparation")
        val closer = Thread({ try { settlement.set(rig.transport.shutdown(1)) } finally { done.countDown() } },
            "chatgpt-auth-fixture-preparation-shutdown")
        val probe = Thread({
            try { bound.binding.authorizationRequest() }
            catch (e: ChatGptAuthHttpException) { probeFailure.set(e.failure) }
            finally { probeDone.countDown() }
        }, "chatgpt-auth-fixture-binding-probe")
        owner.start()
        try {
            authAwait(entered); closer.start()
            assertTrue(done.await(350, TimeUnit.MILLISECONDS), "preparation callback cannot delay shutdown")
            assertEquals(ChatGptAuthSettlement.UNSETTLED, settlement.get())
            assertEquals(1, authTransportCount(rig.transport, "pending"))
            assertEquals(1, authTransportCount(rig.transport, "permits"))
            // Shutdown has returned while the original preparation callback is still blocked.
            // A separate entry must fail before invoking that callback again.
            probe.start()
            assertTrue(probeDone.await(350, TimeUnit.MILLISECONDS), "revoked binding rejects without another callback")
            assertEquals(ChatGptAuthHttpFailure.CANCELLED, probeFailure.get())
        } finally {
            release.countDown(); authJoin(owner)
            if (closer.state != Thread.State.NEW) authJoin(closer)
            if (probe.state != Thread.State.NEW) authJoin(probe)
        }
        assertFalse(prepared.get()); assertEquals(0, rig.port.submitted.get())
        authEventually { rig.transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        assertEquals(0, authTransportCount(rig.transport, "permits"))
    }

    // Review MonitorControls regression (cache barrier corrected to work after monitor repair).
    @Test fun transportShutdownDoesNotWaitOnBodyCompletionClockMonitor() {
        val clock = AuthTestClock(); val port = AuthScriptPort()
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val started = CountDownLatch(1); val done = CountDownLatch(1)
        val blocked = AtomicBoolean(); val held = AtomicBoolean()
        val callRef = AtomicReference<ChatGptAuthHttpCall>()
        val transport = newChatGptAuthTransport(port, clock.nanos::get) {
            val call = callRef.get()
            val lock = call.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(call)
            held.set(Thread.holdsLock(lock)); entered.countDown(); authAwait(release)
            clock.now.get()
        }
        port.scripts.add(AuthScript(authDiscovery()))
        val owner = Thread({
            val call = transport.prepareDiscovery(clock.operation()); callRef.set(call); call.start(authGate())
        }, "chatgpt-auth-fixture-clock-owner")
        val closer = Thread({ started.countDown(); try { transport.shutdown(1) } finally { done.countDown() } },
            "chatgpt-auth-fixture-clock-shutdown")
        var finished = false
        owner.start()
        try {
            authAwait(entered); closer.start(); authAwait(started)
            finished = done.await(350, TimeUnit.MILLISECONDS)
            blocked.set(closer.state == Thread.State.BLOCKED && closer.stackTrace.any {
                it.className == "decompengine.chatgpt.AuthCall" && it.methodName == "cancel"
            })
            println("transport_clock finishedWithin350ms=$finished blockedInCancel=${blocked.get()} callbackHeldMonitor=${held.get()}")
        } finally {
            release.countDown(); authJoin(owner)
            if (closer.state != Thread.State.NEW) authJoin(closer)
            authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        }
        assertTrue(finished, "shutdown cannot wait outside its allowance on body-completion clock")
        assertFalse(held.get(), "wall clock callback must run outside call lifetime monitor")
    }


    @Test fun blockedInitializationClockRetainsRegisteredOwnership() = clockStage("initialize", "block")
    @Test fun reentrantInitializationClockCannotPublishPreparedCall() = clockStage("initialize", "reenter")
    @Test fun throwingInitializationClockReleasesOnce() = clockStage("initialize", "throw")
    @Test fun blockedRemainingClockRetainsStartOwnership() = clockStage("ownerCheck", "block")
    @Test fun reentrantRemainingClockCannotSubmit() = clockStage("ownerCheck", "reenter")
    @Test fun throwingRemainingClockReleasesOnce() = clockStage("ownerCheck", "throw")
    @Test fun blockedCompletionWallClockRetainsCapacity() = clockStage("wall", "block")
    @Test fun reentrantCompletionWallClockCannotPublishBody() = clockStage("wall", "reenter")
    @Test fun throwingCompletionWallClockReleasesOnce() = clockStage("wall", "throw")
    @Test fun completionWallClockCannotResetOriginalDeadline() = clockStage("wall", "expire")
    @Test fun blockedDispatchGateRetainsStartOwnership() = clockStage("gate", "block")
    @Test fun reentrantDispatchGateCannotSubmit() = clockStage("gate", "reenter")
    @Test fun throwingDispatchGateReleasesOnce() = clockStage("gate", "throw")

    // Independently authored lifecycle matrix: actual registered owners, no monitor holder,
    // no native/HTTP execution. Reflection observes private identity/counts only.
    private fun clockStage(stage: String, action: String) {
        val time = AuthTestClock(); val port = AuthScriptPort()
        val transportRef = AtomicReference<ChatGptAuthTransport>()
        val callRef = AtomicReference<ChatGptAuthHttpCall>()
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val done = CountDownLatch(1)
        val armed = AtomicBoolean(stage == "initialize"); val fired = AtomicBoolean(); val held = AtomicBoolean()
        val success = AtomicBoolean(); val failure = AtomicReference<Throwable>()
        val settlement = AtomicReference<ChatGptAuthSettlement>()
        fun adversary() {
            if (Thread.currentThread().name != "chatgpt-auth-clock-stage-owner" || !armed.compareAndSet(true, false)) return
            fired.set(true)
            val transport = transportRef.get()
            val ownerLock = transport.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(transport)
            val call = callRef.get() ?: synchronized(ownerLock) {
                val calls = transport.javaClass.getDeclaredField("calls").apply { isAccessible = true }.get(transport) as Set<*>
                calls.single() as ChatGptAuthHttpCall
            }
            val callLock = call.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(call)
            held.set(Thread.holdsLock(ownerLock) || Thread.holdsLock(callLock))
            when (action) {
                "block" -> { entered.countDown(); authAwait(release) }
                "reenter" -> settlement.set(transport.shutdown(0))
                "throw" -> error("synthetic clock failure")
                "expire" -> time.advance(31)
            }
        }
        val transport = newChatGptAuthTransport(port, {
            if (stage != "wall" && Thread.currentThread().stackTrace.any { it.methodName == stage }) adversary()
            time.nanos.get()
        }, { if (stage == "wall") adversary(); time.now.get() })
        transportRef.set(transport); port.scripts.add(AuthScript(authDiscovery()))
        val owner = Thread({
            try {
                val call = transport.prepareDiscovery(time.operation()); callRef.set(call)
                if (stage != "initialize") armed.set(true)
                call.start(authGate { if (stage == "gate") adversary(); true })
                when (val result = call.await()) {
                    is ChatGptAuthHttpOutcome.Document -> { success.set(true); result.reply.discard() }
                    is ChatGptAuthHttpOutcome.Token -> { success.set(true); result.reply.discard() }
                    else -> Unit
                }
            } catch (_: ChatGptAuthHttpException) { }
            catch (e: Throwable) { failure.set(e) }
        }, "chatgpt-auth-clock-stage-owner")
        val closer = Thread({ try { settlement.set(transport.shutdown(1)) } finally { done.countDown() } },
            "chatgpt-auth-clock-stage-closer")
        owner.start()
        try {
            if (action == "block") {
                authAwait(entered); closer.start()
                assertTrue(done.await(350, TimeUnit.MILLISECONDS), "shutdown fences before clock acknowledgement")
                assertEquals(ChatGptAuthSettlement.UNSETTLED, settlement.get())
                assertEquals(1, authTransportCount(transport, "permits"))
                assertEquals(1, authTransportCount(transport, "pending"))
                authFailure(ChatGptAuthHttpFailure.UNSETTLED) { transport.prepareDiscovery(time.operation()) }
            }
        } finally {
            release.countDown(); authJoin(owner)
            if (closer.state != Thread.State.NEW) authJoin(closer)
            authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        }
        assertTrue(fired.get()); assertFalse(held.get()); assertFalse(success.get()); assertNull(failure.get())
        if (action == "reenter") assertEquals(ChatGptAuthSettlement.UNSETTLED, settlement.get())
        assertEquals(0, authTransportCount(transport, "permits")); assertEquals(0, authTransportCount(transport, "pending"))
        if (stage != "wall") assertEquals(0, port.submitted.get())
    }

    @Test fun cleanupCallerNeverInvokesInjectedClockOrOperation() {
        val time = AuthTestClock(); val port = AuthScriptPort(); val armed = AtomicBoolean()
        val caller = Thread.currentThread(); val violations = AtomicInteger()
        val transport = newChatGptAuthTransport(port, {
            if (armed.get() && Thread.currentThread() === caller) { violations.incrementAndGet(); error("cleanup clock") }
            time.nanos.get()
        }, time.now::get)
        val operation = time.operation(cancelled = {
            if (armed.get() && Thread.currentThread() === caller) { violations.incrementAndGet(); error("cleanup operation") }
            false
        })
        val call = transport.prepareDiscovery(operation)
        try {
            armed.set(true); call.cancel(); call.cancelAndSettle(0)
            authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
            assertEquals(0, violations.get())
        } finally { armed.set(false); authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED } }
    }

    @Test fun blockedReaperClockCannotAcknowledgeCallOrRenewZeroCleanupBudget() {
        val time = AuthTestClock(); val port = AuthScriptPort()
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val armed = AtomicBoolean()
        val transport = newChatGptAuthTransport(port, {
            if (Thread.currentThread().name == "chatgpt-auth-reaper" && armed.compareAndSet(true, false)) {
                entered.countDown(); authAwait(release)
            }
            time.nanos.get()
        }, time.now::get)
        val call = transport.prepareDiscovery(time.operation()); armed.set(true)
        try {
            authAwait(entered)
            assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(0))
            val start = System.nanoTime()
            assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(250_000_000))
            assertTrue(System.nanoTime() - start < 150_000_000, "sticky zero cleanup budget")
            assertEquals(1, authTransportCount(transport, "permits"))
        } finally { release.countDown(); authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED } }
        assertEquals(0, authTransportCount(transport, "permits"))
    }

    @Test fun blockedDocumentOperationRetainsPermitUntilReadAcknowledgesDiscard(): Unit = AuthTestRig().use { rig ->
        val armed = AtomicBoolean(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val published = AtomicBoolean(); val operation = rig.clock.operation(cancelled = {
            if (armed.compareAndSet(true, false)) { entered.countDown(); authAwait(release) }; false
        })
        rig.port.scripts.add(AuthScript(authDiscovery()))
        val call = rig.transport.prepareDiscovery(operation); call.start(authGate())
        val reply = (call.await() as ChatGptAuthHttpOutcome.Document).reply
        val reader = Thread({ try { reply.discovery(operation); published.set(true) } catch (_: Exception) { } },
            "chatgpt-auth-document-reader")
        armed.set(true); reader.start()
        try {
            authAwait(entered); reply.discard()
            assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(0))
            assertEquals(1, authTransportCount(rig.transport, "permits"))
        } finally { release.countDown(); authJoin(reader) }
        authEventually { call.cancelAndSettle(0) == ChatGptAuthSettlement.SETTLED }
        assertFalse(published.get()); assertEquals(0, authTransportCount(rig.transport, "permits"))
    }

    @Test fun blockedVendorStatusGetterCannotHoldCallMonitor() = vendorGetter("status", "block")
    @Test fun reentrantVendorStatusGetterCannotPublishSubscriber() = vendorGetter("status", "reenter")
    @Test fun throwingVendorStatusGetterReleasesOwnership() = vendorGetter("status", "throw")
    @Test fun blockedVendorBodyGetterRetainsCompletionAcknowledgement() = vendorGetter("body", "block")
    @Test fun reentrantVendorBodyGetterCannotPublishCandidate() = vendorGetter("body", "reenter")
    @Test fun throwingVendorBodyGetterStillAcknowledgesCompletion() = vendorGetter("body", "throw")
    private fun vendorGetter(stage: String, action: String) {
        val time = AuthTestClock(); val wire = AuthScriptPort(); val ref = AtomicReference<ChatGptAuthTransport>()
        val callRef = AtomicReference<ChatGptAuthHttpCall>(); val once = AtomicBoolean()
        val held = AtomicBoolean(); val success = AtomicBoolean(); val trouble = AtomicReference<Throwable>()
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val done = CountDownLatch(1)
        val result = AtomicReference<ChatGptAuthSettlement>()
        fun adversary() {
            if (!once.compareAndSet(false, true)) return
            val call = callRef.get()
            val lock = call.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(call)
            held.set(Thread.holdsLock(lock))
            when (action) {
                "block" -> { entered.countDown(); authAwait(release) }
                "reenter" -> result.set(ref.get().shutdown(0))
                "throw" -> error("synthetic vendor getter")
            }
        }
        val port = object : ChatGptAuthWirePort() {
            override fun acquire(connectTimeoutNanos: Long): ChatGptAuthWireSession {
                val session = wire.acquire(connectTimeoutNanos)
                return object : ChatGptAuthWireSession() {
                    override fun sendAsync(request: HttpRequest, handler: HttpResponse.BodyHandler<ByteArray>): CompletableFuture<HttpResponse<ByteArray>> {
                        val original = session.sendAsync(request, HttpResponse.BodyHandler { info ->
                            handler.apply(object : HttpResponse.ResponseInfo by info {
                                override fun statusCode(): Int { if (stage == "status") adversary(); return info.statusCode() }
                            })
                        })
                        return original.thenApply { response -> object : HttpResponse<ByteArray> by response {
                            override fun body(): ByteArray { if (stage == "body") adversary(); return response.body() }
                        } }
                    }
                    override fun shutdownNow() = session.shutdownNow()
                    override fun awaitTermination(maxWaitNanos: Long) = session.awaitTermination(maxWaitNanos)
                }
            }
        }
        val transport = newChatGptAuthTransport(port, time.nanos::get, time.now::get); ref.set(transport)
        wire.scripts.add(AuthScript(authDiscovery()))
        val owner = Thread({
            try {
                val call = transport.prepareDiscovery(time.operation()); callRef.set(call); call.start(authGate())
                val outcome = call.await()
                if (outcome is ChatGptAuthHttpOutcome.Document) { success.set(true); outcome.reply.discard() }
            } catch (e: Throwable) { trouble.set(e) }
        }, "chatgpt-auth-vendor-getter")
        val closer = Thread({ try { result.set(transport.shutdown(1)) } finally { done.countDown() } },
            "chatgpt-auth-vendor-getter-closer")
        owner.start()
        try {
            if (action == "block") {
                authAwait(entered); closer.start()
                assertTrue(done.await(350, TimeUnit.MILLISECONDS), "vendor getter cannot hold lifecycle monitor")
                assertEquals(ChatGptAuthSettlement.UNSETTLED, result.get())
                assertEquals(1, authTransportCount(transport, "permits"))
            }
        } finally {
            release.countDown(); authJoin(owner)
            if (closer.state != Thread.State.NEW) authJoin(closer)
            authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        }
        assertTrue(once.get()); assertFalse(held.get()); assertFalse(success.get()); assertNull(trouble.get())
        if (action == "reenter") assertEquals(ChatGptAuthSettlement.UNSETTLED, result.get())
        assertEquals(0, authTransportCount(transport, "permits"))
    }

    @Test fun expiredInjectedClockDoesNotPermitCleanupWait() = expiredCleanup(false)
    @Test fun expiredSeparateOperationClockDoesNotPermitCleanupWait() = expiredCleanup(true)
    // Historical identity retained; parent reconciliation permits only the live trusted allowance.
    @Test fun unobservedLiveClockCannotAuthorizeCleanupWait() {
        val time = AuthTestClock(); val port = AuthScriptPort()
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val armed = AtomicBoolean()
        val transport = newChatGptAuthTransport(port, {
            if (Thread.currentThread().name == "chatgpt-auth-reaper" && armed.compareAndSet(true, false)) {
                entered.countDown(); authAwait(release)
            }
            time.nanos.get()
        }, time.now::get)
        val call = transport.prepareDiscovery(time.operation())
        val result = AtomicReference<ChatGptAuthSettlement>()
        val closer = Thread({ result.set(call.cancelAndSettle(250_000_000L)) }, "chatgpt-auth-live-probe-cleanup")
        try {
            armed.set(true); authAwait(entered); closer.start()
            authEventually { authCallWaitCount(call) > 0 }
            assertTrue(authCallLastWait(call) in 1..25_000_000L)
            time.authority.advanceNanos(250_000_000L)
            authJoin(closer)
            assertEquals(ChatGptAuthSettlement.UNSETTLED, result.get())
            assertEquals(1, authTransportCount(transport, "permits"))
            val requests = authCallWaitCount(call)
            assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(250_000_000L))
            assertEquals(requests, authCallWaitCount(call), "repeated cleanup cannot renew its first allowance")
            time.advance(31)
            assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(250_000_000L))
            assertEquals(requests, authCallWaitCount(call), "trusted expiry authorizes zero additional waits")
        } finally {
            release.countDown(); if (closer.state != Thread.State.NEW) authJoin(closer)
            authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        }
    }
    private fun expiredCleanup(separate: Boolean, expire: Boolean = true) {
        val time = AuthTestClock(); val operationTime = if (separate) AuthTestClock(7_000_000L) else time
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val done = CountDownLatch(1)
        val armed = AtomicBoolean(); val observedWaiting = AtomicBoolean(); val result = AtomicReference<ChatGptAuthSettlement>()
        val transport = newChatGptAuthTransport(AuthScriptPort(), {
            val sample = time.nanos.get()
            if (Thread.currentThread().name == "chatgpt-auth-reaper" && armed.compareAndSet(true, false)) {
                entered.countDown(); authAwait(release)
            }
            sample
        }, time.now::get)
        val operation = operationTime.operation()
        val call = transport.prepareDiscovery(operation)
        val elapsed = AtomicLong()
        val closer = Thread({
            val start = System.nanoTime()
            try { result.set(call.cancelAndSettle(250_000_000L)) }
            finally { elapsed.set(System.nanoTime() - start); done.countDown() }
        }, "chatgpt-auth-review-expired-cleanup")
        var finished = false
        try {
            armed.set(true); authAwait(entered)
            if (expire) { operationTime.advance(31); assertFailsWith<TimeoutException> { operation.check() } }
            else operation.check()
            closer.start()
            finished = done.await(100, TimeUnit.MILLISECONDS)
            observedWaiting.set(closer.state == Thread.State.TIMED_WAITING && closer.stackTrace.any {
                it.className == "decompengine.chatgpt.AuthCall" && it.methodName == "settle"
            })
            authJoin(closer)
            println("expired_cleanup separate=$separate finishedWithin100ms=$finished timedWaitAfterExpiry=${observedWaiting.get()} elapsedNanos=${elapsed.get()} settlement=${result.get()} permits=${authTransportCount(transport, "permits")}")
            assertEquals(ChatGptAuthSettlement.UNSETTLED, result.get())
            assertEquals(1, authTransportCount(transport, "permits"))
        } finally {
            release.countDown()
            if (closer.state != Thread.State.NEW) authJoin(closer)
            authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        }
        assertTrue(finished, "expired original operation must not receive a positive cleanup wait")
        assertFalse(observedWaiting.get(), "no timed wait after original deadline expiry")
    }

    @Test fun expiredDeadlineRejectsLateSubscriptionBeforeDemand() {
        val time = AuthTestClock(); val port = AuthScriptPort()
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val armed = AtomicBoolean()
        val transport = newChatGptAuthTransport(port, {
            val sample = time.nanos.get()
            if (Thread.currentThread().name == "chatgpt-auth-reaper" && armed.compareAndSet(true, false)) {
                entered.countDown(); authAwait(release)
            }
            sample
        }, time.now::get)
        port.scripts.add(AuthScript(authDiscovery(), action = { }))
        val call = transport.prepareDiscovery(time.operation()); call.start(authGate())
        try {
            armed.set(true); authAwait(entered); time.advance(31)
            val exchange = port.exchanges.single(); exchange.subscribe()
            println("expired_subscription demand=${exchange.demands.get()} cancelled=${exchange.cancellations.get()}")
            assertEquals(0, exchange.demands.get(), "no demand may be issued after original captured deadline")
            assertEquals(1, exchange.cancellations.get())
        } finally { release.countDown(); authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED } }
    }

    @Test fun lateSubscriptionBlockedClockRetainsOwnershipUntilCancelAcknowledges() = lateSubscriptionClock("block-cancel")
    @Test fun lateSubscriptionBlockedClockCanAcknowledgeLiveDemand() = lateSubscriptionClock("block-live")
    @Test fun lateSubscriptionReentrantClockCannotDemand() = lateSubscriptionClock("reenter")
    @Test fun lateSubscriptionThrowingClockCancelsBeforeAcknowledgingAndKeepsOriginalFailure() = lateSubscriptionClock("throw")
    @Test fun fencedLateSubscriptionNeverCallsBlockingClock() = lateSubscriptionClock("fenced")
    @Test fun duplicateLateSubscriptionNeverSamplesOrDemandsAgain() = lateSubscriptionClock("duplicate")
    private fun lateSubscriptionClock(mode: String) {
        val clock = AuthTestClock(); val port = AuthScriptPort()
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val cancelEntered = CountDownLatch(1); val cancelRelease = CountDownLatch(1)
        val samples = AtomicInteger(); val demands = AtomicInteger(); val cancels = AtomicInteger()
        val armed = AtomicBoolean(); val failure = AtomicReference<Throwable>()
        val cancelThrows = AtomicBoolean(true)
        val reentered = AtomicReference<ChatGptAuthSettlement>()
        lateinit var transport: ChatGptAuthTransport
        transport = newChatGptAuthTransport(port, {
            if (Thread.currentThread().name == "chatgpt-auth-subscription-owner" && armed.compareAndSet(true, false)) {
                samples.incrementAndGet()
                when (mode) {
                    "block-cancel", "block-live" -> { entered.countDown(); authAwait(release) }
                    "reenter" -> reentered.set(transport.shutdown(0))
                    "throw" -> throw ChatGptAuthHttpException(ChatGptAuthHttpFailure.DEPENDENCY_FAILED, ChatGptAuthDispatchEvidence.MAY_HAVE_BEEN_SENT)
                    else -> error("fenced subscription sampled clock")
                }
            }
            clock.nanos.get()
        }, clock.now::get)
        port.scripts.add(AuthScript(action = { }))
        val call = transport.prepareDiscovery(clock.operation()); call.start(authGate())
        val exchange = port.exchanges.single()
        if (mode == "fenced") call.cancel()
        if (mode == "duplicate") exchange.subscribe()
        val value = object : Flow.Subscription {
            override fun request(n: Long) { demands.incrementAndGet() }
            override fun cancel() {
                cancels.incrementAndGet()
                if (mode == "throw" && cancelThrows.get()) {
                    cancelEntered.countDown(); authAwait(cancelRelease)
                    throw ChatGptAuthHttpException(ChatGptAuthHttpFailure.INVALID_BODY, ChatGptAuthDispatchEvidence.MAY_HAVE_BEEN_SENT)
                }
            }
        }
        val worker = Thread({ try { exchange.subscriber.onSubscribe(value) } catch (e: Throwable) { failure.set(e) } },
            "chatgpt-auth-subscription-owner")
        try {
            armed.set(true); worker.start()
            if (mode.startsWith("block")) {
                authAwait(entered)
                assertEquals(1, authTransportCount(transport, "permits"))
                if (mode == "block-cancel") {
                    assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(0))
                    assertEquals(1, authTransportCount(transport, "permits"))
                }
                assertEquals(0, demands.get()); release.countDown()
            }
            if (mode == "throw") {
                authAwait(cancelEntered)
                assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(0))
                assertEquals(1, authTransportCount(transport, "permits"))
                assertEquals(0, demands.get()); cancelRelease.countDown()
            }
            authJoin(worker); failure.get()?.let { throw it }
            assertEquals(if (mode == "block-live") 1 else 0, demands.get())
            if (mode != "block-live") assertTrue(cancels.get() > 0)
            if (mode in listOf("fenced", "duplicate")) assertEquals(0, samples.get()) else assertEquals(1, samples.get())
            if (mode == "reenter") assertEquals(ChatGptAuthSettlement.UNSETTLED, reentered.get())
            if (mode == "throw") {
                assertEquals(ChatGptAuthHttpFailure.DEPENDENCY_FAILED, (call.await() as ChatGptAuthHttpOutcome.Failed).failure)
                assertEquals(ChatGptAuthSettlement.UNSETTLED, call.cancelAndSettle(0))
                assertEquals(1, authTransportCount(transport, "permits"))
            }
        } finally {
            release.countDown(); cancelRelease.countDown(); cancelThrows.set(false)
            if (worker.state != Thread.State.NEW) authJoin(worker)
            authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        }
    }

}
