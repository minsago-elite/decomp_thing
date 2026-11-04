package decompengine.chatgpt

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Timeout

@Timeout(8)
class ChatGptLoopbackListenerTest {
    private val host = "127.0.0.1:12345"
    private fun request(target: String = "/auth/callback?state=s&code=c", authority: String = host, extra: String = "") =
        "GET $target HTTP/1.1\r\nHost: $authority\r\n$extra\r\n"
    private fun parse(raw: String, chunk: Int = 1): ChatGptCallbackEnvelope {
        val parser = ChatGptCallbackEnvelope(host)
        for (bytes in raw.toByteArray(StandardCharsets.ISO_8859_1).asList().chunked(chunk)) parser.feed(ByteBuffer.wrap(bytes.toByteArray()))
        return parser
    }

    @Test fun parserPositiveIndependentFragmentationAndRawTargetPreservation() {
        val raw = "/auth/callback?code=a%2Bb&state=S%26x&client_id=oaiapp_fixture"
        for (chunk in listOf(1, 2, 7, 2048)) {
            val p = parse(request(raw).replace("Host:", "hOsT:"), chunk)
            assertEquals(ChatGptCallbackEnvelope.State.ADMITTED, p.state)
            assertEquals(raw, p.rawTarget)
            assertFalse(p.toString().contains("a%2Bb"))
        }
    }

    @Test fun parserRejectsHostTargetMethodVersionAndFramingWithoutNormalization() {
        val valid = request()
        val hostile = listOf(
            valid.replace("GET ", "POST "), valid.replace("HTTP/1.1", "HTTP/1.0"),
            valid.replace("/auth/callback?", "http://$host/auth/callback?"),
            valid.replace("/auth/callback?", "/auth/%63allback?"),
            valid.replace("/auth/callback?", "/auth/../auth/callback?"),
            valid.replace("/auth/callback?", "/favicon.ico?"),
            valid.replace("127.0.0.1", "localhost"), valid.replace(":12345", ":012345"),
            valid.replace("Host:", "Host :"), valid.replace("Host:", " Host:"),
            valid.replace("Host: $host\r\n", ""), request(extra = "hOsT: $host\r\n"),
            valid.replace("\r\n", "\n"), valid.replace("\r\n", "\rX"),
            request(extra = "X: \u0080\r\n"), request(extra = "X: a\u0000b\r\n"),
            request(extra = "Content-Length: 0\r\n"), request(extra = "Content-Length: 2\r\n") + "xx",
            request(extra = "Transfer-Encoding: chunked\r\n"), request(extra = "Upgrade: websocket\r\n"),
            request(extra = "Connection: keep-alive, Upgrade\r\n"), request(extra = "Expect: 100-continue\r\n"),
            request(extra = "X: one\r\n folded\r\n"), valid + valid, valid + "body",
            request("/auth/callback?state=x#fragment"), request("/auth/callback?state=x\\y"),
        )
        for ((i, raw) in hostile.withIndex()) {
            val p = parse(raw, 2048)
            assertEquals(ChatGptCallbackEnvelope.State.REJECTED, p.state, "hostile fixture $i")
            assertNull(p.rawTarget)
        }
    }

    @Test fun parserBoundsQueryLineHeaderCountAndAggregateBeforeAdmission() {
        assertEquals(ChatGptCallbackEnvelope.State.ADMITTED, parse(request("/auth/callback?" + "x".repeat(16 * 1024)), 2048).state)
        assertEquals(ChatGptCallbackEnvelope.State.REJECTED, parse(request("/auth/callback?" + "x".repeat(16 * 1024 + 1)), 2048).state)
        assertEquals(ChatGptCallbackEnvelope.State.REJECTED, parse("GET " + "x".repeat(18 * 1024), 2048).state)
        assertEquals(ChatGptCallbackEnvelope.State.ADMITTED, parse(request(extra = "X: a\r\n".repeat(31))).state)
        assertEquals(ChatGptCallbackEnvelope.State.REJECTED, parse(request(extra = "X: a\r\n".repeat(32))).state)
        val overhead = "Host: $host\r\nX: \r\n\r\n".length
        assertEquals(ChatGptCallbackEnvelope.State.ADMITTED, parse(request(extra = "X: " + "a".repeat(8192 - overhead) + "\r\n"), 2048).state)
        assertEquals(ChatGptCallbackEnvelope.State.REJECTED, parse(request(extra = "X: " + "a".repeat(8193 - overhead) + "\r\n"), 2048).state)
    }

    private class Session(timeout: Duration = Duration.ofSeconds(6)) : AutoCloseable {
        val life = ChatGptAuthLifetime.start(timeout)
        val bound = try { ChatGptLoopbackListener().bind(life) } catch (e: Throwable) { life.settle(); throw e }
        @Volatile var onProtocolCheck: () -> Unit = {}
        val attempt = try { ChatGptPlanOAuthAttempt.start(
            ChatGptPlanOAuthRegistration.Returning("oaiapp_fixture", "urn:uuid:12345678-1234-1234-1234-123456789abc"), bound.redirect,
            ChatGptPlanOAuthClock { onProtocolCheck(); System.nanoTime() }, ChatGptPlanOAuthRandom { bytes -> bytes.fill(37) },
            ChatGptPlanOAuthCancellation { try { life.check(); false } catch (_: Exception) { true } },
        ) } catch (e: Throwable) { bound.close(); ChatGptAuthLifetimeTest.settleEventually(life); throw e }
        val state = URLDecoder.decode(attempt.authorizationRequest().uri.substringAfter("&state=").substringBefore('&'), "UTF-8")
        val result = AtomicReference<ChatGptPlanOAuthAttempt.CallbackResult?>()
        val failure = AtomicReference<Throwable?>()
        val started = CountDownLatch(1)
        val thread = Thread({
            started.countDown()
            try { result.set(bound.await(attempt, life)) } catch (e: Throwable) { failure.set(e) }
        }, "chatgpt-test-await")
        val clients = ArrayList<Socket>()
        fun start() { thread.start(); check(started.await(1, TimeUnit.SECONDS)) }
        fun socket(): Socket {
            val socket = Socket()
            clients.add(socket)
            socket.soTimeout = 3000
            socket.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), bound.redirect.port), 1000)
            return socket
        }
        fun wire(query: String = "state=$state&code=CANARY-code-positive"): String =
            "GET /auth/callback?$query HTTP/1.1\r\nHost: 127.0.0.1:${bound.redirect.port}\r\n\r\n"
        fun send(raw: String = wire()): String {
            val socket = socket()
            socket.getOutputStream().write(raw.toByteArray(StandardCharsets.US_ASCII))
            return socket.getInputStream().readBytes().toString(StandardCharsets.US_ASCII)
        }
        fun joined() { thread.join(3500); assertFalse(thread.isAlive) }
        override fun close() {
            clients.forEach { it.close() }
            life.cancel(); bound.close()
            if (thread.state != Thread.State.NEW) thread.join(1500)
            assertFalse(thread.isAlive)
            ChatGptAuthLifetimeTest.settleEventually(life)
        }
    }

    private fun assertClosed(socket: Socket) {
        // Closing a listener with unread bytes can produce either TCP FIN or RST; both revoke the peer.
        val closed = try { socket.getInputStream().read() == -1 } catch (_: java.net.SocketException) { true }
        assertTrue(closed)
    }

    private fun assertReply(reply: String) {
        assertEquals("Return to the application.\n", reply.substringAfter("\r\n\r\n"))
        for (line in listOf("Cache-Control: no-store", "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'", "Referrer-Policy: no-referrer", "X-Content-Type-Options: nosniff", "Connection: close", "Content-Length: 26")) assertTrue(reply.contains(line))
        for (secret in listOf("CANARY", "state=", "code=", "oaiapp_", "Location:", "Set-Cookie:", "Access-Control")) assertFalse(reply.contains(secret))
    }

    @Test @Tag("socket") fun actualBoundPortIsUsedBeforeAuthorizationAndInRepeatedExchange() {
        Session().use { s ->
            assertTrue(s.bound.redirect.port in 1..65535)
            val uri = URLDecoder.decode(s.attempt.authorizationRequest().uri, "UTF-8")
            assertTrue(uri.contains("redirect_uri=http://127.0.0.1:${s.bound.redirect.port}/auth/callback"))
            s.start(); assertReply(s.send()); s.joined()
            assertNull(s.failure.get())
            val code = assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(s.result.get())
            val a = code.prepareExchange().encodedBody
            assertEquals(a, code.prepareExchange().encodedBody)
            assertTrue(URLDecoder.decode(a, "UTF-8").contains("redirect_uri=http://127.0.0.1:${s.bound.redirect.port}/auth/callback"))
            assertTrue(s.life.claimDispatch()); assertFalse(s.life.claimDispatch())
            assertFailsWith<ChatGptAuthException> { s.bound.await(s.attempt, s.life) }
        }
    }

    @Test @Tag("socket") fun unrelatedAndMalformedRequestsLeaveProtocolAvailableThenPositiveSucceeds() {
        Session().use { s ->
            s.start()
            val good = s.wire()
            val rejected = listOf(good.replace("GET", "POST"), good.replace("/auth/callback?", "/favicon.ico?"),
                good.replace("127.0.0.1", "localhost"), good.replace("Host:", "Host :"),
                good.replace("\r\n\r\n", "\r\nHost: 127.0.0.1:${s.bound.redirect.port}\r\n\r\n"),
                good.replace("/auth/callback?", "/auth/%63allback?"), good + good,
                good.replace("\r\n\r\n", "\r\nContent-Length: 0\r\n\r\n"))
            for (raw in rejected) assertReply(s.send(raw))
            assertNull(s.result.get()); assertTrue(s.thread.isAlive)
            assertReply(s.send()); s.joined()
            assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(s.result.get())
        }
    }

    @Test @Tag("socket") fun firstAdmittedBadProtocolIsTerminalAndCannotBeRepaired() {
        val fixtures = listOf(
            "state=wrong&code=CANARY" to ChatGptPlanOAuthFailure.STATE_MISMATCH,
            "code=CANARY" to ChatGptPlanOAuthFailure.MISSING_STATE,
            "state=STATE&state=STATE&code=CANARY" to ChatGptPlanOAuthFailure.DUPLICATE_PARAMETER,
            "state=STATE&error=access_denied" to ChatGptPlanOAuthFailure.OAUTH_REJECTED,
            "state=STATE&code=CANARY&client_id=oaiapp_other" to ChatGptPlanOAuthFailure.CLIENT_MISMATCH,
        )
        for ((query, failure) in fixtures) Session().use { s ->
            s.start(); assertReply(s.send(s.wire(query.replace("STATE", s.state)))); s.joined()
            assertEquals(failure, assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Rejected>(s.result.get()).failure)
            val retry = s.attempt.consumeCallback("GET", "127.0.0.1:${s.bound.redirect.port}", "/auth/callback?state=${s.state}&code=correct")
            assertEquals(ChatGptPlanOAuthFailure.ATTEMPT_USED, assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Rejected>(retry).failure)
            assertFails { s.socket() }
        }
    }

    @Test @Tag("socket") fun sixteenthUnrelatedConnectionTerminatesWithInputLimit() {
        Session().use { s ->
            s.start()
            repeat(16) { assertReply(s.send(s.wire().replace("/auth/callback?", "/favicon.ico?"))) }
            s.joined(); assertNull(s.result.get())
            assertEquals(ChatGptAuthFailure.CALLBACK_INPUT_LIMIT, assertIs<ChatGptAuthException>(s.failure.get()).failure)
            // Listener never handed these envelopes to the protocol.
            assertEquals(ChatGptPlanOAuthFailure.CANCELLED, s.attempt.cancel())
        }
    }

    @Test @Tag("socket") fun concurrentCallbacksHaveOneProtocolWinner() {
        Session().use { s ->
            val a = s.socket(); val b = s.socket()
            a.getOutputStream().write(s.wire("state=${s.state}&code=CANARY-a").toByteArray())
            b.getOutputStream().write(s.wire("state=${s.state}&code=CANARY-b").toByteArray())
            s.start(); s.joined()
            val code = assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(s.result.get())
            assertTrue(code.code in setOf("CANARY-a", "CANARY-b"))
            assertTrue(s.life.claimDispatch()); assertFalse(s.life.claimDispatch())
            assertEquals(ChatGptPlanOAuthFailure.ATTEMPT_USED, s.attempt.cancel())
        }
    }

    @Test @Tag("socket") fun fourSlowlorisConnectionsExpireAndFifthIsRefused() {
        Session().use { s ->
            s.start()
            val slow = List(4) { s.socket().also { it.getOutputStream().write("GET /auth/callback?".toByteArray()) } }
            // Ordered connections plus a bounded scheduling allowance make all four live before fifth.
            Thread.sleep(100)
            val fifth = s.socket()
            assertEquals(-1, fifth.getInputStream().read())
            val start = System.nanoTime()
            slow.forEach { assertEquals(-1, it.getInputStream().read()) }
            assertTrue(System.nanoTime() - start < 2_500_000_000)
            assertReply(s.send()); s.joined()
            assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(s.result.get())
        }
    }

    @Test @Tag("socket") fun cancellationAndExplicitCloseReapListenerDuringRead() {
        for (cancel in listOf(true, false)) Session().use { s ->
            s.start(); val slow = s.socket(); slow.getOutputStream().write("GET /".toByteArray())
            val start = System.nanoTime()
            if (cancel) s.life.cancel() else s.bound.close()
            s.joined()
            assertTrue(System.nanoTime() - start < 500_000_000)
            assertNull(s.result.get())
            assertIs<ChatGptAuthException>(s.failure.get())
            assertClosed(slow)
            if (cancel) assertFalse(s.life.publication().enterCommit())
        }
    }

    @Test @Tag("socket") fun shortParentClipsConnectionLifetimeAndLateResults() {
        Session(Duration.ofMillis(150)).use { s ->
            s.start(); val slow = s.socket(); slow.getOutputStream().write("G".toByteArray())
            val start = System.nanoTime(); s.joined()
            assertTrue(System.nanoTime() - start < 700_000_000)
            assertNull(s.result.get()); assertIs<ChatGptAuthException>(s.failure.get())
            assertFalse(s.life.publication().enterCommit())
        }
    }

    @Test @Tag("socket") fun beforeAwaitCancelWrongOwnerAndDuplicateBindFailClosed() {
        Session().use { s ->
            val other = ChatGptAuthLifetime.start()
            try {
                assertEquals(ChatGptAuthFailure.INVALID_OWNER, assertFailsWith<ChatGptAuthException> { s.bound.await(s.attempt, other) }.failure)
                assertEquals(ChatGptAuthFailure.ATTEMPT_USED, assertFailsWith<ChatGptAuthException> { ChatGptLoopbackListener().bind(s.life) }.failure)
            } finally { other.settle() }
            s.life.cancel(); s.start(); s.joined()
            assertNull(s.result.get()); assertIs<ChatGptAuthException>(s.failure.get())
        }
        val cancelled = ChatGptAuthLifetime.start(); cancelled.cancel()
        assertFailsWith<ChatGptAuthException> { ChatGptLoopbackListener().bind(cancelled) }
        ChatGptAuthLifetimeTest.settleEventually(cancelled)
    }

    @Test @Tag("socket") fun cancellationInsideProtocolValidationCannotReturnLateCode() {
        Session().use { s ->
            s.onProtocolCheck = { s.life.cancel() }
            s.start()
            val socket = s.socket()
            socket.getOutputStream().write(s.wire().toByteArray())
            s.joined()
            assertNull(s.result.get()); assertIs<ChatGptAuthException>(s.failure.get())
            assertFalse(s.life.claimDispatch()); assertFalse(s.life.publication().enterCommit())
            assertEquals(ChatGptPlanOAuthFailure.ATTEMPT_USED, s.attempt.cancel())
        }
    }

    @Test @Tag("socket") fun cancellationInsideFormSerializationRevokesSubmissionDespiteLateForm() {
        Session().use { s ->
            s.start(); assertReply(s.send()); s.joined()
            val code = assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(s.result.get())
            s.onProtocolCheck = { s.life.cancel() }
            val late = code.prepareExchange()
            assertFalse(late.toString().contains("CANARY"))
            assertFalse(s.life.claimDispatch()); assertFalse(s.life.publication().enterCommit())
        }
    }

    @Test @Tag("socket") fun slowTrustedInitializationUsesAdmissionOriginAndClosesAlreadyBoundSocket() {
        val now = java.util.concurrent.atomic.AtomicLong()
        val life = ChatGptAuthLifetime.start(Duration.ofSeconds(1), clock = now::get)
        val bound = ChatGptLoopbackListener().bind(life)
        var launches = 0
        try {
            val attempt = ChatGptPlanOAuthAttempt.start(
                ChatGptPlanOAuthRegistration.New("urn:uuid:12345678-1234-1234-1234-123456789abc", "fixture"),
                bound.redirect, ChatGptPlanOAuthClock(now::get), ChatGptPlanOAuthRandom { it.fill(17); now.addAndGet(500_000_000) },
            )
            assertFailsWith<ChatGptAuthException> { life.check(); attempt.authorizationRequest(); launches++ }
            assertEquals(0, launches); assertFalse(life.publication().enterCommit())
        } finally { bound.close(); ChatGptAuthLifetimeTest.settleEventually(life) }
        Socket().use { peer -> assertFails { peer.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127,0,0,1)), bound.redirect.port), 1000) } }
    }

    @Test @Tag("socket") fun failureBeforeSocketAcquisitionDoesNotLeakAttemptCapacity() {
        val life = ChatGptAuthLifetime.start()
        try {
            repeat(16) { life.own(object : ChatGptAuthResource() { override fun stopAndAwait() = true }) }
            assertEquals(ChatGptAuthFailure.RESOURCE_LIMIT, assertFailsWith<ChatGptAuthException> { ChatGptLoopbackListener().bind(life) }.failure)
        } finally { ChatGptAuthLifetimeTest.settleEventually(life) }
        Session().use { s -> s.start(); assertReply(s.send()); s.joined(); assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(s.result.get()) }
    }

    @Test @Tag("socket") fun failureAfterActualBindClosesPartiallyAcquiredResourcesAndRedactsCause() {
        val ownerChecks = AtomicInteger()
        val life = ChatGptAuthLifetime.start(parent = object : ChatGptAuthParent() {
            override fun remainingNanos(): Long {
                if (Thread.currentThread().name == "chatgpt-auth-loopback" && ownerChecks.incrementAndGet() == 2) {
                    throw IllegalStateException("CANARY-bind-private-hint")
                }
                return 5_000_000_000
            }
        })
        try {
            val e = assertFailsWith<ChatGptAuthException> { ChatGptLoopbackListener().bind(life) }
            assertNull(e.cause); assertTrue(e.suppressed.isEmpty()); assertFalse(e.toString().contains("CANARY"))
            assertTrue(ownerChecks.get() >= 2) // cleanup also consults the remaining parent budget
        } finally { ChatGptAuthLifetimeTest.settleEventually(life) }
        Session().use { s -> s.start(); assertReply(s.send()); s.joined(); assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(s.result.get()) }
    }

    @Test @Tag("socket") fun protocolExceptionAndPrivacyCanariesNeverEscapeToRepliesOrThrowableChains() {
        Session().use { s ->
            s.onProtocolCheck = { throw IllegalStateException("CANARY-secret-value") }
            s.start(); val socket = s.socket(); socket.getOutputStream().write(s.wire().toByteArray())
            s.joined()
            val e = assertIs<ChatGptAuthException>(s.failure.get())
            assertEquals(ChatGptAuthFailure.LISTENER_FAILED, e.failure)
            assertNull(e.cause); assertTrue(e.suppressed.isEmpty()); assertFalse(e.toString().contains("CANARY"))
            assertNull(s.result.get())
        }
        Session().use { s ->
            s.start()
            val canaries = listOf("CANARY-secret-value", "CANARY%2Dsecret%2Dvalue", "Q0FOQVJZLXNlY3JldC12YWx1ZQ", "CANARY-secret-" + "value")
            for (canary in canaries) {
                val reply = s.send(s.wire("state=$canary&code=$canary").replace("/auth/callback?", "/unrelated?"))
                assertReply(reply)
                assertFalse(reply.contains(canary)); assertFalse(s.bound.toString().contains(canary))
            }
            assertReply(s.send()); s.joined()
        }
    }

    @Test @Tag("socket") fun peerThatNeverReadsAcknowledgementCannotHoldListenerOpen() {
        Session().use { s ->
            s.start(); val socket = s.socket()
            socket.getOutputStream().write(s.wire().toByteArray())
            s.joined() // no read until after the entire listener owner has terminated
            assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(s.result.get())
            assertReply(socket.getInputStream().readBytes().toString(StandardCharsets.US_ASCII))
            assertEquals(ChatGptAuthSettlement.SETTLED, s.bound.close())
        }
    }

    @Test @Tag("socket") fun uncooperativeProtocolCallbackIsQuarantinedThenExplicitlyReleasedAndJoined() {
        Session().use { s ->
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val owner = AtomicReference<Thread?>()
            s.onProtocolCheck = { owner.set(Thread.currentThread()); entered.countDown(); release.await() }
            try {
                s.start(); val socket = s.socket(); socket.getOutputStream().write(s.wire().toByteArray())
                assertTrue(entered.await(1, TimeUnit.SECONDS))
                s.life.cancel(); s.joined()
                assertEquals(ChatGptAuthSettlement.UNSETTLED, s.life.settle())
                assertTrue(owner.get()!!.isAlive)
                assertFalse(s.life.claimDispatch()); assertFalse(s.life.publication().enterCommit())
                assertNull(s.result.get())
            } finally {
                release.countDown(); owner.get()?.join(1000)
                assertFalse(owner.get()?.isAlive == true)
            }
        }
    }

    @Test @Tag("socket") fun resetPeerIsolatedFromSubsequentValidCallback() {
        Session().use { s ->
            s.start()
            repeat(3) {
                val broken = s.socket()
                broken.getOutputStream().write("GET /auth/".toByteArray())
                broken.setSoLinger(true, 0); broken.close()
                Thread.sleep(30)
            }
            assertTrue(s.thread.isAlive)
            assertReply(s.send()); s.joined()
            assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(s.result.get())
        }
    }

    @Test @Tag("socket") fun processAttemptCapRetainsQuarantineUntilExplicitAcknowledgedReaping() {
        val lives = ArrayList<ChatGptAuthLifetime>()
        val bounds = ArrayList<ChatGptBoundCallback>()
        val release = CountDownLatch(1)
        val entered = CountDownLatch(1)
        var stuck: Thread? = null
        try {
            repeat(4) { val l = ChatGptAuthLifetime.start(); lives.add(l); bounds.add(ChatGptLoopbackListener().bind(l)) }
            lives[0].own(object : ChatGptAuthResource() {
                override fun stopAndAwait(): Boolean { stuck = Thread.currentThread(); entered.countDown(); release.await(); return true }
            })
            assertEquals(ChatGptAuthSettlement.UNSETTLED, lives[0].settle())
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            assertTrue(stuck!!.isAlive); assertFalse(lives[0].publication().enterCommit())
            val fifth = ChatGptAuthLifetime.start()
            try { assertEquals(ChatGptAuthFailure.RESOURCE_LIMIT, assertFailsWith<ChatGptAuthException> { ChatGptLoopbackListener().bind(fifth) }.failure) }
            finally { fifth.settle() }
            release.countDown(); stuck!!.join(1000); assertFalse(stuck!!.isAlive)
            ChatGptAuthLifetimeTest.settleEventually(lives[0])
            val replacement = ChatGptAuthLifetime.start(); lives.add(replacement)
            bounds.add(ChatGptLoopbackListener().bind(replacement))
        } finally {
            release.countDown(); stuck?.join(1000)
            bounds.forEach { it.close() }
            lives.forEach { ChatGptAuthLifetimeTest.settleEventually(it) }
        }
    }
}
