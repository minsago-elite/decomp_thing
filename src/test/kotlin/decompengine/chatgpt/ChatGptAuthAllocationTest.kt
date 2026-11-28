package decompengine.chatgpt

import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.URI
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*
import org.junit.jupiter.api.Test

internal class ChatGptAuthAllocationTest {
    @Test fun rejectedWholeBatchDoesNotAdvanceAnySourceBuffer() = AuthTestRig().use { rig ->
        val first = ByteBuffer.wrap(byteArrayOf(1))
        val sliced = ByteBuffer.wrap(ByteArray(262145).also { it.fill(2) }, 1, 262144).slice().asReadOnlyBuffer()
        var observation: ChatGptAuthBoundaryFixtures.CopyObservation? = null
        rig.port.scripts.add(AuthScript(action = { exchange ->
            exchange.subscribe()
            observation = ChatGptAuthBoundaryFixtures.observe(listOf(first, sliced)) { exchange.body(first, sliced) }
        }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation())
        call.start(authGate())
        assertEquals(ChatGptAuthHttpFailure.BODY_LIMIT, (call.await() as ChatGptAuthHttpOutcome.Failed).failure,
            "oversized whole batch is refused")
        assertEquals(0, observation?.advancedBytes, "no rejected source bytes were copied")
        assertEquals(listOf(0, 0), observation?.positionsAfter, "rejection leaves buffer cursors unchanged")
    }

    @Test fun hugeClaimedAggregateListFailsAtBoundBeforeAnyCopy() = AuthTestRig().use { rig ->
        val accesses = AtomicInteger()
        val observed = mutableListOf<ByteBuffer>()
        val claimed = object : AbstractList<ByteBuffer>() {
            override val size: Int = Int.MAX_VALUE
            override fun get(index: Int): ByteBuffer {
                accesses.incrementAndGet()
                return ByteBuffer.wrap(ByteArray(131072)).also(observed::add)
            }
        }
        lateinit var delivered: HttpResponse.BodySubscriber<ByteArray>
        rig.port.scripts.add(AuthScript(action = { exchange ->
            exchange.subscribe()
            delivered = exchange.subscriber
            delivered.onNext(claimed)
        }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
        assertEquals(ChatGptAuthHttpFailure.BODY_LIMIT, (call.await() as ChatGptAuthHttpOutcome.Failed).failure,
            "huge claimed list is bounded at the first over-limit prefix")
        assertEquals(3, accesses.get(), "oversized aggregate is rejected without traversing its claimed tail")
        assertEquals(listOf(0, 0, 0), observed.map(ByteBuffer::position), "no prefix buffer is advanced before whole-batch acceptance")
    }

    @Test fun admittedSplitReadOnlyAndEmptySlicesCopyOnlyTheirRemainingBytes() = AuthTestRig().use { rig ->
        val body = authDiscovery()
        val slicedReadOnly = ByteBuffer.wrap(body, 0, 3).slice().asReadOnlyBuffer()
        val empty = ByteBuffer.allocate(0)
        val tail = ByteBuffer.wrap(body, 3, body.size - 3).slice()
        val before = listOf(slicedReadOnly.position(), empty.position(), tail.position())
        rig.port.scripts.add(AuthScript(action = { exchange ->
            exchange.subscribe(); exchange.body(slicedReadOnly, empty); exchange.body(tail); exchange.complete()
        }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation())
        call.start(authGate())
        assertTrue(call.await() is ChatGptAuthHttpOutcome.Document, "split JSON body is admitted")
        assertEquals(listOf(3, 0, body.size - 3), listOf(slicedReadOnly.position(), empty.position(), tail.position()).zip(before).map { it.first - it.second },
            "only actual remaining body bytes advance")
    }

    @Test fun declaredLengthMismatchAndClaimedOversizeFailBeforeBatchCopy() = AuthTestRig().use { rig ->
        val buffers = listOf(ByteBuffer.wrap("{}".toByteArray()), ByteBuffer.wrap(byteArrayOf(7)))
        rig.port.scripts.add(AuthScript(headers = mapOf("Content-Type" to listOf("application/json"), "Content-Length" to listOf("2")),
            action = { exchange -> exchange.subscribe(); exchange.body(*buffers.toTypedArray()); exchange.complete() }))
        val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
        val outcome = call.await()
        assertTrue(outcome is ChatGptAuthHttpOutcome.Failed, "content-length mismatch fails closed")
        assertEquals(listOf(0, 0), buffers.map(ByteBuffer::position), "mismatched batch rejected before source copy")
    }

    @Test fun headerCountsAndValuesUseExactAcceptedAndRejectedEdges() {
        val base = mapOf("Content-Type" to listOf("application/json"))
        val accepted64 = base + ("X-Test" to List(63) { "v" })
        val rejected65 = base + ("X-Test" to List(64) { "v" })
        for ((headers, accepted) in listOf(accepted64 to true, rejected65 to false)) {
            AuthTestRig().use { rig ->
                rig.port.scripts.add(AuthScript(headers = headers))
                val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
                val outcome = call.await()
                assertEquals(accepted, outcome is ChatGptAuthHttpOutcome.Document, "header count edge")
            }
        }
        for ((size, accepted) in listOf(8192 to true, 8193 to false)) {
            AuthTestRig().use { rig ->
                rig.port.scripts.add(AuthScript(headers = base + ("X-Test" to listOf("v".repeat(size)))))
                val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
                val outcome = call.await()
                assertEquals(accepted, outcome is ChatGptAuthHttpOutcome.Document, "header value edge")
            }
        }
    }

    @Test fun aggregateHeaderBoundaryAndLengthPreflightReject() {
        val base = mapOf("Content-Type" to listOf("application/json"))
        for ((size, accepted) in listOf(32768 to true, 32769 to false)) {
            AuthTestRig().use { rig ->
                // Two values plus their field names stay at or cross the aggregate byte cap.
                val overhead = 12 + "application/json".length + 32 + 4 * ("X-Test".length + 32)
                val valueTotal = size - overhead
                val each = valueTotal / 4
                val remainder = valueTotal - each * 4
                val headers = base + ("X-Test" to List(3) { "a".repeat(each) } + listOf("b".repeat(each + remainder)))
                rig.port.scripts.add(AuthScript(headers = headers))
                val call = rig.transport.prepareDiscovery(rig.clock.operation()); call.start(authGate())
                val outcome = call.await()
                assertEquals(accepted, outcome is ChatGptAuthHttpOutcome.Document, "aggregate header size edge")
            }
        }
    }

    @Test fun formFactoryEnforcesPerValueBoundBeforePublisherAndCountsUtf8Expansion() {
        val clock = AuthTestClock()
        val op = clock.operation()
        val deadline = op.deadline.cap(Duration.ofSeconds(10).toNanos())
        val exactFields = listOf("f0" to "%".repeat(16384), "f1" to "%".repeat(16384), "f2" to "%".repeat(10919))
        val exactPublisher = ChatGptAuthBoundaryFixtures.privateForm(exactFields, op, deadline)
        assertEquals(131072L, exactPublisher.contentLength(), "private form encoder accepts exact 128 KiB")
        val overFields = exactFields.toMutableList()
        val final = overFields.last()
        overFields[overFields.lastIndex] = final.first to (final.second + "a")
        assertEquals(ChatGptAuthHttpFailure.INVALID_FORM, assertFailsWith<ChatGptAuthHttpException> {
            ChatGptAuthBoundaryFixtures.privateForm(overFields, op, deadline)
        }.failure, "private form encoder refuses one byte over the cap")
        val unicodePublisher = ChatGptAuthBoundaryFixtures.privateForm(listOf("u" to "é𐍈"), op, deadline)
        assertEquals("u=%C3%A9%F0%90%8D%88", ChatGptAuthBoundaryFixtures.collect(unicodePublisher).toString(Charsets.US_ASCII),
            "UTF-8 multibyte and supplementary scalars are percent encoded bytewise")
        val valid = authRevocationPublisher(
            ChatGptLocalLogout(ChatGptPlanAccount("id", "issuer", "oaiapp_test", "label", null, null, 0, 0,
                ChatGptPlanAccount.State.READY, emptySet(), null), "oaiapp_test", "a".repeat(16384), false), op, deadline,
        )
        assertTrue(valid.contentLength() <= 131072, "bounded high-level revocation form")
        authFailure(ChatGptAuthHttpFailure.INVALID_FORM) {
            authRevocationPublisher(ChatGptLocalLogout(ChatGptPlanAccount("id", "issuer", "oaiapp_test", "label", null, null, 0, 0,
                ChatGptPlanAccount.State.READY, emptySet(), null), "oaiapp_test", "a".repeat(16385), false), op, deadline)
        }
        authFailure(ChatGptAuthHttpFailure.INVALID_FORM) {
            authRevocationPublisher(ChatGptLocalLogout(ChatGptPlanAccount("id", "issuer", "oaiapp_test", "label", null, null, 0, 0,
                ChatGptPlanAccount.State.READY, emptySet(), null), "oaiapp_test", "\uD83D" + "a".repeat(16383), false), op, deadline)
        }
    }

    @Test fun actualCodeAndRefreshRequestsUseFixedLiteralFieldSets() = AuthTestRig().use { rig ->
        val bound = authBound(rig)
        val codeOperation = rig.clock.operation()
        val codeRequest = authCodeRequest(bound.code, codeOperation, codeOperation.deadline.cap(Duration.ofSeconds(10).toNanos()))
        val codeBody = ChatGptAuthBoundaryFixtures.collect(codeRequest.bodyPublisher().orElseThrow())
        assertTrue(codeBody.isNotEmpty(), "actual code form is emitted")
        val codeText = codeBody.toString(Charsets.US_ASCII)
        assertTrue(codeText.startsWith("grant_type=authorization_code&client_id="), "code form order is fixed")
        assertTrue(codeText.contains("&code=") && codeText.contains("&redirect_uri=") && codeText.contains("&code_verifier=") &&
            codeText.endsWith("&resource=https%3A%2F%2Fapi.openai.com%2Fv1"), "code form fields are complete")
        assertFalse(codeText.contains("client_secret") || codeText.contains("scope="), "code form omits secret and scope")
        assertEquals(setOf("accept", "content-type"), codeRequest.headers().map().keys.map(String::lowercase).toSet(), "code request has only fixed headers")

        val fakeAccess = "access" + "-fixture"
        val fakeRefresh = "refresh" + "-fixture"
        val tokenResponse = "{\"access_token\":\"$fakeAccess\",\"refresh_token\":\"$fakeRefresh\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"openid\"}".toByteArray()
        rig.port.scripts.add(AuthScript(tokenResponse,
            action = { exchange -> exchange.subscribe() }))
        val operation = rig.clock.operation()
        val call = rig.transport.prepareRefresh("oaiapp_test", fakeRefresh, operation)
        call.start(authGate())
        val refresh = rig.port.requests.last()
        val refreshText = ChatGptAuthBoundaryFixtures.collect(refresh.bodyPublisher().orElseThrow()).toString(Charsets.US_ASCII)
        val expectedRefresh = listOf("grant_type=refresh_token", "client_id=oaiapp_test", "refresh_token=$fakeRefresh",
            "resource=https%3A%2F%2Fapi.openai.com%2Fv1").joinToString("&")
        assertTrue(refreshText == expectedRefresh,
            "refresh body has exact fixed literal field order")
        assertFalse(refreshText.contains("client_secret") || refreshText.contains("scope="), "refresh omits client secret and scope")
        assertEquals(setOf("accept", "content-type"), refresh.headers().map().keys.map(String::lowercase).toSet(), "refresh request has only fixed headers")
        val exchange = rig.port.exchanges.last()
        exchange.body(ByteBuffer.wrap(tokenResponse))
        exchange.complete()
        assertTrue(call.await() is ChatGptAuthHttpOutcome.Token, "scripted refresh response remains positive")
    }

    @Test fun actualCodeFactoryAcceptsUpstreamMaximumAndStaysBelowConservativeFormBound() = AuthTestRig().use { rig ->
        val client = "oaiapp_" + "x".repeat(160)
        val binding = rig.metadata.bindAuthorization(authSnapshot(client = null), ChatGptPlanOAuthRedirect.of(42321),
            ChatGptPlanOAuthClock(rig.clock.nanos::get), ChatGptPlanOAuthRandom { it.fill(7) },
            ChatGptPlanOAuthCancellation { false }, rig.clock.operation())
        val rawQuery = URI(binding.authorizationRequest().uri).rawQuery
        val state = rawQuery.split('&').first { it.startsWith("state=") }.substringAfter('=')
        val callback = "/auth/callback?state=$state&code=${"x".repeat(4096)}&client_id=$client"
        val code = binding.receiveCode(object : ChatGptAuthCodeReceiver() {
            override fun await(attempt: ChatGptPlanOAuthAttempt) = attempt.consumeCallback("GET", "127.0.0.1:42321", callback)
        }) as ChatGptPlanOAuthAttempt.CallbackResult.Code
        val operation = rig.clock.operation()
        val request = authCodeRequest(code, operation, operation.deadline.cap(Duration.ofSeconds(10).toNanos()))
        val body = ChatGptAuthBoundaryFixtures.collect(request.bodyPublisher().orElseThrow())
        assertEquals(4096, code.code.length, "actual OAuth parser admits the code factory maximum")
        assertEquals(167, code.issuedClientId.length, "actual OAuth parser admits the client identifier maximum")
        assertEquals(16 * 1024, ChatGptPlanOAuthAttempt.MAX_CALLBACK_QUERY_BYTES, "query byte ceiling is the upstream code bound")
        assertTrue(body.size < 50 * 1024, "actual code factory remains below the documented conservative 50 KiB bound")
        val text = body.toString(Charsets.US_ASCII)
        assertTrue(text.startsWith("grant_type=authorization_code&client_id=$client&code="), "maximum accepted code uses fixed field order")
        assertTrue(text.endsWith("&resource=https%3A%2F%2Fapi.openai.com%2Fv1"), "resource literal remains exact")
    }
}
