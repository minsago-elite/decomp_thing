package decompengine.chatgpt

import java.net.http.HttpRequest
import java.time.Instant
import java.util.concurrent.*
import java.util.concurrent.atomic.*
import kotlin.test.*

class ChatGptAuthMetadataTest {

    @Test fun metadataRejectsMismatchedTrustedDomainBeforeAnyFetch(): Unit = AuthTestRig().use { rig ->
        val other = AuthTestClock()
        authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) { rig.metadata.discovery(other.operation()) }
        assertEquals(0, rig.port.acquired.get()); assertEquals(0, rig.port.submitted.get())
    }
    @Test fun cacheFetchOriginIsSeparateFromOlderParentRoot(): Unit = AuthTestRig().use { rig ->
        val root = ChatGptDeadline.start(rig.clock.authority, 300_000_000_000L)
        rig.clock.advance(290)
        val op = ChatGptStoreOperation.fromDeadline(root, ChatGptOperationFence()) { false }
        rig.port.scripts.add(AuthScript(authDiscovery()))
        rig.metadata.discovery(op)
        rig.clock.advance(599)
        rig.metadata.discovery(rig.clock.operation())
        assertEquals(1, rig.port.submitted.get())
        rig.clock.advance(1); rig.port.scripts.add(AuthScript(authDiscovery()))
        rig.metadata.discovery(rig.clock.operation())
        assertEquals(2, rig.port.submitted.get())
    }
    private val key by lazy { AuthSigningKey() }
    @Test fun actualSignedProofUsesCapturedSnapshotCodeNonceAndReceptionTime(): Unit = AuthTestRig().use { rig ->
        val snapshot = authSnapshot(); val bound = authBound(rig, snapshot); val op = rig.clock.operation()
        val received = rig.clock.now.get()
        val reply = authToken(rig, bound, key, op)
        rig.port.scripts.add(AuthScript(key.jwks()))
        rig.clock.now.set(received.plusSeconds(30))
        val proof = rig.metadata.validateAuthorization(reply, op)
        assertEquals(snapshot.attemptId, proof.attemptId)
        assertTrue(proof.registration.clientId == bound.code.issuedClientId, "bound client")
        assertTrue(proof.registration.tokenSet.authorizationNonceHash == proof.authorizationNonceHash, "bound nonce hash")
        assertEquals(received.plusSeconds(3600), proof.registration.tokenSet.expiresAt)
        assertEquals(received.plusSeconds(30), proof.verifiedAt)
        assertEquals(received.plusSeconds(3600), proof.idTokenExpiresAt)
        assertEquals(2, rig.port.submitted.get())
        authFailure { rig.metadata.validateAuthorization(reply, op) }
    }
    @Test fun codeSwapDuplicateReservationAndOperationSwapAreRejected(): Unit = AuthTestRig().use { rig ->
        val first = authBound(rig); val second = authBound(rig); val op = rig.clock.operation()
        authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) { rig.transport.prepareCode(first.binding, second.code, op) }
        // A failed call consumes its binding conservatively; use the other original binding.
        val reply = authToken(rig, second, key, op)
        rig.port.scripts.add(AuthScript(key.jwks()))
        authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) { rig.metadata.validateAuthorization(reply, rig.clock.operation()) }
        authFailure { rig.transport.prepareCode(second.binding, second.code, op) }
        assertEquals(1, rig.port.requests.count { it.method() == "POST" })
    }
    @Test fun cancellationDuringTrustedReceiverReturnCannotRetainCode(): Unit = AuthTestRig().use { rig ->
        val cancelled = AtomicBoolean()
        val binding = rig.metadata.bindAuthorization(authSnapshot(), ChatGptPlanOAuthRedirect.of(42321),
            ChatGptPlanOAuthClock(rig.clock.nanos::get), ChatGptPlanOAuthRandom { it.fill(3) },
            ChatGptPlanOAuthCancellation(cancelled::get), rig.clock.operation())
        authFailure(ChatGptAuthHttpFailure.CANCELLED) {
            binding.receiveCode(object : ChatGptAuthCodeReceiver() {
                override fun await(attempt: ChatGptPlanOAuthAttempt): ChatGptPlanOAuthAttempt.CallbackResult {
                    cancelled.set(true); return ChatGptPlanOAuthAttempt.CallbackResult.Rejected(ChatGptPlanOAuthFailure.CANCELLED)
                }
            })
        }
    }
    @Test fun forgedTransportRepliesAndBindingsRejectedBeforeVirtualCalls(): Unit = AuthTestRig().use { rig ->
        val called = AtomicBoolean()
        val forged = object : ChatGptAuthTokenReply() {
            override val receivedAt: Instant get() { called.set(true); error("forged getter") }
            override val purpose: ChatGptAuthHttpPurpose get() { called.set(true); error("forged getter") }
            override fun validateAuthorization(keys: ChatGptOidcJwks, validatedAt: Instant, operation: ChatGptStoreOperation,
                jwksAlreadyRefetched: Boolean): ChatGptAuthorizationProof { called.set(true); error("forged method") }
            override fun discard() { called.set(true) }
        }
        authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) { rig.metadata.validateAuthorization(forged, rig.clock.operation()) }
        val binding = object : ChatGptAuthCodeBinding() {
            override fun authorizationRequest(): ChatGptPlanOAuthAttempt.AuthorizationRequest { called.set(true); error("forged") }
            override fun receiveCode(receiver: ChatGptAuthCodeReceiver): ChatGptPlanOAuthAttempt.CallbackResult { called.set(true); error("forged") }
            override fun claimCode(code: ChatGptPlanOAuthAttempt.CallbackResult.Code, operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline): HttpRequest { called.set(true); error("forged") }
            override fun prove(bytes: ByteArray, keys: ChatGptOidcJwks, receivedAt: Instant, validatedAt: Instant,
                operation: ChatGptStoreOperation, jwksAlreadyRefetched: Boolean): ChatGptAuthorizationProof { called.set(true); error("forged") }
        }
        val real = authBound(rig)
        authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) { rig.transport.prepareCode(binding, real.code, rig.clock.operation()) }
        assertFalse(called.get()); assertEquals(0, rig.port.acquired.get())
    }
    @Test fun transportPolicyMintBridgeRejectsForgedProjections() {
        var invoked = false
        val fakePolicy = object : ChatGptAuthDocumentCachePolicy() {
            override val reusable: Boolean get() { invoked = true; return true }
            override val maximumAgeNanos: Long get() { invoked = true; return Long.MAX_VALUE }
        }
        val fakeReply = object : ChatGptAuthDocumentReply() {
            override fun cachePolicy(operation: ChatGptStoreOperation): ChatGptAuthDocumentCachePolicy { invoked = true; return fakePolicy }
            override fun discovery(operation: ChatGptStoreOperation): ChatGptOidcDiscovery { invoked = true; error("forged") }
            override fun jwks(operation: ChatGptStoreOperation): ChatGptOidcJwks { invoked = true; error("forged") }
            override fun discard() { invoked = true }
        }
        assertFalse(isTransportCachePolicy(fakePolicy)); assertFalse(isTransportDocumentReply(fakeReply)); assertFalse(invoked)
    }
    @Test fun cacheHit599Expiry600AndWallClockJumpDoNotExtendTtl(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(AuthScript(key.jwks()))
        rig.metadata.keys(rig.clock.operation()).close()
        rig.clock.advance(599); rig.clock.now.set(Instant.EPOCH)
        rig.metadata.keys(rig.clock.operation()).close(); assertEquals(1, rig.port.submitted.get())
        rig.clock.advance(1); rig.port.scripts.add(AuthScript(key.jwks()))
        rig.metadata.keys(rig.clock.operation()).close(); assertEquals(2, rig.port.submitted.get())
    }
    @Test fun cacheOriginSurvivesSignedNanoTimeWrapAndRejectsBackwardTime() {
        AuthTestRig(AuthTestClock(Long.MAX_VALUE - 5_000_000_000L)).use { rig ->
            rig.port.scripts.add(AuthScript(key.jwks())); rig.metadata.keys(rig.clock.operation()).close()
            rig.clock.advance(6); rig.metadata.keys(rig.clock.operation()).close(); assertEquals(1, rig.port.submitted.get())
            rig.clock.advance(-7)
            authFailure { rig.metadata.keys(rig.clock.operation()).close() }
            assertEquals(1, rig.port.submitted.get())
            assertFalse(rig.clock.authority.valid())
            AuthTestRig().use { fresh ->
                fresh.port.scripts.add(AuthScript(key.jwks()))
                fresh.metadata.keys(fresh.clock.operation()).close()
                assertEquals(1, fresh.port.submitted.get())
            }
        }
    }
    @Test fun shortAgeAndAgeHeaderTightenActualTransportMetadataCache(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(rig.document(key.jwks(), listOf("max-age=4"), listOf("2")))
        rig.metadata.keys(rig.clock.operation()).close(); rig.clock.advance(1)
        rig.metadata.keys(rig.clock.operation()).close(); assertEquals(1, rig.port.submitted.get())
        rig.clock.advance(1); rig.port.scripts.add(AuthScript(key.jwks()))
        rig.metadata.keys(rig.clock.operation()).close(); assertEquals(2, rig.port.submitted.get())
    }
    @Test fun noStoreNoCacheDuplicateMalformedAndOverflowPoliciesAreEphemeral() {
        val policies = listOf("max-age=0", "no-store", "No-CaChE=\"field,other\"", "max-age=60,max-age=60",
            "max-age=30,max-age=60", "max-age=-1", "max-age=01",
            "max-age=10,", "max-age=\"10\"", "bad directive", "x=\"unterminated")
        for (policy in policies) AuthTestRig().use { rig ->
            repeat(2) { rig.port.scripts.add(rig.document(key.jwks(), listOf(policy))) }
            rig.metadata.keys(rig.clock.operation()).close(); rig.metadata.keys(rig.clock.operation()).close()
            assertEquals(2, rig.port.submitted.get(), "ephemeral policy")
        }
        for (ages in listOf(listOf("1", "2"), listOf("-1"), listOf("999999999999999999999"), listOf("garbage"))) AuthTestRig().use { rig ->
            repeat(2) { rig.port.scripts.add(rig.document(key.jwks(), ages = ages)) }
            rig.metadata.keys(rig.clock.operation()).close(); rig.metadata.keys(rig.clock.operation()).close()
            assertEquals(2, rig.port.submitted.get(), "ephemeral age")
        }
    }
    @Test fun multipleCacheHeadersAndUnknownDirectiveNeverExtendCeiling(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(rig.document(key.jwks(), listOf("public,extension=\"a,b\"", "MAX-AGE=1")))
        rig.metadata.keys(rig.clock.operation()).close(); rig.clock.advance(1)
        rig.port.scripts.add(AuthScript(key.jwks())); rig.metadata.keys(rig.clock.operation()).close()
        assertEquals(2, rig.port.submitted.get())
    }
    @Test fun ephemeralDiscoveryEndpointCannotEscapeOperationOrBeUsedTwice(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(rig.document(authDiscovery("https://auth.openai.com/revoke"), listOf("no-store")))
        val op = rig.clock.operation(); val endpoint = rig.metadata.discovery(op).revocation!!
        val logout = logout()
        authFailure { rig.transport.prepareRevocation(endpoint, logout, rig.clock.operation()) }
        rig.port.scripts.add(AuthScript(ByteArray(0), headers = emptyMap()))
        val call = rig.transport.prepareRevocation(endpoint, logout, op); call.start(authGate())
        assertTrue(call.await() is ChatGptAuthHttpOutcome.Revoked)
        authFailure { rig.transport.prepareRevocation(endpoint, logout, op) }
        rig.port.scripts.add(rig.document(authDiscovery(), listOf("no-store")))
        rig.metadata.discovery(rig.clock.operation())
        assertEquals(3, rig.port.submitted.get())
    }
    @Test fun endpointExpiryAndForgedEndpointFailBeforeRequestVirtualMethod(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(rig.document(authDiscovery("https://auth.openai.com/revoke"), listOf("max-age=1")))
        val op = rig.clock.operation(); val endpoint = rig.metadata.discovery(op).revocation!!
        rig.clock.advance(1)
        authFailure { rig.transport.prepareRevocation(endpoint, logout(), op) }
        var invoked = false
        val forged = object : ChatGptAuthRevocationEndpoint() {
            override fun newRevocationRequest(logout: ChatGptLocalLogout, operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline): HttpRequest { invoked = true; error("forged") }
        }
        authFailure { rig.transport.prepareRevocation(forged, logout(), op) }; assertFalse(invoked)
    }
    @Test fun retainedEphemeralKeysRejectOtherOperationAndClosedUse(): Unit = AuthTestRig().use { rig ->
        val bound = authBound(rig); val op = rig.clock.operation()
        rig.port.scripts.add(rig.document(key.jwks(), listOf("no-store")))
        val use = rig.metadata.keys(op); val document = use.document
        authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) {
            ChatGptPlanOidc.validateAuthorizationProof(key.response(bound.code, rig.clock.now.get()), document, authSnapshot(),
                bound.code, rig.clock.now.get(), rig.clock.now.get(), rig.clock.operation())
        }
        use.close()
        authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) {
            ChatGptPlanOidc.validateAuthorizationProof(key.response(bound.code, rig.clock.now.get()), document, authSnapshot(),
                bound.code, rig.clock.now.get(), rig.clock.now.get(), op)
        }
    }
    @Test fun firstUnknownKidRefetchesExactReplyOnceWithoutAnotherPost(): Unit = AuthTestRig().use { rig ->
        val bound = authBound(rig); val op = rig.clock.operation()
        val reply = authToken(rig, bound, key, op)
        rig.port.scripts.add(AuthScript(("{\"keys\":[${key.keyJson("old-key")}]}").toByteArray()))
        rig.port.scripts.add(AuthScript(key.jwks()))
        val proof = rig.metadata.validateAuthorization(reply, op)
        assertTrue(proof.registration.subject == "test-subject", "real signed identity")
        assertEquals(1, rig.port.requests.count { it.method() == "POST" })
        assertEquals(2, rig.port.requests.count { it.method() == "GET" })
    }
    @Test fun secondUnknownAndCooldownNeverCreateUnboundedRepairRequests(): Unit = AuthTestRig().use { rig ->
        val old = ("{\"keys\":[${key.keyJson("old-key")}]}").toByteArray()
        val bound = authBound(rig); val op = rig.clock.operation(); val reply = authToken(rig, bound, key, op)
        rig.port.scripts.add(AuthScript(old)); rig.port.scripts.add(AuthScript(old))
        assertEquals(ChatGptOidcFailure.Reason.UNKNOWN_KEY, assertFailsWith<ChatGptOidcFailure> { rig.metadata.validateAuthorization(reply, op) }.reason)
        val second = authBound(rig); val secondOp = rig.clock.operation(); val secondReply = authToken(rig, second, key, secondOp)
        assertEquals(ChatGptOidcFailure.Reason.UNKNOWN_KEY, assertFailsWith<ChatGptOidcFailure> { rig.metadata.validateAuthorization(secondReply, secondOp) }.reason)
        assertEquals(2, rig.port.requests.count { it.method() == "GET" })
    }
    @Test fun newerGenerationConsumesRepairWithoutExtraGetAndCannotRepairTwice(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(AuthScript(key.jwks()))
        val op = rig.clock.operation(); val a = rig.metadata.keys(op); val b = rig.metadata.keys(op)
        rig.port.scripts.add(AuthScript(key.jwks()))
        val repaired = b.refetchUnknown(op)
        val joined = a.refetchUnknown(op)
        assertTrue(repaired.refetched); assertTrue(joined.refetched)
        assertEquals(2, rig.port.submitted.get())
        assertEquals(ChatGptOidcFailure.Reason.UNKNOWN_KEY, assertFailsWith<ChatGptOidcFailure> { joined.refetchUnknown(op) }.reason)
        repaired.close(); joined.close()
    }
    @Test fun invalidSignatureClaimsAndExpiredSignedTokenNeverTriggerRepair() {
        for (mode in 0..2) AuthTestRig().use { rig ->
            val bound = authBound(rig); val op = rig.clock.operation(); val time = rig.clock.now.get()
            val bytes = key.response(bound.code, time, exp = if (mode == 2) time.epochSecond + 1 else time.epochSecond + 3600,
                subject = if (mode == 1) "wrong-subject" else "test-subject", badSignature = mode == 0)
            val reply = authToken(rig, bound, key, op, bytes)
            rig.port.scripts.add(AuthScript(key.jwks()))
            if (mode == 2) rig.clock.now.set(time.plusSeconds(7))
            assertFailsWith<ChatGptOidcFailure> { rig.metadata.validateAuthorization(reply, op) }
            assertEquals(1, rig.port.requests.count { it.method() == "GET" })
        }
    }
    @Test fun twoWaitersShareFetchAndFirstCancellationDoesNotCancelSecond(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val firstCancelled = AtomicBoolean()
        rig.port.scripts.add(AuthScript(key.jwks(), action = { e -> entered.countDown(); authAwait(release); e.deliver() }))
        val firstDone = CountDownLatch(1); val secondStarted = CountDownLatch(1); val secondGood = AtomicBoolean()
        val first = Thread {
            try { rig.metadata.keys(rig.clock.operation(firstCancelled::get)).close() } catch (_: Exception) { }
            finally { firstDone.countDown() }
        }
        val second = Thread {
            secondStarted.countDown()
            try { rig.metadata.keys(rig.clock.operation()).close(); secondGood.set(true) } catch (_: Exception) { }
        }
        first.start()
        try {
            authAwait(entered); second.start(); authAwait(secondStarted)
            // Wait for actual waiter admission using a test-only observer, not a timing assumption.
            awaitMetadataWaiters(rig.metadata, 2)
            firstCancelled.set(true); authAwait(firstDone)
            release.countDown(); authJoin(second)
            assertTrue(secondGood.get()); assertEquals(1, rig.port.submitted.get())
        } finally { release.countDown(); authJoin(first); if (second.state != Thread.State.NEW) authJoin(second) }
    }
    @Test fun lastWaiterCancellationFencesInstallAndLateJoinKeepsOriginalDeadline(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val cancelled = AtomicBoolean()
        rig.port.scripts.add(AuthScript(key.jwks(), action = { e -> entered.countDown(); authAwait(release); e.deliver() }))
        val finished = CountDownLatch(1)
        val waiter = Thread { try { rig.metadata.keys(rig.clock.operation(cancelled::get)).close() } catch (_: Exception) { } finally { finished.countDown() } }
        waiter.start()
        try {
            authAwait(entered); cancelled.set(true); authAwait(finished)
            release.countDown(); authJoin(waiter)
        } finally { release.countDown(); authJoin(waiter) }
        awaitMetadataIdle(rig.metadata)
        rig.port.scripts.add(AuthScript(key.jwks())); rig.metadata.keys(rig.clock.operation()).close()
        assertEquals(2, rig.port.submitted.get())
    }

    @Test fun ninthWaiterDeniedAndAllAdmittedWaitersJoined(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val successes = AtomicInteger()
        rig.port.scripts.add(AuthScript(key.jwks(), action = { e -> entered.countDown(); authAwait(release); e.deliver() }))
        val workers = List(8) { Thread { try { rig.metadata.keys(rig.clock.operation()).close(); successes.incrementAndGet() } catch (_: Exception) { } } }
        workers.forEach { it.start() }
        try {
            authAwait(entered); awaitMetadataWaiters(rig.metadata, 8)
            authFailure(ChatGptAuthHttpFailure.CAPACITY) { rig.metadata.keys(rig.clock.operation()) }
        } finally { release.countDown(); workers.forEach(::authJoin) }
        assertEquals(8, successes.get()); assertEquals(1, rig.port.submitted.get())
    }
    @Test fun concurrentActualTokenRepairsCoalesceAndKeepBothSnapshots(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(AuthScript(("{\"keys\":[${key.keyJson("old-key")}]}").toByteArray()))
        rig.metadata.keys(rig.clock.operation()).close()
        val snapshots = List(2) { authSnapshot() }; val bounds = snapshots.map { authBound(rig, it) }
        bounds.forEach { rig.port.scripts.add(AuthScript(key.response(it.code, rig.clock.now.get()))) }
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val ready = CountDownLatch(2); val successes = AtomicInteger()
        rig.port.scripts.add(AuthScript(key.jwks(), action = { e -> entered.countDown(); authAwait(release); e.deliver() }))
        val workers = bounds.mapIndexed { index, bound -> Thread {
            try {
                val op = rig.clock.operation()
                val call = rig.transport.prepareCode(bound.binding, bound.code, op); call.start(authGate())
                val reply = (call.await() as ChatGptAuthHttpOutcome.Token).reply
                ready.countDown(); authAwait(ready)
                val proof = rig.metadata.validateAuthorization(reply, op)
                if (proof.attemptId == snapshots[index].attemptId) successes.incrementAndGet()
            } catch (_: Exception) { ready.countDown() }
        } }
        workers.forEach { it.start() }
        try { authAwait(entered); awaitMetadataWaiters(rig.metadata, 2) }
        finally { release.countDown(); workers.forEach(::authJoin) }
        assertEquals(2, successes.get()); assertEquals(2, rig.port.requests.count { it.method() == "POST" })
        assertEquals(2, rig.port.requests.count { it.method() == "GET" })
    }
    @Test fun lateWaiterCannotExtendFirstFetchDeadlineAndFailureHasNoTransparentRetry(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val successes = AtomicInteger()
        rig.port.scripts.add(AuthScript(key.jwks(), action = { e -> entered.countDown(); authAwait(release); e.deliver() }))
        val first = Thread { try { rig.metadata.keys(rig.clock.operation(seconds = 1)).close(); successes.incrementAndGet() } catch (_: Exception) { } }
        val second = Thread { try { rig.metadata.keys(rig.clock.operation()).close(); successes.incrementAndGet() } catch (_: Exception) { } }
        first.start()
        try {
            authAwait(entered); second.start(); awaitMetadataWaiters(rig.metadata, 2)
            rig.clock.advance(1)
        } finally { release.countDown(); authJoin(first); if (second.state != Thread.State.NEW) authJoin(second) }
        assertEquals(0, successes.get()); assertEquals(1, rig.port.submitted.get())
    }
    @Test fun generationExhaustionFailsClosedWithoutAGet(): Unit = AuthTestRig().use { rig ->
        // Test-only boundary injection, never used to construct or authenticate a capability.
        rig.metadata.javaClass.getDeclaredField("generation").apply { isAccessible = true }.setLong(rig.metadata, Long.MAX_VALUE)
        authFailure(ChatGptAuthHttpFailure.CAPACITY) { rig.metadata.keys(rig.clock.operation()) }
        assertEquals(0, rig.port.submitted.get())
    }
    @Test fun hugeCanonicalMaxAgeSaturatesBeforeArithmeticAndRemainsTenMinuteBound(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(rig.document(key.jwks(), listOf("max-age=999999999999999999999999999999")))
        rig.metadata.keys(rig.clock.operation()).close(); rig.clock.advance(599)
        rig.metadata.keys(rig.clock.operation()).close(); assertEquals(1, rig.port.submitted.get())
        rig.clock.advance(1); rig.port.scripts.add(AuthScript(key.jwks())); rig.metadata.keys(rig.clock.operation()).close()
        assertEquals(2, rig.port.submitted.get())
    }
    @Test fun shutdownRevokesAlreadyReturnedKeyAuthority(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(AuthScript(key.jwks())); val op = rig.clock.operation(); val use = rig.metadata.keys(op)
        assertEquals(ChatGptAuthSettlement.SETTLED, rig.metadata.shutdown(250_000_000))
        authFailure { use.document }
        use.close()
    }

    @Test fun signedExpiryIsRecheckedWithFreshClockAfterSignatureWork(): Unit = AuthTestRig().use { rig ->
        val time = rig.clock.now.get(); val bound = authBound(rig); val op = rig.clock.operation()
        val reply = authToken(rig, bound, key, op, key.response(bound.code, time, exp = time.epochSecond + 10))
        val samples = AtomicInteger()
        val metadata = newChatGptAuthMetadata(rig.transport, rig.clock.authority, rig.clock.nanos::get) {
            if (samples.incrementAndGet() == 1) time else time.plusSeconds(15)
        }
        try {
            rig.port.scripts.add(AuthScript(key.jwks()))
            assertEquals(ChatGptOidcFailure.Reason.INVALID_CLAIMS,
                assertFailsWith<ChatGptOidcFailure> { metadata.validateAuthorization(reply, op) }.reason)
            assertEquals(2, samples.get())
        } finally { assertEquals(ChatGptAuthSettlement.SETTLED, metadata.shutdown(250_000_000)) }
    }
    @Test fun failedForcedFetchStillConsumesCooldownAndNoStaleFallbackIsReturned(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(AuthScript(key.jwks()))
        val op = rig.clock.operation(); val use = rig.metadata.keys(op)
        rig.port.scripts.add(AuthScript("{}".toByteArray(), 503))
        authFailure { use.refetchUnknown(op) }
        val second = rig.metadata.keys(op)
        assertEquals(ChatGptOidcFailure.Reason.UNKNOWN_KEY,
            assertFailsWith<ChatGptOidcFailure> { second.refetchUnknown(op) }.reason)
        second.close(); assertEquals(2, rig.port.submitted.get())
        rig.clock.advance(30)
        val thirdOp = rig.clock.operation(); val third = rig.metadata.keys(thirdOp)
        rig.port.scripts.add(AuthScript(key.jwks())); third.refetchUnknown(thirdOp).close()
        assertEquals(3, rig.port.submitted.get())
    }

    @Test fun discardingReplyDuringActualProofValidationDoesNotWaitForValidatorOrPublish(): Unit = AuthTestRig().use { rig ->
        val bound = authBound(rig); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val armed = AtomicBoolean(); val checks = AtomicInteger(); val success = AtomicBoolean()
        val replyRef = AtomicReference<ChatGptAuthTokenReply>()
        val keys = ChatGptPlanOidc.validateJwksDocument(key.jwks(), rig.clock.operation())
        val worker = Thread {
            val op = rig.clock.operation(cancelled = {
                if (armed.get() && checks.incrementAndGet() == 3) { entered.countDown(); authAwait(release) }
                false
            })
            try {
                val reply = authToken(rig, bound, key, op); replyRef.set(reply); armed.set(true)
                reply.validateAuthorization(keys, rig.clock.now.get(), op, false); success.set(true)
            } catch (_: Exception) { }
        }
        worker.start()
        try {
            authAwait(entered)
            val start = System.nanoTime(); replyRef.get().discard()
            assertTrue(System.nanoTime() - start < 250_000_000, "discard does not wait for signature work")
        } finally { release.countDown(); authJoin(worker) }
        assertFalse(success.get())
    }

    @Test fun invalidFetchCannotBeCachedOrFallBackToExpiredGeneration(): Unit = AuthTestRig().use { rig ->
        rig.port.scripts.add(rig.document(key.jwks(), listOf("max-age=1")))
        rig.metadata.keys(rig.clock.operation()).close(); rig.clock.advance(1)
        rig.port.scripts.add(AuthScript("{\"keys\":[]}".toByteArray()))
        authFailure { rig.metadata.keys(rig.clock.operation()) }
        rig.port.scripts.add(AuthScript(key.jwks())); rig.metadata.keys(rig.clock.operation()).close()
        assertEquals(3, rig.port.submitted.get())
    }
    @Test fun revocationRequiresExactlyEmpty200ForItsActualPurpose() {
        for ((status, bytes) in listOf(200 to "{}".toByteArray(), 204 to ByteArray(0), 302 to ByteArray(0))) AuthTestRig().use { rig ->
            rig.port.scripts.add(AuthScript(authDiscovery("https://auth.openai.com/revoke")))
            val op = rig.clock.operation(); val endpoint = rig.metadata.discovery(op).revocation!!
            rig.port.scripts.add(AuthScript(bytes, status))
            val call = rig.transport.prepareRevocation(endpoint, logout(), op); call.start(authGate())
            assertFalse(call.await() is ChatGptAuthHttpOutcome.Revoked)
            assertEquals(1, rig.port.requests.count { it.method() == "POST" })
        }
    }

    @Test fun exactRetainedReplyCannotResetUnknownKidAllowanceWithFreshKeyHandles(): Unit = AuthTestRig().use { rig ->
        val bound = authBound(rig); val op = rig.clock.operation(); val reply = authToken(rig, bound, key, op)
        val unknown = ("{\"keys\":[${key.keyJson("old-key")}]}").toByteArray()
        val first = ChatGptPlanOidc.validateJwksDocument(unknown, op)
        val second = ChatGptPlanOidc.validateJwksDocument(unknown, op)
        assertEquals(ChatGptOidcFailure.Reason.UNKNOWN_KEY_REFETCH_ONCE,
            assertFailsWith<ChatGptOidcFailure> { reply.validateAuthorization(first, rig.clock.now.get(), op, false) }.reason)
        authFailure(ChatGptAuthHttpFailure.ALREADY_USED) { reply.validateAuthorization(second, rig.clock.now.get(), op, false) }
        assertEquals(1, rig.port.submitted.get())
    }
    private fun logout(): ChatGptLocalLogout = ChatGptLocalLogout(
        ChatGptPlanAccount("test-account", ChatGptPlanOidc.ISSUER, "oaiapp_test", "test-label", null, null, 0, 0, ChatGptPlanAccount.State.SIGNED_OUT, emptySet(), null), "oaiapp_test", "synthetic-refresh", false)
    // Promoted verbatim from independent review v2; historical red evidence remains intact.
    @Test fun shutdownDoesNotAcknowledgeBlockedValidation(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val succeeded = AtomicBoolean()
        val bound = authBound(rig); val key = AuthSigningKey()
        val metadata = newChatGptAuthMetadata(rig.transport, rig.clock.authority, rig.clock.nanos::get) {
            entered.countDown(); authAwait(release); rig.clock.now.get()
        }
        val worker = Thread {
            try {
                val op = rig.clock.operation(); val reply = authToken(rig, bound, key, op)
                rig.port.scripts.add(AuthScript(key.jwks()))
                metadata.validateAuthorization(reply, op); succeeded.set(true)
            } catch (_: Exception) { }
        }
        var settlement: ChatGptAuthSettlement? = null
        worker.start()
        try {
            authAwait(entered)
            settlement = metadata.shutdown(50_000_000)
            println("shutdown_validation settlement=" + settlement + " workerAlive=" + worker.isAlive)
        } finally {
            release.countDown(); authJoin(worker)
            metadata.shutdown(250_000_000)
        }
        assertFalse(succeeded.get(), "shutdown fences validation result")
        assertEquals(ChatGptAuthSettlement.UNSETTLED, settlement, "active validation lacks physical acknowledgement")
    }
    @Test fun ephemeralKeyScopeCannotAuthorizeTwoDistinctReplies(): Unit = AuthTestRig().use { rig ->
        val key = AuthSigningKey(); val op = rig.clock.operation()
        val first = authBound(rig); val second = authBound(rig)
        val replyA = authToken(rig, first, key, op); val replyB = authToken(rig, second, key, op)
        rig.port.scripts.add(rig.document(key.jwks(), listOf("no-store")))
        val use = rig.metadata.keys(op)
        try {
            val document = use.document
            replyA.validateAuthorization(document, rig.clock.now.get(), op, false)
            var denied = false
            try { replyB.validateAuthorization(document, rig.clock.now.get(), op, false) } catch (_: Exception) { denied = true }
            println("ephemeral_keys secondValidationDenied=" + denied + " submissions=" + rig.port.submitted.get())
            assertTrue(denied, "ephemeral keys remain one validation scoped")
        } finally { use.close(); replyA.discard(); replyB.discard() }
    }
    @Test fun retainedEphemeralKeyRejectsFixedFetchDeadline(): Unit = AuthTestRig().use { rig ->
        val key = AuthSigningKey(); val op = rig.clock.operation(); val bound = authBound(rig)
        val reply = authToken(rig, bound, key, op)
        rig.port.scripts.add(rig.document(key.jwks(), listOf("no-cache")))
        val use = rig.metadata.keys(op); val document = use.document
        try {
            rig.clock.advance(10)
            authFailure(ChatGptAuthHttpFailure.DEADLINE) {
                reply.validateAuthorization(document, rig.clock.now.get(), op, false)
            }
        } finally { use.close(); reply.discard() }
    }
    @Test fun forgedReplyHasNoVirtualCallsOrFetch(): Unit = AuthTestRig().use { rig ->
        val virtual = AtomicInteger()
        val reply = object : ChatGptAuthTokenReply() {
            override val receivedAt get() = rig.clock.now.get().also { virtual.incrementAndGet() }
            override val purpose get() = ChatGptAuthHttpPurpose.CODE.also { virtual.incrementAndGet() }
            override fun validateAuthorization(keys: ChatGptOidcJwks, validatedAt: java.time.Instant,
                operation: ChatGptStoreOperation, jwksAlreadyRefetched: Boolean): ChatGptAuthorizationProof {
                virtual.incrementAndGet(); error("forged callback")
            }
            override fun discard() { virtual.incrementAndGet() }
        }
        authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) { rig.metadata.validateAuthorization(reply, rig.clock.operation()) }
        assertEquals(0, virtual.get()); assertEquals(0, rig.port.acquired.get())
    }
    @Test fun ephemeralRepairKeepsOriginalReplyReservation() {
        for (policy in listOf("no-store", "no-cache")) AuthTestRig().use { rig ->
            val op = rig.clock.operation(); val first = authBound(rig); val second = authBound(rig)
            val replyA = authToken(rig, first, key, op)
            val replyB = authToken(rig, second, key, op,
                key.response(second.code, rig.clock.now.get(), badSignature = true))
            val old = ("{\"keys\":[${key.keyJson("old-key")}]}").toByteArray()
            rig.port.scripts.add(rig.document(old, listOf(policy)))
            val use = rig.metadata.keys(op)
            var repaired: ChatGptAuthKeysUse? = null
            try {
                assertEquals(ChatGptOidcFailure.Reason.UNKNOWN_KEY_REFETCH_ONCE,
                    assertFailsWith<ChatGptOidcFailure> { replyA.validateAuthorization(use.document, rig.clock.now.get(), op, false) }.reason)
                rig.port.scripts.add(rig.document(key.jwks(), listOf(policy)))
                val next = use.refetchUnknown(op); repaired = next
                assertTrue(next.refetched)
                // INVALID_BINDING, rather than INVALID_SIGNATURE: foreign denial precedes verifier work.
                authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) {
                    replyB.validateAuthorization(next.document, rig.clock.now.get(), op, false)
                }
                val proof = replyA.validateAuthorization(next.document, rig.clock.now.get(), op, true)
                assertTrue(proof.registration.subject == "test-subject", "actual repaired signature proof")
                assertEquals(2, rig.port.requests.count { it.method() == "GET" })
                assertEquals(2, rig.port.requests.count { it.method() == "POST" })
                authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) {
                    replyA.validateAuthorization(next.document, rig.clock.now.get(), op, true)
                }
            } finally { repaired?.close(); use.close(); replyA.discard(); replyB.discard() }
        }
    }
    @Test fun ephemeralReservationSurvivesInvalidSignature() {
        for (policy in listOf("no-store", "no-cache")) AuthTestRig().use { rig ->
            val op = rig.clock.operation(); val first = authBound(rig); val second = authBound(rig)
            val replyA = authToken(rig, first, key, op, key.response(first.code, rig.clock.now.get(), badSignature = true))
            val replyB = authToken(rig, second, key, op, key.response(second.code, rig.clock.now.get(), badSignature = true))
            rig.port.scripts.add(rig.document(key.jwks(), listOf(policy))); val use = rig.metadata.keys(op)
            try {
                assertEquals(ChatGptOidcFailure.Reason.INVALID_SIGNATURE,
                    assertFailsWith<ChatGptOidcFailure> { replyA.validateAuthorization(use.document, rig.clock.now.get(), op, false) }.reason)
                authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) {
                    replyB.validateAuthorization(use.document, rig.clock.now.get(), op, false)
                }
                assertEquals(3, rig.port.submitted.get())
            } finally { use.close(); replyA.discard(); replyB.discard() }
        }
    }
    @Test fun shutdownAtFinalProofCheckFencesPublicationAndAcknowledgesRelease() = blockedValidationShutdown(finalCheck = true, releaseWithinBudget = false)
    @Test fun shutdownWaitsForValidationFinallyWithoutOwnerCallbacks() = blockedValidationShutdown(finalCheck = false, releaseWithinBudget = true)
    private fun blockedValidationShutdown(finalCheck: Boolean, releaseWithinBudget: Boolean): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val succeeded = AtomicBoolean(); val wrongThread = AtomicBoolean(); val samples = AtomicInteger()
        val bound = authBound(rig)
        val metadata = newChatGptAuthMetadata(rig.transport, rig.clock.authority, rig.clock.nanos::get) {
            if (samples.incrementAndGet() == (if (finalCheck) 2 else 1)) { entered.countDown(); authAwait(release) }
            rig.clock.now.get()
        }
        val worker = Thread({
            val owner = Thread.currentThread()
            val op = rig.clock.operation(cancelled = { if (Thread.currentThread() !== owner) wrongThread.set(true); false })
            try {
                val reply = authToken(rig, bound, key, op); rig.port.scripts.add(AuthScript(key.jwks()))
                metadata.validateAuthorization(reply, op); succeeded.set(true)
            } catch (_: Exception) { }
        }, "chatgpt-auth-fixture-validation")
        val outcome = AtomicReference<ChatGptAuthSettlement>()
        val shutdown = Thread({ outcome.set(metadata.shutdown(if (releaseWithinBudget) 250_000_000 else 50_000_000)) },
            "chatgpt-auth-fixture-shutdown")
        worker.start()
        try {
            authAwait(entered); assertEquals(1, authMetadataValidations(metadata))
            shutdown.start(); authEventually { authMetadataClosed(metadata) }
            if (releaseWithinBudget) { assertNull(outcome.get()); release.countDown() }
            authJoin(shutdown)
            assertEquals(if (releaseWithinBudget) ChatGptAuthSettlement.SETTLED else ChatGptAuthSettlement.UNSETTLED, outcome.get())
            if (!releaseWithinBudget) {
                assertTrue(worker.isAlive)
                assertEquals(ChatGptAuthSettlement.UNSETTLED, metadata.shutdown(0))
            }
            val extra = authToken(rig, authBound(rig), key, rig.clock.operation())
            try { authFailure(ChatGptAuthHttpFailure.CANCELLED) { metadata.validateAuthorization(extra, rig.clock.operation()) } }
            finally { extra.discard() }
        } finally {
            release.countDown(); authJoin(worker)
            if (shutdown.state != Thread.State.NEW) authJoin(shutdown)
            assertEquals(ChatGptAuthSettlement.SETTLED, metadata.shutdown(250_000_000))
        }
        assertFalse(succeeded.get()); assertFalse(wrongThread.get())
        assertEquals(0, authMetadataValidations(metadata))
        assertEquals(1, rig.port.requests.count { it.method() == "GET" })
    }

    @Test fun repeatedShutdownCannotRenewOriginalValidationAllowance(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val succeeded = AtomicBoolean()
        val bound = authBound(rig)
        val metadata = newChatGptAuthMetadata(rig.transport, rig.clock.authority, rig.clock.nanos::get) {
            entered.countDown(); authAwait(release); rig.clock.now.get()
        }
        val worker = Thread({
            try {
                val op = rig.clock.operation(); val reply = authToken(rig, bound, key, op)
                rig.port.scripts.add(AuthScript(key.jwks()))
                metadata.validateAuthorization(reply, op); succeeded.set(true)
            } catch (_: Exception) { }
        }, "chatgpt-auth-fixture-shutdown-budget")
        worker.start()
        try {
            authAwait(entered)
            assertEquals(ChatGptAuthSettlement.UNSETTLED, metadata.shutdown(0))
            val start = System.nanoTime()
            assertEquals(ChatGptAuthSettlement.UNSETTLED, metadata.shutdown(250_000_000))
            assertTrue(System.nanoTime() - start < 150_000_000, "first zero allowance cannot become a fresh wait")
            assertTrue(worker.isAlive); assertEquals(1, authMetadataValidations(metadata))
        } finally {
            release.countDown(); authJoin(worker)
            authEventually { metadata.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        }
        assertFalse(succeeded.get()); assertEquals(0, authMetadataValidations(metadata))
    }

    @Test fun authorizationCancellationCannotHoldBindingMonitor() = bindingHelperRace("authorization", 1)
    @Test fun authorizationOAuthClockCannotHoldBindingMonitor() = bindingHelperRace("clock", 0)
    @Test fun trustedReceiverCannotPreventBindingDiscard() = bindingHelperRace("receiver", 0)
    @Test fun receiverPostcheckCannotRetainCodeAfterDiscard() = bindingHelperRace("receive", 3)
    @Test fun claimOAuthHelperCannotPreventBindingDiscard() = bindingHelperRace("claim", 2)
    @Test fun claimPostcheckCannotReturnRequestAfterDiscard() = bindingHelperRace("claim", 3)

    private fun bindingHelperRace(phase: String, stopAt: Int): Unit = AuthTestRig().use { rig ->
        val armed = AtomicBoolean(); val checks = AtomicInteger(); val held = AtomicBoolean()
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val done = CountDownLatch(1)
        val succeeded = AtomicBoolean(); val ref = AtomicReference<ChatGptAuthCodeBinding>()
        fun block() { held.set(Thread.holdsLock(ref.get())); entered.countDown(); authAwait(release) }
        val seed = AtomicInteger()
        val binding = rig.metadata.bindAuthorization(authSnapshot(), ChatGptPlanOAuthRedirect.of(42321),
            ChatGptPlanOAuthClock {
                if (armed.get() && phase == "clock") block()
                rig.clock.nanos.get()
            }, ChatGptPlanOAuthRandom { it.fill(seed.incrementAndGet().toByte()) },
            ChatGptPlanOAuthCancellation {
                if (armed.get() && checks.incrementAndGet() == stopAt) block()
                false
            }, rig.clock.operation())
        ref.set(binding)
        val fields = java.net.URI(binding.authorizationRequest().uri).rawQuery.split('&').associate {
            val pair = it.split('=', limit = 2); pair[0] to java.net.URLDecoder.decode(pair[1], Charsets.UTF_8)
        }
        val receiver = object : ChatGptAuthCodeReceiver() {
            override fun await(attempt: ChatGptPlanOAuthAttempt): ChatGptPlanOAuthAttempt.CallbackResult {
                if (armed.get() && phase == "receiver") block()
                return attempt.consumeCallback("GET", "127.0.0.1:42321",
                    "/auth/callback?state=${fields.getValue("state")}&code=synthetic-code&client_id=oaiapp_test")
            }
        }
        val code = if (phase == "claim") binding.receiveCode(receiver) as ChatGptPlanOAuthAttempt.CallbackResult.Code else null
        armed.set(true)
        val owner = Thread({
            try {
                when (phase) {
                    "authorization", "clock" -> binding.authorizationRequest()
                    "claim" -> rig.clock.operation().let { binding.claimCode(code!!, it, it.deadline.cap(10_000_000_000L)) }
                    else -> binding.receiveCode(receiver)
                }
                succeeded.set(true)
            } catch (_: Exception) { }
        }, "chatgpt-auth-fixture-binding-helper")
        val discarder = Thread({ try { discardMetadataCodeBinding(binding) } finally { done.countDown() } },
            "chatgpt-auth-fixture-binding-discard")
        owner.start()
        try {
            authAwait(entered); discarder.start()
            assertTrue(done.await(350, TimeUnit.MILLISECONDS), "discard cannot wait on helper callback")
            assertFalse(held.get(), "helper must not own binding monitor")
        } finally {
            release.countDown(); authJoin(owner)
            if (discarder.state != Thread.State.NEW) authJoin(discarder)
        }
        assertFalse(succeeded.get(), "helper return cannot restore revoked binding")
        val previousChecks = checks.get()
        authFailure(ChatGptAuthHttpFailure.CANCELLED) { binding.authorizationRequest() }
        assertEquals(previousChecks, checks.get(), "closed binding rejects before callbacks")
    }

    @Test fun authorizationCallbackReentryCannotRestoreDiscardedBinding(): Unit = AuthTestRig().use { rig ->
        val ref = AtomicReference<ChatGptAuthCodeBinding>(); val armed = AtomicBoolean()
        val binding = rig.metadata.bindAuthorization(authSnapshot(), ChatGptPlanOAuthRedirect.of(42321),
            ChatGptPlanOAuthClock(rig.clock.nanos::get), ChatGptPlanOAuthRandom { it.fill(5) },
            ChatGptPlanOAuthCancellation {
                if (armed.compareAndSet(true, false)) {
                    assertFalse(Thread.holdsLock(ref.get())); discardMetadataCodeBinding(ref.get())
                }
                false
            }, rig.clock.operation())
        ref.set(binding); armed.set(true)
        authFailure(ChatGptAuthHttpFailure.CANCELLED) { binding.authorizationRequest() }
        authFailure(ChatGptAuthHttpFailure.CANCELLED) { binding.authorizationRequest() }
    }

    @Test fun throwingAuthorizationCallbackClosesBindingWithoutLeakingCause(): Unit = AuthTestRig().use { rig ->
        val armed = AtomicBoolean()
        val binding = rig.metadata.bindAuthorization(authSnapshot(), ChatGptPlanOAuthRedirect.of(42321),
            ChatGptPlanOAuthClock(rig.clock.nanos::get), ChatGptPlanOAuthRandom { it.fill(5) },
            ChatGptPlanOAuthCancellation { if (armed.get()) error("synthetic cancellation failure"); false }, rig.clock.operation())
        armed.set(true)
        authFailure(ChatGptAuthHttpFailure.DEPENDENCY_FAILED) { binding.authorizationRequest() }
        armed.set(false)
        authFailure(ChatGptAuthHttpFailure.CANCELLED) { binding.authorizationRequest() }
    }

    @Test fun throwingReceiverClosesBindingWithoutLeakingCause(): Unit = AuthTestRig().use { rig ->
        val binding = rig.metadata.bindAuthorization(authSnapshot(), ChatGptPlanOAuthRedirect.of(42321),
            ChatGptPlanOAuthClock(rig.clock.nanos::get), ChatGptPlanOAuthRandom { it.fill(5) },
            ChatGptPlanOAuthCancellation { false }, rig.clock.operation())
        authFailure(ChatGptAuthHttpFailure.DEPENDENCY_FAILED) {
            binding.receiveCode(object : ChatGptAuthCodeReceiver() {
                override fun await(attempt: ChatGptPlanOAuthAttempt): ChatGptPlanOAuthAttempt.CallbackResult = error("synthetic receiver failure")
            })
        }
        authFailure(ChatGptAuthHttpFailure.CANCELLED) { binding.authorizationRequest() }
    }

    @Test fun finalBindingOperationReentryCannotReturnProof(): Unit = AuthTestRig().use { rig ->
        val bound = authBound(rig); val armed = AtomicBoolean(); val ran = AtomicBoolean()
        val op = rig.clock.operation(cancelled = {
            val stack = Thread.currentThread().stackTrace
            if (armed.get() && stack.any { it.className == "decompengine.chatgpt.CodeBinding" && it.methodName.startsWith("prove") } &&
                stack.none { it.className.startsWith("decompengine.chatgpt.ChatGptPlanOidc") }) {
                armed.set(false); ran.set(true)
                assertFalse(Thread.holdsLock(bound.binding)); discardMetadataCodeBinding(bound.binding)
            }
            false
        })
        val reply = authToken(rig, bound, key, op)
        val document = ChatGptPlanOidc.validateJwksDocument(key.jwks(), op)
        armed.set(true)
        try {
            authFailure(ChatGptAuthHttpFailure.CANCELLED) {
                bound.binding.prove(key.response(bound.code, rig.clock.now.get()), document,
                    rig.clock.now.get(), rig.clock.now.get(), op, false)
            }
            assertTrue(ran.get(), "actual post-signature operation check ran")
        } finally { reply.discard() }
    }

    @Test fun bindingFinalCancellationStillChargesOperationBudget(): Unit = AuthTestRig().use { rig ->
        val armed = AtomicBoolean(); val checks = AtomicInteger()
        val bound = authBound(rig, cancelled = {
            if (armed.get() && checks.incrementAndGet() == 2) rig.clock.advance(31)
            false
        })
        val op = rig.clock.operation(); val reply = authToken(rig, bound, key, op)
        val document = ChatGptPlanOidc.validateJwksDocument(key.jwks(), op)
        armed.set(true)
        try {
            assertFailsWith<TimeoutException> {
                bound.binding.prove(key.response(bound.code, rig.clock.now.get()), document,
                    rig.clock.now.get(), rig.clock.now.get(), op, false)
            }
            assertEquals(2, checks.get())
        } finally { reply.discard() }
    }

    // Review MonitorControls regression (cache barrier corrected to work after monitor repair).
    @Test fun metadataShutdownDoesNotWaitOnCachedRecordClockMonitor(): Unit = AuthTestRig().use { rig ->
        val armed = AtomicBoolean(); val held = AtomicBoolean()
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val started = CountDownLatch(1); val done = CountDownLatch(1)
        val lockRef = AtomicReference<Any>(); val blocked = AtomicBoolean(); val samples = AtomicInteger()
        val metadata = newChatGptAuthMetadata(rig.transport, rig.clock.authority, {
            if (armed.get() && Thread.currentThread().name == "chatgpt-auth-fixture-cache-clock" &&
                samples.incrementAndGet() == 2 && armed.compareAndSet(true, false)) {
                held.set(Thread.holdsLock(lockRef.get())); entered.countDown(); authAwait(release)
            }
            rig.clock.nanos.get()
        }, rig.clock.now::get)
        lockRef.set(metadata.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(metadata))
        rig.port.scripts.add(AuthScript(AuthSigningKey().jwks()))
        metadata.keys(rig.clock.operation()).close(); armed.set(true)
        val reader = Thread({ try { metadata.keys(rig.clock.operation()).close() } catch (_: Exception) { } },
            "chatgpt-auth-fixture-cache-clock")
        val closer = Thread({ started.countDown(); try { metadata.shutdown(1) } finally { done.countDown() } },
            "chatgpt-auth-fixture-cache-shutdown")
        var finished = false
        reader.start()
        try {
            authAwait(entered); closer.start(); authAwait(started)
            finished = done.await(350, TimeUnit.MILLISECONDS)
            blocked.set(closer.state == Thread.State.BLOCKED && closer.stackTrace.any {
                it.className == "decompengine.chatgpt.AuthMetadata" && it.methodName == "shutdown"
            })
            println("metadata_clock finishedWithin350ms=$finished blockedInShutdown=${blocked.get()} callbackHeldMonitor=${held.get()}")
        } finally {
            release.countDown(); authJoin(reader)
            if (closer.state != Thread.State.NEW) authJoin(closer)
            authEventually { metadata.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        }
        assertTrue(finished, "metadata shutdown cannot wait outside its allowance on cached-record clock")
        assertFalse(held.get(), "cache clock callback must run outside metadata lifetime monitor")
    }
    @Test fun blockedMetadataAdmissionClockRetainsCaller() = metadataClockStage("admission", "block")
    @Test fun reentrantMetadataAdmissionClockCannotCreateFetch() = metadataClockStage("admission", "reenter")
    @Test fun throwingMetadataAdmissionClockAcknowledgesCaller() = metadataClockStage("admission", "throw")
    @Test fun blockedCacheHitClockRetainsCallerUntilAcknowledgement() = metadataClockStage("cache", "block")
    @Test fun reentrantCacheHitClockCannotReturnKeys() = metadataClockStage("cache", "reenter")
    @Test fun throwingCacheHitClockAcknowledgesCaller() = metadataClockStage("cache", "throw")
    @Test fun blockedFetchPublicationClockCannotHoldServiceLock() = metadataClockStage("parsed", "block")
    @Test fun reentrantFetchPublicationClockCannotInstallCache() = metadataClockStage("parsed", "reenter")
    @Test fun throwingFetchPublicationClockCompletesGeneration() = metadataClockStage("parsed", "throw")
    @Test fun blockedCacheInstallClockRetainsWorkerUntilAcknowledgement() = metadataClockStage("install", "block")
    @Test fun reentrantCacheInstallClockCannotInstallCache() = metadataClockStage("install", "reenter")
    @Test fun throwingCacheInstallClockCompletesGeneration() = metadataClockStage("install", "throw")
    @Test fun cacheInstallClockCannotRenewOriginalFetchDeadline() = metadataClockStage("install", "expire")

    private fun metadataClockStage(stage: String, action: String): Unit = AuthTestRig().use { rig ->
        val metadataRef = AtomicReference<ChatGptAuthMetadata>(); val armed = AtomicBoolean()
        val samples = AtomicInteger(); val fired = AtomicBoolean(); val held = AtomicBoolean(); val published = AtomicBoolean()
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val done = CountDownLatch(1)
        val failure = AtomicReference<Throwable>(); val settlement = AtomicReference<ChatGptAuthSettlement>()
        val metadata = newChatGptAuthMetadata(rig.transport, rig.clock.authority, {
            val stack = Thread.currentThread().stackTrace
            val worker = Thread.currentThread().name == "chatgpt-auth-metadata-jwks"
            val directWorkerClock = worker && stack.none { it.className == "decompengine.chatgpt.ChatGptStoreOperation" }
            val selected = if (stage in listOf("parsed", "install")) directWorkerClock else
                Thread.currentThread().name == "chatgpt-auth-metadata-clock-reader"
            val ordinal = when (stage) { "admission" -> 1; "cache", "parsed" -> 2; else -> 3 }
            if (armed.get() && selected && samples.incrementAndGet() == ordinal && armed.compareAndSet(true, false)) {
                fired.set(true)
                val own = metadataRef.get()
                val lock = own.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(own)
                held.set(Thread.holdsLock(lock))
                when (action) {
                    "block" -> { entered.countDown(); awaitClockRelease(release) }
                    "reenter" -> settlement.set(own.shutdown(0))
                    "throw" -> error("synthetic metadata clock failure")
                    "expire" -> rig.clock.advance(11)
                }
            }
            rig.clock.nanos.get()
        }, rig.clock.now::get)
        metadataRef.set(metadata); rig.port.scripts.add(AuthScript(key.jwks()))
        if (stage == "cache") metadata.keys(rig.clock.operation()).close()
        val reader = Thread({
            try { metadata.keys(rig.clock.operation()).close(); published.set(true) }
            catch (_: Exception) { }
            catch (e: Throwable) { failure.set(e) }
        }, "chatgpt-auth-metadata-clock-reader")
        val closer = Thread({ try { settlement.set(metadata.shutdown(1)) } finally { done.countDown() } },
            "chatgpt-auth-metadata-clock-closer")
        armed.set(true); reader.start()
        try {
            if (action == "block") {
                authAwait(entered); closer.start()
                assertTrue(done.await(350, TimeUnit.MILLISECONDS), "metadata shutdown fences before callback returns")
                assertEquals(ChatGptAuthSettlement.UNSETTLED, settlement.get())
                assertTrue(authMetadataClosed(metadata))
                assertEquals(ChatGptAuthSettlement.UNSETTLED, metadata.shutdown(250_000_000))
            }
        } finally {
            release.countDown(); authJoin(reader)
            if (closer.state != Thread.State.NEW) authJoin(closer)
            authEventually { metadata.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        }
        assertTrue(fired.get(), "target callback reached"); assertFalse(held.get()); assertFalse(published.get()); assertNull(failure.get())
        if (action == "reenter") assertEquals(ChatGptAuthSettlement.UNSETTLED, settlement.get())
        val lock = metadata.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(metadata)
        synchronized(lock) {
            val slot = metadata.javaClass.getDeclaredField("keysSlot").apply { isAccessible = true }.get(metadata)
            assertNull(slot.javaClass.getDeclaredField("record").apply { isAccessible = true }.get(slot))
            assertTrue((metadata.javaClass.getDeclaredField("users").apply { isAccessible = true }.get(metadata) as Map<*, *>).isEmpty())
        }
    }
    private fun awaitClockRelease(release: CountDownLatch) {
        val start = System.nanoTime(); var interrupted = false
        try {
            while (true) {
                val remaining = 3_000_000_000L - (System.nanoTime() - start)
                assertTrue(remaining > 0, "bounded clock fixture")
                try { assertTrue(release.await(remaining, TimeUnit.NANOSECONDS)); return }
                catch (_: InterruptedException) { interrupted = true }
            }
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }

    @Test fun leaseClockReentryCannotReturnClosedKeys(): Unit = AuthTestRig().use { rig ->
        val armed = AtomicBoolean(); val use = AtomicReference<ChatGptAuthKeysUse>()
        val metadata = newChatGptAuthMetadata(rig.transport, rig.clock.authority, {
            if (armed.compareAndSet(true, false)) use.get().close()
            rig.clock.nanos.get()
        }, rig.clock.now::get)
        try {
            rig.port.scripts.add(AuthScript(key.jwks())); use.set(metadata.keys(rig.clock.operation()))
            armed.set(true)
            authFailure(ChatGptAuthHttpFailure.INVALID_BINDING) { use.get().document }
        } finally { metadata.shutdown(250_000_000) }
    }

    @Test fun bindingInitializationShutdownCannotPublishNewBinding(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val published = AtomicBoolean()
        val owner = Thread({
            try {
                rig.metadata.bindAuthorization(authSnapshot(), ChatGptPlanOAuthRedirect.of(42321),
                    ChatGptPlanOAuthClock { entered.countDown(); authAwait(release); rig.clock.nanos.get() },
                    ChatGptPlanOAuthRandom { it.fill(1) }, ChatGptPlanOAuthCancellation { false }, rig.clock.operation())
                published.set(true)
            } catch (_: Exception) { }
        }, "chatgpt-auth-binding-initialization")
        owner.start()
        try {
            authAwait(entered)
            assertEquals(ChatGptAuthSettlement.UNSETTLED, rig.metadata.shutdown(0))
        } finally { release.countDown(); authJoin(owner) }
        assertFalse(published.get())
        assertEquals(ChatGptAuthSettlement.SETTLED, rig.metadata.shutdown(0))
    }

    @Test fun metadataShutdownRetainsDerivedEndpointHelperUntilAcknowledged(): Unit = AuthTestRig().use { rig ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val armed = AtomicBoolean(); val published = AtomicBoolean(); val failures = AtomicReference<Throwable>()
        rig.port.scripts.add(AuthScript(authDiscovery("https://auth.openai.com/oauth/revoke")))
        val owner = Thread({
            try {
                val operation = rig.clock.operation(cancelled = {
                    if (Thread.currentThread().stackTrace.any { it.className == "decompengine.chatgpt.OidcEndpoint" } && armed.compareAndSet(true, false)) {
                        entered.countDown(); authAwait(release)
                    }
                    false
                })
                val endpoint = rig.metadata.discovery(operation).revocation!!
                armed.set(true)
                endpoint.newRevocationRequest(ChatGptLocalLogout(ChatGptPlanAccount("review-account", ChatGptPlanOidc.ISSUER, "oaiapp_test", "Review", null, null, 0, 0, ChatGptPlanAccount.State.SIGNED_OUT, emptySet(), null), "oaiapp_test", "synthetic-refresh", false), operation, operation.deadline.cap(10_000_000_000L))
                published.set(true)
            } catch (e: ChatGptAuthHttpException) { }
            catch (e: Throwable) { failures.set(e) }
        }, "chatgpt-auth-review-endpoint-owner")
        var settlement: ChatGptAuthSettlement? = null
        owner.start()
        try {
            authAwait(entered)
            // Executor shutdown is asynchronous even when idle; observe repeated receipts
            // while the raw endpoint owner is still held, without releasing its barrier.
            repeat(50) {
                if (settlement != ChatGptAuthSettlement.SETTLED) {
                    settlement = rig.metadata.shutdown(0)
                    Thread.sleep(1)
                }
            }
            println("endpoint_helper settlement=$settlement ownerAlive=${owner.isAlive}")
        } finally { release.countDown(); authJoin(owner) }
        failures.get()?.let { throw it }
        assertFalse(published.get(), "postcheck must fence late request")
        assertEquals(ChatGptAuthSettlement.UNSETTLED, settlement, "derived endpoint helper still owns its callback stack")
    }

    @Test fun derivedEndpointBlockedHelperRetainsActivityThroughLateAcknowledgement() = derivedEndpointHelper("block-close")
    @Test fun derivedEndpointBlockedHelperCanReturnWhileLeaseRemainsLive() = derivedEndpointHelper("block-live")
    @Test fun derivedEndpointReentrantHelperShutdownCannotPublish() = derivedEndpointHelper("reenter")
    @Test fun derivedEndpointThrowingHelperAcknowledgesAndSanitizesFailure() = derivedEndpointHelper("throw")
    @Test fun derivedEndpointFinalClockShutdownCannotPublish() = derivedEndpointHelper("final-close")
    private fun derivedEndpointHelper(mode: String) {
        val clock = AuthTestClock(); val port = AuthScriptPort()
        val transport = newChatGptAuthTransport(port, clock.nanos::get, clock.now::get)
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val armed = AtomicBoolean(); val finalArmed = AtomicBoolean()
        val published = AtomicBoolean(); val failure = AtomicReference<Throwable>()
        val helperFailure = AtomicReference<ChatGptAuthHttpException>()
        val receipt = AtomicReference<ChatGptAuthSettlement>()
        lateinit var metadata: ChatGptAuthMetadata
        metadata = newChatGptAuthMetadata(transport, clock.authority, {
            if (finalArmed.compareAndSet(true, false)) receipt.set(metadata.shutdown(0))
            clock.nanos.get()
        }, clock.now::get)
        port.scripts.add(AuthScript(authDiscovery("https://auth.openai.com/oauth/revoke")))
        val worker = Thread({
            try {
                val operation = clock.operation(cancelled = {
                    if (Thread.currentThread().stackTrace.any { it.className == "decompengine.chatgpt.OidcEndpoint" } && armed.compareAndSet(true, false)) {
                        when (mode) {
                            "block-close", "block-live" -> { entered.countDown(); authAwait(release) }
                            "reenter" -> receipt.set(metadata.shutdown(0))
                            "throw" -> error("synthetic endpoint helper detail")
                            "final-close" -> finalArmed.set(true)
                        }
                    }
                    false
                })
                val endpoint = metadata.discovery(operation).revocation!!
                armed.set(true)
                endpoint.newRevocationRequest(ChatGptLocalLogout(ChatGptPlanAccount("endpoint-account", ChatGptPlanOidc.ISSUER,
                    "oaiapp_test", "Endpoint", null, null, 0, 0, ChatGptPlanAccount.State.SIGNED_OUT, emptySet(), null),
                    "oaiapp_test", "synthetic-refresh", false), operation, operation.deadline.cap(10_000_000_000L))
                published.set(true)
            } catch (e: ChatGptAuthHttpException) { helperFailure.set(e) }
            catch (e: Throwable) { failure.set(e) }
        }, "chatgpt-auth-endpoint-owner")
        worker.start()
        try {
            if (mode.startsWith("block")) {
                authAwait(entered)
                if (mode == "block-close") repeat(10) {
                    assertEquals(ChatGptAuthSettlement.UNSETTLED, metadata.shutdown(0))
                    assertTrue(worker.isAlive)
                    Thread.sleep(1)
                }
                release.countDown()
            }
            authJoin(worker); failure.get()?.let { throw it }
            assertEquals(mode == "block-live", published.get())
            if (mode != "block-live") {
                assertNotNull(helperFailure.get())
                assertNull(helperFailure.get().cause); assertTrue(helperFailure.get().suppressed.isEmpty())
            }
            if (mode in listOf("reenter", "final-close")) assertEquals(ChatGptAuthSettlement.UNSETTLED, receipt.get())
            authEventually { metadata.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        } finally {
            release.countDown(); authJoin(worker)
            authEventually { metadata.shutdown(0) == ChatGptAuthSettlement.SETTLED }
            authEventually { transport.shutdown(0) == ChatGptAuthSettlement.SETTLED }
        }
    }

}
