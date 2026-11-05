package decompengine.builtin.provider

import decompengine.agent.AgentExecutionLimits
import decompengine.builtin.*
import java.time.Duration
import kotlin.test.*
import kotlinx.serialization.json.JsonPrimitive

class ChatGptPlanOfflineHarnessTest {
    private fun assertPrivate(f: C3Fixture, value: OfflineHttpValueV1) {
        assertFalse(value is OfflineHttpValueV1.Attempt && value.value is ChatGptAttemptResultV1.Completed)
        val text = ((value as? OfflineHttpValueV1.Attempt)?.value as? ChatGptAttemptResultV1.Stopped)?.diagnostic?.render()
        if (text != null) {
            val scan = runCatching { f.secrets.rejectCredentialsInPrivateJson(JsonPrimitive(text)) }
            assertTrue(scan.isSuccess, "cleanup published a diagnostic that the current secret registry rejects")
        }
        assertEquals(0, f.effects)
        assertTrue(f.allocated.all { it.closed })
        assertEquals(1, f.ledger.observations().size)
    }
    @Test fun finishedRegistrationCannotEscapeViaCleanupDiagnostic() {
        val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(body = C3Wire.text(usage = C2Fixture.usage("1", "2", "3"))))
        var hit = false
        f.hook = { if (it == "Finished") { hit = true; f.secrets.registerSynthetic("kind=") } }
        val value = f.drive(f.start()); assertTrue(hit)
        assertEquals(AttemptOutcomeV2.COMPLETED, f.ledger.observations().single().outcome)
        assertEquals(3, f.ledger.observations().single().reported!!.total)
        assertPrivate(f, value)
    }
    @Test fun settledRegistrationCannotEscapeViaCleanupDiagnostic() {
        val f = C3Fixture(durabilityAt = 99); f.admit(); f.script(C3Reply.catalog(), C3Reply())
        var hit = false
        f.hook = { if (it == "settlement:SETTLED") { hit = true; f.secrets.registerSynthetic("kind=") } }
        val value = f.drive(f.start()); assertTrue(hit)
        assertTrue(f.events.none { it is ModelEventV2.Finished })
        assertPrivate(f, value)
    }
    @Test fun classifiedDiagnosticMustBeRescannedAfterSettlementCallback() {
        val f = C3Fixture(durabilityAt = 99); f.admit()
        f.script(C3Reply.catalog(), C3Reply(429, "{}".toByteArray(), listOf("x-request-id" to "req_review_sentinel")))
        var hit = false
        f.hook = { if (it == "settlement:SETTLED") { hit = true; f.secrets.registerSynthetic("req_review_sentinel") } }
        val value = f.drive(f.start()); assertTrue(hit)
        assertEquals(AttemptOutcomeV2.FAILED, f.ledger.observations().single().outcome)
        assertPrivate(f, value)
    }

    @Test fun admissionRejectionsHaveZeroTokenCatalogSendAndToolEffects() {
        for (f in listOf(C3Fixture(requirement = GenerationRequirementV2.RequireServerOutputCap(1)),
            C3Fixture(legacy = AgentExecutionLimits(maxInputTokens = 1)), C3Fixture(legacy = AgentExecutionLimits(maxOutputTokens = 1)))) {
            assertFailsWith<ModelProviderException> { f.admit() }; assertEquals(0, f.acquire); assertEquals(0, f.allocations); assertEquals(0, f.effects)
        }
        for (mode in 0..2) {
            val f = C3Fixture(); f.admit(); f.missingScopes = mode == 0; f.wrongBinding = mode == 1
            f.script(C3Reply.catalog("other-model")); assertIs<OfflineHttpValueV1.CatalogFailure>(f.drive(f.start()))
            assertEquals(0, f.ledger.counters().requests); assertEquals(LedgerStateV2.READY, f.ledger.state()); assertEquals(0, f.effects)
            assertEquals(if (mode == 2) 1 else 0, f.allocations)
        }
    }
    @Test fun fullTwoTurnActualBatchPreservesRawItemsResultsAndAccounting() {
        val f = C3Fixture(); f.admit()
        val raw = listOf(C2Fixture.message("hello"), C2Fixture.reasoning(), C2Fixture.function())
        val first = C3Reply(body = C3Wire.stream(raw, C2Fixture.usage("1", "9", "10")))
        val second = C3Reply(body = C3Wire.text("done", C2Fixture.usage()))
        f.script(C3Reply.catalog(), first, C3Reply.catalog(), second)
        val one = f.completed(f.drive(f.start()))
        assertTrue(first.closed); assertEquals(LedgerStateV2.READY, f.ledger.state()); assertEquals(0, f.previews)
        assertEquals(raw, one.response.continuation.orderedItems().map { it.toString(Charsets.UTF_8) })
        val results = f.execute(one.response); assertEquals(1, f.previews); assertEquals(1, f.effects)
        val messages = f.prior + ModelMessageV2(ModelRole.ASSISTANT, one.response.text, one.response.continuation)
        val resultMap = mapOf(one.response.continuation to results)
        val expected = f.codec.encode(f.run, messages, resultMap).encoded()
        f.completed(f.drive(f.start(2, messages, resultMap)))
        assertContentEquals(expected, second.sent)
        val replay = second.sent!!.toString(Charsets.UTF_8)
        raw.forEach { item -> assertEquals(1, replay.windowed(item.length).count { it == item }) }
        assertEquals(1, Regex("function_call_output").findAll(replay).count()); assertTrue(replay.contains("\"output\":\"ok\""))
        for (field in listOf("max_output_tokens", "temperature", "previous_response_id", "conversation", "background")) assertFalse(replay.contains(field))
        val displayed = f.events.filterIsInstance<ModelEventV2.TextDelta>().joinToString("") { it.text }
        assertEquals("hellodone", displayed); assertFalse(displayed.contains("private")); assertFalse(displayed.contains("source.c"))
        assertEquals(first.sent!!.size.toLong() + second.sent!!.size, f.ledger.counters().input)
        assertEquals(first.body.size.toLong() + second.body.size, f.ledger.counters().wire)
        assertEquals(listOf(1, 2), f.ledger.observations().map { it.callOrdinal }); assertEquals(UsageCoverageV1.COMPLETE, f.ledger.aggregate().coverage)
        assertTrue(second.closed); assertEquals(2, f.events.filterIsInstance<ModelEventV2.Finished>().size)
    }
    @Test fun continuationAndResultsRequireOwnedExactIdentities() {
        val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(body = C3Wire.stream(listOf(C2Fixture.function()))))
        val r = f.completed(f.drive(f.start())).response; val batch = f.batch(); val results = f.execute(r, batch)
        assertFailsWith<ModelProviderException> { f.harness.executeCompleted(r, batch) { _, _, _ -> f.effects++ } }
        assertEquals(1, f.effects)
        val g = C3Fixture(); g.admit()
        assertFailsWith<ModelProviderException> { g.start(1, g.prior + ModelMessageV2(ModelRole.ASSISTANT, r.text, r.continuation), mapOf(r.continuation to results)) }
        assertEquals(0, g.acquire); assertEquals(0, g.effects)
    }
    @Test fun failedIncompleteAndErrorRetainTerminalUsageAndNeverFinish() {
        for (type in listOf("failed", "incomplete", "error")) {
            val f = C3Fixture(); f.admit()
            val body = if (type == "error") "data: {\"type\":\"error\",\"sequence_number\":0,\"code\":null,\"message\":\"safe\",\"param\":null}\n\n".toByteArray()
                else C3Wire.stream(emptyList(), C2Fixture.usage("2", "3", "5"), type)
            f.script(C3Reply.catalog(), C3Reply(body = body)); val r = f.stopped(f.drive(f.start()))
            val expected = if (type == "incomplete") AttemptOutcomeV2.INCOMPLETE else AttemptOutcomeV2.FAILED
            assertEquals(expected, r.outcome); assertEquals(expected, f.ledger.observations().single().outcome)
            assertEquals(if (type == "error") null else 5L, r.reported?.total)
            assertTrue(f.events.none { it is ModelEventV2.Finished }); assertEquals(0, f.effects)
        }
    }
    @Test fun unknownNullAndZeroUsageRemainDistinct() {
        for (usage in listOf(null, "null", C2Fixture.usage())) {
            val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(body = C3Wire.text(usage = usage)))
            val r = f.completed(f.drive(f.start())); assertEquals(if (usage == null || usage == "null") null else 0L, r.reported?.total)
            assertEquals(if (r.reported == null) UsageCoverageV1.NONE else UsageCoverageV1.COMPLETE, f.ledger.aggregate().coverage)
            assertEquals(r.reported?.total, f.ledger.aggregate().total)
        }
    }
    @Test fun malformedUsageIsAmbiguousAndActualOverdrawIsNotClamped() {
        for (usage in listOf(C2Fixture.usage("1", "2", "4"), C2Fixture.usage("-1", "1", "0"))) {
            val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(body = C3Wire.text(usage = usage)))
            assertEquals(AttemptOutcomeV2.AMBIGUOUS, f.stopped(f.drive(f.start())).outcome)
            assertNull(f.ledger.aggregate().total); assertEquals(f.run.budget.outputUnits, f.ledger.counters().output)
        }
        val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(body = C3Wire.text(usage = C2Fixture.usage("0", "128001", "128001"))))
        f.stopped(f.drive(f.start())); assertEquals(128001, f.ledger.counters().output); assertEquals(LedgerStateV2.EXHAUSTED, f.ledger.state())
        assertTrue(f.events.none { it is ModelEventV2.Finished }); assertEquals(0, f.effects)
    }
    @Test fun refusedMapsToUnsupportedFailedWithoutCompletedAuthority() {
        val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(body = C3Wire.stream(listOf(C2Fixture.message("no", type = "refusal")), C2Fixture.usage())))
        val r = f.stopped(f.drive(f.start())); assertEquals(ModelFailureKind.UNSUPPORTED_FEATURE, r.kind)
        assertEquals(AttemptOutcomeV2.FAILED, r.outcome); assertNotNull(r.reported); assertEquals(AttemptOutcomeV2.FAILED, f.ledger.observations().single().outcome)
        assertTrue(f.events.none { it is ModelEventV2.Finished }); assertEquals(0, f.previews)
    }
    @Test fun retry503Then200ChargesFullRepeatedBodyAndErrorWireOnce() {
        val f = C3Fixture(); f.admit(); val bad = C3Reply(503, "{}".toByteArray(), listOf("Retry-After" to "1")); val good = C3Reply(body = C3Wire.text(usage = C2Fixture.usage()))
        f.script(C3Reply.catalog(), bad, good); val t = f.start(); f.completed(f.drive(t))
        assertTrue(bad.closed); assertTrue(good.closed); assertEquals(1, f.acquire); assertEquals(0, f.renew); assertEquals(3, f.allocations)
        assertContentEquals(bad.sent, good.sent); assertEquals(2L * bad.sent!!.size, f.ledger.counters().input)
        assertEquals(bad.body.size.toLong() + good.body.size, f.ledger.counters().wire); assertEquals(listOf(1, 2), f.ledger.observations().map { it.attempt })
        assertEquals(UsageCoverageV1.PARTIAL, f.ledger.aggregate().coverage); assertNull(f.ledger.aggregate().total); assertTrue(f.state.now >= 1_000_000_000)
    }
    @Test fun renewalIsSharedBetweenExpiryAnd401AndRecatalogsExactlyOnce() {
        val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(401, "{}".toByteArray()), C3Reply.catalog(), C3Reply())
        f.completed(f.drive(f.start())); assertEquals(1, f.renew); assertEquals(4, f.allocations); assertEquals(2, f.ledger.counters().requests)
        assertEquals(2, f.secrets.registryRevision())
        val g = C3Fixture(); g.admit(); g.expired = true; g.script(C3Reply.catalog(), C3Reply(401, "{}".toByteArray()))
        g.stopped(g.drive(g.start())); assertEquals(1, g.renew); assertEquals(2, g.allocations); assertEquals(1, g.ledger.counters().requests)
    }
    @Test fun retryClassificationAndRetryAfterNeverClampToFit() {
        val stop = listOf(C3Reply(429, "{}".toByteArray()), C3Reply(403, "{}".toByteArray()),
            C3Reply(503, """{"error":{"code":"subscription_sharing_unsupported_capability"}}""".toByteArray()),
            C3Reply(503, "{}".toByteArray(), listOf("Retry-After" to "31")),
            C3Reply(503, "{}".toByteArray(), listOf("Retry-After" to "1", "Retry-After" to "1")),
            C3Reply(503, "{}".toByteArray(), listOf("Retry-After" to "999999999999999999999999")))
        for (r in stop) { val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), r); f.stopped(f.drive(f.start())); assertEquals(1, f.ledger.counters().requests); assertTrue(r.closed) }
        val f = C3Fixture(LocalBudgetV1(overallTimeout = Duration.ofMillis(100))); f.admit(); f.script(C3Reply.catalog(), C3Reply(503, "{}".toByteArray()))
        f.stopped(f.drive(f.start())); assertEquals(1, f.ledger.counters().requests)
        for (status in listOf(408, 500, 502, 504)) {
            val g = C3Fixture(); g.admit(); g.script(C3Reply.catalog(), C3Reply(status, """{"detail":"private"}""".toByteArray()), C3Reply())
            g.completed(g.drive(g.start())); assertEquals(2, g.ledger.counters().requests)
        }
    }
    @Test fun any200ByteAndEmpty200EofNeverReplayOrRefund() {
        for (body in listOf(byteArrayOf(), ": keepalive\n\n".toByteArray(), "garbage".toByteArray(),
            "data: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":${C2Fixture.envelope("in_progress")}}\n\n".toByteArray())) {
            val f = C3Fixture(); f.admit(); val r = C3Reply(body = body); f.script(C3Reply.catalog(), r, C3Reply())
            val result = f.stopped(f.drive(f.start())); assertEquals(AttemptOutcomeV2.AMBIGUOUS, result.outcome)
            assertEquals(1, f.ledger.counters().requests); assertEquals(2, f.allocations); assertEquals(f.run.budget.outputUnits, f.ledger.counters().output)
            assertEquals(LedgerStateV2.INDETERMINATE, f.ledger.state()); assertEquals(body.size.toLong(), f.ledger.counters().wire)
        }
    }
    @Test fun allocationAndUnsentDispatchFailuresRetainReservationWithoutAuthority() {
        for (mode in 0..3) {
            val f = C3Fixture(); f.admit(); val r = C3Reply().also {
                it.throwAllocate = mode == 0; it.throwDispatch = mode != 0
                it.send = if (mode == 1) OfflineSendFactV1.SCRIPTED_ZERO_SEND else if (mode == 2) OfflineSendFactV1.NEVER_DISPATCHED else OfflineSendFactV1.POSSIBLY_SENT
            }
            f.script(C3Reply.catalog(), r); f.stopped(f.drive(f.start()))
            assertEquals(1, f.ledger.counters().requests); assertEquals(f.run.budget.outputUnits, f.ledger.counters().output)
            assertEquals(LedgerStateV2.INDETERMINATE, f.ledger.state()); if (mode != 0) assertTrue(r.closed)
        }
    }
    @Test fun originalOrdinalLifetimeSurvivesRetriesAndCatalogTime() {
        val f = C3Fixture(LocalBudgetV1(overallTimeout = Duration.ofMillis(400))); f.admit()
        val second = C3Reply().also { it.readPending = 1000 }
        f.script(C3Reply.catalog(), C3Reply(503, "{}".toByteArray()), second)
        val turn = f.start(); f.stopped(f.drive(turn)); assertEquals(2, f.ledger.counters().requests)
        assertNotNull(second.timeouts); assertTrue(second.timeouts!!.overallNanos < 150_000_000)
        assertTrue(f.state.now < 450_000_000); assertTrue(second.closed)
    }
    @Test fun reserveIntentAndSettlementPublicationFailuresRetainActualOwner() {
        for (at in 1..3) {
            val f = C3Fixture(durabilityAt = at); f.admit(); f.script(C3Reply.catalog(), C3Reply())
            val result = f.drive(f.start()); assertFalse(result is OfflineHttpValueV1.Attempt && result.value is ChatGptAttemptResultV1.Completed)
            assertEquals(LedgerStateV2.INDETERMINATE, f.ledger.state()); assertEquals(if (at == 1) 0 else 1, f.ledger.counters().requests)
            assertEquals(if (at < 3) 1 else 2, f.allocations); assertTrue(f.events.none { it is ModelEventV2.Finished })
            assertEquals(if (at == 3) 1 else 0, f.ledger.observations().size)
            assertFailsWith<ModelProviderException> { f.start(2) }
        }
    }
    @Test fun finishedCancellationThrowReentryAndDistinctRegistryWithholdResponse() {
        for (mode in 0..4) {
            val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply()); lateinit var turn: OfflineTurnV1
            var hit = false
            f.hook = { if (it == "Finished") { hit = true; when (mode) {
                0 -> f.state.cancelled = true
                1 -> throw IllegalStateException("private failure")
                2 -> try { turn.step() } catch (_: ModelProviderException) { }
                3 -> f.secrets.registerSynthetic("unrelated-distinct")
                4 -> f.state.revision++
            } } }
            turn = f.start(); val value = f.drive(turn)
            // AUTHORIZATION is itself rejected by the credential-marker scanner.
            if (mode == 4) assertEquals(ModelFailureKind.SECRET_EXPOSURE, assertIs<OfflineHttpValueV1.CatalogFailure>(value).kind)
            else f.stopped(value)
            assertPrivate(f, value); assertTrue(hit); assertEquals(1, f.ledger.observations().size)
            assertEquals(AttemptOutcomeV2.COMPLETED, f.ledger.observations().single().outcome); assertEquals(0, f.effects)
        }
    }
    @Test fun duplicateRegistryAtFinalCallbackIsHarmless() {
        val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply())
        f.hook = { if (it == "Finished") f.secrets.registerSynthetic("fixture-secret-0") }
        f.completed(f.drive(f.start())); assertEquals(1, f.secrets.registryRevision())
    }
    @Test fun everyTransportAndTokenCallbackRechecksCancellationAndRevocation() {
        for (stage in listOf("acquire", "register", "recheck", "wall", "dispatch:MODELS", "headers:MODELS", "read:MODELS", "close:MODELS",
            "dispatch:RESPONSES", "headers:RESPONSES", "read:RESPONSES", "sink", "close:RESPONSES")) {
            for (cancel in listOf(true, false)) {
                val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply()); var hit = false
                f.hook = { if (it == stage && !hit) { hit = true; if (cancel) f.state.cancelled = true else f.state.revision++ } }
                val out = f.drive(f.start()); assertTrue(hit, stage); assertFalse(out is OfflineHttpValueV1.Attempt && out.value is ChatGptAttemptResultV1.Completed, stage)
                assertTrue(f.events.none { it is ModelEventV2.Finished }, stage); assertEquals(0, f.effects)
                assertTrue(f.allocated.all { it.closed }, stage)
            }
        }
    }
    @Test fun swallowedNestedStartAndStepPermanentlyRevokeAtCallbacks() {
        for (stage in listOf("acquire", "register", "dispatch:RESPONSES", "headers:RESPONSES", "read:RESPONSES", "close:RESPONSES", "sink")) {
            for (nestedStart in listOf(true, false)) {
                val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply()); lateinit var t: OfflineTurnV1; var hit = false
                f.hook = { if (it == stage && !hit) { hit = true; try { if (nestedStart) f.start(2) else t.step() } catch (_: ModelProviderException) { } } }
                t = f.start(); val out = f.drive(t); assertTrue(hit); assertFalse(out is OfflineHttpValueV1.Attempt && out.value is ChatGptAttemptResultV1.Completed)
                assertTrue(f.allocated.all { it.closed }); assertEquals(0, f.effects)
            }
        }
    }
    @Test fun clockCallbackCancelsAfterACancellationSampleAndCannotPublish() {
        for (method in listOf("encode", "reserve", "markDispatchIntent", "call", "feed", "readDemand", "requireCurrentSuccessful")) {
            val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply()); var hit = false
            f.hook = { if (it == "clock" && !hit && Thread.currentThread().stackTrace.any { frame -> frame.methodName.substringBefore('$') == method }) { hit = true; f.state.cancelled = true } }
            val value = f.drive(f.start()); assertTrue(hit, method)
            assertFalse(value is OfflineHttpValueV1.Attempt && value.value is ChatGptAttemptResultV1.Completed, method)
            assertEquals(0, f.effects); assertTrue(f.allocated.all { it.closed })
        }
    }
    @Test fun terminalRegistryMutationInCloseIsFencedButDuplicatePasses() {
        for (duplicate in listOf(false, true)) {
            val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(body = C3Wire.text(usage = C2Fixture.usage())))
            f.hook = { if (it == "close:RESPONSES") f.secrets.registerSynthetic(if (duplicate) "fixture-secret-0" else "new-private-sentinel") }
            val out = f.drive(f.start()); if (duplicate) f.completed(out) else { val r = f.stopped(out); assertEquals(ModelFailureKind.SECRET_EXPOSURE, r.kind); assertNotNull(r.reported) }
        }
    }
    @Test fun finalAuthorityAndDeadlineCallbacksCannotAuthorizeRevokedEffect() {
        for (stage in listOf("authority", "authority-recheck", "clock")) {
            val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(body = C3Wire.stream(listOf(C2Fixture.function()))))
            val r = f.completed(f.drive(f.start())).response; val batch = f.batch(); var hit = false
            f.hook = { if (it == stage) { hit = true; f.state.revision++ } }
            assertFailsWith<ModelProviderException> { f.execute(r, batch) }; assertTrue(hit); assertEquals(0, f.effects)
        }
    }
    @Test fun noRemainingRequestOrResultCapacityMeansZeroEffects() {
        val f = C3Fixture(LocalBudgetV1(maxRequests = 1)); f.admit(); f.script(C3Reply.catalog(), C3Reply(body = C3Wire.stream(listOf(C2Fixture.function()))))
        val r = f.completed(f.drive(f.start())).response
        assertFailsWith<ModelProviderException> { f.execute(r) }; assertEquals(0, f.previews); assertEquals(0, f.effects)
        val g = C3Fixture(LocalBudgetV1(toolResultBytes = 8)); g.admit(); g.script(C3Reply.catalog(), C3Reply(body = C3Wire.stream(listOf(C2Fixture.function()))))
        val s = g.completed(g.drive(g.start())).response
        assertFailsWith<ModelProviderException> { g.execute(s) }; assertEquals(1, g.previews); assertEquals(0, g.effects)
    }
    @Test fun renewalCallbackCancelRevokeAndReentryNeverDispatchAgain() {
        for (mode in 0..2) {
            val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(401, "{}".toByteArray()))
            lateinit var t: OfflineTurnV1; var hit = false
            f.hook = { if (it == "renew") { hit = true; when (mode) {
                0 -> f.state.cancelled = true
                1 -> f.state.revision++
                2 -> try { t.step() } catch (_: ModelProviderException) { }
            } } }
            t = f.start(); f.drive(t); assertTrue(hit); assertEquals(1, f.renew); assertEquals(1, f.ledger.counters().requests)
            assertTrue(f.allocated.all { it.closed }); assertEquals(0, f.effects)
        }
    }
    @Test fun publicationCallbacksRevokeEvenWhenNestedFailureIsSwallowed() {
        for (state in listOf("RESERVED", "DISPATCH_INTENT", "SETTLED")) {
            for (mode in 0..3) {
                val f = C3Fixture(durabilityAt = 99); f.admit(); f.script(C3Reply.catalog(), C3Reply())
                lateinit var t: OfflineTurnV1; var hit = false
                f.hook = { if (it == "settlement:$state") { hit = true; when (mode) {
                    0 -> f.state.cancelled = true
                    1 -> f.state.revision++
                    2 -> f.secrets.registerSynthetic("publication-sentinel")
                    3 -> try { t.step() } catch (_: ModelProviderException) { }
                } } }
                t = f.start(); val value = f.drive(t); assertTrue(hit, state)
                assertFalse(value is OfflineHttpValueV1.Attempt && value.value is ChatGptAttemptResultV1.Completed)
                assertTrue(f.events.none { it is ModelEventV2.Finished }); assertEquals(0, f.effects)
                assertTrue(f.ledger.observations().size <= 1); assertTrue(f.allocated.all { it.closed })
            }
        }
    }
    @Test fun finalAuthorityClockHasCallbackFreeFenceImmediatelyBeforeEffect() {
        for (mode in 0..3) {
            val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(body = C3Wire.stream(listOf(C2Fixture.function()))))
            val r = f.completed(f.drive(f.start())).response; val batch = f.batch(); var calls = 0; var hit = false
            f.hook = {
                if (it == "authority") calls++
                if (it == "clock" && calls == 2 && !hit) { hit = true; when (mode) {
                    0 -> f.state.cancelled = true
                    1 -> f.state.revision++
                    2 -> f.secrets.registerSynthetic("tool-fence-sentinel")
                    3 -> try { f.start(2) } catch (_: ModelProviderException) { }
                } }
            }
            assertFailsWith<ModelProviderException> { f.execute(r, batch) }; assertTrue(hit); assertEquals(0, f.effects)
        }
    }
    @Test fun secretAndGenerationChangesAtTransportBoundariesNeverPublish() {
        for (stage in listOf("dispatch:MODELS", "headers:MODELS", "read:MODELS", "close:MODELS", "dispatch:RESPONSES",
            "headers:RESPONSES", "read:RESPONSES", "sink", "close:RESPONSES", "Finished")) {
            for (mode in 0..2) {
                val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply()); var hit = false
                f.hook = { if (it == stage && !hit) { hit = true; when (mode) {
                    0 -> f.state.generation++
                    1 -> f.state.commitment = "9".repeat(64)
                    2 -> f.secrets.registerSynthetic("arbitrary-distinct-sentinel")
                } } }
                val value = f.drive(f.start()); assertTrue(hit, stage)
                assertFalse(value is OfflineHttpValueV1.Attempt && value.value is ChatGptAttemptResultV1.Completed, stage)
                assertEquals(0, f.effects); assertTrue(f.allocated.all { it.closed })
            }
        }
    }
    @Test fun runDeadlineAndOrdinalDeadlineAreBothOriginal() {
        val f = C3Fixture(LocalBudgetV1(wallClock = Duration.ofMillis(300))); f.admit()
        f.script(C3Reply.catalog(), C3Reply(503, "{}".toByteArray()), C3Reply().also { it.readPending = 1000 })
        f.stopped(f.drive(f.start())); assertTrue(f.state.now <= 310_000_000); assertTrue(f.allocated.all { it.closed })
        val g = C3Fixture(LocalBudgetV1(overallTimeout = Duration.ofMillis(10))); g.admit()
        g.script(C3Reply.catalog().also { it.headersPending = 30 })
        assertIs<OfflineHttpValueV1.CatalogFailure>(g.drive(g.start())); assertEquals(0, g.ledger.counters().requests)
        assertEquals(1, g.allocations); assertTrue(g.allocated.single().closed)
    }
    @Test fun retryStartsRemainBoundedAndNoResponseCapRefund() {
        val f = C3Fixture(LocalBudgetV1(maxRetries = 2)); f.admit()
        f.script(C3Reply.catalog(), C3Reply(503, "{}".toByteArray()), C3Reply(503, "{}".toByteArray()), C3Reply(503, "{}".toByteArray()))
        f.stopped(f.drive(f.start())); assertEquals(3, f.ledger.counters().requests); assertEquals(4, f.allocations)
        assertEquals(listOf(1, 2, 3), f.ledger.observations().map { it.attempt }); assertEquals(UsageCoverageV1.NONE, f.ledger.aggregate().coverage)
        val g = C3Fixture(LocalBudgetV1(responseBytes = 32768, eventBytes = 8192)); g.admit()
        val body = (": ping\n\n").repeat(5000).toByteArray(); g.script(C3Reply.catalog(), C3Reply(body = body))
        g.stopped(g.drive(g.start())); assertEquals(32769, g.ledger.counters().wire); assertEquals(g.run.budget.outputUnits, g.ledger.counters().output)
    }
    @Test fun pendingErrorBodiesAndErrorDiagnosticsAreBoundedAndPrivate() {
        val f = C3Fixture(); f.admit()
        val r = C3Reply(429, """{"error":{"message":"fixture-secret-0","code":"unknown-private","param":"private"}}""".toByteArray(), listOf("x-request-id" to "req_safe"))
        r.readPending = 3; f.script(C3Reply.catalog(), r)
        val stopped = f.stopped(f.drive(f.start())); val text = stopped.diagnostic.render()
        assertFalse(text.contains("fixture-secret")); assertFalse(text.contains("unknown-private")); assertFalse(text.contains("param=private"))
        assertTrue(text.toByteArray().size <= 2048); assertTrue(r.closed)
        val g = C3Fixture(); g.admit(); g.script(C3Reply.catalog(), C3Reply(429, "{}".toByteArray(), listOf("x-request-id" to "req_collision")))
        g.hook = { if (it == "register") g.secrets.registerSynthetic("req_collision") }
        val rejected = g.stopped(g.drive(g.start())); assertEquals(ModelFailureKind.SECRET_EXPOSURE, rejected.kind)
        assertFalse(rejected.diagnostic.render().contains("req_collision"))
    }
    @Test fun failedAndIncompleteCloseFailuresKeepOriginalOutcomeAndUsage() {
        for (type in listOf("failed", "incomplete")) {
            val f = C3Fixture(); f.admit(); val r = C3Reply(body = C3Wire.stream(emptyList(), C2Fixture.usage("1", "2", "3"), type)).also { it.closeFailure = true }
            f.script(C3Reply.catalog(), r); val result = assertIs<OfflineHttpValueV1.Attempt>(f.drive(f.start()))
            assertEquals(ModelFailureKind.TRANSPORT, result.closeFailure)
            assertEquals(if (type == "incomplete") AttemptOutcomeV2.INCOMPLETE else AttemptOutcomeV2.FAILED, result.value.outcome)
            assertEquals(3, result.value.reported!!.total); assertEquals(result.value.outcome, f.ledger.observations().single().outcome)
            assertTrue(f.events.none { it is ModelEventV2.Finished }); assertTrue(r.closed)
        }
    }
    @Test fun nextInputReservationRejectsBeforeAnyToolEffect() {
        val probe = C3Fixture(); probe.admit(); val bytes = probe.codec.encode(probe.run, probe.prior, emptyMap()).bytes
        val f = C3Fixture(LocalBudgetV1(inputUnits = bytes + 1)); f.admit()
        f.script(C3Reply.catalog(), C3Reply(body = C3Wire.stream(listOf(C2Fixture.function()))))
        val r = f.completed(f.drive(f.start())).response
        assertFailsWith<ModelProviderException> { f.execute(r) }; assertEquals(1, f.previews); assertEquals(0, f.effects)
        assertEquals(LedgerStateV2.INDETERMINATE, f.ledger.state())
    }

    @Test fun fixedDiagnosticCollisionIsWithheldButKnownTerminalUsageSettles() {
        for (terminal in listOf("failed", "incomplete")) {
            val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(body = C3Wire.stream(emptyList(), C2Fixture.usage("1", "2", "3"), terminal)))
            f.hook = { if (it == "close:RESPONSES") f.secrets.registerSynthetic("kind=") }
            val value = assertIs<OfflineHttpValueV1.CatalogFailure>(f.drive(f.start()))
            assertEquals(ModelFailureKind.SECRET_EXPOSURE, value.kind)
            val observation = f.ledger.observations().single(); assertEquals(3, observation.reported!!.total)
            assertEquals(if (terminal == "incomplete") AttemptOutcomeV2.INCOMPLETE else AttemptOutcomeV2.FAILED, observation.outcome)
            assertTrue(f.events.none { it is ModelEventV2.Finished }); assertEquals(0, f.effects)
        }
    }

    @Test fun actualCallbackEdgesFenceAllSixInvalidations() {
        for (method in listOf("encode", "reserve", "markDispatchIntent", "call", "readDemand", "feed", "requireCurrentSuccessful")) {
            for (mode in 0..5) {
                val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply()); var hit = false; lateinit var t: OfflineTurnV1
                f.hook = { if (it == "clock" && !hit && Thread.currentThread().stackTrace.any { frame -> frame.methodName.substringBefore('$') == method }) {
                    hit = true; when (mode) {
                        0 -> f.state.cancelled = true
                        1 -> f.state.now = f.state.end
                        2 -> f.state.revision++
                        3 -> f.state.generation++
                        4 -> f.secrets.registerSynthetic("callback-distinct-sentinel")
                        5 -> try { t.step() } catch (_: ModelProviderException) { }
                    }
                } }
                t = f.start(); val value = f.drive(t); assertTrue(hit, "$method/$mode")
                assertFalse(value is OfflineHttpValueV1.Attempt && value.value is ChatGptAttemptResultV1.Completed, "$method/$mode")
                assertTrue(f.events.none { it is ModelEventV2.Finished }); assertTrue(f.allocated.all { it.closed }); assertEquals(0, f.effects)
                assertTrue(f.ledger.observations().size <= 1)
            }
        }
    }
    @Test fun repeatedClosedStepsDoNotRepeatSettlementOrFinished() {
        val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply()); val t = f.start()
        val value = f.drive(t); repeat(3) { assertSame(value, assertIs<OfflineHttpProgressV1.Closed>(t.step()).value) }
        assertEquals(1, f.ledger.observations().size); assertEquals(1, f.events.filterIsInstance<ModelEventV2.Finished>().size)
        assertEquals(1, f.allocated.last().closes)
    }

    @Test fun allExternalCallbackEdgesExpireRegisterAndReenterSafely() {
        for (stage in listOf("acquire", "register", "recheck", "renew", "wall", "dispatch:MODELS", "headers:MODELS", "read:MODELS", "close:MODELS",
            "dispatch:RESPONSES", "headers:RESPONSES", "read:RESPONSES", "sink", "close:RESPONSES", "Finished")) {
            for (mode in 0..2) {
                val f = C3Fixture(); f.admit(); if (stage == "renew") f.expired = true
                f.script(C3Reply.catalog(), C3Reply()); var hit = false; lateinit var t: OfflineTurnV1
                f.hook = { if (it == stage && !hit) { hit = true; when (mode) {
                    0 -> f.state.now = f.state.end
                    1 -> f.secrets.registerSynthetic("fixture task")
                    2 -> try { t.step() } catch (_: ModelProviderException) { }
                } } }
                t = f.start(); val value = f.drive(t); assertTrue(hit, "$stage/$mode")
                assertFalse(value is OfflineHttpValueV1.Attempt && value.value is ChatGptAttemptResultV1.Completed, "$stage/$mode")
                assertTrue(f.allocated.all { it.closed }); assertEquals(0, f.effects); assertTrue(f.ledger.observations().size <= 1)
            }
        }
    }

    @Test fun actualAFrozenSuccessfulGateStillRejectsRefused() {
        val f = C2Fixture(); val raw = C2Fixture.message("no", type = "refusal")
        f.created(); f.added(raw); f.done(raw); f.terminal(listOf(raw), C2Fixture.usage())
        val refused = assertIs<ChatGptAttemptResultV1.Completed>(f.session.terminalResult()); f.settle(refused)
        assertFailsWith<ModelProviderException> { f.ledger.requireCurrentSuccessful(refused.response) }
        assertFailsWith<ModelProviderException> { f.execute(refused.response) }; assertEquals(0, f.previews); assertEquals(0, f.effects)
        val positive = C2Fixture(); val success = positive.complete(); positive.settle(success)
        positive.ledger.requireCurrentSuccessful(success.response)
    }
    @Test fun lastClockAfterFinishedCannotPublishUnfencedResponse() {
        for (mode in 0..2) {
            val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply()); var armed = false; var hit = false
            f.hook = {
                if (it == "Finished") armed = true
                if (it == "clock" && armed && !hit) { hit = true; when (mode) {
                    0 -> f.state.cancelled = true
                    1 -> f.state.revision++
                    2 -> f.secrets.registerSynthetic("last-clock-distinct")
                } }
            }
            val value = f.drive(f.start())
            // AUTHORIZATION is itself rejected by the credential-marker scanner.
            if (mode == 1) assertEquals(ModelFailureKind.SECRET_EXPOSURE, assertIs<OfflineHttpValueV1.CatalogFailure>(value).kind)
            else f.stopped(value)
            assertPrivate(f, value); assertTrue(hit); assertEquals(1, f.ledger.observations().size)
            assertEquals(AttemptOutcomeV2.COMPLETED, f.ledger.observations().single().outcome); assertEquals(0, f.effects)
        }
    }

}
