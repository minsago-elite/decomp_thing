package decompengine.builtin

import decompengine.agent.AgentCancellation
import decompengine.agent.AgentExecutionLimits
import decompengine.builtin.provider.*
import decompengine.chatgpt.ChatGptDeadlineClock
import decompengine.project.GeneratedCValidationHostSafetyLimits
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.lang.reflect.Modifier
import java.time.Duration
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.*

/** Actual A + explicit lower TEST composition only. No credentials, socket, host or production wiring. */
class ModelRunOriginalDeadlineTest {
    private fun seconds(n: Long) = Duration.ofSeconds(n)
    private fun check(a: ModelRunAdmissionV2, f: V2Fixture = V2Fixture()) = a.checkCapabilities(f.selection,
        GenerationRequirementV2.ElectLocalAcceptance(), ProviderCapabilitiesV2.siwc(),
        CallerRequirementsV2(f.legacy, f.local), HostAdmissionLimitsV2(f.hostLocal, GeneratedCValidationHostSafetyLimits()),
        ProfileAdmissionLimitsV2(f.profileLocal, f.validation))
    private fun original(c: ChatGptDeadlineClock, seconds: Long = 1200) =
        OriginalModelRunOperationV2.captureControlledForTest(c, Duration.ofSeconds(seconds))
    private fun admission(o: OriginalModelRunOperationV2, f: V2Fixture = V2Fixture(), registry: () -> List<ToolDefinitionV2> = { f.definitions }) =
        ModelRunAdmissionV2.fromOriginal(registry, f.commitments, o)
    private fun denied(kind: ModelFailureKind = ModelFailureKind.INVALID_REQUEST, block: () -> Unit) {
        assertEquals(kind, assertFailsWith<ModelProviderException>(block = block).kind)
    }
    private fun noLocks(a: ModelRunAdmissionV2) {
        assertFalse(Thread.holdsLock(a))
        val lock = ModelRunAdmissionV2::class.java.getDeclaredField("admissionLock").apply { isAccessible = true }.get(a)
        assertFalse(Thread.holdsLock(lock), "arbitrary callback held private admission lock")
    }
    private fun await(l: CountDownLatch) { assertTrue(l.await(3, TimeUnit.SECONDS), "bounded barrier") }
    private fun join(t: Thread) { t.join(3000); assertFalse(t.isAlive, "bounded join") }
    private fun eventual(predicate: () -> Boolean) {
        val start = System.nanoTime()
        while (!predicate()) { assertTrue(System.nanoTime() - start < 3_000_000_000L); Thread.sleep(1) }
    }

    @Test fun queue600And800ChargeOriginalDefaultAndLedgerSeesExpiry() {
        for (queue in listOf(600L, 800L)) {
            val f = V2Fixture(); val c = ChatGptDeadlineClock.controlled(); val o = original(c)
            c.advanceNanos(seconds(queue).toNanos())
            val a = admission(o, f); val run = a.bind(check(a, f), f.binding)
            val authority = run.deadline.requireTestAuthority(o)
            assertSame(authority, run.deadline.requireTestAuthority(o))
            assertEquals(seconds(1200 - queue).toNanos(), run.deadline.remainingNanos())
            val ledger = AttemptLedgerV2(run)
            val lease = ledger.reserve(UUID(8, 1), 1, 1, 1)
            ledger.markDispatchIntent(lease, 1); ledger.call(lease, byteArrayOf(1))
            c.advanceNanos(seconds(1200 - queue).toNanos())
            denied(ModelFailureKind.TIMEOUT) { run.deadline.requireTestAuthority(o) }
            denied(ModelFailureKind.TIMEOUT) { ledger.observe(lease, ObservedLocalCountersV2(), 0) }
        }
    }
    @Test fun everyWallMinimumAndDigestUsesSameOrigin() {
        val cases = listOf(
            1200L to V2Fixture(),
            900L to V2Fixture(),
            700L to V2Fixture(local = LocalBudgetV1(wallClock = seconds(700))),
            650L to V2Fixture(legacy = AgentExecutionLimits(wallClockTimeout = seconds(650))),
            600L to V2Fixture(hostLocal = LocalBudgetV1(wallClock = seconds(600))),
            550L to V2Fixture(profileLocal = LocalBudgetV1(wallClock = seconds(550))),
            500L to V2Fixture(local = LocalBudgetV1(wallClock = seconds(500))))
        for ((limit, f) in cases) {
            val c = ChatGptDeadlineClock.controlled(); val o = original(c, if (limit == 900L) 900 else 1200)
            c.advanceNanos(seconds(100).toNanos()); val a = admission(o, f); val checked = check(a, f)
            assertEquals(seconds(limit - 100).toNanos(), checked.deadline.remainingNanos())
            val offline = f.check()
            assertEquals(offline.budget.fields(), checked.budget.fields()); assertEquals(24, checked.budget.fields().size)
            assertEquals(offline.limitsDigest, checked.limitsDigest); assertEquals(offline.policyDigest, checked.policyDigest)
            assertEquals(CallTimeoutsV2(180_000_000_000, 10_000_000_000, 60_000_000_000, 30_000_000_000), checked.deadline.callTimeouts(checked.budget))
        }
        val c = ChatGptDeadlineClock.controlled(); val f = V2Fixture(local = LocalBudgetV1(wallClock = seconds(600)))
        val o = original(c); c.advanceNanos(seconds(500).toNanos()); val a = admission(o, f)
        assertEquals(seconds(100).toNanos(), a.bind(check(a, f), f.binding).deadline.remainingNanos())
    }
    @Test fun all24MinimaAndProportionalHistoryCommitmentsArePreserved() {
        val small = LocalBudgetV1(inputUnits = 11000, outputUnits = 6000, maxRequests = 9, maxToolActions = 10,
            callsPerResponse = 8, requestBytes = 9000, responseBytes = 8000, eventBytes = 7000, contextBytes = 10000,
            historyReserveBytes = 4000, continuationBytes = 8000, toolResultBytes = 1000, receivedBytesTotal = 9000,
            displayedBytesTotal = 8000, evidenceBytes = 15000, privateDiskBytes = 20000, maxIdenticalAction = 2,
            traceRecords = 100, wallClock = seconds(400), overallTimeout = seconds(90), connectTimeout = seconds(5),
            requestTimeout = seconds(40), idleTimeout = seconds(10), maxRetries = 1)
        for (f in listOf(V2Fixture(local = small), V2Fixture(hostLocal = small), V2Fixture(profileLocal = small))) {
            val c = ChatGptDeadlineClock.controlled(); val o = original(c); val a = admission(o, f)
            c.advanceNanos(seconds(100).toNanos()); val checked = check(a, f)
            assertEquals(small.fields(), checked.budget.fields()); assertEquals(f.check().policyDigest, checked.policyDigest)
            assertEquals(seconds(300).toNanos(), a.bind(checked, f.binding).deadline.remainingNanos())
        }
        val f = V2Fixture(local = LocalBudgetV1(contextBytes = 10000, historyReserveBytes = 4000, continuationBytes = 10000, toolResultBytes = 1000),
            hostLocal = LocalBudgetV1(contextBytes = 5000, continuationBytes = 5000, toolResultBytes = 1000))
        val a = admission(original(ChatGptDeadlineClock.controlled()), f)
        assertEquals(2000, check(a, f).budget.historyReserveBytes)
    }
    @Test fun trustedStrictCapsAndMissingElectionRejectBeforeRegistry() {
        for (mode in 0..3) {
            val f = V2Fixture(legacy = when (mode) {
                2 -> AgentExecutionLimits(maxInputTokens = 1)
                3 -> AgentExecutionLimits(maxOutputTokens = 1)
                else -> AgentExecutionLimits()
            })
            var reads = 0; val a = admission(original(ChatGptDeadlineClock.controlled()), f) { reads++; f.definitions }
            denied(ModelFailureKind.UNSUPPORTED_FEATURE) {
                a.checkCapabilities(if (mode <= 1) null else f.selection,
                    if (mode == 0) GenerationRequirementV2.RequireServerOutputCap(1) else GenerationRequirementV2.ElectLocalAcceptance(),
                    ProviderCapabilitiesV2.siwc(), CallerRequirementsV2(f.legacy, f.local),
                    HostAdmissionLimitsV2(f.hostLocal, GeneratedCValidationHostSafetyLimits()), ProfileAdmissionLimitsV2(f.profileLocal, f.validation))
            }
            assertEquals(0, reads); assertEquals(8192, ModelCallLimits().maxOutputTokens); assertEquals(1, MODEL_PROVIDER_CONTRACT_VERSION)
        }
    }
    @Test fun helper90Of100AndFinalFenceChargeWithoutFreshWindow() {
        for (elapsed in listOf(90L, 100L)) {
            val c = ChatGptDeadlineClock.controlled(); val o = original(c); val f = V2Fixture()
            val entry = c.readNanos()
            val a = admission(o, f) { c.advanceNanos(seconds(elapsed).toNanos()); o.tightenFrom(entry, seconds(100).toNanos()); f.definitions }
            if (elapsed == 100L) denied(ModelFailureKind.TIMEOUT) { check(a, f) }
            else {
                val run = a.bind(check(a, f), f.binding); assertEquals(seconds(10).toNanos(), run.deadline.remainingNanos())
                o.tightenFrom(c.readNanos(), seconds(1200).toNanos()); assertEquals(seconds(10).toNanos(), run.deadline.remainingNanos())
                c.advanceNanos(seconds(10).toNanos()); denied(ModelFailureKind.TIMEOUT) { run.deadline.requireTestAuthority(o) }
            }
        }
    }
    @Test fun systemTestForeignAndLegacyExportAreExplicitAndCached() {
        val f = V2Fixture(); val o = OriginalModelRunOperationV2.captureSystem(seconds(1200)); val a = admission(o, f)
        val run = a.bind(check(a, f), f.binding); val export = run.deadline.requireSystemAuthority(o)
        assertSame(ChatGptDeadlineClock.SYSTEM, export.deadline.clock)
        assertSame(export, run.deadline.requireSystemAuthority(o)); assertTrue(export.deadline.remainingNanos() > seconds(1100).toNanos())
        denied { run.deadline.requireTestAuthority(o) }
        denied { run.deadline.requireSystemAuthority(OriginalModelRunOperationV2.captureSystem(seconds(1200))) }
        denied { admission(o, f) }
        for (type in listOf(OriginalModelRunOperationV2::class.java, ModelRunDeadlineAuthorityV2::class.java)) {
            assertTrue(Modifier.isFinal(type.modifiers))
            assertTrue(type.declaredConstructors.filterNot { it.isSynthetic }.all { Modifier.isPrivate(it.modifiers) })
        }
        val c = ChatGptDeadlineClock.controlled(); val test = original(c); val ta = admission(test, f)
        val tr = ta.bind(check(ta, f), f.binding); val te = tr.deadline.requireTestAuthority(test)
        assertSame(te, tr.deadline.requireTestAuthority(test)); denied { tr.deadline.requireSystemAuthority(test) }
        denied { test.validate(te.deadline.detach(), te.fence, false) }
        denied { test.validate(te.deadline, decompengine.chatgpt.ChatGptOperationFence(), false) }
        denied { tr.deadline.requireTestAuthority(original(c)) }
        denied { tr.deadline.requireTestAuthority(original(ChatGptDeadlineClock.controlled())) }
        denied { OriginalModelRunOperationV2.captureControlledForTest(ChatGptDeadlineClock.SYSTEM, seconds(1)) }
        for (legacy in listOf(f.bind().deadline, RunDeadlineV2(Long.MAX_VALUE, NanoClockV2 { System.nanoTime() }, AgentCancellation.NONE))) {
            denied { legacy.requireSystemAuthority(o) }; denied { legacy.requireTestAuthority(test) }
        }
        o.cancel(); denied(ModelFailureKind.CANCELLED) { run.deadline.requireSystemAuthority(o) }
        assertTrue(export.fence.isCancelled())
    }
    @Test fun captureValidationWrapStickyCancelAndTighteningReachActualLedger() {
        denied { OriginalModelRunOperationV2.captureSystem(Duration.ZERO) }
        denied { OriginalModelRunOperationV2.captureSystem(Duration.ofNanos(-1)) }
        denied(ModelFailureKind.RESOURCE_EXHAUSTED) { OriginalModelRunOperationV2.captureSystem(seconds(Long.MAX_VALUE)) }
        for (cancel in listOf(false, true)) {
            val c = ChatGptDeadlineClock.controlled(Long.MAX_VALUE - 20); val o = original(c, 1500); val f = V2Fixture()
            val a = admission(o, f); val run = a.bind(check(a, f), f.binding); val ledger = AttemptLedgerV2(run)
            c.advanceNanos(seconds(800).toNanos()); assertEquals(seconds(400).toNanos(), run.deadline.remainingNanos())
            val authority = run.deadline.requireTestAuthority(o)
            if (cancel) o.cancel() else o.tightenFrom(c.readNanos(), 0)
            val kind = if (cancel) ModelFailureKind.CANCELLED else ModelFailureKind.TIMEOUT
            denied(kind) { ledger.reserve(UUID(1, 8), 1, 1, 1) }
            o.tightenFrom(c.readNanos(), seconds(1200).toNanos()); denied(kind) { run.deadline.requireTestAuthority(o) }
            assertEquals(cancel, authority.fence.isCancelled())
        }
        val c = ChatGptDeadlineClock.controlled(); val o = original(c); c.advanceNanos(seconds(1200).toNanos())
        denied(ModelFailureKind.TIMEOUT) { admission(o) }
    }
    @Test fun newestCheckWrongAccountRetryOneRunAndOneActualLedger() {
        val f = V2Fixture(); val o = original(ChatGptDeadlineClock.controlled()); val a = admission(o, f)
        val old = check(a, f); val current = check(a, f); denied { a.bind(old, f.binding) }
        val wrong = AccountBindingV2(UUID(9, 9), f.binding.issuer, f.binding.hostId, f.binding.issuedClient, f.binding.verifiedSubjectCommitment, 1, f.binding.modelSlug)
        denied { a.bind(current, wrong) }
        val run = a.bind(current, f.binding); val ledger = AttemptLedgerV2(run)
        assertSame(run, ledger.run); denied { AttemptLedgerV2(run) }
        denied { check(a, f) }; denied { a.bind(old, f.binding) }; denied { a.bind(current, f.binding) }
        val forged = AdmittedModelRunV2.mint(current, f.binding); denied { AttemptLedgerV2(forged) }
        o.cancel(); denied { check(a, f) }; denied { AttemptLedgerV2(run) }
    }
    @Test fun registryCaughtCheckAndBindReentryPoisonThenRecoverSameOriginal() {
        for (bind in listOf(false, true)) {
            val f = V2Fixture(); val c = ChatGptDeadlineClock.controlled(); val o = original(c)
            lateinit var a: ModelRunAdmissionV2; lateinit var prior: CheckedAdmissionV2
            var nested = false; var reads = 0
            a = admission(o, f) {
                reads++; noLocks(a)
                if (nested) {
                    nested = false // keep a faulty nested admission finite for the paired mutant
                    try { denied { if (bind) a.bind(prior, f.binding) else check(a, f) } } finally { nested = true }
                }
                f.definitions
            }
            prior = check(a, f); nested = true
            denied { check(a, f) }; assertEquals(2, reads)
            nested = false; val good = check(a, f); assertEquals(3, reads)
            assertNotNull(AttemptLedgerV2(a.bind(good, f.binding)))
            denied { admission(o, f) }
        }
    }
    @Test fun arbitraryThrowableClearsOwnTokenWithoutReleasingOriginalOwner() {
        val c = ChatGptDeadlineClock.controlled(); val o = original(c); val f = V2Fixture(); var throws = true
        val marker = AssertionError("synthetic")
        val a = admission(o, f) { if (throws) { c.advanceNanos(seconds(90).toNanos()); throw marker }; f.definitions }
        assertSame(marker, assertFailsWith<AssertionError> { check(a, f) }); denied { admission(o, f) }
        throws = false; val run = a.bind(check(a, f), f.binding)
        assertEquals(seconds(1110).toNanos(), run.deadline.remainingNanos()); assertNotNull(AttemptLedgerV2(run))
    }
    @Test fun competingRegistryMutationNeverWaitsAndPoisonsOuterUntilFinally() {
        for (bind in listOf(false, true)) {
            val f = V2Fixture(); val o = original(ChatGptDeadlineClock.controlled()); var block = false
            val entered = CountDownLatch(1); val release = CountDownLatch(1); val result = AtomicReference<Throwable?>()
            lateinit var a: ModelRunAdmissionV2
            a = admission(o, f) { noLocks(a); if (block) { entered.countDown(); await(release) }; f.definitions }
            val previous = check(a, f); block = true
            val outer = Thread { try { check(a, f); result.set(AssertionError("stale check escaped")) } catch (t: Throwable) { result.set(t) } }
            outer.start()
            try {
                await(entered)
                denied { if (bind) a.bind(previous, f.binding) else check(a, f) }
                // A second contender cannot replace the poisoned token before its owner finally.
                denied { check(a, f) }
            } finally { release.countDown(); join(outer) }
            assertEquals(ModelFailureKind.INVALID_REQUEST, (result.get() as ModelProviderException).kind)
            block = false; assertNotNull(AttemptLedgerV2(a.bind(check(a, f), f.binding)))
        }
    }
    @Test fun blockedCallbackCancelOrTightenSurvivesThrowAndPreventsPublication() {
        for (cancel in listOf(false, true)) for (throws in listOf(false, true)) {
            val f = V2Fixture(); val c = ChatGptDeadlineClock.controlled(); val o = original(c, 100)
            val entry = c.readNanos(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
            var blocking = true; val result = AtomicReference<Throwable?>(); val marker = AssertionError("callback")
            val a = admission(o, f) { if (blocking) { entered.countDown(); await(release); if (throws) throw marker }; f.definitions }
            val t = Thread { try { check(a, f); result.set(AssertionError("late check")) } catch (e: Throwable) { result.set(e) } }
            t.start()
            try {
                await(entered); c.advanceNanos(seconds(90).toNanos())
                if (cancel) o.cancel() else { o.tightenFrom(entry, seconds(90).toNanos()); o.tightenFrom(c.readNanos(), seconds(1200).toNanos()) }
            } finally { release.countDown(); join(t) }
            val kind = if (cancel) ModelFailureKind.CANCELLED else ModelFailureKind.TIMEOUT
            if (throws) assertSame(marker, result.get()) else assertEquals(kind, (result.get() as ModelProviderException).kind)
            blocking = false; denied(kind) { check(a, f) }
        }
    }
    @Test fun legacyClockAndCancellationBindReentryRunsNoNestedCallback() {
        for (viaClock in listOf(false, true)) {
            val f = V2Fixture(); lateinit var a: ModelRunAdmissionV2; lateinit var checked: CheckedAdmissionV2
            var reenter = false; var clocks = 0; var cancels = 0
            fun callback() { noLocks(a); if (reenter) denied { a.bind(checked, f.binding) } }
            a = ModelRunAdmissionV2({ noLocks(a); f.definitions }, f.commitments,
                NanoClockV2 { clocks++; if (viaClock) callback(); 0 }, seconds(1200).toNanos(),
                AgentCancellation { cancels++; if (!viaClock) callback(); false })
            checked = check(a, f); val before = clocks to cancels; reenter = true
            denied { a.bind(checked, f.binding) }
            assertEquals(before.first + 1, clocks); assertEquals(before.second + 1, cancels)
            reenter = false; val run = a.bind(checked, f.binding); assertNotNull(AttemptLedgerV2(run))
        }
    }
    @Test fun blockedLegacyBindRejectsCompetingBindAndLedgerClaimPoisonsCheck() {
        val f = V2Fixture(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        var block = false; val outcome = AtomicReference<Throwable?>()
        val a = ModelRunAdmissionV2({ f.definitions }, f.commitments, NanoClockV2 { if (block) { entered.countDown(); await(release) }; 0 }, seconds(1200).toNanos())
        val checked = check(a, f); block = true
        val t = Thread { try { a.bind(checked, f.binding); outcome.set(AssertionError("stale run")) } catch (e: Throwable) { outcome.set(e) } }
        t.start()
        try { await(entered); denied { a.bind(checked, f.binding) } } finally { release.countDown(); join(t) }
        assertEquals(ModelFailureKind.INVALID_REQUEST, (outcome.get() as ModelProviderException).kind)
        block = false; assertNotNull(AttemptLedgerV2(a.bind(checked, f.binding)))
        lateinit var other: ModelRunAdmissionV2; lateinit var run: AdmittedModelRunV2; var claim = false
        other = ModelRunAdmissionV2({ if (claim) denied { AttemptLedgerV2(run) }; f.definitions }, f.commitments, NanoClockV2 { 0 }, seconds(1200).toNanos())
        run = other.bind(check(other, f), f.binding); claim = true
        denied { check(other, f) }; claim = false
        assertNotNull(AttemptLedgerV2(run)); denied { AttemptLedgerV2(run) }
    }
    @Test fun fallibleBindCandidateRunsOutsideLockAndFinalFenceOrTokenWins() {
        // JCA is a real fallible candidate-building seam. It must finish before commit;
        // this test provider never supplies deadline time or production authority.
        for (mode in listOf("positive", "cancel", "tighten", "reenter", "throw")) {
            val c = ChatGptDeadlineClock.controlled(); val o = original(c); val f = V2Fixture(); val a = admission(o, f)
            val checked = check(a, f); var armed = true; var hits = 0; val owner = Thread.currentThread()
            val marker = AssertionError("digest candidate")
            val base = java.security.Security.getProviders("MessageDigest.SHA-256").first()
            val provider = object : java.security.Provider("OriginalDeadlineTestDigest", "1.0", "inert candidate control") {
                init {
                    putService(object : Service(this, "MessageDigest", "SHA-256", "test-only", null, null) {
                        override fun newInstance(parameter: Any?): Any = object : java.security.MessageDigestSpi() {
                            private val delegate = java.security.MessageDigest.getInstance("SHA-256", base)
                            override fun engineUpdate(b: Byte) = delegate.update(b)
                            override fun engineUpdate(b: ByteArray, offset: Int, length: Int) = delegate.update(b, offset, length)
                            override fun engineReset() = delegate.reset()
                            override fun engineDigest(): ByteArray {
                                if (Thread.currentThread() === owner && armed) {
                                    armed = false; hits++; noLocks(a)
                                    when (mode) {
                                        "cancel" -> o.cancel()
                                        "tighten" -> o.tightenFrom(c.readNanos(), 0)
                                        "reenter" -> denied { a.bind(checked, f.binding) }
                                        "throw" -> throw marker
                                    }
                                }
                                return delegate.digest()
                            }
                        }
                    })
                }
            }
            assertEquals(1, java.security.Security.insertProviderAt(provider, 1))
            try {
                when (mode) {
                    "positive" -> assertNotNull(AttemptLedgerV2(a.bind(checked, f.binding)))
                    "cancel" -> denied(ModelFailureKind.CANCELLED) { a.bind(checked, f.binding) }
                    "tighten" -> denied(ModelFailureKind.TIMEOUT) { a.bind(checked, f.binding) }
                    "reenter" -> denied { a.bind(checked, f.binding) }
                    "throw" -> assertSame(marker, assertFailsWith<AssertionError> { a.bind(checked, f.binding) })
                }
                assertEquals(1, hits)
                if (mode == "throw" || mode == "reenter") assertNotNull(AttemptLedgerV2(a.bind(checked, f.binding)))
            } finally { java.security.Security.removeProvider(provider.name) }
        }
    }
    @Test fun simultaneousTrustedBindsNeverCreateTwoAccountingLedgers() {
        repeat(12) {
            val f = V2Fixture(); val a = admission(original(ChatGptDeadlineClock.controlled()), f); val checked = check(a, f)
            val start = CountDownLatch(1); val runs = java.util.concurrent.ConcurrentLinkedQueue<AdmittedModelRunV2>()
            val failures = java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
            val threads = List(2) { Thread { await(start); try { runs.add(a.bind(checked, f.binding)) } catch (t: Throwable) { failures.add(t) } } }
            threads.forEach { it.start() }; start.countDown(); threads.forEach { join(it) }
            assertTrue(runs.size <= 1); assertEquals(2, runs.size + failures.size)
            failures.forEach { assertEquals(ModelFailureKind.INVALID_REQUEST, (it as ModelProviderException).kind) }
            val run = runs.singleOrNull() ?: a.bind(checked, f.binding)
            assertNotNull(AttemptLedgerV2(run)); denied { AttemptLedgerV2(run) }; denied { check(a, f) }
        }
    }

    @Test fun lateReadRetainsActualAccountingAfterCancelOrTightenWithoutCopy() {
        for (cancel in listOf(false, true)) {
            val c = ChatGptDeadlineClock.controlled(); val o = original(c); val f = V2Fixture(); val a = admission(o, f)
            val run = a.bind(check(a, f), f.binding); val ledger = AttemptLedgerV2(run)
            val lease = ledger.reserve(UUID(90, 1), 1, 1, 10); ledger.markDispatchIntent(lease, 1)
            val call = ledger.call(lease, byteArrayOf(1)); val authority = run.deadline.requireTestAuthority(o)
            val entered = CountDownLatch(1); val release = CountDownLatch(1)
            val header = ByteArrayInputStream("HTTP/1.1 200 OK\r\nContent-Length:5\r\n\r\n".toByteArray())
            val input = object : java.io.InputStream() {
                override fun read(): Int = error("no scalar helper")
                override fun read(bytes: ByteArray, off: Int, len: Int): Int {
                    if (header.available() > 0) return header.read(bytes, off, minOf(1, len))
                    entered.countDown(); await(release)
                    "hello".toByteArray().copyInto(bytes, off); return 5
                }
            }
            val op = ChatGptPlanTransportLifetimeV1.reserve(PlanHttpTestContextV1(authority.deadline, authority.fence, 100, 100),
                PlanHttpTestGateV1 {}) { life, arena ->
                val acquire: () -> Unit = {
                    life.own(0, Closeable {})
                    life.install(ChatGptPlanHttp1FramingV1(input, arena, PlanHttpEndpointV1.RESPONSES, 100,
                        { life.action(PlanHttpActionV1.READ) }, life::observed, life::framed))
                }
                acquire
            }
            try {
                eventual { op.headers(25_000_000) is PlanHttpHeaderStepV1.Ready }
                val buffer = ByteArray(5) { 7 }; assertEquals(0, op.read(buffer, 5, 0)); await(entered)
                if (cancel) o.cancel() else o.tightenFrom(c.readNanos(), 0)
                eventual { op.transfer().failure }; assertTrue(op.transfer().retained)
                assertTrue(ledger.observations().isEmpty()) // no immutable terminal before late reads/ACK
                release.countDown(); eventual { !op.transfer().retained }
                assertEquals(5, op.transfer().entityBytesObserved); assertEquals(0, op.transfer().entityBytesCopiedToOwner)
                assertContentEquals(ByteArray(5) { 7 }, buffer)
                assertFailsWith<PlanHttpBoundaryV1> { op.read(buffer, 5, 0) }
                val kind = if (cancel) ModelFailureKind.CANCELLED else ModelFailureKind.TIMEOUT
                val totals = ObservedLocalCountersV2(wireBytes = op.transfer().entityBytesObserved)
                denied(kind) { call.meter.beforeDelivery(totals) }
                assertEquals(5, ledger.counters().wire)
                val terminal = ledger.markAmbiguous(lease, kind)
                assertEquals(totals, terminal.local); assertSame(terminal, ledger.markAmbiguous(lease, kind))
                assertEquals(1, ledger.observations().size); assertEquals(5, ledger.counters().wire)
                denied(kind) { ledger.reserve(UUID(90, 2), 2, 1, 1) }
                println("ORIGINAL_LATE cancel=$cancel observed=${op.transfer().entityBytesObserved} copied=${op.transfer().entityBytesCopiedToOwner} charged=${ledger.counters().wire}")
            } finally { release.countDown(); op.requestClose(); eventual { !op.transfer().retained } }
        }
    }

    /** In-memory parser and Closeable exercise the existing lower TEST reserve path; no sockets. */
    private fun lower(authority: ModelRunDeadlineAuthorityV2, entered: CountDownLatch, release: CountDownLatch): ChatGptPlanTransportLifetimeV1 {
        val context = PlanHttpTestContextV1(authority.deadline, authority.fence, 100, 100)
        return ChatGptPlanTransportLifetimeV1.reserve(context, PlanHttpTestGateV1 {}) { op, arena ->
            val acquire: () -> Unit = {
                op.own(0, Closeable { entered.countDown(); await(release) })
                op.install(ChatGptPlanHttp1FramingV1(ByteArrayInputStream("HTTP/1.1 200 OK\r\nContent-Length:0\r\n\r\n".toByteArray()),
                    arena, PlanHttpEndpointV1.RESPONSES, 100, { op.action(PlanHttpActionV1.READ) }, op::observed, op::framed))
            }
            acquire
        }
    }
    @Test fun boundedAsynchronousPhysicalSettlementUsesActualATestAuthority() {
        for (mode in listOf("positive", "cancel", "expire", "first-zero", "stop-expire")) {
            val c = ChatGptDeadlineClock.controlled(); val o = original(c); val f = V2Fixture(); val a = admission(o, f)
            val run = a.bind(check(a, f), f.binding); val ledger = AttemptLedgerV2(run)
            val entered = CountDownLatch(1); val release = CountDownLatch(1)
            val op = lower(run.deadline.requireTestAuthority(o), entered, release)
            var closer: Thread? = null
            try {
                eventual { op.headers(25_000_000L) is PlanHttpHeaderStepV1.Ready }
                var read = 0; eventual { read = op.read(ByteArray(1), 1, 25_000_000); read != 0 }; assertEquals(-1, read)
                op.finish(); await(entered); assertTrue(op.transfer().retained)
                assertEquals(1, ChatGptPlanTransportLifetimeV1.processFacts()[0])
                when (mode) {
                    "cancel" -> o.cancel()
                    "expire" -> o.tightenFrom(c.readNanos(), 0)
                    "first-zero" -> assertEquals(PlanHttpCloseV1.RETAINED, op.closeStep(0))
                    "stop-expire" -> c.advanceNanos(250_000_000)
                }
                if (mode == "positive") {
                    closer = Thread { Thread.sleep(15); release.countDown() }.also { it.start() }
                    assertEquals(PlanHttpCloseV1.SUCCEEDED, op.closeStep(200_000_000))
                    assertTrue(op.waitFacts().first > 0)
                } else {
                    val waits = op.waitFacts().first
                    assertEquals(PlanHttpCloseV1.RETAINED, op.closeStep(100_000_000))
                    if (mode != "cancel") assertEquals(waits, op.waitFacts().first)
                    release.countDown(); eventual { !op.transfer().retained }
                    assertEquals(PlanHttpCloseV1.FAILED, op.closeStep(200_000_000))
                }
                assertFalse(op.transfer().retained); assertTrue(op.transfer().ioTasksExited >= 3); assertTrue(op.transfer().stopTasksExited >= 1)
                assertEquals(0, ChatGptPlanTransportLifetimeV1.processFacts()[0]); assertSame(run, ledger.run)
                println("ORIGINAL_LOWER mode=$mode transfer=${op.transfer()} waits=${op.waitSamples()}")
            } finally { release.countDown(); closer?.let { join(it) }; op.requestClose(); eventual { !op.transfer().retained } }
        }
    }
}
