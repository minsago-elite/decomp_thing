package decompengine.builtin.provider

import decompengine.builtin.*
import decompengine.chatgpt.ChatGptDeadline
import decompengine.chatgpt.ChatGptDeadlineClock
import decompengine.chatgpt.ChatGptOperationFence
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Tag
import java.io.*
import java.net.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.*
import kotlin.test.*

internal fun c4await(predicate: () -> Boolean) {
    val end = System.nanoTime() + 3_000_000_000L
    while (!predicate()) { if (System.nanoTime() - end >= 0) fail("bounded fixture wait failed"); Thread.sleep(1) }
}
internal fun c4context(clock: ChatGptDeadlineClock = ChatGptDeadlineClock.SYSTEM, span: Long = 5_000_000_000L,
    cap: Long = 100000, request: Int = 100000, idle: Long = 5_000_000_000L) =
    PlanHttpTestContextV1(ChatGptDeadline.start(clock, span), ChatGptOperationFence(), cap, request, idle)
internal class C4Latch {
    private val entered = CountDownLatch(1)
    private val release = CountDownLatch(1)
    fun block() { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) }
    fun await() { check(entered.await(3, TimeUnit.SECONDS)) }
    fun open() { release.countDown() }
}
internal class C4Input(body: String = "hello", val length: Boolean = true) : InputStream() {
    private val header = ByteArrayInputStream(("HTTP/1.1 200 OK\r\n" + if (length) "Content-Length:${body.length}\r\n\r\n" else "\r\n").toByteArray())
    private val entity = ByteArrayInputStream(body.toByteArray())
    var barrier: C4Latch? = null
    val entityReads = AtomicInteger()
    override fun read(): Int = error("unexpected scalar read")
    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (header.available() > 0) return header.read(b, off, minOf(1, len))
        entityReads.incrementAndGet(); barrier?.block()
        return entity.read(b, off, len)
    }
}
internal class C4Tls(val source: InputStream, val sink: OutputStream = ByteArrayOutputStream()) : SSLSocket() {
    var closing: C4Latch? = null
    var closeThrows = false
    val closes = AtomicInteger()
    var handshakeFailure = false
    var negotiated = "http/1.1"
    private var parameters = SSLParameters()
    var selected = emptyArray<String>()
    override fun close() { closing?.block(); closes.incrementAndGet(); if (closeThrows) throw IOException("synthetic close") }
    override fun getInputStream() = source
    override fun getOutputStream() = sink
    override fun setSoTimeout(timeout: Int) { check(timeout > 0) }
    override fun startHandshake() { if (handshakeFailure) throw SSLHandshakeException("synthetic") }
    override fun getApplicationProtocol() = negotiated
    override fun setSSLParameters(p: SSLParameters) { parameters = p }
    override fun getSSLParameters() = parameters
    override fun getSupportedCipherSuites() = emptyArray<String>()
    override fun getEnabledCipherSuites() = emptyArray<String>()
    override fun setEnabledCipherSuites(v: Array<out String>?) {}
    override fun getSupportedProtocols() = arrayOf("TLSv1.2", "TLSv1.3")
    override fun getEnabledProtocols() = selected
    override fun setEnabledProtocols(v: Array<out String>) { selected = v.map { it }.toTypedArray() }
    override fun getSession(): SSLSession = throw UnsupportedOperationException()
    override fun addHandshakeCompletedListener(l: HandshakeCompletedListener?) {}
    override fun removeHandshakeCompletedListener(l: HandshakeCompletedListener?) {}
    override fun setUseClientMode(b: Boolean) { check(b) }
    override fun getUseClientMode() = true
    override fun setNeedClientAuth(b: Boolean) {}
    override fun getNeedClientAuth() = false
    override fun setWantClientAuth(b: Boolean) {}
    override fun getWantClientAuth() = false
    override fun setEnableSessionCreation(b: Boolean) {}
    override fun getEnableSessionCreation() = true
}
internal class C4Connector(val input: InputStream = C4Input(), output: OutputStream = ByteArrayOutputStream()) : PlanHttpTestConnectorV1 {
    val tls = C4Tls(input, output)
    val resolves = AtomicInteger(); val rawCloses = AtomicInteger(); val connects = AtomicInteger()
    var dns: C4Latch? = null; var wrapping: C4Latch? = null; var rawCreation: C4Latch? = null
    var address = InetAddress.getLoopbackAddress()
    override val loopbackPort = 1
    override fun resolveLoopback(): InetAddress { resolves.incrementAndGet(); dns?.block(); return address }
    override fun rawSocket(): Socket {
        rawCreation?.block()
        return object : Socket() {
            override fun connect(endpoint: SocketAddress?, timeout: Int) { check(timeout > 0); connects.incrementAndGet() }
            override fun close() { rawCloses.incrementAndGet() }
        }
    }
    override fun wrapForTest(raw: Socket): SSLSocket { wrapping?.block(); return tls }
}
internal fun c4start(c: C4Connector = C4Connector(), ctx: PlanHttpTestContextV1 = c4context(),
    gate: PlanHttpTestGateV1 = PlanHttpTestGateV1 {}) = ChatGptPlanSocketHttpV1.startForTest(ctx,
    PlanHttpEndpointV1.RESPONSES, "synthetic-test-token", byteArrayOf(123, 125), c, gate)
internal fun c4headers(op: ChatGptPlanTransportLifetimeV1): PlanHttpHeadersV1 {
    var h: PlanHttpHeadersV1? = null
    c4await { h = (op.headers(25_000_000) as? PlanHttpHeaderStepV1.Ready)?.headers; h != null }
    return h!!
}
internal fun c4read(op: ChatGptPlanTransportLifetimeV1, into: ByteArray, demand: Int = into.size): Int {
    var n = 0; c4await { n = op.read(into, demand, 25_000_000); n != 0 }; return n
}
internal fun c4release(op: ChatGptPlanTransportLifetimeV1) { op.requestClose(); c4await { !op.transfer().retained } }

internal class ChatGptPlanTransportLifetimeV1Test {
    @Test fun pendingReadAllowsCallerReuseAndOneSuccessfulCopyThenExactEof() {
        val input = C4Input(); val barrier = C4Latch(); input.barrier = barrier
        val c = C4Connector(input); val op = c4start(c)
        try {
            c4headers(op); val buffer = ByteArray(5)
            assertEquals(0, op.read(buffer, 5, 0)); barrier.await()
            buffer.fill(88); repeat(20) { assertEquals(0, op.read(buffer, 5, 0)); assertContentEquals(ByteArray(5) { 88 }, buffer) }
            assertEquals(1, input.entityReads.get()); barrier.open()
            assertEquals(5, c4read(op, buffer)); assertEquals("hello", String(buffer))
            assertEquals(5, op.transfer().entityBytesObserved); assertEquals(5, op.transfer().entityBytesCopiedToOwner)
            assertEquals(-1, c4read(op, buffer)); assertEquals(1, input.entityReads.get())
            op.finish(); assertEquals(PlanHttpCloseV1.SUCCEEDED, op.closeStep(200_000_000))
            assertEquals(1, c.rawCloses.get()); assertEquals(1, c.tls.closes.get())
        } finally { barrier.open(); c4release(op) }
    }
    @Test fun changedPendingDemandPermanentlyStopsAndRetainsLateAccounting() {
        val input = C4Input(); val barrier = C4Latch(); input.barrier = barrier
        val op = c4start(C4Connector(input))
        try {
            c4headers(op); val buffer = ByteArray(5) { 77 }
            op.read(buffer, 5, 0); barrier.await()
            assertFailsWith<PlanHttpBoundaryV1> { op.read(buffer, 4, 0) }
            barrier.open(); c4await { !op.transfer().retained }
            assertEquals(5, op.transfer().entityBytesObserved); assertEquals(0, op.transfer().entityBytesCopiedToOwner)
            assertContentEquals(ByteArray(5) { 77 }, buffer); assertEquals(PlanHttpCloseV1.FAILED, op.closeStep(1))
        } finally { barrier.open(); c4release(op) }
    }
    @Test fun cancelledLateReadCountsBeforeVetoAndCannotResumeAcrossGap() {
        val input = C4Input(); val barrier = C4Latch(); input.barrier = barrier
        val op = c4start(C4Connector(input))
        try {
            c4headers(op); val buffer = ByteArray(5) { 7 }; op.read(buffer, 5, 0); barrier.await()
            op.cancel(); assertEquals(PlanHttpCloseV1.RETAINED, op.closeStep(0)); barrier.open()
            c4await { !op.transfer().retained }
            assertEquals(5, op.transfer().entityBytesObserved); assertEquals(0, op.transfer().entityBytesCopiedToOwner)
            assertFailsWith<PlanHttpBoundaryV1> { op.read(buffer, 5, 0) }
            assertContentEquals(ByteArray(5) { 7 }, buffer)
        } finally { barrier.open(); c4release(op) }
    }
    @Test fun delayedPhysicalCloseBeforeOriginalCutoffSucceedsAndSlotIsReusable() {
        val c = C4Connector(C4Input("")); val barrier = C4Latch(); c.tls.closing = barrier
        val op = c4start(c)
        val release = Thread { barrier.await(); Thread.sleep(15); barrier.open() }
        try {
            c4headers(op); assertEquals(-1, c4read(op, ByteArray(1))); op.finish()
            release.start(); assertEquals(PlanHttpCloseV1.SUCCEEDED, op.closeStep(200_000_000)); release.join(3000)
            assertFalse(release.isAlive); assertFalse(op.transfer().retained)
            assertTrue(op.transfer().ioTasksExited >= 3); assertTrue(op.transfer().stopTasksExited >= 1)
            val next = c4start(); c4headers(next); c4release(next)
            for (sample in op.waitSamples()) {
                assertTrue(sample[1] in 1..25_000_000L)
                assertTrue(sample[1] <= minOf(sample[2], sample[3], sample[4]))
            }
            println("C4A_WAIT_ADMISSIONS " + op.waitSamples())
            println("C4A_SETTLED io=${op.transfer().ioTasksExited} stop=${op.transfer().stopTasksExited} waits=${op.waitFacts()}")
        } finally { barrier.open(); if (release.isAlive) release.join(3000); c4release(op) }
    }
    @Test fun firstZeroAndOriginalExpiryNeverReviveAfterPhysicalAck() {
        for (zero in listOf(true, false)) {
            val clock = ChatGptDeadlineClock.controlled(); val ctx = c4context(clock, 1_000_000_000)
            val c = C4Connector(C4Input("")); val barrier = C4Latch(); c.tls.closing = barrier
            val op = c4start(c, ctx)
            try {
                c4headers(op); assertEquals(-1, c4read(op, ByteArray(1)))
                if (zero) {
                    assertEquals(PlanHttpCloseV1.RETAINED, op.closeStep(0))
                    val before = op.waitFacts().first
                    assertEquals(PlanHttpCloseV1.RETAINED, op.closeStep(100_000_000))
                    assertEquals(before, op.waitFacts().first)
                }
                else { op.finish(); barrier.await(); clock.advanceNanos(1_000_000_000); assertEquals(PlanHttpCloseV1.RETAINED, op.closeStep(100_000_000)) }
                barrier.open(); c4await { !op.transfer().retained }
                assertEquals(PlanHttpCloseV1.FAILED, op.closeStep(200_000_000))
            } finally { barrier.open(); c4release(op) }
        }
    }
    @Test fun initializationRawAndTlsReturnedAfterStopJoinSameReservedSlot() {
        for (stage in 0..2) {
            val c = C4Connector(); val barrier = C4Latch()
            when (stage) { 0 -> c.dns = barrier; 1 -> c.rawCreation = barrier; else -> c.wrapping = barrier }
            val op = c4start(c)
            try {
                barrier.await(); op.cancel(); assertEquals(PlanHttpCloseV1.RETAINED, op.closeStep(0))
                barrier.open(); c4await { !op.transfer().retained }
                assertEquals(if (stage >= 1) 1 else 0, c.rawCloses.get())
                assertEquals(if (stage == 2) 1 else 0, c.tls.closes.get())
                assertFalse(op.transfer().headerPossiblySent)
            } finally { barrier.open(); c4release(op) }
        }
    }
    @Test fun eightRetainedAcquisitionsRefuseNinthBeforeAnyConnectorWork() {
        val barriers = List(8) { C4Latch() }; val connectors = barriers.map { C4Connector().also { c -> c.dns = it } }
        val ops = ArrayList<ChatGptPlanTransportLifetimeV1>()
        try {
            connectors.forEach { ops.add(c4start(it)) }; barriers.forEach { it.await() }
            ops.forEach { it.cancel() }
            val ninth = C4Connector()
            assertFailsWith<PlanHttpBoundaryV1> { c4start(ninth) }; assertEquals(0, ninth.resolves.get())
            val facts = ChatGptPlanTransportLifetimeV1.processFacts(); assertEquals(8, facts[0]); assertEquals(8, facts[1]); assertEquals(17, facts[2])
            println("C4A_PROCESS retained=${facts[0]} high=${facts[1]} lanes=${facts[2]} activeIo=${facts[3]} activeStop=${facts[4]} queuedIo=${facts[5]} queuedStop=${facts[6]}")
        } finally { barriers.forEach { it.open() }; ops.forEach { c4release(it) } }
        assertEquals(0, ChatGptPlanTransportLifetimeV1.processFacts()[0])
        val next = c4start(); c4headers(next); c4release(next)
    }
    @Test fun blockedStoppersDoNotOccupyIoOrOtherStopperOrTimerLanes() {
        val barriers = List(8) { C4Latch() }; val ops = ArrayList<ChatGptPlanTransportLifetimeV1>()
        try {
            for (i in 0..7) {
                val c = C4Connector(C4Input("")); c.tls.closing = barriers[i]
                val op = c4start(c); ops.add(op); c4headers(op); op.requestClose()
            }
            barriers.forEach { it.await() }
            val f = ChatGptPlanTransportLifetimeV1.processFacts(); assertEquals(8, f[4]); assertEquals(0, f[3])
            assertFailsWith<PlanHttpBoundaryV1> { c4start() }
            barriers[0].open(); c4await { !ops[0].transfer().retained }
            val clock = ChatGptDeadlineClock.controlled(); val c = C4Connector(); val dns = C4Latch(); c.dns = dns
            val next = c4start(c, c4context(clock, 100_000_000))
            try { dns.await(); clock.advanceNanos(100_000_000); c4await { next.transfer().failure }; assertTrue(next.transfer().retained) }
            finally { dns.open(); c4release(next) }
        } finally { barriers.forEach { it.open() }; ops.forEach { c4release(it) } }
    }
    @Test fun gateCancelReentryAndSubMillisecondAuthorityAdmitNoIo() {
        val ctx = c4context(); val c = C4Connector()
        val op = c4start(c, ctx, PlanHttpTestGateV1 { ctx.fence.cancel() })
        c4release(op); assertEquals(0, c.resolves.get())
        val controlled = ChatGptDeadlineClock.controlled(); val tiny = c4context(controlled, 999999)
        val second = C4Connector(); val o = c4start(second, tiny)
        c4await { o.transfer().failure }; c4release(o); assertEquals(0, second.connects.get())
    }
    @Test fun incompleteKnownLengthCandidateRejectedUnknownTerminalMayCloseUnreadSuffix() {
        val known = c4start(C4Connector(C4Input("xy")))
        try { c4headers(known); c4read(known, ByteArray(1)); assertFailsWith<PlanHttpBoundaryV1> { known.finish(true) } }
        finally { c4release(known) }
        val source = ByteArrayInputStream("HTTP/1.1 200 OK\r\nTransfer-Encoding:chunked\r\n\r\n1\r\nxUNREAD".toByteArray())
        val unknown = c4start(C4Connector(source))
        try { c4headers(unknown); assertEquals(1, c4read(unknown, ByteArray(1))); unknown.finish(true)
            assertEquals(PlanHttpCloseV1.SUCCEEDED, unknown.closeStep(200_000_000)); assertEquals(6, source.available()) }
        finally { c4release(unknown) }
    }
    @Test fun actualC2AndLedgerObserveWireOnceAndSettleAfterPhysicalAck() {
        val f = C2Fixture()
        val item = C2Fixture.message("hello")
        val wire = listOf(
            f.event("response.created", "\"response\":${C2Fixture.envelope("in_progress")}"),
            f.event("response.output_item.added", "\"output_index\":0,\"item\":$item"),
            f.event("response.output_item.done", "\"output_index\":0,\"item\":$item"),
            f.event("response.completed", "\"response\":${C2Fixture.envelope("completed", listOf(item))}")
        ).joinToString("") { "data: $it\n\n" }
        val c = C4Connector(C4Input(wire)); val op = c4start(c)
        try {
            c4headers(op); val buffer = ByteArray(8192)
            while (f.session.terminalResult() == null) {
                val n = c4read(op, buffer, f.session.readDemand())
                assertTrue(n > 0)
                f.call.meter.beforeDelivery(f.session.observed().copy(wireBytes = op.transfer().entityBytesObserved))
                f.session.feed(buffer, 0, n)
                assertEquals(op.transfer().entityBytesObserved, f.ledger.counters().wire)
            }
            op.finish(true); assertEquals(PlanHttpCloseV1.SUCCEEDED, op.closeStep(200_000_000))
            val result = f.session.terminalResult()!!
            val final = result.local.copy(wireBytes = op.transfer().entityBytesObserved)
            f.call.meter.beforeDelivery(final)
            val settled = f.ledger.settle(f.lease, final, result.reported, result.outcome)
            assertSame(settled, f.ledger.settle(f.lease, final, result.reported, result.outcome))
            assertEquals(1, f.ledger.observations().size)
            assertEquals(wire.toByteArray().size.toLong(), f.ledger.counters().wire)
            assertEquals(wire.toByteArray().size.toLong(), f.session.observed().wireBytes)
            assertEquals("hello", f.text())
            println("C4A_LEDGER observed=${op.transfer().entityBytesObserved} copied=${op.transfer().entityBytesCopiedToOwner} c2=${f.session.observed().wireBytes} wire=${f.ledger.counters().wire} settlements=${f.ledger.observations().size}")
        } finally { c4release(op) }
    }
    @Test fun lateObservedBytesSurviveActualMeterThrowAndOneAmbiguousSettlement() {
        for (overdraw in listOf(false, true)) {
            val f = C2Fixture()
            val source = C4Input(); val barrier = C4Latch(); source.barrier = barrier
            val op = c4start(C4Connector(source))
            try {
                c4headers(op); op.read(ByteArray(5), 5, 0); barrier.await(); op.cancel(); barrier.open()
                c4await { !op.transfer().retained }
                val totals = f.session.observed().copy(wireBytes = op.transfer().entityBytesObserved)
                if (overdraw) assertFailsWith<ModelProviderException> { f.call.meter.beforeDelivery(totals, f.run.budget.eventBytes + 1) }
                else { f.call.meter.beforeDelivery(totals); f.call.meter.beforeDelivery(totals) }
                assertEquals(5, f.ledger.counters().wire); assertEquals(0, f.session.observed().wireBytes)
                assertEquals(0, op.transfer().entityBytesCopiedToOwner)
                val settled = f.ledger.markAmbiguous(f.lease, ModelFailureKind.TRANSPORT)
                assertSame(settled, f.ledger.markAmbiguous(f.lease, ModelFailureKind.TRANSPORT))
                assertEquals(5, settled.local.wireBytes); assertEquals(1, f.ledger.observations().size)
                assertEquals(f.body.size.toLong(), f.ledger.counters().input)
            } finally { barrier.open(); c4release(op) }
        }
    }
    @Test fun overlappingConsumersLatchFailureAndPendingPollingDoesNotRenewIdle() {
        val source = C4Input(); val barrier = C4Latch(); source.barrier = barrier
        val op = c4start(C4Connector(source)); val completed = CountDownLatch(1)
        val consumer = Thread {
            try { op.read(ByteArray(5), 5, 200_000_000); fail("overlap should stop waiter") }
            catch (_: PlanHttpBoundaryV1) {} finally { completed.countDown() }
        }
        try {
            c4headers(op); consumer.start(); barrier.await()
            assertFailsWith<PlanHttpBoundaryV1> { op.read(ByteArray(5), 5, 0) }
            assertTrue(completed.await(2, TimeUnit.SECONDS)); barrier.open(); consumer.join(2000)
        } finally { barrier.open(); c4release(op); if (consumer.isAlive) consumer.join(2000) }
        val clock = ChatGptDeadlineClock.controlled(); val ctx = c4context(clock, idle = 100_000_000)
        val input = C4Input(); val blocked = C4Latch(); input.barrier = blocked
        val pending = c4start(C4Connector(input), ctx)
        try {
            c4headers(pending); pending.read(ByteArray(5), 5, 0); blocked.await()
            repeat(3) { clock.advanceNanos(25_000_000); assertEquals(0, pending.read(ByteArray(5), 5, 0)) }
            clock.advanceNanos(25_000_000)
            assertFailsWith<PlanHttpBoundaryV1> { pending.read(ByteArray(5), 5, 0) }
            val before = pending.waitFacts().first
            pending.closeStep(200_000_000) // root remains, but first stop window is bounded
            ctx.deadline.tightenFrom(clock.readNanos(), 0)
            pending.closeStep(200_000_000)
            val afterExpiry = pending.waitFacts().first
            pending.closeStep(200_000_000); assertEquals(afterExpiry, pending.waitFacts().first)
            assertTrue(afterExpiry >= before)
        } finally { blocked.open(); c4release(pending) }
    }

    @Test fun closeFailureStaysStickyUntilActualLaterCloseReturnReleasesSlot() {
        val c = C4Connector(C4Input("")); c.tls.closeThrows = true
        val op = c4start(c)
        try {
            c4headers(op); assertEquals(-1, c4read(op, ByteArray(1))); op.finish()
            c4await { op.transfer().closeFailure }
            assertTrue(op.transfer().retained); assertEquals(PlanHttpCloseV1.RETAINED, op.closeStep(0))
            c.tls.closeThrows = false; op.requestClose(); c4await { !op.transfer().retained }
            assertEquals(PlanHttpCloseV1.FAILED, op.closeStep(200_000_000))
            assertTrue(op.transfer().closeFailure)
        } finally { c.tls.closeThrows = false; c4release(op) }
    }
    @Tag("shutdown")
    @Test fun shutdownUsesOneAllowanceAcrossChildrenAndNeverRecreatesRetainedCapacity() {
        val barriers = List(8) { C4Latch() }; val ops = ArrayList<ChatGptPlanTransportLifetimeV1>()
        try {
            for (b in barriers) {
                val c = C4Connector(C4Input("")); c.tls.closing = b
                val op = c4start(c); ops.add(op); c4headers(op)
            }
            ChatGptPlanTransportLifetimeV1.shutdown()
            barriers.forEach { it.await() }
            assertEquals(8, ChatGptPlanTransportLifetimeV1.processFacts()[0])
            ChatGptPlanTransportLifetimeV1.shutdown()
            val c = C4Connector(); assertFailsWith<PlanHttpBoundaryV1> { c4start(c) }; assertEquals(0, c.resolves.get())
        } finally { barriers.forEach { it.open() }; ops.forEach { c4release(it) } }
        assertEquals(0, ChatGptPlanTransportLifetimeV1.processFacts()[0])
        assertEquals(17, ChatGptPlanTransportLifetimeV1.processFacts()[2]) // idle service lanes are not operation stacks
        assertFailsWith<PlanHttpBoundaryV1> { c4start() }
        println("C4A_SHUTDOWN retained=0 idleServiceLanes=17 noReplacement=true")
    }

    @Test fun everyActionGateRechecksPrivateCancellationAfterCallbackReturn() {
        for (target in PlanHttpActionV1.entries) {
            val ctx = c4context(); val c = C4Connector()
            val op = c4start(c, ctx, PlanHttpTestGateV1 { if (it == target) ctx.fence.cancel() })
            try {
                c4await { op.transfer().failure }; c4release(op)
                val f = op.transfer()
                when (target) {
                    PlanHttpActionV1.ACQUIRE -> assertEquals(0, c.resolves.get())
                    PlanHttpActionV1.HEADER_WRITE -> assertFalse(f.headerPossiblySent)
                    PlanHttpActionV1.BODY_WRITE -> { assertTrue(f.headerPossiblySent); assertEquals(0, f.bodyBytesOffered) }
                    PlanHttpActionV1.READ -> { assertEquals(2, f.bodyBytesReturned); assertEquals(0, f.entityBytesObserved) }
                }
            } finally { c4release(op) }
        }
    }
    @Test fun initializationReservationExistsBeforeArbitraryHelperAndNoInlineClose() {
        val barrier = C4Latch(); val ref = java.util.concurrent.atomic.AtomicReference<ChatGptPlanTransportLifetimeV1?>()
        val helperFinished = CountDownLatch(1)
        val initializer = Thread {
            try {
                ChatGptPlanTransportLifetimeV1.reserve(c4context(), PlanHttpTestGateV1 {}) { op, _ ->
                    ref.set(op); barrier.block()
                    val work: () -> Unit = { fail("stopped initialization cannot dispatch") }
                    work
                }
            } finally { helperFinished.countDown() }
        }
        initializer.start(); barrier.await(); val op = ref.get()!!
        try {
            op.requestClose(); assertEquals(PlanHttpCloseV1.RETAINED, op.closeStep(0))
            assertTrue(op.transfer().retained); assertEquals(1L, helperFinished.count)
        } finally { barrier.open(); initializer.join(3000); c4release(op); assertFalse(initializer.isAlive) }
    }
    @Test fun inputExceptionIsNotCloseDelimitedEofAndCatalogCannotUseSseShortcut() {
        val bytes = ByteArrayInputStream("HTTP/1.1 200 OK\r\n\r\n".toByteArray())
        val input = object : InputStream() {
            override fun read(): Int = error("scalar")
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (bytes.available() > 0) return bytes.read(b, off, len)
                throw javax.net.ssl.SSLException("synthetic truncation")
            }
        }
        val op = c4start(C4Connector(input))
        try { c4headers(op); assertFailsWith<PlanHttpBoundaryV1> { c4read(op, ByteArray(1)) }; assertTrue(op.transfer().failure) }
        finally { c4release(op) }
        val raw = ByteArrayInputStream("HTTP/1.1 200 OK\r\nContent-Type:application/json\r\n\r\n{}".toByteArray())
        val catalog = ChatGptPlanSocketHttpV1.startForTest(c4context(), PlanHttpEndpointV1.MODELS, "synthetic", null, C4Connector(raw))
        try { c4headers(catalog); c4read(catalog, ByteArray(2)); assertFailsWith<PlanHttpBoundaryV1> { catalog.finish(true) } }
        finally { c4release(catalog) }
    }

    @Test fun subMillisecondRemainderAfterEachActionGateAdmitsNoBlockingAction() {
        for (target in PlanHttpActionV1.entries) {
            val clock = ChatGptDeadlineClock.controlled(); val ctx = c4context(clock, span = 10_000_000)
            val c = C4Connector()
            val op = c4start(c, ctx, PlanHttpTestGateV1 { if (it == target) clock.advanceNanos(9_500_000) })
            try {
                c4await { op.transfer().failure }; c4release(op)
                val f = op.transfer()
                when (target) {
                    PlanHttpActionV1.ACQUIRE -> assertEquals(0, c.resolves.get())
                    PlanHttpActionV1.HEADER_WRITE -> assertFalse(f.headerPossiblySent)
                    PlanHttpActionV1.BODY_WRITE -> assertEquals(0, f.bodyBytesOffered)
                    PlanHttpActionV1.READ -> assertEquals(0, f.entityBytesObserved)
                }
            } finally { c4release(op) }
        }
    }

    @Test fun closeMethodEntryAllowanceAgesWhileWaitingToEnterPrivateMonitor() {
        val connector = C4Connector(C4Input("")); val barrier = C4Latch(); connector.tls.closing = barrier
        val op = c4start(connector); c4headers(op)
        val field = ChatGptPlanTransportLifetimeV1::class.java.getDeclaredField("MON")
        field.isAccessible = true
        val monitor = field.get(null) // scheduling adversary only; no authority/state mutation
        val result = java.util.concurrent.atomic.AtomicReference<PlanHttpCloseV1?>()
        val consumer = Thread { result.set(op.closeStep(5_000_000)) }
        val before = op.waitFacts().first
        try {
            synchronized(monitor) {
                consumer.start(); c4await { consumer.state == Thread.State.BLOCKED }
                Thread.sleep(20) // age entry allowance, NOT an elapsed-overshoot assertion
            }
            consumer.join(3000); assertFalse(consumer.isAlive)
            assertEquals(PlanHttpCloseV1.RETAINED, result.get())
            assertEquals(before, op.waitFacts().first)
            barrier.open(); c4await { !op.transfer().retained }
            assertEquals(PlanHttpCloseV1.FAILED, op.closeStep(200_000_000))
        } finally { barrier.open(); c4release(op); if (consumer.isAlive) consumer.join(3000) }
    }

}
