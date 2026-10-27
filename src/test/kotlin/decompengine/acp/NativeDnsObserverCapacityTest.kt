package decompengine.acp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Pure injected data/clock controls. No process, namespace, /proc or resolver access. */
class NativeDnsObserverCapacityTest {
    @Test fun `sixteenth proved foreign observation aggregates with one fatal detail slot reserved`() {
        val rows = mutableListOf<String>(); val state = NativeVisibilityAccumulator(rows)
        repeat(15) { state.record("pid=$it outcome=DISTINCT_CREDENTIALS", true) }
        state.record("pid=17 outcome=DISTINCT_CREDENTIALS", true)
        state.record("pid=17 outcome=DISTINCT_CREDENTIALS", true)
        assertEquals(15, rows.size); assertEquals(2, state.overflowObservations)
        assertTrue(state.render().size <= 16384)
        assertTrue(state.render().toString(Charsets.US_ASCII).contains("scanComplete=false"))
    }
    @Test fun `unknown overflow remains fatal and exact primary identity survives diagnostics`() {
        val state = NativeVisibilityAccumulator()
        repeat(15) { state.record("pid=$it", true) }
        val capacity = assertFailsWith<NativeObserverFailure> { state.record("pid=17 unknown", false) }
        assertEquals("DIAGNOSTIC_CAPACITY", capacity.category)
        val primary = NativeObserverFailure("POSSIBLE_OWNED_VISIBILITY", 17, "net", "OUTER_CLEANUP")
        nativeKeepPrimaryFailure(primary, capacity)
        assertSame(capacity, primary.suppressed.single())
        assertTrue(nativeObserverFailureFields(primary,"primary").contains("primaryObserverPid=17\n"))
        assertEquals("POSSIBLE_OWNED_VISIBILITY",nativeFailureCategory(primary))
        assertEquals(0,state.overflowObservations)
    }
    @Test fun `digest commits framing identity and observation order with fixed state`() {
        fun digest(a: String, b: String): String {
            val s = NativeVisibilityAccumulator(); repeat(15) { s.record("initial=$it",true) }
            s.record(a,true); s.record(b,true); return s.render().toString(Charsets.US_ASCII)
        }
        assertTrue(digest("ab","c").contains("observationDigest=41a3b2f67b62adf8f5bfadba2834a9f059ffc16a9a6dbde740c4469401dd14e0"))
        assertFalse(digest("ab","c") == digest("c","ab"))
        assertFalse(digest("ab","c") == digest("a","bc"))
        val s = NativeVisibilityAccumulator(); repeat(15) { s.record("initial=$it",true) }
        repeat(16384) { s.record("overflow=$it",true) }
        assertTrue(s.render().size<=16384)
        assertFailsWith<IllegalStateException> { s.record("one-over",true) }
        assertEquals(16384,s.overflowObservations)
    }
    @Test fun `work and PID limits reject before a caller can perform one over operation`() {
        val work = NativeObserverBudget(100,{0},maximumWork=2)
        work.operation(); work.operation()
        assertEquals("SCAN_WORK_LIMIT", assertFailsWith<NativeObserverFailure> { work.operation() }.category)
        val pids = NativeObserverBudget(100,{0},maximumPidsPerScan=1,maximumPids=2)
        pids.beginScan(); pids.pid()
        assertFailsWith<NativeObserverFailure> { pids.pid() }
        pids.beginScan(); pids.pid(); pids.beginScan()
        assertFailsWith<NativeObserverFailure> { pids.pid() }
        val scans=NativeObserverBudget(100,{0},maximumScans=1)
        scans.beginScan(); assertFailsWith<NativeObserverFailure> { scans.beginScan() }
    }
    @Test fun `byte budget bounds sentinel allocation and refuses before exhausted read`() {
        val b=NativeObserverBudget(100,{0},maximumBytes=3)
        assertEquals(4,b.readLimit()); b.readCompleted(2); assertEquals(2,b.readLimit())
        b.readCompleted(1)
        assertEquals("PROC_BYTE_LIMIT",assertFailsWith<NativeObserverFailure> { b.readLimit() }.category)
        val over=NativeObserverBudget(100,{0},maximumBytes=3)
        assertFailsWith<NativeObserverFailure> { over.readCompleted(4) }
        assertEquals(4,over.readLimit())
    }
    @Test fun `absolute deadline never resets between scans operations or text completion`() {
        var time=0L;val b=NativeObserverBudget(30,{time})
        b.beginScan();time=29;b.operation();b.beginScan();time=30
        for (operation in listOf<() -> Unit>({b.beginScan()},{b.operation()},{b.pid()},{b.readLimit()},{b.readCompleted(1)})) {
            assertEquals("OBSERVER_DEADLINE",assertFailsWith<NativeObserverFailure> { operation() }.category)
        }
    }
    @Test fun `unstable or unreadable denied identity never becomes proved foreign`() {
        val caller=NativeNamespaceCredentials(listOf(1,1,1,1),listOf(2,2,2,2))
        val foreign=NativeNamespaceCredentials(listOf(3,3,3,3),listOf(4,4,4,4))
        assertFalse(nativeDeniedVisibilityRequiresFailure(caller,nativeStableDeniedCredentials(7,7,foreign)))
        for (identity in listOf(nativeStableDeniedCredentials(7,8,foreign),nativeStableDeniedCredentials(null,7,foreign),
            nativeStableDeniedCredentials(7,null,foreign),nativeStableDeniedCredentials(7,7,null))) {
            assertTrue(nativeDeniedVisibilityRequiresFailure(caller,identity))
        }
    }
    @Test fun `typed primary fields are closed bounded and historical state remains unknown`() {
        assertFailsWith<IllegalArgumentException> { NativeObserverFailure("untrusted\ntext") }
        assertFailsWith<IllegalArgumentException> { NativeObserverFailure("SCAN_WORK_LIMIT",1,"other") }
        assertEquals("",nativeObserverFailureFields(IllegalStateException("untrusted"),"primary"))
        assertEquals("STATE_FAILURE",nativeFailureCategory(IllegalStateException("historical")))
        assertTrue(nativeObserverFailureFields(NativeObserverFailure("SCAN_WORK_LIMIT"),"cleanup").length<256)
    }

    @Test fun `first possible witness survives foreign saturation and later diagnostic failure within sixteen details`() {
        val state=NativeVisibilityAccumulator()
        repeat(15) { state.record("pid=$it outcome=DISTINCT_CREDENTIALS",true) }
        repeat(101) { state.record("pid=999 outcome=DISTINCT_CREDENTIALS",true) }
        val caller=NativeNamespaceCredentials(listOf(1,1,1,1),listOf(2,2,2,2))
        val witness=NativeObserverFailure.Witness(1136,"net","OUTER_CLEANUP",10,caller,null,7,null,
            NativeObserverFailure.ReadStage.STATUS,NativeObserverFailure.ExceptionKind.ACCESS_DENIED)
        val primary=NativeObserverFailure("POSSIBLE_OWNED_VISIBILITY",1136,"net","OUTER_CLEANUP",witness)
        state.recordFirstPossible(witness)
        val capacity=assertFailsWith<NativeObserverFailure> { state.record("unknown extra detail",false) }
        nativeKeepPrimaryFailure(primary,capacity)
        val later=NativeObserverFailure.Witness(1137,"user","HOST_CLEANUP",10,caller,null,null,null,
            NativeObserverFailure.ReadStage.START_BEFORE,NativeObserverFailure.ExceptionKind.NO_SUCH_FILE)
        state.recordFirstPossible(later)
        assertSame(witness,state.firstPossibleWitness);assertSame(witness,primary.witness)
        assertSame(capacity,primary.suppressed.single())
        val rendered=state.render().toString(Charsets.US_ASCII)
        assertTrue(rendered.contains(witness.record));assertFalse(rendered.contains(later.record))
        assertTrue(rendered.contains("retainedRowCount=16\n"));assertTrue(rendered.contains("credentialOverflowObservations=101\n"))
        assertTrue(rendered.contains("scanComplete=false\n"));assertTrue(rendered.length<=16384)
        assertTrue(nativeObserverFailureFields(primary,"primary").contains("primaryObserverWitness=${witness.record}\n"))
        assertEquals("POSSIBLE_OWNED_VISIBILITY",nativeFailureCategory(primary))
        state.reset();assertEquals(null,state.firstPossibleWitness);assertEquals(0,state.overflowObservations)
    }
}
