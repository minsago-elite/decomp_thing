package decompengine.acp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Credential-free parser/classification controls; no namespace or resolver is launched. */
class NativeDnsObserverDiagnosticTest {
    private fun status(pid: Long, uid: String = "1000 1001 1002 1003", gid: String = "2000 2001 2002 2003") =
        "Pid:\t$pid\nUid:\t$uid\nGid:\t$gid\n"
    @Test
    fun `caller identity retains all credential IDs independently of proc inode ownership`() {
        val caller = parseNativeNamespaceCredentials(status(123), 123)
        assertEquals(listOf(1000L, 1001L, 1002L, 1003L), caller.uid)
        assertEquals(listOf(2000L, 2001L, 2002L, 2003L), caller.gid)
        // A nondumpable caller's proc inode could be root-owned; that proxy is not an input.
        val fsUidMatch = parseNativeNamespaceCredentials(status(124, "4000 4001 4002 1003", "5000 5001 5002 5003"), 124)
        assertTrue(nativeDeniedVisibilityRequiresFailure(caller, fsUidMatch))
    }
    @Test
    fun `unknown and any matching credential cannot certify denied namespace absence`() {
        val caller = parseNativeNamespaceCredentials(status(123), 123)
        assertTrue(nativeDeniedVisibilityRequiresFailure(caller, null))
        assertTrue(nativeDeniedVisibilityRequiresFailure(caller,
            parseNativeNamespaceCredentials(status(124, "4000 4001 4002 4003", "5000 5001 5002 2003"), 124)))
        assertFalse(nativeDeniedVisibilityRequiresFailure(caller,
            parseNativeNamespaceCredentials(status(124, "4000 4001 4002 4003", "5000 5001 5002 5003"), 124)))
    }
    @Test
    fun `wrong PID duplicate incomplete and out of range identity fail closed`() {
        listOf(status(124), status(123) + "Uid: 1 1 1 1\n", status(123, "1 1 1"), status(123, "1 1 1 4294967296"),
            "Pid: 123\nUid: 1 1 1 1\n", "x".repeat(65537)).forEach {
            assertFailsWith<IllegalStateException> { parseNativeNamespaceCredentials(it, 123) }
        }
    }
    @Test
    fun `primary failure survives cleanup failure as exact suppressed object`() {
        val primary = IllegalStateException("inert primary")
        val cleanup = IllegalArgumentException("inert cleanup")
        nativeKeepPrimaryFailure(primary, cleanup)
        assertSame(cleanup, primary.suppressed.single())
        assertEquals("STATE_FAILURE", nativeFailureCategory(primary))
        assertEquals("ACCESS_DENIED", nativeFailureCategory(java.nio.file.AccessDeniedException("inert")))
        assertSame(cleanup, assertFailsWith<IllegalArgumentException> { nativeKeepPrimaryFailure(null, cleanup) })
    }
    @Test
    fun `cleanup-only diagnostic classifies selected primary without replacing pre-cleanup liveness`() {
        val before = linkedMapOf("primaryFailure" to "NONE", "rootAliveAtFailure" to "true", "hostPhase" to "PAYLOAD_RELEASE_FLUSHED")
        val cleanup = java.io.IOException("private cleanup detail")
        val diagnostic = nativeFinalFailureDiagnostic(before, cleanup)
        assertEquals("IO_FAILURE", diagnostic["primaryFailure"])
        assertEquals("true", diagnostic["rootAliveAtFailure"])
        assertEquals(before["hostPhase"], diagnostic["hostPhase"])
        assertEquals("NONE", before["primaryFailure"])
        assertFalse(diagnostic.values.any { it.contains("private") })
        val primary = IllegalStateException("private original")
        nativeKeepPrimaryFailure(primary, cleanup)
        assertEquals("STATE_FAILURE", nativeFinalFailureDiagnostic(before, primary)["primaryFailure"])
        assertSame(cleanup, primary.suppressed.single())
    }

    @Test
    fun `denial diagnostics deduplicate retained observations and fail on ordinary detail overflow`() {
        // This test owns its accumulator; no global deadline, sink, /proc lookup or reflection.
        val records = mutableListOf<String>()
        val accumulator = NativeVisibilityAccumulator(records)
        repeat(32) { accumulator.record("pid=124 outcome=OBSERVER_UNAVAILABLE", false) }
        assertEquals(1, records.size)
        repeat(14) { accumulator.record("pid=${125 + it} outcome=OBSERVER_UNAVAILABLE", false) }
        assertEquals("DIAGNOSTIC_CAPACITY", assertFailsWith<NativeObserverFailure> {
            accumulator.record("pid=999 outcome=OBSERVER_UNAVAILABLE", false)
        }.category)
        assertEquals(15, records.size)
    }

    @Test
    fun `child outcome retains fixed phase and exit without arbitrary output`() {
        assertEquals("exit=1;stage=INNER_CAPABILITIES", nativeFixedChildOutcome(1, "NATIVE_DNS_CONTROL_FAILED_INNER_CAPABILITIES\n".toByteArray()))
        assertEquals("exit=UNAVAILABLE;stage=WAIT_INCOMPLETE", nativeFixedChildOutcome(null, "private untrusted text".toByteArray()))
        assertEquals("exit=1;stage=UNRECOGNIZED_OUTPUT", nativeFixedChildOutcome(1, "private untrusted text".toByteArray()))
    }

    @Test
    fun `first witness distinguishes existing read stages and keeps every outcome fatal`() {
        val caller=NativeNamespaceCredentials(listOf(1,1,1,1),listOf(2,2,2,2))
        val target=NativeNamespaceCredentials(listOf(3,3,3,1),listOf(4,4,4,4))
        fun witness(stage: NativeObserverFailure.ReadStage, before: Long?, after: Long?,
            observed: NativeNamespaceCredentials?, failure: Exception?) = NativeObserverFailure.Witness(
                1136,"net","OUTER_CLEANUP",10,caller,observed,before,after,stage,
                failure?.let { NativeObserverFailure.exceptionKind(it) } ?: NativeObserverFailure.ExceptionKind.NONE)
        val stages=listOf(
            witness(NativeObserverFailure.ReadStage.START_BEFORE,null,null,null,java.nio.file.NoSuchFileException("private path")),
            witness(NativeObserverFailure.ReadStage.STATUS,7,null,null,java.nio.file.AccessDeniedException("private path")),
            witness(NativeObserverFailure.ReadStage.STATUS,7,null,null,IllegalStateException("private parse detail")),
            witness(NativeObserverFailure.ReadStage.START_AFTER,7,null,target,java.io.IOException("private I/O detail")),
            witness(NativeObserverFailure.ReadStage.STABILITY,7,8,target,null),
            witness(NativeObserverFailure.ReadStage.CLASSIFY,7,7,target,null),
        )
        assertEquals(listOf(NativeObserverFailure.Outcome.IDENTITY_UNAVAILABLE,NativeObserverFailure.Outcome.IDENTITY_UNAVAILABLE,
            NativeObserverFailure.Outcome.IDENTITY_UNAVAILABLE,NativeObserverFailure.Outcome.IDENTITY_UNAVAILABLE,
            NativeObserverFailure.Outcome.START_CHANGED,NativeObserverFailure.Outcome.STABLE_OVERLAP),stages.map { it.outcome })
        for (observed in stages) {
            val primary=NativeObserverFailure("POSSIBLE_OWNED_VISIBILITY",1136,"net","OUTER_CLEANUP",observed)
            assertEquals("POSSIBLE_OWNED_VISIBILITY",nativeFailureCategory(primary))
            assertFalse(observed.record.contains("private"))
        }
        assertTrue(stages[0].record.contains("readStage=START_BEFORE"));assertTrue(stages[0].record.contains("exceptionClass=NO_SUCH_FILE"))
        assertTrue(stages[1].record.contains("exceptionClass=ACCESS_DENIED"));assertTrue(stages[2].record.contains("exceptionClass=STATE"))
        assertTrue(stages[3].record.contains("readStage=START_AFTER"));assertTrue(stages[3].record.contains("targetIdentity=UNVERIFIED"))
        assertTrue(stages[3].record.contains("targetUid=3,3,3,1"));assertTrue(stages[3].record.contains("uidMatch=UNAVAILABLE"))
        assertTrue(stages[4].record.contains("startBefore=7 startAfter=8"));assertTrue(stages[4].record.contains("targetIdentity=UNVERIFIED"))
        assertTrue(stages[5].record.contains("targetIdentity=STABLE"));assertTrue(stages[5].record.contains("uidMatch=true gidMatch=false"))
        val gidOnly=NativeObserverFailure.Witness(1136,"user","HOST_CLEANUP",10,caller,
            NativeNamespaceCredentials(listOf(3,3,3,3),listOf(4,4,4,2)),7,7,
            NativeObserverFailure.ReadStage.CLASSIFY,NativeObserverFailure.ExceptionKind.NONE)
        assertTrue(gidOnly.record.contains("uidMatch=false gidMatch=true"))
    }

    @Test
    fun `witness is immutable bounded typed data and cannot turn stable foreign credentials into fatal identity`() {
        val values=mutableListOf(4294967295L,4294967295L,4294967295L,4294967295L)
        val credentials=NativeNamespaceCredentials(values,values)
        val witness=NativeObserverFailure.Witness(4294967295L,"user","HOST_CLEANUP",4294967295L,
            credentials,credentials,Long.MAX_VALUE,Long.MAX_VALUE,NativeObserverFailure.ReadStage.CLASSIFY,
            NativeObserverFailure.ExceptionKind.NONE)
        val saved=witness.record;values[0]=0
        assertEquals(saved,witness.record);assertTrue(saved.contains("callerUid=4294967295,4294967295,4294967295,4294967295"))
        assertTrue(saved.length<=768);assertTrue(saved.all { it.code in 32..126 })
        val accumulator=NativeVisibilityAccumulator();repeat(15) { accumulator.record(("$it:"+"x".repeat(768)).take(768),true) }
        accumulator.recordFirstPossible(witness);assertTrue(accumulator.render().size<=16384)
        val caller=NativeNamespaceCredentials(listOf(1,1,1,1),listOf(2,2,2,2))
        val foreign=NativeNamespaceCredentials(listOf(3,3,3,3),listOf(4,4,4,4))
        assertFailsWith<IllegalArgumentException> {
            NativeObserverFailure.Witness(1,"net","HOST_CLEANUP",2,caller,foreign,7,7,
                NativeObserverFailure.ReadStage.CLASSIFY,NativeObserverFailure.ExceptionKind.NONE)
        }
        assertFailsWith<IllegalArgumentException> {
            NativeObserverFailure.Witness(1,"net\nsecret","HOST_CLEANUP",2,caller,null,null,null,
                NativeObserverFailure.ReadStage.START_BEFORE,NativeObserverFailure.ExceptionKind.NONE)
        }
        for ((failure,kind) in listOf(
            SecurityException("secret") to NativeObserverFailure.ExceptionKind.SECURITY,
            IllegalArgumentException("secret") to NativeObserverFailure.ExceptionKind.FORMAT,
            RuntimeException("secret") to NativeObserverFailure.ExceptionKind.OTHER)) {
            assertEquals(kind,NativeObserverFailure.exceptionKind(failure))
        }
    }
}
