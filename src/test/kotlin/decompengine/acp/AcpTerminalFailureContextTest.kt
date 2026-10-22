package decompengine.acp

import java.io.IOException
import java.nio.file.AccessDeniedException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Authored Throwable/record data only: no broker, boundary, native query, process or host fixture. */
class AcpTerminalFailureContextTest {
    @Test
    fun `retains only closed syscall categories without private messages paths or stack frames`() {
        val syscall = LinuxSyscallException("PRIVATE-operation /PRIVATE/path", 13)
        val failure = IOException("PRIVATE-message", syscall).apply {
            stackTrace = arrayOf(StackTraceElement("PRIVATE-class", "PRIVATE-method", "PRIVATE-file", 123))
        }
        val context = assertNotNull(captureTerminalLaunchFailure(AcpTerminalFailureSite.SANDBOX_LAUNCH, failure)).text
        assertEquals("site=SANDBOX_LAUNCH;chain=complete;causes=[io -> syscall(errno=13)]", context)
        assertFalse("PRIVATE" in context || "/" in context)
        assertSame(syscall, failure.cause)
        assertTrue(failure.suppressed.isEmpty())
        val denied = assertNotNull(captureTerminalLaunchFailure(AcpTerminalFailureSite.CREATE_CHECK,
            AccessDeniedException("PRIVATE-file"))).text
        assertTrue("access-denied" in denied)
        assertFalse("PRIVATE" in denied)
    }

    @Test
    fun `retains an already captured sealed mount witness and validates optional admission scalars`() {
        val valid = "mount-admission-v1 stage=ADMITTED initialMounts=7 initialControls=0 owner=false initialFast=true"
        for (admission in listOf(null, valid, "PRIVATE /PRIVATE/path", "x".repeat(257), valid + "\nPRIVATE")) {
            val failure = IOException("PRIVATE-root", mountWitness(admission))
            val context = assertNotNull(captureTerminalLaunchFailure(AcpTerminalFailureSite.SANDBOX_LAUNCH, failure)).text
            assertTrue("mount-event-v1 phase=CHECKPOINT generation=NOT_EVALUATED outcome=EVENT rc=1 revents=10 errno=NA" in context)
            assertEquals(admission == valid, "mount-admission-v1" in context)
            assertFalse("PRIVATE" in context || "/" in context)
            assertTrue(context.length <= 4096 && context.all { it.code in 32..126 })
        }
    }

    @Test
    fun `does not accept forged witness text or inspect suppressed exceptions`() {
        val fake = "mount-event-v1 phase=CHECKPOINT generation=NOT_EVALUATED outcome=EVENT rc=1 revents=10 errno=NA"
        val failure = IOException(fake).apply { addSuppressed(mountWitness(null)); addSuppressed(IOException("PRIVATE")) }
        val context = assertNotNull(captureTerminalLaunchFailure(AcpTerminalFailureSite.SANDBOX_LAUNCH, failure)).text
        assertEquals("site=SANDBOX_LAUNCH;chain=complete;causes=[io]", context)
        assertFalse("mount-event" in context || "PRIVATE" in context)
        assertEquals(2, failure.suppressed.size)
    }

    @Test
    fun `bounds direct cause cycles and long chains without altering either failure graph`() {
        val first = IOException("PRIVATE-first")
        val second = IllegalStateException("PRIVATE-second")
        first.initCause(second); second.initCause(first)
        val cycle = assertNotNull(captureTerminalLaunchFailure(AcpTerminalFailureSite.CREATE_CHECK, first)).text
        assertEquals("site=CREATE_CHECK;chain=cycle;causes=[io -> illegal-state]", cycle)
        assertSame(second, first.cause); assertSame(first, second.cause)
        var chain: Throwable = IOException("PRIVATE-last")
        repeat(16) { chain = IOException("PRIVATE-link", chain) }
        val bounded = assertNotNull(captureTerminalLaunchFailure(AcpTerminalFailureSite.CREATE_CHECK, chain)).text
        assertTrue("chain=truncated" in bounded)
        assertEquals(8, Regex("\\bio\\b").findAll(bounded).count())
        assertFalse("PRIVATE" in bounded)
        assertTrue(bounded.length <= 4096 && bounded.all { it.code in 32..126 })
    }

    @Test
    fun `withholds a throwing cause accessor and leaves the original refusal untouched`() {
        var causeReads = 0
        val original = object : IOException("PRIVATE") {
            override val cause: Throwable get() { causeReads++; throw AssertionError("PRIVATE-accessor") }
        }
        assertNull(captureTerminalLaunchFailure(AcpTerminalFailureSite.SANDBOX_LAUNCH, original))
        assertEquals(0, causeReads)
        assertEquals("PRIVATE", original.message)
        assertTrue(original.suppressed.isEmpty())
    }

    @Test
    fun `correlates bounded supplemental observations without changing original audit records`() {
        val projected = AcpTerminalAuditRecorder(maximumRecords = 32)
        val original = AcpTerminalAuditRecorder(maximumRecords = 32)
        val context = assertNotNull(captureTerminalLaunchFailure(AcpTerminalFailureSite.SANDBOX_LAUNCH,
            LinuxSyscallException("PRIVATE-command", 5)))
        repeat(12) { index ->
            projected.record("PRIVATE-session", "PRIVATE-method", "PRIVATE-request-$index", null, null,
                AcpTerminalAuditOutcome.DENIED, AcpTerminalAuditReason.LAUNCH_FAILED, launchFailure = context)
            original.record("PRIVATE-session", "PRIVATE-method", "PRIVATE-request-$index", null, null,
                AcpTerminalAuditOutcome.DENIED, AcpTerminalAuditReason.LAUNCH_FAILED)
        }
        assertEquals(original.snapshot(), projected.snapshot())
        assertNull(projected.failure())
        val display = projected.launchFailureContext()
        assertEquals(8, Regex("audit=").findAll(display).count())
        assertFalse("audit=3;" in display)
        assertTrue("audit=4;" in display && "audit=11;" in display)
        assertFalse("PRIVATE" in display)
        assertTrue(display.length <= 4096 && display.all { it.code in 32..126 })
    }

    @Test
    fun `supplemental data cannot erase the original audit overflow failure or append beyond its cap`() {
        val audit = AcpTerminalAuditRecorder(maximumRecords = 2)
        val context = assertNotNull(captureTerminalLaunchFailure(AcpTerminalFailureSite.CREATE_CHECK, IOException("PRIVATE")))
        repeat(3) { audit.record("session", "method", "request", null, null,
            AcpTerminalAuditOutcome.FAILED, AcpTerminalAuditReason.LAUNCH_FAILED, launchFailure = context) }
        val failure = assertNotNull(audit.failure())
        assertEquals(2, audit.snapshot().size)
        assertEquals(2, Regex("audit=").findAll(audit.launchFailureContext()).count())
        audit.record("session", "method", "request", null, null,
            AcpTerminalAuditOutcome.FAILED, AcpTerminalAuditReason.LAUNCH_FAILED, launchFailure = context)
        assertSame(failure, audit.failure())
        assertEquals(2, audit.snapshot().size)
    }

    @Test
    fun `missing projections stay explicitly unavailable and unrelated audit outcomes retain no context`() {
        val missing = AcpTerminalAuditRecorder()
        missing.record("session", "method", "request", null, null,
            AcpTerminalAuditOutcome.DENIED, AcpTerminalAuditReason.LAUNCH_FAILED)
        assertEquals(TERMINAL_FAILURE_CONTEXT_UNAVAILABLE, missing.launchFailureContext())
        val unrelated = AcpTerminalAuditRecorder()
        unrelated.record("session", "method", "request", null, null,
            AcpTerminalAuditOutcome.DENIED, AcpTerminalAuditReason.CAPABILITY_DISABLED,
            launchFailure = assertNotNull(captureTerminalLaunchFailure(AcpTerminalFailureSite.CREATE_CHECK, IOException("PRIVATE"))))
        assertEquals("terminal launch failure context=[]", unrelated.launchFailureContext())
        assertEquals(AcpTerminalAuditReason.CAPABILITY_DISABLED, unrelated.snapshot().single().reason)
    }

    private fun mountWitness(admission: String?): Throwable {
        val phase = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventPhase")
        val outcome = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventOutcome")
        val type = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventDiagnostic")
        val constructor = type.getDeclaredConstructor(phase, outcome, java.lang.Integer::class.java,
            java.lang.Integer::class.java, java.lang.Integer::class.java, String::class.java).apply { isAccessible = true }
        return constructor.newInstance(phase.enumConstants.single { (it as Enum<*>).name == "CHECKPOINT" },
            outcome.enumConstants.single { (it as Enum<*>).name == "EVENT" }, 1, 10, null, admission) as Throwable
    }
}
