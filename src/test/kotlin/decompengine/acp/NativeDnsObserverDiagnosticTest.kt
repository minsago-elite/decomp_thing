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
    fun `denial diagnostics deduplicate observations and fail on distinct overflow`() {
        val type = Class.forName("decompengine.acp.AcpProviderNativeDnsContractTestKt")
        @Suppress("UNCHECKED_CAST")
        val records = type.getDeclaredField("nativeVisibilityRecords").apply { isAccessible = true }.get(null) as MutableList<String>
        val record = type.getDeclaredMethod("nativeRecordDenied", Long::class.javaPrimitiveType, String::class.java,
            String::class.java, NativeNamespaceCredentials::class.java, NativeNamespaceCredentials::class.java,
            java.lang.Long::class.java, String::class.java).apply { isAccessible = true }
        val caller = parseNativeNamespaceCredentials(status(123), 123)
        records.clear()
        try {
            repeat(32) { record.invoke(null, 124L, "net", "HOST_CLEANUP", caller, null, 1L, "OBSERVER_UNAVAILABLE") }
            assertEquals(1, records.size)
            repeat(15) { record.invoke(null, 125L + it, "net", "HOST_CLEANUP", caller, null, 1L, "OBSERVER_UNAVAILABLE") }
            val overflow = assertFailsWith<java.lang.reflect.InvocationTargetException> {
                record.invoke(null, 999L, "net", "HOST_CLEANUP", caller, null, 1L, "OBSERVER_UNAVAILABLE")
            }
            assertTrue(overflow.targetException is IllegalStateException)
            assertEquals(16, records.size)
        } finally { records.clear() }
    }

    @Test
    fun `child outcome retains fixed phase and exit without arbitrary output`() {
        assertEquals("exit=1;stage=INNER_CAPABILITIES", nativeFixedChildOutcome(1, "NATIVE_DNS_CONTROL_FAILED_INNER_CAPABILITIES\n".toByteArray()))
        assertEquals("exit=UNAVAILABLE;stage=WAIT_INCOMPLETE", nativeFixedChildOutcome(null, "private untrusted text".toByteArray()))
        assertEquals("exit=1;stage=UNRECOGNIZED_OUTPUT", nativeFixedChildOutcome(1, "private untrusted text".toByteArray()))
    }
}
