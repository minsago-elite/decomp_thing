package decompengine.project

import org.junit.jupiter.api.Test
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertEquals

class ModuleCompilationCancellationTest {
    @Test fun `wrapped cancellation retains original execution and cleanup failures`() {
        val interruption = InterruptedException("cancelled in scope wait")
        val execution = IllegalArgumentException("contained execution failed", interruption)
        val cleanup = IllegalStateException("cleanup failed")
        execution.addSuppressed(cleanup)
        val classified = moduleCompilationFailurePreservingCancellation(execution)
        assertIs<InterruptedException>(classified)
        assertSame(execution, classified.cause)
        assertSame(cleanup, classified.cause!!.suppressed.single())
    }
    @Test fun `ordinary failure retains identity and explicit cancellation remains typed`() {
        val original = IllegalStateException("compiler unavailable")
        assertSame(original, moduleCompilationFailurePreservingCancellation(original))
        assertIs<InterruptedException>(moduleCompilationFailurePreservingCancellation(original, interrupted = true))
        val cancellation = InterruptedException("already classified")
        assertSame(cancellation, moduleCompilationFailurePreservingCancellation(cancellation))
    }
    @Test fun `malformed cyclic cause chain terminates without changing ordinary failure`() {
        val first = IllegalArgumentException("first")
        val second = IllegalArgumentException("second")
        first.initCause(second)
        second.initCause(first)
        assertSame(first, moduleCompilationFailurePreservingCancellation(first))
        assertEquals("first", first.message)
    }
}
