package decompengine.web

import decompengine.acp.AcpAgentHarness
import kotlin.test.*

class WebAuthenticationSelectionTest {
    @Test fun `failed selection stays frozen until a new inspector is created`() {
        for (failure in listOf(java.io.IOException("missing configuration"),
            IllegalArgumentException("malformed configuration"),
            IllegalStateException("non-ACP selection"))) {
            var selections = 0
            var currentFailure: Exception = failure
            val select: () -> AcpAgentHarness = { selections++; throw currentFailure }
            val inspector = defaultWebAuthenticationInspector(select)
            assertEquals(0, selections, "construction remains lazy")
            assertSame(failure, assertFails { inspector() })
            currentFailure = IllegalArgumentException("changed configuration")
            repeat(2) { assertSame(failure, assertFails { inspector() }) }
            assertEquals(1, selections, "failed selection must not reread changed configuration")
            val restarted = defaultWebAuthenticationInspector(select)
            assertSame(currentFailure, assertFails { restarted() })
            assertEquals(2, selections, "a new inspector may select configuration again")
        }
    }
}
