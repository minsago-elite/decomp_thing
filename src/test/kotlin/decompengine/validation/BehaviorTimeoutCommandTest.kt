package decompengine.validation

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class BehaviorTimeoutCommandTest {
    @Test
    fun `native timeout arguments preserve each selected millisecond`() {
        val cases = mapOf(1L to "0.001s", 999L to "0.999s", 1000L to "1s", 1001L to "1.001s",
            1500L to "1.500s", 1900L to "1.900s", 5000L to "5s")
        for ((millis, expected) in cases) {
            assertEquals(expected, command(millis)[1])
        }
        assertFailsWith<IllegalArgumentException> { command(0) }
        assertFailsWith<IllegalArgumentException> { command(-1) }
    }

    private fun command(millis: Long) = behaviorSandboxCommand(Path.of("/program"), emptyList(), millis,
        Path.of("/usr/bin/bwrap"), Path.of("/usr/bin/timeout"), false)
}
