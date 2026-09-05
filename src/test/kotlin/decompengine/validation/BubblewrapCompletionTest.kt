package decompengine.validation

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

class BubblewrapCompletionTest {
    private val launch = "{ \"child-pid\": 123, \"mnt-namespace\": 4026539305, \"pid-namespace\": 4026539306 }\n"

    @Test
    fun `normal completion distinguishes application exits from missing terminal evidence`() {
        for (exit in listOf(0, 1, 123, 124, 125, 126, 127)) {
            val bytes = (launch + "{ \"exit-code\": $exit }\n").toByteArray()
            assertEquals(BubblewrapCompletionObservation(123, exit), parseBubblewrapCompletion(bytes, exit))
            assertFails { parseBubblewrapCompletion(launch.toByteArray(), exit) }
        }
        assertFails { parseBubblewrapCompletion((launch + "{\"exit-code\":0}\n").toByteArray(), 124) }
        assertFails { parseBubblewrapCompletion((launch + "{\"exit-code\":143}\n").toByteArray(), 143) }
    }

    @Test
    fun `incomplete contradictory and excessive completion records remain unusable`() {
        val terminal = "{\"exit-code\":0}\n"
        val variants = listOf(
            "", terminal, launch, launch + terminal.trimEnd(), launch + terminal + terminal,
            terminal + launch, launch + "{\"exit-code\":0,\"exit-code\":0}\n",
            launch + "{\"exit-code\":\"0\"}\n", launch + "{\"exit-code\":0.0}\n",
            launch + "{\"exit-code\":-1}\n", launch + "{\"exit-code\":0,\"verified\":true}\n",
            launch.replace("\"child-pid\": 123", "\"child-pid\": 0") + terminal,
            launch.replace("\"pid-namespace\"", "\"unknown-namespace\"") + terminal,
            " ".repeat(MAXIMUM_BUBBLEWRAP_COMPLETION_BYTES) + launch + terminal,
        )
        variants.forEach { value -> assertFails { parseBubblewrapCompletion(value.toByteArray(), 0) } }
        assertFails { parseBubblewrapCompletion(byteArrayOf(0xff.toByte(), 10), 0) }
    }
}
