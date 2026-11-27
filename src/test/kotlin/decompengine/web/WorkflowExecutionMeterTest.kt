package decompengine.web
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertEquals
class WorkflowExecutionMeterTest {
 @Test fun measurementCarriesOnlyApplicableLocalFields() {
  val time = Instant.parse("2026-09-05T00:00:02Z")
  for (metered in listOf(false, true)) {
   val usage = WorkflowExecutionMeter(Path.of("reports"), metered, clock = Clock.fixed(time, ZoneOffset.UTC)).usage(900)
   assertEquals(time, usage.localMeasurement!!.sampledAt)
   assertEquals(if (metered) listOf("wallClockMs", "toolCalls") else listOf("wallClockMs"), usage.localMeasurement!!.fields)
   assertEquals(900uL, usage.wallClockMs)
  }
 }
}
