package decompengine.web

import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals

class WebSchedulerSnapshotTest {
    @Test fun `owned and unavailable scheduler projections match shared wire fixtures`() {
        val sampledAt = Instant.parse("2026-09-05T00:00:00Z")
        val fixtures = listOf(
            "bootstrap-scheduler-saturated" to WebSchedulerSnapshot.Available(sampledAt, false, 2, 2, 32, 32),
            "bootstrap-scheduler-unavailable" to WebSchedulerSnapshot.Unavailable(sampledAt),
        )
        for ((name, sample) in fixtures) {
            val expected = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/fixtures/$name.json")))
                .jsonObject.getValue("data").jsonObject.getValue("runtime").jsonObject.getValue("scheduler")
            assertEquals(expected, webSchedulerSnapshot(sample))
        }
    }
}
