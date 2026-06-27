package decompengine.roadmap

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.io.path.Path
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RoadmapManagerTest {
    @Test
    fun `progress has required evidence and current level`() {
        val progress = Json.parseToJsonElement(Path("roadmap/progress.json").readText()).jsonObject

        assertEquals("L5", progress["current_level"].toString().trim('"'))
        assertEquals("active", progress["current_status"].toString().trim('"'))
        assertTrue(progress["levels"]!!.toString().contains("\"evidence\""))
    }

    @Test
    fun `roadmap check passes`() {
        assertEquals("Roadmap check passed", RoadmapManager().check())
    }
}
