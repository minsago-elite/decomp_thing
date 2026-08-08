package decompengine.roadmap

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
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

        assertEquals("L1", progress["current_level"].toString().trim('"'))
        assertEquals("active", progress["current_status"].toString().trim('"'))
        assertTrue(progress["levels"]!!.toString().contains("\"evidence\""))
    }

    @Test
    fun `MVP contains only reconstruct patch and delivery steps`() {
        val progress = Json.parseToJsonElement(Path("roadmap/progress.json").readText()).jsonObject
        val levels = progress["levels"]!!.jsonArray.map { it.jsonObject }

        assertEquals(listOf("L1", "L2", "L6"), levels.map { it["id"].toString().trim('"') })
        assertEquals(listOf("active", "pending", "pending"), levels.map { it["status"].toString().trim('"') })
        assertTrue(levels.last()["gates"]!!.toString().contains("l6_exploit_blocked"))
    }

    @Test
    fun `roadmap check passes`() {
        assertEquals("Roadmap check passed", RoadmapManager().check())
    }
}
