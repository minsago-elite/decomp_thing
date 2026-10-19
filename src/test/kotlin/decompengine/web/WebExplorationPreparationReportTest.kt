package decompengine.web

import decompengine.exploration.*
import kotlinx.serialization.json.*
import kotlin.test.*

class WebExplorationPreparationReportTest {
    private fun record() = ExplorationPreparationFailureRecord(ExplorationPreparationStage.ANGR,
        ExplorationPreparationReason.FAILED, listOf(CandidateInput("seed", CandidateSource.SEED)), null, null).toJson()
    private fun project(text: String) = webExplorationReport("a".repeat(32), "run_preparation", text.toByteArray())

    @Test fun `known generation failure retains partial binding without a fabricated sample or numeric summary`() {
        val result = project(record())
        assertEquals("partial", result.getValue("state").jsonPrimitive.content)
        assertEquals(1, result.getValue("producerSchemaVersion").jsonPrimitive.int)
        assertEquals(JsonNull, result.getValue("summary"))
        assertEquals("run_preparation", result.getValue("binding").jsonObject.getValue("runId").jsonPrimitive.content)
        assertEquals("not-evaluated", result.getValue("acceptance").jsonPrimitive.content)
        assertEquals("raw-evidence", result.getValue("sourceArtifact").jsonObject.getValue("role").jsonPrimitive.content)
        assertTrue(result.getValue("limitations").jsonArray.single().jsonPrimitive.content.contains("sample counts are unknown"))
    }

    @Test fun `unknown generation versions and missing declarations refuse numeric fallback`() {
        for (text in listOf(record().replace("\"schemaVersion\":1", "\"schemaVersion\":2"), record().replace("\"schemaVersion\":1,", ""))) {
            val result = project(text)
            assertEquals("unsupported", result.getValue("state").jsonPrimitive.content)
            assertEquals(JsonNull, result.getValue("summary"))
        }
    }

    @Test fun `forged preparation availability is invalid while literal zero returned inputs remain known`() {
        val malformed = record().replace("\"angr\":null", "\"angr\":0")
        assertEquals("invalid", project(malformed).getValue("state").jsonPrimitive.content)
        val valid = ExplorationPreparationFailureRecord(ExplorationPreparationStage.STATIC_HINTS,
            ExplorationPreparationReason.IO_FAILED, emptyList(), emptyList(), null).toJson()
        assertEquals("partial", project(valid).getValue("state").jsonPrimitive.content)
    }
}
