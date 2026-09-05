package decompengine.web

import kotlinx.serialization.json.*
import kotlin.test.*

class WebExplorationReportTest {
    private val valid = """{"candidateCount":1,"coverageIncreased":true,"baselineOutputSignatures":0,"expandedOutputSignatures":1,"newOutputSignatures":["sample"],"angr":null,"confidence":{"score":0.5,"inputCount":18446744073709551615,"sourceCount":1,"outputSignatureCount":1,"newOutputSignatureCount":1,"sandboxed":true,"networkIsolated":false},"candidates":[{}],"observations":[]}"""
    private fun report(text: String?) = webExplorationReport("a".repeat(32), "run_1", text?.toByteArray())
    @Test fun `known summary retains exact counts with observations authority and no acceptance`() {
        val result = report(valid)
        assertEquals("available", result.getValue("state").jsonPrimitive.content)
        assertEquals("18446744073709551615", result.getValue("summary").jsonObject.getValue("confidence").jsonObject.getValue("inputCount").jsonPrimitive.content)
        assertEquals("observations", result.getValue("authority").jsonPrimitive.content)
        assertEquals("not-evaluated", result.getValue("acceptance").jsonPrimitive.content)
        assertEquals(JsonNull, result.getValue("sourceArtifact"))
        assertEquals(result, report(valid))
        assertNotEquals(result.getValue("reportId"), report(valid.replace("0.5", "0.4")).getValue("reportId"))
    }
    @Test fun `missing partial malformed future and invalid numeric values do not invent summaries`() {
        for ((bytes, state) in listOf(null to "unknown", "{}" to "partial", "{" to "invalid", "{\"schemaVersion\":2}" to "unsupported",
            valid.replace("0.5", "2.0") to "invalid", valid.replace("\"candidateCount\":1", "\"candidateCount\":2") to "invalid",
            valid.replace("18446744073709551615", "18446744073709551616") to "invalid", valid.replace("\"score\":0.5", "\"score\":0.5,\"score\":0.6") to "invalid")) {
            val result = report(bytes)
            assertEquals(state, result.getValue("state").jsonPrimitive.content)
            assertEquals(JsonNull, result.getValue("summary"))
        }
    }
}
