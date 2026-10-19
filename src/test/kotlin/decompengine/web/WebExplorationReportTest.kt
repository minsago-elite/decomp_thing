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
        assertEquals("raw-evidence", result.getValue("sourceArtifact").jsonObject.getValue("role").jsonPrimitive.content)
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

    private val failed = """{"schema":"decomp-exploration-failure","schemaVersion":1,"state":"partial","failure":{"phase":"expanded","candidateIndex":0,"kind":"timeout","code":"behavior-deadline-exceeded"},"samples":{"baselineInputs":1,"expandedInputs":1,"baselineObserved":1,"expandedObserved":0},"details":{"baselineInputs":[{"id":"seed","source":"SEED","args":[""],"stdinHex":"00"}],"expandedInputs":[{"id":"generated","source":"MUTATION","args":[],"stdinHex":""}],"baselineObservations":[{"candidateId":"seed","signature":"0::","exitCode":0,"stdoutHex":"","stderrHex":"","networkIsolated":false}],"expandedObservations":[]},"detailsOmitted":null,"coverage":null,"confidence":null}"""

    @Test fun `versioned producer failure retains artifact and attempt binding without a success summary`() {
        val result = report(failed)
        assertEquals("partial", result.getValue("state").jsonPrimitive.content)
        assertEquals(1, result.getValue("producerSchemaVersion").jsonPrimitive.int)
        assertEquals(JsonNull, result.getValue("summary"))
        assertEquals("observations", result.getValue("authority").jsonPrimitive.content)
        assertEquals("not-evaluated", result.getValue("acceptance").jsonPrimitive.content)
        assertEquals("run_1", result.getValue("binding").jsonObject.getValue("runId").jsonPrimitive.content)
        assertEquals("raw-evidence", result.getValue("sourceArtifact").jsonObject.getValue("role").jsonPrimitive.content)
        assertTrue(result.getValue("limitations").jsonArray.single().jsonPrimitive.content.contains("a timeout"))
        assertTrue(result.getValue("limitations").jsonArray.single().jsonPrimitive.content.contains("Coverage and confidence are unavailable"))
    }

    @Test fun `malformed failed progress is invalid and future producer versions remain unsupported`() {
        for (text in listOf(
            failed.replace("\"candidateIndex\":0", "\"candidateIndex\":1"),
            failed.replace("\"signature\":\"0::\"", "\"signature\":\"1::\""),
            failed.replace("\"confidence\":null", "\"confidence\":0"),
            failed.replace("\"baselineObserved\":1", "\"baselineObserved\":0"),
        )) {
            val result = report(text)
            assertEquals("invalid", result.getValue("state").jsonPrimitive.content)
            assertEquals(JsonNull, result.getValue("summary"))
        }
        val result = report(failed.replace("\"schemaVersion\":1", "\"schemaVersion\":2"))
        assertEquals("unsupported", result.getValue("state").jsonPrimitive.content)
        assertEquals(JsonNull, result.getValue("summary"))
    }
}
