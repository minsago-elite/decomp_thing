package decompengine.web

import decompengine.exploration.CandidateInput
import decompengine.exploration.CandidateObservation
import decompengine.exploration.CandidateSource
import decompengine.exploration.ExplorationFailureReason
import decompengine.exploration.ExplorationFailureRecord
import decompengine.exploration.ExplorationSamplePhase
import kotlinx.serialization.json.*
import kotlin.test.*

/** Synthetic bytes and read-only projection only; no explorer, sandbox, host or process. */
class WebExplorationScalarTypesTest {
    private val legacy = Json.parseToJsonElement("""{"candidateCount":1,"coverageIncreased":false,"baselineOutputSignatures":1,"expandedOutputSignatures":1,"newOutputSignatures":[],"angr":null,"confidence":{"score":0.5,"inputCount":1,"sourceCount":1,"outputSignatureCount":1,"newOutputSignatureCount":0,"sandboxed":true,"networkIsolated":false},"candidates":[{}],"observations":[]}""").jsonObject
    private fun project(root: JsonObject) = webExplorationReport("a".repeat(32), "run_scalar", root.toString().toByteArray())
    private fun assertUnavailable(root: JsonObject, state: String) {
        val result = project(root)
        assertEquals(state, result.getValue("state").jsonPrimitive.content)
        assertEquals(JsonNull, result.getValue("summary"))
        assertEquals(JsonNull, result.getValue("producerSchemaVersion"))
        assertEquals("observations", result.getValue("authority").jsonPrimitive.content)
        assertEquals("not-evaluated", result.getValue("acceptance").jsonPrimitive.content)
        assertEquals(JsonNull, result.getValue("acceptanceArtifactId"))
    }

    private fun failure(isolated: Boolean): JsonObject {
        val input = CandidateInput("case", CandidateSource.SEED)
        return Json.parseToJsonElement(ExplorationFailureRecord(
            ExplorationSamplePhase.EXPANDED, 0, ExplorationFailureReason.TIMEOUT,
            listOf(input), listOf(input), 1, 0,
            listOf(CandidateObservation("case", "0::", 0, "", "", isolated)), emptyList(),
        ).toJson()).jsonObject
    }

    @Test fun `failure observations accept literal booleans and reject quoted or nonboolean isolation flags`() {
        for (isolated in listOf(false, true)) {
            val root = failure(isolated)
            val result = project(root)
            assertEquals("partial", result.getValue("state").jsonPrimitive.content)
            assertEquals(1, result.getValue("producerSchemaVersion").jsonPrimitive.int)
            assertEquals(JsonNull, result.getValue("summary"))
            val detail = root.getValue("details").jsonObject
            val observation = detail.getValue("baselineObservations").jsonArray.single().jsonObject
            assertEquals(JsonPrimitive(isolated), observation.getValue("networkIsolated"))
            for (invalid in listOf(JsonPrimitive("false"), JsonPrimitive("true"), JsonPrimitive(0), JsonNull)) {
                val changed = JsonObject(observation + ("networkIsolated" to invalid))
                val changedDetails = JsonObject(detail + ("baselineObservations" to JsonArray(listOf(changed))))
                assertUnavailable(JsonObject(root + ("details" to changedDetails)), "invalid")
            }
        }
    }

    @Test fun `legacy coverage and isolation flags require literal booleans without coercing strings`() {
        assertEquals("available", project(legacy).getValue("state").jsonPrimitive.content)
        for (flag in listOf("coverageIncreased", "sandboxed", "networkIsolated")) {
            for (valid in listOf(false, true)) {
                val changed = if (flag == "coverageIncreased") JsonObject(legacy + (flag to JsonPrimitive(valid)))
                else JsonObject(legacy + ("confidence" to JsonObject(legacy.getValue("confidence").jsonObject + (flag to JsonPrimitive(valid)))))
                assertEquals("available", project(changed).getValue("state").jsonPrimitive.content)
                for (invalid in listOf(JsonPrimitive("false"), JsonPrimitive("true"), JsonPrimitive(0), JsonNull)) {
                    val malformed = if (flag == "coverageIncreased") JsonObject(changed + (flag to invalid))
                    else JsonObject(changed + ("confidence" to JsonObject(changed.getValue("confidence").jsonObject + (flag to invalid))))
                    assertUnavailable(malformed, "invalid")
                }
            }
        }
    }

    @Test fun `unknown schema declarations cannot fall through to a complete legacy numeric summary`() {
        for (schema in listOf("unknown-exploration-format", "decomp-exploration-failure")) {
            val root = JsonObject(legacy + ("schema" to JsonPrimitive(schema)))
            assertUnavailable(root, "unsupported")
            assertUnavailable(JsonObject(root + ("schemaVersion" to JsonPrimitive(2))), "unsupported")
        }
        assertEquals("available", project(legacy).getValue("state").jsonPrimitive.content)
    }

    @Test fun `legacy new signature count must match its retained list before exposing a summary`() {
        fun retained(signatures: List<String>, count: String): JsonObject = JsonObject(legacy + mapOf(
            "newOutputSignatures" to JsonArray(signatures.map(::JsonPrimitive)),
            "confidence" to JsonObject(legacy.getValue("confidence").jsonObject +
                ("newOutputSignatureCount" to Json.parseToJsonElement(count))),
        ))
        for ((signatures, count) in listOf(emptyList<String>() to "0", listOf("new") to "1")) {
            val result = project(retained(signatures, count))
            assertEquals("available", result.getValue("state").jsonPrimitive.content)
            assertEquals(count, result.getValue("summary").jsonObject.getValue("confidence").jsonObject
                .getValue("newOutputSignatureCount").jsonPrimitive.content)
        }
        for ((signatures, count) in listOf(
            emptyList<String>() to "1", listOf("new") to "0", listOf("new") to "2",
            listOf("new", "other") to "1", emptyList<String>() to "18446744073709551615",
        )) assertUnavailable(retained(signatures, count), "invalid")
    }
}
