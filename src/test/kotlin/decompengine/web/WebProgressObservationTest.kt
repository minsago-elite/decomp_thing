package decompengine.web

import decompengine.jobs.AgentProgressJournal
import kotlinx.serialization.json.*
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class WebProgressObservationTest {
    private fun fixture() = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/fixtures/event-workflow-observation.json"))).jsonObject
    private fun record(event: JsonObject = fixture()): JsonObject = buildJsonObject {
        val payload = event.getValue("payload").jsonObject
        put("runId", payload.getValue("writerId")); put("workflow", payload.getValue("workflow")); put("kind", payload.getValue("observationKind"))
        put("time", event.getValue("occurredAt")); put("sequence", event.getValue("sequence").jsonPrimitive.content.toLong())
        put("agentSequence", event.getValue("agentSequence").jsonPrimitive.content.toLong())
        payload.getValue("fields").jsonObject.forEach { (key, value) -> put(key, value) }
    }
    private fun project(value: JsonObject): JsonObject {
        val expected = fixture()
        return webProgressObservation(expected.getValue("jobId").jsonPrimitive.content, expected.getValue("runId").jsonPrimitive.content,
            expected.getValue("cursor").jsonPrimitive.content, value)
    }

    @Test fun `projection matches the shared contract fixture without promoting reported acceptance`() {
        assertEquals(fixture(), project(record()))
    }

    @Test fun `bounded plans and upstream truncation markers match the shared fixture`() {
        val expected = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/fixtures/event-observation-truncated-preview.json"))).jsonObject
        val source = JsonObject(record(expected) + ("futureField" to JsonPrimitive("omitted")))
        assertEquals(expected, project(source))
    }

    @Test fun `unknown fields are counted but not copied into observations`() {
        val event = project(JsonObject(record() + ("future_private_field" to JsonPrimitive("must not escape"))))
        val payload = event.getValue("payload").jsonObject
        assertEquals("1", payload.getValue("omittedFieldCount").jsonPrimitive.content)
        assertFalse(event.toString().contains("must not escape"))
        assertFalse(event.toString().contains("future_private_field"))
        assertEquals("observations", payload.getValue("authority").jsonPrimitive.content)
    }

    @Test fun `invalid known values fail instead of silently changing counts or flags`() {
        for ((key, value) in listOf(
            "inputTokens" to JsonPrimitive(-1), "inputTokens" to JsonPrimitive("18446744073709551616"),
            "inputTokens" to JsonPrimitive("1e3"), "completed" to JsonPrimitive("true"),
            "text" to JsonPrimitive("x".repeat(8193)), "requestSha256" to JsonPrimitive("invalid"),
            "runId" to JsonPrimitive("invalid/path"), "agentSequence" to JsonPrimitive("01"),
            "entries" to JsonArray(List(9) { JsonObject(emptyMap()) }),
        )) assertFails(key) { project(JsonObject(record() + (key to value))) }
    }

    @Test fun `actual persisted writer records retain distinct attempt and writer identity`() {
        val root = Files.createTempDirectory("web-progress-projection-")
        try {
            AgentProgressJournal(root, "reconstruct").use { journal ->
                journal.phase(decompengine.agent.AgentWorkflowPhase.PLANNING, taskId = "t".repeat(600))
            }
            val journal = AgentProgressJournal.decode(Files.readAllBytes(root.resolve(AgentProgressJournal.FILE_NAME)))
            assertTrue(journal.getValue("events").jsonArray.size >= 2)
            var sawTruncatedTask = false
            for (raw in journal.getValue("events").jsonArray) {
                val event = webProgressObservation("job_fixture", "attempt_fixture", "cursor_fixture", raw.jsonObject)
                assertEquals("attempt_fixture", event.getValue("runId").jsonPrimitive.content)
                val payload = event.getValue("payload").jsonObject
                assertNotEquals("attempt_fixture", payload.getValue("writerId").jsonPrimitive.content)
                assertEquals("0", payload.getValue("omittedFieldCount").jsonPrimitive.content)
                payload.getValue("fields").jsonObject["taskId"]?.jsonPrimitive?.content?.let { task ->
                    assertEquals(533, task.length); assertTrue(task.endsWith("… [preview truncated]")); sawTruncatedTask = true
                }
            }
            assertTrue(sawTruncatedTask)
        } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }
}
