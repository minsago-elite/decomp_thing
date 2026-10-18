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

    @Test fun `legacy progress attachments project root and records without losing event accounting`() {
        val ranges = buildJsonArray {
            for ((start, end) in listOf(0 to 1, 3 to 4, 5 to 6)) add(buildJsonObject {
                put("startInclusive", start.toString()); put("endExclusive", end.toString())
            })
        }
        val input = buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", 6)
            put("queueDropped", 2); put("historyDropped", 1); put("truncated", true)
            put("omittedSequenceRanges", ranges); put("PRIVATE_ROOT_FIELD", "PRIVATE_ROOT_VALUE")
            put("events", buildJsonArray {
                add(buildJsonObject {
                    put("sequence", 1); put("kind", "message"); put("workflow", "repair"); put("runId", "writer-1")
                    put("text", "Authorization: [redacted] PRIVATE_TAIL"); put("textOmitted", false)
                    put("workflowRunId", "PRIVATE_RUN"); put("workflowRunIdSha256", "a".repeat(64))
                    put("inputTokens", 11); put("contextWindowTokens", "9007199254740993")
                    put("reportedCostAmount", "-0.0"); put("reportedCostCurrency", "USD")
                })
                add(buildJsonObject {
                    put("sequence", 2); put("kind", "plan"); put("entryCount", 1); put("entriesTruncated", false)
                    put("entries", buildJsonArray { add(buildJsonObject { put("text", "PRIVATE_PLAN") }) })
                })
                add(buildJsonObject { put("sequence", 4); put("kind", "agent_finished"); put("stopReason", "completed"); put("validationPending", true) })
            })
        }
        val expected = buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", 6)
            put("queueDropped", 2); put("historyDropped", 1); put("truncated", true)
            put("omittedSequenceRanges", ranges); put("replayOmittedFields", 1)
            put("events", buildJsonArray {
                add(buildJsonObject {
                    put("sequence", 1); put("kind", "message"); put("workflow", "repair"); put("runId", "writer-1")
                    put("textOmitted", true); put("workflowRunIdSha256", "a".repeat(64))
                    put("inputTokens", 11); put("contextWindowTokens", "9007199254740993")
                    put("reportedCostAmount", "-0.0"); put("reportedCostCurrency", "USD"); put("replayOmittedFields", 2)
                })
                add(buildJsonObject {
                    put("sequence", 2); put("kind", "plan"); put("entryCount", 1); put("entriesTruncated", false)
                    put("replayOmittedFields", 1)
                })
                add(buildJsonObject { put("sequence", 4); put("kind", "agent_finished"); put("stopReason", "completed"); put("validationPending", true) })
            })
        }
        val raw = input.toString().toByteArray(Charsets.UTF_8)
        for (path in listOf("reports/agent-progress.json", "reports/runs/attempt-1/agent-progress.json")) {
            val projected = progressArtifactProjection(path, raw)
            assertEquals(expected, AgentProgressJournal.decode(projected))
            assertContentEquals(projected, progressArtifactProjection(path, projected))
            assertTrue(projected.size <= AgentProgressJournal.MAXIMUM_READ_BYTES)
            assertFalse(projected.toString(Charsets.UTF_8).contains("PRIVATE"))
        }
        assertEquals(input, AgentProgressJournal.decode(raw))
        val expired = buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", 6)
            put("queueDropped", 2); put("historyDropped", 4); put("truncated", true)
            put("events", JsonArray(emptyList())); put("retentionExpiredAt", "2026-10-18T00:00:00Z")
        }
        assertEquals(expired, AgentProgressJournal.decode(progressArtifactProjection("reports/agent-progress.json",
            expired.toString().toByteArray(Charsets.UTF_8))))
    }

    @Test fun `progress attachment namespaces and limits preserve unrelated bytes and withhold failures`() {
        val arbitrary = byteArrayOf(0xff.toByte(), 0, 1)
        for (path in listOf("reports/source-tree/agent-progress.json", "reports/receipts/agent-progress.json",
            "reports/runs/attempt-1/source-tree/agent-progress.json", "reports/runs/attempt-1/receipts/agent-progress.json",
            "reports/agent-progress.json.source")) {
            assertFalse(isProgressJournalArtifact(path))
            assertSame(arbitrary, progressArtifactProjection(path, arbitrary))
        }
        for (path in listOf("../reports/agent-progress.json", "/reports/agent-progress.json", "reports//agent-progress.json",
            "reports/../agent-progress.json", "reports\\agent-progress.json", "reports/runs/-invalid/agent-progress.json")) {
            assertFailsWith<IllegalArgumentException> { isProgressJournalArtifact(path) }
        }
        val base = buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", 1)
            put("queueDropped", 0); put("historyDropped", 0); put("truncated", false)
            put("events", buildJsonArray { add(buildJsonObject { put("sequence", 0); put("kind", "run_started") }) })
        }
        val invalidRootCount = JsonObject(base + ("replayOmittedFields" to JsonPrimitive("PRIVATE_INVALID_COUNT")))
        val overflowRootCount = JsonObject(base + mapOf("replayOmittedFields" to JsonPrimitive(Int.MAX_VALUE),
            "PRIVATE_UNKNOWN_FIELD" to JsonPrimitive("PRIVATE_VALUE")))
        for (bytes in listOf("PRIVATE_PARSER_INPUT".toByteArray(), arbitrary,
            invalidRootCount.toString().toByteArray(), overflowRootCount.toString().toByteArray(),
            ByteArray(AgentProgressJournal.MAXIMUM_READ_BYTES + 1))) {
            val copy = bytes.copyOf()
            val failure = assertFailsWith<WebJobServiceException> {
                progressArtifactProjection("reports/agent-progress.json", bytes)
            }
            assertEquals("PROGRESS_UNAVAILABLE", failure.code)
            assertEquals("The retained progress report is unavailable.", failure.message)
            assertNull(failure.cause)
            assertContentEquals(copy, bytes)
        }
    }

    @Test fun `projection matches the shared contract fixture without promoting reported acceptance`() {
        assertEquals(Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/fixtures/event-observation-public-metadata.json"))), project(record()))
    }

    @Test fun `plan prose and raw task labels are withheld despite upstream truncation markers`() {
        val expected = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/fixtures/event-observation-truncated-preview.json"))).jsonObject
        val source = JsonObject(record(expected) + ("futureField" to JsonPrimitive("omitted")))
        assertEquals(Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/fixtures/event-observation-plan-metadata.json"))), project(source))
    }

    @Test fun `unknown fields are counted but not copied into observations`() {
        val event = project(JsonObject(record() + ("future_private_field" to JsonPrimitive("must not escape"))))
        val payload = event.getValue("payload").jsonObject
        assertEquals("3", payload.getValue("omittedFieldCount").jsonPrimitive.content)
        assertFalse(event.toString().contains("must not escape"))
        assertFalse(event.toString().contains("future_private_field"))
        assertEquals("observations", payload.getValue("authority").jsonPrimitive.content)
    }

    @Test fun `known message roles retain typed state while prose and paths are withheld`() {
        for (role in listOf("thought", "system", "assistant", "user")) {
            val output = project(JsonObject(record() + mapOf(
                "role" to JsonPrimitive(role), "text" to JsonPrimitive("PRIVATE_PROSE"),
                "path" to JsonPrimitive("/PRIVATE_HOST_ROOT/input"), "textOmitted" to JsonPrimitive(false),
            )))
            val payload = output.getValue("payload").jsonObject
            val fields = payload.getValue("fields").jsonObject
            assertFalse(output.toString().contains("PRIVATE_"))
            assertEquals("true", fields.getValue("textOmitted").jsonPrimitive.content)
            assertEquals("3", payload.getValue("omittedFieldCount").jsonPrimitive.content)
            assertEquals(role, fields.getValue("role").jsonPrimitive.content)
            assertEquals("18446744073709551615", fields.getValue("inputTokens").jsonPrimitive.content)
        }
    }

    @Test fun `invalid known values fail instead of silently changing counts or flags`() {
        for ((key, value) in listOf(
            "inputTokens" to JsonPrimitive(-1), "inputTokens" to JsonPrimitive("18446744073709551616"),
            "inputTokens" to JsonPrimitive("1e3"), "completed" to JsonPrimitive("true"),
            "requestSha256" to JsonPrimitive("invalid"),
            "runId" to JsonPrimitive("invalid/path"), "agentSequence" to JsonPrimitive("01"),
            "wallClock" to JsonPrimitive("-PT1S"), "role" to JsonObject(emptyMap()),
        )) assertFails(key) { project(JsonObject(record() + (key to value))) }
    }

    @Test fun `legacy and v1 projection suppress private labels prose paths plans and forward values`() {
        val private = JsonObject(record() + mapOf(
            "workflow" to JsonPrimitive("future_ENV_SECRET_workflow"),
            "kind" to JsonPrimitive("future_raw_exception_kind"),
            "taskId" to buildJsonObject { put("nested", "RAW_TASK_ENV_SECRET") },
            "workflowRunId" to JsonPrimitive("RAW_RUN_/PRIVATE_HOST_ROOT"),
            "revisionId" to JsonPrimitive("RAW_REV_IllegalStateException"),
            "path" to JsonPrimitive("/PRIVATE_HOST_ROOT/input.elf"),
            "text" to JsonPrimitive("ENV_SECRET=private IllegalStateException(/PRIVATE_HOST_ROOT)"),
            "role" to JsonPrimitive("future_PRIVATE_ROLE"),
            "entries" to JsonArray(listOf(buildJsonObject {
                put("idSha256", "f".repeat(64)); put("status", "future_plan_state"); put("text", "PRIVATE_PLAN_TEXT")
            })),
        ))
        val versioned = project(private)
        val legacy = legacyProgressPresentation(buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", "9007199254740994")
            put("queueDropped", 0); put("historyDropped", 0); put("truncated", false)
            put("events", JsonArray(listOf(private)))
        })

        for (wire in listOf(versioned.toString(), legacy.toString())) {
            for (privateValue in listOf("ENV_SECRET", "PRIVATE_HOST_ROOT", "IllegalStateException", "RAW_TASK", "RAW_RUN", "RAW_REV", "PRIVATE_PLAN_TEXT", "future_PRIVATE_ROLE")) {
                assertFalse(wire.contains(privateValue), privateValue)
            }
        }
        val payload = versioned.getValue("payload").jsonObject
        assertEquals("unknown", payload.getValue("workflow").jsonPrimitive.content)
        assertEquals("unknown", payload.getValue("observationKind").jsonPrimitive.content)
        assertEquals("7", payload.getValue("omittedFieldCount").jsonPrimitive.content)
        assertEquals("unknown", legacy.getValue("events").jsonArray.single().jsonObject.getValue("workflow").jsonPrimitive.content)
        assertEquals("unknown", legacy.getValue("events").jsonArray.single().jsonObject.getValue("kind").jsonPrimitive.content)
    }

    @Test fun `metadata sparse legacy records remain readable without invented identity or time`() {
        val legacy = legacyProgressPresentation(buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", 1)
            put("queueDropped", 0); put("historyDropped", 0); put("truncated", false)
            put("events", buildJsonArray { add(buildJsonObject {
                put("sequence", 0); put("kind", "future_message_kind")
                put("role", "future_PRIVATE_ROLE"); put("text", "ENV_SECRET=/PRIVATE_HOST_ROOT")
            }) })
        })
        val event = legacy.getValue("events").jsonArray.single().jsonObject
        assertEquals("unknown", event.getValue("kind").jsonPrimitive.content)
        assertFalse(event.containsKey("runId")); assertFalse(event.containsKey("workflow")); assertFalse(event.containsKey("time"))
        assertEquals("2", event.getValue("presentationOmittedFields").jsonPrimitive.content)
        assertFalse(legacy.toString().contains("PRIVATE")); assertFalse(legacy.toString().contains("ENV_SECRET"))
    }

    @Test fun `actual persisted writer records retain distinct attempt and writer identity`() {
        val root = Files.createTempDirectory("web-progress-projection-")
        try {
            AgentProgressJournal(root, "reconstruct").use { journal ->
                journal.phase(decompengine.agent.AgentWorkflowPhase.PLANNING, taskId = "t".repeat(600))
            }
            val journal = AgentProgressJournal.decode(Files.readAllBytes(root.resolve(AgentProgressJournal.FILE_NAME)))
            assertTrue(journal.getValue("events").jsonArray.size >= 2)
            var sawWithheldTask = false
            for (raw in journal.getValue("events").jsonArray) {
                val event = webProgressObservation("job_fixture", "attempt_fixture", "cursor_fixture", raw.jsonObject)
                assertEquals("attempt_fixture", event.getValue("runId").jsonPrimitive.content)
                val payload = event.getValue("payload").jsonObject
                assertNotEquals("attempt_fixture", payload.getValue("writerId").jsonPrimitive.content)
                assertFalse(payload.getValue("fields").jsonObject.containsKey("taskId"))
                if (payload.getValue("omittedFieldCount").jsonPrimitive.content == "1") sawWithheldTask = true
            }
            assertTrue(sawWithheldTask)
        } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }
}
