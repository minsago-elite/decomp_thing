package decompengine.jobs

import decompengine.testing.recoveryMatrixTempDirectory
import decompengine.testing.RecoveryMatrixEvidence
import decompengine.web.WorkflowExecutionMeter
import decompengine.web.webRun
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import java.nio.file.Files
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.*

@ExtendWith(RecoveryMatrixEvidence::class)
class WorkflowUsageProvenanceTest {
    @Test fun `meter provenance and nullable counters survive store reload and public projection`() {
        val root = recoveryMatrixTempDirectory("usage-provenance-")
        try {
            val sampleTime = Instant.parse("2026-01-02T03:04:05Z")
            val endTime = Instant.parse("2026-01-02T03:05:00Z")
            var now = sampleTime.minusSeconds(1)
            val clock = object : Clock() {
                override fun getZone() = ZoneOffset.UTC
                override fun withZone(zone: java.time.ZoneId) = Clock.fixed(now, zone)
                override fun instant(): Instant = now
            }
            val job = JobStore(root).createFromUpload("sample.elf", elfFixture()).id
            val run = WorkflowAttemptStore.open(root, clock).use { store ->
                val version = (store.inspect(job) as WorkflowJobInspection.Available).snapshot.version
                val created = store.create(job, version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                    WorkflowExecutionLimits(60_000u, 60_000u, 1024u, 10u))).attempt
                val started = store.transition(job, created.runId, created.version, WorkflowTransition.Start).attempt
                now = sampleTime
                val sampled = WorkflowExecutionMeter(root, toolCallsMetered = true, clock = clock).usage(0)
                now = endTime
                store.transition(job, started.runId, started.version,
                    WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED, usage = sampled)).attempt
            }
            val disk = root.resolve(job).resolve("workflow-state.json")
            val json = Json.parseToJsonElement(Files.readString(disk)).jsonObject
            val persistedUsage = json["attempts"]!!.jsonArray.single().jsonObject["usage"]!!.jsonObject
            val provenance = persistedUsage["localMeasurement"]!!.jsonObject
            assertEquals(setOf("source", "sampledAt", "fields"), provenance.keys)
            assertEquals("workflow-execution-meter", provenance["source"]!!.jsonPrimitive.content)
            assertEquals(sampleTime.toString(), provenance["sampledAt"]!!.jsonPrimitive.content)
            assertEquals(listOf("wallClockMs", "toolCalls"), provenance["fields"]!!.jsonArray.map { it.jsonPrimitive.content })

            WorkflowAttemptStore.open(root, Clock.fixed(endTime, ZoneOffset.UTC)).use { reopened ->
                val reloaded = (reopened.inspect(job) as WorkflowJobInspection.Available).snapshot.latestRun!!
                assertEquals(run.usage, reloaded.usage)
                assertEquals(endTime, reloaded.endedAt)
                assertNotEquals(reloaded.endedAt, reloaded.usage!!.localMeasurement!!.sampledAt)
                val api = webRun(reloaded)["usage"]!!.jsonObject
                assertEquals("workflow-execution-meter", api["localMeasurement"]!!.jsonObject["source"]!!.jsonPrimitive.content)
                assertEquals(setOf("source", "sampledAt", "fields"), api["localMeasurement"]!!.jsonObject.keys)
                assertEquals("0", api["toolCalls"]!!.jsonPrimitive.content)
                assertEquals("0", api["wallClockMs"]!!.jsonPrimitive.content)
                assertEquals(JsonNull, api["inputTokens"])
                assertEquals(JsonNull, api["outputTokens"])
                assertEquals(JsonNull, api["cachedInputTokens"])
            }
        } finally { root.toFile().deleteRecursively() }
    }

    @Test fun `legacy persisted usage without provenance remains readable and missing metrics stay null`() {
        val root = recoveryMatrixTempDirectory("legacy-usage-")
        try {
            val job = JobStore(root).createFromUpload("legacy.elf", elfFixture()).id
            val run = WorkflowAttemptStore.open(root).use { store ->
                val snapshot = (store.inspect(job) as WorkflowJobInspection.Available).snapshot
                val created = store.create(job, snapshot.version,
                    NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60_000u, 60_000u, 1024u, 10u))).attempt
                val started = store.transition(job, created.runId, created.version, WorkflowTransition.Start).attempt
                store.transition(job, started.runId, started.version,
                    WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED,
                        usage = WorkflowUsage(inputTokens = 9u, toolCalls = null, wallClockMs = null))).attempt
            }
            val stateFile = root.resolve(job).resolve("workflow-state.json")
            val rootJson = Json.parseToJsonElement(Files.readString(stateFile)).jsonObject
            val oldUsage = run.usage!!
            val legacyUsage = buildJsonObject {
                put("inputTokens", oldUsage.inputTokens!!.toString()); put("outputTokens", JsonNull)
                put("cachedInputTokens", JsonNull); put("toolCalls", JsonNull); put("wallClockMs", JsonNull)
            }
            val attemptList = rootJson["attempts"]!!.jsonArray
            val oldAttempt = attemptList.single().jsonObject
            Files.writeString(stateFile, JsonObject(rootJson + ("attempts" to JsonArray(listOf(JsonObject(oldAttempt + ("usage" to legacyUsage)))))).toString())
            WorkflowAttemptStore.open(root).use { reopened ->
                val usage = (reopened.inspect(job) as WorkflowJobInspection.Available).snapshot.latestRun!!.usage!!
                assertEquals(9uL, usage.inputTokens)
                assertNull(usage.localMeasurement)
                assertNull(usage.toolCalls); assertNull(usage.wallClockMs)
                val api = webRun((reopened.inspect(job) as WorkflowJobInspection.Available).snapshot.latestRun!!)["usage"]!!.jsonObject
                assertEquals(JsonNull, api["toolCalls"]); assertEquals(JsonNull, api["wallClockMs"])
                assertFalse("localMeasurement" in api)
            }
        } finally { root.toFile().deleteRecursively() }
    }
}
