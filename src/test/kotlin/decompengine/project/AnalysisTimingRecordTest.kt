package decompengine.project

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AnalysisTimingRecordTest {
    @Test
    fun `complete correlated worker phase stream is retained in a fresh sidecar`() {
        val directory = Files.createTempDirectory(java.nio.file.Path.of("build"), "analysis-timing-record-").resolve("timings")
        val record = newRecord(directory)
        record.measure("worker-process-lifecycle") { Unit }
        val phases = listOf(
            "worker-entry-to-parent-permit",
            "application-initialization",
            "project-import-analysis-pre-script",
            "exporter:ExportProgramModelOwned.java",
        )
        val events = buildList {
            var sequence = 0
            phases.forEachIndexed { index, phase ->
                add(frame(record, sequence++, "begin", phase, index * 20L))
                add(frame(record, sequence++, "end", phase, index * 20L + 10L))
            }
            add(frame(record, sequence, "terminal", "succeeded", 100L))
        }.joinToString("\n", postfix = "\n")
        record.captureWorkerTelemetry(events.toByteArray(StandardCharsets.UTF_8), truncated = false)
        record.publish(success = true)

        val file = directory.toFile().listFiles().orEmpty().single()
        val document = Json.parseToJsonElement(file.readText()).jsonObject
        assertEquals("succeeded", document.getValue("terminalStatus").jsonPrimitive.content)
        assertEquals("succeeded", document.getValue("workerTerminalStatus").jsonPrimitive.content)
        assertEquals(4, document.getValue("workerSpans").jsonArray.size)
        val coverage = document.getValue("coverage").jsonObject
        assertEquals("true", coverage.getValue("complete").jsonPrimitive.content)
        assertEquals(0, coverage.getValue("missingPhases").jsonArray.size)
    }

    @Test
    fun `truncated or mismatched worker telemetry remains incomplete without failing analysis`() {
        val directory = Files.createTempDirectory(java.nio.file.Path.of("build"), "analysis-timing-incomplete-").resolve("timings")
        val first = newRecord(directory)
        first.captureWorkerTelemetry(frame(first, 0, "begin", "application-initialization", 1L)
            .toByteArray(StandardCharsets.UTF_8), truncated = true)
        first.publish(success = true)
        val firstDocument = Json.parseToJsonElement(directory.toFile().listFiles().orEmpty().single().readText()).jsonObject
        assertEquals("true", firstDocument.getValue("coverage").jsonObject.getValue("truncated").jsonPrimitive.content)
        assertEquals("false", firstDocument.getValue("coverage").jsonObject.getValue("complete").jsonPrimitive.content)

        val second = newRecord(directory)
        second.captureWorkerTelemetry("DECOMP_ANALYSIS_TIMING_V1 00000000-0000-0000-0000-000000000000 0 begin application-initialization 1\n"
            .toByteArray(StandardCharsets.UTF_8), truncated = false)
        second.publish(success = true)
        val documents = directory.toFile().listFiles().orEmpty().map { Json.parseToJsonElement(it.readText()).jsonObject }
        assertEquals(2, documents.size)
        assertNotEquals(
            documents[0].getValue("analysisInvocationId").jsonPrimitive.content,
            documents[1].getValue("analysisInvocationId").jsonPrimitive.content,
        )
        assertTrue(documents.all { it.getValue("coverage").jsonObject.getValue("complete").jsonPrimitive.content == "false" })
        assertFalse(documents.any { it.getValue("workerTerminalStatus").jsonPrimitive.content == "succeeded" })
    }

    @Test
    fun `blocked sidecar publisher cannot hold analysis completion`() {
        val executor = Executors.newSingleThreadExecutor()
        val blocked = CountDownLatch(1)
        executor.submit { blocked.await() }
        val directory = java.nio.file.Path.of("build", "analysis-timing-blocked-${System.nanoTime()}")
        try {
            val record = AnalysisTimingRecord(
                directory, "full", "a".repeat(64), null, timingConfigurationSha256(listOf("fixture")),
                publicationExecutor = executor,
                publicationWaitMillis = 25,
            )
            val started = System.nanoTime()
            record.publish(success = false)
            val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue(elapsedMillis < 1_000, "sidecar publisher blocked for ${elapsedMillis}ms")
            assertFalse(Files.exists(directory))
        } finally {
            blocked.countDown()
            executor.shutdownNow()
        }
    }

    private fun newRecord(directory: java.nio.file.Path) =
        AnalysisTimingRecord(directory, "full", "a".repeat(64), null, timingConfigurationSha256(listOf("fixture")))

    private fun frame(record: AnalysisTimingRecord, sequence: Int, event: String, phase: String, elapsed: Long) =
        "DECOMP_ANALYSIS_TIMING_V1 ${record.invocationId} $sequence $event $phase $elapsed"
}
