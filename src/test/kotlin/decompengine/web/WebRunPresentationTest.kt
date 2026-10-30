package decompengine.web

import decompengine.jobs.*
import kotlinx.serialization.json.*
import java.time.Instant
import kotlin.test.*

class WebRunPresentationTest {
    @Test fun `configured responses retain the always-null v1 profile placeholder alongside additive reconstruction facts`() {
        val reconstruction = WorkflowAttemptReconstruction("generated-c-make-v1", "c".repeat(64), 60_000uL)
        val configuration = WorkflowAttemptConfiguration("workflow-reconstruct-agent-acp", "agent", false, true,
            listOf("ghidra", "agent-harness", "c-toolchain"), "none", true,
            WorkflowAttemptHarness("acp", "fixture-agent", 1, 1, "0.30.1", "a".repeat(64), false), reconstruction)
        val at = Instant.parse("2026-09-05T00:00:00Z")
        val run = WorkflowAttempt("run_1", "a".repeat(32), WorkflowKind.RECONSTRUCT,
            WorkflowRunState.RUNNING, "version_1", at, at, null, null, null, "agent-acp",
            WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u), null, null, null, null,
            configuration = configuration)
        val dto = webRun(run).getValue("configuration").jsonObject
        assertEquals(JsonNull, dto.getValue("profileId"), "older v1 clients require this field, but it conveys no profile authority")
        assertEquals("generated-c-make-v1", dto.getValue("reconstruction").jsonObject.getValue("profileId").jsonPrimitive.content)
        assertEquals("60000", dto.getValue("reconstruction").jsonObject.getValue("maxContextCharacters").jsonPrimitive.content)
        val unrecordedProfile = webRunConfiguration(configuration.copy(reconstruction = null))
        assertEquals(JsonNull, unrecordedProfile.getValue("profileId"))
        assertEquals(JsonNull, unrecordedProfile.getValue("reconstruction"))
    }

    @Test fun `completed candidate remains unaccepted and usage preserves unsigned precision`() {
        val at = Instant.parse("2026-09-05T00:00:00Z")
        val run = WorkflowAttempt("run_1", "a".repeat(32), WorkflowKind.RECONSTRUCT,
            WorkflowRunState.COMPLETED, "version_1", at, at, at.plusSeconds(1), null, null, null,
            WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u), WorkflowTerminalReason.COMPLETED,
            WorkflowUsage(inputTokens = ULong.MAX_VALUE, toolCalls = 0u), WorkflowCandidate("revision_1", "a".repeat(64)), null)
        val result = webRun(run)
        assertEquals("not-evaluated", result.getValue("acceptance").jsonPrimitive.content)
        assertEquals("revision_1", result.getValue("resultRevisionId").jsonPrimitive.content)
        val usage = result.getValue("usage").jsonObject
        assertEquals("18446744073709551615", usage.getValue("inputTokens").jsonPrimitive.content)
        assertEquals("0", usage.getValue("toolCalls").jsonPrimitive.content)
        assertEquals(JsonNull, usage.getValue("outputTokens"))
        val accepted = run.copy(acceptedRevision = WorkflowAcceptanceReference(run.jobId, run.runId,
            "revision_1", "a".repeat(64), "node_1", "artifact_1", "b".repeat(64)))
        assertEquals("accepted", webRun(accepted).getValue("acceptance").jsonPrimitive.content)
        assertFalse(result.toString().contains("sourceSha256"))
    }
}
