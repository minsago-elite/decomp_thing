package decompengine.repair

import decompengine.binary.ElfMetadata
import decompengine.jobs.Job
import decompengine.presentRepairOutcome
import decompengine.web.renderRepairHistory
import java.nio.file.Path
import kotlinx.serialization.json.*
import kotlin.test.*

class RepairHistoryPresentationTest {
    private val job = Job("fixture", "fixture", "complete", "now", sizeBytes = 0, binaryPath = Path.of("fixture"),
        metadata = ElfMetadata("ELF64", "little", 1u, "fixture", "executable", "fixture", 0uL, 0u, 0u, 0u, 0u))
    private val run = RepairRunState("run_00000001", RepairRunStatus.REJECTED, "baseline", "revision_prior",
        null, "a".repeat(64), 10, 1, 1, 2)

    @Test fun `persisted canonical outcomes have matching distinct CLI and web labels`() {
        val cases = listOf(
            Triple("returned-completed", RepairAgentAssessmentStatus.PENDING, "pending"),
            Triple("returned-completed", RepairAgentAssessmentStatus.ACCEPTED, "accepted"),
            Triple("returned-completed", RepairAgentAssessmentStatus.REJECTED, "rejected"),
            Triple("returned-no-changes", RepairAgentAssessmentStatus.REJECTED, "no-change"),
            Triple("returned-refused", RepairAgentAssessmentStatus.REJECTED, "refused"),
            Triple("returned-cancelled", RepairAgentAssessmentStatus.REJECTED, "cancelled"),
            Triple("returned-limit-exhausted", RepairAgentAssessmentStatus.REJECTED, "limit-exhausted"),
            Triple("failed-process-crash", RepairAgentAssessmentStatus.REJECTED, "process-crashed"),
            Triple("returned-completed", RepairAgentAssessmentStatus.REJECTED, "validation-failed"),
        )
        cases.forEach { (terminal, assessment, expected) ->
            val disposition = when (assessment) {
                RepairAgentAssessmentStatus.ACCEPTED -> RepairAttemptDisposition.FULLY_ACCEPTED
                RepairAgentAssessmentStatus.PENDING -> RepairAttemptDisposition.LEGACY_UNVERIFIED
                else -> RepairAttemptDisposition.REJECTED
            }
            val binding = RepairAgentInvocationBinding("reports/repair-revisions/revision_fixture.acp-receipt.json",
                "b".repeat(64), 2, "c".repeat(64), "d".repeat(64), terminal,
                terminal == "returned-completed", assessment)
            val iteration = RepairIteration(7, "fixture", "", "", emptyList(), emptyList(),
                // Deliberately contradictory legacy success cannot override the canonical assessment.
                succeeded = true, agentInvocation = binding, disposition = disposition,
                revisionId = "revision_candidate", runId = run.id,
                after = if (expected == "validation-failed") RepairEvidence("assessment-error", "fixture") else null)
            val payload = Json.parseToJsonElement(renderRepairHistoryProjection(listOf(iteration), emptyList(),
                MAXIMUM_REPAIR_PROJECTION_BYTES, runs = listOf(run))).jsonObject
            val persisted = payload.getValue("iterations").jsonArray.single().jsonObject
            assertEquals(expected, repairAttemptLabel(persisted))
            val cli = presentRepairOutcome(RepairRunOutcome(listOf(iteration), null, run))
            assertTrue(cli.lines.contains("repair iteration 7: $expected"), cli.toString())
            val html = renderRepairHistory(job, payload = payload)
            assertTrue(html.contains("fixture — $expected"), html)
            assertTrue(html.contains("Accepted revision: <code>revision_prior</code>"), html)
            assertTrue(html.contains("Attempt revision: <code>revision_candidate</code>"), html)
            assertFalse(html.contains("Accepted revision: <code>revision_candidate</code>"))
            assertTrue(cli.lines.contains("accepted revision: revision_prior"))
        }
    }

    @Test fun `older canonical assessments remain readable without a success boolean`() {
        for ((assessment, expected) in listOf("accepted" to "accepted", "pending" to "pending", "rejected" to "rejected")) {
            val iteration = Json.parseToJsonElement("""{"agentInvocation":{"assessmentStatus":"$assessment",
                "terminalOutcome":"returned-completed"}}""").jsonObject
            assertEquals(expected, repairAttemptLabel(iteration))
        }
    }

    @Test fun `zero attempt run status and accepted identity remain visible`() {
        for ((status, label) in listOf(RepairRunStatus.RUNNING to "pending",
            RepairRunStatus.FULLY_ACCEPTED to "accepted", RepairRunStatus.ITERATION_EXHAUSTED to "limit-exhausted",
            RepairRunStatus.CANCELLED to "cancelled", RepairRunStatus.VALIDATION_FAILED to "validation-failed")) {
            val state = run.copy(status = status, attemptedCount = 0)
            val payload = Json.parseToJsonElement(renderRepairHistoryProjection(emptyList(), emptyList(),
                MAXIMUM_REPAIR_PROJECTION_BYTES, runs = listOf(state))).jsonObject
            val html = renderRepairHistory(job, payload = payload)
            assertTrue(html.contains("run_00000001: $label"), html)
            assertTrue(html.contains("0/10 attempts"), html)
            assertTrue(html.contains("Accepted revision: <code>revision_prior</code>"), html)
            assertTrue(presentRepairOutcome(RepairRunOutcome(emptyList(), null, state)).lines.first().contains(": $label"))
        }
    }

    @Test fun `legacy success alone is unverified and revision identities are escaped`() {
        val payload = Json.parseToJsonElement("""{"runs":[{"id":"run_00000001","status":"rejected",
            "acceptedHeadId":"<prior>","attemptedCount":9,"maximumAttempts":10}],
            "iterations":[{"index":9,"succeeded":true,"revisionId":"<candidate>"}]}""").jsonObject
        val html = renderRepairHistory(job, payload = payload)
        assertTrue(html.contains("unknown — unverified"), html)
        assertTrue(html.contains("Accepted revision: <code>&lt;prior&gt;</code>"), html)
        assertTrue(html.contains("Attempt revision: <code>&lt;candidate&gt;</code>"), html)
        assertFalse(html.contains("<prior>") || html.contains("<candidate>"))
    }
}
