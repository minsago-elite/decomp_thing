package decompengine.repair

import decompengine.binary.ElfMetadata
import decompengine.jobs.Job
import decompengine.presentRepairOutcome
import decompengine.web.RepairEvidenceArtifactState
import decompengine.web.repairReceiptBindingIdentity
import decompengine.web.WebArtifactSummary
import decompengine.web.renderRepairHistory
import java.nio.file.Path
import kotlinx.serialization.json.*
import kotlin.test.*

class RepairHistoryPresentationTest {
    private val job = Job("fixture", "fixture", "complete", "now", sizeBytes = 0, binaryPath = Path.of("fixture"),
        metadata = ElfMetadata("ELF64", "little", 1u, "fixture", "executable", "fixture", 0uL, 0u, 0u, 0u, 0u))
    private val run = RepairRunState("run_00000001", RepairRunStatus.REJECTED, "baseline", "revision_00000001_aaaaaaaaaaaaaaaa",
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
                revisionId = "revision_00000002_bbbbbbbbbbbbbbbb", runId = run.id,
                after = if (expected == "validation-failed") RepairEvidence("assessment-error", "fixture") else null)
            val payload = Json.parseToJsonElement(renderRepairHistoryProjection(listOf(iteration), emptyList(),
                MAXIMUM_REPAIR_PROJECTION_BYTES, runs = listOf(run))).jsonObject
            val persisted = payload.getValue("iterations").jsonArray.single().jsonObject
            assertEquals(expected, repairAttemptLabel(persisted))
            val cli = presentRepairOutcome(RepairRunOutcome(listOf(iteration), null, run))
            assertTrue(cli.lines.contains("repair iteration 7: $expected"), cli.toString())
            val html = renderRepairHistory(job, payload = payload)
            assertTrue(html.contains("Repair attempt — $expected"), html)
            assertTrue(html.contains("Accepted revision: <code>revision_00000001_aaaaaaaaaaaaaaaa</code>"), html)
            assertTrue(html.contains("Attempt revision: <code>revision_00000002_bbbbbbbbbbbbbbbb</code>"), html)
            assertFalse(html.contains("Accepted revision: <code>revision_00000002_bbbbbbbbbbbbbbbb</code>"))
            assertTrue(cli.lines.contains("accepted revision: revision_00000001_aaaaaaaaaaaaaaaa"))
        }
    }

    @Test fun `legacy unknown or missing disposition cannot inherit receipt acceptance`() {
        for (disposition in listOf("legacy_unverified", "unknown", null)) {
            val iteration = canonicalAcceptedJson()
            val fields = iteration.toMutableMap().apply {
                if (disposition == null) remove("disposition") else put("disposition", JsonPrimitive(disposition))
            }
            assertEquals("unverified", repairAttemptLabel(JsonObject(fields)))
        }
    }

    @Test fun `malformed or missing ACP binding cannot authorize acceptance`() {
        val iteration = canonicalAcceptedJson()
        val binding = iteration.getValue("agentInvocation").jsonObject
        val malformed = binding.keys.map { JsonObject(binding - it) } + listOf(
            JsonPrimitive("invalid"), JsonArray(emptyList()), JsonObject(emptyMap()),
            JsonObject(binding + ("receiptSha256" to JsonPrimitive("bad"))),
            JsonObject(binding + ("receiptReleaseComplete" to JsonPrimitive(false))),
            JsonObject(binding + ("assessmentStatus" to JsonPrimitive("unknown"))),
            JsonNull,
        )
        malformed.forEach { value ->
            assertEquals("unverified", repairAttemptLabel(JsonObject(iteration + ("agentInvocation" to value))), value.toString())
        }
        assertEquals("unverified", repairAttemptLabel(JsonObject(iteration - "agentInvocation")))
        assertEquals("accepted", repairAttemptLabel(iteration))
        val missingBinding = RepairIteration(1, "compile", "", "", emptyList(), emptyList(),
            disposition = RepairAttemptDisposition.FULLY_ACCEPTED, publicationMode = RepairPublicationMode.ACP_RELEASE)
        assertEquals("unverified", repairAttemptLabel(missingBinding))
        assertEquals("accepted", repairAttemptLabel(missingBinding.copy(publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE)))
    }

    private fun canonicalAcceptedJson(): JsonObject = Json.parseToJsonElement("""{
        "index":1,"failureKind":"behavior","prompt":"","summary":"","succeeded":true,
        "retainedRegressionIds":[],"before":null,"after":null,"patches":[],
        "disposition":"fully_accepted","publicationMode":"acp_release",
        "revisionId":"revision_00000001_aaaaaaaaaaaaaaaa","parentRevisionId":"baseline","runId":null,
        "agentInvocation":{"receiptPath":"reports/repair-revisions/revision_fixture.acp-receipt.json",
        "receiptSha256":"${"a".repeat(64)}","receiptSchemaVersion":2,"requestSha256":"${"b".repeat(64)}",
        "resultChangesSha256":"${"c".repeat(64)}","terminalOutcome":"returned-completed",
        "receiptReleaseComplete":true,"assessmentStatus":"accepted"}}""").jsonObject

    @Test fun `zero attempt run status and accepted identity remain visible`() {
        for ((status, label) in listOf(RepairRunStatus.RUNNING to "pending",
            RepairRunStatus.FULLY_ACCEPTED to "accepted", RepairRunStatus.ITERATION_EXHAUSTED to "limit-exhausted",
            RepairRunStatus.CANCELLED to "cancelled", RepairRunStatus.VALIDATION_FAILED to "validation-failed")) {
            val state = run.copy(status = status, attemptedCount = 0)
            val payload = Json.parseToJsonElement(renderRepairHistoryProjection(emptyList(), emptyList(),
                MAXIMUM_REPAIR_PROJECTION_BYTES, runs = listOf(state))).jsonObject
            val html = renderRepairHistory(job, payload = payload)
            assertTrue(html.contains("Repair run: $label"), html)
            assertTrue(html.contains("0/10 attempts"), html)
            assertTrue(html.contains("Accepted revision: <code>revision_00000001_aaaaaaaaaaaaaaaa</code>"), html)
            assertTrue(presentRepairOutcome(RepairRunOutcome(emptyList(), null, state)).lines.first().contains(": $label"))
        }
    }

    @Test fun `legacy success alone is unverified and revision identities are escaped`() {
        val payload = Json.parseToJsonElement("""{"iterations":[{"index":9,
            "failureKind":"behavior","prompt":"","summary":"","succeeded":true,
            "retainedRegressionIds":[],"before":null,"after":null,"patches":[]}]}""").jsonObject
        val html = renderRepairHistory(job, payload = payload)
        assertTrue(html.contains("Behavior repair — unverified"), html)
        assertFalse(html.contains("Behavior repair — accepted"))
    }

    @Test fun `history shows bounded rollback and evidence assurance without peer text`() {
        val payload = Json.parseToJsonElement("""{
            "schemaVersion":3,"runs":[],"regressionInputs":[],
            "iterations":[{
                "index":4,"failureKind":"behavior","summary":"PRIVATE summary","prompt":"PRIVATE prompt",
                "succeeded":false,"disposition":"rejected","publicationMode":"test_only_non_release",
                "agentInvocation":null,"patches":[],
                "revisionId":"revision_00000004_cccccccccccccccc",
                "retainedRegressionIds":["PRIVATE case"],
                "before":{"kind":"behavior","summary":"PRIVATE before","artifactPath":"reports/before.diff.json"},
                "after":{"kind":"valid","summary":"PRIVATE after","artifactPath":"reports/foreign.json"}
            }]
        }""").jsonObject
        val artifacts = listOf(WebArtifactSummary("reports/before.diff.json", "before.diff.json", 30))
        val html = renderRepairHistory(job, payload = payload, authorizedArtifacts = artifacts,
            artifactStates = mapOf("reports/before.diff.json" to RepairEvidenceArtifactState.CORRUPT))

        assertTrue(html.contains("Rollback: Completed; the rejected candidate did not advance the source head."), html)
        assertTrue(html.contains("Test-only evidence; release completeness is not established."), html)
        assertTrue(html.contains("Retained evidence is corrupt."), html)
        assertTrue(html.contains("Evidence artifact is unavailable."), html)
        assertTrue(html.contains("Retained regression cases:</b> 1"), html)
        listOf("PRIVATE summary", "PRIVATE prompt", "PRIVATE case", "PRIVATE before", "PRIVATE after", "foreign.json")
            .forEach { assertFalse(html.contains(it), html) }
    }

    @Test fun `accepted outcome stays accepted while a missing receipt withholds completeness`() {
        val accepted = canonicalAcceptedJson()
        val payload = JsonObject(mapOf("schemaVersion" to JsonPrimitive(3),
            "regressionInputs" to JsonArray(emptyList()), "runs" to JsonArray(emptyList()),
            "iterations" to JsonArray(listOf(accepted))))
        val html = renderRepairHistory(job, payload = payload)

        assertTrue(html.contains("Behavior repair — accepted"), html)
        assertTrue(html.contains("ACP receipt is unavailable; release completeness is not established."), html)
    }

    @Test fun `empty supported projection differs from missing or malformed history`() {
        val emptyProjection = Json.parseToJsonElement(renderRepairHistoryProjection(emptyList(), emptyList(),
            MAXIMUM_REPAIR_PROJECTION_BYTES)).jsonObject
        assertTrue(renderRepairHistory(job, payload = emptyProjection).contains("No repair attempts are recorded."))

        val malformed = listOf(
            JsonObject(emptyProjection - "iterations"),
            JsonObject(emptyProjection - "runs"),
            JsonObject(emptyProjection - "regressionInputs"),
            JsonObject(emptyProjection + ("iterations" to JsonObject(emptyMap()))),
            JsonObject(emptyProjection + ("runs" to JsonPrimitive("not-an-array"))),
            JsonObject(emptyProjection + ("iterations" to JsonArray(listOf(JsonNull)))),
            JsonObject(emptyProjection + ("iterations" to JsonArray(listOf(JsonObject(mapOf(
                "index" to JsonPrimitive("wrong-type"), "failureKind" to JsonPrimitive("behavior"),
                "summary" to JsonPrimitive("fixture"), "disposition" to JsonPrimitive("rejected"),
                "publicationMode" to JsonPrimitive("test_only_non_release"),
            )))))),
        )
        malformed.forEach { payload ->
            val html = renderRepairHistory(job, payload = payload)
            assertTrue(html.contains("Repair history is unavailable or corrupt."), html)
            assertFalse(html.contains("No repair attempts are recorded."), html)
        }

        val validIteration = canonicalAcceptedJson()
        for ((field, invalid) in listOf("failureKind" to JsonPrimitive(3), "summary" to JsonPrimitive(false))) {
            val payload = JsonObject(emptyProjection + ("iterations" to JsonArray(listOf(
                JsonObject(validIteration + (field to invalid)),
            ))))
            val html = renderRepairHistory(job, payload = payload)
            assertTrue(html.contains("Repair history is unavailable or corrupt."), html)
            assertFalse(html.contains("No repair attempts are recorded."), html)
        }

        val legacyWithoutRegressionInputs = Json.parseToJsonElement("""{"iterations":[{"index":1,
            "failureKind":"behavior","prompt":"","summary":"legacy","succeeded":true,
            "retainedRegressionIds":[],"before":null,"after":null,"patches":[]}] }""").jsonObject
        assertTrue(renderRepairHistory(job, payload = legacyWithoutRegressionInputs)
            .contains("Behavior repair — unverified"))
        val schemaTwoWithoutRegressionInputs = Json.parseToJsonElement("""{"schemaVersion":2,"iterations":[{"index":1,
            "failureKind":"behavior","prompt":"","summary":"legacy","succeeded":false,
            "retainedRegressionIds":[],"before":null,"after":null,"patches":[],
            "agentInvocation":null,"publicationMode":"test_only_non_release"}] }""").jsonObject
        assertTrue(renderRepairHistory(job, payload = schemaTwoWithoutRegressionInputs)
            .contains("Behavior repair — unverified"))
    }

    @Test fun `verified receipt state is bound to the complete invocation record`() {
        fun record(revision: String, requestDigest: String): JsonObject = Json.parseToJsonElement("""{
            "index":1,"failureKind":"behavior","prompt":"","summary":"","succeeded":true,
            "retainedRegressionIds":[],"before":null,"after":null,"patches":[],
            "disposition":"fully_accepted","publicationMode":"acp_release",
            "revisionId":"$revision","parentRevisionId":"baseline","runId":null,
            "agentInvocation":{"receiptPath":"reports/repair-revisions/revision_00000001_aaaaaaaaaaaaaaaa.acp-receipt.json",
            "receiptSha256":"${"a".repeat(64)}","receiptSchemaVersion":2,"requestSha256":"$requestDigest",
            "resultChangesSha256":"${"c".repeat(64)}","terminalOutcome":"returned-completed",
            "receiptReleaseComplete":true,"assessmentStatus":"accepted"}}""").jsonObject
        val first = record("revision_00000001_aaaaaaaaaaaaaaaa", "${"b".repeat(64)}")
        val second = record("revision_00000002_bbbbbbbbbbbbbbbb", "${"d".repeat(64)}")
        val identity = requireNotNull(repairReceiptBindingIdentity(first))
        val payload = JsonObject(mapOf("schemaVersion" to JsonPrimitive(3),
            "regressionInputs" to JsonArray(emptyList()), "runs" to JsonArray(emptyList()),
            "iterations" to JsonArray(listOf(first, second))))
        val html = renderRepairHistory(job, payload = payload,
            authorizedArtifacts = listOf(WebArtifactSummary(identity.receiptPath,
                "revision_00000001_aaaaaaaaaaaaaaaa.acp-receipt.json", 1)),
            receiptBindingStates = mapOf(identity to RepairEvidenceArtifactState.AVAILABLE))
        assertEquals(1, Regex("Release-complete ACP evidence; the retained receipt was verified\\.")
            .findAll(html).count(), html)
        assertTrue(html.contains("ACP receipt is unavailable; release completeness is not established."), html)
    }
}
