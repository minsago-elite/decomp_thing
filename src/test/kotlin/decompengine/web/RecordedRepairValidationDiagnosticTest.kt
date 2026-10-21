package decompengine.web

import decompengine.oracle.core.OracleJson
import decompengine.project.GeneratedCValidationFailurePhase
import decompengine.project.GeneratedCValidationFailureReason
import decompengine.project.GeneratedCValidationFailureRecord
import decompengine.project.sha256
import decompengine.repair.*
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RecordedRepairValidationDiagnosticTest {
    private val graph = "a".repeat(64)
    private fun invocation() = RepairValidationInvocation("validation_" + "b".repeat(32), "run_00000001",
        "root_" + "1".repeat(24), "2".repeat(64), "3".repeat(64), "4".repeat(64), "5".repeat(64))

    private data class Fixture(val receipt: ByteArray, val diagnostic: ByteArray,
        val binding: RepairRecordedValidationDiagnostic, val record: GeneratedCValidationFailureRecord,
        val primary: JsonObject) {
        fun withRecord(value: GeneratedCValidationFailureRecord): Fixture {
            val bytes = value.encode()
            return copy(diagnostic = bytes, binding = binding.copy(diagnosticSha256 = sha256(bytes), diagnosticBytes = bytes.size), record = value)
        }
    }

    private fun fixture(): Fixture {
        val invocation = invocation()
        val primary = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(2), "provider" to JsonPrimitive("generated-c-linux-bubblewrap-cgroup-v1"),
            "profileId" to JsonPrimitive("authored-data"), "sourceRevisionSha256" to JsonPrimitive(invocation.sourceRevisionSha256),
            "profileSha256" to JsonPrimitive(invocation.profileSha256), "indexSha256" to JsonPrimitive(invocation.indexSha256),
            "regressionCorpusSha256" to JsonPrimitive(invocation.regressionCorpusSha256), "runtimeSha256" to JsonPrimitive("6".repeat(64)),
            "runtimeConfiguration" to JsonObject(mapOf("privateCanary" to JsonPrimitive("PRIVATE-host-command-peer"))),
            "behaviorBudgetEvidence" to JsonObject(emptyMap()), "sourceSnapshot" to JsonNull, "buildOutputLink" to JsonNull,
            "originalExecutable" to JsonNull, "rebuiltExecutable" to JsonNull,
            "inputs" to JsonArray(List(3) { JsonObject(mapOf("id" to JsonPrimitive("PRIVATE-case-$it"),
                "args" to JsonArray(emptyList()), "stdinBase64" to JsonPrimitive(""))) }),
            "scopes" to JsonArray(emptyList()), "outcome" to JsonPrimitive("resource-exhausted"),
            "caseCount" to JsonPrimitive(0), "matches" to JsonPrimitive(false), "cleanupVerified" to JsonPrimitive(true),
            "assurance" to JsonPrimitive("strict-contained"),
        ))
        val receipt = OracleJson.canonicalBytes(primary)
        val record = GeneratedCValidationFailureRecord(sha256(receipt), invocation.sourceRevisionSha256,
            invocation.profileSha256, invocation.indexSha256, invocation.regressionCorpusSha256, "6".repeat(64),
            RepairValidationFailureKind.RESOURCE_EXHAUSTED, GeneratedCValidationFailureReason.TIMEOUT,
            GeneratedCValidationFailurePhase.SOURCE_PREPARATION, 3, invocation = invocation)
        val diagnostic = record.encode()
        val binding = RepairRecordedValidationDiagnostic(invocation.commitmentSha256(),
            RepairRecordedIdentity(invocation.candidateRevisionId, false), invocation.sourceRevisionSha256,
            invocation.profileSha256, invocation.indexSha256, invocation.regressionCorpusSha256, "6".repeat(64),
            recordedRepairArtifactReference(invocation.regressionCorpusSha256, "reports/fixture.validation.json"),
            sha256(receipt), receipt.size.toLong(), recordedRepairArtifactReference(invocation.regressionCorpusSha256,
                "reports/${invocation.id}.validation-failure.json"), sha256(diagnostic), diagnostic.size,
            RepairValidationFailureKind.RESOURCE_EXHAUSTED, true)
        return Fixture(receipt, diagnostic, binding, record, primary)
    }

    private fun view(fixture: Fixture) = checkedRecordedRepairValidationDiagnostic(fixture.binding, fixture.receipt, fixture.diagnostic)

    private fun withPrimary(f: Fixture, value: JsonObject): Fixture {
        val receipt = OracleJson.canonicalBytes(value)
        val record = f.record.copy(receiptSha256 = sha256(receipt))
        val diagnostic = record.encode()
        return f.copy(receipt = receipt, diagnostic = diagnostic, record = record, primary = value,
            binding = f.binding.copy(receiptSha256 = sha256(receipt), receiptBytes = receipt.size.toLong(),
                diagnosticSha256 = sha256(diagnostic), diagnosticBytes = diagnostic.size))
    }

    @Test
    fun `exact bound bytes expose only finite diagnostic labels`() {
        val result = view(fixture())
        assertEquals(RepairEvidenceArtifactState.AVAILABLE, result.state)
        assertEquals("timeout", result.reason)
        assertEquals("source-preparation", result.phase)
        assertNull(result.inputIndex)
        assertEquals(3, result.inputCount)
        assertFalse(result.toString().contains("PRIVATE"))
    }

    @Test
    fun `missing empty and withheld bytes remain unavailable`() {
        val f = fixture()
        for ((receipt, diagnostic) in listOf(null to f.diagnostic, f.receipt to null,
                ByteArray(0) to f.diagnostic, f.receipt to ByteArray(0))) {
            assertEquals(RepairEvidenceArtifactState.UNAVAILABLE,
                checkedRecordedRepairValidationDiagnostic(f.binding, receipt, diagnostic).state)
        }
    }

    @Test
    fun `changed receipt diagnostic and declared lengths are corrupt`() {
        val f = fixture()
        assertEquals(RepairEvidenceArtifactState.CORRUPT, view(f.copy(receipt = f.receipt + ' '.code.toByte())).state)
        assertEquals(RepairEvidenceArtifactState.CORRUPT, view(f.copy(diagnostic = f.diagnostic + ' '.code.toByte())).state)
        assertEquals(RepairEvidenceArtifactState.CORRUPT, view(f.copy(binding = f.binding.copy(receiptBytes = 1))).state)
        assertEquals(RepairEvidenceArtifactState.CORRUPT, view(f.copy(binding = f.binding.copy(diagnosticBytes = 1))).state)
    }

    @Test
    fun `identical primary bytes cannot cross pair a second nonce run or candidate`() {
        val f = fixture()
        val i = requireNotNull(f.record.invocation)
        for (other in listOf(i.copy(id = "validation_" + "c".repeat(32)), i.copy(runId = "run_00000002"),
                i.copy(candidateRevisionId = "root_" + "9".repeat(24)))) {
            val changed = f.withRecord(f.record.copy(invocation = other))
            assertEquals(RepairEvidenceArtifactState.CORRUPT, view(changed).state)
        }
    }

    @Test
    fun `each captured source profile index corpus runtime receipt and invocation commitment is checked`() {
        val f = fixture()
        val bad = "9".repeat(64)
        val bindings = listOf(f.binding.copy(sourceRevisionSha256 = bad), f.binding.copy(profileSha256 = bad),
            f.binding.copy(indexSha256 = bad), f.binding.copy(regressionCorpusSha256 = bad),
            f.binding.copy(runtimeSha256 = bad), f.binding.copy(receiptSha256 = bad), f.binding.copy(invocationSha256 = bad),
            f.binding.copy(candidate = RepairRecordedIdentity("root_" + "9".repeat(24), false)))
        bindings.forEach { binding -> assertEquals(RepairEvidenceArtifactState.CORRUPT, view(f.copy(binding = binding)).state) }
    }

    @Test
    fun `legacy schema one cannot become an invocation bound diagnostic`() {
        val f = fixture()
        assertEquals(RepairEvidenceArtifactState.CORRUPT, view(f.withRecord(f.record.copy(invocation = null))).state)
    }

    @Test
    fun `matching byte digests do not replace primary schema and semantic pairing`() {
        val f = fixture()
        val edits = listOf(f.primary - "scopes", f.primary + ("extra" to JsonPrimitive(true)),
            f.primary + ("schemaVersion" to JsonPrimitive("2")), f.primary + ("provider" to JsonPrimitive("other")),
            f.primary + ("sourceRevisionSha256" to JsonPrimitive("9".repeat(64))),
            f.primary + ("outcome" to JsonPrimitive("behavior-checked")), f.primary + ("matches" to JsonPrimitive(true)),
            f.primary + ("cleanupVerified" to JsonPrimitive(false)), f.primary + ("assurance" to JsonPrimitive("test-only")),
            f.primary + ("inputs" to JsonArray(emptyList())), f.primary + ("caseCount" to JsonPrimitive(4)),
            f.primary + ("caseCount" to JsonPrimitive(-1)))
        edits.forEach { fields -> assertEquals(RepairEvidenceArtifactState.CORRUPT, view(withPrimary(f, JsonObject(fields))).state) }
    }

    @Test
    fun `case position must follow completed cases and never supplies unobserved outcomes`() {
        val f = fixture()
        val advanced = withPrimary(f, JsonObject(f.primary + ("caseCount" to JsonPrimitive(1))))
        val selected = advanced.withRecord(advanced.record.copy(phase = GeneratedCValidationFailurePhase.ORIGINAL_OPERATION, inputIndex = 1))
        assertEquals(RepairEvidenceArtifactState.AVAILABLE, view(selected).state)
        assertEquals(1, view(selected).inputIndex)
        assertEquals(RepairEvidenceArtifactState.CORRUPT, view(selected.withRecord(selected.record.copy(inputIndex = 2))).state)
    }

    @Test
    fun `same path byte capture still produces a separate integrity decision for each invocation`() {
        val f = fixture()
        val good = checkedRecordedRepairValidationDiagnostic(f.binding, f.receipt, f.diagnostic)
        val other = f.binding.copy(invocationSha256 = "9".repeat(64))
        val bad = checkedRecordedRepairValidationDiagnostic(other, f.receipt, f.diagnostic)
        assertEquals(RepairEvidenceArtifactState.AVAILABLE, good.state)
        assertEquals(RepairEvidenceArtifactState.CORRUPT, bad.state)
        assertNull(bad.reason)
    }

    @Test
    fun `malformed and extra diagnostic fields cannot leak private text into a view`() {
        val f = fixture()
        val bytes = "{\"private\":\"PRIVATE-peer-message\"}".toByteArray()
        val changed = f.copy(diagnostic = bytes, binding = f.binding.copy(diagnosticSha256 = sha256(bytes), diagnosticBytes = bytes.size))
        val result = view(changed)
        assertEquals(RepairEvidenceArtifactState.CORRUPT, result.state)
        assertFalse(result.toString().contains("PRIVATE"))
    }

    @Test
    fun `run selection requires its graph and cannot combine owners`() {
        assertFailsWith<IllegalArgumentException> { RepairRecordedHistorySelection(evidenceRun = "run_00000001") }
        assertFailsWith<IllegalArgumentException> {
            RepairRecordedHistorySelection(expectedGraphSha256 = graph, evidenceRun = "run_00000001", evidenceAttempt = "revision_00000001")
        }
        assertFailsWith<IllegalArgumentException> {
            parseRecordedRepairHistoryQuery("historyGraph=$graph&historyRunEvidence=../PRIVATE")
        }
        val selected = parseRecordedRepairHistoryQuery("historyGraph=$graph&historyRunEvidence=run_00000001")
        assertEquals("run_00000001", selected.selection.evidenceRun)
        assertFalse(selected.selection.isDefault)
    }

    private fun snapshot(binding: RepairRecordedValidationDiagnostic? = fixture().binding): RepairHistorySnapshot {
        val identity = RepairRecordedIdentity(invocation().candidateRevisionId, false)
        val run = RepairRecordedRun(3, RepairRecordedIdentity("run_00000001", false), RepairRunStatus.VALIDATION_FAILED,
            identity, null, null, invocation().regressionCorpusSha256, 2, 0, 1, 100, null, null, binding)
        return RepairHistorySnapshot(graph, 4, RepairRecordedGraphWire.COMPACT, invocation().regressionCorpusSha256,
            identity, null, null, listOf(run), emptyList(), null, emptyList())
    }

    @Test
    fun `run only baseline evidence is bounded explicit and available without an attempt`() {
        val snapshot = snapshot()
        val default = RepairRecordedHistoryPage.select(snapshot, RepairRecordedHistorySelection(), 20)
        assertTrue(recordedRepairArtifactReferences(snapshot, default).isEmpty())
        val selected = RepairRecordedHistoryPage.select(snapshot,
            RepairRecordedHistorySelection(expectedGraphSha256 = graph, evidenceRun = "run_00000001"), 20)
        assertTrue(selected.evidenceAttempts.isEmpty())
        assertEquals(1, selected.evidenceRuns.size)
        assertEquals(setOf(fixture().binding.receipt, fixture().binding.diagnostic), recordedRepairArtifactReferences(snapshot, selected))
    }

    @Test
    fun `missing legacy run diagnostic grants no artifact target`() {
        val snapshot = snapshot(null)
        val selected = RepairRecordedHistoryPage.select(snapshot,
            RepairRecordedHistorySelection(expectedGraphSha256 = graph, evidenceRun = "run_00000001"), 20)
        assertTrue(recordedRepairArtifactReferences(snapshot, selected).isEmpty())
    }

    @Test
    fun `run selection refuses changed graph or out of page owner`() {
        val snapshot = snapshot()
        val changed = assertFailsWith<RepairRecordedSelectionFailure> {
            RepairRecordedHistoryPage.select(snapshot,
                RepairRecordedHistorySelection(expectedGraphSha256 = "f".repeat(64), evidenceRun = "run_00000001"), 20)
        }
        assertEquals(RepairRecordedSelectionProblem.CHANGED, changed.problem)
        val absent = assertFailsWith<RepairRecordedSelectionFailure> {
            RepairRecordedHistoryPage.select(snapshot,
                RepairRecordedHistorySelection(expectedGraphSha256 = graph, evidenceRun = "run_00000002"), 20)
        }
        assertEquals(RepairRecordedSelectionProblem.OUT_OF_RANGE, absent.problem)
    }
}
