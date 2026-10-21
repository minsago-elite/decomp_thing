package decompengine.web

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
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

    @Test
    fun `an admitted bound primary larger than sixteen MiB exposes only finite labels`() {
        val f = fixture()
        val maximum = MAXIMUM_RECORDED_REPAIR_EVIDENCE_REQUEST_BYTES.toInt()
        val primary = JsonObject(f.primary + ("runtimeConfiguration" to JsonObject(mapOf(
            "privateCanary" to JsonPrimitive("PRIVATE" + "x".repeat(16 * 1024 * 1024))))))
        val receipt = OracleJson.canonicalBytes(primary, StrictJsonLimits(maximumInputBytes = maximum,
            maximumCanonicalBytes = maximum, maximumStringBytes = maximum, maximumTotalStringBytes = maximum))
        assertTrue(receipt.size > 16 * 1024 * 1024)
        val record = f.record.copy(receiptSha256 = sha256(receipt))
        val diagnostic = record.encode()
        val binding = f.binding.copy(receiptBytes = receipt.size.toLong(), receiptSha256 = sha256(receipt),
            diagnosticBytes = diagnostic.size, diagnosticSha256 = sha256(diagnostic))
        var remaining = MAXIMUM_RECORDED_REPAIR_EVIDENCE_REQUEST_BYTES
        val primaryReservation = recordedRepairEvidenceReadReservation(binding.receiptBytes, remaining)
        assertEquals(binding.receiptBytes, primaryReservation)
        remaining -= primaryReservation
        assertEquals(binding.diagnosticBytes.toLong(), recordedRepairEvidenceReadReservation(binding.diagnosticBytes.toLong(), remaining))
        val result = checkedRecordedRepairValidationDiagnostic(binding, receipt, diagnostic)
        assertEquals(RepairEvidenceArtifactState.AVAILABLE, result.state)
        assertEquals("timeout", result.reason)
        assertFalse(result.toString().contains("PRIVATE"))
    }

    @Test
    fun `explicit receipt reservations cannot increase the shared request allowance`() {
        val maximum = MAXIMUM_RECORDED_REPAIR_EVIDENCE_REQUEST_BYTES
        assertEquals(0L, recordedRepairEvidenceReadReservation(maximum, 0))
        assertEquals(1024L, recordedRepairEvidenceReadReservation(maximum, 1024))
        assertEquals(16L * 1024 * 1024, recordedRepairEvidenceReadReservation(16L * 1024 * 1024, maximum))
        assertFailsWith<IllegalArgumentException> { recordedRepairEvidenceReadReservation(maximum + 1, maximum) }
        assertFailsWith<IllegalArgumentException> { recordedRepairEvidenceReadReservation(1, maximum + 1) }
        assertFailsWith<IllegalArgumentException> { recordedRepairEvidenceReadReservation(-1, maximum) }
        assertFailsWith<IllegalArgumentException> { recordedRepairEvidenceReadReservation(1, -1) }
    }

    @Test
    fun `an out of range recorded size cannot select parser limits`() {
        val f = fixture()
        for (bytes in listOf(0L, MAXIMUM_RECORDED_REPAIR_EVIDENCE_REQUEST_BYTES + 1, Long.MAX_VALUE)) {
            assertEquals(RepairEvidenceArtifactState.CORRUPT, view(f.copy(binding = f.binding.copy(receiptBytes = bytes))).state)
        }
    }

    private val apiJob = "a".repeat(32)
    private val apiRun = "run_selected"
    private val failureQuery get() = "historyGraph=$graph&historyFailureRun=run_00000001"
    private fun apiFailureFixture(): Fixture {
        val f = fixture()
        val corpus = recordedNormalValidationCorpusSha256(f.primary.getValue("inputs") as JsonArray)
        val invocation = invocation().copy(regressionCorpusSha256 = corpus)
        val value = JsonObject(f.primary + ("regressionCorpusSha256" to JsonPrimitive(corpus)))
        val receipt = OracleJson.canonicalBytes(value)
        val record = f.record.copy(receiptSha256 = sha256(receipt), regressionCorpusSha256 = corpus, invocation = invocation)
        val diagnostic = record.encode()
        // Artifact references belong to the current graph corpus; the receipt proof has its own historical corpus.
        return f.copy(primary = value, receipt = receipt, diagnostic = diagnostic, record = record,
            binding = f.binding.copy(invocationSha256 = invocation.commitmentSha256(), regressionCorpusSha256 = corpus,
                receiptSha256 = sha256(receipt), receiptBytes = receipt.size.toLong(),
                diagnosticSha256 = sha256(diagnostic), diagnosticBytes = diagnostic.size))
    }
    private fun apiFailureVariant(f: Fixture, reason: GeneratedCValidationFailureReason,
        phase: GeneratedCValidationFailurePhase, index: Int? = null, completed: Int = 0): Fixture {
        val kind = reason.classification
        val changed = f.withRecord(f.record.copy(classification = kind, reason = reason, phase = phase, inputIndex = index))
            .let { it.copy(binding = it.binding.copy(failureKind = kind, cleanupVerified = kind != RepairValidationFailureKind.CLEANUP_UNVERIFIED)) }
        return withPrimary(changed, JsonObject(changed.primary + mapOf(
            "outcome" to JsonPrimitive(kind.name.lowercase().replace('_', '-')),
            "cleanupVerified" to JsonPrimitive(kind != RepairValidationFailureKind.CLEANUP_UNVERIFIED), "caseCount" to JsonPrimitive(completed))))
    }
    private fun apiFailureSnapshot(f: Fixture): RepairHistorySnapshot {
        val base = snapshot(f.binding)
        return RepairHistorySnapshot(base.graphSha256, 4, base.graphWire, base.corpusSha256, base.publishedHead,
            null, null, base.runs.map { it.copy(corpusSha256 = f.binding.regressionCorpusSha256) }, emptyList(), null, emptyList())
    }
    private fun failurePage(f: Fixture, selection: RepairRecordedHistorySelection = parseWebValidationFailureQuery(failureQuery)) =
        RepairRecordedHistoryPage.select(apiFailureSnapshot(f), selection, 20)
    private fun failureCapture(f: Fixture, primary: ByteArray? = f.receipt, diagnostic: ByteArray? = f.diagnostic) =
        WebRevisionValidationFailureCapture(failurePage(f), primary, diagnostic)
    private fun failureReport(f: Fixture, primary: ByteArray? = f.receipt, diagnostic: ByteArray? = f.diagnostic) =
        recordedValidationFailureReport(apiJob, apiRun, failureCapture(f, primary, diagnostic))
    private val failureContext get() = WebReportContext(java.nio.file.Path.of("authored"), "reports/runs/$apiRun", apiRun)
    private fun failureArtifacts(f: Fixture) = listOf(
        WebArtifactSummary("reports/runs/$apiRun/source-tree/reports/fixture.validation.json", "PRIVATE-receipt", f.binding.receiptBytes),
        WebArtifactSummary("reports/runs/$apiRun/source-tree/reports/${invocation().id}.validation-failure.json", "PRIVATE-diagnostic", f.binding.diagnosticBytes.toLong()))
    private fun failureField(report: JsonObject, name: String) = (report.getValue("validationFailure") as JsonObject).getValue(name)
    private fun reportState(report: JsonObject) = (report.getValue("state") as JsonPrimitive).content

    @Test fun `failed operation query requires one canonical graph and exclusive run before capture`() {
        var captures = 0
        val reports = WebRevisionValidationReports { _, _, _ -> error("normal capture must not run") }
        for (raw in listOf(null, "", "historyFailureRun=run_00000001", "historyGraph=$graph",
            "$failureQuery&historyRunEvidence=run_00000001", "$failureQuery&historyEvidence=revision_1",
            "$failureQuery&historyFailureRun=run_00000001", "$failureQuery&historyValidationPage=2",
            "$failureQuery&historyPage=02", "$failureQuery&PRIVATE=1", failureQuery.replace("run_00000001", "..%2FPRIVATE"))) {
            assertEquals(400, assertFailsWith<WebAccessDenied> { reports.failure(apiJob, apiRun, raw) { _, _, _ ->
                captures++; error("invalid failure selection was captured") } }.status)
        }
        assertEquals(0, captures)
        assertEquals("run_00000001", parseWebValidationFailureQuery(failureQuery).evidenceRun)
    }
    @Test fun `failed operation report exposes bound finite diagnostics without case comparison authority`() {
        val f = apiFailureFixture(); val report = failureReport(f)
        assertEquals("available", reportState(report)); assertEquals(JsonPrimitive("observations"), report.getValue("authority"))
        assertEquals(JsonPrimitive("not-evaluated"), report.getValue("acceptance"))
        for (key in listOf("summary", "sourceArtifact", "acceptanceArtifactId", "validationCases")) assertEquals(JsonNull, report.getValue(key))
        assertEquals(JsonPrimitive("producer-diagnostic"), failureField(report, "authority"))
        assertEquals(JsonPrimitive("timeout"), failureField(report, "reason"))
        assertEquals(JsonPrimitive("source-preparation"), failureField(report, "phase"))
        assertEquals(JsonPrimitive(f.binding.regressionCorpusSha256), failureField(report, "corpusSha256"))
        assertEquals(JsonPrimitive("3"), failureField(report, "inputCount")); assertEquals(JsonNull, failureField(report, "inputOrdinal"))
        assertFalse(report.toString().contains("PRIVATE"))
    }
    @Test fun `all finite failure reasons and enclosing phases retain their recorded distinctions`() {
        val f = apiFailureFixture()
        for (reason in GeneratedCValidationFailureReason.entries) for (phase in GeneratedCValidationFailurePhase.entries) {
            val report = failureReport(apiFailureVariant(f, reason, phase, if (phase.hasCase) 0 else null))
            assertEquals("available", reportState(report))
            assertEquals(JsonPrimitive(reason.wireName), failureField(report, "reason"))
            assertEquals(JsonPrimitive(phase.wireName), failureField(report, "phase"))
            assertEquals(JsonPrimitive(reason != GeneratedCValidationFailureReason.CLEANUP_UNVERIFIED), failureField(report, "reportedCleanupVerified"))
            assertEquals(JsonNull, report.getValue("validationCases"))
        }
    }
    @Test fun `failed operation case position is one based and retains only reported completed prefix`() {
        val f = apiFailureVariant(apiFailureFixture(), GeneratedCValidationFailureReason.TIMEOUT,
            GeneratedCValidationFailurePhase.REBUILT_OPERATION, index = 1, completed = 1)
        val report = failureReport(f)
        assertEquals("available", reportState(report)); assertEquals(JsonPrimitive("2"), failureField(report, "inputOrdinal"))
        assertEquals(JsonPrimitive("1"), failureField(report, "reportedCompletedPairs")); assertEquals(JsonNull, report.getValue("summary"))
    }
    @Test fun `failed operation metadata rejects inconsistent phase position prefix and corpus`() {
        val f = apiFailureFixture()
        val missingPosition = apiFailureVariant(f, GeneratedCValidationFailureReason.TIMEOUT, GeneratedCValidationFailurePhase.BEFORE_CASE)
        val wrongPrefix = apiFailureVariant(f, GeneratedCValidationFailureReason.TIMEOUT, GeneratedCValidationFailurePhase.REBUILT_OPERATION, index = 1)
        val earlyPairs = apiFailureVariant(f, GeneratedCValidationFailureReason.TIMEOUT, GeneratedCValidationFailurePhase.BUILD, completed = 1)
        for (value in listOf(missingPosition, wrongPrefix, earlyPairs, fixture())) {
            val report = failureReport(value); assertEquals("invalid", reportState(report)); assertEquals(JsonNull, report.getValue("validationFailure"))
        }
    }
    @Test fun `missing failed operation receipt and required diagnostic remain distinct unavailable states`() {
        val f = apiFailureFixture()
        for (primary in listOf(null, byteArrayOf())) {
            val report = failureReport(f, primary = primary)
            assertEquals("unknown", reportState(report)); assertEquals(JsonNull, report.getValue("producerSchemaVersion"))
        }
        for (diagnostic in listOf(null, byteArrayOf())) {
            val report = failureReport(f, diagnostic = diagnostic)
            assertEquals("partial", reportState(report)); assertEquals(JsonPrimitive(2), report.getValue("producerSchemaVersion"))
            assertEquals(JsonNull, report.getValue("validationFailure"))
        }
    }
    @Test fun `unsupported failed receipt schema and corrupt bound bytes never expose failure labels`() {
        val f = apiFailureFixture(); val unsupported = withPrimary(f, JsonObject(f.primary + ("schemaVersion" to JsonPrimitive(3))))
        assertEquals("unsupported", reportState(failureReport(unsupported)))
        for (report in listOf(failureReport(f, primary = byteArrayOf(1)), failureReport(f, diagnostic = byteArrayOf(1)),
            failureReport(f.copy(binding = f.binding.copy(sourceRevisionSha256 = "9".repeat(64)))))) {
            assertEquals("invalid", reportState(report)); assertEquals(JsonNull, report.getValue("validationFailure"))
            assertFalse(report.toString().contains("PRIVATE"))
        }
    }
    @Test fun `absent failure binding cannot borrow a baseline receipt or invent a fatal outcome`() {
        val f = apiFailureFixture(); val selected = RepairRecordedHistoryPage.select(snapshot(null), parseWebValidationFailureQuery(failureQuery), 20)
        val report = recordedValidationFailureReport(apiJob, apiRun, WebRevisionValidationFailureCapture(selected, f.receipt, f.diagnostic))
        assertEquals("unknown", reportState(report)); assertEquals(JsonNull, report.getValue("validationFailure"))
        assertEquals(JsonNull, report.getValue("producerSchemaVersion"))
    }
    @Test fun `failed receipt selection refuses stale graph and missing owner before any payload work`() {
        val f = apiFailureFixture(); var payloads = 0
        for (selection in listOf(RepairRecordedHistorySelection(expectedGraphSha256 = "9".repeat(64), evidenceRun = "run_00000001"),
            RepairRecordedHistorySelection(expectedGraphSha256 = graph, evidenceRun = "run_00000002"))) {
            assertFailsWith<WebAccessDenied> { captureRecordedValidationFailureReport(selection, failureContext, { "v1" },
                { RepairHistoryReadResult.recorded(apiFailureSnapshot(f)) }, { _, _ -> payloads++; failureArtifacts(f) },
                { _, _ -> payloads++; error("payload must not be read") }) }
        }
        assertEquals(0, payloads)
    }
    @Test fun `failed receipt and diagnostic capture use checked targets and one shared byte allowance`() {
        val f = apiFailureFixture(); val reads = mutableListOf<Pair<String, Long>>()
        val capture = captureRecordedValidationFailureReport(parseWebValidationFailureQuery(failureQuery), failureContext, { "v1" },
            { RepairHistoryReadResult.recorded(apiFailureSnapshot(f)) }, { _, _ -> failureArtifacts(f) }, { target, maximum ->
                reads += target to maximum
                if (target.endsWith(".validation-failure.json")) f.diagnostic else f.receipt })
        assertEquals(2, reads.size); assertEquals(f.binding.receiptBytes, reads[0].second)
        assertEquals(f.binding.diagnosticBytes.toLong(), reads[1].second)
        assertEquals("available", reportState(recordedValidationFailureReport(apiJob, apiRun, capture)))
        val oversized = f.binding.copy(receiptBytes = MAXIMUM_RECORDED_REPAIR_EVIDENCE_REQUEST_BYTES)
        var calls = 0
        val withheld = captureRecordedValidationFailureReport(parseWebValidationFailureQuery(failureQuery), failureContext, { "v1" },
            { RepairHistoryReadResult.recorded(apiFailureSnapshot(f.copy(binding = oversized))) }, { _, _ -> failureArtifacts(f) }, { _, maximum ->
                calls++; assertEquals(MAXIMUM_RECORDED_REPAIR_EVIDENCE_REQUEST_BYTES, maximum); null })
        assertEquals(1, calls); assertNull(withheld.primary); assertNull(withheld.diagnostic)
    }
    @Test fun `failed receipt capture rejects graph and durable attempt mutation after bounded reads`() {
        val f = apiFailureFixture()
        for (changeGraph in listOf(false, true)) {
            var read = false
            assertEquals(409, assertFailsWith<WebAccessDenied> { captureRecordedValidationFailureReport(
                parseWebValidationFailureQuery(failureQuery), failureContext, { if (read && !changeGraph) "v2" else "v1" },
                { val before = apiFailureSnapshot(f)
                    if (read && changeGraph) RepairHistoryReadResult.recorded(RepairHistorySnapshot("9".repeat(64), 4,
                        RepairRecordedGraphWire.COMPACT, before.corpusSha256, before.publishedHead, null, null, before.runs, emptyList(), null, emptyList()))
                    else RepairHistoryReadResult.recorded(before) }, { _, _ -> failureArtifacts(f) },
                { target, _ -> read = true; if (target.endsWith(".validation-failure.json")) f.diagnostic else f.receipt }) }.status)
        }
    }
    @Test fun `failure history discovers distinct candidates and historical corpus without reading receipts`() {
        val f = apiFailureFixture(); val before = apiFailureSnapshot(f)
        val history = webValidationHistory(apiJob, apiRun, WebValidationHistoryCapture(RepairHistoryReadResult.recorded(before),
            RepairRecordedHistoryPage.select(before, RepairRecordedHistorySelection(), 20)))
        val rows = history.getValue("items") as JsonArray
        assertEquals(2, rows.size)
        val baseline = rows[0] as JsonObject; val failure = rows[1] as JsonObject
        assertEquals(JsonPrimitive(false), baseline.getValue("hasReceipt"))
        assertEquals(JsonPrimitive("run-failure"), failure.getValue("ownerKind")); assertEquals(JsonNull, failure.getValue("normalOutcome"))
        assertEquals(JsonPrimitive("resource-exhausted"), failure.getValue("failureKind"))
        assertEquals(JsonPrimitive(f.binding.regressionCorpusSha256), failure.getValue("corpusSha256"))
        assertTrue(failure.getValue("corpusSha256") != history.getValue("corpusSha256"))
        assertFalse(history.toString().contains("PRIVATE"))
    }
    @Test fun `failed operation report identity binds both artifacts and cannot collide with normal baseline`() {
        val f = apiFailureFixture(); val report = failureReport(f)
        val changed = f.withRecord(f.record.copy(reason = GeneratedCValidationFailureReason.RESOURCE_EXHAUSTED))
        assertTrue(report.getValue("reportId") != failureReport(changed).getValue("reportId"))
        val baseline = recordedValidationReport(apiJob, apiRun, WebRevisionValidationCapture(failurePage(f), null, null))
        assertTrue(report.getValue("reportId") != baseline.getValue("reportId"))
        assertEquals(JsonPrimitive(f.binding.candidate.value), (report.getValue("binding") as JsonObject).getValue("revisionId"))
    }
    @Test fun `failure normal and discovery reads share admission and release it after a failed callback`() {
        val f = apiFailureFixture(); val reports = WebRevisionValidationReports { _, _, _ ->
            WebRevisionValidationCapture(failurePage(f), null, null) }
        assertFailsWith<IllegalStateException> { reports.failure(apiJob, apiRun, failureQuery) { _, _, _ ->
            assertEquals(429, assertFailsWith<WebAccessDenied> { reports.read(apiJob, apiRun, failureQuery.replace("historyFailureRun", "historyRunEvidence")) }.status)
            assertEquals(429, assertFailsWith<WebAccessDenied> { reports.history(apiJob, apiRun, null) { _, _, _ -> error("busy") } }.status)
            assertEquals(429, assertFailsWith<WebAccessDenied> { reports.failure(apiJob, apiRun, failureQuery) { _, _, _ -> error("busy") } }.status)
            error("authored callback failure")
        } }
        assertEquals("available", reportState(reports.failure(apiJob, apiRun, failureQuery) { _, _, _ -> failureCapture(f) }))
    }

    @Test fun `failure history windows bound all three owner families and pending to sixty one rows`() {
        val f = apiFailureFixture(); val base = apiFailureSnapshot(f)
        fun attempt(index: Int, kind: RepairRecordedAttemptKind = RepairRecordedAttemptKind.FINALIZED) = RepairRecordedAttempt(
            kind, RepairRecordedIdentity("revision_$index", false), null, index, null, null, null, null, null, null,
            emptyList(), null, RepairRecordedFailureKind.OTHER, null, null)
        val all = RepairHistorySnapshot(graph, 4, RepairRecordedGraphWire.COMPACT, base.corpusSha256,
            base.publishedHead, null, null, (1..25).map { base.runs.single().copy(identity = RepairRecordedIdentity("run_$it", false)) },
            (1..25).map { attempt(it) }, attempt(26, RepairRecordedAttemptKind.PENDING), emptyList())
        fun page(number: Int): JsonObject {
            val selection = RepairRecordedHistorySelection(pageNumber = number, expectedGraphSha256 = graph)
            return webValidationHistory(apiJob, apiRun, WebValidationHistoryCapture(RepairHistoryReadResult.recorded(all),
                RepairRecordedHistoryPage.select(all, selection, 20)))
        }
        val first = page(1).getValue("items") as JsonArray; val second = page(2).getValue("items") as JsonArray
        assertEquals(61, first.size); assertEquals(15, second.size)
        val keys = (first + second).map { (it as JsonObject).let { row -> row.getValue("ownerKind") to row.getValue("ownerId") } }
        assertEquals(76, keys.toSet().size)
    }
    @Test fun `withheld failed operation references cannot expose candidate commitments or diagnostic detail`() {
        val f = apiFailureFixture(); val base = apiFailureSnapshot(f)
        val run = base.runs.single().copy(identity = RepairRecordedIdentity("run_00000001", true))
        val withheld = RepairHistorySnapshot(graph, 4, RepairRecordedGraphWire.COMPACT, base.corpusSha256,
            base.publishedHead, null, null, listOf(run), emptyList(), null, emptyList())
        val page = RepairRecordedHistoryPage.select(withheld, parseWebValidationFailureQuery(failureQuery), 20)
        val report = recordedValidationFailureReport(apiJob, apiRun, WebRevisionValidationFailureCapture(page, f.receipt, f.diagnostic))
        assertEquals("partial", reportState(report)); assertEquals(JsonNull, report.getValue("validationFailure"))
        val history = webValidationHistory(apiJob, apiRun, WebValidationHistoryCapture(RepairHistoryReadResult.recorded(withheld),
            RepairRecordedHistoryPage.select(withheld, RepairRecordedHistorySelection(), 20)))
        for (value in history.getValue("items") as JsonArray) {
            val row = value as JsonObject; assertEquals(JsonPrimitive(false), row.getValue("canInspect"))
            for (key in listOf("candidateId", "sourceSha256", "corpusSha256")) assertEquals(JsonNull, row.getValue(key))
        }
        assertFalse(report.toString().contains("PRIVATE")); assertFalse(history.toString().contains("PRIVATE"))
    }

    @Test fun `failure projection refuses an otherwise valid invocation attached to another selected run`() {
        val f = apiFailureFixture(); val base = apiFailureSnapshot(f)
        val crossPaired = RepairHistorySnapshot(graph, 4, base.graphWire, base.corpusSha256, base.publishedHead,
            null, null, listOf(base.runs.single().copy(identity = RepairRecordedIdentity("run_00000002", false))), emptyList(), null, emptyList())
        val selection = parseWebValidationFailureQuery(failureQuery.replace("run_00000001", "run_00000002"))
        val page = RepairRecordedHistoryPage.select(crossPaired, selection, 20)
        val report = recordedValidationFailureReport(apiJob, apiRun, WebRevisionValidationFailureCapture(page, f.receipt, f.diagnostic))
        assertEquals("invalid", reportState(report)); assertEquals(JsonNull, report.getValue("validationFailure"))
    }
    @Test fun `failure projection binds the selected run corpus while allowing a different current graph corpus`() {
        val f = apiFailureFixture(); val base = apiFailureSnapshot(f)
        assertTrue(base.corpusSha256 != f.binding.regressionCorpusSha256)
        assertEquals("available", reportState(failureReport(f)))
        val crossPaired = RepairHistorySnapshot(graph, 4, base.graphWire, base.corpusSha256, base.publishedHead,
            null, null, listOf(base.runs.single().copy(corpusSha256 = "9".repeat(64))), emptyList(), null, emptyList())
        val page = RepairRecordedHistoryPage.select(crossPaired, parseWebValidationFailureQuery(failureQuery), 20)
        val report = recordedValidationFailureReport(apiJob, apiRun, WebRevisionValidationFailureCapture(page, f.receipt, f.diagnostic))
        assertEquals("invalid", reportState(report)); assertEquals(JsonNull, report.getValue("validationFailure"))
    }
}
