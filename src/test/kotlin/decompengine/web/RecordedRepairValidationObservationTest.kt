package decompengine.web

import decompengine.oracle.core.OracleJson
import decompengine.binary.ElfMetadata
import decompengine.jobs.Job
import decompengine.project.sha256
import decompengine.repair.*
import decompengine.validation.ProcessInput
import java.nio.file.Path
import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RecordedRepairValidationObservationTest {
    private val graph = "a".repeat(64)
    private val ids = listOf("PRIVATE-case-one", "PRIVATE-case-two")
    private val corpus = repairRegressionCorpusSha256(ids.map { ProcessInput(it) })
    private data class Fixture(val binding: RepairRecordedValidationObservation, val primary: JsonObject,
        val primaryBytes: ByteArray, val diff: JsonObject?, val diffBytes: ByteArray?)

    private fun fixture(outcome: RepairValidationObservedOutcome = RepairValidationObservedOutcome.BEHAVIOR_CHECKED,
        includeDiff: Boolean = outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED): Fixture {
        val invocation = RepairValidationInvocation("validation_" + "b".repeat(32), "run_00000001",
            "root_" + "1".repeat(24), "2".repeat(64), "3".repeat(64), "4".repeat(64), corpus)
        fun executable(hash: String?) = hash?.let { JsonObject(mapOf("sha256" to JsonPrimitive(it))) } ?: JsonNull
        val original = "6".repeat(64).takeUnless { outcome == RepairValidationObservedOutcome.COMPILE_VALID }
        val rebuilt = "7".repeat(64).takeUnless { outcome == RepairValidationObservedOutcome.COMPILE_FAILED }
        val primary = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(2), "provider" to JsonPrimitive("generated-c-linux-bubblewrap-cgroup-v1"),
            "profileId" to JsonPrimitive("authored-data"), "sourceRevisionSha256" to JsonPrimitive(invocation.sourceRevisionSha256),
            "profileSha256" to JsonPrimitive(invocation.profileSha256), "indexSha256" to JsonPrimitive(invocation.indexSha256),
            "regressionCorpusSha256" to JsonPrimitive(corpus), "runtimeSha256" to JsonPrimitive("8".repeat(64)),
            "runtimeConfiguration" to JsonObject(mapOf("privateCanary" to JsonPrimitive("PRIVATE-host-command-peer"))),
            "behaviorBudgetEvidence" to JsonObject(emptyMap()), "sourceSnapshot" to JsonNull, "buildOutputLink" to JsonNull,
            "originalExecutable" to executable(original), "rebuiltExecutable" to executable(rebuilt),
            "inputs" to JsonArray(ids.map { JsonObject(mapOf("id" to JsonPrimitive(it), "args" to JsonArray(emptyList()),
                "stdinBase64" to JsonPrimitive(""))) }), "scopes" to JsonArray(emptyList()),
            "outcome" to JsonPrimitive(outcome.name.lowercase().replace('_', '-')),
            "caseCount" to JsonPrimitive(if (outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED) ids.size else 0),
            "matches" to JsonPrimitive(outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED && !includeDiff),
            "cleanupVerified" to JsonPrimitive(true), "assurance" to JsonPrimitive("strict-contained"),
        ))
        val primaryBytes = OracleJson.canonicalBytes(primary)
        val proof = RepairValidationProof(invocation.sourceRevisionSha256, invocation.profileSha256, invocation.indexSha256,
            corpus, original, rebuilt, "8".repeat(64), sha256(primaryBytes), true, RepairValidationAssurance.STRICT_CONTAINED)
        val diff = if (includeDiff) JsonObject(mapOf("id" to JsonPrimitive("PRIVATE-label"), "matches" to JsonPrimitive(false),
            "cases" to JsonArray(ids.map { JsonObject(mapOf("id" to JsonPrimitive(it))) }))) else null
        val diffBytes = diff?.let { OracleJson.canonicalBytes(it) }
        fun artifact(path: String, bytes: ByteArray) = RepairRecordedValidationObservedArtifact(
            recordedRepairArtifactReference(corpus, path), sha256(bytes), bytes.size.toLong())
        val binding = RepairRecordedValidationObservation(invocation.commitmentSha256(),
            RepairRecordedIdentity(invocation.candidateRevisionId, false), proof, outcome,
            artifact("reports/${invocation.id}.validation.json", primaryBytes),
            diffBytes?.let { artifact(repairValidationDiffPath(sha256(it)), it) })
        return Fixture(binding, primary, primaryBytes, diff, diffBytes)
    }

    private fun view(f: Fixture) = checkedRecordedRepairValidationObservation(f.binding, f.primaryBytes, f.diffBytes)
    private fun withPrimary(f: Fixture, primary: JsonObject): Fixture {
        val bytes = OracleJson.canonicalBytes(primary)
        return f.copy(primary = primary, primaryBytes = bytes, binding = f.binding.copy(
            proof = f.binding.proof.copy(evidenceSha256 = sha256(bytes)),
            primary = f.binding.primary.copy(sha256 = sha256(bytes), bytes = bytes.size.toLong())))
    }
    private fun withDiff(f: Fixture, diff: JsonObject): Fixture {
        val bytes = OracleJson.canonicalBytes(diff)
        return f.copy(diff = diff, diffBytes = bytes, binding = f.binding.copy(
            diff = requireNotNull(f.binding.diff).copy(sha256 = sha256(bytes), bytes = bytes.size.toLong())))
    }

    @Test
    fun `returned operation labels and counts never project private receipt or diff text`() {
        for (outcome in RepairValidationObservedOutcome.entries) {
            val result = view(fixture(outcome))
            assertEquals(RepairEvidenceArtifactState.AVAILABLE, result.primaryState)
            assertEquals(outcome, result.outcome)
            assertEquals(2, result.inputCount)
            assertEquals(if (outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED) 2 else 0, result.completedCasePairs)
            assertFalse(result.toString().contains("PRIVATE"))
            assertFalse(result.toString().contains("accepted", ignoreCase = true))
        }
    }

    @Test
    fun `a matching behavior receipt needs no derived diff`() {
        val result = view(fixture(includeDiff = false))
        assertEquals(RepairEvidenceArtifactState.AVAILABLE, result.primaryState)
        assertNull(result.diffState)
        assertEquals(2, result.completedCasePairs)
    }

    @Test
    fun `an empty behavior receipt cannot invent case completion even with a consistent empty corpus digest`() {
        val f = fixture(includeDiff = false)
        val emptyCorpus = repairRegressionCorpusSha256(emptyList())
        val empty = withPrimary(f, JsonObject(f.primary + mapOf("inputs" to JsonArray(emptyList()),
            "caseCount" to JsonPrimitive(0), "matches" to JsonPrimitive(false),
            "regressionCorpusSha256" to JsonPrimitive(emptyCorpus))))
        val bound = empty.copy(binding = empty.binding.copy(proof = empty.binding.proof.copy(regressionCorpusSha256 = emptyCorpus)))
        assertEquals(RepairEvidenceArtifactState.CORRUPT, view(bound).primaryState)
        assertNull(view(bound).inputCount)
        assertNull(view(bound).completedCasePairs)
    }

    @Test
    fun `missing diff does not hide an authenticated primary and missing primary supplies no outcome`() {
        val f = fixture()
        val missingDiff = checkedRecordedRepairValidationObservation(f.binding, f.primaryBytes, null)
        assertEquals(RepairEvidenceArtifactState.AVAILABLE, missingDiff.primaryState)
        assertEquals(RepairEvidenceArtifactState.UNAVAILABLE, missingDiff.diffState)
        val missingPrimary = checkedRecordedRepairValidationObservation(f.binding, null, f.diffBytes)
        assertEquals(RepairEvidenceArtifactState.UNAVAILABLE, missingPrimary.primaryState)
        assertNull(missingPrimary.outcome)
        assertNull(missingPrimary.diffState)
    }

    @Test
    fun `changed bytes swapped roles and changed proof digests are withheld`() {
        val f = fixture()
        assertEquals(RepairEvidenceArtifactState.CORRUPT,
            checkedRecordedRepairValidationObservation(f.binding, f.diffBytes, f.primaryBytes).primaryState)
        assertEquals(RepairEvidenceArtifactState.CORRUPT,
            view(f.copy(binding = f.binding.copy(proof = f.binding.proof.copy(evidenceSha256 = "9".repeat(64))))).primaryState)
        assertEquals(RepairEvidenceArtifactState.CORRUPT,
            checkedRecordedRepairValidationObservation(f.binding, f.primaryBytes, "changed".toByteArray()).diffState)
    }

    @Test
    fun `a mismatching behavior receipt must retain its bound derived role`() {
        val f = fixture()
        val missingBinding = f.copy(binding = f.binding.copy(diff = null))
        val result = view(missingBinding)
        assertEquals(RepairEvidenceArtifactState.CORRUPT, result.primaryState)
        assertNull(result.outcome)
        assertNull(result.completedCasePairs)
        assertFalse("Open retained primary validation receipt" in rendered(missingBinding))
        assertEquals(RepairEvidenceArtifactState.AVAILABLE, view(fixture(includeDiff = false)).primaryState)
    }

    @Test
    fun `matching byte commitments cannot replace receipt schema ownership cleanup or completion checks`() {
        val f = fixture()
        val edits = listOf(f.primary - "scopes", f.primary + ("extra" to JsonPrimitive(true)),
            f.primary + ("schemaVersion" to JsonPrimitive("2")), f.primary + ("provider" to JsonPrimitive("other")),
            f.primary + ("sourceRevisionSha256" to JsonPrimitive("9".repeat(64))),
            f.primary + ("profileSha256" to JsonPrimitive("9".repeat(64))),
            f.primary + ("indexSha256" to JsonPrimitive("9".repeat(64))),
            f.primary + ("regressionCorpusSha256" to JsonPrimitive("9".repeat(64))),
            f.primary + ("runtimeSha256" to JsonPrimitive("9".repeat(64))),
            f.primary + ("outcome" to JsonPrimitive("compile-valid")), f.primary + ("cleanupVerified" to JsonPrimitive(false)),
            f.primary + ("assurance" to JsonPrimitive("test-only")), f.primary + ("caseCount" to JsonPrimitive(1)),
            f.primary + ("originalExecutable" to JsonNull), f.primary + ("rebuiltExecutable" to JsonNull))
        for (fields in edits) {
            val result = view(withPrimary(f, JsonObject(fields)))
            assertEquals(RepairEvidenceArtifactState.CORRUPT, result.primaryState)
            assertNull(result.outcome)
            assertFalse(result.toString().contains("PRIVATE"))
        }
    }

    @Test
    fun `derived diff integrity requires a false global match and exact ordered input identities`() {
        val f = fixture()
        val diff = requireNotNull(f.diff)
        val cases = requireNotNull(diff["cases"] as? JsonArray)
        val edits = listOf(diff + ("matches" to JsonPrimitive(true)), diff + ("extra" to JsonPrimitive(true)),
            diff + ("cases" to JsonArray(cases.reversed())), diff + ("cases" to JsonArray(cases.take(1))),
            diff + ("cases" to JsonArray(listOf(cases.first(), cases.first()))))
        assertEquals(RepairEvidenceArtifactState.AVAILABLE, view(f).diffState)
        edits.forEach { assertEquals(RepairEvidenceArtifactState.CORRUPT, view(withDiff(f, JsonObject(it))).diffState) }
        assertEquals(RepairEvidenceArtifactState.CORRUPT,
            view(withPrimary(f, JsonObject(f.primary + ("matches" to JsonPrimitive(true))))).primaryState)
    }

    @Test
    fun `a baseline normal observation only exposes artifacts after explicit graph bound selection`() {
        val f = fixture()
        val run = RepairRecordedRun(4, RepairRecordedIdentity("run_00000001", false), RepairRunStatus.RUNNING,
            f.binding.candidate, null, null, corpus, 2, 0, 1, 100, null, null, baselineValidationObservation = f.binding)
        val snapshot = RepairHistorySnapshot(graph, 4, RepairRecordedGraphWire.COMPACT, corpus,
            f.binding.candidate, null, null, listOf(run), emptyList(), null, emptyList())
        val default = RepairRecordedHistoryPage.select(snapshot, RepairRecordedHistorySelection(), 20)
        assertTrue(recordedRepairArtifactReferences(snapshot, default).isEmpty())
        val selected = RepairRecordedHistoryPage.select(snapshot,
            RepairRecordedHistorySelection(expectedGraphSha256 = graph, evidenceRun = run.identity.value), 20)
        assertTrue(selected.evidenceAttempts.isEmpty())
        assertEquals(setOf(f.binding.primary.artifact, requireNotNull(f.binding.diff).artifact),
            recordedRepairArtifactReferences(snapshot, selected))
        val nonce = "validation_" + "b".repeat(32)
        val paths = linkedMapOf(f.binding.primary.artifact to "reports/$nonce.validation.json",
            requireNotNull(f.binding.diff).artifact to repairValidationDiffPath(requireNotNull(f.binding.diff).sha256))
        val capture = RepairHistoryArtifactCapture(snapshot, paths)
        assertTrue(capture.selectedPaths(default).isEmpty())
        assertEquals(paths.values.toList(), capture.selectedPaths(selected))
        assertFalse(f.binding.primary.artifact.value.contains("reports"))
    }

    @Test
    fun `normal attempt primary and diff reach both collectors only after explicit attempt selection`() {
        val f = fixture()
        val identity = RepairRecordedIdentity("revision_00000001_" + "c".repeat(16), false)
        val nonce = "validation_" + "b".repeat(32)
        val proof = f.binding.proof
        val invocation = RepairValidationInvocation(nonce, "run_00000001", identity.value,
            proof.sourceRevisionSha256, proof.profileSha256, proof.indexSha256, corpus)
        val binding = f.binding.copy(candidate = identity, invocationSha256 = invocation.commitmentSha256())
        val attempt = RepairRecordedAttempt(RepairRecordedAttemptKind.FINALIZED, identity,
            f.binding.candidate, 1, ModuleRevisionStatus.REJECTED, f.binding.proof.sourceRevisionSha256,
            RepairRecordedIdentity("run_00000001", false), null, null, null, emptyList(), 1,
            RepairRecordedFailureKind.BEHAVIOR, null, null, corpus, binding)
        val run = RepairRecordedRun(4, RepairRecordedIdentity("run_00000001", false), RepairRunStatus.RUNNING,
            f.binding.candidate, null, null, corpus, 2, 1, 1, 100, null, null)
        val snapshot = RepairHistorySnapshot(graph, 4, RepairRecordedGraphWire.COMPACT, corpus,
            f.binding.candidate, null, null, listOf(run), listOf(attempt), null, emptyList())
        val default = RepairRecordedHistoryPage.select(snapshot, RepairRecordedHistorySelection(), 20)
        val selected = RepairRecordedHistoryPage.select(snapshot,
            RepairRecordedHistorySelection(expectedGraphSha256 = graph, evidenceAttempt = identity.value), 20)
        val paths = linkedMapOf(binding.primary.artifact to "reports/$nonce.validation.json",
            requireNotNull(binding.diff).artifact to repairValidationDiffPath(requireNotNull(binding.diff).sha256))
        val capture = RepairHistoryArtifactCapture(snapshot, paths)
        assertTrue(recordedRepairArtifactReferences(snapshot, default).isEmpty())
        assertTrue(capture.selectedPaths(default).isEmpty())
        assertEquals(paths.keys, recordedRepairArtifactReferences(snapshot, selected))
        assertEquals(paths.values.toList(), capture.selectedPaths(selected))
    }

    private fun rendered(f: Fixture, detail: RecordedRepairValidationObservationView = view(f),
        selected: Boolean = true, duplicatePrimary: Boolean = false,
        disposition: RepairRecordedEvidenceKind? = null): String {
        val attemptIdentity = RepairRecordedIdentity("revision_00000001_" + "c".repeat(16), false)
        val proof = f.binding.proof
        val invocation = RepairValidationInvocation("validation_" + "b".repeat(32), "run_00000001", attemptIdentity.value,
            proof.sourceRevisionSha256, proof.profileSha256, proof.indexSha256, corpus)
        val attemptBinding = f.binding.copy(candidate = attemptIdentity, invocationSha256 = invocation.commitmentSha256())
        val attempts = disposition?.let { listOf(RepairRecordedAttempt(RepairRecordedAttemptKind.FINALIZED,
            attemptIdentity, f.binding.candidate, 1, ModuleRevisionStatus.REJECTED, proof.sourceRevisionSha256,
            RepairRecordedIdentity("run_00000001", false), null, null, null, emptyList(), 1,
            RepairRecordedFailureKind.BEHAVIOR, null, RepairRecordedEvidence(it, f.binding.primary.artifact),
            corpus, attemptBinding)) } ?: emptyList()
        val run = RepairRecordedRun(4, RepairRecordedIdentity("run_00000001", false), RepairRunStatus.RUNNING,
            f.binding.candidate, null, null, corpus, 2, attempts.size, 1, 100, null, null,
            baselineValidationObservation = f.binding.takeIf { disposition == null })
        val snapshot = RepairHistorySnapshot(graph, 4, RepairRecordedGraphWire.COMPACT, corpus,
            f.binding.candidate, null, null, listOf(run), attempts, null, emptyList())
        val page = RepairRecordedHistoryPage.select(snapshot, if (selected)
            RepairRecordedHistorySelection(expectedGraphSha256 = graph,
                evidenceRun = run.identity.value.takeIf { disposition == null },
                evidenceAttempt = attemptIdentity.value.takeIf { disposition != null })
            else RepairRecordedHistorySelection(), 20)
        val context = WebReportContext(Path.of("authored-reports"), "reports/runs/run_selected", "run_selected")
        val nonce = "validation_" + "b".repeat(32)
        val primary = WebArtifactSummary("${context.artifactPrefix}/source-tree/reports/$nonce.validation.json", "Repair evidence", f.primaryBytes.size.toLong())
        val diff = WebArtifactSummary("${context.artifactPrefix}/source-tree/${repairValidationDiffPath(f.diffBytes?.let(::sha256) ?: "0".repeat(64))}", "Repair evidence", f.diffBytes?.size?.toLong() ?: 0L)
        val listing = listOf(primary, diff) + if (duplicatePrimary) listOf(primary) else emptyList()
        val targets = recordedRepairArtifactReferences(snapshot, page).mapNotNull { reference ->
            recordedRepairEvidenceTarget(reference, snapshot, context, listing)?.let { reference to it }
        }.toMap()
        val job = Job("a".repeat(32), "authored.elf", "complete", "2026-01-01T00:00:00Z", sizeBytes = 0,
            binaryPath = Path.of("authored.elf"), metadata = ElfMetadata("ELF64", "little-endian", 1u, "System V",
                "EXEC", "x86-64", 0uL, 64.toUShort(), 0.toUShort(), 0.toUShort(), 0.toUShort()))
        return renderRecordedRepairHistory(job, RecordedRepairHistoryView(RepairHistoryReadResult.recorded(snapshot),
            targets = targets, evidenceStates = targets.mapValues { RepairEvidenceArtifactState.AVAILABLE },
            page = page, runId = context.runId,
            validationObservations = mapOf((if (disposition == null) run.identity else attemptIdentity) to detail)))
    }

    @Test
    fun `only fixed canonical diff names are admitted from the repair state namespace`() {
        val context = WebReportContext(Path.of("authored-reports"), "reports/runs/run_selected", "run_selected")
        val name = "b".repeat(64) + ".json"
        val prefix = "${context.artifactPrefix}/source-tree/reports/repair-revisions/validation-diffs/"
        assertEquals("reports/repair-revisions/validation-diffs/$name", recordedRepairLogicalArtifactPath(prefix + name, context))
        for (suffix in listOf("graph.json", "recovery-binding.json", "blobs/private", "nested/$name", "validation_bad.diff.json"))
            assertNull(recordedRepairLogicalArtifactPath(prefix + suffix, context))
    }

    @Test
    fun `normal validation keeps the later regression and no improvement disposition visible`() {
        for (kind in listOf(RepairRecordedEvidenceKind.REGRESSION, RepairRecordedEvidenceKind.VALIDATION)) {
            val html = rendered(fixture(), disposition = kind)
            assertTrue("<b>After:</b> ${recordedRepairEvidenceLabel(kind)} evidence" in html)
            assertTrue("Recorded validation: Behavior checked" in html)
            assertTrue("Open retained evidence" in html)
            assertTrue("Open retained primary validation receipt" in html)
            assertFalse("PRIVATE" in html)
            assertFalse("<form" in html)
        }
    }

    @Test
    fun `selected normal HTML links distinct checked roles and displays only recorded finite metadata`() {
        val f = fixture()
        val html = rendered(f)
        assertTrue("Recorded validation: Behavior checked" in html)
        assertTrue("Receipt records 2 of 2 completed case pairs." in html)
        assertTrue("Comparison policy: exact bytes (v1)." in html)
        assertTrue("Open retained primary validation receipt" in html)
        assertTrue("Open retained derived diff" in html)
        val prefix = "/jobs/${"a".repeat(32)}/artifacts/reports/runs/run_selected/source-tree/reports/validation_${"b".repeat(32)}"
        assertTrue("href=\"$prefix.validation.json\"" in html)
        val diffTarget = "/jobs/${"a".repeat(32)}/artifacts/reports/runs/run_selected/source-tree/" +
            repairValidationDiffPath(requireNotNull(f.binding.diff).sha256)
        assertTrue("href=\"$diffTarget\"" in html)
        assertFalse("PRIVATE" in html)
        assertFalse("<form" in html)
        assertTrue("Fully accepted revision: <code>none</code>" in html)
    }

    @Test
    fun `corrupt missing or ambiguous normal HTML evidence never retains a download link for that role`() {
        val f = fixture()
        for (state in listOf(RepairEvidenceArtifactState.UNAVAILABLE, RepairEvidenceArtifactState.CORRUPT)) {
            val primary = rendered(f, RecordedRepairValidationObservationView(state))
            assertFalse("Open retained primary validation receipt" in primary)
            assertFalse("Open retained derived diff" in primary)
            val diff = rendered(f, view(f).copy(diffState = state))
            assertTrue("Open retained primary validation receipt" in diff)
            assertFalse("Open retained derived diff" in diff)
            assertTrue(if (state == RepairEvidenceArtifactState.CORRUPT) "Derived diff is corrupt or changed." in diff
                else "Derived diff is unavailable." in diff)
        }
        val ambiguous = rendered(f, duplicatePrimary = true)
        assertTrue("Recorded validation receipt is unavailable" in ambiguous)
        assertFalse("Open retained primary validation receipt" in ambiguous)
        assertFalse("Open retained derived diff" in ambiguous)
    }

    @Test
    fun `unselected normal HTML offers graph and run bound inspection without reading or linking receipts`() {
        val html = rendered(fixture(), selected = false)
        assertTrue("Inspect baseline validation evidence" in html)
        assertTrue("historyGraph=$graph" in html)
        assertTrue("historyRunEvidence=run_00000001" in html)
        assertTrue("runId=run_selected" in html)
        assertFalse("Open retained primary validation receipt" in html)
        assertFalse("Open retained derived diff" in html)
        assertFalse("PRIVATE" in html)
        assertFalse("<form" in html)
    }

    @Test
    fun `streamed corpus commitments match the producer framing across UTF8 and base64 boundaries`() {
        fun rows(inputs: List<ProcessInput>) = JsonArray(inputs.map { input -> JsonObject(mapOf(
            "id" to JsonPrimitive(input.id), "args" to JsonArray(input.args.map(::JsonPrimitive)),
            "stdinBase64" to JsonPrimitive(Base64.getEncoder().encodeToString(input.stdin)))) })
        assertEquals(repairRegressionCorpusSha256(emptyList()), recordedNormalValidationCorpusSha256(JsonArray(emptyList())))
        for (size in listOf(0, 1, 2, 3, 4, 5, 6, 8193)) {
            val inputs = listOf(ProcessInput("a한글", listOf("", "λ|:\n", "😀"), ByteArray(size) { (it * 31).toByte() }),
                ProcessInput("b", listOf("second"), byteArrayOf(0, -1, 127)))
            assertEquals(repairRegressionCorpusSha256(inputs), recordedNormalValidationCorpusSha256(rows(inputs)))
        }
        val row = JsonObject(mapOf("id" to JsonPrimitive("a"), "args" to JsonArray(emptyList()), "stdinBase64" to JsonPrimitive("")))
        for (bad in listOf("A", "AA", "AAA", "AA=A", "AA==AAAA", "AB==", "AAB=", "AA-_", "AA\n=", "====")) {
            assertTrue(runCatching { recordedNormalValidationCorpusSha256(JsonArray(listOf(
                JsonObject(row + ("stdinBase64" to JsonPrimitive(bad)))))) }.isFailure)
        }
    }

    @Test
    fun `rebound receipt hashes cannot conceal changed input identities arguments stdin or ordering`() {
        val f = fixture()
        val inputs = requireNotNull(f.primary["inputs"] as? JsonArray)
        val first = requireNotNull(inputs.first() as? JsonObject)
        val edits = listOf(first + ("id" to JsonPrimitive("PRIVATE-other-case")),
            first + ("args" to JsonArray(listOf(JsonPrimitive("PRIVATE-other-argument")))),
            first + ("stdinBase64" to JsonPrimitive("YQ==")), first + ("stdinBase64" to JsonPrimitive("AB==")),
            first + ("extra" to JsonPrimitive(true)))
        for (edit in edits) {
            val changed = withPrimary(f, JsonObject(f.primary + ("inputs" to JsonArray(listOf(JsonObject(edit), inputs[1])))))
            assertEquals(RepairEvidenceArtifactState.CORRUPT, view(changed).primaryState)
            assertFalse(view(changed).toString().contains("PRIVATE"))
        }
        val reordered = withPrimary(f, JsonObject(f.primary + ("inputs" to JsonArray(inputs.reversed()))))
        assertEquals(RepairEvidenceArtifactState.CORRUPT, view(reordered).primaryState)
    }

    @Test
    fun `byte consistent receipt and proof executable roles cannot contradict the recorded operation`() {
        for (outcome in RepairValidationObservedOutcome.entries) {
            val f = fixture(outcome)
            val field = if (outcome == RepairValidationObservedOutcome.COMPILE_FAILED) "rebuiltExecutable" else "originalExecutable"
            val executable = if (outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED) JsonNull
                else JsonObject(mapOf("sha256" to JsonPrimitive("6".repeat(64))))
            val changed = withPrimary(f, JsonObject(f.primary + (field to executable)))
            val proof = when (outcome) {
                RepairValidationObservedOutcome.COMPILE_FAILED -> changed.binding.proof.copy(rebuiltBinarySha256 = "6".repeat(64))
                RepairValidationObservedOutcome.COMPILE_VALID -> changed.binding.proof.copy(originalBinarySha256 = "6".repeat(64))
                RepairValidationObservedOutcome.BEHAVIOR_CHECKED -> changed.binding.proof.copy(originalBinarySha256 = null)
            }
            assertEquals(RepairEvidenceArtifactState.CORRUPT, view(changed.copy(binding = changed.binding.copy(proof = proof))).primaryState)
        }
    }
}
