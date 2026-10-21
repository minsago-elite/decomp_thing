package decompengine.repair

import decompengine.project.sha256
import java.io.IOException
import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class RepairValidationDiagnosticTest {
    private fun invocation() = RepairValidationInvocation("validation_" + "a".repeat(32), "run_00000001",
        "root_" + "1".repeat(24), "2".repeat(64), "3".repeat(64), "4".repeat(64), "5".repeat(64))

    private fun binding() = RepairValidationDiagnosticBinding(invocation(), "6".repeat(64),
        "reports/run_00000001_initial.validation.json", "7".repeat(64), 100,
        "reports/${invocation().id}.validation-failure.json", "8".repeat(64), 1000,
        RepairValidationFailureKind.RESOURCE_EXHAUSTED, true)

    private fun run(version: Int, diagnostic: RepairValidationDiagnosticBinding? = null) = RepairRunState(
        "run_00000001", RepairRunStatus.VALIDATION_FAILED, invocation().candidateRevisionId, null, null,
        "5".repeat(64), 2, 0, 1, 100, RepairEvidence("validation-failed", "bounded failure",
            "reports/run_00000001_initial.validation.json"), schemaVersion = version, validationDiagnostic = diagnostic)

    @Test
    fun `each invocation and selected source component changes the framed commitment`() {
        val original = invocation()
        val different = listOf(original.copy(id = "validation_" + "b".repeat(32)), original.copy(runId = "run_00000002"),
            original.copy(candidateRevisionId = "revision_00000001_" + "1".repeat(16)),
            original.copy(sourceRevisionSha256 = "9".repeat(64)), original.copy(profileSha256 = "9".repeat(64)),
            original.copy(indexSha256 = "9".repeat(64)), original.copy(regressionCorpusSha256 = "9".repeat(64)))
        assertEquals(8, (different + original).map { it.commitmentSha256() }.distinct().size)
        assertEquals(original, parseRepairValidationInvocation(original.toJsonObject()))
    }

    @Test
    fun `invocation identities reject private arbitrary and malformed text`() {
        listOf("PRIVATE-token", "validation_" + "A".repeat(32), "validation_" + "a".repeat(31)).forEach {
            assertFailsWith<IllegalArgumentException> { invocation().copy(id = it) }
        }
        assertFailsWith<IllegalArgumentException> { invocation().copy(runId = "private-run") }
        assertFailsWith<IllegalArgumentException> { invocation().copy(candidateRevisionId = "private-source") }
        assertFailsWith<IllegalArgumentException> { invocation().copy(sourceRevisionSha256 = "x".repeat(64)) }
    }

    @Test
    fun `canonical binding roundtrips every commitment without an acceptance flag`() {
        val original = binding()
        assertEquals(original, parseRepairValidationDiagnosticBinding(original.toJsonObject()))
        val keys = original.toJsonObject().keys
        assertFalse("accepted" in keys || "proof" in keys || "releaseComplete" in keys)
    }

    @Test
    fun `binding paths cannot select canonical internal external or traversal payloads`() {
        listOf("/host/receipt.json", "../receipt.json", "reports/../receipt.json", "reports//receipt.json",
            "reports/repair-revisions/private.json", "reports/source-tree/private.json", "reports/runs/private.json",
            "reports/repair_history.json", "reports/a b.json", "external/receipt.json").forEach {
            assertFailsWith<IllegalArgumentException> { binding().copy(receiptPath = it) }
        }
        assertFailsWith<IllegalArgumentException> { binding().copy(diagnosticPath = "reports/old.validation-failure.json") }
        assertFailsWith<IllegalArgumentException> { binding().copy(receiptPath = binding().diagnosticPath) }
    }

    @Test
    fun `publication sizes and cleanup classification are bounded and consistent`() {
        binding().requireRetainedBudget(2100)
        assertFailsWith<IllegalArgumentException> { binding().requireRetainedBudget(2099) }
        assertFailsWith<IllegalArgumentException> { binding().requireRetainedBudget(-1) }
        assertFailsWith<IllegalArgumentException> { binding().copy(receiptBytes = 0) }
        assertFailsWith<IllegalArgumentException> { binding().copy(receiptBytes = 64L * 1024 * 1024 + 1) }
        assertFailsWith<IllegalArgumentException> { binding().copy(diagnosticBytes = 0) }
        assertFailsWith<IllegalArgumentException> { binding().copy(diagnosticBytes = 4097) }
        assertFailsWith<IllegalArgumentException> { binding().copy(cleanupVerified = false) }
        assertFailsWith<IllegalArgumentException> { binding().copy(failureKind = RepairValidationFailureKind.CLEANUP_UNVERIFIED) }
        assertFalse(binding().copy(failureKind = RepairValidationFailureKind.CLEANUP_UNVERIFIED, cleanupVerified = false).cleanupVerified)
    }

    @Test
    fun `association refuses every cross run candidate source profile index or corpus pair`() {
        val b = binding()
        val i = b.invocation
        fun check(run: String = i.runId, profile: String = i.profileSha256, index: String = i.indexSha256,
            corpus: String = i.regressionCorpusSha256, candidate: String = i.candidateRevisionId, source: String = i.sourceRevisionSha256) =
            requireRepairValidationDiagnosticAssociation(b, run, profile, index, corpus, candidate, source)
        check()
        assertFailsWith<IllegalArgumentException> { check(run = "run_00000002") }
        assertFailsWith<IllegalArgumentException> { check(profile = "9".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { check(index = "9".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { check(corpus = "9".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { check(candidate = "root_" + "9".repeat(24)) }
        assertFailsWith<IllegalArgumentException> { check(source = "9".repeat(64)) }
    }

    @Test
    fun `legacy run schemas preserve their exact bytes and omit new metadata`() {
        for (version in 1..2) {
            val original = run(version)
            val bytes = original.toJson()
            assertEquals(original, parseRepairRunState(bytes))
            assertEquals(bytes, parseRepairRunState(bytes).toJson())
            assertFalse("validationDiagnostic" in Json.parseToJsonElement(bytes).jsonObject)
        }
    }

    @Test
    fun `schema three retains exact portable diagnostic bytes and relation`() {
        val original = run(3, binding())
        val text = original.toJson()
        assertEquals(original, parseRepairRunState(text))
        assertEquals(text, parseRepairRunState(text).toJson())
        assertEquals(binding(), parseRepairRunState(text).validationDiagnostic)
    }

    @Test
    fun `schema three explicit absence remains absence after roundtrip`() {
        val text = run(3).toJson()
        assertEquals(JsonNull, Json.parseToJsonElement(text).jsonObject.getValue("validationDiagnostic"))
        assertNull(parseRepairRunState(text).validationDiagnostic)
        assertEquals(text, parseRepairRunState(text).toJson())
    }

    @Test
    fun `downgrading a diagnostic run cannot hide the new canonical field`() {
        assertFailsWith<IllegalArgumentException> { run(2, binding()) }
        val root = Json.parseToJsonElement(run(3, binding()).toJson()).jsonObject
        assertFailsWith<IllegalArgumentException> {
            parseRepairRunState(JsonObject(root + ("schemaVersion" to JsonPrimitive(2))).toString())
        }
    }

    @Test
    fun `run diagnostic cannot attach to another run corpus or successful outcome`() {
        assertFailsWith<IllegalArgumentException> { run(3, binding()).copy(id = "run_00000002") }
        assertFailsWith<IllegalArgumentException> { run(3, binding()).copy(regressionCorpusSha256 = "9".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { run(3, binding()).copy(status = RepairRunStatus.COMPILE_VALID) }
        assertFailsWith<IllegalArgumentException> {
            run(3, binding()).copy(status = RepairRunStatus.FULLY_ACCEPTED, acceptedHeadId = invocation().candidateRevisionId)
        }
    }

    @Test
    fun `strict new binding rejects unknown missing string numeric and string boolean fields`() {
        val root = binding().toJsonObject()
        val edits = listOf(JsonObject(root + ("extra" to JsonPrimitive(true))), JsonObject(root - "receiptSha256"),
            JsonObject(root + ("receiptBytes" to JsonPrimitive("100"))),
            JsonObject(root + ("cleanupVerified" to JsonPrimitive("true"))))
        edits.forEach { value -> assertTrue(runCatching { parseRepairValidationDiagnosticBinding(value) }.isFailure) }
    }

    @Test
    fun `rollback metadata and diagnostic coexist in schema three without success promotion`() {
        val original = run(3, binding()).copy(status = RepairRunStatus.ROLLBACK_FAILED,
            rollbackFailureAttemptId = "revision_00000001_" + "1".repeat(16),
            rollbackResolution = RepairRollbackState.RESTORE_FAILED_UNRESOLVED)
        assertEquals(original, parseRepairRunState(original.toJson()))
        assertEquals(binding(), original.validationDiagnostic)
        assertNotEquals(RepairRunStatus.FULLY_ACCEPTED, original.status)
    }

    private fun publication() = RepairValidationDiagnosticPublication(invocation(), "6".repeat(64),
        Path.of("/authored/reports/primary.validation.json"), "7".repeat(64), 100,
        Path.of("/authored/reports/primary.validation-failure.json"), "8".repeat(64), 1000,
        RepairValidationFailureKind.RESOURCE_EXHAUSTED, true)

    private class Marker(private val value: () -> RepairValidationDiagnosticPublication?) : Exception("authored marker"),
        RepairValidationFailureEvidence {
        override val receiptPath = Path.of("/authored/reports/primary.validation.json")
        override val receiptSha256 = "7".repeat(64)
        override val cleanupVerified = true
        override val failureKind = RepairValidationFailureKind.RESOURCE_EXHAUSTED
        override val diagnosticPublication get() = value()
    }

    @Test
    fun `exact publication reaches canonical retention once with the original marker intact`() {
        val publication = publication()
        val marker = Marker { publication }
        val failure = IOException("authored original").also { it.addSuppressed(marker) }
        var calls = 0
        retainRepairValidationDiagnostic(failure, invocation()) { assertSame(publication, it); calls++ }
        assertEquals(1, calls)
        assertEquals(listOf(marker), failure.suppressed.toList())
    }

    @Test
    fun `missing ambiguous and withheld markers never invoke canonical retention`() {
        var calls = 0
        val missing = IOException("authored missing")
        val withheld = IOException("authored withheld").also { it.addSuppressed(Marker { null }) }
        val ambiguous = IOException("authored ambiguous").also {
            it.addSuppressed(Marker { publication() }); it.addSuppressed(Marker { publication() })
        }
        for (failure in listOf(missing, withheld, ambiguous)) retainRepairValidationDiagnostic(failure, invocation()) { calls++ }
        assertEquals(0, calls)
    }

    @Test
    fun `cross invocation publication is suppressed before canonical retention`() {
        val publication = publication().copy(invocation = invocation().copy(id = "validation_" + "b".repeat(32)))
        val failure = IOException("authored original").also { it.addSuppressed(Marker { publication }) }
        var calls = 0
        retainRepairValidationDiagnostic(failure, invocation()) { calls++ }
        assertEquals(0, calls)
        assertEquals(2, failure.suppressed.size)
        assertTrue(failure.suppressed.last() is IllegalArgumentException)
    }

    @Test
    fun `throwing publication getter and retention callback preserve the original exception`() {
        for (getterFailure in listOf(true, false)) {
            val original = IOException("authored original")
            val auxiliary = IllegalStateException("authored auxiliary")
            original.addSuppressed(Marker { if (getterFailure) throw auxiliary else publication() })
            val thrown = assertFailsWith<IOException> {
                retainRepairValidationDiagnostic(original, invocation()) { throw auxiliary }
                throw original
            }
            assertSame(original, thrown)
            assertSame(auxiliary, original.suppressed.last())
        }
    }

    @Test
    fun `retention throwing the original object cannot cause self suppression`() {
        val original = IOException("authored original")
        val marker = Marker { publication() }
        original.addSuppressed(marker)
        retainRepairValidationDiagnostic(original, invocation()) { throw original }
        assertEquals(listOf(marker), original.suppressed.toList())
    }

    private class ClassifiedMarker(override val failureKind: RepairValidationFailureKind,
        private val value: () -> RepairValidationDiagnosticPublication?) : Exception("authored classified marker"),
        RepairValidationFailureEvidence {
        override val receiptPath = Path.of("/authored/reports/primary.validation.json")
        override val receiptSha256 = "7".repeat(64)
        override val cleanupVerified = failureKind != RepairValidationFailureKind.CLEANUP_UNVERIFIED
        override val diagnosticPublication get() = value()
    }

    @Test
    fun `throwing the existing provider marker cannot duplicate or hide its classification`() {
        for (kind in RepairValidationFailureKind.entries) for (getterFailure in listOf(true, false)) {
            val original = IOException("authored original")
            lateinit var marker: ClassifiedMarker
            marker = ClassifiedMarker(kind) { if (getterFailure) throw marker else publication().copy(
                failureKind = kind, cleanupVerified = kind != RepairValidationFailureKind.CLEANUP_UNVERIFIED) }
            original.addSuppressed(marker)
            retainRepairValidationDiagnostic(original, invocation()) { throw marker }
            assertEquals(listOf(marker), original.suppressed.toList())
            val selected = original.suppressed.filterIsInstance<RepairValidationFailureEvidence>().singleOrNull()
            assertSame(marker, selected)
            assertEquals(kind, selected?.failureKind)
        }
    }

    @Test
    fun `an auxiliary provider marker remains a cause without competing with the primary marker`() {
        for (kind in RepairValidationFailureKind.entries) for (getterFailure in listOf(true, false)) {
            val original = IOException("authored original")
            val auxiliary = ClassifiedMarker(if (kind == RepairValidationFailureKind.CANCELLED)
                RepairValidationFailureKind.CLEANUP_UNVERIFIED else RepairValidationFailureKind.CANCELLED) { null }
            val primary = ClassifiedMarker(kind) { if (getterFailure) throw auxiliary else publication().copy(
                failureKind = kind, cleanupVerified = kind != RepairValidationFailureKind.CLEANUP_UNVERIFIED) }
            original.addSuppressed(primary)
            retainRepairValidationDiagnostic(original, invocation()) { throw auxiliary }
            assertSame(primary, original.suppressed.filterIsInstance<RepairValidationFailureEvidence>().singleOrNull())
            assertEquals(kind, original.suppressed.filterIsInstance<RepairValidationFailureEvidence>().single().failureKind)
            val wrapper = original.suppressed.last()
            assertTrue(wrapper is IllegalStateException)
            assertFalse(wrapper is RepairValidationFailureEvidence)
            assertSame(auxiliary, wrapper.cause)
        }
    }

    @Test
    fun `an already retained auxiliary exception is not attached a second time`() {
        val original = IOException("authored original")
        val auxiliary = IllegalStateException("authored auxiliary")
        val primary = Marker { publication() }
        original.addSuppressed(primary)
        original.addSuppressed(auxiliary)
        retainRepairValidationDiagnostic(original, invocation()) { throw auxiliary }
        assertEquals(listOf(primary, auxiliary), original.suppressed.toList())
        assertSame(primary, original.suppressed.filterIsInstance<RepairValidationFailureEvidence>().singleOrNull())
    }

    @Test
    fun `operator selected external relative and project directories retain the same canonical pair`() {
        val primary = "authored primary receipt".toByteArray()
        val diagnostic = "authored diagnostic".toByteArray()
        for (directory in listOf(Path.of("/operator/output"), Path.of("/authored/project/other"),
                Path.of("authored-relative-output"))) {
            val source = publication().copy(receiptPath = directory.resolve("initial.validation.json"),
                diagnosticPath = directory.resolve("initial.validation-failure.json"),
                receiptSha256 = sha256(primary), receiptBytes = primary.size.toLong(),
                diagnosticSha256 = sha256(diagnostic), diagnosticBytes = diagnostic.size)
            val plan = planRepairValidationDiagnosticRetention(source, 4096)
            val supplied = mapOf(source.receiptPath.toAbsolutePath().normalize() to primary,
                source.diagnosticPath.toAbsolutePath().normalize() to diagnostic)
            val retained = linkedMapOf<String, ByteArray>()
            plan.retain(read = { path, limit -> supplied.getValue(path).also { assertEquals(it.size.toLong(), limit) } },
                write = { name, bytes -> retained[name] = bytes },
                readRetained = { name, limit -> retained.getValue(name).also { assertEquals(it.size.toLong(), limit) } })
            assertEquals(listOf("${invocation().id}.validation.json", "${invocation().id}.validation-failure.json"), retained.keys.toList())
            assertEquals(2, plan.binding.schemaVersion)
            assertEquals("reports/${invocation().id}.validation.json", plan.binding.receiptPath)
            assertTrue(primary.contentEquals(retained.getValue("${invocation().id}.validation.json")))
            assertEquals(plan.binding, parseRepairValidationDiagnosticBinding(plan.binding.toJsonObject()))
            assertFalse(plan.binding.toJsonObject().toString().contains(directory.toString()))
        }
    }

    @Test
    fun `canonical pair counts both physical copies and keeps its inspection frame bounded`() {
        val pair = planRepairValidationDiagnosticRetention(publication(), 2200).binding
        pair.requireRetainedBudget(2200)
        assertFailsWith<IllegalArgumentException> { pair.requireRetainedBudget(2199) }
        assertFailsWith<IllegalArgumentException> {
            pair.copy(receiptBytes = 64L * 1024 * 1024).requireRetainedBudget(Long.MAX_VALUE)
        }
        assertFailsWith<IllegalArgumentException> { pair.copy(receiptPath = "reports/operator.validation.json") }
        assertFailsWith<IllegalArgumentException> { pair.copy(diagnosticPath = "reports/sub/${invocation().id}.validation-failure.json") }
        assertEquals(1, binding().schemaVersion)
        binding().requireRetainedBudget(2100)
    }

    @Test
    fun `changed source primary or diagnostic refuses the pair before either canonical write`() {
        val primary = "authored primary".toByteArray()
        val diagnostic = "authored diagnostic".toByteArray()
        val source = publication().copy(receiptSha256 = sha256(primary), receiptBytes = primary.size.toLong(),
            diagnosticSha256 = sha256(diagnostic), diagnosticBytes = diagnostic.size)
        for (changedPrimary in listOf(true, false)) {
            var writes = 0
            assertFailsWith<IllegalArgumentException> {
                planRepairValidationDiagnosticRetention(source, 4096).retain(
                    read = { path, _ ->
                        if (path == source.receiptPath) { if (changedPrimary) "changed primary".toByteArray() else primary }
                        else { if (changedPrimary) diagnostic else "changed diagnostic".toByteArray() }
                    }, write = { _, _ -> writes++ }, readRetained = { _, _ -> error("must not read a refused pair") })
            }
            assertEquals(0, writes)
        }
    }

    @Test
    fun `failed or changed immutable publication cannot reach the canonical commit`() {
        val primary = "authored primary".toByteArray()
        val diagnostic = "authored diagnostic".toByteArray()
        val source = publication().copy(receiptSha256 = sha256(primary), receiptBytes = primary.size.toLong(),
            diagnosticSha256 = sha256(diagnostic), diagnosticBytes = diagnostic.size)
        for (writeFailure in listOf(true, false)) {
            val original = IOException("authored publication failure")
            var committed = false
            val result = runCatching {
                planRepairValidationDiagnosticRetention(source, 4096).retain(
                    read = { path, _ -> if (path == source.receiptPath) primary else diagnostic },
                    write = { name, _ -> if (writeFailure && name.endsWith(".validation-failure.json")) throw original },
                    readRetained = { _, _ -> "changed retained bytes".toByteArray() })
                committed = true
            }
            assertTrue(result.isFailure)
            if (writeFailure) assertSame(original, result.exceptionOrNull())
            else assertTrue(result.exceptionOrNull() is IllegalArgumentException)
            assertFalse(committed)
        }
    }

    @Test
    fun `retention cannot select an unrelated sibling name or source directory`() {
        val source = publication()
        for (changed in listOf(source.copy(diagnosticPath = Path.of("/other/primary.validation-failure.json")),
                source.copy(diagnosticPath = Path.of("/authored/reports/other.validation-failure.json")),
                source.copy(receiptPath = Path.of("/authored/reports/primary.txt")))) {
            assertFailsWith<IllegalArgumentException> { planRepairValidationDiagnosticRetention(changed, 4096) }
        }
    }

    @Test
    fun `reported publication must match both paths selected by the exact request`() {
        val source = publication()
        for (changed in listOf(source.receiptPath.resolveSibling("other.validation.json") to source.diagnosticPath,
                source.receiptPath to source.diagnosticPath.resolveSibling("other.validation-failure.json"))) {
            val original = IOException("authored original").also { it.addSuppressed(Marker { source }) }
            var calls = 0
            retainRepairValidationDiagnostic(original, invocation(), changed.first, changed.second) { calls++ }
            assertEquals(0, calls)
            assertTrue(original.suppressed.last() is IllegalArgumentException)
        }
        val original = IOException("authored original").also { it.addSuppressed(Marker { source }) }
        var calls = 0
        retainRepairValidationDiagnostic(original, invocation(), source.receiptPath, source.diagnosticPath) { calls++ }
        assertEquals(1, calls)
        assertEquals(1, original.suppressed.size)
    }

    private fun capturedDiagnostic(): Pair<RepairHistorySnapshot, Map<RepairRecordedArtifactReference, String>> {
        val b = planRepairValidationDiagnosticRetention(publication(), 4096).binding
        val corpus = b.invocation.regressionCorpusSha256
        val primary = recordedRepairArtifactReference(corpus, b.receiptPath)
        val diagnostic = recordedRepairArtifactReference(corpus, b.diagnosticPath)
        val baseline = RepairRecordedIdentity(b.invocation.candidateRevisionId, false)
        val recorded = RepairRecordedValidationDiagnostic(b.invocation.commitmentSha256(), baseline,
            b.invocation.sourceRevisionSha256, b.invocation.profileSha256, b.invocation.indexSha256, corpus,
            b.runtimeSha256, primary, b.receiptSha256, b.receiptBytes, diagnostic, b.diagnosticSha256,
            b.diagnosticBytes, b.failureKind, b.cleanupVerified)
        val run = RepairRecordedRun(3, RepairRecordedIdentity(b.invocation.runId, false), RepairRunStatus.VALIDATION_FAILED,
            baseline, null, null, corpus, 2, 0, 1, 100, null, null, recorded)
        val snapshot = RepairHistorySnapshot("f".repeat(64), 4, RepairRecordedGraphWire.COMPACT, corpus,
            baseline, null, null, listOf(run), emptyList(), null, emptyList())
        return snapshot to linkedMapOf(primary to b.receiptPath, diagnostic to b.diagnosticPath)
    }

    @Test
    fun `run only canonical diagnostics reach the selected artifact capture without an attempt`() {
        val (snapshot, paths) = capturedDiagnostic()
        val capture = RepairHistoryArtifactCapture(snapshot, paths)
        val result = RepairHistoryReadResult.recorded(snapshot, artifactCapture = capture)
        val default = RepairRecordedHistoryPage.select(snapshot, RepairRecordedHistorySelection(), 20)
        assertTrue(result.selectedArtifactPaths(default).isEmpty())
        val selected = RepairRecordedHistoryPage.select(snapshot,
            RepairRecordedHistorySelection(expectedGraphSha256 = snapshot.graphSha256, evidenceRun = "run_00000001"), 20)
        assertTrue(selected.evidenceAttempts.isEmpty())
        assertEquals(paths.values.toList(), result.selectedArtifactPaths(selected))
        assertEquals(2, result.selectedArtifactPaths(selected).size)
    }

    @Test
    fun `selected diagnostic paths remain captured and cannot cross snapshots or invent missing mappings`() {
        val (snapshot, originalPaths) = capturedDiagnostic()
        val caller = originalPaths.toMutableMap()
        val capture = RepairHistoryArtifactCapture(snapshot, caller)
        caller.clear()
        val selected = RepairRecordedHistoryPage.select(snapshot,
            RepairRecordedHistorySelection(expectedGraphSha256 = snapshot.graphSha256, evidenceRun = "run_00000001"), 20)
        assertEquals(originalPaths.values.toList(), capture.selectedPaths(selected))
        assertTrue(RepairHistoryArtifactCapture(snapshot, emptyMap()).selectedPaths(selected).isEmpty())
        val (other, _) = capturedDiagnostic()
        val otherPage = RepairRecordedHistoryPage.select(other,
            RepairRecordedHistorySelection(expectedGraphSha256 = other.graphSha256, evidenceRun = "run_00000001"), 20)
        assertFailsWith<IllegalArgumentException> { capture.selectedPaths(otherPage) }
    }
}
