package decompengine.repair

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
}
