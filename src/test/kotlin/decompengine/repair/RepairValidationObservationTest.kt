package decompengine.repair

import decompengine.project.sha256
import java.io.IOException
import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class RepairValidationObservationTest {
    private fun invocation() = RepairValidationInvocation("validation_" + "a".repeat(32), "run_00000001",
        "root_" + "1".repeat(24), "2".repeat(64), "3".repeat(64), "4".repeat(64), "5".repeat(64))

    private fun observation(outcome: RepairValidationObservedOutcome = RepairValidationObservedOutcome.BEHAVIOR_CHECKED): RepairValidationObservation {
        val i = invocation()
        val proof = RepairValidationProof(i.sourceRevisionSha256, i.profileSha256, i.indexSha256,
            i.regressionCorpusSha256, "6".repeat(64).takeUnless { outcome == RepairValidationObservedOutcome.COMPILE_VALID },
            "7".repeat(64).takeUnless { outcome == RepairValidationObservedOutcome.COMPILE_FAILED }, "8".repeat(64), "9".repeat(64),
            true, RepairValidationAssurance.STRICT_CONTAINED)
        return RepairValidationObservation(i, proof, outcome,
            RepairValidationObservedArtifact("reports/${i.id}.validation.json", proof.evidenceSha256, 80))
    }

    private fun run(version: Int, log: RepairValidationObservationLog = RepairValidationObservationLog.EMPTY) =
        RepairRunState("run_00000001", RepairRunStatus.RUNNING, invocation().candidateRevisionId, null, null,
            invocation().regressionCorpusSha256, 2, 0, 1, 100, schemaVersion = version, validationObservations = log)

    @Test
    fun `text commitments match the exact UTF8 writer encoding including replacement characters`() {
        val path = Path.of("authored.diff.json")
        for (text in listOf("", "plain", "한글 λ 😀", "a\uD800b", "a\uDC00b", "a\r\nb\n")) {
            val expected = text.toByteArray(Charsets.UTF_8)
            val artifact = repairValidationPublishedTextArtifact(path, text)
            assertEquals(path, artifact.path)
            assertEquals(expected.size.toLong(), artifact.bytes)
            assertEquals(sha256(expected), artifact.sha256)
        }
    }

    @Test
    fun `all returned operation kinds roundtrip independently of candidate acceptance`() {
        for (outcome in RepairValidationObservedOutcome.entries) {
            val value = observation(outcome)
            assertEquals(value, parseRepairValidationObservation(value.toJsonObject()))
            assertEquals("exact-bytes-v1", value.comparisonPolicy)
            assertFalse(value.toJsonObject().keys.any { it in setOf("accepted", "releaseComplete", "succeeded") })
        }
    }

    @Test
    fun `proofs must bind every selected source component and strict cleanup assurance`() {
        val value = observation()
        val proof = value.proof
        val bad = "b".repeat(64)
        for (changed in listOf(proof.copy(sourceRevisionSha256 = bad), proof.copy(profileSha256 = bad),
                proof.copy(indexSha256 = bad), proof.copy(regressionCorpusSha256 = bad),
                proof.copy(evidenceSha256 = bad), proof.copy(runtimeSha256 = "private"),
                proof.copy(cleanupVerified = false), proof.copy(assurance = RepairValidationAssurance.TEST_ONLY_HOST_PROCESS),
                proof.copy(originalBinarySha256 = null), proof.copy(rebuiltBinarySha256 = null))) {
            assertFailsWith<IllegalArgumentException> { value.copy(proof = changed) }
        }
    }

    @Test
    fun `primary and diff roles require their own fixed canonical names and commitments`() {
        val value = observation()
        val diff = RepairValidationObservedArtifact(repairValidationDiffPath("b".repeat(64)), "b".repeat(64), 40)
        assertEquals(diff, value.copy(diff = diff).diff)
        assertFailsWith<IllegalArgumentException> {
            value.copy(diff = diff.copy(path = "reports/${value.invocation.id}.diff.json"))
        }
        for (path in listOf("reports/repair-revisions/graph.json", "reports/repair-revisions/blobs/private",
                "reports/repair-revisions/nested/${value.invocation.id}.diff.json")) {
            assertFailsWith<IllegalArgumentException> { diff.copy(path = path) }
        }
        assertFailsWith<IllegalArgumentException> { value.copy(primary = value.primary.copy(path = diff.path)) }
        assertFailsWith<IllegalArgumentException> { value.copy(diff = diff.copy(path = value.primary.path)) }
        assertFailsWith<IllegalArgumentException> { observation(RepairValidationObservedOutcome.COMPILE_FAILED).copy(diff = diff) }
        assertFailsWith<IllegalArgumentException> { value.primary.copy(path = "reports/../private") }
        assertFailsWith<IllegalArgumentException> { value.primary.copy(bytes = 0) }
        assertFailsWith<IllegalArgumentException> { value.primary.copy(bytes = 64L * 1024 * 1024 + 1) }
    }

    @Test
    fun `normal receipt copies count physical retention and the shared inspection frame`() {
        val value = observation()
        value.requireRetainedBudget(160)
        assertFailsWith<IllegalArgumentException> { value.requireRetainedBudget(159) }
        val diff = RepairValidationObservedArtifact(repairValidationDiffPath("b".repeat(64)), "b".repeat(64), 40)
        value.copy(diff = diff).requireRetainedBudget(240)
        assertFailsWith<IllegalArgumentException> { value.copy(diff = diff).requireRetainedBudget(239) }
        assertFailsWith<IllegalArgumentException> {
            value.copy(primary = value.primary.copy(bytes = 64L * 1024 * 1024), diff = diff).requireRetainedBudget(Long.MAX_VALUE)
        }
    }

    @Test
    fun `normal logs detach caller collections and refuse duplicate invocation or candidate identities`() {
        val value = observation()
        val caller = mutableListOf(value)
        val log = RepairValidationObservationLog(caller)
        caller.clear()
        assertEquals(listOf(value), log.entries)
        assertFailsWith<UnsupportedOperationException> { (log.entries as MutableList<RepairValidationObservation>).clear() }
        assertFailsWith<IllegalArgumentException> { log.appended(value) }
        val invocation = value.invocation.copy(id = "validation_" + "b".repeat(32))
        val sameCandidate = value.copy(invocation = invocation,
            primary = value.primary.copy(path = "reports/${invocation.id}.validation.json"))
        assertFailsWith<IllegalArgumentException> { log.appended(sameCandidate) }
        assertEquals(RepairValidationObservationLog.EMPTY, RepairValidationObservationLog(emptyList()))
    }

    @Test
    fun `normal log bounds are checked before parsing entries`() {
        val invalid = JsonArray(listOf(JsonPrimitive("PRIVATE malformed entry")))
        assertFailsWith<IllegalArgumentException> { parseRepairValidationObservationLog(invalid, 0) }
        assertFailsWith<IllegalArgumentException> { parseRepairValidationObservationLog(JsonArray(emptyList()), -1) }
        val log = RepairValidationObservationLog(listOf(observation()))
        assertEquals(log, parseRepairValidationObservationLog(log.toJsonArray(), 1))
    }

    @Test
    fun `strict normal schemas refuse unknown fields policy changes and primitive type changes`() {
        val root = observation().toJsonObject()
        val proof = root.getValue("proof").jsonObject
        val primary = root.getValue("primary").jsonObject
        fun proofEdit(name: String, value: JsonPrimitive) =
            JsonObject(root + ("proof" to JsonObject(proof + (name to value))))
        val edits = listOf(JsonObject(root + ("extra" to JsonPrimitive(true))), JsonObject(root - "proof"),
            JsonObject(root + ("schemaVersion" to JsonPrimitive("1"))),
            JsonObject(root + ("comparisonPolicy" to JsonPrimitive("normalized"))),
            proofEdit("cleanupVerified", JsonPrimitive("true")), proofEdit("runtimeSha256", JsonPrimitive(8)),
            JsonObject(root + ("primary" to JsonObject(primary + ("bytes" to JsonPrimitive("80"))))))
        edits.forEach { assertTrue(runCatching { parseRepairValidationObservation(it) }.isFailure) }
    }

    @Test
    fun `schema four preserves normal observations while older run encodings remain absent`() {
        val log = RepairValidationObservationLog(listOf(observation()))
        val current = run(4, log)
        assertEquals(current, parseRepairRunState(current.toJson()))
        assertEquals(current.toJson(), parseRepairRunState(current.toJson()).toJson())
        for (version in 1..3) {
            val legacy = run(version)
            assertFalse("validationObservations" in Json.parseToJsonElement(legacy.toJson()).jsonObject)
            assertEquals(legacy.toJson(), parseRepairRunState(legacy.toJson()).toJson())
            assertFailsWith<IllegalArgumentException> { run(version, log) }
        }
        val root = Json.parseToJsonElement(current.toJson()).jsonObject
        assertFailsWith<IllegalArgumentException> { parseRepairRunState(JsonObject(root - "validationObservations").toString()) }
        assertFailsWith<IllegalArgumentException> {
            parseRepairRunState(JsonObject(root + ("validationObservations" to JsonNull)).toString())
        }
    }

    @Test
    fun `run ownership rejects a different run corpus or too many candidate observations`() {
        val value = observation()
        val log = RepairValidationObservationLog(listOf(value))
        assertFailsWith<IllegalArgumentException> { run(4, log).copy(id = "run_00000002") }
        assertFailsWith<IllegalArgumentException> { run(4, log).copy(regressionCorpusSha256 = "b".repeat(64)) }
        val invocation = value.invocation.copy(id = "validation_" + "b".repeat(32),
            candidateRevisionId = "revision_00000001_" + "c".repeat(16))
        val next = value.copy(invocation = invocation,
            primary = value.primary.copy(path = "reports/${invocation.id}.validation.json"))
        assertFailsWith<IllegalArgumentException> { run(4, log.appended(next)) }
        assertEquals(2, run(4).copy(attemptedCount = 1, validationObservations = log.appended(next)).validationObservations.entries.size)
    }

    @Test
    fun `external normal primary and diff are authenticated before canonical role publication`() {
        val primary = "authored primary".toByteArray()
        val diff = "authored diff".toByteArray()
        val value = observation()
        val source = RepairValidationPublishedArtifact(Path.of("/operator/output/initial.validation.json"), sha256(primary), primary.size.toLong())
        val derived = RepairValidationPublishedArtifact(Path.of("/operator/output/initial.diff.json"), sha256(diff), diff.size.toLong())
        val plan = planRepairValidationObservationRetention(value.invocation, value.proof.copy(evidenceSha256 = source.sha256),
            value.outcome, source, derived, 4096)
        val reads = mapOf(source.path to primary, derived.path to diff)
        val writes = linkedMapOf<String, ByteArray>()
        plan.retain(read = { path, limit -> reads.getValue(path).also { assertEquals(it.size.toLong(), limit) } },
            write = { name, bytes -> writes[name] = bytes }, readRetained = { name, _ -> writes.getValue(name) })
        assertEquals(listOf("${value.invocation.id}.validation.json", "repair-revisions/validation-diffs/${derived.sha256}.json"), writes.keys.toList())
        assertEquals(source.sha256, plan.observation.primary.sha256)
        assertEquals(derived.sha256, plan.observation.diff?.sha256)
        assertFalse(plan.observation.toJsonObject().toString().contains("operator"))
    }

    @Test
    fun `changed normal data and publication failures cannot commit a retained observation`() {
        val primary = "authored primary".toByteArray()
        val value = observation()
        val source = RepairValidationPublishedArtifact(Path.of("/operator/output/initial.validation.json"), sha256(primary), primary.size.toLong())
        val plan = planRepairValidationObservationRetention(value.invocation, value.proof.copy(evidenceSha256 = source.sha256),
            value.outcome, source, null, 4096)
        var writes = 0
        assertFailsWith<IllegalArgumentException> { plan.retain(read = { _, _ -> "changed".toByteArray() },
            write = { _, _ -> writes++ }, readRetained = { _, _ -> primary }) }
        assertEquals(0, writes)
        val failure = IOException("authored immutable publication")
        val thrown = assertFailsWith<IOException> { plan.retain(read = { _, _ -> primary },
            write = { _, _ -> throw failure }, readRetained = { _, _ -> error("uncommitted") }) }
        assertSame(failure, thrown)
    }

    @Test
    fun `normal association refuses each cross run candidate source profile index corpus and binary pair`() {
        val value = observation()
        val i = value.invocation
        fun check(run: String = i.runId, profile: String = i.profileSha256, index: String = i.indexSha256,
            corpus: String = i.regressionCorpusSha256, candidate: String = i.candidateRevisionId,
            source: String = i.sourceRevisionSha256, original: String? = value.proof.originalBinarySha256) =
            requireRepairValidationObservationAssociation(value, run, profile, index, corpus, candidate, source, original)
        check()
        assertFailsWith<IllegalArgumentException> { check(run = "run_00000002") }
        assertFailsWith<IllegalArgumentException> { check(profile = "b".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { check(index = "b".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { check(corpus = "b".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { check(candidate = "revision_00000001_" + "b".repeat(16)) }
        assertFailsWith<IllegalArgumentException> { check(source = "b".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { check(original = "b".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { check(original = null) }
    }

    @Test
    fun `the same revision in later baselines keeps separate run association and invocation commitments`() {
        val first = observation()
        val invocation = first.invocation.copy(runId = "run_00000002", id = "validation_" + "b".repeat(32))
        val second = first.copy(invocation = invocation,
            primary = first.primary.copy(path = "reports/${invocation.id}.validation.json"))
        fun check(value: RepairValidationObservation, run: String) = requireRepairValidationObservationAssociation(value,
            run, value.invocation.profileSha256, value.invocation.indexSha256, value.invocation.regressionCorpusSha256,
            value.invocation.candidateRevisionId, value.invocation.sourceRevisionSha256, value.proof.originalBinarySha256)
        check(first, "run_00000001")
        check(second, "run_00000002")
        assertFalse(first.invocation.commitmentSha256() == second.invocation.commitmentSha256())
        assertFailsWith<IllegalArgumentException> { check(first, "run_00000002") }
        assertFailsWith<IllegalArgumentException> { check(second, "run_00000001") }
        assertEquals(first.proof, second.proof)
    }

    @Test
    fun `operation kinds retain the exact executable role combinations the producer can return`() {
        val failed = observation(RepairValidationObservedOutcome.COMPILE_FAILED)
        val compiled = observation(RepairValidationObservedOutcome.COMPILE_VALID)
        val behavior = observation()
        assertFailsWith<IllegalArgumentException> { failed.copy(proof = failed.proof.copy(rebuiltBinarySha256 = "7".repeat(64))) }
        assertFailsWith<IllegalArgumentException> { compiled.copy(proof = compiled.proof.copy(originalBinarySha256 = "6".repeat(64))) }
        assertFailsWith<IllegalArgumentException> { compiled.copy(proof = compiled.proof.copy(rebuiltBinarySha256 = null)) }
        assertFailsWith<IllegalArgumentException> { behavior.copy(proof = behavior.proof.copy(originalBinarySha256 = null)) }
        assertFailsWith<IllegalArgumentException> { behavior.copy(proof = behavior.proof.copy(rebuiltBinarySha256 = null)) }
    }
}
