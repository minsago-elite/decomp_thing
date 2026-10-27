package decompengine.project

import decompengine.repair.*
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Authored maps and byte callbacks only; no project, native validator or archive trial. */
class RepairValidationObservationArchiveTest {
    // Partial authored receipt DTOs exercise association checks, not contained execution qualification.
    private val primary = JsonObject(mapOf("schemaVersion" to JsonPrimitive(2),
        "provider" to JsonPrimitive("generated-c-linux-bubblewrap-cgroup-v1"),
        "outcome" to JsonPrimitive("behavior-checked"), "matches" to JsonPrimitive(false),
        "sourceRevisionSha256" to JsonPrimitive("2".repeat(64)), "profileSha256" to JsonPrimitive("3".repeat(64)),
        "indexSha256" to JsonPrimitive("4".repeat(64)), "regressionCorpusSha256" to JsonPrimitive("5".repeat(64)),
        "runtimeSha256" to JsonPrimitive("8".repeat(64)), "cleanupVerified" to JsonPrimitive(true),
        "assurance" to JsonPrimitive("strict-contained"),
        "originalExecutable" to JsonObject(mapOf("sha256" to JsonPrimitive("6".repeat(64)))),
        "rebuiltExecutable" to JsonObject(mapOf("sha256" to JsonPrimitive("7".repeat(64)))),
        "inputs" to JsonArray(listOf("case-a", "case-b").map { JsonObject(mapOf("id" to JsonPrimitive(it))) })))
    private val diff = JsonObject(mapOf("id" to JsonPrimitive("authored mismatch"), "matches" to JsonPrimitive(false),
        "cases" to JsonArray(listOf("case-a", "case-b").map { JsonObject(mapOf("id" to JsonPrimitive(it))) })))
    private val primaryBytes = primary.toString().toByteArray()
    private val diffBytes = diff.toString().toByteArray()
    private fun observation(index: Char = 'a', receipt: ByteArray = primaryBytes,
        derived: ByteArray = diffBytes): RepairValidationObservation {
        val invocation = RepairValidationInvocation("validation_" + index.toString().repeat(32), "run_00000001",
            "revision_00000001_" + index.toString().repeat(16), "2".repeat(64), "3".repeat(64), "4".repeat(64), "5".repeat(64))
        val proof = RepairValidationProof(invocation.sourceRevisionSha256, invocation.profileSha256,
            invocation.indexSha256, invocation.regressionCorpusSha256, "6".repeat(64), "7".repeat(64), "8".repeat(64),
            sha256(receipt), true, RepairValidationAssurance.STRICT_CONTAINED)
        return RepairValidationObservation(invocation, proof, RepairValidationObservedOutcome.BEHAVIOR_CHECKED,
            RepairValidationObservedArtifact(repairValidationReceiptPath(invocation.id, sha256(receipt)), sha256(receipt), receipt.size.toLong()),
            RepairValidationObservedArtifact(repairValidationDiffPath(sha256(derived)), sha256(derived), derived.size.toLong()))
    }
    private fun payloads(observations: List<RepairValidationObservation>): Map<String, ByteArray> = buildMap {
        observations.forEach { put(it.primary.path, primaryBytes); put(requireNotNull(it.diff).path, diffBytes) }
    }
    private fun verify(value: RepairValidationObservation, receipt: ByteArray = primaryBytes,
        derived: ByteArray = diffBytes) {
        val payloads = buildMap {
            put(value.primary.path, receipt)
            value.diff?.let { put(it.path, derived) }
        }
        verifyRepairValidationObservedArtifactsForArchive(listOf(value), payloads.mapValues { sha256(it.value) },
            payloads.mapValues { it.value.size.toLong() }) { path, _ -> payloads.getValue(path) }
    }

    @Test
    fun `a bound canonical receipt selects its exact path despite identical operator aliases`() {
        val value = observation()
        val paths = mapOf(value.primary.path to value.primary.sha256, "reports/initial.validation.json" to value.primary.sha256)
        assertEquals(value.primary.path, selectRepairValidationReceiptForArchive(value.proof.evidenceSha256,
            value.primary, paths, mapOf(value.primary.path to value.primary.bytes)))
    }

    @Test
    fun `equal receipt bytes in different invocations retain distinct canonical ownership`() {
        val a = observation('a'); val b = observation('b')
        val payloads = payloads(listOf(a, b))
        val hashes = payloads.mapValues { sha256(it.value) }
        val sizes = payloads.mapValues { it.value.size.toLong() }
        for (value in listOf(a, b)) assertEquals(value.primary.path,
            selectRepairValidationReceiptForArchive(value.proof.evidenceSha256, value.primary, hashes, sizes))
    }

    @Test
    fun `a missing changed or incorrectly sized canonical receipt cannot fall back to an alias`() {
        val value = observation()
        val alias = "reports/initial.validation.json" to value.primary.sha256
        val valid = mapOf(value.primary.path to value.primary.sha256, alias)
        val size = mapOf(value.primary.path to value.primary.bytes)
        for (hashes in listOf(mapOf(alias), valid + (value.primary.path to "0".repeat(64)))) {
            assertFailsWith<IllegalArgumentException> {
                selectRepairValidationReceiptForArchive(value.proof.evidenceSha256, value.primary, hashes, size)
            }
        }
        for (sizes in listOf(emptyMap(), size + (value.primary.path to value.primary.bytes + 1))) {
            assertFailsWith<IllegalArgumentException> {
                selectRepairValidationReceiptForArchive(value.proof.evidenceSha256, value.primary, valid, sizes)
            }
        }
    }

    @Test
    fun `legacy absence preserves unique digest lookup and duplicate refusal`() {
        val value = observation()
        val path = "reports/initial.validation.json"
        assertEquals(path, selectRepairValidationReceiptForArchive(value.proof.evidenceSha256, null,
            mapOf(path to value.primary.sha256), emptyMap()))
        for (paths in listOf(emptyMap(), mapOf(path to value.primary.sha256, "reports/other.validation.json" to value.primary.sha256))) {
            assertFailsWith<IllegalArgumentException> {
                selectRepairValidationReceiptForArchive(value.proof.evidenceSha256, null, paths, emptyMap())
            }
        }
    }

    @Test
    fun `managed normal primary bytes cannot make a legacy receipt digest lookup ambiguous`() {
        val value = observation()
        val legacy = "reports/initial.validation.json"
        assertEquals(legacy, selectRepairValidationReceiptForArchive(value.proof.evidenceSha256, null,
            mapOf(legacy to value.primary.sha256, value.primary.path to value.primary.sha256), emptyMap()))
        assertFailsWith<IllegalArgumentException> {
            selectRepairValidationReceiptForArchive(value.proof.evidenceSha256, null,
                mapOf(value.primary.path to value.primary.sha256), emptyMap())
        }
    }

    @Test
    fun `all recorded observations verify both exact roles including earlier mismatches`() {
        val observations = listOf(observation('a'), observation('b'))
        val payloads = payloads(observations)
        val readPaths = mutableListOf<String>()
        verifyRepairValidationObservedArtifactsForArchive(observations, payloads.mapValues { sha256(it.value) },
            payloads.mapValues { it.value.size.toLong() }) { path, limit ->
            readPaths += path
            payloads.getValue(path).also { assertEquals(it.size.toLong(), limit) }
        }
        assertEquals(payloads.keys.toList(), readPaths)
        assertEquals(readPaths.size, readPaths.distinct().size)
        assertTrue(readPaths.filter { it.contains("/validation-diffs/") }.all { validationObservationDiffPath(it) })
    }

    @Test
    fun `missing or rebound diff inventory is refused before reading that role`() {
        val value = observation(); val diff = requireNotNull(value.diff)
        val payloads = payloads(listOf(value))
        val hashes = payloads.mapValues { sha256(it.value) }
        val sizes = payloads.mapValues { it.value.size.toLong() }
        val inventories = listOf((hashes - diff.path) to sizes, (hashes + (diff.path to "0".repeat(64))) to sizes,
            hashes to (sizes - diff.path), hashes to (sizes + (diff.path to diff.bytes + 1)))
        for ((inventory, counts) in inventories) {
            val reads = mutableListOf<String>()
            assertFailsWith<IllegalArgumentException> {
                verifyRepairValidationObservedArtifactsForArchive(listOf(value), inventory, counts) { path, _ ->
                    reads += path; payloads.getValue(path)
                }
            }
            assertTrue(diff.path !in reads)
        }
    }

    @Test
    fun `inventory agreement cannot conceal changed bytes at either retained role`() {
        val value = observation(); val payloads = payloads(listOf(value))
        for (changedPath in payloads.keys) {
            assertFailsWith<IllegalArgumentException> {
                verifyRepairValidationObservedArtifactsForArchive(listOf(value), payloads.mapValues { sha256(it.value) },
                    payloads.mapValues { it.value.size.toLong() }) { path, _ ->
                    if (path == changedPath) payloads.getValue(path).copyOf().also { it[0] = 0 } else payloads.getValue(path)
                }
            }
        }
    }

    @Test
    fun `a byte perfect mismatch primary cannot archive an omitted derived role`() {
        val value = observation().copy(diff = null)
        assertFailsWith<IllegalArgumentException> {
            verifyRepairValidationObservedArtifactsForArchive(listOf(value),
                mapOf(value.primary.path to value.primary.sha256), mapOf(value.primary.path to value.primary.bytes)) { path, limit ->
                assertEquals(value.primary.path, path)
                assertEquals(primaryBytes.size.toLong(), limit)
                primaryBytes
            }
        }
    }

    @Test
    fun `rejected observation receipts cannot rebind any proof digest through self consistent inventory`() {
        for (field in listOf("sourceRevisionSha256", "profileSha256", "indexSha256", "regressionCorpusSha256", "runtimeSha256")) {
            val bytes = JsonObject(primary + (field to JsonPrimitive("9".repeat(64)))).toString().toByteArray()
            assertFailsWith<IllegalArgumentException> { verify(observation(receipt = bytes), bytes) }
        }
    }

    @Test
    fun `original and rebuilt executable identities are bound even for unaccepted observations`() {
        for (field in listOf("originalExecutable", "rebuiltExecutable")) {
            for (executable in listOf(JsonNull, JsonPrimitive("7".repeat(64)),
                    JsonObject(mapOf("sha256" to JsonPrimitive("9".repeat(64)))))) {
                val bytes = JsonObject(primary + (field to executable)).toString().toByteArray()
                assertFailsWith<IllegalArgumentException> { verify(observation(receipt = bytes), bytes) }
            }
        }
    }

    @Test
    fun `receipt cleanup assurance and primitive types cannot be relabeled by a graph digest`() {
        val edits = listOf(primary + ("cleanupVerified" to JsonPrimitive(false)),
            primary + ("cleanupVerified" to JsonPrimitive("true")), primary + ("assurance" to JsonPrimitive("test-only")),
            primary + ("runtimeSha256" to JsonPrimitive(8)), primary - "sourceRevisionSha256")
        for (fields in edits) {
            val bytes = JsonObject(fields).toString().toByteArray()
            assertFailsWith<IllegalArgumentException> { verify(observation(receipt = bytes), bytes) }
        }
    }

    @Test
    fun `earlier compile failure and compile only observations retain nullable executable roles`() {
        for (outcome in listOf(RepairValidationObservedOutcome.COMPILE_FAILED, RepairValidationObservedOutcome.COMPILE_VALID)) {
            val rebuilt = if (outcome == RepairValidationObservedOutcome.COMPILE_FAILED) null else "7".repeat(64)
            val root = JsonObject(primary + mapOf("outcome" to JsonPrimitive(outcome.name.lowercase().replace('_', '-')),
                "originalExecutable" to JsonNull, "rebuiltExecutable" to
                    (rebuilt?.let { JsonObject(mapOf("sha256" to JsonPrimitive(it))) } ?: JsonNull)))
            val bytes = root.toString().toByteArray()
            val initial = observation(receipt = bytes)
            val value = initial.copy(outcome = outcome, proof = initial.proof.copy(originalBinarySha256 = null,
                rebuiltBinarySha256 = rebuilt), diff = null)
            verify(value, bytes)
            val unexpected = JsonObject(root + ("originalExecutable" to primary.getValue("originalExecutable"))).toString().toByteArray()
            val rebound = value.copy(proof = value.proof.copy(evidenceSha256 = sha256(unexpected)),
                primary = value.primary.copy(path = repairValidationReceiptPath(value.invocation.id, sha256(unexpected)),
                    sha256 = sha256(unexpected), bytes = unexpected.size.toLong()))
            assertFailsWith<IllegalArgumentException> { verify(rebound, unexpected) }
        }
    }

    @Test
    fun `content addressed arbitrary bytes cannot masquerade as a derived diff`() {
        val bytes = "authored arbitrary bytes".toByteArray()
        assertFails { verify(observation(derived = bytes), derived = bytes) }
        val notObject = "[]".toByteArray()
        assertFails { verify(observation(derived = notObject), derived = notObject) }
    }

    @Test
    fun `derived diff schema and false match flag remain mandatory after hash rebinding`() {
        val edits = listOf(diff - "id", diff + ("id" to JsonPrimitive(1)), diff + ("extra" to JsonPrimitive(true)),
            diff + ("matches" to JsonPrimitive(true)), diff + ("matches" to JsonPrimitive("false")),
            diff + ("cases" to JsonPrimitive("case-a")))
        for (fields in edits) {
            val bytes = JsonObject(fields).toString().toByteArray()
            assertFails { verify(observation(derived = bytes), derived = bytes) }
        }
    }

    @Test
    fun `derived diff cannot reorder omit duplicate or substitute retained input identities`() {
        for (ids in listOf(listOf("case-b", "case-a"), listOf("case-a"), listOf("case-a", "case-a"),
                listOf("case-a", "foreign"), emptyList())) {
            val cases = JsonArray(ids.map { JsonObject(mapOf("id" to JsonPrimitive(it))) })
            val bytes = JsonObject(diff + ("cases" to cases)).toString().toByteArray()
            assertFailsWith<IllegalArgumentException> { verify(observation(derived = bytes), derived = bytes) }
        }
    }

    @Test
    fun `a shared diff cannot bind incompatible primary input inventories`() {
        val a = observation('a')
        val changed = JsonObject(primary + ("inputs" to JsonArray(listOf(JsonObject(mapOf("id" to JsonPrimitive("other")))))))
            .toString().toByteArray()
        val b = observation('b', changed)
        val payloads = mapOf(a.primary.path to primaryBytes, b.primary.path to changed, requireNotNull(a.diff).path to diffBytes)
        assertFailsWith<IllegalArgumentException> {
            verifyRepairValidationObservedArtifactsForArchive(listOf(a, b), payloads.mapValues { sha256(it.value) },
                payloads.mapValues { it.value.size.toLong() }) { path, _ -> payloads.getValue(path) }
        }
    }

    @Test
    fun `legacy empty observations do not acquire new evidence reads`() {
        verifyRepairValidationObservedArtifactsForArchive(emptyList(), emptyMap(), emptyMap()) { _, _ ->
            error("legacy graph must not read observation payloads")
        }
    }
}
