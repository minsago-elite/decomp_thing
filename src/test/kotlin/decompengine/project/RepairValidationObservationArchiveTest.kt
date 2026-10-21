package decompengine.project

import decompengine.repair.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Authored maps and byte callbacks only; no project, native validator or archive trial. */
class RepairValidationObservationArchiveTest {
    private val primaryBytes = "authored receipt".toByteArray()
    private val diffBytes = "authored mismatch diff".toByteArray()
    private fun observation(index: Char = 'a'): RepairValidationObservation {
        val invocation = RepairValidationInvocation("validation_" + index.toString().repeat(32), "run_00000001",
            "revision_00000001_" + index.toString().repeat(16), "2".repeat(64), "3".repeat(64), "4".repeat(64), "5".repeat(64))
        val proof = RepairValidationProof(invocation.sourceRevisionSha256, invocation.profileSha256,
            invocation.indexSha256, invocation.regressionCorpusSha256, "6".repeat(64), "7".repeat(64), "8".repeat(64),
            sha256(primaryBytes), true, RepairValidationAssurance.STRICT_CONTAINED)
        return RepairValidationObservation(invocation, proof, RepairValidationObservedOutcome.BEHAVIOR_CHECKED,
            RepairValidationObservedArtifact("reports/${invocation.id}.validation.json", sha256(primaryBytes), primaryBytes.size.toLong()),
            RepairValidationObservedArtifact("reports/repair-revisions/${invocation.id}.diff.json", sha256(diffBytes), diffBytes.size.toLong()))
    }
    private fun payloads(observations: List<RepairValidationObservation>): Map<String, ByteArray> = buildMap {
        observations.forEach { put(it.primary.path, primaryBytes); put(requireNotNull(it.diff).path, diffBytes) }
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
        for (paths in listOf(emptyMap(), mapOf(path to value.primary.sha256, value.primary.path to value.primary.sha256))) {
            assertFailsWith<IllegalArgumentException> {
                selectRepairValidationReceiptForArchive(value.proof.evidenceSha256, null, paths, emptyMap())
            }
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
        assertTrue(readPaths.filter { it.endsWith(".diff.json") }.all { it.startsWith("reports/repair-revisions/") })
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
    fun `legacy empty observations do not acquire new evidence reads`() {
        verifyRepairValidationObservedArtifactsForArchive(emptyList(), emptyMap(), emptyMap()) { _, _ ->
            error("legacy graph must not read observation payloads")
        }
    }
}
