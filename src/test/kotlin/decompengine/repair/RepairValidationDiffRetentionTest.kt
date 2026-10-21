package decompengine.repair

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Pure naming, graph-reference and cleanup-budget controls; no filesystem or native trial. */
class RepairValidationDiffRetentionTest {
    private val first = "a".repeat(64)
    private val second = "b".repeat(64)
    private fun artifact(hash: String = first, bytes: Long = 40) =
        RepairValidationObservedArtifact(repairValidationDiffPath(hash), hash, bytes)
    private fun plan(names: List<String>, retained: List<RepairValidationObservedArtifact> = emptyList(), limit: Int = 20) =
        planRepairValidationDiffDirectory(names, retained, limit)

    @Test fun `derived paths are content addressed and cannot select graph binding or blob roles`() {
        assertEquals("reports/repair-revisions/validation-diffs/$first.json", repairValidationDiffPath(first))
        assertTrue(validationObservationDiffPath(repairValidationDiffPath(first)))
        for (bad in listOf("reports/repair-revisions/graph.json", "reports/repair-revisions/recovery-binding.json",
                "reports/repair-revisions/blobs/$first", "reports/repair-revisions/validation-diffs/nested/$first.json",
                "reports/repair-revisions/validation-diffs/$first.json.cleanup"))
            assertFailsWith<IllegalArgumentException> { RepairValidationObservedArtifact(bad, first, 40) }
        assertFailsWith<IllegalArgumentException> { repairValidationDiffPath("private") }
    }
    @Test fun `new role population accounts for runs and attempts without widening the original root cap`() {
        for (nodes in listOf(2, 10, 10_000, 1_000_000)) {
            val budget = RepairResourceBudget(maximumRevisionNodes = nodes)
            assertEquals(nodes + 16, repairRevisionDirectoryEntryLimit(budget))
            assertEquals(2 * nodes + 16, repairValidationDiffDirectoryEntryLimit(budget))
        }
    }
    @Test fun `an absent optional directory has no cleanup actions`() {
        val result = plan(emptyList())
        assertTrue(result.orphans.isEmpty())
        assertTrue(result.temporaryTargets.isEmpty())
    }
    @Test fun `identical retained diffs may be shared by independent observation references`() {
        val result = plan(listOf("$first.json"), listOf(artifact(), artifact()))
        assertTrue(result.orphans.isEmpty())
    }
    @Test fun `a diff written before an uncommitted graph is a content addressed orphan candidate`() {
        val result = plan(listOf("$first.json"))
        assertEquals(listOf(RepairValidationDiffOrphan("$first.json", "$first.json", first)), result.orphans)
    }
    @Test fun `the same diff survives recovery when the actual committed graph references it`() {
        val result = plan(listOf("$first.json", "$second.json"), listOf(artifact()))
        assertEquals(listOf(second), result.orphans.map { it.sha256 })
        assertEquals("$second.json", result.orphans.single().targetName)
    }
    @Test fun `interrupted quarantine resumes through the existing exact cleanup target`() {
        val result = plan(listOf("$first.json.cleanup"))
        assertEquals(listOf(RepairValidationDiffOrphan("$first.json", "$first.json.cleanup", first)), result.orphans)
        assertFailsWith<IllegalArgumentException> { plan(listOf("$first.json", "$first.json.cleanup")) }
    }
    @Test fun `partial atomic publications use only the existing reserved temporary role`() {
        val result = plan(listOf(".$first.json.repair-atomic.tmp"))
        assertEquals(listOf("$first.json"), result.temporaryTargets)
        assertTrue(result.orphans.isEmpty())
        assertFailsWith<IllegalArgumentException> { plan(listOf(".$first.json.repair-atomic.tmp"), listOf(artifact())) }
    }
    @Test fun `unknown or foreign names are refused before cleanup can be planned`() {
        for (bad in listOf("private", "../$first.json", "nested/$first.json", "$first.json.other", "graph.json", ".$first.json.tmp"))
            assertFailsWith<IllegalArgumentException> { plan(listOf("$first.json", bad)) }
    }
    @Test fun `missing quarantined or conflicting retained commitments are refused`() {
        assertFailsWith<IllegalArgumentException> { plan(emptyList(), listOf(artifact())) }
        assertFailsWith<IllegalArgumentException> { plan(listOf("$first.json.cleanup"), listOf(artifact())) }
        assertFailsWith<IllegalArgumentException> { plan(listOf("$first.json"), listOf(artifact(), artifact(bytes = 41))) }
        assertFailsWith<IllegalArgumentException> {
            plan(listOf("$first.json"), listOf(RepairValidationObservedArtifact(repairValidationDiffPath(first), second, 40)))
        }
    }
    @Test fun `every directory entry counts before deduplication or filename admission`() {
        assertFailsWith<IllegalArgumentException> { plan(listOf("$first.json", "$second.json"), limit = 1) }
        assertFailsWith<IllegalArgumentException> { plan(listOf("$first.json", "$first.json")) }
        assertFailsWith<IllegalArgumentException> { plan(emptyList(), limit = -1) }
    }
    @Test fun `both quarantine reads are reserved before cleanup without overflow or free failed work`() {
        assertEquals(0L, reserveRepairValidationDiffCleanupBytes(40, 80))
        assertEquals(20L, reserveRepairValidationDiffCleanupBytes(40, 100))
        assertEquals(0L, reserveRepairValidationDiffCleanupBytes(40L * 1024 * 1024, 80L * 1024 * 1024))
        assertFailsWith<RepairBudgetExceededException> { reserveRepairValidationDiffCleanupBytes(40, 79) }
        assertFailsWith<IllegalArgumentException> { reserveRepairValidationDiffCleanupBytes(0, 80) }
        assertFailsWith<IllegalArgumentException> { reserveRepairValidationDiffCleanupBytes(64L * 1024 * 1024 + 1, 80) }
        assertFailsWith<IllegalArgumentException> { reserveRepairValidationDiffCleanupBytes(1, Long.MAX_VALUE) }
    }
}
