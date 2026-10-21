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
        assertEquals(listOf(RepairValidationArtifactOrphan("$first.json", "$first.json", first)), result.orphans)
    }
    @Test fun `the same diff survives recovery when the actual committed graph references it`() {
        val result = plan(listOf("$first.json", "$second.json"), listOf(artifact()))
        assertEquals(listOf(second), result.orphans.map { it.sha256 })
        assertEquals("$second.json", result.orphans.single().targetName)
    }
    @Test fun `interrupted quarantine resumes through the existing exact cleanup target`() {
        val result = plan(listOf("$first.json.cleanup"))
        assertEquals(listOf(RepairValidationArtifactOrphan("$first.json", "$first.json.cleanup", first)), result.orphans)
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
        assertEquals(0L, reserveRepairValidationArtifactCleanupBytes(40, 80))
        assertEquals(20L, reserveRepairValidationArtifactCleanupBytes(40, 100))
        assertEquals(0L, reserveRepairValidationArtifactCleanupBytes(40L * 1024 * 1024, 80L * 1024 * 1024))
        assertFailsWith<RepairBudgetExceededException> { reserveRepairValidationArtifactCleanupBytes(40, 79) }
        assertFailsWith<IllegalArgumentException> { reserveRepairValidationArtifactCleanupBytes(0, 80) }
        assertFailsWith<IllegalArgumentException> { reserveRepairValidationArtifactCleanupBytes(64L * 1024 * 1024 + 1, 80) }
        assertFailsWith<IllegalArgumentException> { reserveRepairValidationArtifactCleanupBytes(1, Long.MAX_VALUE) }
    }

    private val invocation = "validation_" + "c".repeat(32)
    private fun receipt(hash: String = first, id: String = invocation, bytes: Long = 40) =
        RepairValidationObservedArtifact(repairValidationReceiptPath(id, hash), hash, bytes)
    private fun receiptPlan(names: List<String>, retained: List<RepairValidationObservedArtifact> = emptyList(), limit: Int = 20) =
        planRepairValidationReceiptDirectory(names, retained, limit)

    @Test fun `normal primary path carries both invocation ownership and exact content identity`() {
        val path = repairValidationReceiptPath(invocation, first)
        assertEquals("reports/repair-revisions/validation-receipts/${invocation}_$first.json", path)
        assertTrue(validationObservationReceiptPath(path))
        assertTrue(!path.endsWith(".validation.json"))
        for (bad in listOf(path + ".cleanup", "reports/$invocation.validation.json", repairValidationDiffPath(first)))
            assertTrue(!validationObservationReceiptPath(bad))
        assertFailsWith<IllegalArgumentException> { repairValidationReceiptPath("../private", first) }
        assertFailsWith<IllegalArgumentException> { repairValidationReceiptPath(invocation, "private") }
    }
    @Test fun `a normal primary written before an uncommitted graph is an exact owned orphan candidate`() {
        val name = "${invocation}_$first.json"
        val result = receiptPlan(listOf(name))
        assertEquals(listOf(RepairValidationArtifactOrphan(name, name, first)), result.orphans)
        assertTrue(result.temporaryTargets.isEmpty())
    }
    @Test fun `equal primary bytes in separate committed invocations retain independent ownership`() {
        val a = receipt(); val b = receipt(id = "validation_" + "d".repeat(32))
        val names = listOf(a.path.substringAfterLast('/'), b.path.substringAfterLast('/'))
        assertTrue(receiptPlan(names, listOf(a, b)).orphans.isEmpty())
        assertEquals(listOf(names[1]), receiptPlan(names, listOf(a)).orphans.map { it.targetName })
        assertFailsWith<IllegalArgumentException> { receiptPlan(names.take(1), listOf(b)) }
    }
    @Test fun `primary quarantine and atomic leftovers use the existing exact owned roles`() {
        val name = "${invocation}_$first.json"
        assertEquals(listOf(RepairValidationArtifactOrphan(name, "$name.cleanup", first)),
            receiptPlan(listOf("$name.cleanup")).orphans)
        assertEquals(listOf(name), receiptPlan(listOf(repairAtomicTemporaryName(name))).temporaryTargets)
        assertFailsWith<IllegalArgumentException> { receiptPlan(listOf(name, "$name.cleanup")) }
        assertFailsWith<IllegalArgumentException> { receiptPlan(listOf("$name.cleanup"), listOf(receipt())) }
    }
    @Test fun `normal cleanup cannot adopt legacy fatal foreign or cross bound primary names`() {
        val name = "${invocation}_$first.json"
        for (bad in listOf("$invocation.validation.json", "$invocation.validation-failure.json", "$first.json",
                "../$name", "nested/$name", "graph.json", "$name.other"))
            assertFailsWith<IllegalArgumentException> { receiptPlan(listOf(name, bad)) }
        assertFailsWith<IllegalArgumentException> { receiptPlan(emptyList(), listOf(receipt())) }
        assertFailsWith<IllegalArgumentException> { receiptPlan(listOf(name), listOf(receipt(), receipt(bytes = 41))) }
        assertFailsWith<IllegalArgumentException> {
            receiptPlan(listOf(name), listOf(RepairValidationObservedArtifact(repairValidationReceiptPath(invocation, first), second, 40)))
        }
    }
    @Test fun `primary and diff cleanup share one finite allowance while every name counts`() {
        val name = "${invocation}_$first.json"
        assertFailsWith<IllegalArgumentException> { receiptPlan(listOf(name, name)) }
        assertFailsWith<IllegalArgumentException> { receiptPlan(listOf(name), limit = 0) }
        val afterPrimary = reserveRepairValidationArtifactCleanupBytes(40, 100)
        assertEquals(20L, afterPrimary)
        assertFailsWith<RepairBudgetExceededException> { reserveRepairValidationArtifactCleanupBytes(11, afterPrimary) }
        assertEquals(0L, reserveRepairValidationArtifactCleanupBytes(10, afterPrimary))
        assertTrue(receiptPlan(emptyList()).orphans.isEmpty())
    }
}
