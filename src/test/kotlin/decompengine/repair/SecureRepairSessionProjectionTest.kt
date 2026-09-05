package decompengine.repair

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotSame
import kotlin.test.assertTrue

class SecureRepairSessionProjectionTest {
    @Test
    fun `session facade preserves invocation evidence and publication eligibility`() {
        val copy = SecureRepairSession::class.java.getDeclaredMethod("copyIteration", RepairIteration::class.java)
            .also { it.isAccessible = true }
        for (mode in RepairPublicationMode.entries) {
            for (status in listOf(RepairAgentAssessmentStatus.ACCEPTED, RepairAgentAssessmentStatus.REJECTED)) {
                val binding = RepairAgentInvocationBinding(
                    "reports/repair-revisions/revision_000001.acp-receipt.json", "a".repeat(64), 2,
                    "b".repeat(64), "c".repeat(64), "returned-completed", true, status,
                )
                val original = RepairIteration(
                    index = 1, failureKind = "behavior", prompt = "prompt digest", summary = "repair assessment",
                    patches = listOf(RepairPatch("src/program.c", byteArrayOf(0, 1, 2))),
                    retainedRegressionIds = listOf("retained"),
                    before = RepairEvidence("behavior", "one mismatch"),
                    after = RepairEvidence(if (status == RepairAgentAssessmentStatus.ACCEPTED) "valid" else "behavior", "checked"),
                    succeeded = status == RepairAgentAssessmentStatus.ACCEPTED,
                    agentInvocation = binding, publicationMode = mode,
                )

                val projected = copy.invoke(null, original) as RepairIteration

                assertEquals(original, projected)
                assertEquals(original.releaseComplete, projected.releaseComplete)
                assertNotSame(original, projected)
                assertNotSame(original.agentInvocation, projected.agentInvocation)
                assertNotSame(original.patches.single(), projected.patches.single())
                if (mode == RepairPublicationMode.ACP_RELEASE && status == RepairAgentAssessmentStatus.ACCEPTED) {
                    assertTrue(projected.releaseComplete)
                }
            }
        }
    }
}
