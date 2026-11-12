package decompengine.project

import decompengine.agent.AgentTurnIdentity
import decompengine.agent.AgentStopReason
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AcpChangeAssessmentTest {
    private val digest = "a".repeat(64)

    @Test
    fun intentAndUnknownAssessmentRoundTripCanonicallyWithoutInventingAnAfterHash() {
        val identity = AgentTurnIdentity(UUID.randomUUID().toString(), "module-a", digest)
        val intent = AgentTurnIntent.create(
            identity = identity,
            workflowId = "reconstruction-run-1",
            attemptId = identity.turnId,
            profileSha256 = digest,
            policySha256 = "b".repeat(64),
            beforeSha256 = "c".repeat(64),
        )

        assertEquals(intent.sha256, AgentTurnIntent.parse(intent.canonicalBytes()).sha256)
        assertContentEquals(intent.canonicalBytes(), AgentTurnIntent.parse(intent.canonicalBytes()).canonicalBytes())

        val assessment = AcpChangeAssessment.create(
            intent = intent,
            receiptSha256 = null,
            sessionIdSha256 = null,
            changesSha256 = null,
            beforeSha256 = intent.beforeSha256,
            afterSha256 = null,
            observation = AcpChangeObservationStatus.UNKNOWN,
            protocolStopCode = null,
            normalizedStopReason = AgentStopReason.CANCELLED,
            policyVerdict = AcpChangePolicyVerdict.NOT_EVALUATED,
            reasonCodes = listOf("turn-incomplete"),
            validationStatus = AcpChangeValidationStatus.NOT_RUN,
            validationProofSha256 = emptyList(),
            eligibility = AcpChangePublicationEligibility.INTERRUPTED,
            updatesSha256 = null,
        )
        val parsed = AcpChangeAssessment.parse(assessment.canonicalBytes())
        assertEquals(assessment.sha256, parsed.sha256)
        assertEquals(AcpChangeObservationStatus.UNKNOWN, parsed.observation)
        assertEquals(null, parsed.afterSha256)
        assertEquals(AcpChangePublicationEligibility.INTERRUPTED, parsed.eligibility)
    }

    @Test
    fun completeObservationAndPublicationEligibilityRequireTheirEvidence() {
        val intent = AgentTurnIntent.create(
            AgentTurnIdentity(UUID.randomUUID().toString(), "module-a", digest),
            "reconstruction-run-1",
            "attempt-1",
            digest,
            "b".repeat(64),
            "c".repeat(64),
        )

        assertFailsWith<IllegalArgumentException> {
            AcpChangeAssessment.create(
                intent, digest, digest, digest, intent.beforeSha256, null,
                AcpChangeObservationStatus.COMPLETE, null, AgentStopReason.COMPLETED,
                AcpChangePolicyVerdict.ALLOW, emptyList(), AcpChangeValidationStatus.PASSED,
                listOf(digest), AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION, null,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            AcpChangeAssessment.create(
                intent, digest, null, null, intent.beforeSha256, null,
                AcpChangeObservationStatus.COMPLETE, null, AgentStopReason.COMPLETED,
                AcpChangePolicyVerdict.ALLOW, emptyList(), AcpChangeValidationStatus.PASSED,
                listOf(digest), AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION, null,
            )
        }
    }
}
