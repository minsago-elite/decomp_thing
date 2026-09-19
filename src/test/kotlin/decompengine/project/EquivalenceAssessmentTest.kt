package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals

class EquivalenceAssessmentTest {
    @Test
    fun `unselected behavior corpus remains not assessed`() {
        assertEquals(
            EquivalenceAssessment(
                EquivalenceStatus.NOT_ASSESSED,
                listOf("required-behavior-corpus-not-selected"),
            ),
            assessEquivalence(emptyList(), emptyList(), true, emptyMap(), emptyList()),
        )
    }

    @Test
    fun `missing or failed selected behavior evidence blocks equivalence`() {
        val assessment = assessEquivalence(
            requiredCorpusSha256 = listOf("a".repeat(64)),
            observedPortableCorpusSha256 = emptyList(),
            behaviorMatched = null,
            behaviorEvidenceProblems = mapOf("reports/stale.behavior.json" to "stale"),
            unresolvedBehaviorReportIds = listOf("stale"),
        )
        assertEquals(EquivalenceStatus.BLOCKED, assessment.status)
        assertEquals(
            listOf(
                "required-behavior-result-unavailable",
                "required-behavior-evidence-problem",
                "required-behavior-report-unresolved",
                "required-behavior-corpus-missing",
            ),
            assessment.blockers,
        )
    }

    @Test
    fun `a selected current matching corpus passes the behavior gate`() {
        val corpus = "b".repeat(64)
        assertEquals(
            EquivalenceAssessment(EquivalenceStatus.PASSED, emptyList()),
            assessEquivalence(listOf(corpus), listOf(corpus), true, emptyMap(), emptyList()),
        )
    }
}
