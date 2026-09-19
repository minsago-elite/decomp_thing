package decompengine.project

enum class EquivalenceStatus(val wireValue: String) {
    NOT_ASSESSED("not-assessed"),
    BLOCKED("blocked"),
    PASSED("passed"),
}

data class EquivalenceAssessment(
    val status: EquivalenceStatus,
    val blockers: List<String>,
)

/**
 * Derives the behavior gate from the caller-selected current corpus.
 * An observation report's self-selected corpus is not enough to pass this gate.
 */
fun assessEquivalence(
    requiredCorpusSha256: List<String>,
    observedPortableCorpusSha256: List<String>,
    behaviorMatched: Boolean?,
    behaviorEvidenceProblems: Map<String, String>,
    unresolvedBehaviorReportIds: List<String>,
): EquivalenceAssessment {
    if (requiredCorpusSha256.isEmpty()) {
        return EquivalenceAssessment(
            EquivalenceStatus.NOT_ASSESSED,
            listOf("required-behavior-corpus-not-selected"),
        )
    }

    val blockers = linkedSetOf<String>()
    when (behaviorMatched) {
        false -> blockers += "required-behavior-mismatch"
        null -> blockers += "required-behavior-result-unavailable"
        true -> Unit
    }
    if (behaviorEvidenceProblems.isNotEmpty()) blockers += "required-behavior-evidence-problem"
    if (unresolvedBehaviorReportIds.isNotEmpty()) blockers += "required-behavior-report-unresolved"
    if (!requiredCorpusSha256.toSet().containsAll(observedPortableCorpusSha256) ||
        !observedPortableCorpusSha256.toSet().containsAll(requiredCorpusSha256)
    ) {
        blockers += "required-behavior-corpus-missing"
    }
    return if (blockers.isEmpty()) {
        EquivalenceAssessment(EquivalenceStatus.PASSED, emptyList())
    } else {
        EquivalenceAssessment(EquivalenceStatus.BLOCKED, blockers.toList())
    }
}
