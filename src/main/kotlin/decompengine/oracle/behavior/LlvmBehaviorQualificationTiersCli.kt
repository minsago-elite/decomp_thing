package decompengine.oracle.behavior

import java.nio.file.Path

/**
 * Authenticates the checked LLVM behavior qualification tiers and requires the given GitHub event
 * to select the expected tier. CI events select the bounded smoke tier, which is never eligible for
 * production evidence; manual and periodic events select the full corpus matrix. This validates
 * policy only: nothing is executed and no run is admitted as evidence.
 */
object LlvmBehaviorQualificationTiersCli {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 4 && arguments[0] == "--event" && arguments[2] == "--tier") {
            "usage: verifyLlvmBehaviorQualificationTiers --args='--event <github event name> --tier <tier>'"
        }
        val event = LlvmBehaviorQualificationEvent.parse(arguments[1])
        val expected = LlvmBehaviorQualificationTierKind.entries.firstOrNull { it.policyName == arguments[3] }
            ?: throw LlvmBehaviorQualificationTierException("unsupported qualification tier: ${arguments[3]}")
        val profile = Path.of("oracle/llvm/22.1.6").toAbsolutePath().normalize()
        val reference = LlvmBehaviorReferenceEvidenceVerifier.verify(
            corpusPath = profile.resolve("behavior-corpus.json"),
            reportPath = profile.resolve("behavior-corpus-evidence.json"),
            diagnosticMatrixPath = profile.resolve("diagnostic-matrix.json"),
            artifactManifestPath = profile.resolve("oracle-manifest.json"),
        )
        val policy = LlvmBehaviorQualificationTierVerifier.verify(
            policyPath = profile.resolve("behavior-qualification-tiers.json"),
            corpusPath = profile.resolve("behavior-corpus.json"),
            reference = reference,
        )
        val selected = policy.tierFor(event).kind
        if (selected != expected) {
            throw LlvmBehaviorQualificationTierException(
                "${event.eventName} selects ${selected.policyName}, not ${expected.policyName}",
            )
        }
        println(describe(policy, event))
    }

    internal fun describe(policy: LlvmBehaviorQualificationTierPolicy, event: LlvmBehaviorQualificationEvent): String {
        val tier = policy.tierFor(event)
        return when (tier.kind) {
            LlvmBehaviorQualificationTierKind.CI_SMOKE ->
                "${event.eventName} selects ci-smoke: ${tier.caseIds.size} of ${policy.corpusCaseIds.size} cases, " +
                    "${tier.repetitions} repetition, aggregate wall bound " +
                    "${tier.maximumAggregateWallMilliseconds} ms; never eligible for production evidence " +
                    "(policy ${policy.policySha256})"
            LlvmBehaviorQualificationTierKind.FULL_QUALIFICATION ->
                "${event.eventName} selects full-qualification: all ${tier.caseIds.size} corpus cases, " +
                    "at least ${tier.repetitions} clean repetitions under corpus limits; policy only, no evidence admitted " +
                    "(policy ${policy.policySha256})"
        }
    }
}
