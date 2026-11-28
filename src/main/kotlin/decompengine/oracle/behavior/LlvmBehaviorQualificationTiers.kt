package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

class LlvmBehaviorQualificationTierException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** GitHub event names that may start an LLVM behavior qualification run. Anything else is rejected. */
enum class LlvmBehaviorQualificationEvent(val eventName: String) {
    PULL_REQUEST("pull_request"),
    PUSH("push"),
    SCHEDULE("schedule"),
    WORKFLOW_DISPATCH("workflow_dispatch"),
    ;

    companion object {
        fun parse(name: String): LlvmBehaviorQualificationEvent =
            entries.firstOrNull { it.eventName == name } ?: tierFail("unsupported qualification event: $name")
    }
}

enum class LlvmBehaviorQualificationTierKind(val policyName: String) {
    CI_SMOKE("ci-smoke"),
    FULL_QUALIFICATION("full-qualification"),
}

/**
 * One authenticated tier. [caseIds] is the exact case set a run of this tier must execute;
 * [repetitions] is exact for CI smoke and a minimum for full qualification.
 */
class LlvmBehaviorQualificationTier internal constructor(
    val kind: LlvmBehaviorQualificationTierKind,
    val events: Set<LlvmBehaviorQualificationEvent>,
    val caseIds: List<String>,
    val repetitions: Int,
    val caseLimits: Map<String, Long>,
    val maximumAggregateWallMilliseconds: Long?,
    val productionEvidence: Boolean,
)

/** Admission of one completed run. Only a full-matrix, repeated, manual or periodic run is production evidence. */
class LlvmBehaviorQualificationAdmission internal constructor(
    val tier: LlvmBehaviorQualificationTierKind,
    val event: LlvmBehaviorQualificationEvent,
    val caseCount: Int,
    val repetitions: Int,
    val productionEvidence: Boolean,
)

/**
 * Separates bounded CI smoke from full target/resource qualification (#917).
 *
 * The policy is bound to the authenticated behavior corpus. CI events select a strict, bounded
 * subset at one repetition whose ceilings never exceed the corpus limits, and such a run is never
 * production evidence. Manual and periodic events select every corpus case at three or more
 * clean repetitions. This gate does not execute Clang, measure resources, or derive regression
 * ratios; those remain with the measurement and threshold slices (#915, #916).
 */
class LlvmBehaviorQualificationTierPolicy internal constructor(
    val corpusId: String,
    val corpusSha256: String,
    val policySha256: String,
    val corpusCaseIds: List<String>,
    val smoke: LlvmBehaviorQualificationTier,
    val full: LlvmBehaviorQualificationTier,
) {
    fun tierFor(event: LlvmBehaviorQualificationEvent): LlvmBehaviorQualificationTier =
        listOf(smoke, full).single { event in it.events }

    fun admit(
        requested: LlvmBehaviorQualificationTierKind,
        event: LlvmBehaviorQualificationEvent,
        observedCaseIds: List<String>,
        repetitions: Int,
    ): LlvmBehaviorQualificationAdmission {
        val tier = tierFor(event)
        if (tier.kind != requested) {
            tierFail("${event.eventName} runs must use ${tier.kind.policyName}, not ${requested.policyName}")
        }
        if (observedCaseIds.toSet().size != observedCaseIds.size) tierFail("observed case identifiers repeat")
        if (observedCaseIds.toSet() != tier.caseIds.toSet()) {
            tierFail("${tier.kind.policyName} runs must execute exactly the declared case set")
        }
        when (tier.kind) {
            LlvmBehaviorQualificationTierKind.CI_SMOKE -> if (repetitions != tier.repetitions) {
                tierFail("ci-smoke runs must use exactly ${tier.repetitions} repetition")
            }
            LlvmBehaviorQualificationTierKind.FULL_QUALIFICATION -> if (repetitions < tier.repetitions) {
                tierFail("full-qualification runs need at least ${tier.repetitions} clean repetitions")
            }
        }
        return LlvmBehaviorQualificationAdmission(
            tier.kind,
            event,
            observedCaseIds.size,
            repetitions,
            tier.productionEvidence,
        )
    }
}

object LlvmBehaviorQualificationTierVerifier {
    /** Smoke must finish inside this worst-case wall budget, whatever the policy file says. */
    const val MAXIMUM_SMOKE_AGGREGATE_WALL_MILLISECONDS = 180_000L
    const val MINIMUM_FULL_REPETITIONS = 3

    fun verify(
        policyPath: Path,
        corpusPath: Path,
        reference: LlvmBehaviorReferenceEvidence,
    ): LlvmBehaviorQualificationTierPolicy = try {
        val corpusSnapshot = OracleArtifacts.read(corpusPath, OracleArtifactLimits(MAXIMUM_CORPUS_BYTES))
        if (corpusSnapshot.sha256 != reference.corpusSha256) {
            tierFail("behavior corpus changed after reference authentication")
        }
        val corpus = OracleJson.parse(corpusSnapshot.bytes, jsonLimits(MAXIMUM_CORPUS_BYTES)) as? JsonObject
            ?: tierFail("behavior corpus root must be an object")
        val corpusLimits = corpus.obj("limits", "behavior corpus").entries.associate { (key, value) ->
            key to value.positiveLong("behavior corpus limit $key")
        }
        val policySnapshot = OracleArtifacts.readCanonical(
            policyPath,
            OracleArtifactLimits(MAXIMUM_POLICY_BYTES),
            jsonLimits(MAXIMUM_POLICY_BYTES),
        )
        val policy = OracleJson.parse(policySnapshot.bytes, jsonLimits(MAXIMUM_POLICY_BYTES)) as? JsonObject
            ?: tierFail("qualification tier policy root must be an object")
        parsePolicy(policy, policySnapshot.sha256, reference, corpusLimits)
    } catch (failure: LlvmBehaviorQualificationTierException) {
        throw failure
    } catch (failure: Exception) {
        throw LlvmBehaviorQualificationTierException(
            "LLVM behavior qualification tier verification failed: " +
                (failure.message ?: failure.javaClass.simpleName),
            failure,
        )
    }

    private fun parsePolicy(
        policy: JsonObject,
        policySha256: String,
        reference: LlvmBehaviorReferenceEvidence,
        corpusLimits: Map<String, Long>,
    ): LlvmBehaviorQualificationTierPolicy {
        policy.exactFields(setOf("schemaVersion", "corpus", "tiers"), "qualification tier policy")
        if (policy["schemaVersion"].positiveLong("schemaVersion") != 1L) tierFail("unsupported schemaVersion")
        val corpusBinding = policy.obj("corpus", "qualification tier policy")
        corpusBinding.exactFields(setOf("id", "sha256"), "corpus binding")
        if (corpusBinding["id"].string("corpus id") != reference.corpusId ||
            corpusBinding["sha256"].string("corpus sha256") != reference.corpusSha256
        ) {
            tierFail("qualification tier policy is not bound to the authenticated behavior corpus")
        }
        val tiers = policy.obj("tiers", "qualification tier policy")
        tiers.exactFields(LlvmBehaviorQualificationTierKind.entries.map { it.policyName }.toSet(), "tiers")
        val corpusCaseIds = reference.caseIds.toList()
        val smoke = parseSmoke(tiers.obj("ci-smoke", "tiers"), corpusCaseIds, corpusLimits)
        val full = parseFull(tiers.obj("full-qualification", "tiers"), corpusCaseIds, corpusLimits)
        return LlvmBehaviorQualificationTierPolicy(
            reference.corpusId,
            reference.corpusSha256,
            policySha256,
            corpusCaseIds,
            smoke,
            full,
        )
    }

    private fun parseSmoke(
        tier: JsonObject,
        corpusCaseIds: List<String>,
        corpusLimits: Map<String, Long>,
    ): LlvmBehaviorQualificationTier {
        val label = "ci-smoke tier"
        tier.exactFields(
            setOf(
                "events",
                "productionEvidence",
                "repetitions",
                "caseIds",
                "caseLimits",
                "maximumAggregateWallMilliseconds",
            ),
            label,
        )
        val events = parseEvents(tier, label, SMOKE_EVENTS)
        if (tier["productionEvidence"].boolean("$label productionEvidence")) {
            tierFail("$label can never be production evidence")
        }
        if (tier["repetitions"].positiveLong("$label repetitions") != 1L) tierFail("$label must run exactly once")
        val caseIds = tier.array("caseIds", label).map { it.string("$label case identifier") }
        if (caseIds.isEmpty()) tierFail("$label must select at least one case")
        if (caseIds != caseIds.sorted() || caseIds.toSet().size != caseIds.size) {
            tierFail("$label case identifiers must be sorted and unique")
        }
        val unknown = caseIds.filterNot { it in corpusCaseIds }
        if (unknown.isNotEmpty()) tierFail("$label selects cases outside the corpus: $unknown")
        if (caseIds.size >= corpusCaseIds.size) tierFail("$label must be a strict subset of the corpus")
        val limitsObject = tier.obj("caseLimits", label)
        limitsObject.exactFields(corpusLimits.keys, "$label caseLimits")
        val caseLimits = limitsObject.entries.associate { (key, value) ->
            val limit = value.positiveLong("$label caseLimits $key")
            if (limit > corpusLimits.getValue(key)) tierFail("$label caseLimits $key exceeds the corpus ceiling")
            key to limit
        }
        val aggregate = tier["maximumAggregateWallMilliseconds"].positiveLong("$label aggregate wall bound")
        if (aggregate > MAXIMUM_SMOKE_AGGREGATE_WALL_MILLISECONDS) {
            tierFail("$label aggregate wall bound exceeds $MAXIMUM_SMOKE_AGGREGATE_WALL_MILLISECONDS ms")
        }
        val timeout = caseLimits["timeoutMilliseconds"] ?: tierFail("$label needs a per-case timeout")
        if (Math.multiplyExact(timeout, caseIds.size.toLong()) > aggregate) {
            tierFail("$label worst-case wall time exceeds its aggregate bound")
        }
        return LlvmBehaviorQualificationTier(
            LlvmBehaviorQualificationTierKind.CI_SMOKE,
            events,
            caseIds,
            1,
            caseLimits,
            aggregate,
            productionEvidence = false,
        )
    }

    private fun parseFull(
        tier: JsonObject,
        corpusCaseIds: List<String>,
        corpusLimits: Map<String, Long>,
    ): LlvmBehaviorQualificationTier {
        val label = "full-qualification tier"
        tier.exactFields(
            setOf("events", "productionEvidence", "minimumRepetitions", "caseSelection", "caseLimitSource"),
            label,
        )
        val events = parseEvents(tier, label, FULL_EVENTS)
        if (!tier["productionEvidence"].boolean("$label productionEvidence")) {
            tierFail("$label must be the production evidence tier")
        }
        val repetitions = tier["minimumRepetitions"].positiveLong("$label minimumRepetitions")
        if (repetitions < MINIMUM_FULL_REPETITIONS || repetitions > MAXIMUM_FULL_REPETITIONS) {
            tierFail("$label needs $MINIMUM_FULL_REPETITIONS to $MAXIMUM_FULL_REPETITIONS clean repetitions")
        }
        if (tier["caseSelection"].string("$label caseSelection") != "every-corpus-case") {
            tierFail("$label must select every corpus case")
        }
        if (tier["caseLimitSource"].string("$label caseLimitSource") != "corpus") {
            tierFail("$label must use the corpus-declared case limits")
        }
        return LlvmBehaviorQualificationTier(
            LlvmBehaviorQualificationTierKind.FULL_QUALIFICATION,
            events,
            corpusCaseIds,
            repetitions.toInt(),
            corpusLimits,
            maximumAggregateWallMilliseconds = null,
            productionEvidence = true,
        )
    }

    private fun parseEvents(
        tier: JsonObject,
        label: String,
        required: List<LlvmBehaviorQualificationEvent>,
    ): Set<LlvmBehaviorQualificationEvent> {
        val names = tier.array("events", label).map { it.string("$label event") }
        if (names != required.map { it.eventName }) {
            tierFail("$label events must be exactly ${required.map { it.eventName }}")
        }
        return names.map(LlvmBehaviorQualificationEvent::parse).toSet()
    }

    private val SMOKE_EVENTS = listOf(LlvmBehaviorQualificationEvent.PULL_REQUEST, LlvmBehaviorQualificationEvent.PUSH)
    private val FULL_EVENTS = listOf(
        LlvmBehaviorQualificationEvent.SCHEDULE,
        LlvmBehaviorQualificationEvent.WORKFLOW_DISPATCH,
    )
    private const val MAXIMUM_FULL_REPETITIONS = 16L
    private const val MAXIMUM_CORPUS_BYTES = 16 * 1024 * 1024
    private const val MAXIMUM_POLICY_BYTES = 64 * 1024
}

private fun jsonLimits(maximumBytes: Int) = StrictJsonLimits(
    maximumInputBytes = maximumBytes,
    maximumCanonicalBytes = maximumBytes,
    maximumDepth = 64,
    maximumNodes = 250_000,
    maximumStringBytes = maximumBytes,
    maximumTotalStringBytes = maximumBytes,
    maximumNumberCharacters = 64,
)

private fun JsonObject.exactFields(expected: Set<String>, label: String) {
    if (keys != expected) tierFail("$label fields must be exactly ${expected.sorted()}")
}

private fun JsonObject.obj(name: String, label: String): JsonObject =
    this[name] as? JsonObject ?: tierFail("$label $name must be an object")

private fun JsonObject.array(name: String, label: String): JsonArray =
    this[name] as? JsonArray ?: tierFail("$label $name must be an array")

private fun JsonElement?.string(label: String): String =
    (this as? JsonPrimitive)?.takeIf { it.isString }?.content ?: tierFail("$label must be a string")

private fun JsonElement?.boolean(label: String): Boolean =
    (this as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull ?: tierFail("$label must be a boolean")

private fun JsonElement?.positiveLong(label: String): Long =
    (this as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull?.takeIf { it > 0 }
        ?: tierFail("$label must be a positive integer")

private fun tierFail(message: String): Nothing = throw LlvmBehaviorQualificationTierException(message)
