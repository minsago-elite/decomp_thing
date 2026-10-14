package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.BoundedDwarfCanonicalShardWriter
import decompengine.oracle.fulltree.BoundedDwarfShardLimits
import decompengine.oracle.fulltree.FullTreeControlException
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

internal data class GccDriverAutomaticLocalPopulationLimits(
    val maximumRecords: Int = 100_000,
    val maximumWorkSteps: Long = 5_000_000,
    val maximumRecordBytes: Int = 8 * 1024 * 1024,
    val maximumRecordNodes: Int = 100_000,
    val maximumCanonicalBytes: Long = 512L * 1024 * 1024,
    val maximumCanonicalNodes: Long = 16_000_000,
    val maximumShards: Int = 256,
) {
    init {
        require(maximumRecords in 1..100_000)
        require(maximumWorkSteps in 1..5_000_000)
        require(maximumRecordBytes in 1..8 * 1024 * 1024)
        require(maximumRecordNodes in 1..100_000)
        require(maximumCanonicalBytes in 1..512L * 1024 * 1024)
        require(maximumCanonicalNodes in 1..16_000_000)
        require(maximumShards in 1..256)
    }

    internal fun recordJsonLimits() = StrictJsonLimits(
        maximumInputBytes = maximumRecordBytes,
        maximumCanonicalBytes = maximumRecordBytes,
        maximumDepth = 62,
        maximumNodes = maximumRecordNodes,
        maximumStringBytes = maximumRecordBytes,
        maximumTotalStringBytes = maximumRecordBytes,
    )

    internal fun shardLimits() = BoundedDwarfShardLimits(
        maximumShardBytes = maximumRecordBytes,
        maximumShardNodes = maximumRecordNodes,
        maximumTotalBytes = maximumCanonicalBytes,
        maximumTotalNodes = maximumCanonicalNodes,
        maximumShards = maximumShards,
    )
}

internal class GccDriverAutomaticLocalPopulationPolicy internal constructor(
    val policyId: String,
    val inputKind: String,
    val countingUnit: String,
    allowedScopes: List<String>,
    allowedLocationKinds: List<String>,
    declarationGuard: List<Pair<String, List<String>>>,
    private val encoded: ByteArray,
) {
    val allowedScopes: List<String> = Collections.unmodifiableList(ArrayList(allowedScopes))
    val allowedLocationKinds: List<String> = Collections.unmodifiableList(ArrayList(allowedLocationKinds))
    val declarationGuard: List<Pair<String, List<String>>> = Collections.unmodifiableList(
        declarationGuard.map { it.first to Collections.unmodifiableList(ArrayList(it.second)) },
    )
    val canonicalSha256: String = OracleArtifacts.sha256(encoded)
    fun canonicalBytes(): ByteArray = encoded.copyOf()
}

internal class GccDriverAutomaticLocalPopulationApplication internal constructor(
    decisions: List<JsonObject>,
    summary: JsonObject,
) {
    private val decisionBytes = decisions.map { OracleJson.canonicalBytes(it, APPLICATION_JSON_LIMITS) }
    private val summaryBytes = OracleJson.canonicalBytes(summary, APPLICATION_JSON_LIMITS)
    val decisions: List<JsonObject>
        get() = Collections.unmodifiableList(decisionBytes.map {
            OracleJson.parseCanonical(it, APPLICATION_JSON_LIMITS) as JsonObject
        })
    val summary: JsonObject
        get() = OracleJson.parseCanonical(summaryBytes, APPLICATION_JSON_LIMITS) as JsonObject
}

internal object GccDriverAutomaticLocalPopulationPolicyV1 {
    const val POLICY_ID = "gcc-driver-automatic-local-population-policy-v1"
    const val APPLICATION_ID = "gcc-driver-automatic-local-population-application-v1"
    const val DECISION_KIND = "automaticLocalPopulationDecisions"
    const val COMMITMENT_ENCODING =
        "sha256-domain-kind-record-marker-u64be-length-canonical-json-end-marker-u64be-count-v1"

    fun load(bytes: ByteArray): GccDriverAutomaticLocalPopulationPolicy = policyBoundary {
        if (bytes.size > POLICY_JSON_LIMITS.maximumInputBytes) policyFail("input exceeds the byte limit")
        val document = OracleJson.parse(bytes.copyOf(), POLICY_JSON_LIMITS) as? JsonObject
            ?: policyFail("root must be an object")
        exact(document, POLICY_KEYS, "policy")
        expectText(document, "schema", POLICY_ID)
        expectText(document, "policyId", POLICY_ID)
        expectText(document, "inputKind", "authenticated-raw-dwarf-variable-record")
        expectText(document, "countingUnit", "raw-dwarf-variable-record")
        expectText(document, "otherExclusions", "exact-reviewed-identity-and-reason-required")
        if (boolean(document, "entityDenominatorEstablished")) policyFail("entity denominator must remain unavailable")

        val proof = objectField(document, "automaticProof")
        exact(proof, setOf("storage", "scope", "location"), "automaticProof")
        stateValues(objectField(proof, "storage"), listOf("automatic"), "automaticProof.storage")
        stateValues(objectField(proof, "scope"), listOf("function", "block"), "automaticProof.scope")
        val location = objectField(proof, "location")
        exact(location, setOf("state", "kinds"), "automaticProof.location")
        expectText(location, "state", "known")
        expectStrings(location, "kinds", listOf("frame-relative", "register"))

        val guard = objectField(document, "declarationGuard")
        exact(guard, setOf("accepted", "role"), "declarationGuard")
        expectText(guard, "role", "negative-definition-guard-only")
        val accepted = arrayField(guard, "accepted")
        if (accepted.size != 2) policyFail("declarationGuard.accepted differs from the closed rule")
        val decodedGuard = accepted.mapIndexed { index, value ->
            val entry = value as? JsonObject ?: policyFail("declarationGuard.accepted[$index] must be an object")
            exact(entry, setOf("state", "values"), "declarationGuard.accepted[$index]")
            text(entry, "state") to strings(entry, "values")
        }
        if (decodedGuard != listOf("absent" to emptyList(), "known" to listOf("0"))) {
            policyFail("declarationGuard.accepted differs from the closed rule")
        }

        val excluded = objectField(document, "excludedDecision")
        exact(excluded, setOf("classification", "reason"), "excludedDecision")
        expectText(excluded, "classification", "excluded")
        expectText(excluded, "reason", "positively-proved-automatic-local")
        val retained = objectField(document, "retainedDecision")
        exact(retained, setOf("classification", "defaultReason", "declarationVetoReason"), "retainedDecision")
        expectText(retained, "classification", "retained-raw-candidate")
        expectText(retained, "defaultReason", "automatic-local-not-positively-proved")
        expectText(retained, "declarationVetoReason", "declaration-is-not-a-proved-definition")

        val canonical = OracleJson.canonicalBytes(document, POLICY_JSON_LIMITS)
        GccDriverAutomaticLocalPopulationPolicy(
            POLICY_ID,
            "authenticated-raw-dwarf-variable-record",
            "raw-dwarf-variable-record",
            listOf("function", "block"),
            listOf("frame-relative", "register"),
            decodedGuard,
            canonical,
        )
    }

    fun apply(
        policy: GccDriverAutomaticLocalPopulationPolicy,
        rawVariables: Sequence<JsonObject>,
        policyInputSha256: String,
        policyInputBytes: Long,
        prePolicyInventorySha256: String,
        rawGlobalsCommitment: JsonObject,
        limits: GccDriverAutomaticLocalPopulationLimits = GccDriverAutomaticLocalPopulationLimits(),
    ): GccDriverAutomaticLocalPopulationApplication = policyBoundary {
        validateBinding(policy, policyInputSha256, policyInputBytes, prePolicyInventorySha256, rawGlobalsCommitment)
        val decisions = ArrayList<JsonObject>()
        val sourceCommitter = DecisionCommitter()
        val rawCommitter = RawGlobalsCommitter()
        val seen = HashSet<String>()
        val counts = DecisionCounts()
        var sourceBytes = 0L
        var sourceNodes = 0L
        var work = 0L
        for (record in rawVariables) {
            if (decisions.size >= limits.maximumRecords) policyFail("raw variable record count exceeds bounds")
            val admission = admitRawRecord(record, sourceNodes, work, limits)
            val recordNodes = admission.nodes
            work = admission.work
            validateRawVariable(record)
            val locator = text(record, "locator")
            if (!LOCATOR.matches(locator)) policyFail("source locator is not canonical")
            if (!seen.add(locator)) policyFail("source locator repeats")
            val source = OracleJson.canonicalBytes(record, limits.recordJsonLimits())
            if (sourceBytes > limits.maximumCanonicalBytes - source.size) policyFail("raw canonical bytes exceed bounds")
            sourceBytes += source.size
            sourceNodes += recordNodes
            rawCommitter.add(source)
            val decision = deriveDecision(record, OracleArtifacts.sha256(source))
            val encodedDecision = OracleJson.canonicalBytes(decision, limits.recordJsonLimits())
            sourceCommitter.add(encodedDecision)
            counts.observe(decision)
            decisions += decision
        }
        validateRawCommitment(rawGlobalsCommitment, rawCommitter.finish(), decisions.size.toLong(), sourceBytes)
        enforceDecisionShardBudget(decisions, limits)
        val commitment = sourceCommitter.finish()
        val unsigned = JsonObject(linkedMapOf(
            "schema" to JsonPrimitive(APPLICATION_ID),
            "policyId" to JsonPrimitive(policy.policyId),
            "policyInputSha256" to JsonPrimitive(policyInputSha256),
            "policyInputBytes" to JsonPrimitive(policyInputBytes),
            "canonicalPolicySha256" to JsonPrimitive(policy.canonicalSha256),
            "prePolicyInventorySha256" to JsonPrimitive(prePolicyInventorySha256),
            "rawGlobalsCommitment" to defensiveObject(rawGlobalsCommitment),
            "decisionCommitment" to commitment,
            "counts" to counts.toJson(),
            "entityDenominatorEstablished" to JsonPrimitive(false),
        ))
        val applicationSha = domainSha("gcc-driver-automatic-local-population-application-v1\n",
            OracleJson.canonicalBytes(unsigned, APPLICATION_JSON_LIMITS))
        val summary = JsonObject(unsigned + ("applicationSha256" to JsonPrimitive(applicationSha)))
        GccDriverAutomaticLocalPopulationApplication(decisions, summary)
    }

    fun verify(
        policy: GccDriverAutomaticLocalPopulationPolicy,
        rawVariables: Sequence<JsonObject>,
        policyInputSha256: String,
        policyInputBytes: Long,
        prePolicyInventorySha256: String,
        rawGlobalsCommitment: JsonObject,
        decisions: Sequence<JsonObject>,
        summary: JsonObject,
        limits: GccDriverAutomaticLocalPopulationLimits = GccDriverAutomaticLocalPopulationLimits(),
    ) = policyBoundary {
        val expected = apply(policy, rawVariables, policyInputSha256, policyInputBytes,
            prePolicyInventorySha256, rawGlobalsCommitment, limits)
        val expectedIterator = expected.decisions.iterator()
        val actualIterator = decisions.iterator()
        var count = 0
        while (expectedIterator.hasNext() && actualIterator.hasNext()) {
            val expectedDecision = expectedIterator.next()
            val actual = actualIterator.next()
            validateDecision(actual)
            if (actual != expectedDecision) policyFail("decision $count differs from authenticated raw membership")
            count++
        }
        if (expectedIterator.hasNext() || actualIterator.hasNext()) policyFail("decision stream is incomplete or has additional records")
        if (defensiveObject(summary) != expected.summary) policyFail("application summary differs from semantic rederivation")
        Unit
    }

    private fun validateBinding(
        policy: GccDriverAutomaticLocalPopulationPolicy,
        policyInputSha256: String,
        policyInputBytes: Long,
        prePolicyInventorySha256: String,
        rawGlobalsCommitment: JsonObject,
    ) {
        if (policy.policyId != POLICY_ID || policy.inputKind != "authenticated-raw-dwarf-variable-record" ||
            policy.countingUnit != "raw-dwarf-variable-record" || policy.allowedScopes != listOf("function", "block") ||
            policy.allowedLocationKinds != listOf("frame-relative", "register") ||
            policy.declarationGuard != listOf("absent" to emptyList(), "known" to listOf("0"))) {
            policyFail("typed policy differs from the closed contract")
        }
        requireSha(policyInputSha256, "policy input")
        if (policyInputBytes < 1) policyFail("policy input byte count must be positive")
        requireSha(prePolicyInventorySha256, "pre-policy inventory")
        validateCommitmentShape(rawGlobalsCommitment)
    }

    private fun deriveDecision(record: JsonObject, sourceSha: String): JsonObject {
        val storage = fact(record, "storage", stringsOnly = true)
        val scope = fact(record, "scope", stringsOnly = true)
        val location = fact(record, "location", locationValues = true)
        val declaration = declarationFact(record)
        val basePositive = storage.state == "known" && storage.stringValues == listOf("automatic") &&
            scope.state == "known" && scope.stringValues.singleOrNull() in setOf("function", "block") &&
            location.state == "known" && location.locationKinds.singleOrNull() in setOf("frame-relative", "register")
        val declarationAccepted = (declaration.state == "absent" && declaration.stringValues.isEmpty()) ||
            (declaration.state == "known" && declaration.stringValues == listOf("0"))
        val excluded = basePositive && declarationAccepted
        val declarationVeto = basePositive && !declarationAccepted
        val evidence = when {
            excluded -> orderedDistinct(storage.evidence + scope.evidence + location.evidence + declaration.evidence)
            declarationVeto -> declaration.evidence
            else -> emptyList()
        }
        return JsonObject(linkedMapOf(
            "kind" to JsonPrimitive(DECISION_KIND),
            "sourceLocator" to JsonPrimitive(text(record, "locator")),
            "sourceRecordSha256" to JsonPrimitive(sourceSha),
            "classification" to JsonPrimitive(if (excluded) "excluded" else "retained-raw-candidate"),
            "reason" to JsonPrimitive(when {
                excluded -> "positively-proved-automatic-local"
                declarationVeto -> "declaration-is-not-a-proved-definition"
                else -> "automatic-local-not-positively-proved"
            }),
            "provedScope" to if (excluded) JsonPrimitive(scope.stringValues.single()) else JsonNull,
            "provedLocationKind" to if (excluded) JsonPrimitive(location.locationKinds.single()) else JsonNull,
            "evidenceLocators" to JsonArray(evidence.map(::JsonPrimitive)),
        ))
    }

    private fun validateRawVariable(record: JsonObject) {
        exact(record, RAW_VARIABLE_KEYS, "raw variable record")
        text(record, "locator")
        RAW_STRING_FACT_FIELDS.forEach {
            if (it == "declaration") declarationFact(record) else fact(record, it, stringsOnly = true)
        }
        fact(record, "location", locationValues = true)
        val scopes = arrayField(record, "scopes")
        scopes.forEachIndexed { index, value ->
            val scope = value as? JsonObject ?: policyFail("scopes[$index] must be an object")
            exact(scope, setOf("locator", "tag", "name", "ownerLocator"), "scopes[$index]")
            text(scope, "locator"); text(scope, "tag"); fact(scope, "name", stringsOnly = true); text(scope, "ownerLocator")
        }
        strings(record, "origins")
        strings(record, "reasons")
    }

    private fun validateDecision(decision: JsonObject) {
        exact(decision, DECISION_KEYS, "decision")
        expectText(decision, "kind", DECISION_KIND)
        text(decision, "sourceLocator").also { if (!LOCATOR.matches(it)) policyFail("decision source locator is not canonical") }
        requireSha(text(decision, "sourceRecordSha256"), "decision source record")
        if (text(decision, "classification") !in setOf("excluded", "retained-raw-candidate")) {
            policyFail("decision classification is unsupported")
        }
        if (text(decision, "reason") !in setOf("positively-proved-automatic-local",
                "declaration-is-not-a-proved-definition", "automatic-local-not-positively-proved")) {
            policyFail("decision reason is unsupported")
        }
        nullableText(decision.getValue("provedScope"))
        nullableText(decision.getValue("provedLocationKind"))
        strings(decision, "evidenceLocators")
    }

    private data class Fact(
        val state: String,
        val stringValues: List<String>,
        val locationKinds: List<String>,
        val evidence: List<String>,
    )

    private fun declarationFact(owner: JsonObject): Fact = fact(owner, "declaration", stringsOnly = true).also { declaration ->
        declaration.stringValues.forEachIndexed { index, value ->
            if (!isCanonicalDecimal(value)) policyFail("declaration.values[$index] must be a canonical decimal string")
        }
    }

    private fun fact(owner: JsonObject, field: String, stringsOnly: Boolean = false, locationValues: Boolean = false): Fact {
        val value = objectField(owner, field)
        exact(value, FACT_KEYS, "$field fact")
        val state = text(value, "state")
        if (state !in FACT_STATES) policyFail("$field fact state is unsupported")
        val values = arrayField(value, "values")
        val stringValues = if (stringsOnly) values.mapIndexed { index, element ->
            nullableText(element) ?: policyFail("$field.values[$index] must be a string")
        } else emptyList()
        val locationKinds = if (locationValues) values.mapIndexed { index, element ->
            val location = element as? JsonObject ?: policyFail("$field.values[$index] must be an object")
            exact(location, LOCATION_KEYS, "$field.values[$index]")
            text(location, "sourceLocator"); text(location, "declaredForm")
            nullableText(location.getValue("resolvedForm")); text(location, "kind")
            nullableText(location.getValue("expressionHex")); nullableText(location.getValue("operand"))
            text(location, "kind")
        } else emptyList()
        val evidence = strings(value, "evidence")
        strings(value, "reasons")
        if (state == "absent" && values.isNotEmpty()) policyFail("$field absent fact has values")
        return Fact(state, stringValues, locationKinds, evidence)
    }

    private fun enforceDecisionShardBudget(decisions: List<JsonObject>, limits: GccDriverAutomaticLocalPopulationLimits) {
        val writer = BoundedDwarfCanonicalShardWriter(limits.shardLimits()) { _, _, _, _ -> Unit }
        writer.write(DECISION_KIND, decisions.asSequence())
        writer.finish()
    }

    private fun validateRawCommitment(
        commitment: JsonObject,
        rederived: JsonObject,
        recordCount: Long,
        canonicalBytes: Long,
    ) {
        validateCommitmentShape(commitment)
        if (text(commitment, "kind") != "globals") policyFail("raw commitment kind is not globals")
        if (number(commitment, "recordCount") != recordCount) policyFail("raw commitment record count differs")
        if (number(commitment, "canonicalBytes") != canonicalBytes) policyFail("raw commitment canonical byte count differs")
        if (commitment != rederived) policyFail("raw commitment digest differs from the exact source record stream")
    }

    private fun validateCommitmentShape(commitment: JsonObject) {
        exact(commitment, COMMITMENT_KEYS, "raw globals commitment")
        text(commitment, "kind")
        number(commitment, "recordCount")
        number(commitment, "canonicalBytes")
        requireSha(text(commitment, "sha256"), "raw globals commitment")
    }
}

/** Exact duplicate of the retained inventory's closed raw-record commitment wire algorithm. */
private class RawGlobalsCommitter {
    private val digest = MessageDigest.getInstance("SHA-256").apply {
        update("bounded-dwarf-observation-records-v1\nglobals\n".toByteArray(Charsets.UTF_8))
    }
    private var count = 0L
    private var bytes = 0L
    fun add(record: ByteArray) {
        digest.update(1.toByte()); digest.update(frame(record.size.toLong())); digest.update(record)
        count++; bytes += record.size
    }
    fun finish(): JsonObject {
        digest.update(0.toByte()); digest.update(frame(count))
        return JsonObject(linkedMapOf(
            "kind" to JsonPrimitive("globals"),
            "recordCount" to JsonPrimitive(count),
            "canonicalBytes" to JsonPrimitive(bytes),
            "sha256" to JsonPrimitive(hex(digest.digest())),
        ))
    }
}

private class DecisionCommitter {
    private val digest = MessageDigest.getInstance("SHA-256").apply {
        update("gcc-driver-automatic-local-population-decisions-v1\n${GccDriverAutomaticLocalPopulationPolicyV1.DECISION_KIND}\n".toByteArray())
    }
    private var count = 0L
    private var bytes = 0L
    fun add(record: ByteArray) {
        digest.update(1.toByte()); digest.update(frame(record.size.toLong())); digest.update(record)
        count++; bytes += record.size
    }
    fun finish(): JsonObject {
        digest.update(0.toByte()); digest.update(frame(count))
        return JsonObject(linkedMapOf(
            "kind" to JsonPrimitive(GccDriverAutomaticLocalPopulationPolicyV1.DECISION_KIND),
            "recordCount" to JsonPrimitive(count),
            "canonicalBytes" to JsonPrimitive(bytes),
            "encoding" to JsonPrimitive(GccDriverAutomaticLocalPopulationPolicyV1.COMMITMENT_ENCODING),
            "sha256" to JsonPrimitive(hex(digest.digest())),
        ))
    }
}

private class DecisionCounts {
    private var raw = 0L
    private var excluded = 0L
    private var retained = 0L
    private var function = 0L
    private var block = 0L
    private var frameRelative = 0L
    private var register = 0L
    fun observe(decision: JsonObject) {
        raw++
        if (decision.getValue("classification") == JsonPrimitive("excluded")) {
            excluded++
            when (decision.getValue("provedScope")) {
                JsonPrimitive("function") -> function++
                JsonPrimitive("block") -> block++
                else -> policyFail("excluded decision has unsupported scope")
            }
            when (decision.getValue("provedLocationKind")) {
                JsonPrimitive("frame-relative") -> frameRelative++
                JsonPrimitive("register") -> register++
                else -> policyFail("excluded decision has unsupported location kind")
            }
        } else retained++
    }
    fun toJson(): JsonObject {
        if (raw != excluded + retained || excluded != function + block || excluded != frameRelative + register) {
            policyFail("decision counts do not conserve")
        }
        return JsonObject(linkedMapOf(
            "rawVariableRecords" to JsonPrimitive(raw),
            "excludedAutomaticLocalRecords" to JsonPrimitive(excluded),
            "retainedRawCandidateRecords" to JsonPrimitive(retained),
            "excludedFunctionScopeRecords" to JsonPrimitive(function),
            "excludedBlockScopeRecords" to JsonPrimitive(block),
            "excludedFrameRelativeRecords" to JsonPrimitive(frameRelative),
            "excludedRegisterRecords" to JsonPrimitive(register),
        ))
    }
}

private fun stateValues(value: JsonObject, expected: List<String>, label: String) {
    exact(value, setOf("state", "values"), label)
    expectText(value, "state", "known")
    expectStrings(value, "values", expected)
}
private fun expectStrings(owner: JsonObject, field: String, expected: List<String>) {
    val actual = strings(owner, field)
    if (actual != expected || actual.distinct().size != actual.size) policyFail("$field differs from the closed ordered values")
}
private fun expectText(owner: JsonObject, field: String, expected: String) {
    if (text(owner, field) != expected) policyFail("$field differs from the closed value")
}
private fun exact(value: JsonObject, keys: Set<String>, label: String) {
    if (value.keys != keys) policyFail("$label differs from its closed schema")
}
private fun objectField(owner: JsonObject, field: String): JsonObject =
    owner[field] as? JsonObject ?: policyFail("$field must be an object")
private fun arrayField(owner: JsonObject, field: String): JsonArray =
    owner[field] as? JsonArray ?: policyFail("$field must be an array")
private fun text(owner: JsonObject, field: String): String =
    nullableText(owner[field] ?: policyFail("$field is missing")) ?: policyFail("$field must be a string")
private fun nullableText(value: JsonElement): String? {
    if (value == JsonNull) return null
    val primitive = value as? JsonPrimitive ?: policyFail("expected a string")
    if (!primitive.isString || primitive.content.toByteArray().size > 16_384) policyFail("text is not a bounded string")
    return primitive.content
}
private fun strings(owner: JsonObject, field: String): List<String> = arrayField(owner, field).mapIndexed { index, value ->
    nullableText(value) ?: policyFail("$field[$index] must be a string")
}
private fun boolean(owner: JsonObject, field: String): Boolean =
    (owner[field] as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull ?: policyFail("$field must be a boolean")
private fun number(owner: JsonObject, field: String): Long =
    (owner[field] as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull?.takeIf { it >= 0 }
        ?: policyFail("$field must be a nonnegative integer")
private fun isCanonicalDecimal(value: String): Boolean {
    if (value.isEmpty()) return false
    var index = 0
    if (value[0] == '-') {
        if (value.length == 1) return false
        index = 1
    }
    if (value[index] == '0') return index == 0 && value.length == 1
    if (value[index] !in '1'..'9') return false
    index++
    while (index < value.length) {
        if (value[index] !in '0'..'9') return false
        index++
    }
    return true
}
private fun requireSha(value: String, label: String) {
    if (!SHA.matches(value)) policyFail("$label SHA-256 is malformed")
}
private fun orderedDistinct(values: List<String>): List<String> {
    val seen = LinkedHashSet<String>()
    values.forEach(seen::add)
    return seen.toList()
}
private fun defensiveObject(value: JsonObject): JsonObject =
    OracleJson.parseCanonical(OracleJson.canonicalBytes(value, APPLICATION_JSON_LIMITS), APPLICATION_JSON_LIMITS) as JsonObject
private data class RawRecordAdmission(val nodes: Long, val work: Long)

/** One work step per canonical raw node bounds every later variable-length pass over the admitted record. */
private fun admitRawRecord(
    root: JsonObject,
    priorNodes: Long,
    priorWork: Long,
    limits: GccDriverAutomaticLocalPopulationLimits,
): RawRecordAdmission {
    val pending = ArrayDeque<JsonElement>()
    var nodes = 0L
    var work = priorWork
    fun admit(value: JsonElement) {
        if (nodes >= limits.maximumRecordNodes) policyFail("raw record nodes exceed bounds")
        if (priorNodes > limits.maximumCanonicalNodes - nodes - 1) policyFail("raw canonical nodes exceed bounds")
        work = chargeWork(work, 1, limits)
        nodes++
        pending.addLast(value)
    }
    admit(root)
    while (pending.isNotEmpty()) {
        when (val value = pending.removeLast()) {
            is JsonObject -> value.values.forEach(::admit)
            is JsonArray -> value.forEach(::admit)
            else -> Unit
        }
    }
    return RawRecordAdmission(nodes, work)
}
private fun chargeWork(current: Long, added: Long, limits: GccDriverAutomaticLocalPopulationLimits): Long {
    if (current > limits.maximumWorkSteps - added) policyFail("application work exceeds bounds")
    return current + added
}
private fun domainSha(domain: String, bytes: ByteArray): String =
    OracleArtifacts.sha256(domain.toByteArray() + bytes)
private fun frame(value: Long): ByteArray = ByteBuffer.allocate(8).putLong(value).array()
private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
private inline fun <T> policyBoundary(block: () -> T): T = try {
    block()
} catch (failure: FullTreeControlException) {
    if (failure.message?.startsWith(POLICY_FAILURE_PREFIX) == true) throw failure
    throw FullTreeControlException("$POLICY_FAILURE_PREFIX${failure.message ?: failure::class.simpleName}")
} catch (failure: Exception) {
    throw FullTreeControlException("$POLICY_FAILURE_PREFIX${failure.message ?: failure::class.simpleName}")
}
private fun policyFail(message: String): Nothing = throw FullTreeControlException("$POLICY_FAILURE_PREFIX$message")

private const val POLICY_FAILURE_PREFIX = "GCC driver automatic-local policy: "
private val POLICY_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 16 * 1024,
    maximumCanonicalBytes = 16 * 1024,
    maximumDepth = 8,
    maximumNodes = 128,
    maximumStringBytes = 256,
    maximumTotalStringBytes = 4096,
    maximumNumberCharacters = 32,
)
private val APPLICATION_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 8 * 1024 * 1024,
    maximumCanonicalBytes = 8 * 1024 * 1024,
    maximumDepth = 64,
    maximumNodes = 100_000,
    maximumStringBytes = 8 * 1024 * 1024,
    maximumTotalStringBytes = 8 * 1024 * 1024,
)
private val POLICY_KEYS = setOf("automaticProof", "countingUnit", "declarationGuard", "entityDenominatorEstablished",
    "excludedDecision", "inputKind", "otherExclusions", "policyId", "retainedDecision", "schema")
private val RAW_VARIABLE_KEYS = setOf("locator", "sourceName", "linkageName", "language", "type", "external",
    "declaration", "artificial", "visibility", "byteSize", "alignment", "constant", "scope", "location",
    "address", "rva", "tlsOffset", "storage", "scopes", "origins", "reasons")
private val RAW_STRING_FACT_FIELDS = RAW_VARIABLE_KEYS - setOf("locator", "location", "scopes", "origins", "reasons")
private val FACT_KEYS = setOf("state", "values", "evidence", "reasons")
private val FACT_STATES = setOf("absent", "known", "unknown", "ambiguous")
private val LOCATION_KEYS = setOf("sourceLocator", "declaredForm", "resolvedForm", "kind", "expressionHex", "operand")
private val DECISION_KEYS = setOf("kind", "sourceLocator", "sourceRecordSha256", "classification", "reason",
    "provedScope", "provedLocationKind", "evidenceLocators")
private val COMMITMENT_KEYS = setOf("kind", "recordCount", "canonicalBytes", "sha256")
private val SHA = Regex("[0-9a-f]{64}")
private val LOCATOR = Regex("\\.debug_info:cu=0x(?:0|[1-9a-f][0-9a-f]*):die=0x(?:0|[1-9a-f][0-9a-f]*)")
