package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.structural.StructuralProductionReplayContract
import decompengine.oracle.structural.StructuralRecoveryV1Contract
import java.security.MessageDigest
import java.util.Collections
import java.util.Locale
import kotlinx.serialization.json.*

/**
 * Immutable, passive report data. There is deliberately no stored live-verification flag. Even a
 * perfectly rehashed imported report can only acquire current-process verification by comparison
 * with the existing capability in [ProgramAnalysisResult]. Its digest excludes all enclosing files.
 */
class RecoveryAssessmentProjectionV1 private constructor(bytes: ByteArray, checkpoint: (String) -> Unit) {
    private val storedBytes = bytes.copyOf()
    val canonicalBytes: ByteArray get() = storedBytes.copyOf()
    // Derive the view from the same immutable bytes even on synthetic JVM constructor paths.
    val document: JsonObject = immutableJson(OracleJson.parse(storedBytes, projectionLimits(MAXIMUM_BYTES)) {
        assessmentCheckpoint(checkpoint, it)
    }, checkpoint).jsonObject
    val sha256: String = decompengine.project.sha256(storedBytes)

    fun publicSummary(confidenceSha256: String): RecordedRecoverySummaryV1 = RecordedRecoverySummaryV1.parse(
        JsonObject(document.filterKeys { it != "modules" } + mapOf(
            "projectionSha256" to JsonPrimitive(sha256), "confidenceSha256" to JsonPrimitive(confidenceSha256))),
    )

    /** Computes a disposition now; passive decoding never produces a live capability or flag. */
    fun verificationDisposition(analysis: ProgramAnalysisResult, plan: ModulePlan,
        checkpoint: (String) -> Unit = {}): String {
        validateBound(document, analysis, plan, MAXIMUM_BYTES, checkpoint)
        if (analysis.selectedStructuralInputs == null) return if (document["measurements"] == JsonNull)
            "no-structural-evidence" else "recorded-origin-unverified"
        val expected = derive(analysis, plan, checkpoint = checkpoint)
        require(storedBytes.contentEquals(expected.storedBytes)) {
            "recorded assessment differs from the existing owned structural capability"
        }
        return "same-process-owned-selected-evidence"
    }

    companion object {
        const val MAXIMUM_BYTES = 64 * 1024 * 1024
        const val SCOPE = "selected-function-starts-and-surviving-symbol-identities"

        fun derive(analysis: ProgramAnalysisResult, plan: ModulePlan, maximumBytes: Int = MAXIMUM_BYTES,
            checkpoint: (String) -> Unit = {}): RecoveryAssessmentProjectionV1 {
            projectionLimits(maximumBytes)
            val capturedPlan = capturePlan(plan, checkpoint)
            val base = baseProjection(analysis, capturedPlan, maximumBytes, checkpoint)
            val capability = analysis.selectedStructuralInputs
            val projected = if (capability == null) base else {
                assessmentCheckpoint(checkpoint, "before owned selected assessment")
                val bytes = StructuralProductionReplayContract.assessSelectedFunctions(capability)
                require(bytes.size in 1..MAXIMUM_BYTES) { "selected overlay exceeds its byte bound" }
                val overlay = OracleJson.parseCanonical(bytes, StrictJsonLimits(
                    maximumInputBytes = MAXIMUM_BYTES, maximumCanonicalBytes = MAXIMUM_BYTES,
                    maximumNodes = 1_000_000, maximumStringBytes = 16 * 1024 * 1024,
                    maximumTotalStringBytes = 48 * 1024 * 1024,
                )) {
                    assessmentCheckpoint(checkpoint, it)
                }.obj()
                assessmentCheckpoint(checkpoint, "after owned selected assessment")
                withSelectedEvidence(base, analysis, capturedPlan.plan, bytes, overlay, checkpoint)
            }
            validateProjection(projected, includeModules = true, checkpoint)
            return encoded(projected, maximumBytes, checkpoint)
        }

        /** Bounded passive syntax/arithmetic only. No model, source, execution or origin attestation. */
        fun parsePassive(bytes: ByteArray, maximumBytes: Int = MAXIMUM_BYTES,
            checkpoint: (String) -> Unit = {}): RecoveryAssessmentProjectionV1 {
            val value = OracleJson.parse(bytes, projectionLimits(maximumBytes)) {
                assessmentCheckpoint(checkpoint, it)
            }.obj()
            validateProjection(value, includeModules = true, checkpoint)
            return encoded(value, maximumBytes, checkpoint)
        }

        /** Also rederives the full typed census and ownership from independently supplied bytes. */
        fun parsePassive(bytes: ByteArray, analysis: ProgramAnalysisResult, plan: ModulePlan,
            maximumBytes: Int = MAXIMUM_BYTES, checkpoint: (String) -> Unit = {}): RecoveryAssessmentProjectionV1 =
            parsePassive(bytes, maximumBytes, checkpoint).also {
                validateBound(it.document, analysis, plan, maximumBytes, checkpoint)
            }

        private fun encoded(value: JsonObject, maximumBytes: Int, checkpoint: (String) -> Unit): RecoveryAssessmentProjectionV1 {
            preflightJson(value, maximumBytes, checkpoint)
            val bytes = OracleJson.canonicalBytes(value, projectionLimits(maximumBytes)) {
                assessmentCheckpoint(checkpoint, it)
            }
            assessmentCheckpoint(checkpoint, "after recovery assessment encoding")
            return RecoveryAssessmentProjectionV1(bytes, checkpoint).also {
                assessmentCheckpoint(checkpoint, "after immutable assessment capture")
            }
        }
    }
}

/** Closed scalar copy for public metadata. The confidence hash is outside the projection digest. */
class RecordedRecoverySummaryV1 private constructor(bytes: ByteArray) {
    private val storedBytes = bytes.copyOf()
    val canonicalBytes: ByteArray get() = storedBytes.copyOf()
    val document: JsonObject = immutableJson(OracleJson.parse(storedBytes, projectionLimits(MAXIMUM_BYTES))).jsonObject
    init {
        document.digest("projectionSha256"); document.digest("confidenceSha256")
        validateProjection(document, includeModules = false) {}
    }
    fun toJson(): String = storedBytes.toString(Charsets.UTF_8)
    fun toJsonObject(): JsonObject = document
    fun rebindConfidenceSha256(confidenceSha256: String): RecordedRecoverySummaryV1 =
        parse(JsonObject(document + ("confidenceSha256" to JsonPrimitive(confidenceSha256))))

    companion object {
        const val MAXIMUM_BYTES = 64 * 1024
        fun parse(value: JsonObject): RecordedRecoverySummaryV1 {
            preflightJson(value, MAXIMUM_BYTES) {}
            val safe = OracleJson.parse(OracleJson.canonicalBytes(value, projectionLimits(MAXIMUM_BYTES)),
                projectionLimits(MAXIMUM_BYTES)).obj()
            safe.digest("projectionSha256"); safe.digest("confidenceSha256")
            validateProjection(safe, includeModules = false) {}
            val bytes = OracleJson.canonicalBytes(safe, projectionLimits(MAXIMUM_BYTES))
            return RecordedRecoverySummaryV1(bytes)
        }
    }
}

private data class AssessmentEntity(val kind: String, val id: String, val status: String)
private data class AssessmentPlanSnapshot(val plan: ModulePlan, val bytes: ByteArray)
private const val OVERLAY_SCOPE = "selected-function-starts-and-surviving-symbol-identities-with-complete-model-census"
private val SHA = Regex("[0-9a-f]{64}")
private val MODULE_ID = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
private val KINDS = listOf("function", "global", "type")
private val STATUSES = listOf("recovered", "partial", "failed", "synthetic")
private val ROOT_FIELDS = setOf("schemaVersion", "authority", "scope", "recoveryAssessmentState", "complete",
    "releaseEligible", "bindings", "population", "extraction", "dimensions", "measurements", "unassigned")
private val BINDING_FIELDS = setOf("inputSha256", "modelSha256", "modelBytes", "modelSchemaVersion", "planSha256",
    "planBytes", "planSchemaVersion", "censusSha256", "sourceOverlay")
private val POPULATION_FIELDS = setOf("unit", "modelEntityCount", "functionCount", "globalCount", "typeCount",
    "assessedEntityCount", "unassessedEntityCount")
private val CANDIDATE_FIELDS = setOf("rawRecoveredCount", "scoredRecoveredCount", "ignoredExcludedCount", "exactMatches",
    "nearMisses", "unmatchedCount", "survivingAliasCount", "exactSurvivingAliasCount", "mismatchedSurvivingAliasCount")
private val START_FIELDS = setOf("rawRecoveredCount", "scoredRecoveredCount", "ignoredExcludedCount", "exactMatches",
    "nearMisses", "falsePositives", "falseNegatives", "oracleFunctionCount", "scoreableOracleFunctionCount",
    "excludedOracleFunctionCount", "oracleOnlyFunctionCount", "precision", "recall")
private val ALIAS_FIELDS = setOf("population", "exact", "nameMismatch", "missing", "identityRecovery")
private val UNASSIGNED_FIELDS = setOf("oracleFunctionCount", "oracleOnlyFunctionCount", "excludedOracleFunctionCount", "survivingAliasCount")

private fun capturePlan(suppliedPlan: ModulePlan, checkpoint: (String) -> Unit): AssessmentPlanSnapshot {
    assessmentCheckpoint(checkpoint, "before projection plan encoding")
    val planBytes = suppliedPlan.toJson().toByteArray(Charsets.UTF_8)
    val plan = ModulePlanJson.readCanonical(planBytes, RecoveryAssessmentProjectionV1.MAXIMUM_BYTES) {
        assessmentCheckpoint(checkpoint, it)
    }
    return AssessmentPlanSnapshot(plan, planBytes)
}

private fun baseProjection(analysis: ProgramAnalysisResult, capturedPlan: AssessmentPlanSnapshot, maximumBytes: Int,
    checkpoint: (String) -> Unit): JsonObject {
    projectionLimits(maximumBytes)
    val planBytes = capturedPlan.bytes
    val plan = capturedPlan.plan
    val entities = census(analysis.model, checkpoint)
    val owners = exactOwners(entities, plan, checkpoint)
    val counts = entities.groupingBy { it.kind }.eachCount()
    val population = population(KINDS.associateWith { counts[it]?.toLong() ?: 0L })
    val statuses = entities.groupingBy { it.status }.eachCount()
    val bindings = obj(
        "inputSha256" to analysis.inputSha256.takeIf(SHA::matches)?.let(::JsonPrimitive),
        "modelSha256" to JsonPrimitive(analysis.modelSha256), "modelBytes" to JsonPrimitive(analysis.modelBytes),
        "modelSchemaVersion" to JsonPrimitive(analysis.modelSchemaVersion), "planSha256" to JsonPrimitive(sha256(planBytes)),
        "planBytes" to JsonPrimitive(planBytes.size), "planSchemaVersion" to JsonPrimitive(2),
        "censusSha256" to JsonPrimitive(censusDigest(entities, checkpoint)), "sourceOverlay" to JsonNull,
    )
    val modules = plan.modules.sortedBy { it.id }.map { module ->
        assessmentCheckpoint(checkpoint, "projecting typed module population")
        obj("moduleId" to JsonPrimitive(module.id), "population" to population(mapOf(
            "function" to module.functionIds.size.toLong(), "global" to module.globalIds.size.toLong(),
            "type" to module.typeIds.size.toLong())), "candidateMeasurements" to JsonNull)
    }
    require(owners.size == entities.size)
    return obj("schemaVersion" to JsonPrimitive(1), "authority" to JsonPrimitive("reported-assessment"),
        "scope" to JsonPrimitive(RecoveryAssessmentProjectionV1.SCOPE), "recoveryAssessmentState" to JsonPrimitive("unassessed"),
        "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false), "bindings" to bindings,
        "population" to population, "extraction" to JsonObject(mapOf("calibration" to JsonPrimitive("uncalibrated")) +
            STATUSES.associateWith { JsonPrimitive(statuses[it] ?: 0) }),
        "dimensions" to dimensions(population), "measurements" to JsonNull, "unassigned" to JsonNull,
        "modules" to JsonArray(modules))
}

private fun census(model: RecoveredProgramModel, checkpoint: (String) -> Unit): List<AssessmentEntity> {
    val count = Math.addExact(Math.addExact(model.functions.size, model.globals.size), model.types.size)
    val result = ArrayList<AssessmentEntity>(count)
    fun add(kind: String, id: String, status: RecoveryStatus) {
        assessmentCheckpoint(checkpoint, "counting complete typed model census")
        result += AssessmentEntity(kind, id, status.name.lowercase(Locale.ROOT))
    }
    model.functions.forEach { add("function", it.id, it.status) }
    model.globals.forEach { add("global", it.id, it.status) }
    model.types.forEach { add("type", it.id, it.status) }
    return result.sortedWith { left, right ->
        StructuralRecoveryV1Contract.CODE_POINT_ORDER.compare(left.kind, right.kind).takeIf { it != 0 }
            ?: StructuralRecoveryV1Contract.CODE_POINT_ORDER.compare(left.id, right.id)
    }
}

/** Canonical census v1: domain tag, code-point-sorted tuples of four UTF-8 fields with u32 BE lengths. */
private fun censusDigest(entities: List<AssessmentEntity>, checkpoint: (String) -> Unit): String {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update("recovery-assessment-typed-census-v1\n".toByteArray(Charsets.UTF_8))
    for (entity in entities) {
        assessmentCheckpoint(checkpoint, "hashing typed census tuple")
        for (text in listOf(entity.kind, entity.id, entity.status, "unassessed")) {
            val bytes = text.toByteArray(Charsets.UTF_8)
            digest.update(byteArrayOf((bytes.size ushr 24).toByte(), (bytes.size ushr 16).toByte(),
                (bytes.size ushr 8).toByte(), bytes.size.toByte()))
            digest.update(bytes)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

private fun exactOwners(entities: List<AssessmentEntity>, plan: ModulePlan,
    checkpoint: (String) -> Unit): Map<Pair<String, String>, String> {
    require(plan.schemaVersion == 2)
    val remaining = entities.mapTo(hashSetOf()) { it.kind to it.id }
    require(remaining.size == entities.size)
    val owners = HashMap<Pair<String, String>, String>()
    val ids = hashSetOf<String>()
    val paths = hashSetOf<String>()
    plan.modules.forEach { module ->
        assessmentCheckpoint(checkpoint, "checking typed module ownership")
        require(MODULE_ID.matches(module.id) && ids.add(module.id)) { "invalid or duplicate assessment module ID" }
        require(paths.add(module.sourcePath) && paths.add(module.headerPath)) { "module plan aliases output paths" }
        for ((kind, members) in listOf("function" to module.functionIds, "global" to module.globalIds, "type" to module.typeIds)) {
            members.forEach { id ->
                assessmentCheckpoint(checkpoint, "joining typed module membership")
                val key = kind to id
                require(remaining.remove(key)) { "assessment plan repeats or invents a typed entity" }
                owners[key] = module.id
            }
        }
    }
    require(remaining.isEmpty()) { "assessment plan omits typed model entities" }
    val seenCycles = hashSetOf<String>()
    plan.dependencyCycles.forEach { cycle ->
        require(cycle.size > 1 && cycle == cycle.sorted())
        cycle.forEach { require(it in ids && seenCycles.add(it)) { "invalid module cycle reference" } }
    }
    require(plan.dependencyCycles == plan.dependencyCycles.sortedBy { it.joinToString("\u0000") })
    return owners
}

private fun population(counts: Map<String, Long>): JsonObject {
    val total = checkedSum(KINDS.map { counts.getValue(it) })
    return obj("unit" to JsonPrimitive("model-entities"), "modelEntityCount" to JsonPrimitive(total),
        "functionCount" to JsonPrimitive(counts.getValue("function")), "globalCount" to JsonPrimitive(counts.getValue("global")),
        "typeCount" to JsonPrimitive(counts.getValue("type")), "assessedEntityCount" to JsonPrimitive(0),
        "unassessedEntityCount" to JsonPrimitive(total))
}

private fun dimensions(population: JsonObject): JsonArray = JsonArray(StructuralRecoveryV1Contract.DIMENSIONS.map { id ->
    val kind = StructuralRecoveryV1Contract.DIMENSION_ENTITY_KIND.getValue(id)
    obj("id" to JsonPrimitive(id), "entityKind" to JsonPrimitive(kind),
        "applicableEntityCount" to population.getValue("${kind}Count"), "state" to JsonPrimitive("unassessed"),
        "factDenominator" to JsonNull)
})

private fun withSelectedEvidence(base: JsonObject, analysis: ProgramAnalysisResult, plan: ModulePlan,
    overlayBytes: ByteArray, overlay: JsonObject, checkpoint: (String) -> Unit): JsonObject {
    require(overlay.text("provider") == "structural-selected-function-assessment-v1" && overlay.count("schemaVersion") == 1L &&
        overlay.text("scope") == OVERLAY_SCOPE && overlay.text("authority") == "passive-derived-overlay")
    val binding = overlay.getValue("bindings").obj()
    require(binding.text("inputSha256") == analysis.inputSha256 && binding.text("programModelSha256") == analysis.modelSha256 &&
        binding.count("programModelBytes") == analysis.modelBytes && binding.count("modelSchemaVersion") == analysis.modelSchemaVersion.toLong())
    val entities = census(analysis.model, checkpoint)
    val owners = exactOwners(entities, plan, checkpoint)
    val expected = entities.associateBy { it.kind to it.id }
    val remaining = expected.keys.toMutableSet()
    val candidates = plan.modules.associate { it.id to CANDIDATE_FIELDS.associateWith { 0L }.toMutableMap() }
    fun increment(module: String, field: String) {
        val row = candidates.getValue(module)
        row[field] = Math.addExact(row.getValue(field), 1L)
    }
    for (value in overlay.getValue("entities").arr()) {
        assessmentCheckpoint(checkpoint, "joining selected candidate population")
        val entity = value.obj()
        val key = entity.text("kind") to entity.text("id")
        val original = expected[key]
        require(original != null && remaining.remove(key) && entity.text("extractionStatus") == original.status &&
            entity.text("recoveryAssessment") == "unassessed") { "selected overlay census differs from exact model" }
        if (key.first == "function") {
            val module = owners.getValue(key)
            val outcome = entity.getValue("functionStart").obj().text("outcome")
            increment(module, "rawRecoveredCount")
            if (outcome == "excluded") increment(module, "ignoredExcludedCount") else increment(module, "scoredRecoveredCount")
            increment(module, when (outcome) { "exact" -> "exactMatches"; "near-miss" -> "nearMisses"
                "unmatched" -> "unmatchedCount"; "excluded" -> continue; else -> error("unknown selected function outcome") })
        }
    }
    require(remaining.isEmpty()) { "selected overlay omitted typed model census" }
    val originalMeasurements = overlay.getValue("measurements").obj()
    val starts = originalMeasurements.getValue("functionStarts").obj()
    val oracle = originalMeasurements.getValue("oraclePopulation").obj()
    val aliases = originalMeasurements.getValue("survivingSymbolIdentity").obj()
    var missingAliases = 0L
    for (element in aliases.getValue("symbols").arr()) {
        assessmentCheckpoint(checkpoint, "joining complete surviving alias population")
        val row = element.obj()
        if (row["recoveredId"] == JsonNull) {
            require(row.text("outcome") == "missing")
            missingAliases = Math.addExact(missingAliases, 1)
        } else {
            val module = owners.getValue("function" to row.text("recoveredId"))
            increment(module, "survivingAliasCount")
            increment(module, when (row.text("outcome")) { "exact" -> "exactSurvivingAliasCount"
                "name-mismatch" -> "mismatchedSurvivingAliasCount"; else -> error("unknown selected alias outcome") })
        }
    }
    val ratios = overlay.getValue("ratios").obj()
    val startProjection = JsonObject(START_FIELDS.filter { it in starts && it !in setOf("precision", "recall") }
        .associateWith { starts.getValue(it) } + mapOf(
            "oracleFunctionCount" to oracle.getValue("totalFunctions"),
            "scoreableOracleFunctionCount" to oracle.getValue("scoreableFunctions"),
            "excludedOracleFunctionCount" to oracle.getValue("excludedFunctions"),
            "oracleOnlyFunctionCount" to JsonPrimitive(overlay.getValue("oracleOnlyFunctions").arr().size),
            "precision" to ratios.getValue("exactStartPrecision"), "recall" to ratios.getValue("exactStartRecall")))
    val aliasProjection = JsonObject(ALIAS_FIELDS.filter { it != "identityRecovery" }.associateWith { aliases.getValue(it) } +
        ("identityRecovery" to ratios.getValue("survivingSymbolIdentity")))
    val projectedBindings = JsonObject(base.getValue("bindings").obj() + ("sourceOverlay" to obj(
        "sha256" to JsonPrimitive(sha256(overlayBytes)), "bytes" to JsonPrimitive(overlayBytes.size),
        "schemaVersion" to JsonPrimitive(1), "scope" to JsonPrimitive(OVERLAY_SCOPE))))
    val modules = base.getValue("modules").arr().map { it.obj() }.map { module ->
        JsonObject(module + ("candidateMeasurements" to JsonObject(candidates.getValue(module.text("moduleId"))
            .mapValues { JsonPrimitive(it.value) })))
    }
    return JsonObject(base + mapOf("bindings" to projectedBindings, "modules" to JsonArray(modules),
        "measurements" to obj("functionStarts" to startProjection, "survivingSymbolIdentity" to aliasProjection),
        "unassigned" to obj("oracleFunctionCount" to oracle.getValue("totalFunctions"),
            "oracleOnlyFunctionCount" to startProjection.getValue("oracleOnlyFunctionCount"),
            "excludedOracleFunctionCount" to oracle.getValue("excludedFunctions"),
            "survivingAliasCount" to JsonPrimitive(missingAliases))))
}

private fun validateBound(value: JsonObject, analysis: ProgramAnalysisResult, plan: ModulePlan,
    maximumBytes: Int, checkpoint: (String) -> Unit) {
    val expected = baseProjection(analysis, capturePlan(plan, checkpoint), maximumBytes, checkpoint)
    val bindings = value.getValue("bindings").obj()
    require(bindings.filterKeys { it != "sourceOverlay" } == expected.getValue("bindings").obj().filterKeys { it != "sourceOverlay" }) {
        "assessment bindings differ from exact model, plan or complete typed census"
    }
    for (field in listOf("population", "extraction", "dimensions")) require(value[field] == expected[field]) {
        "assessment $field differs from the complete model census"
    }
    val modules = value.getValue("modules").arr().map { it.obj().filterKeys { key -> key != "candidateMeasurements" } }
    val expectedModules = expected.getValue("modules").arr().map { it.obj().filterKeys { key -> key != "candidateMeasurements" } }
    require(modules == expectedModules) { "assessment module population differs from exact typed ownership" }
    assessmentCheckpoint(checkpoint, "after exact assessment binding validation")
}

private fun validateProjection(root: JsonObject, includeModules: Boolean, checkpoint: (String) -> Unit) {
    assessmentCheckpoint(checkpoint, "before passive assessment validation")
    root.keysExactly(ROOT_FIELDS + if (includeModules) setOf("modules") else setOf("projectionSha256", "confidenceSha256"))
    require(root.count("schemaVersion") == 1L && root.text("authority") == "reported-assessment" &&
        root.text("scope") == RecoveryAssessmentProjectionV1.SCOPE && root.text("recoveryAssessmentState") == "unassessed" &&
        root["complete"] == JsonPrimitive(false) && root["releaseEligible"] == JsonPrimitive(false))
    val binding = root.getValue("bindings").obj()
    binding.keysExactly(BINDING_FIELDS)
    if (binding["inputSha256"] != JsonNull) binding.digest("inputSha256")
    listOf("modelSha256", "planSha256", "censusSha256").forEach(binding::digest)
    require(binding.count("modelBytes") in 1..ProgramAnalysisResult.MAXIMUM_MODEL_BYTES.toLong() &&
        binding.count("modelSchemaVersion") in 1..4 && binding.count("planSchemaVersion") == 2L &&
        binding.count("planBytes") in 1..RecoveryAssessmentProjectionV1.MAXIMUM_BYTES.toLong())
    val population = root.getValue("population").obj()
    validatePopulation(population)
    val extraction = root.getValue("extraction").obj()
    extraction.keysExactly(STATUSES.toSet() + "calibration")
    require(extraction.text("calibration") == "uncalibrated" && checkedSum(STATUSES.map(extraction::count)) == population.count("modelEntityCount"))
    require(root["dimensions"] == dimensions(population)) { "assessment dimensions must remain completely unassessed" }
    val hasEvidence = root["measurements"] != JsonNull
    require((binding["sourceOverlay"] != JsonNull) == hasEvidence && (root["unassigned"] != JsonNull) == hasEvidence)
    if (hasEvidence) {
        require(binding["inputSha256"] != JsonNull)
        val source = binding.getValue("sourceOverlay").obj()
        source.keysExactly(setOf("sha256", "bytes", "schemaVersion", "scope")); source.digest("sha256")
        require(source.count("bytes") in 1..RecoveryAssessmentProjectionV1.MAXIMUM_BYTES.toLong() &&
            source.count("schemaVersion") == 1L && source.text("scope") == OVERLAY_SCOPE)
        validateMeasurements(root.getValue("measurements").obj(), root.getValue("unassigned").obj(), population)
    }
    if (includeModules) {
        val modules = root.getValue("modules").arr().map { it.obj() }
        val ids = hashSetOf<String>()
        var previous = ""
        modules.forEach { module ->
            assessmentCheckpoint(checkpoint, "validating bounded module assessment")
            module.keysExactly(setOf("moduleId", "population", "candidateMeasurements"))
            val id = module.text("moduleId")
            require(MODULE_ID.matches(id) && ids.add(id) && id >= previous); previous = id
            validatePopulation(module.getValue("population").obj())
            require((module["candidateMeasurements"] != JsonNull) == hasEvidence)
            if (hasEvidence) validateCandidate(module.getValue("candidateMeasurements").obj(), module.getValue("population").obj())
        }
        for (field in POPULATION_FIELDS - "unit") require(checkedSum(modules.map { it.getValue("population").obj().count(field) }) == population.count(field)) {
            "module population does not reconcile with complete project census"
        }
        if (hasEvidence) reconcileCandidates(modules, root.getValue("measurements").obj(), root.getValue("unassigned").obj())
    }
    assessmentCheckpoint(checkpoint, "after passive assessment validation")
}

private fun validatePopulation(row: JsonObject) {
    row.keysExactly(POPULATION_FIELDS)
    require(row.text("unit") == "model-entities" && row.count("assessedEntityCount") == 0L &&
        row.count("unassessedEntityCount") == row.count("modelEntityCount") &&
        checkedSum(KINDS.map { row.count("${it}Count") }) == row.count("modelEntityCount"))
}

private fun validateMeasurements(measurements: JsonObject, unassigned: JsonObject, population: JsonObject) {
    measurements.keysExactly(setOf("functionStarts", "survivingSymbolIdentity"))
    val s = measurements.getValue("functionStarts").obj(); s.keysExactly(START_FIELDS)
    val a = measurements.getValue("survivingSymbolIdentity").obj(); a.keysExactly(ALIAS_FIELDS)
    (START_FIELDS - setOf("precision", "recall")).forEach(s::count)
    (ALIAS_FIELDS - "identityRecovery").forEach(a::count)
    require(s.count("rawRecoveredCount") == population.count("functionCount") &&
        s.count("rawRecoveredCount") == checkedSum(listOf(s.count("scoredRecoveredCount"), s.count("ignoredExcludedCount"))) &&
        s.count("scoredRecoveredCount") == checkedSum(listOf(s.count("exactMatches"), s.count("falsePositives"))) &&
        s.count("scoreableOracleFunctionCount") == checkedSum(listOf(s.count("exactMatches"), s.count("falseNegatives"))) &&
        s.count("oracleFunctionCount") == checkedSum(listOf(s.count("scoreableOracleFunctionCount"), s.count("excludedOracleFunctionCount"))) &&
        s.count("nearMisses") <= s.count("falsePositives") &&
        s.count("falseNegatives") == checkedSum(listOf(s.count("nearMisses"), s.count("oracleOnlyFunctionCount"))) &&
        s.count("ignoredExcludedCount") <= s.count("excludedOracleFunctionCount")) { "inconsistent complete start population" }
    validateRatio(s.getValue("precision").obj(), "recovered-function-starts", s.count("exactMatches"), s.count("scoredRecoveredCount"))
    validateRatio(s.getValue("recall").obj(), "oracle-function-starts", s.count("exactMatches"), s.count("scoreableOracleFunctionCount"))
    require(a.count("population") == checkedSum(listOf(a.count("exact"), a.count("nameMismatch"), a.count("missing"))))
    validateRatio(a.getValue("identityRecovery").obj(), "surviving-oracle-aliases", a.count("exact"), a.count("population"))
    unassigned.keysExactly(UNASSIGNED_FIELDS)
    for (field in UNASSIGNED_FIELDS - "survivingAliasCount") require(unassigned.count(field) == s.count(field))
    require(unassigned.count("survivingAliasCount") == a.count("missing"))
}

private fun validateRatio(row: JsonObject, unit: String, numerator: Long, denominator: Long) {
    row.keysExactly(setOf("unit", "numerator", "denominator", "value"))
    require(row.text("unit") == unit && row.count("numerator") == numerator && row.count("denominator") == denominator && numerator <= denominator)
    if (denominator == 0L) require(row["value"] == JsonNull) else {
        val value = row["value"] as? JsonPrimitive
        require(value != null && !value.isString && value.doubleOrNull == numerator.toDouble() / denominator)
    }
}

private fun validateCandidate(row: JsonObject, population: JsonObject) {
    row.keysExactly(CANDIDATE_FIELDS); CANDIDATE_FIELDS.forEach(row::count)
    require(row.count("rawRecoveredCount") == population.count("functionCount") &&
        row.count("rawRecoveredCount") == checkedSum(listOf(row.count("scoredRecoveredCount"), row.count("ignoredExcludedCount"))) &&
        row.count("scoredRecoveredCount") == checkedSum(listOf(row.count("exactMatches"), row.count("nearMisses"), row.count("unmatchedCount"))) &&
        row.count("survivingAliasCount") == checkedSum(listOf(row.count("exactSurvivingAliasCount"), row.count("mismatchedSurvivingAliasCount"))))
}

private fun reconcileCandidates(modules: List<JsonObject>, measurements: JsonObject, unassigned: JsonObject) {
    fun sum(field: String) = checkedSum(modules.map { it.getValue("candidateMeasurements").obj().count(field) })
    val starts = measurements.getValue("functionStarts").obj()
    val aliases = measurements.getValue("survivingSymbolIdentity").obj()
    for (field in listOf("rawRecoveredCount", "scoredRecoveredCount", "ignoredExcludedCount", "exactMatches", "nearMisses"))
        require(sum(field) == starts.count(field))
    require(checkedSum(listOf(sum("unmatchedCount"), sum("nearMisses"))) == starts.count("falsePositives") &&
        checkedSum(listOf(sum("survivingAliasCount"), unassigned.count("survivingAliasCount"))) == aliases.count("population") &&
        sum("exactSurvivingAliasCount") == aliases.count("exact") && sum("mismatchedSurvivingAliasCount") == aliases.count("nameMismatch"))
}

private fun projectionLimits(maximumBytes: Int): StrictJsonLimits {
    require(maximumBytes in 1..RecoveryAssessmentProjectionV1.MAXIMUM_BYTES)
    return StrictJsonLimits(maximumInputBytes = maximumBytes, maximumCanonicalBytes = maximumBytes,
        maximumDepth = 16, maximumNodes = 1_000_000, maximumStringBytes = minOf(maximumBytes, 16 * 1024),
        maximumTotalStringBytes = maximumBytes)
}

/** Exact canonical expansion preflight, before the encoder allocates its output buffer. */
private fun preflightJson(value: JsonElement, maximumBytes: Int, checkpoint: (String) -> Unit) {
    require(maximumBytes in 1..RecoveryAssessmentProjectionV1.MAXIMUM_BYTES)
    var bytes = 1L
    var nodes = 0L
    fun add(n: Long) { bytes = Math.addExact(bytes, n); require(bytes <= maximumBytes) { "assessment exceeds its encoded byte budget" } }
    fun text(text: String) {
        add(2)
        var index = 0
        while (index < text.length) {
            if (index % 1024 == 0) assessmentCheckpoint(checkpoint, "preflighting assessment string")
            val char = text[index++]
            add(when {
                char in listOf('"', '\\', '\b', '\u000c', '\n', '\r', '\t') -> 2
                char.code < 0x20 -> 6
                char.code < 0x80 -> 1
                char.code < 0x800 -> 2
                Character.isHighSurrogate(char) -> {
                    require(index < text.length && Character.isLowSurrogate(text[index])) { "unpaired assessment surrogate" }
                    index++; 4
                }
                Character.isLowSurrogate(char) -> throw IllegalArgumentException("unpaired assessment surrogate")
                else -> 3
            }.toLong())
        }
    }
    fun visit(element: JsonElement, indentation: Int, depth: Int) {
        assessmentCheckpoint(checkpoint, "preflighting assessment bytes")
        nodes = Math.addExact(nodes, 1); require(nodes <= 1_000_000 && depth <= 16)
        when (element) {
            is JsonObject -> {
                if (element.isEmpty()) add(2) else {
                    add(2)
                    element.entries.forEachIndexed { index, (key, child) ->
                        add((indentation + 1) * 2L); text(key); add(2)
                        visit(child, indentation + 1, depth + 1)
                        add(if (index < element.size - 1) 2 else 1)
                    }
                    add(indentation * 2L + 1)
                }
            }
            is JsonArray -> {
                if (element.isEmpty()) add(2) else {
                    add(2)
                    element.forEachIndexed { index, child ->
                        add((indentation + 1) * 2L); visit(child, indentation + 1, depth + 1)
                        add(if (index < element.size - 1) 2 else 1)
                    }
                    add(indentation * 2L + 1)
                }
            }
            is JsonPrimitive -> if (element.isString) text(element.content) else {
                // Numeric normalization is delegated for one bounded scalar, never the report tree.
                require(element.content.length <= 256)
                add(OracleJson.canonicalBytes(element, projectionLimits(1024)).size.toLong() - 1)
            }
        }
    }
    visit(value, 0, 1)
}

private fun immutableJson(value: JsonElement, checkpoint: (String) -> Unit = {}): JsonElement {
    assessmentCheckpoint(checkpoint, "freezing assessment value")
    return when (value) {
        is JsonObject -> JsonObject(Collections.unmodifiableMap(value.mapValues { immutableJson(it.value, checkpoint) }))
        is JsonArray -> JsonArray(Collections.unmodifiableList(value.map { immutableJson(it, checkpoint) }))
        else -> value
    }
}
private fun obj(vararg fields: Pair<String, JsonElement?>): JsonObject = JsonObject(fields.associate { it.first to (it.second ?: JsonNull) })
private fun JsonElement.obj(): JsonObject = this as? JsonObject ?: throw IllegalArgumentException("assessment field must be an object")
private fun JsonElement.arr(): JsonArray = this as? JsonArray ?: throw IllegalArgumentException("assessment field must be an array")
private fun JsonObject.keysExactly(fields: Set<String>) = require(keys == fields) { "assessment fields differ from closed schema" }
private fun JsonObject.text(field: String): String = (this[field] as? JsonPrimitive)?.takeIf { it.isString }?.content
    ?: throw IllegalArgumentException("assessment $field must be a string")
private fun JsonObject.digest(field: String): String = text(field).also { require(SHA.matches(it)) { "assessment $field must be a digest" } }
private fun JsonObject.count(field: String): Long {
    val value = this[field] as? JsonPrimitive
    require(value != null && !value.isString && value.content.matches(Regex("0|[1-9][0-9]*"))) { "assessment $field must be nonnegative integer" }
    val count = requireNotNull(value.content.toLongOrNull()) { "assessment $field overflows" }
    require(count <= ProgramAnalysisResult.MAXIMUM_MODEL_BYTES.toLong()) { "assessment count exceeds bounded population" }
    return count
}
private fun checkedSum(values: Iterable<Long>): Long = values.fold(0L, Math::addExact)
