package decompengine.web

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import decompengine.project.RecoveryStatus
import decompengine.project.StructuralRecoveryScore
import java.math.BigDecimal
import java.util.concurrent.CancellationException
import kotlinx.serialization.json.*

/**
 * Recorded facts of one revision's `reports/confidence.json` (schema 2), read in one closed-shape pass. Scores
 * keep their exact recorded decimal text; identity lists are counted, not retained.
 */
internal class WebConfidenceRecord(
    val basis: String,
    val scoreMeaning: String,
    val interpretationKind: String,
    val interpretationSchema: Long,
    val calibrationStatus: String,
    val calibratedProbability: String?,
    val empiricalSampleCount: String?,
    val assessmentState: String,
    val assessmentModelSchema: Long,
    val assessmentModelSha256: String,
    val assessedEntities: Int,
    val unassessedEntities: Int,
    val projectScore: String,
    val modules: Map<String, String>,
    val unresolvedRecoveryEntities: Int,
    val unresolvedImplementationEntities: Int,
    val generation: Generation?,
) {
    class Generation(val planned: Long, val completed: Long, val accepted: Long, val unresolved: Long)

    companion object {
        const val MAXIMUM_BYTES = 32 * 1024 * 1024
        private const val MAXIMUM_MODULES = WebSourceCatalogSnapshot.MAXIMUM_FILES
        private const val MAXIMUM_TEXT = 4096
        private val FIELDS = setOf("schemaVersion", "basis", "scoreMeaning", "scoreInterpretation", "recoveryAssessment",
            "projectScore", "modules", "unresolvedRecoveryEntityIds", "unresolvedImplementationIds", "unresolvedEntityIds",
            "semanticPlanningBudgetEvidence", "sourceGenerationBudgetEvidence")
        private val OPTIONAL = setOf("semanticPlanningBudgetEvidence", "sourceGenerationBudgetEvidence")
        private val DECIMAL = Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?")

        /** Parse outcome with the structure state vocabulary; only `available` carries a record. */
        fun parse(bytes: ByteArray): WebStructureParse<WebConfidenceRecord> = try {
            WebStructureParse(Reader(bytes).read(), WebStructureOutcome.AVAILABLE)
        } catch (failure: WebProgramStructureBuilder.WebStructureFailure) {
            WebStructureParse(null, WebStructureOutcome(failure.state, failure.reason))
        } catch (failure: Exception) {
            if (failure is CancellationException || failure is InterruptedException) throw failure
            WebStructureParse(null, WebStructureOutcome("invalid", "CONFIDENCE_MALFORMED"))
        }
    }

    private class Reader(private val bytes: ByteArray) {
        private fun malformed(): Nothing = throw WebProgramStructureBuilder.WebStructureFailure("invalid", "CONFIDENCE_MALFORMED")

        fun read(): WebConfidenceRecord = WebProgramStructureBuilder.JSON.createParser(bytes).use { parser ->
            if (parser.nextToken() != JsonToken.START_OBJECT) malformed()
            if (parser.nextToken() != JsonToken.FIELD_NAME || parser.currentName() != "schemaVersion") malformed()
            if (parser.nextToken() != JsonToken.VALUE_NUMBER_INT) malformed()
            if (parser.text != "2") throw WebProgramStructureBuilder.WebStructureFailure("unsupported", "CONFIDENCE_SCHEMA_UNSUPPORTED")
            val seen = hashSetOf("schemaVersion")
            var basis: String? = null; var meaning: String? = null; var score: String? = null
            var interpretation: Map<String, String?>? = null
            var assessment: Map<String, String?>? = null; var assessed = -1; var unassessed = -1
            val modules = LinkedHashMap<String, String>()
            var recovery = -1; var implementation = -1
            var generation: Generation? = null
            while (true) {
                val token = parser.nextToken()
                if (token == JsonToken.END_OBJECT) break
                if (token != JsonToken.FIELD_NAME) malformed()
                val key = parser.currentName()
                if (key !in FIELDS || !seen.add(key)) malformed()
                when (key) {
                    "basis" -> basis = text(parser)
                    "scoreMeaning" -> meaning = text(parser)
                    "projectScore" -> score = decimal(parser)
                    "scoreInterpretation" -> interpretation = scalars(parser) { _, _ -> malformed() }
                    "recoveryAssessment" -> assessment = scalars(parser) { field, value ->
                        when (field) {
                            "unassessedEntityIds" -> unassessed = count(value)
                            "assessedEntityIds" -> assessed = count(value)
                            else -> malformed()
                        }
                    }
                    "modules" -> {
                        if (parser.nextToken() != JsonToken.START_ARRAY) malformed()
                        while (parser.nextToken() != JsonToken.END_ARRAY) {
                            if (parser.currentToken() != JsonToken.START_OBJECT) malformed()
                            if (modules.size >= MAXIMUM_MODULES) throw WebProgramStructureBuilder.WebStructureFailure("limit-exceeded", "CONFIDENCE_MODULES_EXCEEDED")
                            var id: String? = null; var moduleScore: String? = null
                            val fields = HashSet<String>()
                            while (parser.nextToken() != JsonToken.END_OBJECT) {
                                val field = parser.currentName()
                                if (!fields.add(field)) malformed()
                                when (field) {
                                    "id" -> id = text(parser)
                                    "score" -> moduleScore = decimal(parser)
                                    "unresolvedRecoveryEntityIds", "unresolvedImplementationIds" -> { if (parser.nextToken() != JsonToken.START_ARRAY) malformed(); count(parser) }
                                    "revisionEvidence" -> { parser.nextToken(); parser.skipChildren() }
                                    else -> malformed()
                                }
                            }
                            if (id == null || moduleScore == null || modules.put(id, moduleScore) != null) malformed()
                        }
                    }
                    "unresolvedRecoveryEntityIds" -> { if (parser.nextToken() != JsonToken.START_ARRAY) malformed(); recovery = count(parser) }
                    "unresolvedImplementationIds" -> { if (parser.nextToken() != JsonToken.START_ARRAY) malformed(); implementation = count(parser) }
                    "unresolvedEntityIds" -> { if (parser.nextToken() != JsonToken.START_ARRAY) malformed(); count(parser) }
                    "semanticPlanningBudgetEvidence" -> { if (parser.nextToken() != JsonToken.START_OBJECT) malformed(); parser.skipChildren() }
                    "sourceGenerationBudgetEvidence" -> generation = generation(parser)
                }
            }
            if (parser.nextToken() != null || !seen.containsAll(FIELDS - OPTIONAL)) malformed()
            val scoring = checkNotNull(interpretation)
            val recorded = checkNotNull(assessment)
            if (scoring.keys != setOf("schemaVersion", "kind", "calibrationStatus", "calibratedProbability",
                    "calibrationArtifactSha256", "empiricalSampleCount")) malformed()
            if (recorded.keys != setOf("schemaVersion", "state", "modelSchemaVersion", "modelSha256") || assessed < 0 || unassessed < 0) malformed()
            WebConfidenceRecord(checkNotNull(basis), checkNotNull(meaning), scoring["kind"] ?: malformed(),
                scoring["schemaVersion"]?.toLongOrNull() ?: malformed(), scoring["calibrationStatus"] ?: malformed(),
                scoring["calibratedProbability"], scoring["empiricalSampleCount"], recorded["state"] ?: malformed(),
                recorded["modelSchemaVersion"]?.toLongOrNull() ?: malformed(),
                recorded["modelSha256"]?.takeIf { it.matches(Regex("[a-f0-9]{64}")) } ?: malformed(),
                assessed, unassessed, checkNotNull(score), modules, recovery, implementation, generation)
        }

        private fun text(parser: JsonParser): String {
            if (parser.nextToken() != JsonToken.VALUE_STRING || parser.textLength > MAXIMUM_TEXT) malformed()
            return parser.text
        }

        private fun decimal(parser: JsonParser): String {
            val token = parser.nextToken()
            if (token != JsonToken.VALUE_NUMBER_FLOAT && token != JsonToken.VALUE_NUMBER_INT) malformed()
            return parser.text.takeIf { DECIMAL.matches(it) } ?: malformed()
        }

        /** One flat object of scalars (text kept, null as null); arrays go to [array] at their start token. */
        private fun scalars(parser: JsonParser, array: (String, JsonParser) -> Unit): Map<String, String?> {
            if (parser.nextToken() != JsonToken.START_OBJECT) malformed()
            val values = LinkedHashMap<String, String?>()
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                val field = parser.currentName()
                if (field in values) malformed()
                when (parser.nextToken()) {
                    JsonToken.VALUE_NULL -> values[field] = null
                    JsonToken.VALUE_STRING, JsonToken.VALUE_NUMBER_INT, JsonToken.VALUE_NUMBER_FLOAT ->
                        values[field] = parser.text.also { if (it.length > MAXIMUM_TEXT) malformed() }
                    JsonToken.START_ARRAY -> array(field, parser)
                    else -> malformed()
                }
            }
            return values
        }

        /** Count string items of the array whose start token is current. */
        private fun count(parser: JsonParser): Int {
            var count = 0
            while (parser.nextToken() != JsonToken.END_ARRAY) {
                if (parser.currentToken() != JsonToken.VALUE_STRING) malformed()
                count++
            }
            return count
        }

        private fun generation(parser: JsonParser): Generation? {
            if (parser.nextToken() != JsonToken.START_OBJECT) malformed()
            var outcome: Generation? = null
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                if (parser.currentName() != "outcome") { parser.nextToken(); parser.skipChildren(); continue }
                val values = scalars(parser) { _, _ -> malformed() }
                fun number(name: String) = values[name]?.toLongOrNull()?.takeIf { it >= 0 } ?: malformed()
                outcome = Generation(number("plannedModules"), number("completedModules"), number("acceptedModules"), number("unresolvedModules"))
            }
            return outcome
        }
    }
}

/** One stated measure: exact numerator and denominator, recorded and reproduced values, and why it has its state. */
internal class WebScorecardMetric(
    val id: String,
    val unit: String,
    val state: String,
    val reason: String?,
    val value: String?,
    val recomputed: String?,
    val numerator: String?,
    val denominator: Long?,
    val record: String,
    val field: String,
    val formula: String?,
) {
    fun json(): JsonObject = buildJsonObject {
        put("id", id); put("unit", unit); put("state", state); put("reason", reason?.let(::JsonPrimitive) ?: JsonNull)
        put("value", value?.let(::JsonPrimitive) ?: JsonNull); put("recomputed", recomputed?.let(::JsonPrimitive) ?: JsonNull)
        put("numerator", numerator?.let(::JsonPrimitive) ?: JsonNull)
        put("denominator", denominator?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
        put("source", buildJsonObject { put("record", record); put("field", field); put("formula", formula?.let(::JsonPrimitive) ?: JsonNull) })
    }
}

internal class WebScorecardModule(val row: Int, val moduleId: String, val metric: WebScorecardMetric)

/**
 * The scorecard of one projection: the recorded confidence facts joined to the recorded model and plan. Every
 * value shown is recorded; the web side only reproduces recorded scores from recorded labels to state parity.
 */
internal class WebStructureScorecard(
    val outcome: WebStructureOutcome,
    val record: WebStructureRecord?,
    val confidence: WebConfidenceRecord?,
    val metrics: List<WebScorecardMetric>,
    val labels: List<JsonObject>,
    val modules: List<WebScorecardModule>,
    val reconciliation: JsonObject?,
    val entities: Long,
) {
    val available: Boolean get() = outcome.state == "available"

    companion object {
        private val STATUS = mapOf(WebExtractionStatus.RECOVERED to RecoveryStatus.RECOVERED, WebExtractionStatus.PARTIAL to RecoveryStatus.PARTIAL,
            WebExtractionStatus.SYNTHETIC to RecoveryStatus.SYNTHETIC, WebExtractionStatus.FAILED to RecoveryStatus.FAILED)

        fun of(index: WebProgramStructureIndex, records: WebStructureRecordReader): WebStructureScorecard {
            index.scorecard?.let { return it }
            return build(index, records).also { index.scorecard = it }
        }

        private fun unavailable(outcome: WebStructureOutcome, record: WebStructureRecord? = null) =
            WebStructureScorecard(outcome, record, null, emptyList(), emptyList(), emptyList(), null, 0)

        private fun build(index: WebProgramStructureIndex, records: WebStructureRecordReader): WebStructureScorecard {
            val file = index.confidenceFile ?: return unavailable(WebStructureOutcome("not-recorded",
                if (index.confidenceDeclared) "CONFIDENCE_NOT_RECORDED" else "PROFILE_DECLARES_NO_CONFIDENCE"))
            if (!index.available) return unavailable(WebStructureOutcome(index.outcome.state, index.outcome.reason))
            val bytes = try { records.read(WebStructureRecord(file.path, file.sha256, -1), WebConfidenceRecord.MAXIMUM_BYTES) }
                catch (_: decompengine.repair.RepairBudgetExceededException) {
                    return unavailable(WebStructureOutcome("limit-exceeded", "CONFIDENCE_BYTES_EXCEEDED"))
                }
            val record = WebStructureRecord(file.path, file.sha256, bytes.size.toLong())
            val parsed = WebConfidenceRecord.parse(bytes)
            val confidence = parsed.value ?: return unavailable(parsed.outcome, record)
            if (confidence.assessmentModelSha256 != index.model?.sha256 || confidence.assessmentModelSchema != index.modelSchemaVersion?.toLong()) {
                return unavailable(WebStructureOutcome("invalid", "CONFIDENCE_MODEL_MISMATCH"), record)
            }
            return compute(index, record, confidence)
        }

        private fun compute(index: WebProgramStructureIndex, record: WebStructureRecord, confidence: WebConfidenceRecord): WebStructureScorecard {
            val tables = index.tables
            val all = ArrayList<RecoveryStatus>(tables.sumOf { it.size })
            for (table in tables) for (row in 0 until table.size) all += STATUS.getValue(table.status[row])
            val entities = all.size.toLong()
            fun numerator(statuses: List<RecoveryStatus>): BigDecimal =
                statuses.fold(BigDecimal.ZERO) { sum, status -> sum + StructuralRecoveryScore.exactWeight(status) }
            fun plain(value: BigDecimal) = value.stripTrailingZeros().toPlainString()
            fun score(id: String, recorded: String?, statuses: List<RecoveryStatus>?, field: String): WebScorecardMetric {
                val recomputed = statuses?.let(StructuralRecoveryScore::render)
                val (state, reason) = when {
                    recorded == null -> "unknown" to "SCORE_NOT_RECORDED"
                    statuses == null -> "failed" to "PLAN_REFERENCES_UNRECORDED_ENTITY"
                    statuses.isEmpty() -> "unmeasured" to "EMPTY_POPULATION"
                    BigDecimal(recorded).compareTo(BigDecimal(checkNotNull(recomputed))) != 0 -> "failed" to "SCORE_PARITY_MISMATCH"
                    else -> "measured" to null
                }
                return WebScorecardMetric(id, "ratio", state, reason, recorded, recomputed, statuses?.let { plain(numerator(it)) },
                    statuses?.size?.toLong(), "confidence", field, StructuralRecoveryScore.FORMULA)
            }
            val metrics = ArrayList<WebScorecardMetric>()
            metrics += score("structural-recovery-score", confidence.projectScore, all, "projectScore")
            metrics += if (confidence.calibrationStatus == "uncalibrated" && confidence.calibratedProbability == null) {
                WebScorecardMetric("calibrated-confidence", "ratio", "unmeasured", "UNCALIBRATED", null, null, null,
                    confidence.empiricalSampleCount?.toLongOrNull(), "confidence", "scoreInterpretation.calibratedProbability", null)
            } else WebScorecardMetric("calibrated-confidence", "ratio", "unknown", "CALIBRATION_STATE_UNSUPPORTED", null, null, null, null,
                "confidence", "scoreInterpretation.calibratedProbability", null)
            metrics += WebScorecardMetric("assessed-recovery", "count",
                if (confidence.assessmentState == "unassessed" && confidence.assessedEntities == 0) "unmeasured" else "unknown",
                if (confidence.assessmentState == "unassessed" && confidence.assessedEntities == 0) "UNASSESSED" else "ASSESSMENT_STATE_UNSUPPORTED",
                null, null, confidence.assessedEntities.toString(), (confidence.assessedEntities + confidence.unassessedEntities).toLong(),
                "confidence", "recoveryAssessment.assessedEntityIds", null)
            val planned = index.planOutcome.state == "available"
            val declaredAccepted = index.modules.count { it.implementationDeclaration == "accepted" }.toLong()
            val generation = confidence.generation
            // Current acceptance is the manifest's declaration. The confidence report's generation outcome is the
            // historical generation population: an accepted repair updates the manifest but not that outcome, so the
            // two are separate measures and a difference between them is expected, not a disagreement.
            metrics += if (!planned) WebScorecardMetric("implementation-acceptance", "count", "unknown", "PLAN_NOT_AVAILABLE", null, null,
                null, null, "manifest", "files[].acceptedImplementation", null)
            else WebScorecardMetric("implementation-acceptance", "count", "measured", null, null, null,
                declaredAccepted.toString(), index.modules.size.toLong(), "manifest", "files[].acceptedImplementation", null)
            metrics += when {
                generation == null -> WebScorecardMetric("generation-completion", "count", "unknown", "GENERATION_EVIDENCE_NOT_RECORDED",
                    null, null, null, null, "confidence", "sourceGenerationBudgetEvidence.outcome.completedModules", null)
                generation.completed < generation.planned -> WebScorecardMetric("generation-completion", "count", "partial", "GENERATION_INCOMPLETE",
                    null, null, generation.completed.toString(), generation.planned, "confidence", "sourceGenerationBudgetEvidence.outcome.completedModules", null)
                generation.completed > generation.planned -> WebScorecardMetric("generation-completion", "count", "failed", "GENERATION_EXCEEDS_PLAN",
                    null, null, generation.completed.toString(), generation.planned, "confidence", "sourceGenerationBudgetEvidence.outcome.completedModules", null)
                else -> WebScorecardMetric("generation-completion", "count", "measured", null, null, null, generation.completed.toString(),
                    generation.planned, "confidence", "sourceGenerationBudgetEvidence.outcome.completedModules", null)
            }
            fun unresolved(id: String, recorded: Int, manifest: Int, field: String) = WebScorecardMetric(id, "count",
                if (recorded < 0) "unknown" else if (recorded != manifest) "failed" else "measured",
                if (recorded < 0) "NOT_RECORDED" else if (recorded != manifest) "MANIFEST_RECORD_DISAGREES" else null,
                null, null, recorded.takeIf { it >= 0 }?.toString(), entities, "confidence", field, null)
            metrics += unresolved("unresolved-recovery", confidence.unresolvedRecoveryEntities, index.manifestUnresolvedEntities, "unresolvedRecoveryEntityIds")
            metrics += unresolved("unresolved-implementation", confidence.unresolvedImplementationEntities,
                index.manifestUnresolvedImplementations, "unresolvedImplementationIds")
            val excluded = tables.sumOf { table -> (0 until table.size).count { table.owners[it] == OWNER_UNOWNED } }.toLong()
            metrics += if (planned) WebScorecardMetric("excluded-entities", "count", "measured", null, null, null, excluded.toString(), entities,
                "plan", "modules[].functionIds|globalIds|typeIds", null)
                else WebScorecardMetric("excluded-entities", "count", "unknown", "PLAN_NOT_AVAILABLE", null, null, null, null,
                    "plan", "modules[].functionIds|globalIds|typeIds", null)

            // Extraction-label components of the score numerator, per kind.
            val labels = RecoveryStatus.entries.map { status ->
                val counts = tables.map { table -> (0 until table.size).count { STATUS.getValue(table.status[it]) == status } }
                val total = counts.sum()
                buildJsonObject {
                    put("label", status.name.lowercase())
                    put("functions", counts[0]); put("globals", counts[1]); put("types", counts[2]); put("entities", total)
                    put("weight", plain(StructuralRecoveryScore.exactWeight(status)))
                    put("contribution", plain(StructuralRecoveryScore.exactWeight(status) * BigDecimal(total)))
                }
            }

            // Module rows and the reconciliation of module numerators/denominators with the project population.
            val modules = ArrayList<WebScorecardModule>()
            var moduleNumerators = BigDecimal.ZERO; var moduleDenominators = 0L
            val memberships = tables.map { IntArray(it.size) }
            for ((row, module) in index.modules.withIndex()) {
                var complete = true
                val statuses = ArrayList<RecoveryStatus>()
                for ((kind, ids) in listOf(WebStructureKind.FUNCTION to module.functionIds, WebStructureKind.GLOBAL to module.globalIds,
                    WebStructureKind.TYPE to module.typeIds)) {
                    val table = index.table(kind)
                    for (id in ids) {
                        val entity = table.index[id]
                        if (entity == null) { complete = false; continue }
                        memberships[kind.ordinal][entity]++
                        statuses += STATUS.getValue(table.status[entity])
                    }
                }
                moduleNumerators += numerator(statuses); moduleDenominators += statuses.size
                modules += WebScorecardModule(row, module.id, score("module-structural-recovery-score", confidence.modules[module.id],
                    statuses.takeIf { complete }, "modules[].score"))
            }
            var excludedNumerator = BigDecimal.ZERO; var duplicateNumerator = BigDecimal.ZERO; var duplicates = 0L
            for ((kind, table) in tables.withIndex()) for (row in 0 until table.size) {
                val weight = StructuralRecoveryScore.exactWeight(STATUS.getValue(table.status[row]))
                val count = memberships[kind][row]
                if (count == 0) excludedNumerator += weight
                if (count > 1) { duplicates += count - 1; duplicateNumerator += weight * BigDecimal(count - 1) }
            }
            val project = numerator(all)
            val unplanned = confidence.modules.keys.count { it !in index.moduleIndex }
            val reconciliation = if (!planned) null else buildJsonObject {
                put("projectNumerator", plain(project)); put("projectDenominator", entities.toString())
                put("moduleNumeratorSum", plain(moduleNumerators)); put("moduleDenominatorSum", moduleDenominators.toString())
                put("excludedNumerator", plain(excludedNumerator)); put("excludedEntities", excluded.toString())
                put("duplicateNumerator", plain(duplicateNumerator)); put("duplicateMemberships", duplicates.toString())
                put("unrecordedPlanReferences", index.unknownPlanReferences); put("unplannedScoreRows", unplanned)
                put("reconciles", moduleDenominators + excluded - duplicates == entities &&
                    (moduleNumerators + excludedNumerator - duplicateNumerator).compareTo(project) == 0 &&
                    index.unknownPlanReferences == 0 && unplanned == 0)
                put("adjustments", JsonArray(buildList {
                    if (excluded > 0) add("EXCLUDED_ENTITIES")
                    if (duplicates > 0) add("SHARED_OWNERSHIP")
                    if (index.unknownPlanReferences > 0) add("UNRECORDED_PLAN_REFERENCES")
                    if (unplanned > 0) add("SCORES_FOR_UNPLANNED_MODULES")
                }.map(::JsonPrimitive)))
                put("scoreAdditivity", "non-additive-mean")
            }
            return WebStructureScorecard(WebStructureOutcome.AVAILABLE, record, confidence, metrics, labels, modules, reconciliation, entities)
        }
    }
}
