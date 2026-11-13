package decompengine.repair

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.security.MessageDigest
import java.util.Collections
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

private fun <T> frozenEvidenceList(values: Collection<T>): List<T> =
    Collections.unmodifiableList(ArrayList(values))
private const val MAXIMUM_EVIDENCE_JSON_BYTES = 64 * 1024 * 1024
private const val MAXIMUM_EVIDENCE_JSON_NODES = 1_000_000
private val evidenceOriginOrder = compareBy<RepairEvidenceOrigin>(
    { it.documentRole }, { it.locator }, { it.contentSha256 }, { it.schemaVersion ?: 0 },
)
private val evidenceUncertaintyOrder = compareBy<RepairEvidenceUncertainty>(
    { it.subject }, { it.category }, { it.reason.name }, { it.origin?.documentRole.orEmpty() },
    { it.origin?.locator.orEmpty() }, { it.origin?.contentSha256.orEmpty() }, { it.origin?.schemaVersion ?: 0 },
)

/** Stable locations in an admitted evidence document. Paths are document roles, never host paths. */
data class RepairEvidenceOrigin(
    val documentRole: String,
    val contentSha256: String,
    val schemaVersion: Int?,
    val locator: String,
) {
    init {
        require(documentRole.matches(Regex("[a-z][a-z0-9-]{0,63}")))
        require(contentSha256.matches(Regex("[0-9a-f]{64}")))
        require(schemaVersion == null || schemaVersion > 0)
        require(locator.startsWith('/') && locator.length <= 1024 && '\\' !in locator &&
            locator.split('/').drop(1).none { it == "." || it == ".." })
    }
}

enum class RepairEvidenceEntityKind { MODULE, FUNCTION, GLOBAL, TYPE }
enum class RepairEvidenceRelationKind { MODULE_OWNS, CALLS, REFERENCES_GLOBAL }
enum class RepairDiagnosticAttributionBasis {
    PROFILE_BOUND_MODULES,
    CALLER_HINT_EXACT_PATHS,
    CALLER_HINT_TOKENS,
    CALLER_HINT_UNATTRIBUTED,
    PROFILE_BEHAVIOR_ROOTS,
    NONE,
}
enum class RepairEvidenceUncertaintyReason {
    EVIDENCE_NOT_CAPTURED,
    SOURCE_LOCATION_UNAVAILABLE,
    RECOVERY_UNASSESSED,
    RELATIONSHIP_NOT_ESTABLISHED,
    AMBIGUOUS_ATTRIBUTION,
    CONTEXT_BUDGET_DEFERRED,
    INDEX_BASIS_DIFFERS_FROM_WORKING_REVISION,
}

data class RepairEntityFact(
    val id: String,
    val kind: RepairEvidenceEntityKind,
    val extractionStatus: String?,
    val origin: RepairEvidenceOrigin,
) {
    init {
        require(id.isNotBlank() && id.length <= 512)
        require(extractionStatus == null || extractionStatus in setOf("recovered", "partial", "failed", "synthetic"))
    }
}

data class RepairEntityRelation(
    val kind: RepairEvidenceRelationKind,
    val sourceEntityId: String,
    val targetEntityId: String,
    val origin: RepairEvidenceOrigin,
) {
    init {
        require(sourceEntityId.isNotBlank() && targetEntityId.isNotBlank())
    }
}

data class RepairDeclarationEvidence(
    val entityId: String,
    val form: String,
    val origin: RepairEvidenceOrigin,
) {
    init { require(entityId.isNotBlank() && form.matches(Regex("[a-z][a-z0-9_-]{0,63}"))) }
}

data class RepairDefinitionEvidence(
    val entityId: String,
    val form: String,
    val origin: RepairEvidenceOrigin,
) {
    init { require(entityId.isNotBlank() && form.matches(Regex("[a-z][a-z0-9_-]{0,63}"))) }
}

class RepairBuildEvidence(
    val artifactPath: String,
    val origin: RepairEvidenceOrigin?,
    explicitTargets: List<String> = emptyList(),
) {
    val explicitTargets: List<String> = frozenEvidenceList(explicitTargets)

    init {
        require(isPortableEvidencePath(artifactPath))
        require(explicitTargets == explicitTargets.distinct().sorted() &&
            explicitTargets.all { it.isNotBlank() && it.length <= 512 })
    }

    override fun equals(other: Any?): Boolean = other is RepairBuildEvidence &&
        artifactPath == other.artifactPath && origin == other.origin && explicitTargets == other.explicitTargets

    override fun hashCode(): Int = listOf(artifactPath, origin, explicitTargets).hashCode()
}

private fun isPortableEvidencePath(path: String): Boolean = path.isNotBlank() && path.length <= 1024 &&
    !path.startsWith('/') && !path.contains('\\') && path.split('/').all { it.isNotBlank() && it != "." && it != ".." }

data class RepairBehaviorCaseEvidence(
    val caseId: String,
    val inputSha256: String,
    val corpusSha256: String,
) {
    init {
        require(caseId.isNotBlank() && caseId.length <= 512 && inputSha256.matches(Regex("[0-9a-f]{64}")) &&
            corpusSha256.matches(Regex("[0-9a-f]{64}")))
    }
}

/** Subject-revision and attribution metadata only; the diagnostic text is never retained as authority. */
class RepairDiagnosticEvidence(
    val hintSha256: String?,
    val subjectSourceRevisionSha256: String,
    /** Source revision whose authenticated profile facts support profile-derived ownership. */
    val ownershipEvidenceSourceRevisionSha256: String?,
    val attributionBasis: RepairDiagnosticAttributionBasis,
    val ownershipEvidenceOrigin: RepairEvidenceOrigin? = null,
    selectedModuleIds: List<String>,
    matchedSourcePaths: List<String>,
    val includesSharedContext: Boolean,
) {
    val selectedModuleIds: List<String> = frozenEvidenceList(selectedModuleIds.sorted())
    val matchedSourcePaths: List<String> = frozenEvidenceList(matchedSourcePaths.sorted())

    init {
        require(hintSha256 == null || hintSha256.matches(Regex("[0-9a-f]{64}")))
        require(subjectSourceRevisionSha256.matches(Regex("[0-9a-f]{64}")))
        require(ownershipEvidenceSourceRevisionSha256 == null ||
            ownershipEvidenceSourceRevisionSha256.matches(Regex("[0-9a-f]{64}")))
        require((attributionBasis == RepairDiagnosticAttributionBasis.PROFILE_BOUND_MODULES) ==
            (ownershipEvidenceSourceRevisionSha256 != null))
        require(this.selectedModuleIds.none(String::isBlank) && this.selectedModuleIds.distinct().size == this.selectedModuleIds.size)
        require(this.matchedSourcePaths == this.matchedSourcePaths.distinct().sorted() &&
            this.matchedSourcePaths.all(::isPortableEvidencePath))
    }

    override fun equals(other: Any?): Boolean = other is RepairDiagnosticEvidence &&
        hintSha256 == other.hintSha256 && subjectSourceRevisionSha256 == other.subjectSourceRevisionSha256 &&
        ownershipEvidenceSourceRevisionSha256 == other.ownershipEvidenceSourceRevisionSha256 &&
        attributionBasis == other.attributionBasis && ownershipEvidenceOrigin == other.ownershipEvidenceOrigin &&
        selectedModuleIds == other.selectedModuleIds &&
        matchedSourcePaths == other.matchedSourcePaths && includesSharedContext == other.includesSharedContext

    override fun hashCode(): Int = listOf(
        hintSha256, subjectSourceRevisionSha256, ownershipEvidenceSourceRevisionSha256, attributionBasis,
        ownershipEvidenceOrigin, selectedModuleIds,
        matchedSourcePaths, includesSharedContext,
    ).hashCode()

    fun withSubjectSourceRevision(revisionSha256: String): RepairDiagnosticEvidence = RepairDiagnosticEvidence(
        hintSha256 = hintSha256,
        subjectSourceRevisionSha256 = revisionSha256,
        ownershipEvidenceSourceRevisionSha256 = ownershipEvidenceSourceRevisionSha256,
        attributionBasis = attributionBasis,
        ownershipEvidenceOrigin = ownershipEvidenceOrigin,
        selectedModuleIds = selectedModuleIds,
        matchedSourcePaths = matchedSourcePaths,
        includesSharedContext = includesSharedContext,
    )
}

data class RepairEvidenceUncertainty(
    val subject: String,
    val category: String,
    val reason: RepairEvidenceUncertaintyReason,
    val origin: RepairEvidenceOrigin? = null,
) {
    init {
        require(subject.isNotBlank() && subject.length <= 512)
        require(category.matches(Regex("[a-z][a-z0-9_-]{0,63}")))
    }
}

/** Immutable static evidence committed by the structural repair index. */
class RepairEvidenceFacts(
    origins: List<RepairEvidenceOrigin> = emptyList(),
    entities: List<RepairEntityFact> = emptyList(),
    relations: List<RepairEntityRelation> = emptyList(),
    declarations: List<RepairDeclarationEvidence> = emptyList(),
    definitions: List<RepairDefinitionEvidence> = emptyList(),
    buildEvidence: List<RepairBuildEvidence> = emptyList(),
    uncertainties: List<RepairEvidenceUncertainty> = emptyList(),
) {
    val origins: List<RepairEvidenceOrigin> = frozenEvidenceList(origins.sortedWith(evidenceOriginOrder))
    val entities: List<RepairEntityFact> = frozenEvidenceList(entities.sortedWith(compareBy({ it.kind.name }, { it.id })))
    val relations: List<RepairEntityRelation> = frozenEvidenceList(relations.sortedWith(compareBy(
        { it.kind.name }, { it.sourceEntityId }, { it.targetEntityId }, { it.origin.documentRole },
        { it.origin.locator }, { it.origin.contentSha256 }, { it.origin.schemaVersion ?: 0 },
    )))
    val declarations: List<RepairDeclarationEvidence> = frozenEvidenceList(declarations.sortedWith(compareBy(
        { it.entityId }, { it.form }, { it.origin.documentRole }, { it.origin.locator },
        { it.origin.contentSha256 }, { it.origin.schemaVersion ?: 0 },
    )))
    val definitions: List<RepairDefinitionEvidence> = frozenEvidenceList(definitions.sortedWith(compareBy(
        { it.entityId }, { it.form }, { it.origin.documentRole }, { it.origin.locator },
        { it.origin.contentSha256 }, { it.origin.schemaVersion ?: 0 },
    )))
    val buildEvidence: List<RepairBuildEvidence> = frozenEvidenceList(buildEvidence.sortedBy { it.artifactPath })
    val uncertainties: List<RepairEvidenceUncertainty> = frozenEvidenceList(uncertainties.distinct().sortedWith(evidenceUncertaintyOrder))

    init {
        require(this.origins.distinct().size == this.origins.size) { "repair evidence origins must be unique" }
        val originSet = this.origins.toSet()
        require((this.entities.map { it.origin } + this.relations.map { it.origin } +
            this.declarations.map { it.origin } + this.definitions.map { it.origin } +
            this.buildEvidence.mapNotNull { it.origin } + this.uncertainties.mapNotNull { it.origin })
            .all { it in originSet }) { "repair evidence references an undeclared origin" }
        require(this.entities.map { it.id }.distinct().size == this.entities.size) {
            "repair evidence entity IDs must be unique"
        }
        val entityById = this.entities.associateBy { it.id }
        val entityIds = entityById.keys
        require(this.relations.all { it.sourceEntityId in entityIds && it.targetEntityId in entityIds }) {
            "repair evidence relation references an unknown entity"
        }
        require(this.relations.all { relation ->
            val source = entityById.getValue(relation.sourceEntityId).kind
            val target = entityById.getValue(relation.targetEntityId).kind
            when (relation.kind) {
                RepairEvidenceRelationKind.MODULE_OWNS -> source == RepairEvidenceEntityKind.MODULE &&
                    target in setOf(RepairEvidenceEntityKind.FUNCTION, RepairEvidenceEntityKind.GLOBAL, RepairEvidenceEntityKind.TYPE)
                RepairEvidenceRelationKind.CALLS -> source == RepairEvidenceEntityKind.FUNCTION && target == RepairEvidenceEntityKind.FUNCTION
                RepairEvidenceRelationKind.REFERENCES_GLOBAL -> source == RepairEvidenceEntityKind.FUNCTION && target == RepairEvidenceEntityKind.GLOBAL
            }
        }) { "repair evidence relation has incompatible entity kinds" }
        require((this.declarations.map { it.entityId } + this.definitions.map { it.entityId }).all { it in entityIds }) {
            "repair declaration or definition references an unknown entity"
        }
        require(this.relations.distinct().size == this.relations.size) { "repair evidence relations must be unique" }
        require(this.declarations.distinct().size == this.declarations.size) { "repair declarations must be unique" }
        require(this.definitions.distinct().size == this.definitions.size) { "repair definitions must be unique" }
        require(this.buildEvidence.map { it.artifactPath }.distinct().size == this.buildEvidence.size) {
            "repair build evidence paths must be unique"
        }
    }

    fun canonicalBytes(maximumBytes: Long): ByteArray {
        require(maximumBytes in 1..Int.MAX_VALUE.toLong())
        val maximum = minOf(maximumBytes, MAXIMUM_EVIDENCE_JSON_BYTES.toLong()).toInt()
        return try {
            OracleJson.canonicalBytes(
                toJson(),
                StrictJsonLimits(
                    maximumInputBytes = maximum,
                    maximumCanonicalBytes = maximum,
                    maximumDepth = 32,
                    maximumNodes = MAXIMUM_EVIDENCE_JSON_NODES,
                    maximumStringBytes = maximum,
                    maximumTotalStringBytes = maximum,
                ),
            )
        } catch (failure: IllegalArgumentException) {
            throw RepairBudgetExceededException("repair evidence facts exceed $maximumBytes canonical bytes")
        }
    }

    fun sha256(maximumBytes: Long): String = MessageDigest.getInstance("SHA-256")
        .digest(canonicalBytes(maximumBytes)).joinToString("") { "%02x".format(it) }

    internal fun toJson(): JsonObject {
        fun origin(value: RepairEvidenceOrigin) = buildJsonObject {
            put("documentRole", value.documentRole)
            put("contentSha256", value.contentSha256)
            put("schemaVersion", value.schemaVersion?.let { JsonPrimitive(it) } ?: JsonNull)
            put("locator", value.locator)
        }
        fun arr(values: List<JsonObject>) = JsonArray(values)
        return buildJsonObject {
            put("schemaVersion", 1)
            put("origins", arr(origins.map(::origin)))
            put("entities", arr(entities.map { value -> buildJsonObject {
                put("id", value.id); put("kind", value.kind.name); put("extractionStatus", value.extractionStatus?.let(::JsonPrimitive) ?: JsonNull)
                put("origin", origin(value.origin))
            } }))
            put("relations", arr(relations.map { value -> buildJsonObject {
                put("kind", value.kind.name); put("sourceEntityId", value.sourceEntityId); put("targetEntityId", value.targetEntityId); put("origin", origin(value.origin))
            } }))
            put("declarations", arr(declarations.map { value -> buildJsonObject {
                put("entityId", value.entityId); put("form", value.form); put("origin", origin(value.origin))
            } }))
            put("definitions", arr(definitions.map { value -> buildJsonObject {
                put("entityId", value.entityId); put("form", value.form); put("origin", origin(value.origin))
            } }))
            put("buildEvidence", arr(buildEvidence.map { value -> buildJsonObject {
                put("artifactPath", value.artifactPath); put("origin", value.origin?.let(::origin) ?: JsonNull)
                put("explicitTargets", JsonArray(value.explicitTargets.map(::JsonPrimitive)))
            } }))
            put("uncertainties", arr(uncertainties.map { value -> buildJsonObject {
                put("subject", value.subject); put("category", value.category); put("reason", value.reason.name)
                put("origin", value.origin?.let(::origin) ?: JsonNull)
            } }))
        }
    }

    override fun equals(other: Any?): Boolean = other is RepairEvidenceFacts &&
        origins == other.origins && entities == other.entities && relations == other.relations &&
        declarations == other.declarations && definitions == other.definitions &&
        buildEvidence == other.buildEvidence && uncertainties == other.uncertainties

    override fun hashCode(): Int = listOf(origins, entities, relations, declarations, definitions, buildEvidence, uncertainties).hashCode()

    companion object { val EMPTY = RepairEvidenceFacts() }
}

/** Dynamic graph/corpus binding for the evidence shown with a selected repair context. */
class RepairEvidenceSnapshot(
    val profileId: String,
    val profileSha256: String,
    val reconstructionDescriptorSha256: String?,
    val indexSha256: String,
    val indexBasisSourceRevisionSha256: String,
    val workingRevisionSha256: String,
    val graphHeadId: String,
    val graphHeadSha256: String,
    val graphHeadStatus: String,
    val fullyAcceptedHeadId: String?,
    val fullyAcceptedHeadSha256: String?,
    val regressionCorpusSha256: String,
    val staticFacts: RepairEvidenceFacts,
    selectedEntityIds: List<String>,
    behaviorCases: List<RepairBehaviorCaseEvidence>,
    val diagnosticEvidence: RepairDiagnosticEvidence,
    omittedEntityCount: Int,
    omittedRecordCounts: Map<String, Int>,
    val diagnosticHintSha256: String?,
    val maximumCanonicalBytes: Long,
    uncertainties: List<RepairEvidenceUncertainty>,
) {
    val selectedEntityIds: List<String> = frozenEvidenceList(selectedEntityIds.sorted())
    val behaviorCases: List<RepairBehaviorCaseEvidence> = frozenEvidenceList(behaviorCases.sortedBy { it.caseId })
    val omittedEntityCount: Int = omittedEntityCount
    val omittedRecordCounts: Map<String, Int> = Collections.unmodifiableMap(TreeMap(omittedRecordCounts))
    val uncertainties: List<RepairEvidenceUncertainty> = frozenEvidenceList(uncertainties.distinct().sortedWith(evidenceUncertaintyOrder))

    init {
        val hashes = listOf(profileSha256, indexSha256, indexBasisSourceRevisionSha256, workingRevisionSha256, graphHeadSha256, regressionCorpusSha256) + listOfNotNull(fullyAcceptedHeadSha256)
        require(profileId.isNotBlank() && profileId.length <= 512 && graphHeadId.isNotBlank() && graphHeadId.length <= 512 &&
            hashes.all { it.matches(Regex("[0-9a-f]{64}")) })
        require(reconstructionDescriptorSha256 == null || reconstructionDescriptorSha256.matches(Regex("[0-9a-f]{64}")))
        require((fullyAcceptedHeadId == null) == (fullyAcceptedHeadSha256 == null))
        require(diagnosticEvidence.hintSha256 == diagnosticHintSha256 &&
            diagnosticEvidence.subjectSourceRevisionSha256 == workingRevisionSha256 &&
            (diagnosticEvidence.ownershipEvidenceSourceRevisionSha256 == null ||
                diagnosticEvidence.ownershipEvidenceSourceRevisionSha256 == indexBasisSourceRevisionSha256))
        require(graphHeadStatus in setOf("ROOT", "PROVISIONAL", "REJECTED", "ACCEPTED", "LEGACY_UNVERIFIED"))
        require(omittedEntityCount >= 0)
        require(this.omittedRecordCounts.keys == setOf(
            "entities", "relations", "declarations", "definitions", "buildEvidence", "uncertainties",
        ))
        require(this.omittedRecordCounts.values.all { it >= 0 })
        require(this.selectedEntityIds.none(String::isBlank) && this.selectedEntityIds.size == this.selectedEntityIds.distinct().size)
        require(this.behaviorCases.map { it.caseId }.distinct().size == this.behaviorCases.size)
        require(diagnosticHintSha256 == null || diagnosticHintSha256.matches(Regex("[0-9a-f]{64}")))
        require(maximumCanonicalBytes in 1..Int.MAX_VALUE.toLong())
    }

    fun canonicalBytes(maximumBytes: Long): ByteArray {
        require(maximumBytes in 1..Int.MAX_VALUE.toLong())
        val max = minOf(maximumBytes, MAXIMUM_EVIDENCE_JSON_BYTES.toLong()).toInt()
        val payload = buildJsonObject {
            put("schemaVersion", 1); put("profileId", profileId); put("profileSha256", profileSha256)
            put("reconstructionDescriptorSha256", reconstructionDescriptorSha256?.let(::JsonPrimitive) ?: JsonNull)
            put("indexSha256", indexSha256); put("indexBasisSourceRevisionSha256", indexBasisSourceRevisionSha256)
            put("workingRevisionSha256", workingRevisionSha256); put("graphHeadId", graphHeadId)
            put("graphHeadSha256", graphHeadSha256); put("graphHeadStatus", graphHeadStatus)
            put("fullyAcceptedHeadId", fullyAcceptedHeadId?.let(::JsonPrimitive) ?: JsonNull)
            put("fullyAcceptedHeadSha256", fullyAcceptedHeadSha256?.let(::JsonPrimitive) ?: JsonNull)
            put("regressionCorpusSha256", regressionCorpusSha256)
            put("staticEvidence", staticFacts.toJson())
            put("selectedEntityIds", JsonArray(selectedEntityIds.map(::JsonPrimitive)))
            put("behaviorCases", JsonArray(behaviorCases.map { value -> buildJsonObject {
                put("caseId", value.caseId); put("inputSha256", value.inputSha256); put("corpusSha256", value.corpusSha256)
            } }))
            put("diagnosticEvidence", buildJsonObject {
                put("hintSha256", diagnosticEvidence.hintSha256?.let(::JsonPrimitive) ?: JsonNull)
                put("subjectSourceRevisionSha256", diagnosticEvidence.subjectSourceRevisionSha256)
                put("ownershipEvidenceSourceRevisionSha256", diagnosticEvidence.ownershipEvidenceSourceRevisionSha256?.let(::JsonPrimitive) ?: JsonNull)
                put("ownershipEvidenceOrigin", diagnosticEvidence.ownershipEvidenceOrigin?.let { origin -> buildJsonObject {
                    put("documentRole", origin.documentRole); put("contentSha256", origin.contentSha256)
                    put("schemaVersion", origin.schemaVersion?.let(::JsonPrimitive) ?: JsonNull); put("locator", origin.locator)
                } } ?: JsonNull)
                put("attributionBasis", diagnosticEvidence.attributionBasis.name)
                put("selectedModuleIds", JsonArray(diagnosticEvidence.selectedModuleIds.map(::JsonPrimitive)))
                put("matchedSourcePaths", JsonArray(diagnosticEvidence.matchedSourcePaths.map(::JsonPrimitive)))
                put("includesSharedContext", diagnosticEvidence.includesSharedContext)
            })
            put("omittedEntityCount", omittedEntityCount)
            put("omittedRecordCounts", buildJsonObject {
                omittedRecordCounts.forEach { (kind, count) -> put(kind, count) }
            })
            put("diagnosticHintSha256", diagnosticHintSha256?.let(::JsonPrimitive) ?: JsonNull)
            put("uncertainties", JsonArray(uncertainties.map { uncertainty ->
                buildJsonObject {
                    put("subject", uncertainty.subject); put("category", uncertainty.category); put("reason", uncertainty.reason.name)
                    put("origin", uncertainty.origin?.let { origin -> buildJsonObject {
                        put("documentRole", origin.documentRole); put("contentSha256", origin.contentSha256)
                        put("schemaVersion", origin.schemaVersion?.let(::JsonPrimitive) ?: JsonNull)
                        put("locator", origin.locator)
                    } } ?: kotlinx.serialization.json.JsonNull)
                }
            }))
        }
        return try {
            OracleJson.canonicalBytes(payload, StrictJsonLimits(
                maximumInputBytes = max, maximumCanonicalBytes = max, maximumDepth = 32,
                maximumNodes = MAXIMUM_EVIDENCE_JSON_NODES, maximumStringBytes = max, maximumTotalStringBytes = max,
            ))
        } catch (failure: IllegalArgumentException) {
            throw RepairBudgetExceededException("repair evidence snapshot exceeds $maximumBytes canonical bytes")
        }
    }

    fun sha256(maximumBytes: Long): String = MessageDigest.getInstance("SHA-256")
        .digest(canonicalBytes(maximumBytes)).joinToString("") { "%02x".format(it) }
}
