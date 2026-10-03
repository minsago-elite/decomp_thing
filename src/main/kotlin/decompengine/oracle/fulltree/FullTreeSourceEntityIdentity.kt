package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.charset.StandardCharsets
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Separate source census kinds. RVA links in this census never add denominator rows. */
internal enum class FullTreeSourceEntityKind(val wireValue: String) {
    DECLARATION_ONLY("declaration-only"),
    NO_RANGE_DEFINITION("no-range-definition"),
    TEMPLATE_PATTERN("template-pattern"),
    TEMPLATE_INSTANCE("template-instance"),
    INLINE_INSTANCE("inline-instance"),
    UNRESOLVED("unresolved"),
}

/** Anchor roles also include related definitions that are not rows in the source census. */
internal enum class FullTreeSourceAnchorKind(val wireValue: String) {
    DECLARATION_ONLY("declaration-only"),
    NO_RANGE_DEFINITION("no-range-definition"),
    TEMPLATE_PATTERN("template-pattern"),
    TEMPLATE_INSTANCE("template-instance"),
    INLINE_INSTANCE("inline-instance"),
    SOURCE_DEFINITION("source-definition"),
}

internal fun FullTreeSourceEntityKind.anchorKind(): FullTreeSourceAnchorKind? = when (this) {
    FullTreeSourceEntityKind.DECLARATION_ONLY -> FullTreeSourceAnchorKind.DECLARATION_ONLY
    FullTreeSourceEntityKind.NO_RANGE_DEFINITION -> FullTreeSourceAnchorKind.NO_RANGE_DEFINITION
    FullTreeSourceEntityKind.TEMPLATE_PATTERN -> FullTreeSourceAnchorKind.TEMPLATE_PATTERN
    FullTreeSourceEntityKind.TEMPLATE_INSTANCE -> FullTreeSourceAnchorKind.TEMPLATE_INSTANCE
    FullTreeSourceEntityKind.INLINE_INSTANCE -> FullTreeSourceAnchorKind.INLINE_INSTANCE
    FullTreeSourceEntityKind.UNRESOLVED -> null
}

internal enum class FullTreeIdentityObservability(val wireValue: String) {
    OBSERVABLE("observable"),
    UNOBSERVABLE("unobservable"),
    UNKNOWN("unknown"),
    AMBIGUOUS("ambiguous"),
}

internal enum class FullTreeDenominatorDisposition(val wireValue: String) {
    NON_SCOREABLE("non-scoreable"),
    EMITTED_RVA_LINK("emitted-rva-link"),
    UNKNOWN("unknown"),
    AMBIGUOUS("ambiguous"),
}

internal enum class FullTreeSourceIdentityEdgeKind(val wireValue: String) {
    SPECIFICATION("specification"),
    ABSTRACT_ORIGIN("abstract-origin"),
    TYPE("type"),
    TEMPLATE_FORMAL("template-formal"),
    TEMPLATE_ARGUMENT("template-argument"),
    INLINE_OWNER("inline-owner"),
}

internal enum class FullTreeSourceIdentityEdgeState(val wireValue: String) {
    RESOLVED("resolved"),
    MISSING_TARGET("missing-target"),
    MALFORMED("malformed"),
    UNSUPPORTED("unsupported"),
    CYCLIC("cyclic"),
    OVER_BOUND("over-bound"),
}

/** Artifact-local physical address of one retained DWARF DIE. */
internal data class FullTreeSourcePhysicalDie(
    val richArtifactSha256: String,
    val unitId: String,
    val section: String,
    val compilationUnitOffset: String,
    val dieOffset: String,
) {
    init {
        require(richArtifactSha256.matches(Regex("[0-9a-f]{64}")))
        require(unitId.matches(Regex("cu-[0-9a-f]{32}")))
        require(section == ".debug_info")
        require(compilationUnitOffset.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]*)")))
        require(dieOffset.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]*)")))
    }

    fun locator(): String = "$richArtifactSha256:.debug_info:unit=$unitId:cu=$compilationUnitOffset:die=$dieOffset"

    /** Physical census identity. It intentionally binds bytes and artifact-local inventory location. */
    fun sourceEntityId(kind: FullTreeSourceEntityKind): String = sourceEntityId(kind.wireValue)

    fun sourceEntityId(kind: FullTreeSourceAnchorKind): String = sourceEntityId(kind.wireValue)

    private fun sourceEntityId(kind: String): String {
        val preimage = JsonObject(
            mapOf(
                "compilationUnitOffset" to JsonPrimitive(compilationUnitOffset),
                "dieOffset" to JsonPrimitive(dieOffset),
                "entityKind" to JsonPrimitive(kind),
                "richArtifactSha256" to JsonPrimitive(richArtifactSha256),
                "section" to JsonPrimitive(section),
                "unitId" to JsonPrimitive(unitId),
                "version" to JsonPrimitive(1),
            ),
        )
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update(SOURCE_ENTITY_DOMAIN)
        digest.update(OracleJson.canonicalBytes(preimage))
        return digest.digest().joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
    }
}

/** Raw, typed reference evidence. An unresolved target is deliberately represented, never guessed. */
internal data class FullTreeSourceIdentityEdge(
    val kind: FullTreeSourceIdentityEdgeKind,
    val source: FullTreeSourcePhysicalDie,
    val target: FullTreeSourcePhysicalDie?,
    val referenceForm: String?,
    val rawReference: String?,
    val state: FullTreeSourceIdentityEdgeState,
    val reasonCode: String?,
) {
    init {
        require((state == FullTreeSourceIdentityEdgeState.RESOLVED) == (target != null))
        require(reasonCode == null || reasonCode.matches(REASON_CODE))
        if (state == FullTreeSourceIdentityEdgeState.RESOLVED) require(reasonCode == null)
        if (referenceForm != null) require(referenceForm.matches(Regex("0x[0-9a-f]+")))
        if (rawReference != null) require(rawReference.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]*)")))
    }

    fun canonicalJson(): JsonObject = JsonObject(
        mapOf(
            "kind" to JsonPrimitive(kind.wireValue),
            "rawReference" to (rawReference?.let(::JsonPrimitive) ?: JsonNull),
            "reasonCode" to (reasonCode?.let(::JsonPrimitive) ?: JsonNull),
            "referenceForm" to (referenceForm?.let(::JsonPrimitive) ?: JsonNull),
            "source" to JsonPrimitive(source.locator()),
            "state" to JsonPrimitive(state.wireValue),
            "target" to (target?.let { JsonPrimitive(it.locator()) } ?: JsonNull),
        ),
    )
}

/** Source-aligned tuple used to derive a semantic ID; compiler DIE offsets are excluded. */
internal data class FullTreeSourceAnchorFields(
    val sourcePath: String?,
    val declarationFileIndex: Long?,
    val declarationLine: Long?,
    val declarationColumn: Long?,
    val language: Long?,
    val lexicalContext: List<String>,
    val sourceName: String?,
    val signature: List<String>?,
    val templateFormalParameters: List<String>? = null,
    val templatePatternAnchorCandidateId: String? = null,
    val templateActualArguments: List<String>? = null,
    val inlineCalleeAnchorCandidateId: String? = null,
    val inlineOwnerAnchorCandidateId: String? = null,
    val inlineCallFile: String? = null,
    val inlineCallLine: Long? = null,
    val inlineCallColumn: Long? = null,
    val inlinePathAnchorCandidateIds: List<String>? = null,
    val authenticatedSourceRevision: String? = null,
    val authenticatedSourceFileSha256: String? = null,
) {
    init {
        require(sourcePath == null || isNormalizedSourcePath(sourcePath))
        require(declarationFileIndex == null || declarationFileIndex >= 0L)
        require(declarationLine == null || declarationLine > 0L)
        require(declarationColumn == null || declarationColumn >= 0L)
        require(language == null || language >= 0L)
        require(inlineCallLine == null || inlineCallLine > 0L)
        require(inlineCallColumn == null || inlineCallColumn >= 0L)
        require(authenticatedSourceFileSha256 == null || authenticatedSourceFileSha256.matches(Regex("[0-9a-f]{64}")))
        listOfNotNull(
            sourceName,
            authenticatedSourceRevision,
            templatePatternAnchorCandidateId,
            inlineCalleeAnchorCandidateId,
            inlineOwnerAnchorCandidateId,
            inlineCallFile,
        ).forEach { require(it.isNotEmpty()) }
        require(templatePatternAnchorCandidateId == null || templatePatternAnchorCandidateId.matches(Regex("[0-9a-f]{64}")))
        require(inlineCalleeAnchorCandidateId == null || inlineCalleeAnchorCandidateId.matches(Regex("[0-9a-f]{64}")))
        require(inlineOwnerAnchorCandidateId == null || inlineOwnerAnchorCandidateId.matches(Regex("[0-9a-f]{64}")))
        require(lexicalContext.none(String::isEmpty))
        require(signature?.any(String::isEmpty) != true)
        require(templateFormalParameters?.any(String::isEmpty) != true)
        require(templateActualArguments?.any(String::isEmpty) != true)
        require(inlinePathAnchorCandidateIds?.any(String::isEmpty) != true)
        inlinePathAnchorCandidateIds?.forEach { require(it.matches(Regex("[0-9a-f]{64}"))) }
    }

    fun canonicalJson(): JsonObject = JsonObject(
        mapOf(
            "authenticatedSourceFileSha256" to (authenticatedSourceFileSha256?.let(::JsonPrimitive) ?: JsonNull),
            "authenticatedSourceRevision" to (authenticatedSourceRevision?.let(::JsonPrimitive) ?: JsonNull),
            "declarationColumn" to (declarationColumn?.let(::JsonPrimitive) ?: JsonNull),
            "declarationFileIndex" to (declarationFileIndex?.let(::JsonPrimitive) ?: JsonNull),
            "declarationLine" to (declarationLine?.let(::JsonPrimitive) ?: JsonNull),
            "inlineCallColumn" to (inlineCallColumn?.let(::JsonPrimitive) ?: JsonNull),
            "inlineCallFile" to (inlineCallFile?.let(::JsonPrimitive) ?: JsonNull),
            "inlineCallLine" to (inlineCallLine?.let(::JsonPrimitive) ?: JsonNull),
            "inlineCalleeAnchorCandidateId" to (inlineCalleeAnchorCandidateId?.let(::JsonPrimitive) ?: JsonNull),
            "inlineOwnerAnchorCandidateId" to (inlineOwnerAnchorCandidateId?.let(::JsonPrimitive) ?: JsonNull),
            "inlinePathAnchorCandidateIds" to
                (inlinePathAnchorCandidateIds?.let { JsonArray(it.map(::JsonPrimitive)) } ?: JsonNull),
            "language" to (language?.let(::JsonPrimitive) ?: JsonNull),
            "lexicalContext" to JsonArray(lexicalContext.map(::JsonPrimitive)),
            "signature" to (signature?.let { JsonArray(it.map(::JsonPrimitive)) } ?: JsonNull),
            "sourceName" to (sourceName?.let(::JsonPrimitive) ?: JsonNull),
            "sourcePath" to (sourcePath?.let(::JsonPrimitive) ?: JsonNull),
            "templateActualArguments" to
                (templateActualArguments?.let { JsonArray(it.map(::JsonPrimitive)) } ?: JsonNull),
            "templateFormalParameters" to
                (templateFormalParameters?.let { JsonArray(it.map(::JsonPrimitive)) } ?: JsonNull),
            "templatePatternAnchorCandidateId" to (templatePatternAnchorCandidateId?.let(::JsonPrimitive) ?: JsonNull),
        ),
    )

    fun isComplete(kind: FullTreeSourceAnchorKind): Boolean =
        sourcePath != null && declarationLine != null && language != null &&
            sourceName != null && signature != null &&
            when (kind) {
                FullTreeSourceAnchorKind.TEMPLATE_PATTERN -> templateFormalParameters != null
                FullTreeSourceAnchorKind.TEMPLATE_INSTANCE ->
                    templatePatternAnchorCandidateId != null && templateActualArguments != null
                FullTreeSourceAnchorKind.INLINE_INSTANCE ->
                    inlineCalleeAnchorCandidateId != null && inlineOwnerAnchorCandidateId != null &&
                        inlineCallFile != null && inlineCallLine != null && inlinePathAnchorCandidateIds != null
                FullTreeSourceAnchorKind.SOURCE_DEFINITION,
                FullTreeSourceAnchorKind.DECLARATION_ONLY,
                FullTreeSourceAnchorKind.NO_RANGE_DEFINITION,
                -> true
            }

    fun candidateId(kind: FullTreeSourceAnchorKind): String? {
        if (!isComplete(kind)) return null
        // declarationFileIndex preserves the raw DW_AT_decl_file line-table index in the fact. That
        // index is compiler-local; sourcePath is its authenticated, normalized source identity.
        val semanticFields = JsonObject(canonicalJson().toMutableMap().apply { remove("declarationFileIndex") })
        val preimage = JsonObject(
            mapOf(
                "fields" to semanticFields,
                "kind" to JsonPrimitive(kind.wireValue),
                "version" to JsonPrimitive(1),
            ),
        )
        val bytes = OracleJson.canonicalBytes(preimage)
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update(ANCHOR_DOMAIN)
        digest.update(bytes)
        return digest.digest().joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
    }

    fun candidateId(kind: FullTreeSourceEntityKind): String? = kind.anchorKind()?.let(::candidateId)
}

/** One source-entity observation; it never is an emitted-function score row. */
internal data class FullTreeSourceEntityFact(
    val sourceEntityId: String,
    val physicalDie: FullTreeSourcePhysicalDie,
    val kind: FullTreeSourceEntityKind,
    val identityObservability: FullTreeIdentityObservability,
    val denominatorDisposition: FullTreeDenominatorDisposition,
    val semanticAnchorFields: FullTreeSourceAnchorFields?,
    val semanticAnchorCandidateId: String?,
    val resolvedSemanticIdentityId: String?,
    val candidateCollisionSourceEntityIds: List<String>,
    val linkedEmittedRva: String?,
    val reasonCodes: List<String>,
    val edges: List<FullTreeSourceIdentityEdge>,
) {
    init {
        require(linkedEmittedRva == null || linkedEmittedRva.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")))
        require((denominatorDisposition == FullTreeDenominatorDisposition.EMITTED_RVA_LINK) ==
            (linkedEmittedRva != null))
        require(reasonCodes == reasonCodes.distinct().sorted())
        reasonCodes.forEach { require(it.matches(REASON_CODE)) }
        require(edges.size <= MAXIMUM_IDENTITY_EDGES_PER_ENTITY)
        require(sourceEntityId.matches(Regex("[0-9a-f]{64}")))
        require(sourceEntityId == physicalDie.sourceEntityId(kind))
        require(resolvedSemanticIdentityId == null || resolvedSemanticIdentityId.matches(Regex("[0-9a-f]{64}")))
        // This extractor records candidates and raw relation evidence only; it has no validated
        // cross-build semantic-resolution rule that can populate a resolved identity.
        require(resolvedSemanticIdentityId == null)
        require(candidateCollisionSourceEntityIds == candidateCollisionSourceEntityIds.distinct().sorted())
        candidateCollisionSourceEntityIds.forEach { require(it.matches(Regex("[0-9a-f]{64}"))) }
        val expectedAnchor = kind.anchorKind()?.let { semanticAnchorFields?.candidateId(it) }
        if (identityObservability == FullTreeIdentityObservability.OBSERVABLE) {
            require(semanticAnchorCandidateId != null && semanticAnchorCandidateId == expectedAnchor)
        }
        if (semanticAnchorCandidateId != null) {
            require(semanticAnchorCandidateId.matches(Regex("[0-9a-f]{64}")))
            require(expectedAnchor == semanticAnchorCandidateId)
        }
        if (kind == FullTreeSourceEntityKind.INLINE_INSTANCE) {
            require(denominatorDisposition != FullTreeDenominatorDisposition.EMITTED_RVA_LINK)
            require(linkedEmittedRva == null)
        }
        if (kind == FullTreeSourceEntityKind.DECLARATION_ONLY || kind == FullTreeSourceEntityKind.NO_RANGE_DEFINITION ||
            kind == FullTreeSourceEntityKind.TEMPLATE_PATTERN
        ) {
            require(denominatorDisposition == FullTreeDenominatorDisposition.NON_SCOREABLE)
            require(linkedEmittedRva == null)
        }
    }

    fun canonicalJson(): JsonObject = JsonObject(
        mapOf(
            "denominatorDisposition" to JsonPrimitive(denominatorDisposition.wireValue),
            "edges" to JsonArray(edges.sortedWith(SOURCE_EDGE_ORDER).map(FullTreeSourceIdentityEdge::canonicalJson)),
            "entityKind" to JsonPrimitive(kind.wireValue),
            "identityObservability" to JsonPrimitive(identityObservability.wireValue),
            "linkedEmittedRva" to (linkedEmittedRva?.let(::JsonPrimitive) ?: JsonNull),
            "physicalDie" to JsonObject(
                mapOf(
                    "compilationUnitOffset" to JsonPrimitive(physicalDie.compilationUnitOffset),
                    "dieOffset" to JsonPrimitive(physicalDie.dieOffset),
                    "locator" to JsonPrimitive(physicalDie.locator()),
                    "richArtifactSha256" to JsonPrimitive(physicalDie.richArtifactSha256),
                    "section" to JsonPrimitive(physicalDie.section),
                    "unitId" to JsonPrimitive(physicalDie.unitId),
                ),
            ),
            "reasonCodes" to JsonArray(reasonCodes.map(::JsonPrimitive)),
            "sourceEntityId" to JsonPrimitive(sourceEntityId),
            "semanticAnchorFields" to (semanticAnchorFields?.canonicalJson() ?: JsonNull),
            "semanticAnchorCandidateId" to (semanticAnchorCandidateId?.let(::JsonPrimitive) ?: JsonNull),
            "resolvedSemanticIdentityId" to (resolvedSemanticIdentityId?.let(::JsonPrimitive) ?: JsonNull),
            "candidateCollisionSourceEntityIds" to JsonArray(candidateCollisionSourceEntityIds.map(::JsonPrimitive)),
        ),
    )

    companion object {
        fun deterministicOrder(facts: Iterable<FullTreeSourceEntityFact>): List<FullTreeSourceEntityFact> =
            facts.sortedWith(
                compareBy<FullTreeSourceEntityFact> { it.kind.wireValue }
                    .thenBy { it.semanticAnchorCandidateId ?: "~" }
                    .thenBy { it.physicalDie.unitId }
                    .thenBy { it.physicalDie.compilationUnitOffset }
                    .thenBy { it.physicalDie.dieOffset },
            )
    }
}

/** Canonical bytes for test evidence and later observation-v2 sinks. */
internal fun canonicalSourceEntityFacts(facts: Iterable<FullTreeSourceEntityFact>): ByteArray =
    FullTreeSourceEntityFact.deterministicOrder(facts).let { ordered ->
        require(ordered.map { it.sourceEntityId }.distinct().size == ordered.size) {
            "source-identity census repeats a physical sourceEntityId"
        }
        OracleJson.canonicalBytes(JsonArray(ordered.map { it.canonicalJson() }))
    }

internal fun sourceIdentitySha256(bytes: ByteArray): String = OracleArtifacts.sha256(bytes)

internal const val MAXIMUM_IDENTITY_EDGES_PER_ENTITY = 32

private val ANCHOR_DOMAIN = "decomp-thing:full-tree-source-anchor-v1\u0000".toByteArray(StandardCharsets.UTF_8)
private val SOURCE_ENTITY_DOMAIN = "decomp-thing:full-tree-source-entity-v1\u0000".toByteArray(StandardCharsets.UTF_8)
private val REASON_CODE = Regex("[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
private val SOURCE_EDGE_ORDER = compareBy<FullTreeSourceIdentityEdge> { it.kind.wireValue }
    .thenBy { it.source.locator() }
    .thenBy { it.target?.locator() ?: "~" }
    .thenBy { it.state.wireValue }
    .thenBy { it.rawReference ?: "~" }

private fun isNormalizedSourcePath(value: String): Boolean =
    value.isNotEmpty() && !value.startsWith('/') && '\\' !in value && '\u0000' !in value &&
        value.split('/').none { it.isEmpty() || it == "." || it == ".." }
