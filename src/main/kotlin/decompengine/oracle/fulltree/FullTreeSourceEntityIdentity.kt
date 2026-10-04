package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

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
}

/**
 * Returns a rendered function-template base only when its trailing template-id parses and its
 * top-level argument count agrees with the validated typed-actual DIEs. The spelling is not used
 * to resolve a relation; typed descriptors carry the specialization's semantic arguments.
 */
internal fun canonicalSourceIdentityTemplateInstanceBaseName(
    sourceName: String,
    typedActualCount: Int,
): String? {
    val name = sourceName.trim()
    if (!name.endsWith('>') || typedActualCount <= 0) return null
    // A malformed name can contain many candidate '<' characters. Cap aggregate parsing work so
    // this bounded string decoder cannot become quadratic on hostile DWARF input.
    val maximumParseSteps = name.length * 64
    var parseSteps = 0
    for (open in name.lastIndex downTo 1) {
        if (name[open] != '<') continue
        var angleDepth = 1
        var parenDepth = 0
        var bracketDepth = 0
        var braceDepth = 0
        var quote: Char? = null
        var escaped = false
        var argumentCount = 1
        var argumentHasContent = false
        var valid = true
        var close = -1
        var index = open + 1
        while (index < name.length) {
            if (++parseSteps > maximumParseSteps) return null
            val char = name[index]
            if (quote != null) {
                if (escaped) escaped = false
                else if (char == '\\') escaped = true
                else if (char == quote) quote = null
                argumentHasContent = true
                index++
                continue
            }
            when (char) {
                '\'', '"' -> {
                    quote = char
                    argumentHasContent = true
                }
                '(' -> {
                    parenDepth++
                    argumentHasContent = true
                }
                ')' -> {
                    if (parenDepth == 0) valid = false else parenDepth--
                    argumentHasContent = true
                }
                '[' -> {
                    bracketDepth++
                    argumentHasContent = true
                }
                ']' -> {
                    if (bracketDepth == 0) valid = false else bracketDepth--
                    argumentHasContent = true
                }
                '{' -> {
                    braceDepth++
                    argumentHasContent = true
                }
                '}' -> {
                    if (braceDepth == 0) valid = false else braceDepth--
                    argumentHasContent = true
                }
                '<' -> {
                    if (parenDepth == 0 && bracketDepth == 0 && braceDepth == 0) angleDepth++
                    argumentHasContent = true
                }
                '>' -> if (parenDepth == 0 && bracketDepth == 0 && braceDepth == 0) {
                    angleDepth--
                    if (angleDepth < 0) valid = false
                    if (angleDepth == 0) {
                        close = index
                        break
                    }
                    argumentHasContent = true
                } else {
                    argumentHasContent = true
                }
                ',' -> if (angleDepth == 1 && parenDepth == 0 && bracketDepth == 0 && braceDepth == 0) {
                    if (!argumentHasContent) valid = false
                    argumentCount++
                    argumentHasContent = false
                } else {
                    argumentHasContent = true
                }
                else -> if (!char.isWhitespace()) argumentHasContent = true
            }
            if (!valid) break
            index++
        }
        if (!valid || quote != null || parenDepth != 0 || bracketDepth != 0 || braceDepth != 0) continue
        if (close != name.lastIndex || angleDepth != 0 || !argumentHasContent || argumentCount != typedActualCount) continue
        val base = name.substring(0, open).trimEnd()
        if (base.isNotEmpty()) return base
    }
    return null
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
internal class FullTreeSourceAnchorFields(
    val sourcePath: String?,
    val declarationFileIndex: Long?,
    val declarationLine: Long?,
    val declarationColumn: Long?,
    val language: Long?,
    lexicalContext: List<String>,
    val sourceName: String?,
    signature: List<String>?,
    templateFormalParameters: List<String>? = null,
    val templatePatternAnchorCandidateId: String? = null,
    templateActualArguments: List<String>? = null,
    val inlineCalleeAnchorCandidateId: String? = null,
    val inlineOwnerAnchorCandidateId: String? = null,
    val inlineCallFile: String? = null,
    val inlineCallLine: Long? = null,
    val inlineCallColumn: Long? = null,
    inlinePathAnchorCandidateIds: List<String>? = null,
    val authenticatedSourceRevision: String? = null,
    val authenticatedSourceFileSha256: String? = null,
) {
    val lexicalContext: List<String> = immutableSourceList(lexicalContext)
    val signature: List<String>? = signature?.let(::immutableSourceList)
    val templateFormalParameters: List<String>? = templateFormalParameters?.let(::immutableSourceList)
    val templateActualArguments: List<String>? = templateActualArguments?.let(::immutableSourceList)
    val inlinePathAnchorCandidateIds: List<String>? = inlinePathAnchorCandidateIds?.let(::immutableSourceList)

    init {
        require(sourcePath == null || isNormalizedSourcePath(sourcePath))
        require(declarationFileIndex == null || declarationFileIndex >= 0L)
        require(declarationLine == null || declarationLine > 0L)
        require(declarationColumn == null || declarationColumn >= 0L)
        require(language == null || language >= 0L)
        require(inlineCallLine == null || inlineCallLine > 0L)
        require(inlineCallColumn == null || inlineCallColumn >= 0L)
        require(inlineCallFile == null || isNormalizedSourcePath(inlineCallFile))
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
                    templateActualArguments != null
                FullTreeSourceAnchorKind.INLINE_INSTANCE ->
                    inlineCalleeAnchorCandidateId != null && inlineOwnerAnchorCandidateId != null &&
                        inlineCallFile != null && inlineCallLine != null && inlineCallColumn != null &&
                        inlinePathAnchorCandidateIds != null
                FullTreeSourceAnchorKind.SOURCE_DEFINITION,
                FullTreeSourceAnchorKind.DECLARATION_ONLY,
                FullTreeSourceAnchorKind.NO_RANGE_DEFINITION,
                -> true
            }

    fun candidateId(kind: FullTreeSourceAnchorKind): String? {
        if (!isComplete(kind)) return null
        // declarationFileIndex preserves the raw DW_AT_decl_file line-table index in the fact. That
        // index is compiler-local; sourcePath is its authenticated, normalized source identity.
        val semanticFields = JsonObject(canonicalJson().toMutableMap().apply {
            // The line-table file index is artifact-local. The column is retained as raw fact
            // evidence, but some compilers omit it for the same declaration, so it is not part of
            // the cross-compiler semantic tuple. Inline call columns are retained in the semantic
            // tuple because distinct calls on one source line need that discriminator; an absent
            // call column leaves the inline candidate unknown rather than merging those calls.
            remove("declarationFileIndex")
            remove("declarationColumn")
            // A concrete instance candidate describes its own complete source tuple and typed
            // actuals. A missing or later-proven pattern relation must not alter that candidate.
            if (kind == FullTreeSourceAnchorKind.TEMPLATE_INSTANCE) {
                remove("templatePatternAnchorCandidateId")
                val rawName = (get("sourceName") as? JsonPrimitive)?.content ?: return null
                val actualCount = templateActualArguments?.size ?: return null
                val baseName = canonicalSourceIdentityTemplateInstanceBaseName(rawName, actualCount) ?: return null
                this["sourceName"] = JsonPrimitive(baseName)
            }
        })
        val preimage = JsonObject(
            mapOf(
                "fields" to semanticFields,
                "kind" to JsonPrimitive(kind.wireValue),
                "version" to JsonPrimitive(6),
            ),
        )
        val bytes = OracleJson.canonicalBytes(preimage, sourceIdentityRowJsonLimits(MAXIMUM_SOURCE_IDENTITY_ROW_BYTES))
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update(ANCHOR_DOMAIN)
        digest.update(bytes)
        return digest.digest().joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
    }

    fun candidateId(kind: FullTreeSourceEntityKind): String? = kind.anchorKind()?.let(::candidateId)

    override fun equals(other: Any?): Boolean = other is FullTreeSourceAnchorFields && canonicalJson() == other.canonicalJson()

    override fun hashCode(): Int = canonicalJson().hashCode()
}

/** One source-entity observation; it never is an emitted-function score row. */
internal class FullTreeSourceEntityFact(
    val sourceEntityId: String,
    val physicalDie: FullTreeSourcePhysicalDie,
    val kind: FullTreeSourceEntityKind,
    val identityObservability: FullTreeIdentityObservability,
    val denominatorDisposition: FullTreeDenominatorDisposition,
    val semanticAnchorFields: FullTreeSourceAnchorFields?,
    val semanticAnchorCandidateId: String?,
    val resolvedSemanticIdentityId: String?,
    candidateCollisionSourceEntityIds: List<String>,
    val linkedEmittedRva: String?,
    reasonCodes: List<String>,
    edges: List<FullTreeSourceIdentityEdge>,
) {
    val candidateCollisionSourceEntityIds: List<String> = immutableSourceList(candidateCollisionSourceEntityIds)
    val reasonCodes: List<String> = immutableSourceList(reasonCodes)
    val edges: List<FullTreeSourceIdentityEdge> = immutableSourceList(edges)

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

    fun copy(
        sourceEntityId: String = this.sourceEntityId,
        physicalDie: FullTreeSourcePhysicalDie = this.physicalDie,
        kind: FullTreeSourceEntityKind = this.kind,
        identityObservability: FullTreeIdentityObservability = this.identityObservability,
        denominatorDisposition: FullTreeDenominatorDisposition = this.denominatorDisposition,
        semanticAnchorFields: FullTreeSourceAnchorFields? = this.semanticAnchorFields,
        semanticAnchorCandidateId: String? = this.semanticAnchorCandidateId,
        resolvedSemanticIdentityId: String? = this.resolvedSemanticIdentityId,
        candidateCollisionSourceEntityIds: List<String> = this.candidateCollisionSourceEntityIds,
        linkedEmittedRva: String? = this.linkedEmittedRva,
        reasonCodes: List<String> = this.reasonCodes,
        edges: List<FullTreeSourceIdentityEdge> = this.edges,
    ): FullTreeSourceEntityFact = FullTreeSourceEntityFact(
        sourceEntityId, physicalDie, kind, identityObservability, denominatorDisposition,
        semanticAnchorFields, semanticAnchorCandidateId, resolvedSemanticIdentityId,
        candidateCollisionSourceEntityIds, linkedEmittedRva, reasonCodes, edges,
    )

    companion object {
        /** Strictly decodes the new observation-v2 source row and rechecks every derived ID. */
        fun fromCanonicalJson(value: JsonObject, label: String = "source entity"): FullTreeSourceEntityFact {
            fun fail(detail: String): Nothing = throw FullTreeFunctionObservationV2Exception("$label $detail")
            fun obj(element: JsonElement?, name: String): JsonObject = element as? JsonObject ?: fail("$name is not an object")
            fun str(element: JsonElement?, name: String): String =
                (element as? JsonPrimitive)?.takeIf { it.isString }?.content ?: fail("$name is not a string")
            fun nullableString(element: JsonElement?, name: String): String? = when (element) {
                JsonNull -> null
                is JsonPrimitive -> if (element.isString) element.content else fail("$name is not a string or null")
                else -> fail("$name is not a string or null")
            }
            fun long(element: JsonElement?, name: String): Long =
                (element as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull ?: fail("$name is not an integer")
            fun nullableLong(element: JsonElement?, name: String): Long? =
                if (element == JsonNull) null else long(element, name)
            fun array(element: JsonElement?, name: String): JsonArray = element as? JsonArray ?: fail("$name is not an array")
            fun nullableStringList(element: JsonElement?, name: String): List<String>? = when (element) {
                JsonNull -> null
                is JsonArray -> element.mapIndexed { index, item -> str(item, "$name[$index]") }
                else -> fail("$name is not an array or null")
            }
            fun stringList(element: JsonElement?, name: String): List<String> =
                array(element, name).mapIndexed { index, item -> str(item, "$name[$index]") }
            fun <T> enumValue(values: Array<T>, wire: String, wireValue: (T) -> String, name: String): T =
                values.singleOrNull { wireValue(it) == wire } ?: fail("$name has an unknown enum value")
            fun physical(document: JsonObject, name: String): FullTreeSourcePhysicalDie {
                val die = FullTreeSourcePhysicalDie(
                    richArtifactSha256 = str(document["richArtifactSha256"], "$name.richArtifactSha256"),
                    unitId = str(document["unitId"], "$name.unitId"),
                    section = str(document["section"], "$name.section"),
                    compilationUnitOffset = str(document["compilationUnitOffset"], "$name.compilationUnitOffset"),
                    dieOffset = str(document["dieOffset"], "$name.dieOffset"),
                )
                if (str(document["locator"], "$name.locator") != die.locator()) fail("$name locator differs from its fields")
                return die
            }
            fun nullableFields(element: JsonElement?): FullTreeSourceAnchorFields? {
                if (element == JsonNull) return null
                val fields = obj(element, "semanticAnchorFields")
                return FullTreeSourceAnchorFields(
                    sourcePath = nullableString(fields["sourcePath"], "sourcePath"),
                    declarationFileIndex = nullableLong(fields["declarationFileIndex"], "declarationFileIndex"),
                    declarationLine = nullableLong(fields["declarationLine"], "declarationLine"),
                    declarationColumn = nullableLong(fields["declarationColumn"], "declarationColumn"),
                    language = nullableLong(fields["language"], "language"),
                    lexicalContext = stringList(fields["lexicalContext"], "lexicalContext"),
                    sourceName = nullableString(fields["sourceName"], "sourceName"),
                    signature = nullableStringList(fields["signature"], "signature"),
                    templateFormalParameters = nullableStringList(fields["templateFormalParameters"], "templateFormalParameters"),
                    templatePatternAnchorCandidateId = nullableString(fields["templatePatternAnchorCandidateId"], "templatePatternAnchorCandidateId"),
                    templateActualArguments = nullableStringList(fields["templateActualArguments"], "templateActualArguments"),
                    inlineCalleeAnchorCandidateId = nullableString(fields["inlineCalleeAnchorCandidateId"], "inlineCalleeAnchorCandidateId"),
                    inlineOwnerAnchorCandidateId = nullableString(fields["inlineOwnerAnchorCandidateId"], "inlineOwnerAnchorCandidateId"),
                    inlineCallFile = nullableString(fields["inlineCallFile"], "inlineCallFile"),
                    inlineCallLine = nullableLong(fields["inlineCallLine"], "inlineCallLine"),
                    inlineCallColumn = nullableLong(fields["inlineCallColumn"], "inlineCallColumn"),
                    inlinePathAnchorCandidateIds = nullableStringList(fields["inlinePathAnchorCandidateIds"], "inlinePathAnchorCandidateIds"),
                    authenticatedSourceRevision = nullableString(fields["authenticatedSourceRevision"], "authenticatedSourceRevision"),
                    authenticatedSourceFileSha256 = nullableString(fields["authenticatedSourceFileSha256"], "authenticatedSourceFileSha256"),
                )
            }

            val physical = physical(obj(value["physicalDie"], "$label.physicalDie"), "$label.physicalDie")
            val kindWire = str(value["entityKind"], "$label.entityKind")
            val kind = enumValue(FullTreeSourceEntityKind.entries.toTypedArray(), kindWire, { it.wireValue }, "entityKind")
            val observability = enumValue(
                FullTreeIdentityObservability.entries.toTypedArray(),
                str(value["identityObservability"], "$label.identityObservability"),
                { it.wireValue },
                "identityObservability",
            )
            val disposition = enumValue(
                FullTreeDenominatorDisposition.entries.toTypedArray(),
                str(value["denominatorDisposition"], "$label.denominatorDisposition"),
                { it.wireValue },
                "denominatorDisposition",
            )
            val edges = array(value["edges"], "$label.edges").mapIndexed { index, raw ->
                val edge = obj(raw, "edge $index")
                val edgeKind = enumValue(
                    FullTreeSourceIdentityEdgeKind.entries.toTypedArray(),
                    str(edge["kind"], "edge.kind"),
                    { it.wireValue },
                    "edge.kind",
                )
                val state = enumValue(
                    FullTreeSourceIdentityEdgeState.entries.toTypedArray(),
                    str(edge["state"], "edge.state"),
                    { it.wireValue },
                    "edge.state",
                )
                FullTreeSourceIdentityEdge(
                    kind = edgeKind,
                    source = physicalFromLocator(str(edge["source"], "edge.source"), physical.richArtifactSha256),
                    target = if (edge["target"] == JsonNull) null else physicalFromLocator(
                        str(edge["target"], "edge.target"),
                        physical.richArtifactSha256,
                    ),
                    referenceForm = nullableString(edge["referenceForm"], "edge.referenceForm"),
                    rawReference = nullableString(edge["rawReference"], "edge.rawReference"),
                    state = state,
                    reasonCode = nullableString(edge["reasonCode"], "edge.reasonCode"),
                )
            }
            val fact = FullTreeSourceEntityFact(
                sourceEntityId = str(value["sourceEntityId"], "$label.sourceEntityId"),
                physicalDie = physical,
                kind = kind,
                identityObservability = observability,
                denominatorDisposition = disposition,
                semanticAnchorFields = nullableFields(value["semanticAnchorFields"]),
                semanticAnchorCandidateId = nullableString(value["semanticAnchorCandidateId"], "$label.semanticAnchorCandidateId"),
                resolvedSemanticIdentityId = nullableString(value["resolvedSemanticIdentityId"], "$label.resolvedSemanticIdentityId"),
                candidateCollisionSourceEntityIds = stringList(value["candidateCollisionSourceEntityIds"], "$label.candidateCollisionSourceEntityIds"),
                linkedEmittedRva = nullableString(value["linkedEmittedRva"], "$label.linkedEmittedRva"),
                reasonCodes = stringList(value["reasonCodes"], "$label.reasonCodes"),
                edges = edges,
            )
            if (fact.canonicalJson() != value) fail("is not the canonical source fact for its derived identities")
            return fact
        }

        private fun physicalFromLocator(locator: String, artifactSha256: String): FullTreeSourcePhysicalDie {
            val match = Regex("^([0-9a-f]{64}):\\.debug_info:unit=(cu-[0-9a-f]{32}):cu=(0x(?:0|[1-9a-f][0-9a-f]*)):die=(0x(?:0|[1-9a-f][0-9a-f]*))$")
                .matchEntire(locator)
                ?: throw FullTreeFunctionObservationV2Exception("source identity edge locator is malformed")
            if (match.groupValues[1] != artifactSha256) {
                throw FullTreeFunctionObservationV2Exception("source identity edge locator belongs to another artifact")
            }
            return FullTreeSourcePhysicalDie(
                richArtifactSha256 = match.groupValues[1],
                unitId = match.groupValues[2],
                section = ".debug_info",
                compilationUnitOffset = match.groupValues[3],
                dieOffset = match.groupValues[4],
            )
        }

        fun deterministicOrder(facts: Iterable<FullTreeSourceEntityFact>): List<FullTreeSourceEntityFact> =
            facts.sortedWith(
                compareBy<FullTreeSourceEntityFact> { it.kind.wireValue }
                    .thenBy { it.semanticAnchorCandidateId ?: "~" }
                    .thenBy { it.physicalDie.unitId }
                    .thenBy { it.physicalDie.compilationUnitOffset }
                    .thenBy { it.physicalDie.dieOffset },
            )
    }

    override fun equals(other: Any?): Boolean = other is FullTreeSourceEntityFact && canonicalJson() == other.canonicalJson()

    override fun hashCode(): Int = canonicalJson().hashCode()
}

/** Canonical bytes for test evidence and later observation-v2 sinks. */
internal fun canonicalSourceEntityFacts(
    facts: Iterable<FullTreeSourceEntityFact>,
    maximumCanonicalBytes: Long = MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES,
): ByteArray =
    FullTreeSourceEntityFact.deterministicOrder(facts).let { ordered ->
        require(ordered.map { it.sourceEntityId }.distinct().size == ordered.size) {
            "source-identity census repeats a physical sourceEntityId"
        }
        require(maximumCanonicalBytes in 1L..MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES)
        val expectedBytes = canonicalSourceEntityFactsByteLength(ordered, maximumCanonicalBytes)
        require(expectedBytes <= maximumCanonicalBytes) {
            "canonical source-identity output exceeds its implementation byte bound"
        }
        val output = ByteArray(expectedBytes.toInt())
        var position = 0
        fun write(value: Byte) {
            check(position < output.size) { "canonical source-identity writer exceeded its preflight" }
            output[position++] = value
        }
        fun writeAscii(value: String) = value.toByteArray(StandardCharsets.US_ASCII).forEach(::write)
        if (ordered.isEmpty()) {
            writeAscii("[]\n")
        } else {
            writeAscii("[\n")
            ordered.forEachIndexed { index, fact ->
                writeAscii("  ")
                val row = OracleJson.canonicalBytes(fact.canonicalJson(), sourceIdentityRowJsonLimits(maximumCanonicalBytes))
                check(row.isNotEmpty() && row.last() == '\n'.code.toByte()) {
                    "canonical source-identity row has no final newline"
                }
                for (rowIndex in 0 until row.lastIndex) {
                    val byte = row[rowIndex]
                    write(byte)
                    if (byte == '\n'.code.toByte()) writeAscii("  ")
                }
                if (index != ordered.lastIndex) write(','.code.toByte())
                write('\n'.code.toByte())
            }
            writeAscii("]\n")
        }
        check(position == output.size) {
            "canonical source-identity byte preflight mismatch: expected ${output.size}, wrote $position"
        }
        output
    }

/** Computes canonical output size without materializing a shard-wide output buffer. */
internal fun canonicalSourceEntityFactsByteLength(
    facts: Iterable<FullTreeSourceEntityFact>,
    maximumCanonicalBytes: Long = MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES,
): Long =
    FullTreeSourceEntityFact.deterministicOrder(facts).let { ordered ->
        require(ordered.map { it.sourceEntityId }.distinct().size == ordered.size) {
            "source-identity census repeats a physical sourceEntityId"
        }
        require(maximumCanonicalBytes in 1L..MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES)
        if (ordered.isEmpty()) {
            require(3L <= maximumCanonicalBytes) { "canonical source-identity output exceeds its authenticated byte bound" }
            return@let 3L // [] plus the canonical encoder's final newline
        }
        var size = 4L // opening [\n and closing ] plus the final newline
        ordered.forEachIndexed { index, fact ->
            val bytes = OracleJson.canonicalBytes(fact.canonicalJson(), sourceIdentityRowJsonLimits(maximumCanonicalBytes))
            val lineBreaks = bytes.count { it == '\n'.code.toByte() }
            check(lineBreaks > 0) { "canonical source-identity row has no final newline" }
            val internalLineBreaks = lineBreaks - 1
            size = Math.addExact(size, bytes.size.toLong() - 1L) // omit the row encoder's final newline
            size = Math.addExact(size, 2L) // array element indentation
            size = Math.addExact(size, Math.multiplyExact(internalLineBreaks.toLong(), 2L)) // nested indentation
            size = Math.addExact(size, 1L) // newline after this array element
            if (index != ordered.lastIndex) size = Math.addExact(size, 1L) // array comma
        }
        require(size <= maximumCanonicalBytes) { "canonical source-identity output exceeds its authenticated byte bound" }
        size
    }

internal fun sourceIdentitySha256(bytes: ByteArray): String = OracleArtifacts.sha256(bytes)

internal const val MAXIMUM_IDENTITY_EDGES_PER_ENTITY = 32
internal const val MAXIMUM_SOURCE_IDENTITY_ROW_BYTES = 64L * 1024L * 1024L
internal const val MAXIMUM_SOURCE_IDENTITY_RETAINED_BYTES = 64L * 1024L * 1024L
internal const val MAXIMUM_SOURCE_IDENTITY_ROW_SCRATCH_FACTOR = 2L
internal const val SOURCE_IDENTITY_RETAINED_CONTENT_EXPANSION_FACTOR = 3L
internal const val SOURCE_IDENTITY_RETAINED_CHARGE_OVERHEAD_BYTES = 64L
internal const val SOURCE_IDENTITY_INVENTORY_EXPANSION_FACTOR = 8L
internal const val SOURCE_IDENTITY_CONTROL_JSON_NODE_BYTES = 64L
internal const val MAXIMUM_SOURCE_IDENTITY_CONTROL_JSON_NODES = 1_000_000L
internal const val SOURCE_IDENTITY_COMPILATION_UNIT_INDEX_BYTES = 1_024L
internal const val SOURCE_IDENTITY_UNIT_METADATA_EXPANSION_FACTOR = 3L
internal const val MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES = 256 * 1024 * 1024L

internal fun sourceIdentityRowJsonLimits(maximumCanonicalBytes: Long): StrictJsonLimits {
    val rowLimit = minOf(maximumCanonicalBytes, MAXIMUM_SOURCE_IDENTITY_ROW_BYTES).toInt()
    require(rowLimit > 0)
    return StrictJsonLimits(
        maximumInputBytes = rowLimit,
        maximumCanonicalBytes = rowLimit,
        maximumNodes = 1_000_000,
        maximumStringBytes = rowLimit,
        maximumTotalStringBytes = rowLimit,
    )
}

private val ANCHOR_DOMAIN = "decomp-thing:full-tree-source-anchor-v1\u0000".toByteArray(StandardCharsets.UTF_8)
private val SOURCE_ENTITY_DOMAIN = "decomp-thing:full-tree-source-entity-v1\u0000".toByteArray(StandardCharsets.UTF_8)
private val REASON_CODE = Regex("[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
private val SOURCE_EDGE_ORDER = compareBy<FullTreeSourceIdentityEdge> { it.kind.wireValue }
    .thenBy { it.source.locator() }
    .thenBy { it.target?.locator() ?: "~" }
    .thenBy { it.state.wireValue }
    .thenBy { it.rawReference ?: "~" }
    .thenBy { it.referenceForm ?: "~" }
    .thenBy { it.reasonCode ?: "~" }

private fun <T> immutableSourceList(values: List<T>): List<T> =
    java.util.Collections.unmodifiableList(ArrayList(values))

private fun isNormalizedSourcePath(value: String): Boolean =
    value.isNotEmpty() && !value.startsWith('/') && '\\' !in value && '\u0000' !in value &&
        value.split('/').none { it.isEmpty() || it == "." || it == ".." }
