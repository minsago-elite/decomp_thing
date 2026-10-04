package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
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
        val semanticFields = JsonObject(canonicalJson().toMutableMap().apply {
            // The line-table file index is artifact-local. The column is retained as raw fact
            // evidence, but some compilers omit it for the same declaration, so it is not part of
            // the cross-compiler semantic tuple.
            remove("declarationFileIndex")
            remove("declarationColumn")
            // A concrete instance candidate describes its own complete source tuple and typed
            // actuals. A missing or later-proven pattern relation must not alter that candidate.
            if (kind == FullTreeSourceAnchorKind.TEMPLATE_INSTANCE) {
                remove("templatePatternAnchorCandidateId")
            }
        })
        val preimage = JsonObject(
            mapOf(
                "fields" to semanticFields,
                "kind" to JsonPrimitive(kind.wireValue),
                "version" to JsonPrimitive(2),
            ),
        )
        val bytes = OracleJson.canonicalBytes(preimage)
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
internal const val MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES = 256 * 1024 * 1024L

private fun sourceIdentityRowJsonLimits(maximumCanonicalBytes: Long): StrictJsonLimits {
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

private fun <T> immutableSourceList(values: List<T>): List<T> =
    java.util.Collections.unmodifiableList(ArrayList(values))

private fun isNormalizedSourcePath(value: String): Boolean =
    value.isNotEmpty() && !value.startsWith('/') && '\\' !in value && '\u0000' !in value &&
        value.split('/').none { it.isEmpty() || it == "." || it == ".." }
