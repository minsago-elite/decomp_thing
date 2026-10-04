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
    val authenticatedSourceFileSha256: String