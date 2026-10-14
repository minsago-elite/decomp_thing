package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Path
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Raw DWARF evidence states. ABSENT never supplies an invented source type or target ABI default. */
internal enum class DwarfInterfaceFactState { KNOWN, ABSENT, UNKNOWN, AMBIGUOUS }

internal class DwarfInterfaceFact<T>(
    val state: DwarfInterfaceFactState,
    values: List<T> = emptyList(),
    evidence: List<String> = emptyList(),
    reasons: List<String> = emptyList(),
) {
    val values: List<T> = interfaceList(values)
    val evidence: List<String> = interfaceList(evidence.distinct())
    val reasons: List<String> = interfaceList(reasons.distinct())

    fun toJson(value: (T) -> JsonElement): JsonObject = JsonObject(linkedMapOf(
        "state" to JsonPrimitive(state.name.lowercase()),
        "values" to JsonArray(values.map(value)),
        "evidence" to interfaceStrings(evidence),
        "reasons" to interfaceStrings(reasons),
    ))
}

internal class DwarfInterfaceParameterFacts(
    val ordinal: Int,
    val locator: String,
    val name: DwarfInterfaceFact<String>,
    val type: DwarfInterfaceFact<String>,
    val artificial: DwarfInterfaceFact<String>,
    origins: List<String>,
    reasons: List<String>,
) {
    val origins: List<String> = interfaceList(origins)
    val reasons: List<String> = interfaceList(reasons)
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "ordinal" to JsonPrimitive(ordinal), "locator" to JsonPrimitive(locator),
        "name" to name.toJson(::JsonPrimitive), "type" to type.toJson(::JsonPrimitive),
        "artificial" to artificial.toJson(::JsonPrimitive),
        "origins" to interfaceStrings(origins), "reasons" to interfaceStrings(reasons),
    ))
}

/** Every candidate child sequence is retained, including conflicting concrete/declaration sequences. */
internal class DwarfInterfaceParameterList(
    val locator: String,
    parameters: List<DwarfInterfaceParameterFacts>,
    val variadic: DwarfInterfaceFact<Boolean>,
    childOrder: List<String> = parameters.map { it.locator },
) {
    val parameters: List<DwarfInterfaceParameterFacts> = interfaceList(parameters)
    val childOrder: List<String> = interfaceList(childOrder)
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "locator" to JsonPrimitive(locator),
        "parameters" to JsonArray(parameters.map { it.toJson() }),
        "variadic" to variadic.toJson(::JsonPrimitive),
        "childOrder" to interfaceStrings(childOrder),
    ))
}

internal class DwarfInterfaceFunctionFacts(
    val rva: ULong?,
    val absoluteAddress: ULong,
    val executable: Boolean,
    val locator: String,
    val sourceName: DwarfInterfaceFact<String>,
    val linkageName: DwarfInterfaceFact<String>,
    val language: DwarfInterfaceFact<String>,
    val callingConvention: DwarfInterfaceFact<String>,
    val prototyped: DwarfInterfaceFact<String>,
    val artificial: DwarfInterfaceFact<String>,
    val declaration: DwarfInterfaceFact<String>,
    val returnType: DwarfInterfaceFact<String>,
    parameters: List<DwarfInterfaceParameterFacts>,
    val parameterList: DwarfInterfaceFact<String>,
    parameterLists: List<DwarfInterfaceParameterList>,
    val variadic: DwarfInterfaceFact<Boolean>,
    origins: List<String>,
    reasons: List<String>,
) {
    val parameters: List<DwarfInterfaceParameterFacts> = interfaceList(parameters)
    val parameterLists: List<DwarfInterfaceParameterList> = interfaceList(parameterLists)
    val origins: List<String> = interfaceList(origins)
    val reasons: List<String> = interfaceList(reasons)

    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "rva" to (rva?.let { JsonPrimitive("0x${it.toString(16)}") } ?: JsonNull),
        "absoluteAddress" to JsonPrimitive("0x${absoluteAddress.toString(16)}"),
        "executable" to JsonPrimitive(executable), "locator" to JsonPrimitive(locator),
        "sourceName" to sourceName.toJson(::JsonPrimitive),
        "linkageName" to linkageName.toJson(::JsonPrimitive),
        "language" to language.toJson(::JsonPrimitive),
        "callingConvention" to callingConvention.toJson(::JsonPrimitive),
        "prototyped" to prototyped.toJson(::JsonPrimitive),
        "artificial" to artificial.toJson(::JsonPrimitive),
        "declaration" to declaration.toJson(::JsonPrimitive),
        "returnType" to returnType.toJson(::JsonPrimitive),
        "parameters" to JsonArray(parameters.map { it.toJson() }),
        "parameterList" to parameterList.toJson(::JsonPrimitive),
        "parameterLists" to JsonArray(parameterLists.map { it.toJson() }),
        "variadic" to variadic.toJson(::JsonPrimitive),
        "origins" to interfaceStrings(origins), "reasons" to interfaceStrings(reasons),
    ))
}

/** Which validated raw type references also require materializing their target declarations. */
internal enum class BoundedDwarfTypeGraphScope(val wireName: String) {
    FULL_REFERENCES("full-references"),
    ABI_LAYOUT("abi-layout"),
}

internal data class BoundedDwarfInterfaceFactLimits(
    val maximumArtifactBytes: Long = 512L * 1024L * 1024L,
    val maximumFunctions: Int = 20_000,
    val maximumGlobals: Int = 100_000,
    val maximumObjects: Int = 100_000,
    val maximumLocationExpressionBytes: Int = 4096,
    val maximumScopeDepth: Int = 128,
    val maximumScannedDies: Long = 5_000_000L,
    val maximumTypes: Int = 100_000,
    val maximumTypeDepth: Int = 64,
    val maximumTypeTraversalSteps: Long = 5_000_000L,
    val maximumParameters: Int = 1024,
    val maximumChildrenPerType: Int = 4096,
    val maximumNameCharacters: Int = 4096,
    val maximumReferenceChainEntries: Int = 32,
    val maximumCachedCompilationUnits: Int = 2,
    val maximumRetainedUnitBytes: Long = 64L * 1024L * 1024L,
    val maximumRetainedWorkingSetBytes: Long = 512L * 1024L * 1024L,
    val maximumOutputBytes: Long = 512L * 1024L * 1024L,
    val maximumRetainedFactBytes: Long = maximumOutputBytes,
    val shardLimits: BoundedDwarfShardLimits = BoundedDwarfShardLimits(),
    val typeGraphScope: BoundedDwarfTypeGraphScope = BoundedDwarfTypeGraphScope.FULL_REFERENCES,
) {
    init {
        require(maximumArtifactBytes in 1..1024L * 1024L * 1024L)
        require(maximumFunctions in 1..20_000)
        require(maximumGlobals in 1..100_000)
        require(maximumObjects in 1..100_000)
        require(maximumLocationExpressionBytes in 1..64 * 1024)
        require(maximumScopeDepth in 1..128)
        require(maximumScannedDies in 1L..5_000_000L)
        require(maximumTypes in 1..100_000)
        require(maximumTypeDepth in 1..128)
        require(maximumTypeTraversalSteps in 1L..50_000_000L)
        require(maximumParameters in 1..1024)
        require(maximumChildrenPerType in 1..4096)
        require(maximumNameCharacters in 1..4096)
        require(maximumReferenceChainEntries in 1..32)
        require(maximumCachedCompilationUnits in 1..32)
        require(maximumRetainedUnitBytes in 1..256L * 1024L * 1024L)
        require(maximumRetainedWorkingSetBytes in 1..1024L * 1024L * 1024L)
        require(maximumOutputBytes in 1..1024L * 1024L * 1024L)
        require(maximumRetainedFactBytes in 1..1024L * 1024L * 1024L)
    }
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "maximumArtifactBytes" to JsonPrimitive(maximumArtifactBytes),
        "maximumFunctions" to JsonPrimitive(maximumFunctions),
        "maximumGlobals" to JsonPrimitive(maximumGlobals),
        "maximumObjects" to JsonPrimitive(maximumObjects),
        "maximumLocationExpressionBytes" to JsonPrimitive(maximumLocationExpressionBytes),
        "maximumScopeDepth" to JsonPrimitive(maximumScopeDepth),
        "maximumScannedDies" to JsonPrimitive(maximumScannedDies),
        "maximumTypes" to JsonPrimitive(maximumTypes),
        "maximumTypeDepth" to JsonPrimitive(maximumTypeDepth),
        "maximumTypeTraversalSteps" to JsonPrimitive(maximumTypeTraversalSteps),
        "maximumParameters" to JsonPrimitive(maximumParameters),
        "maximumChildrenPerType" to JsonPrimitive(maximumChildrenPerType),
        "maximumNameCharacters" to JsonPrimitive(maximumNameCharacters),
        "maximumReferenceChainEntries" to JsonPrimitive(maximumReferenceChainEntries),
        "maximumCachedCompilationUnits" to JsonPrimitive(maximumCachedCompilationUnits),
        "maximumRetainedUnitBytes" to JsonPrimitive(maximumRetainedUnitBytes),
        "maximumRetainedWorkingSetBytes" to JsonPrimitive(maximumRetainedWorkingSetBytes),
        "maximumOutputBytes" to JsonPrimitive(maximumOutputBytes),
        "maximumRetainedFactBytes" to JsonPrimitive(maximumRetainedFactBytes),
        "shardLimits" to shardLimits.toJson(),
        "typeGraphScope" to JsonPrimitive(typeGraphScope.wireName),
    ))
}

/** Every non-null physical DIE is retained independently of semantic or ABI projection. */
internal class DwarfPhysicalUnitCensus(
    val compilationUnitOffset: Long,
    val firstDieOffset: Long,
    val endOffset: Long,
    val rootLocator: String,
    val physicalRecordCount: Long,
    val nullRecordCount: Long,
    val nonNullRecordCount: Long,
) {
    val locator: String = physicalUnitLocator(compilationUnitOffset)
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "locator" to JsonPrimitive(locator), "compilationUnitOffset" to JsonPrimitive(canonicalHex(compilationUnitOffset)),
        "firstDieOffset" to JsonPrimitive(canonicalHex(firstDieOffset)), "endOffset" to JsonPrimitive(canonicalHex(endOffset)),
        "rootLocator" to JsonPrimitive(rootLocator), "physicalRecordCount" to JsonPrimitive(physicalRecordCount),
        "nullRecordCount" to JsonPrimitive(nullRecordCount), "nonNullRecordCount" to JsonPrimitive(nonNullRecordCount),
    ))
}

/** Immutable row views. Production rows live in primitive blocks, not per-DIE object graphs. */
internal interface DwarfPhysicalReferenceCensus {
    val attributeOrdinal: Int
    val attribute: Long
    val declaredForm: Long
    val resolvedForm: Long
    val indirectDepth: Int
    val rawOperand: ULong
    val targetLocator: String?
    val state: String
    val reasons: List<String>
    fun bindTargets(locators: Set<String>)
    fun markCycle()
    fun seal()
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "attributeOrdinal" to JsonPrimitive(attributeOrdinal), "attribute" to JsonPrimitive(canonicalHex(attribute)),
        "declaredForm" to JsonPrimitive(canonicalHex(declaredForm)), "resolvedForm" to JsonPrimitive(canonicalHex(resolvedForm)),
        "indirectDepth" to JsonPrimitive(indirectDepth), "rawOperand" to JsonPrimitive("0x${rawOperand.toString(16)}"),
        "targetLocator" to (targetLocator?.let(::JsonPrimitive) ?: JsonNull), "state" to JsonPrimitive(state),
        "reasons" to interfaceStrings(reasons),
    ))
}

/** Standalone construction is retained for small fixtures and independently forged replay controls. */
internal fun DwarfPhysicalReferenceCensus(attributeOrdinal: Int, attribute: Long, declaredForm: Long,
    resolvedForm: Long, indirectDepth: Int, rawOperand: ULong, targetLocator: String?,
    unresolvedState: String? = null): DwarfPhysicalReferenceCensus =
    StandalonePhysicalReference(attributeOrdinal, attribute, declaredForm, resolvedForm, indirectDepth,
        rawOperand, targetLocator, unresolvedState)

private class StandalonePhysicalReference(
    override val attributeOrdinal: Int, override val attribute: Long, override val declaredForm: Long,
    override val resolvedForm: Long, override val indirectDepth: Int, override val rawOperand: ULong,
    override val targetLocator: String?, private val unresolvedState: String?,
) : DwarfPhysicalReferenceCensus {
    private var boundState: String? = null
    private var cyclic = false
    private var sealed = false
    override val state: String get() = boundState ?: throw IllegalStateException("physical reference has not been reconciled")
    override val reasons: List<String> get() = buildList {
        if (state != "retained-target") add(state)
        if (cyclic) add("reference-cycle")
    }
    override fun bindTargets(locators: Set<String>) {
        check(boundState == null) { "physical reference reconciliation repeats" }
        boundState = unresolvedState ?: if (targetLocator in locators) "retained-target" else "missing-target"
    }
    override fun markCycle() { check(boundState != null && !sealed); cyclic = true }
    override fun seal() { check(boundState != null && !sealed); sealed = true }
}

internal interface DwarfPhysicalDieCensus {
    val compilationUnitOffset: Long
    val offset: Long
    val endOffset: Long
    val tag: Long
    val depth: Int
    val parentOffset: Long?
    val hasChildren: Boolean
    val references: List<DwarfPhysicalReferenceCensus>
    val locator: String get() = physicalDieLocator(compilationUnitOffset, offset)
    val compilationUnitLocator: String get() = physicalUnitLocator(compilationUnitOffset)
    val parentLocator: String? get() = parentOffset?.let { physicalDieLocator(compilationUnitOffset, it) }
    val category: String get() = physicalCategory(tag)
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "locator" to JsonPrimitive(locator), "compilationUnitLocator" to JsonPrimitive(compilationUnitLocator),
        "offset" to JsonPrimitive(canonicalHex(offset)), "endOffset" to JsonPrimitive(canonicalHex(endOffset)),
        "tag" to JsonPrimitive(canonicalHex(tag)), "category" to JsonPrimitive(category), "depth" to JsonPrimitive(depth),
        "parentLocator" to (parentLocator?.let(::JsonPrimitive) ?: JsonNull), "hasChildren" to JsonPrimitive(hasChildren),
        "references" to JsonArray(references.map { it.toJson() }),
    ))
}

internal fun DwarfPhysicalDieCensus(compilationUnitOffset: Long, offset: Long, endOffset: Long, tag: Long,
    depth: Int, parentOffset: Long?, hasChildren: Boolean,
    references: List<DwarfPhysicalReferenceCensus> = emptyList()): DwarfPhysicalDieCensus =
    StandalonePhysicalDie(compilationUnitOffset, offset, endOffset, tag, depth, parentOffset, hasChildren, references)

private class StandalonePhysicalDie(
    override val compilationUnitOffset: Long, override val offset: Long, override val endOffset: Long,
    override val tag: Long, override val depth: Int, override val parentOffset: Long?, override val hasChildren: Boolean,
    references: List<DwarfPhysicalReferenceCensus>,
) : DwarfPhysicalDieCensus {
    override val references: List<DwarfPhysicalReferenceCensus> = interfaceList(references)
}

internal fun physicalUnitLocator(offset: Long): String = ".debug_info:cu=${canonicalHex(offset)}"
internal fun physicalDieLocator(unit: Long, offset: Long): String = "${physicalUnitLocator(unit)}:die=${canonicalHex(offset)}"
/** Closed reviewed DWARF tag categories; unknown/vendor tags remain in the complete raw universe. */
internal fun physicalCategory(tag: Long): String = when (tag) {
    0x11L, 0x3cL, 0x41L -> "unit"
    DW_TAG_SUBPROGRAM, 0x1dL -> "function"
    in INTERFACE_TYPE_TAGS -> "type"
    GLOBAL_VARIABLE_TAG -> "variable"
    0x05L, 0x18L -> "parameter"
    0x0dL, 0x1cL, 0x28L -> "type-child"
    0x0bL, 0x39L -> "scope"
    0x03L, 0x08L, 0x0aL, 0x19L, 0x1aL, 0x1bL, 0x1eL, 0x22L, 0x23L, 0x25L, 0x27L,
    0x2aL, 0x2bL, 0x2cL, 0x2fL, 0x30L, 0x31L, 0x32L, 0x33L, 0x34L, 0x36L,
    0x3aL, 0x3dL, 0x3eL, 0x3fL, 0x43L, 0x48L, 0x49L, 0x4aL -> "other-known"
    else -> "unknown"
}

internal class BoundedDwarfInterfaceFacts internal constructor(
    val inputSha256: String,
    val inputBytes: Long,
    val elfType: String,
    val imageBase: ULong,
    executableRanges: List<FullTreeElfExecutableRange>,
    functions: List<DwarfInterfaceFunctionFacts>,
    types: Map<String, DwarfInterfaceTypeNode>,
    val scannedDies: Long,
    val compilationUnits: Int,
    val dwarfPresent: Boolean,
    val limits: BoundedDwarfInterfaceFactLimits,
    private val controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
    globals: List<DwarfGlobalVariableFacts> = emptyList(),
    objectSymbols: List<FullTreeElfObjectSymbol> = emptyList(),
    val objectLayout: FullTreeElfObjectLayoutObservation? = null,
    val loadedUnitBytes: Long = 0L,
    val peakRetainedUnitBytes: Long = 0L,
    val modeledRetainedFactBytes: Long = 0L,
    physicalUnits: List<DwarfPhysicalUnitCensus> = emptyList(),
    physicalDies: List<DwarfPhysicalDieCensus> = emptyList(),
    val physicalCensusPresent: Boolean = false,
) {
    val physicalUnits: List<DwarfPhysicalUnitCensus> = interfaceList(physicalUnits)
    val physicalDies: List<DwarfPhysicalDieCensus> =
        if (physicalDies is CompactPhysicalDieList) physicalDies else interfaceList(physicalDies)
    val executableRanges: List<FullTreeElfExecutableRange> = interfaceList(executableRanges)
    val functions: List<DwarfInterfaceFunctionFacts> = interfaceList(functions)
    val types: Map<String, DwarfInterfaceTypeNode> = Collections.unmodifiableMap(LinkedHashMap(types))
    val globals: List<DwarfGlobalVariableFacts> = interfaceList(globals)
    val objectSymbols: List<FullTreeElfObjectSymbol> = interfaceList(objectSymbols)
    fun metadataJson(): JsonObject = JsonObject(linkedMapOf(
        "schema" to JsonPrimitive(BoundedDwarfInterfaceFactScanner.PRODUCER),
        "inputSha256" to JsonPrimitive(inputSha256), "inputBytes" to JsonPrimitive(inputBytes),
        "elfType" to JsonPrimitive(elfType), "imageBase" to JsonPrimitive("0x${imageBase.toString(16)}"),
        "executableRanges" to JsonArray(executableRanges.map { range -> JsonObject(linkedMapOf(
            "start" to JsonPrimitive("0x${range.start.toString(16)}"),
            "endExclusive" to JsonPrimitive("0x${range.endExclusive.toString(16)}"),
        )) }),
        "dwarfPresent" to JsonPrimitive(dwarfPresent), "compilationUnits" to JsonPrimitive(compilationUnits),
        "scannedDies" to JsonPrimitive(scannedDies), "limits" to limits.toJson(),
        "physicalCensus" to physicalCensusJson(),
        "dwarfControls" to JsonObject(linkedMapOf(
            "maximumDwarfSectionBytes" to JsonPrimitive(controlLimits.maximumDwarfSectionBytes),
            "maximumDwarfScratchBytes" to JsonPrimitive(controlLimits.maximumDwarfScratchBytes),
            "maximumDwarfMetadataBytes" to JsonPrimitive(controlLimits.maximumDwarfMetadataBytes),
            "maximumDwarfAttributeBytes" to JsonPrimitive(controlLimits.maximumDwarfAttributeBytes),
            "maximumDwarfParseSteps" to JsonPrimitive(controlLimits.maximumDwarfParseSteps),
            "maximumCompilationUnits" to JsonPrimitive(controlLimits.maximumCompilationUnits),
            "maximumAbbreviationDeclarationsPerUnit" to JsonPrimitive(controlLimits.maximumAbbreviationDeclarationsPerUnit),
            "maximumAbbreviationAttributesPerUnit" to JsonPrimitive(controlLimits.maximumAbbreviationAttributesPerUnit),
        )),
        "recordCounts" to JsonObject(linkedMapOf(
            "functions" to JsonPrimitive(functions.size), "types" to JsonPrimitive(types.size),
            "globals" to JsonPrimitive(globals.size), "objectSymbols" to JsonPrimitive(objectSymbols.size),
            "physicalUnits" to JsonPrimitive(physicalUnits.size), "physicalDies" to JsonPrimitive(physicalDies.size),
        )),
        "ordering" to JsonPrimitive("functions-by-address-locator;types-by-locator;globals-by-physical-DIE;objects-by-table-entry;physicalUnits-by-CU-offset;physicalDies-by-CU-offset-physical-offset"),
        "objectLayout" to (objectLayout?.toJson() ?: JsonNull),
        "loadedUnitBytes" to JsonPrimitive(loadedUnitBytes),
        "peakRetainedUnitBytes" to JsonPrimitive(peakRetainedUnitBytes),
        "modeledRetainedFactBytes" to JsonPrimitive(modeledRetainedFactBytes),
        "retainedFactAccounting" to JsonPrimitive("charged-primitive-census-block-capacity-and-traversal-arrays;other-facts-fixed-allowances-plus-utf16;not-rss"),
    ))
    fun physicalCensusJson(): JsonObject = JsonObject(linkedMapOf(
        "schema" to JsonPrimitive(DwarfPhysicalDieTableEncoding.CENSUS_SCHEMA), "present" to JsonPrimitive(physicalCensusPresent),
        "recordEncoding" to JsonPrimitive(DwarfPhysicalDieTableEncoding.NAME),
        "rowEncoding" to JsonPrimitive(DwarfPhysicalDieRowEncoding.NAME),
        "maximumRowsPerWireRecord" to JsonPrimitive(DwarfPhysicalDieTableEncoding.MAXIMUM_ROWS),
        "wireRecordUnit" to JsonPrimitive("bounded-contiguous-CU-table"),
        "decodedRecordUnit" to JsonPrimitive("non-null-physical-DIE"),
        "complete" to JsonPrimitive(physicalCensusPresent), "scope" to JsonPrimitive("all-non-null-physical-debug-info-DIEs"),
        "compilationUnitCount" to JsonPrimitive(physicalUnits.size), "physicalRecordCount" to JsonPrimitive(physicalUnits.sumOf { it.physicalRecordCount }),
        "nullRecordCount" to JsonPrimitive(physicalUnits.sumOf { it.nullRecordCount }),
        "nonNullRecordCount" to JsonPrimitive(physicalDies.size),
        "referenceCount" to JsonPrimitive(if (physicalDies is CompactPhysicalDieList) physicalDies.referenceCount.toLong()
            else physicalDies.sumOf { it.references.size.toLong() }),
        "semanticPopulationComplete" to JsonPrimitive(false),
        "verificationBoundary" to JsonPrimitive("authenticated-input-scan-replay-required;bundle-hashes-alone-are-not-coverage-proof"),
    ))
    /** Expanded semantic fixture/debug view, not the row-encoded wire. Publication uses visitCanonicalShards. */
    fun toJson(): JsonObject = JsonObject(metadataJson() + linkedMapOf(
        "functions" to JsonArray(functions.map { it.toJson() }),
        "types" to JsonArray(types.values.map { it.toJson() }),
        "globals" to JsonArray(globals.map { it.toJson() }),
        "objectSymbols" to JsonArray(objectSymbols.map { it.toJson() }),
        "physicalUnits" to JsonArray(physicalUnits.map { it.toJson() }),
        "physicalDies" to JsonArray(physicalDies.map { it.toJson() }),
    ))
    fun visitCanonicalShards(consumer: (String, Int, ByteArray, Int) -> Unit): BoundedDwarfShardSummary {
        val writer = BoundedDwarfCanonicalShardWriter(limits.shardLimits.copy(
            maximumTotalBytes = minOf(limits.maximumOutputBytes, limits.shardLimits.maximumTotalBytes),
        ), consumer)
        visitCanonicalRecordGroups(writer::write)
        return writer.finish()
    }

    /** Shared normalized record stream; never constructs an inline type graph or all-record array. */
    fun visitCanonicalRecordGroups(consumer: (String, Sequence<JsonObject>) -> Unit) {
        val orderedTypes = types.values.sortedBy { it.id }
        val metadata = metadataJson()
        consumer("metadata", sequenceOf(JsonObject(metadata + mapOf(
            "typeChildEncoding" to JsonPrimitive(RAW_RECORD_ENCODING),
            "typePromotedFactFallbacks" to JsonObject(linkedMapOf(
                "types" to JsonObject(TYPE_PROMOTED_FACT_ATTRIBUTES.mapValues { JsonPrimitive(it.value) }),
                "typeChildren" to JsonObject(CHILD_PROMOTED_FACT_ATTRIBUTES.mapValues { JsonPrimitive(it.value) }),
            )),
            "typePromotedFactRule" to JsonPrimitive("only-exact-JSON-duplicates-omitted;" +
                "absent-promoted-field-resolves-to-required-attribute;explicit-field-takes-precedence"),
            "recordCounts" to JsonObject((metadata.getValue("recordCounts") as JsonObject) +
                ("typeChildren" to JsonPrimitive(orderedTypes.sumOf { it.children.size.toLong() }))),
            "ordering" to JsonPrimitive("functions-by-address-locator;types-by-locator;" +
                "typeChildren-by-parent-locator-physical-child;globals-by-physical-DIE;objects-by-table-entry;" +
                "physicalUnits-by-CU-offset;physicalDies-by-CU-offset-physical-offset"),
        ))))
        consumer("functions", functions.asSequence().map { it.toJson() })
        consumer("types", orderedTypes.asSequence().map(::typeShardHeader))
        consumer("typeChildren", orderedTypes.asSequence().flatMap { parent ->
            parent.children.asSequence().map { child -> JsonObject(linkedMapOf(
                "parentTypeId" to JsonPrimitive(parent.id),
                "child" to compactPromotedTypeFacts(child.toJson(), CHILD_PROMOTED_FACT_ATTRIBUTES),
            )) }
        })
        consumer("globals", globals.asSequence().map { it.toJson() })
        consumer("objectSymbols", objectSymbols.asSequence().map { it.toJson() })
        consumer("physicalUnits", physicalUnits.asSequence().map { it.toJson() })
        consumer("physicalDies", DwarfPhysicalDieTableEncoding.records(physicalDies))
    }

    /** Project the header directly: inline child JSON can itself exceed a shard's node bound. */
    private fun typeShardHeader(type: DwarfInterfaceTypeNode): JsonObject = compactPromotedTypeFacts(JsonObject(linkedMapOf(
        "id" to JsonPrimitive(type.id), "tag" to JsonPrimitive("0x${type.tag.toString(16)}"),
        "name" to type.name.toJson(::JsonPrimitive), "byteSize" to type.byteSize.toJson(::JsonPrimitive),
        "encoding" to type.encoding.toJson(::JsonPrimitive), "type" to type.type.toJson(::JsonPrimitive),
        "attributes" to JsonObject(type.attributes.toSortedMap().entries.associate { (name, fact) ->
            "0x${name.toString(16)}" to fact.toJson(::JsonPrimitive)
        }),
        "childLocators" to interfaceStrings(type.children.map { it.id }),
        "reasons" to interfaceStrings(type.reasons),
    )), TYPE_PROMOTED_FACT_ATTRIBUTES)

    /** Omission means an exact copy of the required attribute fact, including all provenance. */
    private fun compactPromotedTypeFacts(record: JsonObject, promotedAttributes: Map<String, String>): JsonObject {
        val attributes = record.getValue("attributes") as JsonObject
        return JsonObject(record.filter { (field, value) ->
            val attribute = promotedAttributes[field]
            attribute == null || attributes[attribute] != value
        })
    }

    companion object {
        const val RAW_RECORD_ENCODING = "type-headers-with-ordered-child-locators-v2"
        private val TYPE_PROMOTED_FACT_ATTRIBUTES = linkedMapOf("name" to "0x3", "byteSize" to "0xb",
            "encoding" to "0x3e", "type" to "0x49")
        private val CHILD_PROMOTED_FACT_ATTRIBUTES = linkedMapOf("name" to "0x3", "type" to "0x49")
    }
    fun canonicalBytes(): ByteArray = OracleJson.canonicalBytes(toJson(), StrictJsonLimits(
        maximumInputBytes = minOf(limits.maximumOutputBytes, 64L * 1024L * 1024L).toInt(),
        maximumCanonicalBytes = minOf(limits.maximumOutputBytes, 64L * 1024L * 1024L).toInt(), maximumDepth = 64,
        maximumNodes = 1_000_000, maximumStringBytes = 1024 * 1024,
        maximumTotalStringBytes = minOf(limits.maximumOutputBytes, 64L * 1024L * 1024L).toInt(),
    ))
}

/** Program-neutral source interface facts, independent of recovered models and ABI scoring. */
internal object BoundedDwarfInterfaceFactScanner {
    const val PRODUCER = "bounded-dwarf-interface-facts-v5"

    /** Replays every physical record from the held authenticated input without retaining a second census. */
    fun verifyPhysicalCensus(
        artifact: StableControlFile,
        scratchParent: Path,
        facts: BoundedDwarfInterfaceFacts,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        checkpoint: (String) -> Unit = {},
    ) {
        require(facts.physicalCensusPresent && artifact.size <= facts.limits.maximumArtifactBytes && artifact.size == facts.inputBytes &&
            artifact.sha256(checkpoint, "physical census replay ELF") == facts.inputSha256) {
            "physical census replay input differs from scanned facts"
        }
        val limits = facts.limits
        var unitOrdinal = 0; var dieOrdinal = 0; var physicalCount = 0L; var referenceCount = 0L
        val replayBudget = FullTreeDwarfParseBudget(controlLimits.maximumDwarfParseSteps, checkpoint)
        FullTreeDwarfSections.open(artifact, scratchParent, controlLimits,
            FullTreeDwarfSections.FUNCTION_OBSERVATION_SECTION_NAMES, requiredNames = emptySet()).use { sections ->
            val info = sections.optional(".debug_info")
            require((info == null) == (sections.optional(".debug_abbrev") == null)) { "incomplete replay DWARF" }
            require(facts.dwarfPresent == (info != null)) { "physical census DWARF presence differs from source replay" }
            if (info != null) {
                val parseBudget = replayBudget
                val iterator = FullTreeDwarfCompilationUnitHeaders(info, controlLimits.maximumCompilationUnits.toLong(), parseBudget)
                val headers = ArrayList<FullTreeDwarfCompilationUnitHeader>()
                while (iterator.hasNext()) headers += iterator.next()
                for (header in headers) {
                    checkpoint("replaying physical census unit ${canonicalHex(header.offset)}")
                    val index = FullTreeDwarfDies.readCompilationUnit(info, sections.required(".debug_abbrev"), header,
                        controlLimits, FullTreeDwarfDieLimits(limits.maximumScannedDies, limits.maximumScannedDies.toInt(),
                            minOf(50_000_000L, limits.maximumScannedDies * 10L), 65_536, limits.maximumRetainedUnitBytes),
                        parseBudget, contextForAttribute = ::interfaceAttributeContext)
                    physicalCount = Math.addExact(physicalCount, index.physicalRecordCount)
                    require(physicalCount <= limits.maximumScannedDies) { "physical census replay exceeds DIE bound" }
                    val unit = facts.physicalUnits.getOrNull(unitOrdinal++)
                        ?: throw FullTreeControlException("physical census omits a replayed compilation unit")
                    require(unit.compilationUnitOffset == header.offset && unit.firstDieOffset == header.firstDieOffset &&
                        unit.endOffset == header.endOffset && unit.rootLocator == physicalDieLocator(header.offset, index.root.offset) &&
                        unit.physicalRecordCount == index.physicalRecordCount && unit.nullRecordCount == index.nullRecordCount &&
                        unit.nonNullRecordCount == index.recordsInPhysicalOrder.size.toLong()) { "physical census unit differs from source replay" }
                    for (record in index.recordsInPhysicalOrder) {
                        parseBudget.consume("physical census replay DIEs")
                        val die = facts.physicalDies.getOrNull(dieOrdinal++)
                            ?: throw FullTreeControlException("physical census omits a replayed DIE")
                        require(die.compilationUnitOffset == header.offset && die.offset == record.offset &&
                            die.endOffset == record.endOffset && die.tag == record.tag && die.depth == record.depth &&
                            die.parentOffset == record.parentOffset && die.hasChildren == record.hasChildren) {
                            "physical census DIE differs from source replay"
                        }
                        var referenceOrdinal = 0
                        for ((ordinal, attribute) in record.attributes.withIndex()) {
                            val raw = attribute.value
                            if (raw !is FullTreeDwarfReferenceValue && raw !is FullTreeDwarfUnsupportedReferenceValue) continue
                            parseBudget.consume("physical census replay references")
                            if (++referenceCount > limits.maximumTypeTraversalSteps) throw FullTreeControlException("physical census replay exceeds reference bound")
                            val value = raw as FullTreeDwarfUnsignedFormValue
                            val reference = die.references.getOrNull(referenceOrdinal++)
                                ?: throw FullTreeControlException("physical census omits a replayed reference")
                            val targetOffset = physicalReferenceOffset(raw, header, info.size)
                            val targetHeader = targetOffset?.let { physicalHeaderContaining(headers, it, parseBudget) }
                            val target = targetHeader?.let { physicalDieLocator(it.offset, targetOffset!!) }
                            require(reference.attributeOrdinal == ordinal && reference.attribute == attribute.name &&
                                reference.declaredForm == attribute.declaredForm && reference.resolvedForm == value.resolvedForm &&
                                reference.indirectDepth == value.indirectDepth && reference.rawOperand == value.rawValue &&
                                reference.targetLocator == target &&
                                (raw !is FullTreeDwarfUnsupportedReferenceValue || reference.state == "unsupported-reference") &&
                                (raw !is FullTreeDwarfReferenceValue || target != null || reference.state == "out-of-range-reference")) {
                                "physical census reference differs from source replay"
                            }
                        }
                        require(referenceOrdinal == die.references.size) { "physical census adds references absent from source replay" }
                    }
                }
            }
        }
        require(unitOrdinal == facts.physicalUnits.size && dieOrdinal == facts.physicalDies.size &&
            physicalCount == facts.scannedDies && unitOrdinal == facts.compilationUnits) { "physical census adds or drops source records" }
        verifyPhysicalReferenceClassifications(facts.physicalDies, limits, replayBudget)
        artifact.verifyUnchanged("after physical census source replay")
    }

    fun scan(
        artifact: StableControlFile,
        scratchParent: Path,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        limits: BoundedDwarfInterfaceFactLimits = BoundedDwarfInterfaceFactLimits(),
        checkpoint: (String) -> Unit = {},
    ): BoundedDwarfInterfaceFacts {
        if (artifact.size > limits.maximumArtifactBytes) throw FullTreeControlException("interface ELF exceeds artifact bound")
        val digest = artifact.sha256(checkpoint, "interface ELF")
        val budget = DwarfInterfaceFactBudget(limits.maximumRetainedFactBytes)
        val objects = ArrayList<FullTreeElfObjectSymbol>()
        val layout = FullTreeElfLayout.scanObjects(artifact, "rich", FullTreeElfLayoutLimits(), checkpoint) { symbol ->
            if (objects.size >= limits.maximumObjects) throw FullTreeControlException("interface scan exceeds object symbol bound")
            // Charge boxed indices and retained list slots before keeping the symbol. The
            // temporary single-symbol builder remains bounded by maximumProgramHeaders.
            budget.chargeElfObjectSymbol(symbol, "ELF object facts")
            objects += symbol
        }
        val executable = FullTreeElfExecutableMembership.fromSorted(layout.executableRanges)
        val functions = ArrayList<DwarfInterfaceFunctionFacts>()
        val globals = ArrayList<DwarfGlobalVariableFacts>()
        val physicalUnits = ArrayList<DwarfPhysicalUnitCensus>()
        val physicalCensus = CompactDwarfPhysicalCensus(budget, limits.maximumScannedDies.toInt(), limits.maximumTypeTraversalSteps)
        var physicalReferences = 0L
        var loadedUnitBytes = 0L
        var peakRetainedUnitBytes = 0L
        var types: Map<String, DwarfInterfaceTypeNode> = emptyMap()
        var scannedDies = 0L
        var compilationUnits = 0
        var dwarfPresent = false
        FullTreeDwarfSections.open(artifact, scratchParent, controlLimits,
            FullTreeDwarfSections.FUNCTION_OBSERVATION_SECTION_NAMES, requiredNames = emptySet()).use { sections ->
            val info = sections.optional(".debug_info")
            if ((info == null) != (sections.optional(".debug_abbrev") == null)) {
                throw FullTreeControlException("interface ELF has incomplete DWARF information")
            }
            if (info != null) {
                dwarfPresent = true
                val parseBudget = FullTreeDwarfParseBudget(controlLimits.maximumDwarfParseSteps, checkpoint)
                val iterator = FullTreeDwarfCompilationUnitHeaders(info, controlLimits.maximumCompilationUnits.toLong(), parseBudget)
                val headers = ArrayList<FullTreeDwarfCompilationUnitHeader>()
                while (iterator.hasNext()) headers += iterator.next()
                compilationUnits = headers.size
                val repository = FunctionDwarfUnitRepository(sections, headers, controlLimits,
                    FullTreeFunctionObservationProducerLimits(
                        dieLimits = FullTreeDwarfDieLimits(limits.maximumScannedDies, limits.maximumScannedDies.toInt(),
                            minOf(50_000_000L, limits.maximumScannedDies * 10L), 65_536, limits.maximumRetainedUnitBytes),
                        maximumReferenceChainEntries = limits.maximumReferenceChainEntries,
                        maximumCachedCompilationUnits = limits.maximumCachedCompilationUnits,
                    ), parseBudget, contextForAttribute = ::interfaceAttributeContext, retainAllRecords = true,
                    maximumRetainedWorkingSetBytes = limits.maximumRetainedWorkingSetBytes)
                val resolver = BoundedDwarfInterfaceTypeResolver(repository, limits, budget)
                val globalReader = BoundedDwarfGlobalFactReader(repository, resolver, limits, budget, parseBudget, layout)
                for (header in headers) {
                    checkpoint("DWARF interface unit ${canonicalHex(header.offset)}")
                    val owner = repository.load(header)
                    scannedDies = Math.addExact(scannedDies, owner.index.physicalRecordCount)
                    if (scannedDies > limits.maximumScannedDies) throw FullTreeControlException("interface scan exceeds DIE bound")
                    val index = owner.index
                    check(index.physicalRecordCount == index.nullRecordCount + index.recordsInPhysicalOrder.size.toLong()) {
                        "complete physical DIE index differs from decoded record counts"
                    }
                    budget.charge(512L, "physical compilation-unit census")
                    physicalUnits += DwarfPhysicalUnitCensus(header.offset, header.firstDieOffset, header.endOffset,
                        physicalDieLocator(header.offset, index.root.offset), index.physicalRecordCount,
                        index.nullRecordCount, index.recordsInPhysicalOrder.size.toLong())
                    for (record in index.recordsInPhysicalOrder) {
                        parseBudget.consume("physical DIE census")
                        physicalCensus.appendDie(header.offset, record.offset, record.endOffset, record.tag,
                            record.depth, record.parentOffset, record.hasChildren)
                        for ((ordinal, attribute) in record.attributes.withIndex()) {
                            val raw = attribute.value
                            if (raw !is FullTreeDwarfReferenceValue && raw !is FullTreeDwarfUnsupportedReferenceValue) continue
                            parseBudget.consume("physical DIE census references")
                            if (physicalReferences >= limits.maximumTypeTraversalSteps) {
                                throw FullTreeControlException("physical DIE census exceeds traversal-work bound: references")
                            }
                            physicalReferences++
                            val value = raw as FullTreeDwarfUnsignedFormValue
                            val targetOffset = physicalReferenceOffset(raw, header, info.size)
                            val targetHeader = targetOffset?.let { offset -> physicalHeaderContaining(headers, offset, parseBudget) }
                            physicalCensus.appendReference(ordinal, attribute.name, attribute.declaredForm,
                                value.resolvedForm, value.indirectDepth, value.rawValue, targetHeader?.offset, targetOffset,
                                if (raw is FullTreeDwarfUnsupportedReferenceValue) "unsupported-reference"
                                else if (targetHeader == null) "out-of-range-reference" else null)
                        }
                        if (record.tag == GLOBAL_VARIABLE_TAG) {
                            if (globals.size >= limits.maximumGlobals) throw FullTreeControlException("interface scan exceeds global candidate bound")
                            globals += repository.withRetainedUnits(owner) {
                                globalReader.read(ResolvedFunctionDie(owner, record))
                            }
                        }
                        if (record.tag != DW_TAG_SUBPROGRAM) continue
                        val start = owner.functionStart(record) ?: continue
                        if (functions.size >= limits.maximumFunctions) throw FullTreeControlException("interface scan exceeds function bound")
                        val rva = if (start >= layout.imageBase) start - layout.imageBase else null
                        functions += repository.withRetainedUnits(owner) {
                            InterfaceFunctionReader(repository, resolver, limits, budget).read(
                                ResolvedFunctionDie(owner, record), start, rva, rva != null && executable.contains(rva))
                        }
                    }
                }
                physicalCensus.reconcile(limits, parseBudget)
                types = resolver.nodes()
                loadedUnitBytes = repository.loadedUnitBytes
                peakRetainedUnitBytes = repository.peakRetainedUnitBytes
            }
        }
        artifact.verifyUnchanged("interface ELF after DWARF interface scanning")
        return BoundedDwarfInterfaceFacts(digest, artifact.size, layout.elfType, layout.imageBase,
            layout.executableRanges, functions.sortedWith(compareBy<DwarfInterfaceFunctionFacts> { it.absoluteAddress }
                .thenBy { it.locator }), types, scannedDies, compilationUnits, dwarfPresent, limits, controlLimits,
            globals, objects, layout, loadedUnitBytes, peakRetainedUnitBytes, budget.chargedBytes,
            physicalUnits, physicalCensus.sealedDies(), physicalCensusPresent = true).also {
            // Enforce per-shard and aggregate bounds without materializing a monolithic document.
            it.visitCanonicalShards { _, _, _, _ -> }
        }
    }
}

/** A prior source replay matches this ordered universe exactly; binary membership retains no second index. */
private fun physicalTargetIndex(dies: List<DwarfPhysicalDieCensus>, locator: String?, parseBudget: FullTreeDwarfParseBudget): Int {
    if (locator == null) return -1
    val offset = locator.substringAfterLast(":die=0x", "").toLongOrNull(16) ?: return -1
    var low = 0; var high = dies.lastIndex
    while (low <= high) {
        parseBudget.consume("physical replay target lookup")
        val middle = low + (high - low) / 2
        val die = dies[middle]
        when { offset < die.offset -> high = middle - 1; offset > die.offset -> low = middle + 1
            else -> return if (die.locator == locator) middle else -1 }
    }
    return -1
}

/** Reuses the scanner's charged compact traversal allowance, never retaining another DIE population. */
private fun verifyPhysicalReferenceClassifications(dies: List<DwarfPhysicalDieCensus>,
    limits: BoundedDwarfInterfaceFactLimits, parseBudget: FullTreeDwarfParseBudget) {
    for (die in dies) for (reference in die.references) {
        parseBudget.consume("physical replay reference availability")
        val expected = when {
            reference.resolvedForm in setOf(FULL_TREE_DW_FORM_REF_SUP4, FULL_TREE_DW_FORM_REF_SUP8, FULL_TREE_DW_FORM_REF_SIG8, FULL_TREE_DW_FORM_GNU_REF_ALT) -> "unsupported-reference"
            reference.targetLocator == null -> "out-of-range-reference"
            physicalTargetIndex(dies, reference.targetLocator, parseBudget) >= 0 -> "retained-target"
            else -> "missing-target"
        }
        require(reference.state == expected) { "physical census reference state differs from source replay" }
    }
    require(dies.size.toLong() <= limits.maximumScannedDies) { "physical replay census exceeds DIE bound" }
    val colors = ByteArray(dies.size)
    val stackDies = IntArray(dies.size)
    val stackNext = IntArray(dies.size)
    var steps = 0L
    for (root in dies.indices) {
        if (colors[root].toInt() != 0) continue
        var size = 1; stackDies[0] = root; stackNext[0] = 0; colors[root] = 1
        while (size > 0) {
            parseBudget.consume("physical replay reference cycles")
            if (++steps > limits.maximumTypeTraversalSteps) throw FullTreeControlException("physical replay exceeds traversal-work bound")
            val position = size - 1; val die = dies[stackDies[position]]
            if (stackNext[position] == die.references.size) { colors[stackDies[position]] = 2; size--; continue }
            val reference = die.references[stackNext[position]++]
            val target = if (reference.state == "retained-target") physicalTargetIndex(dies, reference.targetLocator, parseBudget) else -1
            val backEdge = target >= 0 && colors[target].toInt() == 1
            require(("reference-cycle" in reference.reasons) == backEdge) { "physical census reference cycle differs from source replay" }
            if (target >= 0 && colors[target].toInt() == 0) { stackDies[size] = target; stackNext[size] = 0; size++; colors[target] = 1 }
        }
    }
}

private fun physicalReferenceOffset(raw: FullTreeDwarfFormValue, header: FullTreeDwarfCompilationUnitHeader, infoBytes: Long): Long? {
    if (raw !is FullTreeDwarfReferenceValue || raw.rawValue > Long.MAX_VALUE.toULong()) return null
    return try {
        val offset = if (raw.scope == FullTreeDwarfReferenceScope.COMPILATION_UNIT)
            Math.addExact(header.offset, raw.rawValue.toLong()) else raw.rawValue.toLong()
        offset.takeIf { it >= 0 && it < infoBytes &&
            (raw.scope != FullTreeDwarfReferenceScope.COMPILATION_UNIT || it in header.firstDieOffset until header.endOffset) }
    } catch (_: ArithmeticException) { null }
}

private fun physicalHeaderContaining(headers: List<FullTreeDwarfCompilationUnitHeader>, offset: Long, parseBudget: FullTreeDwarfParseBudget): FullTreeDwarfCompilationUnitHeader? {
    var low = 0; var high = headers.lastIndex
    while (low <= high) {
        parseBudget.consume("physical census compilation-unit target lookup")
        val middle = low + (high - low) / 2
        val header = headers[middle]
        when { offset < header.firstDieOffset -> high = middle - 1; offset >= header.endOffset -> low = middle + 1; else -> return header }
    }
    return null
}

/** Modeled retained facts, separate from exact encoded shard bytes and the JVM heap limit. */
internal class DwarfInterfaceFactBudget(
    private val maximumBytes: Long,
    initiallyChargedBytes: Long = 0L,
) {
    var chargedBytes = initiallyChargedBytes
        private set
    init {
        require(maximumBytes > 0 && initiallyChargedBytes in 0..maximumBytes)
    }
    fun charge(bytes: Long, label: String) {
        if (bytes < 0 || bytes > maximumBytes - chargedBytes) throw FullTreeControlException("$label exceeds retained fact bound")
        chargedBytes += bytes
    }
    fun chargeElfObjectSymbol(symbol: FullTreeElfObjectSymbol, label: String) {
        var bytes = Math.addExact(1024L, Math.multiplyExact(symbol.segmentIndices.size.toLong(), 32L))
        fun addString(value: String) {
            bytes = Math.addExact(bytes, Math.addExact(32L, Math.multiplyExact(value.length.toLong(), 2L)))
        }
        addString(symbol.name)
        addString(symbol.locator)
        symbol.sectionName?.let(::addString)
        symbol.reasons.forEach(::addString)
        charge(bytes, label)
    }
    fun chargeStringFact(fact: DwarfInterfaceFact<String>, label: String) {
        var bytes = 192L
        for (text in fact.values + fact.evidence + fact.reasons) {
            bytes = Math.addExact(bytes, Math.addExact(32L, Math.multiplyExact(text.length.toLong(), 2L)))
        }
        charge(bytes, label)
    }
}

internal fun dwarfInterfaceLocator(source: ResolvedFunctionDie): String =
    ".debug_info:cu=${canonicalHex(source.unit.header.offset)}:die=${canonicalHex(source.record.offset)}"

private class InterfaceFunctionReader(
    private val repository: FunctionDwarfUnitRepository,
    private val types: BoundedDwarfInterfaceTypeResolver,
    private val limits: BoundedDwarfInterfaceFactLimits,
    private val budget: DwarfInterfaceFactBudget,
) {
    fun read(source: ResolvedFunctionDie, start: ULong, rva: ULong?, executable: Boolean): DwarfInterfaceFunctionFacts {
        budget.charge(4096, "DWARF interface function")
        val inheritance = InterfaceInheritance(repository, source, limits.maximumReferenceChainEntries)
        val reasons = inheritance.reasons.toMutableList()
        if (!executable) reasons += "emitted-start-outside-executable-ranges"
        // These attributes may affect the callable interface beyond an ordinary source prototype.
        // Preserve their presence and source identity until a target projector supports their semantics.
        for (candidate in inheritance.sources) {
            for (attribute in candidate.record.attributes) {
                if (attribute.name != 0x48L && attribute.name != 0x56L && attribute.name != 0x69L) continue
                budget.charge(512, "unsupported DWARF function attribute")
                reasons += "unsupported-function-attribute:${canonicalHex(attribute.name)}:" +
                    "form=${canonicalHex(attribute.declaredForm)}:${dwarfInterfaceLocator(candidate)}"
            }
        }
        val candidates = inheritance.sources.mapNotNull { candidate ->
            val direct = children(candidate).filter { it.tag == INTERFACE_FORMAL_PARAMETER || it.tag == INTERFACE_UNSPECIFIED_PARAMETERS }
            if (direct.isEmpty() && candidate != source) return@mapNotNull null
            if (direct.count { it.tag == INTERFACE_FORMAL_PARAMETER } > limits.maximumParameters) {
                throw FullTreeControlException("DWARF interface exceeds parameter bound")
            }
            var ordinal = 0
            val parameters = direct.filter { it.tag == INTERFACE_FORMAL_PARAMETER }.map { record ->
                parameter(ResolvedFunctionDie(candidate.unit, record), ordinal++)
            }
            val markers = direct.filter { it.tag == INTERFACE_UNSPECIFIED_PARAMETERS }
            val variadic = when {
                markers.size > 1 -> DwarfInterfaceFact(DwarfInterfaceFactState.AMBIGUOUS, listOf(true),
                    markers.map { dwarfInterfaceLocator(ResolvedFunctionDie(candidate.unit, it)) }, listOf("multiple-unspecified-parameter-markers"))
                markers.size == 1 && direct.last() != markers.single() ->
                    DwarfInterfaceFact(DwarfInterfaceFactState.AMBIGUOUS, listOf(true),
                        listOf(dwarfInterfaceLocator(ResolvedFunctionDie(candidate.unit, markers.single()))),
                        listOf("unspecified-parameter-marker-is-not-last"))
                markers.size == 1 -> DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(true),
                    markers.map { dwarfInterfaceLocator(ResolvedFunctionDie(candidate.unit, it)) })
                else -> DwarfInterfaceFact(DwarfInterfaceFactState.ABSENT, emptyList(), listOf(dwarfInterfaceLocator(candidate)),
                    listOf("unspecified-parameter-marker-absent"))
            }
            DwarfInterfaceParameterList(dwarfInterfaceLocator(candidate), parameters, variadic,
                direct.map { dwarfInterfaceLocator(ResolvedFunctionDie(candidate.unit, it)) })
        }
        val nonempty = candidates.filter { it.parameters.isNotEmpty() || it.variadic.state != DwarfInterfaceFactState.ABSENT }
        val selected = nonempty.firstOrNull() ?: candidates.first()
        val shapes = nonempty.map { candidate -> candidate.parameters.map { parameter ->
            parameter.type.state to parameter.type.values
        } to candidate.variadic.values }.distinct()
        val state = when {
            shapes.size > 1 || candidates.any { it.variadic.state == DwarfInterfaceFactState.AMBIGUOUS } -> DwarfInterfaceFactState.AMBIGUOUS
            inheritance.reasons.isNotEmpty() -> DwarfInterfaceFactState.UNKNOWN
            else -> DwarfInterfaceFactState.KNOWN
        }
        val listReasons = buildList {
            if (shapes.size > 1) add("concrete-and-inherited-parameter-sequences-differ")
            if (selected.locator != dwarfInterfaceLocator(source)) add("parameter-sequence-inherited")
            addAll(candidates.flatMap { it.variadic.reasons }.filter { it != "unspecified-parameter-marker-absent" })
            addAll(inheritance.reasons)
        }
        val parameterList = DwarfInterfaceFact(state, listOf(selected.locator), candidates.map { it.locator }, listReasons)
        val variadic = if (state == DwarfInterfaceFactState.AMBIGUOUS || state == DwarfInterfaceFactState.UNKNOWN) {
            DwarfInterfaceFact(state, candidates.flatMap { it.variadic.values }.distinct(),
                candidates.flatMap { it.variadic.evidence }, listReasons)
        } else selected.variadic
        val language = integralFact(InterfaceInheritance(repository,
            ResolvedFunctionDie(source.unit, source.unit.index.root), limits.maximumReferenceChainEntries), INTERFACE_LANGUAGE)
        val standardLinkage = stringFact(inheritance, DW_AT_LINKAGE_NAME)
        val linkage = if (standardLinkage.state == DwarfInterfaceFactState.ABSENT) stringFact(inheritance, DW_AT_MIPS_LINKAGE_NAME) else standardLinkage
        return DwarfInterfaceFunctionFacts(rva, start, executable, dwarfInterfaceLocator(source),
            stringFact(inheritance, DW_AT_NAME), linkage, language,
            integralFact(inheritance, INTERFACE_CALLING_CONVENTION), integralFact(inheritance, INTERFACE_PROTOTYPED),
            integralFact(inheritance, INTERFACE_ARTIFICIAL), integralFact(inheritance, DW_AT_DECLARATION),
            typeFact(inheritance), selected.parameters, parameterList, candidates, variadic,
            inheritance.sources.map(::dwarfInterfaceLocator), reasons)
    }

    private fun parameter(source: ResolvedFunctionDie, ordinal: Int): DwarfInterfaceParameterFacts {
        budget.charge(1024, "DWARF interface parameter")
        val inheritance = InterfaceInheritance(repository, source, limits.maximumReferenceChainEntries)
        val type = typeFact(inheritance).let { fact ->
            if (fact.state == DwarfInterfaceFactState.ABSENT) DwarfInterfaceFact(DwarfInterfaceFactState.UNKNOWN,
                emptyList(), fact.evidence, fact.reasons + "parameter-type-absent") else fact
        }
        return DwarfInterfaceParameterFacts(ordinal, dwarfInterfaceLocator(source), stringFact(inheritance, DW_AT_NAME),
            type, integralFact(inheritance, INTERFACE_ARTIFICIAL), inheritance.sources.map(::dwarfInterfaceLocator), inheritance.reasons)
    }

    private fun children(source: ResolvedFunctionDie): List<FullTreeDwarfDieRecord> =
        source.unit.directChildren(source.record)

    private fun typeFact(inheritance: InterfaceInheritance): DwarfInterfaceFact<String> =
        inheritedFact(inheritance, INTERFACE_TYPE) { source, _ -> types.resolve(source) }

    private fun stringFact(inheritance: InterfaceInheritance, name: Long): DwarfInterfaceFact<String> =
        interfaceStringFact(inheritance, name, limits, budget)

    private fun integralFact(inheritance: InterfaceInheritance, name: Long): DwarfInterfaceFact<String> =
        interfaceIntegralFact(inheritance, name, budget)

}

internal fun interfaceStringFact(inheritance: InterfaceInheritance, name: Long,
    limits: BoundedDwarfInterfaceFactLimits, budget: DwarfInterfaceFactBudget): DwarfInterfaceFact<String> =
        inheritedFact(inheritance, name) { source, attribute ->
            val locator = "${dwarfInterfaceLocator(source)}:attribute=${canonicalHex(name)}"
            if (attribute.value == FullTreeDwarfUnsupportedExternalStringValue) {
                DwarfInterfaceFact(DwarfInterfaceFactState.UNKNOWN, emptyList(), listOf(locator), listOf("external-string-unavailable"))
            } else {
                val value = FullTreeDwarfForms.decodeString(attribute.value, source.unit.sections, source.unit.stringOffsetsBase,
                    source.unit.header.offsetSize, source.unit.controlLimits, locator,
                    maximumCharacters = limits.maximumNameCharacters, allowEmpty = true)
                DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(value), listOf(locator))
            }
        }.also { budget.chargeStringFact(it, "DWARF interface string") }

internal fun interfaceIntegralFact(
    inheritance: InterfaceInheritance,
    name: Long,
    budget: DwarfInterfaceFactBudget,
): DwarfInterfaceFact<String> =
        inheritedFact(inheritance, name) { source, attribute ->
            val locator = "${dwarfInterfaceLocator(source)}:attribute=${canonicalHex(name)}"
            val value = when (val raw = attribute.value) {
                is FullTreeDwarfNumericValue -> if (attribute.declaredForm in setOf(FULL_TREE_DW_FORM_FLAG,
                        FULL_TREE_DW_FORM_FLAG_PRESENT)) raw.value.toString() else null
                is FullTreeDwarfUnsignedConstantValue -> raw.rawValue.toString()
                is FullTreeDwarfWideUnsignedConstantValue -> raw.rawValue.toString()
                is FullTreeDwarfSignedConstantValue -> raw.rawValue.toString()
                else -> null
            }
            if (value == null) DwarfInterfaceFact(DwarfInterfaceFactState.UNKNOWN, emptyList(), listOf(locator), listOf("unsupported-integral-form"))
            else DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(value), listOf(locator))
        }.also { budget.chargeStringFact(it, "DWARF interface integral") }

/** Attribute override follows each origin/specification edge independently; conflicting branches remain explicit. */
internal fun <T> inheritedFact(
    inheritance: InterfaceInheritance,
    name: Long,
    decode: (ResolvedFunctionDie, FullTreeDwarfDieAttribute) -> DwarfInterfaceFact<T>,
): DwarfInterfaceFact<T> {
    val memo = HashMap<Long, DwarfInterfaceFact<T>>()
    fun visit(source: ResolvedFunctionDie, path: Set<Long>): DwarfInterfaceFact<T> {
        val offset = source.record.offset
        memo[offset]?.let { return it }
        if (offset in path) return DwarfInterfaceFact(DwarfInterfaceFactState.UNKNOWN, reasons = listOf("origin-specification-cycle"))
        source.record.optionalUniqueAttribute(name, "interface attribute ${canonicalHex(name)}")?.let { return decode(source, it) }
        // DWARF 5 section 2.13.2 excludes these from specification inheritance.
        if (name == DW_AT_DECLARATION || name == 0x01L) return DwarfInterfaceFact(
            DwarfInterfaceFactState.ABSENT,
            evidence = listOf("${dwarfInterfaceLocator(source)}:attribute=${canonicalHex(name)}:absent"),
        )
        val children = inheritance.edges[offset].orEmpty()
        val facts = children.map { visit(it, path + offset) }
        val issues = inheritance.issues[offset].orEmpty()
        val values = facts.flatMap { it.values }.distinct()
        val state = when {
            values.size > 1 || facts.any { it.state == DwarfInterfaceFactState.AMBIGUOUS } -> DwarfInterfaceFactState.AMBIGUOUS
            issues.isNotEmpty() || facts.any { it.state == DwarfInterfaceFactState.UNKNOWN } -> DwarfInterfaceFactState.UNKNOWN
            values.isNotEmpty() -> DwarfInterfaceFactState.KNOWN
            else -> DwarfInterfaceFactState.ABSENT
        }
        return DwarfInterfaceFact(state, values,
            facts.flatMap { it.evidence }.ifEmpty { listOf("${dwarfInterfaceLocator(source)}:attribute=${canonicalHex(name)}:absent") },
            issues + facts.flatMap { it.reasons }).also { memo[offset] = it }
    }
    return visit(inheritance.sources.first(), emptySet())
}

internal class InterfaceInheritance(repository: FunctionDwarfUnitRepository, source: ResolvedFunctionDie, maximumEntries: Int) {
    val sources = ArrayList<ResolvedFunctionDie>()
    val edges = LinkedHashMap<Long, List<ResolvedFunctionDie>>()
    val issues = LinkedHashMap<Long, List<String>>()
    val reasons: List<String>
    init {
        val pending = ArrayDeque<ResolvedFunctionDie>()
        val scheduled = hashSetOf(source.record.offset)
        pending += source
        while (pending.isNotEmpty()) {
            val current = pending.removeFirst()
            sources += current
            val next = ArrayList<ResolvedFunctionDie>()
            val localIssues = ArrayList<String>()
            for (name in listOf(DW_AT_ABSTRACT_ORIGIN, DW_AT_SPECIFICATION)) {
                val attribute = current.record.optionalUniqueAttribute(name, "interface origin/specification") ?: continue
                if (attribute.value !is FullTreeDwarfReferenceValue) {
                    localIssues += "unsupported-origin-specification-reference:${canonicalHex(name)}"
                    continue
                }
                val target = repository.resolveReference(current.unit, attribute, "interface origin/specification")
                if (target.record.tag != current.record.tag) localIssues += "origin-specification-tag-mismatch"
                next += target
                if (scheduled.add(target.record.offset)) {
                    if (scheduled.size > maximumEntries) throw FullTreeControlException("interface reference chain exceeds entry bound")
                    pending += target
                }
            }
            edges[current.record.offset] = next
            issues[current.record.offset] = localIssues
        }
        val examined = HashSet<Long>()
        fun cyclic(node: Long, path: Set<Long>): Boolean {
            if (node in path) return true
            if (!examined.add(node)) return false
            return edges[node].orEmpty().any { cyclic(it.record.offset, path + node) }
        }
        reasons = (issues.values.flatten() + if (cyclic(source.record.offset, emptySet())) listOf("origin-specification-cycle") else emptyList()).distinct()
    }
}

private fun interfaceAttributeContext(attribute: FullTreeDwarfAbbreviationAttribute): FullTreeDwarfFormContext =
    when (attribute.name) {
        GLOBAL_LOCATION -> FullTreeDwarfFormContext.LOCATION
        DW_AT_CONST_VALUE -> FullTreeDwarfFormContext.DATA_VALUE
        GLOBAL_EXTERNAL, 0x17L, INTERFACE_LANGUAGE, INTERFACE_CALLING_CONVENTION, INTERFACE_PROTOTYPED, INTERFACE_ARTIFICIAL,
        in INTERFACE_TYPE_CONSTANT_ATTRIBUTES,
        -> FullTreeDwarfFormContext.CONSTANT
        else -> functionAttributeContext(attribute)
    }

private fun <T> interfaceList(source: List<T>): List<T> = Collections.unmodifiableList(ArrayList(source))
private fun interfaceStrings(source: List<String>): JsonArray = JsonArray(source.map(::JsonPrimitive))
private const val INTERFACE_FORMAL_PARAMETER = 0x05L
private const val INTERFACE_UNSPECIFIED_PARAMETERS = 0x18L
private const val INTERFACE_LANGUAGE = 0x13L
private const val INTERFACE_PROTOTYPED = 0x27L
private const val INTERFACE_ARTIFICIAL = 0x34L
private const val INTERFACE_CALLING_CONVENTION = 0x36L
private const val INTERFACE_TYPE = 0x49L
