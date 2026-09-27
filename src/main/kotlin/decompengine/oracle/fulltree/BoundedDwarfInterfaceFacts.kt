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
    val shardLimits: BoundedDwarfShardLimits = BoundedDwarfShardLimits(),
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
        "shardLimits" to shardLimits.toJson(),
    ))
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
) {
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
        )),
        "ordering" to JsonPrimitive("functions-by-address-locator;types-by-locator;globals-by-physical-DIE;objects-by-table-entry"),
        "objectLayout" to (objectLayout?.toJson() ?: JsonNull),
        "loadedUnitBytes" to JsonPrimitive(loadedUnitBytes),
        "peakRetainedUnitBytes" to JsonPrimitive(peakRetainedUnitBytes),
    ))
    /** Small-fixture convenience. Production publication uses visitCanonicalShards. */
    fun toJson(): JsonObject = JsonObject(metadataJson() + linkedMapOf(
        "functions" to JsonArray(functions.map { it.toJson() }),
        "types" to JsonArray(types.values.map { it.toJson() }),
        "globals" to JsonArray(globals.map { it.toJson() }),
        "objectSymbols" to JsonArray(objectSymbols.map { it.toJson() }),
    ))
    fun visitCanonicalShards(consumer: (String, Int, ByteArray, Int) -> Unit): BoundedDwarfShardSummary {
        val writer = BoundedDwarfCanonicalShardWriter(limits.shardLimits, consumer)
        writer.write("metadata", sequenceOf(metadataJson()))
        writer.write("functions", functions.asSequence().map { it.toJson() })
        writer.write("types", types.values.asSequence().map { it.toJson() })
        writer.write("globals", globals.asSequence().map { it.toJson() })
        writer.write("objectSymbols", objectSymbols.asSequence().map { it.toJson() })
        return writer.finish()
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
    const val PRODUCER = "bounded-dwarf-interface-facts-v2"

    fun scan(
        artifact: StableControlFile,
        scratchParent: Path,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        limits: BoundedDwarfInterfaceFactLimits = BoundedDwarfInterfaceFactLimits(),
        checkpoint: (String) -> Unit = {},
    ): BoundedDwarfInterfaceFacts {
        if (artifact.size > limits.maximumArtifactBytes) throw FullTreeControlException("interface ELF exceeds artifact bound")
        val digest = artifact.sha256(checkpoint, "interface ELF")
        val budget = DwarfInterfaceOutputBudget(limits.maximumOutputBytes)
        val objects = ArrayList<FullTreeElfObjectSymbol>()
        val layout = FullTreeElfLayout.scanObjects(artifact, "rich", FullTreeElfLayoutLimits(), checkpoint) { symbol ->
            if (objects.size >= limits.maximumObjects) throw FullTreeControlException("interface scan exceeds object symbol bound")
            budget.charge(1024L + symbol.name.length.toLong() * 8L, "ELF object facts")
            objects += symbol
        }
        val executable = FullTreeElfExecutableMembership.fromSorted(layout.executableRanges)
        val functions = ArrayList<DwarfInterfaceFunctionFacts>()
        val globals = ArrayList<DwarfGlobalVariableFacts>()
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
                    for (record in owner.index.recordsInPhysicalOrder) {
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
                types = resolver.nodes()
                loadedUnitBytes = repository.loadedUnitBytes
                peakRetainedUnitBytes = repository.peakRetainedUnitBytes
            }
        }
        artifact.verifyUnchanged("interface ELF after DWARF interface scanning")
        return BoundedDwarfInterfaceFacts(digest, artifact.size, layout.elfType, layout.imageBase,
            layout.executableRanges, functions.sortedWith(compareBy<DwarfInterfaceFunctionFacts> { it.absoluteAddress }
                .thenBy { it.locator }), types, scannedDies, compilationUnits, dwarfPresent, limits, controlLimits,
            globals, objects, layout, loadedUnitBytes, peakRetainedUnitBytes).also {
            // Enforce per-shard and aggregate bounds without materializing a monolithic document.
            it.visitCanonicalShards { _, _, _, _ -> }
        }
    }
}

internal class DwarfInterfaceOutputBudget(private val maximumBytes: Long) {
    private var chargedBytes = 0L
    fun charge(bytes: Long, label: String) {
        if (bytes < 0 || bytes > maximumBytes - chargedBytes) throw FullTreeControlException("$label exceeds interface output bound")
        chargedBytes += bytes
    }
}

internal fun dwarfInterfaceLocator(source: ResolvedFunctionDie): String =
    ".debug_info:cu=${canonicalHex(source.unit.header.offset)}:die=${canonicalHex(source.record.offset)}"

private class InterfaceFunctionReader(
    private val repository: FunctionDwarfUnitRepository,
    private val types: BoundedDwarfInterfaceTypeResolver,
    private val limits: BoundedDwarfInterfaceFactLimits,
    private val budget: DwarfInterfaceOutputBudget,
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
        interfaceIntegralFact(inheritance, name)

}

internal fun interfaceStringFact(inheritance: InterfaceInheritance, name: Long,
    limits: BoundedDwarfInterfaceFactLimits, budget: DwarfInterfaceOutputBudget): DwarfInterfaceFact<String> =
        inheritedFact(inheritance, name) { source, attribute ->
            val locator = "${dwarfInterfaceLocator(source)}:attribute=${canonicalHex(name)}"
            if (attribute.value == FullTreeDwarfUnsupportedExternalStringValue) {
                DwarfInterfaceFact(DwarfInterfaceFactState.UNKNOWN, emptyList(), listOf(locator), listOf("external-string-unavailable"))
            } else {
                val value = FullTreeDwarfForms.decodeString(attribute.value, source.unit.sections, source.unit.stringOffsetsBase,
                    source.unit.header.offsetSize, source.unit.controlLimits, locator,
                    maximumCharacters = limits.maximumNameCharacters, allowEmpty = true)
                budget.charge(256 + value.length.toLong() * 8, "DWARF interface string")
                DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(value), listOf(locator))
            }
        }

internal fun interfaceIntegralFact(inheritance: InterfaceInheritance, name: Long): DwarfInterfaceFact<String> =
        inheritedFact(inheritance, name) { source, attribute ->
            val locator = "${dwarfInterfaceLocator(source)}:attribute=${canonicalHex(name)}"
            val value = when (val raw = attribute.value) {
                is FullTreeDwarfNumericValue -> if (attribute.declaredForm in setOf(FULL_TREE_DW_FORM_FLAG,
                        FULL_TREE_DW_FORM_FLAG_PRESENT)) raw.value.toString() else null
                is FullTreeDwarfUnsignedConstantValue -> raw.rawValue.toString()
                is FullTreeDwarfSignedConstantValue -> raw.rawValue.toString()
                else -> null
            }
            if (value == null) DwarfInterfaceFact(DwarfInterfaceFactState.UNKNOWN, emptyList(), listOf(locator), listOf("unsupported-integral-form"))
            else DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(value), listOf(locator))
        }

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
