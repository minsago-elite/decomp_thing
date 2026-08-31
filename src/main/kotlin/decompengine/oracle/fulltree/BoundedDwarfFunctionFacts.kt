package decompengine.oracle.fulltree

import java.nio.file.Path
import java.util.Collections

/** One historical function-oracle v1 evidence atom. */
internal data class BoundedFunctionEvidence(
    val kind: String,
    val locator: String,
)

/** Raw ELF/DWARF facts retained under the frozen function-oracle v1 bounds. */
internal class BoundedDwarfFunctionFacts internal constructor(
    val inputSha256: String,
    val elfType: String,
    val imageBase: ULong,
    executableRanges: List<FullTreeElfExecutableRange>,
    aliasesByRva: Map<ULong, Map<String, List<BoundedFunctionEvidence>>>,
    inlineOnly: List<Pair<ULong, Map<String, List<BoundedFunctionEvidence>>>>,
) {
    val executableRanges: List<FullTreeElfExecutableRange> =
        Collections.unmodifiableList(ArrayList(executableRanges))
    val aliasesByRva: Map<ULong, Map<String, List<BoundedFunctionEvidence>>> =
        immutableAliasesByRva(aliasesByRva)
    val inlineOnly: List<Pair<ULong, Map<String, List<BoundedFunctionEvidence>>>> =
        Collections.unmodifiableList(
            inlineOnly.map { (offset, aliases) -> offset to immutableAliases(aliases) },
        )
}

internal data class BoundedDwarfFunctionFactLimits(
    val maximumArtifactBytes: Long = 512L * 1024L * 1024L,
    val maximumFunctions: Int = 20_000,
    val maximumAliasesPerFunction: Int = 256,
    val maximumEvidencePerAlias: Int = 256,
    val maximumScannedSymbols: Long = 2_000_000L,
    val maximumScannedSubprograms: Long = 2_000_000L,
    val maximumScannedDies: Long = 5_000_000L,
    val maximumRangeSectionBytes: Long = 16L * 1024L * 1024L,
    val maximumNameCharacters: Int = 4096,
    val maximumLocatorCharacters: Int = 16_384,
    val maximumReferenceChainEntries: Int = 32,
    val maximumCachedCompilationUnits: Int = 2,
) {
    init {
        require(maximumArtifactBytes in 1L..1024L * 1024L * 1024L)
        require(maximumFunctions in 1..20_000)
        require(maximumAliasesPerFunction in 1..256)
        require(maximumEvidencePerAlias in 1..256)
        require(maximumScannedSymbols in 1L..2_000_000L)
        require(maximumScannedSubprograms in 1L..2_000_000L)
        require(maximumScannedDies in 1L..5_000_000L)
        require(maximumRangeSectionBytes in 1L..16L * 1024L * 1024L)
        require(maximumNameCharacters in 1..4096)
        require(maximumLocatorCharacters in 1..16_384)
        require(maximumReferenceChainEntries in 1..32)
        require(maximumCachedCompilationUnits in 1..32)
    }
}

/**
 * Program-neutral, bounded scanner for the legacy function-oracle v1 fact model.
 *
 * The caller supplies only a closed profile predicate. The production LLVM authority keeps those
 * predicates private and fixed; they are not caller-controlled authority inputs. This scanner and
 * the full-tree observation producer share the same DIE repository, reference-chain resolver,
 * indexed-address decoder, and range-list implementation.
 */
internal object BoundedDwarfFunctionFactScanner {
    fun scan(
        artifact: StableControlFile,
        twin: String,
        scratchParent: Path,
        symbolNameSelected: (String) -> Boolean,
        compilationUnitSelected: (String) -> Boolean,
        includeInlineOnly: Boolean,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        limits: BoundedDwarfFunctionFactLimits = BoundedDwarfFunctionFactLimits(),
        checkpoint: (String) -> Unit = {},
    ): BoundedDwarfFunctionFacts {
        if (twin !in setOf("rich", "stripped")) {
            throw FullTreeControlException("function-fact twin must be rich or stripped")
        }
        if (artifact.size > limits.maximumArtifactBytes) {
            throw FullTreeControlException("$twin ELF exceeds the function-fact artifact bound")
        }
        val inputSha256 = artifact.sha256(checkpoint, "$twin ELF")
        val mutable = MutableFunctionFacts(twin, limits)
        val elfLimits = FullTreeElfLayoutLimits(
            maximumSymbols = limits.maximumScannedSymbols,
            maximumFunctionNameCodePoints = limits.maximumNameCharacters,
            maximumLocatorBytes = limits.maximumLocatorCharacters,
        )
        val layout = FullTreeElfLayout.scanFunctions(
            artifact,
            twin,
            elfLimits,
            checkpoint,
        ) { symbol ->
            if (symbolNameSelected(symbol.name)) {
                symbol.rva?.let { rva ->
                    mutable.add(
                        rva,
                        symbol.name,
                        BoundedFunctionEvidence("elf-symbol", symbol.locator),
                    )
                }
            }
        }
        layout.executableRanges.zipWithNext().forEach { (previous, current) ->
            if (current.start < previous.endExclusive) {
                throw FullTreeControlException("$twin ELF executable PT_LOAD ranges overlap")
            }
        }
        val executable = FullTreeElfExecutableMembership.fromSorted(layout.executableRanges)

        FullTreeDwarfSections.open(
            artifact,
            scratchParent,
            controlLimits,
            FullTreeDwarfSections.FUNCTION_OBSERVATION_SECTION_NAMES,
            requiredNames = emptySet(),
        ).use { sections ->
            val info = sections.optional(".debug_info")
            val abbreviations = sections.optional(".debug_abbrev")
            if ((info == null) != (abbreviations == null)) {
                throw FullTreeControlException("$twin ELF has incomplete DWARF information")
            }
            listOf(".debug_ranges", ".debug_rnglists").forEach { name ->
                sections.optional(name)?.let { section ->
                    if (section.size > limits.maximumRangeSectionBytes) {
                        throw FullTreeControlException(
                            "$twin ELF $name exceeds the ${limits.maximumRangeSectionBytes}-byte logical-size limit",
                        )
                    }
                }
            }
            if (info != null && abbreviations != null) {
                scanDwarf(
                    twin,
                    sections,
                    info,
                    layout,
                    executable,
                    compilationUnitSelected,
                    includeInlineOnly,
                    mutable,
                    controlLimits,
                    limits,
                    checkpoint,
                )
            }
        }
        artifact.verifyUnchanged("$twin ELF after function-fact scanning")
        return mutable.freeze(inputSha256, layout)
    }

    private fun scanDwarf(
        twin: String,
        sections: FullTreeDwarfSections,
        info: FullTreeDwarfSection,
        layout: FullTreeElfLayoutObservation,
        executable: FullTreeElfExecutableMembership,
        compilationUnitSelected: (String) -> Boolean,
        includeInlineOnly: Boolean,
        mutable: MutableFunctionFacts,
        controlLimits: FullTreeControlLimits,
        limits: BoundedDwarfFunctionFactLimits,
        checkpoint: (String) -> Unit,
    ) {
        val parseBudget = FullTreeDwarfParseBudget(controlLimits.maximumDwarfParseSteps, checkpoint)
        val headers = ArrayList<FullTreeDwarfCompilationUnitHeader>()
        val iterator = FullTreeDwarfCompilationUnitHeaders(
            info,
            controlLimits.maximumCompilationUnits.toLong(),
            parseBudget,
        )
        while (iterator.hasNext()) headers += iterator.next()
        val selected = headers.filter { header ->
            compilationUnitSelected(compilationUnitPath(header, sections, controlLimits, parseBudget))
        }

        var scannedDies = 0L
        val producerLimits = FullTreeFunctionObservationProducerLimits(
            dieLimits = FullTreeDwarfDieLimits(
                maximumPhysicalRecords = limits.maximumScannedDies,
                maximumNonNullRecords = limits.maximumScannedDies.toInt(),
                maximumAttributes = minOf(50_000_000L, Math.multiplyExact(limits.maximumScannedDies, 10L)),
                maximumTreeDepth = 65_536,
                maximumRetainedBytes = 64L * 1024L * 1024L,
            ),
            maximumReferenceChainEntries = limits.maximumReferenceChainEntries,
            maximumCachedCompilationUnits = limits.maximumCachedCompilationUnits,
        )
        val repository = FunctionDwarfUnitRepository(
            sections,
            headers,
            controlLimits,
            producerLimits,
            parseBudget,
        )
        var subprograms = 0L
        selected.forEach { header ->
            val owner = repository.load(header)
            scannedDies = Math.addExact(scannedDies, owner.index.physicalRecordCount)
            if (scannedDies > limits.maximumScannedDies) {
                throw FullTreeControlException(
                    "DWARF function scan exceeds the ${limits.maximumScannedDies}-DIE limit",
                )
            }
            owner.index.recordsInPhysicalOrder.forEach { record ->
                if (record.tag != DW_TAG_SUBPROGRAM || record.truthy(DW_AT_DECLARATION, "DW_AT_declaration")) {
                    return@forEach
                }
                subprograms = Math.addExact(subprograms, 1L)
                if (subprograms > limits.maximumScannedSubprograms) {
                    throw FullTreeControlException(
                        "DWARF function scan exceeds the ${limits.maximumScannedSubprograms}-subprogram limit",
                    )
                }
                val start = observeStart(owner, record)
                val inline = record.optionalIntegral(DW_AT_INLINE, "DW_AT_inline")
                if (start != null) {
                    val aliases = observeNames(
                        owner,
                        record,
                        repository,
                        limits.maximumReferenceChainEntries,
                        limits,
                        twin,
                    )
                    if (start >= layout.imageBase) {
                        val rva = start - layout.imageBase
                        if (executable.contains(rva)) {
                            aliases.forEach { (name, evidence) ->
                                evidence.forEach { mutable.add(rva, name, it) }
                            }
                        }
                    }
                } else if (includeInlineOnly && inline in setOf(1UL, 3UL)) {
                    val aliases = observeNames(
                        owner,
                        record,
                        repository,
                        limits.maximumReferenceChainEntries,
                        limits,
                        twin,
                    )
                    mutable.addInline(record.offset.toULong(), aliases)
                }
            }
        }
    }

    private fun compilationUnitPath(
        header: FullTreeDwarfCompilationUnitHeader,
        sections: FullTreeDwarfSections,
        controlLimits: FullTreeControlLimits,
        parseBudget: FullTreeDwarfParseBudget,
    ): String {
        val info = sections.required(".debug_info")
        val abbreviations = sections.required(".debug_abbrev")
        val cursor = header.dieCursor(info)
        val abbreviationCode = cursor.readUleb128()
        if (abbreviationCode == 0L) {
            throw FullTreeControlException("DWARF compilation unit has no top-level DIE")
        }
        val declaration = FullTreeDwarfAbbreviations(
            abbreviations,
            header.abbreviationOffset,
            controlLimits,
            parseBudget,
        ).required(abbreviationCode, "DWARF top-level abbreviation")
        val values = LinkedHashMap<Long, FullTreeDwarfFormValue>()
        declaration.attributes.forEach { attribute ->
            val value = FullTreeDwarfForms.read(
                cursor,
                attribute.form,
                attribute.implicitConstant,
                header.version,
                header.addressSize,
                header.offsetSize,
                controlLimits,
            )
            if (attribute.name in COMPILATION_UNIT_PATH_ATTRIBUTES) {
                if (values.put(attribute.name, value) != null) {
                    throw FullTreeControlException("DWARF compilation-unit path attribute is duplicated")
                }
            }
        }
        val stringOffsetsBase = (values[DW_AT_STR_OFFSETS_BASE] as? FullTreeDwarfNumericValue)?.value
        val parts = listOf(DW_AT_COMP_DIR, DW_AT_NAME).mapNotNull { name ->
            values[name]?.let { value ->
                FullTreeDwarfForms.decodeString(
                    value,
                    sections,
                    stringOffsetsBase,
                    header.offsetSize,
                    controlLimits,
                    "DWARF compilation-unit path",
                    maximumCharacters = 4096,
                ).trimEnd('/')
            }
        }
        if (parts.isEmpty()) {
            throw FullTreeControlException(
                "DWARF compilation unit ${canonicalHex(header.offset)} has no path identity",
            )
        }
        return parts.joinToString("/")
    }

    private fun observeNames(
        owner: FunctionDwarfUnit,
        original: FullTreeDwarfDieRecord,
        repository: FunctionDwarfUnitRepository,
        maximumReferenceChainEntries: Int,
        limits: BoundedDwarfFunctionFactLimits,
        twin: String,
    ): Map<String, List<BoundedFunctionEvidence>> {
        val byName = java.util.TreeMap<String, MutableSet<BoundedFunctionEvidence>>(FULL_TREE_CODE_POINT_ORDER)
        val chain = repository.referenceChain(owner, original, maximumReferenceChainEntries)
        for (source in chain) {
            for ((attributeName, attributeLabel) in FUNCTION_NAME_ATTRIBUTES) {
                val attribute = source.record.optionalUniqueAttribute(attributeName, attributeLabel) ?: continue
                val locator = "$twin:.debug_info:die=${canonicalHex(original.offset)}:" +
                    "$attributeLabel@${canonicalHex(source.record.offset)}"
                if (locator.codePointCount(0, locator.length) > limits.maximumLocatorCharacters) {
                    throw FullTreeControlException("DWARF function evidence locator exceeds its bound")
                }
                val name = FullTreeDwarfForms.decodeString(
                    attribute.value,
                    source.unit.sections,
                    source.unit.stringOffsetsBase,
                    source.unit.header.offsetSize,
                    source.unit.controlLimits,
                    locator,
                    maximumCharacters = limits.maximumNameCharacters,
                )
                val evidence = byName.getOrPut(name) { linkedSetOf() }
                evidence += BoundedFunctionEvidence("dwarf-subprogram", locator)
                if (evidence.size > limits.maximumEvidencePerAlias) {
                    throw FullTreeControlException("DWARF function alias exceeds its evidence bound")
                }
            }
        }
        if (byName.isEmpty()) {
            throw FullTreeControlException(
                "non-declaration DWARF subprogram ${canonicalHex(original.offset)} has no resolvable name",
            )
        }
        if (byName.size > limits.maximumAliasesPerFunction) {
            throw FullTreeControlException("DWARF subprogram exceeds its alias bound")
        }
        return byName.mapValues { (_, evidence) -> evidence.sortedWith(EVIDENCE_ORDER) }
    }

    private fun observeStart(owner: FunctionDwarfUnit, record: FullTreeDwarfDieRecord): ULong? {
        var rangeResolved = false
        var rangeStart: ULong? = null
        fun range(): ULong? {
            if (!rangeResolved) {
                rangeStart = owner.rangeStart(record)
                rangeResolved = true
            }
            return rangeStart
        }
        val entry = record.optionalUniqueAttribute(DW_AT_ENTRY_PC, "DW_AT_entry_pc")
        if (entry != null) {
            return when (val value = entry.value) {
                is FullTreeDwarfAddressValue -> value.rawValue
                is FullTreeDwarfAddressIndexValue -> owner.resolveAddress(value)
                is FullTreeDwarfUnsignedConstantValue -> checkedAddressAdd(
                    owner.lowPc(record) ?: range()
                        ?: throw FullTreeControlException(
                            "DW_AT_entry_pc on ${canonicalHex(record.offset)} has no function base",
                        ),
                    value.rawValue,
                    "DW_AT_entry_pc",
                )
                is FullTreeDwarfSignedConstantValue -> {
                    if (value.rawValue < 0L) {
                        throw FullTreeControlException("DW_AT_entry_pc is outside unsigned 64-bit range")
                    }
                    checkedAddressAdd(
                        owner.lowPc(record) ?: range()
                            ?: throw FullTreeControlException(
                                "DW_AT_entry_pc on ${canonicalHex(record.offset)} has no function base",
                            ),
                        value.rawValue.toULong(),
                        "DW_AT_entry_pc",
                    )
                }
                else -> throw FullTreeControlException("DW_AT_entry_pc has an unsupported DWARF form class")
            }
        }
        return owner.lowPc(record) ?: range()
    }
}

private class MutableFunctionFacts(
    private val twin: String,
    private val limits: BoundedDwarfFunctionFactLimits,
) {
    private val aliases = java.util.TreeMap<ULong, java.util.TreeMap<String, MutableSet<BoundedFunctionEvidence>>>()
    private val inlineOnly = ArrayList<Pair<ULong, Map<String, List<BoundedFunctionEvidence>>>>()

    fun add(rva: ULong, name: String, evidence: BoundedFunctionEvidence) {
        if (rva !in aliases && aliases.size + inlineOnly.size >= limits.maximumFunctions) {
            throw FullTreeControlException("$twin ELF exceeds the ${limits.maximumFunctions}-record function bound")
        }
        val byName = aliases.getOrPut(rva) { java.util.TreeMap(FULL_TREE_CODE_POINT_ORDER) }
        if (name !in byName && byName.size >= limits.maximumAliasesPerFunction) {
            throw FullTreeControlException("$twin emitted RVA ${canonicalHex(rva)} exceeds its alias bound")
        }
        val evidenceSet = byName.getOrPut(name) { linkedSetOf() }
        evidenceSet += evidence
        if (evidenceSet.size > limits.maximumEvidencePerAlias) {
            throw FullTreeControlException("$twin alias evidence exceeds its bound")
        }
    }

    fun addInline(offset: ULong, names: Map<String, List<BoundedFunctionEvidence>>) {
        if (aliases.size + inlineOnly.size >= limits.maximumFunctions) {
            throw FullTreeControlException("$twin ELF exceeds the ${limits.maximumFunctions}-record function bound")
        }
        inlineOnly += offset to names
    }

    fun freeze(inputSha256: String, layout: FullTreeElfLayoutObservation): BoundedDwarfFunctionFacts =
        BoundedDwarfFunctionFacts(
            inputSha256,
            layout.elfType,
            layout.imageBase,
            layout.executableRanges,
            aliases.mapValues { (_, byName) ->
                byName.mapValues { (_, evidence) -> evidence.sortedWith(EVIDENCE_ORDER) }
            },
            inlineOnly.sortedBy { it.first },
        )
}

private fun immutableAliasesByRva(
    source: Map<ULong, Map<String, List<BoundedFunctionEvidence>>>,
): Map<ULong, Map<String, List<BoundedFunctionEvidence>>> = Collections.unmodifiableMap(
    LinkedHashMap<ULong, Map<String, List<BoundedFunctionEvidence>>>().apply {
        source.forEach { (rva, aliases) -> put(rva, immutableAliases(aliases)) }
    },
)

private fun immutableAliases(
    source: Map<String, List<BoundedFunctionEvidence>>,
): Map<String, List<BoundedFunctionEvidence>> = Collections.unmodifiableMap(
    LinkedHashMap<String, List<BoundedFunctionEvidence>>().apply {
        source.forEach { (name, evidence) ->
            put(name, Collections.unmodifiableList(ArrayList(evidence)))
        }
    },
)

private fun canonicalHex(value: ULong): String = "0x${value.toString(16)}"

private val EVIDENCE_ORDER = Comparator<BoundedFunctionEvidence> { left, right ->
    FULL_TREE_CODE_POINT_ORDER.compare(left.kind, right.kind).takeIf { it != 0 }
        ?: FULL_TREE_CODE_POINT_ORDER.compare(left.locator, right.locator)
}

private val COMPILATION_UNIT_PATH_ATTRIBUTES = setOf(
    DW_AT_NAME,
    DW_AT_COMP_DIR,
    DW_AT_STR_OFFSETS_BASE,
)
