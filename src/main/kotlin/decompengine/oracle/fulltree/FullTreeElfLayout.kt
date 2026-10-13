package decompengine.oracle.fulltree

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

data class FullTreeElfLayoutLimits(
    val maximumProgramHeaders: Int = 65_535,
    val maximumSectionHeaders: Int = 131_072,
    val maximumSymbolTables: Int = 32_768,
    val maximumSymbols: Long = 2_000_000L,
    val maximumSectionNameBytes: Int = 4096,
    val maximumTotalSectionNameBytes: Long = 8L * 1024L * 1024L,
    val maximumFunctionNameBytes: Int = 16 * 1024,
    val maximumFunctionNameCodePoints: Int = 4096,
    val maximumLocatorBytes: Int = 16 * 1024,
    val maximumParseSteps: Long = 100_000_000L,
) {
    init {
        require(maximumProgramHeaders in 1..1_000_000)
        require(maximumSectionHeaders in 1..1_000_000)
        require(maximumSymbolTables in 1..1_000_000)
        require(maximumSymbols in 1L..2_000_000L)
        require(maximumSectionNameBytes in 1..1024 * 1024)
        require(maximumTotalSectionNameBytes in 1L..256L * 1024L * 1024L)
        require(maximumFunctionNameBytes in 1..1024 * 1024)
        require(maximumFunctionNameCodePoints in 1..4096)
        require(maximumLocatorBytes in 1..1024 * 1024)
        require(maximumParseSteps in 1L..1_000_000_000L)
    }

    /** Conservative modeled heap/native working set for the bounded layout structures. */
    internal fun modeledResidentBytes(): Long = listOf(
        LAYOUT_FIXED_MODEL_BYTES,
        Math.multiplyExact(maximumProgramHeaders.toLong(), PROGRAM_HEADER_MODEL_BYTES),
        Math.multiplyExact(maximumSectionHeaders.toLong(), SECTION_HEADER_MODEL_BYTES),
        Math.multiplyExact(maximumSymbolTables.toLong(), SYMBOL_TABLE_MODEL_BYTES),
        Math.multiplyExact(maximumTotalSectionNameBytes, SECTION_NAME_MODEL_MULTIPLIER),
    ).fold(0L) { total, value -> Math.addExact(total, value) }
}

internal data class FullTreeElfExecutableRange(
    val start: ULong,
    val endExclusive: ULong,
)

/** Core ELF facts authenticated without traversing section names or symbol-table contents. */
internal data class FullTreeElfCoreLayout(
    val elfClass: Int,
    val byteOrder: Int,
    val elfType: String,
    val machine: Int,
    val osAbi: Int,
    val abiVersion: Int,
    val imageBase: ULong,
    val executableRanges: List<FullTreeElfExecutableRange>,
)

/** Merged interval index used only for membership; emitted v1 ranges remain unmerged. */
internal class FullTreeElfExecutableMembership private constructor(
    private val merged: List<FullTreeElfExecutableRange>,
) {
    fun contains(rva: ULong): Boolean {
        var low = 0
        var high = merged.lastIndex
        while (low <= high) {
            val middle = low + (high - low) / 2
            val range = merged[middle]
            when {
                rva < range.start -> high = middle - 1
                rva >= range.endExclusive -> low = middle + 1
                else -> return true
            }
        }
        return false
    }

    companion object {
        fun fromSorted(
            ranges: List<FullTreeElfExecutableRange>,
            charge: () -> Unit = {},
        ): FullTreeElfExecutableMembership {
            if (ranges.isEmpty()) return FullTreeElfExecutableMembership(emptyList())
            val result = ArrayList<FullTreeElfExecutableRange>(ranges.size)
            var current: FullTreeElfExecutableRange? = null
            ranges.forEach { range ->
                charge()
                if (range.start >= range.endExclusive) {
                    throw FullTreeControlException("ELF executable range is empty or reversed")
                }
                val previous = current
                if (previous == null) {
                    current = range
                } else {
                    if (range.start < previous.start) {
                        throw FullTreeControlException("ELF executable ranges are not sorted")
                    }
                    if (range.start <= previous.endExclusive) {
                        current = FullTreeElfExecutableRange(
                            previous.start,
                            maxOf(previous.endExclusive, range.endExclusive),
                        )
                    } else {
                        result += previous
                        current = range
                    }
                }
            }
            result += checkNotNull(current)
            return FullTreeElfExecutableMembership(result)
        }
    }
}

internal data class FullTreeElfLayoutObservation(
    val elfClass: Int,
    val byteOrder: Int,
    val elfType: String,
    val machine: Int,
    val osAbi: Int,
    val abiVersion: Int,
    val imageBase: ULong,
    val executableRanges: List<FullTreeElfExecutableRange>,
    val scannedSymbols: Long,
)

internal data class FullTreeElfFunctionSymbol(
    val name: String,
    val locator: String,
    val rva: ULong?,
)

internal enum class FullTreeElfSymbolSectionKind { DEFINED, UNDEFINED, COMMON, ABSOLUTE, RESERVED }
internal enum class FullTreeElfObjectStorage { MAPPED_LOAD, TLS, UNDEFINED, COMMON, ABSOLUTE, NONALLOC, UNMAPPED }

/** Raw PT_LOAD/PT_TLS evidence. File and memory ends are virtual addresses, not file offsets. */
internal data class FullTreeElfMemorySegment(
    val index: Int,
    val flags: Long,
    val fileOffset: ULong,
    val virtualAddress: ULong,
    val fileSize: ULong,
    val memorySize: ULong,
    val endExclusive: ULong,
    val fileEndExclusive: ULong,
    val rva: ULong?,
    /** Null means absent evidence; real ELF 0 and 1 are retained as known no-alignment values. */
    val alignment: ULong? = null,
) {
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "index" to JsonPrimitive(index), "flags" to JsonPrimitive(flags),
        "fileOffset" to elfHex(fileOffset), "virtualAddress" to elfHex(virtualAddress),
        "fileSize" to elfHex(fileSize), "memorySize" to elfHex(memorySize),
        "endExclusive" to elfHex(endExclusive), "fileEndExclusive" to elfHex(fileEndExclusive),
        "rva" to elfHex(rva),
        "alignment" to elfHex(alignment),
    ))
}

/**
 * One symbol-table entry; aliases and repeated dynamic/static entries are intentionally retained.
 * GABI symbol-table semantics distinguish TLS offsets, COMMON alignment, and absolute values:
 * https://gabi.xinuos.com/v42/elf/05-symtab.html
 */
internal class FullTreeElfObjectSymbol(
    val name: String,
    val locator: String,
    val type: Int,
    val binding: Int,
    val visibility: Int,
    val other: Int,
    val rawSectionIndex: Int,
    val resolvedSectionIndex: Long?,
    val sectionKind: FullTreeElfSymbolSectionKind,
    val sectionName: String?,
    val value: ULong,
    val size: ULong,
    val rva: ULong?,
    val storage: FullTreeElfObjectStorage,
    val sectionFlags: ULong?,
    val sectionType: Long?,
    val sectionAddress: ULong?,
    val sectionSize: ULong?,
    segmentIndices: List<Int>,
    reasons: List<String>,
) {
    val segmentIndices: List<Int> = Collections.unmodifiableList(ArrayList(segmentIndices))
    val reasons: List<String> = Collections.unmodifiableList(ArrayList(reasons))
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "name" to JsonPrimitive(name), "locator" to JsonPrimitive(locator),
        "type" to JsonPrimitive(type), "binding" to JsonPrimitive(binding),
        "visibility" to JsonPrimitive(visibility), "other" to JsonPrimitive(other),
        "rawSectionIndex" to JsonPrimitive(rawSectionIndex),
        "resolvedSectionIndex" to (resolvedSectionIndex?.let(::JsonPrimitive) ?: JsonNull),
        "sectionKind" to JsonPrimitive(sectionKind.name.lowercase()),
        "sectionName" to (sectionName?.let(::JsonPrimitive) ?: JsonNull),
        "value" to elfHex(value), "size" to elfHex(size), "rva" to elfHex(rva),
        "storage" to JsonPrimitive(storage.name.lowercase()),
        "sectionFlags" to elfHex(sectionFlags),
        "sectionType" to (sectionType?.let(::JsonPrimitive) ?: JsonNull),
        "sectionAddress" to elfHex(sectionAddress), "sectionSize" to elfHex(sectionSize),
        "segmentIndices" to JsonArray(segmentIndices.map(::JsonPrimitive)),
        "reasons" to JsonArray(reasons.map(::JsonPrimitive)),
    ))
}

internal class FullTreeElfObjectLayoutObservation(
    val elfClass: Int,
    val byteOrder: Int,
    val elfType: String,
    val machine: Int,
    val osAbi: Int,
    val abiVersion: Int,
    val imageBase: ULong,
    executableRanges: List<FullTreeElfExecutableRange>,
    val scannedSymbols: Long,
    loadedMemory: List<FullTreeElfMemorySegment>,
    tlsSegments: List<FullTreeElfMemorySegment>,
) {
    val executableRanges: List<FullTreeElfExecutableRange> = Collections.unmodifiableList(ArrayList(executableRanges))
    val loadedMemory: List<FullTreeElfMemorySegment> = Collections.unmodifiableList(ArrayList(loadedMemory))
    val tlsSegments: List<FullTreeElfMemorySegment> = Collections.unmodifiableList(ArrayList(tlsSegments))
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "elfClass" to JsonPrimitive(elfClass), "byteOrder" to JsonPrimitive(byteOrder),
        "elfType" to JsonPrimitive(elfType), "machine" to JsonPrimitive(machine),
        "osAbi" to JsonPrimitive(osAbi), "abiVersion" to JsonPrimitive(abiVersion),
        "imageBase" to elfHex(imageBase),
        "executableRanges" to JsonArray(executableRanges.map {
            JsonObject(linkedMapOf("start" to elfHex(it.start), "endExclusive" to elfHex(it.endExclusive)))
        }),
        "scannedSymbols" to JsonPrimitive(scannedSymbols),
        "loadedMemory" to JsonArray(loadedMemory.map { it.toJson() }),
        "tlsSegments" to JsonArray(tlsSegments.map { it.toJson() }),
    ))
}

private fun elfHex(value: ULong?): JsonElement = value?.let { JsonPrimitive("0x${it.toString(16)}") } ?: JsonNull

/**
 * Bounded random-access ELF reader for the v1 function-index contract.
 *
 * It deliberately implements only the ELF facts used by that contract. Both 32/64-bit classes,
 * both byte orders, ELF extended header numbering, and SHT_SYMTAB_SHNDX are handled explicitly.
 * No native parser, mmap, unbounded section materialization, or process-global parser state is
 * involved.
 */
internal object FullTreeElfLayout {
    /**
     * Reads only ELF identity, extended header metadata, and PT_LOAD layout. The returned layout
     * is path-identity checked before it escapes; section names and symbol tables are not visited.
     */
    fun scanLayout(
        file: StableControlFile,
        label: String,
        limits: FullTreeElfLayoutLimits = FullTreeElfLayoutLimits(),
        checkpoint: (String) -> Unit = {},
    ): FullTreeElfCoreLayout {
        val layout = ElfReader(file, label, limits, checkpoint).scanLayout()
        file.verifyUnchanged("$label ELF layout source")
        return layout
    }

    fun scanFunctions(
        file: StableControlFile,
        label: String,
        limits: FullTreeElfLayoutLimits = FullTreeElfLayoutLimits(),
        checkpoint: (String) -> Unit = {},
        consume: (FullTreeElfFunctionSymbol) -> Unit,
    ): FullTreeElfLayoutObservation = ElfReader(file, label, limits, checkpoint).scanFunctions(consume)

    fun scanObjects(
        file: StableControlFile,
        label: String,
        limits: FullTreeElfLayoutLimits = FullTreeElfLayoutLimits(),
        checkpoint: (String) -> Unit = {},
        consume: (FullTreeElfObjectSymbol) -> Unit,
    ): FullTreeElfObjectLayoutObservation {
        val observation = ElfReader(file, label, limits, checkpoint).scanObjects(consume)
        file.verifyUnchanged("$label ELF object source")
        return observation
    }
}

private class ElfReader(
    private val file: StableControlFile,
    private val label: String,
    private val limits: FullTreeElfLayoutLimits,
    private val checkpoint: (String) -> Unit,
) {
    private val window = ElfWindow(file, label)
    private var parseSteps = 0L

    fun scanLayout(): FullTreeElfCoreLayout = readCoreLayout(parseHeaders())

    fun scanFunctions(consume: (FullTreeElfFunctionSymbol) -> Unit): FullTreeElfLayoutObservation {
        val headers = parseHeaders()
        val sections = readNamedSections(headers)
        val core = readCoreLayout(headers)
        val membership = FullTreeElfExecutableMembership.fromSorted(core.executableRanges) {
            step("executable-range membership index")
        }
        val scanned = scanSymbols(headers, sections, objectMode = false) { symbol ->
            if (symbol.info and ELF_ST_TYPE_MASK == STT_FUNC && symbol.nameOffset != 0L) {
                val name = symbolName(symbol, "function alias")
                if (name.isNotEmpty()) {
                    val locator = symbolLocator(symbol, "function")
                    if (symbol.sectionKind == FullTreeElfSymbolSectionKind.UNDEFINED) {
                        consume(FullTreeElfFunctionSymbol(name, locator, null))
                    } else if (symbol.value >= core.imageBase) {
                        val rva = symbol.value - core.imageBase
                        if (membership.contains(rva)) consume(FullTreeElfFunctionSymbol(name, locator, rva))
                    }
                }
            }
        }
        return FullTreeElfLayoutObservation(
            core.elfClass, core.byteOrder, core.elfType, core.machine, core.osAbi, core.abiVersion,
            core.imageBase, core.executableRanges, scanned,
        )
    }

    fun scanObjects(consume: (FullTreeElfObjectSymbol) -> Unit): FullTreeElfObjectLayoutObservation {
        val headers = parseHeaders()
        val sections = readNamedSections(headers)
        val ranges = readExecutableRanges(
            headers.programOffset, headers.programEntrySize, headers.programCount,
            headers.elfClass, headers.byteOrder, includeObjectStorage = true,
        )
        val core = readCoreLayout(headers, ranges)
        val scanned = scanSymbols(headers, sections, objectMode = true) { symbol ->
            val type = symbol.info and ELF_ST_TYPE_MASK
            if (type == STT_OBJECT || type == STT_TLS) {
                consume(observeObject(symbol, sections, core, ranges))
            }
        }
        return FullTreeElfObjectLayoutObservation(
            core.elfClass, core.byteOrder, core.elfType, core.machine, core.osAbi, core.abiVersion,
            core.imageBase, core.executableRanges, scanned, ranges.loaded, ranges.tls,
        )
    }

    private fun observeObject(
        symbol: ParsedElfSymbol,
        sections: List<FunctionElfSection>,
        core: FullTreeElfCoreLayout,
        ranges: LoadedRanges,
    ): FullTreeElfObjectSymbol {
        val type = symbol.info and ELF_ST_TYPE_MASK
        val reasons = arrayListOf<String>()
        val segments = arrayListOf<Int>()
        val section = if (symbol.sectionKind == FullTreeElfSymbolSectionKind.DEFINED) {
            sections[symbol.resolvedSectionIndex.toInt()]
        } else null
        if (symbol.size == 0UL) reasons += "zero_size_metadata"
        val end = if (section == null) null else objectEnd(symbol.value, symbol.size, core.elfClass)
        if (section != null && end == null) reasons += "symbol_extent_overflows_address_width"
        var rva: ULong? = null
        val storage = when (symbol.sectionKind) {
            FullTreeElfSymbolSectionKind.UNDEFINED -> {
                reasons += "undefined_symbol_has_no_storage"
                FullTreeElfObjectStorage.UNDEFINED
            }
            FullTreeElfSymbolSectionKind.COMMON -> {
                reasons += "common_value_is_alignment_not_address"
                FullTreeElfObjectStorage.COMMON
            }
            FullTreeElfSymbolSectionKind.ABSOLUTE -> {
                reasons += "absolute_value_has_no_section_storage"
                FullTreeElfObjectStorage.ABSOLUTE
            }
            FullTreeElfSymbolSectionKind.RESERVED -> {
                reasons += "reserved_section_index_has_no_supported_storage_semantics"
                FullTreeElfObjectStorage.UNMAPPED
            }
            FullTreeElfSymbolSectionKind.DEFINED -> {
                checkNotNull(section)
                when {
                    section.type == SHT_NULL -> {
                        reasons += "inactive_section_has_no_storage"
                        FullTreeElfObjectStorage.UNMAPPED
                    }
                    section.flags and SHF_ALLOC == 0UL -> {
                        reasons += "section_is_not_allocated"
                        FullTreeElfObjectStorage.NONALLOC
                    }
                    section.flags and SHF_COMPRESSED != 0UL -> {
                        reasons += "allocated_section_is_compressed"
                        FullTreeElfObjectStorage.UNMAPPED
                    }
                    type == STT_TLS -> {
                        reasons += "tls_value_is_template_offset_not_process_address"
                        if (section.flags and SHF_TLS == 0UL) {
                            reasons += "tls_symbol_section_lacks_tls_flag"
                        } else if (end != null) {
                            ranges.tls.forEach { segment ->
                                step("TLS object storage membership")
                                if (symbol.value < segment.memorySize && end <= segment.memorySize &&
                                    ULong.MAX_VALUE - segment.virtualAddress >= symbol.value
                                ) {
                                    val address = segment.virtualAddress + symbol.value
                                    val absoluteEnd = objectEnd(address, symbol.size, core.elfClass)
                                    if (absoluteEnd != null && objectFitsSection(address, absoluteEnd, section, core.elfClass) &&
                                        objectFileMappingMatches(address, absoluteEnd, section, segment)
                                    ) segments += segment.index
                                }
                            }
                        }
                        if (segments.isEmpty()) {
                            reasons += "tls_extent_is_not_contained_in_section_and_template"
                            FullTreeElfObjectStorage.UNMAPPED
                        } else FullTreeElfObjectStorage.TLS
                    }
                    section.flags and SHF_TLS != 0UL -> {
                        reasons += "non_tls_symbol_in_tls_section"
                        FullTreeElfObjectStorage.UNMAPPED
                    }
                    end == null -> FullTreeElfObjectStorage.UNMAPPED
                    !objectFitsSection(symbol.value, end, section, core.elfClass) -> {
                        val sectionEnd = objectEnd(section.address, section.size, core.elfClass)
                        reasons += when {
                            sectionEnd == null -> "section_extent_overflows_address_width"
                            symbol.value < section.address || symbol.value >= sectionEnd -> "symbol_starts_outside_section"
                            else -> "symbol_extent_crosses_section_boundary"
                        }
                        FullTreeElfObjectStorage.UNMAPPED
                    }
                    else -> {
                        var startsInLoad = false
                        var fitsLoad = false
                        ranges.loaded.forEach { segment ->
                            step("loaded object storage membership")
                            if (symbol.value >= segment.virtualAddress && symbol.value < segment.endExclusive) {
                                startsInLoad = true
                                if (end <= segment.endExclusive) {
                                    fitsLoad = true
                                    if (objectFileMappingMatches(symbol.value, end, section, segment)) segments += segment.index
                                }
                            }
                        }
                        if (segments.isEmpty()) {
                            reasons += when {
                                !startsInLoad -> "symbol_starts_outside_load_segments"
                                !fitsLoad -> "symbol_extent_crosses_load_segment_boundary"
                                else -> "section_and_segment_file_mapping_disagree"
                            }
                            FullTreeElfObjectStorage.UNMAPPED
                        } else {
                            rva = symbol.value - core.imageBase
                            reasons += if (section.type == SHT_NOBITS) "zero_fill_storage" else "file_backed_storage"
                            FullTreeElfObjectStorage.MAPPED_LOAD
                        }
                    }
                }
            }
        }
        return FullTreeElfObjectSymbol(
            name = symbolName(symbol, "object alias"), locator = symbolLocator(symbol, "object"),
            type = type, binding = symbol.info ushr 4, visibility = symbol.other and 3, other = symbol.other,
            rawSectionIndex = symbol.rawSectionIndex,
            resolvedSectionIndex = if (section == null) null else symbol.resolvedSectionIndex,
            sectionKind = symbol.sectionKind, sectionName = section?.name,
            value = symbol.value, size = symbol.size, rva = rva, storage = storage,
            sectionFlags = section?.flags, sectionType = section?.type,
            sectionAddress = section?.address, sectionSize = section?.size,
            segmentIndices = segments, reasons = reasons,
        )
    }

    private fun objectEnd(value: ULong, size: ULong, elfClass: Int): ULong? {
        if (ULong.MAX_VALUE - value < size) return null
        val end = value + size
        if (elfClass == ELFCLASS32 && end > ELF32_ADDRESS_SPACE_END) return null
        return end
    }

    private fun objectFitsSection(value: ULong, end: ULong, section: FunctionElfSection, elfClass: Int): Boolean {
        val sectionEnd = objectEnd(section.address, section.size, elfClass) ?: return false
        // A zero-sized symbol is metadata at a real byte, never proof of an object beyond the section.
        return value >= section.address && value < sectionEnd && end <= sectionEnd
    }

    private fun objectFileMappingMatches(
        value: ULong,
        end: ULong,
        section: FunctionElfSection,
        segment: FullTreeElfMemorySegment,
    ): Boolean {
        if (section.type == SHT_NOBITS) return value >= segment.fileEndExclusive
        if (value >= segment.fileEndExclusive || end > segment.fileEndExclusive) return false
        val sectionDelta = value - section.address
        val segmentDelta = value - segment.virtualAddress
        if (ULong.MAX_VALUE - section.offset.toULong() < sectionDelta ||
            ULong.MAX_VALUE - segment.fileOffset < segmentDelta
        ) return false
        return section.offset.toULong() + sectionDelta == segment.fileOffset + segmentDelta
    }

    private fun readNamedSections(headers: ParsedElfHeaders): List<FunctionElfSection> {
        val sections = ArrayList<FunctionElfSection>(headers.sectionCount)
        repeat(headers.sectionCount) { index ->
            step("section headers")
            val offset = checkedAdd(
                headers.sectionOffset,
                checkedMultiply(index.toLong(), headers.sectionEntrySize.toLong(), "section-header offset"),
                "section-header offset",
            )
            sections += readSection(offset, headers.sectionEntrySize, headers.elfClass, headers.byteOrder, index)
        }
        return attachSectionNames(sections, headers.nameIndex)
    }

    private fun symbolName(symbol: ParsedElfSymbol, subject: String): String =
        if (symbol.nameOffset == 0L) "" else readUtf8String(
            symbol.strings, symbol.nameOffset, limits.maximumFunctionNameBytes,
            limits.maximumFunctionNameCodePoints, subject,
        )

    private fun symbolLocator(symbol: ParsedElfSymbol, subject: String): String {
        val locator = "$label:section[${symbol.tableIndex}]=${symbol.tableName}:symbol[${symbol.index}]"
        if (locator.toByteArray(StandardCharsets.UTF_8).size > limits.maximumLocatorBytes) {
            fail("$subject evidence locator exceeds its byte bound")
        }
        return locator
    }

    private fun scanSymbols(
        headers: ParsedElfHeaders,
        namedSections: List<FunctionElfSection>,
        objectMode: Boolean,
        consume: (ParsedElfSymbol) -> Unit,
    ): Long {
        val elfClass = headers.elfClass
        val byteOrder = headers.byteOrder
        val sectionCount = headers.sectionCount
        val symbolTables = namedSections.withIndex().filter { it.value.type == SHT_SYMTAB || it.value.type == SHT_DYNSYM }
        if (symbolTables.size > limits.maximumSymbolTables) fail("ELF symbol-table count exceeds its bound")
        var totalSymbols = 0L
        val tableCounts = HashMap<Int, Long>()
        symbolTables.forEach { (index, section) ->
            step("symbol tables")
            val minimumSymbolEntry = if (elfClass == ELFCLASS64) ELF64_SYMBOL_BYTES else ELF32_SYMBOL_BYTES
            if (section.flags and SHF_COMPRESSED != 0UL) fail("symbol table ${section.name} is compressed")
            if (section.entrySize < minimumSymbolEntry.toULong() || section.size % section.entrySize != 0UL) {
                fail("symbol table ${section.name} has an invalid entry size")
            }
            val count = longValue(section.size / section.entrySize, "symbol count")
            if (count < 1L) fail("symbol table ${section.name} has no STN_UNDEF entry")
            if (window.bytes(section.offset, minimumSymbolEntry).any { it != 0.toByte() }) {
                fail("symbol table ${section.name} has a nonzero STN_UNDEF entry")
            }
            totalSymbols = checkedAdd(totalSymbols, count, "aggregate symbol count")
            if (totalSymbols > limits.maximumSymbols) fail("ELF exceeds the ${limits.maximumSymbols}-symbol bound")
            tableCounts[index] = count
            val stringIndex = section.link
            if (stringIndex !in namedSections.indices || namedSections[stringIndex].type != SHT_STRTAB) {
                fail("symbol table ${section.name} has an invalid string table")
            }
            val strings = namedSections[stringIndex]
            if (strings.type == SHT_NOBITS || strings.flags and SHF_COMPRESSED != 0UL) {
                fail("symbol table ${section.name} uses a non-file-backed string table")
            }
        }
        val extendedBySymbolTable = indexExtendedSymbolSections(namedSections, tableCounts)

        var scanned = 0L
        symbolTables.forEach { (sectionIndex, section) ->
            val count = tableCounts.getValue(sectionIndex)
            val strings = namedSections[section.link]
            val extended = extendedBySymbolTable[sectionIndex]
            var symbolIndex = 0L
            while (symbolIndex < count) {
                step("symbols")
                scanned++
                val entryOffset = checkedAdd(
                    section.offset,
                    checkedMultiply(symbolIndex, longValue(section.entrySize, "symbol entry size"), "symbol offset"),
                    "symbol offset",
                )
                val entryBytes = if (elfClass == ELFCLASS64) ELF64_SYMBOL_BYTES else ELF32_SYMBOL_BYTES
                val symbol = window.bytes(entryOffset, entryBytes)
                val nameOffset: Long
                val info: Int
                val rawSectionIndex: Int
                val value: ULong
                val size: ULong
                val other: Int
                if (elfClass == ELFCLASS64) {
                    nameOffset = u32(symbol, 0, byteOrder)
                    info = symbol[4].toInt() and 0xff
                    rawSectionIndex = u16(symbol, 6, byteOrder)
                    value = u64(symbol, 8, byteOrder)
                    size = u64(symbol, 16, byteOrder)
                    other = symbol[5].toInt() and 0xff
                } else {
                    nameOffset = u32(symbol, 0, byteOrder)
                    value = u32(symbol, 4, byteOrder).toULong()
                    size = u32(symbol, 8, byteOrder).toULong()
                    other = symbol[13].toInt() and 0xff
                    info = symbol[12].toInt() and 0xff
                    rawSectionIndex = u16(symbol, 14, byteOrder)
                }
                val extendedWord = extended?.let { companion ->
                    u32At(
                        checkedAdd(
                            companion.offset,
                            checkedMultiply(symbolIndex, 4L, "extended symbol-index offset"),
                            "extended symbol-index offset",
                        ),
                        byteOrder,
                    )
                }
                val usesExtendedIndex = rawSectionIndex == SHN_XINDEX
                val resolvedSectionIndex = if (usesExtendedIndex) {
                    extendedWord ?: fail("symbol uses SHN_XINDEX without SHT_SYMTAB_SHNDX")
                } else {
                    if (extendedWord != null && extendedWord != SHN_UNDEF.toLong()) {
                        fail("SHT_SYMTAB_SHNDX has a nonzero word for a non-XINDEX symbol")
                    }
                    rawSectionIndex.toLong()
                }
                val sectionKind = classifySymbolSectionIndex(
                    resolvedSectionIndex,
                    sectionCount,
                    usesExtendedIndex,
                    objectMode,
                )
                consume(ParsedElfSymbol(
                    sectionIndex, section.name, symbolIndex, strings, nameOffset, info, other,
                    rawSectionIndex, resolvedSectionIndex, sectionKind, value, size,
                ))
                symbolIndex++
            }
        }
        return scanned
    }

    private fun parseHeaders(): ParsedElfHeaders {
        if (file.size < ELF32_HEADER_BYTES) fail("ELF header is truncated")
        val identification = window.bytes(0L, ELF_IDENT_BYTES)
        if (!identification.copyOfRange(0, 4).contentEquals(ELF_MAGIC)) fail("input is not ELF")
        val elfClass = identification[EI_CLASS].toInt() and 0xff
        if (elfClass != ELFCLASS32 && elfClass != ELFCLASS64) fail("ELF class is unsupported")
        val byteOrder = identification[EI_DATA].toInt() and 0xff
        if (byteOrder != ELFDATA2LSB && byteOrder != ELFDATA2MSB) fail("ELF byte order is unsupported")
        if ((identification[EI_VERSION].toInt() and 0xff) != EV_CURRENT) fail("ELF identification version is invalid")
        val headerBytes = if (elfClass == ELFCLASS64) ELF64_HEADER_BYTES else ELF32_HEADER_BYTES
        if (file.size < headerBytes) fail("ELF header is truncated")
        val header = window.bytes(0L, headerBytes)
        val elfTypeValue = u16(header, 16, byteOrder)
        val elfType = when (elfTypeValue) {
            ET_EXEC -> "ET_EXEC"
            ET_DYN -> "ET_DYN"
            else -> fail("ELF type is not ET_EXEC or ET_DYN")
        }
        val machine = u16(header, 18, byteOrder)
        if (u32(header, 20, byteOrder) != EV_CURRENT.toLong()) fail("ELF header version is invalid")
        val headerSize = u16(header, if (elfClass == ELFCLASS64) 52 else 40, byteOrder)
        if (headerSize != headerBytes) fail("ELF header size is noncanonical")

        val programOffset = if (elfClass == ELFCLASS64) {
            fileOffset(u64(header, 32, byteOrder), "program-header offset")
        } else {
            u32(header, 28, byteOrder)
        }
        val sectionOffset = if (elfClass == ELFCLASS64) {
            fileOffset(u64(header, 40, byteOrder), "section-header offset")
        } else {
            u32(header, 32, byteOrder)
        }
        val programEntrySize = u16(header, if (elfClass == ELFCLASS64) 54 else 42, byteOrder)
        val rawProgramCount = u16(header, if (elfClass == ELFCLASS64) 56 else 44, byteOrder)
        val sectionEntrySize = u16(header, if (elfClass == ELFCLASS64) 58 else 46, byteOrder)
        val rawSectionCount = u16(header, if (elfClass == ELFCLASS64) 60 else 48, byteOrder)
        val rawNameIndex = u16(header, if (elfClass == ELFCLASS64) 62 else 50, byteOrder)
        val minimumSectionEntry = if (elfClass == ELFCLASS64) ELF64_SECTION_BYTES else ELF32_SECTION_BYTES
        if (sectionOffset <= 0L || sectionEntrySize < minimumSectionEntry) {
            fail("ELF section table is malformed")
        }
        requireFileRange(sectionOffset, sectionEntrySize.toLong(), "ELF section zero")
        val sectionZero = readSection(sectionOffset, sectionEntrySize, elfClass, byteOrder, 0)
        validateSectionZero(sectionZero)

        val sectionCount = when (rawSectionCount) {
            0 -> {
                if (sectionZero.size < SHN_LORESERVE.toULong()) {
                    fail("extended section-header count is below the ELF threshold")
                }
                boundedCount(sectionZero.size, limits.maximumSectionHeaders, "section-header count")
            }
            else -> rawSectionCount.also {
                if (it >= SHN_LORESERVE) fail("direct section-header count uses a reserved value")
                if (it > limits.maximumSectionHeaders) fail("section-header count exceeds its bound")
                if (sectionZero.size != 0UL) fail("section zero carries an unrequested extended section count")
            }
        }
        if (sectionCount <= 0) fail("ELF has no section headers")
        val sectionTableBytes = checkedMultiply(sectionCount.toLong(), sectionEntrySize.toLong(), "section table")
        requireFileRange(sectionOffset, sectionTableBytes, "ELF section table")
        val nameIndex = when (rawNameIndex) {
            SHN_XINDEX -> sectionZero.link.also {
                if (it !in SHN_LORESERVE until sectionCount) {
                    fail("extended ELF section-name index is invalid or below its threshold")
                }
            }
            else -> rawNameIndex.also {
                if (sectionZero.link != 0) fail("section zero carries an unrequested extended name index")
                if (it >= SHN_LORESERVE) fail("direct ELF section-name index uses a reserved value")
                if (it !in 0 until sectionCount) fail("ELF section-name index is invalid")
            }
        }

        val programCount = when (rawProgramCount) {
            PN_XNUM -> sectionZero.info.also {
                if (it !in PN_XNUM..limits.maximumProgramHeaders) {
                    fail("extended program-header count is invalid, below its threshold, or exceeds its bound")
                }
            }
            else -> rawProgramCount.also {
                if (sectionZero.info != 0) fail("section zero carries an unrequested extended program count")
                if (it !in 1..limits.maximumProgramHeaders) fail("ELF has no bounded program-header table")
            }
        }
        val minimumProgramEntry = if (elfClass == ELFCLASS64) ELF64_PROGRAM_BYTES else ELF32_PROGRAM_BYTES
        if (programOffset <= 0L || programEntrySize < minimumProgramEntry) fail("ELF program table is malformed")
        requireFileRange(
            programOffset,
            checkedMultiply(programCount.toLong(), programEntrySize.toLong(), "program table"),
            "ELF program table",
        )

        return ParsedElfHeaders(
            elfClass = elfClass,
            byteOrder = byteOrder,
            elfType = elfType,
            machine = machine,
            osAbi = identification[EI_OSABI].toInt() and 0xff,
            abiVersion = identification[EI_ABIVERSION].toInt() and 0xff,
            programOffset = programOffset,
            programEntrySize = programEntrySize,
            programCount = programCount,
            sectionOffset = sectionOffset,
            sectionEntrySize = sectionEntrySize,
            sectionCount = sectionCount,
            nameIndex = nameIndex,
        )
    }

    private fun readCoreLayout(
        headers: ParsedElfHeaders,
        ranges: LoadedRanges = readExecutableRanges(
            headers.programOffset,
            headers.programEntrySize,
            headers.programCount,
            headers.elfClass,
            headers.byteOrder,
        ),
    ): FullTreeElfCoreLayout {
        val executable = ranges.executable.sortedWith(
            compareBy<FullTreeElfExecutableRange> { it.start }.thenBy { it.endExclusive },
        )
        if (executable.isEmpty()) fail("ELF has no nonempty executable PT_LOAD segment")
        return FullTreeElfCoreLayout(
            elfClass = headers.elfClass,
            byteOrder = headers.byteOrder,
            elfType = headers.elfType,
            machine = headers.machine,
            osAbi = headers.osAbi,
            abiVersion = headers.abiVersion,
            imageBase = ranges.imageBase,
            executableRanges = Collections.unmodifiableList(ArrayList(executable)),
        )
    }

    private fun attachSectionNames(
        sections: List<FunctionElfSection>,
        nameIndex: Int,
    ): List<FunctionElfSection> {
        if (nameIndex == SHN_UNDEF) {
            if (sections.any { it.nameOffset != 0L }) fail("ELF has section names without a section-name table")
            return sections
        }
        val names = sections[nameIndex]
        if (names.type != SHT_STRTAB || names.type == SHT_NOBITS || names.flags and SHF_COMPRESSED != 0UL) {
            fail("ELF section-name table is invalid")
        }
        var totalNameBytes = 0L
        return sections.map { section ->
            val name = if (section.nameOffset == 0L) "" else readUtf8String(
                names,
                section.nameOffset,
                limits.maximumSectionNameBytes,
                limits.maximumSectionNameBytes,
                "section name",
            )
            totalNameBytes = checkedAdd(
                totalNameBytes,
                name.toByteArray(StandardCharsets.UTF_8).size.toLong(),
                "aggregate section-name bytes",
            )
            if (totalNameBytes > limits.maximumTotalSectionNameBytes) {
                fail("aggregate section names exceed their byte bound")
            }
            section.copy(name = name)
        }
    }

    private fun readExecutableRanges(
        tableOffset: Long,
        entrySize: Int,
        count: Int,
        elfClass: Int,
        byteOrder: Int,
        includeObjectStorage: Boolean = false,
    ): LoadedRanges {
        val loads = arrayListOf<FullTreeElfMemorySegment>()
        val tls = arrayListOf<FullTreeElfMemorySegment>()
        repeat(count) { index ->
            step("program headers")
            val offset = checkedAdd(
                tableOffset,
                checkedMultiply(index.toLong(), entrySize.toLong(), "program-header offset"),
                "program-header offset",
            )
            val bytes = window.bytes(offset, if (elfClass == ELFCLASS64) ELF64_PROGRAM_BYTES else ELF32_PROGRAM_BYTES)
            val type = u32(bytes, 0, byteOrder)
            if (type != PT_LOAD.toLong() && !(includeObjectStorage && type == PT_TLS.toLong())) return@repeat
            val subject = if (type == PT_TLS.toLong()) "PT_TLS" else "PT_LOAD"
            val flags: Long
            val fileOffset: ULong
            val virtualAddress: ULong
            val fileSize: ULong
            val memorySize: ULong
            val alignment: ULong
            if (elfClass == ELFCLASS64) {
                flags = u32(bytes, 4, byteOrder)
                fileOffset = u64(bytes, 8, byteOrder)
                virtualAddress = u64(bytes, 16, byteOrder)
                fileSize = u64(bytes, 32, byteOrder)
                memorySize = u64(bytes, 40, byteOrder)
                alignment = u64(bytes, 48, byteOrder)
            } else {
                fileOffset = u32(bytes, 4, byteOrder).toULong()
                virtualAddress = u32(bytes, 8, byteOrder).toULong()
                fileSize = u32(bytes, 16, byteOrder).toULong()
                memorySize = u32(bytes, 20, byteOrder).toULong()
                flags = u32(bytes, 24, byteOrder)
                alignment = u32(bytes, 28, byteOrder).toULong()
            }
            // Validate the new object-storage evidence without changing historical layout/function policy.
            // GABI p_align: 0/1 means no alignment; otherwise power-of-two with congruent offset/address.
            if (includeObjectStorage && alignment > 1UL) {
                if (alignment and (alignment - 1UL) != 0UL) fail("$subject alignment is not a power of two")
                if (virtualAddress % alignment != fileOffset % alignment) {
                    fail("$subject virtual address and file offset are incongruent with its alignment")
                }
            }
            if (fileSize > memorySize) fail("$subject file size exceeds its memory size")
            requireFileRange(
                fileOffsetValue(fileOffset, "$subject file offset"),
                fileOffsetValue(fileSize, "$subject file size"),
                "$subject file range",
            )
            if (memorySize == 0UL && !includeObjectStorage) return@repeat
            val end = addUnsigned(virtualAddress, memorySize, "$subject virtual range")
            if (elfClass == ELFCLASS32 && end > ELF32_ADDRESS_SPACE_END) {
                fail("ELF32 $subject virtual range exceeds its address width")
            }
            val segment = FullTreeElfMemorySegment(
                index, flags, fileOffset, virtualAddress, fileSize, memorySize,
                end, addUnsigned(virtualAddress, fileSize, "$subject file-backed virtual range"), null, alignment,
            )
            if (type == PT_LOAD.toLong()) loads += segment else tls += segment
        }
        val nonempty = loads.filter { it.memorySize != 0UL }
        if (nonempty.isEmpty()) fail("ELF has no nonempty PT_LOAD segment")
        val imageBase = nonempty.minOf { it.virtualAddress }
        return LoadedRanges(
            imageBase,
            nonempty.filter { it.flags and PF_X != 0L }.map {
                FullTreeElfExecutableRange(it.virtualAddress - imageBase, it.endExclusive - imageBase)
            },
            loads.map { it.copy(rva = it.virtualAddress.takeIf { address -> address >= imageBase }?.minus(imageBase)) },
            // A TLS template has a linked virtual address; STT_TLS values remain offsets into it.
            tls.map { it.copy(rva = it.virtualAddress.takeIf { address -> address >= imageBase }?.minus(imageBase)) },
        )
    }

    private fun readSection(
        offset: Long,
        entrySize: Int,
        elfClass: Int,
        byteOrder: Int,
        index: Int,
    ): FunctionElfSection {
        val minimum = if (elfClass == ELFCLASS64) ELF64_SECTION_BYTES else ELF32_SECTION_BYTES
        val bytes = window.bytes(offset, minimum)
        val nameOffset = u32(bytes, 0, byteOrder)
        val type = u32(bytes, 4, byteOrder)
        val flags: ULong
        val address: ULong
        val sectionOffset: ULong
        val size: ULong
        val link: Long
        val info: Long
        val alignment: ULong
        val entry: ULong
        if (elfClass == ELFCLASS64) {
            flags = u64(bytes, 8, byteOrder)
            address = u64(bytes, 16, byteOrder)
            sectionOffset = u64(bytes, 24, byteOrder)
            size = u64(bytes, 32, byteOrder)
            link = u32(bytes, 40, byteOrder)
            info = u32(bytes, 44, byteOrder)
            alignment = u64(bytes, 48, byteOrder)
            entry = u64(bytes, 56, byteOrder)
        } else {
            flags = u32(bytes, 8, byteOrder).toULong()
            address = u32(bytes, 12, byteOrder).toULong()
            sectionOffset = u32(bytes, 16, byteOrder).toULong()
            size = u32(bytes, 20, byteOrder).toULong()
            link = u32(bytes, 24, byteOrder)
            info = u32(bytes, 28, byteOrder)
            alignment = u32(bytes, 32, byteOrder).toULong()
            entry = u32(bytes, 36, byteOrder).toULong()
        }
        val storedOffset = fileOffset(sectionOffset, "section $index offset")
        val storedSize = fileOffset(size, "section $index size")
        if (type != SHT_NOBITS && !(index == 0 && type == SHT_NULL)) {
            requireFileRange(storedOffset, storedSize, "ELF section $index")
        }
        return FunctionElfSection(
            index = index,
            name = "",
            nameOffset = nameOffset,
            type = type,
            flags = flags,
            address = address,
            offset = storedOffset,
            size = size,
            link = intValue(link, "section $index link"),
            info = intValue(info, "section $index info"),
            alignment = alignment,
            entrySize = entry,
        )
    }

    private fun validateSectionZero(section: FunctionElfSection) {
        if (section.type != SHT_NULL || section.nameOffset != 0L || section.flags != 0UL ||
            section.address != 0UL || section.offset != 0L || section.alignment != 0UL ||
            section.entrySize != 0UL
        ) fail("ELF section zero has non-null structural fields")
    }

    private fun indexExtendedSymbolSections(
        sections: List<FunctionElfSection>,
        symbolCounts: Map<Int, Long>,
    ): Map<Int, FunctionElfSection> {
        val indexed = HashMap<Int, FunctionElfSection>()
        sections.forEach { section ->
            if (section.type != SHT_SYMTAB_SHNDX) return@forEach
            step("extended symbol-index sections")
            val count = symbolCounts[section.link]
                ?: fail("SHT_SYMTAB_SHNDX companion targets a non-symbol-table section")
            if (section.flags and SHF_COMPRESSED != 0UL || section.info != 0 ||
                section.alignment != 4UL || section.entrySize != 4UL ||
                section.size != count.toULong() * 4UL
            ) fail("SHT_SYMTAB_SHNDX companion is malformed")
            if (indexed.put(section.link, section) != null) {
                fail("symbol table has multiple SHT_SYMTAB_SHNDX companions")
            }
        }
        return indexed
    }

    private fun readUtf8String(
        section: FunctionElfSection,
        rawOffset: Long,
        maximumBytes: Int,
        maximumCodePoints: Int,
        valueLabel: String,
    ): String {
        if (rawOffset < 0L || rawOffset.toULong() >= section.size) fail("$valueLabel offset exceeds its string table")
        val output = java.io.ByteArrayOutputStream(minOf(maximumBytes, 4096))
        var offset = rawOffset
        while (output.size() <= maximumBytes) {
            step("ELF strings")
            if (offset.toULong() >= section.size) fail("$valueLabel is unterminated")
            val byte = window.byte(checkedAdd(section.offset, offset, "$valueLabel offset"))
            offset++
            if (byte == 0) {
                val decoded = try {
                    StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(output.toByteArray())).toString()
                } catch (failure: Exception) {
                    throw FullTreeControlException("$label $valueLabel is not strict UTF-8", failure)
                }
                if (decoded.codePointCount(0, decoded.length) > maximumCodePoints) {
                    fail("$valueLabel exceeds its character bound")
                }
                return decoded
            }
            if (output.size() == maximumBytes) fail("$valueLabel exceeds its byte bound")
            output.write(byte)
        }
        fail("$valueLabel exceeds its byte bound")
    }

    private fun classifySymbolSectionIndex(
        value: Long,
        sectionCount: Int,
        extended: Boolean,
        objectMode: Boolean,
    ): FullTreeElfSymbolSectionKind {
        if (extended) {
            if (value in SHN_LORESERVE.toLong() until sectionCount.toLong()) {
                return FullTreeElfSymbolSectionKind.DEFINED
            }
            fail("SHN_XINDEX does not resolve to a real high section index")
        }
        return when {
            value == SHN_UNDEF.toLong() -> FullTreeElfSymbolSectionKind.UNDEFINED
            value == SHN_ABS.toLong() -> FullTreeElfSymbolSectionKind.ABSOLUTE
            value in 1 until minOf(sectionCount, SHN_LORESERVE).toLong() -> FullTreeElfSymbolSectionKind.DEFINED
            objectMode && value == SHN_COMMON.toLong() -> FullTreeElfSymbolSectionKind.COMMON
            objectMode && value >= SHN_LORESERVE -> FullTreeElfSymbolSectionKind.RESERVED
            else -> fail("symbol uses an unsupported reserved or invalid section index")
        }
    }

    private fun u32At(offset: Long, byteOrder: Int): Long = u32(window.bytes(offset, 4), 0, byteOrder)

    private fun step(subject: String) {
        parseSteps = checkedAdd(parseSteps, 1L, "ELF parse-step count")
        if (parseSteps > limits.maximumParseSteps) fail("ELF parse-step bound exceeded")
        if (parseSteps == 1L || parseSteps % CHECKPOINT_STEPS == 0L) checkpoint("while parsing $label $subject")
    }

    private fun requireFileRange(offset: Long, length: Long, subject: String) {
        if (offset < 0L || length < 0L || offset > file.size - length) fail("$subject exceeds the file")
    }

    private fun fail(message: String): Nothing = throw FullTreeControlException("$label $message")
}

private data class ParsedElfHeaders(
    val elfClass: Int,
    val byteOrder: Int,
    val elfType: String,
    val machine: Int,
    val osAbi: Int,
    val abiVersion: Int,
    val programOffset: Long,
    val programEntrySize: Int,
    val programCount: Int,
    val sectionOffset: Long,
    val sectionEntrySize: Int,
    val sectionCount: Int,
    val nameIndex: Int,
)

private data class LoadedRanges(
    val imageBase: ULong,
    val executable: List<FullTreeElfExecutableRange>,
    val loaded: List<FullTreeElfMemorySegment>,
    val tls: List<FullTreeElfMemorySegment>,
)

private data class ParsedElfSymbol(
    val tableIndex: Int,
    val tableName: String,
    val index: Long,
    val strings: FunctionElfSection,
    val nameOffset: Long,
    val info: Int,
    val other: Int,
    val rawSectionIndex: Int,
    val resolvedSectionIndex: Long,
    val sectionKind: FullTreeElfSymbolSectionKind,
    val value: ULong,
    val size: ULong,
)

private data class FunctionElfSection(
    val index: Int,
    val name: String,
    val nameOffset: Long,
    val type: Long,
    val flags: ULong,
    val address: ULong,
    val offset: Long,
    val size: ULong,
    val link: Int,
    val info: Int,
    val alignment: ULong,
    val entrySize: ULong,
)

private class ElfWindow(
    private val file: StableControlFile,
    private val label: String,
) {
    private var start = -1L
    private var content = ByteArray(0)

    fun byte(offset: Long): Int {
        if (offset < start || offset >= start + content.size) {
            if (offset < 0L || offset >= file.size) throw FullTreeControlException("$label ELF read exceeds the file")
            start = offset
            content = file.readExactly(offset, minOf(WINDOW_BYTES.toLong(), file.size - offset).toInt(), "$label ELF")
        }
        return content[(offset - start).toInt()].toInt() and 0xff
    }

    fun bytes(offset: Long, length: Int): ByteArray {
        if (length < 0 || offset < 0L || offset > file.size - length.toLong()) {
            throw FullTreeControlException("$label ELF read exceeds the file")
        }
        if (length <= WINDOW_BYTES && offset >= start && offset <= start + content.size - length) {
            return content.copyOfRange((offset - start).toInt(), (offset - start).toInt() + length)
        }
        return file.readExactly(offset, length, "$label ELF")
    }
}

private fun u16(bytes: ByteArray, offset: Int, order: Int): Int {
    val first = bytes[offset].toInt() and 0xff
    val second = bytes[offset + 1].toInt() and 0xff
    return if (order == ELFDATA2LSB) first or (second shl 8) else (first shl 8) or second
}

private fun u32(bytes: ByteArray, offset: Int, order: Int): Long {
    var value = 0L
    repeat(4) { index ->
        val source = if (order == ELFDATA2LSB) offset + 3 - index else offset + index
        value = (value shl 8) or (bytes[source].toLong() and 0xffL)
    }
    return value
}

private fun u64(bytes: ByteArray, offset: Int, order: Int): ULong {
    var value = 0UL
    repeat(8) { index ->
        val source = if (order == ELFDATA2LSB) offset + 7 - index else offset + index
        value = (value shl 8) or (bytes[source].toULong() and 0xffUL)
    }
    return value
}

private fun checkedAdd(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeControlException("$label overflows", failure)
}

private fun checkedMultiply(left: Long, right: Long, label: String): Long = try {
    Math.multiplyExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeControlException("$label overflows", failure)
}

private fun addUnsigned(left: ULong, right: ULong, label: String): ULong {
    if (ULong.MAX_VALUE - left < right) throw FullTreeControlException("$label overflows")
    return left + right
}

private fun fileOffset(value: ULong, label: String): Long {
    if (value > Long.MAX_VALUE.toULong()) throw FullTreeControlException("$label exceeds the supported file range")
    return value.toLong()
}

private fun fileOffsetValue(value: ULong, label: String): Long = fileOffset(value, label)

private fun longValue(value: ULong, label: String): Long {
    if (value > Long.MAX_VALUE.toULong()) throw FullTreeControlException("$label exceeds the supported range")
    return value.toLong()
}

private fun intValue(value: Long, label: String): Int {
    if (value !in 0L..Int.MAX_VALUE.toLong()) throw FullTreeControlException("$label exceeds the supported range")
    return value.toInt()
}

private fun boundedCount(value: ULong, maximum: Int, label: String): Int {
    if (value == 0UL || value > maximum.toULong()) throw FullTreeControlException("$label exceeds its bound")
    return value.toInt()
}

private const val ELF_IDENT_BYTES = 16
private const val ELF32_HEADER_BYTES = 52
private const val ELF64_HEADER_BYTES = 64
private const val ELF32_PROGRAM_BYTES = 32
private const val ELF64_PROGRAM_BYTES = 56
private const val ELF32_SECTION_BYTES = 40
private const val ELF64_SECTION_BYTES = 64
private const val ELF32_SYMBOL_BYTES = 16
private const val ELF64_SYMBOL_BYTES = 24
private const val WINDOW_BYTES = 64 * 1024
private const val CHECKPOINT_STEPS = 4096L
private const val LAYOUT_FIXED_MODEL_BYTES = 8L * 1024L * 1024L
private const val PROGRAM_HEADER_MODEL_BYTES = 256L
private const val SECTION_HEADER_MODEL_BYTES = 256L
private const val SYMBOL_TABLE_MODEL_BYTES = 256L
private const val SECTION_NAME_MODEL_MULTIPLIER = 3L
private const val EI_CLASS = 4
private const val EI_DATA = 5
private const val EI_VERSION = 6
private const val EI_OSABI = 7
private const val EI_ABIVERSION = 8
private const val ELFCLASS32 = 1
private const val ELFCLASS64 = 2
private const val ELFDATA2LSB = 1
private const val ELFDATA2MSB = 2
private const val EV_CURRENT = 1
private const val ET_EXEC = 2
private const val ET_DYN = 3
private const val PT_TLS = 7
private const val PT_LOAD = 1
private const val PF_X = 1L
private const val SHT_SYMTAB = 2L
private const val SHT_NULL = 0L
private const val SHT_STRTAB = 3L
private const val SHT_NOBITS = 8L
private const val SHT_DYNSYM = 11L
private const val SHT_SYMTAB_SHNDX = 18L
private const val SHF_ALLOC = 0x2UL
private const val SHF_TLS = 0x400UL
private const val SHF_COMPRESSED = 0x800UL
private const val SHN_UNDEF = 0
private const val SHN_LORESERVE = 0xff00
private const val SHN_COMMON = 0xfff2
private const val SHN_ABS = 0xfff1
private const val SHN_XINDEX = 0xffff
private const val PN_XNUM = 0xffff
private const val STT_OBJECT = 1
private const val STT_TLS = 6
private const val STT_FUNC = 2
private const val ELF_ST_TYPE_MASK = 0x0f
private val ELF32_ADDRESS_SPACE_END = 1UL shl 32
private val ELF_MAGIC = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
