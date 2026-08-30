package decompengine.oracle.fulltree

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

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

/**
 * Bounded random-access ELF reader for the v1 function-index contract.
 *
 * It deliberately implements only the ELF facts used by that contract. Both 32/64-bit classes,
 * both byte orders, ELF extended header numbering, and SHT_SYMTAB_SHNDX are handled explicitly.
 * No native parser, mmap, unbounded section materialization, or process-global parser state is
 * involved.
 */
internal object FullTreeElfLayout {
    fun scanFunctions(
        file: StableControlFile,
        label: String,
        limits: FullTreeElfLayoutLimits = FullTreeElfLayoutLimits(),
        checkpoint: (String) -> Unit = {},
        consume: (FullTreeElfFunctionSymbol) -> Unit,
    ): FullTreeElfLayoutObservation = ElfReader(file, label, limits, checkpoint).scan(consume)
}

private class ElfReader(
    private val file: StableControlFile,
    private val label: String,
    private val limits: FullTreeElfLayoutLimits,
    private val checkpoint: (String) -> Unit,
) {
    private val window = ElfWindow(file, label)
    private var parseSteps = 0L

    fun scan(consume: (FullTreeElfFunctionSymbol) -> Unit): FullTreeElfLayoutObservation {
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

        val sections = ArrayList<FunctionElfSection>(sectionCount)
        repeat(sectionCount) { index ->
            step("section headers")
            val offset = checkedAdd(
                sectionOffset,
                checkedMultiply(index.toLong(), sectionEntrySize.toLong(), "section-header offset"),
                "section-header offset",
            )
            sections += readSection(offset, sectionEntrySize, elfClass, byteOrder, index)
        }
        val namedSections = attachSectionNames(sections, nameIndex)
        val ranges = readExecutableRanges(programOffset, programEntrySize, programCount, elfClass, byteOrder)
        val imageBase = ranges.imageBase
        val executable = ranges.executable.sortedWith(compareBy<FullTreeElfExecutableRange> { it.start }.thenBy { it.endExclusive })
        if (executable.isEmpty()) fail("ELF has no nonempty executable PT_LOAD segment")
        val executableMembership = FullTreeElfExecutableMembership.fromSorted(executable) {
            step("executable-range membership index")
        }

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
                if (elfClass == ELFCLASS64) {
                    nameOffset = u32(symbol, 0, byteOrder)
                    info = symbol[4].toInt() and 0xff
                    rawSectionIndex = u16(symbol, 6, byteOrder)
                    value = u64(symbol, 8, byteOrder)
                } else {
                    nameOffset = u32(symbol, 0, byteOrder)
                    value = u32(symbol, 4, byteOrder).toULong()
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
                )
                if (info and ELF_ST_TYPE_MASK == STT_FUNC && nameOffset != 0L) {
                    val name = readUtf8String(
                        strings,
                        nameOffset,
                        limits.maximumFunctionNameBytes,
                        limits.maximumFunctionNameCodePoints,
                        "function alias",
                    )
                    if (name.isNotEmpty()) {
                        val locator = "$label:section[$sectionIndex]=${section.name}:symbol[$symbolIndex]"
                        if (locator.toByteArray(StandardCharsets.UTF_8).size > limits.maximumLocatorBytes) {
                            fail("function evidence locator exceeds its byte bound")
                        }
                        if (sectionKind == SymbolSectionKind.UNDEFINED) {
                            consume(FullTreeElfFunctionSymbol(name, locator, null))
                        } else if (value >= imageBase) {
                            val rva = value - imageBase
                            if (executableMembership.contains(rva)) {
                                consume(FullTreeElfFunctionSymbol(name, locator, rva))
                            }
                        }
                    }
                }
                symbolIndex++
            }
        }
        return FullTreeElfLayoutObservation(
            elfClass = elfClass,
            byteOrder = byteOrder,
            elfType = elfType,
            machine = machine,
            osAbi = identification[EI_OSABI].toInt() and 0xff,
            abiVersion = identification[EI_ABIVERSION].toInt() and 0xff,
            imageBase = imageBase,
            executableRanges = executable,
            scannedSymbols = scanned,
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
    ): LoadedRanges {
        val loads = arrayListOf<Pair<ULong, ULong>>()
        val executable = arrayListOf<Pair<ULong, ULong>>()
        repeat(count) { index ->
            step("program headers")
            val offset = checkedAdd(
                tableOffset,
                checkedMultiply(index.toLong(), entrySize.toLong(), "program-header offset"),
                "program-header offset",
            )
            val bytes = window.bytes(offset, if (elfClass == ELFCLASS64) ELF64_PROGRAM_BYTES else ELF32_PROGRAM_BYTES)
            val type = u32(bytes, 0, byteOrder)
            if (type != PT_LOAD.toLong()) return@repeat
            val flags: Long
            val fileOffset: ULong
            val virtualAddress: ULong
            val fileSize: ULong
            val memorySize: ULong
            if (elfClass == ELFCLASS64) {
                flags = u32(bytes, 4, byteOrder)
                fileOffset = u64(bytes, 8, byteOrder)
                virtualAddress = u64(bytes, 16, byteOrder)
                fileSize = u64(bytes, 32, byteOrder)
                memorySize = u64(bytes, 40, byteOrder)
            } else {
                fileOffset = u32(bytes, 4, byteOrder).toULong()
                virtualAddress = u32(bytes, 8, byteOrder).toULong()
                fileSize = u32(bytes, 16, byteOrder).toULong()
                memorySize = u32(bytes, 20, byteOrder).toULong()
                flags = u32(bytes, 24, byteOrder)
            }
            if (fileSize > memorySize) fail("PT_LOAD file size exceeds its memory size")
            requireFileRange(
                fileOffsetValue(fileOffset, "PT_LOAD file offset"),
                fileOffsetValue(fileSize, "PT_LOAD file size"),
                "PT_LOAD file range",
            )
            if (memorySize == 0UL) return@repeat
            val end = addUnsigned(virtualAddress, memorySize, "PT_LOAD virtual range")
            if (elfClass == ELFCLASS32 && end > ELF32_ADDRESS_SPACE_END) {
                fail("ELF32 PT_LOAD virtual range exceeds its address width")
            }
            loads += virtualAddress to end
            if (flags and PF_X != 0L) executable += virtualAddress to end
        }
        if (loads.isEmpty()) fail("ELF has no nonempty PT_LOAD segment")
        val imageBase = loads.minOf { it.first }
        return LoadedRanges(
            imageBase,
            executable.map { (start, end) -> FullTreeElfExecutableRange(start - imageBase, end - imageBase) },
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
    ): SymbolSectionKind {
        if (extended) {
            if (value in SHN_LORESERVE.toLong() until sectionCount.toLong()) {
                return SymbolSectionKind.DEFINED
            }
            fail("SHN_XINDEX does not resolve to a real high section index")
        }
        return when {
            value == SHN_UNDEF.toLong() -> SymbolSectionKind.UNDEFINED
            value == SHN_ABS.toLong() -> SymbolSectionKind.DEFINED
            value in 1 until minOf(sectionCount, SHN_LORESERVE).toLong() -> SymbolSectionKind.DEFINED
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

private data class LoadedRanges(
    val imageBase: ULong,
    val executable: List<FullTreeElfExecutableRange>,
)

private enum class SymbolSectionKind {
    UNDEFINED,
    DEFINED,
}

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
private const val PT_LOAD = 1
private const val PF_X = 1L
private const val SHT_SYMTAB = 2L
private const val SHT_NULL = 0L
private const val SHT_STRTAB = 3L
private const val SHT_NOBITS = 8L
private const val SHT_DYNSYM = 11L
private const val SHT_SYMTAB_SHNDX = 18L
private const val SHF_COMPRESSED = 0x800UL
private const val SHN_UNDEF = 0
private const val SHN_LORESERVE = 0xff00
private const val SHN_ABS = 0xfff1
private const val SHN_XINDEX = 0xffff
private const val PN_XNUM = 0xffff
private const val STT_FUNC = 2
private const val ELF_ST_TYPE_MASK = 0x0f
private val ELF32_ADDRESS_SPACE_END = 1UL shl 32
private val ELF_MAGIC = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
