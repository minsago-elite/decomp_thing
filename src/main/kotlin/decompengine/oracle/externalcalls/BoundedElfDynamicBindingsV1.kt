package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeControlException
import decompengine.oracle.fulltree.FullTreeElfDynamicStructure
import decompengine.oracle.fulltree.FullTreeElfLayout
import decompengine.oracle.fulltree.FullTreeElfLayoutLimits
import decompengine.oracle.fulltree.FullTreeElfMemorySegment
import decompengine.oracle.fulltree.FullTreeElfRawDynamicSymbol
import decompengine.oracle.fulltree.FullTreeElfRawProgramHeader
import decompengine.oracle.fulltree.FullTreeElfRawSection
import decompengine.oracle.fulltree.FullTreeElfSymbolSectionKind
import decompengine.oracle.fulltree.StableControlFile
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Limits apply before accumulation; work includes range comparisons and string bytes. */
internal data class ElfDynamicBindingLimitsV1(
    val maximumDynamicEntries: Int = 65_536,
    val maximumDynamicSymbols: Int = 131_072,
    val maximumRelocations: Int = 1_000_000,
    val maximumVersionRecords: Int = 131_072,
    val maximumStringBytes: Int = 16 * 1024,
    val maximumTotalStringBytes: Long = 8L * 1024 * 1024,
    val maximumReadBytes: Long = 256L * 1024 * 1024,
    val maximumWorkUnits: Long = 100_000_000,
    val maximumOutputBytes: Int = 64 * 1024 * 1024,
    val layout: FullTreeElfLayoutLimits = FullTreeElfLayoutLimits(),
) {
    init {
        require(maximumDynamicEntries in 1..65_536 && maximumDynamicSymbols in 1..131_072)
        require(maximumRelocations in 1..1_000_000 && maximumVersionRecords in 1..131_072)
        require(maximumStringBytes in 1..16 * 1024 && maximumTotalStringBytes in 1..8L * 1024 * 1024)
        require(maximumReadBytes in 1..256L * 1024 * 1024 && maximumWorkUnits in 1..100_000_000)
        require(maximumOutputBytes in 1..64 * 1024 * 1024)
    }
}

internal data class ElfDynamicEntryV1(val index: Int, val fileOffset: Long, val tag: ULong, val value: ULong)
internal data class ElfVersionRequirementV1(
    val sectionIndex: Int, val stringSectionIndex: Int, val recordOffset: Long, val auxiliaryOffset: Long,
    val providerRequest: String, val providerRequestOffset: Long, val name: String, val nameOffset: Long,
    val rawIndex: Int, val index: Int, val flags: Int, val hash: Long,
)
internal data class ElfVersionDefinitionV1(
    val sectionIndex: Int, val stringSectionIndex: Int, val recordOffset: Long,
    val rawIndex: Int, val index: Int, val flags: Int, val hash: Long,
    val name: String, val parentNames: List<String>, val auxiliaryOffsets: List<Long>, val auxiliaryNameOffsets: List<Long>,
)
internal data class ElfSymbolVersionV1(
    val sectionIndex: Int, val fileOffset: Long, val raw: Int, val index: Int, val hidden: Boolean,
    val kind: String, val name: String?, val providerRequest: String?,
)
internal data class ElfDynamicSymbolV1(val raw: FullTreeElfRawDynamicSymbol, val version: ElfSymbolVersionV1?) {
    val tableSectionIndex: Int get() = raw.tableSectionIndex
    val symbolIndex: Long get() = raw.symbolIndex
    val name: String get() = raw.name
    val type: Int get() = raw.info and 15
    val binding: Int get() = raw.info ushr 4
    val visibility: Int get() = raw.other and 3
}
internal data class ElfDynamicRelocationV1(
    val sectionIndex: Int, val relocationIndex: Long, val fileOffset: Long, val locator: String,
    val symbolTableSectionIndex: Int, val symbolIndex: Long, val offset: ULong, val type: Long,
    val addend: Long?, val dynamicTables: List<String>, val slotFileOffset: Long?,
    val slotLoadIndices: List<Int>, val dispositions: List<String>,
)

/**
 * Section-declared raw evidence, not a complete runtime namespace or a call population. A provider
 * request is a VERNEED string, never an observed runtime provider. All authority flags stay false.
 */
internal class ElfDynamicBindingInventoryV1(
    val inputSha256: String, val imageBase: ULong, val activeSymbolTableSectionIndex: Int,
    val structure: FullTreeElfDynamicStructure,
    dynamicEntries: List<ElfDynamicEntryV1>, dynamicSymbols: List<ElfDynamicSymbolV1>,
    relocations: List<ElfDynamicRelocationV1>, versionRequirements: List<ElfVersionRequirementV1>,
    versionDefinitions: List<ElfVersionDefinitionV1>, neededLibraries: List<String>, unsupportedReasons: List<String>,
) {
    val sections: List<FullTreeElfRawSection> get() = structure.sections
    val programHeaders: List<FullTreeElfRawProgramHeader> get() = structure.programHeaders
    val loadedMemory: List<FullTreeElfMemorySegment> get() = structure.loadedMemory
    val dynamicEntries = immutable(dynamicEntries)
    val dynamicSymbols = immutable(dynamicSymbols)
    val relocations = immutable(relocations)
    val versionRequirements = immutable(versionRequirements)
    val versionDefinitions = immutable(versionDefinitions)
    val neededLibraries = immutable(neededLibraries)
    val unsupportedReasons = immutable(unsupportedReasons)

    fun toJson(): JsonObject = obj(
        "schemaVersion" to n(1), "kind" to s("independent-elf-dynamic-bindings-v1"),
        "authority" to s("diagnostic-authenticated-elf-metadata"), "inputSha256" to s(inputSha256),
        "elfClass" to n(structure.core.elfClass), "byteOrder" to n(structure.core.byteOrder),
        "elfType" to s(structure.core.elfType), "machine" to n(structure.core.machine),
        "imageBase" to h(imageBase), "activeSymbolTableSectionIndex" to n(activeSymbolTableSectionIndex),
        "symbolPopulationBasis" to s("section-declared-dynsym"),
        "complete" to b(false), "releaseEligible" to b(false), "negativeCompleteness" to b(false),
        "sections" to array(sections.map { obj("index" to n(it.index), "name" to s(it.name), "type" to n(it.type),
            "flags" to h(it.flags), "address" to h(it.address), "offset" to n(it.offset), "size" to h(it.size),
            "link" to n(it.link), "info" to n(it.info), "alignment" to h(it.alignment), "entrySize" to h(it.entrySize)) }),
        "programHeaders" to array(programHeaders.map { obj("index" to n(it.index), "type" to n(it.type),
            "flags" to n(it.flags), "offset" to h(it.offset), "virtualAddress" to h(it.virtualAddress),
            "physicalAddress" to h(it.physicalAddress), "fileSize" to h(it.fileSize), "memorySize" to h(it.memorySize),
            "alignment" to h(it.alignment)) }),
        "dynamicEntries" to array(dynamicEntries.map { obj("index" to n(it.index), "fileOffset" to n(it.fileOffset),
            "tag" to h(it.tag), "value" to h(it.value)) }),
        "dynamicSymbols" to array(dynamicSymbols.map { symbol -> val raw = symbol.raw
            obj("tableSectionIndex" to n(raw.tableSectionIndex), "symbolIndex" to n(raw.symbolIndex),
                "locator" to s(raw.locator), "nameOffset" to n(raw.nameOffset), "name" to s(raw.name),
                "info" to n(raw.info), "other" to n(raw.other), "type" to n(symbol.type), "binding" to n(symbol.binding),
                "visibility" to n(symbol.visibility), "rawSectionIndex" to n(raw.rawSectionIndex),
                "resolvedSectionIndex" to n(raw.resolvedSectionIndex), "sectionKind" to s(raw.sectionKind.name.lowercase()),
                "value" to h(raw.value), "size" to h(raw.size), "version" to (symbol.version?.let { version ->
                    obj("sectionIndex" to n(version.sectionIndex), "fileOffset" to n(version.fileOffset),
                        "raw" to n(version.raw), "index" to n(version.index), "hidden" to b(version.hidden),
                        "kind" to s(version.kind), "name" to nullable(version.name),
                        "providerRequest" to nullable(version.providerRequest)) } ?: JsonNull)) }),
        "relocations" to array(relocations.map { obj("sectionIndex" to n(it.sectionIndex),
            "relocationIndex" to n(it.relocationIndex), "fileOffset" to n(it.fileOffset), "locator" to s(it.locator),
            "symbolTableSectionIndex" to n(it.symbolTableSectionIndex), "symbolIndex" to n(it.symbolIndex),
            "offset" to h(it.offset), "type" to n(it.type), "addend" to (it.addend?.let(::n) ?: JsonNull),
            "dynamicTables" to strings(it.dynamicTables), "slotFileOffset" to (it.slotFileOffset?.let(::n) ?: JsonNull),
            "slotLoadIndices" to array(it.slotLoadIndices.map(::n)), "dispositions" to strings(it.dispositions)) }),
        "versionRequirements" to array(versionRequirements.map { obj("sectionIndex" to n(it.sectionIndex),
            "stringSectionIndex" to n(it.stringSectionIndex), "recordOffset" to n(it.recordOffset),
            "auxiliaryOffset" to n(it.auxiliaryOffset), "providerRequest" to s(it.providerRequest),
            "providerRequestOffset" to n(it.providerRequestOffset), "name" to s(it.name), "nameOffset" to n(it.nameOffset),
            "rawIndex" to n(it.rawIndex), "index" to n(it.index), "flags" to n(it.flags), "hash" to n(it.hash)) }),
        "versionDefinitions" to array(versionDefinitions.map { obj("sectionIndex" to n(it.sectionIndex),
            "stringSectionIndex" to n(it.stringSectionIndex), "recordOffset" to n(it.recordOffset),
            "rawIndex" to n(it.rawIndex), "index" to n(it.index), "flags" to n(it.flags), "hash" to n(it.hash),
            "name" to s(it.name), "parentNames" to strings(it.parentNames),
            "auxiliaryOffsets" to array(it.auxiliaryOffsets.map(::n)),
            "auxiliaryNameOffsets" to array(it.auxiliaryNameOffsets.map(::n))) }),
        "neededLibraries" to strings(neededLibraries), "unsupportedReasons" to strings(unsupportedReasons),
    )
}

internal object BoundedElfDynamicBindingsV1 {
    fun scan(
        file: StableControlFile, expectedInputSha256: String,
        limits: ElfDynamicBindingLimitsV1 = ElfDynamicBindingLimitsV1(), checkpoint: (String) -> Unit = {},
    ): ElfDynamicBindingInventoryV1 {
        require(expectedInputSha256.matches(Regex("[0-9a-f]{64}")))
        require(file.authenticatedSha256 == expectedInputSha256) { "dynamic-binding ELF identity mismatch" }
        val result = Reader(file, limits, checkpoint).scan()
        file.verifyUnchanged("dynamic-binding ELF source")
        return result
    }
}

private class Reader(
    val file: StableControlFile, val limits: ElfDynamicBindingLimitsV1, val checkpoint: (String) -> Unit,
) {
    var work = 0L; var reads = 0L; var output = 4096L; var stringBytes = 0L; var versionRecords = 0
    lateinit var structure: FullTreeElfDynamicStructure
    lateinit var activeSymbols: FullTreeElfRawSection
    lateinit var activeStrings: FullTreeElfRawSection
    val entries = arrayListOf<ElfDynamicEntryV1>()
    val requirements = arrayListOf<ElfVersionRequirementV1>()
    val definitions = arrayListOf<ElfVersionDefinitionV1>()
    val unsupported = sortedSetOf("runtime-provider-and-interposition-unresolved", "dynamic-hash-population-not-reconciled")
    val singleton = hashMapOf<ULong, ULong>()
    val taggedRanges = arrayListOf<RelocationRange>()

    fun scan(): ElfDynamicBindingInventoryV1 {
        val rawSymbols = arrayListOf<FullTreeElfRawDynamicSymbol>()
        structure = FullTreeElfLayout.scanDynamicStructure(file, "dynamic-binding", limits.layout.copy(
            maximumFunctionNameBytes = minOf(limits.layout.maximumFunctionNameBytes, limits.maximumStringBytes),
            maximumParseSteps = minOf(limits.layout.maximumParseSteps, limits.maximumWorkUnits)), checkpoint,
            charge = ::step, chargeRead = ::chargeRead) { symbol ->
            step(); requireBound(rawSymbols.size < limits.maximumDynamicSymbols, "dynamic symbol count")
            retain(1024L); retainString(symbol.name); retainString(symbol.locator); rawSymbols += symbol
        }
        requireBound(structure.core.elfClass == 2 && structure.core.byteOrder == 1 && structure.core.machine == 62,
            "unsupported capability: requires ELF64 little-endian x86-64")
        structure.sections.forEach { step(); retain(512); retainString(it.name) }
        structure.programHeaders.forEach { step(); retain(384) }
        val dynamicPrograms = structure.programHeaders.filter { step(); it.type == 2L }
        requireBound(dynamicPrograms.size == 1, "unsupported capability: requires exactly one PT_DYNAMIC")
        val dynamicProgram = dynamicPrograms.single()
        val dynamicSections = structure.sections.filter { step(); it.type == 6L }
        requireBound(dynamicSections.size == 1, "unsupported capability: requires exactly one SHT_DYNAMIC")
        val dynamic = dynamicSections.single()
        requireBound(dynamic.offset.toULong() == dynamicProgram.offset && dynamic.address == dynamicProgram.virtualAddress &&
            dynamic.size == dynamicProgram.fileSize && dynamicProgram.fileSize <= dynamicProgram.memorySize,
            "PT_DYNAMIC and SHT_DYNAMIC disagree")
        metadataSection(dynamic)
        requireBound(dynamic.entrySize == 16UL && dynamic.size > 0UL && dynamic.size % 16UL == 0UL,
            "invalid dynamic entry size")
        requireBound(dynamic.size / 16UL <= limits.maximumDynamicEntries.toULong(), "dynamic entry count")
        var terminated = false
        repeat((dynamic.size / 16UL).toInt()) { index ->
            val position = add(dynamic.offset, index.toLong() * 16)
            val bytes = read(position, 16)
            val tag = u64(bytes, 0); val value = u64(bytes, 8)
            if (terminated) requireBound(tag == 0UL && value == 0UL, "non-null entries after DT_NULL")
            retain(160); entries += ElfDynamicEntryV1(index, position, tag, value)
            if (tag == 0UL) terminated = true
            else if (tag in SINGLETON_TAGS) requireBound(singleton.put(tag, value) == null, "duplicate dynamic singleton tag")
        }
        requireBound(terminated, "unterminated PT_DYNAMIC")
        val symAddress = required(6UL)
        activeSymbols = uniqueSection(11L, symAddress)
        requireBound(activeSymbols.entrySize == 24UL && required(11UL) == 24UL, "DT_SYMENT disagrees with ELF64 symbol width")
        metadataSection(activeSymbols)
        activeStrings = section(activeSymbols.link, 3L)
        requireBound(dynamic.link == activeStrings.index && required(5UL) == activeStrings.address &&
            required(10UL) == activeStrings.size, "dynamic symbol/string table metadata disagree")
        metadataSection(activeStrings); stringBoundaries(activeStrings)
        val symbolsByTable = rawSymbols.groupBy { step(); it.tableSectionIndex }
        structure.sections.filter { step(); it.type == 11L }.forEach { table ->
            requireBound(table.entrySize == 24UL && table.info.toULong() in 1UL..(table.size / 24UL), "invalid DYNSYM shape")
            val tableStrings = section(table.link, 3L); stringBoundaries(tableStrings)
            symbolsByTable.getValue(table.index).forEach { symbol ->
                step(); requireBound((symbol.info ushr 4 == 0) == (symbol.symbolIndex < table.info), "DYNSYM local-symbol boundary mismatch")
            }
            if (table.index != activeSymbols.index) unsupported += "inactive-dynsym-table-retained"
        }
        val needed = entries.filter { step(); it.tag == 1UL }.map { string(activeStrings, it.value) }
        entries.forEach { entry ->
            step()
            when (entry.tag) {
                35UL, 36UL, 37UL -> unsupported += "packed-relr-relocations-not-expanded"
                0x6000000fUL, 0x60000010UL, 0x60000011UL, 0x60000012UL,
                0x6fffe000UL, 0x6fffe001UL, 0x6fffe003UL -> unsupported += "android-packed-relocations-not-expanded"
                0x7ffffffdUL, 0x7fffffffUL -> unsupported += "dynamic-filter-provider-selection-unresolved"
                else -> if (entry.tag !in KNOWN_DYNAMIC_TAGS) unsupported += "unclassified-dynamic-tag"
            }
        }
        parseVersionSections()
        val versions = parseSymbolVersions(symbolsByTable)
        validateVersionTags(0x6ffffffeUL, 0x6fffffffUL, 0x6ffffffeL)
        validateVersionTags(0x6ffffffcUL, 0x6ffffffdUL, 0x6ffffffdL)
        val activeVersionSections = structure.sections.filter { step(); it.type == 0x6fffffffL && it.link == activeSymbols.index }
        requireBound((singleton[0x6ffffff0UL] == null) == activeVersionSections.isEmpty(), "DT_VERSYM presence mismatch")
        singleton[0x6ffffff0UL]?.let { pointer ->
            requireBound(activeVersionSections.size == 1 && activeVersionSections.single().address == pointer, "DT_VERSYM pointer mismatch")
        }
        addRelocationRange("rela", 7UL, 8UL, 9UL, 4L, 24)
        addRelocationRange("rel", 17UL, 18UL, 19UL, 9L, 16)
        val jumpKeys = listOf(23UL, 2UL, 20UL)
        if (jumpKeys.any { singleton.containsKey(it) }) {
            requireBound(jumpKeys.all { singleton.containsKey(it) }, "incomplete JMPREL tags")
            val kind = required(20UL)
            requireBound(kind == 7UL || kind == 17UL, "invalid DT_PLTREL type")
            addRange("jmprel", required(23UL), required(2UL), if (kind == 7UL) 4L else 9L, if (kind == 7UL) 24 else 16)
        }
        val symbols = rawSymbols.map { step(); ElfDynamicSymbolV1(it, versions[it.tableSectionIndex to it.symbolIndex]) }
        val relocations = parseRelocations(symbols.associateBy { step(); it.tableSectionIndex to it.symbolIndex })
        validateRelativePrefix(relocations, 0x6ffffff9UL, "rela")
        validateRelativePrefix(relocations, 0x6ffffffaUL, "rel")
        val metadata = structure.sections.filter { step(); it.flags and 2UL != 0UL &&
            it.type in setOf(6L, 11L, 4L, 9L, 0x6fffffffL, 0x6ffffffeL, 0x6ffffffdL) } + activeStrings
        val orderedMetadata = metadata.distinctBy { step(); it.index }.filter { it.size != 0UL }.sortedWith { a, b -> step(); a.offset.compareTo(b.offset) }
        var end = 0L
        orderedMetadata.forEach { item ->
            step(); requireBound(item.offset >= end, "dynamic metadata sections overlap")
            end = add(item.offset, long(item.size))
        }
        val result = ElfDynamicBindingInventoryV1(file.authenticatedSha256, structure.core.imageBase, activeSymbols.index,
            structure, entries, symbols, relocations, requirements, definitions, needed, unsupported.toList())
        // Conservative reservation above bounds construction; the canonical writer enforces the exact final cap.
        OracleJson.canonicalBytes(result.toJson(), StrictJsonLimits(maximumInputBytes = limits.maximumOutputBytes,
            maximumCanonicalBytes = limits.maximumOutputBytes, maximumNodes = 1_000_000,
            maximumStringBytes = limits.maximumOutputBytes, maximumTotalStringBytes = limits.maximumOutputBytes), checkpoint)
        checkpoint("after dynamic-binding inventory")
        return result
    }

    private fun parseVersionSections() {
        structure.sections.forEach { section ->
            step()
            if (section.type != 0x6ffffffeL && section.type != 0x6ffffffdL) return@forEach
            metadataSection(section)
            requireBound(section.entrySize == 0UL && section.info > 0, "invalid version-list section shape")
            val strings = section(section.link, 3L); stringBoundaries(strings)
            var position = 0L
            repeat(section.info) { recordIndex ->
                versionRecord()
                val definition = section.type == 0x6ffffffdL
                val width = if (definition) 20 else 16
                val header = within(section, position, width)
                requireBound(u16(header, 0) == 1, "unsupported GNU version structure version")
                val count = u16(header, if (definition) 6 else 2)
                requireBound(count > 0, "empty version auxiliary list")
                val auxDelta = u32(header, if (definition) 12 else 8)
                val next = u32(header, if (definition) 16 else 12)
                requireBound((recordIndex == section.info - 1) == (next == 0L), "version record count/terminator mismatch")
                val recordEnd = if (next == 0L) long(section.size) else add(position, next)
                requireBound(recordEnd <= long(section.size) && recordEnd >= add(position, width.toLong()) && recordEnd % 4L == 0L,
                    "invalid version record extent")
                requireBound(auxDelta >= width && auxDelta % 4L == 0L, "invalid version auxiliary offset")
                var auxiliary = add(position, auxDelta)
                val names = arrayListOf<String>(); val offsets = arrayListOf<Long>(); val nameOffsets = arrayListOf<Long>()
                val providerOffset = if (definition) null else u32(header, 4).toULong()
                val provider = providerOffset?.let { string(strings, it) }
                repeat(count) { auxIndex ->
                    versionRecord()
                    val auxWidth = if (definition) 8 else 16
                    requireBound(auxiliary <= recordEnd - auxWidth, "version auxiliary exceeds its record")
                    val bytes = within(section, auxiliary, auxWidth)
                    val nameOffset = u32(bytes, if (definition) 0 else 8).toULong()
                    val name = string(strings, nameOffset)
                    requireBound(name.isNotEmpty(), "empty version name")
                    val nextAux = u32(bytes, if (definition) 4 else 12)
                    requireBound((auxIndex == count - 1) == (nextAux == 0L), "version auxiliary count/terminator mismatch")
                    if (definition) {
                        names += name; offsets += add(section.offset, auxiliary); nameOffsets += nameOffset.toLong()
                    } else {
                        val rawIndex = u16(bytes, 6); val index = rawIndex and 0x7fff
                        requireBound(index > 1, "invalid required version index")
                        val hash = u32(bytes, 0); requireBound(hash == elfHash(name), "required version hash mismatch")
                        retain(528); retainString(checkNotNull(provider))
                        requirements += ElfVersionRequirementV1(section.index, strings.index, add(section.offset, position),
                            add(section.offset, auxiliary), checkNotNull(provider), checkNotNull(providerOffset).toLong(), name,
                            nameOffset.toLong(), rawIndex, index, u16(bytes, 4), hash)
                    }
                    if (nextAux != 0L) {
                        requireBound(nextAux >= auxWidth && nextAux % 4L == 0L, "overlapping or misaligned version auxiliaries")
                        auxiliary = add(auxiliary, nextAux)
                    }
                }
                if (definition) {
                    val rawIndex = u16(header, 4); val index = rawIndex and 0x7fff
                    requireBound(index > 0, "invalid defined version index")
                    val hash = u32(header, 8); requireBound(hash == elfHash(names.first()), "defined version hash mismatch")
                    retain(512L + offsets.size * 40L)
                    definitions += ElfVersionDefinitionV1(section.index, strings.index, add(section.offset, position),
                        rawIndex, index, u16(header, 2), hash, names.first(), immutable(names.drop(1)), immutable(offsets), immutable(nameOffsets))
                }
                position = recordEnd
            }
        }
        val indices = hashSetOf<Pair<Int, Int>>()
        requirements.forEach { step(); requireBound(indices.add(it.stringSectionIndex to it.index), "duplicate version index") }
        definitions.forEach { step(); requireBound(indices.add(it.stringSectionIndex to it.index), "duplicate version index") }
    }

    private fun parseSymbolVersions(tables: Map<Int, List<FullTreeElfRawDynamicSymbol>>): Map<Pair<Int, Long>, ElfSymbolVersionV1> {
        val result = hashMapOf<Pair<Int, Long>, ElfSymbolVersionV1>()
        val seenTables = hashSetOf<Int>()
        val need = requirements.associateBy { step(); it.stringSectionIndex to it.index }
        val defined = definitions.associateBy { step(); it.stringSectionIndex to it.index }
        structure.sections.forEach { versions ->
            step(); if (versions.type != 0x6fffffffL) return@forEach
            metadataSection(versions)
            val symbols = tables[versions.link] ?: fail("VERSYM links a missing dynamic symbol table")
            val table = section(versions.link, 11L)
            requireBound(seenTables.add(table.index), "multiple VERSYM sections for one table")
            requireBound(versions.entrySize == 2UL && versions.size == symbols.size.toULong() * 2UL, "VERSYM count/width mismatch")
            symbols.forEach { symbol ->
                val offset = add(versions.offset, symbol.symbolIndex * 2)
                val raw = u16(read(offset, 2), 0); val index = raw and 0x7fff
                // Index 1 is global/unversioned even when VERDEF carries a base definition at index 1.
                val requirement = if (index > 1) need[table.link to index] else null
                val definition = if (index > 1) defined[table.link to index] else null
                requireBound(index <= 1 || requirement != null || definition != null, "dangling VERSYM index")
                if (symbol.symbolIndex == 0L) requireBound(raw == 0, "nonlocal VERSYM for STN_UNDEF")
                retain(384)
                val name = requirement?.name ?: definition?.name
                val provider = requirement?.providerRequest
                name?.let(::retainString); provider?.let(::retainString)
                result[table.index to symbol.symbolIndex] = ElfSymbolVersionV1(versions.index, offset, raw, index,
                    raw and 0x8000 != 0, when { index == 0 -> "local"; index == 1 -> "global-unversioned"
                        requirement != null -> "required-version"; else -> "defined-version" }, name, provider)
            }
        }
        return result
    }

    private fun validateVersionTags(pointerTag: ULong, countTag: ULong, type: Long) {
        val sections = structure.sections.filter { step(); it.type == type && it.link == activeStrings.index }
        val pointer = singleton[pointerTag]; val count = singleton[countTag]
        requireBound((pointer == null) == (count == null), "incomplete GNU version dynamic tags")
        requireBound((pointer == null) == sections.isEmpty(), "GNU version section/tag presence mismatch")
        if (pointer != null) requireBound(sections.size == 1 && sections.single().address == pointer &&
            sections.single().info.toULong() == count, "GNU version pointer/count mismatch")
    }

    private fun addRelocationRange(name: String, addressTag: ULong, sizeTag: ULong, widthTag: ULong, type: Long, width: Int) {
        if (listOf(addressTag, sizeTag, widthTag).any { singleton.containsKey(it) }) {
            requireBound(singleton[addressTag] != null && singleton[sizeTag] != null && singleton[widthTag] == width.toULong(),
                "incomplete or inconsistent dynamic relocation tags")
            addRange(name, required(addressTag), required(sizeTag), type, width)
        }
    }

    private fun addRange(name: String, address: ULong, size: ULong, type: Long, width: Int) {
        requireBound(size % width.toULong() == 0UL, "dynamic relocation range is not entry-aligned")
        val end = unsignedAdd(address, size)
        if (size == 0UL) { taggedRanges += RelocationRange(name, address, end, type, width); return }
        val pieces = structure.sections.filter { item ->
            step(); item.type == type && item.size != 0UL && item.address < end && unsignedAdd(item.address, item.size) > address
        }.sortedWith { a, b -> step(); a.address.compareTo(b.address) }
        var covered = address
        pieces.forEach { item ->
            step(); metadataSection(item)
            requireBound(item.entrySize == width.toULong() && item.link == activeSymbols.index, "dynamic relocation section metadata mismatch")
            val begin = maxOf(address, item.address); val pieceEnd = minOf(end, unsignedAdd(item.address, item.size))
            requireBound(begin == covered && (begin - item.address) % width.toULong() == 0UL &&
                (pieceEnd - item.address) % width.toULong() == 0UL, "dynamic relocation range has gaps, overlap or split entries")
            covered = pieceEnd
        }
        requireBound(covered == end, "dynamic relocation pointer/size lacks section coverage")
        taggedRanges += RelocationRange(name, address, end, type, width)
    }

    private fun parseRelocations(symbols: Map<Pair<Int, Long>, ElfDynamicSymbolV1>): List<ElfDynamicRelocationV1> {
        val result = arrayListOf<ElfDynamicRelocationV1>()
        structure.sections.forEach { table ->
            step(); if (table.type != 4L && table.type != 9L) return@forEach
            val linked = structure.sections.getOrNull(table.link) ?: fail("relocation section has invalid link")
            if (linked.type != 11L) return@forEach // Static/linker relocations are outside the dynamic inventory.
            requireBound(table.info == 0 || table.info in structure.sections.indices && structure.sections[table.info].type != 0L,
                "dynamic relocation section has invalid target-section index")
            val width = if (table.type == 4L) 24 else 16
            requireBound(table.entrySize == width.toULong() && table.size % width.toULong() == 0UL, "invalid dynamic relocation section shape")
            requireBound(table.size / width.toULong() <= (limits.maximumRelocations - result.size).toULong(), "relocation count")
            if (table.flags and 2UL != 0UL) metadataSection(table)
            repeat((table.size / width.toULong()).toInt()) { index ->
                val position = add(table.offset, index.toLong() * width)
                val bytes = read(position, width); val offset = u64(bytes, 0); val info = u64(bytes, 8)
                val symbolIndex = (info shr 32).toLong(); val type = (info and 0xffffffffUL).toLong()
                val symbol = symbols[table.link to symbolIndex] ?: fail("relocation has dangling dynamic symbol index")
                val address = unsignedAdd(table.address, index.toULong() * width.toULong())
                val memberships = taggedRanges.filter { range ->
                    step(); range.type == table.type && address >= range.start && address < range.end
                }.map { it.name }
                val reasons = arrayListOf<String>()
                if (memberships.isEmpty()) reasons += "not-in-active-dynamic-relocation-tables"
                if (table.link != activeSymbols.index) reasons += "inactive-dynsym-table"
                when {
                    type == 37L -> reasons += "irelative-runtime-resolver-unresolved"
                    type != 6L && type != 7L -> reasons += "unsupported-relocation-type"
                    symbolIndex == 0L -> reasons += "null-symbol-reference"
                    symbol.type == 10 -> reasons += "ifunc-runtime-resolution-unresolved"
                    symbol.raw.sectionKind != FullTreeElfSymbolSectionKind.UNDEFINED -> reasons += "defined-symbol-runtime-binding-unresolved"
                    symbol.name.isEmpty() -> reasons += "unnamed-import-reference"
                    else -> reasons += "declared-import-runtime-provider-unresolved"
                }
                if (symbol.binding == 2 && symbol.raw.sectionKind == FullTreeElfSymbolSectionKind.UNDEFINED)
                    reasons += "weak-import-may-resolve-null"
                if (symbol.binding !in listOf(1, 2) && symbolIndex != 0L) reasons += "symbol-binding-not-global-or-weak"
                if (symbol.visibility != 0) reasons += "symbol-visibility-nondefault"
                if (symbol.type != 0 && symbol.type != 2 && symbol.type != 10) reasons += "non-function-symbol-reference"
                val slot = if (type == 6L || type == 7L || type == 37L) slot(offset, reasons) else null
                val locator = "elf:section[${table.index}]:relocation[$index]"
                retain(1024L); retainString(locator)
                result += ElfDynamicRelocationV1(table.index, index.toLong(), position, locator, table.link,
                    symbolIndex, offset, type, if (width == 24) u64(bytes, 16).toLong() else null,
                    immutable(memberships), slot?.first, immutable(slot?.second ?: emptyList()), immutable(reasons))
            }
        }
        val counts = hashMapOf<ULong, Int>()
        result.forEach { step(); counts[it.offset] = (counts[it.offset] ?: 0) + 1 }
        return result.map { relocation ->
            step(); if (counts.getValue(relocation.offset) > 1) relocation.copy(
                dispositions = immutable(relocation.dispositions + "competing-relocation-slot")) else relocation
        }
    }

    private fun validateRelativePrefix(relocations: List<ElfDynamicRelocationV1>, tag: ULong, table: String) {
        val count = singleton[tag] ?: return
        val ordered = relocations.filter { step(); table in it.dynamicTables }.sortedWith { a, b ->
            step()
            val first = unsignedAdd(structure.sections[a.sectionIndex].address,
                a.relocationIndex.toULong() * (if (table == "rela") 24UL else 16UL))
            val second = unsignedAdd(structure.sections[b.sectionIndex].address,
                b.relocationIndex.toULong() * (if (table == "rela") 24UL else 16UL))
            first.compareTo(second)
        }
        requireBound(count <= ordered.size.toULong(), "relative relocation prefix exceeds its table")
        repeat(count.toInt()) { index ->
            step(); requireBound(ordered[index].type == 8L && ordered[index].symbolIndex == 0L,
                "relative relocation prefix contains a non-relative symbol reference")
        }
    }

    private fun slot(address: ULong, reasons: MutableList<String>): Pair<Long?, List<Int>> {
        val end = if (ULong.MAX_VALUE - address < 8UL) { reasons += "slot-address-overflow"; return null to emptyList() } else address + 8UL
        val owners = structure.loadedMemory.filter { segment ->
            step(); segment.virtualAddress < end && segment.endExclusive > address
        }
        if (owners.size != 1) {
            reasons += if (owners.isEmpty()) "unmapped-slot" else "ambiguous-load-slot"
            return null to owners.map { it.index }
        }
        val owner = owners.single()
        if (address < owner.virtualAddress || end > owner.endExclusive) { reasons += "partial-load-slot"; return null to listOf(owner.index) }
        if (end > owner.fileEndExclusive) { reasons += "zero-filled-slot"; return null to listOf(owner.index) }
        return long(unsignedAdd(owner.fileOffset, address - owner.virtualAddress)) to listOf(owner.index)
    }

    private fun metadataSection(section: FullTreeElfRawSection) {
        step(); requireBound(section.flags and 2UL != 0UL && section.flags and 0x800UL == 0UL && section.type != 8L,
            "dynamic metadata is not allocated uncompressed file storage")
        if (section.size == 0UL) return
        val end = unsignedAdd(section.address, section.size)
        val owners = structure.loadedMemory.filter { segment ->
            step(); segment.virtualAddress < end && segment.endExclusive > section.address
        }
        requireBound(owners.size == 1, "dynamic metadata has ambiguous or absent LOAD ownership")
        val owner = owners.single()
        requireBound(section.address >= owner.virtualAddress && end <= owner.fileEndExclusive &&
            unsignedAdd(owner.fileOffset, section.address - owner.virtualAddress) == section.offset.toULong(),
            "dynamic metadata file and LOAD mappings disagree")
    }

    private fun uniqueSection(type: Long, address: ULong): FullTreeElfRawSection {
        val matching = structure.sections.filter { step(); it.type == type && it.address == address }
        requireBound(matching.size == 1, "dynamic pointer does not identify one section")
        return matching.single()
    }
    private fun section(index: Int, type: Long): FullTreeElfRawSection {
        step(); val result = structure.sections.getOrNull(index) ?: fail("invalid section link")
        requireBound(result.type == type, "section link has wrong type"); return result
    }
    private fun required(tag: ULong): ULong = singleton[tag] ?: fail("required dynamic tag is missing")
    private fun stringBoundaries(section: FullTreeElfRawSection) {
        requireBound(section.size > 0UL && section.flags and 0x800UL == 0UL, "invalid dynamic string table")
        requireBound(read(section.offset, 1)[0] == 0.toByte() && read(add(section.offset, long(section.size) - 1), 1)[0] == 0.toByte(),
            "dynamic string table lacks boundary NUL bytes")
    }
    private fun string(section: FullTreeElfRawSection, offset: ULong): String {
        requireBound(offset < section.size, "dynamic string offset is out of bounds")
        val available = minOf(section.size - offset, limits.maximumStringBytes.toULong() + 1UL).toInt()
        val bytes = read(add(section.offset, long(offset)), available)
        val nul = bytes.indexOf(0)
        requireBound(nul >= 0, "dynamic string is unterminated or exceeds byte limit")
        repeat(nul) { step() }
        val result = try { StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes, 0, nul)).toString()
        } catch (failure: Exception) { throw FullTreeControlException("dynamic string is not UTF-8", failure) }
        retainString(result); return result
    }
    private fun within(section: FullTreeElfRawSection, offset: Long, count: Int): ByteArray {
        requireBound(offset >= 0 && offset <= long(section.size) - count, "version record exceeds section")
        requireBound(offset % 4L == 0L, "misaligned version record")
        return read(add(section.offset, offset), count)
    }
    private fun read(offset: Long, count: Int): ByteArray {
        chargeRead(count)
        return file.readExactly(offset, count, "dynamic ELF metadata", checkpoint)
    }
    private fun chargeRead(count: Int) {
        step(); reads = add(reads, count.toLong()); requireBound(reads <= limits.maximumReadBytes, "read byte bound")
    }
    private fun retainString(value: String) {
        val count = value.toByteArray(StandardCharsets.UTF_8).size
        requireBound(count <= maxOf(limits.maximumStringBytes, limits.layout.maximumLocatorBytes), "retained string bound")
        stringBytes = add(stringBytes, count.toLong()); requireBound(stringBytes <= limits.maximumTotalStringBytes, "aggregate string byte bound")
        retain(count * 6L + 2)
    }
    private fun retain(count: Long) { output = add(output, count); requireBound(output <= limits.maximumOutputBytes, "modeled output byte bound") }
    private fun versionRecord() { step(); requireBound(++versionRecords <= limits.maximumVersionRecords, "version record count") }
    private fun step() { requireBound(++work <= limits.maximumWorkUnits, "work unit bound"); if (work == 1L || work % 1024 == 0L) checkpoint("while parsing dynamic ELF metadata") }
    private fun elfHash(name: String): Long {
        var hash = 0L
        name.toByteArray(StandardCharsets.UTF_8).forEach { byte ->
            step(); hash = ((hash shl 4) + (byte.toInt() and 255)) and 0xffffffffL; val high = hash and 0xf0000000L
            if (high != 0L) hash = hash xor (high ushr 24)
            hash = hash and high.inv()
        }
        return hash
    }
}

private data class RelocationRange(val name: String, val start: ULong, val end: ULong, val type: Long, val width: Int)
private val KNOWN_DYNAMIC_TAGS = (0UL..34UL).toSet() + setOf(0x6ffffef5UL, 0x6ffffff0UL,
    0x6ffffff9UL, 0x6ffffffaUL, 0x6ffffffbUL, 0x6ffffffcUL, 0x6ffffffdUL, 0x6ffffffeUL, 0x6fffffffUL)
private val SINGLETON_TAGS = setOf(2UL, 3UL, 4UL, 5UL, 6UL, 7UL, 8UL, 9UL, 10UL, 11UL, 17UL, 18UL, 19UL, 20UL, 23UL,
    35UL, 36UL, 37UL, 0x6ffffef5UL, 0x6ffffff0UL, 0x6ffffff9UL, 0x6ffffffaUL, 0x6ffffffcUL, 0x6ffffffdUL, 0x6ffffffeUL, 0x6fffffffUL)
private fun fail(message: String): Nothing = throw FullTreeControlException("dynamic-binding ELF: $message")
private fun requireBound(condition: Boolean, message: String) { if (!condition) fail(message) }
private fun add(a: Long, b: Long): Long = try { Math.addExact(a, b) } catch (failure: ArithmeticException) { fail("offset overflow") }
private fun long(value: ULong): Long { requireBound(value <= Long.MAX_VALUE.toULong(), "file range exceeds signed address space"); return value.toLong() }
private fun unsignedAdd(a: ULong, b: ULong): ULong { requireBound(ULong.MAX_VALUE - a >= b, "unsigned address overflow"); return a + b }
private fun u16(bytes: ByteArray, offset: Int): Int = (bytes[offset].toInt() and 255) or ((bytes[offset + 1].toInt() and 255) shl 8)
private fun u32(bytes: ByteArray, offset: Int): Long = (0..3).fold(0L) { result, i -> result or ((bytes[offset + i].toLong() and 255) shl (i * 8)) }
private fun u64(bytes: ByteArray, offset: Int): ULong = (0..7).fold(0UL) { result, i -> result or ((bytes[offset + i].toULong() and 255UL) shl (i * 8)) }
private fun <T> immutable(items: List<T>): List<T> = Collections.unmodifiableList(ArrayList(items))
private fun obj(vararg pairs: Pair<String, JsonElement>): JsonObject = JsonObject(linkedMapOf(*pairs))
private fun s(value: String): JsonPrimitive = JsonPrimitive(value)
private fun n(value: Int): JsonPrimitive = JsonPrimitive(value)
private fun n(value: Long): JsonPrimitive = JsonPrimitive(value)
private fun b(value: Boolean): JsonPrimitive = JsonPrimitive(value)
private fun h(value: ULong): JsonPrimitive = s("0x${value.toString(16)}")
private fun nullable(value: String?): JsonElement = value?.let(::s) ?: JsonNull
private fun array(values: List<JsonElement>): JsonArray = JsonArray(values)
private fun strings(values: List<String>): JsonArray = array(values.map(::s))
