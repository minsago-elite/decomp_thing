package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeElfRawSection
import decompengine.oracle.fulltree.FullTreeElfSymbolSectionKind
import decompengine.oracle.fulltree.StableControlFile
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

internal data class ElfExternalNamespacePairLimitsV1(
    val maximumManifestBytes: Int = 2 * 1024 * 1024,
    val maximumWorkUnits: Long = 100_000_000,
    val maximumReadBytes: Long = 4L * 1024 * 1024 * 1024,
    val maximumOutputBytes: Int = 64 * 1024 * 1024,
    val maximumCodeProofs: Int = 500_000,
    val maximumWallMillis: Long = 1_800_000,
) {
    init {
        require(maximumManifestBytes in 1..2 * 1024 * 1024 && maximumWorkUnits in 16..100_000_000)
        require(maximumReadBytes in 16..4L * 1024 * 1024 * 1024 && maximumOutputBytes in 1..64 * 1024 * 1024)
        require(maximumCodeProofs in 1..500_000 && maximumWallMillis in 1..1_800_000)
    }
}

internal data class ElfExternalCodePairV1(
    val rva: ULong, val bytesHex: String, val richAddress: ULong, val strippedAddress: ULong,
    val richFileOffset: Long, val strippedFileOffset: Long,
) {
    val length: Int get() = bytesHex.length / 2
    val bytes: ByteArray get() = ByteArray(length) { bytesHex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    fun toJson(): JsonObject = pairObject("kind" to pairString("elf-twin-code-bytes-v1"), "rva" to pairHex(rva),
        "bytes" to pairString(bytesHex), "length" to pairNumber(length), "richAddress" to pairHex(richAddress),
        "strippedAddress" to pairHex(strippedAddress), "richFileOffset" to pairNumber(richFileOffset),
        "strippedFileOffset" to pairNumber(strippedFileOffset), "negativeCompleteness" to pairBool(false))
}

internal data class ElfExternalSlotPairV1(
    val slotRva: ULong?, val richRelocation: ElfDynamicRelocationV1, val strippedRelocation: ElfDynamicRelocationV1,
    val richSymbol: ElfDynamicSymbolV1, val strippedSymbol: ElfDynamicSymbolV1,
    val richImportId: String?, val strippedImportId: String?, val disposition: String,
    val slotBytesHex: String?, val richWriteCoverage: ElfRelocationWriteAssessmentV1,
    val strippedWriteCoverage: ElfRelocationWriteAssessmentV1,
) {
    val eligible: Boolean get() = disposition == "paired-static-import-request"
    fun toJson(): JsonObject = pairObject("slotRva" to pairHex(slotRva), "disposition" to pairString(disposition),
        "eligible" to pairBool(eligible), "slotBytes" to pairNullable(slotBytesHex),
        "richImportId" to pairNullable(richImportId), "strippedImportId" to pairNullable(strippedImportId),
        "richRelocation" to pairRelocationReceipt(richRelocation), "strippedRelocation" to pairRelocationReceipt(strippedRelocation),
        "richSymbolLocator" to pairString(richSymbol.raw.locator), "strippedSymbolLocator" to pairString(strippedSymbol.raw.locator),
        "richWriteCoverage" to pairFlatSnapshot(richWriteCoverage.toJson()), "strippedWriteCoverage" to pairFlatSnapshot(strippedWriteCoverage.toJson()),
        "runtimeProviderAvailable" to pairBool(false), "runtimeImplementationAvailable" to pairBool(false),
        "negativeCompleteness" to pairBool(false))
}

/**
 * A descriptor-bound namespace correspondence, never call or runtime-provider truth. The expected
 * manifest digest must come from the caller's authenticated profile, not from a recovered document.
 * Only the manifest's exact artifact pins are used as authority; logical ELF facts are independently
 * scanned and compared. Original manifest paths and asserted equivalence summaries are not followed.
 *
 * V1 keeps runtime metadata addresses and symbol/version ordinals fixed. Section indices and file
 * offsets may differ. Reindexing, name-based reconciliation and nonallocated dynamic tables are
 * unsupported. The caller owns all three descriptors and must call requireCurrent before committing
 * results. On-demand code proof checks descriptor continuity; it does not decode an instruction.
 */
internal class ElfExternalNamespacePairV1 private constructor(
    private val manifest: StableControlFile, private val richFile: StableControlFile, private val strippedFile: StableControlFile,
    val richInventory: ElfDynamicBindingInventoryV1, val strippedInventory: ElfDynamicBindingInventoryV1,
    val richNamespace: JsonObject, val richNamespaceSha256: String,
    val strippedNamespace: JsonObject, val strippedNamespaceSha256: String,
    slots: List<ElfExternalSlotPairV1>, val receipt: JsonObject, val receiptSha256: String,
    private val budget: PairBudget,
) {
    val slots: List<ElfExternalSlotPairV1> = Collections.unmodifiableList(ArrayList(slots))
    private val uniqueSlots = slots.filter { budget.step("index paired slot"); it.slotRva != null }.groupBy { it.slotRva!! }
        .filterValues { budget.step("index unique slot"); it.size == 1 }.mapValues { budget.step("retain unique slot"); it.value.single() }

    fun slotAtRva(rva: ULong): ElfExternalSlotPairV1? {
        budget.step("lookup twin slot"); requireContinuity(); return uniqueSlots[rva]
    }

    fun codeWindowAtRva(rva: ULong): ElfExternalCodePairV1? = code(rva, null)

    fun proveCodeBytes(rva: ULong, expectedStrippedBytes: ByteArray): ElfExternalCodePairV1? {
        require(expectedStrippedBytes.size in 1..15) { "code receipt must contain one bounded instruction" }
        return code(rva, expectedStrippedBytes.copyOf())
    }

    private fun code(rva: ULong, expected: ByteArray?): ElfExternalCodePairV1? {
        budget.code(); requireContinuity()
        val rich = ownedCode(richInventory, rva, budget) ?: return null
        val stripped = ownedCode(strippedInventory, rva, budget) ?: return null
        val length = expected?.size ?: minOf(rich.second, stripped.second)
        if (length > rich.second || length > stripped.second) return null
        val a = budget.read(richFile, rich.first, length, "rich code bytes")
        val b = budget.read(strippedFile, stripped.first, length, "stripped code bytes")
        requireContinuity()
        if (expected != null && (!a.contentEquals(b) || !b.contentEquals(expected))) return null
        var matched = 0
        while (matched < length && a[matched] == b[matched]) matched++
        if (matched == 0) return null
        return ElfExternalCodePairV1(rva, pairBytes(a.copyOf(matched)), pairAdd(richInventory.imageBase, rva),
            pairAdd(strippedInventory.imageBase, rva), rich.first, stripped.first)
    }

    private fun requireContinuity() {
        budget.step("twin descriptor continuity")
        manifest.requirePathAndIdentity("external namespace manifest")
        richFile.requirePathAndIdentity("external namespace rich ELF")
        strippedFile.requirePathAndIdentity("external namespace stripped ELF")
    }

    fun requireCurrent() {
        budget.authenticate(manifest, "external namespace manifest")
        budget.authenticate(richFile, "external namespace rich ELF")
        budget.authenticate(strippedFile, "external namespace stripped ELF")
    }

    companion object {
        fun prove(
            manifest: StableControlFile, expectedManifestSha256: String,
            rich: StableControlFile, stripped: StableControlFile,
            limits: ElfExternalNamespacePairLimitsV1 = ElfExternalNamespacePairLimitsV1(),
            checkpoint: (String) -> Unit = {},
        ): ElfExternalNamespacePairV1 {
            val budget = PairBudget(limits, checkpoint)
            require(expectedManifestSha256.matches(Regex("[0-9a-f]{64}")) && manifest.authenticatedSha256 == expectedManifestSha256) {
                "external namespace manifest identity differs"
            }
            require(manifest.size in 1..limits.maximumManifestBytes.toLong()) { "external namespace manifest exceeds byte bound" }
            val document = OracleJson.parseCanonical(budget.read(manifest, 0, manifest.size.toInt(), "external namespace manifest"),
                pairJsonLimits(limits.maximumManifestBytes), budget::step) as? JsonObject ?: error("manifest is not an object")
            budget.step("manifest schema validation"); OracleSchemas.validate("oracle-manifest", document); budget.step("manifest schema validated")
            val artifacts = document.getValue("artifacts") as JsonObject
            fun pin(name: String, file: StableControlFile): JsonObject {
                val record = artifacts.getValue(name) as JsonObject
                require(record.getValue("sha256") == JsonPrimitive(file.authenticatedSha256) &&
                    (record.getValue("bytes") as JsonPrimitive).longOrNull == file.size && file.size in 1..512L * 1024 * 1024) {
                    "external namespace $name artifact differs from pinned manifest"
                }
                return pairObject("sha256" to pairString(file.authenticatedSha256), "bytes" to pairNumber(file.size))
            }
            val richPin = pin("full", rich); val strippedPin = pin("stripped", stripped)
            budget.reserveScannerAuthentications(rich.size, stripped.size)
            val metadataLimits = budget.reserveParsers()
            val a = BoundedElfDynamicBindingsV1.scan(rich, rich.authenticatedSha256, metadataLimits, budget::step)
            budget.step("after rich dynamic scan and mandatory authentication")
            val b = BoundedElfDynamicBindingsV1.scan(stripped, stripped.authenticatedSha256, metadataLimits, budget::step)
            budget.step("after stripped dynamic scan and mandatory authentication")
            require(a.structure.core == b.structure.core) { "twin ELF core layouts differ" }
            val left = LogicalInventory(a, budget); val right = LogicalInventory(b, budget)
            val logicalA = left.document(); val logicalB = right.document()
            val logicalBytesA = budget.encode(logicalA); val logicalBytesB = budget.encode(logicalB)
            require(logicalBytesA.contentEquals(logicalBytesB)) { "twin logical dynamic metadata differs or requires reindexing" }
            val namespaceA = pairNamespace(a, budget); val namespaceB = pairNamespace(b, budget)
            val namespaceShaA = OracleArtifacts.sha256(budget.encode(namespaceA)); val namespaceShaB = OracleArtifacts.sha256(budget.encode(namespaceB))
            val importA = pairImportIds(a, budget); val importB = pairImportIds(b, budget)
            val writesA = ElfRelocationWriteCoverageV1.build(a, charge = budget::step)
            val writesB = ElfRelocationWriteCoverageV1.build(b, charge = budget::step)
            val competingA = a.relocations.groupingBy { budget.step("rich slot counts"); it.offset }.eachCount()
            val competingB = b.relocations.groupingBy { budget.step("stripped slot counts"); it.offset }.eachCount()
            val mechanisms = (a.unsupportedReasons + b.unsupportedReasons).any { it in PAIR_UNSUPPORTED_WRITES }
            val rows = left.relocations.entries.map { (key, relocationA) ->
                budget.step("pair relocation"); budget.retain(3072)
                val relocationB = right.relocations.getValue(key)
                val symbolA = left.symbols.getValue(left.symbolKey(relocationA.symbolTableSectionIndex, relocationA.symbolIndex))
                val symbolB = right.symbols.getValue(right.symbolKey(relocationB.symbolTableSectionIndex, relocationB.symbolIndex))
                val coverageA = writesA.assess(relocationA.offset, relocationA)
                val coverageB = writesB.assess(relocationB.offset, relocationB)
                val idA = importA[relocationA.symbolTableSectionIndex to relocationA.symbolIndex]
                val idB = importB[relocationB.symbolTableSectionIndex to relocationB.symbolIndex]
                val rva = relocationA.offset.takeIf { it >= a.imageBase }?.minus(a.imageBase)
                val bytes = if (rva != null && relocationA.slotFileOffset != null && relocationB.slotFileOffset != null &&
                    coverageA.safeForStaticSlotAssociation && coverageB.safeForStaticSlotAssociation) {
                    val first = budget.read(rich, relocationA.slotFileOffset, 8, "rich pointer slot")
                    val second = budget.read(stripped, relocationB.slotFileOffset, 8, "stripped pointer slot")
                    require(first.contentEquals(second)) { "twin pointer-slot bytes differ" }
                    pairBytes(first)
                } else null
                val status = when {
                    rva == null -> "unresolved-slot-below-image-base"
                    mechanisms -> "unresolved-unexpanded-relocation-writes"
                    competingA.getValue(relocationA.offset) != 1 || competingB.getValue(relocationB.offset) != 1 -> "unresolved-competing-relocations"
                    relocationA.dynamicTables.size != 1 || relocationB.dynamicTables.size != 1 -> "unresolved-relocation-runtime-membership"
                    relocationA.symbolTableSectionIndex != a.activeSymbolTableSectionIndex || relocationB.symbolTableSectionIndex != b.activeSymbolTableSectionIndex -> "unresolved-inactive-symbol-table"
                    relocationA.slotLoadIndices.size != 1 || relocationB.slotLoadIndices.size != 1 -> "unresolved-slot-memory-ownership"
                    relocationA.slotFileOffset == null || relocationB.slotFileOffset == null -> "unresolved-slot-file-storage"
                    relocationA.type == 37L -> "unresolved-irelative-resolver"
                    relocationA.type !in setOf(6L, 7L) -> "unresolved-relocation-type"
                    relocationA.symbolIndex == 0L -> "unresolved-null-symbol-index"
                    !coverageA.safeForStaticSlotAssociation || !coverageB.safeForStaticSlotAssociation -> "unresolved-relocation-write-coverage"
                    symbolA.type == 10 -> "unresolved-ifunc-runtime-implementation"
                    symbolA.raw.sectionKind != FullTreeElfSymbolSectionKind.UNDEFINED -> "unresolved-defined-symbol-reference"
                    idA == null || idB == null -> "unresolved-symbol-import-identity"
                    symbolA.version != null && symbolA.version.index >= 2 && symbolA.version.kind != "required-version" -> "unresolved-symbol-version"
                    symbolA.binding == 2 -> "unresolved-weak-runtime-target"
                    symbolA.type != 2 -> "unresolved-symbol-callability"
                    else -> "paired-static-import-request"
                }
                ElfExternalSlotPairV1(rva, relocationA, relocationB, symbolA, symbolB, idA, idB, status, bytes, coverageA, coverageB)
            }
            val receipt = pairObject("schemaVersion" to pairNumber(1), "kind" to pairString("elf-external-namespace-pair-v1"),
                "authority" to pairString("authenticated-logical-elf-pair"), "manifestSha256" to pairString(expectedManifestSha256),
                "rich" to richPin, "stripped" to strippedPin, "imageBase" to pairHex(a.imageBase),
                "logicalMetadataSha256" to pairString(OracleArtifacts.sha256(logicalBytesA)),
                "richNamespaceSha256" to pairString(namespaceShaA), "strippedNamespaceSha256" to pairString(namespaceShaB),
                "profile" to pairString("elf64-le-x86-64-fixed-runtime-tables-and-ordinals-v1"),
                "slots" to pairArray(rows.map { it.toJson() }),
                "counts" to pairObject("relocations" to pairNumber(rows.size), "eligibleSlots" to pairNumber(rows.count { it.eligible }),
                    "richNamespaceEntries" to pairNumber((namespaceA.getValue("entries") as JsonArray).size),
                    "strippedNamespaceEntries" to pairNumber((namespaceB.getValue("entries") as JsonArray).size)),
                "complete" to pairBool(false), "releaseEligible" to pairBool(false), "negativeCompleteness" to pairBool(false),
                "runtimeProviderAvailable" to pairBool(false), "runtimeImplementationAvailable" to pairBool(false))
            val encoded = budget.encode(receipt)
            return ElfExternalNamespacePairV1(manifest, rich, stripped, a, b, namespaceA, namespaceShaA, namespaceB, namespaceShaB,
                rows, receipt, OracleArtifacts.sha256(encoded), budget).also { it.requireCurrent() }
        }
    }
}

/** Logical coordinates deliberately exclude section ordinals and file offsets. */
private class LogicalInventory(val inventory: ElfDynamicBindingInventoryV1, val budget: PairBudget) {
    val symbols = linkedMapOf<Pair<ULong, Long>, ElfDynamicSymbolV1>()
    val relocations = linkedMapOf<ULong, ElfDynamicRelocationV1>()
    private val requirements = inventory.versionRequirements.associateBy {
        budget.step("index twin version requirement"); it.stringSectionIndex to it.index
    }
    private val definitions = inventory.versionDefinitions.associateBy {
        budget.step("index twin version definition"); it.stringSectionIndex to it.index
    }
    init {
        inventory.dynamicSymbols.forEach { symbol ->
            budget.step("index twin symbol"); require(symbols.put(symbolKey(symbol.tableSectionIndex, symbol.symbolIndex), symbol) == null) {
                "ambiguous runtime dynamic-symbol table"
            }
        }
        inventory.relocations.forEach { relocation ->
            budget.step("index twin relocation")
            val table = allocated(relocation.sectionIndex)
            val coordinate = pairAdd(table.address, Math.multiplyExact(relocation.relocationIndex, table.entrySize.toLong()).toULong())
            require(relocations.put(coordinate, relocation) == null) { "ambiguous runtime relocation coordinate" }
        }
    }
    fun symbolKey(section: Int, index: Long): Pair<ULong, Long> = allocated(section).address to index
    private fun section(index: Int) = inventory.sections.getOrNull(index) ?: error("missing twin section")
    private fun allocated(index: Int): FullTreeElfRawSection = section(index).also {
        budget.step("logical runtime section"); require(it.flags and 2UL != 0UL && it.address >= inventory.imageBase) {
            "nonallocated or below-base dynamic table is unsupported by twin pairing"
        }
    }
    private fun sectionIdentity(index: Int): JsonObject {
        val s = section(index); budget.step("logical section identity")
        return pairObject("type" to pairNumber(s.type), "flags" to pairHex(s.flags), "address" to pairHex(s.address),
            "size" to pairHex(s.size), "alignment" to pairHex(s.alignment), "entrySize" to pairHex(s.entrySize))
    }
    private fun versionRecord(symbol: ElfDynamicSymbolV1): JsonElement {
        val v = symbol.version ?: return JsonNull
        val table = section(symbol.tableSectionIndex)
        budget.step("join twin version")
        val requirement = requirements[table.link to v.index]
        val definition = definitions[table.link to v.index]
        return pairObject("symbol" to pairVersion(v),
            "requirementAddress" to requirement?.let { pairHex(runtime(it.sectionIndex, it.auxiliaryOffset)) }.orNull(),
            "definitionAddress" to definition?.let { pairHex(runtime(it.sectionIndex, it.recordOffset)) }.orNull())
    }
    private fun requirement(v: ElfVersionRequirementV1): JsonObject = pairObject(
        "table" to sectionIdentity(v.sectionIndex), "strings" to sectionIdentity(v.stringSectionIndex),
        "recordAddress" to pairHex(runtime(v.sectionIndex, v.recordOffset)), "auxiliaryAddress" to pairHex(runtime(v.sectionIndex, v.auxiliaryOffset)),
        "providerRequest" to pairString(v.providerRequest), "name" to pairString(v.name), "rawIndex" to pairNumber(v.rawIndex),
        "index" to pairNumber(v.index), "flags" to pairNumber(v.flags), "hash" to pairNumber(v.hash))
    private fun definition(v: ElfVersionDefinitionV1): JsonObject = pairObject(
        "table" to sectionIdentity(v.sectionIndex), "strings" to sectionIdentity(v.stringSectionIndex),
        "recordAddress" to pairHex(runtime(v.sectionIndex, v.recordOffset)), "rawIndex" to pairNumber(v.rawIndex),
        "index" to pairNumber(v.index), "flags" to pairNumber(v.flags), "hash" to pairNumber(v.hash), "name" to pairString(v.name),
        "parentNames" to pairArray(v.parentNames.map { budget.step("version parent"); pairString(it) }),
        "auxiliaryAddresses" to pairArray(v.auxiliaryOffsets.map { budget.step("version auxiliary"); pairHex(runtime(v.sectionIndex, it)) }))
    private fun runtime(index: Int, offset: Long): ULong {
        val s = allocated(index); require(offset >= s.offset); return pairAdd(s.address, (offset - s.offset).toULong())
    }
    fun document(): JsonObject {
        val symbolRows = symbols.entries.sortedWith { a, b -> budget.step("sort logical symbols")
            a.key.first.compareTo(b.key.first).takeIf { it != 0 } ?: a.key.second.compareTo(b.key.second) }.map { (_, symbol) ->
            budget.step("logical symbol"); budget.retain(1024)
            val raw = symbol.raw
            budget.retainString(raw.name)
            symbol.version?.let { version -> version.name?.let(budget::retainString); version.providerRequest?.let(budget::retainString) }
            pairObject("table" to sectionIdentity(raw.tableSectionIndex), "strings" to sectionIdentity(section(raw.tableSectionIndex).link),
                "index" to pairNumber(raw.symbolIndex), "nameOffset" to pairNumber(raw.nameOffset), "name" to pairString(raw.name),
                "info" to pairNumber(raw.info), "other" to pairNumber(raw.other), "sectionKind" to pairString(raw.sectionKind.name),
                "specialSectionIndex" to if (raw.sectionKind == FullTreeElfSymbolSectionKind.DEFINED) JsonNull else pairNumber(raw.rawSectionIndex),
                "definedSection" to if (raw.sectionKind == FullTreeElfSymbolSectionKind.DEFINED) sectionIdentity(raw.resolvedSectionIndex.toInt()) else JsonNull,
                "value" to pairHex(raw.value), "size" to pairHex(raw.size), "version" to versionRecord(symbol))
        }
        val relocationRows = relocations.entries.sortedWith { a, b -> budget.step("sort logical relocations"); a.key.compareTo(b.key) }.map { (coordinate, r) ->
            budget.step("logical relocation"); budget.retain(512)
            pairObject("recordAddress" to pairHex(coordinate), "tableType" to pairNumber(section(r.sectionIndex).type),
                "slotAddress" to pairHex(r.offset), "type" to pairNumber(r.type), "addend" to (r.addend?.let(::pairNumber) ?: JsonNull),
                "symbolTableAddress" to pairHex(allocated(r.symbolTableSectionIndex).address), "symbolIndex" to pairNumber(r.symbolIndex),
                "dynamicTables" to pairArray(r.dynamicTables.map(::pairString)))
        }
        val loads = inventory.loadedMemory.sortedWith { a, b -> budget.step("sort twin LOADs"); a.virtualAddress.compareTo(b.virtualAddress) }.map {
            budget.step("twin LOAD"); pairObject("virtualAddress" to pairHex(it.virtualAddress), "flags" to pairNumber(it.flags),
                "fileSize" to pairHex(it.fileSize), "memorySize" to pairHex(it.memorySize), "alignment" to pairHex(it.alignment))
        }
        return pairObject("activeSymbolTable" to sectionIdentity(inventory.activeSymbolTableSectionIndex),
            "loads" to pairArray(loads), "dynamicEntries" to pairArray(inventory.dynamicEntries.map {
                budget.step("logical dynamic entry"); pairObject("tag" to pairHex(it.tag), "value" to pairHex(it.value)) }),
            "neededLibraries" to pairArray(inventory.neededLibraries.map {
                budget.step("logical needed library"); budget.retainString(it); pairString(it)
            }),
            "symbols" to pairArray(symbolRows), "relocations" to pairArray(relocationRows),
            "versionRequirements" to pairArray(inventory.versionRequirements.map { budget.step("logical version need"); requirement(it) }
                .sortedWith { a, b -> budget.step("sort version needs"); (a.getValue("auxiliaryAddress") as JsonPrimitive).content
                    .compareTo((b.getValue("auxiliaryAddress") as JsonPrimitive).content) }),
            "versionDefinitions" to pairArray(inventory.versionDefinitions.map { budget.step("logical version definition"); definition(it) }
                .sortedWith { a, b -> budget.step("sort version definitions"); (a.getValue("recordAddress") as JsonPrimitive).content
                    .compareTo((b.getValue("recordAddress") as JsonPrimitive).content) }),
            "unsupportedReasons" to pairArray(inventory.unsupportedReasons.map(::pairString)))
    }
}

private fun ownedCode(inventory: ElfDynamicBindingInventoryV1, rva: ULong, budget: PairBudget): Pair<Long, Int>? {
    if (rva > ULong.MAX_VALUE - inventory.imageBase) return null
    val address = inventory.imageBase + rva
    val sections = inventory.sections.filter { budget.step("code section ownership"); it.flags and 2UL != 0UL && it.address <= address && address - it.address < it.size }
    if (sections.size != 1) return null
    val s = sections.single()
    if (s.type != 1L || s.flags and 6UL != 6UL || s.flags and 0x800UL != 0UL || s.size > ULong.MAX_VALUE - s.address) return null
    val loads = inventory.loadedMemory.filter { budget.step("code LOAD ownership"); it.virtualAddress <= address && address < it.endExclusive }
    if (loads.size != 1) return null
    val load = loads.single()
    if (load.flags and 1L == 0L || address >= load.fileEndExclusive) return null
    val length = minOf(15UL, s.address + s.size - address, load.fileEndExclusive - address).toInt()
    val end = address + length.toULong()
    if (inventory.loadedMemory.any { budget.step("code overlapping LOAD"); it.index != load.index && it.virtualAddress < end && it.endExclusive > address }) return null
    if (inventory.sections.any { budget.step("code overlapping section"); it.index != s.index && it.flags and 2UL != 0UL && it.address < end &&
            (it.size > ULong.MAX_VALUE - it.address || it.address + it.size > address) }) return null
    val offset = pairAdd(load.fileOffset, address - load.virtualAddress)
    if (offset > Long.MAX_VALUE.toULong() || offset != pairAdd(s.offset.toULong(), address - s.address)) return null
    return offset.toLong() to length
}

private fun pairImportIdentity(input: String, symbol: ElfDynamicSymbolV1): JsonObject = pairObject(
    "schemaVersion" to pairNumber(1), "namespace" to pairString("elf-static-import-request-v1"), "inputSha256" to pairString(input),
    "symbolTableSectionIndex" to pairNumber(symbol.tableSectionIndex), "symbolIndex" to pairNumber(symbol.symbolIndex),
    "name" to pairString(symbol.name), "type" to pairNumber(symbol.type), "binding" to pairNumber(symbol.binding), "visibility" to pairNumber(symbol.visibility),
    "version" to (symbol.version?.let(::pairVersion) ?: JsonNull), "weakMayRemainNull" to pairBool(symbol.binding == 2),
    "ifuncImplementationUnresolved" to pairBool(symbol.type == 10), "runtimeProviderAvailable" to pairBool(false),
    "runtimeImplementationAvailable" to pairBool(false), "interpositionUnresolved" to pairBool(true))
private fun pairVersion(v: ElfSymbolVersionV1): JsonObject = pairObject("raw" to pairNumber(v.raw), "index" to pairNumber(v.index),
    "hidden" to pairBool(v.hidden), "kind" to pairString(v.kind), "name" to pairNullable(v.name), "providerRequest" to pairNullable(v.providerRequest))
private fun pairEligible(symbol: ElfDynamicSymbolV1): Boolean = symbol.symbolIndex != 0L &&
    symbol.raw.sectionKind == FullTreeElfSymbolSectionKind.UNDEFINED && symbol.name.isNotEmpty() &&
    symbol.binding in setOf(1, 2) && symbol.visibility == 0 && symbol.type in setOf(0, 2, 10)
private fun pairImportIds(inventory: ElfDynamicBindingInventoryV1, budget: PairBudget): Map<Pair<Int, Long>, String> =
    inventory.dynamicSymbols.filter { budget.step("import namespace membership"); pairEligible(it) }.associate {
        (it.tableSectionIndex to it.symbolIndex) to "ext-${OracleArtifacts.sha256(budget.encode(pairImportIdentity(inventory.inputSha256, it)))}"
    }
private fun pairNamespace(inventory: ElfDynamicBindingInventoryV1, budget: PairBudget): JsonObject = pairObject(
    "schemaVersion" to pairNumber(1), "kind" to pairString("elf-static-import-request-namespace-v1"), "inputSha256" to pairString(inventory.inputSha256),
    "populationBasis" to pairString("eligible-section-declared-undefined-dynamic-symbols"), "runtimeImplementationAvailable" to pairBool(false),
    "negativeCompleteness" to pairBool(false), "entries" to pairArray(inventory.dynamicSymbols.filter { budget.step("namespace symbol"); pairEligible(it) }.map {
        val identity = pairImportIdentity(inventory.inputSha256, it)
        pairObject("id" to pairString("ext-${OracleArtifacts.sha256(budget.encode(identity))}"), "identity" to identity)
    }))
private fun pairRelocationReceipt(r: ElfDynamicRelocationV1): JsonObject = pairObject(
    "locator" to pairString(r.locator), "sectionIndex" to pairNumber(r.sectionIndex), "relocationIndex" to pairNumber(r.relocationIndex),
    "fileOffset" to pairNumber(r.fileOffset), "slotAddress" to pairHex(r.offset), "type" to pairNumber(r.type),
    "addend" to (r.addend?.let(::pairNumber) ?: JsonNull), "symbolTableSectionIndex" to pairNumber(r.symbolTableSectionIndex),
    "symbolIndex" to pairNumber(r.symbolIndex), "dynamicTables" to pairArray(r.dynamicTables.map(::pairString)),
    "slotFileOffset" to (r.slotFileOffset?.let(::pairNumber) ?: JsonNull), "slotLoadIndices" to pairArray(r.slotLoadIndices.map(::pairNumber)),
    "dispositions" to pairArray(r.dispositions.map(::pairString)))

private class PairBudget(val limits: ElfExternalNamespacePairLimitsV1, val checkpoint: (String) -> Unit) {
    private val started = System.nanoTime()
    private var work = 0L; private var reads = 0L; private var retained = 4096L; private var codeProofs = 0
    fun step(stage: String) {
        require(++work <= limits.maximumWorkUnits) { "external namespace pair work limit exceeded" }
        require(!Thread.currentThread().isInterrupted) { "external namespace pair interrupted" }
        require((System.nanoTime() - started) / 1_000_000 < limits.maximumWallMillis) { "external namespace pair deadline exceeded" }
        checkpoint(stage)
    }
    fun retain(bytes: Long) { step("reserve pair output"); retained = Math.addExact(retained, bytes); require(retained <= limits.maximumOutputBytes) { "external namespace pair output limit exceeded" } }
    fun retainString(value: String) { retain(Math.addExact(value.toByteArray(Charsets.UTF_8).size.toLong() * 6, 32)) }
    fun reserveParsers(): ElfDynamicBindingLimitsV1 {
        val parserWork = limits.maximumWorkUnits / 4
        val parserReads = minOf(limits.maximumReadBytes / 4, 256L * 1024 * 1024)
        work = Math.addExact(work, parserWork * 2); readReservation(parserReads * 2); step("reserve two bounded ELF scans")
        return ElfDynamicBindingLimitsV1(maximumWorkUnits = parserWork, maximumReadBytes = parserReads,
            maximumOutputBytes = limits.maximumOutputBytes)
    }
    fun reserveScannerAuthentications(richBytes: Long, strippedBytes: Long) {
        // Both reused scanners terminally hash the file. These reads are outside their metadata
        // read caps; reserve them here. Per-chunk cancellation uses each caller-opened descriptor's
        // authentication checkpoint; this pair additionally checks its deadline after each scan.
        readReservation(Math.multiplyExact(Math.addExact(richBytes, strippedBytes), 2))
        val chunks = (richBytes + 1024 * 1024 - 1) / (1024 * 1024) + (strippedBytes + 1024 * 1024 - 1) / (1024 * 1024)
        work = Math.addExact(work, Math.multiplyExact(chunks + 4, 2))
        step("reserve scanner terminal authentication reads")
    }
    private fun readReservation(bytes: Long) { reads = Math.addExact(reads, bytes); require(reads <= limits.maximumReadBytes) { "external namespace pair read limit exceeded" } }
    fun read(file: StableControlFile, offset: Long, length: Int, label: String): ByteArray {
        step(label); readReservation(length.toLong()); return file.readExactly(offset, length, label, ::step)
    }
    fun authenticate(file: StableControlFile, label: String) {
        step("authenticate $label"); readReservation(file.size)
        require(file.sha256(::step, label) == file.authenticatedSha256) { "$label changed bytes" }
        file.requirePathAndIdentity(label)
    }
    fun code() { step("twin code proof"); require(++codeProofs <= limits.maximumCodeProofs) { "external namespace code-proof limit exceeded" } }
    fun encode(value: JsonElement): ByteArray = OracleJson.canonicalBytes(value, pairJsonLimits(limits.maximumOutputBytes), ::step)
}
private val PAIR_UNSUPPORTED_WRITES = setOf("packed-relr-relocations-not-expanded", "android-packed-relocations-not-expanded", "unclassified-dynamic-tag")
private fun pairJsonLimits(bytes: Int) = StrictJsonLimits(maximumInputBytes = bytes, maximumCanonicalBytes = bytes,
    maximumNodes = 1_000_000, maximumStringBytes = bytes, maximumTotalStringBytes = bytes)
private fun pairObject(vararg fields: Pair<String, JsonElement>): JsonObject = JsonObject(Collections.unmodifiableMap(linkedMapOf(*fields)))
private fun pairFlatSnapshot(value: JsonObject): JsonObject {
    require(value.values.all { it is JsonPrimitive }) { "write coverage must remain a flat closed record" }
    return JsonObject(Collections.unmodifiableMap(LinkedHashMap(value)))
}
private fun pairArray(values: List<JsonElement>): JsonArray = JsonArray(Collections.unmodifiableList(ArrayList(values)))
private fun pairNumber(value: Number): JsonPrimitive = JsonPrimitive(value)
private fun pairString(value: String): JsonPrimitive = JsonPrimitive(value)
private fun pairNullable(value: String?): JsonElement = value?.let(::pairString) ?: JsonNull
private fun JsonElement?.orNull(): JsonElement = this ?: JsonNull
private fun pairHex(value: ULong?): JsonElement = value?.let { pairString("0x${it.toString(16)}") } ?: JsonNull
private fun pairBool(value: Boolean): JsonPrimitive = JsonPrimitive(value)
private fun pairBytes(value: ByteArray): String = value.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
private fun pairAdd(a: ULong, b: ULong): ULong { require(b <= ULong.MAX_VALUE - a) { "twin coordinate overflow" }; return a + b }
