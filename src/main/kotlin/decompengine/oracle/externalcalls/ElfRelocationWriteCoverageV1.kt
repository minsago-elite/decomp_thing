package decompengine.oracle.externalcalls

import decompengine.oracle.fulltree.FullTreeControlException
import decompengine.oracle.fulltree.FullTreeElfSymbolSectionKind
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal data class ElfRelocationWriteLimitsV1(
    val maximumRelocations: Int = 1_000_000,
    val maximumWorkUnits: Long = 100_000_000,
) {
    init { require(maximumRelocations in 1..1_000_000 && maximumWorkUnits in 1..100_000_000) }
}

internal data class ElfRelocationWriteAssessmentV1(
    val slot: ULong, val candidateLocator: String, val candidateActive: Boolean, val candidateCoversSlot: Boolean,
    val slotAddressOverflow: Boolean, val unknownWriteWidth: Boolean, val writeAddressOverflow: Boolean,
    val overlappingWrite: Boolean, val overlapLocator: String?, val unknownWidthLocator: String?, val overflowLocator: String?,
) {
    /** Only the encoded relocation write bounds; not runtime provider, instruction, or call authority. */
    val safeForStaticSlotAssociation: Boolean get() = candidateActive && candidateCoversSlot &&
        !slotAddressOverflow && !unknownWriteWidth && !writeAddressOverflow && !overlappingWrite

    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "kind" to JsonPrimitive("elf-relocation-slot-write-coverage-v1"),
        "slotAddress" to JsonPrimitive("0x${slot.toString(16)}"), "candidateLocator" to JsonPrimitive(candidateLocator),
        "candidateActive" to JsonPrimitive(candidateActive), "candidateCoversSlot" to JsonPrimitive(candidateCoversSlot),
        "slotAddressOverflow" to JsonPrimitive(slotAddressOverflow), "unknownWriteWidth" to JsonPrimitive(unknownWriteWidth),
        "writeAddressOverflow" to JsonPrimitive(writeAddressOverflow), "overlappingWrite" to JsonPrimitive(overlappingWrite),
        "overlapLocator" to nullableLocator(overlapLocator), "unknownWidthLocator" to nullableLocator(unknownWidthLocator),
        "overflowLocator" to nullableLocator(overflowLocator),
        "safeForStaticSlotAssociation" to JsonPrimitive(safeForStaticSlotAssociation),
        "negativeCompleteness" to JsonPrimitive(false),
    ))
}

/**
 * Bounded potential writes by active DT-tagged ELF64 x86-64 relocations. Unknown widths and
 * overflowing writes are global uncertainty, never treated as distant/harmless. Packed and unknown
 * dynamic mechanisms are a separate inventory-level gate owned by the composer. This index does
 * not model arbitrary code executed by resolvers, constructors, interposition, or runtime mutation.
 *
 * Width/type source pins (LP64):
 * https://github.com/bminor/glibc/blob/04e750e75b73957cf1c791535a3f4319534a52fc/elf/elf.h#L3380
 * https://github.com/bminor/glibc/blob/04e750e75b73957cf1c791535a3f4319534a52fc/sysdeps/x86_64/dl-machine.h#L230
 * https://github.com/bminor/glibc/blob/04e750e75b73957cf1c791535a3f4319534a52fc/sysdeps/x86_64/dl-tlsdesc.h#L21
 * COPY is conservatively bounded by the defined destination's declared size (the actual provider
 * may supply fewer bytes). TLSDESC owns two 8-byte slots. Unsupported linker/processor types remain
 * unknown even when their names suggest a width. NONE is an explicit zero write, not an omission.
 */
internal class ElfRelocationWriteCoverageV1 private constructor(
    private val active: Map<RelocationKey, IndexedRelocation>, private val root: WriteNode?,
    private val firstUnknown: String?, private val firstOverflow: String?, private val budget: WriteBudget,
) {
    fun assess(slot: ULong, candidate: ElfDynamicRelocationV1): ElfRelocationWriteAssessmentV1 {
        budget.step("assess relocation slot")
        val key = candidate.key()
        val indexed = active[key]
        val candidateActive = indexed != null && indexed.record == candidate
        val slotOverflow = ULong.MAX_VALUE - slot < 7UL
        val covers = candidateActive && !slotOverflow && indexed!!.record.offset == slot && indexed.width == 8UL
        val conflict = if (slotOverflow) null else findOther(root, slot, slot + 7UL, if (candidateActive) key else null)
        return ElfRelocationWriteAssessmentV1(slot, candidate.locator, candidateActive, covers, slotOverflow,
            firstUnknown != null, firstOverflow != null, conflict != null, conflict?.record?.locator, firstUnknown, firstOverflow)
    }

    /** The augmented balanced tree stops at the first witness; it never enumerates every overlap. */
    private fun findOther(node: WriteNode?, start: ULong, endInclusive: ULong, excluded: RelocationKey?): IndexedRelocation? {
        budget.step("query relocation write interval")
        if (node == null || node.maximumEndInclusive < start || node.minimumStart > endInclusive) return null
        val item = node.item
        if (item.record.offset <= endInclusive && item.endInclusive!! >= start && item.record.key() != excluded) return item
        return findOther(node.left, start, endInclusive, excluded) ?: findOther(node.right, start, endInclusive, excluded)
    }

    companion object {
        fun build(
            inventory: ElfDynamicBindingInventoryV1,
            limits: ElfRelocationWriteLimitsV1 = ElfRelocationWriteLimitsV1(), charge: (String) -> Unit = {},
        ): ElfRelocationWriteCoverageV1 {
            require(inventory.structure.core.elfClass == 2 && inventory.structure.core.byteOrder == 1 && inventory.structure.core.machine == 62) {
                "relocation write coverage requires ELF64 little-endian x86-64"
            }
            if (inventory.relocations.size > limits.maximumRelocations || inventory.dynamicSymbols.size > 131_072)
                throw FullTreeControlException("relocation write index population exceeds its bound")
            val budget = WriteBudget(limits.maximumWorkUnits, charge)
            val symbols = HashMap<Pair<Int, Long>, ElfDynamicSymbolV1>()
            inventory.dynamicSymbols.forEach { symbol ->
                budget.step("index relocation symbols")
                if (symbols.put(symbol.tableSectionIndex to symbol.symbolIndex, symbol) != null)
                    throw FullTreeControlException("duplicate dynamic symbol identity in relocation write index")
            }
            val active = HashMap<RelocationKey, IndexedRelocation>()
            val writes = arrayListOf<IndexedRelocation>()
            var firstUnknown: String? = null; var firstOverflow: String? = null
            inventory.relocations.forEach { record ->
                budget.step("index relocation write")
                if (record.dynamicTables.isEmpty() || record.symbolTableSectionIndex != inventory.activeSymbolTableSectionIndex) return@forEach
                if (record.dynamicTables.size > 3 || record.dynamicTables.any { it !in setOf("rela", "rel", "jmprel") })
                    throw FullTreeControlException("invalid active dynamic relocation membership")
                val width = writeWidth(record, symbols[record.symbolTableSectionIndex to record.symbolIndex], inventory)
                val overflow = width != null && width > 0UL && ULong.MAX_VALUE - record.offset < width - 1UL
                val end = if (width == null || width == 0UL || overflow) null else record.offset + (width - 1UL)
                val item = IndexedRelocation(record, width, end)
                if (active.put(record.key(), item) != null)
                    throw FullTreeControlException("duplicate relocation record identity in write index")
                when {
                    width == null -> if (firstUnknown == null) firstUnknown = record.locator
                    overflow -> if (firstOverflow == null) firstOverflow = record.locator
                    width > 0UL -> writes += item
                }
            }
            writes.sortWith { a, b ->
                budget.step("sort relocation write intervals")
                val address = a.record.offset.compareTo(b.record.offset)
                if (address != 0) address else {
                    val section = a.record.sectionIndex.compareTo(b.record.sectionIndex)
                    if (section != 0) section else a.record.relocationIndex.compareTo(b.record.relocationIndex)
                }
            }
            fun tree(begin: Int, end: Int): WriteNode? {
                if (begin == end) return null
                budget.step("build relocation write interval tree")
                val middle = begin + (end - begin) / 2
                val left = tree(begin, middle); val right = tree(middle + 1, end)
                val item = writes[middle]
                return WriteNode(item, left, right, writes[begin].record.offset,
                    maxOf(item.endInclusive!!, left?.maximumEndInclusive ?: 0UL, right?.maximumEndInclusive ?: 0UL))
            }
            return ElfRelocationWriteCoverageV1(active, tree(0, writes.size), firstUnknown, firstOverflow, budget)
        }
    }
}

private fun writeWidth(
    record: ElfDynamicRelocationV1, symbol: ElfDynamicSymbolV1?, inventory: ElfDynamicBindingInventoryV1,
): ULong? = when (record.type) {
    0L -> 0UL // NONE
    1L, 6L, 7L, 8L, 16L, 17L, 18L, 33L, 37L, 38L -> 8UL
    2L, 10L, 32L -> 4UL
    36L -> 16UL
    5L -> {
        val raw = symbol?.raw
        val section = raw?.resolvedSectionIndex?.takeIf { it in 0L..Int.MAX_VALUE.toLong() }
            ?.let { inventory.sections.getOrNull(it.toInt()) }
        if (raw == null || raw.sectionKind != FullTreeElfSymbolSectionKind.DEFINED || raw.value != record.offset ||
            section == null || section.flags and 2UL == 0UL) null else raw.size
    }
    else -> null
}

private data class RelocationKey(val section: Int, val index: Long)
private fun ElfDynamicRelocationV1.key(): RelocationKey = RelocationKey(sectionIndex, relocationIndex)
private data class IndexedRelocation(val record: ElfDynamicRelocationV1, val width: ULong?, val endInclusive: ULong?)
private data class WriteNode(
    val item: IndexedRelocation, val left: WriteNode?, val right: WriteNode?,
    val minimumStart: ULong, val maximumEndInclusive: ULong,
)
private class WriteBudget(val maximum: Long, val charge: (String) -> Unit) {
    private var used = 0L
    fun step(phase: String) {
        if (++used > maximum) throw FullTreeControlException("relocation write index work bound exceeded")
        charge(phase)
    }
}
private fun nullableLocator(value: String?): JsonElement = value?.let(::JsonPrimitive) ?: JsonNull
