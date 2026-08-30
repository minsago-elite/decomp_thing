package decompengine.oracle.fulltree

/**
 * Bounded interpretation of one artifact-backed DWARF range list.
 *
 * The first non-empty range retains producer order, matching the historical v3 function oracle.
 * Parsing nevertheless continues through the list terminator so malformed or overflowing later
 * entries cannot hide behind an earlier usable range.
 */
internal object FullTreeDwarfRanges {
    internal const val MAXIMUM_ENTRIES = 250_000

    fun firstNonEmptyStart(
        input: FullTreeDwarfRangeListInput,
        addressResolver: FullTreeDwarfAddressResolver?,
        compilationUnitLowPc: ULong?,
        parseBudget: FullTreeDwarfParseBudget,
    ): ULong? {
        if (input.addressSize !in 1..16) {
            throw FullTreeControlException("DWARF range-list address size is invalid")
        }
        if (input.offsetSize !in setOf(4, 8)) {
            throw FullTreeControlException("DWARF range-list offset size is invalid")
        }
        return when (input.encoding) {
            FullTreeDwarfRangeListEncoding.DEBUG_RANGES -> {
                if (input.dwarfVersion !in 2..4) {
                    throw FullTreeControlException(".debug_ranges requires DWARF version 2 through 4")
                }
                firstLegacyStart(input, compilationUnitLowPc ?: 0UL, parseBudget)
            }
            FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS -> {
                if (input.dwarfVersion != 5) {
                    throw FullTreeControlException(".debug_rnglists requires DWARF version 5")
                }
                firstVersionFiveStart(
                    input,
                    addressResolver,
                    compilationUnitLowPc ?: 0UL,
                    parseBudget,
                )
            }
        }
    }

    private fun firstLegacyStart(
        input: FullTreeDwarfRangeListInput,
        initialBase: ULong,
        parseBudget: FullTreeDwarfParseBudget,
    ): ULong? {
        val cursor = input.cursor()
        var base = initialBase
        var firstStart: ULong? = null
        var entries = 0
        while (true) {
            requireEntryBytes(cursor, ".debug_ranges list")
            parseBudget.consume("DWARF range-list entries")
            val begin = readLegacyBegin(cursor, input.addressSize)
            val end = cursor.readAddress(input.addressSize)
            if (!begin.isBaseSelection && begin.value == 0UL && end == 0UL) return firstStart
            entries = countEntry(entries)
            if (begin.isBaseSelection) {
                base = end
            } else {
                val absoluteBegin = checkedAdd(base, begin.value)
                val absoluteEnd = checkedAdd(base, end)
                firstStart = retainFirstNonEmpty(firstStart, absoluteBegin, absoluteEnd)
            }
        }
    }

    private fun firstVersionFiveStart(
        input: FullTreeDwarfRangeListInput,
        addressResolver: FullTreeDwarfAddressResolver?,
        initialBase: ULong,
        parseBudget: FullTreeDwarfParseBudget,
    ): ULong? {
        val cursor = input.cursor()
        var base = initialBase
        var firstStart: ULong? = null
        var entries = 0
        while (true) {
            requireEntryBytes(cursor, ".debug_rnglists list")
            parseBudget.consume("DWARF range-list entries")
            when (val encoding = cursor.readUnsigned(1).toInt()) {
                DW_RLE_END_OF_LIST -> return firstStart
                DW_RLE_BASE_ADDRESSX -> {
                    entries = countEntry(entries)
                    base = resolveAddress(addressResolver, cursor.readUleb128Bits())
                }
                DW_RLE_STARTX_ENDX -> {
                    entries = countEntry(entries)
                    val begin = resolveAddress(addressResolver, cursor.readUleb128Bits())
                    val end = resolveAddress(addressResolver, cursor.readUleb128Bits())
                    firstStart = retainFirstNonEmpty(firstStart, begin, end)
                }
                DW_RLE_STARTX_LENGTH -> {
                    entries = countEntry(entries)
                    val begin = resolveAddress(addressResolver, cursor.readUleb128Bits())
                    val end = checkedAdd(begin, cursor.readUleb128Bits())
                    firstStart = retainFirstNonEmpty(firstStart, begin, end)
                }
                DW_RLE_OFFSET_PAIR -> {
                    entries = countEntry(entries)
                    val begin = checkedAdd(base, cursor.readUleb128Bits())
                    val end = checkedAdd(base, cursor.readUleb128Bits())
                    firstStart = retainFirstNonEmpty(firstStart, begin, end)
                }
                DW_RLE_BASE_ADDRESS -> {
                    entries = countEntry(entries)
                    base = cursor.readAddress(input.addressSize)
                }
                DW_RLE_START_END -> {
                    entries = countEntry(entries)
                    val begin = cursor.readAddress(input.addressSize)
                    val end = cursor.readAddress(input.addressSize)
                    firstStart = retainFirstNonEmpty(firstStart, begin, end)
                }
                DW_RLE_START_LENGTH -> {
                    entries = countEntry(entries)
                    val begin = cursor.readAddress(input.addressSize)
                    val end = checkedAdd(begin, cursor.readUleb128Bits())
                    firstStart = retainFirstNonEmpty(firstStart, begin, end)
                }
                else -> throw FullTreeControlException(
                    ".debug_rnglists list uses unsupported DW_RLE encoding 0x${encoding.toString(16)}",
                )
            }
        }
    }

    private fun requireEntryBytes(cursor: FullTreeDwarfSectionCursor, label: String) {
        if (cursor.position >= cursor.limit) {
            throw FullTreeControlException("$label is unterminated")
        }
    }

    private fun countEntry(previous: Int): Int {
        if (previous >= MAXIMUM_ENTRIES) {
            throw FullTreeControlException(
                "DWARF range list exceeds the $MAXIMUM_ENTRIES-entry limit",
            )
        }
        return previous + 1
    }

    private fun resolveAddress(
        resolver: FullTreeDwarfAddressResolver?,
        index: ULong,
    ): ULong {
        val required = resolver ?: throw FullTreeControlException(
            "indexed DWARF range entry requires a validated .debug_addr contribution",
        )
        return required.resolve(
            FullTreeDwarfAddressIndexValue(
                resolvedForm = FULL_TREE_DW_FORM_ADDRX,
                rawValue = index,
                indirectDepth = 0,
            ),
        )
    }

    private fun checkedAdd(left: ULong, right: ULong): ULong {
        if (right > ULong.MAX_VALUE - left) {
            throw FullTreeControlException("DWARF range overflows unsigned 64-bit address space")
        }
        return left + right
    }

    private fun retainFirstNonEmpty(first: ULong?, begin: ULong, end: ULong): ULong? =
        if (first == null && begin < end) begin else first

    private fun readLegacyBegin(
        cursor: FullTreeDwarfSectionCursor,
        addressSize: Int,
    ): LegacyRangeBegin {
        val maximumAddress = maximumEncodedAddress(addressSize)
        if (maximumAddress != null) {
            val value = cursor.readAddress(addressSize)
            return LegacyRangeBegin(value, value == maximumAddress)
        }

        // For 9-16 byte targets the all-ones base-selection marker itself is wider than ULong.
        // The shared address reader leaves the cursor untouched on this precise failure, allowing
        // the marker to be recognized bytewise while all other wide values remain rejected.
        val initialPosition = cursor.position
        val failure = try {
            return LegacyRangeBegin(cursor.readAddress(addressSize), false)
        } catch (candidate: FullTreeControlException) {
            candidate
        }
        if (
            cursor.position != initialPosition ||
            failure.message != ".debug_ranges list address exceeds the supported range"
        ) {
            throw failure
        }
        repeat(addressSize) {
            if (cursor.readUnsigned(1) != 0xffL) throw failure
        }
        return LegacyRangeBegin(0UL, true)
    }

    private fun maximumEncodedAddress(addressSize: Int): ULong? = when {
        addressSize > 8 -> null
        addressSize == 8 -> ULong.MAX_VALUE
        else -> (1UL shl (addressSize * 8)) - 1UL
    }

    private data class LegacyRangeBegin(val value: ULong, val isBaseSelection: Boolean)
}

private const val DW_RLE_END_OF_LIST = 0x00
private const val DW_RLE_BASE_ADDRESSX = 0x01
private const val DW_RLE_STARTX_ENDX = 0x02
private const val DW_RLE_STARTX_LENGTH = 0x03
private const val DW_RLE_OFFSET_PAIR = 0x04
private const val DW_RLE_BASE_ADDRESS = 0x05
private const val DW_RLE_START_END = 0x06
private const val DW_RLE_START_LENGTH = 0x07
