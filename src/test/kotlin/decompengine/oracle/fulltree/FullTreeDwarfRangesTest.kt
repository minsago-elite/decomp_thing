package decompengine.oracle.fulltree

import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class FullTreeDwarfRangesTest {
    @Test
    fun `legacy ranges use the CU base and base selections in producer order`() {
        val maximum = ULong.MAX_VALUE
        val bytes = pair(0x10UL, 0x10UL) +
            pair(maximum, 0x5000UL) +
            pair(0x20UL, 0x30UL) +
            pair(maximum, 0x6000UL) +
            pair(1UL, 2UL) +
            pair(0UL, 0UL)

        assertEquals(
            0x5020UL,
            firstStart(
                input(bytes, FullTreeDwarfRangeListEncoding.DEBUG_RANGES, version = 4),
                compilationUnitLowPc = 0x1000UL,
            ),
        )

        val bigEndian = pair(2UL, 3UL, ByteOrder.BIG_ENDIAN) +
            pair(0UL, 0UL, ByteOrder.BIG_ENDIAN)
        assertEquals(
            0x1002UL,
            firstStart(
                input(
                    bigEndian,
                    FullTreeDwarfRangeListEncoding.DEBUG_RANGES,
                    version = 2,
                    byteOrder = ByteOrder.BIG_ENDIAN,
                ),
                compilationUnitLowPc = 0x1000UL,
            ),
        )

        val wideBaseSelection = ByteArray(16) { 0xff.toByte() } + wideAddress(0x7000UL) +
            wideAddress(0x20UL) + wideAddress(0x30UL) +
            wideAddress(0UL) + wideAddress(0UL)
        assertEquals(
            0x7020UL,
            firstStart(
                input(
                    wideBaseSelection,
                    FullTreeDwarfRangeListEncoding.DEBUG_RANGES,
                    version = 4,
                    addressSize = 16,
                ),
            ),
        )
    }

    @Test
    fun `version five accepts every standard range-list encoding`() {
        val addressSection = section(
            addressContribution(listOf(0x4000UL, 0x8000UL, 0x8010UL, 0x9000UL)),
            ".debug_addr",
        )
        val resolver = FullTreeDwarfAddressResolver(
            section = addressSection,
            addressBase = 8L,
            version = 5,
            offsetSize = 4,
            addressSize = 8,
        )
        val bytes = byteArrayOf(DW_RLE_BASE_ADDRESSX_TEST) + uleb(0UL) +
            byteArrayOf(DW_RLE_OFFSET_PAIR_TEST) + uleb(0x10UL) + uleb(0x10UL) +
            byteArrayOf(DW_RLE_OFFSET_PAIR_TEST) + uleb(0x20UL) + uleb(0x30UL) +
            byteArrayOf(DW_RLE_STARTX_ENDX_TEST) + uleb(1UL) + uleb(2UL) +
            byteArrayOf(DW_RLE_STARTX_LENGTH_TEST) + uleb(3UL) + uleb(0x10UL) +
            byteArrayOf(DW_RLE_BASE_ADDRESS_TEST) + unsigned(0xa000UL, 8) +
            byteArrayOf(DW_RLE_OFFSET_PAIR_TEST) + uleb(1UL) + uleb(2UL) +
            byteArrayOf(DW_RLE_START_END_TEST) + unsigned(0xb000UL, 8) + unsigned(0xb010UL, 8) +
            byteArrayOf(DW_RLE_START_LENGTH_TEST) + unsigned(0xc000UL, 8) + uleb(0x10UL) +
            byteArrayOf(DW_RLE_END_OF_LIST_TEST)

        assertEquals(
            0x4020UL,
            firstStart(
                input(bytes, FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS, version = 5),
                addressResolver = resolver,
            ),
        )

        val initialBase = byteArrayOf(DW_RLE_OFFSET_PAIR_TEST) + uleb(5UL) + uleb(8UL) +
            byteArrayOf(DW_RLE_END_OF_LIST_TEST)
        assertEquals(
            0x1005UL,
            firstStart(
                input(initialBase, FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS, version = 5),
                compilationUnitLowPc = 0x1000UL,
            ),
        )
    }

    @Test
    fun `later malformed and overflowing entries cannot hide behind a usable start`() {
        val validThenUnknown = byteArrayOf(DW_RLE_START_END_TEST) +
            unsigned(0x10UL, 8) + unsigned(0x20UL, 8) + byteArrayOf(0x7f)
        assertFailsWith<FullTreeControlException> {
            firstStart(
                input(
                    validThenUnknown,
                    FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS,
                    version = 5,
                ),
            )
        }

        val validThenOverflow = byteArrayOf(DW_RLE_START_END_TEST) +
            unsigned(0x10UL, 8) + unsigned(0x20UL, 8) +
            byteArrayOf(DW_RLE_START_LENGTH_TEST) + unsigned(ULong.MAX_VALUE, 8) + uleb(1UL) +
            byteArrayOf(DW_RLE_END_OF_LIST_TEST)
        assertFailsWith<FullTreeControlException> {
            firstStart(
                input(
                    validThenOverflow,
                    FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS,
                    version = 5,
                ),
            )
        }

        val offsetOverflow = byteArrayOf(DW_RLE_BASE_ADDRESS_TEST) +
            unsigned(ULong.MAX_VALUE, 8) +
            byteArrayOf(DW_RLE_OFFSET_PAIR_TEST) + uleb(1UL) + uleb(2UL) +
            byteArrayOf(DW_RLE_END_OF_LIST_TEST)
        assertFailsWith<FullTreeControlException> {
            firstStart(
                input(
                    offsetOverflow,
                    FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS,
                    version = 5,
                ),
            )
        }

        val legacyOverflow = pair(1UL, 2UL) +
            pair(ULong.MAX_VALUE, ULong.MAX_VALUE) +
            pair(1UL, 2UL) + pair(0UL, 0UL)
        assertFailsWith<FullTreeControlException> {
            firstStart(
                input(legacyOverflow, FullTreeDwarfRangeListEncoding.DEBUG_RANGES, version = 4),
            )
        }
    }

    @Test
    fun `indexed entries require the matching bounded address contribution`() {
        val indexed = byteArrayOf(DW_RLE_STARTX_ENDX_TEST) + uleb(0UL) + uleb(1UL) +
            byteArrayOf(DW_RLE_END_OF_LIST_TEST)
        val rangeInput = input(indexed, FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS, version = 5)
        assertFailsWith<FullTreeControlException> { firstStart(rangeInput) }

        val oneAddress = section(addressContribution(listOf(0x1000UL)), ".debug_addr")
        val resolver = FullTreeDwarfAddressResolver(oneAddress, 8L, 5, 4, 8)
        assertFailsWith<FullTreeControlException> {
            firstStart(rangeInput, addressResolver = resolver)
        }

        val indexedLength = byteArrayOf(DW_RLE_STARTX_LENGTH_TEST) + uleb(0UL) + uleb(1UL) +
            byteArrayOf(DW_RLE_END_OF_LIST_TEST)
        val maximumAddress = section(addressContribution(listOf(ULong.MAX_VALUE)), ".debug_addr maximum")
        val maximumResolver = FullTreeDwarfAddressResolver(maximumAddress, 8L, 5, 4, 8)
        assertFailsWith<FullTreeControlException> {
            firstStart(
                input(indexedLength, FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS, version = 5),
                addressResolver = maximumResolver,
            )
        }
    }

    @Test
    fun `terminators bounds wide addresses and the shared budget fail closed`() {
        assertFailsWith<FullTreeControlException> {
            firstStart(
                input(
                    byteArrayOf(DW_RLE_BASE_ADDRESS_TEST) + unsigned(1UL, 8),
                    FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS,
                    version = 5,
                ),
            )
        }
        assertFailsWith<FullTreeControlException> {
            firstStart(
                input(
                    byteArrayOf(DW_RLE_START_END_TEST) + unsigned(1UL, 8) + unsigned(2UL, 8),
                    FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS,
                    version = 5,
                ),
                budget = 1L,
            )
        }
        assertFailsWith<FullTreeControlException> {
            firstStart(
                input(
                    pair(1UL, 2UL),
                    FullTreeDwarfRangeListEncoding.DEBUG_RANGES,
                    version = 4,
                ),
            )
        }

        val wide = byteArrayOf(DW_RLE_START_END_TEST) +
            ByteArray(16) { if (it == 15) 1 else 0 } + ByteArray(16) +
            byteArrayOf(DW_RLE_END_OF_LIST_TEST)
        assertFailsWith<FullTreeControlException> {
            firstStart(
                input(
                    wide,
                    FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS,
                    version = 5,
                    addressSize = 16,
                ),
            )
        }
    }

    @Test
    fun `segmented rnglists contributions are rejected before interpretation`() {
        val contribution = section(
            rnglistsContribution(
                offsets = listOf(4UL),
                lists = byteArrayOf(DW_RLE_END_OF_LIST_TEST),
                segmentSelectorSize = 1,
            ),
            ".debug_rnglists segmented",
        )
        val resolver = FullTreeDwarfRangeListResolver(
            version = 5,
            addressSize = 8,
            offsetSize = 4,
            debugRanges = null,
            debugRnglists = contribution,
            rnglistsBase = 12L,
            parseBudget = FullTreeDwarfParseBudget(16L),
        )
        assertFailsWith<FullTreeControlException> {
            resolver.resolve(
                FullTreeDwarfRangeListIndexValue(FULL_TREE_DW_FORM_RNGLISTX, 0UL, 0),
            )
        }
    }

    @Test
    fun `the historical entry limit is exact`() {
        val accepted = repeatedBaseEntries(FullTreeDwarfRanges.MAXIMUM_ENTRIES)
        assertEquals(
            null,
            firstStart(
                input(accepted, FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS, version = 5, addressSize = 1),
                budget = FullTreeDwarfRanges.MAXIMUM_ENTRIES.toLong() + 1L,
            ),
        )

        val rejected = repeatedBaseEntries(FullTreeDwarfRanges.MAXIMUM_ENTRIES + 1)
        assertFailsWith<FullTreeControlException> {
            firstStart(
                input(rejected, FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS, version = 5, addressSize = 1),
                budget = FullTreeDwarfRanges.MAXIMUM_ENTRIES.toLong() + 2L,
            )
        }
    }

    private fun firstStart(
        input: FullTreeDwarfRangeListInput,
        addressResolver: FullTreeDwarfAddressResolver? = null,
        compilationUnitLowPc: ULong? = null,
        budget: Long = 1_000_000L,
    ): ULong? = FullTreeDwarfRanges.firstNonEmptyStart(
        input = input,
        addressResolver = addressResolver,
        compilationUnitLowPc = compilationUnitLowPc,
        parseBudget = FullTreeDwarfParseBudget(budget),
    )

    private fun input(
        bytes: ByteArray,
        encoding: FullTreeDwarfRangeListEncoding,
        version: Int,
        addressSize: Int = 8,
        byteOrder: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    ): FullTreeDwarfRangeListInput {
        val section = section(bytes, "range-list test section", byteOrder)
        return FullTreeDwarfRangeListInput(
            section = section,
            encoding = encoding,
            offset = 0L,
            endOffset = bytes.size.toLong(),
            dwarfVersion = version,
            addressSize = addressSize,
            offsetSize = 4,
        )
    }

    private fun repeatedBaseEntries(count: Int): ByteArray {
        val result = ByteArray(Math.addExact(Math.multiplyExact(count, 2), 1))
        repeat(count) { index -> result[index * 2] = DW_RLE_BASE_ADDRESS_TEST }
        result[result.lastIndex] = DW_RLE_END_OF_LIST_TEST
        return result
    }

    private fun pair(
        begin: ULong,
        end: ULong,
        byteOrder: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    ): ByteArray = unsigned(begin, 8, byteOrder) + unsigned(end, 8, byteOrder)

    private fun wideAddress(value: ULong): ByteArray = unsigned(value, 8) + ByteArray(8)

    private fun addressContribution(values: List<ULong>): ByteArray {
        val body = byteArrayOf(0x05, 0x00, 0x08, 0x00) +
            values.fold(ByteArray(0)) { bytes, value -> bytes + unsigned(value, 8) }
        return unsigned(body.size.toULong(), 4) + body
    }

    private fun rnglistsContribution(
        offsets: List<ULong>,
        lists: ByteArray,
        segmentSelectorSize: Int,
    ): ByteArray {
        val header = byteArrayOf(0x05, 0x00, 0x08, segmentSelectorSize.toByte()) +
            unsigned(offsets.size.toULong(), 4)
        val table = offsets.fold(ByteArray(0)) { bytes, offset -> bytes + unsigned(offset, 4) }
        val body = header + table + lists
        return unsigned(body.size.toULong(), 4) + body
    }

    private fun unsigned(
        value: ULong,
        width: Int,
        byteOrder: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    ): ByteArray {
        val little = ByteArray(width) { index -> ((value shr (index * 8)) and 0xffUL).toByte() }
        return if (byteOrder == ByteOrder.LITTLE_ENDIAN) little else little.reversedArray()
    }

    private fun uleb(value: ULong): ByteArray {
        var remaining = value
        val bytes = ArrayList<Byte>()
        do {
            var byte = (remaining and 0x7fUL).toByte()
            remaining = remaining shr 7
            if (remaining != 0UL) byte = (byte.toInt() or 0x80).toByte()
            bytes += byte
        } while (remaining != 0UL)
        return bytes.toByteArray()
    }

    private fun section(
        bytes: ByteArray,
        label: String,
        byteOrder: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    ) = FullTreeDwarfSection(
        size = bytes.size.toLong(),
        byteOrder = byteOrder,
        label = label,
        readWindow = { offset, length ->
            bytes.copyOfRange(offset.toInt(), Math.addExact(offset.toInt(), length))
        },
    )
}

private const val DW_RLE_END_OF_LIST_TEST: Byte = 0x00
private const val DW_RLE_BASE_ADDRESSX_TEST: Byte = 0x01
private const val DW_RLE_STARTX_ENDX_TEST: Byte = 0x02
private const val DW_RLE_STARTX_LENGTH_TEST: Byte = 0x03
private const val DW_RLE_OFFSET_PAIR_TEST: Byte = 0x04
private const val DW_RLE_BASE_ADDRESS_TEST: Byte = 0x05
private const val DW_RLE_START_END_TEST: Byte = 0x06
private const val DW_RLE_START_LENGTH_TEST: Byte = 0x07
