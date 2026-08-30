package decompengine.oracle.fulltree

import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class FullTreeDwarfFormsTest {
    @Test
    fun `constant context retains effective forms signedness and indirect depth`() {
        val unsigned = listOf(
            Triple(FULL_TREE_DW_FORM_DATA1, unsigned(0xffUL, 1), 0xffUL),
            Triple(FULL_TREE_DW_FORM_DATA2, unsigned(0xffffUL, 2), 0xffffUL),
            Triple(FULL_TREE_DW_FORM_DATA4, unsigned(0xffff_ffffUL, 4), 0xffff_ffffUL),
            Triple(FULL_TREE_DW_FORM_DATA8, unsigned(ULong.MAX_VALUE, 8), ULong.MAX_VALUE),
            Triple(FULL_TREE_DW_FORM_UDATA, uleb(ULong.MAX_VALUE), ULong.MAX_VALUE),
        )
        unsigned.forEach { (form, bytes, raw) ->
            val value = assertIs<FullTreeDwarfUnsignedConstantValue>(
                readForm(bytes, form, context = FullTreeDwarfFormContext.CONSTANT),
            )
            assertEquals(form, value.resolvedForm)
            assertEquals(raw, value.rawValue)
            assertEquals(0, value.indirectDepth)
        }

        val signed = assertIs<FullTreeDwarfSignedConstantValue>(
            readForm(
                byteArrayOf(0x7e),
                FULL_TREE_DW_FORM_SDATA,
                context = FullTreeDwarfFormContext.CONSTANT,
            ),
        )
        assertEquals(FULL_TREE_DW_FORM_SDATA, signed.resolvedForm)
        assertEquals(-2L, signed.rawValue)
        assertEquals(0, signed.indirectDepth)

        val implicit = assertIs<FullTreeDwarfSignedConstantValue>(
            readForm(
                byteArrayOf(0),
                FULL_TREE_DW_FORM_IMPLICIT_CONST,
                context = FullTreeDwarfFormContext.CONSTANT,
                implicitConstant = -17L,
            ),
        )
        assertEquals(FULL_TREE_DW_FORM_IMPLICIT_CONST, implicit.resolvedForm)
        assertEquals(-17L, implicit.rawValue)

        val indirectUnsigned = assertIs<FullTreeDwarfUnsignedConstantValue>(
            readForm(
                byteArrayOf(FULL_TREE_DW_FORM_DATA8.toByte()) + unsigned(ULong.MAX_VALUE, 8),
                FULL_TREE_DW_FORM_INDIRECT,
                context = FullTreeDwarfFormContext.CONSTANT,
            ),
        )
        assertEquals(FULL_TREE_DW_FORM_DATA8, indirectUnsigned.resolvedForm)
        assertEquals(ULong.MAX_VALUE, indirectUnsigned.rawValue)
        assertEquals(1, indirectUnsigned.indirectDepth)

        val indirectSigned = assertIs<FullTreeDwarfSignedConstantValue>(
            readForm(
                byteArrayOf(FULL_TREE_DW_FORM_SDATA.toByte(), 0x7e),
                FULL_TREE_DW_FORM_INDIRECT,
                context = FullTreeDwarfFormContext.CONSTANT,
            ),
        )
        assertEquals(FULL_TREE_DW_FORM_SDATA, indirectSigned.resolvedForm)
        assertEquals(-2L, indirectSigned.rawValue)
        assertEquals(1, indirectSigned.indirectDepth)

        // GENERAL is the frozen inventory behavior: signed Long numerics and skipped data16.
        assertEquals(
            FullTreeDwarfNumericValue(7L),
            readForm(unsigned(7UL, 8), FULL_TREE_DW_FORM_DATA8),
        )
        assertEquals(
            FullTreeDwarfNumericValue(-2L),
            readForm(byteArrayOf(0x7e), FULL_TREE_DW_FORM_SDATA),
        )
        assertEquals(
            FullTreeDwarfNumericValue(129L),
            readForm(byteArrayOf(0x81.toByte(), 0x01), FULL_TREE_DW_FORM_UDATA),
        )
        assertEquals(
            FullTreeDwarfNumericValue(17L),
            readForm(
                byteArrayOf(0),
                FULL_TREE_DW_FORM_IMPLICIT_CONST,
                implicitConstant = 17L,
            ),
        )
        assertEquals(
            FullTreeDwarfIgnoredValue,
            readForm(ByteArray(16), FULL_TREE_DW_FORM_DATA16),
        )
        assertFailsWith<FullTreeControlException> {
            readForm(unsigned(ULong.MAX_VALUE, 8), FULL_TREE_DW_FORM_DATA8)
        }
        assertFailsWith<FullTreeControlException> {
            readForm(uleb(ULong.MAX_VALUE), FULL_TREE_DW_FORM_UDATA)
        }
    }

    @Test
    fun `data16 constants honor CU byte order and reject a nonzero high half`() {
        val little = unsigned(ULong.MAX_VALUE, 8) + ByteArray(8)
        val littleValue = assertIs<FullTreeDwarfUnsignedConstantValue>(
            readForm(
                little,
                FULL_TREE_DW_FORM_DATA16,
                context = FullTreeDwarfFormContext.CONSTANT,
            ),
        )
        assertEquals(ULong.MAX_VALUE, littleValue.rawValue)

        val bigRaw = 0x0123_4567_89ab_cdefUL
        val big = ByteArray(8) + unsigned(bigRaw, 8).reversedArray()
        val bigValue = assertIs<FullTreeDwarfUnsignedConstantValue>(
            readForm(
                big,
                FULL_TREE_DW_FORM_DATA16,
                context = FullTreeDwarfFormContext.CONSTANT,
                byteOrder = ByteOrder.BIG_ENDIAN,
            ),
        )
        assertEquals(bigRaw, bigValue.rawValue)

        val indirect = assertIs<FullTreeDwarfUnsignedConstantValue>(
            readForm(
                byteArrayOf(FULL_TREE_DW_FORM_DATA16.toByte()) + little,
                FULL_TREE_DW_FORM_INDIRECT,
                context = FullTreeDwarfFormContext.CONSTANT,
            ),
        )
        assertEquals(FULL_TREE_DW_FORM_DATA16, indirect.resolvedForm)
        assertEquals(ULong.MAX_VALUE, indirect.rawValue)
        assertEquals(1, indirect.indirectDepth)

        val littleOverflow = little.copyOf().also { it[8] = 1 }
        assertFailsWith<FullTreeControlException> {
            readForm(
                littleOverflow,
                FULL_TREE_DW_FORM_DATA16,
                context = FullTreeDwarfFormContext.CONSTANT,
            )
        }
        val bigOverflow = big.copyOf().also { it[0] = 1 }
        assertFailsWith<FullTreeControlException> {
            readForm(
                bigOverflow,
                FULL_TREE_DW_FORM_DATA16,
                context = FullTreeDwarfFormContext.CONSTANT,
                byteOrder = ByteOrder.BIG_ENDIAN,
            )
        }
    }

    @Test
    fun `typed ULEB operands retain the full unsigned 64 bit domain`() {
        val maximum = uleb(ULong.MAX_VALUE)
        val maximumSection = section(maximum)
        assertEquals(
            ULong.MAX_VALUE,
            FullTreeDwarfSectionCursor(
                maximumSection,
                0L,
                maximumSection.size,
                "unsigned ULEB128",
            ).readUleb128Bits(),
        )
        assertFailsWith<FullTreeControlException> {
            val signedSection = section(maximum)
            FullTreeDwarfSectionCursor(
                signedSection,
                0L,
                signedSection.size,
                "signed ULEB128 wrapper",
            ).readUleb128()
        }

        listOf(
            FULL_TREE_DW_FORM_REF_UDATA,
            FULL_TREE_DW_FORM_ADDRX,
            FULL_TREE_DW_FORM_RNGLISTX,
        ).forEach { form ->
            val value = assertIs<FullTreeDwarfUnsignedFormValue>(readForm(maximum, form))
            assertEquals(form, value.resolvedForm)
            assertEquals(ULong.MAX_VALUE, value.rawValue)
        }

        val overflow = ByteArray(10) { index -> if (index == 9) 0x02 else 0x80.toByte() }
        assertFailsWith<FullTreeControlException> {
            val overflowSection = section(overflow)
            FullTreeDwarfSectionCursor(
                overflowSection,
                0L,
                overflowSection.size,
                "overflowing unsigned ULEB128",
            ).readUleb128Bits()
        }
        listOf(
            FULL_TREE_DW_FORM_REF_UDATA,
            FULL_TREE_DW_FORM_ADDRX,
            FULL_TREE_DW_FORM_RNGLISTX,
        ).forEach { form ->
            assertFailsWith<FullTreeControlException> { readForm(overflow, form) }
        }
    }

    @Test
    fun `address index range and reference forms retain raw form metadata`() {
        val address = assertIs<FullTreeDwarfAddressValue>(
            readForm(unsigned(0xfedc_ba98_7654_3210UL, 8), FULL_TREE_DW_FORM_ADDR),
        )
        assertEquals(FULL_TREE_DW_FORM_ADDR, address.resolvedForm)
        assertEquals(0xfedc_ba98_7654_3210UL, address.rawValue)
        assertEquals(0, address.indirectDepth)

        val indexes = listOf(
            Triple(FULL_TREE_DW_FORM_ADDRX, byteArrayOf(0x81.toByte(), 0x01), 129UL),
            Triple(FULL_TREE_DW_FORM_ADDRX1, unsigned(0x12UL, 1), 0x12UL),
            Triple(FULL_TREE_DW_FORM_ADDRX2, unsigned(0x1234UL, 2), 0x1234UL),
            Triple(FULL_TREE_DW_FORM_ADDRX3, unsigned(0x12_3456UL, 3), 0x12_3456UL),
            Triple(FULL_TREE_DW_FORM_ADDRX4, unsigned(0x1234_5678UL, 4), 0x1234_5678UL),
        )
        indexes.forEach { (form, bytes, raw) ->
            val value = assertIs<FullTreeDwarfAddressIndexValue>(readForm(bytes, form))
            assertEquals(form, value.resolvedForm)
            assertEquals(raw, value.rawValue)
            assertEquals(0, value.indirectDepth)
        }

        val references = listOf(
            Triple(FULL_TREE_DW_FORM_REF1, unsigned(0x12UL, 1), 0x12UL),
            Triple(FULL_TREE_DW_FORM_REF2, unsigned(0x1234UL, 2), 0x1234UL),
            Triple(FULL_TREE_DW_FORM_REF4, unsigned(0x1234_5678UL, 4), 0x1234_5678UL),
            Triple(FULL_TREE_DW_FORM_REF8, unsigned(0xfedc_ba98_7654_3210UL, 8), 0xfedc_ba98_7654_3210UL),
            Triple(FULL_TREE_DW_FORM_REF_UDATA, byteArrayOf(0x81.toByte(), 0x01), 129UL),
        )
        references.forEach { (form, bytes, raw) ->
            val value = assertIs<FullTreeDwarfReferenceValue>(readForm(bytes, form))
            assertEquals(form, value.resolvedForm)
            assertEquals(raw, value.rawValue)
            assertEquals(FullTreeDwarfReferenceScope.COMPILATION_UNIT, value.scope)
        }
        val globalV2 = assertIs<FullTreeDwarfReferenceValue>(
            readForm(
                unsigned(0xfedc_ba98_7654_3210UL, 8) + ByteArray(8),
                FULL_TREE_DW_FORM_REF_ADDR,
                version = 2,
                addressSize = 16,
            ),
        )
        assertEquals(0xfedc_ba98_7654_3210UL, globalV2.rawValue)
        assertEquals(FullTreeDwarfReferenceScope.DEBUG_INFO, globalV2.scope)
        val globalV5 = assertIs<FullTreeDwarfReferenceValue>(
            readForm(unsigned(0x1234_5678UL, 4), FULL_TREE_DW_FORM_REF_ADDR),
        )
        assertEquals(0x1234_5678UL, globalV5.rawValue)

        val rangeIndex = assertIs<FullTreeDwarfRangeListIndexValue>(
            readForm(byteArrayOf(0x2a), FULL_TREE_DW_FORM_RNGLISTX),
        )
        assertEquals(FULL_TREE_DW_FORM_RNGLISTX, rangeIndex.resolvedForm)
        assertEquals(42UL, rangeIndex.rawValue)

        // The default is frozen for FullTreeDwarfCompilationUnits' inventory-v1 base handling.
        val inventoryOffset = assertIs<FullTreeDwarfNumericValue>(
            readForm(unsigned(0x1234UL, 4), FULL_TREE_DW_FORM_SEC_OFFSET),
        )
        assertEquals(0x1234L, inventoryOffset.value)
        val rangeOffset = assertIs<FullTreeDwarfRangeSectionOffsetValue>(
            readForm(
                unsigned(0x1234UL, 4),
                FULL_TREE_DW_FORM_SEC_OFFSET,
                context = FullTreeDwarfFormContext.RANGE_LIST,
            ),
        )
        assertEquals(FULL_TREE_DW_FORM_SEC_OFFSET, rangeOffset.resolvedForm)
        assertEquals(0x1234UL, rangeOffset.rawValue)

        assertEquals(
            listOf(".debug_info", ".debug_abbrev", ".debug_str", ".debug_line_str", ".debug_str_offsets"),
            FullTreeDwarfSections.COMPILATION_UNIT_SECTION_NAMES,
        )
        assertEquals(
            FullTreeDwarfSections.COMPILATION_UNIT_SECTION_NAMES +
                listOf(".debug_line", ".debug_addr", ".debug_ranges", ".debug_rnglists"),
            FullTreeDwarfSections.FUNCTION_OBSERVATION_SECTION_NAMES,
        )
    }

    @Test
    fun `indirect forms retain effective form raw value and nesting depth`() {
        val bytes = byteArrayOf(
            FULL_TREE_DW_FORM_INDIRECT.toByte(),
            FULL_TREE_DW_FORM_ADDR.toByte(),
        ) + unsigned(0x1234UL, 8)
        val value = assertIs<FullTreeDwarfAddressValue>(
            readForm(bytes, FULL_TREE_DW_FORM_INDIRECT),
        )
        assertEquals(FULL_TREE_DW_FORM_ADDR, value.resolvedForm)
        assertEquals(0x1234UL, value.rawValue)
        assertEquals(2, value.indirectDepth)

        val range = assertIs<FullTreeDwarfRangeSectionOffsetValue>(
            readForm(
                byteArrayOf(FULL_TREE_DW_FORM_SEC_OFFSET.toByte()) + unsigned(7UL, 4),
                FULL_TREE_DW_FORM_INDIRECT,
                context = FullTreeDwarfFormContext.RANGE_LIST,
            ),
        )
        assertEquals(FULL_TREE_DW_FORM_SEC_OFFSET, range.resolvedForm)
        assertEquals(7UL, range.rawValue)
        assertEquals(1, range.indirectDepth)
    }

    @Test
    fun `unsupported reference forms retain direct and indirect operands`() {
        val vectors = listOf(
            Triple(FULL_TREE_DW_FORM_REF_SUP4, 4, 0x1234_5678UL),
            Triple(FULL_TREE_DW_FORM_REF_SUP8, 8, 0xfedc_ba98_7654_3210UL),
            Triple(FULL_TREE_DW_FORM_REF_SIG8, 8, 0x8877_6655_4433_2211UL),
            Triple(FULL_TREE_DW_FORM_GNU_REF_ALT, 4, 0x7654_3210UL),
        )
        vectors.forEach { (form, width, raw) ->
            val direct = assertIs<FullTreeDwarfUnsupportedReferenceValue>(
                readForm(unsigned(raw, width), form),
            )
            assertEquals(form, direct.resolvedForm)
            assertEquals(raw, direct.rawValue)
            assertEquals(0, direct.indirectDepth)

            val indirect = assertIs<FullTreeDwarfUnsupportedReferenceValue>(
                readForm(uleb(form.toULong()) + unsigned(raw, width), FULL_TREE_DW_FORM_INDIRECT),
            )
            assertEquals(form, indirect.resolvedForm)
            assertEquals(raw, indirect.rawValue)
            assertEquals(1, indirect.indirectDepth)
        }
    }

    @Test
    fun `addresses preserve unsigned 64 bit values and reject wider overflow`() {
        val representable = unsigned(ULong.MAX_VALUE, 8) + ByteArray(8)
        val value = assertIs<FullTreeDwarfAddressValue>(
            readForm(representable, FULL_TREE_DW_FORM_ADDR, addressSize = 16),
        )
        assertEquals(ULong.MAX_VALUE, value.rawValue)

        val overflowing = representable.copyOf().also { it[8] = 1 }
        assertFailsWith<FullTreeControlException> {
            readForm(overflowing, FULL_TREE_DW_FORM_ADDR, addressSize = 16)
        }

        val bigEndian = section(
            unsigned(0xfedc_ba98_7654_3210UL, 8).reversedArray(),
            byteOrder = ByteOrder.BIG_ENDIAN,
        )
        assertEquals(
            0xfedc_ba98_7654_3210UL,
            FullTreeDwarfSectionCursor(bigEndian, 0L, bigEndian.size, "big-endian address").readAddress(8),
        )
    }

    @Test
    fun `CU and global references resolve only inside their authenticated bounds`() {
        val info = section(ByteArray(128), ".debug_info")
        val header = FullTreeDwarfCompilationUnitHeader(
            offset = 16L,
            endOffset = 80L,
            version = 5,
            unitType = FULL_TREE_DW_UT_COMPILE,
            addressSize = 8,
            offsetSize = 4,
            abbreviationOffset = 0L,
            firstDieOffset = 24L,
            originatingSection = info,
        )
        assertEquals(
            24L,
            header.resolveReference(
                info,
                FullTreeDwarfReferenceValue(FULL_TREE_DW_FORM_REF1, 8UL, 0),
            ),
        )
        assertEquals(
            100L,
            header.resolveReference(
                info,
                FullTreeDwarfReferenceValue(FULL_TREE_DW_FORM_REF_ADDR, 100UL, 0),
            ),
        )

        assertFailsWith<FullTreeControlException> {
            header.resolveReference(
                info,
                FullTreeDwarfReferenceValue(FULL_TREE_DW_FORM_REF4, 64UL, 0),
            )
        }
        assertFailsWith<FullTreeControlException> {
            header.resolveReference(
                info,
                FullTreeDwarfReferenceValue(FULL_TREE_DW_FORM_REF_ADDR, 128UL, 0),
            )
        }
        assertFailsWith<FullTreeControlException> {
            header.resolveReference(
                info,
                FullTreeDwarfReferenceValue(FULL_TREE_DW_FORM_REF_ADDR, ULong.MAX_VALUE, 0),
            )
        }
        assertFailsWith<FullTreeControlException> {
            header.resolveReference(
                section(ByteArray(128), "substituted .debug_info"),
                FullTreeDwarfReferenceValue(FULL_TREE_DW_FORM_REF_ADDR, 100UL, 0),
            )
        }
    }

    @Test
    fun `address indexes stay inside one validated contribution`() {
        val first = addressContribution(listOf(0x1234UL, ULong.MAX_VALUE))
        val second = addressContribution(listOf(0x9999UL))
        val addresses = section(first + second, ".debug_addr")
        val resolver = FullTreeDwarfAddressResolver(
            section = addresses,
            addressBase = 8L,
            version = 5,
            offsetSize = 4,
            addressSize = 8,
        )
        assertEquals(
            0x1234UL,
            resolver.resolve(FullTreeDwarfAddressIndexValue(FULL_TREE_DW_FORM_ADDRX, 0UL, 0)),
        )
        assertEquals(
            ULong.MAX_VALUE,
            resolver.resolve(FullTreeDwarfAddressIndexValue(FULL_TREE_DW_FORM_ADDRX4, 1UL, 0)),
        )
        assertFailsWith<FullTreeControlException> {
            resolver.resolve(FullTreeDwarfAddressIndexValue(FULL_TREE_DW_FORM_ADDRX, 2UL, 0))
        }
        assertFailsWith<FullTreeControlException> {
            resolver.resolve(FullTreeDwarfAddressIndexValue(FULL_TREE_DW_FORM_ADDR, 0UL, 0))
        }
        assertFailsWith<FullTreeControlException> {
            FullTreeDwarfAddressResolver(addresses, 8L, 4, 4, 8)
        }
        assertFailsWith<FullTreeControlException> {
            FullTreeDwarfAddressResolver(
                section(addressContribution(listOf(1UL), segmentSelectorSize = 1), ".debug_addr segmented"),
                8L,
                5,
                4,
                8,
            )
        }
    }

    @Test
    fun `range offsets and indexes produce contribution-bounded reader inputs`() {
        val first = rnglistsContribution(
            offsets = listOf(8UL, 10UL),
            lists = byteArrayOf(0x00, 0x04, 0x00),
        )
        val second = rnglistsContribution(offsets = emptyList(), lists = byteArrayOf(0x00))
        val rnglists = section(first + second, ".debug_rnglists")
        val resolver = rangeResolver(
            debugRnglists = rnglists,
            rnglistsBase = 12L,
            budget = 16L,
        )

        val indexed = resolver.resolve(
            FullTreeDwarfRangeListIndexValue(FULL_TREE_DW_FORM_RNGLISTX, 0UL, 0),
        )
        assertEquals(FullTreeDwarfRangeListEncoding.DEBUG_RNGLISTS, indexed.encoding)
        assertEquals(20L, indexed.offset)
        assertEquals(first.size.toLong(), indexed.endOffset)
        assertEquals(20L, indexed.cursor().position)
        assertEquals(first.size.toLong(), indexed.cursor().limit)

        val secondIndex = resolver.resolve(
            FullTreeDwarfRangeListIndexValue(FULL_TREE_DW_FORM_RNGLISTX, 1UL, 0),
        )
        assertEquals(22L, secondIndex.offset)
        assertFailsWith<FullTreeControlException> {
            resolver.resolve(FullTreeDwarfRangeListIndexValue(FULL_TREE_DW_FORM_RNGLISTX, 2UL, 0))
        }

        val direct = resolver.resolve(
            FullTreeDwarfRangeSectionOffsetValue(FULL_TREE_DW_FORM_SEC_OFFSET, 20UL, 1),
        )
        assertEquals(20L, direct.offset)
        assertEquals(first.size.toLong(), direct.endOffset)
        assertFailsWith<FullTreeControlException> {
            resolver.resolve(
                FullTreeDwarfRangeSectionOffsetValue(
                    FULL_TREE_DW_FORM_SEC_OFFSET,
                    rnglists.size.toULong(),
                    0,
                ),
            )
        }

        val invalidOffsetTable = section(
            rnglistsContribution(offsets = listOf(1UL), lists = byteArrayOf(0x00)),
            ".debug_rnglists invalid offset",
        )
        assertFailsWith<FullTreeControlException> {
            rangeResolver(invalidOffsetTable, 12L).resolve(
                FullTreeDwarfRangeListIndexValue(FULL_TREE_DW_FORM_RNGLISTX, 0UL, 0),
            )
        }

        val secondListOffset = first.size.toLong() + 12L
        assertFailsWith<FullTreeControlException> {
            rangeResolver(rnglists, 12L, budget = 1L).resolve(
                FullTreeDwarfRangeSectionOffsetValue(
                    FULL_TREE_DW_FORM_SEC_OFFSET,
                    secondListOffset.toULong(),
                    0,
                ),
            )
        }
    }

    @Test
    fun `legacy range inputs are section bounded and version specific`() {
        val ranges = section(ByteArray(32), ".debug_ranges")
        val resolver = FullTreeDwarfRangeListResolver(
            version = 4,
            addressSize = 8,
            offsetSize = 4,
            debugRanges = ranges,
            debugRnglists = null,
            rnglistsBase = null,
            parseBudget = FullTreeDwarfParseBudget(4L),
        )
        val input = resolver.resolve(
            FullTreeDwarfRangeSectionOffsetValue(FULL_TREE_DW_FORM_SEC_OFFSET, 8UL, 0),
        )
        assertEquals(FullTreeDwarfRangeListEncoding.DEBUG_RANGES, input.encoding)
        assertEquals(8L, input.offset)
        assertEquals(32L, input.endOffset)
        assertEquals(4, input.dwarfVersion)
        assertFailsWith<FullTreeControlException> {
            resolver.resolve(FullTreeDwarfRangeListIndexValue(FULL_TREE_DW_FORM_RNGLISTX, 0UL, 0))
        }
        assertFailsWith<FullTreeControlException> {
            resolver.resolve(
                FullTreeDwarfRangeSectionOffsetValue(FULL_TREE_DW_FORM_SEC_OFFSET, ULong.MAX_VALUE, 0),
            )
        }
    }

    private fun readForm(
        bytes: ByteArray,
        form: Long,
        version: Int = 5,
        addressSize: Int = 8,
        offsetSize: Int = 4,
        context: FullTreeDwarfFormContext = FullTreeDwarfFormContext.GENERAL,
        implicitConstant: Long? = null,
        byteOrder: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    ): FullTreeDwarfFormValue {
        val section = section(bytes, byteOrder = byteOrder)
        return FullTreeDwarfForms.read(
            cursor = FullTreeDwarfSectionCursor(section, 0L, section.size, "form test"),
            form = form,
            implicitConstant = implicitConstant,
            version = version,
            addressSize = addressSize,
            offsetSize = offsetSize,
            limits = FullTreeControlLimits(),
            context = context,
        )
    }

    private fun rangeResolver(
        debugRnglists: FullTreeDwarfSection,
        rnglistsBase: Long?,
        budget: Long = 16L,
    ) = FullTreeDwarfRangeListResolver(
        version = 5,
        addressSize = 8,
        offsetSize = 4,
        debugRanges = null,
        debugRnglists = debugRnglists,
        rnglistsBase = rnglistsBase,
        parseBudget = FullTreeDwarfParseBudget(budget),
    )

    private fun addressContribution(
        values: List<ULong>,
        addressSize: Int = 8,
        segmentSelectorSize: Int = 0,
    ): ByteArray {
        val body = byteArrayOf(0x05, 0x00, addressSize.toByte(), segmentSelectorSize.toByte()) +
            values.fold(ByteArray(0)) { bytes, value -> bytes + unsigned(value, addressSize) }
        return unsigned(body.size.toULong(), 4) + body
    }

    private fun rnglistsContribution(
        offsets: List<ULong>,
        lists: ByteArray,
        addressSize: Int = 8,
        segmentSelectorSize: Int = 0,
    ): ByteArray {
        val header = byteArrayOf(0x05, 0x00, addressSize.toByte(), segmentSelectorSize.toByte()) +
            unsigned(offsets.size.toULong(), 4)
        val table = offsets.fold(ByteArray(0)) { bytes, offset -> bytes + unsigned(offset, 4) }
        val body = header + table + lists
        return unsigned(body.size.toULong(), 4) + body
    }

    private fun unsigned(value: ULong, width: Int): ByteArray = ByteArray(width) { index ->
        ((value shr (index * 8)) and 0xffUL).toByte()
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
        label: String = "form test section",
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
