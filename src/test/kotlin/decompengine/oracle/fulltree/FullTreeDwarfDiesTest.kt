package decompengine.oracle.fulltree

import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame

class FullTreeDwarfDiesTest {
    @Test
    fun `indexes one complete tree while counting null and trailing physical records`() {
        val abbreviations = section(richAbbreviations(), ".debug_abbrev")
        val unit = compilationUnit(
            byteArrayOf(1) + utf8z("root") + littleUnsigned(0x1234L, 4) +
                byteArrayOf(2) + utf8z("left") + utf8z("alias") + byteArrayOf(11) +
                byteArrayOf(3) +
                byteArrayOf(2) + utf8z("nested") + utf8z("nested-alias") + byteArrayOf(11) +
                byteArrayOf(0, 0, 0),
        )
        val observed = ArrayList<Pair<Long, Long>>()
        val requestedContexts = ArrayList<Long>()
        val index = FullTreeDwarfDies.readCompilationUnit(
            info = unit.info,
            abbreviations = abbreviations,
            header = unit.header,
            controlLimits = FullTreeControlLimits(),
            dieLimits = generousLimits(),
            sharedParseBudget = FullTreeDwarfParseBudget(256L),
            contextForAttribute = { attribute ->
                requestedContexts += attribute.name
                if (attribute.name == DW_AT_RANGES) {
                    FullTreeDwarfFormContext.RANGE_LIST
                } else {
                    FullTreeDwarfFormContext.GENERAL
                }
            },
            observePhysicalRecord = { offset, code -> observed += offset to code },
        )

        assertEquals(7L, index.physicalRecordCount)
        assertEquals(3L, index.nullRecordCount)
        assertEquals(listOf(1L, 2L, 3L, 2L, 0L, 0L, 0L), observed.map { it.second })
        assertEquals(unit.header.endOffset, observed.last().first + 1L)
        assertEquals(4, index.recordsInPhysicalOrder.size)
        assertEquals(listOf(1L, 2L, 3L, 2L), index.recordsInPhysicalOrder.map { it.abbreviationCode })
        assertEquals(
            listOf(
                DW_AT_NAME,
                DW_AT_RANGES,
                DW_AT_NAME,
                DW_AT_NAME,
                DW_AT_SPECIFICATION,
                DW_AT_NAME,
                DW_AT_NAME,
                DW_AT_SPECIFICATION,
            ),
            requestedContexts,
        )

        val root = index.root
        val firstFunction = index.recordsInPhysicalOrder[1]
        val block = index.recordsInPhysicalOrder[2]
        val nestedFunction = index.recordsInPhysicalOrder[3]
        assertEquals(0, root.depth)
        assertNull(root.parentOffset)
        assertEquals(1, firstFunction.depth)
        assertEquals(root.offset, firstFunction.parentOffset)
        assertEquals(1, block.depth)
        assertEquals(root.offset, block.parentOffset)
        assertEquals(2, nestedFunction.depth)
        assertEquals(block.offset, nestedFunction.parentOffset)
        assertEquals(2, firstFunction.attributesNamed(DW_AT_NAME).size)
        assertFailsWith<FullTreeControlException> {
            firstFunction.optionalUniqueAttribute(DW_AT_NAME, "DW_AT_name")
        }

        val ranges = assertIs<FullTreeDwarfRangeSectionOffsetValue>(
            root.optionalUniqueAttribute(DW_AT_RANGES, "DW_AT_ranges")?.value,
        )
        assertEquals(0x1234UL, ranges.rawValue)
        val reference = assertIs<FullTreeDwarfReferenceValue>(
            firstFunction.optionalUniqueAttribute(DW_AT_SPECIFICATION, "DW_AT_specification")?.value,
        )
        val targetOffset = unit.header.resolveReference(unit.info, reference)
        assertSame(root, index.required(targetOffset, "DW_AT_specification"))
        assertNull(index.find(root.offset + 2L))
        assertFailsWith<FullTreeControlException> { index.required(root.offset + 2L) }
        val firstNullOffset = observed.first { it.second == 0L }.first
        assertFailsWith<FullTreeControlException> { index.required(firstNullOffset) }

        assertFailsWith<UnsupportedOperationException> {
            (index.recordsInPhysicalOrder as MutableList<*>).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            (firstFunction.attributes as MutableList<*>).clear()
        }
    }

    @Test
    fun `rejects absent and duplicate abbreviation codes before trusting the DIE index`() {
        val missing = compilationUnit(byteArrayOf(2))
        assertFailsWith<FullTreeControlException> {
            read(missing, leafAbbreviations())
        }

        val duplicateAbbreviations = byteArrayOf(
            1, DW_TAG_COMPILE_UNIT.toByte(), 0, 0, 0,
            1, DW_TAG_SUBPROGRAM.toByte(), 0, 0, 0,
            0,
        )
        val validUnit = compilationUnit(byteArrayOf(1))
        assertFailsWith<FullTreeControlException> {
            read(validUnit, duplicateAbbreviations)
        }
    }

    @Test
    fun `rejects missing roots multiple roots and malformed tree nesting`() {
        assertFailsWith<FullTreeControlException> {
            read(compilationUnit(byteArrayOf(0)), leafAbbreviations())
        }
        assertFailsWith<FullTreeControlException> {
            read(compilationUnit(byteArrayOf(1, 1)), leafAbbreviations())
        }

        val nestedAbbreviations = byteArrayOf(
            1, DW_TAG_COMPILE_UNIT.toByte(), 1, 0, 0,
            2, DW_TAG_LEXICAL_BLOCK.toByte(), 1, 0, 0,
            0,
        )
        assertFailsWith<FullTreeControlException> {
            read(compilationUnit(byteArrayOf(1)), nestedAbbreviations)
        }
        assertFailsWith<FullTreeControlException> {
            read(compilationUnit(byteArrayOf(1, 2, 0)), nestedAbbreviations)
        }
    }

    @Test
    fun `enforces shared step record depth attribute and retained-byte bounds independently`() {
        val leaf = compilationUnit(byteArrayOf(1, 0))
        assertFailsWith<FullTreeControlException> {
            FullTreeDwarfDies.readCompilationUnit(
                leaf.info,
                section(leafAbbreviations(), ".debug_abbrev"),
                leaf.header,
                FullTreeControlLimits(),
                generousLimits(),
                FullTreeDwarfParseBudget(3L),
            )
        }
        assertFailsWith<FullTreeControlException> {
            read(
                leaf,
                leafAbbreviations(),
                generousLimits().copy(maximumPhysicalRecords = 1L),
            )
        }
        val rootAndChild = compilationUnit(byteArrayOf(1, 2, 0))
        val rootAndChildAbbreviations = byteArrayOf(
            1, DW_TAG_COMPILE_UNIT.toByte(), 1, 0, 0,
            2, DW_TAG_SUBPROGRAM.toByte(), 0, 0, 0,
            0,
        )
        assertFailsWith<FullTreeControlException> {
            read(
                rootAndChild,
                rootAndChildAbbreviations,
                generousLimits().copy(maximumNonNullRecords = 1),
            )
        }
        val rootAndNestedParent = compilationUnit(byteArrayOf(1, 2, 0, 0))
        val parents = byteArrayOf(
            1, DW_TAG_COMPILE_UNIT.toByte(), 1, 0, 0,
            2, DW_TAG_LEXICAL_BLOCK.toByte(), 1, 0, 0,
            0,
        )
        assertFailsWith<FullTreeControlException> {
            read(
                rootAndNestedParent,
                parents,
                generousLimits().copy(maximumTreeDepth = 1),
            )
        }

        val repeatedAttributes = byteArrayOf(
            1, DW_TAG_COMPILE_UNIT.toByte(), 1, DW_AT_NAME.toByte(), FULL_TREE_DW_FORM_STRING.toByte(), 0, 0,
            2, DW_TAG_SUBPROGRAM.toByte(), 0, DW_AT_NAME.toByte(), FULL_TREE_DW_FORM_STRING.toByte(), 0, 0,
            0,
        )
        val threeAttributes = compilationUnit(
            byteArrayOf(1) + utf8z("root") +
                byteArrayOf(2) + utf8z("one") +
                byteArrayOf(2) + utf8z("two") +
                byteArrayOf(0),
        )
        assertFailsWith<FullTreeControlException> {
            read(
                threeAttributes,
                repeatedAttributes,
                generousLimits().copy(maximumAttributes = 2L),
            )
        }
        assertFailsWith<FullTreeControlException> {
            read(
                leaf,
                leafAbbreviations(),
                generousLimits().copy(maximumRetainedBytes = 1L),
            )
        }
    }

    @Test
    fun `filtered retention still parses counts and validates the complete DIE tree`() {
        val abbreviations = byteArrayOf(
            1, DW_TAG_COMPILE_UNIT.toByte(), 1, 0, 0,
            2, DW_TAG_LEXICAL_BLOCK.toByte(), 1,
            DW_AT_NAME.toByte(), FULL_TREE_DW_FORM_STRING.toByte(), 0, 0,
            3, DW_TAG_SUBPROGRAM.toByte(), 0,
            DW_AT_NAME.toByte(), FULL_TREE_DW_FORM_STRING.toByte(), 0, 0,
            0,
        )
        val unit = compilationUnit(
            byteArrayOf(1, 2) + utf8z("x".repeat(256)) +
                byteArrayOf(3) + utf8z("kept") +
                byteArrayOf(2) + utf8z("also-dropped") + byteArrayOf(0, 0, 0),
        )
        val limits = generousLimits().copy(maximumRetainedBytes = 1_800L)

        assertFailsWith<FullTreeControlException> {
            read(unit, abbreviations, limits)
        }

        val readFiltered = { selectedLimits: FullTreeDwarfDieLimits ->
            FullTreeDwarfDies.readCompilationUnit(
                info = unit.info,
                abbreviations = section(abbreviations, ".debug_abbrev"),
                header = unit.header,
                controlLimits = FullTreeControlLimits(),
                dieLimits = selectedLimits,
                sharedParseBudget = FullTreeDwarfParseBudget(256L),
                retainRecord = { tag, _ -> tag == DW_TAG_SUBPROGRAM.toLong() },
            )
        }
        assertFailsWith<FullTreeControlException> {
            readFiltered(limits.copy(maximumNonNullRecords = 3))
        }
        assertFailsWith<FullTreeControlException> {
            readFiltered(limits.copy(maximumPhysicalRecords = 6L))
        }
        assertFailsWith<FullTreeControlException> {
            readFiltered(limits.copy(maximumTreeDepth = 1))
        }
        assertFailsWith<FullTreeControlException> {
            readFiltered(limits.copy(maximumAttributes = 2L))
        }
        val unterminated = compilationUnit(
            byteArrayOf(1, 2) + utf8z("dropped") +
                byteArrayOf(3) + utf8z("kept") + byteArrayOf(0),
        )
        assertFailsWith<FullTreeControlException> {
            FullTreeDwarfDies.readCompilationUnit(
                info = unterminated.info,
                abbreviations = section(abbreviations, ".debug_abbrev"),
                header = unterminated.header,
                controlLimits = FullTreeControlLimits(),
                dieLimits = generousLimits(),
                sharedParseBudget = FullTreeDwarfParseBudget(256L),
                retainRecord = { tag, _ -> tag == DW_TAG_SUBPROGRAM.toLong() },
            )
        }
        val index = readFiltered(limits)

        assertEquals(7L, index.physicalRecordCount)
        assertEquals(3L, index.nullRecordCount)
        assertEquals(
            listOf(DW_TAG_COMPILE_UNIT.toLong(), DW_TAG_SUBPROGRAM.toLong()),
            index.recordsInPhysicalOrder.map { it.tag },
        )
        val function = index.recordsInPhysicalOrder.single {
            it.tag == DW_TAG_SUBPROGRAM.toLong()
        }
        assertEquals(
            "kept",
            assertIs<FullTreeDwarfInlineStringValue>(
                function.optionalUniqueAttribute(DW_AT_NAME, "DW_AT_name")?.value,
            ).bytes.toString(Charsets.UTF_8),
        )
        assertNull(index.find(checkNotNull(function.parentOffset)))
    }

    private fun read(
        unit: TestUnit,
        abbreviationBytes: ByteArray,
        dieLimits: FullTreeDwarfDieLimits = generousLimits(),
    ): FullTreeDwarfDieIndex = FullTreeDwarfDies.readCompilationUnit(
        info = unit.info,
        abbreviations = section(abbreviationBytes, ".debug_abbrev"),
        header = unit.header,
        controlLimits = FullTreeControlLimits(),
        dieLimits = dieLimits,
        sharedParseBudget = FullTreeDwarfParseBudget(256L),
    )

    private fun compilationUnit(dieBytes: ByteArray): TestUnit {
        val body = byteArrayOf(
            4, 0, // version 4
            0, 0, 0, 0, // abbreviation offset
            8, // address size
        ) + dieBytes
        val bytes = littleUnsigned(body.size.toLong(), 4) + body
        val info = section(bytes, ".debug_info")
        val header = FullTreeDwarfCompilationUnitHeaders(
            info,
            maximumUnits = 1L,
            parseBudget = FullTreeDwarfParseBudget(16L),
        ).next()
        return TestUnit(info, header)
    }

    private fun richAbbreviations(): ByteArray = byteArrayOf(
        1, DW_TAG_COMPILE_UNIT.toByte(), 1,
        DW_AT_NAME.toByte(), FULL_TREE_DW_FORM_STRING.toByte(),
        DW_AT_RANGES.toByte(), FULL_TREE_DW_FORM_SEC_OFFSET.toByte(),
        0, 0,
        2, DW_TAG_SUBPROGRAM.toByte(), 0,
        DW_AT_NAME.toByte(), FULL_TREE_DW_FORM_STRING.toByte(),
        DW_AT_NAME.toByte(), FULL_TREE_DW_FORM_STRING.toByte(),
        DW_AT_SPECIFICATION.toByte(), FULL_TREE_DW_FORM_REF1.toByte(),
        0, 0,
        3, DW_TAG_LEXICAL_BLOCK.toByte(), 1,
        0, 0,
        0,
    )

    private fun leafAbbreviations(): ByteArray = byteArrayOf(
        1, DW_TAG_COMPILE_UNIT.toByte(), 0, 0, 0,
        0,
    )

    private fun generousLimits() = FullTreeDwarfDieLimits(
        maximumPhysicalRecords = 100L,
        maximumNonNullRecords = 100,
        maximumAttributes = 100L,
        maximumTreeDepth = 16,
        maximumRetainedBytes = 1024L * 1024L,
    )

    private fun section(bytes: ByteArray, label: String) = FullTreeDwarfSection(
        size = bytes.size.toLong(),
        byteOrder = ByteOrder.LITTLE_ENDIAN,
        label = label,
        readWindow = { offset, length ->
            bytes.copyOfRange(offset.toInt(), Math.addExact(offset.toInt(), length))
        },
    )

    private fun littleUnsigned(value: Long, width: Int): ByteArray =
        ByteArray(width) { index -> (value ushr (index * 8)).toByte() }

    private fun utf8z(value: String): ByteArray = value.toByteArray(Charsets.UTF_8) + byteArrayOf(0)

    private data class TestUnit(
        val info: FullTreeDwarfSection,
        val header: FullTreeDwarfCompilationUnitHeader,
    )

    private companion object {
        const val DW_TAG_COMPILE_UNIT = 0x11
        const val DW_TAG_LEXICAL_BLOCK = 0x0b
        const val DW_TAG_SUBPROGRAM = 0x2e
        const val DW_AT_NAME = 0x03L
        const val DW_AT_SPECIFICATION = 0x47L
        const val DW_AT_RANGES = 0x55L
    }
}
