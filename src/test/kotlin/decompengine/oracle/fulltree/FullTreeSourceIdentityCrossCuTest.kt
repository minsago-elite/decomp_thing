package decompengine.oracle.fulltree

import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull

/** Handcrafted parser control: this is bounded raw-DWARF evidence, not compiler-emitted evidence. */
class FullTreeSourceIdentityCrossCuTest {
    @Test
    fun `resolves an authenticated cross CU reference only at a target DIE boundary`() {
        val abbreviations = section(
            byteArrayOf(
                1, DW_TAG_COMPILE_UNIT.toByte(), 1, 0, 0,
                2, DW_TAG_SUBPROGRAM.toByte(), 0,
                DW_AT_ABSTRACT_ORIGIN.toByte(), FULL_TREE_DW_FORM_REF_ADDR.toByte(),
                DW_AT_NAME.toByte(), FULL_TREE_DW_FORM_STRING.toByte(), 0, 0,
                3, DW_TAG_SUBPROGRAM.toByte(), 0,
                DW_AT_NAME.toByte(), FULL_TREE_DW_FORM_STRING.toByte(),
                DW_AT_DECL_LINE.toByte(), FULL_TREE_DW_FORM_DATA2.toByte(), 0, 0,
                0,
            ),
            ".debug_abbrev",
        )

        val firstCuPlaceholder = compilationUnit(
            byteArrayOf(1, 2) + littleUnsigned(0L, 4) + utf8z("cross_cu_instance") + byteArrayOf(0),
        )
        val targetOffset = firstCuPlaceholder.size.toLong() + 4L + 7L + 1L
        val firstCu = compilationUnit(
            byteArrayOf(1, 2) + littleUnsigned(targetOffset, 4) + utf8z("cross_cu_instance") + byteArrayOf(0),
        )
        val secondCu = compilationUnit(
            byteArrayOf(1, 3) + utf8z("cross_cu_definition") + littleUnsigned(29L, 2) + byteArrayOf(0),
        )
        val bytes = firstCu + secondCu
        val info = section(bytes, ".debug_info")
        val parseBudget = FullTreeDwarfParseBudget(512L)
        val headerIterator = FullTreeDwarfCompilationUnitHeaders(info, 2L, parseBudget)
        val headers = buildList {
            while (headerIterator.hasNext()) add(headerIterator.next())
        }
        assertEquals(2, headers.size)
        val limits = FullTreeDwarfDieLimits(
            maximumPhysicalRecords = 32L,
            maximumNonNullRecords = 32,
            maximumAttributes = 32L,
            maximumTreeDepth = 8,
            maximumRetainedBytes = 64L * 1024L,
        )
        val firstIndex = readIndex(info, abbreviations, headers[0], limits, parseBudget)
        val sourceRecord = firstIndex.recordsInPhysicalOrder.single { it.tag == DW_TAG_SUBPROGRAM.toLong() }
        val reference = assertIs<FullTreeDwarfReferenceValue>(
            sourceRecord.optionalUniqueAttribute(DW_AT_ABSTRACT_ORIGIN, "DW_AT_abstract_origin")?.value,
        )
        val resolvedOffset = headers[0].resolveReference(info, reference)
        assertEquals(targetOffset, resolvedOffset)
        val targetHeader = sourceIdentityCompilationUnitAt(resolvedOffset, headers)
        assertEquals(headers[1], targetHeader)
        val secondIndex = readIndex(info, abbreviations, targetHeader, limits, parseBudget)
        val targetRecord = sourceIdentityTargetDie(secondIndex, resolvedOffset, "synthetic cross-CU abstract origin")
        assertEquals("cross_cu_definition", decodedName(targetRecord))
        assertEquals(29L, targetRecord.optionalNonNegativeLong(DW_AT_DECL_LINE, "DW_AT_decl_line"))

        val sourcePhysical = physical("1", headers[0].offset, sourceRecord.offset)
        val targetPhysical = physical("2", headers[1].offset, targetRecord.offset)
        val edge = FullTreeSourceIdentityEdge(
            kind = FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN,
            source = sourcePhysical,
            target = targetPhysical,
            referenceForm = "0x${FULL_TREE_DW_FORM_REF_ADDR.toString(16)}",
            rawReference = "0x${resolvedOffset.toString(16)}",
            state = FullTreeSourceIdentityEdgeState.RESOLVED,
            reasonCode = null,
        )
        assertEquals(FullTreeSourceIdentityEdgeState.RESOLVED, edge.state)
        assertEquals(targetPhysical.locator(), edge.target?.locator())

        // A CU header and an out-of-section address are syntactically readable integers, but not
        // valid target DIEs. Preserve that distinction in the same bounded parser path.
        val headerOffsetReference = reference.copy(rawValue = headers[1].offset.toULong())
        val headerOffset = headers[0].resolveReference(info, headerOffsetReference)
        val headerForInvalidTarget = sourceIdentityCompilationUnitAt(headerOffset, headers)
        assertFailsWith<FullTreeControlException> {
            sourceIdentityTargetDie(secondIndex, headerOffset, "cross-CU target header mutation")
        }
        assertEquals(headers[1], headerForInvalidTarget)
        assertFailsWith<FullTreeControlException> {
            headers[0].resolveReference(info, reference.copy(rawValue = info.size.toULong()))
        }
    }

    private fun readIndex(
        info: FullTreeDwarfSection,
        abbreviations: FullTreeDwarfSection,
        header: FullTreeDwarfCompilationUnitHeader,
        limits: FullTreeDwarfDieLimits,
        parseBudget: FullTreeDwarfParseBudget,
    ): FullTreeDwarfDieIndex = FullTreeDwarfDies.readCompilationUnit(
        info = info,
        abbreviations = abbreviations,
        header = header,
        controlLimits = FullTreeControlLimits(),
        dieLimits = limits,
        sharedParseBudget = parseBudget,
    )

    private fun decodedName(record: FullTreeDwarfDieRecord): String = assertNotNull(
        record.optionalUniqueAttribute(DW_AT_NAME, "DW_AT_name"),
    ).let { attribute ->
        assertIs<FullTreeDwarfInlineStringValue>(attribute.value).bytes.toString(Charsets.UTF_8)
    }

    private fun physical(unit: String, cuOffset: Long, dieOffset: Long) = FullTreeSourcePhysicalDie(
        richArtifactSha256 = "a".repeat(64),
        unitId = "cu-${unit.repeat(32)}",
        section = ".debug_info",
        compilationUnitOffset = "0x${cuOffset.toString(16)}",
        dieOffset = "0x${dieOffset.toString(16)}",
    )

    private fun compilationUnit(dieBytes: ByteArray): ByteArray {
        val body = byteArrayOf(4, 0) + littleUnsigned(0L, 4) + byteArrayOf(8) + dieBytes
        return littleUnsigned(body.size.toLong(), 4) + body
    }

    private fun section(bytes: ByteArray, label: String) = FullTreeDwarfSection(
        size = bytes.size.toLong(),
        byteOrder = ByteOrder.LITTLE_ENDIAN,
        label = label,
        readWindow = { offset, length -> bytes.copyOfRange(offset.toInt(), Math.addExact(offset.toInt(), length)) },
    )

    private fun littleUnsigned(value: Long, width: Int): ByteArray =
        ByteArray(width) { index -> (value ushr (index * 8)).toByte() }

    private fun utf8z(value: String): ByteArray = value.toByteArray(Charsets.UTF_8) + byteArrayOf(0)

    private companion object {
        const val DW_TAG_COMPILE_UNIT = 0x11
        const val DW_TAG_SUBPROGRAM = 0x2e
        const val DW_AT_NAME = 0x03L
        const val DW_AT_ABSTRACT_ORIGIN = 0x31L
        const val DW_AT_DECL_LINE = 0x3bL
    }
}
