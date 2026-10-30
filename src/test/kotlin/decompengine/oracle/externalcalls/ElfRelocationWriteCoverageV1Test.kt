package decompengine.oracle.externalcalls

import decompengine.oracle.fulltree.FullTreeControlException
import decompengine.oracle.fulltree.FullTreeElfSymbolSectionKind
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonPrimitive

class ElfRelocationWriteCoverageV1Test {
    @Test
    fun `a relative write at slot plus four blocks association while adjacent writes and NONE do not`(): Unit = withWriteFixture { source, candidate ->
        fun assess(delta: Long, type: Long = 8) = index(source, listOf(candidate, other(candidate, type,
            if (delta < 0) candidate.offset - (-delta).toULong() else candidate.offset + delta.toULong())))
            .assess(candidate.offset, candidate)
        for (delta in listOf(-4L, 0L, 4L)) {
            val result = assess(delta)
            assertTrue(result.overlappingWrite)
            assertFalse(result.safeForStaticSlotAssociation)
            assertEquals("authored-other", result.overlapLocator)
        }
        for (delta in listOf(-8L, 8L)) assertTrue(assess(delta).safeForStaticSlotAssociation)
        assertTrue(assess(0, 0).safeForStaticSlotAssociation)
        val selfOnly = index(source, listOf(candidate)).assess(candidate.offset, candidate)
        assertTrue(selfOnly.safeForStaticSlotAssociation)
        assertEquals(JsonPrimitive(false), selfOnly.toJson()["negativeCompleteness"])
        val forged = candidate.copy(locator = "forged-candidate")
        assertFalse(index(source, listOf(candidate)).assess(candidate.offset, forged).candidateActive)
    }

    @Test
    fun `runtime widths include two word TLS descriptors and retain IFUNC write bounds without resolving implementations`(): Unit = withWriteFixture { source, candidate ->
        val widths = listOf(1L, 6L, 7L, 8L, 16L, 17L, 18L, 33L, 37L, 38L).map { it to 8UL } +
            listOf(2L, 10L, 32L).map { it to 4UL } + (36L to 16UL)
        widths.forEach { (type, width) ->
            val overlapping = other(candidate, type, candidate.offset - width + 1UL)
            val result = index(source, listOf(candidate, overlapping)).assess(candidate.offset, candidate)
            assertTrue(result.overlappingWrite, "type $type must retain all $width possible write bytes")
            assertFalse(result.unknownWriteWidth)
            val adjacent = overlapping.copy(offset = candidate.offset - width)
            assertTrue(index(source, listOf(candidate, adjacent)).assess(candidate.offset, candidate).safeForStaticSlotAssociation)
        }
    }

    @Test
    fun `COPY uses defined destination size and preserves missing undefined or mismatched destination uncertainty`(): Unit = withWriteFixture { source, original ->
        val destination = source.dynamicSymbols.single { it.symbolIndex == 5L }
        val candidate = original.copy(offset = destination.raw.value + 4UL)
        val copy = other(original, 5, destination.raw.value).copy(symbolIndex = destination.symbolIndex)
        assertTrue(index(source, listOf(candidate, copy)).assess(candidate.offset, candidate).overlappingWrite)
        val missing = copy.copy(symbolIndex = 999)
        assertTrue(index(source, listOf(candidate, missing)).assess(candidate.offset, candidate).unknownWriteWidth)
        val mismatched = copy.copy(offset = copy.offset + 1UL)
        assertTrue(index(source, listOf(candidate, mismatched)).assess(candidate.offset, candidate).unknownWriteWidth)
        val undefined = destination.copy(raw = destination.raw.copy(sectionKind = FullTreeElfSymbolSectionKind.UNDEFINED))
        val replaced = source.dynamicSymbols.map { if (it.symbolIndex == destination.symbolIndex) undefined else it }
        assertTrue(index(source, listOf(candidate, copy), replaced).assess(candidate.offset, candidate).unknownWriteWidth)
        val empty = destination.copy(raw = destination.raw.copy(size = 0UL))
        val emptySymbols = source.dynamicSymbols.map { if (it.symbolIndex == destination.symbolIndex) empty else it }
        assertTrue(index(source, listOf(candidate, copy), emptySymbols).assess(candidate.offset, candidate).safeForStaticSlotAssociation)
    }

    @Test
    fun `unknown and overflowing writes remain global uncertainty while inactive records do not become runtime writes`(): Unit = withWriteFixture { source, candidate ->
        val unknown = other(candidate, 0x1234, 0x900000UL)
        val uncertain = index(source, listOf(candidate, unknown)).assess(candidate.offset, candidate)
        assertTrue(uncertain.unknownWriteWidth)
        assertEquals(unknown.locator, uncertain.unknownWidthLocator)
        assertFalse(uncertain.safeForStaticSlotAssociation)
        val overflow = other(candidate, 8, ULong.MAX_VALUE - 3UL)
        val overflowing = index(source, listOf(candidate, overflow)).assess(candidate.offset, candidate)
        assertTrue(overflowing.writeAddressOverflow)
        assertFalse(overflowing.safeForStaticSlotAssociation)
        assertEquals(overflow.locator, overflowing.overflowLocator)
        for (inactive in listOf(unknown.copy(dynamicTables = emptyList()), unknown.copy(symbolTableSectionIndex = 999)))
            assertTrue(index(source, listOf(candidate, inactive)).assess(candidate.offset, candidate).safeForStaticSlotAssociation)
        val overflowingCandidate = candidate.copy(offset = ULong.MAX_VALUE - 3UL)
        assertTrue(index(source, listOf(overflowingCandidate)).assess(overflowingCandidate.offset, overflowingCandidate).slotAddressOverflow)
        val lastCompleteSlot = candidate.copy(offset = ULong.MAX_VALUE - 7UL)
        assertTrue(index(source, listOf(lastCompleteSlot)).assess(lastCompleteSlot.offset, lastCompleteSlot).safeForStaticSlotAssociation)
    }

    @Test
    fun `population and lifetime work bounds cancellation and duplicate identities fail closed`(): Unit = withWriteFixture { source, candidate ->
        val entries = listOf(candidate, other(candidate, 8, candidate.offset + 16UL))
        assertFailsWith<FullTreeControlException> { index(source, entries, limits = ElfRelocationWriteLimitsV1(maximumRelocations = 1)) }
        assertFailsWith<FullTreeControlException> { index(source, entries, limits = ElfRelocationWriteLimitsV1(maximumWorkUnits = 1)) }
        assertFailsWith<FullTreeControlException> { index(source, listOf(candidate, candidate)) }
        val limited = index(source, listOf(candidate), limits = ElfRelocationWriteLimitsV1(maximumWorkUnits = 64))
        assertFailsWith<FullTreeControlException> { repeat(100) { limited.assess(candidate.offset, candidate) } }
        val cancelled = IllegalStateException("authored index cancellation")
        val actual = assertFailsWith<IllegalStateException> { index(source, entries, charge = { throw cancelled }) }
        assertSame(cancelled, actual)
    }

    @Test
    fun `many disjoint writes use indexed queries instead of a relocation scan per candidate`(): Unit = withWriteFixture { source, original ->
        val records = (0 until 8192).map { index -> original.copy(sectionIndex = 4, relocationIndex = index.toLong(),
            locator = "authored[$index]", offset = 0x100000UL + index.toULong() * 16UL) }
        var charged = 0L
        val coverage = index(source, records, charge = { charged++ })
        val afterBuild = charged
        records.filterIndexed { i, _ -> i % 32 == 0 }.forEach { candidate ->
            assertTrue(coverage.assess(candidate.offset, candidate).safeForStaticSlotAssociation)
        }
        assertTrue(charged - afterBuild < 256L * 128L, "query work must stay well below 8192 comparisons per slot")
    }
}

private fun other(candidate: ElfDynamicRelocationV1, type: Long, address: ULong): ElfDynamicRelocationV1 =
    candidate.copy(sectionIndex = 4, relocationIndex = 99, locator = "authored-other", type = type, offset = address,
        symbolIndex = 0, dynamicTables = listOf("rela"))

/** Helper unit inputs derive their layout from an authenticated authored ELF; write mutations are explicit. */
private fun index(
    source: ElfDynamicBindingInventoryV1, relocations: List<ElfDynamicRelocationV1>,
    symbols: List<ElfDynamicSymbolV1> = source.dynamicSymbols,
    limits: ElfRelocationWriteLimitsV1 = ElfRelocationWriteLimitsV1(), charge: (String) -> Unit = {},
): ElfRelocationWriteCoverageV1 = ElfRelocationWriteCoverageV1.build(ElfDynamicBindingInventoryV1(
    source.inputSha256, source.imageBase, source.activeSymbolTableSectionIndex, source.structure,
    source.dynamicEntries, symbols, relocations, source.versionRequirements, source.versionDefinitions,
    source.neededLibraries, source.unsupportedReasons), limits, charge)

private fun withWriteFixture(action: (ElfDynamicBindingInventoryV1, ElfDynamicRelocationV1) -> Unit) {
    withDynamicFixture { directory ->
        val path = directory.resolve("writes.elf"); val bytes = DynamicBindingElfFixtureV1().bytes; Files.write(path, bytes)
        StableControlFile.open(path, bytes.size.toLong(), "write fixture").use { file ->
            val inventory = BoundedElfDynamicBindingsV1.scan(file, file.authenticatedSha256)
            action(inventory, inventory.relocations.first { it.sectionIndex == 5 })
        }
    }
}
