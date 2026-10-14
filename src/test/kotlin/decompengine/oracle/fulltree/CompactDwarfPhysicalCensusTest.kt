package decompengine.oracle.fulltree

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class CompactDwarfPhysicalCensusTest {
    @Test
    fun `block boundaries preserve every numeric column ordered references and sealed views`() {
        val budget = DwarfInterfaceFactBudget(1024 * 1024)
        val census = CompactDwarfPhysicalCensus(budget, 2048, 4096)
        for (index in 0 until 1030) {
            census.appendDie(0, index.toLong() + 11, index.toLong() + 12, 0x4080, index % 4,
                if (index == 0) null else 11, index % 2 == 0)
            census.appendReference(7, 0x49, FULL_TREE_DW_FORM_INDIRECT, FULL_TREE_DW_FORM_GNU_REF_ALT,
                1, ULong.MAX_VALUE - index.toULong(), null, null, "unsupported-reference")
            census.appendReference(9, 0x31, FULL_TREE_DW_FORM_REF4, FULL_TREE_DW_FORM_REF4,
                0, 11UL, 0, 11, null)
        }
        census.reconcile(BoundedDwarfInterfaceFactLimits(), FullTreeDwarfParseBudget(1_000_000) {})
        val rows = census.sealedDies()
        assertEquals(1030, rows.size)
        for (index in listOf(0, 1023, 1024, 1029)) {
            val die = rows[index]
            assertEquals(index.toLong() + 11, die.offset)
            assertEquals(index.toLong() + 12, die.endOffset)
            assertEquals(index % 4, die.depth)
            assertEquals(index % 2 == 0, die.hasChildren)
            assertEquals(listOf(7, 9), die.references.map { it.attributeOrdinal })
            assertEquals(ULong.MAX_VALUE - index.toULong(), die.references[0].rawOperand)
            assertEquals("unsupported-reference", die.references[0].state)
            assertEquals("retained-target", die.references[1].state)
            assertEquals(index == 0, "reference-cycle" in die.references[1].reasons)
            assertEquals(die.toJson(), DwarfPhysicalDieRowEncoding.decode(DwarfPhysicalDieRowEncoding.encode(die)).toJson())
        }
        assertFailsWith<IllegalStateException> { census.appendDie(0, 2000, 2001, 1, 0, null, false) }
        assertFailsWith<IllegalStateException> { rows[0].references[0].markCycle() }
        assertFailsWith<UnsupportedOperationException> { (rows as MutableList<DwarfPhysicalDieCensus>).clear() }
        assertEquals(census.modeledBytes, budget.chargedBytes)
    }

    @Test
    fun `finding bitmaps preserve physical order and every finding while skipping ordinary rows`() {
        val census = CompactDwarfPhysicalCensus(DwarfInterfaceFactBudget(1024 * 1024), 2048, 4096)
        val special = setOf(63, 64, 127, 128, 1023, 1024)
        repeat(1030) { index ->
            census.appendDie(0, index.toLong() + 11, index.toLong() + 12,
                if (index == 128 || index == 1029) 0x4080 else 0x11, 0, null, false)
            census.appendReference(0, 0x49, 0x13, 0x13, 0, 11UL, 0, 11, null)
            if (index in special) census.appendReference(7, 0x31, 0x1f20, 0x1f20, 0, ULong.MAX_VALUE, null, null, "unsupported-reference")
        }
        census.reconcile(BoundedDwarfInterfaceFactLimits(), FullTreeDwarfParseBudget(1_000_000) {})
        val rows = census.sealedDies()
        val expected = rows.flatMap { die -> buildList<Pair<String, Int?>> {
            if (die.category == "unknown") add(die.locator to null)
            for (ref in die.references) if (ref.state != "retained-target" || "reference-cycle" in ref.reasons) add(die.locator to ref.attributeOrdinal)
        } }
        var probes = 0
        val actual = rows.findingRows { probes++ }.map { (die, ref) -> die.locator to ref?.attributeOrdinal }.toList()
        assertEquals(expected, actual)
        assertEquals(9, actual.size)
        assertTrue(probes < 100, "ordinary rows were unnecessarily visited: $probes")
    }

    @Test
    fun `capacity charge refuses before allocating or retaining the next block`() {
        val bound = 1024L + CompactDwarfPhysicalCensus.DIE_BLOCK_BYTES
        val budget = DwarfInterfaceFactBudget(bound)
        val census = CompactDwarfPhysicalCensus(budget, 2048, 1)
        repeat(CompactDwarfPhysicalCensus.BLOCK_ROWS) { census.appendDie(0, it.toLong() + 11, it.toLong() + 12, 0x11, 0, null, false) }
        val failure = assertFailsWith<FullTreeControlException> { census.appendDie(0, 1035, 1036, 0x11, 0, null, false) }
        assertTrue(failure.message.orEmpty().contains("retained fact bound"))
        assertEquals(CompactDwarfPhysicalCensus.BLOCK_ROWS, census.dieCount)
        assertEquals(bound, budget.chargedBytes)
        assertFailsWith<FullTreeControlException> { census.appendReference(0, 1, 0x1c, 0x1c, 0, 1UL, null, null, "unsupported-reference") }
        assertEquals(0, census.referenceCount)
    }

    @Test
    fun `retained GCC population cardinalities fit compact storage without changing one GiB ceiling`() {
        // Cardinality pressure control, not a substituted GCC artifact qualification.
        val dies = 710_694; val refs = 800_168
        val budget = DwarfInterfaceFactBudget(128L * 1024 * 1024)
        val census = CompactDwarfPhysicalCensus(budget, dies, refs.toLong())
        repeat(dies) { index ->
            val offset = index.toLong() + 11
            census.appendDie(0, offset, offset + 1, 0x4080, 1, if (index == 0) null else 11, false)
            val count = if (index < refs - dies) 2 else 1
            repeat(count) { ordinal -> census.appendReference(ordinal, 0x49, 0x13, 0x13, 0,
                ULong.MAX_VALUE, null, null, "out-of-range-reference") }
        }
        census.reconcile(BoundedDwarfInterfaceFactLimits(), FullTreeDwarfParseBudget(10_000_000) {})
        val rows = census.sealedDies()
        assertEquals(dies, rows.size)
        assertEquals(refs, census.referenceCount)
        assertEquals(ULong.MAX_VALUE, rows.last().references.single().rawOperand)
        assertTrue(census.modeledBytes < 100L * 1024 * 1024, census.modeledBytes.toString())
        assertEquals(census.modeledBytes, budget.chargedBytes)
    }

    @Test
    fun `numeric row grammar rejects alternative spellings extra fields truncation and width overflow`() {
        val row = "0,b,c,11,0,-,1|0,49,13,13,0,c,0,c,r,0"
        val expected = DwarfPhysicalDieCensus(0, 11, 12, 0x11, 0, null, true,
            listOf(DwarfPhysicalReferenceCensus(0, 0x49, 0x13, 0x13, 0, 12UL, ".debug_info:cu=0x0:die=0xc")
                .also { it.bindTargets(setOf(".debug_info:cu=0x0:die=0xc")); it.seal() }))
        assertEquals(expected.toJson(), DwarfPhysicalDieRowEncoding.decode(JsonObject(mapOf("row" to JsonPrimitive(row)))).toJson())
        val empty = DwarfPhysicalDieCensus(0, 11, 12, 0x11, 0, null, true)
        assertEquals(empty.toJson(), DwarfPhysicalDieRowEncoding.decode(DwarfPhysicalDieRowEncoding.encode(empty)).toJson())
        val malformed = listOf(row.replace("0,b", "00,b"), row.replace(",b,", ",B,"), row.replace(",0,-,", ",00,-,"),
            row.replace(",0,-,", ",-1,-,"), row + ";", row + ",0", row.dropLast(1), row.replace(",r,", ",x,"),
            row.replace(",r,0", ",u,1"), row.replace(",0,c,r", ",-,c,r"), row.replace(",0,c,r", ",0,-,r"),
            row.replace("0,b,", "8000000000000000,b,"), row.replace(",0,c,0,c,", ",0,10000000000000000,0,c,"),
            row.replace(",0,-,", ",2147483648,-,"), row.replace("|0,", "|00,"), row.replace("|0,", "| 0,"),
            row + ";0,49,13,13,0,c,0,c,r,0")
        for (bad in malformed) assertFailsWith<IllegalArgumentException>(bad) {
            DwarfPhysicalDieRowEncoding.decode(JsonObject(mapOf("row" to JsonPrimitive(bad))))
        }
        assertFailsWith<IllegalArgumentException> { DwarfPhysicalDieRowEncoding.decode(JsonObject(mapOf("row" to JsonPrimitive(row), "extra" to JsonPrimitive(0)))) }
        assertFailsWith<IllegalArgumentException> { DwarfPhysicalDieRowEncoding.decode(JsonObject(mapOf("row" to JsonPrimitive(row))), row.length - 1) }
    }

    @Test
    fun `row decoder charges reference work before retaining hostile population`() {
        var charged = 0
        val row = "0,b,c,11,0,-,1|0,49,13,13,0,c,0,c,r,0;1,49,13,13,0,c,0,c,r,0"
        assertFailsWith<FullTreeControlException> {
            DwarfPhysicalDieRowEncoding.decode(JsonObject(mapOf("row" to JsonPrimitive(row))), referenceWork = {
                if (++charged > 1) throw FullTreeControlException("bounded reference work")
            })
        }
        assertEquals(2, charged)
    }
}
