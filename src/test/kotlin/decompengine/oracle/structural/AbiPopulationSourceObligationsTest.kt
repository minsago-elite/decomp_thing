package decompengine.oracle.structural

import decompengine.oracle.fulltree.DwarfPhysicalDieCensus
import decompengine.oracle.fulltree.DwarfPhysicalReferenceCensus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AbiPopulationSourceObligationsTest {
    @Test fun `complete source and ordered references replay independently`() {
        val source = fixture()
        val rows = build(source)
        assertEquals(AbiSourceRole.STORAGE, rows[2].role)
        assertEquals(AbiReferenceRole.TYPE_USE, rows[2].references.single().role)
        val totals = AbiPopulationSourceVerifier.verify({ source.asSequence() }, rows.asSequence())
        assertEquals(4, totals.physicalRows)
        assertEquals(1, totals.referenceRows)
        assertEquals(10, totals.rowEdgeVisits)
    }

    @Test fun `omitted duplicate reordered and forged role obligations reject`() {
        val source = fixture()
        val rows = build(source)
        listOf(rows.dropLast(1), rows + rows.last(), rows.reversed(),
            rows.map { if (it.ordinal == 2L) it.copy(role = AbiSourceRole.TYPE) else it },
            rows.map { if (it.ordinal == 2L) it.copy(references = emptyList()) else it },
        ).forEach { altered ->
            assertFailsWith<IllegalArgumentException> {
                AbiPopulationSourceVerifier.verify({ source.asSequence() }, altered.asSequence())
            }
        }
    }

    @Test fun `equal address and origin edges never become identity proof`() {
        val source = fixture()
        val rows = build(source)
        assertTrue(rows.none { it.role.name.contains("ENTITY") })
        val storage = rows.single { it.role == AbiSourceRole.STORAGE }
        assertTrue(storage.references.single().interpretationRequired)
    }

    @Test fun `GNU packs are interpretation obligations and unknown tag rejects`() {
        for (tag in listOf(0x4106L, 0x4107L, 0x4108L)) {
            val source = listOf(die(0, 0x11, 0, null, true), die(1, tag, 1, 0, false))
            assertEquals(AbiSourceRole.TEMPLATE, build(source).last().role)
        }
        assertFailsWith<IllegalArgumentException> { build(listOf(die(0, 0xffff, 0, null, false))) }
    }

    @Test fun `one over row edge and work bounds reject`() {
        assertFailsWith<IllegalArgumentException> {
            AbiPopulationSourceObligations.build(fixture().asSequence(), AbiSourceBudget(maximumRows = 3)) {}
        }
        assertFailsWith<IllegalArgumentException> {
            AbiPopulationSourceVerifier.verify({ fixture().asSequence() }, build(fixture()).asSequence(),
                AbiSourceBudget(maximumRowEdgeVisits = 8))
        }
        assertFailsWith<IllegalArgumentException> { AbiSourceBudget(maximumRows = 1_000_001) }
    }

    @Test fun `forged target and parent cannot be repaired by producer summaries`() {
        val original = fixture()
        val forged = original.take(2) + die(2, 0x34, 1, 0, false,
            edge(0x49, 99, ".debug_info:cu=0x0:die=0x3")) + original.last()
        assertFailsWith<IllegalArgumentException> {
            AbiPopulationSourceVerifier.verify({ forged.asSequence() }, build(forged).asSequence())
        }
        val badParent = original.take(3) + die(3, 0x24, 2, 2, false)
        assertFailsWith<IllegalArgumentException> {
            AbiPopulationSourceVerifier.verify({ badParent.asSequence() }, build(badParent).asSequence())
        }
    }

    @Test fun `unknown and false missing reference states are refused by this policy`() {
        for (state in listOf("invented-state", "missing-target", "out-of-range-reference", "unsupported-reference")) {
            val source = fixture().toMutableList()
            val ref = DwarfPhysicalReferenceCensus(0, 0x49, 0x13, 0x13, 0, 3u,
                ".debug_info:cu=0x0:die=0x3", state).also { it.bindTargets(emptySet()); it.seal() }
            source[2] = die(2, 0x34, 1, 0, false, ref)
            assertFailsWith<IllegalArgumentException> { build(source) }
            assertFailsWith<IllegalArgumentException> {
                AbiPopulationSourceVerifier.verify({ source.asSequence() }, build(fixture()).asSequence())
            }
        }
    }

    @Test fun `ref4 width and cross CU coordinate overlap reject`() {
        val high = 0x1_0000_0000L
        val source = listOf(die(0, 0x11, 0, null, true), die(1, 0x2e, 1, 0, false),
            die(2, 0x34, 1, 0, false, edge(0x49, high, ".debug_info:cu=0x0:die=0x100000000")),
            die(high, 0x24, 1, 0, false))
        assertFailsWith<IllegalArgumentException> { build(source) }
        val rows = build(fixture()).map { row -> when(row.ordinal) {
            2L -> row.copy(references = row.references.map { it.copy(targetLocator = ".debug_info:cu=0x0:die=0x100000000") })
            3L -> row.copy(locator = ".debug_info:cu=0x0:die=0x100000000")
            else -> row
        } }
        assertFailsWith<IllegalArgumentException> { AbiPopulationSourceVerifier.verify({ source.asSequence() }, rows.asSequence()) }
        val attributeOverlap = listOf(DwarfPhysicalDieCensus(0, 0, 10, 0x11, 0, null, true),
            die(1, 0x24, 1, 0, false))
        assertFailsWith<IllegalArgumentException> {
            AbiPopulationSourceVerifier.verify({ attributeOverlap.asSequence() }, build(attributeOverlap).asSequence())
        }
        val overlapping = listOf(die(0, 0x11, 0, null, true), die(10, 0x24, 1, 0, false),
            DwarfPhysicalDieCensus(5, 6, 7, 0x11, 0, null, false))
        assertFailsWith<IllegalArgumentException> {
            AbiPopulationSourceVerifier.verify({ overlapping.asSequence() }, build(overlapping).asSequence())
        }
    }

    @Test fun `forward sibling does not claim semantic tree interpretation complete`() {
        val source = listOf(die(0, 0x11, 0, null, true),
            die(1, 0x2e, 1, 0, true, edge(1, 2, ".debug_info:cu=0x0:die=0x2")),
            die(2, 0x5, 2, 1, false))
        val rows = build(source)
        assertTrue(rows[1].references.single().interpretationRequired)
        val forged = rows.map { row -> row.copy(references = row.references.map { it.copy(interpretationRequired = false) }) }
        assertFailsWith<IllegalArgumentException> {
            AbiPopulationSourceVerifier.verify({ source.asSequence() }, forged.asSequence())
        }
    }

    @Test fun `verifier rejects discarded depth ancestry without producer or locator prevalidation`() {
        for (parent in listOf(-1L, -2L, 99L, null)) {
            val source = listOf(
                ancestryDie(0, 0, 0x11, 0, null, true),
                ancestryDie(0, 1, 0x2e, 1, 0, true),
                ancestryDie(0, 2, 0xb, 2, 1, true),
                ancestryDie(0, 3, 0x24, 3, 2, false),
                ancestryDie(0, 4, 0x24, 1, 0, false),
                ancestryDie(0, 5, 0x24, 3, parent, false),
            )
            val rows = ancestryRows(source)
            var consumed = false
            val proposed = sequence { consumed = true; yieldAll(rows) }
            assertFailsWith<IllegalArgumentException> {
                AbiPopulationSourceVerifier.verify({ source.asSequence() }, proposed, ancestryBudget(source))
            }
            assertTrue(!consumed, "malformed ancestry must fail in the first source pass")
        }
    }

    @Test fun `verifier rejects stale ancestry across compilation unit reset`() {
        for (parent in listOf(-1L, -2L, 2L, null)) {
            val source = listOf(
                ancestryDie(0, 0, 0x11, 0, null, true),
                ancestryDie(0, 1, 0x2e, 1, 0, true),
                ancestryDie(0, 2, 0xb, 2, 1, true),
                ancestryDie(0, 3, 0x24, 3, 2, false),
                ancestryDie(10, 10, 0x11, 0, null, true),
                ancestryDie(10, 11, 0x24, 3, parent, false),
            )
            val rows = ancestryRows(source)
            var consumed = false
            val proposed = sequence { consumed = true; yieldAll(rows) }
            assertFailsWith<IllegalArgumentException> {
                AbiPopulationSourceVerifier.verify({ source.asSequence() }, proposed, ancestryBudget(source))
            }
            assertTrue(!consumed, "a new unit must not inherit the prior unit's ancestry")
        }
    }

    @Test fun `verifier accepts nested siblings and fresh unit ancestry from direct obligations`() {
        val source = listOf(
            ancestryDie(0, 0, 0x11, 0, null, true),
            ancestryDie(0, 1, 0x2e, 1, 0, true),
            ancestryDie(0, 2, 0xb, 2, 1, true),
            ancestryDie(0, 3, 0x24, 3, 2, false),
            ancestryDie(0, 4, 0x24, 2, 1, false),
            ancestryDie(0, 5, 0x2e, 1, 0, true),
            ancestryDie(0, 6, 0x24, 2, 5, false),
            ancestryDie(10, 10, 0x11, 0, null, true),
            ancestryDie(10, 11, 0x24, 1, 10, false),
        )
        val rows = ancestryRows(source)
        var replays = 0
        val totals = AbiPopulationSourceVerifier.verify(
            { replays++; source.asSequence() }, rows.asSequence(), ancestryBudget(source),
        )
        assertEquals(2, replays)
        assertEquals(9L, totals.physicalRows)
        assertEquals(0L, totals.referenceRows)
        assertEquals(18L, totals.rowEdgeVisits)
    }

    // Deliberately bypass the producer and negative-offset locator formatter: the verifier must
    // reject the raw parent coordinate itself, not rely on another layer throwing first.
    private fun ancestryDie(unit: Long, offset: Long, tag: Long, depth: Int, parent: Long?, children: Boolean): DwarfPhysicalDieCensus {
        val raw = DwarfPhysicalDieCensus(unit, offset, offset + 1, tag, depth, parent, children)
        return if (parent == null || parent >= 0) raw else object : DwarfPhysicalDieCensus by raw {
            override val parentLocator: String? = null
        }
    }
    private fun ancestryRows(source: List<DwarfPhysicalDieCensus>): List<AbiSourceObligation> = source.mapIndexed { index, die ->
        val role = when (die.tag) {
            0x11L -> AbiSourceRole.UNIT
            0x2eL -> AbiSourceRole.CALLABLE
            0xbL -> AbiSourceRole.SCOPE
            0x24L -> AbiSourceRole.TYPE
            else -> error("unreviewed ancestry fixture tag")
        }
        AbiSourceObligation(index.toLong(), die.locator, die.tag, role, die.parentLocator,
            die.depth, die.hasChildren, emptyList())
    }
    private fun ancestryBudget(source: List<DwarfPhysicalDieCensus>) = AbiSourceBudget(
        maximumRows = source.size.toLong(), maximumRowEdgeVisits = 2L * source.size,
    )

    private fun build(source: List<DwarfPhysicalDieCensus>): List<AbiSourceObligation> = buildList {
        AbiPopulationSourceObligations.build(source.asSequence(), emit = ::add)
    }
    private fun fixture() = listOf(
        die(0, 0x11, 0, null, true), die(1, 0x2e, 1, 0, false),
        die(2, 0x34, 1, 0, false, edge(0x49, 3, ".debug_info:cu=0x0:die=0x3")),
        die(3, 0x24, 1, 0, false),
    )
    private fun edge(attribute: Long, operand: Long, target: String): DwarfPhysicalReferenceCensus =
        DwarfPhysicalReferenceCensus(0, attribute, 0x13, 0x13, 0, operand.toULong(), target).also {
            it.bindTargets(setOf(target)); it.seal()
        }
    private fun die(offset: Long, tag: Long, depth: Int, parent: Long?, children: Boolean,
        vararg refs: DwarfPhysicalReferenceCensus) =
        DwarfPhysicalDieCensus(0, offset, offset + 1, tag, depth, parent, children, refs.toList())
}
