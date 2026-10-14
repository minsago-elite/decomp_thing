package decompengine.oracle.structural

import decompengine.oracle.fulltree.DwarfPhysicalDieCensus
import java.security.MessageDigest

/**
 * Independent two-pass reconstruction. The source supplier must replay the same authenticated
 * stream on each invocation. No producer total, builder or stored cycle flag is trusted.
 * Primitive coordinate indexes are bounded by the profile; references do not allocate an index.
 */
internal object AbiPopulationSourceVerifier {
    fun verify(
        source: () -> Sequence<DwarfPhysicalDieCensus>,
        proposed: Sequence<AbiSourceObligation>,
        budget: AbiSourceBudget = AbiSourceBudget(),
    ): AbiSourceTotals {
        val offsets = LongArray(budget.maximumRows.toInt())
        val units = LongArray(budget.maximumRows.toInt())
        val firstReplay = MessageDigest.getInstance("SHA-256")
        val secondReplay = MessageDigest.getInstance("SHA-256")
        var count = 0
        var work = 0L
        var priorUnit = -1L
        var priorOffset = -1L
        var previousEnd = -1L
        val parents = LongArray(65) { -1 }
        val children = BooleanArray(65)
        for (die in source()) {
            require(++work <= budget.maximumRowEdgeVisits && count < offsets.size) { "verification bound" }
            require(die.compilationUnitOffset >= priorUnit)
            require(die.offset >= previousEnd) { "physical coordinates overlap or reorder" }
            if (die.compilationUnitOffset != priorUnit) {
                require(die.compilationUnitOffset >= previousEnd) { "compilation units overlap" }
                require(die.depth == 0 && die.tag == 0x11L && die.parentOffset == null)
                parents.fill(-1)
                priorOffset = -1
            } else {
                require(die.depth in 1..64 && die.depth <= 64)
                require(parents[die.depth - 1] == die.parentOffset && children[die.depth - 1])
            }
            require(die.offset > priorOffset && die.endOffset > die.offset)
            require(die.offset >= die.compilationUnitOffset && die.locator.length <= budget.maximumLocatorCharacters)
            parents[die.depth] = die.offset
            children[die.depth] = die.hasChildren
            for (depth in die.depth + 1..64) parents[depth] = -1
            require(die.references.size <= budget.maximumReferencesPerRow)
            for (edge in die.references) {
                require(++work <= budget.maximumRowEdgeVisits)
                require(edge.state == "retained-target" && edge.targetLocator != null) { "reference state requires reviewed policy" }
                require(edge.targetLocator!!.length <= budget.maximumLocatorCharacters) { "reference locator character bound" }
            }
            fingerprint(firstReplay, die)
            offsets[count] = die.offset
            units[count++] = die.compilationUnitOffset
            priorUnit = die.compilationUnitOffset
            priorOffset = die.offset
            previousEnd = die.endOffset
        }
        val rows = proposed.iterator()
        var ordinal = 0
        var edges = 0L
        for (die in source()) {
            require(++work <= budget.maximumRowEdgeVisits && ordinal < count)
            require(offsets[ordinal] == die.offset && units[ordinal] == die.compilationUnitOffset) { "source replay changed" }
            fingerprint(secondReplay, die)
            require(rows.hasNext()) { "omitted physical obligation" }
            val row = rows.next()
            require(row.ordinal == ordinal.toLong() && row.locator == die.locator && row.tag == die.tag)
            require(row.parentLocator == die.parentLocator && row.depth == die.depth && row.hasChildren == die.hasChildren)
            // Independent table: wire names deliberately do not invoke producer classification.
            val expectedRole = when (die.tag) {
                17L -> "UNIT"
                46L, 29L -> "CALLABLE"
                52L -> "STORAGE"
                1L, 2L, 4L, 15L, 16L, 19L, 21L, 22L, 23L, 36L, 38L, 55L, 59L, 66L -> "TYPE"
                5L, 24L -> "PARAMETER"
                13L, 28L, 33L, 40L -> "MEMBER"
                11L, 57L -> "SCOPE"
                8L, 58L -> "IMPORT"
                47L, 48L, 16646L, 16647L, 16648L -> "TEMPLATE"
                72L, 73L -> "CALLSITE"
                10L -> "LABEL"
                54L -> "EXPRESSION"
                else -> error("unreviewed physical tag")
            }
            require(row.role.name == expectedRole)
            require(die.references.size <= budget.maximumReferencesPerRow && row.references.size == die.references.size)
            var lastAttribute = -1
            die.references.forEachIndexed { index, edge ->
                require(++work <= budget.maximumRowEdgeVisits)
                edges++
                val relation = row.references[index]
                require(edge.attributeOrdinal > lastAttribute)
                lastAttribute = edge.attributeOrdinal
                val expected = when (edge.attribute) {
                    1L -> "SIBLING"
                    24L -> "IMPORT"
                    29L -> "CONTAINING_TYPE"
                    47L -> "UPPER_BOUND"
                    49L -> "ABSTRACT_ORIGIN"
                    71L -> "SPECIFICATION"
                    73L -> "TYPE_USE"
                    100L -> "OBJECT_POINTER"
                    127L -> "CALL_ORIGIN"
                    else -> error("unreviewed reference attribute")
                }
                require(relation.attributeOrdinal == edge.attributeOrdinal && relation.attribute == edge.attribute)
                require(relation.role.name == expected && relation.targetLocator == edge.targetLocator)
                require(relation.interpretationRequired) { "typed semantic interpretation remains required" }
                require(edge.declaredForm == 19L && edge.resolvedForm == 19L && edge.indirectDepth == 0)
                require(edge.rawOperand <= 0xffff_ffffuL) { "ref4 operand width" }
                require(edge.state == "retained-target" && edge.targetLocator != null) { "reference state requires reviewed policy" }
                require(edge.rawOperand <= Long.MAX_VALUE.toULong() - die.compilationUnitOffset.toULong())
                if (edge.state == "retained-target") {
                    val target = die.compilationUnitOffset + edge.rawOperand.toLong()
                    val found = offsets.binarySearch(target, 0, count)
                    require(found >= 0 && units[found] == die.compilationUnitOffset) { "forged reference target" }
                    require(edge.targetLocator == ".debug_info:cu=0x${die.compilationUnitOffset.toString(16)}:die=0x${target.toString(16)}")
                    if (expected == "SIBLING") require(target > die.offset) { "backward sibling" }
                }
            }
            ordinal++
        }
        require(ordinal == count && !rows.hasNext()) { "extra physical obligation or changed replay" }
        require(firstReplay.digest().contentEquals(secondReplay.digest())) { "authenticated source replay changed" }
        return AbiSourceTotals(count.toLong(), edges, work)
    }
    private fun fingerprint(digest: MessageDigest, die: DwarfPhysicalDieCensus) {
        fun number(value: Long) { for (shift in 56 downTo 0 step 8) digest.update((value ushr shift).toByte()) }
        fun text(value: String?) {
            if (value == null) number(-1) else {
                require(value.length <= 4096) { "fingerprint text character bound" }
                val bytes = value.toByteArray(Charsets.UTF_8)
                require(bytes.size <= 16_384)
                number(bytes.size.toLong()); digest.update(bytes)
            }
        }
        number(die.compilationUnitOffset); number(die.offset); number(die.endOffset); number(die.tag)
        number(die.depth.toLong()); number(die.parentOffset ?: -1); number(if (die.hasChildren) 1 else 0)
        number(die.references.size.toLong())
        for (edge in die.references) {
            number(edge.attributeOrdinal.toLong()); number(edge.attribute); number(edge.declaredForm)
            number(edge.resolvedForm); number(edge.indirectDepth.toLong()); number(edge.rawOperand.toLong())
            text(edge.targetLocator); text(edge.state)
            // Producer cycle bits are deliberately not used as semantic identity evidence.
        }
    }
}
