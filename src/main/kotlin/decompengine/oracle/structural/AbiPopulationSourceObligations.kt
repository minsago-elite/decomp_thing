package decompengine.oracle.structural

import decompengine.oracle.fulltree.DwarfPhysicalDieCensus

/** Coverage roles are obligations, never semantic entities or classifications. */
internal enum class AbiSourceRole {
    UNIT, CALLABLE, STORAGE, TYPE, PARAMETER, MEMBER, SCOPE, IMPORT, TEMPLATE, CALLSITE, LABEL, EXPRESSION,
}
internal enum class AbiReferenceRole {
    SIBLING, IMPORT, CONTAINING_TYPE, UPPER_BOUND, ABSTRACT_ORIGIN, SPECIFICATION, TYPE_USE, OBJECT_POINTER, CALL_ORIGIN,
}

internal data class AbiSourceObligation(
    val ordinal: Long,
    val locator: String,
    val tag: Long,
    val role: AbiSourceRole,
    val parentLocator: String?,
    val depth: Int,
    val hasChildren: Boolean,
    val references: List<AbiReferenceObligation>,
)
internal data class AbiReferenceObligation(
    val attributeOrdinal: Int,
    val attribute: Long,
    val role: AbiReferenceRole,
    val targetLocator: String?,
    val interpretationRequired: Boolean,
)

/**
 * Row/edge traversal guard only. This is NOT an admitted aggregate ledger/capture profile:
 * canonical parsing, scalar decoding, emitted bytes, index storage and replay deadline/RSS must
 * be charged by the authenticated caller. Passing this guard supplies no resource qualification.
 * In particular it cannot be added to a capture's remaining work allowance by splitting passes.
 */
internal data class AbiSourceBudget(
    val maximumRows: Long = 1_000_000,
    val maximumRowEdgeVisits: Long = 5_000_000,
    val maximumReferencesPerRow: Int = 100_000,
    val maximumLocatorCharacters: Int = 4096,
) {
    init {
        require(maximumRows in 1..1_000_000 && maximumRowEdgeVisits in 1..5_000_000)
        require(maximumReferencesPerRow in 1..100_000 && maximumLocatorCharacters in 1..4096)
    }
}
internal data class AbiSourceTotals(val physicalRows: Long, val referenceRows: Long, val rowEdgeVisits: Long)

/**
 * Closed admission-v1 tag table. Unsupported future tags fail this version, rather than inheriting
 * coarse scanner irrelevance. GNU packs remain explicit semantic interpretation obligations.
 * Callers supply authenticated replay views, not producer population summaries.
 */
internal object AbiPopulationSourceObligations {
    fun build(
        source: Sequence<DwarfPhysicalDieCensus>,
        budget: AbiSourceBudget = AbiSourceBudget(),
        emit: (AbiSourceObligation) -> Unit,
    ): AbiSourceTotals {
        var rows = 0L
        var edges = 0L
        var work = 0L
        for (die in source) {
            require(++rows <= budget.maximumRows) { "source row bound" }
            require(++work <= budget.maximumRowEdgeVisits) { "source work bound" }
            require(die.locator.length <= budget.maximumLocatorCharacters && die.depth in 0..64)
            require(die.offset >= die.compilationUnitOffset && die.endOffset > die.offset)
            require(die.references.size <= budget.maximumReferencesPerRow)
            var previous = -1
            val references = die.references.map { edge ->
                require(++work <= budget.maximumRowEdgeVisits) { "source work bound" }
                edges++
                require(edge.attributeOrdinal > previous) { "duplicate or unordered attribute ordinal" }
                previous = edge.attributeOrdinal
                require(edge.targetLocator == null || edge.targetLocator!!.length <= budget.maximumLocatorCharacters)
                val role = referenceRole(edge.attribute)
                // This policy admits only the observed CU-relative form. Other forms need a new policy.
                require(edge.declaredForm == 0x13L && edge.resolvedForm == 0x13L && edge.indirectDepth == 0)
                require(edge.rawOperand <= 0xffff_ffffuL) { "ref4 operand width" }
                require(edge.state == "retained-target" && edge.targetLocator != null) { "reference state requires reviewed policy" }
                AbiReferenceObligation(edge.attributeOrdinal, edge.attribute, role, edge.targetLocator, true)
            }
            emit(AbiSourceObligation(rows - 1, die.locator, die.tag, role(die.tag), die.parentLocator,
                die.depth, die.hasChildren, references))
        }
        return AbiSourceTotals(rows, edges, work)
    }

    private fun role(tag: Long): AbiSourceRole = when (tag) {
        0x11L -> AbiSourceRole.UNIT
        0x2eL, 0x1dL -> AbiSourceRole.CALLABLE
        0x34L -> AbiSourceRole.STORAGE
        0x1L, 0x2L, 0x4L, 0xfL, 0x10L, 0x13L, 0x15L, 0x16L, 0x17L, 0x24L,
        0x26L, 0x37L, 0x3bL, 0x42L -> AbiSourceRole.TYPE
        0x5L, 0x18L -> AbiSourceRole.PARAMETER
        0xdL, 0x1cL, 0x21L, 0x28L -> AbiSourceRole.MEMBER
        0xbL, 0x39L -> AbiSourceRole.SCOPE
        0x8L, 0x3aL -> AbiSourceRole.IMPORT
        0x2fL, 0x30L, 0x4106L, 0x4107L, 0x4108L -> AbiSourceRole.TEMPLATE
        0x48L, 0x49L -> AbiSourceRole.CALLSITE
        0xaL -> AbiSourceRole.LABEL
        0x36L -> AbiSourceRole.EXPRESSION
        else -> throw IllegalArgumentException("tag requires reviewed policy: $tag")
    }
    private fun referenceRole(attribute: Long): AbiReferenceRole = when (attribute) {
        0x1L -> AbiReferenceRole.SIBLING
        0x18L -> AbiReferenceRole.IMPORT
        0x1dL -> AbiReferenceRole.CONTAINING_TYPE
        0x2fL -> AbiReferenceRole.UPPER_BOUND
        0x31L -> AbiReferenceRole.ABSTRACT_ORIGIN
        0x47L -> AbiReferenceRole.SPECIFICATION
        0x49L -> AbiReferenceRole.TYPE_USE
        0x64L -> AbiReferenceRole.OBJECT_POINTER
        0x7fL -> AbiReferenceRole.CALL_ORIGIN
        else -> throw IllegalArgumentException("attribute requires reviewed policy: $attribute")
    }
}
