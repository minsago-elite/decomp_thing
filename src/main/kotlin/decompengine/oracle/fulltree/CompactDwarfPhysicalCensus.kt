package decompengine.oracle.fulltree

/**
 * Full physical universe in fixed primitive blocks. No DIE, reference, locator string,
 * boxed offset, hash entry or per-DIE reference list is retained. Row objects and their
 * canonical locators are short-lived read views only. Capacity, not occupied rows, is
 * charged before allocation. Bounds do not depend on compressed references or strings.
 */
internal class CompactDwarfPhysicalCensus(
    private val budget: DwarfInterfaceFactBudget,
    private val maximumDies: Int,
    private val maximumReferences: Long,
) {
    private class DieBlock {
        val longs = LongArray(BLOCK_ROWS * DIE_LONGS)
        val ints = IntArray(BLOCK_ROWS * DIE_INTS)
        val flags = ByteArray(BLOCK_ROWS)
        val findings = LongArray(BLOCK_ROWS / 64)
    }
    private class ReferenceBlock {
        val longs = LongArray(BLOCK_ROWS * REFERENCE_LONGS)
        val ints = IntArray(BLOCK_ROWS * REFERENCE_INTS)
        val flags = ByteArray(BLOCK_ROWS)
        val findings = LongArray(BLOCK_ROWS / 64)
    }
    private val dieBlocks = ArrayList<DieBlock>()
    private val referenceBlocks = ArrayList<ReferenceBlock>()
    var dieCount: Int = 0
        private set
    var referenceCount: Int = 0
        private set
    var modeledBytes: Long = FIXED_ALLOWANCE
        private set
    private var sealed = false
    init {
        require(maximumDies in 1..5_000_000 && maximumReferences in 1..50_000_000)
        budget.charge(FIXED_ALLOWANCE, "compact physical census containers")
    }
    private fun charge(bytes: Long, label: String) {
        budget.charge(bytes, label)
        modeledBytes = Math.addExact(modeledBytes, bytes)
    }
    fun appendDie(unit: Long, offset: Long, end: Long, tag: Long, depth: Int, parent: Long?, children: Boolean) {
        check(!sealed)
        if (dieCount >= maximumDies) throw FullTreeControlException("physical census exceeds DIE bound")
        require(unit >= 0 && offset >= unit && end > offset && tag >= 0 && depth >= 0 && (parent == null || parent in unit until offset))
        require(dieCount == 0 || offset > dieLong(dieCount - 1, 1)) { "physical DIE census repeats or reorders an offset" }
        if (dieCount % BLOCK_ROWS == 0) {
            charge(DIE_BLOCK_BYTES, "compact physical DIE block capacity")
            dieBlocks += DieBlock()
        }
        val row = dieCount++
        setDieLong(row, 0, unit); setDieLong(row, 1, offset); setDieLong(row, 2, end)
        setDieLong(row, 3, tag); setDieLong(row, 4, parent ?: -1L)
        setDieInt(row, 0, depth); setDieInt(row, 1, referenceCount); setDieInt(row, 2, 0)
        dieBlocks[row / BLOCK_ROWS].flags[row % BLOCK_ROWS] = if (children) 1 else 0
        if (physicalCategory(tag) == "unknown") markDieFinding(row)
    }
    fun appendReference(ordinal: Int, attribute: Long, declared: Long, resolved: Long, indirect: Int, operand: ULong,
                        targetUnit: Long?, targetOffset: Long?, unresolved: String?) {
        check(!sealed && dieCount > 0)
        if (referenceCount.toLong() >= maximumReferences) throw FullTreeControlException("physical DIE census exceeds traversal-work bound: references")
        require(ordinal >= 0 && attribute >= 0 && declared >= 0 && resolved >= 0 && indirect >= 0)
        require(targetUnit == null || targetUnit >= 0 && targetOffset != null && targetOffset >= targetUnit)
        val initialState = when (unresolved) {
            null -> { require(targetUnit != null && targetOffset != null); UNBOUND }
            "unsupported-reference" -> { require(targetUnit == null); UNSUPPORTED }
            "out-of-range-reference" -> { require(targetUnit == null); OUT_OF_RANGE }
            else -> error("unknown physical reference state")
        }
        if (referenceCount % BLOCK_ROWS == 0) {
            charge(REFERENCE_BLOCK_BYTES, "compact physical reference block capacity")
            referenceBlocks += ReferenceBlock()
        }
        val row = referenceCount++
        setReferenceInt(row, 0, ordinal); setReferenceInt(row, 1, indirect); setReferenceInt(row, 2, -1)
        setReferenceLong(row, 0, attribute); setReferenceLong(row, 1, declared); setReferenceLong(row, 2, resolved)
        setReferenceLong(row, 3, operand.toLong()); setReferenceLong(row, 4, targetUnit ?: -1L)
        setReferenceLong(row, 5, if (targetUnit == null) -1L else targetOffset!!)
        setReferenceFlag(row, initialState)
        setDieInt(dieCount - 1, 2, Math.addExact(dieInt(dieCount - 1, 2), 1))
    }
    fun reconcile(limits: BoundedDwarfInterfaceFactLimits, parseBudget: FullTreeDwarfParseBudget) {
        check(!sealed)
        require(dieCount.toLong() <= limits.maximumScannedDies && referenceCount.toLong() <= limits.maximumTypeTraversalSteps)
        for (row in 0 until dieCount) parseBudget.consume("physical census identities")
        for (die in 0 until dieCount) {
            val first = dieInt(die, 1)
            for (row in first until first + dieInt(die, 2)) {
                parseBudget.consume("physical census target reconciliation")
                if (referenceFlag(row) == UNBOUND) {
                    val target = findDie(referenceLong(row, 4), referenceLong(row, 5), parseBudget)
                    setReferenceInt(row, 2, target)
                    setReferenceFlag(row, if (target >= 0) RETAINED else MISSING)
                }
                if (referenceFlag(row) != RETAINED) { markDieFinding(die); markReferenceFinding(row) }
            }
        }
        // Both scan and later source replay use this same bounded allowance, never
        // simultaneously. No per-node frames, maps or second census are allocated.
        charge(traversalBytes(dieCount), "physical census primitive traversal capacity")
        val colors = ByteArray(dieCount)
        val stackDies = IntArray(dieCount)
        val stackNext = IntArray(dieCount)
        var steps = 0L
        for (root in 0 until dieCount) {
            if (colors[root].toInt() != 0) continue
            var size = 1; stackDies[0] = root; stackNext[0] = 0; colors[root] = 1
            while (size > 0) {
                parseBudget.consume("physical census reference cycles")
                if (++steps > limits.maximumTypeTraversalSteps) throw FullTreeControlException("physical census cycle scan exceeds traversal-work bound")
                val position = size - 1; val die = stackDies[position]
                if (stackNext[position] == dieInt(die, 2)) { colors[die] = 2; size--; continue }
                val ref = dieInt(die, 1) + stackNext[position]++
                val target = referenceInt(ref, 2)
                if (target < 0) continue
                when (colors[target].toInt()) {
                    1 -> { setReferenceFlag(ref, referenceFlag(ref) or CYCLIC); markDieFinding(die); markReferenceFinding(ref) }
                    2 -> Unit
                    else -> { stackDies[size] = target; stackNext[size] = 0; size++; colors[target] = 1 }
                }
            }
        }
        sealed = true
    }
    fun sealedDies(): CompactPhysicalDieList {
        // No-DWARF inputs have the complete empty census, with no graph to reconcile.
        if (dieCount == 0 && referenceCount == 0) sealed = true
        check(sealed)
        return CompactPhysicalDieList(this)
    }
    /** Word scans skip ordinary rows; each actual bitmap probe consumes inventory work. */
    internal fun findingRows(work: () -> Unit): Sequence<Pair<DwarfPhysicalDieCensus, DwarfPhysicalReferenceCensus?>> = sequence {
        check(sealed)
        var die = nextFinding(0, dieCount, true, work)
        while (die >= 0) {
            val view = DieView(this@CompactDwarfPhysicalCensus, die)
            if (view.category == "unknown") yield(view to null)
            val first = dieInt(die, 1); val end = first + dieInt(die, 2)
            var ref = nextFinding(first, end, false, work)
            while (ref >= 0) {
                yield(view to ReferenceView(this@CompactDwarfPhysicalCensus, ref))
                ref = nextFinding(ref + 1, end, false, work)
            }
            die = nextFinding(die + 1, dieCount, true, work)
        }
    }
    private fun markDieFinding(row: Int) {
        val block = dieBlocks[row / BLOCK_ROWS]
        block.findings[(row % BLOCK_ROWS) / 64] = block.findings[(row % BLOCK_ROWS) / 64] or (1L shl (row % 64))
    }
    private fun markReferenceFinding(row: Int) {
        val block = referenceBlocks[row / BLOCK_ROWS]
        block.findings[(row % BLOCK_ROWS) / 64] = block.findings[(row % BLOCK_ROWS) / 64] or (1L shl (row % 64))
    }
    private fun nextFinding(start: Int, end: Int, dies: Boolean, work: () -> Unit): Int {
        var row = start
        while (row < end) {
            work()
            val word = if (dies) dieBlocks[row / BLOCK_ROWS].findings[(row % BLOCK_ROWS) / 64]
                else referenceBlocks[row / BLOCK_ROWS].findings[(row % BLOCK_ROWS) / 64]
            val candidates = word and (-1L shl (row % 64))
            if (candidates != 0L) return (row / 64 * 64 + java.lang.Long.numberOfTrailingZeros(candidates)).takeIf { it < end } ?: -1
            row = (row / 64 + 1) * 64
        }
        return -1
    }
    private fun findDie(unit: Long, offset: Long, parseBudget: FullTreeDwarfParseBudget): Int {
        var low = 0; var high = dieCount - 1
        while (low <= high) {
            parseBudget.consume("physical census target lookup")
            val middle = low + (high - low) / 2
            when { offset < dieLong(middle, 1) -> high = middle - 1
                offset > dieLong(middle, 1) -> low = middle + 1
                else -> return if (dieLong(middle, 0) == unit) middle else -1 }
        }
        return -1
    }
    internal fun die(row: Int): DwarfPhysicalDieCensus {
        check(sealed); require(row in 0 until dieCount)
        return DieView(this, row)
    }
    private class DieView(private val census: CompactDwarfPhysicalCensus, private val row: Int) : DwarfPhysicalDieCensus {
        override val compilationUnitOffset: Long get() = census.dieLong(row, 0)
        override val offset: Long get() = census.dieLong(row, 1)
        override val endOffset: Long get() = census.dieLong(row, 2)
        override val tag: Long get() = census.dieLong(row, 3)
        override val parentOffset: Long? get() = census.dieLong(row, 4).takeIf { it >= 0 }
        override val depth: Int get() = census.dieInt(row, 0)
        override val hasChildren: Boolean get() = census.dieBlocks[row / BLOCK_ROWS].flags[row % BLOCK_ROWS].toInt() != 0
        override val references: List<DwarfPhysicalReferenceCensus> get() = object : java.util.AbstractList<DwarfPhysicalReferenceCensus>() {
            override val size: Int get() = census.dieInt(row, 2)
            override fun get(index: Int): DwarfPhysicalReferenceCensus {
                require(index in 0 until size)
                return ReferenceView(census, census.dieInt(row, 1) + index)
            }
        }
    }
    private class ReferenceView(private val census: CompactDwarfPhysicalCensus, private val row: Int) : DwarfPhysicalReferenceCensus {
        override val attributeOrdinal: Int get() = census.referenceInt(row, 0)
        override val indirectDepth: Int get() = census.referenceInt(row, 1)
        override val attribute: Long get() = census.referenceLong(row, 0)
        override val declaredForm: Long get() = census.referenceLong(row, 1)
        override val resolvedForm: Long get() = census.referenceLong(row, 2)
        override val rawOperand: ULong get() = census.referenceLong(row, 3).toULong()
        override val targetLocator: String? get() = census.referenceLong(row, 4).takeIf { it >= 0 }?.let {
            physicalDieLocator(it, census.referenceLong(row, 5))
        }
        override val state: String get() = when (census.referenceFlag(row) and STATE_MASK) {
            RETAINED -> "retained-target"; UNSUPPORTED -> "unsupported-reference"
            OUT_OF_RANGE -> "out-of-range-reference"; MISSING -> "missing-target"
            else -> error("physical reference has not been reconciled")
        }
        override val reasons: List<String> get() = buildList {
            if (state != "retained-target") add(state)
            if (census.referenceFlag(row) and CYCLIC != 0) add("reference-cycle")
        }
        override fun bindTargets(locators: Set<String>): Unit = error("physical reference is sealed")
        override fun markCycle(): Unit = error("physical reference is sealed")
        override fun seal(): Unit = error("physical reference is sealed")
    }
    private fun dieLong(row: Int, column: Int) = dieBlocks[row / BLOCK_ROWS].longs[(row % BLOCK_ROWS) * DIE_LONGS + column]
    private fun setDieLong(row: Int, column: Int, value: Long) { dieBlocks[row / BLOCK_ROWS].longs[(row % BLOCK_ROWS) * DIE_LONGS + column] = value }
    private fun dieInt(row: Int, column: Int) = dieBlocks[row / BLOCK_ROWS].ints[(row % BLOCK_ROWS) * DIE_INTS + column]
    private fun setDieInt(row: Int, column: Int, value: Int) { dieBlocks[row / BLOCK_ROWS].ints[(row % BLOCK_ROWS) * DIE_INTS + column] = value }
    private fun referenceLong(row: Int, column: Int) = referenceBlocks[row / BLOCK_ROWS].longs[(row % BLOCK_ROWS) * REFERENCE_LONGS + column]
    private fun setReferenceLong(row: Int, column: Int, value: Long) { referenceBlocks[row / BLOCK_ROWS].longs[(row % BLOCK_ROWS) * REFERENCE_LONGS + column] = value }
    private fun referenceInt(row: Int, column: Int) = referenceBlocks[row / BLOCK_ROWS].ints[(row % BLOCK_ROWS) * REFERENCE_INTS + column]
    private fun setReferenceInt(row: Int, column: Int, value: Int) { referenceBlocks[row / BLOCK_ROWS].ints[(row % BLOCK_ROWS) * REFERENCE_INTS + column] = value }
    private fun referenceFlag(row: Int) = referenceBlocks[row / BLOCK_ROWS].flags[row % BLOCK_ROWS].toInt()
    private fun setReferenceFlag(row: Int, value: Int) { referenceBlocks[row / BLOCK_ROWS].flags[row % BLOCK_ROWS] = value.toByte() }
    internal companion object {
        const val BLOCK_ROWS = 128
        private const val DIE_LONGS = 5
        private const val DIE_INTS = 3
        private const val REFERENCE_LONGS = 6
        private const val REFERENCE_INTS = 3
        private const val FIXED_ALLOWANCE = 1024L
        // 512/block covers four array headers/alignment, the block, retained list
        // slots plus ArrayList growth slack, even with uncompressed object pointers.
        const val DIE_BLOCK_BYTES = BLOCK_ROWS * (8L * DIE_LONGS + 4L * DIE_INTS + 1L) + BLOCK_ROWS / 8L + 512L
        const val REFERENCE_BLOCK_BYTES = BLOCK_ROWS * (8L * REFERENCE_LONGS + 4L * REFERENCE_INTS + 1L) + BLOCK_ROWS / 8L + 512L
        fun traversalBytes(rows: Int): Long = Math.addExact(Math.multiplyExact(rows.toLong(), 9L), 256L)
        private const val UNBOUND = 0
        private const val RETAINED = 1
        private const val UNSUPPORTED = 2
        private const val OUT_OF_RANGE = 3
        private const val MISSING = 4
        private const val STATE_MASK = 7
        private const val CYCLIC = 8
    }
}

/** Trusted, immutable, non-materializing census list. No collection-copy facade is needed. */
internal class CompactPhysicalDieList(private val census: CompactDwarfPhysicalCensus) : java.util.AbstractList<DwarfPhysicalDieCensus>() {
    override val size: Int get() = census.dieCount
    override fun get(index: Int): DwarfPhysicalDieCensus = census.die(index)
    internal fun findingRows(work: () -> Unit) = census.findingRows(work)
}
