package decompengine.oracle.structural

/** Explicit resource bounds for the sparse, globally order-preserving boundary assignment. */
internal data class SparseMonotoneAssignmentLimits(
    val maximumLeftRecords: Int = 1_000_000,
    val maximumRightRecords: Int = 1_000_000,
    val maximumDistanceBytes: Int = 4_096,
    val maximumCandidateEdges: Int = 5_000_000,
    val maximumOptimalCandidateEdges: Int = 1_000_000,
) {
    init {
        require(maximumLeftRecords in 0..HARD_MAXIMUM_RECORDS)
        require(maximumRightRecords in 0..HARD_MAXIMUM_RECORDS)
        require(maximumDistanceBytes in 0..HARD_MAXIMUM_DISTANCE_BYTES)
        require(maximumCandidateEdges in 1..HARD_MAXIMUM_CANDIDATE_EDGES)
        require(maximumOptimalCandidateEdges in 1..HARD_MAXIMUM_OPTIMAL_CANDIDATE_EDGES)
    }

    private companion object {
        const val HARD_MAXIMUM_RECORDS = 5_000_000
        const val HARD_MAXIMUM_DISTANCE_BYTES = 4_096
        const val HARD_MAXIMUM_CANDIDATE_EDGES = 50_000_000
        const val HARD_MAXIMUM_OPTIMAL_CANDIDATE_EDGES = 5_000_000
    }
}

internal data class SparseMonotoneAssignmentEdge(
    val leftIndex: Int,
    val rightIndex: Int,
    val distanceBytes: Int,
)

internal data class SparseMonotoneAssignmentResult(
    val selectedEdges: List<SparseMonotoneAssignmentEdge>,
    val optimalCandidateEdges: List<SparseMonotoneAssignmentEdge>,
    val maximumCardinality: Int,
    val minimumTotalDistanceBytes: Long,
    val candidateEdgeCount: Int,
)

internal class SparseMonotoneAssignmentException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Solves the exact historical boundary objective without allocating the dense Cartesian grid.
 *
 * Inputs must be unique, strictly increasing unsigned RVAs. Legal edges are those whose absolute
 * distance is at most [maximumDistanceBytes]. Among strictly order-preserving one-to-one chains,
 * the solver maximizes cardinality, minimizes total distance, and then selects the
 * lexicographically lowest `(left RVA, right RVA)` edge sequence. Two grouped Fenwick passes keep
 * the objective global; independently solving address shards would not be equivalent.
 */
internal object SparseMonotoneAssignment {
    fun solve(
        leftRvas: List<ULong>,
        rightRvas: List<ULong>,
        maximumDistanceBytes: Int,
        limits: SparseMonotoneAssignmentLimits = SparseMonotoneAssignmentLimits(),
    ): SparseMonotoneAssignmentResult {
        validateInput(leftRvas, limits.maximumLeftRecords, "left")
        validateInput(rightRvas, limits.maximumRightRecords, "right")
        if (maximumDistanceBytes !in 0..limits.maximumDistanceBytes) {
            sparseAssignmentFail("distance bound exceeds the configured sparse-assignment limit")
        }
        if (leftRvas.isEmpty() || rightRvas.isEmpty()) {
            return SparseMonotoneAssignmentResult(emptyList(), emptyList(), 0, 0L, 0)
        }

        val candidateCount = countCandidateEdges(
            leftRvas,
            rightRvas,
            maximumDistanceBytes,
            limits.maximumCandidateEdges,
        )
        if (candidateCount == 0) {
            return SparseMonotoneAssignmentResult(emptyList(), emptyList(), 0, 0L, 0)
        }

        try {
            val edges = CandidateEdges(candidateCount)
            fillCandidateEdges(leftRvas, rightRvas, maximumDistanceBytes, edges)

            val fenwick = ObjectiveFenwick(rightRvas.size)
            computePrefixes(edges, fenwick)
            val global = fenwick.query(rightRvas.size)
            fenwick.clear()
            computeSuffixes(edges, rightRvas.size, fenwick)
            if (fenwick.query(rightRvas.size) != global) {
                sparseAssignmentFail("forward and backward sparse-assignment objectives disagree")
            }

            val optimalCandidates = collectOptimalCandidates(
                edges,
                global,
                limits.maximumOptimalCandidateEdges,
            )
            val selected = reconstructLexicographicallyLowest(edges, global)
            return SparseMonotoneAssignmentResult(
                selectedEdges = selected,
                optimalCandidateEdges = optimalCandidates,
                maximumCardinality = global.count,
                minimumTotalDistanceBytes = global.cost,
                candidateEdgeCount = candidateCount,
            )
        } catch (failure: OutOfMemoryError) {
            throw SparseMonotoneAssignmentException(
                "not enough memory for the bounded sparse monotone assignment",
                failure,
            )
        }
    }
}

private data class AssignmentObjective(val count: Int, val cost: Long)

private class CandidateEdges(size: Int) {
    val left = IntArray(size)
    val right = IntArray(size)
    val distance = IntArray(size)
    val prefixCount = IntArray(size)
    val prefixCost = LongArray(size)
    val suffixCount = IntArray(size)
    val suffixCost = LongArray(size)
    val size: Int = size

    fun edge(index: Int): SparseMonotoneAssignmentEdge = SparseMonotoneAssignmentEdge(
        left[index],
        right[index],
        distance[index],
    )
}

private class ObjectiveFenwick(size: Int) {
    private val counts = IntArray(size + 1)
    private val costs = LongArray(size + 1)

    /** Returns the best state whose zero-based position is strictly below [exclusivePosition]. */
    fun query(exclusivePosition: Int): AssignmentObjective {
        var position = exclusivePosition
        var best = AssignmentObjective(0, 0L)
        while (position > 0) {
            val candidate = AssignmentObjective(counts[position], costs[position])
            if (candidate.betterThan(best)) best = candidate
            position -= position and -position
        }
        return best
    }

    fun update(position: Int, objective: AssignmentObjective) {
        var cursor = position + 1
        while (cursor < counts.size) {
            val current = AssignmentObjective(counts[cursor], costs[cursor])
            if (objective.betterThan(current)) {
                counts[cursor] = objective.count
                costs[cursor] = objective.cost
            }
            cursor += cursor and -cursor
        }
    }

    fun clear() {
        counts.fill(0)
        costs.fill(0L)
    }
}

private fun validateInput(values: List<ULong>, maximumRecords: Int, label: String) {
    if (values.size > maximumRecords) sparseAssignmentFail("$label input exceeds its record limit")
    for (index in 1 until values.size) {
        if (values[index - 1] >= values[index]) {
            sparseAssignmentFail("$label RVAs must be unique and strictly increasing")
        }
    }
}

private fun countCandidateEdges(
    left: List<ULong>,
    right: List<ULong>,
    maximumDistanceBytes: Int,
    maximumCandidateEdges: Int,
): Int {
    var count = 0L
    candidateWindows(left, right, maximumDistanceBytes) { _, start, endExclusive ->
        count = try {
            Math.addExact(count, (endExclusive - start).toLong())
        } catch (failure: ArithmeticException) {
            throw SparseMonotoneAssignmentException("candidate-edge count overflowed", failure)
        }
        if (count > maximumCandidateEdges.toLong()) {
            sparseAssignmentFail("candidate-edge count exceeds the configured sparse-assignment limit")
        }
    }
    return count.toInt()
}

private fun fillCandidateEdges(
    left: List<ULong>,
    right: List<ULong>,
    maximumDistanceBytes: Int,
    edges: CandidateEdges,
) {
    var edgeIndex = 0
    candidateWindows(left, right, maximumDistanceBytes) { leftIndex, start, endExclusive ->
        for (rightIndex in start until endExclusive) {
            edges.left[edgeIndex] = leftIndex
            edges.right[edgeIndex] = rightIndex
            edges.distance[edgeIndex] = boundedDistance(left[leftIndex], right[rightIndex], maximumDistanceBytes)
            edgeIndex++
        }
    }
    if (edgeIndex != edges.size) sparseAssignmentFail("candidate-edge enumeration drifted after preflight")
}

private inline fun candidateWindows(
    left: List<ULong>,
    right: List<ULong>,
    maximumDistanceBytes: Int,
    visit: (leftIndex: Int, start: Int, endExclusive: Int) -> Unit,
) {
    val distance = maximumDistanceBytes.toULong()
    var start = 0
    var endExclusive = 0
    left.forEachIndexed { leftIndex, leftRva ->
        val minimum = if (leftRva >= distance) leftRva - distance else 0UL
        val maximum = if (ULong.MAX_VALUE - leftRva >= distance) leftRva + distance else ULong.MAX_VALUE
        while (start < right.size && right[start] < minimum) start++
        if (endExclusive < start) endExclusive = start
        while (endExclusive < right.size && right[endExclusive] <= maximum) endExclusive++
        visit(leftIndex, start, endExclusive)
    }
}

private fun boundedDistance(left: ULong, right: ULong, maximumDistanceBytes: Int): Int {
    val distance = if (left >= right) left - right else right - left
    if (distance > maximumDistanceBytes.toULong()) {
        sparseAssignmentFail("candidate-edge enumeration produced an out-of-bound distance")
    }
    return distance.toInt()
}

private fun computePrefixes(edges: CandidateEdges, fenwick: ObjectiveFenwick) {
    var groupStart = 0
    while (groupStart < edges.size) {
        val leftIndex = edges.left[groupStart]
        var groupEnd = groupStart + 1
        while (groupEnd < edges.size && edges.left[groupEnd] == leftIndex) groupEnd++

        for (edgeIndex in groupStart until groupEnd) {
            val before = fenwick.query(edges.right[edgeIndex])
            edges.prefixCount[edgeIndex] = Math.addExact(before.count, 1)
            edges.prefixCost[edgeIndex] = checkedCostAdd(before.cost, edges.distance[edgeIndex])
        }
        for (edgeIndex in groupStart until groupEnd) {
            fenwick.update(
                edges.right[edgeIndex],
                AssignmentObjective(edges.prefixCount[edgeIndex], edges.prefixCost[edgeIndex]),
            )
        }
        groupStart = groupEnd
    }
}

private fun computeSuffixes(edges: CandidateEdges, rightCount: Int, fenwick: ObjectiveFenwick) {
    var groupEnd = edges.size
    while (groupEnd > 0) {
        val leftIndex = edges.left[groupEnd - 1]
        var groupStart = groupEnd - 1
        while (groupStart > 0 && edges.left[groupStart - 1] == leftIndex) groupStart--

        for (edgeIndex in groupStart until groupEnd) {
            val reversePosition = rightCount - 1 - edges.right[edgeIndex]
            val after = fenwick.query(reversePosition)
            edges.suffixCount[edgeIndex] = Math.addExact(after.count, 1)
            edges.suffixCost[edgeIndex] = checkedCostAdd(after.cost, edges.distance[edgeIndex])
        }
        for (edgeIndex in groupStart until groupEnd) {
            val reversePosition = rightCount - 1 - edges.right[edgeIndex]
            fenwick.update(
                reversePosition,
                AssignmentObjective(edges.suffixCount[edgeIndex], edges.suffixCost[edgeIndex]),
            )
        }
        groupEnd = groupStart
    }
}

private fun collectOptimalCandidates(
    edges: CandidateEdges,
    global: AssignmentObjective,
    maximumOptimalCandidateEdges: Int,
): List<SparseMonotoneAssignmentEdge> {
    val result = ArrayList<SparseMonotoneAssignmentEdge>(minOf(global.count, maximumOptimalCandidateEdges))
    for (edgeIndex in 0 until edges.size) {
        val combinedCount = Math.addExact(edges.prefixCount[edgeIndex], edges.suffixCount[edgeIndex]) - 1
        val combinedCost = Math.subtractExact(
            Math.addExact(edges.prefixCost[edgeIndex], edges.suffixCost[edgeIndex]),
            edges.distance[edgeIndex].toLong(),
        )
        if (combinedCount == global.count && combinedCost == global.cost) {
            if (result.size >= maximumOptimalCandidateEdges) {
                sparseAssignmentFail("optimal candidate-edge count exceeds the configured ambiguity limit")
            }
            result += edges.edge(edgeIndex)
        }
    }
    return result
}

private fun reconstructLexicographicallyLowest(
    edges: CandidateEdges,
    global: AssignmentObjective,
): List<SparseMonotoneAssignmentEdge> {
    val selected = ArrayList<SparseMonotoneAssignmentEdge>(global.count)
    var lastLeft = -1
    var lastRight = -1
    var remainingCount = global.count
    var remainingCost = global.cost
    var edgeIndex = 0
    while (remainingCount > 0) {
        var found = false
        while (edgeIndex < edges.size) {
            val eligible = edges.left[edgeIndex] > lastLeft && edges.right[edgeIndex] > lastRight
            if (eligible &&
                edges.suffixCount[edgeIndex] == remainingCount &&
                edges.suffixCost[edgeIndex] == remainingCost
            ) {
                selected += edges.edge(edgeIndex)
                lastLeft = edges.left[edgeIndex]
                lastRight = edges.right[edgeIndex]
                remainingCount--
                remainingCost = Math.subtractExact(remainingCost, edges.distance[edgeIndex].toLong())
                edgeIndex++
                found = true
                break
            }
            edgeIndex++
        }
        if (!found) sparseAssignmentFail("sparse assignment reconstruction drifted from its objective")
    }
    if (remainingCost != 0L || selected.size != global.count) {
        sparseAssignmentFail("sparse assignment reconstruction did not close its objective")
    }
    return selected
}

private fun checkedCostAdd(cost: Long, distance: Int): Long = try {
    Math.addExact(cost, distance.toLong())
} catch (failure: ArithmeticException) {
    throw SparseMonotoneAssignmentException("assignment distance cost overflowed", failure)
}

private fun AssignmentObjective.betterThan(other: AssignmentObjective): Boolean =
    count > other.count || count == other.count && cost < other.cost

private fun sparseAssignmentFail(message: String): Nothing = throw SparseMonotoneAssignmentException(message)
