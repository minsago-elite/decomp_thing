package decompengine.oracle.structural

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SparseMonotoneAssignmentTest {
    @Test
    fun `sparse solver exactly matches exhaustive global semantics`() {
        val sequences = (0 until (1 shl 5)).mapNotNull { mask ->
            (0 until 5).filter { bit -> mask and (1 shl bit) != 0 }
                .takeIf { it.size <= 4 }
                ?.map(Int::toULong)
        }
        var cases = 0
        sequences.forEach { left ->
            sequences.forEach { right ->
                for (bound in 0..4) {
                    val expected = bruteForce(left, right, bound)
                    val actual = SparseMonotoneAssignment.solve(left, right, bound)
                    assertEquals(expected.selected, actual.selectedEdges, "selected edges for $left / $right / $bound")
                    assertEquals(
                        expected.optimalCandidates,
                        actual.optimalCandidateEdges,
                        "optimal candidate edges for $left / $right / $bound",
                    )
                    assertEquals(expected.cardinality, actual.maximumCardinality)
                    assertEquals(expected.cost, actual.minimumTotalDistanceBytes)
                    assertEquals(expected.candidateCount, actual.candidateEdgeCount)
                    cases++
                }
            }
        }
        assertEquals(4_805, cases)
    }

    @Test
    fun `equal objective selects the lexicographically lowest edge sequence`() {
        val result = SparseMonotoneAssignment.solve(
            leftRvas = listOf(0UL, 2UL),
            rightRvas = listOf(1UL),
            maximumDistanceBytes = 1,
        )

        assertEquals(1, result.maximumCardinality)
        assertEquals(1L, result.minimumTotalDistanceBytes)
        assertEquals(
            listOf(SparseMonotoneAssignmentEdge(0, 0, 1)),
            result.selectedEdges,
        )
        assertEquals(
            listOf(
                SparseMonotoneAssignmentEdge(0, 0, 1),
                SparseMonotoneAssignmentEdge(1, 0, 1),
            ),
            result.optimalCandidateEdges,
        )
    }

    @Test
    fun `unsigned endpoint windows do not wrap`() {
        val result = SparseMonotoneAssignment.solve(
            leftRvas = listOf(0UL, ULong.MAX_VALUE),
            rightRvas = listOf(1UL, ULong.MAX_VALUE - 1UL),
            maximumDistanceBytes = 1,
        )

        assertEquals(2, result.maximumCardinality)
        assertEquals(2L, result.minimumTotalDistanceBytes)
        assertEquals(2, result.candidateEdgeCount)
    }

    @Test
    fun `cc1 scale remains sparse beyond every historical v1 function ceiling`() {
        val count = 50_228
        val left = List(count) { index -> index.toULong() * 64UL }
        val right = left.map { it + 1UL }

        val result = SparseMonotoneAssignment.solve(left, right, maximumDistanceBytes = 1)

        assertEquals(count, result.candidateEdgeCount)
        assertEquals(count, result.maximumCardinality)
        assertEquals(count.toLong(), result.minimumTotalDistanceBytes)
        assertEquals(count, result.selectedEdges.size)
        assertEquals(count, result.optimalCandidateEdges.size)
        assertEquals(SparseMonotoneAssignmentEdge(0, 0, 1), result.selectedEdges.first())
        assertEquals(
            SparseMonotoneAssignmentEdge(count - 1, count - 1, 1),
            result.selectedEdges.last(),
        )
    }

    @Test
    fun `record distance candidate and ambiguity limits fail closed`() {
        assertFailsWith<SparseMonotoneAssignmentException> {
            SparseMonotoneAssignment.solve(
                listOf(0UL, 1UL),
                listOf(0UL),
                0,
                SparseMonotoneAssignmentLimits(maximumLeftRecords = 1),
            )
        }
        assertFailsWith<SparseMonotoneAssignmentException> {
            SparseMonotoneAssignment.solve(
                listOf(0UL),
                listOf(0UL),
                2,
                SparseMonotoneAssignmentLimits(maximumDistanceBytes = 1),
            )
        }
        assertFailsWith<SparseMonotoneAssignmentException> {
            SparseMonotoneAssignment.solve(
                listOf(0UL, 1UL),
                listOf(0UL, 1UL),
                1,
                SparseMonotoneAssignmentLimits(maximumCandidateEdges = 3),
            )
        }
        assertFailsWith<SparseMonotoneAssignmentException> {
            SparseMonotoneAssignment.solve(
                listOf(0UL, 2UL),
                listOf(1UL),
                1,
                SparseMonotoneAssignmentLimits(maximumOptimalCandidateEdges = 1),
            )
        }
        listOf(
            listOf(1UL, 1UL),
            listOf(2UL, 1UL),
        ).forEach { invalid ->
            val failure = assertFailsWith<SparseMonotoneAssignmentException> {
                SparseMonotoneAssignment.solve(invalid, listOf(1UL), 1)
            }
            assertTrue(failure.message.orEmpty().contains("strictly increasing"))
        }
    }

    private fun bruteForce(left: List<ULong>, right: List<ULong>, bound: Int): BruteResult {
        val candidates = buildList {
            left.forEachIndexed { leftIndex, leftRva ->
                right.forEachIndexed { rightIndex, rightRva ->
                    val distance = if (leftRva >= rightRva) leftRva - rightRva else rightRva - leftRva
                    if (distance <= bound.toULong()) {
                        add(SparseMonotoneAssignmentEdge(leftIndex, rightIndex, distance.toInt()))
                    }
                }
            }
        }
        var bestCardinality = -1
        var bestCost = Long.MAX_VALUE
        val optimal = arrayListOf<List<SparseMonotoneAssignmentEdge>>()
        val chain = arrayListOf<SparseMonotoneAssignmentEdge>()

        fun visit(start: Int, lastLeft: Int, lastRight: Int, cost: Long) {
            when {
                chain.size > bestCardinality || chain.size == bestCardinality && cost < bestCost -> {
                    bestCardinality = chain.size
                    bestCost = cost
                    optimal.clear()
                    optimal += chain.toList()
                }
                chain.size == bestCardinality && cost == bestCost -> optimal += chain.toList()
            }
            for (index in start until candidates.size) {
                val edge = candidates[index]
                if (edge.leftIndex > lastLeft && edge.rightIndex > lastRight) {
                    chain += edge
                    visit(index + 1, edge.leftIndex, edge.rightIndex, cost + edge.distanceBytes)
                    chain.removeAt(chain.lastIndex)
                }
            }
        }
        visit(0, -1, -1, 0L)

        val selected = optimal.minWithOrNull(::compareChains).orEmpty()
        val inAnyOptimal = optimal.flatten().toSet()
        return BruteResult(
            selected = selected,
            optimalCandidates = candidates.filter(inAnyOptimal::contains),
            cardinality = bestCardinality,
            cost = bestCost,
            candidateCount = candidates.size,
        )
    }

    private fun compareChains(
        left: List<SparseMonotoneAssignmentEdge>,
        right: List<SparseMonotoneAssignmentEdge>,
    ): Int {
        left.indices.forEach { index ->
            val leftEdge = left[index]
            val rightEdge = right[index]
            leftEdge.leftIndex.compareTo(rightEdge.leftIndex).takeIf { it != 0 }?.let { return it }
            leftEdge.rightIndex.compareTo(rightEdge.rightIndex).takeIf { it != 0 }?.let { return it }
        }
        return left.size.compareTo(right.size)
    }

    private data class BruteResult(
        val selected: List<SparseMonotoneAssignmentEdge>,
        val optimalCandidates: List<SparseMonotoneAssignmentEdge>,
        val cardinality: Int,
        val cost: Long,
        val candidateCount: Int,
    )
}
