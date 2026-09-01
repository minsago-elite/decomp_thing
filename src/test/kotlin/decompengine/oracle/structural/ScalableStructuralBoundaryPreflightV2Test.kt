package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import java.lang.reflect.Modifier
import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class ScalableStructuralBoundaryPreflightV2Test {
    @Test
    fun `cc1 sized raw model binds deterministically beyond the frozen v1 ceiling`() {
        val count = 50_228
        val modelBytes = canonicalModelBytes(count) { index -> index.toULong() * 64UL + 1UL }
        val projection = projection(
            scoreable = List(count) { index ->
                ScalableStructuralOracleFunctionV2(oracleId(index), index.toULong() * 64UL)
            },
            rangeEnd = count.toULong() * 64UL + 2UL,
            nearMissBytes = 1,
        )

        val first = ScalableStructuralBoundaryPreflightV2.bind(modelBytes, projection)
        val second = ScalableStructuralBoundaryPreflightV2.bind(modelBytes, projection)

        assertEquals(first.observedPreflightSha256, second.observedPreflightSha256)
        assertEquals(first.selectedMappingSha256, second.selectedMappingSha256)
        assertEquals(first.optimalCandidateSetSha256, second.optimalCandidateSetSha256)
        assertEquals(OracleArtifacts.sha256(modelBytes), first.recoveredProgramModelSha256)
        assertEquals(count, first.rawRecoveredFunctionCount)
        assertEquals(count, first.scoredRecoveredFunctionCount)
        assertEquals(count, first.oracleFunctionCount)
        assertEquals(0, first.exactMatchCount)
        assertEquals(count, first.nearMatchCount)
        assertEquals(0, first.falsePositiveCount)
        assertEquals(0, first.falseNegativeCount)
        assertEquals(0, first.ignoredExcludedRecoveryCount)
        assertEquals(count.toLong(), first.nearMatchDistanceBytes)
        assertEquals(count, first.candidateEdgeCount)
        assertEquals(count, first.optimalCandidateEdgeCount)
        assertFalse(first.hasAlternativeOptimalMatching)
        assertEquals(count, first.matches.size)
        assertEquals(
            ScalableStructuralBoundaryMatchV2(
                oracleId(0),
                0UL,
                recoveredId(0),
                1UL,
                1,
                ScalableStructuralBoundaryMatchKindV2.NEAR,
            ),
            first.matches.first(),
        )
        assertEquals(
            ScalableStructuralBoundaryMatchV2(
                oracleId(count - 1),
                (count - 1).toULong() * 64UL,
                recoveredId(count - 1),
                (count - 1).toULong() * 64UL + 1UL,
                1,
                ScalableStructuralBoundaryMatchKindV2.NEAR,
            ),
            first.matches.last(),
        )
        assertEquals("non-authoritative-observed-input-preflight-v2", first.authority)
        assertTrue(first.nameIndependent)
        assertFalse(first.adapterReplayVerified)
        assertFalse(first.productionVerified)
        assertFailsWith<UnsupportedOperationException> {
            (first.matches as MutableList<ScalableStructuralBoundaryMatchV2>).clear()
        }
    }

    @Test
    fun `mixed universes preserve exact first exclusions and global sparse assignment`() {
        val modelBytes = canonicalModelBytes(listOf(0x10UL, 0x21UL, 0x40UL, 0x80UL))
        val ordered = projection(
            scoreable = listOf(
                ScalableStructuralOracleFunctionV2("oracle-a", 0x10UL),
                ScalableStructuralOracleFunctionV2("oracle-b", 0x20UL),
                ScalableStructuralOracleFunctionV2("oracle-c", 0x30UL),
            ),
            exclusions = listOf(ScalableStructuralOracleExclusionV2("excluded", 0x40UL)),
            rangeEnd = 0x100UL,
            nearMissBytes = 1,
        )
        val reordered = ordered.copy(
            scoreableFunctions = ordered.scoreableFunctions.reversed(),
            emittedExclusions = ordered.emittedExclusions.reversed(),
        )

        val first = ScalableStructuralBoundaryPreflightV2.bind(modelBytes, ordered)
        val second = ScalableStructuralBoundaryPreflightV2.bind(modelBytes, reordered)
        val renamed = ScalableStructuralBoundaryPreflightV2.bind(
            modelBytes,
            ordered.copy(
                scoreableFunctions = ordered.scoreableFunctions.map { function ->
                    if (function.id == "oracle-c") function.copy(id = "oracle-c-renamed") else function
                },
            ),
        )
        val lowerPolicy = ScalableStructuralBoundaryPreflightV2.bind(
            modelBytes,
            ordered,
            ScalableStructuralBoundaryPreflightV2Limits(
                maximumModelDepth = 7,
                maximumModelNodes = 31_999_999,
                maximumModelTokens = 63_999_999,
                maximumCandidateEdges = 999_999,
            ),
        )

        assertEquals(first.observedPreflightSha256, second.observedPreflightSha256)
        assertEquals(first.projectionSha256, second.projectionSha256)
        assertNotEquals(first.projectionSha256, renamed.projectionSha256)
        assertNotEquals(first.observedPreflightSha256, renamed.observedPreflightSha256)
        assertEquals(first.selectedMappingSha256, lowerPolicy.selectedMappingSha256)
        assertNotEquals(first.policySha256, lowerPolicy.policySha256)
        assertNotEquals(first.observedPreflightSha256, lowerPolicy.observedPreflightSha256)
        assertEquals(4, first.rawRecoveredFunctionCount)
        assertEquals(3, first.scoredRecoveredFunctionCount)
        assertEquals(3, first.oracleFunctionCount)
        assertEquals(1, first.exactMatchCount)
        assertEquals(1, first.nearMatchCount)
        assertEquals(1, first.falsePositiveCount)
        assertEquals(1, first.falseNegativeCount)
        assertEquals(1, first.ignoredExcludedRecoveryCount)
        assertEquals(1L, first.nearMatchDistanceBytes)
        assertEquals(listOf("oracle-a", "oracle-b"), first.matches.map { it.oracleId })
        assertEquals(
            listOf(ScalableStructuralBoundaryMatchKindV2.EXACT, ScalableStructuralBoundaryMatchKindV2.NEAR),
            first.matches.map { it.kind },
        )
    }

    @Test
    fun `candidate edge cap admits the exact bound and rejects one edge beyond it`() {
        val count = 10
        val modelBytes = canonicalModelBytes(count) { index -> 10UL + index.toULong() }
        val projection = projection(
            scoreable = List(count) { index -> ScalableStructuralOracleFunctionV2(oracleId(index), index.toULong()) },
            rangeEnd = 20UL,
            nearMissBytes = 19,
        )
        val atLimit = ScalableStructuralBoundaryPreflightV2.bind(
            modelBytes,
            projection,
            ScalableStructuralBoundaryPreflightV2Limits(
                maximumCandidateEdges = 100,
                maximumOptimalCandidateEdges = 100,
            ),
        )
        assertEquals(100, atLimit.candidateEdgeCount)
        assertEquals(count, atLimit.nearMatchCount)

        val failure = assertFailsWith<ScalableStructuralBoundaryPreflightV2Exception> {
            ScalableStructuralBoundaryPreflightV2.bind(
                modelBytes,
                projection,
                ScalableStructuralBoundaryPreflightV2Limits(
                    maximumCandidateEdges = 99,
                    maximumOptimalCandidateEdges = 99,
                ),
            )
        }
        assertTrue(failure.causeChain().any { it.message.orEmpty().contains("candidate-edge count") })
    }

    @Test
    fun `projection snapshot is single pass and size drift fails closed`() {
        val canonical = listOf(
            ScalableStructuralOracleFunctionV2("oracle-a", 0x10UL),
            ScalableStructuralOracleFunctionV2("oracle-b", 0x20UL),
        )
        val hostile = listOf(
            ScalableStructuralOracleFunctionV2("oracle-a", 0x10UL),
            ScalableStructuralOracleFunctionV2("oracle-a", 0x10UL),
        )
        val switching = SequencedList(canonical, hostile)
        val binding = ScalableStructuralBoundaryPreflightV2.bind(
            canonicalModelBytes(listOf(0x10UL, 0x20UL)),
            projection(switching, rangeEnd = 0x30UL),
        )
        assertEquals(2, binding.exactMatchCount)
        assertEquals(1, switching.iteratorCalls)
        assertEquals(0, switching.randomAccessCalls)

        val overproducing = object : java.util.AbstractList<ScalableStructuralOracleFunctionV2>() {
            override val size: Int = 1
            override fun get(index: Int): ScalableStructuralOracleFunctionV2 = canonical.first()
            override fun iterator(): MutableIterator<ScalableStructuralOracleFunctionV2> =
                canonical.toMutableList().iterator()
        }
        val failure = assertFailsWith<ScalableStructuralBoundaryPreflightV2Exception> {
            ScalableStructuralBoundaryPreflightV2.bind(
                canonicalModelBytes(listOf(0x10UL)),
                projection(overproducing, rangeEnd = 0x30UL),
            )
        }
        assertTrue(failure.message.orEmpty().contains("changed while it was snapshotted"))
    }

    @Test
    fun `malformed projection raw model and lowered bounds reject through the closed failure type`() {
        val modelBytes = canonicalModelBytes(listOf(0x10UL, 0x20UL))
        val base = projection(
            listOf(
                ScalableStructuralOracleFunctionV2("oracle-a", 0x10UL),
                ScalableStructuralOracleFunctionV2("oracle-b", 0x20UL),
            ),
            rangeEnd = 0x30UL,
        )
        val malformed = listOf(
            base.copy(
                scoreableFunctions = listOf(
                    ScalableStructuralOracleFunctionV2("duplicate", 0x10UL),
                    ScalableStructuralOracleFunctionV2("duplicate", 0x20UL),
                ),
            ),
            base.copy(
                emittedExclusions = listOf(ScalableStructuralOracleExclusionV2("excluded", 0x10UL)),
            ),
            base.copy(
                executableRanges = listOf(
                    ScalableStructuralExecutableRangeV2(0UL, 0x20UL),
                    ScalableStructuralExecutableRangeV2(0x10UL, 0x30UL),
                ),
            ),
        )
        malformed.forEach { projection ->
            assertFailsWith<ScalableStructuralBoundaryPreflightV2Exception> {
                ScalableStructuralBoundaryPreflightV2.bind(modelBytes, projection)
            }
        }
        assertFailsWith<ScalableStructuralBoundaryPreflightV2Exception> {
            ScalableStructuralBoundaryPreflightV2.bind(modelBytes + '\n'.code.toByte(), base)
        }
        assertFailsWith<ScalableStructuralBoundaryPreflightV2Exception> {
            ScalableStructuralBoundaryPreflightV2.bind(
                modelBytes,
                base,
                ScalableStructuralBoundaryPreflightV2Limits(maximumFunctionRecords = 1),
            )
        }
    }

    @Test
    fun `historical v1 ceilings and frozen boundary bytes remain unchanged`() {
        val v1 = StructuralBoundaryReplayV1Limits()
        assertEquals(20_000, v1.maximumFunctionRecords)
        assertEquals(20_000_000, v1.maximumMatchingCells)
        assertFailsWith<IllegalArgumentException> {
            StructuralBoundaryReplayV1Limits(maximumFunctionRecords = 20_001)
        }
        val boundaryBytes = checkNotNull(
            javaClass.getResourceAsStream("/oracle/structural-v1/boundary-score.json"),
        ).use { it.readAllBytes() }
        assertEquals(FROZEN_V1_BOUNDARY_SHA256, OracleArtifacts.sha256(boundaryBytes))
        val boundaryText = boundaryBytes.toString(StandardCharsets.UTF_8)
        assertTrue(boundaryText.contains("\"maxFunctionRecords\": 20000"))
        assertTrue(boundaryText.contains("\"maxMatchingCells\": 20000000"))
    }

    @Test
    fun `observed binding has no public or synthetic JVM constructor`() {
        val constructors = ScalableStructuralBoundaryBindingV2::class.java.declaredConstructors
        assertEquals(1, constructors.size)
        assertTrue(Modifier.isPrivate(constructors.single().modifiers))
        assertFalse(constructors.single().isSynthetic)
    }

    @Test
    fun `maximum fragmented executable range set admits a record in its final range`() {
        val ranges = List(4_096) { index ->
            val start = index.toULong() * 2UL
            ScalableStructuralExecutableRangeV2(start, start + 1UL)
        }
        val finalRva = ranges.last().start
        val binding = ScalableStructuralBoundaryPreflightV2.bind(
            canonicalModelBytes(listOf(finalRva)),
            ScalableStructuralBoundaryProjectionV2(
                inputSha256 = INPUT_SHA256,
                modelImageBase = IMAGE_BASE,
                executableRanges = ranges,
                nearMissBytes = 1,
                scoreableFunctions = listOf(ScalableStructuralOracleFunctionV2("oracle-final", finalRva)),
            ),
            ScalableStructuralBoundaryPreflightV2Limits(maximumExecutableRanges = ranges.size),
        )
        assertEquals(1, binding.exactMatchCount)
    }

    @Test
    fun `image base and executable range endpoints never wrap unsigned addresses`() {
        val zeroBaseRva = ULong.MAX_VALUE - 1UL
        val zeroBase = ScalableStructuralBoundaryPreflightV2.bind(
            canonicalModelBytesAtBase(0UL, listOf(zeroBaseRva)),
            ScalableStructuralBoundaryProjectionV2(
                inputSha256 = INPUT_SHA256,
                modelImageBase = 0UL,
                executableRanges = listOf(
                    ScalableStructuralExecutableRangeV2(zeroBaseRva, ULong.MAX_VALUE),
                ),
                nearMissBytes = 1,
                scoreableFunctions = listOf(ScalableStructuralOracleFunctionV2("oracle-zero-base", zeroBaseRva)),
            ),
        )
        assertEquals(1, zeroBase.exactMatchCount)

        val highBase = ULong.MAX_VALUE - 10UL
        val highEndpoint = ScalableStructuralBoundaryPreflightV2.bind(
            canonicalModelBytesAtBase(highBase, listOf(10UL)),
            ScalableStructuralBoundaryProjectionV2(
                inputSha256 = INPUT_SHA256,
                modelImageBase = highBase,
                executableRanges = listOf(ScalableStructuralExecutableRangeV2(0UL, 11UL)),
                nearMissBytes = 1,
                scoreableFunctions = listOf(ScalableStructuralOracleFunctionV2("oracle-high-base", 10UL)),
            ),
        )
        assertEquals(ULong.MAX_VALUE, highEndpoint.matches.single().recoveredRva + highBase)

        val falseNegativeOnlyModel = canonicalModelBytesAtBase(highBase, emptyList())
        val wrappingProjection = ScalableStructuralBoundaryProjectionV2(
            inputSha256 = INPUT_SHA256,
            modelImageBase = highBase,
            executableRanges = listOf(ScalableStructuralExecutableRangeV2(0UL, 12UL)),
            nearMissBytes = 1,
            scoreableFunctions = listOf(ScalableStructuralOracleFunctionV2("oracle-false-negative", 0UL)),
        )
        val failure = assertFailsWith<ScalableStructuralBoundaryPreflightV2Exception> {
            ScalableStructuralBoundaryPreflightV2.bind(falseNegativeOnlyModel, wrappingProjection)
        }
        assertTrue(failure.message.orEmpty().contains("cannot be represented"))
    }

    private fun projection(
        scoreable: List<ScalableStructuralOracleFunctionV2>,
        exclusions: List<ScalableStructuralOracleExclusionV2> = emptyList(),
        rangeEnd: ULong,
        nearMissBytes: Int = 1,
    ) = ScalableStructuralBoundaryProjectionV2(
        inputSha256 = INPUT_SHA256,
        modelImageBase = IMAGE_BASE,
        executableRanges = listOf(ScalableStructuralExecutableRangeV2(0UL, rangeEnd)),
        nearMissBytes = nearMissBytes,
        scoreableFunctions = scoreable,
        emittedExclusions = exclusions,
    )

    private fun canonicalModelBytes(count: Int, rva: (Int) -> ULong): ByteArray =
        canonicalModelBytes(List(count, rva))

    private fun canonicalModelBytes(rvas: List<ULong>): ByteArray = RecoveredProgramModel(
        inputSha256 = INPUT_SHA256,
        functions = rvas.mapIndexed { index, rva ->
            RecoveredFunction(
                id = recoveredId(index),
                name = "recovered_$index",
                address = IMAGE_BASE + rva,
                prototype = "",
            )
        },
    ).toJson().toByteArray(StandardCharsets.UTF_8)

    private fun canonicalModelBytesAtBase(imageBase: ULong, rvas: List<ULong>): ByteArray = RecoveredProgramModel(
        inputSha256 = INPUT_SHA256,
        functions = rvas.mapIndexed { index, rva ->
            RecoveredFunction(
                id = recoveredId(index),
                name = "recovered_$index",
                address = imageBase + rva,
                prototype = "",
            )
        },
    ).toJson().toByteArray(StandardCharsets.UTF_8)

    private fun oracleId(index: Int): String = "oracle_${index.toString().padStart(6, '0')}"
    private fun recoveredId(index: Int): String = "recovered_${index.toString().padStart(6, '0')}"

    private companion object {
        val INPUT_SHA256 = "7".repeat(64)
        const val IMAGE_BASE = 0x400000UL
        const val FROZEN_V1_BOUNDARY_SHA256 = "b05d85d9f21e704c2581b84ded3ea5442eb4695ed75e74d25778e417a5a8d593"
    }
}

private class SequencedList<T>(
    private val first: List<T>,
    private val later: List<T>,
) : java.util.AbstractList<T>() {
    var iteratorCalls: Int = 0
        private set
    var randomAccessCalls: Int = 0
        private set

    override val size: Int
        get() = first.size

    override fun get(index: Int): T {
        randomAccessCalls++
        return first[index]
    }

    override fun iterator(): MutableIterator<T> {
        val selected = if (iteratorCalls++ == 0) first else later
        return selected.toMutableList().iterator()
    }
}

private fun Throwable.causeChain(): Sequence<Throwable> = generateSequence(this, Throwable::cause)
