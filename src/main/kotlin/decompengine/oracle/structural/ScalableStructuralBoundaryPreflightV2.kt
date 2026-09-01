package decompengine.oracle.structural

import java.security.MessageDigest
import java.util.Collections

/** Explicit bounds for the non-authoritative, GCC-scale boundary preflight. */
internal data class ScalableStructuralBoundaryPreflightV2Limits(
    val maximumProgramModelBytes: Int = 512 * 1024 * 1024,
    val maximumFunctionRecords: Int = 131_072,
    val maximumModelGlobalsOrTypes: Int = 1_000_000,
    val maximumReferencesPerFunction: Int = 100_000,
    val maximumModelIdentifierCodePoints: Int = 4_096,
    val maximumModelPrototypeCodePoints: Int = 1_048_576,
    val maximumTextCodePoints: Int = 16 * 1024 * 1024,
    val maximumModelTotalStringBytes: Long = maximumProgramModelBytes.toLong(),
    val maximumModelNodes: Long = 32_000_000,
    val maximumModelTokens: Long = 64_000_000,
    val maximumModelDepth: Int = 8,
    val maximumExecutableRanges: Int = 256,
    val maximumOracleIdentifierCodePoints: Int = 4_096,
    val maximumOracleIdentifierUtf8Bytes: Int = 64 * 1024 * 1024,
    val maximumNearMissBytes: Int = 4_096,
    val maximumCandidateEdges: Int = 1_000_000,
    val maximumOptimalCandidateEdges: Int = 262_144,
) {
    init {
        require(maximumProgramModelBytes in 1..HARD_MAXIMUM_PROGRAM_MODEL_BYTES)
        require(maximumFunctionRecords in 1..HARD_MAXIMUM_FUNCTION_RECORDS)
        require(maximumModelGlobalsOrTypes in 0..HARD_MAXIMUM_MODEL_GLOBALS_OR_TYPES)
        require(maximumReferencesPerFunction in 0..HARD_MAXIMUM_REFERENCES_PER_FUNCTION)
        require(maximumModelIdentifierCodePoints in 1..HARD_MAXIMUM_MODEL_IDENTIFIER_CODE_POINTS)
        require(maximumModelPrototypeCodePoints in 1..HARD_MAXIMUM_MODEL_PROTOTYPE_CODE_POINTS)
        require(maximumTextCodePoints in 1..HARD_MAXIMUM_TEXT_CODE_POINTS)
        require(maximumModelTotalStringBytes in 1L..maximumProgramModelBytes.toLong())
        require(maximumModelNodes in 1L..HARD_MAXIMUM_MODEL_NODES)
        require(maximumModelTokens in 1L..HARD_MAXIMUM_MODEL_TOKENS)
        require(maximumModelDepth in 1..HARD_MAXIMUM_MODEL_DEPTH)
        require(maximumExecutableRanges in 1..HARD_MAXIMUM_EXECUTABLE_RANGES)
        require(maximumOracleIdentifierCodePoints in 1..HARD_MAXIMUM_ORACLE_IDENTIFIER_CODE_POINTS)
        require(maximumOracleIdentifierUtf8Bytes in 1..HARD_MAXIMUM_ORACLE_IDENTIFIER_UTF8_BYTES)
        require(maximumNearMissBytes in 1..HARD_MAXIMUM_NEAR_MISS_BYTES)
        require(maximumCandidateEdges in 1..HARD_MAXIMUM_CANDIDATE_EDGES)
        require(maximumOptimalCandidateEdges in 1..maximumCandidateEdges)
    }

    private companion object {
        const val HARD_MAXIMUM_PROGRAM_MODEL_BYTES = 512 * 1024 * 1024
        const val HARD_MAXIMUM_FUNCTION_RECORDS = 131_072
        const val HARD_MAXIMUM_MODEL_GLOBALS_OR_TYPES = 1_000_000
        const val HARD_MAXIMUM_REFERENCES_PER_FUNCTION = 100_000
        const val HARD_MAXIMUM_MODEL_IDENTIFIER_CODE_POINTS = 4_096
        const val HARD_MAXIMUM_MODEL_PROTOTYPE_CODE_POINTS = 1_048_576
        const val HARD_MAXIMUM_TEXT_CODE_POINTS = 16 * 1024 * 1024
        const val HARD_MAXIMUM_MODEL_NODES = 64_000_000L
        const val HARD_MAXIMUM_MODEL_TOKENS = 128_000_000L
        const val HARD_MAXIMUM_MODEL_DEPTH = 32
        const val HARD_MAXIMUM_EXECUTABLE_RANGES = 4_096
        const val HARD_MAXIMUM_ORACLE_IDENTIFIER_CODE_POINTS = 4_096
        const val HARD_MAXIMUM_ORACLE_IDENTIFIER_UTF8_BYTES = 128 * 1024 * 1024
        const val HARD_MAXIMUM_NEAR_MISS_BYTES = 4_096
        const val HARD_MAXIMUM_CANDIDATE_EDGES = 5_000_000
    }
}

internal data class ScalableStructuralExecutableRangeV2(
    val start: ULong,
    val endExclusive: ULong,
)

internal data class ScalableStructuralOracleFunctionV2(
    val id: String,
    val rva: ULong,
)

/** An emitted compiler-generated exclusion; non-emitted/inlined records do not partition recovered starts. */
internal data class ScalableStructuralOracleExclusionV2(
    val id: String,
    val rva: ULong,
)

/**
 * Caller-supplied projection used only for deterministic preflight.
 *
 * It is not an authenticated oracle artifact and therefore cannot itself authorize scoring.
 */
internal data class ScalableStructuralBoundaryProjectionV2(
    val inputSha256: String,
    val modelImageBase: ULong,
    val executableRanges: List<ScalableStructuralExecutableRangeV2>,
    val nearMissBytes: Int,
    val scoreableFunctions: List<ScalableStructuralOracleFunctionV2>,
    val emittedExclusions: List<ScalableStructuralOracleExclusionV2> = emptyList(),
)

internal enum class ScalableStructuralBoundaryMatchKindV2(val wireName: String) {
    EXACT("exact"),
    NEAR("near"),
}

internal data class ScalableStructuralBoundaryMatchV2(
    val oracleId: String,
    val oracleRva: ULong,
    val recoveredId: String,
    val recoveredRva: ULong,
    val distanceBytes: Int,
    val kind: ScalableStructuralBoundaryMatchKindV2,
)

private data class ScalableStructuralBoundaryBindingStateV2(
    val observedPreflightSha256: String,
    val policySha256: String,
    val projectionSha256: String,
    val recoveredProgramModelSha256: String,
    val oracleUniverseSha256: String,
    val scoredRecoveredUniverseSha256: String,
    val selectedMappingSha256: String,
    val optimalCandidateSetSha256: String,
    val rawRecoveredFunctionCount: Int,
    val scoredRecoveredFunctionCount: Int,
    val oracleFunctionCount: Int,
    val exactMatchCount: Int,
    val nearMatchCount: Int,
    val falsePositiveCount: Int,
    val falseNegativeCount: Int,
    val ignoredExcludedRecoveryCount: Int,
    val nearMatchDistanceBytes: Long,
    val candidateEdgeCount: Int,
    val optimalCandidateEdgeCount: Int,
    val hasAlternativeOptimalMatching: Boolean,
    val matches: List<ScalableStructuralBoundaryMatchV2>,
)

/**
 * Immutable evidence about the supplied bytes and projection only.
 *
 * The fixed negative authority fields are intentional: this binding does not authenticate an
 * exporter, adapter execution, filesystem snapshot, resource receipt, or oracle provenance.
 */
internal class ScalableStructuralBoundaryBindingV2 private constructor(
    state: ScalableStructuralBoundaryBindingStateV2,
) {
    val observedPreflightSha256: String = state.observedPreflightSha256
    val policySha256: String = state.policySha256
    val projectionSha256: String = state.projectionSha256
    val recoveredProgramModelSha256: String = state.recoveredProgramModelSha256
    val oracleUniverseSha256: String = state.oracleUniverseSha256
    val scoredRecoveredUniverseSha256: String = state.scoredRecoveredUniverseSha256
    val selectedMappingSha256: String = state.selectedMappingSha256
    val optimalCandidateSetSha256: String = state.optimalCandidateSetSha256
    val rawRecoveredFunctionCount: Int = state.rawRecoveredFunctionCount
    val scoredRecoveredFunctionCount: Int = state.scoredRecoveredFunctionCount
    val oracleFunctionCount: Int = state.oracleFunctionCount
    val exactMatchCount: Int = state.exactMatchCount
    val nearMatchCount: Int = state.nearMatchCount
    val falsePositiveCount: Int = state.falsePositiveCount
    val falseNegativeCount: Int = state.falseNegativeCount
    val ignoredExcludedRecoveryCount: Int = state.ignoredExcludedRecoveryCount
    val nearMatchDistanceBytes: Long = state.nearMatchDistanceBytes
    val candidateEdgeCount: Int = state.candidateEdgeCount
    val optimalCandidateEdgeCount: Int = state.optimalCandidateEdgeCount
    val hasAlternativeOptimalMatching: Boolean = state.hasAlternativeOptimalMatching
    val authority: String = AUTHORITY
    val nameIndependent: Boolean = true
    val adapterReplayVerified: Boolean = false
    val productionVerified: Boolean = false
    val matches: List<ScalableStructuralBoundaryMatchV2> = Collections.unmodifiableList(ArrayList(state.matches))

    internal companion object {
        const val AUTHORITY = "non-authoritative-observed-input-preflight-v2"
    }
}

internal class ScalableStructuralBoundaryPreflightV2Exception(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Computes an exact-first, name-independent boundary assignment at compiler-engine scale.
 *
 * Unlike [StructuralBoundaryReplayV1], this path has no historical 20,000-record or Cartesian-cell
 * policy. It reads one exact canonical raw-model snapshot under the existing 131,072-function hard
 * ceiling and admits sparse work by candidate-edge count. It deliberately returns only a negative-
 * authority binding; the production adapter registry remains the sole future authority seam.
 */
internal object ScalableStructuralBoundaryPreflightV2 {
    /*
     * Directly invoking a Kotlin private constructor outside its class can create a public
     * synthetic JVM bridge. Resolve the genuinely private constructor instead so caller-supplied
     * digests and counts can never manufacture an observed binding.
     */
    private val bindingConstructor = ScalableStructuralBoundaryBindingV2::class.java.getDeclaredConstructor(
        ScalableStructuralBoundaryBindingStateV2::class.java,
    ).apply {
        if (!trySetAccessible()) scalePreflightFail("scalable boundary binding constructor is not privately accessible")
    }

    fun bind(
        recoveredProgramModelBytes: ByteArray,
        projection: ScalableStructuralBoundaryProjectionV2,
        limits: ScalableStructuralBoundaryPreflightV2Limits = ScalableStructuralBoundaryPreflightV2Limits(),
    ): ScalableStructuralBoundaryBindingV2 = try {
        bindChecked(recoveredProgramModelBytes, projection, limits)
    } catch (failure: ScalableStructuralBoundaryPreflightV2Exception) {
        throw failure
    } catch (failure: StructuralRecoveryV1Exception) {
        throw ScalableStructuralBoundaryPreflightV2Exception(
            "scalable boundary preflight rejected the canonical program model",
            failure,
        )
    } catch (failure: SparseMonotoneAssignmentException) {
        throw ScalableStructuralBoundaryPreflightV2Exception(
            "scalable boundary preflight rejected the sparse assignment",
            failure,
        )
    } catch (failure: RuntimeException) {
        throw ScalableStructuralBoundaryPreflightV2Exception(
            "scalable boundary preflight failed during bounded validation",
            failure,
        )
    } catch (failure: OutOfMemoryError) {
        throw ScalableStructuralBoundaryPreflightV2Exception(
            "not enough memory for the bounded scalable boundary preflight",
            failure,
        )
    }

    private fun bindChecked(
        recoveredProgramModelBytes: ByteArray,
        projection: ScalableStructuralBoundaryProjectionV2,
        limits: ScalableStructuralBoundaryPreflightV2Limits,
    ): ScalableStructuralBoundaryBindingV2 {
        if (!StructuralRecoveryV1Contract.SHA256.matches(projection.inputSha256)) {
            scalePreflightFail("boundary projection inputSha256 is not a lowercase SHA-256 digest")
        }
        if (projection.nearMissBytes !in 1..limits.maximumNearMissBytes) {
            scalePreflightFail("boundary projection near-miss distance exceeds its configured limit")
        }

        val ranges = snapshotList(
            projection.executableRanges,
            limits.maximumExecutableRanges,
            "executable-range projection",
        ) { value, _ -> RangeSnapshot(value.start, value.endExclusive) }
            .sortedBy(RangeSnapshot::start)
        validateRanges(ranges, projection.modelImageBase)

        val identifierBudget = IdentifierBudget(limits)
        val oracle = snapshotList(
            projection.scoreableFunctions,
            limits.maximumFunctionRecords,
            "scoreable-function projection",
        ) { value, index ->
            identifierBudget.charge(value.id, "scoreable function $index ID")
            OracleFunctionSnapshot(value.id, value.rva)
        }.sortedWith(ORACLE_FUNCTION_ORDER)
        if (oracle.isEmpty()) scalePreflightFail("boundary projection must contain a scoreable function")

        val remainingCapacity = limits.maximumFunctionRecords - oracle.size
        val exclusions = snapshotList(
            projection.emittedExclusions,
            remainingCapacity,
            "emitted-exclusion projection",
        ) { value, index ->
            identifierBudget.charge(value.id, "emitted exclusion $index ID")
            OracleExclusionSnapshot(value.id, value.rva)
        }.sortedWith(ORACLE_EXCLUSION_ORDER)
        validateOracleProjection(oracle, exclusions, ranges)

        val modelLimits = effectiveModelLimits(limits)
        val modelSnapshot = CanonicalProgramModelStreaming.readCanonical(recoveredProgramModelBytes, modelLimits)
        if (modelSnapshot.model.inputSha256 != projection.inputSha256) {
            scalePreflightFail("program model input SHA-256 does not match the boundary projection")
        }
        val recovered = normalizeRecovered(
            modelSnapshot.model.functions.map { FunctionSnapshot(it.id, it.address) },
            projection.modelImageBase,
            ranges,
        )

        val exclusionByRva = exclusions.associateBy(OracleExclusionSnapshot::rva)
        val ignored = ArrayList<FunctionSnapshot>()
        val scoredRecovered = ArrayList<FunctionSnapshot>(recovered.size)
        recovered.forEach { function ->
            if (function.rva in exclusionByRva) ignored += function else scoredRecovered += function
        }

        val oracleByRva = oracle.associateBy(OracleFunctionSnapshot::rva)
        val exact = ArrayList<ScalableStructuralBoundaryMatchV2>(minOf(oracle.size, scoredRecovered.size))
        val exactOracleIds = HashSet<String>()
        val exactRecoveredIds = HashSet<String>()
        scoredRecovered.forEach { recoveredFunction ->
            oracleByRva[recoveredFunction.rva]?.let { oracleFunction ->
                exact += match(oracleFunction, recoveredFunction, ScalableStructuralBoundaryMatchKindV2.EXACT)
                exactOracleIds += oracleFunction.id
                exactRecoveredIds += recoveredFunction.id
            }
        }
        val remainingOracle = oracle.filterNot { it.id in exactOracleIds }
        val remainingRecovered = scoredRecovered.filterNot { it.id in exactRecoveredIds }

        val sparse = SparseMonotoneAssignment.solve(
            leftRvas = remainingOracle.map(OracleFunctionSnapshot::rva),
            rightRvas = remainingRecovered.map(FunctionSnapshot::rva),
            maximumDistanceBytes = projection.nearMissBytes,
            limits = SparseMonotoneAssignmentLimits(
                maximumLeftRecords = limits.maximumFunctionRecords,
                maximumRightRecords = limits.maximumFunctionRecords,
                maximumDistanceBytes = limits.maximumNearMissBytes,
                maximumCandidateEdges = limits.maximumCandidateEdges,
                maximumOptimalCandidateEdges = limits.maximumOptimalCandidateEdges,
            ),
        )
        val near = sparse.selectedEdges.map { edge ->
            match(
                remainingOracle[edge.leftIndex],
                remainingRecovered[edge.rightIndex],
                ScalableStructuralBoundaryMatchKindV2.NEAR,
            )
        }
        val selectedNearEdges = sparse.selectedEdges.mapTo(HashSet()) { it.leftIndex to it.rightIndex }
        val hasAlternatives = sparse.optimalCandidateEdges.any { it.leftIndex to it.rightIndex !in selectedNearEdges }
        val matches = (exact + near).sortedWith(MATCH_ORDER)
        val falseNegatives = Math.subtractExact(remainingOracle.size, near.size)
        val falsePositives = Math.subtractExact(remainingRecovered.size, near.size)
        if (matches.size + falseNegatives != oracle.size ||
            matches.size + falsePositives != scoredRecovered.size ||
            scoredRecovered.size + ignored.size != recovered.size
        ) scalePreflightFail("scalable boundary preflight did not partition its universes")

        val policySha256 = policySha256(limits, modelLimits, projection.nearMissBytes)
        val projectionSha256 = projectionSha256(
            projection.inputSha256,
            projection.modelImageBase,
            ranges,
            oracle,
            exclusions,
            projection.nearMissBytes,
        )
        val oracleUniverseSha256 = oracleUniverseSha256(oracle)
        val recoveredUniverseSha256 = recoveredUniverseSha256(scoredRecovered)
        val selectedMappingSha256 = mappingSha256(matches)
        val optimalCandidateSetSha256 = optimalCandidatesSha256(
            sparse.optimalCandidateEdges,
            remainingOracle,
            remainingRecovered,
        )
        val observedPreflightSha256 = observedPreflightSha256(
            policySha256 = policySha256,
            projectionSha256 = projectionSha256,
            modelSha256 = modelSnapshot.sha256,
            oracleUniverseSha256 = oracleUniverseSha256,
            recoveredUniverseSha256 = recoveredUniverseSha256,
            selectedMappingSha256 = selectedMappingSha256,
            optimalCandidateSetSha256 = optimalCandidateSetSha256,
            rawRecovered = recovered.size,
            scoredRecovered = scoredRecovered.size,
            oracleFunctions = oracle.size,
            exact = exact.size,
            near = near.size,
            falsePositives = falsePositives,
            falseNegatives = falseNegatives,
            ignored = ignored.size,
            nearDistance = sparse.minimumTotalDistanceBytes,
            candidateEdges = sparse.candidateEdgeCount,
            optimalCandidateEdges = sparse.optimalCandidateEdges.size,
            hasAlternatives = hasAlternatives,
        )
        return newBinding(ScalableStructuralBoundaryBindingStateV2(
            observedPreflightSha256 = observedPreflightSha256,
            policySha256 = policySha256,
            projectionSha256 = projectionSha256,
            recoveredProgramModelSha256 = modelSnapshot.sha256,
            oracleUniverseSha256 = oracleUniverseSha256,
            scoredRecoveredUniverseSha256 = recoveredUniverseSha256,
            selectedMappingSha256 = selectedMappingSha256,
            optimalCandidateSetSha256 = optimalCandidateSetSha256,
            rawRecoveredFunctionCount = recovered.size,
            scoredRecoveredFunctionCount = scoredRecovered.size,
            oracleFunctionCount = oracle.size,
            exactMatchCount = exact.size,
            nearMatchCount = near.size,
            falsePositiveCount = falsePositives,
            falseNegativeCount = falseNegatives,
            ignoredExcludedRecoveryCount = ignored.size,
            nearMatchDistanceBytes = sparse.minimumTotalDistanceBytes,
            candidateEdgeCount = sparse.candidateEdgeCount,
            optimalCandidateEdgeCount = sparse.optimalCandidateEdges.size,
            hasAlternativeOptimalMatching = hasAlternatives,
            matches = matches,
        ))
    }

    private fun newBinding(state: ScalableStructuralBoundaryBindingStateV2): ScalableStructuralBoundaryBindingV2 = try {
        bindingConstructor.newInstance(state)
    } catch (failure: ReflectiveOperationException) {
        throw ScalableStructuralBoundaryPreflightV2Exception(
            "cannot create the privately derived scalable boundary binding",
            failure,
        )
    }
}

private data class RangeSnapshot(val start: ULong, val endExclusive: ULong)
private data class OracleFunctionSnapshot(val id: String, val rva: ULong)
private data class OracleExclusionSnapshot(val id: String, val rva: ULong)
private data class FunctionSnapshot(val id: String, val rva: ULong)

private val ORACLE_FUNCTION_ORDER = Comparator<OracleFunctionSnapshot> { left, right ->
    left.rva.compareTo(right.rva).takeIf { it != 0 } ?: compareCodePoints(left.id, right.id)
}
private val ORACLE_EXCLUSION_ORDER = Comparator<OracleExclusionSnapshot> { left, right ->
    left.rva.compareTo(right.rva).takeIf { it != 0 } ?: compareCodePoints(left.id, right.id)
}
private val MATCH_ORDER = Comparator<ScalableStructuralBoundaryMatchV2> { left, right ->
    left.oracleRva.compareTo(right.oracleRva).takeIf { it != 0 }
        ?: compareCodePoints(left.oracleId, right.oracleId)
}

private fun validateRanges(ranges: List<RangeSnapshot>, modelImageBase: ULong) {
    if (ranges.isEmpty()) scalePreflightFail("boundary projection must contain an executable range")
    var previousEnd: ULong? = null
    ranges.forEach { range ->
        if (range.start >= range.endExclusive) scalePreflightFail("executable ranges must be non-empty")
        if (range.endExclusive - 1UL > ULong.MAX_VALUE - modelImageBase) {
            scalePreflightFail("executable range cannot be represented above the selected model image base")
        }
        if (previousEnd != null && range.start < previousEnd) {
            scalePreflightFail("executable ranges must not overlap")
        }
        previousEnd = range.endExclusive
    }
}

private fun validateOracleProjection(
    oracle: List<OracleFunctionSnapshot>,
    exclusions: List<OracleExclusionSnapshot>,
    ranges: List<RangeSnapshot>,
) {
    val ids = HashSet<String>()
    val rvas = HashSet<ULong>()
    oracle.forEach { function ->
        if (!ids.add(function.id)) scalePreflightFail("boundary projection contains a duplicate oracle ID")
        if (!rvas.add(function.rva)) scalePreflightFail("boundary projection contains a duplicate scoreable RVA")
        requireInRanges(function.rva, ranges, "scoreable oracle RVA")
    }
    exclusions.forEach { exclusion ->
        if (!ids.add(exclusion.id)) scalePreflightFail("scoreable and excluded functions share an oracle ID")
        if (!rvas.add(exclusion.rva)) scalePreflightFail("scoreable and excluded functions share an emitted RVA")
        requireInRanges(exclusion.rva, ranges, "excluded oracle RVA")
    }
}

private fun normalizeRecovered(
    functions: List<FunctionSnapshot>,
    imageBase: ULong,
    ranges: List<RangeSnapshot>,
): List<FunctionSnapshot> {
    val rvas = HashSet<ULong>()
    return functions.mapIndexed { index, function ->
        if (function.rva < imageBase) {
            scalePreflightFail("program model function $index is below the selected image base")
        }
        val rva = function.rva - imageBase
        requireInRanges(rva, ranges, "recovered function RVA")
        if (!rvas.add(rva)) scalePreflightFail("multiple recovered functions normalize to the same RVA")
        FunctionSnapshot(function.id, rva)
    }
}

private fun requireInRanges(rva: ULong, ranges: List<RangeSnapshot>, label: String) {
    var low = 0
    var high = ranges.size - 1
    while (low <= high) {
        val middle = low + (high - low) / 2
        val range = ranges[middle]
        when {
            rva < range.start -> high = middle - 1
            rva >= range.endExclusive -> low = middle + 1
            else -> return
        }
    }
    scalePreflightFail("$label is outside executable ranges")
}

private fun match(
    oracle: OracleFunctionSnapshot,
    recovered: FunctionSnapshot,
    kind: ScalableStructuralBoundaryMatchKindV2,
): ScalableStructuralBoundaryMatchV2 {
    val distance = if (oracle.rva >= recovered.rva) oracle.rva - recovered.rva else recovered.rva - oracle.rva
    if (distance > Int.MAX_VALUE.toULong()) scalePreflightFail("boundary match distance exceeds the integer range")
    return ScalableStructuralBoundaryMatchV2(
        oracle.id,
        oracle.rva,
        recovered.id,
        recovered.rva,
        Math.toIntExact(distance.toLong()),
        kind,
    )
}

private class IdentifierBudget(private val limits: ScalableStructuralBoundaryPreflightV2Limits) {
    private var bytes = 0L

    fun charge(value: String, label: String) {
        var index = 0
        var codePoints = 0
        var utf8Bytes = 0L
        while (index < value.length) {
            val first = value[index]
            val codePoint = when {
                Character.isHighSurrogate(first) -> {
                    if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                        scalePreflightFail("$label contains an unpaired surrogate")
                    }
                    Character.toCodePoint(first, value[++index])
                }
                Character.isLowSurrogate(first) -> scalePreflightFail("$label contains an unpaired surrogate")
                else -> first.code
            }
            codePoints++
            utf8Bytes = Math.addExact(
                utf8Bytes,
                when {
                    codePoint <= 0x7f -> 1L
                    codePoint <= 0x7ff -> 2L
                    codePoint <= 0xffff -> 3L
                    else -> 4L
                },
            )
            index++
        }
        if (codePoints !in 1..limits.maximumOracleIdentifierCodePoints) {
            scalePreflightFail("$label is empty or exceeds its code-point limit")
        }
        bytes = Math.addExact(bytes, utf8Bytes)
        if (bytes > limits.maximumOracleIdentifierUtf8Bytes.toLong()) {
            scalePreflightFail("boundary projection identifiers exceed their aggregate UTF-8 byte limit")
        }
    }
}

private fun <T, R> snapshotList(
    values: List<T>,
    maximumRecords: Int,
    label: String,
    transform: (T, Int) -> R,
): List<R> {
    val observedSize = try {
        values.size
    } catch (failure: RuntimeException) {
        throw ScalableStructuralBoundaryPreflightV2Exception("$label size could not be observed", failure)
    }
    if (observedSize !in 0..maximumRecords) scalePreflightFail("$label exceeds its record limit")
    val result = ArrayList<R>(observedSize)
    try {
        val iterator = values.iterator()
        while (iterator.hasNext()) {
            if (result.size >= observedSize) scalePreflightFail("$label changed while it was snapshotted")
            result += transform(iterator.next(), result.size)
        }
        if (result.size != observedSize || values.size != observedSize) {
            scalePreflightFail("$label changed while it was snapshotted")
        }
    } catch (failure: ScalableStructuralBoundaryPreflightV2Exception) {
        throw failure
    } catch (failure: RuntimeException) {
        throw ScalableStructuralBoundaryPreflightV2Exception("$label could not be snapshotted", failure)
    }
    return result
}

private fun effectiveModelLimits(
    limits: ScalableStructuralBoundaryPreflightV2Limits,
) = CanonicalProgramModelStreamingLimits(
    maximumInputBytes = limits.maximumProgramModelBytes,
    maximumFunctions = limits.maximumFunctionRecords,
    maximumGlobals = limits.maximumModelGlobalsOrTypes,
    maximumTypes = limits.maximumModelGlobalsOrTypes,
    maximumReferencesPerFunction = limits.maximumReferencesPerFunction,
    maximumIdentifierCodePoints = limits.maximumModelIdentifierCodePoints,
    maximumPrototypeCodePoints = limits.maximumModelPrototypeCodePoints,
    maximumTextCodePoints = limits.maximumTextCodePoints,
    maximumTotalStringBytes = limits.maximumModelTotalStringBytes,
    maximumNodes = limits.maximumModelNodes,
    maximumTokens = limits.maximumModelTokens,
    maximumDepth = limits.maximumModelDepth,
)

private fun policySha256(
    limits: ScalableStructuralBoundaryPreflightV2Limits,
    model: CanonicalProgramModelStreamingLimits,
    nearMissBytes: Int,
): String = Commitment("decompengine-scalable-structural-boundary-policy-v2").apply {
    integer("modelMaximumInputBytes", model.maximumInputBytes)
    integer("modelMaximumFunctions", model.maximumFunctions)
    integer("modelMaximumGlobals", model.maximumGlobals)
    integer("modelMaximumTypes", model.maximumTypes)
    integer("modelMaximumReferencesPerFunction", model.maximumReferencesPerFunction)
    integer("modelMaximumIdentifierCodePoints", model.maximumIdentifierCodePoints)
    integer("modelMaximumPrototypeCodePoints", model.maximumPrototypeCodePoints)
    integer("modelMaximumTextCodePoints", model.maximumTextCodePoints)
    long("modelMaximumTotalStringBytes", model.maximumTotalStringBytes)
    long("modelMaximumNodes", model.maximumNodes)
    long("modelMaximumTokens", model.maximumTokens)
    integer("modelMaximumDepth", model.maximumDepth)
    integer("modelMaximumDecodedStringCharacters", model.maximumDecodedStringCharacters)
    integer("maximumExecutableRanges", limits.maximumExecutableRanges)
    integer("maximumOracleIdentifierCodePoints", limits.maximumOracleIdentifierCodePoints)
    integer("maximumOracleIdentifierUtf8Bytes", limits.maximumOracleIdentifierUtf8Bytes)
    integer("maximumNearMissBytes", limits.maximumNearMissBytes)
    integer("maximumCandidateEdges", limits.maximumCandidateEdges)
    integer("maximumOptimalCandidateEdges", limits.maximumOptimalCandidateEdges)
    integer("selectedNearMissBytes", nearMissBytes)
}.finish()

private fun projectionSha256(
    inputSha256: String,
    modelImageBase: ULong,
    ranges: List<RangeSnapshot>,
    oracle: List<OracleFunctionSnapshot>,
    exclusions: List<OracleExclusionSnapshot>,
    nearMissBytes: Int,
): String = Commitment("decompengine-scalable-structural-boundary-projection-v2").apply {
    text("inputSha256", inputSha256)
    unsigned("modelImageBase", modelImageBase)
    integer("nearMissBytes", nearMissBytes)
    integer("executableRangeCount", ranges.size)
    ranges.forEach { range ->
        unsigned("rangeStart", range.start)
        unsigned("rangeEndExclusive", range.endExclusive)
    }
    integer("scoreableFunctionCount", oracle.size)
    oracle.forEach { function ->
        text("oracleId", function.id)
        unsigned("oracleRva", function.rva)
    }
    integer("emittedExclusionCount", exclusions.size)
    exclusions.forEach { exclusion ->
        text("exclusionId", exclusion.id)
        unsigned("exclusionRva", exclusion.rva)
    }
}.finish()

private fun oracleUniverseSha256(oracle: List<OracleFunctionSnapshot>): String =
    Commitment("decompengine-scalable-structural-boundary-oracle-universe-v2").apply {
        integer("count", oracle.size)
        oracle.forEach { function ->
            text("id", function.id)
            unsigned("rva", function.rva)
        }
    }.finish()

private fun recoveredUniverseSha256(recovered: List<FunctionSnapshot>): String =
    Commitment("decompengine-scalable-structural-boundary-recovered-universe-v2").apply {
        integer("count", recovered.size)
        recovered.forEach { function ->
            text("id", function.id)
            unsigned("rva", function.rva)
        }
    }.finish()

private fun mappingSha256(matches: List<ScalableStructuralBoundaryMatchV2>): String =
    Commitment("decompengine-scalable-structural-boundary-selected-mapping-v2").apply {
        integer("count", matches.size)
        matches.forEach { match ->
            text("kind", match.kind.wireName)
            text("oracleId", match.oracleId)
            unsigned("oracleRva", match.oracleRva)
            text("recoveredId", match.recoveredId)
            unsigned("recoveredRva", match.recoveredRva)
            integer("distanceBytes", match.distanceBytes)
        }
    }.finish()

private fun optimalCandidatesSha256(
    edges: List<SparseMonotoneAssignmentEdge>,
    oracle: List<OracleFunctionSnapshot>,
    recovered: List<FunctionSnapshot>,
): String = Commitment("decompengine-scalable-structural-boundary-optimal-candidates-v2").apply {
    integer("count", edges.size)
    edges.forEach { edge ->
        val oracleFunction = oracle[edge.leftIndex]
        val recoveredFunction = recovered[edge.rightIndex]
        text("oracleId", oracleFunction.id)
        unsigned("oracleRva", oracleFunction.rva)
        text("recoveredId", recoveredFunction.id)
        unsigned("recoveredRva", recoveredFunction.rva)
        integer("distanceBytes", edge.distanceBytes)
    }
}.finish()

@Suppress("LongParameterList")
private fun observedPreflightSha256(
    policySha256: String,
    projectionSha256: String,
    modelSha256: String,
    oracleUniverseSha256: String,
    recoveredUniverseSha256: String,
    selectedMappingSha256: String,
    optimalCandidateSetSha256: String,
    rawRecovered: Int,
    scoredRecovered: Int,
    oracleFunctions: Int,
    exact: Int,
    near: Int,
    falsePositives: Int,
    falseNegatives: Int,
    ignored: Int,
    nearDistance: Long,
    candidateEdges: Int,
    optimalCandidateEdges: Int,
    hasAlternatives: Boolean,
): String = Commitment("decompengine-scalable-structural-boundary-preflight-v2").apply {
    text("authority", ScalableStructuralBoundaryBindingV2.AUTHORITY)
    text("policySha256", policySha256)
    text("projectionSha256", projectionSha256)
    text("modelSha256", modelSha256)
    text("oracleUniverseSha256", oracleUniverseSha256)
    text("recoveredUniverseSha256", recoveredUniverseSha256)
    text("selectedMappingSha256", selectedMappingSha256)
    text("optimalCandidateSetSha256", optimalCandidateSetSha256)
    integer("rawRecovered", rawRecovered)
    integer("scoredRecovered", scoredRecovered)
    integer("oracleFunctions", oracleFunctions)
    integer("exact", exact)
    integer("near", near)
    integer("falsePositives", falsePositives)
    integer("falseNegatives", falseNegatives)
    integer("ignored", ignored)
    long("nearDistance", nearDistance)
    integer("candidateEdges", candidateEdges)
    integer("optimalCandidateEdges", optimalCandidateEdges)
    bool("hasAlternatives", hasAlternatives)
    bool("nameIndependent", true)
    bool("adapterReplayVerified", false)
    bool("productionVerified", false)
}.finish()

/** Small typed binary framing avoids buffering a second large JSON representation for commitments. */
private class Commitment(domain: String) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private val scratch = ByteArray(8)

    init {
        text("domain", domain)
    }

    fun text(label: String, value: String) {
        field(1, label)
        val bytes = value.toByteArray(Charsets.UTF_8)
        writeInt(bytes.size)
        digest.update(bytes)
    }

    fun integer(label: String, value: Int) {
        field(2, label)
        writeInt(value)
    }

    fun long(label: String, value: Long) {
        field(3, label)
        writeLong(value)
    }

    fun unsigned(label: String, value: ULong) {
        field(4, label)
        writeLong(value.toLong())
    }

    fun bool(label: String, value: Boolean) {
        field(5, label)
        digest.update(if (value) 1 else 0)
    }

    fun finish(): String = digest.digest().toLowerHex()

    private fun field(type: Int, label: String) {
        digest.update(type.toByte())
        val bytes = label.toByteArray(Charsets.US_ASCII)
        writeInt(bytes.size)
        digest.update(bytes)
    }

    private fun writeInt(value: Int) {
        scratch[0] = (value ushr 24).toByte()
        scratch[1] = (value ushr 16).toByte()
        scratch[2] = (value ushr 8).toByte()
        scratch[3] = value.toByte()
        digest.update(scratch, 0, 4)
    }

    private fun writeLong(value: Long) {
        for (index in 0 until 8) scratch[index] = (value ushr (56 - index * 8)).toByte()
        digest.update(scratch, 0, 8)
    }
}

private fun ByteArray.toLowerHex(): String {
    val alphabet = "0123456789abcdef"
    return buildString(size * 2) {
        this@toLowerHex.forEach { byte ->
            val value = byte.toInt() and 0xff
            append(alphabet[value ushr 4])
            append(alphabet[value and 0x0f])
        }
    }
}

private fun scalePreflightFail(message: String): Nothing =
    throw ScalableStructuralBoundaryPreflightV2Exception(message)
