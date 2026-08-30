package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.project.RecoveredProgramModel
import java.math.BigDecimal
import java.math.RoundingMode
import java.security.MessageDigest
import java.util.Locale
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Historical v1 resource ceilings used by the function-boundary scorer. */
data class StructuralBoundaryReplayV1Limits(
    val maximumProgramModelBytes: Int = 512 * 1024 * 1024,
    val maximumFunctionRecords: Int = 20_000,
    val maximumModelGlobalsOrTypes: Int = 1_000_000,
    val maximumReferencesPerFunction: Int = 100_000,
    val maximumTextCharacters: Int = 16 * 1024 * 1024,
    val maximumMatchingCells: Int = 20_000_000,
    val maximumAmbiguityEdges: Int = 100_000,
) {
    init {
        require(maximumProgramModelBytes in 1..HARD_MAXIMUM_PROGRAM_MODEL_BYTES)
        require(maximumFunctionRecords in 1..HARD_MAXIMUM_FUNCTION_RECORDS)
        require(maximumModelGlobalsOrTypes in 1..HARD_MAXIMUM_MODEL_GLOBALS_OR_TYPES)
        require(maximumReferencesPerFunction in 1..HARD_MAXIMUM_REFERENCES_PER_FUNCTION)
        require(maximumTextCharacters in 1..HARD_MAXIMUM_TEXT_CHARACTERS)
        require(maximumMatchingCells in 1..HARD_MAXIMUM_MATCHING_CELLS)
        require(maximumAmbiguityEdges in 1..HARD_MAXIMUM_AMBIGUITY_EDGES)
    }

    internal companion object {
        const val HARD_MAXIMUM_PROGRAM_MODEL_BYTES = 512 * 1024 * 1024
        const val HARD_MAXIMUM_FUNCTION_RECORDS = 20_000
        const val HARD_MAXIMUM_MODEL_GLOBALS_OR_TYPES = 1_000_000
        const val HARD_MAXIMUM_REFERENCES_PER_FUNCTION = 100_000
        const val HARD_MAXIMUM_TEXT_CHARACTERS = 16 * 1024 * 1024
        const val HARD_MAXIMUM_MATCHING_CELLS = 20_000_000
        const val HARD_MAXIMUM_AMBIGUITY_EDGES = 100_000
        const val HARD_MAXIMUM_REPORT_BYTES = 64 * 1024 * 1024
    }
}

/**
 * A digest binding exact observed inputs after a successful independent replay.
 *
 * This value attests only that the supplied bytes reproduce the candidate v1
 * boundary projection. It deliberately carries no exporter, adapter, or
 * production-provenance authority.
 */
class StructuralBoundaryReplayBindingV1 internal constructor(
    val observedReplaySha256: String,
    val functionOracleSha256: String,
    val boundaryReportSha256: String,
    val recoveredProgramModelSha256: String,
    val twin: String,
    val inputSha256: String,
    val selectedModelImageBase: ULong,
)

/** Independently replays the historical v1 function-boundary projection. */
object StructuralBoundaryReplayV1 {
    fun replay(
        functionOracle: StructuralFunctionOracleV1,
        candidate: StructuralBoundaryMappingV1,
        recoveredProgramModel: RecoveredProgramModel,
        recoveredProgramModelBytes: ByteArray,
        selectedModelImageBase: ULong,
        limits: StructuralBoundaryReplayV1Limits = StructuralBoundaryReplayV1Limits(),
    ): StructuralBoundaryReplayBindingV1 {
        validateCanonicalCandidate(candidate)
        validateUpstreamBinding(functionOracle, candidate, selectedModelImageBase)
        validatePolicy(candidate.document, functionOracle.nearMissBytes)
        val modelSha256 = validateCanonicalModel(recoveredProgramModel, recoveredProgramModelBytes, limits)

        val artifact = functionOracle.artifacts[candidate.twin]
            ?: boundaryReplayFail("boundary replay twin is absent from the supplied function oracle")
        if (recoveredProgramModel.inputSha256 != artifact.inputSha256 ||
            recoveredProgramModel.inputSha256 != candidate.inputSha256
        ) boundaryReplayFail("program model input SHA-256 does not match the selected artifact")

        val recovered = normalizeRecoveredFunctions(
            recoveredProgramModel,
            selectedModelImageBase,
            artifact.executableRvaRanges,
            limits,
        )
        val oracle = functionOracle.scoreableFunctionsByTwin.getValue(candidate.twin)
            .map { (id, record) -> ReplayOracleFunction(id, record.rva, record.aliases) }
            .sortedWith(ORACLE_ORDER)
        validateOracleUniverse(functionOracle, candidate, oracle, artifact.executableRvaRanges)
        val exclusions = parseCompilerGeneratedExclusions(
            functionOracle.expectedExcludedFunctions,
            artifact.executableRvaRanges,
        )

        val ignored = arrayListOf<ReplayIgnored>()
        val scoredRecovered = arrayListOf<ReplayRecoveredFunction>()
        recovered.forEach { function ->
            val exclusion = exclusions[function.rva]
            if (exclusion == null) scoredRecovered += function
            else ignored += ReplayIgnored(function, exclusion)
        }

        val oracleByRva = oracle.associateBy { it.rva }
        if (exclusions.keys.any(oracleByRva::containsKey)) {
            boundaryReplayFail("scoreable and compiler-generated oracle functions share an RVA")
        }
        val exact = scoredRecovered.mapNotNull { recoveredFunction ->
            oracleByRva[recoveredFunction.rva]?.let { ReplayPair(it, recoveredFunction) }
        }.sortedWith(PAIR_ORDER)
        val exactOracleIds = exact.mapTo(hashSetOf()) { it.oracle.id }
        val exactRecoveredIds = exact.mapTo(hashSetOf()) { it.recovered.id }
        val remainingOracle = oracle.filterNot { it.id in exactOracleIds }
        val remainingRecovered = scoredRecovered.filterNot { it.id in exactRecoveredIds }
        val nearAssignment = minimumCostNearAssignment(
            remainingOracle,
            remainingRecovered,
            functionOracle.nearMissBytes,
            limits,
        )

        val selected = selectedTwin(candidate)
        val expectedExact = JsonArray(exact.map { matchDetail(it, "exact") })
        val expectedNear = JsonArray(nearAssignment.matches.map { matchDetail(it, "near") })
        val expectedFalsePositives = JsonArray(nearAssignment.falsePositives.map(::recoveredDetail))
        val expectedFalseNegatives = JsonArray(
            nearAssignment.falseNegatives.map(::oracleDetail),
        )
        val expectedIgnored = JsonArray(ignored.map(::ignoredDetail))

        requireProjectionEquals(selected, "exactMatches", expectedExact)
        requireProjectionEquals(selected, "nearMisses", expectedNear)
        requireProjectionEquals(selected, "falsePositives", expectedFalsePositives)
        requireProjectionEquals(selected, "falseNegatives", expectedFalseNegatives)
        requireProjectionEquals(selected, "ignoredExcludedRecoveries", expectedIgnored)

        val allMatches = exact + nearAssignment.matches
        val expectedAssignment = nearAssignmentDetail(nearAssignment)
        val expectedBoundaries = boundaryMetrics(
            oracle.size,
            recovered.size,
            scoredRecovered.size,
            ignored.size,
            exact.size,
            nearAssignment,
        )
        val expectedNames = nameMetrics(oracle, allMatches)
        requireProjectionEquals(selected, "nearMatchAssignment", expectedAssignment)
        requireProjectionEquals(selected, "boundaries", expectedBoundaries)
        requireProjectionEquals(selected, "nameRecovery", expectedNames)

        validatePublicProjection(
            functionOracle,
            candidate,
            oracle,
            scoredRecovered,
            ignored,
            allMatches,
        )
        val bindingBytes = observedBindingBytes(
            functionOracle,
            candidate,
            modelSha256,
            selectedModelImageBase,
            exact.size,
            nearAssignment,
            ignored.size,
        )
        return StructuralBoundaryReplayBindingV1(
            observedReplaySha256 = OracleArtifacts.sha256(bindingBytes),
            functionOracleSha256 = functionOracle.snapshot.sha256,
            boundaryReportSha256 = candidate.snapshot.sha256,
            recoveredProgramModelSha256 = modelSha256,
            twin = candidate.twin,
            inputSha256 = candidate.inputSha256,
            selectedModelImageBase = selectedModelImageBase,
        )
    }
}

private data class ReplayOracleFunction(
    val id: String,
    val rva: ULong,
    val aliases: JsonArray,
)

private data class ReplayRecoveredFunction(
    val id: String,
    val name: String,
    val rva: ULong,
    val status: String,
)

private data class ReplayExclusion(val oracleId: String, val reason: String)
private data class ReplayIgnored(val recovered: ReplayRecoveredFunction, val exclusion: ReplayExclusion)
private data class ReplayPair(val oracle: ReplayOracleFunction, val recovered: ReplayRecoveredFunction)

private data class ReplayNearAssignment(
    val matches: List<ReplayPair>,
    val falseNegatives: List<ReplayOracleFunction>,
    val falsePositives: List<ReplayRecoveredFunction>,
    val totalDistanceBytes: Int,
    val optimalCandidateEdges: List<ReplayPair>,
)

private val ORACLE_ORDER = Comparator<ReplayOracleFunction> { left, right ->
    left.rva.compareTo(right.rva).takeIf { it != 0 } ?: compareCodePoints(left.id, right.id)
}
private val RECOVERED_ORDER = Comparator<ReplayRecoveredFunction> { left, right ->
    left.rva.compareTo(right.rva).takeIf { it != 0 } ?: compareCodePoints(left.id, right.id)
}
private val PAIR_ORDER = Comparator<ReplayPair> { left, right ->
    ORACLE_ORDER.compare(left.oracle, right.oracle).takeIf { it != 0 }
        ?: RECOVERED_ORDER.compare(left.recovered, right.recovered)
}

private fun validateCanonicalCandidate(candidate: StructuralBoundaryMappingV1) {
    if (candidate.snapshot.size > StructuralBoundaryReplayV1Limits.HARD_MAXIMUM_REPORT_BYTES) {
        boundaryReplayFail("candidate boundary report exceeds the historical v1 report limit")
    }
    val canonical = StructuralJsonEncoder(
        StructuralBoundaryReplayV1Limits.HARD_MAXIMUM_REPORT_BYTES,
        pretty = true,
        ensureAscii = true,
    ).encode(candidate.document)
    if (!MessageDigest.isEqual(candidate.snapshot.bytes, canonical)) {
        boundaryReplayFail("candidate boundary report is not the exact canonical historical v1 byte form")
    }
}

private fun validateUpstreamBinding(
    functionOracle: StructuralFunctionOracleV1,
    candidate: StructuralBoundaryMappingV1,
    selectedModelImageBase: ULong,
) {
    if (!MessageDigest.isEqual(candidate.upstreamOracleSnapshot.bytes, functionOracle.snapshot.bytes)) {
        boundaryReplayFail("candidate boundary report is not bound to the supplied function-oracle bytes")
    }
    if (candidate.twin !in setOf("rich", "stripped")) boundaryReplayFail("boundary replay twin is invalid")
    if (candidate.projectionAdapterId != StructuralRecoveryV1Contract.BOUNDARY_PROJECTION_ADAPTER_ID ||
        candidate.projectionAdapterVersion != StructuralRecoveryV1Contract.BOUNDARY_PROJECTION_ADAPTER_VERSION ||
        candidate.objectFormat != "ELF"
    ) boundaryReplayFail("candidate boundary projection adapter is not the historical ELF v1 adapter")
    val artifact = functionOracle.artifacts[candidate.twin]
        ?: boundaryReplayFail("boundary replay twin is absent from the supplied function oracle")
    if (candidate.inputSha256 != artifact.inputSha256 ||
        candidate.executableRvaRanges != artifact.executableRvaRanges
    ) boundaryReplayFail("candidate artifact projection does not match the supplied function oracle")
    if (candidate.modelImageBase != selectedModelImageBase) {
        boundaryReplayFail("selected model image base does not match the candidate boundary report")
    }
    if (functionOracle.scope == "production" && selectedModelImageBase != artifact.elfImageBase) {
        boundaryReplayFail("production model image base is not the manifest-bound ELF image base")
    }

    val expectedArtifact = JsonObject(
        mapOf(
            "inputSha256" to JsonPrimitive(artifact.inputSha256),
            "elfType" to JsonPrimitive(artifact.elfType),
            "elfImageBase" to address(artifact.elfImageBase),
            "modelImageBase" to address(selectedModelImageBase),
            "modelImageBaseEvidence" to JsonPrimitive("explicit-scorer-input"),
            "modelImageBaseValidation" to JsonPrimitive(
                if (functionOracle.scope == "production") {
                    "matches-manifest-elf-image-base"
                } else {
                    "fixture-explicit-input"
                },
            ),
            "executableRvaRanges" to JsonArray(
                artifact.executableRvaRanges.map { (start, end) ->
                    JsonObject(mapOf("start" to address(start), "endExclusive" to address(end)))
                },
            ),
        ),
    )
    val selected = selectedTwin(candidate)
    if (selected.field("artifact", "selected boundary twin") != expectedArtifact) {
        boundaryReplayFail("candidate artifact detail does not reproduce the selected input binding")
    }
}

private fun validatePolicy(document: JsonObject, nearMissBytes: Int) {
    val expected = JsonObject(
        mapOf(
            "addressNormalization" to JsonPrimitive(
                "rva = model address - explicit program-model image base; " +
                    "oracle RVA = ELF virtual address - recorded ELF image base " +
                    "(manifest-validated for production)",
            ),
            "nearMissBytes" to JsonPrimitive(nearMissBytes),
            "nearMissMatching" to JsonPrimitive(
                "exact addresses first; then on sorted RVAs maximize order-preserving " +
                    "one-to-one cardinality, minimize total absolute distance, and apply " +
                    "the recorded stable tie break",
            ),
            "nameComparison" to JsonPrimitive("exact UTF-8 match against any oracle alias"),
            "exclusionHandling" to JsonPrimitive(
                "inlined records are never scored; exact starts of explicitly " +
                    "compiler-generated records are ignored",
            ),
            "limits" to JsonObject(
                mapOf(
                    "maxJsonInputBytes" to JsonPrimitive(512 * 1024 * 1024),
                    "maxManifestBytes" to JsonPrimitive(64 * 1024 * 1024),
                    "maxSupportingInputBytes" to JsonPrimitive(64 * 1024 * 1024),
                    "maxArtifactBytes" to JsonPrimitive(512 * 1024 * 1024),
                    "maxReportBytes" to JsonPrimitive(64 * 1024 * 1024),
                    "maxFunctionRecords" to JsonPrimitive(20_000),
                    "maxAliasesPerFunction" to JsonPrimitive(256),
                    "maxEvidencePerAlias" to JsonPrimitive(256),
                    "maxModelReferencesPerFunction" to JsonPrimitive(100_000),
                    "maxModelGlobalsOrTypes" to JsonPrimitive(1_000_000),
                    "maxTextCharacters" to JsonPrimitive(16 * 1024 * 1024),
                    "maxMatchingCells" to JsonPrimitive(20_000_000),
                    "maxAmbiguityEdges" to JsonPrimitive(100_000),
                ),
            ),
        ),
    )
    if (document.field("policy", "candidate boundary report") != expected) {
        boundaryReplayFail("candidate boundary report does not state the exact historical v1 policy")
    }
}

private fun validateCanonicalModel(
    model: RecoveredProgramModel,
    bytes: ByteArray,
    limits: StructuralBoundaryReplayV1Limits,
): String {
    val snapshot = CanonicalProgramModelStreaming.readCanonical(
        bytes,
        CanonicalProgramModelStreamingLimits(
            maximumInputBytes = limits.maximumProgramModelBytes,
            maximumFunctions = limits.maximumFunctionRecords,
            maximumGlobals = limits.maximumModelGlobalsOrTypes,
            maximumTypes = limits.maximumModelGlobalsOrTypes,
            maximumReferencesPerFunction = limits.maximumReferencesPerFunction,
            maximumTextCodePoints = limits.maximumTextCharacters,
        ),
    )
    if (snapshot.model != model) {
        boundaryReplayFail("program model bytes do not encode the supplied program model exactly")
    }
    if (!StructuralRecoveryV1Contract.SHA256.matches(snapshot.model.inputSha256)) {
        boundaryReplayFail("program model inputSha256 is not a lowercase SHA-256 digest")
    }
    return snapshot.sha256
}

private fun normalizeRecoveredFunctions(
    model: RecoveredProgramModel,
    imageBase: ULong,
    executableRanges: List<Pair<ULong, ULong>>,
    limits: StructuralBoundaryReplayV1Limits,
): List<ReplayRecoveredFunction> {
    if (model.functions.size > limits.maximumFunctionRecords) {
        boundaryReplayFail("program model exceeds the configured function-record limit")
    }
    val ids = hashSetOf<String>()
    val rvas = hashSetOf<ULong>()
    return model.functions.mapIndexed { index, function ->
        if (!ids.add(function.id)) boundaryReplayFail("program model contains a duplicate recovered function ID")
        if (function.address < imageBase) {
            boundaryReplayFail("program model.functions[$index].address is below the selected model image base")
        }
        val rva = function.address - imageBase
        if (executableRanges.none { (start, end) -> rva >= start && rva < end }) {
            boundaryReplayFail("program model.functions[$index].address normalizes outside executable ranges")
        }
        if (!rvas.add(rva)) boundaryReplayFail("multiple recovered functions normalize to RVA ${rva.hexAddress()}")
        ReplayRecoveredFunction(
            function.id,
            function.name,
            rva,
            function.status.name.lowercase(Locale.ROOT),
        )
    }.sortedWith(RECOVERED_ORDER)
}

private fun validateOracleUniverse(
    functionOracle: StructuralFunctionOracleV1,
    candidate: StructuralBoundaryMappingV1,
    oracle: List<ReplayOracleFunction>,
    ranges: List<Pair<ULong, ULong>>,
) {
    val ids = hashSetOf<String>()
    val rvas = hashSetOf<ULong>()
    oracle.forEach { function ->
        if (!ids.add(function.id)) boundaryReplayFail("supplied function oracle has a duplicate scored ID")
        if (!rvas.add(function.rva)) boundaryReplayFail("supplied function oracle has a duplicate scored RVA")
        if (ranges.none { (start, end) -> function.rva >= start && function.rva < end }) {
            boundaryReplayFail("supplied function oracle has a scored RVA outside executable ranges")
        }
    }
    if (ids != functionOracle.scoredFunctionIds || candidate.oracleFunctionIds != ids) {
        boundaryReplayFail("candidate scored oracle universe is not the supplied function oracle universe")
    }
}

private fun parseCompilerGeneratedExclusions(
    records: JsonArray,
    ranges: List<Pair<ULong, ULong>>,
): Map<ULong, ReplayExclusion> {
    val allIds = hashSetOf<String>()
    val byRva = linkedMapOf<ULong, ReplayExclusion>()
    records.forEachIndexed { index, raw ->
        val path = "function oracle excludedFunctions[$index]"
        val item = raw.requireObject(path, setOf("oracleId", "rva", "aliases", "kind", "reason"))
        val id = item.field("oracleId", path).requireString("$path.oracleId", 4096)
        if (!allIds.add(id)) boundaryReplayFail("supplied function oracle has a duplicate excluded ID")
        val kind = item.field("kind", path).requireString("$path.kind", 64)
        val rvaElement = item.field("rva", path)
        if (kind == "inlined") {
            if (rvaElement != JsonNull) boundaryReplayFail("inlined exclusions must not identify an emitted RVA")
            return@forEachIndexed
        }
        if (kind != "compiler-generated" || rvaElement == JsonNull) {
            boundaryReplayFail("reviewed exclusions must be compiler-generated or inlined with exact RVA rules")
        }
        val rva = rvaElement.requireAddress("$path.rva", ULong.MAX_VALUE)
        if (ranges.none { (start, end) -> rva >= start && rva < end }) {
            boundaryReplayFail("compiler-generated exclusion is outside executable ranges")
        }
        val exclusion = ReplayExclusion(
            id,
            item.field("reason", path).requireString("$path.reason", 16 * 1024),
        )
        if (byRva.put(rva, exclusion) != null) {
            boundaryReplayFail("multiple reviewed exclusions share an emitted RVA")
        }
    }
    return byRva
}

private fun minimumCostNearAssignment(
    oracle: List<ReplayOracleFunction>,
    recovered: List<ReplayRecoveredFunction>,
    bound: Int,
    limits: StructuralBoundaryReplayV1Limits,
): ReplayNearAssignment {
    if (oracle.isEmpty() || recovered.isEmpty()) {
        return ReplayNearAssignment(emptyList(), oracle, recovered, 0, emptyList())
    }
    val width = recovered.size + 1
    val cells = (oracle.size.toLong() + 1L) * width.toLong()
    if (cells > limits.maximumMatchingCells) boundaryReplayFail("near assignment exceeds the configured cell limit")
    try {
        val suffixCounts = ShortArray(cells.toInt())
        val suffixCosts = IntArray(cells.toInt())
        for (oracleIndex in oracle.lastIndex downTo 0) {
            val row = oracleIndex * width
            val below = (oracleIndex + 1) * width
            for (recoveredIndex in recovered.lastIndex downTo 0) {
                var bestCount = suffixCounts[below + recoveredIndex].toInt()
                var bestCost = suffixCosts[below + recoveredIndex]
                val rightCount = suffixCounts[row + recoveredIndex + 1].toInt()
                val rightCost = suffixCosts[row + recoveredIndex + 1]
                if (betterObjective(rightCount, rightCost, bestCount, bestCost)) {
                    bestCount = rightCount
                    bestCost = rightCost
                }
                val distance = distanceWithinBound(oracle[oracleIndex].rva, recovered[recoveredIndex].rva, bound)
                if (distance != null) {
                    val matchCount = suffixCounts[below + recoveredIndex + 1].toInt() + 1
                    val matchCost = suffixCosts[below + recoveredIndex + 1] + distance
                    if (betterObjective(matchCount, matchCost, bestCount, bestCost)) {
                        bestCount = matchCount
                        bestCost = matchCost
                    }
                }
                suffixCounts[row + recoveredIndex] = bestCount.toShort()
                suffixCosts[row + recoveredIndex] = bestCost
            }
        }

        val maximumCardinality = suffixCounts[0].toInt()
        val minimumCost = suffixCosts[0]
        val selected = arrayListOf<ReplayPair>()
        var startOracle = 0
        var startRecovered = 0
        var remainingCardinality = maximumCardinality
        var remainingCost = minimumCost
        while (remainingCardinality > 0) {
            var chosenOracle = -1
            var chosenRecovered = -1
            var chosenDistance = -1
            search@ for (oracleIndex in startOracle until oracle.size) {
                val below = (oracleIndex + 1) * width
                for (recoveredIndex in startRecovered until recovered.size) {
                    val distance = distanceWithinBound(oracle[oracleIndex].rva, recovered[recoveredIndex].rva, bound)
                        ?: continue
                    val suffixIndex = below + recoveredIndex + 1
                    if (suffixCounts[suffixIndex].toInt() + 1 == remainingCardinality &&
                        suffixCosts[suffixIndex] + distance == remainingCost
                    ) {
                        chosenOracle = oracleIndex
                        chosenRecovered = recoveredIndex
                        chosenDistance = distance
                        break@search
                    }
                }
            }
            if (chosenOracle < 0) boundaryReplayFail("near assignment reconstruction drifted from its objective")
            selected += ReplayPair(oracle[chosenOracle], recovered[chosenRecovered])
            startOracle = chosenOracle + 1
            startRecovered = chosenRecovered + 1
            remainingCardinality--
            remainingCost -= chosenDistance
        }

        val optimalCandidates = arrayListOf<ReplayPair>()
        var previousCounts = ShortArray(width)
        var previousCosts = IntArray(width)
        oracle.forEachIndexed { oracleIndex, oracleFunction ->
            val currentCounts = ShortArray(width)
            val currentCosts = IntArray(width)
            val below = (oracleIndex + 1) * width
            recovered.forEachIndexed { recoveredIndex, recoveredFunction ->
                val distance = distanceWithinBound(oracleFunction.rva, recoveredFunction.rva, bound)
                if (distance != null) {
                    val suffixIndex = below + recoveredIndex + 1
                    if (previousCounts[recoveredIndex].toInt() + 1 + suffixCounts[suffixIndex].toInt() ==
                        maximumCardinality &&
                        previousCosts[recoveredIndex] + distance + suffixCosts[suffixIndex] == minimumCost
                    ) {
                        optimalCandidates += ReplayPair(oracleFunction, recoveredFunction)
                        if (optimalCandidates.size > limits.maximumAmbiguityEdges) {
                            boundaryReplayFail("optimal near-assignment ambiguity exceeds the configured edge limit")
                        }
                    }
                }

                val cell = recoveredIndex + 1
                var bestCount = previousCounts[cell].toInt()
                var bestCost = previousCosts[cell]
                val leftCount = currentCounts[cell - 1].toInt()
                val leftCost = currentCosts[cell - 1]
                if (betterObjective(leftCount, leftCost, bestCount, bestCost)) {
                    bestCount = leftCount
                    bestCost = leftCost
                }
                if (distance != null) {
                    val matchCount = previousCounts[cell - 1].toInt() + 1
                    val matchCost = previousCosts[cell - 1] + distance
                    if (betterObjective(matchCount, matchCost, bestCount, bestCost)) {
                        bestCount = matchCount
                        bestCost = matchCost
                    }
                }
                currentCounts[cell] = bestCount.toShort()
                currentCosts[cell] = bestCost
            }
            previousCounts = currentCounts
            previousCosts = currentCosts
        }
        if (previousCounts.last().toInt() != maximumCardinality || previousCosts.last() != minimumCost) {
            boundaryReplayFail("forward and backward near-assignment objectives disagree")
        }
        val selectedOracle = selected.mapTo(hashSetOf()) { it.oracle.id }
        val selectedRecovered = selected.mapTo(hashSetOf()) { it.recovered.id }
        return ReplayNearAssignment(
            selected,
            oracle.filterNot { it.id in selectedOracle },
            recovered.filterNot { it.id in selectedRecovered },
            minimumCost,
            optimalCandidates,
        )
    } catch (failure: OutOfMemoryError) {
        throw StructuralRecoveryV1Exception("not enough memory for the bounded near assignment", failure)
    }
}

private fun betterObjective(candidateCount: Int, candidateCost: Int, bestCount: Int, bestCost: Int): Boolean =
    candidateCount > bestCount || candidateCount == bestCount && candidateCost < bestCost

private fun distanceWithinBound(left: ULong, right: ULong, bound: Int): Int? {
    val distance = if (left >= right) left - right else right - left
    return if (distance <= bound.toULong()) distance.toInt() else null
}

private fun matchDetail(pair: ReplayPair, kind: String): JsonObject {
    val aliases = pair.oracle.aliases.map { it as JsonObject }
    val observable = aliases.filter { aliasAvailability(it) != "not-observable" }
    val matched = observable.firstOrNull { aliasName(it) == pair.recovered.name }
    val nameResult = when {
        observable.isEmpty() -> "not-scored"
        matched != null -> "exact"
        else -> "incorrect"
    }
    val categoryResults = listOf("surviving", "removed").associateWith { availability ->
        val available = aliases.filter { aliasAvailability(it) == availability }
        when {
            available.isEmpty() -> JsonPrimitive("not-applicable")
            available.any { aliasName(it) == pair.recovered.name } -> JsonPrimitive("exact")
            else -> JsonPrimitive("incorrect")
        }
    }
    return JsonObject(
        oracleDetail(pair.oracle) + recoveredDetail(pair.recovered) + mapOf(
            "deltaBytes" to JsonPrimitive(signedDelta(pair.recovered.rva, pair.oracle.rva)),
            "matchKind" to JsonPrimitive(kind),
            "nameResult" to JsonPrimitive(nameResult),
            "matchedAlias" to (matched?.let { JsonPrimitive(aliasName(it)) } ?: JsonNull),
            "matchedAliasAvailability" to (matched?.let { JsonPrimitive(aliasAvailability(it)) } ?: JsonNull),
            "nameCategoryResults" to JsonObject(categoryResults),
        ),
    )
}

private fun oracleDetail(function: ReplayOracleFunction): JsonObject =
    JsonObject(
        mapOf(
        "oracleId" to JsonPrimitive(function.id),
        "oracleRva" to address(function.rva),
        "oracleAliases" to function.aliases,
        ),
    )

private fun recoveredDetail(function: ReplayRecoveredFunction): JsonObject = JsonObject(
    mapOf(
        "recoveredId" to JsonPrimitive(function.id),
        "recoveredRva" to address(function.rva),
        "recoveredName" to JsonPrimitive(function.name),
        "recoveredStatus" to JsonPrimitive(function.status),
    ),
)

private fun ignoredDetail(ignored: ReplayIgnored): JsonObject = JsonObject(
    recoveredDetail(ignored.recovered) + mapOf(
        "oracleId" to JsonPrimitive(ignored.exclusion.oracleId),
        "exclusionKind" to JsonPrimitive("compiler-generated"),
        "exclusionReason" to JsonPrimitive(ignored.exclusion.reason),
    ),
)

private fun nearAssignmentDetail(assignment: ReplayNearAssignment): JsonObject {
    val selected = assignment.matches.mapTo(hashSetOf()) { it.oracle.id to it.recovered.id }
    val alternatives = assignment.optimalCandidateEdges.filterNot { it.oracle.id to it.recovered.id in selected }
    return JsonObject(
        mapOf(
            "objective" to JsonObject(
                mapOf(
                    "maximumCardinality" to JsonPrimitive(assignment.matches.size),
                    "minimumTotalDistanceBytes" to JsonPrimitive(assignment.totalDistanceBytes),
                ),
            ),
            "stableTieBreak" to JsonPrimitive(
                "lexicographically lowest (oracle RVA, recovered RVA) edge sequence",
            ),
            "nameIndependent" to JsonPrimitive(true),
            "hasAlternativeOptimalMatching" to JsonPrimitive(alternatives.isNotEmpty()),
            "optimalCandidateEdgeCount" to JsonPrimitive(assignment.optimalCandidateEdges.size),
            "alternativeOptimalEdges" to JsonArray(alternatives.map(::assignmentEdgeDetail)),
        ),
    )
}

private fun assignmentEdgeDetail(pair: ReplayPair): JsonObject = JsonObject(
    mapOf(
        "oracleId" to JsonPrimitive(pair.oracle.id),
        "oracleRva" to address(pair.oracle.rva),
        "recoveredId" to JsonPrimitive(pair.recovered.id),
        "recoveredRva" to address(pair.recovered.rva),
        "deltaBytes" to JsonPrimitive(signedDelta(pair.recovered.rva, pair.oracle.rva)),
        "distanceBytes" to JsonPrimitive(checkNotNull(distanceWithinBound(pair.oracle.rva, pair.recovered.rva, 4096))),
    ),
)

private fun boundaryMetrics(
    oracleCount: Int,
    rawRecoveredCount: Int,
    scoredRecoveredCount: Int,
    ignoredCount: Int,
    exactCount: Int,
    near: ReplayNearAssignment,
): JsonObject {
    val truePositives = exactCount + near.matches.size
    val falsePositives = near.falsePositives.size
    val falseNegatives = near.falseNegatives.size
    if (truePositives + falseNegatives != oracleCount || truePositives + falsePositives != scoredRecoveredCount) {
        boundaryReplayFail("replayed boundary denominators do not partition")
    }
    return JsonObject(
        mapOf(
            "referenceCount" to JsonPrimitive(oracleCount),
            "rawRecoveredCount" to JsonPrimitive(rawRecoveredCount),
            "scoredRecoveredCount" to JsonPrimitive(scoredRecoveredCount),
            "ignoredExcludedCount" to JsonPrimitive(ignoredCount),
            "exactMatches" to JsonPrimitive(exactCount),
            "nearMisses" to JsonPrimitive(near.matches.size),
            "truePositives" to JsonPrimitive(truePositives),
            "falsePositives" to JsonPrimitive(falsePositives),
            "falseNegatives" to JsonPrimitive(falseNegatives),
            "precision" to ratio(truePositives, scoredRecoveredCount),
            "recall" to ratio(truePositives, oracleCount),
            "f1" to ratio(2 * truePositives, 2 * truePositives + falsePositives + falseNegatives),
            "exactAddressRate" to ratio(exactCount, oracleCount),
            "nearMissRate" to ratio(near.matches.size, oracleCount),
            "nearMissDistanceBytes" to JsonPrimitive(near.totalDistanceBytes),
        ),
    )
}

private fun nameMetrics(
    oracle: List<ReplayOracleFunction>,
    matches: List<ReplayPair>,
): JsonObject {
    val recoveredByOracle = matches.associate { it.oracle.id to it.recovered }
    fun metric(availabilityFilter: String?): JsonObject {
        val eligible = oracle.filter { function ->
            function.aliases.map { it as JsonObject }.any { alias ->
                aliasAvailability(alias) != "not-observable" &&
                    (availabilityFilter == null || aliasAvailability(alias) == availabilityFilter)
            }
        }
        var exact = 0
        var incorrect = 0
        var missing = 0
        eligible.forEach { function ->
            val recovered = recoveredByOracle[function.id]
            when {
                recovered == null -> missing++
                function.aliases.map { it as JsonObject }.any { alias ->
                    aliasAvailability(alias) != "not-observable" &&
                        (availabilityFilter == null || aliasAvailability(alias) == availabilityFilter) &&
                        aliasName(alias) == recovered.name
                } -> exact++
                else -> incorrect++
            }
        }
        return JsonObject(
            mapOf(
                "referenceCount" to JsonPrimitive(eligible.size),
                "exact" to JsonPrimitive(exact),
                "incorrect" to JsonPrimitive(incorrect),
                "missingBoundary" to JsonPrimitive(missing),
                "accuracy" to ratio(exact, eligible.size),
            ),
        )
    }
    return JsonObject(
        mapOf(
            "overall" to metric(null),
            "surviving" to metric("surviving"),
            "removed" to metric("removed"),
            "notObservableCount" to JsonPrimitive(
                oracle.count { function ->
                    function.aliases.map { it as JsonObject }.none { aliasAvailability(it) != "not-observable" }
                },
            ),
        ),
    )
}

private fun ratio(numerator: Int, denominator: Int): JsonObject = JsonObject(
    mapOf(
        "numerator" to JsonPrimitive(numerator),
        "denominator" to JsonPrimitive(denominator),
        "value" to if (denominator == 0) JsonNull else JsonPrimitive(
            BigDecimal(numerator.toDouble() / denominator.toDouble())
                .setScale(6, RoundingMode.HALF_EVEN)
                .toDouble(),
        ),
    ),
)

private fun validatePublicProjection(
    functionOracle: StructuralFunctionOracleV1,
    candidate: StructuralBoundaryMappingV1,
    oracle: List<ReplayOracleFunction>,
    scoredRecovered: List<ReplayRecoveredFunction>,
    ignored: List<ReplayIgnored>,
    matches: List<ReplayPair>,
) {
    val oracleToRecovered = matches.associate { it.oracle.id to it.recovered.id }
    val recoveredToOracle = matches.associate { it.recovered.id to it.oracle.id }
    val oracleIds = oracle.mapTo(linkedSetOf()) { it.id }
    val recoveredIds = scoredRecovered.mapTo(linkedSetOf()) { it.id }
    val ignoredIds = ignored.mapTo(linkedSetOf()) { it.recovered.id }
    val excludedIds = functionOracle.expectedExcludedFunctions.mapTo(linkedSetOf()) {
        (it as JsonObject).field("oracleId", "function exclusion").requireString("function exclusion.oracleId", 4096)
    }
    if (candidate.oracleToRecovered != oracleToRecovered ||
        candidate.recoveredToOracle != recoveredToOracle ||
        candidate.oracleFunctionIds != oracleIds ||
        candidate.recoveredFunctionIds != recoveredIds ||
        candidate.excludedOracleIds != excludedIds ||
        candidate.ignoredRecoveredIds != ignoredIds
    ) boundaryReplayFail("candidate public boundary projection does not equal the independently replayed universes")
}

private fun observedBindingBytes(
    functionOracle: StructuralFunctionOracleV1,
    candidate: StructuralBoundaryMappingV1,
    modelSha256: String,
    selectedModelImageBase: ULong,
    exactCount: Int,
    near: ReplayNearAssignment,
    ignoredCount: Int,
): ByteArray = StructuralJsonEncoder(64 * 1024, pretty = false, ensureAscii = true).encode(
    JsonObject(
        mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "bindingKind" to JsonPrimitive("observed-structural-boundary-replay"),
            "functionOracleSha256" to JsonPrimitive(functionOracle.snapshot.sha256),
            "boundaryReportSha256" to JsonPrimitive(candidate.snapshot.sha256),
            "recoveredProgramModelSha256" to JsonPrimitive(modelSha256),
            "projectionAdapterId" to JsonPrimitive(candidate.projectionAdapterId),
            "projectionAdapterVersion" to JsonPrimitive(candidate.projectionAdapterVersion),
            "twin" to JsonPrimitive(candidate.twin),
            "inputSha256" to JsonPrimitive(candidate.inputSha256),
            "selectedModelImageBase" to address(selectedModelImageBase),
            "observedCounts" to JsonObject(
                mapOf(
                    "exactMatches" to JsonPrimitive(exactCount),
                    "nearMisses" to JsonPrimitive(near.matches.size),
                    "falsePositives" to JsonPrimitive(near.falsePositives.size),
                    "falseNegatives" to JsonPrimitive(near.falseNegatives.size),
                    "ignoredExcludedRecoveries" to JsonPrimitive(ignoredCount),
                    "nearMissDistanceBytes" to JsonPrimitive(near.totalDistanceBytes),
                ),
            ),
        ),
    ),
)

private fun selectedTwin(candidate: StructuralBoundaryMappingV1): JsonObject {
    val twins = candidate.document.field("twins", "candidate boundary report") as? JsonObject
        ?: boundaryReplayFail("candidate boundary report.twins must be an object")
    return twins.field(candidate.twin, "candidate boundary report.twins") as? JsonObject
        ?: boundaryReplayFail("candidate selected twin must be an object")
}

private fun requireProjectionEquals(selected: JsonObject, field: String, expected: JsonElement) {
    if (selected.field(field, "candidate selected twin") != expected) {
        boundaryReplayFail("candidate $field does not equal the independently replayed historical projection")
    }
}

private fun aliasName(alias: JsonObject): String =
    alias.field("name", "function oracle alias").requireString("function oracle alias.name", 4096)

private fun aliasAvailability(alias: JsonObject): String =
    alias.field("availability", "function oracle alias").requireString("function oracle alias.availability", 32)

private fun signedDelta(recovered: ULong, oracle: ULong): Long = when {
    recovered >= oracle -> {
        val difference = recovered - oracle
        if (difference > Long.MAX_VALUE.toULong()) boundaryReplayFail("boundary delta exceeds the signed v1 report range")
        difference.toLong()
    }
    else -> {
        val difference = oracle - recovered
        if (difference > Long.MAX_VALUE.toULong()) boundaryReplayFail("boundary delta exceeds the signed v1 report range")
        -difference.toLong()
    }
}

private fun address(value: ULong): JsonPrimitive = JsonPrimitive(value.hexAddress())
private fun ULong.hexAddress(): String = "0x${toString(16)}"

private fun boundaryReplayFail(message: String): Nothing = throw StructuralRecoveryV1Exception(message)
