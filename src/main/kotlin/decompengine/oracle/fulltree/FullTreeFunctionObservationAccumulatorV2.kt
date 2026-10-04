package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonObject

/** In-memory reference sink for the same accepted observation and source-fact stream as SQLite. */
internal class FullTreeFunctionObservationAccumulatorV2(
    private val shard: FullTreeFunctionObservationShardInput,
    private val limits: FullTreeFunctionObservationV2AccumulatorLimits =
        FullTreeFunctionObservationV2AccumulatorLimits(),
) {
    private val functions = FullTreeFunctionObservationAccumulator(shard, limits.observations)
    private val sourceFacts = ArrayList<FullTreeSourceEntityFact>()
    private val sourceIds = HashSet<String>()
    private val physicalDies = HashSet<FullTreeSourcePhysicalDie>()
    private var sourceCanonicalBytes = 0L
    private var sourceRetainedBytes = 0L
    private var acceptedSourceCount = 0L
    private var sourceEntitiesStarted = false
    private var finished = false

    fun recordScannedDie() = functions.recordScannedDie()

    fun recordScannedDies(count: Long) = functions.recordScannedDies(count)

    fun accept(observation: FullTreeObservedSubprogram) {
        requireMutable()
        if (sourceEntitiesStarted) {
            v2AccumulatorFail("function observations must precede source entities in the v2 sink stream")
        }
        functions.accept(observation)
    }

    fun acceptSourceEntity(fact: FullTreeSourceEntityFact) {
        requireMutable()
        limits.checkpoint("before accepting an in-memory source entity")
        FullTreeFunctionObservationsV2.validateSourceEntityForV2(fact, limits.checkpoint)
        if (shard.units.none { it.controlString("id") == fact.physicalDie.unitId }) {
            v2AccumulatorFail("source entity owner is outside its authenticated shard")
        }
        FullTreeFunctionObservationsV2.validateSourceEntityEmittedRvaLink(fact) { linkedRva ->
            linkedRva.removePrefix("0x").toULongOrNull(16)?.let(functions::containsEmittedRva) == true
        }
        sourceEntitiesStarted = true
        if (fact.sourceEntityId in sourceIds) v2AccumulatorFail("duplicate sourceEntityId")
        if (fact.physicalDie in physicalDies) v2AccumulatorFail("duplicate physical DIE locator")
        val row = try {
            OracleJson.canonicalBytes(
                fact.canonicalJson(limits.checkpoint),
                sourceIdentityRowJsonLimits(limits.maximumOutputBytes),
                limits.checkpoint,
            )
        } catch (failure: Exception) {
            throw FullTreeFunctionObservationV2Exception("source entity cannot be canonicalized", failure)
        }
        val nextCount = Math.addExact(acceptedSourceCount, 1L)
        val nextOutputBytes = Math.addExact(sourceCanonicalBytes, row.size.toLong() + 4L)
        val nextRetained = sourceIdentityModeledRetainedChargeBytes(row.size.toLong())
        val projected = Math.addExact(functions.projectedEntityCount(), nextCount)
        if (projected > limits.observations.maximumEntities) {
            v2AccumulatorFail("observation-v2 entity population exceeds its authenticated bound")
        }
        if (nextOutputBytes > limits.maximumOutputBytes) {
            v2AccumulatorFail("source-entity canonical rows exceed the authenticated output budget")
        }
        val totalRetained = Math.addExact(sourceRetainedBytes, nextRetained)
        val combinedRetained = Math.addExact(totalRetained, functions.modeledRetainedBytes())
        if (combinedRetained > minOf(limits.maximumRetainedBytes, limits.observations.maximumRetainedBytes)) {
            v2AccumulatorFail("source entity retained population exceeds its authenticated working-set bound")
        }
        sourceCanonicalBytes = nextOutputBytes
        sourceRetainedBytes = totalRetained
        acceptedSourceCount = nextCount
        sourceIds += fact.sourceEntityId
        physicalDies += fact.physicalDie
        sourceFacts += fact
        limits.checkpoint("after accepting an in-memory source entity")
    }

    fun finish(
        inventoryIndexSha256: String,
        richArtifactSha256: String,
        scopeSha256: String,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
    ): JsonObject {
        requireMutable()
        finished = true
        val legacy = functions.finish(inventoryIndexSha256, richArtifactSha256, scopeSha256)
        return FullTreeFunctionObservationsV2.composeEnvelope(
            v1 = legacy,
            sourceFacts = sourceFacts,
            reconciliation = reconciliation,
            maximumBytes = limits.maximumOutputBytes,
            checkpoint = limits.checkpoint,
        )
    }

    private fun requireMutable() {
        if (finished) v2AccumulatorFail("observation-v2 accumulator is already finished")
    }
}

internal data class FullTreeFunctionObservationV2AccumulatorLimits(
    val observations: FullTreeFunctionObservationAccumulatorLimits = FullTreeFunctionObservationAccumulatorLimits(),
    val maximumOutputBytes: Long = 16L * 1024L * 1024L,
    val maximumRetainedBytes: Long = 1024L * 1024L * 1024L,
    val checkpoint: (String) -> Unit = {},
) {
    init {
        require(maximumOutputBytes in 1L..FullTreeFunctionObservationsV2.MAXIMUM_CANONICAL_BYTES)
        require(maximumRetainedBytes in 1L..16L * 1024L * 1024L * 1024L)
    }
}

private fun v2AccumulatorFail(message: String): Nothing = throw FullTreeFunctionObservationV2Exception(message)
