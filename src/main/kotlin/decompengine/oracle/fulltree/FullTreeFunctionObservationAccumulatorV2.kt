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
        sourceEntitiesStarted = true
        if (fact.sourceEntityId in sourceIds) v2AccumulatorFail("duplicate sourceEntityId")
        val row = try {
            OracleJson.canonicalBytes(fact.canonicalJson(), sourceIdentityRowJsonLimits(limits.maximumOutputBytes))
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
        sourceFacts += fact
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
) {
    init {
        require(maximumOutputBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumRetainedBytes in 1L..16L * 1024L * 1024L * 1024L)
    }
}

private fun v2AccumulatorFail(message: String): Nothing = throw FullTreeFunctionObservationV2Exception(message)
