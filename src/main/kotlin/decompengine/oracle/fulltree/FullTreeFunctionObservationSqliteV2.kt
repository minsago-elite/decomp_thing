package decompengine.oracle.fulltree

import java.nio.file.Path

/** Separately named entrypoint for the file-backed observation-v2 sink. */
internal object FullTreeFunctionObservationSqliteV2 {
    fun open(
        scratchParent: Path,
        shard: FullTreeFunctionObservationShardInput,
        limits: FullTreeFunctionObservationSqliteLimits,
    ): FullTreeFunctionObservationV2Sink {
        requireFunctionObservationV2OutputByteLimit(limits.maximumOutputBytes)
        return FullTreeFunctionObservationSqlite.openV2(scratchParent, shard, limits)
    }
}
