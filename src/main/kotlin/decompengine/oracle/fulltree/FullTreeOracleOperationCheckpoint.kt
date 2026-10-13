package decompengine.oracle.fulltree

/** Carries one enclosing operation's cooperative deadline through nested oracle producers. */
internal object FullTreeOracleOperationCheckpoint {
    private data class OperationContext(
        val checkpoint: (String) -> Unit,
        val shardPhases: FullTreeOracleShardPhaseObserver?,
    )

    private val currentOperation = ThreadLocal<OperationContext?>()

    fun current(): ((String) -> Unit)? = currentOperation.get()?.checkpoint

    fun currentShardPhases(): FullTreeOracleShardPhaseObserver? = currentOperation.get()?.shardPhases

    fun checkpoint(stage: String) {
        currentOperation.get()?.checkpoint?.invoke(stage)
    }

    fun beginShardPhase(shardId: String) {
        currentOperation.get()?.shardPhases?.beginShardPhase(shardId)
    }

    fun endShardPhase(shardId: String) {
        currentOperation.get()?.shardPhases?.endShardPhase(shardId)
    }

    fun <T> withShardPhase(shardId: String, operation: () -> T): T {
        val observer = currentOperation.get()?.shardPhases
        observer?.beginShardPhase(shardId)
        var failure: Throwable? = null
        try {
            return operation()
        } catch (caught: Throwable) {
            failure = caught
            throw caught
        } finally {
            if (observer != null) {
                try {
                    observer.endShardPhase(shardId)
                } catch (endFailure: Throwable) {
                    if (failure == null) throw endFailure else failure.addSuppressed(endFailure)
                }
            }
        }
    }

    fun <T> withCheckpoint(checkpoint: (String) -> Unit, operation: () -> T): T =
        withCheckpoint(checkpoint, null, operation)

    fun <T> withCheckpoint(
        checkpoint: (String) -> Unit,
        shardPhases: FullTreeOracleShardPhaseObserver?,
        operation: () -> T,
    ): T {
        val previous = currentOperation.get()
        currentOperation.set(OperationContext(checkpoint, shardPhases))
        return try {
            operation()
        } finally {
            if (previous == null) currentOperation.remove() else currentOperation.set(previous)
        }
    }
}

internal interface FullTreeOracleShardPhaseObserver {
    fun beginShardPhase(shardId: String)
    fun endShardPhase(shardId: String)
}
