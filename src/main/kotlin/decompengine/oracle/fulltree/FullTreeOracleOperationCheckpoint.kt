package decompengine.oracle.fulltree

/** Carries one enclosing operation's cooperative deadline through nested oracle producers. */
internal object FullTreeOracleOperationCheckpoint {
    private val currentCheckpoint = ThreadLocal<((String) -> Unit)?>()

    fun current(): ((String) -> Unit)? = currentCheckpoint.get()

    fun checkpoint(stage: String) {
        currentCheckpoint.get()?.invoke(stage)
    }

    fun <T> withCheckpoint(checkpoint: (String) -> Unit, operation: () -> T): T {
        val previous = currentCheckpoint.get()
        currentCheckpoint.set(checkpoint)
        return try {
            operation()
        } finally {
            if (previous == null) currentCheckpoint.remove() else currentCheckpoint.set(previous)
        }
    }
}
