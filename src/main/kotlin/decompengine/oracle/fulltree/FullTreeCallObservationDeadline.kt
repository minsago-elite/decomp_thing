package decompengine.oracle.fulltree

internal class FullTreeCallObservationDeadline private constructor(
    private val scopeSha256: String,
    private val startedNanos: Long,
    private val maximumWallClockSeconds: Long,
    private val wholeRun: Boolean,
    private val parent: FullTreeCallObservationDeadline?,
) {
    fun requireScope(scope: AuthenticatedFullTreeScope) {
        if (scope.sha256 != scopeSha256) {
            throw FullTreeControlException("call-observation deadline belongs to a different authenticated scope")
        }
    }

    fun requireShardScope(scope: AuthenticatedFullTreeScope) {
        requireScope(scope)
        if (wholeRun) {
            throw FullTreeControlException("call-observation shard requires its own bounded deadline")
        }
    }

    fun startShard(
        scope: AuthenticatedFullTreeScope,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
    ): FullTreeCallObservationDeadline {
        requireScope(scope)
        if (!wholeRun) {
            throw FullTreeControlException("call-observation shard deadline cannot restart another shard deadline")
        }
        checkpoint("before starting call-observation shard deadline")
        return create(scope, controlLimits, wholeRun = false, parent = this)
    }

    fun checkpoint(label: String) {
        parent?.checkpoint(label)
        if (Thread.currentThread().isInterrupted) {
            throw FullTreeControlException("call-observation generation was interrupted $label")
        }
        val elapsedNanos = System.nanoTime() - startedNanos
        if (elapsedNanos < 0L || elapsedNanos / 1_000_000_000L >= maximumWallClockSeconds) {
            throw FullTreeControlException("call-observation generation exceeds its wall-clock bound $label")
        }
    }

    companion object {
        fun start(
            scope: AuthenticatedFullTreeScope,
            controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        ): FullTreeCallObservationDeadline = create(scope, controlLimits, wholeRun = false, parent = null)

        fun startWholeRun(
            scope: AuthenticatedFullTreeScope,
            controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        ): FullTreeCallObservationDeadline = create(scope, controlLimits, wholeRun = true, parent = null)

        private fun create(
            scope: AuthenticatedFullTreeScope,
            controlLimits: FullTreeControlLimits,
            wholeRun: Boolean,
            parent: FullTreeCallObservationDeadline?,
        ): FullTreeCallObservationDeadline {
            val startedNanos = System.nanoTime()
            if (Thread.currentThread().isInterrupted) {
                throw FullTreeControlException("call-observation generation was interrupted before authentication")
            }
            FullTreeScopeControl.validate(scope, controlLimits)
            return FullTreeCallObservationDeadline(
                scope.sha256,
                startedNanos,
                scope.document.controlObject("bounds").controlObject(if (wholeRun) "wholeRun" else "perShard")
                    .controlLong("wallClockSeconds"),
                wholeRun,
                parent,
            ).also { it.checkpoint("after authenticating call-observation deadline") }
        }
    }
}
