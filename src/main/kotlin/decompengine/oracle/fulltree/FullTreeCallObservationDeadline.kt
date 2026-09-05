package decompengine.oracle.fulltree

internal class FullTreeCallObservationDeadline private constructor(
    private val scopeSha256: String,
    private val startedNanos: Long,
    private val maximumWallClockSeconds: Long,
) {
    fun requireScope(scope: AuthenticatedFullTreeScope) {
        if (scope.sha256 != scopeSha256) {
            throw FullTreeControlException("call-observation deadline belongs to a different authenticated scope")
        }
    }

    fun checkpoint(label: String) {
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
        ): FullTreeCallObservationDeadline {
            val startedNanos = System.nanoTime()
            if (Thread.currentThread().isInterrupted) {
                throw FullTreeControlException("call-observation generation was interrupted before authentication")
            }
            FullTreeScopeControl.validate(scope, controlLimits)
            return FullTreeCallObservationDeadline(
                scope.sha256,
                startedNanos,
                scope.document.controlObject("bounds").controlObject("perShard").controlLong("wallClockSeconds"),
            ).also { it.checkpoint("after authenticating call-observation deadline") }
        }
    }
}
