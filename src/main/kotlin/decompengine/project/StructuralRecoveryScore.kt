package decompengine.project

import java.math.BigDecimal
import java.util.Locale

/**
 * The structural recovery heuristic recorded as `projectScore` and per-module `score` in `reports/confidence.json`:
 * the mean of fixed extraction-label weights over a population, rendered with four decimal places. It is an
 * uncalibrated display heuristic, not implementation acceptance or measured behavioral confidence. The producer
 * and the web scorecard share this definition so a recorded score can be reproduced exactly from its labels.
 */
internal object StructuralRecoveryScore {
    const val FORMULA = "extraction-label-mean-v1"

    fun weight(status: RecoveryStatus): Double = when (status) {
        RecoveryStatus.RECOVERED -> 1.0
        RecoveryStatus.PARTIAL -> 0.6
        RecoveryStatus.SYNTHETIC -> 0.25
        RecoveryStatus.FAILED -> 0.0
    }

    /** Exact decimal weight, so numerators are stated without binary floating-point artifacts. */
    fun exactWeight(status: RecoveryStatus): BigDecimal = BigDecimal.valueOf(weight(status)).stripTrailingZeros()

    /** The recorded rendering: an empty population is recorded as `0.0000`, which is not a measured zero. */
    fun render(statuses: List<RecoveryStatus>): String =
        "%.4f".format(Locale.ROOT, if (statuses.isEmpty()) 0.0 else statuses.map(::weight).average())
}
