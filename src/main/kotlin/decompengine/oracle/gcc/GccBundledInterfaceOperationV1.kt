package decompengine.oracle.gcc

/**
 * Construction alone is deliberately insufficient: every evidence accessor checks identity
 * membership issued by the fully checked live coordinator factory. A JVM-visible constructor
 * (including any future synthetic bridge) cannot register an owner or an operation.
 */
internal class GccBundledInterfaceOperation internal constructor(
    snapshot: GccBundledInferredInterfaceSnapshot,
    intentBytes: ByteArray,
    executionReceiptBytes: ByteArray,
    assessmentReceiptBytes: ByteArray,
) {
    private val captured = snapshot
    private val intent = intentBytes.copyOf()
    private val execution = executionReceiptBytes.copyOf()
    private val assessment = assessmentReceiptBytes.copyOf()

    val snapshot: GccBundledInferredInterfaceSnapshot get() = owned { captured }
    val intentBytes: ByteArray get() = owned { intent.copyOf() }
    val executionReceiptBytes: ByteArray get() = owned { execution.copyOf() }
    val assessmentReceiptBytes: ByteArray get() = owned { assessment.copyOf() }
    val complete = false
    val authoritativeOracleEvidence = false
    val productionInterfacesAdmitted = false
    val scored = false
    val releaseEligible = false

    fun requireCurrent() = GccBundledOperationCoordinator.requireOwnedInterfaceOperation(this)

    private inline fun <T> owned(read: () -> T): T {
        requireCurrent()
        return read()
    }
}

/** A pending factory handoff; its identity is held privately by the executing owner. */
internal class GccBundledInterfaceIssuanceV1(
    val snapshot: GccBundledInferredInterfaceSnapshot,
    val intent: ByteArray,
    val execution: ByteArray,
    val assessment: ByteArray,
)
