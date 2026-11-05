package decompengine.oracle.fulltree.repair

import decompengine.repair.RepairValidationInvocation
import decompengine.repair.RepairValidationObservedArtifact
import java.security.MessageDigest

internal enum class DiagnosticStage { COMPILE, LINK }
internal enum class FailureClass { OWNERSHIP, INTERFACE, OTHER, UNCLASSIFIED }
internal enum class DiagnosticStream { STDOUT, STDERR }

/** Bounded recorded claims only; none grants ownership, edit or producer authority. */
internal sealed class DiagnosticOwner {
    internal abstract val context: DiagnosticComputationContext
    class Module(internal override val context: DiagnosticComputationContext, val moduleId: String, val shardId: String) : DiagnosticOwner() {
        init { context.moduleId(moduleId); context.shardId(shardId) }
    }
    class Shared(internal override val context: DiagnosticComputationContext, val headerOwnerId: String, consumerModuleIds: List<String>) : DiagnosticOwner() {
        init {
            context.meter.checkAccess()
            diagnosticCapacity(consumerModuleIds.size in 0..context.limits.observations)
            context.text(headerOwnerId, nonempty = true, controls = false)
        }
        val consumerModuleIds = context.strings(consumerModuleIds, modules = true)
    }
    class External(internal override val context: DiagnosticComputationContext, val boundaryId: String) : DiagnosticOwner() {
        init { context.text(boundaryId, nonempty = true, controls = false) }
    }
    class Unknown(internal override val context: DiagnosticComputationContext, val reason: String) : DiagnosticOwner() {
        init { context.text(reason) }
    }
    class Unclassified(internal override val context: DiagnosticComputationContext, val reason: String) : DiagnosticOwner() {
        init { context.text(reason) }
    }
    class Conflict(internal override val context: DiagnosticComputationContext, evidenceIds: List<String>) : DiagnosticOwner() {
        val evidenceIds = context.strings(evidenceIds)
    }
}

internal class DiagnosticGraphVersion(
    internal val context: DiagnosticComputationContext,
    val schema: Int,
    val planningArtifactSha256: String,
    val planningReportSha256: String,
    val planningConfigurationSha256: String,
    val dependencyPlanSha256: String,
    val dependencyGeneration: Long,
    val frozenInterfaceSha256: String,
    val frozenGeneration: Long,
    val planTransitionSha256: String?,
) {
    init {
        diagnosticCapacity(schema > 0 && dependencyGeneration >= 0 && frozenGeneration >= 0)
        context.digest(planningArtifactSha256)
        context.digest(planningReportSha256)
        context.digest(planningConfigurationSha256)
        context.digest(dependencyPlanSha256)
        context.digest(frozenInterfaceSha256)
        planTransitionSha256?.let(context::digest)
    }
}

internal data class DiagnosticSpan(val stream: DiagnosticStream, val start: Long, val endExclusive: Long) {
    init { diagnosticCapacity(start >= 0 && endExclusive > start) }
}

internal enum class DiagnosticBlockerCode {
    UNKNOWN_OWNER, UNCLASSIFIED, EXTERNAL_BOUNDARY, SHARED_NONEDITABLE, CONFLICT,
    INCOMPLETE_CAPTURE, INCOMPLETE_GRAPH, UNVERIFIED_TRANSITION, MOVED_UNRESOLVED,
}

internal class DiagnosticBlocker(internal val context: DiagnosticComputationContext, val code: DiagnosticBlockerCode, evidenceIds: List<String>) {
    val evidenceIds = context.strings(evidenceIds)
}

/** Untrusted scalar DTO; stableKey always rechecks all three fields before encoding. */
internal data class NormalizedDiagnostic(val normalizerSha256: String, val normalizedKeySha256: String, val payloadBytes: Long)

internal class RecordedDiagnosticObservation(
    internal val context: DiagnosticComputationContext,
    val stage: DiagnosticStage,
    val toolIdentitySha256: String,
    payload: ByteArray,
    spans: List<DiagnosticSpan>,
    val sourcePath: String?,
    val entityId: String?,
    val claimedClass: FailureClass,
) {
    init {
        context.meter.checkAccess()
        diagnosticCapacity(spans.size in 1..context.limits.spansPerObservation)
        diagnosticCapacity(payload.size.toLong() in 1..context.limits.diagnosticPayloadBytes)
        context.meter.ensure(diagnosticAdd(payload.size.toLong(), spans.size.toLong()))
        context.digest(toolIdentitySha256)
        sourcePath?.let { context.text(it) } // Unresolved raw claim; no path/owner inference.
        entityId?.let { context.text(it) }
    }
    private val retainedPayload = context.copy(payload, "diagnostic payload copy")
    val payload: ByteArray get() = context.copy(retainedPayload, "diagnostic payload getter")
    val spans: List<DiagnosticSpan> = context.snapshot(spans, context.limits.spansPerObservation, "diagnostic spans")
    init { diagnosticCapacity(this.spans.size in 1..context.limits.spansPerObservation) }
    internal val payloadBytes: Long get() = retainedPayload.size.toLong()

    internal fun payloadHash(): String = diagnosticHash(context, retainedPayload, "exact diagnostic payload hashing")

    internal fun matchesSingleSpan(source: ByteArray, span: DiagnosticSpan): Boolean {
        context.meter.checkAccess()
        diagnosticCapacity(span.endExclusive <= source.size.toLong())
        if (span.endExclusive - span.start != retainedPayload.size.toLong()) return false
        var equal = true
        context.meter.begin("before exact diagnostic slice comparison")
        context.meter.work(payloadBytes, "while comparing exact diagnostic slice") { offset, count ->
            for (i in offset until offset + count) if (retainedPayload[i] != source[span.start.toInt() + i]) equal = false
        }
        return equal
    }
}

internal class RecordedBuildFailure(
    internal val context: DiagnosticComputationContext,
    val actionId: String,
    val actionSha256: String,
    val stage: DiagnosticStage,
    val toolIdentitySha256: String,
    val invocation: RepairValidationInvocation,
    val receipt: RepairValidationObservedArtifact,
    val exitCode: Int,
    stdout: ByteArray,
    stderr: ByteArray,
    observations: List<RecordedDiagnosticObservation>,
    val captureComplete: Boolean,
) {
    // Count and aggregate summaries before any span traversal, string scan, comparison or copy.
    private val totals = preflightAction(context, stdout, stderr, observations)
    init {
        context.text(actionId, nonempty = true, controls = false)
        context.digest(actionSha256)
        context.digest(toolIdentitySha256)
        context.text(invocation.id)
        context.text(invocation.runId)
        context.text(invocation.candidateRevisionId)
        context.digest(invocation.sourceRevisionSha256)
        context.digest(invocation.profileSha256)
        context.digest(invocation.indexSha256)
        context.digest(invocation.regressionCorpusSha256)
        context.text(receipt.path)
        context.digest(receipt.sha256)
    }
    private val retainedStdout = context.copy(stdout, "stdout copy")
    private val retainedStderr = context.copy(stderr, "stderr copy")
    val observations = context.snapshot(observations, context.limits.observations, "action observations")
    init {
        // A checkpoint may have changed a caller-owned list. Recheck the retained snapshot before
        // any deep traversal; cached totals must describe these exact records.
        diagnosticCapacity(totals == preflightAction(context, retainedStdout, retainedStderr, this.observations, copyPending = false))
        context.each(this.observations) { observation ->
            diagnosticCapacity(observation.stage == stage && context.equal(observation.toolIdentitySha256, toolIdentitySha256))
            var previousStream = -1
            var previousEnd = 0L
            context.each(observation.spans) { span ->
                val ordinal = span.stream.ordinal
                val stream = if (span.stream == DiagnosticStream.STDOUT) retainedStdout else retainedStderr
                diagnosticCapacity(span.endExclusive <= stream.size.toLong())
                diagnosticCapacity(ordinal >= previousStream && (ordinal != previousStream || span.start >= previousEnd))
                previousStream = ordinal
                previousEnd = span.endExclusive
            }
            if (observation.spans.size == 1) {
                val span = observation.spans.single()
                diagnosticCapacity(observation.matchesSingleSpan(if (span.stream == DiagnosticStream.STDOUT) retainedStdout else retainedStderr, span))
            }
        }
    }
    val stdout: ByteArray get() = context.copy(retainedStdout, "stdout getter")
    val stderr: ByteArray get() = context.copy(retainedStderr, "stderr getter")
    internal val stdoutBytes get() = retainedStdout.size.toLong()
    internal val stderrBytes get() = retainedStderr.size.toLong()
    internal val spanCount get() = totals.spans
    internal val maximumObservationSpans get() = totals.maximumObservationSpans
    internal val diagnosticPayloadBytes get() = totals.payload
}

internal class RecordedCompileLinkBatch(internal val context: DiagnosticComputationContext, failures: List<RecordedBuildFailure>) {
    init { preflightBatch(context, failures, context.limits) }
    val failures = context.snapshot(failures, context.limits.failedActions, "batch failures")
    init { preflightBatch(context, this.failures, context.limits) }
    internal fun checkLimits(limits: ShardDiagnosticLimits) = preflightBatch(context, failures, limits)
}

private data class ActionTotals(val spans: Long, val payload: Long, val maximumObservationSpans: Int)
private fun preflightAction(
    context: DiagnosticComputationContext, stdout: ByteArray, stderr: ByteArray,
    observations: List<RecordedDiagnosticObservation>,
    copyPending: Boolean = true,
): ActionTotals {
    context.meter.checkAccess()
    val limits = context.limits
    diagnosticCapacity(observations.size in 0..limits.observations)
    diagnosticCapacity(stdout.size <= limits.actionBytes && stderr.size <= limits.actionBytes)
    diagnosticCapacity(diagnosticAdd(stdout.size.toLong(), stderr.size.toLong()) <= limits.batchBytes)
    context.meter.begin("before action aggregate admission")
    var spans = 0L
    var payload = 0L
    var maximum = 0
    context.each(observations, limits.observations) { o ->
        diagnosticCapacity(o.context === context)
        diagnosticCapacity(o.spans.size <= limits.spansPerObservation)
        spans = diagnosticAdd(spans, o.spans.size.toLong())
        payload = diagnosticAdd(payload, o.payloadBytes)
        maximum = maxOf(maximum, o.spans.size)
        diagnosticCapacity(spans <= limits.spansPerAction && spans <= limits.spansPerBatch && payload <= limits.diagnosticPayloadBytes)
    }
    if (copyPending) context.meter.ensure(diagnosticAdd(diagnosticAdd(stdout.size.toLong(), stderr.size.toLong()), observations.size.toLong()))
    return ActionTotals(spans, payload, maximum)
}

private fun preflightBatch(context: DiagnosticComputationContext, failures: List<RecordedBuildFailure>, limits: ShardDiagnosticLimits) {
    context.meter.checkAccess()
    diagnosticCapacity(failures.size in 0..limits.failedActions)
    context.meter.begin("before batch aggregate admission")
    var streams = 0L
    var observations = 0L
    var payload = 0L
    var spans = 0L
    context.each(failures, limits.failedActions) { f ->
        diagnosticCapacity(f.context === context)
        observations = diagnosticAdd(observations, f.observations.size.toLong())
        diagnosticCapacity(observations <= limits.observations)
        diagnosticCapacity(f.stdoutBytes <= limits.actionBytes && f.stderrBytes <= limits.actionBytes)
        streams = diagnosticAdd(streams, diagnosticAdd(f.stdoutBytes, f.stderrBytes))
        payload = diagnosticAdd(payload, f.diagnosticPayloadBytes)
        spans = diagnosticAdd(spans, f.spanCount)
        diagnosticCapacity(streams <= limits.batchBytes && payload <= limits.diagnosticPayloadBytes)
        diagnosticCapacity(f.spanCount <= limits.spansPerAction && f.maximumObservationSpans <= limits.spansPerObservation)
        diagnosticCapacity(spans <= limits.spansPerBatch)
    }
}

internal fun diagnosticHash(context: DiagnosticComputationContext, bytes: ByteArray, label: String): String {
    context.meter.ensure(bytes.size.toLong())
    context.meter.begin("before $label")
    val digest = MessageDigest.getInstance("SHA-256")
    context.meter.work(bytes.size.toLong(), "while $label") { offset, count -> digest.update(bytes, offset, count) }
    // Fixed-size SHA-256 output/hex materialization, independent of caller input size.
    return digest.digest().joinToString("") { "%02x".format(it) }
}

internal fun diagnosticCapacity(valid: Boolean) {
    if (!valid) throw DiagnosticInputException(DiagnosticInputFailure.INVALID_OR_OVER_LIMIT)
}
internal fun diagnosticAdd(left: Long, right: Long): Long = try { Math.addExact(left, right) } catch (_: ArithmeticException) {
    throw DiagnosticInputException(DiagnosticInputFailure.INVALID_OR_OVER_LIMIT)
}
internal fun diagnosticMultiply(left: Long, right: Long): Long = try { Math.multiplyExact(left, right) } catch (_: ArithmeticException) {
    throw DiagnosticInputException(DiagnosticInputFailure.INVALID_OR_OVER_LIMIT)
}
internal enum class DiagnosticInputFailure { INVALID_OR_OVER_LIMIT, WORK_EXHAUSTED }
internal class DiagnosticInputException(val failure: DiagnosticInputFailure) : IllegalArgumentException("invalid recorded diagnostic input")
