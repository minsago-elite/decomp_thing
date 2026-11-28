package decompengine.builtin

import decompengine.builtin.provider.*
import java.util.Collections
import java.util.UUID

internal data class ReportedModelUsageV1(
    val input: Long, val output: Long, val total: Long,
    val cachedInput: Long? = null, val cacheWriteInput: Long? = null, val reasoningOutput: Long? = null,
) {
    init {
        v2Require(input >= 0 && output >= 0 && total >= 0 && v2Add(input, output) == total)
        v2Require(cachedInput == null || cachedInput in 0..input)
        v2Require(cacheWriteInput == null || cacheWriteInput in 0..input)
        v2Require(reasoningOutput == null || reasoningOutput in 0..output)
    }
}
internal enum class AttemptStateV2 { RESERVED, DISPATCH_INTENT, NOT_SENT, SETTLED, INDETERMINATE }
internal enum class AttemptOutcomeV2 { COMPLETED, FAILED, INCOMPLETE, CANCELLED, AMBIGUOUS }
internal enum class LedgerStateV2 { READY, ACTIVE, EXHAUSTED, INDETERMINATE }
internal enum class UsageCoverageV1 { NONE, PARTIAL, COMPLETE }
internal enum class LedgerModeV2 { NON_RESUMABLE, INJECTED_DURABILITY }
internal data class ObservedLocalCountersV2(
    val wireBytes: Long = 0, val decodedOutputBytes: Long = 0,
    val displayedBytes: Long = 0, val continuationBytes: Long = 0,
) {
    init { v2Require(listOf(wireBytes, decodedOutputBytes, displayedBytes, continuationBytes).all { it >= 0 }) }
}
internal data class UsageAggregateV1(
    val attempted: Long, val reported: Long, val unknown: Long, val coverage: UsageCoverageV1,
    val knownInput: Long, val knownOutput: Long, val knownTotal: Long,
    val input: Long?, val output: Long?, val total: Long?,
    val cachedInput: Long?, val cacheWriteInput: Long?, val reasoningOutput: Long?,
)
internal class SettledObservationV2 internal constructor(
    val invocationId: UUID, val hostAttemptId: UUID, val callOrdinal: Int, val attempt: Int,
    val accountCommitment: String, val authEpoch: Long, val modelSlug: String, val limitsDigest: String,
    val outcome: AttemptOutcomeV2, val reported: ReportedModelUsageV1?,
    val inputCharge: Long, val outputCharge: Long, val local: ObservedLocalCountersV2,
    val failureKind: ModelFailureKind?,
) {
    val estimated = true
    override fun toString() = "SettledObservationV2(redacted)"
}
internal data class LedgerCountersV2(val requests: Long, val input: Long, val output: Long, val wire: Long, val displayed: Long)
/** A host snapshot for an injected sink. No importer or filesystem implementation exists in A. */
internal class DurableLedgerRecordV2 internal constructor(
    val runId: UUID, val sequence: Long, val attemptId: UUID, val attemptState: AttemptStateV2,
    val counters: LedgerCountersV2, val observation: SettledObservationV2?, val previousCommitment: String,
) {
    val commitment = v2Digest(listOf(runId.toString(), sequence.toString(), attemptId.toString(), attemptState.name,
        counters.requests.toString(), counters.input.toString(), counters.output.toString(), counters.wire.toString(),
        counters.displayed.toString(), previousCommitment) + (observation?.let {
        listOf(it.callOrdinal.toString(), it.attempt.toString(), it.accountCommitment, it.authEpoch.toString(), it.modelSlug,
            it.limitsDigest, it.outcome.name, it.inputCharge.toString(), it.outputCharge.toString(),
            it.local.wireBytes.toString(), it.local.decodedOutputBytes.toString(), it.local.displayedBytes.toString(),
            it.local.continuationBytes.toString(), it.failureKind?.name ?: "none") +
            (it.reported?.let { report -> listOf(report.input.toString(), report.output.toString(), report.total.toString(),
                report.cachedInput?.toString() ?: "unknown", report.cacheWriteInput?.toString() ?: "unknown",
                report.reasoningOutput?.toString() ?: "unknown") } ?: listOf("unknown"))
    } ?: listOf("pending")))
    override fun toString() = "DurableLedgerRecordV2(redacted)"
}
internal interface DurableIntentPortV2 {
    /** Must return only after durable publication; failure is uncertain, never an implicit refund. */
    fun publish(record: DurableLedgerRecordV2)
    /** D must implement an authenticated, monotonic head. This fake seam proves no restart safety. */
    fun currentHead(runId: UUID): DurableLedgerRecordV2?
}
internal class ReservedLease private constructor(
    internal val owner: AttemptLedgerV2, val hostAttemptId: UUID, val callOrdinal: Int, val attempt: Int,
    val exactEncodedInputBytes: Long, val localOutputReservation: Long,
) {
    override fun toString() = "ReservedLease(redacted)"
    companion object {
        internal fun mint(owner: AttemptLedgerV2, id: UUID, ordinal: Int, attempt: Int, input: Long, output: Long) =
            ReservedLease(owner, id, ordinal, attempt, input, output)
    }
}
/** Minted only by a trusted future transport before any send; provider events cannot supply it. */
internal class DefinitelyNotSentProofV2 internal constructor(internal val lease: ReservedLease)
/** Absolute, monotonic totals avoid charging both streamed deltas and an identical final projection. */
internal class AttemptMeterV2 internal constructor(private val ledger: AttemptLedgerV2, private val lease: ReservedLease) {
    fun beforeDelivery(totals: ObservedLocalCountersV2, eventBytes: Long = 0) = ledger.observe(lease, totals, eventBytes)
    override fun toString() = "AttemptMeterV2(redacted)"
}

/** Single host-owned serial reducer. Provider callbacks receive a meter, never this owner. */
internal class AttemptLedgerV2(
    val run: AdmittedModelRunV2,
    val mode: LedgerModeV2 = LedgerModeV2.NON_RESUMABLE,
    private val durability: DurableIntentPortV2? = null,
) {
    init {
        v2Require((mode == LedgerModeV2.INJECTED_DURABILITY) == (durability != null))
        run.claimLedger()
    }
    private class Entry(val lease: ReservedLease) {
        var state = AttemptStateV2.RESERVED
        var dispatchReady = false
        var observed = ObservedLocalCountersV2()
        var call: AdmittedModelCallV2? = null
        var observation: SettledObservationV2? = null
    }
    private val entries = LinkedHashMap<UUID, Entry>()
    private val attempts = mutableMapOf<Int, Int>()
    private var current: Entry? = null
    private var counters = LedgerCountersV2(0, 0, 0, 0, 0)
    private var status = LedgerStateV2.READY
    private var sequence = 0L
    private var head = "0".repeat(64)
    private var persistenceFailed = false
    private var publishing = false
    private var batchPending = false
    // Held by the current batch, then transferred to its next inference lease. This is
    // reserved capacity, not reported/observed input usage; only dispatch debits counters.
    private var nextInputReservation: Long? = null
    private var toolSession: Any? = null
    private var responseConsumed = false
    private var checkpointBlocked = false
    private var storage = BatchCapacityV2()
    @Synchronized fun state(): LedgerStateV2 = status
    @Synchronized fun counters(): LedgerCountersV2 = counters
    @Synchronized fun observations(): List<SettledObservationV2> = Collections.unmodifiableList(entries.values.mapNotNull { it.observation })
    @Synchronized fun durableSequence(): Long = sequence
    @Synchronized internal fun storageUsage(): BatchCapacityV2 = storage
    private fun reserveStorage(evidence: Long, disk: Long, traces: Long) {
        v2Require(evidence >= 0 && disk >= 0 && traces >= 0)
        val next = BatchCapacityV2(v2Add(storage.usedEvidenceBytes, evidence), v2Add(storage.usedPrivateDiskBytes, disk),
            v2Add(storage.usedTraceRecords, traces))
        v2Capacity(next.usedEvidenceBytes <= run.budget.evidenceBytes && next.usedPrivateDiskBytes <= run.budget.privateDiskBytes &&
            next.usedTraceRecords <= run.budget.traceRecords)
        storage = next
    }
    /** Checkpoint eligibility is an in-process protocol property, not permission to restore a run. */
    @Synchronized fun checkpointEligible(): Boolean = mode == LedgerModeV2.INJECTED_DURABILITY &&
        !persistenceFailed && !publishing && !checkpointBlocked && status == LedgerStateV2.READY && !batchPending && current?.state == AttemptStateV2.SETTLED

    private inline fun <T> checked(action: () -> T): T {
        // Reject outside the failure-accounting block: a denied nested call must not
        // mutate the publication whose callback attempted it.
        v2Require(!publishing)
        return try { action() } catch (e: ModelProviderException) {
            if (e.kind == ModelFailureKind.RESOURCE_EXHAUSTED) { if (status != LedgerStateV2.INDETERMINATE) status = LedgerStateV2.EXHAUSTED; persistenceFailed = true }
            throw e
        }
    }
    private fun entry(lease: ReservedLease): Entry {
        v2Require(lease.owner === this)
        val e = entries[lease.hostAttemptId] ?: v2Fail()
        v2Require(e.lease === lease)
        return e
    }
    private fun persist(e: Entry): Boolean {
        v2Require(!publishing)
        if (durability == null) return true
        return try {
            val next = v2Add(sequence, 1)
            val record = DurableLedgerRecordV2(run.runId, next, e.lease.hostAttemptId, e.state, counters, e.observation, head)
            val expectedStatus = status
            val expectedPersistenceFailure = persistenceFailed
            // Advance before calling the port: a throw can mean publication succeeded.
            sequence = next; head = record.commitment
            publishing = true
            try { durability.publish(record) } finally { publishing = false }
            v2Require(current === e && e.state == record.attemptState && sequence == next &&
                head == record.commitment && status == expectedStatus && persistenceFailed == expectedPersistenceFailure)
            true
        } catch (_: Exception) {
            persistenceFailed = true; status = LedgerStateV2.INDETERMINATE
            false
        }
    }
    @Synchronized fun reserve(hostAttemptId: UUID, callOrdinal: Int, exactEncodedInputBytes: Long, localOutputReservation: Long): ReservedLease = checked {
        run.deadline.remainingNanos()
        v2Require(status == LedgerStateV2.READY && !publishing && !batchPending && hostAttemptId !in entries)
        v2Require(callOrdinal > 0 && callOrdinal <= run.budget.maxRequests && callOrdinal >= (current?.lease?.callOrdinal ?: 1))
        v2Require(exactEncodedInputBytes > 0 && localOutputReservation > 0)
        nextInputReservation?.let { v2Capacity(exactEncodedInputBytes <= it) }
        v2Capacity(exactEncodedInputBytes <= run.budget.requestBytes && v2Add(counters.input, exactEncodedInputBytes) <= run.budget.inputUnits)
        v2Capacity(v2Add(counters.output, localOutputReservation) <= run.budget.outputUnits && counters.requests < run.budget.maxRequests)
        val attempt = (attempts[callOrdinal] ?: 0) + 1
        v2Capacity(attempt <= run.budget.maxRetries + 1)
        // Reserve all three bounded host records (reserve, intent, terminal) before dispatch.
        // The injected sink may use at most 4 KiB per record including temporary publication bytes.
        reserveStorage(3L * 4096, 3L * 4096, 3)
        val lease = ReservedLease.mint(this, hostAttemptId, callOrdinal, attempt, exactEncodedInputBytes, localOutputReservation)
        val e = Entry(lease); entries[hostAttemptId] = e; current = e; responseConsumed = false; status = LedgerStateV2.ACTIVE
        nextInputReservation = null // The single active lease now owns this exact request allowance.
        if (!persist(e)) v2Fail(ModelFailureKind.RESOURCE_EXHAUSTED)
        lease
    }
    @Synchronized fun markDispatchIntent(lease: ReservedLease, durableSequence: Long) = checked {
        val e = entry(lease); v2Require(current === e && e.state == AttemptStateV2.RESERVED && status == LedgerStateV2.ACTIVE)
        run.deadline.remainingNanos()
        v2Require(durableSequence == v2Add(sequence, 1))
        counters = counters.copy(requests = v2Add(counters.requests, 1), input = v2Add(counters.input, lease.exactEncodedInputBytes))
        attempts[lease.callOrdinal] = lease.attempt
        e.state = AttemptStateV2.DISPATCH_INTENT
        if (!persist(e)) { e.state = AttemptStateV2.INDETERMINATE; v2Fail(ModelFailureKind.RESOURCE_EXHAUSTED) }
        if (durability == null) sequence = durableSequence
        e.dispatchReady = true
    }
    @Synchronized fun call(lease: ReservedLease, exactEncodedInput: ByteArray): AdmittedModelCallV2 {
        val e = entry(lease)
        v2Require(current === e && e.state == AttemptStateV2.DISPATCH_INTENT && e.dispatchReady && !publishing && e.call == null && status == LedgerStateV2.ACTIVE)
        v2Require(exactEncodedInput.size.toLong() == lease.exactEncodedInputBytes)
        val call = AdmittedModelCallV2(run, lease.callOrdinal, lease.attempt, exactEncodedInput,
            AttemptMeterV2(this, lease), run.deadline.callTimeouts(run.budget))
        e.call = call
        return call
    }
    @Synchronized fun markDefinitelyNotSent(lease: ReservedLease, trustedTransportProof: DefinitelyNotSentProofV2) {
        v2Require(!publishing)
        val e = entry(lease)
        v2Require(trustedTransportProof.lease === lease && current === e && status == LedgerStateV2.ACTIVE)
        v2Require(e.state == AttemptStateV2.RESERVED || e.state == AttemptStateV2.DISPATCH_INTENT)
        v2Require(e.observed == ObservedLocalCountersV2())
        if (e.state == AttemptStateV2.DISPATCH_INTENT) {
            counters = counters.copy(requests = v2Subtract(counters.requests, 1), input = v2Subtract(counters.input, lease.exactEncodedInputBytes))
            attempts[lease.callOrdinal] = lease.attempt - 1
        }
        e.state = AttemptStateV2.NOT_SENT; status = LedgerStateV2.READY
        persist(e) // A failed clear remains indeterminate; no further inference permitted.
    }
    @Synchronized internal fun observe(lease: ReservedLease, totals: ObservedLocalCountersV2, eventBytes: Long) = checked {
        val e = entry(lease)
        v2Require(current === e && status == LedgerStateV2.ACTIVE && e.state == AttemptStateV2.DISPATCH_INTENT)
        val old = e.observed
        v2Require(eventBytes >= 0 && totals.wireBytes >= old.wireBytes && totals.decodedOutputBytes >= old.decodedOutputBytes &&
            totals.displayedBytes >= old.displayedBytes && totals.continuationBytes >= old.continuationBytes)
        counters = counters.copy(wire = v2Add(counters.wire, v2Subtract(totals.wireBytes, old.wireBytes)),
            displayed = v2Add(counters.displayed, v2Subtract(totals.displayedBytes, old.displayedBytes)))
        e.observed = totals // retain observed bytes even when this delivery is refused
        v2Capacity(eventBytes <= run.budget.eventBytes && totals.wireBytes <= run.budget.responseBytes &&
            counters.wire <= run.budget.receivedBytesTotal && counters.displayed <= run.budget.displayedBytesTotal &&
            totals.continuationBytes <= run.budget.continuationBytes && totals.decodedOutputBytes <= lease.localOutputReservation)
        // These bytes were observed even if cancellation now prevents their delivery.
        run.deadline.remainingNanos()
    }
    @Synchronized fun settle(lease: ReservedLease, observedLocalCounters: ObservedLocalCountersV2,
        validatedTerminalUsage: ReportedModelUsageV1?, outcome: AttemptOutcomeV2, failureKind: ModelFailureKind? = null): SettledObservationV2 = checked {
        val e = entry(lease)
        e.observation?.let {
            if (it.local != observedLocalCounters || it.reported != validatedTerminalUsage || it.outcome != outcome || it.failureKind != failureKind) {
                status = LedgerStateV2.INDETERMINATE; persistenceFailed = true; v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
            }
            return@checked it
        }
        v2Require(current === e && e.state == AttemptStateV2.DISPATCH_INTENT && observedLocalCounters == e.observed)
        v2Require(outcome != AttemptOutcomeV2.AMBIGUOUS)
        val input = maxOf(lease.exactEncodedInputBytes, validatedTerminalUsage?.input ?: 0)
        val output = maxOf(observedLocalCounters.decodedOutputBytes, validatedTerminalUsage?.output ?: 0)
        // Actual overdraw is recorded, never clamped to the reservation.
        counters = counters.copy(input = v2Add(counters.input, v2Subtract(input, lease.exactEncodedInputBytes)), output = v2Add(counters.output, output))
        val observation = observation(e, validatedTerminalUsage, outcome, input, output, failureKind)
        e.observation = observation; e.state = AttemptStateV2.SETTLED
        status = if (status == LedgerStateV2.ACTIVE && !persistenceFailed && input <= lease.exactEncodedInputBytes &&
            output <= lease.localOutputReservation && counters.input < run.budget.inputUnits && counters.output < run.budget.outputUnits &&
            counters.wire < run.budget.receivedBytesTotal && counters.displayed < run.budget.displayedBytesTotal) LedgerStateV2.READY else LedgerStateV2.EXHAUSTED
        persist(e) // never throw over the original outcome and never refund on a failed settlement write
        observation
    }
    private fun observation(e: Entry, usage: ReportedModelUsageV1?, outcome: AttemptOutcomeV2, input: Long, output: Long, failure: ModelFailureKind?) =
        SettledObservationV2(run.runId, e.lease.hostAttemptId, e.lease.callOrdinal, e.lease.attempt, run.bindingCommitment,
            run.binding.authEpoch, run.binding.modelSlug, run.limitsDigest, outcome, usage, input, output, e.observed, failure)

    @Synchronized fun markAmbiguous(lease: ReservedLease, failureKind: ModelFailureKind? = null): SettledObservationV2 = checked {
        val e = entry(lease)
        if (e.state == AttemptStateV2.INDETERMINATE && e.observation != null) return@checked e.observation!!
        v2Require(current === e && e.state == AttemptStateV2.DISPATCH_INTENT)
        val retained = maxOf(e.observed.decodedOutputBytes, lease.localOutputReservation)
        counters = counters.copy(output = v2Add(counters.output, retained))
        e.state = AttemptStateV2.INDETERMINATE; status = LedgerStateV2.INDETERMINATE
        val observation = observation(e, null, AttemptOutcomeV2.AMBIGUOUS, lease.exactEncodedInputBytes, retained, failureKind)
        e.observation = observation; persist(e)
        observation
    }
    /** Host finally helper: settlement failure never replaces the original provider outcome. */
    fun <T> withSettlement(lease: ReservedLease, outcome: () -> AttemptOutcomeV2, usage: () -> ReportedModelUsageV1?, body: () -> T): T {
        synchronized(this) { v2Require(!publishing) }
        var original: Throwable? = null
        try { return body() } catch (failure: Throwable) { original = failure; throw failure }
        finally {
            try {
                val observed = synchronized(this) { entry(lease).observed }
                val terminal = outcome()
                if (terminal == AttemptOutcomeV2.AMBIGUOUS) markAmbiguous(lease, (original as? ModelProviderException)?.kind)
                else settle(lease, observed, usage(), if (original == null) terminal else if ((original as? ModelProviderException)?.kind == ModelFailureKind.CANCELLED)
                    AttemptOutcomeV2.CANCELLED else AttemptOutcomeV2.FAILED, (original as? ModelProviderException)?.kind)
            } catch (failure: Exception) {
                synchronized(this) {
                    val pending = entry(lease)
                    if (pending.state == AttemptStateV2.DISPATCH_INTENT && pending.observation == null) {
                        try { markAmbiguous(lease, (original as? ModelProviderException)?.kind) } catch (_: Exception) { /* Still non-restorable on arithmetic failure. */ }
                    }
                    persistenceFailed = true; status = LedgerStateV2.INDETERMINATE
                }
                if (original == null) throw failure
            }
        }
    }
    @Synchronized fun aggregate(): UsageAggregateV1 = checked {
        val dispatched = entries.values.filter { it.state != AttemptStateV2.RESERVED && it.state != AttemptStateV2.NOT_SENT }
        val reports = dispatched.mapNotNull { it.observation?.reported }
        fun sum(f: (ReportedModelUsageV1) -> Long) = reports.fold(0L) { a, b -> v2Add(a, f(b)) }
        val count = dispatched.size.toLong(); val known = reports.size.toLong()
        val coverage = when { known == 0L -> UsageCoverageV1.NONE; known == count -> UsageCoverageV1.COMPLETE; else -> UsageCoverageV1.PARTIAL }
        val complete = coverage == UsageCoverageV1.COMPLETE
        fun detail(f: (ReportedModelUsageV1) -> Long?): Long? = if (complete && reports.all { f(it) != null }) reports.fold(0L) { a, b -> v2Add(a, f(b)!!) } else null
        val input = sum { it.input }; val output = sum { it.output }; val total = sum { it.total }
        UsageAggregateV1(count, known, count - known, coverage, input, output, total,
            input.takeIf { complete }, output.takeIf { complete }, total.takeIf { complete },
            detail { it.cachedInput }, detail { it.cacheWriteInput }, detail { it.reasoningOutput })
    }
    @Synchronized internal fun requireCurrentSuccessful(response: ModelResponseV2) {
        run.deadline.remainingNanos()
        val e = current ?: v2Fail()
        v2Require(status == LedgerStateV2.READY && !publishing && !batchPending && !responseConsumed && e.state == AttemptStateV2.SETTLED && e.call === response.continuation.call)
        v2Require(e.observation?.outcome == AttemptOutcomeV2.COMPLETED && e.observation?.reported == response.reported &&
            response.finishReason in setOf(ModelFinishReason.STOP, ModelFinishReason.TOOL_CALLS))
        v2Require((response.finishReason == ModelFinishReason.TOOL_CALLS) == response.continuation.proposals.isNotEmpty())
    }
    @Synchronized internal fun claimBatch(response: ModelResponseV2, reservation: EncodedReservationV2) = checked {
        requireCurrentSuccessful(response)
        v2Require(nextInputReservation == null)
        v2Capacity(v2Add(counters.input, reservation.nextRequestBytes) <= run.budget.inputUnits)
        reserveStorage(reservation.evidenceBytes, reservation.privateDiskBytes, reservation.traceRecords)
        nextInputReservation = reservation.nextRequestBytes
        batchPending = true; responseConsumed = true
    }
    @Synchronized internal fun registerToolSession(session: Any, initial: BatchCapacityV2) = checked {
        v2Require(toolSession == null)
        reserveStorage(initial.usedEvidenceBytes, initial.usedPrivateDiskBytes, initial.usedTraceRecords)
        toolSession = session
    }
    @Synchronized internal fun checkBatchActive() { v2Require(!publishing); run.deadline.remainingNanos(); v2Require(batchPending && status == LedgerStateV2.READY) }
    @Synchronized internal fun chargeToolResult(bytes: Long) = checked {
        checkBatchActive(); v2Require(bytes >= 0)
        counters = counters.copy(displayed = v2Add(counters.displayed, bytes))
        v2Capacity(counters.displayed <= run.budget.displayedBytesTotal)
    }
    @Synchronized internal fun finishBatch() {
        checkBatchActive(); batchPending = false
        if (counters.displayed == run.budget.displayedBytesTotal) status = LedgerStateV2.EXHAUSTED
        // No D tool-intent/settlement persistence exists: a tool batch cannot mint a checkpoint here.
        checkpointBlocked = true
    }
    @Synchronized internal fun failBatch() { v2Require(!publishing); status = LedgerStateV2.INDETERMINATE; persistenceFailed = true }
    @Synchronized internal fun verifyInjectedHead(expectedSequence: Long, expectedCommitment: String) {
        v2Require(mode == LedgerModeV2.INJECTED_DURABILITY && checkpointEligible())
        publishing = true
        val actual = try { durability!!.currentHead(run.runId) ?: v2Fail() } finally { publishing = false }
        v2Require(checkpointEligible())
        v2Require(actual.runId == run.runId && actual.sequence == sequence && actual.sequence == expectedSequence &&
            actual.commitment == head && actual.commitment == expectedCommitment && actual.attemptState == AttemptStateV2.SETTLED)
    }
}
