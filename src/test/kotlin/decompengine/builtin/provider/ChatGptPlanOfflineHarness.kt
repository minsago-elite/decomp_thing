package decompengine.builtin.provider

import decompengine.builtin.*
import java.util.IdentityHashMap
import java.util.UUID
import kotlinx.serialization.json.JsonPrimitive

internal interface OfflineHarnessV1 {
    fun start(ordinal: Int, messages: List<ModelMessageV2>, resultsByTurn: Map<ValidatedResponsesTurnV1, List<ToolResultV2>>,
        sink: ModelEventV2Sink): OfflineTurnV1
    fun executeCompleted(response: ModelResponseV2, batch: BuiltinToolBatchV2, executor: ToolEffectExecutorV2): List<ToolResultV2>
}
internal interface OfflineTurnV1 { fun step(): OfflineHttpProgressV1; fun cancel() }

/** Actual A owns all accounting and tool authority. This test-only host owns serial offline work. */
internal class ChatGptPlanOfflineHarness(val ledger: AttemptLedgerV2, private val tokens: OfflinePlanTokenSourceV1,
    private val http: ChatGptPlanHttpV1, private val codec: ChatGptPlanRequestV1, private val secrets: ChatGptPlanSecretsV1,
    private val fence: OfflineInvocationFenceV1) : OfflineHarnessV1 {
    private val run = ledger.run
    private var active: Turn? = null
    private var busy = false
    private var sealed = false
    private var lastOrdinal = 0
    private val owned = IdentityHashMap<ValidatedResponsesTurnV1, ModelResponseV2>()
    private val results = IdentityHashMap<ValidatedResponsesTurnV1, List<ToolResultV2>>()
    private var executable: ModelResponseV2? = null
    private var publishedFence: OfflineInvocationStateV1? = null
    private var publishedRegistry = -1

    private fun enter() {
        if (busy) { active?.revoke(ModelFailureKind.INVALID_REQUEST); sealed = true; v2Fail() }
        busy = true
    }
    override fun start(ordinal: Int, messages: List<ModelMessageV2>, resultsByTurn: Map<ValidatedResponsesTurnV1, List<ToolResultV2>>,
        sink: ModelEventV2Sink): OfflineTurnV1 {
        enter()
        try {
            if (active != null || sealed) { active?.revoke(ModelFailureKind.INVALID_REQUEST); v2Fail() }
            v2Require(ordinal > lastOrdinal && ordinal <= run.budget.maxRequests)
            v2Capacity(messages.size <= 1024 && resultsByTurn.size <= 1024)
            val ms = messages.toList()
            val rs = IdentityHashMap<ValidatedResponsesTurnV1, List<ToolResultV2>>()
            for (m in ms) {
                v2Utf8Bytes(m.content, run.budget.contextBytes)
                m.continuation?.let { turn ->
                    val response = owned[turn] ?: v2Fail()
                    v2Require(m.content == response.text)
                }
            }
            for ((turn, list) in resultsByTurn) {
                val ours = results[turn] ?: v2Fail()
                v2Require(list.size == ours.size && list.indices.all { list[it] === ours[it] })
                rs[turn] = list.toList()
            }
            lastOrdinal = ordinal; executable = null
            return Turn(ordinal, ms, rs, sink).also { active = it }
        } catch (t: Throwable) { throw ModelProviderException(c3Kind(t)) }
        finally { busy = false }
    }
    override fun executeCompleted(response: ModelResponseV2, batch: BuiltinToolBatchV2, executor: ToolEffectExecutorV2): List<ToolResultV2> {
        enter()
        try {
            v2Require(!sealed && active == null && executable === response && owned[response.continuation] === response)
            v2Capacity(ledger.counters().requests < run.budget.maxRequests)
            fun fenceOnly() {
                val old = publishedFence ?: v2Fail()
                val s = fence.snapshot()
                if (sealed) v2Fail()
                if (s.cancelled) v2Fail(ModelFailureKind.CANCELLED)
                if (s.remainingNanos <= 0) v2Fail(ModelFailureKind.TIMEOUT)
                if (s.bindingCommitment != old.bindingCommitment || s.generation != old.generation || s.revision != old.revision) v2Fail(ModelFailureKind.AUTHORIZATION)
                if (secrets.registryRevision() != publishedRegistry) v2Fail(ModelFailureKind.SECRET_EXPOSURE)
            }
            ledger.requireCurrentSuccessful(response); fenceOnly()
            executable = null // consume before any authority callback
            val preview = batch.previewBatch(response); fenceOnly()
            val value = batch.execute(preview, ToolEffectExecutorV2 { proposal, effect, out ->
                // A just ran its final authority/deadline callbacks. No callback before this fence.
                fenceOnly(); executor.execute(proposal, effect, out)
            })
            run.deadline.remainingNanos(); fenceOnly()
            results[response.continuation] = value
            return value
        } catch (t: Throwable) { sealed = true; throw ModelProviderException(c3Kind(t)) }
        finally { busy = false }
    }

    private inner class Turn(val ordinal: Int, val messages: List<ModelMessageV2>,
        val priorResults: Map<ValidatedResponsesTurnV1, List<ToolResultV2>>, val sink: ModelEventV2Sink) : OfflineTurnV1 {
        private val original = fence.snapshot()
        private var generation = original.generation
        private var revision = secrets.registryRevision()
        private val lifetime = minOf(original.remainingNanos, v2Nanos(run.budget.overallTimeout))
        private var cancelled = false
        private var failure: ModelFailureKind? = null
        private var credential: OfflinePlanCredentialV1? = null
        private var renewed = false
        private var prepared: PreparedChatGptRequestV1? = null
        private var bytes: ByteArray? = null
        private var lease: ReservedLease? = null
        private var intent = false
        private var call: AdmittedModelCallV2? = null
        private var operation: OfflineHttpOperationV1? = null
        private var receipt: OfflineHttpProgressV1.Closed? = null
        private var settled = false
        private var finished: OfflineHttpProgressV1.Closed? = null
        private var starts = 0
        private var phase = 0 // acquire, catalog start, catalog, prepare/start, attempt, retry wait
        private var retryAtRemaining = 0L
        private var nextRenew = false
        fun revoke(kind: ModelFailureKind) { if (failure == null) failure = kind }
        override fun cancel() { cancelled = true; operation?.cancel() }
        private fun left(): Long = minOf(fence.snapshot().remainingNanos,
            maxOf(0L, lifetime - (original.remainingNanos - fence.snapshot().remainingNanos)))
        private fun pureCheck() {
            failure?.let { v2Fail(it) }
            if (sealed) v2Fail()
            val s = fence.snapshot()
            if (cancelled || s.cancelled) v2Fail(ModelFailureKind.CANCELLED)
            if (s.remainingNanos > original.remainingNanos || left() <= 0) v2Fail(ModelFailureKind.TIMEOUT)
            if (s.bindingCommitment != original.bindingCommitment || s.bindingCommitment != run.bindingCommitment ||
                s.generation != generation || s.revision != original.revision) v2Fail(ModelFailureKind.AUTHORIZATION)
            if (secrets.registryRevision() != revision) v2Fail(ModelFailureKind.SECRET_EXPOSURE)
        }
        private fun check() { run.deadline.remainingNanos(); pureCheck() }
        private inline fun <T> callback(action: () -> T): T { check(); val value = action(); check(); return value }
        private fun register(c: OfflinePlanCredentialV1) {
            check()
            tokens.registerFixtureSecrets(c, secrets)
            // Only this explicit registration boundary may add old/new synthetic credentials.
            revision = secrets.registryRevision()
            check()
        }
        private fun ready(c: OfflinePlanCredentialV1) {
            callback { c.requireFor(run); c.requireReadyScopes() }
            v2Require(c.generation == generation)
            credential = c; register(c); callback { tokens.recheck(run, c) }
        }
        private fun renew() {
            v2Require(!renewed && starts < run.budget.maxRetries + 1)
            check(); renewed = true
            val c = tokens.renew(run, generation)
            if (c.generation <= generation || c.binding.commitment() != run.bindingCommitment) v2Fail(ModelFailureKind.AUTHORIZATION)
            generation = c.generation
            check(); ready(c)
        }
        private fun clip() { (operation as? OfflineHttpLifetimeV1)?.clipLifetime(left()) ?: v2Fail(ModelFailureKind.UNSUPPORTED_FEATURE) }
        override fun step(): OfflineHttpProgressV1 {
            enter()
            try {
                finished?.let { return it }
                try {
                    check()
                    when (phase) {
                        0 -> {
                            when (val got = callback { tokens.acquire(run) }) {
                                is OfflineCredentialAcquisitionV1.Ready -> ready(got.credential)
                                is OfflineCredentialAcquisitionV1.Expired -> {
                                    if (got.bindingCommitment != run.bindingCommitment || got.generation != generation) v2Fail(ModelFailureKind.AUTHORIZATION)
                                    renew()
                                }
                            }
                            phase = 1
                        }
                        1 -> { callback { operation = http.catalog(run, credential!!) }; clip(); phase = 2 }
                        2 -> {
                            var progress: OfflineHttpProgressV1? = null
                            callback { progress = operation!!.step(); receipt = progress as? OfflineHttpProgressV1.Closed }
                            if (progress is OfflineHttpProgressV1.Pending) return progress
                            when (val value = receipt!!.value) {
                                is OfflineHttpValueV1.Catalog -> {
                                    callback { value.value.requireFor(credential!!); value.value.catalog.requireExactSlug(run.binding.modelSlug) }
                                    callback { tokens.recheck(run, credential!!) }
                                    operation = null; receipt = null; phase = 3
                                }
                                is OfflineHttpValueV1.CatalogFailure -> v2Fail(value.kind)
                                else -> v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
                            }
                        }
                        3 -> {
                            if (prepared == null) callback { prepared = codec.encode(run, messages, priorResults); bytes = prepared!!.encoded() }
                            v2Capacity(starts < run.budget.maxRetries + 1); starts++
                            val output = v2Subtract(run.budget.outputUnits, ledger.counters().output); v2Capacity(output > 0)
                            callback { lease = ledger.reserve(UUID.randomUUID(), ordinal, prepared!!.bytes, output) }
                            check(); intent = true
                            callback { ledger.markDispatchIntent(lease!!, ledger.durableSequence() + 1) }
                            callback { call = ledger.call(lease!!, bytes!!) }
                            callback { operation = http.exchange(call!!, credential!!, sink) }
                            clip(); phase = 4
                        }
                        4 -> {
                            var progress: OfflineHttpProgressV1? = null
                            callback { progress = operation!!.step(); receipt = progress as? OfflineHttpProgressV1.Closed }
                            if (progress is OfflineHttpProgressV1.Pending) return progress
                            return accept()
                        }
                        5 -> {
                            if (fence.snapshot().remainingNanos > retryAtRemaining) return OfflineHttpProgressV1.Pending(false)
                            if (nextRenew) { renew(); phase = 1 } else phase = 3
                        }
                    }
                } catch (t: Throwable) { revoke(c3Kind(t)) }
                if (failure != null) return cleanup()
                return OfflineHttpProgressV1.Pending(false)
            } finally { busy = false }
        }
        private fun settle(value: ChatGptAttemptResultV1) {
            v2Require(value.call === call && value.call.run === run && value.call.ordinal == ordinal && value.call.attempt == lease!!.attempt)
            if (settled) return
            // Record exactly once, including when a durability callback invalidates publication.
            if (value.outcome == AttemptOutcomeV2.AMBIGUOUS) ledger.markAmbiguous(lease!!, (value as? ChatGptAttemptResultV1.Stopped)?.kind)
            else ledger.settle(lease!!, value.local, value.reported, value.outcome, (value as? ChatGptAttemptResultV1.Stopped)?.kind)
            settled = true
        }
        private fun accept(): OfflineHttpProgressV1 {
            val value = (receipt!!.value as? OfflineHttpValueV1.Attempt) ?: v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
            val r = value.value
            v2Require((operation as? OfflineHttpAccountingV1)?.observedLocal == r.local)
            check(); settle(r)
            if (r.outcome != AttemptOutcomeV2.AMBIGUOUS && ledger.state() == LedgerStateV2.INDETERMINATE) v2Fail(ModelFailureKind.RESOURCE_EXHAUSTED)
            check()
            if (r is ChatGptAttemptResultV1.Completed && value.closeFailure == null) {
                callback { ledger.requireCurrentSuccessful(r.response) }
                callback { sink.emit(ModelEventV2.Finished(r.response.finishReason)) }
                // Last callback is complete; only callback-free primitive/registry reads before unwrap.
                pureCheck()
                owned[r.response.continuation] = r.response
                executable = r.response; publishedFence = fence.snapshot(); publishedRegistry = revision
                active = null; finished = receipt; return receipt!!
            }
            val recovery = (operation as? OfflineHttpRetryV1)?.retry ?: ChatGptRecoveryV1.STOP
            if (r is ChatGptAttemptResultV1.Stopped && !r.validatedTerminal && r.outcome == AttemptOutcomeV2.FAILED &&
                value.closeFailure == null && recovery != ChatGptRecoveryV1.STOP && starts < run.budget.maxRetries + 1 && ledger.state() == LedgerStateV2.READY) {
                nextRenew = recovery == ChatGptRecoveryV1.ONE_RENEWAL_IF_ELIGIBLE
                if (!nextRenew || !renewed) {
                    val delay = maxOf(minOf(2_000_000_000L, 250_000_000L * (1L shl (starts - 1))),
                        (operation as OfflineHttpRetryV1).retryMinimumNanos)
                    if (delay <= 30_000_000_000L && delay < left()) {
                        retryAtRemaining = fence.snapshot().remainingNanos - delay
                        lease = null; call = null; operation = null; receipt = null; settled = false; intent = false
                        phase = 5; return OfflineHttpProgressV1.Pending(false)
                    }
                }
            }
            sealed = true; active = null; finished = receipt; return receipt!!
        }
        private fun cleanup(): OfflineHttpProgressV1 {
            val op = operation
            fun withheld(): OfflineHttpProgressV1.Closed? {
                val hidden = (op as? OfflineClosedFailureOwnerV1)?.withheld ?: return null
                v2Require(hidden.call === call && hidden.call.run === run && (op as? OfflineHttpAccountingV1)?.observedLocal == hidden.local)
                if (!settled) {
                    if (hidden.outcome == AttemptOutcomeV2.AMBIGUOUS) ledger.markAmbiguous(lease!!, hidden.terminalKind)
                    else ledger.settle(lease!!, hidden.local, hidden.reported, hidden.outcome, hidden.terminalKind)
                    settled = true
                }
                sealed = true; executable = null; active = null
                return OfflineHttpProgressV1.Closed(OfflineHttpValueV1.CatalogFailure(hidden.failure)).also { finished = it }
            }
            withheld()?.let { return it }
            if (op != null && receipt == null) {
                op.cancel()
                val progress = try { op.step() } catch (_: Throwable) { return withheld() ?: OfflineHttpProgressV1.Pending(true) }
                if (progress is OfflineHttpProgressV1.Pending) return progress
                receipt = progress as OfflineHttpProgressV1.Closed
            }
            var value = (receipt?.value as? OfflineHttpValueV1.Attempt)?.value
            if (value != null && !settled) {
                if (value is ChatGptAttemptResultV1.Completed) value = ChatGptAttemptResultV1.Stopped(value.call, value.local, value.reported,
                    if (failure == ModelFailureKind.CANCELLED) AttemptOutcomeV2.CANCELLED else AttemptOutcomeV2.FAILED,
                    failure!!, true, c3Diagnostic(failure!!))
                try { settle(value) } catch (_: Throwable) { /* A remains sealed/owns uncertain publication. */ }
            } else if (intent && lease != null && !settled) {
                // No fabricated call/lease/refund on reserve or intent publication failures.
                try { ledger.markAmbiguous(lease!!, failure); settled = true } catch (_: Throwable) { }
            }
            sealed = true; executable = null
            val stopped = value?.let { r ->
                if (r is ChatGptAttemptResultV1.Completed) ChatGptAttemptResultV1.Stopped(r.call, r.local, r.reported,
                    AttemptOutcomeV2.FAILED, failure!!, true, c3Diagnostic(failure!!)) else r
            }
            // Settlement and Finished callbacks may register secrets after the HTTP owner's scan.
            // Recheck the final diagnostic without callbacks; withholding it never changes A's
            // original settlement/usage and never restores response or tool authority.
            val diagnosticSafe = if (stopped is ChatGptAttemptResultV1.Stopped) {
                try { secrets.rejectCredentialsInPrivateJson(JsonPrimitive(stopped.diagnostic.render())); true }
                catch (_: Throwable) { false }
            } else true
            val out = if (stopped != null && diagnosticSafe) OfflineHttpValueV1.Attempt(stopped, (receipt?.value as? OfflineHttpValueV1.Attempt)?.closeFailure)
                else if (!diagnosticSafe) OfflineHttpValueV1.CatalogFailure(ModelFailureKind.SECRET_EXPOSURE)
                else OfflineHttpValueV1.CatalogFailure(failure ?: ModelFailureKind.TRANSPORT)
            // Keep this Turn as the harness's retained owner for unreturned reservation/intent state.
            if (ledger.state() != LedgerStateV2.ACTIVE && ledger.state() != LedgerStateV2.INDETERMINATE) active = null
            return OfflineHttpProgressV1.Closed(out).also { finished = it }
        }
    }
}
