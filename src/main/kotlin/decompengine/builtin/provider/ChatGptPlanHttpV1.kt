package decompengine.builtin.provider

import decompengine.builtin.*
import kotlinx.serialization.json.JsonPrimitive
import java.io.ByteArrayOutputStream
import java.time.Instant
import java.util.Collections

/** Offline contracts only. No registered provider or concrete network/token/fence adapter. */
internal enum class OfflineEndpointV1 { MODELS, RESPONSES }
internal enum class OfflineSendFactV1 { NEVER_DISPATCHED, SCRIPTED_ZERO_SEND, POSSIBLY_SENT, SENT }
internal data class OfflineDeliveryFactsV1(val send: OfflineSendFactV1, val requestEntityBytes: Long, val responseEntityBytes: Long) {
    init { v2Require(requestEntityBytes >= 0 && responseEntityBytes >= 0) }
    override fun toString() = "OfflineDeliveryFactsV1(redacted)"
}
internal class OfflineHeadersV1(val status: Int, fields: List<Pair<String, String>>) {
    val fields: List<Pair<String, String>>
    init {
        v2Require(status in 100..599)
        v2Capacity(fields.size <= ChatGptHeaderMetadataV1.MAX_FIELDS)
        var bytes = 0L
        fields.forEach { (name, value) ->
            bytes = v2Add(bytes, v2Add(v2Utf8Bytes(name, 128), v2Add(v2Utf8Bytes(value, 4096), 4)))
            v2Capacity(bytes <= 16384)
        }
        ChatGptHeaderMetadataV1.fromHeaders(fields, Instant.EPOCH)
        this.fields = Collections.unmodifiableList(fields.map { it.first to it.second })
    }
    override fun toString() = "OfflineHeadersV1(redacted)"
}
internal enum class OfflineCloseFactV1 { CLOSED, RETAINED }
internal data class OfflineCloseV1(val fact: OfflineCloseFactV1, val failure: ModelFailureKind?) {
    init { v2Require(failure == null || failure == ModelFailureKind.TRANSPORT) }
    override fun toString() = "OfflineCloseV1(redacted)"
}
internal interface OfflineHttpPortV1 { fun allocate(): OfflineHttpExchangeV1 }
internal interface OfflineHttpExchangeV1 {
    fun dispatch(endpoint: OfflineEndpointV1, bearer: OfflineBearerV1, entity: ByteArray?, timeouts: CallTimeoutsV2)
    fun headers(maxWaitNanos: Long): OfflineHeadersV1?
    fun read(into: ByteArray, demand: Int, maxWaitNanos: Long): Int
    fun delivery(): OfflineDeliveryFactsV1
    fun closeStep(maxWaitNanos: Long): OfflineCloseV1
}
internal data class OfflineInvocationStateV1(val remainingNanos: Long, val cancelled: Boolean,
    val bindingCommitment: String, val generation: Long, val revision: Long) {
    init { v2Require(remainingNanos >= 0 && generation >= 0 && revision >= 0 && bindingCommitment.matches(Regex("[a-f0-9]{64}"))) }
    override fun toString() = "OfflineInvocationStateV1(redacted)"
}
/** Trusted callback-free bounded fixture snapshot, NOT production identity authority. */
internal interface OfflineInvocationFenceV1 { fun snapshot(): OfflineInvocationStateV1 }
internal sealed interface OfflineHttpValueV1 {
    class Catalog(val value: ChatGptCatalogSnapshotV1) : OfflineHttpValueV1
    class Attempt(val value: ChatGptAttemptResultV1, val closeFailure: ModelFailureKind? = null) : OfflineHttpValueV1
    class CatalogFailure(val kind: ModelFailureKind) : OfflineHttpValueV1
}
internal sealed interface OfflineHttpProgressV1 {
    class Pending(val closing: Boolean) : OfflineHttpProgressV1
    class Closed(val value: OfflineHttpValueV1) : OfflineHttpProgressV1
}
internal interface OfflineHttpOperationV1 { fun step(): OfflineHttpProgressV1; fun cancel() }
internal interface ChatGptPlanHttpV1 {
    fun catalog(run: AdmittedModelRunV2, credential: OfflinePlanCredentialV1): OfflineHttpOperationV1
    fun exchange(call: AdmittedModelCallV2, credential: OfflinePlanCredentialV1, sink: ModelEventV2Sink): OfflineHttpOperationV1
}
/** Callback-free metadata, usable only after Closed. It supplies no definitely-unsent authority. */
internal interface OfflineHttpAccountingV1 { val observedLocal: ObservedLocalCountersV2? }
internal interface OfflineHttpLifetimeV1 { fun clipLifetime(remainingNanos: Long) }
internal interface OfflineHttpRetryV1 {
    val retry: ChatGptRecoveryV1
    val retryMinimumNanos: Long
}

/** A physically closed, withheld diagnostic still supplies accounting, never response/tool authority. */
internal class OfflineClosedFailureV1(val call: AdmittedModelCallV2, val local: ObservedLocalCountersV2,
    val reported: ReportedModelUsageV1?, val outcome: AttemptOutcomeV2, val terminalKind: ModelFailureKind,
    val failure: ModelFailureKind) {
    override fun toString() = "OfflineClosedFailureV1(redacted)"
}
internal interface OfflineClosedFailureOwnerV1 { val withheld: OfflineClosedFailureV1? }

internal fun c3Kind(t: Throwable): ModelFailureKind = (t as? ModelProviderException)?.kind ?: ModelFailureKind.TRANSPORT
internal fun c3Diagnostic(kind: ModelFailureKind) = ChatGptSafeDiagnosticV1.create(kind, null,
    ChatGptBodyShapeV1.OTHER, ChatGptSafeCodeV1.UNKNOWN, ChatGptSafeParamV1.OTHER, ChatGptRecoveryV1.STOP, null)

/** Serial explicit-step reducer. A returned RETAINED handle remains owned by this same operation. */
internal class BoundedChatGptPlanHttpV1(private val io: OfflineHttpPortV1, private val tokens: OfflinePlanTokenSourceV1,
    private val secrets: ChatGptPlanSecretsV1, private val fence: OfflineInvocationFenceV1,
    private val wallNow: () -> Instant) : ChatGptPlanHttpV1 {
    private var active: Operation? = null
    private var ownerRun: AdmittedModelRunV2? = null
    private var sideband = 0L
    override fun catalog(run: AdmittedModelRunV2, credential: OfflinePlanCredentialV1): OfflineHttpOperationV1 =
        create(run, null, credential, ModelEventV2Sink {})
    override fun exchange(call: AdmittedModelCallV2, credential: OfflinePlanCredentialV1, sink: ModelEventV2Sink): OfflineHttpOperationV1 =
        create(call.run, call, credential, sink)
    private fun create(run: AdmittedModelRunV2, call: AdmittedModelCallV2?, credential: OfflinePlanCredentialV1, sink: ModelEventV2Sink): Operation {
        active?.let { it.revoke(ModelFailureKind.INVALID_REQUEST); v2Fail() }
        v2Require(ownerRun == null || ownerRun === run)
        ownerRun = run
        return Operation(run, call, credential, sink).also { active = it }
    }

    private inner class Operation(val run: AdmittedModelRunV2, val call: AdmittedModelCallV2?,
        val credential: OfflinePlanCredentialV1, val sink: ModelEventV2Sink) : OfflineHttpOperationV1, OfflineHttpRetryV1, OfflineHttpLifetimeV1, OfflineClosedFailureOwnerV1, OfflineHttpAccountingV1 {
        override val observedLocal: ObservedLocalCountersV2? get() = if (phase == 4) observed() else null
        private val initial = fence.snapshot()
        private val registry = secrets.registryRevision()
        override var withheld: OfflineClosedFailureV1? = null; private set
        private var busy = false
        private var cancelled = false
        private var failure: ModelFailureKind? = null
        private var closeFailure: ModelFailureKind? = null
        private var phase = 0 // 0 dispatch, 1 headers, 2 body, 3 closing, 4 closed
        private var handle: OfflineHttpExchangeV1? = null
        private var session: ChatGptResponsesSessionV1? = null
        private var terminal: ChatGptAttemptResultV1? = null
        private var catalog: ChatGptCatalogSnapshotV1? = null
        private var result: OfflineHttpProgressV1.Closed? = null
        private var terminalRevision: Int? = null
        private var headers: OfflineHeadersV1? = null
        private var metadata: ChatGptHeaderMetadataV1? = null
        private var contentLength: Long? = null
        private var entity: ByteArray? = null
        private val buffer = ByteArray(8192)
        private var body: ByteArrayOutputStream? = null
        private var wire = 0L
        private var lastFacts = OfflineDeliveryFactsV1(OfflineSendFactV1.NEVER_DISPATCHED, 0, 0)
        private var lastArrival = initial.remainingNanos
        private val queue = ArrayDeque<ModelEventV2.TextDelta>()
        private var queuedBytes = 0L
        override var retry = ChatGptRecoveryV1.STOP; private set
        override var retryMinimumNanos = 0L; private set
        private var overallLimit = Long.MAX_VALUE
        override fun clipLifetime(remainingNanos: Long) {
            v2Require(!busy && phase == 0 && remainingNanos > 0)
            overallLimit = minOf(overallLimit, remainingNanos)
        }
        private val timeouts = call?.timeouts ?: CallTimeoutsV2(v2Nanos(run.budget.overallTimeout),
            v2Nanos(run.budget.connectTimeout), v2Nanos(run.budget.requestTimeout), v2Nanos(run.budget.idleTimeout))

        fun revoke(kind: ModelFailureKind) { if (failure == null) failure = kind }
        override fun cancel() { cancelled = true }
        private fun pureCheck() {
            failure?.let { v2Fail(it) }
            val s = fence.snapshot()
            if (cancelled || s.cancelled) v2Fail(ModelFailureKind.CANCELLED)
            if (s.bindingCommitment != run.bindingCommitment || s.bindingCommitment != initial.bindingCommitment ||
                s.revision != initial.revision || s.generation != credential.generation) v2Fail(ModelFailureKind.AUTHORIZATION)
            if (s.remainingNanos <= 0 || s.remainingNanos > initial.remainingNanos ||
                initial.remainingNanos - s.remainingNanos >= minOf(timeouts.overallNanos, overallLimit)) v2Fail(ModelFailureKind.TIMEOUT)
            if (secrets.registryRevision() != (terminalRevision ?: registry)) v2Fail(ModelFailureKind.SECRET_EXPOSURE)
        }
        private fun check() { run.deadline.remainingNanos(); pureCheck() }
        private inline fun <T> callback(block: () -> T): T { check(); val v = block(); check(); return v }
        private fun waitSlice(): Long = minOf(25_000_000L, fence.snapshot().remainingNanos,
            maxOf(0, minOf(timeouts.overallNanos, overallLimit) - (initial.remainingNanos - fence.snapshot().remainingNanos)))
        private fun observed(): ObservedLocalCountersV2 {
            val o = session?.observed() ?: ObservedLocalCountersV2()
            return o.copy(wireBytes = maxOf(wire, o.wireBytes))
        }
        private fun discard() { queue.clear(); queuedBytes = 0; session?.discard() }
        private fun capture() {
            // Only final field reads and trusted primitive snapshots; no vendor/parent calls here.
            synchronized(secrets) {
                session?.terminalResult()?.let { terminal = it; terminalRevision = secrets.registryRevision() }
            }
        }
        private fun fail(t: Throwable) {
            revoke(c3Kind(t)); retry = ChatGptRecoveryV1.STOP; discard(); phase = 3
        }
        override fun step(): OfflineHttpProgressV1 {
            if (busy) { revoke(ModelFailureKind.INVALID_REQUEST); v2Fail() }
            withheld?.let { throw ModelProviderException(it.failure) }
            result?.let { return it }
            busy = true
            try {
                if (phase == 3) return close()
                try {
                    check()
                    when (phase) {
                        0 -> dispatch()
                        1 -> readHeaders()
                        2 -> readBody()
                    }
                } catch (t: Throwable) { fail(t) }
                return OfflineHttpProgressV1.Pending(phase == 3)
            } finally { busy = false }
        }
        private fun dispatch() {
            callback { credential.requireFor(run); credential.requireReadyScopes() }
            val now = callback { wallNow() }
            if (!credential.expiresAt.isAfter(now)) v2Fail(ModelFailureKind.AUTHENTICATION)
            callback { tokens.recheck(run, credential) }
            if (call != null) {
                entity = callback { PreparedChatGptRequestV1.fromAdmittedCall(call, secrets).encoded() }
                callback { session = ChatGptPlanResponsesV1.start(call, secrets, ModelEventV2Sink { event ->
                    // C2 may hold its own registry monitor. This bridge has NO outward calls.
                    val text = event as? ModelEventV2.TextDelta ?: v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
                    val n = v2Utf8Bytes(text.text, minOf(run.budget.responseBytes, run.budget.displayedBytesTotal))
                    val next = v2Add(queuedBytes, n)
                    v2Capacity(next <= minOf(run.budget.responseBytes, run.budget.displayedBytesTotal) && queue.size < 4096)
                    queue.addLast(ModelEventV2.TextDelta(text.text)); queuedBytes = next
                }) }
            }
            check()
            // allocate is specified inert/callback-free. Assign ownership BEFORE any subsequent check.
            handle = io.allocate()
            check()
            val left = minOf(fence.snapshot().remainingNanos, minOf(timeouts.overallNanos, overallLimit) - (initial.remainingNanos - fence.snapshot().remainingNanos))
            val clipped = CallTimeoutsV2(left, minOf(left, timeouts.connectNanos), minOf(left, timeouts.requestNanos), minOf(left, timeouts.idleNanos))
            callback { handle!!.dispatch(if (call == null) OfflineEndpointV1.MODELS else OfflineEndpointV1.RESPONSES,
                credential.bearer, entity, clipped) }
            facts(); phase = 1
        }
        private fun facts(expectedWire: Long = wire) {
            val f = handle!!.delivery() // contractual callback-free observation, not refund authority
            val size = entity?.size?.toLong() ?: 0
            if (f.requestEntityBytes !in lastFacts.requestEntityBytes..size || f.responseEntityBytes != expectedWire ||
                f.send.ordinal < lastFacts.send.ordinal ||
                (f.send in setOf(OfflineSendFactV1.NEVER_DISPATCHED, OfflineSendFactV1.SCRIPTED_ZERO_SEND) && f.requestEntityBytes != 0L) ||
                (f.send == OfflineSendFactV1.SENT && f.requestEntityBytes != size)) v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
            lastFacts = f
        }
        private fun readHeaders() {
            if (initial.remainingNanos - fence.snapshot().remainingNanos >= minOf(timeouts.connectNanos, timeouts.requestNanos)) v2Fail(ModelFailureKind.TIMEOUT)
            val h = callback { handle!!.headers(waitSlice()) } ?: return
            facts(); headers = h
            metadata = callback { ChatGptHeaderMetadataV1.fromHeaders(h.fields, callback { wallNow() }) }
            val cap = cap()
            fun values(name: String) = h.fields.filter { it.first.equals(name, true) }.map { it.second.trim() }
            val enc = values("content-encoding")
            if (enc.size > 1 || enc.any { !it.equals("identity", true) }) v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
            val lengths = values("content-length")
            if (lengths.size > 1) v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
            lengths.singleOrNull()?.let {
                if (it.isEmpty() || it.any { c -> c !in '0'..'9' }) v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
                contentLength = it.toLongOrNull() ?: v2Fail(ModelFailureKind.RESOURCE_EXHAUSTED)
                v2Capacity(contentLength!! <= cap)
            }
            val mime = values("content-type")
            if (mime.size > 1) v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
            if (h.status == 200) {
                val expected = if (call == null) "application/json" else "text/event-stream"
                if (mime.isEmpty() && call == null) v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
                mime.singleOrNull()?.let {
                    if (!Regex("$expected(?:\\s*;\\s*charset=(?:utf-8|\"utf-8\"))?", RegexOption.IGNORE_CASE).matches(it)) v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
                }
            }
            if (call == null || h.status != 200) body = ByteArrayOutputStream(minOf(8192, cap.toInt()))
            phase = 2
        }
        private fun cap(): Long = if (headers?.status != 200) ChatGptPlanErrorsV1.MAX_BODY_BYTES.toLong()
            else if (call == null) ChatGptCatalogV1.MAX_BODY_BYTES.toLong() else run.budget.responseBytes
        private fun readBody() {
            val elapsed = initial.remainingNanos - fence.snapshot().remainingNanos
            if (elapsed >= timeouts.requestNanos || lastArrival - fence.snapshot().remainingNanos >= timeouts.idleNanos) v2Fail(ModelFailureKind.TIMEOUT)
            val demand = if (call != null && headers!!.status == 200) callback { session!!.readDemand() }
                else minOf(8192L, maxOf(1, cap() - wire + 1), if (call == null) maxOf(1, 2L * 1024 * 1024 - sideband + 1) else 8192).toInt()
            v2Require(demand in 1..8192)
            check()
            val n = handle!!.read(buffer, demand, waitSlice())
            if (n !in -1..demand) v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
            // Arrival precedes post-read cancellation/deadline checks, including those in A's meter.
            if (n > 0) {
                val arrived = v2Add(wire, n.toLong())
                facts(arrived)
                wire = arrived
                if (call == null) { sideband = v2Add(sideband, n.toLong()); v2Capacity(sideband <= 2L * 1024 * 1024) }
                else call.meter.beforeDelivery(observed())
                lastArrival = fence.snapshot().remainingNanos
            } else facts()
            check()
            v2Capacity(wire <= cap())
            if (contentLength != null && wire > contentLength!!) v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
            if (n == 0) return
            if (n == -1) {
                if (contentLength != null && wire != contentLength) v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
                if (call != null && headers!!.status == 200) {
                    check(); session!!.endOfInput(); capture(); check()
                } else finishBody()
                phase = 3; return
            }
            if (call != null && headers!!.status == 200) {
                check(); session!!.feed(buffer, 0, n); capture(); check()
                if (terminal != null) {
                    if (contentLength != null && wire != contentLength) v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
                    phase = 3 // do not drain final text until CLOSED
                } else drain()
            } else body!!.write(buffer, 0, n)
        }
        private fun finishBody() {
            val bytes = body!!.toByteArray()
            if (headers!!.status != 200) {
                val decision = callback { ChatGptPlanErrorsV1.classify(headers!!.status, metadata!!, bytes, false, false) }
                callback { secrets.rejectCredentialsInPrivateJson(JsonPrimitive(decision.diagnostic.render())) }
                retry = decision.recovery; retryMinimumNanos = metadata!!.retryAfterMinimumNanos ?: 0
                if (call != null) terminal = ChatGptAttemptResultV1.Stopped(call, observed(), null,
                    AttemptOutcomeV2.FAILED, decision.kind, false, decision.diagnostic)
                else failure = decision.kind
                terminalRevision = secrets.registryRevision()
            } else {
                val parsed = callback { ChatGptCatalogV1.parse(bytes) }
                callback { parsed.models.forEach { secrets.rejectCredentialsInPrivateJson(JsonPrimitive(it.slug)); secrets.rejectCredentialsInPrivateJson(JsonPrimitive(it.displayName)) } }
                catalog = ChatGptCatalogSnapshotV1(run.bindingCommitment, credential.generation, parsed)
                terminalRevision = secrets.registryRevision()
            }
            body = null
        }
        private fun drain() {
            while (queue.isNotEmpty()) {
                val event = queue.removeFirst(); queuedBytes -= v2Utf8Bytes(event.text, run.budget.displayedBytesTotal)
                callback { sink.emit(event) }
            }
        }
        private fun close(): OfflineHttpProgressV1 {
            // Deadline/fence failure must not abandon cleanup, nor erase known terminal usage.
            try { check() } catch (t: Throwable) { revoke(c3Kind(t)); retry = ChatGptRecoveryV1.STOP; discard() }
            val h = handle
            if (h != null) {
                val ack = try { h.closeStep(waitSlice()) } catch (_: Throwable) {
                    closeFailure = ModelFailureKind.TRANSPORT; retry = ChatGptRecoveryV1.STOP
                    discard(); return OfflineHttpProgressV1.Pending(true)
                }
                if (ack.failure != null) { closeFailure = ModelFailureKind.TRANSPORT; retry = ChatGptRecoveryV1.STOP; discard() }
                try { check() } catch (t: Throwable) { revoke(c3Kind(t)); retry = ChatGptRecoveryV1.STOP; discard() }
                if (ack.fact == OfflineCloseFactV1.RETAINED) return OfflineHttpProgressV1.Pending(true)
                handle = null // only physical CLOSED transfers out of handle ownership
            }
            try {
                if (failure == null && closeFailure == null) {
                    callback { tokens.recheck(run, credential) }
                    drain()
                    check()
                }
            } catch (t: Throwable) { fail(t) }
            val kind = closeFailure ?: failure
            val value: OfflineHttpValueV1 = if (call == null) {
                if (kind == null && catalog != null) OfflineHttpValueV1.Catalog(catalog!!)
                else OfflineHttpValueV1.CatalogFailure(kind ?: ModelFailureKind.TRANSPORT)
            } else {
                val old = terminal
                val r = when {
                    old is ChatGptAttemptResultV1.Stopped && old.validatedTerminal -> old
                    old != null && kind == null && !(old is ChatGptAttemptResultV1.Completed && old.response.finishReason == ModelFinishReason.REFUSED) -> old
                    old != null -> ChatGptAttemptResultV1.Stopped(call, observed(), old.reported,
                        if (kind == ModelFailureKind.CANCELLED) AttemptOutcomeV2.CANCELLED else AttemptOutcomeV2.FAILED,
                        kind ?: ModelFailureKind.UNSUPPORTED_FEATURE, old is ChatGptAttemptResultV1.Completed || (old as? ChatGptAttemptResultV1.Stopped)?.validatedTerminal == true,
                        c3Diagnostic(kind ?: ModelFailureKind.UNSUPPORTED_FEATURE))
                    else -> ChatGptAttemptResultV1.Stopped(call, observed(), null, AttemptOutcomeV2.AMBIGUOUS,
                        kind ?: ModelFailureKind.TRANSPORT, false, c3Diagnostic(kind ?: ModelFailureKind.TRANSPORT))
                }
                OfflineHttpValueV1.Attempt(r, closeFailure)
            }
            if (value is OfflineHttpValueV1.Attempt && value.value is ChatGptAttemptResultV1.Stopped) {
                val stopped = value.value
                try {
                    if (failure == ModelFailureKind.SECRET_EXPOSURE && (terminal as? ChatGptAttemptResultV1.Stopped)?.validatedTerminal == true) v2Fail(ModelFailureKind.SECRET_EXPOSURE)
                    secrets.rejectCredentialsInPrivateJson(JsonPrimitive(stopped.diagnostic.render()))
                }
                catch (t: Throwable) {
                    // Never let even a fixed diagnostic collide with a newly registered secret.
                    // Accounting remains available as primitive totals, without the unsafe diagnostic.
                    withheld = OfflineClosedFailureV1(stopped.call, stopped.local, stopped.reported,
                        stopped.outcome, stopped.kind, c3Kind(t))
                    discard(); phase = 4; active = null
                    throw ModelProviderException(c3Kind(t))
                }
            }
            // No arbitrary callbacks after this point. Registry revision and fixture state are pure.
            // Completed candidates have passed the final callback-bearing check above.
            discard(); phase = 4; active = null
            return OfflineHttpProgressV1.Closed(value).also { result = it }
        }
    }
}
