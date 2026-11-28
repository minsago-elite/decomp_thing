package decompengine.chatgpt

import java.time.Duration
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.net.http.HttpRequest
import java.net.http.HttpResponse
internal abstract class ChatGptAuthCodeReceiver : ChatGptAuthSafeObject() {
    abstract fun await(attempt: ChatGptPlanOAuthAttempt): ChatGptPlanOAuthAttempt.CallbackResult
}
internal abstract class ChatGptAuthCodeBinding : ChatGptAuthSafeObject() {
    abstract fun authorizationRequest(): ChatGptPlanOAuthAttempt.AuthorizationRequest
    // Invokes receiver with the ONE internally constructed attempt. Caches exact Code
    // reference from that return; no independently supplied Code/snapshot setter exists.
    abstract fun receiveCode(receiver: ChatGptAuthCodeReceiver): ChatGptPlanOAuthAttempt.CallbackResult
    internal abstract fun claimCode(
        code: ChatGptPlanOAuthAttempt.CallbackResult.Code, operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline,
    ): HttpRequest
    internal abstract fun prove(
        bytes: ByteArray, keys: ChatGptOidcJwks, receivedAt: Instant, validatedAt: Instant,
        operation: ChatGptStoreOperation, jwksAlreadyRefetched: Boolean,
    ): ChatGptAuthorizationProof
    // Code factory checks exact reference identity and consumes one call reservation.
    // Private implementation also holds original snapshot/attempt and operation authority.
}
internal abstract class ChatGptAuthMetadata : ChatGptAuthSafeObject() {
    abstract fun bindAuthorization(
        snapshot: ChatGptAuthorizationSnapshot,
        redirect: ChatGptPlanOAuthRedirect,
        clock: ChatGptPlanOAuthClock,
        random: ChatGptPlanOAuthRandom,
        cancellation: ChatGptPlanOAuthCancellation,
        operation: ChatGptStoreOperation,
    ): ChatGptAuthCodeBinding
    abstract fun discovery(operation: ChatGptStoreOperation): ChatGptOidcDiscovery
    abstract fun validateAuthorization(
        reply: ChatGptAuthTokenReply, operation: ChatGptStoreOperation,
    ): ChatGptAuthorizationProof
    // A3 primitives needed for EXACT future refresh composition; no renewal result types.
    abstract fun keys(operation: ChatGptStoreOperation): ChatGptAuthKeysUse
    abstract fun shutdown(maxWaitNanos: Long): ChatGptAuthSettlement
}
internal abstract class ChatGptAuthKeysUse : ChatGptAuthSafeObject() {
    abstract val document: ChatGptOidcJwks
    // One explicit unknown-kid repair per validation. Concurrent callers share a generation.
    // Calling twice is terminal UNKNOWN_KEY. Replacement carries refetched=true.
    abstract val refetched: Boolean
    abstract fun refetchUnknown(operation: ChatGptStoreOperation): ChatGptAuthKeysUse
    abstract fun close()
}


internal fun newChatGptAuthMetadata(
    transport: ChatGptAuthTransport, monotonicNanos: () -> Long, wallNow: () -> Instant,
): ChatGptAuthMetadata = AuthMetadata(transport, ChatGptDeadlineClock.SYSTEM, monotonicNanos, wallNow)
internal fun newChatGptAuthMetadata(
    transport: ChatGptAuthTransport, deadlineClock: ChatGptDeadlineClock, monotonicProbe: () -> Long, wallNow: () -> Instant,
): ChatGptAuthMetadata = AuthMetadata(transport, deadlineClock, monotonicProbe, wallNow)

internal fun isMetadataCodeBinding(binding: ChatGptAuthCodeBinding): Boolean = binding is CodeBinding
internal fun discardMetadataCodeBinding(binding: ChatGptAuthCodeBinding) {
    if (binding is CodeBinding) binding.discard()
}
internal fun isMetadataKeysUse(use: ChatGptAuthKeysUse): Boolean = use is KeysUse
internal fun checkMetadataKeysUse(use: ChatGptAuthKeysUse, operation: ChatGptStoreOperation) {
    if (use !is KeysUse) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
    use.checkValidation(operation)
}
internal fun reserveMetadataKeysUse(use: ChatGptAuthKeysUse, reply: ChatGptAuthTokenReply, operation: ChatGptStoreOperation) {
    if (use !is KeysUse || !isTransportReplyValidation(reply, operation)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
    use.reserve(reply, operation)
}
internal fun isMetadataRevocationEndpoint(endpoint: ChatGptAuthRevocationEndpoint): Boolean = endpoint is ExpiringEndpoint
internal fun isLiveChatGptRevocationEndpoint(endpoint: ChatGptAuthRevocationEndpoint): Boolean =
    endpoint is ExpiringEndpoint && endpoint.live()

/** Snapshot provenance and receiver/attempt correspondence belong to the trusted parent A1/A2 adapters. */
private class CodeBinding(
    private var snapshot: ChatGptAuthorizationSnapshot?, private var attempt: ChatGptPlanOAuthAttempt?,
    private val cancellation: ChatGptPlanOAuthCancellation, private val metadata: AuthMetadata,
    private val serviceLive: () -> Boolean,
) : ChatGptAuthCodeBinding() {
    private var receiving = false
    private var reserved = false
    private var code: ChatGptPlanOAuthAttempt.CallbackResult.Code? = null
    private var exchange: ChatGptStoreOperation? = null
    private var closed = false
    private fun checkOpen() {
        if (closed) authFail(ChatGptAuthHttpFailure.CANCELLED)
    }
    // Trusted helpers may block or reenter. Only private state is inspected under
    // this monitor, so revocation never waits for one of those callbacks.
    private fun active() {
        synchronized(this) { checkOpen() }
        if (!serviceLive() || cancellation.isCancelled()) authFail(ChatGptAuthHttpFailure.CANCELLED)
        synchronized(this) { checkOpen() }
    }
    override fun authorizationRequest(): ChatGptPlanOAuthAttempt.AuthorizationRequest = metadata.boundary {
        try {
            val own = synchronized(this) { checkOpen(); attempt!! }
            active()
            own.authorizationRequest().also { active() }
        } catch (e: Exception) { discard(); throw e }
    }
    override fun receiveCode(receiver: ChatGptAuthCodeReceiver): ChatGptPlanOAuthAttempt.CallbackResult = metadata.boundary {
        val own = synchronized(this) {
            checkOpen()
            if (receiving) authFail(ChatGptAuthHttpFailure.ALREADY_USED)
            receiving = true; attempt!!
        }
        try {
            active()
            val result = receiver.await(own)
            active()
            synchronized(this) {
                checkOpen()
                if (result is ChatGptPlanOAuthAttempt.CallbackResult.Code) code = result
            }
            if (result !is ChatGptPlanOAuthAttempt.CallbackResult.Code) discard()
            result
        } catch (e: Exception) { discard(); throw e }
    }
    override fun claimCode(code: ChatGptPlanOAuthAttempt.CallbackResult.Code,
        operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline): HttpRequest = metadata.boundary(operation) {
        try {
            authHttpCheck(operation, httpDeadline)
            synchronized(this) {
                checkOpen()
                if (reserved) authFail(ChatGptAuthHttpFailure.ALREADY_USED)
                if (this.code !== code) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
                reserved = true; exchange = operation
            }
            active()
            authCodeRequest(code, operation, httpDeadline).also { active(); authHttpCheck(operation, httpDeadline); synchronized(this) { checkOpen() } }
        }
        catch (e: Exception) { discard(); throw e }
    }
    override fun prove(bytes: ByteArray, keys: ChatGptOidcJwks, receivedAt: Instant,
        validatedAt: Instant, operation: ChatGptStoreOperation, jwksAlreadyRefetched: Boolean): ChatGptAuthorizationProof = metadata.activity(operation) {
        val captured = synchronized(this) {
            checkOpen()
            if (!reserved || exchange !== operation || code == null || !isOidcJwks(keys)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
            Pair(snapshot!!, code!!)
        }
        active()
        ChatGptPlanOidc.validateAuthorizationProof(bytes, keys, captured.first, captured.second, receivedAt, validatedAt,
            operation, jwksAlreadyRefetched).also { active(); operation.check(); synchronized(this) { checkOpen() } }
    }
    @Synchronized fun discard() { closed = true; code = null; attempt = null; snapshot = null; exchange = null }
}

private class MetadataRecord(
    val generation: Long, val origin: Long, val policy: ChatGptAuthDocumentCachePolicy,
    val document: ChatGptAuthSafeObject,
) {
    // Policy is factory checked before construction; copy its numeric values outside service locks.
    val reusable = policy.reusable
    private val maximumAgeNanos = policy.maximumAgeNanos
    fun reusable(now: Long): Boolean {
        val elapsed = now - origin
        return reusable && elapsed >= 0 && elapsed < maximumAgeNanos
    }
}

/** Authority deadlines are immutable and use subtraction, including signed nanoTime wrap. */
private class MetadataLease(
    val record: MetadataRecord, val operation: ChatGptStoreOperation, private val clock: () -> Long,
    private val deadline: ChatGptDeadline, private val fetchDeadline: ChatGptDeadline?, private val metadata: AuthMetadata,
    private val serviceLive: () -> Boolean,
) {
    private val owner = Thread.currentThread()
    val closed = AtomicBoolean()
    fun check(op: ChatGptStoreOperation): Unit = metadata.activity(op) {
        if (Thread.currentThread() !== owner || op !== operation || closed.get() || !serviceLive()) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
        operation.check()
        val now = clock()
        if (deadline.remainingNanos() == 0L || fetchDeadline?.remainingNanos() == 0L || (record.reusable && !record.reusable(now)))
            authFail(ChatGptAuthHttpFailure.DEADLINE)
        // A clock/operation can reenter close or shutdown before returning its value.
        if (closed.get() || !serviceLive()) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
    }
    fun live(): Boolean = try { check(operation); true } catch (_: Exception) { false }
    fun <T> use(op: ChatGptStoreOperation, block: () -> T): T = metadata.boundary(op) {
        check(op)
        block().also { check(op) }
    }
}
private class MetadataDiscovery(private val lease: MetadataLease, private val raw: ChatGptOidcDiscovery) : ChatGptOidcDiscovery() {
    private val endpoint: ChatGptAuthRevocationEndpoint? = raw.revocation?.let {
        if (!isOidcRevocationEndpoint(it)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
        ExpiringEndpoint(lease, it)
    }
    override val revocation: ChatGptAuthRevocationEndpoint? get() { lease.check(lease.operation); return endpoint }
}
private class ExpiringEndpoint(private val lease: MetadataLease, private val raw: ChatGptAuthRevocationEndpoint) : ChatGptAuthRevocationEndpoint() {
    private val consumed = AtomicBoolean()
    fun live(): Boolean = !consumed.get() && lease.live()
    override fun newRevocationRequest(logout: ChatGptLocalLogout, operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline): HttpRequest = lease.use(operation) {
        authHttpCheck(operation, httpDeadline)
        if (!isOidcRevocationEndpoint(raw)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
        if (!lease.record.reusable && !consumed.compareAndSet(false, true)) authFail(ChatGptAuthHttpFailure.ALREADY_USED)
        raw.newRevocationRequest(logout, operation, httpDeadline).also { authHttpCheck(operation, httpDeadline) }
    }
}
/** Shared across the one repair; identity is an actual transport-minted reply, never a caller ID. */
private class KeysValidation {
    val repair = AtomicBoolean()
    var reply: ChatGptAuthTokenReply? = null
}
private class KeysUse(
    private val metadata: AuthMetadata, val lease: MetadataLease,
    override val refetched: Boolean, private val validation: KeysValidation,
) : ChatGptAuthKeysUse() {
    private val scoped = scopeOidcJwks(lease.record.document as ChatGptOidcJwks, this)
    fun check(operation: ChatGptStoreOperation) = lease.check(operation)
    fun reserve(reply: ChatGptAuthTokenReply, operation: ChatGptStoreOperation) {
        check(operation)
        synchronized(validation) {
            if (validation.reply != null && validation.reply !== reply) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
            validation.reply = reply
        }
    }
    fun checkValidation(operation: ChatGptStoreOperation) {
        check(operation)
        val reply = synchronized(validation) { validation.reply } ?: authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
        if (!isTransportReplyValidation(reply, operation)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
    }
    override val document: ChatGptOidcJwks get() { check(lease.operation); return scoped }
    override fun refetchUnknown(operation: ChatGptStoreOperation): ChatGptAuthKeysUse {
        check(operation)
        if (!validation.repair.compareAndSet(false, true)) throw ChatGptOidcFailure(ChatGptOidcFailure.Reason.UNKNOWN_KEY)
        try { return metadata.repair(lease.record.generation, operation, validation) }
        finally { close() }
    }
    override fun close() { lease.closed.set(true) }
}

private class AuthMetadata(
    private val transport: ChatGptAuthTransport, private val deadlineClock: ChatGptDeadlineClock,
    private val probe: () -> Long, private val wall: () -> Instant,
) : ChatGptAuthMetadata() {
    private val lock = java.lang.Object()
    private var closed = false
    private var generation = 0L
    private var forcedOrigin: Long? = null
    private var validations = 0
    // Public cache/lease/binding helpers also own shutdown acknowledgements, including
    // cache hits and pre-fetch initialization. Nested calls share one bounded caller slot.
    private val users = java.util.IdentityHashMap<Thread, Int>()
    private val userDeadlines = java.util.IdentityHashMap<Thread, MutableList<ChatGptDeadline?>>()
    private fun clock(): Long { probe(); return deadlineClock.readNanos() }
    fun <T> boundary(operation: ChatGptStoreOperation? = null, block: () -> T): T = authBoundary { activity(operation, block) }
    fun <T> activity(operation: ChatGptStoreOperation? = null, block: () -> T): T {
        val thread = Thread.currentThread()
        synchronized(lock) {
            if (closed) authFail(ChatGptAuthHttpFailure.CANCELLED)
            if (thread !in users && users.size >= 8) authFail(ChatGptAuthHttpFailure.CAPACITY)
            if (operation != null && operation.deadline.clock !== deadlineClock) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
            users[thread] = (users[thread] ?: 0) + 1
            userDeadlines.getOrPut(thread) { mutableListOf() }.add(operation?.deadline)
        }
        try {
            val result = block()
            synchronized(lock) {
                if (closed || operation?.fence?.isCancelled() == true) authFail(ChatGptAuthHttpFailure.CANCELLED)
                if (operation?.deadline?.remainingNanos() == 0L) authFail(ChatGptAuthHttpFailure.DEADLINE)
            }
            return result
        } finally {
            synchronized(lock) {
                val depth = users.getValue(thread) - 1
                userDeadlines.getValue(thread).removeAt(depth)
                if (depth == 0) { users.remove(thread); userDeadlines.remove(thread) } else users[thread] = depth
                lock.notifyAll()
            }
        }
    }
    private var shutdownOrigin: Long? = null
    private var shutdownAllowance = 0L
    private class Slot(val purpose: ChatGptAuthHttpPurpose) {
        var record: MetadataRecord? = null
        var fetch: Fetch? = null
        val executor = ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, ArrayBlockingQueue(1),
            { task -> Thread(task, "chatgpt-auth-metadata-${purpose.name.lowercase()}").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy())
    }
    private class Fetch(val generation: Long, val origin: Long, val deadline: ChatGptDeadline, val forced: Boolean) {
        val fence = ChatGptOperationFence()
        var waiters = 0
        @Volatile var fenced = false
        var done = false
        var record: MetadataRecord? = null
        var failure: ChatGptAuthHttpFailure? = null
        var call: ChatGptAuthHttpCall? = null
    }
    private val discoverySlot = Slot(ChatGptAuthHttpPurpose.DISCOVERY)
    private val keysSlot = Slot(ChatGptAuthHttpPurpose.JWKS)
    override fun bindAuthorization(snapshot: ChatGptAuthorizationSnapshot, redirect: ChatGptPlanOAuthRedirect,
        clock: ChatGptPlanOAuthClock, random: ChatGptPlanOAuthRandom, cancellation: ChatGptPlanOAuthCancellation,
        operation: ChatGptStoreOperation): ChatGptAuthCodeBinding = boundary(operation) {
        operation.check()
        synchronized(lock) { if (closed) authFail(ChatGptAuthHttpFailure.CANCELLED) }
        val attempt = ChatGptPlanOAuthAttempt.start(snapshot.oauthRegistration(), redirect, clock, random, cancellation)
        operation.check()
        synchronized(lock) { if (closed) authFail(ChatGptAuthHttpFailure.CANCELLED) }
        CodeBinding(snapshot, attempt, cancellation, this) { synchronized(lock) { !closed } }
    }
    override fun discovery(operation: ChatGptStoreOperation): ChatGptOidcDiscovery = boundary(operation) {
        val lease = obtain(discoverySlot, operation)
        val raw = lease.record.document
        if (raw !is ChatGptOidcDiscovery || !isOidcDiscovery(raw)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
        MetadataDiscovery(lease, raw).also { lease.check(operation) }
    }
    override fun keys(operation: ChatGptStoreOperation): ChatGptAuthKeysUse = boundary(operation) {
        KeysUse(this, obtain(keysSlot, operation), false, KeysValidation())
    }
    fun repair(previous: Long, operation: ChatGptStoreOperation, validation: KeysValidation): ChatGptAuthKeysUse = boundary(operation) {
        KeysUse(this, obtain(keysSlot, operation, previous), true, validation)
    }
    private fun lease(record: MetadataRecord, operation: ChatGptStoreOperation, fetch: Fetch? = null): MetadataLease {
        val child = operation.deadline.cap(30_000_000_000L)
        operation.check()
        clock()
        val fetchDeadline = if (record.reusable) null else fetch?.deadline ?: authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
        return MetadataLease(record, operation, ::clock, child, fetchDeadline, this) { synchronized(lock) { !closed } }.also { it.check(operation) }
    }
    private fun obtain(slot: Slot, operation: ChatGptStoreOperation, repairFrom: Long? = null): MetadataLease {
        // Evaluate parent callbacks only on this owning caller, never on the worker or under the service lock.
        val admissionOrigin = deadlineClock.readNanos()
        val fetchDeadline = operation.deadline.detach().capAt(admissionOrigin, 10_000_000_000L)
        clock()
        operation.remainingNanos()
        val cacheNow = clock()
        operation.check()
        val fetch: Fetch
        var create = false
        var hit: MetadataRecord? = null
        synchronized(lock) {
            if (closed || operation.fence.isCancelled()) authFail(ChatGptAuthHttpFailure.CANCELLED)
            if (!deadlineClock.valid() || operation.deadline.remainingNanos() == 0L) authFail(ChatGptAuthHttpFailure.DEADLINE)
            val cached = slot.record
            if (cached != null && cached.reusable(deadlineClock.readNanos()) && (repairFrom == null || cached.generation > repairFrom)) hit = cached
            if (hit != null) fetch = Fetch(0, 0, fetchDeadline, false) // inert local; no authority or worker
            else {
                val current = slot.fetch
                if (current != null) {
                    if (current.fenced || current.done) authFail(ChatGptAuthHttpFailure.DEPENDENCY_FAILED)
                    if (current.waiters >= 8) authFail(ChatGptAuthHttpFailure.CAPACITY)
                    fetch = current
                } else {
                    val now = admissionOrigin
                    if (repairFrom != null) {
                        val elapsed = forcedOrigin?.let { now - it }
                        if (elapsed != null && (elapsed < 0 || elapsed < 30_000_000_000L))
                            throw ChatGptOidcFailure(ChatGptOidcFailure.Reason.UNKNOWN_KEY)
                        forcedOrigin = now
                    }
                    if (generation == Long.MAX_VALUE) authFail(ChatGptAuthHttpFailure.CAPACITY)
                    generation++
                    fetch = Fetch(generation, now, fetchDeadline, repairFrom != null)
                    slot.fetch = fetch; create = true
                }
                fetch.waiters++
            }
        }
        hit?.let { return lease(it, operation) }
        if (create) {
            try { slot.executor.execute { runFetch(slot, fetch) } }
            catch (_: Exception) { synchronized(lock) { fetch.failure = ChatGptAuthHttpFailure.DEPENDENCY_FAILED; fetch.done = true; lock.notifyAll() } }
        }
        try {
            while (true) {
                operation.check()
                val record = synchronized(lock) {
                    if (closed || fetch.fenced) authFail(ChatGptAuthHttpFailure.CANCELLED)
                    if (fetch.done) {
                        fetch.failure?.let { authFail(it) }
                        fetch.record ?: authFail(ChatGptAuthHttpFailure.DEPENDENCY_FAILED)
                    } else null
                }
                if (record != null) return lease(record, operation, fetch).also { operation.check() }
                operation.check()
                synchronized(lock) {
                    val wait = minOf(25_000_000L, operation.deadline.remainingNanos(), fetch.deadline.remainingNanos())
                    if (!fetch.done && !fetch.fenced && !operation.fence.isCancelled() && wait > 0)
                        TimeUnit.NANOSECONDS.timedWait(lock, wait)
                    else if (wait <= 0) authFail(ChatGptAuthHttpFailure.DEADLINE)
                }
            }
        } finally {
            val cancel = synchronized(lock) {
                fetch.waiters--
                if (fetch.waiters == 0) {
                    if (fetch.done) { if (slot.fetch === fetch) slot.fetch = null; null }
                    else { fetch.fenced = true; fetch.fence.cancel(); fetch.call }
                } else null
            }
            cancel?.cancel()
        }
    }
    private fun runFetch(slot: Slot, fetch: Fetch) {
        var call: ChatGptAuthHttpCall? = null
        var reply: ChatGptAuthDocumentReply? = null
        try {
            clock()
            if (fetch.deadline.remainingNanos() == 0L) authFail(ChatGptAuthHttpFailure.DEADLINE)
            val operation = ChatGptStoreOperation.fromDeadline(fetch.deadline, fetch.fence) { fetch.fenced }
            call = if (slot.purpose == ChatGptAuthHttpPurpose.DISCOVERY) transport.prepareDiscovery(operation) else transport.prepareJwks(operation)
            synchronized(lock) { fetch.call = call }
            if (fetch.fenced) authFail(ChatGptAuthHttpFailure.CANCELLED)
            call.start(object : ChatGptAuthDispatchGate() { override fun claim(): Boolean = !fetch.fenced })
            val outcome = call.await()
            if (outcome !is ChatGptAuthHttpOutcome.Document) {
                authFail(if (outcome is ChatGptAuthHttpOutcome.Failed) outcome.failure else ChatGptAuthHttpFailure.INVALID_BODY)
            }
            if (!isTransportDocumentReply(outcome.reply)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
            reply = outcome.reply
            val policy = reply.cachePolicy(operation)
            if (!isTransportCachePolicy(policy)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
            val document = if (slot.purpose == ChatGptAuthHttpPurpose.DISCOVERY) reply.discovery(operation).also {
                if (!isOidcDiscovery(it)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
            } else reply.jwks(operation).also {
                if (!isOidcJwks(it)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
            }
            operation.check()
            val record = MetadataRecord(fetch.generation, fetch.origin, policy, document)
            val parsedAt = clock()
            synchronized(lock) {
                if (closed || fetch.fenced || fetch.waiters == 0 || fetch.deadline.remainingNanos() == 0L)
                    authFail(ChatGptAuthHttpFailure.CANCELLED)
                fetch.record = record
            }
        } catch (e: Exception) {
            synchronized(lock) { fetch.failure = when (e) {
                is ChatGptAuthHttpException -> e.failure
                is TimeoutException -> ChatGptAuthHttpFailure.DEADLINE
                is CancellationException, is InterruptedException -> ChatGptAuthHttpFailure.CANCELLED
                else -> ChatGptAuthHttpFailure.INVALID_BODY
            } }
        } finally {
            // Cleanup and clock failures cannot strand a generation without a terminal
            // acknowledgement. The executor owns this stack until the entire finally exits.
            var settled = false
            var installedAt: Long? = null
            try {
                reply?.discard()
                settled = call?.cancelAndSettle(250_000_000L) != ChatGptAuthSettlement.UNSETTLED
                installedAt = clock()
            } catch (_: Exception) {
                synchronized(lock) { if (fetch.failure == null) fetch.failure = ChatGptAuthHttpFailure.DEPENDENCY_FAILED; fetch.fenced = true }
            }
            synchronized(lock) {
                if (!settled) {
                    if (fetch.failure == null) fetch.failure = ChatGptAuthHttpFailure.UNSETTLED; fetch.fenced = true
                    if (slot.record?.generation == fetch.generation) slot.record = null
                }
                // Publish the cache and completed generation together, after cleanup. A last
                // waiter detaching between parsing and this point fences the installation.
                if (fetch.failure == null) {
                    if (closed || fetch.fenced || fetch.waiters == 0 || installedAt == null || fetch.deadline.remainingNanos() == 0L) {
                        fetch.record = null; fetch.failure = ChatGptAuthHttpFailure.CANCELLED
                    } else fetch.record?.let { if (it.reusable(deadlineClock.readNanos())) slot.record = it }
                }
                fetch.done = true
                if (fetch.waiters == 0 && settled && slot.fetch === fetch) slot.fetch = null
                lock.notifyAll()
            }
        }
    }
    override fun validateAuthorization(reply: ChatGptAuthTokenReply, operation: ChatGptStoreOperation): ChatGptAuthorizationProof = boundary(operation) {
        if (!isTransportTokenReply(reply)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
        synchronized(lock) {
            if (closed) authFail(ChatGptAuthHttpFailure.CANCELLED)
            if (validations >= 8) authFail(ChatGptAuthHttpFailure.CAPACITY)
            validations++
        }
        var use: ChatGptAuthKeysUse? = null
        try {
            operation.check()
            use = keys(operation)
            val proof = try { reply.validateAuthorization(use.document, wall(), operation, false) }
            catch (e: ChatGptOidcFailure) {
                if (e.reason != ChatGptOidcFailure.Reason.UNKNOWN_KEY_REFETCH_ONCE) throw e
                use = use.refetchUnknown(operation)
                reply.validateAuthorization(use.document, wall(), operation, true)
            }
            use.document // post-signature key scope/expiry recheck
            operation.check()
            if (proof.idTokenExpiresAt <= wall().minusSeconds(5)) throw ChatGptOidcFailure(ChatGptOidcFailure.Reason.INVALID_CLAIMS)
            operation.check()
            synchronized(lock) {
                if (closed || operation.fence.isCancelled()) authFail(ChatGptAuthHttpFailure.CANCELLED)
                if (operation.deadline.remainingNanos() == 0L) authFail(ChatGptAuthHttpFailure.DEADLINE)
                proof
            }
        } finally {
            use?.close(); reply.discard()
            synchronized(lock) { validations--; lock.notifyAll() }
        }
    }
    override fun shutdown(maxWaitNanos: Long): ChatGptAuthSettlement {
        val start = System.nanoTime()
        val requested = maxWaitNanos.coerceIn(0, 250_000_000L)
        val limit: Long
        val calls = synchronized(lock) {
            if (shutdownOrigin == null) { shutdownOrigin = start; shutdownAllowance = requested }
            val elapsed = start - shutdownOrigin!!
            limit = if (elapsed < 0) 0 else minOf(requested, maxOf(0, shutdownAllowance - elapsed))
            closed = true; discoverySlot.record = null; keysSlot.record = null
            listOf(discoverySlot, keysSlot).mapNotNull { it.fetch?.also { f -> f.fenced = true; f.fence.cancel() }?.call }.also { lock.notifyAll() }
        }
        calls.forEach { it.cancel() }
        val slots = listOf(discoverySlot, keysSlot)
        slots.forEach { it.executor.shutdownNow() }
        fun remaining(): Long = synchronized(lock) {
            var left = maxOf(0, limit - (System.nanoTime() - start))
            for (deadlines in userDeadlines.values) for (deadline in deadlines)
                left = minOf(left, deadline?.remainingNanos() ?: 0L)
            for (slot in slots) slot.fetch?.let { left = minOf(left, it.deadline.remainingNanos()) }
            left
        }
        slots.forEach {
            while (!it.executor.isTerminated) {
                val wait = minOf(25_000_000L, remaining())
                if (wait <= 0) break
                try { it.executor.awaitTermination(wait, TimeUnit.NANOSECONDS) }
                catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
            }
        }
        val resourcesSettled = slots.all { it.executor.isTerminated } && calls.all {
            it.cancelAndSettle(remaining()) == ChatGptAuthSettlement.SETTLED
        }
        // Validation may be blocked in a trusted clock/JCA/owner callback after fetch workers
        // finish. Fence it above, but acknowledge only its finally; never invoke its operation here.
        synchronized(lock) {
            while (validations != 0 || users.isNotEmpty()) {
                val left = minOf(25_000_000L, remaining())
                if (left <= 0) break
                try { TimeUnit.NANOSECONDS.timedWait(lock, left) }
                catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
            }
            return if (resourcesSettled && validations == 0 && users.isEmpty()) ChatGptAuthSettlement.SETTLED else ChatGptAuthSettlement.UNSETTLED
        }
    }
}
