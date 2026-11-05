package decompengine.chatgpt

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.StreamReadFeature
import kotlinx.serialization.json.*
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.Path
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock

/**
 * Unwired private-store foundation. One nonescaping transaction owns the JVM lock, stable flock
 * inode and directory handles through durable intent, bounded injected exchange/validation and
 * durable replacement. No OAuth transport or identity-verification implementation is supplied.
 */
class ChatGptPlanCredentialStore private constructor(
    private val directory: Path,
    private val hook: (ChatGptLinuxFiles.Stage) -> Unit = {},
    private val wallClock: () -> Instant = Instant::now,
) {
    private val coordination = COORDINATION.computeIfAbsent(directory) { Coordination() }

    fun hostId(timeout: Duration = Duration.ofSeconds(30), cancelled: () -> Boolean = { false }): String =
        hostId(ChatGptStoreOperation.start(timeout, cancelled))
    fun hostId(operation: ChatGptStoreOperation): String = locked(operation) { files, document ->
        document.hostId ?: "urn:uuid:${UUID.randomUUID()}".also { write(files, document.copy(hostId = it), operation) }
    }
    fun accounts(timeout: Duration = Duration.ofSeconds(30), cancelled: () -> Boolean = { false }): List<ChatGptPlanAccount> =
        accounts(ChatGptStoreOperation.start(timeout, cancelled))
    fun accounts(operation: ChatGptStoreOperation): List<ChatGptPlanAccount> = locked(operation) { _, d -> d.accounts.map { it.public() } }
    fun account(accountId: String, timeout: Duration = Duration.ofSeconds(30), cancelled: () -> Boolean = { false }): ChatGptPlanAccount =
        account(accountId, ChatGptStoreOperation.start(timeout, cancelled))
    fun account(accountId: String, operation: ChatGptStoreOperation): ChatGptPlanAccount =
        locked(operation) { _, d -> requireAccount(d, accountId).public() }

    internal fun add(registration: ChatGptPlanValidatedRegistration, select: Boolean = false,
        operation: ChatGptStoreOperation = ChatGptStoreOperation.start()): ChatGptPlanAccount = mutate(operation) { d ->
        require(d.accounts.size + d.enrollments.size < MAX_ACCOUNTS)
        validateRegistration(registration)
        require(d.accounts.none { it.clientId == registration.clientId } && d.enrollments.none { it.clientId == registration.clientId })
        val a = Record(UUID.randomUUID().toString(), registration.issuer, registration.clientId, registration.subject,
            d.hostId ?: "urn:uuid:${UUID.randomUUID()}", registration.label, registration.email, null, 0, 0,
            stateFor(registration.tokenSet.scopes), registration.tokenSet, null)
        d.copy(hostId = a.hostId, accounts = d.accounts + a, selectedAccountId = if (select) a.accountId else d.selectedAccountId) to a.public()
    }

    internal fun captureAuthorization(target: ChatGptAuthorizationTarget, attemptId: UUID,
        operation: ChatGptStoreOperation): ChatGptAuthorizationSnapshot = locked(operation) { files, d ->
        requireId(attemptId.toString())
        // A host must supply a fresh ID, including after abandonment. Process-lifetime
        // tombstones prevent reusing an old proof ID; durable enrollment fences survive restart.
        // Never evict old IDs to make room: restart is required after this per-root ceiling.
        if (coordination.attemptIds.size >= MAX_AUTHORIZATION_ATTEMPTS)
            throw StoreInputFailure("ChatGPT authorization attempt limit reached; restart the application")
        require(attemptId !in coordination.attemptIds && d.enrollments.none { it.activeAttemptId == attemptId.toString() })
        val snapshot: AuthorizationSnapshot
        val next: Document
        when (target) {
            is ChatGptAuthorizationTarget.New -> {
                require(d.accounts.size + d.enrollments.size < MAX_ACCOUNTS)
                val host = d.hostId ?: "urn:uuid:${UUID.randomUUID()}"
                val enrollment = Enrollment(UUID.randomUUID().toString(), host, null, 0, attemptId.toString())
                next = d.copy(hostId = host, enrollments = d.enrollments + enrollment)
                snapshot = AuthorizationSnapshot(coordination, enrollment.enrollmentId, host, null, null, null, 0, attemptId, null, null)
            }
            is ChatGptAuthorizationTarget.Account -> {
                val a = requireAccount(d, target.accountId)
                synchronized(coordination) { if (a.accountId in coordination.logoutPending) throw CancellationException() }
                requireOAuthClient(a.clientId)
                increment(a.authEpoch); increment(a.generation) // cannot begin an uncommittable authorization
                next = d
                snapshot = AuthorizationSnapshot(coordination, a.accountId, a.hostId, a.issuer, a.clientId, a.subject,
                    a.authEpoch, attemptId, a.tokens?.idToken, a.email?.takeIf { a.tokens != null && it.isNotBlank() })
            }
            is ChatGptAuthorizationTarget.Enrollment -> {
                requireId(target.enrollmentId)
                val e = d.enrollments.singleOrNull { it.enrollmentId == target.enrollmentId } ?: throw NoSuchElementException()
                require(e.clientId != null) // unknown issuance cannot silently repeat dynamic registration
                val epoch = increment(e.authEpoch)
                increment(epoch) // reserve room for promotion/abandonment before any dispatch
                val updated = e.copy(authEpoch = epoch, activeAttemptId = attemptId.toString())
                next = d.replace(updated)
                snapshot = AuthorizationSnapshot(coordination, e.enrollmentId, e.hostId, null, e.clientId, null, epoch, attemptId, null, null)
            }
        }
        // Admission scans cover snapshot host/attempt, including read-only account captures.
        rejectSecretMetadata(next.accounts, operation, next.enrollments, listOf(snapshot.host, attemptId.toString()))
        operation.check()
        coordination.attemptIds.add(attemptId)
        if (next !== d) write(files, next, operation)
        snapshot
    }

    internal fun pendingEnrollments(operation: ChatGptStoreOperation): List<ChatGptPendingEnrollment> =
        locked(operation) { _, d -> java.util.Collections.unmodifiableList(d.enrollments.map { e ->
            object : ChatGptPendingEnrollment() {
                override val enrollmentId = e.enrollmentId
                override val hasIssuedClient = e.clientId != null
            }
        }) }

    /** Called only with the owning protocol's accepted Code, before its code exchange is submitted. */
    internal fun retainIssuedClient(snapshot: ChatGptAuthorizationSnapshot, issuedClientId: String,
        operation: ChatGptStoreOperation) = mutate(operation) { d ->
        val s = own(snapshot); requireOAuthClient(issuedClientId)
        if (s.expectedSubject != null) {
            val a = boundAccount(d, s)
            require(a.clientId == issuedClientId)
            increment(a.authEpoch); increment(a.generation)
            d to Unit
        } else {
            val e = boundEnrollment(d, s)
            increment(e.authEpoch)
            require(e.clientId == null || e.clientId == issuedClientId)
            require(s.expectedClientId == null || s.expectedClientId == issuedClientId)
            require(d.accounts.none { it.clientId == issuedClientId } &&
                d.enrollments.none { it.enrollmentId != e.enrollmentId && it.clientId == issuedClientId })
            if (e.clientId == issuedClientId) d to Unit else d.replace(e.copy(clientId = issuedClientId)) to Unit
        }
    }

    internal fun commitAuthorization(snapshot: ChatGptAuthorizationSnapshot, proof: ChatGptAuthorizationProof,
        select: Boolean, publication: ChatGptAuthPublication, operation: ChatGptStoreOperation): ChatGptAuthCommit {
        var entered = false
        var completing = false
        return locked(operation, completed = { result ->
            completing = true
            publication.complete(result)
        }, failed = { failure ->
            if (!entered) throw failure
            // Once publication starts, never replay a possibly committed transaction. Even a
            // pre-rename error is conservatively unknown; a fresh status read resolves local state.
            val result = AuthorizationCommit(ChatGptAuthCommitState.COMMIT_UNKNOWN, null)
            if (!completing) { completing = true; publication.complete(result) }
            result
        }) { files, d ->
            val s = own(snapshot)
            val registration = proof.registration
            val proofAttempt = proof.attemptId
            val nonceHash = proof.authorizationNonceHash
            val expires = proof.idTokenExpiresAt
            val verified = proof.verifiedAt
            validateRegistration(registration)
            require(proofAttempt == s.attemptId && nonceHash.matches(NONCE_HASH) &&
                registration.tokenSet.authorizationNonceHash == nonceHash)
            val updated: Record
            var next: Document
            if (s.expectedSubject != null) {
                val a = boundAccount(d, s)
                require(registration.issuer == s.issuer && registration.clientId == s.expectedClientId && registration.subject == s.expectedSubject)
                updated = a.copy(label = registration.label, email = registration.email, tokens = registration.tokenSet,
                    authEpoch = increment(a.authEpoch), generation = increment(a.generation),
                    state = stateFor(registration.tokenSet.scopes), renewalIntent = null)
                next = d.replace(updated)
            } else {
                val e = boundEnrollment(d, s)
                require(e.clientId != null && registration.clientId == e.clientId)
                updated = Record(e.enrollmentId, registration.issuer, e.clientId, registration.subject, e.hostId,
                    registration.label, registration.email, null, increment(e.authEpoch), 0,
                    stateFor(registration.tokenSet.scopes), registration.tokenSet, null)
                next = d.copy(accounts = d.accounts + updated, enrollments = d.enrollments.filterNot { it.enrollmentId == e.enrollmentId })
            }
            if (select) next = next.copy(selectedAccountId = updated.accountId)
            // Check the complete candidate BEFORE granting publication authority; no public view
            // may contain any old or new credential, including credentials removed by this write.
            decode(Json.parseToJsonElement(encode(next)).jsonObject, operation)
            rejectSecretMetadata(d.accounts + next.accounts, operation, d.enrollments + next.enrollments,
                listOf(s.host, s.attemptId.toString()))
            val now = wallClock()
            require(expires > minusSkew(now) && verified <= plusSkew(now) && expires > minusSkew(verified))
            operation.check()
            if (!publication.enterCommit()) { s.active = false; throw CancellationException() }
            entered = true
            s.active = false
            operation.check()
            write(files, next, operation)
            AuthorizationCommit(ChatGptAuthCommitState.DURABLE, updated.public())
        }
    }

    internal fun abandonAuthorization(snapshot: ChatGptAuthorizationSnapshot,
        operation: ChatGptStoreOperation) = mutate(operation) { d ->
        val s = own(snapshot, requireActive = false)
        s.active = false // also revoke account completions without changing account credentials
        val e = d.enrollments.singleOrNull { it.enrollmentId == s.targetId }
        if (s.expectedSubject != null || e == null || e.hostId != s.host ||
            e.authEpoch != s.expectedAuthEpoch || e.activeAttemptId != s.attemptId.toString()) d to Unit
        else if (e.clientId == null) d.copy(enrollments = d.enrollments.filterNot { it.enrollmentId == e.enrollmentId }) to Unit
        else d.replace(e.copy(authEpoch = increment(e.authEpoch), activeAttemptId = null)) to Unit
    }

    private fun own(snapshot: ChatGptAuthorizationSnapshot, requireActive: Boolean = true): AuthorizationSnapshot {
        require(snapshot is AuthorizationSnapshot && snapshot.origin === coordination && (!requireActive || snapshot.active))
        return snapshot
    }
    private fun boundAccount(d: Document, s: AuthorizationSnapshot): Record {
        val a = requireAccount(d, s.targetId)
        require(d.hostId == s.host && a.hostId == s.host && a.issuer == s.issuer &&
            a.clientId == s.expectedClientId && a.subject == s.expectedSubject && a.authEpoch == s.expectedAuthEpoch)
        return a
    }
    private fun boundEnrollment(d: Document, s: AuthorizationSnapshot): Enrollment {
        val e = d.enrollments.singleOrNull { it.enrollmentId == s.targetId } ?: throw NoSuchElementException()
        require(d.hostId == s.host && e.hostId == s.host && e.authEpoch == s.expectedAuthEpoch &&
            e.activeAttemptId == s.attemptId.toString() && (s.expectedClientId == null || e.clientId == s.expectedClientId))
        return e
    }

    fun select(accountId: String, operation: ChatGptStoreOperation = ChatGptStoreOperation.start()) = mutate(operation) { d ->
        requireAccount(d, accountId); d.copy(selectedAccountId = accountId) to Unit
    }
    fun setModel(accountId: String, model: String, operation: ChatGptStoreOperation = ChatGptStoreOperation.start()) = mutate(operation) { d ->
        require(model.matches(MODEL)); val a = requireAccount(d, accountId)
        d.replace(a.copy(selectedModel = model)) to Unit
    }

    /**
     * expected epoch binds the caller's identity; expected generation collapses concurrent renewals.
     * The injected exchange AND identity validation run in a bounded private worker. A timed-out
     * worker has no commit authority, cannot reenter this store, and its late result is discarded.
     * It must honor request cancellation for resource cleanup; production wiring needs independent
     * review and a transport-specific bounded-close contract. This seam performs no network I/O.
     */
    internal fun renew(accountId: String, expectedAuthEpoch: Long, expectedGeneration: Long,
        operation: ChatGptStoreOperation, exchange: (ChatGptRenewalRequest) -> ChatGptPlanValidatedRegistration): ChatGptPlanAccount =
        locked(operation) { files, d ->
            val a = requireAccount(d, accountId)
            require(a.authEpoch == expectedAuthEpoch && expectedGeneration >= 0 && a.generation >= expectedGeneration)
            require(a.state in setOf(ChatGptPlanAccount.State.READY, ChatGptPlanAccount.State.PLAN_DISABLED) && a.renewalIntent == null)
            if (a.generation != expectedGeneration) return@locked a.public()
            require(a.state == ChatGptPlanAccount.State.READY)
            val tokens = requireNotNull(a.tokens)
            require(tokens.refreshToken != null && "offline_access" in tokens.scopes)
            val generation = increment(a.generation) // exhaustion must fail before publishing intent
            val cancelled = AtomicBoolean(false)
            val request = ChatGptRenewalRequest(a.issuer, a.clientId, a.subject, tokens, operation.capped(Duration.ofSeconds(10)), cancelled)
            val pending = d.replace(a.copy(renewalIntent = ChatGptPlanRenewalIntent(UUID.randomUUID().toString(), a.authEpoch, a.generation)))
            var intentPublished = false
            var commitAttempted = false
            synchronized(coordination) {
                if (coordination.logoutPending.containsKey(accountId)) throw CancellationException()
                coordination.active[accountId] = cancelled
            }
            try {
                checkRequest(operation, cancelled)
                write(files, pending, operation)
                intentPublished = true
                checkRequest(operation, cancelled)
                val response = boundedExchange(request, operation, exchange)
                checkRequest(operation, cancelled)
                require(request.dispatched())
                validateRegistration(response)
                require(response.issuer == a.issuer && response.clientId == a.clientId && response.subject == a.subject)
                require(response.tokenSet.refreshToken != null && response.tokenSet.scopes.all(tokens.scopes::contains))
                require(response.tokenSet.authorizationNonceHash == tokens.authorizationNonceHash)
                val updated = a.copy(tokens = response.tokenSet, generation = generation,
                    state = stateFor(response.tokenSet.scopes), renewalIntent = null)
                checkRequest(operation, cancelled)
                commitAttempted = true
                write(files, d.replace(updated), operation)
                updated.public()
            } catch (failure: Throwable) {
                request.invalidate()
                // No retry on a possibly dispatched rotation. Keeping the durable intent is enough
                // to fence subsequent owners even if cancellation/disk failure prevents this write.
                if (intentPublished && !commitAttempted) {
                    try {
                        operation.check()
                        val next = if (!request.dispatched()) d else pending.replace(
                            requireAccount(pending, accountId).copy(state = ChatGptPlanAccount.State.REFRESH_UNCERTAIN))
                        write(files, next, operation)
                    } catch (_: Exception) { /* preserve primary; durable intent remains conservative */ }
                }
                throw failure
            } finally {
                request.invalidate()
                synchronized(coordination) { coordination.active.remove(accountId, cancelled) }
            }
        }

    internal fun reauthorize(accountId: String, expectedAuthEpoch: Long, registration: ChatGptPlanValidatedRegistration,
        operation: ChatGptStoreOperation = ChatGptStoreOperation.start()): ChatGptPlanAccount = mutate(operation) { d ->
        val a = requireAccount(d, accountId); validateRegistration(registration)
        require(a.authEpoch == expectedAuthEpoch && a.issuer == registration.issuer && a.clientId == registration.clientId && a.subject == registration.subject)
        val epoch = increment(a.authEpoch); val generation = increment(a.generation)
        val updated = a.copy(label = registration.label, email = registration.email, tokens = registration.tokenSet,
            authEpoch = epoch, generation = generation, state = stateFor(registration.tokenSet.scopes), renewalIntent = null)
        d.replace(updated) to updated.public()
    }

    /** Local deletion only: never represents remote revocation as confirmed. */
    fun logout(accountId: String, operation: ChatGptStoreOperation = ChatGptStoreOperation.start()): ChatGptPlanAccount =
        logoutLocally(accountId, operation).account

    /** Latest known refresh token is captured under lock for a later trusted revoker; never public. */
    internal fun logoutLocally(accountId: String, operation: ChatGptStoreOperation): ChatGptLocalLogout = storeBoundary {
        require(!IN_TRANSACTION.get())
        operation.check(); requireId(accountId)
        synchronized(coordination) {
            coordination.logoutPending[accountId] = (coordination.logoutPending[accountId] ?: 0) + 1
            coordination.active[accountId]?.set(true)
        }
        try {
            mutate(operation) { d ->
                val a = requireAccount(d, accountId)
                val epoch = increment(a.authEpoch); val generation = increment(a.generation)
                val updated = a.copy(tokens = null, authEpoch = epoch, generation = generation,
                    state = ChatGptPlanAccount.State.SIGNED_OUT, renewalIntent = null)
                d.replace(updated) to ChatGptLocalLogout(updated.public(), a.clientId, a.tokens?.refreshToken,
                    a.state == ChatGptPlanAccount.State.REFRESH_UNCERTAIN || a.renewalIntent != null)
            }
        } finally {
            synchronized(coordination) {
                val remaining = coordination.logoutPending.getValue(accountId) - 1
                if (remaining == 0) coordination.logoutPending.remove(accountId) else coordination.logoutPending[accountId] = remaining
            }
        }
    }

    private fun boundedExchange(request: ChatGptRenewalRequest, operation: ChatGptStoreOperation,
        exchange: (ChatGptRenewalRequest) -> ChatGptPlanValidatedRegistration): ChatGptPlanValidatedRegistration {
        val task = FutureTask {
            IN_TRANSACTION.set(true)
            request.enter()
            try { request.check(); exchange(request).also { request.check() } }
            finally { request.leave(); IN_TRANSACTION.remove() }
        }
        val worker = Thread(task, "chatgpt-private-renewal").apply { isDaemon = true }
        operation.check()
        worker.start()
        try {
            while (true) {
                request.checkOwner()
                try { return task.get(minOf(operation.remainingNanos(), ChatGptStoreOperation.POLL_NANOS), TimeUnit.NANOSECONDS) }
                catch (_: TimeoutException) { operation.check() }
                catch (_: ExecutionException) { request.checkOwner(); throw StoreFailure("ChatGPT renewal exchange or validation failed") }
            }
        } finally {
            request.invalidate()
            task.cancel(true)
        }
    }

    private fun <T> mutate(operation: ChatGptStoreOperation, change: (Document) -> Pair<Document, T>): T =
        locked(operation) { files, d ->
            operation.check(); val (next, value) = change(d)
            operation.check(); if (next !== d) write(files, next, operation)
            value
        }

    private fun <T> locked(operation: ChatGptStoreOperation, completed: ((T) -> Unit)? = null,
        failed: ((Throwable) -> T)? = null, action: (ChatGptLinuxFiles, Document) -> T): T = storeBoundary {
        require(!IN_TRANSACTION.get()) // callback cannot nest ANY public store operation
        operation.check()
        while (!coordination.lock.tryLock(minOf(operation.remainingNanos(), ChatGptStoreOperation.POLL_NANOS), TimeUnit.NANOSECONDS)) operation.check()
        IN_TRANSACTION.set(true)
        try {
            var files: ChatGptLinuxFiles? = null
            var primary: Throwable? = null
            val value = try {
                operation.check()
                files = ChatGptLinuxFiles(operation, hook)
                files.open(directory)
                val document = read(files, operation)
                // A new lock owner cannot replay an unresolved renewal's old token.
                val recovered = document.copy(accounts = document.accounts.map {
                    if (it.renewalIntent != null) it.copy(state = ChatGptPlanAccount.State.REFRESH_UNCERTAIN) else it
                })
                if (recovered != document) write(files, recovered, operation)
                operation.check()
                action(files, recovered).also { operation.check() }
            } catch (t: Throwable) { primary = t; throw t }
            finally { try { files?.close() } catch (t: Throwable) { if (primary == null) throw t } }
            operation.check()
            completed?.invoke(value) // trusted completion only after native cleanup, still on JVM lock
            value
        } catch (t: Throwable) { if (failed != null) failed(t) else throw t }
        finally { IN_TRANSACTION.remove(); coordination.lock.unlock() }
    }

    private fun read(files: ChatGptLinuxFiles, operation: ChatGptStoreOperation): Document {
        val bytes = files.read(MAX_BYTES) ?: return Document(null, null, emptyList())
        operation.check()
        try {
            rejectDuplicateKeys(bytes, operation)
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            operation.check()
            return decode(Json.parseToJsonElement(text).jsonObject, operation).also { operation.check() }
        } catch (e: CancellationException) { throw e }
        catch (e: TimeoutException) { throw e }
        catch (_: Exception) { throw StoreFailure("ChatGPT credential document is invalid or unreadable") }
    }

    private fun write(files: ChatGptLinuxFiles, document: Document, operation: ChatGptStoreOperation) {
        operation.check()
        val encoded = encode(document)
        // The same strict schema/invariants apply to every internally constructed document.
        decode(Json.parseToJsonElement(encoded).jsonObject, operation)
        operation.check()
        val bytes = encoded.toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_BYTES)
        files.write(bytes)
    }

    private data class Document(val hostId: String?, val selectedAccountId: String?, val accounts: List<Record>,
        val enrollments: List<Enrollment> = emptyList()) {
        override fun toString() = "ChatGptPrivateDocument([redacted])"
    }
    private data class Enrollment(val enrollmentId: String, val hostId: String, val clientId: String?,
        val authEpoch: Long, val activeAttemptId: String?) {
        override fun toString() = "ChatGptPrivateEnrollment([redacted])"
    }
    private class AuthorizationSnapshot(val origin: Coordination, val targetId: String, val host: String,
        val issuer: String?, override val expectedClientId: String?, override val expectedSubject: String?,
        override val expectedAuthEpoch: Long, override val attemptId: UUID,
        private val idHint: String?, private val emailHint: String?) : ChatGptAuthorizationSnapshot() {
        // Revocation is separate from the immutable original identity, and accessed under the store lock.
        var active = true
        override fun oauthRegistration(): ChatGptPlanOAuthRegistration =
            if (expectedClientId == null) ChatGptPlanOAuthRegistration.New(host, "decomp_engine")
            else ChatGptPlanOAuthRegistration.Returning(expectedClientId, host, idHint, emailHint)
    }
    private class AuthorizationCommit(override val state: ChatGptAuthCommitState,
        override val account: ChatGptPlanAccount?) : ChatGptAuthCommit()
    private data class Record(val accountId: String, val issuer: String, val clientId: String, val subject: String, val hostId: String,
        val label: String, val email: String?, val selectedModel: String?, val authEpoch: Long, val generation: Long,
        val state: ChatGptPlanAccount.State, val tokens: ChatGptPlanTokenSet?, val renewalIntent: ChatGptPlanRenewalIntent?) {
        override fun toString() = "ChatGptPrivateRecord([redacted])"
        fun public() = ChatGptPlanAccount(accountId, issuer, clientId, label, email, selectedModel, authEpoch, generation, state,
            java.util.Collections.unmodifiableSet(tokens?.scopes.orEmpty().intersect(PUBLIC_SCOPES)), tokens?.expiresAt)
    }
    private fun Document.replace(a: Record) = copy(accounts = accounts.map { if (it.accountId == a.accountId) a else it })
    private fun Document.replace(e: Enrollment) = copy(enrollments = enrollments.map { if (it.enrollmentId == e.enrollmentId) e else it })
    private class Coordination {
        val attemptIds = mutableSetOf<UUID>()
        val lock = ReentrantLock()
        val active = mutableMapOf<String, AtomicBoolean>()
        val logoutPending = mutableMapOf<String, Int>()
    }

    companion object {
        private const val MAX_BYTES = 4 * 1024 * 1024
        private const val MAX_ACCOUNTS = 32
        private const val MAX_AUTHORIZATION_ATTEMPTS = 1024
        private val MODEL = Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")
        private val OAUTH_CLIENT = Regex("oaiapp_[A-Za-z0-9_-]{1,160}")
        private val NONCE_HASH = Regex("[a-f0-9]{64}")
        private val CLIENT = Regex("oaiapp_[A-Za-z0-9_-]{1,249}")
        private val SCOPE = Regex("[\\x21\\x23-\\x5B\\x5D-\\x7E]{1,256}") // RFC 6749 scope-token
        private val UUID_ID = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
        private val COORDINATION = ConcurrentHashMap<Path, Coordination>()
        private val IN_TRANSACTION = ThreadLocal.withInitial { false }
        private val REQUIRED = setOf("resource.invoke", "chatgpt.tokens.use.direct")
        private val PUBLIC_SCOPES = REQUIRED + setOf("openid", "profile", "email", "offline_access")
        fun open(root: Path = ChatGptPlanStateRoot.resolve()) = storeBoundary {
            require(root.isAbsolute); ChatGptPlanCredentialStore(root.normalize())
        }
        internal fun withHook(root: Path, hook: (ChatGptLinuxFiles.Stage) -> Unit) = storeBoundary {
            require(root.isAbsolute); ChatGptPlanCredentialStore(root.normalize(), hook)
        }
        internal fun withWallClock(root: Path, clock: () -> Instant, hook: (ChatGptLinuxFiles.Stage) -> Unit = {}) = storeBoundary {
            require(root.isAbsolute); ChatGptPlanCredentialStore(root.normalize(), hook, clock)
        }
        private fun requireOAuthClient(client: String) {
            if (!client.matches(OAUTH_CLIENT)) throw StoreInputFailure("ChatGPT registration is unsupported for authorization")
        }
        private fun minusSkew(now: Instant): Instant = if (now < Instant.MIN.plusSeconds(5)) Instant.MIN else now.minusSeconds(5)
        private fun plusSkew(now: Instant): Instant = if (now > Instant.MAX.minusSeconds(5)) Instant.MAX else now.plusSeconds(5)
        private fun requireId(id: String) { require(id.matches(UUID_ID)) }
        private fun requireAccount(d: Document, id: String): Record {
            requireId(id); return d.accounts.find { it.accountId == id } ?: throw NoSuchElementException()
        }
        private fun increment(value: Long): Long {
            if (value < 0 || value == Long.MAX_VALUE) throw StoreFailure("ChatGPT account counter is exhausted")
            return value + 1
        }
        private fun checkRequest(operation: ChatGptStoreOperation, cancelled: AtomicBoolean) {
            operation.check(); if (cancelled.get()) throw CancellationException()
        }
        private fun stateFor(scopes: Set<String>) = if (REQUIRED.all(scopes::contains)) ChatGptPlanAccount.State.READY else ChatGptPlanAccount.State.PLAN_DISABLED
        private fun validUnicode(text: String) {
            Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(text))
        }
        private fun validateTokens(t: ChatGptPlanTokenSet) {
            for (token in listOfNotNull(t.accessToken, t.idToken, t.refreshToken)) {
                require(token.isNotBlank() && token.length <= 16384 && token.none { Character.isISOControl(it) })
                validUnicode(token)
                require(token.toByteArray(Charsets.UTF_8).size <= 16384)
            }
            require(t.tokenType.equals("Bearer", ignoreCase = true))
            require(t.expiresAt.isAfter(t.receivedAt) && Duration.between(t.receivedAt, t.expiresAt) <= Duration.ofDays(366))
            require(t.scopes.size <= 64 && t.scopes.all { it.matches(SCOPE) })
            require(t.authorizationNonceHash == null || t.authorizationNonceHash.matches(Regex("[a-f0-9]{64}")))
        }
        private fun validateRegistration(r: ChatGptPlanValidatedRegistration) {
            require(r.issuer == "https://auth.openai.com" && r.clientId.matches(CLIENT))
            require(r.subject.isNotBlank() && r.subject.length <= 2048)
            validUnicode(r.subject)
            metadata(r.label, 256); r.email?.let { metadata(it, 320) }
            validateTokens(r.tokenSet)
        }
        private fun metadata(text: String, limit: Int) {
            require(text.length <= limit && text.none { Character.isISOControl(it) || it in '\u202a'..'\u202e' || it in '\u2066'..'\u2069' })
            validUnicode(text)
            require(!Regex("(?i)(bearer\\s|sk-[a-z0-9]|eyJ[a-z0-9_-]{12}|(?:access|refresh|id)[_-]?(?:token|secret))").containsMatchIn(text))
        }
        private fun rejectDuplicateKeys(bytes: ByteArray, operation: ChatGptStoreOperation) {
            JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build().createParser(bytes).use { p ->
                var depth = 0
                while (true) {
                    operation.check()
                    if (p.nextToken() == null) break
                    if (p.currentToken.isStructStart) { depth++; require(depth <= 32) }
                    if (p.currentToken.isStructEnd) depth--
                }
            }
        }
    }

    private fun encode(d: Document): String = buildJsonObject {
        put("schemaVersion", 2); put("hostId", d.hostId); put("selectedAccountId", d.selectedAccountId)
        put("accounts", buildJsonArray { d.accounts.forEach { a -> add(buildJsonObject {
            put("accountId", a.accountId); put("issuer", a.issuer); put("clientId", a.clientId); put("subject", a.subject); put("hostId", a.hostId)
            put("label", a.label); put("email", a.email); put("selectedModel", a.selectedModel); put("authEpoch", a.authEpoch); put("generation", a.generation); put("state", a.state.name.lowercase())
            put("tokenSet", a.tokens?.let(::encodeTokens) ?: JsonNull); put("renewalIntent", a.renewalIntent?.let { buildJsonObject { put("operationId", it.operationId); put("authEpoch", it.authEpoch); put("generation", it.generation) } } ?: JsonNull)
        }) } })
        put("enrollments", buildJsonArray { d.enrollments.forEach { e -> add(buildJsonObject {
            put("enrollmentId", e.enrollmentId); put("hostId", e.hostId); put("clientId", e.clientId)
            put("authEpoch", e.authEpoch); put("activeAttemptId", e.activeAttemptId)
        }) } })
    }.toString()
    private fun encodeTokens(t: ChatGptPlanTokenSet) = buildJsonObject {
        put("accessToken", t.accessToken); put("refreshToken", t.refreshToken); put("idToken", t.idToken); put("tokenType", t.tokenType)
        put("receivedAt", t.receivedAt.toString()); put("expiresAt", t.expiresAt.toString()); put("scopes", JsonArray(t.scopes.sorted().map(::JsonPrimitive))); put("authorizationNonceHash", t.authorizationNonceHash)
    }

    private fun decode(root: JsonObject, operation: ChatGptStoreOperation): Document {
        val version = root.int("schemaVersion")
        val oldKeys = setOf("schemaVersion", "hostId", "selectedAccountId", "accounts")
        require((version == 1 && root.keys == oldKeys) || (version == 2 && root.keys == oldKeys + "enrollments"))
        val host = root.strOrNull("hostId"); require(host == null || (host.startsWith("urn:uuid:") && host.removePrefix("urn:uuid:").matches(UUID_ID)))
        val accounts = root.getValue("accounts").jsonArray; require(accounts.size <= MAX_ACCOUNTS)
        val records = accounts.map { e ->
            operation.check()
            val o = e.jsonObject; require(o.keys == setOf("accountId", "issuer", "clientId", "subject", "hostId", "label", "email", "selectedModel", "authEpoch", "generation", "state", "tokenSet", "renewalIntent"))
            val stateText = o.str("state"); val state = ChatGptPlanAccount.State.entries.single { it.name.lowercase() == stateText }; val t = o.getValue("tokenSet").nullableObject()?.let(::decodeTokens)
            val intent = o.getValue("renewalIntent").nullableObject()?.let { require(it.keys == setOf("operationId", "authEpoch", "generation")); ChatGptPlanRenewalIntent(it.str("operationId"), it.long("authEpoch"), it.long("generation")) }
            val r = Record(o.str("accountId"), o.str("issuer"), o.str("clientId"), o.str("subject"), o.str("hostId"), o.str("label"), o.strOrNull("email"), o.strOrNull("selectedModel"), o.long("authEpoch"), o.long("generation"), state, t, intent)
            require(r.accountId.matches(UUID_ID) && r.hostId == host && r.authEpoch >= 0 && r.generation >= 0 && r.subject.isNotBlank() && r.subject.length <= 2048)
            require(r.issuer == "https://auth.openai.com" && r.clientId.matches(CLIENT) && (r.selectedModel == null || r.selectedModel.matches(MODEL)))
            metadata(r.label, 256); r.email?.let { metadata(it, 320) }; r.selectedModel?.let { metadata(it, 200) }; validUnicode(r.subject)
            require((state == ChatGptPlanAccount.State.SIGNED_OUT || state == ChatGptPlanAccount.State.NEEDS_SIGN_IN) == (t == null))
            if (t != null && state != ChatGptPlanAccount.State.REFRESH_UNCERTAIN) require(state == stateFor(t.scopes))
            require(intent == null || (t?.refreshToken != null && "offline_access" in t.scopes &&
                state in setOf(ChatGptPlanAccount.State.READY, ChatGptPlanAccount.State.REFRESH_UNCERTAIN) &&
                intent.operationId.matches(UUID_ID) && intent.authEpoch == r.authEpoch && intent.generation == r.generation))
            require(state != ChatGptPlanAccount.State.REFRESH_UNCERTAIN || intent != null)
            r
        }
        require(records.map { it.accountId }.distinct().size == records.size && records.map { it.clientId }.distinct().size == records.size)
        require(records.map { Triple(it.issuer, it.clientId, it.subject) }.distinct().size == records.size)
        val selected = root.strOrNull("selectedAccountId"); require(selected == null || records.any { it.accountId == selected })
        val pending = if (version == 1) JsonArray(emptyList()) else root.getValue("enrollments").jsonArray
        require(records.size + pending.size <= MAX_ACCOUNTS)
        val enrollments = pending.map { element ->
            operation.check()
            val e = element.jsonObject
            require(e.keys == setOf("enrollmentId", "hostId", "clientId", "authEpoch", "activeAttemptId"))
            Enrollment(e.str("enrollmentId"), e.str("hostId"), e.strOrNull("clientId"), e.long("authEpoch"), e.strOrNull("activeAttemptId")).also {
                requireId(it.enrollmentId)
                require(it.hostId == host)
                it.clientId?.let { client -> require(client.matches(OAUTH_CLIENT)); metadata(client, 167) }
                it.activeAttemptId?.let(::requireId)
            }
        }
        require(records.size + enrollments.size <= MAX_ACCOUNTS)
        val ids = records.map { it.accountId } + enrollments.map { it.enrollmentId }
        val clients = records.map { it.clientId } + enrollments.mapNotNull { it.clientId }
        val attempts = enrollments.mapNotNull { it.activeAttemptId }
        require(ids.distinct().size == ids.size && clients.distinct().size == clients.size && attempts.distinct().size == attempts.size)
        require((records.isEmpty() && enrollments.isEmpty()) || host != null)
        rejectSecretMetadata(records, operation, enrollments)
        return Document(host, selected, records, enrollments)
    }
    /** Public metadata is checked against all retained secrets, including common encodings and splits.
     * Unknown granted scopes remain private; only fixed protocol scope names reach the projection. */
    private fun rejectSecretMetadata(records: List<Record>, operation: ChatGptStoreOperation,
        enrollments: List<Enrollment> = emptyList(), extra: List<String> = emptyList()) {
        val secrets = records.flatMap { listOfNotNull(it.tokens?.accessToken, it.tokens?.refreshToken, it.tokens?.idToken) }
        val publicFields = records.flatMap { listOfNotNull(it.accountId, it.issuer, it.clientId, it.label, it.email, it.selectedModel, it.tokens?.expiresAt?.toString()) +
            it.tokens?.scopes.orEmpty().intersect(PUBLIC_SCOPES) } +
            enrollments.flatMap { listOfNotNull(it.enrollmentId, it.hostId, it.clientId, it.activeAttemptId) } + extra
        fun normalized(value: String) = value.filter { it.isLetterOrDigit() }.lowercase()
        val fields = publicFields.map { it to normalized(it) }
        for (secret in secrets) {
            operation.check()
            val forms = listOf(secret, java.net.URLEncoder.encode(secret, Charsets.UTF_8),
                java.util.Base64.getEncoder().encodeToString(secret.toByteArray(Charsets.UTF_8)),
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(secret.toByteArray(Charsets.UTF_8)))
                .map { it to normalized(it) }
            for ((field, compactField) in fields) for ((form, compact) in forms) {
                operation.check()
                require(!field.contains(form))
                if (compact.length >= 8) require(!compactField.contains(compact))
            }
        }
    }

    private fun decodeTokens(o: JsonObject): ChatGptPlanTokenSet {
        require(o.keys == setOf("accessToken", "refreshToken", "idToken", "tokenType", "receivedAt", "expiresAt", "scopes", "authorizationNonceHash"))
        val scopes = o.getValue("scopes").jsonArray.map { it.strictString() }
        require(scopes.distinct().size == scopes.size) { "duplicate token scopes" }
        val t = ChatGptPlanTokenSet(o.str("accessToken"), o.strOrNull("refreshToken"), o.str("idToken"), o.str("tokenType"), Instant.parse(o.str("receivedAt")), Instant.parse(o.str("expiresAt")), scopes.toSet(), o.strOrNull("authorizationNonceHash")); validateTokens(t); return t
    }
}

private fun JsonElement.strictString(): String {
    require(this is JsonPrimitive && this !is JsonNull && isString)
    return content
}
private fun JsonObject.str(k: String) = getValue(k).strictString()
private fun JsonObject.strOrNull(k: String) = getValue(k).let { if (it is JsonNull) null else it.strictString() }
private fun JsonObject.long(k: String): Long {
    val value = getValue(k)
    require(value is JsonPrimitive && value !is JsonNull && !value.isString && value.content.matches(Regex("0|[1-9][0-9]*")))
    return value.content.toLong()
}
private fun JsonObject.int(k: String) = long(k).also { require(it <= Int.MAX_VALUE) }.toInt()
private fun JsonElement.nullableObject() = if (this is JsonNull) null else jsonObject
