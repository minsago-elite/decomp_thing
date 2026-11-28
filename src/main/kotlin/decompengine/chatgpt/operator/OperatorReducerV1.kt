package decompengine.chatgpt.operator

import decompengine.chatgpt.*
import java.net.URI
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

internal fun interface OperatorMonotonicClockV1 { fun nowNanos(): Long }
internal interface OperatorRootAttemptClaimV1 {
    fun claim(attemptId: UUID): Boolean
    fun release(attemptId: UUID): Boolean
}
/** Deterministic fake root-wide claim. Sharing this object models a cross-process claim seam only. */
internal class FakeRootAttemptClaimV1 : OperatorRootAttemptClaimV1 {
    private var owner: UUID? = null
    @Synchronized override fun claim(attemptId: UUID) = if (owner == null) { owner = attemptId; true } else false
    @Synchronized override fun release(attemptId: UUID): Boolean = if (owner == attemptId) { owner = null; true } else false
    @Synchronized fun held() = owner != null
}
internal data class PreparedSignInV1(val launch: ChatGptPlanOAuthAttempt.AuthorizationRequest)
internal data class OperatorCancelOutcomeV1(val result: ChatGptAuthCancelResult, val cleanup: ChatGptAuthSettlement)

/** Injected fake-only effects. A production adapter must be separately reviewed and is not supplied. */
internal interface OperatorSignInScriptV1 {
    fun prepare(target: ChatGptAuthorizationTarget, deadlineNanos: Long): PreparedSignInV1
    fun cancel(attemptId: UUID): OperatorCancelOutcomeV1
    fun status(attemptId: UUID): ChatGptAuthCommit?
}
internal fun interface OperatorPhaseExecutorV1 { fun execute(task: () -> Unit) }

internal class OperatorAttemptReducerV1(
    private val clock: OperatorMonotonicClockV1,
    private val wallClock: () -> Instant,
    private val claim: OperatorRootAttemptClaimV1,
    private val script: OperatorSignInScriptV1,
    private val executor: OperatorPhaseExecutorV1,
    private val remoteProfileAllowed: () -> Boolean = { true },
    private val maxRecords: Int = 32,
    initialOperatorRevision: Long = 0,
    private val accountVersionCurrent: (OperatorVersionV1, String) -> Boolean = { _, _ -> true },
) {
    init { require(maxRecords in 1..32) }
    private data class Attempt(val id: UUID, val owner: OperatorOwnerV1, val key: String, val intent: String,
        val deadline: Long, val expiresAt: Instant, val operatorRevision: Long,
        var phase: SignInPhaseV1 = SignInPhaseV1.PREPARING, var version: Long = 0,
        var launch: PreparedSignInV1? = null, var launchTaken: Boolean = false,
        var account: ChatGptPlanAccount? = null, var failure: OperatorFailureV1? = null,
        var cancel: ChatGptAuthCancelResult? = null, var commit: ChatGptAuthCommitState? = null,
        var cleanup: ChatGptAuthSettlement? = null, var retainedAt: Long? = null,
        var verifiedIdentityKey: String? = null, var phaseAfterCleanup: SignInPhaseV1? = null,
        var cancellationFence: Boolean = false, var cancelInFlight: Boolean = false,
        var preparing: Boolean = false, var claiming: Boolean = true, var claimed: Boolean = false,
        var releasing: Boolean = false)
    private data class Ticket(val attempt: Attempt, val version: Long)
    private val attempts = LinkedHashMap<UUID, Attempt>()
    private val byRequest = HashMap<Pair<OperatorOwnerV1, String>, UUID>()
    private val welcomePending = HashMap<String, WelcomeNoticeV1>()
    private val welcomed = HashSet<String>()
    private val revokedOwners = HashSet<OperatorOwnerV1>()
    private var active: UUID? = null
    private var revision = 0L
    private val operatorRevision = initialOperatorRevision.also { require(it >= 0) }
    private fun changed(a: Attempt) { a.version++; revision++ }
    private fun ticket(a: Attempt) = Ticket(a, a.version)
    private fun current(t: Ticket, live: Boolean = true) = attempts[t.attempt.id] === t.attempt &&
        t.attempt.version == t.version && (!live || t.attempt.owner !in revokedOwners)
    private fun valid(t: Ticket, live: Boolean = true) = synchronized(this) { current(t, live) }
    private fun time(t: Ticket, live: Boolean = true): Long? {
        if (!valid(t, live)) return null
        val now = runCatching { clock.nowNanos() }.getOrNull() ?: return null
        return now.takeIf { valid(t, live) }
    }

    fun begin(owner: OperatorOwnerV1, target: ChatGptAuthorizationTarget, expected: OperatorVersionV1,
        requestKey: String): OperatorResultV1<SignInStatusV1> {
        if (!requestKey.matches(Regex("[A-Za-z0-9._~-]{16,128}"))) return fail(OperatorFailureV1.INVALID_REQUEST)
        val intent = try { targetKey(target) + "|" + expected.operatorRevision + "|" +
            listOfNotNull(expected.accountId, expected.authEpoch?.toString(), expected.generation?.toString()).joinToString("|")
        } catch (_: Exception) { return fail(OperatorFailureV1.INVALID_REQUEST) }
        val key = owner to requestKey
        val epoch = synchronized(this) {
            if (owner in revokedOwners) return fail(OperatorFailureV1.NOT_FOUND)
            byRequest[key]?.let { id -> return attempts[id]?.let {
                if (it.intent == intent) ok(snapshot(it)) else fail(OperatorFailureV1.IDEMPOTENCY_CONFLICT)
            } ?: fail(OperatorFailureV1.RESOURCE_LIMIT) }
            revision
        }
        fun unchanged() = synchronized(this) { owner !in revokedOwners && revision == epoch }
        val local = runCatching { remoteProfileAllowed() }.getOrNull()
        if (!unchanged()) return fail(OperatorFailureV1.NOT_FOUND)
        if (local == null) return fail(OperatorFailureV1.UNAVAILABLE)
        if (!local) return fail(OperatorFailureV1.LOCAL_CALLBACK_REQUIRED)
        if (expected.operatorRevision != operatorRevision) return fail(OperatorFailureV1.STALE_ACCOUNT)
        if (target is ChatGptAuthorizationTarget.Account) {
            if (expected.accountId != target.accountId || expected.authEpoch == null || expected.generation == null)
                return fail(OperatorFailureV1.STALE_ACCOUNT)
            val accountCurrent = runCatching { accountVersionCurrent(expected, target.accountId) }.getOrDefault(false)
            if (!unchanged()) return fail(OperatorFailureV1.NOT_FOUND)
            if (!accountCurrent) return fail(OperatorFailureV1.STALE_ACCOUNT)
        } else if (expected.accountId != null) return fail(OperatorFailureV1.INVALID_REQUEST)
        val now = runCatching { clock.nowNanos() }.getOrNull() ?: return fail(OperatorFailureV1.UNAVAILABLE)
        if (!unchanged()) return fail(OperatorFailureV1.NOT_FOUND)
        val wall = runCatching { wallClock() }.getOrNull() ?: return fail(OperatorFailureV1.UNAVAILABLE)
        if (!unchanged()) return fail(OperatorFailureV1.NOT_FOUND)
        val deadline = runCatching { Math.addExact(now, TTL) }.getOrNull() ?: return fail(OperatorFailureV1.RESOURCE_LIMIT)
        val expires = runCatching { wall.plusNanos(TTL) }.getOrNull() ?: return fail(OperatorFailureV1.RESOURCE_LIMIT)
        val a = synchronized(this) {
            if (!unchanged()) return fail(OperatorFailureV1.NOT_FOUND)
            if (active != null) return fail(OperatorFailureV1.ATTEMPT_IN_PROGRESS)
            prune(now)
            if (attempts.size >= maxRecords || welcomePending.size + welcomed.size >= 64) return fail(OperatorFailureV1.RESOURCE_LIMIT)
            Attempt(UUID.randomUUID(), owner, requestKey, intent, deadline, expires, expected.operatorRevision).also {
                attempts[it.id] = it; byRequest[key] = it.id; active = it.id; changed(it)
            }
        }
        // Reserve locally before the external claim; reentrant cancellation cannot start another task.
        val acquired = runCatching { claim.claim(a.id) }.getOrDefault(false)
        val dispatch = synchronized(this) {
            a.claiming = false; a.claimed = acquired; changed(a)
            if (!acquired) {
                attempts.remove(a.id); byRequest.remove(key); if (active == a.id) active = null
                return fail(OperatorFailureV1.ATTEMPT_IN_PROGRESS)
            }
            a.owner !in revokedOwners && !a.cancellationFence && a.phase == SignInPhaseV1.PREPARING
        }
        if (dispatch) {
            try { executor.execute { prepare(a, target) } }
            catch (_: Exception) { stop(a, SignInPhaseV1.FAILED, OperatorFailureV1.RESOURCE_LIMIT) }
        } else releaseIfSettled(a)
        return status(owner, a.id)
    }

    @Synchronized fun status(owner: OperatorOwnerV1, id: UUID): OperatorResultV1<SignInStatusV1> {
        if (owner in revokedOwners) return fail(OperatorFailureV1.NOT_FOUND)
        val a = attempts[id]?.takeIf { it.owner.same(owner) } ?: return fail(OperatorFailureV1.NOT_FOUND)
        return ok(snapshot(a))
    }

    fun takeLaunch(owner: OperatorOwnerV1, id: UUID): OperatorResultV1<SignInLaunchV1> {
        val t = synchronized(this) {
            if (owner in revokedOwners) return fail(OperatorFailureV1.NOT_FOUND)
            ticket(attempts[id]?.takeIf { it.owner.same(owner) } ?: return fail(OperatorFailureV1.NOT_FOUND))
        }
        val now = time(t) ?: return fail(OperatorFailureV1.NOT_FOUND)
        val a = t.attempt
        if (now >= a.deadline) stop(a, SignInPhaseV1.EXPIRED, OperatorFailureV1.TIMEOUT)
        val rejected = synchronized(this) {
            if (owner in revokedOwners) return fail(OperatorFailureV1.NOT_FOUND)
            if (a.launchTaken) return fail(OperatorFailureV1.ATTEMPT_USED)
            if (!current(t) || a.cancellationFence || a.cancelInFlight || a.phase != SignInPhaseV1.WAITING_FOR_BROWSER || a.launch == null)
                return fail(OperatorFailureV1.ATTEMPT_NOT_READY)
            val request = a.launch!!.launch
            if (validLaunch(request.uri)) {
                a.launchTaken = true
                a.launch = null
                changed(a)
                return ok(SignInLaunchV1.issue(snapshot(a), request))
            }
            true
        }
        if (rejected) stop(a, SignInPhaseV1.FAILED, OperatorFailureV1.UNAVAILABLE)
        return fail(OperatorFailureV1.INVALID_REQUEST)
    }

    fun cancel(owner: OperatorOwnerV1, id: UUID): OperatorResultV1<SignInStatusV1> {
        val a = synchronized(this) {
            if (owner in revokedOwners) return fail(OperatorFailureV1.NOT_FOUND)
            attempts[id]?.takeIf { it.owner.same(owner) } ?: return fail(OperatorFailureV1.NOT_FOUND)
        }
        requestCancel(a, SignInPhaseV1.CANCELLED, OperatorFailureV1.CANCELLED)
        return status(owner, id)
    }

    private fun stop(a: Attempt, phase: SignInPhaseV1, failure: OperatorFailureV1) = requestCancel(a, phase, failure)

    private fun requestCancel(a: Attempt, stopped: SignInPhaseV1, reason: OperatorFailureV1) {
        val t = synchronized(this) {
            if (attempts[a.id] !== a || a.cancelInFlight || a.cancellationFence || a.phase in TERMINAL) return
            a.launch = null; a.cancelInFlight = true; changed(a); ticket(a)
        }
        val outcome = runCatching { script.cancel(a.id) }.getOrNull()
        // A callback may already have published DURABLE or revoked this owner. Never replace it.
        val stillCurrent = valid(t, false)
        val now = if (stillCurrent) time(t, false) else null
        synchronized(this) {
            a.cancelInFlight = false
            if (!current(t, false)) return
            a.cancel = outcome?.result
            a.cleanup = if (a.preparing || a.claiming || now == null) ChatGptAuthSettlement.UNSETTLED else outcome?.cleanup ?: ChatGptAuthSettlement.UNSETTLED
            when (outcome?.result) {
                ChatGptAuthCancelResult.COMMIT_IN_PROGRESS -> {
                    a.commit = ChatGptAuthCommitState.COMMIT_UNKNOWN; a.phase = SignInPhaseV1.COMMITTING
                }
                ChatGptAuthCancelResult.ALREADY_SETTLED -> {
                    a.commit = ChatGptAuthCommitState.COMMIT_UNKNOWN; a.phase = SignInPhaseV1.COMMIT_UNKNOWN
                    a.failure = OperatorFailureV1.UNAVAILABLE
                }
                else -> {
                    // Both acknowledged cancellation and an unresolved stop request fence publication.
                    a.cancellationFence = true; a.phase = stopped; a.failure = reason
                }
            }
            finishCleanupState(a, now)
            changed(a)
        }
        releaseIfSettled(a)
    }

    /** Read abstract callback getters once, detach/validate, then publish only to the captured version. */
    fun complete(id: UUID, commit: ChatGptAuthCommit, cleanup: ChatGptAuthSettlement, verifiedIdentityCommitment: String) {
        val t = synchronized(this) {
            val a = attempts[id] ?: return
            if (!canComplete(a)) return
            ticket(a)
        }
        publish(t, commit, cleanup, verifiedIdentityCommitment)
    }
    private fun canComplete(a: Attempt) = a.owner !in revokedOwners && !a.cancellationFence &&
        a.commit != ChatGptAuthCommitState.DURABLE && a.phase !in setOf(SignInPhaseV1.CANCELLED, SignInPhaseV1.EXPIRED, SignInPhaseV1.FAILED)

    private fun publish(t: Ticket, commit: ChatGptAuthCommit, cleanup: ChatGptAuthSettlement, subject: String) {
        val state = runCatching { commit.state }.getOrNull() ?: return
        if (!valid(t)) return
        val supplied = try { commit.account } catch (_: Exception) { return }
        if (!valid(t)) return
        val account = try { supplied?.let { PlanAccountViewV1(it,
            OperatorVersionV1(t.attempt.operatorRevision, it.accountId, it.authEpoch, it.generation), null).account }
        } catch (_: Exception) { return }
        if (!valid(t)) return
        val identity = try { if (state == ChatGptAuthCommitState.DURABLE && account != null && account.canUseChatGptPlan)
            identityKey(account, subject) else null } catch (_: Exception) { return }
        val now = time(t) ?: return
        synchronized(this) {
            val a = t.attempt
            if (!current(t) || !canComplete(a)) return
            a.launch = null; a.commit = state; a.account = account
            a.cleanup = if (a.preparing || a.claiming) ChatGptAuthSettlement.UNSETTLED else cleanup
            when (state) {
                ChatGptAuthCommitState.COMMIT_UNKNOWN -> { a.phase = SignInPhaseV1.COMMIT_UNKNOWN; a.failure = OperatorFailureV1.UNAVAILABLE }
                ChatGptAuthCommitState.DURABLE -> {
                    if (account != null && account.canUseChatGptPlan) {
                        a.phase = SignInPhaseV1.SUCCEEDED; a.failure = null; a.verifiedIdentityKey = identity
                        if (identity != null && identity !in welcomed && identity !in welcomePending)
                            welcomePending[identity] = WelcomeNoticeV1.mint(account.accountId)
                    } else { a.phase = SignInPhaseV1.FAILED; a.failure = OperatorFailureV1.SCOPE_DENIED }
                }
            }
            finishCleanupState(a, now); changed(a)
        }
        releaseIfSettled(t.attempt)
    }

    fun reconcileCommitUnknown(owner: OperatorOwnerV1, id: UUID, verifiedIdentityCommitment: String): OperatorResultV1<SignInStatusV1> {
        val t = synchronized(this) {
            if (owner in revokedOwners) return fail(OperatorFailureV1.NOT_FOUND)
            val a = attempts[id]?.takeIf { it.owner.same(owner) } ?: return fail(OperatorFailureV1.NOT_FOUND)
            if (a.cancellationFence || a.phase !in setOf(SignInPhaseV1.COMMIT_UNKNOWN, SignInPhaseV1.COMMITTING))
                return fail(OperatorFailureV1.INVALID_REQUEST)
            ticket(a)
        }
        val committed = runCatching { script.status(id) }.getOrNull()
        if (!valid(t)) return status(owner, id)
        if (committed == null) return fail(OperatorFailureV1.UNAVAILABLE)
        publish(t, committed, t.attempt.cleanup ?: ChatGptAuthSettlement.UNSETTLED, verifiedIdentityCommitment)
        return status(owner, id)
    }

    @Synchronized fun acknowledgeWelcome(account: ChatGptPlanAccount, verifiedIdentityCommitment: String): WelcomeNoticeV1? {
        val identity = identityKey(account, verifiedIdentityCommitment); val notice = welcomePending.remove(identity) ?: return null
        welcomed += identity; return notice
    }
    @Synchronized fun pendingWelcome(account: ChatGptPlanAccount, verifiedIdentityCommitment: String): WelcomeNoticeV1? = welcomePending[identityKey(account, verifiedIdentityCommitment)]

    fun cleanupSettled(id: UUID) {
        val t = synchronized(this) {
            val a = attempts[id] ?: return
            if (a.cleanup == ChatGptAuthSettlement.SETTLED || a.preparing || a.claiming) return
            ticket(a)
        }
        val now = time(t, false) ?: return
        synchronized(this) {
            if (!current(t, false)) return
            val a = t.attempt
            a.launch = null
            if (a.phase !in TERMINAL && a.phase != SignInPhaseV1.CLEANUP_PENDING && a.phase != SignInPhaseV1.COMMITTING) {
                a.cancellationFence = true; a.phase = SignInPhaseV1.CANCELLED
            }
            a.cleanup = ChatGptAuthSettlement.SETTLED
            if (a.phase == SignInPhaseV1.CLEANUP_PENDING) a.phase = a.phaseAfterCleanup ?: SignInPhaseV1.CANCELLED
            a.phaseAfterCleanup = null
            if (a.phase in TERMINAL && a.retainedAt == null) a.retainedAt = now
            changed(a)
        }
        releaseIfSettled(t.attempt)
    }

    fun ownerRevoked(owner: OperatorOwnerV1) {
        val owned = synchronized(this) {
            if (!revokedOwners.add(owner)) return
            revision++
            attempts.values.filter { it.owner.same(owner) }.onEach { it.launch = null; changed(it) }.toList()
        }
        owned.forEach { requestCancel(it, SignInPhaseV1.CANCELLED, OperatorFailureV1.CANCELLED) }
    }

    fun sweepExpired() {
        val records = synchronized(this) { attempts.values.map(::ticket) }
        records.forEach { t -> time(t, false)?.let { if (it >= t.attempt.deadline) stop(t.attempt, SignInPhaseV1.EXPIRED, OperatorFailureV1.TIMEOUT) } }
        val epoch = synchronized(this) { revision }
        val now = runCatching { clock.nowNanos() }.getOrNull() ?: return
        synchronized(this) { if (revision == epoch) prune(now) }
    }

    private fun finishCleanupState(a: Attempt, now: Long?) {
        if (a.cleanup == ChatGptAuthSettlement.SETTLED) {
            a.phaseAfterCleanup = null
            if (a.phase in TERMINAL && a.retainedAt == null) a.retainedAt = now
        } else if (a.phase != SignInPhaseV1.COMMITTING) {
            a.phaseAfterCleanup = a.phase; a.phase = SignInPhaseV1.CLEANUP_PENDING; a.failure = OperatorFailureV1.CLEANUP_UNSETTLED
        }
    }
    private fun snapshot(a: Attempt) = SignInStatusV1(a.id, a.phase, a.expiresAt,
        a.account?.let { PlanAccountViewV1(it, OperatorVersionV1(a.operatorRevision, it.accountId, it.authEpoch, it.generation), a.verifiedIdentityKey?.let(welcomePending::get)) },
        a.failure, a.cancel, a.commit, a.cleanup, a.version)

    private fun releaseIfSettled(a: Attempt) {
        synchronized(this) {
            if (a.cleanup != ChatGptAuthSettlement.SETTLED || active != a.id || !a.claimed || a.claiming || a.preparing ||
                a.releasing || a.launch != null || a.phase !in TERMINAL) return
            a.releasing = true
        }
        val released = runCatching { claim.release(a.id) }.getOrDefault(false)
        synchronized(this) {
            a.releasing = false
            if (released) { a.claimed = false; if (active == a.id) active = null }
            else { a.phaseAfterCleanup = a.phase; a.phase = SignInPhaseV1.CLEANUP_PENDING; a.cleanup = ChatGptAuthSettlement.UNSETTLED; a.failure = OperatorFailureV1.CLEANUP_UNSETTLED }
            changed(a)
        }
    }
    private fun prune(now: Long) {
        attempts.values.filter { it.id != active && !it.preparing && !it.claiming && !it.releasing && it.phase in TERMINAL &&
            it.cleanup == ChatGptAuthSettlement.SETTLED && it.retainedAt?.let { at -> now >= at && now - at >= TTL } == true
        }.forEach { attempts.remove(it.id); byRequest.remove(it.owner to it.key); revision++ }
    }
    private fun targetKey(target: ChatGptAuthorizationTarget) = when (target) {
        is ChatGptAuthorizationTarget.New -> "new"
        is ChatGptAuthorizationTarget.Account -> "account:${canonicalUuid(target.accountId)}"
        is ChatGptAuthorizationTarget.Enrollment -> "enrollment:${canonicalUuid(target.enrollmentId)}"
    }
    private fun canonicalUuid(value: String): String = UUID.fromString(value).toString().also { require(it == value) }
    private fun identityKey(a: ChatGptPlanAccount, subjectCommitment: String): String = verifiedWelcomeIdentityKey(a, subjectCommitment)
    private fun prepare(a: Attempt, target: ChatGptAuthorizationTarget) {
        val t = synchronized(this) {
            if (a.owner in revokedOwners || a.cancellationFence || a.cancelInFlight || a.phase != SignInPhaseV1.PREPARING || a.preparing) return
            ticket(a)
        }
        val now = time(t) ?: return
        if (now >= a.deadline) { stop(a, SignInPhaseV1.EXPIRED, OperatorFailureV1.TIMEOUT); return }
        val phaseDeadline = minOf(a.deadline, runCatching { Math.addExact(now, Duration.ofSeconds(30).toNanos()) }.getOrElse { a.deadline })
        synchronized(this) { if (!current(t)) return; a.preparing = true }
        val prepared = runCatching { script.prepare(target, phaseDeadline) }.getOrNull()
        val after = time(t)
        val install = synchronized(this) {
            a.preparing = false
            if (current(t) && after != null && after < phaseDeadline && prepared != null && !a.cancellationFence) {
                a.launch = prepared; a.phase = SignInPhaseV1.WAITING_FOR_BROWSER; changed(a); true
            } else false
        }
        if (!install) {
            // Completion of an in-flight prepare is not cleanup acknowledgement. A stopped task
            // stays quarantined until a subsequent explicit acknowledgement from its resource owner.
            val stopped = synchronized(this) { a.cancellationFence || a.commit != null || a.owner in revokedOwners }
            if (!stopped) stop(a, if (after != null && after >= a.deadline) SignInPhaseV1.EXPIRED else SignInPhaseV1.FAILED,
                if (after != null && after >= a.deadline) OperatorFailureV1.TIMEOUT else OperatorFailureV1.UNAVAILABLE)
        }
    }
    private fun validLaunch(value: String): Boolean = runCatching {
        val uri = URI(value)
        val forbidden = setOf("code_verifier", "access_token", "refresh_token", "id_token", "id_token_hint", "login_hint", "code", "client_secret")
        val pairs = uri.rawQuery.orEmpty().split('&').filter(String::isNotEmpty).map {
            URLDecoder.decode(it.substringBefore('='), StandardCharsets.UTF_8).lowercase() to URLDecoder.decode(it.substringAfter('=', ""), StandardCharsets.UTF_8)
        }
        val query = pairs.toMap()
        uri.scheme == "https" && uri.host == "auth.openai.com" && uri.port in setOf(-1, 443) && uri.path == "/authorize" && uri.userInfo == null && uri.fragment == null &&
            pairs.size == query.size && query.keys.none { it in forbidden } && query.keys.containsAll(setOf("state", "nonce", "code_challenge", "code_challenge_method")) &&
            query["code_challenge_method"] == "S256" && !query["state"].isNullOrBlank() && !query["nonce"].isNullOrBlank() && !query["code_challenge"].isNullOrBlank()
    }.getOrDefault(false)
    private fun <T> ok(v: T): OperatorResultV1<T> = OperatorResultV1.Ok(v)
    private fun <T> fail(code: OperatorFailureV1): OperatorResultV1<T> = OperatorResultV1.Failed(code)
    companion object {
        private val TTL = Duration.ofMinutes(5).toNanos()
        private val TERMINAL = setOf(SignInPhaseV1.SUCCEEDED, SignInPhaseV1.FAILED, SignInPhaseV1.CANCELLED, SignInPhaseV1.EXPIRED, SignInPhaseV1.COMMIT_UNKNOWN)
    }
}

internal fun verifiedWelcomeIdentityKey(account: ChatGptPlanAccount, verifiedSubjectCommitment: String): String {
    require(account.issuer == "https://auth.openai.com" && account.clientId.matches(Regex("oaiapp_[A-Za-z0-9_-]{1,192}")))
    require(verifiedSubjectCommitment.matches(Regex("[a-f0-9]{64}")))
    val value = "chatgpt-plan-welcome-v1\u0000${account.issuer}\u0000${account.clientId}\u0000$verifiedSubjectCommitment"
    return MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).joinToString("") { "%02x".format(it) }
}

/** Request-sequence and catalog state are client-local reducer facts; no response can elect defaults. */
internal class OperatorSelectionReducerV1(private val monotonicNow: () -> Long, private val wallNow: () -> Instant) {
    private var sequence = 0L
    private var context: Pair<String, AccountStampV1>? = null
    private var catalog: CatalogViewV1? = null
    private var selectedModel: String? = null
    private var revision = 0L
    private var catalogExpiresAtNanos: Long? = null
    @Synchronized fun beginAction(): Long { sequence = Math.addExact(sequence, 1); catalog = null; catalogExpiresAtNanos = null; selectedModel = null; return sequence }
    @Synchronized fun switched(accountId: String, stamp: AccountStampV1): Long { sequence = Math.addExact(sequence, 1); context = accountId to stamp; catalog = null; catalogExpiresAtNanos = null; selectedModel = null; return sequence }
    fun acceptCatalog(requestSequence: Long, accountId: String, stamp: AccountStampV1, value: CatalogViewV1): Boolean {
        val captured = synchronized(this) { revision to catalog }
        fun current() = synchronized(this) { requestSequence == sequence && context == (accountId to stamp) &&
            revision == captured.first && catalog === captured.second }
        if (!current() || value.account != stamp) return false
        val wall = wallNow()
        if (!current() || wall.isBefore(value.fetchedAt) || !wall.isBefore(value.expiresAt)) return false
        val now = monotonicNow()
        if (!current()) return false
        val remaining = minOf(Duration.ofMinutes(5).toNanos(), Duration.between(wall, value.expiresAt).toNanos())
        val expiry = Math.addExact(now, remaining)
        return synchronized(this) {
            if (!current()) return false
            catalog = value; catalogExpiresAtNanos = expiry; selectedModel = null; revision++; true
        }
    }
    fun chooseModel(requestSequence: Long, slug: String): Boolean {
        val captured = synchronized(this) { Triple(sequence, revision, catalog) }
        val c = captured.third ?: return false
        if (requestSequence != captured.first) return false
        val now = monotonicNow()
        return synchronized(this) {
            if (sequence != captured.first || revision != captured.second || catalog !== c) return false
            if (now >= (catalogExpiresAtNanos ?: return false)) { clearExpired(); return false }
            if (c.models.none { it.slug == slug }) return false
            selectedModel = slug; revision = Math.addExact(revision, 1); true
        }
    }
    fun election(accountId: String, limits: ChatGptLocalLimitsV1, accepted: Boolean): ChatGptPlanRunElectionV1? {
        val captured = synchronized(this) { Triple(sequence, revision, catalog) }
        val c = captured.third ?: return null
        val now = monotonicNow()
        return synchronized(this) {
            if (sequence != captured.first || revision != captured.second || catalog !== c) return null
            if (now >= (catalogExpiresAtNanos ?: return null)) { clearExpired(); return null }
            val pair = context ?: return null; val model = selectedModel ?: return null
            if (pair.first != accountId || !accepted || c.models.none { it.slug == model }) return null
            ChatGptPlanRunElectionV1(accountId, model, "local-acceptance-v1", 1, true,
                pair.second.authEpoch, pair.second.generation, c.catalogId.toString(), limits)
        }
    }
    private fun clearExpired() { catalog = null; catalogExpiresAtNanos = null; selectedModel = null; revision++ }
    @Synchronized fun currentSequence() = sequence
    @Synchronized fun revision() = revision
}

/** Scripted root preference CAS used to exercise cross-tab/CLI revision and account stamp fences. */
internal class OperatorPreferenceReducerV1(
    accounts: Map<String, AccountStampV1>,
    private val monotonicNow: () -> Long,
    private val wallNow: () -> Instant,
) {
    private val stamps = accounts.toMutableMap()
    private var selectedAccount: String? = null
    private var modelByAccount = HashMap<String, String>()
    private var catalogByAccount = HashMap<String, CatalogViewV1>()
    private var catalogExpiryByAccount = HashMap<String, Long>()
    private var revision = 0L
    private val welcomeById = LinkedHashMap<UUID, Pair<String, WelcomeNoticeV1>>()
    private val acknowledgedIdentities = HashSet<String>()

    @Synchronized fun installCatalog(value: CatalogViewV1): Boolean {
        if (stamps[value.account.accountId] != value.account || wallNow().isBefore(value.fetchedAt) || !wallNow().isBefore(value.expiresAt)) return false
        catalogByAccount[value.account.accountId] = value
        val remaining = Duration.between(wallNow(), value.expiresAt).toMillis().coerceAtLeast(0)
        catalogExpiryByAccount[value.account.accountId] = Math.addExact(monotonicNow(), Math.min(Duration.ofMinutes(5).toNanos(), Math.multiplyExact(remaining, 1_000_000L)))
        return true
    }

    @Synchronized fun select(accountId: String, expected: OperatorVersionV1): OperatorResultV1<Long> {
        if (!matches(expected, accountId)) return OperatorResultV1.Failed(OperatorFailureV1.STALE_ACCOUNT)
        if (accountId !in stamps) return OperatorResultV1.Failed(OperatorFailureV1.NEEDS_SIGN_IN)
        if (selectedAccount != accountId) { selectedAccount = accountId; bump() }
        return OperatorResultV1.Ok(revision)
    }

    @Synchronized fun setModel(accountId: String, slug: String, catalogId: UUID, expected: OperatorVersionV1): OperatorResultV1<Long> {
        if (!matches(expected, accountId)) return OperatorResultV1.Failed(OperatorFailureV1.STALE_ACCOUNT)
        val catalog = catalogByAccount[accountId] ?: return OperatorResultV1.Failed(OperatorFailureV1.MODEL_UNAVAILABLE)
        if (catalog.catalogId != catalogId || monotonicNow() >= (catalogExpiryByAccount[accountId] ?: 0) || catalog.models.none { it.slug == slug })
            return OperatorResultV1.Failed(OperatorFailureV1.MODEL_UNAVAILABLE)
        if (modelByAccount[accountId] != slug) { modelByAccount[accountId] = slug; bump() }
        return OperatorResultV1.Ok(revision)
    }

    @Synchronized fun updateStamp(value: AccountStampV1) { stamps[value.accountId] = value; catalogByAccount.remove(value.accountId); catalogExpiryByAccount.remove(value.accountId); modelByAccount.remove(value.accountId) }
    @Synchronized fun selectedAccountId() = selectedAccount
    @Synchronized fun selectedModel(accountId: String) = modelByAccount[accountId]
    @Synchronized fun currentRevision() = revision
    @Synchronized fun registerWelcome(notice: WelcomeNoticeV1, stamp: AccountStampV1, identityKey: String): Boolean {
        if (stamps[stamp.accountId] != stamp || notice.accountId != stamp.accountId || !identityKey.matches(Regex("[a-f0-9]{64}"))) return false
        if (welcomeById.size >= 64 && notice.noticeId !in welcomeById) return false
        welcomeById[notice.noticeId] = identityKey to notice
        return true
    }
    @Synchronized fun pendingWelcome(accountId: String, identityKey: String): WelcomeNoticeV1? =
        welcomeById.values.firstOrNull { it.first == identityKey && it.second.accountId == accountId && identityKey !in acknowledgedIdentities }?.second
    @Synchronized fun acknowledgeWelcome(noticeId: UUID, identityKey: String,
        expected: OperatorVersionV1): OperatorResultV1<Long> {
        if (expected.operatorRevision != revision || expected.accountId == null ||
            stamps[expected.accountId] == null || expected.authEpoch != stamps[expected.accountId]?.authEpoch ||
            expected.generation != stamps[expected.accountId]?.generation) return OperatorResultV1.Failed(OperatorFailureV1.STALE_ACCOUNT)
        val notice = welcomeById[noticeId] ?: return OperatorResultV1.Failed(OperatorFailureV1.NOT_FOUND)
        if (notice.first != identityKey || notice.second.accountId != expected.accountId) return OperatorResultV1.Failed(OperatorFailureV1.NOT_FOUND)
        if (identityKey !in acknowledgedIdentities) { acknowledgedIdentities += identityKey; bump() }
        return OperatorResultV1.Ok(revision)
    }
    private fun matches(expected: OperatorVersionV1, id: String): Boolean {
        if (expected.operatorRevision != revision) return false
        val stamp = stamps[id] ?: return false
        return expected.accountId == id && expected.authEpoch == stamp.authEpoch && expected.generation == stamp.generation
    }
    private fun bump() { revision = Math.addExact(revision, 1) }
}
