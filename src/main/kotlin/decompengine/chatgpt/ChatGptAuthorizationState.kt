package decompengine.chatgpt

import java.time.Instant
import java.util.UUID

/** Host-only contracts. These are not a security boundary against hostile code in this JVM. */
internal abstract class ChatGptAuthSafeObject {
    final override fun toString(): String = "ChatGptAuth([redacted])"
}

internal sealed class ChatGptAuthorizationTarget : ChatGptAuthSafeObject() {
    class New : ChatGptAuthorizationTarget()
    class Account(val accountId: String) : ChatGptAuthorizationTarget()
    class Enrollment(val enrollmentId: String) : ChatGptAuthorizationTarget()
}

internal abstract class ChatGptPendingEnrollment : ChatGptAuthSafeObject() {
    abstract val enrollmentId: String
    abstract val hasIssuedClient: Boolean
}

/** Only the store's private implementation is accepted back by store transactions. */
internal abstract class ChatGptAuthorizationSnapshot : ChatGptAuthSafeObject() {
    abstract val attemptId: UUID
    abstract val expectedAuthEpoch: Long
    abstract val expectedSubject: String?
    abstract val expectedClientId: String?
    abstract fun oauthRegistration(): ChatGptPlanOAuthRegistration
}

/** Supplied by the trusted OIDC adapter, after signature/claims/owning Code validation. */
internal abstract class ChatGptAuthorizationProof : ChatGptAuthSafeObject() {
    abstract val attemptId: UUID
    abstract val registration: ChatGptPlanValidatedRegistration
    abstract val idTokenExpiresAt: Instant
    abstract val verifiedAt: Instant
    abstract val authorizationNonceHash: String
}

internal enum class ChatGptAuthCommitState { DURABLE, COMMIT_UNKNOWN }
internal abstract class ChatGptAuthCommit : ChatGptAuthSafeObject() {
    abstract val state: ChatGptAuthCommitState
    abstract val account: ChatGptPlanAccount?
}

/** Trusted, nonblocking lifetime gate; never an application/UI observer on the store lock. */
internal abstract class ChatGptAuthPublication : ChatGptAuthSafeObject() {
    abstract fun enterCommit(): Boolean
    abstract fun complete(result: ChatGptAuthCommit)
}

internal enum class ChatGptAuthCancelResult { CANCELLED, COMMIT_IN_PROGRESS, ALREADY_SETTLED }
internal enum class ChatGptAuthSettlement { SETTLED, UNSETTLED }
internal enum class ChatGptAuthPhase { PREPARATION, EXCHANGE, RENEWAL, LOGOUT }
