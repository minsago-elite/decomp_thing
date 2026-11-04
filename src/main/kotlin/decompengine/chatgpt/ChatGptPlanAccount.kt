package decompengine.chatgpt

import java.time.Instant

/** Token-free public view of one explicitly identified registration. */
data class ChatGptPlanAccount(
    val accountId: String,
    val issuer: String,
    val clientId: String,
    val label: String,
    val email: String?,
    val selectedModel: String?,
    val authEpoch: Long,
    val generation: Long,
    val state: State,
    val scopes: Set<String>,
    val expiresAt: Instant?,
) {
    enum class State { READY, PLAN_DISABLED, NEEDS_SIGN_IN, REFRESH_UNCERTAIN, SIGNED_OUT }
    val canUseChatGptPlan: Boolean get() = state == State.READY &&
        setOf("resource.invoke", "chatgpt.tokens.use.direct").all(scopes::contains)

    override fun toString() = "ChatGptPlanAccount(state=$state, credentials=[redacted])"
}

/** Secret-bearing values stay internal and never appear in generated diagnostics. */
internal class ChatGptPlanTokenSet(
    val accessToken: String,
    val refreshToken: String?,
    val idToken: String,
    val tokenType: String,
    val receivedAt: Instant,
    val expiresAt: Instant,
    scopes: Set<String>,
    val authorizationNonceHash: String? = null,
) {
    val scopes: Set<String> = java.util.Collections.unmodifiableSet(scopes.toSet())
    override fun toString() = "ChatGptPlanTokenSet([redacted])"
}

internal data class ChatGptPlanRenewalIntent(val operationId: String, val authEpoch: Long, val generation: Long)

/** Used by later OAuth code only after identity validation has succeeded. */
internal class ChatGptPlanValidatedRegistration(
    val issuer: String,
    val clientId: String,
    val subject: String,
    val label: String,
    val email: String?,
    val tokenSet: ChatGptPlanTokenSet,
) {
    override fun toString() = "ChatGptPlanValidatedRegistration([redacted])"
}
