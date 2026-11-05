package decompengine.chatgpt

import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicBoolean

/** Internal ephemeral transport input; no public token getters, serialization or commit method. */
internal class ChatGptRenewalRequest(
    private val issuer: String,
    private val clientId: String,
    private val subject: String,
    private val tokens: ChatGptPlanTokenSet,
    private val operation: ChatGptStoreOperation,
    private val cancelled: AtomicBoolean,
) {
    private var active = true
    private var sent = false
    private var owner: Thread? = null

    @Synchronized internal fun enter() { checkOwner(); owner = Thread.currentThread() }
    @Synchronized internal fun leave() { owner = null }
    @Synchronized internal fun invalidate() { active = false }
    @Synchronized internal fun dispatched(): Boolean = sent

    @Synchronized internal fun checkOwner() {
        if (!active || cancelled.get()) throw CancellationException("ChatGPT renewal cancelled")
        operation.check()
    }
    @Synchronized fun check() { checkOwner(); check(owner === Thread.currentThread()) }
    fun remainingNanos(): Long { check(); return operation.remainingNanos() }

    /** Call immediately before any transport dispatch; throwing earlier is definitely pre-dispatch.
     * The trusted adapter must consume the shared budget and never retain credentials. */
    fun <T> dispatch(send: (clientId: String, refreshToken: String) -> T): T {
        synchronized(this) {
            check(); check(!sent); sent = true
        }
        check()
        return send(clientId, requireNotNull(tokens.refreshToken))
    }

    /** Validator can obtain expected identity only on the owned worker while the scope is live. */
    fun <T> validateIdentity(validate: (issuer: String, clientId: String, subject: String, nonceHash: String?) -> T): T {
        check()
        return validate(issuer, clientId, subject, tokens.authorizationNonceHash).also { check() }
    }
    override fun toString() = "ChatGptRenewalRequest([redacted])"
}

/** Local sign-out evidence for a future trusted revoker, never remote-revocation confirmation. */
internal class ChatGptLocalLogout(
    val account: ChatGptPlanAccount,
    val clientId: String,
    val latestKnownRefreshToken: String?,
    val renewalOutcomeUnknown: Boolean,
) {
    override fun toString() = "ChatGptLocalLogout(remoteRevocation=unconfirmed, credentials=[redacted])"
}
