package decompengine.chatgpt.operator

import kotlinx.serialization.json.*

/** Explicit allowlist encoders. They never inspect auth objects, exceptions, requests or Throwable data. */
internal object OperatorProjectionJsonV1 {
    fun status(value: OperatorStatusV1): JsonObject = buildJsonObject {
        put("available", value.available)
        put("operatorRevision", value.operatorRevision.toString())
        value.selectedAccountId?.let { put("selectedAccountId", it) } ?: put("selectedAccountId", JsonNull)
        value.unavailableReason?.let { put("unavailableReason", it.name) }
        put("accounts", JsonArray(value.accounts.map(::account)))
    }

    fun signIn(value: SignInStatusV1): JsonObject = buildJsonObject {
        put("attemptId", value.attemptId.toString()); put("phase", value.phase.name); put("expiresAt", value.expiresAt.toString())
        put("version", value.version.toString())
        value.account?.let { put("account", account(it)) }
        value.failure?.let { put("failure", it.name) }
        value.cancelResult?.let { put("cancelResult", it.name) }
        value.commit?.let { put("commit", it.name) }
        value.cleanup?.let { put("cleanup", it.name) }
    }

    fun doctor(value: PlanDoctorViewV1): JsonObject = buildJsonObject {
        put("authMode", value.authMode); put("available", value.available); value.reason?.let { put("reason", it.name) }
        value.selectedAccountId?.let { put("selectedAccountId", it) } ?: put("selectedAccountId", JsonNull)
        value.state?.let { put("state", it.name) } ?: put("state", JsonNull)
        value.privateRootPermissionsValid?.let { put("privateRootPermissionsValid", it) } ?: put("privateRootPermissionsValid", JsonNull)
        put("callbackProfile", value.callbackProfile)
    }

    private fun account(value: PlanAccountViewV1): JsonObject = buildJsonObject {
        val a = value.account
        put("accountId", a.accountId); put("issuer", a.issuer); put("clientId", a.clientId); put("label", a.label)
        a.email?.let { put("email", it) } ?: put("email", JsonNull)
        a.selectedModel?.let { put("selectedModel", it) } ?: put("selectedModel", JsonNull)
        put("authEpoch", a.authEpoch.toString()); put("generation", a.generation.toString()); put("state", a.state.name)
        put("scopes", JsonArray(a.scopes.sorted().map(::JsonPrimitive)))
        a.expiresAt?.let { put("expiresAt", it.toString()) } ?: put("expiresAt", JsonNull)
        put("operatorRevision", value.version.operatorRevision.toString())
        value.welcome?.let { put("welcome", buildJsonObject { put("noticeId", it.noticeId.toString()); put("accountId", it.accountId); put("version", it.version) }) }
    }
}

internal data class OperatorFailurePresentationV1(val httpStatus: Int, val message: String, val action: String)

/** Fixed reviewed mapping; no rejected value, throwable, upstream body, request ID, or URL interpolation. */
internal object OperatorFailurePresentationsV1 {
    private val values = mapOf(
        OperatorFailureV1.INVALID_REQUEST to OperatorFailurePresentationV1(422, "Invalid ChatGPT plan request.", "Correct explicit input."),
        OperatorFailureV1.NOT_FOUND to OperatorFailurePresentationV1(404, "ChatGPT operation unavailable.", "Same response for absent or wrong owner."),
        OperatorFailureV1.STALE_ACCOUNT to OperatorFailurePresentationV1(409, "Account state changed.", "Refresh this view."),
        OperatorFailureV1.ATTEMPT_IN_PROGRESS to OperatorFailurePresentationV1(409, "A ChatGPT sign-in is already in progress.", "Wait for the current operation."),
        OperatorFailureV1.ATTEMPT_NOT_READY to OperatorFailurePresentationV1(409, "ChatGPT sign-in preparation is still in progress.", "Poll safe status within the original deadline."),
        OperatorFailureV1.ATTEMPT_USED to OperatorFailurePresentationV1(409, "This ChatGPT sign-in launch was already delivered.", "Inspect or cancel; do not replay the URL."),
        OperatorFailureV1.IDEMPOTENCY_CONFLICT to OperatorFailurePresentationV1(409, "The request key was used for a different ChatGPT operation.", "Inspect the original operation."),
        OperatorFailureV1.LOCAL_CALLBACK_REQUIRED to OperatorFailurePresentationV1(503, "Sign-in requires a browser on this host.", "Use the supported same-host profile."),
        OperatorFailureV1.NEEDS_SIGN_IN to OperatorFailurePresentationV1(409, "Sign in to this ChatGPT registration.", "Explicit user action only."),
        OperatorFailureV1.SCOPE_DENIED to OperatorFailurePresentationV1(403, "ChatGPT plan inference was not granted.", "Explicit reauthorization is required."),
        OperatorFailureV1.MODEL_UNAVAILABLE to OperatorFailurePresentationV1(409, "The selected ChatGPT model is unavailable.", "Refresh and explicitly choose."),
        OperatorFailureV1.STRICT_CAP_UNSUPPORTED to OperatorFailurePresentationV1(422, "This provider cannot enforce a server output-token cap.", "Keep the strict cap; choose another provider."),
        OperatorFailureV1.POLICY_REQUIRED to OperatorFailurePresentationV1(422, "Select local limits for this run.", "No default election is available."),
        OperatorFailureV1.REFRESH_UNCERTAIN to OperatorFailurePresentationV1(409, "ChatGPT session renewal could not be confirmed.", "Reconcile; do not repeat an uncertain exchange."),
        OperatorFailureV1.RATE_LIMIT to OperatorFailurePresentationV1(429, "ChatGPT plan usage limit reached.", "Manage usage in ChatGPT settings."),
        OperatorFailureV1.UNAVAILABLE to OperatorFailurePresentationV1(503, "ChatGPT is unavailable right now.", "Manual check only; no auth or send replay."),
        OperatorFailureV1.TIMEOUT to OperatorFailurePresentationV1(408, "ChatGPT operation timed out.", "Do not reset the original budget."),
        OperatorFailureV1.CANCELLED to OperatorFailurePresentationV1(409, "ChatGPT operation stopped locally.", "Remote processing remains unknown unless trusted as unsent."),
        OperatorFailureV1.CLEANUP_UNSETTLED to OperatorFailurePresentationV1(409, "Local cleanup is not yet confirmed.", "Ownership remains held until cleanup is acknowledged."),
        OperatorFailureV1.AMBIGUOUS_SEND to OperatorFailurePresentationV1(409, "ChatGPT may still be processing the request.", "Do not authenticate, replay, refund, or fall back."),
        OperatorFailureV1.RESOURCE_LIMIT to OperatorFailurePresentationV1(429, "Local ChatGPT operation capacity is reached.", "Try an explicit action after capacity is released."),
    )
    fun forFailure(code: OperatorFailureV1) = values.getValue(code)
}
