package decompengine.chatgpt.operator

import decompengine.chatgpt.ChatGptAuthorizationTarget
import java.util.UUID

/** Pure in-memory/scripted counterpart for safe account projections and explicit owner actions. */
internal interface OperatorDataScriptV1 {
    fun passiveStatus(): OperatorResultV1<OperatorStatusV1>
    fun select(accountId: String, expected: OperatorVersionV1): OperatorResultV1<OperatorStatusV1>
    fun refreshCatalog(accountId: String, expected: OperatorVersionV1): OperatorResultV1<CatalogViewV1>
    fun setModel(accountId: String, slug: String, catalogId: UUID, expected: OperatorVersionV1): OperatorResultV1<PlanAccountViewV1>
    fun refreshAccount(accountId: String, expected: OperatorVersionV1): OperatorResultV1<PlanAccountViewV1>
    fun signOut(accountId: String, expected: OperatorVersionV1): OperatorResultV1<SignOutViewV1>
    fun acknowledgeWelcome(noticeId: UUID, expected: OperatorVersionV1): OperatorResultV1<PlanAccountViewV1>
    fun passiveDoctor(): OperatorResultV1<PlanDoctorViewV1>
}

/**
 * Explicit fake composition for the declared port. Account/store/catalog effects are supplied by
 * scripted in-memory ports. No production factory, transport, process, file, or listener is used.
 */
internal class ScriptedChatGptPlanOperatorPortV1(
    private val attempts: OperatorAttemptReducerV1,
    private val data: OperatorDataScriptV1,
    acceptedOwners: Set<OperatorOwnerV1>,
    private val ownerIsLive: (OperatorOwnerV1) -> Boolean,
) : ChatGptPlanOperatorPortV1 {
    private val owners = acceptedOwners.toSet()
    private fun <T> denied(): OperatorResultV1<T> = OperatorResultV1.Failed(OperatorFailureV1.NOT_FOUND)
    private fun live(owner: OperatorOwnerV1) = owner in owners && runCatching { ownerIsLive(owner) }.getOrDefault(false)
    private fun <T> safe(block: () -> OperatorResultV1<T>): OperatorResultV1<T> =
        try { block() } catch (_: Exception) { OperatorResultV1.Failed(OperatorFailureV1.UNAVAILABLE) }

    override fun status(owner: OperatorOwnerV1): OperatorResultV1<OperatorStatusV1> =
        if (live(owner)) safe { data.passiveStatus() } else denied()
    override fun beginSignIn(owner: OperatorOwnerV1, target: ChatGptAuthorizationTarget, expected: OperatorVersionV1,
        requestKey: String): OperatorResultV1<SignInStatusV1> =
        if (live(owner)) attempts.begin(owner, target, expected, requestKey) else denied()
    override fun takeSignInLaunch(owner: OperatorOwnerV1, attemptId: UUID): OperatorResultV1<SignInLaunchV1> =
        if (live(owner)) attempts.takeLaunch(owner, attemptId) else denied()
    override fun signInStatus(owner: OperatorOwnerV1, attemptId: UUID): OperatorResultV1<SignInStatusV1> =
        if (live(owner)) attempts.status(owner, attemptId) else denied()
    override fun cancelSignIn(owner: OperatorOwnerV1, attemptId: UUID): OperatorResultV1<SignInStatusV1> =
        if (live(owner)) attempts.cancel(owner, attemptId) else denied()
    override fun select(owner: OperatorOwnerV1, accountId: String, expected: OperatorVersionV1): OperatorResultV1<OperatorStatusV1> =
        if (live(owner)) safe { data.select(accountId, expected) } else denied()
    override fun refreshCatalog(owner: OperatorOwnerV1, accountId: String, expected: OperatorVersionV1): OperatorResultV1<CatalogViewV1> =
        if (live(owner)) safe { data.refreshCatalog(accountId, expected) } else denied()
    override fun setModel(owner: OperatorOwnerV1, accountId: String, slug: String, catalogId: UUID,
        expected: OperatorVersionV1): OperatorResultV1<PlanAccountViewV1> =
        if (live(owner)) safe { data.setModel(accountId, slug, catalogId, expected) } else denied()
    override fun refreshAccount(owner: OperatorOwnerV1, accountId: String, expected: OperatorVersionV1): OperatorResultV1<PlanAccountViewV1> =
        if (live(owner)) safe { data.refreshAccount(accountId, expected) } else denied()
    override fun signOut(owner: OperatorOwnerV1, accountId: String, expected: OperatorVersionV1): OperatorResultV1<SignOutViewV1> =
        if (live(owner)) safe { data.signOut(accountId, expected) } else denied()
    override fun acknowledgeWelcome(owner: OperatorOwnerV1, noticeId: UUID,
        expected: OperatorVersionV1): OperatorResultV1<PlanAccountViewV1> =
        if (live(owner)) safe { data.acknowledgeWelcome(noticeId, expected) } else denied()
    override fun doctor(owner: OperatorOwnerV1): OperatorResultV1<PlanDoctorViewV1> =
        if (live(owner)) safe { data.passiveDoctor() } else denied()
}
