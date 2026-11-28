package decompengine.chatgpt.operator

import decompengine.chatgpt.*
import java.time.Instant
import java.util.UUID
import kotlin.test.*

class OperatorMutationBoundaryV1Test {
    private val queued = ArrayDeque<() -> Unit>()
    private var prepared = 0
    private val claim = FakeRootAttemptClaimV1()
    private val script = object : OperatorSignInScriptV1 {
        override fun prepare(target: ChatGptAuthorizationTarget, deadlineNanos: Long): PreparedSignInV1 {
            prepared++
            return PreparedSignInV1(ChatGptPlanOAuthAttempt.AuthorizationRequest("https://auth.openai.com/authorize?state=s&nonce=n&code_challenge=c&code_challenge_method=S256"))
        }
        override fun cancel(attemptId: UUID) = OperatorCancelOutcomeV1(ChatGptAuthCancelResult.CANCELLED, ChatGptAuthSettlement.SETTLED)
        override fun status(attemptId: UUID): ChatGptAuthCommit? = null
    }
    private fun reducer() = OperatorAttemptReducerV1({ 10L }, { Instant.parse("2026-11-05T00:00:00Z") }, claim, script,
        OperatorPhaseExecutorV1 { queued.add(it) }, accountVersionCurrent = { _, _ -> false })

    @Test fun secondLaunchNeverDeliversAnotherPayload() {
        val r=reducer();val owner=OperatorOwnerIssuerV1.cli()
        val a=assertIs<OperatorResultV1.Ok<SignInStatusV1>>(r.begin(owner,ChatGptAuthorizationTarget.New(),OperatorVersionV1(0),"isolated-boundary-key-01")).value
        queued.removeFirst().invoke()
        assertIs<OperatorResultV1.Ok<SignInLaunchV1>>(r.takeLaunch(owner,a.attemptId))
        assertIs<OperatorResultV1.Failed>(r.takeLaunch(owner,a.attemptId),"replay must not return a second payload, regardless of fixed failure code")
        assertEquals(1,prepared)
    }

    @Test fun foreignOwnerNeverReceivesLaunchPayload() {
        val r=reducer();val owner=OperatorOwnerIssuerV1.cli()
        val a=assertIs<OperatorResultV1.Ok<SignInStatusV1>>(r.begin(owner,ChatGptAuthorizationTarget.New(),OperatorVersionV1(0),"isolated-boundary-key-01")).value
        queued.removeFirst().invoke()
        assertIs<OperatorResultV1.Failed>(r.takeLaunch(OperatorOwnerIssuerV1.webSession(),a.attemptId),"foreign owner cannot receive the payload")
    }

    @Test fun staleAccountIsRejectedWithNoCompetingActiveAttempt() {
        val r=reducer();val owner=OperatorOwnerIssuerV1.cli();val id="00000000-0000-0000-0000-000000000001"
        val result=r.begin(owner,ChatGptAuthorizationTarget.Account(id),OperatorVersionV1(0,id,1,0),"isolated-boundary-key-01")
        assertIs<OperatorResultV1.Failed>(result,"stale stamp cannot admit a worker or claim when no competing attempt masks it")
        assertFalse(claim.held());assertEquals(0,queued.size);assertEquals(0,prepared)
    }
}
