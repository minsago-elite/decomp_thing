package decompengine.chatgpt.operator

import decompengine.chatgpt.*
import decompengine.builtin.*
import decompengine.builtin.provider.*
import decompengine.agent.*
import decompengine.project.GeneratedCValidationHostSafetyLimits
import decompengine.repair.RepairResourceBudget
import java.time.Duration
import java.time.Instant
import java.util.UUID
import kotlin.test.*

/** Independent additions; original suites, loops and classes are unchanged. */
class OperatorLifecycleBoundaryV1Test {
    private val wall = Instant.parse("2026-11-05T00:00:00Z")
    private val subject = "a".repeat(64)
    private val url = "https://auth.openai.com/authorize?state=s&nonce=n&code_challenge=c&code_challenge_method=S256"
    private fun <T> ok(r: OperatorResultV1<T>): T = assertIs<OperatorResultV1.Ok<T>>(r).value
    private class Commit(override val state: ChatGptAuthCommitState,
        override val account: ChatGptPlanAccount? = null) : ChatGptAuthCommit()
    private fun account() = ChatGptPlanAccount("00000000-0000-0000-0000-000000000001",
        "https://auth.openai.com", "oaiapp_fixture", "fixture", null, null, 1, 0,
        ChatGptPlanAccount.State.READY, setOf("resource.invoke", "chatgpt.tokens.use.direct"), wall.plusSeconds(3600))
    private class Script(val url: String): OperatorSignInScriptV1 {
        var prepares = 0; var cancels = 0
        var prepareEffect: (() -> Unit)? = null
        var cancelEffect: (() -> OperatorCancelOutcomeV1)? = null
        override fun prepare(target: ChatGptAuthorizationTarget, deadlineNanos: Long): PreparedSignInV1 {
            prepares++; prepareEffect?.invoke()
            return PreparedSignInV1(ChatGptPlanOAuthAttempt.AuthorizationRequest(url))
        }
        override fun cancel(attemptId: UUID): OperatorCancelOutcomeV1 {
            cancels++; return cancelEffect?.invoke() ?: OperatorCancelOutcomeV1(ChatGptAuthCancelResult.CANCELLED, ChatGptAuthSettlement.UNSETTLED)
        }
        override fun status(attemptId: UUID): ChatGptAuthCommit? = null
    }

    @Test fun failedRootReleaseRetainsClaimUntilSuccessfulAcknowledgement() {
        val root = FakeRootAttemptClaimV1(); var releases = 0
        val claim = object: OperatorRootAttemptClaimV1 {
            override fun claim(attemptId: UUID) = root.claim(attemptId)
            override fun release(attemptId: UUID): Boolean { releases++; if (releases == 1) error("release failed"); return root.release(attemptId) }
        }
        val script = Script(url); script.cancelEffect = { OperatorCancelOutcomeV1(ChatGptAuthCancelResult.CANCELLED, ChatGptAuthSettlement.SETTLED) }
        val tasks = ArrayDeque<() -> Unit>(); val owner = OperatorOwnerIssuerV1.cli()
        val r = OperatorAttemptReducerV1(OperatorMonotonicClockV1 { 100 }, { wall }, claim, script, OperatorPhaseExecutorV1 { tasks.add(it) })
        val a = ok(r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "failed-release-001")).attemptId
        tasks.removeFirst()(); r.cancel(owner, a)
        assertTrue(root.held()); assertEquals(ChatGptAuthSettlement.UNSETTLED, ok(r.status(owner,a)).cleanup)
        assertEquals(OperatorFailureV1.ATTEMPT_IN_PROGRESS, assertIs<OperatorResultV1.Failed>(r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "failed-release-002")).code)
        r.cleanupSettled(a); assertFalse(root.held()); assertEquals(2, releases)
    }

    @Test fun cancellationDuringRootClaimCannotDispatchOrInventSettlement() {
        val root = FakeRootAttemptClaimV1(); val owner = OperatorOwnerIssuerV1.cli(); val script = Script(url)
        lateinit var r: OperatorAttemptReducerV1
        val claim = object: OperatorRootAttemptClaimV1 {
            override fun claim(attemptId: UUID): Boolean {
                val acquired = root.claim(attemptId); r.cancel(owner, attemptId); r.cleanupSettled(attemptId); return acquired
            }
            override fun release(attemptId: UUID) = root.release(attemptId)
        }
        val tasks = ArrayDeque<() -> Unit>()
        r = OperatorAttemptReducerV1(OperatorMonotonicClockV1 { 100 }, { wall }, claim, script, OperatorPhaseExecutorV1 { tasks.add(it) })
        val a = ok(r.begin(owner,ChatGptAuthorizationTarget.New(),OperatorVersionV1(0),"claim-cancel-00001")).attemptId
        assertTrue(tasks.isEmpty()); assertEquals(0,script.prepares); assertEquals(1,script.cancels)
        assertTrue(root.held()); assertEquals(ChatGptAuthSettlement.UNSETTLED,ok(r.status(owner,a)).cleanup)
        assertIs<OperatorResultV1.Failed>(r.takeLaunch(owner,a)); r.cleanupSettled(a); assertFalse(root.held())
    }

    @Test fun phaseTimeoutBeforeOverallDeadlineRequestsCancellation() {
        var now = 100L; val root = FakeRootAttemptClaimV1(); val script = Script(url)
        script.prepareEffect = { now += Duration.ofSeconds(31).toNanos() }
        val tasks = ArrayDeque<() -> Unit>(); val owner = OperatorOwnerIssuerV1.cli()
        val r = OperatorAttemptReducerV1(OperatorMonotonicClockV1 { now }, { wall }, root, script, OperatorPhaseExecutorV1 { tasks.add(it) })
        val a = ok(r.begin(owner,ChatGptAuthorizationTarget.New(),OperatorVersionV1(0),"phase-timeout-0001")).attemptId
        tasks.removeFirst()(); assertEquals(1,script.cancels); assertTrue(root.held())
        assertEquals(ChatGptAuthSettlement.UNSETTLED,ok(r.status(owner,a)).cleanup); assertIs<OperatorResultV1.Failed>(r.takeLaunch(owner,a))
        r.cleanupSettled(a); assertFalse(root.held())
    }

    @Test fun durableWinnerSurvivesThrowingCancelCallback() {
        val root = FakeRootAttemptClaimV1(); val script = Script(url); val tasks = ArrayDeque<() -> Unit>(); val owner = OperatorOwnerIssuerV1.cli()
        val r = OperatorAttemptReducerV1(OperatorMonotonicClockV1 { 100 }, { wall }, root, script, OperatorPhaseExecutorV1 { tasks.add(it) })
        val a = ok(r.begin(owner,ChatGptAuthorizationTarget.New(),OperatorVersionV1(0),"throw-after-durable")).attemptId; tasks.removeFirst()()
        script.cancelEffect = { r.complete(a,Commit(ChatGptAuthCommitState.DURABLE,account()),ChatGptAuthSettlement.SETTLED,subject); error("after publication") }
        val status = ok(r.cancel(owner,a)); assertEquals(SignInPhaseV1.SUCCEEDED,status.phase)
        assertEquals(ChatGptAuthCommitState.DURABLE,status.commit); assertNotNull(status.account); assertNotNull(r.pendingWelcome(account(),subject)); assertFalse(root.held())
    }

    private fun admitted(clock: NanoClockV2, deadline: Long, tools: () -> List<ToolDefinitionV2>): Pair<ChatGptPlanRunElectionV1,AdmittedModelRunV2> {
        val f = V2Fixture(); val stamp = AccountStampV1(f.binding.accountId.toString(),f.binding.authEpoch,0)
        val c = CatalogViewV1(stamp,UUID.randomUUID(),wall,wall.plusSeconds(60),listOf(PlanModelViewV1(f.binding.modelSlug,"fixture")),OperatorVersionV1(0,stamp.accountId,stamp.authEpoch,stamp.generation))
        val limits = ChatGptLocalLimitsV1.from(LocalBudgetV1(wallClock=Duration.ofSeconds(1)))
        val e = ChatGptPlanRunElectionV1(stamp.accountId,f.binding.modelSlug,"local-acceptance-v1",1,true,stamp.authEpoch,0,c.catalogId.toString(),limits)
        val run = admitPlanElection(e,ProviderCapabilitiesV2.siwc(),CallerRequirementsV2(AgentExecutionLimits(),LocalBudgetV1()),HostAdmissionLimitsV2(LocalBudgetV1(),GeneratedCValidationHostSafetyLimits()),ProfileAdmissionLimitsV2(LocalBudgetV1(),RepairResourceBudget()),RunCommitmentsV2("1".repeat(64),"2".repeat(64),"3".repeat(64),"4".repeat(64),"5".repeat(64)),tools,clock,deadline,trustedStamp=stamp,trustedCatalog=c,now=wall,binding=f.binding)
        return e to run
    }

    @Test fun admissionCannotResetOriginalDeadlineBetweenTwoChecks() {
        var reads = 0; var effects = 0
        val failure = assertFailsWith<ModelProviderException> { admitted(NanoClockV2 { reads++; if(reads < 4) 0L else Duration.ofSeconds(1).toNanos() },Duration.ofSeconds(1).toNanos()) { effects++; V2Fixture().definitions } }
        assertEquals(ModelFailureKind.TIMEOUT,failure.kind); assertEquals(0,effects)
    }

    @Test fun failedPostToolBindCannotInventAdmissionCapture() {
        var cancelled = false; var effects = 0
        // The clock advances to the original deadline inside the supplied metadata effect.
        val failure = assertFailsWith<ModelProviderException> { admitted(NanoClockV2 { if(cancelled) Duration.ofSeconds(1).toNanos() else 0L },Duration.ofSeconds(1).toNanos()) { effects++; cancelled=true; V2Fixture().definitions } }
        assertEquals(ModelFailureKind.TIMEOUT,failure.kind); assertEquals(1,effects)
    }
}
