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

/** Bounded, fake effects only. Red assertions state the required invariant. */
class OperatorRemediationV1Test {
    private val wall = Instant.parse("2026-11-05T00:00:00Z")
    private val subject = "a".repeat(64)
    private val id = "00000000-0000-0000-0000-000000000001"
    private val url = "https://auth.openai.com/authorize?state=s&nonce=n&code_challenge=c&code_challenge_method=S256"
    private class Clock(var now: Long = 100L) : OperatorMonotonicClockV1 { override fun nowNanos() = now }
    private class Queue : OperatorPhaseExecutorV1 {
        val tasks = ArrayDeque<() -> Unit>()
        override fun execute(task: () -> Unit) { tasks.add(task) }
        fun run() = tasks.removeFirst().invoke()
    }
    private class Script(private val url: String) : OperatorSignInScriptV1 {
        var prepares = 0; var cancels = 0; var reads = 0
        var onPrepare: (() -> PreparedSignInV1)? = null
        var onCancel: (() -> OperatorCancelOutcomeV1)? = null
        var onStatus: (() -> ChatGptAuthCommit?)? = null
        override fun prepare(target: ChatGptAuthorizationTarget, deadlineNanos: Long): PreparedSignInV1 {
            prepares++; return onPrepare?.invoke() ?: PreparedSignInV1(ChatGptPlanOAuthAttempt.AuthorizationRequest(url))
        }
        override fun cancel(attemptId: UUID): OperatorCancelOutcomeV1 {
            cancels++; return onCancel?.invoke() ?: OperatorCancelOutcomeV1(ChatGptAuthCancelResult.CANCELLED, ChatGptAuthSettlement.SETTLED)
        }
        override fun status(attemptId: UUID): ChatGptAuthCommit? { reads++; return onStatus?.invoke() }
    }
    private class Commit(override val state: ChatGptAuthCommitState, override val account: ChatGptPlanAccount?) : ChatGptAuthCommit()
    private inner class Env(launchUrl: String = url) {
        val clock = Clock(); val queue = Queue(); val script = Script(launchUrl); val claim = FakeRootAttemptClaimV1()
        val owner = OperatorOwnerIssuerV1.cli()
        val reducer = OperatorAttemptReducerV1(clock, { wall }, claim, script, queue)
        fun begin(key: String = "independent-key-00001") = ok(reducer.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), key)).attemptId
        fun status(attempt: UUID) = ok(reducer.status(owner, attempt))
    }
    private fun <T> ok(result: OperatorResultV1<T>): T = assertIs<OperatorResultV1.Ok<T>>(result).value
    private fun account(scopes: Set<String> = setOf("resource.invoke", "chatgpt.tokens.use.direct")) = ChatGptPlanAccount(
        id, "https://auth.openai.com", "oaiapp_fixture", "Fixture", null, null, 1, 0,
        ChatGptPlanAccount.State.READY, scopes, wall.plusSeconds(3600))
    private fun durable(account: ChatGptPlanAccount = account()) = Commit(ChatGptAuthCommitState.DURABLE, account)

    @Test fun preparationFailureMustNotInventSettledCleanup() {
        val e = Env(); var resourceLive = false
        e.script.onPrepare = { resourceLive = true; error("scripted failure after acquisition") }
        e.script.onCancel = { OperatorCancelOutcomeV1(ChatGptAuthCancelResult.CANCELLED, ChatGptAuthSettlement.UNSETTLED) }
        val a = e.begin(); e.queue.run()
        assertTrue(resourceLive); assertEquals(1, e.script.cancels)
        assertTrue(e.claim.held(), "unacknowledged acquired resource must retain root ownership")
        assertEquals(ChatGptAuthSettlement.UNSETTLED, e.status(a).cleanup)
    }

    @Test fun rejectedLaunchMustCancelAndRetainUnsettledCleanup() {
        val e = Env(url + "&id_token_hint=fixture")
        e.script.onCancel = { OperatorCancelOutcomeV1(ChatGptAuthCancelResult.CANCELLED, ChatGptAuthSettlement.UNSETTLED) }
        val a = e.begin(); e.queue.run()
        assertIs<OperatorResultV1.Failed>(e.reducer.takeLaunch(e.owner, a))
        assertEquals(1, e.script.cancels, "URL rejection must request actual cleanup")
        assertTrue(e.claim.held()); assertEquals(ChatGptAuthSettlement.UNSETTLED, e.status(a).cleanup)
    }

    @Test fun lateDurableCallbackCannotResurrectCancelledUnsettledAttempt() {
        val e = Env(); val a = e.begin(); e.queue.run()
        e.script.onCancel = { OperatorCancelOutcomeV1(ChatGptAuthCancelResult.CANCELLED, ChatGptAuthSettlement.UNSETTLED) }
        e.reducer.cancel(e.owner, a)
        e.reducer.complete(a, durable(), ChatGptAuthSettlement.SETTLED, subject)
        assertEquals(SignInPhaseV1.CLEANUP_PENDING, e.status(a).phase, "CANCELLED outcome remains fenced during cleanup")
        assertNull(e.reducer.pendingWelcome(account(), subject))
    }

    @Test fun cancellationCallbackCannotOverwriteReentrantDurablePublication() {
        val e = Env(); val a = e.begin(); e.queue.run()
        e.script.onCancel = {
            e.reducer.complete(a, durable(), ChatGptAuthSettlement.SETTLED, subject)
            OperatorCancelOutcomeV1(ChatGptAuthCancelResult.ALREADY_SETTLED, ChatGptAuthSettlement.SETTLED)
        }
        assertEquals(SignInPhaseV1.SUCCEEDED, ok(e.reducer.cancel(e.owner, a)).phase,
            "ALREADY_SETTLED must preserve the durable callback published during cancel")
    }

    @Test fun revokedOwnerCannotReconcileOrReadAccount() {
        val e = Env(); val a = e.begin(); e.queue.run()
        e.reducer.complete(a, Commit(ChatGptAuthCommitState.COMMIT_UNKNOWN, null), ChatGptAuthSettlement.SETTLED, subject)
        e.script.onStatus = { durable() }; e.reducer.ownerRevoked(e.owner)
        val result = e.reducer.reconcileCommitUnknown(e.owner, a, subject)
        assertEquals(0, e.script.reads, "revoked owner cannot initiate fresh status effects")
        assertEquals(OperatorFailureV1.NOT_FOUND, assertIs<OperatorResultV1.Failed>(result).code)
    }

    @Test fun revokedOwnerCannotReadTerminalAccountThroughCancel() {
        val e = Env(); val a = e.begin(); e.queue.run()
        e.reducer.complete(a, durable(), ChatGptAuthSettlement.SETTLED, subject); e.reducer.ownerRevoked(e.owner)
        assertEquals(OperatorFailureV1.NOT_FOUND, assertIs<OperatorResultV1.Failed>(e.reducer.cancel(e.owner, a)).code)
    }

    @Test fun committedAccountMustDetachCallerScopesBeforeRetention() {
        val e = Env(); val a = e.begin(); e.queue.run()
        val scopes = mutableSetOf("resource.invoke", "chatgpt.tokens.use.direct")
        e.reducer.complete(a, durable(account(scopes)), ChatGptAuthSettlement.SETTLED, subject)
        val first = e.status(a); scopes.clear()
        assertEquals(2, first.account!!.account.scopes.size, "previous returned DTO remains immutable")
        assertEquals(2, e.status(a).account!!.account.scopes.size, "retained committed state must also be detached")
    }

    @Test fun selectedExpiredCatalogMustNotMintElection() {
        var now = 10L
        val r = OperatorSelectionReducerV1({ now }, { wall })
        val stamp = AccountStampV1(id, 1, 0); val seq = r.switched(id, stamp)
        val c = CatalogViewV1(stamp, UUID.randomUUID(), wall, wall.plusSeconds(1), listOf(PlanModelViewV1("returned", "Returned")), OperatorVersionV1(0,id,1,0))
        assertTrue(r.acceptCatalog(seq,id,stamp,c)); assertTrue(r.chooseModel(seq,"returned"))
        assertNotNull(r.election(id,ChatGptLocalLimitsV1.from(LocalBudgetV1()),true))
        now += Duration.ofSeconds(2).toNanos()
        assertNull(r.election(id,ChatGptLocalLimitsV1.from(LocalBudgetV1()),true), "expiry must gate election as well as model selection")
    }

    private inner class Admission {
        val fixture = V2Fixture()
        val limits = ChatGptLocalLimitsV1.from(LocalBudgetV1())
        val stamp = AccountStampV1(fixture.binding.accountId.toString(),fixture.binding.authEpoch,0)
        val catalog = CatalogViewV1(stamp,UUID.randomUUID(),wall,wall.plusSeconds(120),listOf(PlanModelViewV1(fixture.binding.modelSlug,"Fixture")),OperatorVersionV1(0,stamp.accountId,stamp.authEpoch,0))
        val election = ChatGptPlanRunElectionV1(stamp.accountId,fixture.binding.modelSlug,"local-acceptance-v1",1,true,stamp.authEpoch,0,catalog.catalogId.toString(),limits)
        val commitments = RunCommitmentsV2("1".repeat(64),"2".repeat(64),"3".repeat(64),"4".repeat(64),"5".repeat(64))
        var tools = 0
        fun admit(e: ChatGptPlanRunElectionV1 = election, local: LocalBudgetV1 = LocalBudgetV1(), legacy: AgentExecutionLimits = AgentExecutionLimits(),
            stamp: AccountStampV1 = this.stamp, catalog: CatalogViewV1 = this.catalog,
            cancellation: AgentCancellation = AgentCancellation.NONE, hostLocal: LocalBudgetV1 = LocalBudgetV1(), profileLocal: LocalBudgetV1 = LocalBudgetV1()): AdmittedModelRunV2 = admitPlanElection(e,ProviderCapabilitiesV2.siwc(),CallerRequirementsV2(legacy,local),
                HostAdmissionLimitsV2(hostLocal,GeneratedCValidationHostSafetyLimits()),ProfileAdmissionLimitsV2(profileLocal,RepairResourceBudget()),
                commitments,{ tools++; fixture.definitions },NanoClockV2 { 0 },Duration.ofMinutes(20).toNanos(),cancellation,
                stamp,catalog,wall.plusSeconds(1),fixture.binding)
    }

    @Test fun explicitElectionCannotEraseStricterCallerLocalLimits() {
        val f = Admission(); val run = f.admit(local = LocalBudgetV1(inputUnits=7,outputUnits=3,maxRequests=2))
        assertEquals(3L,run.budget.outputUnits,"caller local output ceiling must survive election")
        assertEquals(7L,run.budget.inputUnits); assertEquals(2,run.budget.maxRequests)
    }

    @Test fun capturedElectionCannotClaimSmallerLimitsThanActualAdmission() {
        val f = Admission(); val run = f.admit()
        val forged = f.election.copy(requestedLimits=f.limits.copy(outputUnits=1))
        assertFails("capture must bind the original election instead of relabelling admitted work") { capturePlanAdmission(forged,f.stamp,run) }
    }

    @Test fun cleanupNotificationCannotReleaseStillLaunchableAttempt() {
        val e=Env();val a=e.begin();e.queue.run();e.reducer.cleanupSettled(a)
        assertIs<OperatorResultV1.Failed>(e.reducer.takeLaunch(e.owner,a),"cleanup-complete attempt cannot still publish a launch")
    }

    @Test fun duplicateCleanupNotificationCannotExtendTerminalRetention() {
        val e=Env();val a=e.begin();e.queue.run();e.reducer.cancel(e.owner,a)
        e.clock.now+=Duration.ofMinutes(4).toNanos();e.reducer.cleanupSettled(a)
        e.clock.now+=Duration.ofMinutes(2).toNanos();e.reducer.sweepExpired()
        assertIs<OperatorResultV1.Failed>(e.reducer.status(e.owner,a),"duplicate settled notification must not renew terminal TTL")
    }

    @Test fun strictCapStillRefusesBeforeToolDefinitionEffects() {
        val f=Admission()
        val failure=assertFailsWith<ModelProviderException> { f.admit(legacy=AgentExecutionLimits(maxOutputTokens=1)) }
        assertEquals(ModelFailureKind.UNSUPPORTED_FEATURE,failure.kind);assertEquals(0,f.tools)
    }

    @Test fun cancelledAdmissionRefusesBeforeToolDefinitions() {
        val f=Admission()
        val failure=assertFailsWith<ModelProviderException> { f.admit(cancellation=AgentCancellation { true }) }
        assertEquals(ModelFailureKind.CANCELLED,failure.kind);assertEquals(0,f.tools)
    }

    @Test fun explicitConsentAndCurrentGenerationRemainRequired() {
        val f=Admission()
        assertFails { f.admit(e=f.election.copy(acceptedLocalLimits=false)) }
        assertFails { f.admit(stamp=f.stamp.copy(generation=1)) }
        assertEquals(0,f.tools)
        val run=f.admit();assertEquals(f.fixture.binding.commitment(),run.bindingCommitment);assertEquals(1,f.tools)
    }

    @Test fun projectionContainersRejectMutationAndDetachInputs() {
        val scopes=mutableSetOf("resource.invoke");val a=account(scopes)
        val v=PlanAccountViewV1(a,OperatorVersionV1(0,id,1,0),null)
        val rows=mutableListOf(v);val status=OperatorStatusV1(rows,id,0,true,null)
        scopes.clear();rows.clear();assertEquals(1,status.accounts.size);assertEquals(1,v.account.scopes.size)
        assertFailsWith<UnsupportedOperationException> { (status.accounts as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (v.account.scopes as MutableSet).clear() }
    }

    @Test fun parserRejectsDuplicateKeysMalformedUtf8AndExcessDepth() {
        val f=Admission();val run=f.admit();val capture=capturePlanAdmission(f.election,f.stamp,run)
        assertEquals(64,capture.electionSha256.length)
        for(bytes in listOf("{\"inputUnits\":\"1\",\"inputUnits\":\"2\"}".toByteArray(),byteArrayOf(0xc0.toByte(),0xaf.toByte()),("[".repeat(9)+"0"+"]".repeat(9)).toByteArray()))
            assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseLimits(bytes) }
    }

    @Test fun explicitReconciliationUsesOneReadAndNoNewPreparation() {
        val e=Env();val a=e.begin();e.queue.run()
        e.reducer.complete(a,Commit(ChatGptAuthCommitState.COMMIT_UNKNOWN,null),ChatGptAuthSettlement.SETTLED,subject)
        repeat(3) { assertEquals(SignInPhaseV1.COMMIT_UNKNOWN,e.status(a).phase) };assertEquals(0,e.script.reads)
        e.script.onStatus={durable()}
        assertEquals(SignInPhaseV1.SUCCEEDED,ok(e.reducer.reconcileCommitUnknown(e.owner,a,subject)).phase)
        assertEquals(1,e.script.reads);assertEquals(1,e.script.prepares);assertEquals(0,e.script.cancels)
    }

    @Test fun executorFailureRequestsCancellationAndCannotRunQueuedWork() {
        val owner=OperatorOwnerIssuerV1.cli(); val root=FakeRootAttemptClaimV1();val script=Script(url)
        var queued:(()->Unit)?=null
        script.onCancel={OperatorCancelOutcomeV1(ChatGptAuthCancelResult.CANCELLED,ChatGptAuthSettlement.UNSETTLED)}
        val reducer=OperatorAttemptReducerV1(Clock(),{wall},root,script,OperatorPhaseExecutorV1 { queued=it;error("handoff failed") })
        val a=ok(reducer.begin(owner,ChatGptAuthorizationTarget.New(),OperatorVersionV1(0),"executor-failure-001")).attemptId
        assertEquals(1,script.cancels);assertTrue(root.held());queued!!()
        assertEquals(0,script.prepares);assertIs<OperatorResultV1.Failed>(reducer.takeLaunch(owner,a))
        reducer.cleanupSettled(a);assertFalse(root.held())
    }

    @Test fun inFlightPreparationCannotReleaseOnEarlyAcknowledgementOrResurrectLaunch() {
        val e=Env();val a=e.begin()
        e.script.onPrepare={
            e.reducer.cancel(e.owner,a)
            assertTrue(e.claim.held());e.reducer.cleanupSettled(a);assertTrue(e.claim.held())
            PreparedSignInV1(ChatGptPlanOAuthAttempt.AuthorizationRequest(url))
        }
        e.queue.run();assertTrue(e.claim.held());assertEquals(ChatGptAuthSettlement.UNSETTLED,e.status(a).cleanup)
        assertIs<OperatorResultV1.Failed>(e.reducer.takeLaunch(e.owner,a));e.reducer.cleanupSettled(a);assertFalse(e.claim.held())
    }

    @Test fun queuedPreparationCannotRunAfterCleanupNotification() {
        val e=Env();val a=e.begin();e.reducer.cleanupSettled(a)
        assertFalse(e.claim.held());e.queue.run();assertEquals(0,e.script.prepares)
        assertIs<OperatorResultV1.Failed>(e.reducer.takeLaunch(e.owner,a))
    }

    @Test fun cancelExceptionFencesLateCompletionAndRetainsCleanup() {
        val e=Env();val a=e.begin();e.queue.run();e.script.onCancel={error("cancel unknown")}
        e.reducer.cancel(e.owner,a);e.reducer.complete(a,durable(),ChatGptAuthSettlement.SETTLED,subject)
        assertEquals(SignInPhaseV1.CLEANUP_PENDING,e.status(a).phase);assertTrue(e.claim.held())
        assertNull(e.reducer.pendingWelcome(account(),subject));e.reducer.cleanupSettled(a);assertFalse(e.claim.held())
    }

    @Test fun invalidCommitDataCannotPartiallyPublish() {
        val e=Env();val a=e.begin();e.queue.run();val before=e.status(a)
        for (bad in listOf(account().copy(accountId="bad"),account().copy(clientId="bad"),account(setOf("bad scope")),account().copy(label="x".repeat(121)))) {
            e.reducer.complete(a,durable(bad),ChatGptAuthSettlement.SETTLED,subject)
            assertEquals(before.version,e.status(a).version);assertEquals(before.phase,e.status(a).phase);assertTrue(e.claim.held())
        }
        e.reducer.complete(a,durable(),ChatGptAuthSettlement.SETTLED,"bad")
        assertEquals(before.version,e.status(a).version);assertNull(e.status(a).account);assertNull(e.reducer.pendingWelcome(account(),subject))
        val throwing=object:ChatGptAuthCommit(){override val state=ChatGptAuthCommitState.DURABLE;override val account:ChatGptPlanAccount? get()=error("getter")}
        e.reducer.complete(a,throwing,ChatGptAuthSettlement.SETTLED,subject);assertEquals(before.version,e.status(a).version)
    }

    @Test fun reentrantCommitGetterCannotPublishAfterCancellation() {
        val e=Env();val a=e.begin();e.queue.run();var reads=0;var accountReads=0
        val commit=object:ChatGptAuthCommit(){
            override val state:ChatGptAuthCommitState get(){reads++;e.reducer.cancel(e.owner,a);return ChatGptAuthCommitState.DURABLE}
            override val account:ChatGptPlanAccount? get(){accountReads++;return account()}
        }
        e.reducer.complete(a,commit,ChatGptAuthSettlement.SETTLED,subject)
        assertEquals(1,reads);assertEquals(0,accountReads);assertEquals(SignInPhaseV1.CANCELLED,e.status(a).phase);assertNull(e.reducer.pendingWelcome(account(),subject))
    }

    @Test fun scopeCopyReentrancyIsCheckedBeforePublication() {
        val e=Env();val a=e.begin();e.queue.run()
        val scopes=object:AbstractSet<String>() {
            override val size=2
            override fun iterator():Iterator<String> {e.reducer.cancel(e.owner,a);return setOf("resource.invoke","chatgpt.tokens.use.direct").iterator()}
        }
        e.reducer.complete(a,durable(account(scopes)),ChatGptAuthSettlement.SETTLED,subject)
        assertEquals(SignInPhaseV1.CANCELLED,e.status(a).phase);assertNull(e.reducer.pendingWelcome(account(),subject))
    }

    @Test fun revokedDuringReconcileDoesNotReadGettersOrPublishWelcome() {
        val e=Env();val a=e.begin();e.queue.run()
        e.reducer.complete(a,Commit(ChatGptAuthCommitState.COMMIT_UNKNOWN,null),ChatGptAuthSettlement.SETTLED,subject)
        e.script.onStatus={e.reducer.ownerRevoked(e.owner);object:ChatGptAuthCommit(){
            override val state:ChatGptAuthCommitState get()=error("stale result must not read state")
            override val account:ChatGptPlanAccount? get()=error("stale result must not read account")}}
        assertEquals(OperatorFailureV1.NOT_FOUND,assertIs<OperatorResultV1.Failed>(e.reducer.reconcileCommitUnknown(e.owner,a,subject)).code)
        assertEquals(1,e.script.reads);assertNull(e.reducer.pendingWelcome(account(),subject))
    }

    @Test fun revokedDuringCancelCannotReturnTerminalAccount() {
        val e=Env();val a=e.begin();e.queue.run()
        e.script.onCancel={e.reducer.ownerRevoked(e.owner);e.reducer.complete(a,durable(),ChatGptAuthSettlement.SETTLED,subject)
            OperatorCancelOutcomeV1(ChatGptAuthCancelResult.ALREADY_SETTLED,ChatGptAuthSettlement.SETTLED)}
        assertEquals(OperatorFailureV1.NOT_FOUND,assertIs<OperatorResultV1.Failed>(e.reducer.cancel(e.owner,a)).code)
        assertNull(e.reducer.pendingWelcome(account(),subject));assertTrue(e.claim.held())
        e.reducer.cleanupSettled(a);assertFalse(e.claim.held())
    }

    @Test fun everyAttemptEffectAndCommitGetterRunsOutsideMonitor() {
        lateinit var r:OperatorAttemptReducerV1
        var ready=false;var checks=0
        fun unlocked(){if(ready){assertFalse(Thread.holdsLock(r));checks++}}
        val root=FakeRootAttemptClaimV1();val q=Queue();val owner=OperatorOwnerIssuerV1.cli()
        val claim=object:OperatorRootAttemptClaimV1{
            override fun claim(attemptId:UUID):Boolean{unlocked();return root.claim(attemptId)}
            override fun release(attemptId:UUID):Boolean{unlocked();return root.release(attemptId)}}
        val script=Script(url);script.onPrepare={unlocked();PreparedSignInV1(ChatGptPlanOAuthAttempt.AuthorizationRequest(url))}
        script.onCancel={unlocked();OperatorCancelOutcomeV1(ChatGptAuthCancelResult.CANCELLED,ChatGptAuthSettlement.SETTLED)}
        r=OperatorAttemptReducerV1(OperatorMonotonicClockV1{unlocked();100L},{unlocked();wall},claim,script,
            OperatorPhaseExecutorV1{unlocked();q.execute(it)},remoteProfileAllowed={unlocked();true},accountVersionCurrent={_,_->unlocked();true})
        ready=true
        val a=ok(r.begin(owner,ChatGptAuthorizationTarget.Account(id),OperatorVersionV1(0,id,1,0),"outside-monitor-001")).attemptId
        q.run();r.takeLaunch(owner,a)
        val commit=object:ChatGptAuthCommit(){override val state:ChatGptAuthCommitState get(){unlocked();return ChatGptAuthCommitState.COMMIT_UNKNOWN}
            override val account:ChatGptPlanAccount? get(){unlocked();return null}}
        r.complete(a,commit,ChatGptAuthSettlement.SETTLED,subject)
        script.onStatus={unlocked();durable()};r.reconcileCommitUnknown(owner,a,subject)
        val b=ok(r.begin(owner,ChatGptAuthorizationTarget.New(),OperatorVersionV1(0),"outside-monitor-002")).attemptId
        q.run();r.cancel(owner,b);assertTrue(checks>=15);assertFalse(root.held())
    }

    @Test fun terminalRetentionStartsOnceEvenWhenUnknownLaterBecomesDurable() {
        val e=Env();val a=e.begin();e.queue.run()
        e.reducer.complete(a,Commit(ChatGptAuthCommitState.COMMIT_UNKNOWN,null),ChatGptAuthSettlement.SETTLED,subject)
        e.clock.now+=Duration.ofMinutes(4).toNanos();e.script.onStatus={durable()}
        e.reducer.reconcileCommitUnknown(e.owner,a,subject);e.clock.now+=Duration.ofMinutes(2).toNanos();e.reducer.sweepExpired()
        assertIs<OperatorResultV1.Failed>(e.reducer.status(e.owner,a))
    }

    @Test fun expiryClearsSelectionEvenIfClockMovesBackwards() {
        var now=100L;val r=OperatorSelectionReducerV1({now},{wall});val stamp=AccountStampV1(id,1,0);val seq=r.switched(id,stamp)
        val c=CatalogViewV1(stamp,UUID.randomUUID(),wall,wall.plusSeconds(1),listOf(PlanModelViewV1("returned","Returned")),OperatorVersionV1(0,id,1,0))
        r.acceptCatalog(seq,id,stamp,c);r.chooseModel(seq,"returned");now+=Duration.ofSeconds(1).toNanos()
        assertNull(r.election(id,ChatGptLocalLimitsV1.from(LocalBudgetV1()),true));now=100L
        assertNull(r.election(id,ChatGptLocalLimitsV1.from(LocalBudgetV1()),true))
    }

    @Test fun allFourLimitSourcesConstrainActualAdmissionAndCapture() {
        val small=LocalBudgetV1(inputUnits=7,outputUnits=3,maxRequests=2,maxToolActions=4,callsPerResponse=1,
            requestBytes=100000,responseBytes=200000,eventBytes=10000,contextBytes=100000,historyReserveBytes=25000,
            continuationBytes=90000,toolResultBytes=20000,receivedBytesTotal=300000,displayedBytesTotal=300000,
            evidenceBytes=600000,privateDiskBytes=500000,maxIdenticalAction=1,traceRecords=8,wallClock=Duration.ofSeconds(10),
            overallTimeout=Duration.ofSeconds(5),connectTimeout=Duration.ofSeconds(1),requestTimeout=Duration.ofSeconds(3),
            idleTimeout=Duration.ofSeconds(2),maxRetries=0)
        for(source in 0..3){
            val f=Admission();val election=if(source==0)f.election.copy(requestedLimits=ChatGptLocalLimitsV1.from(small)) else f.election
            val run=f.admit(e=election,local=if(source==1)small else LocalBudgetV1(),hostLocal=if(source==2)small else LocalBudgetV1(),profileLocal=if(source==3)small else LocalBudgetV1())
            assertEquals(small.fields(),run.budget.fields(),"all 24 actual C1 fields source $source")
            assertEquals(ChatGptLocalLimitsV1.from(small),capturePlanAdmission(election,f.stamp,run).effectiveLimits)
            assertEquals(1,f.tools)
        }
    }

    @Test fun historyReservationUsesActualProportionalFloorNotMinimum() {
        val f=Admission();val caller=LocalBudgetV1(contextBytes=100000,historyReserveBytes=75000,continuationBytes=100000,toolResultBytes=10000)
        val elected=caller.copy(historyReserveBytes=25000)
        val e=f.election.copy(requestedLimits=ChatGptLocalLimitsV1.from(elected))
        val run=f.admit(e=e,local=caller)
        assertEquals(75000,run.budget.historyReserveBytes);assertEquals(100000,run.budget.contextBytes)
        assertEquals(75000,capturePlanAdmission(e,f.stamp,run).effectiveLimits.historyReserveBytes)
    }

    @Test fun captureCannotRelabelCatalogLimitsOrUnregisteredActualRun() {
        val f=Admission();val run=f.admit();val original=capturePlanAdmission(f.election,f.stamp,run)
        for(e in listOf(f.election.copy(catalogId=UUID.randomUUID().toString()),f.election.copy(requestedLimits=f.limits.copy(outputUnits=1)),f.election.copy(expectedGeneration=1)))
            assertFails {capturePlanAdmission(e,f.stamp,run)}
        assertEquals(original,capturePlanAdmission(f.election.copy(),f.stamp,run))
        val engine=ModelRunAdmissionV2({f.fixture.definitions},f.commitments,NanoClockV2{0},Duration.ofMinutes(20).toNanos())
        val checked=engine.checkCapabilities(PlanRunSelectionV1(f.fixture.binding.accountId,f.fixture.binding.modelSlug,PlanBudgetPolicyV1.LOCAL_ACCEPTANCE_V1),
            GenerationRequirementV2.ElectLocalAcceptance(1),ProviderCapabilitiesV2.siwc(),CallerRequirementsV2(AgentExecutionLimits(),LocalBudgetV1()),
            HostAdmissionLimitsV2(LocalBudgetV1(),GeneratedCValidationHostSafetyLimits()),ProfileAdmissionLimitsV2(LocalBudgetV1(),RepairResourceBudget()))
        val unregistered=engine.bind(checked,f.fixture.binding)
        assertFails{capturePlanAdmission(f.election,f.stamp,unregistered)}
    }

    @Test fun strongLaunchReplayNeverReturnsSecondPayload() {
        val e=Env();val a=e.begin();e.queue.run()
        assertIs<OperatorResultV1.Ok<SignInLaunchV1>>(e.reducer.takeLaunch(e.owner,a))
        repeat(3){assertIs<OperatorResultV1.Failed>(e.reducer.takeLaunch(e.owner,a),"no second authorization payload")}
        assertEquals(1,e.script.prepares)
    }

    @Test fun staleAccountWithNoActiveAttemptNeverSchedulesPreparation() {
        val q=Queue();val root=FakeRootAttemptClaimV1();val script=Script(url)
        val r=OperatorAttemptReducerV1(Clock(),{wall},root,script,q,accountVersionCurrent={_,_->false})
        val result=r.begin(OperatorOwnerIssuerV1.cli(),ChatGptAuthorizationTarget.Account(id),OperatorVersionV1(0,id,1,0),"stale-no-active-001")
        assertEquals(OperatorFailureV1.STALE_ACCOUNT,assertIs<OperatorResultV1.Failed>(result).code)
        assertFalse(root.held());assertTrue(q.tasks.isEmpty());assertEquals(0,script.prepares)
    }

    @Test fun selectionClockCallbackCannotReturnOldAccountElection() {
        lateinit var r:OperatorSelectionReducerV1
        var callback:(()->Unit)?=null
        r=OperatorSelectionReducerV1({assertFalse(Thread.holdsLock(r));val effect=callback;callback=null;effect?.invoke();100L},{assertFalse(Thread.holdsLock(r));wall})
        val stamp=AccountStampV1(id,1,0);val seq=r.switched(id,stamp)
        val c=CatalogViewV1(stamp,UUID.randomUUID(),wall,wall.plusSeconds(60),listOf(PlanModelViewV1("returned","Returned")),OperatorVersionV1(0,id,1,0))
        assertTrue(r.acceptCatalog(seq,id,stamp,c));assertTrue(r.chooseModel(seq,"returned"))
        callback={
            val nextStamp=stamp.copy(generation=1);val next=r.switched(id,nextStamp)
            val newer=CatalogViewV1(nextStamp,UUID.randomUUID(),wall,wall.plusSeconds(60),listOf(PlanModelViewV1("returned","Returned")),OperatorVersionV1(0,id,1,1))
            assertTrue(r.acceptCatalog(next,id,nextStamp,newer));assertTrue(r.chooseModel(next,"returned"))
        }
        assertNull(r.election(id,ChatGptLocalLimitsV1.from(LocalBudgetV1()),true))
    }

    @Test fun clockCallbackCannotResurrectCancelledCommitOrLaunch() {
        var effect:(()->Unit)?=null;val q=Queue();val script=Script(url);val root=FakeRootAttemptClaimV1();val owner=OperatorOwnerIssuerV1.cli()
        val r=OperatorAttemptReducerV1(OperatorMonotonicClockV1{val f=effect;effect=null;f?.invoke();100L},{wall},root,script,q)
        val a=ok(r.begin(owner,ChatGptAuthorizationTarget.New(),OperatorVersionV1(0),"clock-fence-key-001")).attemptId;q.run()
        effect={r.cancel(owner,a)}
        r.complete(a,durable(),ChatGptAuthSettlement.SETTLED,subject)
        assertEquals(SignInPhaseV1.CANCELLED,ok(r.status(owner,a)).phase);assertNull(r.pendingWelcome(account(),subject))
        assertIs<OperatorResultV1.Failed>(r.takeLaunch(owner,a))
    }
}
