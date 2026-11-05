package decompengine.chatgpt.operator

import decompengine.chatgpt.*
import decompengine.builtin.*
import decompengine.builtin.provider.ProviderCapabilitiesV2
import decompengine.agent.AgentExecutionLimits
import decompengine.project.GeneratedCValidationHostSafetyLimits
import decompengine.repair.RepairResourceBudget
import java.time.Instant
import java.util.UUID
import kotlin.test.*

class OperatorReducerV1Test {
    private class Clock(var now: Long = 1_000L) : OperatorMonotonicClockV1 { override fun nowNanos() = now }
    private class Queue : OperatorPhaseExecutorV1 {
        val tasks = ArrayDeque<() -> Unit>()
        override fun execute(task: () -> Unit) { tasks.add(task) }
        fun runNext() = tasks.removeFirst().invoke()
    }
    private class Script : OperatorSignInScriptV1 {
        var prepared = 0; var cancelled = 0; var statusReads = 0; var cancelFailure = false
        var cancelResult = ChatGptAuthCancelResult.CANCELLED
        var cancelCleanup = ChatGptAuthSettlement.SETTLED
        var status: ChatGptAuthCommit? = null
        var launchUri = "https://auth.openai.com/authorize?state=s&nonce=n&code_challenge=c&code_challenge_method=S256"
        override fun prepare(target: ChatGptAuthorizationTarget, deadlineNanos: Long): PreparedSignInV1 {
            prepared++
            return PreparedSignInV1(ChatGptPlanOAuthAttempt.AuthorizationRequest(launchUri))
        }
        override fun cancel(attemptId: UUID): OperatorCancelOutcomeV1 { cancelled++; if (cancelFailure) error("script failure"); return OperatorCancelOutcomeV1(cancelResult, cancelCleanup) }
        override fun status(attemptId: UUID): ChatGptAuthCommit? { statusReads++; return status }
    }
    private class Commit(override val state: ChatGptAuthCommitState, override val account: ChatGptPlanAccount?) : ChatGptAuthCommit()
    private val subject = "a".repeat(64)
    private fun account(id: String = "00000000-0000-0000-0000-000000000001", state: ChatGptPlanAccount.State = ChatGptPlanAccount.State.READY,
        scopes: Set<String> = setOf("resource.invoke", "chatgpt.tokens.use.direct"), epoch: Long = 7, generation: Long = 2) =
        ChatGptPlanAccount(id, "https://auth.openai.com", "oaiapp_test", "Work", "private@example.test", null,
            epoch, generation, state, scopes, Instant.parse("2030-01-01T00:00:00Z"))
    @Test fun `preparation publishes immediately original deadline and launch is one shot and redacted`() {
        val clock = Clock(); val script = Script(); val root = FakeRootAttemptClaimV1(); val queue = Queue()
        val r = OperatorAttemptReducerV1(clock, { Instant.parse("2026-11-05T00:00:00Z") }, root, script, queue)
        val owner = OperatorOwnerIssuerV1.cli()
        val result = r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000001") as OperatorResultV1.Ok
        assertEquals(SignInPhaseV1.PREPARING, result.value.phase); assertEquals(0, script.prepared); assertTrue(root.held())
        assertEquals(SignInPhaseV1.PREPARING, (r.status(owner, result.value.attemptId) as OperatorResultV1.Ok).value.phase)
        assertEquals(0, script.statusReads); assertEquals(0, script.cancelled)
        queue.runNext()
        val readyStatus = (r.status(owner, result.value.attemptId) as OperatorResultV1.Ok).value
        assertEquals(SignInPhaseV1.WAITING_FOR_BROWSER, readyStatus.phase)
        assertFalse(OperatorProjectionJsonV1.signIn(readyStatus).toString().contains("auth.openai.com"))
        val foreign = OperatorOwnerIssuerV1.webSession()
        assertEquals(OperatorFailureV1.NOT_FOUND, (r.takeLaunch(foreign, result.value.attemptId) as OperatorResultV1.Failed).code)
        val launch = (r.takeLaunch(owner, result.value.attemptId) as OperatorResultV1.Ok).value
        assertTrue(launch.authorizationUriForTrustedLauncher().contains("code_challenge"))
        assertFalse(OperatorProjectionJsonV1.signIn(launch.status).toString().contains("auth.openai.com"))
        assertFalse(launch.toString().contains("auth.openai.com")); assertFalse(launch.status.toString().contains("state=s"))
        assertEquals(OperatorFailureV1.ATTEMPT_USED, (r.takeLaunch(owner, result.value.attemptId) as OperatorResultV1.Failed).code)
        assertEquals(OperatorFailureV1.NOT_FOUND, (r.status(foreign, result.value.attemptId) as OperatorResultV1.Failed).code)
        assertEquals(1, script.prepared)
    }

    @Test fun `same request is idempotent changed intent conflicts and remote refuses before root claim`() {
        val clock = Clock(); val s = Script(); val q = Queue(); val root = FakeRootAttemptClaimV1()
        val r = OperatorAttemptReducerV1(clock, Instant::now, root, s, q, initialOperatorRevision = 4,
            accountVersionCurrent = { _, _ -> false })
        val owner = OperatorOwnerIssuerV1.cli()
        val first = (r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(4), "request-key-000001") as OperatorResultV1.Ok).value
        val replay = (r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(4), "request-key-000001") as OperatorResultV1.Ok).value
        assertEquals(first.attemptId, replay.attemptId)
        assertEquals(OperatorFailureV1.IDEMPOTENCY_CONFLICT, (r.begin(owner, ChatGptAuthorizationTarget.Enrollment("00000000-0000-0000-0000-000000000099"), OperatorVersionV1(4), "request-key-000001") as OperatorResultV1.Failed).code)
        val staleAccount = "00000000-0000-0000-0000-000000000001"
        assertEquals(OperatorFailureV1.STALE_ACCOUNT, (r.begin(owner, ChatGptAuthorizationTarget.Account(staleAccount), OperatorVersionV1(4, staleAccount, 0, 0), "request-key-000003") as OperatorResultV1.Failed).code)
        val denied = OperatorAttemptReducerV1(clock, Instant::now, root, s, q, remoteProfileAllowed = { false })
        assertEquals(OperatorFailureV1.LOCAL_CALLBACK_REQUIRED, (denied.begin(OperatorOwnerIssuerV1.cli(), ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000002") as OperatorResultV1.Failed).code)
        assertTrue(root.held()); assertEquals(0, s.prepared)
    }

    @Test fun `launch refuses encoded login hints and does not consume the one shot on rejection`() {
        val clock = Clock(); val script = Script(); val root = FakeRootAttemptClaimV1(); val queue = Queue()
        script.launchUri = "https://auth.openai.com/authorize?state=s&nonce=n&code_challenge=c&code_challenge_method=S256&id_token%5Fhint=secret"
        val r = OperatorAttemptReducerV1(clock, Instant::now, root, script, queue)
        val owner = OperatorOwnerIssuerV1.cli()
        val status = (r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000001") as OperatorResultV1.Ok).value
        queue.runNext()
        assertEquals(OperatorFailureV1.INVALID_REQUEST, (r.takeLaunch(owner, status.attemptId) as OperatorResultV1.Failed).code)
        assertEquals(OperatorFailureV1.ATTEMPT_NOT_READY, (r.takeLaunch(owner, status.attemptId) as OperatorResultV1.Failed).code)
    }

    @Test fun `owner revocation fences later reads and launch while retaining unsettled cleanup`() {
        val clock = Clock(); val script = Script(); val root = FakeRootAttemptClaimV1(); val queue = Queue()
        script.cancelCleanup = ChatGptAuthSettlement.UNSETTLED
        val r = OperatorAttemptReducerV1(clock, Instant::now, root, script, queue)
        val owner = OperatorOwnerIssuerV1.webSession()
        val status = (r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000001") as OperatorResultV1.Ok).value
        queue.runNext(); r.ownerRevoked(owner)
        assertTrue(root.held())
        assertEquals(OperatorFailureV1.NOT_FOUND, (r.status(owner, status.attemptId) as OperatorResultV1.Failed).code)
        assertEquals(OperatorFailureV1.NOT_FOUND, (r.takeLaunch(owner, status.attemptId) as OperatorResultV1.Failed).code)
        assertEquals(OperatorFailureV1.NOT_FOUND, (r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000002") as OperatorResultV1.Failed).code)
        r.cleanupSettled(status.attemptId)
        assertFalse(root.held())
    }

    @Test fun `slow preparation consumes original five minute deadline and cleanup unsettled retains root claim`() {
        val clock = Clock(); val script = Script(); val root = FakeRootAttemptClaimV1(); val queue = Queue()
        val r = OperatorAttemptReducerV1(clock, Instant::now, root, script, queue)
        val owner = OperatorOwnerIssuerV1.cli()
        val status = (r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000001") as OperatorResultV1.Ok).value
        clock.now += java.time.Duration.ofMinutes(5).toNanos()
        queue.runNext()
        assertEquals(SignInPhaseV1.EXPIRED, (r.status(owner, status.attemptId) as OperatorResultV1.Ok).value.phase)
        assertFalse(root.held())
        val owner2 = OperatorOwnerIssuerV1.cli()
        val next = (r.begin(owner2, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000002") as OperatorResultV1.Ok).value
        queue.runNext()
        script.cancelResult = ChatGptAuthCancelResult.COMMIT_IN_PROGRESS
        val pending = (r.cancel(owner2, next.attemptId) as OperatorResultV1.Ok).value
        assertEquals(SignInPhaseV1.COMMITTING, pending.phase)
        script.cancelResult = ChatGptAuthCancelResult.CANCELLED; script.cancelCleanup = ChatGptAuthSettlement.UNSETTLED
        val cleanupPending = (r.cancel(owner2, next.attemptId) as OperatorResultV1.Ok).value
        assertEquals(SignInPhaseV1.CLEANUP_PENDING, cleanupPending.phase)
        assertEquals(SignInPhaseV1.CLEANUP_PENDING, (r.status(owner2, next.attemptId) as OperatorResultV1.Ok).value.phase)
        clock.now += java.time.Duration.ofMinutes(10).toNanos(); r.sweepExpired()
        assertTrue(root.held(), "status TTL and deadline cannot release a live cleanup permit")
        assertTrue(root.held())
        // A retained cleanup blocks new owners until the actual resource owner acknowledges it.
        val blocked = OperatorAttemptReducerV1(clock, Instant::now, root, script, queue)
        val owner3 = OperatorOwnerIssuerV1.cli()
        assertEquals(OperatorFailureV1.ATTEMPT_IN_PROGRESS, (blocked.begin(owner3, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000003") as OperatorResultV1.Failed).code)
        r.cleanupSettled(next.attemptId)
        assertFalse(root.held())
    }

    @Test fun `welcome requires verified successful plan commit and remains identity scoped across signout`() {
        val clock = Clock(); val script = Script(); val root = FakeRootAttemptClaimV1(); val queue = Queue()
        val r = OperatorAttemptReducerV1(clock, Instant::now, root, script, queue)
        val owner = OperatorOwnerIssuerV1.cli()
        val failed = (r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000001") as OperatorResultV1.Ok).value
        queue.runNext(); r.complete(failed.attemptId, Commit(ChatGptAuthCommitState.DURABLE, account(scopes = setOf("resource.invoke"))), ChatGptAuthSettlement.SETTLED, subject)
        assertEquals(SignInPhaseV1.FAILED, (r.status(owner, failed.attemptId) as OperatorResultV1.Ok).value.phase)
        assertNull(r.pendingWelcome(account(scopes = setOf("resource.invoke")), subject))
        val good = (r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000002") as OperatorResultV1.Ok).value
        queue.runNext(); val a = account()
        r.complete(good.attemptId, Commit(ChatGptAuthCommitState.DURABLE, a), ChatGptAuthSettlement.SETTLED, subject)
        val notice = r.pendingWelcome(a, subject)!!
        assertEquals(a.accountId, notice.accountId); assertEquals(1, notice.version)
        val successView = (r.status(owner, good.attemptId) as OperatorResultV1.Ok).value.account!!
        assertEquals(notice.noticeId, successView.welcome?.noticeId)
        assertNotNull(r.acknowledgeWelcome(a, subject))
        assertNull((r.status(owner, good.attemptId) as OperatorResultV1.Ok).value.account?.welcome)
        assertNull(r.pendingWelcome(a.copy(state = ChatGptPlanAccount.State.SIGNED_OUT), subject))
        val good2 = (r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000003") as OperatorResultV1.Ok).value
        queue.runNext()
        val other = account("00000000-0000-0000-0000-000000000002")
        r.complete(good2.attemptId, Commit(ChatGptAuthCommitState.DURABLE, other), ChatGptAuthSettlement.SETTLED, "c".repeat(64))
        assertNotNull(r.pendingWelcome(other, "c".repeat(64)))
    }

    @Test fun `commit unknown is reconciled only by an explicit safe read and late cancelled completion is fenced`() {
        val clock = Clock(); val script = Script(); val root = FakeRootAttemptClaimV1(); val queue = Queue()
        val r = OperatorAttemptReducerV1(clock, Instant::now, root, script, queue)
        val owner = OperatorOwnerIssuerV1.cli()
        val cancelled = (r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000001") as OperatorResultV1.Ok).value
        queue.runNext()
        r.cancel(owner, cancelled.attemptId)
        r.complete(cancelled.attemptId, Commit(ChatGptAuthCommitState.DURABLE, account()), ChatGptAuthSettlement.SETTLED, subject)
        assertEquals(SignInPhaseV1.CANCELLED, (r.status(owner, cancelled.attemptId) as OperatorResultV1.Ok).value.phase)
        assertNull(r.pendingWelcome(account(), subject))

        val uncertain = (r.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "request-key-000002") as OperatorResultV1.Ok).value
        queue.runNext()
        r.complete(uncertain.attemptId, Commit(ChatGptAuthCommitState.COMMIT_UNKNOWN, null), ChatGptAuthSettlement.SETTLED, subject)
        assertEquals(0, script.statusReads, "ordinary status is passive")
        script.status = Commit(ChatGptAuthCommitState.DURABLE, account())
        val resolved = (r.reconcileCommitUnknown(owner, uncertain.attemptId, subject) as OperatorResultV1.Ok).value
        assertEquals(SignInPhaseV1.SUCCEEDED, resolved.phase)
        assertEquals(1, script.statusReads)
        assertNotNull(r.pendingWelcome(account(), subject))
    }

    @Test fun `late catalog and error sequences are discarded and election is explicit`() {
        var now = 0L; var wall = Instant.parse("2026-11-05T00:00:00Z")
        val reducer = OperatorSelectionReducerV1({ now }, { wall })
        val stamp = AccountStampV1("00000000-0000-0000-0000-000000000001", 7, 2)
        val seq1 = reducer.switched(stamp.accountId, stamp)
        val catalog = CatalogViewV1(stamp, UUID.randomUUID(), wall, wall.plusSeconds(300), listOf(PlanModelViewV1("returned", "Returned")), OperatorVersionV1(3, stamp.accountId, 7, 2))
        val seq2 = reducer.beginAction()
        assertFalse(reducer.acceptCatalog(seq1, stamp.accountId, stamp, catalog))
        assertFalse(reducer.acceptCatalog(seq2, stamp.accountId, stamp.copy(generation = 3), catalog))
        assertTrue(reducer.acceptCatalog(seq2, stamp.accountId, stamp, catalog))
        assertFalse(reducer.chooseModel(seq1, "returned")); assertTrue(reducer.chooseModel(seq2, "returned"))
        val limits = ChatGptLocalLimitsV1.from(LocalBudgetV1())
        assertNotNull(reducer.election(stamp.accountId, limits, true))
        assertNull(reducer.election(stamp.accountId, limits, false))
        now += java.time.Duration.ofMinutes(5).toNanos()
        assertFalse(reducer.chooseModel(seq2, "returned"))
    }

    @Test fun `two tab and CLI preference writes use root revision and account epoch generation CAS`() {
        var now = 100L; val wall = Instant.parse("2026-11-05T00:00:00Z")
        val id = "00000000-0000-0000-0000-000000000001"
        val stamp = AccountStampV1(id, 7, 2)
        val prefs = OperatorPreferenceReducerV1(mapOf(id to stamp), { now }, { wall })
        assertEquals(1L, (prefs.select(id, OperatorVersionV1(0, id, 7, 2)) as OperatorResultV1.Ok).value)
        assertEquals(OperatorFailureV1.STALE_ACCOUNT, (prefs.select(id, OperatorVersionV1(0, id, 7, 2)) as OperatorResultV1.Failed).code)
        assertEquals(1L, (prefs.select(id, OperatorVersionV1(1, id, 7, 2)) as OperatorResultV1.Ok).value, "no-op does not advance root revision")
        val catalog = CatalogViewV1(stamp, UUID.randomUUID(), wall, wall.plusSeconds(200), listOf(PlanModelViewV1("returned", "Returned")), OperatorVersionV1(1, id, 7, 2))
        assertTrue(prefs.installCatalog(catalog))
        assertEquals(2L, (prefs.setModel(id, "returned", catalog.catalogId, OperatorVersionV1(1, id, 7, 2)) as OperatorResultV1.Ok).value)
        assertEquals(OperatorFailureV1.STALE_ACCOUNT, (prefs.setModel(id, "returned", catalog.catalogId, OperatorVersionV1(1, id, 7, 2)) as OperatorResultV1.Failed).code)
        assertEquals(OperatorFailureV1.MODEL_UNAVAILABLE, (prefs.setModel(id, "different", catalog.catalogId, OperatorVersionV1(2, id, 7, 2)) as OperatorResultV1.Failed).code)
        prefs.updateStamp(stamp.copy(authEpoch = 8, generation = 3))
        assertEquals(OperatorFailureV1.STALE_ACCOUNT, (prefs.select(id, OperatorVersionV1(2, id, 7, 2)) as OperatorResultV1.Failed).code)
        assertNull(prefs.selectedModel(id))
        assertEquals(2L, prefs.currentRevision(), "credential identity changes do not masquerade as a preference write")
    }

    @Test fun `welcome notice acknowledgement is identity bound revision checked and survives account epoch change`() {
        val wall = Instant.parse("2026-11-05T00:00:00Z")
        val account = account(); val stamp = AccountStampV1(account.accountId, account.authEpoch, account.generation)
        val identity = verifiedWelcomeIdentityKey(account, subject)
        val prefs = OperatorPreferenceReducerV1(mapOf(stamp.accountId to stamp), { 10L }, { wall })
        val notice = WelcomeNoticeV1.mint(account.accountId)
        assertTrue(prefs.registerWelcome(notice, stamp, identity))
        assertEquals(notice.noticeId, prefs.pendingWelcome(account.accountId, identity)?.noticeId)
        assertNull(prefs.pendingWelcome(account.accountId, "c".repeat(64)))
        assertEquals(OperatorFailureV1.NOT_FOUND, (prefs.acknowledgeWelcome(notice.noticeId, "c".repeat(64), OperatorVersionV1(0, stamp.accountId, 7, 2)) as OperatorResultV1.Failed).code)
        assertEquals(1L, (prefs.acknowledgeWelcome(notice.noticeId, identity, OperatorVersionV1(0, stamp.accountId, 7, 2)) as OperatorResultV1.Ok).value)
        assertNull(prefs.pendingWelcome(account.accountId, identity))
        prefs.updateStamp(stamp.copy(authEpoch = 8, generation = 3))
        assertNull(prefs.pendingWelcome(account.accountId, identity), "acknowledgement stays stored across signout/reauthorization")
        assertEquals(1L, (prefs.acknowledgeWelcome(notice.noticeId, identity, OperatorVersionV1(1, stamp.accountId, 8, 3)) as OperatorResultV1.Ok).value)
        assertEquals(1L, prefs.currentRevision(), "idempotent acknowledgement does not invent a second write")
    }

    @Test fun `actual admission V2 validates elected account model minima and produces trusted commitments`() {
        val f = V2Fixture()
        val limits = ChatGptLocalLimitsV1.from(LocalBudgetV1())
        val election = ChatGptPlanRunElectionV1(f.binding.accountId.toString(), f.binding.modelSlug, "local-acceptance-v1", 1, true,
            f.binding.authEpoch, 0, UUID.randomUUID().toString(), limits)
        val trusted = AccountStampV1(election.accountId, election.expectedAuthEpoch, election.expectedGeneration)
        val catalog = CatalogViewV1(trusted, UUID.fromString(election.catalogId), Instant.parse("2026-11-05T00:00:00Z"),
            Instant.parse("2026-11-05T00:04:00Z"), listOf(PlanModelViewV1(election.modelSlug, election.modelSlug)), OperatorVersionV1(0, election.accountId, election.expectedAuthEpoch, election.expectedGeneration))
        val commits = RunCommitmentsV2("1".repeat(64), "2".repeat(64), "3".repeat(64), "4".repeat(64), "5".repeat(64))
        val run = admitPlanElection(election, ProviderCapabilitiesV2.siwc(), CallerRequirementsV2(AgentExecutionLimits(), limits.toLocalBudget()),
            HostAdmissionLimitsV2(LocalBudgetV1(), GeneratedCValidationHostSafetyLimits()), ProfileAdmissionLimitsV2(LocalBudgetV1(), RepairResourceBudget()),
            commits, { f.definitions }, NanoClockV2 { 0 }, java.time.Duration.ofMinutes(20).toNanos(), trustedStamp = trusted, trustedCatalog = catalog,
            now = Instant.parse("2026-11-05T00:01:00Z"), binding = f.binding)
        assertEquals(f.binding.commitment(), run.bindingCommitment)
        assertEquals(f.binding.modelSlug, run.binding.modelSlug)
        assertEquals(election.expectedGeneration, 0)
        val capture = capturePlanAdmission(election, trusted, run)
        assertEquals(run.runId.toString(), capture.invocationId)
        assertEquals(run.limitsDigest, capture.limitsDigest)
        assertEquals(commits.request, capture.requestCommitment)
        assertEquals(64, capture.electionSha256.length)
        assertFails { admitPlanElection(election.copy(acceptedLocalLimits = false), ProviderCapabilitiesV2.siwc(), CallerRequirementsV2(AgentExecutionLimits(), limits.toLocalBudget()),
            HostAdmissionLimitsV2(LocalBudgetV1(), GeneratedCValidationHostSafetyLimits()), ProfileAdmissionLimitsV2(LocalBudgetV1(), RepairResourceBudget()),
            commits, { f.definitions }, NanoClockV2 { 0 }, java.time.Duration.ofMinutes(20).toNanos(), trustedStamp = trusted, trustedCatalog = catalog,
            now = Instant.parse("2026-11-05T00:01:00Z"), binding = f.binding) }
        assertFails { admitPlanElection(election.copy(modelSlug = "ambient-default"), ProviderCapabilitiesV2.siwc(), CallerRequirementsV2(AgentExecutionLimits(), limits.toLocalBudget()),
            HostAdmissionLimitsV2(LocalBudgetV1(), GeneratedCValidationHostSafetyLimits()), ProfileAdmissionLimitsV2(LocalBudgetV1(), RepairResourceBudget()),
            commits, { f.definitions }, NanoClockV2 { 0 }, java.time.Duration.ofMinutes(20).toNanos(), trustedStamp = trusted, trustedCatalog = catalog,
            now = Instant.parse("2026-11-05T00:01:00Z"), binding = f.binding) }
        var strictCapEffects = 0
        assertFails { admitPlanElection(election, ProviderCapabilitiesV2.siwc(), CallerRequirementsV2(AgentExecutionLimits(maxOutputTokens = 8192), limits.toLocalBudget()),
            HostAdmissionLimitsV2(LocalBudgetV1(), GeneratedCValidationHostSafetyLimits()), ProfileAdmissionLimitsV2(LocalBudgetV1(), RepairResourceBudget()),
            commits, { strictCapEffects++; f.definitions }, NanoClockV2 { 0 }, java.time.Duration.ofMinutes(20).toNanos(), trustedStamp = trusted, trustedCatalog = catalog,
            now = Instant.parse("2026-11-05T00:01:00Z"), binding = f.binding) }
        assertEquals(0, strictCapEffects, "strict-cap rejection precedes tool admission effects")
        assertFails { admitPlanElection(election, ProviderCapabilitiesV2.siwc(), CallerRequirementsV2(AgentExecutionLimits(), limits.toLocalBudget()),
            HostAdmissionLimitsV2(LocalBudgetV1(), GeneratedCValidationHostSafetyLimits()), ProfileAdmissionLimitsV2(LocalBudgetV1(), RepairResourceBudget()),
            commits, { f.definitions }, NanoClockV2 { 0 }, java.time.Duration.ofMinutes(20).toNanos(), trustedStamp = trusted.copy(generation = 1), trustedCatalog = catalog,
            now = Instant.parse("2026-11-05T00:01:00Z"), binding = f.binding) }
        assertFails { admitPlanElection(election, ProviderCapabilitiesV2.siwc(), CallerRequirementsV2(AgentExecutionLimits(), limits.toLocalBudget()),
            HostAdmissionLimitsV2(LocalBudgetV1(), GeneratedCValidationHostSafetyLimits()), ProfileAdmissionLimitsV2(LocalBudgetV1(), RepairResourceBudget()),
            commits, { f.definitions }, NanoClockV2 { 0 }, java.time.Duration.ofMinutes(20).toNanos(), trustedStamp = trusted,
            trustedCatalog = CatalogViewV1(trusted, catalog.catalogId, catalog.fetchedAt, catalog.expiresAt, emptyList(), catalog.version),
            now = Instant.parse("2026-11-05T00:01:00Z"), binding = f.binding) }
    }

    @Test fun `smooth sign in welcome account catalog model and explicit election reaches actual admission`() {
        val clock = Clock(); val script = Script(); val root = FakeRootAttemptClaimV1(); val queue = Queue()
        val attempts = OperatorAttemptReducerV1(clock, Instant::now, root, script, queue)
        val owner = OperatorOwnerIssuerV1.cli()
        val started = (attempts.begin(owner, ChatGptAuthorizationTarget.New(), OperatorVersionV1(0), "smooth-flow-key-01") as OperatorResultV1.Ok).value
        queue.runNext()
        val launch = (attempts.takeLaunch(owner, started.attemptId) as OperatorResultV1.Ok).value
        assertTrue(launch.authorizationUriForTrustedLauncher().startsWith("https://auth.openai.com/"))
        val fixture = V2Fixture()
        val account = ChatGptPlanAccount(fixture.binding.accountId.toString(), "https://auth.openai.com", "oaiapp_fixture", "fixture",
            null, null, fixture.binding.authEpoch, 0, ChatGptPlanAccount.State.READY,
            setOf("resource.invoke", "chatgpt.tokens.use.direct"), Instant.parse("2030-01-01T00:00:00Z"))
        attempts.complete(started.attemptId, Commit(ChatGptAuthCommitState.DURABLE, account), ChatGptAuthSettlement.SETTLED, "b".repeat(64))
        assertEquals(SignInPhaseV1.SUCCEEDED, (attempts.status(owner, started.attemptId) as OperatorResultV1.Ok).value.phase)
        val welcome = attempts.pendingWelcome(account, "b".repeat(64))
        assertNotNull(welcome); assertNotNull(attempts.acknowledgeWelcome(account, "b".repeat(64)))
        assertNull(attempts.pendingWelcome(account, "b".repeat(64)))

        var monotonic = 10L
        val wall = Instant.parse("2026-11-05T00:00:00Z")
        val selection = OperatorSelectionReducerV1({ monotonic }, { wall })
        val stamp = AccountStampV1(account.accountId, account.authEpoch, account.generation)
        val sequence = selection.switched(account.accountId, stamp)
        assertNull(selection.election(account.accountId, ChatGptLocalLimitsV1.from(LocalBudgetV1()), accepted = true))
        val catalog = CatalogViewV1(stamp, UUID.randomUUID(), wall, wall.plusSeconds(120),
            listOf(PlanModelViewV1(fixture.binding.modelSlug, "Fixture model")), OperatorVersionV1(0, account.accountId, account.authEpoch, account.generation))
        assertTrue(selection.acceptCatalog(sequence, account.accountId, stamp, catalog))
        assertNull(selection.election(account.accountId, ChatGptLocalLimitsV1.from(LocalBudgetV1()), accepted = true))
        assertTrue(selection.chooseModel(sequence, fixture.binding.modelSlug))
        val election = selection.election(account.accountId, ChatGptLocalLimitsV1.from(LocalBudgetV1()), accepted = true)!!
        assertEquals(catalog.catalogId.toString(), election.catalogId)
        assertEquals(fixture.binding.modelSlug, election.modelSlug)
        val commitments = RunCommitmentsV2("1".repeat(64), "2".repeat(64), "3".repeat(64), "4".repeat(64), "5".repeat(64))
        val run = admitPlanElection(election, ProviderCapabilitiesV2.siwc(), CallerRequirementsV2(AgentExecutionLimits(), LocalBudgetV1()),
            HostAdmissionLimitsV2(LocalBudgetV1(), GeneratedCValidationHostSafetyLimits()), ProfileAdmissionLimitsV2(LocalBudgetV1(), RepairResourceBudget()),
            commitments, { fixture.definitions }, NanoClockV2 { 0 }, java.time.Duration.ofMinutes(20).toNanos(), trustedStamp = stamp, trustedCatalog = catalog,
            now = wall.plusSeconds(1), binding = fixture.binding)
        assertEquals(fixture.binding.commitment(), run.bindingCommitment)
        assertTrue(run.budget.inputUnits > 0)
        val capture = capturePlanAdmission(election, stamp, run)
        assertEquals(election.expectedGeneration, capture.admittedGeneration)
        assertEquals(run.budget.inputUnits, capture.effectiveLimits.inputUnits)
    }
}
