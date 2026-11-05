package decompengine.chatgpt.operator

import decompengine.chatgpt.ChatGptPlanAccount
import java.time.Instant
import java.util.UUID
import kotlin.test.*

class OperatorProjectionJsonV1Test {
    @Test fun `safe projections never include launch url verifier token or throwable data`() {
        val account = ChatGptPlanAccount("00000000-0000-0000-0000-000000000001", "https://auth.openai.com", "oaiapp_fixture",
            "Fixture", "person@example.test", "returned-model", 2, 3, ChatGptPlanAccount.State.READY,
            setOf("resource.invoke", "chatgpt.tokens.use.direct"), Instant.parse("2030-01-01T00:00:00Z"))
        val view = PlanAccountViewV1(account, OperatorVersionV1(7, account.accountId, 2, 3), null)
        val status = OperatorStatusV1(listOf(view), account.accountId, 7, true, null)
        val signIn = SignInStatusV1(UUID.randomUUID(), SignInPhaseV1.WAITING_FOR_BROWSER, Instant.parse("2026-11-05T00:05:00Z"))
        val doctor = PlanDoctorViewV1("chatgpt-plan", true, null, account.accountId, account.state, true, "same-host-loopback")
        val encodings = listOf(OperatorProjectionJsonV1.status(status).toString(), OperatorProjectionJsonV1.signIn(signIn).toString(),
            OperatorProjectionJsonV1.doctor(doctor).toString(), view.toString(), status.toString(), signIn.toString())
        val forbidden = listOf("https://auth.openai.com/authorize", "state=", "code_verifier", "access_token", "refresh_token", "id_token", "Throwable")
        encodings.forEachIndexed { index, encoded -> forbidden.forEachIndexed { deniedIndex, denied ->
            assertFalse(encoded.contains(denied), "projection index=$index matched forbidden marker index=$deniedIndex")
        } }
    }

    @Test fun `view copies scopes and rejects unsafe metadata sizes`() {
        val scopes = mutableSetOf("resource.invoke")
        val account = ChatGptPlanAccount("00000000-0000-0000-0000-000000000001", "https://auth.openai.com", "oaiapp_fixture",
            "Fixture", null, null, 0, 0, ChatGptPlanAccount.State.READY, scopes, null)
        val view = PlanAccountViewV1(account, OperatorVersionV1(0, account.accountId, 0, 0), null)
        scopes += "later-mutated"
        assertEquals(setOf("resource.invoke"), view.account.scopes)
        assertFails { PlanAccountViewV1(account.copy(accountId = "foreign"), OperatorVersionV1(0), null) }
    }

    @Test fun `scripted port status and doctor are passive and foreign owners are indistinguishable`() {
        val owner = OperatorOwnerIssuerV1.cli(); val foreign = OperatorOwnerIssuerV1.webSession()
        var passiveReads = 0; var mutations = 0
        val data = object : OperatorDataScriptV1 {
            override fun passiveStatus(): OperatorResultV1<OperatorStatusV1> { passiveReads++; return OperatorResultV1.Ok(OperatorStatusV1(emptyList(), null, 0, false, OperatorFailureV1.NEEDS_SIGN_IN)) }
            override fun passiveDoctor(): OperatorResultV1<PlanDoctorViewV1> { passiveReads++; return OperatorResultV1.Ok(PlanDoctorViewV1("chatgpt-plan", false, OperatorFailureV1.NEEDS_SIGN_IN, null, null, null, "same-host-loopback")) }
            override fun select(accountId: String, expected: OperatorVersionV1): OperatorResultV1<OperatorStatusV1> { mutations++; return OperatorResultV1.Failed(OperatorFailureV1.UNAVAILABLE) }
            override fun refreshCatalog(accountId: String, expected: OperatorVersionV1): OperatorResultV1<CatalogViewV1> { mutations++; return OperatorResultV1.Failed(OperatorFailureV1.UNAVAILABLE) }
            override fun setModel(accountId: String, slug: String, catalogId: UUID, expected: OperatorVersionV1): OperatorResultV1<PlanAccountViewV1> { mutations++; return OperatorResultV1.Failed(OperatorFailureV1.UNAVAILABLE) }
            override fun refreshAccount(accountId: String, expected: OperatorVersionV1): OperatorResultV1<PlanAccountViewV1> { mutations++; return OperatorResultV1.Failed(OperatorFailureV1.UNAVAILABLE) }
            override fun signOut(accountId: String, expected: OperatorVersionV1): OperatorResultV1<SignOutViewV1> { mutations++; return OperatorResultV1.Failed(OperatorFailureV1.UNAVAILABLE) }
            override fun acknowledgeWelcome(noticeId: UUID, expected: OperatorVersionV1): OperatorResultV1<PlanAccountViewV1> { mutations++; return OperatorResultV1.Failed(OperatorFailureV1.UNAVAILABLE) }
        }
        val script = object : OperatorSignInScriptV1 {
            override fun prepare(target: decompengine.chatgpt.ChatGptAuthorizationTarget, deadlineNanos: Long) = error("not expected")
            override fun cancel(attemptId: UUID) = error("not expected")
            override fun status(attemptId: UUID) = error("not expected")
        }
        val attempts = OperatorAttemptReducerV1({ 1L }, { Instant.parse("2026-11-05T00:00:00Z") }, FakeRootAttemptClaimV1(), script, OperatorPhaseExecutorV1 { error("not expected") })
        val port = ScriptedChatGptPlanOperatorPortV1(attempts, data, setOf(owner), { true })
        assertIs<OperatorResultV1.Ok<OperatorStatusV1>>(port.status(owner))
        assertIs<OperatorResultV1.Ok<PlanDoctorViewV1>>(port.doctor(owner))
        assertEquals(2, passiveReads); assertEquals(0, mutations)
        assertEquals(OperatorFailureV1.NOT_FOUND, (port.status(foreign) as OperatorResultV1.Failed).code)
        assertEquals(2, passiveReads); assertEquals(0, mutations)
    }

    @Test fun `every closed failure has a fixed safe presentation`() {
        OperatorFailureV1.entries.forEach { code ->
            val presentation = OperatorFailurePresentationsV1.forFailure(code)
            assertTrue(presentation.httpStatus in 400..599)
            assertFalse(presentation.message.contains("secret")); assertFalse(presentation.action.contains("secret"))
            assertFalse(presentation.message.contains("http")); assertFalse(presentation.action.contains("http"))
        }
        assertEquals(404, OperatorFailurePresentationsV1.forFailure(OperatorFailureV1.NOT_FOUND).httpStatus)
        assertEquals(409, OperatorFailurePresentationsV1.forFailure(OperatorFailureV1.STALE_ACCOUNT).httpStatus)
        assertEquals(422, OperatorFailurePresentationsV1.forFailure(OperatorFailureV1.STRICT_CAP_UNSUPPORTED).httpStatus)
        assertEquals(429, OperatorFailurePresentationsV1.forFailure(OperatorFailureV1.RATE_LIMIT).httpStatus)
        assertEquals("Same response for absent or wrong owner.", OperatorFailurePresentationsV1.forFailure(OperatorFailureV1.NOT_FOUND).action)
    }
}
