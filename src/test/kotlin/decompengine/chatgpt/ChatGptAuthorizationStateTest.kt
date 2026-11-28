package decompengine.chatgpt

import kotlinx.serialization.json.*
import java.net.URLDecoder
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

/** Explicit synthetic host proofs: these fixtures do not qualify a production OIDC adapter. */
internal object AuthorizationFixtures {
    val now: Instant = Instant.parse("2026-11-05T12:00:00Z")
    val hash = "b".repeat(64)
    fun operation() = ChatGptStoreOperation.start(Duration.ofSeconds(8))
    fun registration(client: String = "oaiapp_enrolled", subject: String = "verified-subject",
        nonce: String? = hash, issuer: String = "https://auth.openai.com", label: String = "person") =
        ChatGptPlanValidatedRegistration(issuer, client, subject, label, "person@example.test",
            ChatGptPlanTokenSet("SYNTHETIC-ACCESS-7139", "SYNTHETIC-REFRESH-4628", "SYNTHETIC-ID-8236",
                "Bearer", now, now.plusSeconds(3600), StoreFixtures.scopes, nonce))
    fun proof(snapshot: ChatGptAuthorizationSnapshot, registration: ChatGptPlanValidatedRegistration = registration(),
        attempt: UUID = snapshot.attemptId, nonce: String = hash, expires: Instant = now.plusSeconds(60),
        verified: Instant = now): ChatGptAuthorizationProof = object : ChatGptAuthorizationProof() {
        override val attemptId = attempt
        override val registration = registration
        override val authorizationNonceHash = nonce
        override val idTokenExpiresAt = expires
        override val verifiedAt = verified
    }
    class Publication(val enter: () -> Boolean = { true }) : ChatGptAuthPublication() {
        var entries = 0
        val results = mutableListOf<ChatGptAuthCommit>()
        override fun enterCommit(): Boolean { entries++; return enter() }
        override fun complete(result: ChatGptAuthCommit) { results.add(result) }
    }
    fun code(snapshot: ChatGptAuthorizationSnapshot, client: String = "oaiapp_enrolled"): ChatGptPlanOAuthAttempt.CallbackResult.Code {
        val attempt = ChatGptPlanOAuthAttempt.start(snapshot.oauthRegistration(), ChatGptPlanOAuthRedirect.of(42381),
            ChatGptPlanOAuthClock(System::nanoTime), ChatGptPlanOAuthProduction.secureRandom)
        val query = java.net.URI(attempt.authorizationRequest().uri).rawQuery.split('&').associate {
            it.substringBefore('=') to URLDecoder.decode(it.substringAfter('='), Charsets.UTF_8)
        }
        return assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(attempt.consumeCallback("GET", "127.0.0.1:42381",
            "/auth/callback?state=${query.getValue("state")}&code=SYNTHETIC-CODE-8542&client_id=$client"))
    }
}

class ChatGptAuthorizationStateTest {
    private val root = Path.of("build/orchestration/chatgpt-auth-a1/fixtures/${UUID.randomUUID()}").toAbsolutePath()
    private val data get() = root.resolve(ChatGptLinuxFiles.DATA)
    private val pool = Executors.newFixedThreadPool(3)
    private val children = mutableListOf<Process>()
    private fun store(hook: (ChatGptLinuxFiles.Stage) -> Unit = {}) =
        ChatGptPlanCredentialStore.withWallClock(root, { AuthorizationFixtures.now }, hook)
    private fun op() = AuthorizationFixtures.operation()
    private fun capture(target: ChatGptAuthorizationTarget = ChatGptAuthorizationTarget.New(), id: UUID = UUID.randomUUID()) =
        store().captureAuthorization(target, id, op())
    private fun contents() = Files.readString(data)
    private fun json() = Json.parseToJsonElement(contents()).jsonObject
    private fun enrollmentId() = store().pendingEnrollments(op()).single().enrollmentId
    private fun ready(client: String = "oaiapp_enrolled"): ChatGptAuthorizationSnapshot {
        val s = capture()
        val code = AuthorizationFixtures.code(s, client)
        store().retainIssuedClient(s, code.issuedClientId, op())
        return s
    }
    private fun commit(s: ChatGptAuthorizationSnapshot, proof: ChatGptAuthorizationProof = AuthorizationFixtures.proof(s),
        select: Boolean = false, publication: AuthorizationFixtures.Publication = AuthorizationFixtures.Publication()) =
        store().commitAuthorization(s, proof, select, publication, op())
    private fun rewrite(transform: (JsonObject) -> JsonObject) { Files.writeString(data, transform(json()).toString()) }
    private fun enrollmentChange(vararg entries: Pair<String, JsonElement>) = rewrite { d ->
        JsonObject(d + ("enrollments" to JsonArray(d.getValue("enrollments").jsonArray.map {
            JsonObject(it.jsonObject + entries.toMap())
        })))
    }
    @AfterTest fun cleanup() {
        for (child in children) {
            if (child.isAlive) child.destroyForcibly()
            assertTrue(child.waitFor(5, TimeUnit.SECONDS), "owned child did not settle")
            assertFalse(child.isAlive)
            processEvidence(buildJsonObject {
                put("event", "settled"); put("pid", child.pid()); put("exitCode", child.exitValue()); put("alive", child.isAlive)
            })
        }
        pool.shutdownNow()
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS), "owned fixture threads did not settle")
        root.toFile().deleteRecursively()
        assertFalse(Files.exists(root))
    }

    @Test fun `new capture durably reserves only host and enrollment on original inode`() {
        val s = capture()
        val view = store().pendingEnrollments(op()).single()
        val registration = assertIs<ChatGptPlanOAuthRegistration.New>(s.oauthRegistration())
        assertEquals("decomp_engine", registration.agentNameHint)
        assertEquals(registration.extAgentHostId, store().hostId())
        assertNull(s.expectedSubject); assertNull(s.expectedClientId)
        assertEquals(0L, s.expectedAuthEpoch)
        assertTrue(store().accounts().isEmpty()); assertFalse(view.hasIssuedClient)
        assertEquals(setOf("schemaVersion", "hostId", "selectedAccountId", "accounts", "enrollments"), json().keys)
        assertEquals(2, json().getValue("schemaVersion").jsonPrimitive.int)
        assertEquals(setOf("enrollmentId", "hostId", "clientId", "authEpoch", "activeAttemptId"), json().getValue("enrollments").jsonArray.single().jsonObject.keys)
        assertTrue(Files.exists(root.resolve("credentials-v1.lock")))
        assertFalse(Files.exists(root.resolve("credentials-v2.lock")))
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(data)))
        assertFailsWith<NoSuchElementException> { store().select(view.enrollmentId) }
        assertFailsWith<NoSuchElementException> { store().account(view.enrollmentId) }
        assertFailsWith<UnsupportedOperationException> { (store().pendingEnrollments(op()) as MutableList).clear() }
    }

    @Test fun `literal v1 migration preserves full account and does not change lock inode`() {
        StoreFixtures.privateDirectory(root)
        val literal = """{"schemaVersion":1,"hostId":"urn:uuid:12345678-1234-4234-8234-123456789abc","selectedAccountId":"12345678-1234-4234-8234-123456789abd","accounts":[{"accountId":"12345678-1234-4234-8234-123456789abd","issuer":"https://auth.openai.com","clientId":"oaiapp_legacy","subject":"original-sub","hostId":"urn:uuid:12345678-1234-4234-8234-123456789abc","label":"legacy","email":"legacy@example.test","selectedModel":"model-original","authEpoch":7,"generation":9,"state":"ready","tokenSet":{"accessToken":"LITERAL-ACCESS-9371","refreshToken":"LITERAL-REFRESH-5728","idToken":"LITERAL-ID-3572","tokenType":"Bearer","receivedAt":"2026-11-05T12:00:00Z","expiresAt":"2026-11-05T13:00:00Z","scopes":["openid","offline_access","resource.invoke","chatgpt.tokens.use.direct"],"authorizationNonceHash":null},"renewalIntent":null}]}"""
        Files.writeString(data, literal, java.nio.file.StandardOpenOption.CREATE_NEW)
        Files.setPosixFilePermissions(data, PosixFilePermissions.fromString("rw-------"))
        val before = store().accounts().single()
        assertEquals(literal, contents()) // reads do not migrate
        val old = json()
        // The source-pinned isolated harness supplies the separately compiled original reader.
        // Ordinary project tests still exercise migration without acquiring a compiler dependency.
        val hasOriginalReader = System.getProperty("chatgpt.a1.oldClasspath") != null
        if (hasOriginalReader) {
            val positive = child("old-positive", root, old = true)
            assertTrue(positive.waitFor(8, TimeUnit.SECONDS)); assertEquals(0, positive.exitValue())
            assertEquals(literal, contents())
        }
        val inode = Files.getAttribute(root.resolve(ChatGptLinuxFiles.LOCK), "unix:ino")
        capture()
        assertEquals(before, store().accounts().single())
        val oldAccount = old.getValue("accounts").jsonArray.single().jsonObject
        val newAccount = json().getValue("accounts").jsonArray.single().jsonObject
        assertEquals(oldAccount - "tokenSet", newAccount - "tokenSet")
        val oldTokens = oldAccount.getValue("tokenSet").jsonObject
        val newTokens = newAccount.getValue("tokenSet").jsonObject
        assertEquals(oldTokens - "scopes", newTokens - "scopes") // every literal token byte and time survives
        assertEquals(oldTokens.getValue("scopes").jsonArray.toSet(), newTokens.getValue("scopes").jsonArray.toSet())
        assertEquals(old.getValue("hostId"), json().getValue("hostId"))
        assertEquals(old.getValue("selectedAccountId"), json().getValue("selectedAccountId"))
        assertEquals(inode, Files.getAttribute(root.resolve(ChatGptLinuxFiles.LOCK), "unix:ino"))
        val unchanged = contents()
        if (hasOriginalReader) {
            val child = child("old-reader", root, old = true)
            assertTrue(child.waitFor(8, TimeUnit.SECONDS)); assertEquals(0, child.exitValue())
        }
        assertEquals(unchanged, contents())
    }

    @Test fun `accepted protocol client survives invalid grant without touching existing account`() {
        val account = store().add(AuthorizationFixtures.registration("oaiapp_existing"), true)
        val original = json().getValue("accounts")
        val s = ready()
        val id = enrollmentId()
        val before = contents()
        // A complete invalid_grant response provides no proof. No commit API is invoked.
        assertEquals("invalid_grant", Json.parseToJsonElement("""{"error":"invalid_grant"}""").jsonObject.getValue("error").jsonPrimitive.content)
        assertEquals(before, contents())
        store().abandonAuthorization(s, op())
        assertEquals(original, json().getValue("accounts"))
        assertEquals(account.accountId, json().getValue("selectedAccountId").jsonPrimitive.content)
        assertTrue(store().pendingEnrollments(op()).single().hasIssuedClient)
        val next = capture(ChatGptAuthorizationTarget.Enrollment(id))
        val returning = assertIs<ChatGptPlanOAuthRegistration.Returning>(next.oauthRegistration())
        assertEquals("oaiapp_enrolled", returning.issuedClientId)
        assertNull(returning.idTokenHint); assertNull(returning.loginHint); assertNull(next.expectedSubject)
        assertEquals(2L, next.expectedAuthEpoch)
        assertEquals("oaiapp_enrolled", AuthorizationFixtures.code(next).issuedClientId)
        val result = commit(next, select = true)
        assertEquals(ChatGptAuthCommitState.DURABLE, result.state)
        assertEquals(id, result.account!!.accountId)
        assertEquals(3L, result.account!!.authEpoch); assertEquals(0L, result.account!!.generation)
        assertTrue(store().pendingEnrollments(op()).isEmpty())
        assertEquals(2, store().accounts().size)
    }

    @Test fun `two enrollment attempts fence retain commit abandon and reject reused ids`() {
        val old = ready(); val id = enrollmentId()
        assertFailsWith<IllegalArgumentException> { capture(ChatGptAuthorizationTarget.Enrollment(id), old.attemptId) }
        val next = capture(ChatGptAuthorizationTarget.Enrollment(id))
        assertNotEquals(old.attemptId, next.attemptId)
        val before = contents()
        assertFailsWith<IllegalArgumentException> { store().retainIssuedClient(old, "oaiapp_enrolled", op()) }
        assertFailsWith<IllegalArgumentException> { commit(old) }
        store().abandonAuthorization(old, op())
        assertEquals(before, contents())
        val committed = commit(next)
        assertEquals(id, committed.account!!.accountId)
        store().abandonAuthorization(next, op()) // cannot undo promotion
        assertEquals(committed.account, store().account(id))
    }

    @Test fun `unissued abandon removes reservation and cannot resume dynamic enrollment`() {
        val s = capture(); val id = enrollmentId()
        assertFailsWith<IllegalArgumentException> { capture(ChatGptAuthorizationTarget.Enrollment(id)) }
        assertFailsWith<IllegalArgumentException> { commit(s) }
        store().abandonAuthorization(s, op())
        assertTrue(store().pendingEnrollments(op()).isEmpty())
        assertFailsWith<IllegalArgumentException> { store().retainIssuedClient(s, "oaiapp_late", op()) }
        val fresh = capture()
        assertNotEquals(id, enrollmentId()); assertNotEquals(s.attemptId, fresh.attemptId)
    }

    @Test fun `wrong proof never replaces credentials or selection`() {
        val a = store().add(AuthorizationFixtures.registration(), true)
        val snapshot = capture(ChatGptAuthorizationTarget.Account(a.accountId))
        val original = contents()
        val proofs = listOf(
            AuthorizationFixtures.proof(snapshot, AuthorizationFixtures.registration(subject = "other")),
            AuthorizationFixtures.proof(snapshot, AuthorizationFixtures.registration(client = "oaiapp_other")),
            AuthorizationFixtures.proof(snapshot, AuthorizationFixtures.registration(issuer = "https://evil.example")),
            AuthorizationFixtures.proof(snapshot, attempt = UUID.randomUUID()),
            AuthorizationFixtures.proof(snapshot, nonce = "c".repeat(64)),
            AuthorizationFixtures.proof(snapshot, AuthorizationFixtures.registration(nonce = null)),
            AuthorizationFixtures.proof(snapshot, nonce = "bad"),
        )
        for (proof in proofs) {
            val gate = AuthorizationFixtures.Publication()
            assertFailsWith<IllegalArgumentException> { commit(snapshot, proof, true, gate) }
            assertEquals(0, gate.entries); assertTrue(gate.results.isEmpty()); assertEquals(original, contents())
        }
        assertEquals(ChatGptAuthCommitState.DURABLE, commit(snapshot).state)
    }

    @Test fun `snapshot implementation and originating root cannot be forged`() {
        val s = ready()
        val forged = object : ChatGptAuthorizationSnapshot() {
            override val attemptId = s.attemptId
            override val expectedAuthEpoch = s.expectedAuthEpoch
            override val expectedSubject = s.expectedSubject
            override val expectedClientId = s.expectedClientId
            override fun oauthRegistration() = s.oauthRegistration()
        }
        val before = contents()
        assertFailsWith<IllegalArgumentException> { commit(forged) }
        val other = ChatGptPlanCredentialStore.withWallClock(root.resolve("other"), { AuthorizationFixtures.now })
        other.hostId()
        assertFailsWith<IllegalArgumentException> { other.retainIssuedClient(s, "oaiapp_enrolled", op()) }
        assertEquals(before, contents())
    }

    @Test fun `reauthorization keeps original identity but uses latest generation model and selection`() {
        val a = store().add(AuthorizationFixtures.registration(), true)
        val one = capture(ChatGptAuthorizationTarget.Account(a.accountId))
        val two = capture(ChatGptAuthorizationTarget.Account(a.accountId))
        val b = store().add(AuthorizationFixtures.registration("oaiapp_other", "other-sub"), true)
        store().setModel(a.accountId, "current-model")
        store().renew(a.accountId, 0, 0, op()) { request -> request.dispatch { client, _ -> AuthorizationFixtures.registration(client) } }
        val accepted = commit(one).account!!
        assertEquals(1L, accepted.authEpoch); assertEquals(2L, accepted.generation)
        assertEquals("current-model", accepted.selectedModel)
        assertEquals(b.accountId, json().getValue("selectedAccountId").jsonPrimitive.content)
        val before = contents()
        assertFailsWith<IllegalArgumentException> { commit(two) }
        assertEquals(before, contents())
    }

    @Test fun `explicit account capture pairs hints and signed out capture has none`() {
        val a = store().add(AuthorizationFixtures.registration(), true)
        val b = store().add(AuthorizationFixtures.registration("oaiapp_other", "other-sub"), true)
        val snapshot = capture(ChatGptAuthorizationTarget.Account(a.accountId))
        val returning = assertIs<ChatGptPlanOAuthRegistration.Returning>(snapshot.oauthRegistration())
        assertEquals(a.clientId, returning.issuedClientId)
        assertEquals("SYNTHETIC-ID-8236", returning.idTokenHint)
        assertEquals(a.email, returning.loginHint)
        assertEquals("verified-subject", snapshot.expectedSubject)
        store().logout(a.accountId)
        val signedOut = assertIs<ChatGptPlanOAuthRegistration.Returning>(capture(ChatGptAuthorizationTarget.Account(a.accountId)).oauthRegistration())
        assertNull(signedOut.idTokenHint); assertNull(signedOut.loginHint)
        assertEquals(b.accountId, json().getValue("selectedAccountId").jsonPrimitive.content)
        assertFailsWith<NoSuchElementException> { capture(ChatGptAuthorizationTarget.Account(UUID.randomUUID().toString())) }
    }

    @Test fun `logout wins first lock order and stale original epoch cannot be reauthorized`() {
        val a = store().add(AuthorizationFixtures.registration())
        val snapshot = capture(ChatGptAuthorizationTarget.Account(a.accountId))
        val acquired = CountDownLatch(1); val release = CountDownLatch(1); val started = CountDownLatch(1)
        val logout = pool.submit<ChatGptPlanAccount> { store { if (it == ChatGptLinuxFiles.Stage.LOCK_ACQUIRED) { acquired.countDown(); StoreFixtures.await(release) } }.logout(a.accountId) }
        StoreFixtures.await(acquired)
        val result = pool.submit<Boolean> { started.countDown(); assertFailsWith<IllegalArgumentException> { commit(snapshot) }; true }
        StoreFixtures.await(started); assertFalse(result.isDone)
        release.countDown(); assertEquals(ChatGptPlanAccount.State.SIGNED_OUT, logout.get(5, TimeUnit.SECONDS).state)
        assertTrue(result.get(5, TimeUnit.SECONDS)); assertFalse(contents().contains("SYNTHETIC-ACCESS-7139"))
    }

    @Test fun `reauthorization wins first lock order then logout clears new tokens`() {
        val a = store().add(AuthorizationFixtures.registration())
        val snapshot = capture(ChatGptAuthorizationTarget.Account(a.accountId))
        val acquired = CountDownLatch(1); val release = CountDownLatch(1); val started = CountDownLatch(1)
        val result = pool.submit<ChatGptAuthCommit> { store { if (it == ChatGptLinuxFiles.Stage.BEFORE_FILE_SYNC) { acquired.countDown(); StoreFixtures.await(release) } }
            .commitAuthorization(snapshot, AuthorizationFixtures.proof(snapshot), false, AuthorizationFixtures.Publication(), op()) }
        StoreFixtures.await(acquired)
        val logout = pool.submit<ChatGptPlanAccount> { started.countDown(); store().logout(a.accountId) }
        StoreFixtures.await(started); assertFalse(logout.isDone)
        release.countDown(); assertEquals(ChatGptAuthCommitState.DURABLE, result.get(5, TimeUnit.SECONDS).state)
        val out = logout.get(5, TimeUnit.SECONDS)
        assertEquals(2L, out.authEpoch); assertEquals(2L, out.generation)
        assertEquals(ChatGptPlanAccount.State.SIGNED_OUT, out.state); assertFalse(contents().contains("SYNTHETIC-ACCESS-7139"))
    }

    @Test fun `capacity counts both collections and duplicate clients never merge by email`() {
        val a = store().add(AuthorizationFixtures.registration("oaiapp_existing"))
        val s = ready()
        repeat(30) { capture() }
        assertEquals(31, store().pendingEnrollments(op()).size)
        assertEquals(1, store().accounts().size)
        val before = contents()
        assertFailsWith<IllegalArgumentException> { capture() }
        assertFailsWith<IllegalArgumentException> { store().add(AuthorizationFixtures.registration("oaiapp_extra")) }
        assertEquals(before, contents())
        assertFailsWith<IllegalArgumentException> { store().add(AuthorizationFixtures.registration("oaiapp_enrolled")) }
        val b = commit(s).account!!
        assertEquals(a.email, b.email); assertNotEquals(a.accountId, b.accountId)
        assertEquals(30, store().pendingEnrollments(op()).size)
    }

    @Test fun `client retention is idempotent immutable unique and OAuth length bounded`() {
        val first = ready(); val before = contents()
        store().retainIssuedClient(first, "oaiapp_enrolled", op()); assertEquals(before, contents())
        assertFailsWith<IllegalArgumentException> { store().retainIssuedClient(first, "oaiapp_changed", op()) }
        val other = capture()
        for (client in listOf("oaiapp_enrolled", "dynamic_agent_client", "oaiapp_" + "x".repeat(161)))
            assertFailsWith<IllegalArgumentException> { store().retainIssuedClient(other, client, op()) }
        store().retainIssuedClient(other, "oaiapp_" + "x".repeat(160), op())
        val saved = store().add(AuthorizationFixtures.registration("oaiapp_" + "z".repeat(249)))
        val unchanged = contents()
        assertFailsWith<IllegalArgumentException> { capture(ChatGptAuthorizationTarget.Account(saved.accountId)) }
        assertEquals(unchanged, contents()); assertEquals(saved, store().account(saved.accountId))
    }

    @Test fun `exhausted counters reject capture retention promotion abandonment and account commit`() {
        val s = ready()
        enrollmentChange("authEpoch" to JsonPrimitive(Long.MAX_VALUE))
        val before = contents()
        assertFailsWith<IllegalStateException> { capture(ChatGptAuthorizationTarget.Enrollment(enrollmentId())) }
        assertEquals(before, contents())
        // Restore owning epoch, then capture max-2 so promotion reaches max safely once.
        enrollmentChange("authEpoch" to JsonPrimitive(Long.MAX_VALUE - 2))
        val terminal = capture(ChatGptAuthorizationTarget.Enrollment(enrollmentId()))
        assertEquals(Long.MAX_VALUE - 1, terminal.expectedAuthEpoch)
        val a = commit(terminal).account!!
        assertEquals(Long.MAX_VALUE, a.authEpoch)
        assertFailsWith<IllegalStateException> { capture(ChatGptAuthorizationTarget.Account(a.accountId)) }
        assertFailsWith<NoSuchElementException> { commit(s) }
        rewrite { d -> JsonObject(d + ("accounts" to JsonArray(d.getValue("accounts").jsonArray.map {
            JsonObject(it.jsonObject + mapOf("authEpoch" to JsonPrimitive(0), "generation" to JsonPrimitive(Long.MAX_VALUE)))
        }))) }
        assertFailsWith<IllegalStateException> { capture(ChatGptAuthorizationTarget.Account(a.accountId)) }
    }

    @Test fun `v2 rejects malformed enrollments duplicate identities selected enrollment and unknown schema unchanged`() {
        store().add(AuthorizationFixtures.registration("oaiapp_existing"))
        ready(); val original = json(); val e = original.getValue("enrollments").jsonArray.single().jsonObject
        val a = original.getValue("accounts").jsonArray.single().jsonObject
        val badEntries = listOf(
            e + ("subject" to JsonPrimitive("fake")), e + ("tokenSet" to JsonNull), e - "clientId",
            e + ("hostId" to JsonPrimitive("urn:uuid:${UUID.randomUUID()}")),
            e + ("clientId" to JsonPrimitive("dynamic_agent_client")),
            e + ("clientId" to a.getValue("clientId")), e + ("enrollmentId" to a.getValue("accountId")),
            e + ("authEpoch" to JsonPrimitive(-1)), e + ("authEpoch" to JsonPrimitive("1")),
            e + ("authEpoch" to JsonPrimitive(1.5)), e + ("activeAttemptId" to JsonPrimitive("bad")),
            e + ("enrollmentId" to JsonPrimitive("bad")), e + ("clientId" to JsonPrimitive("oaiapp_" + "x".repeat(161)))
        )
        val bad = badEntries.map { JsonObject(original + ("enrollments" to JsonArray(listOf(JsonObject(it))))).toString() } + listOf(
            JsonObject(original + ("selectedAccountId" to e.getValue("enrollmentId"))).toString(),
            JsonObject(original + ("hostId" to JsonNull)).toString(),
            JsonObject(original + ("enrollments" to JsonArray(listOf(e, e)))).toString(),
            JsonObject(original + ("schemaVersion" to JsonPrimitive(3))).toString(),
            JsonObject(original + ("schemaVersion" to JsonPrimitive(1))).toString(),
            original.toString().replace("\"authEpoch\":0", "\"authEpoch\":0,\"authEpoch\":0"),
            original.toString().replace("\"authEpoch\":0", "\"authEpoch\":9223372036854775808"),
            JsonObject(original - "enrollments").toString()
        )
        for (text in bad) {
            Files.writeString(data, text)
            assertFailsWith<IllegalStateException> { store().pendingEnrollments(op()) }
            assertEquals(text, contents())
        }
    }

    @Test fun `publication cancellation wins before mutation and positive control reaches same gate`() {
        val s = ready(); val before = contents(); val gate = AuthorizationFixtures.Publication { false }
        assertFailsWith<CancellationException> { commit(s, select = true, publication = gate) }
        assertEquals(1, gate.entries); assertTrue(gate.results.isEmpty()); assertEquals(before, contents())
        assertFailsWith<IllegalArgumentException> { commit(s) }
        val fresh = capture(ChatGptAuthorizationTarget.Enrollment(enrollmentId()))
        val positive = AuthorizationFixtures.Publication()
        val result = commit(fresh, publication = positive)
        assertEquals(1, positive.entries); assertSame(result, positive.results.single())
        assertEquals(ChatGptAuthCommitState.DURABLE, result.state)
    }

    @Test fun `expiry uses trusted live clock inside lock with five second boundary and overflow safety`() {
        val s = ready(); val before = contents()
        for (expires in listOf(AuthorizationFixtures.now.minusSeconds(5), Instant.MIN)) {
            val gate = AuthorizationFixtures.Publication()
            assertFailsWith<IllegalArgumentException> { commit(s, AuthorizationFixtures.proof(s, expires = expires), publication = gate) }
            assertEquals(0, gate.entries); assertEquals(before, contents())
        }
        assertFailsWith<IllegalArgumentException> { commit(s, AuthorizationFixtures.proof(s, verified = AuthorizationFixtures.now.plusSeconds(6))) }
        assertEquals(ChatGptAuthCommitState.DURABLE, commit(s, AuthorizationFixtures.proof(s, expires = AuthorizationFixtures.now.minusSeconds(4))).state)
        val next = ready("oaiapp_extreme")
        val extreme = ChatGptPlanCredentialStore.withWallClock(root, { Instant.MAX })
        val proof = AuthorizationFixtures.proof(next, AuthorizationFixtures.registration("oaiapp_extreme"), expires = Instant.MAX, verified = Instant.MAX)
        assertEquals(ChatGptAuthCommitState.DURABLE, extreme.commitAuthorization(next, proof, false, AuthorizationFixtures.Publication(), op()).state)
    }

    @Test fun `account abandonment revokes completion without changing credentials or counters`() {
        val a = store().add(AuthorizationFixtures.registration())
        val s = capture(ChatGptAuthorizationTarget.Account(a.accountId)); val before = contents()
        store().abandonAuthorization(s, op()); assertEquals(before, contents())
        assertFailsWith<IllegalArgumentException> { commit(s) }
        assertFailsWith<IllegalArgumentException> { capture(ChatGptAuthorizationTarget.Account(a.accountId), s.attemptId) }
        assertEquals(before, contents())
    }

    @Test fun `authorization attempt ceiling refuses new captures without evicting old proofs or blocking admitted completion`() {
        val account = store().add(AuthorizationFixtures.registration())
        val target = ChatGptAuthorizationTarget.Account(account.accountId)
        val before = contents()
        val first = capture(target)
        store().abandonAuthorization(first, op())
        repeat(1022) { store().abandonAuthorization(capture(target), op()) }
        val last = capture(target) // The 1024th lifetime admission still succeeds.
        assertEquals(before, contents())
        val writes = AtomicInteger()
        val reopened = store { if (it == ChatGptLinuxFiles.Stage.TEMP_CREATED) writes.incrementAndGet() }
        for (next in listOf(target, ChatGptAuthorizationTarget.New(),
            ChatGptAuthorizationTarget.Enrollment(UUID.randomUUID().toString()))) {
            val error = assertFailsWith<IllegalArgumentException> {
                reopened.captureAuthorization(next, UUID.randomUUID(), op())
            }
            assertEquals("ChatGPT authorization attempt limit reached; restart the application", error.message)
        }
        assertEquals(0, writes.get())
        assertEquals(before, contents())
        assertFailsWith<IllegalArgumentException> { capture(target, first.attemptId) }
        assertFailsWith<IllegalArgumentException> { commit(first) }
        assertEquals(ChatGptAuthCommitState.DURABLE, commit(last).state)
        assertEquals(account.authEpoch + 1, store().account(account.accountId).authEpoch)
        assertFailsWith<IllegalArgumentException> { capture(target) }
    }

    @Test fun `fault cancellation and timeout at every publication stage preserve complete old or new document`() {
        val stages = listOf(ChatGptLinuxFiles.Stage.TEMP_CREATED, ChatGptLinuxFiles.Stage.WRITE_CHUNK,
            ChatGptLinuxFiles.Stage.BEFORE_FILE_SYNC, ChatGptLinuxFiles.Stage.AFTER_FILE_SYNC,
            ChatGptLinuxFiles.Stage.BEFORE_RENAME, ChatGptLinuxFiles.Stage.AFTER_RENAME,
            ChatGptLinuxFiles.Stage.BEFORE_DIRECTORY_SYNC, ChatGptLinuxFiles.Stage.AFTER_DIRECTORY_SYNC)
        for ((i, stage) in stages.withIndex()) for (mode in 0..2) {
            val client = "oaiapp_fault_${i}_$mode"
            val s = ready(client); val id = store().pendingEnrollments(op()).last().enrollmentId
            val before = contents(); val reached = AtomicBoolean(); val cancelled = AtomicBoolean(); val nanos = AuthControlledTicks()
            val operation = ChatGptStoreOperation.createControlled(Duration.ofSeconds(1), cancelled::get, nanos.authority) { nanos.get() }
            val gate = AuthorizationFixtures.Publication()
            val failing = store { if (it == stage) {
                reached.set(true)
                when (mode) { 0 -> throw IllegalStateException("SYNTHETIC-FAULT-SECRET"); 1 -> cancelled.set(true); else -> nanos.set(1_000_000_000L) }
            } }
            val result = failing.commitAuthorization(s, AuthorizationFixtures.proof(s, AuthorizationFixtures.registration(client)), true, gate, operation)
            assertTrue(reached.get()); assertEquals(ChatGptAuthCommitState.COMMIT_UNKNOWN, result.state); assertNull(result.account)
            assertSame(result, gate.results.single()); assertEquals(1, gate.entries)
            val after = contents()
            if (stage.ordinal < ChatGptLinuxFiles.Stage.AFTER_RENAME.ordinal) assertEquals(before, after)
            else { assertNotEquals(before, after); assertEquals(id, store().account(id).accountId) }
            assertEquals(2, json().getValue("schemaVersion").jsonPrimitive.int)
            assertFailsWith<IllegalArgumentException> { commit(s) }
            assertFalse(Files.list(root).use { it.anyMatch { p -> p.fileName.toString().endsWith(".tmp") } })
            if (after == before) store().abandonAuthorization(s, op())
        }
    }

    @Test fun `cancel after native publication but before final check is unknown without rollback`() {
        val s = ready(); val id = enrollmentId(); val armed = AtomicBoolean(); val calls = AtomicInteger()
        val operation = ChatGptStoreOperation.start(cancelled = { armed.get() && calls.incrementAndGet() >= 1 })
        val gate = AuthorizationFixtures.Publication()
        val result = store { if (it == ChatGptLinuxFiles.Stage.AFTER_DIRECTORY_SYNC) armed.set(true) }
            .commitAuthorization(s, AuthorizationFixtures.proof(s), true, gate, operation)
        assertEquals(ChatGptAuthCommitState.COMMIT_UNKNOWN, result.state); assertNull(result.account)
        assertEquals(id, store().account(id).accountId); assertTrue(store().pendingEnrollments(op()).isEmpty())
    }

    @Test fun `secret collision projections and callback diagnostics stay redacted`() {
        val secret = "CanaryCred4178"
        val a = store().add(ChatGptPlanValidatedRegistration("https://auth.openai.com", "oaiapp_existing", "sub", "person", null,
            ChatGptPlanTokenSet(secret, "FAKE-REFRESH-9152", "FAKE-ID-3185", "Bearer", AuthorizationFixtures.now,
                AuthorizationFixtures.now.plusSeconds(60), StoreFixtures.scopes, AuthorizationFixtures.hash)))
        val s = capture(); val before = contents()
        val forms = listOf(secret, java.util.Base64.getEncoder().encodeToString(secret.toByteArray()),
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(secret.toByteArray()), "Canary-Cred-4178")
        for (form in forms) {
            val failure = assertFailsWith<IllegalArgumentException> { store().retainIssuedClient(s, "oaiapp_$form", op()) }
            assertNull(failure.cause); assertTrue(failure.suppressed.isEmpty()); assertFalse(failure.toString().contains(secret))
            assertEquals(before, contents())
        }
        val proof = AuthorizationFixtures.proof(s); val gate = AuthorizationFixtures.Publication()
        val text = listOf(s, proof, gate, ChatGptAuthorizationTarget.Account(secret), store().pendingEnrollments(op()).single(),
            s.oauthRegistration(), a).joinToString()
        for (form in forms + listOf("SYNTHETIC-CODE-8542", "SYNTHETIC-ID-8236", AuthorizationFixtures.hash)) assertFalse(text.contains(form))
        store().retainIssuedClient(s, "oaiapp_safe", op())
        val token = "${s.attemptId}"
        val registration = ChatGptPlanValidatedRegistration("https://auth.openai.com", "oaiapp_safe", "verified", "person", null,
            ChatGptPlanTokenSet(token, "REFRESH-8901", "ID-7821", "Bearer", AuthorizationFixtures.now, AuthorizationFixtures.now.plusSeconds(60), StoreFixtures.scopes, AuthorizationFixtures.hash))
        assertFailsWith<IllegalArgumentException> { commit(s, AuthorizationFixtures.proof(s, registration)) }
    }

    @Test fun `publication cannot reenter the private store and completion runs after fsync`() {
        val s = ready(); val synced = AtomicBoolean(); var completed = false
        val gate = object : ChatGptAuthPublication() {
            override fun enterCommit(): Boolean {
                assertFailsWith<IllegalArgumentException> { store().accounts() }
                return true
            }
            override fun complete(result: ChatGptAuthCommit) {
                assertTrue(synced.get()); assertEquals(ChatGptAuthCommitState.DURABLE, result.state)
                assertFailsWith<IllegalArgumentException> { store().accounts() }; completed = true
            }
        }
        val result = store { if (it == ChatGptLinuxFiles.Stage.AFTER_DIRECTORY_SYNC) synced.set(true) }
            .commitAuthorization(s, AuthorizationFixtures.proof(s), false, gate, op())
        assertTrue(completed); assertEquals(ChatGptAuthCommitState.DURABLE, result.state)
    }

    @Test fun `child JVM crashes preserve issued mappings and never replay authorization`() {
        for (mode in listOf("before-retain", "retain-before-rename", "retain-after-rename", "after-retain",
            "before-promote", "promote-before-rename", "promote-after-rename", "after-promote")) {
            val path = root.resolve(mode)
            StoreFixtures.privateDirectory(root)
            val process = child(mode, path)
            assertTrue(process.waitFor(8, TimeUnit.SECONDS)); assertEquals(73, process.exitValue()); assertFalse(process.isAlive)
            val reopened = ChatGptPlanCredentialStore.open(path)
            val pending = reopened.pendingEnrollments(op())
            if (mode in setOf("promote-after-rename", "after-promote")) {
                assertTrue(pending.isEmpty()); assertEquals(1, reopened.accounts().size)
                assertEquals(1L, reopened.accounts().single().authEpoch)
            } else {
                assertTrue(reopened.accounts().isEmpty()); assertEquals(1, pending.size)
                val retained = mode !in setOf("before-retain", "retain-before-rename")
                assertEquals(retained, pending.single().hasIssuedClient)
                if (retained) {
                    val next = reopened.captureAuthorization(ChatGptAuthorizationTarget.Enrollment(pending.single().enrollmentId), UUID.randomUUID(), op())
                    assertEquals("oaiapp_enrolled", assertIs<ChatGptPlanOAuthRegistration.Returning>(next.oauthRegistration()).issuedClientId)
                    assertEquals(1L, next.expectedAuthEpoch)
                }
            }
            val text = Files.readString(path.resolve(ChatGptLinuxFiles.DATA))
            assertFalse(text.contains("SYNTHETIC-CODE-8542")); assertFalse(text.contains("code_verifier"))
            println("CRASH_CONTROL mode=$mode exit=${process.exitValue()} alive=${process.isAlive}")
        }
    }

    @Test fun `generation exhaustion during browser wait fails before retention or publication`() {
        val a = store().add(AuthorizationFixtures.registration())
        val s = capture(ChatGptAuthorizationTarget.Account(a.accountId))
        rewrite { d -> JsonObject(d + ("accounts" to JsonArray(d.getValue("accounts").jsonArray.map {
            JsonObject(it.jsonObject + ("generation" to JsonPrimitive(Long.MAX_VALUE)))
        }))) }
        val before = contents(); val gate = AuthorizationFixtures.Publication()
        assertFailsWith<IllegalStateException> { store().retainIssuedClient(s, a.clientId, op()) }
        assertFailsWith<IllegalStateException> { commit(s, publication = gate) }
        assertEquals(0, gate.entries); assertEquals(before, contents())
    }

    @Test fun `enrollment final epoch can be abandoned but cannot be captured for another dispatch`() {
        ready(); val id = enrollmentId()
        enrollmentChange("authEpoch" to JsonPrimitive(Long.MAX_VALUE - 2))
        val s = capture(ChatGptAuthorizationTarget.Enrollment(id))
        store().retainIssuedClient(s, "oaiapp_enrolled", op())
        store().abandonAuthorization(s, op())
        assertEquals(Long.MAX_VALUE, json().getValue("enrollments").jsonArray.single().jsonObject.getValue("authEpoch").jsonPrimitive.long)
        val before = contents()
        assertFailsWith<IllegalStateException> { capture(ChatGptAuthorizationTarget.Enrollment(id)) }
        assertEquals(before, contents())
        enrollmentChange("authEpoch" to JsonPrimitive(Long.MAX_VALUE - 1))
        val nearEnd = contents()
        assertFailsWith<IllegalStateException> { capture(ChatGptAuthorizationTarget.Enrollment(id)) }
        assertEquals(nearEnd, contents())
    }

    @Test fun `ID token expiring while waiting for lock never enters publication`() {
        val s = ready(); val proof = AuthorizationFixtures.proof(s, expires = AuthorizationFixtures.now.plusSeconds(1))
        val acquired = CountDownLatch(1); val release = CountDownLatch(1); val waiting = CountDownLatch(1)
        val now = java.util.concurrent.atomic.AtomicReference(AuthorizationFixtures.now)
        val owner = pool.submit { store { if (it == ChatGptLinuxFiles.Stage.LOCK_ACQUIRED) { acquired.countDown(); StoreFixtures.await(release) } }.accounts() }
        StoreFixtures.await(acquired)
        val gate = AuthorizationFixtures.Publication()
        val commit = pool.submit<Boolean> {
            waiting.countDown()
            assertFailsWith<IllegalArgumentException> {
                ChatGptPlanCredentialStore.withWallClock(root, now::get).commitAuthorization(s, proof, true, gate, op())
            }; true
        }
        StoreFixtures.await(waiting); assertFalse(commit.isDone)
        now.set(AuthorizationFixtures.now.plusSeconds(6)); release.countDown()
        owner.get(5, TimeUnit.SECONDS); assertTrue(commit.get(5, TimeUnit.SECONDS))
        assertEquals(0, gate.entries); assertTrue(store().accounts().isEmpty())
    }

    @Test fun `cancelled lock and read stages never enter publication or start a replacement transaction`() {
        val s = ready(); val before = contents()
        for (stage in listOf(ChatGptLinuxFiles.Stage.DIRECTORY_OPENED, ChatGptLinuxFiles.Stage.LOCK_OPENED,
            ChatGptLinuxFiles.Stage.LOCK_ACQUIRED, ChatGptLinuxFiles.Stage.DATA_OPENED,
            ChatGptLinuxFiles.Stage.READ_CHUNK, ChatGptLinuxFiles.Stage.READ_COMPLETE)) {
            val cancelled = AtomicBoolean(); val gate = AuthorizationFixtures.Publication()
            val operation = ChatGptStoreOperation.start(cancelled = cancelled::get)
            assertFailsWith<CancellationException> { store { if (it == stage) cancelled.set(true) }
                .commitAuthorization(s, AuthorizationFixtures.proof(s), true, gate, operation) }
            assertTrue(cancelled.get()); assertEquals(0, gate.entries); assertTrue(gate.results.isEmpty()); assertEquals(before, contents())
            assertFailsWith<CancellationException> { store().captureAuthorization(ChatGptAuthorizationTarget.New(), UUID.randomUUID(), operation) }
            assertEquals(before, contents())
        }
    }

    @Test fun `temporary cleanup fault is conservative and never publishes a success account`() {
        val s = ready(); val before = contents(); val cleanup = AtomicBoolean()
        val gate = AuthorizationFixtures.Publication()
        val result = store {
            if (it == ChatGptLinuxFiles.Stage.BEFORE_RENAME) throw IllegalStateException("SYNTHETIC-PRIMARY-FAULT")
            if (it == ChatGptLinuxFiles.Stage.BEFORE_TEMP_CLEANUP) { cleanup.set(true); throw IllegalStateException("SYNTHETIC-CLEANUP-FAULT") }
        }.commitAuthorization(s, AuthorizationFixtures.proof(s), false, gate, op())
        assertTrue(cleanup.get()); assertEquals(ChatGptAuthCommitState.COMMIT_UNKNOWN, result.state); assertNull(result.account)
        assertEquals(before, contents()); assertSame(result, gate.results.single())
        // Native cleanup could not complete; the private orphan is not authoritative and is removed by fixture teardown.
        assertTrue(Files.list(root).use { it.anyMatch { p -> p.fileName.toString().endsWith(".tmp") } })
        assertFailsWith<IllegalArgumentException> { commit(s) }
    }

    private fun child(mode: String, path: Path, old: Boolean = false): Process {
        StoreFixtures.privateDirectory(root)
        val tmp = root.resolve("child-tmp"); StoreFixtures.privateDirectory(tmp)
        val java = Path.of(System.getProperty("java.home"), "bin", "java").toString()
        val command = listOf(java, "-XX:-UsePerfData", "-XX:-CreateCoredumpOnCrash", "-XX:-DumpReplayDataOnError",
            "-XX:ErrorFile=$tmp/error-%p.log", "-Djava.io.tmpdir=$tmp", "-Djna.tmpdir=$tmp", "-Duser.home=$tmp",
            "-cp", if (old) System.getProperty("chatgpt.a1.oldClasspath") else StoreFixtures.childClasspath(),
            if (old) "OldReader" else "decompengine.chatgpt.ChatGptAuthorizationCrashProbe", mode, path.toString())
        return ProcessBuilder(command).redirectErrorStream(true).redirectOutput(root.resolve("child-$mode.log").toFile()).start().also {
            children.add(it)
            processEvidence(buildJsonObject {
                put("event", "started"); put("pid", it.pid()); put("argv", JsonArray(command.map(::JsonPrimitive)))
            })
        }
    }
    private fun processEvidence(record: JsonObject) {
        // Optional isolated-run evidence contains only local argv/pids/status, never protocol values.
        System.getProperty("chatgpt.a1.processEvidence")?.let {
            Files.writeString(Path.of(it), record.toString() + "\n", java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND)
        }
    }
}

object ChatGptAuthorizationCrashProbe {
    @JvmStatic fun main(args: Array<String>) {
        var phase = "capture"
        val store = ChatGptPlanCredentialStore.withWallClock(Path.of(args[1]), { AuthorizationFixtures.now }) { stage ->
            if (args[0] == "$phase-before-rename" && stage == ChatGptLinuxFiles.Stage.BEFORE_RENAME ||
                args[0] == "$phase-after-rename" && stage == ChatGptLinuxFiles.Stage.AFTER_RENAME) Runtime.getRuntime().halt(73)
        }
        val s = store.captureAuthorization(ChatGptAuthorizationTarget.New(), UUID.randomUUID(), AuthorizationFixtures.operation())
        val code = AuthorizationFixtures.code(s)
        if (args[0] == "before-retain") Runtime.getRuntime().halt(73)
        phase = "retain"
        store.retainIssuedClient(s, code.issuedClientId, AuthorizationFixtures.operation())
        if (args[0] == "after-retain" || args[0] == "before-promote") Runtime.getRuntime().halt(73)
        phase = "promote"
        check(store.commitAuthorization(s, AuthorizationFixtures.proof(s), true, AuthorizationFixtures.Publication(), AuthorizationFixtures.operation()).state == ChatGptAuthCommitState.DURABLE)
        Runtime.getRuntime().halt(73)
    }
}
