package decompengine.chatgpt

import kotlinx.serialization.json.*
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.*

internal object StoreFixtures {
    val scopes = setOf("openid", "profile", "email", "offline_access", "resource.invoke", "chatgpt.tokens.use.direct")
    fun token(access: String = "FAKE_ACCESS", refresh: String? = "FAKE_REFRESH", id: String = "FAKE_ID", grants: Set<String> = scopes) =
        ChatGptPlanTokenSet(access, refresh, id, "Bearer", Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2026-01-01T01:00:00Z"), grants)
    fun registration(client: String = "oaiapp_test", sub: String = "subject", tokens: ChatGptPlanTokenSet = token(), label: String = "label", email: String? = "same@example.test") =
        ChatGptPlanValidatedRegistration("https://auth.openai.com", client, sub, label, email, tokens)
    fun rotated(request: ChatGptRenewalRequest, access: String = "ROTATED_ACCESS", refresh: String = "ROTATED_REFRESH"): ChatGptPlanValidatedRegistration =
        request.dispatch { client, old ->
            check(old.isNotEmpty())
            request.validateIdentity { _, expected, sub, _ -> check(expected == client); registration(client, sub, token(access, refresh)) }
        }
    fun privateDirectory(path: Path) { Files.createDirectories(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))) }
    fun await(latch: CountDownLatch) { check(latch.await(5, TimeUnit.SECONDS)) { "fixture synchronization timed out" } }
    fun childClasspath(): String {
        val entries = linkedSetOf<String>()
        System.getProperty("java.class.path").split(java.io.File.pathSeparator).filterTo(entries) { it.isNotBlank() }
        var loader: ClassLoader? = ChatGptPlanStoreLockProbe::class.java.classLoader
        while (loader != null) {
            if (loader is URLClassLoader) loader.getURLs().mapNotNullTo(entries) { runCatching { Path.of(it.toURI()).toString() }.getOrNull() }
            loader = loader.parent
        }
        entries.add(Path.of(ChatGptPlanStoreLockProbe::class.java.protectionDomain.codeSource.location.toURI()).toString())
        return entries.joinToString(java.io.File.pathSeparator)
    }
}

class ChatGptPlanCredentialStoreTest {
    private val root = Path.of("build/orchestration/chatgpt-store-remediation/tests/${UUID.randomUUID()}").toAbsolutePath()
    private val data get() = root.resolve(ChatGptLinuxFiles.DATA)
    private val pool = Executors.newFixedThreadPool(4)
    @AfterTest fun cleanup() {
        pool.shutdownNow()
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS), "fixture workers not terminated")
        root.toFile().deleteRecursively()
        assertFalse(Files.exists(root), "fixture cleanup failed")
    }
    private fun store() = ChatGptPlanCredentialStore.open(root)
    private fun add() = store().add(StoreFixtures.registration())
    private fun budget() = ChatGptStoreOperation.start(Duration.ofSeconds(5))
    private fun contents() = Files.readString(data)
    private fun replace(transform: (String) -> String) { Files.writeString(data, transform(contents())) }
    private fun noTemps() = assertFalse(Files.list(root).use { it.anyMatch { p -> p.fileName.toString().endsWith(".tmp") } })

    @Test fun `first initialization restart and explicit account retain identity`() {
        val s = store(); val host = s.hostId(); val saved = s.add(StoreFixtures.registration(), select = true)
        assertEquals(host, store().hostId()); assertEquals(saved, store().account(saved.accountId))
        assertEquals(saved.accountId, store().accounts().single().accountId)
        assertTrue(Files.exists(root.resolve(ChatGptLinuxFiles.LOCK)))
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(data)))
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(root)))
    }

    @Test fun `same email clients stay distinct duplicate and unknown registration fail`() {
        val s = store(); val a = add(); val b = s.add(StoreFixtures.registration("oaiapp_second", "other"))
        assertEquals(a.email, b.email); assertNotEquals(a.accountId, b.accountId)
        assertFailsWith<IllegalArgumentException> { s.add(StoreFixtures.registration(sub = "changed")) }
        assertFailsWith<NoSuchElementException> { s.account(UUID.randomUUID().toString()) }
        assertFailsWith<NoSuchElementException> { s.logout(UUID.randomUUID().toString()) }
        val disabled = s.add(StoreFixtures.registration("oaiapp_disabled", tokens = StoreFixtures.token(grants = setOf("openid", "offline_access"))))
        assertEquals(ChatGptPlanAccount.State.PLAN_DISABLED, disabled.state); assertFalse(disabled.canUseChatGptPlan)
    }

    @Test fun `renew reauthorize and logout preserve binding with checked counters`() {
        val s = store(); val a = add()
        val rotated = s.renew(a.accountId, a.authEpoch, a.generation, budget()) { StoreFixtures.rotated(it) }
        assertEquals(1L, rotated.generation); assertEquals(0L, rotated.authEpoch)
        // An admitted old-generation waiter reuses the committed generation, without dispatch.
        assertEquals(rotated, s.renew(a.accountId, 0, 0, budget()) { error("duplicate dispatch") })
        val local = s.logoutLocally(a.accountId, budget())
        assertEquals("ROTATED_REFRESH", local.latestKnownRefreshToken); assertFalse(local.renewalOutcomeUnknown)
        val out = local.account; assertEquals(1L, out.authEpoch); assertEquals(2L, out.generation)
        assertEquals(ChatGptPlanAccount.State.SIGNED_OUT, out.state)
        assertFalse(contents().contains("ROTATED_REFRESH"))
        assertFailsWith<IllegalArgumentException> { s.reauthorize(a.accountId, 0, StoreFixtures.registration()) }
        assertFailsWith<IllegalArgumentException> { s.reauthorize(a.accountId, out.authEpoch, StoreFixtures.registration(sub = "wrong")) }
        val reauthed = s.reauthorize(a.accountId, out.authEpoch, StoreFixtures.registration())
        assertEquals(2L, reauthed.authEpoch); assertEquals(3L, reauthed.generation)
        assertEquals(a.clientId, reauthed.clientId); assertEquals(a.accountId, reauthed.accountId)
        assertFailsWith<IllegalArgumentException> { s.renew(a.accountId, a.authEpoch, a.generation, budget()) { error("stale identity dispatch") } }
    }

    @Test fun `concurrent readers and renewers cannot recover a live transaction or dispatch twice`() {
        val s = store(); val a = add(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val dispatches = AtomicInteger()
        val first = pool.submit<ChatGptPlanAccount> {
            s.renew(a.accountId, 0, 0, budget()) { request ->
                request.dispatch { client, refresh ->
                    assertEquals("FAKE_REFRESH", refresh); dispatches.incrementAndGet(); entered.countDown()
                    StoreFixtures.await(release); StoreFixtures.registration(client, tokens = StoreFixtures.token("NEW_ACCESS", "NEW_REFRESH"))
                }
            }
        }
        try {
            StoreFixtures.await(entered)
            val waiting = CountDownLatch(2)
            val second = pool.submit<ChatGptPlanAccount> { waiting.countDown(); store().renew(a.accountId, 0, 0, budget()) { error("second dispatch") } }
            val reader = pool.submit<ChatGptPlanAccount> { waiting.countDown(); store().account(a.accountId) }
            StoreFixtures.await(waiting)
            assertFailsWith<TimeoutException> { second.get(100, TimeUnit.MILLISECONDS) }
            assertFailsWith<TimeoutException> { reader.get(100, TimeUnit.MILLISECONDS) }
            assertTrue(contents().contains("\"renewalIntent\":{\"operationId\":"))
            assertFalse(contents().contains("refresh_uncertain"))
            release.countDown()
            val result = first.get(5, TimeUnit.SECONDS)
            assertEquals(result, second.get(5, TimeUnit.SECONDS)); assertEquals(result, reader.get(5, TimeUnit.SECONDS))
            assertEquals(1, dispatches.get()); assertEquals(1L, result.generation)
        } finally { release.countDown() }
    }

    @Test fun `pre dispatch failures clear intent but ambiguous failures permanently fence retry`() {
        val s = store(); val a = add()
        assertFailsWith<IllegalStateException> { s.renew(a.accountId, 0, 0, budget()) { error("synthetic before dispatch") } }
        assertEquals(ChatGptPlanAccount.State.READY, store().account(a.accountId).state)
        assertTrue(contents().contains("\"renewalIntent\":null"))
        assertFailsWith<IllegalStateException> {
            s.renew(a.accountId, 0, 0, budget()) { request -> request.dispatch { _, _ -> error("possibly consumed") } }
        }
        val uncertain = store().account(a.accountId)
        assertEquals(ChatGptPlanAccount.State.REFRESH_UNCERTAIN, uncertain.state)
        assertTrue(contents().contains("FAKE_REFRESH"))
        assertFailsWith<IllegalArgumentException> { store().renew(a.accountId, 0, 0, budget()) { error("replay") } }
        val recovered = s.reauthorize(a.accountId, uncertain.authEpoch, StoreFixtures.registration())
        assertEquals(1L, recovered.authEpoch)
    }

    @Test fun `late transport completion after timeout and subsequent owner recovery is inadmissible`() {
        val s = store(); val a = add(); val entered = CountDownLatch(1); val release = CountDownLatch(1); val finished = CountDownLatch(1)
        val captured = AtomicReference<ChatGptRenewalRequest>()
        val worker = AtomicReference<Thread>()
        val call = pool.submit<ChatGptPlanAccount> {
            s.renew(a.accountId, 0, 0, ChatGptStoreOperation.start(Duration.ofMillis(500))) { request ->
                captured.set(request); worker.set(Thread.currentThread())
                request.dispatch { client, _ ->
                    entered.countDown()
                    try {
                        // A deliberately uncooperative fixture, explicitly released and joined below.
                        while (true) { try { StoreFixtures.await(release); break } catch (_: InterruptedException) {} }
                        StoreFixtures.registration(client, tokens = StoreFixtures.token("LATE_ACCESS", "LATE_REFRESH"))
                    } finally { finished.countDown() }
                }
            }
        }
        try {
            StoreFixtures.await(entered)
            assertIs<TimeoutException>(assertFailsWith<ExecutionException> { call.get(3, TimeUnit.SECONDS) }.cause)
            assertEquals(ChatGptPlanAccount.State.REFRESH_UNCERTAIN, store().account(a.accountId).state)
            val before = contents()
            release.countDown(); StoreFixtures.await(finished)
            worker.get().join(5000); assertFalse(worker.get().isAlive, "late worker cleanup not verified")
            assertFailsWith<CancellationException> { captured.get().dispatch { _, _ -> Unit } }
            assertEquals(before, contents()); assertFalse(contents().contains("LATE_"))
            assertFailsWith<IllegalArgumentException> { s.renew(a.accountId, 0, 0, budget()) { StoreFixtures.rotated(it) } }
        } finally {
            release.countDown()
            worker.get()?.let { acquired -> acquired.join(5000); assertFalse(acquired.isAlive) }
        }
    }

    @Test fun `nested store calls fail instead of escaping renewal scope`() {
        val s = store(); val a = add()
        val entered = AtomicBoolean(); val rejected = AtomicBoolean()
        val captured = AtomicReference<ChatGptRenewalRequest>()
        val operation = budget()
        val renewed = s.renew(a.accountId, 0, 0, operation) { request ->
            entered.set(true)
            assertEquals("invalid or unsafe ChatGPT store input",
                assertFailsWith<IllegalArgumentException> { s.accounts() }.message)
            rejected.set(true); captured.set(request)
            StoreFixtures.rotated(request)
        }
        assertTrue(entered.get()); assertTrue(rejected.get())
        assertEquals(1L, renewed.generation)
        assertEquals(ChatGptPlanAccount.State.READY, s.account(a.accountId).state)
        operation.check() // Reuse is rejected while the original operation still has time.
        val dispatched = AtomicBoolean()
        assertFailsWith<CancellationException> { captured.get().dispatch { _, _ -> dispatched.set(true) } }
        assertFalse(dispatched.get())
    }

    @Test fun `Linux open flags select the supported architecture UAPI`() {
        val x86 = ChatGptLinuxFiles.openFlagsForArchitecture("x86_64")
        assertEquals(0xa0800 to 0xb0800, x86)
        assertEquals(x86, ChatGptLinuxFiles.openFlagsForArchitecture("amd64"))
        val arm = ChatGptLinuxFiles.openFlagsForArchitecture("aarch64")
        assertEquals(0x88800 to 0x8c800, arm)
        assertEquals(0, arm.second and (0x10000 or 0x20000)) // Neither ARM64 O_DIRECT nor O_LARGEFILE.
        assertFailsWith<StoreFailure> { ChatGptLinuxFiles.openFlagsForArchitecture("unknown") }
    }

    @Test fun `logout cancels an owned exchange before lock admission and stale completion cannot sign in`() {
        val s = store(); val a = add(); val entered = CountDownLatch(1); val finished = CountDownLatch(1)
        val renewal = pool.submit<ChatGptPlanAccount> {
            s.renew(a.accountId, 0, 0, budget()) { request ->
                request.dispatch { _, _ ->
                    entered.countDown()
                    try { while (true) { request.check(); Thread.sleep(5) } }
                    finally { finished.countDown() }
                    @Suppress("UNREACHABLE_CODE") StoreFixtures.registration()
                }
            }
        }
        StoreFixtures.await(entered)
        val logout = pool.submit<ChatGptLocalLogout> { store().logoutLocally(a.accountId, budget()) }
        val result = logout.get(5, TimeUnit.SECONDS)
        StoreFixtures.await(finished)
        assertIs<CancellationException>(assertFailsWith<ExecutionException> { renewal.get(5, TimeUnit.SECONDS) }.cause)
        assertEquals(ChatGptPlanAccount.State.SIGNED_OUT, result.account.state)
        assertTrue(result.renewalOutcomeUnknown); assertEquals("FAKE_REFRESH", result.latestKnownRefreshToken)
        assertFalse(contents().contains("FAKE_REFRESH")); assertEquals(result.account, store().account(a.accountId))
        assertFailsWith<IllegalArgumentException> { s.reauthorize(a.accountId, a.authEpoch, StoreFixtures.registration()) }
    }

    @Test fun `simultaneous reauthorization callbacks have exactly one epoch winner`() {
        val s = store(); val a = add(); val start = CountDownLatch(1)
        val callbacks = (1..2).map { index -> pool.submit<Boolean> {
            StoreFixtures.await(start)
            try { s.reauthorize(a.accountId, 0, StoreFixtures.registration(tokens = StoreFixtures.token("CALLBACK_$index"))); true }
            catch (_: IllegalArgumentException) { false }
        } }
        start.countDown()
        assertEquals(1, callbacks.count { it.get(5, TimeUnit.SECONDS) })
        assertEquals(1L, s.account(a.accountId).authEpoch); assertEquals(1L, s.account(a.accountId).generation)
    }

    @Test fun `logout and reauthorization races respect whichever operation owns the lock first`() {
        for (logoutFirst in listOf(true, false)) {
            val childRoot = root.resolve("race-$logoutFirst")
            val s = ChatGptPlanCredentialStore.open(childRoot)
            val a = s.add(StoreFixtures.registration())
            val entered = CountDownLatch(1); val release = CountDownLatch(1)
            val owner = ChatGptPlanCredentialStore.withHook(childRoot) {
                if (it == ChatGptLinuxFiles.Stage.READ_COMPLETE) { entered.countDown(); StoreFixtures.await(release) }
            }
            val first = pool.submit<ChatGptPlanAccount> {
                if (logoutFirst) owner.logout(a.accountId) else owner.reauthorize(a.accountId, 0, StoreFixtures.registration())
            }
            try {
                StoreFixtures.await(entered)
                val admitted = CountDownLatch(1)
                val second = pool.submit<ChatGptPlanAccount> {
                    admitted.countDown()
                    if (logoutFirst) s.reauthorize(a.accountId, 0, StoreFixtures.registration()) else s.logout(a.accountId)
                }
                StoreFixtures.await(admitted)
                assertFailsWith<TimeoutException> { second.get(100, TimeUnit.MILLISECONDS) }
                release.countDown(); first.get(5, TimeUnit.SECONDS)
                if (logoutFirst) assertIs<IllegalArgumentException>(assertFailsWith<ExecutionException> { second.get(5, TimeUnit.SECONDS) }.cause)
                else assertEquals(ChatGptPlanAccount.State.SIGNED_OUT, second.get(5, TimeUnit.SECONDS).state)
                val final = s.account(a.accountId)
                assertEquals(ChatGptPlanAccount.State.SIGNED_OUT, final.state)
                assertEquals(if (logoutFirst) 1L else 2L, final.authEpoch)
            } finally { release.countDown() }
        }
    }

    @Test fun `narrowed scope remains stored disabled and broadened or mismatched renewal is uncertain`() {
        val s = store(); val a = add()
        val disabled = s.renew(a.accountId, 0, 0, budget()) { request -> request.dispatch { client, _ ->
            StoreFixtures.registration(client, tokens = StoreFixtures.token(grants = setOf("openid", "offline_access")))
        } }
        assertEquals(ChatGptPlanAccount.State.PLAN_DISABLED, disabled.state)
        assertEquals(disabled, s.renew(a.accountId, 0, 0, budget()) { error("disabled generation redispatch") })
        val reauthed = s.reauthorize(a.accountId, 0, StoreFixtures.registration())
        assertFailsWith<IllegalArgumentException> {
            s.renew(a.accountId, reauthed.authEpoch, reauthed.generation, budget()) { request -> request.dispatch { client, _ ->
                StoreFixtures.registration(client, tokens = StoreFixtures.token(grants = StoreFixtures.scopes + "extra.authority"))
            } }
        }
        assertEquals(ChatGptPlanAccount.State.REFRESH_UNCERTAIN, s.account(a.accountId).state)
        val rebound = s.reauthorize(a.accountId, reauthed.authEpoch, StoreFixtures.registration())
        assertFailsWith<IllegalArgumentException> {
            s.renew(a.accountId, rebound.authEpoch, rebound.generation, budget()) { request -> request.dispatch { _, _ ->
                StoreFixtures.registration(sub = "wrong-subject")
            } }
        }
        assertEquals(ChatGptPlanAccount.State.REFRESH_UNCERTAIN, s.account(a.accountId).state)
    }

    @Test fun `counter exhaustion rejects renew logout and reauth without any partial document`() {
        val s = store(); val a = add()
        replace { it.replace("\"generation\":0", "\"generation\":${Long.MAX_VALUE}") }
        val before = contents()
        assertFailsWith<IllegalStateException> { s.renew(a.accountId, 0, Long.MAX_VALUE, budget()) { error("exhausted dispatch") } }
        assertEquals(before, contents())
        assertFailsWith<IllegalStateException> { s.logout(a.accountId) }; assertEquals(before, contents())
        assertFailsWith<IllegalStateException> { s.reauthorize(a.accountId, 0, StoreFixtures.registration()) }; assertEquals(before, contents())
        replace { it.replace("\"generation\":${Long.MAX_VALUE}", "\"generation\":0").replace("\"authEpoch\":0", "\"authEpoch\":${Long.MAX_VALUE}") }
        val epochMax = contents()
        assertFailsWith<IllegalStateException> { s.logout(a.accountId) }; assertEquals(epochMax, contents())
        assertFailsWith<IllegalStateException> { s.reauthorize(a.accountId, Long.MAX_VALUE, StoreFixtures.registration()) }; assertEquals(epochMax, contents())
        // Reaching MAX is valid; advancing beyond it is not.
        replace { it.replace("\"authEpoch\":${Long.MAX_VALUE}", "\"authEpoch\":${Long.MAX_VALUE - 1}") }
        assertEquals(Long.MAX_VALUE, s.logout(a.accountId).authEpoch)
    }

    @Test fun `already cancelled operations and invalid durations cause no filesystem side effects`() {
        assertFailsWith<CancellationException> { store().hostId(Duration.ofSeconds(5)) { true } }
        assertFalse(Files.exists(root))
        assertFailsWith<IllegalArgumentException> { ChatGptStoreOperation.start(Duration.ofSeconds(Long.MAX_VALUE)) }
        assertFailsWith<IllegalArgumentException> { ChatGptStoreOperation.start(Duration.ZERO) }
        assertFailsWith<IllegalArgumentException> { ChatGptStoreOperation.start(Duration.ofSeconds(31)) }
        assertFalse(Files.exists(root))
        val now = AtomicReference(Long.MAX_VALUE - 10)
        val operation = ChatGptStoreOperation.create(Duration.ofNanos(30), { false }) { now.get() }
        now.set(Long.MIN_VALUE + 4); operation.check()
        val shorter = operation.capped(Duration.ofNanos(100))
        assertEquals(operation.remainingNanos(), shorter.remainingNanos())
        now.set(Long.MIN_VALUE + 20)
        assertFailsWith<TimeoutException> { operation.check() }
        assertFailsWith<TimeoutException> { shorter.check() }
    }

    @Test fun `mutation shares original budget and cancellation between file chunks preserves old content`() {
        val a = add(); val before = contents(); val cancelled = AtomicBoolean()
        val s = ChatGptPlanCredentialStore.withHook(root) { if (it == ChatGptLinuxFiles.Stage.WRITE_CHUNK) cancelled.set(true) }
        assertFailsWith<CancellationException> { s.setModel(a.accountId, "next", ChatGptStoreOperation.start(cancelled = cancelled::get)) }
        assertEquals(before, contents()); noTemps()
        val now = AtomicReference(0L)
        val expired = ChatGptStoreOperation.create(Duration.ofNanos(10), { false }) { now.get() }
        now.set(11)
        assertFailsWith<TimeoutException> { store().logout(a.accountId, expired) }
        assertEquals(before, contents())
    }

    @Test fun `unsafe directory refuses replacement and unsupported atomic publication leaves old file`() {
        val a = add(); val before = contents()
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("r-x------"))
        try { assertFailsWith<IllegalArgumentException> { store().setModel(a.accountId, "next") } }
        finally { Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------")) }
        assertEquals(before, contents())
        val s = ChatGptPlanCredentialStore.withHook(root) { if (it == ChatGptLinuxFiles.Stage.BEFORE_RENAME)
            throw java.nio.file.AtomicMoveNotSupportedException("SECRET_PATH", "SECRET_PATH", "SECRET") }
        val error = assertFailsWith<IllegalStateException> { s.setModel(a.accountId, "next") }
        assertFalse(error.toString().contains("SECRET")); assertNull(error.cause); assertTrue(error.suppressed.isEmpty())
        assertEquals(before, contents()); noTemps()
    }

    @Test fun `atomic fault stages retain complete old or new document without false success`() {
        val a = add()
        for (stage in listOf(ChatGptLinuxFiles.Stage.TEMP_CREATED, ChatGptLinuxFiles.Stage.WRITE_CHUNK,
            ChatGptLinuxFiles.Stage.BEFORE_FILE_SYNC, ChatGptLinuxFiles.Stage.AFTER_FILE_SYNC,
            ChatGptLinuxFiles.Stage.BEFORE_RENAME, ChatGptLinuxFiles.Stage.AFTER_RENAME,
            ChatGptLinuxFiles.Stage.BEFORE_DIRECTORY_SYNC, ChatGptLinuxFiles.Stage.AFTER_DIRECTORY_SYNC)) {
            store().setModel(a.accountId, "old")
            val s = ChatGptPlanCredentialStore.withHook(root) { if (it == stage) throw java.io.IOException("SYNTHETIC_SECRET") }
            assertFailsWith<IllegalStateException>(stage.name) { s.setModel(a.accountId, "new") }
            val expected = if (stage in setOf(ChatGptLinuxFiles.Stage.AFTER_RENAME, ChatGptLinuxFiles.Stage.BEFORE_DIRECTORY_SYNC,
                ChatGptLinuxFiles.Stage.AFTER_DIRECTORY_SYNC)) "new" else "old"
            assertEquals(expected, store().account(a.accountId).selectedModel, stage.name)
            noTemps()
        }
    }

    @Test fun `commit fsync failure never writes stale token set back over rotated document`() {
        val a = add(); var writes = 0
        val s = ChatGptPlanCredentialStore.withHook(root) {
            if (it == ChatGptLinuxFiles.Stage.BEFORE_DIRECTORY_SYNC && ++writes == 2) throw java.io.IOException("fault")
        }
        assertFailsWith<IllegalStateException> { s.renew(a.accountId, 0, 0, budget()) { StoreFixtures.rotated(it) } }
        assertTrue(contents().contains("ROTATED_REFRESH")); assertFalse(contents().contains("FAKE_REFRESH"))
        assertEquals(1L, store().account(a.accountId).generation)
    }

    @Test fun `cleanup failure does not replace cancellation or expose throwable chains`() {
        val a = add(); val cancelled = AtomicBoolean()
        val s = ChatGptPlanCredentialStore.withHook(root) {
            if (it == ChatGptLinuxFiles.Stage.WRITE_CHUNK) cancelled.set(true)
            if (it == ChatGptLinuxFiles.Stage.BEFORE_TEMP_CLEANUP) throw java.io.IOException("CLEANUP_SECRET")
        }
        val failure = assertFailsWith<CancellationException> { s.setModel(a.accountId, "next", ChatGptStoreOperation.start(cancelled = cancelled::get)) }
        assertNull(failure.cause); assertTrue(failure.suppressed.isEmpty()); assertFalse(failure.toString().contains("SECRET"))
        assertNull(store().account(a.accountId).selectedModel)
    }

    @Test fun `owner policy uses numeric effective uid not configurable home and rejects foreign ancestors`() {
        val a = ChatGptLinuxFiles.Identity(1, 1, 1, 1, 0x41ed, 1000, 1, 0)
        ChatGptLinuxFiles.validateDirectory(a, 1000, false)
        ChatGptLinuxFiles.validateDirectory(a.copy(uid = 0), 1000, false)
        assertFailsWith<IllegalArgumentException> { ChatGptLinuxFiles.validateDirectory(a.copy(uid = 1001), 1000, false) }
        assertFailsWith<IllegalArgumentException> { ChatGptLinuxFiles.validateDirectory(a.copy(mode = 0x41ff), 1000, false) }
        assertFailsWith<IllegalArgumentException> { ChatGptLinuxFiles.validateDirectory(a.copy(uid = 0, mode = 0x41c0), 1000, true) }
        ChatGptLinuxFiles.validateFile(a.copy(mode = 0x8180), 1000)
        assertFailsWith<IllegalArgumentException> { ChatGptLinuxFiles.validateFile(a.copy(mode = 0x8180, uid = 1001), 1000) }
        val old = System.getProperty("user.home")
        try { System.setProperty("user.home", root.resolve("nonexistent-home").toString()); assertTrue(store().hostId().startsWith("urn:uuid:")) }
        finally { System.setProperty("user.home", old) }
    }

    @Test fun `data and lock links and hardlinks are refused`() {
        store().hostId()
        for (name in listOf(ChatGptLinuxFiles.DATA, ChatGptLinuxFiles.LOCK)) {
            val path = root.resolve(name); val saved = root.resolve("saved-$name")
            Files.move(path, saved)
            try {
                Files.createSymbolicLink(path, saved)
                assertFailsWith<IllegalStateException> { store().accounts() }; Files.delete(path)
                Files.createLink(path, saved)
                assertFailsWith<IllegalArgumentException> { store().accounts() }; Files.delete(path)
            } finally { Files.deleteIfExists(path); Files.move(saved, path) }
        }
    }

    @Test fun `ancestor symlink unsafe modes and replacement are rejected`() {
        StoreFixtures.privateDirectory(root)
        val target = root.resolve("target"); StoreFixtures.privateDirectory(target)
        val link = root.resolve("link"); Files.createSymbolicLink(link, target)
        assertFailsWith<IllegalStateException> { ChatGptPlanCredentialStore.open(link).hostId() }
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxrwx---"))
        try { assertFailsWith<IllegalArgumentException> { ChatGptPlanCredentialStore.open(target).hostId() } }
        finally { Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------")) }
        val moved = root.resolve("moved")
        val s = ChatGptPlanCredentialStore.withHook(target) {
            if (it == ChatGptLinuxFiles.Stage.DIRECTORY_OPENED) {
                Files.move(target, moved); StoreFixtures.privateDirectory(target)
            }
        }
        assertFailsWith<IllegalStateException> { s.hostId() }
        assertFalse(Files.exists(target.resolve(ChatGptLinuxFiles.DATA)))
        assertFalse(Files.exists(moved.resolve(ChatGptLinuxFiles.DATA)))
    }

    @Test fun `opened lock and data replacement cannot authenticate replacement handles`() {
        add()
        for ((stage, name) in listOf(ChatGptLinuxFiles.Stage.LOCK_OPENED to ChatGptLinuxFiles.LOCK,
            ChatGptLinuxFiles.Stage.LOCK_ACQUIRED to ChatGptLinuxFiles.LOCK,
            ChatGptLinuxFiles.Stage.DATA_OPENED to ChatGptLinuxFiles.DATA)) {
            val path = root.resolve(name); val saved = root.resolve("saved")
            val s = ChatGptPlanCredentialStore.withHook(root) {
                if (it == stage) {
                    Files.move(path, saved)
                    Files.copy(saved, path, StandardCopyOption.COPY_ATTRIBUTES)
                }
            }
            try { assertFailsWith<IllegalStateException>(stage.name) { s.accounts() } }
            finally { Files.deleteIfExists(path); Files.move(saved, path) }
        }
    }

    @Test fun `temporary inode replacement and hardlink refuse publication`() {
        val a = add(); val before = contents()
        for (hardlink in listOf(false, true)) {
            val saved = root.resolve("saved-temp")
            val s = ChatGptPlanCredentialStore.withHook(root) {
                if (it == ChatGptLinuxFiles.Stage.BEFORE_RENAME) {
                    val temp = Files.list(root).use { files -> files.filter { p -> p.fileName.toString().endsWith(".tmp") }.findFirst().orElseThrow() }
                    if (hardlink) Files.createLink(saved, temp)
                    else { Files.move(temp, saved); Files.copy(saved, temp, StandardCopyOption.COPY_ATTRIBUTES) }
                }
            }
            try {
                if (hardlink) assertFailsWith<IllegalArgumentException> { s.setModel(a.accountId, "next") }
                else assertFailsWith<IllegalStateException> { s.setModel(a.accountId, "next") }
                assertEquals(before, contents())
            }
            finally {
                Files.deleteIfExists(saved)
                Files.list(root).use { files -> files.filter { p -> p.fileName.toString().endsWith(".tmp") }.forEach { Files.delete(it) } }
            }
        }
    }

    @Test fun `reader rejects descriptor growth truncation oversized and invalid UTF8 documents`() {
        add(); val original = Files.readAllBytes(data)
        for (grow in listOf(false, true)) {
            val s = ChatGptPlanCredentialStore.withHook(root) {
                if (it == ChatGptLinuxFiles.Stage.DATA_OPENED) {
                    if (grow) Files.writeString(data, " ", StandardOpenOption.APPEND) else Files.write(data, byteArrayOf(123))
                }
            }
            assertFailsWith<IllegalStateException> { s.accounts() }; Files.write(data, original)
        }
        Files.write(data, original + ByteArray(4 * 1024 * 1024 - original.size) { 32.toByte() })
        assertEquals(1, store().accounts().size) // exact document byte ceiling succeeds
        Files.write(data, ByteArray(4 * 1024 * 1024 + 1))
        val oversized = assertFailsWith<IllegalArgumentException> { store().accounts() }
        assertEquals("ChatGPT credential document size is invalid", oversized.message)
        Files.write(data, byteArrayOf(0xc3.toByte(), 0x28))
        assertFailsWith<IllegalStateException> { store().accounts() }
    }

    @Test fun `strict schemas reject malformed types extra keys duplicate nesting and intent invariants`() {
        add(); val original = contents()
        val intent = "{\"operationId\":\"${UUID.randomUUID()}\",\"authEpoch\":0,\"generation\":0}"
        val bad = listOf<(String) -> String>(
            { it.replace("\"schemaVersion\":2", "\"schemaVersion\":\"2\"") },
            { it.replace("\"authEpoch\":0", "\"authEpoch\":\"0\"") },
            { it.replace("\"generation\":0", "\"generation\":1.0") },
            { it.replace("\"generation\":0", "\"generation\":9223372036854775808") },
            { it.replace("\"subject\":\"subject\"", "\"subject\":1") },
            { it.replace("\"accessToken\":\"FAKE_ACCESS\"", "\"accessToken\":null") },
            { it.replace("\"refreshToken\":\"FAKE_REFRESH\"", "\"refreshToken\":true") },
            { it.replace("\"openid\"", "null") },
            { it.replace("\"openid\"", "false") },
            { it.replace("\"state\":\"ready\"", "\"state\":\"READY\"") },
            { it.replace("\"renewalIntent\":null", "\"renewalIntent\":${intent.dropLast(1)},\"extra\":0}") },
            { it.replace("\"renewalIntent\":null", "\"renewalIntent\":${intent.replace("\"generation\":0", "\"generation\":1")}") },
            { it.replace("\"renewalIntent\":null", "\"renewalIntent\":$intent").replace("\"state\":\"ready\"", "\"state\":\"signed_out\"") },
            { it.replace("\"schemaVersion\":2", "\"schemaVersion\":2,\"schemaVersion\":2") },
            { it.replace("\"subject\":\"subject\"", "\"subject\":\"subject\",\"subject\":\"subject\"") },
            { it.replace("\"tokenType\":\"Bearer\"", "\"tokenType\":\"Bearer\",\"tokenType\":\"Bearer\"") },
            { it.replace("\"renewalIntent\":null", "\"renewalIntent\":${intent.dropLast(1)},\"operationId\":\"${UUID.randomUUID()}\"}") },
            { it.replace("\"tokenType\":\"Bearer\"", "\"extra\":0,\"tokenType\":\"Bearer\"") },
            { it.replace("\"label\":\"label\"", "\"label\":\"\\ud800\"") },
            { it.replace("\"accounts\":[", "\"accounts\":[" + "[".repeat(40)) },
        )
        for ((index, mutate) in bad.withIndex()) {
            val malformed = mutate(original); assertNotEquals(original, malformed, "fixture $index must mutate")
            Files.writeString(data, malformed)
            assertFailsWith<IllegalStateException>("fixture $index") { store().accounts() }
            assertEquals(malformed, contents(), "invalid document must never be recovered or rewritten")
        }
        Files.writeString(data, original)
        val objectRoot = Json.parseToJsonElement(original).jsonObject
        val account = objectRoot.getValue("accounts").jsonArray.single().jsonObject
        for (state in listOf("signed_out", "needs_sign_in")) {
            val poisoned = JsonObject(objectRoot + ("accounts" to JsonArray(listOf(JsonObject(account + mapOf(
                "state" to JsonPrimitive(state), "tokenSet" to JsonNull, "renewalIntent" to Json.parseToJsonElement(intent))))))).toString()
            Files.writeString(data, poisoned)
            assertFailsWith<IllegalStateException> { store().accounts() }; assertEquals(poisoned, contents())
        }
    }

    @Test fun `UTF8 byte limits refresh and client syntax and public secret canaries are enforced`() {
        val s = store()
        assertFailsWith<IllegalArgumentException> { s.add(StoreFixtures.registration(tokens = StoreFixtures.token(access = "é".repeat(8193)))) }
        assertFailsWith<IllegalArgumentException> { s.add(StoreFixtures.registration(tokens = StoreFixtures.token(refresh = ""))) }
        assertFailsWith<IllegalArgumentException> { s.add(StoreFixtures.registration("oaiapp_")) }
        assertFailsWith<IllegalArgumentException> { s.add(StoreFixtures.registration("oaiapp_a b")) }
        assertFailsWith<IllegalArgumentException> { s.add(StoreFixtures.registration(tokens = StoreFixtures.token(grants = setOf("bad scope")))) }
        val secrets = listOf("SYNTHETIC_ACCESS_SECRET", "SYNTHETIC_REFRESH_SECRET", "SYNTHETIC_ID_SECRET")
        val tokens = StoreFixtures.token(secrets[0], secrets[1], secrets[2], StoreFixtures.scopes + secrets[0])
        val registration = StoreFixtures.registration(tokens = tokens)
        val a = s.add(registration)
        val public = a.toString() + tokens.toString() + registration.toString() + a.scopes + a.label + a.email + a.selectedModel
        for (secret in secrets) { assertFalse(public.contains(secret)); assertTrue(contents().contains(secret)) }
        for ((index, secret) in secrets.withIndex()) {
            val forms = listOf(secret, secret.chunked(4).joinToString(" "), java.util.Base64.getEncoder().encodeToString(secret.toByteArray()))
            for (form in forms) {
                val error = assertFailsWith<IllegalArgumentException> { s.add(StoreFixtures.registration("oaiapp_bad_$index", tokens = tokens, label = form)) }
                assertFalse(error.toString().contains(secret)); assertNull(error.cause); assertTrue(error.suppressed.isEmpty())
            }
        }
        assertFailsWith<IllegalArgumentException> { s.setModel(a.accountId, secrets[0]) }
        assertFailsWith<IllegalArgumentException> { s.add(StoreFixtures.registration("oaiapp_controls", label = "line\nsecret")) }
        assertEquals(1, s.accounts().size)
        // Exact 16-KiB UTF-8 boundary is retained in private persistence, not silently truncated.
        s.add(StoreFixtures.registration("oaiapp_multibyte", tokens = StoreFixtures.token(access = "é".repeat(8192))))
    }

    @Test fun `state root precedence invalid paths and legacy non import`() {
        assertEquals(root, ChatGptPlanStateRoot.resolve(mapOf("DECOMP_CHATGPT_TOKEN_STORE" to root.toString(), "XDG_STATE_HOME" to "/unused"), "/unused"))
        assertEquals(root.resolve("decomp_engine/chatgpt-plan"), ChatGptPlanStateRoot.resolve(mapOf("XDG_STATE_HOME" to root.toString()), "/unused"))
        assertEquals(root.resolve(".local/state/decomp_engine/chatgpt-plan"), ChatGptPlanStateRoot.resolve(emptyMap(), root.toString()))
        for (path in listOf("relative", "SECRET\u0000PATH")) {
            val failure = assertFailsWith<IllegalArgumentException> { ChatGptPlanStateRoot.resolve(mapOf("DECOMP_CHATGPT_TOKEN_STORE" to path)) }
            assertFalse(failure.toString().contains("SECRET")); assertNull(failure.cause)
        }
        StoreFixtures.privateDirectory(root.resolve(".config/decomp_engine"))
        Files.writeString(root.resolve(".config/decomp_engine/chatgpt-plan-credentials.json"), "LEGACY_SECRET")
        val fresh = root.resolve("fresh")
        assertTrue(ChatGptPlanCredentialStore.open(fresh).accounts().isEmpty())
        assertFalse(Files.exists(fresh.resolve(ChatGptLinuxFiles.DATA)))
    }

    private fun child(mode: String, directory: Path = root): Process {
        val java = Path.of(System.getProperty("java.home"), "bin", "java").toString()
        StoreFixtures.privateDirectory(root.resolve("child-tmp"))
        val command = mutableListOf(java, "-XX:-UsePerfData", "-XX:ErrorFile=${root.resolve("child-tmp")}/java-error-%p.log",
            "-Duser.home=${root.resolve("child-tmp")}", "-Djava.io.tmpdir=${root.resolve("child-tmp")}", "-Djna.tmpdir=${root.resolve("child-tmp")}")
        for (property in listOf("jna.nounpack", "jna.nosys", "jna.boot.library.path", "jna.library.path"))
            System.getProperty(property)?.let { command.add("-D$property=$it") }
        command.addAll(listOf("-cp", StoreFixtures.childClasspath(), "decompengine.chatgpt.ChatGptPlanStoreLockProbe", mode, directory.toString()))
        val builder = ProcessBuilder(command).redirectErrorStream(true)
        if (mode != "hold") builder.redirectOutput(root.resolve("child-$mode.log").toFile())
        return builder.start()
    }
    private fun finish(child: Process, exit: Int = 0) {
        assertTrue(child.waitFor(10, TimeUnit.SECONDS), "subprocess did not complete")
        assertEquals(exit, child.exitValue(), "subprocess failed; inspect repository-local child log")
    }
    private fun stop(child: Process) {
        if (child.isAlive) child.destroy()
        if (!child.waitFor(1, TimeUnit.SECONDS)) child.destroyForcibly()
        assertTrue(child.waitFor(5, TimeUnit.SECONDS)); assertFalse(child.isAlive, "subprocess cleanup not verified")
    }

    @Test fun `subprocess lock has timeout cancellation and unlocked acquisition controls`() {
        val a = add(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val held = pool.submit<ChatGptPlanAccount> { store().renew(a.accountId, 0, 0, ChatGptStoreOperation.start(Duration.ofSeconds(20))) { request ->
            request.dispatch { client, _ -> entered.countDown(); check(release.await(15, TimeUnit.SECONDS)); StoreFixtures.registration(client) }
        } }
        try {
            StoreFixtures.await(entered)
            val blocked = child("timeout")
            try { finish(blocked) } finally { stop(blocked) }
            var checks = 0
            assertFailsWith<CancellationException> { store().accounts(Duration.ofSeconds(5)) { ++checks > 2 } }
        } finally { release.countDown(); held.get(5, TimeUnit.SECONDS) }
        val unlocked = child("acquire")
        try { finish(unlocked) } finally { stop(unlocked) }
    }

    @Test fun `OS lock cancellation while a separate process owns the inode is bounded`() {
        add()
        val owner = child("hold")
        try {
            val ready = pool.submit<String?> { owner.inputStream.bufferedReader().readLine() }
            assertEquals("LOCKED", ready.get(5, TimeUnit.SECONDS))
            val start = System.nanoTime()
            var checks = 0
            val openedLock = AtomicBoolean()
            val waitingStore = ChatGptPlanCredentialStore.withHook(root) { if (it == ChatGptLinuxFiles.Stage.LOCK_OPENED) openedLock.set(true) }
            assertFailsWith<CancellationException> { waitingStore.accounts(Duration.ofSeconds(3)) { openedLock.get() && ++checks > 4 } }
            assertTrue(openedLock.get(), "fixture did not reach the OS lock")
            assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(3), "OS lock cancellation did not complete")
            owner.outputStream.write(1); owner.outputStream.flush()
            finish(owner)
        } finally { stop(owner) }
        assertEquals(1, store().accounts().size)
    }

    @Test fun `subprocess crash after durable intent is recovered and cannot be replayed`() {
        val a = add()
        val crash = child("crash")
        try { finish(crash, 73) } finally { stop(crash) }
        assertTrue(contents().contains("\"renewalIntent\":{\"operationId\":"))
        assertEquals(ChatGptPlanAccount.State.REFRESH_UNCERTAIN, store().account(a.accountId).state)
        assertFailsWith<IllegalArgumentException> { store().renew(a.accountId, 0, 0, budget()) { error("crashed token replay") } }
        assertEquals(ChatGptPlanAccount.State.REFRESH_UNCERTAIN, store().account(a.accountId).state)
    }

    @Test fun `two processes initializing the same absent directory agree on stable host`() {
        StoreFixtures.privateDirectory(root)
        val target = root.resolve("shared-new-root")
        val one = child("init-one", target)
        try {
            val two = child("init-two", target)
            try {
                finish(one); finish(two)
                val host = ChatGptPlanCredentialStore.open(target).hostId()
                assertEquals(host, Files.readString(root.resolve("child-init-one.log")).trim())
                assertEquals(host, Files.readString(root.resolve("child-init-two.log")).trim())
            } finally { stop(two) }
        } finally { stop(one) }
    }

    @Test fun `concurrent first initialization has one stable host`() {
        val start = CountDownLatch(1)
        val futures = (1..4).map { pool.submit<String> { StoreFixtures.await(start); store().hostId() } }
        start.countDown()
        assertEquals(1, futures.map { it.get(5, TimeUnit.SECONDS) }.toSet().size)
    }
}

/** Actual OS-process controls; zero exit is mode-specific success, never an arbitrary startup error. */
object ChatGptPlanStoreLockProbe {
    @JvmStatic fun main(args: Array<String>) {
        val store = ChatGptPlanCredentialStore.open(Path.of(args[1]))
        when (args[0]) {
            "timeout" -> {
                try { store.accounts(Duration.ofMillis(250)); kotlin.system.exitProcess(2) }
                catch (_: TimeoutException) { kotlin.system.exitProcess(0) }
            }
            "acquire" -> { check(store.accounts(Duration.ofSeconds(2)).size == 1); kotlin.system.exitProcess(0) }
            "init-one", "init-two" -> { println(store.hostId(Duration.ofSeconds(5))); kotlin.system.exitProcess(0) }
            "hold" -> {
                val a = store.accounts().single()
                store.renew(a.accountId, a.authEpoch, a.generation, ChatGptStoreOperation.start(Duration.ofSeconds(8))) { request ->
                    request.dispatch { client, _ ->
                        println("LOCKED"); System.out.flush()
                        check(System.`in`.read() == 1)
                        StoreFixtures.registration(client)
                    }
                }
                kotlin.system.exitProcess(0)
            }
            "crash" -> {
                val a = store.accounts().single()
                store.renew(a.accountId, a.authEpoch, a.generation, ChatGptStoreOperation.start()) { request ->
                    request.dispatch { _, _ -> Runtime.getRuntime().halt(73); error("halt returned") }
                }
                kotlin.system.exitProcess(3)
            }
            else -> error("unknown probe mode")
        }
    }
}
