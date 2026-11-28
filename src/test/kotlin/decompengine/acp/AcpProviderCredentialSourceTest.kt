package decompengine.acp

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AcpProviderCredentialSourceTest {
    private val now = Instant.parse("2026-11-28T00:00:00Z")

    @Test
    fun `a private Codex login cache yields only the access token and account id`() {
        val token = syntheticAccessToken(now.plusSeconds(3600))
        val home = syntheticCodexHome(syntheticChatGptAuth(token))
        val credential = AcpProviderCredentialSource.LocalCodexCachedAuth(home).resolve(now)

        assertEquals(AcpProviderCredentialReference.LOCAL_CODEX_CACHED_AUTH, credential.reference)
        assertEquals(listOf("Authorization" to "Bearer $token", "ChatGPT-Account-ID" to "acct_fixture-1"), credential.authorizationHeaders())
        // The account ID is sent upstream only, so it is treated as secret for echo and launch detection.
        assertEquals(listOf(token, "acct_fixture-1"), credential.secretValues())
        assertFalse(credential.toString().contains(token))
        val noAccount = AcpProviderCredentialSource.LocalCodexCachedAuth(syntheticCodexHome(syntheticChatGptAuth(token, accountId = null)))
        assertEquals(listOf("Authorization" to "Bearer $token"), noAccount.resolve(now).authorizationHeaders())
    }

    @Test
    fun `missing unreadable and linked caches are refused without following them`() {
        val token = syntheticAccessToken(now.plusSeconds(3600))
        assertUnavailable(AcpProviderCredentialFailure.MISSING, providerFixtureDirectory("empty-home"))
        assertUnavailable(AcpProviderCredentialFailure.MISSING, providerFixtureDirectory("absent").resolve("codex"))
        assertUnavailable(AcpProviderCredentialFailure.UNREADABLE, syntheticCodexHome(syntheticChatGptAuth(token), "rw-r--r--"))
        assertUnavailable(AcpProviderCredentialFailure.UNREADABLE, syntheticCodexHome(syntheticChatGptAuth(token), "rw----r--"))
        assertUnavailable(AcpProviderCredentialFailure.UNREADABLE, syntheticCodexHome(" ".repeat(64 * 1024) + syntheticChatGptAuth(token)))

        val target = syntheticCodexHome(syntheticChatGptAuth(token))
        val linked = Files.createDirectories(providerFixtureDirectory("linked").resolve("codex"))
        Files.createSymbolicLink(linked.resolve("auth.json"), target.resolve("auth.json"))
        assertUnavailable(AcpProviderCredentialFailure.UNREADABLE, linked)
        val directory = Files.createDirectories(providerFixtureDirectory("directory").resolve("codex").resolve("auth.json")).parent
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
        assertUnavailable(AcpProviderCredentialFailure.UNREADABLE, directory)

        // A second name for the same inode, or a directory others can write, could expose or replace the file.
        val linkedTwice = syntheticCodexHome(syntheticChatGptAuth(token))
        Files.createLink(providerFixtureDirectory("second-name").resolve("auth.json"), linkedTwice.resolve("auth.json"))
        assertUnavailable(AcpProviderCredentialFailure.UNREADABLE, linkedTwice)
        val writableDirectory = syntheticCodexHome(syntheticChatGptAuth(token))
        Files.setPosixFilePermissions(writableDirectory, PosixFilePermissions.fromString("rwxrwx---"))
        assertUnavailable(AcpProviderCredentialFailure.UNREADABLE, writableDirectory)
        // A FIFO in place of the file is refused without blocking on it.
        val fifoHome = syntheticCodexHome(syntheticChatGptAuth(token))
        Files.delete(fifoHome.resolve("auth.json"))
        mkfifo(fifoHome.resolve("auth.json"))
        withinDeadline { assertUnavailable(AcpProviderCredentialFailure.UNREADABLE, fifoHome) }
    }

    @Test
    fun `a cache whose directory and file are owned by another user is refused`() {
        val token = syntheticAccessToken(now.plusSeconds(3600))
        val home = syntheticCodexHome(syntheticChatGptAuth(token))
        val owner = (Files.getAttribute(java.nio.file.Path.of("/proc/self"), "unix:uid") as Number).toInt()
        AcpProviderCredentialSource.LocalCodexCachedAuth(home, {}, { owner }).resolve(now)
        // The owner check is injectable only so this control can name another owner without privileges.
        val failure = assertFailsWith<AcpProviderCredentialUnavailable> {
            AcpProviderCredentialSource.LocalCodexCachedAuth(home, {}, { owner + 1 }).resolve(now)
        }
        assertEquals(AcpProviderCredentialFailure.UNREADABLE, failure.failure)
    }

    @Test
    fun `a name swapped after the pinned checks cannot supply other bytes or block the read`() {
        val pinnedToken = syntheticAccessToken(now.plusSeconds(3600))
        val replacementToken = syntheticAccessToken(now.plusSeconds(3600))
        // A world-readable replacement file renamed over the checked name.
        val swappedHome = syntheticCodexHome(syntheticChatGptAuth(pinnedToken))
        val replacement = Files.writeString(swappedHome.parent.resolve("replacement.json"), syntheticChatGptAuth(replacementToken))
        Files.setPosixFilePermissions(replacement, PosixFilePermissions.fromString("rw-r--r--"))
        val swapped = AcpProviderCredentialSource.LocalCodexCachedAuth(swappedHome) {
            Files.move(replacement, swappedHome.resolve("auth.json"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        }.resolve(now)
        assertEquals("Bearer $pinnedToken", swapped.authorizationHeaders().first().second)
        assertEquals(syntheticChatGptAuth(replacementToken), Files.readString(swappedHome.resolve("auth.json")), "the swap happened")

        // A FIFO swapped in after the checks: the read stays on the pinned inode and never blocks.
        val fifoHome = syntheticCodexHome(syntheticChatGptAuth(pinnedToken))
        val raced = withinDeadline {
            AcpProviderCredentialSource.LocalCodexCachedAuth(fifoHome) {
                Files.delete(fifoHome.resolve("auth.json"))
                mkfifo(fifoHome.resolve("auth.json"))
            }.resolve(now)
        }
        assertEquals("Bearer $pinnedToken", raced.authorizationHeaders().first().second)
        val swappedIn = Files.readAttributes(fifoHome.resolve("auth.json"), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        assertTrue(swappedIn.isOther, "the FIFO is in place")
    }

    @Test
    fun `malformed documents and tokens are refused`() {
        val token = syntheticAccessToken(now.plusSeconds(3600))
        listOf(
            "not json",
            """{"tokens":{"access_token":"$token"},"tokens":{"access_token":"$token"}}""",
            """{"tokens":"$token"}""",
            """{"tokens":{"access_token":7}}""",
            """{"tokens":{}}""",
            syntheticChatGptAuth("opaque-token-without-claims"),
            syntheticChatGptAuth("a.b.c"),
            syntheticChatGptAuth(token.replaceAfterLast('.', "") + "sig nature"),
            syntheticChatGptAuth(token + "\\r\\nX-Injected: 1"),
            syntheticChatGptAuth(token, accountId = "acct\\r\\nX-Injected: 1"),
            syntheticChatGptAuth(syntheticAccessTokenWithClaims("""{"exp":"4102444800"}""")),
            syntheticChatGptAuth(syntheticAccessTokenWithClaims("""{"sub":"fixture"}""")),
        ).forEachIndexed { index, document ->
            assertUnavailable(AcpProviderCredentialFailure.MALFORMED, syntheticCodexHome(document), "document $index")
        }
        val invalidUtf8 = syntheticCodexHome("")
        Files.write(invalidUtf8.resolve("auth.json"), byteArrayOf('{'.code.toByte(), 0xc3.toByte(), '}'.code.toByte()))
        assertUnavailable(AcpProviderCredentialFailure.MALFORMED, invalidUtf8)
    }

    @Test
    fun `API key logins logged out caches and expired tokens are not available`() {
        listOf(
            """{"OPENAI_API_KEY":"sk-synthetic","tokens":null}""",
            """{"OPENAI_API_KEY":"sk-synthetic"}""",
            """{"auth_mode":"apikey","tokens":{"access_token":"${syntheticAccessToken(now.plusSeconds(60))}"}}""",
        ).forEach { assertUnavailable(AcpProviderCredentialFailure.MECHANISM_UNSUPPORTED, syntheticCodexHome(it)) }
        assertUnavailable(AcpProviderCredentialFailure.EXPIRED, syntheticCodexHome(syntheticChatGptAuth(syntheticAccessToken(now))))
        assertUnavailable(AcpProviderCredentialFailure.EXPIRED, syntheticCodexHome(syntheticChatGptAuth(syntheticAccessToken(now.minusSeconds(1)))))
        val chatGptMode = """{"auth_mode":"ChatGPT","tokens":{"access_token":"${syntheticAccessToken(now.plusSeconds(1))}"}}"""
        AcpProviderCredentialSource.LocalCodexCachedAuth(syntheticCodexHome(chatGptMode)).resolve(now)
    }

    private fun assertUnavailable(expected: AcpProviderCredentialFailure, home: java.nio.file.Path, label: String = expected.name) {
        val failure = assertFailsWith<AcpProviderCredentialUnavailable>(label) {
            AcpProviderCredentialSource.LocalCodexCachedAuth(home).resolve(now)
        }
        assertEquals(expected, failure.failure, label)
        assertNull(failure.cause, label)
        assertEquals("provider credential is unavailable: ${expected.name}", failure.message, label)
        assertFalse(failure.stackTraceToString().contains(home.toString()), label)
    }

    private fun mkfifo(path: java.nio.file.Path) {
        val process = ProcessBuilder("mkfifo", "-m", "600", path.toString()).also { it.environment().clear() }.start()
        assertTrue(process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0, "mkfifo failed")
    }

    /** Runs [action] on another thread and fails, rather than hanging, if it blocks. */
    private fun <T> withinDeadline(action: () -> T): T {
        val executor = Executors.newSingleThreadExecutor { Thread(it).apply { isDaemon = true } }
        try {
            return executor.submit<T> { action() }.get(10, TimeUnit.SECONDS)
        } catch (failure: ExecutionException) {
            throw failure.cause ?: failure
        } finally {
            executor.shutdownNow()
        }
    }

    private fun syntheticAccessTokenWithClaims(claims: String): String {
        val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        return "${encoder.encodeToString("{}".toByteArray())}.${encoder.encodeToString(claims.toByteArray())}.c2ln"
    }
}
