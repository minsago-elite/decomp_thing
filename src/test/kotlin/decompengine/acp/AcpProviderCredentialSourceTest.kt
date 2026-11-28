package decompengine.acp

import java.nio.file.Files
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull

class AcpProviderCredentialSourceTest {
    private val now = Instant.parse("2026-11-28T00:00:00Z")

    @Test
    fun `a private Codex login cache yields only the access token and account id`() {
        val token = syntheticAccessToken(now.plusSeconds(3600))
        val home = syntheticCodexHome(syntheticChatGptAuth(token))
        val credential = AcpProviderCredentialSource.LocalCodexCachedAuth(home).resolve(now)

        assertEquals(AcpProviderCredentialReference.LOCAL_CODEX_CACHED_AUTH, credential.reference)
        assertEquals(listOf("Authorization" to "Bearer $token", "ChatGPT-Account-ID" to "acct_fixture-1"), credential.authorizationHeaders())
        assertEquals(listOf(token), credential.secretValues())
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
        assertUnavailable(AcpProviderCredentialFailure.UNREADABLE, directory)
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

    private fun syntheticAccessTokenWithClaims(claims: String): String {
        val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        return "${encoder.encodeToString("{}".toByteArray())}.${encoder.encodeToString(claims.toByteArray())}.c2ln"
    }
}
