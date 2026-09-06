package decompengine.acp

import com.agentclientprotocol.model.AuthMethod
import com.agentclientprotocol.model.AuthMethodId
import kotlin.test.*

class AcpAuthenticationInventoryTest {
    @Test fun `long private fragments are withheld at every alignment in operator previews`() {
        val secret = "0123456789abcdefghijklmnopqrstuvwxyzABCD"
        val fragments = listOf(secret.dropLast(1), secret.drop(1)) +
            (0..secret.length - 15).map { secret.substring(it, it + 15) }
        for (fragment in fragments) {
            val method = AcpAuthenticationInventory.capture(listOf(
                AuthMethod.AgentAuth(AuthMethodId("id-$fragment"), "Name $fragment", "Description $fragment")),
                listOf(secret)).methods.single()
            assertEquals("", method.namePreview)
            assertEquals("", method.descriptionPreview)
        }
        val controlSplit = secret.take(12) + '\u0001' + secret.drop(12)
        val normalized = AcpAuthenticationInventory.capture(listOf(
            AuthMethod.AgentAuth(AuthMethodId("id"), secret.dropLast(1), null)), listOf(controlSplit))
        assertEquals("", normalized.methods.single().namePreview)
    }

    @Test fun `fragment filtering retains unrelated text at the full private value budget`() {
        val values = List(4096) { it.toString().padStart(256, 'x') }
        val method = AcpAuthenticationInventory.capture(listOf(
            AuthMethod.AgentAuth(AuthMethodId("public"), "Public login", "Use your account")), values).methods.single()
        assertEquals("Public login", method.namePreview)
        assertEquals("Use your account", method.descriptionPreview)
    }

    @Test fun `control normalization precedes literal and credential preview redaction`() {
        val secret = "private-credential-fixture"
        for (control in listOf('\u0000', '\u0001', '\r', '\u007f')) {
            val splitSecret = secret.take(8) + control + secret.drop(8)
            val inventory = AcpAuthenticationInventory.capture(listOf(
                AuthMethod.AgentAuth(AuthMethodId("fixture"), splitSecret,
                    "Bearer" + control + " credential-pattern-fixture")), listOf(secret))
            assertFalse(inventory.methods.single().namePreview.contains(secret))
            assertTrue(inventory.methods.single().namePreview.contains("[redacted]"))
            assertFalse(inventory.methods.single().descriptionPreview.orEmpty().contains("credential-pattern-fixture"))
            assertTrue(inventory.methods.single().descriptionPreview.orEmpty().contains("[redacted]"))
            val normalizedPrivate = AcpAuthenticationInventory.capture(listOf(
                AuthMethod.AgentAuth(AuthMethodId("fixture"), secret, null)), listOf(splitSecret))
            assertFalse(normalizedPrivate.methods.single().namePreview.contains(secret))
            assertTrue(normalizedPrivate.methods.single().namePreview.contains("[redacted]"))
        }
    }

    @Test fun `preview truncation preserves supplementary Unicode boundaries`() {
        val key = "\ud83d\udd11"
        for (prefixLength in listOf(126, 127, 128)) {
            val idAndName = "x".repeat(prefixLength) + key + "tail"
            val description = "x".repeat(prefixLength + 128) + key + "tail"
            val method = AcpAuthenticationInventory.capture(listOf(
                AuthMethod.AgentAuth(AuthMethodId(idAndName), idAndName, description),
            ), emptyList()).methods.single()
            for (preview in listOf(method.namePreview, method.descriptionPreview!!)) {
                assertTrue(Charsets.UTF_8.newEncoder().canEncode(preview))
                assertTrue(preview.endsWith("… [preview truncated]"))
                assertEquals(prefixLength == 126, preview.contains(key))
            }
        }
    }

    @Test fun `replacement-marker matches cannot cause unbounded intermediate preview growth`() {
        val inventory = AcpAuthenticationInventory.capture(listOf(
            AuthMethod.AgentAuth(AuthMethodId("id"), "r".repeat(512), "r".repeat(2048)),
        ), listOf("r", "e", "d", "a", "c", "t", "[", "]"))
        val method = inventory.methods.single()
        assertEquals("[oversized text omitted]", method.namePreview)
        assertEquals("[oversized text omitted]", method.descriptionPreview)
    }

    @Test fun `unknown authentication variants stay unsupported`() {
        val method = AuthMethod.UnknownAuthMethod(AuthMethodId("future"), "future method", null,
            "future-type", kotlinx.serialization.json.JsonObject(emptyMap()))
        val inventory = AcpAuthenticationInventory.capture(listOf(method), emptyList())
        assertEquals("unknown", inventory.methods.single().variant)
        assertFalse(inventory.methods.single().loginSupported)
    }

    @Test fun `operator inventory preserves exact IDs but redacts display previews`() {
        val source = mutableListOf<AuthMethod>(AuthMethod.AgentAuth(AuthMethodId("method-id"),
            "login private-value", "Bearer private-value"))
        val inventory = AcpAuthenticationInventory.capture(source, listOf("private-value"))
        source.clear()
        val method = inventory.methods.single()
        assertEquals("method-id", method.id)
        assertEquals("agent", method.variant)
        assertFalse(method.loginSupported)
        assertFalse(method.namePreview.contains("private-value"))
        assertFalse(method.descriptionPreview!!.contains("private-value"))
        assertFalse(method.toString().contains("method-id"))
        assertFalse(inventory.toString().contains("private-value"))
        assertFailsWith<UnsupportedOperationException> { (inventory.methods as MutableList).clear() }
    }

    @Test fun `empty and changed inventories have deterministic commitments`() {
        val empty = AcpAuthenticationInventory.capture(emptyList(), emptyList())
        assertTrue(empty.methods.isEmpty())
        assertEquals(empty.sha256, AcpAuthenticationInventory.capture(emptyList(), emptyList()).sha256)
        val method = AuthMethod.AgentAuth(AuthMethodId("id"), "name", null)
        assertNotEquals(empty.sha256, AcpAuthenticationInventory.capture(listOf(method), emptyList()).sha256)
    }

    @Test fun `commitments derive from redacted advertisement text instead of raw credentials`() {
        val first = AcpAuthenticationInventory.capture(
            listOf(AuthMethod.AgentAuth(AuthMethodId("method-id"), "password-one", "note password-one")),
            listOf("password-one")).sha256
        val second = AcpAuthenticationInventory.capture(
            listOf(AuthMethod.AgentAuth(AuthMethodId("method-id"), "password-two", "note password-two")),
            listOf("password-two")).sha256
        assertEquals(first, second)
        assertFalse(AcpAuthenticationInventory.capture(
            listOf(AuthMethod.AgentAuth(AuthMethodId("method-id"), "password-three", null)),
            emptyList()).sha256.let { it == first })
    }

    @Test fun `invisible format characters cannot hide configured credentials from previews`() {
        val secret = "credential-fixture"
        val obfuscated = secret.chunked(7).joinToString("\u200b")
        assertTrue(!obfuscated.contains(secret))
        val splitValue = AcpAuthenticationInventory.capture(listOf(
            AuthMethod.AgentAuth(AuthMethodId("fixture"), obfuscated, "Prefix $obfuscated")), listOf(secret))
        assertEquals("", splitValue.methods.single().namePreview)
        assertEquals("", splitValue.methods.single().descriptionPreview)
        val splitPrivate = AcpAuthenticationInventory.capture(listOf(
            AuthMethod.AgentAuth(AuthMethodId("fixture"), secret, null)), listOf(obfuscated))
        assertEquals("", splitPrivate.methods.single().namePreview)
    }

    @Test fun `ambiguous and excessive advertisements fail with fixed diagnostics`() {
        val method = AuthMethod.AgentAuth(AuthMethodId("secret-id"), "name", null)
        for (methods in listOf(listOf(method, method), List(33) { method },
            listOf(AuthMethod.AgentAuth(AuthMethodId("x".repeat(257)), "name", null)),
            listOf(AuthMethod.AgentAuth(AuthMethodId("id"), "x".repeat(513), null)))) {
            val error = assertFailsWith<AcpProtocolFailure> { AcpAuthenticationInventory.capture(methods, emptyList()) }
            assertFalse(error.message!!.contains("secret-id"))
        }
    }
}
