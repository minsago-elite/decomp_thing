package decompengine.acp

import com.agentclientprotocol.model.AuthMethod
import com.agentclientprotocol.model.AuthMethodId
import kotlin.test.*
import kotlinx.serialization.json.*

class AcpAuthenticationInventoryTest {
    @Test fun `numeric payload policy applies at the exact limit to metadata and unknown variants`() {
        // Preserve the token through SDK serialization so this tests the post-SDK admission boundary.
        fun methods(token: String): List<AuthMethod> {
            val payload = buildJsonObject { put("number", JsonUnquotedLiteral(token)) }
            return listOf(
                AuthMethod.AgentAuth(AuthMethodId("agent"), "name", null, payload),
                AuthMethod.UnknownAuthMethod(AuthMethodId("future"), "name", null, "future", payload),
            )
        }
        for (token in listOf("1".repeat(256), "-" + "1".repeat(255), "1.25")) {
            for (method in methods(token)) {
                assertEquals(1, AcpAuthenticationInventory.capture(listOf(method), emptyList()).methods.size)
            }
        }
        for (token in listOf("1".repeat(257), "-" + "1".repeat(256), "1e309", "1e-310")) {
            for (method in methods(token)) {
                val failure = assertFailsWith<AcpAuthenticationInventoryFailure> {
                    AcpAuthenticationInventory.capture(listOf(method), emptyList())
                }
                assertEquals("ACP authentication inventory exceeds its payload limits", failure.message)
            }
        }
    }

    @Test fun `logout advertisement remains independent of methods and execution support`() {
        val absent = AcpAuthenticationInventory.capture(emptyList(), emptyList())
        val advertised = AcpAuthenticationInventory.capture(emptyList(), emptyList(), logoutAdvertised = true)
        assertFalse(absent.logoutAdvertised)
        assertTrue(advertised.logoutAdvertised)
        assertFalse(absent.logoutSupported)
        assertFalse(advertised.logoutSupported)
        assertTrue(advertised.methods.isEmpty())
        // The existing commitment describes method metadata, not logout authority.
        assertEquals(absent.sha256, advertised.sha256)
    }

    @Test fun `unpaired surrogates fail as authentication inventory errors`() {
        for (invalid in listOf("\ud800", "\udc00", "\ud800x")) {
            for (method in listOf(
                AuthMethod.AgentAuth(AuthMethodId(invalid), "name", null),
                AuthMethod.AgentAuth(AuthMethodId("id"), invalid, null),
                AuthMethod.AgentAuth(AuthMethodId("id"), "name", invalid),
            )) {
                val failure = assertFailsWith<AcpAuthenticationInventoryFailure> {
                    AcpAuthenticationInventory.capture(listOf(method), emptyList())
                }
                assertEquals("ACP authentication inventory contains invalid Unicode", failure.message)
            }
        }
        val valid = AuthMethod.AgentAuth(AuthMethodId("id-\ud83d\udd11"), "name", "description")
        assertEquals(valid.id.value, AcpAuthenticationInventory.capture(listOf(valid), emptyList()).methods.single().id)
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

    @Test fun `complete inventory limits include metadata unsupported payloads depth and aggregate size`() {
        fun agent(index: Int, payload: JsonElement): AuthMethod = AuthMethod.AgentAuth(
            AuthMethodId("method-$index"), "name", null, payload)
        val oversized = buildJsonObject { put("private-key", "private-value".repeat(1500)) }
        var nested: JsonElement = JsonPrimitive("private-value")
        repeat(20) { nested = buildJsonArray { add(nested) } }
        val cases = listOf(
            listOf(agent(0, oversized)),
            listOf(AuthMethod.UnknownAuthMethod(AuthMethodId("future"), "name", null,
                "future", buildJsonObject { put("type", "future"); put("payload", oversized) })),
            listOf(agent(0, nested)),
            List(8) { agent(it, JsonPrimitive("x".repeat(9000))) },
            listOf(agent(0, buildJsonArray { repeat(4096) { add(0) } })),
        )
        for (methods in cases) {
            val error = assertFailsWith<AcpAuthenticationInventoryFailure> {
                AcpAuthenticationInventory.capture(methods, emptyList())
            }
            assertEquals("ACP authentication inventory exceeds its payload limits", error.message)
        }
        val accepted = AcpAuthenticationInventory.capture(listOf(agent(0,
            buildJsonObject { put("hint", "private-value") })), listOf("private-value"))
        assertEquals(1, accepted.methods.size)
        assertFalse(accepted.toString().contains("private-value"))
    }

    @Test fun `ambiguous and excessive advertisements fail with fixed diagnostics`() {
        val method = AuthMethod.AgentAuth(AuthMethodId("secret-id"), "name", null)
        for (methods in listOf(listOf(method, method), List(33) { method },
            listOf(AuthMethod.AgentAuth(AuthMethodId("x".repeat(257)), "name", null)),
            listOf(AuthMethod.AgentAuth(AuthMethodId("id"), "x".repeat(513), null)))) {
            val error = assertFailsWith<IllegalArgumentException> { AcpAuthenticationInventory.capture(methods, emptyList()) }
            assertFalse(error.message!!.contains("secret-id"))
        }
    }
}
