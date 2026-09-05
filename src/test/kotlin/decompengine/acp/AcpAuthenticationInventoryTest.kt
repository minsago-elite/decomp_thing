package decompengine.acp

import com.agentclientprotocol.model.AuthMethod
import com.agentclientprotocol.model.AuthMethodId
import kotlin.test.*

class AcpAuthenticationInventoryTest {
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
