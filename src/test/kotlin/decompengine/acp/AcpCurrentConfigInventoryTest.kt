package decompengine.acp

import com.agentclientprotocol.annotations.UnstableApi
import com.agentclientprotocol.model.SessionConfigOption
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentFailureKind
import kotlinx.serialization.json.*
import kotlin.test.*

@OptIn(UnstableApi::class)
class AcpCurrentConfigInventoryTest {
    @Test
    fun `flat and grouped current inventories must retain a unique configured value`() {
        val preference = AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.Select("high"))
        listOf("session-new-configured.response", "session-new-grouped-config.response").forEach { name ->
            val options = inventory(name)
            requireCurrentSessionConfigPreference(options, preference, 1)
            listOf(emptyList(), options + options.first(), options.filter { it.id.value != "reasoning" }).forEach { changed ->
                val failure = assertFailsWith<AgentExecutionException> {
                    requireCurrentSessionConfigPreference(changed, preference, 1)
                }
                assertEquals(AgentFailureKind.CONFIGURATION, failure.failure.kind)
                assertEquals("currentInventoryMismatch", failure.failure.details["reason"])
                assertEquals("1", failure.failure.details["preferenceIndex"])
            }
            val removedValue = options.map { option ->
                Json.decodeFromString<SessionConfigOption>(Json.encodeToString(SessionConfigOption.serializer(), option)
                    .replace("\"high\"", "\"removed\""))
            }
            assertFailsWith<AgentExecutionException> { requireCurrentSessionConfigPreference(removedValue, preference, 1) }
            val duplicateValue = options.map { option ->
                Json.decodeFromString<SessionConfigOption>(Json.encodeToString(SessionConfigOption.serializer(), option)
                    .replace("\"value\":\"low\"", "\"value\":\"high\""))
            }
            assertFailsWith<AgentExecutionException> { requireCurrentSessionConfigPreference(duplicateValue, preference, 1) }
        }
    }

    @Test
    fun `current type mismatch is rejected without exposing preference values`() {
        val options = inventory("session-new-configured.response")
        requireCurrentSessionConfigPreference(options, AcpSessionConfigPreference("telemetry", AcpSessionConfigValue.BooleanValue(false)), 0)
        val preference = AcpSessionConfigPreference("telemetry", AcpSessionConfigValue.Select("private-configured-value"))
        val failure = assertFailsWith<AgentExecutionException> { requireCurrentSessionConfigPreference(options, preference, 0) }
        assertFalse(failure.message.orEmpty().contains("private-configured-value"))
        assertFalse(failure.failure.details.toString().contains("private-configured-value"))
        assertTrue(failure.message.orEmpty().contains("[false,true]"))
    }

    @Test
    fun `choice previews redact configured secrets and bound long inventories`() {
        val original = inventory("session-new-configured.response").first()
        val options = (0 until 20).map { index ->
            Json.decodeFromString<SessionConfigOption>(Json.encodeToString(SessionConfigOption.serializer(), original)
                .replace("\"reasoning\"", "\"private-inventory-$index\""))
        }
        val failure = assertFailsWith<AgentExecutionException> {
            requireCurrentSessionConfigPreference(options,
                AcpSessionConfigPreference("missing", AcpSessionConfigValue.BooleanValue(false)), 0,
                listOf("private-inventory"))
        }
        assertFalse(failure.message.orEmpty().contains("private-inventory"))
        assertTrue(failure.message.orEmpty().contains("[redacted]"))
        assertTrue(failure.message.orEmpty().contains("more choices omitted"))
        assertTrue(failure.message.orEmpty().length < 1024)
    }

    private fun inventory(name: String): List<SessionConfigOption> {
        val fixture = javaClass.getResourceAsStream("/acp/v1/wire-contract.json")!!.use { it.readBytes().decodeToString() }
        return Json.parseToJsonElement(fixture).jsonObject.getValue("messages").jsonObject.getValue(name)
            .jsonObject.getValue("result").jsonObject.getValue("configOptions").jsonArray.map {
                Json.decodeFromJsonElement(SessionConfigOption.serializer(), it)
            }
    }
}
