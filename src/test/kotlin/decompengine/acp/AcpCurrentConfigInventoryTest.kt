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
    fun `full environment budget and complete preferences share redaction without exhausting limits`() {
        val environment = List(4096) { it.toString().padStart(256, 'x') }
        val preferences = AcpSessionPreferences("model-private", "mode-private", List(64) {
            AcpSessionConfigPreference("option-$it", AcpSessionConfigValue.Select("value-$it"))
        })
        val identifiers = preferences.privateIdentifiers()
        assertEquals(130, identifiers.size)
        val preview = previewSessionChoices(sequenceOf("prefix-mode-private", "prefix-option-63", "prefix-value-63"),
            environment, identifiers)
        assertFalse(preview.contains("mode-private"))
        assertFalse(preview.contains("option-63"))
        assertFalse(preview.contains("value-63"))
        assertTrue(preview.contains("[redacted]"))
        val failure = assertFailsWith<AgentExecutionException> {
            requireCurrentSessionConfigPreference(inventory("session-new-configured.response"),
                preferences.configOptions.first(), 0, environment, identifiers)
        }
        assertEquals(AgentFailureKind.CONFIGURATION, failure.failure.kind)
    }

    @Test
    fun `current choices redact configured identifiers embedded in advertised values`() {
        val original = inventory("session-new-configured.response").first()
        val option = Json.decodeFromString<SessionConfigOption>(Json.encodeToString(SessionConfigOption.serializer(), original)
            .replace("reasoning", "prefix-private-option").replace("high", "prefix-private-value"))
        for (preference in listOf(
            AcpSessionConfigPreference("private-option", AcpSessionConfigValue.BooleanValue(false)),
            AcpSessionConfigPreference("prefix-private-option", AcpSessionConfigValue.Select("private-value")),
        )) {
            val failure = assertFailsWith<AgentExecutionException> {
                requireCurrentSessionConfigPreference(listOf(option), preference, 0)
            }
            assertFalse(failure.stackTraceToString().contains(preference.id))
            if (preference.value is AcpSessionConfigValue.Select) {
                assertFalse(failure.stackTraceToString().contains("private-value"))
            }
        }
    }

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

    @Test
    fun `shared choice preview bounds enumeration and escapes redacted peer text`() {
        val choices = sequence {
            yield("private-value\nquoted\"choice")
            repeat(4) { yield("x".repeat(100)) }
            error("preview must not enumerate beyond its lookahead")
        }
        val preview = previewSessionChoices(choices, listOf("private-value"))
        assertFalse(preview.contains("private-value"))
        assertFalse(preview.contains('\n'))
        assertTrue(preview.contains("[redacted]"))
        assertTrue(preview.endsWith(" (more choices omitted)"))
        val decoded = Json.parseToJsonElement(preview.removeSuffix(" (more choices omitted)")).jsonArray
        assertEquals(4, decoded.size)
        assertTrue(decoded.all { it.jsonPrimitive.content.length <= 48 + "… [preview truncated]".length })
        assertTrue(decoded[1].jsonPrimitive.content.endsWith("… [preview truncated]"))
        assertEquals("[]", previewSessionChoices(emptySequence(), emptyList()))
    }

    @Test
    fun `whitespace-only configured identifiers remain private in choice previews`() {
        val preferences = AcpSessionPreferences(" ", "  ", listOf(
            AcpSessionConfigPreference("   ", AcpSessionConfigValue.Select("    "))))
        for (id in preferences.privateIdentifiers()) {
            val preview = previewSessionChoices(sequenceOf("prefix" + id + "suffix"), emptyList(), preferences.privateIdentifiers())
            assertFalse(preview.contains(id))
            assertTrue(preview.contains("[redacted]"))
        }
    }

    @Test
    fun `final preview omits private identifiers synthesized by replacements and formatting`() {
        val cases = listOf(
            listOf("\"model-safe\"") to sequenceOf("model-safe"),
            listOf(" (more choices omitted)") to (1..5).asSequence().map { "choice-$it" },
            listOf("[]") to emptySequence<String>(),
        )
        for ((privateIds, choices) in cases) {
            val preview = previewSessionChoices(choices, emptyList(), privateIds)
            assertEquals("", preview)
            privateIds.forEach { assertFalse(preview.contains(it)) }
        }
        val synthesized = previewSessionChoices(sequenceOf("foobarX"), emptyList(), listOf("[redacted]X", "foobar"))
        assertTrue(synthesized.contains("[redacted]"))
        assertFalse(synthesized.contains("[redacted]X"))
        assertFalse(synthesized.contains("foobar"))
    }

    @Test
    fun `final preview omits environment secrets synthesized by formatting`() {
        val cases = listOf(
            listOf("\"model-safe\"") to sequenceOf("model-safe"),
            listOf(" (more choices omitted)") to (1..5).asSequence().map { "choice-$it" },
        )
        for ((sensitiveValues, choices) in cases) {
            val preview = previewSessionChoices(choices, sensitiveValues, emptyList())
            assertEquals("", preview)
            sensitiveValues.forEach { assertFalse(preview.contains(it)) }
        }
    }

    @Test
    fun `initial rejection preview rechecks environment secrets after formatting`() {
        val options = inventory("session-new-configured.response")
        val failure = assertFailsWith<AgentExecutionException> {
            requireCurrentSessionConfigPreference(options,
                AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.Select("missing-value")), 0,
                listOf("\"high\""))
        }
        assertFalse(failure.message.orEmpty().contains("high"))
        assertFalse(failure.stackTraceToString().contains("high"))
    }

    private fun inventory(name: String): List<SessionConfigOption> {
        val fixture = javaClass.getResourceAsStream("/acp/v1/wire-contract.json")!!.use { it.readBytes().decodeToString() }
        return Json.parseToJsonElement(fixture).jsonObject.getValue("messages").jsonObject.getValue(name)
            .jsonObject.getValue("result").jsonObject.getValue("configOptions").jsonArray.map {
                Json.decodeFromJsonElement(SessionConfigOption.serializer(), it)
            }
    }
}
