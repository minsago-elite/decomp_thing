package decompengine.oracle.gcc

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertFailsWith

/** Authored JSON only: no profile files, operation owner, worker, controller or native fixture. */
class GccFullExportPlannerPolicyTest {
    private val digest = "a".repeat(64)
    private fun policy(profileDigest: String = digest): JsonObject = JsonObject(mapOf(
        "provider" to JsonPrimitive("authored-retained-policy"),
        "profileSha256" to JsonPrimitive(profileDigest),
        "layout" to JsonObject(mapOf("maximumEntities" to JsonPrimitive(12))),
        "inputs" to JsonArray(listOf(JsonPrimitive("authored-input-commitment"))),
    ))
    private fun intent(value: JsonElement?, engine: String = "cc1"): JsonObject = JsonObject(
        mapOf("engineId" to JsonPrimitive(engine)) + (value?.let { mapOf("plannerProfile" to it) } ?: emptyMap()),
    )

    @Test
    fun `accepts an independently copied exact retained policy for the authenticated cc1 profile`() {
        val retained = policy()
        val copied = JsonObject(retained.entries.reversed().associate { it.key to it.value })
        requireGccFullExportPlannerPolicy(intent(copied), retained, digest)
    }

    @Test
    fun `rejects a different selected raw profile digest despite otherwise equal policy data`() {
        assertFailsWith<IllegalArgumentException> {
            requireGccFullExportPlannerPolicy(intent(policy("b".repeat(64))), policy(), digest)
        }
    }

    @Test
    fun `rejects changed layout or input commitments even when the raw profile digest is repeated`() {
        for (field in listOf("layout", "inputs", "provider")) {
            val changed = JsonObject(policy() + (field to JsonPrimitive("changed-authored-value")))
            assertFailsWith<IllegalArgumentException> {
                requireGccFullExportPlannerPolicy(intent(changed), policy(), digest)
            }
        }
    }

    @Test
    fun `rejects a foreign engine and missing null or nonobject selected policy`() {
        for (selected in listOf(null, JsonNull, JsonPrimitive("not-a-policy"), JsonArray(emptyList()))) {
            assertFailsWith<IllegalArgumentException> {
                requireGccFullExportPlannerPolicy(intent(selected), policy(), digest)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            requireGccFullExportPlannerPolicy(intent(policy(), "lto1"), policy(), digest)
        }
    }

    @Test
    fun `rejects an unbound retained policy and malformed authenticated digest before equality`() {
        val changed = policy("b".repeat(64))
        assertFailsWith<IllegalArgumentException> {
            requireGccFullExportPlannerPolicy(intent(changed), changed, digest)
        }
        for (retained in listOf(JsonNull, JsonPrimitive("not-retained"))) {
            assertFailsWith<IllegalArgumentException> {
                requireGccFullExportPlannerPolicy(intent(retained), retained, digest)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            requireGccFullExportPlannerPolicy(intent(policy()), policy(), "not-a-digest")
        }
    }
}
