package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class GccBundledCliEvidenceChecksTest {
    @Test
    fun `missing checksums and foreign lineage are rejected even with a recomputed outer checksum`() {
        val payload = JsonObject(mapOf("diagnosticFixtureOnly" to JsonPrimitive(true)))
        val fields = base("gcc-bundled-planner-executed-v1") + mapOf(
            "execution" to payload, "executionSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(payload))))
        val valid = checksummed(fields)
        assertEquals(JsonObject(fields + ("recordSha256" to digest(fields))),
            requireGccCliLinkedRecord(valid, "planner-execution.json", OPERATION, INTENT, PREVIOUS))
        // Authored JSON tests record consistency; it does not establish execution or START authority.
        val invalid = listOf(
            OracleJson.canonicalBytes(JsonObject(fields)),
            checksummed(fields - "executionSha256"), checksummed(fields - "execution"),
            checksummed(fields + ("executionSha256" to JsonPrimitive(PREVIOUS))),
            checksummed(fields + ("execution" to JsonObject(mapOf("changed" to JsonPrimitive(true))))),
            checksummed(fields + ("execution" to JsonPrimitive("not an object"))),
            checksummed(fields + ("operationId" to JsonPrimitive(PREVIOUS))),
            checksummed(fields + ("intentSha256" to JsonPrimitive(PREVIOUS))),
            checksummed(fields + ("previousSha256" to JsonPrimitive(INTENT))),
            checksummed(fields + ("complete" to JsonPrimitive(true))),
            checksummed(fields + ("releaseEligible" to JsonPrimitive(true))),
            checksummed(fields + ("schemaVersion" to JsonPrimitive("1"))),
            checksummed(fields + ("provider" to JsonPrimitive("unrelated-provider"))),
            checksummed(fields + ("unexpected" to JsonPrimitive(false))),
        )
        invalid.forEach { bytes -> assertFails { requireGccCliLinkedRecord(bytes, "planner-execution.json", OPERATION, INTENT, PREVIOUS) } }
        assertFails { requireGccCliLinkedRecord(valid, "unknown.json", OPERATION, INTENT, PREVIOUS) }
    }

    @Test
    fun `authorization records require their checksum and reject injected payloads`() {
        val fields = base("gcc-bundled-planner-start-authorized-v1")
        requireGccCliLinkedRecord(checksummed(fields), "planner-start-authorized.json", OPERATION, INTENT, PREVIOUS)
        assertFails {
            requireGccCliLinkedRecord(OracleJson.canonicalBytes(JsonObject(fields)), "planner-start-authorized.json", OPERATION, INTENT, PREVIOUS)
        }
        assertFails {
            requireGccCliLinkedRecord(checksummed(fields + ("execution" to JsonObject(emptyMap()))), "planner-start-authorized.json", OPERATION, INTENT, PREVIOUS)
        }
    }

    private fun base(provider: String) = mapOf(
        "provider" to JsonPrimitive(provider), "schemaVersion" to JsonPrimitive(1), "operationId" to JsonPrimitive(OPERATION),
        "intentSha256" to JsonPrimitive(INTENT), "previousSha256" to JsonPrimitive(PREVIOUS),
        "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false))
    private fun digest(fields: Map<String, kotlinx.serialization.json.JsonElement>) = JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(fields))))
    private fun checksummed(fields: Map<String, kotlinx.serialization.json.JsonElement>) = OracleJson.canonicalBytes(JsonObject(fields + ("recordSha256" to digest(fields))))
    private companion object {
        val OPERATION = "a".repeat(64)
        val INTENT = "b".repeat(64)
        val PREVIOUS = "c".repeat(64)
    }
}
