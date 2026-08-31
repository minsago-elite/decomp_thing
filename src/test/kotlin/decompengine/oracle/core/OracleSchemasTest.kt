package decompengine.oracle.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class OracleSchemasTest {
    @Test
    fun `bundled 2020-12 schema validates a minimal full-tree truth partition`() {
        val document = OracleJson.parse(
            """
            {
              "schemaVersion": 1,
              "oracle": {},
              "shard": {},
              "counts": {
                "globals": 0,
                "types": 0,
                "unobservableGlobals": 0,
                "unobservableTypes": 0,
                "fields": 0,
                "bases": 0,
                "enumerators": 0,
                "resolvedTypeReferences": 0,
                "unresolvedTypeReferences": 0,
                "ambiguousTypeReferences": 0,
                "crossShardTypeReferences": 0
              },
              "globals": [],
              "types": []
            }
            """.trimIndent().toByteArray(),
        )

        OracleSchemas.validate("full-tree-data-truth", document)

        val identity = OracleSchemas.identity("full-tree-data-truth")
        assertEquals("full-tree-data-truth", identity.name)
        assertTrue(identity.sha256.matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun `schema validation rejects missing extra and mistyped fields`() {
        listOf(
            "{}",
            """{"schemaVersion":1,"oracle":{},"shard":{},"counts":{},"globals":[],"types":[],"extra":true}""",
            """{"schemaVersion":"1","oracle":{},"shard":{},"counts":{},"globals":[],"types":[]}""",
        ).forEach { input ->
            val failure = assertFailsWith<OracleSchemaException>(input) {
                OracleSchemas.validate("full-tree-data-truth", OracleJson.parse(input.toByteArray()))
            }
            assertTrue(failure.message.orEmpty().contains("schema validation"), failure.message)
        }
    }

    @Test
    fun `schema resources cannot be selected through paths or unknown names`() {
        listOf("../full-tree-data-truth", "/full-tree-data-truth", "FullTree", "", "gcc//build-record").forEach {
            assertFailsWith<OracleSchemaException>(it) { OracleSchemas.identity(it) }
        }
        assertFailsWith<OracleSchemaException> { OracleSchemas.identity("not-a-schema") }
    }

    @Test
    fun `every catalogued schema is bundled and compilable`() {
        assertEquals(55, OracleSchemas.supportedNames.size)
        OracleSchemas.supportedNames.forEach { name ->
            val identity = OracleSchemas.identity(name)
            assertEquals(name, identity.name)
            assertTrue(identity.sha256.matches(Regex("[0-9a-f]{64}")), name)
        }
    }

    @Test
    fun `configuration digest binds canonical policy and exact schema bytes`() {
        assertEquals(
            "90dd097ba542bc5297b37277125ce01e73355fe0e4cea3117b3240315fff5a5b",
            OracleSchemas.configurationSha256(
                "full-tree-data-truth",
                JsonObject(
                    linkedMapOf(
                        "id" to JsonPrimitive("full-tree-data-truth"),
                        "version" to JsonPrimitive(16),
                        "typeIdentity" to JsonPrimitive(
                            "tag-qualified-lexical-context-name-or-anonymous-declaration-with-observation-owned-lambda-and-lossy-local-contexts",
                        ),
                        "globalIdentity" to JsonPrimitive(
                            "rva-or-source-aligned-name-declaration-or-producer-observation",
                        ),
                        "owner" to JsonPrimitive("lowest-unit-id"),
                        "typeReferences" to JsonPrimitive(
                            "exact-dwarf-offset-chain-with-conditional-bounded-authenticated-candidate-commitments-and-no-ambiguous-target-substitution",
                        ),
                        "truthSharding" to JsonPrimitive(
                            "inventory-owner-with-deterministic-two-thirds-byte-budget-entity-partitions",
                        ),
                        "maximumDatabaseBytes" to JsonPrimitive(8L * 1024 * 1024 * 1024),
                    ),
                ),
            ),
        )
    }

    @Test
    fun `validator accepts caller trees without reparsing permissive JSON`() {
        val emptyPartition = OracleJson.parse(
            """{"counts":{"ambiguousTypeReferences":0,"bases":0,"crossShardTypeReferences":0,"enumerators":0,"fields":0,"globals":0,"resolvedTypeReferences":0,"types":0,"unobservableGlobals":0,"unobservableTypes":0,"unresolvedTypeReferences":0},"globals":[],"oracle":{},"schemaVersion":1,"shard":{},"types":[]}""".toByteArray(),
        ) as JsonObject

        OracleSchemas.validate("full-tree-data-truth", emptyPartition)
    }
}
