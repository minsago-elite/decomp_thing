package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeDataObservationsTest {
    @Test
    fun `configuration and shard input match historical canonical bytes`() {
        val inventory = inventory()
        val input = FullTreeDataObservations.shardInputs(
            inventory,
            scopeSha256 = "2".repeat(64),
            richArtifactSha256 = "3".repeat(64),
        ).single()

        assertEquals(
            "5fab5ac3b18c3a29e9809d8d6ad62e6a917360b13e2dddab52b6377dcc3a09ff",
            FullTreeDataObservations.configurationSha256,
        )
        assertEquals("shard-a", input.identifier)
        assertEquals("10ba71206acf6a006f6721639fdad9368a9443e14a7986bdc675860c4c0b7681", input.inputSha256)
    }

    @Test
    fun `empty authenticated shard reconciles schema bindings ordering and counts`() {
        val inventory = inventory()
        val scope = scope()
        val input = FullTreeDataObservations.shardInputs(
            inventory,
            scopeSha256 = "2".repeat(64),
            richArtifactSha256 = "3".repeat(64),
        ).single()
        val document = observationDocument(input)

        FullTreeDataObservations.validateShard(document, scope, "2".repeat(64), inventory, input)
    }

    @Test
    fun `observation validator rejects substituted bindings owners order and counts`() {
        val inventory = inventory()
        val scope = scope()
        val input = FullTreeDataObservations.shardInputs(
            inventory,
            scopeSha256 = "2".repeat(64),
            richArtifactSha256 = "3".repeat(64),
        ).single()
        val valid = observationDocument(input)
        val wrongBinding = JsonObject(valid.toMutableMap().apply {
            this["shard"] = JsonObject(
                mapOf("id" to JsonPrimitive("shard-a"), "inputSha256" to JsonPrimitive("4".repeat(64))),
            )
        })
        assertFailsWith<FullTreeDataTruthException> {
            FullTreeDataObservations.validateShard(wrongBinding, scope, "2".repeat(64), inventory, input)
        }

        val forgedInput = FullTreeDataObservationShardInput(
            input.identifier,
            "5".repeat(64),
            input.units,
        )
        val forgedFailure = assertFailsWith<FullTreeDataTruthException> {
            FullTreeDataObservations.validateShard(valid, scope, "2".repeat(64), inventory, forgedInput)
        }
        assertTrue(forgedFailure.message.orEmpty().contains("not authenticated"))

        val outsideOwner = observationDocument(
            input,
            globals = listOf(globalObservation("global-observation-${"a".repeat(32)}", "unit-b")),
        )
        val ownerFailure = assertFailsWith<FullTreeDataTruthException> {
            FullTreeDataObservations.validateShard(outsideOwner, scope, "2".repeat(64), inventory, input)
        }
        assertTrue(ownerFailure.message.orEmpty().contains("outside its shard"))

        val unordered = observationDocument(
            input,
            globals = listOf(
                globalObservation("global-observation-${"b".repeat(32)}", "unit-a"),
                globalObservation("global-observation-${"a".repeat(32)}", "unit-a"),
            ),
        )
        val orderingFailure = assertFailsWith<FullTreeDataTruthException> {
            FullTreeDataObservations.validateShard(unordered, scope, "2".repeat(64), inventory, input)
        }
        assertTrue(orderingFailure.message.orEmpty().contains("not ordered"))

        val badCount = JsonObject(valid.toMutableMap().apply {
            this["counts"] = JsonObject((getValue("counts") as JsonObject).toMutableMap().apply {
                this["globals"] = JsonPrimitive(1)
            })
        })
        val failure = assertFailsWith<FullTreeDataTruthException> {
            FullTreeDataObservations.validateShard(badCount, scope, "2".repeat(64), inventory, input)
        }
        assertTrue(failure.message.orEmpty().contains("counts"))
    }

    private fun inventory(): JsonObject = JsonObject(
        mapOf(
            "indexSha256" to JsonPrimitive("1".repeat(64)),
            "units" to JsonArray(
                listOf(
                    JsonObject(
                        mapOf(
                            "id" to JsonPrimitive("unit-a"),
                            "dwarfOffset" to JsonPrimitive("0x10"),
                        ),
                    ),
                ),
            ),
            "shards" to JsonArray(
                listOf(
                    JsonObject(
                        mapOf(
                            "id" to JsonPrimitive("shard-a"),
                            "unitIds" to JsonArray(listOf(JsonPrimitive("unit-a"))),
                        ),
                    ),
                ),
            ),
        ),
    )

    private fun scope(): JsonObject = JsonObject(
        mapOf(
            "oracle" to JsonObject(mapOf("richArtifactSha256" to JsonPrimitive("3".repeat(64)))),
        ),
    )

    private fun observationDocument(
        input: FullTreeDataObservationShardInput,
        globals: List<JsonObject> = emptyList(),
    ): JsonObject {
        val document = OracleJson.parse(
            """
            {
              "schemaVersion": 1,
              "oracle": {
                "configurationSha256": "${FullTreeDataObservations.configurationSha256}",
                "inventoryIndexSha256": "${"1".repeat(64)}",
                "richArtifactSha256": "${"3".repeat(64)}",
                "scopeSha256": "${"2".repeat(64)}"
              },
              "shard": {"id": "shard-a", "inputSha256": "${input.inputSha256}"},
              "counts": {"units": 1, "scannedDies": 1, "globals": 0, "types": 0, "fields": 0, "bases": 0, "enumerators": 0},
              "globals": [],
              "types": []
            }
            """.trimIndent().toByteArray(),
        ) as JsonObject
        if (globals.isEmpty()) return document
        return JsonObject(document.toMutableMap().apply {
            this["globals"] = JsonArray(globals)
            this["counts"] = JsonObject((getValue("counts") as JsonObject).toMutableMap().apply {
                this["globals"] = JsonPrimitive(globals.size)
            })
        })
    }

    private fun globalObservation(id: String, unitId: String): JsonObject = JsonObject(
        linkedMapOf(
            "id" to JsonPrimitive(id),
            "unitId" to JsonPrimitive(unitId),
            "dieOffset" to JsonPrimitive("0x10"),
            "names" to JsonArray(listOf(JsonPrimitive("global_name"))),
            "declaration" to JsonObject(emptyMap()),
            "addressRva" to JsonPrimitive("0x10"),
            "size" to JsonPrimitive(8),
            "alignment" to JsonPrimitive(8),
            "external" to JsonPrimitive(true),
            "visibility" to JsonPrimitive("default"),
            "tls" to JsonPrimitive(false),
            "mutability" to JsonPrimitive("mutable"),
            "typeReference" to JsonArray(
                listOf(
                    JsonPrimitive("0x10"),
                    JsonPrimitive("0x20"),
                    JsonArray(emptyList()),
                    JsonNull,
                ),
            ),
            "reasonCode" to JsonNull,
        ),
    )
}
