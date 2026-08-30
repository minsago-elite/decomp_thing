package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FullTreeDataTruthSemanticsTest {
    @Test
    fun `source aligned type identity merges ordinary ODR observations`() {
        val first = typeObservation(id = "observation-a", unitId = "unit-z")
        val second = typeObservation(id = "observation-b", unitId = "unit-a")

        val identity = FullTreeDataTruthSemantics.typeIdentity(first)
        assertEquals(identity, FullTreeDataTruthSemantics.typeIdentity(second))
        assertEquals("98c43afd4b0595a9814c9feae381cd56975a83c70db7ac6b3e4448908e50fd56", identity)
    }

    @Test
    fun `lambda anonymous namespace and producer-only types retain required ownership`() {
        val ordinary = typeObservation(id = "observation-a", unitId = "unit-a")
        val lambdaA = typeObservation(id = "observation-a", unitId = "unit-a", name = "lambda at file.cc:7:3")
        val lambdaB = typeObservation(id = "observation-b", unitId = "unit-a", name = "lambda at file.cc:7:3")
        val anonymousA = typeObservation(id = "observation-a", unitId = "unit-a", name = "anonymous namespace::Thing")
        val anonymousB = typeObservation(id = "observation-b", unitId = "unit-b", name = "anonymous namespace::Thing")
        val producerA = typeObservation(id = "observation-a", unitId = "unit-a", sourcePath = null)
        val producerB = typeObservation(id = "observation-b", unitId = "unit-a", sourcePath = null)

        assertNotEquals(FullTreeDataTruthSemantics.typeIdentity(ordinary), FullTreeDataTruthSemantics.typeIdentity(lambdaA))
        assertNotEquals(FullTreeDataTruthSemantics.typeIdentity(lambdaA), FullTreeDataTruthSemantics.typeIdentity(lambdaB))
        assertNotEquals(FullTreeDataTruthSemantics.typeIdentity(anonymousA), FullTreeDataTruthSemantics.typeIdentity(anonymousB))
        assertNotEquals(FullTreeDataTruthSemantics.typeIdentity(producerA), FullTreeDataTruthSemantics.typeIdentity(producerB))
    }

    @Test
    fun `global identity prefers RVA then source declaration then producer observation`() {
        val first = globalObservation("global-a", "0x10", "/src/file.cc")
        val sameRva = globalObservation("global-b", "0x10", "/other/file.cc")
        val sourceA = globalObservation("global-a", null, "/src/file.cc")
        val sourceB = globalObservation("global-b", null, "/src/file.cc")
        val producerA = globalObservation("global-a", null, null)
        val producerB = globalObservation("global-b", null, null)

        val rvaIdentity = FullTreeDataTruthSemantics.globalIdentity(first)
        assertEquals(rvaIdentity, FullTreeDataTruthSemantics.globalIdentity(sameRva))
        assertEquals("65d4ce536775259f9ba2509635a668022768a324a78f50b1c2b4fa677312734d", rvaIdentity)
        assertEquals(FullTreeDataTruthSemantics.globalIdentity(sourceA), FullTreeDataTruthSemantics.globalIdentity(sourceB))
        assertNotEquals(FullTreeDataTruthSemantics.globalIdentity(producerA), FullTreeDataTruthSemantics.globalIdentity(producerB))
    }

    @Test
    fun `one exact type target is selected without redundant candidate commitment`() {
        val merged = FullTreeDataTruthSemantics.mergeTypeReferences(
            listOf(
                reference("type-a", "owner-a", "source-aligned", "0x10"),
                reference("type-a", "owner-a", "producer-declaration", "0x20"),
            ),
            "field-a",
        )

        assertEquals("exact-dwarf-offset", merged.string("resolutionCode"))
        assertEquals("type-a", merged.string("targetTypeId"))
        assertEquals("owner-a", merged.string("targetOwnerShardId"))
        assertEquals(listOf("0x10", "0x20"), merged.arrayStrings("evidenceDieOffsets"))
        assertTrue("candidateTargets" !in merged)
    }

    @Test
    fun `ambiguous authenticated targets remain unresolved with bounded commitment`() {
        val merged = FullTreeDataTruthSemantics.mergeTypeReferences(
            listOf(
                reference("type-b", "owner-b", "source-aligned", "0x20"),
                reference("type-a", "owner-a", "source-aligned", "0x10"),
            ),
            "field-a",
        )

        assertEquals("unresolved-authenticated-target-set", merged.string("resolutionCode"))
        assertNull(merged.nullableString("targetTypeId"))
        assertNull(merged.nullableString("targetOwnerShardId"))
        assertEquals("ambiguous-authenticated-targets", merged.string("reasonCode"))
        assertEquals(2, merged.getValue("candidateTargetCount").toString().toInt())
        assertEquals(2, merged.getValue("candidateTargets").let { it as JsonArray }.size)
        assertEquals(
            "011d251a34bdde67dc3d9d9a24f1f9ce276be9a5dbb7b35e19a71f2b98467e17",
            merged.string("candidateTargetsSha256"),
        )
    }

    @Test
    fun `sole source aligned target wins only over producer declarations`() {
        val merged = FullTreeDataTruthSemantics.mergeTypeReferences(
            listOf(
                reference("type-source", "owner-source", "source-aligned", "0x30"),
                reference("type-producer", "owner-producer", "producer-declaration", "0x10"),
            ),
            "field-a",
        )

        assertEquals("odr-member-sole-source-aligned-target", merged.string("resolutionCode"))
        assertEquals("type-source", merged.string("targetTypeId"))
        val candidates = merged.getValue("candidateTargets") as JsonArray
        assertEquals("type-source", (candidates.first() as JsonObject).string("targetTypeId"))
        assertEquals(
            "3f8c4393a5fa5614c5909113934fb9fbdd084806f51d21022a4cf6355e5d4c2e",
            merged.string("candidateTargetsSha256"),
        )
    }

    @Test
    fun `incompatible reference shape fails closed`() {
        val first = reference("type-a", "owner-a", "source-aligned", "0x10")
        val incompatible = JsonObject(first.toMutableMap().apply {
            this["modifierTags"] = JsonArray(listOf(JsonPrimitive("DW_TAG_const_type")))
        })

        assertFailsWith<FullTreeDataTruthException> {
            FullTreeDataTruthSemantics.mergeTypeReferences(listOf(first, incompatible), "field-a")
        }
    }

    @Test
    fun `reference samples and partitions are deterministic and bounded`() {
        val references = (20 downTo 1).map { index ->
            reference("type-a", "owner-a", "source-aligned", "0x${index.toString(16)}")
        }
        val merged = FullTreeDataTruthSemantics.mergeTypeReferences(references, "field-a")
        assertEquals(16, (merged.getValue("evidenceDieOffsets") as JsonArray).size)
        assertEquals(20, merged.getValue("evidenceDieOffsetCount").toString().toInt())
        assertTrue(merged.string("evidenceDieOffsetsSha256").matches(Regex("[0-9a-f]{64}")))

        val globals = listOf(globalObservation("global-a", "0x1", "/src/a.cc"))
        val types = listOf(typeObservation("type-a", "unit-a"), typeObservation("type-b", "unit-a"))
        val oneSize = OracleJson.canonicalBytes(globals.single()).size + 1
        val partitions = FullTreeDataTruthSemantics.partitionTruthEntities(globals, types, oneSize)
        assertEquals(3, partitions.size)
        assertEquals(1, partitions[0].globals.size)
        assertEquals(0, partitions[0].types.size)
        assertTrue(partitions.drop(1).all { it.globals.isEmpty() && it.types.size == 1 })
        assertEquals(
            partitions,
            FullTreeDataTruthSemantics.partitionTruthEntities(globals, types, oneSize),
        )
    }

    private fun typeObservation(
        id: String,
        unitId: String,
        name: String? = "Widget",
        sourcePath: String? = "/src/file.cc",
    ): JsonObject = JsonObject(
        linkedMapOf(
            "id" to JsonPrimitive(id),
            "unitId" to JsonPrimitive(unitId),
            "tag" to JsonPrimitive("DW_TAG_structure_type"),
            "context" to JsonArray(listOf(JsonPrimitive("DW_TAG_namespace:demo"))),
            "name" to (name?.let(::JsonPrimitive) ?: JsonNull),
            "declaration" to declaration(sourcePath),
        ),
    )

    private fun globalObservation(id: String, rva: String?, sourcePath: String?): JsonObject = JsonObject(
        linkedMapOf(
            "id" to JsonPrimitive(id),
            "names" to JsonArray(listOf(JsonPrimitive("global_name"))),
            "addressRva" to (rva?.let(::JsonPrimitive) ?: JsonNull),
            "declaration" to declaration(sourcePath),
        ),
    )

    private fun declaration(sourcePath: String?): JsonObject = JsonObject(
        linkedMapOf(
            "sourcePath" to (sourcePath?.let(::JsonPrimitive) ?: JsonNull),
            "externalPathSha256" to JsonNull,
            "line" to JsonPrimitive(7),
            "column" to JsonPrimitive(3),
        ),
    )

    private fun reference(
        target: String?,
        owner: String?,
        quality: String?,
        offset: String,
    ): JsonObject = JsonObject(
        linkedMapOf(
            "evidenceDieOffsets" to JsonArray(listOf(JsonPrimitive(offset))),
            "modifierTags" to JsonArray(emptyList()),
            "reasonCode" to JsonNull,
            "resolutionCode" to JsonPrimitive(if (target == null) "unresolved" else "exact-dwarf-offset"),
            "targetOwnerShardId" to (owner?.let(::JsonPrimitive) ?: JsonNull),
            "targetTypeId" to (target?.let(::JsonPrimitive) ?: JsonNull),
            "_targetQuality" to (quality?.let(::JsonPrimitive) ?: JsonNull),
        ),
    )
}

private fun JsonObject.string(name: String): String = getValue(name).let { it as JsonPrimitive }.content

private fun JsonObject.nullableString(name: String): String? = when (val value = getValue(name)) {
    JsonNull -> null
    is JsonPrimitive -> value.content
    else -> error("$name is not a string")
}

private fun JsonObject.arrayStrings(name: String): List<String> =
    (getValue(name) as JsonArray).map { (it as JsonPrimitive).content }
