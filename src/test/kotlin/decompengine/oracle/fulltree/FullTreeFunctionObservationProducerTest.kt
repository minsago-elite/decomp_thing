package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeFunctionObservationProducerTest {
    @Test
    fun `artifact-backed Kotlin producer authenticates and observes every fixture shard`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root)
            val scope = fixture.authenticatedScope()

            val clang = FullTreeFunctionObservationProducer.generateShard(
                fixture.richArtifact,
                fixture.inventory,
                scope,
                "clang-lib-driver",
                root,
            )
            val generated = FullTreeFunctionObservationProducer.generateShard(
                fixture.richArtifact,
                fixture.inventory,
                scope,
                "generated-tools-clang",
                root,
            )

            assertEquals(5L, clang.scannedDies)
            assertEquals(1L, clang.entities)
            assertEquals(
                "c87459a87ad95733540cee774d156d2d8b1ff64d6a9971398dd6ca8debeafbd8",
                clang.outputSha256,
            )
            assertEquals(fixtureSha256(fixture.inventory), clang.inventoryArtifactSha256)
            assertEquals(fixtureSha256(fixture.richArtifact), clang.richArtifactSha256)
            assertEquals(clang.outputSha256, OracleArtifacts.sha256(OracleJson.canonicalBytes(clang.document)))
            assertFunction(
                clang.document,
                rva = "0x1129",
                aliases = listOf("main"),
                sourcePath = "source/clang/lib/Driver/main.cpp",
                line = 1L,
                column = 35L,
            )

            assertEquals(4L, generated.scannedDies)
            assertEquals(1L, generated.entities)
            assertEquals(
                "9968556a89b7632635b4318a93c26adc3b59ccd98619c63fb05725367d13b3d8",
                generated.outputSha256,
            )
            assertFunction(
                generated.document,
                rva = "0x1139",
                aliases = listOf("_Z15generated_valuev", "generated_value"),
                sourcePath = "generated/tools/clang/lib/Basic/Generated.cpp",
                line = 1L,
                column = 5L,
            )
        }

    @Test
    fun `repeated Kotlin scans are byte identical and forged inventory metadata fails closed`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root)
            val scope = fixture.authenticatedScope()
            val first = FullTreeFunctionObservationProducer.generateShard(
                fixture.richArtifact,
                fixture.inventory,
                scope,
                "clang-lib-driver",
                root,
            )
            val second = FullTreeFunctionObservationProducer.generateShard(
                fixture.richArtifact,
                fixture.inventory,
                scope,
                "clang-lib-driver",
                root,
            )
            assertEquals(first.outputSha256, second.outputSha256)
            assertTrue(
                OracleJson.canonicalBytes(first.document).contentEquals(OracleJson.canonicalBytes(second.document)),
            )

            val original = parseControlObject(fixture.inventory)
            val forgedUnits = original.controlArray("units").controlObjects("inventory units").mapIndexed {
                    index,
                    unit,
                ->
                if (index == 0) {
                    JsonObject(unit.toMutableMap().apply {
                        this["rawPathSha256"] = JsonPrimitive("f".repeat(64))
                    })
                } else {
                    unit
                }
            }
            val forged = JsonObject(original.toMutableMap().apply {
                this["units"] = JsonArray(forgedUnits)
                this["indexSha256"] = JsonPrimitive(inventoryIndex(forgedUnits))
            })
            val forgedPath = root.resolve("forged-inventory.json")
            writeControlObject(forgedPath, forged)

            val failure = assertFailsWith<FullTreeControlException> {
                FullTreeFunctionObservationProducer.generateShard(
                    fixture.richArtifact,
                    forgedPath,
                    scope,
                    "clang-lib-driver",
                    root,
                )
            }
            assertTrue(failure.message.orEmpty().contains("metadata differs"), failure.message)
        }

    @Test
    fun `resident model charges every cached line table before artifact traversal`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root)
            val original = fixture.authenticatedScope()
            val bounds = original.document.controlObject("bounds")
            val perShard = bounds.controlObject("perShard")
            val constrainedDocument = JsonObject(original.document.toMutableMap().apply {
                this["bounds"] = JsonObject(bounds.toMutableMap().apply {
                    this["perShard"] = JsonObject(perShard.toMutableMap().apply {
                        this["maximumResidentBytes"] = JsonPrimitive(2_000L)
                    })
                })
            })
            val constrained = authenticatedScopeWithDocument(original, constrainedDocument)
            val failure = assertFailsWith<FullTreeControlException> {
                FullTreeFunctionObservationProducer.generateShardWithLimits(
                    richArtifact = fixture.richArtifact,
                    inventoryPath = fixture.inventory,
                    scope = constrained,
                    shardId = "clang-lib-driver",
                    scratchParent = root,
                    controlLimits = FullTreeControlLimits(),
                    producerLimits = FullTreeFunctionObservationProducerLimits(
                        dieLimits = FullTreeDwarfDieLimits(
                            maximumPhysicalRecords = 1,
                            maximumNonNullRecords = 1,
                            maximumAttributes = 1,
                            maximumTreeDepth = 1,
                            maximumRetainedBytes = 1,
                        ),
                        lineTableLimits = FullTreeDwarfLineTableLimits(
                            maximumUnitBytes = 1,
                            maximumDirectories = 1,
                            maximumFiles = 1,
                            maximumEntryFormats = 1,
                            maximumPathBytes = 1,
                            maximumPathCharacters = 1,
                            maximumAggregatePathBytes = 1,
                            maximumParseSteps = 1,
                        ),
                        maximumReferenceChainEntries = 1,
                        maximumCachedCompilationUnits = 2,
                    ),
                )
            }
            assertTrue(failure.message.orEmpty().contains("cache model"), failure.message)
        }

    private fun assertFunction(
        document: JsonObject,
        rva: String,
        aliases: List<String>,
        sourcePath: String,
        line: Long,
        column: Long,
    ) {
        assertEquals(0, document.controlArray("nonEmitted").size)
        val emitted = document.controlArray("emitted").single() as JsonObject
        assertEquals(rva, emitted.controlString("rva"))
        assertEquals(
            aliases,
            emitted.controlArray("aliases").map { (it as JsonObject).controlString("name") },
        )
        val declaration = emitted.controlArray("declarations").single() as JsonObject
        assertEquals(sourcePath, declaration.controlString("sourcePath"))
        assertEquals(sourcePath, declaration.controlString("unitSourcePath"))
        assertEquals(1L, declaration.controlLong("fileIndex"))
        assertEquals(line, declaration.controlLong("line"))
        assertEquals(column, declaration.controlLong("column"))
    }

    private fun inventoryIndex(units: List<JsonObject>): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("full-tree-index-v1\u0000".toByteArray(StandardCharsets.UTF_8))
        units.forEach { unit ->
            digest.update(MessageDigest.getInstance("SHA-256").digest(OracleJson.canonicalBytes(unit)))
        }
        return digest.digest().joinToString("") { byte ->
            (byte.toInt() and 0xff).toString(16).padStart(2, '0')
        }
    }
}
