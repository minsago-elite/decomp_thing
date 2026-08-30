package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeInventoryControlTest {
    @Test
    fun `compressed DWARF generator is byte-identical to frozen Python v1 across worker counts`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("fixture"))
            val scope = fixture.authenticatedScope()
            val serialOutput = directory.resolve("serial.json")
            val parallelOutput = directory.resolve("parallel.json")

            val serial = FullTreeInventoryControl.generateAndPublish(
                fixture.richArtifact,
                scope,
                serialOutput,
                maximumWorkers = 1,
            )
            val parallel = FullTreeInventoryControl.generateAndPublish(
                fixture.richArtifact,
                scope,
                parallelOutput,
                maximumWorkers = 2,
            )

            val expected = Files.readAllBytes(fixture.inventory)
            val serialBytes = Files.readAllBytes(serialOutput)
            assertTrue(expected.contentEquals(serialBytes))
            assertTrue(serialBytes.contentEquals(Files.readAllBytes(parallelOutput)))
            assertEquals(FROZEN_ARTIFACT_SHA256, serial.artifactSha256)
            assertEquals(FROZEN_INVENTORY_INDEX_SHA256, serial.indexSha256)
            assertEquals(FROZEN_INVENTORY_ARTIFACT_SHA256, serial.outputSha256)
            assertEquals(serial.inventory, parallel.inventory)
            assertNoInventoryScratch(directory)
        }

    @Test
    fun `frozen inventory mutations in hash order count identity kind and shard fail closed`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("fixture"))
            val scope = fixture.authenticatedScope()
            val original = parseControlObject(fixture.inventory)
            val mutations = listOf<JsonObject>(
                JsonObject(original.toMutableMap().apply { this["indexSha256"] = JsonPrimitive("0".repeat(64)) }),
                JsonObject(original.toMutableMap().apply {
                    this["units"] = JsonArray(original.controlArray("units").reversed())
                }),
                JsonObject(original.toMutableMap().apply {
                    this["counts"] = JsonObject(original.controlObject("counts").toMutableMap().apply {
                        this["compilationUnits"] = JsonPrimitive(3)
                    })
                }),
                mutateFirstUnit(original, "id", JsonPrimitive("cu-" + "0".repeat(32))),
                mutateFirstUnit(original, "sourceKind", JsonPrimitive("handwritten")),
                mutateFirstUnit(original, "shardId", JsonPrimitive("clang-lib-driver")),
            )
            mutations.forEach { mutation ->
                assertFailsWith<FullTreeControlException> {
                    FullTreeInventoryControl.validate(mutation, scope)
                }
            }
        }

    @Test
    fun `inventory enforces artifact path mode byte unit and worker bounds without residue`() =
        inControlTemporaryDirectory { directory ->
            val symlinked = createFullTreeControlFixture(directory.resolve("symlink"))
            val real = symlinked.root.resolve("rich-real.elf")
            Files.move(symlinked.richArtifact, real)
            Files.createSymbolicLink(symlinked.richArtifact, real.fileName)
            assertFailsWith<FullTreeControlException> {
                FullTreeInventoryControl.generateAndPublish(
                    symlinked.richArtifact,
                    symlinked.authenticatedScope(),
                    directory.resolve("symlink-output.json"),
                    1,
                )
            }

            val writable = createFullTreeControlFixture(directory.resolve("writable"))
            Files.setPosixFilePermissions(writable.richArtifact, PosixFilePermissions.fromString("rw-rw-r--"))
            assertFailsWith<FullTreeControlException> {
                FullTreeInventoryControl.generateAndPublish(
                    writable.richArtifact,
                    writable.authenticatedScope(),
                    directory.resolve("writable-output.json"),
                    1,
                )
            }

            val collision = createFullTreeControlFixture(directory.resolve("collision"))
            val collisionHash = fixtureSha256(collision.richArtifact)
            assertFailsWith<FullTreeControlException> {
                FullTreeInventoryControl.generateAndPublish(
                    collision.richArtifact,
                    collision.authenticatedScope(),
                    collision.richArtifact,
                    1,
                )
            }
            assertEquals(collisionHash, fixtureSha256(collision.richArtifact))

            val bounded = createFullTreeControlFixture(directory.resolve("bounded"))
            assertFailsWith<FullTreeControlException> {
                FullTreeInventoryControl.generateAndPublish(
                    bounded.richArtifact,
                    bounded.authenticatedScope(),
                    directory.resolve("byte-output.json"),
                    1,
                    FullTreeControlLimits(maximumRichArtifactBytes = Files.size(bounded.richArtifact) - 1L),
                )
            }
            assertFailsWith<FullTreeControlException> {
                FullTreeInventoryControl.generateAndPublish(
                    bounded.richArtifact,
                    bounded.authenticatedScope(),
                    directory.resolve("worker-output.json"),
                    2,
                    FullTreeControlLimits(maximumWorkers = 1),
                )
            }
            listOf(
                FullTreeControlLimits(maximumDwarfScratchBytes = 1L),
                FullTreeControlLimits(maximumDwarfMetadataBytes = 1L),
                FullTreeControlLimits(maximumDwarfParseSteps = 1L),
            ).forEachIndexed { index, limits ->
                assertFailsWith<FullTreeControlException> {
                    FullTreeInventoryControl.generateAndPublish(
                        bounded.richArtifact,
                        bounded.authenticatedScope(limits),
                        directory.resolve("dwarf-bound-output-$index.json"),
                        1,
                        limits,
                    )
                }
                assertFalse(Files.exists(directory.resolve("dwarf-bound-output-$index.json")))
            }

            val limitedScope = bounded.authenticatedScope().let { authenticated ->
                val document = authenticated.document
                val bounds = document.controlObject("bounds")
                val perShard = JsonObject(bounds.controlObject("perShard").toMutableMap().apply {
                    this["compilationUnits"] = JsonPrimitive(1)
                })
                val whole = JsonObject(bounds.controlObject("wholeRun").toMutableMap().apply {
                    this["compilationUnits"] = JsonPrimitive(1)
                })
                authenticatedScopeWithDocument(
                    authenticated,
                    JsonObject(document.toMutableMap().apply {
                        this["bounds"] = JsonObject(mapOf("perShard" to perShard, "wholeRun" to whole))
                    }),
                )
            }
            assertFailsWith<FullTreeControlException> {
                FullTreeInventoryControl.generateAndPublish(
                    bounded.richArtifact,
                    limitedScope,
                    directory.resolve("unit-output.json"),
                    1,
                )
            }
            assertNoInventoryScratch(directory)
        }

    @Test
    fun `inventory ordering follows Unicode code points rather than UTF-16 units`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("unicode"))
            val scope = fixture.authenticatedScope()
            val original = parseControlObject(fixture.inventory)
            val base = original.controlArray("units").controlObjects("units").last()
            val paths = listOf(
                "source/clang/lib/Driver/\ue000.cpp",
                "source/clang/lib/Driver/\ud83d\ude00.cpp",
            )
            val units = paths.mapIndexed { index, path ->
                JsonObject(base.toMutableMap().apply {
                    this["dwarfOffset"] = JsonPrimitive("0x${index.toString(16)}")
                    this["id"] = JsonPrimitive(FullTreeInventoryControl.compilationUnitId(path))
                    this["rawPathSha256"] = JsonPrimitive(OracleArtifacts.sha256(path.toByteArray()))
                    this["sourcePath"] = JsonPrimitive(path)
                })
            }
            val ids = units.map { it.controlString("id") }.sortedWith(FULL_TREE_CODE_POINT_ORDER)
            val document = JsonObject(original.toMutableMap().apply {
                this["counts"] = JsonObject(
                    mapOf(
                        "compilationUnits" to JsonPrimitive(2),
                        "generatedUnits" to JsonPrimitive(0),
                        "handwrittenUnits" to JsonPrimitive(2),
                        "shards" to JsonPrimitive(1),
                    ),
                )
                this["indexSha256"] = JsonPrimitive(testInventoryIndex(units))
                this["shards"] = JsonArray(
                    listOf(
                        JsonObject(
                            mapOf(
                                "id" to JsonPrimitive("clang-lib-driver"),
                                "unitIds" to JsonArray(ids.map(::JsonPrimitive)),
                            ),
                        ),
                    ),
                )
                this["units"] = JsonArray(units)
            })
            FullTreeInventoryControl.validate(document, scope)
            val reversed = JsonObject(document.toMutableMap().apply {
                val reversedUnits = units.reversed()
                this["indexSha256"] = JsonPrimitive(testInventoryIndex(reversedUnits))
                this["units"] = JsonArray(reversedUnits)
            })
            assertFailsWith<FullTreeControlException> {
                FullTreeInventoryControl.validate(reversed, scope)
            }
        }

    private fun mutateFirstUnit(document: JsonObject, field: String, value: JsonPrimitive): JsonObject {
        val units = document.controlArray("units").controlObjects("units").toMutableList()
        units[0] = JsonObject(units[0].toMutableMap().apply { this[field] = value })
        return JsonObject(document.toMutableMap().apply { this["units"] = JsonArray(units) })
    }

    private fun testInventoryIndex(units: List<JsonObject>): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("full-tree-index-v1\u0000".toByteArray(StandardCharsets.UTF_8))
        units.forEach { unit ->
            digest.update(MessageDigest.getInstance("SHA-256").digest(OracleJson.canonicalBytes(unit)))
        }
        return digest.digest().joinToString("") { byte ->
            (byte.toInt() and 0xff).toString(16).padStart(2, '0')
        }
    }

    private fun assertNoInventoryScratch(root: java.nio.file.Path) {
        val residue = Files.walk(root).use { paths ->
            paths.anyMatch { ".full-tree-inventory-scratch-" in it.fileName?.toString().orEmpty() }
        }
        assertFalse(residue, "DWARF inventory scratch was not revoked")
    }

    private companion object {
        const val FROZEN_ARTIFACT_SHA256 = "28105cb58b619f88d8718e8cf30c0c3471b7f0c8825e95e171eebc940954b859"
        const val FROZEN_INVENTORY_INDEX_SHA256 =
            "e8a49cd70bdcccfeb1d2267da4d1131b3967520620f23f2ed23608942dcbe13e"
        const val FROZEN_INVENTORY_ARTIFACT_SHA256 =
            "c47b4d68323b43873004e7a13705ab1854bce90e80efaa61a961859ade5ec963"
    }
}
