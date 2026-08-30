package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeDataTruthSqliteTest {
    @Test
    fun `frozen multi-shard truth has parity and worker deterministic bytes`() =
        inTemporaryDirectory { directory ->
            val specialParent = directory.resolve("oracle ?#% path")
            Files.createDirectories(specialParent)
            val fixture = createFixture(specialParent.resolve("fixture"))
            val serialRoot = specialParent.resolve("truth-serial")
            val parallelRoot = specialParent.resolve("truth-parallel")

            val serial = generate(fixture, serialRoot, workers = 1)
            val parallel = generate(fixture, parallelRoot, workers = 2)

            assertEquals(serial.index, parallel.index)
            assertEquals(directoryDigests(serialRoot), directoryDigests(parallelRoot))
            assertFalse(Files.exists(serialRoot.resolve(".scratch")))
            assertEquals(2, serial.partitionCount)
            assertEquals(listOf("shard-a", "shard-b"), serial.index.requiredArray("shards").objects("truth shard").map {
                it.requiredString("id")
            })
            assertEquals(expectedCounts(), serial.index.requiredObject("counts"))
            assertEquals(HISTORICAL_V16_SCOPE_SHA256, fixture.scopeSha256)
            assertEquals(
                HISTORICAL_V16_INVENTORY_INDEX_SHA256,
                fixture.inventory.requiredString("indexSha256"),
            )
            assertEquals(HISTORICAL_V16_CONFIGURATION_SHA256, FullTreeDataTruthSqlite.configurationSha256)
            assertEquals(HISTORICAL_V16_OBSERVATION_INDEX_SHA256, serial.observationIndexSha256)
            assertEquals(HISTORICAL_V16_TRUTH_INDEX_SHA256, serial.indexSha256)
            assertEquals(
                HISTORICAL_V16_TRUTH_INDEX_ARTIFACT_SHA256,
                OracleArtifacts.sha256(Files.readAllBytes(serialRoot.resolve("index.json"))),
            )
            assertEquals(HISTORICAL_V16_ARTIFACTS, frozenArtifacts(serial.index))

            val truth = readTruthDocuments(serialRoot, serial.index)
            val shardB = truth.first { it.requiredObject("shard").requiredString("id") == "shard-b" }
            val shardA = truth.first { it.requiredObject("shard").requiredString("id") == "shard-a" }
            assertEquals(1, shardB.requiredArray("globals").size)
            assertEquals(0, shardB.requiredArray("types").size)
            assertEquals(1L, shardB.requiredObject("counts").requiredLong("crossShardTypeReferences"))
            assertEquals("shard-a", shardB.requiredArray("globals").objects("truth global").single()
                .requiredObject("typeReference").requiredString("targetOwnerShardId"))
            assertEquals(CU_A, shardA.requiredArray("types").objects("truth type").single()
                .requiredString("ownerUnitId"))
            assertEquals(2, shardA.requiredArray("types").objects("truth type").single()
                .requiredArray("observationIds").size)
        }

    @Test
    fun `authenticated run index checkpoint and output mutations fail without publication`() =
        inTemporaryDirectory { directory ->
            val mutations: List<(Fixture) -> Unit> = listOf(
                { fixture ->
                    val path = fixture.observationRoot.resolve("checkpoints/shard-a.json")
                    val checkpoint = readObject(path)
                    writeCanonical(path, JsonObject(checkpoint.toMutableMap().apply {
                        this["outputSha256"] = JsonPrimitive("f".repeat(64))
                    }))
                },
                { fixture ->
                    val path = fixture.observationRoot.resolve("index.json")
                    val index = readObject(path)
                    writeCanonical(path, JsonObject(index.toMutableMap().apply {
                        this["indexSha256"] = JsonPrimitive("e".repeat(64))
                    }))
                },
                { fixture ->
                    val path = fixture.observationRoot.resolve("outputs/shard-b.json")
                    Files.write(path, Files.readAllBytes(path) + byteArrayOf(' '.code.toByte()))
                },
                { fixture ->
                    val path = fixture.observationRoot.resolve("index.json")
                    val index = readObject(path)
                    val reversed = index.requiredArray("shards").reversed()
                    val digest = MessageDigest.getInstance("SHA-256").apply {
                        update(INDEX_DOMAIN)
                        reversed.forEach { update(MessageDigest.getInstance("SHA-256").digest(OracleJson.canonicalBytes(it))) }
                    }.digest().hex()
                    writeCanonical(path, JsonObject(index.toMutableMap().apply {
                        this["indexSha256"] = JsonPrimitive(digest)
                        this["shards"] = JsonArray(reversed)
                    }))
                },
                { fixture ->
                    Files.writeString(fixture.observationRoot.resolve("outputs/stale-shard.json"), "stale")
                },
                { fixture ->
                    Files.writeString(fixture.observationRoot.resolve("unexpected.json"), "unexpected")
                },
                { fixture ->
                    val output = fixture.observationRoot.resolve("outputs/shard-a.json")
                    val target = fixture.observationRoot.parent.resolve("symlink-target.json")
                    Files.write(target, Files.readAllBytes(output))
                    Files.delete(output)
                    Files.createSymbolicLink(output, target)
                },
                { fixture ->
                    Files.delete(fixture.observationRoot.resolve("checkpoints/shard-b.json"))
                },
                { fixture ->
                    val output = fixture.observationRoot.resolve("outputs/shard-a.json")
                    val permissions = Files.getPosixFilePermissions(output).toMutableSet()
                    permissions += PosixFilePermission.GROUP_WRITE
                    Files.setPosixFilePermissions(output, permissions)
                },
            )

            mutations.forEachIndexed { index, mutate ->
                val fixture = createFixture(directory.resolve("mutation-$index"))
                mutate(fixture)
                val output = directory.resolve("rejected-$index")
                assertFailsWith<FullTreeDataTruthException> { generate(fixture, output, workers = 2) }
                assertFalse(Files.exists(output), "mutation $index published a truth directory")
            }

            val workerFixture = createFixture(directory.resolve("worker-bound"))
            val workerOutput = directory.resolve("worker-bound-output")
            assertFailsWith<FullTreeDataTruthException> { generate(workerFixture, workerOutput, workers = 3) }
            assertFalse(Files.exists(workerOutput))
        }

    @Test
    fun `scope and inventory commitments ordering ownership and counts fail closed`() =
        inTemporaryDirectory { directory ->
            val scopeFixture = createFixture(directory.resolve("scope-binding"))
            val wholeRun = scopeFixture.scope.requiredObject("bounds").requiredObject("wholeRun")
            val mutatedScope = JsonObject(scopeFixture.scope.toMutableMap().apply {
                this["bounds"] = JsonObject(scopeFixture.scope.requiredObject("bounds").toMutableMap().apply {
                    this["wholeRun"] = JsonObject(wholeRun.toMutableMap().apply {
                        this["cpuSeconds"] = JsonPrimitive(wholeRun.requiredLong("cpuSeconds") + 1L)
                    })
                })
            })
            val staleScopeOutput = directory.resolve("stale-scope-output")
            assertFailsWith<FullTreeDataTruthException> {
                generate(scopeFixture.copy(scope = mutatedScope), staleScopeOutput, workers = 1)
            }
            assertFalse(Files.exists(staleScopeOutput))

            val inventoryMutations: List<(JsonObject) -> JsonObject> = listOf(
                { inventory ->
                    val units = inventory.requiredArray("units").objects("inventory unit").toMutableList()
                    units[0] = JsonObject(units[0].toMutableMap().apply {
                        this["producerSha256"] = JsonPrimitive("7".repeat(64))
                    })
                    JsonObject(inventory.toMutableMap().apply { this["units"] = JsonArray(units) })
                },
                { inventory ->
                    JsonObject(inventory.toMutableMap().apply {
                        this["shards"] = JsonArray(inventory.requiredArray("shards").reversed())
                    })
                },
                { inventory ->
                    val shards = inventory.requiredArray("shards").objects("inventory shard").toMutableList()
                    val firstUnits = shards[0].requiredArray("unitIds")
                    val secondUnits = shards[1].requiredArray("unitIds")
                    shards[0] = JsonObject(shards[0].toMutableMap().apply { this["unitIds"] = secondUnits })
                    shards[1] = JsonObject(shards[1].toMutableMap().apply { this["unitIds"] = firstUnits })
                    JsonObject(inventory.toMutableMap().apply { this["shards"] = JsonArray(shards) })
                },
                { inventory ->
                    val reversed = JsonArray(inventory.requiredArray("units").reversed())
                    rebindInventoryIndex(JsonObject(inventory.toMutableMap().apply { this["units"] = reversed }))
                },
                { inventory ->
                    JsonObject(inventory.toMutableMap().apply {
                        this["counts"] = JsonObject(inventory.requiredObject("counts").toMutableMap().apply {
                            this["generatedUnits"] = JsonPrimitive(1)
                            this["handwrittenUnits"] = JsonPrimitive(1)
                        })
                    })
                },
            )
            inventoryMutations.forEachIndexed { index, mutate ->
                val fixture = createFixture(directory.resolve("inventory-binding-$index"))
                val output = directory.resolve("inventory-binding-output-$index")
                assertFailsWith<FullTreeDataTruthException> {
                    generate(fixture.copy(inventory = mutate(fixture.inventory)), output, workers = 1)
                }
                assertFalse(Files.exists(output), "inventory mutation $index published data truth")
            }
        }

    @Test
    fun `cross-shard duplicate identities offsets and dangling references fail closed`() =
        inTemporaryDirectory { directory ->
            val variants = listOf(
                FixtureOptions(duplicateObservationId = true),
                FixtureOptions(duplicateDieOffset = true),
                FixtureOptions(danglingReference = true),
            )
            variants.forEachIndexed { index, options ->
                val fixture = createFixture(directory.resolve("semantic-$index"), options)
                val output = directory.resolve("semantic-output-$index")
                assertFailsWith<FullTreeDataTruthException> { generate(fixture, output, workers = 2) }
                assertFalse(Files.exists(output), "semantic mutation $index published a truth directory")
            }
        }

    @Test
    fun `control input scratch population and partition bounds are enforced`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("bounded"))
            val runBytes = Files.size(fixture.observationRoot.resolve("run.json"))
            val largestObservation = listOf("shard-a", "shard-b").maxOf {
                Files.size(fixture.observationRoot.resolve("outputs/$it.json"))
            }
            val variants = listOf(
                FullTreeDataTruthGenerationLimits(maximumControlArtifactBytes = (runBytes - 1L).toInt()),
                FullTreeDataTruthGenerationLimits(maximumObservationInputBytes = largestObservation - 1L),
                FullTreeDataTruthGenerationLimits(maximumMergePopulationEntities = 1),
                FullTreeDataTruthGenerationLimits(maximumPartitions = 1),
                FullTreeDataTruthGenerationLimits(
                    maximumObservationDatabaseBytes = 1024L * 1024L,
                    maximumScratchDatabaseBytes = 1024L * 1024L,
                    maximumScratchBytes = 1024L * 1024L + 2L * 4096L,
                ),
            )
            variants.forEachIndexed { index, limits ->
                val output = directory.resolve("bounded-output-$index")
                assertFailsWith<FullTreeDataTruthException> {
                    generate(fixture, output, workers = 2, limits = limits)
                }
                assertFalse(Files.exists(output), "bound $index published a truth directory")
            }

            val countFixture = createFixture(
                directory.resolve("count-bound"),
                FixtureOptions(wholeRunEntities = 3L),
            )
            val countOutput = directory.resolve("count-bound-output")
            assertFailsWith<FullTreeDataTruthException> { generate(countFixture, countOutput, workers = 1) }
            assertFalse(Files.exists(countOutput))

            val residentFixture = createFixture(
                directory.resolve("resident-bound"),
                FixtureOptions(maximumResidentBytes = 64L * 1024L * 1024L),
            )
            val residentOutput = directory.resolve("resident-bound-output")
            assertFailsWith<FullTreeDataTruthException> { generate(residentFixture, residentOutput, workers = 2) }
            assertFalse(Files.exists(residentOutput))
        }

    @Test
    fun `truth entities partition deterministically at the historical two-thirds byte budget`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(
                directory.resolve("partitioned"),
                FixtureOptions(perShardSerializedBytes = 2_000L, wholeRunSerializedBytes = 10_000L),
            )
            val output = directory.resolve("partitioned-output")
            val result = generate(fixture, output, workers = 2)
            val records = result.index.requiredArray("shards").objects("truth shard")
            val shardA = records.filter { it.requiredString("id") == "shard-a" }

            assertTrue(shardA.size > 1)
            assertEquals(
                shardA.indices.map { "shards/shard-a.part-${it.toString().padStart(3, '0')}.json" },
                shardA.map { it.requiredString("path") },
            )
            shardA.forEachIndexed { index, record ->
                val document = readObject(output.resolve(record.requiredString("path")))
                assertEquals(index.toLong(), document.requiredObject("shard").requiredObject("partition").requiredLong("index"))
                assertEquals(shardA.size.toLong(), document.requiredObject("shard").requiredObject("partition").requiredLong("total"))
                assertTrue(record.requiredLong("bytes") <= 2_000L)
            }
        }

    private fun generate(
        fixture: Fixture,
        output: Path,
        workers: Int,
        limits: FullTreeDataTruthGenerationLimits = FullTreeDataTruthGenerationLimits(),
    ): FullTreeDataTruthGeneration = FullTreeDataTruthSqlite.generate(
        scope = fixture.scope,
        scopeSha256 = fixture.scopeSha256,
        inventory = fixture.inventory,
        observationRoot = fixture.observationRoot,
        outputRoot = output,
        maximumWorkers = workers,
        limits = limits,
    )

    private fun createFixture(
        root: Path,
        options: FixtureOptions = FixtureOptions(),
    ): Fixture {
        Files.createDirectories(root.resolve("outputs"))
        Files.createDirectories(root.resolve("checkpoints"))
        val scope = scope(options)
        val scopeSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(scope))
        val inventory = inventory(scopeSha256)
        val inputs = FullTreeDataObservations.shardInputs(inventory, scopeSha256, RICH_SHA256)
            .sortedBy { it.identifier }
        val run = observationRun(scope, scopeSha256, inputs)
        val runBytes = OracleJson.canonicalBytes(run)
        val runSha256 = OracleArtifacts.sha256(runBytes)
        Files.write(root.resolve("run.json"), runBytes)
        val checkpoints = inputs.mapIndexed { index, input ->
            val document = observationDocument(input, index, scope, scopeSha256, inventory, options)
            FullTreeDataObservations.validateShard(document, scope, scopeSha256, inventory, input)
            val outputBytes = OracleJson.canonicalBytes(document)
            Files.write(root.resolve("outputs/${input.identifier}.json"), outputBytes)
            JsonObject(
                mapOf(
                    "entities" to JsonPrimitive(2),
                    "inputSha256" to JsonPrimitive(input.inputSha256),
                    "outputBytes" to JsonPrimitive(outputBytes.size),
                    "outputSha256" to JsonPrimitive(OracleArtifacts.sha256(outputBytes)),
                    "runSha256" to JsonPrimitive(runSha256),
                    "schemaVersion" to JsonPrimitive(1),
                    "shardId" to JsonPrimitive(input.identifier),
                    "status" to JsonPrimitive("complete"),
                ),
            ).also { checkpoint ->
                writeCanonical(root.resolve("checkpoints/${input.identifier}.json"), checkpoint)
            }
        }
        val indexDigest = MessageDigest.getInstance("SHA-256").apply {
            update(INDEX_DOMAIN)
            checkpoints.forEach { checkpoint ->
                update(MessageDigest.getInstance("SHA-256").digest(OracleJson.canonicalBytes(checkpoint)))
            }
        }.digest().hex()
        val outputBytes = checkpoints.sumOf { it.requiredLong("outputBytes") }
        val index = JsonObject(
            mapOf(
                "complete" to JsonPrimitive(true),
                "counts" to JsonObject(
                    mapOf(
                        "entities" to JsonPrimitive(4),
                        "serializedBytes" to JsonPrimitive(outputBytes),
                        "shards" to JsonPrimitive(2),
                    ),
                ),
                "indexSha256" to JsonPrimitive(indexDigest),
                "runSha256" to JsonPrimitive(runSha256),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(checkpoints),
            ),
        )
        writeCanonical(root.resolve("index.json"), index)
        return Fixture(scope, scopeSha256, inventory, root.toAbsolutePath().normalize())
    }

    private fun observationRun(
        scope: JsonObject,
        scopeSha256: String,
        inputs: List<FullTreeDataObservationShardInput>,
    ): JsonObject {
        val perShard = scope.requiredObject("bounds").requiredObject("perShard")
        val wholeRun = scope.requiredObject("bounds").requiredObject("wholeRun")
        return JsonObject(
            mapOf(
                "bounds" to JsonObject(
                    mapOf(
                        "maximumResidentBytes" to wholeRun.requiredElement("maximumResidentBytes"),
                        "maximumShards" to JsonPrimitive(inputs.size),
                        "maximumWorkers" to JsonPrimitive(2),
                        "perShardBytes" to perShard.requiredElement("serializedBytes"),
                        "perShardCpuSeconds" to perShard.requiredElement("cpuSeconds"),
                        "perShardEntities" to perShard.requiredElement("entities"),
                        "perShardSeconds" to perShard.requiredElement("wallClockSeconds"),
                        "wholeRunBytes" to wholeRun.requiredElement("serializedBytes"),
                        "wholeRunCpuSeconds" to wholeRun.requiredElement("cpuSeconds"),
                        "wholeRunEntities" to wholeRun.requiredElement("entities"),
                        "wholeRunSeconds" to wholeRun.requiredElement("wallClockSeconds"),
                    ),
                ),
                "id" to JsonPrimitive("full-tree-data-${scopeSha256.take(16)}"),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(inputs.map { input ->
                    JsonObject(
                        mapOf(
                            "id" to JsonPrimitive(input.identifier),
                            "inputSha256" to JsonPrimitive(input.inputSha256),
                        ),
                    )
                }),
            ),
        )
    }

    private fun observationDocument(
        input: FullTreeDataObservationShardInput,
        index: Int,
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        options: FixtureOptions,
    ): JsonObject {
        val unitId = if (index == 0) CU_A else CU_B
        val typeOffset = if (index == 1 && !options.duplicateDieOffset) "0x31" else "0x30"
        val targetOffset = if (index == 1 && options.danglingReference) "0x99" else typeOffset
        val globalId = if (index == 1 && options.duplicateObservationId) {
            "global-observation-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        } else {
            "global-observation-${(if (index == 0) "a" else "c").repeat(32)}"
        }
        val typeId = "type-observation-${(if (index == 0) "b" else "d").repeat(32)}"
        val bindings = FullTreeDataObservations.authenticatedBindings(scope, scopeSha256, inventory, input)
        val declaration = JsonObject(
            mapOf(
                "column" to JsonPrimitive(1),
                "externalPathSha256" to JsonNull,
                "line" to JsonPrimitive(4),
                "sourcePath" to JsonPrimitive("source/shared.h"),
            ),
        )
        val global = JsonObject(
            mapOf(
                "addressRva" to JsonPrimitive(if (index == 0) "0x40" else "0x50"),
                "alignment" to JsonPrimitive(8),
                "declaration" to declaration,
                "dieOffset" to JsonPrimitive(if (index == 0) "0x11" else "0x21"),
                "external" to JsonPrimitive(true),
                "id" to JsonPrimitive(globalId),
                "mutability" to JsonPrimitive("mutable"),
                "names" to JsonArray(listOf(JsonPrimitive(if (index == 0) "global_a" else "global_b"))),
                "reasonCode" to JsonNull,
                "size" to JsonPrimitive(8),
                "tls" to JsonPrimitive(false),
                "typeReference" to JsonArray(
                    listOf(
                        JsonPrimitive(if (index == 0) "0x12" else "0x22"),
                        JsonPrimitive(targetOffset),
                        JsonArray(emptyList()),
                        JsonNull,
                    ),
                ),
                "unitId" to JsonPrimitive(unitId),
                "visibility" to JsonPrimitive("default"),
            ),
        )
        val type = JsonObject(
            mapOf(
                "alignment" to JsonPrimitive(8),
                "byteSize" to JsonPrimitive(16),
                "context" to JsonArray(listOf(JsonPrimitive("DW_TAG_namespace:sample"))),
                "declaration" to declaration,
                "declarationOnly" to JsonPrimitive(false),
                "dieOffset" to JsonPrimitive(typeOffset),
                "id" to JsonPrimitive(typeId),
                "members" to JsonArray(emptyList()),
                "name" to JsonPrimitive("Shared"),
                "tag" to JsonPrimitive("struct"),
                "unitId" to JsonPrimitive(unitId),
            ),
        )
        return JsonObject(
            mapOf(
                "counts" to JsonObject(
                    mapOf(
                        "bases" to JsonPrimitive(0),
                        "enumerators" to JsonPrimitive(0),
                        "fields" to JsonPrimitive(0),
                        "globals" to JsonPrimitive(1),
                        "scannedDies" to JsonPrimitive(2),
                        "types" to JsonPrimitive(1),
                        "units" to JsonPrimitive(1),
                    ),
                ),
                "globals" to JsonArray(listOf(global)),
                "oracle" to bindings.oracle,
                "schemaVersion" to JsonPrimitive(1),
                "shard" to bindings.shard,
                "types" to JsonArray(listOf(type)),
            ),
        )
    }

    private fun scope(options: FixtureOptions): JsonObject {
        fun bounds(units: Long, entities: Long, bytes: Long): JsonObject = JsonObject(
            mapOf(
                "compilationUnits" to JsonPrimitive(units),
                "cpuSeconds" to JsonPrimitive(120),
                "entities" to JsonPrimitive(entities),
                "maximumResidentBytes" to JsonPrimitive(options.maximumResidentBytes),
                "serializedBytes" to JsonPrimitive(bytes),
                "wallClockSeconds" to JsonPrimitive(120),
            ),
        )
        return JsonObject(
            mapOf(
                "bounds" to JsonObject(
                    mapOf(
                        "perShard" to bounds(1, options.perShardEntities, options.perShardSerializedBytes),
                        "wholeRun" to bounds(2, options.wholeRunEntities, options.wholeRunSerializedBytes),
                    ),
                ),
                "oracle" to JsonObject(
                    mapOf(
                        "artifactManifestSha256" to JsonPrimitive(ARTIFACT_MANIFEST_SHA256),
                        "id" to JsonPrimitive("fixture"),
                        "richArtifactSha256" to JsonPrimitive(RICH_SHA256),
                        "sourceLockSha256" to JsonPrimitive(SOURCE_LOCK_SHA256),
                        "strippedArtifactSha256" to JsonPrimitive(STRIPPED_SHA256),
                    ),
                ),
                "pathPolicy" to JsonObject(
                    mapOf(
                        "prefixMaps" to JsonArray(listOf(JsonObject(mapOf(
                            "from" to JsonPrimitive("/src/"),
                            "to" to JsonPrimitive("source/"),
                        )))),
                    ),
                ),
                "populations" to JsonObject(
                    mapOf(
                        "excluded" to JsonPrimitive("entities matching one reviewed exclusion record and no scored record"),
                        "exclusions" to JsonArray(emptyList()),
                        "scored" to JsonPrimitive("emitted ELF entities with independently source-aligned DWARF ownership"),
                        "unobservable" to JsonPrimitive("authenticated source or DWARF entities without an emitted address"),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "sharding" to JsonObject(
                    mapOf(
                        "duplicateOwnership" to JsonPrimitive(
                            "lowest-source-aligned-unit-id; aliases remain evidence on one emitted RVA",
                        ),
                        "mergeOrdering" to JsonPrimitive("shard-id,source-path,unit-id,entity-kind,entity-id"),
                        "rules" to JsonArray(listOf(JsonObject(mapOf(
                            "componentDepth" to JsonPrimitive(0),
                            "pathPrefix" to JsonPrimitive("source/"),
                            "shardPrefix" to JsonPrimitive("shard"),
                        )))),
                    ),
                ),
            ),
        )
    }

    private fun inventory(scopeSha256: String): JsonObject {
        fun unit(shard: String, source: String, offset: String): JsonObject = JsonObject(
            mapOf(
                "addressSize" to JsonPrimitive(8),
                "dwarfOffset" to JsonPrimitive(offset),
                "dwarfVersion" to JsonPrimitive(5),
                "id" to JsonPrimitive(compilationUnitId(source)),
                "language" to JsonPrimitive(29),
                "producerSha256" to JsonPrimitive("9".repeat(64)),
                "rawPathSha256" to JsonPrimitive("8".repeat(64)),
                "shardId" to JsonPrimitive(shard),
                "sourceKind" to JsonPrimitive("handwritten"),
                "sourcePath" to JsonPrimitive(source),
            ),
        )
        fun shard(id: String, unit: String): JsonObject = JsonObject(
            mapOf("id" to JsonPrimitive(id), "unitIds" to JsonArray(listOf(JsonPrimitive(unit)))),
        )
        val units = listOf(
            unit("shard-a", SOURCE_A, "0x10"),
            unit("shard-b", SOURCE_B, "0x20"),
        )
        val inventoryIndexSha256 = MessageDigest.getInstance("SHA-256").apply {
            update(INVENTORY_INDEX_DOMAIN)
            units.forEach { unit ->
                update(MessageDigest.getInstance("SHA-256").digest(OracleJson.canonicalBytes(unit)))
            }
        }.digest().hex()
        return JsonObject(
            mapOf(
                "counts" to JsonObject(
                    mapOf(
                        "compilationUnits" to JsonPrimitive(2),
                        "generatedUnits" to JsonPrimitive(0),
                        "handwrittenUnits" to JsonPrimitive(2),
                        "shards" to JsonPrimitive(2),
                    ),
                ),
                "indexSha256" to JsonPrimitive(inventoryIndexSha256),
                "oracle" to JsonObject(
                    mapOf(
                        "artifactManifestSha256" to JsonPrimitive(ARTIFACT_MANIFEST_SHA256),
                        "id" to JsonPrimitive("fixture"),
                        "richArtifactSha256" to JsonPrimitive(RICH_SHA256),
                        "scopeSha256" to JsonPrimitive(scopeSha256),
                        "sourceLockSha256" to JsonPrimitive(SOURCE_LOCK_SHA256),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(listOf(shard("shard-a", CU_A), shard("shard-b", CU_B))),
                "units" to JsonArray(units),
            ),
        )
    }

    private fun rebindInventoryIndex(inventory: JsonObject): JsonObject {
        val digest = MessageDigest.getInstance("SHA-256").apply {
            update(INVENTORY_INDEX_DOMAIN)
            inventory.requiredArray("units").forEach { unit ->
                update(MessageDigest.getInstance("SHA-256").digest(OracleJson.canonicalBytes(unit)))
            }
        }.digest().hex()
        return JsonObject(inventory.toMutableMap().apply {
            this["indexSha256"] = JsonPrimitive(digest)
        })
    }

    private fun expectedCounts(): JsonObject = JsonObject(
        mapOf(
            "ambiguousTypeReferences" to JsonPrimitive(0),
            "bases" to JsonPrimitive(0),
            "crossShardTypeReferences" to JsonPrimitive(1),
            "enumerators" to JsonPrimitive(0),
            "fields" to JsonPrimitive(0),
            "globals" to JsonPrimitive(2),
            "resolvedTypeReferences" to JsonPrimitive(2),
            "types" to JsonPrimitive(1),
            "unobservableGlobals" to JsonPrimitive(0),
            "unobservableTypes" to JsonPrimitive(0),
            "unresolvedTypeReferences" to JsonPrimitive(0),
        ),
    )

    private fun readTruthDocuments(root: Path, index: JsonObject): List<JsonObject> =
        index.requiredArray("shards").objects("truth index shard").map { record ->
            readObject(root.resolve(record.requiredString("path")))
        }

    private fun frozenArtifacts(index: JsonObject): Map<String, String> =
        index.requiredArray("shards").objects("truth index shard").associate { record ->
            record.requiredString("path") to "${record.requiredLong("bytes")}:${record.requiredString("sha256")}"
        }

    private fun directoryDigests(root: Path): Map<String, String> = Files.walk(root).use { paths ->
        paths.filter { Files.isRegularFile(it) }.sorted().toList().associate { path ->
            root.relativize(path).toString() to OracleArtifacts.sha256(Files.readAllBytes(path))
        }
    }

    private fun readObject(path: Path): JsonObject = OracleJson.parseCanonical(Files.readAllBytes(path)) as JsonObject

    private fun writeCanonical(path: Path, document: JsonElement) {
        Files.write(path, OracleJson.canonicalBytes(document))
    }

    private fun ByteArray.hex(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    private fun <T> inTemporaryDirectory(action: (Path) -> T): T {
        val directory = createTempDirectory("data-truth-sqlite-").toAbsolutePath().normalize()
        return try {
            action(directory)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private data class Fixture(
        val scope: JsonObject,
        val scopeSha256: String,
        val inventory: JsonObject,
        val observationRoot: Path,
    )

    private data class FixtureOptions(
        val duplicateObservationId: Boolean = false,
        val duplicateDieOffset: Boolean = false,
        val danglingReference: Boolean = false,
        val perShardEntities: Long = 100L,
        val perShardSerializedBytes: Long = 64L * 1024L,
        val wholeRunSerializedBytes: Long = 256L * 1024L,
        val wholeRunEntities: Long = 100L,
        val maximumResidentBytes: Long = 2L * 1024L * 1024L * 1024L,
    )

    private companion object {
        private fun compilationUnitId(sourcePath: String): String =
            "cu-${OracleArtifacts.sha256(sourcePath.toByteArray(StandardCharsets.UTF_8)).take(32)}"

        val INDEX_DOMAIN: ByteArray = "bounded-shards-v1\u0000".toByteArray(StandardCharsets.UTF_8)
        val INVENTORY_INDEX_DOMAIN: ByteArray = "full-tree-index-v1\u0000".toByteArray(StandardCharsets.UTF_8)
        const val SOURCE_A = "source/aaa.c"
        const val SOURCE_B = "source/bbb.c"
        val CU_A: String = compilationUnitId(SOURCE_A)
        val CU_B: String = compilationUnitId(SOURCE_B)
        const val RICH_SHA256 = "3333333333333333333333333333333333333333333333333333333333333333"
        const val STRIPPED_SHA256 = "4444444444444444444444444444444444444444444444444444444444444444"
        const val SOURCE_LOCK_SHA256 = "5555555555555555555555555555555555555555555555555555555555555555"
        const val ARTIFACT_MANIFEST_SHA256 = "6666666666666666666666666666666666666666666666666666666666666666"
        // One-time differential values from the checked-in historical v16 implementation using this
        // schema-valid fixture. Python is not invoked by this test or by production Kotlin authority.
        const val HISTORICAL_V16_SCOPE_SHA256 =
            "4b70c89f14a9a96567e4d3297a080fcfa4327c00e08ad6f471172e472db9731c"
        const val HISTORICAL_V16_INVENTORY_INDEX_SHA256 =
            "b4d12ad9da7af1ab92d4e82e89b1a30a8244f62613241e86b63a15b79e3f6a35"
        const val HISTORICAL_V16_CONFIGURATION_SHA256 =
            "90dd097ba542bc5297b37277125ce01e73355fe0e4cea3117b3240315fff5a5b"
        const val HISTORICAL_V16_OBSERVATION_INDEX_SHA256 =
            "4397cc3acf74df1dfebe4b91321efb77bc138dd4924903cceb99621b7a7f84e8"
        const val HISTORICAL_V16_TRUTH_INDEX_SHA256 =
            "82d24fc54a24fecdeb53993945def767221649816d14b43efa0db55e9f15133c"
        const val HISTORICAL_V16_TRUTH_INDEX_ARTIFACT_SHA256 =
            "50f7906f2bef885c89b967ea8f2e6f16e145aeee84e79ae7d5ee561c9cfa0968"
        val HISTORICAL_V16_ARTIFACTS = mapOf(
            "shards/shard-b.json" to
                "1861:11cf049478c9630632c6cc8e523ab952823c878911828ff2310c330dc1143755",
            "shards/shard-a.json" to
                "2551:25e3ecbeeadd63241b2376101f45920e333d030e231b16526bdac1ba2cfad834",
        )
    }
}
