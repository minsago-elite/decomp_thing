package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeFunctionTruthSqliteTest {
    @Test
    fun `artifact-backed truth is worker deterministic bounded and non-authoritative`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFunctionTruthFixture(root.resolve("authenticated ?#% inputs"))
            val serial = generateTruth(fixture, root.resolve("truth-serial"), maximumWorkers = 2)
            val cappedParallel = generateTruth(fixture, root.resolve("truth-capped-parallel"), maximumWorkers = 4)

            assertEquals(FROZEN_CONFIGURATION_SHA256, FullTreeFunctionTruthSqlite.configurationSha256)
            assertEquals(serial.index, cappedParallel.index)
            assertEquals(
                truthTreeBytes(serial.root),
                truthTreeBytes(cappedParallel.root),
            )
            assertEquals(serial.indexArtifactSha256, cappedParallel.indexArtifactSha256)
            assertEquals(serial.indexSha256, cappedParallel.indexSha256)
            assertEquals(serial.counts, cappedParallel.counts)
            assertFrozenRawV2Truth(serial.root)
            assertFalse(serial.authoritativeReleaseEvidence)
            assertFalse(cappedParallel.authoritativeReleaseEvidence)
            assertTrue(serial.databaseHighWaterBytes > 0L)
            assertTruthPublication(serial, fixture)
            assertTruthPublication(cappedParallel, fixture)
            assertDirectoryEmpty(fixture.scratch)
            assertNoTruthResidue(root)

            val occupied = root.resolve("occupied-truth")
            val sentinel = "preserve existing truth target\n".toByteArray()
            Files.write(occupied, sentinel)
            Files.setPosixFilePermissions(occupied, PosixFilePermissions.fromString("rw-------"))
            assertFailsWith<FullTreeFunctionTruthException> {
                generateTruth(fixture, occupied, maximumWorkers = 2)
            }
            assertContentEquals(sentinel, Files.readAllBytes(occupied))
            assertDirectoryEmpty(fixture.scratch)
            assertNoTruthResidue(root)
        }

    @Test
    fun `resident model cannot understate configured merge structures`() {
        assertFailsWith<IllegalArgumentException> {
            FullTreeFunctionTruthLimits(modeledResidentBytes = 1L)
        }
        assertFailsWith<IllegalArgumentException> {
            FullTreeFunctionTruthLimits(
                maximumEntityBytes = 64 * 1024 * 1024,
                maximumSqliteCacheBytes = 64 * 1024 * 1024,
                modeledResidentBytes = 256L * 1024L * 1024L,
            )
        }
        assertEquals(256L * 1024L * 1024L, FullTreeFunctionTruthLimits().modeledResidentBytes)
    }

    @Test
    fun `run substitutions bounds overlaps and embedded members fail without publication`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFunctionTruthFixture(root.resolve("mutations"))

            val wrongDigestOutput = root.resolve("wrong-digest-output")
            assertFailsWith<FullTreeFunctionTruthException> {
                FullTreeFunctionTruthSqlite.generateAndPublish(
                    richArtifact = fixture.rich,
                    strippedArtifact = fixture.stripped,
                    inventoryPath = fixture.inventoryPath,
                    elfFunctionIndex = fixture.elfIndex,
                    observationRoot = fixture.observationRoot,
                    expectedObservationIndexArtifactSha256 = "f".repeat(64),
                    scope = fixture.scope,
                    scratchParent = fixture.scratch,
                    outputRoot = wrongDigestOutput,
                    maximumWorkers = 2,
                )
            }
            assertFalse(Files.exists(wrongDigestOutput, LinkOption.NOFOLLOW_LINKS))

            val overlapOutput = fixture.scratch.resolve("overlapping-output")
            assertFailsWith<FullTreeFunctionTruthException> {
                generateTruth(fixture, overlapOutput, maximumWorkers = 2)
            }
            assertFalse(Files.exists(overlapOutput, LinkOption.NOFOLLOW_LINKS))

            val boundedOutput = root.resolve("bounded-output")
            assertFailsWith<FullTreeFunctionTruthException> {
                generateTruth(
                    fixture,
                    boundedOutput,
                    maximumWorkers = 2,
                    limits = FullTreeFunctionTruthLimits(maximumOutputBytes = 256),
                )
            }
            assertFalse(Files.exists(boundedOutput, LinkOption.NOFOLLOW_LINKS))
            assertDirectoryEmpty(fixture.scratch)

            Files.setPosixFilePermissions(
                fixture.observationRoot,
                PosixFilePermissions.fromString("rwx------"),
            )
            val extra = fixture.observationRoot.resolve("execution-evidence.json")
            Files.write(extra, "{}\n".toByteArray())
            Files.setPosixFilePermissions(extra, PosixFilePermissions.fromString("r--------"))
            Files.setPosixFilePermissions(
                fixture.observationRoot,
                PosixFilePermissions.fromString("r-x------"),
            )
            val embeddedOutput = root.resolve("embedded-output")
            assertFailsWith<FullTreeFunctionTruthException> {
                generateTruth(fixture, embeddedOutput, maximumWorkers = 2)
            }
            assertFalse(Files.exists(embeddedOutput, LinkOption.NOFOLLOW_LINKS))
            assertDirectoryEmpty(fixture.scratch)

            val wrongRun = createFunctionTruthFixture(
                root.resolve("wrong-run"),
                runIdOverride = "full-tree-functions-${"0".repeat(16)}",
            )
            val wrongRunOutput = root.resolve("wrong-run-output")
            assertFailsWith<FullTreeFunctionTruthException> {
                generateTruth(wrongRun, wrongRunOutput, maximumWorkers = 2)
            }
            assertFalse(Files.exists(wrongRunOutput, LinkOption.NOFOLLOW_LINKS))
            assertDirectoryEmpty(wrongRun.scratch)

            val wrongWorkers = createFunctionTruthFixture(
                root.resolve("wrong-workers"),
                observationWorkers = 1,
            )
            val wrongWorkersOutput = root.resolve("wrong-workers-output")
            assertFailsWith<FullTreeFunctionTruthException> {
                generateTruth(wrongWorkers, wrongWorkersOutput, maximumWorkers = 2)
            }
            assertFalse(Files.exists(wrongWorkersOutput, LinkOption.NOFOLLOW_LINKS))
            assertDirectoryEmpty(wrongWorkers.scratch)
            assertNoTruthResidue(root)
        }
}

private data class FunctionTruthFixture(
    val rich: Path,
    val stripped: Path,
    val inventoryPath: Path,
    val inventory: JsonObject,
    val scope: AuthenticatedFullTreeScope,
    val elfIndex: Path,
    val observationRoot: Path,
    val observationIndexArtifactSha256: String,
    val scratch: Path,
)

private fun createFunctionTruthFixture(
    root: Path,
    observationWorkers: Int = 2,
    runIdOverride: String? = null,
): FunctionTruthFixture {
    Files.createDirectories(root)
    Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
    val control = createFullTreeControlFixture(root.resolve("control"))
    val original = control.authenticatedScope()
    val richBytes = Base64.getMimeDecoder().decode(fullTreeControlResource("rich.elf.b64"))
    val strippedBytes = richBytes.copyOf()
    val rich = writeElf(root.resolve("rich-input.elf"), richBytes)
    val stripped = writeElf(root.resolve("stripped-input.elf"), strippedBytes)
    val originalArtifacts = original.artifactManifest.controlObject("artifacts")
    val originalFull = originalArtifacts.controlObject("full")

    fun reboundArtifact(originalArtifact: JsonObject, bytes: ByteArray): JsonObject = JsonObject(
        originalArtifact.toMutableMap().apply {
            this["bytes"] = JsonPrimitive(bytes.size)
            this["sha256"] = JsonPrimitive(OracleArtifacts.sha256(bytes))
        },
    )

    val manifest = JsonObject(
        original.artifactManifest.toMutableMap().apply {
            this["artifacts"] = JsonObject(
                mapOf(
                    "full" to reboundArtifact(originalFull, richBytes),
                    "stripped" to reboundArtifact(
                        originalArtifacts.controlObject("stripped"),
                        strippedBytes,
                    ),
                ),
            )
        },
    )
    val manifestSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(manifest))
    val scopeDocument = JsonObject(
        original.document.toMutableMap().apply {
            this["oracle"] = JsonObject(
                original.document.controlObject("oracle").toMutableMap().apply {
                    this["artifactManifestSha256"] = JsonPrimitive(manifestSha256)
                    this["richArtifactSha256"] = JsonPrimitive(OracleArtifacts.sha256(richBytes))
                    this["strippedArtifactSha256"] = JsonPrimitive(OracleArtifacts.sha256(strippedBytes))
                },
            )
        },
    )
    val scopeSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(scopeDocument))
    val scope = AuthenticatedFullTreeScope(
        document = scopeDocument,
        sha256 = scopeSha256,
        sourceLock = original.sourceLock,
        sourceLockSha256 = original.sourceLockSha256,
        artifactManifest = manifest,
        artifactManifestSha256 = manifestSha256,
    )
    val originalInventory = parseControlObject(control.inventory)
    val inventory = JsonObject(
        originalInventory.toMutableMap().apply {
            this["oracle"] = JsonObject(
                originalInventory.controlObject("oracle").toMutableMap().apply {
                    this["artifactManifestSha256"] = JsonPrimitive(manifestSha256)
                    this["richArtifactSha256"] = JsonPrimitive(OracleArtifacts.sha256(richBytes))
                    this["scopeSha256"] = JsonPrimitive(scopeSha256)
                },
            )
        },
    )
    val inventoryPath = root.resolve("inventory.json")
    writeControlObject(inventoryPath, inventory)
    FullTreeScopeControl.validate(scope)
    FullTreeInventoryControl.loadAndValidate(inventoryPath, scope)

    val elfDirectory = privateTruthDirectory(root.resolve("elf"))
    val elfIndex = elfDirectory.resolve("functions.json")
    FullTreeElfFunctionsSqlite.generateAndPublish(
        richArtifact = rich,
        strippedArtifact = stripped,
        scope = scope,
        inventory = inventory,
        output = elfIndex,
        maximumWorkers = 2,
    )

    val scratch = privateTruthDirectory(root.resolve("scratch"))
    val preparedDirectory = privateTruthDirectory(root.resolve("prepared-observations"))
    val inventoryArtifactSha256 = OracleArtifacts.sha256(Files.readAllBytes(inventoryPath))
    val inputs = FullTreeFunctionObservations.shardInputs(
        inventory,
        inventoryArtifactSha256,
        scope.document,
        scope.sha256,
    )
    val prepared = inputs.map { input ->
        val output = preparedDirectory.resolve("${input.identifier}.json")
        val receipt = FullTreeFunctionObservationShardPublisher.generateAndPublish(
            richArtifact = rich,
            inventoryPath = inventoryPath,
            scope = scope,
            shardId = input.identifier,
            scratchParent = scratch,
            output = output,
        )
        BoundedShardPreparedOutput(
            shardId = input.identifier,
            inputSha256 = input.inputSha256,
            output = output,
            outputSha256 = receipt.outputSha256,
            outputBytes = receipt.outputBytes,
            entities = receipt.entities,
        )
    }
    val perShard = scope.document.controlObject("bounds").controlObject("perShard")
    val wholeRun = scope.document.controlObject("bounds").controlObject("wholeRun")
    val observationRoot = root.resolve("observations")
    val run = BoundedShardRunPublisher.publish(
        target = observationRoot,
        runId = runIdOverride ?: "full-tree-functions-${scope.sha256.take(16)}",
        preparedOutputs = prepared,
        bounds = BoundedShardRunPublicationBounds(
            maximumShards = inputs.size,
            perShardEntities = perShard.controlLong("entities"),
            wholeRunEntities = wholeRun.controlLong("entities"),
            perShardBytes = perShard.controlLong("serializedBytes"),
            wholeRunBytes = wholeRun.controlLong("serializedBytes"),
            perShardSeconds = perShard.controlLong("wallClockSeconds").toDouble(),
            wholeRunSeconds = wholeRun.controlLong("wallClockSeconds").toDouble(),
            perShardCpuSeconds = perShard.controlLong("cpuSeconds").toDouble(),
            wholeRunCpuSeconds = wholeRun.controlLong("cpuSeconds").toDouble(),
            maximumResidentBytes = wholeRun.controlLong("maximumResidentBytes"),
            maximumWorkers = observationWorkers,
        ),
        semanticValidator = BoundedShardOutputSemanticValidator { validation ->
            val receipt = FullTreeFunctionObservationShardPublisher.loadAndValidate(
                candidate = validation.output,
                richArtifact = rich,
                inventoryPath = inventoryPath,
                scope = scope,
                shardId = validation.shardId,
                scratchParent = scratch,
            )
            assertEquals(validation.inputSha256, receipt.inputSha256)
            assertEquals(validation.outputSha256, receipt.outputSha256)
            assertEquals(validation.outputBytes, receipt.outputBytes)
            assertEquals(validation.entities, receipt.entities)
        },
    )
    assertDirectoryEmpty(scratch)
    return FunctionTruthFixture(
        rich,
        stripped,
        inventoryPath,
        inventory,
        scope,
        elfIndex,
        observationRoot,
        run.indexArtifactSha256,
        scratch,
    )
}

private fun generateTruth(
    fixture: FunctionTruthFixture,
    output: Path,
    maximumWorkers: Int,
    limits: FullTreeFunctionTruthLimits = FullTreeFunctionTruthLimits(),
): FullTreeFunctionTruthGeneration = FullTreeFunctionTruthSqlite.generateAndPublish(
    richArtifact = fixture.rich,
    strippedArtifact = fixture.stripped,
    inventoryPath = fixture.inventoryPath,
    elfFunctionIndex = fixture.elfIndex,
    observationRoot = fixture.observationRoot,
    expectedObservationIndexArtifactSha256 = fixture.observationIndexArtifactSha256,
    scope = fixture.scope,
    scratchParent = fixture.scratch,
    outputRoot = output,
    maximumWorkers = maximumWorkers,
    limits = limits,
)

private fun assertTruthPublication(
    generation: FullTreeFunctionTruthGeneration,
    fixture: FunctionTruthFixture,
) {
    val root = generation.root
    assertEquals(
        setOf("exclusions.json", "index.json", "shards"),
        Files.list(root).use { paths -> paths.map { it.fileName.toString() }.toList().toSet() },
    )
    val expectedShardIds = fixture.inventory.controlArray("shards").map { raw ->
        (raw as JsonObject).controlString("id")
    }
    assertEquals(
        expectedShardIds.mapTo(linkedSetOf()) { "$it.json" },
        Files.list(root.resolve("shards")).use { paths ->
            paths.map { it.fileName.toString() }.toList().toSet()
        },
    )
    assertEquals(
        PosixFilePermissions.fromString("r-x------"),
        Files.getPosixFilePermissions(root, LinkOption.NOFOLLOW_LINKS),
    )
    assertEquals(
        PosixFilePermissions.fromString("r-x------"),
        Files.getPosixFilePermissions(root.resolve("shards"), LinkOption.NOFOLLOW_LINKS),
    )

    val indexBytes = Files.readAllBytes(root.resolve("index.json"))
    val index = OracleJson.parseCanonical(indexBytes, controlJsonLimits(16 * 1024 * 1024)) as JsonObject
    OracleSchemas.validate("full-tree-function-truth-index", index)
    assertEquals(generation.index, index)
    assertEquals(OracleArtifacts.sha256(indexBytes), generation.indexArtifactSha256)
    assertEquals(generation.indexSha256, index.controlString("indexSha256"))
    assertEquals(fixture.observationIndexArtifactSha256, generation.observationIndexArtifactSha256)
    assertEquals(
        OracleArtifacts.sha256(Files.readAllBytes(fixture.elfIndex)),
        generation.elfIndexArtifactSha256,
    )

    var publishedBytes = indexBytes.size.toLong()
    val indexedShards = index.controlArray("shards").map { raw -> raw as JsonObject }
    assertEquals(expectedShardIds, indexedShards.map { it.controlString("id") })
    indexedShards.forEach { record ->
        val path = root.resolve(record.controlString("path"))
        val bytes = Files.readAllBytes(path)
        val document = OracleJson.parseCanonical(bytes, controlJsonLimits(64 * 1024 * 1024))
        OracleSchemas.validate("full-tree-function-truth", document)
        assertEquals(record.controlString("sha256"), OracleArtifacts.sha256(bytes))
        assertEquals(record.controlLong("bytes"), bytes.size.toLong())
        assertEquals(
            PosixFilePermissions.fromString("r--------"),
            Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS),
        )
        publishedBytes += bytes.size.toLong()
    }
    val exclusionRecord = index.controlObject("exclusions")
    val exclusionPath = root.resolve(exclusionRecord.controlString("path"))
    val exclusionBytes = Files.readAllBytes(exclusionPath)
    val exclusions = OracleJson.parseCanonical(
        exclusionBytes,
        controlJsonLimits(64 * 1024 * 1024),
    )
    OracleSchemas.validate("full-tree-function-exclusions", exclusions)
    assertEquals(exclusionRecord.controlString("sha256"), OracleArtifacts.sha256(exclusionBytes))
    assertEquals(exclusionRecord.controlLong("bytes"), exclusionBytes.size.toLong())
    publishedBytes += exclusionBytes.size.toLong()
    assertEquals(generation.outputBytes, publishedBytes)
    listOf(root.resolve("index.json"), exclusionPath).forEach { path ->
        assertEquals(
            PosixFilePermissions.fromString("r--------"),
            Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS),
        )
    }

    val counts = index.controlObject("counts")
    assertEquals(
        counts.controlLong("elfRvas"),
        counts.controlLong("scoredRvas") + counts.controlLong("elfOnlyRvas"),
    )
    assertEquals(
        counts.controlLong("dwarfRvas"),
        counts.controlLong("scoredRvas") + counts.controlLong("dwarfOnlyRvas"),
    )
    assertEquals(
        counts.controlLong("nonEmittedUnique"),
        counts.controlLong("inlineOnlyUnique") +
            counts.controlLong("selectedElsewhereUnique") +
            counts.controlLong("definitionNoRangeUnique"),
    )
}

private fun truthTreeBytes(root: Path): Map<String, List<Byte>> = Files.walk(root).use { paths ->
    paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }
        .sorted()
        .toList()
        .associate { path -> root.relativize(path).toString() to Files.readAllBytes(path).toList() }
}

private fun assertFrozenRawV2Truth(actualRoot: Path) {
    val expectedResources = linkedMapOf(
        "exclusions.json" to "exclusions.json.b64",
        "index.json" to "index.json.b64",
        "shards/clang-lib-driver.json" to "clang-lib-driver.json.b64",
        "shards/generated-tools-clang.json" to "generated-tools-clang.json.b64",
    )
    val actualMembers = Files.walk(actualRoot).use { paths ->
        paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }
            .map { actualRoot.relativize(it).toString() }
            .toList()
            .toSet()
    }
    assertEquals(expectedResources.keys, actualMembers)
    expectedResources.forEach { (relative, resource) ->
        val encoded = checkNotNull(
            FullTreeFunctionTruthSqliteTest::class.java.getResourceAsStream(
                "/oracle/full-tree-function-truth-raw-v2/expected/$resource",
            ),
        ) { "frozen raw-path function-truth v2 fixture $resource is unavailable" }.use {
            it.readAllBytes()
        }
        assertContentEquals(
            Base64.getMimeDecoder().decode(encoded),
            Files.readAllBytes(actualRoot.resolve(relative)),
            "raw-derived Kotlin truth differs from the frozen Python-retirement bytes at $relative",
        )
    }
}

private fun privateTruthDirectory(path: Path): Path = path.also {
    Files.createDirectory(it, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
}

private fun assertDirectoryEmpty(path: Path) {
    assertEquals(emptyList(), Files.list(path).use { it.toList() })
}

private fun assertNoTruthResidue(root: Path) {
    val residue = Files.walk(root).use { paths ->
        paths.filter { path ->
            val name = path.fileName.toString()
            name.startsWith(".function-truth-") || name.contains(".function-truth-") ||
                name.contains(".elf-functions-scratch-")
        }.toList()
    }
    assertEquals(emptyList(), residue)
}

private const val FROZEN_CONFIGURATION_SHA256 =
    "17c61e43524b98a215075b82fa50732d6d8f50d883dce235e511731612da04e5"
