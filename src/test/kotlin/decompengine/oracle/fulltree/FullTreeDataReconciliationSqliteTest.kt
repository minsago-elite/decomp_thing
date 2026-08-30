package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.nio.charset.StandardCharsets
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

class FullTreeDataReconciliationSqliteTest {
    @Test
    fun `streaming reader rejects a permission mutation after speculative callbacks`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("permission-mutation"))
            var callbacks = 0
            assertFailsWith<FullTreeDataTruthException> {
                FullTreeCanonicalStreaming.readObject(
                    path = fixture.elfPath,
                    label = "permission mutation ELF index",
                    expectedSourceSha256 = fixture.elfSha256,
                    fieldOrder = listOf(
                        "artifacts",
                        "counts",
                        "externalGlobals",
                        "globals",
                        "indexSha256",
                        "oracle",
                        "schemaVersion",
                    ),
                    arrayFields = setOf("externalGlobals", "globals"),
                    omittedDigestField = "indexSha256",
                    limits = FullTreeCanonicalStreamingLimits(
                        maximumInputBytes = Files.size(fixture.elfPath),
                        maximumTokens = 1_000_000,
                        maximumEntities = 100,
                        maximumEntityBytes = 1024 * 1024,
                        maximumEntityNodes = 100_000,
                        maximumTotalStringBytes = Files.size(fixture.elfPath),
                    ),
                ) { _, _, _, _ ->
                    callbacks++
                    if (callbacks == 1) {
                        Files.setPosixFilePermissions(
                            fixture.elfPath,
                            PosixFilePermissions.fromString("rw-rw-rw-"),
                        )
                    }
                }
            }
            assertTrue(callbacks > 0)
            Files.setPosixFilePermissions(fixture.elfPath, PosixFilePermissions.fromString("rw-r--r--"))
        }

    @Test
    fun `frozen Kotlin reconciliation matches v1 semantics and worker ordering`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("authenticated ?#% fixture"))
            val serialRoot = directory.resolve("serial ?#% report")
            val parallelRoot = directory.resolve("parallel ?#% report")

            val serial = generate(fixture, serialRoot, workers = 1)
            val parallel = generate(fixture, parallelRoot, workers = 2)
            val serialBytes = Files.readAllBytes(serialRoot.resolve("report.json"))
            val parallelBytes = Files.readAllBytes(parallelRoot.resolve("report.json"))
            val report = parseObject(serialBytes)
            val frozenBytes = checkNotNull(
                javaClass.getResourceAsStream("/oracle/full-tree-data-reconciliation-v1-frozen.json"),
            ) { "frozen v1 reconciliation fixture is unavailable" }.use { it.readAllBytes() }

            assertTrue(serialBytes.contentEquals(parallelBytes))
            assertTrue(serialBytes.contentEquals(frozenBytes))
            assertEquals(parseObject(frozenBytes), report)
            assertEquals(report.requiredString("reportSha256"), serial.reportSha256)
            assertEquals(serial.counts, parallel.counts)
            assertEquals(setOf("", "report.json"), Files.walk(serialRoot).use { paths ->
                paths.map { serialRoot.relativize(it).toString() }.toList().toSet()
            })
            assertEquals(FROZEN_CONFIGURATION_SHA256, FullTreeDataReconciliationSqlite.configurationSha256)
            assertEquals(FROZEN_ELF_CONFIGURATION_SHA256, FullTreeDataReconciliationSqlite.elfDataConfigurationSha256)
            assertEquals(FROZEN_SCOPE_SHA256, fixture.scopeSha256)
            assertEquals(FROZEN_INVENTORY_INDEX_SHA256, fixture.inventory.requiredString("indexSha256"))
            assertEquals(FROZEN_TRUTH_INDEX_SHA256, fixture.truthIndexSha256)
            assertEquals(FROZEN_ELF_INDEX_SHA256, fixture.elfSha256)
            assertEquals(FROZEN_REPORT_SHA256, serial.reportSha256)
            assertEquals(FROZEN_REPORT_ARTIFACT_SHA256, OracleArtifacts.sha256(serialBytes))
        }

    @Test
    fun `malformed duplicate-key duplicate-address Unicode-order and extra-tree mutations fail closed`() =
        inTemporaryDirectory { directory ->
            val mutations: List<(Fixture) -> String> = listOf(
                { fixture ->
                    val bytes = Files.readAllBytes(fixture.elfPath) + "{".toByteArray()
                    Files.write(fixture.elfPath, bytes)
                    OracleArtifacts.sha256(bytes)
                },
                { fixture ->
                    val text = Files.readString(fixture.elfPath)
                    val bytes = text.replaceFirst("{\n", "{\n  \"artifacts\": {},\n").toByteArray()
                    Files.write(fixture.elfPath, bytes)
                    OracleArtifacts.sha256(bytes)
                },
                { fixture ->
                    rewriteElf(fixture) { document ->
                        val globals = document.requiredArray("globals").toMutableList()
                        globals.add(1, globals.first())
                        JsonObject(document.toMutableMap().apply { this["globals"] = JsonArray(globals) })
                    }
                },
                { fixture ->
                    rewriteElf(fixture) { document ->
                        val globals = document.requiredArray("globals").objects("ELF global").map { global ->
                            if (global.requiredString("id") != "global-rva-0x20") global else {
                                JsonObject(global.toMutableMap().apply {
                                    this["aliases"] = JsonArray(global.requiredArray("aliases").reversed())
                                })
                            }
                        }
                        JsonObject(document.toMutableMap().apply { this["globals"] = JsonArray(globals) })
                    }
                },
                { fixture ->
                    Files.writeString(fixture.truthRoot.resolve("shards/unindexed.json"), "{}")
                    fixture.elfSha256
                },
            )
            mutations.forEachIndexed { index, mutate ->
                val fixture = createFixture(directory.resolve("mutation-$index"))
                val elfSha256 = mutate(fixture)
                val output = directory.resolve("rejected-$index")
                assertFailsWith<FullTreeDataTruthException> {
                    generate(fixture.copy(elfSha256 = elfSha256), output, workers = 2)
                }
                assertFalse(Files.exists(output), "mutation $index published a reconciliation directory")
                assertNoPublicationResidue(directory)
            }
        }

    @Test
    fun `stale hashes bindings and explicit input resource limits fail closed`() =
        inTemporaryDirectory { directory ->
            val stale = createFixture(directory.resolve("stale"))
            Files.write(stale.elfPath, Files.readAllBytes(stale.elfPath) + byteArrayOf(' '.code.toByte()))
            assertRejected(stale, directory.resolve("stale-output"))

            val wrongSource = createFixture(directory.resolve("source-binding"))
            val output = directory.resolve("source-binding-output")
            assertFailsWith<FullTreeDataTruthException> {
                FullTreeDataReconciliationSqlite.generate(
                    scope = wrongSource.scope,
                    scopeSha256 = wrongSource.scopeSha256,
                    inventory = wrongSource.inventory,
                    sourceLockSha256 = "f".repeat(64),
                    artifactManifestSha256 = MANIFEST_SHA256,
                    dataTruthRoot = wrongSource.truthRoot,
                    dataTruthIndexSha256 = wrongSource.truthIndexSha256,
                    elfDataIndex = wrongSource.elfPath,
                    elfDataIndexSha256 = wrongSource.elfSha256,
                    outputRoot = output,
                    maximumWorkers = 1,
                )
            }
            assertFalse(Files.exists(output))

            val bounded = createFixture(directory.resolve("bounded"))
            val elfBytes = Files.size(bounded.elfPath)
            val variants = listOf(
                FullTreeDataReconciliationLimits(maximumElfIndexBytes = elfBytes - 1L),
                FullTreeDataReconciliationLimits(maximumEntities = 2L),
                FullTreeDataReconciliationLimits(maximumWorkers = 1),
            )
            variants.forEachIndexed { index, limits ->
                val boundedOutput = directory.resolve("bounded-output-$index")
                assertFailsWith<FullTreeDataTruthException> {
                    generate(bounded, boundedOutput, workers = 2, limits = limits)
                }
                assertFalse(Files.exists(boundedOutput))
            }

            val accepted = generate(bounded, directory.resolve("size-reference"), workers = 1)
            val reportBoundOutput = directory.resolve("report-bound-output")
            assertFailsWith<FullTreeDataTruthException> {
                generate(
                    bounded,
                    reportBoundOutput,
                    workers = 1,
                    limits = FullTreeDataReconciliationLimits(maximumReportBytes = accepted.outputBytes - 1L),
                )
            }
            assertFalse(Files.exists(reportBoundOutput))

            val perShardBound = createFixture(directory.resolve("per-shard-bound"), perShardEntities = 2)
            val perShardOutput = directory.resolve("per-shard-bound-output")
            assertFailsWith<FullTreeDataTruthException> {
                generate(perShardBound, perShardOutput, workers = 1)
            }
            assertFalse(Files.exists(perShardOutput))
        }

    @Test
    fun `scope and inventory are independently authenticated rather than trusted as caller objects`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("controls"))
            val reorderedUnits = fixture.inventory.requiredArray("units").reversed()
            val badInventory = JsonObject(fixture.inventory.toMutableMap().apply {
                this["units"] = JsonArray(reorderedUnits)
            })
            val output = directory.resolve("bad-inventory")
            assertFailsWith<FullTreeDataTruthException> {
                FullTreeDataReconciliationSqlite.generate(
                    scope = fixture.scope,
                    scopeSha256 = fixture.scopeSha256,
                    inventory = badInventory,
                    sourceLockSha256 = SOURCE_LOCK_SHA256,
                    artifactManifestSha256 = MANIFEST_SHA256,
                    dataTruthRoot = fixture.truthRoot,
                    dataTruthIndexSha256 = fixture.truthIndexSha256,
                    elfDataIndex = fixture.elfPath,
                    elfDataIndexSha256 = fixture.elfSha256,
                    outputRoot = output,
                    maximumWorkers = 1,
                )
            }
            assertFalse(Files.exists(output))

            val badScopeOutput = directory.resolve("bad-scope")
            assertFailsWith<FullTreeDataTruthException> {
                FullTreeDataReconciliationSqlite.generate(
                    scope = fixture.scope,
                    scopeSha256 = "0".repeat(64),
                    inventory = fixture.inventory,
                    sourceLockSha256 = SOURCE_LOCK_SHA256,
                    artifactManifestSha256 = MANIFEST_SHA256,
                    dataTruthRoot = fixture.truthRoot,
                    dataTruthIndexSha256 = fixture.truthIndexSha256,
                    elfDataIndex = fixture.elfPath,
                    elfDataIndexSha256 = fixture.elfSha256,
                    outputRoot = badScopeOutput,
                    maximumWorkers = 1,
                )
            }
            assertFalse(Files.exists(badScopeOutput))

            val repeatedUnits = List(200) { fixture.inventory.requiredArray("units").first() }
            val oversizedInventory = JsonObject(fixture.inventory.toMutableMap().apply {
                this["units"] = JsonArray(repeatedUnits)
            })
            val scopeBytes = OracleJson.canonicalBytes(fixture.scope).size
            val inventoryBytes = OracleJson.canonicalBytes(oversizedInventory).size
            assertTrue(inventoryBytes > scopeBytes + 1)
            val oversizedOutput = directory.resolve("oversized-in-memory-inventory")
            assertFailsWith<FullTreeDataTruthException> {
                FullTreeDataReconciliationSqlite.generate(
                    scope = fixture.scope,
                    scopeSha256 = fixture.scopeSha256,
                    inventory = oversizedInventory,
                    sourceLockSha256 = SOURCE_LOCK_SHA256,
                    artifactManifestSha256 = MANIFEST_SHA256,
                    dataTruthRoot = fixture.truthRoot,
                    dataTruthIndexSha256 = fixture.truthIndexSha256,
                    elfDataIndex = fixture.elfPath,
                    elfDataIndexSha256 = fixture.elfSha256,
                    outputRoot = oversizedOutput,
                    maximumWorkers = 1,
                    limits = FullTreeDataReconciliationLimits(
                        maximumControlArtifactBytes = maxOf(scopeBytes + 1, inventoryBytes - 1),
                    ),
                )
            }
            assertFalse(Files.exists(oversizedOutput))
        }

    @Test
    fun `control snapshot time is charged to the cooperative deadline`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("control-deadline"))
            val output = directory.resolve("control-deadline-output")
            val stages = mutableListOf<String>()
            val runtime = FullTreeReconciliationRuntime { stage ->
                stages += stage
                FullTreeReconciliationRuntimeSample(
                    wallNanos = if (stage == "start") 0L else 121_000_000_000L,
                    processCpuNanos = 0L,
                )
            }
            val failure = assertFailsWith<FullTreeDataTruthException> {
                FullTreeDataReconciliationSqlite.generateForTesting(
                    scope = fixture.scope,
                    scopeSha256 = fixture.scopeSha256,
                    inventory = fixture.inventory,
                    sourceLockSha256 = SOURCE_LOCK_SHA256,
                    artifactManifestSha256 = MANIFEST_SHA256,
                    dataTruthRoot = fixture.truthRoot,
                    dataTruthIndexSha256 = fixture.truthIndexSha256,
                    elfDataIndex = fixture.elfPath,
                    elfDataIndexSha256 = fixture.elfSha256,
                    outputRoot = output,
                    maximumWorkers = 1,
                    runtime = runtime,
                )
            }
            assertEquals(listOf("start", "after control snapshots"), stages)
            assertTrue("wall-clock bound" in failure.message.orEmpty())
            assertFalse(Files.exists(output))
            assertNoPublicationResidue(directory)
        }

    @Test
    fun `partial publication construction failures revoke every created directory`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("partial-publication"))
            listOf(
                "after reconciliation staging creation",
                "after reconciliation scratch creation",
            ).forEachIndexed { index, failingStage ->
                val output = directory.resolve("partial-publication-output-$index")
                var reachedFailure = false
                val runtime = FullTreeReconciliationRuntime { stage ->
                    if (stage == failingStage) reachedFailure = true
                    FullTreeReconciliationRuntimeSample(
                        wallNanos = if (reachedFailure) 121_000_000_000L else 0L,
                        processCpuNanos = 0L,
                    )
                }
                val failure = assertFailsWith<FullTreeDataTruthException> {
                    FullTreeDataReconciliationSqlite.generateForTesting(
                        scope = fixture.scope,
                        scopeSha256 = fixture.scopeSha256,
                        inventory = fixture.inventory,
                        sourceLockSha256 = SOURCE_LOCK_SHA256,
                        artifactManifestSha256 = MANIFEST_SHA256,
                        dataTruthRoot = fixture.truthRoot,
                        dataTruthIndexSha256 = fixture.truthIndexSha256,
                        elfDataIndex = fixture.elfPath,
                        elfDataIndexSha256 = fixture.elfSha256,
                        outputRoot = output,
                        maximumWorkers = 1,
                        runtime = runtime,
                    )
                }
                assertTrue(reachedFailure)
                assertTrue("wall-clock bound" in failure.message.orEmpty())
                assertFalse(Files.exists(output))
                assertNoPublicationResidue(directory)
            }
        }

    @Test
    fun `cooperative monotonic deadline expiring during report emission revokes all output`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("deadline"))
            val output = directory.resolve("deadline-output")
            var emissionSamples = 0
            val runtime = FullTreeReconciliationRuntime { stage ->
                if ("emitting reconciliation report" in stage) emissionSamples++
                FullTreeReconciliationRuntimeSample(
                    wallNanos = if (emissionSamples >= 2) 121_000_000_000L else 0L,
                    processCpuNanos = 0L,
                )
            }
            val failure = assertFailsWith<FullTreeDataTruthException> {
                FullTreeDataReconciliationSqlite.generateForTesting(
                    scope = fixture.scope,
                    scopeSha256 = fixture.scopeSha256,
                    inventory = fixture.inventory,
                    sourceLockSha256 = SOURCE_LOCK_SHA256,
                    artifactManifestSha256 = MANIFEST_SHA256,
                    dataTruthRoot = fixture.truthRoot,
                    dataTruthIndexSha256 = fixture.truthIndexSha256,
                    elfDataIndex = fixture.elfPath,
                    elfDataIndexSha256 = fixture.elfSha256,
                    outputRoot = output,
                    maximumWorkers = 1,
                    runtime = runtime,
                )
            }
            assertTrue("wall-clock bound" in failure.message.orEmpty())
            assertTrue(emissionSamples >= 2)
            assertFalse(Files.exists(output))
            assertNoPublicationResidue(directory)
        }

    @Test
    fun `cooperative deadline after atomic directory move revokes the published target`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("post-move-deadline"))
            val output = directory.resolve("post-move-output")
            var reachedPostMove = false
            val runtime = FullTreeReconciliationRuntime { stage ->
                if (stage == "after atomic reconciliation publication") reachedPostMove = true
                FullTreeReconciliationRuntimeSample(
                    wallNanos = if (reachedPostMove) 121_000_000_000L else 0L,
                    processCpuNanos = 0L,
                )
            }
            val failure = assertFailsWith<FullTreeDataTruthException> {
                FullTreeDataReconciliationSqlite.generateForTesting(
                    scope = fixture.scope,
                    scopeSha256 = fixture.scopeSha256,
                    inventory = fixture.inventory,
                    sourceLockSha256 = SOURCE_LOCK_SHA256,
                    artifactManifestSha256 = MANIFEST_SHA256,
                    dataTruthRoot = fixture.truthRoot,
                    dataTruthIndexSha256 = fixture.truthIndexSha256,
                    elfDataIndex = fixture.elfPath,
                    elfDataIndexSha256 = fixture.elfSha256,
                    outputRoot = output,
                    maximumWorkers = 1,
                    runtime = runtime,
                )
            }
            assertTrue(reachedPostMove)
            assertTrue("wall-clock bound" in failure.message.orEmpty())
            assertFalse(Files.exists(output))
            assertNoPublicationResidue(directory)
        }

    private fun generate(
        fixture: Fixture,
        output: Path,
        workers: Int,
        limits: FullTreeDataReconciliationLimits = FullTreeDataReconciliationLimits(),
    ): FullTreeDataReconciliationGeneration = FullTreeDataReconciliationSqlite.generate(
        scope = fixture.scope,
        scopeSha256 = fixture.scopeSha256,
        inventory = fixture.inventory,
        sourceLockSha256 = SOURCE_LOCK_SHA256,
        artifactManifestSha256 = MANIFEST_SHA256,
        dataTruthRoot = fixture.truthRoot,
        dataTruthIndexSha256 = fixture.truthIndexSha256,
        elfDataIndex = fixture.elfPath,
        elfDataIndexSha256 = fixture.elfSha256,
        outputRoot = output,
        maximumWorkers = workers,
        limits = limits,
    )

    private fun assertRejected(fixture: Fixture, output: Path) {
        assertFailsWith<FullTreeDataTruthException> { generate(fixture, output, workers = 1) }
        assertFalse(Files.exists(output))
        assertNoPublicationResidue(output.parent)
    }

    private fun assertNoPublicationResidue(root: Path) {
        val residue = Files.walk(root).use { paths ->
            paths.anyMatch { path ->
                val name = path.fileName?.toString().orEmpty()
                "reconciliation-stage" in name || "reconciliation-scratch" in name
            }
        }
        assertFalse(residue, "reconciliation staging or scratch state was not revoked")
    }

    private fun createFixture(root: Path, perShardEntities: Int = 100): Fixture {
        Files.createDirectories(root.resolve("truth/shards"))
        val scope = scope(perShardEntities)
        val scopeSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(scope))
        val inventory = inventory(scopeSha256)
        val truth = truth(root.resolve("truth"), scopeSha256, inventory)
        val elfPath = root.resolve("elf-data.json")
        val elf = elf(scopeSha256, inventory)
        val elfBytes = OracleJson.canonicalBytes(elf)
        Files.write(elfPath, elfBytes)
        return Fixture(
            scope,
            scopeSha256,
            inventory,
            root.resolve("truth").toAbsolutePath().normalize(),
            truth,
            elfPath.toAbsolutePath().normalize(),
            OracleArtifacts.sha256(elfBytes),
        )
    }

    private fun scope(perShardEntities: Int): JsonObject {
        fun bounds(units: Int, entities: Int, bytes: Long): JsonObject = JsonObject(
            mapOf(
                "compilationUnits" to JsonPrimitive(units),
                "cpuSeconds" to JsonPrimitive(120),
                "entities" to JsonPrimitive(entities),
                "maximumResidentBytes" to JsonPrimitive(2L * 1024L * 1024L * 1024L),
                "serializedBytes" to JsonPrimitive(bytes),
                "wallClockSeconds" to JsonPrimitive(120),
            ),
        )
        return JsonObject(
            mapOf(
                "bounds" to JsonObject(
                    mapOf(
                        "perShard" to bounds(1, perShardEntities, 32L * 1024L * 1024L),
                        "wholeRun" to bounds(2, 100, 64L * 1024L * 1024L),
                    ),
                ),
                "oracle" to JsonObject(
                    mapOf(
                        "artifactManifestSha256" to JsonPrimitive(MANIFEST_SHA256),
                        "id" to JsonPrimitive("reconciliation-fixture"),
                        "richArtifactSha256" to JsonPrimitive(RICH_SHA256),
                        "sourceLockSha256" to JsonPrimitive(SOURCE_LOCK_SHA256),
                        "strippedArtifactSha256" to JsonPrimitive(STRIPPED_SHA256),
                    ),
                ),
                "pathPolicy" to JsonObject(
                    mapOf(
                        "prefixMaps" to JsonArray(
                            listOf(JsonObject(mapOf("from" to JsonPrimitive("/src/"), "to" to JsonPrimitive("source/")))),
                        ),
                    ),
                ),
                "populations" to JsonObject(
                    mapOf(
                        "excluded" to JsonPrimitive(
                            "entities matching one reviewed exclusion record and no scored record",
                        ),
                        "exclusions" to JsonArray(emptyList()),
                        "scored" to JsonPrimitive(
                            "emitted ELF entities with independently source-aligned DWARF ownership",
                        ),
                        "unobservable" to JsonPrimitive(
                            "authenticated source or DWARF entities without an emitted address",
                        ),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "sharding" to JsonObject(
                    mapOf(
                        "duplicateOwnership" to JsonPrimitive(
                            "lowest-source-aligned-unit-id; aliases remain evidence on one emitted RVA",
                        ),
                        "mergeOrdering" to JsonPrimitive("shard-id,source-path,unit-id,entity-kind,entity-id"),
                        "rules" to JsonArray(
                            listOf(
                                JsonObject(
                                    mapOf(
                                        "componentDepth" to JsonPrimitive(0),
                                        "pathPrefix" to JsonPrimitive("source/"),
                                        "shardPrefix" to JsonPrimitive("shard"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )
    }

    private fun inventory(scopeSha256: String): JsonObject {
        fun unit(id: String, shard: String, path: String, offset: String): JsonObject = JsonObject(
            mapOf(
                "addressSize" to JsonPrimitive(8),
                "dwarfOffset" to JsonPrimitive(offset),
                "dwarfVersion" to JsonPrimitive(5),
                "id" to JsonPrimitive(id),
                "language" to JsonPrimitive(29),
                "producerSha256" to JsonPrimitive("9".repeat(64)),
                "rawPathSha256" to JsonPrimitive("8".repeat(64)),
                "shardId" to JsonPrimitive(shard),
                "sourceKind" to JsonPrimitive("handwritten"),
                "sourcePath" to JsonPrimitive(path),
            ),
        )
        val units = listOf(
            unit("unit-a", "shard-a", "source/\ue000.cc", "0x10"),
            unit("unit-b", "shard-b", "source/\ud83d\ude00.cc", "0x20"),
        )
        val indexDigest = MessageDigest.getInstance("SHA-256").apply {
            update("full-tree-index-v1\u0000".toByteArray(StandardCharsets.UTF_8))
            units.forEach { update(MessageDigest.getInstance("SHA-256").digest(OracleJson.canonicalBytes(it))) }
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
                "indexSha256" to JsonPrimitive(indexDigest),
                "oracle" to JsonObject(
                    mapOf(
                        "artifactManifestSha256" to JsonPrimitive(MANIFEST_SHA256),
                        "id" to JsonPrimitive("reconciliation-fixture"),
                        "richArtifactSha256" to JsonPrimitive(RICH_SHA256),
                        "scopeSha256" to JsonPrimitive(scopeSha256),
                        "sourceLockSha256" to JsonPrimitive(SOURCE_LOCK_SHA256),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(
                    listOf(
                        JsonObject(mapOf("id" to JsonPrimitive("shard-a"), "unitIds" to JsonArray(listOf(JsonPrimitive("unit-a"))))),
                        JsonObject(mapOf("id" to JsonPrimitive("shard-b"), "unitIds" to JsonArray(listOf(JsonPrimitive("unit-b"))))),
                    ),
                ),
                "units" to JsonArray(units),
            ),
        )
    }

    private fun truth(root: Path, scopeSha256: String, inventory: JsonObject): String {
        val oracle = JsonObject(
            mapOf(
                "configurationSha256" to JsonPrimitive(FullTreeDataTruthSqlite.configurationSha256),
                "dataObservationIndexSha256" to JsonPrimitive("7".repeat(64)),
                "inventoryIndexSha256" to inventory.requiredElement("indexSha256"),
                "scopeSha256" to JsonPrimitive(scopeSha256),
            ),
        )
        val type = truthType(TYPE_A, "unit-a")
        val shardAGlobals = listOf(
            truthGlobal(GLOBAL_IMAGE, "unit-a", listOf("image_a"), "0x10", tls = false),
            truthGlobal(GLOBAL_TLS, "unit-a", listOf("_tls"), "0x30", tls = true),
        )
        val shardBGlobals = listOf(
            truthGlobal(GLOBAL_DWARF_ONLY, "unit-b", listOf("dwarf_only"), "0x99", tls = false),
            truthGlobal(GLOBAL_UNOBSERVABLE, "unit-b", listOf("hidden"), null, tls = false),
        )
        val aCounts = truthCounts(globals = 2, types = 1, resolved = 2, crossShard = 0)
        val bCounts = truthCounts(
            globals = 2,
            types = 0,
            unobservableGlobals = 1,
            resolved = 2,
            crossShard = 2,
        )
        val documents = listOf(
            "shard-a" to JsonObject(
                mapOf(
                    "counts" to aCounts,
                    "globals" to JsonArray(shardAGlobals),
                    "oracle" to oracle,
                    "schemaVersion" to JsonPrimitive(1),
                    "shard" to JsonObject(
                        mapOf(
                            "id" to JsonPrimitive("shard-a"),
                            "unitIds" to JsonArray(listOf(JsonPrimitive("unit-a"))),
                        ),
                    ),
                    "types" to JsonArray(listOf(type)),
                ),
            ),
            "shard-b" to JsonObject(
                mapOf(
                    "counts" to bCounts,
                    "globals" to JsonArray(shardBGlobals),
                    "oracle" to oracle,
                    "schemaVersion" to JsonPrimitive(1),
                    "shard" to JsonObject(
                        mapOf(
                            "id" to JsonPrimitive("shard-b"),
                            "unitIds" to JsonArray(listOf(JsonPrimitive("unit-b"))),
                        ),
                    ),
                    "types" to JsonArray(emptyList()),
                ),
            ),
        )
        val records = documents.map { (id, document) ->
            val bytes = OracleJson.canonicalBytes(document)
            val path = root.resolve("shards/$id.json")
            Files.write(path, bytes)
            JsonObject(
                linkedMapOf<String, JsonElement>(
                    "id" to JsonPrimitive(id),
                    "path" to JsonPrimitive("shards/$id.json"),
                    "bytes" to JsonPrimitive(bytes.size),
                    "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
                ).apply { putAll(document.requiredObject("counts")) },
            )
        }
        val aggregate = truthCounts(
            globals = 4,
            types = 1,
            unobservableGlobals = 1,
            resolved = 4,
            crossShard = 2,
        )
        val withoutHash = JsonObject(
            mapOf(
                "complete" to JsonPrimitive(true),
                "counts" to aggregate,
                "oracle" to oracle,
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(records),
            ),
        )
        val index = JsonObject(withoutHash.toMutableMap().apply {
            this["indexSha256"] = JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutHash)))
        })
        val bytes = OracleJson.canonicalBytes(index)
        Files.write(root.resolve("index.json"), bytes)
        return OracleArtifacts.sha256(bytes)
    }

    private fun truthGlobal(
        id: String,
        ownerUnit: String,
        names: List<String>,
        address: String?,
        tls: Boolean,
    ): JsonObject = JsonObject(
        mapOf(
            "addressRva" to (address?.let(::JsonPrimitive) ?: JsonNull),
            "alignment" to JsonPrimitive(8),
            "declarations" to JsonArray(listOf(JsonObject(mapOf("source" to JsonPrimitive(id))))),
            "external" to JsonPrimitive(true),
            "id" to JsonPrimitive(id),
            "mutability" to JsonPrimitive("mutable"),
            "names" to JsonArray(names.map(::JsonPrimitive)),
            "observationIds" to JsonArray(listOf(JsonPrimitive("observation-${id.removePrefix("global-")}"))),
            "ownerUnitId" to JsonPrimitive(ownerUnit),
            "population" to JsonPrimitive(if (address == null) "unobservable" else "scored"),
            "reasonCode" to if (address == null) JsonPrimitive("location-unobservable") else JsonNull,
            "size" to JsonPrimitive(8),
            "tls" to JsonPrimitive(tls),
            "typeReference" to resolvedTypeReference(),
            "visibility" to JsonPrimitive("default"),
        ),
    )

    private fun truthType(id: String, ownerUnit: String): JsonObject = JsonObject(
        mapOf(
            "alignment" to JsonPrimitive(8),
            "byteSize" to JsonPrimitive(8),
            "context" to JsonArray(emptyList()),
            "declarations" to JsonArray(listOf(JsonObject(mapOf("source" to JsonPrimitive(id))))),
            "id" to JsonPrimitive(id),
            "members" to JsonArray(emptyList()),
            "name" to JsonPrimitive("FixtureType"),
            "observationIds" to JsonArray(listOf(JsonPrimitive("observation-type-a"))),
            "ownerUnitId" to JsonPrimitive(ownerUnit),
            "population" to JsonPrimitive("scored"),
            "reasonCode" to JsonNull,
            "tag" to JsonPrimitive("DW_TAG_structure_type"),
        ),
    )

    private fun resolvedTypeReference(): JsonObject = JsonObject(
        mapOf(
            "evidenceDieOffsets" to JsonArray(listOf(JsonPrimitive("0x1"))),
            "modifierTags" to JsonArray(emptyList()),
            "reasonCode" to JsonNull,
            "resolutionCode" to JsonPrimitive("exact-dwarf-offset"),
            "targetOwnerShardId" to JsonPrimitive("shard-a"),
            "targetTypeId" to JsonPrimitive(TYPE_A),
        ),
    )

    private fun truthCounts(
        globals: Int,
        types: Int,
        unobservableGlobals: Int = 0,
        resolved: Int,
        crossShard: Int,
    ): JsonObject = JsonObject(
        mapOf(
            "ambiguousTypeReferences" to JsonPrimitive(0),
            "bases" to JsonPrimitive(0),
            "crossShardTypeReferences" to JsonPrimitive(crossShard),
            "enumerators" to JsonPrimitive(0),
            "fields" to JsonPrimitive(0),
            "globals" to JsonPrimitive(globals),
            "resolvedTypeReferences" to JsonPrimitive(resolved),
            "types" to JsonPrimitive(types),
            "unobservableGlobals" to JsonPrimitive(unobservableGlobals),
            "unobservableTypes" to JsonPrimitive(0),
            "unresolvedTypeReferences" to JsonPrimitive(0),
        ),
    )

    private fun elf(scopeSha256: String, inventory: JsonObject): JsonObject {
        val aliasesAtElfOnly = listOf(
            elfAlias(BMP_ALIAS, abi = fixtureAbi()),
            elfAlias(SUPPLEMENTARY_ALIAS, abi = fixtureAbi()),
        )
        val globals = listOf(
            JsonObject(
                mapOf(
                    "address" to JsonPrimitive("0x10"),
                    "addressKind" to JsonPrimitive("image-rva"),
                    "aliases" to JsonArray(listOf(elfAlias("image_a"))),
                    "id" to JsonPrimitive("global-rva-0x10"),
                ),
            ),
            JsonObject(
                mapOf(
                    "address" to JsonPrimitive("0x20"),
                    "addressKind" to JsonPrimitive("image-rva"),
                    "aliases" to JsonArray(aliasesAtElfOnly),
                    "id" to JsonPrimitive("global-rva-0x20"),
                ),
            ),
            JsonObject(
                mapOf(
                    "address" to JsonPrimitive("0x8"),
                    "addressKind" to JsonPrimitive("tls-offset"),
                    "aliases" to JsonArray(listOf(elfAlias("_tls", tls = true))),
                    "id" to JsonPrimitive("global-tls-0x8"),
                ),
            ),
        )
        val withoutHash = JsonObject(
            mapOf(
                "artifacts" to JsonObject(
                    mapOf(
                        "rich" to JsonObject(
                            mapOf(
                                "inputSha256" to JsonPrimitive(RICH_SHA256),
                                "scannedSymbols" to JsonPrimitive(10),
                                "sizeBytes" to JsonPrimitive(4096),
                            ),
                        ),
                        "stripped" to JsonObject(
                            mapOf(
                                "inputSha256" to JsonPrimitive(STRIPPED_SHA256),
                                "scannedSymbols" to JsonPrimitive(8),
                                "sizeBytes" to JsonPrimitive(2048),
                            ),
                        ),
                    ),
                ),
                "counts" to JsonObject(
                    mapOf(
                        "abiObjects" to JsonPrimitive(2),
                        "abiResolvedSlots" to JsonPrimitive(2),
                        "abiSlots" to JsonPrimitive(4),
                        "aliases" to JsonPrimitive(4),
                        "externalGlobals" to JsonPrimitive(2),
                        "globalRvas" to JsonPrimitive(3),
                    ),
                ),
                "externalGlobals" to JsonArray(
                    listOf(
                        external(BMP_EXTERNAL),
                        external(SUPPLEMENTARY_EXTERNAL),
                    ),
                ),
                "globals" to JsonArray(globals),
                "oracle" to JsonObject(
                    mapOf(
                        "configurationSha256" to JsonPrimitive(
                            FullTreeDataReconciliationSqlite.elfDataConfigurationSha256,
                        ),
                        "inventoryIndexSha256" to inventory.requiredElement("indexSha256"),
                        "scopeSha256" to JsonPrimitive(scopeSha256),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
            ),
        )
        return JsonObject(withoutHash.toMutableMap().apply {
            this["indexSha256"] = JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutHash)))
        })
    }

    private fun external(name: String): JsonObject = JsonObject(
        mapOf(
            "evidence" to JsonArray(listOf(JsonPrimitive("rich:symbol:$name"))),
            "name" to JsonPrimitive(name),
        ),
    )

    private fun elfAlias(name: String, tls: Boolean = false, abi: JsonElement = JsonNull): JsonObject = JsonObject(
        mapOf(
            "abi" to abi,
            "alignment" to JsonPrimitive(8),
            "availability" to JsonObject(
                mapOf("rich" to JsonPrimitive("surviving"), "stripped" to JsonPrimitive("surviving")),
            ),
            "binding" to JsonPrimitive("STB_GLOBAL"),
            "evidence" to JsonArray(listOf(JsonPrimitive("rich:symbol:$name"))),
            "kind" to JsonPrimitive(if (tls) "tls" else "object"),
            "mutability" to JsonPrimitive("mutable"),
            "name" to JsonPrimitive(name),
            "size" to JsonPrimitive(16),
            "visibility" to JsonPrimitive("STV_DEFAULT"),
        ),
    )

    private fun fixtureAbi(): JsonObject = JsonObject(
        mapOf(
            "kind" to JsonPrimitive("vtable"),
            "ownerMangledName" to JsonPrimitive("Fixture"),
            "slots" to JsonArray(
                listOf(
                    abiSlot(0, "0x20", "0001000000000000", "code", "0x100"),
                    abiSlot(1, "0x28", "0000000000000000", null, null),
                ),
            ),
        ),
    )

    private fun abiSlot(index: Int, rva: String, raw: String, kind: String?, target: String?): JsonObject =
        JsonObject(
            mapOf(
                "index" to JsonPrimitive(index),
                "rawLittleEndian" to JsonPrimitive(raw),
                "rva" to JsonPrimitive(rva),
                "targetKind" to (kind?.let(::JsonPrimitive) ?: JsonNull),
                "targetRva" to (target?.let(::JsonPrimitive) ?: JsonNull),
            ),
        )

    private fun rewriteElf(fixture: Fixture, mutate: (JsonObject) -> JsonObject): String {
        val original = parseObject(Files.readAllBytes(fixture.elfPath))
        val mutated = mutate(original)
        val withoutHash = JsonObject(mutated.filterKeys { it != "indexSha256" })
        val rebound = JsonObject(withoutHash.toMutableMap().apply {
            this["indexSha256"] = JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutHash)))
        })
        val bytes = OracleJson.canonicalBytes(rebound)
        Files.write(fixture.elfPath, bytes)
        return OracleArtifacts.sha256(bytes)
    }

    private fun parseObject(bytes: ByteArray): JsonObject = OracleJson.parseCanonical(bytes) as JsonObject

    private fun ByteArray.hex(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    private inline fun <T> inTemporaryDirectory(block: (Path) -> T): T {
        val directory = createTempDirectory("full-tree-data-reconciliation-test-")
        return try {
            block(directory)
        } finally {
            val paths = Files.walk(directory).use { it.toList() }
            paths.filter { path -> Files.isDirectory(path) }.forEach { path ->
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
            }
            paths.sortedWith(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private data class Fixture(
        val scope: JsonObject,
        val scopeSha256: String,
        val inventory: JsonObject,
        val truthRoot: Path,
        val truthIndexSha256: String,
        val elfPath: Path,
        val elfSha256: String,
    )

    private companion object {
        const val SOURCE_LOCK_SHA256 =
            "1111111111111111111111111111111111111111111111111111111111111111"
        const val MANIFEST_SHA256 =
            "2222222222222222222222222222222222222222222222222222222222222222"
        const val RICH_SHA256 =
            "3333333333333333333333333333333333333333333333333333333333333333"
        const val STRIPPED_SHA256 =
            "4444444444444444444444444444444444444444444444444444444444444444"
        const val TYPE_A = "type-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val GLOBAL_IMAGE = "global-11111111111111111111111111111111"
        const val GLOBAL_TLS = "global-22222222222222222222222222222222"
        const val GLOBAL_DWARF_ONLY = "global-33333333333333333333333333333333"
        const val GLOBAL_UNOBSERVABLE = "global-44444444444444444444444444444444"
        const val BMP_ALIAS = "\ue000-object"
        const val SUPPLEMENTARY_ALIAS = "\ud83d\ude00-object"
        const val BMP_EXTERNAL = "\ue000-external"
        const val SUPPLEMENTARY_EXTERNAL = "\ud83d\ude00-external"

        /*
         * One-time migration provenance: these identities and the frozen resource were emitted on
         * 2026-08-30 by the checked-in historical v1 `generate_full_tree_data_reconciliation`
         * against this fixture, then committed as inert bytes. Production and tests never invoke or
         * import Python; the historical artifact is an independent compatibility witness only.
         */
        const val FROZEN_SCOPE_SHA256 =
            "aeca7101bf0bdb485fc21e6257ca5c64f6321d8d1a316dbf008f7ccb96c30602"
        const val FROZEN_INVENTORY_INDEX_SHA256 =
            "9f77d14b6a10351e0d89f1f214d29dcbcf050e27c89ee78c442a5ddf7c6fd4a8"
        const val FROZEN_TRUTH_INDEX_SHA256 =
            "714ce2ecb009ded8d993610d625d361eb49ab34d3214c3a0c0158f9e7576fe78"
        const val FROZEN_ELF_INDEX_SHA256 =
            "1e5a170df0ccf390d123f2638c678e17655973837696067c32d424dfc7421623"
        const val FROZEN_CONFIGURATION_SHA256 =
            "753a61d45f5af7be542102a0d06a55d237075673f822dcb1e8b3f011a4588815"
        const val FROZEN_ELF_CONFIGURATION_SHA256 =
            "17a38c15e629a64735554eb1d79db7c0720e5e9c84924856f03fe6842a682973"
        const val FROZEN_REPORT_SHA256 =
            "5c6e42381fdc2977928ff534438455f19e19c385d21cae78c3c47f70968899e3"
        const val FROZEN_REPORT_ARTIFACT_SHA256 =
            "cfcca6e636f058c9670b39495fb0d4516c1a287d54ec45b85560b5c4810bf5d4"
    }
}
