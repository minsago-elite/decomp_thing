package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
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

class FullTreeDataBaselineSqliteTest {
    @Test
    fun `frozen Kotlin baseline matches historical v1 bytes and worker ordering`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("authenticated ?#% baseline"))
            val serialRoot = directory.resolve("serial ?#% baseline")
            val parallelRoot = directory.resolve("parallel ?#% baseline")
            val serial = generate(fixture, serialRoot, workers = 1)
            val parallel = generate(fixture, parallelRoot, workers = 2)
            val serialBytes = Files.readAllBytes(serialRoot.resolve("report.json"))
            val parallelBytes = Files.readAllBytes(parallelRoot.resolve("report.json"))
            val frozenBytes = checkNotNull(
                javaClass.getResourceAsStream("/oracle/full-tree-data-baseline-v1-frozen.json"),
            ) { "frozen v1 data baseline fixture is unavailable" }.use { it.readAllBytes() }

            assertTrue(serialBytes.contentEquals(parallelBytes))
            assertTrue(serialBytes.contentEquals(frozenBytes))
            assertEquals(FROZEN_CONFIGURATION_SHA256, FullTreeDataBaselineSqlite.configurationSha256)
            assertEquals(FROZEN_REPORT_SHA256, serial.reportSha256)
            assertEquals(FROZEN_ARTIFACT_SHA256, serial.artifactSha256)
            assertEquals(serial, parallel)
            assertEquals(setOf("", "report.json"), Files.walk(serialRoot).use { paths ->
                paths.map { serialRoot.relativize(it).toString() }.toList().toSet()
            })

            val validationScratch = directory.resolve("validation scratch")
            Files.createDirectory(validationScratch)
            val binding = FullTreeDataBaselineSqlite.validate(
                serialRoot.resolve("report.json"),
                serial.artifactSha256,
                validationScratch,
            )
            assertEquals(serial.reportSha256, binding.reportSha256)
            assertEquals(serial.aggregate, binding.aggregate)
            assertEquals(emptyList(), Files.list(validationScratch).use { it.toList() })
            val comparisonScratch = directory.resolve("comparison ?#% scratch")
            Files.createDirectory(comparisonScratch)
            FullTreeDataBaselineSqlite.requireNoRegression(
                current = serialRoot.resolve("report.json"),
                currentArtifactSha256 = serial.artifactSha256,
                accepted = parallelRoot.resolve("report.json"),
                acceptedArtifactSha256 = parallel.artifactSha256,
                scratchRoot = comparisonScratch,
            )
            assertEquals(emptyList(), Files.list(comparisonScratch).use { it.toList() })
        }

    @Test
    fun `malformed duplicate and extra-tree mutations roll back speculative baseline state`() =
        inTemporaryDirectory { directory ->
            val malformed = createFixture(directory.resolve("malformed-tail"))
            val malformedBytes = Files.readAllBytes(malformed.reconciliationPath) + byteArrayOf('{'.code.toByte())
            Files.write(malformed.reconciliationPath, malformedBytes)
            assertRejected(
                malformed.copy(reconciliationSha256 = OracleArtifacts.sha256(malformedBytes)),
                directory.resolve("malformed-output"),
            )

            val duplicate = createFixture(directory.resolve("duplicate-key"))
            val duplicateBytes = Files.readString(duplicate.reconciliationPath)
                .replaceFirst("{\n", "{\n  \"abiObjects\": [],\n")
                .toByteArray(StandardCharsets.UTF_8)
            Files.write(duplicate.reconciliationPath, duplicateBytes)
            assertRejected(
                duplicate.copy(reconciliationSha256 = OracleArtifacts.sha256(duplicateBytes)),
                directory.resolve("duplicate-output"),
            )

            val extra = createFixture(directory.resolve("extra-tree"))
            Files.writeString(extra.truthRoot.resolve("shards/unindexed.json"), "{}")
            assertRejected(extra, directory.resolve("extra-output"))
        }

    @Test
    fun `stale hashes rebound ownership and explicit limits fail closed`() =
        inTemporaryDirectory { directory ->
            val staleTruth = createFixture(directory.resolve("stale-truth"))
            assertRejected(
                staleTruth.copy(truthIndexSha256 = "f".repeat(64)),
                directory.resolve("stale-truth-output"),
            )

            val rebound = createFixture(directory.resolve("rebound-owner"))
            val reboundSha = rewriteReconciliation(rebound) { report ->
                val globals = report.requiredArray("globals").objects("global").mapIndexed { index, global ->
                    if (index != 0) global else JsonObject(global.toMutableMap().apply {
                        this["ownerShardIds"] = JsonArray(listOf(JsonPrimitive("shard-b")))
                    })
                }
                JsonObject(report.toMutableMap().apply { this["globals"] = JsonArray(globals) })
            }
            assertRejected(
                rebound.copy(reconciliationSha256 = reboundSha),
                directory.resolve("rebound-owner-output"),
            )

            val bounded = createFixture(directory.resolve("bounded"))
            val truthSizes = Files.list(bounded.truthRoot.resolve("shards")).use { paths ->
                paths.map { path -> Files.size(path) }.toList()
            }
            listOf(
                FullTreeDataBaselineLimits(
                    maximumReconciliationBytes = Files.size(bounded.reconciliationPath) - 1L,
                ),
                FullTreeDataBaselineLimits(maximumEntities = 2L, maximumTruthPartitionEntities = 2L),
                FullTreeDataBaselineLimits(maximumWorkers = 1),
                FullTreeDataBaselineLimits(
                    maximumTruthPartitionBytes = checkNotNull(truthSizes.maxOrNull()),
                    maximumTruthBytes = truthSizes.sum() - 1L,
                ),
                FullTreeDataBaselineLimits(maximumDatabaseBytes = 4096L, maximumScratchBytes = 4096L),
                FullTreeDataBaselineLimits(maximumModeledResidentBytes = 1L),
            ).forEachIndexed { index, limits ->
                val output = directory.resolve("bounded-output-$index")
                assertFailsWith<FullTreeDataBaselineException> {
                    generate(bounded, output, workers = 2, limits = limits)
                }
                assertFalse(Files.exists(output))
                assertNoPublicationResidue(directory)
            }

            val reference = generate(bounded, directory.resolve("baseline-size-reference"), workers = 1)
            val reportBound = directory.resolve("report-bound-output")
            assertFailsWith<FullTreeDataBaselineException> {
                generate(
                    bounded,
                    reportBound,
                    workers = 1,
                    limits = FullTreeDataBaselineLimits(maximumBaselineBytes = reference.outputBytes - 1L),
                )
            }
            assertFalse(Files.exists(reportBound))
            assertNoPublicationResidue(directory)
        }

    @Test
    fun `cooperative interruption during report emission revokes staging and scratch`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("report-deadline"))
            val output = directory.resolve("report-deadline-output")
            var reached = false
            val runtime = FullTreeDataBaselineRuntime { stage ->
                if (stage == "after data baseline report artifact pass") reached = true
                FullTreeDataBaselineRuntimeSample(
                    wallNanos = if (reached) 3601L * 1_000_000_000L else 0L,
                    processCpuNanos = 0L,
                )
            }
            val failure = assertFailsWith<FullTreeDataBaselineException> {
                generateForTesting(fixture, output, runtime)
            }
            assertTrue(reached)
            assertTrue("wall-clock bound" in failure.message.orEmpty())
            assertFalse(Files.exists(output))
            assertNoPublicationResidue(directory)
        }

    @Test
    fun `entry and partial-publication deadlines fail closed without residue`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("early-deadlines"))
            listOf(
                "after baseline control snapshot",
                "after data baseline staging creation",
            ).forEachIndexed { index, deadlineStage ->
                val output = directory.resolve("early-deadline-output-$index")
                var reached = false
                val runtime = FullTreeDataBaselineRuntime { stage ->
                    if (stage == deadlineStage) reached = true
                    FullTreeDataBaselineRuntimeSample(
                        wallNanos = if (reached) 3601L * 1_000_000_000L else 0L,
                        processCpuNanos = 0L,
                    )
                }
                val failure = assertFailsWith<FullTreeDataBaselineException> {
                    generateForTesting(fixture, output, runtime)
                }
                assertTrue(reached)
                assertTrue("wall-clock bound" in failure.message.orEmpty())
                assertFalse(Files.exists(output))
                assertNoPublicationResidue(directory)
            }
        }

    @Test
    fun `cooperative interruption after atomic publication revokes target`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("post-move-deadline"))
            val output = directory.resolve("post-move-output")
            var reached = false
            val runtime = FullTreeDataBaselineRuntime { stage ->
                if (stage == "after atomic data baseline publication") reached = true
                FullTreeDataBaselineRuntimeSample(
                    wallNanos = if (reached) 3601L * 1_000_000_000L else 0L,
                    processCpuNanos = 0L,
                )
            }
            val failure = assertFailsWith<FullTreeDataBaselineException> {
                generateForTesting(fixture, output, runtime)
            }
            assertTrue(reached)
            assertTrue("wall-clock bound" in failure.message.orEmpty())
            assertFalse(Files.exists(output))
            assertNoPublicationResidue(directory)
        }

    @Test
    fun `baseline validation rejects rebound denominator and mismatch mutations`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("baseline-validation"))
            val generatedRoot = directory.resolve("generated-baseline")
            generate(fixture, generatedRoot, workers = 1)
            val original = parseObject(Files.readAllBytes(generatedRoot.resolve("report.json")))

            val badDenominator = rewriteBaseline(directory.resolve("bad-denominator.json"), original) { report ->
                val aggregate = report.requiredObject("aggregate")
                val globals = aggregate.requiredObject("globals")
                val badGlobals = JsonObject(globals.toMutableMap().apply {
                    this["denominator"] = JsonPrimitive(globals.requiredLong("denominator") + 1L)
                })
                JsonObject(report.toMutableMap().apply {
                    this["aggregate"] = JsonObject(aggregate.toMutableMap().apply { this["globals"] = badGlobals })
                })
            }
            val validationScratch = directory.resolve("mutated-validation-scratch")
            Files.createDirectory(validationScratch)
            assertFailsWith<FullTreeDataBaselineException> {
                FullTreeDataBaselineSqlite.validate(
                    badDenominator.first,
                    badDenominator.second,
                    validationScratch,
                )
            }

            val mismatches = original.requiredArray("mismatches").objects("mismatch")
            val badMismatch = rewriteBaseline(directory.resolve("bad-mismatch.json"), original) { report ->
                val first = JsonObject(mismatches.first().toMutableMap().apply {
                    this["reasonCode"] = JsonPrimitive("forged-reason")
                })
                JsonObject(report.toMutableMap().apply {
                    this["mismatches"] = JsonArray(listOf(first) + mismatches.drop(1))
                })
            }
            assertFailsWith<FullTreeDataBaselineException> {
                FullTreeDataBaselineSqlite.validate(
                    badMismatch.first,
                    badMismatch.second,
                    validationScratch,
                )
            }
            assertEquals(emptyList(), Files.list(validationScratch).use { it.toList() })
        }

    @Test
    fun `accepted baseline comparison detects exact regressions and shard drift`() =
        inTemporaryDirectory { directory ->
            val fixture = createFixture(directory.resolve("comparison"))
            val acceptedRoot = directory.resolve("accepted")
            val accepted = generate(fixture, acceptedRoot, workers = 1)
            val report = parseObject(Files.readAllBytes(acceptedRoot.resolve("report.json")))
            val regressed = rewriteBaseline(directory.resolve("regressed.json"), report) { baseline ->
                val shards = baseline.requiredArray("shards").objects("shard").map { shard ->
                    if (shard.requiredString("id") != "shard-a") shard else {
                        val types = shard.requiredObject("types")
                        JsonObject(shard.toMutableMap().apply {
                            this["types"] = JsonObject(types.toMutableMap().apply {
                                this["exact"] = JsonPrimitive(types.requiredLong("exact") - 1L)
                                this["partial"] = JsonPrimitive(types.requiredLong("partial") + 1L)
                            })
                        })
                    }
                }
                val aggregate = baseline.requiredObject("aggregate")
                val types = aggregate.requiredObject("types")
                JsonObject(baseline.toMutableMap().apply {
                    this["aggregate"] = JsonObject(aggregate.toMutableMap().apply {
                        this["types"] = JsonObject(types.toMutableMap().apply {
                            this["exact"] = JsonPrimitive(types.requiredLong("exact") - 1L)
                            this["partial"] = JsonPrimitive(types.requiredLong("partial") + 1L)
                        })
                    })
                    this["shards"] = JsonArray(shards)
                })
            }
            val scratch = directory.resolve("comparison-scratch")
            Files.createDirectory(scratch)
            assertFailsWith<FullTreeDataBaselineException> {
                FullTreeDataBaselineSqlite.requireNoRegression(
                    current = regressed.first,
                    currentArtifactSha256 = regressed.second,
                    accepted = acceptedRoot.resolve("report.json"),
                    acceptedArtifactSha256 = accepted.artifactSha256,
                    scratchRoot = scratch,
                )
            }
            assertEquals(emptyList(), Files.list(scratch).use { it.toList() })

            val zeroMetric = JsonObject(
                mapOf(
                    "denominator" to JsonPrimitive(0),
                    "exact" to JsonPrimitive(0),
                    "excluded" to JsonPrimitive(0),
                    "fabricated" to JsonPrimitive(0),
                    "missing" to JsonPrimitive(0),
                    "partial" to JsonPrimitive(0),
                ),
            )
            val drifted = rewriteBaseline(directory.resolve("shard-drift.json"), report) { baseline ->
                val extra = JsonObject(
                    mapOf(
                        "abiObjects" to zeroMetric,
                        "globals" to zeroMetric,
                        "id" to JsonPrimitive("zz-extra"),
                        "types" to zeroMetric,
                    ),
                )
                JsonObject(baseline.toMutableMap().apply {
                    this["shards"] = JsonArray(baseline.requiredArray("shards") + extra)
                })
            }
            assertFailsWith<FullTreeDataBaselineException> {
                FullTreeDataBaselineSqlite.requireNoRegression(
                    current = drifted.first,
                    currentArtifactSha256 = drifted.second,
                    accepted = acceptedRoot.resolve("report.json"),
                    acceptedArtifactSha256 = accepted.artifactSha256,
                    scratchRoot = scratch,
                )
            }
            assertEquals(emptyList(), Files.list(scratch).use { it.toList() })
        }

    private fun generate(
        fixture: Fixture,
        output: Path,
        workers: Int,
        limits: FullTreeDataBaselineLimits = FullTreeDataBaselineLimits(),
    ): FullTreeDataBaselineGeneration = FullTreeDataBaselineSqlite.generate(
        dataTruthRoot = fixture.truthRoot,
        dataTruthIndexSha256 = fixture.truthIndexSha256,
        reconciliationReport = fixture.reconciliationPath,
        reconciliationReportSha256 = fixture.reconciliationSha256,
        inventory = fixture.inventory,
        scopeSha256 = SCOPE_SHA256,
        outputRoot = output,
        maximumWorkers = workers,
        limits = limits,
    )

    private fun generateForTesting(
        fixture: Fixture,
        output: Path,
        runtime: FullTreeDataBaselineRuntime,
    ): FullTreeDataBaselineGeneration = FullTreeDataBaselineSqlite.generateForTesting(
        dataTruthRoot = fixture.truthRoot,
        dataTruthIndexSha256 = fixture.truthIndexSha256,
        reconciliationReport = fixture.reconciliationPath,
        reconciliationReportSha256 = fixture.reconciliationSha256,
        inventory = fixture.inventory,
        scopeSha256 = SCOPE_SHA256,
        outputRoot = output,
        maximumWorkers = 1,
        runtime = runtime,
    )

    private fun assertRejected(fixture: Fixture, output: Path) {
        assertFailsWith<FullTreeDataBaselineException> { generate(fixture, output, workers = 1) }
        assertFalse(Files.exists(output))
        assertNoPublicationResidue(output.parent)
    }

    private fun assertNoPublicationResidue(parent: Path) {
        val residue = Files.walk(parent).use { paths ->
            paths.filter { path ->
                val name = path.fileName?.toString().orEmpty()
                ".data-baseline-stage-" in name || ".data-baseline-scratch-" in name ||
                    name.startsWith(".data-baseline-comparison-")
            }.toList()
        }
        assertEquals(emptyList(), residue)
    }

    private fun rewriteReconciliation(fixture: Fixture, mutate: (JsonObject) -> JsonObject): String {
        val original = parseObject(Files.readAllBytes(fixture.reconciliationPath))
        val mutated = mutate(original)
        val withoutHash = JsonObject(mutated.filterKeys { it != "reportSha256" })
        val rebound = JsonObject(withoutHash.toMutableMap().apply {
            this["reportSha256"] = JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutHash)))
        })
        val bytes = OracleJson.canonicalBytes(rebound)
        Files.write(fixture.reconciliationPath, bytes)
        return OracleArtifacts.sha256(bytes)
    }

    private fun rewriteBaseline(
        path: Path,
        original: JsonObject,
        mutate: (JsonObject) -> JsonObject,
    ): Pair<Path, String> {
        val mutated = mutate(original)
        val withoutHash = JsonObject(mutated.filterKeys { it != "reportSha256" })
        val rebound = JsonObject(withoutHash.toMutableMap().apply {
            this["reportSha256"] = JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutHash)))
        })
        val bytes = OracleJson.canonicalBytes(rebound)
        Files.write(path, bytes)
        return path to OracleArtifacts.sha256(bytes)
    }

    private fun createFixture(root: Path): Fixture {
        Files.createDirectories(root)
        val truthRoot = root.resolve("data truth ?#%")
        Files.createDirectories(truthRoot.resolve("shards"))
        val inventory = inventory()
        val truthIndexSha256 = truth(truthRoot, inventory)
        assertEquals(FROZEN_TRUTH_INDEX_SHA256, truthIndexSha256)
        val reconciliationPath = root.resolve("data reconciliation ?#%.json")
        val reconciliationBytes = checkNotNull(
            javaClass.getResourceAsStream("/oracle/full-tree-data-reconciliation-v1-frozen.json"),
        ).use { it.readAllBytes() }
        Files.write(reconciliationPath, reconciliationBytes)
        val reconciliationSha256 = OracleArtifacts.sha256(reconciliationBytes)
        assertEquals(FROZEN_RECONCILIATION_ARTIFACT_SHA256, reconciliationSha256)
        return Fixture(inventory, truthRoot, truthIndexSha256, reconciliationPath, reconciliationSha256)
    }

    private fun inventory(): JsonObject {
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
                        "scopeSha256" to JsonPrimitive(SCOPE_SHA256),
                        "sourceLockSha256" to JsonPrimitive(SOURCE_LOCK_SHA256),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(
                    listOf(
                        JsonObject(
                            mapOf(
                                "id" to JsonPrimitive("shard-a"),
                                "unitIds" to JsonArray(listOf(JsonPrimitive("unit-a"))),
                            ),
                        ),
                        JsonObject(
                            mapOf(
                                "id" to JsonPrimitive("shard-b"),
                                "unitIds" to JsonArray(listOf(JsonPrimitive("unit-b"))),
                            ),
                        ),
                    ),
                ),
                "units" to JsonArray(units),
            ),
        )
    }

    private fun truth(root: Path, inventory: JsonObject): String {
        val oracle = JsonObject(
            mapOf(
                "configurationSha256" to JsonPrimitive(FullTreeDataTruthSqlite.configurationSha256),
                "dataObservationIndexSha256" to JsonPrimitive("7".repeat(64)),
                "inventoryIndexSha256" to inventory.requiredElement("indexSha256"),
                "scopeSha256" to JsonPrimitive(SCOPE_SHA256),
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
            Files.write(root.resolve("shards/$id.json"), bytes)
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

    private fun parseObject(bytes: ByteArray): JsonObject = OracleJson.parseCanonical(bytes) as JsonObject

    private fun ByteArray.hex(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    private inline fun <T> inTemporaryDirectory(block: (Path) -> T): T {
        val directory = createTempDirectory("full-tree-data-baseline-test-")
        return try {
            block(directory)
        } finally {
            val paths = Files.walk(directory).use { it.toList() }
            paths.filter { Files.isDirectory(it) }.forEach { path ->
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
            }
            paths.sortedWith(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private data class Fixture(
        val inventory: JsonObject,
        val truthRoot: Path,
        val truthIndexSha256: String,
        val reconciliationPath: Path,
        val reconciliationSha256: String,
    )

    private companion object {
        const val SOURCE_LOCK_SHA256 =
            "1111111111111111111111111111111111111111111111111111111111111111"
        const val MANIFEST_SHA256 =
            "2222222222222222222222222222222222222222222222222222222222222222"
        const val RICH_SHA256 =
            "3333333333333333333333333333333333333333333333333333333333333333"
        const val SCOPE_SHA256 =
            "aeca7101bf0bdb485fc21e6257ca5c64f6321d8d1a316dbf008f7ccb96c30602"
        const val FROZEN_TRUTH_INDEX_SHA256 =
            "714ce2ecb009ded8d993610d625d361eb49ab34d3214c3a0c0158f9e7576fe78"
        const val FROZEN_RECONCILIATION_ARTIFACT_SHA256 =
            "cfcca6e636f058c9670b39495fb0d4516c1a287d54ec45b85560b5c4810bf5d4"

        // Frozen once from checked-in historical oracle/full_tree_data_baseline.py v1 on 2026-08-30.
        // Runtime and tests never import or invoke Python; these literals are inert migration provenance.
        const val FROZEN_CONFIGURATION_SHA256 =
            "27151643e613d66dc0ea9d640c3e300f9f6c1c4c835af20d6dd6913da449695d"
        const val FROZEN_REPORT_SHA256 =
            "d3203e8b4c0b7bba1563e25d080ebf7ed73616d996111e931a28fa625585ae11"
        const val FROZEN_ARTIFACT_SHA256 =
            "3ea992adf57a53677b76661ce5e0f8a81c70b1cdfb744a6276ae37f4543c9bfb"

        const val TYPE_A = "type-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val GLOBAL_IMAGE = "global-11111111111111111111111111111111"
        const val GLOBAL_TLS = "global-22222222222222222222222222222222"
        const val GLOBAL_DWARF_ONLY = "global-33333333333333333333333333333333"
        const val GLOBAL_UNOBSERVABLE = "global-44444444444444444444444444444444"
    }
}
