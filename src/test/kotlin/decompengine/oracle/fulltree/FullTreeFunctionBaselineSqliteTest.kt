package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
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

class FullTreeFunctionBaselineSqliteTest {
    @Test
    fun `Kotlin accepts the inert historical Python v1 parity artifact without invoking Python`() =
        inControlTemporaryDirectory { root ->
            val bytes = Base64.getMimeDecoder().decode(
                checkNotNull(
                    FullTreeFunctionBaselineSqliteTest::class.java.getResourceAsStream(
                        "/oracle/full-tree-function-baseline-raw-v1/expected/" +
                            "historical-python-v1-report.json.b64",
                    ),
                ).use { it.readAllBytes() },
            )
            assertEquals(HISTORICAL_FUNCTION_BASELINE_BYTES, bytes.size.toLong())
            assertEquals(HISTORICAL_FUNCTION_BASELINE_ARTIFACT_SHA256, OracleArtifacts.sha256(bytes))
            assertEquals(
                HISTORICAL_FUNCTION_BASELINE_TRUTH_INDEX_SHA256,
                OracleArtifacts.sha256(
                    Files.readAllBytes(
                        Path.of(
                            "src/test/resources/oracle/full-tree-function-truth-v2/expected-truth/index.json",
                        ),
                    ),
                ),
            )

            val reportRoot = Files.createDirectory(
                root.resolve("historical-report"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
            )
            val report = Files.write(reportRoot.resolve("report.json"), bytes)
            Files.setPosixFilePermissions(report, PosixFilePermissions.fromString("r--------"))
            val scratch = Files.createDirectory(
                root.resolve("historical-scratch"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
            )
            val validated = FullTreeFunctionBaselineSqlite.loadAndValidate(
                report = report,
                expectedArtifactSha256 = HISTORICAL_FUNCTION_BASELINE_ARTIFACT_SHA256,
                expectedTruthIndexArtifactSha256 = HISTORICAL_FUNCTION_BASELINE_TRUTH_INDEX_SHA256,
                scratchParent = scratch,
            )
            assertEquals(HISTORICAL_FUNCTION_BASELINE_REPORT_SHA256, validated.reportSha256)
            assertEquals(3, validated.aggregate.denominator)
            assertEquals(2, validated.aggregate.recovered)
            assertEquals(1, validated.aggregate.missing)
            assertEquals(0, validated.aggregate.fabricated)
            assertEquals(2, validated.aggregate.excluded)
            assertEquals(1, validated.mismatchCount)
            assertFalse(validated.authoritativeReleaseEvidence)
            assertBaselineScratchEmpty(scratch)
        }

    @Test
    fun `raw projection baseline is deterministic bounded and non-authoritative`() =
        inControlTemporaryDirectory { root ->
            val strippedBytes = Base64.getMimeDecoder().decode(
                checkNotNull(
                    FullTreeFunctionBaselineSqliteTest::class.java.getResourceAsStream(
                        "/oracle/elf-twin-v1/stripped.elf.b64",
                    ),
                ).use { it.readAllBytes() },
            )
            val fixture = createFunctionTruthFixture(
                root.resolve("baseline-inputs"),
                strippedBytesOverride = strippedBytes,
            )
            val truth = generateTruth(fixture, root.resolve("candidate-truth"), maximumWorkers = 2)
            val originalTruth = baselineTreeBytes(truth.root)

            val serial = generateBaseline(fixture, truth.root, root.resolve("baseline-serial"), 2)
            val parallel = generateBaseline(fixture, truth.root, root.resolve("baseline-parallel"), 4)

            assertEquals(FROZEN_FUNCTION_BASELINE_CONFIGURATION, FullTreeFunctionBaselineSqlite.configurationSha256)
            assertEquals(FROZEN_RAW_BASELINE_REPORT_SHA256, serial.reportSha256)
            assertEquals(FROZEN_RAW_BASELINE_ARTIFACT_SHA256, serial.artifactSha256)
            assertEquals(FROZEN_RAW_BASELINE_TRUTH_INDEX_SHA256, serial.truthIndexArtifactSha256)
            assertEquals(FROZEN_RAW_BASELINE_BYTES, serial.outputBytes)
            assertEquals(serial.reportSha256, parallel.reportSha256)
            assertEquals(serial.artifactSha256, parallel.artifactSha256)
            assertEquals(serial.truthIndexArtifactSha256, parallel.truthIndexArtifactSha256)
            assertEquals(serial.outputBytes, parallel.outputBytes)
            assertEquals(serial.aggregate, parallel.aggregate)
            assertContentEquals(
                Files.readAllBytes(root.resolve("baseline-serial/report.json")),
                Files.readAllBytes(root.resolve("baseline-parallel/report.json")),
            )

            val singleWorkerFixture = createFunctionTruthFixture(
                root.resolve("baseline-inputs-single-worker"),
                observationWorkers = 1,
                strippedBytesOverride = strippedBytes,
            )
            val singleWorkerTruth = generateTruth(
                singleWorkerFixture,
                root.resolve("candidate-truth-single-worker"),
                maximumWorkers = 1,
            )
            val singleWorker = generateBaseline(
                singleWorkerFixture,
                singleWorkerTruth.root,
                root.resolve("baseline-single-worker"),
                1,
            )
            assertEquals(serial.aggregate, singleWorker.aggregate)
            assertEquals(
                baselineSemantics(parseControlObject(root.resolve("baseline-serial/report.json"))),
                baselineSemantics(parseControlObject(root.resolve("baseline-single-worker/report.json"))),
            )
            assertBaselineScratchEmpty(singleWorkerFixture.scratch)
            assertContentEquals(
                Base64.getMimeDecoder().decode(
                    checkNotNull(
                        FullTreeFunctionBaselineSqliteTest::class.java.getResourceAsStream(
                            "/oracle/full-tree-function-baseline-raw-v1/expected/report.json.b64",
                        ),
                    ).use { it.readAllBytes() },
                ),
                Files.readAllBytes(root.resolve("baseline-serial/report.json")),
            )
            assertEquals(
                FullTreeFunctionBaselineMetric(
                    denominator = 2,
                    recovered = 0,
                    missing = 2,
                    fabricated = 0,
                    excluded = 3,
                ),
                serial.aggregate,
            )
            assertFalse(serial.candidateLeaseRetained)
            assertFalse(serial.downstreamScoringAuthorized)
            assertFalse(serial.authoritativeReleaseEvidence)
            assertTrue(serial.derivationScratchHighWaterBytes > 0L)
            assertEquals(originalTruth, baselineTreeBytes(truth.root))
            assertBaselineScratchEmpty(fixture.scratch)

            val validated = FullTreeFunctionBaselineSqlite.loadAndValidate(
                report = root.resolve("baseline-serial/report.json"),
                expectedArtifactSha256 = serial.artifactSha256,
                expectedTruthIndexArtifactSha256 = truth.indexArtifactSha256,
                scratchParent = fixture.scratch,
            )
            assertEquals(serial.reportSha256, validated.reportSha256)
            assertEquals(serial.artifactSha256, validated.artifactSha256)
            assertEquals(serial.truthIndexArtifactSha256, validated.truthIndexArtifactSha256)
            assertEquals(serial.outputBytes, validated.bytes)
            assertEquals(3, validated.shardCount)
            assertEquals(2, validated.mismatchCount)
            assertEquals(serial.aggregate, validated.aggregate)
            assertFalse(validated.authoritativeReleaseEvidence)
            assertBaselineScratchEmpty(fixture.scratch)

            FullTreeFunctionBaselineSqlite.requireNoRegression(
                current = root.resolve("baseline-serial/report.json"),
                currentArtifactSha256 = serial.artifactSha256,
                currentTruthIndexArtifactSha256 = truth.indexArtifactSha256,
                accepted = root.resolve("baseline-parallel/report.json"),
                acceptedArtifactSha256 = parallel.artifactSha256,
                acceptedTruthIndexArtifactSha256 = truth.indexArtifactSha256,
                scratchParent = fixture.scratch,
            )
            assertBaselineScratchEmpty(fixture.scratch)

            val occupied = root.resolve("occupied-baseline")
            val sentinel = "preserve occupied function baseline\n".toByteArray()
            Files.write(occupied, sentinel)
            assertFailsWith<FullTreeFunctionTruthException> {
                generateBaseline(fixture, truth.root, occupied, 2)
            }
            assertContentEquals(sentinel, Files.readAllBytes(occupied))
            assertEquals(originalTruth, baselineTreeBytes(truth.root))
            assertBaselineScratchEmpty(fixture.scratch)
        }

    @Test
    fun `validation and regression gates reject self-consistent hostile reports`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFunctionTruthFixture(root.resolve("regression-inputs"))
            val truth = generateTruth(fixture, root.resolve("regression-truth"), maximumWorkers = 2)
            val accepted = generateBaseline(fixture, truth.root, root.resolve("accepted-baseline"), 2)
            val acceptedPath = root.resolve("accepted-baseline/report.json")
            val acceptedDocument = parseControlObject(acceptedPath)

            assertFailsWith<FullTreeFunctionBaselineException> {
                FullTreeFunctionBaselineSqlite.loadAndValidate(
                    acceptedPath,
                    accepted.artifactSha256,
                    "0".repeat(64),
                    fixture.scratch,
                )
            }
            assertBaselineScratchEmpty(fixture.scratch)

            val uncoveredFabrication = mutateBaselineMetric(
                acceptedDocument,
                metricMutation = { metric -> metric.withDelta(fabricated = 1) },
                aggregateMutation = { metric -> metric.withDelta(fabricated = 1) },
            )
            val uncovered = writeBaselineCandidate(
                root.resolve("uncovered-fabrication"),
                uncoveredFabrication,
            )
            assertFailsWith<FullTreeFunctionBaselineException> {
                validateBaselineCandidate(uncovered, truth.indexArtifactSha256, fixture.scratch)
            }
            assertBaselineScratchEmpty(fixture.scratch)

            val wrongShardFabrication = writeBaselineCandidate(
                root.resolve("wrong-shard-fabrication"),
                moveFabricatedMismatchToWrongShard(mutateFabricated(acceptedDocument)),
            )
            val wrongShardFailure = assertFailsWith<FullTreeFunctionBaselineException> {
                validateBaselineCandidate(
                    wrongShardFabrication,
                    truth.indexArtifactSha256,
                    fixture.scratch,
                )
            }
            assertTrue(wrongShardFailure.message.orEmpty().contains("shard metrics"))
            assertBaselineScratchEmpty(fixture.scratch)

            val duplicateShardDocument = rehashBaseline(
                JsonObject(
                    acceptedDocument.toMutableMap().apply {
                        val shards = (getValue("shards") as JsonArray).toMutableList()
                        shards.add(0, shards.first())
                        this["shards"] = JsonArray(shards)
                    },
                ),
            )
            val duplicate = writeBaselineCandidate(root.resolve("duplicate-shard"), duplicateShardDocument)
            assertFailsWith<FullTreeFunctionBaselineException> {
                validateBaselineCandidate(duplicate, truth.indexArtifactSha256, fixture.scratch)
            }
            assertBaselineScratchEmpty(fixture.scratch)

            val regressedDocument = mutateRecoveredToMissing(acceptedDocument)
            val regressed = writeBaselineCandidate(root.resolve("recovered-regression"), regressedDocument)
            val regressedBinding = validateBaselineCandidate(regressed, truth.indexArtifactSha256, fixture.scratch)
            assertEquals(1, regressedBinding.mismatchCount)
            val recoveredFailure = assertFailsWith<FullTreeFunctionBaselineException> {
                compareBaselineCandidates(
                    current = regressed,
                    accepted = acceptedPath,
                    acceptedArtifactSha256 = accepted.artifactSha256,
                    truthIndexSha256 = truth.indexArtifactSha256,
                    scratch = fixture.scratch,
                )
            }
            assertTrue(
                recoveredFailure.message.orEmpty().contains("introduced mismatch identity") ||
                    recoveredFailure.message.orEmpty().contains("regressed"),
            )
            assertBaselineScratchEmpty(fixture.scratch)

            val denominatorDocument = mutateDenominator(acceptedDocument)
            val denominator = writeBaselineCandidate(root.resolve("denominator-drift"), denominatorDocument)
            validateBaselineCandidate(denominator, truth.indexArtifactSha256, fixture.scratch)
            val denominatorFailure = assertFailsWith<FullTreeFunctionBaselineException> {
                compareBaselineCandidates(
                    denominator,
                    acceptedPath,
                    accepted.artifactSha256,
                    truth.indexArtifactSha256,
                    fixture.scratch,
                )
            }
            assertTrue(denominatorFailure.message.orEmpty().contains("denominator drifted"))
            assertBaselineScratchEmpty(fixture.scratch)

            val fabricatedDocument = mutateFabricated(acceptedDocument)
            val fabricated = writeBaselineCandidate(root.resolve("fabricated-regression"), fabricatedDocument)
            validateBaselineCandidate(fabricated, truth.indexArtifactSha256, fixture.scratch)
            val fabricatedFailure = assertFailsWith<FullTreeFunctionBaselineException> {
                compareBaselineCandidates(
                    fabricated,
                    acceptedPath,
                    accepted.artifactSha256,
                    truth.indexArtifactSha256,
                    fixture.scratch,
                )
            }
            assertTrue(
                fabricatedFailure.message.orEmpty().contains("introduced mismatch identity") ||
                    fabricatedFailure.message.orEmpty().contains("regressed"),
            )
            assertBaselineScratchEmpty(fixture.scratch)

            val disappearedDocument = removeShard(acceptedDocument)
            val disappeared = writeBaselineCandidate(root.resolve("shard-disappearance"), disappearedDocument)
            validateBaselineCandidate(disappeared, truth.indexArtifactSha256, fixture.scratch)
            val disappearanceFailure = assertFailsWith<FullTreeFunctionBaselineException> {
                compareBaselineCandidates(
                    disappeared,
                    acceptedPath,
                    accepted.artifactSha256,
                    truth.indexArtifactSha256,
                    fixture.scratch,
                )
            }
            assertTrue(disappearanceFailure.message.orEmpty().contains("shard population drifted"))
            assertBaselineScratchEmpty(fixture.scratch)

            val acceptedWithMissing = writeBaselineCandidate(
                root.resolve("accepted-with-missing"),
                mutateRecoveredToMissing(acceptedDocument),
            )
            val acceptedWithMissingBinding = validateBaselineCandidate(
                acceptedWithMissing,
                truth.indexArtifactSha256,
                fixture.scratch,
            )
            val swappedMismatch = writeBaselineCandidate(
                root.resolve("swapped-mismatch"),
                replaceFirstMissingIdentity(parseControlObject(acceptedWithMissing)),
            )
            validateBaselineCandidate(swappedMismatch, truth.indexArtifactSha256, fixture.scratch)
            val identityFailure = assertFailsWith<FullTreeFunctionBaselineException> {
                compareBaselineCandidates(
                    swappedMismatch,
                    acceptedWithMissing,
                    acceptedWithMissingBinding.artifactSha256,
                    truth.indexArtifactSha256,
                    fixture.scratch,
                )
            }
            assertTrue(identityFailure.message.orEmpty().contains("introduced mismatch identity"))
            assertBaselineScratchEmpty(fixture.scratch)

            val excludedDrift = writeBaselineCandidate(
                root.resolve("excluded-drift"),
                moveExcludedBetweenShards(acceptedDocument),
            )
            validateBaselineCandidate(excludedDrift, truth.indexArtifactSha256, fixture.scratch)
            val excludedFailure = assertFailsWith<FullTreeFunctionBaselineException> {
                compareBaselineCandidates(
                    excludedDrift,
                    acceptedPath,
                    accepted.artifactSha256,
                    truth.indexArtifactSha256,
                    fixture.scratch,
                )
            }
            assertTrue(excludedFailure.message.orEmpty().contains("excluded population drifted"))
            assertBaselineScratchEmpty(fixture.scratch)

            val truthPopulationFailure = assertFailsWith<FullTreeFunctionBaselineException> {
                FullTreeFunctionBaselineSqlite.requireNoRegression(
                    current = acceptedPath,
                    currentArtifactSha256 = accepted.artifactSha256,
                    currentTruthIndexArtifactSha256 = "0".repeat(64),
                    accepted = acceptedPath,
                    acceptedArtifactSha256 = accepted.artifactSha256,
                    acceptedTruthIndexArtifactSha256 = truth.indexArtifactSha256,
                    scratchParent = fixture.scratch,
                )
            }
            assertTrue(truthPopulationFailure.message.orEmpty().contains("truth population differs"))
            assertBaselineScratchEmpty(fixture.scratch)
        }

    @Test
    fun `generation and validation limits fail closed and clean private state`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFunctionTruthFixture(root.resolve("bounded-inputs"))
            val truth = generateTruth(fixture, root.resolve("bounded-truth"), maximumWorkers = 2)
            val originalTruth = baselineTreeBytes(truth.root)

            val entityBoundOutput = root.resolve("entity-bound-output")
            assertFailsWith<FullTreeFunctionTruthException> {
                generateBaseline(
                    fixture,
                    truth.root,
                    entityBoundOutput,
                    2,
                    FullTreeFunctionBaselineLimits(maximumEntities = 1),
                )
            }
            assertFalse(Files.exists(entityBoundOutput, LinkOption.NOFOLLOW_LINKS))
            assertEquals(originalTruth, baselineTreeBytes(truth.root))
            assertBaselineScratchEmpty(fixture.scratch)

            val scratchBoundOutput = root.resolve("scratch-bound-output")
            assertFailsWith<FullTreeFunctionTruthException> {
                generateBaseline(
                    fixture,
                    truth.root,
                    scratchBoundOutput,
                    2,
                    FullTreeFunctionBaselineLimits(
                        maximumDatabaseBytes = 4096,
                        maximumScratchBytes = 4096,
                    ),
                )
            }
            assertFalse(Files.exists(scratchBoundOutput, LinkOption.NOFOLLOW_LINKS))
            assertEquals(originalTruth, baselineTreeBytes(truth.root))
            assertBaselineScratchEmpty(fixture.scratch)

            val accepted = generateBaseline(fixture, truth.root, root.resolve("bounded-accepted"), 2)
            assertFailsWith<FullTreeFunctionBaselineException> {
                FullTreeFunctionBaselineSqlite.loadAndValidate(
                    report = root.resolve("bounded-accepted/report.json"),
                    expectedArtifactSha256 = accepted.artifactSha256,
                    expectedTruthIndexArtifactSha256 = truth.indexArtifactSha256,
                    scratchParent = fixture.scratch,
                    limits = FullTreeFunctionBaselineLimits(
                        maximumBaselineBytes = 128,
                        maximumTotalStringBytes = 128,
                    ),
                )
            }
            assertBaselineScratchEmpty(fixture.scratch)
        }
}

private fun generateBaseline(
    fixture: FunctionTruthFixture,
    candidate: Path,
    output: Path,
    maximumWorkers: Int,
    limits: FullTreeFunctionBaselineLimits = FullTreeFunctionBaselineLimits(),
): FullTreeFunctionBaselineGeneration = FullTreeFunctionTruthSqlite.generateBaselineAndPublish(
    candidateRoot = candidate,
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

private fun validateBaselineCandidate(
    path: Path,
    truthIndexSha256: String,
    scratch: Path,
): FullTreeFunctionBaselineValidation {
    val artifact = OracleArtifacts.sha256(Files.readAllBytes(path))
    return FullTreeFunctionBaselineSqlite.loadAndValidate(
        path,
        artifact,
        truthIndexSha256,
        scratch,
    )
}

private fun compareBaselineCandidates(
    current: Path,
    accepted: Path,
    acceptedArtifactSha256: String,
    truthIndexSha256: String,
    scratch: Path,
) = FullTreeFunctionBaselineSqlite.requireNoRegression(
    current = current,
    currentArtifactSha256 = OracleArtifacts.sha256(Files.readAllBytes(current)),
    currentTruthIndexArtifactSha256 = truthIndexSha256,
    accepted = accepted,
    acceptedArtifactSha256 = acceptedArtifactSha256,
    acceptedTruthIndexArtifactSha256 = truthIndexSha256,
    scratchParent = scratch,
)

private fun mutateRecoveredToMissing(document: JsonObject): JsonObject {
    val shards = document.baselineTestArray("shards").map { raw -> raw as JsonObject }.toMutableList()
    val index = shards.indexOfFirst { shard ->
        shard.baselineTestObject("metric").baselineTestLong("recovered") > 0
    }
    val selected = shards[index]
    val shardId = selected.baselineTestString("id")
    val metric = selected.baselineTestObject("metric").withDelta(recovered = -1, missing = 1)
    shards[index] = JsonObject(selected.toMutableMap().apply { this["metric"] = metric })
    val truthId = "function-rva-0x1129"
    val mismatches = document.baselineTestArray("mismatches").toMutableList().apply {
        add(baselineTestMismatch("missing", truthId, shardId))
        sortBy { (it as JsonObject).baselineTestString("id") }
    }
    return rehashBaseline(
        JsonObject(
            document.toMutableMap().apply {
                this["aggregate"] = document.baselineTestObject("aggregate").withDelta(
                    recovered = -1,
                    missing = 1,
                )
                this["mismatches"] = JsonArray(mismatches)
                this["shards"] = JsonArray(shards)
            },
        ),
    )
}

private fun mutateDenominator(document: JsonObject): JsonObject {
    val shards = document.baselineTestArray("shards").map { it as JsonObject }.toMutableList()
    val index = shards.indexOfFirst { it.baselineTestString("id") != "elf-only-exclusions" }
    val selected = shards[index]
    val shardId = selected.baselineTestString("id")
    shards[index] = JsonObject(
        selected.toMutableMap().apply {
            this["metric"] = selected.baselineTestObject("metric").withDelta(missing = 1)
        },
    )
    val truthId = "function-rva-0xfeed"
    val mismatches = document.baselineTestArray("mismatches").toMutableList().apply {
        add(baselineTestMismatch("missing", truthId, shardId))
        sortBy { (it as JsonObject).baselineTestString("id") }
    }
    return rehashBaseline(
        JsonObject(
            document.toMutableMap().apply {
                this["aggregate"] = document.baselineTestObject("aggregate").withDelta(missing = 1)
                this["mismatches"] = JsonArray(mismatches)
                this["shards"] = JsonArray(shards)
            },
        ),
    )
}

private fun mutateFabricated(document: JsonObject): JsonObject {
    val shards = document.baselineTestArray("shards").map { it as JsonObject }.toMutableList()
    val index = shards.indexOfFirst { it.baselineTestString("id") != "elf-only-exclusions" }
    val selected = shards[index]
    shards[index] = JsonObject(
        selected.toMutableMap().apply {
            this["metric"] = selected.baselineTestObject("metric").withDelta(fabricated = 1)
        },
    )
    val truthId = "fabricated-fixture"
    val mismatches = document.baselineTestArray("mismatches").toMutableList().apply {
        add(baselineTestMismatch("fabricated", truthId, null))
        sortBy { (it as JsonObject).baselineTestString("id") }
    }
    return rehashBaseline(
        JsonObject(
            document.toMutableMap().apply {
                this["aggregate"] = document.baselineTestObject("aggregate").withDelta(fabricated = 1)
                this["mismatches"] = JsonArray(mismatches)
                this["shards"] = JsonArray(shards)
            },
        ),
    )
}

private fun moveFabricatedMismatchToWrongShard(document: JsonObject): JsonObject {
    val metricOwner = document.baselineTestArray("shards")
        .map { it as JsonObject }
        .single { it.baselineTestObject("metric").baselineTestLong("fabricated") > 0L }
        .baselineTestString("id")
    val wrongOwner = document.baselineTestArray("shards")
        .map { it as JsonObject }
        .first { it.baselineTestString("id") != metricOwner }
        .baselineTestString("id")
    val mismatches = document.baselineTestArray("mismatches").map { raw ->
        val mismatch = raw as JsonObject
        if (mismatch.baselineTestString("kind") != "fabricated") {
            mismatch
        } else {
            JsonObject(mismatch.toMutableMap().apply { this["shardId"] = JsonPrimitive(wrongOwner) })
        }
    }
    return rehashBaseline(
        JsonObject(document.toMutableMap().apply { this["mismatches"] = JsonArray(mismatches) }),
    )
}

private fun replaceFirstMissingIdentity(document: JsonObject): JsonObject {
    var replaced = false
    val mismatches = document.baselineTestArray("mismatches").map { raw ->
        val mismatch = raw as JsonObject
        if (replaced || mismatch.baselineTestString("kind") != "missing") {
            mismatch
        } else {
            replaced = true
            baselineTestMismatch(
                kind = "missing",
                truthId = mismatch.baselineTestString("truthId") + "-replacement",
                shardId = mismatch.baselineTestString("shardId"),
            )
        }
    }.sortedBy { it.baselineTestString("id") }
    check(replaced)
    return rehashBaseline(
        JsonObject(document.toMutableMap().apply { this["mismatches"] = JsonArray(mismatches) }),
    )
}

private fun moveExcludedBetweenShards(document: JsonObject): JsonObject {
    val shards = document.baselineTestArray("shards").map { it as JsonObject }.toMutableList()
    val sourceIndex = shards.indexOfFirst { it.baselineTestObject("metric").baselineTestLong("excluded") > 0L }
    check(sourceIndex >= 0)
    val targetIndex = shards.indices.first { it != sourceIndex }
    val source = shards[sourceIndex]
    val target = shards[targetIndex]
    shards[sourceIndex] = JsonObject(
        source.toMutableMap().apply {
            this["metric"] = source.baselineTestObject("metric").withDelta(excluded = -1)
        },
    )
    shards[targetIndex] = JsonObject(
        target.toMutableMap().apply {
            this["metric"] = target.baselineTestObject("metric").withDelta(excluded = 1)
        },
    )
    return rehashBaseline(
        JsonObject(document.toMutableMap().apply { this["shards"] = JsonArray(shards) }),
    )
}

private fun mutateBaselineMetric(
    document: JsonObject,
    metricMutation: (JsonObject) -> JsonObject,
    aggregateMutation: (JsonObject) -> JsonObject,
): JsonObject {
    val shards = document.baselineTestArray("shards").map { it as JsonObject }.toMutableList()
    val index = shards.indexOfFirst { it.baselineTestString("id") != "elf-only-exclusions" }
    val selected = shards[index]
    shards[index] = JsonObject(
        selected.toMutableMap().apply {
            this["metric"] = metricMutation(selected.baselineTestObject("metric"))
        },
    )
    return rehashBaseline(
        JsonObject(
            document.toMutableMap().apply {
                this["aggregate"] = aggregateMutation(document.baselineTestObject("aggregate"))
                this["shards"] = JsonArray(shards)
            },
        ),
    )
}

private fun removeShard(document: JsonObject): JsonObject {
    val shards = document.baselineTestArray("shards").map { it as JsonObject }.toMutableList()
    val removedIndex = shards.indexOfFirst { shard ->
        shard.baselineTestString("id") != "elf-only-exclusions"
    }
    check(removedIndex >= 0)
    val removed = shards.removeAt(removedIndex).baselineTestObject("metric")
    return rehashBaseline(
        JsonObject(
            document.toMutableMap().apply {
                this["aggregate"] = document.baselineTestObject("aggregate").withDelta(
                    recovered = -removed.baselineTestLong("recovered"),
                    missing = -removed.baselineTestLong("missing"),
                    fabricated = -removed.baselineTestLong("fabricated"),
                    excluded = -removed.baselineTestLong("excluded"),
                )
                this["shards"] = JsonArray(shards)
            },
        ),
    )
}

private fun JsonObject.withDelta(
    recovered: Long = 0,
    missing: Long = 0,
    fabricated: Long = 0,
    excluded: Long = 0,
): JsonObject {
    val updatedRecovered = baselineTestLong("recovered") + recovered
    val updatedMissing = baselineTestLong("missing") + missing
    return JsonObject(
        toMutableMap().apply {
            this["denominator"] = JsonPrimitive(updatedRecovered + updatedMissing)
            this["excluded"] = JsonPrimitive(baselineTestLong("excluded") + excluded)
            this["fabricated"] = JsonPrimitive(baselineTestLong("fabricated") + fabricated)
            this["missing"] = JsonPrimitive(updatedMissing)
            this["recallDenominator"] = JsonPrimitive(updatedRecovered + updatedMissing)
            this["recallNumerator"] = JsonPrimitive(updatedRecovered)
            this["recovered"] = JsonPrimitive(updatedRecovered)
        },
    )
}

private fun baselineTestMismatch(kind: String, truthId: String, shardId: String?): JsonObject {
    val preimage = JsonObject(mapOf("kind" to JsonPrimitive(kind), "truthId" to JsonPrimitive(truthId)))
    val id = "$kind-function-${OracleArtifacts.sha256(OracleJson.canonicalBytes(preimage)).take(32)}"
    return JsonObject(
        mapOf(
            "id" to JsonPrimitive(id),
            "kind" to JsonPrimitive(kind),
            "shardId" to (shardId?.let(::JsonPrimitive) ?: kotlinx.serialization.json.JsonNull),
            "truthId" to JsonPrimitive(truthId),
        ),
    )
}

private fun rehashBaseline(document: JsonObject): JsonObject {
    val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
    return JsonObject(
        withoutHash + (
            "reportSha256" to JsonPrimitive(
                OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutHash)),
            )
        ),
    )
}

private fun baselineSemantics(document: JsonObject): JsonObject = JsonObject(
    document.filterKeys { it != "reportSha256" && it != "truthIndexSha256" },
)

private fun writeBaselineCandidate(root: Path, document: JsonObject): Path {
    Files.createDirectory(
        root,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
    )
    val report = root.resolve("report.json")
    Files.write(report, OracleJson.canonicalBytes(document))
    Files.setPosixFilePermissions(report, PosixFilePermissions.fromString("r--------"))
    Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("r-x------"))
    return report
}

private fun baselineTreeBytes(root: Path): Map<String, List<Byte>> = Files.walk(root).use { paths ->
    paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }
        .sorted()
        .toList()
        .associate { path -> root.relativize(path).toString() to Files.readAllBytes(path).toList() }
}

private fun assertBaselineScratchEmpty(path: Path) {
    assertTrue(Files.list(path).use { entries -> entries.findAny().isEmpty })
}

private fun JsonObject.baselineTestString(name: String): String = (getValue(name) as JsonPrimitive).content
private fun JsonObject.baselineTestLong(name: String): Long = (getValue(name) as JsonPrimitive).content.toLong()
private fun JsonObject.baselineTestObject(name: String): JsonObject = getValue(name) as JsonObject
private fun JsonObject.baselineTestArray(name: String): JsonArray = getValue(name) as JsonArray

private const val FROZEN_FUNCTION_BASELINE_CONFIGURATION =
    "c29ef7047ba26e9165e78faffd5781711923f75c1fb265e5f615bfd1ffd21951"
private const val FROZEN_RAW_BASELINE_REPORT_SHA256 =
    "8f8f9e23f81c7def19b9f74ab6b5e8df45ca1bedba9505ccb6322ee5733feda6"
private const val FROZEN_RAW_BASELINE_ARTIFACT_SHA256 =
    "3771bc71bda4e054d766c0ee6ecdc3599b85fa22326e8ee537da20079e807c06"
private const val FROZEN_RAW_BASELINE_TRUTH_INDEX_SHA256 =
    "184b25045d17802b46ce3c91daf834a13023aaf7931127dbe946ba388ece9316"
private const val FROZEN_RAW_BASELINE_BYTES = 1636L
private const val HISTORICAL_FUNCTION_BASELINE_REPORT_SHA256 =
    "58dd10d9ccf82c66d0d87bbbeb917f42cecf4d9a682558098d82a4bc62ac0295"
private const val HISTORICAL_FUNCTION_BASELINE_ARTIFACT_SHA256 =
    "6190f0719ebc52ab01159a4f35455a6113d4b3039baa7116e9d417ff7bb8efa3"
private const val HISTORICAL_FUNCTION_BASELINE_TRUTH_INDEX_SHA256 =
    "9f6a6e61cee7a63e538fc76104fd0b51f564405ef31ba416b131248d00e9b907"
private const val HISTORICAL_FUNCTION_BASELINE_BYTES = 1455L
