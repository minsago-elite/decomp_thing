package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.Comparator
import java.util.concurrent.TimeUnit
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

class FullTreeFunctionTruthSqliteV3Test {
    @Test
    fun `truth v3 combined resource bounds admit exact limits and reject one over`() {
        assertEquals(10L, fullTreeFunctionTruthV3CombinedEntityCount(4L, 6L, 10L))
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionTruthV3CombinedEntityCount(4L, 7L, 10L)
        }
        assertTrue(fullTreeFunctionTruthV3HasOnlyEmittedRvaLinks(
            listOf("emitted-rva-from-another-shard"), setOf("emitted-rva-from-another-shard"),
        ), "a source link may name an emitted score row owned by another shard")
        assertFalse(fullTreeFunctionTruthV3HasOnlyEmittedRvaLinks(
            listOf("rva-absent-from-full-run"), setOf("emitted-rva-from-another-shard"),
        ), "a source link must not name an off-run RVA")
        assertEquals(10L, FullTreeFunctionTruthSqliteV3.reserveV3OutputBytes(0L, 10L, 10L))
        assertFailsWith<IllegalArgumentException> {
            FullTreeFunctionTruthSqliteV3.reserveV3OutputBytes(0L, 10L, 9L)
        }

        val nestedAtLimit = fullTreeFunctionTruthV3NestedScratchPlan(
            remainingBytes = 10L,
            databaseMinimumBytes = 8L,
            maximumScratchBytes = 16L,
            maximumOutputBytes = 4L,
        )
        assertEquals(8L, nestedAtLimit.maximumScratchBytes)
        assertEquals(2L, nestedAtLimit.maximumOutputBytes)
        assertEquals(10L, nestedAtLimit.maximumScratchBytes + nestedAtLimit.maximumOutputBytes)
        val oneByteOfRoom = fullTreeFunctionTruthV3NestedScratchPlan(9L, 8L, 16L, 4L)
        assertEquals(8L, oneByteOfRoom.maximumScratchBytes)
        assertEquals(1L, oneByteOfRoom.maximumOutputBytes)
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionTruthV3NestedScratchPlan(8L, 8L, 16L, 4L)
        }

        val observed = 100L
        val truth = 50L
        val projected = 200L
        val retainedControl = 80L
        val exactWorkingSet = fullTreeFunctionTruthV3ModeledWorkingSetBytes(observed, truth, projected, retainedControl)
        assertEquals(exactWorkingSet, fullTreeFunctionTruthV3AdmitWorkingSet(
            observed, truth, projected, retainedControl, exactWorkingSet,
        ))
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionTruthV3AdmitWorkingSet(observed, truth, projected, retainedControl, exactWorkingSet - 1L)
        }
        assertEquals(exactWorkingSet, fullTreeFunctionTruthV3AdmitShardWorkingSet(
            observed, truth, projected, retainedControl, exactWorkingSet + 100L, exactWorkingSet,
        ))
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionTruthV3AdmitShardWorkingSet(
                observed, truth, projected, retainedControl, exactWorkingSet + 100L, exactWorkingSet - 1L,
            )
        }
        fullTreeFunctionTruthV3CheckResidentBytes(95L, 100L, 200L, 100L)
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionTruthV3CheckResidentBytes(101L, 101L, 200L, 100L)
        }
        // A prior operation's high-water mark remains a whole-run constraint, not a new shard's limit.
        fullTreeFunctionTruthV3CheckResidentBytes(95L, 150L, 200L, 100L)
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionTruthV3CheckResidentBytes(95L, 201L, 200L, 100L)
        }

        val tight = tightScratchLimits()
        val sharedScratchLimits = tight.copy(
            truth = tight.truth.copy(
                maximumDatabaseBytes = 8L * 1024L * 1024L * 1024L,
                maximumScratchBytes = 8L * 1024L * 1024L * 1024L,
            ),
            observationV2 = tight.observationV2.copy(maximumScratchBytes = 1024L * 1024L * 1024L),
            maximumScratchBytes = 16L * 1024L * 1024L * 1024L,
        )
        assertEquals(16L * 1024L * 1024L * 1024L, fullTreeFunctionTruthV3SharedScratchBound(sharedScratchLimits))
        assertTrue(fullTreeFunctionTruthV3HasDatabaseScratchCapacity(sharedScratchLimits))
        assertTrue(sharedScratchLimits.observationV2.maximumScratchBytes < sharedScratchLimits.maximumScratchBytes)
        assertTrue(sharedScratchLimits.truth.maximumScratchBytes < sharedScratchLimits.maximumScratchBytes)

        assertEquals(6L to 4L, fullTreeFunctionTruthV3AccumulateShardBudget(0L, 0L, 6L, 4L, 10L, 10L))
        assertEquals(10L to 10L, fullTreeFunctionTruthV3AccumulateShardBudget(6L, 4L, 4L, 6L, 10L, 10L))
        assertFailsWith<IllegalArgumentException> {
            // Each phase is below the authenticated cap, but their accumulated wall time is not.
            fullTreeFunctionTruthV3AccumulateShardBudget(6L, 0L, 5L, 0L, 10L, 10L)
        }
        assertFailsWith<IllegalArgumentException> {
            // Cumulative CPU is checked independently of wall time.
            fullTreeFunctionTruthV3AccumulateShardBudget(0L, 7L, 0L, 4L, 10L, 10L)
        }

        var wallNanos = 0L
        var cpuNanos = 0L
        val ledger = FullTreeFunctionTruthV3ShardPhaseLedger(
            maximumWallNanos = 10L,
            maximumCpuNanos = 10L,
            wallClock = { wallNanos },
            cpuClock = { cpuNanos },
        )
        FullTreeOracleOperationCheckpoint.withCheckpoint({}, ledger) {
            FullTreeOracleOperationCheckpoint.withShardPhase("nested-shard") {
                wallNanos += 2L
                cpuNanos += 2L
                FullTreeOracleOperationCheckpoint.withShardPhase("nested-shard") {
                    assertEquals(1, ledger.activeShardCount())
                    wallNanos += 3L
                    cpuNanos += 3L
                }
            }
            FullTreeOracleOperationCheckpoint.withShardPhase("nested-shard") {
                wallNanos += 5L
                cpuNanos += 5L
            }
            assertFailsWith<IllegalArgumentException>("nested callbacks share one cumulative shard wall/CPU budget") {
                FullTreeOracleOperationCheckpoint.withShardPhase("nested-shard") {
                    wallNanos += 1L
                    cpuNanos += 1L
                }
            }
        }
    }

    @Test
    fun `truth v3 rederives observation census and preserves one score row per RVA`() =
        inControlTemporaryDirectory { root ->
            val fixture = createCompilerFixture(root, perShardResidentBytes = 1792L * 1024L * 1024L)
            val limits = tightScratchLimits().copy(maximumRetainedWorkingSetBytes = 2L * 1024L * 1024L * 1024L)
            val first = FullTreeFunctionTruthSqliteV3.generateAndPublish(
                richArtifact = fixture.rich,
                strippedArtifact = fixture.stripped,
                inventoryPath = fixture.inventoryPath,
                elfFunctionIndex = fixture.elfIndex,
                observationV2Root = fixture.observationV2Root,
                expectedObservationV2IndexArtifactSha256 = fixture.observationV2IndexSha256,
                scope = fixture.scope,
                scratchParent = fixture.scratch,
                outputRoot = root.resolve("truth-v3-first"),
                limits = limits,
            )
            val second = FullTreeFunctionTruthSqliteV3.generateAndPublish(
                richArtifact = fixture.rich,
                strippedArtifact = fixture.stripped,
                inventoryPath = fixture.inventoryPath,
                elfFunctionIndex = fixture.elfIndex,
                observationV2Root = fixture.observationV2Root,
                expectedObservationV2IndexArtifactSha256 = fixture.observationV2IndexSha256,
                scope = fixture.scope,
                scratchParent = fixture.scratch,
                outputRoot = root.resolve("truth-v3-second"),
                limits = limits.copy(
                    maximumOutputBytes = first.outputBytes,
                    truth = limits.truth.copy(maximumOutputBytes = minOf(limits.truth.maximumOutputBytes, first.outputBytes - 1L)),
                ),
            )

            val narrowNestedTruthOutput = minOf(limits.truth.maximumOutputBytes, first.outputBytes - 1L)
            assertTrue(narrowNestedTruthOutput < first.outputBytes, "V3's census output must have its own output allowance")
            assertFailsWith<FullTreeFunctionTruthV3Exception>("one byte below generated V3 bytes must reject publication") {
                FullTreeFunctionTruthSqliteV3.generateAndPublish(
                    richArtifact = fixture.rich,
                    strippedArtifact = fixture.stripped,
                    inventoryPath = fixture.inventoryPath,
                    elfFunctionIndex = fixture.elfIndex,
                    observationV2Root = fixture.observationV2Root,
                    expectedObservationV2IndexArtifactSha256 = fixture.observationV2IndexSha256,
                    scope = fixture.scope,
                    scratchParent = fixture.scratch,
                    outputRoot = root.resolve("truth-v3-one-over-output-limit"),
                    limits = limits.copy(
                        maximumOutputBytes = first.outputBytes - 1L,
                        truth = limits.truth.copy(maximumOutputBytes = narrowNestedTruthOutput),
                    ),
                )
            }
            assertFalse(Files.exists(root.resolve("truth-v3-one-over-output-limit")))

            assertEquals(first.index, second.index)
            assertEquals(first.indexArtifactSha256, second.indexArtifactSha256)
            assertEquals(first.indexSha256, second.indexSha256)
            assertEquals(first.counts, second.counts)
            assertEquals(v3TreeBytes(first.root), v3TreeBytes(second.root))
            writeFixtureVector(fixture, first)
            assertFalse(first.authoritativeReleaseEvidence)
            assertFalse(first.productionQualification)
            assertFalse(first.downstreamScoringAuthorized)
            assertEquals(FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME, OracleSchemas.identity(
                FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME,
            ).name)
            assertEquals(FullTreeFunctionTruthSqliteV3.INDEX_SCHEMA_NAME, OracleSchemas.identity(
                FullTreeFunctionTruthSqliteV3.INDEX_SCHEMA_NAME,
            ).name)
            assertEquals("full-tree-function-truth", FullTreeFunctionTruthSqliteV3.producerPolicy.controlString("id"))
            assertEquals(3L, FullTreeFunctionTruthSqliteV3.producerPolicy.controlLong("version"))
            assertEquals(
                "b21be27d085c61c60cbaba11da1208b24c897c264001c790b0ca32b2ae24e5f7",
                OracleSchemas.identity("full-tree-function-truth").sha256,
                "the v2 shard schema bytes must stay frozen",
            )
            assertEquals(
                "40a2c4d0c3a1b3317e010fd267b56e6ea3ec94620abd79c591b01bc6357e084f",
                OracleSchemas.identity("full-tree-function-truth-index").sha256,
                "the v2 index schema bytes must stay frozen",
            )
            assertEquals(
                "a59e80ed0cd440f07be4741892d75ba5a3514532a73ecb67bbc617b4d24a34c2",
                FullTreeFunctionTruthSqliteV3.configurationSha256,
            )
            assertEquals(
                "17c61e43524b98a215075b82fa50732d6d8f50d883dce235e511731612da04e5",
                FullTreeFunctionTruthSqlite.configurationSha256,
                "adding v3 must preserve the frozen truth-v2 digest",
            )

            val index = parseControlObject(first.root.resolve("index.json"))
            OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.INDEX_SCHEMA_NAME, index)
            assertEquals(2L, index.controlLong("schemaVersion"))
            assertEquals(fixture.observationV2IndexSha256, first.observationV2IndexArtifactSha256)
            assertEquals(first.counts.sourceEntities, index.controlObject("counts").controlLong("sourceEntities"))
            assertTrue(first.counts.sourceEntities > 0L, "compiler fixture must exercise source census projection")
            assertCensusCounts(first.root, index)
            assertConcreteTemplateShapes(first.root)
            val wholeTruthEntities = Math.addExact(
                Math.addExact(first.counts.functions.elfRvas, first.counts.functions.dwarfOnlyRvas),
                first.counts.functions.nonEmittedUnique,
            )
            val exactWholeCombined = fullTreeFunctionTruthV3CombinedEntityCount(
                wholeTruthEntities,
                first.counts.sourceEntities,
                Math.addExact(wholeTruthEntities, first.counts.sourceEntities),
            )
            assertEquals(Math.addExact(wholeTruthEntities, first.counts.sourceEntities), exactWholeCombined)
            assertFailsWith<IllegalArgumentException>("one fewer whole-run entity must reject actual V3 evidence") {
                fullTreeFunctionTruthV3CombinedEntityCount(
                    wholeTruthEntities,
                    first.counts.sourceEntities,
                    exactWholeCombined - 1L,
                )
            }
            index.controlArray("shards").forEach { raw ->
                val record = raw as JsonObject
                val shard = parseControlObject(first.root.resolve(record.controlString("path")))
                val counts = shard.controlObject("counts")
                val shardTruthEntities = Math.addExact(
                    Math.addExact(counts.controlLong("elfRvas"), counts.controlLong("dwarfOnlyRvas")),
                    counts.controlLong("nonEmittedUnique"),
                )
                val exactPerShardCombined = Math.addExact(shardTruthEntities, counts.controlLong("sourceEntities"))
                assertEquals(
                    exactPerShardCombined,
                    fullTreeFunctionTruthV3CombinedEntityCount(
                        shardTruthEntities, counts.controlLong("sourceEntities"), exactPerShardCombined,
                    ),
                )
                assertFailsWith<IllegalArgumentException>("one fewer per-shard entity must reject actual V3 evidence") {
                    fullTreeFunctionTruthV3CombinedEntityCount(
                        shardTruthEntities, counts.controlLong("sourceEntities"), exactPerShardCombined - 1L,
                    )
                }
            }

            val scoreRvas = HashSet<String>()
            val scoreRowCount = index.controlArray("shards").sumOf { raw ->
                val shardRecord = raw as JsonObject
                val shard = parseControlObject(first.root.resolve(shardRecord.controlString("path")))
                OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME, shard)
                val functions = shard.controlArray("functions").controlObjects("truth functions")
                assertEquals(functions.size.toLong(), shard.controlObject("counts").controlLong("functions"))
                assertEquals(shard.controlArray("sourceEntities").size.toLong(), shard.controlObject("counts").controlLong("sourceEntities"))
                val rvas = functions.map { it.controlString("rva") }
                assertEquals(rvas.size, rvas.distinct().size, "source census must not duplicate score rows")
                assertTrue(rvas.all(scoreRvas::add), "an emitted RVA may have only one truth row across the full run")
                val emittedRvas = rvas.toSet()
                shard.controlArray("sourceEntities").controlObjects("source entities").forEach { entity ->
                    val linked = entity["linkedEmittedRva"]
                    if (entity.controlString("denominatorDisposition") == "emitted-rva-link") {
                        assertTrue(linked is JsonPrimitive && linked.content in emittedRvas)
                    } else {
                        assertEquals(JsonNull, linked, "non-linked source facts must not create score rows")
                    }
                }
                functions.size.toLong()
            }
            assertEquals(first.counts.functions.dwarfRvas, scoreRowCount)
            assertEquals(
                first.counts.functions.scoredRvas,
                index.controlArray("shards").sumOf { raw ->
                    parseControlObject(first.root.resolve((raw as JsonObject).controlString("path")))
                        .controlArray("functions").controlObjects("truth functions")
                        .count { it.controlString("population") == "scored" }.toLong()
                },
            )

            val validated = FullTreeFunctionTruthSqliteV3.loadAndValidate(
                candidateRoot = first.root,
                richArtifact = fixture.rich,
                strippedArtifact = fixture.stripped,
                inventoryPath = fixture.inventoryPath,
                elfFunctionIndex = fixture.elfIndex,
                observationV2Root = fixture.observationV2Root,
                expectedObservationV2IndexArtifactSha256 = fixture.observationV2IndexSha256,
                scope = fixture.scope,
                scratchParent = fixture.scratch,
                limits = limits,
            )
            assertTrue(validated.rawInputsRederived)
            assertTrue(validated.candidateBytesMatchedAtValidationBoundary)
            assertFalse(validated.candidateLeaseRetained)
            assertFalse(validated.downstreamScoringAuthorized)
            assertFalse(validated.authoritativeReleaseEvidence)
            assertEquals(first.indexArtifactSha256, validated.indexArtifactSha256)
            assertEquals(first.outputBytes, validated.outputBytes)

            val forged = copyTree(first.root, root.resolve("truth-v3-forged"))
            mutateAndRehashSourceIdentity(forged)
            val forgedBytes = v3TreeBytes(forged)
            assertFailsWith<FullTreeFunctionTruthV3Exception> {
                FullTreeFunctionTruthSqliteV3.loadAndValidate(
                    candidateRoot = forged,
                    richArtifact = fixture.rich,
                    strippedArtifact = fixture.stripped,
                    inventoryPath = fixture.inventoryPath,
                    elfFunctionIndex = fixture.elfIndex,
                    observationV2Root = fixture.observationV2Root,
                    expectedObservationV2IndexArtifactSha256 = fixture.observationV2IndexSha256,
                    scope = fixture.scope,
                    scratchParent = fixture.scratch,
                    limits = limits,
                )
            }
            assertEquals(forgedBytes, v3TreeBytes(forged), "rejected candidate bytes remain unchanged")

            assertSelfConsistentMutationsRejected(first, root)
            assertV3RawInputPathReplacementIsDetected(fixture, root)
            assertV3CandidateSnapshotRejectsRaces(first, root)
            assertV3StagingIsReauthenticatedAroundFreeze(first, root)
            assertV3ObservationSnapshotRejectsTreeSwap(fixture, root)
            assertTrue(
                fixture.compilerInputVectorMatches,
                "compiler fixture drift is not pinned: compiler=${fixture.compilerIdentity}, " +
                    "readelf=${fixture.readelfIdentity}, linkedElfBytes=${Files.size(fixture.rich)}, " +
                    "linkedElfSha256=${fixtureSha256(fixture.rich)}; check in a matching input vector",
            )
            assertDirectoryEmpty(fixture.scratch)
        }

    private fun assertSelfConsistentMutationsRejected(
        expected: FullTreeFunctionTruthV3Generation,
        root: Path,
    ) {
        val index = parseControlObject(expected.root.resolve("index.json"))
        val shard = parseControlObject(expected.root.resolve((index.controlArray("shards").single() as JsonObject).controlString("path")))
        val rows = shard.controlArray("sourceEntities").controlObjects("source entities")
        val rvas = shard.controlArray("functions").controlObjects("functions").map { it.controlString("rva") }
        assertTrue(rows.any { it.controlString("entityKind") == "declaration-only" }, "declaration promotion case must exist")
        val inlineOrigin = rows.firstOrNull { row ->
            row.controlString("entityKind") == "inline-instance" && row.controlArray("edges").any { raw ->
                val edge = raw as? JsonObject ?: return@any false
                edge.controlString("kind") == "abstract-origin" && edge.controlString("state") == "resolved" &&
                    (edge["target"] as? JsonPrimitive)?.isString == true
            }
        } ?: error("fixture must contain a resolved inline abstract-origin row")
        val intTemplate = rows.first { row ->
            row.controlString("entityKind") == "template-instance" &&
                row.controlObject("semanticAnchorFields").controlArray("templateActualArguments")
                    .any { it.toString().contains("int") } && row["semanticAnchorCandidateId"] != JsonNull
        }
        val longTemplate = rows.first { row ->
            row.controlString("entityKind") == "template-instance" &&
                row.controlObject("semanticAnchorFields").controlArray("templateActualArguments")
                    .any { it.toString().contains("long") } && row["semanticAnchorCandidateId"] != JsonNull
        }
        val linked = rows.first { it.controlString("denominatorDisposition") == "emitted-rva-link" }
        assertTrue(rvas.size > 1 && linked["linkedEmittedRva"] != JsonNull, "link mutation case must have alternate emitted RVAs")

        val cases = listOf(
            V3Mutation("candidate identity", rows.first { it["semanticAnchorCandidateId"] != JsonNull }) { row ->
                val current = (row["semanticAnchorCandidateId"] as JsonPrimitive).content
                row.withField("semanticAnchorCandidateId", JsonPrimitive(if (current == "a".repeat(64)) "b".repeat(64) else "a".repeat(64)))
            },
            V3Mutation("source category", rows.first { it.controlString("entityKind") == "declaration-only" }) { row ->
                row.withField("entityKind", JsonPrimitive("unresolved"))
            },
            V3Mutation("declaration promoted to scored", rows.first { it.controlString("entityKind") == "declaration-only" }) { row ->
                row.withField("denominatorDisposition", JsonPrimitive("emitted-rva-link"))
                    .withField("linkedEmittedRva", JsonPrimitive(rvas.first()))
            },
            V3Mutation("inline instance promoted to scored", inlineOrigin) { row ->
                row.withField("denominatorDisposition", JsonPrimitive("emitted-rva-link"))
                    .withField("linkedEmittedRva", JsonPrimitive(rvas.first()))
            },
            V3Mutation("denominator disposition", linked) { row ->
                row.withField("denominatorDisposition", JsonPrimitive("non-scoreable"))
                    .withField("linkedEmittedRva", JsonNull)
            },
            V3Mutation("emitted RVA link", linked) { row ->
                val old = row.controlString("linkedEmittedRva")
                row.withField("linkedEmittedRva", JsonPrimitive(rvas.first { it != old }))
            },
            V3Mutation("resolved identity", inlineOrigin) { row ->
                row.withField("resolvedSemanticIdentityId", JsonPrimitive("c".repeat(64)))
            },
            V3Mutation("inline origin edge", inlineOrigin) { row ->
                row.withField("edges", JsonArray(row.controlArray("edges").map { raw ->
                    val edge = raw as? JsonObject ?: return@map raw
                    if (edge.controlString("kind") == "abstract-origin") {
                        edge.withField("target", JsonPrimitive("forged-origin-target"))
                    } else edge
                }))
            },
            V3Mutation("generic template pattern proof", intTemplate) { row ->
                val fields = row.controlObject("semanticAnchorFields").withField(
                    "templatePatternAnchorCandidateId", JsonPrimitive("d".repeat(64)),
                )
                row.withField("semanticAnchorFields", fields)
            },
            V3Mutation("merge typed int and long instances", intTemplate) { row ->
                row.withField("semanticAnchorCandidateId", longTemplate["semanticAnchorCandidateId"]!!)
            },
            V3Mutation("collision evidence", rows.first()) { row ->
                row.withField("candidateCollisionSourceEntityIds", JsonArray(listOf(JsonPrimitive("e".repeat(64)))))
            },
            V3Mutation("duplicate physical row id", rows.last()) { row ->
                row.withField("sourceEntityId", JsonPrimitive(rows.first().controlString("sourceEntityId")))
            },
        )
        cases.forEachIndexed { indexInCases, case ->
            assertTrue(case.row in rows, "${case.name} mutation must select a fixture row")
            val candidate = copyTree(expected.root, root.resolve("truth-v3-mutation-$indexInCases"))
            mutateAndRehashSourceRow(candidate, case.row.controlString("sourceEntityId"), case.mutate)
            val changedIndex = parseControlObject(candidate.resolve("index.json"))
            OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.INDEX_SCHEMA_NAME, changedIndex)
            Files.list(candidate.resolve("shards")).use { paths ->
                paths.forEach { OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME, parseControlObject(it)) }
            }
            assertFailsWith<FullTreeFunctionTruthV3Exception>("rehashed ${case.name} mutation must fail raw-derived byte comparison") {
                FullTreeFunctionTruthSqliteV3.compareV3CandidateTreeBytes(
                    candidate,
                    expected.root,
                    changedIndex.controlArray("shards").size.toLong() + 2L,
                    expected.outputBytes,
                )
            }
        }
    }

    private fun JsonObject.withField(name: String, value: JsonElement): JsonObject =
        JsonObject(toMutableMap().apply { put(name, value) })

    private fun assertV3RawInputPathReplacementIsDetected(fixture: V3Fixture, root: Path) {
        val guardedInventory = root.resolve("guarded-inventory.json")
        Files.copy(fixture.inventoryPath, guardedInventory)
        val replacement = root.resolve("replacement-inventory.json")
        Files.write(replacement, Files.readAllBytes(guardedInventory))
        FullTreeFunctionTruthSqliteV3.V3RawInputGuards.open(
            fixture.rich,
            fixture.stripped,
            guardedInventory,
            fixture.elfIndex,
            FullTreeFunctionTruthV3Limits(),
        ).use { guards ->
            Files.delete(guardedInventory)
            Files.move(replacement, guardedInventory, StandardCopyOption.ATOMIC_MOVE)
            assertFailsWith<IllegalArgumentException> {
                guards.verifyUnchanged("post-derivation publication boundary regression")
            }
        }
    }

    private fun assertV3CandidateSnapshotRejectsRaces(
        expected: FullTreeFunctionTruthV3Generation,
        root: Path,
    ) {
        val maximumFiles = expected.index.controlArray("shards").size.toLong() + 2L
        fun pinned(label: String): Pair<Path, FullTreeFunctionTruthSqliteV3.V3StableTreeSnapshot> {
            val candidate = copyTree(expected.root, root.resolve("truth-v3-$label-original"))
            val identity = FullTreeFunctionTruthSqliteV3.V3StableTreeSnapshot.captureIdentity(
                candidate, setOf("shards"), maximumFiles, expected.outputBytes, {},
                setOf("index.json", "exclusions.json"),
            )
            val snapshot = identity.createSnapshot(
                candidate, root.resolve("truth-v3-$label-pinned"), setOf("shards"), null, {}, expected.outputBytes,
            )
            return candidate to snapshot
        }

        val (rewritten, rewrittenSnapshot) = pinned("rewrite-race")
        var rewrote = false
        FullTreeFunctionTruthSqliteV3.compareV3CandidateTreeBytes(
            rewrittenSnapshot.root, expected.root, maximumFiles, expected.outputBytes,
        ) { member ->
            if (member == "exclusions.json" && !rewrote) {
                makeTreeWritable(rewritten)
                val index = rewritten.resolve("index.json")
                val bytes = Files.readAllBytes(index)
                bytes[0] = if (bytes[0] == '{'.code.toByte()) '['.code.toByte() else '{'.code.toByte()
                Files.write(index, bytes)
                rewrote = true
            }
        }
        assertTrue(rewrote, "a later candidate comparison must overlap the in-place rewrite")
        assertFailsWith<FullTreeFunctionTruthV3Exception>("the earlier-compared member remains pinned through final validation") {
            rewrittenSnapshot.verifyOriginalUnchanged()
        }

        val (swapped, swappedSnapshot) = pinned("path-swap-race")
        var swappedMember = false
        FullTreeFunctionTruthSqliteV3.compareV3CandidateTreeBytes(
            swappedSnapshot.root, expected.root, maximumFiles, expected.outputBytes,
        ) { member ->
            if (member == "exclusions.json" && !swappedMember) {
                makeTreeWritable(swapped)
                val shard = Files.list(swapped.resolve("shards")).use { it.findFirst().orElseThrow() }
                val saved = Files.readAllBytes(shard)
                val displaced = shard.resolveSibling("${shard.fileName}.displaced")
                Files.move(shard, displaced, StandardCopyOption.ATOMIC_MOVE)
                Files.write(shard, saved)
                swappedMember = true
            }
        }
        assertTrue(swappedMember, "a later candidate comparison must overlap the path swap")
        assertFailsWith<FullTreeFunctionTruthV3Exception>("byte-identical path replacement must retain its original file identity") {
            swappedSnapshot.verifyOriginalUnchanged()
        }
    }

    private fun assertV3StagingIsReauthenticatedAroundFreeze(
        expected: FullTreeFunctionTruthV3Generation,
        root: Path,
    ) {
        val index = parseControlObject(expected.root.resolve("index.json"))
        val firstShard = expected.root.resolve((index.controlArray("shards").first() as JsonObject).controlString("path"))
        val indexBytes = Files.readAllBytes(expected.root.resolve("index.json"))

        val freezeRace = copyTree(expected.root, root.resolve("truth-v3-staging-freeze-race"))
        makeTreeWritable(freezeRace)
        val freezeRaceIndex = parseControlObject(freezeRace.resolve("index.json"))
        val freezeRaceShard = freezeRace.resolve(expected.root.relativize(firstShard).toString())
        var mutatedDuringFreeze = false
        assertFailsWith<FullTreeFunctionTruthV3Exception>("post-freeze member rehash must reject a mutation during chmod") {
            FullTreeFunctionTruthSqliteV3.freezeAndVerifyV3Staging(
                freezeRace,
                freezeRaceIndex,
                Files.readAllBytes(freezeRace.resolve("index.json")),
                expected.outputBytes,
            ) { stage ->
                if (!mutatedDuringFreeze && stage == "while freezing truth-v3 member ${freezeRaceShard.fileName}") {
                    val changed = Files.readAllBytes(freezeRaceShard)
                    changed[0] = if (changed[0] == '{'.code.toByte()) '['.code.toByte() else '{'.code.toByte()
                    Files.write(freezeRaceShard, changed)
                    mutatedDuringFreeze = true
                }
            }
        }
        assertTrue(mutatedDuringFreeze, "the fixture mutation must overlap staged-file freezing")

        val finalBoundary = copyTree(expected.root, root.resolve("truth-v3-staging-final-boundary"))
        val finalIndex = parseControlObject(finalBoundary.resolve("index.json"))
        val snapshot = FullTreeFunctionTruthSqliteV3.freezeAndVerifyV3Staging(
            finalBoundary,
            finalIndex,
            Files.readAllBytes(finalBoundary.resolve("index.json")),
            expected.outputBytes,
        )
        makeTreeWritable(finalBoundary)
        val finalShard = finalBoundary.resolve(expected.root.relativize(firstShard).toString())
        val changed = Files.readAllBytes(finalShard)
        changed[0] = if (changed[0] == '{'.code.toByte()) '['.code.toByte() else '{'.code.toByte()
        Files.write(finalShard, changed)
        assertFailsWith<FullTreeFunctionTruthV3Exception>("the final rename-boundary rehash must catch a changed staged member") {
            FullTreeFunctionTruthSqliteV3.reauthenticateV3Staging(
                snapshot,
                finalIndex,
                Files.readAllBytes(finalBoundary.resolve("index.json")),
                expected.outputBytes,
            )
        }
        assertEquals(indexBytes.toList(), Files.readAllBytes(expected.root.resolve("index.json")).toList())
    }

    private fun assertV3ObservationSnapshotRejectsTreeSwap(fixture: V3Fixture, root: Path) {
        val limits = tightScratchLimits()
        val identity = FullTreeFunctionTruthSqliteV3.V3StableTreeSnapshot.captureIdentity(
            fixture.observationV2Root,
            setOf("outputs", "checkpoints"),
            Math.addExact(Math.multiplyExact(limits.observationV2.run.maximumShards.toLong(), 2L), 2L),
            minOf(limits.maximumScratchBytes, limits.truth.maximumScratchBytes, limits.observationV2.maximumScratchBytes),
            {},
            setOf("run.json", "index.json"),
        )
        val validationScratch = privateDirectory(root.resolve("observation-v2-snapshot-validation-scratch"))
        val validated = FullTreeFunctionObservationV2RunPublisher.loadAndValidate(
            candidateRoot = fixture.observationV2Root,
            expectedIndexArtifactSha256 = fixture.observationV2IndexSha256,
            richArtifact = fixture.rich,
            inventoryPath = fixture.inventoryPath,
            scope = fixture.scope,
            scratchParent = validationScratch,
            limits = limits.observationV2,
        )
        assertEquals(fixture.observationV2IndexSha256, validated.binding.indexArtifactSha256)
        identity.verifyIdentity()
        val pinned = identity.createSnapshot(
            fixture.observationV2Root,
            root.resolve("observation-v2-pinned-source"),
            setOf("outputs", "checkpoints"),
            null,
            {},
        )
        val replacement = copyTree(fixture.observationV2Root, root.resolve("observation-v2-replacement"))
        val displaced = root.resolve("observation-v2-displaced")
        Files.move(fixture.observationV2Root, displaced, StandardCopyOption.ATOMIC_MOVE)
        Files.move(replacement, fixture.observationV2Root, StandardCopyOption.ATOMIC_MOVE)
        assertFailsWith<FullTreeFunctionTruthV3Exception>(
            "an observation tree swap after nested validation must be rejected before publication",
        ) {
            pinned.verifyOriginalUnchanged()
        }
    }

    private fun tightScratchLimits(): FullTreeFunctionTruthV3Limits {
        val mebibyte = 1024L * 1024L
        return FullTreeFunctionTruthV3Limits(
            truth = FullTreeFunctionTruthLimits(
                maximumDatabaseBytes = 64L * mebibyte,
                maximumScratchBytes = 512L * mebibyte,
                maximumOutputBytes = 128L * mebibyte,
                maximumEntityBytes = 1 * 1024 * 1024,
                maximumStringBytes = 1 * 1024 * 1024,
            ),
            observationV2 = FullTreeFunctionObservationV2RunLimits(
                shard = FullTreeFunctionObservationShardPublisherLimits().copy(
                    producer = FullTreeFunctionObservationProducerLimits().copy(
                        dieLimits = FullTreeDwarfDieLimits(
                            maximumPhysicalRecords = 10_000_000L,
                            maximumNonNullRecords = 5_000_000,
                            maximumAttributes = 50_000_000L,
                            maximumTreeDepth = 65_536,
                            maximumRetainedBytes = 24L * mebibyte,
                        ),
                        lineTableLimits = FullTreeDwarfLineTableLimits().copy(
                            maximumDirectories = 4096,
                            maximumFiles = 8192,
                            maximumAggregatePathBytes = 4L * mebibyte,
                        ),
                    ),
                ),
            ),
            // SQLite reserves authenticated database headroom before the fixture's small output
            // is known; keep the fixture budget generous while retaining the narrowed producer
            // model above. V3 still enforces its own shared cap independently.
            maximumScratchBytes = 2L * 1024L * 1024L * 1024L,
        )
    }

    private fun assertConcreteTemplateShapes(root: Path) {
        val rows = Files.list(root.resolve("shards")).use { paths ->
            paths.map { parseControlObject(it).controlArray("sourceEntities").controlObjects("source entities") }
                .toList().flatten()
        }
        val templates = rows.filter { it.controlString("entityKind") == "template-instance" }
        val ints = templates.filter {
            it.controlObject("semanticAnchorFields").controlArray("templateActualArguments")
                .any { argument -> argument.toString().contains("int") }
        }
        val longs = templates.filter {
            it.controlObject("semanticAnchorFields").controlArray("templateActualArguments")
                .any { argument -> argument.toString().contains("long") }
        }
        assertTrue(ints.isNotEmpty(), "compiler fixture must contain a concrete int template instance")
        assertTrue(longs.isNotEmpty(), "compiler fixture must contain a concrete long template instance")
        val intCandidates = ints.mapNotNull { it["semanticAnchorCandidateId"] as? JsonPrimitive }.map { it.content }.toSet()
        val longCandidates = longs.mapNotNull { it["semanticAnchorCandidateId"] as? JsonPrimitive }.map { it.content }.toSet()
        assertTrue(intCandidates.isNotEmpty() && longCandidates.isNotEmpty())
        assertTrue(intCandidates.intersect(longCandidates).isEmpty(), "typed int/long actuals must yield distinct candidates")
        val missingPatternProof = ints + longs
        assertTrue(missingPatternProof.all { row ->
            val fields = row.controlObject("semanticAnchorFields")
            fields["templatePatternAnchorCandidateId"] == JsonNull &&
                row["resolvedSemanticIdentityId"] == JsonNull &&
                row.controlArray("reasonCodes").any { it.toString().contains("unknown-template-pattern-reference") } &&
                row.controlString("identityObservability") in setOf("unknown", "ambiguous")
        }, "generic-template relation remains unknown and null without authenticated pattern proof")
        val inlineInstances = rows.filter { it.controlString("entityKind") == "inline-instance" }
        assertTrue(inlineInstances.any { row ->
            row.controlString("identityObservability") == "observable" &&
                row.controlArray("edges").any { edge ->
                    val value = edge as? JsonObject ?: return@any false
                    value.controlString("kind") == "abstract-origin" &&
                        value.controlString("state") == "resolved" && value["target"] != JsonNull
                }
        }, "the compiler-emitted inline-origin relation remains positively observable")
    }

    private fun mutateAndRehashSourceIdentity(root: Path) {
        val rows = allSourceRows(root)
        val selected = rows.firstOrNull { row ->
            row["linkedEmittedRva"] != null && row["linkedEmittedRva"] != JsonNull &&
                row.controlArray("edges").any { rawEdge ->
                    val edge = rawEdge as? JsonObject ?: return@any false
                    (edge["target"] as? JsonPrimitive)?.isString == true
                }
        } ?: error("fixture must contain an emitted-RVA-linked census row with a resolved typed edge")
        val original = selected
        val current = original["semanticAnchorCandidateId"]
        val oldCandidate = (current as? JsonPrimitive)?.takeIf { it.isString }?.content
        val forgedCandidate: JsonElement = if (oldCandidate == "a".repeat(64)) JsonPrimitive("b".repeat(64)) else JsonPrimitive("a".repeat(64))
        val oldObservability = original.controlString("identityObservability")
        val oldDisposition = original.controlString("denominatorDisposition")
        mutateAndRehashSourceRow(root, selected.controlString("sourceEntityId")) { original -> JsonObject(original.toMutableMap().apply {
            put("semanticAnchorCandidateId", forgedCandidate)
            put("entityKind", JsonPrimitive("unresolved"))
            put("identityObservability", JsonPrimitive(if (oldObservability == "ambiguous") "unknown" else "ambiguous"))
            put("denominatorDisposition", JsonPrimitive(if (oldDisposition == "ambiguous") "unknown" else "ambiguous"))
            put("linkedEmittedRva", JsonNull)
            put("resolvedSemanticIdentityId", if (original["resolvedSemanticIdentityId"] == JsonNull) JsonPrimitive("c".repeat(64)) else JsonNull)
            val edges = original.controlArray("edges").map { raw ->
                val edge = raw as? JsonObject ?: return@map raw
                if ((edge["target"] as? JsonPrimitive)?.isString == true) {
                    JsonObject(edge.toMutableMap().apply { put("target", JsonPrimitive("forged-edge-target")) })
                } else edge
            }
            put("edges", JsonArray(edges))
        }) }
    }

    private fun mutateAndRehashSourceRow(root: Path, sourceEntityId: String, mutate: (JsonObject) -> JsonObject) {
        makeTreeWritable(root)
        val selected = Files.list(root.resolve("shards")).use { paths ->
            paths.toList().asSequence().mapNotNull { path ->
                val shard = parseControlObject(path)
                val index = shard.controlArray("sourceEntities").indexOfFirst { raw ->
                    (raw as? JsonObject)?.controlString("sourceEntityId") == sourceEntityId
                }
                if (index < 0) null else CandidateSource(
                    path,
                    shard,
                    index,
                    shard.controlArray("sourceEntities")[index] as JsonObject,
                )
            }.firstOrNull()
        } ?: error("candidate census row is missing before mutation")
        val sources = selected.shard.controlArray("sourceEntities").toMutableList()
        sources[selected.sourceIndex] = mutate(selected.source)
        val changedShard = withSourceRowsAndCounts(selected.shard, JsonArray(sources))
        OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME, changedShard)
        val changedShardBytes = OracleJson.canonicalBytes(changedShard)
        Files.write(selected.path, changedShardBytes)
        val indexPath = root.resolve("index.json")
        val index = parseControlObject(indexPath)
        val allRows = allSourceRows(root)
        val records = index.controlArray("shards").map { raw ->
            val record = raw as JsonObject
            if (record.controlString("path") == root.relativize(selected.path).toString().replace('\\', '/')) {
                JsonObject(record.toMutableMap().apply {
                    put("bytes", JsonPrimitive(changedShardBytes.size))
                    put("sha256", JsonPrimitive(OracleArtifacts.sha256(changedShardBytes)))
                })
            } else record
        }
        val counts = JsonObject(index.controlObject("counts").toMutableMap().apply {
            put("sourceEntities", JsonPrimitive(allRows.size))
            put("sourceEntitiesByKind", countBy(allRows, "entityKind", FullTreeSourceEntityKind.entries.map { it.wireValue }))
            put("sourceEntitiesByObservability", countBy(allRows, "identityObservability", FullTreeIdentityObservability.entries.map { it.wireValue }))
            put("sourceEntitiesByDenominatorDisposition", countBy(allRows, "denominatorDisposition", FullTreeDenominatorDisposition.entries.map { it.wireValue }))
        })
        val withoutDigest = JsonObject(index.toMutableMap().apply {
            remove("indexSha256")
            put("shards", JsonArray(records))
            put("counts", counts)
        })
        val logicalDigest = OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutDigest))
        val changedIndex = JsonObject(withoutDigest + ("indexSha256" to JsonPrimitive(logicalDigest)))
        OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.INDEX_SCHEMA_NAME, changedIndex)
        Files.write(indexPath, OracleJson.canonicalBytes(changedIndex))
        freezeTree(root)
    }

    private fun allSourceRows(root: Path): List<JsonObject> = Files.list(root.resolve("shards")).use { paths ->
        paths.map(::parseControlObject).map { it.controlArray("sourceEntities").controlObjects("source entities") }
            .toList().flatten()
    }

    private fun assertCensusCounts(root: Path, index: JsonObject) {
        val rows = Files.list(root.resolve("shards")).use { paths ->
            paths.map(::parseControlObject).map { it.controlArray("sourceEntities").controlObjects("source entities") }
                .toList().flatten()
        }
        assertEquals(rows.size, rows.map { it.controlString("sourceEntityId") }.distinct().size,
            "every physical source fact has one artifact-local row id")
        val counts = index.controlObject("counts")
        assertEquals(rows.size.toLong(), counts.controlLong("sourceEntities"))
        assertEquals(countBy(rows, "entityKind", FullTreeSourceEntityKind.entries.map { it.wireValue }), counts.controlObject("sourceEntitiesByKind"))
        assertEquals(countBy(rows, "identityObservability", FullTreeIdentityObservability.entries.map { it.wireValue }), counts.controlObject("sourceEntitiesByObservability"))
        assertEquals(countBy(rows, "denominatorDisposition", FullTreeDenominatorDisposition.entries.map { it.wireValue }), counts.controlObject("sourceEntitiesByDenominatorDisposition"))
        assertTrue("no-range-definition" in counts.controlObject("sourceEntitiesByKind"))
    }

    private fun withSourceRowsAndCounts(shard: JsonObject, rows: JsonArray): JsonObject {
        val counts = JsonObject(shard.controlObject("counts").toMutableMap().apply {
            val objects = rows.controlObjects("source entities")
            put("sourceEntities", JsonPrimitive(objects.size))
            put("sourceEntitiesByKind", countBy(objects, "entityKind", FullTreeSourceEntityKind.entries.map { it.wireValue }))
            put("sourceEntitiesByObservability", countBy(objects, "identityObservability", FullTreeIdentityObservability.entries.map { it.wireValue }))
            put("sourceEntitiesByDenominatorDisposition", countBy(objects, "denominatorDisposition", FullTreeDenominatorDisposition.entries.map { it.wireValue }))
        })
        return JsonObject(shard.toMutableMap().apply {
            put("counts", counts)
            put("sourceEntities", rows)
        })
    }

    private fun countBy(rows: List<JsonObject>, field: String, keys: List<String>): JsonObject {
        val counts = keys.associateWith { key -> rows.count { it.controlString(field) == key }.toLong() }
        return JsonObject(counts.mapValues { JsonPrimitive(it.value) })
    }

    private fun createCompilerFixture(root: Path, perShardResidentBytes: Long? = null): V3Fixture {
        val sourceRoot = Path.of(System.getProperty("user.dir"))
            .resolve("src/test/resources/oracle/inline-template-identity-v1").toAbsolutePath().normalize()
        val compiler = resolveCompiler("GXX", listOf("g++", "g++-14", "g++-13"))
        val compilerVersion = runCommand(listOf(compiler.toString(), "--version"), root, "compiler-version.txt")
        val readelf = resolveCompiler("READELF", listOf("readelf", "llvm-readelf"))
        val readelfVersion = runCommand(listOf(readelf.toString(), "--version"), root, "readelf-version.txt")
        val build = Files.createDirectories(root.resolve("compiled"))
        val objects = listOf("caller_one", "caller_two", "instantiate", "unique_pattern").map { name ->
            val target = build.resolve("$name.o")
            runCommand(
                listOf(
                    compiler.toString(), "-std=c++17", "-O2", "-g", "-gdwarf-5", "-fPIC",
                    "-fdebug-prefix-map=$sourceRoot=/fixture/source-tree/clang/lib/InlineTemplate",
                    "-fdebug-prefix-map=$build=/fixture/build",
                    "-I${sourceRoot.resolve("include")}", sourceRoot.resolve("$name.cpp").toString(),
                    "-c", "-o", target.toString(),
                ),
                build,
                "$name-compile.txt",
            )
            target
        }
        val artifact = build.resolve("fixture.so")
        runCommand(
            listOf(compiler.toString(), "-shared", "-Wl,--build-id=none") + objects.map(Path::toString) + listOf("-o", artifact.toString()),
            build,
            "link.txt",
        )
        val stripped = build.resolve("fixture-stripped.so")
        Files.copy(artifact, stripped)
        writeCompilerObservationDiagnostic(compilerVersion, readelfVersion, artifact)
        val compilerInputVectorMatches = assertCompilerInputVector(sourceRoot, compilerVersion, readelfVersion, artifact)
        val controls = createFullTreeControlFixture(root.resolve("control"))
        val original = controls.authenticatedScope()
        val richHash = fixtureSha256(artifact)
        val strippedHash = fixtureSha256(stripped)
        val artifacts = original.artifactManifest.controlObject("artifacts")
        fun rebound(name: String, path: Path): JsonObject = JsonObject(artifacts.controlObject(name).toMutableMap().apply {
            put("bytes", JsonPrimitive(Files.size(path)))
            put("sha256", JsonPrimitive(fixtureSha256(path)))
        })
        val manifest = JsonObject(original.artifactManifest.toMutableMap().apply {
            put("artifacts", JsonObject(artifacts.toMutableMap().apply {
                put("full", rebound("full", artifact))
                put("stripped", rebound("stripped", stripped))
            }))
        })
        val manifestHash = OracleArtifacts.sha256(OracleJson.canonicalBytes(manifest))
        val scopeDocument = JsonObject(original.document.toMutableMap().apply {
            put("oracle", JsonObject(original.document.controlObject("oracle").toMutableMap().apply {
                put("artifactManifestSha256", JsonPrimitive(manifestHash))
                put("richArtifactSha256", JsonPrimitive(richHash))
                put("strippedArtifactSha256", JsonPrimitive(strippedHash))
            }))
            if (perShardResidentBytes != null) {
                put("bounds", JsonObject(original.document.controlObject("bounds").toMutableMap().apply {
                    put("perShard", JsonObject(original.document.controlObject("bounds").controlObject("perShard").toMutableMap().apply {
                        put("maximumResidentBytes", JsonPrimitive(perShardResidentBytes))
                    }))
                }))
            }
        })
        val scope = AuthenticatedFullTreeScope(
            document = scopeDocument,
            sha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(scopeDocument)),
            sourceLock = original.sourceLock,
            sourceLockSha256 = original.sourceLockSha256,
            artifactManifest = manifest,
            artifactManifestSha256 = manifestHash,
        )
        FullTreeScopeControl.validate(scope)
        val inventoryPath = root.resolve("inventory.json")
        FullTreeInventoryControl.generateAndPublish(artifact, scope, inventoryPath, maximumWorkers = 1)
        val inventory = parseControlObject(inventoryPath)
        val elfDirectory = privateDirectory(root.resolve("elf"))
        val elfIndex = elfDirectory.resolve("functions.json")
        FullTreeElfFunctionsSqlite.generateAndPublish(
            richArtifact = artifact,
            strippedArtifact = stripped,
            scope = scope,
            inventory = inventory,
            output = elfIndex,
            maximumWorkers = 1,
        )
        val scratch = privateDirectory(root.resolve("scratch"))
        val v2Root = root.resolve("observations-v2")
        val v2 = FullTreeFunctionObservationV2RunPublisher.generateAndPublish(
            richArtifact = artifact,
            inventoryPath = inventoryPath,
            scope = scope,
            scratchParent = scratch,
            outputRoot = v2Root,
            maximumWorkers = 2,
            limits = tightScratchLimits().observationV2,
        )
        assertTrue(compilerVersion.isNotBlank())
        return V3Fixture(
            artifact,
            stripped,
            inventoryPath,
            scope,
            elfIndex,
            v2Root,
            v2.binding.indexArtifactSha256,
            scratch,
            compilerVersion.lineSequence().first(),
            readelfVersion.lineSequence().first(),
            compilerInputVectorMatches,
        )
    }

    private fun writeCompilerObservationDiagnostic(compilerVersion: String, readelfVersion: String, artifact: Path) {
        val diagnostic = JsonObject(
            mapOf(
                "compiler" to JsonObject(mapOf(
                    "observedVersion" to JsonPrimitive(compilerVersion.lineSequence().first()),
                    "readelfVersion" to JsonPrimitive(readelfVersion.lineSequence().first()),
                )),
                "linkedElf" to JsonObject(mapOf(
                    "bytes" to JsonPrimitive(Files.size(artifact)),
                    "sha256" to JsonPrimitive(fixtureSha256(artifact)),
                )),
                "vectorKind" to JsonPrimitive("compiler-output-v1"),
            ),
        )
        val path = Path.of(System.getProperty("user.dir"))
            .resolve("build/test-results/test/full-tree-function-truth-v3-compiler-observed-v1.json")
        Files.createDirectories(path.parent)
        Files.write(path, OracleJson.canonicalBytes(diagnostic))
    }

    private fun assertCompilerInputVector(sourceRoot: Path, compilerVersion: String, readelfVersion: String, artifact: Path): Boolean {
        val vector = parseControlObject(sourceRoot.parent.resolve("full-tree-function-truth-v3/compiler-input-v1.json"))
        assertEquals("compiler-input-v1", vector.controlString("vectorKind"))
        assertEquals("inline-template-identity-v1", vector.controlString("fixture"))
        val policy = vector.controlObject("producer")
        assertEquals(FullTreeFunctionTruthSqliteV3.POLICY_ID, policy.controlString("id"))
        assertEquals(FullTreeFunctionTruthSqliteV3.POLICY_VERSION.toLong(), policy.controlLong("version"))
        assertEquals(FullTreeFunctionTruthSqliteV3.configurationSha256, policy.controlString("configurationSha256"))
        vector.controlArray("schemaIdentities").controlObjects("schema identities").forEach { identity ->
            assertEquals(identity.controlString("schemaSha256"), OracleSchemas.identity(identity.controlString("name")).sha256)
        }
        vector.controlArray("sourceFiles").controlObjects("source files").forEach { source ->
            assertEquals(source.controlString("sha256"), fixtureSha256(sourceRoot.resolve(source.controlString("path"))))
        }
        val recordedToolchain = vector.controlObject("compiler")
        val toolchainMatches = recordedToolchain.controlString("observedVersion") == compilerVersion.lineSequence().first() &&
            recordedToolchain.controlString("readelfVersion") == readelfVersion.lineSequence().first()
        if (toolchainMatches) {
            val linkedElf = vector.controlObject("linkedElf")
            assertEquals(linkedElf.controlLong("bytes"), Files.size(artifact), "linked fixture ELF byte count")
            assertEquals(linkedElf.controlString("sha256"), fixtureSha256(artifact), "linked fixture ELF digest")
        }
        assertTrue(Files.size(artifact) > 0L)
        return toolchainMatches
    }

    private fun writeFixtureVector(fixture: V3Fixture, generation: FullTreeFunctionTruthV3Generation) {
        val inputVectorPath = Path.of(System.getProperty("user.dir"))
            .resolve("src/test/resources/oracle/full-tree-function-truth-v3/compiler-input-v1.json")
        val inputVector = parseControlObject(inputVectorPath)
        val schemas = listOf(
            FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME,
            FullTreeFunctionTruthSqliteV3.INDEX_SCHEMA_NAME,
        ).map { name ->
            val identity = OracleSchemas.identity(name)
            JsonObject(mapOf("name" to JsonPrimitive(name), "schemaSha256" to JsonPrimitive(identity.sha256)))
        }
        val vector = JsonObject(
            mapOf(
                "compiler" to JsonObject(mapOf(
                    "observedVersion" to JsonPrimitive(fixture.compilerIdentity),
                    "readelfVersion" to JsonPrimitive(fixture.readelfIdentity),
                )),
                "compilerInputVectorMatches" to JsonPrimitive(fixture.compilerInputVectorMatches),
                "fixtureInputVectorSha256" to JsonPrimitive(fixtureSha256(inputVectorPath)),
                "input" to JsonObject(
                    mapOf(
                        "richElfSha256" to JsonPrimitive(fixtureSha256(fixture.rich)),
                        "strippedElfSha256" to JsonPrimitive(fixtureSha256(fixture.stripped)),
                        "observationV2IndexArtifactSha256" to JsonPrimitive(fixture.observationV2IndexSha256),
                        "scopeSha256" to JsonPrimitive(fixture.scope.sha256),
                    "inventoryArtifactSha256" to JsonPrimitive(fixtureSha256(fixture.inventoryPath)),
                    "linkedElfBytes" to JsonPrimitive(Files.size(fixture.rich)),
                    "linkedElfSha256" to JsonPrimitive(fixtureSha256(fixture.rich)),
                    ),
                ),
                "output" to JsonObject(
                    mapOf(
                        "indexArtifactSha256" to JsonPrimitive(generation.indexArtifactSha256),
                        "indexSha256" to JsonPrimitive(generation.indexSha256),
                        "outputBytes" to JsonPrimitive(generation.outputBytes),
                        "databaseHighWaterBytes" to JsonPrimitive(generation.databaseHighWaterBytes),
                        "counts" to generation.counts.toJson(),
                        "index" to generation.index,
                    ),
                ),
                "producer" to JsonObject(
                    mapOf(
                        "id" to JsonPrimitive(FullTreeFunctionTruthSqliteV3.POLICY_ID),
                        "version" to JsonPrimitive(FullTreeFunctionTruthSqliteV3.POLICY_VERSION),
                        "configurationSha256" to JsonPrimitive(FullTreeFunctionTruthSqliteV3.configurationSha256),
                        "schemas" to JsonArray(schemas),
                    ),
                ),
                "vectorKind" to JsonPrimitive("full-tree-function-truth-v3-output-v1"),
            ),
        )
        val output = Path.of(System.getProperty("user.dir"))
            .resolve("build/test-results/test/full-tree-function-truth-v3-vector.json")
        Files.createDirectories(output.parent)
        val bytes = OracleJson.canonicalBytes(vector)
        Files.write(output, bytes)
        if (fixture.compilerInputVectorMatches) {
            val golden = inputVectorPath.resolveSibling("compiler-output-v1.json")
            assertTrue(Files.isRegularFile(golden), "the matching compiler input has no checked-in V3 output vector")
            assertEquals(Files.readAllBytes(golden).toList(), bytes.toList(), "V3 canonical compiler output vector")
        }
    }

    private fun resolveCompiler(environment: String, candidates: List<String>): Path {
        val names = System.getenv(environment)?.takeIf(String::isNotBlank)?.let(::listOf) ?: candidates
        val searchPath = System.getenv("PATH").orEmpty().split(File.pathSeparator).filter(String::isNotBlank)
        names.forEach { name ->
            val path = Path.of(name)
            val matches = if (path.isAbsolute || name.contains('/')) listOf(path) else searchPath.map { Path.of(it).resolve(name) }
            matches.firstOrNull { Files.isRegularFile(it) && Files.isExecutable(it) }?.let { return it.toAbsolutePath().normalize() }
        }
        error("required fixture compiler $environment is unavailable: ${candidates.joinToString()}")
    }

    private fun runCommand(command: List<String>, directory: Path, outputName: String): String {
        val output = directory.resolve(outputName)
        val process = ProcessBuilder(command).directory(directory.toFile()).redirectErrorStream(true).redirectOutput(output.toFile()).start()
        if (!process.waitFor(2, TimeUnit.MINUTES)) {
            process.destroyForcibly()
            error("fixture command timed out: ${command.joinToString(" ")}")
        }
        val text = Files.readAllBytes(output).toString(StandardCharsets.UTF_8)
        if (process.exitValue() != 0) error("fixture command failed (${process.exitValue()}): ${command.joinToString(" ")}\n$text")
        return text
    }

    private fun copyTree(source: Path, target: Path): Path {
        Files.createDirectory(target, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        Files.walk(source).use { paths ->
            paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.forEach { input ->
                val out = target.resolve(source.relativize(input).toString())
                Files.createDirectories(out.parent)
                Files.copy(input, out, StandardCopyOption.COPY_ATTRIBUTES)
                Files.setPosixFilePermissions(out, PosixFilePermissions.fromString("r--------"))
            }
        }
        Files.walk(target).use { paths -> paths.filter { Files.isDirectory(it) }.forEach {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("r-x------"))
        } }
        return target
    }

    private fun makeTreeWritable(root: Path) {
        Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { path ->
            Files.setPosixFilePermissions(
                path,
                if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) PosixFilePermissions.fromString("rwx------")
                else PosixFilePermissions.fromString("rw-------"),
            )
        } }
    }

    private fun freezeTree(root: Path) {
        Files.walk(root).use { paths -> paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.forEach {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("r--------"))
        } }
        Files.walk(root).use { paths -> paths.filter { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }
            .sorted(Comparator.reverseOrder()).forEach { Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("r-x------")) } }
    }

    private fun assertDirectoryEmpty(path: Path) {
        assertTrue(Files.list(path).use { it.findAny().isEmpty })
    }

    private fun privateDirectory(path: Path): Path = Files.createDirectory(path).also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
    }

    private fun v3TreeBytes(root: Path): Map<String, List<Byte>> = Files.walk(root).use { paths ->
        paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.sorted()
            .toList().associate { root.relativize(it).toString() to Files.readAllBytes(it).toList() }
    }

    private data class V3Fixture(
        val rich: Path,
        val stripped: Path,
        val inventoryPath: Path,
        val scope: AuthenticatedFullTreeScope,
        val elfIndex: Path,
        val observationV2Root: Path,
        val observationV2IndexSha256: String,
        val scratch: Path,
        val compilerIdentity: String,
        val readelfIdentity: String,
        val compilerInputVectorMatches: Boolean,
    )

    private data class CandidateSource(
        val path: Path,
        val shard: JsonObject,
        val sourceIndex: Int,
        val source: JsonObject,
    )

    private data class V3Mutation(
        val name: String,
        val row: JsonObject,
        val mutate: (JsonObject) -> JsonObject,
    )
}
