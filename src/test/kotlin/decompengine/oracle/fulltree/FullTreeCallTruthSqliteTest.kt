package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeCallTruthSqliteTest {
    @Test
    fun `raw coordinate pairs merge partial observations without merging adjacent instruction and return addresses`() {
        inControlTemporaryDirectory { root ->
            val extra = listOf(
                FullTreeCrossShardFixtureCall("gamma-paired", "gamma", 0x305, "direct-internal", "alpha",
                    callPcRva = 0x300, returnPcRva = 0x305),
                FullTreeCrossShardFixtureCall("gamma-instruction", "gamma", 0x300, "direct-internal", "alpha",
                    callPcRva = 0x300, returnPcRva = null),
                FullTreeCrossShardFixtureCall("alpha-neighbor-paired", "alpha", 0x10a, "direct-internal", "thunk",
                    callPcRva = 0x105, returnPcRva = 0x10a),
                FullTreeCrossShardFixtureCall("alpha-neighbor-instruction", "alpha", 0x105, "direct-internal", "thunk",
                    callPcRva = 0x105, returnPcRva = null),
            )
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"), extra)
            val first = compose(fixture, root.resolve("first"), maximumWorkers = 3)
            val repeated = compose(fixture, root.resolve("repeated"), maximumWorkers = 8)
            assertEquals(11L, first.counts.edges)
            assertEquals(16L, first.counts.observations)
            val edges = calls(first.root)
            val gamma = edges.single { it["callPcRva"] == JsonPrimitive("0x300") }
            assertEquals(JsonPrimitive("0x305"), gamma["returnPcRva"])
            assertEquals(4, gamma.controlArray("observationIds").size)
            val previous = edges.single { it["returnPcRva"] == JsonPrimitive("0x105") }
            val next = edges.single { it["callPcRva"] == JsonPrimitive("0x105") }
            assertNotEquals(previous["id"], next["id"])
            assertEquals(JsonNull, previous["callPcRva"])
            assertEquals(JsonPrimitive("0x10a"), next["returnPcRva"])
            assertEquals(JsonPrimitive("0x5"), next["callerLocalCallOffset"])
            assertEquals(JsonPrimitive("0xa"), next["callerLocalReturnOffset"])
            assertEquals(3, next.controlArray("observationIds").size)
            assertEquals(first.indexArtifactSha256, repeated.indexArtifactSha256)
            assertEquals(treeBytes(first.root), treeBytes(repeated.root))
            assertEquals(first.indexArtifactSha256, validate(fixture, first.root).indexArtifactSha256)
            assertNonAuthoritative(first)
            assertClean(fixture)
        }
    }

    @Test
    fun `conflicting raw instruction to return mappings fail closed in both directions`() {
        for ((callPc, returnPc) in listOf(0x100L to 0x106L, 0x101L to 0x105L)) {
            inControlTemporaryDirectory { root ->
                val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"), listOf(
                    FullTreeCrossShardFixtureCall("pair-first", "alpha", 0x105, "direct-internal", "beta",
                        callPcRva = 0x100, returnPcRva = 0x105),
                    FullTreeCrossShardFixtureCall("pair-conflict", "alpha", returnPc, "direct-internal", "beta",
                        callPcRva = callPc, returnPcRva = returnPc),
                ))
                val output = root.resolve("conflicting")
                val failure = assertFailsWith<FullTreeCallTruthException> { compose(fixture, output) }
                assertTrue(generateSequence<Throwable>(failure) { it.cause }
                    .any { it.message.orEmpty().contains("conflicting raw mappings") })
                assertFalse(Files.exists(output))
                assertClean(fixture)
            }
        }
    }

    @Test
    fun `raw policy four configuration binds the frozen policy and both exact schemas`() {
        assertEquals(
            "5a3549d94b691d70cc2ea98b919ac40127c8cd73f76b29df47c0c1b977f306f7",
            FullTreeCallTruthSqlite.configurationSha256,
        )
    }

    @Test
    fun `raw three shard composition preserves cycles aliases physical thunks and proven singleton targets`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val first = compose(fixture, root.resolve("truth-first"), maximumWorkers = 3)
            val repeated = compose(fixture, root.resolve("truth-repeated"), maximumWorkers = 8)
            assertEquals(first.index, repeated.index)
            assertEquals(first.indexArtifactSha256, repeated.indexArtifactSha256)
            assertEquals(first.indexSha256, repeated.indexSha256)
            assertEquals(treeBytes(first.root), treeBytes(repeated.root))
            assertEquals(first.counts, repeated.counts)
            assertEquals(11L, first.counts.edges)
            assertEquals(12L, first.counts.observations)
            assertEquals(6L, first.counts.directInternal)
            assertEquals(1L, first.counts.external)
            assertEquals(1L, first.counts.indirectProven)
            assertEquals(2L, first.counts.indirectUnresolved)
            assertEquals(1L, first.counts.virtualUnresolved)
            assertEquals(2L, first.counts.tailCalls)
            assertEquals(2L, first.counts.unobservable)
            assertTrue(first.databaseHighWaterBytes > 0L)
            assertNonAuthoritative(first)
            assertTrue(first.rawInputsRederived)
            assertFalse(first.candidateBytesMatchedAtValidationBoundary)
            assertPublishedTree(first, fixture)

            val byAddress = calls(first.root).filter { it["returnPcRva"] != JsonNull }
                .associateBy { it.controlString("returnPcRva") }
            for ((address, caller, target) in listOf(
                Triple("0x105", "alpha", "beta"),
                Triple("0x205", "beta", "gamma"),
                Triple("0x305", "gamma", "alpha"),
            )) {
                val edge = byAddress.getValue(address)
                assertNotEquals(fixture.raw.shardForFunction(caller), fixture.raw.shardForFunction(target))
                assertEquals(fixture.raw.functionIds.getValue(caller), edge.controlString("callerId"))
                assertEquals(fixture.raw.functionIds.getValue(target), edge.controlString("physicalTargetId"))
                assertEquals(edge["physicalTargetId"], edge["semanticTargetId"])
                assertEquals("direct-internal", edge.controlString("targetKind"))
                assertEquals("scored", edge.controlString("population"))
            }
            val thunk = byAddress.getValue("0x10a")
            assertEquals(fixture.raw.functionIds.getValue("thunk"), thunk.controlString("physicalTargetId"))
            assertEquals(JsonNull, thunk["semanticTargetId"])
            assertEquals("thunk-semantic-target-unresolved", thunk.controlString("reasonCode"))
            assertEquals("scored", thunk.controlString("population"))
            val byInstruction = calls(first.root).filter { it["callPcRva"] != JsonNull }
                .associateBy { it.controlString("callPcRva") }
            assertEquals(JsonPrimitive(true), byInstruction.getValue("0x220")["tailCall"])
            assertEquals(JsonPrimitive(true), byInstruction.getValue("0x380")["tailCall"])
            assertEquals("0x0", byInstruction.getValue("0x380").controlString("callerLocalCallOffset"))
            assertTrue(byInstruction.values.all { it["returnPcRva"] == JsonNull && it["callerLocalReturnOffset"] == JsonNull })

            val external = byAddress.getValue("0x10c")
            assertEquals("external", external.controlString("targetKind"))
            assertEquals("scored", external.controlString("population"))
            assertEquals(
                JsonArray(listOf(JsonPrimitive(
                    "external-function-${OracleArtifacts.sha256("fixture_external".toByteArray()).take(32)}",
                ))),
                external["externalTargetIds"],
            )
            val proven = byAddress.getValue("0x118")
            assertEquals("indirect-proven", proven.controlString("targetKind"))
            assertEquals("call-target-expression", proven.controlString("targetEvidence"))
            assertEquals(
                JsonArray(listOf(JsonPrimitive(fixture.raw.functionIds.getValue("callback")))),
                proven["provenTargetIds"],
            )
            assertEquals("virtual-unresolved", byAddress.getValue("0x207").controlString("targetKind"))
            assertEquals("virtual-target-set-unproven", byAddress.getValue("0x207").controlString("reasonCode"))
            assertEquals("indirect-unresolved", byAddress.getValue("0x209").controlString("targetKind"))
            assertEquals("scored", byAddress.getValue("0x209").controlString("population"))
            val addressless = calls(first.root).single { it["returnPcRva"] == JsonNull && it["callPcRva"] == JsonNull }
            assertEquals(JsonNull, addressless["callerId"])
            assertEquals("call-site-no-address", addressless.controlString("reasonCode"))
            assertEquals("unobservable", addressless.controlString("population"))
            val duplicate = byAddress.getValue("0x305")
            assertEquals(2, duplicate.controlArray("observationIds").size)
            assertEquals(12, calls(first.root).flatMap { it.controlArray("observationIds") }.toSet().size)

            val betaFunction = parseControlObject(
                fixture.functionTruth.root.resolve("shards/${fixture.raw.shardForFunction("beta")}.json"),
            ).controlArray("functions").controlObjects("functions")
                .single { it.controlString("id") == fixture.raw.functionIds.getValue("beta") }
            assertEquals(
                setOf("beta", "_ZN4Beta4callEv"),
                betaFunction.controlArray("aliases").controlObjects("aliases").map { it.controlString("name") }.toSet(),
            )
            val validated = validate(fixture, first.root, maximumWorkers = 8)
            assertTrue(validated.rawInputsRederived)
            assertTrue(validated.candidateBytesMatchedAtValidationBoundary)
            assertNonAuthoritative(validated)
            assertEquals(first.indexArtifactSha256, validated.indexArtifactSha256)
            assertEquals(first.counts, validated.counts)
            assertEquals(treeBytes(first.root), treeBytes(repeated.root))
            assertClean(fixture)
        }

    @Test
    fun `independent validation rejects a schema valid rehashed forged truth without repairing it`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val original = compose(fixture, root.resolve("truth"))
            val forged = copyTree(original.root, root.resolve("forged"))
            mutateTruthShard(forged, fixture.raw.shardForFunction("alpha")) { shard ->
                JsonObject(shard.toMutableMap().apply {
                    this["calls"] = JsonArray(shard.controlArray("calls").controlObjects("calls").map { edge ->
                        if (edge["returnPcRva"] != JsonPrimitive("0x105")) edge else {
                            JsonObject(edge.toMutableMap().apply {
                                this["physicalTargetId"] = JsonPrimitive(fixture.raw.functionIds.getValue("gamma"))
                                this["semanticTargetId"] = JsonPrimitive(fixture.raw.functionIds.getValue("gamma"))
                            })
                        }
                    })
                })
            }
            val before = treeBytes(forged)
            assertFailsWith<FullTreeCallTruthException> { validate(fixture, forged) }
            assertEquals(before, treeBytes(forged))
            assertNotEquals(treeBytes(original.root), before)
            assertClean(fixture)
        }

    @Test
    fun `missing extra linked writable and wrong shard candidates fail closed without mutation`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val original = compose(fixture, root.resolve("truth"))
            val shardName = "${fixture.raw.shardIds.first()}.json"
            val mutations = linkedMapOf<String, (Path) -> Unit>(
                "missing" to { candidate -> Files.delete(candidate.resolve("shards/$shardName")) },
                "extra" to { candidate -> Files.write(candidate.resolve("unexpected.json"), byteArrayOf(1)) },
                "hardlink" to { candidate ->
                    Files.delete(candidate.resolve("shards/$shardName"))
                    Files.createLink(candidate.resolve("shards/$shardName"), candidate.resolve("index.json"))
                },
                "symlink" to { candidate ->
                    Files.delete(candidate.resolve("shards/$shardName"))
                    Files.createSymbolicLink(candidate.resolve("shards/$shardName"), original.root.resolve("shards/$shardName"))
                },
                "wrong-shard" to { candidate ->
                    Files.move(candidate.resolve("shards/$shardName"), candidate.resolve("shards/not-an-inventory-shard.json"))
                },
            )
            mutations.forEach { (name, mutation) ->
                val candidate = copyTree(original.root, root.resolve(name))
                makeWritable(candidate)
                mutation(candidate)
                freeze(candidate)
                val before = treeBytes(candidate)
                assertFailsWith<FullTreeCallTruthException>(name) { validate(fixture, candidate) }
                assertEquals(before, treeBytes(candidate), name)
                assertClean(fixture)
            }
            val writable = copyTree(original.root, root.resolve("writable"))
            Files.setPosixFilePermissions(writable.resolve("index.json"), PosixFilePermissions.fromString("rw-------"))
            val before = treeBytes(writable)
            assertFailsWith<FullTreeCallTruthException> { validate(fixture, writable) }
            assertEquals(before, treeBytes(writable))
            assertFailsWith<FullTreeCallTruthException> { validate(fixture, root.resolve("absent")) }
            assertFalse(Files.exists(root.resolve("absent"), LinkOption.NOFOLLOW_LINKS))
            assertClean(fixture)
        }

    @Test
    fun `schema valid dangling call references and historical policy two never enter composition`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val mutations = linkedMapOf<String, (JsonObject) -> JsonObject>(
                "dangling-caller" to { call ->
                    JsonObject(call.toMutableMap().apply { this["callerId"] = JsonPrimitive("function-rva-0x999") })
                },
                "dangling-direct" to { call -> mutateTarget(call) { target ->
                    JsonObject(target.toMutableMap().apply { this["functionId"] = JsonPrimitive("function-rva-0x999") })
                } },
                "dangling-proven" to { call -> mutateTarget(call) { target ->
                    JsonObject(target.toMutableMap().apply {
                        this["provenFunctionIds"] = JsonArray(listOf(JsonPrimitive("function-rva-0x999")))
                    })
                } },
            )
            mutations.forEach { (name, mutation) ->
                val run = forgeCallRun(fixture, root.resolve(name), name) { shard ->
                    JsonObject(shard.toMutableMap().apply {
                        this["calls"] = JsonArray(shard.controlArray("calls").controlObjects("calls").map { call ->
                            val expectedAddress = if (name == "dangling-proven") "0x118" else "0x105"
                            if (call["returnPcRva"] == JsonPrimitive(expectedAddress)) mutation(call) else call
                        })
                    })
                }
                val before = treeBytes(run.root)
                val output = root.resolve("$name-output")
                assertFailsWith<FullTreeCallTruthException>(name) {
                    compose(fixture, output, callRoot = run.root, callIndexSha256 = run.indexArtifactSha256)
                }
                assertEquals(before, treeBytes(run.root))
                assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
                assertClean(fixture)
            }
            for ((version, digest) in listOf(
                2 to FullTreeCallObservations.historicalV2ConfigurationSha256,
                3 to FullTreeCallObservations.historicalV3ConfigurationSha256,
            )) {
                val historical = forgeCallRun(fixture, root.resolve("policy-$version"), "policy-$version") { shard ->
                    JsonObject(shard.toMutableMap().apply {
                        this["oracle"] = JsonObject(shard.controlObject("oracle").toMutableMap().apply {
                            this["configurationSha256"] = JsonPrimitive(digest)
                        })
                    })
                }
                val before = treeBytes(historical.root)
                val output = root.resolve("policy-$version-output")
                assertFailsWith<FullTreeCallTruthException> {
                    compose(fixture, output, callRoot = historical.root, callIndexSha256 = historical.indexArtifactSha256)
                }
                assertEquals(before, treeBytes(historical.root))
                assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
                assertClean(fixture)
            }
        }

    @Test
    fun `rehashed function truth forgery and missing raw input members cannot supply facts`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val forged = copyTree(fixture.functionTruth.root, root.resolve("forged-functions"))
            mutateTruthShard(forged, fixture.raw.shardForFunction("alpha"), "full-tree-function-truth") { shard ->
                val functions = shard.controlArray("functions").controlObjects("functions").toMutableList()
                val function = functions.first()
                val aliases = function.controlArray("aliases").controlObjects("aliases").toMutableList()
                val alias = aliases.first()
                val evidence = alias.controlArray("evidence").controlObjects("evidence").toMutableList()
                evidence[0] = JsonObject(evidence.first().toMutableMap().apply {
                    this["locator"] = JsonPrimitive(evidence.first().controlString("locator") + ":forged")
                })
                aliases[0] = JsonObject(alias.toMutableMap().apply { this["evidence"] = JsonArray(evidence) })
                functions[0] = JsonObject(function.toMutableMap().apply { this["aliases"] = JsonArray(aliases) })
                JsonObject(shard.toMutableMap().apply { this["functions"] = JsonArray(functions) })
            }
            val forgedBytes = treeBytes(forged)
            val forgedOutput = root.resolve("forged-functions-output")
            assertFailsWith<FullTreeCallTruthException> {
                compose(fixture, forgedOutput, functionTruthRoot = forged)
            }
            assertEquals(forgedBytes, treeBytes(forged))
            assertFalse(Files.exists(forgedOutput, LinkOption.NOFOLLOW_LINKS))
            assertClean(fixture)

            val missing = copyTree(fixture.callRun.root, root.resolve("missing-raw-call-shard"))
            makeWritable(missing)
            Files.delete(missing.resolve("outputs/${fixture.raw.shardIds.first()}.json"))
            freeze(missing)
            val missingBytes = treeBytes(missing)
            val missingOutput = root.resolve("missing-raw-output")
            assertFailsWith<FullTreeCallTruthException> { compose(fixture, missingOutput, callRoot = missing) }
            assertEquals(missingBytes, treeBytes(missing))
            assertFalse(Files.exists(missingOutput, LinkOption.NOFOLLOW_LINKS))
            assertClean(fixture)
        }

    @Test
    fun `output database grouping and scratch bounds reject without publishing or leaking`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val bounds = linkedMapOf(
                "output" to FullTreeCallTruthLimits(maximumOutputBytes = 128),
                "database" to FullTreeCallTruthLimits(maximumDatabaseBytes = 4096),
                "group-rows" to FullTreeCallTruthLimits(maximumGroupRows = 1),
                "group-bytes" to FullTreeCallTruthLimits(maximumGroupBytes = 32),
                "scratch" to FullTreeCallTruthLimits(maximumDatabaseBytes = 64 * 1024, maximumScratchBytes = 64 * 1024),
            )
            bounds.forEach { (name, limits) ->
                val output = root.resolve(name)
                assertFailsWith<FullTreeCallTruthException>(name) { compose(fixture, output, limits = limits) }
                assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
                assertClean(fixture)
            }
            assertFailsWith<IllegalArgumentException> { FullTreeCallTruthLimits(modeledResidentBytes = 1) }
            assertFailsWith<IllegalArgumentException> { FullTreeCallTruthLimits(maximumGroupRows = 0) }
            assertFailsWith<IllegalArgumentException> { FullTreeCallTruthLimits(maximumAliasTargets = 0) }
        }

    @Test
    fun `occupied overlapping linked destinations and wrong input bindings preserve original bytes`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val sentinel = "preserve occupied output\n".toByteArray()
            val occupied = root.resolve("occupied")
            Files.write(occupied, sentinel)
            Files.setPosixFilePermissions(occupied, PosixFilePermissions.fromString("rw-------"))
            val linked = root.resolve("linked")
            Files.createSymbolicLink(linked, occupied)
            listOf(occupied, linked, fixture.functions.scratch.resolve("overlap"), fixture.functionTruth.root).forEach { output ->
                assertFailsWith<FullTreeCallTruthException> { compose(fixture, output) }
            }
            assertContentEquals(sentinel, Files.readAllBytes(occupied))
            assertTrue(Files.isSymbolicLink(linked))
            val output = root.resolve("wrong-call-index")
            assertFailsWith<FullTreeCallTruthException> { compose(fixture, output, callIndexSha256 = "f".repeat(64)) }
            assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
            val wrongFunctions = root.resolve("wrong-function-index")
            assertFailsWith<FullTreeCallTruthException> {
                compose(fixture, wrongFunctions, functionIndexSha256 = "f".repeat(64))
            }
            assertFalse(Files.exists(wrongFunctions, LinkOption.NOFOLLOW_LINKS))
            listOf(0, 33).forEach { workers ->
                val workerOutput = root.resolve("workers-$workers")
                assertFailsWith<FullTreeCallTruthException> { compose(fixture, workerOutput, maximumWorkers = workers) }
                assertFalse(Files.exists(workerOutput, LinkOption.NOFOLLOW_LINKS))
            }
            assertClean(fixture)
        }

    @Test
    fun `interrupted composition preserves interrupt and leaves no candidate or scratch residue`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val output = root.resolve("interrupted")
            try {
                Thread.currentThread().interrupt()
                assertFailsWith<FullTreeCallTruthException> { compose(fixture, output) }
                assertTrue(Thread.currentThread().isInterrupted)
            } finally {
                Thread.interrupted()
            }
            assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
            assertClean(fixture)
        }

    private fun compose(
        fixture: FullTreeCallTruthTestFixture,
        output: Path,
        maximumWorkers: Int = 3,
        limits: FullTreeCallTruthLimits = FullTreeCallTruthLimits(),
        callRoot: Path = fixture.callRun.root,
        callIndexSha256: String = fixture.callRun.indexArtifactSha256,
        functionIndexSha256: String = fixture.functions.observationIndexArtifactSha256,
        functionTruthRoot: Path = fixture.functionTruth.root,
    ): FullTreeCallTruthPublication = FullTreeCallTruthSqlite.generateAndPublish(
        richArtifact = fixture.raw.artifact,
        strippedArtifact = fixture.raw.strippedArtifact,
        inventoryPath = fixture.raw.inventoryPath,
        elfFunctionIndex = fixture.functions.elfIndex,
        functionObservationRoot = fixture.functions.observationRoot,
        expectedFunctionObservationIndexArtifactSha256 = functionIndexSha256,
        functionTruthRoot = functionTruthRoot,
        callObservationRoot = callRoot,
        expectedCallObservationIndexArtifactSha256 = callIndexSha256,
        scope = fixture.raw.scope,
        scratchParent = fixture.functions.scratch,
        outputRoot = output,
        maximumWorkers = maximumWorkers,
        limits = limits,
    )

    private fun validate(
        fixture: FullTreeCallTruthTestFixture,
        candidate: Path,
        maximumWorkers: Int = 3,
    ): FullTreeCallTruthPublication = FullTreeCallTruthSqlite.loadAndValidate(
        candidateRoot = candidate,
        richArtifact = fixture.raw.artifact,
        strippedArtifact = fixture.raw.strippedArtifact,
        inventoryPath = fixture.raw.inventoryPath,
        elfFunctionIndex = fixture.functions.elfIndex,
        functionObservationRoot = fixture.functions.observationRoot,
        expectedFunctionObservationIndexArtifactSha256 = fixture.functions.observationIndexArtifactSha256,
        functionTruthRoot = fixture.functionTruth.root,
        callObservationRoot = fixture.callRun.root,
        expectedCallObservationIndexArtifactSha256 = fixture.callRun.indexArtifactSha256,
        scope = fixture.raw.scope,
        scratchParent = fixture.functions.scratch,
        maximumWorkers = maximumWorkers,
    )

    private fun assertNonAuthoritative(receipt: FullTreeCallTruthPublication) {
        assertFalse(receipt.candidateLeaseRetained)
        assertFalse(receipt.downstreamScoringAuthorized)
        assertFalse(receipt.authoritativeReleaseEvidence)
    }

    private fun assertPublishedTree(receipt: FullTreeCallTruthPublication, fixture: FullTreeCallTruthTestFixture) {
        assertEquals(setOf("index.json", "shards"), childNames(receipt.root))
        assertEquals(fixture.raw.shardIds.map { "$it.json" }.toSet(), childNames(receipt.root.resolve("shards")))
        val index = parseControlObject(receipt.root.resolve("index.json"))
        OracleSchemas.validate("full-tree-call-truth-index", index)
        assertEquals(receipt.index, index)
        assertEquals(receipt.indexSha256, index.controlString("indexSha256"))
        assertEquals(receipt.indexArtifactSha256, sha256(receipt.root.resolve("index.json")))
        assertEquals(fixture.functionTruth.indexArtifactSha256, receipt.functionTruthIndexArtifactSha256)
        assertEquals(sha256(fixture.functions.elfIndex), receipt.elfIndexArtifactSha256)
        assertEquals(fixture.callRun.indexArtifactSha256, receipt.callObservationIndexArtifactSha256)
        val oracle = index.controlObject("oracle")
        assertEquals("non-authoritative-kotlin-raw-call-truth-v3", oracle.controlString("authority"))
        assertEquals(FullTreeCallTruthSqlite.configurationSha256, oracle.controlString("configurationSha256"))
        assertEquals(FullTreeCallObservations.configurationSha256, oracle.controlString("callObservationConfigurationSha256"))
        assertNotEquals(FullTreeCallObservations.historicalV2ConfigurationSha256, oracle.controlString("callObservationConfigurationSha256"))
        assertEquals(fixture.callRun.indexArtifactSha256, oracle.controlString("callObservationIndexSha256"))
        assertEquals(fixture.functionTruth.indexArtifactSha256, oracle.controlString("functionTruthIndexSha256"))
        assertEquals(fixture.raw.scope.sha256, oracle.controlString("scopeSha256"))
        assertEquals(sha256(fixture.raw.artifact), oracle.controlString("richArtifactSha256"))
        assertEquals(sha256(fixture.raw.strippedArtifact), oracle.controlString("strippedArtifactSha256"))
        assertNotEquals(
            FullTreeCallTruthAssessmentVerifier.historicalCallTruthConfigurationSha256,
            oracle.controlString("configurationSha256"),
        )
        val records = index.controlArray("shards").controlObjects("shards")
        assertEquals(fixture.raw.shardIds, records.map { it.controlString("id") })
        var totalBytes = Files.size(receipt.root.resolve("index.json"))
        records.forEach { record ->
            val output = receipt.root.resolve(record.controlString("path"))
            assertEquals(record.controlLong("bytes"), Files.size(output))
            assertEquals(record.controlString("sha256"), sha256(output))
            val shard = parseControlObject(output)
            OracleSchemas.validate("full-tree-call-truth-v2", shard)
            assertEquals(oracle, shard.controlObject("oracle"))
            assertContentEquals(OracleJson.canonicalBytes(shard), Files.readAllBytes(output))
            val edges = shard.controlArray("calls").controlObjects("calls")
            assertEquals(edges.map { it.controlString("id") }.sorted(), edges.map { it.controlString("id") })
            edges.forEach { edge ->
                if (edge["callerId"] != JsonNull) {
                    val owner = fixture.raw.functions.entries.single { it.value.functionId == edge.controlString("callerId") }.key
                    assertEquals(fixture.raw.shardForFunction(owner), record.controlString("id"))
                }
            }
            totalBytes += Files.size(output)
        }
        assertEquals(receipt.outputBytes, totalBytes)
        Files.walk(receipt.root).use { paths ->
            paths.forEach { path ->
                assertEquals(
                    PosixFilePermissions.fromString(if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) "r-x------" else "r--------"),
                    Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS),
                )
            }
        }
    }

    private fun forgeCallRun(
        fixture: FullTreeCallTruthTestFixture,
        parent: Path,
        label: String,
        mutation: (JsonObject) -> JsonObject,
    ): BoundedShardRunBinding {
        callTruthPrivateDirectory(parent)
        val preparedRoot = callTruthPrivateDirectory(parent.resolve("prepared"))
        val prepared = fixture.callRun.outputs.map { receipt ->
            val original = parseControlObject(fixture.callRun.root.resolve("outputs/${receipt.shardId}.json"))
            val forged = mutation(original)
            OracleSchemas.validate("full-tree-call-observations-v2", forged)
            val bytes = OracleJson.canonicalBytes(forged)
            val output = preparedRoot.resolve("${receipt.shardId}.json")
            Files.write(output, bytes)
            Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("r--------"))
            BoundedShardPreparedOutput(receipt.shardId, receipt.inputSha256, output, OracleArtifacts.sha256(bytes), bytes.size.toLong(), receipt.entities)
        }
        return BoundedShardRunPublisher.publish(
            target = parent.resolve("$label-run"),
            runId = "full-tree-calls-${fixture.raw.scope.sha256.take(16)}",
            preparedOutputs = prepared,
            bounds = callTruthTestRunBounds(fixture.raw),
            semanticValidator = BoundedShardOutputSemanticValidator { output ->
                OracleSchemas.validate("full-tree-call-observations-v2", parseControlObject(output.output))
            },
        )
    }

    private fun mutateTarget(call: JsonObject, mutation: (JsonObject) -> JsonObject): JsonObject =
        JsonObject(call.toMutableMap().apply { this["target"] = mutation(call.controlObject("target")) })

    private fun mutateTruthShard(
        root: Path,
        shardId: String,
        schemaName: String = "full-tree-call-truth-v2",
        mutation: (JsonObject) -> JsonObject,
    ) {
        makeWritable(root)
        val shardPath = root.resolve("shards/$shardId.json")
        val shard = mutation(parseControlObject(shardPath))
        OracleSchemas.validate(schemaName, shard)
        val bytes = OracleJson.canonicalBytes(shard)
        Files.write(shardPath, bytes)
        val index = parseControlObject(root.resolve("index.json"))
        val modified = JsonObject(index.toMutableMap().apply {
            remove("indexSha256")
            this["shards"] = JsonArray(index.controlArray("shards").controlObjects("shards").map { record ->
                if (record.controlString("id") != shardId) record else JsonObject(record.toMutableMap().apply {
                    this["bytes"] = JsonPrimitive(bytes.size)
                    this["sha256"] = JsonPrimitive(OracleArtifacts.sha256(bytes))
                })
            })
        })
        val rebound = JsonObject(modified + ("indexSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(modified)))))
        OracleSchemas.validate(if (schemaName == "full-tree-call-truth-v2") "full-tree-call-truth-index" else "$schemaName-index", rebound)
        Files.write(root.resolve("index.json"), OracleJson.canonicalBytes(rebound))
        freeze(root)
    }

    private fun calls(root: Path): List<JsonObject> = parseControlObject(root.resolve("index.json"))
        .controlArray("shards").controlObjects("shards").flatMap { record ->
            parseControlObject(root.resolve(record.controlString("path"))).controlArray("calls").controlObjects("calls")
        }

    private fun treeBytes(root: Path): Map<String, List<Byte>> = Files.walk(root).use { paths ->
        paths.filter { !Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }.sorted().toList().associate { path ->
            root.relativize(path).toString() to if (Files.isSymbolicLink(path)) {
                Files.readSymbolicLink(path).toString().toByteArray().toList()
            } else Files.readAllBytes(path).toList()
        }
    }

    private fun copyTree(source: Path, target: Path): Path {
        callTruthPrivateDirectory(target)
        Files.walk(source).use { paths ->
            paths.filter { it != source }.forEach { path ->
                val output = target.resolve(source.relativize(path))
                if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) callTruthPrivateDirectory(output)
                else Files.copy(path, output)
            }
        }
        freeze(target)
        return target
    }

    private fun makeWritable(root: Path) {
        Files.walk(root).use { paths ->
            paths.forEach { path ->
                if (!Files.isSymbolicLink(path)) Files.setPosixFilePermissions(
                    path,
                    PosixFilePermissions.fromString(if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) "rwx------" else "rw-------"),
                )
            }
        }
    }

    private fun freeze(root: Path) {
        Files.walk(root).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach { path ->
                if (!Files.isSymbolicLink(path)) Files.setPosixFilePermissions(
                    path,
                    PosixFilePermissions.fromString(if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) "r-x------" else "r--------"),
                )
            }
        }
    }

    private fun assertClean(fixture: FullTreeCallTruthTestFixture) {
        assertEquals(emptySet(), childNames(fixture.functions.scratch))
        Files.walk(fixture.raw.root.parent).use { paths ->
            assertEquals(emptyList(), paths.filter { path ->
                val name = path.fileName.toString()
                name.startsWith(".call-truth-") || name.startsWith(".function-truth-") ||
                    name.contains(".elf-functions-scratch-") || name.startsWith(".call-observation-")
            }.toList())
        }
    }

    private fun childNames(root: Path): Set<String> = Files.list(root).use { paths -> paths.map { it.fileName.toString() }.toList().toSet() }

    private fun sha256(path: Path): String = OracleArtifacts.sha256(Files.readAllBytes(path))
}
