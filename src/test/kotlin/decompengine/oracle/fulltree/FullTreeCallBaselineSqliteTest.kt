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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeCallBaselineSqliteTest {
    @Test
    fun `raw baseline reports observability without double credit and validates deterministically`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val truth = compose(fixture, root.resolve("truth"))
            val serial = generate(fixture, truth.root, root.resolve("serial"))
            val repeated = generate(fixture, truth.root, root.resolve("repeated"), workers = 8)
            val validated = validate(fixture, truth.root, serial.root)
            assertEquals(FullTreeCallBaselineMetric(7, 2, 2), serial.aggregate)
            assertEquals(9L, serial.aggregate.denominator)
            assertEquals(0L, serial.aggregate.missing)
            assertEquals(0L, serial.aggregate.fabricated)
            assertEquals(truth.indexArtifactSha256, serial.truthIndexArtifactSha256)
            assertTrue(serial.databaseHighWaterBytes > 0)
            assertFalse(serial.candidateBytesMatchedAtValidationBoundary)
            assertTrue(validated.candidateBytesMatchedAtValidationBoundary)
            for (receipt in listOf(serial, repeated, validated)) {
                assertTrue(receipt.rawInputsRederived)
                assertFalse(receipt.candidateLeaseRetained)
                assertFalse(receipt.downstreamScoringAuthorized)
                assertFalse(receipt.authoritativeReleaseEvidence)
                assertFalse(receipt.recoveredModelScored)
                assertEquals(serial.aggregate, receipt.aggregate)
                assertEquals(serial.reportSha256, receipt.reportSha256)
                assertEquals(serial.artifactSha256, receipt.artifactSha256)
                assertEquals(serial.outputBytes, receipt.outputBytes)
            }
            val bytes = Files.readAllBytes(serial.root.resolve("report.json"))
            val report = parseControlObject(serial.root.resolve("report.json"))
            OracleSchemas.validate("full-tree-call-baseline", report)
            assertContentEquals(OracleJson.canonicalBytes(report), bytes)
            assertEquals(serial.outputBytes, bytes.size.toLong())
            assertEquals(serial.artifactSha256, OracleArtifacts.sha256(bytes))
            assertEquals(serial.reportSha256, OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(report - "reportSha256"))))
            assertEquals(FullTreeCallBaselineSqlite.configurationSha256, report.controlString("configurationSha256"))
            assertEquals("708bc81e3dad00944dbda89cda2e0282e2145b2d850155b2d8655fbede64399d", FullTreeCallBaselineSqlite.configurationSha256)
            assertEquals(serial.aggregate.toJson(), report.controlObject("aggregate"))
            val shards = report.controlArray("shards").controlObjects("shards")
            assertEquals(fixture.raw.shardIds, shards.map { it.controlString("id") })
            for (field in listOf("denominator", "exact", "partial", "excluded", "missing", "fabricated")) {
                assertEquals(report.controlObject("aggregate").controlLong(field), shards.sumOf { it.controlObject("metric").controlLong(field) })
            }
            val mismatches = report.controlArray("mismatches").controlObjects("mismatches")
            assertEquals(2, mismatches.size)
            assertEquals(mismatches.map { it.controlString("id") }.sorted(), mismatches.map { it.controlString("id") })
            val calls = truth.index.controlArray("shards").controlObjects("shards").flatMap { record ->
                parseControlObject(truth.root.resolve(record.controlString("path"))).controlArray("calls").controlObjects("calls")
            }.associateBy { it.controlString("id") }
            assertEquals(setOf("0x10a", "0x209"), mismatches.map { calls.getValue(it.controlString("truthId")).controlString("returnPcRva") }.toSet())
            mismatches.forEach { mismatch ->
                assertEquals("partial", mismatch.controlString("kind"))
                assertEquals(calls.getValue(mismatch.controlString("truthId"))["reasonCode"], mismatch["reasonCode"])
            }
            assertEquals(setOf("report.json"), childNames(serial.root))
            assertEquals(PosixFilePermissions.fromString("r-x------"), Files.getPosixFilePermissions(serial.root))
            assertEquals(PosixFilePermissions.fromString("r--------"), Files.getPosixFilePermissions(serial.root.resolve("report.json")))
            assertContentEquals(bytes, Files.readAllBytes(repeated.root.resolve("report.json")))
            assertClean(fixture)
        }

    @Test
    fun `zero edge raw truth retains every inventory shard and canonical empty mismatches`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = createFunctionTruthFixture(root.resolve("inputs"))
            val functions = generateTruth(fixture, root.resolve("functions"), maximumWorkers = 3)
            val calls = FullTreeCallObservationRunPublisher.generateAndPublish(
                fixture.rich, fixture.inventoryPath, fixture.scope, fixture.scratch,
                callTruthPrivateDirectory(root.resolve("call-outputs")).resolve("calls"), 3,
            )
            val truth = FullTreeCallTruthSqlite.generateAndPublish(
                fixture.rich, fixture.stripped, fixture.inventoryPath, fixture.elfIndex, fixture.observationRoot,
                fixture.observationIndexArtifactSha256, functions.root, calls.root, calls.indexArtifactSha256,
                fixture.scope, fixture.scratch, root.resolve("truth"), 3,
            )
            assertEquals(0L, truth.counts.edges)
            val baseline = FullTreeCallBaselineSqlite.generateAndPublishFromRawInputs(
                truth.root, fixture.rich, fixture.stripped, fixture.inventoryPath, fixture.elfIndex, fixture.observationRoot,
                fixture.observationIndexArtifactSha256, functions.root, calls.root, calls.indexArtifactSha256,
                fixture.scope, fixture.scratch, root.resolve("baseline"), 3,
            )
            val validated = FullTreeCallBaselineSqlite.loadAndValidateFromRawInputs(
                baseline.root, truth.root, fixture.rich, fixture.stripped, fixture.inventoryPath, fixture.elfIndex, fixture.observationRoot,
                fixture.observationIndexArtifactSha256, functions.root, calls.root, calls.indexArtifactSha256,
                fixture.scope, fixture.scratch, 3,
            )
            assertEquals(FullTreeCallBaselineMetric(0, 0, 0), baseline.aggregate)
            assertEquals(baseline.artifactSha256, validated.artifactSha256)
            val report = parseControlObject(baseline.root.resolve("report.json"))
            OracleSchemas.validate("full-tree-call-baseline", report)
            assertContentEquals(OracleJson.canonicalBytes(report), Files.readAllBytes(baseline.root.resolve("report.json")))
            assertEquals(JsonArray(emptyList()), report.controlArray("mismatches"))
            assertEquals(fixture.inventory.controlArray("shards").controlObjects("inventory").map { it.controlString("id") },
                report.controlArray("shards").controlObjects("metrics").map { it.controlString("id") })
            assertEquals(emptySet(), childNames(fixture.scratch))
        }

    @Test
    fun `schema valid self consistent forged baseline fails independent raw validation without repair`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val truth = compose(fixture, root.resolve("truth"))
            val baseline = generate(fixture, truth.root, root.resolve("baseline"))
            val report = parseControlObject(baseline.root.resolve("report.json"))
            val forged = copyTree(baseline.root, root.resolve("forged"))
            val unsigned = JsonObject(report.toMutableMap().apply {
                remove("reportSha256")
                this["aggregate"] = FullTreeCallBaselineMetric(9, 0, 2).toJson()
                this["shards"] = JsonArray(report.controlArray("shards").controlObjects("shards").map { shard ->
                    val metric = shard.controlObject("metric")
                    JsonObject(shard + ("metric" to FullTreeCallBaselineMetric(
                        metric.controlLong("exact") + metric.controlLong("partial"), 0, metric.controlLong("excluded"),
                    ).toJson()))
                })
                this["mismatches"] = JsonArray(emptyList())
            })
            val rebound = JsonObject(unsigned + ("reportSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned)))))
            OracleSchemas.validate("full-tree-call-baseline", rebound)
            writeFrozen(forged.resolve("report.json"), OracleJson.canonicalBytes(rebound))
            val before = treeBytes(forged)
            assertFailsWith<FullTreeCallBaselineException> { validate(fixture, truth.root, forged) }
            assertEquals(before, treeBytes(forged))
            assertNotEquals(treeBytes(baseline.root), before)
            assertClean(fixture)
        }

    @Test
    fun `rehashed forged call truth and changed raw artifact cannot authorize a baseline`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val truth = compose(fixture, root.resolve("truth"))
            val forged = copyTree(truth.root, root.resolve("forged-truth"))
            val owner = fixture.raw.shardForFunction("alpha")
            val path = forged.resolve("shards/$owner.json")
            val original = parseControlObject(path)
            val modified = JsonObject(original + ("calls" to JsonArray(original.controlArray("calls").controlObjects("calls").map { call ->
                if (call["returnPcRva"] != JsonPrimitive("0x105")) call else JsonObject(call.toMutableMap().apply {
                    this["physicalTargetId"] = JsonPrimitive(fixture.raw.functionIds.getValue("gamma"))
                    this["semanticTargetId"] = JsonPrimitive(fixture.raw.functionIds.getValue("gamma"))
                })
            })))
            OracleSchemas.validate("full-tree-call-truth-v2", modified)
            val bytes = OracleJson.canonicalBytes(modified)
            writeFrozen(path, bytes)
            val index = parseControlObject(forged.resolve("index.json"))
            val unsigned = JsonObject(index.toMutableMap().apply {
                remove("indexSha256")
                this["shards"] = JsonArray(index.controlArray("shards").controlObjects("shards").map { record ->
                    if (record.controlString("id") != owner) record else JsonObject(record.toMutableMap().apply {
                        this["bytes"] = JsonPrimitive(bytes.size)
                        this["sha256"] = JsonPrimitive(OracleArtifacts.sha256(bytes))
                    })
                })
            })
            val rebound = JsonObject(unsigned + ("indexSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned)))))
            OracleSchemas.validate("full-tree-call-truth-index", rebound)
            writeFrozen(forged.resolve("index.json"), OracleJson.canonicalBytes(rebound))
            val before = treeBytes(forged)
            val output = root.resolve("forged-output")
            assertFailsWith<FullTreeCallBaselineException> { generate(fixture, forged, output) }
            assertEquals(before, treeBytes(forged))
            assertFalse(Files.exists(output))
            val rawBytes = Files.readAllBytes(fixture.raw.artifact)
            val rawMode = Files.getPosixFilePermissions(fixture.raw.artifact)
            try {
                Files.setPosixFilePermissions(fixture.raw.artifact, PosixFilePermissions.fromString("rw-------"))
                Files.write(fixture.raw.artifact, rawBytes.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() })
                Files.setPosixFilePermissions(fixture.raw.artifact, rawMode)
                val mutated = Files.readAllBytes(fixture.raw.artifact)
                assertFailsWith<FullTreeCallBaselineException> { generate(fixture, truth.root, output) }
                assertContentEquals(mutated, Files.readAllBytes(fixture.raw.artifact))
            } finally {
                Files.setPosixFilePermissions(fixture.raw.artifact, PosixFilePermissions.fromString("rw-------"))
                Files.write(fixture.raw.artifact, rawBytes)
                Files.setPosixFilePermissions(fixture.raw.artifact, rawMode)
            }
            assertFalse(Files.exists(output))
            assertClean(fixture)
        }

    @Test
    fun `missing extra linked and writable baseline candidates fail closed without mutation`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val truth = compose(fixture, root.resolve("truth"))
            val baseline = generate(fixture, truth.root, root.resolve("baseline"))
            val mutations = linkedMapOf<String, (Path) -> Unit>(
                "missing" to { candidate -> Files.delete(candidate.resolve("report.json")) },
                "extra" to { candidate -> Files.write(candidate.resolve("extra"), byteArrayOf(1)) },
                "symlink" to { candidate ->
                    Files.delete(candidate.resolve("report.json"))
                    Files.createSymbolicLink(candidate.resolve("report.json"), baseline.root.resolve("report.json"))
                },
                "hardlink" to { candidate ->
                    Files.delete(candidate.resolve("report.json"))
                    Files.createLink(candidate.resolve("report.json"), baseline.root.resolve("report.json"))
                },
                "writable" to { candidate -> Files.setPosixFilePermissions(candidate.resolve("report.json"), PosixFilePermissions.fromString("rw-------")) },
            )
            for ((name, mutation) in mutations) {
                val candidate = copyTree(baseline.root, root.resolve(name))
                Files.setPosixFilePermissions(candidate, PosixFilePermissions.fromString("rwx------"))
                mutation(candidate)
                Files.setPosixFilePermissions(candidate, PosixFilePermissions.fromString("r-x------"))
                val before = treeBytes(candidate)
                assertFailsWith<FullTreeCallBaselineException>(name) { validate(fixture, truth.root, candidate) }
                assertEquals(before, treeBytes(candidate), name)
                if (name == "hardlink") {
                    Files.setPosixFilePermissions(candidate, PosixFilePermissions.fromString("rwx------"))
                    Files.delete(candidate.resolve("report.json"))
                }
                assertClean(fixture)
            }
            val absent = root.resolve("absent")
            assertFailsWith<FullTreeCallBaselineException> { validate(fixture, truth.root, absent) }
            assertFalse(Files.exists(absent))
            val linkedRoot = root.resolve("linked-root")
            Files.createSymbolicLink(linkedRoot, baseline.root)
            assertFailsWith<FullTreeCallBaselineException> { validate(fixture, truth.root, linkedRoot) }
            assertTrue(Files.isSymbolicLink(linkedRoot))
            assertClean(fixture)
        }

    @Test
    fun `occupied overlapping destinations and mismatched raw bindings are never overwritten`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val truth = compose(fixture, root.resolve("truth"))
            val occupied = Files.write(root.resolve("occupied"), "keep original".toByteArray())
            val linked = Files.createSymbolicLink(root.resolve("linked"), occupied)
            val before = treeBytes(truth.root)
            for (output in listOf(occupied, linked, truth.root, truth.root.resolve("nested"), fixture.functions.scratch.resolve("overlap"))) {
                assertFailsWith<FullTreeCallBaselineException> { generate(fixture, truth.root, output) }
            }
            assertContentEquals("keep original".toByteArray(), Files.readAllBytes(occupied))
            assertTrue(Files.isSymbolicLink(linked))
            assertEquals(before, treeBytes(truth.root))
            for (workers in listOf(0, 33)) {
                assertFailsWith<FullTreeCallBaselineException> { generate(fixture, truth.root, root.resolve("worker-$workers"), workers) }
            }
            val output = root.resolve("wrong-binding")
            assertFailsWith<FullTreeCallBaselineException> { generate(fixture, truth.root, output, callDigest = "f".repeat(64)) }
            assertFalse(Files.exists(output))
            assertClean(fixture)
        }

    @Test
    fun `baseline resource ceilings fail closed with ordinary rollback`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val truth = compose(fixture, root.resolve("truth"))
            val limits = linkedMapOf(
                "output" to FullTreeCallBaselineLimits(maximumBaselineBytes = 1),
                "database" to FullTreeCallBaselineLimits(maximumDatabaseBytes = 4096),
                "entities" to FullTreeCallBaselineLimits(maximumEntities = 3),
                "entity-bytes" to FullTreeCallBaselineLimits(maximumEntityBytes = 256, maximumStringBytes = 128),
                "tokens" to FullTreeCallBaselineLimits(maximumTokensPerInput = 10),
                "nested-scratch" to FullTreeCallBaselineLimits(maximumScratchBytes = 16L * 1024 * 1024 * 1024 - 1),
            )
            limits.forEach { (name, bound) ->
                val output = root.resolve(name)
                assertFailsWith<FullTreeCallBaselineException>(name) { generate(fixture, truth.root, output, limits = bound) }
                assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS), name)
                assertClean(fixture)
            }
            assertFailsWith<IllegalArgumentException> { FullTreeCallBaselineLimits(modeledResidentBytes = 1) }
            assertFailsWith<IllegalArgumentException> { FullTreeCallBaselineLimits(maximumEntities = 0) }
            assertFailsWith<IllegalArgumentException> { FullTreeCallBaselineMetric(-1, 0, 0) }
            assertFailsWith<ArithmeticException> { FullTreeCallBaselineMetric(Long.MAX_VALUE, 1, 0) }
        }

    @Test
    fun `interrupted baseline preserves interrupt and leaves no output or scratch`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val truth = compose(fixture, root.resolve("truth"))
            val output = root.resolve("interrupted")
            try {
                Thread.currentThread().interrupt()
                assertFailsWith<FullTreeCallBaselineException> { generate(fixture, truth.root, output) }
                assertTrue(Thread.currentThread().isInterrupted)
            } finally {
                Thread.interrupted()
            }
            assertFalse(Files.exists(output))
            assertClean(fixture)
        }

    @Test
    fun `live projection closes on consumer failure and cannot be reused after release`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val truth = compose(fixture, root.resolve("truth"))
            var retained: FullTreeCallBaselineRawProjection? = null
            val failure = assertFailsWith<FullTreeCallTruthException> {
                withProjection(fixture, truth.root, root.resolve("not-published")) { raw ->
                    retained = raw
                    raw.recheck("during the failure regression")
                    throw IllegalStateException("consumer failed deliberately")
                }
            }
            assertTrue(generateSequence<Throwable>(failure) { it.cause }.any {
                it is IllegalStateException && it.message == "consumer failed deliberately"
            }, failure.stackTraceToString())
            val released = checkNotNull(retained)
            assertFailsWith<IllegalStateException> { released.recheck("after release") }
            assertFailsWith<IllegalStateException> { released.checkpoint("after release") }
            released.release()
            released.terminalCheckpoint("bounded terminal work after release")
            try {
                Thread.currentThread().interrupt()
                assertFailsWith<IllegalArgumentException> { released.terminalCheckpoint("interrupted terminal work after release") }
                assertTrue(Thread.currentThread().isInterrupted)
            } finally {
                Thread.interrupted()
            }
            assertClean(fixture)
        }

    @Test
    fun `live projection rechecks reject call truth replacement during consumption`(): Unit =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCallTruthTestFixture(root.resolve("inputs"))
            val truth = compose(fixture, root.resolve("truth"))
            val index = truth.root.resolve("index.json")
            val original = Files.readAllBytes(index)
            try {
                assertFailsWith<FullTreeCallTruthException> {
                    withProjection(fixture, truth.root, root.resolve("not-published")) { raw ->
                        writeFrozen(index, original + ' '.code.toByte())
                        raw.recheck("after replacing a candidate during consumption")
                    }
                }
                assertContentEquals(original + ' '.code.toByte(), Files.readAllBytes(index))
            } finally {
                writeFrozen(index, original)
            }
            assertClean(fixture)
        }

    private fun compose(fixture: FullTreeCallTruthTestFixture, output: Path): FullTreeCallTruthPublication =
        FullTreeCallTruthSqlite.generateAndPublish(
            fixture.raw.artifact, fixture.raw.strippedArtifact, fixture.raw.inventoryPath, fixture.functions.elfIndex,
            fixture.functions.observationRoot, fixture.functions.observationIndexArtifactSha256, fixture.functionTruth.root,
            fixture.callRun.root, fixture.callRun.indexArtifactSha256, fixture.raw.scope, fixture.functions.scratch, output, 3,
        )

    private fun generate(
        fixture: FullTreeCallTruthTestFixture, truth: Path, output: Path, workers: Int = 3,
        limits: FullTreeCallBaselineLimits = FullTreeCallBaselineLimits(),
        callDigest: String = fixture.callRun.indexArtifactSha256,
    ): FullTreeCallBaselinePublication = FullTreeCallBaselineSqlite.generateAndPublishFromRawInputs(
        truth, fixture.raw.artifact, fixture.raw.strippedArtifact, fixture.raw.inventoryPath, fixture.functions.elfIndex,
        fixture.functions.observationRoot, fixture.functions.observationIndexArtifactSha256, fixture.functionTruth.root,
        fixture.callRun.root, callDigest, fixture.raw.scope, fixture.functions.scratch, output, workers, limits,
    )

    private fun validate(fixture: FullTreeCallTruthTestFixture, truth: Path, candidate: Path): FullTreeCallBaselinePublication =
        FullTreeCallBaselineSqlite.loadAndValidateFromRawInputs(
            candidate, truth, fixture.raw.artifact, fixture.raw.strippedArtifact, fixture.raw.inventoryPath, fixture.functions.elfIndex,
            fixture.functions.observationRoot, fixture.functions.observationIndexArtifactSha256, fixture.functionTruth.root,
            fixture.callRun.root, fixture.callRun.indexArtifactSha256, fixture.raw.scope, fixture.functions.scratch, 3,
        )

    private fun withProjection(
        fixture: FullTreeCallTruthTestFixture, truth: Path, output: Path, consume: (FullTreeCallBaselineRawProjection) -> Unit,
    ) = FullTreeCallTruthSqlite.withValidatedBaselineProjection(
        truth, fixture.raw.artifact, fixture.raw.strippedArtifact, fixture.raw.inventoryPath, fixture.functions.elfIndex,
        fixture.functions.observationRoot, fixture.functions.observationIndexArtifactSha256, fixture.functionTruth.root,
        fixture.callRun.root, fixture.callRun.indexArtifactSha256, fixture.raw.scope, fixture.functions.scratch,
        output, 3, FullTreeCallTruthLimits(), consume,
    )

    private fun writeFrozen(path: Path, bytes: ByteArray) {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
    }

    private fun copyTree(source: Path, target: Path): Path {
        callTruthPrivateDirectory(target)
        Files.walk(source).use { paths ->
            paths.filter { it != source }.forEach { path ->
                val output = target.resolve(source.relativize(path))
                if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) callTruthPrivateDirectory(output) else {
                    Files.copy(path, output)
                    Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("r--------"))
                }
            }
        }
        Files.walk(target).use { paths ->
            paths.filter { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }.forEach {
                Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("r-x------"))
            }
        }
        return target
    }

    private fun treeBytes(root: Path): Map<String, List<Byte>> = Files.walk(root).use { paths ->
        paths.filter { !Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }.toList().associate { path ->
            root.relativize(path).toString() to if (Files.isSymbolicLink(path)) {
                Files.readSymbolicLink(path).toString().toByteArray().toList()
            } else Files.readAllBytes(path).toList()
        }
    }

    private fun assertClean(fixture: FullTreeCallTruthTestFixture) {
        assertEquals(emptySet(), childNames(fixture.functions.scratch))
        Files.walk(fixture.raw.root.parent).use { paths ->
            assertEquals(emptyList(), paths.filter { path ->
                path.fileName.toString().let { it.startsWith(".call-baseline-") || it.startsWith(".call-truth-") || it.startsWith(".function-truth-") }
            }.toList())
        }
    }

    private fun childNames(root: Path): Set<String> = Files.list(root).use { paths -> paths.map { it.fileName.toString() }.toList().toSet() }
}
