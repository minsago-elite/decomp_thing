package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeSourceEntityIdentityProducerTest {
    @Test
    fun `line table cache bounds cover every authenticated compilation unit`() {
        val perUnit = 16L * 1024L
        val configured = FullTreeDwarfLineTableLimits(
            maximumDirectories = 1_000,
            maximumFiles = 1_000,
            maximumAggregatePathBytes = 1L shl 20,
        )
        val bounded = boundedSourceIdentityLineTableLimits(configured, perUnit)
        val modeledPerUnit = 1_024L + 2L * bounded.maximumAggregatePathBytes +
            128L * (bounded.maximumDirectories + bounded.maximumFiles)
        assertTrue(bounded.maximumDirectories <= configured.maximumDirectories)
        assertTrue(bounded.maximumFiles <= configured.maximumFiles)
        assertTrue(bounded.maximumAggregatePathBytes <= configured.maximumAggregatePathBytes)
        assertTrue(modeledPerUnit <= perUnit)
        assertTrue(Math.multiplyExact(modeledPerUnit, 32L) <= Math.multiplyExact(perUnit, 32L))
        assertFailsWith<FullTreeControlException> {
            boundedSourceIdentityLineTableLimits(configured, 1_024L)
        }
    }

    @Test
    fun `available GCC and Clang DWARF5 fixture rows yield deterministic bounded facts`() {
        val root = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
        val fixture = root.resolve("src/test/resources/oracle/inline-template-identity-v1")
        val evidence = root.resolve("build/source-identity-fixture-evidence")
        Files.createDirectories(evidence)
        val controls = createFullTreeControlFixture(evidence.resolve("control-fixture"))
        val compilerRows = mutableListOf<String>()
        val gcc = resolveCompiler("GXX", listOf("g++", "g++-14", "g++-13"))
        val clang = resolveCompilerOrNull(
            listOfNotNull(System.getenv("DECOMP_TEST_CLANG"), System.getenv("CLANGXX")).takeIf { it.isNotEmpty() }
                ?: listOf("clang++", "clang++-20", "clang++-19", "clang++-18", "clang++-17"),
        )
        if (System.getenv("DECOMP_REQUIRE_CLANG_TESTS") == "1") {
            assertTrue(clang != null, "DECOMP_REQUIRE_CLANG_TESTS=1 requires a Clang executable")
        }
        val compilers = listOfNotNull(gcc, clang)

        compilers.forEach { compiler ->
            val compilerIdentity = runCommand(listOf(compiler.toString(), "--version"), evidence, "compiler-version.txt")
                .lineSequence().firstOrNull().orEmpty().trim()
            assertTrue(compilerIdentity.isNotEmpty(), "compiler identity is empty for $compiler")
            listOf(0, 2).forEach { optimization ->
                val rowName = "${compiler.fileName}-O$optimization"
                val rowRoot = evidence.resolve(rowName)
                deleteTree(rowRoot)
                Files.createDirectories(rowRoot)
                val artifact = compileFixture(compiler, fixture, rowRoot, optimization)
                val dwarfShape = runCommand(
                    listOf("readelf", "--debug-dump=info", "--wide", artifact.toString()),
                    rowRoot,
                    "dwarf-shape.txt",
                )
                assertTrue(dwarfShape.contains("Compilation Unit @"), "no DWARF CU shape was emitted; $compilerIdentity")
                val artifactSha256 = fixtureSha256(artifact)
                val scope = scopeForArtifact(
                    controls.authenticatedScope(),
                    artifactSha256,
                    Files.size(artifact),
                )
                val inventoryPath = rowRoot.resolve("inventory.json")
                val inventory = FullTreeInventoryControl.generateAndPublish(
                    artifact,
                    scope,
                    inventoryPath,
                    maximumWorkers = 1,
                )
                val shard = inventory.inventory.controlArray("shards").single() as JsonObject
                val shardId = shard.controlString("id")
                val first = FullTreeSourceEntityIdentityProducer.scanShard(
                    artifact,
                    inventoryPath,
                    scope,
                    shardId,
                    rowRoot,
                )
                val second = FullTreeSourceEntityIdentityProducer.scanShard(
                    artifact,
                    inventoryPath,
                    scope,
                    shardId,
                    rowRoot,
                )
                val runDescription = "$compilerIdentity -O$optimization artifact=$artifactSha256"
                assertEquals(artifactSha256, first.richArtifactSha256, runDescription)
                assertEquals(first.canonicalSha256, second.canonicalSha256, runDescription)
                assertEquals(first.facts.size, first.facts.map { it.sourceEntityId }.distinct().size, runDescription)
                assertEquals(first.facts.size, first.facts.map { it.physicalDie.locator() }.distinct().size, runDescription)
                assertTrue(first.facts.all { it.sourceEntityId == it.physicalDie.sourceEntityId(it.kind) }, runDescription)
                assertTrue(first.facts.all { it.resolvedSemanticIdentityId == null }, runDescription)
                assertTrue(first.facts.filter { it.kind == FullTreeSourceEntityKind.NO_RANGE_DEFINITION }.all {
                    it.denominatorDisposition == FullTreeDenominatorDisposition.NON_SCOREABLE && it.linkedEmittedRva == null
                }, runDescription)
                assertTrue(first.facts.filter { it.kind == FullTreeSourceEntityKind.UNRESOLVED }.all {
                    it.identityObservability in setOf(FullTreeIdentityObservability.UNKNOWN, FullTreeIdentityObservability.AMBIGUOUS) &&
                        it.semanticAnchorCandidateId == null
                }, runDescription)
                assertContentEquals(
                    canonicalSourceEntityFacts(first.facts),
                    canonicalSourceEntityFacts(second.facts),
                    runDescription,
                )
                assertContentEquals(
                    canonicalSourceEntityFacts(first.facts),
                    canonicalSourceEntityFacts(first.facts.asReversed()),
                    "$runDescription; source-fact input order changed",
                )
                assertFixtureFacts(
                    first.facts,
                    optimization,
                    runDescription,
                    declarationShapePre