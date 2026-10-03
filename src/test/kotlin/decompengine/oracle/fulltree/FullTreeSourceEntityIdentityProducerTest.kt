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
                    declarationShapePresent = Regex("DW_AT_name.*declaration_only_inline").containsMatchIn(dwarfShape),
                    dwarfShape = dwarfShape,
                )

                if (optimization == 2) {
                    val overBound = assertFailsWith<FullTreeControlException>(runDescription) {
                        FullTreeSourceEntityIdentityProducer.scanShard(
                            artifact,
                            inventoryPath,
                            scope,
                            shardId,
                            rowRoot,
                            producerLimits = FullTreeFunctionObservationProducerLimits(
                                maximumReferenceChainEntries = 1,
                            ),
                        )
                    }
                    assertTrue(overBound.message.orEmpty().contains("exceeds"), runDescription)

                    if (compiler.toRealPath() == gcc.toRealPath()) {
                        val dieBoundFailure = assertFailsWith<FullTreeControlException>(runDescription) {
                            FullTreeSourceEntityIdentityProducer.scanShard(
                                artifact,
                                inventoryPath,
                                scope,
                                shardId,
                                rowRoot,
                                producerLimits = FullTreeFunctionObservationProducerLimits(
                                    dieLimits = FullTreeDwarfDieLimits(
                                        maximumPhysicalRecords = 1,
                                        maximumNonNullRecords = 1,
                                        maximumAttributes = 1,
                                        maximumTreeDepth = 1,
                                        maximumRetainedBytes = 1,
                                    ),
                                ),
                            )
                        }
                        assertTrue(dieBoundFailure.message.orEmpty().contains("bound"), runDescription)

                        val mutatingArtifact = rowRoot.resolve("mutating-fixture.so")
                        Files.copy(artifact, mutatingArtifact)
                        var mutatedDuringScan = false
                        assertFailsWith<FullTreeControlException>(runDescription) {
                            FullTreeSourceEntityIdentityProducer.scanShard(
                                mutatingArtifact,
                                inventoryPath,
                                scope,
                                shardId,
                                rowRoot,
                                checkpoint = { stage ->
                                    if (!mutatedDuringScan && stage == "while hashing source-identity rich artifact") {
                                        val contents = Files.readAllBytes(mutatingArtifact)
                                        contents[contents.lastIndex] = (contents.last().toInt() xor 1).toByte()
                                        Files.write(mutatingArtifact, contents)
                                        mutatedDuringScan = true
                                    }
                                },
                            )
                        }
                        assertTrue(mutatedDuringScan, "artifact mutation checkpoint was not reached; $runDescription")
                    }
                }

                compilerRows += "$compilerIdentity\t-O$optimization\t$artifactSha256\t${first.canonicalSha256}\t${first.facts.size}"
                Files.writeString(
                    evidence.resolve("compiler-matrix.tsv"),
                    compilerRows.joinToString("\n", postfix = "\n"),
                    StandardCharsets.UTF_8,
                )
            }
        }
    }

    private fun assertFixtureFacts(
        facts: List<FullTreeSourceEntityFact>,
        optimization: Int,
        runDescription: String,
        declarationShapePresent: Boolean,
        dwarfShape: String,
    ) {
        val declaration = facts.filter { it.semanticAnchorFields?.sourceName == "declaration_only_inline" }
        assertEquals(
            declarationShapePresent,
            declaration.isNotEmpty(),
            "declaration-only observation must follow the compiler-emitted DIE shape; $runDescription",
        )
        if (!declarationShapePresent) {
            assertTrue(declaration.isEmpty(), "compiler-absent declaration-only DIE was fabricated; $runDescription")
        } else {
            val declarationsByCandidate = declaration.groupBy { it.semanticAnchorCandidateId }
            declaration.forEach { fact ->
                val candidateRows = declarationsByCandidate[fact.semanticAnchorCandidateId].orEmpty()
                if (fact.semanticAnchorCandidateId != null && candidateRows.size > 1) {
                    assertEquals(FullTreeIdentityObservability.AMBIGUOUS, fact.identityObservability, runDescription)
                    assertEquals(candidateRows.map { it.sourceEntityId }.sorted(), fact.candidateCollisionSourceEntityIds, runDescription)
                } else {
                    assertEquals(FullTreeIdentityObservability.UNOBSERVABLE, fact.identityObservability, runDescription)
                    assertTrue(fact.candidateCollisionSourceEntityIds.isEmpty(), runDescription)
                }
            }
        }
        assertTrue(declaration.all { it.kind == FullTreeSourceEntityKind.DECLARATION_ONLY }, runDescription)
        assertTrue(declaration.all { it.denominatorDisposition == FullTreeDenominatorDisposition.NON_SCOREABLE }, runDescription)
        assertTrue(declaration.all { it.linkedEmittedRva == null }, runDescription)

        val patterns = facts.filter { it.kind == FullTreeSourceEntityKind.TEMPLATE_PATTERN }
        assertTrue(patterns.all { it.denominatorDisposition == FullTreeDenominatorDisposition.NON_SCOREABLE }, runDescription)
        assertTrue(patterns.all { it.linkedEmittedRva == null }, runDescription)
        assertTrue(patterns.all { it.semanticAnchorFields?.templateFormalParameters?.isNotEmpty() == true }, runDescription)

        val uninstantiatedPattern = facts.filter { it.semanticAnchorFields?.sourceName == "pattern_only" }
        val uninstantiatedPatternShapePresent = Regex("DW_AT_name\\s*:.*pattern_only").containsMatchIn(dwarfShape)
        assertEquals(uninstantiatedPatternShapePresent, uninstantiatedPattern.isNotEmpty(), runDescription)
        assertTrue(uninstantiatedPattern.all {
            it.kind in setOf(FullTreeSourceEntityKind.TEMPLATE_PATTERN, FullTreeSourceEntityKind.UNRESOLVED) &&
                it.denominatorDisposition == FullTreeDenominatorDisposition.NON_SCOREABLE
        }, runDescription)

        val templateInstances = facts.filter { it.kind == FullTreeSourceEntityKind.TEMPLATE_INSTANCE }
        assertTrue(templateInstances.isNotEmpty(), "template instance DIEs were not retained; $runDescription")
        val intAndLongShapesPresent = dwarfShape.contains("template_pattern<int>") && dwarfShape.contains("template_pattern<long")
        val intTemplateInstances = templateInstances.filter {
            it.semanticAnchorFields?.sourceName?.startsWith("template_pattern<int>") == true
        }
        val longTemplateInstances = templateInstances.filter {
            it.semanticAnchorFields?.sourceName?.startsWith("template_pattern<long") == true
        }
        assertTrue(intTemplateInstances.isNotEmpty(), "int template instance DIE was not classified; $runDescription")
        assertTrue(
            intTemplateInstances.any { it.denominatorDisposition == FullTreeDenominatorDisposition.EMITTED_RVA_LINK },
            "emitted int template instance did not link to its exact RVA; $runDescription",
        )
        assertEquals(dwarfShape.contains("template_pattern<long"), longTemplateInstances.isNotEmpty(), runDescription)
        if (intAndLongShapesPresent) {
            val intArguments = intTemplateInstances.mapNotNull { it.semanticAnchorFields?.templateActualArguments }.distinct()
            val longArguments = longTemplateInstances.mapNotNull { it.semanticAnchorFields?.templateActualArguments }.distinct()
            assertTrue(intArguments.isNotEmpty() && longArguments.isNotEmpty() && intArguments != longArguments, runDescription)
            assertTrue(
                longTemplateInstances.any { it.denominatorDisposition == FullTreeDenominatorDisposition.NON_SCOREABLE },
                "compiler-emitted no-range long template instance was not kept non-scoreable; $runDescription",
            )
        }
        templateInstances.filter { it.semanticAnchorFields?.templatePatternAnchorCandidateId == null }.forEach { fact ->
            assertTrue(fact.identityObservability == FullTreeIdentityObservability.UNKNOWN, runDescription)
            assertTrue("unknown-template-pattern-reference" in fact.reasonCodes, runDescription)
        }
        assertTrue(
            templateInstances.any { it.denominatorDisposition == FullTreeDenominatorDisposition.EMITTED_RVA_LINK },
            "emitted template instance did not link to its exact RVA; $runDescription",
        )
        if (dwarfShape.contains("template_pattern<long")) {
            assertTrue(
                longTemplateInstances.any { it.denominatorDisposition == FullTreeDenominatorDisposition.NON_SCOREABLE },
                "compiler-emitted no-range template instance was not kept non-scoreable; $runDescription",
            )
        } else {
            assertTrue(
                longTemplateInstances.isEmpty(),
                "compiler-absent no-range template instance was fabricated; $runDescription",
            )
        }
        val valueTemplateArguments = templateInstances.filter { fact ->
            fact.semanticAnchorFields?.templateActualArguments?.any { it.startsWith("value-argument:") } == true
        }.mapNotNull { it.semanticAnchorFields?.templateActualArguments }
        if (optimization == 2) {
            assertTrue(valueTemplateArguments.size >= 2, "non-type template actual arguments were not retained; $runDescription")
            assertTrue(valueTemplateArguments.distinct().size >= 2, "different non-type template values collided; $runDescription")
        }

        assertTrue(facts.filter { it.kind == FullTreeSourceEntityKind.INLINE_INSTANCE }.all {
            it.denominatorDisposition == FullTreeDenominatorDisposition.NON_SCOREABLE && it.linkedEmittedRva == null
        }, runDescription)

        val sharedInline = facts.filter {
            it.kind == FullTreeSourceEntityKind.INLINE_INSTANCE && it.semanticAnchorFields?.sourceName == "shared_inline"
        }
        if (optimization == 2) {
            val overloadFacts = facts.filter { it.semanticAnchorFields?.sourceName == "overloaded" }
            val overloadedShapePresent = Regex("DW_AT_name.*overloaded").containsMatchIn(dwarfShape)
            assertEquals(overloadedShapePresent, overloadFacts.isNotEmpty(), runDescription)
            if (overloadedShapePresent) {
                assertTrue(overloadFacts.mapNotNull { it.semanticAnchorFields?.signature }.distinct().size >= 2, runDescription)
            }
            val overloadInlineFacts = overloadFacts.filter { it.kind == FullTreeSourceEntityKind.INLINE_INSTANCE }
            if (overloadedShapePresent) {
                assertTrue(overloadInlineFacts.isNotEmpty(), "no overloaded inline observation was retained; $runDescription")
                assertTrue(overloadInlineFacts.all { it.semanticAnchorFields?.signature != null }, runDescription)
            } else {
                assertTrue(overloadInlineFacts.isEmpty(), "compiler-absent overload DIE was fabricated; $runDescription")
            }

            val sharedShapePresent = Regex("DW_AT_name.*shared_inline").containsMatchIn(dwarfShape)
            assertEquals(sharedShapePresent, sharedInline.isNotEmpty(), runDescription)
            if (sharedShapePresent) {
                assertEquals(2, sharedInline.size, "expected two concrete shared_inline call sites; $runDescription")
                assertEquals(2, sharedInline.mapNotNull { it.semanticAnchorCandidateId }.distinct().size, runDescription)
                assertEquals(1, sharedInline.mapNotNull { it.semanticAnchorFields?.inlineCalleeAnchorCandidateId }.distinct().size, runDescription)
                assertEquals(1, sharedInline.mapNotNull { it.semanticAnchorFields?.inlineOwnerAnchorCandidateId }.distinct().size, runDescription)
                assertEquals(2, sharedInline.mapNotNull { it.semanticAnchorFields?.inlineCallColumn }.distinct().size, runDescription)
                assertTrue(sharedInline.all { fact ->
                    fact.edges.any { it.kind == FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN &&
                        it.state == FullTreeSourceIdentityEdgeState.RESOLVED && it.target != null
                    }
                }, runDescription)
            } else {
                assertTrue(sharedInline.isEmpty(), "compiler-absent shared inline DIE was fabricated; $runDescription")
            }

            val uniquePattern = facts.filter {
                it.kind == FullTreeSourceEntityKind.INLINE_INSTANCE &&
                    it.semanticAnchorFields?.sourceName == "unique_source_pattern"
            }
            assertTrue(dwarfShape.contains("unique_source_pattern"), "positive source-pattern shape is absent; $runDescription")
            assertTrue(dwarfShape.contains("DW_TAG_inlined_subroutine"), "positive inline-instance shape is absent; $runDescription")
            assertEquals(1, uniquePattern.size, "expected one physical positive pattern/instance relationship; $runDescription")
            assertEquals(FullTreeIdentityObservability.OBSERVABLE, uniquePattern.single().identityObservability, runDescription)
            assertTrue(uniquePattern.single().candidateCollisionSourceEntityIds.isEmpty(), runDescription)
            assertTrue(uniquePattern.single().semanticAnchorFields?.inlineCalleeAnchorCandidateId != null, runDescription)
            assertTrue(uniquePattern.single().edges.any {
                it.kind == FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN &&
                    it.state == FullTreeSourceIdentityEdgeState.RESOLVED && it.target != null
            }, runDescription)
        }
    }

    private fun compileFixture(compiler: Path, fixture: Path, output: Path, optimization: Int): Path {
        val objects = listOf("caller_one", "caller_two", "instantiate", "unique_pattern").map { name ->
            val target = output.resolve("$name.o")
            runCommand(
                listOf(
                    compiler.toString(),
                    "-std=c++17",
                    "-O$optimization",
                    "-g",
                    "-gdwarf-5",
                    "-fPIC",
                    "-fdebug-prefix-map=$fixture=/fixture/source-tree/clang/lib/InlineTemplate",
                    "-I${fixture.resolve("include")}",
                    fixture.resolve("$name.cpp").toString(),
                    "-c",
                    "-o",
                    target.toString(),
                ),
                output,
                "$name-compile.txt",
            )
            target
        }
        val artifact = output.resolve("fixture.so")
        runCommand(
            listOf(compiler.toString(), "-shared", "-Wl,--build-id=none") + objects.map(Path::toString) + listOf("-o", artifact.toString()),
            output,
            "link.txt",
        )
        return artifact
    }

    private fun resolveCompiler(environmentName: String, candidates: List<String>): Path =
        resolveCompilerOrNull(System.getenv(environmentName)?.takeIf(String::isNotBlank)?.let(::listOf) ?: candidates)
            ?: throw AssertionError("required fixture compiler $environmentName is unavailable; tried ${candidates.joinToString()}")

    private fun resolveCompilerOrNull(names: List<String>): Path? {
        val searchPath = System.getenv("PATH").orEmpty().split(File.pathSeparator).filter(String::isNotBlank)
        names.forEach { name ->
            val direct = Path.of(name)
            val choices = if (direct.isAbsolute || name.contains('/')) listOf(direct) else searchPath.map { Path.of(it).resolve(name) }
            choices.firstOrNull { Files.isRegularFile(it) && Files.isExecutable(it) }?.let { return it.toAbsolutePath().normalize() }
        }
        return null
    }

    private fun runCommand(command: List<String>, directory: Path, outputName: String): String {
        val output = directory.resolve(outputName)
        val process = ProcessBuilder(command)
            .directory(directory.toFile())
            .redirectErrorStream(true)
            .redirectOutput(output.toFile())
            .start()
        if (!process.waitFor(2, TimeUnit.MINUTES)) {
            process.destroyForcibly()
            throw AssertionError("fixture command timed out: ${command.joinToString(" ")}")
        }
        val bytes = Files.readAllBytes(output)
        if (bytes.size > 256 * 1024) throw AssertionError("fixture command output exceeds its diagnostic bound")
        val text = bytes.toString(StandardCharsets.UTF_8)
        if (process.exitValue() != 0) {
            throw AssertionError("fixture command failed (${process.exitValue()}): ${command.joinToString(" ")}\n$text")
        }
        return text
    }

    private fun scopeForArtifact(
        original: AuthenticatedFullTreeScope,
        artifactSha256: String,
        artifactBytes: Long,
    ): AuthenticatedFullTreeScope {
        val originalArtifacts = original.artifactManifest.controlObject("artifacts")
        val full = JsonObject(originalArtifacts.controlObject("full").toMutableMap().apply {
            this["bytes"] = JsonPrimitive(artifactBytes)
            this["sha256"] = JsonPrimitive(artifactSha256)
        })
        val manifest = JsonObject(original.artifactManifest.toMutableMap().apply {
            this["artifacts"] = JsonObject(originalArtifacts.toMutableMap().apply { this["full"] = full })
        })
        val manifestSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(manifest))
        val oracle = original.document.controlObject("oracle")
        val document = JsonObject(original.document.toMutableMap().apply {
            this["oracle"] = JsonObject(oracle.toMutableMap().apply {
                this["artifactManifestSha256"] = JsonPrimitive(manifestSha256)
                this["richArtifactSha256"] = JsonPrimitive(artifactSha256)
            })
        })
        return AuthenticatedFullTreeScope(
            document = document,
            sha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(document)),
            sourceLock = original.sourceLock,
            sourceLockSha256 = original.sourceLockSha256,
            artifactManifest = manifest,
            artifactManifestSha256 = manifestSha256,
        )
    }

    private fun deleteTree(path: Path) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return
        Files.walk(path).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }
}
