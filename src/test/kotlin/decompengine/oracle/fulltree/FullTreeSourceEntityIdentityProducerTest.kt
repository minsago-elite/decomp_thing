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
import kotlinx.serialization.json.JsonArray
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
        val packedTemplateSemanticsByCompilerOptimization = mutableMapOf<String, List<Pair<String, List<String>>>>()

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
                val fullRunClaims = mutableListOf<Pair<String, String>>()
                val first = FullTreeSourceEntityIdentityProducer.scanShard(
                    artifact,
                    inventoryPath,
                    scope,
                    shardId,
                    rowRoot,
                    anchorClaim = { candidate, physicalClaim -> fullRunClaims += candidate to physicalClaim },
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
                val censusClaims = first.facts.mapNotNull { fact ->
                    fact.semanticAnchorCandidateId?.let { it to fact.sourceEntityId }
                }.toSet()
                assertTrue(censusClaims.isNotEmpty(), "$runDescription produced no source anchor claims")
                assertTrue(censusClaims.all { it in fullRunClaims }, "$runDescription omitted a census anchor claim")
                assertTrue(
                    fullRunClaims.toSet().any { it !in censusClaims },
                    "$runDescription omitted bounded claims from ordinary emitted source definitions",
                )
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
                val compilerFamily = if (compiler.toRealPath() == gcc.toRealPath()) "gcc" else "clang"
                val packedTemplateRows = first.facts.asSequence()
                    .filter { it.kind == FullTreeSourceEntityKind.TEMPLATE_INSTANCE }
                    .filter { it.semanticAnchorFields?.sourceName?.startsWith("packed_template<") == true }
                    .mapNotNull { fact ->
                        val candidate = fact.semanticAnchorCandidateId ?: return@mapNotNull null
                        val arguments = fact.semanticAnchorFields?.templateActualArguments ?: return@mapNotNull null
                        candidate to arguments
                    }
                    .distinct()
                    .sortedWith(compareBy<Pair<String, List<String>>>({ it.first }, { it.second.joinToString("\u0000") }))
                    .toList()
                if (dwarfShape.contains("packed_template<int, int>")) {
                    assertTrue(packedTemplateRows.isNotEmpty(), "packed template has no complete semantic candidate; $runDescription")
                    packedTemplateSemanticsByCompilerOptimization["$compilerFamily-O$optimization"] = packedTemplateRows
                }
                if (optimization == 2) {
                    val nestedLeaves = first.facts.filter {
                        it.kind == FullTreeSourceEntityKind.INLINE_INSTANCE &&
                            it.semanticAnchorFields?.sourceName == "nested_leaf"
                    }
                    assertTrue(nestedLeaves.isNotEmpty(), "nested inline fixture did not emit its leaf instances; $runDescription")
                    assertTrue(nestedLeaves.all { fact ->
                        fact.semanticAnchorFields?.inlinePathAnchorCandidateIds?.size == 2 &&
                            fact.edges.count {
                                it.kind == FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN &&
                                    it.state == FullTreeSourceIdentityEdgeState.RESOLVED
                            } >= 3
                    }, "nested inline ancestry or ancestor reference evidence was lost; $runDescription")
                }

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
                        verifyPinnedLineTableAccounting(artifact, rowRoot)

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
                        verifyIdentityEdgeLimitAbort(compiler, fixture, rowRoot, scope)
                        verifyRowScratchLimitAbort(compiler, rowRoot, controls.authenticatedScope())
                        verifyRelativeSourcePathNormalization(controls.authenticatedScope())
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
        if (clang != null) {
            listOf(0, 2).forEach { optimization ->
                val gccRows = packedTemplateSemanticsByCompilerOptimization["gcc-O$optimization"]
                val clangRows = packedTemplateSemanticsByCompilerOptimization["clang-O$optimization"]
                assertTrue(gccRows != null, "GCC packed-template facts missing at -O$optimization")
                assertTrue(clangRows != null, "Clang packed-template facts missing at -O$optimization")
                assertEquals(
                    gccRows,
                    clangRows,
                    "packed-template semantic candidates and ordered actuals differ across GCC/Clang at -O$optimization",
                )
            }
        }
    }

    private fun verifyPinnedLineTableAccounting(artifact: Path, scratch: Path) {
        val lineLimits = FullTreeDwarfLineTableLimits(
            maximumDirectories = 512,
            maximumFiles = 512,
            maximumAggregatePathBytes = 4L * 1024L * 1024L,
        )
        val modeledPerUnit = 1_024L + 2L * lineLimits.maximumAggregatePathBytes +
            128L * (lineLimits.maximumDirectories.toLong() + lineLimits.maximumFiles.toLong())
        val controlLimits = FullTreeControlLimits()
        val producerLimits = FullTreeFunctionObservationProducerLimits(
            lineTableLimits = lineLimits,
            maximumCachedCompilationUnits = 1,
        )
        StableControlFile.open(artifact, Files.size(artifact), "source identity line-table bound fixture").use { stableArtifact ->
            FullTreeDwarfSections.open(
                stableArtifact,
                scratch,
                controlLimits,
                FullTreeDwarfSections.FUNCTION_OBSERVATION_SECTION_NAMES,
            ).use { sections ->
                val parseBudget = FullTreeDwarfParseBudget(controlLimits.maximumDwarfParseSteps)
                val info = sections.required(".debug_info")
                val headerIterator = FullTreeDwarfCompilationUnitHeaders(
                    info,
                    controlLimits.maximumCompilationUnits.toLong(),
                    parseBudget,
                )
                val headers = buildList {
                    while (headerIterator.hasNext()) add(headerIterator.next())
                }
                assertTrue(headers.size > producerLimits.maximumCachedCompilationUnits + 1)
                val repository = FunctionDwarfUnitRepository(
                    sections = sections,
                    headers = headers,
                    controlLimits = controlLimits,
                    producerLimits = producerLimits,
                    parseBudget = parseBudget,
                    maximumRetainedWorkingSetBytes = 256L * 1024L * 1024L,
                    maximumRetainedLineTableWorkingSetBytes = modeledPerUnit * 2L,
                )
                val root = repository.load(headers.first())
                repository.withRetainedUnits(root) {
                    checkNotNull(root.lineTable(lineLimits)) { "root CU fixture has no retained line table" }
                    val second = repository.load(headers[1])
                    checkNotNull(second.lineTable(lineLimits)) { "second CU fixture has no retained line table" }
                    assertEquals(2, repository.peakRetainedLineTableUnits)
                    assertFailsWith<FullTreeControlException> {
                        repository.load(headers[2]).lineTable(lineLimits)
                    }
                }
            }
        }
    }

    private fun verifyIdentityEdgeLimitAbort(
        compiler: Path,
        fixture: Path,
        rowRoot: Path,
        originalScope: AuthenticatedFullTreeScope,
    ) {
        val formalParameters = (0..32).joinToString(", ") { "int p$it" }
        val source = rowRoot.resolve("edge-bound.cpp")
        Files.writeString(
            source,
            "inline int edge_bound($formalParameters);\n" +
                "int (*edge_bound_reference)($formalParameters) = &edge_bound;\n",
            StandardCharsets.UTF_8,
        )
        val edgeObject = rowRoot.resolve("edge-bound.o")
        runCommand(
            listOf(
                compiler.toString(), "-std=c++17", "-O2", "-g", "-gdwarf-5", "-fPIC",
                "-fdebug-prefix-map=$fixture=/fixture/source-tree/clang/lib/InlineTemplate",
                "-fdebug-prefix-map=$rowRoot=/fixture/source-tree/clang/lib/InlineTemplate",
                source.toString(), "-c", "-o", edgeObject.toString(),
            ),
            rowRoot,
            "edge-bound-compile.txt",
        )
        val objects = listOf("caller_one.o", "caller_two.o", "instantiate.o", "unique_pattern.o")
            .map { rowRoot.resolve(it).toString() } + edgeObject.fileName.toString()
        val artifact = rowRoot.resolve("edge-bound-fixture.so")
        runCommand(
            listOf(compiler.toString(), "-shared", "-Wl,--build-id=none") +
                objects +
                listOf("-o", artifact.toString()),
            rowRoot,
            "edge-bound-link.txt",
        )
        val dwarfShape = runCommand(
            listOf("readelf", "--debug-dump=info", "--wide", artifact.toString()),
            rowRoot,
            "edge-bound-dwarf-shape.txt",
        )
        assertTrue(Regex("DW_AT_name.*edge_bound").containsMatchIn(dwarfShape), "33-parameter declaration DIE was not emitted")
        assertTrue(dwarfShape.contains("DW_AT_declaration"), "declaration-only edge-bound shape was not emitted")
        val scope = scopeForArtifact(originalScope, fixtureSha256(artifact), Files.size(artifact))
        val inventoryPath = rowRoot.resolve("edge-bound-inventory.json")
        val inventory = FullTreeInventoryControl.generateAndPublish(artifact, scope, inventoryPath, maximumWorkers = 1)
        val shard = inventory.inventory.controlArray("shards").single() as JsonObject
        val failure = assertFailsWith<FullTreeControlException> {
            FullTreeSourceEntityIdentityProducer.scanShard(
                artifact,
                inventoryPath,
                scope,
                shard.controlString("id"),
                rowRoot,
            )
        }
        assertTrue(failure.message.orEmpty().contains("more than 32 edges"), failure.message.orEmpty())
    }

    private fun verifyRowScratchLimitAbort(
        compiler: Path,
        scratch: Path,
        originalScope: AuthenticatedFullTreeScope,
    ) {
        val rowRoot = scratch.resolve("row-scratch-bound")
        Files.createDirectories(rowRoot)
        val namespaces = (0 until 255).map { index -> "n${index.toString().padStart(3, '0')}" + "x".repeat(16_380) }
        val source = rowRoot.resolve("row-scratch-bound.cpp")
        Files.newBufferedWriter(source, StandardCharsets.UTF_8).use { writer ->
            namespaces.forEach { writer.append("namespace ").append(it).append(" {\n") }
            writer.append("struct Big {};\n")
            repeat(namespaces.size) { writer.append("}\n") }
            writer.append("using namespace ").append(namespaces.joinToString("::")).append(";\n")
            val parameters = (0..31).joinToString(", ") { "Big p$it" }
            writer.append("extern \"C\" void descriptor_bound($parameters) {}\n")
            writer.append("extern \"C\" void (*descriptor_bound_reference)($parameters) = &descriptor_bound;\n")
            writer.append("int main() { return descriptor_bound_reference == nullptr; }\n")
        }
        val artifact = rowRoot.resolve("row-scratch-bound.so")
        runCommand(
            listOf(
                compiler.toString(), "-std=c++17", "-O0", "-g", "-gdwarf-5", "-fPIC",
                "-fdebug-prefix-map=$rowRoot=/fixture/source-tree/clang/lib/InlineTemplate",
                source.toString(), "-shared", "-Wl,--build-id=none", "-o", artifact.toString(),
            ),
            rowRoot,
            "row-scratch-bound-compile.txt",
        )
        val scope = scopeForArtifact(originalScope, fixtureSha256(artifact), Files.size(artifact))
        val inventoryPath = rowRoot.resolve("row-scratch-bound-inventory.json")
        val inventory = FullTreeInventoryControl.generateAndPublish(artifact, scope, inventoryPath, maximumWorkers = 1)
        val shard = inventory.inventory.controlArray("shards").single() as JsonObject
        val failure = assertFailsWith<FullTreeControlException> {
            FullTreeSourceEntityIdentityProducer.scanShard(
                artifact,
                inventoryPath,
                scope,
                shard.controlString("id"),
                rowRoot,
            )
        }
        assertTrue(failure.message.orEmpty().contains("row scratch exceeds"), failure.message.orEmpty())
    }

    private fun verifyRelativeSourcePathNormalization(
        originalScope: AuthenticatedFullTreeScope,
    ) {
        val pathPolicy = originalScope.document.controlObject("pathPolicy")
        val prefixMaps = pathPolicy.controlArray("prefixMaps").map { value ->
            val prefix = value as JsonObject
            if (prefix.controlString("from") == "/fixture/source-tree/") {
                JsonObject(prefix.toMutableMap().apply {
                    this["from"] = JsonPrimitive("relative-src/")
                    this["to"] = JsonPrimitive("source/clang/lib/InlineTemplate/")
                })
            } else {
                prefix
            }
        }
        // The frozen scope-v1 JSON schema requires absolute prefix-map sources. Exercise the
        // shared normalizer directly for a future versioned policy that admits relative sources;
        // do not broaden or requalify the frozen scope schema in this extraction unit.
        val document = JsonObject(originalScope.document.toMutableMap().apply {
            this["pathPolicy"] = JsonObject(pathPolicy.toMutableMap().apply {
                this["prefixMaps"] = JsonArray(prefixMaps)
            })
        })
        val relativeScope = authenticatedScopeWithDocument(originalScope, document)
        val schemaFailure = assertFailsWith<FullTreeControlException> {
            FullTreeScopeControl.validate(relativeScope)
        }
        assertTrue(schemaFailure.message.orEmpty().contains("bundled schema"), schemaFailure.message.orEmpty())
        assertEquals(
            "source/clang/lib/InlineTemplate/outside.cpp",
            FullTreeScopeControl.normalizeSourcePath(document, "relative-src/outside.cpp"),
        )
        assertFailsWith<FullTreeControlException> {
            FullTreeScopeControl.normalizeSourcePath(document, "relative-src/../outside.cpp")
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
        val enumTemplateShapePresent = Regex("DW_AT_name.*enum_template").containsMatchIn(dwarfShape)
        val enumTemplateInstances = templateInstances.filter {
            it.semanticAnchorFields?.sourceName?.startsWith("enum_template<") == true
        }
        assertEquals(enumTemplateShapePresent, enumTemplateInstances.isNotEmpty(), runDescription)
        if (enumTemplateShapePresent) {
            val enumArguments = enumTemplateInstances.mapNotNull {
                it.semanticAnchorFields?.templateActualArguments?.singleOrNull()
            }.distinct()
            assertTrue(enumArguments.size >= 2, "enum actuals were not retained as typed arguments; $runDescription")
            assertTrue(enumArguments.all { it.startsWith("value-argument:type=enum:") }, runDescription)
            assertEquals(
                setOf("3", "7"),
                enumArguments.mapNotNull { it.substringAfterLast(":value=", "").takeIf(String::isNotEmpty) }.toSet(),
                "enum actual values were not decoded using the validated underlying type; $runDescription",
            )
            assertTrue(
                enumTemplateInstances.mapNotNull { it.semanticAnchorCandidateId }.distinct().size >= 2,
                "distinct enum specializations shared a semantic candidate; $runDescription",
            )
            assertTrue(enumTemplateInstances.none { "unsupported-template-argument-type" in it.reasonCodes }, runDescription)
        }
        val packedTemplateShapePresent = dwarfShape.contains("packed_template<int, int>")
        val packedTemplateInstances = templateInstances.filter {
            it.semanticAnchorFields?.sourceName?.startsWith("packed_template<") == true
        }
        assertEquals(packedTemplateShapePresent, packedTemplateInstances.isNotEmpty(), runDescription)
        if (packedTemplateShapePresent) {
            assertTrue(packedTemplateInstances.any {
                it.semanticAnchorFields?.templateActualArguments?.let { arguments ->
                    arguments.size == 2 && arguments.none { argument -> argument.startsWith("pack[") }
                } == true
            }, "variadic template actuals were not flattened from emitted pack DIEs; $runDescription")
            if (dwarfShape.contains("DW_TAG_GNU_template_parameter_pack")) {
                assertTrue(packedTemplateInstances.any { fact ->
                    fact.edges.any { edge ->
                        edge.kind == FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT &&
                            edge.rawReference == null &&
                            edge.state == FullTreeSourceIdentityEdgeState.RESOLVED &&
                            edge.target != null
                    }
                }, "GNU template parameter pack structure was not retained as typed edge evidence; $runDescription")
            }
            if (dwarfShape.contains("DW_TAG_GNU_formal_parameter_pack")) {
                assertTrue(packedTemplateInstances.any { fact ->
                    fact.semanticAnchorFields?.signature.orEmpty().any { it.startsWith("parameter:") }
                }, "expanded GNU formal parameter pack types were not retained; $runDescription")
                assertTrue(packedTemplateInstances.all { fact ->
                    fact.semanticAnchorFields?.signature.orEmpty().none { it.startsWith("pack[") }
                }, "producer-specific formal parameter pack wrappers leaked into signatures; $runDescription")
            }
        }
        val intAndLongShapesPresent = hasDwarfName(dwarfShape, "template_pattern<int") &&
            hasDwarfName(dwarfShape, "template_pattern<long")
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
        val longTemplateShapePresent = hasDwarfName(dwarfShape, "template_pattern<long")
        assertEquals(
            longTemplateShapePresent,
            longTemplateInstances.isNotEmpty(),
            "$runDescription; long template rows=${longTemplateInstances.map {
                Triple(it.semanticAnchorFields?.sourceName, it.physicalDie.locator(), it.edges.map { edge -> edge.kind to edge.target?.locator() })
            }}",
        )
        if (intAndLongShapesPresent) {
            val intArguments = intTemplateInstances.mapNotNull { it.semanticAnchorFields?.templateActualArguments }.distinct()
            val longArguments = longTemplateInstances.mapNotNull { it.semanticAnchorFields?.templateActualArguments }.distinct()
            assertTrue(intArguments.isNotEmpty() && longArguments.isNotEmpty() && intArguments != longArguments, runDescription)
            val intCandidates = intTemplateInstances.mapNotNull { it.semanticAnchorCandidateId }.distinct()
            val longCandidates = longTemplateInstances.mapNotNull { it.semanticAnchorCandidateId }.distinct()
            assertTrue(intCandidates.isNotEmpty(), "complete int instance tuple has no candidate; $runDescription")
            assertTrue(longCandidates.isNotEmpty(), "complete long instance tuple has no candidate; $runDescription")
            assertTrue(intCandidates.intersect(longCandidates.toSet()).isEmpty(), "int/long instance candidates collided; $runDescription")
            val unlinkedIntInstances = intTemplateInstances.filter {
                it.semanticAnchorFields?.templatePatternAnchorCandidateId == null
            }
            val unlinkedLongInstances = longTemplateInstances.filter {
                it.semanticAnchorFields?.templatePatternAnchorCandidateId == null
            }
            assertTrue(unlinkedIntInstances.isNotEmpty(), "compiler emitted no explicitly unlinked int instance; $runDescription")
            assertTrue(unlinkedLongInstances.isNotEmpty(), "compiler emitted no explicitly unlinked long instance; $runDescription")
            val missingPatternRelation = unlinkedIntInstances + unlinkedLongInstances
            assertTrue(missingPatternRelation.all {
                it.identityObservability in setOf(FullTreeIdentityObservability.UNKNOWN, FullTreeIdentityObservability.AMBIGUOUS) &&
                    it.resolvedSemanticIdentityId == null &&
                    "unknown-template-pattern-reference" in it.reasonCodes
            }, "missing generic-pattern relation must remain explicitly unknown/ambiguous; $runDescription")
            assertTrue(missingPatternRelation.filter { it.semanticAnchorCandidateId != null }.all {
                it.resolvedSemanticIdentityId == null
            }, "a candidate hash must not assert a resolved identity; $runDescription")
            assertTrue(
                longTemplateInstances.any { it.denominatorDisposition == FullTreeDenominatorDisposition.NON_SCOREABLE },
                "compiler-emitted no-range long template instance was not kept non-scoreable; $runDescription",
            )
        }
        templateInstances.filter { it.semanticAnchorFields?.templatePatternAnchorCandidateId == null }.forEach { fact ->
            assertTrue(
                fact.identityObservability in setOf(FullTreeIdentityObservability.UNKNOWN, FullTreeIdentityObservability.AMBIGUOUS),
                runDescription,
            )
            assertTrue("unknown-template-pattern-reference" in fact.reasonCodes, runDescription)
        }
        assertTrue(
            templateInstances.any { it.denominatorDisposition == FullTreeDenominatorDisposition.EMITTED_RVA_LINK },
            "emitted template instance did not link to its exact RVA; $runDescription",
        )
        if (longTemplateShapePresent) {
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
            assertTrue(
                valueTemplateArguments.flatten().any { it.endsWith(":value=-1") },
                "signed non-type template value was not sign-extended to its declared type width; $runDescription",
            )
            val booleanTemplateInstances = templateInstances.filter {
                it.semanticAnchorFields?.sourceName?.startsWith("boolean_template<") == true
            }
            assertTrue(booleanTemplateInstances.isNotEmpty(), "bool template instantiations were not retained; $runDescription")
            val booleanArguments = booleanTemplateInstances.mapNotNull {
                it.semanticAnchorFields?.templateActualArguments
            }.flatten().filter { it.startsWith("value-argument:") }
            assertTrue(booleanArguments.any { it.endsWith(":value=0") }, "false template argument was not decoded; $runDescription")
            assertTrue(booleanArguments.any { it.endsWith(":value=1") }, "true template argument was not decoded; $runDescription")
            assertTrue(
                booleanTemplateInstances.mapNotNull { it.semanticAnchorCandidateId }.distinct().size >= 2,
                "boolean false/true template instance candidates collided; $runDescription",
            )
        }

        assertTrue(facts.filter { it.kind == FullTreeSourceEntityKind.INLINE_INSTANCE }.all {
            it.denominatorDisposition == FullTreeDenominatorDisposition.NON_SCOREABLE && it.linkedEmittedRva == null
        }, runDescription)

        val callbackFacts = facts.filter {
            it.semanticAnchorFields?.sourceName?.startsWith("callback_signature<") == true
        }
        assertTrue(callbackFacts.isNotEmpty(), "callback function DIE was not retained; $runDescription")
        assertTrue(callbackFacts.all { fact ->
            val signature = fact.semanticAnchorFields?.signature.orEmpty().joinToString("|")
            "subroutine[" in signature && "varargs" in signature
        }, "callback signatures were not completely described; $runDescription")
        assertTrue(callbackFacts.none { "unsupported-type-shape" in it.reasonCodes }, runDescription)

        val sharedInline = facts.filter {
            it.kind == FullTreeSourceEntityKind.INLINE_INSTANCE && it.semanticAnchorFields?.sourceName == "shared_inline"
        }
        if (optimization == 2) {
            val scopedTypeInstances = templateInstances.filter {
                it.semanticAnchorFields?.sourceName?.startsWith("scoped_type_template<") == true
            }
            assertTrue(scopedTypeInstances.isNotEmpty(), "same-spelling namespace type template instances were not retained; $runDescription")
            val scopedTypeArguments = scopedTypeInstances.mapNotNull {
                it.semanticAnchorFields?.templateActualArguments?.singleOrNull()
            }.distinct()
            assertTrue(scopedTypeArguments.size >= 2, "same-spelling types from different namespaces collided; $runDescription")
            assertTrue(scopedTypeArguments.all { "scope[" in it }, "named-type template descriptors omitted lexical scope; $runDescription")

            val unionScopedInstances = templateInstances.filter {
                it.semanticAnchorFields?.sourceName?.startsWith("union_scoped_template<") == true
            }
            assertTrue(unionScopedInstances.isNotEmpty(), "union-scoped template instances were not retained; $runDescription")
            val unionScopedArguments = unionScopedInstances.mapNotNull {
                it.semanticAnchorFields?.templateActualArguments?.singleOrNull()
            }.distinct()
            assertTrue(unionScopedArguments.size >= 2, "same-name types in distinct union scopes collided; $runDescription")
            assertTrue(unionScopedArguments.all { "scope[" in it && "SameUnion" in it }, runDescription)
            assertTrue(
                unionScopedInstances.mapNotNull { it.semanticAnchorCandidateId }.distinct().size >= 2,
                "union lexical scopes did not distinguish instance candidates; $runDescription",
            )

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

            val uniqueInlineOrigin = facts.filter {
                it.kind == FullTreeSourceEntityKind.INLINE_INSTANCE &&
                    it.semanticAnchorFields?.sourceName == "unique_source_pattern"
            }
            assertTrue(dwarfShape.contains("unique_source_pattern"), "positive source-pattern shape is absent; $runDescription")
            assertTrue(dwarfShape.contains("DW_TAG_inlined_subroutine"), "positive inline-instance shape is absent; $runDescription")
            assertEquals(1, uniqueInlineOrigin.size, "expected one physical positive inline-origin relationship; $runDescription")
            assertEquals(FullTreeIdentityObservability.OBSERVABLE, uniqueInlineOrigin.single().identityObservability, runDescription)
            assertTrue(uniqueInlineOrigin.single().candidateCollisionSourceEntityIds.isEmpty(), runDescription)
            assertTrue(uniqueInlineOrigin.single().semanticAnchorFields?.inlineCalleeAnchorCandidateId != null, runDescription)
            assertTrue(uniqueInlineOrigin.single().edges.any {
                it.kind == FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN &&
                    it.state == FullTreeSourceIdentityEdgeState.RESOLVED && it.target != null
            }, runDescription)
            assertTrue(uniqueInlineOrigin.single().edges.any {
                it.kind == FullTreeSourceIdentityEdgeKind.TYPE &&
                    it.state == FullTreeSourceIdentityEdgeState.RESOLVED && it.target != null
            }, "cached inline-callee signature reference evidence was dropped; $runDescription")
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

    private fun hasDwarfName(dwarfShape: String, namePrefix: String): Boolean =
        Regex("DW_AT_name\\s*:[^\\n]*:\\s*${Regex.escape(namePrefix)}(?:>|[ \\t]|$)")
            .containsMatchIn(dwarfShape)

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
