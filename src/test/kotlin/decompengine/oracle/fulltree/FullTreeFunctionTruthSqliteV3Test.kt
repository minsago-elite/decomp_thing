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
    fun `truth v3 rederives observation census and preserves one score row per RVA`() =
        inControlTemporaryDirectory { root ->
            val fixture = createCompilerFixture(root)
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
            )

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
                "ca163ed4fcf7d36e54e7967c52e2c58fac3b9eae7c215b455bee24e4cc09d0c8",
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

            val scoreRowCount = index.controlArray("shards").sumOf { raw ->
                val shardRecord = raw as JsonObject
                val shard = parseControlObject(first.root.resolve(shardRecord.controlString("path")))
                OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME, shard)
                val functions = shard.controlArray("functions").controlObjects("truth functions")
                assertEquals(functions.size.toLong(), shard.controlObject("counts").controlLong("functions"))
                assertEquals(shard.controlArray("sourceEntities").size.toLong(), shard.controlObject("counts").controlLong("sourceEntities"))
                val rvas = functions.map { it.controlString("rva") }
                assertEquals(rvas.size, rvas.distinct().size, "source census must not duplicate score rows")
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
                )
            }
            assertEquals(forgedBytes, v3TreeBytes(forged), "rejected candidate bytes remain unchanged")
            assertDirectoryEmpty(fixture.scratch)
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
        makeTreeWritable(root)
        val selected = Files.list(root.resolve("shards")).use { paths ->
            paths.toList().asSequence().mapNotNull { path ->
                val value = parseControlObject(path)
                val index = value.controlArray("sourceEntities").indexOfFirst { raw ->
                    val row = raw as? JsonObject ?: return@indexOfFirst false
                    row["linkedEmittedRva"] != null && row["linkedEmittedRva"] != JsonNull
                }
                if (index < 0) null else CandidateSource(
                    path,
                    value,
                    index,
                    value.controlArray("sourceEntities")[index] as JsonObject,
                )
            }.firstOrNull()
        }
        val (shardPath, shard, sourceIndex, original) = selected
            ?: error("fixture must contain an emitted-RVA-linked census row")
        val sources = shard.controlArray("sourceEntities").toMutableList()
        val current = original["semanticAnchorCandidateId"]
        val oldCandidate = (current as? JsonPrimitive)?.takeIf { it.isString }?.content
        val forgedCandidate: JsonElement = if (oldCandidate == "a".repeat(64)) JsonPrimitive("b".repeat(64)) else JsonPrimitive("a".repeat(64))
        val oldObservability = original.controlString("identityObservability")
        val oldDisposition = original.controlString("denominatorDisposition")
        val sourceEntity = JsonObject(original.toMutableMap().apply {
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
        })
        sources[sourceIndex] = sourceEntity
        val changedShard = withSourceRowsAndCounts(shard, JsonArray(sources))
        OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME, changedShard)
        val changedShardBytes = OracleJson.canonicalBytes(changedShard)
        Files.write(shardPath, changedShardBytes)

        val indexPath = root.resolve("index.json")
        val index = parseControlObject(indexPath)
        val allRows = Files.list(root.resolve("shards")).use { paths ->
            paths.map(::parseControlObject).map { it.controlArray("sourceEntities").controlObjects("source entities") }
                .toList().flatten()
        }
        val records = index.controlArray("shards").map { raw ->
            val record = raw as JsonObject
            if (record.controlString("path") == root.relativize(shardPath).toString()) {
                JsonObject(record.toMutableMap().apply {
                    put("bytes", JsonPrimitive(changedShardBytes.size))
                    put("sha256", JsonPrimitive(OracleArtifacts.sha256(changedShardBytes)))
                })
            } else record
        }
        val counts = JsonObject(index.controlObject("counts").toMutableMap().apply {
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

    private fun createCompilerFixture(root: Path): V3Fixture {
        val sourceRoot = Path.of(System.getProperty("user.dir"))
            .resolve("src/test/resources/oracle/inline-template-identity-v1").toAbsolutePath().normalize()
        val compiler = resolveCompiler("GXX", listOf("g++", "g++-14", "g++-13"))
        val compilerVersion = runCommand(listOf(compiler.toString(), "--version"), root, "compiler-version.txt")
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
        assertCompilerInputVector(sourceRoot, compilerVersion, artifact)
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
        )
    }

    private fun assertCompilerInputVector(sourceRoot: Path, compilerVersion: String, artifact: Path) {
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
        if (compilerVersion.startsWith("g++ (Debian 14.2.0-19) 14.2.0")) {
            assertEquals(vector.controlObject("compiler").controlString("observedVersion"), compilerVersion.lineSequence().first())
        }
        assertTrue(Files.size(artifact) > 0L)
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
                "compiler" to JsonPrimitive(fixture.compilerIdentity),
                "fixtureInputVectorSha256" to JsonPrimitive(fixtureSha256(inputVectorPath)),
                "input" to JsonObject(
                    mapOf(
                        "richElfSha256" to JsonPrimitive(fixtureSha256(fixture.rich)),
                        "strippedElfSha256" to JsonPrimitive(fixtureSha256(fixture.stripped)),
                        "observationV2IndexArtifactSha256" to JsonPrimitive(fixture.observationV2IndexSha256),
                        "scopeSha256" to JsonPrimitive(fixture.scope.sha256),
                        "inventoryArtifactSha256" to JsonPrimitive(fixtureSha256(fixture.inventoryPath)),
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
        Files.write(output, OracleJson.canonicalBytes(vector))
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
    )

    private data class CandidateSource(
        val path: Path,
        val shard: JsonObject,
        val sourceIndex: Int,
        val source: JsonObject,
    )
}
