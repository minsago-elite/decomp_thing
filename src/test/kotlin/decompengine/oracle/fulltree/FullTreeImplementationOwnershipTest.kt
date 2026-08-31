package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue

class FullTreeImplementationOwnershipTest {
    @Test
    fun `historical projection maps exact populations without inventing dependencies`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createOwnershipFixture(directory.resolve("complete"))

            val first = assess(fixture)
            val second = assess(fixture)
            assertContentEquals(first.canonicalBytes, second.canonicalBytes)
            assertEquals(first.reportSha256, second.reportSha256)
            assertEquals(1L, first.recoveredImplementations)
            assertEquals(1L, first.missingImplementations)

            val document = OracleJson.parseCanonical(
                first.canonicalBytes,
                controlJsonLimits(64 * 1024 * 1024),
            ) as JsonObject
            assertEquals("non-authoritative", document.controlObject("authority").controlString("status"))
            assertEquals("inline-only-v1", document.controlObject("authority").controlString("historicalFunctionTruthFormat"))
            assertFalse(document.controlObject("authority")["releaseEligible"]!!.toString().toBoolean())
            assertEquals(
                JsonObject(
                    mapOf(
                        "dependencyEdges" to JsonPrimitive(0),
                        "emittedImplementations" to JsonPrimitive(3),
                        "fabricatedImplementations" to JsonPrimitive(0),
                        "inlineOnlyDeclarations" to JsonPrimitive(1),
                        "missingImplementations" to JsonPrimitive(1),
                        "modulesWithImplementations" to JsonPrimitive(2),
                        "ownedExcludedImplementations" to JsonPrimitive(1),
                        "ownerlessExcludedImplementations" to JsonPrimitive(1),
                        "recoveredImplementations" to JsonPrimitive(1),
                        "scoredImplementations" to JsonPrimitive(2),
                        "sourceModules" to JsonPrimitive(2),
                        "sourceOnlyUnits" to JsonPrimitive(3),
                        "totalExcludedImplementations" to JsonPrimitive(2),
                        "truthShards" to JsonPrimitive(2),
                        "workUnits" to JsonPrimitive(19),
                    ),
                ),
                document.controlObject("counts"),
            )
            assertEquals(
                "not-inferred-from-historical-function-evidence",
                document.controlObject("dependencies").controlString("status"),
            )
            assertTrue(document.controlObject("dependencies").controlArray("edges").isEmpty())
            val modules = document.controlArray("modules").controlObjects("ownership modules")
            assertEquals(2, modules.size)
            assertTrue(modules.all { it.controlString("moduleId") == it.controlString("ownerUnitId") })
            assertTrue(modules.none { it.controlString("moduleId") == "core" })
            assertEquals(1L, modules.sumOf { it.controlObject("counts").controlLong("recoveredImplementations") })
            assertEquals(1L, modules.sumOf { it.controlObject("counts").controlLong("missingImplementations") })
            assertEquals(1L, modules.sumOf { it.controlObject("counts").controlLong("excludedImplementations") })
            assertEquals(1L, modules.sumOf { it.controlObject("counts").controlLong("inlineOnlyDeclarations") })
            val driverModule = modules.single { it.controlString("shardId") == "clang-lib-driver" }
            assertEquals(
                "ab4ed6920f107a192406db1de5dd692c879fd3b9e3b47eab8b8a8b933db8e9aa",
                driverModule.controlObject("commitments").controlString("missingImplementationIdsSha256"),
                "the frozen domain/framing digest detects duplicated or omitted missing IDs",
            )

            val mutated = first.canonicalBytes
            mutated[0] = (mutated[0].toInt() xor 1).toByte()
            assertContentEquals(second.canonicalBytes, first.canonicalBytes)
        }

    @Test
    fun `unowned source-only cross-shard and duplicate implementation ownership fail closed`() =
        inControlTemporaryDirectory { directory ->
            val variants = listOf(
                OwnershipFixtureVariant.UNOWNED,
                OwnershipFixtureVariant.SOURCE_ONLY_OWNER,
                OwnershipFixtureVariant.CROSS_SHARD_OWNER,
                OwnershipFixtureVariant.DUPLICATE_RVA,
            )
            variants.forEach { variant ->
                val fixture = createOwnershipFixture(directory.resolve(variant.name.lowercase()), variant)
                assertFailsWith<FullTreeImplementationOwnershipException>(variant.name) { assess(fixture) }
            }
        }

    @Test
    fun `self-consistent forged baseline and unsafe shard paths fail closed`() =
        inControlTemporaryDirectory { directory ->
            listOf(
                OwnershipFixtureVariant.BASELINE_SURVIVAL_DRIFT,
                OwnershipFixtureVariant.TRAVERSAL_PATH,
                OwnershipFixtureVariant.NONCANONICAL_SHARD,
                OwnershipFixtureVariant.LIVE_NON_EMITTED_SHAPE,
            ).forEach { variant ->
                val fixture = createOwnershipFixture(directory.resolve(variant.name.lowercase()), variant)
                assertFailsWith<FullTreeImplementationOwnershipException>(variant.name) { assess(fixture) }
            }
        }

    @Test
    fun `caller lowering bounds and symbolic link inputs fail closed`(): Unit =
        inControlTemporaryDirectory { directory ->
            val bounded = createOwnershipFixture(directory.resolve("bounded"))
            assertFailsWith<FullTreeImplementationOwnershipException> {
                assess(
                    bounded,
                    FullTreeImplementationOwnershipLimits(maximumImplementations = 2),
                )
            }

            val linked = createOwnershipFixture(directory.resolve("linked"))
            val aliasRoot = directory.resolve("alias")
            Files.createDirectories(aliasRoot)
            Files.setPosixFilePermissions(aliasRoot, PosixFilePermissions.fromString("rwx------"))
            val alias = aliasRoot.resolve("index.json")
            Files.createSymbolicLink(alias, linked.truthIndex)
            assertFailsWith<FullTreeImplementationOwnershipException> {
                assess(linked.copy(truthIndex = alias))
            }
        }

    @Test
    fun `lowered work bound rejects before historical shard traversal`(): Unit =
        inControlTemporaryDirectory { directory ->
            val fixture = createOwnershipFixture(directory.resolve("work-bound"))
            val firstShard = fixture.truthIndex.parent.resolve("shards/clang-lib-driver.json")
            Files.write(firstShard, byteArrayOf('\n'.code.toByte()), StandardOpenOption.APPEND)
            val failure = assertFailsWith<FullTreeImplementationOwnershipException> {
                assess(
                    fixture,
                    FullTreeImplementationOwnershipLimits(maximumWorkUnits = 18),
                )
            }
            assertEquals(
                "implementation ownership projection exceeds its work-unit bound",
                failure.message,
            )
        }

    @Test
    fun `JVM construction and public API accept only raw paths and lowering limits`() {
        val implementation = Class.forName(
            "decompengine.oracle.fulltree.FullTreeImplementationOwnership\$ValidatedAssessment",
        )
        val constructors = implementation.declaredConstructors
        assertTrue(constructors.isNotEmpty())
        constructors.forEach { constructor ->
            val unsupported = constructor.parameterTypes.filterNot { type ->
                type == Path::class.java ||
                    type == FullTreeImplementationOwnershipLimits::class.java ||
                    type.name == "kotlin.jvm.internal.DefaultConstructorMarker"
            }
            assertTrue(unsupported.isEmpty(), "unexpected constructor inputs: $unsupported")
            assertFalse(constructor.parameterTypes.any { it == ByteArray::class.java })
            assertFalse(constructor.parameterTypes.any { JsonObject::class.java.isAssignableFrom(it) })
        }
        FullTreeImplementationOwnership::class.java.declaredMethods
            .filter { Modifier.isPublic(it.modifiers) && it.name == "assessHistoricalA13V2" }
            .forEach { method ->
                assertTrue(method.parameterTypes.all {
                    it == Path::class.java || it == FullTreeImplementationOwnershipLimits::class.java
                })
            }
    }

    @Test
    fun `locked historical A13 v2 projection reproduces exact planning populations`() {
        val truthRoot = System.getenv("DECOMP_A14_HISTORICAL_FUNCTION_TRUTH_ROOT")
            ?.takeIf(String::isNotBlank)?.let(Path::of)
        val baseline = System.getenv("DECOMP_A14_HISTORICAL_FUNCTION_BASELINE")
            ?.takeIf(String::isNotBlank)?.let(Path::of)
        assumeTrue(
            truthRoot != null && baseline != null,
            "set both DECOMP_A14_HISTORICAL_FUNCTION_* paths for the long parity proof",
        )
        val requiredTruthRoot = requireNotNull(truthRoot)
        val requiredBaseline = requireNotNull(baseline)
        val profile = Path.of("oracle/llvm/22.1.6").toAbsolutePath().normalize()
        val assessment = FullTreeImplementationOwnership.assessHistoricalA13V2(
            profile.resolve("full-tree-scope.json"),
            profile.resolve("source-lock.json"),
            profile.resolve("oracle-manifest.json"),
            profile.resolve("build-record.json"),
            profile.resolve("full-tree-inventory.json"),
            profile.resolve("full-tree-source-inventory.json"),
            profile.resolve("full-tree-planning-inventory.json"),
            requiredTruthRoot.resolve("index.json"),
            requiredBaseline,
        )
        val document = OracleJson.parseCanonical(
            assessment.canonicalBytes,
            controlJsonLimits(64 * 1024 * 1024),
        ) as JsonObject
        val counts = document.controlObject("counts")
        assertEquals(2_150L, counts.controlLong("sourceModules"))
        assertEquals(267_945L, counts.controlLong("emittedImplementations"))
        assertEquals(267_944L, counts.controlLong("scoredImplementations"))
        assertEquals(78_103L, counts.controlLong("recoveredImplementations"))
        assertEquals(189_841L, counts.controlLong("missingImplementations"))
        assertEquals(1L, counts.controlLong("ownedExcludedImplementations"))
        assertEquals(8L, counts.controlLong("ownerlessExcludedImplementations"))
        assertEquals(988_799L, counts.controlLong("inlineOnlyDeclarations"))
        assertEquals(
            "159c32bbfa773c77974d18f07e56cf346096db10f874ded0f70cb0e6759f2381",
            OracleArtifacts.sha256(assessment.canonicalBytes),
        )
        assertEquals(
            "c099b914196208b480edbd59cd215fee76004bf398b96f6d1118ea81f16632d7",
            assessment.reportSha256,
        )
        assertEquals(2_394_235, assessment.canonicalBytes.size)
    }
}

private enum class OwnershipFixtureVariant {
    COMPLETE,
    UNOWNED,
    SOURCE_ONLY_OWNER,
    CROSS_SHARD_OWNER,
    DUPLICATE_RVA,
    BASELINE_SURVIVAL_DRIFT,
    TRAVERSAL_PATH,
    NONCANONICAL_SHARD,
    LIVE_NON_EMITTED_SHAPE,
}

private data class OwnershipFixture(
    val control: FullTreeControlFixture,
    val planning: Path,
    val truthIndex: Path,
    val baseline: Path,
)

private fun createOwnershipFixture(
    root: Path,
    variant: OwnershipFixtureVariant = OwnershipFixtureVariant.COMPLETE,
): OwnershipFixture {
    Files.createDirectories(root)
    Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
    val control = createFullTreeControlFixture(root.resolve("control"))
    val planning = root.resolve("planning.json")
    FullTreePlanningInventoryControl.generateAndPublish(
        control.scope,
        control.sourceLock,
        control.manifest,
        control.buildRecord,
        control.inventory,
        control.sourceInventory,
        planning,
    )
    val planningDocument = parseControlObject(planning)
    val planningOracle = planningDocument.controlObject("oracle")
    val modules = planningDocument.controlArray("sourceModules").controlObjects("fixture modules")
        .associateBy { it.controlString("shardId") }
    val driver = modules.getValue("clang-lib-driver").controlString("unitId")
    val generated = modules.getValue("generated-tools-clang").controlString("unitId")
    val sourceOnly = FullTreeInventoryControl.compilationUnitId("source/clang/tools/Extra/tool.cpp")
    val historicalOracle = JsonObject(
        mapOf(
            "configurationSha256" to JsonPrimitive(HISTORICAL_TRUTH_CONFIGURATION_FIXTURE),
            "elfIndexSha256" to JsonPrimitive("1".repeat(64)),
            "inventoryIndexSha256" to planningOracle.getValue("inventoryIndexSha256"),
            "observationIndexSha256" to JsonPrimitive("2".repeat(64)),
            "scopeSha256" to planningOracle.getValue("scopeSha256"),
        ),
    )
    val truthRoot = root.resolve("truth")
    val shardsRoot = truthRoot.resolve("shards")
    Files.createDirectories(shardsRoot)
    Files.setPosixFilePermissions(truthRoot, PosixFilePermissions.fromString("rwx------"))
    Files.setPosixFilePermissions(shardsRoot, PosixFilePermissions.fromString("rwx------"))

    val selectedOwner = when (variant) {
        OwnershipFixtureVariant.UNOWNED -> "cu-${"f".repeat(32)}"
        OwnershipFixtureVariant.SOURCE_ONLY_OWNER -> sourceOnly
        OwnershipFixtureVariant.CROSS_SHARD_OWNER -> generated
        else -> driver
    }
    var driverFunctions = listOf(
        fixtureFunction("0x10", driver, stripped = true),
        fixtureFunction("0x20", selectedOwner, stripped = false),
    )
    var driverInline = listOf(fixtureInline(driver))
    if (variant == OwnershipFixtureVariant.LIVE_NON_EMITTED_SHAPE) {
        driverFunctions = driverFunctions.map { function ->
            JsonObject(function + ("emissionKind" to JsonPrimitive("single-definition")))
        }
        driverInline = driverInline.map { inline ->
            JsonObject(
                inline + ("observationDieOffsets" to JsonArray(
                    listOf(
                        JsonObject(
                            mapOf(
                                "dieOffset" to JsonPrimitive("0x50"),
                                "unitId" to JsonPrimitive(driver),
                            ),
                        ),
                    ),
                )),
            )
        }
    }
    val generatedRva = if (variant == OwnershipFixtureVariant.DUPLICATE_RVA) "0x20" else "0x30"
    val shardDocuments = linkedMapOf(
        "clang-lib-driver" to fixtureTruthShard(
            "clang-lib-driver",
            listOf(driver),
            driverFunctions,
            driverInline,
            historicalOracle,
        ),
        "generated-tools-clang" to fixtureTruthShard(
            "generated-tools-clang",
            listOf(generated),
            listOf(fixtureFunction(generatedRva, generated, stripped = false, excluded = true)),
            emptyList(),
            historicalOracle,
        ),
    )
    val shardRecords = shardDocuments.map { (id, document) ->
        val path = shardsRoot.resolve("$id.json")
        val bytes = writeOwnershipJson(path, document)
        JsonObject(
            mapOf(
                "bytes" to JsonPrimitive(bytes.size),
                "functions" to JsonPrimitive(document.controlArray("functions").size),
                "id" to JsonPrimitive(id),
                "inlineOnly" to JsonPrimitive(document.controlArray("inlineOnly").size),
                "path" to JsonPrimitive(
                    if (variant == OwnershipFixtureVariant.TRAVERSAL_PATH && id == "clang-lib-driver") {
                        "../outside.json"
                    } else {
                        "shards/$id.json"
                    },
                ),
                "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
            ),
        )
    }
    if (variant == OwnershipFixtureVariant.NONCANONICAL_SHARD) {
        val path = shardsRoot.resolve("clang-lib-driver.json")
        Files.write(path, Files.readAllBytes(path) + '\n'.code.toByte())
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"))
        val record = shardRecords.first()
        val bytes = Files.readAllBytes(path)
        val replacement = JsonObject(record + mapOf(
            "bytes" to JsonPrimitive(bytes.size),
            "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
        ))
        (shardRecords as MutableList)[0] = replacement
    }

    val exclusionsDocument = JsonObject(
        mapOf(
            "functions" to JsonArray(listOf(fixtureExclusion("0x40"))),
            "oracle" to historicalOracle,
            "reasonCode" to JsonPrimitive("elf-no-source-aligned-dwarf"),
            "schemaVersion" to JsonPrimitive(1),
        ),
    )
    val exclusionBytes = writeOwnershipJson(truthRoot.resolve("exclusions.json"), exclusionsDocument)
    val exclusionRecord = JsonObject(
        mapOf(
            "bytes" to JsonPrimitive(exclusionBytes.size),
            "functions" to JsonPrimitive(1),
            "id" to JsonPrimitive("elf-only-exclusions"),
            "inlineOnly" to JsonPrimitive(0),
            "path" to JsonPrimitive("exclusions.json"),
            "sha256" to JsonPrimitive(OracleArtifacts.sha256(exclusionBytes)),
        ),
    )
    val indexWithoutHash = JsonObject(
        mapOf(
            "complete" to JsonPrimitive(true),
            "counts" to JsonObject(
                mapOf(
                    "dwarfOnlyRvas" to JsonPrimitive(1),
                    "dwarfRvas" to JsonPrimitive(3),
                    "elfOnlyRvas" to JsonPrimitive(1),
                    "elfRvas" to JsonPrimitive(3),
                    "inlineObservations" to JsonPrimitive(1),
                    "inlineUnique" to JsonPrimitive(1),
                    "scoredRvas" to JsonPrimitive(2),
                ),
            ),
            "exclusions" to exclusionRecord,
            "oracle" to historicalOracle,
            "schemaVersion" to JsonPrimitive(1),
            "shards" to JsonArray(shardRecords),
        ),
    )
    val indexDocument = JsonObject(
        indexWithoutHash + ("indexSha256" to JsonPrimitive(OracleArtifacts.sha256(canonical(indexWithoutHash)))),
    )
    val indexPath = truthRoot.resolve("index.json")
    val indexBytes = writeOwnershipJson(indexPath, indexDocument)

    val baselineDrift = variant == OwnershipFixtureVariant.BASELINE_SURVIVAL_DRIFT
    val missingId = "function-rva-0x20"
    val mismatches = if (baselineDrift) emptyList() else listOf(fixtureMismatch(missingId, "clang-lib-driver"))
    val driverMetric = if (baselineDrift) fixtureMetric(2, 0, 0) else fixtureMetric(1, 1, 0)
    val baselineShards = listOf(
        fixtureMetricRecord("clang-lib-driver", driverMetric),
        fixtureMetricRecord("elf-only-exclusions", fixtureMetric(0, 0, 1)),
        fixtureMetricRecord("generated-tools-clang", fixtureMetric(0, 0, 1)),
    )
    val aggregate = if (baselineDrift) fixtureMetric(2, 0, 2) else fixtureMetric(1, 1, 2)
    val baselineWithoutHash = JsonObject(
        mapOf(
            "aggregate" to aggregate,
            "configurationSha256" to JsonPrimitive(HISTORICAL_BASELINE_CONFIGURATION_FIXTURE),
            "mismatches" to JsonArray(mismatches),
            "schemaVersion" to JsonPrimitive(1),
            "shards" to JsonArray(baselineShards),
            "truthIndexSha256" to JsonPrimitive(OracleArtifacts.sha256(indexBytes)),
        ),
    )
    val baselineDocument = JsonObject(
        baselineWithoutHash +
            ("reportSha256" to JsonPrimitive(OracleArtifacts.sha256(canonical(baselineWithoutHash)))),
    )
    val baselinePath = root.resolve("llvm-full-tree-function-baseline-v3.json")
    writeOwnershipJson(baselinePath, baselineDocument)
    return OwnershipFixture(control, planning, indexPath, baselinePath)
}

private fun assess(
    fixture: OwnershipFixture,
    limits: FullTreeImplementationOwnershipLimits = FullTreeImplementationOwnershipLimits(),
): FullTreeImplementationOwnershipAssessment = FullTreeImplementationOwnership.assessHistoricalA13V2(
    fixture.control.scope,
    fixture.control.sourceLock,
    fixture.control.manifest,
    fixture.control.buildRecord,
    fixture.control.inventory,
    fixture.control.sourceInventory,
    fixture.planning,
    fixture.truthIndex,
    fixture.baseline,
    limits,
)

private fun fixtureTruthShard(
    shardId: String,
    unitIds: List<String>,
    functions: List<JsonObject>,
    inlineOnly: List<JsonObject>,
    oracle: JsonObject,
): JsonObject = JsonObject(
    mapOf(
        "counts" to JsonObject(
            mapOf(
                "functions" to JsonPrimitive(functions.size),
                "inlineOnly" to JsonPrimitive(inlineOnly.size),
            ),
        ),
        "functions" to JsonArray(functions),
        "inlineOnly" to JsonArray(inlineOnly),
        "oracle" to oracle,
        "schemaVersion" to JsonPrimitive(1),
        "shard" to JsonObject(
            mapOf(
                "id" to JsonPrimitive(shardId),
                "unitIds" to JsonArray(unitIds.map(::JsonPrimitive)),
            ),
        ),
    ),
)

private fun fixtureFunction(
    rva: String,
    owner: String,
    stripped: Boolean,
    excluded: Boolean = false,
): JsonObject {
    val evidence = if (stripped) {
        JsonObject(
            mapOf(
                "kind" to JsonPrimitive("elf-symbol"),
                "locator" to JsonPrimitive("stripped:section[1]=.dynsym:symbol[1]"),
                "unitId" to JsonNull,
            ),
        )
    } else {
        JsonObject(
            mapOf(
                "kind" to JsonPrimitive("dwarf-subprogram"),
                "locator" to JsonPrimitive("rich:.debug_info:die=$rva:DW_AT_name@$rva"),
                "unitId" to JsonPrimitive(owner),
            ),
        )
    }
    return JsonObject(
        mapOf(
            "aliases" to JsonArray(
                listOf(
                    JsonObject(
                        mapOf(
                            "evidence" to JsonArray(listOf(evidence)),
                            "name" to JsonPrimitive("function_${rva.removePrefix("0x")}"),
                        ),
                    ),
                ),
            ),
            "declarations" to JsonArray(listOf(fixtureDeclaration(owner))),
            "entityKind" to JsonPrimitive("function"),
            "id" to JsonPrimitive("function-rva-$rva"),
            "ownerUnitId" to JsonPrimitive(owner),
            "ownershipCandidates" to JsonArray(listOf(JsonPrimitive(owner))),
            "population" to JsonPrimitive(if (excluded) "excluded" else "scored"),
            "reasonCode" to if (excluded) JsonPrimitive("dwarf-rva-without-elf-function") else JsonNull,
            "rva" to JsonPrimitive(rva),
        ),
    )
}

private fun fixtureInline(owner: String): JsonObject = JsonObject(
    mapOf(
        "aliases" to JsonArray(
            listOf(
                JsonObject(
                    mapOf(
                        "evidence" to JsonArray(
                            listOf(
                                JsonObject(
                                    mapOf(
                                        "kind" to JsonPrimitive("dwarf-subprogram"),
                                        "locator" to JsonPrimitive("rich:.debug_info:die=0x50:DW_AT_name@0x50"),
                                        "unitId" to JsonPrimitive(owner),
                                    ),
                                ),
                            ),
                        ),
                        "name" to JsonPrimitive("inline_fixture"),
                    ),
                ),
            ),
        ),
        "declarations" to JsonArray(listOf(fixtureDeclaration(owner))),
        "id" to JsonPrimitive("inline-declaration-${"a".repeat(32)}"),
        "observationIds" to JsonArray(listOf(JsonPrimitive("observation-fixture"))),
        "ownerUnitId" to JsonPrimitive(owner),
        "population" to JsonPrimitive("unobservable"),
        "reasonCode" to JsonPrimitive("inline-no-emitted-range"),
    ),
)

private fun fixtureExclusion(rva: String): JsonObject = JsonObject(
    mapOf(
        "aliases" to JsonArray(
            listOf(
                JsonObject(
                    mapOf(
                        "evidence" to JsonArray(
                            listOf(
                                JsonObject(
                                    mapOf(
                                        "kind" to JsonPrimitive("elf-symbol"),
                                        "locator" to JsonPrimitive("stripped:section[1]=.dynsym:symbol[2]"),
                                        "unitId" to JsonNull,
                                    ),
                                ),
                            ),
                        ),
                        "name" to JsonPrimitive("_start"),
                    ),
                ),
            ),
        ),
        "id" to JsonPrimitive("function-rva-$rva"),
        "reasonCode" to JsonPrimitive("elf-no-source-aligned-dwarf"),
        "rva" to JsonPrimitive(rva),
    ),
)

private fun fixtureDeclaration(owner: String): JsonObject = JsonObject(
    mapOf(
        "column" to JsonNull,
        "externalPathSha256" to JsonNull,
        "fileIndex" to JsonPrimitive(1),
        "line" to JsonPrimitive(1),
        "sourcePath" to JsonPrimitive("source/fixture/$owner.cpp"),
        "unitSourcePath" to JsonPrimitive("source/fixture/$owner.cpp"),
    ),
)

private fun fixtureMetric(recovered: Long, missing: Long, excluded: Long): JsonObject {
    val denominator = recovered + missing
    return JsonObject(
        mapOf(
            "denominator" to JsonPrimitive(denominator),
            "excluded" to JsonPrimitive(excluded),
            "fabricated" to JsonPrimitive(0),
            "missing" to JsonPrimitive(missing),
            "recallDenominator" to JsonPrimitive(denominator),
            "recallNumerator" to JsonPrimitive(recovered),
            "recovered" to JsonPrimitive(recovered),
        ),
    )
}

private fun fixtureMetricRecord(id: String, metric: JsonObject): JsonObject = JsonObject(
    mapOf("id" to JsonPrimitive(id), "metric" to metric),
)

private fun fixtureMismatch(truthId: String, shardId: String): JsonObject {
    val identityPayload = JsonObject(
        mapOf("kind" to JsonPrimitive("missing"), "truthId" to JsonPrimitive(truthId)),
    )
    return JsonObject(
        mapOf(
            "id" to JsonPrimitive(
                "missing-function-${OracleArtifacts.sha256(canonical(identityPayload)).take(32)}",
            ),
            "kind" to JsonPrimitive("missing"),
            "shardId" to JsonPrimitive(shardId),
            "truthId" to JsonPrimitive(truthId),
        ),
    )
}

private fun canonical(value: JsonObject): ByteArray = OracleJson.canonicalBytes(
    value,
    controlJsonLimits(64 * 1024 * 1024),
)

private fun writeOwnershipJson(path: Path, value: JsonObject): ByteArray = canonical(value).also { bytes ->
    Files.write(path, bytes)
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"))
}

private const val HISTORICAL_TRUTH_CONFIGURATION_FIXTURE =
    "3c192005e782c255a9779769676a2cf3e7d33050830f220adc32e03d3e65b329"
private const val HISTORICAL_BASELINE_CONFIGURATION_FIXTURE =
    "c29ef7047ba26e9165e78faffd5781711923f75c1fb265e5f615bfd1ffd21951"
