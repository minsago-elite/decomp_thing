package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeFunctionObservationsTest {
    @Test
    fun `Kotlin policy and authenticated shard bytes match historical v3 contract`() {
        val fixture = fixture()
        val input = FullTreeFunctionObservations.shardInputs(
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            fixture.scope,
            fixture.scopeSha256,
        ).single()

        assertEquals(
            "dffe8bad65e82b46150cd1f5368925ae10709fd01adf905d27f1e8784634a86e",
            FullTreeFunctionObservations.configurationSha256,
        )
        assertEquals("shard-a", input.identifier)
        assertEquals(fixture.units, input.units)
        assertEquals(
            "9010b1185dc54c2e8d04310e88731d9f461bfa75f3738911d583301fe153d0a6",
            input.inputSha256,
        )
    }

    @Test
    fun `valid emitted and non-emitted evidence reconciles exactly`() {
        val fixture = fixture()
        val input = FullTreeFunctionObservations.shardInputs(
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            fixture.scope,
            fixture.scopeSha256,
        ).single()
        val document = observationDocument(fixture, input)

        FullTreeFunctionObservations.validateEnvelope(
            document,
            fixture.scope,
            fixture.scopeSha256,
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            input,
        )
    }

    @Test
    fun `validator rejects identity ownership ordering count and bound mutations`() {
        val fixture = fixture()
        val input = FullTreeFunctionObservations.shardInputs(
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            fixture.scope,
            fixture.scopeSha256,
        ).single()
        val valid = observationDocument(fixture, input)

        val nonEmitted = valid.array("nonEmitted").single() as JsonObject
        val wrongIdentity = replaceArrayItem(
            valid,
            "nonEmitted",
            0,
            JsonObject(nonEmitted.toMutableMap().apply {
                this["id"] = JsonPrimitive("non-emitted-observation-${"f".repeat(32)}")
            }),
        )
        assertFailsWithMessage("identity") { validate(wrongIdentity, fixture, input) }

        val emitted = valid.array("emitted").single() as JsonObject
        val aliases = emitted.array("aliases")
        val alias = aliases.single() as JsonObject
        val evidence = alias.array("evidence").toMutableList()
        evidence[0] = JsonObject((evidence[0] as JsonObject).toMutableMap().apply {
            this["unitId"] = JsonPrimitive("cu-${"f".repeat(32)}")
        })
        val outsideAlias = JsonObject(alias.toMutableMap().apply {
            this["evidence"] = JsonArray(evidence)
        })
        val outsideEmitted = JsonObject(emitted.toMutableMap().apply {
            this["aliases"] = JsonArray(listOf(outsideAlias))
        })
        val outsideOwner = replaceArrayItem(valid, "emitted", 0, outsideEmitted)
        assertFailsWithMessage("outside ownership") { validate(outsideOwner, fixture, input) }

        val reversedDeclarations = JsonObject(emitted.toMutableMap().apply {
            this["declarations"] = JsonArray(emitted.array("declarations").reversed())
        })
        val unordered = replaceArrayItem(valid, "emitted", 0, reversedDeclarations)
        assertFailsWithMessage("ordered") { validate(unordered, fixture, input) }

        val badCounts = JsonObject(valid.toMutableMap().apply {
            this["counts"] = JsonObject(valid.objectValue("counts").toMutableMap().apply {
                this["nonEmittedDies"] = JsonPrimitive(1)
            })
        })
        assertFailsWithMessage("counts") { validate(badCounts, fixture, input) }

        val insufficientScan = JsonObject(valid.toMutableMap().apply {
            this["counts"] = JsonObject(valid.objectValue("counts").toMutableMap().apply {
                this["scannedDies"] = JsonPrimitive(3)
            })
        })
        assertFailsWithMessage("cannot cover") { validate(insufficientScan, fixture, input) }

        val crossUnitOffsets = nonEmitted.array("dieOffsets").toMutableList().apply {
            this[0] = dieOffset(fixture.units[0].string("id"), "0x10")
        }
        val crossUnit = replaceArrayItem(
            valid,
            "nonEmitted",
            0,
            JsonObject(nonEmitted.toMutableMap().apply {
                this["dieOffsets"] = JsonArray(crossUnitOffsets)
            }),
        )
        assertFailsWithMessage("outside its compilation unit") { validate(crossUnit, fixture, input) }

        val tinyScope = withPerShardValue(fixture.scope, "entities", 1)
        val tinyScopeSha = OracleArtifacts.sha256(OracleJson.canonicalBytes(tinyScope))
        val tinyInventory = rebindInventory(fixture.inventory, tinyScope, tinyScopeSha)
        val tinyInventorySha = OracleArtifacts.sha256(OracleJson.canonicalBytes(tinyInventory))
        val tinyInput = FullTreeFunctionObservations.shardInputs(
            tinyInventory,
            tinyInventorySha,
            tinyScope,
            tinyScopeSha,
        ).single()
        val overBound = observationDocument(fixture.copy(
            scope = tinyScope,
            scopeSha256 = tinyScopeSha,
            inventory = tinyInventory,
            inventoryArtifactSha256 = tinyInventorySha,
        ), tinyInput)
        assertFailsWithMessage("entity bound") {
            FullTreeFunctionObservations.validateEnvelope(
                overBound,
                tinyScope,
                tinyScopeSha,
                tinyInventory,
                tinyInventorySha,
                tinyInput,
            )
        }

        val byteBoundScope = withPerShardValue(fixture.scope, "serializedBytes", 256)
        val byteBoundScopeSha = OracleArtifacts.sha256(OracleJson.canonicalBytes(byteBoundScope))
        val byteBoundInventory = rebindInventory(fixture.inventory, byteBoundScope, byteBoundScopeSha)
        val byteBoundInventorySha = OracleArtifacts.sha256(OracleJson.canonicalBytes(byteBoundInventory))
        val byteBoundInput = FullTreeFunctionObservations.shardInputs(
            byteBoundInventory,
            byteBoundInventorySha,
            byteBoundScope,
            byteBoundScopeSha,
        ).single()
        val byteBoundFixture = fixture.copy(
            scope = byteBoundScope,
            scopeSha256 = byteBoundScopeSha,
            inventory = byteBoundInventory,
            inventoryArtifactSha256 = byteBoundInventorySha,
        )
        assertFailsWithMessage("serialized-byte bound") {
            validate(observationDocument(byteBoundFixture, byteBoundInput), byteBoundFixture, byteBoundInput)
        }
    }

    @Test
    fun `code-point order accepts BMP before astral alias and rejects UTF-16 order`() {
        val fixture = fixture()
        val input = FullTreeFunctionObservations.shardInputs(
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            fixture.scope,
            fixture.scopeSha256,
        ).single()
        val bmp = "\ue000"
        val astral = "\ud800\udc00"
        val valid = observationDocument(fixture, input, emittedAliasNames = listOf(bmp, astral))
        validate(valid, fixture, input)

        val emitted = valid.array("emitted").single() as JsonObject
        val reversed = JsonObject(emitted.toMutableMap().apply {
            this["aliases"] = JsonArray(emitted.array("aliases").reversed())
        })
        val failure = assertFailsWith<FullTreeFunctionObservationException> {
            validate(replaceArrayItem(valid, "emitted", 0, reversed), fixture, input)
        }
        assertTrue(failure.message.orEmpty().contains("canonically ordered"), failure.message)
    }

    @Test
    fun `canonical declaration selection uses historical JSON bytes rather than raw path order`() {
        val fixture = fixture(listOf("source/\n.cpp", "source/!.cpp"))
        val input = FullTreeFunctionObservations.shardInputs(
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            fixture.scope,
            fixture.scopeSha256,
        ).single()
        val document = observationDocument(fixture, input)
        val declaration = (document.array("nonEmitted").single() as JsonObject).objectValue("declaration")

        assertEquals("source/!.cpp", declaration.string("unitSourcePath"))
        validate(document, fixture, input)
    }

    @Test
    fun `forged shard inputs and post-derivation caller mutations are rejected`() {
        val fixture = fixture()
        val input = FullTreeFunctionObservations.shardInputs(
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            fixture.scope,
            fixture.scopeSha256,
        ).single()
        val valid = observationDocument(fixture, input)
        val forgedDigest = FullTreeFunctionObservationShardInput(
            input.identifier,
            "a".repeat(64),
            input.units,
        )
        assertFailsWithMessage("not authenticated") { validate(valid, fixture, forgedDigest) }

        val substitutedUnits = input.units.toMutableList().apply { removeLast() }
        val forgedUnits = FullTreeFunctionObservationShardInput(
            input.identifier,
            input.inputSha256,
            substitutedUnits,
        )
        assertFailsWithMessage("not authenticated") { validate(valid, fixture, forgedUnits) }

        val substitutedInventory = JsonObject(fixture.inventory.toMutableMap().apply {
            this["counts"] = JsonObject(fixture.inventory.objectValue("counts").toMutableMap().apply {
                this["compilationUnits"] = JsonPrimitive(3)
            })
        })
        assertFailsWithMessage("authenticated digest") {
            FullTreeFunctionObservations.validateEnvelope(
                valid,
                fixture.scope,
                fixture.scopeSha256,
                substitutedInventory,
                fixture.inventoryArtifactSha256,
                input,
            )
        }

        val mutableUnitMap = fixture.units.first().toMutableMap()
        val isolated = FullTreeFunctionObservationShardInput(
            input.identifier,
            input.inputSha256,
            listOf(JsonObject(mutableUnitMap)),
        )
        mutableUnitMap["sourcePath"] = JsonPrimitive("source/substituted.cpp")
        assertEquals(fixture.units.first().string("sourcePath"), isolated.units.single().string("sourcePath"))
    }

    @Test
    fun `Kotlin accumulator reproduces historical grouping independent of traversal order`() {
        val fixture = fixture(listOf("source/\n.cpp", "source/!.cpp"))
        val input = FullTreeFunctionObservations.shardInputs(
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            fixture.scope,
            fixture.scopeSha256,
        ).single()
        val firstUnit = fixture.units[0]
        val secondUnit = fixture.units[1]
        val firstId = firstUnit.string("id")
        val secondId = secondUnit.string("id")
        val bmp = "\ue000"
        val astral = "\ud800\udc00"
        val observations = listOf(
            FullTreeObservedSubprogram(
                unitId = firstId,
                dieOffset = 0x4uL,
                rvas = listOf(0x40uL),
                aliases = listOf(
                    observedAlias(astral, "rich:.debug_info:die=0x4:DW_AT_name@0x4", firstId),
                    observedAlias("alpha", "rich:.debug_info:die=0x4:DW_AT_linkage_name@0x4", firstId),
                ),
                declaration = declaration(firstUnit.string("sourcePath")),
                inlineWithoutEmittedRange = false,
            ),
            FullTreeObservedSubprogram(
                unitId = secondId,
                dieOffset = 0x18uL,
                rvas = listOf(0x40uL),
                aliases = listOf(
                    observedAlias(bmp, "rich:.debug_info:die=0x18:DW_AT_name@0x18", secondId),
                    observedAlias("alpha", "rich:.debug_info:die=0x18:DW_AT_linkage_name@0x18", secondId),
                ),
                declaration = declaration(secondUnit.string("sourcePath")),
                inlineWithoutEmittedRange = false,
            ),
            FullTreeObservedSubprogram(
                unitId = firstId,
                dieOffset = 0x8uL,
                rvas = emptyList(),
                aliases = listOf(
                    observedAlias("inline-alpha", "rich:.debug_info:die=0x8:DW_AT_name@0x8", firstId),
                ),
                declaration = declaration(firstUnit.string("sourcePath")),
                inlineWithoutEmittedRange = false,
            ),
            FullTreeObservedSubprogram(
                unitId = secondId,
                dieOffset = 0x30uL,
                rvas = emptyList(),
                aliases = listOf(
                    observedAlias("inline-alpha", "rich:.debug_info:die=0x30:DW_AT_name@0x30", secondId),
                ),
                declaration = declaration(secondUnit.string("sourcePath")),
                inlineWithoutEmittedRange = true,
            ),
        )

        fun accumulate(items: List<FullTreeObservedSubprogram>): JsonObject {
            val accumulator = FullTreeFunctionObservationAccumulator(input)
            repeat(6) { accumulator.recordScannedDie() }
            items.forEach(accumulator::accept)
            return accumulator.finish(
                inventoryIndexSha256 = fixture.inventory.string("indexSha256"),
                richArtifactSha256 = fixture.scope.objectValue("oracle").string("richArtifactSha256"),
                scopeSha256 = fixture.scopeSha256,
            )
        }

        val forward = accumulate(observations)
        val reverse = accumulate(observations.reversed())
        assertTrue(
            OracleJson.canonicalBytes(forward).contentEquals(OracleJson.canonicalBytes(reverse)),
            "canonical output changed with physical DIE traversal order",
        )
        validate(forward, fixture, input)
        validate(reverse, fixture, input)

        val emitted = forward.array("emitted").single() as JsonObject
        assertEquals("function-rva-0x40", emitted.string("id"))
        assertEquals(
            listOf("alpha", bmp, astral),
            emitted.array("aliases").map { (it as JsonObject).string("name") },
        )
        val nonEmitted = forward.array("nonEmitted").single() as JsonObject
        assertEquals(
            listOf("definition-no-emitted-range", "inline-no-emitted-range"),
            nonEmitted.array("reasonCodes").map { (it as JsonPrimitive).content },
        )
        assertEquals("source/!.cpp", nonEmitted.objectValue("declaration").string("unitSourcePath"))
        assertEquals(6L, forward.objectValue("counts")["scannedDies"]?.let { (it as JsonPrimitive).content.toLong() })
    }

    @Test
    fun `Kotlin accumulator fails closed on duplicate DIE bounds coverage and reuse`() {
        val fixture = fixture()
        val input = FullTreeFunctionObservations.shardInputs(
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            fixture.scope,
            fixture.scopeSha256,
        ).single()
        val unit = fixture.units.first()
        val unitId = unit.string("id")
        val observation = FullTreeObservedSubprogram(
            unitId = unitId,
            dieOffset = 0x8uL,
            rvas = emptyList(),
            aliases = listOf(observedAlias("alpha", "rich:.debug_info:die=0x8:DW_AT_name@0x8", unitId)),
            declaration = declaration(unit.string("sourcePath")),
            inlineWithoutEmittedRange = false,
        )

        val duplicate = FullTreeFunctionObservationAccumulator(input)
        duplicate.accept(observation)
        assertFailsWithMessage("same subprogram DIE") { duplicate.accept(observation) }

        val insufficient = FullTreeFunctionObservationAccumulator(input)
        repeat(2) { insufficient.recordScannedDie() }
        insufficient.accept(observation)
        assertFailsWithMessage("cannot cover") {
            insufficient.finish(
                fixture.inventory.string("indexSha256"),
                fixture.scope.objectValue("oracle").string("richArtifactSha256"),
                fixture.scopeSha256,
            )
        }

        val omittedEmittedDie = FullTreeFunctionObservationAccumulator(input)
        repeat(2) { omittedEmittedDie.recordScannedDie() }
        omittedEmittedDie.accept(observation.copy(rvas = listOf(0x40uL)))
        assertFailsWithMessage("cannot cover") {
            omittedEmittedDie.finish(
                fixture.inventory.string("indexSha256"),
                fixture.scope.objectValue("oracle").string("richArtifactSha256"),
                fixture.scopeSha256,
            )
        }

        val multipleStarts = FullTreeFunctionObservationAccumulator(input)
        assertFailsWithMessage("more than one") {
            multipleStarts.accept(observation.copy(rvas = listOf(0x40uL, 0x50uL)))
        }

        val bounded = FullTreeFunctionObservationAccumulator(
            input,
            FullTreeFunctionObservationAccumulatorLimits(maximumAliasesPerSubprogram = 1),
        )
        assertFailsWithMessage("alias population") {
            bounded.accept(observation.copy(aliases = listOf(
                observedAlias("alpha", "locator-a", unitId),
                observedAlias("beta", "locator-b", unitId),
            )))
        }

        val coalesced = FullTreeFunctionObservationAccumulator(
            input,
            FullTreeFunctionObservationAccumulatorLimits(
                maximumAliasesPerSubprogram = 1,
                maximumAliasesPerEntity = 2,
            ),
        )
        repeat(4) { coalesced.recordScannedDie() }
        coalesced.accept(observation.copy(rvas = listOf(0x40uL)))
        coalesced.accept(
            observation.copy(
                dieOffset = 0x9uL,
                rvas = listOf(0x40uL),
                aliases = listOf(observedAlias("beta", "locator-b", unitId)),
            ),
        )
        val coalescedDocument = coalesced.finish(
            fixture.inventory.string("indexSha256"),
            fixture.scope.objectValue("oracle").string("richArtifactSha256"),
            fixture.scopeSha256,
        )
        assertEquals(
            listOf("alpha", "beta"),
            (coalescedDocument.array("emitted").single() as JsonObject).array("aliases")
                .map { (it as JsonObject).string("name") },
        )
        validate(coalescedDocument, fixture, input)

        val frozen = FullTreeFunctionObservationAccumulator(input)
        frozen.recordScannedDies(3L)
        frozen.accept(observation)
        val frozenDocument = frozen.finish(
            fixture.inventory.string("indexSha256"),
            fixture.scope.objectValue("oracle").string("richArtifactSha256"),
            fixture.scopeSha256,
        )
        assertEquals(
            3L,
            (frozenDocument.objectValue("counts")["scannedDies"] as JsonPrimitive).content.toLong(),
        )
        assertFailsWithMessage("already frozen") { frozen.recordScannedDie() }

        val invalidIncrement = FullTreeFunctionObservationAccumulator(input)
        assertFailsWithMessage("increment is invalid") { invalidIncrement.recordScannedDies(0L) }

        val scannedBound = FullTreeFunctionObservationAccumulator(
            input,
            FullTreeFunctionObservationAccumulatorLimits(
                maximumScannedDies = 2L,
                maximumSubprograms = 2L,
            ),
        )
        assertFailsWithMessage("exceeds its DIE bound") { scannedBound.recordScannedDies(3L) }
    }

    private fun assertFailsWithMessage(fragment: String, block: () -> Unit) {
        val failure = assertFailsWith<FullTreeFunctionObservationException> { block() }
        assertTrue(failure.message.orEmpty().contains(fragment), failure.message)
    }

    private fun validate(
        document: JsonObject,
        fixture: Fixture,
        input: FullTreeFunctionObservationShardInput,
    ) {
        FullTreeFunctionObservations.validateEnvelope(
            document,
            fixture.scope,
            fixture.scopeSha256,
            fixture.inventory,
            fixture.inventoryArtifactSha256,
            input,
        )
    }

    private fun observationDocument(
        fixture: Fixture,
        input: FullTreeFunctionObservationShardInput,
        emittedAliasNames: List<String> = listOf("alpha"),
    ): JsonObject {
        val unitsById = fixture.units.sortedWith { left, right ->
            FULL_TREE_CODE_POINT_ORDER.compare(left.string("id"), right.string("id"))
        }
        val aliases = emittedAliasNames.map { name ->
            alias(
                name,
                listOf(
                    evidence("locator-a-$name", fixture.units[0].string("id")),
                    evidence("locator-b-$name", fixture.units[1].string("id")),
                ).sortedWith(CANONICAL_OBJECT_ORDER),
            )
        }
        val declarations = fixture.units.map { unit -> declaration(unit.string("sourcePath")) }
            .sortedWith(CANONICAL_OBJECT_ORDER)
        val nonEmittedAliases = listOf(
            alias(
                "inline-alpha",
                listOf(
                    evidence("inline-a", fixture.units[0].string("id")),
                    evidence("inline-b", fixture.units[1].string("id")),
                ).sortedWith(CANONICAL_OBJECT_ORDER),
            ),
        )
        val nonEmittedDeclaration = declarations.minWith(CANONICAL_OBJECT_ORDER)
        val nonEmittedDieOffsets = fixture.units.mapIndexed { index, unit ->
            dieOffset(unit.string("id"), if (index == 0) "0x8" else "0x30")
        }.sortedWith { left, right ->
            val unit = FULL_TREE_CODE_POINT_ORDER.compare(left.string("unitId"), right.string("unitId"))
            if (unit != 0) unit else {
                left.string("dieOffset").removePrefix("0x").toULong(16)
                    .compareTo(right.string("dieOffset").removePrefix("0x").toULong(16))
            }
        }
        val nonEmittedId = nonEmittedId("shard-a", nonEmittedAliases, nonEmittedDeclaration)
        return JsonObject(
            mapOf(
                "counts" to JsonObject(
                    mapOf(
                        "emittedRvas" to JsonPrimitive(1),
                        "nonEmitted" to JsonPrimitive(1),
                        "nonEmittedDies" to JsonPrimitive(2),
                        "scannedDies" to JsonPrimitive(4),
                        "units" to JsonPrimitive(2),
                    ),
                ),
                "emitted" to JsonArray(
                    listOf(
                        JsonObject(
                            mapOf(
                                "aliases" to JsonArray(aliases),
                                "declarations" to JsonArray(declarations),
                                "id" to JsonPrimitive("function-rva-0x10"),
                                "ownerUnitIds" to JsonArray(
                                    unitsById.map { JsonPrimitive(it.string("id")) },
                                ),
                                "rva" to JsonPrimitive("0x10"),
                            ),
                        ),
                    ),
                ),
                "nonEmitted" to JsonArray(
                    listOf(
                        JsonObject(
                            mapOf(
                                "aliases" to JsonArray(nonEmittedAliases),
                                "declaration" to nonEmittedDeclaration,
                                "dieOffsets" to JsonArray(
                                    nonEmittedDieOffsets,
                                ),
                                "id" to JsonPrimitive(nonEmittedId),
                                "reasonCodes" to JsonArray(
                                    listOf(
                                        JsonPrimitive("definition-no-emitted-range"),
                                        JsonPrimitive("inline-no-emitted-range"),
                                    ),
                                ),
                                "unitIds" to JsonArray(
                                    unitsById.map { JsonPrimitive(it.string("id")) },
                                ),
                            ),
                        ),
                    ),
                ),
                "oracle" to JsonObject(
                    mapOf(
                        "configurationSha256" to JsonPrimitive(FullTreeFunctionObservations.configurationSha256),
                        "inventoryIndexSha256" to fixture.inventory["indexSha256"]!!,
                        "richArtifactSha256" to fixture.scope.objectValue("oracle")["richArtifactSha256"]!!,
                        "scopeSha256" to JsonPrimitive(fixture.scopeSha256),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "shard" to JsonObject(
                    mapOf(
                        "id" to JsonPrimitive(input.identifier),
                        "inputSha256" to JsonPrimitive(input.inputSha256),
                    ),
                ),
            ),
        )
    }

    private fun fixture(
        sourcePaths: List<String> = listOf("source/a.cpp", "source/b.cpp"),
    ): Fixture {
        val richSha = "3".repeat(64)
        val scope = JsonObject(
            mapOf(
                "bounds" to JsonObject(
                    mapOf(
                        "perShard" to bounds(compilationUnits = 10, entities = 100, serializedBytes = 1_000_000),
                        "wholeRun" to bounds(compilationUnits = 20, entities = 200, serializedBytes = 2_000_000),
                    ),
                ),
                "oracle" to JsonObject(
                    mapOf(
                        "artifactManifestSha256" to JsonPrimitive("2".repeat(64)),
                        "id" to JsonPrimitive("fixture"),
                        "richArtifactSha256" to JsonPrimitive(richSha),
                        "sourceLockSha256" to JsonPrimitive("1".repeat(64)),
                        "strippedArtifactSha256" to JsonPrimitive("4".repeat(64)),
                    ),
                ),
                "pathPolicy" to JsonObject(
                    mapOf(
                        "prefixMaps" to JsonArray(
                            listOf(
                                JsonObject(
                                    mapOf(
                                        "from" to JsonPrimitive("/build/"),
                                        "to" to JsonPrimitive("source/"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                "populations" to JsonObject(
                    mapOf(
                        "excluded" to JsonPrimitive(
                            "entities matching one reviewed exclusion record and no scored record",
                        ),
                        "exclusions" to JsonArray(emptyList()),
                        "scored" to JsonPrimitive(
                            "emitted ELF entities with independently source-aligned DWARF ownership",
                        ),
                        "unobservable" to JsonPrimitive(
                            "authenticated source or DWARF entities without an emitted address",
                        ),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "sharding" to JsonObject(
                    mapOf(
                        "duplicateOwnership" to JsonPrimitive(
                            "lowest-source-aligned-unit-id; aliases remain evidence on one emitted RVA",
                        ),
                        "mergeOrdering" to JsonPrimitive(
                            "shard-id,source-path,unit-id,entity-kind,entity-id",
                        ),
                        "rules" to JsonArray(
                            listOf(
                                JsonObject(
                                    mapOf(
                                        "componentDepth" to JsonPrimitive(0),
                                        "pathPrefix" to JsonPrimitive("source/"),
                                        "shardPrefix" to JsonPrimitive("shard-a"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )
        val scopeSha = OracleArtifacts.sha256(OracleJson.canonicalBytes(scope))
        require(sourcePaths.size == 2)
        val units = sourcePaths.mapIndexed { index, sourcePath ->
            unit(sourcePath, if (index == 0) "0x0" else "0x10")
        }
        val inventory = inventory(scope, scopeSha, units)
        val inventoryArtifactSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(inventory))
        return Fixture(scope, scopeSha, inventory, inventoryArtifactSha256, units)
    }

    private fun unit(sourcePath: String, dwarfOffset: String): JsonObject = JsonObject(
        mapOf(
            "addressSize" to JsonPrimitive(8),
            "dwarfOffset" to JsonPrimitive(dwarfOffset),
            "dwarfVersion" to JsonPrimitive(5),
            "id" to JsonPrimitive("cu-${sha256(sourcePath.toByteArray()).take(32)}"),
            "language" to JsonPrimitive(33),
            "producerSha256" to JsonNull,
            "rawPathSha256" to JsonPrimitive(sha256("/build/$sourcePath".toByteArray())),
            "shardId" to JsonPrimitive("shard-a"),
            "sourceKind" to JsonPrimitive("handwritten"),
            "sourcePath" to JsonPrimitive(sourcePath),
        ),
    )

    private fun inventory(scope: JsonObject, scopeSha: String, units: List<JsonObject>): JsonObject {
        val indexDigest = MessageDigest.getInstance("SHA-256")
        indexDigest.update("full-tree-index-v1\u0000".toByteArray(StandardCharsets.UTF_8))
        units.forEach { unit ->
            indexDigest.update(MessageDigest.getInstance("SHA-256").digest(OracleJson.canonicalBytes(unit)))
        }
        val scopeOracle = scope.objectValue("oracle")
        return JsonObject(
            mapOf(
                "counts" to JsonObject(
                    mapOf(
                        "compilationUnits" to JsonPrimitive(units.size),
                        "generatedUnits" to JsonPrimitive(0),
                        "handwrittenUnits" to JsonPrimitive(units.size),
                        "shards" to JsonPrimitive(1),
                    ),
                ),
                "indexSha256" to JsonPrimitive(indexDigest.digest().hex()),
                "oracle" to JsonObject(
                    mapOf(
                        "artifactManifestSha256" to scopeOracle["artifactManifestSha256"]!!,
                        "id" to scopeOracle["id"]!!,
                        "richArtifactSha256" to scopeOracle["richArtifactSha256"]!!,
                        "scopeSha256" to JsonPrimitive(scopeSha),
                        "sourceLockSha256" to scopeOracle["sourceLockSha256"]!!,
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(
                    listOf(
                        JsonObject(
                            mapOf(
                                "id" to JsonPrimitive("shard-a"),
                                "unitIds" to JsonArray(
                                    units.map { it.string("id") }
                                        .sortedWith(FULL_TREE_CODE_POINT_ORDER)
                                        .map(::JsonPrimitive),
                                ),
                            ),
                        ),
                    ),
                ),
                "units" to JsonArray(units),
            ),
        )
    }

    private fun rebindInventory(inventory: JsonObject, scope: JsonObject, scopeSha: String): JsonObject =
        JsonObject(inventory.toMutableMap().apply {
            val scopeOracle = scope.objectValue("oracle")
            this["oracle"] = JsonObject(
                mapOf(
                    "artifactManifestSha256" to scopeOracle["artifactManifestSha256"]!!,
                    "id" to scopeOracle["id"]!!,
                    "richArtifactSha256" to scopeOracle["richArtifactSha256"]!!,
                    "scopeSha256" to JsonPrimitive(scopeSha),
                    "sourceLockSha256" to scopeOracle["sourceLockSha256"]!!,
                ),
            )
        })

    private fun withPerShardValue(scope: JsonObject, name: String, value: Long): JsonObject {
        val bounds = scope.objectValue("bounds")
        val perShard = bounds.objectValue("perShard")
        return JsonObject(scope.toMutableMap().apply {
            this["bounds"] = JsonObject(bounds.toMutableMap().apply {
                this["perShard"] = JsonObject(perShard.toMutableMap().apply {
                    this[name] = JsonPrimitive(value)
                })
            })
        })
    }

    private fun bounds(compilationUnits: Long, entities: Long, serializedBytes: Long): JsonObject = JsonObject(
        mapOf(
            "compilationUnits" to JsonPrimitive(compilationUnits),
            "cpuSeconds" to JsonPrimitive(100),
            "entities" to JsonPrimitive(entities),
            "maximumResidentBytes" to JsonPrimitive(100_000_000),
            "serializedBytes" to JsonPrimitive(serializedBytes),
            "wallClockSeconds" to JsonPrimitive(100),
        ),
    )

    private fun alias(name: String, evidence: List<JsonObject>): JsonObject = JsonObject(
        mapOf("evidence" to JsonArray(evidence), "name" to JsonPrimitive(name)),
    )

    private fun evidence(locator: String, unitId: String): JsonObject = JsonObject(
        mapOf(
            "kind" to JsonPrimitive("dwarf-subprogram"),
            "locator" to JsonPrimitive(locator),
            "unitId" to JsonPrimitive(unitId),
        ),
    )

    private fun observedAlias(
        name: String,
        locator: String,
        unitId: String,
    ): FullTreeObservedFunctionAlias = FullTreeObservedFunctionAlias(
        name,
        listOf(FullTreeObservedFunctionEvidence(locator, unitId)),
    )

    private fun declaration(unitSourcePath: String): JsonObject = JsonObject(
        mapOf(
            "column" to JsonPrimitive(3),
            "externalPathSha256" to JsonNull,
            "fileIndex" to JsonPrimitive(1),
            "line" to JsonPrimitive(2),
            "sourcePath" to JsonPrimitive("source/include/header.h"),
            "unitSourcePath" to JsonPrimitive(unitSourcePath),
        ),
    )

    private fun dieOffset(unitId: String, offset: String): JsonObject = JsonObject(
        mapOf("dieOffset" to JsonPrimitive(offset), "unitId" to JsonPrimitive(unitId)),
    )

    private fun nonEmittedId(
        shardId: String,
        aliases: List<JsonObject>,
        declaration: JsonObject,
    ): String {
        val identity = sha256(
            OracleJson.canonicalBytes(
                JsonObject(
                    mapOf(
                        "aliasNames" to JsonArray(aliases.map { JsonPrimitive(it.string("name")) }),
                        "declaration" to JsonObject(declaration.filterKeys { it != "unitSourcePath" }),
                    ),
                ),
            ),
        ).take(32)
        return "non-emitted-observation-${sha256("$shardId:$identity".toByteArray()).take(32)}"
    }

    private fun replaceArrayItem(
        document: JsonObject,
        field: String,
        index: Int,
        replacement: JsonObject,
    ): JsonObject = JsonObject(document.toMutableMap().apply {
        val items = document.array(field).toMutableList()
        items[index] = replacement
        this[field] = JsonArray(items)
    })

    private fun JsonObject.objectValue(name: String): JsonObject = this[name] as JsonObject
    private fun JsonObject.array(name: String): JsonArray = this[name] as JsonArray
    private fun JsonObject.string(name: String): String = (this[name] as JsonPrimitive).content

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).hex()
    private fun ByteArray.hex(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    private data class Fixture(
        val scope: JsonObject,
        val scopeSha256: String,
        val inventory: JsonObject,
        val inventoryArtifactSha256: String,
        val units: List<JsonObject>,
    )

    private companion object {
        val CANONICAL_OBJECT_ORDER = Comparator<JsonObject> { left, right ->
            compareUnsigned(OracleJson.canonicalBytes(left), OracleJson.canonicalBytes(right))
        }

        fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
            val common = minOf(left.size, right.size)
            for (index in 0 until common) {
                val result = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
                if (result != 0) return result
            }
            return left.size.compareTo(right.size)
        }
    }
}
