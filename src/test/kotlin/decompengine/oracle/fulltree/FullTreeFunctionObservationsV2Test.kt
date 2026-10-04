package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemaException
import decompengine.oracle.core.OracleSchemas
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class FullTreeFunctionObservationsV2Test {
    @Test
    fun `v2 schema policy digest is pinned and compact fixture output stays canonical`() {
        assertEquals("c068ed200c8493acbe830ba4e4d8390e8a30499b3d866c43646ff802ff645d89", OracleSchemas.identity(
            FullTreeFunctionObservationsV2.SCHEMA_NAME,
        ).sha256)
        assertEquals("0a2942329a1e483216cf428590d338128882cec2b91d9a8957589874073d1fe9", FullTreeFunctionObservationsV2.configurationSha256)
        assertEquals("dffe8bad65e82b46150cd1f5368925ae10709fd01adf905d27f1e8784634a86e", FullTreeFunctionObservations.configurationSha256)

        val unit = JsonObject(
            mapOf(
                "id" to JsonPrimitive("cu-${"1".repeat(32)}"),
                "sourcePath" to JsonPrimitive("source/fixture.cpp"),
            ),
        )
        val shard = FullTreeFunctionObservationShardInput(
            identifier = "fixture-shard",
            inputSha256 = "a".repeat(64),
            units = listOf(unit),
        )
        val physical = FullTreeSourcePhysicalDie(
            richArtifactSha256 = "c".repeat(64),
            unitId = unit.controlString("id"),
            section = ".debug_info",
            compilationUnitOffset = "0x0",
            dieOffset = "0x10",
        )
        val sourceRow = fact(
            physical,
            FullTreeSourceEntityKind.UNRESOLVED,
            FullTreeIdentityObservability.UNOBSERVABLE,
            FullTreeDenominatorDisposition.UNKNOWN,
            fields = null,
            reasons = listOf("unsupported-source-identity"),
        )
        val reconciliation = FullTreeFunctionObservationV2AnchorIndex(1L, 4096L).reconciliation()
        val accumulator = FullTreeFunctionObservationAccumulatorV2(shard)
        accumulator.recordScannedDies(1L)
        accumulator.acceptSourceEntity(sourceRow)
        val actual = FullTreeFunctionObservationsV2.canonicalEnvelopeBytes(
            accumulator.finish(
                inventoryIndexSha256 = "b".repeat(64),
                richArtifactSha256 = "c".repeat(64),
                scopeSha256 = "d".repeat(64),
                reconciliation = reconciliation,
            ),
        )
        val expected = requireNotNull(
            javaClass.getResourceAsStream("/oracle/full-tree-function-observations-v2/fixture-only-output.json"),
        ).use { it.readAllBytes() }
        assertContentEquals(expected, actual)
        OracleSchemas.validate(FullTreeFunctionObservationsV2.SCHEMA_NAME, OracleJson.parseCanonical(actual))
    }

    @Test
    fun `in-memory and SQLite v2 sinks preserve full-run collision census without changing RVA denominators`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("control"))
            val scope = fixture.authenticatedScope()
            val inventory = parseControlObject(fixture.inventory)
            val inventorySha256 = fixtureSha256(fixture.inventory)
            val richSha256 = scope.document.controlObject("oracle").controlString("richArtifactSha256")
            val inputs = FullTreeFunctionObservations.shardInputs(
                inventory,
                inventorySha256,
                scope.document,
                scope.sha256,
            ).sortedBy { it.identifier }
            assertEquals(2, inputs.size)
            val firstShard = inputs[0]
            val secondShard = inputs[1]
            val firstUnit = firstShard.units.single()
            val secondUnit = secondShard.units.single()

            fun physical(unit: JsonObject, dieOffset: String) = FullTreeSourcePhysicalDie(
                richArtifactSha256 = richSha256,
                unitId = unit.controlString("id"),
                section = ".debug_info",
                compilationUnitOffset = unit.controlString("dwarfOffset"),
                dieOffset = dieOffset,
            )
            fun absoluteOffset(unit: JsonObject, withinCu: ULong): String =
                "0x${(unit.controlString("dwarfOffset").removePrefix("0x").toULong(16) + withinCu).toString(16)}"

            fun anchorFields(
                sourceName: String,
                sourcePath: String = "source/include/shared.h",
                line: Long = 42L,
                fileIndex: Long? = 1L,
                column: Long? = null,
                signature: List<String> = listOf("void ()"),
                templateActuals: List<String>? = null,
                inlineCallee: String? = null,
                inlineOwner: String? = null,
                authenticatedSourceRevision: String? = null,
                callFile: String? = null,
                callLine: Long? = null,
                callColumn: Long? = null,
                inlinePath: List<String>? = null,
            ) = FullTreeSourceAnchorFields(
                sourcePath = sourcePath,
                declarationFileIndex = fileIndex,
                declarationLine = line,
                declarationColumn = column,
                language = 33L,
                lexicalContext = listOf("sample"),
                sourceName = sourceName,
                signature = signature,
                templateActualArguments = templateActuals,
                inlineCalleeAnchorCandidateId = inlineCallee,
                inlineOwnerAnchorCandidateId = inlineOwner,
                inlineCallFile = callFile,
                inlineCallLine = callLine,
                inlineCallColumn = callColumn,
                inlinePathAnchorCandidateIds = inlinePath,
                authenticatedSourceRevision = authenticatedSourceRevision,
            )

            val declarationFieldsA = anchorFields("shared_declaration", fileIndex = 1L, column = 4L)
            val declarationFieldsB = anchorFields("shared_declaration", fileIndex = 17L, column = null)
            val declarationFieldsC = anchorFields("shared_declaration", fileIndex = 22L, column = 19L)
            assertEquals(
                declarationFieldsA.candidateId(FullTreeSourceAnchorKind.DECLARATION_ONLY),
                declarationFieldsC.candidateId(FullTreeSourceAnchorKind.DECLARATION_ONLY),
            )
            val declarationA = fact(
                physical(firstUnit, "0x100"),
                FullTreeSourceEntityKind.DECLARATION_ONLY,
                FullTreeIdentityObservability.OBSERVABLE,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                declarationFieldsA,
            )
            val declarationB = fact(
                physical(secondUnit, "0x100"),
                FullTreeSourceEntityKind.DECLARATION_ONLY,
                FullTreeIdentityObservability.OBSERVABLE,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                declarationFieldsB,
            )
            val declarationA2 = fact(
                physical(firstUnit, absoluteOffset(firstUnit, 0x20UL)),
                FullTreeSourceEntityKind.DECLARATION_ONLY,
                FullTreeIdentityObservability.OBSERVABLE,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                declarationFieldsC,
            )
            assertEquals(declarationA.semanticAnchorCandidateId, declarationB.semanticAnchorCandidateId)
            assertNotEquals(
                declarationA.physicalDie.sourceEntityId(declarationA.kind),
                declarationB.physicalDie.sourceEntityId(declarationB.kind),
            )
            assertEquals(4L, declarationA.semanticAnchorFields?.declarationColumn)
            assertEquals(null, declarationB.semanticAnchorFields?.declarationColumn)

            val noRange = fact(
                physical(firstUnit, "0x110"),
                FullTreeSourceEntityKind.NO_RANGE_DEFINITION,
                FullTreeIdentityObservability.UNKNOWN,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                anchorFields("unranged_definition", line = 70L),
                reasons = listOf("unknown-source-range"),
            )
            val unresolved = fact(
                physical(firstUnit, "0x120"),
                FullTreeSourceEntityKind.UNRESOLVED,
                FullTreeIdentityObservability.UNOBSERVABLE,
                FullTreeDenominatorDisposition.UNKNOWN,
                fields = null,
                reasons = listOf("unsupported-source-identity"),
            )

            val templateIntFields = anchorFields(
                sourceName = "value_template<int>",
                line = 88L,
                signature = listOf("void (int)"),
                templateActuals = listOf("type:int"),
            )
            val templateLongFields = anchorFields(
                sourceName = "value_template<long>",
                line = 88L,
                signature = listOf("void (long)"),
                templateActuals = listOf("type:long"),
            )
            assertEquals(null, templateIntFields.templatePatternAnchorCandidateId)
            assertEquals(null, templateLongFields.templatePatternAnchorCandidateId)
            val templateIntPhysical = physical(firstUnit, "0x130")
            val templateIntToOtherCu = FullTreeSourceIdentityEdge(
                kind = FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT,
                source = templateIntPhysical,
                target = physical(secondUnit, "0x80"),
                referenceForm = "0x10",
                rawReference = "0x80",
                state = FullTreeSourceIdentityEdgeState.RESOLVED,
                reasonCode = null,
            )
            val templateInt = fact(
                templateIntPhysical,
                FullTreeSourceEntityKind.TEMPLATE_INSTANCE,
                FullTreeIdentityObservability.UNKNOWN,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                templateIntFields,
                reasons = listOf("unknown-template-pattern-reference"),
                edges = listOf(templateIntToOtherCu),
            )
            val templateLong = fact(
                physical(firstUnit, "0x140"),
                FullTreeSourceEntityKind.TEMPLATE_INSTANCE,
                FullTreeIdentityObservability.UNKNOWN,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                templateLongFields,
                reasons = listOf("unknown-template-pattern-reference"),
                edges = listOf(
                    FullTreeSourceIdentityEdge(
                        kind = FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT,
                        source = physical(firstUnit, "0x140"),
                        target = null,
                        referenceForm = "0x10",
                        rawReference = "0x80",
                        state = FullTreeSourceIdentityEdgeState.MISSING_TARGET,
                        reasonCode = "missing-reference-target",
                    ),
                ),
            )
            assertNotEquals(templateInt.semanticAnchorCandidateId, templateLong.semanticAnchorCandidateId)
            assertEquals(null, templateInt.linkedEmittedRva)
            assertEquals(null, templateLong.linkedEmittedRva)

            val ownerFields = anchorFields("inline_owner", line = 105L)
            val ownerCandidate = requireNotNull(ownerFields.candidateId(FullTreeSourceAnchorKind.SOURCE_DEFINITION))
            val calleeFields = anchorFields("inline_callee", line = 106L)
            val calleeCandidate = requireNotNull(calleeFields.candidateId(FullTreeSourceAnchorKind.SOURCE_DEFINITION))
            val ownerA = physical(firstUnit, "0x200")
            val ownerB = physical(secondUnit, "0x200")
            val callee = physical(firstUnit, "0x210")
            val inlinePhysical = physical(firstUnit, "0x150")
            val inlineFields = anchorFields(
                sourceName = "inline_call",
                line = 107L,
                inlineCallee = calleeCandidate,
                inlineOwner = ownerCandidate,
                callFile = "source/caller.cpp",
                callLine = 108L,
                callColumn = 9L,
                inlinePath = emptyList(),
            )
            val inlineFact = fact(
                inlinePhysical,
                FullTreeSourceEntityKind.INLINE_INSTANCE,
                FullTreeIdentityObservability.OBSERVABLE,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                inlineFields,
                edges = listOf(
                    FullTreeSourceIdentityEdge(
                        kind = FullTreeSourceIdentityEdgeKind.INLINE_OWNER,
                        source = inlinePhysical,
                        target = ownerB,
                        referenceForm = "0x10",
                        rawReference = "0x200",
                        state = FullTreeSourceIdentityEdgeState.RESOLVED,
                        reasonCode = null,
                    ),
                ),
            )
            val inlineOwnerClaimIds = listOf(
                ownerA.sourceEntityId(FullTreeSourceAnchorKind.SOURCE_DEFINITION),
                ownerB.sourceEntityId(FullTreeSourceAnchorKind.SOURCE_DEFINITION),
            ).sorted()
            val locallyMarkedInlineFact = inlineFact.copy(
                identityObservability = FullTreeIdentityObservability.AMBIGUOUS,
                candidateCollisionSourceEntityIds = inlineOwnerClaimIds,
                reasonCodes = (inlineFact.reasonCodes + "ambiguous-related-source-anchor").distinct().sorted(),
            )

            val shardFacts = mapOf(
                firstShard.identifier to listOf(declarationA, declarationA2, noRange, unresolved, templateInt, templateLong, locallyMarkedInlineFact),
                secondShard.identifier to listOf(declarationB),
            )
            val anchorIndex = FullTreeFunctionObservationV2AnchorIndex(
                maximumClaims = 64L,
                maximumRetainedBytes = 1024L * 1024L,
            )
            val allAnchorClaims = mutableListOf<Pair<String, String>>()
            fun admitAnchor(candidate: String, physicalClaim: String) {
                anchorIndex.accept(candidate, physicalClaim)
                allAnchorClaims += candidate to physicalClaim
            }
            shardFacts.values.flatten().forEach { row ->
                row.semanticAnchorCandidateId?.let { admitAnchor(it, row.sourceEntityId) }
            }
            // These are ordinary emitted definitions, not source-census rows. They still
            // participate in global anchor collision reconciliation and can make an inline owner
            // candidate ambiguous without adding denominator records.
            admitAnchor(ownerCandidate, ownerA.sourceEntityId(FullTreeSourceAnchorKind.SOURCE_DEFINITION))
            admitAnchor(ownerCandidate, ownerB.sourceEntityId(FullTreeSourceAnchorKind.SOURCE_DEFINITION))
            admitAnchor(calleeCandidate, callee.sourceEntityId(FullTreeSourceAnchorKind.SOURCE_DEFINITION))
            val inlineCandidate = requireNotNull(inlineFields.candidateId(FullTreeSourceAnchorKind.INLINE_INSTANCE))
            admitAnchor(
                inlineCandidate,
                physical(secondUnit, "0x220").sourceEntityId(FullTreeSourceAnchorKind.SOURCE_DEFINITION),
            )
            val reconciliation = anchorIndex.reconciliation()
            val canonicalClaims = JsonArray(allAnchorClaims.sortedWith(
                compareBy<Pair<String, String>> { it.first }.thenBy { it.second },
            ).map { (candidate, physicalClaim) ->
                JsonObject(mapOf(
                    "candidateId" to JsonPrimitive(candidate),
                    "physicalClaimId" to JsonPrimitive(physicalClaim),
                ))
            })
            assertEquals(
                OracleArtifacts.sha256(OracleJson.canonicalBytes(canonicalClaims)),
                reconciliation.populationSha256,
            )
            assertEquals(11L, reconciliation.claimCount)
            assertEquals(8L, reconciliation.candidateCount)
            assertEquals(3L, reconciliation.collisionCandidateCount)
            val reconciledByShard = shardFacts.mapValues { (_, rows) -> reconcileObservationV2Facts(rows, reconciliation) }

            val observationLimits = FullTreeFunctionObservationAccumulatorLimits(
                maximumEntities = 100,
                maximumEmittedRvas = 100,
                maximumNonEmittedGroups = 100,
                maximumRetainedBytes = 8L * 1024L * 1024L,
            )
            val bindings = FullTreeFunctionObservationBindings(
                inventoryIndexSha256 = inventory.controlString("indexSha256"),
                richArtifactSha256 = richSha256,
                scopeSha256 = scope.sha256,
            )
            val outputs = LinkedHashMap<String, JsonObject>()
            inputs.forEach { shard ->
                val unit = shard.units.single()
                val observations = listOf("a", "b").mapIndexed { index, suffix ->
                    val dieOffset = 0x400UL + index.toULong()
                    val alias = observationAlias("function_${shard.identifier}_$suffix", unit, dieOffset)
                    FullTreeObservedSubprogram(
                        unitId = unit.controlString("id"),
                        dieOffset = dieOffset,
                        rvas = listOf(0x40UL),
                        aliases = listOf(alias),
                        declaration = observationDeclaration(unit.controlString("sourcePath")),
                        inlineWithoutEmittedRange = false,
                    )
                }.reversed()
                val memory = FullTreeFunctionObservationAccumulatorV2(
                    shard,
                    FullTreeFunctionObservationV2AccumulatorLimits(
                        observations = observationLimits,
                        maximumOutputBytes = 8L * 1024L * 1024L,
                        maximumRetainedBytes = 8L * 1024L * 1024L,
                    ),
                )
                if (shard.identifier == firstShard.identifier) {
                    assertFailsWith<FullTreeFunctionObservationV2Exception> {
                        memory.acceptSourceEntity(declarationB)
                    }
                    FullTreeFunctionObservationSqlite.openV2(
                        root,
                        shard,
                        FullTreeFunctionObservationSqliteLimits(
                            maximumDatabaseBytes = 4L * 1024L * 1024L,
                            maximumOutputBytes = 8L * 1024L * 1024L,
                            observations = observationLimits,
                            maximumCacheBytes = 64 * 1024,
                            databaseCheckpointRows = 2,
                            checkpoint = FullTreeFunctionObservationSqliteCheckpoint {},
                        ),
                    ).use { outOfShardSink ->
                        assertFailsWith<FullTreeFunctionObservationSqliteException> {
                            outOfShardSink.acceptSourceEntity(declarationB)
                        }
                    }
                }
                memory.recordScannedDies(3L)
                observations.forEach(memory::accept)
                reconciledByShard.getValue(shard.identifier).asReversed().forEach(memory::acceptSourceEntity)
                val memoryBytes = FullTreeFunctionObservationsV2.canonicalEnvelopeBytes(
                    memory.finish(
                        inventoryIndexSha256 = bindings.inventoryIndexSha256,
                        richArtifactSha256 = bindings.richArtifactSha256,
                        scopeSha256 = bindings.scopeSha256,
                        reconciliation = reconciliation,
                    ),
                )

                val sqliteOutput = ByteArrayOutputStream()
                val sqliteLimits = FullTreeFunctionObservationSqliteLimits(
                    maximumDatabaseBytes = 4L * 1024L * 1024L,
                    maximumOutputBytes = 8L * 1024L * 1024L,
                    observations = observationLimits,
                    maximumCacheBytes = 64 * 1024,
                    databaseCheckpointRows = 2,
                    checkpoint = FullTreeFunctionObservationSqliteCheckpoint {},
                )
                val sqliteReceipt = FullTreeFunctionObservationSqlite.openV2(root, shard, sqliteLimits).use { sink ->
                    sink.recordScannedDies(3L)
                    observations.forEach(sink::accept)
                    reconciledByShard.getValue(shard.identifier).forEach(sink::acceptSourceEntity)
                    sink.finishToV2(sqliteOutput, bindings, reconciliation)
                }
                assertContentEquals(memoryBytes, sqliteOutput.toByteArray())
                assertEquals(memoryBytes.size.toLong(), sqliteReceipt.outputBytes)
                assertEquals(1L, sqliteReceipt.emitted)
                assertEquals(reconciledByShard.getValue(shard.identifier).size.toLong(), sqliteReceipt.sourceEntities)
                assertEquals(OracleArtifacts.sha256(memoryBytes), sqliteReceipt.outputSha256)

                if (shard.identifier == firstShard.identifier) {
                    val overV2WireLimit = sqliteLimits.copy(
                        maximumOutputBytes = FullTreeFunctionObservationsV2.MAXIMUM_CANONICAL_BYTES + 1L,
                    )
                    assertFailsWith<FullTreeFunctionObservationSqliteException> {
                        FullTreeFunctionObservationSqlite.openV2(root, shard, overV2WireLimit)
                    }
                    assertFailsWith<FullTreeFunctionObservationSqliteException> {
                        FullTreeFunctionObservationSqliteV2.open(root, shard, overV2WireLimit)
                    }

                    val requiredScratchBytes = Math.addExact(
                        sqliteReceipt.outputBytes,
                        sqliteReceipt.databaseHighWaterBytes,
                    )
                    val tightScratchBytes = requiredScratchBytes - 1L
                    assertTrue(tightScratchBytes >= FULL_TREE_FUNCTION_OBSERVATION_SQLITE_PAGE_BYTES)
                    assertFailsWith<FullTreeFunctionObservationSqliteException> {
                        FullTreeFunctionObservationSqlite.openV2(
                            root,
                            shard,
                            FullTreeFunctionObservationSqliteLimits(
                                maximumDatabaseBytes = minOf(4L * 1024L * 1024L, tightScratchBytes),
                                maximumOutputBytes = 8L * 1024L * 1024L,
                                observations = observationLimits,
                                maximumCacheBytes = 64 * 1024,
                                databaseCheckpointRows = 1,
                                checkpoint = FullTreeFunctionObservationSqliteCheckpoint {},
                                maximumScratchBytes = tightScratchBytes,
                            ),
                        ).use { boundedSink ->
                            boundedSink.recordScannedDies(3L)
                            observations.forEach(boundedSink::accept)
                            reconciledByShard.getValue(shard.identifier).forEach(boundedSink::acceptSourceEntity)
                            boundedSink.finishToV2(
                                ByteArrayOutputStream(),
                                bindings,
                                reconciliation,
                            )
                        }
                    }
                }

                val document = OracleJson.parseCanonical(memoryBytes) as JsonObject
                OracleSchemas.validate(FullTreeFunctionObservationsV2.SCHEMA_NAME, document)
                assertFailsWith<OracleSchemaException> {
                    OracleSchemas.validate(
                        FullTreeFunctionObservationsV2.SCHEMA_NAME,
                        JsonObject(document.toMutableMap().apply { this["extra"] = JsonPrimitive(true) }),
                    )
                }
                FullTreeFunctionObservationsV2.validateEnvelope(
                    document,
                    scope,
                    inventory,
                    inventorySha256,
                    shard,
                    reconciliation,
                )
                assertEquals(1, document.getValue("emitted").jsonArray.size)
                assertEquals(1L, document.getValue("counts").jsonObject.getValue("emittedRvas").jsonPrimitive.long)
                outputs[shard.identifier] = document
            }

            val allRows = outputs.values.flatMap { it.getValue("sourceEntities").jsonArray }
                .map { FullTreeSourceEntityFact.fromCanonicalJson(it.jsonObject) }
            assertEquals(8, allRows.size)
            assertEquals(3, allRows.count { it.kind == FullTreeSourceEntityKind.DECLARATION_ONLY })
            assertEquals(1, allRows.count { it.kind == FullTreeSourceEntityKind.NO_RANGE_DEFINITION })
            assertEquals(0, allRows.count { it.kind == FullTreeSourceEntityKind.TEMPLATE_PATTERN })
            assertEquals(2, allRows.count { it.kind == FullTreeSourceEntityKind.TEMPLATE_INSTANCE })
            assertEquals(1, allRows.count { it.kind == FullTreeSourceEntityKind.INLINE_INSTANCE })
            assertEquals(1, allRows.count { it.kind == FullTreeSourceEntityKind.UNRESOLVED })
            assertEquals(4, allRows.count { it.identityObservability == FullTreeIdentityObservability.AMBIGUOUS })
            assertEquals(3, allRows.count { it.identityObservability == FullTreeIdentityObservability.UNKNOWN })
            assertEquals(1, allRows.count { it.identityObservability == FullTreeIdentityObservability.UNOBSERVABLE })
            assertTrue(allRows.filter { it.kind == FullTreeSourceEntityKind.TEMPLATE_INSTANCE }.all {
                it.semanticAnchorFields?.templatePatternAnchorCandidateId == null &&
                    "unknown-template-pattern-reference" in it.reasonCodes && it.resolvedSemanticIdentityId == null
            })
            val declarationRows = allRows.filter { it.kind == FullTreeSourceEntityKind.DECLARATION_ONLY }
            assertTrue(declarationRows.all {
                it.identityObservability == FullTreeIdentityObservability.AMBIGUOUS &&
                    it.candidateCollisionSourceEntityIds.size == 3 &&
                    "duplicate-source-anchor-unproven" in it.reasonCodes
            })
            val reconciledInline = allRows.single { it.kind == FullTreeSourceEntityKind.INLINE_INSTANCE }
            assertTrue(reconciledInline.identityObservability == FullTreeIdentityObservability.AMBIGUOUS)
            assertEquals(4, reconciledInline.candidateCollisionSourceEntityIds.size)
            assertTrue("duplicate-source-anchor-unproven" in reconciledInline.reasonCodes)
            assertTrue("ambiguous-related-source-anchor" !in reconciledInline.reasonCodes)
            assertTrue(allRows.filter { it.kind == FullTreeSourceEntityKind.TEMPLATE_INSTANCE }.any { row ->
                row.edges.any { it.state == FullTreeSourceIdentityEdgeState.RESOLVED && it.source.unitId != it.target?.unitId }
            })
            assertEquals(7, allRows.count { it.denominatorDisposition == FullTreeDenominatorDisposition.NON_SCOREABLE })
            assertEquals(1, allRows.count { it.denominatorDisposition == FullTreeDenominatorDisposition.UNKNOWN })
            assertEquals(11L, outputs.values.first().getValue("counts").jsonObject.getValue("anchorClaims").jsonPrimitive.long)

            val valid = outputs.getValue(firstShard.identifier)
            val inlineIndex = valid.getValue("sourceEntities").jsonArray.indexOfFirst { row ->
                row.jsonObject.getValue("entityKind").jsonPrimitive.content == "inline-instance"
            }
            val inlineRow = valid.getValue("sourceEntities").jsonArray[inlineIndex].jsonObject
            val detachedSource = FullTreeSourcePhysicalDie(
                richArtifactSha256 = richSha256,
                unitId = "cu-${"f".repeat(32)}",
                section = ".debug_info",
                compilationUnitOffset = "0x0",
                dieOffset = "0x200",
            )
            val detachedEdge = JsonObject(inlineRow.getValue("edges").jsonArray.single().jsonObject.toMutableMap().apply {
                this["source"] = JsonPrimitive(detachedSource.locator())
            })
            val detached = replaceSourceRow(valid, inlineIndex, JsonObject(inlineRow.toMutableMap().apply {
                this["edges"] = JsonArray(listOf(detachedEdge))
            }))
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    detached, scope, inventory, inventorySha256, firstShard, reconciliation,
                )
            }

            val repointedEdge = JsonObject(inlineRow.getValue("edges").jsonArray.single().jsonObject.toMutableMap().apply {
                this["target"] = JsonPrimitive(ownerA.locator())
            })
            val repointed = replaceSourceRow(valid, inlineIndex, JsonObject(inlineRow.toMutableMap().apply {
                this["edges"] = JsonArray(listOf(repointedEdge))
            }))
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    repointed, scope, inventory, inventorySha256, firstShard, reconciliation,
                )
            }

            val changedCollision = replaceSourceRow(valid, 0, JsonObject(
                valid.getValue("sourceEntities").jsonArray[0].jsonObject.toMutableMap().apply {
                    this["identityObservability"] = JsonPrimitive("observable")
                },
            ))
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    changedCollision, scope, inventory, inventorySha256, firstShard, reconciliation,
                )
            }
            val nonCollidingIndex = valid.getValue("sourceEntities").jsonArray.indexOfFirst { row ->
                row.jsonObject.getValue("entityKind").jsonPrimitive.content == "no-range-definition"
            }
            val nonCollidingRow = valid.getValue("sourceEntities").jsonArray[nonCollidingIndex].jsonObject
            val fabricatedCollisionIds = replaceSourceRow(valid, nonCollidingIndex, JsonObject(
                nonCollidingRow.toMutableMap().apply {
                    this["identityObservability"] = JsonPrimitive("ambiguous")
                    this["candidateCollisionSourceEntityIds"] = JsonArray(listOf(JsonPrimitive("f".repeat(64))))
                    this["reasonCodes"] = JsonArray(
                        (nonCollidingRow.getValue("reasonCodes").jsonArray.map { it.jsonPrimitive.content } +
                            "ambiguous-related-source-anchor").distinct().sorted().map(::JsonPrimitive),
                    )
                },
            ))
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    fabricatedCollisionIds, scope, inventory, inventorySha256, firstShard, reconciliation,
                )
            }
            val fabricatedCollisionReason = replaceSourceRow(valid, nonCollidingIndex, JsonObject(
                nonCollidingRow.toMutableMap().apply {
                    this["identityObservability"] = JsonPrimitive("ambiguous")
                    this["reasonCodes"] = JsonArray(
                        (nonCollidingRow.getValue("reasonCodes").jsonArray.map { it.jsonPrimitive.content } +
                            "ambiguous-related-source-anchor").distinct().sorted().map(::JsonPrimitive),
                    )
                },
            ))
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    fabricatedCollisionReason, scope, inventory, inventorySha256, firstShard, reconciliation,
                )
            }
            assertTrue(Files.list(root).use { paths -> paths.noneMatch { it.fileName.toString().startsWith(".function-observation-sqlite-") } })
        }

    @Test
    fun `per-shard deadline accumulates source census and output phases`() {
        var wall = 0L
        var cpu = 0L
        val budget = V2ShardDeadline(
            runCheckpoint = {},
            maximumWall = 10L,
            maximumCpu = 10L,
            wallClock = { wall },
            cpuClock = { cpu },
        )
        budget.beginPhase()
        wall = 6L
        cpu = 6L
        budget.endPhase("after source census")

        budget.beginPhase()
        wall = 11L
        cpu = 11L
        assertFailsWith<FullTreeFunctionObservationV2RunException> {
            budget.endPhase("after observation output")
        }
    }

    @Test
    fun `v2 run retained admission shares one bound between anchor claims and source facts`() {
        val budget = fullTreeFunctionObservationV2RetainedBudget(
            maximumRunRetainedBytes = 1_000L,
            maximumResidentBytes = 1_000_000L,
        )
        assertEquals(500L, budget.anchorIndexBytes)
        assertEquals(500L, budget.sourceFactsBytes)
        assertTrue(budget.anchorIndexBytes + budget.sourceFactsBytes <= 1_000L)
    }

    @Test
    fun `v2 run worker bound cannot exceed the authenticated shard count`() {
        assertEquals(1, fullTreeFunctionObservationV2EffectiveWorkers(requestedWorkers = 2, shardCount = 1))
        assertEquals(2, fullTreeFunctionObservationV2EffectiveWorkers(requestedWorkers = 2, shardCount = 3))
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionObservationV2EffectiveWorkers(requestedWorkers = 2, shardCount = 0)
        }
    }

    @Test
    fun `SQLite v2 output budget clamps to its hard canonical ceiling`() {
        assertEquals(
            FullTreeFunctionObservationsV2.MAXIMUM_CANONICAL_BYTES,
            fullTreeFunctionObservationV2OutputByteLimit(
                FullTreeFunctionObservationsV2.MAXIMUM_CANONICAL_BYTES + 1L,
            ),
        )
        assertEquals(128L, fullTreeFunctionObservationV2OutputByteLimit(256L, hardLimit = 128L))
        assertEquals(64L, fullTreeFunctionObservationV2OutputByteLimit(64L, hardLimit = 128L))
    }

    @Test
    fun `v2 validator binds candidate source revision to authenticated source lock`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("control"))
            val scope = fixture.authenticatedScope()
            val inventory = parseControlObject(fixture.inventory)
            val inventorySha = fixtureSha256(fixture.inventory)
            val shard = FullTreeFunctionObservations.shardInputs(
                inventory,
                inventorySha,
                scope.document,
                scope.sha256,
            ).first()
            val unit = shard.units.single()
            val richSha = scope.document.controlObject("oracle").controlString("richArtifactSha256")
            val physical = FullTreeSourcePhysicalDie(
                richArtifactSha256 = richSha,
                unitId = unit.controlString("id"),
                section = ".debug_info",
                compilationUnitOffset = unit.controlString("dwarfOffset"),
                dieOffset = "0x456",
            )
            fun boundDocument(revision: String): Pair<JsonObject, FullTreeFunctionObservationV2IdentityReconciliation> {
                val fields = FullTreeSourceAnchorFields(
                    sourcePath = "source/revision-bound.h",
                    declarationFileIndex = 1L,
                    declarationLine = 24L,
                    declarationColumn = null,
                    language = 33L,
                    lexicalContext = listOf("sample"),
                    sourceName = "revision_bound",
                    signature = listOf("void ()"),
                    authenticatedSourceRevision = revision,
                )
                val row = fact(
                    physical,
                    FullTreeSourceEntityKind.DECLARATION_ONLY,
                    FullTreeIdentityObservability.OBSERVABLE,
                    FullTreeDenominatorDisposition.NON_SCOREABLE,
                    fields,
                )
                val anchorIndex = FullTreeFunctionObservationV2AnchorIndex(4L, 4096L)
                anchorIndex.accept(requireNotNull(row.semanticAnchorCandidateId), row.sourceEntityId)
                val reconciliation = anchorIndex.reconciliation()
                val accumulator = FullTreeFunctionObservationAccumulatorV2(shard)
                accumulator.recordScannedDies(shard.units.size.toLong())
                accumulator.acceptSourceEntity(row)
                return accumulator.finish(
                    inventoryIndexSha256 = inventory.controlString("indexSha256"),
                    richArtifactSha256 = richSha,
                    scopeSha256 = scope.sha256,
                    reconciliation = reconciliation,
                ) to reconciliation
            }

            val authenticatedRevision = scope.sourceLock.controlObject("revision").controlString("commit")
            val (valid, validReconciliation) = boundDocument(authenticatedRevision)
            FullTreeFunctionObservationsV2.validateEnvelope(
                valid,
                scope,
                inventory,
                inventorySha,
                shard,
                validReconciliation,
            )

            val (forged, forgedReconciliation) = boundDocument("forged-revision")
            val validFact = FullTreeSourceEntityFact.fromCanonicalJson(valid.getValue("sourceEntities").jsonArray.single().jsonObject)
            val forgedFact = FullTreeSourceEntityFact.fromCanonicalJson(forged.getValue("sourceEntities").jsonArray.single().jsonObject)
            assertNotEquals(validFact.semanticAnchorCandidateId, forgedFact.semanticAnchorCandidateId)
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    forged,
                    scope,
                    inventory,
                    inventorySha,
                    shard,
                    forgedReconciliation,
                )
            }
            Unit
        }

    @Test
    fun `authenticated v2 run receipts reproduce identical outputs across worker bounds`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("control"))
            val scope = fixture.authenticatedScope()
            val scratch = privateDirectory(root.resolve("scratch"))
            val outputParentA = privateDirectory(root.resolve("output-a"))
            val outputParentB = privateDirectory(root.resolve("output-b"))
            val firstRoot = outputParentA.resolve("run")
            val secondRoot = outputParentB.resolve("run")
            val first = FullTreeFunctionObservationV2RunPublisher.generateAndPublish(
                richArtifact = fixture.richArtifact,
                inventoryPath = fixture.inventory,
                scope = scope,
                scratchParent = scratch,
                outputRoot = firstRoot,
                maximumWorkers = 1,
            )
            val second = FullTreeFunctionObservationV2RunPublisher.generateAndPublish(
                richArtifact = fixture.richArtifact,
                inventoryPath = fixture.inventory,
                scope = scope,
                scratchParent = scratch,
                outputRoot = secondRoot,
                maximumWorkers = 2,
            )
            assertEquals(1, first.maximumWorkers)
            assertEquals(2, second.maximumWorkers)
            assertEquals(first.outputs, second.outputs)
            assertEquals(first.reconciliation, second.reconciliation)
            assertEquals(first.binding.outputs, second.binding.outputs)
            assertTrue(first.fixtureOnly && second.fixtureOnly)
            assertTrue(!first.productionQualification && !first.authoritativeReleaseEvidence && !first.downstreamScoringAuthorized)

            val inventory = parseControlObject(fixture.inventory)
            val inventorySha = fixtureSha256(fixture.inventory)
            val firstInput = FullTreeFunctionObservations.shardInputs(
                inventory, inventorySha, scope.document, scope.sha256,
            ).associateBy { it.identifier }
            first.outputs.forEach { receipt ->
                val a = Files.readAllBytes(firstRoot.resolve("outputs/${receipt.shardId}.json"))
                val b = Files.readAllBytes(secondRoot.resolve("outputs/${receipt.shardId}.json"))
                assertContentEquals(a, b, receipt.shardId)
                assertEquals(receipt.outputBytes, a.size.toLong())
                assertEquals(receipt.outputSha256, OracleArtifacts.sha256(a))
                val document = OracleJson.parseCanonical(a) as JsonObject
                OracleSchemas.validate(FullTreeFunctionObservationsV2.SCHEMA_NAME, document)
                FullTreeFunctionObservationsV2.validateEnvelope(
                    document,
                    scope,
                    inventory,
                    inventorySha,
                    firstInput.getValue(receipt.shardId),
                    first.reconciliation,
                )
            }
            val rederived = FullTreeFunctionObservationV2RunPublisher.loadAndValidate(
                candidateRoot = firstRoot,
                expectedIndexArtifactSha256 = first.binding.indexArtifactSha256,
                richArtifact = fixture.richArtifact,
                inventoryPath = fixture.inventory,
                scope = scope,
                scratchParent = scratch,
            )
            assertEquals(first.binding.runSha256, rederived.binding.runSha256)
            assertEquals(first.outputs, rederived.outputs)
            assertTrue(Files.list(scratch).use { paths -> paths.findAny().isEmpty })
        }

    @Test
    fun `v2 source rows reject repeated physical IDs forged candidates resolutions promotions and overlong edges`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("control"))
            val scope = fixture.authenticatedScope()
            val inventory = parseControlObject(fixture.inventory)
            val inventorySha = fixtureSha256(fixture.inventory)
            val shard = FullTreeFunctionObservations.shardInputs(
                inventory,
                inventorySha,
                scope.document,
                scope.sha256,
            ).first()
            val unit = shard.units.single()
            val richSha = scope.document.controlObject("oracle").controlString("richArtifactSha256")
            val physical = FullTreeSourcePhysicalDie(
                richSha,
                unit.controlString("id"),
                ".debug_info",
                unit.controlString("dwarfOffset"),
                "0x400",
            )
            val fields = FullTreeSourceAnchorFields(
                sourcePath = "source/declarations.h",
                declarationFileIndex = 1L,
                declarationLine = 20L,
                declarationColumn = 7L,
                language = 33L,
                lexicalContext = listOf("sample"),
                sourceName = "declared",
                signature = listOf("void ()"),
            )
            val row = fact(
                physical,
                FullTreeSourceEntityKind.DECLARATION_ONLY,
                FullTreeIdentityObservability.OBSERVABLE,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                fields,
            )
            val accumulator = FullTreeFunctionObservationAccumulatorV2(shard)
            accumulator.acceptSourceEntity(row)
            assertFailsWith<FullTreeFunctionObservationV2Exception> { accumulator.acceptSourceEntity(row) }

            fun mutatedRow(vararg changes: Pair<String, kotlinx.serialization.json.JsonElement>) = JsonObject(
                row.canonicalJson().toMutableMap().apply { changes.forEach { (key, value) -> put(key, value) } },
            )
            assertFailsWith<IllegalArgumentException> {
                FullTreeSourceEntityFact.fromCanonicalJson(mutatedRow("sourceEntityId" to JsonPrimitive("f".repeat(64))))
            }
            assertFailsWith<IllegalArgumentException> {
                FullTreeSourceEntityFact.fromCanonicalJson(
                    mutatedRow("semanticAnchorCandidateId" to JsonPrimitive("e".repeat(64))),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                row.copy(
                    denominatorDisposition = FullTreeDenominatorDisposition.EMITTED_RVA_LINK,
                    linkedEmittedRva = "0x40",
                )
            }
            val resolvedMutation = mutatedRow("resolvedSemanticIdentityId" to JsonPrimitive("a".repeat(64)))
            assertFailsWith<IllegalArgumentException> { FullTreeSourceEntityFact.fromCanonicalJson(resolvedMutation) }

            val other = physical.copy(dieOffset = "0x401")
            val edge = FullTreeSourceIdentityEdge(
                kind = FullTreeSourceIdentityEdgeKind.SPECIFICATION,
                source = physical,
                target = other,
                referenceForm = "0x11",
                rawReference = "0x401",
                state = FullTreeSourceIdentityEdgeState.RESOLVED,
                reasonCode = null,
            )
            assertFailsWith<IllegalArgumentException> { row.copy(edges = List(33) { edge }) }
            val relatedSourceEdge = JsonObject(edge.canonicalJson().toMutableMap().apply {
                this["source"] = JsonPrimitive(other.locator())
            })
            assertEquals(
                other,
                FullTreeSourceEntityFact.fromCanonicalJson(
                    mutatedRow("edges" to JsonArray(listOf(relatedSourceEdge))),
                ).edges.single().source,
            )
            val malformedEdge = JsonObject(edge.canonicalJson().toMutableMap().apply {
                this["source"] = JsonPrimitive("detached")
            })
            assertFailsWith<IllegalArgumentException> {
                FullTreeSourceEntityFact.fromCanonicalJson(mutatedRow("edges" to JsonArray(listOf(malformedEdge))))
            }
            Unit
        }

    private fun fact(
        physical: FullTreeSourcePhysicalDie,
        kind: FullTreeSourceEntityKind,
        observability: FullTreeIdentityObservability,
        disposition: FullTreeDenominatorDisposition,
        fields: FullTreeSourceAnchorFields?,
        reasons: List<String> = emptyList(),
        edges: List<FullTreeSourceIdentityEdge> = emptyList(),
    ) = FullTreeSourceEntityFact(
        sourceEntityId = physical.sourceEntityId(kind),
        physicalDie = physical,
        kind = kind,
        identityObservability = observability,
        denominatorDisposition = disposition,
        semanticAnchorFields = fields,
        semanticAnchorCandidateId = kind.anchorKind()?.let { fields?.candidateId(it) },
        resolvedSemanticIdentityId = null,
        candidateCollisionSourceEntityIds = emptyList(),
        linkedEmittedRva = null,
        reasonCodes = reasons.distinct().sorted(),
        edges = edges,
    )

    private fun observationAlias(name: String, unit: JsonObject, dieOffset: ULong) = FullTreeObservedFunctionAlias(
        name = name,
        evidence = listOf(
            FullTreeObservedFunctionEvidence("rich:.debug_info:die=0x${dieOffset.toString(16)}", unit.controlString("id")),
        ),
    )

    private fun observationDeclaration(unitSourcePath: String) = JsonObject(
        mapOf(
            "column" to JsonPrimitive(3),
            "externalPathSha256" to JsonNull,
            "fileIndex" to JsonPrimitive(1),
            "line" to JsonPrimitive(2),
            "sourcePath" to JsonPrimitive("source/include/header.h"),
            "unitSourcePath" to JsonPrimitive(unitSourcePath),
        ),
    )

    private fun replaceSourceRow(document: JsonObject, index: Int, row: JsonObject): JsonObject = JsonObject(
        document.toMutableMap().apply {
            this["sourceEntities"] = JsonArray(getValue("sourceEntities").jsonArray.toMutableList().apply {
                this[index] = row
            })
        },
    )

    private fun privateDirectory(path: java.nio.file.Path): java.nio.file.Path =
        Files.createDirectory(path).also {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
        }
}
