package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemaException
import decompengine.oracle.core.OracleSchemas
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
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
    fun `v2 concurrent scratch budget accounts for prepared outputs sqlite and dwarf decompression`() {
        val budget = fullTreeFunctionObservationV2ShardScratchBudget(
            maximumScratchBytes = 1_000L,
            preparedOutputBytes = 100L,
            configuredDwarfScratchBytes = 800L,
            configuredOutputBytes = 300L,
            configuredDatabaseBytes = 500L,
            sqlitePageBytes = 64L,
        )
        assertEquals(536L, budget.dwarfScratchBytes)
        assertEquals(300L, budget.outputBytes)
        assertEquals(64L, budget.databaseBytes)
        assertEquals(636L, budget.additionalScratchBytes)
        assertEquals(1_000L, budget.additionalScratchBytes + budget.databaseBytes + budget.outputBytes)
        assertFailsWith<FullTreeFunctionObservationV2RunException> {
            fullTreeFunctionObservationV2ShardScratchBudget(
                maximumScratchBytes = 463L,
                preparedOutputBytes = 100L,
                configuredDwarfScratchBytes = 800L,
                configuredOutputBytes = 300L,
                configuredDatabaseBytes = 500L,
                sqlitePageBytes = 64L,
            )
        }
    }

    @Test
    fun `v2 anchor claim cap follows physical scan capacity and retained memory`() {
        assertEquals(100L, fullTreeFunctionObservationV2AnchorClaimBound(Long.MAX_VALUE, 32, 100L, 1_000_000L))
        val claimBound = fullTreeFunctionObservationV2AnchorClaimBound(1_000_000L, 1, 4_000_000L, 1_000_000L)
        assertTrue(claimBound > 64L)
        assertEquals(
            132_000L,
            fullTreeFunctionObservationV2AnchorClaimBound(100L, 40L, 4_000_000L, 100_000_000L),
            "anchor capacity must include physical-record ceilings for every authenticated CU",
        )
        val index = FullTreeFunctionObservationV2AnchorIndex(claimBound, 1_000_000L)
        repeat(65) { ordinal ->
            index.accept(
                OracleArtifacts.sha256("candidate-$ordinal".toByteArray()),
                OracleArtifacts.sha256("ordinary-emitted-die-$ordinal".toByteArray()),
            )
        }
        assertEquals(65L, index.reconciliation().claimCount)
    }

    @Test
    fun `fixed reference forms enforce their encoded operand widths`() {
        assertEquals(0xffuL, fullTreeDwarfReferenceFormMaximumRawValue(FULL_TREE_DW_FORM_REF1.toULong()))
        assertEquals(0xffffuL, fullTreeDwarfReferenceFormMaximumRawValue(FULL_TREE_DW_FORM_REF2.toULong()))
        assertEquals(0xffff_ffffuL, fullTreeDwarfReferenceFormMaximumRawValue(FULL_TREE_DW_FORM_REF4.toULong()))
        assertEquals(0xffff_ffffuL, fullTreeDwarfReferenceFormMaximumRawValue(FULL_TREE_DW_FORM_REF_SUP4.toULong()))
        assertTrue(fullTreeDwarfReferenceFormMaximumRawValue(FULL_TREE_DW_FORM_REF8.toULong()) == null)
        assertTrue(fullTreeDwarfReferenceFormMaximumRawValue(FULL_TREE_DW_FORM_REF_UDATA.toULong()) == null)
    }

    @Test
    fun `full-run anchor reconciliation invokes bounded progress checkpoints`() {
        val index = FullTreeFunctionObservationV2AnchorIndex(9_000L, 8L * 1024L * 1024L)
        repeat(8_192) { ordinal ->
            index.accept(
                OracleArtifacts.sha256("candidate-$ordinal".toByteArray()),
                OracleArtifacts.sha256("physical-$ordinal".toByteArray()),
            )
        }
        var checkpoints = 0
        assertFailsWith<IllegalStateException> {
            index.reconciliation {
                if (++checkpoints == 3) throw IllegalStateException("deadline checkpoint")
            }
        }
        assertEquals(3, checkpoints)
    }

    @Test
    fun `v2 shard resident allowance subtracts co-resident run state`() {
        assertEquals(700L, fullTreeFunctionObservationV2AvailableResidentBytes(1_000L, 100L, 200L))
        assertEquals(650L, fullTreeFunctionObservationV2AvailableResidentBytes(1_000L, 100L, 200L, 50L))
        assertEquals(600L, fullTreeFunctionObservationV2AvailableResidentBytes(1_000L, 100L, 200L, 50L, 50L))
        assertEquals(
            200L,
            fullTreeFunctionObservationV2SourceRowCanonicalizationScratchBytes(100L),
        )
        assertEquals(
            MAXIMUM_SOURCE_IDENTITY_ROW_BYTES * MAXIMUM_SOURCE_IDENTITY_SINK_CANONICALIZATION_FACTOR,
            fullTreeFunctionObservationV2SourceRowCanonicalizationScratchBytes(MAXIMUM_SOURCE_IDENTITY_ROW_BYTES + 1L),
        )
        assertFailsWith<FullTreeFunctionObservationV2RunException> {
            fullTreeFunctionObservationV2AvailableResidentBytes(1_000L, 400L, 600L)
        }
        assertFailsWith<FullTreeFunctionObservationV2RunException> {
            fullTreeFunctionObservationV2AvailableResidentBytes(1_000L, 100L, 200L, 700L)
        }
        assertEquals(
            2L * sourceIdentityFixedStructureResidentBytes(100L, 80L, 2L, 0L, 0L),
            fullTreeFunctionObservationV2RunControlSnapshotBytes(100L, 80L, 2L),
        )
        assertFailsWith<FullTreeFunctionObservationV2RunException> {
            fullTreeFunctionObservationV2AvailableResidentBytes(1_000L, 100L, 200L, 50L, 700L)
        }
    }

    @Test
    fun `run retained fact model drops array framing and charges each persistent row`() {
        // A two-row canonical array has four fixed framing bytes and one comma in addition
        // to the rows' exact additive contributions: 35 = 4 + 10 + 20 + 1.
        assertEquals(602L, fullTreeFunctionObservationV2RetainedFactListBytes(35L, 2L))
        assertEquals(0L, fullTreeFunctionObservationV2RetainedFactListBytes(3L, 0L))
        assertFailsWith<FullTreeFunctionObservationV2RunException> {
            fullTreeFunctionObservationV2RetainedFactListBytes(2L, 0L)
        }
    }

    @Test
    fun `v2 schema policy digest is pinned and compact fixture output stays canonical`() {
        assertEquals("c068ed200c8493acbe830ba4e4d8390e8a30499b3d866c43646ff802ff645d89", OracleSchemas.identity(
            FullTreeFunctionObservationsV2.SCHEMA_NAME,
        ).sha256)
        assertEquals("5a4b9dc9015fb64ebb8ec038c8ceefa394b1eaaabfbaf0cf9bc3349497e7e116", FullTreeFunctionObservationsV2.configurationSha256)
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
            FullTreeIdentityObservability.UNKNOWN,
            FullTreeDenominatorDisposition.UNKNOWN,
            fields = null,
            reasons = listOf("unsupported-source-identity"),
        )
        assertEquals(
            OracleArtifacts.sha256(canonicalSourceEntityFacts(listOf(sourceRow))),
            observationV2CollisionNeutralSourceEntitiesSha256(
                listOf(sourceRow),
                MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES,
            ),
        )
        val index = FullTreeFunctionObservationV2AnchorIndex(1L, 4096L)
        index.acceptSourceEntityPopulation(shard.identifier, listOf(sourceRow))
        val reconciliation = index.reconciliation()
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
                authenticatedSourceRevision = authenticatedSourceRevision
                    ?: scope.sourceLock.controlObject("revision").controlString("commit"),
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
                FullTreeIdentityObservability.UNOBSERVABLE,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                declarationFieldsA,
            )
            val declarationB = fact(
                physical(secondUnit, "0x100"),
                FullTreeSourceEntityKind.DECLARATION_ONLY,
                FullTreeIdentityObservability.UNOBSERVABLE,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                declarationFieldsB,
            )
            val declarationA2 = fact(
                physical(firstUnit, absoluteOffset(firstUnit, 0x20UL)),
                FullTreeSourceEntityKind.DECLARATION_ONLY,
                FullTreeIdentityObservability.UNOBSERVABLE,
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
                FullTreeIdentityObservability.UNKNOWN,
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
            val templateIntPhysical = physical(firstUnit, absoluteOffset(firstUnit, 0x130uL))
            val templateIntTarget = physical(secondUnit, absoluteOffset(secondUnit, 0x80uL))
            val templateIntToOtherCu = FullTreeSourceIdentityEdge(
                kind = FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT,
                source = templateIntPhysical,
                target = templateIntTarget,
                referenceForm = "0x10",
                rawReference = templateIntTarget.dieOffset,
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
                        reasonCode = "target-not-retained-or-not-a-die-boundary",
                    ),
                ),
            )
            assertNotEquals(templateInt.semanticAnchorCandidateId, templateLong.semanticAnchorCandidateId)
            assertEquals(null, templateInt.linkedEmittedRva)
            assertEquals(null, templateLong.linkedEmittedRva)
            assertFailsWith<IllegalArgumentException> {
                templateInt.copy(denominatorDisposition = FullTreeDenominatorDisposition.AMBIGUOUS)
            }

            val ownerFields = anchorFields("inline_owner", line = 105L)
            val ownerCandidate = requireNotNull(ownerFields.candidateId(FullTreeSourceAnchorKind.SOURCE_DEFINITION))
            val calleeFields = anchorFields("inline_callee", line = 106L)
            val calleeCandidate = requireNotNull(calleeFields.candidateId(FullTreeSourceAnchorKind.SOURCE_DEFINITION))
            val ownerA = physical(firstUnit, absoluteOffset(firstUnit, 0x200uL))
            val ownerB = physical(secondUnit, absoluteOffset(secondUnit, 0x200uL))
            val callee = physical(firstUnit, absoluteOffset(firstUnit, 0x210uL))
            val inlinePhysical = physical(firstUnit, absoluteOffset(firstUnit, 0x150uL))
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
                        kind = FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN,
                        source = inlinePhysical,
                        target = callee,
                        referenceForm = "0x10",
                        rawReference = callee.dieOffset,
                        state = FullTreeSourceIdentityEdgeState.RESOLVED,
                        reasonCode = null,
                    ),
                    FullTreeSourceIdentityEdge(
                        kind = FullTreeSourceIdentityEdgeKind.INLINE_OWNER,
                        source = inlinePhysical,
                        target = ownerB,
                        referenceForm = "0x10",
                        rawReference = ownerB.dieOffset,
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
            shardFacts.values.flatten()
                .filter { it.kind == FullTreeSourceEntityKind.INLINE_INSTANCE }
                .forEach(anchorIndex::acceptInlineRelatedClaims)
            shardFacts.forEach { (shardId, facts) ->
                anchorIndex.acceptSourceEntityPopulation(
                    shardId,
                    FullTreeSourceEntityFact.deterministicOrder(facts),
                )
            }
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
            assertEquals(7L, reconciliation.candidateCount)
            assertEquals(allAnchorClaims.map { it.first }.distinct().size.toLong(), reconciliation.candidateCount)
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
                    fun jsonNodeCount(element: kotlinx.serialization.json.JsonElement): Int = 1 + when (element) {
                        is JsonObject -> element.values.sumOf(::jsonNodeCount)
                        is JsonArray -> element.sumOf(::jsonNodeCount)
                        else -> 0
                    }
                    val exactV2NodeCount = jsonNodeCount(OracleJson.parseCanonical(memoryBytes))
                    assertTrue(exactV2NodeCount > 16)
                    FullTreeFunctionObservationSqlite.openV2(
                        root,
                        shard,
                        sqliteLimits.copy(maximumV2JsonNodes = exactV2NodeCount),
                    ).use { exactNodeLimitSink ->
                        exactNodeLimitSink.recordScannedDies(3L)
                        observations.forEach(exactNodeLimitSink::accept)
                        reconciledByShard.getValue(shard.identifier).forEach(exactNodeLimitSink::acceptSourceEntity)
                        val exactNodeOutput = ByteArrayOutputStream()
                        exactNodeLimitSink.finishToV2(exactNodeOutput, bindings, reconciliation)
                        assertContentEquals(memoryBytes, exactNodeOutput.toByteArray())
                    }
                    assertFailsWith<FullTreeFunctionObservationSqliteException> {
                        FullTreeFunctionObservationSqlite.openV2(
                            root,
                            shard,
                            sqliteLimits.copy(maximumV2JsonNodes = exactV2NodeCount - 1),
                        ).use { nodeLimitedSink ->
                            nodeLimitedSink.recordScannedDies(3L)
                            observations.forEach(nodeLimitedSink::accept)
                            reconciledByShard.getValue(shard.identifier).forEach(nodeLimitedSink::acceptSourceEntity)
                            nodeLimitedSink.finishToV2(ByteArrayOutputStream(), bindings, reconciliation)
                        }
                    }
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
            val admittedArrayBytes = Math.addExact(
                Math.addExact(
                    4L,
                    allRows.sumOf { fullTreeSourceEntityCanonicalContribution(it).arrayContributionBytes },
                ),
                allRows.size.toLong() - 1L,
            )
            assertEquals(canonicalSourceEntityFacts(allRows).size.toLong(), admittedArrayBytes)
            assertEquals(3L, canonicalSourceEntityFacts(emptyList()).size.toLong())
            assertEquals(3, allRows.count { it.kind == FullTreeSourceEntityKind.DECLARATION_ONLY })
            assertEquals(1, allRows.count { it.kind == FullTreeSourceEntityKind.NO_RANGE_DEFINITION })
            assertEquals(0, allRows.count { it.kind == FullTreeSourceEntityKind.TEMPLATE_PATTERN })
            assertEquals(2, allRows.count { it.kind == FullTreeSourceEntityKind.TEMPLATE_INSTANCE })
            assertEquals(1, allRows.count { it.kind == FullTreeSourceEntityKind.INLINE_INSTANCE })
            assertEquals(1, allRows.count { it.kind == FullTreeSourceEntityKind.UNRESOLVED })
            assertEquals(4, allRows.count { it.identityObservability == FullTreeIdentityObservability.AMBIGUOUS })
            assertEquals(4, allRows.count { it.identityObservability == FullTreeIdentityObservability.UNKNOWN })
            assertEquals(0, allRows.count { it.identityObservability == FullTreeIdentityObservability.UNOBSERVABLE })
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

            val noRunCollisions = FullTreeFunctionObservationV2AnchorIndex(1L, 4096L).reconciliation()
            var sawNeutralizedCollision = false
            outputs.values.forEach { shardDocument ->
                val shardFacts = shardDocument.getValue("sourceEntities").jsonArray.map {
                    FullTreeSourceEntityFact.fromCanonicalJson(it.jsonObject)
                }
                val neutralFacts = reconcileObservationV2Facts(shardFacts, noRunCollisions)
                val neutralBytes = observationV2CollisionNeutralSourceEntityFactsByteLength(
                    shardFacts,
                    MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES,
                )
                assertEquals(
                    canonicalSourceEntityFactsByteLength(neutralFacts),
                    neutralBytes,
                    "collision-neutral preflight must size the adjusted facts exactly",
                )
                if (shardFacts.any { it.candidateCollisionSourceEntityIds.isNotEmpty() }) {
                    sawNeutralizedCollision = true
                    assertTrue(neutralBytes < canonicalSourceEntityFactsByteLength(shardFacts))
                }
            }
            assertTrue(sawNeutralizedCollision, "fixture must exercise collision-neutral byte preflight")

            val valid = outputs.getValue(firstShard.identifier)
            val directCandidateRow = valid.getValue("sourceEntities").jsonArray
                .map { FullTreeSourceEntityFact.fromCanonicalJson(it.jsonObject) }
                .first { it.kind == FullTreeSourceEntityKind.TEMPLATE_INSTANCE && it.semanticAnchorCandidateId != null }
            val directCandidateFields = requireNotNull(directCandidateRow.semanticAnchorFields)
            val forgedDirectCandidateFields = copyAnchorFields(
                directCandidateFields,
                authenticatedFileSha256 = directCandidateFields.authenticatedSourceFileSha256,
                sourceName = "forged-template-instance",
            )
            val forgedDirectCandidate = directCandidateRow.copy(
                semanticAnchorFields = forgedDirectCandidateFields,
                semanticAnchorCandidateId = requireNotNull(
                    forgedDirectCandidateFields.candidateId(FullTreeSourceAnchorKind.TEMPLATE_INSTANCE),
                ),
            )
            val forgedDirectCandidateFacts = valid.getValue("sourceEntities").jsonArray.map { row ->
                val parsed = FullTreeSourceEntityFact.fromCanonicalJson(row.jsonObject)
                if (parsed.sourceEntityId == directCandidateRow.sourceEntityId) forgedDirectCandidate else parsed
            }
            val directCandidateFailure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.composeEnvelope(
                    v1ProjectionForCompose(valid),
                    forgedDirectCandidateFacts,
                    reconciliation,
                    8L * 1024L * 1024L,
                )
            }
            assertTrue(directCandidateFailure.message.orEmpty().contains("physical DIE claim"))

            val unknownCompleteIndex = valid.getValue("sourceEntities").jsonArray.indexOfFirst { row ->
                val fact = FullTreeSourceEntityFact.fromCanonicalJson(row.jsonObject)
                fact.kind == FullTreeSourceEntityKind.NO_RANGE_DEFINITION &&
                    fact.identityObservability == FullTreeIdentityObservability.UNKNOWN &&
                    fact.semanticAnchorCandidateId != null && fact.reasonCodes.any { it.startsWith("unknown-") }
            }
            assertTrue(unknownCompleteIndex >= 0)
            val unknownComplete = valid.getValue("sourceEntities").jsonArray[unknownCompleteIndex].jsonObject
            val hiddenCompleteCandidate = replaceSourceRow(
                valid,
                unknownCompleteIndex,
                JsonObject(unknownComplete.toMutableMap().apply {
                    this["semanticAnchorCandidateId"] = JsonNull
                }),
            )
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    hiddenCompleteCandidate,
                    scope,
                    inventory,
                    inventorySha256,
                    firstShard,
                    reconciliation,
                )
            }
            val observabilityCounts = JsonObject(
                valid.controlObject("counts").controlObject("sourceEntitiesByObservability").toMutableMap().apply {
                    put("unknown", JsonPrimitive(getValue("unknown").jsonPrimitive.long - 1L))
                    put("observable", JsonPrimitive(getValue("observable").jsonPrimitive.long + 1L))
                },
            )
            val changedCounts = JsonObject(valid.controlObject("counts").toMutableMap().apply {
                put("sourceEntitiesByObservability", observabilityCounts)
            })
            val observableWithUnknownEvidence = JsonObject(
                replaceSourceRow(
                    valid,
                    unknownCompleteIndex,
                    JsonObject(unknownComplete.toMutableMap().apply {
                        this["identityObservability"] = JsonPrimitive("observable")
                    }),
                ).toMutableMap().apply { put("counts", changedCounts) },
            )
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    observableWithUnknownEvidence,
                    scope,
                    inventory,
                    inventorySha256,
                    firstShard,
                    reconciliation,
                )
            }
            val inlineIndex = valid.getValue("sourceEntities").jsonArray.indexOfFirst { row ->
                row.jsonObject.getValue("entityKind").jsonPrimitive.content == "inline-instance"
            }
            val inlineRow = valid.getValue("sourceEntities").jsonArray[inlineIndex].jsonObject
            fun inlineOwnerEdge(row: JsonObject): JsonObject = row.getValue("edges").jsonArray
                .map { it.jsonObject }
                .single { it.getValue("kind").jsonPrimitive.content == "inline-owner" }
            val originalInlineFact = FullTreeSourceEntityFact.fromCanonicalJson(inlineRow)
            val originalInlineFields = requireNotNull(originalInlineFact.semanticAnchorFields)
            val forgedCalleeFields = copyAnchorFields(
                originalInlineFields,
                authenticatedFileSha256 = originalInlineFields.authenticatedSourceFileSha256,
                inlineCalleeAnchorCandidateId = OracleArtifacts.sha256("unclaimed-inline-callee".toByteArray()),
            )
            val forgedCalleeFact = originalInlineFact.copy(
                semanticAnchorFields = forgedCalleeFields,
                semanticAnchorCandidateId = requireNotNull(
                    forgedCalleeFields.candidateId(FullTreeSourceAnchorKind.INLINE_INSTANCE),
                ),
            )
            val forgedCalleeFacts = valid.getValue("sourceEntities").jsonArray.map { row ->
                val parsed = FullTreeSourceEntityFact.fromCanonicalJson(row.jsonObject)
                if (parsed.sourceEntityId == originalInlineFact.sourceEntityId) forgedCalleeFact else parsed
            }
            val forgedCalleeFailure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.composeEnvelope(
                    v1ProjectionForCompose(valid),
                    forgedCalleeFacts,
                    reconciliation,
                    8L * 1024L * 1024L,
                )
            }
            assertTrue(forgedCalleeFailure.message.orEmpty().contains("inline callee candidate"))
            val nestedOwnerA = physical(firstUnit, "0x103")
            val nestedOwnerB = ownerB
            val nestedFormal = physical(firstUnit, "0x102")
            val nestedTypeTarget = physical(secondUnit, "0x80")
            val inlineFactPhysical = FullTreeSourceEntityFact.fromCanonicalJson(inlineRow).physicalDie
            val nestedOwnerPath = listOf(
                FullTreeSourceIdentityEdge(
                    kind = FullTreeSourceIdentityEdgeKind.INLINE_OWNER,
                    source = inlineFactPhysical,
                    target = nestedOwnerA,
                    referenceForm = null,
                    rawReference = null,
                    state = FullTreeSourceIdentityEdgeState.RESOLVED,
                    reasonCode = null,
                ),
                FullTreeSourceIdentityEdge(
                    kind = FullTreeSourceIdentityEdgeKind.INLINE_OWNER,
                    source = nestedOwnerA,
                    target = nestedOwnerB,
                    referenceForm = null,
                    rawReference = null,
                    state = FullTreeSourceIdentityEdgeState.RESOLVED,
                    reasonCode = null,
                ),
                FullTreeSourceIdentityEdge(
                    kind = FullTreeSourceIdentityEdgeKind.TYPE,
                    source = nestedOwnerB,
                    target = nestedFormal,
                    referenceForm = null,
                    rawReference = null,
                    state = FullTreeSourceIdentityEdgeState.RESOLVED,
                    reasonCode = null,
                ),
                FullTreeSourceIdentityEdge(
                    kind = FullTreeSourceIdentityEdgeKind.TYPE,
                    source = nestedFormal,
                    target = nestedTypeTarget,
                    referenceForm = "0x10",
                    rawReference = nestedTypeTarget.dieOffset,
                    state = FullTreeSourceIdentityEdgeState.RESOLVED,
                    reasonCode = null,
                ),
            )
            val nestedOwnerFact = FullTreeSourceEntityFact.fromCanonicalJson(inlineRow).copy(edges = nestedOwnerPath)
            val nestedOwnerFacts = valid.getValue("sourceEntities").jsonArray.map { row ->
                val fact = FullTreeSourceEntityFact.fromCanonicalJson(row.jsonObject)
                if (fact.sourceEntityId == nestedOwnerFact.sourceEntityId) nestedOwnerFact else fact
            }
            val nestedOwnerDocument = FullTreeFunctionObservationsV2.composeEnvelope(
                v1ProjectionForCompose(valid),
                nestedOwnerFacts,
                reconciliation,
                8L * 1024L * 1024L,
            )
            FullTreeFunctionObservationsV2.validateEnvelope(
                nestedOwnerDocument, scope, inventory, inventorySha256, firstShard, reconciliation,
            )

            val detachedSource = physical(firstUnit, "0x500")
            val detachedEdge = JsonObject(inlineOwnerEdge(inlineRow).toMutableMap().apply {
                this["source"] = JsonPrimitive(detachedSource.locator())
            })
            val detached = replaceSourceRow(valid, inlineIndex, JsonObject(inlineRow.toMutableMap().apply {
                this["edges"] = JsonArray(getValue("edges").jsonArray.map { edge ->
                    if (edge.jsonObject.getValue("kind").jsonPrimitive.content == "inline-owner") detachedEdge else edge
                })
            }))
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    detached, scope, inventory, inventorySha256, firstShard, reconciliation,
                )
            }

            val repointedEdge = JsonObject(inlineOwnerEdge(inlineRow).toMutableMap().apply {
                this["target"] = JsonPrimitive(ownerA.locator())
            })
            val repointed = replaceSourceRow(valid, inlineIndex, JsonObject(inlineRow.toMutableMap().apply {
                this["edges"] = JsonArray(getValue("edges").jsonArray.map { edge ->
                    if (edge.jsonObject.getValue("kind").jsonPrimitive.content == "inline-owner") repointedEdge else edge
                })
            }))
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    repointed, scope, inventory, inventorySha256, firstShard, reconciliation,
                )
            }

            val parsedInlineFact = FullTreeSourceEntityFact.fromCanonicalJson(inlineRow)
            val sourceCuOffset = parsedInlineFact.physicalDie.compilationUnitOffset.removePrefix("0x").toULong(16)
            val sourceDieOffset = parsedInlineFact.physicalDie.dieOffset.removePrefix("0x").toULong(16)
            val targetDieOffset = sourceDieOffset + 0x100uL
            val rawReferenceOffset = targetDieOffset - sourceCuOffset
            assertTrue(rawReferenceOffset > 0xffuL)
            val overWidthEdge = FullTreeSourceIdentityEdge(
                kind = FullTreeSourceIdentityEdgeKind.TYPE,
                source = parsedInlineFact.physicalDie,
                target = parsedInlineFact.physicalDie.copy(dieOffset = "0x${targetDieOffset.toString(16)}"),
                referenceForm = "0x${FULL_TREE_DW_FORM_REF1.toString(16)}",
                rawReference = "0x${rawReferenceOffset.toString(16)}",
                state = FullTreeSourceIdentityEdgeState.RESOLVED,
                reasonCode = null,
            )
            val forgedWidthFact = parsedInlineFact.copy(edges = parsedInlineFact.edges + overWidthEdge)
            val forgedWidthRows = valid.getValue("sourceEntities").jsonArray.map { row ->
                val fact = FullTreeSourceEntityFact.fromCanonicalJson(row.jsonObject)
                if (fact.sourceEntityId == parsedInlineFact.sourceEntityId) forgedWidthFact else fact
            }
            val forgedWidthDocument = FullTreeFunctionObservationsV2.composeEnvelope(
                v1ProjectionForCompose(valid),
                forgedWidthRows,
                reconciliation,
                8L * 1024L * 1024L,
            )
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    forgedWidthDocument, scope, inventory, inventorySha256, firstShard, reconciliation,
                )
            }
            val masqueradingTypedEdge = JsonObject(inlineOwnerEdge(inlineRow).toMutableMap().apply {
                this["kind"] = JsonPrimitive("type")
            })
            val missingTypedEvidence = replaceSourceRow(valid, inlineIndex, JsonObject(inlineRow.toMutableMap().apply {
                this["edges"] = JsonArray(listOf(masqueradingTypedEdge))
            }))
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    missingTypedEvidence, scope, inventory, inventorySha256, firstShard, reconciliation,
                )
            }

            val collidingIndex = valid.getValue("sourceEntities").jsonArray.indexOfFirst { row ->
                row.jsonObject.getValue("candidateCollisionSourceEntityIds").jsonArray.isNotEmpty()
            }
            assertTrue(collidingIndex >= 0, "fixture must contain a full-run collision claimant")
            val collisionReasons = setOf("duplicate-source-anchor-unproven", "ambiguous-related-source-anchor")
            val changedCollisionRow = JsonObject(
                valid.getValue("sourceEntities").jsonArray[collidingIndex].jsonObject.toMutableMap().apply {
                    this["identityObservability"] = JsonPrimitive("observable")
                    this["candidateCollisionSourceEntityIds"] = JsonArray(emptyList())
                    this["reasonCodes"] = JsonArray(
                        getValue("reasonCodes").jsonArray.filterNot {
                            it.jsonPrimitive.content in collisionReasons
                        },
                    )
                },
            )
            val changedCollision = replaceSourceRow(valid, collidingIndex, changedCollisionRow)
            val changedCollisionFacts = changedCollision.getValue("sourceEntities").jsonArray.map {
                FullTreeSourceEntityFact.fromCanonicalJson(it.jsonObject)
            }
            val collisionCounts = JsonObject(changedCollision.getValue("counts").jsonObject.toMutableMap().apply {
                put("sourceEntitiesByObservability", sourceObservabilityCounts(changedCollisionFacts))
            })
            val collisionDocumentWithRecount = JsonObject(changedCollision.toMutableMap().apply {
                put("counts", collisionCounts)
            })
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    collisionDocumentWithRecount, scope, inventory, inventorySha256, firstShard, reconciliation,
                )
            }
            val declarationCandidate = requireNotNull(declarationA.semanticAnchorCandidateId)
            val forgedPhysical = physical(firstUnit, "0x300")
            val originalNonclaimant = fact(
                forgedPhysical,
                FullTreeSourceEntityKind.DECLARATION_ONLY,
                FullTreeIdentityObservability.UNOBSERVABLE,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                fields = null,
            )
            val claimantIndex = FullTreeFunctionObservationV2AnchorIndex(4L, 4096L)
            claimantIndex.accept(
                FullTreeSourceAnchorKind.DECLARATION_ONLY,
                declarationCandidate,
                declarationA.sourceEntityId,
            )
            claimantIndex.accept(
                FullTreeSourceAnchorKind.DECLARATION_ONLY,
                declarationCandidate,
                declarationA2.sourceEntityId,
            )
            claimantIndex.acceptSourceEntityPopulation(firstShard.identifier, listOf(originalNonclaimant))
            val claimantReconciliation = claimantIndex.reconciliation()
            val declarationCollisionIds = requireNotNull(
                claimantReconciliation.collisionIdsByCandidate[declarationCandidate],
            )
            val forgedNonclaimant = originalNonclaimant.copy(
                identityObservability = FullTreeIdentityObservability.AMBIGUOUS,
                semanticAnchorFields = declarationA.semanticAnchorFields,
                semanticAnchorCandidateId = declarationCandidate,
                candidateCollisionSourceEntityIds = declarationCollisionIds,
                reasonCodes = listOf("duplicate-source-anchor-unproven"),
            )
            val forgedNonclaimantFailure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.composeEnvelope(
                    v1ProjectionForCompose(valid),
                    listOf(forgedNonclaimant),
                    claimantReconciliation,
                    8L * 1024L * 1024L,
                )
            }
            assertTrue(forgedNonclaimantFailure.message.orEmpty().contains("not an authenticated direct anchor claimant"))
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
    fun `per-shard deadline accumulates source reconciliation and output phases`() {
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
        wall = 3L
        cpu = 3L
        budget.endPhase("after source census")

        budget.beginPhase()
        wall = 7L
        cpu = 7L
        budget.endPhase("after source reconciliation")

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
    fun `both v2 sinks enforce completed descriptor schema bounds before retention`(): Unit =
        inControlTemporaryDirectory { root ->
            val unit = JsonObject(mapOf(
                "id" to JsonPrimitive("cu-${"1".repeat(32)}"),
                "sourcePath" to JsonPrimitive("source/fixture.cpp"),
            ))
            val shard = FullTreeFunctionObservationShardInput("fixture-shard", "a".repeat(64), listOf(unit))
            fun fact(dieOffset: String, descriptor: String): FullTreeSourceEntityFact {
                val physical = FullTreeSourcePhysicalDie(
                    richArtifactSha256 = "c".repeat(64),
                    unitId = unit.controlString("id"),
                    section = ".debug_info",
                    compilationUnitOffset = "0x0",
                    dieOffset = dieOffset,
                )
                val fields = FullTreeSourceAnchorFields(
                    sourcePath = "source/fixture.cpp",
                    declarationFileIndex = 0L,
                    declarationLine = 1L,
                    declarationColumn = null,
                    language = 33L,
                    lexicalContext = emptyList(),
                    sourceName = "fixture",
                    signature = listOf(descriptor),
                )
                return FullTreeSourceEntityFact(
                    sourceEntityId = physical.sourceEntityId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
                    physicalDie = physical,
                    kind = FullTreeSourceEntityKind.NO_RANGE_DEFINITION,
                    identityObservability = FullTreeIdentityObservability.OBSERVABLE,
                    denominatorDisposition = FullTreeDenominatorDisposition.NON_SCOREABLE,
                    semanticAnchorFields = fields,
                    semanticAnchorCandidateId = requireNotNull(
                        fields.candidateId(FullTreeSourceAnchorKind.NO_RANGE_DEFINITION),
                    ),
                    resolvedSemanticIdentityId = null,
                    candidateCollisionSourceEntityIds = emptyList(),
                    linkedEmittedRva = null,
                    reasonCodes = emptyList(),
                    edges = emptyList(),
                )
            }

            val exactFact = fact("0x10", "x".repeat(MAXIMUM_SOURCE_IDENTITY_DESCRIPTOR_CHARACTERS))
            val overlongFact = fact("0x11", "x".repeat(MAXIMUM_SOURCE_IDENTITY_DESCRIPTOR_CHARACTERS + 1))
            val index = FullTreeFunctionObservationV2AnchorIndex(1L, 4096L)
            index.accept(
                FullTreeSourceAnchorKind.NO_RANGE_DEFINITION,
                requireNotNull(exactFact.semanticAnchorCandidateId),
                exactFact.sourceEntityId,
            )
            index.acceptSourceEntityPopulation(shard.identifier, listOf(exactFact))
            val reconciliation = index.reconciliation()
            val bindings = FullTreeFunctionObservationBindings(
                inventoryIndexSha256 = "b".repeat(64),
                richArtifactSha256 = "c".repeat(64),
                scopeSha256 = "d".repeat(64),
            )
            val memory = FullTreeFunctionObservationAccumulatorV2(shard)
            memory.recordScannedDies(1L)
            memory.acceptSourceEntity(exactFact)
            val memoryBytes = FullTreeFunctionObservationsV2.canonicalEnvelopeBytes(
                memory.finish(
                    inventoryIndexSha256 = bindings.inventoryIndexSha256,
                    richArtifactSha256 = bindings.richArtifactSha256,
                    scopeSha256 = bindings.scopeSha256,
                    reconciliation = reconciliation,
                ),
            )
            OracleSchemas.validate(
                FullTreeFunctionObservationsV2.SCHEMA_NAME,
                OracleJson.parseCanonical(memoryBytes),
            )
            val memoryRejectsOverlong = FullTreeFunctionObservationAccumulatorV2(shard)
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                memoryRejectsOverlong.acceptSourceEntity(overlongFact)
            }

            val sqliteLimits = FullTreeFunctionObservationSqliteLimits(
                maximumDatabaseBytes = 4L * 1024L * 1024L,
                maximumOutputBytes = 1024L * 1024L,
                maximumCacheBytes = 64 * 1024,
                databaseCheckpointRows = 1,
                checkpoint = FullTreeFunctionObservationSqliteCheckpoint {},
            )
            val sqliteOutput = ByteArrayOutputStream()
            FullTreeFunctionObservationSqlite.openV2(
                privateDirectory(root.resolve("sqlite-exact")),
                shard,
                sqliteLimits,
            ).use { sqlite ->
                sqlite.recordScannedDies(1L)
                sqlite.acceptSourceEntity(exactFact)
                sqlite.finishToV2(sqliteOutput, bindings, reconciliation)
            }
            assertContentEquals(memoryBytes, sqliteOutput.toByteArray())
            OracleSchemas.validate(
                FullTreeFunctionObservationsV2.SCHEMA_NAME,
                OracleJson.parseCanonical(sqliteOutput.toByteArray()),
            )
            FullTreeFunctionObservationSqlite.openV2(
                privateDirectory(root.resolve("sqlite-overlong")),
                shard,
                sqliteLimits,
            ).use { sqlite ->
                assertFailsWith<FullTreeFunctionObservationV2Exception> {
                    sqlite.acceptSourceEntity(overlongFact)
                }
            }
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
            fun boundDocument(revision: String?): Pair<JsonObject, FullTreeFunctionObservationV2IdentityReconciliation> {
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
                    FullTreeSourceEntityKind.NO_RANGE_DEFINITION,
                    FullTreeIdentityObservability.OBSERVABLE,
                    FullTreeDenominatorDisposition.NON_SCOREABLE,
                    fields,
                )
                val anchorIndex = FullTreeFunctionObservationV2AnchorIndex(4L, 4096L)
                anchorIndex.accept(requireNotNull(row.semanticAnchorCandidateId), row.sourceEntityId)
                anchorIndex.acceptSourceEntityPopulation(shard.identifier, listOf(row))
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
            val validFact = FullTreeSourceEntityFact.fromCanonicalJson(
                valid.getValue("sourceEntities").jsonArray.single().jsonObject,
            )
            val changedCoordinates = JsonObject(
                requireNotNull(validFact.semanticAnchorFields).canonicalJson().toMutableMap().apply {
                    put("declarationFileIndex", JsonPrimitive(9))
                    put("declarationColumn", JsonPrimitive(13))
                },
            )
            val changedCoordinatesFact = FullTreeSourceEntityFact.fromCanonicalJson(
                JsonObject(validFact.canonicalJson().toMutableMap().apply {
                    put("semanticAnchorFields", changedCoordinates)
                }),
            )
            assertEquals(validFact.semanticAnchorCandidateId, changedCoordinatesFact.semanticAnchorCandidateId)
            val changedCoordinatesFailure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.composeEnvelope(
                    v1ProjectionForCompose(valid),
                    listOf(changedCoordinatesFact),
                    validReconciliation,
                    8L * 1024L * 1024L,
                )
            }
            assertTrue(changedCoordinatesFailure.message.orEmpty().contains("scan receipt"))

            val fabricatedUnknownReason = validFact.copy(
                identityObservability = FullTreeIdentityObservability.UNKNOWN,
                reasonCodes = listOf("unknown-reference-edge"),
            )
            val fabricatedUnknownReasonDocument = FullTreeFunctionObservationsV2.composeEnvelope(
                v1ProjectionForCompose(valid),
                listOf(fabricatedUnknownReason),
                validReconciliation,
                8L * 1024L * 1024L,
            )
            val fabricatedUnknownReasonFailure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    fabricatedUnknownReasonDocument,
                    scope,
                    inventory,
                    inventorySha,
                    shard,
                    validReconciliation,
                )
            }
            assertTrue(fabricatedUnknownReasonFailure.message.orEmpty().contains("scan receipt"))

            for ((state, observability) in listOf(
                FullTreeSourceIdentityEdgeState.MISSING_TARGET to FullTreeIdentityObservability.UNKNOWN,
                FullTreeSourceIdentityEdgeState.CYCLIC to FullTreeIdentityObservability.AMBIGUOUS,
            )) {
                val unresolvedEdge = FullTreeSourceIdentityEdge(
                    kind = FullTreeSourceIdentityEdgeKind.SPECIFICATION,
                    source = validFact.physicalDie,
                    target = null,
                    referenceForm = "0x${FULL_TREE_DW_FORM_REF1.toString(16)}",
                    rawReference = "0x100",
                    state = state,
                    reasonCode = when (state) {
                        FullTreeSourceIdentityEdgeState.MISSING_TARGET ->
                            "target-not-retained-or-not-a-die-boundary"
                        FullTreeSourceIdentityEdgeState.CYCLIC -> "reference-cycle"
                        else -> error("unexpected unresolved edge state")
                    },
                )
                val forgedFact = validFact.copy(identityObservability = observability, edges = listOf(unresolvedEdge))
                val forgedIndex = FullTreeFunctionObservationV2AnchorIndex(4L, 4096L)
                forgedIndex.accept(requireNotNull(forgedFact.semanticAnchorCandidateId), forgedFact.sourceEntityId)
                forgedIndex.acceptSourceEntityPopulation(
                    shard.identifier,
                    listOf(forgedFact),
                    maximumCanonicalBytes = scope.document.controlObject("bounds")
                        .controlObject("perShard").controlLong("serializedBytes"),
                )
                val forgedReconciliation = forgedIndex.reconciliation()
                val forgedDocument = FullTreeFunctionObservationsV2.composeEnvelope(
                    v1ProjectionForCompose(valid),
                    listOf(forgedFact),
                    forgedReconciliation,
                    8L * 1024L * 1024L,
                )
                val failure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                    FullTreeFunctionObservationsV2.validateEnvelope(
                        forgedDocument,
                        scope,
                        inventory,
                        inventorySha,
                        shard,
                        forgedReconciliation,
                    )
                }
                assertTrue(failure.message.orEmpty().contains("fixed-width DWARF form"))
            }

            fun unsupportedReferenceDocument(
                form: Long,
                raw: String,
            ): Pair<JsonObject, FullTreeFunctionObservationV2IdentityReconciliation> {
                val edge = FullTreeSourceIdentityEdge(
                    kind = FullTreeSourceIdentityEdgeKind.SPECIFICATION,
                    source = validFact.physicalDie,
                    target = null,
                    referenceForm = "0x${form.toString(16)}",
                    rawReference = raw,
                    state = FullTreeSourceIdentityEdgeState.UNSUPPORTED,
                    reasonCode = "unsupported-reference-form",
                )
                val forgedFact = validFact.copy(
                    identityObservability = FullTreeIdentityObservability.UNKNOWN,
                    reasonCodes = listOf("unknown-reference-edge"),
                    edges = listOf(edge),
                )
                val forgedIndex = FullTreeFunctionObservationV2AnchorIndex(4L, 4096L)
                forgedFact.semanticAnchorCandidateId?.let {
                    forgedIndex.accept(it, forgedFact.sourceEntityId)
                }
                forgedIndex.acceptSourceEntityPopulation(shard.identifier, listOf(forgedFact))
                val forgedReconciliation = forgedIndex.reconciliation()
                return FullTreeFunctionObservationsV2.composeEnvelope(
                    v1ProjectionForCompose(valid),
                    listOf(forgedFact),
                    forgedReconciliation,
                    8L * 1024L * 1024L,
                ) to forgedReconciliation
            }

            val validUnsupportedForm = unsupportedReferenceDocument(
                FULL_TREE_DW_FORM_REF_SUP4,
                "0xffffffff",
            )
            FullTreeFunctionObservationsV2.validateEnvelope(
                validUnsupportedForm.first,
                scope,
                inventory,
                inventorySha,
                shard,
                validUnsupportedForm.second,
            )
            val supportedFormLabeledUnsupported = unsupportedReferenceDocument(
                FULL_TREE_DW_FORM_REF1,
                "0x1",
            )
            val unsupportedFormFailure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    supportedFormLabeledUnsupported.first,
                    scope,
                    inventory,
                    inventorySha,
                    shard,
                    supportedFormLabeledUnsupported.second,
                )
            }
            assertTrue(unsupportedFormFailure.message.orEmpty().contains("does not classify as unsupported"))

            val overWidthSup4 = unsupportedReferenceDocument(
                FULL_TREE_DW_FORM_REF_SUP4,
                "0x100000000",
            )
            val overWidthSup4Failure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    overWidthSup4.first,
                    scope,
                    inventory,
                    inventorySha,
                    shard,
                    overWidthSup4.second,
                )
            }
            assertTrue(overWidthSup4Failure.message.orEmpty().contains("fixed-width DWARF form"))

            val (missingRevision, missingRevisionReconciliation) = boundDocument(null)
            val missingRevisionFailure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    missingRevision,
                    scope,
                    inventory,
                    inventorySha,
                    shard,
                    missingRevisionReconciliation,
                )
            }
            assertTrue(missingRevisionFailure.message.orEmpty().contains("revision"))

            val incompleteFields = FullTreeSourceAnchorFields(
                sourcePath = "source/revision-bound.h",
                declarationFileIndex = 1L,
                declarationLine = null,
                declarationColumn = null,
                language = 33L,
                lexicalContext = listOf("sample"),
                sourceName = "revision_bound",
                signature = listOf("void ()"),
                authenticatedSourceRevision = null,
            )
            val incompleteRow = fact(
                physical.copy(dieOffset = "0x457"),
                FullTreeSourceEntityKind.DECLARATION_ONLY,
                FullTreeIdentityObservability.UNOBSERVABLE,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                incompleteFields,
                reasons = listOf("unknown-declaration-location"),
            )
            val incompleteIndex = FullTreeFunctionObservationV2AnchorIndex(4L, 4096L)
            incompleteIndex.acceptSourceEntityPopulation(shard.identifier, listOf(incompleteRow))
            val incompleteReconciliation = incompleteIndex.reconciliation()
            val incompleteAccumulator = FullTreeFunctionObservationAccumulatorV2(shard)
            incompleteAccumulator.recordScannedDies(1L)
            incompleteAccumulator.acceptSourceEntity(incompleteRow)
            val incompleteAnchorDocument = incompleteAccumulator.finish(
                inventoryIndexSha256 = inventory.controlString("indexSha256"),
                richArtifactSha256 = richSha,
                scopeSha256 = scope.sha256,
                reconciliation = incompleteReconciliation,
            )
            val incompleteRevisionFailure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    incompleteAnchorDocument,
                    scope,
                    inventory,
                    inventorySha,
                    shard,
                    incompleteReconciliation,
                )
            }
            assertTrue(incompleteRevisionFailure.message.orEmpty().contains("revision"))

            val (forged, forgedReconciliation) = boundDocument("forged-revision")
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

            val receipt = first.outputs.first { candidate ->
                if (candidate.sourceEntities == 0L) return@first false
                val rows = OracleJson.parseCanonical(
                    Files.readAllBytes(firstRoot.resolve("outputs/${candidate.shardId}.json")),
                ).jsonObject.getValue("sourceEntities").jsonArray.map {
                    FullTreeSourceEntityFact.fromCanonicalJson(it.jsonObject)
                }
                rows.any { it.semanticAnchorFields != null } && rows.any {
                    it.semanticAnchorCandidateId != null && it.candidateCollisionSourceEntityIds.isEmpty()
                }
            }
            val shard = firstInput.getValue(receipt.shardId)
            val document = OracleJson.parseCanonical(
                Files.readAllBytes(firstRoot.resolve("outputs/${receipt.shardId}.json")),
            ) as JsonObject
            val originalRows = document.getValue("sourceEntities").jsonArray.map {
                FullTreeSourceEntityFact.fromCanonicalJson(it.jsonObject)
            }
            val source = originalRows.first { it.semanticAnchorFields != null }
            val alternateKind = if (source.kind == FullTreeSourceEntityKind.NO_RANGE_DEFINITION) {
                FullTreeSourceEntityKind.DECLARATION_ONLY
            } else {
                FullTreeSourceEntityKind.NO_RANGE_DEFINITION
            }
            val alternate = source.copy(
                sourceEntityId = source.physicalDie.sourceEntityId(alternateKind),
                kind = alternateKind,
                denominatorDisposition = FullTreeDenominatorDisposition.NON_SCOREABLE,
                semanticAnchorCandidateId = source.semanticAnchorFields?.candidateId(
                    requireNotNull(alternateKind.anchorKind()),
                ),
            )
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.composeEnvelope(
                    v1ProjectionForCompose(document),
                    listOf(source, alternate),
                    first.reconciliation,
                    8L * 1024L * 1024L,
                )
            }
            val duplicatedRows = originalRows + alternate
            val duplicatedCounts = JsonObject(document.controlObject("counts").toMutableMap().apply {
                put("sourceEntities", JsonPrimitive(duplicatedRows.size))
                put("sourceEntitiesByKind", sourceKindCounts(duplicatedRows))
                put("sourceEntitiesByObservability", sourceObservabilityCounts(duplicatedRows))
                put("sourceEntitiesByDenominatorDisposition", sourceDispositionCounts(duplicatedRows))
            })
            val duplicatedDocument = JsonObject(document.toMutableMap().apply {
                put("sourceEntities", JsonArray(duplicatedRows.map(FullTreeSourceEntityFact::canonicalJson)))
                put("counts", duplicatedCounts)
            })
            val duplicateFailure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    duplicatedDocument,
                    scope,
                    inventory,
                    inventorySha,
                    shard,
                    first.reconciliation,
                )
            }
            assertTrue(duplicateFailure.message.orEmpty().contains("duplicate physical DIE locator"))

            val digestSubject = originalRows.first {
                it.semanticAnchorFields != null && it.semanticAnchorCandidateId != null &&
                    it.candidateCollisionSourceEntityIds.isEmpty()
            }
            val digestFields = copyAnchorFields(
                requireNotNull(digestSubject.semanticAnchorFields),
                authenticatedFileSha256 = "d".repeat(64),
            )
            val forgedDigestFact = digestSubject.copy(
                semanticAnchorFields = digestFields,
                semanticAnchorCandidateId = digestFields.candidateId(requireNotNull(digestSubject.kind.anchorKind())),
            )
            val forgedDigestRows = originalRows.map { fact ->
                if (fact.sourceEntityId == digestSubject.sourceEntityId) forgedDigestFact else fact
            }
            val forgedDigestDocument = JsonObject(document.toMutableMap().apply {
                put("sourceEntities", JsonArray(forgedDigestRows.map(FullTreeSourceEntityFact::canonicalJson)))
            })
            val fileDigestFailure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    forgedDigestDocument,
                    scope,
                    inventory,
                    inventorySha,
                    shard,
                    first.reconciliation,
                )
            }
            assertTrue(fileDigestFailure.message.orEmpty().contains("authenticated scan receipt"))

            val offsetSource = originalRows.first {
                it.semanticAnchorCandidateId != null && it.candidateCollisionSourceEntityIds.isEmpty()
            }
            val offsetSubject = offsetSource.copy(edges = emptyList())
            val movedDie = offsetSubject.physicalDie.copy(dieOffset = "0x7fffffffffffffff")
            val forgedOffsetFact = offsetSubject.copy(
                sourceEntityId = movedDie.sourceEntityId(offsetSubject.kind),
                physicalDie = movedDie,
            )
            val offsetFacts = originalRows.map { fact ->
                if (fact.sourceEntityId == offsetSubject.sourceEntityId) forgedOffsetFact else fact
            }
            val forgedOffsetDocument = JsonObject(document.toMutableMap().apply {
                put("sourceEntities", JsonArray(offsetFacts.map(FullTreeSourceEntityFact::canonicalJson)))
            })
            fun publishForgedDocument(label: String, forgedDocument: JsonObject): BoundedShardRunBinding {
                val prepared = privateDirectory(root.resolve("$label-prepared"))
                val preparedOutputs = first.binding.outputs.map { outputBinding ->
                    val bytes = if (outputBinding.shardId == receipt.shardId) {
                        FullTreeFunctionObservationsV2.canonicalEnvelopeBytes(forgedDocument)
                    } else {
                        Files.readAllBytes(firstRoot.resolve("outputs/${outputBinding.shardId}.json"))
                    }
                    val path = prepared.resolve("${outputBinding.shardId}.json")
                    Files.write(path, bytes)
                    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
                    BoundedShardPreparedOutput(
                        shardId = outputBinding.shardId,
                        inputSha256 = outputBinding.inputSha256,
                        output = path,
                        outputSha256 = OracleArtifacts.sha256(bytes),
                        outputBytes = bytes.size.toLong(),
                        entities = outputBinding.entities,
                    )
                }
                val parent = privateDirectory(root.resolve("$label-run"))
                return BoundedShardRunPublisher.publish(
                    target = parent.resolve("run"),
                    runId = first.binding.run.controlString("id"),
                    preparedOutputs = preparedOutputs,
                    bounds = boundedRunBounds(first.binding.run.controlObject("bounds")),
                    semanticValidator = BoundedShardOutputSemanticValidator {},
                )
            }
            fun assertRawReexecutionRejects(forged: BoundedShardRunBinding) {
                val rawFailure = assertFailsWith<FullTreeFunctionObservationV2RunException> {
                    FullTreeFunctionObservationV2RunPublisher.loadAndValidate(
                        candidateRoot = forged.root,
                        expectedIndexArtifactSha256 = forged.indexArtifactSha256,
                        richArtifact = fixture.richArtifact,
                        inventoryPath = fixture.inventory,
                        scope = scope,
                        scratchParent = scratch,
                    )
                }
                assertTrue(rawFailure.message.orEmpty().contains("raw-input rederivation"))
            }
            val physicalOffsetFailure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    forgedOffsetDocument, scope, inventory, inventorySha, shard, first.reconciliation,
                )
            }
            assertTrue(physicalOffsetFailure.message.orEmpty().contains("physical DIE locators"))
            assertRawReexecutionRejects(publishForgedDocument("forged-offset", forgedOffsetDocument))

            val emittedRva = document.getValue("emitted").jsonArray.single()
                .jsonObject.getValue("rva").jsonPrimitive.content
            val linkSubject = originalRows.first { it.semanticAnchorFields != null }

            val patternTarget = linkSubject.physicalDie.copy(
                dieOffset = if (linkSubject.physicalDie.dieOffset == "0x777") "0x778" else "0x777",
            )
            val patternAnchorFields = FullTreeSourceAnchorFields(
                sourcePath = "source/include/fixture.h",
                declarationFileIndex = 1L,
                declarationLine = 17L,
                declarationColumn = 3L,
                language = 33L,
                lexicalContext = listOf("fixture"),
                sourceName = "linked_template",
                signature = listOf("int (int)"),
                templateFormalParameters = listOf("type:T"),
                authenticatedSourceRevision = scope.sourceLock.controlObject("revision").controlString("commit"),
            )
            val patternCandidateId = requireNotNull(
                patternAnchorFields.candidateId(FullTreeSourceAnchorKind.TEMPLATE_PATTERN),
            )
            val patternClaims = FullTreeFunctionObservationV2AnchorIndex(4L, 4096L)
            patternClaims.accept(
                FullTreeSourceAnchorKind.TEMPLATE_PATTERN,
                patternCandidateId,
                patternTarget.sourceEntityId(FullTreeSourceAnchorKind.TEMPLATE_PATTERN),
            )
            fun templateInstanceFields(patternCandidate: String) = FullTreeSourceAnchorFields(
                sourcePath = "source/include/fixture.h",
                declarationFileIndex = 1L,
                declarationLine = 17L,
                declarationColumn = 3L,
                language = 33L,
                lexicalContext = listOf("fixture"),
                sourceName = "linked_template<int>",
                signature = listOf("int (int)"),
                templatePatternAnchorCandidateId = patternCandidate,
                templateActualArguments = listOf("type:int"),
                authenticatedSourceRevision = scope.sourceLock.controlObject("revision").controlString("commit"),
            )
            val patternEdge = FullTreeSourceIdentityEdge(
                kind = FullTreeSourceIdentityEdgeKind.SPECIFICATION,
                source = linkSubject.physicalDie,
                target = patternTarget,
                referenceForm = "0x10",
                rawReference = patternTarget.dieOffset,
                state = FullTreeSourceIdentityEdgeState.RESOLVED,
                reasonCode = null,
            )
            val validPatternInstanceFields = templateInstanceFields(patternCandidateId)
            val validPatternInstance = FullTreeSourceEntityFact(
                sourceEntityId = linkSubject.physicalDie.sourceEntityId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE),
                physicalDie = linkSubject.physicalDie,
                kind = FullTreeSourceEntityKind.TEMPLATE_INSTANCE,
                identityObservability = FullTreeIdentityObservability.UNKNOWN,
                denominatorDisposition = FullTreeDenominatorDisposition.NON_SCOREABLE,
                semanticAnchorFields = validPatternInstanceFields,
                semanticAnchorCandidateId = requireNotNull(
                    validPatternInstanceFields.candidateId(FullTreeSourceAnchorKind.TEMPLATE_INSTANCE),
                ),
                resolvedSemanticIdentityId = null,
                candidateCollisionSourceEntityIds = emptyList(),
                linkedEmittedRva = null,
                reasonCodes = listOf("unknown-template-pattern-reference"),
                edges = listOf(patternEdge),
            )
            patternClaims.acceptSourceEntityPopulation(shard.identifier, listOf(validPatternInstance))
            val patternReconciliation = patternClaims.reconciliation()
            val validPatternDocument = FullTreeFunctionObservationsV2.composeEnvelope(
                v1ProjectionForCompose(document), listOf(validPatternInstance), patternReconciliation,
                8L * 1024L * 1024L,
            )
            FullTreeFunctionObservationsV2.validateEnvelope(
                validPatternDocument, scope, inventory, inventorySha, shard, patternReconciliation,
            )
            val forgedPatternFields = templateInstanceFields("d".repeat(64))
            val forgedPatternInstance = validPatternInstance.copy(semanticAnchorFields = forgedPatternFields)
            val forgedPatternDocument = FullTreeFunctionObservationsV2.composeEnvelope(
                v1ProjectionForCompose(document), listOf(forgedPatternInstance), patternReconciliation,
                8L * 1024L * 1024L,
            )
            val forgedPatternFailure = assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeFunctionObservationsV2.validateEnvelope(
                    forgedPatternDocument, scope, inventory, inventorySha, shard, patternReconciliation,
                )
            }
            assertTrue(forgedPatternFailure.message.orEmpty().contains("referenced pattern DIE"))

            // This small control ELF has no emitted template-instance census row. Build a
            // fixture-only, schema-valid template row on its authenticated physical locator so
            // the validator's allowed target membership can be exercised independently from the
            // run publisher's raw-input rederivation.
            val linkFields = FullTreeSourceAnchorFields(
                sourcePath = "source/include/fixture.h",
                declarationFileIndex = 1L,
                declarationLine = 17L,
                declarationColumn = 3L,
                language = 33L,
                lexicalContext = listOf("fixture"),
                sourceName = "linked_template<int>",
                signature = listOf("int (int)"),
                templateActualArguments = listOf("type:int"),
                authenticatedSourceRevision = scope.sourceLock.controlObject("revision").controlString("commit"),
            )
            val linked = FullTreeSourceEntityFact(
                sourceEntityId = linkSubject.physicalDie.sourceEntityId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE),
                physicalDie = linkSubject.physicalDie,
                kind = FullTreeSourceEntityKind.TEMPLATE_INSTANCE,
                identityObservability = FullTreeIdentityObservability.UNKNOWN,
                denominatorDisposition = FullTreeDenominatorDisposition.EMITTED_RVA_LINK,
                semanticAnchorFields = linkFields,
                semanticAnchorCandidateId = requireNotNull(
                    linkFields.candidateId(FullTreeSourceAnchorKind.TEMPLATE_INSTANCE),
                ),
                resolvedSemanticIdentityId = null,
                candidateCollisionSourceEntityIds = emptyList(),
                linkedEmittedRva = emittedRva,
                reasonCodes = listOf("unknown-template-pattern-reference"),
                edges = emptyList(),
            )
            val linkedClaims = FullTreeFunctionObservationV2AnchorIndex(2L, 4096L)
            linkedClaims.accept(requireNotNull(linked.semanticAnchorCandidateId), linked.sourceEntityId)
            linkedClaims.acceptSourceEntityPopulation(shard.identifier, listOf(linked))
            val linkedReconciliation = linkedClaims.reconciliation()
            val linkedDocument = FullTreeFunctionObservationsV2.composeEnvelope(
                v1ProjectionForCompose(document), listOf(linked), linkedReconciliation, 8L * 1024L * 1024L,
            )
            FullTreeFunctionObservationsV2.validateEnvelope(
                linkedDocument, scope, inventory, inventorySha, shard, linkedReconciliation,
            )
            val structuralSubject = originalRows.firstOrNull { source ->
                source.semanticAnchorCandidateId != null && source.candidateCollisionSourceEntityIds.isEmpty() &&
                    originalRows.any { target ->
                        target.physicalDie.unitId == source.physicalDie.unitId &&
                            target.physicalDie.compilationUnitOffset == source.physicalDie.compilationUnitOffset &&
                            target.physicalDie.dieOffset.removePrefix("0x").toULong(16) >
                            source.physicalDie.dieOffset.removePrefix("0x").toULong(16)
                    }
            }
            assertTrue(structuralSubject != null, "fixture must contain two source DIEs in one CU")
            val structural = requireNotNull(structuralSubject)
            val unrelatedTarget = originalRows.first { target ->
                target.physicalDie.unitId == structural.physicalDie.unitId &&
                    target.physicalDie.compilationUnitOffset == structural.physicalDie.compilationUnitOffset &&
                    target.physicalDie.dieOffset.removePrefix("0x").toULong(16) >
                    structural.physicalDie.dieOffset.removePrefix("0x").toULong(16)
            }.physicalDie
            val forgedStructuralEdge = FullTreeSourceIdentityEdge(
                kind = FullTreeSourceIdentityEdgeKind.TYPE,
                source = structural.physicalDie,
                target = unrelatedTarget,
                referenceForm = null,
                rawReference = null,
                state = FullTreeSourceIdentityEdgeState.RESOLVED,
                reasonCode = null,
            )
            val forgedStructuralFact = structural.copy(edges = listOf(forgedStructuralEdge))
            val forgedStructuralRows = originalRows.map { fact ->
                if (fact.sourceEntityId == structural.sourceEntityId) forgedStructuralFact else fact
            }
            val forgedStructuralDocument = FullTreeFunctionObservationsV2.composeEnvelope(
                v1ProjectionForCompose(document), forgedStructuralRows, first.reconciliation, 8L * 1024L * 1024L,
            )
            FullTreeFunctionObservationsV2.validateEnvelope(
                forgedStructuralDocument, scope, inventory, inventorySha, shard, first.reconciliation,
            )
            assertRawReexecutionRejects(publishForgedDocument("forged-structural-edge", forgedStructuralDocument))

            val unsafeScratch = Files.createDirectory(root.resolve("unsafe-scratch"))
            Files.setPosixFilePermissions(unsafeScratch, PosixFilePermissions.fromString("rwxrwxrwx"))
            assertFailsWith<FullTreeFunctionObservationV2RunException> {
                FullTreeFunctionObservationV2RunPublisher.loadAndValidate(
                    candidateRoot = firstRoot,
                    expectedIndexArtifactSha256 = first.binding.indexArtifactSha256,
                    richArtifact = fixture.richArtifact,
                    inventoryPath = fixture.inventory,
                    scope = scope,
                    scratchParent = unsafeScratch,
                )
            }
            assertTrue(Files.list(unsafeScratch).use { paths -> paths.findAny().isEmpty })
            assertTrue(Files.list(scratch).use { paths -> paths.findAny().isEmpty })
        }

    @Test
    fun `raw reexecution rejects a source link repointed to another real emitted RVA`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("control"))
            val originalScope = fixture.authenticatedScope()
            val mergedRules = JsonArray(
                listOf(
                    JsonObject(mapOf(
                        "componentDepth" to JsonPrimitive(1),
                        "pathPrefix" to JsonPrimitive("source/clang/"),
                        "shardPrefix" to JsonPrimitive("fixture"),
                    )),
                    JsonObject(mapOf(
                        "componentDepth" to JsonPrimitive(1),
                        "pathPrefix" to JsonPrimitive("generated/tools/clang/"),
                        "shardPrefix" to JsonPrimitive("fixture"),
                    )),
                ),
            )
            val mergedSharding = JsonObject(originalScope.document.controlObject("sharding").toMutableMap().apply {
                put("rules", mergedRules)
            })
            writeControlObject(
                fixture.scope,
                JsonObject(originalScope.document.toMutableMap().apply { put("sharding", mergedSharding) }),
            )
            val scope = fixture.authenticatedScope()
            val inventoryGeneration = FullTreeInventoryControl.generateAndPublish(
                richArtifact = fixture.richArtifact,
                scope = scope,
                output = fixture.inventory,
                maximumWorkers = 1,
            )
            assertEquals(1L, inventoryGeneration.inventory.getValue("counts").jsonObject
                .getValue("shards").jsonPrimitive.long)

            val scratch = privateDirectory(root.resolve("scratch"))
            val outputParent = privateDirectory(root.resolve("output"))
            val outputRoot = outputParent.resolve("run")
            val publication = FullTreeFunctionObservationV2RunPublisher.generateAndPublish(
                richArtifact = fixture.richArtifact,
                inventoryPath = fixture.inventory,
                scope = scope,
                scratchParent = scratch,
                outputRoot = outputRoot,
                maximumWorkers = 1,
            )
            val receipt = publication.outputs.single()
            val inventory = parseControlObject(fixture.inventory)
            val inventorySha = fixtureSha256(fixture.inventory)
            val shard = FullTreeFunctionObservations.shardInputs(
                inventory,
                inventorySha,
                scope.document,
                scope.sha256,
            ).single()
            val originalDocument = OracleJson.parseCanonical(
                Files.readAllBytes(outputRoot.resolve("outputs/${receipt.shardId}.json")),
            ) as JsonObject
            val actualRvas = originalDocument.getValue("emitted").jsonArray.map {
                it.jsonObject.getValue("rva").jsonPrimitive.content
            }.distinct()
            assertTrue(actualRvas.size >= 2, "authenticated fixture must provide two real emitted RVAs in one shard")
            val originalFacts = originalDocument.getValue("sourceEntities").jsonArray.map {
                FullTreeSourceEntityFact.fromCanonicalJson(it.jsonObject)
            }
            val subject = originalFacts.firstOrNull {
                it.semanticAnchorFields != null && it.candidateCollisionSourceEntityIds.isEmpty() &&
                    (it.kind == FullTreeSourceEntityKind.TEMPLATE_INSTANCE || originalFacts.none { other ->
                        other.physicalDie == it.physicalDie && other.kind == FullTreeSourceEntityKind.TEMPLATE_INSTANCE
                    })
            }
            assertTrue(subject != null, "authenticated fixture must provide a source row for the link mutation")
            val source = requireNotNull(subject)
            val fields = FullTreeSourceAnchorFields(
                sourcePath = "source/clang/lib/Driver/main.cpp",
                declarationFileIndex = 1L,
                declarationLine = 1L,
                declarationColumn = null,
                language = 33L,
                lexicalContext = emptyList(),
                sourceName = "publisher_link_probe<int>",
                signature = listOf("return:void"),
                templateActualArguments = listOf("type:int"),
                authenticatedSourceRevision = scope.sourceLock.controlObject("revision").controlString("commit"),
            )
            val linked = FullTreeSourceEntityFact(
                sourceEntityId = source.physicalDie.sourceEntityId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE),
                physicalDie = source.physicalDie,
                kind = FullTreeSourceEntityKind.TEMPLATE_INSTANCE,
                identityObservability = FullTreeIdentityObservability.UNKNOWN,
                denominatorDisposition = FullTreeDenominatorDisposition.EMITTED_RVA_LINK,
                semanticAnchorFields = fields,
                semanticAnchorCandidateId = requireNotNull(fields.candidateId(FullTreeSourceAnchorKind.TEMPLATE_INSTANCE)),
                resolvedSemanticIdentityId = null,
                candidateCollisionSourceEntityIds = emptyList(),
                linkedEmittedRva = actualRvas.first(),
                reasonCodes = listOf("unknown-template-pattern-reference"),
                edges = emptyList(),
            )
            val linkedFacts = FullTreeSourceEntityFact.deterministicOrder(
                originalFacts.map { if (it.sourceEntityId == source.sourceEntityId) linked else it },
            )
            val alternateRva = actualRvas.first { it != linked.linkedEmittedRva }
            val forgedLink = linked.copy(linkedEmittedRva = alternateRva)
            val forgedFacts = FullTreeSourceEntityFact.deterministicOrder(
                linkedFacts.map { if (it.sourceEntityId == linked.sourceEntityId) forgedLink else it },
            )
            val forgedCounts = JsonObject(originalDocument.getValue("counts").jsonObject.toMutableMap().apply {
                put("sourceEntities", JsonPrimitive(forgedFacts.size))
                put("sourceEntitiesByKind", sourceKindCounts(forgedFacts))
                put("sourceEntitiesByObservability", sourceObservabilityCounts(forgedFacts))
                put("sourceEntitiesByDenominatorDisposition", sourceDispositionCounts(forgedFacts))
            })
            val forgedDocument = JsonObject(originalDocument.toMutableMap().apply {
                put("sourceEntities", JsonArray(forgedFacts.map(FullTreeSourceEntityFact::canonicalJson)))
                put("counts", forgedCounts)
            })

            val prepared = privateDirectory(root.resolve("prepared"))
            val preparedOutputs = publication.binding.outputs.map { outputBinding ->
                val bytes = FullTreeFunctionObservationsV2.canonicalEnvelopeBytes(forgedDocument)
                val path = prepared.resolve("${outputBinding.shardId}.json")
                Files.write(path, bytes)
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
                BoundedShardPreparedOutput(
                    shardId = outputBinding.shardId,
                    inputSha256 = outputBinding.inputSha256,
                    output = path,
                    outputSha256 = OracleArtifacts.sha256(bytes),
                    outputBytes = bytes.size.toLong(),
                    entities = outputBinding.entities,
                )
            }
            val forgedParent = privateDirectory(root.resolve("forged"))
            val forgedBinding = BoundedShardRunPublisher.publish(
                target = forgedParent.resolve("run"),
                runId = publication.binding.run.controlString("id"),
                preparedOutputs = preparedOutputs,
                bounds = boundedRunBounds(publication.binding.run.controlObject("bounds")),
                semanticValidator = BoundedShardOutputSemanticValidator {},
            )
            val rejection = assertFailsWith<FullTreeFunctionObservationV2RunException> {
                FullTreeFunctionObservationV2RunPublisher.loadAndValidate(
                    candidateRoot = forgedBinding.root,
                    expectedIndexArtifactSha256 = forgedBinding.indexArtifactSha256,
                    richArtifact = fixture.richArtifact,
                    inventoryPath = fixture.inventory,
                    scope = scope,
                    scratchParent = scratch,
                )
            }
            assertTrue(rejection.message.orEmpty().contains("raw-input rederivation"))
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
                FullTreeIdentityObservability.UNOBSERVABLE,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                fields,
            )
            assertFailsWith<IllegalArgumentException> {
                fact(
                    physical,
                    FullTreeSourceEntityKind.UNRESOLVED,
                    FullTreeIdentityObservability.UNKNOWN,
                    FullTreeDenominatorDisposition.UNKNOWN,
                    fields,
                )
            }
            val unresolved = fact(
                physical.copy(dieOffset = "0x401"),
                FullTreeSourceEntityKind.UNRESOLVED,
                FullTreeIdentityObservability.UNKNOWN,
                FullTreeDenominatorDisposition.UNKNOWN,
                fields = null,
                reasons = listOf("unsupported-source-identity"),
            )
            assertFailsWith<IllegalArgumentException> {
                unresolved.copy(denominatorDisposition = FullTreeDenominatorDisposition.NON_SCOREABLE)
            }
            assertFailsWith<IllegalArgumentException> {
                FullTreeSourceIdentityEdge(
                    kind = FullTreeSourceIdentityEdgeKind.SPECIFICATION,
                    source = physical,
                    target = null,
                    referenceForm = "0x13",
                    rawReference = "0x40",
                    state = FullTreeSourceIdentityEdgeState.MISSING_TARGET,
                    reasonCode = null,
                )
            }
            val duplicateStructuralEdge = FullTreeSourceIdentityEdge(
                kind = FullTreeSourceIdentityEdgeKind.TYPE,
                source = physical,
                target = physical.copy(dieOffset = "0x402"),
                referenceForm = null,
                rawReference = null,
                state = FullTreeSourceIdentityEdgeState.RESOLVED,
                reasonCode = null,
            )
            assertFailsWith<IllegalArgumentException> {
                fact(
                    physical.copy(dieOffset = "0x403"),
                    FullTreeSourceEntityKind.NO_RANGE_DEFINITION,
                    FullTreeIdentityObservability.UNKNOWN,
                    FullTreeDenominatorDisposition.NON_SCOREABLE,
                    fields = null,
                    reasons = listOf("unknown-type-reference"),
                    edges = listOf(duplicateStructuralEdge, duplicateStructuralEdge),
                )
            }
            val accumulator = FullTreeFunctionObservationAccumulatorV2(shard)
            accumulator.acceptSourceEntity(row)
            assertFailsWith<FullTreeFunctionObservationV2Exception> { accumulator.acceptSourceEntity(row) }
            val alternateKind = FullTreeSourceEntityKind.NO_RANGE_DEFINITION
            val sameDieOtherKind = row.copy(
                sourceEntityId = physical.sourceEntityId(alternateKind),
                kind = alternateKind,
                identityObservability = FullTreeIdentityObservability.OBSERVABLE,
                denominatorDisposition = FullTreeDenominatorDisposition.NON_SCOREABLE,
                semanticAnchorCandidateId = fields.candidateId(requireNotNull(alternateKind.anchorKind())),
            )
            assertNotEquals(row.sourceEntityId, sameDieOtherKind.sourceEntityId)
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                accumulator.acceptSourceEntity(sameDieOtherKind)
            }

            val sqliteScratch = privateDirectory(root.resolve("sqlite-scratch"))
            FullTreeFunctionObservationSqlite.openV2(
                sqliteScratch,
                shard,
                FullTreeFunctionObservationSqliteLimits(
                    maximumDatabaseBytes = 4L * 1024L * 1024L,
                    maximumOutputBytes = 8L * 1024L * 1024L,
                    observations = FullTreeFunctionObservationAccumulatorLimits(
                        maximumEntities = 100,
                        maximumEmittedRvas = 100,
                        maximumNonEmittedGroups = 100,
                        maximumRetainedBytes = 8L * 1024L * 1024L,
                    ),
                    maximumCacheBytes = 64 * 1024,
                    databaseCheckpointRows = 2,
                    checkpoint = FullTreeFunctionObservationSqliteCheckpoint {},
                ),
            ).use { sink ->
                sink.acceptSourceEntity(row)
                assertFailsWith<FullTreeFunctionObservationSqliteException> {
                    sink.acceptSourceEntity(sameDieOtherKind)
                }
            }

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
            assertFailsWith<IllegalArgumentException> { row.copy(edges = listOf(edge, edge)) }
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

            val inlineFields = FullTreeSourceAnchorFields(
                sourcePath = "source/caller.cpp",
                declarationFileIndex = 1L,
                declarationLine = 11L,
                declarationColumn = 4L,
                language = 33L,
                lexicalContext = listOf("caller"),
                sourceName = "callee",
                signature = listOf("void ()"),
                inlineCalleeAnchorCandidateId = "a".repeat(64),
                inlineOwnerAnchorCandidateId = "b".repeat(64),
                inlineCallFile = "source/caller.cpp",
                inlineCallLine = 12L,
                inlineCallColumn = 5L,
                inlinePathAnchorCandidateIds = emptyList(),
            )
            assertFailsWith<IllegalArgumentException> {
                FullTreeSourceAnchorFields(
                    sourcePath = "source/caller.cpp",
                    declarationFileIndex = 1L,
                    declarationLine = 11L,
                    declarationColumn = 4L,
                    language = 33L,
                    lexicalContext = listOf("caller"),
                    sourceName = "callee",
                    signature = listOf("void ()"),
                    inlineCalleeAnchorCandidateId = "a".repeat(64),
                    inlineOwnerAnchorCandidateId = "b".repeat(64),
                    inlineCallFile = "/outside.cpp",
                    inlineCallLine = 12L,
                    inlineCallColumn = 5L,
                    inlinePathAnchorCandidateIds = emptyList(),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                FullTreeSourceAnchorFields(
                    sourcePath = "source/caller.cpp",
                    declarationFileIndex = 1L,
                    declarationLine = 11L,
                    declarationColumn = 4L,
                    language = 33L,
                    lexicalContext = listOf("caller"),
                    sourceName = "callee",
                    signature = listOf("void ()"),
                    inlineCalleeAnchorCandidateId = "a".repeat(64),
                    inlineOwnerAnchorCandidateId = "b".repeat(64),
                    inlineCallFile = "../outside.cpp",
                    inlineCallLine = 12L,
                    inlineCallColumn = 5L,
                    inlinePathAnchorCandidateIds = emptyList(),
                )
            }
            val inlineRow = fact(
                physical,
                FullTreeSourceEntityKind.INLINE_INSTANCE,
                FullTreeIdentityObservability.OBSERVABLE,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                inlineFields,
            )
            for (disposition in listOf("unknown", "ambiguous")) {
                val invalidDisposition = JsonObject(inlineRow.canonicalJson().toMutableMap().apply {
                    put("denominatorDisposition", JsonPrimitive(disposition))
                })
                assertFailsWith<FullTreeFunctionObservationV2Exception> {
                    FullTreeSourceEntityFact.fromCanonicalJson(invalidDisposition)
                }
            }
            val templateFields = FullTreeSourceAnchorFields(
                sourcePath = "source/template.h",
                declarationFileIndex = 1L,
                declarationLine = 24L,
                declarationColumn = null,
                language = 33L,
                lexicalContext = listOf("fixture"),
                sourceName = "mutated_template<int>",
                signature = listOf("int (int)"),
                templateActualArguments = listOf("type:int"),
            )
            val templateRow = fact(
                physical.copy(dieOffset = "0x408"),
                FullTreeSourceEntityKind.TEMPLATE_INSTANCE,
                FullTreeIdentityObservability.UNKNOWN,
                FullTreeDenominatorDisposition.NON_SCOREABLE,
                templateFields,
                reasons = listOf("unknown-template-pattern-reference"),
            )
            val ambiguousTemplateDisposition = JsonObject(templateRow.canonicalJson().toMutableMap().apply {
                put("denominatorDisposition", JsonPrimitive("ambiguous"))
            })
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeSourceEntityFact.fromCanonicalJson(ambiguousTemplateDisposition)
            }
            val forgedInlineFields = JsonObject(inlineFields.canonicalJson().toMutableMap().apply {
                put("inlineCallFile", JsonPrimitive("../outside.cpp"))
            })
            val forgedAnchorPreimage = JsonObject(
                mapOf(
                    "fields" to JsonObject(forgedInlineFields.toMutableMap().apply {
                        remove("declarationFileIndex")
                        remove("declarationColumn")
                    }),
                    "kind" to JsonPrimitive(FullTreeSourceAnchorKind.INLINE_INSTANCE.wireValue),
                    "version" to JsonPrimitive(6),
                ),
            )
            val forgedDigest = MessageDigest.getInstance("SHA-256").apply {
                update("decomp-thing:full-tree-source-anchor-v1\u0000".toByteArray(StandardCharsets.UTF_8))
                update(OracleJson.canonicalBytes(forgedAnchorPreimage))
            }.digest().joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
            val forgedInlineRow = JsonObject(inlineRow.canonicalJson().toMutableMap().apply {
                put("semanticAnchorFields", forgedInlineFields)
                put("semanticAnchorCandidateId", JsonPrimitive(forgedDigest))
            })
            assertFailsWith<FullTreeFunctionObservationV2Exception> {
                FullTreeSourceEntityFact.fromCanonicalJson(forgedInlineRow)
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

    private fun v1ProjectionForCompose(document: JsonObject): JsonObject {
        val counts = JsonObject(document.controlObject("counts").toMutableMap().apply {
            remove("sourceEntities")
            remove("sourceEntitiesByKind")
            remove("sourceEntitiesByObservability")
            remove("sourceEntitiesByDenominatorDisposition")
            remove("anchorClaims")
            remove("anchorCandidateCount")
            remove("anchorCollisionCandidateCount")
        })
        val oracle = JsonObject(document.controlObject("oracle").toMutableMap().apply {
            put("configurationSha256", JsonPrimitive(FullTreeFunctionObservations.configurationSha256))
        })
        return JsonObject(document.toMutableMap().apply {
            remove("sourceEntities")
            remove("identityReconciliation")
            put("counts", counts)
            put("oracle", oracle)
            put("schemaVersion", JsonPrimitive(1))
        })
    }

    private fun sourceKindCounts(facts: List<FullTreeSourceEntityFact>) = JsonObject(
        FullTreeSourceEntityKind.entries.associate { kind ->
            kind.wireValue to JsonPrimitive(facts.count { it.kind == kind })
        }.toSortedMap(),
    )

    private fun sourceObservabilityCounts(facts: List<FullTreeSourceEntityFact>) = JsonObject(
        FullTreeIdentityObservability.entries.associate { state ->
            state.wireValue to JsonPrimitive(facts.count { it.identityObservability == state })
        }.toSortedMap(),
    )

    private fun sourceDispositionCounts(facts: List<FullTreeSourceEntityFact>) = JsonObject(
        FullTreeDenominatorDisposition.entries.associate { disposition ->
            disposition.wireValue to JsonPrimitive(facts.count { it.denominatorDisposition == disposition })
        }.toSortedMap(),
    )

    private fun boundedRunBounds(bounds: JsonObject) = BoundedShardRunPublicationBounds(
        maximumShards = bounds.controlLong("maximumShards").toInt(),
        perShardEntities = bounds.controlLong("perShardEntities"),
        wholeRunEntities = bounds.controlLong("wholeRunEntities"),
        perShardBytes = bounds.controlLong("perShardBytes"),
        wholeRunBytes = bounds.controlLong("wholeRunBytes"),
        perShardSeconds = bounds.getValue("perShardSeconds").jsonPrimitive.content.toDouble(),
        wholeRunSeconds = bounds.getValue("wholeRunSeconds").jsonPrimitive.content.toDouble(),
        perShardCpuSeconds = bounds.getValue("perShardCpuSeconds").jsonPrimitive.content.toDouble(),
        wholeRunCpuSeconds = bounds.getValue("wholeRunCpuSeconds").jsonPrimitive.content.toDouble(),
        maximumResidentBytes = bounds.controlLong("maximumResidentBytes"),
        maximumWorkers = bounds.controlLong("maximumWorkers").toInt(),
    )

    private fun copyAnchorFields(
        fields: FullTreeSourceAnchorFields,
        authenticatedFileSha256: String?,
        inlineCalleeAnchorCandidateId: String? = fields.inlineCalleeAnchorCandidateId,
        sourceName: String? = fields.sourceName,
    ) = FullTreeSourceAnchorFields(
        sourcePath = fields.sourcePath,
        declarationFileIndex = fields.declarationFileIndex,
        declarationLine = fields.declarationLine,
        declarationColumn = fields.declarationColumn,
        language = fields.language,
        lexicalContext = fields.lexicalContext,
        sourceName = sourceName,
        signature = fields.signature,
        templateFormalParameters = fields.templateFormalParameters,
        templatePatternAnchorCandidateId = fields.templatePatternAnchorCandidateId,
        templateActualArguments = fields.templateActualArguments,
        inlineCalleeAnchorCandidateId = inlineCalleeAnchorCandidateId,
        inlineOwnerAnchorCandidateId = fields.inlineOwnerAnchorCandidateId,
        inlineCallFile = fields.inlineCallFile,
        inlineCallLine = fields.inlineCallLine,
        inlineCallColumn = fields.inlineCallColumn,
        inlinePathAnchorCandidateIds = fields.inlinePathAnchorCandidateIds,
        authenticatedSourceRevision = fields.authenticatedSourceRevision,
        authenticatedSourceFileSha256 = authenticatedFileSha256,
    )

    private fun privateDirectory(path: java.nio.file.Path): java.nio.file.Path =
        Files.createDirectory(path).also {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
        }
}
