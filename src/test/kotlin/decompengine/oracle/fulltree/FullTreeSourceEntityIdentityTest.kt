package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonException
import decompengine.oracle.core.StrictJsonLimits
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

import kotlinx.serialization.json.JsonArray

class FullTreeSourceEntityIdentityTest {
    @Test
    fun `semantic anchors ignore physical DIE offsets but bind source and typed signature`() {
        val first = fields()
        val sameSourceOtherProducer = fields(declarationFileIndex = 4)
        val changedSignature = fields(signature = listOf("base:long"))

        val firstId = first.candidateId(FullTreeSourceEntityKind.DECLARATION_ONLY)
        assertEquals(firstId, sameSourceOtherProducer.candidateId(FullTreeSourceEntityKind.DECLARATION_ONLY))
        assertNotEquals(firstId, changedSignature.candidateId(FullTreeSourceEntityKind.DECLARATION_ONLY))

        val declaration = fact("0x10", FullTreeSourceEntityKind.DECLARATION_ONLY, first)
        val definition = fact("0x99", FullTreeSourceEntityKind.DECLARATION_ONLY, sameSourceOtherProducer)
        val bytesA = canonicalSourceEntityFacts(listOf(declaration, definition))
        val bytesB = canonicalSourceEntityFacts(listOf(definition, declaration))
        assertContentEquals(bytesA, bytesB)
        assertEquals(bytesA.size.toLong(), canonicalSourceEntityFactsByteLength(listOf(declaration, definition)))
        assertTrue(sourceIdentitySha256(bytesA).matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun `physical source rows remain distinct when semantic candidates collide`() {
        val candidateFields = fields()
        val first = fact("0x10", FullTreeSourceEntityKind.DECLARATION_ONLY, candidateFields)
        val second = fact("0x11", FullTreeSourceEntityKind.DECLARATION_ONLY, candidateFields)

        assertEquals(first.semanticAnchorCandidateId, second.semanticAnchorCandidateId)
        assertNotEquals(first.sourceEntityId, second.sourceEntityId)
        assertEquals(first.physicalDie.sourceEntityId(first.kind), first.sourceEntityId)
        assertEquals(second.physicalDie.sourceEntityId(second.kind), second.sourceEntityId)

        val ambiguous = first.copy(
            identityObservability = FullTreeIdentityObservability.AMBIGUOUS,
            candidateCollisionSourceEntityIds = listOf(first.sourceEntityId, second.sourceEntityId).sorted(),
            reasonCodes = listOf("duplicate-source-anchor-unproven"),
        )
        assertEquals(first.semanticAnchorCandidateId, ambiguous.semanticAnchorCandidateId)
        assertEquals(listOf(first.sourceEntityId, second.sourceEntityId).sorted(), ambiguous.candidateCollisionSourceEntityIds)
        assertContentEquals(
            canonicalSourceEntityFacts(listOf(ambiguous, second)),
            canonicalSourceEntityFacts(listOf(second, ambiguous)),
        )
        val ambiguousSecond = second.copy(
            identityObservability = FullTreeIdentityObservability.AMBIGUOUS,
            candidateCollisionSourceEntityIds = listOf(first.sourceEntityId, second.sourceEntityId).sorted(),
            reasonCodes = listOf("duplicate-source-anchor-unproven"),
        )
        val baseBytes = canonicalSourceEntityFactsByteLength(listOf(first, second))
        val expandedBytes = canonicalSourceEntityFactsByteLength(listOf(ambiguous, ambiguousSecond))
        val candidate = checkNotNull(first.semanticAnchorCandidateId)
        val expansionUpperBound = sourceIdentityCollisionExpansionUpperBound(
            listOf(first, second),
            mapOf(candidate to listOf(first.sourceEntityId, second.sourceEntityId).sorted()),
        )
        val adjustedCopyUpperBound = sourceIdentityCollisionAdjustedFactCopyUpperBound(
            listOf(first, second),
            mapOf(candidate to listOf(first.sourceEntityId, second.sourceEntityId).sorted()),
        )
        assertTrue(expansionUpperBound >= expandedBytes - baseBytes)
        assertTrue(adjustedCopyUpperBound >= baseBytes)
        assertFailsWith<IllegalArgumentException> {
            canonicalSourceEntityFacts(listOf(first, first))
        }
    }

    @Test
    fun `a duplicate outer inline anchor makes a nested inline path ambiguous`() {
        val ancestorFields = fields(sourceName = "outer_inline")
        val ancestorCandidate = checkNotNull(ancestorFields.candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION))
        val firstAncestor = fact("0x101", FullTreeSourceEntityKind.NO_RANGE_DEFINITION, ancestorFields)
        val secondAncestor = fact("0x102", FullTreeSourceEntityKind.NO_RANGE_DEFINITION, ancestorFields)

        val descendantFields = fields(
            sourceName = "inner_inline",
            inlineCalleeAnchorCandidateId = fields(sourceName = "inner_inline").candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
            inlineOwnerAnchorCandidateId = fields(sourceName = "caller").candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
            inlineCallFile = "source/clang/lib/inline-template/caller.cpp",
            inlineCallLine = 28,
            inlinePathAnchorCandidateIds = listOf(ancestorCandidate),
        )
        val nested = fact(
            "0x103",
            FullTreeSourceEntityKind.INLINE_INSTANCE,
            descendantFields,
            edges = listOf(
                FullTreeSourceIdentityEdge(
                    kind = FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN,
                    source = physical("0x103"),
                    target = physical("0x101"),
                    referenceForm = "0x11",
                    rawReference = "0x101",
                    state = FullTreeSourceIdentityEdgeState.RESOLVED,
                    reasonCode = null,
                ),
            ),
        )
        val collisionIds = listOf(firstAncestor.sourceEntityId, secondAncestor.sourceEntityId).sorted()
        val reconciled = FullTreeSourceEntityIdentityProducer.markUnprovedAnchorCollisions(
            listOf(firstAncestor, secondAncestor, nested),
            SourceIdentityAnchorCollisionReport(mapOf(ancestorCandidate to collisionIds)),
        )
        val reconciledNested = reconciled.single { it.sourceEntityId == nested.sourceEntityId }
        val baseBytes = canonicalSourceEntityFactsByteLength(listOf(nested))
        val expandedBytes = canonicalSourceEntityFactsByteLength(listOf(reconciledNested))
        val expansionUpperBound = sourceIdentityCollisionExpansionUpperBound(
            listOf(nested),
            mapOf(ancestorCandidate to collisionIds),
        )
        val adjustedCopyUpperBound = sourceIdentityCollisionAdjustedFactCopyUpperBound(
            listOf(nested),
            mapOf(ancestorCandidate to collisionIds),
        )

        assertEquals(FullTreeIdentityObservability.AMBIGUOUS, reconciledNested.identityObservability)
        assertEquals(collisionIds, reconciledNested.candidateCollisionSourceEntityIds)
        assertTrue("ambiguous-related-source-anchor" in reconciledNested.reasonCodes)
        assertEquals(nested.edges, reconciledNested.edges)
        assertTrue(reconciledNested.edges.any { it.kind == FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN })
        assertTrue(expansionUpperBound >= expandedBytes - baseBytes)
        assertTrue(adjustedCopyUpperBound >= baseBytes)
    }

    @Test
    fun `function start resolution memoizes its bounded range lookup`() {
        val parseBudget = FullTreeDwarfParseBudget(1L)
        var calls = 0
        val resolution = FullTreeSourceIdentityFunctionStartResolution {
            calls++
            parseBudget.consume("memoized function start")
            0x1234uL
        }

        assertEquals(0x1234uL, resolution.get())
        assertEquals(0x1234uL, resolution.get())
        assertEquals(1, calls)
        assertFailsWith<FullTreeControlException> { parseBudget.consume("second function-start parse") }
    }

    @Test
    fun `incomplete or conflicting source fields cannot produce a semantic anchor`() {
        assertNull(fields(signature = null).candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION))
        assertNull(
            fields(sourcePath = null).candidateId(FullTreeSourceEntityKind.DECLARATION_ONLY),
        )
        assertNull(fields(templateActualArguments = null).candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE))
        assertFailsWith<IllegalArgumentException> {
            fields(sourcePath = "source/../outside.cpp")
        }
    }

    @Test
    fun `optional declaration columns remain evidence but do not split semantic candidates`() {
        val withoutColumn = fields(declarationColumn = null)
        val withColumn = fields(declarationColumn = 31)
        assertNotEquals(withoutColumn.canonicalJson(), withColumn.canonicalJson())
        assertEquals(
            withoutColumn.candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
            withColumn.candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
        )
    }

    @Test
    fun `inline candidates require call columns to distinguish same-line call sites`() {
        val callee = fields(sourceName = "inline_callee").candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION)
        val owner = fields(sourceName = "inline_owner").candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION)
        val withoutColumn = fields(
            inlineCalleeAnchorCandidateId = callee,
            inlineOwnerAnchorCandidateId = owner,
            inlineCallFile = "source/clang/lib/inline-template/caller.cpp",
            inlineCallLine = 42,
            inlineCallColumn = null,
            inlinePathAnchorCandidateIds = listOf(checkNotNull(callee)),
        )
        val withColumn = fields(
            inlineCalleeAnchorCandidateId = callee,
            inlineOwnerAnchorCandidateId = owner,
            inlineCallFile = "source/clang/lib/inline-template/caller.cpp",
            inlineCallLine = 42,
            inlineCallColumn = 19,
            inlinePathAnchorCandidateIds = listOf(checkNotNull(callee)),
        )
        assertNotEquals(withoutColumn.canonicalJson(), withColumn.canonicalJson())
        assertNull(withoutColumn.candidateId(FullTreeSourceEntityKind.INLINE_INSTANCE))
        assertNotNull(withColumn.candidateId(FullTreeSourceEntityKind.INLINE_INSTANCE))
    }

    @Test
    fun `conflicting lower ranked source branch makes the merged anchor ambiguous`() {
        val sourceName = mergeValidatedSourceAnchorBranches(
            listOf(
                SourceAnchorBranchValue(score = 7, value = "plain"),
                SourceAnchorBranchValue(score = 2, value = "other"),
            ),
        )
        assertTrue(sourceName.ambiguous)
        assertNull(sourceName.value)

        val parameterSet = mergeValidatedSourceAnchorBranches(
            listOf(
                SourceAnchorBranchValue(score = 7, value = listOf("return:base:int", "parameter:base:long")),
                SourceAnchorBranchValue(score = 2, value = listOf("return:base:int", "parameter:base:short")),
            ),
        )
        assertTrue(parameterSet.ambiguous)
        assertNull(parameterSet.value)

        val templateFormals = mergeValidatedSourceAnchorBranches(
            listOf(
                SourceAnchorBranchValue(score = 10, value = listOf("type-formal:T", "value-formal:base:int:N")),
                SourceAnchorBranchValue(score = 1, value = listOf("type-formal:U", "value-formal:base:int:N")),
            ),
        )
        assertTrue(templateFormals.ambiguous)
        assertNull(templateFormals.value)

        val declarationColumn = mergeValidatedSourceAnchorBranches(
            listOf(
                SourceAnchorBranchValue(score = 9, value = 23L),
                SourceAnchorBranchValue(score = 1, value = 24L),
            ),
        )
        assertTrue(declarationColumn.ambiguous)
        assertNull(declarationColumn.value)

        val sourcePath = mergeValidatedSourceAnchorBranches(
            listOf(
                SourceAnchorBranchValue(score = 7, value = "source/fixture.cpp"),
                SourceAnchorBranchValue(score = 2, value = "source/fixture.cpp"),
            ),
        )
        val sourceLine = mergeValidatedSourceAnchorBranches(
            listOf(
                SourceAnchorBranchValue(score = 7, value = 11L),
                SourceAnchorBranchValue(score = 2, value = 11L),
            ),
        )
        val anchor = fields(
            sourcePath = sourcePath.value,
            declarationLine = sourceLine.value,
            sourceName = sourceName.value,
        )
        assertNull(anchor.candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION))
    }

    @Test
    fun `consistent partial source branches merge into a complete anchor`() {
        val path = mergeValidatedSourceAnchorBranches(
            listOf(
                SourceAnchorBranchValue(score = 8, value = "source/fixture.cpp"),
                SourceAnchorBranchValue<String>(score = 3, value = null),
            ),
        )
        val line = mergeValidatedSourceAnchorBranches(
            listOf(
                SourceAnchorBranchValue<Long>(score = 8, value = null),
                SourceAnchorBranchValue(score = 3, value = 27L),
            ),
        )
        val name = mergeValidatedSourceAnchorBranches(
            listOf(
                SourceAnchorBranchValue<String>(score = 8, value = null),
                SourceAnchorBranchValue(score = 3, value = "split_source"),
            ),
        )
        val signature = mergeValidatedSourceAnchorBranches(
            listOf(
                SourceAnchorBranchValue(score = 8, value = listOf("return:base:int", "parameter:base:long")),
                SourceAnchorBranchValue<List<String>>(score = 3, value = null),
            ),
        )
        assertEquals(false, path.ambiguous || line.ambiguous || name.ambiguous || signature.ambiguous)
        val anchor = fields(
            sourcePath = path.value,
            declarationLine = line.value,
            sourceName = name.value,
            signature = signature.value,
        )
        assertNotNull(anchor.candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION))
    }

    @Test
    fun `anchor preimage accepts data above legacy json string defaults within row bound`() {
        val wide = fields(signature = listOf("parameter:" + "x".repeat(3 * 1024 * 1024)))
        assertNotNull(wide.candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION))
    }

    @Test
    fun `source memory policy separates row retained and serialized ceilings`() {
        val generous = sourceIdentityMemoryBounds(
            authenticatedMaximumResidentBytes = 512L * 1024L * 1024L,
            authenticatedMaximumSerializedBytes = 256L * 1024L * 1024L,
        )
        assertEquals(64L * 1024L * 1024L, generous.maximumCanonicalRowBytes)
        assertEquals(128L * 1024L * 1024L, generous.maximumRowScratchBytes)
        assertEquals(64L * 1024L * 1024L, generous.maximumModeledRetainedBytes)

        val residentConstrained = sourceIdentityMemoryBounds(
            authenticatedMaximumResidentBytes = 32L * 1024L * 1024L,
            authenticatedMaximumSerializedBytes = 256L * 1024L * 1024L,
        )
        assertEquals(64L * 1024L * 1024L, residentConstrained.maximumCanonicalRowBytes)
        assertEquals(128L * 1024L * 1024L, residentConstrained.maximumRowScratchBytes)
        assertEquals(8L * 1024L * 1024L, residentConstrained.maximumModeledRetainedBytes)

        val outputConstrained = sourceIdentityMemoryBounds(
            authenticatedMaximumResidentBytes = 512L * 1024L * 1024L,
            authenticatedMaximumSerializedBytes = 32L * 1024L * 1024L,
        )
        assertEquals(32L * 1024L * 1024L, outputConstrained.maximumCanonicalRowBytes)
        assertEquals(64L * 1024L * 1024L, outputConstrained.maximumRowScratchBytes)
        assertEquals(64L * 1024L * 1024L, outputConstrained.maximumModeledRetainedBytes)
        val compactOutput = sourceIdentityMemoryBounds(
            authenticatedMaximumResidentBytes = 4L * 1024L * 1024L * 1024L,
            authenticatedMaximumSerializedBytes = 1024L * 1024L,
        )
        assertEquals(3L * 1024L * 1024L, compactOutput.maximumModeledRetainedBytes)

        val available = sourceIdentityAvailableRepositoryWorkingSetBytes(
            authenticatedMaximumResidentBytes = 4L * 1024L * 1024L * 1024L,
            modeledLineTableBytes = 1L * 1024L * 1024L * 1024L,
            modeledRetainedFactBytes = generous.maximumModeledRetainedBytes,
            maximumSerializedOutputBytes = 256L * 1024L * 1024L,
            maximumRowScratchBytes = generous.maximumRowScratchBytes,
        )
        assertEquals(2_624L * 1024L * 1024L, available)
        assertFailsWith<FullTreeControlException> {
            sourceIdentityAvailableRepositoryWorkingSetBytes(
                authenticatedMaximumResidentBytes = 512L * 1024L * 1024L,
                modeledLineTableBytes = 128L * 1024L * 1024L,
                modeledRetainedFactBytes = 64L * 1024L * 1024L,
                maximumSerializedOutputBytes = 256L * 1024L * 1024L,
                maximumRowScratchBytes = 128L * 1024L * 1024L,
            )
        }
    }

    @Test
    fun `small resident budgets reject co-resident many-unit index structures before headers materialize`() {
        assertEquals(controlJsonLimits(1_024).maximumNodes.toLong(), MAXIMUM_SOURCE_IDENTITY_CONTROL_JSON_NODES)
        assertEquals(
            64L * 1024L,
            sourceIdentityFixedStructureResidentBytes(
                authenticatedInventoryBytes = 0L,
                modeledInventoryJsonNodes = 1_024L,
                compilationUnitCount = 0L,
                modeledElfLayoutBytes = 0L,
                modeledObservedUnitMetadataBytes = 0L,
            ),
        )
        val fixedStructures = sourceIdentityFixedStructureResidentBytes(
            authenticatedInventoryBytes = 4L * 1024L,
            modeledInventoryJsonNodes = 0L,
            compilationUnitCount = 16_384L,
            modeledElfLayoutBytes = 8L * 1024L * 1024L,
            modeledObservedUnitMetadataBytes = 0L,
        )
        assertTrue(fixedStructures > 24L * 1024L * 1024L)
        assertFailsWith<FullTreeControlException> {
            sourceIdentityAvailableRepositoryWorkingSetBytes(
                authenticatedMaximumResidentBytes = 24L * 1024L * 1024L,
                modeledLineTableBytes = 1L * 1024L * 1024L,
                modeledRetainedFactBytes = 4L * 1024L * 1024L,
                maximumSerializedOutputBytes = 4L * 1024L * 1024L,
                maximumRowScratchBytes = 2L * 1024L * 1024L,
                modeledFixedStructureBytes = fixedStructures,
            )
        }
    }

    @Test
    fun `retained model charges include configured content expansion and allocation overhead`() {
        assertEquals(64L, sourceIdentityModeledRetainedChargeBytes(0L))
        assertEquals(
            3L * 1024L + 64L,
            sourceIdentityModeledRetainedChargeBytes(1024L),
        )
        assertFailsWith<FullTreeControlException> {
            sourceIdentityModeledRetainedChargeBytes(Long.MAX_VALUE)
        }
    }

    @Test
    fun `fixed unsigned dwarf forms do not guess sign extension across widths`() {
        assertEquals(
            "127",
            sourceIdentityIntegralValueDescriptor(
                FullTreeDwarfUnsignedConstantValue(FULL_TREE_DW_FORM_DATA1, 0x7fUL, 0),
                signed = true,
                bits = 32,
            ),
        )
        assertNull(
            sourceIdentityIntegralValueDescriptor(
                FullTreeDwarfUnsignedConstantValue(FULL_TREE_DW_FORM_DATA1, 0xffUL, 0),
                signed = true,
                bits = 32,
            ),
        )
        assertNull(
            sourceIdentityIntegralValueDescriptor(
                FullTreeDwarfUnsignedConstantValue(FULL_TREE_DW_FORM_DATA2, 0xffffUL, 0),
                signed = true,
                bits = 64,
            ),
        )
        assertNull(
            sourceIdentityIntegralValueDescriptor(
                FullTreeDwarfUnsignedConstantValue(FULL_TREE_DW_FORM_DATA4, 0x80000000UL, 0),
                signed = true,
                bits = 64,
            ),
        )
        assertEquals(
            "-2147483648",
            sourceIdentityIntegralValueDescriptor(
                FullTreeDwarfUnsignedConstantValue(FULL_TREE_DW_FORM_DATA4, 0x80000000UL, 0),
                signed = true,
                bits = 32,
            ),
        )
        assertEquals(
            "-1",
            sourceIdentityIntegralValueDescriptor(
                FullTreeDwarfUnsignedConstantValue(FULL_TREE_DW_FORM_DATA1, 0xffUL, 0),
                signed = true,
                bits = 8,
            ),
        )
    }

    @Test
    fun `explicit signed and unsigned dwarf constant controls retain their declared values`() {
        assertEquals(
            "-1",
            sourceIdentityIntegralValueDescriptor(
                FullTreeDwarfSignedConstantValue(FULL_TREE_DW_FORM_SDATA, -1, 0),
                signed = true,
                bits = 32,
            ),
        )
        assertEquals(
            "-2",
            sourceIdentityIntegralValueDescriptor(
                FullTreeDwarfSignedConstantValue(FULL_TREE_DW_FORM_IMPLICIT_CONST, -2, 0),
                signed = true,
                bits = 32,
            ),
        )
        assertEquals(
            "255",
            sourceIdentityIntegralValueDescriptor(
                FullTreeDwarfUnsignedConstantValue(FULL_TREE_DW_FORM_DATA1, 0xffUL, 0),
                signed = false,
                bits = 32,
            ),
        )
        assertEquals(
            "255",
            sourceIdentityIntegralValueDescriptor(
                FullTreeDwarfUnsignedConstantValue(FULL_TREE_DW_FORM_UDATA, 255UL, 0),
                signed = true,
                bits = 32,
            ),
        )
        assertNull(
            sourceIdentityIntegralValueDescriptor(
                FullTreeDwarfUnsignedConstantValue(FULL_TREE_DW_FORM_UDATA, 0xffffffffUL, 0),
                signed = true,
                bits = 32,
            ),
        )
    }

    @Test
    fun `boolean template actuals accept only the two boolean values`() {
        assertEquals(
            "0",
            sourceIdentityBooleanValueDescriptor(
                FullTreeDwarfUnsignedConstantValue(FULL_TREE_DW_FORM_DATA1, 0UL, 0),
            ),
        )
        assertEquals(
            "1",
            sourceIdentityBooleanValueDescriptor(
                FullTreeDwarfUnsignedConstantValue(FULL_TREE_DW_FORM_UDATA, 1UL, 0),
            ),
        )
        assertEquals(
            "1",
            sourceIdentityBooleanValueDescriptor(
                FullTreeDwarfSignedConstantValue(FULL_TREE_DW_FORM_IMPLICIT_CONST, 1L, 0),
            ),
        )
        assertNull(
            sourceIdentityBooleanValueDescriptor(
                FullTreeDwarfUnsignedConstantValue(FULL_TREE_DW_FORM_DATA1, 2UL, 0),
            ),
        )
        assertNull(
            sourceIdentityBooleanValueDescriptor(
                FullTreeDwarfSignedConstantValue(FULL_TREE_DW_FORM_SDATA, -1L, 0),
            ),
        )
    }

    @Test
    fun `common compiler builtin spellings normalize without merging distinct C++ types`() {
        assertEquals("unsigned long", canonicalSourceIdentityBuiltinName("unsigned long"))
        assertEquals("unsigned long", canonicalSourceIdentityBuiltinName("long unsigned int"))
        assertEquals("unsigned short", canonicalSourceIdentityBuiltinName("short unsigned int"))
        assertEquals("unsigned long long", canonicalSourceIdentityBuiltinName("long long unsigned int"))
        assertEquals("long", canonicalSourceIdentityBuiltinName("signed long int"))
        assertEquals("long long", canonicalSourceIdentityBuiltinName("long long int"))
        assertNotEquals(
            canonicalSourceIdentityBuiltinName("long"),
            canonicalSourceIdentityBuiltinName("long long"),
        )
        val gccStyle = fields(
            declarationColumn = 31,
            signature = listOf("parameter:base:${canonicalSourceIdentityBuiltinName("long unsigned int")}:encoding=7:bytes=8"),
        )
        val clangStyle = fields(
            declarationColumn = null,
            signature = listOf("parameter:base:${canonicalSourceIdentityBuiltinName("unsigned long")}:encoding=7:bytes=8"),
        )
        assertEquals(
            gccStyle.candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
            clangStyle.candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
        )
    }

    @Test
    fun `template instance and inline instance anchors include verified ownership facts`() {
        val pattern = fields(
            templateFormalParameters = listOf("type-parameter:T"),
        ).candidateId(FullTreeSourceEntityKind.TEMPLATE_PATTERN)
        val intInstance = fields(
            templatePatternAnchorCandidateId = pattern,
            templateActualArguments = listOf("type:base:int"),
        ).candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE)
        val intInstanceWithoutPattern = fields(
            templatePatternAnchorCandidateId = null,
            templateActualArguments = listOf("type:base:int"),
        ).candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE)
        val longInstance = fields(
            templatePatternAnchorCandidateId = null,
            templateActualArguments = listOf("type:base:long"),
        ).candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE)
        val offsetThree = fields(
            sourceName = "offset<3, int>",
            templatePatternAnchorCandidateId = pattern,
            templateActualArguments = listOf("value-argument:type=base:int:value=3", "type-argument:base:int"),
        ).candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE)
        val offsetFour = fields(
            sourceName = "offset<4, int>",
            templatePatternAnchorCandidateId = pattern,
            templateActualArguments = listOf("value-argument:type=base:int:value=4", "type-argument:base:int"),
        ).candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE)
        assertNotEquals(intInstance, longInstance)
        assertEquals(intInstance, intInstanceWithoutPattern)
        assertNotNull(intInstanceWithoutPattern)
        assertNotNull(offsetThree)
        assertNotNull(offsetFour)
        assertNotEquals(offsetThree, offsetFour)

        val patternFact = fact(
            "0x12",
            FullTreeSourceEntityKind.TEMPLATE_PATTERN,
            fields(templateFormalParameters = listOf("type-formal:T")),
        )
        assertEquals(FullTreeDenominatorDisposition.NON_SCOREABLE, patternFact.denominatorDisposition)
        assertNull(patternFact.linkedEmittedRva)

        val inlineAtCallOne = fields(
            inlineCalleeAnchorCandidateId = fields().candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
            inlineOwnerAnchorCandidateId = fields(sourceName = "caller_one").candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
            inlineCallFile = "source/clang/lib/inline-template/caller_one.cpp",
            inlineCallLine = 17,
            inlineCallColumn = 9,
            inlinePathAnchorCandidateIds = listOf("a".repeat(64)),
        ).candidateId(FullTreeSourceEntityKind.INLINE_INSTANCE)
        val inlineAtCallTwo = fields(
            inlineCalleeAnchorCandidateId = fields().candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
            inlineOwnerAnchorCandidateId = fields(sourceName = "caller_two").candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
            inlineCallFile = "source/clang/lib/inline-template/caller_two.cpp",
            inlineCallLine = 23,
            inlineCallColumn = 14,
            inlinePathAnchorCandidateIds = listOf("c".repeat(64)),
        ).candidateId(FullTreeSourceEntityKind.INLINE_INSTANCE)
        assertNotEquals(inlineAtCallOne, inlineAtCallTwo)
    }

    @Test
    fun `template instance candidates normalize only balanced rendered specialization suffixes`() {
        val actual = listOf("type-argument:base:long:encoding=5:bytes=8")
        val gccStyle = fields(sourceName = "rendered<long int>", templateActualArguments = actual)
        val clangStyle = fields(sourceName = "rendered<long>", templateActualArguments = actual)
        assertNotEquals(gccStyle.canonicalJson(), clangStyle.canonicalJson())
        assertEquals(
            gccStyle.candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE),
            clangStyle.candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE),
        )
        val gccNestedStyle = fields(
            sourceName = "rendered<std::pair<long int, long int>>",
            templateActualArguments = listOf("type-argument:pair<long,long>"),
        )
        val clangNestedStyle = fields(
            sourceName = "rendered<std::pair<long, long>>",
            templateActualArguments = listOf("type-argument:pair<long,long>"),
        )
        assertEquals(
            gccNestedStyle.candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE),
            clangNestedStyle.candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE),
        )
        assertNotEquals(
            fields(sourceName = "first<long>", templateActualArguments = actual)
                .candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE),
            fields(sourceName = "second<long>", templateActualArguments = actual)
                .candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE),
        )
        assertNull(fields(sourceName = "rendered<long", templateActualArguments = actual)
            .candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE))
        assertNull(fields(sourceName = "rendered<>", templateActualArguments = actual)
            .candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE))
        assertNull(fields(sourceName = "rendered<long, int>", templateActualArguments = actual)
            .candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE))
        assertNull(
            fields(sourceName = "rendered" + "<".repeat(4_096) + ">", templateActualArguments = actual)
                .candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE),
        )
        assertNotEquals(
            fields(sourceName = "rendered<long int>")
                .candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
            fields(sourceName = "rendered<long>")
                .candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
        )
    }

    @Test
    fun `physical locators and edge bounds are explicit`() {
        val physical = physical("0x10")
        assertNotEquals(
            physical.sourceEntityId(FullTreeSourceEntityKind.INLINE_INSTANCE),
            physical("0x11").sourceEntityId(FullTreeSourceEntityKind.INLINE_INSTANCE),
        )
        assertNotEquals(
            physical.sourceEntityId(FullTreeSourceEntityKind.INLINE_INSTANCE),
            physical.sourceEntityId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE),
        )
        assertNotEquals(
            physical.sourceEntityId(FullTreeSourceEntityKind.INLINE_INSTANCE),
            physical.copy(richArtifactSha256 = "c".repeat(64)).sourceEntityId(FullTreeSourceEntityKind.INLINE_INSTANCE),
        )
        assertNotEquals(
            physical.sourceEntityId(FullTreeSourceEntityKind.INLINE_INSTANCE),
            physical.copy(unitId = "cu-${"d".repeat(32)}").sourceEntityId(FullTreeSourceEntityKind.INLINE_INSTANCE),
        )
        assertEquals(
            "${"a".repeat(64)}:.debug_info:unit=cu-${"b".repeat(32)}:cu=0x20:die=0x10",
            physical.locator(),
        )
        val edge = FullTreeSourceIdentityEdge(
            kind = FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN,
            source = physical,
            target = physical("0x30"),
            referenceForm = "0x11",
            rawReference = "0x10",
            state = FullTreeSourceIdentityEdgeState.RESOLVED,
            reasonCode = null,
        )
        assertEquals(FullTreeSourceIdentityEdgeState.RESOLVED, edge.state)

        val thirtyTwo = List(MAXIMUM_IDENTITY_EDGES_PER_ENTITY) { index -> edge.copy(rawReference = "0x${index + 1}") }
        fact("0x10", FullTreeSourceEntityKind.NO_RANGE_DEFINITION, fields(), edges = thirtyTwo)
        assertFailsWith<IllegalArgumentException> {
            fact(
                "0x10",
                FullTreeSourceEntityKind.NO_RANGE_DEFINITION,
                fields(),
                edges = thirtyTwo + edge,
            )
        }
    }

    @Test
    fun `unsupported and cyclic references remain explicit raw evidence`() {
        val source = physical("0x10")
        val unresolvedStates = listOf(
            FullTreeSourceIdentityEdgeState.MISSING_TARGET,
            FullTreeSourceIdentityEdgeState.MALFORMED,
            FullTreeSourceIdentityEdgeState.UNSUPPORTED,
            FullTreeSourceIdentityEdgeState.CYCLIC,
        )
        val facts = unresolvedStates.mapIndexed { index, state ->
            val factKind = FullTreeSourceEntityKind.NO_RANGE_DEFINITION
            val edge = FullTreeSourceIdentityEdge(
                kind = FullTreeSourceIdentityEdgeKind.SPECIFICATION,
                source = source,
                target = null,
                referenceForm = "0x11",
                rawReference = "0x${index + 1}",
                state = state,
                reasonCode = when (state) {
                    FullTreeSourceIdentityEdgeState.MISSING_TARGET -> "target-not-retained-or-not-a-die-boundary"
                    FullTreeSourceIdentityEdgeState.MALFORMED -> "reference-outside-validated-dwarf-boundary"
                    FullTreeSourceIdentityEdgeState.UNSUPPORTED -> "unsupported-reference-form"
                    FullTreeSourceIdentityEdgeState.CYCLIC -> "reference-cycle"
                    FullTreeSourceIdentityEdgeState.RESOLVED -> error("unresolved state expected")
                },
            )
            fact("0x${0x20 + index}", factKind, fields(), edges = listOf(edge))
        }
        assertEquals(unresolvedStates.map { it.wireValue }, facts.map { it.edges.single().state.wireValue })
        assertContentEquals(canonicalSourceEntityFacts(facts), canonicalSourceEntityFacts(facts.reversed()))
        listOf(FullTreeSourceIdentityEdgeState.MISSING_TARGET, FullTreeSourceIdentityEdgeState.CYCLIC).forEach { state ->
            val edge = facts.single { it.edges.single().state == state }.edges.single()
            assertFailsWith<IllegalArgumentException> { edge.copy(referenceForm = null) }
            assertFailsWith<IllegalArgumentException> { edge.copy(rawReference = null) }
        }
    }

    @Test
    fun `source facts defensively freeze nested caller lists`() {
        val lexical = mutableListOf("namespace:before")
        val signature = mutableListOf("return:base:int")
        val arguments = mutableListOf("value-argument:type=base:int:value=-1")
        val fields = FullTreeSourceAnchorFields(
            sourcePath = "source/fixture.cpp",
            declarationFileIndex = 1L,
            declarationLine = 10L,
            declarationColumn = null,
            language = 33L,
            lexicalContext = lexical,
            sourceName = "signed_value",
            signature = signature,
            templateActualArguments = arguments,
        )
        val candidateId = fields.candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE)
        val reasonCodes = mutableListOf("source-anchor-incomplete")
        val collisionIds = mutableListOf("a".repeat(64))
        val edges = mutableListOf<FullTreeSourceIdentityEdge>()
        val source = physical("0x40")
        val fact = FullTreeSourceEntityFact(
            sourceEntityId = source.sourceEntityId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE),
            physicalDie = source,
            kind = FullTreeSourceEntityKind.TEMPLATE_INSTANCE,
            identityObservability = FullTreeIdentityObservability.AMBIGUOUS,
            denominatorDisposition = FullTreeDenominatorDisposition.NON_SCOREABLE,
            semanticAnchorFields = fields,
            semanticAnchorCandidateId = candidateId,
            resolvedSemanticIdentityId = null,
            candidateCollisionSourceEntityIds = collisionIds,
            linkedEmittedRva = null,
            reasonCodes = reasonCodes,
            edges = edges,
        )
        val frozen = canonicalSourceEntityFacts(listOf(fact))

        lexical += "namespace:after"
        signature[0] = "return:base:long"
        arguments += "type-argument:base:int"
        reasonCodes.clear()
        collisionIds.clear()
        edges += FullTreeSourceIdentityEdge(
            kind = FullTreeSourceIdentityEdgeKind.SPECIFICATION,
            source = source,
            target = null,
            referenceForm = "0x11",
            rawReference = "0x1",
            state = FullTreeSourceIdentityEdgeState.MISSING_TARGET,
            reasonCode = "target-not-retained-or-not-a-die-boundary",
        )

        assertEquals(listOf("namespace:before"), fields.lexicalContext)
        assertEquals(listOf("return:base:int"), fields.signature)
        assertEquals(listOf("value-argument:type=base:int:value=-1"), fields.templateActualArguments)
        assertEquals(listOf("source-anchor-incomplete"), fact.reasonCodes)
        assertEquals(listOf("a".repeat(64)), fact.candidateCollisionSourceEntityIds)
        assertTrue(fact.edges.isEmpty())
        assertContentEquals(frozen, canonicalSourceEntityFacts(listOf(fact)))
        assertFailsWith<UnsupportedOperationException> { (fields.lexicalContext as MutableList<String>).add("mutation") }
        assertFailsWith<UnsupportedOperationException> { (fact.reasonCodes as MutableList<String>).clear() }
    }

    @Test
    fun `canonical source census streams beyond the legacy four mebibyte ceiling`() {
        val wideFields = fields(sourceName = "wide_identity_" + "x".repeat(6_000))
        val facts = (0 until 1_000).map { index ->
            fact("0x${(0x1_000 + index).toString(16)}", FullTreeSourceEntityKind.NO_RANGE_DEFINITION, wideFields)
        }
        val bytes = canonicalSourceEntityFacts(facts)
        assertTrue(bytes.size > 4 * 1024 * 1024)
        assertEquals(bytes.size.toLong(), canonicalSourceEntityFactsByteLength(facts))
        assertContentEquals(bytes, canonicalSourceEntityFacts(facts, bytes.size.toLong()))
        assertFailsWith<IllegalArgumentException> {
            canonicalSourceEntityFacts(facts, bytes.size.toLong() - 1L)
        }
        assertFailsWith<IllegalArgumentException> {
            canonicalSourceEntityFactsByteLength(facts, bytes.size.toLong() - 1L)
        }
        assertFailsWith<StrictJsonException> {
            canonicalSourceEntityFacts(listOf(facts.first()), maximumCanonicalBytes = 4_096L)
        }
        val limits = StrictJsonLimits(
            maximumInputBytes = 16 * 1024 * 1024,
            maximumCanonicalBytes = 16 * 1024 * 1024,
            maximumNodes = 100_000,
            maximumStringBytes = 16 * 1024 * 1024,
            maximumTotalStringBytes = 16 * 1024 * 1024,
        )
        val expected = JsonArray(facts.map { it.canonicalJson() })
        val reference = OracleJson.canonicalBytes(expected, limits)
        assertContentEquals(reference, bytes)
        assertEquals(expected, OracleJson.parseCanonical(bytes, limits))
        assertFailsWith<StrictJsonException> { OracleJson.canonicalBytes(expected) }
    }

    @Test
    fun `inline and no-range rows cannot claim an emitted denominator link`() {
        val source = physical("0x10")
        val fields = fields()
        assertFailsWith<IllegalArgumentException> {
            FullTreeSourceEntityFact(
                physicalDie = source,
                sourceEntityId = source.sourceEntityId(FullTreeSourceEntityKind.INLINE_INSTANCE),
                kind = FullTreeSourceEntityKind.INLINE_INSTANCE,
                identityObservability = FullTreeIdentityObservability.UNKNOWN,
                denominatorDisposition = FullTreeDenominatorDisposition.EMITTED_RVA_LINK,
                semanticAnchorFields = fields,
                semanticAnchorCandidateId = null,
                resolvedSemanticIdentityId = null,
                candidateCollisionSourceEntityIds = emptyList(),
                linkedEmittedRva = "0x1",
                reasonCodes = listOf("source-anchor-incomplete"),
                edges = emptyList(),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            FullTreeSourceEntityFact(
                physicalDie = source,
                sourceEntityId = source.sourceEntityId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
                kind = FullTreeSourceEntityKind.NO_RANGE_DEFINITION,
                identityObservability = FullTreeIdentityObservability.UNKNOWN,
                denominatorDisposition = FullTreeDenominatorDisposition.EMITTED_RVA_LINK,
                semanticAnchorFields = fields,
                semanticAnchorCandidateId = null,
                resolvedSemanticIdentityId = null,
                candidateCollisionSourceEntityIds = emptyList(),
                linkedEmittedRva = "0x1",
                reasonCodes = listOf("source-anchor-incomplete"),
                edges = emptyList(),
            )
        }
    }

    private fun fields(
        sourcePath: String? = "source/clang/lib/inline-template/header.hpp",
        declarationFileIndex: Long? = 1,
        declarationLine: Long? = 11,
        declarationColumn: Long? = 3,
        language: Long? = 33,
        lexicalContext: List<String> = listOf("namespace:fixture"),
        sourceName: String? = "identity<T>",
        signature: List<String>? = listOf("base:int", "pointer:base:char"),
        templateFormalParameters: List<String>? = null,
        templatePatternAnchorCandidateId: String? = null,
        templateActualArguments: List<String>? = null,
        inlineCalleeAnchorCandidateId: String? = null,
        inlineOwnerAnchorCandidateId: String? = null,
        inlineCallFile: String? = null,
        inlineCallLine: Long? = null,
        inlineCallColumn: Long? = null,
        inlinePathAnchorCandidateIds: List<String>? = null,
    ) = FullTreeSourceAnchorFields(
        sourcePath = sourcePath,
        declarationFileIndex = declarationFileIndex,
        declarationLine = declarationLine,
        declarationColumn = declarationColumn,
        language = language,
        lexicalContext = lexicalContext,
        sourceName = sourceName,
        signature = signature,
        templateFormalParameters = templateFormalParameters,
        templatePatternAnchorCandidateId = templatePatternAnchorCandidateId,
        templateActualArguments = templateActualArguments,
        inlineCalleeAnchorCandidateId = inlineCalleeAnchorCandidateId,
        inlineOwnerAnchorCandidateId = inlineOwnerAnchorCandidateId,
        inlineCallFile = inlineCallFile,
        inlineCallLine = inlineCallLine,
        inlineCallColumn = inlineCallColumn,
        inlinePathAnchorCandidateIds = inlinePathAnchorCandidateIds,
    )

    private fun physical(offset: String) = FullTreeSourcePhysicalDie(
        richArtifactSha256 = "a".repeat(64),
        unitId = "cu-${"b".repeat(32)}",
        section = ".debug_info",
        compilationUnitOffset = "0x20",
        dieOffset = offset,
    )

    private fun fact(
        offset: String,
        kind: FullTreeSourceEntityKind,
        fields: FullTreeSourceAnchorFields,
        edges: List<FullTreeSourceIdentityEdge> = emptyList(),
    ) = FullTreeSourceEntityFact(
        sourceEntityId = physical(offset).sourceEntityId(kind),
        physicalDie = physical(offset),
        kind = kind,
        identityObservability = when {
            edges.any { it.state == FullTreeSourceIdentityEdgeState.CYCLIC } ->
                FullTreeIdentityObservability.AMBIGUOUS
            kind == FullTreeSourceEntityKind.DECLARATION_ONLY ->
                FullTreeIdentityObservability.UNOBSERVABLE
            edges.any {
                it.state == FullTreeSourceIdentityEdgeState.MISSING_TARGET ||
                    it.state == FullTreeSourceIdentityEdgeState.MALFORMED ||
                    it.state == FullTreeSourceIdentityEdgeState.UNSUPPORTED
            } -> FullTreeIdentityObservability.UNKNOWN
            fields.candidateId(kind) == null -> FullTreeIdentityObservability.UNKNOWN
            else -> FullTreeIdentityObservability.OBSERVABLE
        },
        denominatorDisposition = FullTreeDenominatorDisposition.NON_SCOREABLE,
        semanticAnchorFields = fields,
        semanticAnchorCandidateId = fields.candidateId(kind),
        resolvedSemanticIdentityId = null,
        candidateCollisionSourceEntityIds = emptyList(),
        linkedEmittedRva = null,
        reasonCodes = if (fields.candidateId(kind) == null) listOf("source-anchor-incomplete") else emptyList(),
        edges = edges,
    )
}
