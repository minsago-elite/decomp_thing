package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonException
import decompengine.oracle.core.StrictJsonLimits
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
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
        assertTrue(expansionUpperBound >= expandedBytes - baseBytes)
        assertFailsWith<IllegalArgumentException> {
            canonicalSourceEntityFacts(listOf(first, first))
        }
    }

    @Test
    fun `incomplete or conflicting source fields cannot produce a semantic anchor`() {
        assertNull(fields(signature = null).candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION))
        assertNull(
            fields(sourcePath = null).candidateId(FullTreeSourceEntityKind.DECLARATION_ONLY),
        )
        assertFailsWith<IllegalArgumentException> {
            fields(sourcePath = "source/../outside.cpp")
        }
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
        val longInstance = fields(
            templatePatternAnchorCandidateId = pattern,
            templateActualArguments = listOf("type:base:long"),
        ).candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE)
        val offsetThree = fields(
            templatePatternAnchorCandidateId = pattern,
            templateActualArguments = listOf("value-argument:type=base:int:value=3", "type-argument:base:int"),
        ).candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE)
        val offsetFour = fields(
            templatePatternAnchorCandidateId = pattern,
            templateActualArguments = listOf("value-argument:type=base:int:value=4", "type-argument:base:int"),
        ).candidateId(FullTreeSourceEntityKind.TEMPLATE_INSTANCE)
        assertNotEquals(intInstance, longInstance)
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
            inlinePathAnchorCandidateIds = listOf("a".repeat(64)),
        ).candidateId(FullTreeSourceEntityKind.INLINE_INSTANCE)
        val inlineAtCallTwo = fields(
            inlineCalleeAnchorCandidateId = fields().candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
            inlineOwnerAnchorCandidateId = fields(sourceName = "caller_two").candidateId(FullTreeSourceEntityKind.NO_RANGE_DEFINITION),
            inlineCallFile = "source/clang/lib/inline-template/caller_two.cpp",
            inlineCallLine = 23,
            inlinePathAnchorCandidateIds = listOf("c".repeat(64)),
        ).candidateId(FullTreeSourceEntityKind.INLINE_INSTANCE)
        assertNotEquals(inlineAtCallOne, inlineAtCallTwo)
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
                reasonCode = "reference-${state.wireValue}",
            )
            fact("0x${0x20 + index}", factKind, fields(), edges = listOf(edge))
        }
        assertEquals(unresolvedStates.map { it.wireValue }, facts.map { it.edges.single().state.wireValue })
        assertContentEquals(canonicalSourceEntityFacts(facts), canonicalSourceEntityFacts(facts.reversed()))
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
            identityObservability = FullTreeIdentityObservability.UNKNOWN,
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
            reasonCode = "target-not-found",
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
        identityObservability = if (fields.candidateId(kind) == null) {
            FullTreeIdentityObservability.UNKNOWN
        } else {
            FullTreeIdentityObservability.OBSERVABLE
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
