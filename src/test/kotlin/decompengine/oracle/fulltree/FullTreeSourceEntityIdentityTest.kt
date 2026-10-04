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
        assertTrue(expansionUpperBound >= expandedBytes - baseBytes)
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

        assertEquals(FullTreeIdentityObservability.AMBIGUOUS, reconciledNested.identityObservability)
        assertEquals(collisionIds, reconciledNested.candidateCollisionSourceEntityIds)
        assertTrue("ambiguous-related-source-anchor" in reconciledNested.reasonCodes)
        assertEquals(nested.edges, reconciledNested.edges)
        assertTrue(reconciledNested.edges.any { it.kind == FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN })
        assertTrue(expansionUpperBound >= expandedBytes - baseBytes)
    }

    @