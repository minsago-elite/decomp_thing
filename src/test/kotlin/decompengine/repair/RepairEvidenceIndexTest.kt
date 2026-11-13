package decompengine.repair

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class RepairEvidenceIndexTest {
    private val modelOrigin = RepairEvidenceOrigin("program-model", "a".repeat(64), 4, "/functions/0")
    private val planOrigin = RepairEvidenceOrigin("module-plan", "b".repeat(64), 2, "/modules/0")

    private fun facts(): RepairEvidenceFacts = RepairEvidenceFacts(
        origins = listOf(modelOrigin, planOrigin),
        entities = listOf(
            RepairEntityFact("module:alpha", RepairEvidenceEntityKind.MODULE, null, planOrigin),
            RepairEntityFact("fn_alpha", RepairEvidenceEntityKind.FUNCTION, "recovered", modelOrigin),
            RepairEntityFact("global_state", RepairEvidenceEntityKind.GLOBAL, "partial", modelOrigin),
            RepairEntityFact("type_state", RepairEvidenceEntityKind.TYPE, "recovered", modelOrigin),
        ),
        relations = listOf(
            RepairEntityRelation(RepairEvidenceRelationKind.CALLS, "fn_alpha", "fn_alpha", modelOrigin),
            RepairEntityRelation(RepairEvidenceRelationKind.REFERENCES_GLOBAL, "fn_alpha", "global_state", modelOrigin),
        ),
        declarations = listOf(
            RepairDeclarationEvidence("fn_alpha", "recovered-prototype", modelOrigin),
            RepairDeclarationEvidence("global_state", "global-type", modelOrigin),
            RepairDeclarationEvidence("type_state", "type-declaration", modelOrigin),
        ),
        definitions = listOf(
            RepairDefinitionEvidence("fn_alpha", "recovered-body", modelOrigin),
            RepairDefinitionEvidence("type_state", "type-definition", modelOrigin),
        ),
        buildEvidence = listOf(RepairBuildEvidence("Makefile", null, emptyList())),
        uncertainties = listOf(
            RepairEvidenceUncertainty("fn_alpha", "source-location", RepairEvidenceUncertaintyReason.SOURCE_LOCATION_UNAVAILABLE, modelOrigin),
            RepairEvidenceUncertainty("Makefile", "build-target", RepairEvidenceUncertaintyReason.RELATIONSHIP_NOT_ESTABLISHED),
        ),
    )

    @Test
    fun `canonical evidence is deterministic immutable and preserves typed relationship kinds`() {
        val inputEntities = facts().entities.toMutableList()
        val inputTargets = mutableListOf("all")
        val build = RepairBuildEvidence("Makefile", null, inputTargets)
        val built = RepairEvidenceFacts(buildEvidence = listOf(build))
        val buildDigest = built.sha256(64 * 1024)
        inputTargets.clear()
        val original = facts()
        val permuted = RepairEvidenceFacts(
            origins = original.origins.reversed(), entities = inputEntities.reversed(),
            relations = original.relations.reversed(), declarations = original.declarations.reversed(),
            definitions = original.definitions.reversed(), buildEvidence = original.buildEvidence.reversed(),
            uncertainties = original.uncertainties.reversed(),
        )
        inputEntities.clear()
        assertContentEquals(original.canonicalBytes(64 * 1024), permuted.canonicalBytes(64 * 1024))
        assertEquals(original.sha256(64 * 1024), permuted.sha256(64 * 1024))
        assertEquals(setOf(RepairEvidenceRelationKind.CALLS, RepairEvidenceRelationKind.REFERENCES_GLOBAL), original.relations.map { it.kind }.toSet())
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (original.entities as MutableList<RepairEntityFact>).clear()
        }
        assertEquals(listOf("all"), build.explicitTargets)
        assertEquals(buildDigest, built.sha256(64 * 1024))
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (build.explicitTargets as MutableList<String>).clear()
        }
        val encoded = original.canonicalBytes(64 * 1024)
        assertContentEquals(encoded, original.canonicalBytes(encoded.size.toLong()))
        assertFailsWith<RepairBudgetExceededException> { original.canonicalBytes((encoded.size - 1).toLong()) }
        assertNotEquals(original.sha256(64 * 1024), factsWithChangedDocumentHash().sha256(64 * 1024))
    }

    @Test
    fun `canonical evidence tie breakers include complete origin identity`() {
        val first = RepairEvidenceOrigin("program-model", "a".repeat(64), 3, "/functions/0")
        val second = RepairEvidenceOrigin("program-model", "b".repeat(64), 4, "/functions/0")
        val entities = listOf(
            RepairEntityFact("fn_alpha", RepairEvidenceEntityKind.FUNCTION, "recovered", first),
            RepairEntityFact("fn_beta", RepairEvidenceEntityKind.FUNCTION, "recovered", second),
        )
        val relations = listOf(
            RepairEntityRelation(RepairEvidenceRelationKind.CALLS, "fn_alpha", "fn_beta", first),
            RepairEntityRelation(RepairEvidenceRelationKind.CALLS, "fn_alpha", "fn_beta", second),
        )
        val declarations = listOf(
            RepairDeclarationEvidence("fn_alpha", "prototype", first),
            RepairDeclarationEvidence("fn_alpha", "prototype", second),
        )
        val definitions = listOf(
            RepairDefinitionEvidence("fn_alpha", "body", first),
            RepairDefinitionEvidence("fn_alpha", "body", second),
        )
        val uncertainties = listOf(
            RepairEvidenceUncertainty("fn_alpha", "source-location", RepairEvidenceUncertaintyReason.SOURCE_LOCATION_UNAVAILABLE, first),
            RepairEvidenceUncertainty("fn_alpha", "source-location", RepairEvidenceUncertaintyReason.SOURCE_LOCATION_UNAVAILABLE, second),
        )
        val forward = RepairEvidenceFacts(
            origins = listOf(first, second), entities = entities, relations = relations,
            declarations = declarations, definitions = definitions, uncertainties = uncertainties,
        )
        val reversed = RepairEvidenceFacts(
            origins = listOf(second, first), entities = entities.reversed(), relations = relations.reversed(),
            declarations = declarations.reversed(), definitions = definitions.reversed(), uncertainties = uncertainties.reversed(),
        )

        assertContentEquals(forward.canonicalBytes(64 * 1024), reversed.canonicalBytes(64 * 1024))
        assertEquals(forward.sha256(64 * 1024), reversed.sha256(64 * 1024))
    }

    @Test
    fun `evidence facts reject dangling origins entities and duplicate identities`() {
        assertFailsWith<IllegalArgumentException> {
            RepairEvidenceFacts(entities = listOf(RepairEntityFact("orphan", RepairEvidenceEntityKind.FUNCTION, "recovered", modelOrigin)))
        }
        assertFailsWith<IllegalArgumentException> {
            RepairEvidenceFacts(
                origins = listOf(modelOrigin),
                entities = listOf(RepairEntityFact("fn", RepairEvidenceEntityKind.FUNCTION, "recovered", modelOrigin)),
                relations = listOf(RepairEntityRelation(RepairEvidenceRelationKind.CALLS, "fn", "missing", modelOrigin)),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairEvidenceFacts(origins = listOf(modelOrigin), entities = listOf(
                RepairEntityFact("same", RepairEvidenceEntityKind.FUNCTION, "recovered", modelOrigin),
                RepairEntityFact("same", RepairEvidenceEntityKind.GLOBAL, "recovered", modelOrigin),
            ))
        }
        assertFailsWith<IllegalArgumentException> {
            val base = facts()
            RepairEvidenceFacts(
                origins = base.origins,
                entities = base.entities,
                relations = listOf(RepairEntityRelation(RepairEvidenceRelationKind.CALLS, "fn_alpha", "global_state", modelOrigin)),
            )
        }
    }

    @Test
    fun `snapshot digest binds provisional and accepted identities without conflating them`() {
        val baseline = snapshot(working = "c", head = "c", acceptedId = "root", accepted = "c")
        val provisional = snapshot(working = "d", head = "c", acceptedId = "root", accepted = "c", status = "PROVISIONAL")
        val accepted = snapshot(working = "d", head = "d", acceptedId = "head", accepted = "d", status = "ACCEPTED")
        assertNotEquals(baseline.sha256(64 * 1024), provisional.sha256(64 * 1024))
        assertNotEquals(provisional.sha256(64 * 1024), accepted.sha256(64 * 1024))
        assertEquals("c".repeat(64), provisional.fullyAcceptedHeadSha256)
        assertEquals("d".repeat(64), provisional.workingRevisionSha256)
        assertEquals(RepairEvidenceUncertaintyReason.EVIDENCE_NOT_CAPTURED, provisional.uncertainties.first().reason)
        assertFailsWith<RepairBudgetExceededException> { provisional.canonicalBytes(8) }
        assertFailsWith<IllegalArgumentException> {
            RepairEvidenceSnapshot(
                profileId = "profile", profileSha256 = "1".repeat(64), reconstructionDescriptorSha256 = null,
                indexSha256 = "3".repeat(64), indexBasisSourceRevisionSha256 = "c".repeat(64),
                workingRevisionSha256 = "c".repeat(64), graphHeadId = "head", graphHeadSha256 = "c".repeat(64),
                graphHeadStatus = "ROOT", fullyAcceptedHeadId = null, fullyAcceptedHeadSha256 = null,
                regressionCorpusSha256 = "4".repeat(64), staticFacts = facts(), selectedEntityIds = listOf("fn_alpha", "fn_alpha"),
                diagnosticEvidence = RepairDiagnosticEvidence(
                    null, "c".repeat(64), null, RepairDiagnosticAttributionBasis.NONE, null, emptyList(), emptyList(), false,
                ),
                behaviorCases = emptyList(), omittedEntityCount = 0,
                omittedRecordCounts = mapOf("entities" to 0, "relations" to 0, "declarations" to 0, "definitions" to 0,
                    "buildEvidence" to 0, "uncertainties" to 0),
                diagnosticHintSha256 = null,
                maximumCanonicalBytes = 64 * 1024, uncertainties = emptyList(),
            )
        }
    }

    private fun factsWithChangedDocumentHash() = RepairEvidenceFacts(
        origins = listOf(RepairEvidenceOrigin("program-model", "e".repeat(64), 4, "/functions/0"), planOrigin),
        entities = facts().entities.map { if (it.kind == RepairEvidenceEntityKind.MODULE) it else it.copy(origin = RepairEvidenceOrigin("program-model", "e".repeat(64), 4, "/functions/0")) },
        relations = facts().relations.map { it.copy(origin = RepairEvidenceOrigin("program-model", "e".repeat(64), 4, "/functions/0")) },
        declarations = facts().declarations.map { it.copy(origin = RepairEvidenceOrigin("program-model", "e".repeat(64), 4, "/functions/0")) },
        definitions = facts().definitions.map { it.copy(origin = RepairEvidenceOrigin("program-model", "e".repeat(64), 4, "/functions/0")) },
        buildEvidence = facts().buildEvidence,
        uncertainties = facts().uncertainties.map { if (it.origin == null) it else it.copy(origin = RepairEvidenceOrigin("program-model", "e".repeat(64), 4, "/functions/0")) },
    )

    private fun snapshot(
        working: String,
        head: String,
        acceptedId: String?,
        accepted: String?,
        status: String = "ACCEPTED",
    ) = RepairEvidenceSnapshot(
        profileId = "profile",
        profileSha256 = "1".repeat(64),
        reconstructionDescriptorSha256 = "2".repeat(64),
        indexSha256 = "3".repeat(64),
        indexBasisSourceRevisionSha256 = "c".repeat(64),
        workingRevisionSha256 = working.repeat(64),
        graphHeadId = "head",
        graphHeadSha256 = head.repeat(64),
        graphHeadStatus = status,
        fullyAcceptedHeadId = acceptedId,
        fullyAcceptedHeadSha256 = accepted?.repeat(64),
        regressionCorpusSha256 = "4".repeat(64),
        staticFacts = facts(),
        selectedEntityIds = listOf("fn_alpha", "global_state", "type_state"),
        behaviorCases = listOf(RepairBehaviorCaseEvidence("case", "5".repeat(64), "4".repeat(64))),
        diagnosticEvidence = RepairDiagnosticEvidence(
            hintSha256 = "6".repeat(64), subjectSourceRevisionSha256 = working.repeat(64),
            ownershipEvidenceSourceRevisionSha256 = null,
            attributionBasis = RepairDiagnosticAttributionBasis.CALLER_HINT_UNATTRIBUTED,
            selectedModuleIds = listOf("alpha"), matchedSourcePaths = listOf("src/modules/alpha.c"),
            includesSharedContext = false,
        ),
        omittedEntityCount = 0,
        omittedRecordCounts = mapOf("entities" to 0, "relations" to 0, "declarations" to 0, "definitions" to 0,
            "buildEvidence" to 0, "uncertainties" to 0),
        diagnosticHintSha256 = "6".repeat(64),
        maximumCanonicalBytes = 64 * 1024,
        uncertainties = listOf(RepairEvidenceUncertainty("case", "outcome", RepairEvidenceUncertaintyReason.EVIDENCE_NOT_CAPTURED)),
    )
}
