package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.project.ProgramModelJson
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveryStatus
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class StructuralBoundaryReplayV1Test {
    @Test
    fun `historical rich fixture replays deterministically to an observed binding`() = withReplayFixture { fixture ->
        val first = fixture.replay()
        val second = fixture.replay()

        assertEquals(first.observedReplaySha256, second.observedReplaySha256)
        assertEquals(EXPECTED_OBSERVED_REPLAY_SHA256, first.observedReplaySha256)
        assertEquals(FUNCTION_ORACLE_SHA256, first.functionOracleSha256)
        assertEquals(BOUNDARY_REPORT_SHA256, first.boundaryReportSha256)
        assertEquals(RICH_MODEL_SHA256, first.recoveredProgramModelSha256)
        assertEquals("rich", first.twin)
        assertEquals(0x400000UL, first.selectedModelImageBase)
        assertEquals("1".repeat(64), first.inputSha256)
        assertEquals(
            RICH_MODEL_SHA256,
            OracleArtifacts.sha256(fixture.modelBytes),
            "the replay input must remain pinned to the exact canonical program-model bytes",
        )
        val historicalBytes = boundaryReplayResource("historical-rich-model.json")
        assertEquals(HISTORICAL_RICH_MODEL_SHA256, OracleArtifacts.sha256(historicalBytes))
        assertEquals(
            fixture.model,
            ProgramModelJson.read(historicalBytes.toString(StandardCharsets.UTF_8)),
            "canonical replay bytes must retain the historical Python fixture semantics",
        )
    }

    @Test
    fun `recovered names cannot choose the upper edge of an equal-distance tie`() = withReplayFixture { fixture ->
        val model = fixture.mutateModel { functions ->
            functions.map { function ->
                when (function.id) {
                    BETA_RECOVERED_ID -> function.copy(address = 0x40001fUL, name = "wrong-lower")
                    FALSE_POSITIVE_ID -> function.copy(address = 0x400021UL, name = "beta")
                    else -> function
                }
            }
        }
        val rich = fixture.richTwin()
        val betaNear = rich.array("nearMisses").single().objectValue()
        val lower = model.model.function(BETA_RECOVERED_ID)
        val upper = model.model.function(FALSE_POSITIVE_ID)
        val maliciousNear = betaNear.withRecovered(upper, 0x400000UL, delta = 1)
        val maliciousAssignment = rich.objectField("nearMatchAssignment").changed(
            "objective" to objective(1, 1),
            "hasAlternativeOptimalMatching" to JsonPrimitive(true),
            "optimalCandidateEdgeCount" to JsonPrimitive(2),
            "alternativeOptimalEdges" to JsonArray(
                listOf(assignmentEdge(betaNear, lower, 0x400000UL)),
            ),
        )
        val candidateDocument = fixture.boundary.document.changeRich { selected ->
            selected.changed(
                "nearMisses" to JsonArray(listOf(maliciousNear)),
                "falsePositives" to JsonArray(listOf(recoveredDetail(lower, 0x400000UL))),
                "nearMatchAssignment" to maliciousAssignment,
                "boundaries" to selected.objectField("boundaries").changed(
                    "nearMissDistanceBytes" to JsonPrimitive(1),
                ),
            )
        }
        val candidate = fixture.loadBoundary(candidateDocument)

        assertReplayRejected(fixture, candidate, model, "nearMisses")
    }

    @Test
    fun `a valid one-to-one near mapping is rejected when it is not minimum distance`() = withReplayFixture { fixture ->
        val model = fixture.mutateModel { functions ->
            functions.map { function ->
                when (function.id) {
                    BETA_RECOVERED_ID -> function.copy(address = 0x40001eUL)
                    FALSE_POSITIVE_ID -> function.copy(address = 0x400021UL)
                    else -> function
                }
            }
        }
        val rich = fixture.richTwin()
        val betaNear = rich.array("nearMisses").single().objectValue()
        val lower = model.model.function(BETA_RECOVERED_ID)
        val upper = model.model.function(FALSE_POSITIVE_ID)
        val candidateDocument = fixture.boundary.document.changeRich { selected ->
            selected.changed(
                "nearMisses" to JsonArray(listOf(betaNear.withRecovered(lower, 0x400000UL, delta = -2))),
                "falsePositives" to JsonArray(listOf(recoveredDetail(upper, 0x400000UL))),
            )
        }
        val candidate = fixture.loadBoundary(candidateDocument)

        assertReplayRejected(fixture, candidate, model, "nearMisses")
    }

    @Test
    fun `crossed name-driven pair sequence is rejected even when local equations close`() = withReplayFixture { fixture ->
        val oracleDocument = fixture.oracle.document.changed(
            "scoringPolicy" to fixture.oracle.document.objectField("scoringPolicy").changed(
                "nearMissBytes" to JsonPrimitive(32),
            ),
        )
        val oracle = fixture.loadOracle(oracleDocument)
        val model = fixture.mutateModel { functions ->
            functions.map { function ->
                when (function.id) {
                    BETA_RECOVERED_ID -> function.copy(name = "gamma")
                    FALSE_POSITIVE_ID -> function.copy(address = 0x40002eUL, name = "beta")
                    else -> function
                }
            }
        }
        val rich = fixture.richTwin()
        val beta = rich.array("nearMisses").single().objectValue()
        val gamma = rich.array("falseNegatives").single().objectValue()
        val betaRecovery = model.model.function(BETA_RECOVERED_ID)
        val gammaRecovery = model.model.function(FALSE_POSITIVE_ID)
        val crossedBeta = beta.withRecovered(gammaRecovery, 0x400000UL, delta = 14)
        val crossedGamma = JsonObject(
            gamma + recoveredDetail(betaRecovery, 0x400000UL) + mapOf(
                "deltaBytes" to JsonPrimitive(-14),
                "matchKind" to JsonPrimitive("near"),
                "nameResult" to JsonPrimitive("exact"),
                "matchedAlias" to JsonPrimitive("gamma"),
                "matchedAliasAvailability" to JsonPrimitive("surviving"),
                "nameCategoryResults" to JsonObject(
                    mapOf(
                        "surviving" to JsonPrimitive("exact"),
                        "removed" to JsonPrimitive("not-applicable"),
                    ),
                ),
            ),
        )
        val reportWithPolicy = fixture.boundary.document.changed(
            "policy" to fixture.boundary.document.objectField("policy").changed(
                "nearMissBytes" to JsonPrimitive(32),
            ),
        )
        val candidateDocument = reportWithPolicy.changeRich { selected ->
            selected.changed(
                "nearMisses" to JsonArray(listOf(crossedBeta, crossedGamma)),
                "falsePositives" to JsonArray(emptyList()),
                "falseNegatives" to JsonArray(emptyList()),
                "nearMatchAssignment" to selected.objectField("nearMatchAssignment").changed(
                    "objective" to objective(2, 28),
                    "hasAlternativeOptimalMatching" to JsonPrimitive(false),
                    "optimalCandidateEdgeCount" to JsonPrimitive(2),
                    "alternativeOptimalEdges" to JsonArray(emptyList()),
                ),
                "boundaries" to selected.objectField("boundaries").changed(
                    "nearMisses" to JsonPrimitive(2),
                    "truePositives" to JsonPrimitive(5),
                    "falsePositives" to JsonPrimitive(0),
                    "falseNegatives" to JsonPrimitive(0),
                    "nearMissDistanceBytes" to JsonPrimitive(28),
                ),
            )
        }
        val candidate = fixture.loadBoundary(candidateDocument, oracle)

        assertReplayRejected(fixture, candidate, model, "nearMisses", oracle)
    }

    @Test
    fun `recovered universe omissions and substitutions are rejected`() = withReplayFixture { fixture ->
        val rich = fixture.richTwin()
        val omittedDocument = fixture.boundary.document.changeRich { selected ->
            selected.changed(
                "falsePositives" to JsonArray(emptyList()),
                "boundaries" to selected.objectField("boundaries").changed(
                    "rawRecoveredCount" to JsonPrimitive(5),
                    "scoredRecoveredCount" to JsonPrimitive(4),
                    "falsePositives" to JsonPrimitive(0),
                ),
            )
        }
        val omitted = fixture.loadBoundary(omittedDocument)
        assertReplayRejected(fixture, omitted, fixture.baseModel, "falsePositives")

        val substitutedRecord = rich.array("falsePositives").single().objectValue().changed(
            "recoveredId" to JsonPrimitive("substituted-recovery"),
            "recoveredName" to JsonPrimitive("substituted_name"),
            "recoveredStatus" to JsonPrimitive("recovered"),
        )
        val substitutedDocument = fixture.boundary.document.changeRich { selected ->
            selected.changed("falsePositives" to JsonArray(listOf(substitutedRecord)))
        }
        val substituted = fixture.loadBoundary(substitutedDocument)
        assertReplayRejected(fixture, substituted, fixture.baseModel, "falsePositives")

        val ignored = rich.array("ignoredExcludedRecoveries").single().objectValue()
        val forgedScoredClone = JsonObject(
            mapOf(
                "recoveredId" to ignored.getValue("recoveredId"),
                "recoveredRva" to ignored.getValue("recoveredRva"),
                "recoveredName" to ignored.getValue("recoveredName"),
                "recoveredStatus" to ignored.getValue("recoveredStatus"),
            ),
        )
        val exclusionPartitionDocument = fixture.boundary.document.changeRich { selected ->
            selected.changed(
                "falsePositives" to JsonArray(selected.array("falsePositives") + forgedScoredClone),
                "ignoredExcludedRecoveries" to JsonArray(emptyList()),
                "boundaries" to selected.objectField("boundaries").changed(
                    "scoredRecoveredCount" to JsonPrimitive(6),
                    "ignoredExcludedCount" to JsonPrimitive(0),
                    "falsePositives" to JsonPrimitive(2),
                ),
            )
        }
        val exclusionPartition = fixture.loadBoundary(exclusionPartitionDocument)
        assertReplayRejected(fixture, exclusionPartition, fixture.baseModel, "falsePositives")
    }

    @Test
    fun `selected base underflow and executable-range escapes fail closed`() = withReplayFixture { fixture ->
        val mismatch = assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.replay(selectedBase = 0x400001UL)
        }
        assertTrue(mismatch.message.orEmpty().contains("selected model image base"))

        val underflowDocument = fixture.boundary.document.changeRich { selected ->
            selected.changed(
                "artifact" to selected.objectField("artifact").changed(
                    "modelImageBase" to JsonPrimitive("0x400011"),
                ),
            )
        }
        val underflowCandidate = fixture.loadBoundary(underflowDocument)
        val underflow = assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.replay(underflowCandidate, selectedBase = 0x400011UL)
        }
        assertTrue(underflow.message.orEmpty().contains("below the selected model image base"))

        val outside = fixture.mutateModel { functions ->
            functions.map { function ->
                if (function.id == ALPHA_RECOVERED_ID) function.copy(address = 0x401000UL) else function
            }
        }
        val rangeFailure = assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.replay(fixture.boundary, outside)
        }
        assertTrue(rangeFailure.message.orEmpty().contains("outside executable ranges"))
    }

    @Test
    fun `duplicate normalized starts and noncanonical model bytes fail closed`() = withReplayFixture { fixture ->
        val duplicate = fixture.mutateModel { functions ->
            functions + functions.first { it.id == ALPHA_RECOVERED_ID }.copy(id = "duplicate-start")
        }
        val duplicateFailure = assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.replay(fixture.boundary, duplicate)
        }
        assertTrue(duplicateFailure.message.orEmpty().contains("normalize to RVA"))

        val noncanonical = fixture.modelBytes + '\n'.code.toByte()
        val canonicalFailure = assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralBoundaryReplayV1.replay(
                fixture.oracle,
                fixture.boundary,
                fixture.model,
                noncanonical,
                0x400000UL,
            )
        }
        assertTrue(canonicalFailure.message.orEmpty().contains("exact canonical"))
    }

    @Test
    fun `replay derives facts from the authenticated parsed snapshot only`() = withReplayFixture { fixture ->
        val forgedFunctions = fixture.model.functions.map { function ->
            if (function.id == ALPHA_RECOVERED_ID) function.copy(address = 0x401000UL) else function
        }
        val switching = IterationSwitchingFunctionList(fixture.model.functions, forgedFunctions)
        val callerModel = fixture.model.copy(functions = switching)

        val binding = StructuralBoundaryReplayV1.replay(
            fixture.oracle,
            fixture.boundary,
            callerModel,
            fixture.modelBytes,
            0x400000UL,
        )

        assertEquals(EXPECTED_OBSERVED_REPLAY_SHA256, binding.observedReplaySha256)
        assertEquals(2, switching.iteratorCalls, "caller model must only be constructed and compared")
    }

    @Test
    fun `objective tie ambiguity and canonical-report claims are independently checked`() = withReplayFixture { fixture ->
        val rich = fixture.richTwin()
        val assignment = rich.objectField("nearMatchAssignment")
        val forgedAssignments = listOf(
            assignment.changed("nameIndependent" to JsonPrimitive(false)),
            assignment.changed("objective" to objective(99, 2)),
            assignment.changed("stableTieBreak" to JsonPrimitive("names first")),
            assignment.changed(
                "hasAlternativeOptimalMatching" to JsonPrimitive(true),
                "optimalCandidateEdgeCount" to JsonPrimitive(2),
            ),
        )
        forgedAssignments.forEach { forgedAssignment ->
            val document = fixture.boundary.document.changeRich { selected ->
                selected.changed("nearMatchAssignment" to forgedAssignment)
            }
            val forged = fixture.forgeBoundary(document)
            assertReplayRejected(fixture, forged, fixture.baseModel, "nearMatchAssignment")
        }

        val noncanonical = fixture.forgeBoundary(
            fixture.boundary.document,
            StructuralJsonEncoder(64 * 1024 * 1024, pretty = true, ensureAscii = true)
                .encode(fixture.boundary.document) + '\n'.code.toByte(),
        )
        assertReplayRejected(fixture, noncanonical, fixture.baseModel, "exact canonical historical")

        val computationLimit = assertFailsWith<StructuralRecoveryV1Exception> {
            fixture.replay(
                limits = StructuralBoundaryReplayV1Limits(maximumMatchingCells = 8),
            )
        }
        assertTrue(computationLimit.message.orEmpty().contains("cell limit"))
    }

    @Test
    fun `selected observation reproduces every historical rich projection without scoring authority`() =
        withReplayFixture { fixture ->
            val observation = fixture.observeSelected()
            val document = observation.canonicalBytes.observationDocument()
            val expectedFields = setOf(
                "exactMatches", "nearMisses", "falsePositives", "falseNegatives",
                "ignoredExcludedRecoveries", "nearMatchAssignment", "boundaries", "nameRecovery",
            )
            val result = document.objectField("result")

            assertEquals(expectedFields, result.keys)
            expectedFields.forEach { field ->
                assertEquals(fixture.richTwin().getValue(field), result.getValue(field), field)
            }
            assertEquals(JsonPrimitive("selected-twin-boundary-observation-v1"), document["provider"])
            assertEquals(JsonPrimitive(1), document["schemaVersion"])
            assertEquals(JsonPrimitive("rich"), document["twin"])
            assertEquals(JsonPrimitive("1".repeat(64)), document["inputSha256"])
            assertEquals(JsonPrimitive(RICH_MODEL_SHA256), document["programModelSha256"])
            assertEquals(JsonPrimitive(fixture.modelBytes.size), document["programModelBytes"])
            assertEquals(JsonPrimitive(FUNCTION_ORACLE_SHA256), document["functionOracleSha256"])
            assertEquals(address(0x400000UL), document["selectedModelImageBase"])
            assertEquals(
                fixture.richTwin().objectField("artifact")["executableRvaRanges"],
                document["executableRvaRanges"],
            )
            assertEquals(JsonPrimitive(4), document["nearMissBytes"])
            assertEquals(fixture.boundary.document["policy"], document["policy"])
            assertEquals(fixture.oracle.expectedExcludedFunctions, document["excludedFunctions"])
            assertEquals(outcomeCounts(recovered = 4, partial = 1, synthetic = 1), document["recoveredOutcomeCounts"])
            listOf("scored", "complete", "releaseEligible").forEach { flag ->
                assertEquals(JsonPrimitive(false), document[flag], flag)
            }
            assertTrue("twins" !in document, "a selected observation must not invent an unobserved twin")
            assertEquals(OracleArtifacts.sha256(observation.canonicalBytes), observation.sha256)
        }

    @Test
    fun `selected observation bytes are deterministic and defensively owned`() = withReplayFixture { fixture ->
        val input = fixture.modelBytes.copyOf()
        val first = StructuralBoundaryReplayV1.observeSelected(fixture.oracle, "rich", input, 0x400000UL)
        val expected = first.canonicalBytes
        val second = fixture.observeSelected()
        val verified = StructuralBoundaryReplayV1.verifySelected(
            fixture.oracle, "rich", fixture.modelBytes, 0x400000UL, expected,
        )

        assertContentEquals(expected, second.canonicalBytes)
        assertContentEquals(expected, verified.canonicalBytes)
        assertEquals(first.sha256, second.sha256)
        assertEquals(first.sha256, verified.sha256)
        input.fill(0)
        first.canonicalBytes.fill(0)
        expected.fill(0)
        assertContentEquals(second.canonicalBytes, first.canonicalBytes)
        assertContentEquals(second.canonicalBytes, verified.canonicalBytes)
        assertEquals(OracleArtifacts.sha256(first.canonicalBytes), first.sha256)
    }

    @Test
    fun `selected verification rejects altered results metadata and canonical bytes`() = withReplayFixture { fixture ->
        val observation = fixture.observeSelected()
        val document = observation.canonicalBytes.observationDocument()
        val mutations = listOf(
            document.changed(
                "result" to document.objectField("result").changed("falsePositives" to JsonArray(emptyList())),
            ),
            document.changed("excludedFunctions" to JsonArray(emptyList())),
            document.changed("recoveredOutcomeCounts" to outcomeCounts(recovered = 6)),
            document.changed("scored" to JsonPrimitive(true)),
            document.changed("functionOracleSha256" to JsonPrimitive("0".repeat(64))),
        )
        mutations.forEach { mutated ->
            val bytes = StructuralJsonEncoder(64 * 1024 * 1024, pretty = true, ensureAscii = true).encode(mutated)
            assertFailsWith<StructuralRecoveryV1Exception> {
                StructuralBoundaryReplayV1.verifySelected(
                    fixture.oracle, "rich", fixture.modelBytes, 0x400000UL, bytes,
                )
            }
        }
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralBoundaryReplayV1.verifySelected(
                fixture.oracle, "rich", fixture.modelBytes, 0x400000UL,
                observation.canonicalBytes + '\n'.code.toByte(),
            )
        }
    }

    @Test
    fun `selected verification cannot reuse an observation for another model twin base or oracle`() =
        withReplayFixture { fixture ->
            val original = fixture.observeSelected().canonicalBytes
            val changedModel = fixture.mutateModel { functions ->
                functions.map { function ->
                    if (function.id == ALPHA_RECOVERED_ID) function.copy(prototype = "long alpha(void)") else function
                }
            }
            val strippedModel = fixture.model.copy(inputSha256 = "2".repeat(64))
                .toJson().toByteArray(StandardCharsets.UTF_8)
            val oracle = fixture.loadOracle(
                fixture.oracle.document.changed(
                    "scoringPolicy" to fixture.oracle.document.objectField("scoringPolicy").changed(
                        "nearMissBytes" to JsonPrimitive(3),
                    ),
                ),
            )

            assertEquals(
                original.observationDocument()["result"],
                fixture.observeSelected(changedModel).canonicalBytes.observationDocument()["result"],
                "a non-boundary model change must still invalidate the exact model-byte binding",
            )
            assertFailsWith<StructuralRecoveryV1Exception> {
                StructuralBoundaryReplayV1.verifySelected(fixture.oracle, "rich", changedModel.bytes, 0x400000UL, original)
            }
            assertFailsWith<StructuralRecoveryV1Exception> {
                StructuralBoundaryReplayV1.verifySelected(fixture.oracle, "stripped", strippedModel, 0x400000UL, original)
            }
            assertFailsWith<StructuralRecoveryV1Exception> {
                StructuralBoundaryReplayV1.verifySelected(fixture.oracle, "rich", fixture.modelBytes, 0x400001UL, original)
            }
            assertFailsWith<StructuralRecoveryV1Exception> {
                StructuralBoundaryReplayV1.verifySelected(oracle, "rich", fixture.modelBytes, 0x400000UL, original)
            }

            val stripped = StructuralBoundaryReplayV1.observeSelected(
                fixture.oracle, "stripped", strippedModel, 0x400000UL,
            ).canonicalBytes.observationDocument()
            assertEquals(JsonPrimitive("stripped"), stripped["twin"])
            assertEquals(JsonPrimitive("2".repeat(64)), stripped["inputSha256"])
            val alpha = stripped.objectField("result").array("exactMatches").map { it.objectValue() }
                .single { it["recoveredId"] == JsonPrimitive(ALPHA_RECOVERED_ID) }
            assertEquals(JsonPrimitive("removed"), alpha["matchedAliasAvailability"])
            assertEquals(JsonPrimitive(false), stripped["scored"])
            assertTrue("twins" !in stripped)
        }

    @Test
    fun `selected observation preserves name-independent stable ties and exclusion accounting`() =
        withReplayFixture { fixture ->
            val model = fixture.mutateModel { functions ->
                functions.map { function ->
                    when (function.id) {
                        BETA_RECOVERED_ID -> function.copy(address = 0x40001fUL, name = "wrong-lower")
                        FALSE_POSITIVE_ID -> function.copy(address = 0x400021UL, name = "beta")
                        else -> function
                    }
                }
            }
            val result = fixture.observeSelected(model).canonicalBytes.observationDocument().objectField("result")
            val near = result.array("nearMisses").single().objectValue()
            val assignment = result.objectField("nearMatchAssignment")
            val upper = model.model.function(FALSE_POSITIVE_ID)

            assertEquals(JsonPrimitive(BETA_RECOVERED_ID), near["recoveredId"])
            assertEquals(JsonPrimitive(-1), near["deltaBytes"])
            assertEquals(JsonPrimitive("incorrect"), near["nameResult"])
            assertEquals(JsonArray(listOf(recoveredDetail(upper, 0x400000UL))), result["falsePositives"])
            assertEquals(objective(1, 1), assignment["objective"])
            assertEquals(JsonPrimitive(true), assignment["nameIndependent"])
            assertEquals(JsonPrimitive(true), assignment["hasAlternativeOptimalMatching"])
            assertEquals(JsonPrimitive(2), assignment["optimalCandidateEdgeCount"])
            assertEquals(
                JsonArray(
                    listOf(assignmentEdge(fixture.richTwin().array("nearMisses").single().objectValue(), upper, 0x400000UL)),
                ),
                assignment["alternativeOptimalEdges"],
            )
            assertEquals(fixture.richTwin()["ignoredExcludedRecoveries"], result["ignoredExcludedRecoveries"])
            assertEquals(fixture.richTwin()["falseNegatives"], result["falseNegatives"])
            assertEquals(
                fixture.richTwin().objectField("boundaries").changed("nearMissDistanceBytes" to JsonPrimitive(1)),
                result["boundaries"],
            )
            assertFailsWith<StructuralRecoveryV1Exception> {
                fixture.observeSelected(model, limits = StructuralBoundaryReplayV1Limits(maximumAmbiguityEdges = 1))
            }
        }

    @Test
    fun `selected observation retains failed extraction records in every recovered boundary partition`() =
        withReplayFixture { fixture ->
            val model = fixture.mutateModel { functions -> functions.map { it.copy(status = RecoveryStatus.FAILED) } }
            val document = fixture.observeSelected(model).canonicalBytes.observationDocument()
            val result = document.objectField("result")
            val recoveredPartitions = listOf("exactMatches", "nearMisses", "falsePositives", "ignoredExcludedRecoveries")
            val observedIds = mutableListOf<String>()

            recoveredPartitions.forEach { field ->
                val expected = JsonArray(
                    fixture.richTwin().array(field).map {
                        it.objectValue().changed("recoveredStatus" to JsonPrimitive("failed"))
                    },
                )
                assertEquals(expected, result[field], "$field must not drop a failed extraction boundary")
                result.array(field).forEach { raw ->
                    observedIds += (raw.objectValue().getValue("recoveredId") as JsonPrimitive).content
                }
            }
            assertEquals(model.model.functions.map { it.id }.sorted(), observedIds.sorted())
            assertEquals(observedIds.size, observedIds.toSet().size, "partitions must be disjoint")
            assertEquals(outcomeCounts(failed = 6), document["recoveredOutcomeCounts"])
            assertEquals(fixture.richTwin()["boundaries"], result["boundaries"])
            assertEquals(fixture.richTwin()["falseNegatives"], result["falseNegatives"])
            assertEquals(fixture.richTwin()["nameRecovery"], result["nameRecovery"])
            assertEquals(JsonPrimitive(false), document["scored"])
            assertEquals(JsonPrimitive(false), document["releaseEligible"])
        }

    @Test
    fun `selected full export parser admits large source without widening historical replay`() = withReplayFixture { fixture ->
        val source = "x".repeat(16 * 1024 * 1024 + 1)
        val changed = fixture.mutateModel { functions -> functions.map { function ->
            if (function.id == ALPHA_RECOVERED_ID) function.copy(decompiledC = source) else function
        } }
        val modelLimits = CanonicalProgramModelStreamingLimits(maximumTextCodePoints = 64 * 1024 * 1024)
        assertFailsWith<StructuralRecoveryV1Exception> { fixture.observeSelected(changed) }
        assertFailsWith<StructuralRecoveryV1Exception> { fixture.replay(replayModel = changed) }
        val observed = StructuralBoundaryReplayV1.observeSelected(
            fixture.oracle, "rich", changed.bytes, 0x400000UL, modelLimits = modelLimits,
        )
        val document = observed.canonicalBytes.observationDocument()
        assertEquals(fixture.observeSelected().canonicalBytes.observationDocument()["result"], document["result"])
        assertEquals(JsonPrimitive(64 * 1024 * 1024), document.objectField("programModelParserLimits")["maximumTextCodePoints"])
        assertEquals(JsonPrimitive(64 * 1024 * 1024), document.objectField("policy").objectField("limits")["maxTextCharacters"])
        assertEquals(JsonPrimitive(20_000), document.objectField("policy").objectField("limits")["maxFunctionRecords"])
        assertEquals(JsonPrimitive(20_000_000), document.objectField("policy").objectField("limits")["maxMatchingCells"])
        assertContentEquals(observed.canonicalBytes, StructuralBoundaryReplayV1.verifySelected(
            fixture.oracle, "rich", changed.bytes, 0x400000UL, observed.canonicalBytes, modelLimits = modelLimits,
        ).canonicalBytes)
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralBoundaryReplayV1.observeSelected(
                fixture.oracle, "rich", changed.bytes, 0x400000UL,
                modelLimits = modelLimits.copy(maximumFunctions = 20_001),
            )
        }
        assertFailsWith<StructuralRecoveryV1Exception> {
            StructuralBoundaryReplayV1.verifySelected(
                fixture.oracle, "rich", changed.bytes, 0x400000UL, observed.canonicalBytes,
                modelLimits = modelLimits.copy(maximumTextCodePoints = 32 * 1024 * 1024),
            )
        }
    }

    @Test
    fun `selected observation enforces canonical input address and resource bounds`() = withReplayFixture { fixture ->
        val invalidInputs = listOf(
            fixture.baseModel.copy(bytes = fixture.modelBytes + '\n'.code.toByte()),
            fixture.mutateModel { functions ->
                functions + functions.first().copy(id = "duplicate-selected-start")
            },
            fixture.mutateModel { functions ->
                functions.map { if (it.id == ALPHA_RECOVERED_ID) it.copy(address = 0x401000UL) else it }
            },
        )
        invalidInputs.forEach { model ->
            assertFailsWith<StructuralRecoveryV1Exception> { fixture.observeSelected(model) }
        }
        assertFailsWith<StructuralRecoveryV1Exception> { fixture.observeSelected(selectedBase = 0x400011UL) }
        listOf(
            StructuralBoundaryReplayV1Limits(maximumProgramModelBytes = fixture.modelBytes.size - 1),
            StructuralBoundaryReplayV1Limits(maximumFunctionRecords = fixture.model.functions.size - 1),
            StructuralBoundaryReplayV1Limits(maximumMatchingCells = 8),
        ).forEach { limits ->
            assertFailsWith<StructuralRecoveryV1Exception> { fixture.observeSelected(limits = limits) }
        }
        listOf("stripped", "unknown").forEach { twin ->
            assertFailsWith<StructuralRecoveryV1Exception> {
                StructuralBoundaryReplayV1.observeSelected(fixture.oracle, twin, fixture.modelBytes, 0x400000UL)
            }
        }
    }

    private companion object {
        const val ALPHA_RECOVERED_ID = "fn_0000000000400010"
        const val BETA_RECOVERED_ID = "fn_0000000000400022"
        const val FALSE_POSITIVE_ID = "fn_0000000000400080"
        const val FUNCTION_ORACLE_SHA256 = "3239d0747456fb92edb48c322464cd76573236b107454d84b10553da23299f93"
        const val BOUNDARY_REPORT_SHA256 = "b05d85d9f21e704c2581b84ded3ea5442eb4695ed75e74d25778e417a5a8d593"
        const val HISTORICAL_RICH_MODEL_SHA256 = "b15e5576ae86b07dbe561c40acfd57c6717ff66e77010e543de758f29e7138d5"
        const val RICH_MODEL_SHA256 = "aaa37c236f0c0f9f6f69a2bbd045d9d9cb234912008a7444d38c7c7b90132e51"
        const val EXPECTED_OBSERVED_REPLAY_SHA256 = "83906419c25178a1e2db674e7c3bec3b55aad9273eaf6da3bfcaf46545f4d6fa"
    }
}

/** Presents canonical values for construction/equality, then forged values on any later traversal. */
private class IterationSwitchingFunctionList(
    private val canonical: List<RecoveredFunction>,
    private val forged: List<RecoveredFunction>,
) : java.util.AbstractList<RecoveredFunction>() {
    var iteratorCalls: Int = 0
        private set

    override val size: Int
        get() = canonical.size

    override fun get(index: Int): RecoveredFunction = canonical[index]

    override fun iterator(): MutableIterator<RecoveredFunction> {
        iteratorCalls++
        val selected = if (iteratorCalls <= 2) canonical else forged
        return selected.toMutableList().iterator()
    }
}

private data class ReplayModelFixture(val model: RecoveredProgramModel, val bytes: ByteArray)

private class BoundaryReplayFixture(
    private val files: StructuralV1Fixture,
    val target: StructuralTargetAbiV1,
    val oracle: StructuralFunctionOracleV1,
    val boundary: StructuralBoundaryMappingV1,
    val model: RecoveredProgramModel,
    val modelBytes: ByteArray,
) {
    private var sequence = 0
    val baseModel: ReplayModelFixture
        get() = ReplayModelFixture(model, modelBytes)

    fun replay(
        candidate: StructuralBoundaryMappingV1 = boundary,
        replayModel: ReplayModelFixture = ReplayModelFixture(model, modelBytes),
        selectedBase: ULong = 0x400000UL,
        limits: StructuralBoundaryReplayV1Limits = StructuralBoundaryReplayV1Limits(),
        suppliedOracle: StructuralFunctionOracleV1 = oracle,
    ): StructuralBoundaryReplayBindingV1 = StructuralBoundaryReplayV1.replay(
        suppliedOracle,
        candidate,
        replayModel.model,
        replayModel.bytes,
        selectedBase,
        limits,
    )

    fun richTwin(): JsonObject = boundary.document.objectField("twins").objectField("rich")

    fun observeSelected(
        replayModel: ReplayModelFixture = baseModel,
        selectedBase: ULong = 0x400000UL,
        limits: StructuralBoundaryReplayV1Limits = StructuralBoundaryReplayV1Limits(),
    ): StructuralSelectedBoundaryObservationV1 = StructuralBoundaryReplayV1.observeSelected(
        oracle, "rich", replayModel.bytes, selectedBase, limits,
    )

    fun mutateModel(transform: (List<RecoveredFunction>) -> List<RecoveredFunction>): ReplayModelFixture {
        val functions = transform(model.functions).sortedWith(
            compareBy<RecoveredFunction> { it.address }.thenBy { it.id },
        )
        val changed = model.copy(functions = functions)
        val bytes = changed.toJson().toByteArray(StandardCharsets.UTF_8)
        assertEquals(changed, ProgramModelJson.readCanonical(bytes), "test mutation must remain a canonical exact model")
        return ReplayModelFixture(changed, bytes)
    }

    fun loadOracle(document: JsonObject): StructuralFunctionOracleV1 {
        val path = writeDocument("function-oracle", document)
        return StructuralRecoveryV1Inputs.loadFunctionOracle(path)
    }

    fun loadBoundary(
        document: JsonObject,
        suppliedOracle: StructuralFunctionOracleV1 = oracle,
    ): StructuralBoundaryMappingV1 {
        val path = writeDocument("boundary-score", document)
        return StructuralRecoveryV1Inputs.loadBoundaryMapping(path, "rich", target, suppliedOracle)
    }

    fun forgeBoundary(
        document: JsonObject,
        bytes: ByteArray = StructuralJsonEncoder(64 * 1024 * 1024, pretty = true, ensureAscii = true).encode(document),
    ): StructuralBoundaryMappingV1 = StructuralBoundaryMappingV1(
        snapshot = StructuralSnapshot(files.path("forged-${sequence++}.json"), bytes),
        upstreamOracleSnapshot = boundary.upstreamOracleSnapshot,
        document = document,
        twin = boundary.twin,
        projectionAdapterId = boundary.projectionAdapterId,
        projectionAdapterVersion = boundary.projectionAdapterVersion,
        objectFormat = boundary.objectFormat,
        inputSha256 = boundary.inputSha256,
        modelImageBase = boundary.modelImageBase,
        executableRvaRanges = boundary.executableRvaRanges,
        oracleToRecovered = boundary.oracleToRecovered,
        recoveredToOracle = boundary.recoveredToOracle,
        oracleFunctionIds = boundary.oracleFunctionIds,
        recoveredFunctionIds = boundary.recoveredFunctionIds,
        excludedOracleIds = boundary.excludedOracleIds,
        ignoredRecoveredIds = boundary.ignoredRecoveredIds,
    )

    private fun writeDocument(label: String, document: JsonObject) = files.path("$label-${sequence++}.json").also { path ->
        val bytes = StructuralJsonEncoder(64 * 1024 * 1024, pretty = true, ensureAscii = true).encode(document)
        Files.write(path, bytes)
        setPermissions(path, "rw-------")
    }
}

private fun <T> withReplayFixture(block: (BoundaryReplayFixture) -> T): T = withStructuralFixture { files ->
    val loaded = files.load()
    val modelBytes = boundaryReplayResource("rich-model.json")
    val model = ProgramModelJson.readCanonical(modelBytes)
    block(
        BoundaryReplayFixture(
            files,
            loaded.target,
            loaded.functionOracle,
            loaded.boundary,
            model,
            modelBytes,
        ),
    )
}

private fun boundaryReplayResource(name: String): ByteArray = checkNotNull(
    StructuralBoundaryReplayV1Test::class.java.getResourceAsStream(
        "/oracle/structural-boundary-replay-v1/$name",
    ),
) { "missing boundary-replay fixture: $name" }.use { it.readAllBytes() }

private fun assertReplayRejected(
    fixture: BoundaryReplayFixture,
    candidate: StructuralBoundaryMappingV1,
    model: ReplayModelFixture,
    messageFragment: String,
    oracle: StructuralFunctionOracleV1 = fixture.oracle,
) {
    val failure = assertFailsWith<StructuralRecoveryV1Exception> {
        fixture.replay(candidate, model, suppliedOracle = oracle)
    }
    assertTrue(
        failure.message.orEmpty().contains(messageFragment),
        "expected replay failure containing '$messageFragment', got '${failure.message}'",
    )
}

private fun JsonObject.changed(vararg replacements: Pair<String, JsonElement>): JsonObject = JsonObject(
    toMutableMap().apply { replacements.forEach { (key, value) -> put(key, value) } },
)

private fun JsonObject.changeRich(transform: (JsonObject) -> JsonObject): JsonObject {
    val twins = objectField("twins")
    return changed("twins" to twins.changed("rich" to transform(twins.objectField("rich"))))
}

private fun JsonObject.objectField(name: String): JsonObject = getValue(name).objectValue()
private fun JsonObject.array(name: String): JsonArray = getValue(name) as JsonArray
private fun JsonElement.objectValue(): JsonObject = this as JsonObject

private fun ByteArray.observationDocument(): JsonObject =
    Json.parseToJsonElement(toString(StandardCharsets.UTF_8)).objectValue()

private fun outcomeCounts(
    recovered: Int = 0,
    partial: Int = 0,
    failed: Int = 0,
    synthetic: Int = 0,
): JsonObject = JsonObject(
    mapOf(
        "recovered" to JsonPrimitive(recovered),
        "partial" to JsonPrimitive(partial),
        "failed" to JsonPrimitive(failed),
        "synthetic" to JsonPrimitive(synthetic),
    ),
)

private fun JsonObject.withRecovered(
    function: RecoveredFunction,
    imageBase: ULong,
    delta: Int,
): JsonObject = changed(
    "recoveredId" to JsonPrimitive(function.id),
    "recoveredRva" to address(function.address - imageBase),
    "recoveredName" to JsonPrimitive(function.name),
    "recoveredStatus" to JsonPrimitive(function.status.name.lowercase(Locale.ROOT)),
    "deltaBytes" to JsonPrimitive(delta),
)

private fun recoveredDetail(function: RecoveredFunction, imageBase: ULong): JsonObject = JsonObject(
    mapOf(
        "recoveredId" to JsonPrimitive(function.id),
        "recoveredRva" to address(function.address - imageBase),
        "recoveredName" to JsonPrimitive(function.name),
        "recoveredStatus" to JsonPrimitive(function.status.name.lowercase(Locale.ROOT)),
    ),
)

private fun assignmentEdge(
    oracleMatch: JsonObject,
    function: RecoveredFunction,
    imageBase: ULong,
): JsonObject {
    val oracleRva = oracleMatch.getValue("oracleRva").jsonAddress()
    val recoveredRva = function.address - imageBase
    val delta = recoveredRva.toLong() - oracleRva.toLong()
    return JsonObject(
        mapOf(
            "oracleId" to oracleMatch.getValue("oracleId"),
            "oracleRva" to oracleMatch.getValue("oracleRva"),
            "recoveredId" to JsonPrimitive(function.id),
            "recoveredRva" to address(recoveredRva),
            "deltaBytes" to JsonPrimitive(delta),
            "distanceBytes" to JsonPrimitive(kotlin.math.abs(delta)),
        ),
    )
}

private fun objective(cardinality: Int, distance: Int): JsonObject = JsonObject(
    mapOf(
        "maximumCardinality" to JsonPrimitive(cardinality),
        "minimumTotalDistanceBytes" to JsonPrimitive(distance),
    ),
)

private fun RecoveredProgramModel.function(id: String): RecoveredFunction = functions.single { it.id == id }

private fun JsonElement.jsonAddress(): ULong =
    (this as JsonPrimitive).content.removePrefix("0x").toULong(16)

private fun address(value: ULong): JsonPrimitive = JsonPrimitive("0x${value.toString(16)}")
