package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.project.ProgramModelJson
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
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
