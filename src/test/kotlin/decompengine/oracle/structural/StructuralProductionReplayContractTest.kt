package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class StructuralProductionReplayContractTest {
    @Test
    fun `frozen receipts have exact acyclic canonical bytes and independent hashes`() {
        val fixture = ReplayFixture()
        val receipts = fixture.receipts()
        val frozenIdentity = resourceBase64("identity-receipt-v1.canonical.b64")
        val frozenModel = resourceBase64("model-receipt-v1.canonical.b64")

        assertContentEquals(frozenIdentity, receipts.identity.canonicalBytes)
        assertContentEquals(frozenModel, receipts.model.canonicalBytes)
        assertEquals(FROZEN_IDENTITY_SELF_SHA256, receipts.identity.selfSha256)
        assertEquals(FROZEN_IDENTITY_ARTIFACT_SHA256, receipts.identity.artifactSha256)
        assertEquals(FROZEN_REQUEST_SHA256, receipts.identity.requestSha256)
        assertEquals(FROZEN_OBSERVATION_SHA256, receipts.identity.observationSha256)
        assertEquals(FROZEN_OUTPUT_TREE_SHA256, receipts.identity.observation.outputTree.sha256)
        assertEquals(FROZEN_MODEL_PROVENANCE_SHA256, receipts.model.model.provenanceSha256)
        assertEquals(FROZEN_MODEL_SELF_SHA256, receipts.model.selfSha256)
        assertEquals(FROZEN_MODEL_ARTIFACT_SHA256, receipts.model.artifactSha256)
        assertEquals(receipts.identity.artifactSha256, receipts.model.identityReceiptSha256)
        assertFalse(receipts.identity.selfSha256 == receipts.identity.artifactSha256)
        assertFalse(receipts.model.selfSha256 == receipts.model.artifactSha256)
    }

    @Test
    fun `canonical parsing rejects whitespace duplicate malformed and extra fields`(): Unit = inTemporaryDirectory { directory ->
        val fixture = ReplayFixture()
        val receipts = fixture.receipts()
        val identityPath = directory.resolve("identity.json")
        Files.write(identityPath, receipts.identity.canonicalBytes + byteArrayOf('\n'.code.toByte()))
        assertFailsWith<StructuralProductionReplayException> {
            fixture.authenticateIdentity(identityPath)
        }

        val text = receipts.identity.canonicalBytes.decodeToString()
        Files.writeString(identityPath, text.replaceFirst("{", "{\"kind\":\"${StructuralProductionReplayContract.IDENTITY_RECEIPT_KIND}\","))
        assertFailsWith<StructuralProductionReplayException> { fixture.authenticateIdentity(identityPath) }

        Files.writeString(identityPath, text.dropLast(1))
        assertFailsWith<StructuralProductionReplayException> { fixture.authenticateIdentity(identityPath) }

        val extra = mutateAndResign(receipts.identity.document) { root -> root + ("extra" to JsonPrimitive(true)) }
        Files.write(identityPath, extra)
        assertFailsWith<StructuralProductionReplayException> { fixture.authenticateIdentity(identityPath) }
    }

    @Test
    fun `planning mode and any request anchor substitution reject even after resigning`() {
        val fixture = ReplayFixture()
        val identity = fixture.receipts().identity
        listOf(
            mutateRequest(identity.document, "recoveryMode", JsonPrimitive("planning")),
            mutateNestedRequest(identity.document, "profile", "sha256", JsonPrimitive(hash('e'))),
            mutateNestedRequest(identity.document, "inputBinary", "bytes", JsonPrimitive(123_457)),
            mutateNestedRequest(identity.document, "loader", "implementationSha256", JsonPrimitive(hash('e'))),
            mutateNestedRequest(identity.document, "sandbox", "policySha256", JsonPrimitive(hash('e'))),
        ).forEach { bytes ->
            assertFailsWith<StructuralProductionReplayException> {
                fixture.authenticateIdentityBytes(bytes)
            }
        }
    }

    @Test
    fun `failed truncated nonisolated and unclean execution observations reject`() {
        val fixture = ReplayFixture()
        val identity = fixture.receipts().identity
        val cases = listOf(
            "networkIsolated" to JsonPrimitive(false),
            "exitCode" to JsonPrimitive(7),
            "terminalOutcome" to JsonPrimitive("killed"),
            "timedOut" to JsonPrimitive(true),
            "outOfMemory" to JsonPrimitive(true),
            "cleanupVerified" to JsonPrimitive(false),
        )
        cases.forEach { (key, value) ->
            assertFailsWith<StructuralProductionReplayException> {
                fixture.authenticateIdentityBytes(mutateExecution(identity.document, key, value))
            }
        }
        val truncated = mutateStream(identity.document, "stdout", "truncated", JsonPrimitive(true))
        assertFailsWith<StructuralProductionReplayException> { fixture.authenticateIdentityBytes(truncated) }
    }

    @Test
    fun `missing extra and substituted output commitments reject`() {
        val fixture = ReplayFixture()
        val identity = fixture.receipts().identity
        listOf(
            mutateOutputTree(identity.document, "fileCount", JsonPrimitive(1)),
            mutateOutputTree(identity.document, "fileCount", JsonPrimitive(3)),
            mutateOutputTree(identity.document, "totalBytes", JsonPrimitive(301)),
            mutateOutputTree(identity.document, "sha256", JsonPrimitive(hash('f'))),
            mutateObservationArtifact(identity.document, "programModel", "sha256", JsonPrimitive(hash('f'))),
        ).forEach { bytes ->
            assertFailsWith<StructuralProductionReplayException> { fixture.authenticateIdentityBytes(bytes) }
        }
    }

    @Test
    fun `self hash count equations and digest cycle mistakes reject`() {
        val fixture = ReplayFixture()
        val receipts = fixture.receipts()
        val forgedSelf = canonical(
            JsonObject(receipts.identity.document + ("receiptSha256" to JsonPrimitive(hash('0')))),
        )
        assertFailsWith<StructuralProductionReplayException> { fixture.authenticateIdentityBytes(forgedSelf) }

        val selfAsArtifact = canonical(
            JsonObject(
                receipts.identity.document +
                    ("receiptSha256" to JsonPrimitive(receipts.identity.artifactSha256)),
            ),
        )
        assertFailsWith<StructuralProductionReplayException> { fixture.authenticateIdentityBytes(selfAsArtifact) }

        val badBoundary = mutateNestedRoot(
            receipts.identity.document,
            "boundaryReplay",
            "rawRecoveredCount",
            JsonPrimitive(4),
        )
        assertFailsWith<StructuralProductionReplayException> { fixture.authenticateIdentityBytes(badBoundary) }

        val badIdentity = mutateNestedRoot(
            receipts.identity.document,
            "identityReplay",
            "mappingCount",
            JsonPrimitive(5),
        )
        assertFailsWith<StructuralProductionReplayException> { fixture.authenticateIdentityBytes(badIdentity) }

        val cycle = mutateAndResign(receipts.model.document) { root ->
            root + ("identityReceiptSha256" to JsonPrimitive(receipts.identity.selfSha256))
        }
        assertFailsWith<StructuralProductionReplayException> {
            StructuralProductionReplayContract.authenticateModelBytes(
                cycle,
                receipts.identity,
                receipts.model.model,
                fixture.limits,
            )
        }
    }

    @Test
    fun `model receipt rejects cross pairing output substitution and caller provenance`() {
        val fixture = ReplayFixture()
        val receipts = fixture.receipts()
        val other = ReplayFixture(profileSha256 = hash('e')).receipts().identity
        assertFailsWith<StructuralProductionReplayException> {
            StructuralProductionReplayContract.authenticateModelBytes(
                receipts.model.canonicalBytes,
                other,
                receipts.model.model,
                fixture.limits,
            )
        }

        val substituted = receipts.model.model.copy(
            programModel = receipts.model.model.programModel.copy(sha256 = hash('f')),
        )
        assertFailsWith<StructuralProductionReplayException> {
            StructuralProductionReplayContract.authenticateModelBytes(
                receipts.model.canonicalBytes,
                receipts.identity,
                substituted,
                fixture.limits,
            )
        }

        val forgedProvenance = receipts.model.model.copy(provenanceSha256 = hash('f'))
        assertFailsWith<StructuralProductionReplayException> {
            StructuralProductionReplayContract.buildModelReceipt(receipts.identity, forgedProvenance, fixture.limits)
        }
    }

    @Test
    fun `strict runtime and entity bounds reject before receipt authority`() {
        val fixture = ReplayFixture()
        val receipts = fixture.receipts()
        val tinyStreams = fixture.limits.copy(maximumStreamBytes = 0)
        val stdoutOne = fixture.observation.copy(
            execution = fixture.observation.execution.copy(
                stdout = fixture.observation.execution.stdout.copy(bytes = 1),
            ),
        )
        assertFailsWith<StructuralProductionReplayException> {
            StructuralProductionReplayContract.buildIdentityReceipt(
                fixture.request,
                stdoutOne,
                fixture.boundaryReplay,
                fixture.identityReplay,
                fixture.identityMapPayloadSha256,
                tinyStreams,
            )
        }
        assertFailsWith<StructuralProductionReplayException> {
            StructuralProductionReplayContract.authenticateIdentityBytes(
                receipts.identity.canonicalBytes,
                fixture.request,
                fixture.observation,
                fixture.boundaryReplay,
                fixture.identityReplay,
                fixture.identityMapPayloadSha256,
                fixture.limits.copy(maximumMappings = 2),
            )
        }
    }

    @Test
    fun `registry is exact match test isolated and cannot accept a fake implementation`() {
        val fixture = ReplayFixture()
        val transcript = fixture.transcript()
        val registry = StructuralReplayAdapterRegistry.testOnlyFixture(fixture.request, transcript, fixture.limits)
        val first = registry.replayFreshForTests(fixture.request)
        val second = registry.replayFreshForTests(fixture.request)
        assertContentEquals(first.identity.canonicalBytes, second.identity.canonicalBytes)
        assertContentEquals(first.model.canonicalBytes, second.model.canonicalBytes)
        assertFailsWith<StructuralProductionReplayException> {
            registry.replayFreshForTests(fixture.request.copy(anchor = fixture.request.anchor.copy(twin = "rich")))
        }
        assertFailsWith<StructuralProductionReplayException> {
            StructuralReplayAdapterRegistry.production.replayFreshForTests(fixture.request)
        }
        assertTrue(VerifiedStructuralInputsV1::class.java.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        assertTrue(
            StructuralProductionReplayContract::class.java.methods.none {
                it.returnType == VerifiedStructuralInputsV1::class.java
            },
        )
        assertTrue(
            StructuralReplayAdapterRegistry::class.java.declaredMethods
                .filter { it.name.contains("testOnlyFixture") }
                .none { method -> method.parameterTypes.any { it.name.contains("Adapter") } },
        )
    }

    @Test
    fun `canonical receipts publish atomically and reauthenticate as a pair`(): Unit = inTemporaryDirectory { directory ->
        val fixture = ReplayFixture()
        val receipts = fixture.receipts()
        val identityPath = directory.resolve("identity.json")
        val modelPath = directory.resolve("model.json")
        val publishedIdentity = StructuralProductionReplayContract.publishIdentityReceipt(identityPath, receipts.identity, fixture.limits)
        val publishedModel = StructuralProductionReplayContract.publishModelReceipt(modelPath, receipts.model, publishedIdentity, fixture.limits)
        val authenticated = StructuralProductionReplayContract.authenticateReceiptPair(
            identityPath,
            modelPath,
            fixture.request,
            fixture.observation,
            fixture.boundaryReplay,
            fixture.identityReplay,
            publishedModel.model,
            fixture.limits,
        )
        assertEquals(receipts.identity.artifactSha256, authenticated.identity.artifactSha256)
        assertEquals(receipts.model.artifactSha256, authenticated.model.artifactSha256)
        assertEquals(setOf("identity.json", "model.json"), Files.list(directory).use { paths ->
            paths.map { it.fileName.toString() }.toList().toSet()
        })
    }

    @Test
    fun `production envelopes bind full receipt hashes without a digest cycle`(): Unit = inTemporaryDirectory { directory ->
        val draftMap = identityMapEnvelope(hash('0'), hash('0'))
        val mapPayload = fixturePayloadSha256(draftMap, 4 * 1024 * 1024)
        val fixture = ReplayFixture(identityMapPayloadSha256 = mapPayload)
        val identityReceipt = fixture.identityReceipt()
        val identityDocument = identityMapEnvelope(mapPayload, identityReceipt.artifactSha256)
        val identityPath = directory.resolve("identity-map.json")
        writeStructuralEnvelope(identityPath, identityDocument)
        val identityMap = StructuralProductionReplayContract.authenticateIdentityMapEnvelope(
            identityPath,
            identityReceipt,
            fixture.limits,
        )

        val draftRecovered = recoveredEnvelope(
            fixture.request,
            identityMap.binding.sha256,
            "gcc-recovered-model",
            hash('0'),
            hash('0'),
        )
        val recoveredPayload = fixturePayloadSha256(draftRecovered, 4 * 1024 * 1024)
        val provisionalModel = StructuralModelReplayObservationV1(
            identityMap.binding,
            fixture.programModel,
            fixture.structuralObservation,
            "gcc-recovered-model",
            recoveredPayload,
            hash('0'),
        )
        val expectedModel = provisionalModel.copy(
            provenanceSha256 = StructuralProductionReplayContract.modelProvenanceSha256(
                identityReceipt,
                provisionalModel.identityMap,
                provisionalModel.programModel,
                provisionalModel.structuralObservation,
                provisionalModel.recoveredModelId,
                fixture.limits,
            ),
        )
        val modelReceipt = StructuralProductionReplayContract.buildModelReceipt(
            identityReceipt,
            expectedModel,
            fixture.limits,
        )
        val recoveredDocument = recoveredEnvelope(
            fixture.request,
            identityMap.binding.sha256,
            expectedModel.recoveredModelId,
            recoveredPayload,
            modelReceipt.artifactSha256,
        )
        val recoveredPath = directory.resolve("recovered.json")
        writeStructuralEnvelope(recoveredPath, recoveredDocument)
        val recovered = StructuralProductionReplayContract.authenticateRecoveredModelEnvelope(
            recoveredPath,
            AuthenticatedStructuralReplayReceiptsV1(identityReceipt, modelReceipt),
            identityMap,
            fixture.limits,
        )
        assertEquals(recoveredPayload, recovered.payloadSha256)
        assertEquals(expectedModel.recoveredModelId, recovered.recoveredModelId)

        val otherFixture = ReplayFixture(profileSha256 = hash('e'), identityMapPayloadSha256 = mapPayload)
        val otherIdentity = otherFixture.identityReceipt()
        val otherModel = expectedModel.copy(
            provenanceSha256 = StructuralProductionReplayContract.modelProvenanceSha256(
                otherIdentity,
                expectedModel.identityMap,
                expectedModel.programModel,
                expectedModel.structuralObservation,
                expectedModel.recoveredModelId,
                fixture.limits,
            ),
        )
        val otherModelReceipt = StructuralProductionReplayContract.buildModelReceipt(
            otherIdentity,
            otherModel,
            fixture.limits,
        )
        assertFailsWith<StructuralProductionReplayException> {
            StructuralProductionReplayContract.authenticateRecoveredModelEnvelope(
                recoveredPath,
                AuthenticatedStructuralReplayReceiptsV1(identityReceipt, otherModelReceipt),
                identityMap,
                fixture.limits,
            )
        }
        assertFailsWith<StructuralProductionReplayException> {
            StructuralProductionReplayContract.authenticateRecoveredModelEnvelope(
                recoveredPath,
                AuthenticatedStructuralReplayReceiptsV1(otherIdentity, otherModelReceipt),
                identityMap,
                fixture.limits,
            )
        }

        writeStructuralEnvelope(identityPath, identityMapEnvelope(mapPayload, identityReceipt.selfSha256))
        assertFailsWith<StructuralProductionReplayException> {
            StructuralProductionReplayContract.authenticateIdentityMapEnvelope(identityPath, identityReceipt, fixture.limits)
        }
        writeStructuralEnvelope(identityPath, identityDocument)

        writeStructuralEnvelope(
            recoveredPath,
            recoveredEnvelope(
                fixture.request,
                identityMap.binding.sha256,
                expectedModel.recoveredModelId,
                recoveredPayload,
                modelReceipt.selfSha256,
            ),
        )
        assertFailsWith<StructuralProductionReplayException> {
            StructuralProductionReplayContract.authenticateRecoveredModelEnvelope(
                recoveredPath,
                AuthenticatedStructuralReplayReceiptsV1(identityReceipt, modelReceipt),
                identityMap,
                fixture.limits,
            )
        }
    }

    private fun resourceBase64(name: String): ByteArray = checkNotNull(
        javaClass.getResourceAsStream("/oracle/structural-production-replay-v1/$name"),
    ) { "frozen structural replay resource is unavailable: $name" }.use { input ->
        Base64.getDecoder().decode(input.readAllBytes().decodeToString().trim())
    }
}

private class ReplayFixture(
    profileSha256: String = hash('0'),
    val identityMapPayloadSha256: String = hash('8'),
) {
    val limits = StructuralProductionReplayLimitsV1()
    val request = StructuralReplayRequestV1(
        anchor = StructuralReplayAnchorV1(
            profile = StructuralReplayProfileV1("gcc-cc1-structural-v1", profileSha256),
            artifactManifestSha256 = hash('1'),
            twin = "stripped",
            inputBinary = StructuralReplayInputBinaryV1(hash('2'), 123_456, "ET_DYN", "0x400000", hash('3')),
            targetAbi = StructuralReplayNamedArtifactV1("x86-64-sysv", hash('4')),
            functionOracle = StructuralReplayNamedArtifactV1("gcc-function-oracle", hash('5')),
            structuralOracle = StructuralReplayNamedArtifactV1("gcc-structural-oracle", hash('6')),
            normalizationProfile = StructuralReplayNormalizationProfileV1(
                "structural-source-normalization",
                "1",
                StructuralRecoveryV1Contract.NORMALIZATION_PROFILE_CONFIGURATION_SHA256,
            ),
            boundaryReport = StructuralReplayBoundaryReportV1(
                hash('8'),
                StructuralReplayToolV1("function-recovery-score-elf", "1", hash('9'), hash('a')),
            ),
        ),
        exporter = StructuralReplayToolV1("decompengine-ghidra-program-model", "10", hash('b'), hash('c')),
        loader = StructuralReplayLoaderV1("ghidra-elf-loader", "12.1.3", hash('d'), hash('e'), "0x400000"),
        runtime = StructuralReplayToolV1("structural-runtime", "1", hash('f'), hash('0')),
        identityVerifier = StructuralReplayToolV1("structural-identity-verifier", "1", hash('1'), hash('2')),
        sandbox = StructuralReplaySandboxV1(hash('3'), hash('4')),
    )
    val programModel = StructuralReplayArtifactObservationV1(hash('5'), 100)
    val structuralObservation = StructuralReplayArtifactObservationV1(hash('6'), 200)
    val observation = StructuralReplayObservationV1(
        execution = StructuralReplayExecutionObservationV1(
            logicalInvocationSha256 = hash('7'),
            environmentSha256 = hash('8'),
            sandboxEvidenceSha256 = hash('9'),
            networkIsolated = true,
            exitCode = 0,
            terminalOutcome = "returned-completed",
            timedOut = false,
            outOfMemory = false,
            cleanupVerified = true,
            stdout = StructuralReplayStreamObservationV1(hash('0'), 0, false),
            stderr = StructuralReplayStreamObservationV1(hash('1'), 0, false),
        ),
        outputTree = StructuralProductionReplayContract.outputTreeFor(programModel, structuralObservation),
        programModel = programModel,
        structuralObservation = structuralObservation,
    )
    val boundaryReplay = StructuralBoundaryReplayObservationV1(
        replaySha256 = hash('2'),
        rawRecoveredCount = 5,
        exactMatches = 2,
        nearMisses = 1,
        falsePositives = 1,
        falseNegatives = 2,
        ignoredExcludedRecoveries = 1,
        oracleUniverseSha256 = hash('3'),
        recoveredUniverseSha256 = hash('4'),
        selectedMappingSha256 = hash('5'),
        nameIndependent = true,
    )
    val identityReplay = StructuralIdentityReplayObservationV1(
        replaySha256 = hash('6'),
        mappingCount = 3,
        oracleGlobalCount = 2,
        recoveredGlobalCount = 3,
        oracleTypeCount = 2,
        recoveredTypeCount = 2,
        mappingUniverseSha256 = hash('7'),
        complete = true,
    )
    private val identityMap = StructuralIdentityMapReplayBindingV1("gcc-identity-map", hash('9'), 500, identityMapPayloadSha256)

    fun identityReceipt(): AuthenticatedStructuralIdentityReplayReceiptV1 =
        StructuralProductionReplayContract.buildIdentityReceipt(
            request,
            observation,
            boundaryReplay,
            identityReplay,
            identityMapPayloadSha256,
            limits,
        )

    fun receipts(): AuthenticatedStructuralReplayReceiptsV1 {
        val identity = identityReceipt()
        val model = StructuralModelReplayObservationV1(
            identityMap,
            programModel,
            structuralObservation,
            "gcc-recovered-model",
            hash('a'),
            StructuralProductionReplayContract.modelProvenanceSha256(
                identity,
                identityMap,
                programModel,
                structuralObservation,
                "gcc-recovered-model",
                limits,
            ),
        )
        return AuthenticatedStructuralReplayReceiptsV1(
            identity,
            StructuralProductionReplayContract.buildModelReceipt(identity, model, limits),
        )
    }

    fun transcript(): StructuralReplayTestTranscriptV1 {
        val identity = StructuralProductionReplayContract.buildIdentityReceipt(
            request,
            observation,
            boundaryReplay,
            identityReplay,
            identityMapPayloadSha256,
            limits,
        )
        return StructuralReplayTestTranscriptV1(
            observation,
            boundaryReplay,
            identityReplay,
            StructuralModelReplayObservationV1(
                identityMap,
                programModel,
                structuralObservation,
                "gcc-recovered-model",
                hash('a'),
                StructuralProductionReplayContract.modelProvenanceSha256(
                    identity,
                    identityMap,
                    programModel,
                    structuralObservation,
                    "gcc-recovered-model",
                    limits,
                ),
            ),
        )
    }

    fun authenticateIdentity(path: Path): AuthenticatedStructuralIdentityReplayReceiptV1 =
        StructuralProductionReplayContract.authenticateIdentityReceipt(
            path,
            request,
            observation,
            boundaryReplay,
            identityReplay,
            identityMapPayloadSha256,
            limits,
        )

    fun authenticateIdentityBytes(bytes: ByteArray): AuthenticatedStructuralIdentityReplayReceiptV1 =
        StructuralProductionReplayContract.authenticateIdentityBytes(
            bytes,
            request,
            observation,
            boundaryReplay,
            identityReplay,
            identityMapPayloadSha256,
            limits,
        )
}

private fun identityMapEnvelope(payloadSha256: String, evidenceSha256: String): JsonObject = JsonObject(
    linkedMapOf(
        "schemaVersion" to JsonPrimitive(1),
        "scope" to JsonPrimitive("production"),
        "map" to JsonObject(
            linkedMapOf(
                "id" to JsonPrimitive("gcc-identity-map"),
                "oracleId" to JsonPrimitive("gcc-structural-oracle"),
                "oracleSha256" to JsonPrimitive(hash('6')),
                "recoveredModelId" to JsonPrimitive("gcc-recovered-model"),
            ),
        ),
        "mappings" to JsonArray(
            listOf(
                identityMapping("global", "oracle-global-1", "recovered-global-1"),
                identityMapping("global", "oracle-global-2", "recovered-global-2"),
                identityMapping("type", "oracle-type-1", "recovered-type-1"),
            ),
        ),
        "attestation" to adapterAttestation(
            payloadSha256,
            evidenceSha256,
            "structural-identity-verifier",
            "1",
        ),
    ),
)

private fun identityMapping(kind: String, oracleId: String, recoveredId: String): JsonObject = JsonObject(
    linkedMapOf(
        "kind" to JsonPrimitive(kind),
        "oracleId" to JsonPrimitive(oracleId),
        "recoveredId" to JsonPrimitive(recoveredId),
        "evidence" to JsonArray(
            listOf(
                JsonObject(
                    linkedMapOf(
                        "kind" to JsonPrimitive("independent-replay"),
                        "oracleLocator" to JsonPrimitive("oracle:$oracleId"),
                        "recoveredLocator" to JsonPrimitive("recovered:$recoveredId"),
                        "verifier" to JsonPrimitive("structural-identity-verifier:1"),
                    ),
                ),
            ),
        ),
    ),
)

private fun recoveredEnvelope(
    request: StructuralReplayRequestV1,
    identityMapSha256: String,
    modelId: String,
    payloadSha256: String,
    evidenceSha256: String,
): JsonObject = JsonObject(
    linkedMapOf(
        "schemaVersion" to JsonPrimitive(1),
        "scope" to JsonPrimitive("production"),
        "model" to JsonObject(linkedMapOf("id" to JsonPrimitive(modelId))),
        "provenance" to historicalProvenance(request, identityMapSha256),
        "entities" to JsonArray(
            listOf(
                JsonObject(
                    linkedMapOf(
                        "kind" to JsonPrimitive("global"),
                        "id" to JsonPrimitive("recovered-global-1"),
                        "facts" to JsonArray(
                            listOf(
                                JsonObject(
                                    linkedMapOf(
                                        "id" to JsonPrimitive("recovered-fact-1"),
                                        "slot" to JsonPrimitive("linkage"),
                                        "dimension" to JsonPrimitive("global.linkage"),
                                        "state" to JsonPrimitive("recovered-unknown"),
                                        "value" to JsonNull,
                                        "evidence" to JsonArray(
                                            listOf(
                                                JsonObject(
                                                    linkedMapOf(
                                                        "kind" to JsonPrimitive("adapter-observation"),
                                                        "locator" to JsonPrimitive("observation:global-1"),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        "attestation" to adapterAttestation(payloadSha256, evidenceSha256, request.runtime.id, request.runtime.version),
    ),
)

private fun historicalProvenance(request: StructuralReplayRequestV1, identityMapSha256: String): JsonObject = JsonObject(
    linkedMapOf(
        "inputBinary" to JsonObject(
            linkedMapOf(
                "sha256" to JsonPrimitive(request.anchor.inputBinary.sha256),
                "sizeBytes" to JsonPrimitive(request.anchor.inputBinary.bytes),
            ),
        ),
        "exporter" to historicalTool(request.exporter),
        "loader" to JsonObject(
            historicalTool(request.loader.asTool()) + ("imageBase" to JsonPrimitive(request.loader.imageBase)),
        ),
        "targetAbi" to JsonObject(
            linkedMapOf(
                "id" to JsonPrimitive(request.anchor.targetAbi.id),
                "sha256" to JsonPrimitive(request.anchor.targetAbi.sha256),
            ),
        ),
        "normalizationProfile" to JsonObject(
            linkedMapOf(
                "id" to JsonPrimitive(request.anchor.normalizationProfile.id),
                "version" to JsonPrimitive(request.anchor.normalizationProfile.version),
                "configurationSha256" to JsonPrimitive(request.anchor.normalizationProfile.configurationSha256),
            ),
        ),
        "boundaryScore" to JsonObject(
            linkedMapOf(
                "sha256" to JsonPrimitive(request.anchor.boundaryReport.sha256),
                "twin" to JsonPrimitive(request.anchor.twin),
                "projectionAdapter" to JsonObject(
                    linkedMapOf(
                        "id" to JsonPrimitive(request.anchor.boundaryReport.adapter.id),
                        "version" to JsonPrimitive(request.anchor.boundaryReport.adapter.version),
                    ),
                ),
            ),
        ),
        "identityMap" to JsonObject(linkedMapOf("sha256" to JsonPrimitive(identityMapSha256))),
    ),
)

private fun historicalTool(tool: StructuralReplayToolV1): JsonObject = JsonObject(
    linkedMapOf(
        "id" to JsonPrimitive(tool.id),
        "version" to JsonPrimitive(tool.version),
        "executableSha256" to JsonPrimitive(tool.implementationSha256),
        "configurationSha256" to JsonPrimitive(tool.configurationSha256),
    ),
)

private fun adapterAttestation(
    payloadSha256: String,
    evidenceSha256: String,
    verifierId: String,
    verifierVersion: String,
): JsonObject = JsonObject(
    linkedMapOf(
        "kind" to JsonPrimitive("adapter-replay"),
        "payloadSha256" to JsonPrimitive(payloadSha256),
        "evidenceSha256" to JsonPrimitive(evidenceSha256),
        "verifier" to JsonObject(
            linkedMapOf(
                "id" to JsonPrimitive(verifierId),
                "version" to JsonPrimitive(verifierVersion),
            ),
        ),
    ),
)

private fun writeStructuralEnvelope(path: Path, document: JsonObject) {
    Files.write(path, StructuralJsonEncoder(4 * 1024 * 1024, pretty = true, ensureAscii = false).encode(document))
}

private fun mutateRequest(root: JsonObject, key: String, value: JsonElement): ByteArray {
    val request = root.getValue("request") as JsonObject
    return mutateAndResign(root) { it + ("request" to JsonObject(request + (key to value))) }
}

private fun mutateNestedRequest(root: JsonObject, section: String, key: String, value: JsonElement): ByteArray {
    val request = root.getValue("request") as JsonObject
    val nested = request.getValue(section) as JsonObject
    return mutateAndResign(root) {
        it + ("request" to JsonObject(request + (section to JsonObject(nested + (key to value)))))
    }
}

private fun mutateExecution(root: JsonObject, key: String, value: JsonElement): ByteArray {
    val observation = root.getValue("observation") as JsonObject
    val execution = observation.getValue("execution") as JsonObject
    return mutateAndResign(root) {
        it + ("observation" to JsonObject(observation + ("execution" to JsonObject(execution + (key to value)))))
    }
}

private fun mutateStream(root: JsonObject, stream: String, key: String, value: JsonElement): ByteArray {
    val observation = root.getValue("observation") as JsonObject
    val execution = observation.getValue("execution") as JsonObject
    val streamObject = execution.getValue(stream) as JsonObject
    val changedExecution = JsonObject(execution + (stream to JsonObject(streamObject + (key to value))))
    return mutateAndResign(root) { it + ("observation" to JsonObject(observation + ("execution" to changedExecution))) }
}

private fun mutateOutputTree(root: JsonObject, key: String, value: JsonElement): ByteArray {
    val observation = root.getValue("observation") as JsonObject
    val tree = observation.getValue("outputTree") as JsonObject
    return mutateAndResign(root) {
        it + ("observation" to JsonObject(observation + ("outputTree" to JsonObject(tree + (key to value)))))
    }
}

private fun mutateObservationArtifact(root: JsonObject, section: String, key: String, value: JsonElement): ByteArray {
    val observation = root.getValue("observation") as JsonObject
    val artifact = observation.getValue(section) as JsonObject
    return mutateAndResign(root) {
        it + ("observation" to JsonObject(observation + (section to JsonObject(artifact + (key to value)))))
    }
}

private fun mutateNestedRoot(root: JsonObject, section: String, key: String, value: JsonElement): ByteArray {
    val nested = root.getValue(section) as JsonObject
    return mutateAndResign(root) { it + (section to JsonObject(nested + (key to value))) }
}

private fun mutateAndResign(root: JsonObject, mutate: (Map<String, JsonElement>) -> Map<String, JsonElement>): ByteArray {
    val withoutSelf = mutate(root.filterKeys { it != "receiptSha256" })
    val self = OracleArtifacts.sha256(canonical(JsonObject(withoutSelf)))
    return canonical(JsonObject(withoutSelf + ("receiptSha256" to JsonPrimitive(self))))
}

private fun canonical(value: JsonElement): ByteArray = OracleJson.canonicalBytes(value)

private fun hash(character: Char): String = character.toString().repeat(64)

private inline fun <T> inTemporaryDirectory(block: (Path) -> T): T {
    val directory = createTempDirectory("structural-production-replay-")
    Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
    return try {
        block(directory)
    } finally {
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}

// Frozen once with an independent jq sorted two-space renderer plus sha256sum: receipts and
// subobjects include the canonical final LF, while the two domain commitments are sorted compact
// bytes without an LF. Tests/runtime never invoke that generator or bless implementation output.
private const val FROZEN_IDENTITY_SELF_SHA256 = "e011fdaa8648b7e92cfa566a999d665ec204bc1a8095e6b2707a18a359764f0f"
private const val FROZEN_IDENTITY_ARTIFACT_SHA256 = "117bdcd3a6a2cd36c3c572c4c8c22a74607cd7387ce8e105e6421d505b566b2f"
private const val FROZEN_REQUEST_SHA256 = "4a417dbc3cc0b1e282eddc307eb388ba8222f051dc2f4071d4e957066f9cdd62"
private const val FROZEN_OBSERVATION_SHA256 = "a8246c7187225c5e4dd654c4771d41ddd2b781a5426e47f8f9e36868f3def732"
private const val FROZEN_OUTPUT_TREE_SHA256 = "a76c175948f2399b674f74cfef8ab516d8d61fdedc4687563fc9aecf6f760dd9"
private const val FROZEN_MODEL_PROVENANCE_SHA256 = "37b7023760db6a8aef10546bb386ea75e13d17839a5084cc670c752649c97f41"
private const val FROZEN_MODEL_SELF_SHA256 = "60f5d72cb298c92fd32f363cb1467af67c1c915e0136001594287db443c4bfa8"
private const val FROZEN_MODEL_ARTIFACT_SHA256 = "b3deeddc5cad7e7b79ffc411d13676048e7d22d594056adff237fbe73202eca3"
