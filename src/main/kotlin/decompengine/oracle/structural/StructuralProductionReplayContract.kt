package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class StructuralProductionReplayException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

data class StructuralProductionReplayLimitsV1(
    val maximumReceiptBytes: Int = 4 * 1024 * 1024,
    val maximumEnvelopeBytes: Int = 64 * 1024 * 1024,
    val maximumInputBinaryBytes: Long = 16L * 1024 * 1024 * 1024,
    val maximumOutputArtifactBytes: Long = 16L * 1024 * 1024 * 1024,
    val maximumOutputTreeBytes: Long = 32L * 1024 * 1024 * 1024,
    val maximumStreamBytes: Long = 64L * 1024 * 1024,
    val maximumBoundaryEntities: Long = 10_000_000,
    val maximumIdentityEntities: Long = 10_000_000,
    val maximumMappings: Long = 10_000_000,
) {
    init {
        require(maximumReceiptBytes in 1..HARD_MAXIMUM_RECEIPT_BYTES)
        require(maximumEnvelopeBytes in 1..HARD_MAXIMUM_ENVELOPE_BYTES)
        require(maximumInputBinaryBytes in 1L..HARD_MAXIMUM_ARTIFACT_BYTES)
        require(maximumOutputArtifactBytes in 1L..HARD_MAXIMUM_ARTIFACT_BYTES)
        require(maximumOutputTreeBytes in 2L..HARD_MAXIMUM_OUTPUT_TREE_BYTES)
        require(maximumStreamBytes in 0L..HARD_MAXIMUM_STREAM_BYTES)
        require(maximumBoundaryEntities in 1L..HARD_MAXIMUM_COUNT)
        require(maximumIdentityEntities in 1L..HARD_MAXIMUM_COUNT)
        require(maximumMappings in 1L..HARD_MAXIMUM_COUNT)
    }

    private companion object {
        const val HARD_MAXIMUM_RECEIPT_BYTES = 64 * 1024 * 1024
        const val HARD_MAXIMUM_ENVELOPE_BYTES = 64 * 1024 * 1024
        const val HARD_MAXIMUM_ARTIFACT_BYTES = 16L * 1024 * 1024 * 1024
        const val HARD_MAXIMUM_OUTPUT_TREE_BYTES = 32L * 1024 * 1024 * 1024
        const val HARD_MAXIMUM_STREAM_BYTES = 64L * 1024 * 1024
        const val HARD_MAXIMUM_COUNT = 10_000_000L
    }
}

data class StructuralReplayProfileV1(val id: String, val sha256: String) {
    init {
        requireReplayIdentifier(id, "structural replay profile ID")
        requireReplaySha256(sha256, "structural replay profile digest")
    }
}

data class StructuralReplayNamedArtifactV1(val id: String, val sha256: String) {
    init {
        requireReplayIdentifier(id, "structural replay artifact ID")
        requireReplaySha256(sha256, "structural replay artifact digest")
    }
}

data class StructuralReplayInputBinaryV1(
    val sha256: String,
    val bytes: Long,
    val elfType: String,
    val imageBase: String,
    val executableRangesSha256: String,
) {
    init {
        requireReplaySha256(sha256, "structural replay input digest")
        require(bytes > 0L) { "structural replay input size must be positive" }
        require(elfType in setOf("ET_EXEC", "ET_DYN")) { "structural replay ELF type is invalid" }
        requireReplayAddress(imageBase, "structural replay image base")
        requireReplaySha256(executableRangesSha256, "structural replay executable-range digest")
    }
}

data class StructuralReplayNormalizationProfileV1(
    val id: String,
    val version: String,
    val configurationSha256: String,
) {
    init {
        requireReplayIdentifier(id, "structural replay normalization-profile ID")
        requireReplayIdentifier(version, "structural replay normalization-profile version")
        requireReplaySha256(configurationSha256, "structural replay normalization-profile configuration digest")
    }
}

data class StructuralReplayToolV1(
    val id: String,
    val version: String,
    val implementationSha256: String,
    val configurationSha256: String,
) {
    init {
        requireReplayIdentifier(id, "structural replay tool ID")
        requireReplayIdentifier(version, "structural replay tool version")
        requireReplaySha256(implementationSha256, "structural replay tool implementation digest")
        requireReplaySha256(configurationSha256, "structural replay tool configuration digest")
    }
}

data class StructuralReplayLoaderV1(
    val id: String,
    val version: String,
    val implementationSha256: String,
    val configurationSha256: String,
    val imageBase: String,
) {
    init {
        requireReplayIdentifier(id, "structural replay loader ID")
        requireReplayIdentifier(version, "structural replay loader version")
        requireReplaySha256(implementationSha256, "structural replay loader implementation digest")
        requireReplaySha256(configurationSha256, "structural replay loader configuration digest")
        requireReplayAddress(imageBase, "structural replay loader image base")
    }

    internal fun asTool(): StructuralReplayToolV1 =
        StructuralReplayToolV1(id, version, implementationSha256, configurationSha256)
}

data class StructuralReplayBoundaryReportV1(
    val sha256: String,
    val adapter: StructuralReplayToolV1,
) {
    init {
        requireReplaySha256(sha256, "structural replay boundary-report digest")
    }
}

data class StructuralReplaySandboxV1(
    val launcherImplementationSha256: String,
    val policySha256: String,
) {
    init {
        requireReplaySha256(launcherImplementationSha256, "structural replay sandbox launcher digest")
        requireReplaySha256(policySha256, "structural replay sandbox policy digest")
    }
}

/** Trusted profile data supplied independently of both replay receipts. */
data class StructuralReplayAnchorV1(
    val profile: StructuralReplayProfileV1,
    val artifactManifestSha256: String,
    val twin: String,
    val inputBinary: StructuralReplayInputBinaryV1,
    val targetAbi: StructuralReplayNamedArtifactV1,
    val functionOracle: StructuralReplayNamedArtifactV1,
    val structuralOracle: StructuralReplayNamedArtifactV1,
    val normalizationProfile: StructuralReplayNormalizationProfileV1,
    val boundaryReport: StructuralReplayBoundaryReportV1,
) {
    init {
        requireReplaySha256(artifactManifestSha256, "structural replay artifact-manifest digest")
        require(twin in setOf("rich", "stripped")) { "structural replay twin is invalid" }
    }
}

/** Exact request pinned by a registered profile; it deliberately contains no filesystem path. */
data class StructuralReplayRequestV1(
    val anchor: StructuralReplayAnchorV1,
    val recoveryMode: String = "full",
    val exporter: StructuralReplayToolV1,
    val loader: StructuralReplayLoaderV1,
    val runtime: StructuralReplayToolV1,
    val identityVerifier: StructuralReplayToolV1,
    val sandbox: StructuralReplaySandboxV1,
) {
    init {
        require(recoveryMode == "full") { "production structural replay requires full recovery mode" }
        require(loader.imageBase == anchor.inputBinary.imageBase) {
            "structural replay loader and input image bases differ"
        }
    }
}

data class StructuralReplayArtifactObservationV1(val sha256: String, val bytes: Long) {
    init {
        requireReplaySha256(sha256, "structural replay output digest")
        require(bytes > 0L) { "structural replay output size must be positive" }
    }
}

data class StructuralReplayStreamObservationV1(
    val sha256: String,
    val bytes: Long,
    val truncated: Boolean,
) {
    init {
        requireReplaySha256(sha256, "structural replay stream digest")
        require(bytes >= 0L) { "structural replay stream size must be nonnegative" }
    }
}

data class StructuralReplayExecutionObservationV1(
    val logicalInvocationSha256: String,
    val environmentSha256: String,
    val sandboxEvidenceSha256: String,
    val networkIsolated: Boolean,
    val exitCode: Int,
    val terminalOutcome: String,
    val timedOut: Boolean,
    val outOfMemory: Boolean,
    val cleanupVerified: Boolean,
    val stdout: StructuralReplayStreamObservationV1,
    val stderr: StructuralReplayStreamObservationV1,
) {
    init {
        requireReplaySha256(logicalInvocationSha256, "structural replay logical-invocation digest")
        requireReplaySha256(environmentSha256, "structural replay environment digest")
        requireReplaySha256(sandboxEvidenceSha256, "structural replay sandbox-evidence digest")
        require(terminalOutcome.length <= 128) { "structural replay terminal outcome is too long" }
    }
}

data class StructuralReplayOutputTreeObservationV1(
    val sha256: String,
    val fileCount: Long,
    val totalBytes: Long,
) {
    init {
        requireReplaySha256(sha256, "structural replay output-tree digest")
        require(fileCount >= 0L) { "structural replay output-tree file count must be nonnegative" }
        require(totalBytes >= 0L) { "structural replay output-tree size must be nonnegative" }
    }
}

/** Raw adapter result. Success is authenticated by the host contract, never asserted by the adapter. */
data class StructuralReplayObservationV1(
    val execution: StructuralReplayExecutionObservationV1,
    val outputTree: StructuralReplayOutputTreeObservationV1,
    val programModel: StructuralReplayArtifactObservationV1,
    val structuralObservation: StructuralReplayArtifactObservationV1,
)

data class StructuralBoundaryReplayObservationV1(
    val replaySha256: String,
    val rawRecoveredCount: Long,
    val exactMatches: Long,
    val nearMisses: Long,
    val falsePositives: Long,
    val falseNegatives: Long,
    val ignoredExcludedRecoveries: Long,
    val oracleUniverseSha256: String,
    val recoveredUniverseSha256: String,
    val selectedMappingSha256: String,
    val nameIndependent: Boolean,
) {
    init {
        listOf(
            rawRecoveredCount,
            exactMatches,
            nearMisses,
            falsePositives,
            falseNegatives,
            ignoredExcludedRecoveries,
        ).forEach { require(it >= 0L) { "structural boundary replay counts must be nonnegative" } }
        requireReplaySha256(replaySha256, "structural boundary replay digest")
        requireReplaySha256(oracleUniverseSha256, "structural boundary oracle-universe digest")
        requireReplaySha256(recoveredUniverseSha256, "structural boundary recovered-universe digest")
        requireReplaySha256(selectedMappingSha256, "structural boundary selected-mapping digest")
    }
}

data class StructuralIdentityReplayObservationV1(
    val replaySha256: String,
    val mappingCount: Long,
    val oracleGlobalCount: Long,
    val recoveredGlobalCount: Long,
    val oracleTypeCount: Long,
    val recoveredTypeCount: Long,
    val mappingUniverseSha256: String,
    val complete: Boolean,
) {
    init {
        listOf(mappingCount, oracleGlobalCount, recoveredGlobalCount, oracleTypeCount, recoveredTypeCount).forEach {
            require(it >= 0L) { "structural identity replay counts must be nonnegative" }
        }
        requireReplaySha256(replaySha256, "structural identity replay digest")
        requireReplaySha256(mappingUniverseSha256, "structural identity mapping-universe digest")
    }
}

data class StructuralIdentityMapReplayBindingV1(
    val id: String,
    val sha256: String,
    val bytes: Long,
    val payloadSha256: String,
) {
    init {
        requireReplayIdentifier(id, "structural identity-map ID")
        requireReplaySha256(sha256, "structural identity-map digest")
        require(bytes > 0L) { "structural identity-map size must be positive" }
        requireReplaySha256(payloadSha256, "structural identity-map payload digest")
    }
}

data class StructuralModelReplayObservationV1(
    val identityMap: StructuralIdentityMapReplayBindingV1,
    val programModel: StructuralReplayArtifactObservationV1,
    val structuralObservation: StructuralReplayArtifactObservationV1,
    val recoveredModelId: String,
    val recoveredModelPayloadSha256: String,
    val provenanceSha256: String,
) {
    init {
        requireReplayIdentifier(recoveredModelId, "recovered structural model ID")
        requireReplaySha256(recoveredModelPayloadSha256, "recovered structural model payload digest")
        requireReplaySha256(provenanceSha256, "recovered structural model provenance digest")
    }
}

class AuthenticatedStructuralIdentityReplayReceiptV1 internal constructor(
    bytes: ByteArray,
    val document: JsonObject,
    val request: StructuralReplayRequestV1,
    val observation: StructuralReplayObservationV1,
    val boundaryReplay: StructuralBoundaryReplayObservationV1,
    val identityReplay: StructuralIdentityReplayObservationV1,
    val identityMapPayloadSha256: String,
    val selfSha256: String,
    val requestSha256: String,
    val observationSha256: String,
) {
    private val storedBytes = bytes.copyOf()
    val canonicalBytes: ByteArray get() = storedBytes.copyOf()
    val artifactSha256: String = OracleArtifacts.sha256(storedBytes)
    val sizeBytes: Int = storedBytes.size
}

class AuthenticatedStructuralModelReplayReceiptV1 internal constructor(
    bytes: ByteArray,
    val document: JsonObject,
    val identityReceiptSha256: String,
    val identityRequestSha256: String,
    val identityObservationSha256: String,
    val model: StructuralModelReplayObservationV1,
    val boundaryReportSha256: String,
    val twin: String,
    val selfSha256: String,
) {
    private val storedBytes = bytes.copyOf()
    val canonicalBytes: ByteArray get() = storedBytes.copyOf()
    val artifactSha256: String = OracleArtifacts.sha256(storedBytes)
    val sizeBytes: Int = storedBytes.size
}

class AuthenticatedStructuralIdentityMapEnvelopeV1 internal constructor(
    bytes: ByteArray,
    val document: JsonObject,
    val binding: StructuralIdentityMapReplayBindingV1,
    val recoveredModelId: String,
    val identityReceiptSha256: String,
) {
    private val storedBytes = bytes.copyOf()
    val canonicalBytes: ByteArray get() = storedBytes.copyOf()
}

class AuthenticatedStructuralRecoveredModelEnvelopeV1 internal constructor(
    bytes: ByteArray,
    val document: JsonObject,
    val recoveredModelId: String,
    val payloadSha256: String,
) {
    private val storedBytes = bytes.copyOf()
    val canonicalBytes: ByteArray get() = storedBytes.copyOf()
    val artifactSha256: String = OracleArtifacts.sha256(storedBytes)
    val sizeBytes: Int = storedBytes.size
}

class AuthenticatedStructuralReplayReceiptsV1 internal constructor(
    val identity: AuthenticatedStructuralIdentityReplayReceiptV1,
    val model: AuthenticatedStructuralModelReplayReceiptV1,
)

/**
 * Reserved opaque capability for production structural scoring. It intentionally has no creator in
 * this checkpoint: stored receipts and adapter-asserted hashes are insufficient. A later host-owned
 * output-snapshot orchestrator must become the sole constructor gate.
 */
class VerifiedStructuralInputsV1 private constructor()

object StructuralProductionReplayContract {
    const val IDENTITY_RECEIPT_KIND = "structural-identity-replay-receipt-v1"
    const val MODEL_RECEIPT_KIND = "structural-model-replay-receipt-v1"
    const val OUTPUT_TREE_KIND = "structural-replay-output-tree-v1"

    fun requestSha256(
        request: StructuralReplayRequestV1,
        limits: StructuralProductionReplayLimitsV1 = StructuralProductionReplayLimitsV1(),
    ): String = canonicalSha256(request.toJson(), limits.maximumReceiptBytes)

    fun outputTreeFor(
        programModel: StructuralReplayArtifactObservationV1,
        structuralObservation: StructuralReplayArtifactObservationV1,
    ): StructuralReplayOutputTreeObservationV1 {
        val total = checkedAdd(programModel.bytes, structuralObservation.bytes, "structural replay output sizes overflow")
        val commitment = outputTreeCommitment(programModel, structuralObservation)
        return StructuralReplayOutputTreeObservationV1(commitment, EXPECTED_OUTPUT_FILE_COUNT, total)
    }

    /** Host-derived provenance commitment; candidate output never supplies authoritative provenance. */
    fun modelProvenanceSha256(
        identityReceipt: AuthenticatedStructuralIdentityReplayReceiptV1,
        identityMap: StructuralIdentityMapReplayBindingV1,
        programModel: StructuralReplayArtifactObservationV1,
        structuralObservation: StructuralReplayArtifactObservationV1,
        recoveredModelId: String,
        limits: StructuralProductionReplayLimitsV1 = StructuralProductionReplayLimitsV1(),
    ): String {
        requireReplayIdentifier(recoveredModelId, "recovered structural model ID")
        val request = identityReceipt.request
        val commitment = JsonObject(
            linkedMapOf(
                "kind" to JsonPrimitive("structural-model-provenance-v1"),
                "runtime" to request.runtime.toJson(),
                "normalizationProfile" to request.anchor.normalizationProfile.toJson(),
                "identityReceiptSha256" to JsonPrimitive(identityReceipt.artifactSha256),
                "identityMap" to identityMap.toJson(),
                "boundaryReport" to JsonObject(
                    linkedMapOf(
                        "sha256" to JsonPrimitive(request.anchor.boundaryReport.sha256),
                        "twin" to JsonPrimitive(request.anchor.twin),
                    ),
                ),
                "programModel" to programModel.toJson(),
                "structuralObservation" to structuralObservation.toJson(),
                "recoveredModelId" to JsonPrimitive(recoveredModelId),
            ),
        )
        return compactCommitmentSha256(commitment, limits.maximumReceiptBytes)
    }

    /** Authenticates stored evidence; this never creates [VerifiedStructuralInputsV1]. */
    fun authenticateIdentityReceipt(
        path: Path,
        expectedRequest: StructuralReplayRequestV1,
        expectedObservation: StructuralReplayObservationV1,
        expectedBoundaryReplay: StructuralBoundaryReplayObservationV1,
        expectedIdentityReplay: StructuralIdentityReplayObservationV1,
        expectedIdentityMapPayloadSha256: String,
        limits: StructuralProductionReplayLimitsV1 = StructuralProductionReplayLimitsV1(),
    ): AuthenticatedStructuralIdentityReplayReceiptV1 {
        val bytes = readReceipt(path, limits)
        return authenticateIdentityBytes(
            bytes,
            expectedRequest,
            expectedObservation,
            expectedBoundaryReplay,
            expectedIdentityReplay,
            expectedIdentityMapPayloadSha256,
            limits,
        )
    }

    fun authenticateModelReceipt(
        path: Path,
        identityReceipt: AuthenticatedStructuralIdentityReplayReceiptV1,
        expectedModel: StructuralModelReplayObservationV1,
        limits: StructuralProductionReplayLimitsV1 = StructuralProductionReplayLimitsV1(),
    ): AuthenticatedStructuralModelReplayReceiptV1 =
        authenticateModelBytes(readReceipt(path, limits), identityReceipt, expectedModel, limits)

    fun authenticateReceiptPair(
        identityReceiptPath: Path,
        modelReceiptPath: Path,
        expectedRequest: StructuralReplayRequestV1,
        expectedObservation: StructuralReplayObservationV1,
        expectedBoundaryReplay: StructuralBoundaryReplayObservationV1,
        expectedIdentityReplay: StructuralIdentityReplayObservationV1,
        expectedModel: StructuralModelReplayObservationV1,
        limits: StructuralProductionReplayLimitsV1 = StructuralProductionReplayLimitsV1(),
    ): AuthenticatedStructuralReplayReceiptsV1 {
        val identity = authenticateIdentityReceipt(
            identityReceiptPath,
            expectedRequest,
            expectedObservation,
            expectedBoundaryReplay,
            expectedIdentityReplay,
            expectedModel.identityMap.payloadSha256,
            limits,
        )
        val model = authenticateModelReceipt(modelReceiptPath, identity, expectedModel, limits)
        return AuthenticatedStructuralReplayReceiptsV1(identity, model)
    }

    fun authenticateIdentityMapEnvelope(
        path: Path,
        identityReceipt: AuthenticatedStructuralIdentityReplayReceiptV1,
        limits: StructuralProductionReplayLimitsV1 = StructuralProductionReplayLimitsV1(),
    ): AuthenticatedStructuralIdentityMapEnvelopeV1 {
        val snapshot = readStructuralEnvelope(path, "structural identity map", "structural-identity-map", limits)
        val root = snapshot.document
        requireExactKeys(root, IDENTITY_MAP_ENVELOPE_KEYS, "structural identity map")
        requireInteger(root.required("schemaVersion", "structural identity map"), "identity-map schemaVersion", 1L, 1L)
        requireLiteral(root.required("scope", "structural identity map"), "production", "identity-map scope")
        val header = requireObject(root.required("map", "structural identity map"), IDENTITY_MAP_HEADER_KEYS, "structural identity-map header")
        val request = identityReceipt.request
        if (requireIdentifier(header.required("oracleId", "structural identity-map header"), "identity-map oracle ID") !=
            request.anchor.structuralOracle.id ||
            requireSha256(header.required("oracleSha256", "structural identity-map header"), "identity-map oracle digest") !=
            request.anchor.structuralOracle.sha256
        ) replayFail("structural identity map is not bound to the requested structural oracle")
        val mapId = requireIdentifier(header.required("id", "structural identity-map header"), "identity-map ID")
        val recoveredModelId = requireIdentifier(
            header.required("recoveredModelId", "structural identity-map header"),
            "identity-map recovered-model ID",
        )
        val mappings = root.required("mappings", "structural identity map") as? JsonArray
            ?: replayFail("structural identity-map mappings must be an array")
        if (mappings.size.toLong() != identityReceipt.identityReplay.mappingCount) {
            replayFail("structural identity-map mapping count differs from the authenticated replay")
        }
        val oracleKeys = hashSetOf<Pair<String, String>>()
        val recoveredKeys = hashSetOf<Pair<String, String>>()
        mappings.forEachIndexed { index, raw ->
            val item = requireObject(raw, IDENTITY_MAPPING_KEYS, "structural identity-map mapping[$index]")
            val kind = requireString(item.required("kind", "structural identity-map mapping[$index]"), "identity mapping kind", 32)
            if (kind !in setOf("global", "type")) replayFail("structural identity mapping kind is invalid")
            val oracleId = requireIdentifier(item.required("oracleId", "structural identity-map mapping[$index]"), "identity mapping oracle ID")
            val recoveredId = requireIdentifier(
                item.required("recoveredId", "structural identity-map mapping[$index]"),
                "identity mapping recovered ID",
            )
            if (!oracleKeys.add(kind to oracleId) || !recoveredKeys.add(kind to recoveredId)) {
                replayFail("structural identity map is not one-to-one")
            }
        }
        val payloadSha = fixturePayloadSha256(root, limits.maximumEnvelopeBytes)
        if (payloadSha != identityReceipt.identityMapPayloadSha256) {
            replayFail("structural identity-map payload differs from the identity receipt")
        }
        validateAdapterReplayAttestation(
            root.required("attestation", "structural identity map"),
            "structural identity-map attestation",
            payloadSha,
            identityReceipt.artifactSha256,
            request.identityVerifier,
        )
        val binding = StructuralIdentityMapReplayBindingV1(
            mapId,
            OracleArtifacts.sha256(snapshot.bytes),
            snapshot.bytes.size.toLong(),
            payloadSha,
        )
        return AuthenticatedStructuralIdentityMapEnvelopeV1(
            snapshot.bytes,
            root,
            binding,
            recoveredModelId,
            identityReceipt.artifactSha256,
        )
    }

    fun authenticateRecoveredModelEnvelope(
        path: Path,
        receipts: AuthenticatedStructuralReplayReceiptsV1,
        identityMap: AuthenticatedStructuralIdentityMapEnvelopeV1,
        limits: StructuralProductionReplayLimitsV1 = StructuralProductionReplayLimitsV1(),
    ): AuthenticatedStructuralRecoveredModelEnvelopeV1 {
        requireAuthenticatedReceiptPairBindings(receipts.identity, receipts.model)
        if (identityMap.identityReceiptSha256 != receipts.identity.artifactSha256) {
            replayFail("structural identity map is cross-paired with a different identity receipt")
        }
        val snapshot = readStructuralEnvelope(path, "recovered structural model", "recovered-structure", limits)
        val root = snapshot.document
        requireExactKeys(root, RECOVERED_MODEL_ENVELOPE_KEYS, "recovered structural model")
        requireInteger(root.required("schemaVersion", "recovered structural model"), "recovered-model schemaVersion", 1L, 1L)
        requireLiteral(root.required("scope", "recovered structural model"), "production", "recovered-model scope")
        val model = requireObject(root.required("model", "recovered structural model"), MODEL_HEADER_KEYS, "recovered-model header")
        val modelId = requireIdentifier(model.required("id", "recovered-model header"), "recovered-model ID")
        if (modelId != identityMap.recoveredModelId || modelId != receipts.model.model.recoveredModelId) {
            replayFail("recovered-model ID differs from its identity map or model receipt")
        }
        if (identityMap.binding != receipts.model.model.identityMap) {
            replayFail("recovered model is cross-paired with a different identity map")
        }
        validateRecoveredProvenance(
            requireObject(
                root.required("provenance", "recovered structural model"),
                RECOVERED_PROVENANCE_KEYS,
                "recovered-model provenance",
            ),
            receipts.identity.request,
            identityMap.binding,
        )
        val payloadSha = fixturePayloadSha256(root, limits.maximumEnvelopeBytes)
        if (payloadSha != receipts.model.model.recoveredModelPayloadSha256) {
            replayFail("recovered-model payload differs from the model receipt")
        }
        validateAdapterReplayAttestation(
            root.required("attestation", "recovered structural model"),
            "recovered-model attestation",
            payloadSha,
            receipts.model.artifactSha256,
            receipts.identity.request.runtime,
        )
        return AuthenticatedStructuralRecoveredModelEnvelopeV1(snapshot.bytes, root, modelId, payloadSha)
    }

    fun publishIdentityReceipt(
        path: Path,
        receipt: AuthenticatedStructuralIdentityReplayReceiptV1,
        limits: StructuralProductionReplayLimitsV1 = StructuralProductionReplayLimitsV1(),
    ): AuthenticatedStructuralIdentityReplayReceiptV1 {
        publishReceipt(path, receipt.canonicalBytes, limits)
        return authenticateIdentityReceipt(
            path,
            receipt.request,
            receipt.observation,
            receipt.boundaryReplay,
            receipt.identityReplay,
            receipt.identityMapPayloadSha256,
            limits,
        )
    }

    fun publishModelReceipt(
        path: Path,
        receipt: AuthenticatedStructuralModelReplayReceiptV1,
        identityReceipt: AuthenticatedStructuralIdentityReplayReceiptV1,
        limits: StructuralProductionReplayLimitsV1 = StructuralProductionReplayLimitsV1(),
    ): AuthenticatedStructuralModelReplayReceiptV1 {
        publishReceipt(path, receipt.canonicalBytes, limits)
        return authenticateModelReceipt(path, identityReceipt, receipt.model, limits)
    }

    internal fun buildIdentityReceipt(
        request: StructuralReplayRequestV1,
        observation: StructuralReplayObservationV1,
        boundaryReplay: StructuralBoundaryReplayObservationV1,
        identityReplay: StructuralIdentityReplayObservationV1,
        identityMapPayloadSha256: String,
        limits: StructuralProductionReplayLimitsV1,
    ): AuthenticatedStructuralIdentityReplayReceiptV1 {
        requireReplaySha256(identityMapPayloadSha256, "structural identity-map payload digest")
        validateRequest(request, limits)
        validateObservation(observation, limits)
        validateBoundaryReplay(boundaryReplay, limits)
        validateIdentityReplay(identityReplay, limits)
        val withoutSelf = JsonObject(
            linkedMapOf(
                "schemaVersion" to JsonPrimitive(1),
                "kind" to JsonPrimitive(IDENTITY_RECEIPT_KIND),
                "request" to request.toJson(),
                "observation" to observation.toJson(),
                "boundaryReplay" to boundaryReplay.toJson(),
                "identityReplay" to identityReplay.toJson(),
                "identityMapPayloadSha256" to JsonPrimitive(identityMapPayloadSha256),
            ),
        )
        val self = canonicalSha256(withoutSelf, limits.maximumReceiptBytes)
        val document = JsonObject(withoutSelf + ("receiptSha256" to JsonPrimitive(self)))
        val bytes = canonicalBytes(document, limits.maximumReceiptBytes)
        return authenticateIdentityBytes(
            bytes,
            request,
            observation,
            boundaryReplay,
            identityReplay,
            identityMapPayloadSha256,
            limits,
        )
    }

    internal fun buildModelReceipt(
        identityReceipt: AuthenticatedStructuralIdentityReplayReceiptV1,
        model: StructuralModelReplayObservationV1,
        limits: StructuralProductionReplayLimitsV1,
    ): AuthenticatedStructuralModelReplayReceiptV1 {
        validateModelObservation(model, limits)
        requireModelMatchesIdentity(identityReceipt, model, limits)
        val withoutSelf = JsonObject(
            linkedMapOf(
                "schemaVersion" to JsonPrimitive(1),
                "kind" to JsonPrimitive(MODEL_RECEIPT_KIND),
                "identityReceiptSha256" to JsonPrimitive(identityReceipt.artifactSha256),
                "identityRequestSha256" to JsonPrimitive(identityReceipt.requestSha256),
                "identityObservationSha256" to JsonPrimitive(identityReceipt.observationSha256),
                "identityMap" to model.identityMap.toJson(),
                "boundaryReportSha256" to JsonPrimitive(identityReceipt.request.anchor.boundaryReport.sha256),
                "twin" to JsonPrimitive(identityReceipt.request.anchor.twin),
                "programModel" to model.programModel.toJson(),
                "structuralObservation" to model.structuralObservation.toJson(),
                "recoveredModelId" to JsonPrimitive(model.recoveredModelId),
                "recoveredModelPayloadSha256" to JsonPrimitive(model.recoveredModelPayloadSha256),
                "provenanceSha256" to JsonPrimitive(model.provenanceSha256),
            ),
        )
        val self = canonicalSha256(withoutSelf, limits.maximumReceiptBytes)
        val document = JsonObject(withoutSelf + ("receiptSha256" to JsonPrimitive(self)))
        val bytes = canonicalBytes(document, limits.maximumReceiptBytes)
        return authenticateModelBytes(bytes, identityReceipt, model, limits)
    }

    internal fun authenticateIdentityBytes(
        bytes: ByteArray,
        expectedRequest: StructuralReplayRequestV1,
        expectedObservation: StructuralReplayObservationV1,
        expectedBoundaryReplay: StructuralBoundaryReplayObservationV1,
        expectedIdentityReplay: StructuralIdentityReplayObservationV1,
        expectedIdentityMapPayloadSha256: String,
        limits: StructuralProductionReplayLimitsV1,
    ): AuthenticatedStructuralIdentityReplayReceiptV1 {
        requireReplaySha256(expectedIdentityMapPayloadSha256, "expected structural identity-map payload digest")
        validateRequest(expectedRequest, limits)
        validateObservation(expectedObservation, limits)
        validateBoundaryReplay(expectedBoundaryReplay, limits)
        validateIdentityReplay(expectedIdentityReplay, limits)
        val root = parseCanonicalReceipt(bytes, "structural-identity-replay-receipt", limits)
        requireExactKeys(root, IDENTITY_ROOT_KEYS, "structural identity replay receipt")
        requireInteger(root.required("schemaVersion", "structural identity replay receipt"), "identity receipt schemaVersion", 1L, 1L)
        requireLiteral(root.required("kind", "structural identity replay receipt"), IDENTITY_RECEIPT_KIND, "identity receipt kind")
        val requestElement = requireObject(root.required("request", "structural identity replay receipt"), REQUEST_KEYS, "identity receipt request")
        val observationElement = requireObject(
            root.required("observation", "structural identity replay receipt"),
            OBSERVATION_KEYS,
            "identity receipt observation",
        )
        val boundaryElement = requireObject(
            root.required("boundaryReplay", "structural identity replay receipt"),
            BOUNDARY_REPLAY_KEYS,
            "identity receipt boundary replay",
        )
        val identityElement = requireObject(
            root.required("identityReplay", "structural identity replay receipt"),
            IDENTITY_REPLAY_KEYS,
            "identity receipt identity replay",
        )
        val request = parseRequest(requestElement)
        val observation = parseObservation(observationElement)
        val boundaryReplay = parseBoundaryReplay(boundaryElement)
        val identityReplay = parseIdentityReplay(identityElement)
        validateRequest(request, limits)
        validateObservation(observation, limits)
        validateBoundaryReplay(boundaryReplay, limits)
        validateIdentityReplay(identityReplay, limits)
        if (request != expectedRequest) replayFail("identity receipt request differs from its out-of-band anchor")
        if (observation != expectedObservation) replayFail("identity receipt observation differs from the fresh replay")
        if (boundaryReplay != expectedBoundaryReplay) replayFail("identity receipt boundary replay differs from the fresh replay")
        if (identityReplay != expectedIdentityReplay) replayFail("identity receipt identity replay differs from the fresh replay")
        val identityPayload = requireSha256(
            root.required("identityMapPayloadSha256", "structural identity replay receipt"),
            "identity receipt identity-map payload digest",
        )
        if (identityPayload != expectedIdentityMapPayloadSha256) {
            replayFail("identity receipt is not bound to the expected identity-map payload")
        }
        val self = requireSha256(root.required("receiptSha256", "structural identity replay receipt"), "identity receipt self digest")
        val computedSelf = canonicalSha256(JsonObject(root.filterKeys { it != "receiptSha256" }), limits.maximumReceiptBytes)
        if (self != computedSelf) replayFail("identity receipt self digest does not verify")
        val requestSha = canonicalSha256(requestElement, limits.maximumReceiptBytes)
        val observationSha = canonicalSha256(observationElement, limits.maximumReceiptBytes)
        return AuthenticatedStructuralIdentityReplayReceiptV1(
            bytes,
            root,
            request,
            observation,
            boundaryReplay,
            identityReplay,
            identityPayload,
            self,
            requestSha,
            observationSha,
        )
    }

    internal fun authenticateModelBytes(
        bytes: ByteArray,
        identityReceipt: AuthenticatedStructuralIdentityReplayReceiptV1,
        expectedModel: StructuralModelReplayObservationV1,
        limits: StructuralProductionReplayLimitsV1,
    ): AuthenticatedStructuralModelReplayReceiptV1 {
        validateModelObservation(expectedModel, limits)
        requireModelMatchesIdentity(identityReceipt, expectedModel, limits)
        val root = parseCanonicalReceipt(bytes, "structural-model-replay-receipt", limits)
        requireExactKeys(root, MODEL_ROOT_KEYS, "structural model replay receipt")
        requireInteger(root.required("schemaVersion", "structural model replay receipt"), "model receipt schemaVersion", 1L, 1L)
        requireLiteral(root.required("kind", "structural model replay receipt"), MODEL_RECEIPT_KIND, "model receipt kind")
        val identityReceiptSha = requireSha256(
            root.required("identityReceiptSha256", "structural model replay receipt"),
            "model receipt identity-receipt digest",
        )
        val requestSha = requireSha256(
            root.required("identityRequestSha256", "structural model replay receipt"),
            "model receipt identity-request digest",
        )
        val observationSha = requireSha256(
            root.required("identityObservationSha256", "structural model replay receipt"),
            "model receipt identity-observation digest",
        )
        if (identityReceiptSha != identityReceipt.artifactSha256 ||
            requestSha != identityReceipt.requestSha256 ||
            observationSha != identityReceipt.observationSha256
        ) replayFail("model receipt is cross-paired with a different identity replay")
        val identityMap = parseIdentityMapBinding(
            requireObject(root.required("identityMap", "structural model replay receipt"), IDENTITY_MAP_KEYS, "model receipt identity map"),
        )
        val programModel = parseArtifact(
            requireObject(root.required("programModel", "structural model replay receipt"), ARTIFACT_KEYS, "model receipt program model"),
            "model receipt program model",
        )
        val structuralObservation = parseArtifact(
            requireObject(
                root.required("structuralObservation", "structural model replay receipt"),
                ARTIFACT_KEYS,
                "model receipt structural observation",
            ),
            "model receipt structural observation",
        )
        val model = StructuralModelReplayObservationV1(
            identityMap,
            programModel,
            structuralObservation,
            requireIdentifier(root.required("recoveredModelId", "structural model replay receipt"), "model receipt recovered-model ID"),
            requireSha256(
                root.required("recoveredModelPayloadSha256", "structural model replay receipt"),
                "model receipt recovered-model payload digest",
            ),
            requireSha256(root.required("provenanceSha256", "structural model replay receipt"), "model receipt provenance digest"),
        )
        validateModelObservation(model, limits)
        requireModelMatchesIdentity(identityReceipt, model, limits)
        if (model != expectedModel) replayFail("model receipt differs from the fresh host-derived model binding")
        val boundarySha = requireSha256(
            root.required("boundaryReportSha256", "structural model replay receipt"),
            "model receipt boundary-report digest",
        )
        val twin = requireString(root.required("twin", "structural model replay receipt"), "model receipt twin", 32)
        if (boundarySha != identityReceipt.request.anchor.boundaryReport.sha256 || twin != identityReceipt.request.anchor.twin) {
            replayFail("model receipt boundary selection differs from the identity replay")
        }
        val self = requireSha256(root.required("receiptSha256", "structural model replay receipt"), "model receipt self digest")
        val computedSelf = canonicalSha256(JsonObject(root.filterKeys { it != "receiptSha256" }), limits.maximumReceiptBytes)
        if (self != computedSelf) replayFail("model receipt self digest does not verify")
        return AuthenticatedStructuralModelReplayReceiptV1(
            bytes,
            root,
            identityReceiptSha,
            requestSha,
            observationSha,
            model,
            boundarySha,
            twin,
            self,
        )
    }

    private fun requireModelMatchesIdentity(
        identityReceipt: AuthenticatedStructuralIdentityReplayReceiptV1,
        model: StructuralModelReplayObservationV1,
        limits: StructuralProductionReplayLimitsV1,
    ) {
        if (model.identityMap.payloadSha256 != identityReceipt.identityMapPayloadSha256) {
            replayFail("model receipt identity-map payload differs from the identity replay")
        }
        if (model.programModel != identityReceipt.observation.programModel ||
            model.structuralObservation != identityReceipt.observation.structuralObservation
        ) replayFail("model receipt substitutes a replay output")
        val expectedProvenance = modelProvenanceSha256(
            identityReceipt,
            model.identityMap,
            model.programModel,
            model.structuralObservation,
            model.recoveredModelId,
            limits,
        )
        if (model.provenanceSha256 != expectedProvenance) {
            replayFail("model receipt provenance digest is not the host-derived commitment")
        }
    }

    private fun validateRequest(request: StructuralReplayRequestV1, limits: StructuralProductionReplayLimitsV1) {
        if (request.recoveryMode != "full") replayFail("planning-mode structural replay is not production evidence")
        if (request.anchor.inputBinary.bytes > limits.maximumInputBinaryBytes) {
            replayFail("structural replay input exceeds the authenticated byte limit")
        }
        if (request.loader.imageBase != request.anchor.inputBinary.imageBase) {
            replayFail("structural replay loader and input image bases differ")
        }
    }

    private fun validateObservation(observation: StructuralReplayObservationV1, limits: StructuralProductionReplayLimitsV1) {
        val execution = observation.execution
        if (!execution.networkIsolated || execution.exitCode != 0 || execution.terminalOutcome != "returned-completed" ||
            execution.timedOut || execution.outOfMemory || !execution.cleanupVerified
        ) replayFail("structural adapter execution did not complete cleanly in the authenticated sandbox")
        if (execution.stdout.truncated || execution.stderr.truncated) replayFail("structural adapter output was truncated")
        if (execution.stdout.bytes > limits.maximumStreamBytes || execution.stderr.bytes > limits.maximumStreamBytes) {
            replayFail("structural adapter stream exceeds the authenticated byte limit")
        }
        if (observation.programModel.bytes > limits.maximumOutputArtifactBytes ||
            observation.structuralObservation.bytes > limits.maximumOutputArtifactBytes
        ) replayFail("structural adapter artifact exceeds the authenticated byte limit")
        val expected = outputTreeFor(observation.programModel, observation.structuralObservation)
        if (observation.outputTree != expected || observation.outputTree.totalBytes > limits.maximumOutputTreeBytes) {
            replayFail("structural adapter output tree has missing, extra, or substituted outputs")
        }
    }

    private fun validateBoundaryReplay(
        replay: StructuralBoundaryReplayObservationV1,
        limits: StructuralProductionReplayLimitsV1,
    ) {
        if (!replay.nameIndependent) replayFail("structural boundary replay is not name-independent")
        val matched = checkedAdd(replay.exactMatches, replay.nearMisses, "structural boundary match count overflows")
        val recovered = checkedAdd(
            checkedAdd(matched, replay.falsePositives, "structural boundary recovered count overflows"),
            replay.ignoredExcludedRecoveries,
            "structural boundary recovered count overflows",
        )
        val oracle = checkedAdd(matched, replay.falseNegatives, "structural boundary oracle count overflows")
        if (recovered != replay.rawRecoveredCount) replayFail("structural boundary raw recovered count is inconsistent")
        listOf(recovered, oracle, replay.rawRecoveredCount).forEach {
            if (it > limits.maximumBoundaryEntities) replayFail("structural boundary replay exceeds the entity limit")
        }
    }

    private fun validateIdentityReplay(
        replay: StructuralIdentityReplayObservationV1,
        limits: StructuralProductionReplayLimitsV1,
    ) {
        if (!replay.complete) replayFail("structural identity replay is incomplete")
        val oracle = checkedAdd(replay.oracleGlobalCount, replay.oracleTypeCount, "structural identity oracle count overflows")
        val recovered = checkedAdd(
            replay.recoveredGlobalCount,
            replay.recoveredTypeCount,
            "structural identity recovered count overflows",
        )
        if (oracle > limits.maximumIdentityEntities || recovered > limits.maximumIdentityEntities ||
            replay.mappingCount > limits.maximumMappings || replay.mappingCount > minOf(oracle, recovered)
        ) replayFail("structural identity replay exceeds its count bounds")
    }

    private fun validateModelObservation(
        model: StructuralModelReplayObservationV1,
        limits: StructuralProductionReplayLimitsV1,
    ) {
        if (model.identityMap.bytes > limits.maximumOutputArtifactBytes ||
            model.programModel.bytes > limits.maximumOutputArtifactBytes ||
            model.structuralObservation.bytes > limits.maximumOutputArtifactBytes
        ) replayFail("structural model replay binding exceeds the artifact byte limit")
    }

    private fun validateAdapterReplayAttestation(
        value: JsonElement,
        label: String,
        expectedPayloadSha256: String,
        expectedEvidenceSha256: String,
        expectedVerifier: StructuralReplayToolV1,
    ) {
        val attestation = requireObject(value, ATTESTATION_KEYS, label)
        requireLiteral(attestation.required("kind", label), "adapter-replay", "$label kind")
        if (requireSha256(attestation.required("payloadSha256", label), "$label payload digest") != expectedPayloadSha256 ||
            requireSha256(attestation.required("evidenceSha256", label), "$label evidence digest") != expectedEvidenceSha256
        ) replayFail("$label does not bind the authenticated payload and replay receipt")
        val verifier = requireObject(attestation.required("verifier", label), VERIFIER_KEYS, "$label verifier")
        if (requireIdentifier(verifier.required("id", "$label verifier"), "$label verifier ID") != expectedVerifier.id ||
            requireIdentifier(verifier.required("version", "$label verifier"), "$label verifier version") != expectedVerifier.version
        ) replayFail("$label verifier is not the registered implementation")
    }

    private fun validateRecoveredProvenance(
        actual: JsonObject,
        request: StructuralReplayRequestV1,
        identityMap: StructuralIdentityMapReplayBindingV1,
    ) {
        val expected = JsonObject(
            linkedMapOf(
                "inputBinary" to JsonObject(
                    linkedMapOf(
                        "sha256" to JsonPrimitive(request.anchor.inputBinary.sha256),
                        "sizeBytes" to JsonPrimitive(request.anchor.inputBinary.bytes),
                    ),
                ),
                "exporter" to request.exporter.toHistoricalToolJson(),
                "loader" to JsonObject(
                    request.loader.asTool().toHistoricalToolJson() +
                        ("imageBase" to JsonPrimitive(request.loader.imageBase)),
                ),
                "targetAbi" to request.anchor.targetAbi.toJson(),
                "normalizationProfile" to request.anchor.normalizationProfile.toJson(),
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
                "identityMap" to JsonObject(linkedMapOf("sha256" to JsonPrimitive(identityMap.sha256))),
            ),
        )
        if (actual != expected) replayFail("recovered-model provenance differs from the registered replay request")
    }

    private fun readStructuralEnvelope(
        path: Path,
        label: String,
        schema: String,
        limits: StructuralProductionReplayLimitsV1,
    ): StructuralEnvelopeSnapshot {
        val bytes = try {
            OracleArtifacts.read(path, OracleArtifactLimits(limits.maximumEnvelopeBytes)).bytes
        } catch (failure: Exception) {
            throw StructuralProductionReplayException("cannot read $label", failure)
        }
        val jsonLimits = StrictJsonLimits(
            maximumInputBytes = limits.maximumEnvelopeBytes,
            maximumCanonicalBytes = limits.maximumEnvelopeBytes,
            maximumDepth = 128,
            maximumNodes = 1_000_000,
            maximumStringBytes = minOf(limits.maximumEnvelopeBytes, 1024 * 1024),
            maximumTotalStringBytes = limits.maximumEnvelopeBytes,
            maximumNumberCharacters = 128,
        )
        val root = try {
            OracleJson.parse(bytes, jsonLimits) as? JsonObject ?: replayFail("$label root must be an object")
        } catch (failure: StructuralProductionReplayException) {
            throw failure
        } catch (failure: Exception) {
            throw StructuralProductionReplayException("$label is not strict bounded UTF-8 JSON", failure)
        }
        try {
            OracleSchemas.validate(schema, root)
        } catch (failure: Exception) {
            throw StructuralProductionReplayException("$label fails the bundled $schema schema", failure)
        }
        val canonical = try {
            StructuralJsonEncoder(limits.maximumEnvelopeBytes, pretty = true, ensureAscii = false).encode(root)
        } catch (failure: Exception) {
            throw StructuralProductionReplayException("$label cannot be rendered in canonical structural form", failure)
        }
        if (!bytes.contentEquals(canonical)) replayFail("$label is not in canonical structural byte form")
        return StructuralEnvelopeSnapshot(bytes, root)
    }

    private fun readReceipt(path: Path, limits: StructuralProductionReplayLimitsV1): ByteArray = try {
        OracleArtifacts.read(path, OracleArtifactLimits(limits.maximumReceiptBytes)).bytes
    } catch (failure: Exception) {
        throw StructuralProductionReplayException("cannot read structural replay receipt", failure)
    }

    private fun publishReceipt(path: Path, bytes: ByteArray, limits: StructuralProductionReplayLimitsV1) {
        try {
            OracleArtifacts.publishAtomically(path, bytes, OracleArtifactLimits(limits.maximumReceiptBytes))
        } catch (failure: Exception) {
            throw StructuralProductionReplayException("cannot publish structural replay receipt", failure)
        }
    }

    private fun parseCanonicalReceipt(
        bytes: ByteArray,
        schema: String,
        limits: StructuralProductionReplayLimitsV1,
    ): JsonObject {
        if (bytes.size > limits.maximumReceiptBytes) replayFail("structural replay receipt exceeds its byte limit")
        val root = try {
            OracleJson.parseCanonical(bytes, receiptJsonLimits(limits.maximumReceiptBytes)) as? JsonObject
                ?: replayFail("structural replay receipt root must be an object")
        } catch (failure: StructuralProductionReplayException) {
            throw failure
        } catch (failure: Exception) {
            throw StructuralProductionReplayException("structural replay receipt is not strict canonical UTF-8 JSON", failure)
        }
        try {
            OracleSchemas.validate(schema, root)
        } catch (failure: Exception) {
            throw StructuralProductionReplayException("structural replay receipt fails the bundled $schema schema", failure)
        }
        return root
    }

    private const val EXPECTED_OUTPUT_FILE_COUNT = 2L
}

private data class StructuralEnvelopeSnapshot(val bytes: ByteArray, val document: JsonObject)

private fun StructuralReplayRequestV1.toJson(): JsonObject = JsonObject(
    linkedMapOf(
        "profile" to anchor.profile.toJson(),
        "artifactManifestSha256" to JsonPrimitive(anchor.artifactManifestSha256),
        "twin" to JsonPrimitive(anchor.twin),
        "recoveryMode" to JsonPrimitive(recoveryMode),
        "inputBinary" to anchor.inputBinary.toJson(),
        "targetAbi" to anchor.targetAbi.toJson(),
        "functionOracle" to anchor.functionOracle.toJson(),
        "structuralOracle" to anchor.structuralOracle.toJson(),
        "normalizationProfile" to anchor.normalizationProfile.toJson(),
        "boundaryReport" to anchor.boundaryReport.toJson(),
        "exporter" to exporter.toJson(),
        "loader" to loader.toJson(),
        "runtime" to runtime.toJson(),
        "identityVerifier" to identityVerifier.toJson(),
        "sandbox" to sandbox.toJson(),
    ),
)

private fun StructuralReplayProfileV1.toJson() = JsonObject(
    linkedMapOf("id" to JsonPrimitive(id), "sha256" to JsonPrimitive(sha256)),
)

private fun StructuralReplayNamedArtifactV1.toJson() = JsonObject(
    linkedMapOf("id" to JsonPrimitive(id), "sha256" to JsonPrimitive(sha256)),
)

private fun StructuralReplayInputBinaryV1.toJson() = JsonObject(
    linkedMapOf(
        "sha256" to JsonPrimitive(sha256),
        "bytes" to JsonPrimitive(bytes),
        "elfType" to JsonPrimitive(elfType),
        "imageBase" to JsonPrimitive(imageBase),
        "executableRangesSha256" to JsonPrimitive(executableRangesSha256),
    ),
)

private fun StructuralReplayNormalizationProfileV1.toJson() = JsonObject(
    linkedMapOf(
        "id" to JsonPrimitive(id),
        "version" to JsonPrimitive(version),
        "configurationSha256" to JsonPrimitive(configurationSha256),
    ),
)

private fun StructuralReplayToolV1.toJson() = JsonObject(
    linkedMapOf(
        "id" to JsonPrimitive(id),
        "version" to JsonPrimitive(version),
        "implementationSha256" to JsonPrimitive(implementationSha256),
        "configurationSha256" to JsonPrimitive(configurationSha256),
    ),
)

private fun StructuralReplayToolV1.toHistoricalToolJson() = JsonObject(
    linkedMapOf(
        "id" to JsonPrimitive(id),
        "version" to JsonPrimitive(version),
        "executableSha256" to JsonPrimitive(implementationSha256),
        "configurationSha256" to JsonPrimitive(configurationSha256),
    ),
)

private fun StructuralReplayLoaderV1.toJson() = JsonObject(
    linkedMapOf(
        "id" to JsonPrimitive(id),
        "version" to JsonPrimitive(version),
        "implementationSha256" to JsonPrimitive(implementationSha256),
        "configurationSha256" to JsonPrimitive(configurationSha256),
        "imageBase" to JsonPrimitive(imageBase),
    ),
)

private fun StructuralReplayBoundaryReportV1.toJson() = JsonObject(
    linkedMapOf("sha256" to JsonPrimitive(sha256), "adapter" to adapter.toJson()),
)

private fun StructuralReplaySandboxV1.toJson() = JsonObject(
    linkedMapOf(
        "launcherImplementationSha256" to JsonPrimitive(launcherImplementationSha256),
        "policySha256" to JsonPrimitive(policySha256),
    ),
)

private fun StructuralReplayArtifactObservationV1.toJson() = JsonObject(
    linkedMapOf("sha256" to JsonPrimitive(sha256), "bytes" to JsonPrimitive(bytes)),
)

private fun StructuralReplayStreamObservationV1.toJson() = JsonObject(
    linkedMapOf(
        "sha256" to JsonPrimitive(sha256),
        "bytes" to JsonPrimitive(bytes),
        "truncated" to JsonPrimitive(truncated),
    ),
)

private fun StructuralReplayExecutionObservationV1.toJson() = JsonObject(
    linkedMapOf(
        "logicalInvocationSha256" to JsonPrimitive(logicalInvocationSha256),
        "environmentSha256" to JsonPrimitive(environmentSha256),
        "sandboxEvidenceSha256" to JsonPrimitive(sandboxEvidenceSha256),
        "networkIsolated" to JsonPrimitive(networkIsolated),
        "exitCode" to JsonPrimitive(exitCode),
        "terminalOutcome" to JsonPrimitive(terminalOutcome),
        "timedOut" to JsonPrimitive(timedOut),
        "outOfMemory" to JsonPrimitive(outOfMemory),
        "cleanupVerified" to JsonPrimitive(cleanupVerified),
        "stdout" to stdout.toJson(),
        "stderr" to stderr.toJson(),
    ),
)

private fun StructuralReplayOutputTreeObservationV1.toJson() = JsonObject(
    linkedMapOf(
        "sha256" to JsonPrimitive(sha256),
        "fileCount" to JsonPrimitive(fileCount),
        "totalBytes" to JsonPrimitive(totalBytes),
    ),
)

private fun StructuralReplayObservationV1.toJson() = JsonObject(
    linkedMapOf(
        "execution" to execution.toJson(),
        "outputTree" to outputTree.toJson(),
        "programModel" to programModel.toJson(),
        "structuralObservation" to structuralObservation.toJson(),
    ),
)

private fun StructuralBoundaryReplayObservationV1.toJson() = JsonObject(
    linkedMapOf(
        "replaySha256" to JsonPrimitive(replaySha256),
        "rawRecoveredCount" to JsonPrimitive(rawRecoveredCount),
        "exactMatches" to JsonPrimitive(exactMatches),
        "nearMisses" to JsonPrimitive(nearMisses),
        "falsePositives" to JsonPrimitive(falsePositives),
        "falseNegatives" to JsonPrimitive(falseNegatives),
        "ignoredExcludedRecoveries" to JsonPrimitive(ignoredExcludedRecoveries),
        "oracleUniverseSha256" to JsonPrimitive(oracleUniverseSha256),
        "recoveredUniverseSha256" to JsonPrimitive(recoveredUniverseSha256),
        "selectedMappingSha256" to JsonPrimitive(selectedMappingSha256),
        "nameIndependent" to JsonPrimitive(nameIndependent),
    ),
)

private fun StructuralIdentityReplayObservationV1.toJson() = JsonObject(
    linkedMapOf(
        "replaySha256" to JsonPrimitive(replaySha256),
        "mappingCount" to JsonPrimitive(mappingCount),
        "oracleGlobalCount" to JsonPrimitive(oracleGlobalCount),
        "recoveredGlobalCount" to JsonPrimitive(recoveredGlobalCount),
        "oracleTypeCount" to JsonPrimitive(oracleTypeCount),
        "recoveredTypeCount" to JsonPrimitive(recoveredTypeCount),
        "mappingUniverseSha256" to JsonPrimitive(mappingUniverseSha256),
        "complete" to JsonPrimitive(complete),
    ),
)

private fun StructuralIdentityMapReplayBindingV1.toJson() = JsonObject(
    linkedMapOf(
        "id" to JsonPrimitive(id),
        "sha256" to JsonPrimitive(sha256),
        "bytes" to JsonPrimitive(bytes),
        "payloadSha256" to JsonPrimitive(payloadSha256),
    ),
)

private fun parseRequest(root: JsonObject): StructuralReplayRequestV1 {
    requireExactKeys(root, REQUEST_KEYS, "identity receipt request")
    val profileObject = requireObject(root.required("profile", "identity receipt request"), PROFILE_KEYS, "identity receipt profile")
    val input = requireObject(root.required("inputBinary", "identity receipt request"), INPUT_BINARY_KEYS, "identity receipt input binary")
    val normalization = requireObject(
        root.required("normalizationProfile", "identity receipt request"),
        NORMALIZATION_KEYS,
        "identity receipt normalization profile",
    )
    val boundary = requireObject(root.required("boundaryReport", "identity receipt request"), BOUNDARY_REPORT_KEYS, "identity receipt boundary report")
    val loader = requireObject(root.required("loader", "identity receipt request"), LOADER_KEYS, "identity receipt loader")
    val sandbox = requireObject(root.required("sandbox", "identity receipt request"), SANDBOX_KEYS, "identity receipt sandbox")
    return StructuralReplayRequestV1(
        StructuralReplayAnchorV1(
            StructuralReplayProfileV1(
                requireIdentifier(profileObject.required("id", "identity receipt profile"), "identity receipt profile ID"),
                requireSha256(profileObject.required("sha256", "identity receipt profile"), "identity receipt profile digest"),
            ),
            requireSha256(root.required("artifactManifestSha256", "identity receipt request"), "identity receipt manifest digest"),
            requireString(root.required("twin", "identity receipt request"), "identity receipt twin", 32),
            StructuralReplayInputBinaryV1(
                requireSha256(input.required("sha256", "identity receipt input binary"), "identity receipt input digest"),
                requireInteger(input.required("bytes", "identity receipt input binary"), "identity receipt input bytes", 1L),
                requireString(input.required("elfType", "identity receipt input binary"), "identity receipt ELF type", 16),
                requireAddress(input.required("imageBase", "identity receipt input binary"), "identity receipt image base"),
                requireSha256(
                    input.required("executableRangesSha256", "identity receipt input binary"),
                    "identity receipt executable-range digest",
                ),
            ),
            parseNamedArtifact(root, "targetAbi", "identity receipt target ABI"),
            parseNamedArtifact(root, "functionOracle", "identity receipt function oracle"),
            parseNamedArtifact(root, "structuralOracle", "identity receipt structural oracle"),
            StructuralReplayNormalizationProfileV1(
                requireIdentifier(normalization.required("id", "identity receipt normalization profile"), "normalization-profile ID"),
                requireIdentifier(
                    normalization.required("version", "identity receipt normalization profile"),
                    "normalization-profile version",
                ),
                requireSha256(
                    normalization.required("configurationSha256", "identity receipt normalization profile"),
                    "normalization-profile configuration digest",
                ),
            ),
            StructuralReplayBoundaryReportV1(
                requireSha256(boundary.required("sha256", "identity receipt boundary report"), "boundary-report digest"),
                parseTool(
                    requireObject(boundary.required("adapter", "identity receipt boundary report"), TOOL_KEYS, "boundary adapter"),
                    "boundary adapter",
                ),
            ),
        ),
        requireString(root.required("recoveryMode", "identity receipt request"), "identity receipt recovery mode", 32),
        parseTool(requireObject(root.required("exporter", "identity receipt request"), TOOL_KEYS, "identity receipt exporter"), "exporter"),
        StructuralReplayLoaderV1(
            requireIdentifier(loader.required("id", "identity receipt loader"), "loader ID"),
            requireIdentifier(loader.required("version", "identity receipt loader"), "loader version"),
            requireSha256(loader.required("implementationSha256", "identity receipt loader"), "loader implementation digest"),
            requireSha256(loader.required("configurationSha256", "identity receipt loader"), "loader configuration digest"),
            requireAddress(loader.required("imageBase", "identity receipt loader"), "loader image base"),
        ),
        parseTool(requireObject(root.required("runtime", "identity receipt request"), TOOL_KEYS, "identity receipt runtime"), "runtime"),
        parseTool(
            requireObject(root.required("identityVerifier", "identity receipt request"), TOOL_KEYS, "identity receipt identity verifier"),
            "identity verifier",
        ),
        StructuralReplaySandboxV1(
            requireSha256(
                sandbox.required("launcherImplementationSha256", "identity receipt sandbox"),
                "sandbox launcher implementation digest",
            ),
            requireSha256(sandbox.required("policySha256", "identity receipt sandbox"), "sandbox policy digest"),
        ),
    )
}

private fun parseNamedArtifact(root: JsonObject, key: String, label: String): StructuralReplayNamedArtifactV1 {
    val value = requireObject(root.required(key, "identity receipt request"), NAMED_ARTIFACT_KEYS, label)
    return StructuralReplayNamedArtifactV1(
        requireIdentifier(value.required("id", label), "$label ID"),
        requireSha256(value.required("sha256", label), "$label digest"),
    )
}

private fun parseTool(root: JsonObject, label: String): StructuralReplayToolV1 {
    requireExactKeys(root, TOOL_KEYS, label)
    return StructuralReplayToolV1(
        requireIdentifier(root.required("id", label), "$label ID"),
        requireIdentifier(root.required("version", label), "$label version"),
        requireSha256(root.required("implementationSha256", label), "$label implementation digest"),
        requireSha256(root.required("configurationSha256", label), "$label configuration digest"),
    )
}

private fun parseObservation(root: JsonObject): StructuralReplayObservationV1 {
    requireExactKeys(root, OBSERVATION_KEYS, "identity receipt observation")
    val execution = requireObject(root.required("execution", "identity receipt observation"), EXECUTION_KEYS, "identity receipt execution")
    val outputTree = requireObject(root.required("outputTree", "identity receipt observation"), OUTPUT_TREE_KEYS, "identity receipt output tree")
    return StructuralReplayObservationV1(
        StructuralReplayExecutionObservationV1(
            requireSha256(execution.required("logicalInvocationSha256", "identity receipt execution"), "logical invocation digest"),
            requireSha256(execution.required("environmentSha256", "identity receipt execution"), "environment digest"),
            requireSha256(execution.required("sandboxEvidenceSha256", "identity receipt execution"), "sandbox evidence digest"),
            requireBoolean(execution.required("networkIsolated", "identity receipt execution"), "network-isolation status"),
            requireInteger(execution.required("exitCode", "identity receipt execution"), "execution exit code", 0L, 255L).toInt(),
            requireString(execution.required("terminalOutcome", "identity receipt execution"), "execution terminal outcome", 128),
            requireBoolean(execution.required("timedOut", "identity receipt execution"), "execution timeout status"),
            requireBoolean(execution.required("outOfMemory", "identity receipt execution"), "execution memory status"),
            requireBoolean(execution.required("cleanupVerified", "identity receipt execution"), "execution cleanup status"),
            parseStream(
                requireObject(execution.required("stdout", "identity receipt execution"), STREAM_KEYS, "identity receipt stdout"),
                "stdout",
            ),
            parseStream(
                requireObject(execution.required("stderr", "identity receipt execution"), STREAM_KEYS, "identity receipt stderr"),
                "stderr",
            ),
        ),
        StructuralReplayOutputTreeObservationV1(
            requireSha256(outputTree.required("sha256", "identity receipt output tree"), "output-tree digest"),
            requireInteger(outputTree.required("fileCount", "identity receipt output tree"), "output-tree file count"),
            requireInteger(outputTree.required("totalBytes", "identity receipt output tree"), "output-tree bytes"),
        ),
        parseArtifact(
            requireObject(root.required("programModel", "identity receipt observation"), ARTIFACT_KEYS, "identity receipt program model"),
            "identity receipt program model",
        ),
        parseArtifact(
            requireObject(
                root.required("structuralObservation", "identity receipt observation"),
                ARTIFACT_KEYS,
                "identity receipt structural observation",
            ),
            "identity receipt structural observation",
        ),
    )
}

private fun parseStream(root: JsonObject, label: String) = StructuralReplayStreamObservationV1(
    requireSha256(root.required("sha256", label), "$label digest"),
    requireInteger(root.required("bytes", label), "$label bytes"),
    requireBoolean(root.required("truncated", label), "$label truncation status"),
)

private fun parseArtifact(root: JsonObject, label: String) = StructuralReplayArtifactObservationV1(
    requireSha256(root.required("sha256", label), "$label digest"),
    requireInteger(root.required("bytes", label), "$label bytes", 1L),
)

private fun parseBoundaryReplay(root: JsonObject): StructuralBoundaryReplayObservationV1 =
    StructuralBoundaryReplayObservationV1(
        requireSha256(root.required("replaySha256", "identity receipt boundary replay"), "boundary replay digest"),
        requireInteger(root.required("rawRecoveredCount", "identity receipt boundary replay"), "raw recovered count"),
        requireInteger(root.required("exactMatches", "identity receipt boundary replay"), "exact-match count"),
        requireInteger(root.required("nearMisses", "identity receipt boundary replay"), "near-miss count"),
        requireInteger(root.required("falsePositives", "identity receipt boundary replay"), "false-positive count"),
        requireInteger(root.required("falseNegatives", "identity receipt boundary replay"), "false-negative count"),
        requireInteger(
            root.required("ignoredExcludedRecoveries", "identity receipt boundary replay"),
            "ignored-excluded-recovery count",
        ),
        requireSha256(root.required("oracleUniverseSha256", "identity receipt boundary replay"), "boundary oracle-universe digest"),
        requireSha256(
            root.required("recoveredUniverseSha256", "identity receipt boundary replay"),
            "boundary recovered-universe digest",
        ),
        requireSha256(root.required("selectedMappingSha256", "identity receipt boundary replay"), "selected mapping digest"),
        requireBoolean(root.required("nameIndependent", "identity receipt boundary replay"), "boundary name-independence status"),
    )

private fun parseIdentityReplay(root: JsonObject): StructuralIdentityReplayObservationV1 =
    StructuralIdentityReplayObservationV1(
        requireSha256(root.required("replaySha256", "identity receipt identity replay"), "identity replay digest"),
        requireInteger(root.required("mappingCount", "identity receipt identity replay"), "identity mapping count"),
        requireInteger(root.required("oracleGlobalCount", "identity receipt identity replay"), "oracle global count"),
        requireInteger(root.required("recoveredGlobalCount", "identity receipt identity replay"), "recovered global count"),
        requireInteger(root.required("oracleTypeCount", "identity receipt identity replay"), "oracle type count"),
        requireInteger(root.required("recoveredTypeCount", "identity receipt identity replay"), "recovered type count"),
        requireSha256(root.required("mappingUniverseSha256", "identity receipt identity replay"), "mapping-universe digest"),
        requireBoolean(root.required("complete", "identity receipt identity replay"), "identity replay completion status"),
    )

private fun parseIdentityMapBinding(root: JsonObject): StructuralIdentityMapReplayBindingV1 =
    StructuralIdentityMapReplayBindingV1(
        requireIdentifier(root.required("id", "model receipt identity map"), "identity-map ID"),
        requireSha256(root.required("sha256", "model receipt identity map"), "identity-map digest"),
        requireInteger(root.required("bytes", "model receipt identity map"), "identity-map bytes", 1L),
        requireSha256(root.required("payloadSha256", "model receipt identity map"), "identity-map payload digest"),
    )

private fun outputTreeCommitment(
    programModel: StructuralReplayArtifactObservationV1,
    structuralObservation: StructuralReplayArtifactObservationV1,
): String {
    val value = JsonObject(
        linkedMapOf(
            "kind" to JsonPrimitive(StructuralProductionReplayContract.OUTPUT_TREE_KIND),
            "files" to JsonArray(
                listOf(
                    JsonObject(
                        linkedMapOf(
                            "name" to JsonPrimitive("program-model"),
                            "sha256" to JsonPrimitive(programModel.sha256),
                            "bytes" to JsonPrimitive(programModel.bytes),
                        ),
                    ),
                    JsonObject(
                        linkedMapOf(
                            "name" to JsonPrimitive("structural-observation"),
                            "sha256" to JsonPrimitive(structuralObservation.sha256),
                            "bytes" to JsonPrimitive(structuralObservation.bytes),
                        ),
                    ),
                ),
            ),
        ),
    )
    return compactCommitmentSha256(value, 64 * 1024)
}

private fun compactCommitmentSha256(value: JsonElement, maximumBytes: Int): String = try {
    OracleArtifacts.sha256(
        StructuralJsonEncoder(maximumBytes, pretty = false, ensureAscii = false).encode(value),
    )
} catch (failure: Exception) {
    throw StructuralProductionReplayException("structural replay compact commitment exceeds its bounds", failure)
}

private fun requireAuthenticatedReceiptPairBindings(
    identity: AuthenticatedStructuralIdentityReplayReceiptV1,
    model: AuthenticatedStructuralModelReplayReceiptV1,
) {
    if (model.identityReceiptSha256 != identity.artifactSha256 ||
        model.identityRequestSha256 != identity.requestSha256 ||
        model.identityObservationSha256 != identity.observationSha256 ||
        model.boundaryReportSha256 != identity.request.anchor.boundaryReport.sha256 ||
        model.twin != identity.request.anchor.twin
    ) replayFail("stored structural replay receipts are cross-paired")
}

private fun canonicalSha256(value: JsonElement, maximumBytes: Int): String =
    OracleArtifacts.sha256(canonicalBytes(value, maximumBytes))

private fun canonicalBytes(value: JsonElement, maximumBytes: Int): ByteArray = try {
    OracleJson.canonicalBytes(value, receiptJsonLimits(maximumBytes))
} catch (failure: Exception) {
    throw StructuralProductionReplayException("structural replay canonical JSON exceeds its bounds", failure)
}

private fun receiptJsonLimits(maximumBytes: Int) = StrictJsonLimits(
    maximumInputBytes = maximumBytes,
    maximumCanonicalBytes = maximumBytes,
    maximumDepth = 32,
    maximumNodes = 16_384,
    maximumStringBytes = minOf(maximumBytes, 16 * 1024),
    maximumTotalStringBytes = minOf(maximumBytes, 1024 * 1024),
    maximumNumberCharacters = 32,
)

private fun requireReplayIdentifier(value: String, label: String) {
    require(value.codePointLength() in 1..4096 && StructuralRecoveryV1Contract.IDENTIFIER.matches(value)) {
        "$label is not a canonical structural identifier"
    }
}

private fun requireReplaySha256(value: String, label: String) {
    require(StructuralRecoveryV1Contract.SHA256.matches(value)) { "$label is not a lowercase SHA-256 digest" }
}

private fun requireReplayAddress(value: String, label: String) {
    require(StructuralRecoveryV1Contract.ADDRESS.matches(value)) { "$label is not a canonical lowercase address" }
}

private fun requireExactKeys(value: JsonObject, keys: Set<String>, label: String) {
    if (value.keys != keys) replayFail("$label must contain exactly ${keys.sortedWith(StructuralRecoveryV1Contract.CODE_POINT_ORDER)}")
}

private fun requireObject(value: JsonElement, keys: Set<String>, label: String): JsonObject {
    val result = value as? JsonObject ?: replayFail("$label must be an object")
    requireExactKeys(result, keys, label)
    return result
}

private fun JsonObject.required(key: String, label: String): JsonElement = this[key] ?: replayFail("$label.$key is required")

private fun requireString(value: JsonElement, label: String, maximum: Int): String {
    val primitive = value as? JsonPrimitive ?: replayFail("$label must be a string")
    if (!primitive.isString) replayFail("$label must be a string")
    val result = primitive.content
    if (result.codePointLength() !in 1..maximum) replayFail("$label is empty or exceeds its character limit")
    return result
}

private fun requireIdentifier(value: JsonElement, label: String): String =
    requireString(value, label, 4096).also {
        if (!StructuralRecoveryV1Contract.IDENTIFIER.matches(it)) replayFail("$label is not a canonical structural identifier")
    }

private fun requireSha256(value: JsonElement, label: String): String =
    requireString(value, label, 64).also {
        if (!StructuralRecoveryV1Contract.SHA256.matches(it)) replayFail("$label is not a lowercase SHA-256 digest")
    }

private fun requireAddress(value: JsonElement, label: String): String =
    requireString(value, label, 18).also {
        if (!StructuralRecoveryV1Contract.ADDRESS.matches(it)) replayFail("$label is not a canonical lowercase address")
    }

private fun requireBoolean(value: JsonElement, label: String): Boolean {
    val primitive = value as? JsonPrimitive ?: replayFail("$label must be a boolean")
    if (primitive.isString || primitive.content !in setOf("true", "false")) replayFail("$label must be a boolean")
    return primitive.content == "true"
}

private fun requireLiteral(value: JsonElement, expected: String, label: String) {
    if (requireString(value, label, 128) != expected) replayFail("$label is invalid")
}

private fun requireInteger(
    value: JsonElement,
    label: String,
    minimum: Long = 0L,
    maximum: Long = Long.MAX_VALUE,
): Long {
    val primitive = value as? JsonPrimitive ?: replayFail("$label must be an integer")
    if (primitive.isString || primitive.content.any { it in ".eE" }) replayFail("$label must be an integer")
    val result = primitive.content.toLongOrNull() ?: replayFail("$label is outside the supported integer range")
    if (result !in minimum..maximum) replayFail("$label is outside its integer range")
    return result
}

private fun checkedAdd(left: Long, right: Long, message: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw StructuralProductionReplayException(message, failure)
}

internal fun replayFail(message: String): Nothing = throw StructuralProductionReplayException(message)

private val IDENTITY_ROOT_KEYS = setOf(
    "schemaVersion",
    "kind",
    "request",
    "observation",
    "boundaryReplay",
    "identityReplay",
    "identityMapPayloadSha256",
    "receiptSha256",
)
private val MODEL_ROOT_KEYS = setOf(
    "schemaVersion",
    "kind",
    "identityReceiptSha256",
    "identityRequestSha256",
    "identityObservationSha256",
    "identityMap",
    "boundaryReportSha256",
    "twin",
    "programModel",
    "structuralObservation",
    "recoveredModelId",
    "recoveredModelPayloadSha256",
    "provenanceSha256",
    "receiptSha256",
)
private val REQUEST_KEYS = setOf(
    "profile",
    "artifactManifestSha256",
    "twin",
    "recoveryMode",
    "inputBinary",
    "targetAbi",
    "functionOracle",
    "structuralOracle",
    "normalizationProfile",
    "boundaryReport",
    "exporter",
    "loader",
    "runtime",
    "identityVerifier",
    "sandbox",
)
private val PROFILE_KEYS = setOf("id", "sha256")
private val NAMED_ARTIFACT_KEYS = setOf("id", "sha256")
private val INPUT_BINARY_KEYS = setOf("sha256", "bytes", "elfType", "imageBase", "executableRangesSha256")
private val NORMALIZATION_KEYS = setOf("id", "version", "configurationSha256")
private val BOUNDARY_REPORT_KEYS = setOf("sha256", "adapter")
private val TOOL_KEYS = setOf("id", "version", "implementationSha256", "configurationSha256")
private val LOADER_KEYS = TOOL_KEYS + "imageBase"
private val SANDBOX_KEYS = setOf("launcherImplementationSha256", "policySha256")
private val ARTIFACT_KEYS = setOf("sha256", "bytes")
private val STREAM_KEYS = setOf("sha256", "bytes", "truncated")
private val OBSERVATION_KEYS = setOf("execution", "outputTree", "programModel", "structuralObservation")
private val EXECUTION_KEYS = setOf(
    "logicalInvocationSha256",
    "environmentSha256",
    "sandboxEvidenceSha256",
    "networkIsolated",
    "exitCode",
    "terminalOutcome",
    "timedOut",
    "outOfMemory",
    "cleanupVerified",
    "stdout",
    "stderr",
)
private val OUTPUT_TREE_KEYS = setOf("sha256", "fileCount", "totalBytes")
private val BOUNDARY_REPLAY_KEYS = setOf(
    "replaySha256",
    "rawRecoveredCount",
    "exactMatches",
    "nearMisses",
    "falsePositives",
    "falseNegatives",
    "ignoredExcludedRecoveries",
    "oracleUniverseSha256",
    "recoveredUniverseSha256",
    "selectedMappingSha256",
    "nameIndependent",
)
private val IDENTITY_REPLAY_KEYS = setOf(
    "replaySha256",
    "mappingCount",
    "oracleGlobalCount",
    "recoveredGlobalCount",
    "oracleTypeCount",
    "recoveredTypeCount",
    "mappingUniverseSha256",
    "complete",
)
private val IDENTITY_MAP_KEYS = setOf("id", "sha256", "bytes", "payloadSha256")
private val IDENTITY_MAP_ENVELOPE_KEYS = setOf("schemaVersion", "scope", "map", "mappings", "attestation")
private val IDENTITY_MAP_HEADER_KEYS = setOf("id", "oracleId", "oracleSha256", "recoveredModelId")
private val IDENTITY_MAPPING_KEYS = setOf("kind", "oracleId", "recoveredId", "evidence")
private val RECOVERED_MODEL_ENVELOPE_KEYS = setOf("schemaVersion", "scope", "model", "provenance", "entities", "attestation")
private val MODEL_HEADER_KEYS = setOf("id")
private val RECOVERED_PROVENANCE_KEYS = setOf(
    "inputBinary",
    "exporter",
    "loader",
    "targetAbi",
    "normalizationProfile",
    "boundaryScore",
    "identityMap",
)
private val ATTESTATION_KEYS = setOf("kind", "payloadSha256", "evidenceSha256", "verifier")
private val VERIFIER_KEYS = setOf("id", "version")
