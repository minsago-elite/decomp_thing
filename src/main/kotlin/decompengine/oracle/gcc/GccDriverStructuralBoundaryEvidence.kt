package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.structural.CanonicalProgramModelStreaming
import decompengine.oracle.structural.StructuralBoundaryReplayV1
import decompengine.oracle.structural.StructuralFunctionOracleV1
import decompengine.oracle.structural.StructuralRecoveryV1Inputs
import decompengine.oracle.structural.StructuralRecoveryV1Limits
import java.security.MessageDigest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Boundary/name observations from one captured driver twin, without structural scoring authority. */
internal class GccDriverStructuralBoundaryEvidenceV1 private constructor(observation: ByteArray, binding: ByteArray) {
    private val observation = observation.copyOf()
    private val binding = binding.copyOf()
    val observationBytes: ByteArray get() = observation.copyOf()
    val bindingBytes: ByteArray get() = binding.copyOf()

    companion object {
        const val OBSERVATION_NAME = "driver-boundary-observation.json"
        const val BINDING_NAME = "driver-boundary-binding.json"
        const val MAXIMUM_OBSERVATION_BYTES = 64 * 1024 * 1024
        const val MAXIMUM_BINDING_BYTES = 256 * 1024
        const val FUNCTION_ORACLE_SHA256 = "b49b8a72a96580bd8727d9dc530753f40f78185a656f472ebe83a7a1f6fc9aae"
        const val EXCLUSIONS_SHA256 = "71039d9d5462c54b920d3ebe2cd2aff855faf211389a4e86bab3158bca742031"
        private const val MANIFEST_SHA256 = "c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9"
        private const val TARGET_SHA256 = "d251d5e6a0edc17655c355fb8fd757d557f064a6e67095ad53c8ca1e7569a343"

        fun capture(
            profile: GccDriverStructuralInputsV1,
            authenticatedExport: GccDriverStructuralAuthenticatedFullExportV1,
        ): GccDriverStructuralBoundaryEvidenceV1 {
            check(!authenticatedExport.scored && !authenticatedExport.releaseEligible)
            val bytes = authenticatedExport.canonicalProgramModelBytes
            require(bytes.size.toLong() == authenticatedExport.programModelBytes &&
                OracleArtifacts.sha256(bytes) == authenticatedExport.programModelSha256) {
                "driver boundary input differs from its authenticated snapshot"
            }
            return create(profile, authenticatedExport.binding.canonicalBytes, bytes).also {
                val binding = OracleJson.parseCanonical(it.bindingBytes).jsonObject
                require(binding.getValue("outputTreeSha256").jsonPrimitive.content == authenticatedExport.outputTreeSha256)
            }
        }

        /**
         * Replays retained observations after the caller authenticates the full-export binding and
         * operation receipts. This verifies bytes only and cannot construct an authenticated export.
         */
        fun verifyRetained(
            profile: GccDriverStructuralInputsV1,
            fullExportBindingBytes: ByteArray,
            programModelBytes: ByteArray,
            observationBytes: ByteArray,
            bindingBytes: ByteArray,
        ) {
            require(observationBytes.size in 1..MAXIMUM_OBSERVATION_BYTES && bindingBytes.size in 1..MAXIMUM_BINDING_BYTES) {
                "driver boundary evidence exceeds its byte bound"
            }
            val expected = create(profile, fullExportBindingBytes, programModelBytes)
            require(MessageDigest.isEqual(expected.observationBytes, observationBytes)) {
                "retained driver boundary observation differs from replay"
            }
            require(MessageDigest.isEqual(expected.bindingBytes, bindingBytes)) {
                "retained driver boundary binding differs from its full-export inputs"
            }
        }

        private fun create(
            profile: GccDriverStructuralInputsV1,
            fullExportBindingBytes: ByteArray,
            programModelBytes: ByteArray,
        ): GccDriverStructuralBoundaryEvidenceV1 {
            val oracle = loadOracle(profile)
            val model = CanonicalProgramModelStreaming.readCanonical(programModelBytes)
            require(model.model.inputSha256 == profile.strippedBinary.sha256) {
                "driver boundary model does not identify the selected stripped artifact"
            }
            require(fullExportBindingBytes.size in 1..MAXIMUM_BINDING_BYTES)
            val full = OracleJson.parseCanonical(fullExportBindingBytes, StrictJsonLimits(
                maximumInputBytes = MAXIMUM_BINDING_BYTES, maximumCanonicalBytes = MAXIMUM_BINDING_BYTES,
            )).jsonObject
            require(full["provider"] == JsonPrimitive("gcc-compiler-engine-structural-full-export-binding-v2") &&
                full["schemaVersion"] == JsonPrimitive(2) && full["profileId"] == JsonPrimitive(profile.profileId) &&
                full["artifactManifestSha256"] == JsonPrimitive(profile.artifactManifestSha256) &&
                full["compilerEngineProfileSha256"] == JsonPrimitive(profile.compilerEngineProfileSha256) &&
                full["fullExportProfileSha256"] == JsonPrimitive(profile.fullExportProfileSha256) &&
                full.getValue("receiptLineage").jsonObject["engineId"] == JsonPrimitive("driver")) {
                "driver boundary full-export binding identifies another profile or engine"
            }
            require(full["inputBinary"] == JsonObject(mapOf(
                "sha256" to JsonPrimitive(profile.strippedBinary.sha256), "bytes" to JsonPrimitive(profile.strippedBinary.bytes),
            )) && full["programModel"] == JsonObject(mapOf(
                "sha256" to JsonPrimitive(model.sha256), "bytes" to JsonPrimitive(model.sizeBytes),
                "functionCount" to JsonPrimitive(model.model.functions.size),
            ))) { "driver boundary full-export binding differs from the exact model or input inventory" }
            val target = full.getValue("targetDescriptor").jsonObject
            require(target["checkedTargetAbiSha256"] == JsonPrimitive(TARGET_SHA256) &&
                target["imageBase"] == JsonPrimitive("0x${profile.imageBase.toString(16)}") &&
                target["executableRangesSha256"] == JsonPrimitive(profile.inputBinary.executableRangesSha256) &&
                full["targetDescriptorSha256"] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(target)))) {
                "driver boundary target or executable ranges differ from its profile"
            }
            val treeSha256 = full.getValue("outputTreeSha256").jsonPrimitive.let {
                require(it.isString && it.content.matches(Regex("[a-f0-9]{64}")))
                it.content
            }
            val observed = StructuralBoundaryReplayV1.observeSelected(oracle, "stripped", programModelBytes, profile.imageBase)
            val verified = StructuralBoundaryReplayV1.verifySelected(
                oracle, "stripped", programModelBytes, profile.imageBase, observed.canonicalBytes,
            )
            val binding = OracleJson.canonicalBytes(JsonObject(mapOf(
                "provider" to JsonPrimitive("gcc-driver-boundary-evidence-binding-v1"),
                "schemaVersion" to JsonPrimitive(1),
                "scope" to JsonPrimitive("selected-twin-function-boundaries-and-names"),
                "profileId" to JsonPrimitive(profile.profileId),
                "twin" to JsonPrimitive("stripped"),
                "fullExportBindingSha256" to JsonPrimitive(OracleArtifacts.sha256(fullExportBindingBytes)),
                "observationSha256" to JsonPrimitive(verified.sha256),
                "observationBytes" to JsonPrimitive(verified.canonicalBytes.size),
                "programModelSha256" to JsonPrimitive(model.sha256),
                "programModelBytes" to JsonPrimitive(model.sizeBytes),
                "outputTreeSha256" to JsonPrimitive(treeSha256),
                "functionOracleSha256" to JsonPrimitive(FUNCTION_ORACLE_SHA256),
                "reviewedExclusionsSha256" to JsonPrimitive(EXCLUSIONS_SHA256),
                "artifactManifestSha256" to JsonPrimitive(MANIFEST_SHA256),
                "checkedTargetAbiSha256" to JsonPrimitive(TARGET_SHA256),
                "inputSha256" to JsonPrimitive(profile.strippedBinary.sha256),
                "imageBase" to JsonPrimitive("0x${profile.imageBase.toString(16)}"),
                "executableRangesSha256" to JsonPrimitive(profile.inputBinary.executableRangesSha256),
                "complete" to JsonPrimitive(false),
                "scored" to JsonPrimitive(false),
                "productionVerified" to JsonPrimitive(false),
                "releaseEligible" to JsonPrimitive(false),
            )))
            require(binding.size <= MAXIMUM_BINDING_BYTES)
            return GccDriverStructuralBoundaryEvidenceV1(verified.canonicalBytes, binding)
        }

        private fun loadOracle(profile: GccDriverStructuralInputsV1): StructuralFunctionOracleV1 {
            require(profile.engineId == "driver" && profile.profileId == "gcc-driver-16.2.0" &&
                profile.artifactManifestSha256 == MANIFEST_SHA256 && profile.targetAbi.descriptorSha256 == TARGET_SHA256) {
                "driver boundary evidence requires the checked driver profile"
            }
            val oracle = StructuralRecoveryV1Inputs.loadFunctionOracle(
                profile.root.resolve("function-recovery-oracle.json"),
                StructuralRecoveryV1Limits(maximumJsonInputBytes = 16 * 1024 * 1024),
            )
            require(oracle.snapshot.size == 12_558_460 && oracle.snapshot.sha256 == FUNCTION_ORACLE_SHA256 &&
                oracle.scope == "production" && oracle.id == profile.profileId && oracle.artifactManifestSha256 == MANIFEST_SHA256) {
                "driver function oracle differs from its checked identity"
            }
            val exclusions = OracleArtifacts.read(profile.root.resolve("function-recovery-exclusions.json"),
                OracleArtifactLimits(256 * 1024))
            require(exclusions.sha256 == EXCLUSIONS_SHA256 &&
                OracleJson.parse(exclusions.bytes).jsonObject["richArtifactSha256"] == JsonPrimitive(profile.fullBinary.sha256)) {
                "driver reviewed exclusions differ from the checked rich artifact"
            }
            for ((twin, binary) in listOf("rich" to profile.fullBinary, "stripped" to profile.strippedBinary)) {
                val artifact = oracle.artifacts.getValue(twin)
                require(artifact.inputSha256 == binary.sha256 && artifact.elfType == binary.elfType &&
                    artifact.elfImageBase == profile.imageBase &&
                    artifact.executableRvaRanges == profile.executableRanges.map { it.startRva to it.endExclusiveRva }) {
                    "driver boundary oracle artifact, image base or executable ranges differ from the authenticated profile"
                }
            }
            return oracle
        }
    }
}
