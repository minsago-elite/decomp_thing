package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Profile-bound provenance for a full export; it is not a verified-input capability or score authority. */
internal class GccDriverStructuralFullExportBindingV1 private constructor(bytes: ByteArray) {
    private val storedBytes = bytes.copyOf()
    val canonicalBytes: ByteArray get() = storedBytes.copyOf()
    val sha256: String = OracleArtifacts.sha256(storedBytes)

    companion object {
        fun create(
            profileId: String,
            version: String,
            sourceRevision: String,
            artifactManifestSha256: String,
            targetDescriptorBytes: ByteArray,
            inputSha256: String,
            inputBytes: Long,
            exporterSha256: String,
            exporterBytes: Long,
            ghidraArchiveSha256: String,
            ghidraArchiveBytes: Long,
            programModelSha256: String,
            programModelBytes: Long,
            outputTreeSha256: String,
            functionCount: Long,
        ): GccDriverStructuralFullExportBindingV1 {
            val target = OracleJson.parseCanonical(targetDescriptorBytes) as? JsonObject
                ?: throw GccDriverStructuralProfileException("GCC target descriptor is not a canonical object")
            val fields = JsonObject(linkedMapOf(
                "provider" to JsonPrimitive("gcc-driver-structural-full-export-binding-v1"),
                "schemaVersion" to JsonPrimitive(1),
                "profileId" to JsonPrimitive(profileId),
                "profileVersion" to JsonPrimitive(version),
                "sourceRevision" to JsonPrimitive(sourceRevision),
                "artifactManifestSha256" to JsonPrimitive(artifactManifestSha256),
                "targetDescriptor" to target,
                "targetDescriptorSha256" to JsonPrimitive(OracleArtifacts.sha256(targetDescriptorBytes)),
                "inputBinary" to JsonObject(mapOf(
                    "sha256" to JsonPrimitive(inputSha256),
                    "bytes" to JsonPrimitive(inputBytes),
                )),
                "exporter" to JsonObject(mapOf(
                    "sha256" to JsonPrimitive(exporterSha256),
                    "bytes" to JsonPrimitive(exporterBytes),
                    "recoveryMode" to JsonPrimitive("full"),
                )),
                "ghidraArchive" to JsonObject(mapOf(
                    "sha256" to JsonPrimitive(ghidraArchiveSha256),
                    "bytes" to JsonPrimitive(ghidraArchiveBytes),
                )),
                "programModel" to JsonObject(mapOf(
                    "sha256" to JsonPrimitive(programModelSha256),
                    "bytes" to JsonPrimitive(programModelBytes),
                    "functionCount" to JsonPrimitive(functionCount),
                )),
                "outputTreeSha256" to JsonPrimitive(outputTreeSha256),
            ))
            require(profileId.matches(Regex("[a-z0-9][a-z0-9._-]{0,127}"))) {
                "GCC structural full-export profile ID is invalid"
            }
            require(version.matches(Regex("[A-Za-z0-9._+-]{1,64}"))) {
                "GCC structural full-export profile version is invalid"
            }
            require(sourceRevision.matches(Regex("[a-f0-9]{40}"))) {
                "GCC structural full-export source revision is invalid"
            }
            listOf(
                artifactManifestSha256, inputSha256, exporterSha256, ghidraArchiveSha256,
                programModelSha256, outputTreeSha256,
            ).forEach { require(it.matches(Regex("[a-f0-9]{64}"))) { "GCC structural full-export digest is invalid" } }
            require(inputBytes > 0L && exporterBytes > 0L && ghidraArchiveBytes > 0L &&
                programModelBytes > 0L && functionCount > 0L
            ) { "GCC structural full-export inventory is empty or invalid" }
            val bytes = OracleJson.canonicalBytes(fields)
            return GccDriverStructuralFullExportBindingV1(bytes)
        }
    }
}
