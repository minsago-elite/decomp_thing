package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Exact host-captured full-export model paired with the profile binding and operation receipt chain
 * that authenticated it. This value carries provenance only; production scoring remains unavailable.
 */
internal class GccDriverStructuralAuthenticatedFullExportV1 private constructor(
    val binding: GccDriverStructuralFullExportBindingV2,
    private val snapshot: GccBundledFullExportSnapshot,
) {
    val programModelSha256: String = snapshot.programModelSha256
    val programModelBytes: Long = snapshot.programModelBytes
    val outputTreeSha256: String = snapshot.outputTreeSha256
    val scored: Boolean = false
    val releaseEligible: Boolean = false

    /** Defensive copy of the exact model bytes captured after the contained exporter stopped. */
    val canonicalProgramModelBytes: ByteArray
        get() = snapshot.programModel

    /** Prevents a result publisher from pairing this binding with a different operation snapshot. */
    internal fun requireSameSnapshot(candidate: GccBundledFullExportSnapshot) {
        if (candidate !== snapshot) {
            throw GccDriverStructuralProfileException(
                "authenticated GCC structural model is detached from its captured full-export operation",
            )
        }
    }

    companion object {
        internal fun capture(
            profile: GccDriverStructuralInputsV1,
            operation: GccBundledFullExportOperation,
        ): GccDriverStructuralAuthenticatedFullExportV1 {
            val binding = profile.bindFullExport(operation)
            val snapshot = operation.snapshot
            val modelBytes = snapshot.programModel
            if (modelBytes.size.toLong() != snapshot.programModelBytes ||
                OracleArtifacts.sha256(modelBytes) != snapshot.programModelSha256
            ) {
                throw GccDriverStructuralProfileException(
                    "authenticated GCC structural model differs from its captured full-export commitment",
                )
            }
            val bindingDocument = OracleJson.parseCanonical(binding.canonicalBytes) as JsonObject
            val boundModel = bindingDocument.getValue("programModel").jsonObject
            if (boundModel.getValue("sha256").jsonPrimitive.content != snapshot.programModelSha256 ||
                boundModel.getValue("bytes").jsonPrimitive.content.toLongOrNull() != snapshot.programModelBytes ||
                bindingDocument.getValue("outputTreeSha256").jsonPrimitive.content != snapshot.outputTreeSha256
            ) {
                throw GccDriverStructuralProfileException(
                    "authenticated GCC structural binding does not cover the captured model and output tree",
                )
            }
            return GccDriverStructuralAuthenticatedFullExportV1(binding, snapshot)
        }
    }
}
