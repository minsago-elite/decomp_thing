package decompengine.project

import decompengine.oracle.structural.VerifiedStructuralInputsV1
import java.util.Collections

/**
 * Exact analysis bytes and optional EXISTING selected-domain authority. This publicly constructible
 * transport grants no authority itself. A capability is usable only with its exact captured model.
 */
class ProgramAnalysisResult(
    programModelBytes: ByteArray,
    structuralInputs: VerifiedStructuralInputsV1? = null,
    checkpoint: (String) -> Unit = {},
) {
    private val bytes: ByteArray
    val model: RecoveredProgramModel
    val modelSha256: String
    val modelBytes: Long
    val modelSchemaVersion: Int get() = model.schemaVersion
    val inputSha256: String get() = model.inputSha256
    val canonicalModelBytes: ByteArray get() = bytes.copyOf()
    internal val selectedStructuralInputs: VerifiedStructuralInputsV1? = structuralInputs

    init {
        fun check(stage: String) = assessmentCheckpoint(checkpoint, stage)
        check("before analysis snapshot")
        require(programModelBytes.size in 1..MAXIMUM_MODEL_BYTES) { "analysis model exceeds its byte bound" }
        bytes = programModelBytes.copyOf()
        modelBytes = bytes.size.toLong()
        modelSha256 = sha256(bytes)
        model = freezeModel(ProgramModelJson.readCanonical(bytes, ::check), ::check)
        structuralInputs?.let { capability ->
            require(inputSha256.matches(Regex("[0-9a-f]{64}")) &&
                capability.inputSha256 == inputSha256 && capability.programModelSha256 == modelSha256 &&
                capability.programModelBytes == modelBytes) {
                "structural capability differs from the exact analysis snapshot"
            }
        }
        check("after analysis snapshot")
    }

    companion object {
        const val MAXIMUM_MODEL_BYTES: Int = 512 * 1024 * 1024

        /** Ordinary analysis retains historical extraction labels, without structural authority. */
        fun fromModel(model: RecoveredProgramModel, checkpoint: (String) -> Unit = {}): ProgramAnalysisResult {
            assessmentCheckpoint(checkpoint, "before ordinary model encoding")
            val bytes = model.toJson { assessmentCheckpoint(checkpoint, it) }.toByteArray(Charsets.UTF_8)
            assessmentCheckpoint(checkpoint, "after ordinary model encoding")
            return ProgramAnalysisResult(bytes, checkpoint = checkpoint)
        }
    }
}

internal fun assessmentCheckpoint(checkpoint: (String) -> Unit, stage: String) {
    if (Thread.currentThread().isInterrupted) throw InterruptedException("recovery assessment interrupted")
    checkpoint(stage)
    if (Thread.currentThread().isInterrupted) throw InterruptedException("recovery assessment interrupted")
}

private fun freezeModel(model: RecoveredProgramModel, checkpoint: (String) -> Unit): RecoveredProgramModel {
    fun <T> freeze(values: List<T>): List<T> = Collections.unmodifiableList(values.toList())
    return model.copy(
        functions = freeze(model.functions.map { function ->
            checkpoint("freezing analysis function")
            function.copy(calls = Collections.unmodifiableSet(function.calls.toSet()),
                referencedGlobals = Collections.unmodifiableSet(function.referencedGlobals.toSet()),
                strings = Collections.unmodifiableSet(function.strings.toSet()))
        }),
        globals = freeze(model.globals.map { global ->
            checkpoint("freezing analysis global")
            global.copy(byteEvidence = global.byteEvidence?.let { evidence -> evidence.copy(
                windows = freeze(evidence.windows.map { it.copy(segments = freeze(it.segments)) }),
                collectionOmissions = freeze(evidence.collectionOmissions),
            ) })
        }),
        types = freeze(model.types),
    )
}
