package decompengine.project

import kotlinx.serialization.json.JsonPrimitive

/** Workflow-owned compiler evidence; ACP completion alone never establishes compilability. */
internal data class ModuleCompilationEvidence(
    val sourceSha256: String,
    val command: List<String>,
    val outcome: String,
    val returnCode: Int?,
    val diagnosticsSha256: String,
    val diagnosticsBytes: Long,
) {
    val passed: Boolean get() = outcome == "passed" && returnCode == 0

    fun toJson(): String = buildString {
        append("{\"sourceSha256\":\"").append(sourceSha256).append("\",\"command\":[")
        append(command.joinToString(",") { JsonPrimitive(it).toString() })
        append("],\"outcome\":\"").append(outcome).append("\",\"returnCode\":")
        append(returnCode ?: "null")
        append(",\"diagnosticsSha256\":\"").append(diagnosticsSha256)
        append("\",\"diagnosticsBytes\":").append(diagnosticsBytes).append('}')
    }
}

