package decompengine.builtin

import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentWorkflow
import decompengine.agent.AgentWorkspacePath
import java.nio.file.Path

/**
 * Per-attempt journal provisioning for the shared captured repair workflow. The existing private
 * directory is operator-owned; task names cannot select paths. Journal creation remains exclusive.
 */
class BuiltinRepairJournalFactory(
    private val directory: Path,
    private val provider: String,
    private val model: String,
    private val maximumBytes: Long = 64L * 1024 * 1024,
    private val maximumRecordBytes: Int = 8 * 1024 * 1024,
    private val maximumRecords: Int = 10_000,
    internal val factoryProvenance: BuiltinHarnessProvenance? = null,
) {
    init {
        // Reuse the journal's configuration grammar and limits without accessing the filesystem.
        configuration("0".repeat(64), BuiltinJournalIdentity(provider, model,
            "0".repeat(64), "0".repeat(64), "0".repeat(64), factoryProvenance))
    }

    internal fun create(request: AgentExecutionRequest, files: Map<String, ByteArray>,
        maximumEvidenceBytes: Long): BuiltinJournalConfiguration {
        val workflow = requireNotNull(request.workflowIdentity) { "captured repair requires workflow lineage" }
        require(workflow.workflow == AgentWorkflow.REPAIR) { "captured repair requires repair lineage" }
        val root = request.workspaceRoots.single()
        val source = BuiltinWorkspaceSnapshot.capture(files.mapKeys { AgentWorkspacePath(root.id, it.key) }, maximumEvidenceBytes)
        val stage = builtinCapturedStageSha256(request, source.sha256)
        // Name by the durable task, not the request: changing a request cannot restart the same task.
        val task = checkpointHash("builtin-repair-task-v1\n${workflow.taskId}".toByteArray(Charsets.UTF_8))
        return configuration(task, BuiltinJournalIdentity(provider, model, source.sha256, stage, workflow.acceptedRevisionSha256, factoryProvenance, workflow.inputRevisionSha256))
    }

    private fun configuration(task: String, identity: BuiltinJournalIdentity) = BuiltinJournalConfiguration(
        directory.resolve("$task.jsonl"), identity, maximumBytes, maximumRecordBytes, maximumRecords,
    )

    override fun toString() = "BuiltinRepairJournalFactory(redacted)"
}

internal fun builtinCapturedStageSha256(request: AgentExecutionRequest, sourceSha256: String): String =
    checkpointHash(("builtin-captured-stage-v1\n" + AgentExecutionRequestBinding.capture(request).requestSha256 +
        "\n" + sourceSha256).toByteArray(Charsets.UTF_8))
