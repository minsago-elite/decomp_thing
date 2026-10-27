package decompengine.project

import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentOperation
import decompengine.agent.AgentStopReason
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*

/** Trusted in-memory capture has no agent process, ACP session, or sandbox lifecycle to attest. */
internal class CapturedReconstructionReceipt private constructor(
    val requestSha256: String,
    val json: String,
) {
    companion object {
        fun capture(
            moduleId: String,
            promptSha256: String,
            strategy: String,
            request: AgentExecutionRequest,
            receipt: AgentExecutionReceipt,
            events: ArchivedAgentEventSnapshot,
        ): CapturedReconstructionReceipt {
            require(receipt.requestBinding == AgentExecutionRequestBinding.capture(request))
            val result = receipt.requireResult()
            require(result.stopReason == AgentStopReason.COMPLETED)
            require(events.complete && events.observedEventCount == events.events.size.toLong())
            require(events.fileChanges() == result.changes)
            val change = result.changes.single()
            require(change.kind in setOf(AgentFileChangeKind.CREATED, AgentFileChangeKind.MODIFIED))
            require(request.accessPolicy.allows(change.path, AgentOperation.WRITE_FILE))
            val json = buildJsonObject {
                put("schemaVersion", 3)
                put("kind", "decomp-engine.reconstruction-captured-source-receipt")
                put("moduleId", moduleId)
                put("requestSha256", receipt.requestBinding.requestSha256)
                put("accessPolicySha256", receipt.requestBinding.accessPolicySha256)
                put("promptSha256", promptSha256)
                put("strategy", strategy)
                put("target", change.path.relativePath)
                put("rootId", change.path.rootId)
                put("changeKind", change.kind.name.lowercase())
                put("beforeSha256", change.beforeSha256?.let(::JsonPrimitive) ?: JsonNull)
                put("afterSha256", requireNotNull(change.afterSha256))
                put("sizeBytes", requireNotNull(change.sizeBytes))
                put("terminalOutcome", "returned-completed")
                put("authority", "bounded-in-memory-source-replacements")
            }.toString()
            return CapturedReconstructionReceipt(receipt.requestBinding.requestSha256, json)
        }
    }
}

/** Independently checks the captured receipt against the archived source and checkpoint. */
internal fun verifyCapturedReconstructionReceipt(
    bytes: ByteArray,
    moduleId: String,
    source: GeneratedFileEvidence,
    sourceBytes: Long,
    requestSha256: String?,
    promptSha256: String,
    strategy: String,
) {
    val root = OracleJson.parse(bytes, StrictJsonLimits(maximumInputBytes = 16_384)).jsonObject
    require(root.keys == setOf("schemaVersion", "kind", "moduleId", "requestSha256", "accessPolicySha256",
        "promptSha256", "strategy", "target", "rootId", "changeKind", "beforeSha256", "afterSha256",
        "sizeBytes", "terminalOutcome", "authority"))
    fun string(key: String): String = root.getValue(key).jsonPrimitive.let {
        require(it.isString)
        it.content
    }
    require(root.getValue("schemaVersion").jsonPrimitive.let { !it.isString && it.int == 3 })
    require(string("kind") == "decomp-engine.reconstruction-captured-source-receipt")
    require(string("authority") == "bounded-in-memory-source-replacements")
    require(string("moduleId") == moduleId && string("rootId") == "project")
    require(string("target") == source.path && string("afterSha256") == source.sha256)
    require(root.getValue("sizeBytes").jsonPrimitive.let { !it.isString && it.long == sourceBytes })
    require(string("terminalOutcome") == "returned-completed")
    require(string("requestSha256") == requestSha256 && string("promptSha256") == promptSha256)
    require(string("strategy") == strategy && strategy.startsWith(source.generator + ":context-"))
    for (key in listOf("requestSha256", "promptSha256", "accessPolicySha256", "afterSha256")) {
        require(string(key).matches(Regex("[0-9a-f]{64}")))
    }
    when (string("changeKind")) {
        "created" -> require(root.getValue("beforeSha256") == JsonNull)
        "modified" -> require(string("beforeSha256").matches(Regex("[0-9a-f]{64}")))
        else -> error("unsupported captured reconstruction change kind")
    }
}
