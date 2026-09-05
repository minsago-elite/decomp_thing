package decompengine.builtin

import com.agentclientprotocol.protocol.AcpExpectedError
import decompengine.acp.*
import decompengine.agent.*
import decompengine.builtin.provider.*
import decompengine.repair.BoundedRepairOutput
import decompengine.repair.CapturedRepairAgentHarness
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import java.util.Collections

/** Typed adapters only: every actual file operation is performed and authorized by an ACP callback. */
internal class BuiltinFilesystemDispatcher(
    private val request: AgentExecutionRequest,
    private val filesystem: AcpFilesystemSession,
    private val maximumResultBytes: Int,
) {
    val definitions = listOf(
        definition("read_text", "Read a bounded authorized UTF-8 file", emptyMap()),
        definition("write_text", "Replace authorized candidate text atomically", mapOf("content" to stringSchema())),
        definition("search_text", "Find literal text in one authorized file, returning at most 100 lines",
            mapOf("query" to buildJsonObject { put("type", "string"); put("minLength", 1); put("maxLength", 1024) })),
    )

    fun execute(call: ModelToolCall, control: BuiltinExecutionControl): BuiltinToolResult {
        control.checkpoint()
        val arguments = call.arguments
        val path = try {
            AgentWorkspacePath(arguments.getValue("root").jsonPrimitive.content, arguments.getValue("path").jsonPrimitive.content)
                .resolve(request.workspaceRoots).toString()
        } catch (_: IllegalArgumentException) { return BuiltinToolResult("invalid workspace path", failed = true) }
        return try {
            val result = runBlocking {
                when (call.name) {
                    "read_text" -> filesystem.readTextFile(call.id, path, null, null).content
                    "write_text" -> {
                        filesystem.writeTextFile(call.id, path, arguments.getValue("content").jsonPrimitive.content)
                        "candidate text replaced"
                    }
                    "search_text" -> {
                        val query = arguments.getValue("query").jsonPrimitive.content
                        val content = filesystem.readTextFile(call.id, path, null, null).content
                        search(content, query, control)
                    }
                    else -> return@runBlocking null
                }
            } ?: return BuiltinToolResult("unregistered filesystem tool", failed = true)
            control.checkpoint()
            if (result.length > maximumResultBytes || result.toByteArray().size > maximumResultBytes)
                return BuiltinToolResult("filesystem result exceeds its byte budget", failed = true)
            BuiltinToolResult(result)
        } catch (_: AcpExpectedError) {
            control.checkpoint()
            // The shared broker retains the exact reason in its metadata audit, without raw error text.
            BuiltinToolResult("shared filesystem authority denied or failed this operation", failed = true)
        }
    }

    private fun search(content: String, query: String, control: BuiltinExecutionControl): String {
        var truncated = false
        val matches = mutableListOf<Pair<Int, String>>()
        for ((index, line) in content.lineSequence().withIndex()) {
            control.checkpoint()
            if (query in line) {
                if (matches.size == 100) { truncated = true; break }
                matches += index + 1 to line
            }
        }
        return boundedProviderJson(maximumResultBytes) { json ->
            json.writeStartObject(); json.writeBooleanField("truncated", truncated)
            json.writeArrayFieldStart("matches")
            matches.forEach { (number, text) ->
                json.writeStartObject(); json.writeNumberField("line", number); json.writeStringField("text", text); json.writeEndObject()
            }
            json.writeEndArray(); json.writeEndObject()
        }.decodeToString()
    }

    private fun definition(name: String, description: String, extra: Map<String, JsonObject>) = ModelToolDefinition(name, description,
        buildJsonObject {
            put("type", "object"); put("additionalProperties", false)
            putJsonObject("properties") { put("root", stringSchema()); put("path", stringSchema()); extra.forEach { (key, value) -> put(key, value) } }
            putJsonArray("required") { add("root"); add("path"); extra.keys.forEach { add(it) } }
        })
    private fun stringSchema() = buildJsonObject { put("type", "string") }
}

class BuiltinCapturedExecutionEvidence(
    val loop: BuiltinLoopEvidence,
    audit: List<AcpFilesystemAuditRecord>,
    candidateChanges: List<AgentFileChange>,
    contextAudit: List<BuiltinContextToolAudit> = emptyList(),
) : AgentExecutionProviderEvidence {
    override val providerId = "builtin"
    override val schemaVersion = 1
    val filesystemAudit: List<AcpFilesystemAuditRecord> = Collections.unmodifiableList(ArrayList(audit))
    val candidateChanges: List<AgentFileChange> = Collections.unmodifiableList(ArrayList(candidateChanges))
    val contextAudit: List<BuiltinContextToolAudit> = Collections.unmodifiableList(ArrayList(contextAudit))
}

/**
 * Strict captured repair integration: source bytes enter through the existing authority, and every
 * write reaches its BoundedRepairOutput sink. The namespace anchor is never accessed on the host.
 */
class BuiltinCapturedRepairHarness(
    private val provider: ModelProvider,
    private val limits: BuiltinLoopLimits = BuiltinLoopLimits(),
) : CapturedRepairAgentHarness {
    override fun implementationIdentifier() = "builtin-captured-repair-v1"
    override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit) =
        executeReceipt(request, onEvent).requireResult()
    override fun executeReceipt(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit) = AgentExecutionReceipt(
        AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Failed(AgentFailure(AgentFailureKind.CONFIGURATION,
            "Built-in captured repair requires the shared captured staging authority")),
    )
    override fun executeCaptured(request: AgentExecutionRequest, initialFiles: Map<String, ByteArray>, output: BoundedRepairOutput,
        onEvent: (AgentExecutionEvent) -> Unit) = executeCapturedReceipt(request, initialFiles, output, onEvent).requireResult()

    override fun executeCapturedReceipt(request: AgentExecutionRequest, initialFiles: Map<String, ByteArray>, output: BoundedRepairOutput,
        onEvent: (AgentExecutionEvent) -> Unit): AgentExecutionReceipt {
        val audit = AcpFilesystemAuditRecorder(limits.maxTraceRecords)
        var openedCapture: AcpCapturedRepairFilesystem? = null
        var contextTools: BuiltinCapturedContextTools? = null
        val harness = BuiltinAgentHarness(provider, { invocation, control ->
            control.checkpoint()
            val captured = AcpCapturedRepairFilesystem(initialFiles, output)
            val fileLimits = AcpFilesystemLimits(limits.maxToolResultBytes, limits.maxToolResultBytes)
            captured.preflight(invocation, fileLimits)
            val session = captured.open(invocation, fileLimits, audit)
            openedCapture = captured
            val dispatcher = BuiltinFilesystemDispatcher(invocation, session, limits.maxToolResultBytes)
            val context = BuiltinCapturedContextTools(invocation, initialFiles.keys, limits.maxToolResultBytes, limits.maxTraceRecords)
                .also { contextTools = it }
            object : BuiltinToolSession {
                override val definitions = dispatcher.definitions + context.definitions
                override fun authorize(call: ModelToolCall, control: BuiltinExecutionControl): Boolean {
                    control.checkpoint()
                    // Filesystem path/operation authorization is delegated once to the shared callback.
                    return definitions.any { it.name == call.name }
                }
                override fun execute(call: ModelToolCall, control: BuiltinExecutionControl) =
                    if (context.definitions.any { it.name == call.name }) context.execute(call, control) else dispatcher.execute(call, control)
                override fun changes(control: BuiltinExecutionControl): List<AgentFileChange> {
                    control.checkpoint(); session.close(); return captured.changes()
                }
                override fun close() = session.close()
            }
        }, limits)
        val receipt = harness.executeReceipt(request, onEvent)
        val changes = openedCapture?.changes() ?: emptyList()
        // Interrupted or refused turns can still have staged edits. Retain them without accepting them.
        val outcome = when (val terminal = receipt.outcome) {
            is AgentExecutionOutcome.Failed -> terminal
            is AgentExecutionOutcome.Returned -> terminal.result.let { original -> AgentExecutionOutcome.Returned(
                AgentExecutionResult(original.stopReason, original.summary, changes, original.session, original.usage),
            ) }
        }
        return AgentExecutionReceipt(receipt.requestBinding, outcome,
            BuiltinCapturedExecutionEvidence(receipt.providerEvidence as BuiltinLoopEvidence, audit.snapshot(), changes, contextTools?.audit().orEmpty()))
    }
}
