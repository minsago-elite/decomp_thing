package decompengine.builtin

import com.agentclientprotocol.model.*
import com.agentclientprotocol.protocol.AcpExpectedError
import decompengine.acp.*
import decompengine.agent.AgentExecutionRequest
import decompengine.builtin.provider.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import java.util.Collections

enum class BuiltinProcessPurpose { BUILD, TEST, BEHAVIOR }

/** The profile supplies exact immutable command authority; provider arguments contain only an operation ID. */
class BuiltinProcessOperation(
    val id: String,
    val purpose: BuiltinProcessPurpose,
    val description: String,
    val rule: AcpTerminalCommandRule,
) {
    init {
        require(id.matches(Regex("[a-z][a-z0-9_-]{0,63}"))) { "Invalid built-in operation id" }
        require(description.length in 1..4096) { "Invalid built-in operation description" }
    }
    override fun toString() = "BuiltinProcessOperation(id=$id, purpose=$purpose, command=redacted)"
}

/** All process creation, policy decisions and cleanup are owned by the existing verified ACP boundary. */
internal class BuiltinTerminalDispatcher private constructor(
    private val boundary: LinuxBubblewrapBoundary,
    private val broker: AcpTerminalBroker,
    private val audit: AcpTerminalAuditRecorder,
    private val policy: AcpTerminalExecutionPolicy,
    operations: List<BuiltinProcessOperation>,
    private val maximumResultBytes: Int,
) : AutoCloseable {
    private val operations = operations.associateBy { it.id }
    private var closed = false
    val definitions = listOf(ModelToolDefinition("run_process", "Run a profile-approved operation:\n" +
        operations.sortedBy { it.id }.joinToString("\n") { "${it.id} (${it.purpose.name.lowercase()}): ${it.description}" }, buildJsonObject {
        put("type", "object"); put("additionalProperties", false)
        putJsonObject("properties") {
            putJsonObject("operation") { put("type", "string"); putJsonArray("enum") { operations.sortedBy { it.id }.forEach { add(it.id) } } }
        }
        putJsonArray("required") { add("operation") }
    }))

    fun execute(call: ModelToolCall, control: BuiltinExecutionControl): BuiltinToolResult {
        check(!closed) { "Built-in process session is closed" }
        control.checkpoint()
        if (call.name != "run_process" || call.arguments.keys != setOf("operation"))
            return BuiltinToolResult("unregistered process operation", failed = true)
        val id = (call.arguments["operation"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        val operation = operations[id] ?: return BuiltinToolResult("unregistered process operation", failed = true)
        val rule = operation.rule
        return try {
            runBlocking {
                val terminal = broker.create(SESSION, rule.command, rule.arguments, rule.workingDirectory.toString(),
                    rule.environment.map { (name, value) -> EnvVariable(name, value) }, null).terminalId
                try {
                    broker.observeToolCall(SESSION, SessionUpdate.ToolCallUpdate(
                        toolCallId = ToolCallId(call.id), title = "Run approved operation", kind = ToolKind.EXECUTE,
                        status = ToolCallStatus.IN_PROGRESS, content = listOf(ToolCallContent.Terminal(terminal)),
                    ))
                    val exit = broker.waitForExit(SESSION, terminal)
                    val output = broker.output(SESSION, terminal)
                    control.checkpoint()
                    // Nonzero compile/test exits are feedback. Truncated results never claim a passing check.
                    val bytes = boundedProviderJson(maximumResultBytes) { json ->
                        json.writeStartObject()
                        json.writeStringField("operation", operation.id)
                        json.writeStringField("purpose", operation.purpose.name.lowercase())
                        json.writeBooleanField("passed", exit.exitCode == 0u && exit.signal == null && !output.truncated)
                        json.writeFieldName("exitCode"); exit.exitCode?.let { json.writeNumber(it.toLong()) } ?: json.writeNull()
                        json.writeFieldName("signal"); exit.signal?.let { json.writeString(it) } ?: json.writeNull()
                        json.writeBooleanField("truncated", output.truncated)
                        json.writeStringField("output", output.output)
                        json.writeEndObject()
                    }
                    BuiltinToolResult(bytes.decodeToString())
                } finally {
                    // Release performs the same bounded termination/reclamation used by ACP callbacks.
                    broker.release(SESSION, terminal)
                }
            }
        } catch (_: AcpExpectedError) {
            control.checkpoint()
            BuiltinToolResult("shared terminal authority denied or failed this operation", failed = true)
        }
    }

    fun audit(): List<AcpTerminalAuditRecord> = audit.snapshot()
    fun sandboxEvidence(): AcpSandboxEvidence = boundary.evidence(policy, audit.snapshot())
    fun finish() { broker.finishSession(SESSION); broker.throwIfFailed() }

    override fun close() {
        if (closed) return
        // A failed cleanup must remain retryable; never mark an unproved boundary closed.
        try { broker.close() } finally { boundary.close() }
        closed = true
    }

    companion object {
        private const val SESSION = "builtin-process-session"

        fun open(
            request: AgentExecutionRequest,
            control: BuiltinExecutionControl,
            configuration: AcpLinuxSandboxConfiguration,
            policy: AcpTerminalExecutionPolicy,
            operations: List<BuiltinProcessOperation>,
            providerEnvironment: Map<String, AcpEnvironmentValue>,
            maximumResultBytes: Int,
            maximumAuditRecords: Int = 4096,
        ): BuiltinTerminalDispatcher {
            require(operations.isNotEmpty() && operations.size <= 128 && operations.map { it.id }.distinct().size == operations.size)
            require(operations.all { operation -> policy.commandRules.any { it === operation.rule } }) {
                "Built-in operation is not bound to an exact policy rule"
            }
            require(maximumResultBytes in 1024..32 * 1024 * 1024 && maximumAuditRecords in 1..100_000)
            control.checkpoint()
            val audit = AcpTerminalAuditRecorder(networkIsolated = true, maximumRecords = maximumAuditRecords)
            val boundary = LinuxBubblewrapBoundary.prepare(configuration, cancellationCheck = control::checkpoint)
            try {
                val broker = boundary.openTerminalBroker(request, control.cancellation, policy, providerEnvironment, audit, control::checkpoint)
                try {
                    broker.bindSession(SESSION)
                    return BuiltinTerminalDispatcher(boundary, broker, audit, policy, Collections.unmodifiableList(ArrayList(operations)), maximumResultBytes)
                } catch (failure: Throwable) { broker.close(); throw failure }
            } catch (failure: Throwable) { boundary.close(); throw failure }
        }
    }
}

/** Compose file/evidence authority with process tools without giving either provider direct host APIs. */
internal class BuiltinProcessToolSession(
    private val workspace: BuiltinToolSession,
    private val terminals: BuiltinTerminalDispatcher,
) : BuiltinToolSession {
    override val definitions = Collections.unmodifiableList(workspace.definitions + terminals.definitions)
    override val supportsContextRetrieval get() = workspace.supportsContextRetrieval
    init { require(definitions.map { it.name }.distinct().size == definitions.size) { "Duplicate composed built-in tool" } }
    override fun authorize(call: ModelToolCall, control: BuiltinExecutionControl): Boolean =
        if (call.name == "run_process") { control.checkpoint(); true } else workspace.authorize(call, control)
    override fun execute(call: ModelToolCall, control: BuiltinExecutionControl): BuiltinToolResult =
        if (call.name == "run_process") terminals.execute(call, control) else workspace.execute(call, control)
    override fun changes(control: BuiltinExecutionControl) = workspace.changes(control)
    override fun validateCompletion(control: BuiltinExecutionControl): BuiltinCompletion {
        control.checkpoint(); terminals.finish(); return workspace.validateCompletion(control)
    }
    override fun close() { try { terminals.close() } finally { workspace.close() } }
    fun terminalAudit(): List<AcpTerminalAuditRecord> = terminals.audit()
    fun sandboxEvidence(): AcpSandboxEvidence = terminals.sandboxEvidence()
}
