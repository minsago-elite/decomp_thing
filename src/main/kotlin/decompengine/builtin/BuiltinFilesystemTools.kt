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
    restorationAudit: List<AcpFilesystemAuditRecord> = emptyList(),
    val workflowIdentity: AgentWorkflowIdentity? = null,
    val journalIdentity: BuiltinJournalIdentity? = null,
    internal val invocationArchive: BuiltinInvocationArchiveDocument? = null,
    val factoryProvenance: BuiltinHarnessProvenance? = null,
) : AgentExecutionProviderEvidence {
    override val providerId = "builtin"
    override val schemaVersion = 1
    val filesystemAudit: List<AcpFilesystemAuditRecord> = Collections.unmodifiableList(ArrayList(audit))
    val candidateChanges: List<AgentFileChange> = Collections.unmodifiableList(ArrayList(candidateChanges))
    val contextAudit: List<BuiltinContextToolAudit> = Collections.unmodifiableList(ArrayList(contextAudit))
    val restorationAudit: List<AcpFilesystemAuditRecord> = Collections.unmodifiableList(ArrayList(restorationAudit))
}

/**
 * Strict captured repair integration: source bytes enter through the existing authority, and every
 * write reaches its BoundedRepairOutput sink. The namespace anchor is never accessed on the host.
 */
class BuiltinCapturedRepairHarness(
    private val provider: ModelProvider,
    private val limits: BuiltinLoopLimits = BuiltinLoopLimits(),
    private val journalConfiguration: BuiltinJournalConfiguration? = null,
    private val checkpointConfiguration: BuiltinCheckpointConfiguration? = null,
    private val resume: BuiltinCapturedResume? = null,
    secrets: Collection<String> = emptyList(),
    private val sourceStoreConfiguration: BuiltinSourceStoreConfiguration? = null,
    private val journalFactory: BuiltinRepairJournalFactory? = null,
) : CapturedRepairAgentHarness {
    private val secrets = secrets.toList()
    private var configuredFactoryProvenance: BuiltinHarnessProvenance? = null
    private var invoked = false

    @Synchronized
    internal fun bindFactoryProvenance(provenance: BuiltinHarnessProvenance): BuiltinCapturedRepairHarness {
        check(!invoked && configuredFactoryProvenance == null)
        require(provenance.implementationId == implementationIdentifier() && journalFactory?.factoryProvenance == provenance)
        configuredFactoryProvenance = provenance
        return this
    }
    @Synchronized
    private fun invocationProvenance(): BuiltinHarnessProvenance? {
        invoked = true
        return configuredFactoryProvenance
    }
    init {
        require(checkpointConfiguration == null || journalConfiguration != null)
        require(resume == null || checkpointConfiguration != null)
        require(sourceStoreConfiguration == null || checkpointConfiguration != null)
        require(journalFactory == null || (journalConfiguration == null && checkpointConfiguration == null && resume == null)) {
            "per-attempt journal provisioning cannot use a caller-owned journal or checkpoint"
        }
    }
    override fun implementationIdentifier() = "builtin-captured-repair-v1"
    override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit) =
        executeReceipt(request, onEvent).requireResult()
    override fun executeReceipt(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit): AgentExecutionReceipt {
        invocationProvenance()
        return AgentExecutionReceipt(
        AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Failed(AgentFailure(AgentFailureKind.CONFIGURATION,
            "Built-in captured repair requires the shared captured staging authority")),
        )
    }
    override fun executeCaptured(request: AgentExecutionRequest, initialFiles: Map<String, ByteArray>, output: BoundedRepairOutput,
        onEvent: (AgentExecutionEvent) -> Unit) = executeCapturedReceipt(request, initialFiles, output, onEvent).requireResult()

    override fun executeCapturedReceipt(request: AgentExecutionRequest, initialFiles: Map<String, ByteArray>, output: BoundedRepairOutput,
        onEvent: (AgentExecutionEvent) -> Unit): AgentExecutionReceipt {
        val factoryProvenance = invocationProvenance()
        val journalConfiguration = try {
            (journalFactory?.create(request, initialFiles, limits.maximumEvidenceBytes) ?: this.journalConfiguration).also { journal ->
                require(journal?.identity?.factoryProvenance == factoryProvenance)
                if (journal != null && request.workflowIdentity != null) {
                    require(request.workflowIdentity.workflow == AgentWorkflow.REPAIR)
                    require(journal.identity.acceptedRevisionSha256 == request.workflowIdentity.acceptedRevisionSha256)
                    require(journal.identity.stageSha256 == builtinCapturedStageSha256(request, journal.identity.sourceSha256))
                }
            }
        } catch (_: Exception) {
            return AgentExecutionReceipt(AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Failed(
                AgentFailure(AgentFailureKind.INVALID_REQUEST, "Built-in repair journal lineage is invalid")))
        }
        val audit = AcpFilesystemAuditRecorder(limits.maxTraceRecords)
        var openedCapture: AcpCapturedRepairFilesystem? = null
        var contextTools: BuiltinCapturedContextTools? = null
        var restorationRecords = 0
        val harness = BuiltinAgentHarness(provider, { invocation, control ->
            control.checkpoint()
            fun snapshot(files: Map<String, ByteArray>) = BuiltinWorkspaceSnapshot.capture(
                files.mapKeys { AgentWorkspacePath(invocation.workspaceRoots.single().id, it.key) }, limits.maximumEvidenceBytes)
            fun sourceStore(): BuiltinSourceStore = BuiltinSourceStore(checkNotNull(sourceStoreConfiguration), invocation,
                setOf(checkNotNull(journalConfiguration).path.parent, checkNotNull(checkpointConfiguration).directory), secrets)
            // The authority's initial files remain the accepted baseline even when candidates are rehydrated.
            if (journalConfiguration != null) check(snapshot(initialFiles).sha256 == journalConfiguration.identity.sourceSha256)
            val captured = AcpCapturedRepairFilesystem(initialFiles, output)
            val fileLimits = AcpFilesystemLimits(limits.maxToolResultBytes, limits.maxToolResultBytes)
            captured.preflight(invocation, fileLimits)
            val context = BuiltinCapturedContextTools(invocation, initialFiles.keys, limits.maxToolResultBytes, limits.maxTraceRecords)
                .also { contextTools = it }
            val session = captured.open(invocation, fileLimits, audit)
            openedCapture = captured
            val dispatcher = BuiltinFilesystemDispatcher(invocation, session, limits.maxToolResultBytes)
            object : BuiltinToolSession {
                override val definitions = dispatcher.definitions + context.definitions
                override val supportsContextRetrieval = true
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
                override fun finalChanges() = captured.changes()
                override fun finalToolAudit(): JsonObject {
                    val records = audit.snapshot()
                    return builtinCapturedAuditJson(records.drop(restorationRecords), records.take(restorationRecords), context.audit())
                }
                override fun checkpointToolAudit(control: BuiltinExecutionControl): JsonObject {
                    control.checkpoint(); return finalToolAudit()
                }
                override fun checkpointSnapshot(control: BuiltinExecutionControl): BuiltinWorkspaceSnapshot {
                    control.checkpoint(); return snapshot(captured.snapshot())
                }
                override fun checkpointAuthoritySha256(control: BuiltinExecutionControl): String {
                    control.checkpoint()
                    return checkpointHash(boundedProviderJson(limits.maxContextBytes) { out ->
                        out.writeStartObject(); out.writeStringField("repairBudget", output.resourceBudget.toString())
                        out.writeArrayFieldStart("replacementPaths")
                        output.allowedReplacementPaths().sorted().forEach(out::writeString)
                        out.writeEndArray()
                        sourceStoreConfiguration?.let { out.writeStringField("sourceStoreLimits", it.limitBinding()) }
                        out.writeEndObject()
                    })
                }
                override fun persistCheckpointSource(snapshot: BuiltinWorkspaceSnapshot, control: BuiltinExecutionControl) {
                    if (sourceStoreConfiguration != null) sourceStore().save(captured.snapshot().mapKeys {
                        AgentWorkspacePath(invocation.workspaceRoots.single().id, it.key)
                    }, snapshot.sha256, control)
                }
                override fun restoreCheckpointStage(expectedSourceSha256: String, control: BuiltinExecutionControl) {
                    control.checkpoint()
                    val restored = checkNotNull(resume).files() ?: sourceStore().load(expectedSourceSha256, control).let { files ->
                        check(files.keys.all { it.rootId == invocation.workspaceRoots.single().id })
                        files.mapKeys { it.key.relativePath }
                    }
                    check(restored.keys == initialFiles.keys)
                    check(snapshot(restored).sha256 == expectedSourceSha256)
                    val changed = restored.keys.filter { !restored.getValue(it).contentEquals(initialFiles.getValue(it)) }
                    val budget = output.resourceBudget
                    check(changed.size <= budget.maximumPatchFiles)
                    check(changed.sumOf { restored.getValue(it).size.toLong() } <= budget.maximumPatchBytes)
                    check(restored.values.sumOf { it.size.toLong() } <= budget.maximumStagingBytes)
                    val text = restored.mapValues { (path, bytes) ->
                        control.checkpoint()
                        check(bytes.size <= limits.maxToolResultBytes)
                        if (path in changed) {
                            check(bytes.size <= budget.maximumSourceFileBytes)
                            check(invocation.accessPolicy.allows(
                                AgentWorkspacePath(invocation.workspaceRoots.single().id, path), AgentOperation.WRITE_FILE))
                        }
                        bytes.decodeToString(throwOnInvalidSequence = true)
                    }
                    // Shrink first so a valid final stage cannot exceed the original staging quota mid-restore.
                    try {
                        changed.sortedWith(compareBy<String> { restored.getValue(it).size.toLong() - initialFiles.getValue(it).size }
                            .thenBy { it }).forEachIndexed { index, path ->
                            val result = dispatcher.execute(ModelToolCall("builtin_restore_$index", "write_text", buildJsonObject {
                                put("root", invocation.workspaceRoots.single().id); put("path", path); put("content", text.getValue(path))
                            }), control)
                            check(!result.failed)
                        }
                    } finally {
                        restorationRecords = audit.snapshot().size
                    }
                }
                override fun close() = session.close()
            }
        }, limits, secrets, journalConfiguration, checkpointConfiguration)
        val receipt = if (resume == null) harness.executeReceipt(request, onEvent)
            else harness.resumeReceipt(request, resume.checkpoint, onEvent)
        val changes = openedCapture?.changes() ?: emptyList()
        // Interrupted or refused turns can still have staged edits. Retain them without accepting them.
        val outcome = when (val terminal = receipt.outcome) {
            is AgentExecutionOutcome.Failed -> terminal
            is AgentExecutionOutcome.Returned -> terminal.result.let { original -> AgentExecutionOutcome.Returned(
                AgentExecutionResult(original.stopReason, original.summary, changes, original.session, original.usage),
            ) }
        }
        val records = audit.snapshot()
        val capturedReceipt = AgentExecutionReceipt(receipt.requestBinding, outcome,
            BuiltinCapturedExecutionEvidence(receipt.providerEvidence as BuiltinLoopEvidence, records.drop(restorationRecords), changes,
                contextTools?.audit().orEmpty(), records.take(restorationRecords), request.workflowIdentity, journalConfiguration?.identity,
                factoryProvenance = factoryProvenance))
        val evidence = capturedReceipt.providerEvidence as BuiltinCapturedExecutionEvidence
        val workflow = request.workflowIdentity
        if (workflow == null || journalConfiguration == null || evidence.loop.journal?.complete != true) return capturedReceipt
        return try {
            val identity = BuiltinInvocationArchiveIdentity("repair", workflow.taskId, workflow.promptSha256,
                capturedReceipt.requestBinding, journalConfiguration.identity)
            val archive = BuiltinInvocationArchiveDocument.capture(identity, request, capturedReceipt, journalConfiguration)
            AgentExecutionReceipt(capturedReceipt.requestBinding, outcome, BuiltinCapturedExecutionEvidence(evidence.loop,
                evidence.filesystemAudit, changes, evidence.contextAudit, evidence.restorationAudit, workflow,
                journalConfiguration.identity, archive, factoryProvenance))
        } catch (_: Exception) {
            AgentExecutionReceipt(capturedReceipt.requestBinding, AgentExecutionOutcome.Failed(AgentFailure(
                AgentFailureKind.INTERNAL, "Built-in invocation archive capture failed")), evidence)
        }
    }
}
