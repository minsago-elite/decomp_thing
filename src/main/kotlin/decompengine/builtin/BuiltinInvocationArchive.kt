package decompengine.builtin

import decompengine.agent.*
import decompengine.acp.AcpFilesystemAuditRecord
import decompengine.acp.AcpFilesystemAuditOutcome
import decompengine.acp.AcpFilesystemAuditReason
import decompengine.builtin.provider.boundedProviderJson
import decompengine.builtin.provider.parseProviderObject
import decompengine.builtin.provider.writeProviderValue
import decompengine.project.agentFileChangeSetSha256
import kotlinx.serialization.json.*

/** Path commitments allow comparison with workflow-owned changes without exporting sensitive names. */
internal fun builtinChangeJson(changes: List<AgentFileChange>): JsonArray {
    check(changes.size <= 100_000)
    return JsonArray(changes.map { change -> buildJsonObject {
        fun path(name: String, value: String) = putJsonObject(name) {
            val bytes = receiptCommitmentBytes(value)
            put("sha256", checkpointHash(bytes)); put("bytes", bytes.size)
        }
        path("root", change.path.rootId); path("path", change.path.relativePath)
        put("kind", change.kind.name); put("beforeSha256", change.beforeSha256); put("afterSha256", change.afterSha256)
        put("bytes", change.sizeBytes)
    } })
}

internal fun builtinCapturedAuditJson(filesystem: List<AcpFilesystemAuditRecord>, restoration: List<AcpFilesystemAuditRecord>,
    context: List<BuiltinContextToolAudit>) = buildJsonObject {
    fun text(value: String) = JsonPrimitive(checkpointHash(receiptCommitmentBytes(value)))
    fun records(values: List<AcpFilesystemAuditRecord>) = JsonArray(values.map { record -> buildJsonObject {
        put("sequence", record.sequence); put("callIdSha256", text(record.sessionId)); put("methodSha256", text(record.method))
        put("requestedPathSha256", record.requestedPathSha256)
        put("policyPath", record.policyPath?.let { path -> buildJsonObject {
            put("rootSha256", text(path.rootId)); put("pathSha256", text(path.relativePath))
        } } ?: JsonNull)
        put("outcome", record.outcome.name); put("reason", record.reason.name)
    } })
    put("filesystem", records(filesystem)); put("restoration", records(restoration))
    put("context", JsonArray(context.map { record -> buildJsonObject {
        put("callIdSha256", text(record.callId)); put("toolSha256", text(record.tool))
        put("resultSha256", record.resultSha256); put("failed", record.failed)
    } }))
}

internal class BuiltinInvocationArchiveIdentity(
    val workflow: String,
    val taskId: String,
    val promptSha256: String,
    val binding: AgentExecutionRequestBinding,
    val journal: BuiltinJournalIdentity,
) {
    init {
        require(workflow in setOf("repair", "reconstruction"))
        require(taskId.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")))
        require(promptSha256.matches(Regex("[a-f0-9]{64}")))
        require(journal.factoryProvenance == null || workflow == "repair") { "configured captured factory requires repair workflow" }
    }
    fun json() = buildJsonObject {
        put("workflow", workflow); put("taskId", taskId); put("promptSha256", promptSha256)
        put("invocation", BuiltinJournal.identity(journal, binding))
    }
    override fun toString() = "BuiltinInvocationArchiveIdentity(redacted)"
}

internal class BuiltinInvocationArchiveLimits(
    val maximumBytes: Int = 64 * 1024 * 1024,
    val maximumJournalBytes: Long = 64L * 1024 * 1024,
    val maximumRecordBytes: Int = 8 * 1024 * 1024,
    val maximumRecords: Int = 10_000,
) {
    init {
        require(maximumBytes in 1024..128 * 1024 * 1024 && maximumJournalBytes in 1024..128L * 1024 * 1024)
        require(maximumRecordBytes in 512..32 * 1024 * 1024 && maximumRecords in 2..100_000)
    }
}

/** A portable immutable invocation artifact. Workflow acceptance is deliberately a different artifact. */
class BuiltinInvocationArchiveDocument private constructor(raw: ByteArray, internal val verified: VerifiedBuiltinInvocationArchive,
    val reference: BuiltinInvocationArchiveReference) {
    private val raw = raw.copyOf()
    val bytes get() = raw.copyOf()
    val sha256 = checkpointHash(raw)
    val schemaVersion = 1

    companion object {
        internal fun capture(identity: BuiltinInvocationArchiveIdentity, request: AgentExecutionRequest, receipt: AgentExecutionReceipt,
            configuration: BuiltinJournalConfiguration, limits: BuiltinInvocationArchiveLimits = BuiltinInvocationArchiveLimits()): BuiltinInvocationArchiveDocument = guarded {
            check(identity.binding == receipt.requestBinding && identity.binding == AgentExecutionRequestBinding.capture(request))
            check(BuiltinJournal.identity(configuration.identity, identity.binding) == BuiltinJournal.identity(identity.journal, identity.binding))
            request.workflowIdentity?.let { workflow ->
                check(identity.workflow == workflow.workflow.name.lowercase() && identity.taskId == workflow.taskId)
                check(identity.promptSha256 == workflow.promptSha256 && identity.journal.acceptedRevisionSha256 == workflow.acceptedRevisionSha256 &&
                    identity.journal.inputRevisionSha256 == workflow.inputRevisionSha256)
                check(identity.journal.stageSha256 == builtinCapturedStageSha256(request, identity.journal.sourceSha256))
            }
            val provider = receipt.providerEvidence
            if (identity.journal.factoryProvenance != null) check(provider is BuiltinCapturedExecutionEvidence)
            if (provider is BuiltinCapturedExecutionEvidence) check(provider.factoryProvenance == identity.journal.factoryProvenance)
            if (provider is BuiltinCapturedExecutionEvidence && request.workflowIdentity != null) {
                check(provider.workflowIdentity == request.workflowIdentity)
                check(BuiltinJournal.identity(checkNotNull(provider.journalIdentity), identity.binding) ==
                    BuiltinJournal.identity(identity.journal, identity.binding))
            }
            val loop = when (provider) {
                is BuiltinLoopEvidence -> provider
                is BuiltinCapturedExecutionEvidence -> provider.loop
                else -> error("Unsupported provider evidence")
            }
            val evidence = checkNotNull(loop.journal)
            val journal = BuiltinJournal.inspect(configuration, identity.binding, evidence.commitment)
            check(journal.complete == evidence.complete && journal.indeterminate == evidence.indeterminate)
            check(journal.complete) // Suspended checkpoints remain private recovery evidence, not terminal invocation artifacts.
            val returned = (receipt.outcome as? AgentExecutionOutcome.Returned)?.result
            val candidates = (provider as? BuiltinCapturedExecutionEvidence)?.candidateChanges ?: returned?.changes.orEmpty()
            if (returned != null) check(builtinChangeJson(returned.changes) == builtinChangeJson(candidates))
            val outcome = when (val value = receipt.outcome) {
                is AgentExecutionOutcome.Returned -> "returned-${value.result.stopReason.name}"
                is AgentExecutionOutcome.Failed -> "failed-${value.failure.kind.name}"
            }
            val json = buildJsonObject {
                put("schemaVersion", 1); put("kind", "builtin-invocation-archive")
                put("identity", identity.json()); put("releaseQualified", false)
                putJsonObject("receipt") {
                    put("outcome", outcome); put("stop", loop.stop.name); put("cleanupComplete", loop.cleanupComplete)
                    put("modelCalls", loop.modelCalls); put("toolCalls", loop.toolCalls)
                    put("inputTokens", loop.inputTokens); put("outputTokens", loop.outputTokens); put("estimated", loop.estimatedUsage)
                    put("candidateChanges", builtinChangeJson(candidates))
                    put("toolAudit", (provider as? BuiltinCapturedExecutionEvidence)?.let {
                        builtinCapturedAuditJson(it.filesystemAudit, it.restorationAudit, it.contextAudit)
                    } ?: JsonNull)
                    put("resultChangesSha256", agentFileChangeSetSha256(returned?.changes.orEmpty()))
                    put("journalComplete", evidence.complete); put("indeterminate", evidence.indeterminate)
                }
                putJsonObject("commitment") {
                    put("records", evidence.commitment.records); put("bytes", evidence.commitment.bytes); put("headSha256", evidence.commitment.headSha256)
                }
                put("records", JsonArray(journal.records))
            }
            val bytes = boundedProviderJson(limits.maximumBytes) { it.writeProviderValue(json) }
            BuiltinInvocationArchiveDocument(bytes, verifyBuiltinInvocationArchive(bytes, identity, evidence.commitment, limits),
                BuiltinInvocationArchiveReference(identity, evidence.commitment))
        }
    }
}

/** Detached graph-owned expectations for an invocation artifact; contains no runtime paths or source text. */
class BuiltinInvocationArchiveReference internal constructor(
    internal val identity: BuiltinInvocationArchiveIdentity,
    val commitment: BuiltinJournalCommitment,
) {
    init {
        require(commitment.records in 2..100_000 && commitment.bytes in 1..128L * 1024 * 1024)
        require(commitment.headSha256.matches(Regex("[a-f0-9]{64}")))
    }
    internal fun json() = buildJsonObject {
        put("identity", identity.json())
        putJsonObject("commitment") {
            put("records", commitment.records); put("bytes", commitment.bytes); put("headSha256", commitment.headSha256)
        }
    }
    internal fun requireWorkflow(expected: AgentWorkflowIdentity) {
        require(identity.workflow == expected.workflow.name.lowercase() && identity.taskId == expected.taskId &&
            identity.promptSha256 == expected.promptSha256 && identity.journal.acceptedRevisionSha256 == expected.acceptedRevisionSha256 &&
            identity.journal.inputRevisionSha256 == expected.inputRevisionSha256) {
            "built-in invocation reference differs from its workflow lineage"
        }
    }
    override fun equals(other: Any?) = other is BuiltinInvocationArchiveReference && json() == other.json()
    override fun hashCode() = json().hashCode()
    override fun toString() = "BuiltinInvocationArchiveReference(redacted)"
}

internal fun parseBuiltinInvocationArchiveReference(value: JsonElement): BuiltinInvocationArchiveReference {
    val root = value.jsonObject
    val identity = root.getValue("identity").jsonObject
    val invocation = identity.getValue("invocation").jsonObject
    fun JsonObject.text(name: String) = getValue(name).jsonPrimitive.content
    val commitment = root.getValue("commitment").jsonObject
    val reference = BuiltinInvocationArchiveReference(BuiltinInvocationArchiveIdentity(
        identity.text("workflow"), identity.text("taskId"), identity.text("promptSha256"),
        AgentExecutionRequestBinding(invocation.getValue("contractVersion").jsonPrimitive.int,
            invocation.text("requestSha256"), invocation.text("accessPolicySha256")),
        BuiltinJournalIdentity(invocation.text("provider"), invocation.text("model"), invocation.text("sourceSha256"),
            invocation.text("stageSha256"), invocation.text("acceptedRevisionSha256"),
            invocation["factoryProvenance"]?.let(::parseBuiltinHarnessProvenance),
            invocation["inputRevisionSha256"]?.jsonPrimitive?.content)),
        BuiltinJournalCommitment(commitment.getValue("records").jsonPrimitive.int, commitment.getValue("bytes").jsonPrimitive.long,
            commitment.text("headSha256")))
    require(reference.json() == root) { "built-in invocation reference has invalid or extra fields" }
    return reference
}

/** Only for a workflow-owned immutable orphan file, before its graph binding was published. */
internal fun recoverBuiltinInvocationArchiveReference(bytes: ByteArray, expected: AgentWorkflowIdentity): BuiltinInvocationArchiveReference {
    val maximumBytes = BuiltinInvocationArchiveLimits().maximumBytes
    require(bytes.size <= maximumBytes)
    val root = parseProviderObject(bytes.decodeToString(throwOnInvalidSequence = true), maximumBytes)
    val reference = parseBuiltinInvocationArchiveReference(buildJsonObject {
        put("identity", root.getValue("identity")); put("commitment", root.getValue("commitment"))
    })
    reference.requireWorkflow(expected)
    verifyBuiltinInvocationArchive(bytes, reference.identity, reference.commitment)
    return reference
}

internal class VerifiedBuiltinInvocationArchive(
    val requestSha256: String,
    val promptSha256: String,
    val resultChangesSha256: String,
    val terminalOutcome: String,
    val candidateEvidenceComplete: Boolean,
    val indeterminate: Boolean,
    val candidateChanges: JsonArray,
    val journalCommitment: BuiltinJournalCommitment,
) {
    /** Factory provenance, workflow validation and acceptance are not proven by this artifact. */
    val releaseComplete = false
    override fun toString() = "VerifiedBuiltinInvocationArchive(candidateEvidenceComplete=$candidateEvidenceComplete, releaseComplete=false)"
}

/** Pure verification requires independently supplied workflow identities and the committed journal head. */
internal fun verifyBuiltinInvocationArchive(bytes: ByteArray, identity: BuiltinInvocationArchiveIdentity,
    expectedCommitment: BuiltinJournalCommitment, limits: BuiltinInvocationArchiveLimits = BuiltinInvocationArchiveLimits()): VerifiedBuiltinInvocationArchive = guarded {
    check(bytes.size <= limits.maximumBytes)
    val root = parseProviderObject(bytes.decodeToString(throwOnInvalidSequence = true), limits.maximumBytes)
    check(root.keys == setOf("schemaVersion", "kind", "identity", "releaseQualified", "receipt", "commitment", "records"))
    check(root["schemaVersion"] == JsonPrimitive(1) && root["kind"] == JsonPrimitive("builtin-invocation-archive"))
    check(root["identity"] == identity.json() && root["releaseQualified"] == JsonPrimitive(false))
    val committed = root.getValue("commitment").jsonObject
    check(committed.keys == setOf("records", "bytes", "headSha256"))
    val commitment = BuiltinJournalCommitment(committed.getValue("records").jsonPrimitive.int,
        committed.getValue("bytes").jsonPrimitive.long, committed.getValue("headSha256").jsonPrimitive.content)
    check(commitment == expectedCommitment)
    val inspection = BuiltinJournal.inspectRecords(root.getValue("records").jsonArray,
        BuiltinJournal.identity(identity.journal, identity.binding), commitment, limits.maximumRecordBytes, limits.maximumJournalBytes, limits.maximumRecords)
    check(inspection.complete)
    inspection.records.filter { it["kind"] == JsonPrimitive(BuiltinJournalKind.CHECKPOINT.name) }.forEach { record ->
        record.getValue("payload").jsonObject["resumeState"]?.jsonObject?.get("toolAudit")?.let {
            verifyBuiltinArchiveAudit(it, limits.maximumRecords)
        }
    }
    val receipt = root.getValue("receipt").jsonObject
    check(identity.journal.factoryProvenance == null || receipt["toolAudit"] is JsonObject)
    check(receipt.keys == setOf("outcome", "stop", "cleanupComplete", "modelCalls", "toolCalls", "inputTokens", "outputTokens",
        "estimated", "candidateChanges", "toolAudit", "resultChangesSha256", "journalComplete", "indeterminate"))
    val stop = BuiltinStop.valueOf(receipt.getValue("stop").jsonPrimitive.content)
    val outcome = receipt.getValue("outcome").jsonPrimitive.content
    val expectedStop = when (stop) {
        BuiltinStop.COMPLETED, BuiltinStop.VALIDATION_REQUIRED -> AgentStopReason.COMPLETED
        BuiltinStop.NO_CHANGE -> AgentStopReason.NO_CHANGES
        BuiltinStop.CANCELLED, BuiltinStop.SUSPENDED -> AgentStopReason.CANCELLED
        BuiltinStop.REFUSED -> AgentStopReason.REFUSED
        BuiltinStop.EXHAUSTED -> AgentStopReason.LIMIT_EXHAUSTED
        else -> null
    }
    if (expectedStop != null) check(outcome == "returned-${expectedStop.name}")
    else check(outcome in AgentFailureKind.entries.map { "failed-${it.name}" })
    val cleanup = receipt.getValue("cleanupComplete").jsonPrimitive.boolean
    check(receipt.getValue("journalComplete") == JsonPrimitive(inspection.complete))
    check(receipt.getValue("indeterminate") == JsonPrimitive(inspection.indeterminate))
    val changes = receipt.getValue("candidateChanges").jsonArray
    check(changes.size <= 100_000)
    val paths = mutableSetOf<Pair<JsonObject, JsonObject>>()
    changes.forEach { element ->
        val change = element.jsonObject
        check(change.keys == setOf("root", "path", "kind", "beforeSha256", "afterSha256", "bytes"))
        fun path(field: String): JsonObject = change.getValue(field).jsonObject.also {
            check(it.keys == setOf("sha256", "bytes") && it.getValue("sha256").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")))
            check(it.getValue("bytes").jsonPrimitive.long >= 0)
        }
        check(paths.add(path("root") to path("path")))
        val before = change.getValue("beforeSha256").jsonPrimitive.contentOrNull
        val after = change.getValue("afterSha256").jsonPrimitive.contentOrNull
        listOfNotNull(before, after).forEach { check(it.matches(Regex("[a-f0-9]{64}"))) }
        val size = change.getValue("bytes").jsonPrimitive.longOrNull
        check(change["bytes"] == JsonNull || (size != null && size >= 0))
        when (AgentFileChangeKind.valueOf(change.getValue("kind").jsonPrimitive.content)) {
            AgentFileChangeKind.CREATED -> check(before == null && after != null)
            AgentFileChangeKind.MODIFIED -> check(before != null && after != null && before != after)
            AgentFileChangeKind.DELETED -> check(before != null && after == null)
        }
    }
    val resultDigest = receipt.getValue("resultChangesSha256").jsonPrimitive.content
    check(resultDigest.matches(Regex("[a-f0-9]{64}")))
    val terminal = inspection.records.last().getValue("payload").jsonObject
    check(terminal["stop"] == JsonPrimitive(stop.name) && terminal["cleanupComplete"] == JsonPrimitive(cleanup))
    check(terminal["state"] == JsonPrimitive(BuiltinLoopState.TERMINATED.name))
    check(terminal["candidateChanges"] == changes)
    check(terminal["toolAudit"] == receipt["toolAudit"])
    verifyBuiltinArchiveAudit(receipt.getValue("toolAudit"), limits.maximumRecords)
    check(terminal["resultChangesSha256"] == JsonPrimitive(resultDigest))
    val usage = terminal.getValue("usage").jsonObject
    listOf("modelCalls", "toolCalls", "inputTokens", "outputTokens").forEach { key ->
        check(receipt.getValue(key).jsonPrimitive.long >= 0 && receipt[key] == usage[key])
    }
    check(receipt.getValue("estimated").jsonPrimitive.boolean == usage.getValue("estimated").jsonPrimitive.boolean)
    if (outcome.startsWith("failed-")) check(resultDigest == agentFileChangeSetSha256(emptyList()))
    val candidateComplete = inspection.complete && !inspection.indeterminate && cleanup && expectedStop == AgentStopReason.COMPLETED
    verifyBuiltinArchiveActions(inspection.records, receipt, candidateComplete)
    VerifiedBuiltinInvocationArchive(identity.binding.requestSha256, identity.promptSha256, resultDigest, outcome,
        candidateComplete,
        inspection.indeterminate, changes, commitment)
}

/** Rebuild action correlation and successful-invocation accounting without trusting receipt claims. */
private fun verifyBuiltinArchiveActions(records: List<JsonObject>, receipt: JsonObject, candidateComplete: Boolean) {
    var definitions = emptyMap<String, JsonObject>()
    var proposals = emptyList<JsonObject>()
    var policy: JsonObject? = null
    var activeTool: JsonObject? = null
    val executed = mutableSetOf<String>()
    var modelCalls = 0L
    var policyCalls = 0L
    var attempts = 0
    var inputTokens = 0L
    var outputTokens = 0L
    var finish: String? = null
    var validation: String? = null
    records.forEach { record ->
        val value = record.getValue("payload").jsonObject
        when (BuiltinJournalKind.valueOf(record.getValue("kind").jsonPrimitive.content)) {
            BuiltinJournalKind.MODEL_REQUEST -> {
                modelCalls++; attempts = 1
                val tools = value.getValue("context").jsonObject.getValue("tools").jsonArray.map { it.jsonObject }
                check(tools.map { it.getValue("name").jsonPrimitive.content }.distinct().size == tools.size)
                definitions = tools.associate { it.getValue("name").jsonPrimitive.content to it.getValue("parameters").jsonObject }
                proposals = emptyList(); policy = null
            }
            BuiltinJournalKind.MODEL_RETRY -> { modelCalls++; attempts++ }
            BuiltinJournalKind.MODEL_RESPONSE -> {
                if (candidateComplete) check(value.getValue("attempts") == JsonPrimitive(attempts))
                proposals = value.getValue("calls").jsonArray.map { it.jsonObject }
                val usage = value.getValue("usage").jsonObject
                val input = usage.getValue("inputTokens").jsonPrimitive.long
                val output = usage.getValue("outputTokens").jsonPrimitive.long
                check(input >= 0 && output >= 0)
                inputTokens = Math.addExact(inputTokens, input); outputTokens = Math.addExact(outputTokens, output)
                finish = value.getValue("finishReason").jsonPrimitive.content
            }
            BuiltinJournalKind.POLICY -> { policy = value; policyCalls++ }
            BuiltinJournalKind.TOOL_REQUEST -> {
                val id = value.getValue("id").jsonPrimitive.content
                val name = value.getValue("name").jsonPrimitive.content
                check(executed.add(id) && activeTool == null)
                check(proposals.count { it == value } == 1)
                val admitted = checkNotNull(policy)
                check(admitted["call"] == value && admitted["allowed"] == JsonPrimitive(true))
                validateBuiltinArchivedArguments(checkNotNull(definitions[name]), value.getValue("arguments"))
                activeTool = value; policy = null
            }
            BuiltinJournalKind.TOOL_RESULT -> {
                check(value["callId"] == checkNotNull(activeTool)["id"])
                if (candidateComplete) check(value["failed"] == JsonPrimitive(false))
                activeTool = null
            }
            BuiltinJournalKind.VALIDATION_RESULT -> validation = value.getValue("validation").jsonPrimitive.content
            else -> Unit
        }
    }
    if (candidateComplete) {
        check(receipt["modelCalls"] == JsonPrimitive(modelCalls) && receipt["toolCalls"] == JsonPrimitive(policyCalls))
        check(receipt["inputTokens"] == JsonPrimitive(inputTokens) && receipt["outputTokens"] == JsonPrimitive(outputTokens))
        check(finish == "STOP" && activeTool == null)
        check(validation == if (receipt["stop"] == JsonPrimitive(BuiltinStop.VALIDATION_REQUIRED.name)) "REQUIRED" else "VALIDATED")
    }
}

/** Interpret only the finite schema vocabulary used by built-in tools; never evaluate archive-authored regexes or references. */
private fun validateBuiltinArchivedArguments(schema: JsonObject, value: JsonElement, depth: Int = 0) {
    check(depth <= 16)
    when (schema.getValue("type").jsonPrimitive.content) {
        "object" -> {
            check(schema.keys.all { it in setOf("type", "properties", "required", "additionalProperties") })
            check(schema["additionalProperties"] == JsonPrimitive(false))
            val properties = schema.getValue("properties").jsonObject
            check(properties.size <= 1024)
            val required = schema.getValue("required").jsonArray.map { it.jsonPrimitive.content }
            check(required == required.distinct() && required.all { it in properties })
            val fields = value.jsonObject
            check(required.all { it in fields } && fields.keys.all { it in properties })
            fields.forEach { (key, child) -> validateBuiltinArchivedArguments(properties.getValue(key).jsonObject, child, depth + 1) }
        }
        "string" -> {
            check(schema.keys.all { it in setOf("type", "enum", "minLength", "maxLength") })
            val text = value.jsonPrimitive
            check(text.isString)
            val length = text.content.codePointCount(0, text.content.length)
            val minimum = schema["minLength"]?.jsonPrimitive?.int ?: 0
            val maximum = schema["maxLength"]?.jsonPrimitive?.int ?: Int.MAX_VALUE
            check(minimum >= 0 && maximum >= minimum && length in minimum..maximum)
            schema["enum"]?.jsonArray?.let { allowed -> check(allowed.size in 1..1024 && text in allowed) }
        }
        "integer" -> {
            check(schema.keys.all { it in setOf("type", "minimum", "maximum") })
            check(!value.jsonPrimitive.isString)
            val number = value.jsonPrimitive.long
            val minimum = schema["minimum"]?.jsonPrimitive?.long ?: Long.MIN_VALUE
            val maximum = schema["maximum"]?.jsonPrimitive?.long ?: Long.MAX_VALUE
            check(minimum <= maximum && number in minimum..maximum)
        }
        else -> error("Unsupported archived tool schema")
    }
}

private fun verifyBuiltinArchiveAudit(value: JsonElement, maximumRecords: Int) {
    if (value == JsonNull) return
    val audit = value.jsonObject
    check(audit.keys == setOf("filesystem", "restoration", "context"))
    fun digest(value: JsonElement) { check(value.jsonPrimitive.content.matches(Regex("[a-f0-9]{64}"))) }
    val callbacks = audit.getValue("restoration").jsonArray + audit.getValue("filesystem").jsonArray
    check(callbacks.size <= maximumRecords)
    callbacks.forEachIndexed { index, element ->
        val record = element.jsonObject
        check(record.keys == setOf("sequence", "callIdSha256", "methodSha256", "requestedPathSha256", "policyPath", "outcome", "reason"))
        check(record["sequence"] == JsonPrimitive(index))
        listOf("callIdSha256", "methodSha256", "requestedPathSha256").forEach { digest(record.getValue(it)) }
        if (record["policyPath"] != JsonNull) {
            val path = record.getValue("policyPath").jsonObject
            check(path.keys == setOf("rootSha256", "pathSha256")); path.values.forEach(::digest)
        }
        AcpFilesystemAuditOutcome.valueOf(record.getValue("outcome").jsonPrimitive.content)
        AcpFilesystemAuditReason.valueOf(record.getValue("reason").jsonPrimitive.content)
    }
    val context = audit.getValue("context").jsonArray
    check(context.size <= maximumRecords)
    context.forEach { element ->
        val record = element.jsonObject
        check(record.keys == setOf("callIdSha256", "toolSha256", "resultSha256", "failed"))
        listOf("callIdSha256", "toolSha256", "resultSha256").forEach { digest(record.getValue(it)) }
        record.getValue("failed").jsonPrimitive.boolean
    }
}
