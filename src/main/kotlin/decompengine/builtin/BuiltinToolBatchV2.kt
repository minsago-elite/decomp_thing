package decompengine.builtin

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import decompengine.builtin.provider.*
import kotlinx.serialization.json.*
import java.util.Collections

/** Bounded strict JSON for offline schema/argument controls. C still owns Responses wire parsing. */
internal fun parseToolObjectV2(text: String, maximumBytes: Long): JsonObject {
    v2Utf8Bytes(text, maximumBytes)
    v2Require(maximumBytes in 1..Int.MAX_VALUE.toLong())
    try {
        val factory = JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(32).maxDocumentLength(maximumBytes)
                .maxStringLength(maximumBytes.toInt()).maxNameLength(minOf(maximumBytes, 8192).toInt())
                .maxNumberLength(32).maxTokenCount(100_000).build()).build()
        factory.createParser(text).use { parser -> while (parser.nextToken() != null) { /* Validate before materialization. */ } }
        val parsed = Json.parseToJsonElement(text) as? JsonObject ?: v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
        fun strings(value: JsonElement) {
            when (value) {
                is JsonObject -> value.forEach { (key, child) -> v2Utf8Bytes(key, maximumBytes); strings(child) }
                is JsonArray -> value.forEach { strings(it) }
                is JsonPrimitive -> if (value.isString) v2Utf8Bytes(value.content, maximumBytes)
            }
        }
        strings(parsed)
        return parsed
    } catch (_: Exception) { v2Fail(ModelFailureKind.MALFORMED_RESPONSE) }
}
internal fun canonicalToolJsonV2(value: JsonElement): String = when (value) {
    is JsonObject -> value.entries.sortedBy { it.key }.joinToString(",", "{", "}") { JsonPrimitive(it.key).toString() + ":" + canonicalToolJsonV2(it.value) }
    is JsonArray -> value.joinToString(",", "[", "]") { canonicalToolJsonV2(it) }
    is JsonPrimitive -> if (!value.isString && value.longOrNull != null) value.long.toString() else value.toString()
}

/** Deliberately narrow schema dialect. Unsupported schemas fail at registry freeze, never allow-all. */
internal class ToolSchemaV2 private constructor(private val encoded: String) {
    fun accepts(value: JsonObject): Boolean = try { validate(Json.parseToJsonElement(encoded).jsonObject, value, 0); true } catch (_: Exception) { false }
    val commitment = v2Digest(listOf(encoded))
    companion object {
        fun compile(encoded: String): ToolSchemaV2 {
            val schema = parseToolObjectV2(encoded, 256L * 1024)
            inspect(schema, 0)
            v2Require(schema["type"] == JsonPrimitive("object"))
            return ToolSchemaV2(canonicalToolJsonV2(schema))
        }
        private fun number(schema: JsonObject, key: String, default: Long): Long {
            val v = schema[key] ?: return default
            val p = v as? JsonPrimitive ?: v2Fail()
            v2Require(!p.isString && p.content.matches(Regex("-?(0|[1-9][0-9]*)")))
            return p.longOrNull ?: v2Fail()
        }
        private fun inspect(s: JsonObject, depth: Int) {
            v2Require(depth <= 16)
            when (s["type"]) {
                JsonPrimitive("object") -> {
                    v2Require(s.keys == setOf("type", "properties", "required", "additionalProperties") && s["additionalProperties"] == JsonPrimitive(false))
                    val props = s["properties"] as? JsonObject ?: v2Fail()
                    val required = (s["required"] as? JsonArray ?: v2Fail()).map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: v2Fail() }
                    v2Require(props.size <= 1024 && required.size == required.distinct().size && required.all { it in props })
                    props.forEach { (name, child) -> v2Require(name.matches(Regex("[A-Za-z_][A-Za-z0-9_-]{0,63}"))); inspect(child as? JsonObject ?: v2Fail(), depth + 1) }
                }
                JsonPrimitive("string") -> {
                    v2Require(s.keys.all { it in setOf("type", "minLength", "maxLength", "enum") })
                    val min = number(s, "minLength", 0); val max = number(s, "maxLength", Int.MAX_VALUE.toLong())
                    v2Require(min >= 0 && max in min..Int.MAX_VALUE.toLong())
                    s["enum"]?.let { e ->
                        val values = e as? JsonArray ?: v2Fail()
                        v2Require(values.size in 1..1024 && values.distinct().size == values.size)
                        values.forEach { v -> val p = v as? JsonPrimitive ?: v2Fail(); v2Require(p.isString && p.content.codePointCount(0, p.content.length).toLong() in min..max) }
                    }
                }
                JsonPrimitive("integer") -> {
                    v2Require(s.keys.all { it in setOf("type", "minimum", "maximum") })
                    v2Require(number(s, "minimum", Long.MIN_VALUE) <= number(s, "maximum", Long.MAX_VALUE))
                }
                JsonPrimitive("boolean") -> v2Require(s.keys == setOf("type"))
                else -> v2Fail(ModelFailureKind.UNSUPPORTED_FEATURE)
            }
        }
        private fun validate(s: JsonObject, v: JsonElement, depth: Int) {
            v2Require(depth <= 16)
            when (s.getValue("type")) {
                JsonPrimitive("object") -> {
                    val obj = v as? JsonObject ?: v2Fail(); val props = s.getValue("properties").jsonObject
                    v2Require(s.getValue("required").jsonArray.all { it.jsonPrimitive.content in obj } && obj.keys.all { it in props })
                    obj.forEach { (name, child) -> validate(props.getValue(name).jsonObject, child, depth + 1) }
                }
                JsonPrimitive("string") -> {
                    val p = v as? JsonPrimitive ?: v2Fail(); v2Require(p.isString)
                    v2Require(p.content.codePointCount(0, p.content.length).toLong() in number(s, "minLength", 0)..number(s, "maxLength", Int.MAX_VALUE.toLong()))
                    s["enum"]?.let { v2Require(p in it.jsonArray) }
                }
                JsonPrimitive("integer") -> {
                    val p = v as? JsonPrimitive ?: v2Fail()
                    v2Require(!p.isString && p.content.matches(Regex("-?(0|[1-9][0-9]*)")))
                    val n = p.longOrNull ?: v2Fail(); v2Require(n in number(s, "minimum", Long.MIN_VALUE)..number(s, "maximum", Long.MAX_VALUE))
                }
                JsonPrimitive("boolean") -> v2Require(v is JsonPrimitive && !v.isString && v.booleanOrNull != null)
                else -> v2Fail(ModelFailureKind.UNSUPPORTED_FEATURE)
            }
        }
    }
}
internal class ToolDefinitionV2(val name: String, val description: String, val parametersJson: String) {
    override fun toString() = "ToolDefinitionV2(redacted)"
}
internal class FrozenToolRegistryV2 private constructor(definitions: List<ToolDefinitionV2>, schemas: Map<String, ToolSchemaV2>) {
    val definitions: List<ToolDefinitionV2> = Collections.unmodifiableList(ArrayList(definitions))
    private val schemas = Collections.unmodifiableMap(HashMap(schemas))
    val commitment = v2Digest(definitions.flatMap { listOf(it.name, it.description, schemas.getValue(it.name).commitment) })
    fun schema(name: String): ToolSchemaV2? = schemas[name]
    companion object {
        fun freeze(definitions: List<ToolDefinitionV2>, maximumBytes: Long): FrozenToolRegistryV2 {
            v2Require(definitions.size <= 1024 && definitions.map { it.name }.distinct().size == definitions.size)
            var bytes = 0L
            val schemas = definitions.associate { definition ->
                v2Require(definition.name.matches(Regex("[A-Za-z_][A-Za-z0-9_-]{0,63}")))
                bytes = v2Add(bytes, v2Add(v2Utf8Bytes(definition.description, 8192),
                    v2Add(v2Utf8Bytes(definition.parametersJson, 256L * 1024), definition.name.length.toLong())))
                v2Capacity(bytes <= maximumBytes)
                definition.name to ToolSchemaV2.compile(definition.parametersJson)
            }
            return FrozenToolRegistryV2(definitions, schemas)
        }
    }
}
internal class ToolProposalV2 internal constructor(
    val namespace: String?, val name: String, val callId: String, val outputItemId: String,
    val argumentsJson: String, val caller: String? = null, val asynchronous: Boolean = false,
) { override fun toString() = "ToolProposalV2(redacted)" }
internal enum class ToolOperationV2 { READ, WRITE }
internal data class ToolPathV2(val root: String, val relative: String) {
    init {
        v2Require(root.matches(Regex("[A-Za-z0-9_-]{1,64}")) && relative.length in 1..1024)
        v2Require(!relative.startsWith('/') && relative.none { it == '\\' || it == ':' || it.code < 32 } &&
            relative.split('/').none { it.isEmpty() || it == "." || it == ".." })
    }
    override fun toString() = "ToolPathV2(redacted)"
}
internal class ToolRequestPolicyV2(permissions: Map<ToolPathV2, Set<ToolOperationV2>>) {
    private val permissions = Collections.unmodifiableMap(permissions.mapValues { Collections.unmodifiableSet(HashSet(it.value)) })
    val commitment = v2Digest(this.permissions.entries.sortedWith(compareBy({ it.key.root }, { it.key.relative })).flatMap {
        listOf(it.key.root, it.key.relative) + it.value.map { op -> op.name }.sorted()
    })
    fun allows(path: ToolPathV2, operation: ToolOperationV2) = operation in permissions[path].orEmpty()
}
internal class ToolInventoryV2(files: Map<ToolPathV2, String>) {
    private val files = Collections.unmodifiableMap(HashMap(files))
    init { v2Require(this.files.values.all { it.matches(Regex("[a-f0-9]{64}")) }) }
    val commitment = v2Digest(this.files.entries.sortedWith(compareBy({ it.key.root }, { it.key.relative })).flatMap { listOf(it.key.root, it.key.relative, it.value) })
    fun contains(path: ToolPathV2) = path in files
}
internal class EffectPreviewV2(
    val path: ToolPathV2, val operation: ToolOperationV2,
    val resultUtf8Ceiling: Long, val auditBytes: Long, val checkpointBytes: Long, val sourceStoreBytes: Long,
    val traceBytes: Long, val traceRecords: Long,
) {
    init { v2Require(resultUtf8Ceiling > 0 && auditBytes > 0 && checkpointBytes > 0 && sourceStoreBytes >= 0 && traceBytes > 0 && traceRecords > 0) }
    override fun toString() = "EffectPreviewV2(redacted)"
}
/** Implementors must share actual broker path/operation semantics. No production or name-only fallback. */
internal interface ToolAuthorityV2 {
    fun preview(proposal: ToolProposalV2, arguments: JsonObject, policy: ToolRequestPolicyV2, inventory: ToolInventoryV2): EffectPreviewV2?
    fun currentBindingCommitment(): String
    fun recheck(effect: EffectPreviewV2, policy: ToolRequestPolicyV2, inventory: ToolInventoryV2): Boolean
}
internal data class EncodedLayoutV2(val exactCurrentHistoryBytes: Long, val exactResultFramingBytes: Long) {
    init { v2Require(exactCurrentHistoryBytes >= 0 && exactResultFramingBytes >= 0) }
}
internal fun interface EncodedSpaceV2 {
    /** Exact encoding of current full input and all empty result envelopes, including delimiters/IDs. */
    fun layout(response: ModelResponseV2, proposals: List<ToolProposalV2>): EncodedLayoutV2
}
internal data class BatchCapacityV2(
    val usedEvidenceBytes: Long = 0, val usedPrivateDiskBytes: Long = 0, val usedTraceRecords: Long = 0,
) { init { v2Require(usedEvidenceBytes >= 0 && usedPrivateDiskBytes >= 0 && usedTraceRecords >= 0) } }
internal data class EncodedReservationV2(val nextRequestBytes: Long, val resultBytes: Long, val evidenceBytes: Long, val privateDiskBytes: Long, val traceRecords: Long)
internal class AdmittedBatchV2 private constructor(
    internal val owner: BuiltinToolBatchV2, internal val response: ModelResponseV2,
    proposals: List<ToolProposalV2>, effects: List<EffectPreviewV2>, val reservation: EncodedReservationV2,
) {
    val proposals: List<ToolProposalV2> = Collections.unmodifiableList(ArrayList(proposals))
    val effects: List<EffectPreviewV2> = Collections.unmodifiableList(ArrayList(effects))
    override fun toString() = "AdmittedBatchV2(redacted)"
    companion object {
        internal fun mint(owner: BuiltinToolBatchV2, response: ModelResponseV2, proposals: List<ToolProposalV2>, effects: List<EffectPreviewV2>, reservation: EncodedReservationV2) =
            AdmittedBatchV2(owner, response, proposals, effects, reservation)
    }
}
/** Callback must stream into the bounded collector, never return an already unbounded result. */
internal fun interface ToolEffectExecutorV2 { fun execute(proposal: ToolProposalV2, effect: EffectPreviewV2, result: BoundedToolResultV2) }
internal class BoundedToolResultV2 internal constructor(private val ceiling: Long, private val beforeRetain: (Long) -> Unit) {
    private val content = StringBuilder(); private var bytes = 0L; private var closed = false
    @Synchronized fun append(fragment: String) {
        v2Require(!closed)
        val size = v2Utf8Bytes(fragment, v2Subtract(ceiling, bytes))
        beforeRetain(size)
        bytes = v2Add(bytes, size); content.append(fragment)
    }
    @Synchronized internal fun finish(): String { v2Require(!closed); closed = true; return content.toString() }
    @Synchronized internal fun close() { closed = true }
}
internal class ToolResultV2 internal constructor(val callId: String, val text: String) { override fun toString() = "ToolResultV2(redacted)" }

/** One session per ledger. Only fake executors are supplied in A; no captured broker is adapted. */
internal class BuiltinToolBatchV2(
    private val ledger: AttemptLedgerV2, private val policy: ToolRequestPolicyV2, private val inventory: ToolInventoryV2,
    private val authority: ToolAuthorityV2, private val encodedSpace: EncodedSpaceV2,
    initialCapacity: BatchCapacityV2 = BatchCapacityV2(),
) {
    private val run = ledger.run
    private val usedIds = mutableSetOf<String>()
    private val repeated = mutableMapOf<String, Int>()
    private var actions = 0L
    private var pending: AdmittedBatchV2? = null
    init {
        v2Require(run.checked.commitments.source == inventory.commitment && run.checked.commitments.toolPolicy == policy.commitment)
        ledger.registerToolSession(this, initialCapacity)
    }
    @Synchronized fun previewBatch(currentSuccessfulResponse: ModelResponseV2): AdmittedBatchV2 = try {
        v2Require(pending == null)
        ledger.requireCurrentSuccessful(currentSuccessfulResponse)
        val proposals = currentSuccessfulResponse.continuation.proposals
        val budget = run.budget
        v2Capacity(proposals.size <= budget.callsPerResponse && v2Add(actions, proposals.size.toLong()) <= budget.maxToolActions)
        val ids = HashSet(usedIds); val itemIds = mutableSetOf<String>(); val counts = HashMap(repeated)
        val effects = ArrayList<EffectPreviewV2>()
        for (p in proposals) {
            v2Require(p.namespace == "decomp" && p.name.matches(Regex("[A-Za-z_][A-Za-z0-9_-]{0,63}")) &&
                p.callId.matches(Regex("[A-Za-z0-9_-]{1,128}")) && p.outputItemId.matches(Regex("[A-Za-z0-9_-]{1,128}")) &&
                ids.add(p.callId) && itemIds.add(p.outputItemId) && (p.caller == null || p.caller == "direct") && !p.asynchronous)
            val schema = run.tools.schema(p.name) ?: v2Fail(ModelFailureKind.UNSUPPORTED_FEATURE)
            val arguments = parseToolObjectV2(p.argumentsJson, budget.eventBytes)
            v2Require(schema.accepts(arguments))
            val action = v2Digest(listOf(p.namespace!!, p.name, canonicalToolJsonV2(arguments)))
            val count = v2Add((counts[action] ?: 0).toLong(), 1)
            v2Capacity(count <= budget.maxIdenticalAction); counts[action] = count.toInt()
            val effect = authority.preview(p, arguments, policy, inventory) ?: v2Fail(ModelFailureKind.AUTHORIZATION)
            if (!policy.allows(effect.path, effect.operation) || !inventory.contains(effect.path)) v2Fail(ModelFailureKind.AUTHORIZATION)
            v2Capacity(effect.resultUtf8Ceiling <= budget.toolResultBytes)
            effects += effect
        }
        val layout = encodedSpace.layout(currentSuccessfulResponse, proposals)
        var results = 0L; var evidence = 0L; var disk = 0L; var traces = 0L
        effects.forEach { e ->
            results = v2Add(results, e.resultUtf8Ceiling)
            val growth = v2Add(v2Add(e.auditBytes, e.checkpointBytes), v2Add(e.sourceStoreBytes, e.traceBytes))
            evidence = v2Add(evidence, v2Add(growth, e.resultUtf8Ceiling))
            disk = v2Add(disk, v2Add(growth, e.resultUtf8Ceiling))
            traces = v2Add(traces, e.traceRecords)
        }
        val next = v2Add(v2Add(layout.exactCurrentHistoryBytes, layout.exactResultFramingBytes), v2Multiply(6, results))
        v2Capacity(next <= budget.requestBytes && v2Add(next, budget.historyReserveBytes) <= budget.contextBytes)
        v2Capacity(v2Add(ledger.counters().displayed, results) <= budget.displayedBytesTotal)
        val capacity = ledger.storageUsage()
        v2Capacity(v2Add(capacity.usedEvidenceBytes, evidence) <= budget.evidenceBytes &&
            v2Add(capacity.usedPrivateDiskBytes, disk) <= budget.privateDiskBytes && v2Add(capacity.usedTraceRecords, traces) <= budget.traceRecords)
        val reservation = EncodedReservationV2(next, results, evidence, disk, traces)
        val admitted = AdmittedBatchV2.mint(this, currentSuccessfulResponse, proposals, effects, reservation)
        // Pure preview ports have completed; this host reservation prevents concurrent reuse.
        ledger.claimBatch(currentSuccessfulResponse, reservation)
        usedIds.clear(); usedIds.addAll(ids); repeated.clear(); repeated.putAll(counts)
        actions = v2Add(actions, proposals.size.toLong()); pending = admitted
        admitted
    } catch (failure: Exception) {
        ledger.failBatch()
        if (failure is ModelProviderException) throw failure
        v2Fail(ModelFailureKind.AUTHORIZATION)
    }
    @Synchronized fun execute(batch: AdmittedBatchV2, executor: ToolEffectExecutorV2): List<ToolResultV2> {
        v2Require(batch.owner === this && pending === batch)
        // Consume before calling external ports: recursive or duplicate execute cannot reuse a permit.
        pending = null
        val results = ArrayList<ToolResultV2>()
        try {
            batch.proposals.forEachIndexed { index, proposal ->
                ledger.checkBatchActive()
                val effect = batch.effects[index]
                if (authority.currentBindingCommitment() != run.bindingCommitment ||
                    !authority.recheck(effect, policy, inventory)) v2Fail(ModelFailureKind.AUTHORIZATION)
                ledger.checkBatchActive() // recheck cancellation/deadline after the broker callback
                if (authority.currentBindingCommitment() != run.bindingCommitment) v2Fail(ModelFailureKind.AUTHORIZATION)
                ledger.checkBatchActive() // The final identity callback may itself exhaust time or cancel.
                val collector = BoundedToolResultV2(effect.resultUtf8Ceiling, ledger::chargeToolResult)
                val text = try { executor.execute(proposal, effect, collector); collector.finish() } finally { collector.close() }
                results += ToolResultV2(proposal.callId, text)
            }
            ledger.finishBatch()
            return Collections.unmodifiableList(results)
        } catch (failure: Exception) {
            ledger.failBatch()
            // Candidate effects may already exist. No rollback/publication/next-call authority is claimed.
            if (failure is ModelProviderException) throw failure
            v2Fail(ModelFailureKind.AUTHORIZATION)
        }
    }
}
