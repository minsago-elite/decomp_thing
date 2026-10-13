package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

/** An authenticated caller supplies identities; collecting an inventory authenticates no input. */
internal data class BoundedDwarfObservationInput(val role: String, val sha256: String, val bytes: Long) {
    init {
        require(Regex("[A-Za-z][A-Za-z0-9_-]{0,63}").matches(role))
        require(INVENTORY_SHA.matches(sha256) && bytes >= 0)
    }
    fun toJson(): JsonObject = JsonObject(mapOf("role" to JsonPrimitive(role),
        "sha256" to JsonPrimitive(sha256), "bytes" to JsonPrimitive(bytes)))
}

/** Reviewed selections remain observations, including excluded and missing-DWARF entries. */
internal class BoundedDwarfFunctionSelection(
    val id: String,
    val rva: ULong?,
    candidateLocators: List<String>,
    val excluded: Boolean,
) {
    val candidateLocators: List<String> = Collections.unmodifiableList(ArrayList(candidateLocators))
    init { require(id.isNotEmpty() && id.length <= 4096 && candidateLocators.all { it.isNotEmpty() && it.length <= 4096 }) }
}

internal data class BoundedDwarfObservationInventoryLimits(
    val maximumRecords: Long = 1_000_000,
    val maximumWorkSteps: Long = 5_000_000,
    val maximumCanonicalBytes: Long = 512L * 1024 * 1024,
    val maximumCanonicalNodes: Long = 16_000_000,
    val maximumRecordBytes: Int = 8 * 1024 * 1024,
    val maximumRecordNodes: Int = 100_000,
    val shardLimits: BoundedDwarfShardLimits = BoundedDwarfShardLimits(),
) {
    init {
        require(maximumRecords in 1..1_000_000L && maximumWorkSteps in 1..50_000_000L)
        require(maximumCanonicalBytes in 1..512L * 1024 * 1024 && maximumCanonicalNodes in 1..16_000_000L)
        require(maximumRecordBytes in 1..8 * 1024 * 1024 && maximumRecordNodes in 1..100_000)
    }
    internal fun jsonLimits(): StrictJsonLimits = StrictJsonLimits(
        maximumInputBytes = maximumRecordBytes, maximumCanonicalBytes = maximumRecordBytes,
        maximumDepth = 62, maximumNodes = maximumRecordNodes,
        maximumStringBytes = maximumRecordBytes, maximumTotalStringBytes = maximumRecordBytes,
    )
}

/** Holds the existing immutable facts, never a second raw graph or a retained list of JSON records. */
internal class BoundedDwarfObservationInventory internal constructor(
    private val source: InventorySource,
    private val manifestBytes: ByteArray,
    private val limits: BoundedDwarfObservationInventoryLimits,
) {
    val manifest: JsonObject get() = OracleJson.parseCanonical(manifestBytes, INVENTORY_MANIFEST_LIMITS) as JsonObject

    fun visitCanonicalShards(consumer: (String, Int, ByteArray, Int) -> Unit): BoundedDwarfShardSummary {
        val budget = InventoryBudget(limits)
        val writer = BoundedDwarfCanonicalShardWriter(limits.shardLimits, consumer)
        source.visitInventory(budget) { kind, records -> writer.write(kind, records.onEach {
            validateInventoryRecord(kind, it)
            budget.encode(it)
        }) }
        return writer.finish()
    }
}

internal object BoundedDwarfObservationInventoryV1 {
    const val SCHEMA = "dwarf-pre-policy-inventory-v1"
    val RECORD_KINDS: List<String> = Collections.unmodifiableList(listOf(
        "inventoryRoots", "inventoryReferences", "inventoryTypeCompleteness", "inventoryFindings", "inventorySelections",
    ))
    val RAW_RECORD_KINDS: List<String> = Collections.unmodifiableList(listOf(
        "metadata", "functions", "types", "typeChildren", "globals", "objectSymbols", "strippedObjects",
    ))

    fun collect(
        facts: BoundedDwarfInterfaceFacts,
        strippedObjects: List<FullTreeElfObjectSymbol>,
        strippedLayout: FullTreeElfObjectLayoutObservation?,
        inputs: List<BoundedDwarfObservationInput>,
        selections: List<BoundedDwarfFunctionSelection> = emptyList(),
        limits: BoundedDwarfObservationInventoryLimits = BoundedDwarfObservationInventoryLimits(),
    ): BoundedDwarfObservationInventory {
        require(inputs.size in 1..128 && inputs.map { it.role }.distinct().size == inputs.size) { "inventory input roles repeat or exceed bounds" }
        val rich = inputs.singleOrNull { it.role == "rich" } ?: inventoryFail("missing rich input binding")
        require(rich.sha256 == facts.inputSha256 && rich.bytes == facts.inputBytes) { "inventory rich binding differs from scanned facts" }
        if (strippedLayout != null || strippedObjects.isNotEmpty()) require(inputs.any { it.role == "stripped" }) { "missing stripped input binding" }
        require(facts.types.size <= facts.limits.maximumTypes && facts.functions.size <= facts.limits.maximumFunctions &&
            facts.globals.size <= facts.limits.maximumGlobals && facts.objectSymbols.size <= facts.limits.maximumObjects &&
            strippedObjects.size <= facts.limits.maximumObjects && selections.size <= 100_000) { "inventory source population exceeds scanner ceilings" }
        require(facts.types.all { it.key == it.value.id }) { "inventory type map does not bind physical IDs" }
        require(selections.map { it.id }.distinct().size == selections.size) { "inventory selection IDs repeat" }
        val source = InventorySource(facts, Collections.unmodifiableList(ArrayList(strippedObjects)), strippedLayout,
            Collections.unmodifiableList(ArrayList(selections)))
        val budget = InventoryBudget(limits)
        val raw = ArrayList<JsonObject>()
        source.visitRaw { kind, records -> raw += commitRecords(kind, records, budget) }
        val inventory = ArrayList<JsonObject>()
        val counts = InventoryCounts()
        source.visitInventory(budget) { kind, records ->
            inventory += commitRecords(kind, records.onEach { validateInventoryRecord(kind, it); counts.observe(kind, it) }, budget)
        }
        val unsigned = JsonObject(linkedMapOf(
            "schema" to JsonPrimitive(SCHEMA), "scannerProducer" to JsonPrimitive(BoundedDwarfInterfaceFactScanner.PRODUCER),
            "rawRecordEncoding" to JsonPrimitive(BoundedDwarfInterfaceFacts.RAW_RECORD_ENCODING),
            "commitmentEncoding" to JsonPrimitive(INVENTORY_COMMITMENT_ENCODING),
            "typeGraphScope" to JsonPrimitive(facts.limits.typeGraphScope.wireName),
            "inputs" to JsonArray(inputs.sortedBy { it.role }.map { it.toJson() }),
            "requiredTypePopulationComplete" to JsonPrimitive(false),
            "rawCommitments" to JsonArray(raw), "inventoryCommitments" to JsonArray(inventory), "counts" to counts.toJson(),
        ))
        val manifest = JsonObject(unsigned + ("inventorySha256" to JsonPrimitive(inventorySha(OracleJson.canonicalBytes(unsigned, INVENTORY_MANIFEST_LIMITS)))))
        return BoundedDwarfObservationInventory(source, OracleJson.canonicalBytes(manifest, INVENTORY_MANIFEST_LIMITS), limits)
    }

    fun verifier(manifest: JsonObject, limits: BoundedDwarfObservationInventoryLimits = BoundedDwarfObservationInventoryLimits()):
        BoundedDwarfObservationInventoryVerifier = BoundedDwarfObservationInventoryVerifier(manifest, limits)
}

/**
 * Integrity verification only: the outer caller still authenticates this manifest's identity and
 * provenance. Matching stream commitments do not independently rederive roots or prove population
 * completeness; a changed derivation produces a different inventory identity requiring review.
 */
internal class BoundedDwarfObservationInventoryVerifier internal constructor(
    manifest: JsonObject,
    private val limits: BoundedDwarfObservationInventoryLimits,
) {
    private val expected: Map<String, JsonObject>
    private val budget = InventoryBudget(limits)
    private val counts = InventoryCounts()
    private val commitments = LinkedHashMap<String, InventoryCommitter>()
    private val ordinals = HashMap<String, Int>()
    private var lastKind = -1
    private var layoutAccepted = false
    private var failed = false
    private var finished = false
    private var shardBytes = 0L
    private var shardNodes = 0L
    private var shardCount = 0
    private val boundManifest: JsonObject
    private val hasStrippedInput: Boolean
    private val kinds = BoundedDwarfObservationInventoryV1.RAW_RECORD_KINDS + BoundedDwarfObservationInventoryV1.RECORD_KINDS

    init {
        // Encoding checks the caller's object before its defensive snapshot can allocate a large copy.
        val bytes = OracleJson.canonicalBytes(manifest, INVENTORY_MANIFEST_LIMITS)
        boundManifest = OracleJson.parseCanonical(bytes, INVENTORY_MANIFEST_LIMITS) as JsonObject
        exact(boundManifest, MANIFEST_KEYS)
        require(boundManifest["schema"] == JsonPrimitive(BoundedDwarfObservationInventoryV1.SCHEMA) &&
            boundManifest["scannerProducer"] == JsonPrimitive(BoundedDwarfInterfaceFactScanner.PRODUCER) &&
            boundManifest["rawRecordEncoding"] == JsonPrimitive(BoundedDwarfInterfaceFacts.RAW_RECORD_ENCODING) &&
            boundManifest["commitmentEncoding"] == JsonPrimitive(INVENTORY_COMMITMENT_ENCODING) &&
            boundManifest["requiredTypePopulationComplete"] == JsonPrimitive(false)) { "unsupported inventory manifest" }
        require(text(boundManifest, "typeGraphScope") in BoundedDwarfTypeGraphScope.entries.map { it.wireName })
        require(text(boundManifest, "inventorySha256") == inventorySha(OracleJson.canonicalBytes(JsonObject(boundManifest - "inventorySha256"), INVENTORY_MANIFEST_LIMITS))) {
            "inventory manifest digest mismatch"
        }
        val inputs = array(boundManifest, "inputs").map { element ->
            val input = obj(element); exact(input, setOf("role", "sha256", "bytes"))
            BoundedDwarfObservationInput(text(input, "role"), text(input, "sha256"), number(input, "bytes"))
        }
        require(inputs.size in 1..128 && inputs.map { it.role } == inputs.map { it.role }.distinct().sorted() && inputs.any { it.role == "rich" })
        hasStrippedInput = inputs.any { it.role == "stripped" }
        val raw = readCommitments(boundManifest, "rawCommitments", BoundedDwarfObservationInventoryV1.RAW_RECORD_KINDS + "strippedMetadata")
        val inventory = readCommitments(boundManifest, "inventoryCommitments", BoundedDwarfObservationInventoryV1.RECORD_KINDS)
        expected = raw + inventory
        exact(obj(boundManifest.getValue("counts")), InventoryCounts.KEYS)
        obj(boundManifest.getValue("counts")).keys.forEach { number(obj(boundManifest.getValue("counts")), it) }
    }

    fun accept(kind: String, ordinal: Int, bytes: ByteArray, recordCount: Int) = guarded {
        val index = kinds.indexOf(kind)
        require(index >= 0 && index >= lastKind && (lastKind < 0 || index <= lastKind + 1)) { "inventory record kinds are missing or reordered" }
        require(index != 0 || lastKind >= 0 || ordinal == 0)
        if (lastKind < 0) require(index == 0) { "inventory raw metadata is missing" }
        require(ordinal == (ordinals[kind] ?: 0)) { "inventory shard ordinal repeats or skips" }
        val parsed = parseCanonicalDwarfShard(bytes, limits.shardLimits, kind, ordinal, recordCount)
        if (kind == "metadata") require(ordinal == 0 && parsed.recordCount == 1) {
            "inventory requires exactly one raw metadata record"
        }
        if (kind == "strippedObjects" && parsed.recordCount > 0) require(hasStrippedInput) {
            "missing stripped input binding"
        }
        require(shardCount < limits.shardLimits.maximumShards &&
            shardBytes <= limits.shardLimits.maximumTotalBytes - bytes.size &&
            shardNodes <= limits.shardLimits.maximumTotalNodes - parsed.nodeCount) { "inventory shard totals exceed bounds" }
        shardCount++; shardBytes += bytes.size; shardNodes += parsed.nodeCount
        val committer = commitments.getOrPut(kind) { InventoryCommitter(kind) }
        for (record in parsed.records) {
            if (kind in BoundedDwarfObservationInventoryV1.RECORD_KINDS) {
                validateInventoryRecord(kind, record); counts.observe(kind, record)
            }
            val normalized = if (kind == "metadata") normalizeMetadata(record) else record
            if (kind == "metadata") {
                require(normalized["typeGraphScope"] == boundManifest["typeGraphScope"])
                val rich = array(boundManifest, "inputs").map(::obj).single { text(it, "role") == "rich" }
                require(normalized["inputSha256"] == rich["sha256"] && normalized["inputBytes"] == rich["bytes"])
            }
            committer.add(budget.encode(normalized))
        }
        ordinals[kind] = ordinal + 1
        lastKind = index
    }

    fun acceptStrippedLayout(layout: JsonObject?) = guarded {
        require(!layoutAccepted) { "stripped inventory metadata repeats" }
        layoutAccepted = true
        if (layout != null) require(hasStrippedInput) { "missing stripped input binding" }
        val committer = InventoryCommitter("strippedMetadata")
        committer.add(budget.encode(strippedMetadata(layout)))
        commitments["strippedMetadata"] = committer
    }

    fun finish() = guarded {
        require(layoutAccepted && lastKind == kinds.lastIndex && commitments.keys == expected.keys) { "inventory records are incomplete" }
        for ((kind, value) in expected) require(commitments.getValue(kind).finish() == value) { "inventory $kind commitment differs from its records" }
        require(counts.toJson() == boundManifest["counts"]) { "inventory counts differ from the records" }
        finished = true
    }

    private fun guarded(action: () -> Unit) {
        require(!failed && !finished) { "inventory verifier is closed" }
        try { action() } catch (failure: Throwable) { failed = true; throw failure }
    }
}

internal class InventorySource(
    private val facts: BoundedDwarfInterfaceFacts,
    private val strippedObjects: List<FullTreeElfObjectSymbol>,
    private val strippedLayout: FullTreeElfObjectLayoutObservation?,
    private val selections: List<BoundedDwarfFunctionSelection>,
) {
    fun visitRaw(consumer: (String, Sequence<JsonObject>) -> Unit) {
        facts.visitCanonicalRecordGroups { kind, records -> consumer(kind,
            if (kind == "metadata") records.map(::normalizeMetadata) else records) }
        consumer("strippedObjects", strippedObjects.asSequence().map { it.toJson() })
        consumer("strippedMetadata", sequenceOf(strippedMetadata(strippedLayout?.toJson())))
    }

    fun visitInventory(budget: InventoryBudget, consumer: (String, Sequence<JsonObject>) -> Unit) {
        val types = facts.types.values.sortedBy { it.id }
        consumer("inventoryRoots", roots(budget).map { it.toJson(facts.types, budget) })
        consumer("inventoryReferences", references(types, budget).map { it.toJson(facts.types, budget) })
        consumer("inventoryTypeCompleteness", types.asSequence().map { completeness(it, budget) })
        consumer("inventoryFindings", sequence {
            yield(finding("inventory", "inventory", "required-type-population-unresolved"))
            yield(finding("inventory", "inventory", "member-cardinality-unresolved"))
            if (facts.limits.typeGraphScope != BoundedDwarfTypeGraphScope.FULL_REFERENCES) {
                yield(finding("inventory", "inventory", "type-graph-scope-is-abi-layout"))
            }
            for (root in roots(budget)) for (code in root.findings(facts.types, budget)) yield(finding(root.ownerKind, root.ownerLocator, code, root.relation))
            for (reference in references(types, budget)) for (code in reference.findings(facts.types, budget)) {
                yield(finding(reference.ownerKind, reference.ownerLocator, code, reference.relation))
            }
            for (type in types) for (code in completenessReasons(type, budget)) yield(finding("type", type.id, code))
            for (selection in selections) for (code in selectionFindings(selection, budget)) yield(finding("selection", selection.id, code))
            yieldAll(cycleFindings(types, budget))
        })
        consumer("inventorySelections", selections.asSequence().map { selection ->
            budget.work()
            JsonObject(linkedMapOf("id" to JsonPrimitive(selection.id), "rva" to (selection.rva?.let { JsonPrimitive("0x${it.toString(16)}") } ?: JsonNull),
                "candidateLocators" to strings(selection.candidateLocators), "excluded" to JsonPrimitive(selection.excluded),
                "findings" to strings(selectionFindings(selection, budget))))
        })
    }

    private fun roots(budget: InventoryBudget): Sequence<InventoryReference> = sequence {
        for (function in facts.functions) {
            budget.work()
            yield(InventoryReference("function-return", function.locator, "return", function.returnType))
            // Only one function's fingerprints are retained. Identical convenience views add no root.
            val candidateParameters = HashSet<String>()
            for (list in function.parameterLists) for (parameter in list.parameters) {
                budget.work()
                candidateParameters += inventorySha(OracleJson.canonicalBytes(parameter.toJson(), budget.limits.jsonLimits()))
                yield(InventoryReference("function-parameter", function.locator, "parameter", parameter.type,
                    parameterListLocator = list.locator, parameterOrdinal = parameter.ordinal))
            }
            for (parameter in function.parameters) {
                budget.work()
                if (inventorySha(OracleJson.canonicalBytes(parameter.toJson(), budget.limits.jsonLimits())) !in candidateParameters) {
                    yield(InventoryReference("selected-parameter-unmatched", function.locator, "parameter", parameter.type,
                        parameterListLocator = parameter.locator, parameterOrdinal = parameter.ordinal,
                        additionalFindings = listOf("selected-parameter-has-no-identical-candidate")))
                }
            }
        }
        for (variable in facts.globals) {
            budget.work()
            yield(InventoryReference("variable", variable.locator, "type", variable.type))
        }
    }

    private fun references(types: List<DwarfInterfaceTypeNode>, budget: InventoryBudget): Sequence<InventoryReference> = sequence {
        for (type in types) {
            yieldAll(nodeReferences(type, budget))
        }
    }

    private fun nodeReferences(type: DwarfInterfaceTypeNode, budget: InventoryBudget): Sequence<InventoryReference> = sequence {
        budget.work()
        yield(InventoryReference("type", type.id, "type", type.type))
        if (type.attributes[0x49]?.let { !sameFact(it, type.type) } == true) {
            yield(InventoryReference("type", type.id, "type-attribute", type.attributes.getValue(0x49)))
        }
        type.attributes[0x1d]?.let { yield(InventoryReference("type", type.id, "containing-type", it)) }
        for (child in type.children) {
            budget.work()
            yield(InventoryReference("type-child", child.id, "type", child.type, parentTypeId = type.id))
            if (child.attributes[0x49]?.let { !sameFact(it, child.type) } == true) {
                yield(InventoryReference("type-child", child.id, "type-attribute", child.attributes.getValue(0x49), parentTypeId = type.id))
            }
            child.attributes[0x1d]?.let { yield(InventoryReference("type-child", child.id, "containing-type", it, parentTypeId = type.id)) }
        }
    }

    private fun cycleFindings(types: List<DwarfInterfaceTypeNode>, budget: InventoryBudget): Sequence<JsonObject> = sequence {
        data class Frame(val id: String, val outgoing: Iterator<Pair<InventoryReference, String>>)
        val colors = HashMap<String, Int>()
        val stack = ArrayDeque<Frame>()
        fun enter(id: String) {
            budget.work()
            colors[id] = 1
            val edges = nodeReferences(facts.types.getValue(id), budget).flatMap { reference ->
                reference.fact.values.asSequence().map { reference to it }
            }.iterator()
            stack.addLast(Frame(id, edges))
        }
        for (root in types) {
            if (root.id in colors) continue
            enter(root.id)
            while (stack.isNotEmpty()) {
                budget.work()
                val frame = stack.last()
                if (!frame.outgoing.hasNext()) { colors[frame.id] = 2; stack.removeLast(); continue }
                val (reference, target) = frame.outgoing.next()
                if (target !in facts.types) continue
                when (colors[target]) {
                    null -> enter(target)
                    1 -> yield(finding(reference.ownerKind, reference.ownerLocator, "reference-cycle", target))
                }
            }
        }
    }

    private val functionsByLocator by lazy { facts.functions.associateBy { it.locator } }
    private fun selectionFindings(selection: BoundedDwarfFunctionSelection, budget: InventoryBudget): List<String> = buildList {
        if (selection.candidateLocators.isEmpty()) add("selection-has-no-DWARF-candidate")
        if (selection.candidateLocators.size > 1) add("selection-has-multiple-DWARF-candidates")
        for (locator in selection.candidateLocators) {
            budget.work()
            val function = functionsByLocator[locator]
            if (function == null) add("selection-candidate-missing:$locator")
            else if (function.rva != selection.rva) add("selection-candidate-rva-mismatch:$locator")
        }
    }
}

private class InventoryReference(
    val ownerKind: String,
    val ownerLocator: String,
    val relation: String,
    val fact: DwarfInterfaceFact<String>,
    val parentTypeId: String? = null,
    val parameterListLocator: String? = null,
    val parameterOrdinal: Int? = null,
    val additionalFindings: List<String> = emptyList(),
) {
    private fun deferred(): Boolean = fact.reasons.any {
        it.startsWith("type-reference-not-expanded:") || it == "type-graph-not-expanded-for-automatic-local"
    }
    fun findings(types: Map<String, DwarfInterfaceTypeNode>, budget: InventoryBudget): List<String> = buildList {
        addAll(additionalFindings)
        if (fact.state != DwarfInterfaceFactState.KNOWN) add("reference-state-${fact.state.name.lowercase()}")
        if (fact.state == DwarfInterfaceFactState.KNOWN && fact.values.size != 1) add("reference-known-cardinality-unresolved")
        for (target in fact.values) {
            budget.work()
            if (target !in types) add(if (deferred()) "reference-target-deferred:$target" else "reference-target-missing:$target")
        }
        if (deferred()) add("reference-expansion-deferred")
        if (fact.reasons.any { it.startsWith("type-reference-cycle:") }) add("reference-cycle")
    }
    fun toJson(types: Map<String, DwarfInterfaceTypeNode>, budget: InventoryBudget): JsonObject {
        val fields = linkedMapOf<String, JsonElement>("ownerKind" to JsonPrimitive(ownerKind), "ownerLocator" to JsonPrimitive(ownerLocator))
        if (ownerKind in ROOT_KINDS) {
            fields["parameterListLocator"] = parameterListLocator?.let(::JsonPrimitive) ?: JsonNull
            fields["parameterOrdinal"] = parameterOrdinal?.let(::JsonPrimitive) ?: JsonNull
        } else {
            fields["parentTypeId"] = parentTypeId?.let(::JsonPrimitive) ?: JsonNull
            fields["relation"] = JsonPrimitive(relation)
        }
        fields["typeFact"] = fact.toJson(::JsonPrimitive)
        fields["candidates"] = JsonArray(fact.values.map { target ->
            budget.work()
            JsonObject(mapOf("targetId" to JsonPrimitive(target), "availability" to JsonPrimitive(
                if (target in types) "materialized" else if (deferred()) "deferred" else "missing")))
        })
        fields["findings"] = strings(findings(types, budget))
        return JsonObject(fields)
    }
}

private fun completeness(type: DwarfInterfaceTypeNode, budget: InventoryBudget): JsonObject = JsonObject(linkedMapOf(
    "ownerTypeId" to JsonPrimitive(type.id), "observedChildCount" to JsonPrimitive(type.children.size),
    "observedDirectMemberCount" to JsonPrimitive(type.children.count { it.tag == 0x0dL }),
    "requiredMemberCardinality" to JsonNull, "complete" to JsonPrimitive(false),
    "findings" to strings(completenessReasons(type, budget)),
))

private fun completenessReasons(type: DwarfInterfaceTypeNode, budget: InventoryBudget): List<String> = buildList {
    budget.work()
    add("member-cardinality-not-established")
    if (type.tag !in INTERFACE_TYPE_TAGS) add("unsupported-type-tag")
    type.attributes[0x3c]?.let {
        if (it.state == DwarfInterfaceFactState.KNOWN && it.values.any { value -> value != "0" }) add("declaration-only-type")
        else if (it.state != DwarfInterfaceFactState.KNOWN && it.state != DwarfInterfaceFactState.ABSENT) add("declaration-status-unresolved")
    }
    if (type.reasons.any { it.startsWith("inherited-type-children-unrepresented:") }) add("inherited-type-children-unrepresented")
    for (child in type.children) {
        budget.work()
        if (child.tag == 0x1cL) add("inherited-member-population-unresolved:${child.id}")
        if (child.tag in INTERFACE_TYPE_TAGS) add("nested-type-child-unexpanded:${child.id}")
        if (child.tag !in setOf(0x05L, 0x0dL, 0x18L, 0x1cL, 0x21L, 0x28L) && child.tag !in INTERFACE_TYPE_TAGS) {
            add("unsupported-child-semantics:${child.id}")
        }
        if (child.reasons.any { it.contains("nested") || it.contains("unsupported") || it.contains("inherited") }) {
            add("child-semantics-unresolved:${child.id}")
        }
    }
}

internal class InventoryBudget(val limits: BoundedDwarfObservationInventoryLimits) {
    private var steps = 0L
    private var records = 0L
    private var bytes = 0L
    private var nodes = 0L
    fun work() { if (steps >= limits.maximumWorkSteps) inventoryFail("traversal work exceeds bounds"); steps++ }
    fun encode(record: JsonObject): ByteArray {
        work()
        if (records >= limits.maximumRecords) inventoryFail("record count exceeds bounds")
        val encoded = OracleJson.canonicalBytes(record, limits.jsonLimits())
        var recordNodes = 0
        val stack = ArrayDeque<Iterator<JsonElement>>()
        stack.addLast(listOf<JsonElement>(record).iterator())
        while (stack.isNotEmpty()) {
            val cursor = stack.last()
            if (!cursor.hasNext()) { stack.removeLast(); continue }
            val value = cursor.next(); recordNodes++
            when (value) { is JsonObject -> stack.addLast(value.values.iterator()); is JsonArray -> stack.addLast(value.iterator()); else -> Unit }
        }
        if (bytes > limits.maximumCanonicalBytes - encoded.size || nodes > limits.maximumCanonicalNodes - recordNodes) {
            inventoryFail("canonical record totals exceed bounds")
        }
        records++; bytes += encoded.size; nodes += recordNodes
        return encoded
    }
}

private class InventoryCommitter(private val kind: String) {
    private val digest = MessageDigest.getInstance("SHA-256").apply { update("bounded-dwarf-observation-records-v1\n$kind\n".toByteArray(Charsets.UTF_8)) }
    private var count = 0L
    private var bytes = 0L
    fun add(record: ByteArray) { digest.update(1.toByte()); digest.update(frame(record.size.toLong())); digest.update(record); count++; bytes += record.size }
    fun finish(): JsonObject {
        digest.update(0.toByte()); digest.update(frame(count))
        return JsonObject(mapOf("kind" to JsonPrimitive(kind), "recordCount" to JsonPrimitive(count),
            "canonicalBytes" to JsonPrimitive(bytes), "sha256" to JsonPrimitive(hex(digest.digest()))))
    }
}

private fun commitRecords(kind: String, records: Sequence<JsonObject>, budget: InventoryBudget): JsonObject =
    InventoryCommitter(kind).also { commitment -> records.forEach { commitment.add(budget.encode(it)) } }.finish()

private class InventoryCounts {
    private val values = KEYS.associateWith { 0L }.toMutableMap()
    fun observe(kind: String, record: JsonObject) {
        val key = when (kind) {
            "inventoryRoots" -> when (text(record, "ownerKind")) {
                "function-return" -> "functionReturnRoots"; "function-parameter" -> "candidateParameterRoots"
                "selected-parameter-unmatched" -> "unmatchedSelectedParameterRoots"; else -> "variableRoots"
            }
            "inventoryReferences" -> if (text(record, "relation") == "containing-type") "containingTypeReferences" else "typeReferences"
            "inventoryTypeCompleteness" -> "typeCompleteness"; "inventoryFindings" -> "findings"; else -> "selections"
        }
        values[key] = values.getValue(key) + 1
    }
    fun toJson(): JsonObject = JsonObject(values.mapValues { JsonPrimitive(it.value) })
    companion object {
        val KEYS = linkedSetOf("functionReturnRoots", "candidateParameterRoots", "unmatchedSelectedParameterRoots", "variableRoots",
            "typeReferences", "containingTypeReferences", "typeCompleteness", "findings", "selections")
    }
}

private fun normalizeMetadata(raw: JsonObject): JsonObject {
    val required = setOf("schema", "inputSha256", "inputBytes", "elfType", "imageBase", "executableRanges", "dwarfPresent",
        "recordCounts", "ordering", "objectLayout", "typeChildEncoding", "typePromotedFactFallbacks", "typePromotedFactRule")
    require(raw.keys.containsAll(required)) { "raw metadata omits semantic observation fields" }
    val result = raw.filterKeys { it in required }.toMutableMap()
    result["objectLayout"] = raw.getValue("objectLayout").let { if (it == JsonNull) it else JsonObject(obj(it) - "scannedSymbols") }
    result["typeGraphScope"] = obj(raw.getValue("limits")).getValue("typeGraphScope")
    return JsonObject(result)
}

private fun strippedMetadata(layout: JsonObject?): JsonObject = JsonObject(mapOf(
    "objectLayout" to (layout?.let { JsonObject(it - "scannedSymbols") } ?: JsonNull),
))

private fun validateInventoryRecord(kind: String, record: JsonObject) {
    when (kind) {
        "inventoryRoots", "inventoryReferences" -> {
            val roots = kind == "inventoryRoots"
            exact(record, setOf("ownerKind", "ownerLocator", "typeFact", "candidates", "findings") +
                if (roots) setOf("parameterListLocator", "parameterOrdinal") else setOf("parentTypeId", "relation"))
            val owner = text(record, "ownerKind"); text(record, "ownerLocator")
            if (roots) {
                require(owner in ROOT_KINDS)
                nullableText(record.getValue("parameterListLocator"))
                if (record["parameterOrdinal"] != JsonNull) number(record, "parameterOrdinal")
            } else {
                require(owner in setOf("type", "type-child"))
                nullableText(record.getValue("parentTypeId"))
                require(text(record, "relation") in setOf("type", "type-attribute", "containing-type"))
            }
            val fact = obj(record.getValue("typeFact")); exact(fact, setOf("state", "values", "evidence", "reasons"))
            require(text(fact, "state") in setOf("known", "absent", "unknown", "ambiguous"))
            val values = stringArray(fact, "values"); stringArray(fact, "evidence"); stringArray(fact, "reasons")
            val candidates = array(record, "candidates").map { item ->
                val candidate = obj(item); exact(candidate, setOf("targetId", "availability"))
                require(text(candidate, "availability") in setOf("materialized", "deferred", "missing")); text(candidate, "targetId")
            }
            require(values == candidates)
            stringArray(record, "findings")
        }
        "inventoryTypeCompleteness" -> {
            exact(record, setOf("ownerTypeId", "observedChildCount", "observedDirectMemberCount", "requiredMemberCardinality", "complete", "findings"))
            text(record, "ownerTypeId")
            require(number(record, "observedDirectMemberCount") <= number(record, "observedChildCount"))
            require(record["requiredMemberCardinality"] == JsonNull && record["complete"] == JsonPrimitive(false))
            stringArray(record, "findings")
        }
        "inventoryFindings" -> {
            exact(record, setOf("ownerKind", "ownerLocator", "code", "detail"))
            text(record, "ownerKind"); text(record, "ownerLocator"); text(record, "code"); nullableText(record.getValue("detail"))
        }
        "inventorySelections" -> {
            exact(record, setOf("id", "rva", "candidateLocators", "excluded", "findings"))
            text(record, "id"); stringArray(record, "candidateLocators"); stringArray(record, "findings")
            require((record["excluded"] as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull != null)
            nullableText(record.getValue("rva"))?.let { require(Regex("0x(?:0|[1-9a-f][0-9a-f]*)").matches(it) && it.removePrefix("0x").toULongOrNull(16) != null) }
        }
        else -> inventoryFail("unsupported record kind")
    }
}

private fun readCommitments(manifest: JsonObject, name: String, kinds: List<String>): Map<String, JsonObject> {
    val entries = array(manifest, name).map(::obj)
    require(entries.map { text(it, "kind") } == kinds) { "inventory commitment kinds differ from the closed list" }
    return entries.associate { value ->
        exact(value, setOf("kind", "recordCount", "canonicalBytes", "sha256"))
        number(value, "recordCount"); number(value, "canonicalBytes"); require(INVENTORY_SHA.matches(text(value, "sha256")))
        text(value, "kind") to value
    }
}

private fun finding(ownerKind: String, owner: String, code: String, detail: String? = null): JsonObject = JsonObject(mapOf(
    "ownerKind" to JsonPrimitive(ownerKind), "ownerLocator" to JsonPrimitive(owner), "code" to JsonPrimitive(code),
    "detail" to (detail?.let(::JsonPrimitive) ?: JsonNull),
))
private fun sameFact(a: DwarfInterfaceFact<String>, b: DwarfInterfaceFact<String>): Boolean =
    a.state == b.state && a.values == b.values && a.evidence == b.evidence && a.reasons == b.reasons
private fun frame(value: Long): ByteArray = ByteBuffer.allocate(8).putLong(value).array()
private fun strings(values: List<String>): JsonArray = JsonArray(values.map(::JsonPrimitive))
private fun inventorySha(bytes: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))
private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
private fun exact(value: JsonObject, keys: Set<String>) { require(value.keys == keys) { "inventory object differs from its closed schema" } }
private fun obj(value: JsonElement): JsonObject = value as? JsonObject ?: inventoryFail("expected object")
private fun array(value: JsonObject, key: String): JsonArray = value[key] as? JsonArray ?: inventoryFail("expected $key array")
private fun text(value: JsonObject, key: String): String = nullableText(value.getValue(key)) ?: inventoryFail("expected $key string")
private fun nullableText(value: JsonElement): String? {
    if (value == JsonNull) return null
    val primitive = value as? JsonPrimitive ?: inventoryFail("expected string")
    require(primitive.isString && primitive.content.length <= 16_384) { "inventory text exceeds bounds or is not a string" }
    return primitive.content
}
private fun stringArray(value: JsonObject, key: String): List<String> = array(value, key).map { nullableText(it) ?: inventoryFail("null string entry") }
private fun number(value: JsonObject, key: String): Long = (value[key] as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull
    ?.takeIf { it >= 0 } ?: inventoryFail("expected nonnegative $key integer")
private fun inventoryFail(message: String): Nothing = throw FullTreeControlException("DWARF observation inventory: $message")
private val ROOT_KINDS = setOf("function-return", "function-parameter", "selected-parameter-unmatched", "variable")
private val INVENTORY_SHA = Regex("[0-9a-f]{64}")
private const val INVENTORY_COMMITMENT_ENCODING = "sha256-domain-kind-record-marker-u64be-length-canonical-json-end-marker-u64be-count-v1"
private val MANIFEST_KEYS = setOf("schema", "scannerProducer", "rawRecordEncoding", "commitmentEncoding", "typeGraphScope", "inputs",
    "requiredTypePopulationComplete", "rawCommitments", "inventoryCommitments", "counts", "inventorySha256")
private val INVENTORY_MANIFEST_LIMITS = StrictJsonLimits(maximumInputBytes = 1024 * 1024, maximumCanonicalBytes = 1024 * 1024,
    maximumNodes = 10_000, maximumStringBytes = 16_384, maximumTotalStringBytes = 512 * 1024)
