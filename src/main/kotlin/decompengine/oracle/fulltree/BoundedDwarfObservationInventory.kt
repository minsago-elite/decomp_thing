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
    const val SCHEMA = "dwarf-pre-policy-inventory-v2"
    val RECORD_KINDS: List<String> = Collections.unmodifiableList(listOf(
        "inventoryRoots", "inventoryReferences", "inventoryTypeCompleteness", "inventoryFindings", "inventorySelections",
    ))
    val RAW_RECORD_KINDS: List<String> = Collections.unmodifiableList(listOf(
        "metadata", "functions", "types", "typeChildren", "globals", "objectSymbols", "physicalUnits", "physicalDies", "strippedObjects",
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
        val physicalCensus = physicalCensusMetadata(facts)
        val physical = PhysicalCensusVerifier(physicalCensus, budget)
        val raw = ArrayList<JsonObject>()
        source.visitRaw { kind, records -> raw += commitRecords(kind, records, budget) { physical.observe(kind, it) } }
        physical.finish()
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
            "physicalCensus" to physicalCensus,
            "rawCommitments" to JsonArray(raw), "inventoryCommitments" to JsonArray(inventory), "counts" to counts.toJson(),
        ))
        val manifest = JsonObject(unsigned + ("inventorySha256" to JsonPrimitive(inventorySha(OracleJson.canonicalBytes(unsigned, INVENTORY_MANIFEST_LIMITS)))))
        return BoundedDwarfObservationInventory(source, OracleJson.canonicalBytes(manifest, INVENTORY_MANIFEST_LIMITS), limits)
    }

    fun verifier(manifest: JsonObject, limits: BoundedDwarfObservationInventoryLimits = BoundedDwarfObservationInventoryLimits()):
        BoundedDwarfObservationInventoryVerifier = BoundedDwarfObservationInventoryVerifier(manifest, limits)

    /** The caller authenticates the scan and input; this independently binds its physical census. */
    fun authenticatedVerifier(
        manifest: JsonObject,
        trustedFacts: BoundedDwarfInterfaceFacts,
        limits: BoundedDwarfObservationInventoryLimits = BoundedDwarfObservationInventoryLimits(),
    ): BoundedDwarfObservationInventoryVerifier {
        require(trustedFacts.physicalCensusPresent) { "authenticated scan has no physical census" }
        // Bind authentication and stream verification to one defensive snapshot of caller data.
        val bound = OracleJson.parseCanonical(OracleJson.canonicalBytes(manifest, INVENTORY_MANIFEST_LIMITS),
            INVENTORY_MANIFEST_LIMITS) as JsonObject
        val verifier = BoundedDwarfObservationInventoryVerifier(bound, limits)
        val budget = InventoryBudget(limits)
        val metadata = physicalCensusMetadata(trustedFacts)
        val physical = PhysicalCensusVerifier(metadata, budget)
        val commitments = LinkedHashMap<String, JsonObject>()
        trustedFacts.visitCanonicalRecordGroups { kind, records ->
            if (kind == "metadata" || kind == "physicalUnits" || kind == "physicalDies") {
                val normalized = if (kind == "metadata") records.map(::normalizeMetadata) else records
                val commitment = commitRecords(kind, normalized, budget) { physical.observe(kind, it) }
                if (kind != "metadata") commitments[kind] = commitment
            }
        }
        physical.finish()
        val rich = array(bound, "inputs").map(::obj).single { text(it, "role") == "rich" }
        require(rich["sha256"] == JsonPrimitive(trustedFacts.inputSha256) && rich["bytes"] == JsonPrimitive(trustedFacts.inputBytes)) {
            "inventory input differs from authenticated scan"
        }
        require(bound["physicalCensus"] == metadata) { "inventory physical census differs from authenticated scan" }
        val expected = readCommitments(bound, "rawCommitments", RAW_RECORD_KINDS + "strippedMetadata")
        require(commitments.all { (kind, commitment) -> expected[kind] == commitment }) {
            "inventory physical records differ from authenticated scan"
        }
        return verifier
    }
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
    private val physical: PhysicalCensusVerifier
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
        physical = PhysicalCensusVerifier(obj(boundManifest.getValue("physicalCensus")), budget)
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
            val encoded = budget.encode(normalized)
            // Charge canonical records before retaining compact structural descriptors.
            physical.observe(kind, normalized)
            committer.add(encoded)
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
        physical.finish()
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
            if (!facts.physicalCensusPresent) yield(finding("physical-census", "physical-census", "physical-census-absent"))
            for (die in facts.physicalDies) {
                budget.work()
                if (die.category == "unknown") yield(finding("physical-DIE", die.locator, "physical-DIE-tag-unresolved", "0x${die.tag.toString(16)}"))
                for (reference in die.references) {
                    budget.work()
                    if (reference.state != "retained-target") yield(finding("physical-reference", die.locator,
                        "physical-reference-${reference.state}", reference.attributeOrdinal.toString()))
                    if ("reference-cycle" in reference.reasons) yield(finding("physical-reference", die.locator,
                        "physical-reference-cycle", reference.attributeOrdinal.toString()))
                }
            }
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
    fun work(count: Long = 1L) {
        require(count >= 0)
        if (count > limits.maximumWorkSteps - steps) inventoryFail("traversal work exceeds bounds")
        steps += count
    }
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

private fun commitRecords(kind: String, records: Sequence<JsonObject>, budget: InventoryBudget,
                          observe: (JsonObject) -> Unit = {}): JsonObject =
    InventoryCommitter(kind).also { commitment -> records.forEach {
        val encoded = budget.encode(it)
        observe(it)
        commitment.add(encoded)
    } }.finish()

private fun physicalCensusMetadata(facts: BoundedDwarfInterfaceFacts): JsonObject = facts.physicalCensusJson()

/** Keeps identities and compact tree state, never raw JSON records or a second attribute graph. */
private class PhysicalCensusVerifier(metadata: JsonObject, private val budget: InventoryBudget) {
    private val boundMetadata = metadata
    private class UnitState(
        val locator: String, val compilationUnitOffset: Long, val firstDieOffset: Long, val endOffset: Long,
        val rootLocator: String, val physicalRecordCount: Long, val nullRecordCount: Long, val nonNullRecordCount: Long,
    ) {
        var observedDies = 0L
        var previousEndOffset = firstDieOffset
        var betweenNulls = 0L
        val parents = ArrayDeque<String>()
    }
    private val present: Boolean
    private val expectedUnits: Long
    private val expectedPhysical: Long
    private val expectedNulls: Long
    private val expectedNonNulls: Long
    private val units = LinkedHashMap<String, UnitState>()
    private val unitOrder = ArrayList<UnitState>()
    private val dies = HashSet<String>()
    // Repeated references to one target need one descriptor; mixed states still fail reconciliation.
    private val targetStates = HashMap<String, Int>()
    private var previousUnit: UnitState? = null
    private var currentUnit: UnitState? = null
    private var nextUnitOrdinal = 0
    private var summedPhysical = 0L
    private var summedNulls = 0L
    private var summedNonNulls = 0L
    private var metadataCounts: Pair<Long, Long>? = null

    init {
        exact(metadata, PHYSICAL_CENSUS_KEYS)
        require(metadata["schema"] == JsonPrimitive("bounded-physical-die-census-v1") &&
            metadata["scope"] == JsonPrimitive("all-non-null-physical-debug-info-DIEs") &&
            metadata["semanticPopulationComplete"] == JsonPrimitive(false) &&
            metadata["verificationBoundary"] == JsonPrimitive("authenticated-input-scan-replay-required;bundle-hashes-alone-are-not-coverage-proof")) {
            "unsupported physical census metadata"
        }
        present = boolean(metadata, "present")
        require(boolean(metadata, "complete") == present) { "physical census completeness differs from presence" }
        expectedUnits = number(metadata, "compilationUnitCount")
        expectedPhysical = number(metadata, "physicalRecordCount")
        expectedNulls = number(metadata, "nullRecordCount")
        expectedNonNulls = number(metadata, "nonNullRecordCount")
        require(expectedUnits <= budget.limits.maximumRecords && expectedNonNulls <= budget.limits.maximumRecords &&
            expectedPhysical <= budget.limits.maximumWorkSteps) { "physical census population exceeds bounds" }
        require(expectedNulls <= expectedPhysical && expectedNonNulls <= expectedPhysical &&
            expectedPhysical == expectedNulls + expectedNonNulls) { "physical census counts do not reconcile" }
        if (!present) require(expectedUnits == 0L && expectedPhysical == 0L) { "absent physical census has records" }
    }

    fun observe(kind: String, record: JsonObject) {
        when (kind) {
            "metadata" -> {
                require(metadataCounts == null) { "physical census raw metadata repeats" }
                require(record["physicalCensus"] == boundMetadata) { "raw metadata physical census differs from the manifest" }
                val counts = obj(record.getValue("recordCounts"))
                metadataCounts = number(counts, "physicalUnits") to number(counts, "physicalDies")
            }
            "physicalUnits" -> observeUnit(record)
            "physicalDies" -> observeDie(record)
        }
    }

    private fun observeUnit(record: JsonObject) {
        require(present) { "absent physical census contains a compilation unit" }
        exact(record, PHYSICAL_UNIT_KEYS)
        budget.work()
        val offset = physicalOffset(record, "compilationUnitOffset")
        val locator = text(record, "locator")
        val first = physicalOffset(record, "firstDieOffset")
        val end = physicalOffset(record, "endOffset")
        val root = text(record, "rootLocator")
        val physical = number(record, "physicalRecordCount")
        val nulls = number(record, "nullRecordCount")
        val nonNulls = number(record, "nonNullRecordCount")
        require(locator == unitLocator(offset) && root == dieLocator(offset, first)) { "physical compilation unit identity differs from offsets" }
        require(offset < first && first < end && (previousUnit == null || offset >= previousUnit!!.endOffset)) {
            "physical compilation unit ranges overlap or are reordered"
        }
        require(physical <= expectedPhysical && nulls <= physical && nonNulls in 1..physical && physical == nulls + nonNulls) {
            "physical compilation unit counts do not reconcile"
        }
        require(units.size.toLong() < expectedUnits && summedPhysical <= expectedPhysical - physical &&
            summedNulls <= expectedNulls - nulls && summedNonNulls <= expectedNonNulls - nonNulls) {
            "physical compilation unit counts exceed the census"
        }
        // Null records are not retained as DIE records, but their traversal consumes the same work budget.
        budget.work(nulls)
        val unit = UnitState(locator, offset, first, end, root, physical, nulls, nonNulls)
        require(units.putIfAbsent(locator, unit) == null) { "physical compilation unit locator repeats" }
        unitOrder += unit
        previousUnit = unit
        summedPhysical += physical; summedNulls += nulls; summedNonNulls += nonNulls
    }

    private fun observeDie(record: JsonObject) {
        require(present) { "absent physical census contains a DIE" }
        exact(record, PHYSICAL_DIE_KEYS)
        budget.work()
        val locator = text(record, "locator")
        val unitLocator = text(record, "compilationUnitLocator")
        val unit = units[unitLocator] ?: inventoryFail("physical DIE compilation unit is missing")
        if (currentUnit !== unit) {
            currentUnit?.let(::finishUnit)
            require(nextUnitOrdinal < unitOrder.size && unitOrder[nextUnitOrdinal] === unit) {
                "physical DIE compilation units are missing or reordered"
            }
            nextUnitOrdinal++
            currentUnit = unit
        }
        val offset = physicalOffset(record, "offset")
        val end = physicalOffset(record, "endOffset")
        val tag = physicalOffset(record, "tag")
        require(text(record, "category") == physicalCategory(tag)) { "physical DIE category differs from its tag" }
        val depth = number(record, "depth").also { require(it <= Int.MAX_VALUE) }.toInt()
        val parent = nullableText(record.getValue("parentLocator"))
        val children = boolean(record, "hasChildren")
        require(locator == dieLocator(unit.compilationUnitOffset, offset) && offset >= unit.firstDieOffset && end > offset && end <= unit.endOffset) {
            "physical DIE identity or range differs from its compilation unit"
        }
        require(unit.observedDies < unit.nonNullRecordCount && dies.add(locator)) { "physical DIE locator repeats or exceeds unit count" }
        if (unit.observedDies == 0L) {
            require(locator == unit.rootLocator && offset == unit.firstDieOffset && depth == 0 && parent == null) {
                "physical compilation unit root is missing or inconsistent"
            }
        } else {
            require(depth > 0 && depth <= unit.parents.size) { "physical DIE parent depth is inconsistent" }
            val closures = unit.parents.size - depth
            repeat(closures) { budget.work(); unit.parents.removeLast() }
            require(parent == unit.parents.lastOrNull()) { "physical DIE parent is missing or inconsistent" }
            requireNullBytes(offset - unit.previousEndOffset, closures.toLong())
            unit.betweenNulls = Math.addExact(unit.betweenNulls, closures.toLong())
        }
        if (children) unit.parents.addLast(locator)
        unit.observedDies++
        unit.previousEndOffset = end
        var previousOrdinal = -1L
        for (element in array(record, "references")) {
            budget.work()
            val reference = obj(element)
            exact(reference, PHYSICAL_REFERENCE_KEYS)
            val ordinal = number(reference, "attributeOrdinal")
            require(ordinal <= Int.MAX_VALUE && ordinal > previousOrdinal) { "physical reference attribute ordinals repeat or are reordered" }
            previousOrdinal = ordinal
            physicalOffset(reference, "attribute")
            val declared = physicalOffset(reference, "declaredForm")
            val resolved = physicalOffset(reference, "resolvedForm")
            val operand = physicalHex(reference, "rawOperand")
            val indirectDepth = number(reference, "indirectDepth")
            require(if (declared == FULL_TREE_DW_FORM_INDIRECT) indirectDepth in 1L..4L else declared == resolved && indirectDepth == 0L) {
                "physical reference declared and resolved forms differ"
            }
            require(resolved in PHYSICAL_REFERENCE_FORMS) { "physical reference uses a non-reference form" }
            val maximumOperand = when (resolved) {
                FULL_TREE_DW_FORM_REF1 -> 0xffUL
                FULL_TREE_DW_FORM_REF2 -> 0xffffUL
                FULL_TREE_DW_FORM_REF4, FULL_TREE_DW_FORM_REF_SUP4 -> 0xffffffffUL
                else -> ULong.MAX_VALUE
            }
            require(operand <= maximumOperand) { "physical reference operand exceeds its form width" }
            val target = nullableText(reference.getValue("targetLocator"))
            val state = text(reference, "state")
            val reasons = stringArray(reference, "reasons")
            val unsupported = resolved in PHYSICAL_UNSUPPORTED_REFERENCE_FORMS
            val derivedTarget = if (unsupported) null else referenceTarget(unit, resolved, operand)
            require(target == derivedTarget) { "physical reference target differs from its form and operand" }
            require(if (unsupported) state == "unsupported-reference" else if (target == null) state == "out-of-range-reference"
                else state == "retained-target" || state == "missing-target") { "physical reference state differs from its form and range" }
            require(reasons == (if (state == "retained-target") emptyList<String>() else listOf(state)) ||
                state == "retained-target" && reasons == listOf("reference-cycle")) { "physical reference reasons differ from its state" }
            when (state) {
                "retained-target", "missing-target" -> {
                    require(target != null && PHYSICAL_DIE_LOCATOR.matches(target)) { "physical reference target identity is missing or malformed" }
                    if (state == "missing-target") require(reasons.isNotEmpty()) { "missing physical reference target has no reason" }
                    targetStates[target] = (targetStates[target] ?: 0) or if (state == "retained-target") 1 else 2
                }
                "unsupported-reference", "out-of-range-reference" -> require(target == null && reasons.isNotEmpty()) {
                    "unresolved physical reference has a target or no reason"
                }
                else -> inventoryFail("unsupported physical reference state")
            }
        }
    }

    private fun referenceTarget(unit: UnitState, form: Long, operand: ULong): String? {
        if (operand > Long.MAX_VALUE.toULong()) return null
        val raw = operand.toLong()
        if (form != FULL_TREE_DW_FORM_REF_ADDR) {
            if (raw > Long.MAX_VALUE - unit.compilationUnitOffset) return null
            val offset = unit.compilationUnitOffset + raw
            return if (offset in unit.firstDieOffset until unit.endOffset) dieLocator(unit.compilationUnitOffset, offset) else null
        }
        var low = 0
        var high = unitOrder.lastIndex
        while (low <= high) {
            budget.work()
            val middle = low + (high - low) / 2
            val candidate = unitOrder[middle]
            when {
                raw < candidate.firstDieOffset -> high = middle - 1
                raw >= candidate.endOffset -> low = middle + 1
                else -> return dieLocator(candidate.compilationUnitOffset, raw)
            }
        }
        return null
    }

    private fun finishUnit(unit: UnitState) {
        require(unit.observedDies == unit.nonNullRecordCount) { "physical compilation unit DIE count differs from its records" }
        require(unit.betweenNulls <= unit.nullRecordCount) { "physical compilation unit null count is inconsistent" }
        val remaining = unit.nullRecordCount - unit.betweenNulls
        require(remaining >= unit.parents.size.toLong()) { "physical compilation unit tree is unterminated" }
        // The parser admits trailing null records and up to ten bytes per zero ULEB128 operand.
        requireNullBytes(unit.endOffset - unit.previousEndOffset, remaining)
        unit.parents.clear()
    }

    fun finish() {
        currentUnit?.let(::finishUnit)
        require(units.size.toLong() == expectedUnits && nextUnitOrdinal == units.size &&
            dies.size.toLong() == expectedNonNulls && summedPhysical == expectedPhysical &&
            summedNulls == expectedNulls && summedNonNulls == expectedNonNulls) { "physical census counts differ from its records" }
        require(metadataCounts == (expectedUnits to expectedNonNulls)) { "raw metadata physical counts differ from the census" }
        for ((target, states) in targetStates) {
            budget.work()
            require(states == if (target in dies) 1 else 2) { "physical reference state differs from target availability" }
        }
    }

    private fun requireNullBytes(bytes: Long, count: Long) {
        require(bytes >= count && bytes <= Math.multiplyExact(count, 10L)) { "physical DIE byte gaps differ from null-record counts" }
    }
}

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
        "recordCounts", "ordering", "objectLayout", "typeChildEncoding", "typePromotedFactFallbacks", "typePromotedFactRule", "physicalCensus")
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
private fun boolean(value: JsonObject, key: String): Boolean = (value[key] as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull
    ?: inventoryFail("expected $key boolean")
private fun physicalHex(value: JsonObject, key: String): ULong {
    val encoded = text(value, key)
    require(PHYSICAL_HEX.matches(encoded)) { "physical $key is not canonical hexadecimal" }
    return encoded.removePrefix("0x").toULongOrNull(16) ?: inventoryFail("physical $key exceeds unsigned range")
}
private fun physicalOffset(value: JsonObject, key: String): Long = physicalHex(value, key).let {
    require(it <= Long.MAX_VALUE.toULong()) { "physical $key exceeds offset range" }
    it.toLong()
}
private fun unitLocator(offset: Long): String = ".debug_info:cu=0x${offset.toString(16)}"
private fun dieLocator(unit: Long, offset: Long): String = "${unitLocator(unit)}:die=0x${offset.toString(16)}"
private fun inventoryFail(message: String): Nothing = throw FullTreeControlException("DWARF observation inventory: $message")
private val ROOT_KINDS = setOf("function-return", "function-parameter", "selected-parameter-unmatched", "variable")
private val INVENTORY_SHA = Regex("[0-9a-f]{64}")
private const val INVENTORY_COMMITMENT_ENCODING = "sha256-domain-kind-record-marker-u64be-length-canonical-json-end-marker-u64be-count-v1"
private val MANIFEST_KEYS = setOf("schema", "scannerProducer", "rawRecordEncoding", "commitmentEncoding", "typeGraphScope", "inputs",
    "requiredTypePopulationComplete", "physicalCensus", "rawCommitments", "inventoryCommitments", "counts", "inventorySha256")
private val PHYSICAL_CENSUS_KEYS = setOf("schema", "present", "complete", "scope", "compilationUnitCount", "physicalRecordCount",
    "nullRecordCount", "nonNullRecordCount", "semanticPopulationComplete", "verificationBoundary")
private val PHYSICAL_UNIT_KEYS = setOf("locator", "compilationUnitOffset", "firstDieOffset", "endOffset", "rootLocator",
    "physicalRecordCount", "nullRecordCount", "nonNullRecordCount")
private val PHYSICAL_DIE_KEYS = setOf("locator", "compilationUnitLocator", "offset", "endOffset", "tag", "category", "depth",
    "parentLocator", "hasChildren", "references")
private val PHYSICAL_REFERENCE_KEYS = setOf("attributeOrdinal", "attribute", "declaredForm", "resolvedForm", "indirectDepth",
    "rawOperand", "targetLocator", "state", "reasons")
private val PHYSICAL_UNSUPPORTED_REFERENCE_FORMS = setOf(FULL_TREE_DW_FORM_REF_SIG8, FULL_TREE_DW_FORM_REF_SUP4, FULL_TREE_DW_FORM_REF_SUP8)
private val PHYSICAL_REFERENCE_FORMS = setOf(FULL_TREE_DW_FORM_REF_ADDR, FULL_TREE_DW_FORM_REF1, FULL_TREE_DW_FORM_REF2,
    FULL_TREE_DW_FORM_REF4, FULL_TREE_DW_FORM_REF8, FULL_TREE_DW_FORM_REF_UDATA) + PHYSICAL_UNSUPPORTED_REFERENCE_FORMS
private val PHYSICAL_HEX = Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")
private val PHYSICAL_DIE_LOCATOR = Regex("\\.debug_info:cu=0x(?:0|[1-9a-f][0-9a-f]{0,15}):die=0x(?:0|[1-9a-f][0-9a-f]{0,15})")
private val INVENTORY_MANIFEST_LIMITS = StrictJsonLimits(maximumInputBytes = 1024 * 1024, maximumCanonicalBytes = 1024 * 1024,
    maximumNodes = 10_000, maximumStringBytes = 16_384, maximumTotalStringBytes = 512 * 1024)
