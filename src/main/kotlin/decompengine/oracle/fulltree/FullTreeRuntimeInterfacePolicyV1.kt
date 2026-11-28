package decompengine.oracle.fulltree

import decompengine.analysis.AnalysisDeadline
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*
import java.util.Collections
import java.util.LinkedHashSet

internal class ExternalBoundaryFindingV1(
    val code: String,
    val category: String,
    val stageId: String? = null,
    val occurrenceId: String? = null,
    evidenceRefs: List<String> = emptyList(),
) {
    init { require(evidenceRefs.size <= 65536); boundedConstructorStrings(listOf(code,category)+listOfNotNull(stageId,occurrenceId)+evidenceRefs) }
    val evidenceRefs: List<String> = Collections.unmodifiableList(evidenceRefs.toList())
    fun copy(evidenceRefs: List<String> = this.evidenceRefs) = ExternalBoundaryFindingV1(code,category,stageId,occurrenceId,evidenceRefs)
}

internal class ExternalBoundaryBudgetV1(
    val limits: ExternalProviderLimitsV1,
    private val parent: AnalysisDeadline,
) {
    private var work = 0L
    private var retainedBytes = 0L
    private var retainedRecords = 0L
    fun checkpoint(stage: String, units: Long = 1) {
        parent.checkpoint(stage)
        require(units >= 0 && work <= limits.maximumWorkUnits - units) { "external boundary work limit exceeded" }
        work += units
    }
    fun retain(bytes: Long, records: Long = 0, stage: String = "external boundary retention") {
        checkpoint("before $stage")
        require(bytes >= 0 && bytes <= limits.maximumDocumentBytes.toLong() &&
            retainedBytes <= limits.maximumDocumentBytes.toLong() - bytes) { "retained output byte ceiling exceeded" }
        require(records >= 0 && records <= limits.maximumReferencesAndEvents.toLong() &&
            retainedRecords <= limits.maximumReferencesAndEvents.toLong() - records) { "aggregate record ceiling exceeded" }
        retainedBytes += bytes
        retainedRecords += records
    }
    fun reserveOutputHeadroom(bytes: Long, stage: String) { retain(bytes,stage=stage) }
    fun jsonLimits(input: Int = limits.maximumDocumentBytes) = StrictJsonLimits(
        maximumInputBytes = minOf(input, limits.maximumDocumentBytes),
        maximumCanonicalBytes = limits.maximumDocumentBytes,
        maximumDepth = limits.maximumDepth, maximumNodes = limits.maximumNodes,
        maximumStringBytes = limits.maximumStringBytes, maximumTotalStringBytes = limits.maximumTotalStringBytes,
    )
}

internal data class ExternalProviderLimitsV1(
    val maximumDocumentBytes: Int = 4 * 1024 * 1024,
    val maximumAggregateInputBytes: Int = 8 * 1024 * 1024,
    val maximumDepth: Int = 32,
    val maximumNodes: Int = 100_000,
    val maximumStringBytes: Int = 16 * 1024,
    val maximumTotalStringBytes: Int = 2 * 1024 * 1024,
    val maximumProviders: Int = 1024,
    val maximumTools: Int = 256,
    val maximumStages: Int = 4096,
    val maximumRequirements: Int = 16_384,
    val maximumReferencesAndEvents: Int = 65_536,
    val maximumClauses: Int = 4096,
    val maximumFindings: Int = 16_384,
    val maximumWorkUnits: Long = 10_000_000,
) {
    init {
        require(maximumDocumentBytes in 1..4 * 1024 * 1024)
        require(maximumAggregateInputBytes in 1..8 * 1024 * 1024)
        require(maximumDepth in 1..32 && maximumNodes in 1..100_000)
        require(maximumStringBytes in 1..16 * 1024 && maximumTotalStringBytes in 1..2 * 1024 * 1024)
        require(maximumProviders in 1..1024 && maximumTools in 1..256 && maximumStages in 1..4096)
        require(maximumRequirements in 1..16_384 && maximumReferencesAndEvents in 1..65_536)
        require(maximumClauses in 1..4096 && maximumFindings in 1..16_384)
        require(maximumWorkUnits in 1..10_000_000)
    }
}

internal class RuntimeInterfaceClauseV1(
    val id: String, val category: String, val subjectOwner: String,
    operations: Set<String>, targets: Set<String>, inputs: Set<String>,
    val observableResultPolicy: String, evidenceRefs: List<String>, budget: ExternalBoundaryBudgetV1? = null,
) {
    init {
        require(operations.size.toLong()+targets.size+inputs.size+evidenceRefs.size <= (budget?.limits?.maximumReferencesAndEvents ?: 65536))
        boundedConstructorStrings(listOf(id,category,subjectOwner,observableResultPolicy)+operations+targets+inputs+evidenceRefs,budget)
    }
    val operations: Set<String> = Collections.unmodifiableSet(LinkedHashSet(operations))
    val targets: Set<String> = Collections.unmodifiableSet(LinkedHashSet(targets))
    val inputs: Set<String> = Collections.unmodifiableSet(LinkedHashSet(inputs))
    val evidenceRefs: List<String> = Collections.unmodifiableList(evidenceRefs.toList())
}

internal class RuntimeInterfacePolicyV1 internal constructor(clauses: List<RuntimeInterfaceClauseV1>) {
    init { require(clauses.size <= 4096); require(clauses.sumOf { it.operations.size.toLong()+it.targets.size+it.inputs.size+it.evidenceRefs.size } <= 65536) }
    val clauses: List<RuntimeInterfaceClauseV1> = Collections.unmodifiableList(clauses.toList())
}

internal data class RecordedRuntimeInterfaceUseV1(
    val id: String, val category: String, val subjectOwner: String,
    val operation: String, val target: String, val input: String, val result: String,
) { init { boundedConstructorStrings(listOf(id,category,subjectOwner,operation,target,input,result)) } }

internal class RecordedRuntimeInterfacesV1 internal constructor(uses: List<RecordedRuntimeInterfaceUseV1>, trace: JsonObject? = null, budget: ExternalBoundaryBudgetV1? = null) {
    val trace: JsonObject? = trace?.let { BoundaryOwnedSnapshotV1(byteArrayOf(),listOf(it),budget).json.single().jsonObject }
    init { require(uses.size <= 65536); uses.forEach { boundedConstructorStrings(listOf(it.id,it.category,it.subjectOwner,it.operation,it.target,it.input,it.result),budget) } }
    val uses: List<RecordedRuntimeInterfaceUseV1> = Collections.unmodifiableList(uses.toList())
}

internal object FullTreeRuntimeInterfacePolicyV1 {
    private val categories = setOf("filesystem", "process", "environment", "locale", "terminal", "time")
    private val clauseKeys = setOf("id", "category", "subjectOwner", "operations", "targets", "inputs", "observableResultPolicy", "evidenceRefs")
    private val useKeys = setOf("id", "category", "subjectOwner", "operation", "target", "input", "result")

    fun decode(bytes: ByteArray, budget: ExternalBoundaryBudgetV1): RuntimeInterfacePolicyV1 {
        budget.checkpoint("runtime-interface policy decode")
        require(bytes.size <= budget.limits.maximumDocumentBytes) { "runtime policy exceeds byte ceiling" }
        val root = OracleJson.parseCanonical(bytes, budget.jsonLimits(), budget::checkpoint) as? JsonObject
            ?: throw IllegalArgumentException("runtime policy must be an object")
        require(root.keys == setOf("schemaVersion", "kind", "clauses")) { "runtime policy keys differ from v1 schema" }
        require(root["schemaVersion"] == JsonPrimitive(1) && root["kind"] == JsonPrimitive("runtime-interface-policy-v1"))
        val arr = root["clauses"] as? JsonArray ?: throw IllegalArgumentException("clauses must be an array")
        require(arr.size <= budget.limits.maximumClauses) { "too many runtime policy clauses" }
        val nestedCount = arr.fold(0L) { total, item ->
            val row=item.jsonObject
            listOf("operations","targets","inputs","evidenceRefs").fold(total) { n,key -> Math.addExact(n,row[key]!!.jsonArray.size.toLong()) }
        }
        require(nestedCount <= budget.limits.maximumReferencesAndEvents)
        budget.retain(0,nestedCount,"runtime policy nested population admission")
        val clauses = arr.map { item ->
            budget.checkpoint("runtime-interface clause projection")
            val o = item as? JsonObject ?: throw IllegalArgumentException("clause must be an object")
            require(o.keys == clauseKeys) { "runtime clause keys differ from v1 schema" }
            val category = str(o, "category"); require(category in categories)
        RuntimeInterfaceClauseV1(str(o,"id"), category, str(o,"subjectOwner"), immutableSet(strings(o,"operations")),
                immutableSet(strings(o,"targets")), immutableSet(strings(o,"inputs")), str(o,"observableResultPolicy"),
                Collections.unmodifiableList(strictStrings(o,"evidenceRefs")), budget)
        }
        require(clauses.map { it.id }.toSet().size == clauses.size) { "duplicate clause identity" }
        budget.checkpoint("terminal runtime policy publication")
        return RuntimeInterfacePolicyV1(clauses)
    }

    internal fun decodeObserved(bytes: ByteArray, budget: ExternalBoundaryBudgetV1): RecordedRuntimeInterfacesV1 {
        budget.checkpoint("runtime-interface observations decode")
        require(bytes.size <= budget.limits.maximumDocumentBytes)
        val root = OracleJson.parseCanonical(bytes, budget.jsonLimits(), budget::checkpoint) as? JsonObject ?: error("observations must be object")
        require(root.keys == setOf("schemaVersion", "kind", "uses") || root.keys == setOf("schemaVersion", "kind", "uses", "trace"))
        require(root["schemaVersion"] == JsonPrimitive(1) && root["kind"] == JsonPrimitive("runtime-interface-observations-v1"))
        val arr = root["uses"] as? JsonArray ?: error("uses must be array")
        require(arr.size <= budget.limits.maximumReferencesAndEvents)
        budget.retain(0, arr.size.toLong(), "runtime interface event population")
        val uses = arr.map { item ->
            budget.checkpoint("runtime-interface event projection")
            val o = item as? JsonObject ?: error("use must be object"); require(o.keys == useKeys)
            val c = str(o,"category"); require(c in categories)
            RecordedRuntimeInterfaceUseV1(str(o,"id"), c, str(o,"subjectOwner"), str(o,"operation"), str(o,"target"), str(o,"input"), str(o,"result"))
        }
        require(uses.map { it.id }.toSet().size == uses.size) { "duplicate observed event identity" }
        budget.checkpoint("terminal runtime uses publication")
        val trace=root["trace"]?.let { it as? JsonObject ?: error("trace must be object") }
        if(trace != null) {
            require(trace.keys == setOf("buildRunId","graphActionId","firstSequence","lastSequence","eventCount","descendantsComplete","truncated","lostEvents"))
            str(trace,"buildRunId");str(trace,"graphActionId")
            for(key in listOf("firstSequence","lastSequence","eventCount","lostEvents")) require(trace[key] is JsonPrimitive && !trace[key]!!.jsonPrimitive.isString && trace[key]!!.jsonPrimitive.longOrNull?.let { it >= 0 } == true)
            for(key in listOf("descendantsComplete","truncated")) require(trace[key] is JsonPrimitive && !trace[key]!!.jsonPrimitive.isString && trace[key]!!.jsonPrimitive.booleanOrNull != null)
        }
        val result=RecordedRuntimeInterfacesV1(uses,trace,budget)
        budget.checkpoint("terminal runtime trace publication")
        return result
    }

    fun detect(policy: RuntimeInterfacePolicyV1, observed: RecordedRuntimeInterfacesV1, budget: ExternalBoundaryBudgetV1): List<ExternalBoundaryFindingV1> {
        budget.checkpoint("runtime detector population preflight")
        require(policy.clauses.size <= budget.limits.maximumClauses && observed.uses.size <= budget.limits.maximumReferencesAndEvents)
        val findings = mutableListOf<ExternalBoundaryFindingV1>()
        fun add(code: String, id: String? = null) {
            require(findings.size < budget.limits.maximumFindings) { "finding ceiling exceeded" }
            findings += ExternalBoundaryFindingV1(code, "consistency", occurrenceId = id)
        }
        val trace=observed.trace
        if(trace==null) {
            require(findings.size < budget.limits.maximumFindings)
            findings += ExternalBoundaryFindingV1("runtime-interface-trace-coverage-unavailable","qualification")
        } else {
            budget.checkpoint("runtime trace coverage reconciliation")
            val first=trace["firstSequence"]!!.jsonPrimitive.long;val last=trace["lastSequence"]!!.jsonPrimitive.long;val count=trace["eventCount"]!!.jsonPrimitive.long
            if(first != 0L || count != observed.uses.size.toLong() || last < first || last-first != count-1) add("runtime-trace-sequence-gap")
            if(trace["descendantsComplete"] != JsonPrimitive(true)) add("runtime-descendant-coverage-gap")
            if(trace["truncated"] != JsonPrimitive(false) || trace["lostEvents"] != JsonPrimitive(0)) add("runtime-trace-loss-or-truncation")
        }
        for (category in categories.sorted()) {
            budget.checkpoint("runtime-interface category reconciliation")
            val clauses = policy.clauses.filter { it.category == category }
            if (clauses.isEmpty()) add("missing-runtime-category:$category")
        }
        for (use in observed.uses) {
            budget.checkpoint("runtime-interface use reconciliation")
            budget.checkpoint("runtime-interface use candidate scan", policy.clauses.size.toLong())
            val permitted = policy.clauses.any { clause ->
                budget.checkpoint("runtime clause comparison",(use.operation.length+use.target.length+use.input.length).toLong())
                clause.category == use.category && clause.subjectOwner == use.subjectOwner &&
                    use.operation in clause.operations && use.target in clause.targets && use.input in clause.inputs &&
                    (clause.observableResultPolicy == "any" || clause.observableResultPolicy == use.result)
            }
            if (!permitted) add("undeclared-runtime-interface-use:${use.category}", use.id)
            if (use.category in setOf("process", "locale") && (use.target.contains('/') || use.input.contains('/')))
                add("runtime-${use.category}-namespace-binding-unavailable", use.id)
            if (forbiddenHostUse(use)) add("forbidden-host-interface-use:${use.category}", use.id)
        }
        // Every declared input is an expected use. A missing event is a consistency gap, not proof of absence.
        for (clause in policy.clauses) for (operation in clause.operations) for (target in clause.targets) for (input in clause.inputs) {
            budget.checkpoint("runtime-interface expected-use reconciliation")
            budget.checkpoint("runtime-interface expected-use cross join", observed.uses.size.toLong())
            if (observed.uses.none { budget.checkpoint("runtime expected-event comparison",(it.operation.length+it.target.length+it.input.length).toLong()); it.category == clause.category && it.subjectOwner == clause.subjectOwner &&
                    it.operation == operation && it.target == target && it.input == input })
                add("missing-expected-runtime-use:${clause.category}")
        }
        budget.checkpoint("terminal runtime findings publication")
        return Collections.unmodifiableList(findings.toList())
    }

    private fun forbiddenHostUse(use: RecordedRuntimeInterfaceUseV1): Boolean {
        val target = use.target.lowercase()
        val input = use.input.lowercase()
        return when (use.category) {
            "filesystem" -> target.startsWith("/") || target.split('/').any { it == ".." || it == "." } ||
                listOf("/home/", "/root/", "/proc/", "/sys/", "/dev/", "/run/").any { target.contains(it) }
            "process" -> target in setOf("sh", "bash", "/bin/sh", "/bin/bash", "path-search", "shell") || target.startsWith("-")
            "environment" -> target in setOf("ld_preload", "ld_audit", "ld_library_path", "cpath", "library_path") ||
                listOf("/home/", "/root/").any { input.contains(it) }
            "locale" -> target in setOf("/etc/locale.conf", "/etc/localtime", "/usr/share/locale") || input.startsWith("/etc/") || input.startsWith("/usr/share/locale")
            "terminal" -> target == "/dev/tty" || target.startsWith("/dev/pts/") || target == "controlling-terminal"
            "time" -> target in setOf("host-realtime-unbounded", "host-timezone-database")
            else -> true
        }
    }

    private fun str(o: JsonObject, key: String): String = (o[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
        ?.also { require(it.isNotEmpty() && it.length <= 16 * 1024 && it.none(Char::isISOControl)) } ?: error("$key must be a bounded string")
    private fun strings(o: JsonObject, key: String): Set<String> {
        val values = strictStrings(o,key)
        require(values.isNotEmpty() && values.all { it.isNotEmpty() && it.length <= 16 * 1024 && it.none(Char::isISOControl) })
        require(values.toSet().size == values.size) { "$key contains duplicate values" }
        return values.toSet()
    }
    private fun strictStrings(o: JsonObject, key: String): List<String> = (o[key] as? JsonArray ?: error("$key must be array")).map {
        (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content?.also { v -> require(v.isNotBlank() && v.none(Char::isISOControl)) } ?: error("$key elements must be strings")
    }
    private fun immutableSet(values: Set<String>): Set<String> = Collections.unmodifiableSet(LinkedHashSet(values))
}

internal fun boundarySha256(bytes: ByteArray, budget: ExternalBoundaryBudgetV1?): String {
    val digest=java.security.MessageDigest.getInstance("SHA-256")
    var at=0
    while(at < bytes.size) {
        val n=minOf(4096,bytes.size-at)
        budget?.checkpoint("external boundary hash chunk",n.toLong())
        if(Thread.currentThread().isInterrupted) throw InterruptedException("cancelled hash")
        digest.update(bytes,at,n); at+=n
    }
    budget?.checkpoint("external boundary hash terminal")
    return digest.digest().joinToString("") { (it.toInt() and 255).toString(16).padStart(2,'0') }
}

internal fun boundedConstructorStrings(values: Collection<String>, budget: ExternalBoundaryBudgetV1? = null) {
    require(values.size <= (budget?.limits?.maximumNodes ?: 100000))
    val visitor=BoundaryTreeV1(budget,false)
    visitor.array(null,values) { str(null,it) }
}
