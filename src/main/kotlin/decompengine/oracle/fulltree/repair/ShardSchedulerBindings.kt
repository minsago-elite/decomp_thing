package decompengine.oracle.fulltree.repair

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.repair.*
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.*

/** Lowerable codec policy, never a budget or permission supplied by an imported document. */
internal data class ShardSchedulerLimits(
    val json: StrictJsonLimits = StrictJsonLimits(16 * 1024 * 1024, 16 * 1024 * 1024, 24,
        1_000_000, 4096, 8 * 1024 * 1024, 19),
    val works: Int = 2048,
    val operations: Int = 4096,
    val events: Int = 16384,
    val modules: Int = 4096,
    val frozen: Int = 4096,
    val cases: Int = 4096,
    val roots: Int = 4096,
    val commands: Int = 64,
    val argv: Int = 256,
) {
    init {
        require(json.maximumInputBytes <= 16 * 1024 * 1024 && json.maximumCanonicalBytes <= 16 * 1024 * 1024 &&
            json.maximumDepth <= 24 && json.maximumNodes <= 1_000_000 && json.maximumStringBytes <= 4096 &&
            json.maximumTotalStringBytes <= 8 * 1024 * 1024 && json.maximumNumberCharacters <= 19)
        require(works in 0..2048 && operations in 0..4096 && events in 0..16384 && modules in 0..4096 &&
            frozen in 0..4096 && cases in 0..4096 && roots in 0..4096 && commands in 0..64 && argv in 0..256)
    }
}

/**
 * An immutable, schema-checked recorded value. The JSON-shaped constructor deliberately grants no
 * graph, receipt, planning, budget or execution authority. Every nested collection is copied and
 * frozen; existing validation objects are parsed by their owning codecs, not reimplemented here.
 */
internal class RecordedShardSchedulerHistory(value: JsonObject, limits: ShardSchedulerLimits = ShardSchedulerLimits()) {
    val record: JsonObject = schedulerChecked {
        // Bound caller-owned trees before recursive copying or set sorting.
        OracleJson.canonicalBytes(value, limits.json)
        val canonical = SchedulerSchema(limits, false).normalize(value)
        SchedulerSchema(limits, true).validate(canonical)
        freeze(canonical) as JsonObject
    }
}

/** Canonical recorded data only. Ingestion is not checkpoint authentication or resume authority. */
internal object ShardSchedulerBindings {
    fun encode(history: RecordedShardSchedulerHistory, limits: ShardSchedulerLimits = ShardSchedulerLimits()): ByteArray =
        schedulerChecked {
            SchedulerSchema(limits, true).validate(history.record)
            OracleJson.canonicalBytes(history.record, limits.json)
        }

    fun decode(bytes: ByteArray, limits: ShardSchedulerLimits = ShardSchedulerLimits()): RecordedShardSchedulerHistory =
        schedulerChecked {
            val value = OracleJson.parse(bytes, limits.json) as? JsonObject ?: invalid()
            SchedulerSchema(limits, true).validate(value)
            RecordedShardSchedulerHistory(value, limits)
        }

    fun commitmentSha256(history: RecordedShardSchedulerHistory, limits: ShardSchedulerLimits = ShardSchedulerLimits()): String =
        digest(encode(history, limits))
}

private inline fun <T> schedulerChecked(block: () -> T): T = try { block() } catch (_: IllegalArgumentException) {
    throw IllegalArgumentException("invalid recorded shard scheduler history")
} catch (_: IllegalStateException) {
    throw IllegalArgumentException("invalid recorded shard scheduler history")
} catch (_: NoSuchElementException) {
    throw IllegalArgumentException("invalid recorded shard scheduler history")
}
private fun invalid(): Nothing = throw IllegalArgumentException("invalid recorded shard scheduler history")
private fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
private fun hash(value: JsonElement): String = digest(OracleJson.canonicalBytes(value, ShardSchedulerLimits().json))
private fun identity(role: String, binding: JsonObject): String =
    (if (role == "external-invocation") "invocation" else role) + "-" + hash(JsonObject(mapOf(
        "domain" to JsonPrimitive("full-tree-shard-scheduler-v1/$role"), "binding" to binding)))
private fun freeze(value: JsonElement): JsonElement = when (value) {
    is JsonObject -> JsonObject(Collections.unmodifiableMap(value.mapValues { freeze(it.value) }))
    is JsonArray -> JsonArray(Collections.unmodifiableList(value.map(::freeze)))
    else -> value
}
private fun JsonElement.obj(): JsonObject = this as? JsonObject ?: invalid()
private fun JsonElement.text(): String = (this as? JsonPrimitive)?.takeIf { it.isString }?.content ?: invalid()
private fun JsonElement.number(): Long {
    val p = this as? JsonPrimitive ?: invalid()
    require(!p.isString && p.content.matches(Regex("0|[1-9][0-9]*")))
    return p.content.toLongOrNull() ?: invalid()
}
private fun JsonElement.bool(): Boolean = (this as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull ?: invalid()
private fun JsonObject.s(key: String) = getValue(key).text()
private fun JsonObject.n(key: String) = getValue(key).number()
private fun JsonObject.b(key: String) = getValue(key).bool()
private fun JsonObject.o(key: String) = getValue(key).obj()
private fun JsonObject.a(key: String) = getValue(key) as? JsonArray ?: invalid()
private fun JsonObject.nullable(key: String): JsonElement? = getValue(key).takeUnless { it == JsonNull }
private fun JsonObject.select(vararg keys: String) = JsonObject(keys.associateWith { getValue(it) })
private fun JsonObject.with(key: String, value: JsonElement) = JsonObject(this + (key to value))
private val codePoints = Comparator<String> { a, b ->
    val x = a.codePoints().iterator(); val y = b.codePoints().iterator()
    var result = 0
    while (x.hasNext() && y.hasNext() && result == 0) result = x.nextInt().compareTo(y.nextInt())
    if (result != 0) result else x.hasNext().compareTo(y.hasNext())
}
private val revision = Regex("(?:root_[0-9a-f]{24}|revision_[0-9]{8}_[0-9a-f]{16})")
private val attempt = Regex("revision_[0-9]{8}_[0-9a-f]{16}")
private val sha = Regex("[0-9a-f]{64}")
private val shard = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
private val module = Regex("cu-[0-9a-f]{32}")
private val budgetKeys = "modelCalls inputTokens outputTokens wallMillis patchBytes rebuilds"
private val dispositions = mapOf("legacy_unverified" to RepairAttemptDisposition.LEGACY_UNVERIFIED,
    "provisional" to RepairAttemptDisposition.PROVISIONAL, "rejected" to RepairAttemptDisposition.REJECTED,
    "fully_accepted" to RepairAttemptDisposition.FULLY_ACCEPTED)
private val statuses = mapOf("running" to RepairRunStatus.RUNNING, "fully_accepted" to RepairRunStatus.FULLY_ACCEPTED,
    "compile_valid" to RepairRunStatus.COMPILE_VALID, "no_changes" to RepairRunStatus.NO_CHANGES,
    "rejected" to RepairRunStatus.REJECTED, "iteration_exhausted" to RepairRunStatus.ITERATION_EXHAUSTED,
    "resource_exhausted" to RepairRunStatus.RESOURCE_EXHAUSTED, "cancelled" to RepairRunStatus.CANCELLED,
    "interrupted" to RepairRunStatus.INTERRUPTED, "validation_failed" to RepairRunStatus.VALIDATION_FAILED,
    "rollback_failed" to RepairRunStatus.ROLLBACK_FAILED)

private class SchedulerSchema(private val limits: ShardSchedulerLimits, private val reading: Boolean) {
    private fun fields(o: JsonObject, specification: String) {
        val pairs = specification.split(' ').filter { it.isNotEmpty() }.map { it.split(':') }
        require(o.keys == pairs.map { it[0] }.toSet())
        for ((key, type) in pairs) {
            val v = o.getValue(key)
            if (type.endsWith('?') && v == JsonNull) continue
            when (type.removeSuffix("?")) {
                "T" -> text(v)
                "D" -> require(sha.matches(v.text()))
                "N" -> v.number()
                "B" -> v.bool()
                "O" -> v.obj()
                "A" -> require(v is JsonArray)
                "R" -> require(revision.matches(v.text()))
                "I" -> require(attempt.matches(v.text()))
                "P" -> path(v.text())
                else -> invalid()
            }
        }
    }
    private fun text(v: JsonElement) {
        val s = v.text()
        require(s.isNotEmpty() && s.none { Character.isISOControl(it) })
    }
    private fun path(s: String, cwd: Boolean = false) {
        require(s.isNotEmpty() && !s.startsWith('/') && '\\' !in s && !Regex("^[A-Za-z]:").containsMatchIn(s) && s.none { Character.isISOControl(it) })
        require(cwd && s == "." || s.split('/').all { it.isNotEmpty() && it != "." && it != ".." })
    }
    private fun recursive(v: JsonElement) {
        when (v) {
            is JsonObject -> v.forEach { (k, child) ->
                if (child != JsonNull && (k == "path" || k.endsWith("Path"))) path(child.text())
                recursive(child)
            }
            is JsonArray -> v.forEach(::recursive)
            is JsonPrimitive -> if (v != JsonNull) {
                if (v.isString) text(v) else if (v.content !in setOf("true", "false")) v.number()
            }
        }
    }
    private fun array(o: JsonObject, key: String, cap: Int): JsonArray = o.a(key).also { require(it.size <= cap) }
    private fun sorted(v: JsonArray, compare: Comparator<JsonElement>): JsonArray {
        val ordered = v.sortedWith(compare)
        require(ordered.zipWithNext().all { (a, b) -> compare.compare(a, b) != 0 })
        if (reading) require(v == ordered)
        return JsonArray(ordered)
    }
    private fun strings(o: JsonObject, key: String, cap: Int) = sorted(array(o, key, cap), Comparator { a, b -> codePoints.compare(a.text(), b.text()) })
    private fun table(o: JsonObject, key: String, cap: Int, field: String) =
        sorted(array(o, key, cap), Comparator { a, b -> codePoints.compare(a.obj().s(field), b.obj().s(field)) })

    fun normalize(root: JsonObject): JsonObject {
        var result = root
        val works = array(root, "works", limits.works).map { element ->
            var w = element.obj()
            for ((key, cap) in listOf("moduleIds" to limits.modules, "retainedCaseIds" to limits.cases)) w = w.with(key, strings(w, key, cap))
            w = w.with("frozenInterfaces", table(w, "frozenInterfaces", limits.frozen, "interfaceId"))
            val ordering = w.o("ordering")
            w.with("ordering", ordering.with("rootDiagnosticKeys", strings(ordering, "rootDiagnosticKeys", limits.roots)))
        }
        result = result.with("works", JsonArray(works))
        result = result.with("works", table(result, "works", limits.works, "id"))
        val ops = array(root, "operations", limits.operations)
        result = result.with("operations", sorted(ops, Comparator { a, b ->
            val x = a.obj(); val y = b.obj()
            var c = codePoints.compare(x.s("workId"), y.s("workId"))
            if (c == 0) c = codePoints.compare(x.s("attemptId"), y.s("attemptId"))
            if (c == 0) c = x.n("ordinal").compareTo(y.n("ordinal"))
            if (c == 0) c = codePoints.compare(x.s("id"), y.s("id"))
            c
        }))
        val budgets = root.o("budgetLimits")
        result = result.with("budgetLimits", budgets.with("shards", table(budgets, "shards", limits.works, "shardId")))
        result = result.with("events", JsonArray(array(root, "events", limits.events).map {
            val e = it.obj()
            if (e.s("kind") != "decision_recorded") e else {
                val p = e.o("payload")
                e.with("payload", p.with("operationIds", strings(p, "operationIds", limits.operations)))
            }
        }))
        return result
    }

    fun validate(root: JsonObject) {
        // Canonical rendering checks bounded depth, nodes, strings and output even on constructor input.
        OracleJson.canonicalBytes(root, limits.json)
        recursive(root)
        fields(root, "schemaVersion:N kind:T binding:O budgetLimits:O works:A operations:A events:A")
        require(root.n("schemaVersion") == 1L && root.s("kind") == "full-tree-shard-scheduler-history")
        require(normalize(root) == root)
        val binding = root.o("binding")
        fields(binding, "repairRunId:T baselineRevisionId:R baselineSourceSha256:D profileSha256:D indexSha256:D regressionCorpusSha256:D expectedObservationsSha256:D? originalBinarySha256:D? boundedRunSha256:D boundedIndexArtifactSha256:D planningArtifactSha256:D planningReportSha256:D planningConfigurationSha256:D dependencyPlanSchema:N dependencyPlanSha256:D frozenInterfaceSchema:N frozenInterfaceSha256:D schedulerPolicySha256:D")
        require(binding.s("repairRunId").matches(Regex("run_[0-9]{8}")) && binding.n("dependencyPlanSchema") > 0 && binding.n("frozenInterfaceSchema") > 0)
        val works = root.a("works").map { it.obj() }
        require(works.isNotEmpty())
        works.forEach { work(it, binding) }
        val workMap = works.associateBy { it.s("id") }
        require(workMap.size == works.size)
        val budgets = root.o("budgetLimits")
        fields(budgets, "run:O shards:A"); budget(budgets.o("run"))
        val shards = budgets.a("shards").map { it.obj().also { s -> fields(s, "shardId:T limit:O"); budget(s.o("limit")); require(shard.matches(s.s("shardId"))) }.s("shardId") }
        require(shards.toSet() == works.map { it.s("shardId") }.toSet())
        val ops = root.a("operations").map { it.obj() }
        ops.forEach { operation(it, binding, workMap) }
        require(ops.map { it.s("id") }.distinct().size == ops.size)
        require(ops.map { it.s("attemptId") to it.n("ordinal") }.distinct().size == ops.size)
        require(ops.groupBy { it.s("attemptId") }.values.all { group -> group.map { it.s("workId") }.distinct().size == 1 })
        lifecycle(root.a("events"), binding, workMap, ops.associateBy { it.s("id") })
        validationDefinitions(works, root.a("events"))
    }

    /** One graph-owned call may be referenced repeatedly, but never redefined within a history. */
    private fun validationDefinitions(works: List<JsonObject>, events: List<JsonElement>) {
        val invocations = mutableMapOf<String, JsonObject>()
        val retained = mutableMapOf<String, JsonObject>()
        fun bind(invocation: JsonObject): String {
            val id = invocation.s("id")
            val previous = invocations.putIfAbsent(id, invocation)
            require(previous == null || previous == invocation)
            return id
        }
        works.forEach { bind(it.o("diagnostic").o("validationInvocation")) }
        for (element in events) {
            val event = element.obj()
            if (event.s("kind") != "validation_recorded") continue
            val payload = event.o("payload")
            val definition = (payload.nullable("observation") ?: payload.getValue("diagnostic")).obj()
            val id = bind(definition.o("invocation"))
            // Keep the tagged payload so an observation cannot replace a failure diagnostic.
            val previous = retained.putIfAbsent(id, payload)
            require(previous == null || previous == payload)
        }
    }

    private fun budget(o: JsonObject) = fields(o, budgetKeys.split(' ').joinToString(" ") { "$it:N" })
    private fun artifact(o: JsonObject) { fields(o, "sha256:D bytes:N"); require(o.n("bytes") > 0) }
    private fun invocation(o: JsonObject, binding: JsonObject): RepairValidationInvocation = parseRepairValidationInvocation(o).also {
        require(it.runId == binding.s("repairRunId") && it.profileSha256 == binding.s("profileSha256") &&
            it.indexSha256 == binding.s("indexSha256") && it.regressionCorpusSha256 == binding.s("regressionCorpusSha256"))
    }

    private fun work(w: JsonObject, binding: JsonObject) {
        fields(w, "id:T shardId:T shardInputSha256:D moduleIds:A diagnostic:O sourceRevisionSha256:D canonicalParentId:R speculativeParentId:R acceptedParentId:R? dependencyPlanSha256:D dependencyGeneration:N frozenInterfaceSha256:D frozenGeneration:N planTransitionSha256:D? frozenInterfaces:A ordering:O retainedCaseIds:A oscillationKeySha256:D?")
        require(shard.matches(w.s("shardId")))
        require(w.a("moduleIds").isNotEmpty() && w.a("moduleIds").all { module.matches(it.text()) })
        w.a("frozenInterfaces").forEach {
            val f = it.obj()
            fields(f, "interfaceId:T version:N bytesSha256:D producerRevisionId:R invalidationTransactionSha256:D?")
        }
        for ((key, generation) in listOf("dependencyPlanSha256" to "dependencyGeneration", "frozenInterfaceSha256" to "frozenGeneration")) {
            if (w.n(generation) == 0L) require(w[key] == binding[key])
            if (w[key] != binding[key]) require(w.n(generation) > 0 && w.nullable("planTransitionSha256") != null)
        }
        val ordering = w.o("ordering")
        fields(ordering, "policySha256:D graphSha256:D componentId:T dependencyRank:N failureClassRank:N downstreamImpact:N rootDiagnosticKeys:A impactSetSha256:D retainedRegressionSetSha256:D assessmentSha256:D?")
        require(ordering["graphSha256"] == w["dependencyPlanSha256"] && ordering["policySha256"] == binding["schedulerPolicySha256"])
        require(ordering.a("rootDiagnosticKeys").all { it.text().matches(Regex("diagnostic-[0-9a-f]{64}")) })
        val d = w.o("diagnostic")
        fields(d, "key:T occurrenceId:T normalizerSha256:D stage:T toolIdentitySha256:D normalizedKeySha256:D validationInvocation:O evidence:O ownerModuleId:T sourcePath:P?")
        require(d.s("stage") in setOf("compile", "link") && d["ownerModuleId"] in w.a("moduleIds"))
        artifact(d.o("evidence"))
        if (w["speculativeParentId"] == binding["baselineRevisionId"]) require(w["sourceRevisionSha256"] == binding["baselineSourceSha256"])
        val observed = invocation(d.o("validationInvocation"), binding)
        require(observed.sourceRevisionSha256 == w.s("sourceRevisionSha256") && observed.candidateRevisionId == w.s("speculativeParentId"))
        require(d.s("key") == identity("diagnostic", d.select("normalizerSha256", "stage", "toolIdentitySha256", "normalizedKeySha256")))
        val occurrence = d.select("key", "validationInvocation", "ownerModuleId") + mapOf(
            "shardId" to w.getValue("shardId"), "planningArtifactSha256" to binding.getValue("planningArtifactSha256"),
            "dependencyPlanSha256" to w.getValue("dependencyPlanSha256"))
        require(d.s("occurrenceId") == identity("diagnostic-occurrence", JsonObject(occurrence)))
        val workIdentity = w.filterKeys { it !in setOf("id", "diagnostic") } + mapOf(
            "repairRunId" to binding.getValue("repairRunId"), "boundedRunSha256" to binding.getValue("boundedRunSha256"),
            "diagnosticOccurrenceId" to d.getValue("occurrenceId"))
        require(w.s("id") == identity("work", JsonObject(workIdentity)))
    }

    private fun operation(op: JsonObject, binding: JsonObject, works: Map<String, JsonObject>) {
        fields(op, "id:T workId:T attemptId:I ordinal:N kind:T requestSha256:D promptSha256:D? contextInputsSha256:D toolIdentitySha256:D accessPolicySha256:D sandboxPolicySha256:D factoryConfigurationSha256:D? modelConfigurationSha256:D? verificationCommands:A reservation:O")
        require(op.n("ordinal") > 0 && op.s("kind") in setOf("model", "rebuild"))
        val work = works[op.s("workId")] ?: invalid()
        require(listOf("canonicalParentId", "speculativeParentId", "acceptedParentId").none { work[it] == op["attemptId"] })
        val idBinding = op.select("workId", "attemptId", "ordinal", "kind").with("repairRunId", binding.getValue("repairRunId"))
        require(op.s("id") == identity("external-invocation", idBinding))
        val commands = array(op, "verificationCommands", limits.commands)
        commands.forEach {
            val c = it.obj(); fields(c, "argv:A cwd:T environmentSha256:D toolIdentitySha256:D")
            require(array(c, "argv", limits.argv).isNotEmpty()); c.a("argv").forEach(::text); path(c.s("cwd"), true)
        }
        val r = op.o("reservation"); budget(r)
        if (op.s("kind") == "model") {
            require(listOf("promptSha256", "factoryConfigurationSha256", "modelConfigurationSha256").all { op.nullable(it) != null })
            require(commands.isEmpty() && r.n("modelCalls") == 1L && r.n("rebuilds") == 0L)
        } else {
            require(listOf("promptSha256", "factoryConfigurationSha256", "modelConfigurationSha256").all { op.nullable(it) == null })
            require(commands.isNotEmpty() && r.n("rebuilds") == 1L &&
                listOf("modelCalls", "inputTokens", "outputTokens", "patchBytes").all { r.n(it) == 0L })
        }
    }

    private fun acp(o: JsonObject): RepairAgentInvocationBinding {
        fields(o, "receiptPath:P receiptSha256:D receiptSchemaVersion:N requestSha256:D resultChangesSha256:D terminalOutcome:T receiptReleaseComplete:B assessmentStatus:T")
        val assessment = mapOf("pending" to RepairAgentAssessmentStatus.PENDING, "accepted" to RepairAgentAssessmentStatus.ACCEPTED,
            "rejected" to RepairAgentAssessmentStatus.REJECTED, "provisional" to RepairAgentAssessmentStatus.PROVISIONAL)[o.s("assessmentStatus")] ?: invalid()
        require(o.n("receiptSchemaVersion") == 2L)
        return RepairAgentInvocationBinding(o.s("receiptPath"), o.s("receiptSha256"), 2, o.s("requestSha256"),
            o.s("resultChangesSha256"), o.s("terminalOutcome"), o.b("receiptReleaseComplete"), assessment)
    }
    private fun session(o: JsonObject, op: JsonObject) {
        fields(o, "implementationId:T implementationVersion:T sdkVersion:T protocolVersion:N agentIdentitySha256:D sessionIdSha256:D resumeReferenceSha256:D? turnOrdinal:N requestSha256:D eventsSha256:D observedEventCount:N retainedEventCount:N eventsComplete:B policyAuditsSha256:D sandboxEvidenceSha256:D")
        require(o.n("protocolVersion") == 1L && o.n("turnOrdinal") > 0 && o["requestSha256"] == op["requestSha256"])
        require(o.n("retainedEventCount") <= o.n("observedEventCount"))
        if (o.b("eventsComplete")) require(o.n("retainedEventCount") == o.n("observedEventCount"))
    }

    private enum class Phase { DEFINED, RESERVED, INTENT, NOT_DISPATCHED, RECOVERED, UNKNOWN, RECEIPT, VALIDATED, SETTLED, RELEASED, VIOLATION }
    private class OperationState(val op: JsonObject) {
        var phase = Phase.DEFINED
        var receipt: JsonObject? = null
        var observation: RepairValidationObservation? = null
        var diagnostic: RepairValidationDiagnosticBinding? = null
        var blocked = false
        var unknownNeedsBlock = false
    }
    private fun resume(r: JsonObject, workId: String, states: Map<String, OperationState>): String {
        fields(r, "disposition:T operationId:T? evidenceSha256:D?")
        val disposition = r.s("disposition")
        require(disposition in setOf("none", "dispatch_same_id", "reconcile_same_id", "validate_retained", "reconcile_graph", "blocked"))
        val id = r.nullable("operationId")?.text()
        val state = id?.let { states[it] ?: invalid() }
        require(state == null || state.op.s("workId") == workId)
        if (disposition == "none") require(id == null && r.nullable("evidenceSha256") == null)
        else require(r.nullable("evidenceSha256") != null)
        when (disposition) {
            "dispatch_same_id" -> require(state?.phase in setOf(Phase.RESERVED, Phase.NOT_DISPATCHED))
            "reconcile_same_id" -> require(state?.phase in setOf(Phase.INTENT, Phase.UNKNOWN, Phase.RECOVERED))
            "validate_retained" -> require(state?.phase == Phase.RECEIPT)
            "reconcile_graph" -> require(state == null || state.phase in setOf(Phase.VALIDATED, Phase.SETTLED))
        }
        return disposition
    }

    private fun lifecycle(events: JsonArray, binding: JsonObject, works: Map<String, JsonObject>, ops: Map<String, JsonObject>) {
        require(events.isNotEmpty())
        val states = ops.mapValues { OperationState(it.value) }
        val prepared = mutableSetOf<String>()
        val blockedWorks = mutableSetOf<String>()
        val decisions = mutableSetOf<String>()
        val lastReservedOrdinal = mutableMapOf<String, Long>()
        var previous: String? = null
        var lastDecision: JsonObject? = null
        var finished = false
        var violation = false
        var terminalDecision: String? = null
        for ((index, element) in events.withIndex()) {
            require(!finished)
            val e = element.obj()
            fields(e, "sequence:N previousSha256:D? workId:T operationId:T? kind:T payload:O")
            require(e.n("sequence") == index.toLong() && e.nullable("previousSha256")?.text() == previous)
            previous = hash(e)
            val workId = e.s("workId"); val work = works[workId] ?: invalid()
            val opId = e.nullable("operationId")?.text()
            val st = opId?.let { states[it] ?: invalid() }
            require(st == null || st.op.s("workId") == workId)
            val kind = e.s("kind"); val p = e.o("payload")
            if (terminalDecision != null) require(kind == "run_finished")
            if (st?.unknownNeedsBlock == true) require(kind in setOf("blocked", "settled"))
            if (kind != "prepared") require(workId in prepared)
            if (workId in blockedWorks || st?.blocked == true) require(kind in setOf("blocked", "resume_recorded", "reconciled", "run_finished"))
            if (violation) require(kind in setOf("blocked", "run_finished", "resume_recorded"))
            if (st != null && st.op.s("attemptId") in decisions) require(kind in setOf("blocked", "resume_recorded"))
            when (kind) {
                "prepared" -> {
                    fields(p, "graphSha256:D"); require(st == null && prepared.add(workId))
                }
                "reserved" -> {
                    fields(p, ""); require(st != null && st.phase == Phase.DEFINED && !violation)
                    val attemptId = st.op.s("attemptId"); val ordinal = st.op.n("ordinal")
                    require(ordinal > (lastReservedOrdinal[attemptId] ?: 0L))
                    require(states.values.none { it !== st && it.op.s("attemptId") == attemptId &&
                        it.phase !in setOf(Phase.DEFINED, Phase.SETTLED, Phase.RELEASED) })
                    lastReservedOrdinal[attemptId] = ordinal; st.phase = Phase.RESERVED
                }
                "dispatch_intent" -> {
                    fields(p, "journalBindingSha256:D"); require(st != null && st.phase in setOf(Phase.RESERVED, Phase.NOT_DISPATCHED) && !violation)
                    st.phase = Phase.INTENT
                }
                "reconciled" -> {
                    fields(p, "result:T evidenceSha256:D"); require(st != null && st.phase in setOf(Phase.INTENT, Phase.UNKNOWN))
                    st.phase = when (p.s("result")) {
                        "not_dispatched" -> Phase.NOT_DISPATCHED
                        "receipt_recovered" -> Phase.RECOVERED
                        "unknown" -> Phase.UNKNOWN
                        else -> invalid()
                    }
                    st.unknownNeedsBlock = st.phase == Phase.UNKNOWN
                    st.blocked = false; blockedWorks.remove(workId)
                }
                "resume_recorded" -> {
                    fields(p, "resume:O"); val r = p.o("resume")
                    require(e["operationId"] == r["operationId"])
                    val disposition = resume(r, workId, states)
                    require(disposition != "none")
                    if (disposition != "blocked") { st?.blocked = false; blockedWorks.remove(workId) }
                }
                "receipt_recorded" -> {
                    fields(p, "receipt:O acp:O? session:O? providerOutcome:T")
                    require(st != null && st.phase in setOf(Phase.INTENT, Phase.RECOVERED))
                    artifact(p.o("receipt"))
                    if (st.op.s("kind") == "model") {
                        val receipt = acp(p.o("acp"))
                        require(receipt.requestSha256 == st.op.s("requestSha256") && receipt.receiptSha256 == p.o("receipt").s("sha256") &&
                            receipt.terminalOutcome == p.s("providerOutcome"))
                    } else {
                        require(p.nullable("acp") == null && p.nullable("session") == null && p.s("providerOutcome") in setOf(
                            "compile_failed", "compile_valid", "behavior_checked", "validation_failed", "cleanup_unverified"))
                    }
                    p.nullable("session")?.let { session(it.obj(), st.op) }
                    st.receipt = p; st.phase = Phase.RECEIPT
                }
                "validation_recorded" -> {
                    fields(p, "observation:O? diagnostic:O?")
                    require(st != null && st.phase == Phase.RECEIPT && st.op.s("kind") == "rebuild")
                    require((p.nullable("observation") != null) != (p.nullable("diagnostic") != null))
                    val receipt = requireNotNull(st.receipt).o("receipt")
                    val validation: RepairValidationInvocation
                    if (p.nullable("observation") != null) {
                        val observation = parseRepairValidationObservation(p.o("observation")); st.observation = observation
                        validation = observation.invocation
                        require(observation.primary.sha256 == receipt.s("sha256") && observation.primary.bytes == receipt.n("bytes"))
                        require(requireNotNull(st.receipt).s("providerOutcome") == p.o("observation").s("outcome"))
                        if (observation.proof.originalBinarySha256 != null) require(observation.proof.originalBinarySha256 == binding.nullable("originalBinarySha256")?.text())
                    } else {
                        val diagnostic = parseRepairValidationDiagnosticBinding(p.o("diagnostic")); st.diagnostic = diagnostic
                        validation = diagnostic.invocation
                        require(diagnostic.receiptSha256 == receipt.s("sha256") && diagnostic.receiptBytes == receipt.n("bytes"))
                        require(requireNotNull(st.receipt).s("providerOutcome") == if (diagnostic.cleanupVerified) "validation_failed" else "cleanup_unverified")
                    }
                    invocation(validation.toJsonObject(), binding)
                    require(validation.candidateRevisionId == st.op.s("attemptId"))
                    st.phase = Phase.VALIDATED
                }
                "settled" -> {
                    fields(p, "spent:O usageKnown:B evidenceSha256:D"); require(st != null)
                    val normal = if (st.op.s("kind") == "model") Phase.RECEIPT else Phase.VALIDATED
                    require(st.phase == normal || st.phase == Phase.UNKNOWN)
                    budget(p.o("spent"))
                    if (!p.b("usageKnown")) require(p["spent"] == st.op["reservation"])
                    if (st.phase == Phase.UNKNOWN) require(!p.b("usageKnown"))
                    require(budgetKeys.split(' ').all { p.o("spent").n(it) <= st.op.o("reservation").n(it) })
                    st.phase = Phase.SETTLED
                }
                "accounting_violation" -> {
                    fields(p, "observedSpent:O evidenceSha256:D reason:T"); budget(p.o("observedSpent"))
                    require(st != null && st.phase in setOf(Phase.INTENT, Phase.RECEIPT, Phase.VALIDATED, Phase.UNKNOWN))
                    require(p.s("reason") in setOf("over_reservation", "over_limit", "overflow"))
                    st.phase = Phase.VIOLATION; st.blocked = true; violation = true
                }
                "released" -> {
                    fields(p, "nonDispatchEvidenceSha256:D"); require(st != null && st.phase in setOf(Phase.RESERVED, Phase.NOT_DISPATCHED))
                    st.phase = Phase.RELEASED
                }
                "blocked" -> {
                    fields(p, "reason:T resume:O")
                    require(p.s("reason") in setOf("exhausted", "interrupted", "cancelled", "cleanup_unverified", "unavailable", "reconciliation_required"))
                    val r = p.o("resume"); require(e["operationId"] == r["operationId"])
                    require(resume(r, workId, states) != "none")
                    if (st != null) { st.blocked = true; st.unknownNeedsBlock = false } else blockedWorks.add(workId)
                }
                "decision_recorded" -> {
                    fields(p, "attemptId:I disposition:T runStatus:T candidateSourceSha256:D? acceptedHeadId:R? provisionalHeadId:R? graphSha256:D assessmentSha256:D? operationIds:A resume:O")
                    require(st == null && !violation && decisions.add(p.s("attemptId")))
                    val ids = p.a("operationIds").map { it.text() }
                    require(ids.isNotEmpty())
                    val contributing = ids.map { states[it] ?: invalid() }
                    require(contributing.all { it.op.s("workId") == workId && it.op.s("attemptId") == p.s("attemptId") && it.phase in setOf(Phase.SETTLED, Phase.RELEASED) })
                    require(states.values.filter { it.op.s("attemptId") == p.s("attemptId") }.map { it.op.s("id") }.toSet() == ids.toSet())
                    decision(p, binding, work, contributing)
                    resume(p.o("resume"), workId, states)
                    lastDecision = p
                    if (p.s("runStatus") != "running") terminalDecision = p.s("runStatus")
                }
                "run_finished" -> {
                    fields(p, "runStatus:T acceptedHeadId:R? provisionalHeadId:R? graphSha256:D resume:O")
                    require(st == null && statuses[p.s("runStatus")]?.terminalStatus() == true)
                    if (violation) require(p.s("runStatus") !in setOf("fully_accepted", "compile_valid"))
                    if (terminalDecision != null) require(p.s("runStatus") == terminalDecision)
                    if (p.s("runStatus") == "fully_accepted") require(blockedWorks.isEmpty() && states.values.all {
                        !it.blocked && it.phase in setOf(Phase.SETTLED, Phase.RELEASED)
                    })
                    val latest = lastDecision
                    if (latest != null) {
                        require(p["acceptedHeadId"] == latest["acceptedHeadId"] && p["provisionalHeadId"] == latest["provisionalHeadId"])
                        if (p.s("runStatus") == "fully_accepted") require(latest.s("disposition") == "fully_accepted")
                    } else {
                        require(p.s("runStatus") != "fully_accepted" && p["acceptedHeadId"] == work["acceptedParentId"])
                    }
                    resume(p.o("resume"), workId, states); finished = true
                }
                else -> invalid()
            }
        }
        require(prepared == works.keys && states.values.all { it.phase != Phase.DEFINED })
    }

    private fun RepairRunStatus.terminalStatus() = this != RepairRunStatus.RUNNING

    private fun decision(p: JsonObject, binding: JsonObject, work: JsonObject, contributing: List<OperationState>) {
        val disposition = dispositions[p.s("disposition")] ?: invalid()
        val status = statuses[p.s("runStatus")] ?: invalid()
        require(disposition != RepairAttemptDisposition.LEGACY_UNVERIFIED)
        require(status != RepairRunStatus.FULLY_ACCEPTED || disposition == RepairAttemptDisposition.FULLY_ACCEPTED)
        val observations = contributing.mapNotNull { it.observation }
        val diagnostics = contributing.mapNotNull { it.diagnostic }
        val validations = observations.map { it.invocation } + diagnostics.map { it.invocation }
        require(validations.all { it.candidateRevisionId == p.s("attemptId") && it.sourceRevisionSha256 == p.nullable("candidateSourceSha256")?.text() })
        if (disposition != RepairAttemptDisposition.FULLY_ACCEPTED) require(p["acceptedHeadId"] == work["acceptedParentId"])
        when (disposition) {
            RepairAttemptDisposition.FULLY_ACCEPTED -> {
                require(p["acceptedHeadId"] == p["attemptId"] && p.nullable("provisionalHeadId") == null &&
                    p.nullable("candidateSourceSha256") != null && binding.nullable("expectedObservationsSha256") != null && binding.nullable("originalBinarySha256") != null)
                require(contributing.all { it.phase == Phase.SETTLED })
                val models = contributing.filter { it.op.s("kind") == "model" }
                require(models.isNotEmpty() && models.all { st ->
                    val r = st.receipt ?: return@all false
                    val a = acp(r.o("acp")); val s = r.nullable("session")?.obj()
                    a.receiptReleaseComplete && a.terminalOutcome == "returned-completed" && s != null && s.b("eventsComplete")
                })
                require(diagnostics.isEmpty() && observations.isNotEmpty() && observations.all {
                    it.outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED && it.diff == null &&
                        it.proof.originalBinarySha256 == binding.s("originalBinarySha256")
                })
                require(work.a("retainedCaseIds").isNotEmpty())
            }
            RepairAttemptDisposition.PROVISIONAL -> {
                require(p["provisionalHeadId"] == p["attemptId"] && p.nullable("candidateSourceSha256") != null)
                require(observations.any { it.outcome != RepairValidationObservedOutcome.COMPILE_FAILED } && diagnostics.isEmpty())
            }
            RepairAttemptDisposition.REJECTED -> require(p.nullable("provisionalHeadId") == null ||
                p["provisionalHeadId"] == work["speculativeParentId"] && work["speculativeParentId"] != work["canonicalParentId"])
            RepairAttemptDisposition.LEGACY_UNVERIFIED -> invalid()
        }
    }
}
