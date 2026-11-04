package decompengine.oracle.fulltree.repair

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.repair.*
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.GZIPInputStream
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Test
import kotlin.test.*

class ShardSchedulerBindingsTest {
    private val h = "a".repeat(64)
    private val other = "b".repeat(64)
    private val rootId = "root_" + "0".repeat(24)
    private fun candidate(n: Int) = "revision_${n.toString().padStart(8, '0')}_" + n.toString(16).repeat(16)
    private fun value(v: Any?): JsonElement = when (v) {
        null -> JsonNull
        is JsonElement -> v
        is String -> JsonPrimitive(v)
        is Boolean -> JsonPrimitive(v)
        is Number -> JsonPrimitive(v)
        is List<*> -> JsonArray(v.map(::value))
        else -> error("fixture type")
    }
    private fun obj(vararg pairs: Pair<String, Any?>) = JsonObject(pairs.associate { it.first to value(it.second) })
    private fun JsonObject.edit(vararg pairs: Pair<String, Any?>) = JsonObject(this + obj(*pairs))
    private fun JsonObject.o(k: String) = getValue(k).jsonObject
    private fun JsonObject.a(k: String) = getValue(k).jsonArray
    private fun JsonObject.s(k: String) = getValue(k).jsonPrimitive.content
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun bytes(v: JsonElement) = OracleJson.canonicalBytes(v, ShardSchedulerLimits().json)
    private fun id(role: String, binding: JsonObject) = (if (role == "external-invocation") "invocation" else role) + "-" +
        sha(bytes(obj("domain" to "full-tree-shard-scheduler-v1/$role", "binding" to binding)))
    private fun JsonObject.pick(vararg keys: String) = JsonObject(keys.associateWith { getValue(it) })
    private fun vector(model: Long = 0, rebuild: Long = 0) = obj("modelCalls" to model, "inputTokens" to 0,
        "outputTokens" to 0, "wallMillis" to 10, "patchBytes" to 0, "rebuilds" to rebuild)
    private fun binding() = obj("repairRunId" to "run_00000001", "baselineRevisionId" to rootId,
        "baselineSourceSha256" to h, "profileSha256" to h, "indexSha256" to h, "regressionCorpusSha256" to h,
        "expectedObservationsSha256" to h, "originalBinarySha256" to h, "boundedRunSha256" to h,
        "boundedIndexArtifactSha256" to h, "planningArtifactSha256" to h, "planningReportSha256" to h,
        "planningConfigurationSha256" to h, "dependencyPlanSchema" to 1, "dependencyPlanSha256" to h,
        "frozenInterfaceSchema" to 1, "frozenInterfaceSha256" to h, "schedulerPolicySha256" to h)
    private fun invocation(n: Int, source: String = h, revision: String = candidate(n)) = RepairValidationInvocation(
        "validation_" + n.toString(16).padStart(32, '0'), "run_00000001", revision, source, h, h, h)
    private fun key(d: JsonObject) = id("diagnostic", d.pick("normalizerSha256", "stage", "toolIdentitySha256", "normalizedKeySha256"))
    private fun work(n: Int = 1, speculative: String = rootId, accepted: String? = null): JsonObject {
        val owner = "cu-" + n.toString().repeat(32)
        val diagnostic = obj("normalizerSha256" to h, "stage" to "compile", "toolIdentitySha256" to h,
            "normalizedKeySha256" to h, "validationInvocation" to invocation(n + 8, revision = speculative).toJsonObject(),
            "evidence" to obj("sha256" to h, "bytes" to 100), "ownerModuleId" to owner, "sourcePath" to "src/a.c")
        val d = diagnostic.edit("key" to key(diagnostic), "occurrenceId" to "pending")
        val w = obj("id" to "pending", "shardId" to "shard-$n", "shardInputSha256" to h, "moduleIds" to listOf(owner),
            "diagnostic" to d, "sourceRevisionSha256" to h, "canonicalParentId" to rootId,
            "speculativeParentId" to speculative, "acceptedParentId" to accepted, "dependencyPlanSha256" to h,
            "dependencyGeneration" to 0, "frozenInterfaceSha256" to h, "frozenGeneration" to 0,
            "planTransitionSha256" to null, "frozenInterfaces" to listOf(obj("interfaceId" to "header-a", "version" to 0,
                "bytesSha256" to h, "producerRevisionId" to rootId, "invalidationTransactionSha256" to null)),
            "ordering" to obj("policySha256" to h, "graphSha256" to h, "componentId" to "component-a", "dependencyRank" to 0,
                "failureClassRank" to 0, "downstreamImpact" to 2, "rootDiagnosticKeys" to listOf(key(d)),
                "impactSetSha256" to h, "retainedRegressionSetSha256" to h, "assessmentSha256" to null),
            "retainedCaseIds" to listOf("case-a", "case-b"), "oscillationKeySha256" to null)
        return identifyWork(w)
    }
    private fun identifyWork(w: JsonObject, b: JsonObject = binding()): JsonObject {
        var d = w.o("diagnostic"); d = d.edit("key" to key(d))
        d = d.edit("occurrenceId" to id("diagnostic-occurrence", d.pick("key", "validationInvocation", "ownerModuleId").edit(
            "shardId" to w["shardId"], "planningArtifactSha256" to b["planningArtifactSha256"], "dependencyPlanSha256" to w["dependencyPlanSha256"])))
        val v = w.edit("diagnostic" to d)
        val fields = JsonObject(v.filterKeys { it !in setOf("id", "diagnostic") }).edit("repairRunId" to b["repairRunId"],
            "boundedRunSha256" to b["boundedRunSha256"], "diagnosticOccurrenceId" to d["occurrenceId"])
        return v.edit("id" to id("work", fields))
    }
    private fun operation(w: JsonObject, n: Int = 1, rebuild: Boolean = false, ordinal: Int = if (rebuild) 2 else 1): JsonObject {
        val identity = obj("repairRunId" to "run_00000001", "workId" to w["id"], "attemptId" to candidate(n),
            "ordinal" to ordinal, "kind" to if (rebuild) "rebuild" else "model")
        return JsonObject(identity - "repairRunId").edit("id" to id("external-invocation", identity), "requestSha256" to h,
            "promptSha256" to if (rebuild) null else h, "contextInputsSha256" to h, "toolIdentitySha256" to h,
            "accessPolicySha256" to h, "sandboxPolicySha256" to h, "factoryConfigurationSha256" to if (rebuild) null else h,
            "modelConfigurationSha256" to if (rebuild) null else h,
            "verificationCommands" to if (rebuild) listOf(obj("argv" to listOf("cc", "-c", "src/a.c"), "cwd" to ".",
                "environmentSha256" to h, "toolIdentitySha256" to h)) else emptyList<JsonElement>(),
            "reservation" to vector(if (rebuild) 0 else 1, if (rebuild) 1 else 0))
    }
    private fun session() = obj("implementationId" to "scripted-fixture", "implementationVersion" to "1", "sdkVersion" to "0.30.1",
        "protocolVersion" to 1, "agentIdentitySha256" to h, "sessionIdSha256" to h, "resumeReferenceSha256" to null,
        "turnOrdinal" to 1, "requestSha256" to h, "eventsSha256" to h, "observedEventCount" to 2,
        "retainedEventCount" to 2, "eventsComplete" to true, "policyAuditsSha256" to h, "sandboxEvidenceSha256" to h)
    private fun acp(n: Int, outcome: String = "returned-completed") = obj(
        "receiptPath" to "reports/repair-revisions/${candidate(n)}.acp-receipt.json", "receiptSha256" to h,
        "receiptSchemaVersion" to 2, "requestSha256" to h, "resultChangesSha256" to other,
        "terminalOutcome" to outcome, "receiptReleaseComplete" to (outcome == "returned-completed"), "assessmentStatus" to "pending")
    private fun observation(n: Int, provisional: Boolean = false): RepairValidationObservation {
        val i = invocation(n)
        val proof = RepairValidationProof(h, h, h, h, h, other, h, h, true, RepairValidationAssurance.STRICT_CONTAINED)
        return RepairValidationObservation(i, proof, RepairValidationObservedOutcome.BEHAVIOR_CHECKED,
            RepairValidationObservedArtifact(repairValidationReceiptPath(i.id, h), h, 100),
            if (provisional) RepairValidationObservedArtifact(repairValidationDiffPath(other), other, 25) else null)
    }
    private fun diagnostic(n: Int, cleanup: Boolean = true) = RepairValidationDiagnosticBinding(invocation(n), h,
        "reports/${invocation(n).id}.validation.json", h, 100, "reports/${invocation(n).id}.validation-failure.json", other, 30,
        if (cleanup) RepairValidationFailureKind.VALIDATION_FAILED else RepairValidationFailureKind.CLEANUP_UNVERIFIED, cleanup, 2)
    private fun resume(disposition: String = "none", op: JsonObject? = null) = obj("disposition" to disposition,
        "operationId" to op?.get("id"), "evidenceSha256" to if (disposition == "none") null else h)
    private fun event(w: JsonObject, kind: String, p: JsonObject, op: JsonObject? = null) = obj("sequence" to 0,
        "previousSha256" to null, "workId" to w["id"], "operationId" to op?.get("id"), "kind" to kind, "payload" to p)
    private fun chain(events: List<JsonObject>): JsonArray {
        var previous: String? = null
        return JsonArray(events.mapIndexed { i, e -> e.edit("sequence" to i, "previousSha256" to previous).also { previous = sha(bytes(it)) } })
    }
    private fun root(works: List<JsonObject>, ops: List<JsonObject>, events: List<JsonObject>, b: JsonObject = binding()) = obj(
        "schemaVersion" to 1, "kind" to "full-tree-shard-scheduler-history", "binding" to b,
        "budgetLimits" to obj("run" to vector(10, 10), "shards" to works.map { it.s("shardId") }.distinct().sorted().map {
            obj("shardId" to it, "limit" to vector(10, 10)) }), "works" to works.sortedBy { it.s("id") },
        "operations" to ops.sortedWith(compareBy({ it.s("workId") }, { it.s("attemptId") }, { it["ordinal"]!!.jsonPrimitive.long }, { it.s("id") })),
        "events" to chain(events))
    private fun prepared(w: JsonObject) = event(w, "prepared", obj("graphSha256" to h))
    private fun operationEvents(w: JsonObject, op: JsonObject, n: Int, provisional: Boolean = false, failure: String? = null): List<JsonObject> {
        val rebuild = op.s("kind") == "rebuild"
        val events = mutableListOf(event(w, "reserved", obj(), op), event(w, "dispatch_intent", obj("journalBindingSha256" to h), op))
        events += event(w, "receipt_recorded", obj("receipt" to obj("sha256" to h, "bytes" to 100),
            "acp" to if (rebuild) null else acp(n, failure ?: "returned-completed"), "session" to if (rebuild || failure != null) null else session(),
            "providerOutcome" to if (rebuild) (failure ?: "behavior_checked") else (failure ?: "returned-completed")), op)
        if (rebuild) events += event(w, "validation_recorded", obj("observation" to if (failure == null) observation(n, provisional).toJsonObject() else null,
            "diagnostic" to if (failure != null) diagnostic(n, failure != "cleanup_unverified").toJsonObject() else null), op)
        events += event(w, "settled", obj("spent" to op["reservation"], "usageKnown" to true, "evidenceSha256" to h), op)
        return events
    }
    private fun decision(w: JsonObject, n: Int, ops: List<JsonObject>, disposition: String, status: String = "running") = event(w,
        "decision_recorded", obj("attemptId" to candidate(n), "disposition" to disposition, "runStatus" to status,
            "candidateSourceSha256" to h, "acceptedHeadId" to if (disposition == "fully_accepted") value(candidate(n)) else w["acceptedParentId"],
            "provisionalHeadId" to if (disposition == "provisional") candidate(n) else null, "graphSha256" to h, "assessmentSha256" to h,
            "operationIds" to ops.map { it.s("id") }.sorted(), "resume" to resume()))
    private fun fixture(): JsonObject {
        val a = work(); val b = work(2, candidate(1))
        val ops = listOf(operation(a), operation(a, rebuild = true), operation(b, 2), operation(b, 2, true), operation(b, 3))
        val events = mutableListOf(prepared(a))
        events += operationEvents(a, ops[0], 1)
        events += operationEvents(a, ops[1], 1, provisional = true)
        events += decision(a, 1, ops.take(2), "provisional")
        events += prepared(b)
        events += operationEvents(b, ops[4], 3, failure = "returned-no-changes")
        events += decision(b, 3, listOf(ops[4]), "rejected")
        events += operationEvents(b, ops[2], 2)
        events += operationEvents(b, ops[3], 2)
        events += decision(b, 2, ops.subList(2, 4), "fully_accepted")
        events += event(b, "run_finished", obj("runStatus" to "fully_accepted", "acceptedHeadId" to candidate(2), "provisionalHeadId" to null,
            "graphSha256" to h, "resume" to resume()))
        return root(listOf(a, b), ops, events)
    }
    private fun minimal(w: JsonObject = work()) = root(listOf(w), emptyList(), listOf(prepared(w)))
    private fun prefix(count: Int, rebuild: Boolean = false): JsonObject {
        val w = work(); val op = operation(w, rebuild = rebuild)
        return root(listOf(w), if (count == 0) emptyList() else listOf(op), listOf(prepared(w)) + operationEvents(w, op, 1).take(count))
    }
    private fun valid(root: JsonObject): RecordedShardSchedulerHistory {
        val h = RecordedShardSchedulerHistory(root)
        assertContentEquals(ShardSchedulerBindings.encode(h), ShardSchedulerBindings.encode(ShardSchedulerBindings.decode(ShardSchedulerBindings.encode(h))))
        return h
    }
    private fun invalid(root: JsonObject) {
        assertFailsWith<IllegalArgumentException> { RecordedShardSchedulerHistory(root) }
        assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(bytes(root)) }
    }
    private fun append(root: JsonObject, vararg events: JsonObject) = root.edit("events" to chain(root.a("events").map { it.jsonObject } + events))
    private fun editEvent(root: JsonObject, kind: String, f: (JsonObject) -> JsonObject): JsonObject {
        var done = false
        return root.edit("events" to chain(root.a("events").map { e ->
            val o = e.jsonObject
            if (!done && o.s("kind") == kind) { done = true; f(o) } else o
        }))
    }

    @Test fun validation_id_cannot_describe_two_candidate_revisions() {
        val original = fixture()
        valid(original)
        val changed = original.a("events").map { element ->
            val e = element.jsonObject
            if (e.s("kind") != "validation_recorded" ||
                e.o("payload").o("observation").o("invocation").s("id") != invocation(2).id) e
            else {
                val observed = e.o("payload").o("observation")
                e.edit("payload" to e.o("payload").edit("observation" to observed.edit(
                    "invocation" to observed.o("invocation").edit("id" to invocation(1).id),
                    "primary" to observed.o("primary").edit("path" to repairValidationReceiptPath(invocation(1).id, h)))))
            }
        }
        invalid(original.edit("events" to chain(changed)))
    }

    @Test fun work_diagnostic_validation_identity_cannot_be_redefined_by_rebuild() {
        val original = fixture()
        valid(original)
        val diagnosticId = work().o("diagnostic").o("validationInvocation").s("id")
        invalid(editEvent(original, "validation_recorded") { e ->
            val observed = e.o("payload").o("observation")
            e.edit("payload" to e.o("payload").edit("observation" to observed.edit(
                "invocation" to observed.o("invocation").edit("id" to diagnosticId),
                "primary" to observed.o("primary").edit("path" to repairValidationReceiptPath(diagnosticId, h)))))
        })
    }

    @Test fun repeated_validation_definition_must_keep_identical_evidence() {
        val w = work()
        val ops = listOf(operation(w), operation(w, rebuild = true), operation(w, rebuild = true, ordinal = 3))
        val events = listOf(prepared(w)) + ops.flatMap { operationEvents(w, it, 1) } +
            decision(w, 1, ops, "fully_accepted")
        val original = root(listOf(w), ops, events)
        // Repeated references to exactly the same graph-owned call remain valid.
        valid(original)
        val changed = events.map { e ->
            if (e["operationId"] != ops.last()["id"]) e else when (e.s("kind")) {
                "receipt_recorded" -> e.edit("payload" to e.o("payload").edit(
                    "receipt" to e.o("payload").o("receipt").edit("sha256" to other)))
                "validation_recorded" -> {
                    val observed = e.o("payload").o("observation")
                    e.edit("payload" to e.o("payload").edit("observation" to observed.edit(
                        "proof" to observed.o("proof").edit("evidenceSha256" to other),
                        "primary" to observed.o("primary").edit("sha256" to other,
                            "path" to repairValidationReceiptPath(invocation(1).id, other)))))
                }
                else -> e
            }
        }
        invalid(root(listOf(w), ops, changed))
    }

    @Test fun later_work_can_reference_an_identical_validation_invocation() {
        val first = work()
        val next = work(2, candidate(1)).let { w -> identifyWork(w.edit(
            "diagnostic" to w.o("diagnostic").edit("validationInvocation" to invocation(1).toJsonObject()))) }
        val op = operation(first, rebuild = true)
        valid(root(listOf(first, next), listOf(op), listOf(prepared(first)) +
            operationEvents(first, op, 1) + prepared(next)))
    }

    @Test fun B1_01_two_shard_graph_correlated_history() {
        val history = valid(fixture())
        val first = ModuleRevisionNode(candidate(1), rootId, 1, ModuleRevisionStatus.PROVISIONAL, h, emptyList(), emptyList(), emptyList(),
            null, null, false, validationProof = observation(1, true).proof)
        val accepted = first.copy(id = candidate(2), parentId = candidate(1), ordinal = 2, status = ModuleRevisionStatus.ACCEPTED,
            validationProof = observation(2).proof)
        val run = RepairRunState("run_00000001", RepairRunStatus.FULLY_ACCEPTED, rootId, accepted.id, null, h, 3, 3, 1, 10,
            expectedObservationsSha256 = h, originalBinarySha256 = h)
        val graph = ModuleRevisionGraphSnapshot("fixture", h, h, accepted.id, 4, listOf(first, accepted), null, 0, h,
            schemaVersion = 4, fullyAcceptedHeadId = accepted.id, runs = listOf(run))
        val last = history.record.a("events").last().jsonObject.o("payload")
        assertEquals(graph.fullyAcceptedHeadId, last.s("acceptedHeadId"))
        assertEquals(run.status, RepairRunStatus.FULLY_ACCEPTED)
        assertEquals(first.id, accepted.parentId)
        assertEquals(observation(2).invocation.sourceRevisionSha256, accepted.validationProof!!.sourceRevisionSha256)
        assertEquals(2, history.record.a("works").size)
    }
    @Test fun B1_02_distinct_failure_no_change_refusal_and_validation_outcomes() {
        for (outcome in listOf("returned-no-changes", "returned-refused", "failed-agent", "failed-startup")) {
            val w = work(accepted = rootId); val op = operation(w)
            val r = root(listOf(w), listOf(op), listOf(prepared(w)) + operationEvents(w, op, 1, failure = outcome) +
                decision(w, 1, listOf(op), "rejected", if (outcome == "returned-no-changes") "no_changes" else "rejected"))
            assertEquals(outcome, valid(r).record.a("events")[3].jsonObject.o("payload").s("providerOutcome"))
        }
        for (outcome in listOf("validation_failed", "cleanup_unverified")) {
            val w = work(); val op = operation(w, rebuild = true)
            valid(root(listOf(w), listOf(op), listOf(prepared(w)) + operationEvents(w, op, 1, failure = outcome) +
                decision(w, 1, listOf(op), "rejected", "validation_failed")))
        }
    }
    @Test fun B1_03_literal_golden_canonical_bytes_and_sha() {
        val encoded = ShardSchedulerBindings.encode(valid(fixture()))
        val output = System.getProperty("scheduler.golden.output")
        if (output != null) java.nio.file.Files.write(java.nio.file.Path.of(output), encoded)
        assertEquals(GOLDEN_SHA, sha(encoded))
        assertContentEquals(GZIPInputStream(Base64.getDecoder().decode(GOLDEN_GZIP).inputStream()).readBytes(), encoded)
        assertEquals('\n'.code.toByte(), encoded.last())
    }
    @Test fun B1_04_roundtrip_and_direct_commitment() {
        val h = valid(fixture()); assertEquals(sha(ShardSchedulerBindings.encode(h)), ShardSchedulerBindings.commitmentSha256(h))
    }
    @Test fun B1_05_every_model_and_rebuild_phase_prefix() {
        for (rebuild in listOf(false, true)) for (count in 0..if (rebuild) 5 else 4) valid(prefix(count, rebuild))
    }
    @Test fun B1_06_member_permutations_whitespace_and_escaped_duplicates() {
        val r = minimal(); val h = valid(r)
        val unordered = JsonObject(r.entries.reversed().associate { it.toPair() }).toString()
        assertContentEquals(ShardSchedulerBindings.encode(h), ShardSchedulerBindings.encode(ShardSchedulerBindings.decode((" \n$unordered \t").toByteArray())))
        val duplicate = r.toString().replaceFirst("{", "{\"schema\\u0056ersion\":1,")
        assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(duplicate.toByteArray()) }
    }
    @Test fun B1_07_every_object_missing_unknown_and_wrong_type_fields() {
        var checked = 0
        fun walk(root: JsonObject, path: List<Any>, node: JsonElement) {
            when (node) {
                is JsonObject -> {
                    for (key in node.keys) { invalid(rehash(replace(root, path, JsonObject(node - key)).jsonObject)); checked++ }
                    invalid(rehash(replace(root, path, node.edit("unknown" to true)).jsonObject)); checked++
                    node.forEach { (key, child) -> walk(root, path + key, child) }
                }
                is JsonArray -> node.forEachIndexed { i, child -> walk(root, path + i, child) }
                else -> {
                    val changed = replace(root, path, JsonArray(emptyList())).jsonObject
                    invalid(if (path.lastOrNull() == "previousSha256") changed else rehash(changed)); checked++
                }
            }
        }
        walk(fixture(), emptyList(), fixture())
        val w = work(); val op = operation(w, rebuild = true)
        val fail = root(listOf(w), listOf(op), listOf(prepared(w)) + operationEvents(w, op, 1, failure = "validation_failed"))
        walk(fail, emptyList(), fail)
        val model = operation(w)
        val variants = listOf(
            append(prefix(1), event(w, "released", obj("nonDispatchEvidenceSha256" to h), model)),
            append(prefix(2), event(w, "reconciled", obj("result" to "unknown", "evidenceSha256" to h), model)),
            append(prefix(2), event(w, "accounting_violation", obj("observedSpent" to vector(2), "evidenceSha256" to h, "reason" to "over_reservation"), model)),
            append(prefix(1), event(w, "resume_recorded", obj("resume" to resume("dispatch_same_id", model)), model)),
            append(minimal(), event(w, "blocked", obj("reason" to "unavailable", "resume" to resume("blocked")))))
        variants.forEach { valid(it); walk(it, emptyList(), it) }
        assertTrue(checked > 1000)
    }
    private fun rehash(root: JsonObject): JsonObject {
        val events = root["events"] as? JsonArray ?: return root
        var previous: String? = null
        return root.edit("events" to events.map { original ->
            var e = original.jsonObject
            if ("previousSha256" in e) e = e.edit("previousSha256" to previous)
            previous = sha(bytes(e)); e
        })
    }
    private fun replace(node: JsonElement, path: List<Any>, replacement: JsonElement): JsonElement {
        if (path.isEmpty()) return replacement
        val k = path.first()
        return if (k is Int) JsonArray(node.jsonArray.mapIndexed { i, e -> if (i == k) replace(e, path.drop(1), replacement) else e })
        else node.jsonObject.edit(k.toString() to replace(node.jsonObject.getValue(k.toString()), path.drop(1), replacement))
    }
    @Test fun B1_08_versions_enums_null_and_union_tags() {
        val r = fixture()
        for (v in listOf(0, 2, Long.MAX_VALUE)) invalid(r.edit("schemaVersion" to v))
        invalid(r.edit("kind" to "history")); invalid(r.edit("binding" to null))
        invalid(editEvent(r, "receipt_recorded") { it.edit("kind" to "receipt") })
        invalid(editEvent(r, "decision_recorded") { it.edit("payload" to it.o("payload").edit("disposition" to "accepted")) })
        invalid(editEvent(r, "run_finished") { it.edit("payload" to it.o("payload").edit("runStatus" to "running")) })
        invalid(editEvent(r, "receipt_recorded") { it.edit("payload" to it.o("payload").edit("acp" to it.o("payload").o("acp").edit("receiptSchemaVersion" to 1))) })
        val w = work(); val op = operation(w)
        for (bad in listOf("bad", "NONE")) {
            invalid(append(prefix(1), event(w, "resume_recorded", obj("resume" to resume(bad, op)), op)))
            invalid(append(prefix(2), event(w, "reconciled", obj("result" to bad, "evidenceSha256" to h), op)))
        }
        invalid(append(prefix(2), event(w, "accounting_violation", obj("observedSpent" to vector(), "reason" to "bad", "evidenceSha256" to h), op)))
        valid(minimal().edit("binding" to binding().edit("originalBinarySha256" to null, "expectedObservationsSha256" to null)))
    }
    @Test fun B1_09_utf8_surrogates_controls_and_paths() {
        for (b in listOf(byteArrayOf(0xc0.toByte(), 0xaf.toByte()), byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte())))
            assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(b) }
        for (s in listOf("\\ud800", "\\udc00", "\\u0000", "\\u007f")) {
            val payload = minimal().toString().replace("src/a.c", s)
            assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(payload.toByteArray()) }
        }
        val colon = work(); valid(minimal(identifyWork(colon.edit("diagnostic" to colon.o("diagnostic").edit("sourcePath" to "src/a:b.c")))))
        for (p in listOf("C:a", "/etc/a", "C:/a", "a\\b", "a/../b", "a/./b", "a//b", "a/", ".", "", "a\n")) {
            val w = work(); invalid(minimal(identifyWork(w.edit("diagnostic" to w.o("diagnostic").edit("sourcePath" to p)))))
        }
    }
    @Test fun B1_10_strict_scalar_and_integer_lexical_grammar() {
        val r = minimal().toString()
        for (v in listOf("\"1\"", "1.0", "1e0", "-0", "-1", "9223372036854775808", "true", "null", "[]", "{}"))
            assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(r.replace("\"schemaVersion\":1", "\"schemaVersion\":$v").toByteArray()) }
        invalid(minimal().edit("kind" to 1))
        for (suffix in listOf(" trailing", " {}", " []")) assertFailsWith<IllegalArgumentException> {
            ShardSchedulerBindings.decode((r + suffix).toByteArray())
        }
        for (root in listOf("[]", "1", "null", "true")) assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(root.toByteArray()) }
        val w = work().edit("dependencyGeneration" to Long.MAX_VALUE); valid(minimal(identifyWork(w)))
    }
    @Test fun B1_11_all_lowerable_limits_at_and_one_over() {
        val r = fixture(); val h = valid(r); val encoded = ShardSchedulerBindings.encode(h)
        val default = ShardSchedulerLimits()
        val jsonCases: List<Pair<Int, (Int) -> StrictJsonLimits>> = listOf(
            encoded.size to { n -> default.json.copy(maximumCanonicalBytes = n) },
            24 to { n -> default.json.copy(maximumDepth = n) },
            1_000_000 to { n -> default.json.copy(maximumNodes = n) },
            4096 to { n -> default.json.copy(maximumStringBytes = n) },
            8 * 1024 * 1024 to { n -> default.json.copy(maximumTotalStringBytes = n) },
            19 to { n -> default.json.copy(maximumNumberCharacters = n) })
        for ((ceiling, configure) in jsonCases) {
            assertFailsWith<IllegalArgumentException> { configure(0) }
            var low = 1; var high = ceiling
            while (low < high) {
                val mid = (low + high) / 2
                if (runCatching { ShardSchedulerBindings.encode(h, default.copy(json = configure(mid))) }.isSuccess) high = mid else low = mid + 1
            }
            val exact = default.copy(json = configure(low))
            ShardSchedulerBindings.encode(h, exact); ShardSchedulerBindings.decode(encoded, exact); RecordedShardSchedulerHistory(r, exact)
            if (low > 1) {
                val over = default.copy(json = configure(low - 1))
                assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.encode(h, over) }
                assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(encoded, over) }
                assertFailsWith<IllegalArgumentException> { RecordedShardSchedulerHistory(r, over) }
            } else assertFailsWith<IllegalArgumentException> { configure(0) }
        }
        assertFailsWith<IllegalArgumentException> { default.json.copy(maximumInputBytes = 0) }
        ShardSchedulerBindings.decode(encoded, default.copy(json = default.json.copy(maximumInputBytes = encoded.size)))
        assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(encoded, default.copy(json = default.json.copy(maximumInputBytes = encoded.size - 1))) }
        val collectionCases: List<Pair<Int, (Int) -> ShardSchedulerLimits>> = listOf(
            2 to { n -> default.copy(works = n) }, 5 to { n -> default.copy(operations = n) },
            r.a("events").size to { n -> default.copy(events = n) }, 1 to { n -> default.copy(modules = n) },
            1 to { n -> default.copy(frozen = n) }, 2 to { n -> default.copy(cases = n) },
            1 to { n -> default.copy(roots = n) }, 1 to { n -> default.copy(commands = n) }, 3 to { n -> default.copy(argv = n) })
        for ((exact, configure) in collectionCases) {
            ShardSchedulerBindings.encode(h, configure(exact)); ShardSchedulerBindings.decode(encoded, configure(exact))
            assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.encode(h, configure(exact - 1)) }
            assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(encoded, configure(exact - 1)) }
            assertFailsWith<IllegalArgumentException> { RecordedShardSchedulerHistory(r, configure(exact - 1)) }
        }
        val empty = work().edit("frozenInterfaces" to emptyList<String>(), "retainedCaseIds" to emptyList<String>(),
            "ordering" to work().o("ordering").edit("rootDiagnosticKeys" to emptyList<String>()))
        val zero = RecordedShardSchedulerHistory(minimal(identifyWork(empty)), default.copy(operations = 0, commands = 0, argv = 0, frozen = 0, cases = 0, roots = 0))
        ShardSchedulerBindings.encode(zero)
        assertFailsWith<IllegalArgumentException> { default.copy(works = 2049) }
        assertFailsWith<IllegalArgumentException> { default.copy(json = default.json.copy(maximumDepth = 25)) }
    }
    @Test fun B1_12_constructor_output_is_bounded_before_return() {
        val r = fixture(); val size = bytes(r).size
        assertFailsWith<IllegalArgumentException> { RecordedShardSchedulerHistory(r, ShardSchedulerLimits(json = ShardSchedulerLimits().json.copy(maximumCanonicalBytes = size - 1))) }
    }
    @Test fun B1_13_unordered_constructor_tables_and_sets_sort_but_wire_does_not() {
        val base = fixture(); val expected = ShardSchedulerBindings.encode(valid(base))
        for (key in listOf("works", "operations")) {
            val changed = base.edit(key to base.a(key).reversed())
            assertContentEquals(expected, ShardSchedulerBindings.encode(RecordedShardSchedulerHistory(changed)))
            assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(bytes(changed)) }
        }
        val changed = base.edit("budgetLimits" to base.o("budgetLimits").edit("shards" to base.o("budgetLimits").a("shards").reversed()),
            "works" to base.a("works").map { it.jsonObject.edit("retainedCaseIds" to it.jsonObject.a("retainedCaseIds").reversed()) })
        assertContentEquals(expected, ShardSchedulerBindings.encode(RecordedShardSchedulerHistory(changed)))
        assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(bytes(changed)) }
        val rich = work().edit("moduleIds" to listOf("cu-" + "1".repeat(32), "cu-" + "2".repeat(32)),
            "frozenInterfaces" to listOf(work().a("frozenInterfaces").first(), work().a("frozenInterfaces").first().jsonObject.edit("interfaceId" to "header-b")),
            "ordering" to work().o("ordering").edit("rootDiagnosticKeys" to listOf("diagnostic-" + "0".repeat(64), "diagnostic-" + "f".repeat(64))))
        val richRoot = minimal(identifyWork(rich)); val canonical = ShardSchedulerBindings.encode(valid(richRoot))
        val richWork = richRoot.a("works").single().jsonObject
        for (key in listOf("moduleIds", "frozenInterfaces")) {
            val reversed = richRoot.edit("works" to listOf(richWork.edit(key to richWork.a(key).reversed())))
            assertContentEquals(canonical, ShardSchedulerBindings.encode(RecordedShardSchedulerHistory(reversed)))
            assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(bytes(reversed)) }
        }
        val decisionPermuted = base.edit("events" to base.a("events").map { e ->
            val x = e.jsonObject
            if (x.s("kind") == "decision_recorded") x.edit("payload" to x.o("payload").edit("operationIds" to x.o("payload").a("operationIds").reversed())) else x
        })
        assertContentEquals(expected, ShardSchedulerBindings.encode(RecordedShardSchedulerHistory(decisionPermuted)))
        assertFailsWith<IllegalArgumentException> { ShardSchedulerBindings.decode(bytes(decisionPermuted)) }
        // Supplementary code points sort after BMP private-use characters, unlike UTF-16 ordering.
        val w = identifyWork(work().edit("retainedCaseIds" to listOf("\ue000", "😀")))
        val sorted = minimal(w)
        assertEquals(listOf("\ue000", "😀"), valid(sorted).record.a("works")[0].jsonObject.a("retainedCaseIds").map { it.jsonPrimitive.content })
    }
    @Test fun B1_14_ordered_events_commands_and_argv_never_sort() {
        val r = prefix(2, true); val op = r.a("operations").single().jsonObject; val c = op.a("verificationCommands").single().jsonObject
        val swapped = r.edit("operations" to listOf(op.edit("verificationCommands" to listOf(c.edit("argv" to c.a("argv").reversed())))))
        assertNotEquals(ShardSchedulerBindings.commitmentSha256(valid(r)), ShardSchedulerBindings.commitmentSha256(valid(swapped)))
        val c2 = c.edit("argv" to listOf("verify", "x"))
        val one = r.edit("operations" to listOf(op.edit("verificationCommands" to listOf(c, c2))))
        val two = r.edit("operations" to listOf(op.edit("verificationCommands" to listOf(c2, c))))
        assertNotEquals(ShardSchedulerBindings.commitmentSha256(valid(one)), ShardSchedulerBindings.commitmentSha256(valid(two)))
        invalid(r.edit("events" to chain(r.a("events").map { it.jsonObject }.reversed())))
    }
    @Test fun B1_15_duplicate_tables_sets_owners_operations_and_ordinals() {
        val r = prefix(1); val w = work(); val op = r.a("operations").single().jsonObject
        invalid(r.edit("works" to listOf(w, w)))
        invalid(r.edit("operations" to listOf(op, op)))
        for (key in listOf("moduleIds", "retainedCaseIds", "frozenInterfaces")) invalid(minimal(w.edit(key to (w.a(key) + w.a(key).first()))))
        invalid(minimal(w.edit("ordering" to w.o("ordering").edit("rootDiagnosticKeys" to w.o("ordering").a("rootDiagnosticKeys").let { it + it.first() }))))
        val rebuild = operation(w, rebuild = true, ordinal = 1)
        invalid(root(listOf(w), listOf(op, rebuild), listOf(prepared(w), event(w, "reserved", obj(), op), event(w, "reserved", obj(), rebuild))))
    }
    @Test fun B1_16_equal_request_and_receipt_bytes_have_distinct_operation_ids() {
        val w = work(); val a = operation(w); val b = operation(w, 2)
        assertEquals(a["requestSha256"], b["requestSha256"]); assertNotEquals(a["id"], b["id"])
        valid(root(listOf(w), listOf(a, b), listOf(prepared(w)) + operationEvents(w, a, 1) + operationEvents(w, b, 2)))
    }
    @Test fun B1_17_reused_operation_id_changed_definition_rejected() {
        val r = prefix(1); val op = r.a("operations").single().jsonObject
        invalid(r.edit("operations" to listOf(op, op.edit("requestSha256" to other))))
        invalid(r.edit("operations" to listOf(op.edit("workId" to "work-$other"))))
        invalid(r.edit("operations" to listOf(op.edit("attemptId" to candidate(2)))))
    }
    @Test fun B1_18_identity_binding_mutations() {
        val w = work()
        for (key in listOf("shardInputSha256", "sourceRevisionSha256", "oscillationKeySha256", "planTransitionSha256")) invalid(minimal(w.edit(key to other)))
        invalid(minimal(w.edit("retainedCaseIds" to listOf("other"))))
        invalid(minimal(w.edit("diagnostic" to w.o("diagnostic").edit("occurrenceId" to "diagnostic-occurrence-$other"))))
        invalid(minimal(w).edit("binding" to binding().edit("boundedRunSha256" to other)))
        invalid(minimal(identifyWork(w.edit("dependencyPlanSha256" to other, "dependencyGeneration" to 0))))
        val changed = w.edit("dependencyPlanSha256" to other, "dependencyGeneration" to 1,
            "ordering" to w.o("ordering").edit("graphSha256" to other))
        invalid(minimal(identifyWork(changed)))
        valid(minimal(identifyWork(changed.edit("planTransitionSha256" to other))))
    }
    @Test fun B1_19_diagnostic_crosslinks_and_ownership() {
        val w = work(); val d = w.o("diagnostic")
        for ((key, changed) in listOf("runId" to "run_00000002", "profileSha256" to other, "indexSha256" to other,
                "regressionCorpusSha256" to other, "sourceRevisionSha256" to other, "candidateRevisionId" to candidate(4))) {
            invalid(minimal(identifyWork(w.edit("diagnostic" to d.edit("validationInvocation" to d.o("validationInvocation").edit(key to changed))))))
        }
        invalid(minimal(identifyWork(w.edit("diagnostic" to d.edit("ownerModuleId" to "cu-" + "f".repeat(32))))))
    }
    @Test fun B1_20_unknown_orphan_and_chain_references() {
        val r = prefix(1)
        invalid(r.edit("operations" to emptyList<JsonElement>()))
        invalid(r.edit("operations" to (r.a("operations") + operation(work(), 2))))
        invalid(editEvent(r, "reserved") { it.edit("workId" to "work-$other") })
        invalid(editEvent(r, "reserved") { it.edit("operationId" to "invocation-$other") })
        val e = r.a("events").last().jsonObject
        invalid(r.edit("events" to listOf(r.a("events").first(), e.edit("sequence" to 8))))
        invalid(r.edit("events" to listOf(r.a("events").first(), e.edit("previousSha256" to other))))
    }
    @Test fun B1_21_distinct_nullable_parents_and_rejected_head_advance() {
        valid(minimal(work(speculative = candidate(8), accepted = candidate(7))))
        val rejected = fixture().edit("events" to fixture().a("events").map { event ->
            val e = event.jsonObject
            if (e.s("kind") == "decision_recorded" && e.o("payload").s("disposition") == "rejected")
                e.edit("payload" to e.o("payload").edit("acceptedHeadId" to candidate(3))) else e
        })
        invalid(rehash(rejected))
        val w = work(speculative = candidate(1)); val op = operation(w)
        invalid(root(listOf(w), listOf(op), listOf(prepared(w), event(w, "reserved", obj(), op))))
        val r = fixture()
        invalid(editEvent(r, "decision_recorded") { it.edit("payload" to it.o("payload").edit("acceptedHeadId" to candidate(1))) })
    }
    @Test fun B1_22_payload_pairing_request_session_and_counts() {
        val r = prefix(3)
        fun receipt(f: (JsonObject) -> JsonObject) = editEvent(r, "receipt_recorded") { it.edit("payload" to f(it.o("payload"))) }
        invalid(receipt { it.edit("acp" to null) })
        invalid(receipt { it.edit("receipt" to obj("sha256" to other, "bytes" to 100)) })
        invalid(receipt { it.edit("session" to session().edit("requestSha256" to other)) })
        invalid(receipt { it.edit("session" to session().edit("retainedEventCount" to 1)) })
        invalid(receipt { it.edit("session" to session().edit("eventsComplete" to "true")) })
        invalid(receipt { it.edit("session" to session().edit("protocolVersion" to 2)) })
        invalid(receipt { it.edit("session" to session().edit("retainedEventCount" to 3, "eventsComplete" to false)) })
        invalid(receipt { it.edit("acp" to acp(1).edit("requestSha256" to other)) })
        val build = prefix(3, true)
        invalid(editEvent(build, "receipt_recorded") { it.edit("payload" to it.o("payload").edit("acp" to acp(1))) })
        val v = prefix(4, true)
        invalid(editEvent(v, "validation_recorded") { it.edit("payload" to obj("observation" to null, "diagnostic" to null)) })
    }
    @Test fun B1_23_skips_doubles_and_terminal_operations_cannot_reopen() {
        for (rebuild in listOf(false, true)) {
            val w = work(); val op = operation(w, rebuild = rebuild); val events = operationEvents(w, op, 1)
            for (i in events.indices) {
                invalid(root(listOf(w), listOf(op), listOf(prepared(w)) + events.take(i) + events[i] + events.drop(i)))
                if (i < events.lastIndex) invalid(root(listOf(w), listOf(op), listOf(prepared(w)) + events.filterIndexed { j, _ -> j != i }))
            }
            invalid(root(listOf(w), listOf(op), listOf(prepared(w)) + events + event(w, "reserved", obj(), op)))
        }
    }
    @Test fun B1_24_block_preserves_phase_and_requires_same_id_resume() {
        val w = work(); val op = operation(w)
        val reserved = prefix(1); val intent = prefix(2)
        val blocked = event(w, "blocked", obj("reason" to "interrupted", "resume" to resume("dispatch_same_id", op)), op)
        val paused = append(reserved, blocked); valid(paused)
        invalid(append(paused, operationEvents(w, op, 1)[1]))
        valid(append(paused, event(w, "resume_recorded", obj("resume" to resume("dispatch_same_id", op)), op), operationEvents(w, op, 1)[1]))
        invalid(append(intent, blocked))
        valid(append(intent, event(w, "blocked", obj("reason" to "interrupted", "resume" to resume("reconcile_same_id", op)), op)))
    }
    @Test fun B1_25_release_requires_retained_non_dispatch_reconciliation() {
        val w = work(); val op = operation(w); val release = event(w, "released", obj("nonDispatchEvidenceSha256" to h), op)
        valid(append(prefix(1), release)); invalid(append(prefix(2), release))
        val reconciled = event(w, "reconciled", obj("result" to "not_dispatched", "evidenceSha256" to h), op)
        valid(append(prefix(2), reconciled, release))
        valid(append(prefix(2), reconciled, operationEvents(w, op, 1)[1]))
        invalid(append(prefix(2), reconciled, release, release))
    }
    @Test fun B1_26_recovered_unknown_and_graph_resume_paths() {
        val w = work(); val op = operation(w)
        fun reconciled(result: String) = event(w, "reconciled", obj("result" to result, "evidenceSha256" to h), op)
        valid(append(prefix(2), reconciled("receipt_recovered"), operationEvents(w, op, 1)[2]))
        invalid(append(prefix(2), reconciled("receipt_recovered"), operationEvents(w, op, 1)[1]))
        valid(append(prefix(2), reconciled("unknown"), event(w, "blocked", obj("reason" to "reconciliation_required", "resume" to resume("reconcile_same_id", op)), op)))
        valid(append(prefix(2), reconciled("unknown"), event(w, "settled", obj("spent" to op["reservation"], "usageKnown" to false, "evidenceSha256" to h), op)))
        invalid(append(prefix(2), reconciled("unknown"), event(w, "settled", obj("spent" to vector(), "usageKnown" to false, "evidenceSha256" to h), op)))
        valid(append(prefix(3), event(w, "resume_recorded", obj("resume" to resume("validate_retained", op)), op)))
        val build = operation(w, rebuild = true)
        valid(append(prefix(4, true), event(w, "resume_recorded", obj("resume" to resume("reconcile_graph", build)), build)))
        for (reason in listOf("exhausted", "interrupted", "cancelled", "cleanup_unverified", "unavailable", "reconciliation_required"))
            valid(append(minimal(), event(w, "blocked", obj("reason" to reason, "resume" to resume("blocked")))))
        invalid(append(prefix(2), reconciled("unknown"), reconciled("receipt_recovered")))
        val violation = event(w, "accounting_violation", obj("observedSpent" to vector(Long.MAX_VALUE), "evidenceSha256" to h, "reason" to "overflow"), op)
        valid(append(prefix(2), violation, event(w, "blocked", obj("reason" to "exhausted", "resume" to resume("blocked", op)), op)))
        invalid(append(prefix(2), violation, operationEvents(w, op, 1)[2]))
    }
    @Test fun B1_27_fully_accepted_requires_all_local_receipt_proof_and_head_links() {
        val w = work(); val a = operation(w); val b = operation(w, rebuild = true)
        val r = root(listOf(w), listOf(a, b), listOf(prepared(w)) + operationEvents(w, a, 1) + operationEvents(w, b, 1) +
            decision(w, 1, listOf(a, b), "fully_accepted"))
        valid(r)
        invalid(editEvent(r, "receipt_recorded") { it.edit("payload" to it.o("payload").edit("session" to session().edit("eventsComplete" to false))) })
        val compile = observation(1).copy(outcome = RepairValidationObservedOutcome.COMPILE_VALID,
            proof = observation(1).proof.copy(originalBinarySha256 = null))
        var compileOnly = editEvent(r, "validation_recorded") { it.edit("payload" to obj("observation" to compile.toJsonObject(), "diagnostic" to null)) }
        compileOnly = rehash(compileOnly.edit("events" to compileOnly.a("events").map { element ->
            val e = element.jsonObject
            if (e.s("kind") == "receipt_recorded" && e["operationId"] == b["id"]) e.edit("payload" to e.o("payload").edit("providerOutcome" to "compile_valid")) else e
        }))
        invalid(compileOnly)
        for (key in listOf("expectedObservationsSha256", "originalBinarySha256")) invalid(r.edit("binding" to binding().edit(key to null)))
        for ((key, v) in listOf("acceptedHeadId" to rootId, "candidateSourceSha256" to other, "provisionalHeadId" to candidate(1)))
            invalid(editEvent(r, "decision_recorded") { it.edit("payload" to it.o("payload").edit(key to v)) })
        invalid(editEvent(r, "receipt_recorded") { it.edit("payload" to it.o("payload").edit("session" to null)) })
        invalid(editEvent(r, "receipt_recorded") { it.edit("payload" to it.o("payload").edit("acp" to acp(1).edit("receiptReleaseComplete" to false))) })
        invalid(editEvent(r, "validation_recorded") { it.edit("payload" to obj("observation" to observation(1, true).toJsonObject(), "diagnostic" to null)) })
        invalid(editEvent(r, "validation_recorded") { it.edit("payload" to obj("observation" to observation(2).toJsonObject(), "diagnostic" to null)) })
        invalid(root(listOf(w), listOf(a), listOf(prepared(w)) + operationEvents(w, a, 1) + decision(w, 1, listOf(a), "fully_accepted")))
        val finished = fixture(); val last = finished.a("events").last().jsonObject
        invalid(append(finished, last))
        val noChanges = root(listOf(w), listOf(a), listOf(prepared(w)) + operationEvents(w, a, 1, failure = "returned-no-changes") +
            decision(w, 1, listOf(a), "rejected", "no_changes"))
        valid(noChanges)
        invalid(append(noChanges, event(w, "blocked", obj("reason" to "interrupted", "resume" to resume("blocked")))))
        valid(append(noChanges, event(w, "run_finished", obj("runStatus" to "no_changes", "acceptedHeadId" to null,
            "provisionalHeadId" to null, "graphSha256" to h, "resume" to resume()))))
    }
    @Test fun B1_28_caller_and_returned_values_are_immutable() {
        val caller = minimal().toMutableMap(); val works = caller.getValue("works").jsonArray.toMutableList()
        caller["works"] = JsonArray(works)
        val recorded = RecordedShardSchedulerHistory(JsonObject(caller)); val expected = ShardSchedulerBindings.encode(recorded)
        caller.clear(); works.clear()
        assertContentEquals(expected, ShardSchedulerBindings.encode(recorded))
        val failure = assertFailsWith<java.lang.reflect.InvocationTargetException> {
            List::class.java.getMethod("clear").invoke(recorded.record.a("works"))
        }
        assertIs<UnsupportedOperationException>(failure.cause)
        val nested = work().o("ordering").toMutableMap()
        val nestedRoot = minimal(work().edit("ordering" to JsonObject(nested)))
        val nestedRecorded = RecordedShardSchedulerHistory(nestedRoot)
        nested.clear()
        assertContentEquals(expected, ShardSchedulerBindings.encode(nestedRecorded))
        val returned = ShardSchedulerBindings.encode(recorded); returned.fill(0)
        assertContentEquals(expected, ShardSchedulerBindings.encode(recorded))
    }
    @Test fun B1_29_forged_producers_return_only_recorded_data() {
        // All fixture hashes and session claims are invented. Internal consistency cannot authenticate them.
        val imported: RecordedShardSchedulerHistory = ShardSchedulerBindings.decode(bytes(fixture()))
        assertEquals("fully_accepted", imported.record.a("events").last().jsonObject.o("payload").s("runStatus"))
        val methods = ShardSchedulerBindings::class.java.declaredMethods.filter { !it.isSynthetic }.map { it.name }.toSet()
        assertEquals(setOf("encode", "decode", "commitmentSha256"), methods)
        assertTrue(imported::class.java.declaredMethods.none { it.name in setOf("accept", "dispatch", "resume", "execute") })
    }
    @Test fun B1_30_existing_graph_run_and_receipt_value_bytes_are_unchanged_by_projection() {
        val run = RepairRunState("run_00000001", RepairRunStatus.RUNNING, rootId, null, null, h, 2, 0, 1, 100)
        val before = run.toJson(); val observation = observation(1); val observedBefore = bytes(observation.toJsonObject())
        valid(fixture())
        assertEquals(before, run.toJson()); assertContentEquals(observedBefore, bytes(observation.toJsonObject()))
        for (version in 1..4) assertEquals(version, parseRepairRunState(run.copy(schemaVersion = version).toJson()).schemaVersion)
    }

    private companion object {
        const val GOLDEN_SHA = "0d75da43e83ade3a42e6a52210ac197ea90b4aa2f95c2205c5b0f6dc63545ac2"
        const val GOLDEN_GZIP =
            "H4sIAAAAAAAC/+1dWXPbSJJ+96/o4HPLXfexbzPeiV3F7EQ77Il52ehQVGVlSWhTABcAZbsn+r9vApR4gKQOi9Bhk46wJBxVqLzq+7KywH+/+emnSSzKVJTn" +
            "k//46d/0Z3cgNDgtSvyAV0VTVOVponOTuqraM7bnM/l589aP1bwG/HgRhDbdzeGRn2X71bxMmE7pvy9/qdsiB2hH6+XDvDx82wlnSI2X8PX9NJQf4QIvA7XP" +
            "d58+ePf4ZYbQYvo1NlhfhZbU2xy+l1xXf2B5WrZYk4Zwa5TD8wd/gKIzkMM3W9XFeVGG6V/pv/rr4dufkc5L8sXxTPumh3dVmYvzed1bwHjdfMBZVY8xjLrK" +
            "xXQEw6nxvMami3rvqno2b8boYRaKmmLLdVidlzdRld9c0pC/pPkU6/fVtIBD2hm1/+fPfdCfp3Ns/6e4LNpmFfnpYZZ/9F40m7f/rD5h2V3Dfr45flklnL4L" +
            "02l3mK+OV/N29w2z0MLFX7+2uHm4xjgvpmnQymdq+B/FdFosjveH/7yRzEWo++v/9/rqm2elc9NuMGuPf9sQbhvGrUO5ZTj7h7R3WGtDWw1vYRf9ryd88mZw" +
            "1Xc+YLEccP/zt6XB4hWW7UrzSxv9RKG+u33W+VWNabKyxhkuwlvffjmfTtfs8eu0CmlDdpPzOswuDutrG8PtHvGqqNZiysYzNfh/c5r3ccNDPlf1p4V4ut9O" +
            "PLDMjIo6ZKW00wZiMoaZ6DB6yZmIGmUUOmWRU85aOK+s8i7SMZBMTtadaUuEFPgIE+wXIdnWVQX93ydeKe6j515xmZL0UkkTkzYsgEVvIlrDHTfeMGTWofA2" +
            "ctB0PjMhwMfJLl3cIqqJiJizMci4tDE6+p0HEXnGDOCizTImGblyLuuglYpCqWy8ZD44jdyZyS5B8+cRdCqa3qPOCkJAZfts8l7Z/u+E1xe4pqMCT+oEk8B5" +
            "4pKxyCRJ0ZmQDOM86KRk1lJqJ4TLlgUWQXZqVQGd0dqCtEGYJHZqVjyXCwEWs/aMflZ1ekZXWqk2wGw4R4SmIYxzSab3sQ3tvOnjJy5Y4CC498N5H9qLxeg6" +
            "NNf8soAwJ/U1P+wOLH5bIpkzPvi8pcc4uW7u7e9NVe7s6ANOkRjku+pyNsW202Nbz3HXlQtK8S+su27X9b1x0aHB27J5srNmxOab+bR9dxHKc1zzk/jIz2Yn" +
            "RL0uOyrz67yF6hIX6m0pCmA6gWv5p8nOSZvA91WRsL791rUbrtUxNMN4DSg42wQOzcHDzwB0LAD+lleck0OcEvdui/brWLpdwJjbDHxxxVj9F13HneevxaIG" +
            "atIOKS8XX0iNeNsdK4+b8M3rqrhAD3/rnv9dNS/bLbec9XTmL/NUjDdAMs62gmq6elD+1L57iR8wY93NRDuh3vWFbSjKW8XVhDLF6svfOmcrR8iS3HSTPq1p" +
            "lb2V7O1AtdcOc5rGeoQuePxapy4edQpbee094AP3aLjyyLJJUWnpBLrAmE/MeikZKIyKI/0zNJ0yoZn3LsjsDXgJUe+GD/J54EODbTt9EagBxzS6STPD8hHM" +
            "9dDE9eG8dd7QbPH3svpcXofwexgqWQZzNniyhqTRueSUMDYqn8EBd9LKTDbFmPLacOFJucCtzTEIj8on2Gmo6hVQRaa0kIwzhUIwDyl6r5VF7gONi05JYm0y" +
            "aZtMVmCwowBZo3FkNEZm92CqiBAyOTl5ueZgOQiuiQl6joyRH2iug0dQzGfNBDLFwEZt6CJAC5wrtlPQ+vVQxTHk/TKoooHMnQjOOBm0BsaSR6c4NzpS4I8G" +
            "kw6gNHlS4tEGAJmEiJznhJJuszs1a14RVRxXtQuquAlVdqH9iBeBNFOfEQmDT68E63fDuoeJWRQMEwXphEYKJpJRRhvlKFqQHXieITEfpE8cuAKRyRikQvTC" +
            "CstSjjtNzD6PiV2FaZF6y3lJVpaKcF5WTVvAtrFVq2XJoQV1zDLURVOVi1WRPtJ/CdCe9LZ1cjUAranIedDGmh0K/fPmidldOY6VME+6pptfHsvHt9MgG/7w" +
            "aLq/1vCfm4xuqept+QBxjm6Yw8X/OxM8w4EUQwtkt3+2GxhlCXc9rI2ygrgWCEdeSVz1dMta4sqw+oqMG61+HCHsDs2suteE0auiuAz11/3OOpg0Huit1zPS" +
            "+rE7jfHssWK5w7nHkzrZdbUj7oWmmddhMRtNmrYuoD2DqlzkIIbPCVMM5Xz2L6yLXGDakaUamyE+RQQYuZjjKSNNx2Tb4TgOmi9+6oDWFpcjSuzpg2EzWK94" +
            "WI5LOxchIHgnNFEbrbKN0UovImMSNCcWFD2jI0zLCMYajzYStHSO2G2Uu3mPe/k5rnGB6EvOcR2+OONJclxJMuEkpqAUC1EmJolKOa7JQLLzpK8UgvPBxaAt" +
            "WVZK2WUpgBsvmHJS7TRU/0ypF4QF5r2LO91dWhIAsFth+W8MaeuWzQXZUWwxtC1eztpvwPIrQjBSSe81V2tmVVNcU5JFyqF7xDBdv+rQBTrrvHOl0PXqsgFd" +
            "OlxA2mr4sdn8Zbu/DVM3CzkuLe+B6l+sZw3D2EBfZVXicJlzEFq31r+2XWhnECIosKpRoD+6otJ7ZQpJol6kgEykCFzKpALySEEIg4iS/kVlgnMUIILnCimU" +
            "KKc5k55BCrA7jcOfqTDrNda2TYxjLAdtbNAQpEmMKSkho8sGXWJRRetESklIhTH7mMmoOSS6h/zF8rxbA3srtjSAY4gkdLDULBBCMioBZnKgHKxUQFBJ0ewU" +
            "lQvMOYfgnI+GB0mPIfPh1jtkMMk6rQmHdas5UdG8x6GrRNOBRcJxySCBs8BMJh/HpHzyIJJihNwUoH/wegczzlgyM0+CY4lbALDWk8gJFIIXhA67yik6nI1I" +
            "YL3P3FqBnOyTcYTdK6BcPI+kv2HBYxSBv5AFDwvkHA45S4JkGVn23BKo94gJncyJwFUWVhqgecFy0rewxqIEkFajT7tVK5/LiR6+4jGybp+jOE6eycHnW4vj" +
            "cpg2x+q4p66OK6sTWPT+8PK4tXu/ozWzbm01EaqySXgWnCDAA5lCULbkkMmi6oAw0zZ0OJb8lgkCBtbQ3UkLlfbUZqvniVIPyE+MHJyONTgHz0/kiKAhGSCs" +
            "mWkiVWSeGSQqFUPuinCCYFJjJAZAQMp4AONZ7OAqmmz5nvlUPxNU+kESFNsT5nMnKGr8vd9F+7KyE48OR/dOIgys47UmCUJKzIlsgSUlUHgSg+UBaX5KQXNL" +
            "DkgSIoJqmaUpiymRo8LMtAzBkvzk7mhgXj5FNTGnzGgupglZY86etM+EzIyYeWcPjgurJIvCaZqhk9AKHFmM1lzrIDI8mKJy61NA7ZO0nnqTEmOibhnzMngl" +
            "QjQyAwYhUQanAhovuXDeJW+tllHvlrR9NRR1FIG/DIqqDQkugUOdkaFgMQUjrSXWCoJzlbUQPne5sCwChowaMvmR4AT/bJfx3K1a93oo6si6fQ6KKs7E4HPc" +
            "v3Xcv3Xcv3Xcv3Xcv3Xcv3XY/Vs+oXSSEyzw6IWCCFJnDikFiwzo1yxtMgZAK8eC8FH7KIwg5m64ANyzUudffPJoZNhwTB4dPHkkJZmdyMGhFCozl7MVxGN4" +
            "zoiQuZKW/vfonNISWWLKRqmCR+Ho6sR2b+AS7OXTRStpdJ4p57sdUoYbYmqBCeudwegCKB6j79JnJJAYAQjhG5Sss3CSz1q65t4v+wiCR+oIVDQ+MW5tSKLb" +
            "whmASW+IVgTvo3NJAI+JZTofIt0hEncCwh5J81dDF0cR+Auhi9wZFpLUyXU0ERTmZAJLGYIASIyUCJ7iX/fSFsDubSCe01UudiVidGK3asXroYsj6/a4h4se" +
            "w+cUkKONNnPBk1bKpEy/2ois21rrQpQCouKZd4Ymg2bAyUjINLQ2breNPdOq+Tdu4hrZzJ52E9cW+j7AFqbtHMdjtzCJ4xam4xaml7KFSRy3MB23MB23MB23" +
            "ML2QLUweIrropGOaE4zniWibEiCt00JYq1KyzKDKANoriBnB6IzGo7IySLF7rVW8/BqhkXHYcQ/TwdM8EEVIiRgDykRsQaB3WUSmVQwOGNFVMhGPTCZiDbnP" +
            "O5DtCC6yMjLRzbst9TusEXoYpH7eGqLbH+05aogyCfzr2Y1QX1Yl0cFy08OGHx0Nf7QSpW6fF8lboNQYjKaQZC3FJO21F0JZFw0TPgfjRXDBRht4khRKSBc8" +
            "JKZxdzB6rhIlIne5KIvm4jnj0Iju9doMcRCD7rPBVwgyQY6JWTQ5Ga5UAGOtkdw6iQF0FJYrHoyVUdmgoudKGC29JaNSu3d1ibELud5cx4ulJXYDP2lrxJPF" +
            "a+eX37hwclE0bUVMvr98KdMdL57vpNY0B/+GhqUkvnU6m3ScGL+0px1MG4PhTLpvJiERjfsVIsv82yhLpjd20OPVyeCLLcYeV7VaKV/ztOpylIKnEQsmrtcQ" +
            "t9Ow+ynC3nXgW+jBXnKwZwV4DzFYRbXruozxXLetqumIhUiTqz6rtXCKd9XlJY2nD1C/Pe20foyAOyPFBoIpxssHrBYhey+4VxTbeLZVHBL74tDG9S84krDD" +
            "RRJ+jCRrvHCzwrI+vxqwxs7bYJibPNk60tTwS3gL68nF3zbQK3zubfntAPWWV0VdlaPlDMaT8FZu9EeKzbds2PqO0enhdoMe0ekRnR7R6WuOgLe8VOk7joCH" +
            "+06KYwQ8RsAfKAKO8/qwYwT8Bn5+uHeOHvn5kZ8f+fmr5+cHis3LJaitMqr+aNfVnkWmbmnufaj7za1Dl4dQViXZx3TtgkldVe3e8tCVbSXs9oxjCV//C8vr" +
            "da6NLx9eXfB+GkZBWhtV5Duqml7KDoRP+HWxk+fmcU+iJCXTROC6VytyaYJlRmRJ8NdYmg8izQo0WXiRHePaGkM/gtUmSmtpbjF+fdW4rOrLMC3+wPR3HKeI" +
            "c9VFPVJdCcC87nfMnqaBpFanTlSQShttUQYVI8agaLJl3DiOzKOEnDl4DJCES8hS4LLf1SWz1hhVNBs9fiab/UfVLdouuoT5ibjjs1Ha1lf63LwZ4Sb+rV/Q" +
            "hvO+1Ljbs1BM19fjxw77P63vOjjdt9XhQN/V8uBtDsMd6SOWOI9cePxU9cD32N7wBPW821W6ua7+wHJP9F+cPCWkXhOcxlFg+mYXtyCbPvCP9k6FmwdY6OgC" +
            "Q8L6ZOuilYf8sw5lQxRjH3K/Md00B6wHznmvufkG+11DBHYLWikOmEdbZyh9XN3UyL1C7NYDdlWndVfttlnEtV0MOiiU6sJuVS5BzfLPk82iyiVG+RDKTwPW" +
            "kGiSaNoaw+Xp5Yz0tfmGBmKJxXRe47spPcyOu0esEyv6x/mII1XCzsbiO2vvvfiwDJ2jDaPzlf9cAgnCRlslq4cEZKvK0q04WTVAJLN3/XWEtlmqSBC5jwvF" +
            "fkJ/I7t3odnhXHRw07b7I3Hbo/qStetXv/TVa+sl5/25jpSPEbBHm6RWPcwQ5p2or3CD0tyNafamwI786cifvg/+ZCyAhYTCeiWkIeLUvWbZKIgWSVZGxcyw" +
            "e5mtVwxN4pIH56XXSQbCBMju4k/8js8Pwp/uD9EeSp38kTodqdOROr086vToJO89qNOd0fVInY7U6UidnpY68e+fOt0aNleLU2/+fPP/X8jJJw+cAAA="
    }
}
