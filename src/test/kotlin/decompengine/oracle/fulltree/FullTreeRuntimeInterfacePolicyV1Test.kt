package decompengine.oracle.fulltree

import decompengine.analysis.AnalysisDeadline
import decompengine.oracle.core.OracleJson
import java.util.concurrent.TimeUnit
import kotlin.test.*
import kotlinx.serialization.json.*

class FullTreeRuntimeInterfacePolicyV1Test {
    private val categories = listOf("filesystem", "process", "environment", "locale", "terminal", "time")

    @Test fun `all six categories reconcile allowed denied missing and host substituted uses`() {
        val policy = decodePolicy(categories)
        val good = categories.mapIndexed { i, c -> use("good-$i", c, "staged", "input-$i") }
        val host = listOf(
            use("host-filesystem", "filesystem", "/home/dev/.local/lib.so", "open"),
            use("host-process", "process", "bash", "exec"),
            use("host-environment", "environment", "LD_PRELOAD", "host-value"),
            use("host-locale", "locale", "/etc/localtime", "host-zone"),
            use("host-terminal", "terminal", "/dev/tty", "isatty"),
            use("host-time", "time", "host-realtime-unbounded", "read-clock"),
        )
        val observed = decodeUses(good.dropLast(1) + host)
        val findings = FullTreeRuntimeInterfacePolicyV1.detect(policy, observed, budget())
        for (category in categories) assertTrue(findings.any { it.code == "forbidden-host-interface-use:$category" }, category)
        assertTrue(findings.any { it.code.startsWith("missing-expected-runtime-use:time") })

        val missingTime = decodePolicy(categories.dropLast(1))
        assertTrue(FullTreeRuntimeInterfacePolicyV1.detect(missingTime, decodeUses(good), budget()).any { it.code == "missing-runtime-category:time" })
    }

    @Test fun `runtime policy decoder enforces exact schema and clause ceiling at N and N plus one`() {
        val six = policyBytes(categories)
        assertEquals(6, FullTreeRuntimeInterfacePolicyV1.decode(six, budget(ExternalProviderLimitsV1(maximumClauses = 6))).clauses.size)
        assertFails { FullTreeRuntimeInterfacePolicyV1.decode(six, budget(ExternalProviderLimitsV1(maximumClauses = 5))) }
        val extra = "{\"extra\":0,\"kind\":\"runtime-interface-policy-v1\",\"schemaVersion\":1,\"clauses\":[]}".toByteArray()
        assertFails { FullTreeRuntimeInterfacePolicyV1.decode(extra, budget()) }
    }

    @Test fun `event budget counts exact ceiling and rejects next event before reconciliation`() {
        val uses = categories.mapIndexed { i, c -> use("u$i", c, "staged", "input-$i") }
        val policy = decodePolicy(categories)
        val atLimit = decodeUses(uses, ExternalProviderLimitsV1(maximumReferencesAndEvents = 6))
        assertTrue(FullTreeRuntimeInterfacePolicyV1.detect(policy, atLimit, budget(ExternalProviderLimitsV1(maximumReferencesAndEvents = 6))).none { it.category == "consistency" })
        assertFails { decodeUses(uses + use("u6", "time", "staged", "input-5"), ExternalProviderLimitsV1(maximumReferencesAndEvents = 6)) }
    }

    @Test fun `document byte node depth string and aggregate string ceilings admit N reject N minus one`() {
        val bytes = policyBytes(listOf("filesystem"))
        val parsed = OracleJson.parseCanonical(bytes)
        val metrics = metrics(parsed)
        val exact = ExternalProviderLimitsV1(
            maximumDocumentBytes = bytes.size,
            maximumAggregateInputBytes = bytes.size,
            maximumNodes = metrics.nodes,
            maximumDepth = metrics.depth,
            maximumStringBytes = metrics.maximumStringBytes,
            maximumTotalStringBytes = metrics.totalStringBytes,
            maximumClauses = 1,
        )
        assertEquals(1, decodePolicy(listOf("filesystem"), exact).clauses.size)
        assertFails { decodePolicy(listOf("filesystem"), exact.copy(maximumDocumentBytes = bytes.size - 1)) }
        assertFails { decodePolicy(listOf("filesystem"), exact.copy(maximumNodes = metrics.nodes - 1)) }
        assertFails { decodePolicy(listOf("filesystem"), exact.copy(maximumDepth = metrics.depth - 1)) }
        assertFails { decodePolicy(listOf("filesystem"), exact.copy(maximumStringBytes = metrics.maximumStringBytes - 1)) }
        assertFails { decodePolicy(listOf("filesystem"), exact.copy(maximumTotalStringBytes = metrics.totalStringBytes - 1)) }
    }

    @Test fun `work ceiling has an exact successful boundary`() {
        var low = 0L
        var high = 10_000L
        fun succeeds(cap: Long): Boolean = try {
            decodePolicy(categories, ExternalProviderLimitsV1(maximumWorkUnits = cap)); true
        } catch (_: IllegalArgumentException) { false }
        assertTrue(succeeds(high))
        while (high - low > 1) {
            val mid = (low + high) / 2
            if (succeeds(mid)) high = mid else low = mid
        }
        assertTrue(succeeds(high))
        assertFalse(succeeds(low))
    }

    @Test fun `interrupted parent deadline cannot be replaced by child detector work`() {
        val policy = decodePolicy(categories)
        val observed = decodeUses(categories.mapIndexed { i, c -> use("u$i", c, "staged", "input-$i") })
        Thread.currentThread().interrupt()
        try {
            assertFails { FullTreeRuntimeInterfacePolicyV1.detect(policy, observed, budget()) }
        } finally { Thread.interrupted() }
    }

    @Test fun `F3 runtime sets require string tokens including evidence references`() {
        val raw=OracleJson.parseCanonical(policyBytes(categories)).jsonObject
        for(field in listOf("operations","targets","inputs","evidenceRefs")) for(token in listOf(JsonPrimitive(7),JsonPrimitive(true),JsonNull)) {
            val clause=raw["clauses"]!!.jsonArray.first().jsonObject
            val changed=JsonObject(raw+("clauses" to JsonArray(listOf(JsonObject(clause+(field to JsonArray(listOf(token)))))+raw["clauses"]!!.jsonArray.drop(1))))
            assertFails("$field=$token") { FullTreeRuntimeInterfacePolicyV1.decode(OracleJson.canonicalBytes(changed),budget()) }
        }
    }

    @Test fun `F10 declared process and locale paths cannot assert finite namespace approval`() {
        for(category in listOf("process","locale")) for(path in listOf("/home/dev/tool","/opt/developer/resource","relative/../../host","/runtime/lib/declared")) {
            val clause=RuntimeInterfaceClauseV1("id",category,"owner",setOf("observe"),setOf(path),setOf("input"),"any",listOf("declaration"))
            val observed=RecordedRuntimeInterfacesV1(listOf(RecordedRuntimeInterfaceUseV1("event",category,"owner","observe",path,"input","ok")))
            val findings=FullTreeRuntimeInterfacePolicyV1.detect(RuntimeInterfacePolicyV1(listOf(clause)),observed,budget())
            assertTrue(findings.any { it.code=="runtime-$category-namespace-binding-unavailable" })
        }
    }

    @Test fun `runtime constructor snapshots and nested population caps are enforced`() {
        val operations=mutableSetOf("observe");val refs=mutableListOf("proof")
        val clause=RuntimeInterfaceClauseV1("id","time","owner",operations,setOf("staged"),setOf("input"),"any",refs)
        val clauses=mutableListOf(clause);val policy=RuntimeInterfacePolicyV1(clauses)
        operations.clear();refs.clear();clauses.clear()
        assertEquals(setOf("observe"),policy.clauses.single().operations); assertEquals(listOf("proof"),policy.clauses.single().evidenceRefs)
        val p=policyBytes(listOf("time"))
        assertNotNull(FullTreeRuntimeInterfacePolicyV1.decode(p,budget(ExternalProviderLimitsV1(maximumReferencesAndEvents=4))))
        assertFails { FullTreeRuntimeInterfacePolicyV1.decode(p,budget(ExternalProviderLimitsV1(maximumReferencesAndEvents=3))) }
    }

    @Test fun `runtime trace gaps descendants and truncation cannot be smuggled through the old observation schema`() {
        val raw=OracleJson.parseCanonical(usesBytes(listOf(use("one","process","staged","input")))).jsonObject
        for(field in listOf("descendantsComplete","traceSequence","traceTruncated","buildRunId","graphActionId")) {
            val changed=JsonObject(raw+(field to JsonPrimitive(true)))
            assertFails { FullTreeRuntimeInterfacePolicyV1.decodeObserved(OracleJson.canonicalBytes(changed),budget()) }
        }
    }

    @Test fun `typed recorded trace detects gaps lost events and incomplete descendants`() {
        val uses=categories.mapIndexed { i,c -> use("event-$i",c,"staged","input-$i") }
        val raw=OracleJson.parseCanonical(usesBytes(uses)).jsonObject
        val trace=buildJsonObject {
            put("buildRunId","run");put("graphActionId","action");put("firstSequence",0);put("lastSequence",5);put("eventCount",6)
            put("descendantsComplete",true);put("truncated",false);put("lostEvents",0)
        }
        fun findings(t: JsonObject): List<ExternalBoundaryFindingV1> {
            val observed=FullTreeRuntimeInterfacePolicyV1.decodeObserved(OracleJson.canonicalBytes(JsonObject(raw+("trace" to t))),budget())
            return FullTreeRuntimeInterfacePolicyV1.detect(decodePolicy(),observed,budget())
        }
        assertTrue(findings(trace).none { it.category=="consistency" })
        for((field,value,code) in listOf(
            Triple("lastSequence",JsonPrimitive(7),"runtime-trace-sequence-gap"),
            Triple("eventCount",JsonPrimitive(5),"runtime-trace-sequence-gap"),
            Triple("descendantsComplete",JsonPrimitive(false),"runtime-descendant-coverage-gap"),
            Triple("truncated",JsonPrimitive(true),"runtime-trace-loss-or-truncation"),
            Triple("lostEvents",JsonPrimitive(1),"runtime-trace-loss-or-truncation")))
            assertTrue(findings(JsonObject(trace+(field to value))).any { it.code==code },field)
        assertFails { findings(JsonObject(trace+("truncated" to JsonPrimitive("false")))) }
    }

    private fun policyBytes(cats: List<String>) = OracleJson.canonicalBytes(buildJsonObject {
        put("schemaVersion", 1); put("kind", "runtime-interface-policy-v1")
        put("clauses", JsonArray(cats.mapIndexed { i, c -> buildJsonObject {
            put("id", "c$i"); put("category", c); put("subjectOwner", "owner")
            put("operations", buildJsonArray { add("observe") }); put("targets", buildJsonArray { add("staged") })
            put("inputs", buildJsonArray { add("input-$i") }); put("observableResultPolicy", "any")
            put("evidenceRefs", buildJsonArray { add("fixture") })
        } }))
    })
    private fun usesBytes(uses: List<JsonObject>) = OracleJson.canonicalBytes(buildJsonObject {
        put("schemaVersion", 1); put("kind", "runtime-interface-observations-v1"); put("uses", JsonArray(uses))
    })
    private fun use(id: String, category: String, target: String, input: String) = buildJsonObject {
        put("id", id); put("category", category); put("subjectOwner", "owner"); put("operation", "observe")
        put("target", target); put("input", input); put("result", "ok")
    }
    private data class JsonMetrics(val nodes: Int, val depth: Int, val maximumStringBytes: Int, val totalStringBytes: Int)
    private fun metrics(root: JsonElement): JsonMetrics {
        var nodes = 0; var maxDepth = 0; var maxString = 0; var totalStrings = 0
        fun charge(text: String) { val size = text.toByteArray(Charsets.UTF_8).size; maxString = maxOf(maxString, size); totalStrings += size }
        fun visit(value: JsonElement, depth: Int) {
            nodes++
            when (value) {
                is JsonObject -> { maxDepth = maxOf(maxDepth, depth); value.forEach { (key, child) -> charge(key); visit(child, depth + 1) } }
                is JsonArray -> { maxDepth = maxOf(maxDepth, depth); value.forEach { visit(it, depth + 1) } }
                is JsonPrimitive -> if (value.isString) charge(value.content)
            }
        }
        visit(root, 1)
        return JsonMetrics(nodes, maxDepth, maxString, totalStrings)
    }
    private fun decodePolicy(cats: List<String> = categories, limits: ExternalProviderLimitsV1 = ExternalProviderLimitsV1()) =
        FullTreeRuntimeInterfacePolicyV1.decode(policyBytes(cats), budget(limits))
    private fun decodeUses(uses: List<JsonObject>, limits: ExternalProviderLimitsV1 = ExternalProviderLimitsV1()) =
        FullTreeRuntimeInterfacePolicyV1.decodeObserved(usesBytes(uses), budget(limits))
    private fun budget(limits: ExternalProviderLimitsV1 = ExternalProviderLimitsV1()) =
        ExternalBoundaryBudgetV1(limits, AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(10), "runtime interface test"))
}
