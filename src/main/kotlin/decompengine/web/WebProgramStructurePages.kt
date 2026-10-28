package decompengine.web

import java.math.BigDecimal
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.*

/**
 * Bounded pages over one revision's recorded program model and module plan. Every response carries the
 * revision binding, record digests and model/plan states; an unavailable record never yields empty rows.
 */
internal class WebProgramStructurePages(
    private val read: (String, String, String, (WebProgramStructureIndex, WebStructureRecordReader) -> JsonObject) -> JsonObject,
) {
    private val secret = ByteArray(32).also(SecureRandom()::nextBytes)

    private class Query(val fields: Map<String, String>, val limit: Int, val cursor: String?, val version: String?)

    private fun parse(raw: String?, allowed: Set<String>, paged: Boolean = true): Query {
        fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED", "Use known structure filters and a page limit between 1 and 200.")
        val fields = linkedMapOf<String, String>()
        if (raw != null) {
            if (raw.isEmpty() || raw.length > 4096) invalid()
            for (part in raw.split('&')) {
                val split = part.indexOf('=')
                if (split < 1) invalid()
                val key = part.substring(0, split)
                if (key !in allowed + (if (paged) setOf("limit", "cursor") else emptySet()) + "structureVersion" || key in fields) invalid()
                val value = try { URLDecoder.decode(part.substring(split + 1), StandardCharsets.UTF_8) } catch (_: Exception) { invalid() }
                if (value.isEmpty() || value.length > 256 || value.any { it.code < 32 || it.code == 127 || it == '�' }) invalid()
                fields[key] = value
            }
        }
        val limit = fields.remove("limit")?.let { if (!it.matches(Regex("[1-9][0-9]{0,2}"))) invalid(); it.toInt() } ?: 50
        if (limit !in 1..200) invalid()
        val cursor = fields.remove("cursor")
        if (cursor != null && !cursor.matches(Regex("[a-f0-9]{64}_(0|[1-9][0-9]{0,6})_[a-f0-9]{32}"))) invalidCursor()
        val version = fields.remove("structureVersion")
        if (version != null && !version.matches(Regex("[a-f0-9]{64}"))) invalid()
        return Query(fields, limit, cursor, version)
    }

    private fun pinned(index: WebProgramStructureIndex, query: Query) {
        if (query.version != null && query.version != index.structureVersion) throw WebAccessDenied(409, "STRUCTURE_CHANGED",
            "The selected revision structure records changed. Return to the inventory and read its current records.")
    }

    // JSON quotes separators inside values, unlike Map.toString()'s ambiguous display format.
    private fun filters(query: Query): String = JsonObject(query.fields.toSortedMap().mapValues { JsonPrimitive(it.value) }).toString()

    private fun offset(owner: String, route: String, index: WebProgramStructureIndex, query: Query, total: Int): Int {
        val cursor = query.cursor ?: return 0
        val parts = cursor.split('_')
        if (!MessageDigest.isEqual(signature(owner, route, filters(query), query.limit, parts[0], parts[1]).toByteArray(),
                parts[2].toByteArray())) invalidCursor()
        if (parts[0] != index.structureVersion) {
            throw WebAccessDenied(410, "CURSOR_EXPIRED", "The structure records changed. Refresh the first page.")
        }
        return parts[1].toInt().also { if (it == 0 || it >= total) invalidCursor() }
    }

    private fun page(owner: String, route: String, index: WebProgramStructureIndex, query: Query, next: Int?): JsonObject = buildJsonObject {
        put("limit", query.limit); put("snapshotVersion", index.structureVersion)
        put("nextCursor", next?.let { JsonPrimitive("${index.structureVersion}_${it}_${signature(owner, route,
            filters(query), query.limit, index.structureVersion, it)}") } ?: JsonNull)
    }

    fun functions(owner: String, jobId: String, runId: String, revisionId: String, rawQuery: String?): JsonObject {
        val query = parse(rawQuery, setOf("sort", "order", "search", "status", "evidence", "ownership", "module"))
        val sort = query.fields["sort"] ?: "address"
        val order = query.fields["order"] ?: "asc"
        val status = query.fields["status"]?.let { WebExtractionStatus.of(it) ?: invalidFilter() }
        val evidence = query.fields["evidence"]?.let { WebEvidenceState.of(it) ?: invalidFilter() }
        val ownership = query.fields["ownership"]?.also { if (it !in setOf("owned", "unowned", "ambiguous", "not-recorded")) invalidFilter() }
        if (sort !in setOf("address", "name", "id") || order !in setOf("asc", "desc")) invalidFilter()
        val search = query.fields["search"]
        return read(jobId, runId, revisionId) { index, _ ->
            pinned(index, query)
            val route = listOf("functions", jobId, runId, revisionId).joinToString("/")
            header(index).apply {
                put("query", buildJsonObject {
                    put("sort", sort); put("order", order)
                    for (key in listOf("search", "status", "evidence", "ownership", "module")) put(key, query.fields[key]?.let(::JsonPrimitive) ?: JsonNull)
                })
                if (!index.available) {
                    if (query.cursor != null) invalidCursor()
                    put("totalFunctions", JsonNull); put("matchedFunctions", JsonNull); put("items", JsonArray(emptyList()))
                    put("page", page(owner, route, index, query, null))
                    return@apply
                }
                val table = index.table(WebStructureKind.FUNCTION)
                val module = query.fields["module"]?.let { selector -> index.moduleIndex[selector] ?: -100 }
                val orderRows = when (sort) { "name" -> table.byName; "id" -> table.byId; else -> table.byAddress }
                val lowered = search?.lowercase(Locale.ROOT)
                val addressPrefix = lowered?.takeIf { it.matches(Regex("0x[0-9a-f]{1,16}")) }
                val matches = IntArray(table.size)
                var matched = 0
                for (position in orderRows.indices) {
                    val row = orderRows[if (order == "asc") position else orderRows.size - 1 - position]
                    if (status != null && table.status[row] != status) continue
                    if (evidence != null && table.evidence(row) != evidence) continue
                    if (ownership != null && table.ownership(row) != ownership) continue
                    if (module != null && table.owners[row] != module) continue
                    if (lowered != null && !(table.ids[row].contains(lowered, true) || table.names[row]?.contains(lowered, true) == true ||
                            (addressPrefix != null && table.address(row)?.startsWith(addressPrefix) == true))) continue
                    matches[matched++] = row
                }
                val start = offset(owner, route, index, query, matched)
                val items = ArrayList<JsonObject>(query.limit)
                var bytes = 0
                for (position in start until minOf(matched, start + query.limit)) {
                    val item = entityItem(index, table, matches[position])
                    val size = item.toString().toByteArray(Charsets.UTF_8).size + 1
                    if (items.isNotEmpty() && bytes + size > MAXIMUM_ITEM_BYTES) break
                    bytes += size; items += item
                }
                val next = start + items.size
                put("totalFunctions", JsonPrimitive(table.size)); put("matchedFunctions", JsonPrimitive(matched)); put("items", JsonArray(items))
                put("page", page(owner, route, index, query, next.takeIf { it < matched }))
            }.let(::JsonObject)
        }
    }

    fun modules(owner: String, jobId: String, runId: String, revisionId: String, rawQuery: String?): JsonObject {
        val query = parse(rawQuery, emptySet())
        return read(jobId, runId, revisionId) { index, _ ->
            pinned(index, query)
            val route = listOf("modules", jobId, runId, revisionId).joinToString("/")
            header(index).apply {
                put("summary", if (index.available) summary(index) else JsonNull)
                val rows = if (index.available) index.modulesByName else emptyList()
                if (rows.isEmpty() && query.cursor != null) invalidCursor()
                val start = if (rows.isEmpty()) 0 else offset(owner, route, index, query, rows.size)
                val items = rows.subList(start, minOf(rows.size, start + query.limit)).map { moduleItem(index, it) }
                put("totalModules", if (index.available && index.planOutcome.state == "available") JsonPrimitive(rows.size) else JsonNull)
                put("items", JsonArray(items))
                put("page", page(owner, route, index, query, (start + items.size).takeIf { it < rows.size }))
            }.let(::JsonObject)
        }
    }

    fun module(owner: String, jobId: String, runId: String, revisionId: String, selector: String, rawQuery: String?): JsonObject {
        val query = parse(rawQuery, setOf("kind"))
        val kind = when (query.fields["kind"] ?: "functions") {
            "functions" -> WebStructureKind.FUNCTION; "globals" -> WebStructureKind.GLOBAL; "types" -> WebStructureKind.TYPE
            else -> invalidFilter()
        }
        return read(jobId, runId, revisionId) { index, _ ->
            pinned(index, query)
            val route = listOf("module", jobId, runId, revisionId, selector).joinToString("/")
            header(index).apply {
                if (!index.available || index.planOutcome.state != "available") {
                    if (query.cursor != null) invalidCursor()
                    put("module", JsonNull); put("owned", JsonNull)
                    return@apply
                }
                val moduleRow = index.moduleIndex[selector]?.takeIf { addressable(selector) } ?: throw WebAccessDenied(404,
                    "MODULE_NOT_FOUND", "The requested module is not recorded in this revision's module plan.")
                val module = index.modules[moduleRow]
                put("module", moduleItem(index, moduleRow).toMutableMap().apply {
                    put("implementationPath", JsonPrimitive(module.sourcePath))
                    put("implementationFileId", index.sourceFileIds[module.sourcePath]?.let(::JsonPrimitive) ?: JsonNull)
                    put("interfacePath", JsonPrimitive(module.headerPath))
                    put("interfaceFileId", index.sourceFileIds[module.headerPath]?.let(::JsonPrimitive) ?: JsonNull)
                    put("cycle", bounded(module.cycle.filter { it != module.id }, 20) { buildJsonObject {
                        put("moduleId", it); put("selector", it.takeIf(::addressable)?.let(::JsonPrimitive) ?: JsonNull)
                    } })
                    put("boundaryEvidence", bounded(module.boundaryEvidence, 20) { text(WebStructureText.of(it, 256)) })
                }.let(::JsonObject))
                val table = index.table(kind)
                val ids = when (kind) {
                    WebStructureKind.FUNCTION -> module.functionIds; WebStructureKind.GLOBAL -> module.globalIds
                    WebStructureKind.TYPE -> module.typeIds
                }
                val start = if (ids.isEmpty()) { if (query.cursor != null) invalidCursor(); 0 } else offset(owner, route, index, query, ids.size)
                val items = ArrayList<JsonObject>(query.limit)
                fun owned(next: Int?) = buildJsonObject {
                    put("kind", kind.wire); put("total", ids.size); put("items", JsonArray(items))
                    put("page", page(owner, route, index, query, next))
                }
                // Charge the complete data payload, including escape-expanded module metadata and the
                // header. Reserve a longest possible continuation before adding rows; the final cursor
                // can only shrink. The 1,000,000-byte data budget also leaves 48,576 bytes for the fixed
                // WebApiResponse envelope (kind, API version and UUID), below its 1 MiB ceiling.
                put("owned", owned(ids.size.takeIf { it > 0 }))
                var bytes = utf8Bytes(JsonObject(this))
                for (id in ids.subList(start, minOf(ids.size, start + query.limit))) {
                    val item = table.index[id]?.let { entityItem(index, table, it) } ?: buildJsonObject {
                        put("kind", kind.wire); put("entityId", id); put("selector", JsonNull); put("recorded", false)
                    }
                    val size = utf8Bytes(item) + if (items.isEmpty()) 0 else 1
                    if (bytes + size > MAXIMUM_ITEM_BYTES) break
                    bytes += size; items += item
                }
                check(items.isNotEmpty() || ids.isEmpty()) { "Module detail cannot fit an owned row within its response budget." }
                put("owned", owned((start + items.size).takeIf { it < ids.size }))
            }.let(::JsonObject)
        }
    }

    fun entity(kind: WebStructureKind, jobId: String, runId: String, revisionId: String, selector: String, rawQuery: String?): JsonObject {
        val query = parse(rawQuery, emptySet(), paged = false)
        return read(jobId, runId, revisionId) { index, records ->
            pinned(index, query)
            header(index).apply {
                if (!index.available) { put("entity", JsonNull); return@apply }
                val table = index.table(kind)
                val row = table.index[selector]?.takeIf { addressable(selector) } ?: throw WebAccessDenied(404,
                    "ENTITY_NOT_FOUND", "The requested ${kind.wire} is not recorded in this revision's program model.")
                val fields = readWebStructureEntity(records.read(checkNotNull(index.model), WebProgramStructureBuilder.MAXIMUM_MODEL_BYTES),
                    table.offsets[row])
                put("entity", fitDetail(JsonObject(entityItem(index, table, row) + detail(index, table, row, fields))))
            }.let(::JsonObject)
        }
    }

    /**
     * A bounded call or module-dependency neighborhood around one recorded focus. Depth, node and edge limits are
     * explicit; omitted counts are exact or null (unknown) and never imply that a truncated graph is complete.
     */
    fun neighborhood(jobId: String, runId: String, revisionId: String, rawQuery: String?): JsonObject {
        val query = parse(rawQuery, setOf("view", "focus", "direction", "depth", "nodeLimit", "edgeLimit", "unresolved"), paged = false)
        val view = query.fields["view"] ?: "calls"
        val direction = query.fields["direction"] ?: "both"
        val unresolved = query.fields["unresolved"] ?: "show"
        fun bounded(name: String, default: Int, range: IntRange): Int = query.fields[name]?.let {
            if (!it.matches(Regex("[1-9][0-9]{0,2}"))) invalidFilter(); it.toInt()
        }?.takeIf { it in range } ?: if (name in query.fields) invalidFilter() else default
        val depth = bounded("depth", 1, 1..MAXIMUM_DEPTH)
        val nodeLimit = bounded("nodeLimit", 60, 1..MAXIMUM_GRAPH_NODES)
        val edgeLimit = bounded("edgeLimit", 150, 1..MAXIMUM_GRAPH_EDGES)
        val focus = query.fields["focus"]?.takeIf(::addressable) ?: invalidFilter()
        if (view !in setOf("calls", "modules") || direction !in setOf("outgoing", "incoming", "both") ||
            unresolved !in setOf("show", "omit") || (view == "modules" && "unresolved" in query.fields)) invalidFilter()
        return read(jobId, runId, revisionId) { index, _ ->
            pinned(index, query)
            header(index).apply {
                put("query", buildJsonObject {
                    put("view", view); put("focus", focus); put("direction", direction); put("depth", depth)
                    put("nodeLimit", nodeLimit); put("edgeLimit", edgeLimit)
                    put("unresolved", if (view == "calls") JsonPrimitive(unresolved) else JsonNull)
                })
                val graphOutcome = when {
                    !index.available -> index.outcome
                    view == "modules" && index.planOutcome.state != "available" -> index.planOutcome
                    else -> WebStructureOutcome.AVAILABLE
                }
                put("graphState", JsonPrimitive(graphOutcome.state)); put("graphReason", graphOutcome.reason?.let(::JsonPrimitive) ?: JsonNull)
                put("relationships", relationships(index, view, graphOutcome))
                if (graphOutcome.state != "available") { put("neighborhood", JsonNull); return@apply }
                val graph = if (view == "calls") index.callGraph else index.moduleGraph
                val start = if (view == "calls") index.table(WebStructureKind.FUNCTION).index[focus] else index.moduleIndex[focus]
                if (start == null) throw WebAccessDenied(404, if (view == "calls") "ENTITY_NOT_FOUND" else "MODULE_NOT_FOUND",
                    "The requested focus is not recorded in this revision's ${if (view == "calls") "program model" else "module plan"}.")
                val result = WebGraphNeighborhood.of(graph, start, depth, direction != "incoming", direction != "outgoing",
                    nodeLimit, edgeLimit, admit = { it < graph.recorded || unresolved == "show" })
                // Node and edge limits bound counts; long recorded identities could still exceed the browser's byte limit.
                var bounded = result
                var json = neighborhoodJson(index, graph, view, bounded)
                while (utf8Bytes(json) > MAXIMUM_ITEM_BYTES && bounded.nodes.size > 1) {
                    bounded = bounded.prefix(bounded.nodes.size / 2, graph)
                    json = neighborhoodJson(index, graph, view, bounded)
                }
                check(utf8Bytes(json) <= MAXIMUM_ITEM_BYTES) { "Neighborhood exceeds its response budget." }
                put("neighborhood", json)
            }.let(::JsonObject)
        }
    }

    private fun neighborhoodJson(index: WebProgramStructureIndex, graph: WebProgramGraph, view: String,
        result: WebGraphNeighborhood): JsonObject = buildJsonObject {
        val position = HashMap<Int, Int>(result.nodes.size * 2).also { map -> result.nodes.forEachIndexed { at, node -> map[node] = at } }
        val shownOut = IntArray(result.nodes.size); val shownIn = IntArray(result.nodes.size)
        for (edge in result.edges) { shownOut[position.getValue(graph.source(edge))]++; shownIn[position.getValue(graph.target(edge))]++ }
        val functions = index.table(WebStructureKind.FUNCTION)
        put("nodes", JsonArray(result.nodes.mapIndexed { at, node -> buildJsonObject {
            put("index", at); put("depth", result.depths[at])
            put("outgoing", buildJsonObject { put("total", graph.outDegree(node)); put("shown", shownOut[at]) })
            put("incoming", buildJsonObject { put("total", graph.inDegree(node)); put("shown", shownIn[at]) })
            when {
                view == "modules" -> {
                    val module = index.modules[node]
                    put("kind", "module"); put("moduleId", module.id); put("selector", module.id.takeIf(::addressable)?.let(::JsonPrimitive) ?: JsonNull)
                    put("functionCount", module.functionIds.size); put("implementationDeclaration", module.implementationDeclaration)
                    put("inDependencyCycle", module.cycle.isNotEmpty()); put("unattributedReferences", graph.unattributed[node])
                    put("implementationPath", module.sourcePath)
                    put("implementationFileId", index.sourceFileIds[module.sourcePath]?.let(::JsonPrimitive) ?: JsonNull)
                    put("interfacePath", module.headerPath)
                    put("interfaceFileId", index.sourceFileIds[module.headerPath]?.let(::JsonPrimitive) ?: JsonNull)
                }
                node < graph.recorded -> {
                    entityItem(index, functions, node).forEach { (key, value) -> if (key != "recorded" && key != "callCount" && key != "referencedGlobalCount") put(key, value) }
                    val owner = functions.owners[node].takeIf { it >= 0 }?.let { index.modules[it] }
                    put("implementationPath", owner?.sourcePath?.let(::JsonPrimitive) ?: JsonNull)
                    put("implementationFileId", owner?.let { index.sourceFileIds[it.sourcePath] }?.let(::JsonPrimitive) ?: JsonNull)
                }
                else -> { put("kind", "unrecorded-function"); put("entityId", graph.unrecordedIds[node - graph.recorded]); put("selector", JsonNull) }
            }
        } }))
        put("edges", JsonArray(result.edges.map { edge -> buildJsonObject {
            val source = graph.source(edge); val target = graph.target(edge)
            put("source", position.getValue(source)); put("target", position.getValue(target))
            put("relationship", graph.relationship(edge).wire)
            put("resolution", if (target < graph.recorded) "recorded" else "no-record")
            put("references", graph.references(edge))
            put("recordedCycle", view == "modules" && index.modules[source].cycle.let { it.isNotEmpty() && index.modules[target].id in it })
        } }))
        put("completeness", buildJsonObject {
            put("state", if (result.reasons.isEmpty()) "complete" else "truncated")
            put("reasons", JsonArray(result.reasons.map(::JsonPrimitive)))
            fun count(value: Int?) = value?.let(::JsonPrimitive) ?: JsonNull
            put("reachableNodes", count(result.reachableNodes)); put("reachableEdges", count(result.reachableEdges))
            put("omittedNodes", count(result.reachableNodes?.minus(result.nodes.size)))
            put("omittedEdges", count(result.reachableEdges?.minus(result.edges.size)))
            put("edgesBeyondDepth", count(result.edgesBeyondDepth)); put("filteredEdges", count(result.filteredEdges))
        })
    }

    /** Relationship families the selected records support, including the call kinds the model does not record. */
    private fun relationships(index: WebProgramStructureIndex, view: String, outcome: WebStructureOutcome): JsonArray {
        fun family(id: String, state: String, reason: String?) = buildJsonObject {
            put("id", id); put("state", state); put("reason", reason?.let(::JsonPrimitive) ?: JsonNull)
        }
        val available = outcome.state == "available"
        val recorded = if (available) "available" else outcome.state
        return JsonArray(if (view == "calls") listOf(
            family("recorded-call", recorded, if (available) "MODEL_RECORDS_CALL_TARGETS" else outcome.reason),
            family("unrecorded-call-target", recorded, if (available) "CALL_TARGET_HAS_NO_MODEL_RECORD" else outcome.reason),
            family("inferred-endpoint", recorded, if (available) "PARTIAL_OR_SYNTHETIC_EXTRACTION" else outcome.reason),
            family("call-kind", "not-recorded", "MODEL_DOES_NOT_RECORD_DIRECT_OR_INDIRECT_CALLS"),
            family("external-call", "not-recorded", "MODEL_DOES_NOT_RECORD_EXTERNAL_TARGETS"),
        ) else listOf(
            family("module-call", recorded, if (available) "DERIVED_FROM_RECORDED_CALLS_AND_OWNERSHIP" else outcome.reason),
            family("module-global-reference", recorded, if (available) "DERIVED_FROM_RECORDED_GLOBAL_REFERENCES_AND_OWNERSHIP" else outcome.reason),
            family("recorded-dependency-cycle", recorded, if (available) "RECORDED_BY_MODULE_PLAN" else outcome.reason),
            family("unattributed-reference", recorded, if (available) "TARGET_HAS_NO_SINGLE_OWNING_MODULE" else outcome.reason),
            family("call-kind", "not-recorded", "MODEL_DOES_NOT_RECORD_DIRECT_OR_INDIRECT_CALLS"),
        ))
    }

    /** The exact committed bytes of one structure record, for download next to the view that cites its digest. */
    class RecordDownload(val name: String, val sha256: String, val bytes: ByteArray)

    /**
     * One manifest-committed record of the revision (program model, module plan or confidence report), digest-checked
     * and pinned to the structure version the browser displayed, so the download is the record that was cited.
     */
    fun record(jobId: String, runId: String, revisionId: String, recordId: String, rawQuery: String?): RecordDownload {
        val query = parse(rawQuery, emptySet(), paged = false)
        if (query.version == null) invalidFilter()
        if (recordId !in setOf("program-model", "module-plan", "confidence")) throw WebAccessDenied(404, "RECORD_NOT_FOUND",
            "The requested structure record is not one this revision view cites.")
        var download: RecordDownload? = null
        read(jobId, runId, revisionId) { index, records ->
            pinned(index, query)
            val (record, maximum) = when (recordId) {
                "program-model" -> index.model to WebProgramStructureBuilder.MAXIMUM_MODEL_BYTES
                "module-plan" -> index.plan to WebProgramStructureBuilder.MAXIMUM_PLAN_BYTES
                else -> index.confidenceFile?.let { WebStructureRecord(it.path, it.sha256, -1) } to WebConfidenceRecord.MAXIMUM_BYTES
            }
            if (record == null) throw WebAccessDenied(404, "RECORD_NOT_RECORDED", "This revision's manifest does not commit the requested record.")
            download = RecordDownload(record.path.substringAfterLast('/'), record.sha256, records.read(record, maximum))
            JsonObject(emptyMap())
        }
        return checkNotNull(download)
    }

    /**
     * The recorded scorecard of one revision: exact numerators and denominators, recorded values with their
     * reproduction from recorded labels, explicit unmeasured/unknown/partial/failed states and a module page.
     */
    fun scorecard(owner: String, jobId: String, runId: String, revisionId: String, rawQuery: String?): JsonObject {
        val query = parse(rawQuery, setOf("sort", "order"))
        val sort = query.fields["sort"] ?: "module"
        val order = query.fields["order"] ?: "asc"
        if (sort !in setOf("module", "score") || order !in setOf("asc", "desc")) invalidFilter()
        return read(jobId, runId, revisionId) { index, records ->
            pinned(index, query)
            val card = WebStructureScorecard.of(index, records)
            val route = listOf("scorecard", jobId, runId, revisionId).joinToString("/")
            header(index).apply {
                put("confidence", record(card.outcome, card.record, if (card.available) 2 else null))
                put("query", buildJsonObject { put("sort", sort); put("order", order) })
                if (!card.available) {
                    if (query.cursor != null) invalidCursor()
                    put("scorecard", JsonNull); return@apply
                }
                val confidence = checkNotNull(card.confidence)
                val rows = sortedModules(card, sort, order)
                val start = if (rows.isEmpty()) { if (query.cursor != null) invalidCursor(); 0 } else offset(owner, route, index, query, rows.size)
                val items = rows.subList(start, minOf(rows.size, start + query.limit)).map { moduleScore(index, it) }
                put("scorecard", buildJsonObject {
                    put("interpretation", buildJsonObject {
                        put("kind", confidence.interpretationKind); put("schemaVersion", confidence.interpretationSchema)
                        put("calibrationStatus", confidence.calibrationStatus)
                        put("basis", text(WebStructureText.of(confidence.basis, 512)))
                        put("scoreMeaning", text(WebStructureText.of(confidence.scoreMeaning, 512)))
                    })
                    put("formula", formula())
                    put("scope", scope(index, card))
                    put("thresholds", buildJsonObject { put("state", "not-recorded"); put("reason", "HEURISTIC_HAS_NO_VALIDATOR_THRESHOLD") })
                    put("metrics", JsonArray(card.metrics.map { it.json() }))
                    put("labels", JsonArray(card.labels))
                    put("reconciliation", card.reconciliation ?: JsonNull)
                    put("modules", buildJsonObject {
                        put("total", if (index.planOutcome.state == "available") JsonPrimitive(rows.size) else JsonNull)
                        put("items", JsonArray(items))
                        put("page", page(owner, route, index, query, (start + items.size).takeIf { it < rows.size }))
                    })
                })
            }.let(::JsonObject)
        }
    }

    /**
     * Two revisions' scorecards side by side. Deltas are exact differences of recorded values and are computed
     * only when every blocking report, schema and scope identity matches; otherwise they are withheld.
     */
    fun comparison(owner: String, jobId: String, runId: String, revisionId: String, rawQuery: String?): JsonObject {
        val query = parse(rawQuery, setOf("baselineRunId", "baselineRevisionId"))
        val baselineRun = query.fields["baselineRunId"]?.takeIf(::addressable) ?: invalidFilter()
        val baselineRevision = query.fields["baselineRevisionId"]?.takeIf(::addressable) ?: invalidFilter()
        var baseline: Pair<WebProgramStructureIndex, WebStructureScorecard>? = null
        read(jobId, baselineRun, baselineRevision) { index, records ->
            baseline = index to WebStructureScorecard.of(index, records); JsonObject(emptyMap())
        }
        val (baseIndex, baseCard) = checkNotNull(baseline)
        return read(jobId, runId, revisionId) { index, records ->
            pinned(index, query)
            val card = WebStructureScorecard.of(index, records)
            val checks = compatibility(index, card, baseIndex, baseCard)
            val state = when {
                !card.available || !baseCard.available -> "unavailable"
                checks.any { it.blocking && it.state != "match" } -> "incompatible"
                else -> "compatible"
            }
            val withheld = when (state) { "unavailable" -> "SCORECARD_UNAVAILABLE"; "incompatible" -> "INCOMPATIBLE_BASELINE"; else -> null }
            val route = listOf("scorecard-comparison", jobId, runId, revisionId, baseIndex.structureVersion).joinToString("/")
            val ids = if (card.available && baseCard.available) (card.modules.map { it.moduleId } + baseCard.modules.map { it.moduleId }).distinct().sorted()
                else emptyList()
            val start = if (ids.isEmpty()) { if (query.cursor != null) invalidCursor(); 0 } else offset(owner, route, index, query, ids.size)
            val current = card.modules.associateBy { it.moduleId }; val previous = baseCard.modules.associateBy { it.moduleId }
            buildJsonObject {
                put("binding", binding(index))
                put("authority", "recorded-confidence-reports")
                put("structureVersion", index.structureVersion)
                put("current", side(index, card)); put("baseline", side(baseIndex, baseCard))
                put("compatibility", buildJsonObject {
                    put("state", state)
                    put("checks", JsonArray(checks.map { check -> buildJsonObject {
                        put("id", check.id); put("state", check.state); put("blocking", check.blocking)
                        put("current", check.current?.let(::JsonPrimitive) ?: JsonNull); put("baseline", check.baseline?.let(::JsonPrimitive) ?: JsonNull)
                    } }))
                })
                put("metrics", JsonArray(if (!card.available || !baseCard.available) emptyList() else card.metrics.map { metric ->
                    val other = baseCard.metrics.single { it.id == metric.id }
                    buildJsonObject {
                        put("id", metric.id); put("unit", metric.unit)
                        put("current", measure(metric)); put("baseline", measure(other)); put("delta", delta(metric, other, withheld))
                    }
                }))
                put("modules", buildJsonObject {
                    put("total", ids.size)
                    put("items", JsonArray(ids.subList(start, minOf(ids.size, start + query.limit)).map { id ->
                        val now = current[id]?.metric; val then = previous[id]?.metric
                        buildJsonObject {
                            put("moduleId", id); put("selector", id.takeIf { addressable(it) && it in index.moduleIndex }?.let(::JsonPrimitive) ?: JsonNull)
                            put("presence", when { now != null && then != null -> "both"; now != null -> "current-only"; else -> "baseline-only" })
                            put("current", now?.let(::measure) ?: JsonNull); put("baseline", then?.let(::measure) ?: JsonNull)
                            put("delta", if (now != null && then != null) delta(now, then, withheld)
                                else buildJsonObject { put("state", "not-comparable"); put("reason", "MODULE_NOT_IN_BOTH_PLANS")
                                    put("value", JsonNull); put("numerator", JsonNull); put("denominator", JsonNull) })
                        }
                    }))
                    put("page", page(owner, route, index, query, (start + query.limit).takeIf { it < ids.size }))
                })
            }
        }
    }

    private class Check(val id: String, val blocking: Boolean, val current: String?, val baseline: String?) {
        val state: String get() = if (current == null || baseline == null) "not-recorded" else if (current == baseline) "match" else "differs"
    }

    private fun compatibility(index: WebProgramStructureIndex, card: WebStructureScorecard,
        baseIndex: WebProgramStructureIndex, baseCard: WebStructureScorecard): List<Check> {
        fun interpretation(card: WebStructureScorecard) = card.confidence?.let { "${it.interpretationKind}/v${it.interpretationSchema}/${it.calibrationStatus}" }
        fun population(index: WebProgramStructureIndex) = if (!index.available) null else index.tables.joinToString("/") { "${it.size} ${it.kind.route}" }
        fun plan(index: WebProgramStructureIndex) = index.plan?.takeIf { index.planOutcome.state == "available" }?.sha256
        return listOf(
            Check("input-binary", true, index.inputSha256, baseIndex.inputSha256),
            Check("reconstruction-profile", true, "${index.profileId}@${index.profileSha256}", "${baseIndex.profileId}@${baseIndex.profileSha256}"),
            Check("confidence-schema", true, card.confidence?.let { "2" }, baseCard.confidence?.let { "2" }),
            Check("score-interpretation", true, interpretation(card), interpretation(baseCard)),
            Check("score-formula", true, card.confidence?.let { decompengine.project.StructuralRecoveryScore.FORMULA },
                baseCard.confidence?.let { decompengine.project.StructuralRecoveryScore.FORMULA }),
            Check("model-schema", true, index.modelSchemaVersion?.toString(), baseIndex.modelSchemaVersion?.toString()),
            Check("entity-population", false, population(index), population(baseIndex)),
            Check("module-plan", false, plan(index), plan(baseIndex)),
        )
    }

    private fun measure(metric: WebScorecardMetric): JsonObject = buildJsonObject {
        put("state", metric.state); put("reason", metric.reason?.let(::JsonPrimitive) ?: JsonNull)
        put("value", metric.value?.let(::JsonPrimitive) ?: JsonNull); put("numerator", metric.numerator?.let(::JsonPrimitive) ?: JsonNull)
        put("denominator", metric.denominator?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
    }

    /** Exact decimal differences of recorded values; withheld for an incompatible baseline, absent for unmeasured sides. */
    private fun delta(current: WebScorecardMetric, baseline: WebScorecardMetric, withheld: String?): JsonObject = buildJsonObject {
        fun difference(a: String?, b: String?) = if (a == null || b == null) JsonNull
            else JsonPrimitive((java.math.BigDecimal(a) - java.math.BigDecimal(b)).let { if (it.signum() == 0) "0" else it.toPlainString() })
        val reason = withheld ?: when {
            current.state != "measured" -> "CURRENT_${current.state.uppercase().replace('-', '_')}"
            baseline.state != "measured" -> "BASELINE_${baseline.state.uppercase().replace('-', '_')}"
            else -> null
        }
        put("state", if (withheld != null) "withheld" else if (reason != null) "not-comparable" else "computed")
        put("reason", reason?.let(::JsonPrimitive) ?: JsonNull)
        val computed = reason == null
        put("value", if (computed) difference(current.value, baseline.value) else JsonNull)
        put("numerator", if (computed) difference(current.numerator, baseline.numerator) else JsonNull)
        put("denominator", if (computed) difference(current.denominator?.toString(), baseline.denominator?.toString()) else JsonNull)
    }

    private fun side(index: WebProgramStructureIndex, card: WebStructureScorecard): JsonObject = buildJsonObject {
        put("binding", binding(index)); put("structureVersion", index.structureVersion); put("sourceSha256", index.reference.sourceSha256)
        put("manifestSha256", index.manifestSha256)
        put("model", record(index.outcome, index.model, index.modelSchemaVersion))
        put("plan", record(index.planOutcome, index.plan, if (index.planOutcome.state == "available") 2 else null))
        put("confidence", record(card.outcome, card.record, if (card.available) 2 else null))
        put("scope", if (card.available) scope(index, card) else JsonNull)
        put("reconciliation", card.reconciliation ?: JsonNull)
    }

    private fun binding(index: WebProgramStructureIndex): JsonObject = buildJsonObject {
        val ref = index.reference
        put("jobId", ref.jobId); put("runId", ref.runId); put("revisionId", ref.revisionId)
    }

    private fun formula(): JsonObject = buildJsonObject {
        put("id", decompengine.project.StructuralRecoveryScore.FORMULA)
        put("weights", JsonArray(decompengine.project.RecoveryStatus.entries.map { status -> buildJsonObject {
            put("label", status.name.lowercase())
            put("weight", decompengine.project.StructuralRecoveryScore.exactWeight(status).toPlainString())
        } }))
        put("rendering", "mean-four-decimal-places")
    }

    private fun scope(index: WebProgramStructureIndex, card: WebStructureScorecard): JsonObject = buildJsonObject {
        put("population", "program-model-entities"); put("inputSha256", index.inputSha256)
        put("modelSha256", checkNotNull(index.model).sha256); put("modelSchemaVersion", index.modelSchemaVersion ?: 1)
        for (table in index.tables) put(table.kind.route, table.size)
        put("entities", card.entities.toString())
        put("modules", if (index.planOutcome.state == "available") JsonPrimitive(index.modules.size) else JsonNull)
    }

    private fun sortedModules(card: WebStructureScorecard, sort: String, order: String): List<WebScorecardModule> {
        val byId = compareBy<WebScorecardModule> { it.moduleId }
        val comparator = if (sort == "module") byId else Comparator<WebScorecardModule> { a, b ->
            // Recorded values order the rows; rows without a measured value follow, in identity order.
            val left = a.metric.value?.takeIf { a.metric.state == "measured" }?.let(::BigDecimal)
            val right = b.metric.value?.takeIf { b.metric.state == "measured" }?.let(::BigDecimal)
            when {
                left != null && right != null -> left.compareTo(right).takeIf { it != 0 } ?: byId.compare(a, b)
                left != null -> -1
                right != null -> 1
                else -> byId.compare(a, b)
            }
        }
        val sorted = card.modules.sortedWith(comparator)
        return when {
            order == "asc" -> sorted
            sort == "module" -> sorted.reversed()
            // Descending scores still list the rows without a measured value last.
            else -> sorted.filter { it.metric.state == "measured" }.reversed() + sorted.filter { it.metric.state != "measured" }
        }
    }

    private fun moduleScore(index: WebProgramStructureIndex, module: WebScorecardModule): JsonObject = buildJsonObject {
        put("moduleId", module.moduleId); put("selector", module.moduleId.takeIf(::addressable)?.let(::JsonPrimitive) ?: JsonNull)
        put("implementationDeclaration", index.modules[module.row].implementationDeclaration)
        put("metric", module.metric.json())
    }

    private fun detail(index: WebProgramStructureIndex, table: WebStructureTable, row: Int,
        fields: WebStructureEntityFields): Map<String, JsonElement> = buildJsonObject {
        put("texts", JsonArray(fields.texts.map { (field, value) -> buildJsonObject {
            put("field", field); put("recorded", value != null)
            put("preview", value?.let(::text) ?: JsonNull)
        } }))
        val functions = index.table(WebStructureKind.FUNCTION)
        val globals = index.table(WebStructureKind.GLOBAL)
        val id = table.ids[row]
        if (table.kind == WebStructureKind.FUNCTION) {
            put("strings", buildJsonObject { put("total", table.stringCounts[row]); put("items", JsonArray(fields.strings.map(::text))) })
            put("calls", references(table.calls[row].toList(), functions))
            put("referencedGlobals", references(table.referencedGlobals[row].toList(), globals))
            put("calledBy", references((0 until functions.size).filter { id in functions.calls[it] }.map { functions.ids[it] }, functions))
        } else {
            put("strings", JsonNull); put("calls", JsonNull); put("referencedGlobals", JsonNull); put("calledBy", JsonNull)
        }
        put("referencedBy", if (table.kind == WebStructureKind.GLOBAL)
            references((0 until functions.size).filter { id in functions.referencedGlobals[it] }.map { functions.ids[it] }, functions) else JsonNull)
        put("byteEvidence", when {
            table.kind != WebStructureKind.GLOBAL -> JsonNull
            (index.modelSchemaVersion ?: 0) < 3 -> JsonPrimitive("unsupported-schema")
            else -> JsonPrimitive(fields.byteEvidence ?: "not-recorded")
        })
        val group = table.names[row]?.let { index.collisions[it] }.orEmpty().filter { it.first != table.kind || it.second != row }
        put("collisions", bounded(group, 20) { (kind, other) -> reference(index.table(kind), other) })
        val owner = table.owners[row].takeIf { it >= 0 }?.let { index.modules[it] }
        put("sources", buildJsonObject {
            put("implementationPath", owner?.sourcePath?.let(::JsonPrimitive) ?: JsonNull)
            put("implementationFileId", owner?.let { index.sourceFileIds[it.sourcePath] }?.let(::JsonPrimitive) ?: JsonNull)
            put("interfacePath", owner?.headerPath?.let(::JsonPrimitive) ?: JsonNull)
            put("interfaceFileId", owner?.let { index.sourceFileIds[it.headerPath] }?.let(::JsonPrimitive) ?: JsonNull)
            put("sharedInterfacePath", index.sharedInterfacePath?.let(::JsonPrimitive) ?: JsonNull)
            put("sharedInterfaceFileId", index.sharedInterfacePath?.let { index.sourceFileIds[it] }?.let(::JsonPrimitive) ?: JsonNull)
        })
    }

    private fun references(ids: List<String>, target: WebStructureTable): JsonObject = bounded(ids, 50) { id ->
        target.index[id]?.let { reference(target, it) } ?: buildJsonObject {
            put("kind", target.kind.wire); put("entityId", id); put("selector", JsonNull); put("name", JsonNull); put("resolution", "no-record")
        }
    }

    private fun reference(table: WebStructureTable, row: Int): JsonObject = buildJsonObject {
        put("kind", table.kind.wire); put("entityId", table.ids[row])
        put("selector", table.ids[row].takeIf(::addressable)?.let(::JsonPrimitive) ?: JsonNull)
        put("name", table.names[row]?.let(::JsonPrimitive) ?: JsonNull); put("resolution", "recorded")
    }

    /**
     * Item-count bounds alone do not bound bytes: long multi-byte names can exceed the browser's 1 MiB response
     * limit. Halve the largest reference list until the detail fits, keeping every recorded total.
     */
    private fun fitDetail(entity: JsonObject): JsonObject {
        val lists = listOf("calls", "calledBy", "referencedGlobals", "referencedBy", "collisions", "strings")
        var current = entity
        while (utf8Bytes(current) > MAXIMUM_ITEM_BYTES) {
            val largest = lists.mapNotNull { key -> (current[key] as? JsonObject)?.let { key to it } }
                .filter { it.second.getValue("items").jsonArray.isNotEmpty() }
                .maxByOrNull { utf8Bytes(it.second) } ?: break
            val items = largest.second.getValue("items").jsonArray
            current = JsonObject(current + (largest.first to JsonObject(largest.second + ("items" to JsonArray(items.take(items.size / 2))))))
        }
        check(utf8Bytes(current) <= MAXIMUM_ITEM_BYTES) { "Entity detail exceeds its response budget." }
        return current
    }

    private fun utf8Bytes(value: JsonElement): Int = value.toString().toByteArray(Charsets.UTF_8).size

    private fun <T> bounded(values: List<T>, limit: Int, render: (T) -> JsonElement): JsonObject = buildJsonObject {
        put("total", values.size); put("items", JsonArray(values.take(limit).map(render)))
    }

    private fun text(value: WebStructureText): JsonObject = buildJsonObject {
        put("text", value.text); put("characters", value.characters.toString()); put("truncated", value.truncated)
    }

    private fun entityItem(index: WebProgramStructureIndex, table: WebStructureTable, row: Int): JsonObject = buildJsonObject {
        put("kind", table.kind.wire); put("entityId", table.ids[row])
        put("selector", table.ids[row].takeIf(::addressable)?.let(::JsonPrimitive) ?: JsonNull)
        put("recorded", true)
        put("name", table.names[row]?.let(::JsonPrimitive) ?: JsonNull)
        put("address", table.address(row)?.let(::JsonPrimitive) ?: JsonNull)
        put("extractionStatus", table.status[row].wire)
        put("evidenceState", table.evidence(row).wire)
        put("ownership", table.ownership(row))
        val module = table.owners[row].takeIf { it >= 0 }?.let { index.modules[it].id }
        put("moduleId", module?.let(::JsonPrimitive) ?: JsonNull)
        put("moduleSelector", module?.takeIf(::addressable)?.let(::JsonPrimitive) ?: JsonNull)
        put("implementationUnresolved", table.implementationUnresolved[row])
        put("reportedUnresolved", table.recoveryUnresolved[row])
        put("nameCollision", table.names[row]?.let { it in index.collisions } == true)
        if (table.kind == WebStructureKind.FUNCTION) {
            put("callCount", table.calls[row].size); put("referencedGlobalCount", table.referencedGlobals[row].size)
        }
    }

    private fun moduleItem(index: WebProgramStructureIndex, row: Int): JsonObject {
        val module = index.modules[row]
        val functions = index.table(WebStructureKind.FUNCTION)
        val counts = IntArray(WebEvidenceState.entries.size)
        for (id in module.functionIds) functions.index[id]?.let { counts[functions.evidence(it).ordinal]++ }
        return buildJsonObject {
            put("moduleId", module.id); put("selector", module.id.takeIf(::addressable)?.let(::JsonPrimitive) ?: JsonNull)
            put("functionCount", module.functionIds.size); put("globalCount", module.globalIds.size); put("typeCount", module.typeIds.size)
            put("implementationDeclaration", module.implementationDeclaration)
            put("inDependencyCycle", module.cycle.isNotEmpty())
            put("functionEvidence", buildJsonObject { WebEvidenceState.entries.forEach { put(it.wire, counts[it.ordinal]) } })
        }
    }

    private fun summary(index: WebProgramStructureIndex): JsonObject = buildJsonObject {
        val functions = index.table(WebStructureKind.FUNCTION)
        val globals = index.table(WebStructureKind.GLOBAL)
        for (table in index.tables) put(table.kind.route, buildJsonObject {
            put("total", table.size)
            val evidence = IntArray(WebEvidenceState.entries.size)
            val extraction = IntArray(WebExtractionStatus.entries.size)
            val ownership = linkedMapOf("owned" to 0, "unowned" to 0, "ambiguous" to 0, "not-recorded" to 0)
            for (row in 0 until table.size) {
                evidence[table.evidence(row).ordinal]++; extraction[table.status[row].ordinal]++
                ownership[table.ownership(row)] = ownership.getValue(table.ownership(row)) + 1
            }
            put("evidence", buildJsonObject { WebEvidenceState.entries.forEach { put(it.wire, evidence[it.ordinal]) } })
            put("extraction", buildJsonObject { WebExtractionStatus.entries.forEach { put(it.wire, extraction[it.ordinal]) } })
            put("ownership", buildJsonObject { ownership.forEach { (key, value) -> put(key, value) } })
        })
        put("modules", index.modules.size)
        put("modulesDeclaredAccepted", index.modules.count { it.implementationDeclaration == "accepted" })
        put("dependencyCycles", index.modules.map { it.cycle }.filter { it.isNotEmpty() }.distinct().size)
        put("unknownPlanReferences", index.unknownPlanReferences)
        put("nameCollisions", index.collisions.size)
        put("unresolvedCallTargets", (0 until functions.size).sumOf { row -> functions.calls[row].count { it !in functions.index } })
        put("unresolvedGlobalReferences", (0 until functions.size).sumOf { row -> functions.referencedGlobals[row].count { it !in globals.index } })
    }

    private fun header(index: WebProgramStructureIndex): MutableMap<String, JsonElement> = linkedMapOf<String, JsonElement>().apply {
        val ref = index.reference
        put("binding", buildJsonObject { put("jobId", ref.jobId); put("runId", ref.runId); put("revisionId", ref.revisionId) })
        put("authority", JsonPrimitive("recorded-program-model"))
        put("state", JsonPrimitive(index.outcome.state)); put("stateReason", index.outcome.reason?.let(::JsonPrimitive) ?: JsonNull)
        put("structureVersion", JsonPrimitive(index.structureVersion))
        put("sourceSha256", JsonPrimitive(ref.sourceSha256)); put("metadataVersion", JsonPrimitive(index.metadataVersion))
        put("manifestSha256", JsonPrimitive(index.manifestSha256))
        put("model", record(index.outcome, index.model, index.modelSchemaVersion))
        put("plan", record(index.planOutcome, index.plan, if (index.planOutcome.state == "available") 2 else null))
        put("recoveryAssessment", JsonPrimitive(if (index.available && (index.modelSchemaVersion ?: 1) >= 2) "unassessed" else "not-recorded"))
        put("capabilities", capabilities(index))
    }

    private fun record(outcome: WebStructureOutcome, record: WebStructureRecord?, schema: Int?): JsonObject = buildJsonObject {
        put("state", outcome.state); put("stateReason", outcome.reason?.let(::JsonPrimitive) ?: JsonNull)
        put("path", record?.path?.let(::JsonPrimitive) ?: JsonNull); put("sha256", record?.sha256?.let(::JsonPrimitive) ?: JsonNull)
        put("sizeBytes", record?.sizeBytes?.toString()?.let(::JsonPrimitive) ?: JsonNull)
        put("schemaVersion", schema?.let(::JsonPrimitive) ?: JsonNull)
    }

    /** Fact families this adapter can show for the selected records, including families no producer records yet. */
    private fun capabilities(index: WebProgramStructureIndex): JsonArray {
        fun capability(id: String, state: String, reason: String?) = buildJsonObject {
            put("id", id); put("state", state); put("reason", reason?.let(::JsonPrimitive) ?: JsonNull)
        }
        val model = index.available
        val schema = index.modelSchemaVersion ?: 0
        val headers = model && index.modules.isNotEmpty() && index.modules.all { it.headerPath in index.sourceFileIds }
        return JsonArray(listOf(
            capability("function-inventory", if (model) "available" else index.outcome.state, index.outcome.reason),
            capability("recorded-prototypes", if (model) "available" else "not-recorded", if (model) "PROTOTYPE_TEXT_NOT_ABI_CHECKED" else index.outcome.reason),
            capability("module-ownership", if (model) index.planOutcome.state else "not-recorded", if (model) index.planOutcome.reason else index.outcome.reason),
            capability("generated-headers", if (headers) "available" else "not-recorded", if (headers) null else "MODULE_HEADERS_NOT_RECORDED"),
            capability("global-byte-evidence", if (model && schema >= 3) "available" else "not-recorded", if (model && schema >= 3) null else "MODEL_SCHEMA_BEFORE_3"),
            capability("recovery-assessment", "not-recorded", "EXTRACTION_LABELS_ARE_UNASSESSED"),
            capability("type-references", "not-recorded", "MODEL_RECORDS_DECLARATION_TEXT_ONLY"),
            capability("type-layouts", "not-recorded", "A_SERIES_LAYOUT_FACTS_NOT_RECORDED"),
            capability("abi-interfaces", "not-recorded", "A_SERIES_ABI_FACTS_NOT_RECORDED"),
            capability("cpp-object-model", "not-recorded", "A_SERIES_CPP_FACTS_NOT_RECORDED"),
        ))
    }

    private fun signature(vararg fields: Any): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
        return mac.doFinal(fields.joinToString("\u0000").toByteArray(Charsets.UTF_8)).take(16).joinToString("") { "%02x".format(it) }
    }

    private fun invalidFilter(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED", "Use known structure filters and a page limit between 1 and 200.")

    private fun invalidCursor(): Nothing = throw WebAccessDenied(400, "INVALID_CURSOR",
        "Use a structure cursor from this session, revision, filter set and page size, or refresh the first page.")

    companion object {
        private const val MAXIMUM_ITEM_BYTES = 1_000_000
        const val MAXIMUM_DEPTH = 3
        const val MAXIMUM_GRAPH_NODES = 200
        const val MAXIMUM_GRAPH_EDGES = 400
        private val SELECTOR = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
        /** Only identifiers that match the URL selector grammar are addressable; others remain listed without a link. */
        fun addressable(value: String): Boolean = SELECTOR.matches(value)
    }
}
