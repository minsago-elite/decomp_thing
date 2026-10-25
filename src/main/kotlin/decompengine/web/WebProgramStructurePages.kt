package decompengine.web

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
    private val read: (String, String, String, (WebProgramStructureIndex, () -> ByteArray) -> JsonObject) -> JsonObject,
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

    private fun offset(owner: String, route: String, index: WebProgramStructureIndex, query: Query, total: Int): Int {
        val cursor = query.cursor ?: return 0
        val parts = cursor.split('_')
        if (!MessageDigest.isEqual(signature(owner, route, query.fields.toSortedMap().toString(), query.limit, parts[0], parts[1]).toByteArray(),
                parts[2].toByteArray())) invalidCursor()
        if (parts[0] != index.structureVersion) {
            throw WebAccessDenied(410, "CURSOR_EXPIRED", "The structure records changed. Refresh the first page.")
        }
        return parts[1].toInt().also { if (it == 0 || it >= total) invalidCursor() }
    }

    private fun page(owner: String, route: String, index: WebProgramStructureIndex, query: Query, next: Int?): JsonObject = buildJsonObject {
        put("limit", query.limit); put("snapshotVersion", index.structureVersion)
        put("nextCursor", next?.let { JsonPrimitive("${index.structureVersion}_${it}_${signature(owner, route,
            query.fields.toSortedMap().toString(), query.limit, index.structureVersion, it)}") } ?: JsonNull)
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
                val items = ids.subList(start, minOf(ids.size, start + query.limit)).map { id ->
                    table.index[id]?.let { entityItem(index, table, it) } ?: buildJsonObject {
                        put("kind", kind.wire); put("entityId", id); put("selector", JsonNull); put("recorded", false)
                    }
                }
                put("owned", buildJsonObject {
                    put("kind", kind.wire); put("total", ids.size); put("items", JsonArray(items))
                    put("page", page(owner, route, index, query, (start + items.size).takeIf { it < ids.size }))
                })
            }.let(::JsonObject)
        }
    }

    fun entity(kind: WebStructureKind, jobId: String, runId: String, revisionId: String, selector: String, rawQuery: String?): JsonObject {
        val query = parse(rawQuery, emptySet(), paged = false)
        return read(jobId, runId, revisionId) { index, readModel ->
            pinned(index, query)
            header(index).apply {
                if (!index.available) { put("entity", JsonNull); return@apply }
                val table = index.table(kind)
                val row = table.index[selector]?.takeIf { addressable(selector) } ?: throw WebAccessDenied(404,
                    "ENTITY_NOT_FOUND", "The requested ${kind.wire} is not recorded in this revision's program model.")
                val fields = readWebStructureEntity(readModel(), table.offsets[row])
                put("entity", JsonObject(entityItem(index, table, row) + detail(index, table, row, fields)))
            }.let(::JsonObject)
        }
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
        private val SELECTOR = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
        /** Only identifiers that match the URL selector grammar are addressable; others remain listed without a link. */
        fun addressable(value: String): Boolean = SELECTOR.matches(value)
    }
}
