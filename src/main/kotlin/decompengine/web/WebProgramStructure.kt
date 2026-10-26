package decompengine.web

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ModulePlan
import decompengine.project.ModulePlanJson
import decompengine.project.ProjectFileRole
import decompengine.project.ReconstructionProfile
import decompengine.project.ReferencedDataByteEvidenceJson
import decompengine.project.SourceTreeManifest
import java.util.concurrent.CancellationException
import kotlinx.serialization.json.Json

/** Recorded entity families of one program model. The array index is the wire `kind` order. */
internal enum class WebStructureKind(val wire: String, val route: String) {
    FUNCTION("function", "functions"), GLOBAL("global", "globals"), TYPE("type", "types");
}

/** Producer extraction labels. None of them is a scored recovery assessment. */
internal enum class WebExtractionStatus(val wire: String) {
    RECOVERED("recovered"), PARTIAL("partial"), FAILED("failed"), SYNTHETIC("synthetic");

    companion object { fun of(value: String): WebExtractionStatus? = entries.singleOrNull { it.wire == value } }
}

/**
 * Display classification derived only from recorded fields, in this precedence:
 * excluded (the recorded plan assigns no module), unresolved (failed extraction, ambiguous
 * plan ownership or a manifest-recorded unresolved implementation), inferred (partial or
 * synthetic extraction) and recovered (an extraction label only; still unassessed).
 */
internal enum class WebEvidenceState(val wire: String) {
    RECOVERED("recovered"), INFERRED("inferred"), UNRESOLVED("unresolved"), EXCLUDED("excluded");

    companion object { fun of(value: String): WebEvidenceState? = entries.singleOrNull { it.wire == value } }
}

internal const val OWNER_UNOWNED = -1
internal const val OWNER_AMBIGUOUS = -2
internal const val OWNER_NOT_RECORDED = -3

/** Compact, immutable columns. Text bodies stay in the committed model and are read per detail request. */
internal class WebStructureTable(
    val kind: WebStructureKind,
    val ids: Array<String>,
    val names: Array<String?>,
    val addresses: LongArray,
    val hasAddress: BooleanArray,
    val status: Array<WebExtractionStatus>,
    val offsets: LongArray,
    val owners: IntArray,
    val implementationUnresolved: BooleanArray,
    val recoveryUnresolved: BooleanArray,
    val calls: Array<Array<String>>,
    val referencedGlobals: Array<Array<String>>,
    val stringCounts: IntArray,
) {
    val size: Int get() = ids.size
    val index: Map<String, Int> = HashMap<String, Int>(ids.size * 2).also { map -> ids.forEachIndexed { i, id -> map[id] = i } }
    // Unsigned 64-bit order; entities without a recorded address (types only) follow all addresses.
    private val addressOrder = Comparator<Int> { a, b ->
        val recorded = hasAddress[b].compareTo(hasAddress[a])
        if (recorded != 0) recorded else {
            val address = java.lang.Long.compareUnsigned(addresses[a], addresses[b])
            if (address != 0) address else ids[a].compareTo(ids[b])
        }
    }
    // Total orders with an identity tie-break, built on first use; canonical models are already address-ordered.
    val byAddress: IntArray by lazy {
        if ((1 until ids.size).all { addressOrder.compare(it - 1, it) < 0 }) IntArray(ids.size) { it } else order(addressOrder)
    }
    val byName: IntArray by lazy {
        order(Comparator { a, b ->
            val name = (names[a] ?: ids[a]).compareTo(names[b] ?: ids[b])
            if (name != 0) name else ids[a].compareTo(ids[b])
        })
    }
    val byId: IntArray by lazy { order(Comparator { a, b -> ids[a].compareTo(ids[b]) }) }

    private fun order(comparator: Comparator<Int>): IntArray =
        (0 until ids.size).sortedWith(comparator).toIntArray()

    fun evidence(row: Int): WebEvidenceState = when {
        owners[row] == OWNER_UNOWNED -> WebEvidenceState.EXCLUDED
        status[row] == WebExtractionStatus.FAILED || owners[row] == OWNER_AMBIGUOUS || implementationUnresolved[row] ->
            WebEvidenceState.UNRESOLVED
        status[row] == WebExtractionStatus.PARTIAL || status[row] == WebExtractionStatus.SYNTHETIC -> WebEvidenceState.INFERRED
        else -> WebEvidenceState.RECOVERED
    }

    fun ownership(row: Int): String = when (owners[row]) {
        OWNER_UNOWNED -> "unowned"
        OWNER_AMBIGUOUS -> "ambiguous"
        OWNER_NOT_RECORDED -> "not-recorded"
        else -> "owned"
    }

    fun address(row: Int): String? = if (hasAddress[row]) "0x" + java.lang.Long.toHexString(addresses[row]) else null
}

internal class WebStructureModule(
    val id: String,
    val sourcePath: String,
    val headerPath: String,
    val functionIds: List<String>,
    val globalIds: List<String>,
    val typeIds: List<String>,
    val boundaryEvidence: List<String>,
    val implementationDeclaration: String,
    val cycle: List<String>,
)

/** Explicit model-level outcome. Only `available` carries entity rows. */
internal class WebStructureOutcome(val state: String, val reason: String?) {
    companion object {
        val AVAILABLE = WebStructureOutcome("available", null)
    }
}

/**
 * One manifest-bound projection of the committed program model and module plan of a revision.
 * Every fact is copied from those two records or the manifest; nothing is inferred from source text.
 */
internal class WebProgramStructureIndex(
    val reference: WebRevisionSourceReference,
    val manifestSha256: String,
    val descriptorSha256: String,
    val inputSha256: String,
    val metadataVersion: String,
    val outcome: WebStructureOutcome,
    val model: WebStructureRecord?,
    val modelSchemaVersion: Int?,
    val planOutcome: WebStructureOutcome,
    val plan: WebStructureRecord?,
    val tables: List<WebStructureTable>,
    val modules: List<WebStructureModule>,
    val sourceFileIds: Map<String, String>,
    val sharedInterfacePath: String?,
    val unknownPlanReferences: Int,
    val retainedBytes: Long,
) {
    val structureVersion: String = revisionSourceDigest(listOf("program-structure-v1", metadataVersion,
        model?.sha256 ?: "-", plan?.sha256 ?: "-", outcome.state, planOutcome.state).joinToString("\n"))
    val moduleIndex: Map<String, Int> = modules.withIndex().associate { it.value.id to it.index }
    val modulesByName: List<Int> = modules.indices.sortedBy { modules[it].id }

    /** Exact name collisions among recorded functions and globals; types are keyed by declaration identity. */
    val collisions: Map<String, List<Pair<WebStructureKind, Int>>> by lazy { collisionGroups() }

    private fun collisionGroups(): Map<String, List<Pair<WebStructureKind, Int>>> = HashMap<String, MutableList<Pair<WebStructureKind, Int>>>().also { groups ->
        for (table in tables) if (table.kind != WebStructureKind.TYPE) {
            for (row in 0 until table.size) table.names[row]?.let { groups.getOrPut(it) { ArrayList(1) } += table.kind to row }
        }
    }.filterValues { it.size > 1 }

    fun table(kind: WebStructureKind): WebStructureTable = tables[kind.ordinal]
    val available: Boolean get() = outcome.state == "available"
}

internal class WebStructureRecord(val path: String, val sha256: String, val sizeBytes: Long)

internal object WebProgramStructureBuilder {
    const val MAXIMUM_MODEL_BYTES = 64 * 1024 * 1024
    const val MAXIMUM_PLAN_BYTES = 16 * 1024 * 1024
    const val MAXIMUM_FUNCTIONS = 250_000
    const val MAXIMUM_GLOBALS_OR_TYPES = 250_000
    const val MAXIMUM_REFERENCES = 100_000
    const val MAXIMUM_IDENTIFIER_CHARACTERS = 4096
    const val MAXIMUM_MODEL_REFERENCES = 500_000
    const val MAXIMUM_RETAINED_BYTES = 96L * 1024 * 1024
    private val MODULE_ID = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
    private val ADDRESS = Regex("0x(0|[1-9a-f][0-9a-f]{0,15})")

    internal val JSON: JsonFactory = JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .streamReadConstraints(StreamReadConstraints.builder()
            .maxDocumentLength(MAXIMUM_MODEL_BYTES.toLong()).maxNestingDepth(16)
            .maxStringLength(MAXIMUM_MODEL_BYTES).maxNameLength(64).maxNumberLength(32).build())
        .build()

    fun declaredPath(profile: ReconstructionProfile, id: String): String? =
        profile.layout.declarations.singleOrNull { it.id == id }?.let { runCatching { it.materialize() }.getOrNull() }

    fun evidenceFile(profile: ReconstructionProfile, manifest: SourceTreeManifest, id: String): GeneratedFileEvidence? {
        val path = declaredPath(profile, id) ?: return null
        return manifest.files.singleOrNull { it.path == path }?.takeIf { ProjectFileRole.EVIDENCE in it.roles }
    }

    /** The reader supplies bytes already bounded by the store and checked against the manifest digest. */
    fun build(
        snapshot: WebRevisionSourceSnapshot,
        profile: ReconstructionProfile,
        manifest: SourceTreeManifest,
        readEvidence: (GeneratedFileEvidence, Int) -> ByteArray?,
    ): WebProgramStructureIndex {
        val ref = snapshot.reference
        // Identity order, not display order: the same IDs the listings, readers, search and diffs resolve.
        val fileIds = snapshot.files.associate { file -> file.evidence.path to snapshot.fileId(file) }
        val shared = declaredPath(profile, "shared-interface")?.takeIf { it in fileIds }
        val budget = RetainedBudget(64 * 1024L + fileIds.entries.sumOf { 128L + 2L * (it.key.length + it.value.length) })
        var retainedBytes = budget.bytes
        fun result(outcome: WebStructureOutcome, model: WebStructureRecord? = null, schema: Int? = null,
            planOutcome: WebStructureOutcome = WebStructureOutcome("not-recorded", "MODEL_UNAVAILABLE"), plan: WebStructureRecord? = null,
            tables: List<WebStructureTable> = emptyList(), modules: List<WebStructureModule> = emptyList(), unknown: Int = 0) =
            WebProgramStructureIndex(ref, snapshot.manifestSha256, snapshot.descriptorSha256, manifest.inputSha256,
                snapshot.metadataVersion, outcome, model, schema, planOutcome, plan, tables, modules, fileIds, shared, unknown, retainedBytes)
        val modelFile = evidenceFile(profile, manifest, "program-model-evidence")
            ?: return result(WebStructureOutcome("not-recorded",
                if (declaredPath(profile, "program-model-evidence") == null) "PROFILE_DECLARES_NO_MODEL" else "MODEL_NOT_RECORDED"))
        val modelBytes = readEvidence(modelFile, MAXIMUM_MODEL_BYTES)
            ?: return result(WebStructureOutcome("limit-exceeded", "MODEL_BYTES_EXCEEDED"))
        val model = WebStructureRecord(modelFile.path, modelFile.sha256, modelBytes.size.toLong())
        val implementationUnresolved = manifest.unresolvedImplementationIds.toHashSet()
        val recoveryUnresolved = manifest.unresolvedEntityIds.toHashSet()
        val parsed = try {
            budget.charge(0) // Also admit the snapshot/file-identity baseline when the model is empty.
            ModelReader(modelBytes, implementationUnresolved, recoveryUnresolved, budget).read()
        }
            catch (failure: WebStructureFailure) { return result(WebStructureOutcome(failure.state, failure.reason), model) }
            catch (failure: Exception) {
                if (failure is CancellationException || failure is InterruptedException) throw failure
                return result(WebStructureOutcome("invalid", "MODEL_MALFORMED"), model)
            }
        if (parsed.inputSha256 != manifest.inputSha256) {
            return result(WebStructureOutcome("invalid", "MODEL_INPUT_MISMATCH"), model, parsed.schemaVersion)
        }
        retainedBytes = budget.bytes
        val planFile = evidenceFile(profile, manifest, "module-plan-evidence")
        var planOutcome = WebStructureOutcome("not-recorded", "PLAN_NOT_RECORDED")
        var planRecord: WebStructureRecord? = null
        var plan: ModulePlan? = null
        if (planFile != null) {
            val bytes = readEvidence(planFile, MAXIMUM_PLAN_BYTES)
            if (bytes == null) planOutcome = WebStructureOutcome("limit-exceeded", "PLAN_BYTES_EXCEEDED")
            else {
                planRecord = WebStructureRecord(planFile.path, planFile.sha256, bytes.size.toLong())
                planOutcome = try {
                    val candidate = ModulePlanJson.readCanonical(bytes, MAXIMUM_PLAN_BYTES)
                    val planBudget = RetainedBudget(retainedBytes, "PLAN_RETAINED_BYTES_EXCEEDED")
                    validatePlan(candidate, planBudget)
                    plan = candidate
                    retainedBytes = planBudget.bytes
                    WebStructureOutcome.AVAILABLE
                } catch (failure: WebStructureFailure) {
                    WebStructureOutcome(failure.state, failure.reason)
                } catch (failure: Exception) {
                    if (failure is CancellationException || failure is InterruptedException) throw failure
                    if (planSchema(bytes)?.let { it != 2L } == true) WebStructureOutcome("unsupported", "PLAN_SCHEMA_UNSUPPORTED")
                    else WebStructureOutcome("invalid", "PLAN_MALFORMED")
                }
            }
        }
        var unknown = 0
        val modules = ArrayList<WebStructureModule>()
        if (plan != null) {
            val implementation = declaredTemplate(profile, "module-implementation")
            val cycles = HashMap<String, List<String>>()
            plan.dependencyCycles.forEach { cycle -> cycle.forEach { cycles[it] = cycle } }
            val ids = plan.modules.map { it.id }
            if (ids.distinct().size != ids.size || plan.modules.size > WebSourceCatalogSnapshot.MAXIMUM_FILES) {
                planOutcome = WebStructureOutcome("invalid", "PLAN_DUPLICATE_MODULE")
            } else {
                plan.modules.sortedBy { it.id }.forEach { planned ->
                    val implementationFile = manifest.files.singleOrNull { it.path == planned.sourcePath }
                    modules += WebStructureModule(planned.id, planned.sourcePath, planned.headerPath, planned.functionIds,
                        planned.globalIds, planned.typeIds, planned.boundaryEvidence,
                        when (implementationFile?.takeIf { implementation?.matches(it.path) != false }?.acceptedImplementation) {
                            true -> "accepted"; false -> "unaccepted"; null -> "not-classified"
                        }, cycles[planned.id].orEmpty())
                }
                for ((moduleIndex, module) in modules.withIndex()) {
                    for ((kind, owned) in listOf(WebStructureKind.FUNCTION to module.functionIds,
                        WebStructureKind.GLOBAL to module.globalIds, WebStructureKind.TYPE to module.typeIds)) {
                        val table = parsed.tables[kind.ordinal]
                        for (id in owned) {
                            val row = table.index[id]
                            if (row == null) { unknown++; continue }
                            table.owners[row] = if (table.owners[row] == OWNER_UNOWNED) moduleIndex else OWNER_AMBIGUOUS
                        }
                    }
                }
            }
        }
        if (planOutcome.state != "available") {
            modules.clear(); unknown = 0
            parsed.tables.forEach { it.owners.fill(OWNER_NOT_RECORDED) }
        }
        return result(WebStructureOutcome.AVAILABLE, model, parsed.schemaVersion, planOutcome, planRecord, parsed.tables, modules, unknown)
    }

    /** Conservative retained allocation charge, including maps, lazy orders/collisions and array growth.
     * Strings are charged as UTF-16 even on compact-string JVMs; no interning assumption is needed. */
    internal class RetainedBudget(initialBytes: Long, private val reason: String = "MODEL_RETAINED_BYTES_EXCEEDED") {
        var bytes: Long = initialBytes; private set
        fun charge(amount: Long) {
            require(amount >= 0)
            if (amount > MAXIMUM_RETAINED_BYTES - bytes) throw WebStructureFailure("limit-exceeded", reason)
            bytes += amount
        }
        fun string(value: String) = charge(64L + 2L * value.length)
    }

    /** Projection admission, not exact producer ownership: ambiguous and missing entity references remain visible. */
    private fun validatePlan(plan: ModulePlan, budget: RetainedBudget) {
        fun invalid(): Nothing = throw WebStructureFailure("invalid", "PLAN_MALFORMED")
        fun identifier(value: String) {
            if (value.isEmpty()) invalid()
            if (value.length > MAXIMUM_IDENTIFIER_CHARACTERS) throw WebStructureFailure("limit-exceeded", "PLAN_IDENTIFIER_EXCEEDED")
            budget.string(value)
        }
        fun moduleId(value: String) {
            if (value.length > 128) throw WebStructureFailure("limit-exceeded", "PLAN_IDENTIFIER_EXCEEDED")
            if (!MODULE_ID.matches(value)) invalid()
            budget.string(value)
        }
        fun path(value: String) {
            if (value.length > 4096) throw WebStructureFailure("limit-exceeded", "PLAN_PATH_EXCEEDED")
            if (value.isEmpty() || value.startsWith('/') || value.any { it == '\\' || it == ':' || it.code < 32 || it.code == 127 } ||
                value.split('/').any { it.isEmpty() || it == "." || it == ".." }) invalid()
            budget.string(value)
        }
        if (plan.modules.size > WebSourceCatalogSnapshot.MAXIMUM_FILES) throw WebStructureFailure("limit-exceeded", "PLAN_MODULES_EXCEEDED")
        val ids = HashSet<String>()
        for (module in plan.modules) {
            budget.charge(512)
            moduleId(module.id)
            if (!ids.add(module.id)) throw WebStructureFailure("invalid", "PLAN_DUPLICATE_MODULE")
            path(module.sourcePath); path(module.headerPath)
            for (owned in listOf(module.functionIds, module.globalIds, module.typeIds)) {
                if (owned.size > MAXIMUM_REFERENCES) throw WebStructureFailure("limit-exceeded", "PLAN_REFERENCES_EXCEEDED")
                owned.forEach(::identifier)
            }
            module.boundaryEvidence.forEach { budget.string(it) }
        }
        val cycleMembers = HashSet<String>()
        for (cycle in plan.dependencyCycles) {
            if (cycle.size < 2) invalid()
            for (id in cycle) {
                moduleId(id)
                if (id !in ids || !cycleMembers.add(id)) invalid()
            }
        }
    }

    private fun declaredTemplate(profile: ReconstructionProfile, id: String) =
        profile.layout.declarations.singleOrNull { it.id == id }

    private fun planSchema(bytes: ByteArray): Long? = try {
        JSON.createParser(bytes).use { parser ->
            if (parser.nextToken() != JsonToken.START_OBJECT || parser.nextToken() != JsonToken.FIELD_NAME ||
                parser.currentName() != "schemaVersion" || parser.nextToken() != JsonToken.VALUE_NUMBER_INT) null
            else parser.longValue
        }
    } catch (_: Exception) { null }

    internal class WebStructureFailure(val state: String, val reason: String) : Exception(reason)

    private class ParsedModel(val schemaVersion: Int, val inputSha256: String, val tables: List<WebStructureTable>)

    /** Closed-shape single pass; entity bodies are skipped after their scalar columns are recorded. */
    private class ModelReader(
        private val bytes: ByteArray,
        private val implementationUnresolved: Set<String>,
        private val recoveryUnresolved: Set<String>,
        private val budget: RetainedBudget,
    ) {
        private var schema = 1
        private var references = 0
        private val byteEvidenceBudget = ReferencedDataByteEvidenceJson.Budget()

        fun read(): ParsedModel = JSON.createParser(bytes).use { parser ->
            expect(parser.nextToken(), JsonToken.START_OBJECT)
            field(parser, "schemaVersion")
            expect(parser.nextToken(), JsonToken.VALUE_NUMBER_INT)
            schema = parser.text.toIntOrNull()?.takeIf { it in 1..4 }
                ?: throw WebStructureFailure("unsupported", "MODEL_SCHEMA_UNSUPPORTED")
            field(parser, "inputSha256")
            val input = text(parser)
            if (!input.matches(Regex("[a-f0-9]{64}"))) malformed()
            field(parser, "functions")
            val functions = table(parser, WebStructureKind.FUNCTION, MAXIMUM_FUNCTIONS)
            field(parser, "globals")
            val globals = table(parser, WebStructureKind.GLOBAL, MAXIMUM_GLOBALS_OR_TYPES)
            field(parser, "types")
            val types = table(parser, WebStructureKind.TYPE, MAXIMUM_GLOBALS_OR_TYPES)
            expect(parser.nextToken(), JsonToken.END_OBJECT)
            if (parser.nextToken() != null) malformed()
            ParsedModel(schema, input, listOf(functions, globals, types))
        }

        private fun statusFields(): Set<String> = if (schema == 1) setOf("status") else setOf("extractionStatus", "recoveryAssessment")

        private fun fields(kind: WebStructureKind): Set<String> = statusFields() + when (kind) {
            WebStructureKind.FUNCTION -> setOf("id", "name", "address", "prototype", "calls", "referencedGlobals", "strings", "decompiledC")
            WebStructureKind.GLOBAL -> setOf("id", "name", "address", "type", "initializer") + if (schema >= 3) setOf("byteEvidence") else emptySet()
            WebStructureKind.TYPE -> setOf("id", "declaration", "sourceAddress")
        }

        private fun table(parser: JsonParser, kind: WebStructureKind, maximum: Int): WebStructureTable {
            expect(parser.nextToken(), JsonToken.START_ARRAY)
            val ids = ArrayList<String>(); val names = ArrayList<String?>(); val offsets = ArrayList<Long>()
            val addresses = ArrayList<Long>(); val hasAddress = ArrayList<Boolean>(); val status = ArrayList<WebExtractionStatus>()
            val calls = ArrayList<Array<String>>(); val globals = ArrayList<Array<String>>(); val strings = ArrayList<Int>()
            val expected = fields(kind)
            val seen = HashSet<String>()
            while (true) {
                val token = parser.nextToken()
                if (token == JsonToken.END_ARRAY) break
                expect(token, JsonToken.START_OBJECT)
                if (ids.size >= maximum) throw WebStructureFailure("limit-exceeded", "MODEL_ENTITIES_EXCEEDED")
                budget.charge(512)
                offsets += parser.currentTokenLocation().byteOffset
                val keys = HashSet<String>()
                var id: String? = null; var name: String? = null; var address: String? = null
                var label: String? = null; var assessment: String? = null
                var called: Array<String> = emptyArray(); var referenced: Array<String> = emptyArray(); var stringCount = 0
                while (true) {
                    val next = parser.nextToken()
                    if (next == JsonToken.END_OBJECT) break
                    expect(next, JsonToken.FIELD_NAME)
                    val key = parser.currentName()
                    if (key !in expected || !keys.add(key)) malformed()
                    when (key) {
                        "id" -> id = identifier(parser)
                        "name" -> name = identifier(parser)
                        "address" -> address = text(parser)
                        "sourceAddress" -> address = nullableText(parser)
                        "status", "extractionStatus" -> label = text(parser)
                        "recoveryAssessment" -> assessment = text(parser)
                        "calls" -> called = identifiers(parser)
                        "referencedGlobals" -> referenced = identifiers(parser)
                        "strings" -> stringCount = count(parser)
                        "prototype", "type", "declaration" -> text(parser)
                        "decompiledC", "initializer" -> nullableText(parser)
                        "byteEvidence" -> byteEvidence(parser)
                    }
                }
                if (keys != expected || id == null) malformed()
                if (schema >= 2 && assessment != "unassessed") malformed()
                if (!seen.add(id)) malformed()
                if (kind != WebStructureKind.TYPE && address == null) malformed()
                if (address != null && !ADDRESS.matches(address)) malformed()
                ids += id; names += name
                addresses += address?.removePrefix("0x")?.toULong(16)?.toLong() ?: 0L; hasAddress += address != null
                status += WebExtractionStatus.of(label ?: malformed()) ?: malformed()
                calls += called; globals += referenced; strings += stringCount
            }
            val size = ids.size
            return WebStructureTable(kind, ids.toTypedArray(), names.toTypedArray(), addresses.toLongArray(),
                hasAddress.toBooleanArray(), status.toTypedArray(), offsets.toLongArray(), IntArray(size) { OWNER_UNOWNED },
                BooleanArray(size) { ids[it] in implementationUnresolved }, BooleanArray(size) { ids[it] in recoveryUnresolved },
                calls.toTypedArray(), globals.toTypedArray(), strings.toIntArray())
        }

        /** Bound the nested document before allocating a JSON tree, then reuse the producer's closed validator. */
        private fun byteEvidence(parser: JsonParser) {
            val token = parser.nextToken()
            if (token == JsonToken.VALUE_NULL) {
                if (schema != 4) malformed()
                return
            }
            expect(token, JsonToken.START_OBJECT)
            val start = parser.currentTokenLocation().byteOffset.toInt()
            var depth = 1
            var tokens = 0
            while (depth > 0) {
                val next = parser.nextToken() ?: malformed()
                if (++tokens > 200_000 || parser.currentLocation().byteOffset - start > 2 * 1024 * 1024) {
                    throw WebStructureFailure("limit-exceeded", "MODEL_BYTE_EVIDENCE_EXCEEDED")
                }
                if (next == JsonToken.VALUE_STRING && parser.text.length > 512) malformed()
                when (next) {
                    JsonToken.START_OBJECT, JsonToken.START_ARRAY -> depth++
                    JsonToken.END_OBJECT, JsonToken.END_ARRAY -> depth--
                    else -> Unit
                }
            }
            val end = parser.currentLocation().byteOffset.toInt()
            val element = Json.parseToJsonElement(bytes.decodeToString(start, end, throwOnInvalidSequence = true))
            ReferencedDataByteEvidenceJson.parseForModel(element, schema, byteEvidenceBudget)
        }

        private fun field(parser: JsonParser, name: String) {
            if (parser.nextToken() != JsonToken.FIELD_NAME || parser.currentName() != name) malformed()
        }
        private fun text(parser: JsonParser): String { expect(parser.nextToken(), JsonToken.VALUE_STRING); return parser.text }
        private fun nullableText(parser: JsonParser): String? = when (parser.nextToken()) {
            JsonToken.VALUE_NULL -> null
            JsonToken.VALUE_STRING -> parser.text
            else -> malformed()
        }
        private fun identifier(parser: JsonParser): String = text(parser).also {
            if (it.isEmpty()) malformed()
            if (it.length > MAXIMUM_IDENTIFIER_CHARACTERS) throw WebStructureFailure("limit-exceeded", "MODEL_IDENTIFIER_EXCEEDED")
            budget.string(it)
        }
        private fun identifiers(parser: JsonParser): Array<String> {
            expect(parser.nextToken(), JsonToken.START_ARRAY)
            val values = ArrayList<String>()
            while (parser.nextToken() != JsonToken.END_ARRAY) {
                if (parser.currentToken() != JsonToken.VALUE_STRING) malformed()
                if (values.size >= MAXIMUM_REFERENCES) throw WebStructureFailure("limit-exceeded", "MODEL_REFERENCES_EXCEEDED")
                if (references >= MAXIMUM_MODEL_REFERENCES) throw WebStructureFailure("limit-exceeded", "MODEL_REFERENCES_EXCEEDED")
                val value = parser.text
                if (value.isEmpty() || value.length > MAXIMUM_IDENTIFIER_CHARACTERS) malformed()
                budget.string(value)
                references++
                values += value
            }
            return values.toTypedArray()
        }
        private fun count(parser: JsonParser): Int {
            expect(parser.nextToken(), JsonToken.START_ARRAY)
            var count = 0
            while (parser.nextToken() != JsonToken.END_ARRAY) {
                if (parser.currentToken() != JsonToken.VALUE_STRING) malformed()
                count++
            }
            return count
        }
        private fun expect(actual: JsonToken?, expected: JsonToken) { if (actual != expected) malformed() }
        private fun malformed(): Nothing = throw WebStructureFailure("invalid", "MODEL_MALFORMED")
    }
}

/** Bounded text from one recorded field; the full value remains in the committed evidence file. */
internal class WebStructureText(val text: String, val characters: Long, val truncated: Boolean) {
    companion object {
        const val PREVIEW_CHARACTERS = 2048
        fun of(value: String, limit: Int = PREVIEW_CHARACTERS): WebStructureText {
            if (value.length <= limit) return WebStructureText(value, value.length.toLong(), false)
            var end = limit
            if (value[end - 1].isHighSurrogate()) end--
            return WebStructureText(value.substring(0, end), value.length.toLong(), true)
        }
    }
}

/** Kind-specific fields of one entity, read from its recorded byte offset within the committed model. */
internal class WebStructureEntityFields(
    val texts: Map<String, WebStructureText?>,
    val strings: List<WebStructureText>,
    val byteEvidence: String?,
)

internal fun readWebStructureEntity(bytes: ByteArray, offset: Long, maximumStrings: Int = 20): WebStructureEntityFields {
    require(offset in 0 until bytes.size)
    val texts = LinkedHashMap<String, WebStructureText?>()
    val strings = ArrayList<WebStructureText>()
    var byteEvidence: String? = null
    WebProgramStructureBuilder.JSON.createParser(bytes, offset.toInt(), bytes.size - offset.toInt()).use { parser ->
        require(parser.nextToken() == JsonToken.START_OBJECT)
        while (true) {
            val token = parser.nextToken()
            if (token == JsonToken.END_OBJECT) break
            require(token == JsonToken.FIELD_NAME)
            when (val key = parser.currentName()) {
                "prototype", "type", "declaration", "decompiledC", "initializer" -> texts[key] = when (parser.nextToken()) {
                    JsonToken.VALUE_STRING -> WebStructureText.of(parser.text)
                    JsonToken.VALUE_NULL -> null
                    else -> error("Recorded text field is invalid.")
                }
                "strings" -> {
                    require(parser.nextToken() == JsonToken.START_ARRAY)
                    while (parser.nextToken() != JsonToken.END_ARRAY) {
                        if (strings.size < maximumStrings) strings += WebStructureText.of(parser.text, 256)
                    }
                }
                "byteEvidence" -> {
                    byteEvidence = if (parser.nextToken() == JsonToken.VALUE_NULL) "not-recorded" else "recorded"
                    parser.skipChildren()
                }
                else -> { parser.nextToken(); parser.skipChildren() }
            }
        }
    }
    return WebStructureEntityFields(texts, strings, byteEvidence)
}

/** Count and conservative byte bounds apply together; a commitment change always selects a new build. */
internal class WebProgramStructureCache(private val capacity: Int = 2, private val maximumRetainedBytes: Long = 128L * 1024 * 1024) {
    data class Key(val jobId: String, val runId: String, val revisionId: String, val sourceSha256: String,
        val manifestSha256: String, val descriptorSha256: String, val inputSha256: String)

    private val entries = LinkedHashMap<Key, WebProgramStructureIndex>(4, 0.75f, true)

    @Synchronized fun get(key: Key): WebProgramStructureIndex? = entries[key]
    @Synchronized fun put(key: Key, value: WebProgramStructureIndex) {
        entries.remove(key)
        if (value.retainedBytes > maximumRetainedBytes) return
        entries[key] = value
        while (entries.size > capacity || entries.values.sumOf { it.retainedBytes } > maximumRetainedBytes) {
            entries.remove(entries.keys.first())
        }
    }
}
