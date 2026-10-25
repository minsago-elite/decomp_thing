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
import decompengine.project.SourceTreeManifest
import decompengine.repair.StableRegularFile
import java.util.concurrent.CancellationException

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
    /** Recorded identity to row; the model reader builds it while it checks identity uniqueness. */
    val index: Map<String, Int> = HashMap<String, Int>(ids.size * 2).also { map -> ids.forEachIndexed { i, id -> map[id] = i } },
) {
    val size: Int get() = ids.size
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
    /** Manifest facts the scorecard joins: the reconstruction profile and the committed confidence record. */
    val profileId: String = "",
    val profileSha256: String = "",
    val confidenceFile: GeneratedFileEvidence? = null,
    val confidenceDeclared: Boolean = false,
    val manifestUnresolvedEntities: Int = 0,
    val manifestUnresolvedImplementations: Int = 0,
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

    /** Relationship adjacency, built on the first neighborhood read of this projection and retained with it. */
    val callGraph: WebProgramGraph by lazy { WebProgramGraph.calls(this) }
    val moduleGraph: WebProgramGraph by lazy { WebProgramGraph.modules(this) }

    /** The confidence-record scorecard, parsed on first use; the record is committed by this projection's manifest. */
    @Volatile var scorecard: WebStructureScorecard? = null
}

internal class WebStructureRecord(val path: String, val sha256: String, val sizeBytes: Long)

/** Reads one manifest-committed record of the selected revision again, refused unless it still has its recorded digest. */
internal fun interface WebStructureRecordReader { fun read(record: WebStructureRecord, maximumBytes: Int): ByteArray }

/** One parse outcome; [value] is present only when [outcome] is `available`. */
internal class WebStructureParse<T>(val value: T?, val outcome: WebStructureOutcome)

/**
 * One declared evidence record as read from the store, with its computed digest and parse. [record] is null when the
 * record exceeded its byte bound. It is used only after [committed] matches it to the manifest entry that commits it.
 */
internal class WebStructureEvidence<T>(val record: StableRegularFile?, val computedSha256: String?, val parse: WebStructureParse<T>?) {
    class Committed<T>(val sizeBytes: Long, val parse: WebStructureParse<T>)

    /** Null when over its bound; a record whose bytes differ from the committed digest is refused as a changed revision. */
    fun committed(entry: GeneratedFileEvidence): Committed<T>? {
        if (record == null) return null
        if (record.sha256 != entry.sha256 || computedSha256 != entry.sha256) revisionSourceChanged()
        return Committed(record.bytes.size.toLong(), checkNotNull(parse))
    }
}

internal object WebProgramStructureBuilder {
    const val MAXIMUM_MODEL_BYTES = 64 * 1024 * 1024
    const val MAXIMUM_PLAN_BYTES = 16 * 1024 * 1024
    const val MAXIMUM_FUNCTIONS = 250_000
    const val MAXIMUM_GLOBALS_OR_TYPES = 250_000
    const val MAXIMUM_REFERENCES = 100_000
    const val MAXIMUM_IDENTIFIER_CHARACTERS = 4096

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

    /** Parse one model; the outcome is explicit for every failure, and nothing here depends on the manifest. */
    fun parseModel(bytes: ByteArray): WebStructureParse<ParsedModel> = try {
        WebStructureParse(ModelReader(bytes).read(), WebStructureOutcome.AVAILABLE)
    } catch (failure: WebStructureFailure) { WebStructureParse(null, WebStructureOutcome(failure.state, failure.reason)) }
    catch (failure: Exception) {
        if (failure is CancellationException || failure is InterruptedException) throw failure
        WebStructureParse(null, WebStructureOutcome("invalid", "MODEL_MALFORMED"))
    }

    fun parsePlan(bytes: ByteArray): WebStructureParse<ModulePlan> = try {
        WebStructureParse(ModulePlanJson.readCanonical(bytes, MAXIMUM_PLAN_BYTES), WebStructureOutcome.AVAILABLE)
    } catch (failure: Exception) {
        if (failure is CancellationException || failure is InterruptedException) throw failure
        WebStructureParse(null, if (planSchema(bytes)?.let { it != 2L } == true) WebStructureOutcome("unsupported", "PLAN_SCHEMA_UNSUPPORTED")
            else WebStructureOutcome("invalid", "PLAN_MALFORMED"))
    }

    /**
     * Bind the parsed records to the manifest that commits them. The callbacks are invoked only for a record the
     * manifest commits; each returns the bytes already bounded by the store, whose digest is checked here.
     */
    fun build(
        snapshot: WebRevisionSourceSnapshot,
        profile: ReconstructionProfile,
        manifest: SourceTreeManifest,
        readModel: () -> WebStructureEvidence<ParsedModel>,
        readPlan: () -> WebStructureEvidence<ModulePlan>,
    ): WebProgramStructureIndex {
        val ref = snapshot.reference
        val fileIds = snapshot.files.withIndex().associate { (index, file) ->
            file.evidence.path to revisionSourceFileId(ref, index, file.evidence.path)
        }
        val shared = declaredPath(profile, "shared-interface")?.takeIf { it in fileIds }
        fun result(outcome: WebStructureOutcome, model: WebStructureRecord? = null, schema: Int? = null,
            planOutcome: WebStructureOutcome = WebStructureOutcome("not-recorded", "MODEL_UNAVAILABLE"), plan: WebStructureRecord? = null,
            tables: List<WebStructureTable> = emptyList(), modules: List<WebStructureModule> = emptyList(), unknown: Int = 0) =
            WebProgramStructureIndex(ref, snapshot.manifestSha256, snapshot.descriptorSha256, manifest.inputSha256,
                snapshot.metadataVersion, outcome, model, schema, planOutcome, plan, tables, modules, fileIds, shared, unknown,
                manifest.profileId, manifest.profileSha256, evidenceFile(profile, manifest, "confidence-evidence"),
                declaredPath(profile, "confidence-evidence") != null, manifest.unresolvedEntityIds.size,
                manifest.unresolvedImplementationIds.size)
        val modelFile = evidenceFile(profile, manifest, "program-model-evidence")
            ?: return result(WebStructureOutcome("not-recorded",
                if (declaredPath(profile, "program-model-evidence") == null) "PROFILE_DECLARES_NO_MODEL" else "MODEL_NOT_RECORDED"))
        val modelRead = readModel().committed(modelFile)
            ?: return result(WebStructureOutcome("limit-exceeded", "MODEL_BYTES_EXCEEDED"))
        val model = WebStructureRecord(modelFile.path, modelFile.sha256, modelRead.sizeBytes)
        val parsed = modelRead.parse.value ?: return result(modelRead.parse.outcome, model)
        if (parsed.inputSha256 != manifest.inputSha256) {
            return result(WebStructureOutcome("invalid", "MODEL_INPUT_MISMATCH"), model, parsed.schemaVersion)
        }
        val implementationUnresolved = manifest.unresolvedImplementationIds.toHashSet()
        val recoveryUnresolved = manifest.unresolvedEntityIds.toHashSet()
        for (table in parsed.tables) for (row in 0 until table.size) {
            table.implementationUnresolved[row] = table.ids[row] in implementationUnresolved
            table.recoveryUnresolved[row] = table.ids[row] in recoveryUnresolved
        }
        val planFile = evidenceFile(profile, manifest, "module-plan-evidence")
        var planOutcome = WebStructureOutcome("not-recorded", "PLAN_NOT_RECORDED")
        var planRecord: WebStructureRecord? = null
        var plan: ModulePlan? = null
        if (planFile != null) {
            val read = readPlan().committed(planFile)
            if (read == null) planOutcome = WebStructureOutcome("limit-exceeded", "PLAN_BYTES_EXCEEDED")
            else {
                planRecord = WebStructureRecord(planFile.path, planFile.sha256, read.sizeBytes)
                plan = read.parse.value
                planOutcome = read.parse.outcome
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
                // Manifest paths are unique (the reader requires sorted, distinct paths), so one keyed join suffices.
                val filesByPath = manifest.files.associateBy { it.path }
                plan.modules.sortedBy { it.id }.forEach { planned ->
                    val implementationFile = filesByPath[planned.sourcePath]
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

    /** Recorded columns of one model; manifest-derived flags are filled when the model is bound to its manifest. */
    internal class ParsedModel(val schemaVersion: Int, val inputSha256: String, val tables: List<WebStructureTable>)

    /** Closed-shape single pass; entity bodies are skipped after their scalar columns are recorded. */
    private class ModelReader(private val bytes: ByteArray) {
        private var schema = 1

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

        /** The closed field set of one entity kind for this schema, each field mapped to its own bit. */
        private fun fields(kind: WebStructureKind): Map<String, Int> = (statusFields() + when (kind) {
            WebStructureKind.FUNCTION -> setOf("id", "name", "address", "prototype", "calls", "referencedGlobals", "strings", "decompiledC")
            WebStructureKind.GLOBAL -> setOf("id", "name", "address", "type", "initializer") + if (schema >= 3) setOf("byteEvidence") else emptySet()
            WebStructureKind.TYPE -> setOf("id", "declaration", "sourceAddress")
        }).withIndex().associate { (bit, field) -> field to (1 shl bit) }

        private fun table(parser: JsonParser, kind: WebStructureKind, maximum: Int): WebStructureTable {
            expect(parser.nextToken(), JsonToken.START_ARRAY)
            val ids = ArrayList<String>(); val names = ArrayList<String?>()
            val offsets = Longs(); val addresses = Longs(); val hasAddress = Longs()
            val status = ArrayList<WebExtractionStatus>()
            val calls = ArrayList<Array<String>>(); val globals = ArrayList<Array<String>>(); val strings = Longs()
            val expected = fields(kind)
            val complete = (1 shl expected.size) - 1
            val index = HashMap<String, Int>()
            while (true) {
                val token = parser.nextToken()
                if (token == JsonToken.END_ARRAY) break
                expect(token, JsonToken.START_OBJECT)
                if (ids.size >= maximum) throw WebStructureFailure("limit-exceeded", "MODEL_ENTITIES_EXCEEDED")
                offsets.add(parser.currentTokenLocation().byteOffset)
                var keys = 0
                var id: String? = null; var name: String? = null; var address: String? = null
                var label: String? = null; var assessment: String? = null
                var called: Array<String> = NONE; var referenced: Array<String> = NONE; var stringCount = 0
                while (true) {
                    val next = parser.nextToken()
                    if (next == JsonToken.END_OBJECT) break
                    expect(next, JsonToken.FIELD_NAME)
                    // The closed field set is one map probe and a bit test per field, not a set per entity.
                    val key = parser.currentName()
                    val bit = expected[key] ?: malformed()
                    if (keys and bit != 0) malformed()
                    keys = keys or bit
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
                        // Text bodies are type-checked but not decoded here; detail reads parse them by offset.
                        "prototype", "type", "declaration" -> expect(parser.nextToken(), JsonToken.VALUE_STRING)
                        "decompiledC", "initializer" -> when (parser.nextToken()) {
                            JsonToken.VALUE_STRING, JsonToken.VALUE_NULL -> Unit
                            else -> malformed()
                        }
                        "byteEvidence" -> { parser.nextToken(); parser.skipChildren() }
                    }
                }
                if (keys != complete || id == null) malformed()
                if (schema >= 2 && assessment != "unassessed") malformed()
                if (index.putIfAbsent(id, ids.size) != null) malformed()
                if (kind != WebStructureKind.TYPE && address == null) malformed()
                ids += id; names += name
                addresses.add(address?.let(::addressValue) ?: 0L); hasAddress.add(if (address != null) 1L else 0L)
                status += WebExtractionStatus.of(label ?: malformed()) ?: malformed()
                calls += called; globals += referenced; strings.add(stringCount.toLong())
            }
            val size = ids.size
            return WebStructureTable(kind, ids.toTypedArray(), names.toTypedArray(), addresses.toArray(),
                BooleanArray(size) { hasAddress[it] != 0L }, status.toTypedArray(), offsets.toArray(), IntArray(size) { OWNER_UNOWNED },
                BooleanArray(size), BooleanArray(size),
                calls.toTypedArray(), globals.toTypedArray(), IntArray(size) { strings[it].toInt() }, index)
        }

        /** `0x(0|[1-9a-f][0-9a-f]{0,15})` as an unsigned 64-bit value, without a regular expression per entity. */
        private fun addressValue(text: String): Long {
            if (text.length !in 3..18 || text[0] != '0' || text[1] != 'x' || (text[2] == '0' && text.length > 3)) malformed()
            var value = 0L
            for (position in 2 until text.length) {
                val digit = when (val char = text[position]) { in '0'..'9' -> char - '0'; in 'a'..'f' -> char - 'a' + 10; else -> malformed() }
                value = (value shl 4) or digit.toLong()
            }
            return value
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
        }
        private fun identifiers(parser: JsonParser): Array<String> {
            expect(parser.nextToken(), JsonToken.START_ARRAY)
            if (parser.nextToken() == JsonToken.END_ARRAY) return NONE
            val values = ArrayList<String>(4)
            do {
                if (parser.currentToken() != JsonToken.VALUE_STRING) malformed()
                if (values.size >= MAXIMUM_REFERENCES) throw WebStructureFailure("limit-exceeded", "MODEL_REFERENCES_EXCEEDED")
                val value = parser.text
                if (value.isEmpty() || value.length > MAXIMUM_IDENTIFIER_CHARACTERS) malformed()
                values += value
            } while (parser.nextToken() != JsonToken.END_ARRAY)
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

        private companion object { val NONE = emptyArray<String>() }
    }

    /** Growable primitive column, so the single pass does not box one value per entity. */
    private class Longs {
        private var values = LongArray(1024)
        private var size = 0
        fun add(value: Long) { if (size == values.size) values = values.copyOf(size * 2); values[size++] = value }
        operator fun get(index: Int): Long = values[index]
        fun toArray(): LongArray = values.copyOf(size)
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

/** At most two retained projections; a manifest or descriptor change always selects a new build. */
internal class WebProgramStructureCache(private val capacity: Int = 2) {
    data class Key(val jobId: String, val runId: String, val revisionId: String, val sourceSha256: String,
        val manifestSha256: String, val descriptorSha256: String, val inputSha256: String)

    private val entries = object : LinkedHashMap<Key, WebProgramStructureIndex>(4, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Key, WebProgramStructureIndex>) = size > capacity
    }

    @Synchronized fun get(key: Key): WebProgramStructureIndex? = entries[key]
    @Synchronized fun put(key: Key, value: WebProgramStructureIndex) { entries[key] = value }
    @Synchronized internal fun retained(): List<WebProgramStructureIndex> = entries.values.toList()
}
