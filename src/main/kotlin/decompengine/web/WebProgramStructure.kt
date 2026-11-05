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
    val index: Map<String, Int> = HashMap<String, Int>(ids.size * 2).also { map ->
        ids.forEachIndexed { i, id -> check(map.put(id, i) == null) { "Recorded entity ID is duplicated." } }
    }
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

/** Fixed-size accounting only; emitted on demand and never retained by an index or sent on the wire. */
internal enum class WebStructureCharge {
    BASELINE, SOURCE_FILES, MODEL_ENTITIES, MODEL_STRINGS, MODEL_REFERENCE_STRINGS,
    MODEL_REFERENCE_SLOTS, MODEL_REFERENCE_ARRAYS, PLAN_MODULES, PLAN_MODULE_STRINGS,
    PLAN_REFERENCE_STRINGS, PLAN_REFERENCE_SLOTS, PLAN_REFERENCE_LISTS, PLAN_BOUNDARY_STRINGS, PLAN_CYCLE_STRINGS,
}

internal class WebStructureRetention(charges: LongArray) {
    private val charges = charges.copyOf()
    val bytes: Long get() = charges.sum()
    operator fun get(category: WebStructureCharge): Long = charges[category.ordinal]
}

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

    internal val JSON: JsonFactory = JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .streamReadConstraints(StreamReadConstraints.builder()
            .maxDocumentLength(MAXIMUM_MODEL_BYTES.toLong()).maxNestingDepth(16)
            .maxStringLength(MAXIMUM_MODEL_BYTES).maxNameLength(64).maxNumberLength(32).build())
        .build()

    // Only the closed model reader supplies its own duplicate checks. Detail and plan readers stay strict.
    internal val MODEL_JSON: JsonFactory = JSON.rebuild()
        .disable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
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
        timing: ((String, Long) -> Unit)? = null,
    ): WebProgramStructureIndex = buildDiagnosed(snapshot, profile, manifest, readEvidence, timing, null)

    fun buildDiagnosed(
        snapshot: WebRevisionSourceSnapshot,
        profile: ReconstructionProfile,
        manifest: SourceTreeManifest,
        readEvidence: (GeneratedFileEvidence, Int) -> ByteArray?,
        timing: ((String, Long) -> Unit)?,
        retention: ((WebStructureRetention) -> Unit)?,
    ): WebProgramStructureIndex {
        fun <T> measured(phase: String, action: () -> T): T {
            if (timing == null) return action()
            val started = System.nanoTime()
            return try { action() } finally { timing(phase, System.nanoTime() - started) }
        }
        val ref = snapshot.reference
        val fileIds = measured("index-source-files") {
            snapshot.files.withIndex().associate { (index, file) ->
                file.evidence.path to revisionSourceFileId(ref, index, file.evidence.path)
            }
        }
        val shared = declaredPath(profile, "shared-interface")?.takeIf { it in fileIds }
        val sourceBytes = fileIds.entries.sumOf { 128L + 2L * (it.key.length + it.value.length) }
        val initialCharges = LongArray(WebStructureCharge.entries.size).also {
            it[WebStructureCharge.BASELINE.ordinal] = 64 * 1024L
            it[WebStructureCharge.SOURCE_FILES.ordinal] = sourceBytes
        }
        val budget = RetainedBudget(64 * 1024L + sourceBytes, initialCharges = initialCharges)
        var retainedCharges = initialCharges
        var retainedBytes = budget.bytes
        fun result(outcome: WebStructureOutcome, model: WebStructureRecord? = null, schema: Int? = null,
            planOutcome: WebStructureOutcome = WebStructureOutcome("not-recorded", "MODEL_UNAVAILABLE"), plan: WebStructureRecord? = null,
            tables: List<WebStructureTable> = emptyList(), modules: List<WebStructureModule> = emptyList(), unknown: Int = 0) =
            WebProgramStructureIndex(ref, snapshot.manifestSha256, snapshot.descriptorSha256, manifest.inputSha256,
                snapshot.metadataVersion, outcome, model, schema, planOutcome, plan, tables, modules, fileIds, shared, unknown, retainedBytes).also {
                    retention?.invoke(WebStructureRetention(retainedCharges).also { check(it.bytes == retainedBytes) })
                }
        val modelFile = evidenceFile(profile, manifest, "program-model-evidence")
            ?: return result(WebStructureOutcome("not-recorded",
                if (declaredPath(profile, "program-model-evidence") == null) "PROFILE_DECLARES_NO_MODEL" else "MODEL_NOT_RECORDED"))
        val modelBytes = measured("read-model-evidence") { readEvidence(modelFile, MAXIMUM_MODEL_BYTES) }
            ?: return result(WebStructureOutcome("limit-exceeded", "MODEL_BYTES_EXCEEDED"))
        val model = WebStructureRecord(modelFile.path, modelFile.sha256, modelBytes.size.toLong())
        val implementationUnresolved = manifest.unresolvedImplementationIds.toHashSet()
        val recoveryUnresolved = manifest.unresolvedEntityIds.toHashSet()
        val parsed = try {
            budget.charge(0) // Also admit the snapshot/file-identity baseline when the model is empty.
            measured("parse-model") { ModelReader(modelBytes, implementationUnresolved, recoveryUnresolved, budget).read() }
        }
            catch (failure: WebStructureFailure) { return result(WebStructureOutcome(failure.state, failure.reason), model) }
            catch (failure: Exception) {
                if (failure is CancellationException || failure is InterruptedException) throw failure
                return result(WebStructureOutcome("invalid", "MODEL_MALFORMED"), model)
            }
        if (parsed.inputSha256 != manifest.inputSha256) {
            return result(WebStructureOutcome("invalid", "MODEL_INPUT_MISMATCH"), model, parsed.schemaVersion)
        }
        measured("canonicalize-references") {
            val functions = parsed.tables[WebStructureKind.FUNCTION.ordinal]
            val globals = parsed.tables[WebStructureKind.GLOBAL.ordinal]
            for (row in 0 until functions.size) {
                canonicalizeReferences(functions.calls[row], functions, budget)
                canonicalizeReferences(functions.referencedGlobals[row], globals, budget)
            }
        }
        retainedBytes = budget.bytes
        retainedCharges = budget.charges()
        val planFile = evidenceFile(profile, manifest, "module-plan-evidence")
        var planOutcome = WebStructureOutcome("not-recorded", "PLAN_NOT_RECORDED")
        var planRecord: WebStructureRecord? = null
        var plan: ModulePlan? = null
        var resolutions: List<List<IntArray>> = emptyList()
        if (planFile != null) {
            val bytes = measured("read-plan-evidence") { readEvidence(planFile, MAXIMUM_PLAN_BYTES) }
            if (bytes == null) planOutcome = WebStructureOutcome("limit-exceeded", "PLAN_BYTES_EXCEEDED")
            else {
                planRecord = WebStructureRecord(planFile.path, planFile.sha256, bytes.size.toLong())
                planOutcome = try {
                    val candidate = measured("parse-canonical-plan") {
                        ModulePlanJson.readCanonical(bytes, MAXIMUM_PLAN_BYTES, {}, timing)
                    }
                    val planBudget = RetainedBudget(retainedBytes, "PLAN_RETAINED_BYTES_EXCEEDED", retainedCharges)
                    resolutions = measured("validate-plan") { validatePlan(candidate, parsed.tables, planBudget) }
                    plan = candidate
                    retainedBytes = planBudget.bytes
                    retainedCharges = planBudget.charges()
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
            val cycles = HashMap<String, List<String>>()
            plan.dependencyCycles.forEach { cycle -> cycle.forEach { cycles[it] = cycle } }
            val filesByPath = manifest.files.associateBy(GeneratedFileEvidence::path)
            val ids = plan.modules.map { it.id }
            if (ids.distinct().size != ids.size || plan.modules.size > WebSourceCatalogSnapshot.MAXIMUM_FILES) {
                planOutcome = WebStructureOutcome("invalid", "PLAN_DUPLICATE_MODULE")
            } else {
                measured("form-modules-and-owners") {
                    plan.modules.withIndex().sortedBy { it.value.id }.forEach { (plannedIndex, planned) ->
                        fun owned(kind: WebStructureKind, raw: List<String>): List<String> {
                            if (raw.isEmpty()) return emptyList()
                            val rows = resolutions[plannedIndex][kind.ordinal]
                            val ids = parsed.tables[kind.ordinal].ids
                            return List(raw.size) { slot -> rows[slot].let { if (it < 0) raw[slot] else ids[it] } }
                        }
                        val implementationFile = filesByPath[planned.sourcePath]
                        modules += WebStructureModule(planned.id, planned.sourcePath, planned.headerPath,
                            owned(WebStructureKind.FUNCTION, planned.functionIds),
                            owned(WebStructureKind.GLOBAL, planned.globalIds), owned(WebStructureKind.TYPE, planned.typeIds), planned.boundaryEvidence,
                            // The source-tree manifest was already checked against this profile by
                            // SourceTreeManifestReader; repeating the declaration's regex match for
                            // every planned module adds substantial cold-path cost at scale.
                            when (implementationFile?.acceptedImplementation) {
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
        }
        if (planOutcome.state != "available") {
            modules.clear(); unknown = 0
            parsed.tables.forEach { it.owners.fill(OWNER_NOT_RECORDED) }
        }
        return result(WebStructureOutcome.AVAILABLE, model, parsed.schemaVersion, planOutcome, planRecord, parsed.tables, modules, unknown)
    }

    /** Conservative retained allocation charge, including maps, lazy orders/collisions and array growth.
     * Strings are charged as UTF-16 even on compact-string JVMs; no interning assumption is needed. */
    internal class RetainedBudget(private val initialBytes: Long,
        private val reason: String = "MODEL_RETAINED_BYTES_EXCEEDED",
        initialCharges: LongArray = LongArray(WebStructureCharge.entries.size).also { it[WebStructureCharge.BASELINE.ordinal] = initialBytes },
    ) {
        private val categories = initialCharges.copyOf()
        private val floors = initialCharges.copyOf()
        init { require(initialBytes >= 0 && categories.size == WebStructureCharge.entries.size &&
            categories.all { it >= 0 } && categories.sum() == initialBytes) }
        var bytes: Long = initialBytes; private set
        fun charges(): LongArray = categories.copyOf()
        fun charge(amount: Long, category: WebStructureCharge = WebStructureCharge.MODEL_STRINGS) {
            require(amount >= 0)
            if (amount > MAXIMUM_RETAINED_BYTES - bytes) throw WebStructureFailure("limit-exceeded", reason)
            bytes += amount
            categories[category.ordinal] += amount
        }
        fun release(amount: Long, category: WebStructureCharge = WebStructureCharge.MODEL_STRINGS) {
            require(amount >= 0 && amount <= bytes - initialBytes &&
                amount <= categories[category.ordinal] - floors[category.ordinal])
            bytes -= amount
            categories[category.ordinal] -= amount
        }
        fun string(value: String, category: WebStructureCharge = WebStructureCharge.MODEL_STRINGS) =
            charge(64L + 2L * value.length, category)
    }

    /** Release only the duplicate object actually displaced from this retained slot. */
    internal fun canonicalizeReferences(values: Array<String>, table: WebStructureTable, budget: RetainedBudget) {
        for (slot in values.indices) {
            val original = values[slot]
            val row = table.index[original] ?: continue
            val canonical = table.ids[row]
            if (original !== canonical) {
                values[slot] = canonical
                budget.release(64L + 2L * original.length, WebStructureCharge.MODEL_REFERENCE_STRINGS)
            }
        }
    }

    /** Projection admission, not exact producer ownership: ambiguous and missing entity references remain visible. */
    private fun validatePlan(plan: ModulePlan, tables: List<WebStructureTable>, budget: RetainedBudget): List<List<IntArray>> {
        fun invalid(): Nothing = throw WebStructureFailure("invalid", "PLAN_MALFORMED")
        fun identifier(value: String) {
            if (value.isEmpty()) invalid()
            if (value.length > MAXIMUM_IDENTIFIER_CHARACTERS) throw WebStructureFailure("limit-exceeded", "PLAN_IDENTIFIER_EXCEEDED")
        }
        fun moduleId(value: String, category: WebStructureCharge = WebStructureCharge.PLAN_MODULE_STRINGS) {
            if (value.length > 128) throw WebStructureFailure("limit-exceeded", "PLAN_IDENTIFIER_EXCEEDED")
            if (!MODULE_ID.matches(value)) invalid()
            budget.string(value, category)
        }
        fun path(value: String) {
            if (value.length > 4096) throw WebStructureFailure("limit-exceeded", "PLAN_PATH_EXCEEDED")
            if (value.isEmpty() || value.startsWith('/') || value.any { it == '\\' || it == ':' || it.code < 32 || it.code == 127 } ||
                value.split('/').any { it.isEmpty() || it == "." || it == ".." }) invalid()
            budget.string(value, WebStructureCharge.PLAN_MODULE_STRINGS)
        }
        if (plan.modules.size > WebSourceCatalogSnapshot.MAXIMUM_FILES) throw WebStructureFailure("limit-exceeded", "PLAN_MODULES_EXCEEDED")
        val ids = HashSet<String>()
        val resolutions = ArrayList<List<IntArray>>(plan.modules.size)
        for (module in plan.modules) {
            budget.charge(512, WebStructureCharge.PLAN_MODULES)
            moduleId(module.id)
            if (!ids.add(module.id)) throw WebStructureFailure("invalid", "PLAN_DUPLICATE_MODULE")
            path(module.sourcePath); path(module.headerPath)
            resolutions += listOf(module.functionIds, module.globalIds, module.typeIds).mapIndexed { kind, owned ->
                if (owned.size > MAXIMUM_REFERENCES) throw WebStructureFailure("limit-exceeded", "PLAN_REFERENCES_EXCEEDED")
                if (owned.isNotEmpty()) budget.charge(64, WebStructureCharge.PLAN_REFERENCE_LISTS)
                IntArray(owned.size) { slot ->
                    val id = owned[slot]
                    identifier(id)
                    val row = tables[kind].index[id] ?: -1
                    budget.charge(8, WebStructureCharge.PLAN_REFERENCE_SLOTS)
                    if (row < 0) budget.string(id, WebStructureCharge.PLAN_REFERENCE_STRINGS)
                    row
                }
            }
            module.boundaryEvidence.forEach { budget.string(it, WebStructureCharge.PLAN_BOUNDARY_STRINGS) }
        }
        val cycleMembers = HashSet<String>()
        for (cycle in plan.dependencyCycles) {
            if (cycle.size < 2) invalid()
            for (id in cycle) {
                moduleId(id, WebStructureCharge.PLAN_CYCLE_STRINGS)
                if (id !in ids || !cycleMembers.add(id)) invalid()
            }
        }
        return resolutions
    }

    private fun declaredTemplate(profile: ReconstructionProfile, id: String) =
        profile.layout.declarations.singleOrNull { it.id == id }

    /** Parse the canonical unsigned address spelling without allocating a regex matcher per row. */
    private fun parseAddress(value: String): Long? {
        if (!value.startsWith("0x")) return null
        val firstDigit = 2
        val digits = value.length - firstDigit
        if (digits !in 1..16 || (digits > 1 && value[firstDigit] == '0')) return null
        var parsed = 0L
        for (index in firstDigit until value.length) {
            val digit = when (val character = value[index]) {
                in '0'..'9' -> character.code - '0'.code
                in 'a'..'f' -> character.code - 'a'.code + 10
                else -> return null
            }
            parsed = (parsed shl 4) or digit.toLong()
        }
        return parsed
    }

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

        fun read(): ParsedModel = MODEL_JSON.createParser(bytes).use { parser ->
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

        private fun fieldBit(name: String): Int = when (name) {
            "id" -> 1 shl 0
            "name" -> 1 shl 1
            "address" -> 1 shl 2
            "prototype" -> 1 shl 3
            "calls" -> 1 shl 4
            "referencedGlobals" -> 1 shl 5
            "strings" -> 1 shl 6
            "decompiledC" -> 1 shl 7
            "type" -> 1 shl 8
            "initializer" -> 1 shl 9
            "byteEvidence" -> 1 shl 10
            "declaration" -> 1 shl 11
            "sourceAddress" -> 1 shl 12
            "status" -> 1 shl 13
            "extractionStatus" -> 1 shl 14
            "recoveryAssessment" -> 1 shl 15
            else -> 0
        }

        private fun fields(kind: WebStructureKind): Int {
            val status = if (schema == 1) fieldBit("status") else fieldBit("extractionStatus") or fieldBit("recoveryAssessment")
            val body = when (kind) {
                WebStructureKind.FUNCTION -> fieldBit("id") or fieldBit("name") or fieldBit("address") or
                    fieldBit("prototype") or fieldBit("calls") or fieldBit("referencedGlobals") or
                    fieldBit("strings") or fieldBit("decompiledC")
                WebStructureKind.GLOBAL -> fieldBit("id") or fieldBit("name") or fieldBit("address") or
                    fieldBit("type") or fieldBit("initializer") or (if (schema >= 3) fieldBit("byteEvidence") else 0)
                WebStructureKind.TYPE -> fieldBit("id") or fieldBit("declaration") or fieldBit("sourceAddress")
            }
            return status or body
        }

        private fun table(parser: JsonParser, kind: WebStructureKind, maximum: Int): WebStructureTable {
            expect(parser.nextToken(), JsonToken.START_ARRAY)
            val ids = ArrayList<String>(); val names = ArrayList<String?>(); val offsets = LongColumn()
            val addresses = LongColumn(); val hasAddress = BooleanColumn(); val status = ArrayList<WebExtractionStatus>()
            val calls = ArrayList<Array<String>>(); val globals = ArrayList<Array<String>>(); val strings = IntColumn()
            val expectedFields = fields(kind)
            while (true) {
                val token = parser.nextToken()
                if (token == JsonToken.END_ARRAY) break
                expect(token, JsonToken.START_OBJECT)
                if (ids.size >= maximum) throw WebStructureFailure("limit-exceeded", "MODEL_ENTITIES_EXCEEDED")
                budget.charge(512, WebStructureCharge.MODEL_ENTITIES)
                offsets.add(parser.currentTokenLocation().byteOffset)
                var seenFields = 0
                var id: String? = null; var name: String? = null; var address: String? = null
                var label: String? = null; var assessment: String? = null
                var called: Array<String> = noIdentifiers; var referenced: Array<String> = noIdentifiers; var stringCount = 0
                while (true) {
                    val next = parser.nextToken()
                    if (next == JsonToken.END_OBJECT) break
                    expect(next, JsonToken.FIELD_NAME)
                    val key = parser.currentName()
                    val bit = fieldBit(key)
                    // currentName is decoded, so escaped aliases collide before their value is consumed.
                    if (bit and expectedFields == 0 || bit and seenFields != 0) malformed()
                    seenFields = seenFields or bit
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
                        "prototype", "type", "declaration" -> discardString(parser, nullable = false)
                        "decompiledC", "initializer" -> discardString(parser, nullable = true)
                        "byteEvidence" -> byteEvidence(parser)
                    }
                }
                if (seenFields != expectedFields || id == null) malformed()
                if (schema >= 2 && assessment != "unassessed") malformed()
                if (kind != WebStructureKind.TYPE && address == null) malformed()
                val parsedAddress = address?.let(::parseAddress)
                if (address != null && parsedAddress == null) malformed()
                ids += id; names += name
                addresses.add(parsedAddress ?: 0L); hasAddress.add(address != null)
                status += WebExtractionStatus.of(label ?: malformed()) ?: malformed()
                calls += called; globals += referenced; strings.add(stringCount)
            }
            val size = ids.size
            return WebStructureTable(kind, ids.toTypedArray(), names.toTypedArray(), addresses.toArray(),
                hasAddress.toArray(), status.toTypedArray(), offsets.toArray(), IntArray(size) { OWNER_UNOWNED },
                BooleanArray(size) { ids[it] in implementationUnresolved }, BooleanArray(size) { ids[it] in recoveryUnresolved },
                calls.toTypedArray(), globals.toTypedArray(), strings.toArray())
        }

        private class LongColumn(initialCapacity: Int = 16) {
            private var values = LongArray(initialCapacity)
            private var size = 0
            fun add(value: Long) {
                if (size == values.size) values = values.copyOf(values.size * 2)
                values[size++] = value
            }
            fun toArray(): LongArray = values.copyOf(size)
        }

        private class IntColumn(initialCapacity: Int = 16) {
            private var values = IntArray(initialCapacity)
            private var size = 0
            fun add(value: Int) {
                if (size == values.size) values = values.copyOf(values.size * 2)
                values[size++] = value
            }
            fun toArray(): IntArray = values.copyOf(size)
        }

        private class BooleanColumn(initialCapacity: Int = 16) {
            private var values = BooleanArray(initialCapacity)
            private var size = 0
            fun add(value: Boolean) {
                if (size == values.size) values = values.copyOf(values.size * 2)
                values[size++] = value
            }
            fun toArray(): BooleanArray = values.copyOf(size)
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
            // Arrays occupy a stack frame too: sibling objects and nested objects have independent names.
            val containers = ArrayList<MutableSet<String>?>()
            containers.add(HashSet())
            var tokens = 0
            while (containers.isNotEmpty()) {
                val next = parser.nextToken() ?: malformed()
                // Strict Jackson detects a duplicate in nextToken, before the scan's token/byte limits.
                if (next == JsonToken.FIELD_NAME && !containers.last()!!.add(parser.currentName())) malformed()
                if (++tokens > 200_000 || parser.currentLocation().byteOffset - start > 2 * 1024 * 1024) {
                    throw WebStructureFailure("limit-exceeded", "MODEL_BYTE_EVIDENCE_EXCEEDED")
                }
                if (next == JsonToken.VALUE_STRING && parser.text.length > 512) malformed()
                when (next) {
                    JsonToken.START_OBJECT -> containers.add(HashSet())
                    JsonToken.START_ARRAY -> containers.add(null)
                    JsonToken.END_OBJECT, JsonToken.END_ARRAY -> containers.removeAt(containers.lastIndex)
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
        private fun discardString(parser: JsonParser, nullable: Boolean) {
            val token = parser.nextToken()
            if (token != JsonToken.VALUE_STRING && !(nullable && token == JsonToken.VALUE_NULL)) malformed()
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
        private val noIdentifiers = emptyArray<String>()

        private fun identifiers(parser: JsonParser): Array<String> {
            expect(parser.nextToken(), JsonToken.START_ARRAY)
            if (parser.nextToken() == JsonToken.END_ARRAY) return noIdentifiers
            budget.charge(24, WebStructureCharge.MODEL_REFERENCE_ARRAYS)
            val values = ArrayList<String>()
            do {
                if (parser.currentToken() != JsonToken.VALUE_STRING) malformed()
                if (values.size >= MAXIMUM_REFERENCES) throw WebStructureFailure("limit-exceeded", "MODEL_REFERENCES_EXCEEDED")
                if (references >= MAXIMUM_MODEL_REFERENCES) throw WebStructureFailure("limit-exceeded", "MODEL_REFERENCES_EXCEEDED")
                val value = parser.text
                if (value.isEmpty() || value.length > MAXIMUM_IDENTIFIER_CHARACTERS) malformed()
                budget.string(value, WebStructureCharge.MODEL_REFERENCE_STRINGS)
                budget.charge(8, WebStructureCharge.MODEL_REFERENCE_SLOTS)
                references++
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
internal class WebProgramStructureCache(private val capacity: Int = 2,
    private val maximumRetainedBytes: Long = 128L * 1024 * 1024,
    private val maximumEntryBytes: Long = 96L * 1024 * 1024) {
    init {
        require(capacity in 0..2)
        require(maximumRetainedBytes in 0..128L * 1024 * 1024)
        require(maximumEntryBytes in 0..96L * 1024 * 1024)
    }
    data class Prefix(val jobId: String, val runId: String, val revisionId: String,
        val sourceSha256: String, val inputSha256: String)
    data class Key(val jobId: String, val runId: String, val revisionId: String, val sourceSha256: String,
        val manifestSha256: String, val descriptorSha256: String, val inputSha256: String) {
        val prefix: Prefix get() = Prefix(jobId, runId, revisionId, sourceSha256, inputSha256)
    }
    class Entry(val key: Key, val index: WebProgramStructureIndex,
        manifest: decompengine.repair.StableRegularFile, descriptor: decompengine.repair.StableRegularFile) {
        val manifest = manifest.copy(bytes = manifest.bytes.copyOf())
        val descriptor = descriptor.copy(bytes = descriptor.bytes.copyOf())
        val retainedBytes: Long
        init {
            val reference = index.reference
            require(key.jobId == reference.jobId && key.runId == reference.runId &&
                key.revisionId == reference.revisionId && key.sourceSha256 == reference.sourceSha256)
            require(key.inputSha256 == index.inputSha256)
            require(key.manifestSha256 == index.manifestSha256 && key.descriptorSha256 == index.descriptorSha256)
            for ((file, sha) in listOf(this.manifest to key.manifestSha256, this.descriptor to key.descriptorSha256)) {
                require(file.bytes.size.toLong() <= WebSourceCatalogEvidence.MAXIMUM_MANIFEST_BYTES)
                require(file.sha256 == sha && java.security.MessageDigest.getInstance("SHA-256")
                    .digest(file.bytes).joinToString("") { "%02x".format(it) } == sha)
                require(file.identity.isRegularFile && !file.identity.isDirectory &&
                    !file.identity.isSymbolicLink && file.identity.linkCount == 1 && file.identity.mode and 0xf000 == 0x8000)
            }
            require(index.retainedBytes >= 0)
            retainedBytes = Math.addExact(index.retainedBytes, this.manifest.bytes.size.toLong() + this.descriptor.bytes.size + 2 * 512L)
        }
    }
    private val entries = LinkedHashMap<Key, Entry>()
    @Synchronized fun candidates(prefix: Prefix): List<Entry> = entries.values.filter { it.key.prefix == prefix }.asReversed()
    @Synchronized fun peek(key: Key): Entry? = entries[key]
    @Synchronized fun getEntry(key: Key): Entry? = entries[key]
    @Synchronized fun get(key: Key): WebProgramStructureIndex? = entries[key]?.index
    @Synchronized fun touch(entry: Entry) {
        if (entries[entry.key] !== entry) return
        entries.remove(entry.key)
        entries[entry.key] = entry
    }
    @Synchronized fun put(entry: Entry) {
        entries.remove(entry.key)
        if (entry.retainedBytes > maximumEntryBytes || entry.retainedBytes > maximumRetainedBytes) return
        entries[entry.key] = entry
        while (entries.size > capacity || entries.values.sumOf { it.retainedBytes } > maximumRetainedBytes) {
            entries.remove(entries.keys.first())
        }
    }
}
