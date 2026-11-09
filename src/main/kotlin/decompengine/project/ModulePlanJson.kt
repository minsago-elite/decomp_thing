package decompengine.project

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature

/** Byte-format and ownership validation only; this does not attest execution or planner semantics. */
internal object ModulePlanJson {
    private val canonicalJsonFactory = JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .streamReadConstraints(StreamReadConstraints.builder()
            .maxDocumentLength(512L * 1024 * 1024)
            .maxNestingDepth(4)
            .maxStringLength(512 * 1024 * 1024)
            .maxNameLength(64)
            .maxNumberLength(32)
            .build())
        .build()

    fun readCanonical(bytes: ByteArray, maximumBytes: Int): ModulePlan = readCanonical(bytes, maximumBytes, {})

    internal fun readCanonical(bytes: ByteArray, maximumBytes: Int, checkpoint: (String) -> Unit): ModulePlan =
        readCanonical(bytes, maximumBytes, checkpoint, null)

    /** Cooperative traversal; individual library parsing, rendering and allocation remain nonpreemptible. */
    internal fun readCanonical(bytes: ByteArray, maximumBytes: Int, checkpoint: (String) -> Unit,
        timing: ((String, Long) -> Unit)?): ModulePlan {
        fun <T> measured(phase: String, action: () -> T): T {
            if (timing == null) return action()
            val started = System.nanoTime()
            return try { action() } finally { timing(phase, System.nanoTime() - started) }
        }
        checkpoint("before reading module plan")
        require(maximumBytes in 1..512 * 1024 * 1024 && bytes.size in 1..maximumBytes) {
            "module plan exceeds its byte bound"
        }
        measured("scan-nesting") { scanNesting(bytes, checkpoint) }
        checkpoint("before parsing module plan JSON")
        val plan = measured("parse-plan-json") { parseCanonicalShape(bytes, checkpoint) }
        checkpoint("before rendering canonical module plan")
        measured("render-canonical-plan") {
            val comparison = CanonicalByteComparison(bytes)
            plan.appendCanonicalJson(comparison)
            comparison.finish()
        }
        checkpoint("after rendering canonical module plan")
        checkpoint("before returning module plan")
        return plan
    }

    private fun parseCanonicalShape(bytes: ByteArray, checkpoint: (String) -> Unit): ModulePlan =
        canonicalJsonFactory.createParser(bytes).use { parser ->
            fun next(expected: JsonToken, subject: String) {
                require(parser.nextToken() == expected) { "invalid module plan $subject" }
            }
            fun field(name: String) {
                next(JsonToken.FIELD_NAME, "field")
                require(parser.currentName() == name) { "invalid module plan field: ${parser.currentName()}" }
            }
            fun string(subject: String): String {
                next(JsonToken.VALUE_STRING, subject)
                return parser.text
            }
            fun strings(subject: String): List<String> {
                next(JsonToken.START_ARRAY, "$subject array")
                val values = ArrayList<String>()
                while (true) {
                    val token = parser.nextToken()
                    if (token == JsonToken.END_ARRAY) break
                    require(token == JsonToken.VALUE_STRING) { "invalid module plan $subject entry" }
                    checkpoint("reading module plan string")
                    values += parser.text
                }
                return values
            }

            next(JsonToken.START_OBJECT, "root")
            field("schemaVersion")
            val versionToken = parser.nextToken()
            val versionText = if (versionToken == JsonToken.VALUE_NUMBER_INT) parser.text else null
            require(versionText == "2") { "unsupported module plan schema" }
            field("modules")
            next(JsonToken.START_ARRAY, "modules")
            val modules = ArrayList<PlannedModule>()
            while (true) {
                val token = parser.nextToken()
                if (token == JsonToken.END_ARRAY) break
                require(token == JsonToken.START_OBJECT) { "invalid module plan module" }
                checkpoint("reading module plan module")
                field("id"); val id = string("module ID")
                field("sourcePath"); val sourcePath = string("source path")
                field("headerPath"); val headerPath = string("header path")
                field("functionIds"); val functionIds = strings("function IDs")
                field("globalIds"); val globalIds = strings("global IDs")
                field("typeIds"); val typeIds = strings("type IDs")
                field("boundaryEvidence"); val boundaryEvidence = strings("boundary evidence")
                next(JsonToken.END_OBJECT, "module end")
                modules += PlannedModule(id, sourcePath, headerPath, functionIds, globalIds, typeIds, boundaryEvidence)
            }
            field("dependencyCycles")
            next(JsonToken.START_ARRAY, "dependency cycles")
            val cycles = ArrayList<List<String>>()
            while (true) {
                val token = parser.nextToken()
                if (token == JsonToken.END_ARRAY) break
                require(token == JsonToken.START_ARRAY) { "invalid module plan dependency cycle" }
                checkpoint("reading module plan cycle")
                val cycle = ArrayList<String>()
                while (true) {
                    val member = parser.nextToken()
                    if (member == JsonToken.END_ARRAY) break
                    require(member == JsonToken.VALUE_STRING) { "invalid module plan cycle member" }
                    checkpoint("reading module plan string")
                    cycle += parser.text
                }
                cycles += cycle
            }
            next(JsonToken.END_OBJECT, "root end")
            require(parser.nextToken() == null) { "trailing module plan content" }
            checkpoint("after parsing module plan JSON")
            ModulePlan(schemaVersion = 2, modules = modules, dependencyCycles = cycles)
        }

    /** JSON punctuation is ASCII, so it can be scanned directly in valid or invalid UTF-8 bytes. */
    private fun scanNesting(bytes: ByteArray, checkpoint: (String) -> Unit) {
        var depth = 0
        var quoted = false
        var escaped = false
        for (index in bytes.indices) {
            if (index > 0 && index % 1024 == 0) checkpoint("scanning module plan after $index bytes")
            val value = bytes[index].toInt() and 0xff
            if (quoted) {
                when {
                    escaped -> escaped = false
                    value == '\\'.code -> escaped = true
                    value == '"'.code -> quoted = false
                }
            } else when (value) {
                '"'.code -> quoted = true
                '{'.code, '['.code -> {
                    depth++
                    require(depth <= 4) { "module plan exceeds its nesting bound" }
                }
                '}'.code, ']'.code -> {
                    depth--
                    require(depth >= 0) { "invalid module plan nesting" }
                }
            }
        }
        require(depth == 0 && !quoted) { "invalid module plan nesting" }
    }

    /** Compares the producer's canonical UTF-8 incrementally without a second document-sized buffer. */
    private class CanonicalByteComparison(private val expected: ByteArray) : Appendable {
        private var offset = 0
        private var pendingHighSurrogate: Char? = null

        override fun append(c: Char): Appendable {
            var character = c
            val pending = pendingHighSurrogate
            if (pending != null) {
                pendingHighSurrogate = null
                if (character.isLowSurrogate()) {
                    val codePoint = Character.toCodePoint(pending, character)
                    emit(0xf0 or (codePoint shr 18))
                    emit(0x80 or ((codePoint shr 12) and 0x3f))
                    emit(0x80 or ((codePoint shr 6) and 0x3f))
                    emit(0x80 or (codePoint and 0x3f))
                    return this
                }
                emit('?'.code)
            }
            when {
                character.isHighSurrogate() -> pendingHighSurrogate = character
                character.isLowSurrogate() -> emit('?'.code)
                character.code < 0x80 -> emit(character.code)
                character.code < 0x800 -> {
                    emit(0xc0 or (character.code shr 6))
                    emit(0x80 or (character.code and 0x3f))
                }
                else -> {
                    emit(0xe0 or (character.code shr 12))
                    emit(0x80 or ((character.code shr 6) and 0x3f))
                    emit(0x80 or (character.code and 0x3f))
                }
            }
            return this
        }

        override fun append(csq: CharSequence?): Appendable {
            val value = csq ?: "null"
            for (index in 0 until value.length) append(value[index])
            return this
        }

        override fun append(csq: CharSequence?, start: Int, end: Int): Appendable {
            val value = csq ?: "null"
            require(start in 0..end && end <= value.length)
            for (index in start until end) append(value[index])
            return this
        }

        fun finish() {
            if (pendingHighSurrogate != null) {
                pendingHighSurrogate = null
                emit('?'.code)
            }
            require(offset == expected.size) { "module plan must use exact canonical fields, ordering, and bytes" }
        }

        private fun emit(value: Int) {
            require(offset < expected.size && expected[offset].toInt().and(0xff) == value) {
                "module plan must use exact canonical fields, ordering, and bytes"
            }
            offset++
        }
    }

    fun requireExactOwnership(plan: ModulePlan, model: RecoveredProgramModel,
        layout: ProjectLayoutProfile, maximumFunctionsPerModule: Int) =
        requireExactOwnership(plan, model, layout, maximumFunctionsPerModule) {}

    internal fun requireExactOwnership(plan: ModulePlan, model: RecoveredProgramModel,
        layout: ProjectLayoutProfile, maximumFunctionsPerModule: Int, checkpoint: (String) -> Unit) {
        checkpoint("before module plan ownership")
        require(plan.schemaVersion == 2 && maximumFunctionsPerModule > 0)
        val moduleIds = hashSetOf<String>()
        val paths = hashSetOf<String>()
        val remainingFunctions = model.functions.mapTo(hashSetOf()) { checkpoint("indexing module plan function"); it.id }
        val remainingGlobals = model.globals.mapTo(hashSetOf()) { checkpoint("indexing module plan global"); it.id }
        val remainingTypes = model.types.mapTo(hashSetOf()) { checkpoint("indexing module plan type"); it.id }
        fun consume(ids: List<String>, remaining: MutableSet<String>, kind: String) {
            val stage = "consuming module plan $kind"
            ids.forEach { checkpoint(stage); require(remaining.remove(it)) { "module plan repeats or invents a $kind" } }
        }
        plan.modules.forEach { module ->
            checkpoint("checking module plan module ownership")
            require(moduleIds.add(module.id)) { "module plan repeats a module ID" }
            require(module.functionIds.size <= maximumFunctionsPerModule) { "module exceeds function bound" }
            require(module.sourcePath == layout.declaration("module-implementation").materialize(mapOf("module" to module.id)))
            require(module.headerPath == layout.declaration("module-interface").materialize(mapOf("module" to module.id)))
            require(paths.add(module.sourcePath) && paths.add(module.headerPath)) { "module plan aliases output paths" }
            consume(module.functionIds, remainingFunctions, "function")
            consume(module.globalIds, remainingGlobals, "global")
            consume(module.typeIds, remainingTypes, "type")
        }
        require(remainingFunctions.isEmpty() && remainingGlobals.isEmpty() && remainingTypes.isEmpty()) {
            "module plan omits recovered entities"
        }
        // Check cycle references, not their graph-theoretic correctness or completeness.
        val cycleMembers = hashSetOf<String>()
        plan.dependencyCycles.forEach { cycle ->
            checkpoint("checking module plan cycle")
            require(cycle.size > 1 && cycle == cycle.sorted())
            cycle.forEach { checkpoint("checking module plan cycle member"); require(it in moduleIds && cycleMembers.add(it)) { "invalid module cycle reference" } }
        }
        require(plan.dependencyCycles == plan.dependencyCycles.sortedBy { it.joinToString("\u0000") })
        checkpoint("after module plan ownership")
    }

}
