package decompengine.project

import java.util.Collections
import java.util.Locale

/**
 * Admission for the existing model/plan encoders. Count their exact historical UTF-8 wire forms
 * while capturing bounded collections, before invoking their sorting, joins or StringBuilders.
 * The legacy encoder itself remains nonpreemptible between its existing checkpoints.
 */
internal object AnalysisCanonicalEncoding {
    fun encodeModel(model: RecoveredProgramModel, maximumBytes: Int = ProgramAnalysisResult.MAXIMUM_MODEL_BYTES,
        checkpoint: (String) -> Unit = {}): ByteArray {
        require(maximumBytes in 1..ProgramAnalysisResult.MAXIMUM_MODEL_BYTES)
        val wire = CanonicalWireBudget(maximumBytes, checkpoint, "model")
        wire.ascii("{\n  \"schemaVersion\": ${model.schemaVersion},\n  \"inputSha256\": ")
        wire.quoted(model.inputSha256)
        wire.ascii(",\n  \"functions\": [")
        val functions = wire.capture(model.functions, first = "\n", separator = ",\n") { function ->
            wire.ascii("    {\n      \"id\": "); wire.quoted(function.id)
            wire.ascii(",\n      \"name\": "); wire.quoted(function.name)
            wire.ascii(",\n      \"address\": \"0x${function.address.toString(16)}\",\n      \"prototype\": ")
            wire.quoted(function.prototype); wire.ascii(",\n      ")
            wire.status(model.schemaVersion, function.status)
            wire.ascii(",\n      \"calls\": [")
            val calls = wire.stringSet(function.calls)
            wire.ascii("],\n      \"referencedGlobals\": [")
            val globals = wire.stringSet(function.referencedGlobals)
            wire.ascii("],\n      \"strings\": [")
            val strings = wire.stringSet(function.strings)
            wire.ascii("],\n      \"decompiledC\": "); wire.nullableQuoted(function.decompiledC)
            wire.ascii("\n    }")
            function.copy(calls = calls, referencedGlobals = globals, strings = strings)
        }
        wire.ascii("\n  ],\n  \"globals\": [")
        val globals = wire.capture(model.globals, first = "\n", separator = ",\n") { global ->
            wire.ascii("    {\n      \"id\": "); wire.quoted(global.id)
            wire.ascii(",\n      \"name\": "); wire.quoted(global.name)
            wire.ascii(",\n      \"address\": \"0x${global.address.toString(16)}\",\n      \"type\": ")
            wire.quoted(global.type)
            wire.ascii(",\n      \"initializer\": "); wire.nullableQuoted(global.initializer)
            wire.ascii(",\n      ")
            val byteEvidence = if (model.schemaVersion >= 3) {
                wire.ascii("\"byteEvidence\": ")
                val captured = global.byteEvidence?.let(wire::byteEvidence)
                if (captured == null) wire.ascii("null")
                wire.ascii(",\n      ")
                captured
            } else global.byteEvidence
            wire.status(model.schemaVersion, global.status)
            wire.ascii("\n    }")
            global.copy(byteEvidence = byteEvidence)
        }
        wire.ascii("\n  ],\n  \"types\": [")
        val types = wire.capture(model.types, first = "\n", separator = ",\n") { type ->
            wire.ascii("    {\n      \"id\": "); wire.quoted(type.id)
            wire.ascii(",\n      \"declaration\": "); wire.quoted(type.declaration)
            wire.ascii(",\n      \"sourceAddress\": ")
            wire.ascii(type.sourceAddress?.let { "\"0x${it.toString(16)}\"" } ?: "null")
            wire.ascii(",\n      "); wire.status(model.schemaVersion, type.status)
            wire.ascii("\n    }")
            type
        }
        wire.ascii("\n  ]\n}\n")
        val snapshot = model.copy(functions = functions, globals = globals, types = types)
        wire.check("before bounded model serialization")
        val bytes = snapshot.toJson { wire.check(it) }.toByteArray(Charsets.UTF_8)
        wire.requireExactSize(bytes)
        return bytes
    }

    fun encodePlan(plan: ModulePlan, maximumBytes: Int = RecoveryAssessmentProjectionV1.MAXIMUM_BYTES,
        checkpoint: (String) -> Unit = {}): ByteArray {
        require(maximumBytes in 1..RecoveryAssessmentProjectionV1.MAXIMUM_BYTES)
        val wire = CanonicalWireBudget(maximumBytes, checkpoint, "plan")
        wire.ascii("{\n  \"schemaVersion\": ${plan.schemaVersion},\n  \"modules\": [")
        val modules = wire.capture(plan.modules, first = "", separator = ",") { module ->
            wire.ascii("    {\n      \"id\": "); wire.quoted(module.id)
            wire.ascii(",\n      \"sourcePath\": "); wire.quoted(module.sourcePath)
            wire.ascii(",\n      \"headerPath\": "); wire.quoted(module.headerPath)
            wire.ascii(",\n      \"functionIds\": [")
            val functions = wire.stringList(module.functionIds)
            wire.ascii("],\n      \"globalIds\": [")
            val globals = wire.stringList(module.globalIds)
            wire.ascii("],\n      \"typeIds\": [")
            val types = wire.stringList(module.typeIds)
            wire.ascii("],\n      \"boundaryEvidence\": [")
            val evidence = wire.stringList(module.boundaryEvidence)
            wire.ascii("]\n    }")
            module.copy(functionIds = functions, globalIds = globals, typeIds = types, boundaryEvidence = evidence)
        }
        wire.ascii("\n  ],\n  \"dependencyCycles\": [")
        val cycles = wire.capture(plan.dependencyCycles, first = "", separator = ",") { cycle ->
            wire.ascii("[")
            val members = wire.stringList(cycle, separator = ",")
            wire.ascii("]")
            members
        }
        wire.ascii("]\n}\n")
        val snapshot = plan.copy(modules = modules, dependencyCycles = cycles)
        wire.check("before bounded plan serialization")
        val bytes = snapshot.toJson().toByteArray(Charsets.UTF_8)
        wire.requireExactSize(bytes)
        return bytes
    }
}

/** No escaped strings, sorted copies, collection-size allocations or full byte buffers are made here. */
private class CanonicalWireBudget(
    private val maximumBytes: Int,
    private val checkpoint: (String) -> Unit,
    private val kind: String,
) {
    private var bytes = 0L

    fun check(stage: String) = assessmentCheckpoint(checkpoint, stage)

    private fun add(count: Long) {
        require(count >= 0 && count <= maximumBytes.toLong() - bytes) {
            "$kind canonical encoding exceeds its byte bound before serialization"
        }
        bytes += count
    }

    fun ascii(value: String) {
        check("preflighting bounded $kind structure")
        add(value.length.toLong())
    }

    fun quoted(value: String, byteEvidenceJson: Boolean = false) {
        check("preflighting bounded $kind string")
        add(2)
        var offset = 0
        while (offset < value.length) {
            if (offset % 1024 == 0) check("preflighting bounded $kind string chunk")
            val char = value[offset++]
            val length = when {
                char == '\\' || char == '"' || char == '\n' || char == '\r' || char == '\t' -> 2
                byteEvidenceJson && (char == '\b' || char == '\u000c') -> 2
                char.code < 0x20 -> 6
                char.code < 0x80 -> 1
                char.code < 0x800 -> 2
                Character.isHighSurrogate(char) && offset < value.length && Character.isLowSurrogate(value[offset]) -> {
                    offset++; 4
                }
                // Kotlin's legacy String.toByteArray(UTF_8) replaces an unpaired surrogate with '?'.
                Character.isSurrogate(char) -> 1
                else -> 3
            }
            add(length.toLong())
        }
    }

    fun nullableQuoted(value: String?, byteEvidenceJson: Boolean = false) {
        if (value == null) ascii("null") else quoted(value, byteEvidenceJson)
    }

    fun status(schemaVersion: Int, status: RecoveryStatus) {
        val value = status.name.lowercase(Locale.ROOT)
        if (schemaVersion == 1) ascii("\"status\": \"$value\"")
        else ascii("\"extractionStatus\": \"$value\",\n      \"recoveryAssessment\": \"unassessed\"")
    }

    fun <T, R> capture(values: Iterable<T>, first: String, separator: String, copy: (T) -> R): List<R> {
        val result = ArrayList<R>()
        var started = false
        for (value in values) {
            check("preflighting bounded $kind collection row")
            ascii(if (started) separator else first)
            val captured = copy(value)
            // Every caller charges the complete encoded row before growing a retained collection.
            result.add(captured)
            started = true
        }
        return Collections.unmodifiableList(result)
    }

    fun stringList(values: Iterable<String>, separator: String = ", "): List<String> =
        capture(values, first = "", separator = separator) { value -> quoted(value); value }

    fun stringSet(values: Set<String>): Set<String> {
        val captured = stringList(values)
        val result = LinkedHashSet<String>()
        for (value in captured) {
            check("capturing bounded $kind set entry")
            require(result.add(value)) { "model set contains duplicate iterator entries" }
        }
        return Collections.unmodifiableSet(result)
    }

    fun byteEvidence(value: ReferencedDataByteEvidence): ReferencedDataByteEvidence {
        require(value.schemaVersion in 1..2) { "unsupported referenced byte evidence schema" }
        if (value.schemaVersion == 1) require(value.collectionOmissions.isEmpty()) {
            "historical referenced byte evidence cannot contain collection omissions"
        }
        ascii("{\"schemaVersion\":${value.schemaVersion},\"windows\":[")
        val windows = capture(value.windows, first = "", separator = ",") { window ->
            val origin = window.origin
            ascii("{\"address\":\"0x${window.address.toString(16)}\",\"requestedLength\":${window.requestedLength},\"origin\":{")
            ascii("\"instructionAddress\":\"0x${origin.instructionAddress.toString(16)}\",\"referenceAddress\":\"0x${origin.referenceAddress.toString(16)}\",\"operandIndex\":${origin.operandIndex},\"widthBasis\":")
            quoted(origin.widthBasis, true)
            ascii("},\"availability\":"); quoted(window.availability, true)
            ascii(",\"segments\":[")
            val segments = capture(window.segments, first = "", separator = ",") { segment ->
                ascii("{\"offset\":${segment.offset},\"length\":${segment.length},\"availability\":")
                quoted(segment.availability, true)
                ascii(",\"hex\":"); nullableQuoted(segment.hex, true)
                ascii(",\"reason\":"); nullableQuoted(segment.reason, true)
                ascii("}")
                segment
            }
            ascii("]}")
            window.copy(segments = segments)
        }
        ascii("],\"omissionReason\":"); nullableQuoted(value.omissionReason, true)
        val omissions = if (value.schemaVersion == 2) {
            ascii(",\"collectionOmissions\":[")
            val result = capture(value.collectionOmissions, first = "", separator = ",") { omission ->
                quoted(omission, true); omission
            }
            ascii("]")
            result
        } else emptyList()
        ascii("}")
        return value.copy(windows = windows, collectionOmissions = omissions)
    }

    fun requireExactSize(encoded: ByteArray) {
        check("after bounded $kind serialization")
        require(encoded.size.toLong() == bytes) { "$kind canonical encoder differs from its exact preflight" }
    }
}
