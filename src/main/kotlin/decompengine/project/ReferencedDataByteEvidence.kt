package decompengine.project

import kotlinx.serialization.json.*

/** Recovered input windows; neither object extents nor type/initializer authority. */
data class ReferencedDataByteEvidence(val schemaVersion: Int = 1, val windows: List<ReferencedDataByteWindow>, val omissionReason: String? = null)
data class ReferencedDataByteWindow(val address: ULong, val requestedLength: Int?, val origin: ReferencedDataByteOrigin, val availability: String, val segments: List<ReferencedDataByteSegment>)
data class ReferencedDataByteOrigin(val instructionAddress: ULong, val referenceAddress: ULong, val operandIndex: Int?, val widthBasis: String)
data class ReferencedDataByteSegment(val offset: Int, val length: Int, val availability: String, val hex: String?, val reason: String?)

object ReferencedDataByteEvidenceJson {
    const val MAXIMUM_WINDOW_BYTES = 256
    const val MAXIMUM_WINDOWS_PER_GLOBAL = 32
    const val MAXIMUM_MODEL_REQUESTED_BYTES = 65536
    const val MAXIMUM_MODEL_WINDOWS = 4096
    const val MAXIMUM_REFERENCE_CANDIDATES = 65536
    const val MAXIMUM_PROMPT_DECODED_BYTES = 65536
    const val MAXIMUM_PROMPT_RENDERED_BYTES = 524288
    val windowComparator: Comparator<ReferencedDataByteWindow> = compareBy<ReferencedDataByteWindow> { it.address }
        .thenBy { it.origin.instructionAddress }.thenBy { it.origin.referenceAddress }
        .thenBy { it.origin.operandIndex ?: -1 }.thenBy { it.origin.widthBasis }.thenBy { it.requestedLength ?: -1 }

    class Budget {
        var requestedBytes: Long = 0; private set
        var windows: Long = 0; private set
        fun charge(evidence: ReferencedDataByteEvidence) {
            validate(evidence)
            windows = Math.addExact(windows, evidence.windows.size.toLong())
            require(windows <= MAXIMUM_MODEL_WINDOWS) { "referenced byte model window bound exceeded" }
            evidence.windows.forEach {
                requestedBytes = Math.addExact(requestedBytes, (it.requestedLength ?: 0).toLong())
                require(requestedBytes <= MAXIMUM_MODEL_REQUESTED_BYTES) { "referenced byte model requested-byte bound exceeded" }
            }
        }
    }

    fun validate(value: ReferencedDataByteEvidence) {
        require(value.schemaVersion == 1) { "unsupported byte evidence schema" }
        require(value.windows.size in 1..MAXIMUM_WINDOWS_PER_GLOBAL) { "referenced byte global window bound exceeded or empty" }
        require(value.omissionReason == if (value.windows.any { it.requestedLength == null }) "unknown_access_width" else null) { "invalid byte evidence omissionReason" }
        require(value.windows.distinct().size == value.windows.size) { "duplicate byte windows" }
        require(value.windows.sortedWith(windowComparator).zipWithNext().all { (a, b) -> windowComparator.compare(a, b) != 0 }) { "conflicting byte window identity" }
        value.windows.forEach { w ->
            require(w.address == w.origin.referenceAddress) { "byte window must start at reference target" }
            require(w.origin.operandIndex == null || w.origin.operandIndex >= 0) { "invalid operand index" }
            require(w.origin.widthBasis in setOf("pcode_load", "pcode_store", "pcode_direct_read", "pcode_direct_write", "unknown_width"))
            val length = w.requestedLength
            if (length == null) {
                require(w.origin.widthBasis == "unknown_width" && w.availability == "unknown" && w.segments.isEmpty()) { "invalid unknown-width window" }
            } else {
                require(length in 1..MAXIMUM_WINDOW_BYTES) { "referenced byte window requested-byte bound exceeded" }
                require(w.origin.widthBasis != "unknown_width")
                require(w.address <= ULong.MAX_VALUE - (length - 1).toULong()) { "byte window address overflow" }
                require(w.segments.isNotEmpty())
                var offset = 0
                var available = 0
                var previous: ReferencedDataByteSegment? = null
                w.segments.forEach { s ->
                    require(s.offset == offset && s.length in 1..length && s.length <= length - offset) { "invalid byte segment coverage" }
                    if (s.availability == "available") {
                        require(s.reason == null && s.hex != null && s.hex.length == s.length * 2 && s.hex.matches(Regex("[0-9a-f]+"))) { "invalid available byte segment" }
                        available += s.length
                    } else {
                        require(s.availability == "unavailable" && s.hex == null && s.reason in setOf("unmapped", "unreadable", "uninitialized", "read_failed")) { "invalid unavailable byte segment" }
                        require(previous?.availability != "unavailable" || previous?.reason != s.reason) { "unavailable byte segments must coalesce" }
                    }
                    offset += s.length; previous = s
                }
                require(offset == length)
                require(w.availability == when (available) { 0 -> "unavailable"; length -> "available"; else -> "partial" }) { "contradictory byte window availability" }
            }
        }
    }

    fun parse(value: JsonObject): ReferencedDataByteEvidence {
        fun JsonObject.keys(vararg names: String) { require(keys == names.toSet()) { "unexpected byte evidence fields" } }
        fun JsonObject.string(name: String): String { val p = getValue(name).jsonPrimitive; require(p.isString); return p.content }
        fun JsonObject.nullString(name: String): String? = if (getValue(name) == JsonNull) null else string(name)
        fun JsonObject.number(name: String): Int { val p = getValue(name).jsonPrimitive; require(!p.isString && p.content.matches(Regex("0|[1-9][0-9]*"))); return p.content.toInt() }
        fun JsonObject.address(name: String): ULong { val s = string(name); require(s.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})"))); return s.substring(2).toULong(16) }
        value.keys("schemaVersion", "windows", "omissionReason")
        val windows = value.getValue("windows").jsonArray
        require(windows.size in 1..MAXIMUM_WINDOWS_PER_GLOBAL)
        return ReferencedDataByteEvidence(value.number("schemaVersion"), windows.map { element ->
            val w = element.jsonObject; w.keys("address", "requestedLength", "origin", "availability", "segments")
            val o = w.getValue("origin").jsonObject; o.keys("instructionAddress", "referenceAddress", "operandIndex", "widthBasis")
            val segments = w.getValue("segments").jsonArray; require(segments.size <= MAXIMUM_WINDOW_BYTES)
            ReferencedDataByteWindow(w.address("address"), if (w["requestedLength"] == JsonNull) null else w.number("requestedLength"),
                ReferencedDataByteOrigin(o.address("instructionAddress"), o.address("referenceAddress"), if (o["operandIndex"] == JsonNull) null else o.number("operandIndex"), o.string("widthBasis")), w.string("availability"), segments.map {
                    val s = it.jsonObject; s.keys("offset", "length", "availability", "hex", "reason")
                    ReferencedDataByteSegment(s.number("offset"), s.number("length"), s.string("availability"), s.nullString("hex"), s.nullString("reason"))
                })
        }, value.nullString("omissionReason")).also(::validate)
    }

    /** Count canonical bytes without allocating a per-global string or UTF-8 byte array. */
    internal fun renderedLength(value: ReferencedDataByteEvidence, maximumBytes: Long): Long {
        var length = 0L
        renderTo(value) { chunk ->
            // Every emitted value is validated ASCII (addresses, decimal integers, closed enums, hex).
            length = Math.addExact(length, chunk.length.toLong())
            require(length <= maximumBytes) { "module referenced byte evidence rendered-text prompt bound exceeded" }
        }
        return length
    }

    /** Compact, deterministic wire form shared by exporter capture and model canonicalization. */
    fun render(value: ReferencedDataByteEvidence): String = buildString { renderTo(value) { append(it) } }

    private fun renderTo(value: ReferencedDataByteEvidence, emit: (String) -> Unit) {
        validate(value)
        fun q(s: String?) = s?.let { JsonPrimitive(it).toString() } ?: "null"
        fun address(a: ULong) = q("0x${a.toString(16)}")
        emit("{\"schemaVersion\":1,\"windows\":[")
        value.windows.sortedWith(windowComparator).forEachIndexed { index, w ->
            if (index != 0) emit(",")
            val o = w.origin
            emit("{\"address\":${address(w.address)},\"requestedLength\":${w.requestedLength},\"origin\":{\"instructionAddress\":${address(o.instructionAddress)},\"referenceAddress\":${address(o.referenceAddress)},\"operandIndex\":${o.operandIndex},\"widthBasis\":${q(o.widthBasis)}},\"availability\":${q(w.availability)},\"segments\":[")
            w.segments.forEachIndexed { segmentIndex, segment ->
                if (segmentIndex != 0) emit(",")
                emit("{\"offset\":${segment.offset},\"length\":${segment.length},\"availability\":${q(segment.availability)},\"hex\":${q(segment.hex)},\"reason\":${q(segment.reason)}}")
            }
            emit("]}")
        }
        emit("],\"omissionReason\":${q(value.omissionReason)}}")
    }

}

class ReferencedDataByteEvidenceBudget {
    private val delegate = ReferencedDataByteEvidenceJson.Budget()
    val requestedBytes: Long get() = delegate.requestedBytes
    val windows: Long get() = delegate.windows
    fun accept(evidence: ReferencedDataByteEvidence) = delegate.charge(evidence)
}
fun parseReferencedDataByteEvidence(element: JsonElement, budget: ReferencedDataByteEvidenceBudget? = null): ReferencedDataByteEvidence =
    ReferencedDataByteEvidenceJson.parse(element.jsonObject).also { budget?.accept(it) }
fun renderReferencedDataByteEvidence(evidence: ReferencedDataByteEvidence): String = ReferencedDataByteEvidenceJson.render(evidence)
fun referencedDataByteEvidenceJson(evidence: ReferencedDataByteEvidence): String = renderReferencedDataByteEvidence(evidence)
