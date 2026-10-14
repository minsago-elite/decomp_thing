package decompengine.project

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonPrimitive

/** Lexical admission runs before a parser input chunk is returned to Jackson's token buffers. */
internal class ReferencedByteEvidenceAdmission(private val byteInput: Boolean) {
    private data class Frame(val role: String, val objectValue: Boolean, var field: String? = null, var key: Boolean = true, var entries: Int = 0, val seen: MutableSet<String> = hashSetOf())
    private val stack = ArrayList<Frame>()
    private var first = true
    private var bom = 0
    private var string = false
    private var escaped = false
    private var unicode = 0
    private var keyString = false
    private var decodedLength = 0
    private val keyText = StringBuilder()
    private var primitive = false
    private var requestedLength = false
    private var scopedPrimitive = false
    private var nullableEvidence = false
    private val number = StringBuilder()
    private var evidenceDepth = 0
    private var windows = 0L
    private var requestedBytes = 0L
    private fun evidence() = evidenceDepth > 0

    fun accept(code: Int) {
        val c = code.toChar()
        if (bom != 0) {
            require(code == if (bom == 1) 0xbb else 0xbf) { "invalid program model UTF-8 prefix" }
            bom++
            if (bom == 3) { bom = 0; first = true }
            return
        }
        if (first) {
            if (c in " \t\r\n") return
            if (byteInput && code == 0xef) { first = false; bom = 1; return }
            require(c == '{') { "program model root must be an object" }
            first = false
        }
        if (string) {
            if (keyString) {
                require(keyText.length < 24576) { "program model field name bound exceeded" }
                keyText.append(c)
            }
            if (unicode > 0) { unicode--; return }
            if (escaped) { escaped = false; if (c == 'u') unicode = 4; return }
            if (c == '"') {
                string = false
                if (keyString) {
                    var encoded = keyText.toString()
                    if (byteInput) encoded = encoded.toByteArray(Charsets.ISO_8859_1).toString(Charsets.UTF_8)
                    val field = Json.parseToJsonElement("\"$encoded").jsonPrimitive.content
                    val frame = stack.last()
                    if (evidence()) require(field in fields(frame.role)) { "unexpected byte evidence field" }
                    if (evidence() || (frame.role == "global" && field == "byteEvidence")) {
                        require(frame.seen.add(field)) { "duplicate byte evidence field" }
                    }
                    frame.field = field
                    frame.key = false
                }
                return
            }
            decodedLength++
            if (evidence()) require(decodedLength <= if (keyString) 32 else 512) { "byte evidence string bound exceeded" }
            if (c == '\\') escaped = true
            return
        }
        if (primitive) {
            if (c !in ",]} \t\r\n") {
                if (scopedPrimitive) {
                    require(number.length < if (nullableEvidence) 4 else 64) { "byte evidence number bound exceeded" }
                    number.append(c)
                }
                return
            }
            finishPrimitive()
        }
        when (c) {
            ' ', '\t', '\r', '\n', ':' -> return
            ',' -> { stack.lastOrNull()?.let { if (it.objectValue) it.key = true }; return }
            '}', ']' -> { if (stack.isNotEmpty() && stack.removeAt(stack.lastIndex).role == "evidence") evidenceDepth--; return }
        }
        val parent = stack.lastOrNull()
        if (parent != null && !parent.objectValue) {
            parent.entries++
            when (parent.role) {
                "windows" -> {
                    require(parent.entries <= ReferencedDataByteEvidenceJson.MAXIMUM_WINDOWS_PER_GLOBAL) { "referenced byte global window bound exceeded" }
                    windows++
                    require(windows <= ReferencedDataByteEvidenceJson.MAXIMUM_MODEL_WINDOWS) { "referenced byte model window bound exceeded" }
                }
                "collectionOmissions" -> require(parent.entries <= 2) { "collection omission bound exceeded" }
                "segments" -> require(parent.entries <= ReferencedDataByteEvidenceJson.MAXIMUM_WINDOW_BYTES) { "referenced byte segment bound exceeded" }
            }
        }
        if (parent?.objectValue == true && !parent.key && parent.role == "global" && parent.field == "byteEvidence") {
            require(c == '{' || c == 'n') { "byte evidence must be an object or null" }
        }
        if (parent?.role == "collectionOmissions") require(c == '"') { "collection omissions must be strings" }
        when (c) {
            '{', '[' -> {
                val role = when {
                    parent == null -> "root"
                    parent.role == "root" && parent.field == "globals" && c == '[' -> "globals"
                    parent.role == "globals" && c == '{' -> "global"
                    parent.role == "global" && parent.field == "byteEvidence" && c == '{' -> "evidence"
                    parent.role == "evidence" && parent.field == "collectionOmissions" && c == '[' -> "collectionOmissions"
                    parent.role == "evidence" && parent.field == "windows" && c == '[' -> "windows"
                    parent.role == "windows" && c == '{' -> "window"
                    parent.role == "window" && parent.field == "origin" && c == '{' -> "origin"
                    parent.role == "window" && parent.field == "segments" && c == '[' -> "segments"
                    parent.role == "segments" && c == '{' -> "segment"
                    else -> "other"
                }
                require(!evidence() || role != "other") { "unexpected byte evidence container" }
                if (role == "evidence") evidenceDepth++
                // Match the canonical parser's depth before an entire hostile chunk/file is scanned.
                require(stack.size < 32) { "program model nesting bound exceeded" }
                stack += Frame(role, c == '{')
            }
            '"' -> {
                string = true; escaped = false; unicode = 0; decodedLength = 0
                keyString = parent?.objectValue == true && parent.key
                keyText.setLength(0)
            }
            else -> {
                primitive = true
                requestedLength = parent?.role == "window" && parent.field == "requestedLength"
                nullableEvidence = parent?.role == "global" && parent.field == "byteEvidence"
                scopedPrimitive = evidence() || nullableEvidence
                number.setLength(0)
                if (scopedPrimitive) number.append(c)
            }
        }
    }

    fun finish() { if (primitive) finishPrimitive() }
    private fun finishPrimitive() {
        if (nullableEvidence) require(number.toString() == "null") { "byte evidence must be an object or null" }
        if (requestedLength && number.toString() != "null") {
            val length = number.toString().toIntOrNull()
            require(length != null && length in 1..ReferencedDataByteEvidenceJson.MAXIMUM_WINDOW_BYTES) { "referenced byte window requested-byte bound exceeded" }
            requestedBytes = Math.addExact(requestedBytes, length.toLong())
            require(requestedBytes <= ReferencedDataByteEvidenceJson.MAXIMUM_MODEL_REQUESTED_BYTES) { "referenced byte model requested-byte bound exceeded" }
        }
        primitive = false
    }
    private fun fields(role: String): Set<String> = when (role) {
        "evidence" -> setOf("schemaVersion", "windows", "omissionReason", "collectionOmissions")
        "window" -> setOf("address", "requestedLength", "origin", "availability", "segments")
        "origin" -> setOf("instructionAddress", "referenceAddress", "operandIndex", "widthBasis")
        "segment" -> setOf("offset", "length", "availability", "hex", "reason")
        else -> emptySet()
    }
}
