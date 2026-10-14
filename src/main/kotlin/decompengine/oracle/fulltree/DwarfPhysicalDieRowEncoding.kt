package decompengine.oracle.fulltree

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Closed, versioned ASCII grammar; every original column survives, with no JSON field repetition. */
internal object DwarfPhysicalDieRowEncoding {
    const val NAME = "physical-die-numeric-row-v1"
    const val CENSUS_SCHEMA = "bounded-physical-die-census-v2"
    private const val MAXIMUM_REFERENCES_PER_DIE = 65_536
    fun encode(die: DwarfPhysicalDieCensus): JsonObject {
        val row = buildString {
            fun hex(value: Long) { append(value.toString(16)) }
            hex(die.compilationUnitOffset); append(','); hex(die.offset); append(','); hex(die.endOffset)
            append(','); hex(die.tag); append(','); append(die.depth); append(',')
            die.parentOffset?.let(::hex) ?: append('-'); append(','); append(if (die.hasChildren) '1' else '0')
            append('|')
            for ((index, ref) in die.references.withIndex()) {
                if (index > 0) append(';')
                append(ref.attributeOrdinal); append(','); hex(ref.attribute); append(','); hex(ref.declaredForm)
                append(','); hex(ref.resolvedForm); append(','); append(ref.indirectDepth); append(','); append(ref.rawOperand.toString(16))
                append(',')
                val target = ref.targetLocator
                if (target == null) append("-,-") else {
                    val marker = target.indexOf(":die=0x")
                    require(target.startsWith(".debug_info:cu=0x") && marker > 0) { "malformed physical target locator" }
                    append(target.substring(17, marker)); append(','); append(target.substring(marker + 7))
                }
                append(','); append(when (ref.state) {
                    "retained-target" -> 'r'; "unsupported-reference" -> 'u'; "out-of-range-reference" -> 'o'; "missing-target" -> 'm'
                    else -> error("unsupported physical reference state")
                })
                append(','); append(if ("reference-cycle" in ref.reasons) '1' else '0')
            }
        }
        return JsonObject(mapOf("row" to JsonPrimitive(row)))
    }
    fun decode(record: JsonObject, maximumRowCharacters: Int = 8 * 1024 * 1024,
               referenceWork: () -> Unit = {}): DwarfPhysicalDieCensus {
        require(record.keys == setOf("row")) { "physical row keys differ from its encoding" }
        val raw = record["row"] as? JsonPrimitive
        require(raw != null && raw.isString && raw.content.length <= maximumRowCharacters) { "physical row string is missing or exceeds bounds" }
        val cursor = Cursor(raw.content)
        val unit = cursor.hex(','); val offset = cursor.hex(','); val end = cursor.hex(','); val tag = cursor.hex(',')
        val depth = cursor.decimal(','); val parent = cursor.optionalHex(','); val children = cursor.bit('|')
        val references = ArrayList<DwarfPhysicalReferenceCensus>()
        var previousOrdinal = -1
        while (!cursor.atEnd) {
            require(references.size < MAXIMUM_REFERENCES_PER_DIE) { "physical row reference count exceeds bounds" }
            referenceWork() // Charge before creating the next descriptor or growing its list.
            val ordinal = cursor.decimal(',')
            require(ordinal > previousOrdinal) { "physical reference attribute ordinals repeat or are reordered" }
            previousOrdinal = ordinal
            val attribute = cursor.hex(','); val declared = cursor.hex(','); val resolved = cursor.hex(',')
            val indirect = cursor.decimal(','); val operand = cursor.unsignedHex(',')
            val targetUnit = cursor.optionalHex(','); val targetOffset = cursor.optionalHex(',')
            require((targetUnit == null) == (targetOffset == null)) { "physical row target offsets are not paired" }
            val state = when (cursor.token(',', 1)) {
                "r" -> "retained-target"; "u" -> "unsupported-reference"; "o" -> "out-of-range-reference"; "m" -> "missing-target"
                else -> throw IllegalArgumentException("unsupported physical row reference state")
            }
            val cyclic = cursor.finalBit()
            require(!cyclic || state == "retained-target") { "unresolved physical reference claims a cycle" }
            require(if (state == "retained-target" || state == "missing-target") targetUnit != null else targetUnit == null) {
                "physical row state differs from target presence"
            }
            val target = targetUnit?.let { physicalDieLocator(it, targetOffset!!) }
            val reference = DwarfPhysicalReferenceCensus(ordinal, attribute, declared, resolved, indirect, operand, target,
                state.takeIf { it != "retained-target" }).also {
                it.bindTargets(if (state == "retained-target") setOf(target!!) else emptySet())
                if (cyclic) it.markCycle()
                it.seal()
            }
            references += reference
        }
        return DwarfPhysicalDieCensus(unit, offset, end, tag, depth, parent, children, references)
    }
    /** Bounded tokens only: never split an attacker-sized row into a population of fields. */
    private class Cursor(private val row: String) {
        private var position = 0
        val atEnd: Boolean get() = position == row.length
        fun token(separator: Char, maximum: Int): String {
            val start = position
            while (position < row.length && row[position] != separator) {
                require(position - start < maximum) { "physical row token exceeds its width" }
                position++
            }
            require(position > start && position < row.length) { "physical row is truncated or has empty fields" }
            return row.substring(start, position++)
        }
        fun unsignedHex(separator: Char): ULong = parseHex(token(separator, 16))
        fun hex(separator: Char): Long = unsignedHex(separator).also { require(it <= Long.MAX_VALUE.toULong()) }.toLong()
        fun optionalHex(separator: Char): Long? {
            val token = token(separator, 16)
            return if (token == "-") null else parseHex(token).also { require(it <= Long.MAX_VALUE.toULong()) }.toLong()
        }
        fun decimal(separator: Char): Int {
            val token = token(separator, 10)
            require(token.all { it in '0'..'9' } && (token == "0" || token[0] != '0')) { "noncanonical physical row decimal" }
            return token.toIntOrNull() ?: throw IllegalArgumentException("physical row decimal exceeds its width")
        }
        fun bit(separator: Char): Boolean = parseBit(token(separator, 1))
        fun finalBit(): Boolean {
            require(position < row.length) { "physical reference cycle bit is missing" }
            val value = parseBit(row[position++].toString())
            if (position < row.length) {
                require(row[position++] == ';' && position < row.length) { "physical row has trailing or extra fields" }
            }
            return value
        }
        private fun parseBit(value: String): Boolean = when (value) {
            "0" -> false; "1" -> true; else -> throw IllegalArgumentException("noncanonical physical row bit")
        }
        private fun parseHex(value: String): ULong {
            require(value.isNotEmpty() && value.all { it in '0'..'9' || it in 'a'..'f' } && (value == "0" || value[0] != '0')) {
                "noncanonical physical row hexadecimal"
            }
            return value.toULongOrNull(16) ?: throw IllegalArgumentException("physical row hexadecimal exceeds its width")
        }
    }
}
