package decompengine.oracle.fulltree

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Closed, versioned ASCII grammar; every original column survives, with no JSON field repetition. */
internal object DwarfPhysicalDieRowEncoding {
    const val NAME = "physical-die-numeric-row-v1"
    const val CENSUS_SCHEMA = "bounded-physical-die-census-v2"
    private const val MAXIMUM_REFERENCES_PER_DIE = 65_536
    private val TARGET_PATTERN = Regex("\\.debug_info:cu=0x(0|[1-9a-f][0-9a-f]{0,15}):die=0x(0|[1-9a-f][0-9a-f]{0,15})")
    fun encode(die: DwarfPhysicalDieCensus, maximumRowCharacters: Int = 8 * 1024 * 1024): JsonObject =
        JsonObject(mapOf("row" to JsonPrimitive(encodeRow(die, maximumRowCharacters))))
    fun encodeRow(die: DwarfPhysicalDieCensus, maximumRowCharacters: Int = 8 * 1024 * 1024): String {
        require(maximumRowCharacters > 0 && die.compilationUnitOffset >= 0 && die.offset >= 0 && die.endOffset >= 0 && die.tag >= 0 && die.depth >= 0)
        val row = StringBuilder()
        fun append(fragment: String) {
            if (fragment.length > maximumRowCharacters - row.length) throw FullTreeControlException("physical row exceeds its byte bound")
            row.append(fragment)
        }
        fun hex(value: Long): String { require(value >= 0); return value.toString(16) }
        append(listOf(hex(die.compilationUnitOffset), hex(die.offset), hex(die.endOffset), hex(die.tag),
            die.depth.toString(), die.parentOffset?.let(::hex) ?: "-", if (die.hasChildren) "1" else "0").joinToString(",") + "|")
        for ((index, ref) in die.references.withIndex()) {
            require(index < MAXIMUM_REFERENCES_PER_DIE && ref.attributeOrdinal >= 0 && ref.indirectDepth >= 0)
            val target = ref.targetLocator
            val targetColumns = if (target == null) "-,-" else {
                require(target.length <= 56 && target.startsWith(".debug_info:cu=0x")) { "malformed physical target locator" }
                val match = TARGET_PATTERN.matchEntire(target)
                require(match != null && match.groupValues[1].toLongOrNull(16) != null && match.groupValues[2].toLongOrNull(16) != null) {
                    "malformed physical target locator"
                }
                match.groupValues[1] + "," + match.groupValues[2]
            }
            val state = when (ref.state) {
                "retained-target" -> "r"; "unsupported-reference" -> "u"; "out-of-range-reference" -> "o"; "missing-target" -> "m"
                else -> error("unsupported physical reference state")
            }
            append((if (index == 0) "" else ";") + listOf(ref.attributeOrdinal.toString(), hex(ref.attribute),
                hex(ref.declaredForm), hex(ref.resolvedForm), ref.indirectDepth.toString(), ref.rawOperand.toString(16),
                targetColumns, state, if ("reference-cycle" in ref.reasons) "1" else "0").joinToString(","))
        }
        return row.toString()
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
