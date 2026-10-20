package decompengine.acp

/** Private, bounded membership index; fragments never leave the capture operation. */
internal class AuthenticationPreviewFragments(
    values: Collection<String>, maximumSearchUnits: Long = 64L * 1024 * 1024,
) {
    private val invisibles = Regex("[\\p{Cntrl}\\p{Cf}\\p{Mn}\\p{Me}&&[^\\n\\t]]")
    private val blocks: Set<String>
    private val privateUnits = java.util.BitSet(65_536)
    private val privateInvisibles = java.util.BitSet(Character.MAX_CODE_POINT + 1)
    private val normalizedValues: List<String>
    private val shortTokens = HashMap<String, Boolean>()
    private val tokenPattern = Regex("[\\p{L}\\p{N}]+")
    private var remainingSearchUnits = maximumSearchUnits
    private var searchExhausted = false
    private var redactionMarkerAllowed = true

    init {
        // Bound supplied work before blank filtering and duplicate suppression.
        require(values.size <= 4096 && values.sumOf { it.length.toLong() } <= 1024 * 1024) {
            "authentication preview private values exceed the configured limit"
        }
        require(maximumSearchUnits in 0..64L * 1024 * 1024) { "authentication preview search budget is invalid" }
        normalizedValues = values.map { it.replace(invisibles, "") }.filter(String::isNotEmpty).distinct()
        redactionMarkerAllowed = normalizedValues.none { REDACTION_MARKER.contains(it) }
        for (value in values) {
            value.forEach { unit -> privateUnits.set(unit.code) }
            var offset = 0
            while (offset < value.length) {
                val codePoint = value.codePointAt(offset)
                when (Character.getType(codePoint)) {
                    Character.CONTROL.toInt(), Character.FORMAT.toInt(),
                    Character.NON_SPACING_MARK.toInt(), Character.ENCLOSING_MARK.toInt() -> privateInvisibles.set(codePoint)
                }
                offset += Character.charCount(codePoint)
            }
        }
        val selected = values.filter { it.isNotBlank() }.distinct()
        require(selected.size <= 4096 && selected.sumOf { it.length.toLong() } <= 1024 * 1024) {
            "authentication preview private values exceed the configured limit"
        }
        blocks = buildSet {
            for (value in selected) {
                val normalized = value.replace(invisibles, "")
                // At most 1 MiB / 8 entries, regardless of duplicate suppression.
                for (start in 0..normalized.length - 8 step 8) add(normalized.substring(start, start + 8))
            }
        }
    }

    /** Keep unrelated identifiers while concealing normalized values and short delimited private fragments. */
    fun concealUntrusted(preview: String): String {
        if (privateUnits.isEmpty()) return preview
        if (REDACTION_MARKER in preview) return if (redactionMarkerAllowed) REDACTION_MARKER else ""
        if (searchExhausted || containsPrivateInvisible(preview)) return ""
        val normalized = preview.replace(invisibles, "")
        if (normalizedValues.any { it.length < 8 && normalized.contains(it) }) return ""
        for (match in tokenPattern.findAll(normalized)) {
            val token = match.value
            if (token.length in 1..7 && token.all { privateUnits.get(it.code) } && privateToken(token)) return ""
        }
        return conceal(preview)
    }

    private fun containsPrivateInvisible(value: String): Boolean {
        var offset = 0
        while (offset < value.length) {
            val codePoint = value.codePointAt(offset)
            if (privateInvisibles.get(codePoint)) return true
            offset += Character.charCount(codePoint)
        }
        return false
    }

    private fun privateToken(token: String): Boolean {
        shortTokens[token]?.let { return it }
        for (value in normalizedValues) {
            // Bound worst-case negative searches; exhaustion withholds instead of publishing unchecked text.
            if (value.length > remainingSearchUnits) {
                searchExhausted = true
                return true
            }
            remainingSearchUnits -= value.length
            if (value.contains(token)) {
                if (shortTokens.size < 4096) shortTokens[token] = true
                return true
            }
        }
        if (shortTokens.size < 4096) shortTokens[token] = false
        return false
    }

    private companion object {
        const val REDACTION_MARKER = "[redacted]"
    }

    /** Any private substring of length >=15 contains a complete aligned eight-unit block. */
    fun conceal(preview: String): String {
        if (blocks.isEmpty()) return preview
        val normalized = preview.replace(invisibles, "")
        for (start in 0..normalized.length - 8) {
            if (normalized.substring(start, start + 8) in blocks) return ""
        }
        return preview
    }
}
