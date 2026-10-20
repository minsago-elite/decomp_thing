package decompengine.acp

/** Private, bounded membership index; fragments never leave the capture operation. */
internal class AuthenticationPreviewFragments(values: Collection<String>) {
    private val invisibles = Regex("[\\p{Cntrl}\\p{Cf}\\p{Mn}\\p{Me}&&[^\\n\\t]]")
    private val blocks: Set<String>
    private val privateUnits = java.util.BitSet(65_536)
    private var redactionMarkerAllowed = true

    init {
        // Bound supplied work before blank filtering and duplicate suppression.
        require(values.size <= 4096 && values.sumOf { it.length.toLong() } <= 1024 * 1024) {
            "authentication preview private values exceed the configured limit"
        }
        for (value in values) {
            value.forEach { privateUnits.set(it.code) }
            val normalized = value.replace(invisibles, "")
            if (normalized.isNotEmpty() && REDACTION_MARKER.contains(normalized)) redactionMarkerAllowed = false
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

    /**
     * Advertised fields may split private values into arbitrarily short fragments. Only a
     * fixed public marker can bypass the unit index; overlapping peer text is withheld.
     * This intentionally suppresses ordinary labels that share any private UTF-16 unit.
     */
    fun concealUntrusted(preview: String): String {
        if (privateUnits.isEmpty()) return preview
        var position = 0
        var hasMarker = false
        var hasPrivateUnit = false
        while (position < preview.length) {
            if (preview.startsWith(REDACTION_MARKER, position)) {
                if (!redactionMarkerAllowed) return ""
                hasMarker = true
                position += REDACTION_MARKER.length
            } else {
                if (privateUnits.get(preview[position].code)) hasPrivateUnit = true
                position++
            }
        }
        return if (!hasPrivateUnit) preview else if (hasMarker) REDACTION_MARKER else ""
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
