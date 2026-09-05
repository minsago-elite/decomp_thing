package decompengine.acp

/** Private, bounded membership index; fragments never leave the capture operation. */
internal class AuthenticationPreviewFragments(values: Collection<String>) {
    private val blocks: Set<String>

    init {
        val selected = values.filter { it.isNotBlank() }.distinct()
        require(selected.size <= 4096 && selected.sumOf { it.length.toLong() } <= 1024 * 1024) {
            "authentication preview private values exceed the configured limit"
        }
        val controls = Regex("[\\p{Cntrl}&&[^\\n\\t]]")
        blocks = buildSet {
            for (value in selected) {
                val normalized = value.replace(controls, "")
                // At most 1 MiB / 8 entries, regardless of duplicate suppression.
                for (start in 0..normalized.length - 8 step 8) add(normalized.substring(start, start + 8))
            }
        }
    }

    /** Any private substring of length >=15 contains a complete aligned eight-unit block. */
    fun conceal(preview: String): String {
        if (blocks.isEmpty()) return preview
        for (start in 0..preview.length - 8) {
            if (preview.substring(start, start + 8) in blocks) return ""
        }
        return preview
    }
}
