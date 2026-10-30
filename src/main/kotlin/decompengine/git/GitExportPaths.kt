package decompengine.git

import java.text.Normalizer
import java.util.Locale

/** Portable, non-aliasing relative file paths shared by source export and independent verification. */
internal class GitExportPaths {
    private val spellings = HashMap<String, String>()
    private val files = HashSet<String>()
    private val directories = HashSet<String>()

    fun add(path: String): Boolean {
        if (path.isBlank() || path.length > 4096 || path.any { it.code < 0x20 || it.code == 0x7f || it in "\\:<>\"|?*" }) return false
        val segments = path.split('/')
        if (segments.any { it.isBlank() || it == "." || it == ".." || it.length > 255 ||
                it.equals(".git", ignoreCase = true) || it.endsWith(' ') || it.endsWith('.') || RESERVED.matches(it) }) return false
        for (end in segments.indices) {
            val prefix = segments.take(end + 1).joinToString("/")
            val key = Normalizer.normalize(prefix, Normalizer.Form.NFC).lowercase(Locale.ROOT)
            if (spellings.putIfAbsent(key, prefix)?.let { it != prefix } == true) return false
            if (end == segments.lastIndex) {
                if (key in directories || !files.add(key)) return false
            } else {
                if (key in files) return false
                directories += key
            }
        }
        return true
    }

    companion object {
        private val RESERVED = Regex("(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\\..*)?$")
    }
}
