package decompengine.web

import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/** Target polling spelling and the retained cursor alias share one bounded replay parser. */
internal object WebProgressQuery {
    fun parse(raw: String?): Pair<WebJobQuery, String?> {
        if (raw == null) return WebJobQuery.parse(null)
        fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED",
            "Progress polling accepts transport=poll, limit and one of after or cursor.")
        if (raw.isEmpty() || raw.length > 4096) invalid()
        val seen = mutableSetOf<String>()
        val normalized = mutableListOf<String>()
        for (part in raw.split('&')) {
            val split = part.indexOf('=')
            if (split < 1) invalid()
            val key = part.substring(0, split)
            if (key !in setOf("transport", "after", "cursor", "limit") || !seen.add(key)) invalid()
            val value = part.substring(split + 1)
            if (key == "transport") {
                val transport = try { URLDecoder.decode(value, StandardCharsets.UTF_8) } catch (_: Exception) { invalid() }
                if (transport != "poll") invalid()
            } else normalized += "${if (key == "after") "cursor" else key}=$value"
        }
        if ("after" in seen && "cursor" in seen) invalid()
        return WebJobQuery.parse(normalized.takeIf { it.isNotEmpty() }?.joinToString("&"))
    }
}
