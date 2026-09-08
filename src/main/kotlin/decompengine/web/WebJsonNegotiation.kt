package decompengine.web

import com.sun.net.httpserver.HttpExchange

/** Shared bounded JSON response negotiation for legacy and versioned read adapters. */
internal fun requireJsonAccept(exchange: HttpExchange) {
    if (!acceptsWebMediaType(exchange, "application/json")) {
        throw WebAccessDenied(406, "NOT_ACCEPTABLE", "This endpoint returns application/json.")
    }
}

internal fun acceptsWebMediaType(exchange: HttpExchange, mediaType: String, explicit: Boolean = false): Boolean {
    val values = exchange.requestHeaders["Accept"] ?: return !explicit
    if (values.size != 1 || values.single().length > 512) {
        throw WebAccessDenied(400, "INVALID_HEADER", "The Accept header exceeds its limit.")
    }
    val ranges = values.single().split(',').mapNotNull { entry ->
        val parts = entry.trim().lowercase().split(';').map(String::trim)
        val baseSpecificity = when (parts[0]) {
            mediaType -> 2
            mediaType.substringBefore('/') + "/*" -> 1
            "*/*" -> 0
            else -> return@mapNotNull null
        }
        var quality = 1.0
        var qualitySeen = false
        var mediaParameterCount = 0
        for (parameter in parts.drop(1)) {
            when {
                parameter == "charset=utf-8" || parameter == "charset=\"utf-8\"" -> mediaParameterCount++
                parameter.startsWith("q=") && !qualitySeen -> {
                    if (!parameter.matches(Regex("q=(?:0(?:\\.[0-9]{0,3})?|1(?:\\.0{0,3})?)"))) {
                        return@mapNotNull null
                    }
                    quality = parameter.removePrefix("q=").toDouble()
                    qualitySeen = true
                }
                else -> return@mapNotNull null
            }
        }
        (baseSpecificity + if (baseSpecificity == 2) mediaParameterCount else 0) to quality
    }
    val specificity = ranges.maxOfOrNull { it.first }
    val accepted = specificity != null && ranges.filter { it.first == specificity }.any { it.second > 0 }
    return accepted && (!explicit || specificity != null && specificity >= 2)
}
