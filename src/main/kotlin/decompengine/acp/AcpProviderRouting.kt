package decompengine.acp

import java.net.InetAddress
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Locale

enum class AcpProviderRouteRefusal {
    TRANSPORT_DISABLED,
    MALFORMED_REQUEST,
    MALFORMED_RESPONSE,
    REQUEST_HEAD_TOO_LARGE,
    REQUEST_FRAMING_UNSUPPORTED,
    REQUEST_BODY_TOO_LARGE,
    CONNECT_REFUSED,
    PROXY_REQUEST_REFUSED,
    QUERY_REFUSED,
    OPERATION_UNSUPPORTED,
    METHOD_UNSUPPORTED,
    ROUTING_OVERRIDE_REFUSED,
    PROTOCOL_UPGRADE_REFUSED,
    REDIRECT_UNDECLARED,
    DESTINATION_ADDRESS_REFUSED,
    PRIVATE_DESTINATION_NOT_PERMITTED,
}

internal sealed interface AcpProviderRouteDecision {
    /**
     * An admitted request. [endpoint] is always the approved policy endpoint and [contentLength] is
     * the exact body length the relay must read next. Nothing from the client head is retained.
     */
    class Routed internal constructor(
        val operation: AcpProviderOperation,
        val endpoint: URI,
        val policyDescriptorSha256: String,
        val contentLength: Int,
    ) : AcpProviderRouteDecision {
        /**
         * The complete non-credential upstream header set, rebuilt from policy-owned values and the
         * validated body length. The broker appends only its own credential headers (#959).
         */
        fun upstreamHeaders(): List<Pair<String, String>> = listOf(
            "Host" to endpoint.host,
            "Content-Type" to operation.requestMediaType,
            "Accept" to operation.responseMediaType,
            "Content-Length" to contentLength.toString(),
        )
    }

    data class Refused(val reason: AcpProviderRouteRefusal) : AcpProviderRouteDecision
}

/**
 * Routing decisions for the approved provider transport. Each check runs before anything is sent
 * upstream. The relay passes the exact request-head bytes it received, ending with the empty line.
 * An admitted request matches the policy's declared operation and uses a single canonical
 * Content-Length; the relay then reads exactly that many body bytes and rebuilds the upstream
 * request from [AcpProviderRouteDecision.Routed.upstreamHeaders]. Client headers and framing are
 * never forwarded. There is no CONNECT, proxy, redirect, scheme or authority override.
 *
 * These are decisions only. They take effect when the #959 broker applies them to its relay.
 */
internal object AcpProviderRouting {
    fun route(policy: AcpProviderTransportPolicy, head: ByteArray): AcpProviderRouteDecision {
        val approved = policy as? AcpProviderTransportPolicy.Approved ?: return refused(AcpProviderRouteRefusal.TRANSPORT_DISABLED)
        val request = when (val parsed = parseRequestHead(approved.bounds, head)) {
            is HeadParse.Parsed -> parsed
            is HeadParse.Rejected -> return refused(parsed.reason)
        }
        if (request.method == "CONNECT") return refused(AcpProviderRouteRefusal.CONNECT_REFUSED)
        // Absolute-form, authority-form and asterisk-form targets are proxy requests.
        if (!request.target.startsWith('/')) return refused(AcpProviderRouteRefusal.PROXY_REQUEST_REFUSED)
        if ('?' in request.target) return refused(AcpProviderRouteRefusal.QUERY_REFUSED)

        val names = request.fields.map { (name, _) -> name.lowercase(Locale.ROOT) }
        if (names.count { it == "host" } != 1 || names.count { it == "content-length" } > 1) {
            return refused(AcpProviderRouteRefusal.MALFORMED_REQUEST)
        }
        // Validated, then discarded: the upstream Host always comes from the policy.
        val host = request.fields.single { (name, _) -> name.equals("host", ignoreCase = true) }.second
        if (!isValidHostField(host)) return refused(AcpProviderRouteRefusal.MALFORMED_REQUEST)
        // Only identity-encoded bodies delimited by one Content-Length are supported.
        if (names.any { it in UNSUPPORTED_FRAMING_FIELDS }) return refused(AcpProviderRouteRefusal.REQUEST_FRAMING_UNSUPPORTED)
        if (names.any(::isRoutingOverrideField)) return refused(AcpProviderRouteRefusal.ROUTING_OVERRIDE_REFUSED)
        if (requestsProtocolUpgrade(request.fields)) return refused(AcpProviderRouteRefusal.PROTOCOL_UPGRADE_REFUSED)

        // Exact byte comparison: no decoding, normalization, case folding or prefix match.
        val operation = approved.operation.takeIf { it.relayPath == request.target }
            ?: return refused(AcpProviderRouteRefusal.OPERATION_UNSUPPORTED)
        if (request.method != operation.method) return refused(AcpProviderRouteRefusal.METHOD_UNSUPPORTED)

        val declaredLength = request.fields.singleOrNull { (name, _) -> name.equals("content-length", ignoreCase = true) }?.second
            ?: return refused(AcpProviderRouteRefusal.REQUEST_FRAMING_UNSUPPORTED)
        if (!declaredLength.matches(CANONICAL_CONTENT_LENGTH)) return refused(AcpProviderRouteRefusal.MALFORMED_REQUEST)
        val contentLength = declaredLength.toLong()
        if (contentLength > approved.bounds.maximumRequestBytes) return refused(AcpProviderRouteRefusal.REQUEST_BODY_TOO_LARGE)
        return AcpProviderRouteDecision.Routed(operation, approved.endpoint, approved.descriptorSha256, contentLength.toInt())
    }

    /** The policy declares no redirect destinations, so every upstream 3xx is refused unfollowed. */
    fun responseStatusRefusal(policy: AcpProviderTransportPolicy, status: Int): AcpProviderRouteRefusal? = when {
        policy !is AcpProviderTransportPolicy.Approved -> AcpProviderRouteRefusal.TRANSPORT_DISABLED
        status !in 100..599 -> AcpProviderRouteRefusal.MALFORMED_RESPONSE
        status in 300..399 -> AcpProviderRouteRefusal.REDIRECT_UNDECLARED
        else -> null
    }

    /**
     * Checks every address resolved for the approved endpoint before any connection. One refused
     * address refuses the whole set, so an adapter cannot fall back onto a host-local destination.
     */
    fun destinationRefusal(policy: AcpProviderTransportPolicy, addresses: List<InetAddress>): AcpProviderRouteRefusal? {
        val approved = policy as? AcpProviderTransportPolicy.Approved ?: return AcpProviderRouteRefusal.TRANSPORT_DISABLED
        if (addresses.isEmpty()) return AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED
        val classes = addresses.map { classifyProviderAddress(it, approved.addressTranslation) }
        return when {
            ProviderAddressClass.FORBIDDEN in classes -> AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED
            ProviderAddressClass.PRIVATE in classes &&
                approved.privateDestinations != AcpProviderPrivateDestinations.PERMITTED ->
                AcpProviderRouteRefusal.PRIVATE_DESTINATION_NOT_PERMITTED
            else -> null
        }
    }

    private fun refused(reason: AcpProviderRouteRefusal) = AcpProviderRouteDecision.Refused(reason)
}

private sealed interface HeadParse {
    class Parsed(val method: String, val target: String, val fields: List<Pair<String, String>>) : HeadParse
    class Rejected(val reason: AcpProviderRouteRefusal) : HeadParse
}

private val HEAD_TOO_LARGE = HeadParse.Rejected(AcpProviderRouteRefusal.REQUEST_HEAD_TOO_LARGE)
private val MALFORMED_HEAD = HeadParse.Rejected(AcpProviderRouteRefusal.MALFORMED_REQUEST)

private val HTTP_TOKEN = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+")
private val CANONICAL_CONTENT_LENGTH = Regex("0|[1-9][0-9]{0,9}")
private val UNSUPPORTED_FRAMING_FIELDS = setOf("transfer-encoding", "te", "expect", "content-encoding", "trailer")
private val ROUTING_OVERRIDE_FIELDS = setOf(
    "forwarded", "x-rewrite-url", "x-host", "x-http-host", "x-http-method", "x-http-method-override",
    "x-method-override", "proxy-authorization", "proxy-connection",
)
private val ROUTING_OVERRIDE_FIELD_PREFIXES = listOf("x-forwarded-", "x-original-")

/**
 * Strict RFC 9112 request-head parser over the exact received bytes: request line, field lines and
 * the terminating empty line. The byte bound covers all of them. Only US-ASCII, single-space
 * request-line separators, HTTP/1.1, CRLF line endings, no obs-fold, no whitespace before a field
 * colon and no control characters other than HTAB in field values are accepted.
 */
private fun parseRequestHead(bounds: AcpProviderTransportBounds, head: ByteArray): HeadParse {
    if (head.size > bounds.maximumHeaderBytes) return HEAD_TOO_LARGE
    if (head.any { it < 0 }) return MALFORMED_HEAD
    val text = String(head, StandardCharsets.US_ASCII)
    if (!text.endsWith("\r\n\r\n")) return MALFORMED_HEAD
    val lines = text.substring(0, text.length - 4).split("\r\n")
    if (lines.any { '\r' in it || '\n' in it }) return MALFORMED_HEAD
    if (lines.size - 1 > bounds.maximumHeaderFields) return HEAD_TOO_LARGE

    val requestLine = lines.first().split(' ')
    if (requestLine.size != 3) return MALFORMED_HEAD
    val (method, target, version) = requestLine
    if (!method.matches(HTTP_TOKEN) || target.isEmpty() || target.any { it !in '!'..'~' } || '#' in target ||
        version != "HTTP/1.1"
    ) return MALFORMED_HEAD

    val fields = ArrayList<Pair<String, String>>(lines.size - 1)
    for (line in lines.drop(1)) {
        val colon = line.indexOf(':')
        if (colon <= 0) return MALFORMED_HEAD
        val name = line.substring(0, colon)
        val value = line.substring(colon + 1).trim { it == ' ' || it == '\t' }
        // A leading space or tab (obs-fold) or whitespace before the colon fails the token check.
        if (!name.matches(HTTP_TOKEN) || value.any { it != '\t' && it !in ' '..'~' }) {
            return MALFORMED_HEAD
        }
        fields += name to value
    }
    return HeadParse.Parsed(method, target, fields)
}

/**
 * RFC 9112 section 3.2 Host = uri-host [ ":" port ] with the RFC 3986 grammar. This is stricter than
 * the grammar in three ways: the host must be nonempty (the relay is always addressed by an
 * authority), a present port must be 1 to 5 digits no greater than 65535, and IP-literals must be
 * IPv6address (IPvFuture and zone identifiers are refused).
 */
private fun isValidHostField(value: String): Boolean {
    val port: String?
    if (value.startsWith('[')) {
        val close = value.indexOf(']')
        if (close < 0 || parseIpv6Literal(value.substring(1, close)) == null) return false
        val rest = value.substring(close + 1)
        port = when {
            rest.isEmpty() -> null
            rest.startsWith(':') -> rest.substring(1)
            else -> return false
        }
    } else {
        val colon = value.indexOf(':')
        if (colon >= 0 && value.indexOf(':', colon + 1) >= 0) return false
        val host = if (colon >= 0) value.substring(0, colon) else value
        if (!isRegName(host)) return false
        port = if (colon >= 0) value.substring(colon + 1) else null
    }
    return port == null || port.length in 1..5 && port.all { it in '0'..'9' } && port.toInt() <= 65_535
}

/** RFC 3986 reg-name = *( unreserved / pct-encoded / sub-delims ), required nonempty here. */
private fun isRegName(host: String): Boolean {
    if (host.isEmpty()) return false
    var index = 0
    while (index < host.length) {
        val character = host[index]
        when {
            character == '%' -> {
                if (index + 2 >= host.length || !isHexDigit(host[index + 1]) || !isHexDigit(host[index + 2])) return false
                index += 3
                continue
            }
            character in 'a'..'z' || character in 'A'..'Z' || character in '0'..'9' || character in REG_NAME_SYMBOLS -> Unit
            else -> return false
        }
        index++
    }
    return true
}

// unreserved punctuation "-._~" plus sub-delims "!$&'()*+,;="
private const val REG_NAME_SYMBOLS = "-._~!$&'()*+,;="

private fun isHexDigit(character: Char): Boolean = character in '0'..'9' || character in 'a'..'f' || character in 'A'..'F'

private fun isRoutingOverrideField(lowercaseName: String): Boolean =
    lowercaseName in ROUTING_OVERRIDE_FIELDS || ROUTING_OVERRIDE_FIELD_PREFIXES.any(lowercaseName::startsWith)

private fun requestsProtocolUpgrade(fields: List<Pair<String, String>>): Boolean = fields.any { (name, value) ->
    when (name.lowercase(Locale.ROOT)) {
        "upgrade", "http2-settings" -> true
        "connection" -> value.split(',').any { it.trim(' ', '\t').equals("upgrade", ignoreCase = true) }
        else -> false
    }
}
