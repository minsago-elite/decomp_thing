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

private fun isRoutingOverrideField(lowercaseName: String): Boolean =
    lowercaseName in ROUTING_OVERRIDE_FIELDS || ROUTING_OVERRIDE_FIELD_PREFIXES.any(lowercaseName::startsWith)

private fun requestsProtocolUpgrade(fields: List<Pair<String, String>>): Boolean = fields.any { (name, value) ->
    when (name.lowercase(Locale.ROOT)) {
        "upgrade", "http2-settings" -> true
        "connection" -> value.split(',').any { it.trim(' ', '\t').equals("upgrade", ignoreCase = true) }
        else -> false
    }
}

private enum class ProviderAddressClass { PUBLIC, PRIVATE, FORBIDDEN }

private fun classifyProviderAddress(address: InetAddress, translation: AcpProviderAddressTranslation): ProviderAddressClass {
    val bytes = address.address
    return when (bytes.size) {
        4 -> classifyIpv4(bytes)
        16 -> classifyIpv6(bytes, translation)
        else -> ProviderAddressClass.FORBIDDEN
    }
}

/** IANA IPv4 special-purpose registry entries are refused; RFC 1918 and shared space are private. */
private fun classifyIpv4(bytes: ByteArray): ProviderAddressClass {
    val a = bytes[0].toInt() and 0xff
    val b = bytes[1].toInt() and 0xff
    val c = bytes[2].toInt() and 0xff
    return when {
        a == 10 || a == 172 && b in 16..31 || a == 192 && b == 168 || a == 100 && b in 64..127 -> ProviderAddressClass.PRIVATE
        a == 0 || a == 127 || a >= 224 || a == 169 && b == 254 || a == 198 && (b == 18 || b == 19) ||
            a == 192 && (b == 0 && (c == 0 || c == 2) || b == 31 && c == 196 || b == 52 && c == 193 ||
                b == 88 && c == 99 || b == 175 && c == 48) ||
            a == 198 && b == 51 && c == 100 || a == 203 && b == 0 && c == 113 ->
            ProviderAddressClass.FORBIDDEN
        else -> ProviderAddressClass.PUBLIC
    }
}

/**
 * Public IPv6 means an RIR-allocated global unicast block outside the IANA special-purpose
 * registry. Unique-local space is private. Everything else, including reserved space inside
 * 2000::/3, 6to4, Teredo, ORCHID, benchmarking, documentation, AS112, discard and local-use NAT64,
 * is refused. The well-known NAT64 prefix is admitted only when the operator enabled it and the
 * embedded IPv4 address is public; it is never treated as private.
 */
private fun classifyIpv6(bytes: ByteArray, translation: AcpProviderAddressTranslation): ProviderAddressClass {
    val word = IntArray(8) { ((bytes[it * 2].toInt() and 0xff) shl 8) or (bytes[it * 2 + 1].toInt() and 0xff) }
    // An IPv4-mapped address is an IPv4 destination on the wire.
    if ((0..4).all { word[it] == 0 } && word[5] == 0xffff) return classifyIpv4(bytes.copyOfRange(12, 16))
    if (word[0] == 0x0064 && word[1] == 0xff9b && (2..5).all { word[it] == 0 }) {
        val embedded = classifyIpv4(bytes.copyOfRange(12, 16))
        return if (translation == AcpProviderAddressTranslation.WELL_KNOWN_NAT64 && embedded == ProviderAddressClass.PUBLIC) {
            ProviderAddressClass.PUBLIC
        } else ProviderAddressClass.FORBIDDEN
    }
    if (word[0] and 0xfe00 == 0xfc00) return ProviderAddressClass.PRIVATE
    val specialPurpose = word[0] == 0x2001 && (word[1] < 0x0200 || word[1] == 0x0db8) ||
        word[0] == 0x2620 && word[1] == 0x004f && word[2] == 0x8000
    return if (!specialPurpose && isAllocatedGlobalUnicast(word[0], word[1])) ProviderAddressClass.PUBLIC else ProviderAddressClass.FORBIDDEN
}

/** IANA IPv6 global unicast blocks delegated to regional registries (excluding 2002::/16 6to4). */
private fun isAllocatedGlobalUnicast(first: Int, second: Int): Boolean = when (first) {
    0x2001 -> true
    0x2003 -> second < 0x4000
    in 0x2400..0x240f, in 0x2600..0x260f, in 0x2630..0x263f, in 0x2800..0x280f,
    in 0x2a00..0x2a1f, in 0x2c00..0x2c0f -> true
    0x2610, 0x2611, 0x2620, 0x2621 -> true
    else -> false
}
