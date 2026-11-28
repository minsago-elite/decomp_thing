package decompengine.acp

import java.net.InetAddress
import java.net.URI
import java.util.Locale
import java.util.Properties
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters

/**
 * One HTTP/1.1 request head received from a contained agent on its provider channel. Every field
 * is untrusted. Header names keep their received case and order; nothing here selects a destination.
 */
internal class AcpProviderRelayRequest(
    val method: String,
    val target: String,
    headers: List<Pair<String, String>>,
) {
    val headers: List<Pair<String, String>> = headers.toList()

    override fun toString(): String = "AcpProviderRelayRequest(<untrusted>)"
}

enum class AcpProviderRouteRefusal {
    TRANSPORT_DISABLED,
    MALFORMED_REQUEST,
    MALFORMED_RESPONSE,
    REQUEST_HEAD_TOO_LARGE,
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
    /** The upstream target. [endpoint] is always the approved policy endpoint. */
    class Routed internal constructor(
        val operation: AcpProviderOperation,
        val endpoint: URI,
        val policyDescriptorSha256: String,
    ) : AcpProviderRouteDecision

    data class Refused(val reason: AcpProviderRouteRefusal) : AcpProviderRouteDecision
}

/**
 * Routing decisions for the approved provider transport. Callers must refuse before forwarding
 * anything upstream: a relay request is matched only against the policy's declared operation, the
 * upstream destination always comes from the policy, and every resolved address and response status
 * is checked before it is used. There is no CONNECT, proxy, redirect, scheme or authority override.
 */
internal object AcpProviderRouting {
    fun route(policy: AcpProviderTransportPolicy, request: AcpProviderRelayRequest): AcpProviderRouteDecision {
        val approved = policy as? AcpProviderTransportPolicy.Approved ?: return refused(AcpProviderRouteRefusal.TRANSPORT_DISABLED)
        headRefusal(approved.bounds, request)?.let { return refused(it) }
        if (request.method == "CONNECT") return refused(AcpProviderRouteRefusal.CONNECT_REFUSED)
        // Absolute-form, authority-form and asterisk-form targets are proxy requests.
        if (!request.target.startsWith('/')) return refused(AcpProviderRouteRefusal.PROXY_REQUEST_REFUSED)
        if ('?' in request.target) return refused(AcpProviderRouteRefusal.QUERY_REFUSED)

        val names = request.headers.map { (name, _) -> name.lowercase(Locale.ROOT) }
        if (names.count { it == "host" } != 1 ||
            names.count { it == "content-length" } > 1 ||
            "content-length" in names && "transfer-encoding" in names
        ) return refused(AcpProviderRouteRefusal.MALFORMED_REQUEST)
        if (names.any(::isRoutingOverrideHeader)) return refused(AcpProviderRouteRefusal.ROUTING_OVERRIDE_REFUSED)
        if (requestsProtocolUpgrade(request.headers)) return refused(AcpProviderRouteRefusal.PROTOCOL_UPGRADE_REFUSED)

        // Exact byte comparison: no decoding, normalization, case folding or prefix match.
        val operation = approved.operation.takeIf { it.relayPath == request.target }
            ?: return refused(AcpProviderRouteRefusal.OPERATION_UNSUPPORTED)
        if (request.method != operation.method) return refused(AcpProviderRouteRefusal.METHOD_UNSUPPORTED)
        return AcpProviderRouteDecision.Routed(operation, approved.endpoint, approved.descriptorSha256)
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
        val classes = addresses.map(::classifyProviderAddress)
        return when {
            ProviderAddressClass.FORBIDDEN in classes -> AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED
            ProviderAddressClass.PRIVATE in classes &&
                approved.privateDestinations != AcpProviderPrivateDestinations.PERMITTED ->
                AcpProviderRouteRefusal.PRIVATE_DESTINATION_NOT_PERMITTED
            else -> null
        }
    }

    /** Upstream TLS parameters: HTTPS hostname verification, policy-host SNI and TLS 1.2 or later. */
    fun upstreamSslParameters(policy: AcpProviderTransportPolicy.Approved, defaults: SSLParameters): SSLParameters {
        val protocols = defaults.protocols.filter { it in PROVIDER_TLS_PROTOCOLS }
        require(protocols.isNotEmpty()) { "provider TLS requires TLSv1.3 or TLSv1.2" }
        return SSLParameters(defaults.cipherSuites, protocols.toTypedArray()).apply {
            endpointIdentificationAlgorithm = "HTTPS"
            serverNames = listOf(SNIHostName(policy.endpoint.host))
        }
    }

    /** Refuses TLS settings or JVM properties that would weaken mandatory upstream verification. */
    fun requireMandatoryUpstreamTls(
        policy: AcpProviderTransportPolicy.Approved,
        parameters: SSLParameters,
        systemProperties: Properties = System.getProperties(),
    ) {
        check(policy.tlsVerification == AcpProviderTlsVerification.PLATFORM_TRUST_HOSTNAME_VERIFIED) {
            "unsupported provider TLS verification mode"
        }
        check(parameters.endpointIdentificationAlgorithm == "HTTPS") { "provider TLS hostname verification is disabled" }
        val protocols = parameters.protocols.orEmpty()
        check(protocols.isNotEmpty() && protocols.all { it in PROVIDER_TLS_PROTOCOLS }) {
            "provider TLS protocol set is not TLSv1.3 or TLSv1.2"
        }
        check(parameters.serverNames.orEmpty().map { (it as? SNIHostName)?.asciiName } == listOf(policy.endpoint.host)) {
            "provider TLS server name does not match the approved endpoint"
        }
        // The JDK HTTP client skips hostname verification when this property is present.
        check(systemProperties.getProperty(JDK_DISABLE_HOSTNAME_VERIFICATION_PROPERTY) == null) {
            "provider TLS hostname verification is disabled by a JVM property"
        }
    }

    private fun refused(reason: AcpProviderRouteRefusal) = AcpProviderRouteDecision.Refused(reason)
}

private val PROVIDER_TLS_PROTOCOLS = setOf("TLSv1.3", "TLSv1.2")
private const val JDK_DISABLE_HOSTNAME_VERIFICATION_PROPERTY = "jdk.internal.httpclient.disableHostnameVerification"
private val HTTP_TOKEN = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+")
private val ROUTING_OVERRIDE_HEADERS = setOf(
    "forwarded", "x-rewrite-url", "x-host", "x-http-host", "x-http-method", "x-http-method-override",
    "x-method-override", "proxy-authorization", "proxy-connection",
)
private val ROUTING_OVERRIDE_HEADER_PREFIXES = listOf("x-forwarded-", "x-original-")

private fun headRefusal(bounds: AcpProviderTransportBounds, request: AcpProviderRelayRequest): AcpProviderRouteRefusal? {
    if (request.headers.size > bounds.maximumHeaderFields) return AcpProviderRouteRefusal.REQUEST_HEAD_TOO_LARGE
    var bytes = request.method.length.toLong() + request.target.length + 2
    request.headers.forEach { (name, value) ->
        bytes += name.length + value.length + 4
        if (bytes > bounds.maximumHeaderBytes) return AcpProviderRouteRefusal.REQUEST_HEAD_TOO_LARGE
    }
    if (bytes > bounds.maximumHeaderBytes) return AcpProviderRouteRefusal.REQUEST_HEAD_TOO_LARGE
    if (!request.method.matches(HTTP_TOKEN) || request.target.isEmpty() || request.target.any { it <= ' ' || it >= '\u007f' } ||
        '#' in request.target
    ) return AcpProviderRouteRefusal.MALFORMED_REQUEST
    val malformedHeader = request.headers.any { (name, value) ->
        !name.matches(HTTP_TOKEN) || value.any { it == '\r' || it == '\n' || it == '\u0000' || it >= '\u007f' }
    }
    return if (malformedHeader) AcpProviderRouteRefusal.MALFORMED_REQUEST else null
}

private fun isRoutingOverrideHeader(lowercaseName: String): Boolean =
    lowercaseName in ROUTING_OVERRIDE_HEADERS || ROUTING_OVERRIDE_HEADER_PREFIXES.any(lowercaseName::startsWith)

private fun requestsProtocolUpgrade(headers: List<Pair<String, String>>): Boolean = headers.any { (name, value) ->
    when (name.lowercase(Locale.ROOT)) {
        "upgrade", "http2-settings" -> true
        "connection" -> value.split(',').any { it.trim().equals("upgrade", ignoreCase = true) }
        else -> false
    }
}

private enum class ProviderAddressClass { PUBLIC, PRIVATE, FORBIDDEN }

private fun classifyProviderAddress(address: InetAddress): ProviderAddressClass {
    val bytes = address.address
    return when (bytes.size) {
        4 -> classifyIpv4(bytes)
        16 -> classifyIpv6(bytes)
        else -> ProviderAddressClass.FORBIDDEN
    }
}

private fun classifyIpv4(bytes: ByteArray): ProviderAddressClass {
    val a = bytes[0].toInt() and 0xff
    val b = bytes[1].toInt() and 0xff
    val c = bytes[2].toInt() and 0xff
    return when {
        a == 10 || a == 172 && b in 16..31 || a == 192 && b == 168 || a == 100 && b in 64..127 -> ProviderAddressClass.PRIVATE
        a == 0 || a == 127 || a >= 224 || a == 169 && b == 254 ||
            a == 192 && b == 0 && (c == 0 || c == 2) || a == 192 && b == 88 && c == 99 ||
            a == 198 && (b == 18 || b == 19) || a == 198 && b == 51 && c == 100 || a == 203 && b == 0 && c == 113 ->
            ProviderAddressClass.FORBIDDEN
        else -> ProviderAddressClass.PUBLIC
    }
}

private fun classifyIpv6(bytes: ByteArray): ProviderAddressClass {
    val word = IntArray(8) { ((bytes[it * 2].toInt() and 0xff) shl 8) or (bytes[it * 2 + 1].toInt() and 0xff) }
    // IPv4-mapped, NAT64 well-known prefix and 6to4 embed an IPv4 destination; classify that destination.
    if (word.slice(0..4).all { it == 0 } && word[5] == 0xffff ||
        word[0] == 0x64 && word[1] == 0xff9b && word.slice(2..5).all { it == 0 }
    ) return classifyIpv4(bytes.copyOfRange(12, 16))
    if (word[0] == 0x2002) return classifyIpv4(bytes.copyOfRange(2, 6))
    return when {
        word[0] and 0xfe00 == 0xfc00 -> ProviderAddressClass.PRIVATE
        // Outside global unicast: unspecified, loopback, IPv4-compatible, link-local, multicast and unallocated.
        word[0] and 0xe000 != 0x2000 -> ProviderAddressClass.FORBIDDEN
        // IETF protocol assignments (Teredo, ORCHID, benchmarking) and documentation prefixes.
        word[0] == 0x2001 && (word[1] < 0x0200 || word[1] == 0x0db8) || word[0] == 0x3fff && word[1] < 0x1000 ->
            ProviderAddressClass.FORBIDDEN
        else -> ProviderAddressClass.PUBLIC
    }
}
