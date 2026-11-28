package decompengine.acp

import java.net.InetAddress

/** Destination class of one resolved provider address. */
internal enum class ProviderAddressClass { PUBLIC, PRIVATE, FORBIDDEN }

/**
 * IANA "IPv6 Global Unicast Address Space", last updated 2025-10-10, ALLOCATED rows only (RESERVED
 * rows are refused by omission). Transcribed from
 * https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xml
 * (SHA-256 22f9a545e020ea6b9adea9ea0276f3157e32c838682459a45bfe7760de0aefc3). Nothing is fetched at
 * build, test or run time; updating this list is a reviewed source change.
 */
internal val IANA_IPV6_GLOBAL_UNICAST_ALLOCATED_2025_10_10: List<String> = listOf(
    "2001::/23", // IANA
    "2001:200::/23", // APNIC
    "2001:400::/23", // ARIN
    "2001:600::/23", // RIPE NCC
    "2001:800::/22", // RIPE NCC
    "2001:c00::/23", // APNIC
    "2001:e00::/23", // APNIC
    "2001:1200::/23", // LACNIC
    "2001:1400::/22", // RIPE NCC
    "2001:1800::/23", // ARIN
    "2001:1a00::/23", // RIPE NCC
    "2001:1c00::/22", // RIPE NCC
    "2001:2000::/19", // RIPE NCC
    "2001:4000::/23", // RIPE NCC
    "2001:4200::/23", // AFRINIC
    "2001:4400::/23", // APNIC
    "2001:4600::/23", // RIPE NCC
    "2001:4800::/23", // ARIN
    "2001:4a00::/23", // RIPE NCC
    "2001:4c00::/23", // RIPE NCC
    "2001:5000::/20", // RIPE NCC
    "2001:8000::/19", // APNIC
    "2001:a000::/20", // APNIC
    "2001:b000::/20", // APNIC
    "2002::/16", // 6to4
    "2003::/18", // RIPE NCC
    "2400::/12", // APNIC
    "2410::/12", // APNIC
    "2600::/12", // ARIN
    "2610::/23", // ARIN
    "2620::/23", // ARIN
    "2630::/12", // ARIN
    "2800::/12", // LACNIC
    "2a00::/12", // RIPE NCC
    "2a10::/12", // RIPE NCC
    "2c00::/12", // AFRINIC
)

/**
 * IANA "IPv6 Special-Purpose Address Space", last updated 2025-10-09, every row. Transcribed from
 * https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xml
 * (SHA-256 660acf0201b462b8d820605ba1cb20c4ed216acd883ee4a55a17453d73d4c3aa).
 */
internal val IANA_IPV6_SPECIAL_PURPOSE_2025_10_09: List<String> = listOf(
    "::1/128", // Loopback Address
    "::/128", // Unspecified Address
    "::ffff:0:0/96", // IPv4-mapped Address
    "64:ff9b::/96", // IPv4-IPv6 Translat.
    "64:ff9b:1::/48", // IPv4-IPv6 Translat.
    "100::/64", // Discard-Only Address Block
    "100:0:0:1::/64", // Dummy IPv6 Prefix
    "2001::/23", // IETF Protocol Assignments
    "2001::/32", // TEREDO
    "2001:1::1/128", // Port Control Protocol Anycast
    "2001:1::2/128", // Traversal Using Relays around NAT Anycast
    "2001:1::3/128", // DNS-SD Service Registration Protocol Anycast
    "2001:2::/48", // Benchmarking
    "2001:3::/32", // AMT
    "2001:4:112::/48", // AS112-v6
    "2001:10::/28", // Deprecated (previously ORCHID)
    "2001:20::/28", // ORCHIDv2
    "2001:30::/28", // Drone Remote ID Protocol Entity Tags (DETs) Prefix
    "2001:db8::/32", // Documentation
    "2002::/16", // 6to4
    "2620:4f:8000::/48", // Direct Delegation AS112 Service
    "3fff::/20", // Documentation
    "5f00::/16", // Segment Routing (SRv6) SIDs
    "fc00::/7", // Unique-Local
    "fe80::/10", // Link-Local Unicast
)

/**
 * IANA "IPv4 Special-Purpose Address Space", last updated 2025-10-09, every row. Transcribed from
 * https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xml
 * (SHA-256 37f334466c842387a8aee8d1ae7a6d5b2208ef27eb8964072538b73ee2f5b21d).
 */
internal val IANA_IPV4_SPECIAL_PURPOSE_2025_10_09: List<String> = listOf(
    "0.0.0.0/8", // "This network"
    "0.0.0.0/32", // "This host on this network"
    "10.0.0.0/8", // Private-Use
    "100.64.0.0/10", // Shared Address Space
    "127.0.0.0/8", // Loopback
    "169.254.0.0/16", // Link Local
    "172.16.0.0/12", // Private-Use
    "192.0.0.0/24", // IETF Protocol Assignments
    "192.0.0.0/29", // IPv4 Service Continuity Prefix
    "192.0.0.8/32", // IPv4 dummy address
    "192.0.0.9/32", // Port Control Protocol Anycast
    "192.0.0.10/32", // Traversal Using Relays around NAT Anycast
    "192.0.0.170/32", // NAT64/DNS64 Discovery
    "192.0.0.171/32", // NAT64/DNS64 Discovery
    "192.0.2.0/24", // Documentation (TEST-NET-1)
    "192.31.196.0/24", // AS112-v4
    "192.52.193.0/24", // AMT
    "192.88.99.0/24", // Deprecated (6to4 Relay Anycast)
    "192.88.99.2/32", // 6a44-relay anycast address
    "192.168.0.0/16", // Private-Use
    "192.175.48.0/24", // Direct Delegation AS112 Service
    "198.18.0.0/15", // Benchmarking
    "198.51.100.0/24", // Documentation (TEST-NET-2)
    "203.0.113.0/24", // Documentation (TEST-NET-3)
    "240.0.0.0/4", // Reserved
    "255.255.255.255/32", // Limited Broadcast
)

/**
 * Classifies one resolved address. Private means the special-purpose Private-Use, Shared Address
 * Space and Unique-Local rows. Public IPv4 is any address outside the IPv4 special-purpose registry
 * and multicast. Public IPv6 is an ALLOCATED global unicast block outside the IPv6 special-purpose
 * registry. Everything else is refused, including globally reachable special-purpose rows (anycast,
 * AS112, AMT, ORCHIDv2), which are never a provider endpoint.
 *
 * IPv4-mapped addresses are classified as the IPv4 address they carry. The well-known NAT64 prefix
 * is admitted only when the operator enabled it and the embedded IPv4 address is public. An address
 * synthesized from a network-specific NAT64 prefix is indistinguishable from native IPv6 by its
 * bytes; this classifier cannot detect it, and the resolver contract owns that case.
 */
internal fun classifyProviderAddress(address: InetAddress, translation: AcpProviderAddressTranslation): ProviderAddressClass {
    val bytes = address.address
    return when (bytes.size) {
        4 -> classifyIpv4(bytes)
        16 -> classifyIpv6(bytes, translation)
        else -> ProviderAddressClass.FORBIDDEN
    }
}

private fun classifyIpv4(bytes: ByteArray): ProviderAddressClass = when {
    IPV4_PRIVATE.any { it.contains(bytes) } -> ProviderAddressClass.PRIVATE
    IPV4_SPECIAL.any { it.contains(bytes) } || IPV4_MULTICAST.contains(bytes) -> ProviderAddressClass.FORBIDDEN
    else -> ProviderAddressClass.PUBLIC
}

private fun classifyIpv6(bytes: ByteArray, translation: AcpProviderAddressTranslation): ProviderAddressClass {
    if (IPV6_MAPPED.contains(bytes)) return classifyIpv4(bytes.copyOfRange(12, 16))
    if (IPV6_WELL_KNOWN_NAT64.contains(bytes)) {
        val embedded = classifyIpv4(bytes.copyOfRange(12, 16))
        return if (translation == AcpProviderAddressTranslation.WELL_KNOWN_NAT64 && embedded == ProviderAddressClass.PUBLIC) {
            ProviderAddressClass.PUBLIC
        } else ProviderAddressClass.FORBIDDEN
    }
    return when {
        IPV6_UNIQUE_LOCAL.contains(bytes) -> ProviderAddressClass.PRIVATE
        IPV6_SPECIAL.any { it.contains(bytes) } -> ProviderAddressClass.FORBIDDEN
        IPV6_ALLOCATED.any { it.contains(bytes) } -> ProviderAddressClass.PUBLIC
        else -> ProviderAddressClass.FORBIDDEN
    }
}

/** A CIDR prefix over 4- or 16-byte network-order addresses. */
internal class ProviderAddressPrefix private constructor(private val network: ByteArray, private val length: Int) {
    fun contains(address: ByteArray): Boolean {
        if (address.size != network.size) return false
        val whole = length / 8
        for (index in 0 until whole) if (address[index] != network[index]) return false
        val remaining = length % 8
        if (remaining == 0) return true
        val mask = (0xff shl (8 - remaining)) and 0xff
        return (address[whole].toInt() and mask) == (network[whole].toInt() and mask)
    }

    companion object {
        fun parse(text: String): ProviderAddressPrefix {
            val slash = text.indexOf('/')
            require(slash > 0) { "address prefix needs a length" }
            val literal = text.substring(0, slash)
            val network = requireNotNull(if (':' in literal) parseIpv6Literal(literal) else parseIpv4Literal(literal)) {
                "address prefix literal is invalid"
            }
            val length = text.substring(slash + 1).toIntOrNull()
            require(length != null && length in 0..network.size * 8) { "address prefix length is invalid" }
            return ProviderAddressPrefix(network, length)
        }
    }
}

private fun registered(registry: List<String>, prefix: String): ProviderAddressPrefix {
    check(prefix in registry) { "address class is not a transcribed registry row" }
    return ProviderAddressPrefix.parse(prefix)
}

private val IPV6_ALLOCATED = IANA_IPV6_GLOBAL_UNICAST_ALLOCATED_2025_10_10.map(ProviderAddressPrefix::parse)
private val IPV6_SPECIAL = IANA_IPV6_SPECIAL_PURPOSE_2025_10_09.map(ProviderAddressPrefix::parse)
private val IPV6_MAPPED = registered(IANA_IPV6_SPECIAL_PURPOSE_2025_10_09, "::ffff:0:0/96")
private val IPV6_WELL_KNOWN_NAT64 = registered(IANA_IPV6_SPECIAL_PURPOSE_2025_10_09, "64:ff9b::/96")
private val IPV6_UNIQUE_LOCAL = registered(IANA_IPV6_SPECIAL_PURPOSE_2025_10_09, "fc00::/7")
private val IPV4_SPECIAL = IANA_IPV4_SPECIAL_PURPOSE_2025_10_09.map(ProviderAddressPrefix::parse)
private val IPV4_PRIVATE = listOf("10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")
    .map { registered(IANA_IPV4_SPECIAL_PURPOSE_2025_10_09, it) }

// IANA IPv4 Multicast Address Space; not part of the special-purpose registry.
private val IPV4_MULTICAST = ProviderAddressPrefix.parse("224.0.0.0/4")

/** RFC 3986 IPv4address: four dec-octets without leading zeros. */
internal fun parseIpv4Literal(text: String): ByteArray? {
    val parts = text.split('.')
    if (parts.size != 4) return null
    val bytes = ByteArray(4)
    parts.forEachIndexed { index, part ->
        if (part.isEmpty() || part.length > 3 || part.any { it !in '0'..'9' } || part.length > 1 && part[0] == '0') return null
        val value = part.toInt()
        if (value > 255) return null
        bytes[index] = value.toByte()
    }
    return bytes
}

/**
 * RFC 3986 IPv6address: eight h16 groups, or fewer with exactly one "::", where the final 32 bits
 * may be an IPv4address. Zone identifiers and IPvFuture are not IPv6address and are refused.
 */
internal fun parseIpv6Literal(text: String): ByteArray? {
    if (text.isEmpty() || text.length > 45) return null
    val gap = text.indexOf("::")
    if (gap >= 0 && text.indexOf("::", gap + 1) >= 0) return null
    val headText = if (gap >= 0) text.substring(0, gap) else text
    val tailText = if (gap >= 0) text.substring(gap + 2) else ""
    val head = ipv6Words(headText, ipv4Last = gap < 0) ?: return null
    val tail = ipv6Words(tailText, ipv4Last = true) ?: return null
    if (gap < 0 && head.size != 8 || gap >= 0 && head.size + tail.size > 7) return null
    val words = head + List(8 - head.size - tail.size) { 0 } + tail
    return ByteArray(16) { index -> (words[index / 2] shr (if (index % 2 == 0) 8 else 0)).toByte() }
}

private fun ipv6Words(text: String, ipv4Last: Boolean): List<Int>? {
    if (text.isEmpty()) return emptyList()
    val groups = text.split(':')
    val words = ArrayList<Int>(8)
    groups.forEachIndexed { index, group ->
        if (ipv4Last && index == groups.lastIndex && '.' in group) {
            val ipv4 = parseIpv4Literal(group) ?: return null
            words += ((ipv4[0].toInt() and 0xff) shl 8) or (ipv4[1].toInt() and 0xff)
            words += ((ipv4[2].toInt() and 0xff) shl 8) or (ipv4[3].toInt() and 0xff)
        } else {
            if (group.length !in 1..4 || group.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' }) return null
            words += group.toInt(16)
        }
    }
    return words
}
