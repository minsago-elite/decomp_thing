package decompengine.acp

import decompengine.builtin.provider.parseProviderObject
import java.io.IOException
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.*

internal class AcpProviderDnsRuntimeUnavailableException : IOException("approved provider DNS runtime profile unavailable")

/** Parsing a candidate grants no profile, resolver, context or process authority. */
internal object AcpProviderDnsRuntimeProfiles {
    internal const val PROFILE_ID = "linux-x86_64-jdk21-dns-v1"
    internal const val ROOT = "/provider-dns-runtime"
    internal const val MAXIMUM_MANIFEST_BYTES = 1024 * 1024
    internal const val MAXIMUM_ENTRIES = 2048
    internal const val MAXIMUM_DEPTH = 16
    internal const val MAXIMUM_BYTES = 256L * 1024 * 1024
    internal const val MAXIMUM_FILE_BYTES = 16L * 1024 * 1024
    internal const val MAXIMUM_MODULE_BYTES = 192L * 1024 * 1024
    internal const val MAXIMUM_EDGES = 256
    internal const val MAXIMUM_NATIVE_LIBRARIES = 32

    private val requiredJdkFiles = setOf("jdk/bin/java", "jdk/release", "jdk/lib/modules",
        "jdk/lib/libjava.so", "jdk/lib/libjimage.so", "jdk/lib/libjli.so", "jdk/lib/libnet.so",
        "jdk/lib/libnio.so", "jdk/lib/libverify.so", "jdk/lib/libzip.so", "jdk/lib/server/libjvm.so",
        "jdk/conf/net.properties", "jdk/conf/security/java.security", "jdk/legal/java.base/LICENSE")
    internal val requiredElfPaths: Set<String> = Collections.unmodifiableSet(
        requiredJdkFiles.filter { it == "jdk/bin/java" || it.endsWith(".so") }.toSet())
    private val nativeNames = setOf("ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6", "libdl.so.2",
        "libpthread.so.0", "librt.so.1", "libz.so.1", "libstdc++.so.6", "libgcc_s.so.1",
        "libnss_files.so.2", "libnss_dns.so.2", "libresolv.so.2")
    private val loaderArgv = listOf("$ROOT/native/ld-linux-x86-64.so.2", "--inhibit-cache", "--library-path",
        "$ROOT/native:$ROOT/jdk/lib:$ROOT/jdk/lib/server", "$ROOT/jdk/bin/java")

    internal fun isLibraryPath(path: String): Boolean = path.startsWith("native/") ||
        path.startsWith("jdk/lib/") && path.substringBeforeLast('/') in setOf("jdk/lib", "jdk/lib/server")

    // No archive/toolchain/output/native subset or #958 resolver identity has been approved.
    // This gate cannot be opened by a candidate, caller path, adjacent checksum or reflection fixture.
    @Suppress("UNUSED_PARAMETER")
    internal fun requireApproved(profileId: String, manifestSha256: String, resolverPolicySha256: String): Nothing =
        throw AcpProviderDnsRuntimeUnavailableException()

    internal fun parseCandidate(bytes: ByteArray): AcpProviderDnsRuntimeProfileCandidate {
        require(bytes.size in 1..MAXIMUM_MANIFEST_BYTES)
        val document = parseProviderObject(bytes.decodeToString(throwOnInvalidSequence = true), MAXIMUM_MANIFEST_BYTES)
        document.exact("schema", "profileId", "applicationBuildSha256", "architecture", "abi", "jdkFeature", "jdkModule",
            "jdkReleaseSha256", "jdkModulesSha256", "sourceArchiveSha256", "toolchainSha256", "recipeSha256",
            "workerSha256", "sourceOwner", "limits", "entries", "elfEdges", "loaderArgv")
        require(document.text("schema") == "provider-dns-runtime-profile-v1" && document.text("profileId") == PROFILE_ID)
        require(document.text("architecture") == "x86_64" && document.text("abi") == "linux-glibc-x86_64" &&
            document.number("jdkFeature") == 21L && document.text("jdkModule") == "java.base")
        listOf("applicationBuildSha256", "jdkReleaseSha256", "jdkModulesSha256", "sourceArchiveSha256",
            "toolchainSha256", "recipeSha256", "workerSha256").forEach { document.hash(it) }
        val owner = document.getValue("sourceOwner").jsonObject
        owner.exact("policy", "uid", "gid")
        val ownerPolicy = owner.text("policy")
        val uid = owner.number("uid"); val gid = owner.number("gid")
        require(uid in 0..Int.MAX_VALUE.toLong() && gid in 0..Int.MAX_VALUE.toLong())
        require(ownerPolicy == "root" && uid == 0L && gid == 0L || ownerPolicy == "service" && uid > 0)
        val limits = document.getValue("limits").jsonObject
        limits.exact("entries", "depth", "bytes", "fileBytes", "moduleBytes", "edges", "nativeLibraries")
        val ceilings = mapOf("entries" to MAXIMUM_ENTRIES.toLong(), "depth" to MAXIMUM_DEPTH.toLong(),
            "bytes" to MAXIMUM_BYTES, "fileBytes" to MAXIMUM_FILE_BYTES, "moduleBytes" to MAXIMUM_MODULE_BYTES,
            "edges" to MAXIMUM_EDGES.toLong(), "nativeLibraries" to MAXIMUM_NATIVE_LIBRARIES.toLong())
        ceilings.forEach { (key, maximum) -> require(limits.number(key) in 1..maximum) }
        val rawEntries = document.getValue("entries").jsonArray
        require(rawEntries.size in 1..limits.number("entries").toInt())
        var total = 0L
        val entries = rawEntries.map { raw ->
            val record = raw.jsonObject
            record.exact("path", "kind", "mode", "owner", "size", "sha256")
            val path = record.text("path")
            require(path.matches(Regex("[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*")) &&
                path.split('/').none { it == "." || it == ".." } && path.split('/').size <= limits.number("depth"))
            require(path == "jdk" || path == "native" || path.startsWith("jdk/") || path.startsWith("native/"))
            require(record.text("owner") == ownerPolicy)
            val kind = record.text("kind"); val mode = record.text("mode"); val size = record.number("size")
            when (kind) {
                "directory" -> require(mode == "0755" && size == 0L && record["sha256"] === JsonNull)
                "file" -> {
                    val maximum = if (path == "jdk/lib/modules") limits.number("moduleBytes") else limits.number("fileBytes")
                    require(size in 1..maximum)
                    total = Math.addExact(total, size)
                    require(total <= limits.number("bytes"))
                    record.hash("sha256")
                    require(mode == "0644" || mode == "0755" && (path == "jdk/bin/java" ||
                        path in requiredJdkFiles && path.endsWith(".so") || path.startsWith("native/")))
                    require(!path.endsWith(".jar") && !path.endsWith(".class") && !path.contains("/services/"))
                }
                else -> error("unsupported runtime entry kind")
            }
            AcpProviderDnsRuntimeEntry(path, kind, mode, size, record["sha256"]?.jsonPrimitive?.contentOrNull)
        }
        require(entries.map { it.path } == entries.map { it.path }.sorted() && entries.map { it.path }.toSet().size == entries.size)
        val byPath = entries.associateBy { it.path }
        require(byPath["jdk"]?.kind == "directory" && byPath["native"]?.kind == "directory")
        entries.forEach { record ->
            if ('/' in record.path) require(byPath[record.path.substringBeforeLast('/')]?.kind == "directory")
        }
        require(requiredJdkFiles.all { byPath[it]?.kind == "file" })
        require(byPath.getValue("jdk/bin/java").mode == "0755")
        require(byPath.getValue("jdk/release").sha256 == document.hash("jdkReleaseSha256") &&
            byPath.getValue("jdk/lib/modules").sha256 == document.hash("jdkModulesSha256"))
        val native = entries.filter { it.path.startsWith("native/") }
        require(native.size in 1..limits.number("nativeLibraries").toInt() && native.all {
            it.kind == "file" && it.path.removePrefix("native/") in nativeNames
        })
        require(byPath["native/ld-linux-x86-64.so.2"]?.mode == "0755" && byPath["native/libc.so.6"]?.kind == "file")
        require(document.getValue("loaderArgv").jsonArray.map { it.jsonPrimitive.also { p -> require(p.isString) }.content } == loaderArgv)
        val rawEdges = document.getValue("elfEdges").jsonArray
        require(rawEdges.size in 1..limits.number("edges").toInt())
        val edges = rawEdges.map { raw ->
            val edge = raw.jsonObject
            edge.exact("from", "kind", "name", "target")
            val from = edge.text("from"); val target = edge.text("target"); val kind = edge.text("kind"); val name = edge.text("name")
            require(byPath[from]?.kind == "file" && byPath[target]?.kind == "file")
            require(isLibraryPath(target))
            require(from == "jdk/bin/java" || isLibraryPath(from))
            when (kind) {
                "PT_INTERP" -> require(from == "jdk/bin/java" && name == "/lib64/ld-linux-x86-64.so.2" && target == "native/ld-linux-x86-64.so.2")
                "DT_NEEDED", "DLOPEN" -> require(name == target.substringAfterLast('/') && name.matches(Regex("[A-Za-z0-9._+-]+")))
                else -> error("unsupported ELF dependency kind")
            }
            AcpProviderDnsRuntimeEdge(from, kind, name, target)
        }
        require(edges.distinctBy { Triple(it.from, it.kind, it.name) }.size == edges.size && edges.count { it.kind == "PT_INTERP" } == 1)
        val reachable = mutableSetOf("jdk/bin/java")
        repeat(entries.size) { edges.filter { it.from in reachable }.forEach { reachable += it.target } }
        require(entries.filter { it.path.startsWith("native/") || it.path in requiredJdkFiles && it.path.endsWith(".so") }
            .all { it.path in reachable })
        return AcpProviderDnsRuntimeProfileCandidate(profileSha256(bytes), total, entries.toList(), edges.toList(), ceilings.mapValues { limits.number(it.key) })
    }
}

/** Structural candidate only: bytes still require authenticated extraction, ELF inspection and app approval. */
internal class AcpProviderDnsRuntimeProfileCandidate internal constructor(
    val manifestSha256: String, val regularBytes: Long,
    private val entryRecords: List<AcpProviderDnsRuntimeEntry>, private val dependencyRecords: List<AcpProviderDnsRuntimeEdge>,
    contentLimits: Map<String, Long>,
) {
    internal val contentLimits: Map<String, Long> = Collections.unmodifiableMap(contentLimits.toMap())
    fun entries(): List<AcpProviderDnsRuntimeEntry> = entryRecords.toList()
    fun edges(): List<AcpProviderDnsRuntimeEdge> = dependencyRecords.toList()
}
internal data class AcpProviderDnsRuntimeEntry(val path: String, val kind: String, val mode: String, val size: Long, val sha256: String?)
internal data class AcpProviderDnsRuntimeEdge(val from: String, val kind: String, val name: String, val target: String)

/** Exact parser/serializer for non-secret resolver policy candidates. Approval belongs to #958. */
internal class AcpProviderDnsResolverCandidate private constructor(
    private val resolver: ByteArray, private val switch: ByteArray, private val hostsFile: ByteArray,
) {
    val sha256: String = profileSha256("provider-dns-resolver-policy-v1\u0000".toByteArray() +
        listOf(resolver, switch, hostsFile).fold(byteArrayOf()) { result, bytes ->
            result + java.nio.ByteBuffer.allocate(4).putInt(bytes.size).array() + bytes
        })
    fun resolvConf(): ByteArray = resolver.copyOf()
    fun nsswitchConf(): ByteArray = switch.copyOf()
    fun hosts(): ByteArray = hostsFile.copyOf()

    companion object {
        private const val SWITCH = "hosts: files dns\n"
        private const val HOSTS = "127.0.0.1 localhost\n::1 localhost\n"
        fun parseForValidation(resolvConf: ByteArray, nsswitchConf: ByteArray, hosts: ByteArray): AcpProviderDnsResolverCandidate {
            require(resolvConf.size in 1..4096 && nsswitchConf.size in 1..64 && hosts.size in 1..128)
            require(resolvConf.size.toLong() + nsswitchConf.size + hosts.size <= 4288L)
            val files = listOf(resolvConf, nsswitchConf, hosts)
            files.forEach { bytes ->
                require(bytes.last() == 10.toByte() && bytes.all { it == 10.toByte() || it.toInt() in 32..126 })
                val lines = bytes.toString(Charsets.US_ASCII).dropLast(1).split('\n')
                require(lines.size <= 32 && lines.all { it.length in 1..256 && !it.startsWith(' ') && !it.endsWith(' ') && "  " !in it })
            }
            require(nsswitchConf.contentEquals(SWITCH.toByteArray()) && hosts.contentEquals(HOSTS.toByteArray()))
            val lines = resolvConf.toString(Charsets.US_ASCII).dropLast(1).split('\n')
            val addresses = mutableSetOf<String>()
            var options = false
            lines.forEachIndexed { index, line ->
                if (line.startsWith("nameserver ")) {
                    require(!options && addresses.size < 3)
                    val literal = line.removePrefix("nameserver ")
                    require(canonicalNumericAddress(literal) == literal && addresses.add(literal))
                } else {
                    require(index == lines.lastIndex && !options && addresses.isNotEmpty() &&
                        line.matches(Regex("options timeout:[1-5] attempts:[1-2]")))
                    options = true
                }
            }
            require(addresses.size in 1..3)
            return AcpProviderDnsResolverCandidate(resolvConf.copyOf(), nsswitchConf.copyOf(), hosts.copyOf())
        }
    }
}

private fun canonicalNumericAddress(text: String): String {
    if (':' !in text) {
        val parts = text.split('.')
        require(parts.size == 4 && parts.all { it.matches(Regex("0|[1-9][0-9]{0,2}")) && it.toInt() <= 255 })
        return parts.joinToString(".") { it.toInt().toString() }
    }
    val hexadecimal = if ('.' in text) {
        val tail = text.substringAfterLast(':')
        require(canonicalNumericAddress(tail) == tail)
        val octets = tail.split('.').map(String::toInt)
        text.substringBeforeLast(':') + ":" + ((octets[0] shl 8) or octets[1]).toString(16) + ":" +
            ((octets[2] shl 8) or octets[3]).toString(16)
    } else text
    require(hexadecimal.matches(Regex("[0-9a-f:]+")) && ":::" !in hexadecimal)
    val halves = hexadecimal.split("::")
    require(halves.size in 1..2)
    fun words(part: String): List<Int> = if (part.isEmpty()) emptyList() else part.split(':').map {
        require(it.matches(Regex("[0-9a-f]{1,4}"))); it.toInt(16)
    }
    val left = words(halves[0]); val right = if (halves.size == 2) words(halves[1]) else emptyList()
    val count = left.size + right.size
    require(if (halves.size == 1) count == 8 else count < 8)
    val groups = if (halves.size == 1) left else left + List(8 - count) { 0 } + right
    // RFC5952 section5 recommends mixed decimal notation for the well-known mapped prefix.
    if (groups.take(5).all { it == 0 } && groups[5] == 0xffff) return "::ffff:" +
        listOf(groups[6] ushr 8, groups[6] and 255, groups[7] ushr 8, groups[7] and 255).joinToString(".")
    var bestStart = -1; var bestLength = 1; var at = 0
    while (at < groups.size) {
        if (groups[at] != 0) { at++; continue }
        val start = at
        while (at < groups.size && groups[at] == 0) at++
        if (at - start > bestLength) { bestStart = start; bestLength = at - start }
    }
    if (bestStart < 0) return groups.joinToString(":") { it.toString(16) }
    return groups.take(bestStart).joinToString(":") { it.toString(16) } + "::" +
        groups.drop(bestStart + bestLength).joinToString(":") { it.toString(16) }
}
private fun JsonObject.exact(vararg keys: String) { require(this.keys == keys.toSet()) }
private fun JsonObject.text(key: String): String = getValue(key).jsonPrimitive.also { require(it.isString) }.content
private fun JsonObject.number(key: String): Long = getValue(key).jsonPrimitive.also {
    require(!it.isString && it.content.matches(Regex("0|[1-9][0-9]*")))
}.long
private fun JsonObject.hash(key: String): String = text(key).also { require(it.matches(Regex("[0-9a-f]{64}"))) }
private fun profileSha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
