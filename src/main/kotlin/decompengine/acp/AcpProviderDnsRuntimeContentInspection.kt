package decompengine.acp

import java.io.InputStream
import java.security.MessageDigest
import java.util.Collections

/**
 * Whole candidate byte observation only. No extraction authentication or semantic dlopen approval.
 * The controller must own and bound/cancel stream opening, reading and closing: this API bounds
 * bytes, not blocking-I/O wall time. An object exceeding the inventory cap can have its four-byte
 * magic prefix read before it is identified and refused, without allocating its ELF buffer.
 */
internal object AcpProviderDnsRuntimeContentInspection {
    class Observation internal constructor(val manifestSha256: String, objects: Map<String, AcpProviderDnsElfInspection.Metadata>) {
        val objects: Map<String, AcpProviderDnsElfInspection.Metadata> = Collections.unmodifiableMap(objects.toMap())
    }

    fun inspect(candidate: AcpProviderDnsRuntimeProfileCandidate, open: (AcpProviderDnsRuntimeEntry) -> InputStream): Observation {
        val entries = candidate.entries()
        require(entries.size in 1..AcpProviderDnsRuntimeProfiles.MAXIMUM_ENTRIES)
        require(entries.map { it.path }.toSet().size == entries.size)
        val limits = candidate.contentLimits
        fun limit(key: String, ceiling: Long): Long = requireNotNull(limits[key]).also { require(it in 1..ceiling) }
        val totalLimit = limit("bytes", AcpProviderDnsRuntimeProfiles.MAXIMUM_BYTES)
        val fileLimit = limit("fileBytes", AcpProviderDnsRuntimeProfiles.MAXIMUM_FILE_BYTES)
        val moduleLimit = limit("moduleBytes", AcpProviderDnsRuntimeProfiles.MAXIMUM_MODULE_BYTES)
        val edgeLimit = limit("edges", AcpProviderDnsRuntimeProfiles.MAXIMUM_EDGES.toLong())
        val files = entries.filter { it.kind == "file" }
        var charged = 0L
        // Validate and charge the entire manifest before opening even its first payload.
        files.forEach { entry ->
            require(entry.size in 1..if (entry.path == "jdk/lib/modules") moduleLimit else fileLimit)
            charged = dnsCharge(charged, entry.size, totalLimit)
        }
        require(charged == candidate.regularBytes)
        val objects = linkedMapOf<String, AcpProviderDnsElfInspection.Metadata>()
        val block = ByteArray(16384)
        files.forEach { entry ->
            val digest = MessageDigest.getInstance("SHA-256")
            var elf: ByteArray? = null
            var elfOffset = 0
            open(entry).use { input ->
                val prefix = ByteArray(minOf(4L, entry.size).toInt())
                var at = 0
                while (at < prefix.size) {
                    val n = input.read(prefix, at, prefix.size - at)
                    require(n > 0); at += n
                }
                val isElf = prefix.contentEquals(byteArrayOf(127, 69, 76, 70))
                if (isElf) {
                    require(entry.size <= fileLimit && objects.size < 256)
                    elf = ByteArray(entry.size.toInt())
                    prefix.copyInto(elf!!)
                    elfOffset = prefix.size
                }
                digest.update(prefix)
                var remaining = entry.size - prefix.size
                while (remaining > 0) {
                    val n = input.read(block, 0, minOf(block.size.toLong(), remaining).toInt())
                    require(n > 0); digest.update(block, 0, n); elf?.let { block.copyInto(it, elfOffset, 0, n); elfOffset += n }; remaining -= n
                }
                require(input.read() == -1)
            }
            require(dnsHex(digest.digest()) == entry.sha256)
            elf?.let { objects[entry.path] = AcpProviderDnsElfInspection.inspectOwned(it) }
        }
        require(objects.containsKey("jdk/bin/java"))
        require(objects.keys.containsAll(AcpProviderDnsRuntimeProfiles.requiredElfPaths))
        entries.filter { it.path.startsWith("native/") && it.kind == "file" }
            .forEach { require(objects.containsKey(it.path)) }
        AcpProviderDnsElfInspection.requireDeclaredProviders(objects)
        val edges = candidate.edges()
        require(edges.size.toLong() in 1..edgeLimit)
        require(edges.distinctBy { Triple(it.from, it.kind, it.name) }.size == edges.size)
        val search = listOf("native", "jdk/lib", "jdk/lib/server")
        fun provider(name: String): String {
            val matches = search.map { "$it/$name" }.filter { it in objects }
            require(matches.size == 1)
            return matches.single().also { require(objects.getValue(it).soname == name) }
        }
        val expected = mutableSetOf<AcpProviderDnsRuntimeEdge>()
        objects.forEach { (path, metadata) ->
            metadata.interpreter?.let {
                require(path == "jdk/bin/java" && it == "/lib64/ld-linux-x86-64.so.2")
                expected += AcpProviderDnsRuntimeEdge(path, "PT_INTERP", it, "native/ld-linux-x86-64.so.2")
            }
            metadata.needed.forEach { name -> expected += AcpProviderDnsRuntimeEdge(path, "DT_NEEDED", name, provider(name)) }
        }
        require(edges.filter { it.kind != "DLOPEN" }.toSet() == expected)
        require(expected.count { it.kind == "PT_INTERP" } == 1)
        edges.forEach {
            require(it.from in objects && it.target in objects)
            if (it.kind == "DLOPEN") {
                require(it.name.matches(Regex("[A-Za-z0-9._+-]+")))
                require(it.target == provider(it.name))
            } else require(it in expected)
        }
        val reachable = mutableSetOf("jdk/bin/java")
        repeat(objects.size) { edges.filter { it.from in reachable }.forEach { reachable += it.target } }
        require(reachable.containsAll(objects.keys))
        return Observation(candidate.manifestSha256, objects)
    }
}

/** Opaque content-checked candidate, not an approval, authenticated extraction or semantic dlopen proof. */
internal class AcpProviderDnsContentCheckedCandidate private constructor(
    private val candidate: AcpProviderDnsRuntimeProfileCandidate,
    private val observation: AcpProviderDnsRuntimeContentInspection.Observation,
) {
    val manifestSha256: String get() = candidate.manifestSha256
    fun entries(): List<AcpProviderDnsRuntimeEntry> = candidate.entries()
    fun edges(): List<AcpProviderDnsRuntimeEdge> = candidate.edges()
    fun objects(): Map<String, AcpProviderDnsElfInspection.Metadata> = observation.objects

    companion object {
        /** No caller-supplied candidate, metadata subset or self-reported seal is accepted here. */
        internal fun validate(bytes: ByteArray, open: (AcpProviderDnsRuntimeEntry) -> InputStream): AcpProviderDnsContentCheckedCandidate {
            require(bytes.size in 1..AcpProviderDnsRuntimeProfiles.MAXIMUM_MANIFEST_BYTES)
            val parsed = AcpProviderDnsRuntimeProfiles.parseCandidate(bytes.copyOf())
            val inspected = AcpProviderDnsRuntimeContentInspection.inspect(parsed, open)
            check(inspected.manifestSha256 == parsed.manifestSha256)
            return AcpProviderDnsContentCheckedCandidate(parsed, inspected)
        }
    }
}
