package decompengine.acp

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Inert byte fixtures only; no native loading, extraction, approval or runtime assembly. */
class AcpProviderDnsRuntimeContentInspectionTest {
    private val loader = "native/ld-linux-x86-64.so.2"
    private fun elf(soname: String? = null, interpreter: Boolean = false, needed: String? = null): ByteArray {
        val bytes = ByteArray(1024)
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        byteArrayOf(127, 69, 76, 70, 2, 1, 1).copyInto(bytes)
        b.putShort(16, 3); b.putShort(18, 62); b.putInt(20, 1)
        b.putLong(32, 64); b.putShort(52, 64); b.putShort(54, 56); b.putShort(56, if (interpreter) 3 else 2)
        fun ph(at: Int, type: Int, offset: Long, size: Long) {
            b.putInt(at, type); b.putInt(at + 4, 4); b.putLong(at + 8, offset)
            b.putLong(at + 16, 0x400000 + offset); b.putLong(at + 32, size); b.putLong(at + 40, size)
        }
        ph(64, 1, 0, bytes.size.toLong())
        val strings = "\u0000" + (soname?.plus("\u0000") ?: "") + (needed?.plus("\u0000") ?: "")
        strings.toByteArray().copyInto(bytes, 700)
        val tags = mutableListOf(5L to 0x4002bcL, 10L to strings.length.toLong())
        if (soname != null) tags += 14L to 1L
        if (needed != null) tags += 1L to (1 + (soname?.length?.plus(1) ?: 0)).toLong()
        tags += 0L to 0L
        ph(120, 2, 512, tags.size * 16L)
        tags.forEachIndexed { i, tag -> b.putLong(512 + i * 16, tag.first); b.putLong(520 + i * 16, tag.second) }
        if (interpreter) {
            val name = "/lib64/ld-linux-x86-64.so.2\u0000".toByteArray()
            name.copyInto(bytes, 900); ph(176, 3, 900, name.size.toLong())
        }
        return bytes
    }
    private fun payloads(): MutableMap<String, ByteArray> = linkedMapOf<String, ByteArray>().apply {
        AcpProviderDnsRuntimeProfiles.requiredElfPaths.forEach {
            put(it, elf(if (it == "jdk/bin/java") null else it.substringAfterLast('/'), it == "jdk/bin/java"))
        }
        put(loader, elf("ld-linux-x86-64.so.2"))
        put("jdk/lib/libextra.so", elf("libextra.so"))
        put("jdk/lib/resource.so", "ordinary data".toByteArray())
        put("jdk/lib/modules", ByteArray(20000) { 1 })
    }
    private fun candidate(payloads: Map<String, ByteArray>, extraEdges: List<AcpProviderDnsRuntimeEdge> = emptyList(),
        omit: Set<String> = emptySet(), totalLimit: Long = AcpProviderDnsRuntimeProfiles.MAXIMUM_BYTES): AcpProviderDnsRuntimeProfileCandidate {
        val files = payloads.map { (path, bytes) -> AcpProviderDnsRuntimeEntry(path, "file", "0644", bytes.size.toLong(), dnsSha(bytes)) }
        val objects = payloads.filterValues { it.size >= 4 && it.take(4) == listOf<Byte>(127, 69, 76, 70) }
        val edges = listOf(AcpProviderDnsRuntimeEdge("jdk/bin/java", "PT_INTERP", "/lib64/ld-linux-x86-64.so.2", loader)) +
            objects.keys.filter { it != "jdk/bin/java" && it != loader && it !in omit }.map {
                AcpProviderDnsRuntimeEdge("jdk/bin/java", "DLOPEN", it.substringAfterLast('/'), it)
            } + extraEdges
        return AcpProviderDnsRuntimeProfileCandidate("a".repeat(64), files.sumOf { it.size }, files, edges,
            mapOf("bytes" to totalLimit, "fileBytes" to AcpProviderDnsRuntimeProfiles.MAXIMUM_FILE_BYTES,
                "moduleBytes" to AcpProviderDnsRuntimeProfiles.MAXIMUM_MODULE_BYTES, "edges" to 256L))
    }
    private fun inspect(payloads: Map<String, ByteArray>, candidate: AcpProviderDnsRuntimeProfileCandidate = candidate(payloads)) =
        AcpProviderDnsRuntimeContentInspection.inspect(candidate) { ByteArrayInputStream(payloads.getValue(it.path)) }

    @Test fun `candidate limit aliases cannot change later content observations`() {
        val p = payloads(); val original = candidate(p)
        val supplied = original.contentLimits.toMutableMap()
        val frozen = AcpProviderDnsRuntimeProfileCandidate(original.manifestSha256, original.regularBytes,
            original.entries(), original.edges(), supplied)
        supplied["bytes"] = 1
        assertEquals(AcpProviderDnsRuntimeProfiles.MAXIMUM_BYTES, frozen.contentLimits.getValue("bytes"))
        assertFails { (frozen.contentLimits as MutableMap<String, Long>)["bytes"] = 1 }
        assertFails { (AcpProviderDnsRuntimeProfiles.requiredElfPaths as MutableSet<String>).clear() }
        assertTrue("jdk/bin/java" in AcpProviderDnsRuntimeProfiles.requiredElfPaths)
        assertTrue(inspect(p, frozen).objects.containsKey("jdk/bin/java"))
        val invalid = AcpProviderDnsRuntimeProfileCandidate(original.manifestSha256, original.regularBytes,
            original.entries(), original.edges(), supplied)
        assertFails { inspect(p, invalid) }
    }

    @Test fun `extra read only library and extensionless ELF are inspected while non ELF resources stream`() {
        val p = payloads(); p["jdk/lib/extensionless"] = elf("extensionless")
        val result = inspect(p)
        assertTrue("jdk/lib/libextra.so" in result.objects && "jdk/lib/extensionless" in result.objects)
        assertTrue("jdk/lib/resource.so" !in result.objects && "jdk/lib/modules" !in result.objects)
        assertFailsWith<AcpProviderDnsRuntimeUnavailableException> {
            AcpProviderDnsRuntimeProfiles.requireApproved(AcpProviderDnsRuntimeProfiles.PROFILE_ID, result.manifestSha256, "b".repeat(64))
        }
    }
    @Test fun `hidden objects missing graph and false ELF endpoints fail`() {
        val p = payloads(); p["jdk/lib/hidden"] = elf("hidden")
        assertFails { inspect(p, candidate(p, omit = setOf("jdk/lib/hidden"))) }
        val edge = AcpProviderDnsRuntimeEdge("jdk/bin/java", "DLOPEN", "resource.so", "jdk/lib/resource.so")
        assertFails { inspect(p, candidate(p, extraEdges = listOf(edge))) }
        p["jdk/lib/hidden"]!![18] = 3
        assertFails { inspect(p) }
    }
    @Test fun `actual needed records require exact provider edges and no spurious declarations`() {
        val p = payloads(); p["jdk/lib/libextra.so"] = elf("libextra.so", needed = "libnet.so")
        assertFails { inspect(p) }
        val actual = AcpProviderDnsRuntimeEdge("jdk/lib/libextra.so", "DT_NEEDED", "libnet.so", "jdk/lib/libnet.so")
        inspect(p, candidate(p, extraEdges = listOf(actual)))
        assertFails { inspect(p, candidate(p, extraEdges = listOf(actual.copy(name = "libjava.so", target = "jdk/lib/libjava.so")))) }
        p["jdk/lib/server/libnet.so"] = elf("libnet.so")
        assertFails { inspect(p, candidate(p, extraEdges = listOf(actual))) }
    }
    @Test fun `disconnected ELF cycles cannot manufacture launcher reachability`() {
        val p = payloads(); p["jdk/lib/one"] = elf("one"); p["jdk/lib/two"] = elf("two")
        val cycle = listOf(AcpProviderDnsRuntimeEdge("jdk/lib/one", "DLOPEN", "two", "jdk/lib/two"),
            AcpProviderDnsRuntimeEdge("jdk/lib/two", "DLOPEN", "one", "jdk/lib/one"))
        assertFails { inspect(p, candidate(p, cycle, setOf("jdk/lib/one", "jdk/lib/two"))) }
    }
    @Test fun `short positive reads preserve complete hash and thrown reads close input`() {
        val p = payloads(); var closed = 0
        val result = AcpProviderDnsRuntimeContentInspection.inspect(candidate(p)) { entry ->
            object : ByteArrayInputStream(p.getValue(entry.path)) {
                override fun read(bytes: ByteArray, offset: Int, length: Int): Int = super.read(bytes, offset, minOf(length, 1))
                override fun close() { closed++; super.close() }
            }
        }
        assertEquals(p.size, closed); assertTrue(result.objects.isNotEmpty())
        closed = 0
        assertFails { AcpProviderDnsRuntimeContentInspection.inspect(candidate(p)) {
            object : InputStream() {
                override fun read(): Int = throw java.io.IOException("inert failure")
                override fun close() { closed++ }
            }
        } }
        assertEquals(1, closed)
    }

    @Test fun `hash length EOF and stream failures close owned input`() {
        val p = payloads(); val c = candidate(p)
        var closed = 0
        assertFails {
            AcpProviderDnsRuntimeContentInspection.inspect(c) { entry ->
                object : ByteArrayInputStream(p.getValue(entry.path) + byteArrayOf(1)) {
                    override fun close() { closed++; super.close() }
                }
            }
        }
        assertEquals(1, closed)
        val changed = p.toMutableMap(); changed["jdk/lib/modules"] = ByteArray(20000) { 2 }
        assertFails { inspect(changed, c) }
        assertFails { AcpProviderDnsRuntimeContentInspection.inspect(c) { object : InputStream() { override fun read(): Int = -1 } } }
    }
    @Test fun `aggregate precharge refuses before any opener and ELF modules cannot bypass file ceiling`() {
        val p = payloads(); var opened = 0
        assertFails { AcpProviderDnsRuntimeContentInspection.inspect(candidate(p, totalLimit = 1)) { opened++; ByteArrayInputStream(byteArrayOf()) } }
        assertEquals(0, opened)
        val oversized = ByteArray(AcpProviderDnsRuntimeProfiles.MAXIMUM_FILE_BYTES.toInt() + 1)
        byteArrayOf(127, 69, 76, 70).copyInto(oversized); p["jdk/lib/modules"] = oversized
        assertFails { inspect(p) }
    }
}
