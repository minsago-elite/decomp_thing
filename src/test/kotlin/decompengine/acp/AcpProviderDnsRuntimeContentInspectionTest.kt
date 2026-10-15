package decompengine.acp

import kotlinx.serialization.json.*
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
    private fun elf(soname: String? = null, interpreter: Boolean = false, needed: String? = null,
        extraDynamicTags: List<Pair<Long, Long>> = emptyList()): ByteArray {
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
        tags += extraDynamicTags
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

    private fun manifestPayloads(): MutableMap<String, ByteArray> = payloads().apply {
        put("native/libc.so.6", elf("libc.so.6"))
        listOf("jdk/release", "jdk/conf/net.properties", "jdk/conf/security/java.security", "jdk/legal/java.base/LICENSE")
            .forEach { put(it, "inert data".toByteArray()) }
    }
    private fun manifest(p: Map<String, ByteArray>, omit: Set<String> = emptySet()): ByteArray {
        val files = p.keys.map { path -> buildJsonObject {
            put("path", path); put("kind", "file"); put("mode", if (path == "jdk/bin/java" || path == loader) "0755" else "0644")
            put("owner", "root"); put("size", p.getValue(path).size); put("sha256", dnsSha(p.getValue(path)))
        } }
        val directories = p.keys.flatMap { path -> val parts = path.split('/');
            (1 until parts.size).map { parts.take(it).joinToString("/") } }.distinct().map { path -> buildJsonObject {
            put("path", path); put("kind", "directory"); put("mode", "0755"); put("owner", "root"); put("size", 0); put("sha256", JsonNull)
        } }
        return buildJsonObject {
            put("schema", "provider-dns-runtime-profile-v1"); put("profileId", AcpProviderDnsRuntimeProfiles.PROFILE_ID)
            put("architecture", "x86_64"); put("abi", "linux-glibc-x86_64"); put("jdkFeature", 21); put("jdkModule", "java.base")
            listOf("applicationBuildSha256", "sourceArchiveSha256", "toolchainSha256", "recipeSha256", "workerSha256")
                .forEach { put(it, "a".repeat(64)) }
            put("jdkReleaseSha256", dnsSha(p.getValue("jdk/release"))); put("jdkModulesSha256", dnsSha(p.getValue("jdk/lib/modules")))
            putJsonObject("sourceOwner") { put("policy", "root"); put("uid", 0); put("gid", 0) }
            putJsonObject("limits") {
                put("entries", 2048); put("depth", 16); put("bytes", 256L * 1024 * 1024)
                put("fileBytes", 16L * 1024 * 1024); put("moduleBytes", 192L * 1024 * 1024); put("edges", 256); put("nativeLibraries", 32)
            }
            put("entries", JsonArray((directories + files).sortedBy { it.getValue("path").jsonPrimitive.content }))
            put("elfEdges", JsonArray(candidate(p, omit = omit).edges().map { edge -> buildJsonObject {
                put("from", edge.from); put("kind", edge.kind); put("name", edge.name); put("target", edge.target)
            } }))
            val root = AcpProviderDnsRuntimeProfiles.ROOT
            put("loaderArgv", JsonArray(listOf("$root/native/ld-linux-x86-64.so.2", "--inhibit-cache", "--library-path",
                "$root/native:$root/jdk/lib:$root/jdk/lib/server", "$root/jdk/bin/java").map(::JsonPrimitive)))
        }.toString().toByteArray()
    }
    @Test fun `every writable executable load is refused independently of read permission`() {
        for (flags in listOf(3, 7)) {
            val objectBytes = elf("libextra.so").also { ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putInt(68, flags) }
            assertFails { AcpProviderDnsElfInspection.inspect(objectBytes) }
            val p = payloads().apply { put("jdk/lib/libextra.so", objectBytes) }
            assertFails { inspect(p) }
        }
        for (flags in listOf(0, 1, 2, 4, 5, 6)) {
            val objectBytes = elf("libextra.so").also { ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putInt(68, flags) }
            assertEquals("libextra.so", AcpProviderDnsElfInspection.inspect(objectBytes).soname)
        }
    }

    @Test fun `SONAME dependency providers must be ET_DYN while both launcher types remain admissible`() {
        for (type in listOf(2, 3)) {
            val p = payloads().apply { put("jdk/bin/java", elf(interpreter = true).also {
                ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putShort(16, type.toShort())
            }) }
            assertTrue(inspect(p).objects.containsKey("jdk/bin/java"))
        }
        val provider = elf("libextra.so")
        assertEquals("libextra.so", AcpProviderDnsElfInspection.inspect(provider).soname)
        val p = payloads().apply { put("jdk/lib/libextra.so", provider) }
        assertTrue(inspect(p).objects.containsKey("jdk/lib/libextra.so"))
        val executableProvider = provider.copyOf().also { ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putShort(16, 2) }
        assertFails { AcpProviderDnsElfInspection.inspect(executableProvider) }
        // Matching path, SONAME and graph edges cannot turn an executable into a provider.
        p["jdk/lib/libextra.so"] = executableProvider
        assertFails { inspect(p) }
    }

    @Test fun `DT_TEXTREL presence and DF_TEXTREL each refuse text relocations`() {
        for (value in listOf(0L, 1L)) {
            val objectBytes = elf("libextra.so", extraDynamicTags = listOf(22L to value, 30L to 0L))
            assertFails { AcpProviderDnsElfInspection.inspect(objectBytes) }
            val p = payloads().apply { put("jdk/lib/libextra.so", objectBytes) }
            assertFails { inspect(p) }
        }
        assertFails { AcpProviderDnsElfInspection.inspect(elf("libextra.so", extraDynamicTags = listOf(30L to 4L))) }
        assertEquals("libextra.so", AcpProviderDnsElfInspection.inspect(elf("libextra.so", extraDynamicTags = listOf(30L to 0L))).soname)
    }

    @Test fun `composed parsed manifest ingress inspects all payloads and binds supported extra library`() {
        val p = manifestPayloads(); val bytes = manifest(p); val opened = mutableSetOf<String>()
        assertFails { AcpProviderDnsRuntimeProfiles.validateCandidate("{}".toByteArray()) {
            opened += it.path; ByteArrayInputStream(byteArrayOf())
        } }
        assertTrue(opened.isEmpty())
        val checked = AcpProviderDnsRuntimeProfiles.validateCandidate(bytes) { entry ->
            assertTrue(opened.add(entry.path)); ByteArrayInputStream(p.getValue(entry.path))
        }
        assertEquals(p.keys, opened); assertEquals(dnsSha(bytes), checked.manifestSha256)
        assertEquals(dnsSha(p.getValue("jdk/lib/libextra.so")), checked.objects().getValue("jdk/lib/libextra.so").sha256)
        assertFailsWith<AcpProviderDnsRuntimeUnavailableException> {
            AcpProviderDnsRuntimeProfiles.requireApproved(AcpProviderDnsRuntimeProfiles.PROFILE_ID, checked.manifestSha256, "b".repeat(64))
        }
    }
    @Test fun `composed ingress refuses hidden extensionless ELF omitted from declared closure`() {
        val p = manifestPayloads(); p["jdk/lib/hidden"] = elf("hidden")
        val bytes = manifest(p, omit = setOf("jdk/lib/hidden"))
        // Structural admission cannot establish the actual content inventory.
        assertTrue(AcpProviderDnsRuntimeProfiles.parseCandidate(bytes).entries().any { it.path == "jdk/lib/hidden" })
        assertFails { AcpProviderDnsRuntimeProfiles.validateCandidate(bytes) { ByteArrayInputStream(p.getValue(it.path)) } }
        // An opener returning an unlisted replacement cannot substitute its bytes for a committed entry.
        val clean = manifestPayloads()
        assertFails { AcpProviderDnsRuntimeProfiles.validateCandidate(manifest(clean)) {
            ByteArrayInputStream(if (it.path == "jdk/lib/resource.so") p.getValue("jdk/lib/hidden") else clean.getValue(it.path))
        } }
    }

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
