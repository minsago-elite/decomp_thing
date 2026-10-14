package decompengine.acp

import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Synthetic manifest/policy validation only: no packaged runtime, native execution or approval. */
class AcpProviderDnsRuntimeProfileTest {
    @Test fun `structural manifest preserves exact closed records without granting approval`() {
        val input = manifest()
        val parsed = parse(input)
        assertEquals(baseEntries().size, parsed.entries().size)
        assertEquals(baseEdges().size, parsed.edges().size)
        assertTrue(parsed.manifestSha256.matches(Regex("[0-9a-f]{64}")))
        assertFailsWith<AcpProviderDnsRuntimeUnavailableException> {
            AcpProviderDnsRuntimeProfiles.requireApproved(PROFILE, parsed.manifestSha256, SHA)
        }
        assertFailsWith<AcpProviderDnsRuntimeUnavailableException> {
            AcpProviderDnsRuntimeProfiles.requireApproved("unknown", "not-a-hash", "not-a-policy")
        }
    }

    @Test fun `unknown fields duplicate JSON and invalid encoding are rejected`() {
        assertFails { parse(change(manifest(), "ambientRuntime", JsonPrimitive("/usr/lib"))) }
        val text = manifest().toString().replaceFirst("{", "{\"schema\":\"duplicate\",")
        assertFails { AcpProviderDnsRuntimeProfiles.parseCandidate(text.toByteArray()) }
        assertFails { AcpProviderDnsRuntimeProfiles.parseCandidate(byteArrayOf(0xc0.toByte(), 0xaf.toByte())) }
        assertFails { AcpProviderDnsRuntimeProfiles.parseCandidate(ByteArray(1024 * 1024 + 1) { 32 }) }
    }

    @Test fun `wrong module ABI launcher worker identity or provenance is rejected`() {
        listOf("profileId" to "other", "architecture" to "aarch64", "abi" to "musl", "jdkModule" to "java.net",
            "workerSha256" to "unknown", "toolchainSha256" to "unapproved").forEach { (key, value) ->
            assertFails { parse(change(manifest(), key, JsonPrimitive(value))) }
        }
        assertFails { parse(change(manifest(), "jdkFeature", JsonPrimitive(25))) }
        val argv = manifest().getValue("loaderArgv").jsonArray.toMutableList().also { it[1] = JsonPrimitive("--help") }
        assertFails { parse(change(manifest(), "loaderArgv", JsonArray(argv))) }
        assertFails { parse(change(manifest(), "jdkModulesSha256", JsonPrimitive("b".repeat(64)))) }
    }

    @Test fun `links aliases escaping and ambiguous entry names are rejected structurally`() {
        listOf("symlink", "hardlink", "socket", "fifo").forEach { kind ->
            assertFails { parse(withEntry("jdk/lib/libjava.so", "kind", JsonPrimitive(kind))) }
        }
        listOf("/absolute", "jdk/../libjava.so", "jdk/./libjava.so", "jdk//libjava.so", "jdk/lib/white space").forEach { path ->
            assertFails { parse(withEntry("jdk/lib/libjava.so", "path", JsonPrimitive(path))) }
        }
        assertFails { parse(withEntries(baseEntries() + baseEntries().first())) }
        assertFails { parse(withEntries(baseEntries().reversed(), sort = false)) }
    }

    @Test fun `missing parents extra native files hooks and classes are rejected`() {
        assertFails { parse(withEntries(baseEntries().filterNot { it.text("path") == "jdk/conf" })) }
        assertFails { parse(withEntries(baseEntries().filterNot { it.text("path") == "jdk/lib/libjava.so" })) }
        listOf("native/libunknown.so", "jdk/lib/hook.jar", "jdk/lib/Hook.class", "jdk/lib/services/provider").forEach { path ->
            assertFails { parse(withEntries(baseEntries() + record(path))) }
        }
        assertFails { parse(withEntries(baseEntries() + record("jdk/bin/jspawnhelper", mode = "0755"))) }
    }

    @Test fun `ownership and permission policy rejects mixed writable and privileged records`() {
        listOf("0777", "0775", "4755", "2755", "1755", "0600", "0500").forEach { mode ->
            assertFails { parse(withEntry("jdk/bin/java", "mode", JsonPrimitive(mode))) }
        }
        assertFails { parse(withEntry("jdk/release", "owner", JsonPrimitive("service"))) }
        assertFails { parse(change(manifest(), "sourceOwner", buildJsonObject { put("policy", "root"); put("uid", 1000); put("gid", 0) })) }
        assertFails { parse(change(manifest(), "sourceOwner", buildJsonObject { put("policy", "service"); put("uid", 0); put("gid", 0) })) }
    }

    @Test fun `entry depth module file and total ceilings admit exact bound and reject one over`() {
        val extra = (0 until 2048 - baseEntries().size).map { record("jdk/lib/f$it") }
        assertEquals(2048, parse(withEntries(baseEntries() + extra)).entries().size)
        assertFails { parse(withEntries(baseEntries() + extra + record("jdk/lib/one-over"))) }
        val dirs = (1..14).map { depth -> record("jdk/" + List(depth) { "d" }.joinToString("/"), "directory") }
        val exactDepth = "jdk/" + List(14) { "d" }.joinToString("/") + "/f"
        parse(withEntries(baseEntries() + dirs + record(exactDepth)))
        assertFails { parse(withEntries(baseEntries() + dirs + record(exactDepth + "/f"))) }
        parse(withEntry("jdk/lib/modules", "size", JsonPrimitive(192L * 1024 * 1024)))
        assertFails { parse(withEntry("jdk/lib/modules", "size", JsonPrimitive(192L * 1024 * 1024 + 1))) }
        parse(withEntry("jdk/release", "size", JsonPrimitive(16L * 1024 * 1024)))
        assertFails { parse(withEntry("jdk/release", "size", JsonPrimitive(16L * 1024 * 1024 + 1))) }
        val large = baseEntries().map { record -> when (record.text("path")) {
            "jdk/lib/modules" -> change(record, "size", JsonPrimitive(192L * 1024 * 1024 - (baseEntries().count { it.text("kind") == "file" } - 5)))
            "jdk/release", "jdk/conf/net.properties", "jdk/conf/security/java.security", "jdk/legal/java.base/LICENSE" ->
                change(record, "size", JsonPrimitive(16L * 1024 * 1024))
            else -> record
        } }
        assertEquals(256L * 1024 * 1024, parse(withEntries(large)).regularBytes)
        assertFails { parse(withEntries(large.map { if (it.text("path") == "jdk/lib/modules") change(it, "size", JsonPrimitive(it.getValue("size").jsonPrimitive.long + 1)) else it })) }
    }

    @Test fun `dependency closure rejects missing targets duplicate names cycles without reachability and extra edges`() {
        assertFails { parse(change(manifest(), "elfEdges", JsonArray(baseEdges().drop(1)))) }
        assertFails { parse(change(manifest(), "elfEdges", JsonArray(baseEdges() + baseEdges().first()))) }
        assertFails { parse(change(manifest(), "elfEdges", JsonArray(baseEdges().mapIndexed { i, edge -> if (i == 0) change(edge, "target", JsonPrimitive("native/missing")) else edge }))) }
        assertFails { parse(change(manifest(), "elfEdges", JsonArray(baseEdges().map { if (it.text("target") == "jdk/lib/libjava.so") change(it, "from", JsonPrimitive("jdk/lib/libjava.so")) else it }))) }
        assertFails { parse(change(manifest(), "limits", change(manifest().getValue("limits").jsonObject, "edges", JsonPrimitive(257)))) }
    }

    @Test fun `resolver serialization is exact defensive and domain bound`() {
        val bytes = "nameserver 192.0.2.53\nnameserver 2001:db8::53\noptions timeout:5 attempts:2\n".toByteArray()
        val original = bytes.copyOf()
        val parsed = resolver(bytes)
        bytes[0] = 0
        assertContentEquals(original, parsed.resolvConf())
        val exposed = parsed.resolvConf(); exposed[0] = 0
        assertContentEquals(original, parsed.resolvConf())
        assertTrue(parsed.sha256 != resolver("nameserver 192.0.2.54\n".toByteArray()).sha256)
    }

    @Test fun `canonical numeric IPv4 IPv6 and mapped IPv6 are accepted without name lookup`() {
        listOf("0.0.0.0", "255.255.255.255", "::", "::1", "2001:db8::1", "2001:db8::1:0:0:1",
            "2001:db8:0:1:1:1:1:1", "::ffff:192.0.2.1").forEach { resolver("nameserver $it\n".toByteArray()) }
        listOf("example.com", "127.1", "01.2.3.4", "256.0.0.1", "[::1]", "fe80::1%eth0", "2001:DB8::1",
            "2001:0db8::1", "2001:db8:0:0:1::1", "2001:db8::1:1:1:1:1", "::ffff:c000:201", "::1:53:port").forEach {
            assertFails { resolver("nameserver $it\n".toByteArray()) }
        }
    }

    @Test fun `duplicate resolvers unsupported options directives and whitespace are rejected`() {
        listOf("nameserver 192.0.2.1\nnameserver 192.0.2.1\n", "nameserver 192.0.2.1\nnameserver 192.0.2.2\nnameserver 192.0.2.3\nnameserver 192.0.2.4\n",
            "options timeout:1 attempts:1\n", "nameserver 192.0.2.1\noptions attempts:1 timeout:1\n",
            "nameserver 192.0.2.1\noptions timeout:0 attempts:1\n", "nameserver 192.0.2.1\noptions timeout:5 attempts:3\n",
            "nameserver  192.0.2.1\n", "nameserver 192.0.2.1 \n", "nameserver\t192.0.2.1\n",
            "nameserver 192.0.2.1\r\n", "nameserver 192.0.2.1", "nameserver 192.0.2.1\n\n").forEach { assertFails { resolver(it.toByteArray()) } }
        listOf("search example.com", "domain example.com", "sortlist 192.0.2.1", "include other", "# comment",
            "options rotate", "options ndots:0", "options trust-ad", "options edns0").forEach {
            assertFails { resolver("nameserver 192.0.2.1\n$it\n".toByteArray()) }
        }
    }

    @Test fun `resolver caps encodings and exact hosts nsswitch bytes reject changed input`() {
        listOf(4096, 4097).forEach { assertFails { resolver(ByteArray(it) { 10 }) } }
        listOf(256, 257).forEach { assertFails { resolver(("x".repeat(it) + "\n").toByteArray()) } }
        listOf(32, 33).forEach { assertFails { resolver("nameserver 192.0.2.1\n".repeat(it).toByteArray()) } }
        assertFails { resolver(byteArrayOf(0, 10)) }
        assertFails { resolver(byteArrayOf(0xc3.toByte(), 0xa9.toByte(), 10)) }
        val resolv = "nameserver 192.0.2.1\n".toByteArray()
        assertFails { AcpProviderDnsResolverCandidate.parseForValidation(resolv, "hosts: files dns [NOTFOUND=return]\n".toByteArray(), HOSTS.toByteArray()) }
        assertFails { AcpProviderDnsResolverCandidate.parseForValidation(resolv, SWITCH.toByteArray(), (HOSTS + "192.0.2.1 chatgpt.com\n").toByteArray()) }
        assertFails { AcpProviderDnsResolverCandidate.parseForValidation(resolv, ByteArray(65) { 32 }, HOSTS.toByteArray()) }
        assertFails { AcpProviderDnsResolverCandidate.parseForValidation(resolv, SWITCH.toByteArray(), ByteArray(129) { 32 }) }
    }

    companion object {
        private const val SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        private const val PROFILE = "linux-x86_64-jdk21-dns-v1"
        private const val SWITCH = "hosts: files dns\n"
        private const val HOSTS = "127.0.0.1 localhost\n::1 localhost\n"
        private val files = listOf("jdk/bin/java", "jdk/release", "jdk/lib/modules", "jdk/lib/libjava.so", "jdk/lib/libjimage.so",
            "jdk/lib/libjli.so", "jdk/lib/libnet.so", "jdk/lib/libnio.so", "jdk/lib/libverify.so", "jdk/lib/libzip.so",
            "jdk/lib/server/libjvm.so", "jdk/conf/net.properties", "jdk/conf/security/java.security", "jdk/legal/java.base/LICENSE",
            "native/ld-linux-x86-64.so.2", "native/libc.so.6")
        private fun record(path: String, kind: String = "file", mode: String = if (kind == "directory" || path in setOf("jdk/bin/java", "native/ld-linux-x86-64.so.2")) "0755" else "0644") = buildJsonObject {
            put("path", path); put("kind", kind); put("mode", mode); put("owner", "root"); put("size", if (kind == "directory") 0 else 1)
            put("sha256", if (kind == "directory") JsonNull else JsonPrimitive(SHA))
        }
        private fun baseEntries(): List<JsonObject> = (files.flatMap { file ->
            val parts = file.split('/'); (1 until parts.size).map { record(parts.take(it).joinToString("/"), "directory") }
        }.distinctBy { it.text("path") } + files.map { record(it) }).sortedBy { it.text("path") }
        private fun baseEdges(): List<JsonObject> = files.filter { it.startsWith("native/") || it.endsWith(".so") }.map { target -> buildJsonObject {
            put("from", "jdk/bin/java"); put("target", target)
            put("kind", if (target == "native/ld-linux-x86-64.so.2") "PT_INTERP" else "DLOPEN")
            put("name", if (target == "native/ld-linux-x86-64.so.2") "/lib64/ld-linux-x86-64.so.2" else target.substringAfterLast('/'))
        } }
        private fun manifest(): JsonObject = buildJsonObject {
            put("schema", "provider-dns-runtime-profile-v1"); put("profileId", PROFILE); put("architecture", "x86_64"); put("abi", "linux-glibc-x86_64")
            put("jdkFeature", 21); put("jdkModule", "java.base")
            listOf("applicationBuildSha256", "jdkReleaseSha256", "jdkModulesSha256", "sourceArchiveSha256", "toolchainSha256", "recipeSha256", "workerSha256").forEach { put(it, SHA) }
            putJsonObject("sourceOwner") { put("policy", "root"); put("uid", 0); put("gid", 0) }
            putJsonObject("limits") { put("entries", 2048); put("depth", 16); put("bytes", 256L * 1024 * 1024); put("fileBytes", 16L * 1024 * 1024); put("moduleBytes", 192L * 1024 * 1024); put("edges", 256); put("nativeLibraries", 32) }
            put("entries", JsonArray(baseEntries())); put("elfEdges", JsonArray(baseEdges()))
            put("loaderArgv", JsonArray(listOf("/provider-dns-runtime/native/ld-linux-x86-64.so.2", "--inhibit-cache", "--library-path",
                "/provider-dns-runtime/native:/provider-dns-runtime/jdk/lib:/provider-dns-runtime/jdk/lib/server", "/provider-dns-runtime/jdk/bin/java").map(::JsonPrimitive)))
        }
        private fun change(value: JsonObject, key: String, item: JsonElement) = JsonObject(value.toMutableMap().also { it[key] = item })
        private fun withEntries(entries: List<JsonObject>, sort: Boolean = true) = change(manifest(), "entries", JsonArray(if (sort) entries.sortedBy { it.text("path") } else entries))
        private fun withEntry(path: String, key: String, value: JsonElement) = withEntries(baseEntries().map { if (it.text("path") == path) change(it, key, value) else it })
        private fun parse(document: JsonObject) = AcpProviderDnsRuntimeProfiles.parseCandidate(document.toString().toByteArray())
        private fun resolver(bytes: ByteArray) = AcpProviderDnsResolverCandidate.parseForValidation(bytes, SWITCH.toByteArray(), HOSTS.toByteArray())
        private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    }
}
