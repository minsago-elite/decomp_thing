package decompengine.acp

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.GZIPOutputStream
import kotlinx.serialization.json.*
import kotlin.test.*

class AcpProviderDnsBuildInputTest {
    private data class Entry(val path: String, val data: ByteArray = byteArrayOf(), val type: Char = '0', val target: String = "")
    private data class Graph(val index: ByteArray, val blobs: Map<String, ByteArray>, val layers: List<ByteArray>) {
        fun inspect(limits: AcpProviderDnsBuildInputs.Limits = AcpProviderDnsBuildInputs.Limits()) =
            AcpProviderDnsBuildInputs.inspectGraph(index, { digest ->
                object : ByteArrayInputStream(blobs.getValue(digest)) {
                    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                        require(length <= 65536)
                        return super.read(bytes, offset, minOf(length, 97))
                    }
                }
            }, limits)
    }
    private fun bytes(value: JsonElement) = value.toString().toByteArray()
    private fun descriptor(value: ByteArray, media: String) = buildJsonObject {
        put("mediaType", media); put("digest", "sha256:" + dnsSha(value)); put("size", value.size)
    }
    private fun graph(vararg rawLayers: ByteArray, gzip: Boolean = false, encodedTransform: (ByteArray) -> ByteArray = { it },
        configTransform: (JsonObject) -> JsonObject = { it }, manifestTransform: (JsonObject) -> JsonObject = { it }, transform: (JsonObject) -> JsonObject = { it }): Graph {
        val encoded = rawLayers.map { raw -> if (!gzip) raw else ByteArrayOutputStream().also { out -> GZIPOutputStream(out).use { it.write(raw) } }.toByteArray() }.map(encodedTransform)
        val config = bytes(configTransform(buildJsonObject {
            put("architecture", "amd64"); put("os", "linux")
            putJsonObject("rootfs") { put("type", "layers"); put("diff_ids", JsonArray(rawLayers.map { JsonPrimitive("sha256:" + dnsSha(it)) })) }
        }))
        val manifest = bytes(manifestTransform(buildJsonObject {
            put("schemaVersion", 2); put("mediaType", AcpProviderDnsBuildInputs.MANIFEST)
            put("config", descriptor(config, AcpProviderDnsBuildInputs.CONFIG))
            put("layers", JsonArray(encoded.map { descriptor(it, if (gzip) AcpProviderDnsBuildInputs.GZIP else AcpProviderDnsBuildInputs.TAR) }))
        }))
        val child = descriptor(manifest, AcpProviderDnsBuildInputs.MANIFEST).toMutableMap().also { it["platform"] = buildJsonObject { put("os", "linux"); put("architecture", "amd64") } }
        val index = bytes(transform(buildJsonObject { put("schemaVersion", 2); put("mediaType", AcpProviderDnsBuildInputs.INDEX); put("manifests", JsonArray(listOf(JsonObject(child)))) }))
        return Graph(index, (encoded + listOf(config, manifest)).associateBy { "sha256:" + dnsSha(it) }, rawLayers.toList())
    }
    private fun tar(vararg entries: Entry): ByteArray = ByteArrayOutputStream().also { output ->
        entries.forEach { entry ->
            val header = ByteArray(512)
            fun text(at: Int, length: Int, value: String) { val data = value.toByteArray(); require(data.size < length); data.copyInto(header, at) }
            fun octal(at: Int, length: Int, value: Long) = text(at, length, value.toString(8).padStart(length - 1, '0'))
            text(0, 100, entry.path); octal(100, 8, if (entry.type == '5') 493 else 420)
            octal(108, 8, 0); octal(116, 8, 0); octal(124, 12, entry.data.size.toLong()); octal(136, 12, 0)
            (148..155).forEach { header[it] = 32 }; header[156] = entry.type.code.toByte()
            text(157, 100, entry.target); "ustar\u0000".toByteArray().copyInto(header, 257); "00".toByteArray().copyInto(header, 263)
            octal(148, 8, header.sumOf { it.toInt() and 255 }.toLong())
            output.write(header); output.write(entry.data)
            output.write(ByteArray((512 - entry.data.size % 512) % 512))
        }
        output.write(ByteArray(1024))
    }.toByteArray()

    @Test fun `regular payload coordinates refer to exact streamed layer bytes and never host paths`() {
        val body = "jdk-payload".toByteArray(); val g = graph(tar(Entry("opt", type = '5'), Entry("opt/java", body)), gzip = true)
        val result = g.inspect(); val coordinate = result.selectRegular("opt/java", "jdk/bin/java")
        assertEquals(1024L, coordinate.contentOffset); assertEquals(body.size.toLong(), coordinate.size)
        assertEquals(dnsSha(body), coordinate.sha256); assertEquals(1, result.layers.size)
        assertEquals(g.layers.single().size.toLong(), result.expandedBytes)
        assertFails { AcpProviderDnsBuildInputs.inspectPinned(g.index, { g.blobs.getValue(it).inputStream() }) }
        assertFails { result.selectRegular("opt", "jdk/bin/java") }
        assertFails { result.selectRegular("opt/java", "../../host") }
        assertFails { (result.members as MutableMap).clear() }
    }
    @Test fun `ordinary and opaque whiteouts remove lower objects but preserve current layer additions regardless order`() {
        val result = graph(tar(Entry("tree", type = '5'), Entry("tree/old", byteArrayOf(1)), Entry("gone", byteArrayOf(2))),
            tar(Entry("tree/new", byteArrayOf(3)), Entry("tree/.wh..wh..opq"), Entry(".wh.gone"))).inspect()
        assertEquals(setOf("tree", "tree/new"), result.members.keys)
        assertEquals(dnsSha(byteArrayOf(3)), result.members.getValue("tree/new").sha256)
    }
    @Test fun `directory and regular replacement are explicit virtual type transitions`() {
        val result = graph(tar(Entry("one", type = '5'), Entry("one/child", byteArrayOf(1)), Entry("two", byteArrayOf(2))),
            tar(Entry("one", byteArrayOf(3)), Entry("two", type = '5'), Entry("two/child", byteArrayOf(4)))).inspect()
        assertEquals(setOf("one", "two", "two/child"), result.members.keys)
        assertEquals(AcpProviderDnsBuildInputs.Kind.REGULAR, result.members.getValue("one").kind)
        assertFails { graph(tar(Entry("same/child", byteArrayOf(1)), Entry("same", byteArrayOf(2)))).inspect() }
    }
    @Test fun `links remain recorded objects and cannot supply regular payload or parent traversal`() {
        val result = graph(tar(Entry("real", byteArrayOf(1)), Entry("symbolic", type = '2', target = "/real"), Entry("hard", type = '1', target = "real"))).inspect()
        assertEquals("/real", result.members.getValue("symbolic").linkTarget)
        for (path in listOf("symbolic", "hard")) assertFails { result.selectRegular(path, "native/libc.so.6") }
        assertFails { graph(tar(Entry("link", type = '2', target = "real"), Entry("link/child", byteArrayOf(1)))).inspect() }
    }
    @Test fun `path escapes duplicate members unknown operations and ambiguous whiteouts are refused`() {
        for (path in listOf("/absolute", "../escape", "a/../escape", "./relative", "a//b", "a\\b"))
            assertFails { graph(tar(Entry(path))).inspect() }
        assertFails { graph(tar(Entry("same"), Entry("same"))).inspect() }
        for (type in listOf('3', '4', '6', 'x', 'g', 'L', 'K')) assertFails { graph(tar(Entry("unknown", type = type))).inspect() }
        assertFails { graph(tar(Entry(".wh."))).inspect() }
        assertFails { graph(tar(Entry(".wh.x", byteArrayOf(1)))).inspect() }
    }
    @Test fun `hash mismatch descriptor size diffID and platform ambiguity cannot be ignored`() {
        val g = graph(tar(Entry("file", byteArrayOf(1))))
        assertFails { AcpProviderDnsBuildInputs.inspectGraph(g.index, { g.blobs.getValue(it).copyOf().also { b -> b[0] = (b[0].toInt() xor 1).toByte() }.inputStream() }) }
        assertFails { graph(tar(Entry("file"))) { index -> JsonObject(index + ("manifests" to JsonArray(index.getValue("manifests").jsonArray + index.getValue("manifests").jsonArray))) }.inspect() }
        val missing = graph(tar(Entry("file"))) { index ->
            val child = index.getValue("manifests").jsonArray.single().jsonObject
            JsonObject(index + ("manifests" to JsonArray(listOf(JsonObject(child + ("platform" to buildJsonObject { put("os", "linux"); put("architecture", "arm64") }))))))
        }
        assertFails { missing.inspect() }
    }
    @Test fun `all stream and metadata ceilings reject one over without truncation`() {
        val raw = tar(Entry("file", byteArrayOf(1, 2))); val g = graph(raw)
        assertEquals(raw.size.toLong(), g.inspect(AcpProviderDnsBuildInputs.Limits(expanded = raw.size.toLong(), layerExpanded = raw.size.toLong(), member = 2, entries = 1)).expandedBytes)
        assertFails { g.inspect(AcpProviderDnsBuildInputs.Limits(expanded = raw.size - 1L)) }
        assertFails { g.inspect(AcpProviderDnsBuildInputs.Limits(layerExpanded = raw.size - 1L)) }
        assertFails { g.inspect(AcpProviderDnsBuildInputs.Limits(compressed = raw.size - 1L)) }
        assertFails { g.inspect(AcpProviderDnsBuildInputs.Limits(layerCompressed = raw.size - 1L)) }
        assertFails { g.inspect(AcpProviderDnsBuildInputs.Limits(member = 1)) }
        assertFails { g.inspect(AcpProviderDnsBuildInputs.Limits(metadata = g.index.size.toLong())) }
        assertFails { graph(tar(Entry("first"), Entry("second"))).inspect(AcpProviderDnsBuildInputs.Limits(entries = 1)) }
        assertFails { AcpProviderDnsBuildInputs.Limits(member = AcpProviderDnsBuildInputs.MEMBER_BYTES + 1) }
    }
    @Test fun `gzip checksum concatenation trailing garbage and tar truncation are refused`() {
        val raw = tar(Entry("file", byteArrayOf(1))); val g = graph(raw, gzip = true)
        assertEquals(1, g.inspect().members.size)
        // Descriptor-preserving mutations fail hashing; raw tar structural mutations have fresh correct descriptors.
        assertFails { graph(raw.copyOf(raw.size - 513)).inspect() }
        assertFails { graph(raw.copyOf().also { it[0] = 0 }).inspect() }
        assertFails { graph(raw + byteArrayOf(1)).inspect() }
        assertFails { graph(raw, gzip = true, encodedTransform = { it + byteArrayOf(1) }).inspect() }
        assertFails { graph(raw, gzip = true, encodedTransform = { it + it }).inspect() }
        assertFails { graph(raw, gzip = true, encodedTransform = { it.copyOf().also { b -> b[b.size - 8] = (b[b.size - 8].toInt() xor 1).toByte() } }).inspect() }
    }

    @Test fun `inspection cancellation closes the current blob and never publishes a partial map`() {
        val g = graph(tar(Entry("file", ByteArray(1024))))
        var opened = 0; var closed = 0; var checks = 0
        assertFailsWith<IllegalStateException> {
            AcpProviderDnsBuildInputs.inspectGraph(g.index, { digest ->
                opened++
                object : ByteArrayInputStream(g.blobs.getValue(digest)) {
                    override fun close() { closed++; super.close() }
                }
            }, checkpoint = { if (++checks == 15) throw IllegalStateException("inert cancellation") })
        }
        assertTrue(opened > 0); assertEquals(opened, closed)
    }
    @Test fun `root metadata is independently copied and virtual opaque parents remain explicit unknown metadata`() {
        val g = graph(tar(Entry("new/.wh..wh..opq")))
        val original = g.index.copyOf()
        var once = false
        val observation = AcpProviderDnsBuildInputs.inspectGraph(g.index, { digest ->
            if (!once) { once = true; g.index.fill(0) }
            g.blobs.getValue(digest).inputStream()
        })
        assertEquals("sha256:" + dnsSha(original), observation.indexDigest)
        assertEquals(setOf("new"), observation.members.keys)
        assertFalse(observation.members.getValue("new").explicitMetadata)
        assertFails { observation.selectRegular("new", "jdk/bin/java") }
    }
    @Test fun `layer counts path depth member map size and strict JSON duplicates have independent ceilings`() {
        assertFails { graph(*(0..32).map { tar(Entry("file")) }.toTypedArray()).inspect() }
        assertFails { graph(tar(Entry((1..33).joinToString("/") { "x" }))).inspect() }
        assertFails { graph(tar(Entry("one/two/three"))).inspect(AcpProviderDnsBuildInputs.Limits(entries = 2)) }
        assertFails { AcpProviderDnsBuildInputs.inspectGraph("{\"schemaVersion\":2,\"schemaVersion\":2}".toByteArray(), { error("no blobs") }) }
        assertFails { AcpProviderDnsBuildInputs.inspectGraph(ByteArray(1048577), { error("no blobs") }) }
    }

    @Test fun `descriptor budget includes the root index and ELF mappings remain resource bounded`() {
        val g = graph(tar(Entry("file"))) { index ->
            val selected = index.getValue("manifests").jsonArray.single().jsonObject
            val others = (1..127).map { number -> JsonObject(selected + mapOf(
                "digest" to JsonPrimitive("sha256:" + number.toString(16).padStart(64, '0')),
                "platform" to buildJsonObject { put("os", "linux"); put("architecture", "arm64") })) }
            JsonObject(index + ("manifests" to JsonArray(others + selected)))
        }
        assertFails { g.inspect() }
        for (mutation in listOf<(ByteBuffer) -> Unit>(
            { it.putLong(104, 268435457) }, { it.putLong(112, 3) }, { it.putInt(68, 7) })) {
            assertFails { AcpProviderDnsElfInspection.inspect(elf().also { mutation(ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN)) }) }
        }
    }

    @Test fun `metadata exhausted by root is refused before manifest provider open or read`() {
        val g = graph(tar(Entry("file", byteArrayOf(1))))
        var opens = 0; var reads = 0
        assertFails { AcpProviderDnsBuildInputs.inspectGraph(g.index, { digest ->
            opens++; object : ByteArrayInputStream(g.blobs.getValue(digest)) {
                override fun read(bytes: ByteArray, offset: Int, length: Int): Int { reads++; return super.read(bytes, offset, length) }
            }
        }, AcpProviderDnsBuildInputs.Limits(metadata = g.index.size.toLong())) }
        assertEquals(0, opens); assertEquals(0, reads)
    }
    @Test fun `metadata one byte short reserves no descriptor while exact remaining metadata succeeds`() {
        val g = graph(tar(Entry("file", byteArrayOf(1))))
        val child = Json.parseToJsonElement(g.index.toString(Charsets.UTF_8)).jsonObject.getValue("manifests").jsonArray.single().jsonObject
        val manifestSize = child.dnsLong("size")
        var opens = 0; var reads = 0; var closes = 0
        fun provider(digest: String): ByteArrayInputStream {
            opens++
            return object : ByteArrayInputStream(g.blobs.getValue(digest)) {
                override fun read(bytes: ByteArray, offset: Int, length: Int): Int { reads++; return super.read(bytes, offset, length) }
                override fun close() { closes++; super.close() }
            }
        }
        assertFails { AcpProviderDnsBuildInputs.inspectGraph(g.index, ::provider,
            AcpProviderDnsBuildInputs.Limits(metadata = g.index.size + manifestSize - 1)) }
        assertEquals(0, opens); assertEquals(0, reads); assertEquals(0, closes)
        val manifest = Json.parseToJsonElement(g.blobs.getValue(child.dnsDigest("digest")).toString(Charsets.UTF_8)).jsonObject
        val metadataSize = g.index.size + manifestSize + manifest.getValue("config").jsonObject.dnsLong("size")
        assertEquals(1, AcpProviderDnsBuildInputs.inspectGraph(g.index, ::provider,
            AcpProviderDnsBuildInputs.Limits(metadata = metadataSize)).members.size)
        assertEquals(3, opens); assertEquals(opens, closes)
    }
    @Test fun `remaining metadata rejects config before open and closes admitted manifest`() {
        val g = graph(tar(Entry("file", byteArrayOf(1))))
        val child = Json.parseToJsonElement(g.index.toString(Charsets.UTF_8)).jsonObject.getValue("manifests").jsonArray.single().jsonObject
        var opens = 0; var closes = 0
        assertFails { AcpProviderDnsBuildInputs.inspectGraph(g.index, { digest ->
            opens++; object : ByteArrayInputStream(g.blobs.getValue(digest)) { override fun close() { closes++; super.close() } }
        }, AcpProviderDnsBuildInputs.Limits(metadata = g.index.size + child.dnsLong("size"))) }
        assertEquals(1, opens); assertEquals(1, closes)
    }

    private fun lockDocument() = buildJsonObject {
        put("schema", "provider-dns-build-input-v1"); put("family", AcpProviderDnsBuildInputs.FAMILY)
        fun d(media: String, hash: String) = buildJsonObject { put("mediaType", media); put("digest", "sha256:$hash"); put("size", 1024) }
        put("index", d(AcpProviderDnsBuildInputs.INDEX, AcpProviderDnsBuildInputs.FAMILY.substringAfter("sha256:")))
        put("indexChildren", JsonArray(listOf(d(AcpProviderDnsBuildInputs.MANIFEST, "1".repeat(64)))))
        put("manifest", d(AcpProviderDnsBuildInputs.MANIFEST, "1".repeat(64))); put("config", d(AcpProviderDnsBuildInputs.CONFIG, "2".repeat(64)))
        putJsonArray("layers") { add(buildJsonObject { put("descriptor", d(AcpProviderDnsBuildInputs.TAR, "3".repeat(64))); put("diffId", "sha256:" + "4".repeat(64)) }) }
        putJsonArray("payloads") { add(buildJsonObject {
            put("path", "opt/java"); put("layerDigest", "sha256:" + "3".repeat(64)); put("diffId", "sha256:" + "4".repeat(64))
            put("contentOffset", 512); put("size", 10); put("sha256", "5".repeat(64)); put("destination", "jdk/bin/java")
            put("mode", 493); put("uid", 0); put("gid", 0)
        }) }
        val tools = JsonArray(listOf("opt/jdk/bin/jlink", "opt/jdk/jmods/java.base.jmod").map { path -> buildJsonObject {
            put("path", path); put("kind", "REGULAR"); put("layerDigest", "sha256:" + "3".repeat(64)); put("diffId", "sha256:" + "4".repeat(64))
            put("contentOffset", 512); put("size", 10); put("sha256", "5".repeat(64)); put("linkTarget", JsonNull)
            put("mode", if (path.endsWith("jlink")) 493 else 420); put("uid", 0); put("gid", 0)
        } })
        put("toolInputs", tools)
        val recipe = buildJsonObject {
            put("jlinkPath", "opt/jdk/bin/jlink"); put("engineIdentitySha256", "6".repeat(64)); put("engineImageBindingSha256", "6".repeat(64)); put("reservationPolicySha256", "6".repeat(64))
            put("argv", JsonArray(listOf("/opt/jdk/bin/jlink", "--add-modules", "java.base", "--no-header-files", "--no-man-pages", "--strip-debug", "--output", "/workspace/provider-dns-build/image").map(::JsonPrimitive)))
            put("workingDirectory", "/workspace/provider-dns-build"); put("environment", JsonObject(emptyMap())); put("network", "disabled")
            putJsonObject("laneCeilings") { for ((key, value) in mapOf("addedDiskBytes" to 8589934592L, "absoluteSeconds" to 1800L,
                "inspectorMemoryBytes" to 1073741824L, "builderMemoryBytes" to 2147483648L, "cpus" to 2L, "pids" to 128L)) put(key, value) }
        }
        put("recipe", recipe)
        put("toolClosureSha256", dnsDomainHash("provider-dns-tool-inputs-v1", buildJsonObject { put("inputs", tools) }))
        put("jmodsSha256", dnsDomainHash("provider-dns-jmods-v1", buildJsonObject { put("inputs", JsonArray(tools.filter { it.jsonObject.dnsText("path").endsWith("/jmods/java.base.jmod") })) }))
        put("recipeSha256", dnsDomainHash("provider-dns-build-recipe-v1", recipe))
        put("sourceRelationshipSha256", "6".repeat(64)); put("authenticationReceiptSha256", "6".repeat(64))
    }
    @Test fun `typed proposed locks retain direct regular coordinates without authenticating observations`() {
        val lock = AcpProviderDnsBuildInputs.parseLockCandidate(bytes(lockDocument()))
        assertEquals(512L, lock.payloads.single().coordinate.contentOffset)
        assertFails { AcpProviderDnsBuildInputs.requireInspectionMatches(lock, graph(tar(Entry("opt/java", byteArrayOf(1)))).inspect()) }
        assertFails { AcpProviderDnsBuildInputs.parseLockCandidate(bytes(JsonObject(lockDocument() + ("sourceArchiveSha256" to JsonPrimitive("0".repeat(64)))))) }
        assertFails { AcpProviderDnsBuildInputs.parseLockCandidate(bytes(JsonObject(lockDocument() + ("family" to JsonPrimitive("eclipse-temurin:latest"))))) }
        assertFailsWith<AcpProviderDnsRuntimeUnavailableException> { AcpProviderDnsRuntimeProfiles.requireApproved("linux-x86_64-jdk21-dns-v2", lock.sha256, "0".repeat(64)) }
    }

    private data class Dag(val a: AcpProviderDnsApprovalCandidates.Candidate, val i: AcpProviderDnsApprovalCandidates.Candidate,
        val m: AcpProviderDnsApprovalCandidates.Candidate, val p: AcpProviderDnsApprovalCandidates.Candidate,
        val receipts: List<AcpProviderDnsApprovalCandidates.Receipt>, val envelope: JsonObject, val roots: Map<String, String>)
    private fun dag(): Dag {
        val a = AcpProviderDnsApprovalCandidates.applicationInput(bytes(buildJsonObject {
            put("schema", "provider-dns-application-input-v1")
            for (key in listOf("sourceFiles", "dependencyLocks")) putJsonArray(key) { add(buildJsonObject {
                put("path", if (key == "sourceFiles") "src/main.kt" else "deps.lock"); put("size", 10); put("sha256", "a".repeat(64)) }) }
            put("buildRecipeSha256", "b".repeat(64)); put("workerSha256", "c".repeat(64))
        }))
        val i = AcpProviderDnsApprovalCandidates.inputLock(AcpProviderDnsBuildInputs.parseLockCandidate(bytes(lockDocument())))
        val m = AcpProviderDnsApprovalCandidates.runtimeManifest(bytes(buildJsonObject {
            put("schema", "provider-dns-runtime-manifest-v2"); put("profileId", "linux-x86_64-jdk21-dns-v2")
            put("applicationInputSha256", a.sha256); put("buildInputLockSha256", i.sha256); put("workerSha256", "c".repeat(64)); put("abi", "linux-glibc-x86_64")
            for (key in listOf("archiveSha256", "fileManifestSha256", "loaderClosureSha256", "dependencyClosureSha256", "mountClosureSha256")) put(key, "d".repeat(64))
            putJsonObject("limits") { for ((key, value) in mapOf("entries" to 2048L, "depth" to 16L, "bytes" to 268435456L,
                "fileBytes" to 16777216L, "moduleBytes" to 201326592L, "edges" to 256L, "nativeLibraries" to 32L)) put(key, value) }
        }), a, i)
        val resolv = "nameserver 192.0.2.1\noptions timeout:1 attempts:1\n" // documentation fixture, no production resolver decision
        val switch = "hosts: files dns\n"; val hosts = "127.0.0.1 localhost\n::1 localhost\n"
        val resolver = AcpProviderDnsResolverCandidate.parseForValidation(resolv.toByteArray(), switch.toByteArray(), hosts.toByteArray())
        val p = AcpProviderDnsApprovalCandidates.resolverCore(bytes(buildJsonObject {
            put("schema", "provider-dns-resolver-core-v2"); put("policyId", "inert-fixture"); put("revision", 1)
            put("applicationInputSha256", a.sha256); put("runtimeManifestSha256", m.sha256); put("workerSha256", "c".repeat(64))
            putJsonObject("resolverFiles") { for ((name, text) in mapOf("resolv.conf" to resolv, "nsswitch.conf" to switch, "hosts" to hosts)) put(name, buildJsonObject {
                put("bytes", text); put("size", text.length); put("sha256", dnsSha(text.toByteArray())) }) }
            put("resolverPolicySha256", resolver.sha256)
            putJsonObject("transport") { put("descriptorSha256", "e".repeat(64)); put("endpoint", "https://chatgpt.com/backend-api/codex/responses"); put("operation", "RESPONSES_CREATE") }
            putJsonObject("network") { put("authorityId", "fixture"); put("authoritySha256", "e".repeat(64)); put("placementId", "fixture"); put("policyInputSha256", "e".repeat(64)) }
            putJsonArray("dnsDestinations") { add(buildJsonObject { put("address", "192.0.2.1"); put("port", 53); put("transports", JsonArray(listOf(JsonPrimitive("UDP"), JsonPrimitive("TCP"))))
                put("operatorId", "fixture"); put("classification", "public"); put("permissionInputSha256", "e".repeat(64)) }) }
            putJsonObject("sourceOwner") { put("policy", "root"); put("uid", 0); put("gid", 0); put("treeIdentitySha256", "e".repeat(64)); put("mode", "0644"); put("links", 1)
                put("acl", "absent"); put("capabilities", "absent"); put("xattrs", JsonArray(emptyList())) }
            putJsonObject("queryPolicy") { put("hostname", "chatgpt.com"); put("types", JsonArray(listOf(JsonPrimitive("A"), JsonPrimitive("AAAA")))); put("search", "none"); put("utsHostname", "fixture-dns"); put("semanticsInputSha256", "e".repeat(64)) }
            put("launchClosureSha256", "e".repeat(64)); put("sourceClosureSha256", "e".repeat(64))
        }), a, m)
        val roots = listOf("source", "provisioning", "policy-decision", "independent-review").associateWith { "f".repeat(64) }
        val receipts = roots.map { (kind, root) -> AcpProviderDnsApprovalCandidates.receipt(bytes(buildJsonObject {
            put("schema", "provider-dns-approval-receipt-candidate-v1"); put("kind", kind); put("rootSha256", root)
            putJsonObject("subjects") { when (kind) {
                "source" -> { put("A", a.sha256); put("I", i.sha256) }
                "independent-review" -> { put("M", m.sha256); put("P", p.sha256) }
                else -> put("P", p.sha256)
            } }
            put("evidenceSha256", "9".repeat(64)); put("signatureSha256", "8".repeat(64))
        })) }
        val envelope = buildJsonObject { put("schema", "provider-dns-approval-envelope-v2"); put("A", a.sha256); put("I", i.sha256); put("M", m.sha256); put("P", p.sha256)
            putJsonObject("receipts") { receipts.forEach { put(it.kind, it.sha256) } } }
        return Dag(a, i, m, p, receipts, envelope, roots)
    }
    @Test fun `parsed receipt subjects reject mutation without changing digest or envelope binding`() {
        val d = dag()
        val review = d.receipts.single { it.kind == "independent-review" }
        val subjects = review.subjects.toMap()
        val digest = review.sha256
        val originalEnvelope = AcpProviderDnsApprovalCandidates.envelope(bytes(d.envelope),
            d.a, d.i, d.m, d.p, d.receipts, d.roots)
        val exposed = review.subjects as MutableMap<AcpProviderDnsApprovalCandidates.Node, String>
        assertFailsWith<UnsupportedOperationException> { exposed[AcpProviderDnsApprovalCandidates.Node.M] = "0".repeat(64) }
        assertFailsWith<UnsupportedOperationException> { exposed.remove(AcpProviderDnsApprovalCandidates.Node.P) }
        assertFailsWith<UnsupportedOperationException> { exposed.clear() }
        assertFailsWith<UnsupportedOperationException> { exposed.entries.first().setValue("0".repeat(64)) }
        assertEquals(subjects, review.subjects)
        assertEquals(digest, review.sha256)
        assertEquals(originalEnvelope.sha256, AcpProviderDnsApprovalCandidates.envelope(bytes(d.envelope),
            d.a, d.i, d.m, d.p, d.receipts, d.roots).sha256)
        assertFailsWith<AcpProviderDnsRuntimeUnavailableException> {
            AcpProviderDnsRuntimeProfiles.requireApproved("linux-x86_64-jdk21-dns-v2", d.m.sha256, d.p.sha256)
        }
    }

    @Test fun `receipt constructor detaches caller aliases and cannot retarget a retained review digest`() {
        val d = dag()
        val review = d.receipts.single { it.kind == "independent-review" }
        val originalSubjects = review.subjects.toMap()
        val alias = LinkedHashMap(originalSubjects)
        val detached = AcpProviderDnsApprovalCandidates.Receipt(review.sha256, review.kind, review.root, alias)
        alias[AcpProviderDnsApprovalCandidates.Node.M] = "0".repeat(64)
        alias.clear()
        assertEquals(originalSubjects, detached.subjects)
        assertEquals(review.sha256, detached.sha256)
        val receipts = d.receipts.map { if (it.kind == review.kind) detached else it }
        AcpProviderDnsApprovalCandidates.envelope(bytes(d.envelope), d.a, d.i, d.m, d.p, receipts, d.roots)

        val wrongReview = AcpProviderDnsApprovalCandidates.receipt(bytes(buildJsonObject {
            put("schema", "provider-dns-approval-receipt-candidate-v1")
            put("kind", "independent-review"); put("rootSha256", review.root)
            putJsonObject("subjects") { put("M", "0".repeat(64)); put("P", "1".repeat(64)) }
            put("evidenceSha256", "9".repeat(64)); put("signatureSha256", "8".repeat(64))
        }))
        val wrongSubjects = wrongReview.subjects.toMap()
        val retargetingAlias = LinkedHashMap(wrongSubjects)
        val retained = AcpProviderDnsApprovalCandidates.Receipt(wrongReview.sha256, wrongReview.kind,
            wrongReview.root, retargetingAlias)
        retargetingAlias.putAll(originalSubjects)
        assertEquals(wrongSubjects, retained.subjects)
        assertEquals(wrongReview.sha256, retained.sha256)
        assertNotEquals(review.sha256, retained.sha256)
        val substitutedReceipts = d.receipts.map { if (it.kind == review.kind) retained else it }
        val declaration = JsonObject(d.envelope + ("receipts" to buildJsonObject {
            substitutedReceipts.forEach { put(it.kind, it.sha256) }
        }))
        assertFailsWith<IllegalArgumentException> {
            AcpProviderDnsApprovalCandidates.envelope(bytes(declaration), d.a, d.i, d.m, d.p,
                substitutedReceipts, d.roots)
        }
    }

    @Test fun `acyclic A I M P E F Q candidates bind immutable upstream identities only`() {
        val d = dag(); val e = AcpProviderDnsApprovalCandidates.envelope(bytes(d.envelope), d.a, d.i, d.m, d.p, d.receipts, d.roots)
        val f = AcpProviderDnsApprovalCandidates.finalArtifactObservation(bytes(buildJsonObject {
            put("schema", "provider-dns-final-artifact-observation-candidate-v1"); put("artifactSha256", "7".repeat(64))
            putJsonObject("embeddedResources") { for (candidate in listOf(d.a, d.i, d.m, d.p, e)) put(candidate.node.name, candidate.sha256) }
        }), d.a, d.i, d.m, d.p, e)
        val q = AcpProviderDnsApprovalCandidates.qualification(bytes(buildJsonObject {
            put("schema", "provider-dns-external-qualification-candidate-v1")
            for (candidate in listOf(d.a, d.i, d.m, d.p, e)) put(candidate.node.name, candidate.sha256)
            put("finalArtifactSha256", "7".repeat(64)); put("nativeEvidenceSha256", "6".repeat(64)); put("qualificationReviewSha256", "5".repeat(64)); put("deploymentDecisionSha256", "4".repeat(64))
        }), d.a, d.i, d.m, d.p, e, f)
        assertEquals(AcpProviderDnsApprovalCandidates.Node.Q, q.node)
        assertEquals("7".repeat(64), q.references[AcpProviderDnsApprovalCandidates.Node.F])
        assertFailsWith<AcpProviderDnsRuntimeUnavailableException> { AcpProviderDnsRuntimeProfiles.requireApproved("linux-x86_64-jdk21-dns-v2", d.m.sha256, d.p.sha256) }
    }
    @Test fun `unknown fields self references unrecognized roots and substituted review cores are refused`() {
        val d = dag()
        assertFails { AcpProviderDnsApprovalCandidates.envelope(bytes(d.envelope), d.a, d.i, d.m, d.p, d.receipts) }
        for (field in listOf("sha256", "Q", "finalArtifactSha256", "applicationBuildSha256")) {
            assertFails { AcpProviderDnsApprovalCandidates.resolverCore(bytes(JsonObject(d.p.document + (field to JsonPrimitive("0".repeat(64))))), d.a, d.m) }
        }
        assertFails { AcpProviderDnsApprovalCandidates.envelope(bytes(JsonObject(d.envelope + ("P" to JsonPrimitive("0".repeat(64))))), d.a, d.i, d.m, d.p, d.receipts, d.roots) }
        assertFails { AcpProviderDnsApprovalCandidates.receipt(bytes(buildJsonObject {
            put("schema", "provider-dns-approval-receipt-candidate-v1"); put("kind", "independent-review"); put("rootSha256", "f".repeat(64))
            putJsonObject("subjects") { put("M", d.m.sha256); put("P", d.p.sha256); put("E", "f".repeat(64)) }
            put("evidenceSha256", "9".repeat(64)); put("signatureSha256", "8".repeat(64))
        })) }
    }
    @Test fun `resolver mutations owner widening numeric destinations and runtime bound widening are refused`() {
        val d = dag()
        assertFails { AcpProviderDnsApprovalCandidates.resolverCore(bytes(JsonObject(d.p.document + ("resolverPolicySha256" to JsonPrimitive("0".repeat(64))))), d.a, d.m) }
        val destinations = d.p.document.getValue("dnsDestinations").jsonArray
        val changed = JsonArray(listOf(JsonObject(destinations.single().jsonObject + ("address" to JsonPrimitive("8.8.8.8")))))
        assertFails { AcpProviderDnsApprovalCandidates.resolverCore(bytes(JsonObject(d.p.document + ("dnsDestinations" to changed))), d.a, d.m) }
        for ((key, value) in mapOf("mode" to JsonPrimitive("0666"), "links" to JsonPrimitive(2), "acl" to JsonPrimitive("present"))) {
            val owner = JsonObject(d.p.document.getValue("sourceOwner").jsonObject + (key to value))
            assertFails { AcpProviderDnsApprovalCandidates.resolverCore(bytes(JsonObject(d.p.document + ("sourceOwner" to owner))), d.a, d.m) }
        }
        val limits = JsonObject(d.m.document.getValue("limits").jsonObject + ("fileBytes" to JsonPrimitive(16777217)))
        assertFails { AcpProviderDnsApprovalCandidates.runtimeManifest(bytes(JsonObject(d.m.document + ("limits" to limits))), d.a, d.i) }
    }

    @Test fun `generated application exclusions final artifact mixups and forged review subjects fail structural binding`() {
        val d = dag()
        assertFails { AcpProviderDnsApprovalCandidates.applicationInput(bytes(JsonObject(d.a.document + ("exclusions" to JsonArray(emptyList()))))) }
        val generated = buildJsonObject { put("path", "META-INF/provider-dns/runtime-manifest-v2.json"); put("size", 10); put("sha256", "a".repeat(64)) }
        assertFails { AcpProviderDnsApprovalCandidates.applicationInput(bytes(JsonObject(d.a.document + ("sourceFiles" to JsonArray(listOf(generated)))))) }
        val wrongReview = AcpProviderDnsApprovalCandidates.receipt(bytes(buildJsonObject {
            put("schema", "provider-dns-approval-receipt-candidate-v1"); put("kind", "independent-review"); put("rootSha256", "f".repeat(64))
            putJsonObject("subjects") { put("M", d.m.sha256); put("P", "0".repeat(64)) }
            put("evidenceSha256", "9".repeat(64)); put("signatureSha256", "8".repeat(64))
        }))
        val receipts = d.receipts.filter { it.kind != "independent-review" } + wrongReview
        val substituted = JsonObject(d.envelope + ("receipts" to buildJsonObject { receipts.forEach { put(it.kind, it.sha256) } }))
        assertFails { AcpProviderDnsApprovalCandidates.envelope(bytes(substituted), d.a, d.i, d.m, d.p, receipts, d.roots) }
        val e = AcpProviderDnsApprovalCandidates.envelope(bytes(d.envelope), d.a, d.i, d.m, d.p, d.receipts, d.roots)
        assertFails { AcpProviderDnsApprovalCandidates.finalArtifactObservation(bytes(buildJsonObject {
            put("schema", "provider-dns-final-artifact-observation-candidate-v1"); put("artifactSha256", d.a.sha256)
            putJsonObject("embeddedResources") { for (candidate in listOf(d.a, d.i, d.m, d.p, e)) put(candidate.node.name, candidate.sha256) }
        }), d.a, d.i, d.m, d.p, e) }
        val files = d.p.document.getValue("resolverFiles").jsonObject
        val resolver = JsonObject(files.getValue("resolv.conf").jsonObject + ("bytes" to JsonPrimitive("nameserver 8.8.8.8\n")))
        assertFails { AcpProviderDnsApprovalCandidates.resolverCore(bytes(JsonObject(d.p.document +
            ("resolverFiles" to JsonObject(files + ("resolv.conf" to resolver))))), d.a, d.m) }
    }

    private fun elf(tag: Long = 0, value: Long = 0, soname: Boolean = false): ByteArray {
        val raw = ByteArray(1024); val b = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        byteArrayOf(0x7f, 69, 76, 70, 2, 1, 1).copyInto(raw)
        b.putShort(16, 3); b.putShort(18, 62); b.putInt(20, 1); b.putLong(32, 64); b.putShort(52, 64); b.putShort(54, 56); b.putShort(56, 2)
        b.putInt(64, 1); b.putLong(72, 0); b.putLong(80, 0x400000); b.putLong(96, raw.size.toLong()); b.putLong(104, raw.size.toLong())
        b.putInt(120, 2); b.putLong(128, 256); b.putLong(136, 0x400100); b.putLong(152, 80); b.putLong(160, 80)
        b.putLong(256, 5); b.putLong(264, 0x400200); b.putLong(272, 10); b.putLong(280, 128)
        b.putLong(288, if (soname) 14 else tag); b.putLong(296, if (soname) 1 else value)
        "\u0000libfixture.so\u0000".toByteArray().copyInto(raw, 512)
        return raw
    }
    @Test fun `raw ELF metadata observes SONAME and never resolves host providers or semantic dlopen`() {
        val metadata = AcpProviderDnsElfInspection.inspect(elf(soname = true))
        assertEquals("libfixture.so", metadata.soname); assertTrue(metadata.fitsCurrentRuntimeFileLimit)
        val needing = AcpProviderDnsElfInspection.inspect(elf(1, 1))
        assertEquals(listOf("libfixture.so"), needing.needed)
        assertFails { AcpProviderDnsElfInspection.requireDeclaredProviders(mapOf("jdk/bin/java" to needing)) }
        AcpProviderDnsElfInspection.requireDeclaredProviders(mapOf("jdk/bin/java" to needing, "native/libfixture.so" to metadata))
        assertFails { AcpProviderDnsElfInspection.requireDeclaredProviders(mapOf("one" to metadata, "two" to metadata)) }
    }
    private fun versionedElf(provider: Boolean): ByteArray {
        val raw = elf().copyOf(2048); val b = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        b.putLong(96, 2048); b.putLong(104, 2048); b.putLong(152, 160); b.putLong(160, 160)
        raw.fill(0, 256, 416)
        val strings = "\u0000libfixture.so\u0000VER_1\u0000".toByteArray(); strings.copyInto(raw, 512)
        val versionName = "VER_1"; val nameOffset = strings.toString(Charsets.US_ASCII).indexOf(versionName)
        var hash = 0L
        versionName.forEach { char -> hash = (hash shl 4) + char.code; val high = hash and 0xf0000000L
            if (high != 0L) hash = hash xor (high ushr 24); hash = hash and high.inv() and 0xffffffffL }
        val tags = mutableListOf(5L to 0x400200L, 10L to 128L, (if (provider) 14L else 1L) to 1L)
        tags += (if (provider) 0x6ffffffcL else 0x6ffffffeL) to 0x400300L
        tags += (if (provider) 0x6ffffffdL else 0x6fffffffL) to 1L
        if (!provider) { tags += 0x6ffffff0L to 0x400390L; tags += 6L to 0x400580L; tags += 11L to 24L }
        tags.forEachIndexed { index, (tag, value) -> b.putLong(256 + index * 16, tag); b.putLong(264 + index * 16, value) }
        b.putShort(768, 1)
        if (provider) {
            b.putShort(772, 2); b.putShort(774, 1); b.putInt(776, hash.toInt()); b.putInt(780, 20)
            b.putInt(788, nameOffset)
        } else {
            b.putShort(770, 1); b.putInt(772, 1); b.putInt(776, 16)
            b.putInt(784, hash.toInt()); b.putShort(790, 2); b.putInt(792, nameOffset)
            b.putShort(912, 0); b.putShort(914, 2)
            b.putLong(40, 1152); b.putShort(58, 64); b.putShort(60, 2)
            b.putInt(1220, 11); b.putLong(1240, 1408); b.putLong(1248, 48); b.putLong(1272, 24)
        }
        return raw
    }
    @Test fun `ELF version requirements definitions and symbol indexes bind exact providers`() {
        val needing = AcpProviderDnsElfInspection.inspect(versionedElf(false))
        val provider = AcpProviderDnsElfInspection.inspect(versionedElf(true))
        assertEquals(setOf("VER_1"), needing.versionsNeeded["libfixture.so"])
        assertEquals(setOf("VER_1"), provider.versionsDefined)
        AcpProviderDnsElfInspection.requireDeclaredProviders(mapOf("jdk/bin/java" to needing, "native/libfixture.so" to provider))
        assertFails { AcpProviderDnsElfInspection.requireDeclaredProviders(mapOf("jdk/bin/java" to needing, "native/libfixture.so" to AcpProviderDnsElfInspection.inspect(elf(soname = true)))) }
        for ((offset, value) in listOf(784 to 1, 780 to 16, 796 to 16, 914 to 3, 360 to 0x400590, 376 to 16)) {
            assertFails { AcpProviderDnsElfInspection.inspect(versionedElf(false).also {
                val b = ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN)
                if (offset == 914) b.putShort(offset, value.toShort()) else b.putInt(offset, value)
            }) }
        }
    }
    @Test fun `tool recipe identities and lane resource ceilings cannot widen a proposed input lock`() {
        val lock = lockDocument()
        val recipe = lock.getValue("recipe").jsonObject
        val lane = recipe.getValue("laneCeilings").jsonObject
        for ((key, maximum) in mapOf("addedDiskBytes" to 8589934592L, "absoluteSeconds" to 1800L,
            "inspectorMemoryBytes" to 1073741824L, "builderMemoryBytes" to 2147483648L, "cpus" to 2L, "pids" to 128L)) {
            val changedRecipe = JsonObject(recipe + ("laneCeilings" to JsonObject(lane + (key to JsonPrimitive(maximum + 1)))))
            assertFails { AcpProviderDnsBuildInputs.parseLockCandidate(bytes(JsonObject(lock + ("recipe" to changedRecipe)))) }
        }
        assertFails { AcpProviderDnsBuildInputs.parseLockCandidate(bytes(JsonObject(lock + ("toolClosureSha256" to JsonPrimitive("0".repeat(64)))))) }
        val changed = JsonObject(recipe + ("environment" to buildJsonObject { put("PATH", "/host/bin") }))
        assertFails { AcpProviderDnsBuildInputs.parseLockCandidate(bytes(JsonObject(lock + ("recipe" to changed)))) }
    }
    @Test fun `fresh valid descriptors do not hide mismatched diffIDs foreign media or compressed tails`() {
        val raw = tar(Entry("file", byteArrayOf(1)))
        assertFails { graph(raw, configTransform = { config -> JsonObject(config + ("rootfs" to buildJsonObject {
            put("type", "layers"); put("diff_ids", JsonArray(listOf(JsonPrimitive("sha256:" + "0".repeat(64))))) })) }).inspect() }
        assertFails { graph(raw, manifestTransform = { manifest ->
            val layer = manifest.getValue("layers").jsonArray.single().jsonObject
            JsonObject(manifest + ("layers" to JsonArray(listOf(JsonObject(layer + ("mediaType" to JsonPrimitive("application/vnd.oci.image.layer.nondistributable.v1.tar")))))))
        }).inspect() }
    }
    @Test fun `ELF split dynamic file and loaded table is refused before interpreting dependencies`() {
        assertTrue(AcpProviderDnsElfInspection.inspect(elf()).needed.isEmpty())
        val split = elf(); val loaded = elf(1, 1)
        loaded.copyInto(split, 768, 256, 336)
        ByteBuffer.wrap(split).order(ByteOrder.LITTLE_ENDIAN).putLong(136, 0x400300)
        assertFails { AcpProviderDnsElfInspection.inspect(split) }
    }
    @Test fun `ELF unmapped dynamic virtual address is refused`() {
        assertFails { AcpProviderDnsElfInspection.inspect(elf().also {
            ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putLong(136, 0x900000)
        }) }
    }
    @Test fun `ELF ambiguous load mapping of an otherwise empty dynamic table is refused`() {
        val raw = elf().also { it.fill(0, 256, 336) }
        raw.copyInto(raw, 176, 64, 120)
        ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).putShort(56, 3)
        assertFails { AcpProviderDnsElfInspection.inspect(raw) }
    }
    @Test fun `ELF partially overlapping load also makes the dynamic table ambiguous`() {
        val raw = elf().also { it.fill(0, 256, 336) }
        val b = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        b.putShort(56, 3); b.putInt(176, 1)
        b.putLong(184, 768); b.putLong(192, 0x400110); b.putLong(208, 16); b.putLong(216, 16)
        assertFails { AcpProviderDnsElfInspection.inspect(raw) }
    }

    private fun elfWithSecondLoad(fileSize: Long, memorySize: Long, address: Long): ByteArray {
        val raw = elf().also { it.fill(0, 256, 336) }
        val b = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        b.putShort(56, 3); b.putInt(176, 1)
        b.putLong(184, address - 0x400000); b.putLong(192, address)
        b.putLong(208, fileSize); b.putLong(216, memorySize); b.putLong(224, 4096)
        return raw
    }

    @Test fun `ELF BSS only load overlapping dynamic memory is refused`() {
        assertFails { AcpProviderDnsElfInspection.inspect(elfWithSecondLoad(0, 16, 0x400100)) }
    }

    @Test fun `ELF load BSS tail overlapping dynamic memory is refused`() {
        for (fileSize in listOf(8L, 16L))
            assertFails { AcpProviderDnsElfInspection.inspect(elfWithSecondLoad(fileSize, fileSize + 16, 0x400100 - fileSize)) }
    }

    @Test fun `ELF nonoverlapping BSS load preserves supported metadata`() {
        val raw = elfWithSecondLoad(0, 16, 0x400150)
        // This BSS starts exactly after the requested dynamic interval.
        assertTrue(AcpProviderDnsElfInspection.inspect(raw).needed.isEmpty())
        assertTrue(AcpProviderDnsElfInspection.inspect(elfWithSecondLoad(8, 24, 0x400150)).needed.isEmpty())
    }

    @Test fun `ELF dynamic range must be completely backed by one load mapping`() {
        val raw = elf().also { it.fill(0, 256, 336) }
        val b = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        b.putLong(96, 300); b.putLong(104, 300)
        assertFails { AcpProviderDnsElfInspection.inspect(raw) }
    }

    @Test fun `ELF external search directives unknown tags wrong ABI and unbounded tables fail closed`() {
        for (tag in listOf(15L, 29L, 0x6ffffefaL, 0x6ffffefbL, 0x6ffffefcL, 0x7fffffffL, 0x7ffffffdL, 0x12345678L))
            assertFails { AcpProviderDnsElfInspection.inspect(elf(tag, 1)) }
        assertFails { AcpProviderDnsElfInspection.inspect(elf().also { it[18] = 3 }) }
        assertFails { AcpProviderDnsElfInspection.inspect(elf().also { ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putShort(56, 513) }) }
        assertFails { AcpProviderDnsElfInspection.inspect(elf(5, 1)) }
    }
}
