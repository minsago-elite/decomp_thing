package decompengine.acp

import decompengine.builtin.provider.parseProviderObject
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.Collections
import java.io.PushbackInputStream
import java.util.zip.CRC32
import java.util.zip.Inflater
import kotlinx.serialization.json.*

/** Offline observation only. No descriptor, checksum, map or lock grants execution/profile authority. */
internal object AcpProviderDnsBuildInputs {
    const val FAMILY = "eclipse-temurin:21-jdk-jammy@sha256:55fb9bf738f5d9b4a6c01b39337e3070d3e27370dd3c478fd1d5d3cd2233c6d8"
    const val INDEX = "application/vnd.oci.image.index.v1+json"
    const val MANIFEST = "application/vnd.oci.image.manifest.v1+json"
    const val CONFIG = "application/vnd.oci.image.config.v1+json"
    const val TAR = "application/vnd.oci.image.layer.v1.tar"
    const val GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
    const val JSON_BYTES = 1024 * 1024
    const val METADATA_BYTES = 8L * 1024 * 1024
    const val DESCRIPTORS = 128
    const val LAYERS = 32
    const val LAYER_COMPRESSED = 512L * 1024 * 1024
    const val COMPRESSED = 2L * 1024 * 1024 * 1024
    const val LAYER_EXPANDED = 1024L * 1024 * 1024
    const val EXPANDED = 4L * 1024 * 1024 * 1024
    const val ENTRIES = 65_536
    const val MEMBER_BYTES = 256L * 1024 * 1024
    const val BLOCK = 64 * 1024

    /** Upper bounds may only be narrowed by an inert caller; there is no acquisition/build API. */
    class Limits(
        val metadata: Long = METADATA_BYTES, val compressed: Long = COMPRESSED,
        val layerCompressed: Long = LAYER_COMPRESSED, val expanded: Long = EXPANDED,
        val layerExpanded: Long = LAYER_EXPANDED, val entries: Int = ENTRIES,
        val member: Long = MEMBER_BYTES,
    ) {
        init {
            require(metadata in 1..METADATA_BYTES && compressed in 1..COMPRESSED &&
                layerCompressed in 1..LAYER_COMPRESSED && expanded in 1..EXPANDED &&
                layerExpanded in 1..LAYER_EXPANDED && entries in 1..ENTRIES && member in 1..MEMBER_BYTES)
        }
    }
    data class Descriptor(val mediaType: String, val digest: String, val size: Long)
    enum class Kind { REGULAR, DIRECTORY, SYMLINK, HARDLINK }
    data class Member internal constructor(
        val path: String, val kind: Kind, val mode: Long, val uid: Long, val gid: Long,
        val size: Long, val sha256: String?, val linkTarget: String?, val layer: Int,
        /** Byte offset in the authenticated uncompressed layer; never a host path. */
        val contentOffset: Long, val explicitMetadata: Boolean,
    )
    data class PayloadCoordinate(val path: String, val layerDigest: String, val diffId: String,
        val contentOffset: Long, val size: Long, val sha256: String, val destination: String)
    class Inspection internal constructor(
        val indexDigest: String, val indexBytes: Long, val manifest: Descriptor, val config: Descriptor,
        indexChildren: List<Descriptor>, layers: List<Descriptor>, diffIds: List<String>, members: Map<String, Member>,
        val compressedBytes: Long, val expandedBytes: Long, val decodedEntries: Int,
    ) {
        val indexChildren = Collections.unmodifiableList(indexChildren.toList())
        val layers = Collections.unmodifiableList(layers.toList())
        val diffIds = Collections.unmodifiableList(diffIds.toList())
        val members = Collections.unmodifiableMap(members.toSortedMap())
        fun selectRegular(path: String, destination: String): PayloadCoordinate {
            dnsRelativePath(path); dnsRelativePath(destination)
            require(destination.startsWith("jdk/") || destination.startsWith("native/"))
            val member = requireNotNull(members[path])
            require(member.kind == Kind.REGULAR && member.explicitMetadata && member.layer in layers.indices)
            return PayloadCoordinate(path, layers[member.layer].digest, diffIds[member.layer],
                member.contentOffset, member.size, requireNotNull(member.sha256), destination)
        }
    }

    /** Expected top bytes/digest must come from reviewed policy; inert fixtures use inspectGraph only. */
    fun inspectPinned(index: ByteArray, blobs: (String) -> InputStream, limits: Limits = Limits(), checkpoint: () -> Unit = {}): Inspection {
        require(index.size in 1..JSON_BYTES && index.size.toLong() <= limits.metadata)
        val pinned = index.copyOf()
        require("sha256:" + dnsSha(pinned) == FAMILY.substringAfter('@'))
        return inspectGraph(pinned, blobs, limits, checkpoint)
    }

    /** Fixture/observation entry point, intentionally does not claim the pinned family is compatible. */
    fun inspectGraph(index: ByteArray, blobs: (String) -> InputStream, limits: Limits = Limits(), checkpoint: () -> Unit = {}): Inspection {
        require(index.size in 1..JSON_BYTES && index.size.toLong() <= limits.metadata)
        val pinnedIndex = index.copyOf()
        val started = System.nanoTime()
        fun progress() { require(System.nanoTime() - started < 1800L * 1_000_000_000L); checkpoint() }
        progress()
        var metadata = 0L; var descriptors = 1 // includes the pinned index descriptor
        val seenDescriptors = mutableMapOf<String, Descriptor>()
        fun reserveMetadata(size: Long) {
            require(size in 1..JSON_BYTES.toLong())
            progress()
            // Reserve before the provider can open/read or the buffer can be allocated.
            metadata = dnsCharge(metadata, size, limits.metadata)
        }
        fun descriptor(raw: JsonElement, platform: Boolean = false): Descriptor {
            progress()
            val obj = raw.jsonObject
            obj.dnsKeys(*(if (platform) arrayOf("mediaType", "digest", "size", "platform") else arrayOf("mediaType", "digest", "size")))
            require(++descriptors <= DESCRIPTORS)
            val value = Descriptor(obj.dnsText("mediaType"), obj.dnsDigest("digest"), obj.dnsLong("size"))
            require(value.size > 0)
            seenDescriptors.putIfAbsent(value.digest, value)?.let { require(it == value) }
            return value
        }
        fun readMetadata(d: Descriptor): JsonObject {
            reserveMetadata(d.size)
            val bytes = blobs(d.digest).use { dnsReadExactBlob(it, d.size, JSON_BYTES.toLong(), ::progress) }
            require("sha256:" + dnsSha(bytes) == d.digest)
            return dnsObject(bytes)
        }
        reserveMetadata(pinnedIndex.size.toLong())
        val root = dnsObject(pinnedIndex)
        root.dnsKeys("schemaVersion", "mediaType", "manifests")
        require(root.dnsLong("schemaVersion") == 2L && root.dnsText("mediaType") == INDEX)
        val children = root.getValue("manifests").jsonArray
        require(children.size in 1..DESCRIPTORS)
        val platformDescriptors = children.map { raw ->
            val d = descriptor(raw, true)
            require(d.mediaType == MANIFEST && d.size <= JSON_BYTES)
            val p = raw.jsonObject.getValue("platform").jsonObject
            p.dnsKeys("os", "architecture")
            d to (p.dnsText("os") == "linux" && p.dnsText("architecture") == "amd64")
        }
        require(platformDescriptors.map { it.first.digest }.distinct().size == platformDescriptors.size)
        val selected = platformDescriptors.filter { it.second }.map { it.first }.single()
        val manifest = readMetadata(selected)
        manifest.dnsKeys("schemaVersion", "mediaType", "config", "layers")
        require(manifest.dnsLong("schemaVersion") == 2L && manifest.dnsText("mediaType") == MANIFEST)
        val configDescriptor = descriptor(manifest.getValue("config"))
        require(configDescriptor.mediaType == CONFIG)
        val config = readMetadata(configDescriptor)
        // Image config is observation, never environment/entrypoint/tool execution authority.
        require(config.dnsText("os") == "linux" && config.dnsText("architecture") == "amd64")
        val rootfs = config.getValue("rootfs").jsonObject
        rootfs.dnsKeys("type", "diff_ids")
        require(rootfs.dnsText("type") == "layers")
        val diffIds = rootfs.getValue("diff_ids").jsonArray.map { it.dnsString().also(::dnsDigest) }
        val layers = manifest.getValue("layers").jsonArray.map { descriptor(it) }
        require(layers.size in 1..LAYERS && diffIds.size == layers.size)
        var compressed = 0L; var expanded = 0L; var entries = 0
        val namespace = linkedMapOf<String, Member>()
        layers.forEachIndexed { layerNumber, layer ->
            progress()
            require(layer.mediaType == TAR || layer.mediaType == GZIP) // Docker, foreign/zstd/PAX extensions unavailable.
            require(layer.size <= limits.layerCompressed)
            compressed = dnsCharge(compressed, layer.size, limits.compressed)
            val compressedHash = MessageDigest.getInstance("SHA-256")
            val expandedHash = MessageDigest.getInstance("SHA-256")
            blobs(layer.digest).use { raw ->
                val bounded = DnsCountingInput(raw, layer.size, compressedHash) { progress() }
                val decoded = if (layer.mediaType == GZIP) DnsGzipInput(bounded) else bounded
                decoded.use { decoded ->
                var layerExpanded = 0L
                val stream = DnsCountingInput(decoded, limits.layerExpanded, expandedHash) { n ->
                    layerExpanded = dnsCharge(layerExpanded, n, limits.layerExpanded)
                    expanded = dnsCharge(expanded, n, limits.expanded)
                }
                val additions = linkedMapOf<String, Member>()
                val removals = linkedSetOf<String>(); val opaque = linkedSetOf<String>()
                var ended = false
                while (true) {
                    progress()
                    val headerOffset = stream.count
                    val header = dnsBlock(stream, 512) ?: error("tar missing end marker")
                    if (header.all { it == 0.toByte() }) {
                        require(dnsBlock(stream, 512)?.all { it == 0.toByte() } == true)
                        // Every expanded padding byte is charged and must be zero.
                        val padding = ByteArray(BLOCK)
                        while (true) { val n = stream.read(padding); if (n < 0) break; require(padding.take(n).all { it == 0.toByte() }) }
                        ended = true; break
                    }
                    require(++entries <= limits.entries)
                    require(header.copyOfRange(257, 263).contentEquals("ustar\u0000".toByteArray()) &&
                        header.copyOfRange(263, 265).contentEquals("00".toByteArray()))
                    val checksum = dnsOctal(header, 148, 8)
                    require(header.indices.sumOf { if (it in 148..155) 32 else header[it].toInt() and 255 }.toLong() == checksum)
                    val name = dnsTarText(header, 0, 100)
                    val prefix = dnsTarText(header, 345, 155)
                    val type = header[156].toInt().toChar()
                    val path = dnsRelativePath((if (prefix.isEmpty()) name else "$prefix/$name").let {
                        if (type == '5' && it.endsWith('/')) it.dropLast(1) else it
                    })
                    val size = dnsOctal(header, 124, 12)
                    require(size <= limits.member)
                    val mode = dnsOctal(header, 100, 8); val uid = dnsOctal(header, 108, 8); val gid = dnsOctal(header, 116, 8)
                    require(mode <= 0xfff && uid <= Int.MAX_VALUE && gid <= Int.MAX_VALUE)
                    val leaf = path.substringAfterLast('/'); val parent = path.substringBeforeLast('/', "")
                    if (leaf.startsWith(".wh.")) {
                        require(type in listOf('0', '\u0000') && size == 0L)
                        if (leaf == ".wh..wh..opq") require(opaque.add(parent))
                        else { require(!leaf.removePrefix(".wh.").startsWith(".wh."))
                            val target = dnsRelativePath((if (parent.isEmpty()) "" else "$parent/") + leaf.removePrefix(".wh.")); require(removals.add(target)) }
                    } else {
                        val kind = when (type) {
                            '0', '\u0000' -> Kind.REGULAR
                            '5' -> Kind.DIRECTORY
                            '2' -> Kind.SYMLINK
                            '1' -> Kind.HARDLINK
                            else -> error("unsupported tar operation")
                        }
                        require(kind == Kind.REGULAR || size == 0L)
                        val target = if (kind in listOf(Kind.SYMLINK, Kind.HARDLINK)) dnsTarText(header, 157, 100).also {
                            require(it.isNotEmpty() && it.toByteArray().size <= 4096 && '\u0000' !in it && it.none(Char::isISOControl))
                            if (kind == Kind.HARDLINK) dnsRelativePath(it)
                        } else null
                        val digest = if (kind == Kind.REGULAR) dnsHashMember(stream, size) else null
                        require(additions.put(path, Member(path, kind, mode, uid, gid, size, digest, target,
                            layerNumber, headerOffset + 512, true)) == null)
                    }
                    val pad = (512 - size % 512) % 512
                    if (pad > 0) require(requireNotNull(dnsBlock(stream, pad.toInt())).all { it == 0.toByte() })
                }
                require(ended && "sha256:" + dnsHex(expandedHash.digest()) == diffIds[layerNumber])
                // Gzip must consume the complete input, including CRC/trailer; no ignored trailing blobs.
                val tail = ByteArray(BLOCK)
                while (bounded.read(tail) >= 0) { error("compressed layer has trailing bytes") }
                require(bounded.count == layer.size && "sha256:" + dnsHex(compressedHash.digest()) == layer.digest)
                fun parents(path: String) {
                    val parts = path.split('/')
                    for (depth in 1 until parts.size) {
                        val p = parts.take(depth).joinToString("/")
                        val old = namespace[p]
                        require(old == null || old.kind == Kind.DIRECTORY)
                        if (old == null) namespace[p] = Member(p, Kind.DIRECTORY, 0, 0, 0, 0, null, null, layerNumber, 0, false)
                        require(namespace.size <= limits.entries)
                    }
                }
                // Whiteouts act only on lower layers, independent of their order in this tar.
                (removals + opaque.filter(String::isNotEmpty)).forEach { parents(it) }
                removals.forEach { p -> namespace.keys.removeAll { progress(); it == p || it.startsWith("$p/") } }
                opaque.forEach { p ->
                    require(p.isEmpty() || namespace[p]?.kind in listOf(null, Kind.DIRECTORY))
                    namespace.keys.removeAll { progress(); p.isEmpty() || it.startsWith("$p/") }
                    if (p.isNotEmpty() && namespace[p] == null) {
                        namespace[p] = Member(p, Kind.DIRECTORY, 0, 0, 0, 0, null, null, layerNumber, 0, false)
                        require(namespace.size <= limits.entries)
                    }
                }
                additions.values.forEach { member ->
                    require(member.kind == Kind.DIRECTORY || additions.keys.none { it.startsWith(member.path + "/") })
                    parents(member.path)
                    if (member.kind != Kind.DIRECTORY || namespace[member.path]?.kind != Kind.DIRECTORY) {
                        namespace.keys.removeAll { progress(); it == member.path || it.startsWith(member.path + "/") }
                    }
                    namespace[member.path] = member
                    require(namespace.size <= limits.entries)
                }
                }
            }
        }
        progress()
        return Inspection("sha256:" + dnsSha(pinnedIndex), pinnedIndex.size.toLong(), selected, configDescriptor, platformDescriptors.map { it.first }, layers, diffIds, namespace, compressed, expanded, entries)
    }

    class InputLock internal constructor(
        val sha256: String, val index: Descriptor, val manifest: Descriptor, val config: Descriptor,
        indexChildren: List<Descriptor>, layers: List<Pair<Descriptor, String>>, payloads: List<LockedPayload>,
        toolInputs: List<LockedObject>, val recipe: Recipe,
        val toolClosureSha256: String, val jmodsSha256: String, val sourceRelationshipSha256: String,
        val recipeSha256: String, val authenticationReceiptSha256: String,
    ) {
        val indexChildren = Collections.unmodifiableList(indexChildren.toList())
        val layers = Collections.unmodifiableList(layers.toList())
        val toolInputs = Collections.unmodifiableList(toolInputs.toList())
        val payloads = Collections.unmodifiableList(payloads.toList())
    }
    data class LockedPayload(val coordinate: PayloadCoordinate, val mode: Long, val uid: Long, val gid: Long)
    data class LockedObject(val path: String, val kind: Kind, val layerDigest: String, val diffId: String,
        val contentOffset: Long, val size: Long, val sha256: String?, val linkTarget: String?, val mode: Long, val uid: Long, val gid: Long)
    class Recipe internal constructor(val jlinkPath: String, val engineIdentitySha256: String, val engineImageBindingSha256: String,
        val reservationPolicySha256: String, laneCeilings: Map<String, Long>) {
        val laneCeilings = Collections.unmodifiableMap(laneCeilings.toMap())
    }

    /** A proposed complete identity lock, never an authenticated/usable approval. */
    fun parseLockCandidate(bytes: ByteArray): InputLock {
        val doc = dnsObject(bytes)
        doc.dnsKeys("schema", "family", "index", "manifest", "config", "indexChildren", "layers", "payloads", "toolInputs", "recipe", "toolClosureSha256", "jmodsSha256", "sourceRelationshipSha256", "recipeSha256", "authenticationReceiptSha256")
        require(doc.dnsText("schema") == "provider-dns-build-input-v1" && doc.dnsText("family") == FAMILY)
        fun record(raw: JsonElement, mediaTypes: Set<String>, maximum: Long): Descriptor {
            val obj = raw.jsonObject; obj.dnsKeys("mediaType", "digest", "size")
            return Descriptor(obj.dnsText("mediaType"), obj.dnsDigest("digest"), obj.dnsLong("size")).also {
                require(it.mediaType in mediaTypes && it.size in 1..maximum)
            }
        }
        val index = record(doc.getValue("index"), setOf(INDEX), JSON_BYTES.toLong())
        require(index.digest == FAMILY.substringAfter('@'))
        val manifest = record(doc.getValue("manifest"), setOf(MANIFEST), JSON_BYTES.toLong())
        val config = record(doc.getValue("config"), setOf(CONFIG), JSON_BYTES.toLong())
        val childRecords = doc.getValue("indexChildren").jsonArray
        require(childRecords.size in 1..DESCRIPTORS)
        val indexChildren = childRecords.map { record(it, setOf(MANIFEST), JSON_BYTES.toLong()) }
        require(indexChildren.distinct().size == indexChildren.size && indexChildren.count { it == manifest } == 1)
        val rawLayers = doc.getValue("layers").jsonArray
        require(rawLayers.size in 1..LAYERS)
        var compressed = 0L
        val layers = rawLayers.map { raw ->
            val obj = raw.jsonObject; obj.dnsKeys("descriptor", "diffId")
            val descriptor = record(obj.getValue("descriptor"), setOf(TAR, GZIP), LAYER_COMPRESSED)
            compressed = dnsCharge(compressed, descriptor.size, COMPRESSED)
            descriptor to obj.dnsDigest("diffId")
        }
        val allDescriptors = listOf(index, config) + indexChildren + layers.map { it.first }
        require(allDescriptors.size <= DESCRIPTORS && allDescriptors.groupBy { it.digest }.values.all { it.distinct().size == 1 })
        require(layers.groupBy { it.first.digest }.values.all { records -> records.map { it.second }.distinct().size == 1 })
        val payloads = doc.getValue("payloads").jsonArray
        require(payloads.size in 1..AcpProviderDnsRuntimeProfiles.MAXIMUM_ENTRIES)
        val destinations = hashSetOf<String>()
        val selected = payloads.map { raw ->
            val obj = raw.jsonObject
            obj.dnsKeys("path", "layerDigest", "diffId", "contentOffset", "size", "sha256", "destination", "mode", "uid", "gid")
            val path = dnsRelativePath(obj.dnsText("path")); val destination = dnsRelativePath(obj.dnsText("destination"))
            require(destination.startsWith("jdk/") || destination.startsWith("native/"))
            require(destinations.add(destination))
            val layer = obj.dnsDigest("layerDigest"); val diff = obj.dnsDigest("diffId")
            require(layers.any { it.first.digest == layer && it.second == diff })
            val offset = obj.dnsLong("contentOffset"); val size = obj.dnsLong("size")
            require(offset >= 512 && offset % 512 == 0L && size in 1..MEMBER_BYTES && offset <= LAYER_EXPANDED - size)
            val mode = obj.dnsLong("mode"); val uid = obj.dnsLong("uid"); val gid = obj.dnsLong("gid")
            require(mode in setOf(420L, 493L) && uid <= Int.MAX_VALUE && gid <= Int.MAX_VALUE)
            LockedPayload(PayloadCoordinate(path, layer, diff, offset, size, obj.dnsHash("sha256"), destination), mode, uid, gid)
        }
        val rawTools = doc.getValue("toolInputs").jsonArray
        require(rawTools.size in 1..2048)
        val toolPaths = hashSetOf<String>()
        val tools = rawTools.map { raw ->
            val obj = raw.jsonObject
            obj.dnsKeys("path", "kind", "layerDigest", "diffId", "contentOffset", "size", "sha256", "linkTarget", "mode", "uid", "gid")
            val path = dnsRelativePath(obj.dnsText("path")); require(toolPaths.add(path))
            val kind = Kind.valueOf(obj.dnsText("kind"))
            val layer = obj.dnsDigest("layerDigest"); val diff = obj.dnsDigest("diffId")
            require(layers.any { it.first.digest == layer && it.second == diff })
            val offset = obj.dnsLong("contentOffset"); val size = obj.dnsLong("size")
            require(offset >= 512 && offset % 512 == 0L && size in 0..MEMBER_BYTES && offset <= LAYER_EXPANDED - size)
            val mode = obj.dnsLong("mode"); val uid = obj.dnsLong("uid"); val gid = obj.dnsLong("gid")
            require(mode <= 0xfff && uid <= Int.MAX_VALUE && gid <= Int.MAX_VALUE)
            val hash = if (kind == Kind.REGULAR) obj.dnsHash("sha256") else { require(obj["sha256"] == JsonNull && size == 0L); null }
            val target = if (kind in setOf(Kind.SYMLINK, Kind.HARDLINK)) obj.dnsText("linkTarget").also {
                require(it.isNotEmpty() && it.none(Char::isISOControl)); if (kind == Kind.HARDLINK) dnsRelativePath(it)
            } else { require(obj["linkTarget"] == JsonNull); null }
            LockedObject(path, kind, layer, diff, offset, size, hash, target, mode, uid, gid)
        }
        require(tools.count { it.path.endsWith("/jmods/java.base.jmod") && it.kind == Kind.REGULAR } == 1)
        val recipe = doc.getValue("recipe").jsonObject
        recipe.dnsKeys("jlinkPath", "engineIdentitySha256", "engineImageBindingSha256", "reservationPolicySha256", "argv", "workingDirectory", "environment", "network", "laneCeilings")
        val jlink = dnsRelativePath(recipe.dnsText("jlinkPath"))
        require(tools.singleOrNull { it.path == jlink }?.let { it.kind == Kind.REGULAR && it.mode == 493L } == true)
        val argv = recipe.getValue("argv").jsonArray.map { it.dnsString() }
        require(argv == listOf("/$jlink", "--add-modules", "java.base", "--no-header-files", "--no-man-pages", "--strip-debug", "--output", "/workspace/provider-dns-build/image") &&
            recipe.dnsText("workingDirectory") == "/workspace/provider-dns-build" && recipe.getValue("environment").jsonObject.isEmpty() && recipe.dnsText("network") == "disabled")
        val lane = recipe.getValue("laneCeilings").jsonObject
        val maxima = mapOf("addedDiskBytes" to 8L * 1024 * 1024 * 1024, "absoluteSeconds" to 1800L,
            "inspectorMemoryBytes" to 1024L * 1024 * 1024, "builderMemoryBytes" to 2L * 1024 * 1024 * 1024, "cpus" to 2L, "pids" to 128L)
        lane.dnsKeys(*maxima.keys.toTypedArray()); maxima.forEach { (key, maximum) -> require(lane.dnsLong(key) in 1..maximum) }
        require(doc.dnsHash("toolClosureSha256") == dnsDomainHash("provider-dns-tool-inputs-v1", buildJsonObject { put("inputs", rawTools) }))
        require(doc.dnsHash("jmodsSha256") == dnsDomainHash("provider-dns-jmods-v1", buildJsonObject {
            put("inputs", JsonArray(rawTools.filter { it.jsonObject.dnsText("path").endsWith("/jmods/java.base.jmod") })) }))
        require(doc.dnsHash("recipeSha256") == dnsDomainHash("provider-dns-build-recipe-v1", recipe))
        val recipeIdentity = Recipe(jlink, recipe.dnsHash("engineIdentitySha256"), recipe.dnsHash("engineImageBindingSha256"),
            recipe.dnsHash("reservationPolicySha256"), maxima.keys.associateWith { lane.dnsLong(it) })
        return InputLock(dnsDomainHash("provider-dns-build-input-v1", doc), index, manifest, config, indexChildren, layers, selected, tools, recipeIdentity,
            doc.dnsHash("toolClosureSha256"), doc.dnsHash("jmodsSha256"), doc.dnsHash("sourceRelationshipSha256"),
            doc.dnsHash("recipeSha256"), doc.dnsHash("authenticationReceiptSha256"))
    }

    fun requireInspectionMatches(lock: InputLock, inspection: Inspection) {
        require(lock.index.digest == inspection.indexDigest && lock.index.size == inspection.indexBytes && lock.manifest == inspection.manifest && lock.config == inspection.config)
        require(lock.indexChildren == inspection.indexChildren && lock.layers == inspection.layers.zip(inspection.diffIds))
        lock.toolInputs.forEach { tool ->
            val member = inspection.members.getValue(tool.path)
            require(member.explicitMetadata && member.kind == tool.kind && member.layer in inspection.layers.indices &&
                inspection.layers[member.layer].digest == tool.layerDigest && inspection.diffIds[member.layer] == tool.diffId &&
                member.contentOffset == tool.contentOffset && member.size == tool.size && member.sha256 == tool.sha256 &&
                member.linkTarget == tool.linkTarget && member.mode == tool.mode && member.uid == tool.uid && member.gid == tool.gid)
        }
        lock.payloads.forEach { payload ->
            val coordinate = payload.coordinate
            require(inspection.selectRegular(coordinate.path, coordinate.destination) == coordinate)
            val member = inspection.members.getValue(coordinate.path)
            require(member.mode == payload.mode && member.uid == payload.uid && member.gid == payload.gid)
        }
    }

}

internal fun dnsObject(bytes: ByteArray): JsonObject {
    require(bytes.size in 1..AcpProviderDnsBuildInputs.JSON_BYTES)
    return parseProviderObject(bytes.decodeToString(throwOnInvalidSequence = true), AcpProviderDnsBuildInputs.JSON_BYTES)
}
internal fun JsonObject.dnsKeys(vararg keys: String) { require(this.keys == keys.toSet()) }
internal fun JsonObject.dnsText(key: String) = getValue(key).dnsString()
internal fun JsonElement.dnsString() = jsonPrimitive.also { require(it.isString && it.content.toByteArray().size <= 4096) }.content
internal fun JsonObject.dnsLong(key: String) = getValue(key).jsonPrimitive.also { require(!it.isString && it.content.matches(Regex("0|[1-9][0-9]*"))) }.long
internal fun JsonObject.dnsHash(key: String): String = decompengine.acp.dnsHash(dnsText(key))
internal fun dnsHash(value: String): String = value.also { require(it.matches(Regex("[0-9a-f]{64}"))) }
internal fun JsonObject.dnsDigest(key: String): String = decompengine.acp.dnsDigest(dnsText(key))
internal fun dnsDigest(value: String): String = value.also { require(it.matches(Regex("sha256:[0-9a-f]{64}"))) }
internal fun dnsSha(bytes: ByteArray) = dnsHex(MessageDigest.getInstance("SHA-256").digest(bytes))
internal fun dnsHex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
internal fun dnsRelativePath(value: String): String = value.also {
    require(it.toByteArray().size in 1..4096 && it.split('/').size <= 32 &&
        it.split('/').all { part -> part.isNotEmpty() && part != "." && part != ".." && part.none { c -> c.isISOControl() || c == '\\' } })
}
internal fun dnsCharge(old: Long, amount: Long, maximum: Long): Long {
    require(amount >= 0 && old <= maximum && amount <= maximum - old)
    return old + amount
}
private class DnsCountingInput(private val input: InputStream, private val maximum: Long,
    private val hash: MessageDigest, private val charge: (Long) -> Unit) : InputStream() {
    var count = 0L; private set
    override fun read(): Int { val b = ByteArray(1); return if (read(b, 0, 1) < 0) -1 else b[0].toInt() and 255 }
    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        require(length >= 0)
        if (length == 0) return 0
        // At the limit probe one byte: overflow is rejected before hashing/allocation/publication.
        val n = input.read(bytes, offset, minOf(length, AcpProviderDnsBuildInputs.BLOCK, (maximum - count + 1).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()))
        if (n < 0) return -1
        require(n > 0 && n.toLong() <= maximum - count)
        charge(n.toLong()); count += n; hash.update(bytes, offset, n); return n
    }
}
private fun dnsReadExactBlob(input: InputStream, size: Long, maximum: Long, checkpoint: () -> Unit): ByteArray {
    require(size in 1..maximum)
    val output = ByteArrayOutputStream(minOf(size, 8192).toInt()); val block = ByteArray(AcpProviderDnsBuildInputs.BLOCK)
    var total = 0L
    while (true) { checkpoint(); val n = input.read(block, 0, minOf(block.size.toLong(), size - total + 1).toInt()); if (n < 0) break
        require(n > 0); total = dnsCharge(total, n.toLong(), size); output.write(block, 0, n) }
    require(total == size); return output.toByteArray()
}
private fun dnsBlock(input: InputStream, size: Int): ByteArray? {
    val bytes = ByteArray(size); var offset = 0
    while (offset < size) { val n = input.read(bytes, offset, size - offset); if (n < 0) return if (offset == 0) null else error("truncated tar block")
        require(n > 0); offset += n }
    return bytes
}
private fun dnsHashMember(input: InputStream, size: Long): String {
    val hash = MessageDigest.getInstance("SHA-256"); val bytes = ByteArray(AcpProviderDnsBuildInputs.BLOCK); var left = size
    while (left > 0) { val n = input.read(bytes, 0, minOf(left, bytes.size.toLong()).toInt()); require(n > 0); hash.update(bytes, 0, n); left -= n }
    return dnsHex(hash.digest())
}
private fun dnsOctal(header: ByteArray, offset: Int, length: Int): Long {
    val text = header.copyOfRange(offset, offset + length).toString(Charsets.US_ASCII).trim('\u0000', ' ')
    require(text.matches(Regex("[0-7]+"))); return text.toLong(8)
}
private fun dnsTarText(header: ByteArray, offset: Int, length: Int): String {
    val bytes = header.copyOfRange(offset, offset + length); val zero = bytes.indexOf(0).let { if (it < 0) bytes.size else it }
    require(bytes.drop(zero).all { it == 0.toByte() })
    return bytes.copyOfRange(0, zero).decodeToString(throwOnInvalidSequence = true)
}

/** Single RFC1952 member; reject optional header extensions, concatenation and ignored trailing bytes. */
private class DnsGzipInput(input: InputStream) : InputStream() {
    private val input = PushbackInputStream(input, AcpProviderDnsBuildInputs.BLOCK)
    private val inflater: Inflater
    private val crc = CRC32()
    private val compressed = ByteArray(AcpProviderDnsBuildInputs.BLOCK)
    private var lastInput = 0
    private var produced = 0L
    private var finished = false
    init {
        val h = requireNotNull(dnsBlock(this.input, 10))
        require(h[0] == 0x1f.toByte() && h[1] == 0x8b.toByte() && h[2] == 8.toByte() && h[3] == 0.toByte())
        inflater = Inflater(true)
    }
    override fun read(): Int { val b = ByteArray(1); return if (read(b, 0, 1) < 0) -1 else b[0].toInt() and 255 }
    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) return 0
        if (finished) return -1
        while (true) {
            if (inflater.needsInput()) {
                lastInput = input.read(compressed)
                require(lastInput > 0)
                inflater.setInput(compressed, 0, lastInput)
            }
            val n = inflater.inflate(bytes, offset, minOf(length, AcpProviderDnsBuildInputs.BLOCK))
            if (n > 0) { crc.update(bytes, offset, n); produced = Math.addExact(produced, n.toLong()); return n }
            require(!inflater.needsDictionary())
            if (inflater.finished()) {
                val remaining = inflater.remaining
                if (remaining > 0) input.unread(compressed, lastInput - remaining, remaining)
                val trailer = requireNotNull(dnsBlock(input, 8))
                fun little(at: Int) = (0..3).fold(0L) { value, i -> value or ((trailer[at + i].toLong() and 255) shl (8 * i)) }
                require(little(0) == crc.value && little(4) == (produced and 0xffffffffL) && input.read() == -1)
                finished = true; return -1
            }
            require(inflater.needsInput())
        }
    }
    override fun close() { inflater.end() }
}

internal fun dnsDomainHash(domain: String, document: JsonObject): String {
    fun canonical(value: JsonElement): JsonElement = when (value) {
        is JsonObject -> JsonObject(value.toSortedMap().mapValues { canonical(it.value) })
        is JsonArray -> JsonArray(value.map(::canonical))
        else -> value
    }
    val bytes = canonical(document).toString().toByteArray()
    require(bytes.size <= AcpProviderDnsBuildInputs.JSON_BYTES)
    return dnsSha(domain.toByteArray() + byteArrayOf(0) + java.nio.ByteBuffer.allocate(4).putInt(bytes.size).array() + bytes)
}
