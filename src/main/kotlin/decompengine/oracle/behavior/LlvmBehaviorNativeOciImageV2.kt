package decompengine.oracle.behavior

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import io.airlift.compress.zstd.ZstdInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.math.BigDecimal
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Base64
import java.util.Collections
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream

internal class LlvmBehaviorNativeOciImageV2Exception(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Raw, descriptor-retained image measurement. It grants no reference, Docker, START, observation,
 * scoring, or release authority. Filesystem nodes are modelled, never extracted onto the host.
 */
internal object LlvmBehaviorNativeOciImageV2 {
    internal data class Layer(
        val blobSha256: String,
        val blobBytes: Long,
        val mediaType: String,
        val diffId: String,
        val uncompressedBytes: Long,
    )

    internal data class Entry(
        val path: String,
        val kind: String,
        val mode: Long,
        val uid: Long,
        val gid: Long,
        val modificationTime: String,
        val size: Long,
        val contentSha256: String?,
        val linkTarget: String?,
        val deviceMajor: Long,
        val deviceMinor: Long,
        /** Exact binary attribute values, represented without lossy UTF-8 conversion. */
        val xattrs: Map<String, String>,
        /** Other PAX values are retained as exact byte strings, including platform attributes. */
        val pax: Map<String, String>,
        /** Equal identifiers designate actual hardlink aliases, not merely equal file bytes. */
        val inode: Long,
        val metadataOrigin: String = "tar-header",
        val modeKnown: Boolean = true,
        val ownershipKnown: Boolean = true,
        val modificationTimeKnown: Boolean = true,
    )

    internal data class FileRange(val offset: Long, val length: Int)

    internal class MeasuredImage private constructor(
        val indexSha256: String,
        val indexBytes: Long,
        val manifestSha256: String,
        val manifestBytes: Long,
        val configSha256: String,
        val configBytes: Long,
        val config: JsonObject,
        val layers: List<Layer>,
        val namespace: Map<String, Entry>,
        val namespaceSha256: String,
        private val owner: LayoutOwner,
        private val contentLocations: Map<Long, ContentLocation>,
    ) : AutoCloseable {
        private var closed = false

        @Synchronized
        fun requireCurrent(checkpoint: (String) -> Unit = {}) {
            check(!closed) { "raw OCI image measurement is closed" }
            owner.requireCurrent(checkpoint)
        }

        /** Container-root resolution; absolute links never become host paths. */
        @Synchronized
        fun resolve(containerPath: String): Entry {
            check(!closed) { "raw OCI image measurement is closed" }
            return namespace[resolvePath(namespace, containerPath, followFinal = true)]
                ?: imageFail("container path is absent: $containerPath")
        }

        /** Bounded selected-file reading through a retained layer descriptor, with terminal checks. */
        @Synchronized
        fun readFile(containerPath: String, maximumBytes: Int, checkpoint: (String) -> Unit = {}): ByteArray {
            require(maximumBytes in 1..MAXIMUM_SELECTED_FILE_BYTES)
            requireCurrent(checkpoint)
            val entry = resolve(containerPath)
            if (entry.kind != "regular" || entry.size > maximumBytes) {
                imageFail("selected container file is not a bounded regular file: $containerPath")
            }
            val location = contentLocations[entry.inode] ?: imageFail("selected file has no retained content source")
            val guard = owner.files[location.blobPath] ?: imageFail("selected file layer is not retained")
            val budget = ByteBudget(MAXIMUM_UNCOMPRESSED_BYTES, checkpoint)
            var found: ByteArray? = null
            openDecoded(guard.slice(), location.mediaType, checkpoint).use { decoded ->
                val reader = RawTarReader(CountingInput(decoded, budget), MetadataBudget(), checkpoint)
                while (true) {
                    val member = reader.next() ?: break
                    if (member.ordinal == location.ordinal) {
                        if (member.kind != "regular" || member.size != entry.size) imageFail("retained file metadata drifted")
                        found = reader.readBytes(maximumBytes)
                        break
                    }
                    reader.drain()
                }
            }
            val bytes = found ?: imageFail("selected file is absent from its retained layer")
            if (OracleArtifacts.sha256(bytes) != entry.contentSha256) imageFail("selected retained file bytes changed")
            requireCurrent(checkpoint)
            return bytes
        }

        fun readFileRange(containerPath: String, offset: Long, length: Int, checkpoint: (String) -> Unit = {}): ByteArray =
            readFileRanges(containerPath, listOf(FileRange(offset, length)), checkpoint).single()

        /**
         * Bounded selected ranges, preserving caller order. Plain tar payloads use positional reads;
         * compressed payloads are decoded once per batch, never retained as a whole-file byte array.
         * Retained read leases, mutation watches, named identities and ctimes protect each read. The
         * coordinator must also call requireCurrent at the complete measurement's terminal boundary.
         */
        @Synchronized
        fun readFileRanges(containerPath: String, ranges: List<FileRange>, checkpoint: (String) -> Unit = {}): List<ByteArray> {
            check(!closed) { "raw OCI image measurement is closed" }
            if (ranges.size !in 1..MAXIMUM_FILE_RANGES || ranges.sumOf { it.length.toLong() } > MAXIMUM_FILE_RANGE_BYTES) {
                imageFail("selected file range count or aggregate bytes exceed their limit")
            }
            owner.requireStructureCurrent(checkpoint)
            val entry = resolve(containerPath)
            if (entry.kind != "regular") imageFail("selected container range is not a regular file")
            ranges.forEach { range ->
                if (range.offset < 0L || range.length !in 0..MAXIMUM_FILE_RANGE_BYTES || range.offset > entry.size - range.length) {
                    imageFail("selected file range exceeds its authenticated file")
                }
            }
            val location = contentLocations[entry.inode] ?: imageFail("selected file range has no retained source")
            val guard = owner.files[location.blobPath] ?: imageFail("selected file range source is not retained")
            guard.requireSingleLink("before selected OCI file range read")
            val result = if (location.mediaType in UNCOMPRESSED_LAYER_MEDIA_TYPES) {
                ranges.map { range ->
                    guard.readExactly(Math.addExact(location.dataOffset, range.offset), range.length, "selected OCI file range", checkpoint)
                }
            } else {
                val output = ranges.map { ByteArray(it.length) }
                var found = false
                openDecoded(guard.slice(), location.mediaType, checkpoint).use { decoded ->
                    val reader = RawTarReader(CountingInput(decoded, ByteBudget(MAXIMUM_UNCOMPRESSED_BYTES, checkpoint)), MetadataBudget(), checkpoint)
                    while (true) {
                        val member = reader.next() ?: break
                        if (member.ordinal != location.ordinal) { reader.drain(); continue }
                        if (member.kind != "regular" || member.size != entry.size || member.dataOffset != location.dataOffset) imageFail("retained range source metadata drifted")
                        var position = 0L
                        reader.transfer { bytes, count ->
                            val end = position + count
                            ranges.forEachIndexed { index, range ->
                                val start = maxOf(position, range.offset)
                                val stop = minOf(end, range.offset + range.length)
                                if (start < stop) bytes.copyInto(output[index], (start - range.offset).toInt(), (start - position).toInt(), (stop - position).toInt())
                            }
                            position = end
                        }
                        found = true
                        break
                    }
                }
                if (!found) imageFail("selected range source is absent from its retained layer")
                output
            }
            guard.requireSingleLink("after selected OCI file range read")
            owner.requireStructureCurrent(checkpoint)
            checkpoint("after selected OCI file range read")
            return immutableList(result)
        }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            owner.close()
        }

        internal companion object {
            fun create(
                index: StableControlFile,
                manifest: StableControlFile,
                configGuard: StableControlFile,
                config: JsonObject,
                layers: List<Layer>,
                model: NamespaceModel,
                owner: LayoutOwner,
                checkpoint: (String) -> Unit,
            ): MeasuredImage = MeasuredImage(
                index.authenticatedSha256, index.size, manifest.authenticatedSha256, manifest.size,
                configGuard.authenticatedSha256, configGuard.size, config,
                immutableList(layers), immutableMap(model.entries), namespaceDigest(model.entries, checkpoint),
                owner, immutableMap(model.locations),
            )
        }
    }

    internal data class DockerExportMeasurement(
        val exportSha256: String,
        val exportBytes: Long,
        val configSha256: String,
        val configBytes: Long,
        val layerDiffIds: List<String>,
        val layerBytes: List<Long>,
        val namespaceSha256: String,
    )

    fun openLayout(root: Path, checkpoint: (String) -> Unit = {}): MeasuredImage {
        val owner = LayoutOwner.open(root, checkpoint)
        try {
            val header = parseGuard(owner.file("oci-layout"), checkpoint)
            if (header["imageLayoutVersion"] != JsonPrimitive("1.0.0")) imageFail("unsupported OCI layout version")
            val indexGuard = owner.file("index.json")
            val index = parseGuard(indexGuard, checkpoint)
            val selected = selectManifest(index, owner, checkpoint, 0)
            val manifestGuard = selected.first
            val manifest = selected.second
            requireSchemaTwo(manifest, "image manifest")
            val configDescriptor = descriptor(manifest["config"] as? JsonObject ?: imageFail("image config descriptor is absent"))
            if (configDescriptor.mediaType !in CONFIG_MEDIA_TYPES) imageFail("unsupported image config media type")
            val configGuard = owner.authenticate(configDescriptor)
            val config = parseGuard(configGuard, checkpoint)
            if (string(config, "os") != "linux" || string(config, "architecture") != "amd64") {
                imageFail("native image must be linux/amd64")
            }
            val rootfs = config["rootfs"] as? JsonObject ?: imageFail("image config rootfs is absent")
            if (string(rootfs, "type") != "layers") imageFail("image config rootfs is not layered")
            val diffIds = (rootfs["diff_ids"] as? JsonArray ?: imageFail("image config diff_ids are absent"))
                .map { digest((it as? JsonPrimitive)?.takeIf { value -> value.isString }?.content ?: imageFail("invalid diffID")) }
            val descriptors = (manifest["layers"] as? JsonArray ?: imageFail("image layers are absent"))
                .map { descriptor(it as? JsonObject ?: imageFail("invalid layer descriptor")) }
            if (descriptors.size !in 1..MAXIMUM_LAYERS || diffIds.size != descriptors.size) imageFail("image layer count or diffID order is invalid")
            val metadata = MetadataBudget()
            val model = NamespaceModel(metadata)
            val layers = ArrayList<Layer>()
            val aggregate = ByteBudget(MAXIMUM_UNCOMPRESSED_BYTES, checkpoint)
            descriptors.forEachIndexed { layerIndex, descriptor ->
                if (descriptor.mediaType !in LAYER_MEDIA_TYPES) imageFail("unsupported image layer media type")
                val blob = owner.authenticate(descriptor)
                val sha = MessageDigest.getInstance("SHA-256")
                val counted = CountingInput(openDecoded(blob.slice(), descriptor.mediaType, checkpoint), aggregate, sha)
                counted.use { stream ->
                    val reader = RawTarReader(stream, metadata, checkpoint)
                    model.applyLayer(reader, "blobs/sha256/${descriptor.sha256}", descriptor.mediaType)
                    reader.finish()
                }
                val actualDiffId = hex(sha.digest())
                if (actualDiffId != diffIds[layerIndex]) imageFail("layer uncompressed diffID differs from image config")
                layers += Layer(descriptor.sha256, descriptor.size, descriptor.mediaType, actualDiffId, counted.bytes)
            }
            val measured = MeasuredImage.create(indexGuard, manifestGuard, configGuard, config, layers, model, owner, checkpoint)
            owner.requireCurrent(checkpoint)
            return measured
        } catch (failure: Throwable) {
            owner.close()
            throw failure
        }
    }

    /**
     * Measures a classic Docker save/export tar without extraction or whole-image buffering.
     * Ordered uncompressed layer bytes and exact config bytes must match the retained OCI image.
     * All regular members are hashed before the manifest is interpreted, allowing arbitrary order.
     */
    fun readDockerExport(
        input: InputStream,
        expected: MeasuredImage,
        checkpoint: (String) -> Unit = {},
    ): DockerExportMeasurement {
        expected.requireCurrent(checkpoint)
        val sha = MessageDigest.getInstance("SHA-256")
        val counted = CountingInput(input, ByteBudget(MAXIMUM_RAW_BYTES, checkpoint), sha)
        val reader = RawTarReader(counted, MetadataBudget(), checkpoint)
        val members = LinkedHashMap<String, ExportMember>()
        val allNames = HashSet<String>()
        var retainedJsonBytes = 0L
        while (true) {
            val member = reader.next() ?: break
            val name = archivePath(member.path).removePrefix("/")
            if (!allNames.add(name)) imageFail("Docker export has duplicate normalized member names")
            if (member.kind == "directory") { reader.drain(); continue }
            if (member.kind != "regular" || name.isEmpty()) imageFail("Docker export contains a non-regular payload member")
            if (members.containsKey(name)) imageFail("Docker export has duplicate member names")
            val digest = MessageDigest.getInstance("SHA-256")
            // Only small JSON payloads are retained. Layer members are streamed into their digests.
            val jsonCandidate = name in setOf("manifest.json", "index.json", "oci-layout") ||
                name.endsWith(".json") || (BLOB_PATH.matches(name) && member.size <= MAXIMUM_JSON_BYTES)
            var json: ByteArrayOutputStream? = null
            var firstBuffer = true
            reader.transfer { buffer, length ->
                digest.update(buffer, 0, length)
                if (firstBuffer && jsonCandidate) {
                    val first = (0 until length).firstOrNull { buffer[it] !in JSON_WHITESPACE }
                    if (first == null || buffer[first] == '{'.code.toByte() || buffer[first] == '['.code.toByte()) {
                        json = ByteArrayOutputStream()
                    }
                    firstBuffer = false
                }
                if (json != null) {
                    if (json.size().toLong() + length > MAXIMUM_JSON_BYTES) imageFail("Docker export JSON exceeds its byte limit")
                    retainedJsonBytes += length
                    if (retainedJsonBytes > MAXIMUM_EXPORT_JSON_BYTES) imageFail("Docker export retained JSON exceeds its aggregate limit")
                    json.write(buffer, 0, length)
                }
            }
            members[name] = ExportMember(member.size, hex(digest.digest()), json?.toByteArray())
        }
        reader.finish()
        val layoutJson = members["oci-layout"]?.json ?: imageFail("Docker export OCI layout is absent")
        if (parseObject(layoutJson, checkpoint)["imageLayoutVersion"] != JsonPrimitive("1.0.0")) imageFail("Docker export OCI layout version is invalid")
        val indexJson = members["index.json"]?.json ?: imageFail("Docker export OCI index is absent")
        val exportManifest = selectExportManifest(parseObject(indexJson, checkpoint), members, checkpoint, 0)
        val configDescriptor = descriptor(exportManifest["config"] as? JsonObject ?: imageFail("Docker export OCI config descriptor is absent"))
        if (configDescriptor.mediaType !in CONFIG_MEDIA_TYPES) imageFail("Docker export OCI config media type is invalid")
        val descriptorConfig = authenticateExportBlob(configDescriptor, members)
        if (descriptorConfig.sha256 != expected.configSha256 || descriptorConfig.bytes != expected.configBytes) {
            imageFail("Docker export OCI config differs from retained raw OCI config")
        }
        val descriptorLayers = (exportManifest["layers"] as? JsonArray ?: imageFail("Docker export OCI layers are absent"))
            .map { descriptor(it as? JsonObject ?: imageFail("invalid Docker export OCI layer descriptor")) }
        if (descriptorLayers.size != expected.layers.size) imageFail("Docker export OCI layer count differs")
        descriptorLayers.forEachIndexed { index, layer ->
            // The pinned classic Docker exporter serializes each layer as its uncompressed tar.
            if (layer.mediaType != "application/vnd.oci.image.layer.v1.tar") imageFail("Docker classic export layer is not an uncompressed OCI tar")
            val member = authenticateExportBlob(layer, members)
            if (member.sha256 != expected.layers[index].diffId || member.bytes != expected.layers[index].uncompressedBytes) {
                imageFail("Docker export OCI ordered layer bytes differ from retained raw OCI")
            }
        }
        val manifestBytes = members["manifest.json"]?.json ?: imageFail("Docker export manifest.json is absent")
        val manifest = OracleJson.parse(manifestBytes, JSON_LIMITS, checkpoint) as? JsonArray
            ?: imageFail("Docker export manifest is not an array")
        if (manifest.size != 1) imageFail("Docker export must describe exactly one selected image")
        val image = manifest.single() as? JsonObject ?: imageFail("invalid Docker export image manifest")
        val configName = archivePath(string(image, "Config")).removePrefix("/")
        val configMember = members[configName] ?: imageFail("Docker export config is absent")
        if (configMember.sha256 != expected.configSha256 || configMember.bytes != expected.configBytes) {
            imageFail("Docker export config bytes do not match raw OCI config")
        }
        val layerNames = (image["Layers"] as? JsonArray ?: imageFail("Docker export layers are absent"))
            .map { archivePath((it as? JsonPrimitive)?.takeIf { value -> value.isString }?.content ?: imageFail("invalid Docker layer name")).removePrefix("/") }
        if (layerNames.size != expected.layers.size || layerNames.toSet().size != layerNames.size) imageFail("Docker export layer order/count is invalid")
        val exportedLayers = layerNames.map { name -> members[name] ?: imageFail("Docker export layer is absent") }
        exportedLayers.forEachIndexed { index, member ->
            val layer = expected.layers[index]
            if (member.sha256 != layer.diffId || member.bytes != layer.uncompressedBytes) {
                imageFail("Docker export ordered uncompressed layer bytes differ from retained OCI")
            }
            if (member != authenticateExportBlob(descriptorLayers[index], members)) imageFail("Docker compatibility manifest and OCI index disagree")
        }
        expected.requireCurrent(checkpoint)
        return DockerExportMeasurement(
            hex(sha.digest()), counted.bytes, configMember.sha256, configMember.bytes,
            immutableList(exportedLayers.map { it.sha256 }), immutableList(exportedLayers.map { it.bytes }),
            expected.namespaceSha256,
        )
    }

    private data class ExportMember(val bytes: Long, val sha256: String, val json: ByteArray?)

    private fun authenticateExportBlob(descriptor: BlobDescriptor, members: Map<String, ExportMember>): ExportMember {
        val member = members["blobs/sha256/${descriptor.sha256}"] ?: imageFail("Docker export OCI descriptor blob is absent")
        if (member.bytes != descriptor.size || member.sha256 != descriptor.sha256) imageFail("Docker export OCI descriptor length or digest is invalid")
        return member
    }

    private fun selectExportManifest(
        index: JsonObject,
        members: Map<String, ExportMember>,
        checkpoint: (String) -> Unit,
        depth: Int,
    ): JsonObject {
        if (depth > MAXIMUM_INDEX_DEPTH) imageFail("Docker export OCI index nesting exceeds its limit")
        requireSchemaTwo(index, "Docker export OCI index")
        val descriptors = index["manifests"] as? JsonArray ?: imageFail("Docker export OCI index manifests are absent")
        if (descriptors.size !in 1..MAXIMUM_BLOBS) imageFail("Docker export OCI index descriptor count is invalid")
        val manifests = ArrayList<JsonObject>()
        descriptors.forEach { element ->
            val json = element as? JsonObject ?: imageFail("invalid Docker export OCI index descriptor")
            val descriptor = descriptor(json)
            val member = authenticateExportBlob(descriptor, members)
            val platform = json["platform"] as? JsonObject
            if (platform != null && (string(platform, "os") != "linux" || string(platform, "architecture") != "amd64")) return@forEach
            val payload = member.json ?: imageFail("Docker export OCI manifest/index JSON is absent")
            when (descriptor.mediaType) {
                in INDEX_MEDIA_TYPES -> manifests += selectExportManifest(parseObject(payload, checkpoint), members, checkpoint, depth + 1)
                in MANIFEST_MEDIA_TYPES -> {
                    val manifest = parseObject(payload, checkpoint)
                    requireSchemaTwo(manifest, "Docker export OCI manifest")
                    val config = descriptor(manifest["config"] as? JsonObject ?: imageFail("Docker export manifest config is absent"))
                    val configBytes = authenticateExportBlob(config, members).json ?: imageFail("Docker export config JSON is absent")
                    val actual = parseObject(configBytes, checkpoint)
                    if (string(actual, "os") == "linux" && string(actual, "architecture") == "amd64") manifests += manifest
                }
                else -> imageFail("Docker export OCI index media type is invalid")
            }
        }
        if (manifests.size != 1) imageFail("Docker export OCI index does not select one linux/amd64 image")
        return manifests.single()
    }
    internal data class BlobDescriptor(val sha256: String, val size: Long, val mediaType: String)
    internal data class ContentLocation(val blobPath: String, val mediaType: String, val ordinal: Int, val dataOffset: Long)

    internal class LayoutOwner private constructor(
        private val root: Path,
        private val rootDescriptor: LinuxDescriptor,
        private val names: Set<String>,
        val files: Map<String, StableControlFile>,
    ) : AutoCloseable {
        private var closed = false

        fun file(name: String): StableControlFile = files[name] ?: imageFail("raw OCI file is absent: $name")

        private fun currentNames(checkpoint: (String) -> Unit): Set<String> = listLayout(root, checkpoint)

        fun requireCurrent(checkpoint: (String) -> Unit) {
            check(!closed) { "raw OCI layout owner is closed" }
            checkpoint("before raw OCI terminal identity and byte authentication")
            requireStructureCurrent(checkpoint)
            files.forEach { (name, guard) ->
                checkpoint("before raw OCI member terminal authentication: $name")
                guard.verifyUnchanged("raw OCI member $name")
            }
            requireStructureCurrent(checkpoint)
            checkpoint("after raw OCI terminal identity and byte authentication")
        }

        fun requireStructureCurrent(checkpoint: (String) -> Unit) {
            check(!closed) { "raw OCI layout owner is closed" }
            checkpoint("before raw OCI layout namespace identity check")
            LinuxFilesystemSyscalls.openRoot(root).use { named ->
                if (LinuxFilesystemSyscalls.identity(named.fd) != LinuxFilesystemSyscalls.identity(rootDescriptor.fd)) {
                    imageFail("raw OCI directory identity changed")
                }
            }
            if (currentNames(checkpoint) != names) imageFail("raw OCI namespace members changed")
            checkpoint("after raw OCI layout namespace identity check")
        }

        private fun authenticateInternal(descriptor: BlobDescriptor): StableControlFile {
            val guard = file("blobs/sha256/${descriptor.sha256}")
            if (guard.size != descriptor.size || guard.authenticatedSha256 != descriptor.sha256) {
                imageFail("raw OCI descriptor digest or length differs from retained blob")
            }
            return guard
        }

        internal fun authenticate(descriptor: BlobDescriptor): StableControlFile = authenticateInternal(descriptor)

        override fun close() {
            if (closed) return
            closed = true
            files.values.toList().asReversed().forEach { it.close() }
            rootDescriptor.close()
        }

        companion object {
            fun open(rawRoot: Path, checkpoint: (String) -> Unit): LayoutOwner {
                val root = rawRoot.toAbsolutePath().normalize()
                checkpoint("before raw OCI directory selection")
                val retainedRoot = LinuxFilesystemSyscalls.openRoot(root)
                val guards = LinkedHashMap<String, StableControlFile>()
                try {
                    val names = listLayout(root, checkpoint)
                    var total = 0L
                    names.sorted().forEach { name ->
                        checkpoint("before raw OCI member selection: $name")
                        val guard = StableControlFile.openWithCheckpoint(root.resolve(name), MAXIMUM_RAW_BYTES, "raw OCI member $name", checkpoint)
                        guards[name] = guard
                        total = Math.addExact(total, guard.size)
                        if (total > MAXIMUM_RAW_BYTES) imageFail("raw OCI aggregate bytes exceed their limit")
                        if (name.startsWith("blobs/sha256/") && guard.authenticatedSha256 != name.substringAfterLast('/')) {
                            imageFail("raw OCI blob name does not authenticate its exact bytes")
                        }
                    }
                    return LayoutOwner(root, retainedRoot, immutableSet(names), immutableMap(guards)).also { it.requireCurrent(checkpoint) }
                } catch (failure: Throwable) {
                    guards.values.toList().asReversed().forEach { it.close() }
                    retainedRoot.close()
                    throw failure
                }
            }
        }
    }

    private fun listLayout(root: Path, checkpoint: (String) -> Unit): Set<String> {
        val names = LinkedHashSet<String>()
        Files.walk(root, 4).use { paths ->
            paths.forEach { path ->
                checkpoint("while enumerating raw OCI layout")
                val relative = root.relativize(path).toString().replace('\\', '/')
                if (relative.isEmpty()) return@forEach
                if (Files.isSymbolicLink(path)) imageFail("raw OCI layout contains a host symlink")
                if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                    if (relative !in setOf("blobs", "blobs/sha256")) imageFail("raw OCI layout contains an unsupported directory")
                } else {
                    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) imageFail("raw OCI layout contains a non-regular blob")
                    if (relative !in setOf("oci-layout", "index.json") && !BLOB_PATH.matches(relative)) imageFail("raw OCI layout member is not a SHA-256 blob")
                    if (!names.add(relative) || names.size > MAXIMUM_BLOBS) imageFail("raw OCI layout member count exceeds its limit")
                }
            }
        }
        if (!names.containsAll(setOf("oci-layout", "index.json")) || !Files.isDirectory(root.resolve("blobs/sha256"), LinkOption.NOFOLLOW_LINKS)) {
            imageFail("raw OCI layout is incomplete")
        }
        return names
    }

    private fun selectManifest(index: JsonObject, owner: LayoutOwner, checkpoint: (String) -> Unit, depth: Int): Pair<StableControlFile, JsonObject> {
        if (depth > MAXIMUM_INDEX_DEPTH) imageFail("OCI image indexes exceed their nesting limit")
        requireSchemaTwo(index, "image index")
        val manifests = index["manifests"] as? JsonArray ?: imageFail("OCI image index manifests are absent")
        if (manifests.size !in 1..MAXIMUM_BLOBS) imageFail("OCI index descriptor count is invalid")
        val candidates = ArrayList<Pair<StableControlFile, JsonObject>>()
        manifests.forEach { element ->
            val json = element as? JsonObject ?: imageFail("invalid OCI index descriptor")
            val descriptor = descriptor(json)
            val guard = owner.authenticate(descriptor)
            val platform = json["platform"] as? JsonObject
            if (platform != null && (string(platform, "os") != "linux" || string(platform, "architecture") != "amd64")) return@forEach
            when (descriptor.mediaType) {
                in INDEX_MEDIA_TYPES -> candidates += selectManifest(parseGuard(guard, checkpoint), owner, checkpoint, depth + 1)
                in MANIFEST_MEDIA_TYPES -> {
                    val manifest = parseGuard(guard, checkpoint)
                    val config = descriptor(manifest["config"] as? JsonObject ?: imageFail("OCI manifest config is absent"))
                    val actual = parseGuard(owner.authenticate(config), checkpoint)
                    if (string(actual, "os") == "linux" && string(actual, "architecture") == "amd64") candidates += guard to manifest
                }
                else -> imageFail("unsupported OCI index descriptor media type")
            }
        }
        if (candidates.size != 1) imageFail("OCI layout does not select exactly one linux/amd64 image")
        return candidates.single()
    }

    private fun descriptor(json: JsonObject): BlobDescriptor {
        val size = (json["size"] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull ?: imageFail("OCI descriptor size is absent")
        if (size !in 1..MAXIMUM_RAW_BYTES) imageFail("OCI descriptor byte length is invalid")
        return BlobDescriptor(digest(string(json, "digest")), size, string(json, "mediaType"))
    }

    private fun parseGuard(guard: StableControlFile, checkpoint: (String) -> Unit): JsonObject {
        if (guard.size > MAXIMUM_JSON_BYTES) imageFail("raw OCI JSON exceeds its byte limit")
        return parseObject(guard.readExactly(0, guard.size.toInt(), "raw OCI JSON", checkpoint), checkpoint)
    }

    private fun parseObject(bytes: ByteArray, checkpoint: (String) -> Unit): JsonObject =
        OracleJson.parse(bytes, JSON_LIMITS, checkpoint) as? JsonObject ?: imageFail("raw OCI JSON is not an object")

    private fun requireSchemaTwo(json: JsonObject, label: String) {
        if (json["schemaVersion"] != JsonPrimitive(2)) imageFail("unsupported $label schema version")
    }

    private fun string(json: JsonObject, name: String): String =
        (json[name] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: imageFail("required image string is absent: $name")

    private fun digest(value: String): String =
        value.takeIf { DIGEST.matches(it) }?.removePrefix("sha256:") ?: imageFail("image digest is not canonical SHA-256")

    private fun openDecoded(input: InputStream, mediaType: String, checkpoint: (String) -> Unit): InputStream {
        val encoded = CountingInput(input, ByteBudget(MAXIMUM_RAW_BYTES, checkpoint))
        return when {
        mediaType.endsWith("+gzip") || mediaType == "application/vnd.docker.image.rootfs.diff.tar.gzip" ->
            GzipCompressorInputStream.builder().setInputStream(encoded).setDecompressConcatenated(true).get()
        // Validate all frame windows and encoded block lengths before the incremental Java decoder
        // sees them. Its compressed-block window check alone does not protect raw/RLE frames.
        mediaType.endsWith("+zstd") -> ZstdInputStream(BoundedZstdFrames(encoded))
        mediaType in LAYER_MEDIA_TYPES -> encoded
        else -> imageFail("unsupported layer compression")
        }
    }

    /** Pass-through Zstandard frame scanner; it buffers only a frame or block header (at most 18B). */
    internal class BoundedZstdFrames(private val input: InputStream) : InputStream() {
        private enum class Next { FRAME, BLOCK, CHECKSUM }
        private var next = Next.FRAME
        private var queued = ByteArray(0)
        private var queuedOffset = 0
        private var payload = 0L
        private var checksum = false
        private var ended = false

        override fun read(): Int {
            val byte = ByteArray(1)
            return if (read(byte, 0, 1) < 0) -1 else byte[0].toInt() and 0xff
        }

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            if (offset < 0 || length < 0 || offset > buffer.size - length) throw IndexOutOfBoundsException()
            if (length == 0) return 0
            // Fill the decoder's bounded request across validated metadata segments, or EOF.
            var consumed = 0
            while (consumed < length) {
                val count = readPart(buffer, offset + consumed, length - consumed)
                if (count < 0) return if (consumed == 0) -1 else consumed
                consumed += count
            }
            return consumed
        }

        private fun readPart(buffer: ByteArray, offset: Int, length: Int): Int {
            if (ended) return -1
            if (queuedOffset == queued.size && payload == 0L && !load()) return -1
            if (queuedOffset < queued.size) {
                val count = minOf(length, queued.size - queuedOffset)
                queued.copyInto(buffer, offset, queuedOffset, queuedOffset + count)
                queuedOffset += count
                return count
            }
            val count = input.read(buffer, offset, minOf(length.toLong(), payload, BUFFER_BYTES.toLong()).toInt())
            if (count <= 0) imageFail("Zstandard encoded block ends prematurely")
            payload -= count
            return count
        }

        private fun load(): Boolean {
            if (ended) return false
            queuedOffset = 0
            when (next) {
                Next.FRAME -> {
                    val magic = exact(4, true)
                    if (magic.isEmpty()) { queued = ByteArray(0); ended = true; return false }
                    if (!magic.contentEquals(byteArrayOf(0x28, 0xb5.toByte(), 0x2f, 0xfd.toByte()))) imageFail("Zstandard frame magic is invalid or unsupported")
                    val header = ByteArrayOutputStream(18)
                    header.write(magic)
                    val descriptor = exact(1, false).also(header::write).single().toInt() and 0xff
                    if ((descriptor and 0x18) != 0) imageFail("Zstandard frame reserved flags are set")
                    val single = (descriptor and 0x20) != 0
                    checksum = (descriptor and 4) != 0
                    val window = if (single) null else {
                        val value = exact(1, false).also(header::write).single().toInt() and 0xff
                        val base = 1L shl (10 + (value ushr 3))
                        base + (base ushr 3) * (value and 7)
                    }
                    val dictionaryBytes = when (descriptor and 3) { 0 -> 0; 1 -> 1; 2 -> 2; else -> 4 }
                    val dictionary = exact(dictionaryBytes, false).also(header::write)
                    if (dictionary.any { it != 0.toByte() }) imageFail("dictionary-dependent Zstandard layers are unsupported")
                    val contentFlag = descriptor ushr 6
                    val contentBytes = when (contentFlag) { 0 -> if (single) 1 else 0; 1 -> 2; 2 -> 4; else -> 8 }
                    val content = exact(contentBytes, false).also(header::write)
                    var contentSize = if (content.isEmpty()) null else BigInteger(1, content.reversedArray())
                    if (contentFlag == 1) contentSize = contentSize!!.add(BigInteger.valueOf(256))
                    if (contentSize != null && contentSize > BigInteger.valueOf(MAXIMUM_UNCOMPRESSED_BYTES)) imageFail("Zstandard frame declares too many decompressed bytes")
                    val actualWindow = window ?: contentSize?.longValueExact() ?: imageFail("Zstandard single-segment content size is absent")
                    if (actualWindow > MAXIMUM_ZSTD_WINDOW_BYTES) imageFail("Zstandard frame window exceeds its 8 MiB limit")
                    queued = header.toByteArray()
                    next = Next.BLOCK
                }
                Next.BLOCK -> {
                    queued = exact(3, false)
                    val word = (queued[0].toInt() and 0xff) or ((queued[1].toInt() and 0xff) shl 8) or ((queued[2].toInt() and 0xff) shl 16)
                    val type = (word ushr 1) and 3
                    val size = word ushr 3
                    if (type == 3 || size > MAXIMUM_ZSTD_BLOCK_BYTES) imageFail("Zstandard block type or byte length exceeds its limit")
                    payload = if (type == 1) 1 else size.toLong()
                    next = if ((word and 1) == 0) Next.BLOCK else if (checksum) Next.CHECKSUM else Next.FRAME
                }
                Next.CHECKSUM -> { queued = exact(4, false); next = Next.FRAME }
            }
            return true
        }

        private fun exact(size: Int, cleanEof: Boolean): ByteArray {
            val bytes = ByteArray(size)
            var position = 0
            while (position < size) {
                val count = input.read(bytes, position, size - position)
                if (count <= 0) {
                    if (cleanEof && position == 0 && count < 0) return ByteArray(0)
                    imageFail("Zstandard frame metadata ends prematurely")
                }
                position += count
            }
            return bytes
        }

        override fun close() = input.close()
    }

    internal class NamespaceModel(private val metadata: MetadataBudget) {
        val entries = TreeMap<String, Entry>()
        val locations = LinkedHashMap<Long, ContentLocation>()
        private var nextInode = 1L
        private val inodePaths = HashMap<Long, MutableSet<String>>()

        init {
            metadata.charge(1024)
            put(Entry("/", "directory", 0, 0, 0, "unrecorded", 0, null, null, 0, 0,
                emptyMap(), emptyMap(), nextInode++, "container-root", false, false, false))
        }

        fun applyLayer(reader: RawTarReader, blobPath: String, mediaType: String) {
            // Retain this layer's metadata only. Its file bytes are hashed as they pass through.
            val changes = ArrayList<Pair<TarMember, String?>>()
            val names = HashSet<String>()
            while (true) {
                val member = reader.next() ?: break
                val path = archivePath(member.path)
                if (path == "/" && member.kind != "directory") imageFail("OCI root entry must be a directory")
                if (!names.add(path)) imageFail("OCI layer contains duplicate normalized paths")
                val basename = path.substringAfterLast('/')
                if (basename.startsWith(".wh.")) {
                    if (member.kind != "regular" || member.size != 0L || basename == ".wh.") imageFail("invalid OCI whiteout")
                    if (basename.removePrefix(".wh.") in setOf(".", "..")) imageFail("whiteout cannot remove an ancestor directory")
                    reader.drain()
                    changes += member.copy(path = path) to null
                } else {
                    val digest = if (member.kind == "regular") reader.hash() else { reader.drain(); null }
                    changes += member.copy(path = path) to digest
                }
            }
            // OCI whiteouts affect lower entries only, even if placed after creates in the tar.
            changes.forEach { (member, _) ->
                val basename = member.path.substringAfterLast('/')
                if (!basename.startsWith(".wh.")) return@forEach
                val parent = member.path.substringBeforeLast('/').ifEmpty { "/" }
                val resolvedParent = resolvePath(entries, parent, followFinal = true, allowMissing = true)
                if (basename == ".wh..wh..opq") removeDescendants(resolvedParent) else {
                    removeTree(join(resolvedParent, basename.removePrefix(".wh.")))
                }
            }
            val pending = ArrayList<TarMember>()
            changes.forEach { (member, sha) ->
                if (member.path.substringAfterLast('/').startsWith(".wh.")) return@forEach
                // The selected Docker extractor ignores tar entries naming the extraction root.
                if (member.path == "/") return@forEach
                val path = resolvePath(entries, member.path, followFinal = false, allowMissing = true)
                requireParentDirectories(path)
                val adjusted = member.copy(path = path)
                if (member.kind == "hardlink") {
                    val target = resolvePath(entries, hardlinkTarget(adjusted.linkTarget ?: imageFail("hardlink target is absent")), followFinal = false, allowMissing = true)
                    if (target == path) imageFail("hardlink target is removed by replacement of the same path")
                    val targetEntry = entries[target]
                    if (targetEntry == null) pending += adjusted else installHardlink(adjusted, targetEntry)
                } else {
                    val prior = entries[path]
                    if (member.kind != "directory" || entries[path]?.kind != "directory") removeTree(path)
                    val inode = nextInode++
                    put(Entry(
                        path, member.kind, if (member.kind == "symlink") 0x1ff else member.mode, member.uid, member.gid, member.mtime,
                        member.size, sha, member.linkTarget, member.major, member.minor,
                        immutableMap(if (member.kind == "directory" && prior?.kind == "directory") prior.xattrs + member.xattrs else member.xattrs), immutableMap(member.pax), inode,
                    ))
                    if (member.kind == "regular") locations[inode] = ContentLocation(blobPath, mediaType, member.ordinal, member.dataOffset)
                }
            }
            val unresolved = pending.associateByTo(LinkedHashMap()) { it.path }
            while (unresolved.isNotEmpty()) {
                val chain = ArrayList<TarMember>()
                val seen = HashSet<String>()
                var member = unresolved.values.first()
                var target: Entry
                while (true) {
                    if (!seen.add(member.path)) imageFail("OCI layer has a cyclic forward hardlink")
                    chain += member
                    val targetPath = resolvePath(entries, hardlinkTarget(member.linkTarget ?: imageFail("hardlink target is absent")), followFinal = false, allowMissing = true)
                    val existing = entries[targetPath]
                    if (existing != null) { target = existing; break }
                    member = unresolved[targetPath] ?: imageFail("OCI layer has a missing forward hardlink target")
                }
                chain.asReversed().forEach { link ->
                    installHardlink(link, target)
                    unresolved.remove(link.path)
                    target = entries[link.path] ?: imageFail("forward hardlink installation failed")
                }
            }
            // Entries through symlink parents are represented at their container-resolved locations.
            entries.keys.toList().forEach { requireParentDirectories(it) }
        }

        private fun installHardlink(member: TarMember, target: Entry) {
            if (target.kind == "directory") imageFail("OCI layer hardlinks a directory")
            removeTree(member.path)
            // Docker applies Lchown/xattrs to the link inode, then mode/mtime unless it is a symlink.
            // Every existing alias therefore observes the hardlink header's effective attributes.
            val attributes = immutableMap(target.xattrs + member.xattrs)
            val updated = target.copy(
                uid = member.uid, gid = member.gid,
                mode = if (target.kind == "symlink") target.mode else member.mode,
                modificationTime = if (target.kind == "symlink") target.modificationTime else member.mtime,
                xattrs = attributes, pax = immutableMap(target.pax + member.pax), metadataOrigin = "tar-hardlink-header",
            )
            inodePaths[target.inode]?.toList()?.forEach { alias -> entries[alias] = updated.copy(path = alias) }
            put(updated.copy(path = member.path))
        }

        private fun requireParentDirectories(path: String) {
            if (path == "/") return
            var parent = path.substringBeforeLast('/').ifEmpty { "/" }
            while (parent != "/") {
                val entry = entries[parent]
                if (entry != null && entry.kind != "directory") imageFail("OCI layer places a node beneath a non-directory")
                if (entry == null) {
                    metadata.charge(1024L + 4L * parent.encodeToByteArray().size)
                    // Numeric IDs are container IDs, before any host user-namespace mapping. The
                    // extractor fixes0755 but does not record a reproducible creation timestamp.
                    put(Entry(parent, "directory", 0x1ed, 0, 0, "unrecorded", 0, null, null, 0, 0,
                        emptyMap(), emptyMap(), nextInode++, "implied-directory", true, true, false))
                }
                parent = parent.substringBeforeLast('/').ifEmpty { "/" }
            }
        }

        private fun removeTree(path: String) {
            remove(path)
            removeDescendants(path)
        }

        private fun removeDescendants(path: String) {
            val prefix = if (path == "/") "/" else "$path/"
            var entry = entries.ceilingEntry(prefix)
            while (entry != null && entry.key.startsWith(prefix)) {
                if (entry.key != path) remove(entry.key)
                entry = entries.higherEntry(entry.key)
            }
        }

        private fun put(entry: Entry) {
            remove(entry.path)
            entries[entry.path] = entry
            inodePaths.getOrPut(entry.inode) { LinkedHashSet() }.add(entry.path)
        }

        private fun remove(path: String) {
            val old = entries.remove(path) ?: return
            val aliases = inodePaths[old.inode] ?: return
            aliases.remove(path)
            if (aliases.isEmpty()) inodePaths.remove(old.inode)
        }
    }

    private fun namespaceDigest(entries: Map<String, Entry>, checkpoint: (String) -> Unit): String {
        val digest = MessageDigest.getInstance("SHA-256")
        // A streaming commitment, not a giant serialization of all filesystem entries.
        entries.toSortedMap().forEach { (path, entry) ->
            checkpoint("while committing measured container namespace")
            val json = JsonObject(linkedMapOf(
                "path" to JsonPrimitive(path), "kind" to JsonPrimitive(entry.kind), "mode" to JsonPrimitive(entry.mode),
                "uid" to JsonPrimitive(entry.uid), "gid" to JsonPrimitive(entry.gid), "mtime" to JsonPrimitive(entry.modificationTime),
                "size" to JsonPrimitive(entry.size), "sha256" to JsonPrimitive(entry.contentSha256 ?: ""),
                "link" to JsonPrimitive(entry.linkTarget ?: ""), "major" to JsonPrimitive(entry.deviceMajor),
                "minor" to JsonPrimitive(entry.deviceMinor), "inode" to JsonPrimitive(entry.inode),
                "metadataOrigin" to JsonPrimitive(entry.metadataOrigin), "modeKnown" to JsonPrimitive(entry.modeKnown),
                "ownershipKnown" to JsonPrimitive(entry.ownershipKnown), "mtimeKnown" to JsonPrimitive(entry.modificationTimeKnown),
                "xattrs" to JsonObject(entry.xattrs.mapValues { JsonPrimitive(it.value) }),
                "pax" to JsonObject(entry.pax.mapValues { JsonPrimitive(it.value) }),
            ))
            val bytes = OracleJson.canonicalBytes(json, JSON_LIMITS)
            digest.update(ByteBuffer.allocate(8).putLong(bytes.size.toLong()).array())
            digest.update(bytes)
        }
        return hex(digest.digest())
    }

    private fun archivePath(raw: String): String {
        if (raw.indexOf('\u0000') >= 0) imageFail("tar member path contains NUL")
        // The pinned extractor strips leading slashes, then performs lexical POSIX cleaning before
        // resolving symlink parents. A prefix traversal still refuses rather than escaping root.
        val pieces = ArrayList<String>()
        raw.trimStart('/').split('/').forEach { component ->
            when (component) {
                "", "." -> Unit
                ".." -> if (pieces.isEmpty()) imageFail("tar member path traverses outside its container root") else pieces.removeAt(pieces.lastIndex)
                else -> pieces += component
            }
            if (pieces.size > MAXIMUM_PATH_COMPONENTS) imageFail("tar path component count exceeds its limit")
        }
        return "/" + pieces.joinToString("/")
    }

    private fun hardlinkTarget(raw: String): String {
        val path = archivePath(raw.trimStart('/'))
        if (path == "/") imageFail("hardlink target cannot be the container root")
        return path
    }

    private fun resolvePath(
        entries: Map<String, Entry>,
        raw: String,
        followFinal: Boolean,
        allowMissing: Boolean = false,
    ): String {
        if (!raw.startsWith('/') || raw.indexOf('\u0000') >= 0) imageFail("container path must be absolute")
        val todo = ArrayDeque(raw.split('/').filter { it.isNotEmpty() })
        val resolved = ArrayList<String>()
        var links = 0
        while (todo.isNotEmpty()) {
            val component = todo.removeFirst()
            when (component) {
                "." -> continue
                ".." -> { if (resolved.isNotEmpty()) resolved.removeAt(resolved.lastIndex); continue }
            }
            resolved += component
            if (resolved.size > MAXIMUM_PATH_COMPONENTS || resolved.sumOf { it.length.toLong() + 1 } > MAXIMUM_NAME_BYTES) {
                imageFail("resolved container path exceeds its bounds")
            }
            val path = "/" + resolved.joinToString("/")
            val entry = entries[path]
            if (entry?.kind == "symlink" && (followFinal || todo.isNotEmpty())) {
                if (++links > MAXIMUM_SYMLINKS) imageFail("container path has cyclic or excessive symlinks")
                resolved.removeAt(resolved.lastIndex)
                val target = entry.linkTarget ?: imageFail("container symlink has no target")
                if (target.startsWith('/')) resolved.clear()
                target.split('/').filter { it.isNotEmpty() }.asReversed().forEach { todo.addFirst(it) }
            } else if (todo.isNotEmpty() && entry != null && entry.kind != "directory") {
                imageFail("container path crosses a non-directory")
            } else if (entry == null && !allowMissing) imageFail("container path is absent: $path")
        }
        return "/" + resolved.joinToString("/")
    }

    private fun join(parent: String, name: String): String = if (parent == "/") "/$name" else "$parent/$name"

    internal data class TarMember(
        val ordinal: Int,
        val path: String,
        val kind: String,
        val mode: Long,
        val uid: Long,
        val gid: Long,
        val mtime: String,
        val size: Long,
        val linkTarget: String?,
        val major: Long,
        val minor: Long,
        val xattrs: Map<String, String>,
        val pax: Map<String, String>,
        val dataOffset: Long,
    )

    /** Strict streaming POSIX/GNU tar parser with limits checked before extension allocation. */
    internal class RawTarReader(
        private val input: InputStream,
        private val metadata: MetadataBudget,
        private val checkpoint: (String) -> Unit,
    ) {
        private var remaining = 0L
        private var payloadSize = 0L
        private var finished = false
        private var ordinal = 0
        private var entries = 0
        private var globalPax = linkedMapOf<String, ByteArray>()
        private var localPax = linkedMapOf<String, ByteArray>()
        private var longName: String? = null
        private var longLink: String? = null
        private var bytesRead = 0L

        fun next(): TarMember? {
            if (finished) return null
            drain()
            skipPadding()
            while (true) {
                checkpoint("before image tar header")
                val header = exact(TAR_BLOCK_BYTES, allowCleanEof = false)
                if (header.all { it == 0.toByte() }) {
                    val second = exact(TAR_BLOCK_BYTES, allowCleanEof = false)
                    if (second.any { it != 0.toByte() }) imageFail("tar end marker is not two zero blocks")
                    if (localPax.isNotEmpty() || longName != null || longLink != null) imageFail("tar ends with unapplied metadata")
                    finished = true
                    return null
                }
                verifyChecksum(header)
                if (++entries > MAXIMUM_ENTRIES) imageFail("image tar entry count exceeds its limit")
                val type = header[156].toInt() and 0xff
                val size = number(header, 124, 12)
                if (size < 0 || size > MAXIMUM_UNCOMPRESSED_BYTES) imageFail("tar member size exceeds its bound")
                payloadSize = size
                remaining = size
                if (type in listOf('x'.code, 'g'.code, 'L'.code, 'K'.code)) {
                    if (size > MAXIMUM_PAX_BYTES) imageFail("tar metadata extension exceeds its byte limit")
                    val extension = readBytes(MAXIMUM_PAX_BYTES)
                    metadata.charge(extension.size.toLong())
                    when (type) {
                        'x'.code -> { if (localPax.isNotEmpty()) imageFail("duplicate local PAX metadata"); localPax = parsePax(extension) }
                        'g'.code -> parsePax(extension).forEach { (key, value) -> if (value.isEmpty()) globalPax.remove(key) else globalPax[key] = value }
                        'L'.code -> { if (longName != null) imageFail("duplicate GNU longname"); longName = longValue(extension) }
                        'K'.code -> { if (longLink != null) imageFail("duplicate GNU longlink"); longLink = longValue(extension) }
                    }
                    skipPadding()
                    continue
                }
                val pax = LinkedHashMap(globalPax).also { result -> localPax.forEach { (key, value) -> if (value.isEmpty()) result.remove(key) else result[key] = value } }
                localPax.clear()
                if (pax.keys.any { it.startsWith("GNU.sparse") || it == "SCHILY.realsize" }) imageFail("sparse image tar members are unsupported")
                val magic = text(header, 257, 6)
                if (magic.isNotEmpty() && magic != "ustar" && magic != "ustar ") imageFail("unsupported tar header magic")
                val prefix = if (magic == "ustar") text(header, 345, 155) else ""
                val basicName = text(header, 0, 100).let { if (prefix.isEmpty()) it else "$prefix/$it" }
                val path = pax["path"]?.let(::utf8) ?: longName ?: basicName
                val link = pax["linkpath"]?.let(::utf8) ?: longLink ?: text(header, 157, 100)
                longName = null
                longLink = null
                val actualSize = pax["size"]?.let { positiveDecimal(it, "PAX size") } ?: size
                if (actualSize > MAXIMUM_UNCOMPRESSED_BYTES) imageFail("PAX member size exceeds its bound")
                remaining = actualSize
                payloadSize = actualSize
                val kind = when (type) {
                    0, '0'.code, '7'.code -> "regular"
                    '1'.code -> "hardlink"
                    '2'.code -> "symlink"
                    '3'.code -> "character"
                    '4'.code -> "block"
                    '5'.code -> "directory"
                    '6'.code -> "fifo"
                    else -> imageFail("unsupported image tar node type")
                }
                if (kind != "regular" && actualSize != 0L) imageFail("non-regular tar node has file data")
                if (path.isEmpty() || link.indexOf('\u0000') >= 0 || (kind in setOf("hardlink", "symlink") && link.isEmpty())) imageFail("tar node name or link is empty or invalid")
                val xattrs = linkedMapOf<String, String>()
                val other = linkedMapOf<String, String>()
                pax.forEach { (key, value) ->
                    when {
                        key.startsWith("SCHILY.xattr.") -> {
                            val name = key.removePrefix("SCHILY.xattr.")
                            val encoded = Base64.getEncoder().encodeToString(value)
                            if (xattrs.put(name, encoded)?.let { it != encoded } == true) imageFail("conflicting tar xattr representations")
                        }
                        key.startsWith("LIBARCHIVE.xattr.") -> {
                            val decoded = try { Base64.getDecoder().decode(value) } catch (failure: IllegalArgumentException) { imageFail("invalid LIBARCHIVE binary xattr") }
                            val name = key.removePrefix("LIBARCHIVE.xattr.")
                            val encoded = Base64.getEncoder().encodeToString(decoded)
                            if (xattrs.put(name, encoded)?.let { it != encoded } == true) imageFail("conflicting tar xattr representations")
                        }
                        key !in INTERPRETED_PAX -> other[key] = Base64.getEncoder().encodeToString(value)
                    }
                }
                metadata.charge(1024L + 4L * (path.encodeToByteArray().size + link.encodeToByteArray().size + pax.entries.sumOf { it.key.encodeToByteArray().size.toLong() + it.value.size }))
                val uid = pax["uid"]?.let { positiveDecimal(it, "PAX uid") } ?: number(header, 108, 8)
                val gid = pax["gid"]?.let { positiveDecimal(it, "PAX gid") } ?: number(header, 116, 8)
                val mode = number(header, 100, 8)
                if (uid < 0 || gid < 0 || mode !in 0..0xfff) imageFail("tar owner or mode metadata is invalid")
                val mtime = pax["mtime"]?.let { decimalTime(it) } ?: number(header, 136, 12).toString()
                val major = number(header, 329, 8)
                val minor = number(header, 337, 8)
                if (major !in 0..0xffff_ffffL || minor !in 0..0xffff_ffffL) imageFail("tar device metadata is invalid")
                return TarMember(ordinal++, path, kind, mode, uid, gid, mtime, actualSize,
                    link.takeIf { kind in setOf("symlink", "hardlink") }, major, minor, immutableMap(xattrs), immutableMap(other), bytesRead)
            }
        }

        fun transfer(consumer: (ByteArray, Int) -> Unit) {
            val buffer = ByteArray(BUFFER_BYTES)
            while (remaining > 0) {
                val read = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                if (read <= 0) imageFail("tar member ends before its declared length")
                remaining -= read
                bytesRead = Math.addExact(bytesRead, read.toLong())
                consumer(buffer, read)
                checkpoint("while streaming image tar member")
            }
        }

        fun drain() = transfer { _, _ -> }
        fun hash(): String {
            val digest = MessageDigest.getInstance("SHA-256")
            transfer { bytes, length -> digest.update(bytes, 0, length) }
            return hex(digest.digest())
        }

        fun readBytes(maximum: Int): ByteArray {
            if (remaining > maximum) imageFail("tar selected bytes exceed their limit")
            val output = ByteArrayOutputStream(remaining.toInt())
            transfer { bytes, length -> output.write(bytes, 0, length) }
            return output.toByteArray()
        }

        fun finish() {
            if (!finished) imageFail("tar terminal framing was not observed")
            val buffer = ByteArray(BUFFER_BYTES)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read == 0) imageFail("image tar stream made no progress")
                if ((0 until read).any { buffer[it] != 0.toByte() }) imageFail("tar contains trailing non-zero payload")
                checkpoint("while authenticating tar terminal padding")
            }
        }

        private fun skipPadding() {
            val padding = ((TAR_BLOCK_BYTES - payloadSize % TAR_BLOCK_BYTES) % TAR_BLOCK_BYTES).toInt()
            if (padding > 0 && exact(padding, false).any { it != 0.toByte() }) imageFail("tar member padding is non-zero")
            payloadSize = 0
        }

        private fun exact(length: Int, allowCleanEof: Boolean): ByteArray {
            val bytes = ByteArray(length)
            var position = 0
            while (position < length) {
                val read = input.read(bytes, position, length - position)
                if (read <= 0) {
                    if (allowCleanEof && position == 0) return ByteArray(0)
                    imageFail("tar framing ends prematurely")
                }
                position += read
                bytesRead = Math.addExact(bytesRead, read.toLong())
            }
            return bytes
        }
    }

    private fun parsePax(bytes: ByteArray): LinkedHashMap<String, ByteArray> {
        val result = linkedMapOf<String, ByteArray>()
        var position = 0
        while (position < bytes.size) {
            val start = position
            while (position < bytes.size && bytes[position] in '0'.code.toByte()..'9'.code.toByte()) position++
            if (position == start || position >= bytes.size || bytes[position] != ' '.code.toByte()) imageFail("malformed PAX record length")
            val length = String(bytes, start, position - start, StandardCharsets.US_ASCII).toIntOrNull() ?: imageFail("PAX record length overflow")
            if (length <= position - start + 3 || length > bytes.size - start || bytes[start + length - 1] != '\n'.code.toByte()) imageFail("PAX record length or terminator is invalid")
            val valueStart = position + 1
            val end = start + length - 1
            var equals = valueStart
            while (equals < end && bytes[equals] != '='.code.toByte()) equals++
            if (equals == valueStart || equals == end) imageFail("PAX record has no key/value delimiter")
            val key = utf8(bytes.copyOfRange(valueStart, equals))
            if (key.any { it == '\u0000' || it == '\n' || it == '=' } || result.containsKey(key)) imageFail("duplicate or invalid PAX key")
            result[key] = bytes.copyOfRange(equals + 1, end)
            position = start + length
        }
        return result
    }

    private fun longValue(bytes: ByteArray): String {
        val end = bytes.indexOf(0.toByte()).let { if (it < 0) bytes.size else it }
        if (bytes.drop(end).any { it != 0.toByte() }) imageFail("GNU longname has bytes after its NUL")
        return utf8(bytes.copyOfRange(0, end))
    }

    private fun text(bytes: ByteArray, offset: Int, length: Int): String {
        var end = offset
        while (end < offset + length && bytes[end] != 0.toByte()) end++
        return utf8(bytes.copyOfRange(offset, end))
    }

    private fun utf8(bytes: ByteArray): String = try {
        if (bytes.size > MAXIMUM_NAME_BYTES) imageFail("tar name exceeds its byte limit")
        StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    } catch (failure: java.nio.charset.CharacterCodingException) {
        throw LlvmBehaviorNativeOciImageV2Exception("tar metadata is not exact UTF-8", failure)
    }

    private fun positiveDecimal(bytes: ByteArray, label: String): Long {
        val text = utf8(bytes)
        if (!DECIMAL.matches(text)) imageFail("$label is not a non-negative decimal integer")
        return text.toLongOrNull() ?: imageFail("$label overflows its bound")
    }

    private fun decimalTime(bytes: ByteArray): String {
        val text = utf8(bytes)
        if (text.length > 128 || !TIME.matches(text)) imageFail("PAX modification time is invalid")
        return BigDecimal(text).stripTrailingZeros().toPlainString()
    }

    private fun number(bytes: ByteArray, offset: Int, length: Int): Long {
        val field = bytes.copyOfRange(offset, offset + length)
        if ((field[0].toInt() and 0x80) != 0) {
            val negative = (field[0].toInt() and 0x40) != 0
            field[0] = (field[0].toInt() and 0x7f).toByte()
            var value = BigInteger(1, field)
            if (negative) value = value.subtract(BigInteger.ONE.shiftLeft(length * 8 - 1))
            return try { value.longValueExact() } catch (failure: ArithmeticException) { imageFail("GNU base-256 tar integer overflows") }
        }
        val text = String(field, StandardCharsets.US_ASCII).trim(' ', '\u0000')
        if (text.isEmpty()) return 0
        if (!OCTAL.matches(text)) imageFail("tar integer is not octal or base-256")
        return text.toLongOrNull(8) ?: imageFail("tar octal integer overflows")
    }

    private fun verifyChecksum(header: ByteArray) {
        val actual = number(header, 148, 8)
        var unsigned = 0L
        var signed = 0L
        header.indices.forEach { index ->
            val value = if (index in 148..155) 32 else header[index].toInt()
            unsigned += value and 0xff
            signed += value
        }
        if (actual != unsigned && actual != signed) imageFail("tar header checksum does not authenticate its metadata")
    }

    internal class MetadataBudget {
        private var bytes = 0L
        fun charge(amount: Long) {
            bytes = Math.addExact(bytes, amount)
            if (bytes > MAXIMUM_METADATA_BYTES) imageFail("image namespace metadata exceeds its byte limit")
        }
    }

    internal class ByteBudget(private val maximum: Long, private val checkpoint: (String) -> Unit) {
        private var bytes = 0L
        fun charge(amount: Int) {
            bytes = Math.addExact(bytes, amount.toLong())
            if (bytes > maximum) imageFail("image stream exceeds its aggregate byte limit")
            checkpoint("while consuming bounded raw image bytes")
        }
    }

    internal class CountingInput(
        private val input: InputStream,
        private val budget: ByteBudget,
        private val digest: MessageDigest? = null,
    ) : InputStream() {
        var bytes = 0L
            private set
        override fun read(): Int {
            val single = ByteArray(1)
            return if (read(single, 0, 1) < 0) -1 else single[0].toInt() and 0xff
        }
        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            if (length == 0) return 0
            val read = input.read(buffer, offset, minOf(length, BUFFER_BYTES))
            if (read > 0) {
                budget.charge(read)
                bytes = Math.addExact(bytes, read.toLong())
                digest?.update(buffer, offset, read)
            }
            return read
        }
        override fun close() = input.close()
    }

    private fun hex(bytes: ByteArray): String {
        val output = CharArray(bytes.size * 2)
        bytes.forEachIndexed { index, byte ->
            val value = byte.toInt() and 0xff
            output[index * 2] = HEX[value ushr 4]
            output[index * 2 + 1] = HEX[value and 15]
        }
        return String(output)
    }
    private fun <T> immutableList(list: List<T>): List<T> = Collections.unmodifiableList(ArrayList(list))
    private fun <K, V> immutableMap(map: Map<K, V>): Map<K, V> = Collections.unmodifiableMap(LinkedHashMap(map))
    private fun <T> immutableSet(set: Set<T>): Set<T> = Collections.unmodifiableSet(LinkedHashSet(set))
    private fun imageFail(message: String): Nothing = throw LlvmBehaviorNativeOciImageV2Exception(message)

    private const val BUFFER_BYTES = 64 * 1024
    private const val TAR_BLOCK_BYTES = 512
    private const val MAXIMUM_RAW_BYTES = 8L * 1024 * 1024 * 1024
    private const val MAXIMUM_UNCOMPRESSED_BYTES = 32L * 1024 * 1024 * 1024
    private const val MAXIMUM_METADATA_BYTES = 128L * 1024 * 1024
    private const val MAXIMUM_SELECTED_FILE_BYTES = 64 * 1024 * 1024
    private const val MAXIMUM_FILE_RANGE_BYTES = 4 * 1024 * 1024
    private const val MAXIMUM_FILE_RANGES = 128
    private const val MAXIMUM_JSON_BYTES = 4 * 1024 * 1024
    private const val MAXIMUM_EXPORT_JSON_BYTES = 32 * 1024 * 1024
    private const val MAXIMUM_PAX_BYTES = 4 * 1024 * 1024
    private const val MAXIMUM_NAME_BYTES = 1024 * 1024
    private const val MAXIMUM_BLOBS = 4096
    private const val MAXIMUM_LAYERS = 256
    private const val MAXIMUM_ENTRIES = 1_000_000
    private const val MAXIMUM_SYMLINKS = 40
    private const val MAXIMUM_PATH_COMPONENTS = 256
    private const val MAXIMUM_INDEX_DEPTH = 8
    private const val MAXIMUM_ZSTD_WINDOW_BYTES = 8L * 1024 * 1024
    private const val MAXIMUM_ZSTD_BLOCK_BYTES = 128 * 1024
    private const val HEX = "0123456789abcdef"
    private val JSON_LIMITS = StrictJsonLimits(maximumInputBytes = MAXIMUM_JSON_BYTES, maximumCanonicalBytes = MAXIMUM_JSON_BYTES)
    private val DIGEST = Regex("sha256:[0-9a-f]{64}")
    private val BLOB_PATH = Regex("blobs/sha256/[0-9a-f]{64}")
    private val OCTAL = Regex("[0-7]+")
    private val DECIMAL = Regex("[0-9]+")
    private val TIME = Regex("-?[0-9]+(?:\\.[0-9]+)?")
    private val JSON_WHITESPACE = setOf(' '.code.toByte(), '\t'.code.toByte(), '\r'.code.toByte(), '\n'.code.toByte())
    private val INTERPRETED_PAX = setOf("path", "linkpath", "size", "uid", "gid", "mtime")
    private val INDEX_MEDIA_TYPES = setOf("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
    private val MANIFEST_MEDIA_TYPES = setOf("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")
    private val CONFIG_MEDIA_TYPES = setOf("application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json")
    private val LAYER_MEDIA_TYPES = setOf(
        "application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.oci.image.layer.nondistributable.v1.tar", "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip", "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
        "application/vnd.docker.image.rootfs.diff.tar", "application/vnd.docker.image.rootfs.diff.tar.gzip",
    )
    private val UNCOMPRESSED_LAYER_MEDIA_TYPES = setOf("application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.nondistributable.v1.tar", "application/vnd.docker.image.rootfs.diff.tar")
}
