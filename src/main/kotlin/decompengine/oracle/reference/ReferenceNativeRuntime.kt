package decompengine.oracle.reference

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Pointer

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.behavior.LlvmBehaviorNativeOciImageV2
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeMount
import decompengine.oracle.fulltree.calculateFullTreeObservationRuntimeManifestSha256
import java.io.OutputStream
import java.math.BigDecimal
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileTime
import java.security.DigestOutputStream
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Non-authoritative transport result. Ownership must be installed by a separate trusted provisioner. */
internal class ReferenceNativeRuntimeStage internal constructor(
    val root: Path,
    canonicalBytes: ByteArray,
    provisioningEntries: List<ReferenceNativeRuntimeProvisioningEntry>,
) {
    private val stored = canonicalBytes.copyOf()
    val canonicalBytes: ByteArray get() = stored.copyOf()
    val identitySha256: String = OracleArtifacts.sha256(stored)
    val provisioningEntries: List<ReferenceNativeRuntimeProvisioningEntry> = Collections.unmodifiableList(provisioningEntries.toList())
}

/** Relative paths are validated, contain no symlink ancestors, and include the complete staged tree. */
internal data class ReferenceNativeRuntimeProvisioningEntry(
    val relativePath: String,
    val kind: String,
    val uid: Long,
    val gid: Long,
    val mode: Int,
)

/**
 * Materializes the authenticated image's closed Linux tool/library namespace, without executing it.
 * OCI decoding and unprivileged staging confer no execution authority. Only [admit] can produce an
 * admitted handle, after byte comparison and the existing root-owned runtime/ancestor checks.
 *
 * Supported transport is an OCI layout with uncompressed tar layers (for example `podman save
 * --uncompressed --format oci-dir`). Config bytes and every diffID remain the profile's exact image
 * identity; a registry digest is not replaced by a caller's extraction receipt. File reads are at
 * most 4 MiB, and every output byte is checked against the measured merged namespace.
 * Admission requires a principal able to read the entire exact root-owned selection, including
 * image-private /etc entries. It never changes source permissions to accommodate the caller.
 */
internal object ReferenceNativeRuntime {
    private val PREFIXES = listOf("/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin")
    private val PLAIN_LAYERS = setOf("application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.nondistributable.v1.tar", "application/vnd.docker.image.rootfs.diff.tar")
    private const val MAXIMUM_ENTRIES = 200_000
    private const val MAXIMUM_DEPTH = 64
    private const val MAXIMUM_FILE_BYTES = 1024L * 1024 * 1024
    private const val MAXIMUM_TOTAL_BYTES = 8L * 1024 * 1024 * 1024
    private const val CHUNK_BYTES = 4 * 1024 * 1024

    fun materialize(ociLayout: Path, stagingRoot: Path, profile: AuthenticatedReferenceCorpusProfile): ReferenceNativeRuntimeStage {
        profile.requireCurrent("before native runtime materialization")
        val result = materializeTransport(ociLayout, stagingRoot, profile.imageConfigSha256, profile.originalArtifacts)
        profile.requireCurrent("after native runtime materialization")
        return result
    }

    /** Explicit pins are transport checks only. This method cannot return an admitted runtime. */
    internal fun materializeTransport(
        ociLayout: Path,
        stagingRoot: Path,
        expectedConfigSha256: String,
        artifacts: List<ReferenceCorpusArtifact>,
    ): ReferenceNativeRuntimeStage = LlvmBehaviorNativeOciImageV2.openLayout(ociLayout).use { image ->
        val plan = plan(image, expectedConfigSha256, artifacts)
        val root = newRoot(stagingRoot)
        // No archive symlink is installed until all directories and regular files have been written.
        // Same-UID writers remain within the cooperating staging boundary; staging is never authority.
        plan.nodes.filter { it.kind == "directory" }.sortedBy { it.relative.count { c -> c == '/' } }.forEach {
            Files.createDirectory(root.resolve(it.relative))
        }
        val hardlinks = mutableMapOf<Long, Path>()
        plan.nodes.filter { it.kind == "regular" }.forEach { node ->
            val destination = root.resolve(node.relative)
            val entry = node.imageEntry
            val previous = entry?.let { hardlinks[it.inode] }
            if (previous != null) {
                Files.createLink(destination, previous)
            } else {
                val digest = MessageDigest.getInstance("SHA-256")
                Files.newOutputStream(destination, WRITE, CREATE_NEW, NOFOLLOW_LINKS).use { output ->
                    if (entry != null) {
                        var position = 0L
                        while (position < entry.size) {
                            val bytes = image.readFileRange(entry.path, position, minOf(CHUNK_BYTES.toLong(), entry.size - position).toInt())
                            output.write(bytes)
                            digest.update(bytes)
                            position += bytes.size
                        }
                        hardlinks[entry.inode] = destination
                    } else {
                        val bytes = node.artifact!!.content
                        output.write(bytes)
                        digest.update(bytes)
                    }
                }
                require(hex(digest.digest()) == node.sha256) { "native runtime file bytes differ from measured input: ${node.relative}" }
            }
        }
        plan.nodes.filter { it.kind == "symlink" }.forEach {
            Files.createSymbolicLink(root.resolve(it.relative), Path.of(it.target!!))
        }
        // Directories are finalized last, since populating their children changes their timestamps.
        plan.nodes.sortedByDescending { it.relative.count { c -> c == '/' } }.forEach { node ->
            val path = root.resolve(node.relative)
            if (node.kind != "symlink") Files.setAttribute(path, "unix:mode", node.mode, NOFOLLOW_LINKS)
            Files.getFileAttributeView(path, BasicFileAttributeView::class.java, NOFOLLOW_LINKS)
                .setTimes(node.time, null, null)
        }
        Files.setAttribute(root, "unix:mode", 0x1ed, NOFOLLOW_LINKS)
        verify(root, plan, trustedOwnership = false)
        image.requireCurrent()
        ReferenceNativeRuntimeStage(root, plan.canonicalBytes, listOf(ReferenceNativeRuntimeProvisioningEntry(".", "directory", 0, 0, 0x1ed)) + plan.nodes.map {
            ReferenceNativeRuntimeProvisioningEntry(it.relative, it.kind, it.uid, it.gid, it.mode)
        })
    }

    fun admit(ociLayout: Path, provisionedRoot: Path, profile: AuthenticatedReferenceCorpusProfile): AdmittedReferenceNativeRuntime =
        AdmittedReferenceNativeRuntime.admit(ociLayout, provisionedRoot, profile)

    /** Re-derives the expected tree from measured OCI; useful for transport verification only. */
    internal fun verifyTransport(ociLayout: Path, stagedRoot: Path, expectedConfigSha256: String, artifacts: List<ReferenceCorpusArtifact>) {
        LlvmBehaviorNativeOciImageV2.openLayout(ociLayout).use { image ->
            verify(canonicalDirectory(stagedRoot), plan(image, expectedConfigSha256, artifacts), trustedOwnership = false)
            image.requireCurrent()
        }
    }

    internal data class Node(
        val relative: String, val kind: String, val mode: Int, val uid: Long, val gid: Long,
        val time: FileTime, val bytes: Long = 0, val sha256: String? = null, val target: String? = null,
        val imageEntry: LlvmBehaviorNativeOciImageV2.Entry? = null, val artifact: ReferenceCorpusArtifact? = null,
    )
    internal data class PlannedMount(val relative: String, val guest: String, val role: String)
    internal data class Plan(val nodes: List<Node>, val mounts: List<PlannedMount>, val canonicalBytes: ByteArray)

    internal fun plan(image: LlvmBehaviorNativeOciImageV2.MeasuredImage, config: String, artifacts: List<ReferenceCorpusArtifact>): Plan {
        require(config.matches(Regex("[0-9a-f]{64}")) && image.configSha256 == config) { "native runtime image config differs from approved profile" }
        require(image.layers.all { it.mediaType in PLAIN_LAYERS }) { "native runtime staging requires uncompressed OCI layers; decode transport before staging" }
        val resolved = PREFIXES.associateWith { prefix ->
            image.resolve(prefix).also { require(it.kind == "directory") { "native runtime prefix is not a directory: $prefix" } }.path
        }
        val roots = (PREFIXES + resolved.values).distinct()
        val selected = image.namespace.values.filter { entry -> roots.any { entry.path == it || entry.path.startsWith("$it/") } }.sortedBy { it.path }
        require(selected.size in 1..MAXIMUM_ENTRIES) { "native runtime entry count exceeds its bound" }
        val nodes = linkedMapOf<String, Node>()
        fun directory(relative: String) {
            nodes.putIfAbsent(relative, Node(relative, "directory", 0x1ed, 0, 0, FileTime.fromMillis(0)))
        }
        directory("image")
        directory("artifacts")
        var total = 0L
        selected.forEach { entry ->
            val relative = "image/${safeAbsolute(entry.path)}"
            require(relative.split('/').size <= MAXIMUM_DEPTH) { "native runtime path exceeds depth bound" }
            require(entry.kind in setOf("directory", "regular", "symlink")) { "native runtime contains unsupported special node: ${entry.path}" }
            require(entry.uid == 0L && entry.gid in 0..Int.MAX_VALUE.toLong()) { "native runtime requires root-owned image nodes" }
            require(entry.mode in 0..0xfff && (entry.kind == "symlink" || entry.mode.toInt() and 0x12 == 0)) { "native runtime contains a writable image node: ${entry.path}" }
            require(entry.xattrs.isEmpty() && entry.pax.keys.all { it in setOf("atime", "ctime") }) { "native runtime contains unsupported extended metadata: ${entry.path}" }
            require(entry.size in 0..MAXIMUM_FILE_BYTES) { "native runtime file exceeds byte bound" }
            if (entry.kind == "regular") total = Math.addExact(total, entry.size)
            require(total <= MAXIMUM_TOTAL_BYTES) { "native runtime exceeds aggregate byte bound" }
            if (entry.kind == "symlink") require(entry.linkTarget!!.length in 1..4096 && '\u0000' !in entry.linkTarget) { "native runtime symlink target exceeds bound" }
            val time = FileTime.from(BigDecimal(entry.modificationTime).movePointRight(9).longValueExact(), TimeUnit.NANOSECONDS)
            nodes[relative] = Node(relative, entry.kind, entry.mode.toInt(), entry.uid, entry.gid, time, entry.size, entry.contentSha256, entry.linkTarget, entry)
        }
        val mounts = resolved.map { (guest, source) -> PlannedMount("image/${safeAbsolute(source)}", guest, "") }.toMutableList()
        require(artifacts.map { it.role }.distinct().size == artifacts.size && artifacts.size in 1..16) { "invalid original runtime artifact roles" }
        artifacts.forEach { artifact ->
            require(artifact.role.matches(Regex("[a-z][a-z0-9-]{0,63}"))) { "invalid original runtime artifact role" }
            val guest = Path.of("/${safeAbsolute(artifact.guestPath)}")
            require(guest.parent != Path.of("/") && PREFIXES.none { guest.startsWith(it) }) { "original artifact overlaps pinned image namespace" }
            require(artifact.bytes in 1..MAXIMUM_FILE_BYTES && artifact.sha256.matches(Regex("[0-9a-f]{64}"))) { "invalid original runtime artifact identity" }
            val bytes = artifact.content
            require(bytes.size.toLong() == artifact.bytes && OracleArtifacts.sha256(bytes) == artifact.sha256) { "original runtime artifact content differs from manifest" }
            total = Math.addExact(total, artifact.bytes)
            require(total <= MAXIMUM_TOTAL_BYTES) { "native runtime exceeds aggregate byte bound" }
            val parent = "artifacts/${artifact.role}"
            directory(parent)
            nodes["$parent/${guest.fileName}"] = Node("$parent/${guest.fileName}", "regular", 0x16d, 0, 0, FileTime.fromMillis(0), artifact.bytes, artifact.sha256, artifact = artifact)
            mounts += PlannedMount(parent, guest.parent.toString(), artifact.role)
        }
        mounts.forEachIndexed { index, mount ->
            val guest = Path.of(mount.guest)
            require(mounts.take(index).none { guest.startsWith(it.guest) || Path.of(it.guest).startsWith(guest) }) {
                "native runtime mount destinations overlap"
            }
        }
        require(nodes.size <= MAXIMUM_ENTRIES) { "native runtime tree exceeds entry bound" }
        nodes.values.forEach { node ->
            var parent = Path.of(node.relative).parent
            while (parent != null) {
                require(nodes[parent.toString()]?.kind == "directory") { "native runtime path has an absent or symlink ancestor: ${node.relative}" }
                parent = parent.parent
            }
        }
        // The full authenticated merged namespace digest retains metadata beyond this selected projection.
        val bytes = OracleJson.canonicalBytes(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive("reference-native-runtime-projection-v1"),
            "imageConfigSha256" to JsonPrimitive(config), "imageNamespaceSha256" to JsonPrimitive(image.namespaceSha256),
            "selectedPrefixes" to JsonArray(PREFIXES.map(::JsonPrimitive)),
            "entries" to JsonPrimitive(nodes.size), "regularBytes" to JsonPrimitive(total),
            "artifacts" to JsonArray(artifacts.sortedBy { it.role }.map { JsonObject(mapOf(
                "role" to JsonPrimitive(it.role), "guestPath" to JsonPrimitive(it.guestPath), "bytes" to JsonPrimitive(it.bytes), "sha256" to JsonPrimitive(it.sha256),
            )) }),
        )))
        return Plan(nodes.values.toList(), mounts, bytes)
    }

    internal fun verify(root: Path, plan: Plan, trustedOwnership: Boolean) = LinuxFilesystemSyscalls.openRoot(root).use { pinnedRoot ->
        val found = Files.walk(root, MAXIMUM_DEPTH + 1).use { paths -> paths.limit(MAXIMUM_ENTRIES.toLong() + 2).toList() }
        require(found.size == plan.nodes.size + 1) { "native runtime namespace has extra or missing entries" }
        val expected = plan.nodes.associateBy { it.relative }
        requireNoExtendedAttributes(root)
        val imageLinkCounts = plan.nodes.filter { it.kind == "regular" && it.imageEntry != null }
            .groupingBy { it.imageEntry!!.inode }.eachCount()
        val inodeKeys = mutableMapOf<Long, Any>()
        val actualInodes = mutableMapOf<Any, Long>()
        found.filter { it != root }.forEach { path ->
            val relative = root.relativize(path).toString()
            val node = requireNotNull(expected[relative]) { "native runtime contains unexpected entry: $relative" }
            val attrs = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
            requireNoExtendedAttributes(path)
            val kind = when { attrs.isDirectory -> "directory"; attrs.isRegularFile -> "regular"; attrs.isSymbolicLink -> "symlink"; else -> "special" }
            require(kind == node.kind) { "native runtime node type changed: $relative" }
            val mode = (Files.getAttribute(path, "unix:mode", NOFOLLOW_LINKS) as Number).toInt() and 0xfff
            require(kind == "symlink" || mode == node.mode) { "native runtime mode changed: $relative" }
            require(attrs.lastModifiedTime() == node.time) { "native runtime timestamp changed: $relative" }
            if (trustedOwnership) {
                require((Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == node.uid &&
                    (Files.getAttribute(path, "unix:gid", NOFOLLOW_LINKS) as Number).toLong() == node.gid) { "native runtime ownership differs from image: $relative" }
            }
            when (kind) {
                "symlink" -> require(Files.readSymbolicLink(path).toString() == node.target) { "native runtime symlink changed: $relative" }
                "regular" -> {
                    val expectedLinks = node.imageEntry?.let { imageLinkCounts.getValue(it.inode) } ?: 1
                    require((Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toInt() == expectedLinks) {
                        "native runtime has an external or substituted hardlink alias: $relative"
                    }
                    verifyRegularFile(root, pinnedRoot, node, attrs)
                    node.imageEntry?.let { entry ->
                        val key = requireNotNull(attrs.fileKey()) { "native runtime file identity unavailable" }
                        require(inodeKeys.putIfAbsent(entry.inode, key)?.let { it == key } != false) { "native runtime hardlink alias changed: $relative" }
                        require(actualInodes.putIfAbsent(key, entry.inode)?.let { it == entry.inode } != false) { "native runtime has an invented hardlink alias: $relative" }
                    }
                }
            }
        }
        LinuxFilesystemSyscalls.openRoot(root).use { named ->
            require(named.identity == pinnedRoot.identity) { "native runtime root was substituted during verification" }
        }
    }

    /**
     * These are image data with independently authenticated expected SHA-256 values, not mutable
     * control documents. Production admission establishes recursively root-owned, non-writable
     * ancestry before this walk and verifies its complete manifest again afterwards. Staging is
     * explicitly cooperative and confers no authority. Thus this boundary uses pinned, no-follow
     * descriptors and complete expected-content checks, rather than cycling the process-global
     * control-document mutation watches for every image member. No watch bypass is added to the
     * control-document mechanism. Per-chunk inode/metadata/ctime checks also reject writes whose
     * original mtime was restored; every retained directory and final name is rechecked at EOF.
     */
    private fun verifyRegularFile(root: Path, pinnedRoot: LinuxDescriptor, node: Node, attributes: BasicFileAttributes) {
        val components = Path.of(node.relative).map { it.toString() }
        val parents = ArrayList<LinuxDescriptor>()
        try {
            var parent = pinnedRoot
            components.dropLast(1).forEach { component ->
                parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, component).also(parents::add)
            }
            requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, components.last())).use { selected ->
                val descriptorPath = LinuxFilesystemSyscalls.descriptorPath(selected)
                val before = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
                val changeTime = Files.getAttribute(descriptorPath, "unix:ctime")
                require(before.fileKey() == attributes.fileKey() && before.size() == node.bytes &&
                    before.lastModifiedTime() == node.time && selected.identity.mode and 0xfff == node.mode) {
                    "native runtime file identity changed: ${node.relative}"
                }
                fun requireCurrent() {
                    val current = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
                    require(LinuxFilesystemSyscalls.identity(selected.fd) == selected.identity &&
                        current.isRegularFile && current.fileKey() == before.fileKey() && current.size() == node.bytes &&
                        current.lastModifiedTime() == before.lastModifiedTime() && Files.getAttribute(descriptorPath, "unix:ctime") == changeTime) {
                        "native runtime file changed during measurement: ${node.relative}"
                    }
                }
                requireCurrent()
                val digest = MessageDigest.getInstance("SHA-256")
                val count = DigestOutputStream(OutputStream.nullOutputStream(), digest).use { output ->
                    LinuxFilesystemSyscalls.copyReadableTo(selected, output, node.bytes, cancellationCheck = ::requireCurrent)
                }
                requireCurrent()
                require(count == node.bytes && hex(digest.digest()) == node.sha256) {
                    "native runtime bytes differ from authenticated input: ${node.relative}"
                }
                // Reopen from the absolute retained root, then walk every component without following
                // links. Comparing only the final parent would miss an exchanged ancestor directory.
                LinuxFilesystemSyscalls.openRoot(root).use { namedRoot ->
                    require(namedRoot.identity == pinnedRoot.identity) { "native runtime root was substituted" }
                    var namedParent = namedRoot
                    val namedDirectories = ArrayList<LinuxDescriptor>()
                    try {
                        components.dropLast(1).forEachIndexed { index, component ->
                            namedParent = LinuxFilesystemSyscalls.openDirectoryAt(namedParent.fd, component).also(namedDirectories::add)
                            require(namedParent.identity == parents[index].identity) { "native runtime ancestor was substituted: ${node.relative}" }
                        }
                        requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(namedParent.fd, components.last())).use { named ->
                            require(named.identity == selected.identity) { "native runtime file was substituted: ${node.relative}" }
                        }
                        requireCurrent()
                    } finally { namedDirectories.asReversed().forEach(LinuxDescriptor::close) }
                }
            }
        } finally { parents.asReversed().forEach(LinuxDescriptor::close) }
    }

    private fun newRoot(path: Path): Path {
        val root = path.toAbsolutePath().normalize()
        require(path.toAbsolutePath() == root && root.parent != null) { "native runtime staging path must be canonical" }
        canonicalDirectory(root.parent)
        Files.createDirectory(root)
        Files.setAttribute(root, "unix:mode", 0x1c0, NOFOLLOW_LINKS)
        return root
    }

    internal fun canonicalDirectory(path: Path): Path {
        val root = path.toAbsolutePath().normalize()
        require(root != Path.of("/") && path.toAbsolutePath() == root && root.toRealPath() == root && Files.isDirectory(root, NOFOLLOW_LINKS)) { "native runtime root must be a canonical real non-root directory" }
        return root
    }

    private fun safeAbsolute(value: String): String {
        require(value.startsWith('/') && value != "/" && '\u0000' !in value && value.length <= 4096) { "invalid native runtime absolute path" }
        require(value.drop(1).split('/').none { it.isEmpty() || it == "." || it == ".." }) { "native runtime path traversal or alias" }
        return value.drop(1)
    }

    // llistxattr never follows an image symlink (including an absolute container target). Only
    // emptiness is supported, so a zero-size query bounds work and never allocates attacker names.
    private fun requireNoExtendedAttributes(path: Path) {
        require(ExtendedAttributes.libc.llistxattr(path.toString(), null, NativeLong(0)).toLong() == 0L) {
            "native runtime extended metadata is present or cannot be authenticated: $path"
        }
    }

    private interface ExtendedAttributes : Library {
        fun llistxattr(path: String, list: Pointer?, size: NativeLong): NativeLong
        companion object { val libc: ExtendedAttributes = Native.load("c", ExtendedAttributes::class.java) }
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}

/**
 * Retained execution input authority; the profile is borrowed and must outlive this handle.
 * After independent byte/metadata admission, root ownership remains the content trust root, as in
 * the existing launcher. Rechecks reject observable tree-manifest/root substitutions; they do not
 * claim detection of arbitrary privileged writers restoring that trusted metadata.
 */
internal class AdmittedReferenceNativeRuntime private constructor(
    private val profile: AuthenticatedReferenceCorpusProfile,
    private val image: LlvmBehaviorNativeOciImageV2.MeasuredImage,
    private val descriptor: LinuxDescriptor,
    private val root: Path,
    private val rootManifest: String,
    private val allMounts: List<Pair<String, FullTreeFunctionObservationRuntimeMount>>,
    canonicalBytes: ByteArray,
) : AutoCloseable {
    private val stored = canonicalBytes.copyOf()
    val canonicalBytes: ByteArray get() = stored.copyOf()
    val identitySha256: String = OracleArtifacts.sha256(stored)
    private var closed = false

    @Synchronized
    fun mounts(batchId: String): List<FullTreeFunctionObservationRuntimeMount> {
        requireCurrent("before native runtime mount selection")
        val roles = profile.artifactRolesForBatch(batchId)
        return Collections.unmodifiableList(allMounts.filter { it.first == "" || it.first in roles }.map { it.second })
    }

    @Synchronized
    fun requireCurrent(label: String = "reference native runtime") {
        check(!closed) { "reference native runtime is closed" }
        profile.requireCurrent(label)
        image.requireCurrent()
        LinuxFilesystemSyscalls.openRoot(root).use { current ->
            require(current.identity == descriptor.identity) { "$label root identity changed" }
        }
        require(calculateFullTreeObservationRuntimeManifestSha256(root) == rootManifest) { "$label runtime tree changed" }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        try { image.close() } finally { descriptor.close() }
    }

    internal companion object {
        fun admit(
            ociLayout: Path,
            provisionedRoot: Path,
            profile: AuthenticatedReferenceCorpusProfile,
        ): AdmittedReferenceNativeRuntime {
            profile.requireCurrent("before native runtime admission")
            val image = LlvmBehaviorNativeOciImageV2.openLayout(ociLayout)
            var descriptor: LinuxDescriptor? = null
            try {
                val plan = ReferenceNativeRuntime.plan(image, profile.imageConfigSha256, profile.originalArtifacts)
                val root = ReferenceNativeRuntime.canonicalDirectory(provisionedRoot)
                descriptor = LinuxFilesystemSyscalls.openRoot(root)
                // Establish root ownership BEFORE trusting any path walk or content measurement.
                val fullManifest = calculateFullTreeObservationRuntimeManifestSha256(root)
                ReferenceNativeRuntime.verify(root, plan, trustedOwnership = true)
                require(calculateFullTreeObservationRuntimeManifestSha256(root) == fullManifest) { "native runtime changed during admission" }
                val mounts = plan.mounts.map { (relative, guest, role) ->
                    val source = root.resolve(relative)
                    role to FullTreeFunctionObservationRuntimeMount(source, Path.of(guest), calculateFullTreeObservationRuntimeManifestSha256(source))
                }
                val bytes = OracleJson.canonicalBytes(JsonObject(mapOf(
                    "schemaVersion" to JsonPrimitive("reference-native-runtime-admission-v1"),
                    "profileSha256" to JsonPrimitive(profile.profileSha256),
                    "projectionSha256" to JsonPrimitive(OracleArtifacts.sha256(plan.canonicalBytes)),
                    "root" to JsonPrimitive(root.toString()),
                    "rootManifestSha256" to JsonPrimitive(fullManifest),
                    "mounts" to JsonArray(mounts.map { (role, mount) -> JsonObject(mapOf(
                        "role" to JsonPrimitive(role), "source" to JsonPrimitive(mount.source.toString()),
                        "destination" to JsonPrimitive(mount.destination.toString()),
                        "manifestSha256" to JsonPrimitive(mount.expectedManifestSha256),
                    )) }),
                )))
                val retained = AdmittedReferenceNativeRuntime(profile, image, descriptor, root, fullManifest, mounts, bytes)
                retained.requireCurrent("after native runtime admission")
                descriptor = null
                return retained
            } catch (failure: Throwable) {
                descriptor?.close()
                image.close()
                throw failure
            }
        }
    }
}
