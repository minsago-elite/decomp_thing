package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeDiskMount
import decompengine.oracle.fulltree.parseFullTreeDiskMountTable
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileTime
import java.security.DigestOutputStream
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class GccBundledGhidraRetainedRuntime private constructor(
    val root: Path,
    private val deployment: GccBundledGhidraDeploymentReference,
    private val descriptor: LinuxDescriptor,
    private val mount: FullTreeDiskMount,
    private val inventory: Map<String, GccBundledRuntimeEntryState>,
) : AutoCloseable {
    val deploymentClosureSha256: String = deployment.reference.closureSha256
    val runtimeIdentitySha256: String = runtimeIdentity(root, deploymentClosureSha256, mount, inventory)
    private var closed = false

    @Synchronized
    fun verify(label: String) {
        check(!closed) { "bundled Ghidra retained runtime is closed" }
        deployment.verify(label)
        openTrustedRuntimeRoot(root).use { current ->
            require(current.identity == descriptor.identity && LinuxFilesystemSyscalls.identity(descriptor.fd) == descriptor.identity) {
                "bundled Ghidra runtime root identity changed $label"
            }
        }
        require(readRuntimeMount(root, descriptor.identity) == mount) { "bundled Ghidra runtime mount changed $label" }
        require(captureInventory(descriptor, deployment.reference, hashContents = false) == inventory) {
            "bundled Ghidra runtime tree changed $label"
        }
        require(readRuntimeMount(root, descriptor.identity) == mount) { "bundled Ghidra runtime mount changed during verification" }
        openTrustedRuntimeRoot(root).use { current ->
            require(current.identity == descriptor.identity) { "bundled Ghidra runtime root changed during verification" }
        }
        deployment.verify("after runtime verification $label")
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        runCatching { descriptor.close() }.exceptionOrNull()?.let { failure = it }
        runCatching { deployment.close() }.exceptionOrNull()?.let { next ->
            val previous = failure
            if (previous == null) failure = next else if (previous !== next) previous.addSuppressed(next)
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(definition: GccCompilerEngineValidatedContainmentDefinition): GccBundledGhidraRetainedRuntime {
            val runtime = requireNotNull(definition.bundledRuntime) { "retained Ghidra runtime requires a bundled v2 definition" }
            val deployment = GccBundledGhidraDeploymentReference.open()
            var descriptor: LinuxDescriptor? = null
            try {
                deployment.reference.requireCandidate(runtime, definition.artifacts)
                require(!runtime.root.startsWith(definition.outputLease.path) && !definition.outputLease.path.startsWith(runtime.root)) {
                    "bundled Ghidra runtime overlaps writable output"
                }
                val selected = openTrustedRuntimeRoot(runtime.root)
                descriptor = selected
                require(selected.identity.mode and 0xfff == 493) { "bundled Ghidra root permissions differ from the deployment reference" }
                val mount = readRuntimeMount(runtime.root, selected.identity)
                val inventory = captureInventory(selected, deployment.reference, hashContents = true)
                val retained = GccBundledGhidraRetainedRuntime(runtime.root, deployment, selected, mount, inventory)
                retained.verify("after full content authentication")
                return retained
            } catch (failure: Throwable) {
                runCatching { descriptor?.close() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
                runCatching { deployment.close() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

internal fun requireGccBundledRuntimeEntry(
    identity: LinuxFileIdentity,
    expected: GccBundledGhidraReferenceEntry,
    rootMountId: Long,
) {
    require(identity.uid == 0 && identity.mode and 0xfff == expected.mode && identity.mountId == rootMountId) {
        "bundled Ghidra entry has untrusted ownership, mode or mount: ${expected.path}"
    }
    require(!identity.isSymbolicLink && when (expected.kind) {
        "directory" -> identity.isDirectory && !identity.isRegularFile
        "file" -> identity.isRegularFile && !identity.isDirectory && identity.linkCount == 1
        else -> false
    }) { "bundled Ghidra entry has an unsupported type or alias: ${expected.path}" }
}

internal fun requireGccBundledRuntimeMount(
    root: Path,
    rootIdentity: LinuxFileIdentity,
    mounts: List<FullTreeDiskMount>,
): FullTreeDiskMount {
    val selected = requireNotNull(mounts.singleOrNull { it.mountId == rootIdentity.mountId }) {
        "bundled Ghidra backing mount identity is unavailable or ambiguous"
    }
    require(root.startsWith(selected.mountPoint) && "noexec" !in selected.options) {
        "bundled Ghidra runtime requires an executable backing mount"
    }
    require(mounts.none { it.mountId != selected.mountId && it.mountPoint.startsWith(root) }) {
        "bundled Ghidra runtime contains a nested or shadowing mount"
    }
    return selected.copy(options = java.util.List.copyOf(selected.options))
}

private data class GccBundledRuntimeEntryState(
    val identity: LinuxFileIdentity,
    val bytes: Long,
    val modified: FileTime,
    val changed: FileTime,
)

private fun openTrustedRuntimeRoot(root: Path): LinuxDescriptor {
    require(root.isAbsolute && root.normalize() == root && root != Path.of("/") && root.nameCount <= 32) {
        "bundled Ghidra runtime root is not canonical"
    }
    var selected = LinuxFilesystemSyscalls.openRoot(Path.of("/"))
    try {
        fun requireTrusted(directory: LinuxDescriptor) {
            val identity = directory.identity
            require(identity.isDirectory && !identity.isSymbolicLink && identity.uid == 0 && identity.mode and 0x12 == 0) {
                "bundled Ghidra runtime has an untrusted ancestor"
            }
        }
        requireTrusted(selected)
        for (component in root) {
            val child = LinuxFilesystemSyscalls.openDirectoryAt(selected.fd, component.toString())
            try {
                requireTrusted(child)
                selected.close()
                selected = child
            } catch (failure: Throwable) {
                runCatching { child.close() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
                throw failure
            }
        }
        return selected
    } catch (failure: Throwable) {
        runCatching { selected.close() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
        throw failure
    }
}

private fun captureInventory(
    root: LinuxDescriptor,
    reference: GccBundledGhidraReference,
    hashContents: Boolean,
): Map<String, GccBundledRuntimeEntryState> {
    val children = reference.entries.keys.groupBy { it.substringBeforeLast('/', "") }
    val observed = linkedMapOf<String, GccBundledRuntimeEntryState>()
    fun state(descriptor: LinuxDescriptor): GccBundledRuntimeEntryState {
        val path = LinuxFilesystemSyscalls.descriptorPath(descriptor)
        val attributes = Files.readAttributes(path, BasicFileAttributes::class.java)
        return GccBundledRuntimeEntryState(
            LinuxFilesystemSyscalls.identity(descriptor.fd), attributes.size(), attributes.lastModifiedTime(),
            Files.getAttribute(path, "unix:ctime") as FileTime,
        )
    }
    fun visit(directory: LinuxDescriptor, relative: String, depth: Int) {
        require(depth <= 32) { "bundled Ghidra runtime exceeds its depth bound" }
        val before = state(directory)
        val expected = children[relative].orEmpty()
        val names = LinuxFilesystemSyscalls.directoryEntryNames(directory, expected.size + 1).sorted()
        require(names == expected.map { it.substringAfterLast('/') }) { "bundled Ghidra directory inventory differs: $relative" }
        observed[relative] = before
        for (name in names) {
            require(observed.size <= 20_000) { "bundled Ghidra runtime exceeds its entry bound" }
            val path = if (relative.isEmpty()) name else "$relative/$name"
            val entry = reference.entries.getValue(path)
            requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)) {
                "bundled Ghidra entry disappeared"
            }.use { selected ->
                requireGccBundledRuntimeEntry(selected.identity, entry, root.identity.mountId)
                val selectedBefore = state(selected)
                if (entry.kind == "directory") {
                    LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, name).use { child ->
                        require(state(child) == selectedBefore) { "bundled Ghidra directory changed during selection" }
                        visit(child, path, depth + 1)
                    }
                } else {
                    require(selectedBefore.bytes == entry.bytes) { "bundled Ghidra file size differs: $path" }
                    if (hashContents) {
                        val digest = MessageDigest.getInstance("SHA-256")
                        val size = DigestOutputStream(OutputStream.nullOutputStream(), digest).use { output ->
                            LinuxFilesystemSyscalls.copyReadableTo(selected, output, checkNotNull(entry.bytes))
                        }
                        require(size == entry.bytes && digest.digest().joinToString("") { "%02x".format(it) } == entry.sha256) {
                            "bundled Ghidra file content differs from the independent deployment reference: $path"
                        }
                    }
                    observed[path] = selectedBefore
                }
                require(state(selected) == selectedBefore) { "bundled Ghidra entry changed during authentication: $path" }
            }
        }
        require(state(directory) == before && names == LinuxFilesystemSyscalls.directoryEntryNames(directory, expected.size + 1).sorted()) {
            "bundled Ghidra directory changed during authentication: $relative"
        }
    }
    visit(root, "", 0)
    require(observed.keys == reference.entries.keys + "") { "bundled Ghidra runtime inventory is incomplete" }
    return java.util.Map.copyOf(observed)
}

private fun readRuntimeMount(root: Path, identity: LinuxFileIdentity): FullTreeDiskMount {
    val bytes = Files.newInputStream(Path.of("/proc/self/mountinfo")).use { it.readNBytes(16 * 1024 * 1024 + 1) }
    require(bytes.size <= 16 * 1024 * 1024) { "bundled Ghidra mount table exceeds its byte bound" }
    val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    return requireGccBundledRuntimeMount(root, identity, parseFullTreeDiskMountTable(text))
}

private fun runtimeIdentity(
    root: Path,
    deployment: String,
    mount: FullTreeDiskMount,
    inventory: Map<String, GccBundledRuntimeEntryState>,
): String {
    val digest = MessageDigest.getInstance("SHA-256")
    for ((path, entry) in inventory.toSortedMap()) {
        val identity = entry.identity
        digest.update(OracleJson.canonicalBytes(JsonObject(mapOf(
            "path" to JsonPrimitive(path),
            "device" to JsonPrimitive(identity.key.device),
            "inode" to JsonPrimitive(identity.key.inode),
            "mode" to JsonPrimitive(identity.mode),
            "uid" to JsonPrimitive(identity.uid),
            "gid" to JsonPrimitive(identity.gid),
            "linkCount" to JsonPrimitive(identity.linkCount),
            "mountId" to JsonPrimitive(identity.mountId),
            "isRegularFile" to JsonPrimitive(identity.isRegularFile),
            "isDirectory" to JsonPrimitive(identity.isDirectory),
            "isSymbolicLink" to JsonPrimitive(identity.isSymbolicLink),
            "bytes" to JsonPrimitive(entry.bytes),
            "modified" to JsonPrimitive(entry.modified.toString()),
            "changed" to JsonPrimitive(entry.changed.toString()),
        ))))
        digest.update('\n'.code.toByte())
    }
    return OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(mapOf(
        "provider" to JsonPrimitive("gcc-bundled-ghidra-retained-root-v1"),
        "root" to JsonPrimitive(root.toString()),
        "deploymentClosureSha256" to JsonPrimitive(deployment),
        "mount" to JsonObject(mapOf(
            "mountId" to JsonPrimitive(mount.mountId),
            "parentMountId" to JsonPrimitive(mount.parentMountId),
            "device" to JsonPrimitive(mount.device),
            "root" to JsonPrimitive(mount.root.toString()),
            "mountPoint" to JsonPrimitive(mount.mountPoint.toString()),
            "options" to JsonArray(mount.options.map(::JsonPrimitive)),
            "fileSystemType" to JsonPrimitive(mount.fileSystemType),
        )),
        "inventorySha256" to JsonPrimitive(digest.digest().joinToString("") { "%02x".format(it) }),
    ))))
}

internal fun gccBundledLiveDeploymentClosureSha256(
    bootClosureSha256: String,
    bundledDeploymentClosureSha256: String,
    bundledRuntimeIdentitySha256: String,
): String {
    require(listOf(bootClosureSha256, bundledDeploymentClosureSha256, bundledRuntimeIdentitySha256).all {
        it.matches(Regex("[0-9a-f]{64}"))
    }) { "bundled live deployment closure inputs must be SHA-256 digests" }
    return OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(mapOf(
        "provider" to JsonPrimitive("gcc-bundled-live-deployment-closure-v1"),
        "bootClosureSha256" to JsonPrimitive(bootClosureSha256),
        "bundledDeploymentClosureSha256" to JsonPrimitive(bundledDeploymentClosureSha256),
        "bundledRuntimeIdentitySha256" to JsonPrimitive(bundledRuntimeIdentitySha256),
    ))))
}
