package decompengine.oracle.fulltree

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Closed selection only. The launcher still needs the genuine lease and pins every selected file. */
internal data class KotlinContainedCommandRetainedInput(val relativePath: String, val bytes: Long, val sha256: String) {
    init {
        require(bytes in 1..64L * 1024 * 1024 && sha256.matches(Regex("[a-f0-9]{64}")))
        val parts = relativePath.split('/')
        require(parts.size in 2..4 && parts.all { it.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")) && it !in setOf(".", "..") })
        require(Path.of(relativePath).normalize().toString() == relativePath && !Path.of(relativePath).isAbsolute)
    }
    fun json() = JsonObject(mapOf("relativePath" to JsonPrimitive(relativePath), "bytes" to JsonPrimitive(bytes), "sha256" to JsonPrimitive(sha256)))
}

/** Empty means no prior byte is visible; null at the launcher means the unchanged legacy view. */
internal class ContainedCommandRetainedInputVisibility(
    private val active: String, protectedRoots: Set<String>, requested: List<KotlinContainedCommandRetainedInput>,
) {
    val inputs: List<KotlinContainedCommandRetainedInput>
    private val parents: List<String>
    init {
        require(validContainedControlName(active))
        require(requested.size <= 64)
        require(requested.map { it.relativePath }.distinct().size == requested.size)
        var total = 0L
        requested.forEach { selected ->
            require(selected.relativePath.substringBefore('/') in protectedRoots && selected.relativePath.substringBefore('/') != active)
            total = Math.addExact(total, selected.bytes)
            require(total <= 128L * 1024 * 1024) { "visible retained input byte bound exceeded" }
        }
        val ordered = requested.sortedBy { it.relativePath }
        ordered.zipWithNext().forEach { (left, right) -> require(!right.relativePath.startsWith(left.relativePath + "/")) }
        inputs = java.util.List.copyOf(ordered)
        val directories = linkedSetOf(active)
        inputs.forEach { selected ->
            val parts = selected.relativePath.split('/')
            for (index in 1 until parts.size) directories += parts.take(index).joinToString("/")
        }
        require(directories.size <= 128) { "visible retained parent bound exceeded" }
        parents = directories.sortedWith(compareBy<String> { it.count { character -> character == '/' } }.thenBy { it })
    }
    fun canonicalIdentity() = JsonObject(mapOf(
        "provider" to JsonPrimitive("contained-retained-input-visibility-v1"), "schemaVersion" to JsonPrimitive(1),
        "mode" to JsonPrimitive("empty-readonly-root-with-owned-active-control"),
        "activeControl" to JsonPrimitive(active), "files" to JsonArray(inputs.map { it.json() }),
        "parentCount" to JsonPrimitive(parents.size), "aggregateBytes" to JsonPrimitive(inputs.sumOf { it.bytes }),
        "maximumFiles" to JsonPrimitive(64), "maximumParents" to JsonPrimitive(128), "maximumDepth" to JsonPrimitive(4),
        "maximumAggregateBytes" to JsonPrimitive(128L * 1024 * 1024)))

    fun verifySources(parent: LinuxDescriptor) {
        val owner = LinuxFilesystemSyscalls.identity(parent.fd)
        for (selected in inputs) {
            val parts = selected.relativePath.split('/')
            var directory: LinuxDescriptor? = null
            try {
                for (name in parts.dropLast(1)) {
                    val opened = LinuxFilesystemSyscalls.openDirectoryAt(directory?.fd ?: parent.fd, name)
                    directory?.close()
                    directory = opened
                    require(opened.identity.isDirectory && !opened.identity.isSymbolicLink && opened.identity.mode.permissions == 448 &&
                        opened.identity.uid == owner.uid && opened.identity.mountId == owner.mountId)
                }
                requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(checkNotNull(directory).fd, parts.last())).use { file ->
                    val id = file.identity
                    require(id.isRegularFile && !id.isSymbolicLink && id.linkCount == 1 && id.uid == owner.uid &&
                        id.mountId == owner.mountId && id.mode.permissions and 0x12 == 0) { "visible retained file is not private single-link owned data" }
                }
            } finally { directory?.close() }
        }
    }

    /** Source paths are resolved by bubblewrap from its original host root, never from the masked view. */
    fun mountArguments(root: Path): List<String> {
        require(root.isAbsolute && root.normalize() == root)
        return buildList {
            addAll(listOf("--tmpfs", root.toString(), "--chmod", "0700", root.toString()))
            parents.forEach { relative -> addAll(listOf("--dir", root.resolve(relative).toString(), "--chmod", "0700", root.resolve(relative).toString())) }
            val activePath = root.resolve(active).toString()
            addAll(listOf("--bind", activePath, activePath))
            inputs.forEach { selected -> val path = root.resolve(selected.relativePath).toString(); addAll(listOf("--ro-bind", path, path)) }
            // Remount only the empty view; the separately bound active subtree is the sole writable mount.
            addAll(listOf("--remount-ro", root.toString()))
        }
    }
}
