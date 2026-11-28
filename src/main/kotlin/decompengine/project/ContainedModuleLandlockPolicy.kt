package decompengine.project

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/** Closed, bounded policy consumed by the native trampoline before it executes the compiler. */
internal object ContainedModuleLandlockPolicy {
    private const val VERSION = 2
    private const val HEADER = "DMLAND02"
    private const val MAXIMUM_RULES = 8192
    private const val MAXIMUM_PATH_BYTES = 4096
    private const val MAXIMUM_POLICY_BYTES = 1024 * 1024

    internal enum class Kind(val wireValue: Int) {
        RUNTIME_DIRECTORY(1),
        SNAPSHOT_DIRECTORY(2),
        SNAPSHOT_FILE(3),
        OUTPUT_FILE(4),
        SCRATCH_DIRECTORY(5),
        RUNTIME_EXECUTE_DIRECTORY(6),
        RUNTIME_EXECUTE_FILE(7),
    }

    internal data class Identity(val device: Long, val inode: Long, val mountId: Long, val directory: Boolean)
    internal data class Entry(val kind: Kind, val path: Path, val identity: Identity)

    fun forRequest(
        request: ContainedModuleCompilerRequest,
        scratchDirectory: Path,
        pinnedInputIdentities: Map<String, Identity>,
    ): ByteArray {
        require(request.schemaVersion == 4) { "historical module compiler request has no read-boundary authority" }
        val expectedInputPaths = request.inputs.map { it.path }.toSet()
        require(pinnedInputIdentities.keys == expectedInputPaths) {
            "compiler read policy input identities do not exactly match the authenticated request"
        }
        val entries = linkedMapOf<Pair<Kind, Path>, Entry>()
        fun add(kind: Kind, path: Path, directory: Boolean, pinnedIdentity: Identity? = null) {
            canonicalPath(path)
            val identity = pinnedIdentity ?: identity(path, directory)
            require(identity.directory == directory) { "compiler read policy target identity has the wrong type" }
            val key = kind to path
            val entry = Entry(kind, path, identity)
            val previous = entries.putIfAbsent(key, entry)
            require(previous == null || previous == entry) { "compiler read policy target identity changed" }
        }
        request.runtimeReadRoots.forEach { root -> add(Kind.RUNTIME_DIRECTORY, root, directory = true) }
        request.runtimeExecuteRoots.forEach { root -> add(Kind.RUNTIME_EXECUTE_DIRECTORY, root, directory = true) }
        request.runtimeExecuteFiles.forEach { file ->
            add(Kind.RUNTIME_EXECUTE_FILE, file, directory = false)
            require(Files.isExecutable(file)) { "compiler runtime interpreter is not executable" }
        }
        val snapshotDirectories = request.inputs.flatMap { input -> directoryAncestors(request.snapshotRoot, input.path) }.toSet()
        snapshotDirectories.forEach { add(Kind.SNAPSHOT_DIRECTORY, it, directory = true) }
        request.inputs.forEach { input ->
            add(Kind.SNAPSHOT_FILE, request.snapshotRoot.resolve(input.path), directory = false,
                pinnedIdentity = pinnedInputIdentities.getValue(input.path))
        }
        add(Kind.OUTPUT_FILE, request.outputDirectory.resolve(ContainedModuleCompilerRequest.OBJECT_FILE), directory = false)
        add(Kind.SCRATCH_DIRECTORY, scratchDirectory, directory = true)
        val roots = request.runtimeReadRoots
        require(entries.values.filter { it.kind == Kind.SNAPSHOT_FILE }.all { entry ->
            roots.none { entry.path.startsWith(it) }
        }) { "compiler snapshot overlaps authenticated runtime authority" }
        require(entries.values.filter { it.kind in setOf(Kind.RUNTIME_DIRECTORY, Kind.RUNTIME_EXECUTE_DIRECTORY, Kind.RUNTIME_EXECUTE_FILE) }.none { entry ->
            entry.path.startsWith(request.snapshotRoot) || request.snapshotRoot.startsWith(entry.path) ||
                entry.path.startsWith(request.outputDirectory) || request.outputDirectory.startsWith(entry.path) ||
                entry.path.startsWith(scratchDirectory) || scratchDirectory.startsWith(entry.path)
        }) { "compiler runtime authority overlaps snapshot or writable output" }
        val selectedEntries = entries.values.toList()
        val mounts = ContainedModuleMountPolicy.readCurrent()
        selectedEntries.filterNot { it.kind == Kind.OUTPUT_FILE || it.kind == Kind.SCRATCH_DIRECTORY }
            .forEach { entry ->
                ContainedModuleMountPolicy.requireReadOnlyTarget(
                    entry.path,
                    entry.identity.mountId,
                    entry.identity.directory,
                    mounts,
                )
            }
        return encode(selectedEntries)
    }

    fun encode(entries: List<Entry>): ByteArray {
        require(entries.size in 1..MAXIMUM_RULES) { "compiler read policy rule count exceeds its bound" }
        val ordered = entries.sortedWith(compareBy<Entry>({ it.path.toString() }, { it.kind.wireValue }))
        require(ordered.map { it.kind to it.path }.distinct().size == ordered.size) {
            "compiler read policy contains duplicate path rules"
        }
        val out = ByteBuffer.allocate(MAXIMUM_POLICY_BYTES).order(ByteOrder.LITTLE_ENDIAN)
        out.put(HEADER.toByteArray(Charsets.US_ASCII))
        out.putInt(VERSION)
        out.putInt(ordered.size)
        for (entry in ordered) {
            val path = canonicalPath(entry.path)
            val bytes = path.toByteArray(Charsets.UTF_8)
            require(bytes.size in 2..MAXIMUM_PATH_BYTES) { "compiler read policy path exceeds its bound" }
            require(entry.identity.device >= 0 && entry.identity.inode > 0 && entry.identity.mountId > 0) {
                "compiler read policy identity is invalid"
            }
            out.putInt(entry.kind.wireValue)
            out.putInt(bytes.size)
            out.putLong(entry.identity.device)
            out.putLong(entry.identity.inode)
            out.putLong(entry.identity.mountId)
            out.put(bytes)
        }
        require(out.position() <= MAXIMUM_POLICY_BYTES) { "compiler read policy exceeds its byte bound" }
        return out.array().copyOf(out.position())
    }

    fun identity(path: Path, expectDirectory: Boolean): Identity {
        val canonical = canonicalPath(path)
        val actual = path.toRealPath(LinkOption.NOFOLLOW_LINKS)
        require(actual == path && !Files.isSymbolicLink(path)) { "compiler read policy target is not canonical" }
        require(canonical == path.toString()) { "compiler read policy target changed during canonicalization" }
        val selected = descriptorIdentity(path, expectDirectory)
        require(if (expectDirectory) selected.isDirectory else selected.isRegularFile && !selected.isSymbolicLink) {
            "compiler read policy target has the wrong descriptor type"
        }
        require(selected.linkCount >= 1 && selected.mountId > 0) { "compiler read policy target identity is incomplete" }
        return Identity(selected.key.device, selected.key.inode, selected.mountId, expectDirectory)
    }

    private fun descriptorIdentity(path: Path, expectDirectory: Boolean): LinuxFileIdentity {
        val parts = path.iterator().asSequence().map { it.toString() }.toList()
        require(parts.isNotEmpty()) { "compiler read policy target cannot be the filesystem root" }
        var current = LinuxFilesystemSyscalls.openRoot(Path.of("/"))
        try {
            val directories = if (expectDirectory) parts else parts.dropLast(1)
            for (part in directories) {
                val next = current.whileOpen { parent -> LinuxFilesystemSyscalls.openDirectoryAt(parent, part) }
                current.close()
                current = next
            }
            if (expectDirectory) return current.whileOpen(LinuxFilesystemSyscalls::identity)
            val file = current.whileOpen { parent ->
                LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent, parts.last())
                    ?: throw IllegalArgumentException("compiler read policy target is absent")
            }
            return file.use { it.whileOpen(LinuxFilesystemSyscalls::identity) }
        } finally {
            current.close()
        }
    }

    fun canonicalPath(path: Path): String {
        require(path.isAbsolute && path.normalize() == path && path != Path.of("/")) {
            "compiler read policy path must be absolute, normalized, and non-root"
        }
        val value = path.toString()
        require(value.length <= MAXIMUM_PATH_BYTES && value.none { it.code < 0x20 || it.code == 0x7f } &&
            !value.contains("//") && value.split('/').none { it == "." || it == ".." }) {
            "compiler read policy path is not canonical"
        }
        return value
    }

    fun directoryAncestors(root: Path, relative: String): Set<Path> {
        val absolute = root.resolve(relative).normalize()
        require(absolute.startsWith(root) && absolute != root) { "compiler snapshot path escaped its root" }
        val result = linkedSetOf(root)
        var current = absolute.parent
        while (current != null && current.startsWith(root)) {
            result.add(current)
            if (current == root) break
            current = current.parent
        }
        return result
    }
}
