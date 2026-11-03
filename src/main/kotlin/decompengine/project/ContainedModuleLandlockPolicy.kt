package decompengine.project

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/** Closed, bounded policy consumed by the native trampoline before it executes the compiler. */
internal object ContainedModuleLandlockPolicy {
    private const val VERSION = 1
    private const val HEADER = "DMLAND01"
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

    internal data class Identity(val device: Long, val inode: Long, val directory: Boolean)
    internal data class Entry(val kind: Kind, val path: Path, val identity: Identity)

    fun forRequest(request: ContainedModuleCompilerRequest, scratchDirectory: Path): ByteArray {
        require(request.schemaVersion == 2) { "historical module compiler request has no read-boundary authority" }
        val entries = linkedMapOf<Pair<Kind, Path>, Entry>()
        fun add(kind: Kind, path: Path, directory: Boolean) {
            canonicalPath(path)
            val identity = identity(path, directory)
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
        request.inputs.forEach { input -> add(Kind.SNAPSHOT_FILE, request.snapshotRoot.resolve(input.path), directory = false) }
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
        return encode(entries.values.toList())
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
            require(entry.identity.device >= 0 && entry.identity.inode > 0) { "compiler read policy identity is invalid" }
            out.putInt(entry.kind.wireValue)
            out.putInt(bytes.size)
            out.putLong(entry.identity.device)
            out.putLong(entry.identity.inode)
            out.put(bytes)
        }
        require(out.position() <= MAXIMUM_POLICY_BYTES) { "compiler read policy exceeds its byte bound" }
        return out.array().copyOf(out.position())
    }

    fun identity(path: Path, expectDirectory: Boolean): Identity {
        val canonical = canonicalPath(path)
        val actual = path.toRealPath(LinkOption.NOFOLLOW_LINKS)
        require(actual == path && !Files.isSymbolicLink(path)) { "compiler read policy target is not canonical" }
        val attrs = Files.readAttributes(path, "unix:dev,ino,mode,nlink", LinkOption.NOFOLLOW_LINKS)
        val mode = (attrs.getValue("mode") as Number).toInt()
        val isDirectory = (mode and 0xf000) == 0x4000
        val isRegular = (mode and 0xf000) == 0x8000
        require(if (expectDirectory) isDirectory else isRegular) { "compiler read policy target has the wrong file type" }
        require((attrs.getValue("nlink") as Number).toInt() >= 1) { "compiler read policy target has no links" }
        require(canonical == path.toString()) { "compiler read policy target changed during canonicalization" }
        return Identity((attrs.getValue("dev") as Number).toLong(), (attrs.getValue("ino") as Number).toLong(), isDirectory)
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
