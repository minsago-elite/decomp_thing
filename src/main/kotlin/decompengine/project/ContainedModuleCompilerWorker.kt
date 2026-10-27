package decompengine.project

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import decompengine.acp.LinuxBoundedSessionCommand
import decompengine.acp.LinuxBoundedSessionOutputLimitException
import decompengine.acp.LinuxBoundedSessionProcess
import decompengine.acp.LinuxBoundedSessionResult
import decompengine.acp.LinuxBoundedSessionTimeoutException
import decompengine.oracle.fulltree.StableControlFile
import decompengine.repair.readStableRegularFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration

/**
 * A native compiler worker, launched only inside the coordinator's authenticated containment.
 * Its stdout is passive bounded JSON. Process exit, this JSON and even a valid object cannot
 * replace the separate keeper receipt, terminal resource proof and source-acceptance checks.
 */
object ContainedModuleCompilerWorker {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 2) { "usage: <absolute-request-path> <expected-request-sha256>" }
        val path = Path.of(arguments[0])
        requireCompilerAbsolutePath(path)
        requireCompilerDigest(arguments[1])
        CompilerWorkerProtection.disableDumping()
        StableControlFile.open(path, ContainedModuleCompilerRequest.MAXIMUM_REQUEST_BYTES.toLong(), "module compiler request").use { guard ->
            guard.requireSingleLink("module compiler request")
            require(guard.authenticatedSha256 == arguments[1]) { "module compiler request digest differs from its launch binding" }
            val request = ContainedModuleCompilerRequest.parse(guard.readExactly(0, guard.size.toInt(), "module compiler request"))
            require(request.sha256 == arguments[1])
            val result = execute(request)
            guard.verifyUnchanged("module compiler request after execution")
            CompilerWorkerProtection.requireNotDumpable()
            System.out.write(result.canonicalBytes)
            System.out.flush()
        }
    }

    private fun execute(request: ContainedModuleCompilerRequest): ContainedModuleCompilerResult {
        requireContainedModuleCompilerProfile(request.profile)
        // Nondumpable processes can have root-owned /proc entries; ask libc for the effective UID.
        val currentUid = CompilerWorkerProtection.currentUid()
        requireOwnedDirectory(request.snapshotRoot, currentUid)
        requireOwnedDirectory(request.outputDirectory, currentUid)
        require(Files.list(request.outputDirectory).use { !it.findAny().isPresent }) { "module compiler output directory must initially be empty" }
        require(request.compilerPath.toRealPath() == request.compilerPath && Files.isExecutable(request.compilerPath)) {
            "module compiler executable is not canonical and executable"
        }
        val pinned = mutableListOf<PinnedCompilerInput>()
        val namespace = CompilerSnapshotNamespaceGuard.open(request.snapshotRoot)
        try {
            verifySnapshotInventory(request)
            request.inputs.forEach { input -> pinned += PinnedCompilerInput.open(request.snapshotRoot, input, currentUid) }
            // The controller binds its authenticated owned executable snapshot at this exact
            // runtime path. Scratch stays noexec; no foreign namespace UID becomes trusted.
            StableControlFile.open(request.compilerPath, MAXIMUM_COMPILER_BYTES, "pinned module compiler").use { compiler ->
                compiler.requireSingleLink("pinned module compiler")
                require(compiler.authenticatedSha256 == request.compilerSha256) { "module compiler executable digest differs" }
                val scratch = Files.createDirectory(request.outputDirectory.resolve("tmp"),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                val environment = mapOf("LANG" to "C", "LC_ALL" to "C", "TZ" to "UTC", "PATH" to request.compilerPath.parent.toString(),
                    "TMPDIR" to scratch.toString(), "HOME" to scratch.toString(), "SOURCE_DATE_EPOCH" to "0")
                CompilerWorkerProtection.requireNotDumpable()
                namespace.requireUnchanged()
                var terminal: LinuxBoundedSessionResult? = null
                var outcome = try {
                    terminal = LinuxBoundedSessionProcess.execute(LinuxBoundedSessionCommand(request.command, environment,
                        workingDirectory = Path.of("/"), timeout = Duration.ofMillis(request.maximumWallMillis),
                        maximumStdoutBytes = (request.maximumOutputBytes / 2).toInt(),
                        maximumStderrBytes = (request.maximumOutputBytes - request.maximumOutputBytes / 2).toInt()))
                    when {
                        terminal.signal != null -> "compiler-signaled"
                        terminal.exitCode == 0 -> "compiled-object"
                        else -> "compiler-failed"
                    }
                } catch (interrupted: InterruptedException) {
                    throw interrupted
                } catch (_: LinuxBoundedSessionTimeoutException) {
                    "timed-out"
                } catch (_: LinuxBoundedSessionOutputLimitException) {
                    "output-limit-exceeded"
                } catch (_: Exception) {
                    // The native helper retains no partial capture on a failed execution. Empty log
                    // files below mean no bytes retained, never that no diagnostic bytes were emitted.
                    "execution-failed"
                }
                CompilerWorkerProtection.requireNotDumpable()
                try {
                    pinned.forEach { it.verifyUnchanged() }
                    verifySnapshotInventory(request)
                    namespace.requireUnchanged()
                    compiler.verifyUnchanged("pinned module compiler after execution")
                } catch (_: Exception) {
                    outcome = "input-changed"
                }
                var objectSha256: String? = null
                var objectBytes: Long? = null
                if (outcome == "compiled-object") {
                    try {
                        val output = request.outputDirectory.resolve(ContainedModuleCompilerRequest.OBJECT_FILE)
                        requireOwnedRegularFile(output, currentUid)
                        StableControlFile.open(output, ContainedModuleCompilerRequest.MAXIMUM_OBJECT_BYTES, "compiled module object").use { objectFile ->
                            objectFile.requireSingleLink("compiled module object")
                            requireRelocatableCompilerObject(objectFile)
                            objectSha256 = objectFile.authenticatedSha256
                            objectBytes = objectFile.size
                            objectFile.verifyUnchanged("compiled module object")
                        }
                    } catch (_: Exception) {
                        objectSha256 = null
                        objectBytes = null
                        outcome = "object-invalid"
                    }
                }
                val stdout = terminal?.stdout ?: ByteArray(0)
                val stderr = terminal?.stderr ?: ByteArray(0)
                requireOwnedDirectory(request.outputDirectory, currentUid)
                writeCompilerLog(request.outputDirectory.resolve(ContainedModuleCompilerRequest.STDOUT_FILE), stdout)
                writeCompilerLog(request.outputDirectory.resolve(ContainedModuleCompilerRequest.STDERR_FILE), stderr)
                // Keep the entire namespace history alive through result artifact capture, not
                // merely through compiler exit or the first member-by-member verification pass.
                try {
                    namespace.requireUnchanged()
                } catch (_: Exception) {
                    outcome = "input-changed"
                    objectSha256 = null
                    objectBytes = null
                }
                return ContainedModuleCompilerResult(request.sha256, request.nonce, request.profileId, request.profileSha256,
                    request.snapshotSha256, request.sourceSha256, request.compilerSha256, outcome, terminal?.exitCode, terminal?.signal,
                    sha256(stdout), stdout.size.toLong(), sha256(stderr), stderr.size.toLong(), objectSha256, objectBytes)
            }
        } finally {
            try { pinned.asReversed().forEach { it.close() } } finally { namespace.close() }
        }
    }
}

private class PinnedCompilerInput private constructor(
    private val root: Path, private val input: ContainedModuleCompilerInput,
    private val uid: Int, private val file: StableControlFile?, private val emptyIdentity: Map<String, Any>?,
) : AutoCloseable {
    fun verifyUnchanged() {
        val path = root.resolve(input.path)
        requireOwnedRegularFile(path, uid)
        if (file != null) file.verifyUnchanged("module compiler snapshot ${input.path}")
        else {
            require(Files.readAttributes(path, "unix:dev,ino,size,mode,uid,gid,nlink,ctime,lastModifiedTime", LinkOption.NOFOLLOW_LINKS) == emptyIdentity) {
                "empty module compiler header changed during execution"
            }
            val current = readStableRegularFile(root, input.path, 1)
            require(current.bytes.isEmpty() && current.sha256 == input.sha256) { "empty module compiler header changed bytes" }
        }
    }

    override fun close() { file?.close() }

    companion object {
        fun open(root: Path, input: ContainedModuleCompilerInput, uid: Int): PinnedCompilerInput {
            val path = root.resolve(input.path)
            requireOwnedRegularFile(path, uid)
            if (input.bytes == 0L) {
                val identity = Files.readAttributes(path, "unix:dev,ino,size,mode,uid,gid,nlink,ctime,lastModifiedTime", LinkOption.NOFOLLOW_LINKS)
                val snapshot = readStableRegularFile(root, input.path, 1)
                require(snapshot.bytes.isEmpty() && snapshot.sha256 == input.sha256) { "empty module compiler header digest differs" }
                return PinnedCompilerInput(root, input, uid, null, identity).also { it.verifyUnchanged() }
            }
            val file = StableControlFile.open(path, ContainedModuleCompilerRequest.MAXIMUM_INPUT_FILE_BYTES, "module compiler snapshot ${input.path}")
            try {
                file.requireSingleLink("module compiler snapshot ${input.path}")
                require(file.size == input.bytes && file.authenticatedSha256 == input.sha256) { "module compiler snapshot digest or size differs" }
                return PinnedCompilerInput(root, input, uid, file, null)
            } catch (failure: Throwable) {
                file.close()
                throw failure
            }
        }
    }
}

private fun verifySnapshotInventory(request: ContainedModuleCompilerRequest) {
    val expected = request.inputs.map { it.path }.toSet()
    val actual = mutableSetOf<String>()
    var entries = 0
    Files.walk(request.snapshotRoot, 32).use { paths ->
        paths.forEach { path ->
            require(++entries <= ContainedModuleCompilerRequest.MAXIMUM_INPUTS * 4) { "module compiler snapshot inventory exceeds its bound" }
            require(!Files.isSymbolicLink(path) && path.toRealPath() == path) { "module compiler snapshot contains a symbolic path" }
            if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) return@forEach
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "module compiler snapshot contains a special file" }
            require(actual.add(request.snapshotRoot.relativize(path).toString())) { "duplicate module compiler inventory path" }
        }
    }
    require(actual == expected) { "module compiler snapshot inventory differs from its manifest" }
}

private fun requireOwnedDirectory(path: Path, uid: Int) {
    require(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) && path.toRealPath() == path) { "module compiler directory is not canonical" }
    val attributes = Files.readAttributes(path, "unix:uid,mode", LinkOption.NOFOLLOW_LINKS)
    require((attributes.getValue("uid") as Number).toInt() == uid && (attributes.getValue("mode") as Number).toInt() and 0x12 == 0) {
        "module compiler directory is not owner controlled"
    }
}

private fun requireOwnedRegularFile(path: Path, uid: Int) {
    require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && path.toRealPath() == path) { "module compiler input or object is not a canonical regular file" }
    val attributes = Files.readAttributes(path, "unix:uid,mode,nlink", LinkOption.NOFOLLOW_LINKS)
    require((attributes.getValue("uid") as Number).toInt() == uid && (attributes.getValue("mode") as Number).toInt() and 0x12 == 0 &&
        (attributes.getValue("nlink") as Number).toInt() == 1) { "module compiler input or object must be owned and single linked" }
}

private fun writeCompilerLog(path: Path, bytes: ByteArray) {
    FileChannel.open(path, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { channel ->
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) channel.write(buffer)
        channel.force(true)
    }
}

private fun requireRelocatableCompilerObject(file: StableControlFile) {
    require(file.size >= 52) { "compiled object has no ELF header" }
    val bytes = file.readExactly(0, minOf(64L, file.size).toInt(), "compiled object ELF header")
    require(bytes.copyOfRange(0, 4).contentEquals(byteArrayOf(0x7f, 0x45, 0x4c, 0x46)) && bytes[6].toInt() == 1) { "compiled object is not ELF" }
    val is64 = when (bytes[4].toInt()) { 1 -> false; 2 -> true; else -> error("compiled object has an invalid ELF class") }
    val order = when (bytes[5].toInt()) { 1 -> ByteOrder.LITTLE_ENDIAN; 2 -> ByteOrder.BIG_ENDIAN; else -> error("compiled object has invalid ELF byte order") }
    require(bytes.size >= if (is64) 64 else 52) { "compiled object ELF header is truncated" }
    val header = ByteBuffer.wrap(bytes).order(order)
    require(header.getShort(16).toInt() == 1 && header.getInt(20) == 1) { "compiled object must be ET_REL version 1" }
    val sectionOffset = if (is64) header.getLong(40) else header.getInt(32).toLong() and 0xffffffffL
    val headerSize = header.getShort(if (is64) 52 else 40).toInt() and 0xffff
    val sectionSize = header.getShort(if (is64) 58 else 46).toInt() and 0xffff
    val sectionCount = header.getShort(if (is64) 60 else 48).toInt() and 0xffff
    require(headerSize == if (is64) 64 else 52)
    require(sectionSize == if (is64) 64 else 40)
    require(sectionCount > 0 && sectionOffset >= headerSize && sectionOffset <= file.size - sectionSize.toLong() * sectionCount) {
        "compiled ET_REL section table exceeds the object"
    }
}

private object CompilerWorkerProtection {
    private val libc: ProtectionLibC by lazy { Native.load(Platform.C_LIBRARY_NAME, ProtectionLibC::class.java) }
    fun disableDumping() {
        require(System.getProperty("os.name") == "Linux") { "module compiler worker requires Linux" }
        require(libc.prctl(4, NativeLong(0), NativeLong(0), NativeLong(0), NativeLong(0)) == 0) { "module compiler worker cannot disable dumping" }
        requireNotDumpable()
    }
    fun requireNotDumpable() {
        require(libc.prctl(3, NativeLong(0), NativeLong(0), NativeLong(0), NativeLong(0)) == 0) { "module compiler worker must remain nondumpable" }
    }
    fun currentUid(): Int = libc.geteuid()
    private interface ProtectionLibC : Library {
        fun geteuid(): Int
        fun prctl(option: Int, argument2: NativeLong, argument3: NativeLong, argument4: NativeLong, argument5: NativeLong): Int
    }
}

private const val MAXIMUM_COMPILER_BYTES = 512L * 1024 * 1024
