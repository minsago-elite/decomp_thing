package decompengine.acp

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.Assumptions.assumeTrue

/** Host-only discovery used by the live, scripted ACP contract fixture. */
internal object AcpLiveContractHost {
    private const val REQUIRED_ENVIRONMENT = "DECOMP_REQUIRE_LIVE_ACP_CONTRACT"
    private const val PROBE_MAGIC = "DECOMP_ACP_PYTHON_RUNTIME_V1"
    private const val MAXIMUM_PROBE_BYTES = 512 * 1024
    private const val MAXIMUM_ELF_INTERPRETER_BYTES = 4 * 1024
    private const val ELF_PT_INTERP = 3L
    private const val ELF_PN_XNUM = 0xffff
    private const val PROBE_TIMEOUT_SECONDS = 10L
    private const val MAXIMUM_RUNTIME_FILE_ALIASES = 64

    private val defaultPythonCandidates = listOf(
        Path.of("/usr/bin/python3"),
        Path.of("/usr/bin/python3.14"),
    )
    private val defaultRuntimeAliasRoots = listOf(
        Path.of("/lib"),
        Path.of("/lib32"),
        Path.of("/lib64"),
        Path.of("/libx32"),
    )

    /**
     * Resolves the effective interpreter, stdlib, extension and native loader closure without
     * consulting PATH, invoking a shell, or assuming a distro multiarch directory.
     */
    fun discoverPythonRuntime(
        candidates: List<Path> = defaultPythonCandidates,
    ): AcpPythonRuntimeLayout {
        require(candidates.isNotEmpty()) { "at least one Python interpreter candidate is required" }
        val failures = mutableListOf<String>()
        val attempted = HashSet<Path>()
        candidates.forEach { candidate ->
            requireAbsoluteNormalized("Python interpreter candidate", candidate)
            if (!Files.isExecutable(candidate)) {
                failures += "$candidate is not executable"
                return@forEach
            }
            val canonicalCandidate = try {
                candidate.toRealPath()
            } catch (failure: Exception) {
                failures += "$candidate could not be resolved: ${failure.javaClass.simpleName}"
                return@forEach
            }
            if (!attempted.add(canonicalCandidate)) return@forEach
            try {
                return parsePythonProbe(runPythonProbe(candidate))
            } catch (failure: Exception) {
                failures += "$candidate failed discovery: ${failure.message ?: failure.javaClass.simpleName}"
            }
        }
        throw IllegalStateException("no usable system Python runtime: ${failures.joinToString("; ")}")
    }

    /**
     * Aborts a local host-dependent test, but becomes a hard assertion in the required CI lane.
     */
    fun requireCapability(
        available: Boolean,
        message: () -> String,
        required: Boolean = System.getenv(REQUIRED_ENVIRONMENT) == "1",
    ) {
        if (available) return
        val detail = message()
        if (required) {
            throw AssertionError("$REQUIRED_ENVIRONMENT=1 but $detail")
        }
        assumeTrue(false, detail)
    }

    private fun runPythonProbe(candidate: Path): ByteArray {
        val process = ProcessBuilder(
            candidate.toString(),
            "-I",
            "-S",
            "-c",
            PYTHON_RUNTIME_PROBE,
        ).also { builder ->
            builder.environment().clear()
        }.start()
        val executor = Executors.newFixedThreadPool(2) { task ->
            Thread(task, "acp-python-runtime-probe-drain").apply { isDaemon = true }
        }
        val stdout = executor.submit(Callable { process.inputStream.readBounded() })
        val stderr = executor.submit(Callable { process.errorStream.readBounded() })
        try {
            if (!process.waitFor(PROBE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                process.waitFor(2, TimeUnit.SECONDS)
                throw IllegalStateException("runtime probe timed out")
            }
            val output = stdout.get(2, TimeUnit.SECONDS)
            val diagnostics = stderr.get(2, TimeUnit.SECONDS)
            check(process.exitValue() == 0) {
                "runtime probe exited ${process.exitValue()}: ${diagnostics.decodeUtf8()}"
            }
            check(output.size <= MAXIMUM_PROBE_BYTES) { "runtime probe output exceeded its byte limit" }
            check(diagnostics.size <= MAXIMUM_PROBE_BYTES) { "runtime probe diagnostics exceeded its byte limit" }
            return output
        } finally {
            if (process.isAlive) {
                process.destroyForcibly()
                process.waitFor(2, TimeUnit.SECONDS)
            }
            stdout.cancel(true)
            stderr.cancel(true)
            executor.shutdownNow()
            executor.awaitTermination(2, TimeUnit.SECONDS)
        }
    }

    private fun parsePythonProbe(output: ByteArray): AcpPythonRuntimeLayout {
        check(output.isNotEmpty() && output.last() == 0.toByte()) {
            "runtime probe did not emit a complete record"
        }
        val records = output.splitNulRecords()
        check(records.size >= 5) { "runtime probe emitted an incomplete record" }
        check(records.first().decodeUtf8() == PROBE_MAGIC) { "runtime probe version is unsupported" }

        val executable = records[1].decodeCanonicalPath("effective Python executable")
        val stdlib = records[2].decodeCanonicalPath("Python stdlib")
        val jsonExtension = records[3].decodeCanonicalPath("Python _json extension")
        check(Files.isExecutable(executable)) { "effective Python executable is not executable: $executable" }
        check(Files.isDirectory(stdlib)) { "Python stdlib is not a directory: $stdlib" }
        check(Files.isRegularFile(jsonExtension)) { "Python _json extension is not a file: $jsonExtension" }
        check(jsonExtension.startsWith(stdlib)) { "Python _json extension is outside its stdlib: $jsonExtension" }

        val executableMappings = records.drop(4)
            .map { it.decodeCanonicalPath("Python executable mapping") }
        check(executableMappings == executableMappings.distinct().sortedBy(Path::toString)) {
            "runtime probe mappings are not canonical, unique, and sorted"
        }
        check(executable in executableMappings) { "effective Python executable was not mapped" }
        check(jsonExtension in executableMappings) { "Python _json extension was not mapped" }
        executableMappings.forEach { mapping ->
            check(Files.isRegularFile(mapping)) { "Python executable mapping is not a file: $mapping" }
            check(mapping.hasElfMagic()) { "Python executable mapping is not ELF: $mapping" }
        }

        val loaderDestination = executable.readElfInterpreter()
        val loaderSource = loaderDestination.toRealPath()
        check(loaderSource in executableMappings) {
            "Python ELF interpreter was not present in its executable mappings: $loaderSource"
        }
        val mountsByDestination = linkedMapOf<Path, AcpSandboxReadOnlyMount>()
        fun addMount(source: Path, destination: Path = source) {
            val mount = AcpSandboxReadOnlyMount(source, destination)
            val existing = mountsByDestination.putIfAbsent(destination, mount)
            check(existing == null || existing.source == source) {
                "Python native runtime produced conflicting mount destination: $destination"
            }
        }

        addMount(loaderSource, loaderDestination)
        executableMappings.asSequence()
            .filter { it != executable }
            .sortedBy(Path::toString)
            .forEach { source ->
                runtimeAliasDestinations(source).forEach { destination ->
                    addMount(source, destination)
                }
            }
        val mounts = mountsByDestination.values.sortedBy { it.destination.toString() }
        check(mounts.any { it.source == jsonExtension }) {
            "Python _json extension was omitted from its runtime mounts"
        }
        return AcpPythonRuntimeLayout(
            executable = executable,
            stdlib = stdlib,
            jsonExtension = jsonExtension,
            nativeRuntimeMounts = mounts,
        )
    }

    /**
     * Expands only verified SONAME and FHS compatibility symlinks for an already authenticated
     * runtime file.
     * The kernel reports canonical `/usr/lib*` paths in `/proc/self/maps`, while an ELF loader may
     * reopen a sibling SONAME such as `libz.so.1` and may search `/lib*`. A fresh bubblewrap root has
     * no host symlinks, so every verified destination must name the same pinned source explicitly.
     */
    internal fun runtimeAliasDestinations(
        source: Path,
        aliasRoots: List<Path> = defaultRuntimeAliasRoots,
    ): List<Path> {
        requireAbsoluteNormalized("Python native runtime source", source)
        val canonicalSource = source.toRealPath()
        check(source == canonicalSource) { "Python native runtime source is not canonical: $source" }
        val canonicalDestinations = linkedSetOf(source)
        Files.newDirectoryStream(source.parent).use { siblings ->
            siblings.asSequence()
                .filter { Files.isSymbolicLink(it) }
                .filter { runCatching { Files.isSameFile(source, it) }.getOrDefault(false) }
                .sortedBy(Path::toString)
                .forEach { sibling ->
                    check(canonicalDestinations.size < MAXIMUM_RUNTIME_FILE_ALIASES) {
                        "Python native runtime file has too many verified aliases: $source"
                    }
                    canonicalDestinations.add(sibling)
                }
        }
        val destinations = linkedSetOf<Path>()
        destinations.addAll(canonicalDestinations)
        aliasRoots.distinct().sortedBy(Path::toString).forEach { aliasRoot ->
            requireAbsoluteNormalized("runtime alias root", aliasRoot)
            if (!Files.isSymbolicLink(aliasRoot)) return@forEach
            val canonicalRoot = aliasRoot.toRealPath()
            if (!Files.isDirectory(canonicalRoot)) return@forEach
            canonicalDestinations.filter { it.startsWith(canonicalRoot) }.forEach { canonicalDestination ->
                val destination = aliasRoot.resolve(canonicalRoot.relativize(canonicalDestination)).normalize()
                check(destination.startsWith(aliasRoot)) { "runtime alias escaped its root: $destination" }
                check(Files.isSameFile(source, destination)) {
                    "runtime alias does not identify its canonical source: $destination"
                }
                destinations.add(destination)
            }
        }
        return destinations.sortedBy(Path::toString)
    }

    private fun java.io.InputStream.readBounded(): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8 * 1024)
        while (true) {
            val read = read(buffer)
            if (read < 0) break
            if (output.size() + read > MAXIMUM_PROBE_BYTES) {
                output.write(buffer, 0, MAXIMUM_PROBE_BYTES - output.size() + 1)
                break
            }
            output.write(buffer, 0, read)
        }
        return output.toByteArray()
    }

    private fun ByteArray.splitNulRecords(): List<ByteArray> {
        val records = mutableListOf<ByteArray>()
        var start = 0
        forEachIndexed { index, byte ->
            if (byte == 0.toByte()) {
                check(index > start) { "runtime probe emitted an empty field" }
                records += copyOfRange(start, index)
                start = index + 1
            }
        }
        check(start == size) { "runtime probe record was not NUL terminated" }
        return records
    }

    private fun ByteArray.decodeCanonicalPath(label: String): Path {
        val path = Path.of(decodeUtf8())
        requireAbsoluteNormalized(label, path)
        val canonical = path.toRealPath()
        check(path == canonical) { "$label is not canonical: $path" }
        return path
    }

    private fun ByteArray.decodeUtf8(): String = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(this))
        .toString()

    private fun Path.hasElfMagic(): Boolean = Files.newInputStream(this).use { input ->
        input.readNBytes(4).contentEquals(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
    }

    private fun Path.readElfInterpreter(): Path {
        StandardOpenOption.READ.let { option ->
            java.nio.channels.FileChannel.open(this, option).use { channel ->
                val identification = channel.readExactly(0, 16)
                check(identification[0] == 0x7f.toByte() && identification.copyOfRange(1, 4).decodeUtf8() == "ELF") {
                    "Python executable is not ELF: $this"
                }
                val elfClass = identification[4].toInt() and 0xff
                val byteOrder = when (identification[5].toInt() and 0xff) {
                    1 -> ByteOrder.LITTLE_ENDIAN
                    2 -> ByteOrder.BIG_ENDIAN
                    else -> error("Python executable has an unsupported ELF byte order")
                }
                val headerSize = when (elfClass) {
                    1 -> 52
                    2 -> 64
                    else -> error("Python executable has an unsupported ELF class")
                }
                val header = ByteBuffer.wrap(channel.readExactly(0, headerSize)).order(byteOrder)
                val programOffset = if (elfClass == 1) {
                    header.getInt(28).toLong() and 0xffff_ffffL
                } else {
                    header.getLong(32)
                }
                val entrySize = header.getShort(if (elfClass == 1) 42 else 54).toInt() and 0xffff
                val entryCount = header.getShort(if (elfClass == 1) 44 else 56).toInt() and 0xffff
                check(entryCount != ELF_PN_XNUM) { "extended ELF program-header counts are unsupported" }
                val minimumEntrySize = if (elfClass == 1) 32 else 56
                check(entrySize >= minimumEntrySize && entrySize <= 4 * 1024) {
                    "Python executable has an invalid ELF program-header size"
                }
                check(entryCount in 1..1024) { "Python executable has an invalid ELF program-header count" }
                check(programOffset >= 0 && programOffset <= channel.size()) {
                    "Python executable has an invalid ELF program-header offset"
                }
                repeat(entryCount) { index ->
                    val offset = Math.addExact(programOffset, Math.multiplyExact(index.toLong(), entrySize.toLong()))
                    val entry = ByteBuffer.wrap(channel.readExactly(offset, entrySize)).order(byteOrder)
                    val type = entry.getInt(0).toLong() and 0xffff_ffffL
                    if (type == ELF_PT_INTERP) {
                        val interpreterOffset = if (elfClass == 1) {
                            entry.getInt(4).toLong() and 0xffff_ffffL
                        } else {
                            entry.getLong(8)
                        }
                        val interpreterSize = if (elfClass == 1) {
                            entry.getInt(16).toLong() and 0xffff_ffffL
                        } else {
                            entry.getLong(32)
                        }
                        check(interpreterSize in 2..MAXIMUM_ELF_INTERPRETER_BYTES.toLong()) {
                            "Python executable has an invalid ELF interpreter size"
                        }
                        val bytes = channel.readExactly(interpreterOffset, interpreterSize.toInt())
                        check(bytes.last() == 0.toByte() && bytes.dropLast(1).none { it == 0.toByte() }) {
                            "Python executable has a malformed ELF interpreter"
                        }
                        val interpreter = Path.of(bytes.copyOf(bytes.size - 1).decodeUtf8())
                        requireAbsoluteNormalized("Python ELF interpreter", interpreter)
                        check(Files.isRegularFile(interpreter)) { "Python ELF interpreter is unavailable: $interpreter" }
                        return interpreter
                    }
                }
            }
        }
        error("Python executable has no ELF interpreter")
    }

    private fun java.nio.channels.FileChannel.readExactly(offset: Long, size: Int): ByteArray {
        check(offset >= 0 && size >= 0 && offset <= this.size() - size) { "ELF field is outside the executable" }
        val buffer = ByteBuffer.allocate(size)
        var position = offset
        while (buffer.hasRemaining()) {
            val read = read(buffer, position)
            check(read > 0) { "ELF field could not be read completely" }
            position += read
        }
        return buffer.array()
    }

    private fun requireAbsoluteNormalized(label: String, path: Path) {
        require(path.isAbsolute && path == path.normalize()) { "$label must be absolute and normalized: $path" }
    }

    private val PYTHON_RUNTIME_PROBE = """
        import _json
        import _signal
        import json
        import os
        import posix
        import re
        import sysconfig
        import time

        executable_mappings = set()
        with open("/proc/self/maps", "rb", buffering=0) as mappings:
            for raw_line in mappings:
                fields = raw_line.rstrip(b"\n").split(None, 5)
                if len(fields) != 6 or not fields[5].startswith(b"/"):
                    continue
                if fields[5].endswith(b" (deleted)"):
                    raise RuntimeError("deleted executable mapping")
                candidate = os.path.realpath(os.fsdecode(fields[5]))
                try:
                    with open(candidate, "rb", buffering=0) as mapped_file:
                        if mapped_file.read(4) == b"\x7fELF":
                            executable_mappings.add(candidate)
                except OSError:
                    raise RuntimeError("mapped runtime file became unreadable")

        records = [
            b"$PROBE_MAGIC",
            os.fsencode(os.path.realpath("/proc/self/exe")),
            os.fsencode(os.path.realpath(sysconfig.get_path("stdlib"))),
            os.fsencode(os.path.realpath(_json.__file__)),
        ]
        records.extend(os.fsencode(path) for path in sorted(executable_mappings))
        os.write(1, b"\0".join(records) + b"\0")
    """.trimIndent()
}

internal data class AcpPythonRuntimeLayout(
    val executable: Path,
    val stdlib: Path,
    val jsonExtension: Path,
    val nativeRuntimeMounts: List<AcpSandboxReadOnlyMount>,
) {
    /** Creates exact same-path mounts for the pure-Python stdlib entries used by a fixture. */
    fun stdlibMounts(relativeEntries: Collection<String>): List<AcpSandboxReadOnlyMount> =
        relativeEntries.distinct().sorted().map { relative ->
            val relativePath = Path.of(relative)
            require(relative.isNotBlank() && !relativePath.isAbsolute && relativePath == relativePath.normalize()) {
                "Python stdlib entry must be a normalized relative path: $relative"
            }
            require(relativePath.none { it.toString() == ".." }) {
                "Python stdlib entry may not traverse its root: $relative"
            }
            val source = stdlib.resolve(relativePath).normalize()
            require(source.startsWith(stdlib) && Files.exists(source)) {
                "Python stdlib entry is unavailable: $source"
            }
            AcpSandboxReadOnlyMount(source)
        }
}
