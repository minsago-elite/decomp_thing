package decompengine.analysis

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.io.FileDescriptor
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import java.util.jar.JarFile
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import sun.misc.Unsafe

/**
 * Fixed analysis I/O commands, authenticated against resources belonging to this application.
 * Verification runs inside the existing capped launch supplier, not on the analysis caller.
 * This is application deployment identity, not oracle execution or hostile path authority.
 */
internal object AnalysisNativeIoHelper {
    internal const val BINARY_NAME = "decomp-analysis-io-helper"
    internal const val HELPER_PROPERTY = "decompengine.analysis.io.helper"
    private const val RESOURCE_DIRECTORY = "analysis-native-io"
    private const val PROPERTIES_NAME = "decomp-analysis-io-helper-v1.properties"
    private const val SOURCE_NAME = "source.c"
    private const val POLICY_NAME = "build-policy.txt"
    private const val RECORD_NAME = "build-v1.json"
    private const val MAXIMUM_HELPER_BYTES = 4 * 1024 * 1024
    private const val MAXIMUM_SOURCE_BYTES = 2 * 1024 * 1024
    private const val MAXIMUM_POLICY_BYTES = 16 * 1024
    private const val MAXIMUM_RECORD_BYTES = 64 * 1024
    private const val MAXIMUM_PROPERTIES_BYTES = 4 * 1024
    private val sha256Pattern = Regex("[0-9a-f]{64}")
    private val executablePins = AnalysisNativeIoExecutablePins()
    private val propertyKeys = setOf(
        "schemaVersion", "sourcePath", "sourceSha256", "buildPolicySha256", "helperSha256",
        "helperBytes", "architecture", "binaryName", "buildRecordPath", "buildRecordSha256", "buildRecordBytes",
    )

    fun reportCommand(candidate: Path, maximumBytes: Long): List<String> {
        require(candidate.fileSystem === FileSystems.getDefault() && candidate.isAbsolute)
        require(maximumBytes in 1..BoundedAnalysisArtifactStagingProcess.MAXIMUM_REPORT_BYTES)
        return pinCommand(null, listOf("report", candidate.toString(), maximumBytes.toString()), executablePins)
    }

    fun modelCommand(path: Path, maximumBytes: Long, residentLimit: Long): List<String> {
        require(path.fileSystem === FileSystems.getDefault() && path.isAbsolute)
        require(maximumBytes in 1..BoundedProgramModelAcquisitionProcess.MAXIMUM_MODEL_BYTES)
        require(residentLimit in BoundedProgramModelAcquisitionProcess.MINIMUM_WORKER_RESIDENT_BYTES..
            BoundedProgramModelAcquisitionProcess.MAXIMUM_WORKER_RESIDENT_BYTES)
        return pinCommand(null, listOf("model", path.toString(), maximumBytes.toString(), residentLimit.toString()), executablePins)
    }

    internal fun reportCommandAt(helper: Path, candidate: Path, maximumBytes: Long,
        pins: AnalysisNativeIoExecutablePins): List<String> {
        require(candidate.fileSystem === FileSystems.getDefault() && candidate.isAbsolute)
        require(maximumBytes in 1..BoundedAnalysisArtifactStagingProcess.MAXIMUM_REPORT_BYTES)
        return pinCommand(helper, listOf("report", candidate.toString(), maximumBytes.toString()), pins)
    }

    internal fun beforeLaunch(command: List<String>) {
        (command as? PinnedNativeIoCommand)?.pin?.beforeLaunch()
    }

    /** The owner's returned Process is retained before this potentially blocking descriptor close. */
    internal fun launchReturned(command: List<String>, process: Process) {
        (command as? PinnedNativeIoCommand)?.pin?.afterReturnedProcess(process)
    }

    /** No thrown starter result proves whether native exec consumed the parent descriptor. */
    internal fun launchUnknown(command: List<String>) {
        (command as? PinnedNativeIoCommand)?.pin?.launchUnknown()
    }

    private fun pinCommand(override: Path?, arguments: List<String>, pins: AnalysisNativeIoExecutablePins): List<String> {
        requireSupportedHost()
        val origin = Path.of(AnalysisNativeIoHelper::class.java.protectionDomain.codeSource.location.toURI())
            .toAbsolutePath()
        val reference = readReference(origin)
        val helper = override ?: selectedHelper(origin)
        val pin = pins.reserve()
        try {
            val before = regularAttributes(helper)
            val channel = FileChannel.open(helper, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)
            pin.accept(channel)
            val descriptor = Jdk21IoDescriptor.number(channel)
            val executable = Path.of("/proc", ProcessHandle.current().pid().toString(), "fd", descriptor.toString())
            val opened = Files.readAttributes(executable, BasicFileAttributes::class.java)
            require(sameFile(before, opened) && opened.isRegularFile && channel.size() == before.size()) {
                "analysis native I/O executable changed while its descriptor was opened"
            }
            val bytes = ByteArray(Math.toIntExact(before.size().also {
                require(it in 64..MAXIMUM_HELPER_BYTES.toLong())
            }))
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) require(channel.read(buffer) > 0)
            require(channel.read(ByteBuffer.allocate(1)) == -1 && channel.size() == before.size() &&
                sameFile(before, regularAttributes(helper))) { "analysis native I/O executable changed while being pinned" }
            verifyArtifact(helper, reference, bytes, executable)
            return PinnedNativeIoCommand(pin, listOf(executable.toString()) + arguments)
        } catch (failure: Throwable) {
            try { pin.notLaunched() } catch (cleanup: Throwable) {
                if (cleanup !== failure) failure.addSuppressed(cleanup)
            }
            throw failure
        }
    }

    private fun selectedHelper(origin: Path): Path {
        val configured = System.getProperty(HELPER_PROPERTY)
        return if (configured != null) {
            require(configured.isNotBlank()) { "analysis native I/O helper override is empty" }
            Path.of(configured).toAbsolutePath()
        } else if (Files.isDirectory(origin, LinkOption.NOFOLLOW_LINKS)) {
            val build = developmentBuildRoot(origin)
                ?: throw IllegalArgumentException("analysis native I/O helper requires its packaged application resources")
            build.resolve("native/analysis").resolve(BINARY_NAME)
        } else {
            requireNotNull(origin.parent?.parent).resolve("libexec").resolve(BINARY_NAME)
        }
    }

    /** Fixed verification seam: alternate bytes cannot replace the defining application's tuple. */
    internal fun verifyAt(helper: Path): Path {
        requireSupportedHost()
        val origin = Path.of(AnalysisNativeIoHelper::class.java.protectionDomain.codeSource.location.toURI())
            .toAbsolutePath()
        val bytes = readStableFile(helper, MAXIMUM_HELPER_BYTES)
        verifyArtifact(helper, readReference(origin), bytes)
        return helper
    }

    /** Read-only installed-artifact seam; no descriptor or execution permission is transferred. */
    internal fun verifiedDefaultArtifact(): Path {
        requireSupportedHost()
        val origin = Path.of(AnalysisNativeIoHelper::class.java.protectionDomain.codeSource.location.toURI())
            .toAbsolutePath()
        return verifyAt(selectedHelper(origin))
    }

    internal fun requireSupportedHost(
        operatingSystem: String = System.getProperty("os.name", ""),
        architecture: String = System.getProperty("os.arch", ""),
    ) {
        require(operatingSystem.equals("Linux", ignoreCase = true) && architecture in setOf("amd64", "x86_64")) {
            "bounded analysis native I/O supports only its qualified Linux x86-64 enforcement"
        }
        require(ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN) {
            "bounded analysis native I/O requires its qualified little-endian ABI"
        }
    }

    private data class Reference(val properties: Map<String, String>, val resources: Map<String, ByteArray>)

    private fun readReference(origin: Path): Reference {
        val limits = linkedMapOf(
            PROPERTIES_NAME to MAXIMUM_PROPERTIES_BYTES, SOURCE_NAME to MAXIMUM_SOURCE_BYTES,
            POLICY_NAME to MAXIMUM_POLICY_BYTES, RECORD_NAME to MAXIMUM_RECORD_BYTES,
        )
        val resources: Map<String, ByteArray>
        if (Files.isDirectory(origin, LinkOption.NOFOLLOW_LINKS)) {
            // Gradle separates main classes and resources. Derive only the sibling of this exact
            // main output; classpath resource lookup could accept another application's shadow.
            val included = origin.resolve(RESOURCE_DIRECTORY)
            val root = if (Files.isDirectory(included, LinkOption.NOFOLLOW_LINKS)) included
                else developmentBuildRoot(origin)?.resolve("resources/main/" + RESOURCE_DIRECTORY)
                    ?: throw IllegalArgumentException("analysis native I/O provenance is outside its defining code origin")
            resources = limits.mapValues { (name, maximum) -> readStableFile(root.resolve(name), maximum) }
        } else {
            val before = regularAttributes(origin)
            require(before.size() in 1..(256L * 1024 * 1024)) { "analysis application JAR exceeds its provenance read bound" }
            JarFile(origin.toFile(), false).use { jar ->
                resources = limits.mapValues { (name, maximum) ->
                    val entry = jar.getJarEntry(RESOURCE_DIRECTORY + "/" + name)
                        ?: throw IllegalArgumentException("application JAR omits analysis native I/O provenance")
                    require(!entry.isDirectory && entry.size in 1..maximum.toLong()) {
                        "analysis native I/O resource exceeds its byte bound"
                    }
                    jar.getInputStream(entry).use { input ->
                        input.readNBytes(maximum + 1).also { bytes ->
                            require(bytes.size in 1..maximum && bytes.size.toLong() == entry.size)
                            require(input.read() == -1)
                        }
                    }
                }
            }
            require(sameFile(before, regularAttributes(origin))) { "application JAR changed during native I/O verification" }
        }
        val properties = parseProperties(resources.getValue(PROPERTIES_NAME))
        require(properties.keys == propertyKeys) { "analysis native I/O provenance has missing or unknown properties" }
        require(properties.getValue("schemaVersion") == "1" && properties.getValue("binaryName") == BINARY_NAME &&
            properties.getValue("architecture") == "linux-x86-64" &&
            properties.getValue("sourcePath") == RESOURCE_DIRECTORY + "/" + SOURCE_NAME &&
            properties.getValue("buildRecordPath") == RESOURCE_DIRECTORY + "/" + RECORD_NAME) {
            "analysis native I/O provenance has an unsupported identity"
        }
        for (key in listOf("sourceSha256", "buildPolicySha256", "helperSha256", "buildRecordSha256")) {
            require(sha256Pattern.matches(properties.getValue(key))) { "analysis native I/O provenance digest is invalid" }
        }
        require(properties.longValue("helperBytes") in 64..MAXIMUM_HELPER_BYTES.toLong())
        require(properties.longValue("buildRecordBytes") == resources.getValue(RECORD_NAME).size.toLong())
        require(digest(resources.getValue(SOURCE_NAME)) == properties.getValue("sourceSha256") &&
            digest(resources.getValue(POLICY_NAME)) == properties.getValue("buildPolicySha256") &&
            digest(resources.getValue(RECORD_NAME)) == properties.getValue("buildRecordSha256")) {
            "analysis native I/O source or build provenance does not match the application tuple"
        }
        verifyBuildRecord(resources.getValue(RECORD_NAME), properties)
        return Reference(properties, resources)
    }

    private fun developmentBuildRoot(origin: Path): Path? {
        val suffix = Path.of("build", "classes", "kotlin", "main")
        if (!origin.endsWith(suffix)) return null
        return origin.parent.parent.parent
    }

    private fun verifyArtifact(helper: Path, reference: Reference, bytes: ByteArray, openedExecutable: Path = helper) {
        require(helper.fileSystem === FileSystems.getDefault() && helper.isAbsolute && helper.fileName.toString() == BINARY_NAME)
        require(Files.isExecutable(openedExecutable)) { "analysis native I/O helper is not executable" }
        // The production path follows only our /proc FD link, so permissions belong to the
        // opened image even if its ordinary pathname is atomically replaced during verification.
        val permissions = Files.getPosixFilePermissions(openedExecutable)
        require(PosixFilePermission.GROUP_WRITE !in permissions && PosixFilePermission.OTHERS_WRITE !in permissions) {
            "analysis native I/O helper is writable outside its owner"
        }
        require(bytes.size.toLong() == reference.properties.longValue("helperBytes") &&
            digest(bytes) == reference.properties.getValue("helperSha256")) {
            "analysis native I/O helper does not match the defining application's build tuple"
        }
        verifyStaticElf(bytes)
        val sidecars = requireNotNull(helper.parent).resolve(RESOURCE_DIRECTORY)
        for ((name, expected) in reference.resources) {
            val installed = readStableFile(sidecars.resolve(name), expected.size)
            require(MessageDigest.isEqual(expected, installed)) {
                "installed analysis native I/O provenance differs from the defining application"
            }
        }
    }

    private fun verifyStaticElf(bytes: ByteArray) {
        require(bytes.size >= 64 && bytes[0] == 0x7f.toByte() && bytes[1] == 'E'.code.toByte() &&
            bytes[2] == 'L'.code.toByte() && bytes[3] == 'F'.code.toByte() &&
            bytes[4] == 2.toByte() && bytes[5] == 1.toByte() && bytes[6] == 1.toByte()) {
            "analysis native I/O helper is not the qualified ELF64 image"
        }
        val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        require(elf.getShort(16).toInt() == 2 && elf.getShort(18).toInt() == 62 && elf.getInt(20) == 1 &&
            elf.getShort(52).toInt() == 64 && elf.getShort(54).toInt() == 56) {
            "analysis native I/O helper has an unsupported ELF ABI"
        }
        val offset = elf.getLong(32)
        val count = elf.getShort(56).toInt() and 0xffff
        require(offset >= 64 && count in 1..128 && offset <= bytes.size.toLong() - count * 56L)
        var loads = 0
        for (index in 0 until count) {
            val position = Math.toIntExact(offset + index * 56L)
            val kind = elf.getInt(position)
            require(kind != 2 && kind != 3) { "analysis native I/O helper must have no dynamic loader or dynamic segment" }
            if (kind == 1) {
                loads++
                val fileOffset = elf.getLong(position + 8)
                val fileSize = elf.getLong(position + 32)
                val memorySize = elf.getLong(position + 40)
                require(fileOffset >= 0 && fileSize >= 0 && memorySize >= fileSize &&
                    memorySize <= BoundedProgramModelAcquisitionProcess.MINIMUM_WORKER_RESIDENT_BYTES &&
                    fileOffset <= bytes.size.toLong() - fileSize)
            }
            if (kind == 0x6474e551) require(elf.getInt(position + 4) and 1 == 0) {
                "analysis native I/O helper has an executable stack"
            }
        }
        require(loads > 0)
    }

    private fun verifyBuildRecord(bytes: ByteArray, properties: Map<String, String>) {
        // Reuse only a bounded, duplicate-rejecting parser; no oracle execution authority is used.
        val root = OracleJson.parse(bytes, StrictJsonLimits(
            maximumInputBytes = MAXIMUM_RECORD_BYTES, maximumCanonicalBytes = MAXIMUM_RECORD_BYTES,
            maximumDepth = 6, maximumNodes = 256, maximumStringBytes = 8 * 1024,
            maximumTotalStringBytes = 48 * 1024, maximumNumberCharacters = 20,
        )) as? JsonObject ?: throw IllegalArgumentException("analysis helper build record is not an object")
        root.keysExactly("schemaVersion", "kind", "binaryName", "architecture", "sourceSha256",
            "buildPolicySha256", "helperSha256", "helperBytes", "compiler", "compilation")
        require(root.number("schemaVersion") == 1L && root.string("kind") == "analysis-native-io-helper-build-v1")
        for (key in listOf("binaryName", "architecture", "sourceSha256", "buildPolicySha256", "helperSha256")) {
            require(root.string(key) == properties.getValue(key)) { "analysis helper build record disagrees with its tuple" }
        }
        require(root.number("helperBytes") == properties.longValue("helperBytes"))
        val compiler = root.obj("compiler")
        compiler.keysExactly("path", "bytes", "sha256", "version", "versionCommand", "result")
        val compilerPath = compiler.string("path")
        require(Path.of(compilerPath).isAbsolute && compiler.number("bytes") in 1..(512L * 1024 * 1024) &&
            sha256Pattern.matches(compiler.string("sha256")) && compiler.string("version").isNotBlank())
        require(compiler.array("versionCommand").map(::jsonString) == listOf(compilerPath, "--version"))
        verifySuccessfulResult(compiler.obj("result"))
        val compilation = root.obj("compilation")
        compilation.keysExactly("arguments", "environment", "workingDirectory", "timeoutMillis",
            "maximumStdoutBytes", "maximumStderrBytes", "result")
        val arguments = compilation.array("arguments").map(::jsonString)
        val prefix = listOf(compilerPath, "-std=c11", "-O2", "-static", "-no-pie", "-Wall", "-Wextra", "-Werror",
            "-Wformat=2", "-Wl,--build-id=none")
        require(arguments.size == 13 && arguments.take(prefix.size) == prefix && arguments[11] == "-o") {
            "analysis helper build record differs from its fixed static recipe"
        }
        val source = Path.of(arguments[10])
        val output = Path.of(arguments[12])
        require(source.isAbsolute && output.isAbsolute && source.parent == output.parent &&
            source.fileName.toString() == "decomp_analysis_io_helper.c" && output.fileName.toString() == BINARY_NAME)
        val environment = compilation.obj("environment")
        environment.keysExactly("HOME", "TMPDIR", "PATH", "LC_ALL", "LANG", "TZ", "SOURCE_DATE_EPOCH")
        require(Path.of(environment.string("HOME")).isAbsolute && Path.of(environment.string("TMPDIR")).isAbsolute &&
            environment.string("PATH") == "/usr/bin:/bin" && environment.string("LC_ALL") == "C" &&
            environment.string("LANG") == "C" && environment.string("TZ") == "UTC" &&
            environment.string("SOURCE_DATE_EPOCH") == "1779182222")
        require(compilation.string("workingDirectory") == "/" && compilation.number("timeoutMillis") == 30_000L &&
            compilation.number("maximumStdoutBytes") == 65_536L && compilation.number("maximumStderrBytes") == 65_536L)
        verifySuccessfulResult(compilation.obj("result"))
    }

    private fun verifySuccessfulResult(result: JsonObject) {
        result.keysExactly("exitCode", "signal", "stdoutBytes", "stdoutSha256", "stderrBytes", "stderrSha256")
        require(result.number("exitCode") == 0L && result.getValue("signal") == JsonNull &&
            result.number("stdoutBytes") in 0..65_536L && result.number("stderrBytes") in 0..65_536L &&
            sha256Pattern.matches(result.string("stdoutSha256")) && sha256Pattern.matches(result.string("stderrSha256"))) {
            "analysis helper build record does not prove successful bounded compilation"
        }
    }

    private fun parseProperties(bytes: ByteArray): Map<String, String> {
        require(bytes.isNotEmpty() && bytes.last() == '\n'.code.toByte() &&
            bytes.all { it == '\n'.code.toByte() || it.toInt() in 0x20..0x7e })
        val result = linkedMapOf<String, String>()
        for (line in String(bytes, Charsets.US_ASCII).dropLast(1).split('\n')) {
            val separator = line.indexOf('=')
            require(separator > 0 && separator < line.lastIndex)
            val key = line.substring(0, separator)
            require(result.put(key, line.substring(separator + 1)) == null) { "analysis helper provenance repeats a property" }
        }
        return result
    }

    private fun readStableFile(path: Path, maximumBytes: Int): ByteArray {
        val before = regularAttributes(path)
        require(before.size() in 1..maximumBytes.toLong()) { "analysis native I/O artifact exceeds its read bound" }
        val bytes = Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input ->
            input.readNBytes(maximumBytes + 1).also { require(it.size in 1..maximumBytes && input.read() == -1) }
        }
        require(bytes.size.toLong() == before.size() && sameFile(before, regularAttributes(path))) {
            "analysis native I/O artifact changed while being verified"
        }
        return bytes
    }

    private fun regularAttributes(path: Path): BasicFileAttributes =
        Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).also {
            require(it.isRegularFile && it.fileKey() != null) { "analysis native I/O artifact is not a stable regular file" }
        }
    private fun sameFile(left: BasicFileAttributes, right: BasicFileAttributes): Boolean =
        left.fileKey() == right.fileKey() && left.size() == right.size() && left.lastModifiedTime() == right.lastModifiedTime()
    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun Map<String, String>.longValue(key: String): Long = getValue(key).let {
        require(it.matches(Regex("0|[1-9][0-9]*"))) { "analysis native I/O provenance number is invalid" }
        it.toLong()
    }
    private fun JsonObject.keysExactly(vararg keys: String) { require(this.keys == keys.toSet()) }
    private fun JsonObject.obj(key: String): JsonObject = getValue(key) as? JsonObject
        ?: throw IllegalArgumentException("analysis helper build record object is invalid")
    private fun JsonObject.array(key: String): JsonArray = getValue(key) as? JsonArray
        ?: throw IllegalArgumentException("analysis helper build record array is invalid")
    private fun JsonObject.string(key: String): String = jsonString(getValue(key))
    private fun jsonString(value: JsonElement): String {
        val string = value as? JsonPrimitive
        require(string != null && string.isString)
        return string.content.also { require(it.isNotEmpty() && '\u0000' !in it) }
    }
    private fun JsonObject.number(key: String): Long {
        val number = getValue(key) as? JsonPrimitive
        require(number != null && !number.isString && number.content.matches(Regex("0|[1-9][0-9]*")))
        return number.content.toLong()
    }
}

/** Only pending launches retain a pin; unknown launches/blocked closes keep these bounded slots. */
internal class AnalysisNativeIoExecutablePins(
    private val close: (FileChannel) -> Unit = { it.close() },
) {
    private val pins = linkedSetOf<NativeIoExecutablePin>()
    @Synchronized internal fun reserve(): NativeIoExecutablePin {
        require(pins.none { it.unconfirmed.get() }) { "analysis executable pin cleanup is unconfirmed" }
        require(pins.size < 2) { "analysis executable pin capacity is exhausted" }
        return NativeIoExecutablePin(this, close).also(pins::add)
    }
    @Synchronized internal fun release(pin: NativeIoExecutablePin) { if (pin.closed.get()) pins.remove(pin) }
    @Synchronized internal fun retained(): Int = pins.size
}

internal class NativeIoExecutablePin(
    private val owner: AnalysisNativeIoExecutablePins,
    private val close: (FileChannel) -> Unit,
) {
    private var channel: FileChannel? = null
    private val admitted = AtomicBoolean(false)
    private val closing = AtomicBoolean(false)
    val closed = AtomicBoolean(false)
    val unconfirmed = AtomicBoolean(false)
    fun accept(value: FileChannel) { check(channel == null); channel = value }
    fun beforeLaunch() { check(admitted.compareAndSet(false, true)) }
    fun notLaunched() { check(!admitted.get()); closePin() }
    fun launchUnknown() { if (!closed.get()) unconfirmed.set(true) }
    fun afterReturnedProcess(process: Process) {
        check(admitted.get())
        try {
            // This qualified OpenJDK21 ProcessImpl waits for the child's CLOEXEC exec-error
            // pipe EOF before returning. It has therefore consumed /proc/<parent>/fd/<fd>.
            // Generic Process objects cannot supply that acknowledgement. The helper disables
            // dumpability, so inspecting /proc/<child>/exe is deliberately not required.
            require(Runtime.version().feature() == 21 && process.javaClass.name == "java.lang.ProcessImpl" &&
                process.javaClass.classLoader == null && process.javaClass.module.name == "java.base") {
                "analysis executable pin requires its qualified OpenJDK21 exec acknowledgement"
            }
            closePin()
        } catch (failure: Throwable) {
            launchUnknown()
            throw failure
        }
    }
    private fun closePin() {
        if (!closing.compareAndSet(false, true)) return
        // A blocked or failed close must refuse another admission until actual closure returns.
        unconfirmed.set(true)
        try {
            channel?.let { opened ->
                close(opened)
                check(!opened.isOpen) { "analysis executable descriptor close was not acknowledged" }
            }
            closed.set(true)
            channel = null
            owner.release(this)
        } catch (failure: Throwable) {
            unconfirmed.set(true)
            throw failure
        }
    }
}

private class PinnedNativeIoCommand(
    val pin: NativeIoExecutablePin,
    private val arguments: List<String>,
) : List<String> by arguments

/** One verified OpenJDK21 layout; no field scanning, external native library or fallback exists. */
private object Jdk21IoDescriptor {
    private val channelClass = Class.forName("sun.nio.ch.FileChannelImpl")
    private val unsafe: Unsafe = Unsafe::class.java.getDeclaredField("theUnsafe").let { field ->
        require(Unsafe::class.java.classLoader == null)
        field.isAccessible = true
        field.get(null) as Unsafe
    }
    private val channelOffset = channelClass.getDeclaredField("fd").let { field ->
        require(channelClass.classLoader == null && channelClass.module.name == "java.base" &&
            field.type == FileDescriptor::class.java)
        unsafe.objectFieldOffset(field)
    }
    private val descriptorOffset = FileDescriptor::class.java.getDeclaredField("fd").let { field ->
        require(field.type == Int::class.javaPrimitiveType)
        unsafe.objectFieldOffset(field)
    }
    fun number(channel: FileChannel): Int {
        require(Runtime.version().feature() == 21 && channel.javaClass == channelClass) {
            "analysis executable pinning requires its qualified OpenJDK21 descriptor layout"
        }
        val descriptor = unsafe.getObject(channel, channelOffset) as? FileDescriptor
            ?: throw IllegalArgumentException("analysis executable descriptor layout is unavailable")
        val number = unsafe.getInt(descriptor, descriptorOffset)
        require(descriptor.valid() && number >= 0)
        return number
    }
}
