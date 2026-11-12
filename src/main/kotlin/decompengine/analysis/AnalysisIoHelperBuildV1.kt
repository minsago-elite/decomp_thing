package decompengine.analysis

import decompengine.acp.LinuxBoundedSessionCommand
import decompengine.acp.LinuxBoundedSessionProcess
import decompengine.acp.LinuxBoundedSessionResult
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Duration
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Builds only the reviewed analysis I/O endpoint. The retained compiler executable and its
 * implicit headers/libraries/tools are cooperating build principals, not compiler qualification.
 * This producer accepts raw paths, executes its fixed recipe and emits passive build provenance.
 * The shared descriptor/process/JSON mechanisms confer no oracle or ACP execution authority.
 */
object AnalysisIoHelperBuildV1 {
    fun build(compilerPath: Path, sourcePath: Path, outputDirectory: Path): Path {
        require(System.getProperty("os.name") == "Linux" &&
            System.getProperty("os.arch") in setOf("amd64", "x86_64")) {
            "analysis I/O helper production requires the pinned Linux x86-64 native bootstrap"
        }
        val compiler = exactAnalysisBuildPath(compilerPath)
        val source = exactAnalysisBuildPath(sourcePath)
        val root = exactAnalysisBuildPath(outputDirectory)
        require(source.fileName.toString() == "decomp_analysis_io_helper.c")
        requireAnalysisBuildDirectory(root)
        require(!source.startsWith(root) && !compiler.startsWith(root))
        require(Files.isExecutable(compiler)) { "analysis helper compiler is not executable" }
        val temporary = Files.createTempDirectory(root, ".analysis-io-build-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            StableControlFile.open(source, 256L * 1024, "analysis helper source").use { sourceGuard ->
                sourceGuard.requireSingleLink("analysis helper source")
                require(sourceGuard.authenticatedSha256 == ANALYSIS_IO_REVIEWED_SOURCE_SHA256) {
                    "analysis helper source differs from the reviewed fixed endpoint"
                }
                StableControlFile.open(compiler, 512L * 1024 * 1024, "analysis helper compiler").use { compilerGuard ->
                    compilerGuard.requireSingleLink("analysis helper compiler")
                    val sourceBytes = sourceGuard.readExactly(0, sourceGuard.size.toInt(), "analysis helper source")
                    val stagedSource = temporary.resolve("decomp_analysis_io_helper.c")
                    writeAnalysisBuildFile(stagedSource, sourceBytes, "r--------")
                    val home = Files.createDirectory(temporary.resolve("home"))
                    val scratch = Files.createDirectory(temporary.resolve("tmp"))
                    val environment = linkedMapOf("HOME" to home.toString(), "LANG" to "C", "LC_ALL" to "C",
                        "PATH" to "/usr/bin:/bin", "SOURCE_DATE_EPOCH" to "1779182222",
                        "TMPDIR" to scratch.toString(), "TZ" to "UTC")
                    fun current() {
                        sourceGuard.verifyUnchanged("analysis helper source execution")
                        compilerGuard.verifyUnchanged("analysis helper compiler execution")
                        require(Files.isExecutable(compiler))
                    }
                    current()
                    val versionArguments = listOf(compiler.toString(), "--version")
                    val version = runAnalysisBuildCommand(versionArguments, environment, Duration.ofSeconds(10))
                    current()
                    val versionText = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(version.stdout)).toString()
                    val firstLine = versionText.lineSequence().firstOrNull().orEmpty()
                    require(firstLine.isNotEmpty() && firstLine.encodeToByteArray().size <= 4096 &&
                        firstLine.none { it.code < 0x20 || it.code == 0x7f }) { "compiler version is not bounded text" }
                    val helper = temporary.resolve(ANALYSIS_IO_BINARY_NAME)
                    val arguments = listOf(compiler.toString()) + ANALYSIS_IO_COMPILER_ARGUMENTS.map {
                        when (it) { "\${SOURCE}" -> stagedSource.toString(); "\${OUTPUT}" -> helper.toString(); else -> it }
                    }
                    StableControlFile.open(stagedSource, 256L * 1024, "staged analysis helper source").use { staged ->
                        val compilation = runAnalysisBuildCommand(arguments, environment, Duration.ofSeconds(30))
                        current(); staged.verifyUnchanged("analysis source after compilation")
                        require(staged.authenticatedSha256 == sourceGuard.authenticatedSha256)
                        require(Files.isRegularFile(helper, LinkOption.NOFOLLOW_LINKS))
                        Files.setPosixFilePermissions(helper, PosixFilePermissions.fromString("rwxr-xr-x"))
                        val helperBytes = analysisBuildBytes(helper, 4L * 1024 * 1024)
                        verifyAnalysisIoStaticElf(helperBytes)
                        val helperSha256 = analysisBuildSha256(helperBytes)
                        val policy = ANALYSIS_IO_BUILD_POLICY.toByteArray(StandardCharsets.US_ASCII)
                        val policySha256 = analysisBuildSha256(policy)
                        val record = JsonObject(linkedMapOf(
                            "schemaVersion" to JsonPrimitive(1), "kind" to JsonPrimitive("analysis-native-io-helper-build-v1"),
                            "binaryName" to JsonPrimitive(ANALYSIS_IO_BINARY_NAME), "architecture" to JsonPrimitive("linux-x86-64"),
                            "sourceSha256" to JsonPrimitive(sourceGuard.authenticatedSha256),
                            "buildPolicySha256" to JsonPrimitive(policySha256), "helperSha256" to JsonPrimitive(helperSha256),
                            "helperBytes" to JsonPrimitive(helperBytes.size),
                            "compiler" to JsonObject(linkedMapOf("path" to JsonPrimitive(ANALYSIS_IO_RECORDED_COMPILER),
                                "bytes" to JsonPrimitive(compilerGuard.size), "sha256" to JsonPrimitive(compilerGuard.authenticatedSha256),
                                "version" to JsonPrimitive(firstLine), "versionCommand" to analysisBuildStrings(listOf(ANALYSIS_IO_RECORDED_COMPILER, "--version")),
                                "result" to analysisBuildProcessResult(version))),
                            "compilation" to JsonObject(linkedMapOf("arguments" to analysisBuildStrings(analysisRecordedArguments()),
                                "environment" to JsonObject(analysisRecordedEnvironment(environment).mapValues { JsonPrimitive(it.value) }),
                                "workingDirectory" to JsonPrimitive("/"), "timeoutMillis" to JsonPrimitive(30000),
                                "maximumStdoutBytes" to JsonPrimitive(65536), "maximumStderrBytes" to JsonPrimitive(65536),
                                "result" to analysisBuildProcessResult(compilation))),
                        ))
                        val recordBytes = OracleJson.canonicalBytes(record, StrictJsonLimits(maximumInputBytes = 64 * 1024, maximumCanonicalBytes = 64 * 1024, maximumDepth = 6,
                            maximumNodes = 256, maximumStringBytes = 8 * 1024, maximumTotalStringBytes = 48 * 1024))
                        val properties = linkedMapOf("schemaVersion" to "1", "sourcePath" to "analysis-native-io/source.c",
                            "sourceSha256" to sourceGuard.authenticatedSha256, "buildPolicySha256" to policySha256,
                            "helperSha256" to helperSha256, "helperBytes" to helperBytes.size.toString(),
                            "architecture" to "linux-x86-64", "binaryName" to ANALYSIS_IO_BINARY_NAME,
                            "buildRecordPath" to "analysis-native-io/build-v1.json", "buildRecordBytes" to recordBytes.size.toString(),
                            "buildRecordSha256" to analysisBuildSha256(recordBytes))
                        val metadata = Files.createDirectory(temporary.resolve(ANALYSIS_IO_METADATA_DIRECTORY))
                        writeAnalysisBuildFile(metadata.resolve("source.c"), sourceBytes, "rw-r--r--")
                        writeAnalysisBuildFile(metadata.resolve("build-policy.txt"), policy, "rw-r--r--")
                        writeAnalysisBuildFile(metadata.resolve("build-v1.json"), recordBytes, "rw-r--r--")
                        writeAnalysisBuildFile(metadata.resolve(ANALYSIS_IO_PROPERTIES_NAME), properties.entries.joinToString("", transform = { "${it.key}=${it.value}\n" }).encodeToByteArray(), "rw-r--r--")
                        writeAnalysisBuildFile(temporary.resolve("$ANALYSIS_IO_BINARY_NAME.sha256"),
                            "$helperSha256  $ANALYSIS_IO_BINARY_NAME\n".encodeToByteArray(), "rw-r--r--")
                        current(); staged.verifyUnchanged("analysis source before publication")
                        require(analysisBuildSha256(analysisBuildBytes(helper, 4L * 1024 * 1024)) == helperSha256)
                    }
                    current()
                }
            }
            // Replaceable build outputs are not publication receipts. The properties tuple is moved
            // last; the runtime locator independently reopens all sidecars against its own resources.
            val metadata = root.resolve(ANALYSIS_IO_METADATA_DIRECTORY)
            if (!Files.exists(metadata, LinkOption.NOFOLLOW_LINKS)) Files.createDirectory(metadata)
            requireAnalysisBuildDirectory(metadata)
            listOf(ANALYSIS_IO_BINARY_NAME, "$ANALYSIS_IO_BINARY_NAME.sha256").forEach {
                publishAnalysisBuildFile(temporary.resolve(it), root.resolve(it))
            }
            listOf("source.c", "build-policy.txt", "build-v1.json", ANALYSIS_IO_PROPERTIES_NAME).forEach {
                publishAnalysisBuildFile(temporary.resolve(ANALYSIS_IO_METADATA_DIRECTORY).resolve(it), metadata.resolve(it))
            }
            return metadata.resolve(ANALYSIS_IO_PROPERTIES_NAME)
        } finally {
            Files.walk(temporary).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}

/**
 * The compiler runs in a private, randomly named directory under the Gradle build directory. Its
 * shipped record names that directory by this fixed token instead, so the application JAR carries
 * no build-host path and is byte-identical across rebuilds of the same source with the same
 * compiler. The token stands for the per-build directory holding the staged source, the output
 * and the `home`/`tmp` scratch directories. The compiler's logical location is also relative to
 * this record root (it is not copied there); its measured size/digest and recipe bindings stay exact.
 * The record is passive provenance, not a command to execute at the logical location.
 */
internal const val ANALYSIS_IO_RECORDED_BUILD_ROOT = "\${BUILD_ROOT}"
internal const val ANALYSIS_IO_RECORDED_COMPILER = "$ANALYSIS_IO_RECORDED_BUILD_ROOT/compiler"

internal fun analysisRecordedArguments(): List<String> =
    listOf(ANALYSIS_IO_RECORDED_COMPILER) + ANALYSIS_IO_COMPILER_ARGUMENTS.map {
        when (it) {
            "\${SOURCE}" -> "$ANALYSIS_IO_RECORDED_BUILD_ROOT/decomp_analysis_io_helper.c"
            "\${OUTPUT}" -> "$ANALYSIS_IO_RECORDED_BUILD_ROOT/$ANALYSIS_IO_BINARY_NAME"
            else -> it
        }
    }

internal fun analysisRecordedEnvironment(environment: Map<String, String>): Map<String, String> =
    LinkedHashMap(environment).apply {
        replace("HOME", "$ANALYSIS_IO_RECORDED_BUILD_ROOT/home")
        replace("TMPDIR", "$ANALYSIS_IO_RECORDED_BUILD_ROOT/tmp")
    }

object AnalysisIoHelperBuildV1Cli {
    @JvmStatic fun main(arguments: Array<String>) {
        require(arguments.size == 3) { "usage: <absolute-compiler> <absolute-source> <absolute-output-directory>" }
        val reference = AnalysisIoHelperBuildV1.build(Path.of(arguments[0]), Path.of(arguments[1]), Path.of(arguments[2]))
        println("${analysisBuildSha256(Files.readAllBytes(reference))}  $ANALYSIS_IO_PROPERTIES_NAME")
    }
}

private fun runAnalysisBuildCommand(arguments: List<String>, environment: Map<String, String>, timeout: Duration): LinuxBoundedSessionResult {
    val result = LinuxBoundedSessionProcess.execute(LinuxBoundedSessionCommand(arguments, environment,
        timeout = timeout, maximumStdoutBytes = 65536, maximumStderrBytes = 65536))
    require(result.exitCode == 0 && result.signal == null) { "analysis helper compiler failed (exit=${result.exitCode}, signal=${result.signal})" }
    return result
}
private fun analysisBuildProcessResult(result: LinuxBoundedSessionResult) = JsonObject(linkedMapOf(
    "exitCode" to JsonPrimitive(0), "signal" to JsonNull,
    "stdoutBytes" to JsonPrimitive(result.stdout.size), "stdoutSha256" to JsonPrimitive(analysisBuildSha256(result.stdout)),
    "stderrBytes" to JsonPrimitive(result.stderr.size), "stderrSha256" to JsonPrimitive(analysisBuildSha256(result.stderr))))
private fun analysisBuildStrings(values: List<String>) = JsonArray(values.map(::JsonPrimitive))
internal fun analysisBuildSha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
    .joinToString("") { "%02x".format(it) }
private fun exactAnalysisBuildPath(path: Path): Path = path.also {
    require(it.isAbsolute && it.normalize() == it && it.parent != null && it.toRealPath() == it) { "analysis build path is not canonical" }
}
private fun requireAnalysisBuildDirectory(path: Path) {
    require(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) && path.toRealPath() == path)
    val mode = (Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
    val uid = (Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
    val currentUid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
    require(uid == currentUid && mode and 0x12 == 0) { "analysis build directory is not owner controlled" }
}
private fun analysisBuildBytes(path: Path, maximum: Long) = StableControlFile.open(path, maximum, "analysis build output").use {
    it.requireSingleLink("analysis build output")
    it.readExactly(0, it.size.toInt(), "analysis build output").also { _ -> it.verifyUnchanged("analysis build output") }
}
private fun writeAnalysisBuildFile(path: Path, bytes: ByteArray, mode: String) {
    FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use {
        val buffer = ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) it.write(buffer); it.force(true)
    }
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(mode))
}
private fun publishAnalysisBuildFile(source: Path, target: Path) {
    requireAnalysisBuildDirectory(target.parent)
    require(!Files.exists(target, LinkOption.NOFOLLOW_LINKS) || Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS))
    Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    FileChannel.open(target.parent, StandardOpenOption.READ).use { it.force(true) }
}
internal fun verifyAnalysisIoStaticElf(bytes: ByteArray) {
    require(bytes.size in 64..4 * 1024 * 1024 && bytes.copyOfRange(0, 4).contentEquals(byteArrayOf(0x7f, 0x45, 0x4c, 0x46)))
    val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    require(bytes[4].toInt() == 2 && bytes[5].toInt() == 1 && bytes[6].toInt() == 1 &&
        elf.getShort(18).toInt() == 62 && elf.getInt(20) == 1 && elf.getShort(52).toInt() == 64)
    require(elf.getShort(16).toInt() == 2)
    val offset = elf.getLong(32); val stride = elf.getShort(54).toInt() and 0xffff; val count = elf.getShort(56).toInt() and 0xffff
    require(stride == 56 && count in 1..256 && offset >= 64 && offset <= bytes.size.toLong() - count.toLong() * stride)
    var executableLoad = false
    repeat(count) {
        val at = (offset + it.toLong() * stride).toInt(); val type = elf.getInt(at)
        require(type != 2 && type != 3) { "analysis helper has dynamic or interpreter ELF headers" }
        if (type == 1) {
            val fileOffset = elf.getLong(at + 8); val fileBytes = elf.getLong(at + 32); val memoryBytes = elf.getLong(at + 40)
            require(fileOffset >= 0 && fileBytes >= 0 && memoryBytes >= fileBytes && fileOffset <= bytes.size.toLong() - fileBytes)
            executableLoad = executableLoad || elf.getInt(at + 4) and 1 != 0
        }
    }
    require(executableLoad)
    require(String(bytes, StandardCharsets.ISO_8859_1).contains("decomp-analysis-io-helper-v1")) { "analysis helper contract marker is absent" }
}
internal const val ANALYSIS_IO_BINARY_NAME = "decomp-analysis-io-helper"
internal const val ANALYSIS_IO_METADATA_DIRECTORY = "analysis-native-io"
internal const val ANALYSIS_IO_PROPERTIES_NAME = "decomp-analysis-io-helper-v1.properties"
internal const val ANALYSIS_IO_REVIEWED_SOURCE_SHA256 = "e8986df0af2b738e5a5d99c8f8b2deb684121b1a1be4de655efd5f727d29bb58"
internal val ANALYSIS_IO_COMPILER_ARGUMENTS: List<String> = Collections.unmodifiableList(listOf("-std=c11", "-O2", "-static", "-no-pie", "-Wall", "-Wextra", "-Werror", "-Wformat=2", "-Wl,--build-id=none", "\${SOURCE}", "-o", "\${OUTPUT}"))
internal val ANALYSIS_IO_BUILD_POLICY = """schemaVersion=1
kind=analysis-native-io-static-build-policy-v1
architecture=linux-x86-64
arguments=-std=c11 -O2 -static -no-pie -Wall -Wextra -Werror -Wformat=2 -Wl,--build-id=none ${'$'}SOURCE -o ${'$'}OUTPUT
reportProtocol=STGR-v1
modelProtocol=MODL-v1
reportBytes=33554432
modelBytes=536870912
reportChunkBytes=8192
modelChunkBytes=65536
reportAddressSpaceBytes=67108864
modelAddressSpaceBytes=67108864..268435456
bootstrap=same-pid-self-descriptor-exec-before-payload-io
payloadEnvironment=empty
coreDumpBytes=0
payloadDumpable=0
bootstrapProcessCreation=absent-in-fixed-code
payloadProcessCreation=kernel-denied
payloadFurtherExec=kernel-denied
finalRenameAuthority=absent
"""
