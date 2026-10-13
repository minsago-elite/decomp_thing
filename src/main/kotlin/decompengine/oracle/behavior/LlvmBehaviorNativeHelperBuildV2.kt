package decompengine.oracle.behavior

import decompengine.acp.LinuxBoundedSessionCommand
import decompengine.acp.LinuxBoundedSessionProcess
import decompengine.acp.LinuxBoundedSessionResult
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Actual build owner for the reviewed helper, not an installed runtime or compiler qualification.
 * The compiler and its implicit toolchain are cooperating build principals. Its executable is
 * retained and measured, but this owner does not claim a complete header/library/tool closure.
 * No parser, command, environment, process runner, claimed digest or build receipt is accepted.
 */
object LlvmBehaviorNativeHelperBuildV2 {
    fun build(compilerPath: Path, sourcePath: Path, outputDirectory: Path): Path {
        require(System.getProperty("os.name") == "Linux" &&
            System.getProperty("os.arch") in setOf("amd64", "x86_64")) {
            "the Kotlin LLVM behavior-helper producer requires the pinned Linux x86-64 oracle native profile"
        }
        val compiler = exactHelperPath(compilerPath, "compiler")
        val source = exactHelperPath(sourcePath, "source")
        val root = exactHelperPath(outputDirectory, "output directory")
        require(source.fileName.toString() == NATIVE_HELPER_SOURCE_NAME) { "helper source has a foreign file name" }
        require(Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) { "helper output directory is missing" }
        requireOwnerDirectory(root)
        require(!source.startsWith(root) && !compiler.startsWith(root)) { "helper output overlaps a build input" }
        require(Files.isExecutable(compiler)) { "helper compiler is not executable" }
        val temporary = Files.createTempDirectory(root, ".native-helper-build-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            StableControlFile.open(source, NATIVE_HELPER_SOURCE_MAXIMUM, "native helper source").use { sourceGuard ->
                sourceGuard.requireSingleLink("native helper source")
                require(sourceGuard.authenticatedSha256 == NATIVE_HELPER_REVIEWED_SOURCE_SHA256) {
                    "native helper source differs from the reviewed compilation source"
                }
                StableControlFile.open(compiler, NATIVE_HELPER_COMPILER_MAXIMUM, "native helper compiler").use { compilerGuard ->
                    compilerGuard.requireSingleLink("native helper compiler")
                    val capturedSource = sourceGuard.readExactly(0, sourceGuard.size.toInt(), "native helper source")
                    val stagedSource = temporary.resolve(NATIVE_HELPER_SOURCE_NAME)
                    writeNew(stagedSource, capturedSource, "r--------")
                    val scratch = Files.createDirectory(temporary.resolve("tmp"))
                    val home = Files.createDirectory(temporary.resolve("home"))
                    val environment = linkedMapOf("HOME" to home.toString(), "LANG" to "C", "LC_ALL" to "C",
                        "PATH" to "/usr/bin:/bin", "SOURCE_DATE_EPOCH" to "1779182222",
                        "TMPDIR" to scratch.toString(), "TZ" to "UTC")
                    fun current() {
                        compilerGuard.verifyUnchanged("native helper compiler execution")
                        sourceGuard.verifyUnchanged("native helper source execution")
                        require(Files.isExecutable(compiler)) { "helper compiler lost executable permission" }
                    }
                    current()
                    val version = runFixed(listOf(compiler.toString(), "--version"), environment, Duration.ofSeconds(10))
                    current()
                    val versionText = strictHelperUtf8(version.stdout)
                    val firstLine = versionText.lineSequence().firstOrNull().orEmpty()
                    require(firstLine.isNotEmpty() && firstLine.encodeToByteArray().size <= 4096 &&
                        firstLine.none { it.code < 0x20 || it.code == 0x7f }) { "compiler version is invalid" }
                    rejectHelperLegacy(firstLine)
                    val helper = temporary.resolve(NATIVE_HELPER_NAME)
                    val arguments = listOf(compiler.toString()) + NATIVE_HELPER_ARGUMENT_TEMPLATE.map {
                        when (it) { "\${SOURCE}" -> stagedSource.toString(); "\${OUTPUT}" -> helper.toString(); else -> it }
                    }
                    StableControlFile.open(stagedSource, NATIVE_HELPER_SOURCE_MAXIMUM, "staged helper source").use { staged ->
                        require(staged.authenticatedSha256 == sourceGuard.authenticatedSha256)
                        val compilation = runFixed(arguments, environment, Duration.ofSeconds(30))
                        current()
                        staged.verifyUnchanged("staged helper source after compilation")
                        require(Files.isRegularFile(helper, LinkOption.NOFOLLOW_LINKS)) { "compiler produced no regular helper" }
                        Files.setPosixFilePermissions(helper, PosixFilePermissions.fromString("rwxr-xr-x"))
                        val helperBytes = boundedHelperBytes(helper, NATIVE_HELPER_MAXIMUM)
                        val checksum = "${OracleArtifacts.sha256(helperBytes)}  $NATIVE_HELPER_NAME\n".encodeToByteArray()
                        writeNew(temporary.resolve(NATIVE_HELPER_CHECKSUM_NAME), checksum, "rw-r--r--")
                        val artifact = LlvmBehaviorNativeHelperArtifactVerifier.verify(helper, temporary.resolve(NATIVE_HELPER_CHECKSUM_NAME))
                        val record = JsonObject(linkedMapOf(
                            "schemaVersion" to JsonPrimitive(2),
                            "kind" to JsonPrimitive("llvm-behavior-native-helper-build-record"),
                            "compiler" to JsonObject(mapOf("executable" to JsonPrimitive(compiler.toString()), "version" to JsonPrimitive(firstLine))),
                            "argumentTemplate" to helperStrings(NATIVE_HELPER_ARGUMENT_TEMPLATE),
                            "source" to helperFileRecord(NATIVE_HELPER_SOURCE_NAME, capturedSource),
                            "output" to helperFileRecord(NATIVE_HELPER_NAME, helperBytes),
                        ))
                        val recordBytes = OracleJson.canonicalBytes(record, NATIVE_HELPER_JSON_LIMITS)
                        writeNew(temporary.resolve(NATIVE_HELPER_BUILD_NAME), recordBytes, "rw-r--r--")
                        val unsigned = JsonObject(linkedMapOf(
                            "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive(NATIVE_HELPER_REFERENCE_PROVIDER),
                            "protocol" to JsonPrimitive(artifact.protocol),
                            "provenanceScope" to JsonPrimitive("reviewed-source-compiler-executable-and-fixed-compilation"),
                            "compilerToolchainClosureAuthenticated" to JsonPrimitive(false),
                            "source" to helperFileRecord(NATIVE_HELPER_SOURCE_NAME, capturedSource),
                            "helper" to helperFileRecord(NATIVE_HELPER_NAME, helperBytes),
                            "checksum" to helperFileRecord(NATIVE_HELPER_CHECKSUM_NAME, checksum),
                            "buildRecord" to helperFileRecord(NATIVE_HELPER_BUILD_NAME, recordBytes),
                            "compiler" to JsonObject(linkedMapOf("path" to JsonPrimitive(compiler.toString()),
                                "bytes" to JsonPrimitive(compilerGuard.size), "sha256" to JsonPrimitive(compilerGuard.authenticatedSha256),
                                "version" to JsonPrimitive(firstLine), "versionCommand" to helperStrings(listOf(compiler.toString(), "--version")),
                                "result" to helperProcessRecord(version))),
                            "compilation" to JsonObject(linkedMapOf("arguments" to helperStrings(arguments),
                                "environment" to JsonObject(environment.mapValues { JsonPrimitive(it.value) }),
                                "workingDirectory" to JsonPrimitive("/"), "result" to helperProcessRecord(compilation))),
                            "claims" to nativeHelperFalseClaims(),
                        ))
                        val reference = JsonObject(unsigned + ("closureSha256" to JsonPrimitive(
                            OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned, NATIVE_HELPER_JSON_LIMITS)))))
                        val referenceBytes = OracleJson.canonicalBytes(reference, NATIVE_HELPER_JSON_LIMITS)
                        parseNativeHelperReference(referenceBytes, capturedSource, recordBytes)
                        writeNew(temporary.resolve(NATIVE_HELPER_REFERENCE_NAME), referenceBytes, "rw-r--r--")
                        current()
                        staged.verifyUnchanged("staged helper source before publication")
                        require(artifact.helperSha256 == OracleArtifacts.sha256(helperBytes))
                    }
                    current()
                }
            }
            // Build outputs are replaceable, not oracle receipts. The reference commits the complete
            // tuple and is moved last; installed authority subsequently reopens every member.
            (NATIVE_HELPER_INSTALLED_NAMES - NATIVE_HELPER_REFERENCE_NAME).forEach { name -> publishBuildMember(temporary, root, name) }
            publishBuildMember(temporary, root, NATIVE_HELPER_REFERENCE_NAME)
            return root.resolve(NATIVE_HELPER_REFERENCE_NAME)
        } finally {
            Files.walk(temporary).use { entries -> entries.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}

object LlvmBehaviorNativeHelperBuildV2Cli {
    @JvmStatic fun main(arguments: Array<String>) {
        require(arguments.size == 3) { "usage: <absolute-compiler> <absolute-source> <absolute-output-directory>" }
        val reference = LlvmBehaviorNativeHelperBuildV2.build(Path.of(arguments[0]), Path.of(arguments[1]), Path.of(arguments[2]))
        println("${OracleArtifacts.sha256(Files.readAllBytes(reference))}  $NATIVE_HELPER_REFERENCE_NAME")
    }
}

private fun runFixed(arguments: List<String>, environment: Map<String, String>, timeout: Duration): LinuxBoundedSessionResult {
    val result = LinuxBoundedSessionProcess.execute(LinuxBoundedSessionCommand(arguments, environment,
        timeout = timeout, maximumStdoutBytes = 64 * 1024, maximumStderrBytes = 64 * 1024))
    require(result.exitCode == 0 && result.signal == null) {
        "native helper compiler command failed (exit=${result.exitCode}, signal=${result.signal})"
    }
    return result
}

private fun publishBuildMember(temporary: Path, root: Path, name: String) {
    requireOwnerDirectory(root)
    val target = root.resolve(name)
    require(!Files.exists(target, LinkOption.NOFOLLOW_LINKS) ||
        (Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(target))) {
        "helper build must not replace a non-regular output"
    }
    Files.move(temporary.resolve(name), target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    FileChannel.open(root, StandardOpenOption.READ).use { it.force(true) }
}

private fun writeNew(path: Path, bytes: ByteArray, mode: String) {
    FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use {
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) it.write(buffer)
        it.force(true)
    }
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(mode))
}

internal fun requireOwnerDirectory(path: Path) {
    require(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) && path.toRealPath() == path) { "helper directory is not canonical" }
    val mode = (Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
    val uid = (Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
    val current = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
    require(mode and 0x12 == 0 && uid == current) { "helper build directory is not owner controlled" }
}

internal fun exactHelperPath(path: Path, label: String): Path {
    require(path.isAbsolute && path.normalize() == path && path.parent != null && path.toRealPath() == path) {
        "native helper $label must be an exact canonical absolute path"
    }
    rejectHelperLegacy(path.toString())
    return path
}

internal fun rejectHelperLegacy(value: String) {
    require(listOf("python", "decomp-llvm-behavior-helper-v1", "behavior-preexec-v1", "oci-container-v1")
        .none { value.contains(it, ignoreCase = true) }) { "native helper contains foreign runtime material" }
}

internal fun strictHelperUtf8(bytes: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
    .decode(ByteBuffer.wrap(bytes)).toString()

internal fun boundedHelperBytes(path: Path, maximum: Long): ByteArray = StableControlFile.open(path, maximum, "native helper build output").use {
    it.requireSingleLink("native helper build output")
    it.readExactly(0, it.size.toInt(), "native helper build output").also { _ -> it.verifyUnchanged("native helper build output") }
}

internal fun helperStrings(values: List<String>) = JsonArray(values.map(::JsonPrimitive))
internal fun helperFileRecord(name: String, bytes: ByteArray) = JsonObject(mapOf("fileName" to JsonPrimitive(name),
    "bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes))))
private fun helperProcessRecord(result: LinuxBoundedSessionResult) = JsonObject(mapOf("exitCode" to JsonPrimitive(0),
    "stdout" to helperFileRecord("stdout", result.stdout), "stderr" to helperFileRecord("stderr", result.stderr)))
internal fun nativeHelperFalseClaims() = JsonObject(listOf("runtimeProfilePinned", "referencePinned", "startAuthorized",
    "containmentAuthority", "scoringAuthority", "releaseEligible").associateWith { JsonPrimitive(false) })

internal const val NATIVE_HELPER_NAME = "decomp-llvm-behavior-helper"
internal const val NATIVE_HELPER_CHECKSUM_NAME = "$NATIVE_HELPER_NAME.sha256"
internal const val NATIVE_HELPER_SOURCE_NAME = "decomp_llvm_behavior_helper.c"
internal const val NATIVE_HELPER_BUILD_NAME = "decomp-llvm-behavior-helper-build-v2.json"
internal const val NATIVE_HELPER_REFERENCE_NAME = "llvm-behavior-native-helper-deployment-reference-v1.json"
internal const val NATIVE_HELPER_RESOURCE_ROOT = "oracle/native-helper/"
internal const val NATIVE_HELPER_REFERENCE_PROVIDER = "llvm-behavior-native-helper-deployment-reference-v1"
internal const val NATIVE_HELPER_REVIEWED_SOURCE_SHA256 = "8465bd7761e3ecc2eefc42f194505e24d6adf3ed68a676a8370ee294f30cd713"
internal const val NATIVE_HELPER_MAXIMUM = 4L * 1024 * 1024
internal const val NATIVE_HELPER_SOURCE_MAXIMUM = 2L * 1024 * 1024
internal const val NATIVE_HELPER_COMPILER_MAXIMUM = 512L * 1024 * 1024
internal val NATIVE_HELPER_INSTALLED_NAMES: List<String> = Collections.unmodifiableList(listOf(NATIVE_HELPER_NAME, NATIVE_HELPER_CHECKSUM_NAME,
    NATIVE_HELPER_SOURCE_NAME, NATIVE_HELPER_BUILD_NAME, NATIVE_HELPER_REFERENCE_NAME))
internal val NATIVE_HELPER_ARGUMENT_TEMPLATE: List<String> = Collections.unmodifiableList(listOf("-std=c11", "-O2", "-static", "-Wall", "-Wextra", "-Werror",
    "-Wformat=2", "-Wl,--build-id=none", "\${SOURCE}", "-o", "\${OUTPUT}"))
internal val NATIVE_HELPER_JSON_LIMITS = StrictJsonLimits(maximumInputBytes = 128 * 1024,
    maximumCanonicalBytes = 128 * 1024, maximumDepth = 16, maximumNodes = 2048,
    maximumStringBytes = 64 * 1024, maximumTotalStringBytes = 96 * 1024)
