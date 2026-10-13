package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.StableControlFile
import java.net.JarURLConnection
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.jar.JarFile
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/**
 * Installed helper bytes authenticated by the already-loaded application JAR, independently of
 * the adjacent checksum. Host root and the installation owner remain cooperating principals.
 * The constructor accepts no state; reflective construction also reopens the own installed JAR.
 * This owner authenticates deployment provenance only, never a runtime, reference corpus or START.
 */
internal class LlvmBehaviorNativeHelperDeploymentReferenceV1 private constructor() : AutoCloseable {
    private val state = openInstalledNativeHelper()
    private var closed = false
    val helperPath: Path get() { requireOpen(); return state.root.resolve(NATIVE_HELPER_NAME) }
    val checksumPath: Path get() { requireOpen(); return state.root.resolve(NATIVE_HELPER_CHECKSUM_NAME) }
    val sourcePath: Path get() { requireOpen(); return state.root.resolve(NATIVE_HELPER_SOURCE_NAME) }
    val buildRecordPath: Path get() { requireOpen(); return state.root.resolve(NATIVE_HELPER_BUILD_NAME) }
    val helperBytes: Long get() { requireOpen(); return state.reference.files.getValue(NATIVE_HELPER_NAME).bytes }
    val helperSha256: String get() { requireOpen(); return state.reference.files.getValue(NATIVE_HELPER_NAME).sha256 }
    val checksumSha256: String get() { requireOpen(); return state.reference.files.getValue(NATIVE_HELPER_CHECKSUM_NAME).sha256 }
    val sourceBytes: Long get() { requireOpen(); return state.reference.files.getValue(NATIVE_HELPER_SOURCE_NAME).bytes }
    val sourceSha256: String get() { requireOpen(); return state.reference.files.getValue(NATIVE_HELPER_SOURCE_NAME).sha256 }
    val buildRecordBytes: Long get() { requireOpen(); return state.reference.files.getValue(NATIVE_HELPER_BUILD_NAME).bytes }
    val buildRecordSha256: String get() { requireOpen(); return state.reference.files.getValue(NATIVE_HELPER_BUILD_NAME).sha256 }
    val referenceSha256: String get() { requireOpen(); return OracleArtifacts.sha256(state.referenceBytes) }
    val applicationJarSha256: String get() { requireOpen(); return state.jar.authenticatedSha256 }
    val compilerToolchainClosureAuthenticated = false
    val runtimeProfilePinned = false
    val referencePinned = false
    val startAuthorized = false
    val containmentAuthority = false
    val scoringAuthority = false
    val releaseEligible = false

    @Synchronized fun requireCurrent() {
        requireOpen()
        state.jar.verifyUnchanged("native helper own application JAR")
        state.files.forEach { (name, guard) ->
            guard.verifyUnchanged("installed native helper $name")
            val expected = if (name == NATIVE_HELPER_REFERENCE_NAME) NativeHelperFileIdentity(
                state.referenceBytes.size.toLong(), OracleArtifacts.sha256(state.referenceBytes))
                else state.reference.files.getValue(name)
            require(guard.size == expected.bytes && guard.sha256(label = "installed native helper $name") == expected.sha256) {
                "installed native helper member changed: $name"
            }
        }
        val artifact = LlvmBehaviorNativeHelperArtifactVerifier.verify(helperPath, checksumPath)
        require(artifact.helperBytes == helperBytes && artifact.helperSha256 == helperSha256)
        state.jar.verifyUnchanged("native helper own application JAR after artifact authentication")
    }

    private fun requireOpen() = check(!closed) { "native helper deployment reference is closed" }
    @Synchronized override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        (state.files.values.toList().asReversed() + state.jar).forEach { guard ->
            runCatching { guard.close() }.exceptionOrNull()?.let { next ->
                val previous = failure
                if (previous == null) failure = next else previous.addSuppressed(next)
            }
        }
        failure?.let { throw it }
    }

    companion object { fun open(): LlvmBehaviorNativeHelperDeploymentReferenceV1 =
        LlvmBehaviorNativeHelperDeploymentReferenceV1().also { owner ->
            try { owner.requireCurrent() } catch (failure: Throwable) { owner.close(); throw failure }
        }
    }
}

internal data class NativeHelperFileIdentity(val bytes: Long, val sha256: String)
internal data class NativeHelperReference(val files: Map<String, NativeHelperFileIdentity>)
private data class InstalledNativeHelper(val root: Path, val jar: StableControlFile,
    val reference: NativeHelperReference, val referenceBytes: ByteArray, val files: Map<String, StableControlFile>)

private fun openInstalledNativeHelper(): InstalledNativeHelper {
    require(System.getProperty("os.name") == "Linux" &&
        System.getProperty("os.arch") in setOf("amd64", "x86_64")) {
        "installed Kotlin native-helper provenance requires the pinned Linux x86-64 oracle native profile"
    }
    val overrides = listOf("nativeHelperExecutable", "nativeHelperChecksum", "nativeHelperSource", "nativeHelperBuildRecord",
        "nativeHelperReference", "nativeHelperRoot")
    require(overrides.none { System.getProperty("decompengine.oracle.behavior.$it") != null }) {
        "installed native helper rejects input/reference overrides"
    }
    val location = LlvmBehaviorNativeHelperDeploymentReferenceV1::class.java.protectionDomain.codeSource?.location
        ?: error("native helper application code source is missing")
    require(location.protocol == "file") { "native helper application must use a local installed JAR" }
    val jarPath = exactHelperPath(Path.of(location.toURI()), "application JAR")
    require(Files.isRegularFile(jarPath, LinkOption.NOFOLLOW_LINKS) && jarPath.fileName.toString().endsWith(".jar") &&
        jarPath.parent.fileName.toString() == "lib") { "native helper production requires its own installed application JAR" }
    val root = exactHelperPath(jarPath.parent.parent.resolve("libexec"), "installed root")
    val jarGuard = StableControlFile.open(jarPath, 1024L * 1024 * 1024, "native helper own application JAR")
    val opened = LinkedHashMap<String, StableControlFile>()
    try {
        jarGuard.requireSingleLink("native helper own application JAR")
        listOf(NATIVE_HELPER_SOURCE_NAME, NATIVE_HELPER_BUILD_NAME, NATIVE_HELPER_REFERENCE_NAME).forEach { name ->
            val resourceName = NATIVE_HELPER_RESOURCE_ROOT + name
            val locations = LlvmBehaviorNativeHelperDeploymentReferenceV1::class.java.classLoader
                .getResources(resourceName).asSequence().take(2).toList()
            require(locations.size == 1 && locations.single().protocol == "jar") {
                "native helper application resource is missing or shadowed: $name"
            }
            val connection = locations.single().openConnection() as? JarURLConnection
                ?: error("native helper resource does not belong to an application JAR")
            require(connection.jarFileURL.protocol == "file" && connection.entryName == resourceName &&
                Path.of(connection.jarFileURL.toURI()).toAbsolutePath().normalize() == jarPath) {
                "native helper resource is shadowed outside the own application JAR"
            }
        }
        val resources = JarFile(jarPath.toFile(), false).use { jar ->
            val entries = jar.entries().asSequence().take(200_001).toList()
            require(entries.size <= 200_000) { "native helper application JAR exceeds its entry limit" }
            listOf(NATIVE_HELPER_SOURCE_NAME, NATIVE_HELPER_BUILD_NAME, NATIVE_HELPER_REFERENCE_NAME).associateWith { name ->
                val entry = entries.singleOrNull { it.name == NATIVE_HELPER_RESOURCE_ROOT + name }
                    ?: error("native helper application JAR resource is missing or duplicated: $name")
                val bound = if (name == NATIVE_HELPER_SOURCE_NAME) NATIVE_HELPER_SOURCE_MAXIMUM else 128L * 1024
                require(!entry.isDirectory && entry.size in 1..bound) { "native helper application resource exceeds its limit" }
                jar.getInputStream(entry).use { it.readNBytes(entry.size.toInt() + 1) }.also {
                    require(it.size.toLong() == entry.size) { "native helper application resource changed length" }
                }
            }
        }
        jarGuard.verifyUnchanged("after native helper own-JAR resource selection")
        val referenceBytes = resources.getValue(NATIVE_HELPER_REFERENCE_NAME)
        val parsed = parseNativeHelperReference(referenceBytes, resources.getValue(NATIVE_HELPER_SOURCE_NAME),
            resources.getValue(NATIVE_HELPER_BUILD_NAME))
        NATIVE_HELPER_INSTALLED_NAMES.forEach { name ->
            val maximum = when (name) { NATIVE_HELPER_NAME -> NATIVE_HELPER_MAXIMUM
                NATIVE_HELPER_SOURCE_NAME -> NATIVE_HELPER_SOURCE_MAXIMUM
                NATIVE_HELPER_CHECKSUM_NAME -> 256L; else -> 128L * 1024 }
            val guard = StableControlFile.open(root.resolve(name), maximum, "installed native helper $name")
            opened[name] = guard
            guard.requireSingleLink("installed native helper $name")
            val expected = if (name == NATIVE_HELPER_REFERENCE_NAME) NativeHelperFileIdentity(referenceBytes.size.toLong(),
                OracleArtifacts.sha256(referenceBytes)) else parsed.files.getValue(name)
            require(guard.size == expected.bytes && guard.authenticatedSha256 == expected.sha256) {
                "installed native helper differs from own-JAR deployment reference: $name"
            }
            resources[name]?.let { expectedBytes ->
                require(guard.readExactly(0, guard.size.toInt(), name).contentEquals(expectedBytes)) {
                    "installed native helper differs from own-JAR resource: $name"
                }
            }
            guard.verifyUnchanged("installed native helper $name selection")
        }
        jarGuard.verifyUnchanged("native helper own application JAR terminal selection")
        return InstalledNativeHelper(root, jarGuard, parsed, referenceBytes, opened.toMap())
    } catch (failure: Throwable) {
        opened.values.toList().asReversed().forEach { runCatching { it.close() }.exceptionOrNull()?.let(failure::addSuppressed) }
        runCatching { jarGuard.close() }.exceptionOrNull()?.let(failure::addSuppressed)
        throw failure
    }
}

/** Closed parser shared with the real build owner; parsed facts cannot construct deployment authority. */
internal fun parseNativeHelperReference(bytes: ByteArray, source: ByteArray, build: ByteArray): NativeHelperReference {
    val root = helperObject(OracleJson.parseCanonical(bytes, NATIVE_HELPER_JSON_LIMITS), "deployment reference")
    helperKeys(root, setOf("schemaVersion", "provider", "protocol", "provenanceScope", "compilerToolchainClosureAuthenticated",
        "source", "helper", "checksum", "buildRecord", "compiler", "compilation", "claims", "closureSha256"))
    require(root["schemaVersion"] == JsonPrimitive(1) && helperString(root, "provider") == NATIVE_HELPER_REFERENCE_PROVIDER &&
        helperString(root, "protocol") == "decomp-llvm-behavior-helper-v2" &&
        helperString(root, "provenanceScope") == "reviewed-source-compiler-executable-and-fixed-compilation" &&
        root["compilerToolchainClosureAuthenticated"] == JsonPrimitive(false) && root["claims"] == nativeHelperFalseClaims()) {
        "native helper deployment reference carries unsupported identity or authority"
    }
    val closure = OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(root - "closureSha256"), NATIVE_HELPER_JSON_LIMITS))
    require(helperString(root, "closureSha256") == closure) { "native helper deployment closure differs" }
    val files = linkedMapOf<String, NativeHelperFileIdentity>()
    listOf("source" to NATIVE_HELPER_SOURCE_NAME, "helper" to NATIVE_HELPER_NAME, "checksum" to NATIVE_HELPER_CHECKSUM_NAME,
        "buildRecord" to NATIVE_HELPER_BUILD_NAME).forEach { (key, name) ->
        files[name] = parseHelperIdentity(helperObject(root[key], key), name,
            when (name) { NATIVE_HELPER_NAME -> NATIVE_HELPER_MAXIMUM; NATIVE_HELPER_SOURCE_NAME -> NATIVE_HELPER_SOURCE_MAXIMUM
                NATIVE_HELPER_CHECKSUM_NAME -> 256L; else -> 128L * 1024 })
    }
    require(files.getValue(NATIVE_HELPER_SOURCE_NAME) == NativeHelperFileIdentity(source.size.toLong(), OracleArtifacts.sha256(source)) &&
        OracleArtifacts.sha256(source) == NATIVE_HELPER_REVIEWED_SOURCE_SHA256 &&
        files.getValue(NATIVE_HELPER_BUILD_NAME) == NativeHelperFileIdentity(build.size.toLong(), OracleArtifacts.sha256(build))) {
        "native helper own-JAR source/build bindings differ"
    }
    val compiler = helperObject(root["compiler"], "compiler")
    helperKeys(compiler, setOf("path", "bytes", "sha256", "version", "versionCommand", "result"))
    val compilerPath = helperHistoricalPath(helperString(compiler, "path"))
    require(helperLong(compiler, "bytes") in 1..NATIVE_HELPER_COMPILER_MAXIMUM)
    require(helperString(compiler, "sha256").matches(Regex("[0-9a-f]{64}")))
    val version = helperString(compiler, "version")
    require(version.isNotEmpty() && version.encodeToByteArray().size <= 4096 && version.none { it.code < 0x20 || it.code == 0x7f })
    require(compiler["versionCommand"] == helperStrings(listOf(compilerPath.toString(), "--version")))
    verifyHelperProcessRecord(helperObject(compiler["result"], "compiler result"))
    val record = helperObject(OracleJson.parseCanonical(build, NATIVE_HELPER_JSON_LIMITS), "build record")
    helperKeys(record, setOf("schemaVersion", "kind", "compiler", "argumentTemplate", "source", "output"))
    require(record["schemaVersion"] == JsonPrimitive(2) && helperString(record, "kind") == "llvm-behavior-native-helper-build-record" &&
        record["compiler"] == JsonObject(mapOf("executable" to JsonPrimitive(compilerPath.toString()), "version" to JsonPrimitive(version))) &&
        record["argumentTemplate"] == helperStrings(NATIVE_HELPER_ARGUMENT_TEMPLATE) && record["source"] == root["source"] &&
        record["output"] == root["helper"]) { "native helper build record differs from fixed v2 recipe/provenance" }
    val compilation = helperObject(root["compilation"], "compilation")
    helperKeys(compilation, setOf("arguments", "environment", "workingDirectory", "result"))
    require(helperString(compilation, "workingDirectory") == "/")
    val arguments = (compilation["arguments"] as? JsonArray)?.map { helperScalarString(it) } ?: error("missing compilation argv")
    require(arguments.size == NATIVE_HELPER_ARGUMENT_TEMPLATE.size + 1 && arguments.first() == compilerPath.toString())
    val sourcePath = helperHistoricalPath(arguments[9])
    val outputPath = helperHistoricalPath(arguments[11])
    require(sourcePath.fileName.toString() == NATIVE_HELPER_SOURCE_NAME && outputPath.fileName.toString() == NATIVE_HELPER_NAME &&
        sourcePath.parent == outputPath.parent)
    val expectedArguments = listOf(compilerPath.toString()) + NATIVE_HELPER_ARGUMENT_TEMPLATE.map {
        when (it) { "\${SOURCE}" -> sourcePath.toString(); "\${OUTPUT}" -> outputPath.toString(); else -> it }
    }
    require(arguments == expectedArguments) { "native helper compilation argv drifted" }
    val environment = helperObject(compilation["environment"], "compilation environment")
    val expectedEnvironment = mapOf("HOME" to sourcePath.parent.resolve("home").toString(), "LANG" to "C", "LC_ALL" to "C",
        "PATH" to "/usr/bin:/bin", "SOURCE_DATE_EPOCH" to "1779182222", "TMPDIR" to sourcePath.parent.resolve("tmp").toString(), "TZ" to "UTC")
    require(environment == JsonObject(expectedEnvironment.mapValues { JsonPrimitive(it.value) })) { "native helper compilation environment drifted" }
    verifyHelperProcessRecord(helperObject(compilation["result"], "compilation result"))
    return NativeHelperReference(files.toMap())
}

private fun verifyHelperProcessRecord(root: JsonObject) {
    helperKeys(root, setOf("exitCode", "stdout", "stderr"))
    require(root["exitCode"] == JsonPrimitive(0)) { "native helper build command was unsuccessful" }
    listOf("stdout", "stderr").forEach { name -> parseHelperIdentity(helperObject(root[name], name), name, 64L * 1024, allowEmpty = true) }
}
private fun parseHelperIdentity(root: JsonObject, name: String, maximum: Long, allowEmpty: Boolean = false): NativeHelperFileIdentity {
    helperKeys(root, setOf("fileName", "bytes", "sha256"))
    require(helperString(root, "fileName") == name)
    val size = helperLong(root, "bytes")
    val sha256 = helperString(root, "sha256")
    require(size in (if (allowEmpty) 0L else 1L)..maximum && sha256.matches(Regex("[0-9a-f]{64}")))
    require(size != 0L || sha256 == OracleArtifacts.sha256(byteArrayOf())) { "empty compiler output has a foreign hash" }
    return NativeHelperFileIdentity(size, sha256)
}
private fun helperHistoricalPath(value: String): Path = Path.of(value).also {
    require(it.isAbsolute && it.normalize() == it && it.parent != null && it.toString() == value) { "noncanonical helper provenance path" }
}
private fun helperObject(value: kotlinx.serialization.json.JsonElement?, label: String) = value as? JsonObject ?: error("invalid native helper $label")
private fun helperKeys(root: JsonObject, keys: Set<String>) = require(root.keys == keys) { "native helper fields are not closed" }
private fun helperString(root: JsonObject, name: String): String = helperScalarString(root[name])
private fun helperScalarString(value: kotlinx.serialization.json.JsonElement?): String {
    val scalar = value as? JsonPrimitive ?: error("missing native helper string")
    require(scalar.isString && '\u0000' !in scalar.content)
    rejectHelperLegacy(scalar.content)
    return scalar.content
}
private fun helperLong(root: JsonObject, name: String): Long {
    val scalar = root[name] as? JsonPrimitive ?: error("missing native helper integer")
    require(!scalar.isString && scalar.content.matches(Regex("0|[1-9][0-9]*")))
    return scalar.longOrNull ?: error("native helper integer overflows")
}
