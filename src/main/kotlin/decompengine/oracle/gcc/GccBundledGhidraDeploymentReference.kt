package decompengine.oracle.gcc

import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.fulltree.requireStableDirectory
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import java.util.jar.JarFile
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

internal data class GccBundledGhidraReferenceEntry(
    val path: String,
    val kind: String,
    val mode: Int,
    val bytes: Long?,
    val sha256: String?,
)

internal class GccBundledGhidraReference private constructor(
    val closureSha256: String,
    entries: Map<String, GccBundledGhidraReferenceEntry>,
    classPath: List<String>,
    val exporterBytes: Long,
    val exporterSha256: String,
) {
    val entries: Map<String, GccBundledGhidraReferenceEntry> = Collections.unmodifiableMap(LinkedHashMap(entries))
    val classPath: List<String> = Collections.unmodifiableList(ArrayList(classPath))

    fun requireCandidate(runtime: GccBundledGhidraRuntime, artifacts: List<GccCompilerEngineContainmentArtifactIdentity>) {
        require(artifacts.size == GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.size) { "bundled reference candidate role count differs" }
        val byRole = artifacts.associateBy { it.role }
        require(byRole.keys == GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES) { "bundled reference candidate roles differ" }
        require(runtime.classPath.size == classPath.size && runtime.classPath.indices.all { index ->
            val expected = entries.getValue(classPath[index])
            val actual = runtime.classPath[index]
            actual.path == runtime.root.resolve(expected.path) && actual.bytes == expected.bytes && actual.sha256 == expected.sha256
        }) { "bundled candidate classpath differs from the independent deployment reference" }
        for ((role, relative) in mapOf(
            GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR to BRIDGE_PATH,
            GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD to GUARD_PATH,
            GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST to "bundle.sha256",
        )) {
            val expected = entries.getValue(relative)
            val actual = byRole.getValue(role)
            require(actual.path == runtime.root.resolve(relative) && actual.bytes == expected.bytes && actual.sha256 == expected.sha256) {
                "bundled candidate ${role.wireName} differs from the independent deployment reference"
            }
        }
        val archive = byRole.getValue(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE)
        require(archive.bytes == ARCHIVE_BYTES && archive.sha256 == BundledGhidra.ARCHIVE_SHA256) {
            "bundled candidate archive differs from the pinned release"
        }
        val exporter = byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE)
        require(exporter.path.fileName.toString() == "ExportProgramModel.java" &&
            exporter.bytes == exporterBytes && exporter.sha256 == exporterSha256
        ) { "bundled candidate exporter differs from the independent application resource" }
    }

    companion object {
        fun parse(bytes: ByteArray): GccBundledGhidraReference {
            val root = OracleJson.parseCanonical(bytes, REFERENCE_LIMITS) as? JsonObject
                ?: throw IllegalArgumentException("bundled Ghidra deployment reference must be an object")
            root.exactFields(setOf(
                "schemaVersion", "provider", "ghidraVersion", "ghidraRelease", "archive", "rootMode", "entries",
                "classPath", "bridgePath", "exportGuardPath", "exporter", "closureSha256",
            ))
            require(root.number("schemaVersion") == 1L && root.string("provider") == REFERENCE_PROVIDER) {
                "bundled Ghidra deployment reference version is invalid"
            }
            require(root.string("ghidraVersion") == BundledGhidra.VERSION && root.string("ghidraRelease") == "PUBLIC") {
                "bundled Ghidra deployment reference release is invalid"
            }
            require(root.number("rootMode") == 493L && root.string("bridgePath") == BRIDGE_PATH && root.string("exportGuardPath") == GUARD_PATH) {
                "bundled Ghidra deployment layout is invalid"
            }
            val archive = root.objectValue("archive")
            archive.exactFields(setOf("bytes", "sha256"))
            require(archive.number("bytes") == ARCHIVE_BYTES && archive.string("sha256") == BundledGhidra.ARCHIVE_SHA256) {
                "bundled Ghidra deployment archive is invalid"
            }
            val exporter = root.objectValue("exporter")
            exporter.exactFields(setOf("resourcePath", "bytes", "sha256"))
            require(exporter.string("resourcePath") == EXPORTER_RESOURCE && exporter.number("bytes") in 1..MAXIMUM_EXPORTER_BYTES.toLong()) {
                "bundled Ghidra deployment exporter is invalid"
            }
            requireDigest(exporter.string("sha256"))
            val records = root.arrayValue("entries")
            require(records.size in 1..20_000) { "bundled Ghidra reference inventory exceeds its entry bound" }
            val entries = linkedMapOf<String, GccBundledGhidraReferenceEntry>()
            var aggregate = 0L
            for (record in records) {
                val entry = record as? JsonObject ?: throw IllegalArgumentException("bundled Ghidra reference entry must be an object")
                val kind = entry.string("kind")
                require(kind == "file" || kind == "directory") { "bundled Ghidra reference entry kind is invalid" }
                entry.exactFields(if (kind == "file") setOf("path", "kind", "mode", "bytes", "sha256") else setOf("path", "kind", "mode"))
                val relative = entry.string("path")
                requireReferencePath(relative)
                val mode = entry.number("mode")
                require(mode == 493L || kind == "file" && mode == 420L) { "bundled Ghidra reference permissions are invalid" }
                val size = if (kind == "file") entry.number("bytes") else null
                val digest = if (kind == "file") entry.string("sha256") else null
                if (size != null) {
                    require(size in 0..128L * 1024 * 1024) { "bundled Ghidra reference entry exceeds its byte bound" }
                    aggregate += size
                    require(aggregate <= 2L * 1024 * 1024 * 1024) { "bundled Ghidra reference exceeds its aggregate byte bound" }
                    requireDigest(checkNotNull(digest))
                    require(size != 0L || digest == EMPTY_SHA256) { "empty bundled file has an invalid content identity" }
                }
                require(entries.put(relative, GccBundledGhidraReferenceEntry(relative, kind, mode.toInt(), size, digest)) == null) {
                    "bundled Ghidra reference repeats a path"
                }
            }
            require(entries.keys.toList() == entries.keys.sorted()) { "bundled Ghidra reference inventory is not sorted" }
            for (entry in entries.values) {
                val parent = entry.path.substringBeforeLast('/', "")
                require(parent.isEmpty() || entries[parent]?.kind == "directory") { "bundled Ghidra reference omits a directory parent" }
            }
            val release = "ghidra_${BundledGhidra.VERSION}_PUBLIC"
            require(entries[release]?.kind == "directory" && entries["$release/Ghidra"]?.kind == "directory") {
                "bundled Ghidra reference omits its release root"
            }
            for (relative in listOf(BRIDGE_PATH, GUARD_PATH, "bundle.sha256")) {
                require(entries[relative]?.let { it.kind == "file" && checkNotNull(it.bytes) > 0L } == true) {
                    "bundled Ghidra reference omits a required application file"
                }
            }
            val declaredClassPath = root.arrayValue("classPath").map { value ->
                (value as? JsonPrimitive)?.takeIf { it.isString }?.content
                    ?: throw IllegalArgumentException("bundled Ghidra reference classpath must contain strings")
            }
            val libraries = entries.values.filter {
                it.kind == "file" && it.path.startsWith("$release/Ghidra/") &&
                    it.path.substringBeforeLast('/').substringAfterLast('/') == "lib" && it.path.endsWith(".jar")
            }.map { it.path }
            require(declaredClassPath.size in 2..512 && declaredClassPath == listOf(BRIDGE_PATH) + libraries &&
                declaredClassPath.all { checkNotNull(entries.getValue(it).bytes) > 0L }
            ) { "bundled Ghidra reference classpath is not its exact ordered library inventory" }
            val digest = root.string("closureSha256")
            requireDigest(digest)
            require(digest == OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(root - "closureSha256"), REFERENCE_LIMITS))) {
                "bundled Ghidra deployment reference commitment is invalid"
            }
            return GccBundledGhidraReference(digest, entries, declaredClassPath, exporter.number("bytes"), exporter.string("sha256"))
        }
    }
}

internal class GccBundledGhidraDeploymentReference private constructor(
    val reference: GccBundledGhidraReference,
    val bundleRoot: Path,
    private val guard: StableControlFile,
    private val captured: ByteArray,
    private val applicationGuard: StableControlFile?,
) : AutoCloseable {
    private var closed = false

    fun verify(label: String) {
        check(!closed) { "bundled Ghidra deployment reference is closed" }
        require(MessageDigest.isEqual(captured, guard.readExactly(0L, captured.size, "bundled deployment reference $label"))) {
            "bundled Ghidra deployment reference changed $label"
        }
        guard.verifyUnchanged("bundled Ghidra deployment reference $label")
        applicationGuard?.let { application ->
            require(application.sha256(label = "application JAR $label") == application.authenticatedSha256) {
                "bundled Ghidra application JAR changed $label"
            }
            application.verifyUnchanged("bundled Ghidra application JAR $label")
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        runCatching { applicationGuard?.close() }.exceptionOrNull()?.let { failure = it }
        runCatching { guard.close() }.exceptionOrNull()?.let { next ->
            val previous = failure
            if (previous == null) failure = next else previous.addSuppressed(next)
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(): GccBundledGhidraDeploymentReference {
            val codeSource = Path.of(GccBundledGhidraDeploymentReference::class.java.protectionDomain.codeSource.location.toURI()).toAbsolutePath().normalize()
            val development = Files.isDirectory(codeSource, LinkOption.NOFOLLOW_LINKS)
            val configuredReference = System.getProperty("decompengine.oracle.gcc.bundledGhidraReference")
            val configuredRoot = System.getProperty("decompengine.oracle.gcc.bundledGhidraRoot")
            require(if (development) configuredReference != null && configuredRoot != null else configuredReference == null && configuredRoot == null) {
                "bundled Ghidra reference overrides require paired Gradle class-directory configuration"
            }
            val referencePath = if (development) Path.of(checkNotNull(configuredReference)) else codeSource.parent.resolve("gcc-bundled-ghidra-reference-v1.json")
            val bundleRoot = if (development) Path.of(checkNotNull(configuredRoot)) else codeSource.parent.parent.resolve("libexec/ghidra")
            require(referencePath.isAbsolute && referencePath.normalize() == referencePath && referencePath.toRealPath() == referencePath) {
                "bundled Ghidra deployment reference path is not canonical"
            }
            require(bundleRoot.isAbsolute && bundleRoot.normalize() == bundleRoot && bundleRoot.toRealPath() == bundleRoot) {
                "bundled Ghidra deployment root is not canonical"
            }
            requireStableDirectory(bundleRoot, "bundled Ghidra deployment root")
            val guard = StableControlFile.open(referencePath, MAXIMUM_REFERENCE_BYTES.toLong(), "bundled Ghidra deployment reference")
            var applicationGuard: StableControlFile? = null
            try {
                val captured = guard.readExactly(0L, guard.size.toInt(), "bundled Ghidra deployment reference")
                val parsed = GccBundledGhidraReference.parse(captured)
                val exporter = if (development) {
                    GccBundledGhidraDeploymentReference::class.java.getResourceAsStream(EXPORTER_RESOURCE)?.use { input ->
                        input.readNBytes(MAXIMUM_EXPORTER_BYTES + 1)
                    } ?: throw IllegalArgumentException("application Ghidra exporter resource is unavailable")
                } else {
                    applicationGuard = StableControlFile.open(codeSource, 1024L * 1024 * 1024, "bundled Ghidra application JAR")
                    JarFile(codeSource.toFile(), false).use { jar ->
                        val entries = jar.entries().asSequence().take(200_001).toList()
                        require(entries.size <= 200_000) { "application JAR exceeds its entry bound" }
                        val entry = entries.singleOrNull { it.name == EXPORTER_RESOURCE.removePrefix("/") }
                        require(entry != null && !entry.isDirectory && entry.size == parsed.exporterBytes) {
                            "application JAR has no exact unique Ghidra exporter resource"
                        }
                        jar.getInputStream(entry).use { it.readNBytes(MAXIMUM_EXPORTER_BYTES + 1) }
                    }.also { checkNotNull(applicationGuard).verifyUnchanged("after reading application JAR exporter") }
                }
                require(exporter.size.toLong() == parsed.exporterBytes && OracleArtifacts.sha256(exporter) == parsed.exporterSha256) {
                    "bundled Ghidra reference exporter differs from the loaded application resource"
                }
                return GccBundledGhidraDeploymentReference(parsed, bundleRoot, guard, captured, applicationGuard).also { it.verify("after opening") }
            } catch (failure: Throwable) {
                runCatching { applicationGuard?.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                runCatching { guard.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private fun requireReferencePath(path: String) {
    val components = path.split('/')
    require(path.toByteArray(Charsets.UTF_8).size in 1..4096 && components.size <= 32 && components.all {
        it.isNotBlank() && it != "." && it != ".." && it.toByteArray(Charsets.UTF_8).size <= 255
    } && path.none { it.code < 32 || it.code == 127 || it == ':' || it == '\\' }) { "bundled Ghidra reference path is invalid" }
}

private fun requireDigest(digest: String) = require(digest.matches(Regex("[a-f0-9]{64}"))) { "bundled Ghidra reference digest is invalid" }
private fun JsonObject.exactFields(fields: Set<String>) = require(keys == fields) { "bundled Ghidra reference fields are invalid" }
private fun JsonObject.string(name: String): String = (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
    ?: throw IllegalArgumentException("bundled Ghidra reference $name must be a string")
private fun JsonObject.number(name: String): Long = (this[name] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
    ?: throw IllegalArgumentException("bundled Ghidra reference $name must be an integer")
private fun JsonObject.objectValue(name: String): JsonObject = this[name] as? JsonObject
    ?: throw IllegalArgumentException("bundled Ghidra reference $name must be an object")
private fun JsonObject.arrayValue(name: String): JsonArray = this[name] as? JsonArray
    ?: throw IllegalArgumentException("bundled Ghidra reference $name must be an array")

private const val REFERENCE_PROVIDER = "gcc-bundled-ghidra-deployment-reference-v1"
private const val BRIDGE_PATH = "decomp-ghidra-bridge.jar"
private const val GUARD_PATH = "scripts/RunBundledExports.class"
private const val EXPORTER_RESOURCE = "/ghidra_scripts/ExportProgramModel.java"
private const val ARCHIVE_BYTES = 569445154L
private const val MAXIMUM_REFERENCE_BYTES = 8 * 1024 * 1024
private const val MAXIMUM_EXPORTER_BYTES = 4 * 1024 * 1024
private const val EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
private val REFERENCE_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_REFERENCE_BYTES, maximumCanonicalBytes = MAXIMUM_REFERENCE_BYTES,
    maximumDepth = 16, maximumNodes = 250_000, maximumStringBytes = 64 * 1024,
    maximumTotalStringBytes = MAXIMUM_REFERENCE_BYTES,
)
